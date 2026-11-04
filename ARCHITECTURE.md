# How lan-devices is put together

Fifteen C files, about 2,300 lines. One process, no threads. Everything happens
on one loop that sends questions, waits for answers, and sorts them into a table.

## One scan, start to finish

```
                 main.c                                  (parse flags, run the steps below, print)
                   │
   1. iface.c      │  which network interface, our IPv4/mask, MAC, IPv6 link-local + prefixes
                   ▼
   2. cap.c  ──── open libpcap on that interface (needs root; drop root right after)
        │
        │   "who is out there?"                      every frame that comes back goes through
        │                                            cap_frame(), which turns it into a row:
        ├── arp.c   ARP request to every IPv4 ─────►  MAC + IPv4
        └── nd6.c   ICMPv6 ping to ff02::1  ─────►  MAC + IPv6
                                                      (plus any IPv6 chatter we overhear)
                   │
                   ▼        hostlist: one row per MAC  [mac | ip4 | ip6[] | names... ]
                   │
   3. "what are they called?"   three UDP sockets, all answered on one poll() loop for ~3 s
        ├── mdns.c   multicast queries, v4 + v6 ──►  service names ("Office speaker"), hostnames, models
        ├── nbns.c   NetBIOS NBSTAT to each IPv4 ──►  Windows/Samba computer names
        └── rdns.c   PTR queries to /etc/resolv.conf ►  DNS names
            (dns.c holds the packet encode/decode both mdns.c and rdns.c use)
                   │
                   ▼
   4. main.c name_hosts()   pick each row's name by priority:
                            alias > mDNS service > mDNS host > NetBIOS > DNS > self > cached
        ├── store.c   aliases file (your labels) and cache file (names learned earlier)
        └── oui.c     MAC prefix → vendor
                   │
                   ▼
   5. main.c print_table()      or, in --watch mode:
        watch.c   diff against the devices seen before, log new/online/offline,
                  save state, render /metrics and /devices.json
        http.c    serve those over a tiny HTTP server, polled from the same loop
```

Without root, step 2 is replaced by `arpcache.c`, which reads the devices the OS
already knows about (its ARP and IPv6 neighbour tables). Steps 3 to 5 are the same.

## The files

| File | Owns | Talks to |
|---|---|---|
| `lan.h` | every struct and function the files share (see below) | everyone |
| `main.c` | flags, the scan steps in order, the table, the watch loop | all |
| `iface.c` | picking the interface and reading its addresses | `main.c` |
| `cap.c` | the libpcap handle; turning raw frames into host rows | `arp.c`, `nd6.c`, `main.c` |
| `arp.c` | building and sending ARP requests | `cap.c` |
| `nd6.c` | building the ICMPv6 echo frame, with its checksum | `cap.c` |
| `arpcache.c` | the no-root fallback: OS neighbour tables | `main.c` |
| `dns.c` | DNS wire format: names, TXT records, building questions | `mdns.c`, `rdns.c`, tests |
| `mdns.c` | mDNS sockets, queries, record parsing, deciding the best service name | `dns.c`, `main.c` |
| `nbns.c` | NetBIOS queries and reply parsing | `main.c` |
| `rdns.c` | reverse DNS as plain UDP queries | `dns.c`, `main.c` |
| `oui.c` | loading an OUI file, MAC → vendor | `main.c` |
| `store.c` | the aliases and cache files, config directory, sudo-aware paths | `main.c`, `watch.c` |
| `watch.c` | watch-mode state, event log, Prometheus and JSON output | `main.c`, `http.c` |
| `http.c` | the HTTP server and `idle_ms()`, the sleep that keeps serving | `watch.c`, `arp.c` |
| `util.c` | small shared helpers: host rows, string copy, time, privilege drop | everyone |

## What `lan.h` is

C has no modules. Each `.c` file is compiled on its own and can only call a
function it has seen a declaration for. `lan.h` is the one place those
declarations live: every struct (`iface`, `host`, `hostlist`, `watch`...) and
the signature of every function one file offers to another. Every `.c` file
starts with `#include "lan.h"`, so they all agree on the same shapes.

Reading order if you are new: `lan.h` first (it is the table of contents),
then `main.c` top to bottom, then whichever module you care about.

## The two data structures that matter

**`struct host`** is one row of the table. It is created by `cap.c` (or
`arpcache.c`) with a MAC and an address, then the name modules fill in the
name fields they can (`svc`, `mdns`, `nbt`, `rdns`, `model`). Nothing decides
which name wins until `name_hosts()` in `main.c`. Rows are keyed by MAC, so a
device's IPv4 and IPv6 addresses end up on one line.

**`struct seen`** (watch mode) is a device's history: first and last seen,
consecutive misses, the name and address it had. It is what `/metrics`
reports and what the `seen` file stores between restarts.

## Things that are not obvious

- **No threads, on purpose.** Every socket is non-blocking and sits on one
  `poll()`. The HTTP server is served from that same loop, and from
  `idle_ms()` wherever the scanner would otherwise sleep. That removes a whole
  class of bugs at the cost of one rule: never block.
- **Root is dropped immediately** after libpcap opens the interface
  (`drop_privs()` in `util.c`). Everything that parses network input runs as
  the normal user, and the config files end up owned by you.
- **Names come off the wire**, so they are sanitized (control characters
  replaced) before they are printed, logged or saved, and every parser is
  bounds-checked, unit-tested, and fuzzed. See `tests/`.
- **IPv6 cannot be swept.** `nd6.c` pings the all-nodes group instead, and
  `cap.c` keeps listening for the rest of the run to catch devices that talk
  but don't answer pings. A frame is only attributed if its source is
  link-local or inside one of our own prefixes, so traffic the router forwards
  from the internet is never mistaken for a neighbour.
- **Watch mode re-points the capture** at a fresh host list every cycle
  (`cap_set_hosts`). Forgetting that was the first bug the deployment found.

## Adding a name source

1. Give `struct host` a field for it in `lan.h`.
2. Write a module with the same shape as `nbns.c`: `start()` opens a socket and
   sends, `fd()` exposes it, `recv()` parses answers into the host field,
   `finish()` closes.
3. Add its fd to the `poll()` set in `discover()` in `main.c`.
4. Give it a line in the priority chain in `name_hosts()`.
5. Put its parser in `tests/test_parsers.c` and call it from `tests/fuzz_parsers.c`.
