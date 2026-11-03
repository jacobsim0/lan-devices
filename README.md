# lan-devices

[![build](https://github.com/jacobsim0/lan-devices/actions/workflows/build.yml/badge.svg)](https://github.com/jacobsim0/lan-devices/actions/workflows/build.yml)

**Who's on my network, with the best name we can find.** A small C tool for
Linux and macOS that sweeps your LAN over IPv4 and IPv6 and names every device
using six name sources in priority order:

1. Your own labels (`lan-devices --add MAC "name"`)
2. mDNS service names — Chromecast `fn=`, AirPlay/HomeKit ("Office speaker"), printers, Sonos, SMB
3. mDNS hostnames ("iPhone")
4. NetBIOS (Windows, Samba, NAS)
5. Reverse DNS
6. A **learned cache**: names discovered while a device was awake are remembered,
   so an idle iPhone that ignores mDNS at 3 AM still shows its name from this afternoon.

```
IP             NAME                 SOURCE    MAC                VENDOR
192.168.0.1    TP-Link router       alias     68:7f:f0:xx:xx:xx  TP-Link Corporation
192.168.0.84   Jacob's MacBook Pro  mdns-svc  f6:75:90:xx:xx:xx  MacBookPro18,3
192.168.0.194  Vizio TV             alias     14:c6:7d:xx:xx:xx  VIZIO Inc.
```

No Avahi, Bonjour SDK, arp-scan or nbtscan needed: the ARP sweep uses libpcap,
and the mDNS and NetBIOS queries are plain UDP sockets. The only dependency is libpcap.

## Install

macOS (libpcap ships with the system):

```bash
make && sudo make install
brew install arp-scan            # optional: only for its OUI vendor file
```

Debian / Ubuntu:

```bash
sudo apt install build-essential libpcap-dev arp-scan   # arp-scan optional, for the OUI file
make && sudo make install
```

Fedora: `sudo dnf install gcc make libpcap-devel`. Alpine: `apk add build-base libpcap-dev`.

Vendor names come from an IEEE OUI file. The tool looks for arp-scan's copy
(`/usr/share/arp-scan/ieee-oui.txt`, `/opt/homebrew/share/arp-scan/ieee-oui.txt`),
Debian's `ieee-data` package, or `~/.config/lan-devices/oui.csv`, which you can fetch with:

```bash
curl -o ~/.config/lan-devices/oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

## Usage

```bash
sudo lan-devices                # scan the interface with the default route
sudo lan-devices -i eth0        # specific interface
sudo lan-devices -t 5           # listen longer for mDNS/NetBIOS answers (default 3 s)
sudo lan-devices -6             # add an IPV6 column (best address: global > ULA > link-local)
lan-devices --passive           # no root: list what the OS ARP table already knows
lan-devices --add <MAC> "name"  # label a device permanently
lan-devices --no-vendor         # skip the vendor column
```

The ARP sweep needs root. Run without sudo and the tool falls back to passive
mode automatically. Under sudo it drops privileges right after opening the raw
socket, so `~/.config/lan-devices/` stays owned by you.

Devices with randomized private MACs (modern phones) show `(private MAC)` as the
vendor and rotate over time — that's the phones behaving correctly, not the tool failing.

## Watch mode: a daemon with Prometheus metrics

```bash
sudo lan-devices --watch                       # scan every 60 s, HTTP on :9341
sudo lan-devices --watch --interval 30 --listen 127.0.0.1:9341
```

Each scan logs changes, one line per event, and remembers every device ever
seen in `~/.config/lan-devices/seen` so "new" means new across restarts:

```
2026-11-03T22:24:43Z new     76:14:29:84:ae:b8 192.168.0.205   iPhone                 (private MAC)
2026-11-03T22:31:12Z offline 22:e8:83:4e:b0:57 192.168.0.154   ?                      (private MAC)
2026-11-03T22:40:01Z online  22:e8:83:4e:b0:57 192.168.0.154   ?                      (private MAC)
```

A device is reported offline after three consecutive missed scans, so a phone
that sleeps through one scan doesn't flap. The HTTP server is tiny and runs on
the scanner's own poll loop:

| Path            | Content                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `/metrics`      | Prometheus text: per device `lan_device_online{mac,name,ip,vendor,known}`, `lan_device_first_seen_seconds`, `lan_device_last_seen_seconds`; totals `lan_devices_online`, `lan_devices_known_total`, `lan_scans_total`, `lan_scan_duration_seconds`, `lan_send_errors_total` |
| `/devices.json` | The same state as JSON                                                  |
| `/healthz`      | `ok`                                                                    |

`known="true"` means the device has an alias, so an "unknown device joined"
alert is simply:

```
lan_device_online{known="false"} == 1 and (time() - lan_device_first_seen_seconds) < 600
```

Label a device with `lan-devices --add` and it becomes known on the next scan.
The container image and Kubernetes manifests are described in `deploy/`.

## How discovery works

1. **IPv4:** one ARP request per address in the subnet, two passes.
2. **IPv6:** there is no way to sweep 2^64 addresses, so the tool pings the
   all-nodes multicast group `ff02::1` from its link-local address; every host
   that answers reveals its MAC and link-local address. Hosts that ignore
   multicast pings (Windows, by default) are still caught passively: the capture
   stays open for the whole run and attributes any on-link IPv6 frame it sees
   (neighbour discovery, MLD, mDNS) to its source MAC. Traffic forwarded by the
   router from outside your prefixes is ignored.
3. Rows are keyed by MAC, so a device's IPv4 and IPv6 addresses land on one line.
   IPv6-only devices show their best IPv6 address in the IP column.
4. **Names:** mDNS queries go out over both IPv4 and IPv6 multicast (service
   types, `in-addr.arpa` and `ip6.arpa` reverse questions; A and AAAA answers
   are both used), NetBIOS NBSTAT over IPv4, and PTR queries to the system
   resolver for anything still unnamed.

## Testing

```bash
make check          # unit tests for every parser (DNS names, TXT, mDNS records, NetBIOS, OUI files, alias store)
make check-asan     # the same tests under AddressSanitizer + UndefinedBehaviorSanitizer
make fuzz           # libFuzzer over all parsers for 60 s (needs clang; FUZZ_TIME=N to change)
```

CI runs the `-Werror` build, the unit tests, the sanitizer run and a 30-second
fuzz on Ubuntu, plus the build and unit tests on macOS, for every push.

## Limitations

- **One interface at a time.** The sweep covers the interface's own IPv4 subnet
  (up to a /16) and its IPv6 link; other VLANs need `-i`.
- **One IPv4 per row.** A MAC with several IPv4 addresses (a router with VIPs) shows
  the first one seen. Up to four IPv6 addresses per device are kept.
- **IPv6 depends on devices answering or talking.** A silent host that ignores
  multicast pings and sends nothing during the listen window will not be found
  over IPv6, though it is still found over IPv4 if it has an address.
- **Reverse DNS** asks the resolvers in `/etc/resolv.conf` directly, so `/etc/hosts`
  entries are not consulted. That keeps lookups bounded by the listen window instead
  of blocking on a slow resolver.
- Names depend on what devices advertise. A device that speaks none of mDNS,
  NetBIOS or DNS shows only its MAC and vendor until you label it.

## Files and environment

| What | Default | Override |
|---|---|---|
| Your labels | `~/.config/lan-devices/aliases` | `LAN_DEVICES_ALIASES` |
| Learned cache | `~/.config/lan-devices/cache` | `LAN_DEVICES_CACHE` |
| Watch state | `~/.config/lan-devices/seen` | `LAN_DEVICES_SEEN` |
| Config dir | `~/.config/lan-devices` | `LAN_DEVICES_DIR` |
| OUI file | searched, see above | `LAN_DEVICES_OUI` |

Both files are tab-separated `mac<TAB>name`, the same format as the original
bash version, so existing files keep working.

## Source layout

```
src/main.c      argument parsing, orchestration, table output
src/iface.c     pick the interface (default route), its IPv4/netmask/MAC
src/cap.c       libpcap capture/injection; attributes ARP and on-link IPv6 frames to MACs
src/arp.c       IPv4 sweep: ARP request to every subnet address
src/nd6.c       IPv6 probe: ICMPv6 echo to all-nodes, with checksum
src/arpcache.c  passive fallback: kernel ARP and IPv6 neighbour tables (procfs/netlink, sysctl, arp/ndp -an)
src/mdns.c      mDNS/DNS-SD queries and record parsing (PTR/SRV/TXT/A, reverse PTR)
src/nbns.c      NetBIOS NBSTAT queries
src/rdns.c      reverse DNS as async UDP queries to the system resolver
src/dns.c       DNS wire-format helpers shared by mdns.c, rdns.c and the tests
src/oui.c       vendor lookup (arp-scan ieee-oui.txt, IEEE oui.txt or oui.csv)
src/store.c     aliases and learned cache
src/watch.c     --watch state (seen devices, events), Prometheus and JSON rendering
src/http.c      minimal HTTP/1.0 server driven from the poll loop
tests/          unit tests and libFuzzer harness
```

The original single-file bash implementation is kept in `legacy/lan-devices.sh`.

## License

MIT
