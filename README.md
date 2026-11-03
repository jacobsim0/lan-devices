# lan-devices

**Who's on my network, with the best name we can find.** A small C tool for
Linux and macOS that ARP-scans your LAN and names every device using six name
sources in priority order:

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
lan-devices --passive           # no root: list what the OS ARP table already knows
lan-devices --add <MAC> "name"  # label a device permanently
lan-devices --no-vendor         # skip the vendor column
```

The ARP sweep needs root. Run without sudo and the tool falls back to passive
mode automatically. Under sudo it drops privileges right after opening the raw
socket, so `~/.config/lan-devices/` stays owned by you.

Devices with randomized private MACs (modern phones) show `(private MAC)` as the
vendor and rotate over time — that's the phones behaving correctly, not the tool failing.

## Files and environment

| What | Default | Override |
|---|---|---|
| Your labels | `~/.config/lan-devices/aliases` | `LAN_DEVICES_ALIASES` |
| Learned cache | `~/.config/lan-devices/cache` | `LAN_DEVICES_CACHE` |
| Config dir | `~/.config/lan-devices` | `LAN_DEVICES_DIR` |
| OUI file | searched, see above | `LAN_DEVICES_OUI` |

Both files are tab-separated `mac<TAB>name`, the same format as the original
bash version, so existing files keep working.

## Source layout

```
src/main.c      argument parsing, orchestration, table output
src/iface.c     pick the interface (default route), its IPv4/netmask/MAC
src/arp.c       ARP sweep via libpcap (root)
src/arpcache.c  passive fallback: kernel ARP table (/proc/net/arp or routing sysctl)
src/mdns.c      mDNS/DNS-SD queries and record parsing (PTR/SRV/TXT/A, reverse PTR)
src/nbns.c      NetBIOS NBSTAT queries
src/rdns.c      reverse DNS on a small thread pool
src/oui.c       vendor lookup (arp-scan ieee-oui.txt, IEEE oui.txt or oui.csv)
src/store.c     aliases and learned cache
```

The original single-file bash implementation is kept in `legacy/lan-devices.sh`.

## License

MIT
