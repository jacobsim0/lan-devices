# lan-devices

**Who's on my network, with the best name we can find.** A single-file bash tool that ARP-scans your LAN and names every device using five name sources in priority order:

1. Your own labels (`lan-devices --add MAC "name"`)
2. mDNS service names — Chromecast `fn=`, AirPlay/HomeKit ("Office speaker")
3. mDNS hostnames ("iPhone.local")
4. NetBIOS (Windows)
5. Reverse DNS

…plus a **learned cache**: names discovered while a device was awake are remembered, so an idle iPhone that ignores mDNS at 3 AM still shows its name from this afternoon.

```
IP             NAME                 SOURCE    MAC                VENDOR
192.168.0.1    TP-Link router       alias     68:7f:f0:xx:xx:xx  TP-Link Corporation
192.168.0.84   Jacob's MacBook Pro  mdns-svc  f6:75:90:xx:xx:xx  Mac15,6
192.168.0.194  Vizio TV             alias     14:c6:7d:xx:xx:xx  VIZIO Inc.
```

## Install

```bash
sudo apt install arp-scan avahi-daemon avahi-utils nbtscan ieee-data
cp lan-devices ~/bin/ && chmod +x ~/bin/lan-devices
```

## Usage

```bash
lan-devices                     # scan default interface
lan-devices -i eth0             # specific interface
lan-devices --add <MAC> "name"  # label a device permanently
lan-devices --no-vendor         # skip OUI vendor lookup
```

Needs sudo for the ARP/NetBIOS sweeps. Devices with randomized private MACs (modern phones) show as unnamed and rotate over time — that's the phones behaving correctly, not the tool failing.

## License

MIT
