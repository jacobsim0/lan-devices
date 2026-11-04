# lan-devices

[![build](https://github.com/jacobsim0/lan-devices/actions/workflows/build.yml/badge.svg)](https://github.com/jacobsim0/lan-devices/actions/workflows/build.yml)

**Who's on my network, with the best name we can find.** Sweeps your LAN over
IPv4 and IPv6 and names each device from your own labels, mDNS (AirPlay,
Chromecast, HomeKit, printers), NetBIOS, DNS, or what it learned last time.
C, Linux and macOS, one dependency (libpcap), about five seconds.

```
IP             NAME                 SOURCE    MAC                VENDOR
192.168.0.1    opnsense.internal    dns       60:be:b4:xx:xx:xx  S-Bluetech co., limited
192.168.0.153  Living Room          mdns-svc  24:ee:5d:xx:xx:xx  Vizio, Inc
192.168.0.182  Jacob's MacBook Pro  mdns-svc  88:66:5a:xx:xx:xx  Apple, Inc.
192.168.0.238  Office speaker       mdns-svc  70:f7:54:xx:xx:xx  AMPAK Technology,Inc.
```

## Install

```bash
# macOS (libpcap is built in)          # Debian / Ubuntu
make && sudo make install              sudo apt install build-essential libpcap-dev && make && sudo make install
```

Vendor names need an OUI file. `brew install arp-scan` / `apt install arp-scan` provides one, or:

```bash
curl -o ~/.config/lan-devices/oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

## Use

```bash
sudo lan-devices                 # scan
sudo lan-devices -6              # add an IPv6 column
lan-devices --passive            # no root: what the OS already knows
lan-devices --add <MAC> "name"   # label a device for good
sudo lan-devices --watch         # daemon: rescan every 60 s, Prometheus metrics on :9341
```

Devices with randomized MACs (phones) show `(private MAC)` and rotate; that's
the phone working as designed. Files live in `~/.config/lan-devices/`
(`aliases`, `cache`, `seen`); override the directory with `LAN_DEVICES_DIR`.

## Watch mode

`--watch` logs one line per change (`new`, `online`, `offline` after three
missed scans) and serves `/metrics`, `/devices.json` and `/healthz`. Metrics
carry `known="true|false"` (has a label or not), so an "unknown device joined"
alert is one expression; `deploy/` has a container image, Kubernetes manifests,
the alert rules and a Grafana dashboard.

## Hacking

`make check` runs the unit tests, `make check-asan` runs them under the
sanitizers, `make fuzz` fuzzes every parser (needs clang). CI does all three on
Ubuntu plus the build on macOS, and publishes the image.

How the code fits together: [ARCHITECTURE.md](ARCHITECTURE.md).

MIT. The original bash version is in `legacy/`.
