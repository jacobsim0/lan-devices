#!/usr/bin/env bash
# lan-devices — list devices on the local network with the best name we can find.
# Name sources, in priority order:
#   1. ~/.config/lan-devices/aliases   (your own labels, keyed by MAC)
#   2. mDNS service names (Cast "fn=", AirPlay/HomeKit names: "Office speaker")
#   3. mDNS hostname (Apple/Linux/printers: "iPhone.local")
#   4. NetBIOS (Windows)
#   5. reverse DNS
#   6. cached name from a previous run (device asleep now, e.g. idle iPhone)
# Usage: lan-devices [-i IFACE] [--no-vendor]
#        lan-devices --add MAC "name"     add/replace an alias
set -euo pipefail

ALIASES="${LAN_DEVICES_ALIASES:-$HOME/.config/lan-devices/aliases}"
CACHE="${LAN_DEVICES_CACHE:-$HOME/.config/lan-devices/cache}"   # learned MAC->name, auto-updated
IFACE=""; SHOW_VENDOR=1
mkdir -p "$(dirname "$ALIASES")"; touch "$ALIASES" "$CACHE"

if [[ "${1:-}" == "--add" ]]; then
  [[ $# -eq 3 ]] || { echo "usage: lan-devices --add MAC \"name\"" >&2; exit 2; }
  mac=$(tr 'A-F' 'a-f' <<<"$2")
  grep -vi "^$mac[[:space:]]" "$ALIASES" > "$ALIASES.tmp" || true
  printf '%s\t%s\n' "$mac" "$3" >> "$ALIASES.tmp"; mv "$ALIASES.tmp" "$ALIASES"
  echo "saved: $mac -> $3"; exit 0
fi
while [[ $# -gt 0 ]]; do case "$1" in
  -i) IFACE="$2"; shift 2;; --no-vendor) SHOW_VENDOR=0; shift;;
  -h|--help) sed -n '2,10p' "$0"; exit 0;; *) echo "unknown arg $1" >&2; exit 2;; esac; done

for t in arp-scan avahi-resolve nbtscan; do
  command -v "$t" >/dev/null || { echo "missing $t (sudo apt install arp-scan avahi-daemon avahi-utils nbtscan ieee-data)" >&2; exit 1; }; done

[[ -n "$IFACE" ]] || IFACE=$(ip route | awk '/^default/{print $5; exit}')
CIDR=$(ip -4 -o addr show "$IFACE" | awk '{print $4; exit}')
MYIP=${CIDR%/*}; MYMAC=$(cat /sys/class/net/"$IFACE"/address)
[[ -n "$CIDR" ]] || { echo "no IPv4 on $IFACE" >&2; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# 1) who's up (ARP) — arp-scan omits ourself, so add it
OUI=(); for f in /usr/share/arp-scan/ieee-oui.txt /usr/share/ieee-data/oui.txt; do [[ -r $f ]] && { OUI=(--ouifile="$f"); break; }; done
sudo arp-scan -I "$IFACE" --localnet --plain --ignoredups "${OUI[@]}" 2>/dev/null \
  | awk -F'\t' '{print $1"\t"tolower($2)"\t"$3}' > "$TMP/hosts"
printf '%s\t%s\t%s\n' "$MYIP" "$MYMAC" "(this host)" >> "$TMP/hosts"
sort -t. -k4,4n "$TMP/hosts" -o "$TMP/hosts"

# 2) NetBIOS sweep (one pass) + mDNS/rDNS per host, in parallel
( sudo nbtscan -q -t 800 "$CIDR" 2>/dev/null | awk '{print $1"\t"$2}' > "$TMP/nbt" || true ) &
cat > "$TMP/svc.py" <<'PY'
import sys, re
def unesc(t):
    b = re.sub(r"\\(\d{3})", lambda m: bytes([int(m.group(1))]).decode("latin-1"), t)
    return b.encode("latin-1", "replace").decode("utf-8", "replace")
# avahi -r prints friendly type names; accept both forms
CAST  = {"_googlecast._tcp"}
NAMED = {"_airplay._tcp":3, "AirPlay Remote Video":3, "_hap._tcp":3, "_homekit._tcp":3, "Apple HomeKit":3,
         "_sonos._tcp":2, "_ipp._tcp":2, "Internet Printer":2, "_printer._tcp":2, "UNIX Printer":2,
         "_companion-link._tcp":1, "_raop._tcp":1, "AirTunes Remote Audio":1}
best, model = {}, {}
for line in sys.stdin:
    f = line.rstrip("\n").split(";")
    if len(f) < 10 or f[0] != "=" or f[2] != "IPv4": continue
    name, typ, ip, txt = unesc(f[3]), f[4], f[7], f[9]
    kv = dict(re.findall(r'"([^="]+)=([^"]*)"', txt))
    fn, pr = None, 0
    if typ in CAST and kv.get("fn"): fn, pr = kv["fn"], 3
    elif typ in NAMED:
        fn, pr = name, NAMED[typ]
        if "@" in fn and typ in ("_raop._tcp", "AirTunes Remote Audio"): fn = fn.split("@", 1)[1]
    if fn and pr > best.get(ip, (0, ""))[0]: best[ip] = (pr, fn)
    if typ in CAST or NAMED.get(typ, 0) >= 2:
        md = kv.get("md") or kv.get("model") or kv.get("am")
        if md and re.search(r"[A-Za-z]", md):
            mf = kv.get("manufacturer", "")
            cand = f"{mf} {md}".strip() if mf and mf.lower() not in md.lower() else md
            if ip not in model or (mf and " " not in model[ip]): model[ip] = cand
for ip in set(best) | set(model):
    print(ip, best.get(ip, (0, ""))[1], model.get(ip, ""), sep="\t")
PY
( timeout 4 avahi-browse -artp 2>/dev/null | python3 "$TMP/svc.py" > "$TMP/svc" || true ) &
while IFS=$'\t' read -r ip mac vendor; do
  ( set +e
    m=$(timeout 1.5 avahi-resolve -a "$ip" 2>/dev/null | awk '{print $2}' | sed 's/\.local\.\?$//')
    r=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}')
    printf '%s\t%s\t%s\n' "$ip" "$m" "$r" > "$TMP/n.$ip" ) </dev/null &
done < "$TMP/hosts"; wait

# 3) merge + print
{
printf 'IP\tNAME\tSOURCE\tMAC\t%s\n' "$([[ $SHOW_VENDOR = 1 ]] && echo VENDOR)"
unnamed=0
while IFS=$'\t' read -r ip mac vendor; do
  IFS=$'\t' read -r _ mdns rdns < "$TMP/n.$ip"
  nbt=$(awk -F'\t' -v i="$ip" '$1==i{print $2; exit}' "$TMP/nbt")
  IFS=$'\t' read -r _ svc model < <(awk -F'\t' -v i="$ip" '$1==i{print; exit}' "$TMP/svc"; echo)
  [[ -n ${model:-} && $vendor == "(Unknown"* ]] && vendor="$model"
  alias=$(awk -F'\t' -v m="$mac" 'tolower($1)==m{ $1=""; sub(/^[ \t]+/,""); print; exit}' "$ALIASES")
  if   [[ -n $alias ]]; then name=$alias; src=alias
  elif [[ -n ${svc:-} ]]; then name=$svc; src=mdns-svc
  elif [[ -n $mdns  ]]; then name=$mdns;  src=mdns
  elif [[ -n $nbt   ]]; then name=$nbt;   src=netbios
  elif [[ -n $rdns  ]]; then name=$rdns;  src=dns
  else
    cached=$(awk -F'\t' -v m="$mac" 'tolower($1)==m{ $1=""; sub(/^[ \t]+/,""); print; exit}' "$CACHE")
    if [[ -n $cached ]]; then name="$cached"; src=cached
    else name="?"; src="-"; unnamed=$((unnamed+1)); fi
  fi
  # learn: remember discovered names (not aliases/cache) for when the device is asleep later
  case $src in mdns-svc|mdns|netbios|dns) printf '%s\t%s\n' "$mac" "$name" >> "$TMP/learned";; esac
  printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "$name" "$src" "$mac" "$([[ $SHOW_VENDOR = 1 ]] && echo "$vendor")"
done < "$TMP/hosts"
echo "$unnamed" > "$TMP/unnamed"
} | column -t -s $'\t'

if [[ -s "$TMP/learned" ]]; then
  { cat "$TMP/learned"; cat "$CACHE"; } | awk -F'\t' '!seen[tolower($1)]++' > "$CACHE.tmp" && mv "$CACHE.tmp" "$CACHE"
fi
n=$(cat "$TMP/unnamed")
(( n == 0 )) || printf '\n%d unnamed device(s). Label one with:  lan-devices --add <MAC> "name"\n' "$n"
