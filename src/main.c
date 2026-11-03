/* lan-devices — list devices on the local network with the best name we can find.
 *
 * Name sources, in priority order:
 *   1. aliases file                    (your own labels, keyed by MAC)
 *   2. mDNS service names              (Chromecast fn=, AirPlay/HomeKit "Office speaker")
 *   3. mDNS hostname                   (Apple/Linux/printers: "iPhone")
 *   4. NetBIOS                         (Windows, Samba)
 *   5. reverse DNS
 *   6. cached name from a previous run (device asleep now, e.g. idle iPhone)
 */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>

static const char *USAGE =
    "usage: lan-devices [-i IFACE] [-t SECONDS] [--no-vendor] [--passive]\n"
    "       lan-devices --add MAC \"name\"      label a device permanently\n"
    "\n"
    "  -i IFACE      scan this interface (default: the one with the default route)\n"
    "  -t SECONDS    how long to listen for mDNS/NetBIOS answers (default 3)\n"
    "  --no-vendor   skip the OUI vendor column\n"
    "  --passive     don't ARP-sweep; list what the OS ARP table already knows (no root)\n"
    "\n"
    "The ARP sweep needs root (sudo). Files: ~/.config/lan-devices/{aliases,cache}\n"
    "Env: LAN_DEVICES_DIR, LAN_DEVICES_ALIASES, LAN_DEVICES_CACHE, LAN_DEVICES_OUI\n";

static void print_cell(const char *s, size_t width, bool last) {
    fputs(s, stdout);
    if (last) { putchar('\n'); return; }
    for (int pad = (int)width - display_width(s) + 2; pad > 0; pad--) putchar(' ');
}

static int by_ip(const void *a, const void *b) {
    uint32_t x = ntohl(((const struct host *)a)->ip.s_addr), y = ntohl(((const struct host *)b)->ip.s_addr);
    return x < y ? -1 : x > y;
}

static int do_add(const char *mac_in, const char *name) {
    unsigned m[6];
    if (sscanf(mac_in, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6 || !*name)
        die("usage: lan-devices --add aa:bb:cc:dd:ee:ff \"name\"");
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    struct kvlist al = { 0 };
    kv_load(&al, aliases_path());
    kv_put_front(&al, mac_str(mac), name);
    if (kv_save(&al, aliases_path()) != 0) die("cannot write %s", aliases_path());
    printf("saved: %s -> %s\n", mac_str(mac), name);
    return 0;
}

int main(int argc, char **argv) {
    const char *want_iface = NULL;
    bool show_vendor = true, passive = false;
    double listen_s = 3.0;

    if (argc >= 2 && !strcmp(argv[1], "--add")) {
        if (argc != 4) die("usage: lan-devices --add MAC \"name\"");
        return do_add(argv[2], argv[3]);
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) want_iface = argv[++i];
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) listen_s = atof(argv[++i]);
        else if (!strcmp(argv[i], "--no-vendor")) show_vendor = false;
        else if (!strcmp(argv[i], "--passive")) passive = true;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { fputs(USAGE, stdout); return 0; }
        else die("unknown arg %s\n%s", argv[i], USAGE);
    }
    if (listen_s < 0.5) listen_s = 0.5;

    struct iface ifc;
    char err[256];
    if (iface_detect(want_iface, &ifc, err, sizeof err) != 0) die("%s", err);

    /* 1) who's up: ARP sweep (root) or the OS ARP table (fallback) */
    struct arp *arp = NULL;
    if (!passive) {
        arp = arp_open(&ifc, err, sizeof err);
        if (!arp) {
            if (geteuid() != 0)
                fprintf(stderr, "note: ARP sweep needs root (run with sudo); showing the OS ARP table instead\n");
            else
                fprintf(stderr, "note: ARP sweep unavailable (%s); showing the OS ARP table instead\n", err);
            passive = true;
        }
    }
    drop_privs();
    int noui = show_vendor ? oui_load(getenv("LAN_DEVICES_OUI")) : 1;

    struct hostlist hl = { 0 };
    struct host *self = hosts_add(&hl, ifc.ip, ifc.mac);
    self->self = true;
    if (arp) {
        if (arp_scan(arp, &hl, 1.0) < 0) die("subnet on %s is larger than /16; pick a smaller one with -i", ifc.name);
        arp_close(arp);
    } else if (arpcache_read(&ifc, &hl) < 0) {
        die("cannot read the ARP table");
    }
    qsort(hl.h, hl.n, sizeof *hl.h, by_ip);

    /* 2) names: NetBIOS + mDNS on one poll loop, reverse DNS on threads */
    rdns_start(&hl);
    struct mdns *md = mdns_start(&ifc, &hl);
    struct nbns *nb = nbns_start(&hl);
    struct pollfd pf[2] = { { mdns_fd(md), POLLIN, 0 }, { nbns_fd(nb), POLLIN, 0 } };
    double t0 = now_s(), deadline = t0 + listen_s;
    bool requeried = false;
    for (double now; (now = now_s()) < deadline;) {
        int ms = (int)((deadline - now) * 1000);
        poll(pf, 2, ms < 100 ? ms : 100);
        if (pf[0].revents & POLLIN) mdns_recv(md);
        if (pf[1].revents & POLLIN) nbns_recv(nb);
        if (!requeried && now - t0 > 1.0) { mdns_query(md); nbns_query(nb); requeried = true; }
    }
    mdns_finish(md);
    nbns_finish(nb);
    rdns_collect(&hl, 0.5);

    /* 3) merge + print */
    struct kvlist aliases = { 0 }, cache = { 0 };
    kv_load(&aliases, aliases_path());
    kv_load(&cache, cache_path());

    enum { C_IP, C_NAME, C_SRC, C_MAC, C_VENDOR, NCOL };
    int ncol = show_vendor ? NCOL : NCOL - 1;
    const char *hdr[NCOL] = { "IP", "NAME", "SOURCE", "MAC", "VENDOR" };
    char (*rows)[NCOL][NAME_LEN] = calloc(hl.n ? hl.n : 1, sizeof *rows);
    size_t w[NCOL] = { 0 };
    for (int c = 0; c < ncol; c++) w[c] = strlen(hdr[c]);
    int unnamed = 0;
    bool learned = false;
    char hostname[NAME_LEN] = "";
    gethostname(hostname, sizeof hostname);
    char *dot = strchr(hostname, '.');
    if (dot) *dot = 0;

    for (int i = 0; i < hl.n; i++) {
        struct host *h = &hl.h[i];
        const char *mac = mac_str(h->mac), *name, *src, *alias, *cached;
        if      ((alias = kv_get(&aliases, mac))) { name = alias;   src = "alias"; }
        else if (h->svc[0])                       { name = h->svc;  src = "mdns-svc"; }
        else if (h->mdns[0])                      { name = h->mdns; src = "mdns"; }
        else if (h->nbt[0])                       { name = h->nbt;  src = "netbios"; }
        else if (h->rdns[0])                      { name = h->rdns; src = "dns"; }
        else if (h->self && hostname[0])          { name = hostname; src = "self"; }
        else if ((cached = kv_get(&cache, mac)))  { name = cached;  src = "cached"; }
        else                                      { name = "?";     src = "-"; unnamed++; }
        if (!strcmp(src, "mdns-svc") || !strcmp(src, "mdns") || !strcmp(src, "netbios") || !strcmp(src, "dns")) {
            kv_put_front(&cache, mac, name);
            learned = true;
        }
        const char *vendor = oui_lookup(h->mac);
        if (!vendor) vendor = h->model[0] ? h->model : (h->mac[0] & 0x02) ? "(private MAC)" : "?";
        inet_ntop(AF_INET, &h->ip, rows[i][C_IP], NAME_LEN);
        cpy(rows[i][C_NAME], NAME_LEN, name);
        cpy(rows[i][C_SRC], NAME_LEN, src);
        cpy(rows[i][C_MAC], NAME_LEN, mac);
        cpy(rows[i][C_VENDOR], NAME_LEN, vendor);
        for (int c = 0; c < ncol; c++) { size_t l = display_width(rows[i][c]); if (l > w[c]) w[c] = l; }
    }
    for (int c = 0; c < ncol; c++) print_cell(hdr[c], w[c], c == ncol - 1);
    for (int i = 0; i < hl.n; i++)
        for (int c = 0; c < ncol; c++) print_cell(rows[i][c], w[c], c == ncol - 1);

    if (learned && kv_save(&cache, cache_path()) != 0)
        fprintf(stderr, "note: could not write cache %s\n", cache_path());
    if (show_vendor && !noui)
        fprintf(stderr, "\nnote: no OUI file for vendor names. Install arp-scan (brew/apt), or:\n"
                        "  curl -o ~/.config/lan-devices/oui.csv https://standards-oui.ieee.org/oui/oui.csv\n");
    if (passive)
        fprintf(stderr, "\n(passive: only devices already in the ARP table; run with sudo for a full sweep)\n");
    if (unnamed)
        printf("\n%d unnamed device(s). Label one with:  lan-devices --add <MAC> \"name\"\n", unnamed);
    return 0;
}
