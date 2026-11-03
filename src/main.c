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
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>

static const char *USAGE =
    "usage: lan-devices [-i IFACE] [-t SECONDS] [-6] [--no-vendor] [--passive]\n"
    "       lan-devices --watch [--interval SECONDS] [--listen [ADDR:]PORT] [scan options]\n"
    "       lan-devices --add MAC \"name\"      label a device permanently\n"
    "\n"
    "  -i IFACE      scan this interface (default: the one with the default route)\n"
    "  -t SECONDS    how long to listen for mDNS/NetBIOS answers (default 3)\n"
    "  -6            add an IPV6 column (best address: global > ULA > link-local)\n"
    "  --no-vendor   skip the OUI vendor column\n"
    "  --passive     don't sweep; list what the OS ARP/neighbour tables already know (no root)\n"
    "\n"
    "  --watch       keep scanning; log new/online/offline devices; serve HTTP:\n"
    "                /metrics (Prometheus), /devices.json, /healthz\n"
    "  --interval N  seconds between scans in watch mode (default 60)\n"
    "  --listen L    HTTP listen address in watch mode (default :9341)\n"
    "\n"
    "The sweep needs root (sudo). Files: ~/.config/lan-devices/{aliases,cache,seen}\n"
    "Env: LAN_DEVICES_DIR, LAN_DEVICES_ALIASES, LAN_DEVICES_CACHE, LAN_DEVICES_SEEN, LAN_DEVICES_OUI\n";

struct opts {
    const char *iface, *listen;
    double listen_s;
    int interval;
    bool vendor, passive, show6, watch;
};

static volatile sig_atomic_t stop_requested;
static void on_signal(int sig) { (void)sig; stop_requested = 1; }

static void print_cell(const char *s, size_t width, bool last) {
    fputs(s, stdout);
    if (last) { putchar('\n'); return; }
    for (int pad = (int)width - display_width(s) + 2; pad > 0; pad--) putchar(' ');
}

/* IPv4 hosts by address, then IPv6-only hosts by MAC */
static int by_ip(const void *a, const void *b) {
    const struct host *x = a, *y = b;
    if (!x->ip4.s_addr != !y->ip4.s_addr) return x->ip4.s_addr ? -1 : 1;
    if (x->ip4.s_addr) { uint32_t p = ntohl(x->ip4.s_addr), q = ntohl(y->ip4.s_addr); return p < q ? -1 : p > q; }
    return memcmp(x->mac, y->mac, 6);
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

/* One discovery cycle: who's up (sweep or neighbour tables), then names. */
static void discover(const struct iface *ifc, struct cap *cap, const struct opts *o, struct hostlist *hl) {
    struct host *self = hosts_add4(hl, ifc->mac, ifc->ip);
    self->self = true;
    if (ifc->have_ll6) hosts_add6(hl, ifc->mac, &ifc->ll6);
    for (int i = 0; i < ifc->npfx6; i++) hosts_add6(hl, ifc->mac, &ifc->pfx6[i].addr);
    if (cap) {
        nd6_probe(cap, ifc, 1);
        if (arp_sweep(cap, ifc, hl, 1.0) < 0) die("subnet on %s is larger than /16; pick a smaller one with -i", ifc->name);
        nd6_probe(cap, ifc, 2);
    } else if (arpcache_read(ifc, hl) < 0) {
        die("cannot read the ARP/neighbour tables");
    }
    qsort(hl->h, hl->n, sizeof *hl->h, by_ip);

    /* mDNS (v4+v6), NetBIOS and reverse DNS on one poll loop; the capture keeps
     * running so passive IPv6 chatter is attributed too; HTTP is served meanwhile */
    struct mdns *md = mdns_start(ifc, hl);
    struct nbns *nb = nbns_start(hl);
    struct rdns *rd = rdns_start(hl);
    struct pollfd pf[5] = { { mdns_fd(md), POLLIN, 0 }, { nbns_fd(nb), POLLIN, 0 }, { rdns_fd(rd), POLLIN, 0 },
                            { mdns_fd6(md), POLLIN, 0 }, { http_fd(), POLLIN, 0 } };
    double t0 = now_s(), deadline = t0 + o->listen_s;
    bool requeried = false;
    for (double now; (now = now_s()) < deadline;) {
        int ms = (int)((deadline - now) * 1000);
        poll(pf, 5, ms < 100 ? ms : 100);
        if (pf[0].revents & POLLIN) mdns_recv(md);
        if (pf[1].revents & POLLIN) nbns_recv(nb);
        if (pf[2].revents & POLLIN) rdns_recv(rd);
        if (pf[3].revents & POLLIN) mdns_recv(md);
        if (pf[4].revents & POLLIN) http_serve();
        cap_poll(cap);
        if (!requeried && now - t0 > 1.0) { mdns_query(md); nbns_query(nb); rdns_query(rd); requeried = true; }
    }
    mdns_finish(md);
    nbns_finish(nb);
    rdns_finish(rd);
    qsort(hl->h, hl->n, sizeof *hl->h, by_ip);   /* IPv6-only hosts may have appeared during the window */
}

/* Pick each host's display name by priority; learn names into the cache. */
static int name_hosts(struct hostlist *hl, const struct kvlist *aliases, struct kvlist *cache, bool *learned) {
    int unnamed = 0;
    static char hostname[NAME_LEN];
    if (!hostname[0]) { gethostname(hostname, sizeof hostname); char *dot = strchr(hostname, '.'); if (dot) *dot = 0; }
    for (int i = 0; i < hl->n; i++) {
        struct host *h = &hl->h[i];
        const char *mac = mac_str(h->mac), *alias, *cached;
        sanitize(h->svc); sanitize(h->mdns); sanitize(h->nbt); sanitize(h->rdns); sanitize(h->model);
        h->known = false;
        if      ((alias = kv_get(aliases, mac)))  { h->name = alias;    h->src = "alias"; h->known = true; }
        else if (h->svc[0])                       { h->name = h->svc;   h->src = "mdns-svc"; }
        else if (h->mdns[0])                      { h->name = h->mdns;  h->src = "mdns"; }
        else if (h->nbt[0])                       { h->name = h->nbt;   h->src = "netbios"; }
        else if (h->rdns[0])                      { h->name = h->rdns;  h->src = "dns"; }
        else if (h->self && hostname[0])          { h->name = hostname; h->src = "self"; }
        else if ((cached = kv_get(cache, mac)))   { h->name = cached;   h->src = "cached"; }
        else                                      { h->name = "?";      h->src = "-"; unnamed++; }
        if (!strcmp(h->src, "mdns-svc") || !strcmp(h->src, "mdns") || !strcmp(h->src, "netbios") || !strcmp(h->src, "dns")) {
            kv_put_front(cache, mac, h->name);
            *learned = true;
        }
        h->vendor = oui_lookup(h->mac);
        if (!h->vendor) h->vendor = h->model[0] ? h->model : (h->mac[0] & 0x02) ? "(private MAC)" : "?";
    }
    return unnamed;
}

static void print_table(const struct hostlist *hl, const struct opts *o) {
    enum { C_IP, C_NAME, C_SRC, C_MAC, C_VENDOR, C_IP6, NCOL };
    const char *hdr[NCOL] = { "IP", "NAME", "SOURCE", "MAC", "VENDOR", "IPV6" };
    int cols[NCOL], ncol = 0;
    cols[ncol++] = C_IP; cols[ncol++] = C_NAME; cols[ncol++] = C_SRC; cols[ncol++] = C_MAC;
    if (o->vendor) cols[ncol++] = C_VENDOR;
    if (o->show6) cols[ncol++] = C_IP6;
    char (*rows)[NCOL][NAME_LEN] = calloc(hl->n ? hl->n : 1, sizeof *rows);
    size_t w[NCOL];
    for (int c = 0; c < NCOL; c++) w[c] = strlen(hdr[c]);
    for (int i = 0; i < hl->n; i++) {
        const struct host *h = &hl->h[i];
        const struct in6_addr *b6 = host_best6(h);
        if (h->ip4.s_addr) inet_ntop(AF_INET, &h->ip4, rows[i][C_IP], NAME_LEN);
        else if (b6) inet_ntop(AF_INET6, b6, rows[i][C_IP], NAME_LEN);
        else cpy(rows[i][C_IP], NAME_LEN, "?");
        if (b6) inet_ntop(AF_INET6, b6, rows[i][C_IP6], NAME_LEN); else cpy(rows[i][C_IP6], NAME_LEN, "-");
        cpy(rows[i][C_NAME], NAME_LEN, h->name);
        cpy(rows[i][C_SRC], NAME_LEN, h->src);
        cpy(rows[i][C_MAC], NAME_LEN, mac_str(h->mac));
        cpy(rows[i][C_VENDOR], NAME_LEN, h->vendor);
        for (int c = 0; c < NCOL; c++) { size_t l = display_width(rows[i][c]); if (l > w[c]) w[c] = l; }
    }
    for (int k = 0; k < ncol; k++) print_cell(hdr[cols[k]], w[cols[k]], k == ncol - 1);
    for (int i = 0; i < hl->n; i++)
        for (int k = 0; k < ncol; k++) print_cell(rows[i][cols[k]], w[cols[k]], k == ncol - 1);
    free(rows);
}

/* ---- watch mode ---- */
static struct watch WATCH;

static void http_route(const char *path, char *body, size_t sz, const char **ctype) {
    if (!strcmp(path, "/metrics")) { *ctype = "text/plain; version=0.0.4; charset=utf-8"; watch_metrics(&WATCH, body, sz); }
    else if (!strcmp(path, "/devices.json")) { *ctype = "application/json"; watch_json(&WATCH, body, sz); }
    else if (!strcmp(path, "/healthz")) cpy(body, sz, "ok\n");
    else if (!strcmp(path, "/")) snprintf(body, sz, "lan-devices watch: %d devices known, %u scans\n\n/metrics\n/devices.json\n/healthz\n", WATCH.n, WATCH.scans);
}

static int watch_loop(const struct iface *ifc, struct cap *cap, const struct opts *o) {
    char err[256];
    if (http_start(o->listen, http_route, err, sizeof err) != 0) die("%s", err);
    watch_load(&WATCH, seen_path());
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "watching %s every %ds; %d devices remembered; http on %s (%s)\n",
            ifc->name, o->interval, WATCH.n, o->listen, cap ? "active sweep" : "passive");
    while (!stop_requested) {
        double t0 = now_s();
        struct hostlist hl = { 0 };
        struct kvlist aliases = { 0 }, cache = { 0 };
        bool learned = false;
        kv_load(&aliases, aliases_path());
        kv_load(&cache, cache_path());
        discover(ifc, cap, o, &hl);
        name_hosts(&hl, &aliases, &cache, &learned);
        WATCH.last_scan_dur = now_s() - t0;
        watch_update(&WATCH, &hl, (double)time(NULL), o->vendor);
        if (learned) kv_save(&cache, cache_path());
        if (watch_save(&WATCH, seen_path()) != 0) fprintf(stderr, "note: could not write %s\n", seen_path());
        free(hl.h); free(aliases.v); free(cache.v);
        for (double until = t0 + o->interval; !stop_requested && now_s() < until;) idle_ms(250);
    }
    fprintf(stderr, "stopping\n");
    return 0;
}

int main(int argc, char **argv) {
    struct opts o = { .listen = ":9341", .listen_s = 3.0, .interval = 60, .vendor = true };

    if (argc >= 2 && !strcmp(argv[1], "--add")) {
        if (argc != 4) die("usage: lan-devices --add MAC \"name\"");
        return do_add(argv[2], argv[3]);
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) o.iface = argv[++i];
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) o.listen_s = atof(argv[++i]);
        else if (!strcmp(argv[i], "--interval") && i + 1 < argc) o.interval = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc) o.listen = argv[++i];
        else if (!strcmp(argv[i], "--no-vendor")) o.vendor = false;
        else if (!strcmp(argv[i], "-6")) o.show6 = true;
        else if (!strcmp(argv[i], "--passive")) o.passive = true;
        else if (!strcmp(argv[i], "--watch")) o.watch = true;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { fputs(USAGE, stdout); return 0; }
        else die("unknown arg %s\n%s", argv[i], USAGE);
    }
    if (o.listen_s < 0.5) o.listen_s = 0.5;
    if (o.interval < 5) o.interval = 5;

    struct iface ifc;
    char err[256];
    if (iface_detect(o.iface, &ifc, err, sizeof err) != 0) die("%s", err);

    struct hostlist hl = { 0 };
    struct cap *cap = NULL;
    if (!o.passive) {
        cap = cap_open(&ifc, &hl, err, sizeof err);
        if (!cap) {
            if (geteuid() != 0)
                fprintf(stderr, "note: the sweep needs root (run with sudo); showing the OS ARP/neighbour tables instead\n");
            else
                fprintf(stderr, "note: sweep unavailable (%s); showing the OS ARP/neighbour tables instead\n", err);
            o.passive = true;
        }
    }
    drop_privs();
    int noui = o.vendor ? oui_load(getenv("LAN_DEVICES_OUI")) : 1;
    if (o.vendor && !noui)
        fprintf(stderr, "note: no OUI file for vendor names. Install arp-scan (brew/apt), or:\n"
                        "  curl -o ~/.config/lan-devices/oui.csv https://standards-oui.ieee.org/oui/oui.csv\n");

    if (o.watch) { int rc = watch_loop(&ifc, cap, &o); cap_close(cap); return rc; }

    struct kvlist aliases = { 0 }, cache = { 0 };
    bool learned = false;
    kv_load(&aliases, aliases_path());
    kv_load(&cache, cache_path());
    discover(&ifc, cap, &o, &hl);
    cap_close(cap);
    int unnamed = name_hosts(&hl, &aliases, &cache, &learned);
    print_table(&hl, &o);

    if (learned && kv_save(&cache, cache_path()) != 0)
        fprintf(stderr, "note: could not write cache %s\n", cache_path());
    if (g_send_errors)
        fprintf(stderr, "\nwarning: %u packet(s) could not be sent; results may be incomplete\n", g_send_errors);
    if (o.passive)
        fprintf(stderr, "\n(passive: only devices already in the ARP/neighbour tables; run with sudo for a full sweep)\n");
    if (unnamed)
        printf("\n%d unnamed device(s). Label one with:  lan-devices --add <MAC> \"name\"\n", unnamed);
    return 0;
}
