/* Unit tests for every function that parses bytes off the network or a file.
 * Build and run with `make check`. Also writes a libFuzzer seed corpus with
 * `--dump-corpus DIR` (used by `make fuzz`). */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_STR(a, b) do { checks++; if (strcmp((a), (b))) { fails++; fprintf(stderr, "FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); } } while (0)

/* ---- tiny packet builder ---- */
struct pb { uint8_t b[2048]; int n; };
static void p8(struct pb *p, unsigned v)  { p->b[p->n++] = (uint8_t)v; }
static void p16(struct pb *p, unsigned v) { p8(p, v >> 8); p8(p, v & 0xff); }
static void p32(struct pb *p, unsigned v) { p16(p, v >> 16); p16(p, v & 0xffff); }
static void pname(struct pb *p, const char *s) { p->n = dns_put_name(p->b, p->n, s); }
static void praw(struct pb *p, const void *d, int n) { memcpy(p->b + p->n, d, n); p->n += n; }
static void dns_hdr(struct pb *p, unsigned flags, int qd, int an, int ns, int ar) {
    p->n = 0; p16(p, 0); p16(p, flags); p16(p, qd); p16(p, an); p16(p, ns); p16(p, ar);
}
/* RR with rdata supplied by a callback-free two step: write header, then rdata, then patch rdlen */
static int rr_begin(struct pb *p, const char *name, int type) {
    pname(p, name); p16(p, type); p16(p, 1); p32(p, 120); p16(p, 0); return p->n;   /* returns rdata offset */
}
static void rr_end(struct pb *p, int rd) { int len = p->n - rd; p->b[rd - 2] = len >> 8; p->b[rd - 1] = len & 0xff; }
static void rr_a(struct pb *p, const char *name, const char *ip) {
    int rd = rr_begin(p, name, 1); struct in_addr a; inet_pton(AF_INET, ip, &a); praw(p, &a, 4); rr_end(p, rd);
}
static void rr_aaaa(struct pb *p, const char *name, const char *ip) {
    int rd = rr_begin(p, name, 28); struct in6_addr a; inet_pton(AF_INET6, ip, &a); praw(p, &a, 16); rr_end(p, rd);
}
static void rr_ptr(struct pb *p, const char *name, const char *target) {
    int rd = rr_begin(p, name, 12); pname(p, target); rr_end(p, rd);
}
static void rr_srv(struct pb *p, const char *name, const char *target) {
    int rd = rr_begin(p, name, 33); p16(p, 0); p16(p, 0); p16(p, 7000); pname(p, target); rr_end(p, rd);
}
static void rr_txt(struct pb *p, const char *name, const char **kv) {
    int rd = rr_begin(p, name, 16);
    for (; *kv; kv++) { int l = (int)strlen(*kv); p8(p, l); praw(p, *kv, l); }
    rr_end(p, rd);
}

/* ---- dns_name_read ---- */
static void test_dns_name(void) {
    struct pb p = { 0 };
    struct dname d;
    pname(&p, "Office speaker._airplay._tcp.local");
    int off = dns_name_read(p.b, p.n, 0, &d);
    CHECK(off == p.n);
    CHECK_STR(d.full, "Office speaker._airplay._tcp.local");
    CHECK_STR(d.first, "Office speaker");
    CHECK_STR(d.rest, "_airplay._tcp.local");

    /* compression pointer back to offset 0, after a leading label */
    int start = p.n;
    p8(&p, 3); praw(&p, "foo", 3); p8(&p, 0xc0); p8(&p, 0);
    off = dns_name_read(p.b, p.n, start, &d);
    CHECK(off == p.n);
    CHECK_STR(d.full, "foo.Office speaker._airplay._tcp.local");
    CHECK_STR(d.first, "foo");

    /* root name */
    uint8_t root[1] = { 0 };
    CHECK(dns_name_read(root, 1, 0, &d) == 1 && d.full[0] == 0);

    /* UTF-8 and a dot inside a label survive in `first` */
    p.n = 0; p8(&p, 11); praw(&p, "Jacob\xe2\x80\x99s.1", 11); p8(&p, 5); praw(&p, "local", 5); p8(&p, 0);
    CHECK(dns_name_read(p.b, p.n, 0, &d) == p.n);
    CHECK_STR(d.first, "Jacob\xe2\x80\x99s.1");
    CHECK_STR(d.rest, "local");

    /* malformed: pointer loop, truncated label, pointer past end, reserved label type, bad offset */
    uint8_t loop[2] = { 0xc0, 0x00 };
    CHECK(dns_name_read(loop, 2, 0, &d) == -1);
    uint8_t trunc[3] = { 5, 'a', 'b' };
    CHECK(dns_name_read(trunc, 3, 0, &d) == -1);
    uint8_t far[2] = { 0xc0, 0x50 };
    CHECK(dns_name_read(far, 2, 0, &d) == -1);
    uint8_t half_ptr[1] = { 0xc0 };
    CHECK(dns_name_read(half_ptr, 1, 0, &d) == -1);
    uint8_t reserved[2] = { 0x40, 0 };
    CHECK(dns_name_read(reserved, 2, 0, &d) == -1);
    CHECK(dns_name_read(root, 1, 5, &d) == -1);
    CHECK(dns_name_read(root, 1, -1, &d) == -1);

    /* a name longer than the buffers is truncated, never overflowed */
    p.n = 0;
    for (int i = 0; i < 12; i++) { p8(&p, 63); for (int k = 0; k < 63; k++) p8(&p, 'a' + i); }
    p8(&p, 0);
    CHECK(dns_name_read(p.b, p.n, 0, &d) == p.n);
    CHECK(strlen(d.full) == sizeof d.full - 1);
    CHECK(strlen(d.first) == 63);
}

/* ---- dns_txt_get ---- */
static void test_txt(void) {
    const char *kv[] = { "id=abc", "fn=Living Room", "md=Chromecast Ultra", "fnx=wrong", "flag", NULL };
    struct pb p = { 0 };
    for (const char **k = kv; *k; k++) { int l = (int)strlen(*k); p8(&p, l); praw(&p, *k, l); }
    char out[64];
    CHECK(dns_txt_get(p.b, p.n, "fn", out, sizeof out)); CHECK_STR(out, "Living Room");
    CHECK(dns_txt_get(p.b, p.n, "md", out, sizeof out)); CHECK_STR(out, "Chromecast Ultra");
    CHECK(!dns_txt_get(p.b, p.n, "f", out, sizeof out));
    CHECK(!dns_txt_get(p.b, p.n, "flag", out, sizeof out));
    CHECK(!dns_txt_get(p.b, p.n, "nope", out, sizeof out));
    uint8_t bad[3] = { 9, 'f', 'n' };                      /* length runs past the end */
    CHECK(!dns_txt_get(bad, 3, "fn", out, sizeof out));
    uint8_t empty[3] = { 2, 'x', '=' };                     /* key with empty value */
    CHECK(!dns_txt_get(empty, 3, "x", out, sizeof out));
    CHECK(dns_txt_get(p.b, p.n, "fn", out, 4)); CHECK_STR(out, "Liv");   /* truncates to buffer */
}

/* ---- mDNS response handling end to end ---- */
static struct iface IFC;
static struct hostlist HL;
static struct host *add_host(const char *ip) {
    struct in_addr a; inet_pton(AF_INET, ip, &a);
    uint8_t mac[6] = { 0, 1, 2, 3, 4, (uint8_t)(a.s_addr >> 24) };
    return hosts_add4(&HL, mac, a);
}
static void reset_hosts(void) {
    free(HL.h); memset(&HL, 0, sizeof HL);
    add_host("192.168.0.1"); add_host("192.168.0.153"); add_host("192.168.0.238"); add_host("192.168.0.182");
}
static struct host *host(const char *ip) { struct in_addr a; inet_pton(AF_INET, ip, &a); return hosts_find4(&HL, a); }

static void build_mdns_response(struct pb *p) {
    dns_hdr(p, 0x8400, 0, 0, 0, 0);
    int rrs = 0;
    /* AirPlay speaker: PTR -> SRV -> A, TXT with model= */
    rr_ptr(p, "_airplay._tcp.local", "Office speaker._airplay._tcp.local"); rrs++;
    rr_srv(p, "Office speaker._airplay._tcp.local", "Office-speaker.local"); rrs++;
    const char *txt1[] = { "model=AudioAccessory1,1", "srcvers=366.0", NULL };
    rr_txt(p, "Office speaker._airplay._tcp.local", txt1); rrs++;
    rr_a(p, "Office-speaker.local", "192.168.0.238"); rrs++;
    /* Chromecast TV: friendly name from fn=, model from md= */
    rr_ptr(p, "_googlecast._tcp.local", "Chromecast-abcdef._googlecast._tcp.local"); rrs++;
    rr_srv(p, "Chromecast-abcdef._googlecast._tcp.local", "abcdef.local"); rrs++;
    const char *txt2[] = { "id=abcdef", "fn=Living Room", "md=Vizio TV", NULL };
    rr_txt(p, "Chromecast-abcdef._googlecast._tcp.local", txt2); rrs++;
    rr_a(p, "abcdef.local", "192.168.0.153"); rrs++;
    /* RAOP on the same TV with lower priority and a MAC@ prefix: must not override fn= */
    rr_ptr(p, "_raop._tcp.local", "24EE5D063278@Living Room TV._raop._tcp.local"); rrs++;
    rr_srv(p, "24EE5D063278@Living Room TV._raop._tcp.local", "abcdef.local"); rrs++;
    /* a Mac: _device-info has TXT only; hostname via A record; companion-link gives the name */
    const char *txt3[] = { "model=MacBookPro16,1", "osxvers=24", NULL };
    rr_txt(p, "Cassidys-MBP._device-info._tcp.local", txt3); rrs++;
    rr_a(p, "Cassidys-MBP.local", "192.168.0.182"); rrs++;
    rr_ptr(p, "_companion-link._tcp.local", "Cassidy\xe2\x80\x99s MacBook Pro._companion-link._tcp.local"); rrs++;
    rr_srv(p, "Cassidy\xe2\x80\x99s MacBook Pro._companion-link._tcp.local", "Cassidys-MBP.local"); rrs++;
    /* reverse PTR for the router */
    rr_ptr(p, "1.0.168.192.in-addr.arpa", "opnsense.local"); rrs++;
    /* an unknown service type and an A record for an IP we don't know: ignored */
    rr_ptr(p, "_spotify-connect._tcp.local", "Whatever._spotify-connect._tcp.local"); rrs++;
    rr_a(p, "stranger.local", "10.9.9.9"); rrs++;
    p->b[7] = (uint8_t)rrs;   /* ancount */
}

static void test_mdns(void) {
    reset_hosts();
    struct pb p = { 0 };
    build_mdns_response(&p);
    struct mdns *m = mdns_new(&IFC, &HL);
    mdns_handle(m, p.b, p.n);
    mdns_finish(m);
    CHECK_STR(host("192.168.0.238")->svc, "Office speaker");
    CHECK_STR(host("192.168.0.238")->mdns, "Office-speaker");
    CHECK_STR(host("192.168.0.238")->model, "AudioAccessory1,1");
    CHECK_STR(host("192.168.0.153")->svc, "Living Room");
    CHECK_STR(host("192.168.0.153")->model, "Vizio TV");
    CHECK_STR(host("192.168.0.182")->svc, "Cassidy\xe2\x80\x99s MacBook Pro");
    CHECK_STR(host("192.168.0.182")->model, "MacBookPro16,1");
    CHECK_STR(host("192.168.0.182")->mdns, "Cassidys-MBP");
    CHECK_STR(host("192.168.0.1")->mdns, "opnsense");
    CHECK(host("192.168.0.1")->svc[0] == 0);

    /* IPv6-only device: AAAA target and an ip6.arpa reverse answer */
    reset_hosts();
    uint8_t m6[6] = { 0xde, 0xad, 0, 0, 0, 1 };
    struct in6_addr a6; inet_pton(AF_INET6, "fe80::dead:1", &a6);
    hosts_add6(&HL, m6, &a6);
    dns_hdr(&p, 0x8400, 0, 4, 0, 0);
    rr_ptr(&p, "_airplay._tcp.local", "Attic TV._airplay._tcp.local");
    rr_srv(&p, "Attic TV._airplay._tcp.local", "attic.local");
    rr_aaaa(&p, "attic.local", "fe80::dead:1");
    char rev6[96]; ip6_arpa(&a6, rev6, sizeof rev6);
    CHECK_STR(rev6, "1.0.0.0.d.a.e.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa");
    rr_ptr(&p, rev6, "attic-rev.local");
    m = mdns_new(&IFC, &HL); mdns_handle(m, p.b, p.n); mdns_finish(m);
    CHECK_STR(hosts_find6(&HL, &a6)->svc, "Attic TV");
    CHECK_STR(hosts_find6(&HL, &a6)->mdns, "attic-rev");

    /* RAOP alone (no higher-priority name): MAC@ prefix is stripped */
    reset_hosts();
    dns_hdr(&p, 0x8400, 0, 3, 0, 0);
    rr_ptr(&p, "_raop._tcp.local", "24EE5D063278@Bedroom TV._raop._tcp.local");
    rr_srv(&p, "24EE5D063278@Bedroom TV._raop._tcp.local", "tv.local");
    rr_a(&p, "tv.local", "192.168.0.153");
    m = mdns_new(&IFC, &HL); mdns_handle(m, p.b, p.n); mdns_finish(m);
    CHECK_STR(host("192.168.0.153")->svc, "Bedroom TV");

    /* queries (QR=0) are ignored; records split across two packets still combine */
    reset_hosts();
    build_mdns_response(&p);
    p.b[2] = 0;
    m = mdns_new(&IFC, &HL); mdns_handle(m, p.b, p.n); mdns_finish(m);
    CHECK(host("192.168.0.238")->svc[0] == 0);

    reset_hosts();
    m = mdns_new(&IFC, &HL);
    dns_hdr(&p, 0x8400, 0, 1, 0, 0); rr_srv(&p, "Office speaker._airplay._tcp.local", "Office-speaker.local");
    mdns_handle(m, p.b, p.n);
    dns_hdr(&p, 0x8400, 0, 2, 0, 0); rr_ptr(&p, "_airplay._tcp.local", "Office speaker._airplay._tcp.local"); rr_a(&p, "Office-speaker.local", "192.168.0.238");
    mdns_handle(m, p.b, p.n);
    mdns_finish(m);
    CHECK_STR(host("192.168.0.238")->svc, "Office speaker");

    /* robustness: every truncation of a valid packet, and random mutations, must not crash */
    build_mdns_response(&p);
    for (int cut = 0; cut <= p.n; cut++) {
        reset_hosts();
        m = mdns_new(&IFC, &HL); mdns_handle(m, p.b, cut); mdns_finish(m);
    }
    srand(1234);
    for (int iter = 0; iter < 3000; iter++) {
        struct pb q = p;
        int flips = 1 + rand() % 8;
        for (int k = 0; k < flips; k++) q.b[rand() % q.n] = (uint8_t)rand();
        reset_hosts();
        m = mdns_new(&IFC, &HL); mdns_handle(m, q.b, q.n); mdns_finish(m);
    }
    checks++;   /* survived */
}

/* ---- IPv6: host model, prefixes, reverse names ---- */
static void test_ip6_model(void) {
    struct hostlist hl = { 0 };
    uint8_t m1[6] = { 0xaa, 1, 1, 1, 1, 1 }, m2[6] = { 0xaa, 2, 2, 2, 2, 2 };
    struct in_addr v4; inet_pton(AF_INET, "192.168.0.50", &v4);
    struct in6_addr ll, gl, ula;
    inet_pton(AF_INET6, "fe80::1", &ll);
    inet_pton(AF_INET6, "2001:db8:1::50", &gl);
    inet_pton(AF_INET6, "fd00::50", &ula);
    /* same MAC seen via ARP, then via IPv6: one row */
    hosts_add4(&hl, m1, v4);
    hosts_add6(&hl, m1, &ll);
    hosts_add6(&hl, m1, &ll);                 /* duplicate ignored */
    hosts_add6(&hl, m1, &ula);
    hosts_add6(&hl, m1, &gl);
    CHECK(hl.n == 1 && hl.h[0].n6 == 3);
    CHECK(hosts_find6(&hl, &gl) == &hl.h[0]);
    CHECK(hosts_find4(&hl, v4) == &hl.h[0]);
    CHECK(!memcmp(host_best6(&hl.h[0]), &gl, 16));    /* global beats ULA beats link-local */
    /* IPv6-only device */
    hosts_add6(&hl, m2, &ll);
    CHECK(hl.n == 2 && hl.h[1].ip4.s_addr == 0 && hl.h[1].n6 == 1);
    CHECK(host_best6(&hl.h[0]) != NULL && host_best6(&hl.h[1]) != NULL);
    /* a second IPv4 for the same MAC does not replace the first */
    struct in_addr v4b; inet_pton(AF_INET, "192.168.0.51", &v4b);
    hosts_add4(&hl, m1, v4b);
    CHECK(hl.n == 2 && hl.h[0].ip4.s_addr == v4.s_addr);
    free(hl.h);

    /* on_link6: link-local always; otherwise only inside a configured prefix */
    struct iface ifc = { 0 };
    inet_pton(AF_INET6, "2601:207:400:fd2::", &ifc.pfx6[0].addr); ifc.pfx6[0].plen = 64;
    inet_pton(AF_INET6, "fd12:3456::", &ifc.pfx6[1].addr); ifc.pfx6[1].plen = 60;
    ifc.npfx6 = 2;
    struct in6_addr t;
    inet_pton(AF_INET6, "fe80::abcd", &t);            CHECK(on_link6(&ifc, &t));
    inet_pton(AF_INET6, "2601:207:400:fd2:1::9", &t); CHECK(on_link6(&ifc, &t));
    inet_pton(AF_INET6, "2601:207:400:fd3::9", &t);   CHECK(!on_link6(&ifc, &t));
    inet_pton(AF_INET6, "fd12:3456:0:f::1", &t);      CHECK(on_link6(&ifc, &t));   /* inside /60 */
    inet_pton(AF_INET6, "fd12:3456:0:10::1", &t);     CHECK(!on_link6(&ifc, &t));  /* outside /60 */
    inet_pton(AF_INET6, "2a00::1", &t);               CHECK(!on_link6(&ifc, &t));

    char name[96];
    inet_pton(AF_INET6, "2001:db8::1", &t);
    ip6_arpa(&t, name, sizeof name);
    CHECK_STR(name, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
}

/* ---- ICMPv6 echo frame ---- */
static void test_nd6(void) {
    /* RFC-style check: a correct packet's checksum field verifies to zero */
    struct iface ifc = IFC;
    inet_pton(AF_INET6, "fe80::1", &ifc.ll6); ifc.have_ll6 = true;
    memcpy(ifc.mac, (uint8_t[]){ 0xf6, 0x75, 0x90, 0xb8, 0xf6, 0x91 }, 6);
    uint8_t f[70];
    CHECK(nd6_build_echo(&ifc, f, sizeof f, 7) == 70);
    CHECK(f[0] == 0x33 && f[1] == 0x33 && f[5] == 0x01);         /* all-nodes multicast MAC */
    CHECK(f[12] == 0x86 && f[13] == 0xdd && f[14 + 6] == 58);
    CHECK(f[54] == 128 && f[61] == 7);                            /* echo request, seq */
    struct in6_addr dst; memcpy(&dst, f + 14 + 24, 16);
    CHECK(icmp6_checksum(&ifc.ll6, &dst, f + 54, 16) == 0);       /* includes the checksum field: must be 0 */
    ifc.have_ll6 = false;
    CHECK(nd6_build_echo(&ifc, f, sizeof f, 1) == -1);
    CHECK(nd6_build_echo(&IFC, f, 10, 1) == -1);
}

/* ---- frame classification (cap_frame) ---- */
static int eth(uint8_t *f, const uint8_t *src, unsigned et) {
    memset(f, 0xff, 6); memcpy(f + 6, src, 6); f[12] = et >> 8; f[13] = et & 0xff; return 14;
}
static void test_cap(void) {
    struct iface ifc = IFC;
    memcpy(ifc.mac, (uint8_t[]){ 0xf6, 0x75, 0x90, 0xb8, 0xf6, 0x91 }, 6);
    inet_pton(AF_INET6, "2601:207:400:fd2::", &ifc.pfx6[0].addr); ifc.pfx6[0].plen = 64; ifc.npfx6 = 1;
    struct hostlist hl = { 0 };
    struct cap *c = cap_new(&ifc, &hl);
    uint8_t dev[6] = { 0x24, 0xee, 0x5d, 6, 0x32, 0x78 }, router[6] = { 0x60, 0xbe, 0xb4, 3, 0x1e, 0xc6 };
    uint8_t f[128];

    /* ARP reply from a device */
    int n = eth(f, dev, 0x0806);
    uint8_t arp[28] = { 0, 1, 8, 0, 6, 4, 0, 2 };
    memcpy(arp + 8, dev, 6); inet_pton(AF_INET, "192.168.0.153", arp + 14);
    memcpy(f + n, arp, 28);
    cap_frame(c, f, n + 28);
    CHECK(hl.n == 1 && !memcmp(hl.h[0].mac, dev, 6));
    /* ARP request from another host also reveals it; sender 0.0.0.0 (probe) does not */
    arp[7] = 1; memcpy(arp + 8, router, 6); inet_pton(AF_INET, "192.168.0.1", arp + 14);
    memcpy(f + n, arp, 28); cap_frame(c, f, n + 28);
    CHECK(hl.n == 2);
    uint8_t other[6] = { 2, 2, 2, 2, 2, 2 };
    memcpy(arp + 8, other, 6); memset(arp + 14, 0, 4); memcpy(f + n, arp, 28); cap_frame(c, f, n + 28);
    CHECK(hl.n == 2);
    /* off-subnet sender and our own MAC are ignored */
    inet_pton(AF_INET, "10.0.0.5", arp + 14); memcpy(f + n, arp, 28); cap_frame(c, f, n + 28);
    CHECK(hl.n == 2);
    n = eth(f, ifc.mac, 0x0806); arp[7] = 2; memcpy(arp + 8, ifc.mac, 6); inet_pton(AF_INET, "192.168.0.228", arp + 14);
    memcpy(f + n, arp, 28); cap_frame(c, f, n + 28);
    CHECK(hl.n == 2);

    /* IPv6 from the TV's link-local: attributed to the same row as its ARP reply */
    n = eth(f, dev, 0x86dd);
    memset(f + n, 0, 40); f[n] = 0x60; f[n + 6] = 58; f[n + 7] = 255;
    inet_pton(AF_INET6, "fe80::26ee:5dff:fe06:3278", f + n + 8);
    inet_pton(AF_INET6, "ff02::1", f + n + 24);
    cap_frame(c, f, n + 40);
    CHECK(hl.n == 2 && hl.h[0].n6 == 1);
    /* global address inside our prefix: accepted. Outside it (forwarded by the router): not */
    inet_pton(AF_INET6, "2601:207:400:fd2:1234::5", f + n + 8); cap_frame(c, f, n + 40);
    CHECK(hl.h[0].n6 == 2);
    n = eth(f, router, 0x86dd);
    memset(f + n, 0, 40); f[n] = 0x60; f[n + 6] = 6;
    inet_pton(AF_INET6, "2a03:2880:f12f:83:face:b00c::25de", f + n + 8);     /* some internet host via the router */
    cap_frame(c, f, n + 40);
    CHECK(hl.n == 2 && hl.h[1].n6 == 0);
    /* unspecified / multicast sources, multicast source MAC, bad version, short frames */
    inet_pton(AF_INET6, "::", f + n + 8); cap_frame(c, f, n + 40);
    inet_pton(AF_INET6, "ff02::fb", f + n + 8); cap_frame(c, f, n + 40);
    CHECK(hl.h[1].n6 == 0);
    f[6] |= 1; inet_pton(AF_INET6, "fe80::9", f + n + 8); cap_frame(c, f, n + 40);
    CHECK(hl.n == 2);
    f[6] &= ~1; f[n] = 0x40; cap_frame(c, f, n + 40);
    CHECK(hl.h[1].n6 == 0);
    for (int cut = 0; cut < n + 40; cut++) cap_frame(c, f, cut);
    CHECK(hl.n == 2);
    cap_close(c);
    free(hl.h);
}

/* ---- NetBIOS ---- */
static void build_nbns_reply(struct pb *p, bool group_first) {
    p->n = 0;
    p16(p, 0x4c44); p16(p, 0x8400); p16(p, 0); p16(p, 1); p16(p, 0); p16(p, 0);
    p8(p, 0x20); for (int i = 0; i < 32; i++) p8(p, i < 2 ? "CK"[i] : 'A'); p8(p, 0);   /* name "*" */
    p16(p, 0x21); p16(p, 1); p32(p, 0);
    int rdlen_off = p->n; p16(p, 0);
    p8(p, 3);                                                   /* three names */
    const char *names[3] = { group_first ? "WORKGROUP" : "DESKTOP-ABC", group_first ? "DESKTOP-ABC" : "WORKGROUP", "DESKTOP-ABC" };
    unsigned flags[3]    = { group_first ? 0x8400 : 0x0400,     group_first ? 0x0400 : 0x8400,     0x0400 };
    uint8_t suffix[3]    = { 0x00, 0x00, 0x20 };
    for (int i = 0; i < 3; i++) {
        char nm[15]; memset(nm, ' ', 15); memcpy(nm, names[i], strlen(names[i]));
        praw(p, nm, 15); p8(p, suffix[i]); p16(p, flags[i]);
    }
    for (int i = 0; i < 6; i++) p8(p, 0x11);                   /* unit id (MAC) */
    int rdlen = p->n - rdlen_off - 2; p->b[rdlen_off] = rdlen >> 8; p->b[rdlen_off + 1] = rdlen & 0xff;
}
static void test_nbns(void) {
    struct pb p; char out[NAME_LEN];
    build_nbns_reply(&p, true);
    CHECK(nbns_parse_reply(p.b, p.n, out, sizeof out)); CHECK_STR(out, "DESKTOP-ABC");
    build_nbns_reply(&p, false);
    CHECK(nbns_parse_reply(p.b, p.n, out, sizeof out)); CHECK_STR(out, "DESKTOP-ABC");
    p.b[2] = 0;                                                 /* a query, not a response */
    CHECK(!nbns_parse_reply(p.b, p.n, out, sizeof out));
    build_nbns_reply(&p, true);
    for (int cut = 0; cut < p.n; cut++) nbns_parse_reply(p.b, cut, out, sizeof out);
    CHECK(!nbns_parse_reply(p.b, 60, out, sizeof out));
    checks++;
}

/* ---- OUI ---- */
static void test_oui(void) {
    char hex[13]; int hl; const char *name;
    char l1[] = "0000F0\tSAMSUNG ELECTRONICS CO., LTD.\n";
    CHECK(oui_parse_line(l1, hex, &hl, &name) && hl == 6 && !strncmp(hex, "0000F0", 6) && !strncmp(name, "SAMSUNG", 7));
    char l2[] = "00-00-0F   (hex)\t\tNEXT, INC.\n";
    CHECK(oui_parse_line(l2, hex, &hl, &name) && hl == 6 && !strncmp(hex, "00000F", 6) && !strncmp(name, "NEXT, INC.", 10));
    char l3[] = "MA-L,000000,XEROX CORPORATION,70 Linden St\n";
    CHECK(oui_parse_line(l3, hex, &hl, &name) && hl == 6 && !strcmp(name, "XEROX CORPORATION"));
    char l4[] = "MA-S,70B3D5FFF,\"Thomas, Conrad Corp.\",1908 Kramer Lane\n";
    CHECK(oui_parse_line(l4, hex, &hl, &name) && hl == 9 && !strcmp(name, "Thomas, Conrad Corp."));
    char l5[] = "\t\t\t\t3475 Deer Creek Rd\n";            /* address line: 4 hex digits, no tab */
    CHECK(!oui_parse_line(l5, hex, &hl, &name));
    char l6[] = "# comment\n";
    CHECK(!oui_parse_line(l6, hex, &hl, &name));
    char l7[] = "Registry,Assignment,Organization Name,Organization Address\n";
    CHECK(!oui_parse_line(l7, hex, &hl, &name));
    char l8[] = "MA-L,ZZZZZZ,Bad\n";
    CHECK(!oui_parse_line(l8, hex, &hl, &name));
    char l9[] = "0000F0\t\n";                                   /* empty name */
    CHECK(!oui_parse_line(l9, hex, &hl, &name));

    char path[] = "/tmp/lan-devices-oui-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fputs("# test file\n0000F0\tSamsung\nMA-S,70B3D5FFF,\"Niche, Inc.\",addr\n70B3D5\tIEEE Registration Authority\n", f);
    fclose(f);
    CHECK(oui_load(path) == 3);
    unlink(path);
    uint8_t m1[6] = { 0x00, 0x00, 0xf0, 1, 2, 3 }, m2[6] = { 0x70, 0xb3, 0xd5, 0xff, 0xf1, 0x00 }, m3[6] = { 0x70, 0xb3, 0xd5, 0x00, 0, 0 }, m4[6] = { 9, 9, 9, 9, 9, 9 };
    CHECK_STR(oui_lookup(m1), "Samsung");
    CHECK_STR(oui_lookup(m2), "Niche, Inc.");                   /* longest prefix wins */
    CHECK_STR(oui_lookup(m3), "IEEE Registration Authority");
    CHECK(oui_lookup(m4) == NULL);
}

/* ---- alias / cache store ---- */
static void test_store(void) {
    char path[] = "/tmp/lan-devices-kv-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fputs("# my labels\n\nAA:BB:CC:DD:EE:FF\tLiving room TV\n00:11:22:33:44:55   Name with  spaces \n", f);
    fclose(f);
    struct kvlist l = { 0 };
    kv_load(&l, path);
    CHECK(l.n == 2);
    CHECK_STR(kv_get(&l, "aa:bb:cc:dd:ee:ff"), "Living room TV");
    CHECK_STR(kv_get(&l, "00:11:22:33:44:55"), "Name with  spaces ");
    CHECK(kv_get(&l, "ff:ff:ff:ff:ff:ff") == NULL);
    kv_put_front(&l, "AA:BB:CC:DD:EE:FF", "Renamed");
    CHECK(l.n == 2 && !strcmp(l.v[0].mac, "aa:bb:cc:dd:ee:ff") && !strcmp(l.v[0].name, "Renamed"));
    kv_put_front(&l, "de:ad:be:ef:00:01", "New");
    CHECK(l.n == 3 && !strcmp(l.v[0].name, "New") && !strcmp(l.v[1].name, "Renamed"));
    CHECK(kv_save(&l, path) == 0);
    struct kvlist l2 = { 0 };
    kv_load(&l2, path);
    CHECK(l2.n == 3);
    CHECK_STR(kv_get(&l2, "de:ad:be:ef:00:01"), "New");
    CHECK_STR(kv_get(&l2, "aa:bb:cc:dd:ee:ff"), "Renamed");
    unlink(path);
    free(l.v); free(l2.v);
}

/* ---- misc helpers ---- */
static void test_util(void) {
    CHECK(display_width("abc") == 3);
    CHECK(display_width("Jacob\xe2\x80\x99s") == 7);
    char b[4]; cpy(b, sizeof b, "toolong"); CHECK_STR(b, "too");
    uint8_t mac[6] = { 0xf6, 0x75, 0x90, 0xb8, 0xf6, 0x91 };
    CHECK_STR(mac_str(mac), "f6:75:90:b8:f6:91");
    struct in_addr in; inet_pton(AF_INET, "192.168.0.77", &in);
    CHECK(in_subnet(&IFC, in));
    inet_pton(AF_INET, "10.0.0.1", &in);
    CHECK(!in_subnet(&IFC, in));
}

/* ---- HTTP request line ---- */
static void test_http(void) {
    char path[64];
    CHECK(http_parse_request("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", path, sizeof path) == 0); CHECK_STR(path, "/metrics");
    CHECK(http_parse_request("HEAD /devices.json?x=1 HTTP/1.0\r\n", path, sizeof path) == 0); CHECK_STR(path, "/devices.json");
    CHECK(http_parse_request("GET / HTTP/1.1\r\n", path, sizeof path) == 0); CHECK_STR(path, "/");
    CHECK(http_parse_request("POST /metrics HTTP/1.1\r\n", path, sizeof path) != 0);
    CHECK(http_parse_request("GET metrics HTTP/1.1\r\n", path, sizeof path) != 0);
    CHECK(http_parse_request("GET  HTTP/1.1\r\n", path, sizeof path) != 0);
    char longreq[300] = "GET /";
    memset(longreq + 5, 'a', 200); strcpy(longreq + 205, " HTTP/1.1\r\n");
    CHECK(http_parse_request(longreq, path, sizeof path) != 0);               /* path too long for buffer */
}

/* ---- watch state machine, metrics, JSON, persistence ---- */
static void test_watch(void) {
    struct watch w = { 0 };
    struct kvlist aliases = { 0 }, cache = { 0 };
    (void)aliases; (void)cache;
    reset_hosts();
    for (int i = 0; i < HL.n; i++) { HL.h[i].name = "dev"; HL.h[i].src = "mdns"; HL.h[i].vendor = "Acme \"Quoted\" Co"; }
    HL.h[0].name = "Router\nwith newline"; HL.h[0].known = true;
    /* scan 1: everything is new */
    CHECK(watch_update(&w, &HL, 1000, true) == 4);
    CHECK(w.n == 4 && w.scans == 1 && w.v[0].first == 1000 && w.v[0].online);
    /* scan 2: one device missing -> not offline yet; scans 3,4 -> offline after 3 misses */
    int removed = HL.n - 1; HL.n--;
    CHECK(watch_update(&w, &HL, 1060, true) == 0);
    CHECK(!w.v[removed].online && w.v[removed].misses == 1 && w.v[removed].last == 1000);
    watch_update(&w, &HL, 1120, true);
    watch_update(&w, &HL, 1180, true);
    CHECK(w.v[removed].misses == 3);
    /* it comes back: last updated, misses reset, no duplicate row */
    HL.n++;
    CHECK(watch_update(&w, &HL, 1240, true) == 0);
    CHECK(w.n == 4 && w.v[removed].online && w.v[removed].misses == 0 && w.v[removed].last == 1240);

    static char out[1 << 16];
    watch_metrics(&w, out, sizeof out);
    CHECK(strstr(out, "lan_devices_online 4\n") != NULL);
    CHECK(strstr(out, "lan_scans_total 5\n") != NULL);
    CHECK(strstr(out, "name=\"Router with newline\"") != NULL);             /* control chars sanitized at update */
    CHECK(strstr(out, "vendor=\"Acme \\\"Quoted\\\" Co\"") != NULL);     /* quotes escaped */
    CHECK(strstr(out, "known=\"true\"") != NULL && strstr(out, "known=\"false\"") != NULL);
    CHECK(strstr(out, "# TYPE lan_device_online gauge") != NULL);
    /* online gauge is still 1 for a device missing fewer than 3 scans */
    HL.n--;
    watch_update(&w, &HL, 1300, true);
    watch_metrics(&w, out, sizeof out);
    char needle[64]; snprintf(needle, sizeof needle, "mac=\"%s\"", w.v[removed].mac);
    char *line = strstr(out, needle); CHECK(line && strstr(line, "} 1\n") < strchr(line, '\n'));
    HL.n++;

    watch_json(&w, out, sizeof out);
    CHECK(strstr(out, "\"name\":\"Router with newline\"") != NULL);
    CHECK(strstr(out, "\"vendor\":\"Acme \\\"Quoted\\\" Co\"") != NULL);
    CHECK(strstr(out, "\"known\":true") != NULL && strstr(out, "\"online\":true") != NULL);
    CHECK(out[strlen(out) - 2] == '}');

    /* escaping of characters that survive sanitization, plus a raw control char injected into state */
    cpy(w.v[1].name, sizeof w.v[1].name, "tab\there \"q\" back\\slash");
    watch_metrics(&w, out, sizeof out);
    CHECK(strstr(out, "name=\"tab\there \\\"q\\\" back\\\\slash\"") != NULL);   /* Prometheus: only \\ and \" escaped */
    watch_json(&w, out, sizeof out);
    CHECK(strstr(out, "\"name\":\"tab\\there \\\"q\\\" back\\\\slash\"") != NULL);
    cpy(w.v[1].name, sizeof w.v[1].name, "dev");

    /* a tiny output buffer must truncate, never overflow */
    char small[40]; memset(small, 'x', sizeof small);
    watch_metrics(&w, small, sizeof small); CHECK(strlen(small) < sizeof small);
    watch_json(&w, small, sizeof small);    CHECK(strlen(small) < sizeof small);

    /* persistence round trip */
    char path[] = "/tmp/lan-devices-seen-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    CHECK(watch_save(&w, path) == 0);
    struct watch w2 = { 0 };
    watch_load(&w2, path);
    CHECK(w2.n == 4);
    CHECK(w2.v[0].first == 1000 && w2.v[0].last == 1300 && !w2.v[0].online);
    CHECK_STR(w2.v[0].name, "Router with newline");
    CHECK_STR(w2.v[1].name, "dev");
    /* a device known from the file is not "new" on the first scan after restart */
    CHECK(watch_update(&w2, &HL, 2000, true) == 0);
    CHECK(w2.v[0].first == 1000 && w2.v[0].online);
    unlink(path);
    free(w.v); free(w2.v);
}

static void dump_corpus(const char *dir) {
    struct pb p; char path[512];
    build_mdns_response(&p);
    snprintf(path, sizeof path, "%s/mdns-response.bin", dir);
    FILE *f = fopen(path, "wb"); if (f) { fwrite(p.b, 1, p.n, f); fclose(f); }
    build_nbns_reply(&p, true);
    snprintf(path, sizeof path, "%s/nbns-reply.bin", dir);
    f = fopen(path, "wb"); if (f) { fwrite(p.b, 1, p.n, f); fclose(f); }
    printf("seed corpus written to %s\n", dir);
}

int main(int argc, char **argv) {
    cpy(IFC.name, sizeof IFC.name, "test0");
    inet_pton(AF_INET, "192.168.0.228", &IFC.ip);
    inet_pton(AF_INET, "255.255.255.0", &IFC.mask);
    if (argc == 3 && !strcmp(argv[1], "--dump-corpus")) { dump_corpus(argv[2]); return 0; }
    test_dns_name();
    test_txt();
    test_mdns();
    test_ip6_model();
    test_nd6();
    test_cap();
    test_nbns();
    test_oui();
    test_store();
    test_util();
    test_http();
    test_watch();
    free(HL.h);
    printf("%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
