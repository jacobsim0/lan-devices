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
    uint8_t mac[6] = { 0, 1, 2, 3, 4, (uint8_t)a.s_addr };
    return hosts_add(&HL, a, mac);
}
static void reset_hosts(void) {
    free(HL.h); memset(&HL, 0, sizeof HL);
    add_host("192.168.0.1"); add_host("192.168.0.153"); add_host("192.168.0.238"); add_host("192.168.0.182");
}
static struct host *host(const char *ip) { struct in_addr a; inet_pton(AF_INET, ip, &a); return hosts_find(&HL, a); }

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
    test_nbns();
    test_oui();
    test_store();
    test_util();
    free(HL.h);
    printf("%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
