/* lan-devices — list devices on the LAN with the best name we can find.
 * Portable C (Linux + macOS). See README.md. */
#ifndef LAN_H
#define LAN_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE          /* glibc: wcswidth, strndup, usleep */
#endif
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

#define NAME_LEN 128

struct iface {
    char name[32];
    unsigned index;
    struct in_addr ip, mask;
    uint8_t mac[6];
    bool have_ll6;
    struct in6_addr ll6;                       /* our link-local IPv6 */
    struct { struct in6_addr addr; int plen; } pfx6[4];   /* on-link IPv6 prefixes (global/ULA) */
    int npfx6;
};

#define MAX_IP6 4
struct host {
    uint8_t mac[6];
    struct in_addr ip4;                /* 0 if IPv6-only */
    struct in6_addr ip6[MAX_IP6];
    int n6;
    bool self;
    char svc[NAME_LEN];   int svc_pri;  /* mDNS service instance name (Cast fn=, AirPlay, HomeKit, ...) */
    char mdns[NAME_LEN];               /* mDNS hostname without .local */
    char nbt[NAME_LEN];                /* NetBIOS name */
    char rdns[NAME_LEN];               /* reverse DNS */
    char model[NAME_LEN];              /* model from mDNS TXT (md= / model= / am= / ty=) */
    /* resolved by name_hosts(): */
    const char *name, *src, *vendor;
    bool known;                        /* has an alias */
};

struct hostlist { struct host *h; int n, cap; };
struct host *hosts_by_mac(struct hostlist *hl, const uint8_t *mac);          /* add if missing */
struct host *hosts_add4(struct hostlist *hl, const uint8_t *mac, struct in_addr ip);
struct host *hosts_add6(struct hostlist *hl, const uint8_t *mac, const struct in6_addr *ip);
struct host *hosts_find4(struct hostlist *hl, struct in_addr ip);
struct host *hosts_find6(struct hostlist *hl, const struct in6_addr *ip);
const struct in6_addr *host_best6(const struct host *h);                     /* global > ULA > link-local, NULL if none */

/* util.c */
double now_s(void);
void cpy(char *dst, size_t sz, const char *src);
void cpyn(char *dst, size_t sz, const char *src, size_t n);
const char *mac_str(const uint8_t *mac);
void sanitize(char *s);
int  display_width(const char *s);
void die(const char *fmt, ...);
void drop_privs(void);
bool in_subnet(const struct iface *ifc, struct in_addr ip);
bool on_link6(const struct iface *ifc, const struct in6_addr *ip);   /* link-local or inside one of our prefixes */
void ip6_arpa(const struct in6_addr *ip, char *out, size_t osz);   /* reverse name, 74 chars */
extern unsigned g_send_errors;       /* packets we failed to send, reported at exit */

/* dns.c — DNS wire-format helpers shared by mdns.c, rdns.c and the tests */
struct dname { char full[256]; char first[128]; char rest[192]; };
int  dns_name_read(const uint8_t *p, int len, int off, struct dname *d);   /* -1 on malformed */
bool dns_txt_get(const uint8_t *txt, int len, const char *key, char *out, size_t osz);
int  dns_put_name(uint8_t *b, int off, const char *dotted);
static inline unsigned dns_u16(const uint8_t *p, int o) { return ((unsigned)p[o] << 8) | p[o + 1]; }

/* iface.c */
int iface_detect(const char *want, struct iface *out, char *err, size_t errsz);

/* cap.c — link-layer capture/injection via libpcap (needs root). Every ARP
 * and on-link IPv6 frame seen is attributed to its source MAC. */
struct cap;
struct cap *cap_open(const struct iface *ifc, struct hostlist *hl, char *err, size_t errsz);
struct cap *cap_new(const struct iface *ifc, struct hostlist *hl);      /* no pcap: tests */
void cap_frame(struct cap *c, const uint8_t *frame, int len);            /* classify one frame */
void cap_poll(struct cap *c);                                            /* drain pending frames */
int  cap_send(struct cap *c, const uint8_t *frame, int len);
void cap_close(struct cap *c);

/* arp.c — IPv4 sweep: ARP request to every address in the subnet */
int  arp_sweep(struct cap *c, const struct iface *ifc, struct hostlist *hl, double linger);

/* nd6.c — IPv6: ICMPv6 echo to all-nodes (ff02::1); replies are picked up by cap */
int  nd6_build_echo(const struct iface *ifc, uint8_t *frame, size_t sz, uint16_t seq);
uint16_t icmp6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const uint8_t *payload, int len);
void nd6_probe(struct cap *c, const struct iface *ifc, uint16_t seq);

/* arpcache.c — passive: read the OS ARP table (no root) */
int arpcache_read(const struct iface *ifc, struct hostlist *hl);   /* IPv4 ARP + IPv6 neighbour tables */

/* mdns.c */
struct mdns;
struct mdns *mdns_new(const struct iface *ifc, struct hostlist *hl);   /* parser only, no socket (tests) */
struct mdns *mdns_start(const struct iface *ifc, struct hostlist *hl); /* socket + first queries */
int  mdns_fd(struct mdns *m);
int  mdns_fd6(struct mdns *m);
void mdns_query(struct mdns *m);
void mdns_recv(struct mdns *m);
void mdns_handle(struct mdns *m, const uint8_t *pkt, int len);          /* parse one response */
void mdns_finish(struct mdns *m);                                       /* apply names, free */

/* nbns.c */
struct nbns;
struct nbns *nbns_start(struct hostlist *hl);
int  nbns_fd(struct nbns *n);
void nbns_query(struct nbns *n);
void nbns_recv(struct nbns *n);
bool nbns_parse_reply(const uint8_t *p, int len, char *out, size_t osz);  /* workstation name */
void nbns_finish(struct nbns *n);

/* rdns.c — reverse DNS as plain UDP queries to the system resolver */
struct rdns;
struct rdns *rdns_start(struct hostlist *hl);
int  rdns_fd(struct rdns *r);
void rdns_query(struct rdns *r);
void rdns_recv(struct rdns *r);
void rdns_finish(struct rdns *r);

/* http.c — minimal HTTP/1.0 server for --watch; served from the poll loop, no threads */
typedef void (*http_handler)(const char *path, char *body, size_t bodysz, const char **ctype);
int  http_start(const char *listen, http_handler h, char *err, size_t errsz);   /* "[addr:]port"; -1 on error */
int  http_fd(void);
void http_serve(void);                 /* accept and answer every pending request */
void idle_ms(int ms);                  /* sleep, but keep serving HTTP meanwhile */
int  http_parse_request(const char *req, char *path, size_t pathsz);           /* exposed for tests */

/* watch.c — long-running mode: periodic scans, device state, Prometheus metrics */
struct seen {
    char mac[18];
    double first, last;                /* unix seconds */
    int misses;                        /* consecutive scans without an answer */
    bool online, known;
    char name[NAME_LEN], src[16], ip[48], ip6[48], vendor[NAME_LEN];
};
struct watch {
    struct seen *v; int n, cap;
    unsigned scans; double last_scan_ts, last_scan_dur;
};
void watch_load(struct watch *w, const char *path);
int  watch_save(const struct watch *w, const char *path);
int  watch_update(struct watch *w, const struct hostlist *hl, double now, bool show_vendor); /* returns # new devices; logs events */
void watch_metrics(const struct watch *w, char *out, size_t sz);
void watch_json(const struct watch *w, char *out, size_t sz);
const char *seen_path(void);

/* oui.c */
int  oui_load(const char *path);                       /* NULL = search defaults; entries loaded */
bool oui_parse_line(char *line, char *hex, int *hexlen, const char **name);
const char *oui_lookup(const uint8_t *mac);            /* NULL if unknown */

/* store.c — aliases + learned cache, same file format as the original bash tool */
struct kv { char mac[18]; char name[NAME_LEN]; };
struct kvlist { struct kv *v; int n, cap; };
const char *store_dir(void);
void store_mkdir_for(const char *path);   /* mkdir -p the parent directory */
const char *aliases_path(void);
const char *cache_path(void);
void kv_load(struct kvlist *l, const char *path);
const char *kv_get(const struct kvlist *l, const char *mac);
void kv_put_front(struct kvlist *l, const char *mac, const char *name);
int  kv_save(const struct kvlist *l, const char *path);

#endif
