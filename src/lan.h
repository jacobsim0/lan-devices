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
    struct in_addr ip, mask;
    uint8_t mac[6];
};

struct host {
    struct in_addr ip;
    uint8_t mac[6];
    bool self;
    char svc[NAME_LEN];   int svc_pri;  /* mDNS service instance name (Cast fn=, AirPlay, HomeKit, ...) */
    char mdns[NAME_LEN];               /* mDNS hostname without .local */
    char nbt[NAME_LEN];                /* NetBIOS name */
    char rdns[NAME_LEN];               /* reverse DNS */
    char model[NAME_LEN];              /* model from mDNS TXT (md= / model= / am= / ty=) */
};

struct hostlist { struct host *h; int n, cap; };
struct host *hosts_add(struct hostlist *hl, struct in_addr ip, const uint8_t *mac);
struct host *hosts_find(struct hostlist *hl, struct in_addr ip);

/* util.c */
double now_s(void);
void cpy(char *dst, size_t sz, const char *src);
void cpyn(char *dst, size_t sz, const char *src, size_t n);
const char *mac_str(const uint8_t *mac);
int display_width(const char *s);
void die(const char *fmt, ...);
void drop_privs(void);
bool in_subnet(const struct iface *ifc, struct in_addr ip);

/* iface.c */
int iface_detect(const char *want, struct iface *out, char *err, size_t errsz);

/* arp.c — active sweep via libpcap (needs root) */
struct arp;
struct arp *arp_open(const struct iface *ifc, char *err, size_t errsz);
int  arp_scan(struct arp *a, struct hostlist *hl, double linger);
void arp_close(struct arp *a);

/* arpcache.c — passive: read the OS ARP table (no root) */
int arpcache_read(const struct iface *ifc, struct hostlist *hl);

/* mdns.c */
struct mdns;
struct mdns *mdns_start(const struct iface *ifc, struct hostlist *hl);
int  mdns_fd(struct mdns *m);
void mdns_query(struct mdns *m);
void mdns_recv(struct mdns *m);
void mdns_finish(struct mdns *m);

/* nbns.c */
struct nbns;
struct nbns *nbns_start(struct hostlist *hl);
int  nbns_fd(struct nbns *n);
void nbns_query(struct nbns *n);
void nbns_recv(struct nbns *n);
void nbns_finish(struct nbns *n);

/* rdns.c */
void rdns_start(struct hostlist *hl);
void rdns_collect(struct hostlist *hl, double wait_s);

/* oui.c */
int oui_load(const char *path);            /* NULL = search default locations; returns 0 if none found */
const char *oui_lookup(const uint8_t *mac); /* NULL if unknown */

/* store.c — aliases + learned cache, same file format as the original bash tool */
struct kv { char mac[18]; char name[NAME_LEN]; };
struct kvlist { struct kv *v; int n, cap; };
const char *store_dir(void);
const char *aliases_path(void);
const char *cache_path(void);
void kv_load(struct kvlist *l, const char *path);
const char *kv_get(const struct kvlist *l, const char *mac);
void kv_put_front(struct kvlist *l, const char *mac, const char *name);
int  kv_save(const struct kvlist *l, const char *path);

#endif
