#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <wchar.h>
#include <locale.h>

unsigned g_send_errors;

double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

void cpy(char *dst, size_t sz, const char *src) { cpyn(dst, sz, src, strlen(src)); }

void cpyn(char *dst, size_t sz, const char *src, size_t n) {
    if (!sz) return;
    size_t l = strnlen(src, n);
    if (l >= sz) l = sz - 1;
    memcpy(dst, src, l);
    dst[l] = 0;
}

/* Replace control characters (tabs, newlines, escapes) with spaces: names come off the wire. */
void sanitize(char *s) {
    for (; *s; s++) if ((unsigned char)*s < 0x20 || *s == 0x7f) *s = ' ';
}

const char *mac_str(const uint8_t *m) {
    static char b[4][18];
    static int i;
    char *o = b[i++ & 3];
    snprintf(o, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return o;
}

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* After the raw socket is open we don't need root: become the sudo caller so
 * config files end up owned by the user, not root. */
void drop_privs(void) {
    const char *u = getenv("SUDO_UID"), *g = getenv("SUDO_GID");
    if (geteuid() != 0 || !u || !g) return;
    uid_t uid = (uid_t)atoi(u);
    gid_t gid = (gid_t)atoi(g);
    if (uid == 0) return;
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
        die("failed to drop privileges");
}

bool in_subnet(const struct iface *ifc, struct in_addr ip) {
    return (ip.s_addr & ifc->mask.s_addr) == (ifc->ip.s_addr & ifc->mask.s_addr);
}

struct host *hosts_find4(struct hostlist *hl, struct in_addr ip) {
    if (!ip.s_addr) return NULL;
    for (int i = 0; i < hl->n; i++)
        if (hl->h[i].ip4.s_addr == ip.s_addr) return &hl->h[i];
    return NULL;
}

struct host *hosts_find6(struct hostlist *hl, const struct in6_addr *ip) {
    for (int i = 0; i < hl->n; i++)
        for (int k = 0; k < hl->h[i].n6; k++)
            if (!memcmp(&hl->h[i].ip6[k], ip, 16)) return &hl->h[i];
    return NULL;
}

struct host *hosts_by_mac(struct hostlist *hl, const uint8_t *mac) {
    for (int i = 0; i < hl->n; i++)
        if (!memcmp(hl->h[i].mac, mac, 6)) return &hl->h[i];
    if (hl->n >= 65536) return NULL;
    if (hl->n == hl->cap) {
        hl->cap = hl->cap ? hl->cap * 2 : 64;
        hl->h = realloc(hl->h, hl->cap * sizeof *hl->h);
        if (!hl->h) die("out of memory");
    }
    struct host *h = &hl->h[hl->n++];
    memset(h, 0, sizeof *h);
    memcpy(h->mac, mac, 6);
    return h;
}

struct host *hosts_add4(struct hostlist *hl, const uint8_t *mac, struct in_addr ip) {
    struct host *h = hosts_by_mac(hl, mac);
    if (h && !h->ip4.s_addr) h->ip4 = ip;       /* first IPv4 per MAC wins */
    return h;
}

struct host *hosts_add6(struct hostlist *hl, const uint8_t *mac, const struct in6_addr *ip) {
    struct host *h = hosts_by_mac(hl, mac);
    if (!h) return NULL;
    for (int k = 0; k < h->n6; k++) if (!memcmp(&h->ip6[k], ip, 16)) return h;
    if (h->n6 < MAX_IP6) h->ip6[h->n6++] = *ip;
    return h;
}

static int scope6(const struct in6_addr *a) {
    if (IN6_IS_ADDR_LINKLOCAL(a)) return 1;
    if ((a->s6_addr[0] & 0xfe) == 0xfc) return 2;    /* ULA fc00::/7 */
    return 3;                                        /* global */
}

const struct in6_addr *host_best6(const struct host *h) {
    const struct in6_addr *best = NULL;
    for (int k = 0; k < h->n6; k++)
        if (!best || scope6(&h->ip6[k]) > scope6(best)) best = &h->ip6[k];
    return best;
}

bool on_link6(const struct iface *ifc, const struct in6_addr *ip) {
    if (IN6_IS_ADDR_LINKLOCAL(ip)) return true;
    for (int i = 0; i < ifc->npfx6; i++) {
        int plen = ifc->pfx6[i].plen, full = plen / 8, rem = plen % 8;
        if (memcmp(ip, &ifc->pfx6[i].addr, full)) continue;
        if (rem && ((ip->s6_addr[full] ^ ifc->pfx6[i].addr.s6_addr[full]) & (0xff << (8 - rem)))) continue;
        return true;
    }
    return false;
}

/* "b.a.9.8.7.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa" */
void ip6_arpa(const struct in6_addr *ip, char *out, size_t osz) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (int i = 15; i >= 0 && o + 4 < osz; i--) {
        out[o++] = hex[ip->s6_addr[i] & 0xf]; out[o++] = '.';
        out[o++] = hex[ip->s6_addr[i] >> 4];  out[o++] = '.';
    }
    out[o] = 0;
    cpy(out + o, osz - o, "ip6.arpa");
}

/* Terminal cells a UTF-8 string occupies (for column alignment). */
int display_width(const char *s) {
    static bool loc;
    if (!loc) { setlocale(LC_CTYPE, ""); loc = true; }
    wchar_t w[NAME_LEN * 2];
    size_t n = mbstowcs(w, s, sizeof w / sizeof w[0] - 1);
    if (n != (size_t)-1) {
        w[n] = 0;
        int cw = wcswidth(w, n);
        if (cw >= 0) return cw;
    }
    int c = 0;
    for (; *s; s++) if (((unsigned char)*s & 0xc0) != 0x80) c++;
    return c;
}
