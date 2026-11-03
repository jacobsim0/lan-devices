#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <wchar.h>
#include <locale.h>

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

struct host *hosts_find(struct hostlist *hl, struct in_addr ip) {
    for (int i = 0; i < hl->n; i++)
        if (hl->h[i].ip.s_addr == ip.s_addr) return &hl->h[i];
    return NULL;
}

struct host *hosts_add(struct hostlist *hl, struct in_addr ip, const uint8_t *mac) {
    struct host *h = hosts_find(hl, ip);
    if (h) return h;
    if (hl->n == hl->cap) {
        hl->cap = hl->cap ? hl->cap * 2 : 64;
        hl->h = realloc(hl->h, hl->cap * sizeof *hl->h);
        if (!hl->h) die("out of memory");
    }
    h = &hl->h[hl->n++];
    memset(h, 0, sizeof *h);
    h->ip = ip;
    memcpy(h->mac, mac, 6);
    return h;
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
