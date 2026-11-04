/* rdns.c — reverse DNS without getnameinfo() or threads.
 *
 * One UDP socket, a PTR query per host to the nameservers in /etc/resolv.conf,
 * answers parsed on the main poll loop like everything else. A slow resolver
 * therefore costs nothing beyond the listen window, which is why the standard
 * blocking resolver is not used. IPv6-only hosts are looked up by their
 * global address (link-local addresses are never in DNS). */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct rdns {
    int fd;
    struct hostlist *hl;
    struct sockaddr_in ns[3];
    int nns, round;
    uint16_t base;
};

static int read_resolv(struct rdns *r) {
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) return 0;
    char line[256], ip[64];
    while (fgets(line, sizeof line, f) && r->nns < 3) {
        if (sscanf(line, "nameserver %63s", ip) != 1) continue;
        struct sockaddr_in *s = &r->ns[r->nns];
        memset(s, 0, sizeof *s);
        s->sin_family = AF_INET;
        s->sin_port = htons(53);
        if (inet_pton(AF_INET, ip, &s->sin_addr) == 1) r->nns++;   /* IPv4 resolvers only */
    }
    fclose(f);
    return r->nns;
}

struct rdns *rdns_start(struct hostlist *hl) {
    struct rdns *r = calloc(1, sizeof *r);
    r->hl = hl;
    r->fd = -1;
    r->base = (uint16_t)(getpid() * 31u);
    if (!read_resolv(r)) return r;          /* no resolver: every call is a no-op */
    r->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (r->fd < 0) return r;
    fcntl(r->fd, F_SETFL, O_NONBLOCK);
    rdns_query(r);
    return r;
}

int rdns_fd(struct rdns *r) { return r ? r->fd : -1; }

/* Send a PTR query for every host still unnamed; each round uses the next nameserver. */
void rdns_query(struct rdns *r) {
    if (!r || r->fd < 0) return;
    const struct sockaddr_in *ns = &r->ns[r->round++ % r->nns];
    for (int i = 0; i < r->hl->n && i < 65000; i++) {
        struct host *h = &r->hl->h[i];
        if (h->rdns[0]) continue;
        char name[96];
        if (h->ip4.s_addr) {
            const uint8_t *q = (const uint8_t *)&h->ip4.s_addr;
            snprintf(name, sizeof name, "%u.%u.%u.%u.in-addr.arpa", q[3], q[2], q[1], q[0]);
        } else {
            const struct in6_addr *a = host_best6(h);
            if (!a || IN6_IS_ADDR_LINKLOCAL(a)) continue;     /* link-local is never in DNS */
            ip6_arpa(a, name, sizeof name);
        }
        uint8_t b[128];
        uint16_t id = (uint16_t)(r->base + i);
        b[0] = id >> 8; b[1] = id & 0xff;
        b[2] = 0x01; b[3] = 0;                 /* recursion desired */
        b[4] = 0; b[5] = 1; memset(b + 6, 0, 6);
        int off = dns_put_name(b, 12, name);
        b[off++] = 0; b[off++] = 12;           /* PTR */
        b[off++] = 0; b[off++] = 1;            /* IN */
        if (sendto(r->fd, b, off, 0, (const struct sockaddr *)ns, sizeof *ns) < 0) g_send_errors++;
    }
}

/* Match answers to hosts by transaction id: id = base + index of the host in
 * the list, so no table is needed and a stray answer can't be mis-filed. */
void rdns_recv(struct rdns *r) {
    if (!r || r->fd < 0) return;
    uint8_t p[2048];
    for (;;) {
        ssize_t len = recv(r->fd, p, sizeof p, 0);
        if (len < 12) return;
        if (!(p[2] & 0x80) || (p[3] & 0x0f) != 0) continue;     /* not a response, or an error */
        int i = (uint16_t)(dns_u16(p, 0) - r->base);
        if (i < 0 || i >= r->hl->n) continue;
        struct host *h = &r->hl->h[i];
        if (h->rdns[0]) continue;
        int qd = dns_u16(p, 4), an = dns_u16(p, 6), off = 12;
        struct dname n, v;
        for (int k = 0; k < qd; k++) { off = dns_name_read(p, (int)len, off, &n); if (off < 0) break; off += 4; }
        if (off < 0) continue;
        for (int k = 0; k < an; k++) {
            off = dns_name_read(p, (int)len, off, &n);
            if (off < 0 || off + 10 > len) break;
            int type = dns_u16(p, off), rdlen = dns_u16(p, off + 8), rd = off + 10;
            off = rd + rdlen;
            if (off > len) break;
            if (type == 12 && dns_name_read(p, (int)len, rd, &v) >= 0 && v.full[0]) {
                cpy(h->rdns, sizeof h->rdns, v.full);
                break;
            }
        }
    }
}

void rdns_finish(struct rdns *r) {
    if (!r) return;
    if (r->fd >= 0) close(r->fd);
    free(r);
}
