/* mdns.c — multicast DNS, done by hand (no Avahi, no Bonjour library).
 *
 * We multicast our own queries to 224.0.0.251 and ff02::fb on port 5353 and
 * parse whatever comes back:
 *   - PTR queries for well-known service types -> instance names (AirPlay,
 *     Chromecast fn=, HomeKit, printers, Sonos, SMB) and model strings
 *   - reverse PTR (in-addr.arpa / ip6.arpa) -> hostname.local
 *   - any A / AAAA record we see -> hostname for that address
 *
 * Owns: the two sockets, the query packets, and three small tables filled
 *       while listening (service instances, A/AAAA records, reverse answers).
 *       mdns_finish() is where those tables are joined: each service instance
 *       is followed to its SRV target, the target to an address, the address
 *       to a host row, and the DEFS[] table says which service types give the
 *       best names. Nothing is written into host rows before finish().
 * Gotcha: binding port 5353 is shared with the system's own mDNS daemon via
 *       SO_REUSEPORT; if that fails we fall back to an ephemeral port and set
 *       the "unicast reply" bit on our questions. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MDNS_GROUP  "224.0.0.251"
#define MDNS_GROUP6 "ff02::fb"
#define MDNS_PORT   5353
#define MAX_INST    4096

struct inst { char key[256]; char name[128]; char type[192]; char target[256]; uint8_t txt[700]; int txtlen; };
struct arec { char host[256]; char first[128]; struct in_addr ip; };            /* A */
struct a6rec { char host[256]; char first[128]; struct in6_addr ip; };          /* AAAA */
struct rrev { struct in_addr ip; char host[128]; };                             /* in-addr.arpa PTR */
struct rrev6 { struct in6_addr ip; char host[128]; };                           /* ip6.arpa PTR */

struct mdns {
    int fd, fd6;                 /* -1 when unavailable */
    bool qu;                     /* true = couldn't bind 5353, ask for unicast replies */
    const struct iface *ifc;
    struct hostlist *hl;
    struct inst *in;  int nin, capin;
    struct arec *a;   int na,  capa;
    struct a6rec *a6; int na6, capa6;
    struct rrev *r;   int nr,  capr;
    struct rrev6 *r6; int nr6, capr6;
};

/* service type -> name priority, which TXT key carries a friendly name
 * (Chromecast "fn="), which carries a model, and whether to strip "MAC@". */
struct svcdef { const char *type; int pri; const char *fnkey; const char *modelkey; bool strip_at; };
static const struct svcdef DEFS[] = {
    { "_googlecast._tcp.local",     3, "fn", "md",    false },
    { "_airplay._tcp.local",        3, NULL, "model", false },
    { "_hap._tcp.local",            3, NULL, "md",    false },
    { "_homekit._tcp.local",        3, NULL, NULL,    false },
    { "_sonos._tcp.local",          2, NULL, NULL,    true  },
    { "_ipp._tcp.local",            2, NULL, "ty",    false },
    { "_printer._tcp.local",        2, NULL, "ty",    false },
    { "_companion-link._tcp.local", 1, NULL, NULL,    false },
    { "_raop._tcp.local",           1, NULL, "am",    true  },
    { "_smb._tcp.local",            1, NULL, NULL,    false },
    { "_workstation._tcp.local",    1, NULL, NULL,    false },
    { "_device-info._tcp.local",    0, NULL, "model", false },
};
#define NDEFS ((int)(sizeof DEFS / sizeof DEFS[0]))

#define GROW(arr, n, cap, T) do { if ((n) == (cap)) { (cap) = (cap) ? (cap) * 2 : 64; \
    (arr) = realloc((arr), (cap) * sizeof(T)); if (!(arr)) die("out of memory"); } } while (0)

static struct inst *get_inst(struct mdns *m, const struct dname *n) {
    for (int i = 0; i < m->nin; i++)
        if (!strcmp(m->in[i].key, n->full)) return &m->in[i];
    if (m->nin >= MAX_INST) return NULL;
    GROW(m->in, m->nin, m->capin, struct inst);
    struct inst *x = &m->in[m->nin++];
    memset(x, 0, sizeof *x);
    cpy(x->key, sizeof x->key, n->full);
    cpy(x->name, sizeof x->name, n->first);
    cpy(x->type, sizeof x->type, n->rest);
    return x;
}

static void add_a(struct mdns *m, const struct dname *n, struct in_addr ip) {
    for (int i = 0; i < m->na; i++) {
        if (strcmp(m->a[i].host, n->full)) continue;
        if (!in_subnet(m->ifc, m->a[i].ip) && in_subnet(m->ifc, ip)) m->a[i].ip = ip;
        return;
    }
    if (m->na >= MAX_INST) return;
    GROW(m->a, m->na, m->capa, struct arec);
    struct arec *a = &m->a[m->na++];
    cpy(a->host, sizeof a->host, n->full);
    cpy(a->first, sizeof a->first, n->first);
    a->ip = ip;
}

static void add_a6(struct mdns *m, const struct dname *n, const struct in6_addr *ip) {
    for (int i = 0; i < m->na6; i++)
        if (!strcmp(m->a6[i].host, n->full) && !memcmp(&m->a6[i].ip, ip, 16)) return;
    if (m->na6 >= MAX_INST) return;
    GROW(m->a6, m->na6, m->capa6, struct a6rec);
    struct a6rec *a = &m->a6[m->na6++];
    cpy(a->host, sizeof a->host, n->full);
    cpy(a->first, sizeof a->first, n->first);
    a->ip = *ip;
}

/* "f.e.d.c....ip6.arpa" -> address; false if malformed */
static bool parse_ip6_arpa(const char *name, struct in6_addr *out) {
    size_t len = strlen(name);
    if (len != 72 || strcmp(name + 64, "ip6.arpa")) return false;
    for (int i = 0; i < 32; i++) {
        char c = name[2 * i];
        if (name[2 * i + 1] != '.') return false;
        int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (v < 0) return false;
        int byte = 15 - i / 2;
        if (i % 2 == 0) out->s6_addr[byte] = (uint8_t)v;           /* low nibble first */
        else out->s6_addr[byte] |= (uint8_t)(v << 4);
    }
    return true;
}

static void add_rev6(struct mdns *m, const struct in6_addr *ip, const char *host) {
    for (int i = 0; i < m->nr6; i++) if (!memcmp(&m->r6[i].ip, ip, 16)) return;
    if (m->nr6 >= MAX_INST) return;
    GROW(m->r6, m->nr6, m->capr6, struct rrev6);
    struct rrev6 *r = &m->r6[m->nr6++];
    r->ip = *ip;
    cpy(r->host, sizeof r->host, host);
}

static void add_rev(struct mdns *m, struct in_addr ip, const char *host) {
    for (int i = 0; i < m->nr; i++) if (m->r[i].ip.s_addr == ip.s_addr) return;
    if (m->nr >= MAX_INST) return;
    GROW(m->r, m->nr, m->capr, struct rrev);
    struct rrev *r = &m->r[m->nr++];
    r->ip = ip;
    cpy(r->host, sizeof r->host, host);
}

static bool ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcmp(s + a - b, suf);
}

/* Parse one mDNS packet into the three tables. Nothing is decided here; every
 * record is just filed by type so finish() can join them in any arrival order
 * (a TXT record often arrives before the PTR that names its service). */
void mdns_handle(struct mdns *m, const uint8_t *p, int len) {
    if (!m || len < 12 || !(dns_u16(p, 2) & 0x8000)) return;      /* responses only */
    int qd = dns_u16(p, 4), rr = dns_u16(p, 6) + dns_u16(p, 8) + dns_u16(p, 10);
    int off = 12;
    struct dname n, r;
    for (int i = 0; i < qd; i++) { off = dns_name_read(p, len, off, &n); if (off < 0) return; off += 4; }
    for (int i = 0; i < rr; i++) {
        off = dns_name_read(p, len, off, &n);
        if (off < 0 || off + 10 > len) return;
        int type = dns_u16(p, off), rdlen = dns_u16(p, off + 8), rd = off + 10;
        off = rd + rdlen;
        if (off > len) return;
        switch (type) {
        case 1:    /* A */
            if (rdlen == 4) { struct in_addr ip; memcpy(&ip, p + rd, 4); add_a(m, &n, ip); }
            break;
        case 28: { /* AAAA */
            if (rdlen != 16) break;
            struct in6_addr ip; memcpy(&ip, p + rd, 16);
            if (!IN6_IS_ADDR_UNSPECIFIED(&ip) && !IN6_IS_ADDR_MULTICAST(&ip)) add_a6(m, &n, &ip);
            break;
        }
        case 12: { /* PTR */
            if (dns_name_read(p, len, rd, &r) < 0) break;
            unsigned a, b, c, d;
            struct in6_addr ip6;
            if (ends_with(n.full, ".in-addr.arpa")) {
                if (sscanf(n.full, "%u.%u.%u.%u.in-addr.arpa", &d, &c, &b, &a) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
                    struct in_addr ip = { .s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d) };
                    add_rev(m, ip, r.first);
                }
            } else if (ends_with(n.full, ".ip6.arpa")) {
                if (parse_ip6_arpa(n.full, &ip6)) add_rev6(m, &ip6, r.first);
            } else if (n.first[0] == '_' && r.first[0] != '_') {
                get_inst(m, &r);
            }
            break;
        }
        case 16: { /* TXT */
            struct inst *x = get_inst(m, &n);
            if (x && x->txtlen == 0) {
                x->txtlen = rdlen < (int)sizeof x->txt ? rdlen : (int)sizeof x->txt;
                memcpy(x->txt, p + rd, x->txtlen);
            }
            break;
        }
        case 33: { /* SRV: pri, weight, port, target */
            if (rdlen > 6 && dns_name_read(p, len, rd + 6, &r) >= 0) {
                struct inst *x = get_inst(m, &n);
                if (x) cpy(x->target, sizeof x->target, r.full);
            }
            break;
        }
        }
    }
}

static void send_q(struct mdns *m, const char **names, int n) {
    uint8_t b[1400];
    memset(b, 0, 12);
    int off = 12, sent = 0;
    for (int i = 0; i < n; i++) {
        if (off + strlen(names[i]) + 6 > sizeof b) break;
        sent++;
        off = dns_put_name(b, off, names[i]);
        b[off++] = 0; b[off++] = 12;                     /* PTR */
        b[off++] = m->qu ? 0x80 : 0; b[off++] = 1;       /* IN, QU bit if we need unicast replies */
    }
    b[5] = (uint8_t)sent;   /* qdcount */
    if (m->fd >= 0) {
        struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(MDNS_PORT) };
        inet_pton(AF_INET, MDNS_GROUP, &to.sin_addr);
        if (sendto(m->fd, b, off, 0, (struct sockaddr *)&to, sizeof to) < 0) g_send_errors++;
    }
    if (m->fd6 >= 0) {
        struct sockaddr_in6 to = { .sin6_family = AF_INET6, .sin6_port = htons(MDNS_PORT), .sin6_scope_id = m->ifc->index };
        inet_pton(AF_INET6, MDNS_GROUP6, &to.sin6_addr);
        if (sendto(m->fd6, b, off, 0, (struct sockaddr *)&to, sizeof to) < 0) g_send_errors++;
    }
}

void mdns_query(struct mdns *m) {
    if (!m || (m->fd < 0 && m->fd6 < 0)) return;
    const char *svc[NDEFS];
    for (int i = 0; i < NDEFS; i++) svc[i] = DEFS[i].type;
    send_q(m, svc, NDEFS);
    /* reverse lookups: in-addr.arpa for IPv4 hosts, ip6.arpa (link-local) for IPv6-only ones */
    static char buf[12][96];
    const char *names[12];
    int k = 0;
    for (int i = 0; i < m->hl->n; i++) {
        struct host *h = &m->hl->h[i];
        if (h->mdns[0]) continue;
        if (h->ip4.s_addr) {
            const uint8_t *q = (const uint8_t *)&h->ip4.s_addr;
            snprintf(buf[k], sizeof buf[k], "%u.%u.%u.%u.in-addr.arpa", q[3], q[2], q[1], q[0]);
        } else if (h->n6) {
            ip6_arpa(&h->ip6[0], buf[k], sizeof buf[k]);
        } else continue;
        names[k] = buf[k];
        if (++k == 12) { send_q(m, names, k); k = 0; }
    }
    if (k) send_q(m, names, k);
}

static int open6(const struct iface *ifc) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_in6 sa = { .sin6_family = AF_INET6, .sin6_port = htons(MDNS_PORT), .sin6_addr = IN6ADDR_ANY_INIT };
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return -1; }
    struct ipv6_mreq mr = { .ipv6mr_interface = ifc->index };
    inet_pton(AF_INET6, MDNS_GROUP6, &mr.ipv6mr_multiaddr);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr, sizeof mr) < 0) { close(fd); return -1; }
    unsigned idx = ifc->index;
    int hops = 255, loop = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof idx);
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof hops);
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof loop);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    return fd;
}

struct mdns *mdns_new(const struct iface *ifc, struct hostlist *hl) {
    struct mdns *m = calloc(1, sizeof *m);
    if (!m) die("out of memory");
    m->fd = m->fd6 = -1;
    m->ifc = ifc;
    m->hl = hl;
    return m;
}

struct mdns *mdns_start(const struct iface *ifc, struct hostlist *hl) {
    struct mdns *m = mdns_new(ifc, hl);
    if (ifc->index) m->fd6 = open6(ifc);
    m->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m->fd < 0) { mdns_query(m); return m; }
    int one = 1;
    setsockopt(m->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
    setsockopt(m->fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(MDNS_PORT), .sin_addr.s_addr = INADDR_ANY };
    if (bind(m->fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        /* someone holds 5353 exclusively: use an ephemeral port and ask for unicast replies */
        sa.sin_port = 0;
        if (bind(m->fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(m->fd); m->fd = -1; mdns_query(m); return m; }
        m->qu = true;
    }
    struct ip_mreq mr = { .imr_interface = ifc->ip };
    inet_pton(AF_INET, MDNS_GROUP, &mr.imr_multiaddr);
    setsockopt(m->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr);
    setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_IF, &ifc->ip, sizeof ifc->ip);
    unsigned char ttl = 255, loop = 1;
    setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
    setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop);
    fcntl(m->fd, F_SETFL, O_NONBLOCK);
    mdns_query(m);
    return m;
}

int mdns_fd(struct mdns *m) { return m ? m->fd : -1; }
int mdns_fd6(struct mdns *m) { return m ? m->fd6 : -1; }

static void drain_fd(struct mdns *m, int fd) {
    if (fd < 0) return;
    uint8_t p[9000];
    for (;;) {
        ssize_t len = recv(fd, p, sizeof p, 0);
        if (len <= 0) return;
        mdns_handle(m, p, (int)len);
    }
}

void mdns_recv(struct mdns *m) {
    if (!m) return;
    drain_fd(m, m->fd);
    drain_fd(m, m->fd6);
}

static struct arec *find_a(struct mdns *m, const char *host) {
    for (int i = 0; i < m->na; i++) if (!strcmp(m->a[i].host, host)) return &m->a[i];
    return NULL;
}

/* Join everything we heard into the host rows. Runs once, after listening.
 * Order matters: reverse answers are the most direct hostname, A/AAAA records
 * are a fallback, and service instances are resolved last because they need
 * the address tables to be complete (instance -> SRV target -> address -> row). */
void mdns_finish(struct mdns *m) {
    if (!m) return;
    /* hostnames: reverse answers first, then any A record we saw */
    for (int i = 0; i < m->nr; i++) {
        struct host *h = hosts_find4(m->hl, m->r[i].ip);
        if (h && !h->mdns[0]) cpy(h->mdns, sizeof h->mdns, m->r[i].host);
    }
    for (int i = 0; i < m->nr6; i++) {
        struct host *h = hosts_find6(m->hl, &m->r6[i].ip);
        if (h && !h->mdns[0]) cpy(h->mdns, sizeof h->mdns, m->r6[i].host);
    }
    for (int i = 0; i < m->na; i++) {
        struct host *h = hosts_find4(m->hl, m->a[i].ip);
        if (h && !h->mdns[0]) cpy(h->mdns, sizeof h->mdns, m->a[i].first);
    }
    for (int i = 0; i < m->na6; i++) {
        struct host *h = hosts_find6(m->hl, &m->a6[i].ip);
        if (h && !h->mdns[0]) cpy(h->mdns, sizeof h->mdns, m->a6[i].first);
    }
    /* service instances -> friendly names and models */
    for (int i = 0; i < m->nin; i++) {
        struct inst *x = &m->in[i];
        const struct svcdef *d = NULL;
        for (int k = 0; k < NDEFS; k++) if (!strcmp(DEFS[k].type, x->type)) { d = &DEFS[k]; break; }
        if (!d) continue;
        struct host *h = NULL;
        struct arec *a = x->target[0] ? find_a(m, x->target) : NULL;
        if (!a) {   /* _device-info has no SRV; its instance name is the hostname label */
            for (int k = 0; k < m->na; k++)
                if (!strcmp(m->a[k].first, x->name)) { a = &m->a[k]; break; }
        }
        if (a) h = hosts_find4(m->hl, a->ip);
        if (!h) {   /* IPv6-only device: resolve the target through its AAAA records */
            for (int k = 0; k < m->na6 && !h; k++)
                if (!strcmp(m->a6[k].host, x->target) || !strcmp(m->a6[k].first, x->name)) h = hosts_find6(m->hl, &m->a6[k].ip);
        }
        if (!h) continue;
        char fn[NAME_LEN] = "";
        if (d->fnkey) dns_txt_get(x->txt, x->txtlen, d->fnkey, fn, sizeof fn);
        else if (d->pri > 0) {
            cpy(fn, sizeof fn, x->name);
            char *at;
            if (d->strip_at && (at = strchr(fn, '@'))) memmove(fn, at + 1, strlen(at + 1) + 1);
            if (!strcmp(d->type, "_workstation._tcp.local") && (at = strstr(fn, " ["))) *at = 0;
        }
        /* several services can name one device (AirPlay + RAOP + companion-link);
         * the highest-priority type in DEFS[] wins, ties keep the first seen */
        if (fn[0] && d->pri > h->svc_pri) { cpy(h->svc, sizeof h->svc, fn); h->svc_pri = d->pri; }
        if (d->modelkey && !h->model[0]) {
            char md[NAME_LEN];
            if (dns_txt_get(x->txt, x->txtlen, d->modelkey, md, sizeof md) && strpbrk(md, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                cpy(h->model, sizeof h->model, md);
        }
    }
    if (m->fd >= 0) close(m->fd);
    if (m->fd6 >= 0) close(m->fd6);
    free(m->in); free(m->a); free(m->a6); free(m->r); free(m->r6);
    free(m);
}
