/* mDNS / DNS-SD without Avahi or Bonjour libraries: we multicast our own
 * queries to 224.0.0.251:5353 and parse whatever comes back.
 *   - PTR queries for well-known service types -> instance names (AirPlay,
 *     Chromecast fn=, HomeKit, printers, Sonos, SMB) and model strings
 *   - reverse PTR (x.x.x.x.in-addr.arpa) -> hostname.local
 *   - any A record seen in additional sections -> hostname for that IP */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT  5353

struct dname { char full[256]; char first[128]; char rest[192]; };
struct inst  { char key[256]; char name[128]; char type[192]; char target[256]; uint8_t txt[700]; int txtlen; };
struct arec  { char host[256]; char first[128]; struct in_addr ip; };
struct rrev  { struct in_addr ip; char host[128]; };

struct mdns {
    int fd;
    bool qu;                     /* true = couldn't bind 5353, ask for unicast replies */
    const struct iface *ifc;
    struct hostlist *hl;
    struct inst *in; int nin, capin;
    struct arec *a;  int na,  capa;
    struct rrev *r;  int nr,  capr;
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

static unsigned u16(const uint8_t *p, int o) { return ((unsigned)p[o] << 8) | p[o + 1]; }

/* Read a (possibly compressed) DNS name. Labels are copied raw (UTF-8, spaces
 * and all); full = all labels dotted, first = first label, rest = the others. */
static int dn_read(const uint8_t *p, int len, int off, struct dname *d) {
    int jumps = 0, ret = -1, nl = 0;
    size_t fo = 0, io = 0, ro = 0;
    d->full[0] = d->first[0] = d->rest[0] = 0;
    for (;;) {
        if (off < 0 || off >= len) return -1;
        int l = p[off];
        if (l == 0) { off++; break; }
        if ((l & 0xc0) == 0xc0) {
            if (off + 1 >= len) return -1;
            if (ret < 0) ret = off + 2;
            off = ((l & 0x3f) << 8) | p[off + 1];
            if (++jumps > 20) return -1;
            continue;
        }
        off++;
        if (off + l > len) return -1;
        if (nl > 0 && fo < sizeof d->full - 1) d->full[fo++] = '.';
        if (nl > 1 && ro < sizeof d->rest - 1) d->rest[ro++] = '.';
        for (int i = 0; i < l; i++) {
            char c = (char)p[off + i];
            if (fo < sizeof d->full - 1) d->full[fo++] = c;
            if (nl == 0) { if (io < sizeof d->first - 1) d->first[io++] = c; }
            else         { if (ro < sizeof d->rest - 1)  d->rest[ro++]  = c; }
        }
        nl++;
        off += l;
    }
    d->full[fo] = d->first[io] = d->rest[ro] = 0;
    return ret < 0 ? off : ret;
}

static bool txt_get(const uint8_t *t, int len, const char *key, char *out, size_t osz) {
    size_t kl = strlen(key);
    int i = 0;
    while (i < len) {
        int l = t[i++];
        if (i + l > len) break;
        if ((size_t)l > kl && memcmp(t + i, key, kl) == 0 && t[i + kl] == '=') {
            cpyn(out, osz, (const char *)t + i + kl + 1, l - kl - 1);
            return out[0] != 0;
        }
        i += l;
    }
    return false;
}

#define GROW(arr, n, cap, T) do { if ((n) == (cap)) { (cap) = (cap) ? (cap) * 2 : 64; \
    (arr) = realloc((arr), (cap) * sizeof(T)); if (!(arr)) die("out of memory"); } } while (0)

static struct inst *get_inst(struct mdns *m, const struct dname *n) {
    for (int i = 0; i < m->nin; i++)
        if (!strcmp(m->in[i].key, n->full)) return &m->in[i];
    if (m->nin >= 4096) return NULL;
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
    GROW(m->a, m->na, m->capa, struct arec);
    struct arec *a = &m->a[m->na++];
    cpy(a->host, sizeof a->host, n->full);
    cpy(a->first, sizeof a->first, n->first);
    a->ip = ip;
}

static void add_rev(struct mdns *m, struct in_addr ip, const char *host) {
    for (int i = 0; i < m->nr; i++) if (m->r[i].ip.s_addr == ip.s_addr) return;
    GROW(m->r, m->nr, m->capr, struct rrev);
    struct rrev *r = &m->r[m->nr++];
    r->ip = ip;
    cpy(r->host, sizeof r->host, host);
}

static bool ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcmp(s + a - b, suf);
}

static void handle(struct mdns *m, const uint8_t *p, int len) {
    if (len < 12 || !(u16(p, 2) & 0x8000)) return;      /* responses only */
    int qd = u16(p, 4), rr = u16(p, 6) + u16(p, 8) + u16(p, 10);
    int off = 12;
    struct dname n, r;
    for (int i = 0; i < qd; i++) { off = dn_read(p, len, off, &n); if (off < 0) return; off += 4; }
    for (int i = 0; i < rr; i++) {
        off = dn_read(p, len, off, &n);
        if (off < 0 || off + 10 > len) return;
        int type = u16(p, off), rdlen = u16(p, off + 8), rd = off + 10;
        off = rd + rdlen;
        if (off > len) return;
        switch (type) {
        case 1:    /* A */
            if (rdlen == 4) { struct in_addr ip; memcpy(&ip, p + rd, 4); add_a(m, &n, ip); }
            break;
        case 12: { /* PTR */
            if (dn_read(p, len, rd, &r) < 0) break;
            unsigned a, b, c, d;
            if (ends_with(n.full, ".in-addr.arpa")) {
                if (sscanf(n.full, "%u.%u.%u.%u.in-addr.arpa", &d, &c, &b, &a) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
                    struct in_addr ip = { .s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d) };
                    add_rev(m, ip, r.first);
                }
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
            if (rdlen > 6 && dn_read(p, len, rd + 6, &r) >= 0) {
                struct inst *x = get_inst(m, &n);
                if (x) cpy(x->target, sizeof x->target, r.full);
            }
            break;
        }
        }
    }
}

static int put_name(uint8_t *b, int off, const char *name) {
    const char *s = name;
    for (;;) {
        const char *dot = strchr(s, '.');
        int l = dot ? (int)(dot - s) : (int)strlen(s);
        if (l > 63) l = 63;
        b[off++] = (uint8_t)l;
        memcpy(b + off, s, l);
        off += l;
        if (!dot) break;
        s = dot + 1;
    }
    b[off++] = 0;
    return off;
}

static void send_q(struct mdns *m, const char **names, int n) {
    uint8_t b[1400];
    memset(b, 0, 12);
    int off = 12, sent = 0;
    for (int i = 0; i < n; i++) {
        if (off + strlen(names[i]) + 6 > sizeof b) break;
        sent++;
        off = put_name(b, off, names[i]);
        b[off++] = 0; b[off++] = 12;                     /* PTR */
        b[off++] = m->qu ? 0x80 : 0; b[off++] = 1;       /* IN, QU bit if we need unicast replies */
    }
    b[5] = (uint8_t)sent;   /* qdcount */
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(MDNS_PORT) };
    inet_pton(AF_INET, MDNS_GROUP, &to.sin_addr);
    sendto(m->fd, b, off, 0, (struct sockaddr *)&to, sizeof to);
}

void mdns_query(struct mdns *m) {
    if (!m) return;
    const char *svc[NDEFS];
    for (int i = 0; i < NDEFS; i++) svc[i] = DEFS[i].type;
    send_q(m, svc, NDEFS);
    /* reverse lookups, 16 questions per packet */
    static char buf[16][40];
    const char *names[16];
    int k = 0;
    for (int i = 0; i < m->hl->n; i++) {
        struct host *h = &m->hl->h[i];
        if (h->mdns[0]) continue;
        uint8_t *q = (uint8_t *)&h->ip.s_addr;
        snprintf(buf[k], sizeof buf[k], "%u.%u.%u.%u.in-addr.arpa", q[3], q[2], q[1], q[0]);
        names[k] = buf[k];
        if (++k == 16) { send_q(m, names, k); k = 0; }
    }
    if (k) send_q(m, names, k);
}

struct mdns *mdns_start(const struct iface *ifc, struct hostlist *hl) {
    struct mdns *m = calloc(1, sizeof *m);
    m->ifc = ifc;
    m->hl = hl;
    m->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m->fd < 0) { free(m); return NULL; }
    int one = 1;
    setsockopt(m->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
    setsockopt(m->fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(MDNS_PORT), .sin_addr.s_addr = INADDR_ANY };
    if (bind(m->fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        /* someone holds 5353 exclusively: use an ephemeral port and ask for unicast replies */
        sa.sin_port = 0;
        if (bind(m->fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(m->fd); free(m); return NULL; }
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

void mdns_recv(struct mdns *m) {
    if (!m) return;
    uint8_t p[9000];
    for (;;) {
        ssize_t len = recv(m->fd, p, sizeof p, 0);
        if (len <= 0) return;
        handle(m, p, (int)len);
    }
}

static struct arec *find_a(struct mdns *m, const char *host) {
    for (int i = 0; i < m->na; i++) if (!strcmp(m->a[i].host, host)) return &m->a[i];
    return NULL;
}

void mdns_finish(struct mdns *m) {
    if (!m) return;
    /* hostnames: reverse answers first, then any A record we saw */
    for (int i = 0; i < m->nr; i++) {
        struct host *h = hosts_find(m->hl, m->r[i].ip);
        if (h && !h->mdns[0]) cpy(h->mdns, sizeof h->mdns, m->r[i].host);
    }
    for (int i = 0; i < m->na; i++) {
        struct host *h = hosts_find(m->hl, m->a[i].ip);
        if (h && !h->mdns[0]) cpy(h->mdns, sizeof h->mdns, m->a[i].first);
    }
    /* service instances -> friendly names and models */
    for (int i = 0; i < m->nin; i++) {
        struct inst *x = &m->in[i];
        const struct svcdef *d = NULL;
        for (int k = 0; k < NDEFS; k++) if (!strcmp(DEFS[k].type, x->type)) { d = &DEFS[k]; break; }
        if (!d) continue;
        struct arec *a = x->target[0] ? find_a(m, x->target) : NULL;
        if (!a) {   /* _device-info has no SRV; its instance name is the hostname label */
            for (int k = 0; k < m->na; k++)
                if (!strcmp(m->a[k].first, x->name)) { a = &m->a[k]; break; }
        }
        if (!a) continue;
        struct host *h = hosts_find(m->hl, a->ip);
        if (!h) continue;
        char fn[NAME_LEN] = "";
        if (d->fnkey) txt_get(x->txt, x->txtlen, d->fnkey, fn, sizeof fn);
        else if (d->pri > 0) {
            cpy(fn, sizeof fn, x->name);
            char *at;
            if (d->strip_at && (at = strchr(fn, '@'))) memmove(fn, at + 1, strlen(at + 1) + 1);
            if (!strcmp(d->type, "_workstation._tcp.local") && (at = strstr(fn, " ["))) *at = 0;
        }
        if (fn[0] && d->pri > h->svc_pri) { cpy(h->svc, sizeof h->svc, fn); h->svc_pri = d->pri; }
        if (d->modelkey && !h->model[0]) {
            char md[NAME_LEN];
            if (txt_get(x->txt, x->txtlen, d->modelkey, md, sizeof md) && strpbrk(md, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                cpy(h->model, sizeof h->model, md);
        }
    }
    close(m->fd);
    free(m->in); free(m->a); free(m->r);
    free(m);
}
