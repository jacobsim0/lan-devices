/* NetBIOS name service: send a NBSTAT ("*") query to every host; Windows boxes,
 * Samba shares and some NAS units answer with their computer name. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct nbns { int fd; struct hostlist *hl; uint8_t q[50]; };

struct nbns *nbns_start(struct hostlist *hl) {
    struct nbns *n = calloc(1, sizeof *n);
    n->hl = hl;
    n->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->fd < 0) { free(n); return NULL; }
    fcntl(n->fd, F_SETFL, O_NONBLOCK);
    /* header: id, flags=0, qdcount=1 */
    uint8_t *q = n->q;
    memset(q, 0, sizeof n->q);
    q[0] = 0x4c; q[1] = 0x44; q[5] = 1;
    /* name "*" padded with NULs to 16 bytes, first-level encoded */
    q[12] = 0x20;
    uint8_t raw[16] = { '*' };
    for (int i = 0; i < 16; i++) {
        q[13 + 2 * i]     = 'A' + (raw[i] >> 4);
        q[13 + 2 * i + 1] = 'A' + (raw[i] & 0xf);
    }
    q[45] = 0;                       /* name terminator */
    q[46] = 0; q[47] = 0x21;         /* NBSTAT */
    q[48] = 0; q[49] = 0x01;         /* IN */
    nbns_query(n);
    return n;
}

int nbns_fd(struct nbns *n) { return n ? n->fd : -1; }

void nbns_query(struct nbns *n) {
    if (!n) return;
    for (int i = 0; i < n->hl->n; i++) {
        struct host *h = &n->hl->h[i];
        if (h->self || h->nbt[0]) continue;
        struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(137), .sin_addr = h->ip };
        sendto(n->fd, n->q, sizeof n->q, 0, (struct sockaddr *)&to, sizeof to);
    }
}

static int skip_name(const uint8_t *p, int len, int off) {
    while (off < len) {
        int l = p[off];
        if (l == 0) return off + 1;
        if ((l & 0xc0) == 0xc0) return off + 2;
        off += 1 + l;
    }
    return -1;
}

void nbns_recv(struct nbns *n) {
    if (!n) return;
    uint8_t p[1500];
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    for (;;) {
        ssize_t len = recvfrom(n->fd, p, sizeof p, 0, (struct sockaddr *)&from, &fl);
        if (len < 12) return;
        struct host *h = hosts_find(n->hl, from.sin_addr);
        if (!h || h->nbt[0]) continue;
        int off = 12;
        int qd = (p[4] << 8) | p[5];
        for (int i = 0; i < qd && off >= 0; i++) { off = skip_name(p, len, off); if (off >= 0) off += 4; }
        if (off < 0) continue;
        off = skip_name(p, len, off);
        if (off < 0 || off + 11 > len) continue;
        off += 10;                               /* type, class, ttl, rdlen */
        int num = p[off++];
        for (int i = 0; i < num && off + 18 <= len; i++, off += 18) {
            uint8_t suffix = p[off + 15];
            unsigned flags = (p[off + 16] << 8) | p[off + 17];
            if (suffix != 0x00 || (flags & 0x8000)) continue;   /* workstation, unique */
            char name[16];
            memcpy(name, p + off, 15);
            name[15] = 0;
            for (int k = 14; k >= 0 && (name[k] == ' ' || name[k] == 0); k--) name[k] = 0;
            if (name[0]) { cpy(h->nbt, sizeof h->nbt, name); break; }
        }
    }
}

void nbns_finish(struct nbns *n) {
    if (!n) return;
    close(n->fd);
    free(n);
}
