/* arp.c — the IPv4 sweep.
 *
 * Owns: building an ARP "who has X?" request and sending one to every address
 *       in the subnet, two passes (the second only to non-responders), then a
 *       short linger. Replies are not handled here: cap.c sees them and adds
 *       the rows. Sleeps go through idle_ms() so --watch keeps serving HTTP. */
#include "lan.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static void build(uint8_t *f, const struct iface *i, uint32_t tip_be) {
    memset(f, 0xff, 6);                 /* dst: broadcast */
    memcpy(f + 6, i->mac, 6);           /* src */
    f[12] = 0x08; f[13] = 0x06;         /* ethertype ARP */
    uint8_t *a = f + 14;
    a[0] = 0; a[1] = 1;                 /* htype Ethernet */
    a[2] = 8; a[3] = 0;                 /* ptype IPv4 */
    a[4] = 6; a[5] = 4;                 /* hlen, plen */
    a[6] = 0; a[7] = 1;                 /* request */
    memcpy(a + 8, i->mac, 6);
    memcpy(a + 14, &i->ip.s_addr, 4);
    memset(a + 18, 0, 6);
    memcpy(a + 24, &tip_be, 4);
}

static void drain(struct cap *c, double secs) {
    double t = now_s() + secs;
    do {
        cap_poll(c);
        idle_ms(5);
    } while (now_s() < t);
}

int arp_sweep(struct cap *c, const struct iface *ifc, struct hostlist *hl, double linger) {
    uint32_t ip = ntohl(ifc->ip.s_addr), mask = ntohl(ifc->mask.s_addr);
    uint32_t net = ip & mask, bc = net | ~mask;
    uint32_t lo = net + 1, hi = bc - 1;
    if (mask >= 0xfffffffe) { lo = net; hi = bc; }
    if (hi < lo || hi - lo + 1 > 65536) return -1;
    unsigned gap_us = (hi - lo + 1 <= 1024) ? 1000 : 250;
    uint8_t f[42];
    for (int pass = 0; pass < 2; pass++) {
        for (uint32_t u = lo; u <= hi; u++) {
            struct in_addr t = { .s_addr = htonl(u) };
            if (u == ip || (pass && hosts_find4(hl, t))) continue;
            build(f, ifc, t.s_addr);
            cap_send(c, f, sizeof f);
            usleep(gap_us);
            if (((u - lo) & 15) == 0) cap_poll(c);
        }
        drain(c, pass == 0 ? 0.3 : linger);
    }
    return hl->n;
}
