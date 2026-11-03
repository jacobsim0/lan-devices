/* IPv6 discovery. There is no IPv6 equivalent of an ARP sweep (2^64 addresses
 * per link), so we ping the all-nodes multicast group ff02::1 from our
 * link-local address; every host that answers reveals its MAC and link-local
 * address to cap.c. Hosts that don't answer multicast pings (Windows, by
 * default) are still caught passively from their own neighbour discovery,
 * MLD and mDNS traffic during the listen window. */
#include "lan.h"
#include <string.h>
#include <arpa/inet.h>

uint16_t icmp6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const uint8_t *payload, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) {
        sum += ((unsigned)src->s6_addr[i] << 8) | src->s6_addr[i + 1];
        sum += ((unsigned)dst->s6_addr[i] << 8) | dst->s6_addr[i + 1];
    }
    sum += (uint32_t)len;
    sum += 58;                                     /* next header: ICMPv6 */
    for (int i = 0; i + 1 < len; i += 2) sum += ((unsigned)payload[i] << 8) | payload[i + 1];
    if (len & 1) sum += (unsigned)payload[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Ethernet + IPv6 + ICMPv6 Echo Request to ff02::1. Returns frame length or -1. */
int nd6_build_echo(const struct iface *ifc, uint8_t *f, size_t sz, uint16_t seq) {
    if (!ifc->have_ll6 || sz < 70) return -1;
    static const uint8_t data[8] = { 'l', 'a', 'n', '-', 'd', 'e', 'v', '!' };
    struct in6_addr dst = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    memset(f, 0, 70);
    f[0] = 0x33; f[1] = 0x33; f[5] = 0x01;         /* 33:33:00:00:00:01 = ff02::1 */
    memcpy(f + 6, ifc->mac, 6);
    f[12] = 0x86; f[13] = 0xdd;
    uint8_t *ip = f + 14;
    ip[0] = 0x60;                                  /* version 6 */
    ip[4] = 0; ip[5] = 16;                         /* payload length */
    ip[6] = 58;                                    /* ICMPv6 */
    ip[7] = 64;                                    /* hop limit */
    memcpy(ip + 8, &ifc->ll6, 16);
    memcpy(ip + 24, &dst, 16);
    uint8_t *ic = ip + 40;
    ic[0] = 128; ic[1] = 0;                        /* echo request */
    ic[4] = 0x4c; ic[5] = 0x44;                    /* identifier */
    ic[6] = seq >> 8; ic[7] = seq & 0xff;
    memcpy(ic + 8, data, 8);
    uint16_t cs = icmp6_checksum(&ifc->ll6, &dst, ic, 16);
    ic[2] = cs >> 8; ic[3] = cs & 0xff;
    return 70;
}

void nd6_probe(struct cap *c, const struct iface *ifc, uint16_t seq) {
    uint8_t f[70];
    if (nd6_build_echo(ifc, f, sizeof f, seq) > 0) cap_send(c, f, 70);
}
