#include "lan.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#endif

/* Which local IP would a packet to the internet leave from? (UDP connect sends nothing.) */
static int default_ip(struct in_addr *out) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(53) };
    inet_pton(AF_INET, "1.1.1.1", &d.sin_addr);
    struct sockaddr_in l;
    socklen_t ll = sizeof l;
    int rc = connect(s, (struct sockaddr *)&d, sizeof d);
    if (rc == 0) rc = getsockname(s, (struct sockaddr *)&l, &ll);
    close(s);
    if (rc) return -1;
    *out = l.sin_addr;
    return 0;
}

int iface_detect(const char *want, struct iface *out, char *err, size_t errsz) {
    struct ifaddrs *ifa0, *ifa;
    if (getifaddrs(&ifa0)) { snprintf(err, errsz, "getifaddrs failed"); return -1; }
    memset(out, 0, sizeof *out);
    struct in_addr dip = { 0 };
    bool have_dip = !want && default_ip(&dip) == 0;
    bool found = false;

    for (ifa = ifa0; ifa && !found; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
        struct sockaddr_in *a = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *m = (struct sockaddr_in *)ifa->ifa_netmask;
        if (want) { if (strcmp(ifa->ifa_name, want)) continue; }
        else if (ifa->ifa_flags & IFF_POINTOPOINT) continue;      /* VPN tunnels can't be ARP-scanned */
        else if (have_dip && a->sin_addr.s_addr != dip.s_addr) continue;
        cpy(out->name, sizeof out->name, ifa->ifa_name);
        out->ip = a->sin_addr;
        out->mask.s_addr = m ? m->sin_addr.s_addr : htonl(0xffffff00);
        found = true;
    }
    if (!found && !want && have_dip) {   /* default route is a tunnel: take the first LAN interface instead */
        for (ifa = ifa0; ifa && !found; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) continue;
            struct sockaddr_in *a = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *m = (struct sockaddr_in *)ifa->ifa_netmask;
            cpy(out->name, sizeof out->name, ifa->ifa_name);
            out->ip = a->sin_addr;
            out->mask.s_addr = m ? m->sin_addr.s_addr : htonl(0xffffff00);
            found = true;
        }
    }
    if (!found) {
        snprintf(err, errsz, want ? "no IPv4 address on %s" : "no usable IPv4 interface found", want);
        freeifaddrs(ifa0);
        return -1;
    }
    bool have_mac = false;
    for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, out->name)) continue;
#ifdef __linux__
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        struct sockaddr_ll *ll = (struct sockaddr_ll *)ifa->ifa_addr;
        if (ll->sll_halen != 6) continue;
        memcpy(out->mac, ll->sll_addr, 6);
#else
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        struct sockaddr_dl *dl = (struct sockaddr_dl *)ifa->ifa_addr;
        if (dl->sdl_alen != 6) continue;
        memcpy(out->mac, LLADDR(dl), 6);
#endif
        have_mac = true;
        break;
    }
    /* IPv6: our link-local address (echo source) and on-link prefixes (to tell neighbours from forwarded traffic) */
    for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6 || strcmp(ifa->ifa_name, out->name)) continue;
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ifa->ifa_addr;
        struct sockaddr_in6 *m = (struct sockaddr_in6 *)ifa->ifa_netmask;
        if (IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)) {
            if (!out->have_ll6) { out->ll6 = a->sin6_addr; out->have_ll6 = true; }
            continue;
        }
        if (IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) || out->npfx6 >= 4) continue;
        int plen = 0;
        if (m) for (int i = 0; i < 16; i++) { uint8_t b = m->sin6_addr.s6_addr[i]; while (b & 0x80) { plen++; b <<= 1; } if (b) break; }
        if (!plen) plen = 64;
        out->pfx6[out->npfx6].addr = a->sin6_addr;
        out->pfx6[out->npfx6].plen = plen;
        out->npfx6++;
    }
    out->index = if_nametoindex(out->name);
    freeifaddrs(ifa0);
    if (!have_mac) { snprintf(err, errsz, "%s has no Ethernet address", out->name); return -1; }
    return 0;
}
