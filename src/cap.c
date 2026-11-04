/* cap.c — the raw packet layer (libpcap).
 *
 * Owns: the one pcap handle used for the whole run: arp.c and nd6.c send
 *       frames through cap_send(); every ARP or IPv6 frame that arrives is
 *       passed to cap_frame(), which creates or updates the host row for its
 *       source MAC. This is the only file that needs root (to open the
 *       interface); main.c drops root right after cap_open().
 * Gotcha: a frame is only attributed when its source is really a neighbour
 *       (link-local, or inside one of our IPv6 prefixes, or in our IPv4
 *       subnet). Otherwise traffic the router forwards from the internet
 *       would be credited to the router's MAC.
 * Tests: cap_new() builds the struct without pcap so cap_frame() can be fed
 *       crafted frames. */
#include "lan.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct cap {
    pcap_t *p;
    const struct iface *ifc;
    struct hostlist *hl;
};

struct cap *cap_new(const struct iface *ifc, struct hostlist *hl) {
    struct cap *c = calloc(1, sizeof *c);
    if (!c) die("out of memory");
    c->ifc = ifc;
    c->hl = hl;
    return c;
}

struct cap *cap_open(const struct iface *ifc, struct hostlist *hl, char *err, size_t errsz) {
    char eb[PCAP_ERRBUF_SIZE] = "";
    pcap_t *p = pcap_create(ifc->name, eb);
    if (!p) { snprintf(err, errsz, "%s", eb); return NULL; }
    pcap_set_snaplen(p, 128);
    pcap_set_promisc(p, 0);
    pcap_set_timeout(p, 50);
    pcap_set_immediate_mode(p, 1);        /* no BPF buffering: replies arrive as they come */
    if (pcap_activate(p) < 0) {
        snprintf(err, errsz, "%s", pcap_geterr(p));
        pcap_close(p);
        return NULL;
    }
    if (pcap_datalink(p) != DLT_EN10MB) {
        snprintf(err, errsz, "%s is not an Ethernet interface", ifc->name);
        pcap_close(p);
        return NULL;
    }
    struct bpf_program fp;
    if (pcap_compile(p, &fp, "arp or ip6", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(p, &fp);
        pcap_freecode(&fp);
    }
    pcap_setnonblock(p, 1, eb);
    struct cap *c = cap_new(ifc, hl);
    c->p = p;
    return c;
}

/* Point the capture at the host list for the current scan (watch mode uses a fresh list per cycle). */
void cap_set_hosts(struct cap *c, struct hostlist *hl) { if (c) c->hl = hl; }

/* Attribute a frame to a neighbour. Pure function of the bytes: used by tests and the fuzzer. */
void cap_frame(struct cap *c, const uint8_t *b, int len) {
    if (len < 14) return;
    const uint8_t *smac = b + 6;
    if (smac[0] & 1) return;                                   /* multicast/broadcast source: bogus */
    if (!memcmp(smac, c->ifc->mac, 6)) return;                 /* our own transmissions */
    unsigned et = ((unsigned)b[12] << 8) | b[13];
    if (et == 0x0806 && len >= 42) {                           /* ARP */
        const uint8_t *ar = b + 14;
        if (ar[2] != 8 || ar[3] != 0 || ar[4] != 6 || ar[5] != 4) return;
        unsigned op = ar[7];
        if (ar[6] != 0 || (op != 1 && op != 2)) return;        /* request or reply */
        struct in_addr ip;
        memcpy(&ip, ar + 14, 4);
        if (!ip.s_addr || ip.s_addr == c->ifc->ip.s_addr || !in_subnet(c->ifc, ip)) return;
        hosts_add4(c->hl, ar + 8, ip);
    } else if (et == 0x86dd && len >= 54) {                    /* IPv6: 14 Ethernet + 40 header */
        const uint8_t *ip6 = b + 14;
        if ((ip6[0] >> 4) != 6) return;
        struct in6_addr src;
        memcpy(&src, ip6 + 8, 16);
        if (IN6_IS_ADDR_UNSPECIFIED(&src) || IN6_IS_ADDR_MULTICAST(&src) || IN6_IS_ADDR_LOOPBACK(&src)) return;
        if (!on_link6(c->ifc, &src)) return;                   /* forwarded by a router, not a neighbour */
        hosts_add6(c->hl, smac, &src);
    }
}

static void on_pkt(u_char *u, const struct pcap_pkthdr *h, const u_char *b) {
    cap_frame((struct cap *)u, b, (int)h->caplen);
}

void cap_poll(struct cap *c) {
    if (c && c->p) pcap_dispatch(c->p, -1, on_pkt, (u_char *)c);
}

int cap_send(struct cap *c, const uint8_t *frame, int len) {
    if (!c || !c->p) return -1;
    int rc = pcap_inject(c->p, frame, len);
    if (rc < 0) g_send_errors++;
    return rc;
}

void cap_close(struct cap *c) {
    if (!c) return;
    if (c->p) pcap_close(c->p);
    free(c);
}
