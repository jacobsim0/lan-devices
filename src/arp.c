/* Active ARP sweep of the local subnet using libpcap (works on Linux and macOS). */
#include "lan.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

struct arp {
    pcap_t *p;
    const struct iface *ifc;
    struct hostlist *hl;
    uint8_t *seen;
    uint32_t lo, hi;
};

struct arp *arp_open(const struct iface *ifc, char *err, size_t errsz) {
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
    if (pcap_compile(p, &fp, "arp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(p, &fp);
        pcap_freecode(&fp);
    }
    pcap_setnonblock(p, 1, eb);
    struct arp *a = calloc(1, sizeof *a);
    a->p = p;
    a->ifc = ifc;
    return a;
}

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

static void on_pkt(u_char *u, const struct pcap_pkthdr *h, const u_char *b) {
    struct arp *a = (struct arp *)u;
    if (h->caplen < 42 || b[12] != 0x08 || b[13] != 0x06) return;
    const u_char *ar = b + 14;
    if (ar[2] != 8 || ar[3] != 0 || ar[4] != 6 || ar[5] != 4) return;
    if (ar[6] != 0 || ar[7] != 2) return;   /* replies only */
    struct in_addr ip;
    memcpy(&ip, ar + 14, 4);
    if (ip.s_addr == a->ifc->ip.s_addr) return;
    uint32_t n = ntohl(ip.s_addr);
    if (n >= a->lo && n <= a->hi) a->seen[n - a->lo] = 1;
    hosts_add(a->hl, ip, ar + 8);
}

static void drain(struct arp *a, double secs) {
    double t = now_s() + secs;
    do {
        pcap_dispatch(a->p, -1, on_pkt, (u_char *)a);
        usleep(5000);
    } while (now_s() < t);
}

int arp_scan(struct arp *a, struct hostlist *hl, double linger) {
    uint32_t ip = ntohl(a->ifc->ip.s_addr), mask = ntohl(a->ifc->mask.s_addr);
    uint32_t net = ip & mask, bc = net | ~mask;
    uint32_t lo = net + 1, hi = bc - 1;
    if (mask >= 0xfffffffe) { lo = net; hi = bc; }
    if (hi < lo || hi - lo + 1 > 65536) return -1;
    a->lo = lo; a->hi = hi; a->hl = hl;
    a->seen = calloc(hi - lo + 1, 1);
    unsigned gap_us = (hi - lo + 1 <= 1024) ? 1000 : 250;
    uint8_t f[42];
    for (int pass = 0; pass < 2; pass++) {
        for (uint32_t u = lo; u <= hi; u++) {
            if (u == ip || a->seen[u - lo]) continue;
            build(f, a->ifc, htonl(u));
            if (pcap_inject(a->p, f, sizeof f) < 0) g_send_errors++;
            usleep(gap_us);
            if (((u - lo) & 15) == 0) pcap_dispatch(a->p, -1, on_pkt, (u_char *)a);
        }
        drain(a, pass == 0 ? 0.3 : linger);
    }
    free(a->seen);
    a->seen = NULL;
    return hl->n;
}

void arp_close(struct arp *a) {
    if (!a) return;
    pcap_close(a->p);
    free(a);
}
