/* arpcache.c — discovery without root.
 *
 * Reads the devices the OS already knows: its ARP table (IPv4) and neighbour
 * table (IPv6). Only devices this machine has talked to recently appear, which
 * is why the full sweep is preferred. Used when --passive is given or when
 * libpcap cannot be opened.
 *
 * Linux: /proc/net/arp for IPv4, rtnetlink RTM_GETNEIGH for IPv6 (there is
 *        no text table for IPv6 neighbours).
 * macOS: the routing sysctl for both families; if that returns nothing (seen
 *        under some sandboxes) it execs arp(8) / ndp(8) directly, no shell. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>

static bool parse_mac(const char *s, uint8_t *mac) {
    unsigned m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) return false;
    for (int i = 0; i < 6; i++) { if (m[i] > 255) return false; mac[i] = (uint8_t)m[i]; }
    return true;
}

static void add4(const struct iface *ifc, struct hostlist *hl, const char *ips, const uint8_t *mac) {
    struct in_addr ip;
    if (inet_pton(AF_INET, ips, &ip) != 1 || !in_subnet(ifc, ip) || ip.s_addr == ifc->ip.s_addr) return;
    hosts_add4(hl, mac, ip);
}

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

static int read_proc_arp(const struct iface *ifc, struct hostlist *hl) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[256], ips[64], hw[64], dev[64];
    unsigned type, flags;
    int n = 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }   /* header line */
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%63s 0x%x 0x%x %63s %*s %63s", ips, &type, &flags, hw, dev) != 5) continue;
        if (!(flags & 0x2) || strcmp(dev, ifc->name)) continue;   /* ATF_COM: complete entries only */
        uint8_t mac[6];
        if (!parse_mac(hw, mac)) continue;
        add4(ifc, hl, ips, mac);
        n++;
    }
    fclose(f);
    return n;
}

/* IPv6 neighbours via rtnetlink RTM_GETNEIGH (there is no /proc text table for them). */
static int read_neigh6(const struct iface *ifc, struct hostlist *hl) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct { struct nlmsghdr nh; struct ndmsg nd; } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof req.nd);
    req.nh.nlmsg_type = RTM_GETNEIGH;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.nd.ndm_family = AF_INET6;
    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) { close(fd); return -1; }
    char *buf = malloc(1 << 16);
    int n = 0;
    for (bool done = false; !done;) {
        ssize_t len = recv(fd, buf, 1 << 16, 0);
        if (len <= 0) break;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
            if (nh->nlmsg_type != RTM_NEWNEIGH) continue;
            struct ndmsg *nd = NLMSG_DATA(nh);
            if (nd->ndm_family != AF_INET6 || nd->ndm_ifindex != (int)ifc->index) continue;
            if (!(nd->ndm_state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT))) continue;
            struct in6_addr *dst = NULL; const uint8_t *lladdr = NULL;
            int rlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof *nd);
            for (struct rtattr *rta = (struct rtattr *)((char *)nd + NLMSG_ALIGN(sizeof *nd)); RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
                if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == 16) dst = RTA_DATA(rta);
                if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6) lladdr = RTA_DATA(rta);
            }
            if (!dst || !lladdr || !on_link6(ifc, dst) || !memcmp(lladdr, ifc->mac, 6)) continue;
            hosts_add6(hl, lladdr, dst);
            n++;
        }
    }
    free(buf);
    close(fd);
    return n;
}

int arpcache_read(const struct iface *ifc, struct hostlist *hl) {
    int n4 = read_proc_arp(ifc, hl);
    int n6 = read_neigh6(ifc, hl);
    return n4 < 0 && n6 < 0 ? -1 : (n4 > 0 ? n4 : 0) + (n6 > 0 ? n6 : 0);
}

#else   /* macOS / BSD */
static void add6(const struct iface *ifc, struct hostlist *hl, const char *ips, const uint8_t *mac) {
    struct in6_addr ip;
    char buf[64];
    cpy(buf, sizeof buf, ips);
    char *pct = strchr(buf, '%');          /* fe80::1%en0 */
    if (pct) *pct = 0;
    if (inet_pton(AF_INET6, buf, &ip) != 1 || !on_link6(ifc, &ip) || !memcmp(mac, ifc->mac, 6)) return;
    hosts_add6(hl, mac, &ip);
}

/* Run a program with no shell and return its stdout as a FILE*. */
static FILE *run_capture(const char *path, char *const argv[], pid_t *pid) {
    int pfd[2];
    if (pipe(pfd) < 0) return NULL;
    *pid = fork();
    if (*pid < 0) { close(pfd[0]); close(pfd[1]); return NULL; }
    if (*pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[0]); close(pfd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execv(path, argv);
        _exit(127);
    }
    close(pfd[1]);
    return fdopen(pfd[0], "r");
}

#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/route.h>

#define RT_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

/* Routing-table dump of link-layer entries for one address family. -1 if the
 * sysctl yields nothing (seen under some sandboxes). */
static int read_sysctl(const struct iface *ifc, struct hostlist *hl, int family) {
    int mib[6] = { CTL_NET, PF_ROUTE, 0, family, NET_RT_FLAGS, RTF_LLINFO };
    size_t need = 0;
    if (sysctl(mib, 6, NULL, &need, NULL, 0) < 0 || need == 0) return -1;
    char *buf = malloc(need);
    if (!buf || sysctl(mib, 6, buf, &need, NULL, 0) < 0) { free(buf); return -1; }
    int n = 0;
    for (char *next = buf; next < buf + need;) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)next;
        next += rtm->rtm_msglen;
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)((char *)sa + RT_ROUNDUP(sa->sa_len));
        if (rtm->rtm_index != ifc->index || sdl->sdl_family != AF_LINK || sdl->sdl_alen != 6) continue;
        const uint8_t *mac = (const uint8_t *)LLADDR(sdl);
        if (family == AF_INET) {
            struct in_addr ip = ((struct sockaddr_in *)sa)->sin_addr;
            if (!in_subnet(ifc, ip) || ip.s_addr == ifc->ip.s_addr) continue;
            hosts_add4(hl, mac, ip);
        } else {
            struct in6_addr ip = ((struct sockaddr_in6 *)sa)->sin6_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&ip)) { ip.s6_addr[2] = ip.s6_addr[3] = 0; }   /* KAME embeds the scope here */
            if (!on_link6(ifc, &ip) || !memcmp(mac, ifc->mac, 6)) continue;
            hosts_add6(hl, mac, &ip);
        }
        n++;
    }
    free(buf);
    return n;
}

/* Fallback: parse `arp -an` / `ndp -an`, whose output formats have been stable for decades. */
static int read_cmd(const struct iface *ifc, struct hostlist *hl, int family) {
    char *const argv4[] = { "arp", "-an", NULL };
    char *const argv6[] = { "ndp", "-an", NULL };
    pid_t pid;
    FILE *f = run_capture(family == AF_INET ? "/usr/sbin/arp" : "/usr/sbin/ndp", family == AF_INET ? argv4 : argv6, &pid);
    if (!f) return -1;
    char line[256], ips[64], hw[64], dev[64];
    uint8_t mac[6];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        if (family == AF_INET) {
            if (sscanf(line, "%*s (%63[^)]) at %63s on %63s", ips, hw, dev) != 3) continue;
        } else {
            if (sscanf(line, "%63s %63s %63s", ips, hw, dev) != 3 || !strchr(ips, ':')) continue;
        }
        if (strcmp(dev, ifc->name) || !parse_mac(hw, mac)) continue;
        if (family == AF_INET) add4(ifc, hl, ips, mac); else add6(ifc, hl, ips, mac);
        n++;
    }
    fclose(f);
    waitpid(pid, NULL, 0);
    return n;
}

int arpcache_read(const struct iface *ifc, struct hostlist *hl) {
    int n4 = read_sysctl(ifc, hl, AF_INET);
    if (n4 < 0) n4 = read_cmd(ifc, hl, AF_INET);
    int n6 = read_sysctl(ifc, hl, AF_INET6);
    if (n6 < 0) n6 = read_cmd(ifc, hl, AF_INET6);
    return n4 < 0 && n6 < 0 ? -1 : (n4 > 0 ? n4 : 0) + (n6 > 0 ? n6 : 0);
}
#endif
