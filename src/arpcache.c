/* Passive discovery: read the kernel's ARP table. No root needed; only shows
 * devices this machine has talked to recently. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef __linux__
int arpcache_read(const struct iface *ifc, struct hostlist *hl) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[256], ips[64], hw[64], dev[64];
    unsigned type, flags;
    int n = 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }   /* header line */
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%63s 0x%x 0x%x %63s %*s %63s", ips, &type, &flags, hw, dev) != 5) continue;
        if (!(flags & 0x2) || strcmp(dev, ifc->name)) continue;   /* ATF_COM: complete entries only */
        struct in_addr ip;
        unsigned m[6];
        if (inet_pton(AF_INET, ips, &ip) != 1) continue;
        if (sscanf(hw, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) continue;
        uint8_t mac[6];
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
        if (!in_subnet(ifc, ip) || ip.s_addr == ifc->ip.s_addr) continue;
        hosts_add(hl, ip, mac);
        n++;
    }
    fclose(f);
    return n;
}
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

#define RT_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

#include <unistd.h>
#include <sys/wait.h>

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

/* Fallback when the routing sysctl yields nothing (seen under some sandboxes):
 * parse `arp -an`, whose output format has been stable for decades. */
static int arpcache_cmd(const struct iface *ifc, struct hostlist *hl) {
    char *const argv[] = { "arp", "-an", NULL };
    pid_t pid;
    FILE *f = run_capture("/usr/sbin/arp", argv, &pid);
    if (!f) return -1;
    char line[256], ips[64], hw[64], dev[64];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%*s (%63[^)]) at %63s on %63s", ips, hw, dev) != 3) continue;
        if (strcmp(dev, ifc->name)) continue;
        struct in_addr ip;
        unsigned m[6];
        if (inet_pton(AF_INET, ips, &ip) != 1) continue;
        if (sscanf(hw, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) continue;
        uint8_t mac[6];
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
        if (!in_subnet(ifc, ip) || ip.s_addr == ifc->ip.s_addr) continue;
        hosts_add(hl, ip, mac);
        n++;
    }
    fclose(f);
    waitpid(pid, NULL, 0);
    return n;
}

int arpcache_read(const struct iface *ifc, struct hostlist *hl) {
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };
    size_t need = 0;
    if (sysctl(mib, 6, NULL, &need, NULL, 0) < 0 || need == 0) return arpcache_cmd(ifc, hl);
    char *buf = malloc(need);
    if (!buf || sysctl(mib, 6, buf, &need, NULL, 0) < 0) { free(buf); return arpcache_cmd(ifc, hl); }
    unsigned ifidx = if_nametoindex(ifc->name);
    int n = 0;
    for (char *next = buf; next < buf + need;) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)next;
        next += rtm->rtm_msglen;
        struct sockaddr_in *sin = (struct sockaddr_in *)(rtm + 1);
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)((char *)sin + RT_ROUNDUP(sin->sin_len));
        if (rtm->rtm_index != ifidx || sdl->sdl_alen != 6) continue;
        struct in_addr ip = sin->sin_addr;
        if (!in_subnet(ifc, ip) || ip.s_addr == ifc->ip.s_addr) continue;
        hosts_add(hl, ip, (const uint8_t *)LLADDR(sdl));
        n++;
    }
    free(buf);
    return n;
}
#endif
