/* libFuzzer harness: feeds arbitrary bytes to every network-facing parser.
 * Build and run with `make fuzz` (needs a clang with -fsanitize=fuzzer). */
#include "lan.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static struct iface IFC;
static bool init;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!init) {
        inet_pton(AF_INET, "192.168.0.228", &IFC.ip);
        inet_pton(AF_INET, "255.255.255.0", &IFC.mask);
        inet_pton(AF_INET6, "2601:207:400:fd2::", &IFC.pfx6[0].addr); IFC.pfx6[0].plen = 64; IFC.npfx6 = 1;
        init = true;
    }
    if (size > 9000) return 0;
    struct hostlist hl = { 0 };
    for (int i = 1; i < 6; i++) {
        uint8_t mac[6] = { 0, 1, 2, 3, 4, (uint8_t)i };
        struct in_addr a; a.s_addr = htonl(0xc0a80000u | i * 50); hosts_add4(&hl, mac, a);
    }
    struct in6_addr ll; inet_pton(AF_INET6, "fe80::dead:1", &ll);
    hosts_add6(&hl, (uint8_t[]){ 0xde, 0xad, 0, 0, 0, 1 }, &ll);

    struct cap *c = cap_new(&IFC, &hl);
    cap_frame(c, data, (int)size);
    cap_close(c);

    struct mdns *m = mdns_new(&IFC, &hl);
    mdns_handle(m, data, (int)size);
    mdns_finish(m);

    char out[NAME_LEN];
    nbns_parse_reply(data, (int)size, out, sizeof out);

    struct dname d;
    dns_name_read(data, (int)size, 0, &d);
    dns_txt_get(data, (int)size, "fn", out, sizeof out);

    if (size < 1024) {
        char line[1025]; memcpy(line, data, size); line[size] = 0;
        char hex[13]; int hl2; const char *name;
        oui_parse_line(line, hex, &hl2, &name);
    }
    free(hl.h);
    return 0;
}
