/* MAC vendor lookup from an IEEE OUI file. Accepts three formats:
 *   arp-scan ieee-oui.txt   "0000F0\tSAMSUNG ELECTRONICS CO., LTD."
 *   IEEE oui.txt            "00-00-0F   (hex)\t\tNEXT, INC."
 *   IEEE oui.csv            "MA-L,00000F,NEXT INC,..." (also MA-M/MA-S 28/36-bit) */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct ent { char pfx[10]; char *name; };
static struct ent *E;
static int N, C;

static const char *DEFAULT_PATHS[] = {
    "/usr/share/lan-devices/oui.csv",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/opt/homebrew/share/arp-scan/ieee-oui.txt",
    "/usr/local/share/arp-scan/ieee-oui.txt",
    "/usr/share/ieee-data/oui.csv",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/misc/oui.txt",
    "/usr/share/hwdata/oui.txt",
    NULL
};

static void add(const char *hex, int hl, const char *name) {
    if (hl < 6 || hl > 9 || !name) return;
    while (*name == ' ' || *name == '\t') name++;
    size_t nl = strlen(name);
    while (nl && (name[nl - 1] == '\n' || name[nl - 1] == '\r' || name[nl - 1] == ' ' || name[nl - 1] == '\t' || name[nl - 1] == '"')) nl--;
    if (!nl) return;
    if (N == C) { C = C ? C * 2 : 8192; E = realloc(E, C * sizeof *E); if (!E) die("out of memory"); }
    for (int i = 0; i < hl; i++) E[N].pfx[i] = (char)toupper((unsigned char)hex[i]);
    E[N].pfx[hl] = 0;
    E[N].name = strndup(name, nl);
    N++;
}

static int cmp(const void *a, const void *b) { return strcmp(((const struct ent *)a)->pfx, ((const struct ent *)b)->pfx); }

/* Parse one line of any supported OUI file into (hex prefix, its length, name).
 * The line may be modified in place. Returns false for comments, addresses, etc. */
bool oui_parse_line(char *line, char *hex, int *hexlen, const char **name) {
    int hl = 0;
    *hexlen = 0; *name = NULL;
    if (!strncmp(line, "MA-", 3)) {                 /* CSV: Registry,Assignment,Organization Name,Address */
        char *p = strchr(line, ',');
        if (!p) return false;
        p++;
        while (isxdigit((unsigned char)*p) && hl < 12) hex[hl++] = *p++;
        if (*p != ',') return false;
        p++;
        char *nm = p, *end;
        if (*p == '"') { nm = p + 1; end = strchr(nm, '"'); }
        else end = strchr(p, ',');
        if (end) *end = 0;
        *hexlen = hl; *name = nm;
        return hl >= 6 && hl <= 9 && *nm;
    }
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || !isxdigit((unsigned char)*p)) return false;
    while ((isxdigit((unsigned char)*p) || *p == '-') && hl < 12) { if (*p != '-') hex[hl++] = *p; p++; }
    if (*p == '\t') { *name = p + 1; }
    else {
        while (*p == ' ') p++;
        if (!strncmp(p, "(hex)", 5)) *name = p + 5;
        else if (!strncmp(p, "(base 16)", 9)) *name = p + 9;
        else return false;
    }
    while (**name == ' ' || **name == '\t') (*name)++;
    *hexlen = hl;
    return hl >= 6 && hl <= 9 && **name && **name != '\n';
}

static void parse_line(char *line) {
    char hex[13];
    int hl;
    const char *name;
    if (oui_parse_line(line, hex, &hl, &name)) add(hex, hl, name);
}

int oui_load(const char *path) {
    FILE *f = NULL;
    if (path && *path) f = fopen(path, "r");
    for (int i = 0; !f && DEFAULT_PATHS[i]; i++) f = fopen(DEFAULT_PATHS[i], "r");
    if (!f) {
        char p[600];
        snprintf(p, sizeof p, "%s/oui.csv", store_dir());
        f = fopen(p, "r");
        if (!f) { snprintf(p, sizeof p, "%s/oui.txt", store_dir()); f = fopen(p, "r"); }
    }
    if (!f) return 0;
    char line[1024];
    while (fgets(line, sizeof line, f)) parse_line(line);
    fclose(f);
    qsort(E, N, sizeof *E, cmp);
    return N;
}

const char *oui_lookup(const uint8_t *mac) {
    if (!N) return NULL;
    char hex[13];
    snprintf(hex, sizeof hex, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    static const int lens[] = { 9, 7, 6 };
    for (int i = 0; i < 3; i++) {
        struct ent key;
        memcpy(key.pfx, hex, lens[i]);
        key.pfx[lens[i]] = 0;
        struct ent *e = bsearch(&key, E, N, sizeof *E, cmp);
        if (e) return e->name;
    }
    return NULL;
}
