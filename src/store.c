/* Aliases (your labels) and the learned-name cache. Tab-separated "mac\tname",
 * identical to the original bash tool, so existing files keep working. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

static char dir[512], apath[600], cpath[600];

const char *store_dir(void) {
    if (dir[0]) return dir;
    const char *d = getenv("LAN_DEVICES_DIR");
    if (d && *d) { cpy(dir, sizeof dir, d); return dir; }
    const char *home = NULL, *su = getenv("SUDO_USER");
    struct passwd *pw;
    if (su && (pw = getpwnam(su))) home = pw->pw_dir;       /* under sudo, use the caller's home */
    if (!home) home = getenv("HOME");
    if (!home && (pw = getpwuid(getuid()))) home = pw->pw_dir;
    snprintf(dir, sizeof dir, "%s/.config/lan-devices", home ? home : "/tmp");
    return dir;
}

const char *aliases_path(void) {
    const char *e = getenv("LAN_DEVICES_ALIASES");
    if (e && *e) return e;
    snprintf(apath, sizeof apath, "%s/aliases", store_dir());
    return apath;
}

const char *cache_path(void) {
    const char *e = getenv("LAN_DEVICES_CACHE");
    if (e && *e) return e;
    snprintf(cpath, sizeof cpath, "%s/cache", store_dir());
    return cpath;
}

static void chown_to_caller(const char *p) {
    const char *u = getenv("SUDO_UID"), *g = getenv("SUDO_GID");
    if (geteuid() == 0 && u && g) { if (chown(p, (uid_t)atoi(u), (gid_t)atoi(g)) != 0) { /* best effort */ } }
}

static void ensure_parent(const char *path) {
    char p[600];
    cpy(p, sizeof p, path);
    char *slash = strrchr(p, '/');
    if (!slash) return;
    *slash = 0;
    /* mkdir -p */
    for (char *q = p + 1; *q; q++) {
        if (*q != '/') continue;
        *q = 0;
        if (mkdir(p, 0755) == 0) chown_to_caller(p);
        *q = '/';
    }
    if (mkdir(p, 0755) == 0) chown_to_caller(p);
}

static void lower(char *s) { for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32; }

void kv_load(struct kvlist *l, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == '\n') continue;
        char *mac = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        if (!*p || *p == '\n') continue;
        *p++ = 0;
        while (*p == ' ' || *p == '\t') p++;
        char *name = p;
        size_t nl = strlen(name);
        while (nl && (name[nl - 1] == '\n' || name[nl - 1] == '\r')) name[--nl] = 0;
        if (!nl) continue;
        lower(mac);
        if (l->n == l->cap) { l->cap = l->cap ? l->cap * 2 : 64; l->v = realloc(l->v, l->cap * sizeof *l->v); if (!l->v) die("out of memory"); }
        cpy(l->v[l->n].mac, sizeof l->v[l->n].mac, mac);
        cpy(l->v[l->n].name, sizeof l->v[l->n].name, name);
        l->n++;
    }
    fclose(f);
}

const char *kv_get(const struct kvlist *l, const char *mac) {
    for (int i = 0; i < l->n; i++) if (!strcasecmp(l->v[i].mac, mac)) return l->v[i].name;
    return NULL;
}

void kv_put_front(struct kvlist *l, const char *mac, const char *name) {
    for (int i = 0; i < l->n; i++) {
        if (strcasecmp(l->v[i].mac, mac)) continue;
        memmove(&l->v[i], &l->v[i + 1], (l->n - i - 1) * sizeof *l->v);
        l->n--;
        break;
    }
    if (l->n == l->cap) { l->cap = l->cap ? l->cap * 2 : 64; l->v = realloc(l->v, l->cap * sizeof *l->v); if (!l->v) die("out of memory"); }
    memmove(&l->v[1], &l->v[0], l->n * sizeof *l->v);
    cpy(l->v[0].mac, sizeof l->v[0].mac, mac);
    lower(l->v[0].mac);
    cpy(l->v[0].name, sizeof l->v[0].name, name);
    l->n++;
}

int kv_save(const struct kvlist *l, const char *path) {
    ensure_parent(path);
    char tmp[700];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    for (int i = 0; i < l->n; i++) fprintf(f, "%s\t%s\n", l->v[i].mac, l->v[i].name);
    if (fclose(f) != 0 || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    chown_to_caller(path);
    return 0;
}
