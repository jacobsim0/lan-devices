/* --watch: scan every N seconds, remember every device ever seen, log joins
 * and departures, and expose the state as Prometheus metrics and JSON. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#define OFFLINE_AFTER 3        /* consecutive missed scans before a device is reported gone */

static struct seen *seen_get(struct watch *w, const char *mac) {
    for (int i = 0; i < w->n; i++) if (!strcasecmp(w->v[i].mac, mac)) return &w->v[i];
    if (w->n == w->cap) { w->cap = w->cap ? w->cap * 2 : 64; w->v = realloc(w->v, w->cap * sizeof *w->v); if (!w->v) die("out of memory"); }
    struct seen *s = &w->v[w->n++];
    memset(s, 0, sizeof *s);
    cpy(s->mac, sizeof s->mac, mac);
    return s;
}

/* file: mac \t first \t last \t name \t ip \t vendor */
void watch_load(struct watch *w, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = 0;
        char *fld[6] = { 0 }, *rest = line;
        int n = 0;
        while (n < 6 && rest) fld[n++] = strsep(&rest, "\t");   /* strsep keeps empty fields; strtok would not */
        if (n < 3 || !fld[0][0]) continue;
        struct seen *s = seen_get(w, fld[0]);
        s->first = atof(fld[1]);
        s->last = atof(fld[2]);
        if (fld[3]) cpy(s->name, sizeof s->name, fld[3]);
        if (fld[4]) cpy(s->ip, sizeof s->ip, fld[4]);
        if (fld[5]) cpy(s->vendor, sizeof s->vendor, fld[5]);
        struct in_addr a4; struct in6_addr a6;                    /* heal files written by the strtok version: */
        if (inet_pton(AF_INET, s->name, &a4) == 1 || inet_pton(AF_INET6, s->name, &a6) == 1) s->name[0] = 0;   /* an address is not a name */
        s->online = false;
        s->misses = OFFLINE_AFTER;
    }
    fclose(f);
}

int watch_save(const struct watch *w, const char *path) {
    store_mkdir_for(path);
    char tmp[700];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    for (int i = 0; i < w->n; i++) {
        const struct seen *s = &w->v[i];
        fprintf(f, "%s\t%.0f\t%.0f\t%s\t%s\t%s\n", s->mac, s->first, s->last, s->name, s->ip, s->vendor);
    }
    if (fclose(f) != 0 || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static void stamp(char *out, size_t sz, double t) {
    time_t tt = (time_t)t;
    struct tm tm;
    gmtime_r(&tt, &tm);
    strftime(out, sz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void event(double now, const char *what, const struct seen *s) {
    char ts[32];
    stamp(ts, sizeof ts, now);
    printf("%s %-7s %s %-15s %-24s %s\n", ts, what, s->mac, s->ip[0] ? s->ip : "-", s->name[0] ? s->name : "?", s->vendor);
    fflush(stdout);
}

int watch_update(struct watch *w, const struct hostlist *hl, double now, bool show_vendor) {
    int new_devices = 0;
    for (int i = 0; i < w->n; i++) w->v[i].online = false;
    for (int i = 0; i < hl->n; i++) {
        const struct host *h = &hl->h[i];
        const char *mac = mac_str(h->mac);
        bool fresh = true;
        for (int k = 0; k < w->n; k++) if (!strcasecmp(w->v[k].mac, mac)) { fresh = false; break; }
        struct seen *s = seen_get(w, mac);
        if (fresh) s->first = now;
        bool was_offline = s->misses >= OFFLINE_AFTER;
        s->last = now;
        s->online = true;
        s->misses = 0;
        s->known = h->known;
        if (h->name && strcmp(h->name, "?")) { cpy(s->name, sizeof s->name, h->name); sanitize(s->name); }
        cpy(s->src, sizeof s->src, h->src ? h->src : "-");
        if (h->ip4.s_addr) inet_ntop(AF_INET, &h->ip4, s->ip, sizeof s->ip); else s->ip[0] = 0;
        const struct in6_addr *b6 = host_best6(h);
        if (b6) inet_ntop(AF_INET6, b6, s->ip6, sizeof s->ip6); else s->ip6[0] = 0;
        if (!s->ip[0] && s->ip6[0]) cpy(s->ip, sizeof s->ip, s->ip6);
        if (show_vendor && h->vendor) { cpy(s->vendor, sizeof s->vendor, h->vendor); sanitize(s->vendor); }
        if (fresh) { new_devices++; event(now, "new", s); }
        else if (was_offline && w->scans > 0) event(now, "online", s);
    }
    for (int i = 0; i < w->n; i++) {
        struct seen *s = &w->v[i];
        if (s->online) continue;
        if (++s->misses == OFFLINE_AFTER) event(now, "offline", s);
    }
    w->scans++;
    w->last_scan_ts = now;
    return new_devices;
}

/* Prometheus label values: escape backslash, quote, newline. */
static void label(char *out, size_t sz, const char *s) {
    size_t o = 0;
    for (; *s && o + 2 < sz; s++) {
        if (*s == '\\' || *s == '"') out[o++] = '\\';
        if (*s == '\n') { out[o++] = '\\'; out[o++] = 'n'; continue; }
        out[o++] = *s;
    }
    out[o] = 0;
}

#define EMIT(...) do { int _n = snprintf(out + o, sz > o ? sz - o : 0, __VA_ARGS__); if (_n > 0) o += (size_t)_n; } while (0)

void watch_metrics(const struct watch *w, char *out, size_t sz) {
    size_t o = 0;
    int online = 0;
    for (int i = 0; i < w->n; i++) online += (w->v[i].online || w->v[i].misses < OFFLINE_AFTER);
    EMIT("# HELP lan_device_online 1 if the device answered in the latest scan, 0 if it has been missing for %d scans.\n", OFFLINE_AFTER);
    EMIT("# TYPE lan_device_online gauge\n");
    EMIT("# HELP lan_device_last_seen_seconds Unix time the device last answered.\n# TYPE lan_device_last_seen_seconds gauge\n");
    EMIT("# HELP lan_device_first_seen_seconds Unix time the device was first ever seen.\n# TYPE lan_device_first_seen_seconds gauge\n");
    for (int i = 0; i < w->n; i++) {
        const struct seen *s = &w->v[i];
        char name[2 * NAME_LEN], vendor[2 * NAME_LEN], ip[96];
        label(name, sizeof name, s->name[0] ? s->name : "?");
        label(vendor, sizeof vendor, s->vendor);
        label(ip, sizeof ip, s->ip);
        EMIT("lan_device_online{mac=\"%s\",name=\"%s\",ip=\"%s\",vendor=\"%s\",known=\"%s\"} %d\n",
             s->mac, name, ip, vendor, s->known ? "true" : "false", s->online || s->misses < OFFLINE_AFTER ? 1 : 0);
        EMIT("lan_device_last_seen_seconds{mac=\"%s\",name=\"%s\"} %.0f\n", s->mac, name, s->last);
        EMIT("lan_device_first_seen_seconds{mac=\"%s\",name=\"%s\"} %.0f\n", s->mac, name, s->first);
    }
    EMIT("# HELP lan_devices_online Devices currently considered online (answered within the last %d scans).\n# TYPE lan_devices_online gauge\nlan_devices_online %d\n", OFFLINE_AFTER, online);
    EMIT("# HELP lan_devices_known_total Devices ever seen.\n# TYPE lan_devices_known_total gauge\nlan_devices_known_total %d\n", w->n);
    EMIT("# HELP lan_scans_total Completed scans since start.\n# TYPE lan_scans_total counter\nlan_scans_total %u\n", w->scans);
    EMIT("# HELP lan_scan_duration_seconds Duration of the latest scan.\n# TYPE lan_scan_duration_seconds gauge\nlan_scan_duration_seconds %.2f\n", w->last_scan_dur);
    EMIT("# HELP lan_scan_last_timestamp_seconds Unix time the latest scan finished.\n# TYPE lan_scan_last_timestamp_seconds gauge\nlan_scan_last_timestamp_seconds %.0f\n", w->last_scan_ts);
    EMIT("# HELP lan_send_errors_total Packets that could not be sent.\n# TYPE lan_send_errors_total counter\nlan_send_errors_total %u\n", g_send_errors);
}

static void jstr(char *out, size_t sz, const char *s) {
    size_t o = 0;
    for (; *s && o + 6 < sz; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\t') { out[o++] = '\\'; out[o++] = 't'; }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c < 0x20) o += (size_t)snprintf(out + o, sz - o, "\\u%04x", c);
        else out[o++] = c;
    }
    out[o] = 0;
}

void watch_json(const struct watch *w, char *out, size_t sz) {
    size_t o = 0;
    EMIT("{\"scans\":%u,\"last_scan\":%.0f,\"devices\":[", w->scans, w->last_scan_ts);
    for (int i = 0; i < w->n; i++) {
        const struct seen *s = &w->v[i];
        char name[2 * NAME_LEN], vendor[2 * NAME_LEN];
        jstr(name, sizeof name, s->name);
        jstr(vendor, sizeof vendor, s->vendor);
        EMIT("%s{\"mac\":\"%s\",\"ip\":\"%s\",\"ip6\":\"%s\",\"name\":\"%s\",\"source\":\"%s\",\"vendor\":\"%s\",\"known\":%s,\"online\":%s,\"first_seen\":%.0f,\"last_seen\":%.0f}",
             i ? "," : "", s->mac, s->ip, s->ip6, name, s->src, vendor, s->known ? "true" : "false", s->online ? "true" : "false", s->first, s->last);
    }
    EMIT("]}\n");
}
