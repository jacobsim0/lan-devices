/* DNS wire-format helpers. Used by mDNS, reverse DNS and the unit tests.
 * All readers are bounds-checked; malformed input returns -1 / false. */
#include "lan.h"
#include <string.h>

/* Read a (possibly compressed) name at `off`. Labels are copied raw (UTF-8,
 * spaces and all). full = all labels dotted, first = first label, rest = the
 * remaining labels dotted. Returns the offset just past the name in the
 * original (uncompressed) position, or -1 if malformed. */
int dns_name_read(const uint8_t *p, int len, int off, struct dname *d) {
    int jumps = 0, ret = -1, nl = 0;
    size_t fo = 0, io = 0, ro = 0;
    d->full[0] = d->first[0] = d->rest[0] = 0;
    for (;;) {
        if (off < 0 || off >= len) return -1;
        int l = p[off];
        if (l == 0) { off++; break; }
        if ((l & 0xc0) == 0xc0) {
            if (off + 1 >= len) return -1;
            if (ret < 0) ret = off + 2;
            off = ((l & 0x3f) << 8) | p[off + 1];
            if (++jumps > 20) return -1;          /* pointer loop */
            continue;
        }
        if (l & 0xc0) return -1;                  /* reserved label types */
        off++;
        if (off + l > len) return -1;
        if (nl > 0 && fo < sizeof d->full - 1) d->full[fo++] = '.';
        if (nl > 1 && ro < sizeof d->rest - 1) d->rest[ro++] = '.';
        for (int i = 0; i < l; i++) {
            char c = (char)p[off + i];
            if (fo < sizeof d->full - 1) d->full[fo++] = c;
            if (nl == 0) { if (io < sizeof d->first - 1) d->first[io++] = c; }
            else         { if (ro < sizeof d->rest - 1)  d->rest[ro++]  = c; }
        }
        nl++;
        off += l;
    }
    d->full[fo] = d->first[io] = d->rest[ro] = 0;
    return ret < 0 ? off : ret;
}

/* Find key=value in a TXT rdata (sequence of length-prefixed strings). */
bool dns_txt_get(const uint8_t *t, int len, const char *key, char *out, size_t osz) {
    size_t kl = strlen(key);
    int i = 0;
    while (i < len) {
        int l = t[i++];
        if (i + l > len) break;
        if ((size_t)l > kl && memcmp(t + i, key, kl) == 0 && t[i + kl] == '=') {
            cpyn(out, osz, (const char *)t + i + kl + 1, l - kl - 1);
            return out[0] != 0;
        }
        i += l;
    }
    return false;
}

/* Write a dotted name as labels. Caller guarantees room (strlen + 2). */
int dns_put_name(uint8_t *b, int off, const char *name) {
    const char *s = name;
    for (;;) {
        const char *dot = strchr(s, '.');
        int l = dot ? (int)(dot - s) : (int)strlen(s);
        if (l > 63) l = 63;
        if (l > 0) {
            b[off++] = (uint8_t)l;
            memcpy(b + off, s, l);
            off += l;
        }
        if (!dot) break;
        s = dot + 1;
    }
    b[off++] = 0;
    return off;
}
