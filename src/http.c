/* http.c — a deliberately tiny HTTP/1.0 server for --watch.
 *
 * One listening socket. Requests are answered inline from the poll loop (they
 * are a few bytes and the responses are small), so the scanner never needs a
 * thread. idle_ms() is the sleep every other module uses: it waits on this
 * socket instead of sleeping blind, so /metrics stays responsive mid-scan.
 * Gotcha: on BSD/macOS accepted sockets inherit O_NONBLOCK from the listener;
 * we clear it or an early recv() would return nothing. */
#include "lan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

static int lfd = -1;
static http_handler handler;

int http_fd(void) { return lfd; }

int http_start(const char *listen_spec, http_handler h, char *err, size_t errsz) {
    char spec[128], *port;
    cpy(spec, sizeof spec, listen_spec);
    struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT };
    struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY) };
    bool v6 = true;
    if ((port = strrchr(spec, ':'))) {
        *port++ = 0;
        if (spec[0] && strcmp(spec, "*")) {
            if (inet_pton(AF_INET, spec, &sa4.sin_addr) == 1) v6 = false;
            else if (inet_pton(AF_INET6, spec, &sa6.sin6_addr) != 1) { snprintf(err, errsz, "bad listen address %s", spec); return -1; }
        }
    } else port = spec;
    int p = atoi(port);
    if (p <= 0 || p > 65535) { snprintf(err, errsz, "bad listen port %s", port); return -1; }
    sa6.sin6_port = sa4.sin_port = htons((uint16_t)p);
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0 && v6) { v6 = false; fd = socket(AF_INET, SOCK_STREAM, 0); }   /* no IPv6 stack */
    if (fd < 0) { snprintf(err, errsz, "socket failed"); return -1; }
    int one = 1, zero = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (v6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);    /* dual-stack */
    if (bind(fd, v6 ? (struct sockaddr *)&sa6 : (struct sockaddr *)&sa4, v6 ? sizeof sa6 : sizeof sa4) < 0 || listen(fd, 16) < 0) {
        snprintf(err, errsz, "cannot listen on %s", listen_spec);
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    lfd = fd;
    handler = h;
    return 0;
}

/* "GET /metrics HTTP/1.1" -> "/metrics" (query string dropped). 0 on success. */
int http_parse_request(const char *req, char *path, size_t pathsz) {
    if (strncmp(req, "GET ", 4) && strncmp(req, "HEAD ", 5)) return -1;
    const char *p = strchr(req, ' ') + 1;
    const char *end = p;
    while (*end && *end != ' ' && *end != '?' && *end != '\r' && *end != '\n') end++;
    if (end == p || *p != '/' || (size_t)(end - p) >= pathsz) return -1;
    memcpy(path, p, end - p);
    path[end - p] = 0;
    return 0;
}

static void answer(int c) {
    char req[1024], path[256];
    fcntl(c, F_SETFL, fcntl(c, F_GETFL) & ~O_NONBLOCK);   /* BSD: accepted sockets inherit O_NONBLOCK */
    struct timeval tv = { 1, 0 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    ssize_t n = recv(c, req, sizeof req - 1, 0);
    if (n <= 0) return;
    req[n] = 0;
    static char body[1 << 20];
    const char *ctype = "text/plain; charset=utf-8";
    const char *status = "200 OK";
    if (http_parse_request(req, path, sizeof path) != 0) { status = "400 Bad Request"; cpy(body, sizeof body, "bad request\n"); }
    else {
        body[0] = 0;
        handler(path, body, sizeof body, &ctype);
        if (!body[0]) { status = "404 Not Found"; cpy(body, sizeof body, "not found\n"); }
    }
    char hdr[256];
    int hl = snprintf(hdr, sizeof hdr, "HTTP/1.0 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", status, ctype, strlen(body));
    if (send(c, hdr, hl, 0) < 0) return;
    if (strncmp(req, "HEAD", 4)) {
        size_t off = 0, len = strlen(body);
        while (off < len) { ssize_t w = send(c, body + off, len - off, 0); if (w <= 0) break; off += (size_t)w; }
    }
}

void http_serve(void) {
    if (lfd < 0) return;
    for (int i = 0; i < 32; i++) {              /* bound work per call */
        int c = accept(lfd, NULL, NULL);
        if (c < 0) return;
        answer(c);
        close(c);
    }
}

void idle_ms(int ms) {
    if (lfd < 0) { usleep((useconds_t)ms * 1000); return; }
    struct pollfd pf = { lfd, POLLIN, 0 };
    if (poll(&pf, 1, ms) > 0) http_serve();
}
