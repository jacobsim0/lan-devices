/* Reverse DNS via getnameinfo(), on a small thread pool so slow resolvers
 * don't serialise. Results are copied into hosts only in rdns_collect(). */
#include "lan.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>

struct job { struct in_addr ip; char name[NAME_LEN]; bool done; };

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static struct job *jobs;
static int njobs, next_job, pending;

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&mu);
        int i = next_job < njobs ? next_job++ : -1;
        pthread_mutex_unlock(&mu);
        if (i < 0) return NULL;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr = jobs[i].ip;
#if defined(__APPLE__) || defined(__FreeBSD__)
        sa.sin_len = sizeof sa;
#endif
        char buf[NI_MAXHOST];
        int rc = getnameinfo((struct sockaddr *)&sa, sizeof sa, buf, sizeof buf, NULL, 0, NI_NAMEREQD);
        pthread_mutex_lock(&mu);
        if (rc == 0) cpy(jobs[i].name, sizeof jobs[i].name, buf);
        jobs[i].done = true;
        pending--;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mu);
    }
}

void rdns_start(struct hostlist *hl) {
    njobs = hl->n;
    jobs = calloc(njobs ? njobs : 1, sizeof *jobs);
    for (int i = 0; i < njobs; i++) jobs[i].ip = hl->h[i].ip;
    pending = njobs;
    int nthreads = njobs < 32 ? njobs : 32;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    for (int i = 0; i < nthreads; i++) {
        pthread_t t;
        pthread_create(&t, &at, worker, NULL);
    }
    pthread_attr_destroy(&at);
}

void rdns_collect(struct hostlist *hl, double wait_s) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += (time_t)wait_s;
    dl.tv_nsec += (long)((wait_s - (time_t)wait_s) * 1e9);
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&mu);
    while (pending > 0 && pthread_cond_timedwait(&cv, &mu, &dl) == 0) {}
    for (int i = 0; i < njobs; i++) {
        if (!jobs[i].done || !jobs[i].name[0]) continue;
        struct host *h = hosts_find(hl, jobs[i].ip);
        if (h) cpy(h->rdns, sizeof h->rdns, jobs[i].name);
    }
    pthread_mutex_unlock(&mu);
    /* jobs[] is intentionally not freed: stragglers may still write to it. */
}
