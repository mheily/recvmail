/*		$Id: address.c 119 2009-02-11 03:25:20Z mheily $		*/

/*
 * Copyright (c) 2009 Mark Heily <devel@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dnsbl.h"
#include "session.h"
#include "log.h"

struct dnsbl_query {
    struct session *sp;
    TAILQ_ENTRY(dnsbl_query) entries;
};

/* Result codes */
#define DNSBL_NOT_FOUND     (0)
#define DNSBL_FOUND         (1)
#define DNSBL_ERROR         (-1)

/* Four hour TTL for cached entries. */
#define DNSBL_CACHE_TTL   (60 * 60 * 4)    

/**
 * Set the value of a cache entry.
 *
 * @param cache either dnsbl->good or dnsbl->bad
 * @param addr the IPv4 address
 */
#define DNSBL_CACHE_SET(cache, addr) do {                               \
    cache[0][addr[3]] =                                                 \
    cache[1][addr[2]] =                                                 \
    cache[2][addr[1]] =                                                 \
    cache[3][addr[0]] = 1;                                              \
} while (0)

/* List of IPv4 addresses. Stored in reverse order (e.g. PTR record).
 * Query by checking each octet against the array. A value of 1 means the
 * address exists, a value of 0 means it does not exist.
 *
 * E.g. to test if IP addr 1.2.3.4 is in the list, evaluate:
 *
 *    iplist[0][4] && iplist[1][3] && iplist[2][2] && iplist[3][1] 
 *
 * E.g. to add IP addr 1.2.3.4 to the list, run:
 *
 *    iplist[0][4] = 1;
 *    iplist[1][3] = 1;
 *    iplist[2][2] = 1;
 *    iplist[3][1] = 1;
 *   
 */
struct dnsbl {
    /* FQDN of the DNSBL service (e.g. zen.spamhaus.org) */
    char         *service;

    /* Blacklist and whitelisted IPs. These should be flushed every 4 hours
     * as a crude way of clearing the cache.
     */
    unsigned char good[4][256];
    unsigned char bad[4][256];
    time_t        refresh;

    /* Query list */
    TAILQ_HEAD(,dnsbl_query) query;
    pthread_mutex_t   query_lock;
    pthread_cond_t    query_pending;
};

struct dnsbl *
dnsbl_new(const char *service)
{
    struct dnsbl *d;

    if ((d = calloc(1, sizeof(*d))) == NULL)
        return (NULL);

    d->service = strdup(service);
    if (d->service == NULL) {
        free(d);
        return (NULL);
    }
    d->refresh = time(NULL) + DNSBL_CACHE_TTL;
    TAILQ_INIT(&d->query);
    pthread_mutex_init(&d->query_lock, NULL);
    pthread_cond_init(&d->query_pending, NULL);

    return (d);
}

static void
dnsbl_response_handler(struct session *s, int res)
{
    if (res == DNSBL_FOUND) {
        log_debug("rejecting client due to DNSBL");
        session_println(s, "421 ESMTP access denied");
        session_close(s);
        free(s);
    } else if (res == DNSBL_NOT_FOUND || res == DNSBL_ERROR) {
        log_debug("client is not in a DNSBL");
        session_accept(s);
    }
}

static int
dnsbl_cache_query(struct dnsbl *d, unsigned int addr)
{
    unsigned char c[4];

    memcpy(&c, &addr, sizeof(c));  

    if (d->good[0][c[3]] && d->good[1][c[2]] &&
            d->good[2][c[1]] && d->good[3][c[0]]) 
                return (DNSBL_NOT_FOUND);

    if (d->bad[0][c[3]] && d->bad[1][c[2]] &&
            d->bad[2][c[1]] && d->bad[3][c[0]]) 
                return (DNSBL_FOUND);
    
    return (DNSBL_ERROR);
}


int
dnsbl_query(struct dnsbl *d, unsigned int addr)
{
    char fqdn[256];
    struct addrinfo hints;
    struct addrinfo *ai;
    unsigned char c[4];
    int rv;

    memcpy(&c, &addr, sizeof(c));  

    /* Generate the FQDN */
    if (snprintf((char *) fqdn, sizeof(fqdn), 
                 "%d.%d.%d.%d.%s",
                 c[3], c[2], c[1], c[0], d->service) >= sizeof(fqdn))
        return (DNSBL_ERROR); // TODO: error handling

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo((char *) fqdn, NULL, NULL, &ai);

    if (rv == EAI_NONAME) {
        DNSBL_CACHE_SET(d->good, c);
        return (DNSBL_NOT_FOUND);
    } else if (rv == 0) {
        DNSBL_CACHE_SET(d->bad, c);
        freeaddrinfo(ai);
        return (DNSBL_FOUND);
    } else {
        return (DNSBL_ERROR); // TODO: error handling
    }
}


int
dnsbl_submit(struct dnsbl *d, struct session *s)
{
    int res;
    struct dnsbl_query *q;

    /* Check the cache */
    res = dnsbl_cache_query(d, s->remote_addr.s_addr);
    if (res != DNSBL_ERROR) {
        log_debug("cached result = %d", res);
        dnsbl_response_handler(s, res);
        return (0);
    }

    log_debug("DNSBL cached MISS");

    /* Create a new request */
    if ((q = malloc(sizeof(*q))) == NULL)
        return (-1);
    q->sp = s;

    /* Add the request to the queue */
    pthread_mutex_lock(&d->query_lock);
    TAILQ_INSERT_TAIL(&d->query, q, entries);
    pthread_cond_signal(&d->query_pending);
    pthread_mutex_unlock(&d->query_lock);

    return (0);
}

void *
dnsbl_dispatch(void *arg)
{
    struct dnsbl *d = (struct dnsbl *) arg;
    struct dnsbl_query *q;
    int res;

    for (;;) {

        /* Wait for a work item and remove it from the queue */
        pthread_mutex_lock(&d->query_lock);
        while (TAILQ_EMPTY(&d->query)) {
            pthread_cond_wait(&d->query_pending, &d->query_lock);
            if ((q = TAILQ_FIRST(&d->query)) == NULL) {
                continue;
            }
        }
        TAILQ_REMOVE(&d->query, q, entries);
        pthread_mutex_unlock(&d->query_lock);

        res = dnsbl_query(d, q->sp->remote_addr.s_addr);
        dnsbl_response_handler(q->sp, res);
        free(q);
    }

    return (NULL);
}

int
dnsbl_init(void)
{
    struct addrinfo hints;
    struct addrinfo *ai;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo("www.recvmail.org", NULL, NULL, &ai);
    if (rv == EAI_NONAME) {
        log_warning("DNS resolution failed -- check your DNS configuration and network connectivity");
        freeaddrinfo(ai);
        return (0);
    } else if (rv == 0) {
        freeaddrinfo(ai);
        return (0);
    } else {
        log_error("DNS resolution failed: internal resolver error");
        return (-1);
    }
}
