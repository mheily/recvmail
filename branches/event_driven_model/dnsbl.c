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

#include "log.h"

struct dnsbl_query {
    unsigned int addr;
    LIST_ENTRY(dnsbl_query) entries;
};

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

    LIST_HEAD(,dnsbl_query) query;
    pthread_mutex_t   query_lock;
    pthread_cond_t    not_empty;
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
    LIST_INIT(&d->query);
    pthread_mutex_init(&d->query_lock, NULL);
    pthread_cond_init(&d->not_empty, NULL);

    return (d);
}


/**
 * @return 1 if "bad", 0 if "good", or -1 if not found
 */
int
dnsbl_cache_query(struct dnsbl *d, unsigned int addr)
{
    unsigned char c[4];

    memcpy(&c, &addr, sizeof(c));  

    if (d->good[0][c[3]] && d->good[1][c[2]] &&
            d->good[2][c[1]] && d->good[3][c[0]]) 
                return (0);

    if (d->bad[0][c[3]] && d->bad[1][c[2]] &&
            d->bad[2][c[1]] && d->bad[3][c[0]]) 
                return (1);
    
    return (-1);
}


/**
 * @return 1 if "bad", 0 if "good", or -1 if not found
 */
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
        return (-1); // TODO: error handling

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo((char *) fqdn, NULL, NULL, &ai);
    if (rv < 0)
        return (-1); // TODO: error handling
    if (rv == EAI_NONAME)
        DNSBL_CACHE_SET(d->good, c);
    else if (rv == 0)
        DNSBL_CACHE_SET(d->bad, c);

    freeaddrinfo(ai);
    return (-1);
}

static void *
dnsbl_dispatch(void *arg)
{
    struct dnsbl *d = (struct dnsbl *) arg;

}
