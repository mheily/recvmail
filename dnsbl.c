/*		$Id$		*/

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
#include "poll.h"
#include "workqueue.h"
#include "log.h"

static void dnsbl_query(struct work *wqa, void *udata);
static void dnsbl_response_handler(struct session *, int);
static int dnsbl_reject_early_talker(struct session *s);

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

    struct workqueue *wq;
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
    d->wq = wq_new(dnsbl_query, dnsbl_response_handler, d);

    return (d);
}

void
dnsbl_free(struct dnsbl *d)
{
    free(d->service);
    wq_free(d->wq); 
    free(d);
}

#if FIXME
//broken
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
#endif

static int
dnsbl_reject_early_talker(struct session *s)
{
	session_println(s, "421 Protocol error -- SMTP early talkers not allowed");
	return (-1);
}

static void
dnsbl_query(struct work *wqa, void *udata)
{
    struct dnsbl *d = (struct dnsbl *) udata;
    unsigned int addr;
    char fqdn[256];
    struct addrinfo hints;
    struct addrinfo *ai;
    unsigned char c[4];
    int rv;

	memcpy(&c, &addr, sizeof(c));  
    //FIXME: Was addr = s->remote_addr.s_addr;
    addr = wqa->argv0.u_i;

    /* Generate the FQDN */
    if (snprintf((char *) fqdn, sizeof(fqdn), 
                 "%d.%d.%d.%d.%s",
                 (int)((ntohl(addr) >> 0) & 0xff),
                 (int)((ntohl(addr) >> 8) & 0xff), 
                 (int)((ntohl(addr) >> 16) & 0xff), 
                 (int)((ntohl(addr) >> 24) & 0xff), 
                 d->service) >= sizeof(fqdn)) {
        wqa->retval = DNSBL_ERROR; // TODO: error handling
        return;
    }

    log_debug("query='%s' host=%d", (char *) fqdn, addr);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo((char *) fqdn, NULL, NULL, &ai);

    if (rv == EAI_NONAME) {
        DNSBL_CACHE_SET(d->good, c);
        wqa->retval = DNSBL_NOT_FOUND;
    } else if (rv == 0) {
        DNSBL_CACHE_SET(d->bad, c);
        freeaddrinfo(ai);
        wqa->retval = DNSBL_FOUND;
    } else {
        wqa->retval = DNSBL_ERROR;
    }
}


int
dnsbl_submit(struct dnsbl *d, struct session *s)
{
    struct work w;

    /* Special case: loopback (127.0.0.1) */
    if (s->remote_addr.s_addr == 16777343) {
        dnsbl_response_handler(s, DNSBL_NOT_FOUND);
        return (0);
    }

    w.sid = s->id;
    w.argc = 1;
    w.argv0.u_i = s->remote_addr.s_addr;

#if FIXME
    int res;

    // the cache is broken now
    
    /* Check the cache */
    res = dnsbl_cache_query(d, s->remote_addr.s_addr);
    if (res != DNSBL_ERROR) {
        log_debug("cached result = %d", res);
        dnsbl_response_handler(s, res);
        return (0);
    }

    log_debug("DNSBL cached MISS");

#endif

	/* Don't allow "early talkers" to send data prior to the greeting */
	s->handler = dnsbl_reject_early_talker;
	
    return wq_submit(d->wq, w);
}

static void
dnsbl_response_handler(struct session *s, int retval)
{
    log_debug("s->fd=%d", s->fd);
    if (retval == DNSBL_FOUND) {
        log_debug("rejecting client due to DNSBL");
        session_println(s, "421 ESMTP access denied");
        session_close(s);
    } else if (retval == DNSBL_NOT_FOUND || retval == DNSBL_ERROR) {
        log_debug("client is not in a DNSBL");
        session_accept(s);
        if (session_read(s) < 0)
            session_close(s);
    }
}

void *
dnsbl_dispatch(void *arg)
{
    struct dnsbl *d = (struct dnsbl *) arg;
    wq_dispatch(d->wq);
    return (NULL);
}

/**
 * Ensure that the libc stub resolver libraries are dynamically loaded 
 * prior to chroot(2).
 */
int
dnsbl_init(void)
{
    struct addrinfo hints;
    struct addrinfo *ai;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo("www.recvmail.org", NULL, NULL, &ai);
    freeaddrinfo(ai);
    if (rv == EAI_NONAME) {
        log_warning("DNS resolution failed -- check your DNS configuration and network connectivity");
        return (0);
    } else if (rv == 0) {
        return (0);
    } else {
        log_error("DNS resolution failed: internal resolver error");
        return (-1);
    }
}
