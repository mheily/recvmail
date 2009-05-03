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

#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dnsbl.h"
#include "session.h"
#include "poll.h"
#include "resolver.h"
#include "workqueue.h"
#include "log.h"

static void dnsbl_query(struct work *wqa, void *udata);
static void dnsbl_response_handler(struct session *, int);
static int  dnsbl_reject_early_talker(struct session *s);

struct dnsbl {
    /* FQDN of the DNSBL service (e.g. zen.spamhaus.org) */
    char *service;
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
    unsigned char c[4];
    int rv;

	memcpy(&c, &addr, sizeof(c));  
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

    rv = resolver_lookup_addr(&addr, (char *) fqdn);
    if (rv < 0) {
        wqa->retval = DNSBL_ERROR;
    } else if (rv == 0) {
        wqa->retval = (addr == 0) ? DNSBL_NOT_FOUND : DNSBL_FOUND;
    }
}


int
dnsbl_submit(struct dnsbl *d, struct session *s)
{
    struct work w;

    /* TODO: Find out if there are IPv6 DNSBLs */
    if (socket_get_family(s->sock) == AF_INET6) {
        dnsbl_response_handler(s, DNSBL_NOT_FOUND);
        return (0);
    }

    /* TODO: check the whitelist (e.g. for loopback, */
    /* Example:
    if (s->remote_addr.s_addr == 16777343) {
        dnsbl_response_handler(s, DNSBL_NOT_FOUND);
        return (0);
    }
    */

    w.sid = s->id;
    w.argc = 1;
    w.argv0.u_i = socket_get_peeraddr4(s->sock);

	/* Don't allow "early talkers" to send data prior to the greeting */
	s->handler = dnsbl_reject_early_talker;
	
    return wq_submit(d->wq, w);
}


static void
dnsbl_response_handler(struct session *s, int retval)
{
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
