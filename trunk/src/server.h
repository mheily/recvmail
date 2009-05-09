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

#ifndef _SERVER_H
#define _SERVER_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include "queue.h"

struct session;
struct net_interface;

struct server {
    int             port;	    /* The port number to bind(2) to */
    char           *chrootdir;	/* The directory to chroot(2) to */
    char           *uid;        /* The symbolic user-ID to setuid(2) to */
    char           *gid;        /* The symbolic group-ID to setgid(2) to */

    pthread_t        fsyncer_tid;

    /* The number of seconds to wait for incoming data from the client */
    int             timeout_read;

    /* The number of seconds to wait to send data to the client */
    int             timeout_write;

    struct dnsbl     *dnsbl;
    unsigned long     next_sid;     /* Next available Session-ID */
    LIST_HEAD(,net_interface) if_list;
};

extern struct server srv;

int  protocol_close(struct session *);
int  server_disconnect(int);
int  server_dispatch(void);
int  server_init(struct server *_srv);
int  server_bind(void);
void server_update_pollset(struct server *);


#endif /* _SERVER_H */
