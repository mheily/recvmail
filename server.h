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

#include <event.h>
#include <netinet/in.h>
#include <pthread.h>
#include "queue.h"

struct session;

struct work {
    struct session *session;
STAILQ_ENTRY(work) entries;
};

struct server {
    int             port;	/* The port number to bind(2) to */
    struct in_addr  addr;	/* The IP address to listen(2) to */
    int             fd;		/* The descriptor returned by socket(2) */
    struct sockaddr sa;		/* The socket address of the server */
    
    char           *chrootdir;	/* The directory to chroot(2) to */
    char           *uid;        /* The symbolic user-ID to setuid(2) to */
    char           *gid;        /* The symbolic group-ID to setgid(2) to */

    struct event    ev_accept;  /* libevent accept() equivalent */
LIST_HEAD(,session) client;
     
    /* Work queue containing sessions to be serviced. */
STAILQ_HEAD(,work)  workq;
    pthread_cond_t  workq_not_empty;
    pthread_mutex_t workq_lock;

    /* Threads to service each connection */
    struct worker  *worker;
    size_t          num_workers;

    /* The number of seconds to wait for incoming data from the client */
    int             timeout_read;

    /* The number of seconds to wait to send data to the client */
    int             timeout_write;

    /* Called once during server_init() */
    int            (*init_hook)(void);

    /* Called after accept(2) */
    void           (*accept_hook) (struct session *);

    /* Called when data is available to read(2) */
    int            (*read_hook) (struct session *, char *);

    /* Called prior to close(2) for a session */
    void           (*close_hook) (struct session *);

    /* Sends a 'fatal internal error' message to the client before closing 
     */
    void           (*abort_hook) (struct session *);

    /* Sends a 'timeout' message to a client that is idle too long */
    void            (*timeout_hook) (struct session *);

    /* Sends a 'too many errors' message to a misbehaving client before
     * closing */
    //DEADWOOD:void            (*reject_hook) (struct session *);
};

struct worker {
    pthread_t   tid;
    int         id;
    int         delivery_counter;
};

extern struct server srv;

#define SCHEDULE(s, listname)  do {                             \
    pthread_mutex_lock(&srv.sched_lock);                        \
    LIST_REMOVE((s), entries);                                  \
    LIST_INSERT_HEAD(&srv.listname, (s), entries);              \
    pthread_cond_signal(&srv.listname##_not_empty);             \
    pthread_mutex_unlock(&srv.sched_lock);                      \
} while (0)

int  protocol_close(struct session *);
int  server_dispatch(void);
int  server_init(struct server *);
void state_transition(struct session *, int);
void server_update_pollset(struct server *);

#endif /* _SERVER_H */
