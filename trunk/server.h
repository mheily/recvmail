/*		$Id: $		*/

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
#include <pthread.h>
#include "queue.h"

struct session;

struct server {
    int             port;	/* The port number to bind(2) to */
    struct in_addr  addr;	/* The IP address to listen(2) to */
    int             fd;		/* The descriptor returned by socket(2) */
    struct sockaddr sa;		/* The socket address of the server */
    struct thread_pool *tpool;

    /* 
     * Each server has a dedicated thread which handles fsync(2) calls
     * by sessions. These are the variables to support this function.
     */
    int              spooldir_fd;
    LIST_HEAD(,session) fsync_queue;
    pthread_t        fsyncer; 
    pthread_cond_t   fsyncer_cond;
    pthread_mutex_t  fsyncer_lock;

    /**
     * At any given time, a session may be on one of the following lists.
     * 
     */
    LIST_HEAD(,session) runnable;
    LIST_HEAD(,session) idle;
    LIST_HEAD(,session) io_wait;

    struct evcb * evcb;

    /* The number of seconds to wait for incoming data from the client */
    int             timeout_read;

    /* The number of seconds to wait to send data to the client */
    int             timeout_write;

    /* Called after accept(2) */
    void           (*accept_hook) (struct session *);

    /* Called prior to close(2) for a session */
    void           (*close_hook) (struct session *);

    /* Called when there is data available to read(2) from the client */
    void           (*read_hook) (struct session *);

    /* Sends a 'fatal internal error' message to the client before closing 
     */
    void           (*abort_hook) (struct session *);

    /* Sends a 'timeout' message to a client that is idle too long */
    void            (*timeout_hook) (struct session *);

    /* Sends a 'too many errors' message to a misbehaving client before
     * closing */
    //DEADWOOD:void            (*reject_hook) (struct session *);
};

int  protocol_close(struct server *, struct session *);
int  server_disconnect(struct server *, int);
int  server_dispatch(struct server *);
int  server_bind(struct server *);
void server_init(void);
void state_transition(struct session *s, int events);
void server_update_pollset(struct server *srv);
void drop_privileges(const char *user, const char *group, const char *chroot_to);

#endif /* _SERVER_H */
