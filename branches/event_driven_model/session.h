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


#ifndef _SESSION_H
#define _SESSION_H

#include <arpa/inet.h>
#include <netinet/in.h>

#include "message.h"
#include "socket.h"
#include "queue.h"
#include "log.h"

/* A client session */
struct session {
    int (*handler)(struct session *);    /* 
                                          * Callback function when data is ready. 
                                          * This MUST be the first element in the structure.
                                          */ 
    unsigned long   id;             /* Session ID */

    int             fd;		        /* The client socket descriptor */
    int flags;          // see SFL_*
    struct in_addr  remote_addr;	/* IP address of the client */
    struct socket_buf in_buf;
    STAILQ_HEAD(,nbuf) out_buf;     /* Output buffer */

    /* ---------- protocol specific members ------------ */

    struct message msg;

    enum {
      FSYNC_PENDING = 0,
      FSYNC_COMPLETE
    } fsync_state;

    enum {
      CONTINUE_AFTER_FSYNC = 0,
      QUIT_AFTER_FSYNC,
      RSET_AFTER_FSYNC,
    } fsync_post_action;

    /* The state determines which SMTP commands are valid */
    enum {
        SMTP_STATE_HELO,
        SMTP_STATE_MAIL,
        SMTP_STATE_RCPT,
        SMTP_STATE_DATA,
        SMTP_STATE_FSYNC,
        SMTP_STATE_QUIT,
    } smtp_state;
    unsigned int    errors;	/* The number of protocol errors */

    /* ---------- end protocol specific members ---------- */

    LIST_ENTRY(session)  st_entries;
    TAILQ_ENTRY(session) workq_entries;
};

int  session_write(struct session *, const char *, size_t size);
int  session_printf(struct session *, const char *, ...);
int  session_println(struct session *, const char *);
void            session_close(struct session *s);
struct session * session_new(int fd);
void            session_free(struct session *s);
char *          remote_addr(char *dest, size_t len, const struct session *s);
//struct session * session_lookup(int fd);
int session_readln(struct session *s);
int session_fsync(struct session *, int (*)(struct session *));

void session_table_init(void);

void    sched_enqueue(struct session *);
void    sched_dequeue(struct session *);
void *  session_syncer(void *arg);

int     session_poll_enable(struct session *); //in server.c
void    session_accept(struct session *);

#endif /* _SESSION_H */
