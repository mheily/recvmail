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
#include "queue.h"

struct message;
struct socket;
struct session;

struct protocol {
    /* Called prior to close(2) for a session due to timeout */
    void           (*timeout_hook) (struct session *);

    /* Called after accept(2) */
    void           (*accept_hook) (struct session *);

    /* Called prior to close(2) for a session */
    void           (*close_hook) (struct session *);

    /* Sends a 'fatal internal error' message to the client before closing 
     */
    void           (*abort_hook) (struct session *);

    /* Sends a 'too many errors' message to a misbehaving client before
     * closing */
    //DEADWOOD:void            (*reject_hook) (struct session *);
};


/* A client session */
struct session {
   /* 
    * Callback function when data is ready. 
    * This MUST be the first element in the structure.
    */ 
    int (*handler)(struct session *); 
    struct protocol *proto;

    u_long      id;             /* Session ID */
    struct socket *sock;
    char       *buf;
    size_t      buf_len;
    time_t          timeout;  

    /* ---------- protocol specific members ------------ */

    struct message *msg;

    /* The state determines which SMTP commands are valid */
    enum {
        SMTP_STATE_HELO,
        SMTP_STATE_MAIL,
        SMTP_STATE_RCPT,
        SMTP_STATE_DATA,
        SMTP_STATE_FSYNC,
        SMTP_STATE_QUIT,
    } smtp_state;
    unsigned int    errors;	    /* The number of protocol errors */

    /* ---------- end protocol specific members ---------- */

    LIST_ENTRY(session)  st_entries;
};
    
struct session * session_new(int);
void             session_free(struct session *s);

int     session_read(struct session *);
int     session_readln(struct session *s);
int     session_printf(struct session *, const char *, ...);
int     session_println(struct session *, const char *);
void    session_close(struct session *);
int     session_suspend(struct session *);
int     session_resume(struct session *);
void    session_handler(void *, int);

void    session_table_init(void);
int     session_table_lookup(struct session **, unsigned long);

#endif /* _SESSION_H */
