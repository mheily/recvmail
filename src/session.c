/*		$Id$		*/

/*
 * Copyright (c) 2004-2009 Mark Heily <devel@heily.com>
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

#include "recvmail.h"

static void session_table_expire(void *unused);

/* A client session */
struct session {
    struct protocol *proto;

    u_long      id;             /* Session ID */
    struct socket *sock;
    char       *buf;
    size_t      buf_len;
    time_t      timeout;  
    void       *udata;

    LIST_ENTRY(session)  st_entries;
};

   
/**
 * Session table.
 * TODO: use a binary tree for faster searching
 */
static LIST_HEAD(,session) st;
static pthread_mutex_t     st_mtx;
static struct timer       *st_expiration_timer;

/* defined in smtp.c */
extern struct protocol SMTP;

static void
session_table_expire(void *unused)
{
    struct session *s, *s_next;
    time_t now;

    log_debug("expiring idle sessions");
    now = time(NULL);
    for (s = LIST_FIRST(&st); s != LIST_END(&st); s = s_next) {
        s_next = LIST_NEXT(s, st_entries);
        if (s->timeout < now) {
            s->proto->timeout_hook(s);
            session_close(s);
        }
    }
}

int
session_vprintf(struct session *s, const char *format, va_list ap)
{
        char    *buf = NULL;
        int rv;
        size_t     len;

        /* Generate the result buffer */
        if ((len = vasprintf(&buf, format, ap)) < 0) {
                /* TODO - error handling */
                return (-1);
        }

        /* Write the buffer to the socket */
        rv = socket_write(s->sock, (const char *) buf, len);
        free(buf);
        return (rv);
}

int
session_printf(struct session *s, const char *format, ...)
{
    int rv;
    va_list ap;

    va_start(ap, format);
    rv = session_vprintf(s, format, ap);
    va_end(ap);

    return (rv);
}

int
session_println(struct session *s, const char *buf)
{
    return (session_printf(s, "%s\r\n", buf));
}

struct session *
session_new(int fd, struct protocol *proto)
{
    static unsigned long session_id = 0;
    struct session *s;

    /* Allocate memory for the structure */
    if ((s = calloc(1, sizeof(*s))) == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }
    s->proto = proto;
  
    /* Initialize the socket object */
    if ((s->sock = socket_new(fd, s, proto)) == NULL) {
        log_error("socket_new()");
        free(s);
        return (NULL);
    }

    /* TODO: Determine the reverse DNS name for the host */

    /* Generate a session ID (TODO: use connection throttling to prevent unlimited wraparound) */
    /* Add to the session table */
    pthread_mutex_lock(&st_mtx);
    if (session_id == ULONG_MAX)
        s->id = session_id = 1;
    else
        s->id = ++session_id;
    LIST_INSERT_HEAD(&st, s, st_entries);
    pthread_mutex_unlock(&st_mtx);

    log_info("accepted connection from %s", socket_get_peername(s->sock)); 
 
    return (s);
}

void
session_close(struct session *s)
{
    log_info("closing session with %s", socket_get_peername(s->sock));

    /* Run any protocol-specific hooks */
    s->proto->close_hook(s);

    /* Remove the descriptor from the session table */
    pthread_mutex_lock(&st_mtx);
    LIST_REMOVE(s, st_entries);
    pthread_mutex_unlock(&st_mtx);

    socket_close(s->sock);
}

void
session_event_handler(struct session *s, int events)
{
    if (events & POLLHUP) {
        log_notice("session %lu got EOF", s->id);
        session_close(s);
        return;       // FIXME: process the rest of the read buffer
    }

    /* TODO: limit the max size of the input buffer */
    //FIXME: turn off polling.

    if (events & POLLIN) {
        log_debug("session %lu is now readable", s->id);
        //if (session_read(s) < 0) 
        //    session_close(s);
    }
#if TODO
    // TODO: implement output buffreing
    if (events & POLLOUT) {
        if (s->fd < 0) 
            log_debug("fd %d is writable (session terminated)", s->fd);
        else
            log_debug("fd %d is now writable", s->fd);
        //TODO - flush output buffer, or do something
    }
#endif
}

int
session_table_lookup(struct session **sptr, unsigned long sid)
{
    struct session *s;
   
    pthread_mutex_lock(&st_mtx);
    LIST_FOREACH(s, &st, st_entries) {
        if (s->id == sid) {
            *sptr = s;
            pthread_mutex_unlock(&st_mtx);
            return (0);
        }
    }

    *sptr = NULL;
    pthread_mutex_unlock(&st_mtx);
    return (-1);
}

int
session_table_init(void)
{
    LIST_INIT(&st);
    st_expiration_timer = poll_timer_new(60, session_table_expire, NULL);
    pthread_mutex_init(&st_mtx, NULL);
    return (0);
}

/*
 * Accessor methods
 */

const struct socket *
session_get_socket(struct session *s)
{
    return (s->sock);
}

unsigned long
session_get_id(struct session *s)
{
    return (s->id);
}

void *
session_data_get(const struct session *s)
{
    return (s->udata);
}

void
session_data_set(struct session *s, const void *udata)
{
    s->udata = (void *) udata;
}

void
session_timeout_set(struct session *s, time_t interval)
{
    s->timeout = time(NULL) + interval;
}

#if DEADWOOD
void
session_resume(struct session *s)
{
    /* Drain the input buffer */
    if (socket_pending(s->sock) && session_read(s) < 0)    
        session_close(s);
}
#endif
