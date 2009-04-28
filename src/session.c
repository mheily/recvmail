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

#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#include "../contrib/tree.h"

#include "log.h"
#include "poll.h"
#include "server.h"
#include "socket.h"
#include "session.h"
#include "message.h"
#include "maildir.h"

int             smtpd_parser(struct session *);//smtp.c

/** vasprintf(3) is a GNU extension and not universally visible */
extern int      vasprintf(char **, const char *, va_list);

/**
 * Session table.
 */
static LIST_HEAD(,session) st;
static pthread_mutex_t     st_mtx;
static struct timer       *st_expiration_timer;

/*
 *
 * PUBLIC FUNCTIONS
 *
 */

/* Convert the IP address to ASCII */
char *
remote_addr(char *dest, size_t len, const struct session *s)
{
    if (inet_ntop(AF_INET, &s->remote_addr, dest, len) == NULL) {
        log_errno("inet_ntop(3)");
        return (NULL);
    }

    return (dest);
}


void
session_accept(struct session *s)
{
    s->handler = smtpd_parser;     // TODO -fix this layering violation
    log_debug("accepted session on fd %d", s->fd);
    srv.accept_hook(s);
}


int
session_read(struct session *s) 
{
    char    *buf;
    ssize_t  len;

    if (s->handler == NULL)
        return (0);

    log_debug("reading data from client");

    /* Continue reading data until EAGAIN is returned */
    do {
        if ((len = socket_readln(&buf, s->sock)) < 0) {
            log_info("readln failed");
            return (-1);
        } 
        log_debug("read: %zu bytes", len);
        if (len > 0) {
            s->buf = buf;
            s->buf_len = len; 
            if (s->handler(s) < 0) 
                return (-1);
            /* Test if session_suspend() was called */
            if (s->handler == NULL)
               return (0);
        }
    } while (len > 0);

    return (0);
}


int
session_write(struct session *s, const char *buf, size_t len)
{
    ssize_t n;

    /* If the file descriptor is closed, do nothing */
    /* TODO: use a status flag instead of checking for -1 */
    if (s->fd < 0)
        return (0);
    
    /* TODO: check for EAGAIN and enable polling for write readiness */
    if ((n = write(s->fd, buf, len)) != len) {
        log_errno("write(2) (%zu of %zu)", n, len);
        return (-1);
    }

    return (0);
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
        rv = session_write(s, (const char *) buf, len);
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
session_new(int fd)
{
    struct session *s;

    /* Allocate memory for the structure */
    if ((s = calloc(1, sizeof(*s))) == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }
    s->fd = fd;
    if ((s->msg = message_new()) == NULL) {
        free(s);
        log_errno("message_new()");
        return (NULL);
    }

    /* Initialize the socket object */
    if ((s->sock = socket_new(s->fd)) == NULL) {
        log_error("socket_new()");
        message_free(s->msg);
        free(s);
        return (NULL);
    }

    /* Add to the session table */
    pthread_mutex_lock(&st_mtx);
    LIST_INSERT_HEAD(&st, s, st_entries);
    pthread_mutex_unlock(&st_mtx);

    return (s);
}

void
session_close(struct session *s)
{
    if (s == NULL) {
        log_warning("session_close() called twice");
        return;
    }

    log_info("closing session with %s", inet_ntoa(s->remote_addr));

    /* Run any protocol-specific hooks */
    (void) protocol_close(s);

    /* Remove the descriptor from the session table */
    pthread_mutex_lock(&st_mtx);
    LIST_REMOVE(s, st_entries);
    pthread_mutex_unlock(&st_mtx);

    socket_free(s->sock);
    message_free(s->msg);
    free(s);
}


void
session_handler(void *sptr, int events)
{
    struct session *s = (struct session *) sptr;
    
    if (events & POLLHUP) {
        log_debug("fd %d got EOF", s->fd);
        session_close(s);
        return;       // FIXME: process the rest of the read buffer
    }
    if (events & POLLIN) {
        log_debug("fd %d is now readable", s->fd);
        if (session_read(s) < 0) 
            session_close(s);
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
session_suspend(struct session *s)
{
    s->handler = NULL;
    return poll_remove(s->fd); //TODO: use disable/enable when poll_enable() is available
}


int
session_resume(struct session *s)
{
    /* Poll for read(2) readiness */
    if (socket_poll(s->sock, session_handler, s) < 0)
        return (-1);

    /* Process lines that are already in the read buffer */
    if (socket_peek(s->sock) != NULL) {
        if (session_read(s) < 0) 
            session_close(s);
    }

    return (0);
}


int
session_table_lookup(struct session **sptr, unsigned long sid)
{
    struct session *s;
   
    // TODO: use a binary tree
   
    LIST_FOREACH(s, &st, st_entries) {
        if (s->id == sid) {
            *sptr = s;
            return (0);
        }
    }

    *sptr = NULL;
    return (-1);
}


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
            srv.timeout_hook(s);
            session_close(s);
        }
    }
}


void
session_table_init(void)
{
    LIST_INIT(&st);
    st_expiration_timer = poll_timer_new(60, session_table_expire, NULL);
    pthread_mutex_init(&st_mtx, NULL);
}
