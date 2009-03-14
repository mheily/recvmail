/*		$Id$		*/

/*
 * Copyright (c) 2004-2007 Mark Heily <devel@heily.com>
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

#include "log.h"
#include "poll.h"
#include "server.h"
#include "session.h"
#include "message.h"
#include "maildir.h"
#include "nbuf.h"

int             smtpd_parser(struct session *);//smtp.c

/** vasprintf(3) is a GNU extension and not universally visible */
extern int      vasprintf(char **, const char *, va_list);


/**
 * Session table.
 */
static LIST_HEAD(,session) st;
static pthread_mutex_t     st_mtx;

static TAILQ_HEAD(,session) syncqueue;
static pthread_cond_t       syncq_not_empty;
static pthread_mutex_t      syncq_mtx;

static LIST_HEAD(,session) io_wait;

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
    poll_enable(srv.evcb, s->fd, s, SOCK_CAN_READ);
    log_debug("accepted session on fd %d", s->fd);
    srv.accept_hook(s);
}

int
session_write(struct session *s, const char *buf, size_t len)
{
    ssize_t n;
    char *p;
    struct nbuf *nbp;

    /* If the output buffer is empty, try writing directly to the client */
    if (STAILQ_FIRST(&s->out_buf) == NULL) {
        for (;;) {
            n = write(s->fd, buf, len);
            if (n == len)
                return (0);
            if (n >= 0 && n < len) {
                buf += n;
                len -= n;
                if (errno == EINTR) {
                    continue; 
                } else if (errno == EAGAIN) {
                    break;
                } else {
                    log_errno("unusual short write(2)");
                    return (-1);
                }
            }
            if (n < 0) {
                log_errno("write(2)");
                return (-1);
            }
        }
    }

    /* Copy the unwritten portion to a new buffer*/
    /* FIXME -- This will fail in low-memory situations. */
    if ((nbp = calloc(1, sizeof(*nbp))) == NULL) 
        goto errout;
    if ((p = strdup(buf)) == NULL) {
        free(nbp);
        goto errout;
    }
    NBUF_INIT(nbp, p, strlen(p));
    STAILQ_INSERT_TAIL(&s->out_buf, nbp, entries);
    return (0);

errout:
    log_errno("calloc(3)");
    return (-1);
}



int
session_vprintf(struct session *s, const char *format, va_list ap)
{
        char    *buf = NULL;
        int rv;
        size_t     len;

        /* Generate the result buffer */
        if ((len = vasprintf(&buf, format, ap)) < 0) {
                /* XXX-FIXME error handling */
                return (-1);
        }

        /* Write the buffer to the socket */
        rv = session_write(s, (const char *) buf, len);
        free(buf);
        return (rv);
}

/**
 * Print a formatted string to a socket.
 *
 * Uses printf(3) formatting syntax.
 *
 * @param sock socket object
 * @param format format string
*/
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
    struct sockaddr_in name;
    socklen_t       namelen = sizeof(name);

    /* Allocate memory for the structure */
    if ((s = calloc(1, sizeof(*s))) == NULL) {
        log_errno("calloc(3)");
        return NULL;
    }
    s->fd = fd;

    /* Initialize the input buffer */
    memset(&s->in_buf, 0, sizeof(s->in_buf));

    /* Initialize the output buffer */
    STAILQ_INIT(&s->out_buf);

    /* Determine the IP address of the client */
    if (getpeername(s->fd, (struct sockaddr *) &name, &namelen) < 0) {
            log_errno("getpeername(2)");
            goto errout;

    }
    s->remote_addr = name.sin_addr;

    /* Use non-blocking I/O */
    if (fcntl(s->fd, F_SETFL, O_NONBLOCK) < 0) {
            log_errno("fcntl(2)");
            goto errout;
    }

    /* TODO: Determine the reverse DNS name for the host */

    /* Add to the session table */
    pthread_mutex_lock(&st_mtx);
    LIST_INSERT_HEAD(&st, s, st_entries);
    pthread_mutex_unlock(&st_mtx);

    return (s);

errout:
    free(s);
    return (NULL);
}

int
session_flush(struct session *s)
{
#if DEADWOOD
    struct nbuf *nbp;

    while ((nbp = STAILQ_FIRST(&s->out_buf))) {
   //XXX-FIXME - this actually kills all output data !! 
            free(nbp->nb_data);
            STAILQ_REMOVE_HEAD(&s->out_buf, entries);
        }
#endif
    // FIXME -- this will be needed someday.
    return (0);
}

void
session_close(struct session *s)
{
    struct nbuf *nbp;

    log_debug("closing transmission channel");

    /* Run any protocol-specific hooks */
    (void) protocol_close(s);

    /* Clear the output buffer. Any unwritten data will be discarded. */
    /* FIXME: shouldn't this be in an abort()-type function? */
    while ((nbp = STAILQ_FIRST(&s->out_buf))) {
             free(nbp->nb_data);
             STAILQ_REMOVE_HEAD(&s->out_buf, entries);
    }

    (void) close(s->fd); 

    /* Remove the descriptor from the session table */
    pthread_mutex_lock(&st_mtx);
    LIST_REMOVE(s, st_entries);
    pthread_mutex_unlock(&st_mtx);

    free(s);
}


int
session_fsync(struct session *s, int (*cb)(struct session *))
{
    if (poll_disable(srv.evcb, s->fd) != 0)
        return (-1);
    s->handler = cb;
    pthread_mutex_lock(&syncq_mtx);
    TAILQ_INSERT_TAIL(&syncqueue, s, workq_entries);
    pthread_cond_signal(&syncq_not_empty);
    pthread_mutex_unlock(&syncq_mtx);

    return (0);
}


void *
session_syncer(void *arg)
{
    TAILQ_HEAD(,session) tmp;
    struct session *s;
    arg = NULL;

    for (;;) {

        /* Wait for the queue to become non-empty */
        pthread_mutex_lock(&syncq_mtx);
        while (TAILQ_EMPTY(&syncqueue)) {
            pthread_cond_wait(&syncq_not_empty, &syncq_mtx);
            if (TAILQ_EMPTY(&syncqueue))
                continue;
        }

        /* Move all items into a private queue */
        memcpy(&tmp, &syncqueue, sizeof(syncqueue));
        TAILQ_INIT(&syncqueue);

        pthread_mutex_unlock(&syncq_mtx);

        /* Send the 250 Message Delivered response */
        TAILQ_FOREACH(s, &tmp, workq_entries) {
            message_fsync(&s->msg); // TODO: error handling
            maildir_deliver(&s->msg);// TODO: error handling
            message_close(&s->msg); // TODO: error handling
            s->handler(s); // FIXME -- do this in worker threads
            /* XXX-FIXME update state field */
        }

        /* Wait to allow more requests to queue up */
        // TODO -- is this a good idea?
        //sleep(5);
        //log_debug("wakeup");
    }
}

void
session_table_init(void)
{
    LIST_INIT(&st);
    pthread_mutex_init(&st_mtx, NULL);

    TAILQ_INIT(&syncqueue);
    pthread_mutex_init(&syncq_mtx, NULL);
    pthread_cond_init(&syncq_not_empty, NULL);

    LIST_INIT(&io_wait);
}
