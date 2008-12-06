/*		$Id: $		*/

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

#include "recvmail.h"

#include <stdarg.h>

/** vasprintf(3) is a GNU extension and not universally visible */
extern int      vasprintf(char **, const char *, va_list);


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
                return;
            if (n >= 0 && n < len) {
                buf += n;
                len -= n;
                if (errno == EINTR) {
                    continue; 
                } else if (errno == EAGAIN) {
                    break;
                } else {
                    log_errno("unusual short write(2)");
                    session_close(s);
                    return;
                }
            }
            if (n < 0) {
                log_errno("write(2)");
                break; /*FIXME - better error handling, should kill the session */
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
    return;

errout:
        log_errno("calloc(3)");
        session_close(s);
        return;
}



void
session_vprintf(struct session *s, const char *format, va_list ap)
{
        char    *buf = NULL;
        size_t     len;

        /* Generate the result buffer */
        if ((len = vasprintf(&buf, format, ap)) < 0) {
                /* XXX-FIXME error handling */
                return;
        }

        /* Write the buffer to the socket */
        session_write(s, (const char *) buf, len);
        free(buf);
}

/**
 * Print a formatted string to a socket.
 *
 * Uses printf(3) formatting syntax.
 *
 * @param sock socket object
 * @param format format string
*/
void
session_printf(struct session *s, const char *format, ...)
{
        va_list ap;

        va_start(ap, format);
        session_vprintf(s, format, ap);
        va_end(ap);
}

void
session_println(struct session *s, const char *buf)
{
        return session_printf(s, "%s\r\n", buf);
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
    STAILQ_INIT(&s->out_buf);
    STAILQ_INIT(&s->in_buf);

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

    return (s);

errout:
    free(s);
    return (NULL);
}

void
session_close(struct session *s)
{
    struct nbuf *nbp;

    if (s->closed) {
        log_debug("double session_close() detected");
        return;
    }

    log_debug("closing transmission channel");

    /* Remove the descriptor from the session table and the pollset */
    LIST_REMOVE(s, entries);
    server_update_pollset(s->srv);

    /* Clear the output buffer. Any unwritten data will be discarded. */
    while ((nbp = STAILQ_FIRST(&s->out_buf))) {
             free(nbp->nb_data);
             STAILQ_REMOVE_HEAD(&s->out_buf, entries);
    }

    /* Run any protocol-specific hooks */
    s->srv->close_hook(s);

    (void) atomic_close(s->fd);
    s->closed = 1;
}

/* Toggle the current I/O state of a session from writer to reader */
void
session_become_reader(struct session *s)
{
    state_transition(s, POLLIN);
}

/* Toggle the current I/O state of a session from reader to writer */
void
session_become_writer(struct session *s)
{
    state_transition(s, POLLOUT);
}