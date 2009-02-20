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
#include <netdb.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <unistd.h>

#include "atomic.h"
#include "log.h"
#include "poll.h"
#include "server.h"
#include "session.h"

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
        atomic_write(s->fd, (const char *) buf, len);
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

    /* Upgrade the socket descriptor to a FILE stream */
    s->in = fdopen(fd, "r");
    s->out = fdopen(fd, "w");
    if (s->in == NULL || s->out == NULL) {
        log_errno("fdopen(3)");
        (void) fclose(s->in);
        (void) fclose(s->out);
        goto errout;
    }

    /* Enable line-buffering */
    setlinebuf(s->in);
    setlinebuf(s->out);

    /* Determine the IP address of the client */
    if (getpeername(s->fd, (struct sockaddr *) &name, &namelen) < 0) {
            log_errno("getpeername(2)");
            goto errout;

    }
    s->remote_addr = name.sin_addr;

    /* TODO: Determine the reverse DNS name for the host */
    if (getnameinfo((struct sockaddr *) &name, namelen, s->buf, sizeof(s->buf),
                NULL, 0, NI_NUMERICHOST) != 0) {
        log_warning("getnameinfo(3)");
    }
    if ((s->remote_name = strdup(s->buf)) == NULL) {
        log_errno("strdup(3)");
        goto errout;
    }
    log_debug("remote_name=%s", s->remote_name);


    return (s);

errout:
    free(s->remote_name);
    free(s);
    return (NULL);
}

void
session_close(struct session *s)
{
    if (s->closed) {
        log_debug("double session_close() detected");
        return;
    }

    log_debug("closing transmission channel");

    /* Run any protocol-specific hooks */
    (void) protocol_close(s);

    (void) fclose(s->in);
    (void) fclose(s->out);
    (void) server_disconnect(s->fd); 

    free(s->remote_name);
    s->remote_name = NULL;

    s->closed = 1;
}
