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


void
session_write(struct session *s, const char *buf, size_t len)
{
        // FIXME - todo error handling
    (void) write(s->fd, buf, len);
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

void
session_init(struct session *s)
{
    struct sockaddr_in name;
    socklen_t       namelen = sizeof(name);

    /* Determine the IP address of the client */
    if (getpeername(s->fd, (struct sockaddr *) &name, &namelen) < 0) {
            log_errno("getpeername(2)");
            goto error;
    }
    s->remote_addr = name.sin_addr;

    /* Convert the IP address to ASCII */
    if (inet_ntop(AF_INET, &s->remote_addr,
		  (char *) &s->remote_addr_str,
		  sizeof(s->remote_addr_str)) == NULL) {
	log_errno("inet_ntop(3)");
	goto error;
    }

    /* Use non-blocking I/O */
    if (fcntl(s->fd, F_SETFL, O_NONBLOCK) < 0) {
            log_errno("fcntl(2)");
            goto error;
    }

    /* Upgrade the file descriptor to a FILE streams */
    if ((s->lbuf_rd = fdopen(s->fd, "r")) == NULL) {
	    log_errno("fdopen(3)");
	    goto error;
    }

    /* Enable line-buffering when reading from the client */
    if (setlinebuf(s->lbuf_rd) != 0) {
	    log_errno("setlinebuf(3)");
	    goto error;
    }

    /* TODO: Determine the reverse DNS name for the host */

    /* Send the greeting */
    (void) s->srv->accept_hook(s);	// TODO: Check return value

    return;

  error:
    free(s);
}

void
session_close(struct session *s)
{
    log_info("closing transmission channel (%d)", 0);
    // TODO: hook function
    s->state = SESSION_CLOSE;
}

void
session_free(struct session *s)
{
    free(s);
}
