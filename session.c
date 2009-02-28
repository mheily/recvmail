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

static inline int
readline(struct bufferevent *bev, struct session *s)
{
    char *p;

    p = evbuffer_readline(bev->input);
    if (p == NULL)
        return (0);
    log_info("got `%s'", p);

    if (srv.read_hook(s, p) < 0)
        return (-1);

    //free(p); // FIXME ? needed ?
    return (0);
}

static void
readcb(struct bufferevent *bev, void *arg)
{
    struct session *s = (struct session *) arg;

    if (readline(bev, s) == 0)
        return;

    /* Error handler */
    session_close(s);
    free(s);
}

static void
writecb(struct bufferevent *bev, void *arg)
{
    struct session *s = (struct session *) arg;

    if (s->smtp_state == SMTP_STATE_QUIT) {
        session_close(s);
        free(s);
    }
    return;
}

static void
errorcb(struct bufferevent *bev, short event, void *arg)
{
	struct session *s = (struct session *) arg;

	if (event & EVBUFFER_EOF) {
        log_info("client sent EOF");
        /* FIXME: infinite loop: Process any remaining input in the buffer */
        //do {} while (readline(bev, s) == 0);
	} else {
        log_warning("unknown socket error");
	}
    session_close(s);
    free(s); //TODO - audit for use-after-free
}

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

    /* Use non-blocking I/O */
    if (fcntl(s->fd, F_SETFL, O_NONBLOCK) < 0) {
            log_errno("fcntl(2)");
            goto errout;
    }

    /* Determine the IP address of the client */
    if (getpeername(s->fd, (struct sockaddr *) &name, &namelen) < 0) {
            log_errno("getpeername(2)");
            goto errout;

    }
    s->remote_addr = name.sin_addr;

#if FIXME
    // use evdnns
    //
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
#endif

    s->buf_ev = bufferevent_new(s->fd, readcb, writecb, errorcb, s);
    bufferevent_enable(s->buf_ev, EV_READ);
    //FIXME error checking

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

    free(s->remote_name);
    s->remote_name = NULL;

	bufferevent_free(s->buf_ev);
	close(s->fd);
    s->closed = 1;
}

/* See also: PUTS() macro for string literals */ 
int session_puts(struct session *s, const char *buf)
{
    return bufferevent_write(s->buf_ev, (char *) buf, strlen(buf));
} 
