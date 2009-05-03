/*      $Id$      */

/*
 * Copyright (c) 2008-2009 Mark Heily <devel@heily.com>
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

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "socket.h"
#include "poll.h"
#include "queue.h"
#include "log.h"

static int socket_read(struct socket *sock);

/* The maximum line length (based on SMTP_LINE_MAX) */
// TODO: don't need 2 identical constants
#define SOCK_LINE_MAX   1000

/* The buffer size of a socket */
#define SOCK_BUF_SIZE   16384

struct line {
    STAILQ_ENTRY(line) entry;
    size_t len;
    char buf[];
};

/* A socket buffer */
struct socket {
    int         fd;
    struct sockaddr_storage peer;
    char peername[INET6_ADDRSTRLEN];
    STAILQ_HEAD(,line) input;
    STAILQ_HEAD(,line) output;  //TODO:not used yet
    struct line *input_tmp;
};

#define LINE_FRAGMENTED(x) ((x)->buf[(x)->len - 1] != '\n')

static int
append_input(struct socket *sock, const char *buf, size_t len)
{
    struct line *x, *tail;

    if (len == 0 || len > SOCK_LINE_MAX) {
        log_error("invalid line length %zu", len);
        return (-1);
    }

    tail = STAILQ_LAST(&sock->input, line, entry);
    if (tail != NULL && LINE_FRAGMENTED(tail)) {
        STAILQ_REMOVE(&sock->input, tail, line, entry);

        /* Create a new line large enough to contain both fragments */
        x = malloc(sizeof(*x) + len + tail->len + 1);
        if (x == NULL) {
            log_errno("malloc(3)");
            return (-1);
        }

        /* Merge the two fragments into a single line */
        x->len = tail->len + len;
        memcpy(&x->buf, tail->buf, tail->len);
        memcpy(&x->buf[tail->len], buf, len);
        x->buf[x->len] = '\0';

    } else {
        x = malloc(sizeof(*x) + len + 1);
        if (x == NULL) {
            log_errno("malloc(3)");
            return (-1);
        }
        memcpy(&x->buf, buf, len);
        x->buf[len] = '\0';
        x->len = len;
    }

    STAILQ_INSERT_TAIL(&sock->input, x, entry);
    log_debug("<<< %zu: `%s'", len,  &x->buf[0]);

    return (0);
}


struct socket *
socket_new(int fd)
{
    struct socket *sock = NULL;
    const int bufsz = SOCK_BUF_SIZE;
	socklen_t cli_len = sizeof(sock->peer);
    int rv;

    /* Set the kernel socket buffer size */
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsz, sizeof(bufsz)) < 0) {
        log_errno("setsockopt(2)");
        goto errout;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsz, sizeof(bufsz)) < 0) {
        log_errno("setsockopt(2)");
        goto errout;
    }
 
    /* Use non-blocking I/O */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        log_errno("fcntl(2)");
        goto errout;
    }

    /* Initialize the object */
    sock = malloc(sizeof(*sock));
    if (sock == NULL) {
        log_errno("malloc(3)");
        return (NULL);
    }
    sock->fd = fd;
    STAILQ_INIT(&sock->input);
    STAILQ_INIT(&sock->output);
    sock->input_tmp = NULL;

    /* Get the peer socket address */
    if (getpeername(fd, (struct sockaddr *) &sock->peer, &cli_len) < 0) {
            log_errno("getpeername(3) of fd %d", fd);
            goto errout;
    }
    /* Generate a human-readable representation of the remote address */
    rv = getnameinfo((struct sockaddr *) &sock->peer, cli_len, 
                &sock->peername[0], sizeof(sock->peername), NULL, 0, NI_NUMERICHOST);
    if (rv != 0) {
            log_errno("getnameinfo(3): %s", gai_strerror(rv));
            goto errout;
    }


    return (sock);

errout:
    free(sock);
    return (NULL);
}


void
socket_free(struct socket *sock)
{
    struct line *n1, *n2;

    if (sock == NULL) {
        log_error("double free");
        return;
    }
    poll_remove(sock->fd);
    (void) close(sock->fd); 

    /* Destroy all items in the input buffer */
    n1 = STAILQ_FIRST(&sock->input);
    while (n1 != NULL) {
        n2 = STAILQ_NEXT(n1, entry);
        free(n1);
        n1 = n2;
    }
    free(sock->input_tmp);

    /* Destroy all items in the output buffer */
    n1 = STAILQ_FIRST(&sock->output);
    while (n1 != NULL) {
        n2 = STAILQ_NEXT(n1, entry);
        free(n1);
        n1 = n2;
    }

    free(sock);
}


ssize_t
socket_readln(char **dst, struct socket *sock)
{
    struct line *x;

    *dst = NULL;

    /* Read data from the socket*/
    if (socket_read(sock) < 0) {
            log_error("socket_read() failed");
            return (-1);
    } 

    /* Destroy the previous line */
    free(sock->input_tmp);
    sock->input_tmp = NULL;

    /* Return the first string */
    if (! STAILQ_EMPTY(&sock->input) ) {
        x = STAILQ_FIRST(&sock->input);
        log_debug("x=%p len=%zu buf=`%s'", x, x->len, x->buf);
        if (LINE_FRAGMENTED(x)) {
            log_debug("fragmented line");
            return (0);
        }
        STAILQ_REMOVE_HEAD(&sock->input, entry);
        *dst = &x->buf[0];
        sock->input_tmp = x;
        return (x->len);
    }
    
    return (0);
}


int
socket_poll_enable(struct socket *sock, 
        int events,
        void (*callback)(void *, int), 
        void *udata)
{
    return poll_enable(sock->fd, events, callback, udata);
}


int
socket_poll_disable(struct socket *sock)
{
    return poll_disable(sock->fd);
}


static int
parse_lines(struct socket *sock, char *buf, size_t buf_len)
{
    size_t line_len, a, z;

    log_debug("buf_len=%zu", buf_len);

    /* Divide the buffer into lines. */
    for (a = z = 0; z < buf_len; z++) {

        if (buf[z] != '\n') 
            continue;

        /* Compute the line length including the trailing LF. */
        line_len = z - a + 1;

        /* Convert CR+LF to LF line endings. */
        if (line_len > 0 && buf[z - 1] == '\r') {
            line_len--;
            buf[z - 1] = '\n';
        }
        if (line_len >= SOCK_LINE_MAX) {
            log_error("line length exceeded");
            return (-1);
        }

        /* Create a new line object */
        if (append_input(sock, &buf[a], line_len) < 0)
            return (-1);

        a = z + 1;
    }

    /* Save any remaining line fragment */
    /* TODO: avoid code duplication with above loop */
    if (a != buf_len) {
        line_len = z - a;
        if (append_input(sock, &buf[a], line_len) < 0)
            return (-1);
    }

    return (0);
}


static int
socket_read(struct socket *sock)
{
    char buf[SOCK_BUF_SIZE];
    ssize_t n;

    /* Read as much as possible from the kernel socket buffer. */
    n = recv(sock->fd, &buf[0], sizeof(buf), 0);
    if (n < 0) { 
        if (errno == EAGAIN) {
            log_debug("got EAGAIN");
            return (0);
        } else if (errno == ECONNRESET) {
            log_info("connection reset by peer");   //TODO: add remote_addr
            return (-1);
        } else {
            log_errno("recv(2)");
            return (-1);
        }
    }

    /* Check for EOF */
    /* TODO - verify: is n==0 actually EOF? */
    if (n == 0) {
        log_debug("zero-length read(2)");
        //TODO -- indicate to session object that no more reads are possible
        return (-1);
    }
    log_debug("read %zu bytes", n);

    return parse_lines(sock, buf, (size_t) n);
} 


static int
socket_buffer_write(struct socket *sock, const char *buf, size_t len)
{
    struct line *x;

    /* Copy the buffer to a <line> object */
    x = malloc(sizeof(*x) + len + 1);
    if (x == NULL) {
        log_errno("malloc(3)");
        return (-1);
    }
    memcpy(&x->buf, buf, len);
    x->buf[len] = '\0';
    x->len = len;

    STAILQ_INSERT_TAIL(&sock->output, x, entry);
    /* FIXME: enable poll() for POLLOUT */
    return (0);
}

int
socket_write(struct socket *sock, const char *buf, size_t len)
{
    ssize_t n;

    /* If the file descriptor is closed, do nothing */
    /* TODO: use a status flag instead of checking for -1 */
    if (sock->fd < 0)
        return (0);
    
    n = send(sock->fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN) 
            return socket_buffer_write(sock, buf, len);
        /* TODO: if (errno == ECONNRESET) ... */
        log_errno("send(2)");
        return (-1);
    }
    if (n < len) {
        /* TODO: this is probably impossible for sockets */
        log_errno("send(2) - short write");
        return (-1);
    }

    return (0);
}


int
socket_pending(struct socket *sock)
{
    return (STAILQ_EMPTY(&sock->input));
}


int
socket_get_family(struct socket *sock)
{
    return (sock->peer.ss_family);
}


int
socket_get_peeraddr4(struct socket *sock)
{
    struct sockaddr_in *sain = (struct sockaddr_in *) &sock->peer;
    return (sain->sin_addr.s_addr);
}


const char *
socket_get_peername(struct socket *sock)
{
    return ((const char *) &sock->peername);
}
