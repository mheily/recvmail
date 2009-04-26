/*      $Id$      */

/*
 * Copyright (c) 2008 Mark Heily <devel@heily.com>
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

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "socket.h"
#include "poll.h"
#include "log.h"

/* The buffer size of a socket */
#define SOCK_BUF_SIZE   16384

/* A socket buffer */
struct socket_buf {
    char          buf[SOCK_BUF_SIZE];
    size_t        buf_len;       /* Number of characters contained in <buf> */
    struct iovec *iov;           /* Lines within <buf> */
    size_t        iov_cnt;       /* Number of lines */
    size_t        iov_pos;       /* Current read offset within <iov> */
    char         *frag;          /* Line fragment */
    size_t        fraglen;       /* Length of the line fragment */
    int           status;        /* Status code */
};

#define SBUF_EMPTY(s)   ((s)->iov_pos >= (s)->iov_cnt)

/* A socket buffer */
struct socket {
    int         fd;
    int        status;   /* SOCK_CAN_READ | SOCK_CAN_WRITE, etc. */
    void       *udata;
    void      (*callback)(void *, int);
    struct socket_buf input;
//TODO:    TAILQ_HEAD(,line) output;
};

struct socket *
socket_new(int fd)
{
    int bufsz = SOCK_BUF_SIZE;
    struct socket *sock;

    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsz, sizeof(bufsz)); 
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsz, sizeof(bufsz)); 

    sock = calloc(1, sizeof(*sock));
    if (sock == NULL) {
        log_errno("malloc(3)");
        return (NULL);
    }

    sock->fd = fd;

    return (sock);
}

void
socket_free(struct socket *sock)
{
    if (sock == NULL) {
        log_error("double free");
        return;
    }
    poll_disable(sock->fd);
    (void) close(sock->fd); 
    free(sock->input.iov);
    free(sock);
}


ssize_t
socket_readln(char **dst, struct socket *sock)
{
    struct socket_buf *sb = &sock->input;

    /* Read data if there is none in the buffer */
    if (SBUF_EMPTY(sb) && socket_readv(NULL, sock) < 0) {
            log_error("socket_readv() failed");
            return (-1);
    }

    /* Return the first string and advance the read pointer */
    if (! SBUF_EMPTY(sb)) {
        *dst = sb->iov[sb->iov_pos].iov_base;
        return (sb->iov[sb->iov_pos++].iov_len);
    }
    
    return (0);
}


static void
socket_read_cb(void *arg, int events)
{
    struct socket *sock = (struct socket *) arg;

    sock->status = events;
    sock->callback(sock->udata, events);
}


int
socket_poll(struct socket *sock, 
        void (*callback)(void *, int), 
        void *udata)
{
    sock->callback = callback;
    sock->udata = udata;
    return poll_enable(sock->fd, SOCK_CAN_READ, socket_read_cb, sock);
}


static int
parse_lines(struct socket *sock)
{
    struct socket_buf *sb = &sock->input;
    struct iovec iov[SOCK_BUF_SIZE];
    char *buf = (char *) sb->buf;
    size_t iov_cnt, a, z;

    /* Divide the buffer into lines. */
    iov_cnt = 0;
    for (a = z = 0; z < sock->input.buf_len; z++) {

        if (buf[z] != '\n') 
            continue;

        /* Convert network line endings (CR+LF) into POSIX line endings (LF). */
        if ((z > a) && (buf[z - 1] == '\r')) {
            buf[z - 1] = '\n';
            iov[iov_cnt].iov_base = (char *) &buf[a];
            iov[iov_cnt].iov_len = (z - a);
        } else {
            iov[iov_cnt].iov_base = (char *) &buf[a];
            iov[iov_cnt].iov_len = (z - a) + 1;
        }

        iov_cnt++;
        a = z + 1;
    }

    /* Special case: the final line is not terminated */
    if (a != sock->input.buf_len) {
        sb->fraglen = (z - a);
        sb->frag = (char *) &buf[a];
    }

    /* Copy the iovec field into the socket object */
    sb->iov = malloc(iov_cnt * sizeof(struct iovec));
    if (sb->iov == NULL) {
        log_errno("malloc(3)");
        return (-1);
    }
    memcpy(sb->iov, iov, iov_cnt * sizeof(struct iovec));
    sb->iov_cnt = iov_cnt;

    return (0);
}

ssize_t
socket_readv(struct iovec **dst, struct socket *sock)
{
    struct socket_buf *sb = &sock->input;
    char *buf = (char *) &sb->buf;
    size_t bufsz = sizeof(sb->buf);
    ssize_t n;

    /* Free any previous iovec */
    if (sb->iov != NULL) {
        if (sb->iov_cnt != sb->iov_pos) {
            log_error("existing iovec not fully processed");
            return (-1);
        }
        free(sb->iov);
        sb->iov = NULL;
        sb->iov_cnt = 0;
        sb->iov_pos = 0;
    }

    /* If there is an existing line fragment, place it at the beginning of the buffer */
    if (sb->frag != NULL) {
        memmove(buf, sb->frag, sb->fraglen);
        buf += sb->fraglen;
        bufsz -= sb->fraglen;

        /* Destroy the fragment */
        sb->frag = NULL;
        sb->fraglen = 0;
    }

    /* Read as much as possible from the kernel socket buffer. */
    if ((n = read(sock->fd, buf, bufsz)) < 0) { 
        if (errno == EAGAIN) {
            return (0);
        } else {
            log_errno("read(2)");
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

    sb->buf_len = n;
    return parse_lines(sock);
} 

/**
 * Display the next line in the socket buffer.
 *
 * @return pointer to the next line, or NULL if no more lines
 */
struct iovec *
socket_peek(struct socket *s)
{
    struct socket_buf *sb = &s->input;

    log_debug("total=%zu pos=%zu", sb->iov_cnt, sb->iov_pos);
    if ((sb->iov_cnt - sb->iov_pos) > 1)
        return (&sb->iov[sb->iov_pos + 1]);
    else
        return (NULL);
}
