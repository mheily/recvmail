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
#include <sys/uio.h>
#include <unistd.h>

#include "socket.h"
#include "poll.h"
#include "log.h"

struct line {
    char   *buf;
    size_t  len;
    int     frag;
    STAILQ_ENTRY(line) entry;
};

/* A socket buffer */
struct socket {
    int fd;
    unsigned int  status;   /* SOCK_CAN_READ | SOCK_CAN_WRITE, etc. */
    void  *udata;
    void (*callback)(void *, int);
    STAILQ_HEAD(,line) input;
    STAILQ_HEAD(,line) output;
};

struct socket *
socket_new(int fd)
{
    struct socket *sock;

    sock = malloc(sizeof(*sock));
    if (sock == NULL) {
        log_errno("malloc(3)");
        return (NULL);
    }

    sock->fd = fd;
    sock->status = 0;
    STAILQ_INIT(&sock->input);
    STAILQ_INIT(&sock->output);

    return (sock);
}

void
socket_free(struct socket *sock)
{
    /* STUB */
}

int
socket_read(struct socket *sock, char *buf, size_t bufsz)
{
    ssize_t n;

    if ((n = read(fd, bufp, bufsz)) < 0) { 
        if (errno == EAGAIN) {
            sock->status &= ~SOCK_CAN_READ; 
            return (0);
        } else {
            log_errno("read(2)");
            return (-1);
        }
    }
    if (n == 0) {
        /* TODO - see if zero-length read is meaningful */
            return (0);
    }
}

ssize_t
socket_readln(char **dst, struct socket *sock)
{
    char buf[8192];
    char *bufp;
    ssize_t n;
    size_t len, bufsz;
    struct line *cur = NULL;

    if (! STAILQ_EMPTY(&sock->input)) {
        cur = STAILQ_FIRST(&sock->input);
        if (cur->frag) {
            memcpy((char *) &buf, cur->buf, cur->len);
            bufp = &buf + cur->len;
            bufsz = sizeof(buf) - cur->len;
        }
    } else {
        bufp = &buf;
        bufsz = sizeof(buf);
    }
    
    if (cur == NULL || cur->frag) {
        if ((n = read(fd, bufp, bufsz - 1)) < 0) { 
            if (errno == EAGAIN) {
                sock->status &= ~SOCK_CAN_READ; 
                return (0);
            } else {
                log_errno("read(2)");
                return (-1);
            }
        }
    }
    if (cur->frag)
        return (1);

    *dst = cur->buf;
    len = cur->len;
    STAILQ_REMOVE_HEAD(&sock->input, entry);
    free(cur);

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

#if DEADWOOD
/* TODO: make tunable, must be larger than kernel socket buffer */
#define __BUFSIZE       (1024 * 256)

/* TODO: make tunable, this is derived from SMTP_LINE_MAX */
#define __MAX_FRAGMENT_LEN  999

/**
 * Multiplexed I/O using non-blocking sockets and a single thread of control.
 */
static char    buf[__BUFSIZE + 2];
static size_t  nbuf;

/* Pointers to all the lines within <buf> */
static struct iovec lines[__BUFSIZE + 2];  //TODO: this is absurdly large, make it dynamic
static size_t       nlines;

ssize_t
socket_readv(struct socket_buf *sb, int fd)
{
    char *a, *z, *buf_edge;
    char *bufp = (char *) &buf;
    size_t bufsz = __BUFSIZE;
    size_t fraglen;
    ssize_t n;

    /* If there is an existing line fragment, place it at the beginning of the buffer */
    if (sb->sb_frag != NULL) {
        memcpy(bufp, sb->sb_frag, sb->sb_fraglen);
        bufp += sb->sb_fraglen;
        bufsz -= sb->sb_fraglen;
        nbuf = sb->sb_fraglen;

        /* Now, the fragment is no longer part of the socket_buf */
        free(sb->sb_frag);
        sb->sb_frag = NULL;
        sb->sb_fraglen = 0;

    } else {
        nbuf = 0;
    }

    /* Read as much as possible from the kernel socket buffer. */
    if ((n = read(fd, bufp, bufsz - 1)) < 0) { 
        sb->sb_iov = NULL;
        sb->sb_iovlen = 0;

        /* If no data is available, go to sleep */
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

    nbuf += n;

    /*
    //uncomment for extra debugging
    //
    bufp = (char *) &buf;       //to un-fragment
    bufp[nbuf] = '\0';          
    log_debug("read %zu bytes: `%s'", nbuf, bufp);
    */
    log_debug("read %zu bytes", nbuf);

    /* Compute the address of the end of the buffer */
    buf_edge = ((char *) &buf) + nbuf;

    /* Divide the buffer into lines. */
    nlines = 0;
    for (a = z = (char *) &buf; z < buf_edge; z++) {
        if ((*z == '\r' && *(z + 1) == '\n') || (*z == '\n')) {

            lines[nlines].iov_base = a;
            lines[nlines].iov_len = (z - a) + 1;
            nlines++;

            /* Convert network line endings (CR+LF) into POSIX line endings (LF). */
            if (*z == '\r') {
                *z = '\n';
                z++;
            }

            a = z + 1;
        }
    }

    /* Special case: the final line is not terminated */
    if (a != buf_edge) {
        *z = '\0';
        fraglen = (z - a);
        if (fraglen > __MAX_FRAGMENT_LEN) {
            log_error("line fragment exceeds maximum length");
            return (-1);
        }
        sb->sb_fraglen = fraglen;
        sb->sb_frag = strdup(a);
        log_debug("frag='%s' fraglen=%zu", sb->sb_frag, sb->sb_fraglen);
    }

    sb->sb_iov = (struct iovec *) &lines;
    sb->sb_iovlen = nlines;

    return (nlines);
} 

/**
 * Display the next line in the socket buffer.
 *
 * @return pointer to the next line, or NULL if no more lines
 */
struct iovec *
socket_peek(struct socket_buf *sb)
{
    log_debug("len=%zu pos=%zu", sb->sb_iovlen , sb->sb_iovpos);
    if ((sb->sb_iovlen - sb->sb_iovpos) > 1)
        return (&sb->sb_iov[sb->sb_iovpos + 1]);
    else
        return (NULL);
}
#endif
