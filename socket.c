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
#include "log.h"

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
    /* XXX- is n==0 actually EOF? */
    if (n == 0) {
        log_debug("zero-length read(2)");
        //FIXME -- how to indicate to session object that no more reads are possible?
        //sb->sb_status = 1; //FIXME: magic constant, not checked anywhere else.
        return (-1);
    }

    nbuf += n;

    /*
    //uncomment for extra debugging
    //
    bufp = (char *) &buf;       //to un-fragment
    bufp[nbuf] = '\0';          //FIXME: temp for debugging
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
