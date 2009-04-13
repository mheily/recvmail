/*		$Id$		*/

/*
 * Copyright (c) 2009 Mark Heily <devel@heily.com>
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
#ifndef _SOCKET_H
#define _SOCKET_H

#include <sys/types.h>
#include <sys/uio.h>
#include "queue.h"

/* Socket status flags */
#define SOCK_CAN_READ   0x0001
#define SOCK_CAN_WRITE  0x0002
#define SOCK_EOF        0x0004
#define SOCK_ERROR      0x0008

struct socket;

struct socket *
         socket_new(int);

void     socket_free(struct socket *);
ssize_t  socket_readln(char **, struct socket *);
int      socket_poll(struct socket *, void (*)(void *, int), void *);

#if DEADWOOD
/* A socket buffer */
struct socket_buf {
    struct iovec *sb_iov;           /* Buffer of lines */
    size_t        sb_iovlen;        /* Number of structures in sb_iov */
    size_t        sb_iovpos;        /* Current read offset within sb_iov */
    char         *sb_frag;          /* Line fragment */
    size_t        sb_fraglen;       /* Length of the line fragment */
    int           sb_status;        /* Status code */
};

ssize_t         socket_readv(struct socket_buf *, int);
struct iovec *  socket_peek(struct socket_buf *);
#endif

#endif /* _SOCKET_H */
