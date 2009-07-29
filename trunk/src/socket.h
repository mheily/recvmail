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
#include "queue.h"

struct socket;
struct session;

struct socket * socket_new(int, struct session *);
void            socket_free(struct socket *);

int      socket_pending(const struct socket *);
ssize_t  socket_readln(char **, struct socket *);
int      socket_write(struct socket *, const char *, size_t);
int      socket_poll_enable(struct socket *, int, void (*)(void *, int), void *);
int      socket_poll_disable(struct socket *);
int      socket_event_handler(struct socket *, int);
int      socket_get_family(const struct socket *);
int      socket_starttls(struct socket *);
int      socket_get_peeraddr4(const struct socket *);
const char *   socket_get_peername(const struct socket *);
int      socket_init(void);

#endif /* _SOCKET_H */
