/*		$Id$		*/

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

#ifndef _POLL_H
#define _POLL_H

#include <poll.h>
#include <signal.h>
#include "socket.h"

struct timer;
struct watch;

struct watch * poll_add(int, int, void (*)(void *, int), void *);
void    poll_remove(struct watch *);
int     poll_dispatch(void);
void    poll_shutdown(void);
int     poll_init(void);
void    poll_free(void);
struct pollfd * 
        poll_get(struct watch *);
int     poll_signal(int, void(*)(void *, int), void *);

struct timer *
        poll_timer_new(unsigned int, void (*)(void *), void *);
void    poll_timer_free(struct timer *);
void    poll_timer_disable(struct timer *);
void    poll_timer_enable(struct timer *);

#endif /* _POLL_H */
