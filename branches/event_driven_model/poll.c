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

#include <stdlib.h>
#include <errno.h>

#include "epoll.h"
#include "poll.h"

/* Maximum number of events to read in a single system call */
/* XXX-FIXME this should be much larger, but there are issues
 * when using an event cache.. see epoll manpage for details */
#define MAXEVENTS 1

struct evcb {
    struct epoll_event   evt[MAXEVENTS];
    struct epoll_event  *cur;
    int                  pfd;
    ssize_t              cnt;
};

struct evcb * 
poll_new(void)
{
    struct evcb *e;

    if ((e = malloc(sizeof(*e))) == NULL)
        return (NULL);
    e->cur = &e->evt[0];
    e->cnt = 0;
    if ((e->pfd = epoll_create(1)) < 0) {
        free(e);
        return (NULL); 
    }
    return (e);
}

/* ------------------------- pollset handling functions -----------------*/




void *
poll_wait(struct evcb *e, int *events)
{
    if (e->cnt <= 0) {
        do {
            e->cnt = epoll_wait(e->pfd, &e->evt[0], MAXEVENTS, -1);
            if (e->cnt < 0 && errno != EINTR) {
                return (NULL);
            }
        } while ((e->cnt < 0) && (errno == EINTR));
        e->cur = &e->evt[0];
    } else {
        e->cur++;
    }

    /* Determine which events happened. */
    *events = 0;
    if (e->cur->events & EPOLLIN) 
        *events |= SOCK_CAN_READ;
    if (e->cur->events & EPOLLOUT) 
        *events |= SOCK_CAN_WRITE;
    if (e->cur->events & EPOLLHUP || e->cur->events & EPOLLRDHUP) 
        *events |= SOCK_EOF;
    if (e->cur->events & EPOLLERR) 
        *events |= SOCK_ERROR;

    e->cnt--;

    return (e->cur->data.ptr);
}

int
poll_disable(struct evcb *e, int fd)
{
    return (epoll_ctl(e->pfd, EPOLL_CTL_DEL, fd, ((void *) -1L)));
}

int
poll_enable(struct evcb *e, int fd, void *udata, int events)
{
    struct epoll_event ev;

    ev.events = EPOLLET | EPOLLRDHUP;
    if (events & SOCK_CAN_READ)
        ev.events |= EPOLLIN;
    if (events & SOCK_CAN_WRITE)
        ev.events |= EPOLLOUT;
    ev.data.ptr = udata;
    return (epoll_ctl(e->pfd, EPOLL_CTL_ADD, fd, &ev));
}
