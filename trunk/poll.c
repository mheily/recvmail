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

// XXX-FIXME -- kludge
#ifdef __linux__
#define HAVE_SYS_EPOLL_H 1
#endif

#include <stdlib.h>
#include <errno.h>
#include "poll.h"
//#include "recvmail.h"

/* Maximum number of events to read in a single system call */
#define MAXEVENTS 500

#if HAVE_SYS_EPOLL_H
#include <sys/epoll.h>

struct evcb {
    struct epoll_event   evt[MAXEVENTS];
    struct epoll_event  *cur;
    int                  pfd;
    ssize_t              cnt;
};

#endif

struct evcb * 
poll_new(void)
{
    struct evcb *e;

#if HAVE_SYS_EPOLL_H
    if ((e = malloc(sizeof(*e))) == NULL)
        return (NULL);
    e->cur = &e->evt[0];
    e->cnt = 0;
    if ((e->pfd = epoll_create(50000)) < 0) {
        free(e);
        return (NULL); 
    }
    return (e);
#endif
}

/* ------------------------- pollset handling functions -----------------*/




void *
poll_wait(struct evcb *e, int *events)
{
#if HAVE_SYS_EPOLL_H
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
    if (e->cur->events & EPOLLRDHUP || e->cur->events & EPOLLHUP) 
        *events |= SOCK_EOF;
    if (e->cur->events & EPOLLERR) 
        *events |= SOCK_ERROR;

    e->cnt--;

    return (e->cur->data.ptr);
#endif
}

int
poll_disable(struct evcb *e, int fd)
{
#if HAVE_SYS_EPOLL_H

    return (epoll_ctl(e->pfd, EPOLL_CTL_DEL, fd, ((void *) -1L)));
#endif
}

int
poll_enable(struct evcb *e, int fd, void *udata, int events)
{
#if HAVE_SYS_EPOLL_H
    struct epoll_event ev;

    ev.events = EPOLLET;
    if (events & SOCK_CAN_READ)
        ev.events |= EPOLLIN;
    if (events & SOCK_CAN_WRITE)
        ev.events |= EPOLLOUT;
    ev.data.ptr = udata;
    return (epoll_ctl(e->pfd, EPOLL_CTL_ADD, fd, &ev));
#endif
}
