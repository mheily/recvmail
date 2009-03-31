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
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "epoll.h"
#include "log.h"
#include "poll.h"
#include "queue.h"

/* Lame.. but one event manager per process is a good idea */
struct evcb * GLOBAL_EVENT;

static struct watch *
poll_wait(struct evcb *e, int *events_ptr);

struct watch {
    struct epoll_event ev;
    int    fd;
    int    mask;
    void  *udata;
    void (*cb)(void *, int);
    LIST_ENTRY(watch) entries;
};

struct signal_handler {
    void (*callback)(void *, int);
    void *udata;
};

struct evcb {
    pthread_t            sig_catcher;
    int                  pfd;
    int        pipefd[2];
    LIST_HEAD(,watch)    watchlist;
    struct signal_handler sig[NSIG + 1];
};

/*
 * Signal handling
 */

/* NOOP signal handler */
void
_sig_handler(int num)
{
    num = 0;
}

static void
set_signal_mask(int how)
{
    sigset_t set;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM);
    if (pthread_sigmask(how, &set, NULL) != 0)
        err(1, "pthread_sigmask(3)");

    if (how == SIG_UNBLOCK) {
        sa.sa_flags = 0;
        sa.sa_handler = _sig_handler;
        sigaction (SIGHUP, &sa, NULL);
        sigaction (SIGINT, &sa, NULL);
        sigaction (SIGTERM, &sa, NULL);
    }
}

static void
signal_handler(void *unused, int signum)
{
    struct evcb *e = GLOBAL_EVENT;
    void (*callback)(void *, int);

    callback = e->sig[signum].callback;
    if (callback != NULL) {
        log_debug("calling signal handler for signum %d", signum);
        callback(e->sig[signum].udata, signum);
    } else {
        log_error("Caught unhandled signal %d -- exiting", signum);
        exit(0);
    }
}

static void *
signal_dispatch(void *arg)
{
    int pipefd = *((int *) arg);
    char c = '\0';

    set_signal_mask(SIG_UNBLOCK);
    for (;;) {
        pause();
        write(pipefd, &c, 1);
    }
}

static struct watch *
watch_new(int fd, 
        int mask, 
        void (*cb)(void *, int),
        void *udata)
{
    struct watch *w;

    if ((w = calloc(1, sizeof(*w))) == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }
    w->fd = fd;
    w->mask = mask;
    w->cb = cb;
    w->udata = udata;

    return (w);
}

struct evcb * 
poll_new(void)
{
    struct evcb *e;

    if ((e = calloc(1, sizeof(*e))) == NULL)
        return (NULL);
    if ((e->pfd = epoll_create(1)) < 0) {
        log_errno("epoll_create(2)");
        free(e);
        return (NULL); 
    }
    LIST_INIT(&e->watchlist); 

    if (GLOBAL_EVENT != NULL)
        err(1, "cannot have multiple event sinks");
    else
        GLOBAL_EVENT = e;

    /* Create a pipe for inter-thread notification */
    if (pipe(e->pipefd) == -1) {
        log_errno("pipe(2)");
        goto errout;
    }

    set_signal_mask(SIG_BLOCK);
    signal(SIGPIPE, SIG_IGN);       /* TODO: put this with the mask */

    /* Create the signal-catching thread */
    if (pthread_create(&e->sig_catcher, NULL, signal_dispatch, &e->pipefd[1]) != 0) {
        log_errno("pthread_create(3)");
        goto errout;
    }

    if (poll_enable(e->pipefd[0], SOCK_CAN_READ, signal_handler, NULL) < 0) { 
        log_errno("poll_enable()");
        goto errout;
    }

    return (e);

errout:
    free(e);
    return (NULL);
}

void
poll_free(struct evcb *e)
{
    struct watch *w;

    while ((w = LIST_FIRST(&e->watchlist)) != NULL) {
        LIST_REMOVE(w, entries);
        free(w);
    }
    close(e->pfd);
    free(e);
}

int
poll_dispatch(struct evcb *e)
{
    struct watch *w;
    int events;

    for (;;) {

        /* Wait for an event */
        log_debug("waiting for event");
        if ((w = poll_wait(e, &events)) == NULL) {
            log_errno("poll_wait()");
            return (-1);
        }

        //FIXME-todo
        log_debug("got an event");
        w->cb(w->udata, events);
    }
}

/* ------------------------- pollset handling functions -----------------*/

static struct watch *
poll_wait(struct evcb *e, int *events_ptr)
{
    struct watch *w;
    struct epoll_event evt;
    int n, events;

    do {
        n = epoll_wait(e->pfd, &evt, 1, -1); 
    } while (n == 0);

    if (n < 0) {
        log_errno("epoll_wait(2)");
        return (NULL);
    }

    /* Determine which events happened. */
    events = 0;
    if (evt.events & EPOLLIN) 
        events |= SOCK_CAN_READ;
    if (evt.events & EPOLLOUT) 
        events |= SOCK_CAN_WRITE;
    if (evt.events & EPOLLHUP || evt.events & EPOLLRDHUP) 
        events |= SOCK_EOF;
    if (evt.events & EPOLLERR) 
        events |= SOCK_ERROR;

    w = (struct watch *) evt.data.ptr;
    log_debug("got event %d on fd %d", events, w->fd);
    *events_ptr = events; //TODO: this is duplicate effort
    return (w);
}

int
poll_disable(int fd)
{
    struct evcb *e = GLOBAL_EVENT;
    struct watch *w;

    /* FIXME: slow linear search */
    LIST_FOREACH(w, &e->watchlist, entries) {
        if (w->fd != fd)
            continue;
        
        LIST_REMOVE(w, entries);
        free(w);
        return (epoll_ctl(e->pfd, EPOLL_CTL_DEL, fd, ((void *) -1L)));
    }

    log_error("fd %d not found", w->fd);
    return (-1);
}

int
poll_signal(int signum, void(*cb)(void *, int), void *udata)
{
    struct evcb *e = GLOBAL_EVENT;

    if (signum > NSIG) {
        log_error("invalid signal number");
        return (-1);
    }

    e->sig[signum].callback = cb;
    e->sig[signum].udata = udata;

    return (0);
}

int
poll_enable(int fd, int events, void (*cb)(void *, int), void *udata)
{
    struct evcb *e = GLOBAL_EVENT;
    struct watch *w;

    if (fd == 0) {
        log_debug("tried to watch fd 0");
        abort();
    }
    
    if ((w = watch_new(fd, events, cb, udata)) == NULL) 
        return (-1);

    w->ev.events = EPOLLRDHUP;
    if (events & SOCK_CAN_READ)
        w->ev.events |= EPOLLIN;
    if (events & SOCK_CAN_WRITE)
        w->ev.events |= EPOLLOUT;
    w->ev.data.ptr = w;
    if (epoll_ctl(e->pfd, EPOLL_CTL_ADD, fd, &w->ev) < 0) {
        log_errno("epoll_ctl(2)");
        free(w);
        return (-1);
    } else {
        LIST_INSERT_HEAD(&e->watchlist, w, entries);
        return (0);
    }
}
