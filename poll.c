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

static void * timekeeper(void *arg);

struct watch {
    struct epoll_event ev;
    int   fd;
    int    mask;
    void  *udata;
    void (*callback)(void *, int);
    LIST_ENTRY(watch) entries;
};

struct timer {
    time_t   next_time;
    uint32_t interval;
    int      active;      
    void    *udata;
    void (*callback)(void *);
    LIST_ENTRY(timer) entries;
};

struct evcb {
    pthread_t            sig_catcher;
    int                  sc_pipefd[2];

    pthread_t            timekeeper;
    int                  tk_pipefd[2];

    int                  pfd;
    int                  shutdown;
    int                  sig_status[NSIG + 1];
    struct watch         sig_watch[NSIG + 1];
    LIST_HEAD(,watch)    watchlist;
    LIST_HEAD(,timer)    timer_list;
};

/*
 * Signal handling
 */

static void
signal_handler(void *unused, int unused2)
{
    int signum;
    char c;
    struct evcb *e = GLOBAL_EVENT;
    struct watch *w;

    (void) read(e->sc_pipefd[0], &c, 1);

    /* Handle all signals */
    for (signum = 0; signum < NSIG; signum++) {
        if (e->sig_status[signum] == 0)
            continue;

        w = &e->sig_watch[signum];
        if (w != NULL) {
            log_debug("calling signal handler for signum %d", signum);
            w->callback(w->udata, signum);
            e->sig_status[signum] = 0;
        } else {
            log_error("Caught unhandled signal %d -- exiting", signum);
            exit(0);
        }
    }
}

static void *
signal_dispatch(void *arg)
{
    int pipefd = *((int *) arg);
    char c = '\0';
    sigset_t set;
    int      signum;

    /* Build the list of signals we are interested in. */
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM);
    
    for (;;) {
        sigwait(&set, &signum);
        log_debug("caught signal %d", signum);
        GLOBAL_EVENT->sig_status[signum] = 1;
        write(pipefd, &c, 1);
    }
}

static void
timer_handler(void *unused, int unused2)
{
    struct evcb *e = GLOBAL_EVENT;
    struct timer *te, *te_next;
    time_t now;
    char c;

    (void) read(e->tk_pipefd[0], &c, 1);

    /* Check each timed event to see if it should occur */
    now = time(NULL);
    for (te = LIST_FIRST(&e->timer_list); te != LIST_END(&e->timer_list);
            te = te_next) {
        te_next = LIST_NEXT(te, entries);

        if (te->active < 0) {
            LIST_REMOVE(te, entries);
            free(te);
            continue;
        }

        if ((te->active == 0) || (now < te->next_time)) 
            continue;

        te->callback(te->udata);
        if (te->interval == 0) {
            LIST_REMOVE(te, entries);
            free(te);
        } else {
            te->next_time = now + te->interval;
        }
    }
}

struct timer *
poll_timer_new(unsigned int interval, 
        void (*callback)(void *),
        void  *udata)
{
    struct timer *te;

    te = calloc(1, sizeof(*te));
    if (te == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }
    te->next_time = time(NULL) + interval;
    te->interval = interval;
    te->callback = callback;
    te->udata = udata;
    te->active = 1;

    LIST_INSERT_HEAD(&GLOBAL_EVENT->timer_list, te, entries);

    return (te);
}

void
poll_timer_free(struct timer *te) 
{
    /* This will cause timer_handler() to free the object
     * the next time it is called. It is normal for users
     * to call poll_timer_free() from inside a timer callback,
     * so if we free'd the object directly it would cause
     * memory corruption inside of timer_handler() when it
     * goes to re-arm the timer after the callback.
     */
    te->active = -1;
}

void
poll_timer_disable(struct timer *te)
{
    te->active = 0;
}

void
poll_timer_enable(struct timer *te)
{
    te->next_time = time(NULL) + te->interval;
    te->active = 1;
}

static void *
timekeeper(void *arg)
{
    int pipefd = *((int *) arg);
    char c = '\0';

    for (;;) {
        sleep(30);
        write(pipefd, &c, 1);
    }
}

static struct watch *
watch_new(int fd, 
        int mask, 
        void (*callback)(void *, int),
        void *udata)
{
    struct watch *w;

    if ((w = calloc(1, sizeof(*w))) == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }
    w->fd = fd;
    w->mask = mask;
    w->callback = callback;
    w->udata = udata;

    return (w);
}

struct evcb * 
poll_new(void)
{
    struct evcb *e;
    sigset_t set;

    if ((e = calloc(1, sizeof(*e))) == NULL)
        return (NULL);
    if ((e->pfd = epoll_create(1)) < 0) {
        log_errno("epoll_create(2)");
        free(e);
        return (NULL); 
    }
    LIST_INIT(&e->watchlist); 
    LIST_INIT(&e->timer_list); 

    /* KLUDGE: Someday this could be multi-threadsafe.. */
    if (GLOBAL_EVENT != NULL)
        err(1, "cannot have multiple event sinks");
    else
        GLOBAL_EVENT = e;

    /* Block all signals */
    sigfillset(&set);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
        err(1, "pthread_sigmask(3)");

    /* Create the signal-catching thread */
    if (pipe(e->sc_pipefd) == -1) {
        log_errno("pipe(2)");
        goto errout;
    }
    if (pthread_create(&e->sig_catcher, NULL, 
                signal_dispatch, &e->sc_pipefd[1]) != 0) {
        log_errno("pthread_create(3)");
        goto errout;
    }
    if (poll_enable(e->sc_pipefd[0], SOCK_CAN_READ, 
                signal_handler, NULL) < 0) { 
        log_errno("poll_enable()");
        goto errout;
    }

    /* Create the timekeeper thread */
    if (pipe(e->tk_pipefd) == -1) {
        log_errno("pipe(2)");
        goto errout;
    }
    if (pthread_create(&e->timekeeper, NULL, 
                timekeeper, &e->tk_pipefd[1]) != 0) {
        log_errno("pthread_create(3)");
        goto errout;
    }
    if (poll_enable(e->tk_pipefd[0], SOCK_CAN_READ, 
                timer_handler, NULL) < 0) { 
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
    struct timer *te;

    while ((w = LIST_FIRST(&e->watchlist)) != NULL) {
        LIST_REMOVE(w, entries);
        free(w);
    }
    while ((te = LIST_FIRST(&e->timer_list)) != NULL) {
        LIST_REMOVE(te, entries);
        free(te);
    }
    close(e->pfd);
    close(e->tk_pipefd[0]);
    close(e->tk_pipefd[1]);
    close(e->sc_pipefd[0]);
    close(e->sc_pipefd[1]);
    free(e);
}

void
poll_shutdown(struct evcb *e)
{
    e->shutdown = 1;
}

int
poll_dispatch(struct evcb *e)
{
    struct watch *w;
    int events;

    for (;;) {
        /* TODO: reap pending events before shutting down.. ? */
        if (e->shutdown) {
            log_debug("shutting down");
            break;
        }

        /* Wait for an event */
        log_debug("waiting for event");
        if ((w = poll_wait(e, &events)) == NULL) {
            log_errno("poll_wait()");
            return (-1);
        }

        log_debug("got an event");
        w->callback(w->udata, events);
    }

    return (0);
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

    log_error("fd %d not found", fd);
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

    e->sig_watch[signum].callback = cb;
    e->sig_watch[signum].udata = udata;

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
