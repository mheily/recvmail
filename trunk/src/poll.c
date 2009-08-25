/*		$Id$		*/

/*
 * Copyright (c) 2004-2009 Mark Heily <devel@heily.com>
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
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "poll.h"
#include "queue.h"

/* Maximum number of descriptors to watch (TODO: make dynamic) */
#define POLLSET_MAX  2048

struct watch {
    struct pollfd *ps_ent;
    int     fd;
    void   *udata;
    void  (*callback)(void *, int);
    LIST_ENTRY(watch) entries;
};

struct timer {
    time_t  next_time;
    u_int   interval;
    int     active;      
    void   *udata;
    void  (*callback)(void *);
    LIST_ENTRY(timer) entries;
};

/*
 * GLOBAL VARIABLES
 */
struct pollfd        pollset[POLLSET_MAX];
struct watch *       poll2watch[POLLSET_MAX];
LIST_HEAD(,watch)    watchlist;
size_t               ps_count;

pthread_t            sig_catcher_tid;
int                  sc_pipefd[2];

pthread_t            timekeeper_tid;
int                  tk_pipefd[2];

int                  shutdown_flag;
int                  sig_status[NSIG + 1];
struct watch         sig_watch[NSIG + 1];
LIST_HEAD(,timer)    timer_list;

/*
 * Signal handling
 */

static void
signal_handler(void *unused, int unused2)
{
    int signum;
    char c;
    struct watch *w;

    (void) read(sc_pipefd[0], &c, 1);

    /* Handle all signals */
    for (signum = 0; signum < NSIG; signum++) {
        if (sig_status[signum] == 0)
            continue;

        w = &sig_watch[signum];
        if (w != NULL) {
            log_debug("calling signal handler for signum %d", signum);
            w->callback(w->udata, signum);
            sig_status[signum] = 0;
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
        sig_status[signum] = 1;
        write(pipefd, &c, 1);
    }
}

static void
timer_handler(void *unused, int unused2)
{
    struct timer *te, *te_next;
    time_t now;
    char c;

    (void) read(tk_pipefd[0], &c, 1);

    /* Check each timed event to see if it should occur */
    now = time(NULL);
    for (te = LIST_FIRST(&timer_list); te != LIST_END(&timer_list);
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

    LIST_INSERT_HEAD(&timer_list, te, entries);

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

int
poll_init(void)
{
    LIST_INIT(&timer_list); 
    LIST_INIT(&watchlist); 

    return (0);
}

void
poll_free(void)
{
    struct timer *te;

    while ((te = LIST_FIRST(&timer_list)) != NULL) {
        LIST_REMOVE(te, entries);
        free(te);
    }
    close(tk_pipefd[0]);
    close(tk_pipefd[1]);
    close(sc_pipefd[0]);
    close(sc_pipefd[1]);
}

void
poll_shutdown(void)
{
    shutdown_flag = 1;
}

int
poll_dispatch(void)
{
    int i;
    sigset_t set;
    int events;

    /* Block all signals */
    sigfillset(&set);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
        err(1, "pthread_sigmask(3)");

    /* Create the signal-catching thread */
    if (pipe(sc_pipefd) == -1) {
        log_errno("pipe(2)");
        return (-1);
    }
    if (pthread_create(&sig_catcher_tid, NULL, 
                signal_dispatch, &sc_pipefd[1]) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }
    if (poll_add(sc_pipefd[0], POLLIN, 
                signal_handler, NULL) == NULL) { 
        log_errno("poll_add()");
        return (-1);
    }

    /* Create the timekeeper thread */
    if (pipe(tk_pipefd) == -1) {
        log_errno("pipe(2)");
        return (-1);
    }
    if (pthread_create(&timekeeper_tid, NULL, 
                timekeeper, &tk_pipefd[1]) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }
    if (poll_add(tk_pipefd[0], POLLIN, timer_handler, NULL) == NULL) { 
        log_errno("poll_add()");
        return (-1);
    }

    /*
     * Main event loop
     */
    for (;;) {
        /* TODO: reap pending events before shutting down.. ? */
        if (shutdown_flag) {
            log_debug("shutting down");
            break;
        }

        /* Wait for an event */
        log_debug("waiting for event");
        events = poll(&pollset[0], ps_count, -1);
        if (events < 0) {
            if (errno == EINTR) {
                log_debug("eintr");
                continue;
            }
            log_debug("ps_count=%zu", ps_count);
            log_errno("poll(2)");
            return (-1);
        }
        if (events == 0) 
            continue;

        for (i = 0; i < ps_count; i++) {
            if (pollset[i].revents == 0)
                continue;

            if (pollset[i].revents)
                poll2watch[i]->callback(poll2watch[i]->udata, pollset[i].revents);

            if (--events == 0)
                break;
        }
    }

    /* TODO: possibly other cleanup (kill threads?) */
    poll_free();

    return (0);
}

struct pollfd * 
poll_get(struct watch *w) 
{
    return (w->ps_ent);

}

int
poll_signal(int signum, void(*cb)(void *, int), void *udata)
{
    if (signum > NSIG) {
        log_error("invalid signal number");
        return (-1);
    }

    sig_watch[signum].callback = cb;
    sig_watch[signum].udata = udata;

    return (0);
}

struct watch *
poll_add(int fd, int events, void (*callback)(void *, int), void *udata)
{
    struct watch *w;

    /* TODO: make this dynamic */
    if (ps_count == POLLSET_MAX) {
        log_error("too many open file descriptors");
        return (NULL);
    }

    w = calloc(1, sizeof(*w));
    if (w == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }

    poll2watch[ps_count] = w;
    w->ps_ent = &pollset[ps_count];
    w->ps_ent->fd = fd;
    w->ps_ent->events = events;
    w->fd = fd;
    w->callback = callback;
    w->udata = udata;
    ps_count++;

    LIST_INSERT_HEAD(&watchlist, w, entries);

    return (w);
}

void
poll_remove(struct watch *w)
{
    u_int i;

    /* Backfill the free slot with the tail entry in the array */
    i = w->ps_ent - &pollset[0];
    ps_count--; 
    if (ps_count > 1 && i < ps_count) {
        memcpy(&pollset[i], &pollset[ps_count], sizeof(struct pollfd));
        poll2watch[i] = poll2watch[ps_count];
        poll2watch[i]->ps_ent = &pollset[i];
    }
    
    LIST_REMOVE(w, entries);
    free(w);
}
