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

#define NDEBUG

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "queue.h"
#include "poll.h"
#include "session.h"
#include "workqueue.h"

static void wq_retrieve_all(void *, int events);

struct wq_entry {
    unsigned long sid;                      /* Session ID */
    struct work w;
    TAILQ_ENTRY(wq_entry) entries;
};

struct workqueue {
    void (*bottom)(struct work *, void *);
    void (*top)(struct session *, int);
    void *udata;

    /* Request list */
    TAILQ_HEAD(,wq_entry) req;
    pthread_mutex_t      req_mtx;
    pthread_cond_t       req_pending;

    /* Response list */
    TAILQ_HEAD(,wq_entry) res;
    pthread_mutex_t      res_mtx;

    /* poll(2) notification fd */
    int pfd[2];
};


struct workqueue *
wq_new( void (*bottom)(struct work *, void *),
        void (*top)(struct session *, int), 
        void *udata)
{
    struct workqueue *wq;

    if ((wq = calloc(1, sizeof(*wq))) == NULL)
        return (NULL);

    if (pipe(wq->pfd) == -1) {
        free(wq);
        log_errno("pipe(2)");
        return (NULL);
    }

    wq->bottom = bottom;
    wq->top = top;
    wq->udata = udata;
    TAILQ_INIT(&wq->req);
    pthread_mutex_init(&wq->req_mtx, NULL);
    pthread_mutex_init(&wq->res_mtx, NULL);
    pthread_cond_init(&wq->req_pending, NULL);
    TAILQ_INIT(&wq->res);

    if (poll_enable(wq->pfd[0], SOCK_CAN_READ, 
                wq_retrieve_all, wq) < 0) { 
        log_errno("poll_enable()");
        free(wq);
        return (NULL);
    }

    return (wq);
}


void
wq_free(struct workqueue *wq)
{
    /* TODO: wait for all response items to be retrieved */
    close(wq->pfd[0]);
    close(wq->pfd[1]);
    free(wq);
}


int
wq_submit(struct workqueue *wq, struct work w)
{
    struct wq_entry *wqe;

    if ((wqe = calloc(1, sizeof(*wqe))) == NULL)
        return (-1);
    memcpy(&wqe->w, &w, sizeof(w));

    pthread_mutex_lock(&wq->req_mtx);
    TAILQ_INSERT_TAIL(&wq->req, wqe, entries);
    pthread_cond_signal(&wq->req_pending);
    pthread_mutex_unlock(&wq->req_mtx);

    return (0);
}


int         
wq_retrieve(struct work *wptr, struct workqueue *wq)
{
    struct wq_entry *wqe;

    pthread_mutex_lock(&wq->res_mtx);
    if ((wqe = TAILQ_FIRST(&wq->res)) != NULL)
        TAILQ_REMOVE(&wq->res, wqe, entries);
    pthread_mutex_unlock(&wq->res_mtx);

    /* Test for spurious wakeup */
    if (wqe == NULL) {
        memset(wptr, 0, sizeof(*wptr));
        return (-1);
    }

    memcpy(wptr, &wqe->w, sizeof(*wptr));
    free(wqe);
    return (0);
}


static void
wq_retrieve_all(void *arg, int events)
{
    struct workqueue *wq = (struct workqueue *) arg;
    struct session *s = NULL;
    struct work w;
    int c;
    ssize_t n;

    log_debug("reading pfd");
    n = read(wq->pfd[0], &c, 1);
    if (n < 0) {
        log_errno("read(2)");
        abort();//TODO: less extreme failure
    }
    log_debug("n=%zu", n);

    if (wq_retrieve(&w, wq) < 0)
        return;

    /* The session might not exist anymore. */
    if (session_table_lookup(&s, w.sid) < 0)
        return;

    log_debug("running top s->fd = %d", s->fd);
    wq->top(s, w.retval); 
}


void *
wq_dispatch(struct workqueue *wq)
{
    struct wq_entry *wqe;
    
    for (;;) {

        /* Wait for an item on the request queue. */
        pthread_mutex_lock(&wq->req_mtx);
        if (!TAILQ_EMPTY(&wq->req)) 
            goto queue_not_empty;
        pthread_cond_wait(&wq->req_pending, &wq->req_mtx);
        if (TAILQ_EMPTY(&wq->req)) {
            log_debug("spurious wakeup");
            pthread_mutex_unlock(&wq->req_mtx);
            continue;
        }

        /* Remove the first request */
queue_not_empty:
        wqe = TAILQ_FIRST(&wq->req);
        TAILQ_REMOVE(&wq->req, wqe, entries);
        pthread_mutex_unlock(&wq->req_mtx);
        log_debug("got an item");

        /* Invoke the callback function */
        wq->bottom(&wqe->w, wq->udata);

        /* Add the session to the response queue */
        pthread_mutex_lock(&wq->res_mtx);
        TAILQ_INSERT_TAIL(&wq->res, wqe, entries);
        pthread_mutex_unlock(&wq->res_mtx);

        /* Notify the main event loop */
        if (write(wq->pfd[1], "!", 1) < 1) {
            log_errno("write(2)");
            abort();//TODO: less extreme failure
        }
    }

    return (NULL);
}
