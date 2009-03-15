/*		$Id: address.c 119 2009-02-11 03:25:20Z mheily $		*/

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

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "queue.h"
#include "session.h"
#include "workqueue.h"

struct workqueue {
    void (*cb)(struct session *, void *);
    void *udata;

    /* Request list */
    TAILQ_HEAD(,session) req;
    pthread_mutex_t      req_mtx;
    pthread_cond_t       req_pending;

    /* Response list */
    TAILQ_HEAD(,session) res;
    pthread_mutex_t      res_mtx;

    /* poll(2) notification fd */
    int pfd;
};


struct workqueue *
wq_new(int pfd, void (*cb)(struct session *, void *), void *udata)
{
    struct workqueue *wq;

    if ((wq = calloc(1, sizeof(*wq))) == NULL)
        return (NULL);

    wq->cb = cb;
    wq->udata = udata;
    TAILQ_INIT(&wq->req);
    if (pthread_mutex_init(&wq->req_mtx, NULL) != 0)
        err(1, "pthread_mutex_init(3)");
    if (pthread_cond_init(&wq->req_pending, NULL) != 0)
        err(1, "pthread_cond_init(3)");
    TAILQ_INIT(&wq->res);
    if (pthread_mutex_init(&wq->res_mtx, NULL) != 0)
        err(1, "pthread_mutex_init(3)");
    wq->pfd = pfd;

    return (wq);
}


int
wq_submit(struct workqueue *wq, struct session *s)
{
    s->refcount++;
    pthread_mutex_lock(&wq->req_mtx);
    TAILQ_INSERT_TAIL(&wq->req, s, workq_entries);
    pthread_cond_signal(&wq->req_pending);
    pthread_mutex_unlock(&wq->req_mtx);
    return (0);
}


int         
wq_retrieve(struct session **sptr, struct workqueue *wq)
{
    struct session *s;

    pthread_mutex_lock(&wq->res_mtx);
    s = TAILQ_FIRST(&wq->res);
    if (s != NULL) {
        TAILQ_REMOVE(&wq->res, s, workq_entries);
    }
    pthread_mutex_unlock(&wq->res_mtx);

    if (s->refcount > 0) {
        s->refcount--;
    } else {
        session_close(s);
        s = NULL;
    }
    
    if (s != NULL) {
        *sptr = s;
        return (0);
    } else {
        *sptr = NULL;
        return (-1);
    }
}


void *
wq_dispatch(struct workqueue *wq)
{
    struct session *s;
    
    log_debug("dispatcher started");

    for (;;) {

        /* Wait for a work item and remove it from the queue */
        pthread_mutex_lock(&wq->req_mtx);
        while (TAILQ_EMPTY(&wq->req)) {
            log_debug("waiting");
            if (pthread_cond_wait(&wq->req_pending, &wq->req_mtx) != 0)  
                log_errno("pthread_cond_wait(3)");
            log_debug("wakeup");
            if ((s = TAILQ_FIRST(&wq->req)) == NULL) {
                continue;
            }
        }
        TAILQ_REMOVE(&wq->req, s, workq_entries);
        pthread_mutex_unlock(&wq->req_mtx);
        log_debug("got an item");

        /* Invoke the callback function */
        wq->cb(s, wq->udata);

        /* Add the session to the response queue */
        pthread_mutex_lock(&wq->res_mtx);
        TAILQ_INSERT_TAIL(&wq->res, s, workq_entries);
        pthread_mutex_unlock(&wq->res_mtx);

        (void)write(wq->pfd, "!", 1); // FIXME: err handling
    }

    return (NULL);
}
