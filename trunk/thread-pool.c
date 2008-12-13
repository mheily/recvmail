/*	$Id: thread-pool.c,v 1.1.1.1 2006/03/19 00:23:12 mheily Exp $	*/

/*
 *              thread-pool.c - thread pools
 *
 * Copyright (c) 2006 Mark Heily <devel@heily.com>
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

#include "recvmail.h"
#include "thread-pool.h"

/* NOTE: to kill the threadpool, add a work entry that invokes pthread_exit() */

static int
thread_main(struct thread_pool *tpool)
{
	struct tpool_work *work = NULL;

    pthread_mutex_lock(&tpool->lock);

	for (;;) {

		/* Wait until there is work to be done. */
		if (STAILQ_EMPTY(&tpool->work_queue) &&
                pthread_cond_wait(&tpool->queue_not_empty, &tpool->lock) != 0) {
            log_error("pthread_cond_wait() failed");
			break;
		}

		/* If the work queue is empty, go back to sleep */
		if (STAILQ_EMPTY(&tpool->work_queue)) {
			pthread_mutex_unlock(&tpool->lock);
			continue;
		}

		/* Remove the first unit of work from the head of the queue */
        work = STAILQ_FIRST(&tpool->work_queue);
        STAILQ_REMOVE_HEAD(&tpool->work_queue, entries);
		pthread_mutex_unlock(&tpool->lock);
		
		/* Run the requested work routine */
		(*(work->func))(work->arg);
        free(work);

		pthread_mutex_lock(&tpool->lock);
	}

    pthread_mutex_unlock(&tpool->lock);
    return (0);
}


struct thread_pool *
thread_pool_create(unsigned int num_workers)
{
	struct thread_pool *tpool;
    pthread_t thread;
    unsigned int i;

    if ((tpool = calloc(1, sizeof(*tpool))) == NULL)
        return (NULL);

    STAILQ_INIT(&tpool->work_queue);
	pthread_mutex_init(&tpool->lock, NULL);
	pthread_cond_init(&tpool->queue_not_empty, NULL);

    for (i = 0; i < num_workers; i++) {
		if (pthread_create(&thread, NULL, (void *) thread_main, (void *) tpool) != 0) {
			log_errno("pthread_create(3)");
            tpool->num_workers = i;
            break;
		}
	}

    return (tpool);
}


void
thread_pool_destroy(struct thread_pool *tpool)
{
    struct tpool_work *work;

    /* Destroy the work queue */
    while (! STAILQ_EMPTY(&tpool->work_queue)) {
        work = STAILQ_FIRST(&tpool->work_queue);
        STAILQ_REMOVE_HEAD(&tpool->work_queue, entries);
        free(work);
    }
	
    /* FIXME: Kill each worker thread */

	free(tpool);
}


int
thread_pool_run(struct thread_pool *tpool, void *func, void *arg)
{
	struct tpool_work  *work;

	/* Generate a unit of work */
    if ((work = malloc(sizeof(*work))) == NULL) {
        log_errno("malloc(3)");
        return (-1);
    }
	work->func = func;
	work->arg = arg;

    /* Add it to the work queue */
	pthread_mutex_lock(&tpool->lock);
    STAILQ_INSERT_TAIL(&tpool->work_queue, work, entries);
    pthread_mutex_unlock(&tpool->lock);

	/* Signal that the queue is not empty */
	/* FIXME - RACE CONDITION - this may fire before the new thread calls cond_wait() */
	pthread_cond_signal(&tpool->queue_not_empty);

    return (0);
}
