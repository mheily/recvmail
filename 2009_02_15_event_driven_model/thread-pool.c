/*	$Id$	*/

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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "thread-pool.h"
#include "session.h"


/* 


thread pools --

  POOL_NAME		DESCRIPTION							NOTES
  listener 		waits for incoming connections and calls accept(2)		no queue items, not a thread_pool
  authorize		looks up the client in a DNS block list,			multi-worker FIFO
  			checks for too many sessions-per-client
  reverse_lookup	gets the PTR record for the client				multi-worker FIFO
  smtp			SMTP conversation						multi-worker FIFO
  idle			place where sessions live when waiting for client I/O		no workers
  fsyncer		call fsync(2) and closes the open file				multi-worker FIFO

 */

static int
thread_main(struct thread_pool *tpool)
{
	struct session *s = NULL;

    pthread_mutex_lock(&tpool->lock);

	for (;;) {

		/* Wait until there is work to be done. */
		if (LIST_EMPTY(&tpool->queue) &&
                pthread_cond_wait(&tpool->queue_not_empty, &tpool->lock) != 0) {
            log_error("pthread_cond_wait() failed");
			break;
		}


		/* Remove the first unit of work from the head of the queue */
		/* If the work queue is empty, go back to sleep */
		if ((s = LIST_FIRST(&tpool->queue)) == NULL) {
			pthread_mutex_unlock(&tpool->lock);
			continue;
		}
		LIST_REMOVE(s, entries);
		pthread_mutex_unlock(&tpool->lock);
		
		/* Run the requested work routine */
		tpool->dispatch(tpool, s);

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

    LIST_INIT(&tpool->queue);
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

#if FIXME
    struct session *s;
    // should be done somewhere else
    /* Destroy the work queue */
    while (! STAILQ_EMPTY(&tpool->work_queue)) {
        work = STAILQ_FIRST(&tpool->work_queue);
        STAILQ_REMOVE_HEAD(&tpool->work_queue, entries);
        free(work);
    }
#endif
	
    /* FIXME: Kill each worker thread */

	free(tpool);
}

void
server_schedule(struct thread_pool *dst, 
			struct thread_pool *src,
			struct session *s)
{
    /* Remove the item from the source */	
	if (src != NULL) {
		pthread_mutex_lock(&src->lock);
		LIST_REMOVE(s, entries);
		pthread_mutex_unlock(&src->lock);
	}

    /* Add the item to the destination */
    pthread_mutex_lock(&dst->lock);
    LIST_INSERT_HEAD(&dst->queue, s, entries);	// TODO: want to put at the end of the list
    pthread_cond_signal(&dst->queue_not_empty);
    pthread_mutex_unlock(&dst->lock);
}

