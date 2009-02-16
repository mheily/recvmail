/*	$Id$	*/

/*
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

#ifndef _THREAD_POOL_H
#define _THREAD_POOL_H

#include <pthread.h>

#include "queue.h"

struct thread_pool {
	pthread_mutex_t  lock; 
LIST_HEAD(,session)      queue; 
	void           (*dispatch)(struct thread_pool *, struct session *);
	size_t	         num_workers;
	pthread_cond_t   queue_not_empty;
};

struct thread_pool * 	thread_pool_create(unsigned int);
void 			thread_pool_destroy(struct thread_pool *);
int 			thread_pool_run(struct thread_pool *, void *, void *);

#endif
