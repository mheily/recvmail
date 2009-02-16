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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "server.h"
#include "message.h"
#include "poll.h"
#include "session.h"

/* NOTE: This was taken from thread-pool.c and is very similar. */
static void *
fsyncer_main(struct server *srv)
{
    int fd;
    LIST_HEAD(,session) q;
    struct session *s;

    for (;;) {
        pthread_mutex_lock(&srv->sched_lock);
        if (LIST_EMPTY(&srv->fsync_queue))
                pthread_cond_wait(&srv->fsync_queue_not_empty, &srv->sched_lock);
        log_debug("fsyncer woke up");
        if (LIST_EMPTY(&srv->fsync_queue)) {
            pthread_mutex_unlock(&srv->sched_lock);
            continue;
        }

        /* Move all of the items in the queue to a list inside the fsyncer thread.
         * This will reduce contention between the main thread and the fsyncer
         * thread. 
         */
        memcpy(&q, &srv->fsync_queue, sizeof(q));
        LIST_INIT(&srv->fsync_queue);
        pthread_mutex_unlock(&srv->sched_lock);

        /* Call fsync(2) for each item in the list. */
        // FIXME -- handle fsync failure
        LIST_FOREACH(s, &q, entries) {
            if ((fd = open(s->msg->path, O_RDWR)) < 0) {
                log_errno("open(2) of `%s'", s->msg->path);
                //FIXME - delete the message
                continue;
            }
            if (fsync(fd) != 0) {
                (void) close(fd);
                log_errno("fsync(2) of `%s'", s->msg->path);
                continue;
                //FIXME - delete the message
            }
            if (close(fd) != 0) {
                log_errno("close(2) of `%s'", s->msg->path);
                //FIXME - delete the message
            }
        }

        /* Send an OK message to the remote client */
        // FIXME -- handle fsync failure
        LIST_FOREACH(s, &q, entries) {
            session_println(s, "250 Ok");
        }

        /* Place each session back into the runnable queue. */
        /* Start listening for socket readability. */
        pthread_mutex_lock(&srv->sched_lock);
        LIST_FOREACH(s, &q, entries) {
            LIST_REMOVE(s, entries);
            LIST_INSERT_HEAD(&srv->runnable, s, entries);
            poll_enable(srv->evcb, s->fd, s, SOCK_CAN_READ);
        }
        pthread_mutex_unlock(&srv->sched_lock);
    }

    pthread_mutex_unlock(&srv->sched_lock);  // FIXME - not needed probably
    return (NULL);
}
    
int
fsyncer_init(struct server *srv)
{
    pthread_cond_init(&srv->fsync_queue_not_empty, NULL);
    if (pthread_create(&srv->fsyncer_tid, NULL, (void *) fsyncer_main, (void *) srv) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }

    return (0);
}
