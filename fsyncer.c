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

#include "recvmail.h"
#include "server.h"
#include "poll.h"
#include "session.h"

/* How frequently this thread wakes up, in seconds */
#define INTERVAL    15

/* NOTE: This was taken from thread-pool.c and is very similar. */
static void *
fsyncer_main(struct server *srv)
{
    int fd;
    LIST_HEAD(,session) q;
    struct session *s;

    //log_debug("fsyncer main woke up");
    pthread_mutex_lock(&srv->sched_lock);

    for (;;) {
        sleep(INTERVAL);
        //log_debug("fsyncer woke up");
        pthread_mutex_lock(&srv->sched_lock);
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

#if FIXME
        /* Force a sync of the metadata for the spool directory. */
        if (fsync(s->msg->fd) != 0) {
            log_errno("fsync(2) of spooldir");
            //FIXME - should probably crash now.
        }
#endif

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

#if FIXME
    // only for ext3, not softupdates
    
    /* 
     * Keep a file descriptor open to the spooldir 
     * to enable the metadata to be sync'd 
     */
    if ((srv->spooldir_fd = open(OPT.spooldir, O_RDWR)) < 0) {
        log_errno("open(2) of `%s'", OPT.spooldir);
        return (-1);
    }
#endif

    if (pthread_create(&srv->fsyncer_tid, NULL, (void *) fsyncer_main, (void *) srv) != 0) {
        log_errno("pthread_create(3)");
       return (-1);
    }

    return (0);
}
