/*		$Id: server.c 151 2009-03-14 01:32:02Z mheily $		*/

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
#include <unistd.h>

#include "session.h"
#include "maildir.h"
#include "mda.h"
#include "workqueue.h"

struct delivery_agent {
    struct workqueue *wq;
};

static void mda_deliver(struct session *s, void *udata);


struct delivery_agent *
mda_new(int pfd)
{
    struct delivery_agent *mda;

    if ((mda = calloc(1, sizeof(*mda))) == NULL)
        return (NULL);

    mda->wq = wq_new(pfd, mda_deliver, mda);

    return (mda);
}

static void
mda_deliver(struct session *s, void *udata)
{
    log_debug("delivering");
    message_fsync(&s->msg); // TODO: error handling
    maildir_deliver(&s->msg);// TODO: error handling
    message_close(&s->msg); // TODO: error handling
    s->handler(s); // FIXME -- do this in worker threads
    /* XXX-FIXME update state field */
}


int
mda_submit(struct delivery_agent *mda, struct session *s)
{
    return wq_submit(mda->wq, s);
}

int
mda_response(struct session **sptr, struct delivery_agent *mda)
{
    return wq_retrieve(sptr, mda->wq);
}

void *
mda_dispatch(void *arg)
{
    struct delivery_agent *mda = (struct delivery_agent *) arg;
    wq_dispatch(mda->wq);
    return (NULL);
}

void
mda_init(void)
{
}
