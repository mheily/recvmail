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
#include "smtp.h"
#include "workqueue.h"

struct delivery_agent {
    struct workqueue *wq;
};

static void mda_deliver(struct work *wqa, void *udata);

struct delivery_agent *
mda_new(void)
{
    struct delivery_agent *mda;

    if ((mda = calloc(1, sizeof(*mda))) == NULL)
        return (NULL);

    mda->wq = wq_new(mda_deliver, smtp_mda_callback, mda);

    return (mda);
}

void
mda_free(struct delivery_agent *mda)
{
    wq_free(mda->wq);
    free(mda);
}

static void
mda_deliver(struct work *wqa, void *udata)
{
    struct message *msg;
    log_debug("delivering");
    // FIXME:msg object needs to be made wqa->ptr
    msg = (struct message *) wqa->argv0.ptr;
    message_fsync(msg); // TODO: error handling
    maildir_deliver(msg);// TODO: error handling
    message_close(msg); // TODO: error handling
    message_free(msg);
    /* XXX-FIXME update state field */
}


int
mda_submit(struct delivery_agent *mda, unsigned long sid, struct message *msg)
{
    struct work w;

    w.sid = sid;
    w.argc = 1;
    w.argv0.ptr = msg;
    
    return wq_submit(mda->wq, w);
}

void *
mda_dispatch(void *arg)
{
    struct delivery_agent *mda = (struct delivery_agent *) arg;
    wq_dispatch(mda->wq);
    return (NULL);
}
