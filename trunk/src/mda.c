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

#include <unistd.h>

#include "log.h"
#include "session.h"
#include "maildir.h"
#include "message.h"
#include "mda.h"
#include "smtp.h"
#include "workqueue.h"

static struct delivery_agent *mda;

struct delivery_agent {
    struct workqueue *wq;
};

static void mda_deliver(struct work *wqa, void *udata);

int
mda_init(void)
{
    /* TODO: eliminate this restriction */
    if (mda != NULL) {
        log_error("cannot have multiple MDAs per process");
        return (-1);
    }
    if ((mda = calloc(1, sizeof(*mda))) == NULL)
        return (-1);

    mda->wq = wq_new(mda_deliver, smtp_mda_callback, mda);

    return (0);
}

void
mda_free(void)
{
    wq_free(mda->wq);
    free(mda);
}

static void
mda_deliver(struct work *wqa, void *udata)
{
    struct message *msg;

    msg = (struct message *) wqa->argv0.ptr;
    if (message_fsync(msg) < 0 ||
            maildir_deliver(msg) < 0 ||
            message_close(msg) < 0) 
    {
        message_free(msg);
        wqa->retval = -1;
    } else {
        message_free(msg);
        wqa->retval = 0;
    }
}


int
mda_submit(unsigned long sid, struct message *msg)
{
    struct work w;

    w.sid = sid;
    w.argc = 1;
    w.argv0.ptr = msg;
    
    return wq_submit(mda->wq, w);
}

void *
mda_dispatch(void *unused)
{
    wq_dispatch(mda->wq);
    return (NULL);
}
