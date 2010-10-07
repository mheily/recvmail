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

static void
mda_deliver(void *arg)
{
    struct message *msg = (struct message *) arg;

    if (message_fsync(msg) < 0 ||
            maildir_deliver(msg) < 0 ||
            message_close(msg) < 0) 
    {
        message_free(msg);
        //FIXME:wqa->retval = -1;
    } else {
        message_free(msg);
        //FIXME:wqa->retval = 0;
    }
}


int
mda_submit(unsigned long sid, struct message *msg)
{
    //return workqueue_submit(mda->wq, w);
    //FIXME:STUB
    mda_deliver(msg);
    return (0);
}
