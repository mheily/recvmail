/*		$Id$		*/

/*
 * Copyright (c) 2004-2007 Mark Heily <devel@heily.com>
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

#include "message.h"
#include "log.h"

struct message *
message_new()
{
    struct message *msg;

    if ((msg = calloc(1, sizeof(struct message))) == NULL) {
        /* TODO: log_err() */
        return (NULL);
    }

    LIST_INIT(&msg->recipient);
    return (msg);
}

void
message_free(struct message *msg)
{
    struct mail_addr *var, *nxt;

    if (msg == NULL) {
        log_debug("double message_free() detected");
        return;
    }

    free(msg->path);
    free(msg->helo);
    address_free(msg->sender);
    free(msg->filename);

    /* Remove all recipients from the list */
    for (var = LIST_FIRST(&msg->recipient); var != LIST_END(&msg->recipient); var = nxt) {
        nxt = LIST_NEXT(var, entries);
        address_free(var);
    }

    free(msg);
}


