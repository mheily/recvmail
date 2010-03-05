/*		$Id$		*/

/*
 * Copyright (c) 2004-2009 Mark Heily <devel@heily.com>
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
recipient_free(struct message *msg)
{
    struct mail_addr *var, *nxt;

    if (LIST_EMPTY(&msg->recipient))
        return;

    /* Remove all recipients from the list */
    for (var = LIST_FIRST(&msg->recipient); 
            var != LIST_END(&msg->recipient); 
            var = nxt) {
        nxt = LIST_NEXT(var, entries);
        address_free(var);
    }

    LIST_INIT(&msg->recipient);
}

struct message *
message_new(void)
{
    return (calloc(1, sizeof(struct message)));
}

int
message_fsync(struct message *msg)
{
    if (fsync(msg->fd) < 0) {
        log_errno("fsync(2) of fd %d", msg->fd);
        return (-1);
    }

    return (0);
}

/* Free the storage used by the message */
void
message_free(struct message *msg)
{
    if (msg == NULL)
        return;

    /* Delete the message from the spool/ directory */
    if (msg->path != NULL) {
        if (unlink(msg->path) != 0)
            log_errno("unlink(2) of `%s'", msg->path);
        free(msg->path);
        msg->path = NULL;
    }

    message_reset(msg);
    free(msg);
}

void
message_reset(struct message *msg)
{
    recipient_free(msg);
    free(msg->client);
    free(msg->return_path);
    free(msg->filename);
    free(msg->path);
    memset(msg, 0, sizeof(*msg));
}
