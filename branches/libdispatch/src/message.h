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
#ifndef _MESSAGE_H
#define _MESSAGE_H

#include "queue.h"

struct session;

/* An RFC-2822 message */
struct message {
    int     fd;		            /* File descriptor of the spoolfile */
    char   *path;	            /* The path to the spoolfile */
    size_t  recipient_count;
    size_t  msg_size;
    char   *filename;	        /* The Maildir message-ID */
    char   *client;     	    /* The "HELO/EHLO" string */
    char   *return_path;   	    /* The "MAIL FROM:" sender */
    LIST_HEAD(,mail_addr) recipient;    /* All recipients */
};

struct message * message_new(void);
void             message_free(struct message *);

int     message_close(struct message *);
int     message_fsync(struct message *);
void    message_reset(struct message *);

#endif /* _MESSAGE_H */
