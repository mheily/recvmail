/*		$Id: recvmail.h 103 2009-01-21 02:28:59Z mheily $		*/

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

struct mail_addr {
    char   *local_part, 
           *domain;
    LIST_ENTRY(mail_addr) entries;
};

/* An RFC-2822 message */
struct message {
    int             fd;		/* A file descriptor opened for writing the message */
    char           *path;	/* The path to the message */
    struct mail_addr *sender;	/* The email address of the sender */
    struct session *session;
    LIST_HEAD(,mail_addr) 
                    recipient;
    size_t          recipient_count;
    size_t          size;
    char           *filename;	/* The Maildir message-ID */
};

int     init_message(struct message *);
int     rset_message(struct message *);
int     valid_message(struct message *);

#endif /* _MESSAGE_H */
