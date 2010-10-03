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
#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

struct work {
    u_long  sid;                /* Session ID */
    u_int   argc;               /* Number of arguments */
    union {
        u_int   u_i;
        u_long  u_l;
        void   *ptr;
    } argv0;                    /* Argument vector */
    int retval;                 /* Return value */
};

struct session;

struct workqueue *
        workqueue_new( void (*)(struct work *, void *),
                void (*)(struct session *, int), 
                void *);

int     workqueue_submit(struct workqueue *, struct work);
void    workqueue_free(struct workqueue *);
int     workqueue_init(void);

#endif  /* _WORKQUEUE_H */