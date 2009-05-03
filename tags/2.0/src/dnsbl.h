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
#ifndef _DNSBL_H
#define _DNSBL_H

/* Result codes */
#define DNSBL_NOT_FOUND     (0)
#define DNSBL_FOUND         (1)
#define DNSBL_ERROR         (-1)

struct dnsbl;
struct session;
struct evcb;

struct dnsbl * dnsbl_new(const char *);

void *      dnsbl_dispatch(void *);
int         dnsbl_submit(struct dnsbl *, struct session *);
int         dnsbl_response(struct session **, struct dnsbl *);
int         dnsbl_init(void);
void        dnsbl_free(struct dnsbl *);

#endif  /* _DNSBL_H */
