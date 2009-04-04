/*		$Id: recvmail.h 115 2009-02-11 02:04:10Z mheily $		*/

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
#ifndef _ALIASES_H
#define _ALIASES_H

#include "hash.h"
#include "queue.h"

struct alias_entry {
    char    *name;
    size_t   namelen;
    char    *addr;
    size_t   addrlen;
    LIST_ENTRY(alias_entry) entries;
    HASH_ENTRY(alias_entry) hashent;
};

struct alias_entry * aliases_lookup(const char *);
void aliases_parse(const char *);
void aliases_init(void);
void aliases_free(void);

#endif  /* _ALIASES_H */
