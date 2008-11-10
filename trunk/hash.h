/*      $Id: hash.h 5 2008-10-13 00:07:57Z mheily $      */
/*
 * Copyright (c) 2008 Mark Heily <devel@heily.com>
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

#ifndef _HASH_H_
#define _HASH_H_

#include <string.h>
#include <sys/queue.h>

/* 
 * The default is a hash table with 4096 buckets that uses 16K of memory.
 * This can be overridden in each translation unit by defining
 * HASH_BITS prior to including this header file.
 */ 
#ifndef HASH_BITS
#define HASH_BITS	(12)
#endif
#define HASH_SIZE	(2 ^ HASH_BITS)

/* Based on the public domain Jenkins one-at-a-time hashing algorithm */
static inline unsigned int
HASH_FUNC(const char *key)
{
    unsigned int hash = 0;
    size_t key_len = strlen(key);
    size_t i;
 
    for (i = 0; i < key_len; i++) {
        hash += (unsigned char) key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return (hash >> (32 - HASH_BITS));
}

#define HASH_HEAD(name, type)                                           \
struct name {                                                           \
	LIST_HEAD(, type) hh_table[HASH_SIZE];                              \
}

#define HASH_ENTRY              LIST_ENTRY 
#define HASH_REMOVE             LIST_REMOVE
#define HASH_BUCKET(head, str)  (&((head)->hh_table[HASH_FUNC(str)]))

#define HASH_INIT(head)                                                 \
    memset((head)->hh_table, 0, sizeof(*((head)->hh_table)))

#define HASH_INSERT(head, elm, cdata, field)                            \
    LIST_INSERT_HEAD(HASH_BUCKET((head), (elm)->cdata), elm, field)

#define HASH_LOOKUP(elm, str, head, cdata, field)                       \
    for((elm) = HASH_BUCKET((head), str)->lh_first;                     \
        (elm) && (strcmp((str), (elm)->cdata) != 0);                    \
        (elm) = (elm)->field.le_next)

#endif  /*  hash.h  */
