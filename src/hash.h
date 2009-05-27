/*          $Id$      */
/*
 * Copyright (c) 2008-09 Mark Heily <mark@heily.com>
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
 * The default hash table size is 2048 buckets which uses 8K of memory 
 * on a 32-bit machine.
 */ 
#define HASH_BITS	(11)
#define HASH_SIZE	(0x1 << HASH_BITS)

/* Based on the public domain Jenkins one-at-a-time hashing algorithm. */
#define HASH_FUNC(head, key, len) do {                                  \
    unsigned int hash = 0;                                              \
    size_t i;                                                           \
    for (i = 0; i < (len); i++) {                                       \
        hash += (unsigned char) key[i];                                 \
        hash += (hash << 10);                                           \
        hash ^= (hash >> 6);                                            \
    }                                                                   \
    hash += (hash << 3);                                                \
    hash ^= (hash >> 11);                                               \
    hash += (hash << 15);                                               \
    hash >>= (32 - HASH_BITS);                                          \
    (head)->hh_cur = (void *) &( (head)->hh_table[hash] );              \
} while (0)

#define HASH_HEAD(name, type)                                           \
struct name {                                                           \
	LIST_HEAD(, type)  hh_table[HASH_SIZE];                             \
    LIST_HEAD(, type) *hh_cur;                                          \
}

#define HASH_ENTRY              LIST_ENTRY 
#define HASH_REMOVE             LIST_REMOVE
#define HASH_FIRST(head)        ((void *) &(head)->hh_table[0])
#define HASH_LAST(head)         ((void *) &(head)->hh_table[HASH_SIZE - 1])

#define HASH_INIT(head)                                                 \
    memset((head), 0, sizeof(*(head)))

#define HASH_INSERT(head, elm, cdata, field) do {                       \
    HASH_FUNC(head, (elm)->cdata, strlen((elm)->cdata));                \
    LIST_INSERT_HEAD((head)->hh_cur, elm, field);                       \
} while (0)

#define HASH_LOOKUP(elm, str, head, cdata, field) do {                  \
    HASH_FUNC(head, str, strlen(str));                                  \
    for((elm) = LIST_FIRST((head)->hh_cur);                             \
        (elm) && (strcmp((str), (elm)->cdata) != 0);                    \
        (elm) = LIST_NEXT(elm, field)) {}                               \
} while (0)

#define HASH_FOREACH(elm, head, field)                                  \
    for((head)->hh_cur = HASH_FIRST(head);                              \
        (void *)(head)->hh_cur <= HASH_LAST(head);                      \
        (head)->hh_cur++)                                               \
           LIST_FOREACH(elm, (head)->hh_cur, field)

#endif  /* _HASH_H */
