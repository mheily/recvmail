/*      $Id$      */
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
 * A hash table contains 4096 buckets that uses 16K of memory 
 * on a 32-bit machine.
 */ 
#define HASH_BITS	(12)
#define HASH_SIZE	(0x1 << HASH_BITS)

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
	LIST_HEAD(, type) hh_keys;                                          \
	LIST_HEAD(, type) hh_values[HASH_SIZE];                             \
}

#define HASH_ENTRY(type)                                                \
struct {                                                                \
    LIST_ENTRY(type)  he_keys;                                          \
    LIST_ENTRY(type)  he_values;                                        \
}

#define HASH_REMOVE(elm, field) do {                                    \
    LIST_REMOVE((elm)->field, he_keys);                                 \
    LIST_REMOVE((elm)->field, he_values);                               \
} while (/*CONSTCOND*/0)

#define HASH_BUCKET(head, str)  (&(head)->hh_values[HASH_FUNC(str)])

#define HASH_INIT(head) do {                                            \
    LIST_INIT(&(head)->hh_keys);                                        \
    memset(&(head)->hh_values, 0, sizeof((head)->hh_values));           \
} while (/*CONSTCOND*/0)

#define HASH_INSERT(head, elm, cdata, field) do {                       \
    LIST_INSERT_HEAD(head.hh_keys, (elm), field.he_keys);               \
    LIST_INSERT_HEAD(HASH_BUCKET((head), (elm)->cdata), elm, field.he_values);    \
} while (/*CONSTCOND*/0)

#define HASH_LOOKUP(elm, str, head, cdata, field)                       \
    for((elm) = HASH_BUCKET((head), str)->lh_first;                   \
        (elm) && (strcmp((str), (elm)->cdata) != 0);                    \
        (elm) = (elm)->field.he_values.le_next)

#define HASH_FOREACH(var, head, field)                                  \
    LIST_FOREACH(var, head.hh_keys, field.he_keys)

#endif  /*  hash.h  */
