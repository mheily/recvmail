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

#ifndef _SESSION_H
#define _SESSION_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "queue.h"

struct message;
struct socket;
struct session;
struct protocol;

struct session * session_new(int, struct protocol *, void (*)(void *, int));
void             session_free(struct session *s);

int     session_read(struct session *);
int     session_readln(struct session *s);
int     session_printf(struct session *, const char *, ...);
int     session_println(struct session *, const char *);
void    session_close(struct session *);
void    session_event_handler(struct session *, int);

int     session_table_init(void);
int     session_table_lookup(struct session **, unsigned long);

int     session_handler_push(struct session *, int (*)(struct session *));
int     session_handler_pop(struct session *);

void *  session_data_get(const struct session *);
void    session_data_set(struct session *, const void *);
void    session_buffer_get(const struct session *, char **, size_t *);
void    session_timeout_set(struct session *, time_t);
void    session_resume(struct session *);

const struct socket * session_get_socket(struct session *);
unsigned long session_get_id(struct session *);

#endif /* _SESSION_H */
