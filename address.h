/*		$Id: recvmail.h 115 2009-02-11 02:04:10Z mheily $		*/

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
#ifndef _ADDRESS_H
#define _ADDRESS_H

#include "queue.h"

/* Maximum length of an email address, including NUL */
#define MAIL_ADDRSTRLEN     130

struct mail_addr {
    char   *local_part, 
           *domain;
    LIST_ENTRY(mail_addr) entries;
};

int             domain_exists(const struct mail_addr *);

struct rfc2822_addr *rfc2822_addr_new();
struct mail_addr * address_parse(const char *src);
void            address_free(struct mail_addr *addr);
char * address_get(char *dst, size_t len, struct mail_addr *src);
int             valid_address(const struct rfc2822_addr *addr);
int             valid_domain(const char *domain);

#endif  /* _ADDRESS_H */
