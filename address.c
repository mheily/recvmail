/*		$Id: $		*/

/*
 * Copyright (c) 2004-2007 Mark Heily <devel@heily.com>
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

#include "recvmail.h"

#include <dirent.h>
#include <stdio.h>


/* Private global variables */

/* Recipient lookup table */
static struct recipient *RCPT = NULL;
static size_t RCPT_COUNT = 0;

/**
 * Parse an Internet mail address.
 *
 * Takes an RFC2822 email address (<foo@bar.com>) and validates it, returning
 * the canonical address or NULL if invalid.
 *
 * Returns: 0 if success, -1 if error
 *
 */
char *
addr_parse(const char *src)
{
    char *buf, *p;

    /* Remove leading whitespace and '<' bracket */
    for (; *src == ' ' || *src == '<'; src++);	

    buf = strdup(src);

    /* Ignore any trailing whitespace and additional options */
    if ((p = strchr(buf, ' ')) != NULL)
	memset(p, 0, 1);
    if ((p = strchr(buf, '>')) != NULL)
	memset(p, 0, 1);

    log_debug("parsed %s as `%s'", src, buf);

    return buf;
}


struct recipient *
recipient_add(const char *addr, const char *path)
{
	struct recipient *r;

	if ((r = malloc(sizeof(*r))) == NULL)
		err(1, "malloc(3)");

	r->addr_len = strlen(addr);
	if (r->addr_len > ADDRESS_MAX)
		errx(1, "address too long");

	strncpy((char *) &r->addr, addr, sizeof(r->addr));
	r->path = strdup(path);

	if (!r->path)
		err(1, "strdup(3)");

	HASH_ADD_STR(RCPT, addr, r);
	RCPT_COUNT++;

	return r;
}

struct recipient *
recipient_find(const char *addr)
{
	struct recipient *r;
	HASH_FIND_STR(RCPT, addr, r);
	return r;
}

void
recipient_dump_all(struct recipient **dest)
{
	struct recipient *r;

	for (r=RCPT; r != NULL; r = r->hh.next) {
		printf("%s\n", (char *) &r->addr);
	}
}

