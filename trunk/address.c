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

/*
 * Take an RFC2822 email address (<foo@bar.com>) and validates it, returning
 * the canonical address or NULL if invalid.
 */
struct mail_addr *
address_parse(const char *src) 
{
    char   local_part[64],
           domain[64];
    struct mail_addr *dst;
    char   *p;
    int     i;

    /* Initialize variables */
    if ((dst = calloc(1, sizeof(*dst))) == NULL) {
        log_errno("calloc(3)");
        return (NULL);
    }

    /* Remove leading whitespace and angle-bracket */
    while ((src[0] == ' ' ) || (src[0] == '<')) {
        src++;
    }

    /* KLUDGE: remove trailing angle-bracket */
    if ((p = strchr(src, '>')) != NULL) 
            *p = ' ';

    /* Split the string into two parts */
    /* XXX-FIXME - need to accept backslash-escaped and quoted strings */
    i = sscanf(src, " %63[a-zA-Z0-9_.+=%#?~^-]@%63[a-zA-Z0-9_.-] ", 
            local_part, domain);
    if (i < 2 || i == EOF) {
        log_debug("unable to parse address");
        goto errout;
    }
    //log_debug("parsed %s as [%s], [%s]", src, dest->user, dest->domain);

    /* Validate the address */
    if (local_part[0] == '\0' || domain[0] == '\0') {
        log_debug("invalid address: empty part not allowed");
        goto errout;
    }
    if (local_part[0] == '.' || domain[0] == '.') {
        log_debug("invalid address: leading dot not allowed");
        goto errout;
    }

    /* Copy the buffers to persistent storage */
    if ((dst->local_part = strdup(local_part)) == NULL) {
        log_errno("strdup(3)");
        goto errout;
    }
    if ((dst->domain = strdup(domain)) == NULL) {
        log_errno("strdup(3)");
        goto errout;
    }

    return (dst);

errout:
    address_free(dst);
    return (NULL);
}

void
address_free(struct mail_addr *ma)
{
    if (ma != NULL) {
        free(ma->local_part);
        free(ma->domain);
        free(ma);
    }
}

/* dst should be sized MAIL_ADDRSTRLEN or more */
char *
address_get(char *dst, size_t len, struct mail_addr *src)
{
    int i;

    i = snprintf(dst, len, "%s@%s", src->local_part, src->domain);
    if (i < 0 || i >= len) {
        log_errno("snprintf(3)");
        return (NULL);
    }

    return (dst);
}
