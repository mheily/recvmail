/*		$Id: $		*/

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

#include "recvmail.h"
#include "hash.h"

struct alias_entry {
    char    *name;
    size_t   namelen;
    char    *addr;
    size_t   addrlen;
    LIST_ENTRY(alias_entry) entries;
    HASH_ENTRY(alias_entry) hashent;
};

LIST_HEAD(,alias_entry) aliases;
HASH_HEAD(,alias_entry) alias_map;

struct alias_entry *
aliases_lookup(const char *name)
{
    struct alias_entry *ae;

    HASH_LOOKUP(ae, name, &alias_map, name, hashent);
    return (ae);
}

static void
aliases_add(const char *name, const char *addr)
{
    struct alias_entry *ae;

    if ((ae = calloc(1,sizeof(*ae))) == NULL)
        err(1, "malloc(3)");
    ae->name = strdup(name);
    ae->namelen = strlen(name);
    ae->addr = strdup(addr);
    ae->addrlen = strlen(addr);

    LIST_INSERT_HEAD(&aliases, ae, entries);
    HASH_INSERT(&alias_map, ae, name, hashent);
}

void
aliases_parse(const char *path)
{
    FILE *f;
    char *p, *name, *addr;
    char buf[8192];
    size_t len;
    int count;

    count = 0;

    if ((f = fopen(path, "r")) == NULL)
        err(1, "unable to open the aliases file");

    do {
        /* Get a line of text */
        if (fgets(buf, sizeof(buf), f) == NULL) {
            if (ferror(f))
                err(1, "error reading aliases file");
            break;
        }
        len = strlen(buf);

        /* Remove the newline */
        if (len > 0) {
            buf[--len] = '\0';
        }

        /* Remove comments */
        if ((p = strchr(buf, '#')) != NULL) {
            *p = '\0';
            len = strlen(buf);
        }

        /* Skip blank lines and split the line at the delimiter */
        if ((p = strchr(buf, ':')) == NULL) {
            continue;
        }
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        name = buf;
        addr = p;

        /*log_debug("buf='%s' name='%s' addr='%s'", buf, name, addr);*/

        aliases_add(name, addr);
        count++;
    } while (! feof(f));

    /*log_debug("loaded %d aliases", count);*/
    if (fclose(f) != 0)
        err(1, "fclose(2) of aliases");
}

void
aliases_init(void)
{
    LIST_INIT(&aliases);
    HASH_INIT(&alias_map);
}
