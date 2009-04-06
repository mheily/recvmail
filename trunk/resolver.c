/*		$Id: dnsbl.c 187 2009-04-05 05:16:59Z mheily $		*/

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

#define NDEBUG

/* to get EAI_NODATA */
#define _GNU_SOURCE 

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "compat/tree.h"
#include "log.h"

/* Cache DNS lookups for 30 minutes by default. */
#define DEFAULT_TTL     (60 * 30)

struct node {
    RB_ENTRY(node) entry;
    in_addr_t addr;
    char     *name;
    time_t    expires;
};

static int
addr_cmp(struct node *e1, struct node *e2)
{
    return (e1->addr < e2->addr ? -1 : e1->addr > e2->addr);
}

static int
name_cmp(struct node *e1, struct node *e2)
{
    return (strcmp(e1->name, e2->name));
}

RB_HEAD(a_tree, node) forward = RB_INITIALIZER(&head);
RB_GENERATE(a_tree, node, entry, name_cmp);

RB_HEAD(ptr_tree, node) reverse = RB_INITIALIZER(&head);
RB_GENERATE(ptr_tree, node, entry, addr_cmp);

static struct node *
node_new(const char *name, in_addr_t addr)
{
    struct node *n;

    if ((n = calloc(1, sizeof(*n))) == NULL)
            return (NULL);
    n->name = strdup(name);
    n->addr = addr;
    n->expires = time(NULL) + DEFAULT_TTL;

    return (n);
}

static void
node_free(struct node *n)
{
    free(n->name);
    free(n);
}


static struct node *
cache_lookup_addr(const char *name)
{
    struct node  query;
    struct node *res;

    query.name = (char *) name;
    res = RB_FIND(a_tree, &forward, &query);
    if (res == NULL)
        return (NULL);

    if (res->expires <= time(NULL)) {
        log_debug("expiring stale cache entry");
        RB_REMOVE(a_tree, &forward, res);
        node_free(res);
        return (NULL);
    }

    return (res);
}

static struct node *
cache_lookup_name(in_addr_t addr)
{
    struct node  query;
    struct node *res;

    query.addr = addr;
    res = RB_FIND(ptr_tree, &reverse, &query);
    if (res == NULL)
        return (NULL);

    if (res->expires <= time(NULL)) {
        RB_REMOVE(ptr_tree, &reverse, res);
        node_free(res);
        return (NULL);
    }

    return (res);
}

static int
cache_add_addr(const char *name, in_addr_t addr)
{
    struct node *n;

    if ((n = node_new(name, addr)) == NULL)
        return (-1);

    RB_INSERT(a_tree, &forward, n);

    return (0);
}

static int
cache_add_name(in_addr_t addr, const char *name)
{
    struct node *n;

    if ((n = node_new(name, addr)) == NULL)
        return (-1);

    RB_INSERT(ptr_tree, &reverse, n);

    return (0);
}

int
resolver_lookup_addr(in_addr_t *dst, const char *src)
{
    struct node *n;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct sockaddr_in *sain;
    int rv;

    /* Check the cache */
    if ((n = cache_lookup_addr(src)) != NULL) {
        log_debug("cache hit");
        *dst = n->addr;
        return (0);
    }
    log_debug("cache miss");

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo(src, NULL, &hints, &ai);

    if (rv == 0) {
        sain = (struct sockaddr_in *) ai->ai_addr;
        *dst = sain->sin_addr.s_addr;
        freeaddrinfo(ai);
    } else if (rv == EAI_NONAME || rv == EAI_NODATA) {
        /* Treat a negative response as one that returned 0.0.0.0 */
        log_debug("lookup failed: %s", src);
        *dst = 0;
    } else {
        log_errno("getaddrinfo(3) of `%s' returned %d", src, rv);
        return (-1);
    }

    return (cache_add_addr(src, *dst));
}

int
resolver_lookup_name(char **dst, const in_addr_t src)
{
    struct node *n;
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    struct sockaddr_in sain;
    int rv;

    /* Check the cache */
    if ((n = cache_lookup_name(src)) != NULL) {
        log_debug("cache hit");
        *dst = n->name;
        return (0);
    }
    log_debug("cache miss");

    sain.sin_family = AF_INET;
    sain.sin_addr.s_addr = src;
    rv = getnameinfo((struct sockaddr *) &sain, sizeof(sain),
            host, sizeof(host), serv, sizeof(serv), NI_NAMEREQD);

    if (rv == 0) {
        if (cache_add_name(src, (char *) &host) < 0) {
            log_error("cache_add_name() failure");
            return (-1);
        }
        return (resolver_lookup_name(dst, src));
    } else if (rv == EAI_NONAME || rv == EAI_NODATA) {
        log_debug("lookup failed: %s", src);
        if (cache_add_name(src, "") < 0) {
            log_error("cache_add_name() failure");
            return (-1);
        }
        return (resolver_lookup_name(dst, src));
    } else {
        log_errno("getnameinfo(3) of %d returned %d", src, rv);
        return (-1);
    }
}
