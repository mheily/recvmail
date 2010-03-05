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

#include "recvmail.h"
#include "tree.h"

struct client {
    RB_ENTRY(client) entry;
    in_addr_t addr;
    u_int   concurrent;     /* Number of concurrent connections */
    u_int   running_total;  /* Total number of connections */
    u_int   errors;         /* Total number of "bad" connections */
    time_t  last_attempt;   /* The last time the client attempted to connect */
    time_t  lockout;        /* The time the client is locked out (0=no lockout) */
};

static int
addr_cmp(struct client *s1, struct client *s2)
{
    return (s1->addr < s2->addr ? -1 : s1->addr > s2->addr);
}

RB_HEAD(client_tree, client) throttle = RB_INITIALIZER(&throttle);
RB_GENERATE(client_tree, client, entry, addr_cmp);

static struct client *
client_new(in_addr_t addr)
{
    struct client *c;

    if ((c = calloc(1, sizeof(*c))) == NULL)
            return (NULL);
    c->addr = addr;
    c->last_attempt = time(NULL);
    RB_INSERT(client_tree, &throttle, c);
    return (c);
}

static struct client *
client_lookup(in_addr_t addr)
{
    struct client  query;
    struct client *res;

    query.addr = addr;
    res = RB_FIND(client_tree, &throttle, &query);
    return (res);
}

static int
client_connect(in_addr_t addr)
{
    struct client *c;

    if ((c = client_lookup(addr)) != NULL) {
        c->concurrent++;
        c->running_total++;
        c->last_attempt = time(NULL);
        return (0);
    } else {
        c = client_new(addr);
        return (c != NULL ? 0 : -1);
    }
}

void
throttle_disconnect(in_addr_t addr)
{
    struct client *c;

    if ((c = client_lookup(addr)) != NULL) {
        c->concurrent--;
    } else {
        log_error("invalid throttle table");
    }
}

void
throttle_error(in_addr_t addr)
{
    struct client *c;

    if ((c = client_lookup(addr)) != NULL) {
        c->errors++;
    } else {
        log_error("invalid throttle table");
    }
}

#if TODO
// taken from resolver.c, modify for throttling
static void
cache_expire_all(void *unused)
{
    struct node *var, *nxt;
    time_t now;

    now = time(NULL);

    /* Remove stale entries from the A record cache */
    for (var = RB_MIN(a_tree, &forward); var != NULL; var = nxt) {
        nxt = RB_NEXT(a_tree, &forward, var);
        if (now > var->expires) {
            RB_REMOVE(a_tree, &forward, var);
            node_free(var);
        }
    }

    /* Remove stale entries from the PTR record cache */
    for (var = RB_MIN(ptr_tree, &reverse); var != NULL; var = nxt) {
        nxt = RB_NEXT(ptr_tree, &reverse, var);
        if (now > var->expires) {
            RB_REMOVE(ptr_tree, &reverse, var);
            node_free(var);
        }
    }
}
#endif
   
int
throttle_connect(in_addr_t addr)
{
    /* Failsafe: allow the connection when the throttle table is full */
    if (client_connect(addr) < 0)
        return (0);

    /* TODO: test connection for allow / reject. return -1 to reject */

    return (0);
}

int
throttle_init(void)
{
#if TODO
    //enable when function is complete
    update_timer = poll_timer_new(60 * 30, cache_expire_all, NULL);
    if (update_timer == NULL)
        return(-1);
#endif

    return (0);
}
