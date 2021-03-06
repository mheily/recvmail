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

#define DEBUG

#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <sys/socket.h>

#include "recvmail.h"
#include "tree.h"

/* Cache DNS lookups for 60 minutes by default. */
#define DEFAULT_TTL     (60 * 60)

/* Structure loosely based on RFC 1035 */
struct resource_rec {
	u_short	rr_class;              /* IN (Internet */
	u_short	rr_type;               /* ns_t_mx, etc. */
    u_int   rr_ttl;
    u_short rr_len;                
    u_short rr_pref;
    union {
        in_addr_t in_addr;
        //TODO : in6_addr;
        char *name;
    } rr_rdata;
};
 
/* Compare two resource records for sorting on the 'pref' field */
static int 
rr_cmp(const void *elem1, const void *elem2)
{
    const struct resource_rec *rec1 = elem1;
    const struct resource_rec *rec2 = elem2;

    return (rec1->rr_pref > rec2->rr_pref);
}


struct node {
    RB_ENTRY(node)   entry;
    int rec_type;
    union {
        in_addr_t   addr;
        /* TODO: struct in6_addr  addr; */
        char       *name;
    } key;
    union {
        in_addr_t   addr;
        /* TODO: struct in6_addr  addr; */
        char       *name;
        char      **name_list;
    } val;
    time_t           expires;
    int              negative;
};

static struct timer       *update_timer;

static int
node_cmp_name(struct node *e1, struct node *e2)
{
    return (strcmp(e1->key.name, e2->key.name));
}

static int
node_cmp_addr(struct node *e1, struct node *e2)
{
    return (memcmp(&e1->key.addr, &e2->key.addr, sizeof(e1->key.addr)));
}


RB_HEAD(a_tree, node)  a_cache = RB_INITIALIZER(&a_cache);
RB_GENERATE(a_tree, node, entry, node_cmp_name);

RB_HEAD(ptr_tree, node)  ptr_cache = RB_INITIALIZER(&ptr_cache);
RB_GENERATE(ptr_tree, node, entry, node_cmp_addr);

RB_HEAD(mx_tree, node)  mx_cache = RB_INITIALIZER(&mx_cache);
RB_GENERATE(mx_tree, node, entry, node_cmp_name);

static struct node *
cache_insert(int rec_type, const void *key, const void *val, u_int ttl)
{
    struct node *n;

    if ((n = calloc(1, sizeof(*n))) == NULL)
            return (NULL);
    n->expires = time(NULL) + ttl;
    n->rec_type = rec_type;
    if (val == NULL)
        n->negative = 1;
    switch (rec_type) {
        case ns_t_a:   
            if ((n->key.name = strdup((char *) key)) == NULL) {
                log_error("out of memory");
                goto errout;
            }
            if (!n->negative) 
                memcpy(&n->val, val, sizeof(in_addr_t));
            RB_INSERT(a_tree, &a_cache, n);
            break;

        case ns_t_mx:   
            if ((n->key.name = strdup((char *) key)) == NULL) { 
                log_error("out of memory");
                goto errout;
            }
            if (!n->negative) 
                n->val.name_list = (char **) val;
            RB_INSERT(mx_tree, &mx_cache, n);
            break;

        case ns_t_ptr:
            memcpy(&n->key, key, sizeof(in_addr_t));
            if (!n->negative && (n->val.name = strdup((char *) val)) == NULL) { 
                log_error("out of memory");
                goto errout;
            }
            RB_INSERT(ptr_tree, &ptr_cache, n);
            break;

        default:
            log_error("invalid node type");
            goto errout;
    }

    return (n);

errout:
    free(n);
    return (NULL);
}


static void
node_free(struct node *n)
{
    char **p;

    switch (n->rec_type) {
        case ns_t_a:   
            free(n->key.name);
            break;

        case ns_t_ptr:   
            if (!n->negative)
                free(n->val.name);
            break;

        case ns_t_mx:   
            free(n->key.name);
            if (!n->negative) {
                p = n->val.name_list;
                while (*p != NULL)
                    free(*p++);
                free(n->val.name_list);
            }
            break;

        default:
            log_error("invalid node type");
    }

    free(n);
}


static struct node *
cache_lookup(int rec_type, const void *key)
{
    struct node  query;
    struct node *res;

    query.rec_type = rec_type;
    switch (rec_type) {
        case ns_t_a:   
            query.key.name = (char *) key;
            res = RB_FIND(a_tree, &a_cache, &query);
            break;

        case ns_t_mx:   
            query.key.name = (char *) key;
            res = RB_FIND(mx_tree, &mx_cache, &query);
            break;

        case ns_t_ptr:   
            query.key.addr = *((in_addr_t *) key);
            res = RB_FIND(ptr_tree, &ptr_cache, &query);
            break;

        default:
            log_error("invalid node type");
            return (NULL);
    }

    return (res);
}


static void
cache_expire_all(void *unused)
{
    struct node *var, *nxt;
    time_t now;

    now = time(NULL);

    /* Remove stale entries from the DNS cache */
    for (var = RB_MIN(a_tree, &a_cache); var != NULL; var = nxt) {
        nxt = RB_NEXT(a_tree, &a_cache, var);
        if (now > var->expires) {
            RB_REMOVE(a_tree, &a_cache, var);
            node_free(var);
        }
    }
    for (var = RB_MIN(ptr_tree, &ptr_cache); var != NULL; var = nxt) {
        nxt = RB_NEXT(ptr_tree, &ptr_cache, var);
        if (now > var->expires) {
            RB_REMOVE(ptr_tree, &ptr_cache, var);
            node_free(var);
        }
    }
    for (var = RB_MIN(mx_tree, &mx_cache); var != NULL; var = nxt) {
        nxt = RB_NEXT(mx_tree, &mx_cache, var);
        if (now > var->expires) {
            RB_REMOVE(mx_tree, &mx_cache, var);
            node_free(var);
        }
    }
}

int
resolver_lookup_addr(in_addr_t *dst, const char *src, int flags)
{
    struct node *n;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct sockaddr_in *sain;
    int rv;

    /* Check the cache */
    if ((n = cache_lookup(ns_t_a, src)) != NULL) {
        log_debug("cache hit: neg=%d", n->negative);
        if (n->negative)
            *dst = 0;
        else
            *dst = n->val.addr;
        return (0);
    } else if (flags & RES_NONBLOCK) {
        *dst = 0;
        return (1);
    }
    log_debug("cache miss");

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo(src, NULL, &hints, &ai);

    if (rv == 0) {
        sain = (struct sockaddr_in *) ai->ai_addr;
        *dst = sain->sin_addr.s_addr;
        n = cache_insert(ns_t_a, src, dst, DEFAULT_TTL);
        freeaddrinfo(ai);
    } else if (rv == EAI_NONAME) {
	/* TODO: glibc also defines EAI_NODATA, should we care? */
        log_debug("lookup failed: %s", src);
        *dst = 0;
        n = cache_insert(ns_t_a, src, NULL, DEFAULT_TTL);
    } else {
        log_errno("getaddrinfo(3) of `%s' returned %d", src, rv);
        return (-1);
    }

    if (n == NULL)
        return (-1);

    return (0);
}

int
resolver_lookup_name(char **dst, const in_addr_t src, int flags)
{
    struct node *n;
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    struct sockaddr_in sain;
    int rv;

    /* Check the cache */
    if ((n = cache_lookup(ns_t_ptr, &src)) != NULL) {
        if (n->negative)
            *dst = "";
        else
            *dst = n->val.name;
        return (0);
    } else if (flags & RES_NONBLOCK) {
        *dst = NULL;
        return (1);
    }

    sain.sin_family = AF_INET;
    sain.sin_addr.s_addr = src;
    rv = getnameinfo((struct sockaddr *) &sain, sizeof(sain),
            host, sizeof(host), serv, sizeof(serv), NI_NAMEREQD);

    if (rv == EAI_NONAME) {
	/* TODO: glibc also defines EAI_NODATA, should we care? */
        host[0] = '\0'; 
    } else if (rv != 0) {
        log_errno("getnameinfo(3) of %d returned %d", src, rv);
        goto errout;
    }

    /* Add the result to the cache */
    n = cache_insert(ns_t_ptr, &src, &host, DEFAULT_TTL);
    if (n == NULL)
        goto errout;

    *dst = n->val.name;
    return (0);

errout:
    *dst = NULL;
    return (-1);
}

static int
dns_log_error(const char *domain, const char *message)
{
	size_t sz = PATH_MAX;
	char buf[PATH_MAX + 1];

	memset(&buf, 0, sizeof(buf));

	switch (h_errno) {
		case HOST_NOT_FOUND:
			(void) snprintf((char *) &buf, sz, "Host not found");
			break;
		case NO_DATA:
			(void) snprintf((char *) &buf, sz, "No records found");
			break;
		case TRY_AGAIN:
			(void) snprintf((char *) &buf, sz, "No response");
			break;
		default:
			(void) snprintf((char *) &buf, sz, "Unknown error");
		}

	/* Print an error message to the system log */
	log_error("%s: error: %s: %s\n", 
			message, (char *) &buf, domain);

    return (-1);
}


/* Based on the parsing techniques discussed at:
        http://www.woodmann.com/fravia/DNS.htm
 */
int
resolver_lookup_mx(char ***dst, const char *src, int flags)
{
	union {
		HEADER hdr;
		unsigned char buf[PACKETSZ];
	} response;
	HEADER	 	*hp;
	int	 	pkt_len, len;
	unsigned int	i, ancount;
	char 		buf[MAXDNAME + 1];
	unsigned char	*cp, *end;
    struct resource_rec *r;
    u_int ttl;
    char **res;
    struct node *n;

    /* Check the cache */
    if ((n = cache_lookup(ns_t_mx, src)) != NULL) {
        *dst = n->val.name_list;
        return (0);
    } else if (flags & RES_NONBLOCK) {
        *dst = NULL;
        return (1);
    }

	/* Initialize variables */
	memset(&buf, 0, sizeof(buf));
    r = NULL;
    ancount = 0;
    ttl = 1;

	/* Lookup the MX records for <domain> */
	pkt_len = res_query(src, C_IN, ns_t_mx, &response.buf[0], sizeof(response));
	if (pkt_len < 0) {
        dns_log_error(src, "MX lookup failed");
		return (-1);
    }
	if ((unsigned long) pkt_len > sizeof(response)) {
        log_error("DNS response too large");
        return (-1);
    }

	/* Move <cp> to the answer portion.. */
	
	/* Skip the header portion */
	hp = (HEADER *) &response;
	cp = (unsigned char *) &response + HFIXEDSZ;
	end = (unsigned char *) &response + pkt_len;

	/* Skip over each question */
	i = ntohs((unsigned short)hp->qdcount);
	while (i > 0) {
		if ((len = dn_skipname(cp, end)) < 0) {
			log_error("bad hostname in question portion of dns packet");
            return (-1);
        }

		cp += len + QFIXEDSZ;
		i--;
	}

	/* Process each answer */
	ancount = ntohs((unsigned short)hp->ancount);
    if (ancount > 100) {
        log_error("too many answers");
        return (-1);
    }
    log_error("ancount=%d", ancount);
    r = calloc(ancount, sizeof(*r));
    if (r == NULL) {
        log_error("out of memory");
        return (-1);
    }
    for (i = 0; i < ancount; i++) {
        len = -1;
        len = dn_expand((unsigned char *) &response, end, cp, (char *) &buf, sizeof(buf) - 1);
        if (len < 0) {
            log_error("error expanding hostname in answer portion");
            goto errout;
        }
        if (strncmp(buf, src, strlen(src) + 1) != 0) {
            log_error("extraneous response");
            goto errout;
        }

		/* Jump to the record type */
		cp += len;
		
		/* Check the record type */
		GETSHORT(r->rr_type, cp);
		if (r->rr_type != ns_t_mx) {
			log_error("bad response record: expecting type MX");
            goto errout;
        }
        GETSHORT(r->rr_class, cp);
        GETLONG(r->rr_ttl, cp);
		GETSHORT(r->rr_len, cp);
		GETSHORT(r->rr_pref, cp);
		//log_error("mx pref == %d", r->rec_pref);

        /* Update the TTL */
        if (r->rr_ttl > ttl)
            ttl = r->rr_ttl;

		/* Decode the MX hostname */
		len = -1;
		len = dn_expand((unsigned char *) &response, end, cp,
				(char *) &buf, sizeof(buf) - 1);
		if (len < 0) {
			log_error("error decompressing RR");
            goto errout;
        }

        r->rr_rdata.name = strdup(buf);
        if (r->rr_rdata.name < 0) {
            log_error("out of memory");
            goto errout;
        }
        //log_warning("%s", buf);

		/* Jump to the next record */
		cp += len;
        r++;
	}

    r -= ancount;

	/* Sort the resulting MX list by priority */
    qsort(r, ancount, sizeof(*r), rr_cmp);

    /* TODO - lookup the A record as a fallback if there are no MX records */

    /* Generate a NUL-terminated array of strings with the answer. */
    res = calloc(ancount + 1, sizeof(char *));
    for (i = 0; i < ancount; i++) {
        res[i] = r->rr_rdata.name;
    /* FIXME - perform an A record lookup on each returned name to ensure
       that the name is cached. */
        r++; // LAME
    }
    r -= ancount;
    free(r);
    
    /* Cache the result */
    n = cache_insert(ns_t_mx, src, res, ttl);
    if (n == NULL) {
        free(res);
        goto errout;
    }

    *dst = n->val.name_list;
    return (0);

errout:
    while (ancount > 0) {
        ancount--;
        free(r->rr_rdata.name);
        r++;
    }
    free(r);
    return (-1);
}


int
resolver_init(void)
{
    struct addrinfo hints;
    struct addrinfo *ai;
    int rv;

    if (res_init() < 0) {
        log_errno("res_init()");
        return (-1);
    }

#if DEADWOOD

//self-testing

    char **ans;
    int i;
    if (resolver_lookup_mx(&ans, "heily.com", RES_NONBLOCK) != 1)
        errx(1, "nonblocking resolver_lookup_mx() failed");
    if (resolver_lookup_mx(&ans, "heily.com", 0) != 0)
        errx(1, "resolver_lookup_mx() failed");
    for (i = 0; ans[i] != NULL; i++) {
        log_warning("%s", ans[i]);
    }
    if (resolver_lookup_mx(&ans, "yahoo.com", 0) != 0)
        errx(1, "resolver_lookup_mx() failed");
    if (resolver_lookup_mx(&ans, "heily.com", RES_NONBLOCK) != 0)
        errx(1, "nonblocking resolver_lookup_mx() failed (2)");

    char *name;
    in_addr_t addr;

    if (resolver_lookup_addr(&addr, "www.recvmail.org", RES_NONBLOCK) != 1)
        errx(1, "nonblocking resolver_lookup_addr() failed");
    if (resolver_lookup_addr(&addr, "www.recvmail.org", 0) < 0)
        errx(1, "resolver_lookup_addr() failed");
    if (resolver_lookup_addr(&addr, "www.recvmail.org", RES_NONBLOCK) != 0)
        errx(1, "nonblocking resolver_lookup_addr() failed 2");
    if (resolver_lookup_name(&name, addr, RES_NONBLOCK) != 1)
        errx(1, "nonblocking resolver_lookup_name() failed");
    if (resolver_lookup_name(&name, addr, 0) < 0)
        errx(1, "resolver_lookup_name() failed");
    if (resolver_lookup_name(&name, addr, RES_NONBLOCK) != 0)
        errx(1, "nonblocking resolver_lookup_name() failed 2");

    log_error("tests ok");
    abort();
#endif

    /* Set a timer to periodically purge the cache of expired entries */
    update_timer = poll_timer_new(DEFAULT_TTL, cache_expire_all, NULL);
    if (update_timer == NULL)
        return(-1);

    /* Ensure that libresolv.so is loaded prior to chroot(2) */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rv = getaddrinfo("www.recvmail.org", NULL, NULL, &ai);
    freeaddrinfo(ai);
    if (rv == EAI_NONAME) {
        log_warning("DNS resolution failed -- check your DNS configuration and network connectivity");
        return (0);
    } else if (rv != 0) {
        log_error("DNS resolution failed: internal resolver error");
        return (-1);
    }

    return (0);
}
