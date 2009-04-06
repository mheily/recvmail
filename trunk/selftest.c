/*		$Id$		*/

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

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "resolver.h"
#include "log.h"

#define test(func,...) if (func(__VA_ARGS__) != 0) errx(1, "%s", "func failed")
#define testnull(func,...) if (func(__VA_ARGS__) == NULL) errx(1, "%s", "func failed")

void
test_resolver(void)
{
    in_addr_t addr, addr2;
    char *name;

    log_level = LOG_DEBUG;

    test(resolver_lookup_addr, &addr, "www.recvmail.org");
    assert(addr == 1001207877);

    /* Test the cache by looking up the same name again. */
    test(resolver_lookup_addr, &addr, "www.recvmail.org");
    assert(addr != addr2);

    /* Reverse lookup */
    test(resolver_lookup_name, &name, addr);
    assert(strcmp(name, "www.recvmail.org"));

    test(resolver_lookup_addr, &addr, "nonexistant.google.com");
    assert(addr == 0);

    test(resolver_lookup_addr, &addr, "nonexist.tld");
    assert(addr == 0);
}

int
main(int argc, char *argv[])
{
    test_resolver();

#if FIXME
    // need #includes
    struct mail_addr *addr;

    if ((addr = address_parse("hi@bye.com")) == NULL)
        errx(1, "address_parse() failed");

    test(strcmp, addr->local_part, "hi");
    test(strcmp, addr->domain, "bye.com");
    address_free(addr);
#endif


    printf("+OK\n");
    exit(0);
}
