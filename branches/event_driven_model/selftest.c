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

#include "recvmail.h"

#define test(func,...) if (func(__VA_ARGS__) != 0) errx(1, "%s", "func failed")
#define testnull(func,...) if (func(__VA_ARGS__) == NULL) errx(1, "%s", "func failed")
void
run_testsuite()
{
    struct mail_addr *addr;

    if ((addr = address_parse("hi@bye.com")) == NULL)
        errx(1, "address_parse() failed");

    test(strcmp, addr->local_part, "hi");
    test(strcmp, addr->domain, "bye.com");
    address_free(addr);

    printf("+OK\n");
}
