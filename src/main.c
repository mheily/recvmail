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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "recvmail.h"

/* TODO: eliminate this struct */
struct options  OPT = {
    .debugging = 0,
    .daemon = 1,
    .uid = "recvmail",
    .port = 0,
    .log_ident = "recvmail",
    .log_level = LOG_INFO,
    .log_facility = LOG_MAIL,
};

int
main(int argc, char *argv[])
{
    if (server_init(argc, argv, &SMTP) < 0)
        errx(1, "server initialization failed");

    dispatch_main();
#if DEADWOOD
    if (server_dispatch() < 0) {
        if (!detached) 
            fprintf(stderr, "Abnormal program termination.\n");
        exit(EXIT_FAILURE);
    }
#endif

    /* NOTREACHED */
    exit (EXIT_SUCCESS);
}
