/*		$Id: privsep.c 329 2009-08-25 00:53:21Z mheily $		*/

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>

#include "privsep.h"
#include "log.h"

struct privsep_context ps_ctx; 

int
privsep_init(void)
{
    int sockfd[2];
    memset(&ps_ctx, 0, sizeof(ps_ctx));

    /* Create a connected pair of full-duplex sockets for IPC */
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfd) < 0) {
        log_errno("socketpair(2)");
        return (-1);
    }
    ps_ctx.p_fd = sockfd[0];
    ps_ctx.np_fd = sockfd[1];

    /* Create a stream I/O handle for each socket descriptor */
    ps_ctx.p_fp = fdopen(ps_ctx.p_fd, "r+");
    ps_ctx.np_fp = fdopen(ps_ctx.np_fd, "r+");
    if ( ps_ctx.p_fp == NULL || ps_ctx.np_fp == NULL) {
        log_errno("fdopen(3)");
        return (-1);
    }

    return (0);
}
    
int
privsep_send(const char *buf)
{
    if (fputs(buf, ps_ctx.np_fp) == EOF) {
        log_error("fputs(3)");
        return (-1);
    }
    if (fflush(ps_ctx.np_fp) < 0) {
        log_errno("fputs(3)");
        return (-1);
    }
    return (0);
}

int
privsep_main(int (*cb)(const char *))
{
    char buf[1024];

    /* Process requests */
    for (;;) {
        log_warning("%d child %d id", ps_ctx.p_pid, getuid());
        if (fgets(&buf[0], sizeof(buf) - 1, ps_ctx.p_fp) == NULL)
            err(1, "fgets(3)");
        if (cb(&buf[0]) < 0) {
            log_error("callback returned error");
            break;
        }
    }

    fclose(ps_ctx.p_fp);

    return (0);
}
