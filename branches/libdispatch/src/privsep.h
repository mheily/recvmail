/*		$Id: privsep.h 243 2009-05-09 04:01:39Z mheily $		*/

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

#ifndef _PRIVSEP_H
#define _PRIVSEP_H

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

/* TODO: This is only needed by server.c, make an accessor function.. */
struct privsep_context {
    /* Priviliged */
    pid_t  p_pid;
    int    p_fd;
    FILE  *p_fp;

    /* Non-Priviliged */
    pid_t  np_pid;
    int    np_fd;
    FILE  *np_fp;
};
extern struct privsep_context ps_ctx; 

int privsep_send(const char *);
int privsep_init(void);
int privsep_main(int (*)(const char *));

#endif /* _PRIVSEP_H */