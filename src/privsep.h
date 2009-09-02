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
#include <unistd.h>

struct privsep_context {
    /* Priviliged */
    pid_t  p_pid;
    int    p_fd;

    /* Non-Priviliged */
    pid_t  np_pid;
    int    np_fd;
};

struct priv_op {
    unsigned int r[8];  /* pseudo-registers */
};

extern struct privsep_context ps_ctx; 

int privsep_send(unsigned int);
int privsep_init(void);
int privsep_main(int (*)(void));

#endif /* _PRIVSEP_H */
