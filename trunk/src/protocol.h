/*		$Id: session.h 243 2009-05-09 04:01:39Z mheily $		*/

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

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

struct session;

struct protocol {
    int     (*getopt_hook)(const char *, const char *);
    int     (*sanity_hook)(void);
    int     (*init_hook)(void); /* FIXME - server startup */
    int     (*shutdown_hook)(void);             /* server shutdown */
    int     (*reload_hook)(void); /* TODO - Reload configuration files */
    void    (*timeout_hook)(struct session *); /* session timeout */
    int     (*accept_hook)(struct session *); /* Called after accept(2) */
    void    (*close_hook)(struct session *); /* Called prior to close(2) for a session */
    void    (*abort_hook) (struct session *); /* Fatal internal error */
    /* Sends a 'too many errors' message to a misbehaving client before
     * closing */
    //DEADWOOD:void            (*reject_hook) (struct session *);
};

#endif /* _SESSION_H */
