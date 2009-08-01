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
#ifndef _LOG_H
#define _LOG_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

extern int detached;
extern int log_level;
extern int log_is_open;
// XXX-fixme - convert OPT.log_level to log_level

#define _log_all(level, format,...) do {                                    \
    if (log_is_open)                                                        \
        syslog(level, format, ## __VA_ARGS__);                              \
    if (!detached && log_level >= level)                                    \
        fprintf(stderr, "%10s:%-5d %-18s" format "\n",                      \
                 __FILE__, __LINE__, __func__, ## __VA_ARGS__);             \
} while (/*CONSTCOND*/0)

#define log_error(format,...)   _log_all(LOG_ERR, "**ERROR** "format, ## __VA_ARGS__)
#define log_warning(format,...) _log_all(LOG_WARNING, "WARNING: "format, ## __VA_ARGS__)
#define log_notice(format,...)  _log_all(LOG_NOTICE, format, ## __VA_ARGS__)
#define log_info(format,...)    _log_all(LOG_INFO, format, ## __VA_ARGS__)
#define log_errno(format,...)   _log_all(LOG_ERR, format": %s (errno=%d)", ## __VA_ARGS__, strerror(errno), errno)

#ifndef NDEBUG
#define log_debug(format,...)   _log_all(LOG_DEBUG, format, ## __VA_ARGS__)
#else
#define log_debug(format,...)   do { } while (/*CONSTCOND*/0)
#endif

/* Emulate macros from <err.h> but use syslog logging instead of stderr */
/* TODO: make variadic functions instead */

#define err(rc,format,...) do {						                        \
    if (detached)                                                           \
        log_errno(format, ## __VA_ARGS__);					                \
    else                                                                    \
        fprintf(stderr, "ERROR: " format "\n", ## __VA_ARGS__);             \
   exit(rc);								                                \
} while (0)

#define errx(rc,format,...) do {					                        \
    if (detached)                                                           \
       log_error(format, ## __VA_ARGS__);					                \
    else                                                                    \
        fprintf(stderr, "ERROR: " format "\n", ## __VA_ARGS__);             \
    exit(rc);								                                \
} while (0)

void log_open(const char *, int, int, int);
void log_close(void);

#endif  /* _LOG_H */