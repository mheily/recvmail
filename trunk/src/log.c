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

#include <execinfo.h>

#include "log.h"

/* Maximum number of stack frames to print in a backtrace */
#define BACKTRACE_MAX 20

static char *_ident;

int detached = 0;
int log_level = LOG_INFO;
int log_is_open = 0;

void
log_open(const char *ident, int option, int facility, int level)
{
    /* Make a permanent copy of the "ident" string */
    if ((_ident = strdup(ident)) == NULL)
        abort();

    openlog(_ident, LOG_NDELAY | LOG_PID | option, facility);
    setlogmask(LOG_UPTO(level));
    
    log_level = level;
    log_is_open = 1;
}

void
log_close(void)
{
    closelog();
    free(_ident);
    _ident = NULL;
}

void
log_backtrace(void)
{
  void *buf[BACKTRACE_MAX];
  size_t len, i;
  char **strings;

  len = backtrace(buf, BACKTRACE_MAX);
  strings = backtrace_symbols(buf, len);

  /* This should never happen. */
  if (len == 0)
      return;

  if (!detached) {
    fprintf(stderr, "\nstack backtrace:\n");
    for (i = 1; i < len; i++)
        fprintf(stderr,"  %zu: %s\n", i, strings[i]);
    fprintf(stderr, "\n");
  } else {
     /* TODO: integrate with syslog */
     log_warning("STUB");
  }

  free(strings);
}
