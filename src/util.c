/*		$Id: workqueue.c 228 2009-04-28 02:59:31Z mheily $		*/

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

#include <sys/stat.h>

#include "recvmail.h"

int
file_exists(const char *path)
{
    struct stat sb;

    if (stat(path, &sb) != 0) {
        /* TODO: if (errno != ENOENT) abort ? hang and retry ? */
        return (0);
    }

    return (1);
}

ssize_t
file_read(char **bufp, const char *path)
{
    struct stat sb;
    char *buf;
    int fd;

    if ((fd = open(path, O_RDONLY)) < 0) {
        log_errno("open(2) of `%s'", path);
        goto errout;
    }
    if (stat(path, &sb) != 0) {
        log_errno("stat(2) of `%s'", path);
        goto errout;
    }
    if (sb.st_size >= (INT_MAX - 1)) {
        log_error("file %s is too large", path);
        goto errout;
    }
    if ((buf = malloc(sb.st_size + 1)) == NULL) {
        log_errno("malloc(3)");
        goto errout;
    }
    if (read(fd, buf, sb.st_size) < sb.st_size) {
        log_errno("read(2)");
        free(buf);
        goto errout;
    }
    if (close(fd) < 0) {
        log_errno("close(2)");
        free(buf);
        goto errout;
    }

    buf[sb.st_size] = '\0';
    *bufp = buf;
    return (sb.st_size);

errout:
    *bufp = NULL;
    return (-1);
}

