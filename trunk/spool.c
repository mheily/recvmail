/*		$Id: $		*/

/*
 * Copyright (c) 2007 Mark Heily <devel@heily.com>
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

/*
 * TODO: add a counter prefix that indicates the number of
 * times the daemon has been started on the current host.
 * this allows for clock skew
 */
static int
spool_generate_id(char **dest)
{
    static uint32_t delivery_counter = 0;

    /* Increment the delivery counter and rollover at 1,000,000,000 */
    if (delivery_counter++ > 999999999)
	delivery_counter = 0;

    return asprintf(dest, "%lX%X", time(NULL), delivery_counter);
}


/*
 * Open a file descriptor to receive the data of <msg>.
 *
 * Modifies: msg->fd, msg->id, msg->path
 */
int
msg_spool(struct rfc2822_msg *msg)
{
    time_t          now;
    struct tm       timeval;
    char            timestr[64];
    size_t          len;
    char           *buf = NULL;

    /* Generate the message pathname */
    if (spool_generate_id(&msg->filename) < 0)
	return -1;
    if (asprintf(&msg->path, "spool/%s", msg->filename) < 0)
	return -1;

    /* Try to open the message file for writing */
    /* NOTE: O_EXCL may not work on older NFS servers */
    msg->fd = open(msg->path, O_CREAT | O_WRONLY | O_EXCL, 00660);
    if (msg->fd < 0) {
	log_errno("open(2) of `%s'", msg->path);
	return -1;
    }

    /* Prepend the local 'Received:' header */
    time(&now);
    gmtime_r(&now, &timeval);
    asctime_r(&timeval, timestr);
    len =
	asprintf(&buf,
		 "Received: from %s@%s ([%s])\n        by %s (recvmail) on %s",
		 msg->sender->user, msg->sender->domain,
		 msg->remote_addr_str, OPT.mailname, timestr);
    if ((len < 0) || rfc2822_msg_write(msg, buf, len) < 0) {
	free(buf);
	return -1;
    }

    free(buf);
    return 0;
}
