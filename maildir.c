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
#include "session.h"


/* Generate a unique ID suitable for delivery to a Maildir */
char *
maildir_generate_id(void)
{
    static unsigned long delivery_counter = 0;
    char *buf;
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    if (asprintf(&buf, "%lu.M%luP%u_%lu.%s", 
			    tv.tv_sec, 
			    tv.tv_usec,
			    getpid(),
			    delivery_counter++,
			    OPT.mailname) < 0) {
	    log_warning("asprintf(3)");
	    return NULL;
    }

	return (buf);
}


/*
 * Open a file descriptor to receive the data of <msg>.
 *
 * Modifies: msg->fd, msg->id, msg->path
 *
 */
int
maildir_msg_open(struct message *msg)
{
    time_t          now;
    struct tm       timeval;
    char            timestr[64];
    size_t          len;
    char            in_addr[INET_ADDRSTRLEN + 1];
    char            ma_addr[MAIL_ADDRSTRLEN + 1];
    char           *buf = NULL;

    if (LIST_EMPTY(&msg->recipient)) {
    	log_warning("cannot deliver a message with no recipients");
        return (-1);
    }

    /* Generate the message pathname */
    if ((msg->filename = maildir_generate_id()) == NULL)
        return -1;
    if (asprintf(&msg->path, "tmp/%s", msg->filename) < 0)
        return -1;

    /* Try to open the message file for writing */
    /* NOTE: O_EXCL may not work on older NFS servers */
    msg->fd =
	open(msg->path, O_CREAT | O_APPEND | O_WRONLY | O_EXCL, 00660);
    if (msg->fd < 0) {
	log_errno("open(2) of `%s'", msg->path);
	return -1;
    }

    /* Prepend the local 'Received:' header */
    time(&now);
    gmtime_r(&now, &timeval);
    asctime_r(&timeval, timestr);
    len = asprintf(&buf,
            "Received: from %s ([%s])\n        by %s (recvmail) on %s",
            address_get(ma_addr, sizeof(ma_addr), msg->sender),
            remote_addr(in_addr, sizeof(in_addr), msg->session), OPT.mailname, timestr);
    if (len < 0) {
        log_errno("asprintf(3)");
        goto errout;
    }

    /* Write the buffer to disk */
    if (atomic_write(msg->fd, buf, len) < len) {
        log_errno("atomic_write() failed");
        goto errout;
    }
    msg->size += len;

    free(buf);
    return (0);

errout:
    free(buf);
    return (-1);
}



/**
 * Close the file descriptor associated with <msg>
 *
 * Modifies: msg->path
 */
int
maildir_msg_close(struct message *msg)
{
    char *path = NULL;

    /* Close the file */
    if (atomic_close(msg->fd) < 0) {
        log_errno("atomic_close(3)");
        goto error;
    }

    /* Generate the new/ pathname */
    if (asprintf(&path, "new/%s", msg->filename) < 0) {
        log_errno("asprintf(3)");
        goto error;
    }

    /* Move the message into the 'new/' directory */
    if (rename(msg->path, path) < 0) {
        log_errno("rename(2) of `%s' to `%s'", msg->path, path);
        goto error;
    }

    /* Update msg->path to point at the new location */
    free(msg->path);
    msg->path = path;

    log_debug("message delivered to %s", msg->path);

    return (0);

  error:
    free(path);
    (void) unlink(msg->path);
    return (-1);
}
