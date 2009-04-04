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

// FIXME - needed to get asprintf decl in stdio.h
#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "address.h"
#include "atomic.h"
#include "message.h"
#include "session.h"
#include "options.h"
#include "log.h"

static int
path_exists(const char *path)
{
    if (access(path, W_OK) < 0) {
        if (errno == ENOENT) {
            return (0);
        } else {
            log_errno("access(2) of `%s'", path);
            return (-1);
        }
    }

    return (1);
}

static int 
maildir_get_path(char *buf, size_t n, const struct mail_addr *ma)
{
    if (snprintf(buf, n, "box/%s/%s", ma->domain, ma->local_part) >= n) {
        log_error("mailbox name too long");
        return (-1);
    }

    return (0);
}

int
domain_exists(const struct mail_addr *ma)
{
    char buf[PATH_MAX];

    if (snprintf((char *) &buf, sizeof(buf), "box/%s",
                ma->domain) >= sizeof(buf)) {
        log_error("mailbox name too long");
        return (-1);
    }

    return (path_exists((char *) &buf));
}

int
maildir_exists(const struct mail_addr *ma)
{
    char buf[PATH_MAX];

    if (maildir_get_path((char *) &buf, sizeof(buf), ma) != 0)
        return (-1);

    return (path_exists((char *) &buf));
}

/* Generate a unique ID suitable for delivery to a Maildir */
char *
maildir_generate_id(int worker_id, unsigned long delivery_counter)
{
    char *buf;
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    if (asprintf(&buf, "%lu.M%luP%uT%u_%lu.%s", 
			    tv.tv_sec, 
			    tv.tv_usec,
			    getpid(),
                worker_id,
			    delivery_counter,
			    OPT.mailname) < 0) {
	    log_warning("asprintf(3)");
	    return (NULL);
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
    char           *buf = NULL;

    if (LIST_EMPTY(&msg->recipient)) {
    	log_warning("cannot deliver a message with no recipients");
        return (-1);
    }

    /* Generate the message pathname */
    if (asprintf(&msg->path, "spool/tmp/%s", msg->filename) < 0)
        return -1;

    /* Try to open the message file for writing */
    /* NOTE: O_EXCL may not work on older NFS servers */
    msg->fd =
	open(msg->path, O_CREAT | O_APPEND | O_WRONLY | O_EXCL, 00660);
    if (msg->fd < 0) {
	log_errno("open(2) of `%s'", msg->path);
	return -1;
    }

    /* XXX-FIXME: put a Return-Path header at the top */

    /* Prepend the local 'Received:' header */
    time(&now);
    gmtime_r(&now, &timeval);
    asctime_r(&timeval, timestr);
    len = asprintf(&buf,
            "Received: from %s (%s [%s])\n"
            "        by %s (recvmail) ; %s",
            msg->helo, 
            msg->session->remote_name,
            remote_addr(in_addr, sizeof(in_addr), msg->session), 
            OPT.mailname, 
            timestr);
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


int
maildir_deliver(struct message *msg)
{
    char prefix[PATH_MAX];
    char dest[PATH_MAX];

    struct mail_addr *ma;

    LIST_FOREACH(ma, &msg->recipient, entries) {
        if (maildir_get_path((char *) &prefix, sizeof(prefix), ma) != 0) {
            log_error("prefix too long");
            goto errout;
        }
        if (snprintf((char *) &dest, sizeof(dest), "%s/new/%s",
                    (char *) &prefix, msg->filename) >= sizeof(dest)) {
            log_error("path too long");
            goto errout;
        }
        if (link(msg->path, dest) != 0) {
            log_errno("link(2) of `%s' to `%s'", msg->path, dest);
            goto errout;
        }
    }

    /* Delete the spooled message */
    if (unlink(msg->path) != 0) {
            log_errno("unlink(2) of `%s'", msg->path);
            goto errout;
    }
#if FIXME
    //this seems dangerous
    message_free(msg);
    free(msg->path);
    msg->path = NULL;
#endif

    return (0);

errout:
    /* Try to "undeliver" the message */
    LIST_FOREACH(ma, &msg->recipient, entries) {
        log_warning("XXX-fixme todo");
    }
    return (-1);
}

/**
 * Close the file descriptor associated with <msg>
 *
 * Modifies: msg->path
 */
int
message_close(struct message *msg)
{
    char *path = NULL;

    /* Close the file */
    if (atomic_close(msg->fd) < 0) {
        log_errno("atomic_close(3)");
        goto error;
    }

    /* Generate the new/ pathname */
    if (asprintf(&path, "spool/new/%s", msg->filename) < 0) {
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
