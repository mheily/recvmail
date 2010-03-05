/*		$Id$		*/

/*
 * Copyright (c) 2004-2009 Mark Heily <devel@heily.com>
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

#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>

#include "recvmail.h"

static int 
maildir_get_path(char *buf, size_t n, const struct mail_addr *ma)
{
    if (snprintf(buf, n, "box/%s/%s", ma->domain, ma->local_part) >= n) {
        log_error("mailbox name too long");
        return (-1);
    }

    return (0);
}

/* Generate a unique ID suitable for delivery to a Maildir */
/* TODO: make threadsafe or move to mda.c */
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
			    OPT.hostname) < 0) {
	    log_warning("asprintf(3)");
	    return NULL;
    }

	return (buf);
}


int
maildir_msg_open(struct message *msg, struct session *s)
{
    time_t          now;
    struct tm       timeval;
    char            timestr[64];
    size_t          len;
    char           *buf = NULL;

    if (LIST_EMPTY(&msg->recipient)) {
    	log_warning("cannot deliver a message with no recipients");
        return (-1);
    }

    /* Generate the message pathname */
    if ((msg->filename = maildir_generate_id()) == NULL)
        return (-1);
    if (asprintf(&msg->path, "spool/tmp/%s", msg->filename) < 0)
        return (-1);

    /* Try to open the message file for writing */
    /* NOTE: O_EXCL may not work on older NFS servers */
    msg->fd = open(msg->path, 
                   O_CREAT | O_APPEND | O_WRONLY | O_EXCL,
                   00660);
    if (msg->fd < 0) {
        log_errno("open(2) of `%s'", msg->path);
        return (-1);
    }

    /* Prepend the local 'Received:' header */
    time(&now);
    gmtime_r(&now, &timeval);
    asctime_r(&timeval, timestr);
    len = asprintf(&buf,
                   "Return-Path: %s\n"
                   "Received: from %s ([%s])\n"
                   "        by %s (recvmail) on %s",
                   msg->return_path,
                   msg->client,
                   socket_get_peername(session_get_socket(s)),
                   OPT.hostname,
                   timestr);
    if (len < 0) {
        log_errno("asprintf(3)");
        goto errout;
    }

    /* Write the buffer to disk */
    if (write(msg->fd, buf, len) < len) {
        log_errno("write(2)");
        goto errout;
    }
    msg->msg_size += len;

    free(buf);
    return (0);

errout:
    free(buf);
    return (-1);
}

/* Generate the full path to the destination message file for
   a delivery. */
static int
mkdestpath(char *buf, 
        size_t len, 
        const struct mail_addr *ma, 
        const struct message *msg)
{
    char prefix[PATH_MAX];

    /* Generate the path to the mailbox root */
    if (maildir_get_path((char *) &prefix, sizeof(prefix), ma) != 0) {
        log_error("prefix too long");
        return (-1);
    }

    /* Generate the path to the new/ message */
    if (snprintf(buf, len, "%s/new/%s,S=%zu",
                (char *) &prefix, msg->filename, msg->msg_size) >= len) {
        log_error("path too long");
        return (-1);
    }

    return (0);
}

int
maildir_deliver(struct message *msg)
{
    char dest[PATH_MAX];
    struct mail_addr *ma;
  
    /* Deliver to each SMTP recipient */
    LIST_FOREACH(ma, &msg->recipient, entries) {
      
        /* Generate the destination path */
        if (mkdestpath(&dest[0], sizeof(dest), ma, msg) < 0) {
            log_error("mkdestpath failed");
            goto errout;
        }

        /* Create a hard link to the message in spool/ */
        if (link(msg->path, dest) != 0) {
            log_errno("link(2) of `%s' to `%s'", msg->path, dest);
            goto errout;
        }
        
        /* TODO - flush dentry metadata to stable storage */
    }

    return (0);

errout:
    /* Try to "undeliver" the message */
    LIST_FOREACH(ma, &msg->recipient, entries) {
        if (mkdestpath(&dest[0], sizeof(dest), ma, msg) == 0) {
            (void) unlink(dest);
        } else {
            return (-1);
        }
    }
    return (-1);
}

int
maildir_create(const char *path)
{
    const char *fmt[] = { "%s", "%s/new", "%s/cur", "%s/tmp", NULL };
    char **p;
    char buf[PATH_MAX];

    for (p = (char **) fmt; *p != NULL; p++) {
        if (snprintf((char *) &buf, sizeof(buf), *p, path) >= sizeof(buf)) {
            log_error("name too long");
            return (-1);
        }
        if (mkdir(buf, 0770) != 0) {
            log_errno("mkdir(2) of `%s'", buf);
            return (-1);
        }
    }
    return (0);
}

int
message_close(struct message *msg)
{
    if (close(msg->fd) < 0) {
        log_errno("close(2)");
        return (-1);
    }
    msg->fd = -1;

    return (0);
}
