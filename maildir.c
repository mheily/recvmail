/*		$Id: $		*/

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


/**
 *
 * Generate a unique ID suitable for delivery to a Maildir
 */
static int
maildir_generate_id(char **dest)
{
	static uint32_t delivery_counter = 0;
	struct timeval tv;

	gettimeofday(&tv,NULL);

	/* Increment the delivery counter and rollover at 1,000,000 */
	if (delivery_counter++ > 999999)
		delivery_counter = 0;

	return asprintf(dest, "%lu.M%luP%u_%d.%s", tv.tv_sec, tv.tv_usec,
				getpid(),
				delivery_counter, OPT.mailname);
}
  

/*
 * open_message(message_t *msg);
 *
 * Open a file descriptor to receive the data of <msg>.
 *
 * Modifies: msg->fd, msg->id, msg->path
 *
 */
int
maildir_msg_open(struct rfc2822_msg *msg)
{
	time_t          now;
	struct tm	timeval;
	char		timestr[64];
	ssize_t          len;
	char *buf = NULL;

	/* Generate the message pathname */
	if (maildir_generate_id(&msg->filename) < 0)
		return -1;
	if (asprintf(&msg->path, "spool/tmp/%s", msg->filename) < 0)
		return -1;

	/* Try to open the message file for writing */
	/* NOTE: O_EXCL may not work on older NFS servers */
	msg->fd = open(msg->path, O_CREAT | O_APPEND | O_WRONLY | O_EXCL, 00660);
	if (msg->fd < 0) {
		log_errno("open(2) of `%s'", msg->path);
		return -1;
	}

	/* Prepend the local 'Received:' header */
	time(&now);
 	gmtime_r(&now, &timeval);
 	asctime_r(&timeval, timestr);
	len = asprintf(&buf, "Received: from %s@%s ([%s])\n        by %s (recvmail) on %s",
			msg->sender->user,
			msg->sender->domain,
			msg->remote_addr_str,
			OPT.mailname,
			timestr
		 );
	if ((len < 0) || rfc2822_msg_write(msg, buf, len) < 0)  {
		free(buf);
		return -1;
	}

	free(buf);
	return 0;
}


struct rfc2822_msg *
rfc2822_msg_new()
{
	struct rfc2822_msg * msg;

	msg = calloc(1, sizeof(struct rfc2822_msg));
	if (!msg)
		return NULL;

	if ((msg->sender = rfc2822_addr_new()) == NULL) {
		free(msg);
		return NULL;
	}

	return msg;
}

void
rfc2822_msg_free(struct rfc2822_msg * msg)
{
	int i;

	if (msg) {
		free(msg->path);
		rfc2822_addr_free(msg->sender);
		for (i = 0; i < msg->num_recipients; i++) 
			rfc2822_addr_free(msg->rcpt_to[i]);
		free(msg->filename);
		free(msg);
	}
}

/**
 * Write <len> bytes of <line> to the <message> file descriptor (or buffer).
 *
 * Returns: 0 if the operation succeded, -1 if there was an error.
 *
 */
int
rfc2822_msg_write(struct rfc2822_msg *msg, const char *src, size_t len)
{
	/* write(2) to the file descriptor */
	if ( write(msg->fd, src, len) < len ) {
		log_errno("write(2)");
		return -1;
	}

	msg->size += len;

	return 0;
}


/**
 * Close the file descriptor associated with <msg>
 *
 * Modifies: msg->path
 */
int
rfc2822_msg_close(struct rfc2822_msg *msg)
{
	char   *path = NULL;
	int	i;

	/* Close the file */
	if (close(msg->fd) < 0) {
		log_errno("close(2)");
		return -1;
	}

	/* Move the message into the 'new/' directory */
	if (asprintf(&path, "%s/new/%s", msg->rcpt_to[0]->path, msg->filename) < 0) 
		goto error;
	if (rename(msg->path, path) < 0) {
		log_errno("rename(2) of `%s' to `%s'", msg->path, path);
		(void) unlink(msg->path);
		goto error;
	}
	free(msg->path);
	msg->path = path;
	path = NULL;

	/* For each additional recipient, create a hard link */
	for (i = 1; i < msg->num_recipients; i++) {
		free(path);
		if (asprintf(&path, "%s/new/%s", 
					msg->rcpt_to[0]->path, 
					msg->filename) < 0) {
			goto error;
		}
		if (link(msg->path, path) < 0) {
			/* TODO: unlink previous attempts */
			log_errno("link(2) of `%s' to `%s'", msg->path, path);
			goto error;
		}
	}

	free(path);
	return 0;

error:
	free(path);
	return -1;
}
