/*		$Id: pop3.c 53 2007-01-13 23:50:04Z mark $		*/

/*
 *               pop3.c - POP3 protocol (RFC 1939, RFC 2449)
 *
 * Copyright (c) 2004, 2005, 2006, 2007 Mark Heily <devel@heily.com>
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

#if TODO
#include "folder.h"
#include "mailbox.h"
#endif


/**************************** PRIVATE FUNCTIONS ************************/

static int
pop3_command_dele(struct session *s, char *arg)
{
#if FIXME
	string_t  *uid, *arg;
	uint32_t   msn = 0;

	/* Parse the message sequence number */
	list_get(arg, s->argv, 1);
	str_to_uint32(&msn, arg);

	/* Delete the message */
	if (folder_message_delete(s->data->mbox->folder, msn) < 0)
		throw_response(s, -1, "Unable to delete requested message");

	str_cpy(s->response.header, "Message deleted");
#endif
}


static int
pop3_command_retr(struct session *s, char *cmd, char *arg)
{
	unsigned int  num = 0,
	              max_lines = 0;
	message_t	*msg;
	string_t    *line_ptr, *arg;
	list_t      *lines;
	size_t          count   = 0;

	/* Parse the message number */
	if (sscanf(arg, "%u %u", &num, &max_lines) < 1) {
		print_response(s, "-ERR Syntax error");
		return -1;
	}
		
	/* Validate input */
	/* Get the message object */
	if (folder_message_read(msg, s->data->mbox->folder, num) < 0)
		throw_response(s, POP3_RC_ERR, "Error retrieving message");

	//log_debug("hdr=`%s' body=`%s'", msg->headers->value, msg->body->value);

	/* Retrieve the list of message lines */
	message_get_lines(lines, msg);

	/* Send all lines unless the caller requests a limited number */
	if (max_lines > 0) {
		if (lines->count < max_lines)
			max_lines = lines->count;
	} else {
			max_lines = lines->count;
	}

	/* Send each line of the message, with byte stuffing */
	//OPTIMIZE: port to list_next() interface
	str_cpy(s->response.header, "message follows");
	foreach (line_ptr, lines) {

		/* Limit the lines to what the caller requested */
		if (max_lines > 0 && count++ >= max_lines)
			break;

		/* Byte-stuff the leading '.' character */
		if (str_ncmp(line_ptr, ".", 1) == 0)
			str_cat(s->response.body, ".");
		
		/* Send the line plus the line terminator */
		str_cat(s->response.body, line_ptr->value);
		str_cat(s->response.body, "\r\n");

	};

	/* Send a single '.' as the EOF marker */	
	str_cat(s->response.body, ".\r\n");
}


static inline int
pop3_command_top(struct session *s)
{
	return pop3_command_retr(s);
}


static int
pop3_command_list(struct session *s)
{
	string_t        *uniq, *arg, *buf;
	message_t	*msg;
	size_t         msn = 0;
	bool             uidl;
	list_t          *msgs;

	/* Determine if the command was called as UIDL */
	list_get(arg, s->argv, 0);
	uidl = (strcmp(arg->value, "UIDL") == 0);

	/* Update the list of messages */
	folder_stat(s->data->mbox->folder);

	str_cpy(s->response.header, "scan listing follows");

	/* Examine each message.. */
	foreach (uniq, s->data->mbox->folder->uniq) {
		msn++;

		/* @todo overkill; we only need the size & delete status */
		folder_message_read(msg, s->data->mbox->folder, msn);

		/* Skip messages marked for deletion */
		if (msg->flags.deleted)
			continue;
		
		if (uidl) {
			str_sprintf(buf, "%zu %s\r\n", msn, uniq->value);
		} else {
			str_sprintf(buf, "%zu %zu\r\n", msn, msg->size);
		}
		str_append(s->response.body, buf);
	}
	
	/* Send a single '.' to terminate the response. */
	str_cat(s->response.body, ".\r\n");
}


static int
pop3_command_stat(struct session *s)
{
	size_t    msg_size = 1024;     /** @todo  this is a workaround */
	size_t    msg_count = 0;

	folder_get_message_count(&msg_count, s->data->mbox->folder);
	str_sprintf(s->response.header, "%zu %zu", msg_count, msg_size);
}


static inline int
pop3_command_user(struct session *s)
{
	list_get(s->user, s->argv, 1);	
}


static int
pop3_command_pass(struct session *s)
{
	address_t *addr;
	string_t  *pass;
	bool       auth_ok;

	/* Parse the password */
	list_get(pass, s->argv, 1);

	/* Authenticate */
	session_authenticate(&auth_ok, s, s->user, pass);
	if (!auth_ok)
		throw_response(s, POP3_RC_ERR, "Password does not match");
	
	/** @todo  Support access to public mailboxes via POP3.
	   	Need to scrub the message headers and remove email addresses,
		and prohibit the DELE command
	if (s->data->mbox->public)
		throw_response(s, POP3_RC_ERR, "TODO - Public mailboxes not supported");
	*/

	/* Open the mailbox and select the INBOX folder */
	address_parse(addr, s->user);
	folder_open(s->data->mbox->folder, s->data->mbox, sys.default_folder_name);
	folder_stat(s->data->mbox->folder);
	folder_expunge(s->data->mbox->folder, false);

	s->protocol_state = POP3_STATE_TRANSACTION;	
}


static int
pop3_command_quit(struct session *s)
{
	require (s);

	/* Purge messages marked for deletion */
	if (s->data->mbox != NULL) {
		if (mailbox_purge(s->data->mbox) < 0)
			throw_response(s, POP3_RC_ERR, "Unable to delete messages");
	}
	
	s->protocol_state = POP3_STATE_QUIT;	
	s->session_state = SESSION_QUIT;	

	str_cpy(s->response.header, "Bye");
}


static int
pop3_command_not_implemented(struct session *s)
{
	print_response(s, "-ERR Not implemented");
}


static int
pop3_command_capa(struct session *s)
{
	print_response(s, "+OK Capability list follows\r\n"
			"PIPELINING\r\n"
			"UIDL\r\n"
			".");
}


/**************************** PUBLIC FUNCTIONS ************************/

int
pop3d_request_handler(struct session *s, char *command)
{
	char *arg;

	/* Parse the command */
	if ((arg = strchr(command, ' ')) != NULL) {
		*arg++ = '\0';
	}

	log_debug("POP3 state=%d cmd=`%s'", s->protocol_state, command);

	/* Execute commands which are valid in any state */
	if (strcasecmp(command, "CAPA") == 0) {
			pop3_command_capa(s);

	/* Execute commands specific to the AUTHORIZATION state */
	} else if (s->protocol_state == POP3_STATE_AUTHORIZATION) {
		if (strcasecmp(command, "USER") == 0) {
			pop3_command_user(s);

		} else if (strcasecmp(command, "PASS") == 0) {
			pop3_command_pass(s);

		} else if (strcasecmp(command, "QUIT") == 0) {
			pop3_command_quit(s);

		} else {
			throw_response(s, POP3_RC_ERR, "Unsupported command");
		}

	/* Execute commands specific to the TRANSACTION state */
	} else if (s->protocol_state == POP3_STATE_TRANSACTION) {
		if (strcasecmp(command, "STAT") == 0) {
			pop3_command_stat(s);

		} else if (strcasecmp(command, "UIDL") == 0) {
			pop3_command_list(s);

		} else if (strcasecmp(command, "RETR") == 0) {
			pop3_command_retr(s);
			
		} else if (strcasecmp(command, "DELE") == 0) {
			pop3_command_dele(s);

		} else if (strcasecmp(command, "LIST") == 0) {
			pop3_command_list(s);

		} else if (strcasecmp(command, "QUIT") == 0) {
			pop3_command_quit(s);
			
		} else if (strcasecmp(command, "TOP") == 0) {
			pop3_command_top(s);
			
		} else if (strcasecmp(command, "APOP") == 0) {
			pop3_command_not_implemented(s);

		} else if (strcasecmp(command, "NOOP") == 0) {
			;

		} else if (strcasecmp(command, "RSET") == 0) {
			mailbox_reset(s->data->mbox);

		} else {
			throw_response(s, POP3_RC_ERR, "Unsupported command");
		}
	}
}


int
pop3d_timeout(struct session *s)
{
	print_response(s, "-ERR Session timed out");
}

void
pop3d_greeting(struct session *s)
{
	print_response(s, "+OK POP3 server ready");
}

void
pop3d_client_error(struct session *s)
{
    print_response(s, "-ERR Too many errors, closing connection");
}
