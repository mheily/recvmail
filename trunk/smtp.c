/*      $Id: $      */

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


static int
smtpd_helo(struct session *s, char *arg)
{
    session_printf(s, "250 %s\r\n", OPT.mailname);
    return 0;
}


static int
smtpd_ehlo(struct session *s, char *arg)
{
    session_printf(s, "250-%s\r\n"
                    "250-PIPELINING\r\n"
                    "250 8BITMIME\r\n" 
                    , OPT.mailname);
    return 0;
}


static int
smtpd_mail(struct session *s, char *arg)
{

    if (s->data->msg->sender != NULL)
        free(s->data->msg->sender);
    if ((s->data->msg->sender = addr_parse(arg)) == NULL) {
            session_println(s, "501 Malformed address");
            return -1;
    }
    session_println(s, "250 Ok");
    return 0;
}


int
smtpd_rcpt(struct session *s, char *line)
{
    struct rfc2822_msg *msg;
    char *addr;
    struct recipient *rcpt;

    msg = s->data->msg;

    if ((addr = addr_parse(line)) == NULL) {
    session_println(s, "501 Invalid address syntax");
    return -1;
    }

    if ((rcpt = recipient_find(addr)) == NULL) {
        free(addr);
        session_println(s, "550 Mailbox unavailable");
        return -1;
    }
    free(addr);

    /* Limit the number of recipients per envelope */
    if (msg->num_recipients > RECIPIENT_MAX) {
    session_println(s, "503 Error: Too many recipients");
    return -1;
    }

    /* Require 'MAIL FROM' before 'RCPT TO' */
    if (msg->sender == NULL) {
    session_println(s, "503 Error: need MAIL command first");
    return -1;
    }

    /* Everything is OK, add the recipient */
    msg->rcpt_to[msg->num_recipients++] = rcpt;
    session_println(s, "250 Ok");

    return 0;
}


static int
smtpd_data(struct session *s, char *arg)
{
    if (s->data->msg->num_recipients == 0) {
            session_println(s, "503 Error: need one or more recipients first");
    return -1;
    } else {
    if (maildir_msg_open(s->data->msg)) {
        session_println(s, "421 Error creating message");
        session_close(s);
        return -1;
    }
    session_println(s, "354 End data with <CR><LF>.<CR><LF>");
    s->data->smtp_state = SMTP_STATE_DATA;
    return 0;
    }
}


static int
smtpd_rset(struct session *s, char *arg)
{
    s->data->num_recipients = 0;
    rfc2822_msg_free(s->data->msg);
    if ((s->data->msg = rfc2822_msg_new()) == NULL) {
            session_println(s, "421 Out of memory error");
            session_close(s);
            return 0;
    }
    s->data->smtp_state = SMTP_STATE_MAIL;
    session_println(s, "250 Ok");
    return 0;
}

static int
smtpd_noop(struct session *s, char *arg)
{
    session_println(s, "250 Ok");
    return 0;
}

static int
smtpd_quit(struct session *s, char *arg)
{
    session_println(s, "221 Bye");
    session_close(s);
    return 0;
}


int
smtpd_parse_command(struct session *s, char *src, size_t len)
{
    size_t          i,
                    cmd_len;
    int             c;
    char           *cp;
    static const char *cmd[9] = {
    "HELO", "EHLO", "MAIL FROM:", "RCPT TO:",
    "DATA", "RSET", "NOOP", "QUIT"
    };
    static int      (*func[]) (struct session *, char *) = {
    smtpd_helo, smtpd_ehlo, smtpd_mail, smtpd_rcpt,
        smtpd_data, smtpd_rset, smtpd_noop, smtpd_quit,};

    /* 
     * Test for invalid ASCII characters. 
     * SMTP commands must be 7-bit clean with no control characters.
     */
    for (i = 0; i < len; i++) {
    c = src[i];
    if (c < 32 || c > 127) {
        log_debug("Syntax error: illegal character(s)");
        session_println(s, "502 Illegal request");
        return -1;
    }
    }

    /* Test for a valid command name */
    for (i = 0; i < 9; i++) {
    cmd_len = strlen(cmd[i]);
    if (strncasecmp(src, cmd[i], cmd_len) != 0)
        continue;

    /* Parse the parameter */
    if (len > cmd_len) {
        cp = src + cmd_len;
    } else {
        cp = "";
    }

    syslog(LOG_DEBUG, "method = `%s', options = `%s'", cmd[i], cp);
    return func[i] (s, cp);
    }

    session_println(s, "502 Error: command not implemented");
    return -1;
}


/*
 * parse_smtp_data(msg, src, len)
 *
 * Parse a line of SMTP data and append it to the message.
 *
 * Returns:   0 if EOF reached, 1 if more data to be read,
 *            or -1 if an error occurred
 *
 */
int
smtpd_parse_data(struct session *s, char *src, size_t len)
{
    int             offset = 0;

    /* If the line is '.', end the data stream */
    if ((len == 1) && strncmp(src, ".", 1) == 0) {

    /* TODO : set state to SMTP_STATE_FSYNC and call syncer */

    /* Deliver the message immediately */
    if (maildir_msg_close(s->data->msg) < 0)
        goto error;

    /* Allow the sender to pipeline another request */
    smtpd_rset(s, "");
    return 0;
    }

    /* Ignore a leading '.' if there are additional characters */
    if (strncmp(src, ".", 1) == 0)
    offset = 1;

    /* Write the line and a trailing newline to the file */
    if ((rfc2822_msg_write(s->data->msg, src + offset, len - offset) < 0)
    || (rfc2822_msg_write(s->data->msg, "\n", 1) < 0)) {
    goto error;
    }

    return 0;

  error:
    session_println(s, "452 Error spooling message, try again later");
    session_close(s);
    return 0;
}



int
smtpd_greeting(struct session *s)
{
    /* Allocate memory for the session data */
    if ((s->data = calloc(1, sizeof(struct session_data))) == NULL ||
    (s->data->msg = rfc2822_msg_new()) == NULL) {
    session_println(s, "421 Internal server error");
    session_close(s);
    return 0;
    }
    s->data->msg->remote_addr = s->remote_addr;

    /* Send the initial greeting */
    session_printf(s, "220 %s recvmail/%s\r\n", OPT.mailname, VERSION);
    return 0;
}


int
smtpd_parser(struct session *s, char *buf, size_t len)
{
    /* Pass control to the 'command' or 'data' subparser */
    if (s->data->smtp_state != SMTP_STATE_DATA)
    return smtpd_parse_command(s, buf, len);
    else
    return smtpd_parse_data(s, buf, len);
}

void
smtpd_timeout(struct session *s)
{
    session_println(s, "421 Idle time limit exceeded, goodbye");
}

void
smtpd_client_error(struct session *s)
{
    session_println(s, "421 Too many unrecognized commands");
}

int
smtpd_close_hook(struct session *s)
{
    rfc2822_msg_free(s->data->msg);
    free(s->data);
    return 0;
}

int
smtpd_monitor_hook(struct server *srv, pid_t child)
{
    for (;;) {
    /* FIXME */
    pause();
    }
}

int
smtpd_start_hook(struct server *srv)
{
    return 0;
}

