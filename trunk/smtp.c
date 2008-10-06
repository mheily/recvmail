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
    if (s->msg->sender != NULL)
        free(s->msg->sender);
    if ((s->msg->sender = address_parse(arg)) == NULL) {
            session_println(s, "501 Malformed address");
            return -1;
    }
    session_println(s, "250 Ok");
    return 0;
}


int
smtpd_rcpt(struct session *s, char *line)
{
    char *p;
    char *buf = NULL;
    struct mail_addr *ma = NULL;

    /* Limit the number of recipients per envelope */
    if (s->msg->recipient_count > RECIPIENT_MAX) {
        session_println(s, "503 Error: Too many recipients");
        goto errout;
    }

    /* Require 'MAIL FROM' before 'RCPT TO' */
    if (s->msg->sender == NULL) {
        session_println(s, "503 Error: need MAIL command first");
        goto errout;
    }

    /* Remove leading whitespace and '<' bracket */
    for (; *line == ' ' || *line == '<'; line++);  

    buf = strdup(line);

    /* Ignore any trailing whitespace and additional options */
    /* FIXME - doesn't handle quoted whitespace */
    if ((p = strchr(buf, ' ')) != NULL)
        memset(p, 0, 1);
    if ((p = strchr(buf, '>')) != NULL)
        memset(p, 0, 1);

    if ((ma = address_parse(buf)) == NULL) {
        session_println(s, "501 Invalid address syntax");
        goto errout;
    }
  
    /* Add the address to recipient list */
    LIST_INSERT_HEAD(&s->msg->recipient, ma, entries);
    s->msg->recipient_count++;
    session_println(s, "250 Ok");

    free(buf);
    return 0;

errout:
    free(buf);
    free(ma);
    return (-1);
}


static int
smtpd_data(struct session *s, char *arg)
{
    if (s->msg->recipient_count == 0) {
            session_println(s, "503 Error: need one or more recipients first");
    return -1;
    } else {
    if (maildir_msg_open(s->msg)) {
        session_println(s, "421 Error creating message");
        session_close(s);
        return -1;
    }
    session_println(s, "354 End data with <CR><LF>.<CR><LF>");
    s->smtp_state = SMTP_STATE_DATA;
    return 0;
    }
}


static int
smtpd_rset(struct session *s, char *arg)
{
    s->msg->recipient_count = 0;
    message_free(s->msg);
    if ((s->msg = message_new()) == NULL) {
            session_println(s, "421 Out of memory error");
            session_close(s);
            return 0;
    }
    s->msg->session = s;
    s->smtp_state = SMTP_STATE_MAIL;
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
        if (atomic_close(s->msg->fd) < 0) {
            log_errno("atomic_close(3)");
            goto error;
        }

        /* Allow the sender to pipeline another request */
        smtpd_rset(s, "");
        return 0;
    }

    /* Ignore a leading '.' if there are additional characters */
    if (strncmp(src, ".", 1) == 0)
    offset = 1;

    /* Write the line and a trailing newline to the file */
    if ((atomic_write(s->msg->fd, src + offset, len - offset) < (len - offset))
            || (atomic_write(s->msg->fd, "\n", 1) < 1)) {
        log_errno("atomic_write(3)");
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
    /* Create a message object */
    if ((s->msg = message_new()) == NULL) {
        log_error("message_new()");
        goto err421;
    } else {
        s->msg->session = s;
    }

    /* Send the initial greeting */
    session_printf(s, "220 %s recvmail/%s\r\n", OPT.mailname, VERSION);

    return (0);

err421:
    session_println(s, "421 Internal server error");
    session_close(s);
    return (0);
}


int
smtpd_parser(struct session *s, char *buf, size_t len)
{
    /* Pass control to the 'command' or 'data' subparser */
    if (s->smtp_state != SMTP_STATE_DATA)
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
    message_free(s->msg);
    return 0;
}
