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
#include <ctype.h>

static int smtpd_parse_command(struct session *, char *, size_t);
static int smtpd_parse_data(struct session *, char *, size_t);

/* Test if we accept mail for a given domain */
static inline int
relay_domain(const char *req)
{
    char **p;

    for (p = OPT.domains; *p != NULL; p++) {
        if (strcasecmp(*p, req) == 0) {
            return (0);
        }
    }

    return (-1);
}

static int
smtpd_helo(struct session *s, const char *arg)
{
    log_debug("HELO=`%s'", arg);
    session_printf(s, "250 %s\r\n", OPT.mailname);
    return (0);
}


static int
smtpd_ehlo(struct session *s, const char *arg)
{
    log_debug("EHLO=`%s'", arg);
    session_printf(s, "250-%s\r\n"
                    "250-PIPELINING\r\n"
                    "250 8BITMIME\r\n" 
                    , OPT.mailname);
    return (0);
}


static int
smtpd_mail(struct session *s, const char *arg)
{
    if (s->msg->sender != NULL)
        free(s->msg->sender);
    if ((s->msg->sender = address_parse(arg)) == NULL) {
            session_println(s, "501 Malformed address");
            return (-1);
    }
    session_println(s, "250 Ok");
    return (0);
}


static int
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

    buf = strdup(line); //fixme: errhandling

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

    /* Check if we accept mail for this domain */
    if (relay_domain(ma->domain) != 0) {
        session_println(s, "551 Relay access denied");
        goto errout;
    }

    /* Add the address to recipient list */
    LIST_INSERT_HEAD(&s->msg->recipient, ma, entries);
    s->msg->recipient_count++;
    session_println(s, "250 Ok");

    free(buf);
    return (0);

errout:
    free(buf);
    address_free(ma);
    return (-1);
}


static int
smtpd_data(struct session *s, const char *arg)
{
    log_debug("DATA arg=%s", arg);

    if (s->msg->recipient_count == 0) {
        session_println(s, "503 Error: need one or more recipients first");
        return (-1);
    }
    if (maildir_msg_open(s->msg)) {
        session_println(s, "421 Error creating message");
        session_close(s);
        return (-1);
    }
    session_println(s, "354 End data with <CR><LF>.<CR><LF>");
    s->smtp_state = SMTP_STATE_DATA;
    return (0);
}

static int
smtpd_rset(struct session *s)
{
    if (s->msg != NULL) {
        s->msg->recipient_count = 0;
        message_free(s->msg);
        if ((s->msg = message_new()) == NULL) {
            session_println(s, "421 Out of memory error");
            session_close(s);
            return (-1);
        }
        s->msg->session = s;
    }

    s->smtp_state = SMTP_STATE_MAIL;
    session_println(s, "250 Ok");
    return (0);
}

static int
smtpd_noop(struct session *s)
{
    session_println(s, "250 Ok");
    return (0);
}

static int
smtpd_quit(struct session *s)
{
    session_println(s, "221 Bye");
    session_close(s);
    return (0);
}

void
smtpd_parser(struct session *s)
{
    struct iovec *iov;
    int i, rv;

    iov = s->in_buf.sb_iov;

    /* Pass control to the 'command' or 'data' subparser */
    for (i = 0; i < s->in_buf.sb_iovlen; i++) {
        if (s->smtp_state != SMTP_STATE_DATA) {
            // XXX-FIXME assumes len >0
            memset(iov[i].iov_base + iov[i].iov_len - 1, 0, 1);     /* Replace LF with NUL */
            log_debug("CMD=`%s'", (char *) iov[i].iov_base);
            rv = smtpd_parse_command(s, iov[i].iov_base, iov[i].iov_len - 1);
        } else {
            rv = smtpd_parse_data(s, iov[i].iov_base, iov[i].iov_len);
        }

        if (rv != 0) 
            s->errors++;

        /* TODO: make configurable, max_errors or something */
        if (s->errors > 10) {
            s->srv->reject_hook(s);
            session_close(s);
        }
    }

}

static int
smtpd_parse_command(struct session *s, char *src, size_t len)
{
    size_t          i;
    int             c;

    /* SMTP commands must be at least four characters plus the trailing NUL */
    if (len < 4) {
            session_println(s, "502 Illegal command");
            return (-1);
    }

    /* 
     * Test for invalid ASCII characters. 
     * SMTP commands must be 7-bit clean with no control characters.
     */
    for (i = 0; i < len; i++) {
        c = src[i];
        if (c < 32 || c > 127) {
            log_debug("illegal character at position %zu", i);
            session_println(s, "502 Illegal request");
            return -1;
        }
    }

    /* Parse the command and call the associated function */
    switch (toupper(src[0])) {
        case 'D': if (strcasecmp(src, "DATA") == 0)
                      return (smtpd_data(s, NULL));
                  break;

        case 'E': if (strncasecmp(src, "EHLO ", 5) == 0)
                      return (smtpd_ehlo(s, src + 5));
                  break;

        case 'H': if (strncasecmp(src, "HELO ", 5) == 0)
                      return (smtpd_helo(s, src + 5));
                  break;

        case 'M': if (strncasecmp(src, "MAIL FROM:", 10) == 0)
                      return (smtpd_mail(s, src + 10));
                  break;

        case 'N': if (strcasecmp(src, "NOOP") == 0)
                      return (smtpd_noop(s));
                  break;

        case 'Q': if (strcasecmp(src, "QUIT") == 0)
                      return (smtpd_quit(s));
                  break;

        case 'R': if (strncasecmp(src, "RCPT TO:", 8) == 0)
                      return (smtpd_rcpt(s, src + 8));
                  if (strcasecmp(src, "RSET") == 0)
                      return (smtpd_rset(s));
                  break;
    }

    session_println(s, "502 Error: invalid command");
    return (-1);
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
static int
smtpd_parse_data(struct session *s, char *src, size_t len)
{
    /* If the line is '.', end the data stream */
    if ((len == 2) && strncmp(src, ".\n", 2) == 0) {

        /* TODO : set state to SMTP_STATE_FSYNC and call syncer */

        /* Deliver the message immediately */
        if (maildir_msg_close(s->msg) < 0) {
            log_error("maildir_msg_close()");
            goto error;
        }

        /* Allow the sender to pipeline another request */
        smtpd_rset(s);
        return (0);
    }

    /* Ignore a leading '.' if there are additional characters */
    if (strncmp(src, ".", 1) == 0) {
        len--;
        src++;
    }

    /* XXX-FIXME use writev(2) to write multiple lines in one syscall. */
    /* Write the line to the file */
    if (atomic_write(s->msg->fd, src, len) < len) {
        log_errno("atomic_write(3)");
        goto error;
    }

    return (0);

  error:
    session_println(s, "452 Error spooling message, try again later");
    session_close(s);
    return (0);
}



int
smtpd_greeting(struct session *s)
{
#ifdef XXX_FIXME_DEADWOOD
    // dont do this until the envelope is accepted [see: spam]
    //
    /* Create a message object */
    if ((s->msg = message_new()) == NULL) {
        log_error("message_new()");
        goto err421;
    } else {
        s->msg->session = s;
    }
#endif

    /* Send the initial greeting */
    session_printf(s, "220 %s recvmail/%s\r\n", OPT.mailname, VERSION);

    return (0);
}



void
smtpd_accept(struct session *s)
{
    if ((s->msg = message_new()) == NULL) {
        errx(1,"FIXME: error handling (memfree)");
    }
    s->msg->session = s;
    smtpd_greeting(s);
    session_become_reader(s);
}

void
smtpd_timeout(struct session *s)
{
    session_println(s, "421 Idle time limit exceeded, goodbye");
}

void
smtpd_client_error(struct session *s)
{
    session_println(s, "421 Too many errors");
}

void
smtpd_close(struct session *s)
{
    message_free(s->msg);
}
