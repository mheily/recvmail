/*      $Id$      */

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

#include <ctype.h>
#include <limits.h>

#include "atomic.h"
#include "log.h"
#include "options.h"
#include "message.h"
#include "session.h"
#include "server.h"
#include "smtp.h"

/* Response to HELO and EHLO */
static char smtp_helo_greeting[HOST_NAME_MAX + 8];
static char smtp_ehlo_greeting[HOST_NAME_MAX + 512];

#define RECIPIENT_MAX		100

#define PUTS(s,c) bufferevent_write((s)->buf_ev, c"\r\n", sizeof(c) + 2)

/* FIXME - put this somewhere else */
/* From aliases.c */

void            aliases_init(void);
void            aliases_parse(const char *);
struct alias_entry * aliases_lookup(const char *name);

/* FIXME - put this somewhere else */
/* From maildir.h */

int             maildir_msg_open(struct message *msg);
int             open_message(struct message *msg);
int             maildir_exists(const struct mail_addr *);
int             maildir_deliver(struct message *);
static int smtpd_parse_command(struct session *, char *, size_t);
static int smtpd_parse_data(struct session *, char *, size_t);
static int smtpd_session_reset(struct session *);

static int
smtpd_session_reset(struct session *s)
{
   if (s->msg != NULL) {
        s->msg->recipient_count = 0;
        message_free(s->msg);
        if ((s->msg = message_new()) == NULL) {
            PUTS(s, "421 Out of memory error");
            s->smtp_state = SMTP_STATE_QUIT;
            return (-1);
        }
        s->msg->session = s;
    }

    s->smtp_state = SMTP_STATE_MAIL;
    return (0);
}

static int
smtpd_helo(struct session *s, const char *arg)
{
    log_debug("HELO=`%s'", arg);
    if ((s->msg->helo = strdup(arg)) == NULL) {
        log_errno("strdup(3)");
        return (-1);
    }
    session_puts(s, smtp_helo_greeting);
    return (0);
}


static int
smtpd_ehlo(struct session *s, const char *arg)
{
    log_debug("EHLO=`%s'", arg);
    if ((s->msg->helo = strdup(arg)) == NULL) {
        log_errno("strdup(3)");
        return (-1);
    }
    session_puts(s, smtp_ehlo_greeting);
    return (0);
}


static int
smtpd_mail(struct session *s, const char *arg)
{
    if (s->msg->sender != NULL)
        free(s->msg->sender);
    if ((s->msg->sender = address_parse(arg)) == NULL) {
            PUTS(s, "501 Malformed address");
            return (-1);
    }
    PUTS(s, "250 Ok");
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
        PUTS(s, "503 Error: Too many recipients");
        goto errout;
    }

    /* Require 'MAIL FROM' before 'RCPT TO' */
    if (s->msg->sender == NULL) {
        PUTS(s, "503 Error: need MAIL command first");
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
        PUTS(s, "501 Invalid address syntax");
        goto errout;
    }

    /* Check if we accept mail for this domain */
    switch (domain_exists(ma)) {
        case -1: 
            PUTS(s, "421 Internal error, closing connection");
            // FIXME: actually close the connection
            goto errout;
        case 0: 
            PUTS(s, "551 Relay access denied");
            goto errout;
            break;
    }

    /* Check if the mailbox exists */
    switch (maildir_exists(ma)) {
        case -1: 
            PUTS(s, "421 Internal error, closing connection");
            // FIXME: actually close the connection
            goto errout;
            break;
        case 0: 
            PUTS(s, "550 Mailbox does not exist");
            goto errout;
            break;
        case 1:
            LIST_INSERT_HEAD(&s->msg->recipient, ma, entries);
            s->msg->recipient_count++;
            PUTS(s, "250 Ok");
            break;
    }

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
        PUTS(s, "503 Error: need one or more recipients first");
        return (-1);
    }
    if ((s->msg->filename = maildir_generate_id(s->worker->id, s->worker->delivery_counter)) == NULL) 
        goto errout;
    if (maildir_msg_open(s->msg)) 
        goto errout;
    PUTS(s, "354 End data with <CR><LF>.<CR><LF>");
    s->smtp_state = SMTP_STATE_DATA;
    return (0);

errout:
    PUTS(s, "421 Error creating message");
    s->smtp_state = SMTP_STATE_QUIT;
    return (-1);
}

static int
smtpd_rset(struct session *s)
{
    if (smtpd_session_reset(s) != 0) {
        // FIXME -- What error code goes here?
        return (-1);
    }

    PUTS(s, "250 Ok");
    return (0);
}

static int
smtpd_noop(struct session *s)
{
    PUTS(s, "250 Ok");
    return (0);
}

static int
smtpd_quit(struct session *s)
{
    PUTS(s, "221 Goodbye");
    s->smtp_state = SMTP_STATE_QUIT;
    return (0);
}

int
smtpd_parser(struct session *s, char *buf)
{
    int rv;
    size_t len;

    len = strlen(buf);

    if (s->smtp_state != SMTP_STATE_DATA) {
        log_debug ("SMTP command=`%s' len=%zu", buf, len);
        rv = smtpd_parse_command(s, buf, len);
    } else {
        rv = smtpd_parse_data(s, buf, len);
    }

    /* Stop reading new data after a QUIT is issued */
    if (s->smtp_state == SMTP_STATE_QUIT) {
        bufferevent_disable(s->buf_ev, EV_READ); 
        return (0);//why?
    }

    if (rv != 0) 
        s->errors++;

    /* TODO: make configurable, max_errors or something */
    if (s->errors > 10) {
        smtpd_client_error(s);
        return (-1);
    }

    return (0);
}

static int
smtpd_parse_command(struct session *s, char *src, size_t len)
{
    size_t          i;
    int             c;

    /* SMTP commands must be at least four characters plus the trailing NUL */
    if (len < 4) {
            PUTS(s, "502 Illegal command");
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
            PUTS(s, "502 Illegal request");
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

    PUTS(s, "502 Error: invalid command");
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
    if ((len == 1) && (*src == '.')) {

        /* Close the tmp/ file and move it to new/ */
        if (message_close(s->msg) < 0) {
            log_error("message_close()");
            goto error;
        }

        if (maildir_deliver(s->msg) < 0) {
            log_error("maildir_deliver()");
            goto error;
        }

        /* XXX-FIXME need to fsync(2) */
        PUTS(s, "250 Ok - message has been delivered");
        (void) smtpd_session_reset(s); // todo -- errorhandling

        /* Increment the delivery counter and explicitly wrap around */
        if (s->worker->delivery_counter == ULONG_MAX)
            s->worker->delivery_counter = 0;
        else
            s->worker->delivery_counter++;

        return (0);
    }

    /* Ignore a leading '.' if there are additional characters */
    if (strncmp(src, ".", 1) == 0) {
        len--;
        src++;
    }

    /* Write the line to the file */
    if (atomic_write(s->msg->fd, src, len) < len) {
        log_errno("atomic_write(3)");
        goto error;
    }

    /* Write a newline */
    if (atomic_write(s->msg->fd, "\n", 1) < 1) {
        log_errno("atomic_write(3)");
        goto error;
    }

    return (0);

  error:
    PUTS(s, "452 Error spooling message, try again later");
    s->smtp_state = SMTP_STATE_QUIT;
    return (0);
}



int
smtpd_greeting(struct session *s)
{
    PUTS(s, "220 ESMTP server ready");

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
}

void
smtpd_timeout(struct session *s)
{
    PUTS(s, "421 Idle time limit exceeded, goodbye");
}

void
smtpd_client_error(struct session *s)
{
    PUTS(s, "421 Too many errors");
}

void
smtpd_close(struct session *s)
{
    message_free(s->msg);
}

int
smtpd_init(void)
{
    memset(&smtp_helo_greeting, 0, sizeof(smtp_helo_greeting));
    memset(&smtp_ehlo_greeting, 0, sizeof(smtp_ehlo_greeting));

    snprintf((char *) &smtp_helo_greeting, sizeof(smtp_helo_greeting) - 1,
            "250 %s\r\n", OPT.mailname);

    snprintf((char *) &smtp_ehlo_greeting, sizeof(smtp_ehlo_greeting) - 1,
        "250-%s\r\n"
        "250-PIPELINING\r\n"
        "250 8BITMIME\r\n" 
        , OPT.mailname);

    return (0);
}
