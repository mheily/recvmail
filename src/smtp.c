/*      $Id$      */

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

#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "address.h"
#include "dnsbl.h"
#include "log.h"
#include "options.h"
#include "maildir.h"
#include "mda.h"
#include "message.h"
#include "session.h"
#include "protocol.h"
#include "poll.h"
#include "recipient.h"
#include "socket.h"
#include "smtp.h"
#include "workqueue.h"
#include "util.h"

static int sanity_check(void);
static int smtpd_getopt(const char *, const char *);
static int smtpd_bind(const struct sockaddr *, const char *);

static int use_dnsbl = 0;      /* If true, check the DNSBL */

struct protocol SMTP = {
    .getopt_hook    = smtpd_getopt,
    .sanity_hook    = sanity_check,
    .bind_hook      = smtpd_bind,
    .accept_hook    = smtpd_accept,
    .timeout_hook   = smtpd_timeout,
    .abort_hook     = NULL,		// fixme
    .close_hook     = smtpd_close,
    .init_hook      = smtpd_init,
    .shutdown_hook  = smtpd_shutdown,
};

struct smtp_session {
    struct message *msg;
    enum {
        SMTP_STATE_HELO,
        SMTP_STATE_MAIL,
        SMTP_STATE_RCPT,
        SMTP_STATE_DATA,
        SMTP_STATE_FSYNC,
        SMTP_STATE_QUIT,
    } smtp_state;
    unsigned int    errors;	    /* The number of protocol errors */
};

#define smtp_session(s)     ((struct smtp_session *) session_data_get((s)))

#define RECIPIENT_MAX		100

/* Maximum line length (excluding trailing NUL) */
#define SMTP_LINE_MAX   1000

/* The timeout (in seconds) while in the command state */
#define SMTP_COMMAND_TIMEOUT    (60 * 5)

static int smtpd_greeting(struct session *s);
static int smtpd_parse_command(struct session *, char *, size_t);
static int smtpd_parse_data(struct session *, char *, size_t);
static int smtpd_session_reset(struct session *);
static int smtpd_fatal_error(struct session *s);

static int smtpd_quit(struct session *s);
static int smtpd_rset(struct session *s);
static int smtpd_starttls(struct session *s);

void
smtp_mda_callback(struct session *s, int retval)
{
    session_handler_push(s, smtpd_parser);
    smtpd_session_reset(s);

    if (retval == 0) {
        session_println(s, "250 Message delivered");
    } else {
        session_println(s, "451 Requested action aborted: error in processing");
    }
}

static int
smtpd_session_reset(struct session *s)
{
    struct smtp_session *sd = smtp_session(s);

    message_free(sd->msg);
    sd->msg = message_new();
    if (sd->msg == NULL) {
        log_errno("calloc(3)");
        return (-1);
    }
    sd->smtp_state = SMTP_STATE_MAIL;
    
    return (0);
}

static int
smtpd_helo(struct session *s, const char *arg)
{
    log_debug("HELO=`%s'", arg);
    session_printf(s, "250 %s\r\n", OPT.hostname);
    return (0);
}

static int
smtpd_ehlo(struct session *s, const char *arg)
{
    log_debug("EHLO=`%s'", arg);
    session_printf(s, "250-%s\r\n"
                    "250-PIPELINING\r\n"
                    "250-STARTTLS\r\n"
                    "250 8BITMIME\r\n" 
                    , OPT.hostname);
    return (0);
}

/* See also: RFC 2487 */
static int
smtpd_starttls(struct session *s)
{
    struct smtp_session *sd = smtp_session(s);

    session_println(s, "220 Ready to start TLS");

    if (socket_starttls((struct socket *) session_get_socket(s)) < 0) {
        log_error("STARTTLS failed");
        return (-1);
    }

    /* Throw away all client information including HELO */
    if (smtpd_session_reset(s) != 0) {
        log_error("reset failed");
        return (-1);
    }
    sd->smtp_state = SMTP_STATE_MAIL;

    return (0);
}

static int
smtpd_mail(struct session *s, const char *arg)
{
    struct smtp_session *sd = smtp_session(s);

    if (sd->msg->sender != NULL)
        free(sd->msg->sender);
    if ((sd->msg->sender = address_parse(arg)) == NULL) {
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
    struct smtp_session *sd = smtp_session(s);

    /* Limit the number of recipients per envelope */
    if (sd->msg->recipient_count > RECIPIENT_MAX) {
        session_println(s, "503 Error: Too many recipients");
        goto errout;
    }

    /* Require 'MAIL FROM' before 'RCPT TO' */
    if (sd->msg->sender == NULL) {
        session_println(s, "503 Error: need MAIL command first");
        goto errout;
    }

    /* Remove leading whitespace and '<' bracket */
    for (; *line == ' ' || *line == '<'; line++);  

    buf = strdup(line); //FIXME: errhandling

    /* Ignore any trailing whitespace and additional options */
    /* TODO - handle quoted whitespace */
    if ((p = strchr(buf, ' ')) != NULL)
        memset(p, 0, 1);
    if ((p = strchr(buf, '>')) != NULL)
        memset(p, 0, 1);

    if ((ma = address_parse(buf)) == NULL) {
        session_println(s, "501 Invalid address syntax");
        goto errout;
    }

    /* Check if we accept mail for this domain */
    if (!recipient_domain_lookup(ma->domain)) {
        session_println(s, "551 Relay access denied");
        goto errout;
    }

    /* Check if the mailbox exists */
    if (!recipient_lookup(ma->local_part, ma->domain)) {
        session_println(s, "550 Mailbox does not exist");
        goto errout;
    }

    /* Add the recipient to the envelope */
    LIST_INSERT_HEAD(&sd->msg->recipient, ma, entries);
    sd->msg->recipient_count++;
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
    struct smtp_session *sd = smtp_session(s);

    if (sd->msg->recipient_count == 0) {
        session_println(s, "503 Error: need one or more recipients first");
        return (-1);
    }
    if (maildir_msg_open(sd->msg, s)) {
        session_println(s, "421 Error creating message");
        sd->smtp_state = SMTP_STATE_QUIT;
        return (-1);
    }
    session_println(s, "354 End data with <CR><LF>.<CR><LF>");
    sd->smtp_state = SMTP_STATE_DATA;
    
    return (0);
}

static int
smtpd_rset(struct session *s)
{
    struct smtp_session *sd = smtp_session(s);

    if (smtpd_session_reset(s) != 0) {
        session_println(s, "421 Reset failed");
        sd->smtp_state = SMTP_STATE_QUIT;
        return (-1);
    }
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
    struct smtp_session *sd = smtp_session(s);

    session_println(s, "221 Bye");
    sd->smtp_state = SMTP_STATE_QUIT;
    return (0);
}

static int
smtpd_fatal_error(struct session *s)
{
    struct smtp_session *sd = smtp_session(s);

    session_println(s, "421 Fatal error, closing connection");
    sd->smtp_state = SMTP_STATE_QUIT;
    return (0);
}


int
smtpd_parser(struct session *s)
{
    char *buf;
    size_t len;
    int rv;
    struct smtp_session *sd = smtp_session(s);

    session_buffer_get(s, &buf, &len);

    if (len == 0 || len > SMTP_LINE_MAX) {
        log_error("invalid line length %zu", len);
        return (-1);
    }

    session_timeout_set(s, SMTP_COMMAND_TIMEOUT);

    if (sd->smtp_state != SMTP_STATE_DATA) {

        /* Replace LF with NUL */
        memset(buf + len - 1, 0, 1);     

        log_debug("CMD=`%s'", buf);
        rv = smtpd_parse_command(s, buf, len - 1);
    } else {
        rv = smtpd_parse_data(s, buf, len);
    }

    if (sd->smtp_state == SMTP_STATE_QUIT) 
        return (-1);

    if (rv != 0) 
        sd->errors++;

    /* Terminate the session after too many errors */
    if (sd->errors > 10) {
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
            return (-1);
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
        case 'S': if (strcasecmp(src, "STARTTLS") == 0)
                      return (smtpd_starttls(s));
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
    struct smtp_session *sd = smtp_session(s);

    /* If the line is '.', end the data stream */
    if ((len == 2) && strncmp(src, ".\n", 2) == 0) {

        /* Submit to the MDA workqueue for processing */
        session_handler_pop(s);
        if (mda_submit(session_get_id(s), sd->msg) < 0) {
            log_error("mda_submit()");
            goto error;
        }

        /* After submitting the message, the 'msg' object becomes 
         * property of the MDA thread. */
        sd->msg = NULL;

        return (0);
    }

    /* Ignore a leading '.' if there are additional characters */
    if (strncmp(src, ".", 1) == 0) {
        len--;
        src++;
    }

    /* TODO: use writev(2) to write multiple lines in one syscall. */
    /* Write the line to the file */
    if (write(sd->msg->fd, src, len) < len) {
        log_errno("write(2)");
        goto error;
    }

    return (0);

  error:
    session_println(s, "452 Error spooling message, try again later");
    sd->smtp_state = SMTP_STATE_QUIT;
    return (-1);
}

static void
dnsbl_response_handler(struct session *s, int retval)
{
    if (retval == DNSBL_FOUND) {
        log_debug("rejecting client due to DNSBL");
        session_println(s, "421 ESMTP access denied");
        session_close(s);
    } else if (retval == DNSBL_NOT_FOUND || retval == DNSBL_ERROR) {
        if (use_dnsbl) {
            log_debug("client is not in a DNSBL");
            session_handler_pop(s);
        }
        session_handler_push(s, smtpd_parser);
        session_timeout_set(s, SMTP_COMMAND_TIMEOUT);
        smtpd_greeting(s);
        if (session_read(s) < 0)
            session_close(s);
    }
}

static int
smtpd_greeting(struct session *s)
{
    session_println(s, "220 ESMTP server ready");
    return (0);
}

int
smtpd_accept(struct session *s)
{
    struct smtp_session *sd;

    sd = calloc(1, sizeof(*sd));
    if (sd == NULL) {
        log_errno("calloc");
        return (-1);
    }

    sd->msg = message_new();
    if (sd->msg == NULL) {
        free(sd);
        free(s);
        log_errno("message_new()");
        return (-1);
    }

    session_data_set(s, sd);

    if (use_dnsbl) {
        if (dnsbl_submit(s) < 0) {
            log_error("dnsbl_submit() failed");
            smtpd_fatal_error(s);
            return (-1);
        }
    } else {
        dnsbl_response_handler(s, DNSBL_NOT_FOUND);
    }

    return (0);
}

void
smtpd_timeout(struct session *s)
{
    log_info("session timed out due to inactivity");
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
    struct smtp_session *sd;

    sd = session_data_get(s);
    message_free(sd->msg);
    free(sd);
    session_data_set(s, NULL);          /* paranoia */
}

static int
smtpd_getopt(const char * key, const char * val)
{
    if (strcmp(key, "UseDNSBL") == 0) {
        use_dnsbl = 1; // FIXME: temp workaround
    } else {
        return (1);
    }

    return (0);
}

static int
smtpd_bind(const struct sockaddr *sa, const char *sa_name)
{
    /* TODO - Support relaying mail from localhost
       For now, Don't listen on the loopback address */
    if (strcmp(&sa_name[0], "127.0.0.1") == 0 
            || strncmp(&sa_name[0], "fe80::1", 7) == 0
            || strcmp(&sa_name[0], "::1") == 0) {
        return (-1);
    }

    return (25);
}

static int
sanity_check(void)
{
#if TODO
   //example
   // test this during drop_privileges
   if (access(OPT.chrootdir, X_OK) != 0) {
        log_errno("unable to access %s", OPT.chrootdir);
        return (-1);
   }
   /* TODO: check spool/ and etc/ and box/ */
#endif

   return (0);
}

/* FIXME: should be called "check_dirs()" and create_dirs() should be
   somewhere else.
   */
static int
create_dirs(void)
{
    if (!file_exists("spool") || !file_exists("box"))  {
        log_error("A required spool/ or box/ directory does not exist.");
        return (-1);
    }

    return (0);
}

int
smtpd_init(void)
{
    pthread_t       tid;

    /* Create the directory heirarchy */
    if (create_dirs() < 0)
        return (-1);

    /* Create the MDA thread */
    if (mda_init() < 0) {
        log_error("mda_init() failed");
        return (-1);
    }
    if (pthread_create(&tid, NULL, mda_dispatch, NULL) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }

    /* Create the recipient table manager thread */
    if (recipient_table_init() < 0) {
        log_error("recipient_table_init() failed");
        return (-1);
    }

    /* Create the DNSBL thread */
    if (use_dnsbl) {
      if (dnsbl_new("zen.spamhaus.org", dnsbl_response_handler) < 0) {
          log_error("dnsbl_new()");
          return (-1);
      }
      if (pthread_create(&tid, NULL, dnsbl_dispatch, NULL) != 0) {
          log_errno("pthread_create(3)");
          return (-1);
      }
    }

    return (0);
}

int
smtpd_shutdown(void)
{
    //TODO: wait for MDA to complete
    //TODO: wait for DNSBL to complete
    mda_free();
    if (use_dnsbl)
        dnsbl_free();
    //TODO: shutdown the MDA and DNSBL threads
    return (0);
}    
