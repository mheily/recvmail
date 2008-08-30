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
#ifndef _RECVMAIL_H
#define _RECVMAIL_H

#include "config.h"

/* Include GNU extensions */
#define _GNU_SOURCE 1

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* Logging */

#define _log_all(level, format,...) syslog(level,			\
   "%s(%s:%d): "format"\n", 						\
   __func__, __FILE__, __LINE__, ## __VA_ARGS__)

#define log_error(format,...) _log_all(LOG_ERR, "**ERROR** "format, ## __VA_ARGS__)
#define log_warning(format,...) _log_all(LOG_WARNING, "WARNING: "format, ## __VA_ARGS__)
#define log_notice(format,...) _log_all(LOG_NOTICE, format, ## __VA_ARGS__)
#define log_info(format,...) _log_all(LOG_INFO, format, ## __VA_ARGS__)
#define log_debug(format,...) _log_all(LOG_DEBUG, format, ## __VA_ARGS__)
#define log_errno(format,...) _log_all(LOG_ERR, format": %s", ## __VA_ARGS__, strerror(errno))

/* Emulate macros from <err.h> but use syslog logging instead of stderr */

#define err(rc,format,...) do {						\
   log_errno(format, ## __VA_ARGS__);					\
   exit(rc);								\
} while (0)

#define errx(rc,format,...) do {					\
  log_error(format, ## __VA_ARGS__);					\
  exit(rc);								\
} while (0)

/* Maximum limits */

#define RECIPIENT_MAX		100
#define DOMAIN_MAX		63
#define HOSTNAME_MAX		63
#define ADDRESS_MAX             (DOMAIN_MAX + HOSTNAME_MAX + 1)

/* Configuration options */

# define DEFAULT_PREFIX		"/var/recvmail"

struct options {
    bool            debugging;
    char           *mailname,
                   *prefix;
    bool            daemon;	/* If TRUE, the server will run as a
				 * daemon */
    char           *uid;	/* The symbolic user-ID to setuid(2) to */
    char           *gid;	/* The symbolic group-ID to setgid(2) to */
    char           *chrootdir;	/* The directory to chroot(2) to */
    int             log_facility;	/* The log facility to provide to
					 * syslog(3) */
    int             log_level;	/* The level used by setlogmask(3) */
};

extern struct options OPT;

struct session;

struct recipient {
	char addr[ADDRESS_MAX + 1]; /* Mailing address in the form 'USER@DOMAIN' */
	size_t addr_len;	/* Number of characters in <addr> */
	char *path;		/* Relative path to the mailbox */
	UT_hash_handle hh;	/* Makes this structure hashable */
};

/* An RFC-2822 message */
struct rfc2822_msg {
    int             fd;		/* A file descriptor opened for writing
				 * the message */
    char           *path;	/* The path to the message */
    char           *sender;	/* The email address of the sender */
    struct in_addr  remote_addr;	/* The IP address of the client */
    /* The remote IP address, converted to string format */
    char            remote_addr_str[INET_ADDRSTRLEN + 1];
    struct recipient *rcpt_to[RECIPIENT_MAX + 1];
    int             num_recipients;
    size_t          size;
    char           *filename;	/* The Maildir message-ID */
};

/** A server */
struct server {
    int             port;	/* The port number to bind(2) to */
    struct in_addr  addr;	/* The IP address to listen(2) to */
    int             fd;		/* The descriptor returned by socket(2) */
    struct sockaddr sa;		/* The socket address of the server */

    /* The number of seconds to wait for incoming data from the client */
    int             timeout_read;

    /* The number of seconds to wait to send data to the client */
    int             timeout_write;

    /* The function that sends the initial greeting to the client */
    int             (*accept_hook) (struct session *);

    /* Parses a line of input from the client */
    int             (*read_hook) (struct session *, char *, size_t);

    /* Called prior to closing a session */
    int             (*close_hook) (struct session *);

    /* Sends a 'fatal internal error' message to the client before closing 
     */
    void            (*abort_hook) (struct session *);

    /* Sends a 'timeout' message to a client that is idle too long */
    void            (*timeout_hook) (struct session *);

    /* Sends a 'too many errors' message to a misbehaving client before
     * closing */
    void            (*reject_hook) (struct session *);

    /* Monitors the child process and restarts/reloads as needed */
    int             (*monitor_hook) (struct server *, pid_t);

    /* Executed when the server is started  */
    // TODO: stop, reload hooks also.
    int             (*start_hook) (struct server *);
};

/** Protocol-specific SMTP session data */
struct session_data {
    int             num_recipients;

    /* An Internet message object */
    struct rfc2822_msg *msg;

    /* The state determines which SMTP commands are valid */
    enum {
	SMTP_STATE_HELO,
	SMTP_STATE_MAIL,
	SMTP_STATE_RCPT,
	SMTP_STATE_DATA,
	SMTP_STATE_FSYNC,
	SMTP_STATE_QUIT,
    } smtp_state;
};

/* A client session */
struct session {
    int             fd;		/* The client socket descriptor */
    FILE           *lbuf_rd;    /* Line-buffered stream I/O handle for reading <fd> */
    struct in_addr  remote_addr;	/* The IP address of the client */

    /* The remote IP address, converted to string format */
    char            remote_addr_str[INET_ADDRSTRLEN + 1];
    struct bufferevent *bev;	/* I/O buffer */
    struct server  *srv;	/* The parent server object */
    struct session_data *data;	/* An opaque pointer to protocol-specific
				 * data */

    /* The state of the session */
    enum {
	SESSION_OPEN = 0,	/* The session is active */
	SESSION_WAIT,		/* Waiting for I/O completion */
	SESSION_CLOSE,		/* The session is closing down */
    } state;

    unsigned int    error_count;	/* The number of errors caused by
					 * the client */
};

/* Forward declarations */

int             open_maillog(const char *path);
int             valid_pathname(const char *pathname);
int             file_exists(const char *path);

/* From address.h (TODO: cleanup) */

#define USERNAME_MAX            63

int             domain_exists(const char *domain);

struct rfc2822_addr *rfc2822_addr_new();
char * addr_parse(const char *);
void            rfc2822_addr_free(struct rfc2822_addr *addr);

int             valid_address(const struct rfc2822_addr *addr);
int             valid_domain(const char *domain);
struct recipient * recipient_find(const char *);

void addr_table_generate(void);

/* From message.h */

int             init_message(struct rfc2822_msg *msg);
int             rset_message(struct rfc2822_msg *msg);
int             valid_message(struct rfc2822_msg *msg);

/* From maildir.h */

int             maildir_msg_open(struct rfc2822_msg *msg);
int             open_message(struct rfc2822_msg *msg);
struct rfc2822_msg *rfc2822_msg_new();
int             rfc2822_msg_write(struct rfc2822_msg *msg, const char *src,
				  size_t len);
int             maildir_msg_close(struct rfc2822_msg *msg);
void            rfc2822_msg_free(struct rfc2822_msg *msg);

/* From http.c */

void httpd_init(struct server *smtpd);

/* From smtp.h */

void session_write(struct session *, const char *, size_t size);
void session_printf(struct session *, const char *, ...);
void session_println(struct session *, const char *);
void            session_close(struct session *s);
void session_init(struct session *);
void            session_free(struct session *s);

int             smtpd_greeting(struct session *s);
int             smtpd_parser(struct session *s, char *buf, size_t len);
void            smtpd_timeout(struct session *s);
void            smtpd_client_error(struct session *s);
int             smtpd_close_hook(struct session *s);
int             smtpd_monitor_hook(struct server *, pid_t);
int             smtpd_start_hook(struct server *);

/* From server.c */

void server_dispatch(struct server *srv);
void server_bind(struct server *srv);
void server_init(void);
void drop_privileges(const char *user, const char *group, const char *chroot_to);

/* From spool.c */

int             msg_spool(struct rfc2822_msg *msg);

/* Thread locking routines */

static inline void
mutex_lock(pthread_mutex_t *m)
{
        if (pthread_mutex_lock(m) != 0)
                err(1, "pthread_mutex_lock(3)");
}

static inline void
mutex_unlock(pthread_mutex_t *m)
{
        if (pthread_mutex_unlock(m) != 0)
                err(1, "pthread_mutex_unlock(3)");
}

#endif
