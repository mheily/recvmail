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
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "queue.h"
#include "nbuf.h"

extern int detached;

/* Logging */

#define _log_all(level, format,...) do {                            \
    if (detached)                                                   \
        syslog(level, "%s(%s:%d): "format"\n", 						\
               __func__, __FILE__, __LINE__, ## __VA_ARGS__);       \
    else if (level < OPT.log_level)                                 \
        fprintf(stderr, "%s(%s:%d): " format "\n",                  \
                __func__, __FILE__, __LINE__, ## __VA_ARGS__);      \
} while (/*CONSTCOND*/0)

#define log_error(format,...) _log_all(LOG_ERR, "**ERROR** "format, ## __VA_ARGS__)
#define log_warning(format,...) _log_all(LOG_WARNING, "WARNING: "format, ## __VA_ARGS__)
#define log_notice(format,...) _log_all(LOG_NOTICE, format, ## __VA_ARGS__)
#define log_info(format,...) _log_all(LOG_INFO, format, ## __VA_ARGS__)
#define log_debug(format,...) _log_all(LOG_DEBUG, format, ## __VA_ARGS__)
#define log_errno(format,...) _log_all(LOG_ERR, format": %s (errno=%d)", ## __VA_ARGS__, strerror(errno), errno)

/* Emulate macros from <err.h> but use syslog logging instead of stderr */
/* TODO: make variadic functions instead */

#define err(rc,format,...) do {						                        \
    if (detached)                                                           \
        log_errno(format, ## __VA_ARGS__);					                \
    else                                                                    \
        fprintf(stderr, "ERROR: " format "\n", ## __VA_ARGS__);                              \
   exit(rc);								                                \
} while (0)

#define errx(rc,format,...) do {					\
    if (detached)                                                           \
       log_error(format, ## __VA_ARGS__);					\
    else                                                                    \
        fprintf(stderr, "ERROR: " format "\n", ## __VA_ARGS__);                              \
    exit(rc);								\
} while (0)

/* Maximum limits */

#define MAX_CLIENTS         1024
#define MAIL_ADDRSTRLEN     130
#define RECIPIENT_MAX		100
#define DOMAIN_MAX		63
#define HOSTNAME_MAX		63
#define ADDRESS_MAX             (DOMAIN_MAX + HOSTNAME_MAX + 1)
#define SMTP_LINE_MAX       998

/* Configuration options */

#define SPOOLDIR            "/var/spool/recvmail"

struct options {
    bool            debugging;
    char           *mailname;
    char           **domains; /* domain(s) to accept mail for */
    bool            daemon;	/* If TRUE, the server will run as a
				 * daemon */
    char           *uid;	/* The symbolic user-ID to setuid(2) to */
    char           *gid;	/* The symbolic group-ID to setgid(2) to */
    char           *spooldir;	/* The directory to chroot(2) to */
    char           *log_ident;	/* Program name to use in syslog */
    int             log_facility;	/* The log facility to provide to
					 * syslog(3) */
    int             log_level;	/* The level used by setlogmask(3) */
};

extern struct options OPT;

struct session;
struct server;

struct mail_addr {
    char   *local_part, 
           *domain;
    LIST_ENTRY(mail_addr) entries;
};

/* An RFC-2822 message */
struct message {
    int             fd;		/* A file descriptor opened for writing the message */
    char           *path;	/* The path to the message */
    struct mail_addr *sender;	/* The email address of the sender */
    struct session *session;
    LIST_HEAD(,mail_addr) recipient;
    size_t          recipient_count;
    size_t          size;
     char           *filename;	/* The Maildir message-ID */
};

/* A socket buffer */
struct socket_buf {
    struct iovec *sb_iov;           /* Buffer of lines */
    size_t        sb_iovlen;        /* Number of structures in sb_iov */
    char         *sb_frag;          /* Line fragment */
    size_t        sb_fraglen;       /* Length of the line fragment */
    int           sb_status;        /* Status code */
};


/* A client session */
struct session {
    struct server  *srv;            /* The server that owns this session */
    int             fd;		        /* The client socket descriptor */
    int flags;          // see SFL_*
    int             events;         //fixme this isnt really used
    int closed; //TODO: deprecate this
    struct in_addr  remote_addr;	/* IP address of the client */
    struct socket_buf in_buf;
    STAILQ_HEAD(,nbuf) out_buf;     /* Output buffer */

    /* ---------- protocol specific members ------------ */

    struct message *msg;

    /* The state determines which SMTP commands are valid */
    enum {
        SMTP_STATE_HELO,
        SMTP_STATE_MAIL,
        SMTP_STATE_RCPT,
        SMTP_STATE_DATA,
        SMTP_STATE_FSYNC,
        SMTP_STATE_QUIT,
    } smtp_state;
    unsigned int    errors;	/* The number of protocol errors */

    /* ---------- end protocol specific members ---------- */

    LIST_ENTRY(session) entries;
};

/* Forward declarations */

int             open_maillog(const char *path);
int             valid_pathname(const char *pathname);
int             file_exists(const char *path);

/* From atomic.c */

ssize_t atomic_printfd(int d, const char *fmt, ...);
ssize_t atomic_read(int d, void *buf, size_t nbytes);
ssize_t atomic_write(int d, const void *buf, size_t nbytes);
int atomic_close(int d);

/* From address.h (TODO: cleanup) */

#define USERNAME_MAX            63

int             domain_exists(const char *domain);

struct rfc2822_addr *rfc2822_addr_new();
struct mail_addr * address_parse(const char *src);
void            address_free(struct mail_addr *addr);
char * address_get(char *dst, size_t len, struct mail_addr *src);
int             valid_address(const struct rfc2822_addr *addr);
int             valid_domain(const char *domain);

/* From aliases.c */

void            aliases_init(void);
void            aliases_parse(const char *);
struct alias_entry * aliases_lookup(const char *name);

/* From message.h */

int             init_message(struct message *msg);
int             rset_message(struct message *msg);
int             valid_message(struct message *msg);

/* From maildir.h */

int             maildir_msg_open(struct message *msg);
int             open_message(struct message *msg);
struct message *message_new();
int             message_write(struct message *msg, const char *src,
				  size_t len);
int             maildir_msg_close(struct message *msg);
void            message_free(struct message *msg);

/* From http.c */

void httpd_init(struct server *smtpd);

/* From smtp.h */

void session_write(struct session *, const char *, size_t size);
void session_printf(struct session *, const char *, ...);
void session_println(struct session *, const char *);
void            session_close(struct session *s);
struct session * session_new(int fd);
void            session_free(struct session *s);
char *          remote_addr(char *dest, size_t len, const struct session *s);
//struct session * session_lookup(int fd);
int session_readln(struct session *s);
int session_fdatasync(struct session *, int);

void            smtpd_accept(struct session *s);
void            smtpd_parser(struct session *s);
void            smtpd_timeout(struct session *s);
void            smtpd_client_error(struct session *s);
void            smtpd_close(struct session *s);

/* From socket.c */

ssize_t socket_readv(struct socket_buf *, int);
int socket_write(int, char **, size_t **);


#endif
