/*		$Id$		*/

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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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
#include "message.h"

extern int detached;

/* Logging */

#define _log_all(level, format,...) do {                            \
    if (detached)                                                   \
        syslog(level, "%s(%s:%d): "format"\n", 						\
               __func__, __FILE__, __LINE__, ## __VA_ARGS__);       \
    else if (OPT.log_level >= level)                                \
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

#define CHROOTDIR            "/srv/mail"

struct options {
    bool            debugging;
    char           *mailname;
    bool            daemon;	/* If TRUE, the server will run as a
				 * daemon */
    char           *uid;	/* The symbolic user-ID to setuid(2) to */
    char           *gid;	/* The symbolic group-ID to setgid(2) to */
    char           *log_ident;	/* Program name to use in syslog */
    int             log_facility;	/* The log facility to provide to
					 * syslog(3) */
    int             log_level;	/* The level used by setlogmask(3) */
};

extern struct options OPT;

struct session;
struct server;


/* A socket buffer */
struct socket_buf {
    struct iovec *sb_iov;           /* Buffer of lines */
    size_t        sb_iovlen;        /* Number of structures in sb_iov */
    char         *sb_frag;          /* Line fragment */
    size_t        sb_fraglen;       /* Length of the line fragment */
    int           sb_status;        /* Status code */
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

int             domain_exists(const struct mail_addr *);

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

/* From maildir.h */

int             maildir_msg_open(struct message *msg);
int             open_message(struct message *msg);
struct message *message_new();
int             message_write(struct message *msg, const char *src,
				  size_t len);
int             message_close(struct message *);
void            message_free(struct message *msg);
int             maildir_exists(const struct mail_addr *);
int             maildir_deliver(struct message *);



/* From socket.c */

ssize_t socket_readv(struct socket_buf *, int);
int socket_write(int, char **, size_t **);

/* From fsyncer.c */
int  fsyncer_init(struct server *);
void fsyncer_wakeup(struct server *);

#endif
