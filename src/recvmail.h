/*		$Id: address.h 344 2010-03-04 02:38:33Z mheily $		*/
/*
 * Copyright (c) 2004-2010 Mark Heily <devel@heily.com>
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

#include <sys/types.h>	/* Needed by ifaddrs.h on FreeBSD*/

#include <assert.h>
#include <ctype.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "queue.h"

/* Maximum length of an email address, including NUL */
#define MAIL_ADDRSTRLEN     130

/* Return codes for address_lookup() */
#define MA_RES_NODOMAIN       -1
#define MA_RES_NOUSER         -2

struct mail_addr {
    char   *local_part, 
           *domain;
    LIST_ENTRY(mail_addr) entries;
};

struct rfc2822_addr * 
    rfc2822_addr_new();

struct mail_addr *
    address_parse(const char *);

void    address_free(struct mail_addr *);
int     address_lookup(struct mail_addr *);
char *  address_get(char *, size_t, const struct mail_addr *);
int     valid_address(const struct rfc2822_addr *addr);
int     valid_domain(const char *domain);

/* Result codes */
#define DNSBL_NOT_FOUND     (0)
#define DNSBL_FOUND         (1)
#define DNSBL_ERROR         (-1)

struct session;

int     dnsbl_new(const char *service, void (*)(struct session *, int));
void    dnsbl_free(void);

void *  dnsbl_dispatch(void *);
int     dnsbl_submit(struct session *);
int     dnsbl_response(struct session **);

//LOG.h

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

extern int detached;
extern int log_level;
extern int log_is_open;
// XXX-fixme - convert OPT.log_level to log_level

#define _log_all(level, format,...) do {                                    \
    if (log_is_open)                                                        \
        syslog(level, format, ## __VA_ARGS__);                              \
    if (!detached && log_level >= level)                                    \
        fprintf(stderr, "%10s:%-5d %-18s" format "\n",                      \
                 __FILE__, __LINE__, __func__, ## __VA_ARGS__);             \
} while (/*CONSTCOND*/0)

#define log_error(format,...)   _log_all(LOG_ERR, "**ERROR** "format, ## __VA_ARGS__)
#define log_warning(format,...) _log_all(LOG_WARNING, "WARNING: "format, ## __VA_ARGS__)
#define log_notice(format,...)  _log_all(LOG_NOTICE, format, ## __VA_ARGS__)
#define log_info(format,...)    _log_all(LOG_INFO, format, ## __VA_ARGS__)
#define log_errno(format,...)   _log_all(LOG_ERR, format": %s (errno=%d)", ## __VA_ARGS__, strerror(errno), errno)

#ifndef NDEBUG
#define log_debug(format,...)   _log_all(LOG_DEBUG, format, ## __VA_ARGS__)
#else
#define log_debug(format,...)   do { } while (/*CONSTCOND*/0)
#endif

/* Emulate macros from <err.h> but use syslog logging instead of stderr */
/* TODO: make variadic functions instead */

#define err(rc,format,...) do {						                        \
    if (detached)                                                           \
        log_errno(format, ## __VA_ARGS__);					                \
    else                                                                    \
        fprintf(stderr, "ERROR: " format "\n", ## __VA_ARGS__);             \
   exit(rc);								                                \
} while (0)

#define errx(rc,format,...) do {					                        \
    if (detached)                                                           \
       log_error(format, ## __VA_ARGS__);					                \
    else                                                                    \
        fprintf(stderr, "ERROR: " format "\n", ## __VA_ARGS__);             \
    exit(rc);								                                \
} while (0)

void log_open(const char *, int, int, int);
void log_close(void);

//maildir.h

struct message;
struct session;

int maildir_msg_open(struct message *, struct session *);
int maildir_deliver(struct message *);
int maildir_create(const char *);

// _MDA_H

struct message;

int    mda_init(void);
void   mda_free(void);
void * mda_dispatch(void *);
int    mda_submit(unsigned long, struct message *);

// message.h

struct session;

/* An RFC-2822 message */
struct message {
    int     fd;		            /* File descriptor of the spoolfile */
    char   *path;	            /* The path to the spoolfile */
    size_t  recipient_count;
    size_t  msg_size;
    char   *filename;	        /* The Maildir message-ID */
    char   *client;     	    /* The "HELO/EHLO" string */
    char   *return_path;   	    /* The "MAIL FROM:" sender */
    LIST_HEAD(,mail_addr) recipient;    /* All recipients */
};

struct message * message_new(void);
void             message_free(struct message *);

int     message_close(struct message *);
int     message_fsync(struct message *);
void    message_reset(struct message *);

//options.h

#include <stdbool.h>

/* Configuration options */

struct options {
    bool        debugging;
    char       *hostname;
    bool        daemon;	        /* Run as daemon ? */
    char       *log_ident;	    /* Program name to use in syslog */
    int         log_facility;	/* The log facility to provide to syslog(3) */
    int         log_level;	    /* The level used by setlogmask(3) */
    char       *uid;            /* The user ID to run under */
    int         ssl_enabled; 
    char       *ssl_certfile;   /* SSL certificate */
    char       *ssl_keyfile;    /* SSL private key */
};

extern struct options OPT;

//TODO: move from server.c to options.c
int options_parse(int argc, char *argv[]);

//poll.h

#include <poll.h>
#include <signal.h>

struct timer;
struct watch;

struct watch * poll_add(int, int, void (*)(void *, int), void *);
void    poll_remove(struct watch *);
int     poll_dispatch(void);
void    poll_shutdown(void);
int     poll_init(void);
void    poll_free(void);
struct pollfd * 
        poll_get(struct watch *);
int     poll_signal(int, void(*)(void *, int), void *);

struct timer *
        poll_timer_new(unsigned int, void (*)(void *), void *);
void    poll_timer_free(struct timer *);
void    poll_timer_disable(struct timer *);
void    poll_timer_enable(struct timer *);

//session.h

struct session;
struct sockaddr;

struct protocol {
    int     (*getopt_hook)(const char *, const char *);
    int     (*bind_hook)(const struct sockaddr *, const char *);
    int     (*sanity_hook)(void);
    int     (*init_hook)(void);
    int     (*privsep_hook)(const char *); 
    int     (*shutdown_hook)(void);             /* server shutdown */
    int     (*reload_hook)(void); /* TODO - Reload configuration files */
    void    (*timeout_hook)(struct session *); /* session timeout */
    int     (*accept_hook)(struct session *); /* Called after accept(2) */
    void    (*close_hook)(struct session *); /* Called prior to close(2) for a session */
    void    (*abort_hook) (struct session *); /* Fatal internal error */
    /* Sends a 'too many errors' message to a misbehaving client before
     * closing */
    //DEADWOOD:void            (*reject_hook) (struct session *);
};

//resolver.h

#include <netinet/in.h>

#define RES_NONBLOCK    0x1 

int     resolver_lookup_addr(in_addr_t *, const char *, int);
int     resolver_lookup_name(char **, const in_addr_t, int);
int     resolver_lookup_mx(char ***dst, const char *src, int flags);
int     resolver_init(void);
//TODO:void    resolver_atexit(void);

//server.h

#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

struct session;
struct net_interface;

struct server {
    struct protocol  *proto;
    LIST_HEAD(,net_interface) if_list;
};

extern struct server srv;

int  protocol_close(struct session *);
int  server_disconnect(int);
int  server_dispatch(void);
int  server_init(int, char *[], struct protocol *);
int  server_bind(void);
void server_update_pollset(struct server *);


//session.h

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

struct message;
struct socket;
struct session;
struct protocol;

struct session * session_new(int, struct protocol *, void (*)(void *, int));
void             session_free(struct session *s);

int     session_read(struct session *);
int     session_readln(struct session *s);
int     session_printf(struct session *, const char *, ...);
int     session_println(struct session *, const char *);
void    session_close(struct session *);
void    session_event_handler(struct session *, int);

int     session_table_init(void);
int     session_table_lookup(struct session **, unsigned long);

int     session_handler_push(struct session *, int (*)(struct session *));
int     session_handler_pop(struct session *);

void *  session_data_get(const struct session *);
void    session_data_set(struct session *, const void *);
void    session_buffer_get(const struct session *, char **, size_t *);
void    session_timeout_set(struct session *, time_t);
void    session_resume(struct session *);

const struct socket * session_get_socket(struct session *);
unsigned long session_get_id(struct session *);

//smtp.h

extern struct protocol SMTP;


int    smtpd_accept(struct session *);
int     smtpd_parser(struct session *);
void    smtpd_client_error(struct session *);
void    smtpd_close(struct session *);
void    smtp_mda_callback(struct session *, int);
void    smtpd_timeout(struct session *s);
int     smtpd_init(void);
int     smtpd_shutdown(void);

//socket.h

#include <sys/types.h>

struct socket;
struct session;

struct socket * socket_new(int, struct session *);
void            socket_free(struct socket *);

int      socket_pending(const struct socket *);
ssize_t  socket_readln(char **, struct socket *);
int      socket_close(struct socket *);
int      socket_write(struct socket *, const char *, size_t);
int      socket_poll_enable(struct socket *, int, void (*)(void *, int), void *);
int      socket_poll_disable(struct socket *);
struct pollfd * socket_get_pollfd(struct socket *);
int      socket_event_handler(struct socket *, int);
int      socket_get_family(const struct socket *);
int      socket_get_peeraddr4(const struct socket *);
const char *   socket_get_peername(const struct socket *);

//throttle.h

#include <netinet/in.h>

int     throttle_connect(in_addr_t);
void    throttle_disconnect(in_addr_t);
void    throttle_error(in_addr_t);

int     throttle_init(void);
//TODO:void    throttle_atexit(void);

//socket.h

int      socket_starttls(struct socket *);
int      socket_init(void);

//util.h

int  file_exists(const char *);
ssize_t file_read(char **, const char *);

//workqueue.h

struct work {
    u_long  sid;                /* Session ID */
    u_int   argc;               /* Number of arguments */
    union {
        u_int   u_i;
        u_long  u_l;
        void   *ptr;
    } argv0;                    /* Argument vector */
    int retval;                 /* Return value */
};

struct session;

struct workqueue *
        workqueue_new( void (*)(struct work *, void *),
                void (*)(struct session *, int), 
                void *);

int     workqueue_submit(struct workqueue *, struct work);
void    workqueue_free(struct workqueue *);
int     workqueue_init(void);

#endif  /* _RECVMAIL_H */
