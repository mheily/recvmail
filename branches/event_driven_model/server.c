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

#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>

#include "dnsbl.h"
#include "mda.h"
#include "options.h"
#include "poll.h"
#include "server.h"
#include "smtp.h"
#include "session.h"

struct server srv;

static void drop_privileges(void);

// wierd place for this..
static void
dnsbl_response_handler(void)
{
    char c;
    struct session *s;

    (void)read(srv.dnsblfd[0], &c, 1); // FIXME errhandling

    if (dnsbl_response(&s, srv.dnsbl) < 0) {
        log_error("bad response");
        return;
    }

    if (s->dnsbl_res == DNSBL_FOUND) {
        log_debug("rejecting client due to DNSBL");
        session_println(s, "421 ESMTP access denied");
        session_close(s);
    } else if (s->dnsbl_res == DNSBL_NOT_FOUND || s->dnsbl_res == DNSBL_ERROR) {
        log_debug("client is not in a DNSBL");
        session_accept(s);
        if (session_read(s) < 0)
            session_close(s);
    }
}

// wierd place for this..
int
protocol_close(struct session *s)
{
    srv.close_hook(s);
    return (0);
}

/*
 * Remove root privileges from the running process.
 * 
 * If the process is running as root, change the UID and GID to the ID's of
 * <uid> and <gid>, respectively.
 * 
 * Also chroot(2) to another directory, if desired.
 * 
 */
static void
drop_privileges(void)
{
    struct group   *grent;
    struct passwd  *pwent;
    uid_t           uid;
    gid_t           gid;

    /* Chdir into the chroot directory */
    if (srv.chrootdir && (chdir(srv.chrootdir) < 0)) 
        err(1, "chdir(2) to `%s'", srv.chrootdir);

    /* Only root is allowed to drop privileges */
    if (getuid() > 0) {
        log_warning("cannot drop privileges if UID != 0");
        return;
    }

    /* Convert the symbolic group to numeric GID */
    /* Convert the symbolic user-id to the numeric UID */
    if ((grent = getgrnam(srv.gid)) == NULL) 
        err(1, "a group named '%s' does not exist", srv.gid);
    if ((pwent = getpwnam(srv.uid)) == NULL)
        err(1, "a user named '%s' does not exist", srv.uid);
    gid = grent->gr_gid;
    uid = pwent->pw_uid;

    /* chroot */
    if (srv.chrootdir && (chroot(srv.chrootdir) < 0))
        err(1, "chroot(2)");

    /* Set the real UID and GID */
    if (setgid(gid) < 0)
        err(1, "setgid(2)");
    if (setuid(uid) < 0)
        err(1, "setuid(2)");
    
    log_info("setuid(2) to %s(%d)", srv.uid, uid);
}


/* NOOP signal handler */
void
_sig_handler(int num)
{
    num = 0;
}

static void
set_signal_mask(int how)
{
    sigset_t set;
    struct sigaction sa;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM);
    if (pthread_sigmask(how, &set, NULL) != 0)
        err(1, "pthread_sigmask(3)");

    if (how == SIG_UNBLOCK) {
        sa.sa_flags = 0;
        sa.sa_handler = _sig_handler;
        sigaction (SIGHUP, &sa, NULL);
        sigaction (SIGINT, &sa, NULL);
        sigaction (SIGTERM, &sa, NULL);
    }
}

static void *
signal_handler(void *arg)
{
    char c;
    struct server *srv = (struct server *) arg;

    set_signal_mask(SIG_UNBLOCK);
    for (;;) {
        pause();
        puts("gotcha");
        write(srv->signalfd[1], &c, 1);
    }
}

/* ------------------- Public functions ----------------------- */



/* Initialization routines common to all servers */
int
server_init(struct server *_srv)
{
    struct rlimit   limit;
    pthread_t       tid;
    pid_t           pid,
                    sid;

    memcpy(&srv, _srv, sizeof(srv));
    session_table_init();

    if (OPT.daemon) {

        /* Create a new process */
        if ((pid = fork()) < 0)
            err(1, "fork(2)");

        /* Terminate the parent process */
        if (pid > 0)
            exit(0);

        /* Create a new session and become the session leader */
        if ((sid = setsid()) < 0)
            err(1, "setsid(2)");

        /* Close all inherited STDIO file descriptors */
        close(0);
        close(1);
        close(2);

        detached = 1;
    }

    log_open(OPT.log_ident, 0, OPT.log_facility, OPT.log_level);

    /* Bind to the server socket */
    if (server_bind() < 0)
        errx(1, "server_bind() failed");

    /* Increase the allowable number of file descriptors */
    if (getuid() == 0) {
        limit.rlim_cur = 50000;
        limit.rlim_max = 50000;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
            err(1, "setrlimit failed");
    }

    /* Enable coredumps */
    if (getrlimit(RLIMIT_CORE, &limit) != 0)
        err(1, "getrlimit failed");
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit) != 0)
        err(1, "setrlimit failed");

    set_signal_mask(SIG_BLOCK);
    signal(SIGPIPE, SIG_IGN);       /* TODO: put this with the mask */

    /* Create the event source */
    if ((srv.evcb = poll_new()) == NULL) {
        log_error("unable to create the event source");
        return (-1);
    }

    /* Drop root privilges and call chroot(2) */
    drop_privileges();

    /* Create the signal-catching thread */
    if (pipe(srv.signalfd) == -1) {
        log_errno("pipe(2)");
        return (-1);
    }
    if (pthread_create(&tid, NULL, signal_handler, &srv) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }

    /* Create the MDA thread */
    if (pipe(srv.mdafd) == -1) {
        log_errno("pipe(2)");
        return (-1);
    }
    srv.mda = mda_new(srv.mdafd[1]);
    if (pthread_create(&tid, NULL, mda_dispatch, srv.mda) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }

    /* Create the DNSBL thread */
    if (pipe(srv.dnsblfd) == -1) {
        log_errno("pipe(2)");
        return (-1);
    }
    srv.dnsbl = dnsbl_new("zen.spamhaus.org", srv.dnsblfd[1]);
    if (srv.dnsbl == NULL) {
        log_error("dnsbl_new()");
        return (-1);
    }
    if (pthread_create(&tid, NULL, dnsbl_dispatch, srv.dnsbl) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }

    return (0);
}


int
server_bind(void)
{
    struct sockaddr_in srv_addr;
    int             one = 1;
    int             fd = -1;

	/* Adjust the port number for non-privileged processes */
	if (getuid() > 0 && srv.port < 1024)
		srv.port += 1000;

	/* Initialize the socket variable */
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr = srv.addr;
	srv_addr.sin_port = htons(srv.port);

	/* Create the socket and bind(2) to it */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_errno("socket(2)");
        goto errout;
    }
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
			 sizeof(one)) != 0) {
		log_errno("setsockopt(3)");
        goto errout;
    }
	if (bind(fd, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) < 0) {
		log_errno("bind(2)");
        goto errout;
    }

	/* Listen for incoming connections */
	if (listen(fd, 100) < 0) {
		log_errno("listen(2)");
        goto errout;
    }

    log_debug("listening on port %d", srv.port);

    srv.fd = fd;

    return (0);

errout:
    if (fd >= 0)
        close(fd);
    srv.fd = -1;
    return (-1);
}


static struct session *
server_accept(void)
{
	socklen_t cli_len;
    int fd;
	struct session *s;

    cli_len = sizeof(srv.sa);

    log_debug("incoming connection on fd %d", srv.fd);

    /* Accept the incoming connection */
    if ((fd = accept(srv.fd, &srv.sa, &cli_len)) < 0) {
        log_errno("accept(2)");
        return (NULL);
    }

    /* Create a new session */
    if ((s = session_new(fd)) == NULL) 
        return (NULL);

    /* Generate a session ID */
    if (srv.next_sid == ULONG_MAX)
        s->id = srv.next_sid = 1;
    else
        s->id = ++srv.next_sid;

    /* Monitor the client socket for events */
    poll_enable(srv.evcb, s->fd, s, SOCK_CAN_READ | SOCK_CAN_WRITE);

    dnsbl_submit(srv.dnsbl, s);

    return (s);
}


int
server_dispatch(void)
{
    int c;
    int events;
    static int srv_udata;
    static int signal_flag;
    static int dnsbl_flag;
    static int mda_flag;
	struct session *s;

    /* Monitor the server descriptor for new connections */
    if (poll_enable(srv.evcb, srv.fd, &srv_udata, SOCK_CAN_READ) < 0) { 
        log_errno("poll_enable() (srv.fd=%d)", srv.fd);
        return (-1);
    }
   
    /* Monitor the signal catching thread */
    if (poll_enable(srv.evcb, srv.signalfd[0], &signal_flag, SOCK_CAN_READ) < 0) { 
        log_errno("poll_enable() signalfd %d", srv.signalfd[0]);
        return (-1);
    }

    // TODO -- this is hackish having three separate pollfds and the flags
    // make a generic inter-thread notification system
    // e.g. server_notify(EVT_SIGNAL | EVT_DNSBL | EVT_MDA)
    //
    
    /* Monitor the DNSBL thread */
    if (poll_enable(srv.evcb, srv.dnsblfd[0], &dnsbl_flag, SOCK_CAN_READ) < 0) { 
        log_errno("poll_enable()");
        return (-1);
    }

    /* Monitor the syncer thread */
    if (poll_enable(srv.evcb, srv.mdafd[0], &mda_flag, SOCK_CAN_READ) < 0) { 
        log_errno("poll_enable()");
        return (-1);
    }

	/* Dispatch incoming connections */
	for (;;) {

        /* Get one event */
        log_debug("waiting for event");
        if ((s = poll_wait(srv.evcb, &events)) == NULL) {
            log_errno("poll_wait()");
            return (-1);
        }

        /* Special case: a signal was received */
        if (s == (struct session *) &signal_flag) {
            err(1, "todo - sighandling");
            continue;
        }

        /* A DNSBL query completed */
        if (s == (struct session *) &dnsbl_flag) {
            dnsbl_response_handler();
            continue;
        }

        /* A message was delivered */
        if (s == (struct session *) &mda_flag) {
            (void)read(srv.mdafd[0], &c, 1); // FIXME errhandling
            mda_response(&s, srv.mda); // FIXME err handl
            if (s != NULL) {
                smtp_mda_callback(s);
            }
            continue;
        }

        /* Special case for a pending accept(2) on the listening socket */
        if (s == (struct session *) &srv_udata) {
            if (events & SOCK_ERROR) {
                log_errno("bad server socket");
                return (-1);
            }
            if ((events & SOCK_CAN_READ) && (s = server_accept()) == NULL) {
                log_errno("server_accept()");
                return (-1);
            }
            continue;
        }

        if (events & SOCK_EOF) {
            log_debug("fd %d got EOF", s->fd);
            s->socket_state = SOCK_EOF;
            session_close(s);
            continue;       // FIXME: this will discard anything in the read buffer
        }
        if (events & SOCK_CAN_READ) {
            s->socket_state |= SOCK_CAN_READ;
            log_debug("fd %d is now readable", s->fd);
            if (session_read(s) < 0)
                session_close(s);
        }
        if (events & SOCK_CAN_WRITE) {
            s->socket_state |= SOCK_CAN_WRITE;
            log_debug("fd %d is now writable", s->fd);
            //TODO - flush output buffer, or do something
        }
    }

    return (0);
}

int
session_poll_enable(struct session *s)
{
    return poll_enable(srv.evcb, s->fd, s, SOCK_CAN_READ);
}
