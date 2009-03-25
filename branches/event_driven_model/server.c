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
#include <sys/resource.h>
#include <unistd.h>

#include "dnsbl.h"
#include "mda.h"
#include "options.h"
#include "poll.h"
#include "server.h"
#include "smtp.h"
#include "session.h"
#include "aliases.h"
#include "workqueue.h"

struct server srv;

static void drop_privileges(void);

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


static void
server_shutdown(void *unused, int events)
{
    //TODO: wait for MDA to complete
    //TODO: wait for DNSBL to complete
    mda_free(srv.mda);
    dnsbl_free(srv.dnsbl);
    //TODO: shutdown the MDA and DNSBL threads
    aliases_free();

    close(srv.fd);
    close(srv.signalfd[0]);
    close(srv.signalfd[1]);

    poll_free(srv.evcb);

    closelog();

    if (!OPT.daemon) {
        close(0);
        close(1);
        close(2);
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
    limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &limit) != 0)
        err(1, "setrlimit failed");

    /* Create the event source */
    if ((srv.evcb = poll_new()) == NULL) {
        log_error("unable to create the event source");
        return (-1);
    }

    /* Drop root privilges and call chroot(2) */
    drop_privileges();

    /* Create the MDA thread */
    srv.mda = mda_new();
    if (pthread_create(&tid, NULL, mda_dispatch, srv.mda) != 0) {
        log_errno("pthread_create(3)");
        return (-1);
    }

    /* Create the DNSBL thread */
    srv.dnsbl = dnsbl_new("zen.spamhaus.org");
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

    log_debug("listening on fd %d port %d", fd, srv.port);

    srv.fd = fd;

    return (0);

errout:
    if (fd >= 0)
        close(fd);
    srv.fd = -1;
    return (-1);
}


static void
server_accept(void *unused, int events)
{
    struct sockaddr_in cli;
	socklen_t cli_len = sizeof(cli);
    int fd;
	struct session *s;

    if (events & SOCK_ERROR) {
        log_errno("bad server socket");
        return; //FIXME - Should abort
    }
    
    /* Assume: (events & SOCK_CAN_READ) */

    log_debug("incoming connection on fd %d", srv.fd);

    /* Accept the incoming connection */
    if ((fd = accept(srv.fd, &srv.sa, &cli_len)) < 0) {
        log_errno("accept(2)");
        return;
    }
    log_debug("accept(2) created fd %d", fd);

    /* Create a new session */
    if ((s = session_new()) == NULL) 
        return;
    s->fd = fd;

    /* Generate a session ID */
    if (srv.next_sid == ULONG_MAX)
        s->id = srv.next_sid = 1;
    else
        s->id = ++srv.next_sid;

    /* Determine the IP address of the client */
    if (getpeername(fd, (struct sockaddr *) &cli, &cli_len) < 0) {
            log_errno("getpeername(2) of fd %d", fd);
            //FIXME: fatal? goto errout;
    }
    s->remote_addr = cli.sin_addr;

    /* Use non-blocking I/O */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
            log_errno("fcntl(2)");
            //FIXME: fatal? goto errout;
    }

    /* TODO: Determine the reverse DNS name for the host */

    /* Monitor the client socket for events */
    //FIXME:Was poll_enable(s->fd, SOCK_CAN_READ | SOCK_CAN_WRITE, session_handler, s);
    poll_enable(s->fd, SOCK_CAN_READ, session_handler, s);

    dnsbl_submit(srv.dnsbl, s);
}


int
server_dispatch(void)
{
    /* Monitor the signal catching thread */
    if (poll_enable(srv.signalfd[0], SOCK_CAN_READ, server_shutdown, &srv) < 0) { 
        log_errno("poll_enable() signalfd %d", srv.signalfd[0]);
        return (-1);
    }

    /* Monitor the server descriptor for new connections */
    if (poll_enable(srv.fd, SOCK_CAN_READ, server_accept, &srv) < 0) { 
        log_errno("poll_enable() (srv.fd=%d)", srv.fd);
        return (-1);
    }
   
    return poll_dispatch(srv.evcb);
}
