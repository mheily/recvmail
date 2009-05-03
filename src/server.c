/*		$Id$		*/

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

#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>

#include "dnsbl.h"
#include "mda.h"
#include "options.h"
#include "poll.h"
#include "mda.h"
#include "server.h"
#include "smtp.h"
#include "session.h"
#include "workqueue.h"

static void server_accept(void *if_ptr, int events);

struct server srv;

struct net_interface {
    char name[INET6_ADDRSTRLEN];
    struct sockaddr_storage ss;
    socklen_t ss_len;
    int fd;
    LIST_ENTRY(net_interface) entry;
};

static void drop_privileges(void);

// wierd place for this..
int
protocol_close(struct session *s)
{
    srv.close_hook(s);
    return (0);
}


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
    
    log_info("chroot(2) to %s", srv.chrootdir);
    log_info("setuid(2) to %s(%d)", srv.uid, uid);
}


static void
server_restart(void *unused, int events)
{
    log_error("STUB");
    sleep(1);
}


static void
server_shutdown(void *unused, int events)
{
    struct net_interface *ni;

    log_notice("shutting down");
    //TODO: wait for MDA to complete
    //TODO: wait for DNSBL to complete
    mda_free();
    dnsbl_free(srv.dnsbl);
    //TODO: shutdown the MDA and DNSBL threads
    
    /* Close all listening sockets */
    while ((ni = LIST_FIRST(&srv.if_list)) != NULL) {
        close(ni->fd);
        LIST_REMOVE(ni, entry);
        free(ni);
    }

    log_close();

    poll_shutdown();
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
    LIST_INIT(&srv.if_list);
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

    /* Drop root privilges and call chroot(2) */
    drop_privileges();

    /* Create the MDA thread */
    if (mda_init() < 0) {
        log_error("mda_init() failed");
        return (-1);
    }
    if (pthread_create(&tid, NULL, mda_dispatch, NULL) != 0) {
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


static int
server_bind_addr(struct sockaddr *sa)
{
    struct sockaddr_in sain;
    struct sockaddr_in6 sain6;
    char sa_name[INET6_ADDRSTRLEN];
    socklen_t sa_len;
    struct net_interface *ni;
    int             one = 1;
    int             fd = -1;
    int rv;

    /* Setup the protocol-specific socket structure */
    if (sa->sa_family == AF_INET) {
        memcpy(&sain, sa, sizeof(sain));
        memset(&sain6, 0, sizeof(sain6));
        sa_len = sizeof(sain);
    } else if (sa->sa_family == AF_INET6) {
        memset(&sain, 0, sizeof(sain));
        memcpy(&sain6, sa, sizeof(sain6));
        sa_len = sizeof(sain6);
    } else {
        log_error("unsupported family %d", sa->sa_family);
        return (-1);
    }

    /* Generate a human-readable representation of the socket address */
    rv = getnameinfo(sa, sa_len, &sa_name[0], sizeof(sa_name), NULL, 0, NI_NUMERICHOST);
    if (rv != 0) {
            log_errno("getnameinfo(3): %s", gai_strerror(rv));
            goto errout;
    }

	/* Adjust the port number for non-privileged processes */
	if (getuid() > 0 && srv.port < 1024)
		srv.port += 1000;
    if (sa->sa_family == AF_INET) {
        sain.sin_port = htons(srv.port);
    } else {
        sain6.sin6_port = htons(srv.port);
    }

    /* Don't listen on the loopback address (127.0.0.1 or ::1) */
    if (strcmp(&sa_name[0], "127.0.0.1") == 0 
            || strcmp(&sa_name[0], "::1") == 0) {
        return (0);
    }

	/* Create the socket and bind(2) to it */
	if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
		log_errno("socket(2)");
        goto errout;
    }
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
			 sizeof(one)) != 0) {
		log_errno("setsockopt(3)");
        goto errout;
    }
    if (sa->sa_family == AF_INET) {
	 rv = bind(fd, (struct sockaddr *) &sain, sa_len);
    } else {
	 rv = bind(fd, (struct sockaddr *) &sain6, sa_len);
    }
	if (rv < 0) {
		log_errno("bind(2)");
        goto errout;
    }

	/* Listen for incoming connections */
	if (listen(fd, 100) < 0) {
		log_errno("listen(2)");
        goto errout;
    }

    log_debug("bound to %s port %d (fd=%d)", &sa_name[0], srv.port, fd);

    if ((ni = calloc(1, sizeof(*ni))) == NULL) {
		log_errno("calloc(3)");
        goto errout;
    }
    ni->fd = fd;
    memcpy(&ni->ss, sa, sa_len);
    memcpy(&ni->name, sa_name, sizeof(ni->name));
    ni->ss_len = sa_len;
    LIST_INSERT_HEAD(&srv.if_list, ni, entry);

    /* Monitor the server descriptor for new connections */
    if (poll_enable(fd, POLLIN, server_accept, ni) < 0) { 
        log_errno("poll_enable() (fd=%d)", fd);
        goto errout;
    }
   
    return (0);

errout:
    log_error("unable to bind(2) to %s", &sa_name[0]);
    if (fd >= 0)
        close(fd);
    return (-1);
}


int
server_bind(void)
{
    struct ifaddrs *ifa;
    struct sockaddr *sa;

    if (getifaddrs(&ifa) < 0) {
        log_errno("getifaddrs(3)");
        return (-1);
    }

    for (; ifa != NULL; ifa = ifa->ifa_next) {
        sa = ifa->ifa_addr;
        if (sa != NULL && (sa->sa_family == AF_INET || sa->sa_family == AF_INET6)) {
            if (server_bind_addr(sa) < 0)
                goto errout;
        }
    } 

    freeifaddrs(ifa);
    return (0);

errout:
    freeifaddrs(ifa);
    return (0);
}


static void
server_accept(void *if_ptr, int events)
{
    struct net_interface *ni = (struct net_interface *) if_ptr;
	socklen_t cli_len = ni->ss_len;
    int fd = -1;
	struct session *s;

    if (events & POLLERR) {
        log_errno("bad server socket");
        abort(); // TODO: cleanly
    }
    
    /* Assume: (events & SOCK_CAN_READ) */

    /* Accept the incoming connection */
    if ((fd = accept(ni->fd, (struct sockaddr *) &ni->ss, &cli_len)) < 0) {
        log_errno("accept(2)");
        return;
    }
    log_debug("accept(2) created fd %d", fd);

    /* Create a new session */
    if ((s = session_new(fd)) == NULL) 
        return;

    /* Generate a session ID */
    if (srv.next_sid == ULONG_MAX)
        s->id = srv.next_sid = 1;
    else
        s->id = ++srv.next_sid;

    log_info("accepted connection from %s", socket_get_peername(s->sock)); 
   
    /* TODO: Determine the reverse DNS name for the host */

    /* Monitor the client socket for events */
    /* FIXME: wait until the dnsbl is complete */
    if (socket_poll_enable(s->sock, POLLIN, session_handler, s) < 0) {
        log_error("poll_enable()");
        goto errout;
    }

    if (dnsbl_submit(srv.dnsbl, s) < 0) {
        log_error("dnsbl_submit()");
        goto errout;
    }

    return;

errout:
    log_error("session_accept() failed");
    if (s != NULL) {
        session_close(s);
    }
}


int
server_dispatch(void)
{
    /* Respond to signals */
    if (poll_signal(SIGINT, server_shutdown, &srv) < 0) 
        return (-1);
    if (poll_signal(SIGTERM, server_shutdown, &srv) < 0) 
        return (-1);
    if (poll_signal(SIGHUP, server_restart, &srv) < 0) 
        return (-1);

    return poll_dispatch();
}
