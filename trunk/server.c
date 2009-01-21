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

#include "recvmail.h"

#include "poll.h"
#include "thread-pool.h"
#include "server.h"
#include "session.h"

/* From fsyncer.c */
int fsyncer_init(struct server *);


// wierd place for this..
int
protocol_close(struct server *srv, struct session *s)
{
    srv->close_hook(s);
    return (0);
}

void
state_transition(struct session *s, int events)
{
    struct server *srv = s->srv;

    LIST_REMOVE(s, entries);
    if (events) {
        LIST_INSERT_HEAD(&srv->io_wait, s, entries);
    } else {
        LIST_INSERT_HEAD(&srv->runnable, s, entries);
    }
    s->events = events;
    //FIXME:server_update_pollset(srv);
    log_debug("state transition to %d", events);
}


int
server_disconnect(struct server *srv, int fd)
{
    /* Unregister the file descriptor */
    if (poll_disable(srv->evcb, fd) != 0) {
        log_error("unable to disable events for fd # %d", fd);
        (void) atomic_close(fd);
        return (-1);
    }

    (void) atomic_close(fd);

    return (0);
}

/*
 * drop_privileges(uid,gid,chroot_to)
 * 
 * Remove root privileges from the running process.
 * 
 * If the process is running as root, change the UID and GID to the ID's of
 * <uid> and <gid>, respectively.
 * 
 * Also chroot(2) to another directory, if desired.
 * 
 */
void
drop_privileges(const char *user, const char *group, const char *chroot_to)
{
    struct group   *grent;
    struct passwd  *pwent;
    uid_t           uid;
    gid_t           gid;

    /* Chdir into the chroot directory */
    if (chroot_to && (chdir(chroot_to) < 0)) 
        err(1, "chdir(2) to `%s'", chroot_to);

    /* Only root is allowed to drop privileges */
    if (getuid() > 0) {
        log_warning("cannot drop privileges if UID != 0");
        return;
    }

    /* Convert the symbolic group to numeric GID */
    /* Convert the symbolic user-id to the numeric UID */
    if ((grent = getgrnam(group)) == NULL) 
        err(1, "a group named '%s' does not exist", group);
    if ((pwent = getpwnam(user)) == NULL)
        err(1, "a user named '%s' does not exist", user);
    gid = grent->gr_gid;
    uid = pwent->pw_uid;

    /* chroot */
    if (chroot_to && (chroot(chroot_to) < 0))
        err(1, "chroot(2)");

    /* Set the real UID and GID */
    if (setgid(gid) < 0)
        err(1, "setgid(2)");
    if (setuid(uid) < 0)
        err(1, "setuid(2)");
    
    log_info("setuid(2) to %s(%d)", user, uid);
}


static void
register_signal_handlers(void)
{
#if XXX_FIXME
	static struct event ev1, ev2, ev3;

	signal_set(&ev1, SIGINT, server_signal_handler, NULL);
	signal_add(&ev1, NULL);
	signal_set(&ev2, SIGHUP, server_signal_handler, NULL);
	signal_add(&ev2, NULL);
	signal_set(&ev3, SIGTERM, server_signal_handler, NULL);
	signal_add(&ev3, NULL);
#endif
}

/* ------------------- Public functions ----------------------- */



/* Initialization routines common to all servers */
void
server_init(void)
{
    struct rlimit   limit;
    int             logopt = LOG_NDELAY;
    pid_t           pid,
                    sid;

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
    } else {
	    logopt |= LOG_PERROR;

    }

    /* Open the log file */
    openlog(OPT.log_ident, logopt, OPT.log_facility);
    setlogmask(OPT.log_level);

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

    /* Register the standard signal handling functions */
    register_signal_handlers();
}


int
server_bind(struct server *srv)
{
    struct sockaddr_in srv_addr;
    int             one = 1;
    int             fd = -1;

    /* Create the event source */
    if ((srv->evcb = poll_new()) == NULL) {
        log_error("unable to create the event source");
        return (-1);
    }

    /* Create a thread pool for blocking system calls */
    // TODO: determine the best # of workers
    if ((srv->tpool = thread_pool_create(4)) == NULL) {
        log_error("unable to create a thread pool");
        return (-1);
    }

    /* Start the fsync(2) worker thread */
    if (fsyncer_init(srv) < 0) {
        log_error("unable to create the fsyncer thread");
        return (-1);
    }

	/* Adjust the port number for non-privileged processes */
	if (getuid() > 0 && srv->port < 1024)
		srv->port += 1000;

	/* Initialize the socket variable */
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr = srv->addr;
	srv_addr.sin_port = htons(srv->port);

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

    log_debug("listening on port %d", srv->port);

    srv->fd = fd;

    return (0);

errout:
    if (fd >= 0)
        close(fd);
    srv->fd = -1;
    return (-1);
}

static struct session *
server_accept(struct server *srv)
{
	socklen_t cli_len;
    int fd;
	struct session *s;

    cli_len = sizeof(srv->sa);

    log_debug("incoming connection on srv->fd %d", srv->fd);

    /* Accept the incoming connection */
    do { 
        fd = accept(srv->fd, &srv->sa, &cli_len);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        log_errno("accept(2)");
        return (NULL);
    }

    /* Create a new session */
    if ((s = session_new(fd)) == NULL) 
        return (NULL);
    s->srv = srv;

    /* Mark the session as runnable, but do not monitor I/O readiness */
    LIST_INSERT_HEAD(&srv->runnable, s, entries);

    poll_enable(s->srv->evcb, s->fd, s, SOCK_CAN_READ);

    log_debug("accepted session on fd %d", fd);
    srv->accept_hook(s);
    return (s);
}

static void
session_read(struct session *s) 
{
    ssize_t n;

    if ((n = socket_readv(&s->in_buf, s->fd)) < 0) {
        log_info("readln failed");
        session_close(s);
        return;
    } 
    
    /* Handle EAGAIN if no data was read. */
    if (n == 0) {
            log_debug("got EAGAIN");
            state_transition(s, SOCK_CAN_READ);
            return;
    }

    // TODO: check return value
    s->handler(s);

    // XXX-Very bad.. probably
    if (s->closed) {
        free(s);        //TODO: recycle by putting on the idle list 
    }
}

int
server_dispatch(struct server *srv)
{
    int events;
    const void *srv_udata = (void *) -1L;
	struct session *s;

    /* Initialize the session table */
    pthread_mutex_init(&srv->sched_lock, NULL);
    LIST_INIT(&srv->runnable);
    LIST_INIT(&srv->io_wait);
    LIST_INIT(&srv->idle);
    LIST_INIT(&srv->fsync_queue);

    /* The first entry in the session table is the server descriptor */
    if (poll_enable(srv->evcb, srv->fd, (void *) srv_udata, SOCK_CAN_READ) < 0) { 
        log_errno("poll_enable() (srv->fd=%d)", srv->fd);
        return (-1);
    }
   
	/* Dispatch incoming connections */
	for (;;) {

        /* Get one event */
        log_debug("waiting for event");
        if ((s = poll_wait(srv->evcb, &events)) == NULL) {
            log_errno("poll_wait()");
            return (-1);
        }

        /* Special case for a pending accept(2) on the listening socket */
        if (s == srv_udata) {
            if (events & SOCK_ERROR) {
                log_errno("bad server socket");
                return (-1);
            }
            if ((events & SOCK_CAN_READ) && (s = server_accept(srv)) == NULL) {
                log_errno("server_accept()");
                return (-1);
            }
        }

        if (events & SOCK_EOF) {
            err(1, "got eof");//FIXME
                //log_debug("POLLERR/HUP/NVAL on session %d (fd %d)", i, s->fd);
                //session_close(s);
                //free(s); //XXX-FIXME-recycle it.        
        }
        if (events & SOCK_CAN_READ) {
            //log_debug("POLLIN on session %d (fd %d)", i, s->fd);
            log_debug("fd %d is now readable", s->fd);
            session_read(s);
        }
        if (events & SOCK_CAN_WRITE) {
            log_debug("fd %d is now writable", s->fd);
            s->events |= SOCK_CAN_WRITE;
        }
    }

    return (0);
}
