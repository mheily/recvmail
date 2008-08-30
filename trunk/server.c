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

#include "recvmail.h"

#include <sys/queue.h>

struct fdwatch {
        int fd;                 /* File descriptor */
        int watch;              /* Events to monitor: EPOLLIN | EPOLLOUT */
        int state;              /* Current socket state: EPOLLIN | EPOLLOUT */
        LIST_ENTRY(fdwatch) entries;
};

LIST_HEAD(, fdwatch) WATCH;
pthread_mutex_t WATCH_MUTEX = PTHREAD_MUTEX_INITIALIZER;

/* ------------------- Private functions ----------------------- */


/*
 * xsetrlimit(resource,max)
 *
 * Wrapper for setrlimit(2) to set per-process resource limits
 *
 */
void
xsetrlimit(int resource, rlim_t max)
{
    struct rlimit   limit;

    if (getuid() == 0) {
	limit.rlim_cur = max;
	limit.rlim_max = max;
	if (setrlimit(resource, &limit) != 0)
	    err(1, "setrlimit failed");
    }
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
	//log_warning("cannot drop privileges");
	return;
    }

    grent = NULL;
    pwent = NULL;

    /* Convert the symbolic group to numeric GID */
    if ((grent = getgrnam(group)) == NULL) {
	syslog(LOG_ERR, "a group named '%s' does not exist", group);
	abort();
    }
    gid = grent->gr_gid;

    /* Convert the symbolic user-id to the numeric UID */
    if ((pwent = getpwnam(user)) == NULL) {
	syslog(LOG_ERR, "a group named '%s' does not exist", group);
	abort();
    }
    uid = pwent->pw_uid;

    /* chroot */
    if (chroot_to && (chroot(chroot_to) < 0))
	err(1, "chroot(2)");

    /* Set the real GID */
    if (setgid(gid) < 0)
	err(1, "setgid(2)");

    /* Set the real UID */
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
    int             logopt = LOG_NDELAY;
    pid_t           pid,
                    sid;

    if (OPT.daemon) {

	syslog(LOG_DEBUG,
	       "pid %d detatching from the controlling terminal",
	       getpid());

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

    } else {
	    logopt |= LOG_PERROR;

    }

    /* Open the log file */
    openlog("", logopt, OPT.log_facility);

    /* Increase the allowable number of file descriptors */
    xsetrlimit(RLIMIT_NOFILE, 50000);

    /* Register the standard signal handling functions */
    register_signal_handlers();

    LIST_INIT(&WATCH);
}


void
server_bind(struct server *srv)
{
    struct sockaddr_in srv_addr;
    int             one = 1;

	/* Adjust the port number for non-privileged processes */
	if (getuid() > 0 && srv->port < 1024)
		srv->port += 1000;

	/* Run the protocol-specific hook function */
	if (srv->start_hook(srv) < 0) 
		err(1, "start_hook() failed");

	/* Initialize the socket variable */
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr = srv->addr;
	srv_addr.sin_port = htons(srv->port);

	/* Create the socket and bind(2) to it */
	if ((srv->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err(1, "Cannot create socket");
	if (setsockopt
			(srv->fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
			 sizeof(one)) != 0)
		err(1, "setsockopt(3)");
	if (bind(srv->fd, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) < 0)
		err(1, "Could not bind to the socket");

	/* Listen for incoming connections */
	if (listen(srv->fd, 100) < 0)
		err(1, "listen(2) failed");
}

void
server_dispatch(struct server *srv)
{
	socklen_t cli_len;
	pthread_t tid;
	struct session *s;

	/* Dispatch incoming connections */
	for (;;) {

		/* Create a new session */
		if ((s = calloc(1, sizeof(*s))) == NULL) {
			/* TODO: handle out-of-memory gracefully */
			sleep(5);
			continue;
		}
		s->srv = srv;

		/* Wait for a new connection */
		s->fd = accept(s->srv->fd, &s->srv->sa, &cli_len);
		if (s->fd < 0 && errno == EINTR)
			continue;
		if (s->fd < 0)
			err(1, "accept(2)");

		/* Handle the session in a seperate thread */
		if (pthread_create(&tid, NULL, (void *(*)(void *)) session_init, s) != 0) {
			/* TODO - error handling */
			close(s->fd);
			continue;
		}
	}
}


void
server_watch(int fd, int event_type)
{
        struct fdwatch *w;

        /* Create a watch */
        if ((w = malloc(sizeof(*w))) == NULL)
                err(1, "malloc failed");
        w->fd = fd;
        w->watch = event_type;
        w->state = 0;

        /* Add to the list */
        mutex_lock(&WATCH_MUTEX);
        LIST_INSERT_HEAD(&WATCH, w, entries);
        mutex_unlock(&WATCH_MUTEX);
}
