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
read_cb(struct bufferevent *bufev, void *arg)
{
    struct session *s = (struct session *) arg;
    char           *line;
    size_t          len;

    while ((line = evbuffer_readline(bufev->input))) {
	// printf("line=`%s'\n", line);
	len = strlen(line);
	if (s->srv->read_hook(s, line, len) < 0) {
	    if (s->error_count++ > 10) {
		s->srv->reject_hook(s);
		s->state = SESSION_CLOSE;
	    }
	}
	free(line);
    }
}

static void
write_cb(struct bufferevent *bev, void *arg)
{
    struct session *s = (struct session *) arg;

    // printf("** WRITE CB\n");
    if (s->state == SESSION_CLOSE) {
	if (s->srv->close_hook(s) < 0) {
	    /* TODO: graceful shutdown of server */
	}
	close(s->fd);
	session_free(s);
    }
}

static void
error_cb(struct bufferevent *bufev, short what, void *arg)
{
    struct session *s = (struct session *) arg;

    if (what & EVBUFFER_EOF) {
	log_info("Client disconnected\n");
    } else if (what & EVBUFFER_TIMEOUT) {
	log_info("Client timed out due to inactivity\n");
	s->srv->timeout_hook(s);
	s->state = SESSION_CLOSE;
	// TODO: disable input from the client
	return;
    } else {
	log_warning("Socket error!\n");
    }
    bufferevent_free(s->bev);
    close(s->fd);
    free(s);
}

static void
server_accept(int srv_fd, short event, void *arg)
{
    struct session *s;
    socklen_t       cli_len = 0;
    struct sockaddr_in name;
    socklen_t       namelen = sizeof(name);

    if (event != EV_READ) {
	errx(1, "unexpected event %d", event);
    }

    /* Create a new session */
    if ((s = calloc(1, sizeof(*s))) == NULL) {
	/* TODO: handle out-of-memory gracefully */
	return;
    }
    s->srv = (struct server *) arg;
  restart_syscall:
    s->fd = accept(srv_fd, &s->srv->sa, &cli_len);

    /* Retry if accept(2) was interrupted by a signal */
    if (s->fd < 0 && errno == EINTR)
	goto restart_syscall;

    /* Check for a valid connection */
    if (s->fd < 0) {
	log_errno("accept(2)");
	goto error;
    }

    /* Determine the IP address of the client */
    if (getpeername(s->fd, (struct sockaddr *) &name, &namelen) < 0) {
	log_errno("getpeername(2)");
	goto error;
    }
    s->remote_addr = name.sin_addr;

    /* Convert the IP address to ASCII */
    if (inet_ntop(AF_INET, &s->remote_addr,
		  (char *) &s->remote_addr_str,
		  sizeof(s->remote_addr_str)) == NULL) {
	log_errno("inet_ntop(3)");
	goto error;
    }

    /* TODO: Determine the reverse DNS name for the host */

    /* Create a libevent I/O buffer */
    s->bev = bufferevent_new(s->fd, read_cb, write_cb, error_cb, s);
    bufferevent_settimeout(s->bev,
			   s->srv->timeout_read, s->srv->timeout_write);
    bufferevent_enable(s->bev, EV_READ);

    log_info("incoming connection from %s", s->remote_addr_str);

    /* Send the greeting */
    (void) s->srv->accept_hook(s);	// TODO: Check return value

    return;

  error:
    free(s);
}

static void 
server_signal_handler(int signum, short what, void *arg)
{
   switch (signum) {
	   case SIGINT:
		   log_warning("got sigint");
		   abort();
		   break;
	   case SIGHUP:
		   log_warning("got sighup");
		   break;
	   case SIGTERM:
		   log_warning("got sigterm");
		   exit(EXIT_SUCCESS);
		   break;
	   default:
		   log_error("received invalid signal %d", (int) what);
		   exit(EXIT_FAILURE);
   }
}

static void
register_signal_handlers(void)
{
	static struct event ev1, ev2, ev3;

	signal_set(&ev1, SIGINT, server_signal_handler, NULL);
	signal_add(&ev1, NULL);
	signal_set(&ev2, SIGHUP, server_signal_handler, NULL);
	signal_add(&ev2, NULL);
	signal_set(&ev3, SIGTERM, server_signal_handler, NULL);
	signal_add(&ev3, NULL);
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

#if FIXME
	// doesn't work when multiple servers within the same process
	
	/* 
	 * Fork again to create a privileged 'monitor' process
	 * and a non-privileged 'server' process.
	 * The child process becomes the server and the parent process is the
	 * monitor.
	 */
	if ((pid = fork()) < 0)
		err(1, "fork(2)");
	if (pid > 0)
		exit(srv->monitor_hook(srv, pid));
#endif

    } else {
	    logopt |= LOG_PERROR;

    }

    /* Open the log file */
    openlog("", logopt, OPT.log_facility);

    /* Increase the allowable number of file descriptors */
    xsetrlimit(RLIMIT_NOFILE, 50000);

    /* Register the standard signal handling functions */
    register_signal_handlers();
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
server_enable(struct server *srv)
{

    /* TODO: Convert NULL hooks to NOOP hooks */

    /* Generate an event when a connection is pending */
    event_set(&srv->accept_evt, srv->fd, EV_READ | EV_PERSIST, server_accept, srv);
    if (event_add(&srv->accept_evt, NULL) != 0)
	errx(1, "event_add() failed");
}

int
session_write(struct session *s, char *buf, size_t size)
{
#if REUSE
    struct evbuffer *evbuf = evbuffer_new();

    if (evbuffer_add(evbuf, line, size) < 0) {
	warnx("evbuffer_add() failed");
	evbuffer_free(evbuf);
	return -1;
    }
#endif

    return bufferevent_write(s->bev, buf, size);
}


void
session_close(struct session *s)
{
    log_info("closing transmission channel (%d)", 0);
    // TODO: hook function
    s->state = SESSION_CLOSE;
}

void
session_free(struct session *s)
{
    bufferevent_free(s->bev);
    free(s);
}


int
session_fsync(struct session *s, int fd)
{
    if (bufferevent_disable(s->bev, EV_READ) < 0) {
	log_error("bufferevent_disable() failed");
	return -1;
    }
    s->state = SESSION_WAIT;
    /* TODO: use a separate thread to do this */
    return 0;
}
