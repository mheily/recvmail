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
 * daemonize()
 * 
 * Detatch from the controlling terminal and become a daemon.
 * 
 */
int daemonize()
{
	pid_t	pid, sid;

	syslog(LOG_DEBUG,"pid %d detatching from the controlling terminal", getpid());

	/* Create a new process */
	if ((pid = fork()) < 0) 
		err(1, "fork(2)");
	if (pid > 0)
		exit(0);

	/* Create a new session and become the session leader */
	if ((sid = setsid()) < 0)
		err(1, "setsid(2)");

	/* Close all inherited STDIO file descriptors */
	close(0);
	close(1);
	close(2);

	return 0;
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
int
drop_privileges(const char * user,
		const char * group,
		const char * chroot_to
		)
{
	struct group   *grent;
	struct passwd  *pwent;
	uid_t uid;
	gid_t gid;

	/* Chdir into the chroot directory */
	if (chroot_to && (chdir(chroot_to) < 0)) {
		log_warning("chdir(2) to `%s'", chroot_to);
		return -1;
	}

	/* Only root is allowed to drop privileges */
	if (getuid() > 0) {
		log_warning("cannot drop privileges");
		return 0;
	}

	grent = NULL;
	pwent = NULL;

	/* Convert the symbolic group to numeric GID */
	if ((grent = getgrnam(group)) == NULL) {
		syslog(LOG_ERR,"a group named '%s' does not exist", group);
		return -1;
	}
	gid = grent->gr_gid;

	/* Convert the symbolic user-id to the numeric UID */
	if ((pwent = getpwnam(user)) == NULL) {
		syslog(LOG_ERR,"a group named '%s' does not exist", group);
		return -1;
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

	return 0;
}

static void
read_cb(struct bufferevent *bufev, void *arg)
{
	struct session *s = (struct session *) arg;
	char *line;
	size_t len;

	while ((line = evbuffer_readline(bufev->input))) {
		//printf("line=`%s'\n", line);
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

	//printf("** WRITE CB\n");
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
	socklen_t  cli_len = 0;
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	
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
	if (getpeername(s->fd, (struct sockaddr *) & name, &namelen) < 0) {
		log_errno("getpeername(2)");
		goto error;
	}
	s->remote_addr = name.sin_addr;

	/* Determine the reverse DNS name for the host */
	/* FIXME - This causes blocking */
	if (inet_ntop(AF_INET, &s->remote_addr, 
				(char *) &s->remote_addr_str, 
				sizeof(s->remote_addr_str)) == NULL) 
	{
		log_errno("inet_ntop(3)");
		goto error;
	}

	/* Create a libevent I/O buffer */
	s->bev = bufferevent_new(s->fd, read_cb, write_cb, error_cb, s);
	bufferevent_settimeout(s->bev, 
			s->srv->timeout_read, 
			s->srv->timeout_write);
	bufferevent_enable(s->bev, EV_READ);

	log_info("incoming connection from %s", s->remote_addr_str);

	/* Send the greeting */
	(void) s->srv->accept_hook(s); //TODO: Check return value

	return;

error:
	free(s);
}

/* ------------------- Public functions ----------------------- */

/*
 * start_smptd(smtpd_config *config)
 *
 * Perform the essential functions of the mail server.
 *
 * 1. Create a socket and bind to port 25 2. Drop privileges and chroot(2) to
 * /var/mail 3. Listen for incoming connections 4. Fork and create a child
 * process for each connection
 *
 */
int
server_start(struct server * srv)
{
	struct event       srv_evt;
	struct sockaddr_in srv_addr;
	int logopt = LOG_NDELAY;
	int             one = 1;
	int 		i;

	/* TODO: Convert NULL hooks to NOOP hooks */

	/* Adjust the port number for non-privileged processes */
	if (getuid() > 0 && srv->port < 1024) 
		srv->port += 1000;

	if (srv->daemon) {

		/* Detatch from the controlling terminal */
		if (daemonize() < 0)
			errx(1, "unable to daemonize");

	}

	/* Open the log file */
	if (!srv->daemon)
		logopt |=  LOG_PERROR;
	openlog("", logopt, srv->log_facility);

	/* Increase the allowable number of file descriptors */
	xsetrlimit(RLIMIT_NOFILE, 50000); 

	/* Initialize the event library */
	(void) event_init();

	/* Initialize the socket variable */
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr = srv->addr;
	srv_addr.sin_port = htons(srv->port);

	/* Create the socket and bind(2) to it */
	if ((srv->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err(1, "Cannot create socket");
	if (setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) != 0)
		err(1, "setsockopt(3)");
	if (bind(srv->fd, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) < 0)
		err(1, "Could not bind to the socket");

	/* Drop privileges and chroot() to /var/mail */
	i = drop_privileges(srv->uid, srv->gid, srv->chrootdir);
	if (i < 0)
		errx(1, "unable to drop privileges");

	/* Listen for incoming connections */
	if (listen(srv->fd, 100) < 0)
		err(1, "listen(2) failed");

	/* Generate an event when a connection is pending */
	event_set(&srv_evt, srv->fd, EV_READ | EV_PERSIST, server_accept, srv);
	if (event_add(&srv_evt, NULL) != 0)
		errx(1, "event_add() failed");

	/* Wait forevent, dispatching events */
	event_dispatch();

	/* NOTREACHED */
	return 0;
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
