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

#include <poll.h>


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

/* ------------------------- pollset handling functions -----------------*/

void
server_update_pollset(struct server *srv)
{
    size_t n;
    struct session *s;

    n = PFD_RESERVED;
    LIST_FOREACH(s, &srv->io_wait, entries) {
        srv->pfd[n].fd = s->fd;
        srv->pfd[n++].events = s->events;
    }
    srv->pfd_count = n;
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
    server_update_pollset(srv);
    log_debug("state transition to %d", events);
}

/* Given a file descriptor, return a pointer to the associated session object */
/* NOTE: only works for sessions that are waiting for I/O. */
struct session *
session_lookup(struct server *srv, int fd)
{
    struct session *s;

    LIST_FOREACH(s, &srv->io_wait, entries) {
        if (s->fd == fd)
            return (s);
    }

    return (NULL);
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

        detached = 1;
    } else {
	    logopt |= LOG_PERROR;

    }

    /* Open the log file */
    openlog("", logopt, OPT.log_facility);

    /* Increase the allowable number of file descriptors */
    if (getuid() == 0) {
        limit.rlim_cur = 50000;
        limit.rlim_max = 50000;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
            err(1, "setrlimit failed");
    }

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
    log_debug("listening on port %d", srv->port);
}

static struct session *
server_accept(struct server *srv)
{
	socklen_t cli_len;
    int fd;
	struct session *s;

    cli_len = sizeof(srv->sa);

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

    log_debug("accepted session on fd %d", fd);
    srv->accept_hook(s);
    return (s);
}

static int
client_read(struct session *s)
{
    ssize_t n;
    struct smtpbuf *b = &s->buf;

    for (;;) {
        n = read(s->fd, (b->data + b->len), sizeof(b->data) - b->len);

        /* Ignore interrupts and resume the system call */
        if (n == -1 && errno == EINTR)
            continue;

        /* If no data is available, go to sleep */
        if (n < 0 && errno == EAGAIN) {
            log_debug("got EAGAIN");
            state_transition(s, POLLIN);
            return (1);
        }

        /* Check for fatal errors */
        if (n < 0) {
            /* XXX-error handling */
            log_errno("read(2)");
            errx(1, "FIXME - error handling %d", (int) n);
            return (-1);
        }

        /* Check for EOF */
        if (n == 0) {
            log_debug("got EOF from client");
            return (0);
        }

        /* Update the buffer length */
        b->len += n;
        log_debug("read %zu bytes", b->len);
        return (0);
    }
} 

/* Write data to the client, or fill the write buffer */
void
client_write(struct session *s, const char *buf, size_t len)
{
    ssize_t n;

    for (;;) {
        n = write(s->fd, buf, len);
        
        /* Ignore interrupts */
        if (errno == EINTR) {
            continue;
        }

        /* If everything was written, switch to read-mode */
        if (n == len) {
            state_transition(s, POLLIN);
            return;
        }

        if (errno == EAGAIN) {
            state_transition(s, POLLOUT);

            /* Copy the unwritten portion to a new buffer*/
            buf += n;
            len -= n;
            if (len >= sizeof(s->buf)) 
                err(1, "illegal write"); /* TODO: less drastic */
            memcpy(s->buf.data, buf, len);
            s->buf.len = len;
            s->buf.pos = 0;

        }

        /* Anything else is an error. */
        log_errno("write(2)");
        session_close(s); /* TODO- session_abort() instead */
    }
}

/* Try to read a line of input from the client */
static int 
client_readln(struct session *s)
{
    struct smtpbuf *b = &s->buf;
    int rv;

    /* Read data into the buffer if it is empty or incomplete */
    if (b->len == 0 || b->fragmented)  {
        if ((rv = client_read(s)) != 0)
            return (rv);
    }

    /* WORKAROUND:
     * If the client disconnects abruptly, client_read()
     * will return 0 but len==0.
     */
    if (b->len == 0) {
        log_warning("remote end has disconnected");
        return (-1);
    }

    log_debug("read: len=%zu pos=%zu", b->len, b->pos);

    /* Look for the line terminator inside the buffer */
    for (; b->pos <= b->len; b->pos++) {
        if ((b->data[b->pos] == '\r' && b->data[b->pos + 1] == '\n') 
                || (b->data[b->pos] == '\n')) {

            /* Copy the line to the 'line' field */
            b->line_len = b->pos + 1;
            memcpy(b->line, b->data, b->line_len);

            /* Shift the rest of the buffer all the way to the left */
            /* TODO: optimize this away by creating a 'b->start' variable */
            if (b->data[b->pos] == '\r') {
                b->pos++;
            }
            if (b->pos == b->len) {
                b->len = 0;
                b->fragmented = 0;
            } else {
                memmove(b->data, b->data + b->pos + 1, b->len - b->pos - 1);
                b->len = b->len - b->pos - 1;
            }
            b->pos = 0;
            
            /* Convert the trailing CR or LF into a NUL */
            b->line[b->line_len - 1] = '\0';

            log_debug("line=`%s' line_len=%zu pos=%zu len=%zu", 
                    b->line, b->line_len, b->pos, b->len);

            return (0);
        }
    }

    log_debug("line is fragmented");
    s->buf.fragmented = 1;
    return (1);
}

void
server_dispatch(struct server *srv)
{
	struct session *s;
    int      i, rv, nfds;

    /* Initialize the session table */
    LIST_INIT(&srv->runnable);
    LIST_INIT(&srv->io_wait);
    LIST_INIT(&srv->idle);
    srv->pfd_count = 0;

    /* The first entry in the session table is the server descriptor */
    srv->pfd[0].fd = srv->fd;
    srv->pfd[0].events = POLLIN;
    srv->pfd_count++;
   
	/* Dispatch incoming connections */
	for (;;) {

        /* Wait for I/O activity */
        nfds = poll(srv->pfd, srv->pfd_count, -1);
        if (nfds == -1 || (srv->pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL)))
            err(1, "poll(2)");
        if (nfds == 0) {
            if (errno == EINTR)
                continue;
            else
                err(1, "poll(2)");
        }

        /* Check for pending connection requests */
        if (srv->pfd[0].revents & POLLIN) {
            if ((s = server_accept(srv)) == 0)
                continue;
        }

        for (i = 1; i < srv->pfd_count; i++) {
            if (srv->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
                log_debug("POLLERR/HUP on session %d", i);
                errx(1, "hi");

                /* FIXME: error handling here */
            } else if (srv->pfd[i].revents & POLLIN) {
                log_debug("POLLIN on session %d", i);

                if ((s = session_lookup(srv, srv->pfd[i].fd)) == NULL)
                    errx(1, "session_lookup failed");
                
                /* Read a line of input, process it, and repeat until
                 * a read(2) would block. */
                /* FIXME: Could a client DOS the server by sending data ad infinitum? */
                do {
                    rv = client_readln(s);
                    if (rv < 0) {
                        log_info("readln failed");
                        session_close(s);
                    } else if (rv > 0) {
                        ; /* EAGAIN */
                    } else {
                        srv->read_hook(s);
                    }
                    if (s->closed) {
                        free(s);        //TODO: recycle by putting on the idle list 
                    }
                    /* TODO: make configurable, max_errors or something */
                    if (s->errors > 10) {
                        srv->reject_hook(s);
                        session_close(s);
                    }
                } while (!s->closed && rv == 0);

            } else if (srv->pfd[i].revents & POLLOUT) {
                log_debug("POLLOUT on session %d", i);
                /* XXX-TODO */
            }
        }

        /* Check for any socket read or write ready conditions */
        /*XXX-todo*/
    }
}
