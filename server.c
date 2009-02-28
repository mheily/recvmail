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

#include <grp.h>
#include <pwd.h>
#include <sys/resource.h>
#include <unistd.h>

#include <sys/types.h>  
#include <event.h>  

#include "atomic.h"
#include "options.h"
#include "poll.h"
#include "server.h"
#include "session.h"

/* Globals */
struct server srv;

static void drop_privileges(void);
static int  server_bind(void);
static void server_accept(int fd, short event, void *unused);

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
int
server_init(struct server *_srv)
{
    struct rlimit   limit;
    pid_t           pid,
                    sid;

    memcpy(&srv, _srv, sizeof(srv));

    /* Initialize the work queue */
    STAILQ_INIT(&srv.workq);
    pthread_mutex_init(&srv.workq_lock, NULL);
    pthread_cond_init(&srv.workq_not_empty, NULL);

    /* Initialize the session table */
    LIST_INIT(&srv.client);

    /* FIXME - kludge */
    srv.uid = OPT.uid;

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

    /* Increase the allowable number of file descriptors */
    /* Note: the '+ 50' allows some headroom for logfds, etc. */
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        err(1, "getrlimit failed");
    log_debug("RLIMIT_NOFILE cur=%lu max=%lu", limit.rlim_cur, limit.rlim_max);
    if (getuid() == 0) {
        limit.rlim_cur = OPT.max_clients + 50;
        limit.rlim_max = OPT.max_clients + 50;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            log_errno("setrlimit(3) RLIMIT_NOFILE");
            goto errout;
        }
    }

    /* Enable coredumps */
    if (getrlimit(RLIMIT_CORE, &limit) != 0)
        err(1, "getrlimit failed");
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit) != 0)
        err(1, "setrlimit failed");

    /* Register the standard signal handling functions */
    register_signal_handlers();

    /* Call the protocol-specific initialization function */
    if (srv.init_hook() < 0) {
        log_error("init_hook() failed");
        goto errout;
    }

    if (server_bind() != 0) 
        return (-1);

    return (0);

errout:
    return (-1);
}


static void 
server_accept(int srv_fd, short event, void *unused)
{
    socklen_t cli_len = sizeof(srv.sa);
    int fd;
    struct session *s;

    /* Accept the incoming connection */
    do { 
        fd = accept(srv.fd, &srv.sa, &cli_len);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        log_errno("accept(2)");
        return;
    }
    log_debug("incoming connection on fd %d", srv.fd);

    /* Create a new session */
    if ((s = session_new(fd)) == NULL) {
        // TODO: send 421 SMTP error
        close(fd);
        return;
    }

    s->worker = srv.worker;                  // FIXME hardcoded for 1 worker
    log_debug("accepted session on fd %d", fd);
    srv.accept_hook(s);

    /* TODO - enable polling for events */
}

#ifdef DEADWOOD
static int
workq_add(struct session *s)
{
    struct work *w;

    if ((w = malloc(sizeof(*w))) == NULL) {
        log_errno("malloc");
        return (-1);
    }

    w->session = s;

    pthread_mutex_lock(&srv.workq_lock);
    STAILQ_INSERT_TAIL(&srv.workq, w, entries);  // TODO: want to put at the end of the list
    pthread_cond_signal(&srv.workq_not_empty);
    pthread_mutex_unlock(&srv.workq_lock);

    return (0);
}
#endif

#if TODO
static void
worker_dispatch(struct session *s)
{
    log_debug("reading input");
    if (fgets((char *) &s->buf, sizeof(s->buf), s->in) == NULL) {
        log_errno("fgets(3)");
        goto errout;
    }
    if (srv.read_hook(s) < 0)
        goto errout;
    if (s->smtp_state == SMTP_STATE_QUIT)
        goto errout;

    return;

errout:
            session_close(s);
            free(s);
}
#endif

#if DEADWOOD
static void *
worker_main(struct worker *self)
{
    struct work *w;

    pthread_mutex_lock(&srv.workq_lock);

    for (;;) {

        /* Wait until there is work to be done. */
        if (STAILQ_EMPTY(&srv.workq) &&
                pthread_cond_wait(&srv.workq_not_empty, &srv.workq_lock) != 0) {
            log_error("pthread_cond_wait() failed");
            break;
        }

        /* Remove the first unit of work from the head of the queue */
        if ((w = STAILQ_FIRST(&srv.workq)) == NULL)
            continue;
        STAILQ_REMOVE_HEAD(&srv.workq, entries);
        pthread_mutex_unlock(&srv.workq_lock);

        /* Process the session */
        if (w != NULL) {
            w->session->worker = self; 
            worker_dispatch(w->session);
            free(w);
        }

        pthread_mutex_lock(&srv.workq_lock);
    }

    pthread_mutex_unlock(&srv.workq_lock);
    return (0);
}

#endif

static int
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

    drop_privileges();

    /* Create a per-thread 'worker' object (TODO - more workers) */
    srv.num_workers = 1;
    srv.worker = calloc(1, sizeof(struct worker));
    srv.worker[0].id = 0;
    srv.worker[0].delivery_counter = 0;

    /* Monitor the socket and call accept(2) when a connection is waiting */
    event_set(&srv.ev_accept, fd, EV_READ | EV_PERSIST, server_accept, NULL);
    event_add(&srv.ev_accept, NULL);

    return (0);

errout:
    if (fd >= 0)
        close(fd);
    srv.fd = -1;
    return (-1);
}
