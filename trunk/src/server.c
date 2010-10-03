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


#include <grp.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "recvmail.h"

static void server_accept(void *if_ptr);
static void server_shutdown(void *unused);
static void server_restart(void *unused);

struct server srv;

struct net_interface {
    char name[INET6_ADDRSTRLEN];
    struct sockaddr_storage ss;
    struct protocol *proto;
    socklen_t ss_len;
    int fd;
    int use_tls;
    LIST_ENTRY(net_interface) entry;
};

/* TODO: refactor to eliminate copy+paste */
/* TODO: error checking */
static int
install_signal_handlers(struct server *srv)
{
    dispatch_source_t ds;
    
    signal(SIGINT, SIG_IGN);
    ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 
            0, dispatch_get_main_queue());
    dispatch_source_set_event_handler_f(ds, server_shutdown);
    dispatch_resume(ds);

    signal(SIGTERM, SIG_IGN);
    ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 
            0, dispatch_get_main_queue());
    dispatch_source_set_event_handler_f(ds, server_shutdown);
    dispatch_resume(ds);

    signal(SIGHUP, SIG_IGN);
    ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGHUP, 
            0, dispatch_get_main_queue());
    dispatch_source_set_event_handler_f(ds, server_restart);
    dispatch_resume(ds);

    return (0);
}

static int
pidfile_check(void)
{
    char *buf = NULL;
    size_t len;
    pid_t pid;
    char *pidfile;

    if (asprintf(&pidfile, "/var/run/%s.pid", OPT.log_ident) < 0)
        err(1, "out of memory");

    if (file_exists(pidfile)) {
        if ((len = file_read(&buf, pidfile)) < 0)
            err(1, "unable to read pidfile");
        pid = atoi(buf);
        if (kill(pid, 0) == 0) {
            free(pidfile);
            free(buf);
            log_error("another %s is already running with pid # %d", 
                 OPT.log_ident, pid);
            return (-1);
        }
    }

    free(pidfile);
    free(buf);
    return (0);
}

static void
pidfile_create(void)
{
    char *pidfile;
    char *pidstr;
    int fd;

    /* Generate the path and output buffer */
    if ((asprintf(&pidfile, "/var/run/%s.pid", OPT.log_ident) < 0) ||
            (asprintf(&pidstr, "%d", getpid()) < 0)) 
        err(1, "out of memory");

    fd = open(pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        log_errno("open(2) of %s", pidfile);
        abort();
    }
    if (write(fd, pidstr, strlen(pidstr)) < strlen(pidstr)) {
        log_errno("write(2) to %s", pidfile);
        abort();
    }
    if (close(fd) < 0) {
        log_errno("close(2) of %s", pidfile);
        abort();
    }

    free(pidfile);
    free(pidstr);
}

static int
drop_privileges(const char *user)
{
    char           *chrootdir;
    struct passwd  *pwent;
    uid_t           uid;
    gid_t           gid;

    /* Lookup the user-ID */
    if ((pwent = getpwnam(user)) == NULL) {
        log_errno("a user named '%s' does not exist", user);
        return (-1);
    }
    uid = pwent->pw_uid;
    gid = pwent->pw_gid;
    chrootdir = pwent->pw_dir;

    /* Make sure the home directory is valid. */
    if (strcmp(chrootdir, "") == 0 || strcmp(chrootdir, "/") == 0) {
        log_error("user '%s' has illegal home directory '%s'", 
                   user, chrootdir);
        return (-1);
    }

    /* Chdir into the chroot directory */
    if (chrootdir && (chdir(chrootdir) < 0)) {
        log_errno("chdir(2) to `%s'", chrootdir);
        return (-1);
    }


    /* Only root is allowed to drop privileges */
    if (getuid() > 0) {
        log_warning("cannot drop privileges if UID != 0");
        return (0);
    }

    /* Populate the chroot environment with required files */
    if (access("etc", F_OK) != 0) {
        if (errno != ENOENT) {
            log_errno("access(2) of `etc'");
            return (-1);
        }
        if (mkdir("etc", 0755) != 0) {
            log_errno("mkdir(2) of `etc'");
            return (-1);
        }
    }
    (void) system("cp /etc/resolv.conf ./etc"); //FIXME: error check

#if TODO
// isn't needed yet...    
    if (access("dev", F_OK) != 0) {
        if (errno != ENOENT) {
            log_errno("access(2) of `dev'");
            return (-1);
        }
        if (mkdir("dev", 0755) != 0) {
            log_errno("mkdir(2) of `dev'");
            return (-1);
        }
    }
    (void) system("cp /dev/null ./dev"); //FIXME: error check
    //TODO: solaris may need more devices
#endif

    /* chroot */
    if (chroot(chrootdir) < 0) {
        log_errno("chroot(2) to `%s'", chrootdir);
        return (-1);
    }

    /* Set the real UID and GID */
    if (setgid(gid) < 0) {
        log_errno("setgid(2)");
        return (-1);
    }
    if (setuid(uid) < 0) {
        log_errno("setuid(2)");
        return (-1);
    }
    
    log_info("chroot(2) to %s", chrootdir);
    log_info("setuid(2) to %s (%d:%d)", user, uid, gid);
    return (0);
}

static void
server_restart(void *unused)
{
    log_error("STUB");
    sleep(1);
}

static void
server_shutdown(void *unused)
{
    struct net_interface *ni;

    log_notice("shutting down");

    (void) srv.proto->shutdown_hook();  /* TODO: error handling */

    /* Close all listening sockets */
    while ((ni = LIST_FIRST(&srv.if_list)) != NULL) {
        close(ni->fd);
        LIST_REMOVE(ni, entry);
        free(ni);
    }

    log_close();
    exit(0);        /* TODO: set non-zero for SIGINT */
}

/* Initialization routines common to all servers */
int
server_init(int argc, char *argv[], struct protocol *proto)
{
    struct rlimit   limit;
    pid_t           pid,
                    sid;

    if (pidfile_check() < 0)
        err(1, "another process is running");

    memset(&srv, 0, sizeof(srv));
    srv.proto = proto;
    LIST_INIT(&srv.if_list);
    if (session_table_init() < 0)
        return (-1);

    if (options_parse(argc, argv) < 0) {
        log_error("options_parse() failed");
        return (-1);
    }
#if TODO
    if (tls_init() < 0) {
        log_error("tls_init() failed");
        return (-1);
    }
#endif
    if (OPT.daemon) {

        /* Create a new process */
        if ((pid = fork()) < 0)
            err(1, "fork(2)");

        /* Terminate the parent process */
        if (pid > 0)
            exit(0);

        pidfile_create();

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

    /* Enable coredumps */
    limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        log_errno("setrlimit(RLIMIT_CORE)");
        abort();
    }

    /* These should occur after all fork(2) calls are complete. */
    if (resolver_init() < 0) {
        log_error("resolver initialization failed");
        return (-1);
    }
    if (workqueue_init() < 0) {
        log_error("workqueue initialization failed");
        return (-1);
    }

    /* Bind to the server socket */
    if (server_bind() < 0)
        errx(1, "server_bind() failed");

    /* Increase the allowable number of file descriptors */
    if (getuid() == 0) {
        limit.rlim_cur = limit.rlim_max = sysconf(_SC_OPEN_MAX);
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            log_errno("setrlimit(RLIMIT_NOFILE)");
            abort();
        }
    }

    /* Drop root privilges and call chroot(2) */
    if (drop_privileges(OPT.uid) < 0)
        err(1, "unable to drop privileges");

    if (install_signal_handlers(&srv) < 0)
        err(1, "unable to install signal handlers");

    /* Run the protocol-specific initialization routines. */
    return srv.proto->init_hook();
}

static int
server_bind_addr(struct sockaddr *sa, struct protocol *proto)
{
    u_int port;
    struct sockaddr_in sain;
    struct sockaddr_in6 sain6;
    char sa_name[INET6_ADDRSTRLEN];
    socklen_t sa_len;
    struct net_interface *ni;
    dispatch_source_t ds;
    int             one = 1;
    int             fd = -1;
    int rv;

    /* Calculate sa_len */
    if (sa->sa_family == AF_INET) {
        sa_len = sizeof(sain);
    } else if (sa->sa_family == AF_INET6) {
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

    /* Determine if this interface should be used, and what port
       number to bind to.
     */
    rv = srv.proto->bind_hook(sa, sa_name);
    if (rv < 0)
        return (0);
    if (rv > USHRT_MAX)
        return (-1);
    port = (unsigned short) rv;

    /* The port number can be overridden by a command-line option */
    if (OPT.port > 0)
        port = OPT.port;

    /* Setup the protocol-specific socket structure */
    if (sa->sa_family == AF_INET) {
        memcpy(&sain, sa, sizeof(sain));
        memset(&sain6, 0, sizeof(sain6));
        sain.sin_port = htons(port);
    } else if (sa->sa_family == AF_INET6) {
        memset(&sain, 0, sizeof(sain));
        memcpy(&sain6, sa, sizeof(sain6));
        sain6.sin6_port = htons(port);
    } else {
        log_error("unsupported family %d", sa->sa_family);
        return (-1);
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

    log_debug("bound to %s port %d (fd=%d)", &sa_name[0], port, fd);

    if ((ni = calloc(1, sizeof(*ni))) == NULL) {
		log_errno("calloc(3)");
        goto errout;
    }
    ni->proto = proto;
    ni->fd = fd;
    memcpy(&ni->ss, sa, sa_len);
    memcpy(&ni->name, sa_name, sizeof(ni->name));
    ni->ss_len = sa_len;
    LIST_INSERT_HEAD(&srv.if_list, ni, entry);

    /* Monitor the server descriptor for new connections */
    /* TODO: error handling */
    ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, dispatch_get_main_queue());
    dispatch_set_context(ds, ni);
    dispatch_source_set_event_handler_f(ds, server_accept);
    dispatch_resume(ds);

    return (0);

errout:
    log_error("unable to bind(2) to %s port %d", &sa_name[0], port);
    if (fd >= 0)
        close(fd);
    return (-1);
}

int
server_bind(void)
{
    struct ifaddrs *ifa_head, *ifa;
    struct sockaddr *sa;

    if (getifaddrs(&ifa_head) < 0) {
        log_errno("getifaddrs(3)");
        return (-1);
    }

    for (ifa = ifa_head; ifa != NULL; ifa = ifa->ifa_next) {
        sa = ifa->ifa_addr;
        if (sa == NULL)
            continue;
            
        if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
            if (server_bind_addr(sa, srv.proto) < 0)
                goto errout;
        }
    } 

    freeifaddrs(ifa_head);
    return (0);

errout:
    freeifaddrs(ifa_head);
    return (-1);
}

#if DEADWOOD
/* TODO: I don't think this needs to be void, void * anymore.

static int
client_event_handler(struct session *s, int events)

   */
static void
client_event_handler(void *sptr)
{
    struct session *s = (struct session *) sptr;
    struct socket *sock = (struct socket *) session_get_socket(s);
    int rv;

    rv = socket_event_handler(sock);
    if (rv < 0) 
        socket_close(sock); /* KLUDGE - lame way to kill the connection. */
    if (rv == 0)
        session_event_handler(s);
}
#endif

static void
server_accept(void *if_ptr)
{
    struct net_interface *ni = (struct net_interface *) if_ptr;
	socklen_t cli_len = ni->ss_len;
    int fd = -1;
	struct session *s;

    /* Accept the incoming connection */
    if ((fd = accept(ni->fd, (struct sockaddr *) &ni->ss, &cli_len)) < 0) {
        log_errno("accept(2)");
        return;
    }
    log_debug("accept(2) created fd %d", fd);

    /* Create a new session */
    if ((s = session_new(fd, ni->proto)) == NULL) 
        return;

    /* Run the protocol specific accept(2) hook */
    if (ni->proto->accept_hook(s) < 0) {
        goto errout;
    }

    return;

errout:
    log_error("session_accept() failed");
    if (s != NULL) {
        session_close(s);
    }
}

/*
 * TODO -- move to options.c
 */

void
usage()
{
    fprintf(stderr, "Usage:\n\n"
	    "  recvmail [-fhstv] [-u uid]\n\n"
	    "        -f      Run in the foreground           (default: no)\n"
	    "        -h      Display this help message\n"
	    "        -p      Run under a different port      (default: 25)\n"
	    "        -q      Quiet (warning messages only)                \n"
	    "        -u      Run under a different user ID   (default: recvmail)\n"
	    "        -v      Verbose debugging messages      (default: no)\n"
	    "\n");
    exit(1);
}

/* getopt(3) variables */
extern char    *optarg;
extern int      optind;
extern int      optopt;
extern int      opterr;
extern int      optreset;

/* TODO - This is incomplete */
static int
option_parse(const char *arg)
{
	char *p;
	char *buf, *key, *val;
    int rv;

	if ((buf = strdup(arg)) == NULL) {
        log_error("out of memory");
        return (-1);
    }

    /* Split the string into a key & value */
    if ((p = strchr(buf, '=')) == NULL) {
        log_error("syntax error parsing option '%s'", buf);
        goto errout;
    }
	*p++ = '\0';
	key = buf;
	val = p;

	log_debug("key=%s val=%s\n", key, val);

    if (strcmp(key, "ServerName") == 0) {
        free(OPT.hostname);
        if ((OPT.hostname = strdup(val)) == NULL) {
            log_error("out of memory");
            return (-1);
        }
    } else if (strcmp(key, "UseSSL") == 0) {
        log_debug("SSL enabled");
        OPT.ssl_enabled = 1;        /* TODO: allow No as a value */
    } else {
        rv = srv.proto->getopt_hook(key, val);
        if (rv < 0) {
            log_error("Failed to parse option `%s'", key);
            goto errout;
        } else if (rv > 0) {
            log_error("Unrecognized configuration option `%s'", key);
            goto errout;
        }
    }

	free(buf);
    return (0);

errout:
	free(buf);
    return (-1);
}

int
options_parse(int argc, char *argv[])
{
    char buf[256];
    int  c;

    /* Get the hostname */
    if (gethostname(&buf[0], 256) != 0) {
        log_errno("gethostname(3)");
        return (-1);
    }
    OPT.hostname = strdup(&buf[0]);

    /* Set the default SSL key/cert location */
    /* XXX-FIXME: for testing only */
    OPT.ssl_certfile = strdup("/etc/ssl/certs/ssl-cert-snakeoil.pem");
    OPT.ssl_keyfile = strdup("/etc/ssl/private/ssl-cert-snakeoil.key");

    /* Get arguments from ARGV */
    while ((c = getopt(argc, argv, "vfho:p:qu:")) != -1) {
        switch (c) {
            case 'f':
                OPT.daemon = 0;
                break;
            case 'h':
                usage();
                break;
            case 'o':
                if (option_parse(optarg) < 0)
                    errx(1, "parse error");
                break;
            case 'p':
                OPT.port = atoi(optarg);
                break;
            case 'q':
                OPT.log_level = LOG_ERR;
                break;
            case 'u':
                if ((OPT.uid = strdup(optarg)) == NULL)
                    err(1, "strdup failed");
                break;
            case 'v':
                if (OPT.log_level == LOG_DEBUG)
                    err(1, "cannot enable logging above LOG_DEBUG");
                OPT.log_level++;
                break;
            default:
                usage();
                break;
        }
    }

    return srv.proto->sanity_hook();
}
