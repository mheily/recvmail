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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "options.h"
#include "log.h"
#include "poll.h"
#include "server.h"
#include "smtp.h"

/* Global variables */

static struct server smtpd = {
    .port = 25,
    .timeout_read = 15,
    .timeout_write = 30,
};

/* TODO: eliminate this struct */
struct options  OPT = {
    .debugging = 0,
    .daemon = 1,
    .log_ident = "recvmail",
    .log_level = LOG_INFO,
    .log_facility = LOG_MAIL,
};

/* getopt(3) variables */
extern char    *optarg;
extern int      optind;
extern int      optopt;
extern int      opterr;
extern int      optreset;

void
usage()
{
    fprintf(stderr, "Usage:\n\n"
	    "  recvmail [-fhstv] [-g gid] [-u uid]\n\n"
	    "        -f      Run in the foreground           (default: no)\n"
	    "        -g      Run under a different group ID  (default: 25)\n"
	    "        -h      Display this help message\n"
	    "        -q      Quiet (warning messages only)                \n"
	    "        -u      Run under a different user ID   (default: 25)\n"
	    "        -v      Verbose debugging messages      (default: no)\n"
	    "\n");
    exit(1);
}


/* TODO - This is incomplete */
void
option_parse(const char *arg)
{
	char *p;
	char *buf, *key, *val;

	buf = strdup(arg);
	if ((p = strchr(arg, '=')) == NULL)
		errx(1, "Syntax error");
	*p++ = '\0';
	key = buf;
	val = p;
	printf("key=%s val=%s\n", key, val);
	abort();
	free(buf);
}


static void
sanity_check(void)
{
   if (access(smtpd.chrootdir, X_OK) != 0)
        errx(1, "%s", smtpd.chrootdir);
   /* TODO: check spool/ and etc/ and box/ */
}


int
main(int argc, char *argv[])
{
    char mailname[256];
    int  c, rv;

    /* Get arguments from ARGV */
    while ((c = getopt(argc, argv, "fg:ho:qu:v")) != -1) {
        switch (c) {
            case 'f':
                OPT.daemon = 0;
                break;
            case 'g':
                if ((smtpd.gid = strdup(optarg)) == NULL)
                    err(1, "strdup failed");
                break;
            case 'h':
                usage();
                break;
            case 'o':
                //TODO: see main.c:parse_option(optarg);
                abort();
                break;
            case 'q':
                OPT.log_level = LOG_ERR;
                break;
            case 'u':
                if ((smtpd.uid = strdup(optarg)) == NULL)
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

    /* Check the 'debugging' environment option */
    if (getenv("RECVMAIL_DEBUG")) {
        OPT.daemon = 0;
        OPT.log_level++;
    }

    /* Determine the chroot(2) prefix, UID, and GID */
#if defined(__linux__)
    smtpd.chrootdir = "/srv/mail";
    smtpd.uid = "recvmail",
    smtpd.gid = "mail",
#elif defined(__OpenBSD__)
    smtpd.uid = "_recvmail";
    smtpd.gid = "_recvmail";
    smtpd.chrootdir = "/var/recvmail";
#else
    smtpd.uid = "recvmail";
    smtpd.gid = "recvmail";
    smtpd.chrootdir = "/var/recvmail";
#endif

    /* Get the hostname */
    OPT.mailname = (char *) &mailname;
    if (gethostname(OPT.mailname, 256) != 0)
        err(1, "gethostname");
    
    sanity_check();

    if (poll_init() < 0) 
        errx(1, "poll_init() failed");

    if (server_init(&smtpd) < 0)
        errx(1, "server initialization failed");

    rv = server_dispatch();

    poll_free();

    /* Print the final log message */
    if (!detached) {
        fprintf(stderr, ((rv == 0) ? "Exiting normally\n" : "Fatal error\n"));
        close(0);
        close(1);
        close(2);
    }

    exit ((rv == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}
