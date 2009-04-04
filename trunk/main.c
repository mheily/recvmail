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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include "aliases.h"
#include "dnsbl.h"
#include "options.h"
#include "log.h"
#include "server.h"
#include "smtp.h"

void            run_testsuite();

/* Global variables */

struct server   smtpd = {
    .port = 25,
    .addr.s_addr = INADDR_ANY,
    .timeout_read = 15,
    .timeout_write = 30,
    .chrootdir = "/srv/mail",
    .uid = "nobody",
    .gid = "mail",

    /* vtable */
    .accept_hook = smtpd_accept,
    .abort_hook = NULL,		// fixme
    .close_hook = smtpd_close,
};

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
	    "  recvmail [-fhstv] [-g gid] [-u uid] [-i address] [-p port]\n\n"
	    "        -f      Run in the foreground           (default: no)\n"
	    "        -g      Run under a different group ID  (default: 25)\n"
	    "        -h      Display this help message\n"
	    "        -i      IP address to listen on         (default: 0.0.0.0)\n"
	    "        -p      Port number                     (default: 25)\n"
	    "        -q      Quiet (warning messages only)                \n"
	    "        -u      Run under a different user ID   (default: 25)\n"
	    "        -v      Verbose debugging messages      (default: no)\n"
	    "\n");
    exit(1);
}


/* FIXME - This is incomplete */
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
block_all_signals(void)
{
    sigset_t set;

    sigfillset(&set);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
        err(1, "pthread_sigmask(3)");
}

int
main(int argc, char *argv[])
{
    char mailname[256];
    int             c;

    /* Get arguments from ARGV */
    while ((c = getopt(argc, argv, "fg:hi:o:p:qu:v")) != -1) {
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
	case 'i':
	    if (inet_aton(optarg, &smtpd.addr) < 0)
		errx(1, "Invalid address");
	    break;
	case 'o':
		//TODO: see option.c: parse_option(optarg);
		abort();
		break;
	case 'p':
	    smtpd.port = atoi(optarg);
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

    /* Get the hostname */
    OPT.mailname = (char *) &mailname;
    if (gethostname(OPT.mailname, 256) != 0)
        err(1, "gethostname");
    
    /* Read the /etc/aliases file */
    aliases_init();
    aliases_parse("/etc/aliases");

    block_all_signals();
    //TODO:want to run poll_init() here so signal handling can take place

    if (dnsbl_init() < 0)
        errx(1, "DNSBL initialization failed");

    if (server_init(&smtpd) < 0)
        errx(1, "server initialization failed");

    /* Dump some variables to the log */
    log_debug("_SC_NPROCESSORS_ONLN=%ld", sysconf(_SC_NPROCESSORS_ONLN));
    log_debug("mailname=`%s'", OPT.mailname);

#ifdef UNIT_TESTING
    /* Run the testsuite */
    run_testsuite();
    exit(EXIT_SUCCESS);
#endif

    if (server_dispatch() < 0) {
        if (!detached) 
            fprintf(stderr, "Fatal error: program bought the farm.");
        exit(EXIT_FAILURE);
    } else {
        if (!detached) 
            fprintf(stderr, "Exiting normally");
        exit(EXIT_SUCCESS);
    }
}
