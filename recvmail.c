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

void            run_testsuite();

/* Global variables */

int detached = 0;
struct server   smtpd = {
    .port = 25,
    .addr.s_addr = INADDR_ANY,
    .timeout_read = 15,
    .timeout_write = 30,

    /* vtable */
    .accept_hook = smtpd_accept,
    .timeout_hook = smtpd_timeout,
    .reject_hook = smtpd_client_error,
    .abort_hook = NULL,		// fixme
    .read_hook = smtpd_parser,
    .close_hook = smtpd_close,
};

struct options  OPT = {
    .debugging = 0,
    .daemon = 1,
    .uid = "nobody",
    .gid = "mail",
    .spooldir = SPOOLDIR,
    .log_level = LOG_NOTICE,
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

int
main(int argc, char *argv[])
{
    char mailname[256];
    char *defaultdomain[2];
    int             c;

    /* Get arguments from ARGV */
    while ((c = getopt(argc, argv, "fg:hi:o:p:qu:v")) != -1) {
	switch (c) {
	case 'f':
	    OPT.daemon = 0;
	    break;
	case 'g':
	    if ((OPT.gid = strdup(optarg)) == NULL)
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
	    OPT.log_level = 0;
	    break;
	case 'u':
	    if ((OPT.uid = strdup(optarg)) == NULL)
		err(1, "strdup failed");
	    break;
	case 'v':
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
    
    /* By default, only accept mail for the local machine. */
    /* FIXME: check for malloc failure */
    OPT.domains = (char **) &defaultdomain;
    OPT.domains[0] = OPT.mailname;
    OPT.domains[1] = NULL;

    /* Check directory accesses */
    if (access(SPOOLDIR, F_OK) != 0)
        err(1, "%s: %s", SPOOLDIR, strerror(errno));

#ifdef FIXME
    //causes valgrind error
    aliases_init();
    aliases_parse("/etc/aliases");
#endif

    server_init();
    if (server_bind(&smtpd) != 0)
        errx(1, "server initialization failed");
    //TODO:server_bind(&pop3d);
    drop_privileges(OPT.uid, OPT.gid, OPT.spooldir);

    /* Dump some variables to the log */
    log_debug("mailname=`%s'", OPT.mailname);

#ifdef UNIT_TESTING
    /* Run the testsuite */
    run_testsuite();
    exit(EXIT_SUCCESS);
#endif

    if (server_dispatch(&smtpd) != 0) {
        log_warning("server_dispatch() failed");
        exit(EXIT_FAILURE);
    } else {
        log_info("exiting normally");
        exit(EXIT_SUCCESS);
    }
}
