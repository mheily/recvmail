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

void run_testsuite();

/* Global variables */

struct server smtpd = {
	.daemon = 1,
	.port = 25,
	.addr.s_addr = INADDR_ANY,
	.uid = "recvmail",
	.gid = "recvmail",
	.timeout_read = 15,
	.timeout_write = 30,
	.log_level = LOG_NOTICE,

	/* vtable */
	.accept_hook      = smtpd_greeting,
	.read_hook        = smtpd_parser,
	.timeout_hook     = smtpd_timeout,
	.reject_hook      = smtpd_client_error,
	.abort_hook       = NULL, // fixme
	.close_hook       = smtpd_close_hook,
};

struct options OPT = {
	.debugging = 0,
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

		"\n"
	);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int             c;
	
	/* Get arguments from ARGV */
	while ((c = getopt(argc, argv, "d:fg:hi:p:qu:v")) != -1) {
		switch (c) {
		case 'f':
			smtpd.daemon = 0;
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
		case 'p':
			smtpd.port = atoi(optarg);
			break;
		case 'q':
			smtpd.log_level = 0;
			break;
		case 'u':
			if ((smtpd.uid = strdup(optarg)) == NULL)
				err(1, "strdup failed");
			break;
		case 'v':
			smtpd.log_level++;
			break;
		default:
			usage();
			break;
		}
	}

	/* Check the 'debugging' environment option */
	if (getenv("RECVMAIL_DEBUG")) {
		smtpd.daemon = 0;
		smtpd.log_level++;
	}

	/* Get the hostname */
	if (!OPT.mailname) {
		if ((OPT.mailname = malloc(256)) == NULL)
			err(1, "malloc");
		if (gethostname(OPT.mailname, 256) != 0)
			err(1, "gethostname");
	}

#ifdef UNIT_TESTING
	/* Run the testsuite */
	run_testsuite();
#else 
	/* Start the server */
	server_start(&smtpd);
#endif

	exit(EXIT_SUCCESS);
}
