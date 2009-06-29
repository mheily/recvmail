#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <stdbool.h>

/* Configuration options */

struct options {
    u_short     port;
    bool        debugging;
    char       *hostname;
    bool        daemon;	        /* Run as daemon ? */
    char       *log_ident;	    /* Program name to use in syslog */
    int         log_facility;	/* The log facility to provide to syslog(3) */
    int         log_level;	    /* The level used by setlogmask(3) */
    char       *uid;            /* The user ID to run under */
    int         use_dnsbl;      /* If true, check the DNSBL */
};

extern struct options OPT;

//TODO: move from server.c to options.c
int options_parse(int argc, char *argv[]);

#endif  /* _OPTIONS_H */
