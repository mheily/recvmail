#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <stdbool.h>

/* Configuration options */

#define CHROOTDIR            "/srv/mail"

struct options {
    bool            debugging;
    char           *mailname;
    bool            daemon;	/* If TRUE, the server will run as a
				 * daemon */
    char           *uid;	/* The symbolic user-ID to setuid(2) to */
    char           *gid;	/* The symbolic group-ID to setgid(2) to */
    char           *log_ident;	/* Program name to use in syslog */
    int             log_facility;	/* The log facility to provide to
					 * syslog(3) */
    int             log_level;	/* The level used by setlogmask(3) */
};

extern struct options OPT;

#endif  /* _OPTIONS_H */
