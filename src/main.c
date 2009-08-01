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
#include <sys/wait.h>
#include <unistd.h>

#include "options.h"
#include "log.h"
#include "server.h"
#include "smtp.h"

/* TODO: eliminate this struct */
struct options  OPT = {
    .debugging = 0,
    .daemon = 1,
    .uid = "recvmail",
    .log_ident = "recvmail",
    .log_level = LOG_INFO,
    .log_facility = LOG_MAIL,
};

int
main(int argc, char *argv[])
{
/* TODO: seperate, non-chroot process
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
    struct stat sb;
    time_t      mtime;
    FILE       *pd;
    int         fd, rv;
    size_t      cnt;
    char        buf[1024];

    memset(buf, 0, sizeof(buf));

    for (;;) {
       if (stat("/etc/passwd", &sb) < 0)
        err(1, "stat(2)");
       if (mtime < sb.st_mtime) {
         mtime = sb.st_mtime;

         fd = open("/srv/mail/etc/passwd", O_WRONLY | O_CREAT, 644);
         if (fd < 0)
            err(1, "open(2)");
    //FIXME - obtain a lock 
    //          see http://www.ecst.csuchico.edu/~beej/guide/ipc/flock.html
         if (lseek(fd, 0, SEEK_SET) < 0)
            err(1, "lseek(2)");
         if (ftruncate(fd, 0) < 0)
            err(1, "ftruncate(2)");

         pd = popen("cat /etc/passwd|cut -f1 -d:|sort|uniq", "r");
         if (pd == NULL)
            err(1, "popen(3)");
         while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
            cnt = strlen(buf);
            if (cnt == 0)
                errx(1, "empty string");
            if (buf[cnt] == '\n')
                buf[cnt] == '\0';
            else
                errx(1, "unterminated line");
            if (write(fd, buf, cnt) < 0)
                err(1, "write(2)");
         }
         rv = pclose(fp);
         if (rv == -1) {
            err(1, "pclose(3)");
        } else {
            // check rv using wait(2) macros
        }
}



       }
    }
}

 --------------------------
 TODO: periodic event inside recvmail:

     #include <sys/types.h>
     #include <sys/stat.h>

    struct stat sb;
    time_t      mtime;

    for (;;) {
       if (stat("/etc/passwd", &sb) < 0)
        err(1, "stat(2)");
       if (mtime < sb.st_mtime) {
         mtime = sb.st_mtime;
    //FIXME - obtain a lock 
    //          see http://www.ecst.csuchico.edu/~beej/guide/ipc/flock.html

         // Read the contents of /etc/passwd
         // use strtok to split into tokens
         // insert into RECIPIENT tree

    //FIXME - release the lock 
    //          see http://www.ecst.csuchico.edu/~beej/guide/ipc/flock.html
       }
    }

*/

            if (server_init(argc, argv, &SMTP) < 0)
            errx(1, "server initialization failed");

        if (server_dispatch() < 0) {
            if (!detached) 
                fprintf(stderr, "Abnormal program termination.\n");
            exit(EXIT_FAILURE);
        }
    
    pid_t pid;
    int   status;

    if ((pid = fork()) < 0)
        err(1, "fork(2)");

    if (pid > 0) {
        /* Wait for the child to become a daemon and reap it. */
        if (wait(&status) != pid)
            err(1, "wait(2) %d", pid);

    exit (EXIT_SUCCESS);
        
#if TODO
// maintain the chroot environment
        /* NOTE: not in POSIX */
        if (daemon(0,0) < 0)
            err(1, "daemon(3)");
        
        //TODO: copy /etc/localtime to chroot
        sleep(99999);
#endif
       exit (0);
    } else {

    }

    exit (EXIT_SUCCESS);
}
