/*		$Id: workqueue.c 228 2009-04-28 02:59:31Z mheily $		*/

/*
 * Copyright (c) 2009 Mark Heily <devel@heily.com>
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

#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "poll.h"

struct domain {
    char   *dm_path;
    u_int   dm_count;
    time_t  dm_mtime;
    struct dirent **dm_entry;
};

struct domain *dlist;
struct domain **rtable;

static int filter_dotfiles(struct dirent *ent);
static int is_newer(const char *path, time_t *mtime);
static void domain_update(struct domain *d);

static struct domain *
domain_new(const char *path)
{
    struct domain *d;
    char *p;
    
    d = calloc(1, sizeof(*d));
    p = strdup(path);

    if (d == NULL || p == NULL) {
        log_error("out of memory");
        free(p);
        free(d);
        return (NULL);
    }
    d->dm_path = p;
    domain_update(d);
    return (d);
}

/* PORTABILITY: scandir(3) and alphasort(3) are not in POSIX */
/* TODO: periodically force an update regardless of mtime */
static void
domain_update(struct domain *d)
{
    struct dirent **names;
    int n;

    if (! is_newer(d->dm_path, &d->dm_mtime))
        return;
    
    n = scandir(d->dm_path, &names, filter_dotfiles, alphasort);
    if (n < 0) {
        log_errno("scandir(3)");
        return;
    }
    while (d->dm_count--)
        free(d->dm_entry[d->dm_count]);
    free(d->dm_entry);
    d->dm_entry = names;
    d->dm_count = n;
}

static int
filter_dotfiles(struct dirent *ent)
{
    return (ent->d_name[0] != '.');
}

/*
 * Check if a file has been modified since <mtime>.
 * If it has, return TRUE and update <mtime> with the
 * new value.
 */
static int
is_newer(const char *path, time_t *mtime)
{
    struct stat sb;
    
    if (stat(path, &sb) < 0 ) {
        log_errno("stat(3) of box/");
        return (0);
    }
    if (sb.st_mtime > *mtime) {
        *mtime = sb.st_mtime;
        return (1);
    } else {
        return (0);
    }
}

    /* Rebuild the list of domains if necessary */
   
static void
recipient_update(void *unused)
{
    int n;

//XXX-FIXME #error broken
// need to do this AND rebuild rtable at the same time
// probably want to copy+paste fro domain_update() and add extra stuff
    domain_update(dlist);
     
    for (n = 0; n < dlist->dm_count; n++) 
         domain_update(rtable[n]);  
}

int
recipient_table_init(void)
{
    char path[PATH_MAX + 1];
    int n;
    
    dlist = domain_new("box");
    if (dlist == NULL)
        return (-1);
    rtable = calloc(dlist->dm_count, sizeof(struct domain));
    if (rtable == NULL)
        return (-1);
    memset(&path, 0, sizeof(path));
    for (n = 0; n < dlist->dm_count; n++) {
        snprintf(path, sizeof(path), "box/%s", 
                 dlist->dm_entry[n]->d_name);
        rtable[n] = domain_new(path);
    }
    
    recipient_update(NULL);
    
    /* Set a timer to periodically refresh the recipient list */
    if (poll_timer_new(60 * 5, recipient_update, NULL) == NULL)
        return(-1);
    
    return (0);
}
