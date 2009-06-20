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

static struct domain *dlist;
static struct domain **rtable;
static size_t   rtable_cnt;

static int      filter_dotfiles(struct dirent *ent);
static int      is_newer(const char *path, time_t *mtime);
static void     domain_update(struct domain *d);
static void     domain_free(struct domain *d);
static void     rtable_update(void);

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

static void
domain_free(struct domain *d)
{
    while (d->dm_count--)
        free(d->dm_entry[d->dm_count]);
    free(d->dm_entry);
    free(d->dm_path);
    free(d);
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
    log_debug("got %d entries in %s", n, d->dm_path);
    if (n < 0) {
        log_errno("scandir(3)");
        return;
    }
    while (d->dm_count--)
        free(d->dm_entry[d->dm_count]);
    free(d->dm_entry);
    d->dm_entry = names;
    d->dm_count = n;

    if (d == dlist) 
        rtable_update();
}

static void
rtable_update(void)
{
    struct domain **rt;
    char path[PATH_MAX + 1];
    int n;
    
    rt = calloc(dlist->dm_count, sizeof(struct domain));
    if (rt == NULL) {
        log_error("out of memory");
        return;
    }

    memset(&path, 0, sizeof(path));
    for (n = 0; n < dlist->dm_count; n++) {
        snprintf(path, sizeof(path), "box/%s", 
                 dlist->dm_entry[n]->d_name);
        rt[n] = domain_new(path);
        if (rt[n] == NULL) {
            while (--n >= 0)
                domain_free(rt[n]);
            free(rt);
            log_error("out of memory");
            return;
        }
    }

    for (n = 0; n < rtable_cnt; n++)
        domain_free(rtable[n]);
    free(rtable);
    rtable = rt;
    rtable_cnt = dlist->dm_count;
}

static int
filter_dotfiles(struct dirent *ent)
{
    log_debug("? %s", ent->d_name);
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
        log_errno("stat(3) of `%s'", path);
        return (0);
    }
    if (sb.st_mtime > *mtime) {
        *mtime = sb.st_mtime;
        return (1);
    } else {
        return (0);
    }
}
   
static void
recipient_update(void *unused)
{
    int n;

    domain_update(dlist);
     
    for (n = 0; n < dlist->dm_count; n++) 
         domain_update(rtable[n]);  
}

int
recipient_lookup(const char *local_part, const char *domain)
{
    int n;
    void *p;

            log_debug("domain count=%d", dlist->dm_count);
    for (n = 0; n < dlist->dm_count; n++) {
            log_debug("check `%s'", dlist->dm_entry[n]->d_name);
        if (strcasecmp(domain, dlist->dm_entry[n]->d_name) == 0) {
            log_debug("found domain `%s'", domain);
            p = bsearch(local_part, rtable[n]->dm_entry, 
                    rtable[n]->dm_count,
                    sizeof(struct dirent),
                    alphasort);
            return (p != NULL);
        }
        return (0);
    }

    return (0);
}

int
recipient_table_init(void)
{
    dlist = domain_new("box");
    if (dlist == NULL)
        return (-1);

    rtable_update();
    if (rtable == NULL)
        return (-1);
    
    /* Set a timer to periodically refresh the recipient list */
    if (poll_timer_new(60 * 5, recipient_update, NULL) == NULL)
        return(-1);
    
    return (0);
}
