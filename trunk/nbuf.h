
#ifndef _NBUF_H
#define _NBUF_H

#include <unistd.h>

#include "queue.h"

/* Define 'struct nbuf_head' */
STAILQ_HEAD(nbuf_head, nbuf);

/* A general-purpose buffer for network data implemented as a linked list. */
struct nbuf {
    char   *nb_data;        /* NUL-terminated character string */
    size_t  nb_len;         /* strlen(3) of the string inside the buffer */
    STAILQ_ENTRY(nbuf) entries;
};

//DEADWOOD
#define NBUF_INIT(nb,data,len)  do {                        \
    (nb)->nb_data = (data);                                 \
    (nb)->nb_len  = (len);                                  \
} while (0)

/* 
 * Return true if the nbuf contains a line fragment. 
 */
#define NBUF_FRAGMENTED(nb)     \
    (((nb)->nb_len == 0) || ((nb)->nb_data[(nb)->nb_len - 1] != '\n'))

#endif /* _NBUF_H */
