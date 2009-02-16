#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <sys/types.h>

ssize_t atomic_printfd(int d, const char *fmt, ...);
ssize_t atomic_read(int d, void *buf, size_t nbytes);
ssize_t atomic_write(int d, const void *buf, size_t nbytes);
int atomic_close(int d);

#endif  /* _ATOMIC_H */
