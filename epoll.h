#if defined(__linux__)
#include <sys/epoll.h>
#else
#ifndef _EPOLL_H
#define _EPOLL_H

#include <sys/types.h>
#include <sys/event.h>

#define EPOLL_CTL_ADD   EV_ADD
#define EPOLL_CTL_DEL   EV_DELETE
/* TODO - EPOLL_CTL_MOD */

enum {
	EPOLLIN  = 0x001,
	EPOLLOUT = 0x004,
    EPOLLERR = 0x008,
    EPOLLHUP = 0x010,
};
#define EPOLLRDHUP    EPOLLHUP
/* TODO: EPOLLET */

struct epoll_event {
        int events;                 /* Any of: EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP */
        union {
                void *ptr;
                int fd;
                uint32_t u32;
                uint64_t u64;
        } data;             
}; 

int epoll_create(int);
int epoll_ctl(int, int, int, struct epoll_event *);
int epoll_wait(int, struct epoll_event *, int, int);

#endif  /* _EPOLL_H */
#endif  /* ! defined(__linux__) */

