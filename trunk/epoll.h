#if defined(__GLIBC__)
#include <sys/epoll.h>
#else
#ifndef _SYS_EPOLL_H
#define _SYS_EPOLL_H

#include <sys/event.h>

#define EPOLL_CTL_ADD   EV_ADD
#define EPOLL_CTL_DEL   EV_DELETE

enum {
	EPOLLIN  = 0x001,
	EPOLLOUT = 0x004,
	EPOLLONESHOT = (1 << 30),
	EPOLLET = (1 << 31)
};

struct epoll_event {
        int events;                 /* Any of: EPOLLIN | EPOLLOUT */
        union {
                void *ptr;
                int fd;
                uint32_t u32;
                uint64_t u64;
        } data;             
}; 

static inline int
epoll_create(int size)
{
        return kqueue();
}

static inline int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
        struct kevent kev;

        kev.ident = fd;
        kev.filter = (event->events & EPOLLIN) ? EVFILT_READ : EVFILT_WRITE;
        kev.flags = op;
        kev.fflags = 0;
        kev.data = 0;
        kev.udata = event->data.ptr;

        if (kevent(epfd, &kev, 1, NULL, 0, NULL) != 0)
                err(1, "kevent(2)");
}

static inline int
epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout)
{
        struct kevent kev;
        int i;

        /* FIXME - TODO */
        if (maxevents > 1 || timeout > 0)
                return -ENOTSUP;
        
        if ((i = kevent(epfd, NULL, 0, &kev, 1, NULL)) != 0)
                return rv;

        /* FIXME: error handling */
        events->events = (kev.filter == EVFILT_READ) ? EPOLLIN : EPOLLOUT;
        events->data.ptr = kev.udata;
}

#endif
#endif
