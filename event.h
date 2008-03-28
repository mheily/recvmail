#ifndef _KERNEL_FD_EVENTS
#define _KERNEL_FD_EVENTS

#if defined(__GLIBC__)
# include <sys/epoll.h>
# define event_init	epoll_create(1024)
# define event		epoll_event
# define EVENT_READ	EPOLLIN
# define EVENT_WRITE	EPOLLOUT
# define event_data(e)	(e.data.ptr)
#else
# include <sys/event.h>
# define event_init 	kqueue
# define event 		kevent
# define EVENT_READ	EVFILT_READ
# define EVENT_WRITE	EVFILT_WRITE
# define event_data(e)	(e.udata)

static inline int
event_add(struct event *kev, int evfd, int fd, int filter, void *udata)
{
	EV_SET(kev, fd, filter, EV_ADD, 0, 0, udata);
        return kevent(evfd, kev, 1, NULL, 0, NULL);
}	

static inline int
event_wait(struct event *kev, int evfd)
{    
        return kevent(evfd, NULL, 0, kev, 1, NULL) == 1 ? 0 : -1;
}	

#endif


#endif /* ! KERNEL_FD_EVENTS */

/************************************************************************/

#if DEADWOOD
	//DISABLED

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

        return kevent(epfd, &kev, 1, NULL, 0, NULL);
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
                return i;

        /* FIXME: error handling */
        events->events = (kev.filter == EVFILT_READ) ? EPOLLIN : EPOLLOUT;
        events->data.ptr = kev.udata;

	return 1;
}

#endif
#endif

#endif /* DEADWOOD */
