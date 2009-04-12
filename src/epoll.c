#if ! defined(__linux__)

#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>

#include "epoll.h"

int
epoll_create(int size)
{
    return kqueue();
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev)
{
    struct kevent kev;

    kev.ident = fd;
    kev.filter = (ev->events & EPOLLIN) ? EVFILT_READ : EVFILT_WRITE;
    if (op == EPOLL_CTL_DEL) 
        kev.udata = NULL;
    else 
        kev.udata = event->data.ptr;
    kev.flags = op;
    kev.fflags = 0;
    kev.data = 0;

    return kevent(epfd, &kev, 1, NULL, 0, NULL);
}

int
epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout)
{
    struct kevent kev;
    struct timespec tv;
    struct timespec *tvp = &tv;
    int nevents;

    /* Convert the timeout from milliseconds to seconds. */
    tv.tv_nsec = 0;
    if (timeout < 0) 
        tvp = NULL;
    else if (timeout == 0) 
        tv.tv_sec = 0;
    else if (timeout < 1000) 
        tv.tv_sec = 1;
    else 
        tv.tv_sec = timeout / 1000;

    /* TODO - Support returning more than one event */
    if (maxevents > 1)
        return -EINVAL;

    nevents = kevent(epfd, NULL, 0, &kev, 1, tvp);

    if (kev.flags & EV_ERROR) {
        events->events = EPOLLERR;
    } else {
        events->events = (kev.filter == EVFILT_READ) ? EPOLLIN : EPOLLOUT;
        if (kev.flags & EV_EOF) 
            events->events |= EPOLLHUP;
    }
    events->data.ptr = kev.udata;

    return (nevents);
}

#endif  /* ! defined(__GLIBC__) */ 
