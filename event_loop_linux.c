#ifdef __linux__

#include <sys/epoll.h>
#include <unistd.h>
#include "event_loop.h"

int event_loop_create(void) {
    return epoll_create1(0);
}

int event_loop_add(int loop_fd, int fd) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    return epoll_ctl(loop_fd, EPOLL_CTL_ADD, fd, &ev);
}

int event_loop_wait(int loop_fd, void *events, int max_events) {
    return epoll_wait(loop_fd, events, max_events, -1);
}

int event_fd(void *event) {
    return ((struct epoll_event *)event)->data.fd;
}

#endif
