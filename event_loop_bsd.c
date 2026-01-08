#ifndef __linux__

#include <sys/event.h>
#include <unistd.h>
#include "event_loop.h"

int event_loop_create(void) {
    return kqueue();
}

int event_loop_add(int loop_fd, int fd) {
    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    return kevent(loop_fd, &kev, 1, NULL, 0, NULL);
}

int event_loop_wait(int loop_fd, void *events, int max_events) {
    return kevent(loop_fd, NULL, 0, events, max_events, NULL);
}

int event_fd(void *event) {
    return ((struct kevent *)event)->ident;
}

#endif
