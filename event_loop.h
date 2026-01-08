#pragma once

int  event_loop_create(void);
int  event_loop_add(int loop_fd, int fd);
int  event_loop_wait(int loop_fd, void *events, int max_events);
int  event_fd(void *event);