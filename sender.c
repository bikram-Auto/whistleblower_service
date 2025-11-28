// sender.c
// UDP receiver from Consumer → TCP hub for Target Users
//
// Build:
//   gcc -Wall -O2 -o sender sender.c
//
// Run:
//   ./sender <user_tcp_port> <listen_udp_port>
//
// Protocol:
//
// Target User → Sender (TCP):
//   1) Connect to TCP <user_tcp_port>
//   2) Send: "HELLO <userId>\n"
//      - On success: Sender replies "OK\n"
//      - If anything sent before HELLO: "ERROR HELLO_REQUIRED\n"
//      - If HELLO sent twice: "ERROR ALREADY_IDENTIFIED\n"
//      - If another connection already uses same userId:
//            "ERROR USER_ALREADY_CONNECTED\n" (and new conn is closed)
//   3) After HELLO, Target User only receives:
//         "FROM <senderId> <x_time> <message>\n"
//      Any further data they send → "ERROR READ_ONLY\n"
//
// Consumer → Sender (UDP):
//   Payload:  "msgId|senderId|toUserId|x_time|message"
//   Behaviour:
//     - If toUserId is connected:
//         - Send over TCP to that user:
//             "FROM senderId x_time message\n"
//         - Reply UDP: "msgId|OK|delivered"
//     - If not connected:
//         - Reply UDP: "msgId|NOT_CONNECTED|Target offline"
//
// NOTE: HMAC is intentionally disabled for testing; to be added later.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define MAX_EVENTS 128
#define BUFSZ      8192

#define MAX_USERS   10000
#define INBUF_SIZE  1024

struct User {
    int   fd;
    char  userId[64];
    int   identified;              // 0 = not yet HELLO, 1 = HELLO done
    char  inbuf[INBUF_SIZE];
    size_t inbuf_len;
};

static struct User users[MAX_USERS];

// ---------- small helpers ----------

static int make_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    if (f == -1) return -1;
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static struct User* alloc_user(int fd) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].fd == 0) {
            users[i].fd = fd;
            users[i].userId[0] = '\0';
            users[i].identified = 0;
            users[i].inbuf_len = 0;
            return &users[i];
        }
    }
    return NULL;
}

// Find by fd
static struct User* find_user_by_fd(int fd) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].fd == fd) return &users[i];
    }
    return NULL;
}

// Find by userId
static struct User* find_user_by_id(const char *uid) {
    if (!uid || !*uid) return NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].fd != 0 && users[i].identified &&
            strcmp(users[i].userId, uid) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

static void free_user(struct User *u) {
    if (!u) return;
    if (u->fd > 0) close(u->fd);
    u->fd = 0;
    u->userId[0] = '\0';
    u->identified = 0;
    u->inbuf_len = 0;
}

// ---------- TCP protocol handling for target users ----------

static void handle_hello(struct User *u, const char *line) {
    // line is a single line without newline: e.g. "HELLO 123456789"
    if (!u) return;

    // If already identified
    if (u->identified) {
        // Duplicate HELLO
        const char *msg = "ERROR ALREADY_IDENTIFIED\n";
        send(u->fd, msg, strlen(msg), 0);
        printf("[sender] fd=%d tried HELLO again (userId=%s)\n",
               u->fd, u->userId);
        return;
    }

    char cmd[16] = {0};
    char uid[64] = {0};

    int n = sscanf(line, "%15s %63s", cmd, uid);
    if (n < 2 || strcmp(cmd, "HELLO") != 0) {
        const char *msg = "ERROR HELLO_REQUIRED\n";
        send(u->fd, msg, strlen(msg), 0);
        printf("[sender] fd=%d sent non-HELLO before identifying\n", u->fd);
        return;
    }

    // Check if this userId is already in use
    struct User *existing = find_user_by_id(uid);
    if (existing) {
        const char *msg = "ERROR USER_ALREADY_CONNECTED\n";
        send(u->fd, msg, strlen(msg), 0);
        printf("[sender] fd=%d tried HELLO with already-used userId=%s; rejecting\n",
               u->fd, uid);
        // Close this NEW connection
        free_user(u);
        return;
    }

    // Assign userId and mark identified
    strncpy(u->userId, uid, sizeof(u->userId)-1);
    u->userId[sizeof(u->userId)-1] = '\0';
    u->identified = 1;

    const char *ok = "OK\n";
    send(u->fd, ok, strlen(ok), 0);

    printf("[sender] fd=%d registered as userId=%s\n", u->fd, u->userId);
}

static void handle_user_readable(struct User *u) {
    if (!u) return;
    char buf[BUFSZ];
    int r = recv(u->fd, buf, sizeof(buf) - 1, 0);
    if (r <= 0) {
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        printf("[sender] user fd=%d disconnected\n", u->fd);
        free_user(u);
        return;
    }
    buf[r] = '\0';

    // Append to per-user buffer
    if (u->inbuf_len + (size_t)r >= INBUF_SIZE) {
        // Overflow → reset buffer, send error if not yet identified
        u->inbuf_len = 0;
        if (!u->identified) {
            const char *msg = "ERROR HELLO_REQUIRED\n";
            send(u->fd, msg, strlen(msg), 0);
        } else {
            const char *msg = "ERROR READ_ONLY\n";
            send(u->fd, msg, strlen(msg), 0);
        }
        return;
    }

    memcpy(u->inbuf + u->inbuf_len, buf, (size_t)r);
    u->inbuf_len += (size_t)r;

    // Process complete lines
    size_t start = 0;
    for (size_t i = 0; i < u->inbuf_len; i++) {
        if (u->inbuf[i] == '\n') {
            u->inbuf[i] = '\0';
            char *line = u->inbuf + start;

            if (!u->identified) {
                // First valid line must be HELLO
                handle_hello(u, line);
                // if handle_hello closed user, u->fd == 0, break
                if (u->fd == 0) {
                    u->inbuf_len = 0;
                    return;
                }
            } else {
                // After HELLO, user should not send commands
                const char *msg = "ERROR READ_ONLY\n";
                send(u->fd, msg, strlen(msg), 0);
                printf("[sender] userId=%s fd=%d sent unexpected data after HELLO: '%s'\n",
                       u->userId, u->fd, line);
            }

            start = i + 1;
        }
    }

    // Move leftover (partial line) to front
    if (start < u->inbuf_len) {
        memmove(u->inbuf, u->inbuf + start, u->inbuf_len - start);
        u->inbuf_len -= start;
    } else {
        u->inbuf_len = 0;
    }
}

// ---------- UDP handling (from Consumer) ----------

static void handle_udp_readable(int udp_fd) {
    char b[BUFSZ];
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);

    int r = recvfrom(udp_fd, b, sizeof(b) - 1, 0,
                     (struct sockaddr*)&src, &sl);
    if (r <= 0) {
        return;
    }
    b[r] = '\0';

    // Expected format:
    //   msgId|senderId|toUserId|x_time|message
    char msgId[64]     = {0};
    char senderId[128] = {0};
    char toUserId[128] = {0};
    char xtime[128]    = {0};
    char message[4096] = {0};

    int n = sscanf(b, "%63[^|]|%127[^|]|%127[^|]|%127[^|]|%4095[^\n]",
                   msgId, senderId, toUserId, xtime, message);
    if (n < 5) {
        fprintf(stderr, "[sender] bad UDP payload: '%s'\n", b);
        // Could reply with error if msgId known; for now just ignore
        return;
    }

    printf("[sender] UDP msgId=%s senderId=%s toUserId=%s x_time=%s message='%s'\n",
           msgId, senderId, toUserId, xtime, message);

    struct User *target = find_user_by_id(toUserId);
    char reply[BUFSZ];

    if (!target) {
        // Target not connected
        snprintf(reply, sizeof(reply),
                 "%s|NOT_CONNECTED|Target offline", msgId);
        sendto(udp_fd, reply, strlen(reply), 0,
               (struct sockaddr*)&src, sl);

        printf("[sender] toUserId=%s is offline -> NOT_CONNECTED\n", toUserId);
        return;
    }

    // Target is connected → send message over TCP
    char line[BUFSZ];
    snprintf(line, sizeof(line),
             "FROM %s %s %s\n", senderId, xtime, message);

    ssize_t sent = send(target->fd, line, strlen(line), 0);
    if (sent < 0) {
        perror("[sender] send to target user failed");
        snprintf(reply, sizeof(reply),
                 "%s|ERROR|send_failed", msgId);
        sendto(udp_fd, reply, strlen(reply), 0,
               (struct sockaddr*)&src, sl);
        return;
    }

    printf("[sender] delivered to userId=%s fd=%d\n",
           target->userId, target->fd);

    // Acknowledge to Consumer
    snprintf(reply, sizeof(reply),
             "%s|OK|delivered", msgId);
    sendto(udp_fd, reply, strlen(reply), 0,
           (struct sockaddr*)&src, sl);
}

// ---------- main ----------

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <user_tcp_port> <listen_udp_port>\n", argv[0]);
        return 1;
    }

    int tcp_port = atoi(argv[1]);
    int udp_port = atoi(argv[2]);

    memset(users, 0, sizeof(users));

    // ----- UDP socket (from Consumer) -----
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) {
        perror("socket udp");
        return 1;
    }

    struct sockaddr_in uaddr;
    memset(&uaddr, 0, sizeof(uaddr));
    uaddr.sin_family      = AF_INET;
    uaddr.sin_addr.s_addr = INADDR_ANY;
    uaddr.sin_port        = htons(udp_port);

    if (bind(udp, (struct sockaddr*)&uaddr, sizeof(uaddr)) < 0) {
        perror("bind udp");
        close(udp);
        return 1;
    }
    if (make_nonblock(udp) < 0) {
        perror("fcntl udp");
        close(udp);
        return 1;
    }

    // ----- TCP server for target users -----
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket tcp");
        close(udp);
        return 1;
    }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in taddr;
    memset(&taddr, 0, sizeof(taddr));
    taddr.sin_family      = AF_INET;
    taddr.sin_addr.s_addr = INADDR_ANY;
    taddr.sin_port        = htons(tcp_port);

    if (bind(srv, (struct sockaddr*)&taddr, sizeof(taddr)) < 0) {
        perror("bind tcp");
        close(srv);
        close(udp);
        return 1;
    }
    if (listen(srv, 64) < 0) {
        perror("listen");
        close(srv);
        close(udp);
        return 1;
    }
    if (make_nonblock(srv) < 0) {
        perror("fcntl srv");
        close(srv);
        close(udp);
        return 1;
    }

    // ----- epoll -----
    int ep = epoll_create1(0);
    if (ep < 0) {
        perror("epoll_create1");
        close(srv);
        close(udp);
        return 1;
    }

    struct epoll_event ev;
    ev.events  = EPOLLIN;
    ev.data.fd = srv;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev) < 0) {
        perror("epoll_ctl srv");
        close(ep);
        close(srv);
        close(udp);
        return 1;
    }

    ev.events  = EPOLLIN;
    ev.data.fd = udp;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, udp, &ev) < 0) {
        perror("epoll_ctl udp");
        close(ep);
        close(srv);
        close(udp);
        return 1;
    }

    printf("[sender] ready. TCP(port=%d) for target users, UDP(port=%d) from consumer\n",
           tcp_port, udp_port);

    struct epoll_event events[MAX_EVENTS];

    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == srv) {
                // New TCP target user
                int c = accept(srv, NULL, NULL);
                if (c < 0) {
                    perror("accept");
                    continue;
                }
                if (make_nonblock(c) < 0) {
                    perror("fcntl client");
                    close(c);
                    continue;
                }

                struct User *u = alloc_user(c);
                if (!u) {
                    fprintf(stderr, "[sender] max users reached, closing new client\n");
                    close(c);
                    continue;
                }

                struct epoll_event cev;
                cev.events  = EPOLLIN;
                cev.data.fd = c;
                if (epoll_ctl(ep, EPOLL_CTL_ADD, c, &cev) < 0) {
                    perror("epoll_ctl client");
                    free_user(u);
                    continue;
                }

                printf("[sender] new TCP target connection fd=%d\n", c);
                continue;
            }

            if (fd == udp) {
                // UDP from Consumer
                handle_udp_readable(udp);
                continue;
            }

            // Otherwise: TCP data from a known user
            struct User *u = find_user_by_fd(fd);
            if (!u) {
                // Unknown fd (shouldn't happen)
                char tmp[256];
                int r = recv(fd, tmp, sizeof(tmp), 0);
                if (r <= 0) close(fd);
                continue;
            }

            handle_user_readable(u);
        }
    }

    close(ep);
    close(srv);
    close(udp);
    return 0;
}
