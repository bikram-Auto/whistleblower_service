// consumer.c  (TCP gateway for producer users → UDP to sender)
//
// TEST MODE: HMAC / token ignored for now
//
// Flow:
//   ProducerUser --TCP--> Consumer --UDP--> Sender --TCP--> TargetUser
//
// Producer side protocol:
//   1) Connect TCP to consumer
//   2) Send:   HELLO <userId>\n
//      - If anything else before HELLO -> "ERROR HELLO_REQUIRED\n"
//      - If same userId already connected -> "ERROR USER_ALREADY_CONNECTED\n" and close
//      - On success -> "OK\n"
//   3) Then send JSON lines:
//      {"toID":"1234","message":"hi","token":"x","x_time":"2025-11-28T12:00:00Z"}
//
// Consumer tasks:
//   - Track connected producer users (by userId, 1 connection per userId)
//   - For each JSON line:
//       * senderId = <HELLO userId>
//       * toUserId = json["toID"]
//       * message  = json["message"]
//       * x_time   = json["x_time"]
//       * Build msgId (M1, M2, ...)
//       * Store pending (msgId -> client fd)
//       * Send UDP to sender: "msgId|senderId|toUserId|x_time|message"
//   - Receive UDP reply from sender: "msgId|status|reason"
//       * Forward to producer as JSON, remove pending

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

#define MAX_EVENTS   128
#define BUFSZ        8192
#define MAX_PENDING  10000
#define MAX_CLIENTS  1024

//----- Pending message correlation table -----

struct Pending {
    int  used;
    int  client_fd;
    char msgId[64];
};

static struct Pending pending[MAX_PENDING];

// find free slot
static int pending_alloc() {
    for (int i = 0; i < MAX_PENDING; i++)
        if (!pending[i].used) return i;
    return -1;
}

// find by msgId
static int pending_find(const char *id) {
    for (int i = 0; i < MAX_PENDING; i++)
        if (pending[i].used && strcmp(pending[i].msgId, id) == 0)
            return i;
    return -1;
}

// free entry
static void pending_free(int idx) {
    pending[idx].used = 0;
}

//----- Utility -----

static int make_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    if (f < 0) return -1;
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

//----- Producer client state -----

struct Client {
    int  fd;
    int  identified;           // 0 until HELLO ok
    char userId[128];          // from HELLO
    char buf[BUFSZ];
    int  len;
};

static struct Client clients[MAX_CLIENTS];

static struct Client* get_client(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd == fd) return &clients[i];
    return NULL;
}

static struct Client* alloc_client(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd == 0) {
            clients[i].fd = fd;
            clients[i].len = 0;
            clients[i].identified = 0;
            clients[i].userId[0] = 0;
            return &clients[i];
        }
    }
    return NULL;
}

static void free_client(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd == fd) {
            printf("Consumer: closing client fd=%d userId=%s\n", fd, clients[i].userId);
            clients[i].fd = 0;
            clients[i].len = 0;
            clients[i].identified = 0;
            clients[i].userId[0] = 0;
        }
    }
}

// is a given userId already connected?
static int userId_in_use(const char *uid, int except_fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != 0 &&
            clients[i].fd != except_fd &&
            clients[i].identified &&
            strcmp(clients[i].userId, uid) == 0) {
            return 1;
        }
    }
    return 0;
}

// if a client disconnects, drop its pending entries
static void drop_pending_for_fd(int fd) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].used && pending[i].client_fd == fd) {
            pending[i].used = 0;
        }
    }
}

//----- JSON parsing (simple and naive) -----
static char* json_get(const char *json, const char *key, char *out, size_t outsz) {
    // looks for `"key":"value"`
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    char *p = strstr(json, pattern);
    if (!p) { out[0] = 0; return out; }
    p += strlen(pattern);
    char *q = strchr(p, '"');
    if (!q) { out[0] = 0; return out; }
    size_t n = (size_t)(q - p);
    if (n >= outsz) n = outsz - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return out;
}

//----- Main -----

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <producer_tcp_port> <sender_udp_port>\n", argv[0]);
        return 1;
    }

    int tcp_port = atoi(argv[1]);
    int udp_port = atoi(argv[2]);

    memset(pending, 0, sizeof(pending));
    memset(clients, 0, sizeof(clients));

    // ----- UDP socket for sending to Sender -----
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) { perror("udp"); return 1; }
    make_nonblock(udp);

    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port   = htons(udp_port);
    inet_pton(AF_INET, "127.0.0.1", &sender_addr.sin_addr);

    // ----- UDP receiving (bind to random local port) -----
    int udp_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_recv < 0) { perror("udp_recv"); return 1; }

    struct sockaddr_in udp_local;
    memset(&udp_local, 0, sizeof(udp_local));
    udp_local.sin_family      = AF_INET;
    udp_local.sin_addr.s_addr = INADDR_ANY;
    udp_local.sin_port        = 0; // OS chooses
    if (bind(udp_recv, (void*)&udp_local, sizeof(udp_local)) < 0) {
        perror("bind udp_recv");
        return 1;
    }
    make_nonblock(udp_recv);

    // ----- TCP server for producer users -----
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("tcp_srv"); return 1; }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(tcp_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (void*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); return 1; }
    make_nonblock(srv);

    int ep = epoll_create1(0);
    if (ep < 0) { perror("epoll_create1"); return 1; }

    struct epoll_event ev;
    ev.events  = EPOLLIN;
    ev.data.fd = srv;
    epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev);

    ev.events  = EPOLLIN;
    ev.data.fd = udp_recv;
    epoll_ctl(ep, EPOLL_CTL_ADD, udp_recv, &ev);

    printf("Consumer: TCP port %d (producers), UDP to sender port %d\n",
           tcp_port, udp_port);

    struct epoll_event events[MAX_EVENTS];
    int msg_counter = 1;

    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            // New producer connection
            if (fd == srv) {
                int c = accept(srv, NULL, NULL);
                if (c >= 0) {
                    make_nonblock(c);
                    struct Client *cl = alloc_client(c);
                    if (!cl) {
                        printf("Consumer: no space for new client\n");
                        close(c);
                    } else {
                        printf("Consumer: new producer fd=%d\n", c);
                        ev.events  = EPOLLIN;
                        ev.data.fd = c;
                        epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev);
                    }
                }
                continue;
            }

            // UDP reply from sender
            if (fd == udp_recv) {
                char b[BUFSZ];
                struct sockaddr_in src;
                socklen_t slen = sizeof(src);
                int r = recvfrom(fd, b, sizeof(b) - 1, 0, (void*)&src, &slen);
                if (r > 0) {
                    b[r] = 0;
                    // format: msgId|status|reason
                    char msgId[64]  = {0};
                    char status[64] = {0};
                    char reason[512]= {0};

                    sscanf(b, "%63[^|]|%63[^|]|%511[^\n]", msgId, status, reason);

                    int idx = pending_find(msgId);
                    if (idx >= 0) {
                        int cfd = pending[idx].client_fd;
                        char resp[BUFSZ];

                        if (strcmp(status, "OK") == 0) {
                            snprintf(resp, sizeof(resp),
                                     "{\"status\":\"OK\",\"delivered\":\"yes\"}\n");
                        } else {
                            // e.g. status="NOT_CONNECTED", reason="Target offline"
                            snprintf(resp, sizeof(resp),
                                     "{\"status\":\"ERROR\",\"code\":\"%s\",\"detail\":\"%s\"}\n",
                                     status, reason);
                        }
                        send(cfd, resp, strlen(resp), 0);
                        pending_free(idx);
                    }
                }
                continue;
            }

            // TCP data from producer client
            struct Client *cl = get_client(fd);
            if (!cl) continue;

            int r = recv(fd, cl->buf + cl->len,
                         (int)(sizeof(cl->buf) - cl->len - 1), 0);
            if (r <= 0) {
                // disconnect
                drop_pending_for_fd(fd);
                close(fd);
                free_client(fd);
                continue;
            }

            cl->len += r;
            cl->buf[cl->len] = 0;

            char *start = cl->buf;

            for (;;) {
                char *nl = strchr(start, '\n');
                if (!nl) break;
                *nl = 0;

                char line[BUFSZ];
                strcpy(line, start);

                // First line(s) must be HELLO
                if (!cl->identified) {
                    char cmd[16] = {0};
                    char uid[128]= {0};
                    if (sscanf(line, "%15s %127s", cmd, uid) == 2 &&
                        strcmp(cmd, "HELLO") == 0) {

                        // check duplicate user
                        if (userId_in_use(uid, fd)) {
                            const char *msg = "ERROR USER_ALREADY_CONNECTED\n";
                            send(fd, msg, strlen(msg), 0);
                            printf("Consumer: duplicate HELLO for userId=%s, closing fd=%d\n",
                                   uid, fd);
                            drop_pending_for_fd(fd);
                            close(fd);
                            free_client(fd);
                            // stop processing this fd further
                            start = nl + 1;
                            break;
                        }

                        strncpy(cl->userId, uid, sizeof(cl->userId) - 1);
                        cl->identified = 1;
                        const char *ok = "OK\n";
                        send(fd, ok, strlen(ok), 0);
                        printf("Consumer: HELLO from userId=%s fd=%d\n", cl->userId, fd);

                    } else {
                        const char *err = "ERROR HELLO_REQUIRED\n";
                        send(fd, err, strlen(err), 0);
                    }

                } else {
                    // Identified: treat line as JSON message
                    char toUserId[128] = {0};
                    char message[4096] = {0};
                    char xtime[128]    = {0};

                    json_get(line, "toID",    toUserId, sizeof(toUserId));
                    json_get(line, "message", message,  sizeof(message));
                    json_get(line, "x_time",  xtime,    sizeof(xtime));

                    // token ignored for now
                    // char token[256]; json_get(line,"token",token,sizeof(token));

                    if (toUserId[0] == 0 || message[0] == 0) {
                        const char *err = "{\"status\":\"ERROR\",\"detail\":\"invalid payload\"}\n";
                        send(fd, err, strlen(err), 0);
                    } else {
                        // Build msgId
                        char msgId[64];
                        snprintf(msgId, sizeof(msgId), "M%d", msg_counter++);

                        int pidx = pending_alloc();
                        if (pidx < 0) {
                            const char *err = "{\"status\":\"ERROR\",\"detail\":\"server busy\"}\n";
                            send(fd, err, strlen(err), 0);
                        } else {
                            pending[pidx].used = 1;
                            pending[pidx].client_fd = fd;
                            strncpy(pending[pidx].msgId, msgId,
                                    sizeof(pending[pidx].msgId) - 1);

                            // build UDP payload: msgId|senderId|toUserId|x_time|message
                            char payload[BUFSZ];
                            snprintf(payload, sizeof(payload),
                                     "%s|%s|%s|%s|%s",
                                     msgId,
                                     cl->userId,
                                     toUserId,
                                     xtime[0] ? xtime : "NA",
                                     message);

                            sendto(udp, payload, strlen(payload), 0,
                                   (void*)&sender_addr, sizeof(sender_addr));

                            printf("Consumer: forwarded msgId=%s from %s to %s\n",
                                   msgId, cl->userId, toUserId);
                        }
                    }
                }

                start = nl + 1;
            }

            // compact buffer (leftover partial line)
            int remain = (int)(cl->buf + cl->len - start);
            memmove(cl->buf, start, remain);
            cl->len = remain;
        }
    }

    close(srv);
    close(udp);
    close(udp_recv);
    close(ep);
    return 0;
}
