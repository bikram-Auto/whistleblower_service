// consumer.c  (TCP gateway for producer users → UDP to sender)
//
// For TESTING: HMAC is commented out.
// Message flow:
//   ProducerUser --TCP--> Consumer --UDP--> Sender --TCP--> TargetUser
//
// Consumer tasks:
//   - Accept producer TCP connections
//   - Read JSON messages (newline-delimited)
//   - Generate msgId, forward via UDP to sender
//   - Wait for sender's UDP reply: "msgId|status|reason"
//   - Respond to producer and delete pending entry
//
// Build:
//   gcc -Wall -O2 -o consumer consumer.c env.c
//
// Run (CLI overrides env):
//   ./consumer <producer_tcp_port> <sender_udp_port>
//   or with .env only:
//   ./consumer
//
// .env variables:
//   SECRET_KEY     = MYKEY123456    (loaded, reserved for future HMAC)
//   UDP_PORT       = 6000           (sender UDP port)
//   CONSUMER_PORT  = 3032           (TCP port for producer users)

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

#include "env.h"  // <--- added

#define MAX_EVENTS 128
#define BUFSZ 8192
#define MAX_PENDING 10000

//----- Pending message correlation table -----

struct Pending {
    int used;
    int client_fd;
    char msgId[64];
};

struct Pending pending[MAX_PENDING];

// find free slot
static int pending_alloc() {
    for (int i=0;i<MAX_PENDING;i++)
        if (!pending[i].used) return i;
    return -1;
}

// find by msgId
static int pending_find(const char *id) {
    for (int i=0;i<MAX_PENDING;i++)
        if (pending[i].used && strcmp(pending[i].msgId, id)==0)
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

// read line-based TCP input
struct Client {
    int fd;
    char buf[BUFSZ];
    int len;
};

// simple client table (many producers allowed)
#define MAX_CLIENTS 1024
struct Client clients[MAX_CLIENTS];

static struct Client* get_client(int fd) {
    for (int i=0;i<MAX_CLIENTS;i++)
        if (clients[i].fd == fd) return &clients[i];
    return NULL;
}

static struct Client* alloc_client(int fd) {
    for (int i=0;i<MAX_CLIENTS;i++) {
        if (clients[i].fd == 0) {
            clients[i].fd = fd;
            clients[i].len = 0;
            return &clients[i];
        }
    }
    return NULL;
}

static void free_client(int fd) {
    for (int i=0;i<MAX_CLIENTS;i++)
        if (clients[i].fd == fd) {
            clients[i].fd = 0;
            clients[i].len = 0;
        }
}

//----- JSON parsing (simple) -----
static char* json_get(const char *json, const char *key, char *out, size_t outsz) {
    // naive extractor: looks for `"key":"value"`
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    char *p = strstr(json, pattern);
    if (!p) { out[0]=0; return out; }
    p += strlen(pattern);
    char *q = strchr(p, '"');
    if (!q) { out[0]=0; return out; }
    size_t n = q - p;
    if (n >= outsz) n = outsz-1;
    memcpy(out, p, n);
    out[n]=0;
    return out;
}

//----- Main -----

int main(int argc, char **argv) {
    // ---- load .env ----
    load_env_file(".env");

    const char *secret            = get_env_value("SECRET_KEY");
    const char *env_consumer_port = get_env_value("CONSUMER_PORT");
    const char *env_udp_port      = get_env_value("UDP_PORT");

    if (!secret) {
        fprintf(stderr, "[consumer] WARNING: SECRET_KEY not set in .env (HMAC disabled for now)\n");
    }

    int tcp_port = 0;
    int udp_port = 0;

    if (argc >= 3) {
        tcp_port = atoi(argv[1]); // producer TCP port
        udp_port = atoi(argv[2]); // sender UDP port
    } else {
        if (!env_consumer_port || !env_udp_port) {
            fprintf(stderr,
                    "Usage: %s <producer_tcp_port> <sender_udp_port>\n"
                    "Or set CONSUMER_PORT and UDP_PORT in .env\n",
                    argv[0]);
            return 1;
        }
        tcp_port = atoi(env_consumer_port);
        udp_port = atoi(env_udp_port);
    }

    memset(pending, 0, sizeof(pending));
    memset(clients, 0, sizeof(clients));

    // ----- UDP socket for sending to Sender -----
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) { perror("udp"); return 1; }
    make_nonblock(udp);

    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(udp_port);
    inet_pton(AF_INET, "127.0.0.1", &sender_addr.sin_addr);

    // ----- UDP receiving (bind to random local port) -----
    int udp_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_recv < 0) { perror("udp_recv"); return 1; }

    struct sockaddr_in udp_local;
    memset(&udp_local, 0, sizeof(udp_local));
    udp_local.sin_family = AF_INET;
    udp_local.sin_addr.s_addr = INADDR_ANY;
    udp_local.sin_port = 0; // auto-assign
    if (bind(udp_recv, (void*)&udp_local, sizeof(udp_local))<0) {
        perror("bind udp_recv");
        return 1;
    }
    make_nonblock(udp_recv);

    // ----- TCP server for producers -----
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv<0){perror("tcp_srv");return 1;}
    int yes=1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR,&yes,sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(tcp_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (void*)&addr, sizeof(addr))<0){perror("bind");return 1;}
    if (listen(srv,16)<0){perror("listen");return 1;}
    make_nonblock(srv);

    int ep = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = srv;
    epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev);

    ev.events = EPOLLIN;
    ev.data.fd = udp_recv;
    epoll_ctl(ep, EPOLL_CTL_ADD, udp_recv, &ev);

    printf("[consumer] TCP port %d, UDP to sender port %d\n", tcp_port, udp_port);

    struct epoll_event events[MAX_EVENTS];
    int msg_counter = 1;

    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        for (int i=0;i<n;i++) {
            int fd = events[i].data.fd;

            // new producer
            if (fd == srv) {
                int c = accept(srv, NULL, NULL);
                if (c>=0) {
                    make_nonblock(c);
                    alloc_client(c);
                    ev.events=EPOLLIN;
                    ev.data.fd=c;
                    epoll_ctl(ep,EPOLL_CTL_ADD,c,&ev);
                }
                continue;
            }

            // UDP reply from sender
            if (fd == udp_recv) {
                char b[BUFSZ];
                struct sockaddr_in src;
                socklen_t slen=sizeof(src);
                int r = recvfrom(fd,b,sizeof(b)-1,0,(void*)&src,&slen);
                if (r>0) {
                    b[r]=0;
                    // parse: msgId|status|reason
                    char msgId[64]={0}, status[64]={0}, reason[512]={0};
                    sscanf(b,"%63[^|]|%63[^|]|%511[^\n]", msgId, status, reason);

                    int idx = pending_find(msgId);
                    if (idx>=0) {
                        int cfd = pending[idx].client_fd;
                        char resp[BUFSZ];
                        if (strcmp(status,"OK")==0) {
                            snprintf(resp,sizeof(resp),
                                "{\"status\":\"OK\",\"delivered\":\"yes\"}\n");
                        } else {
                            snprintf(resp,sizeof(resp),
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

            int r = recv(fd, cl->buf + cl->len, sizeof(cl->buf) - cl->len - 1, 0);
            if (r <= 0) {
                close(fd);
                free_client(fd);
                continue;
            }
            cl->len += r;
            cl->buf[cl->len]=0;

            // process lines
            char *start = cl->buf;
            for (;;) {
                char *nl = strchr(start, '\n');
                if (!nl) break;
                *nl = 0;
                char line[BUFSZ];
                strcpy(line, start);

                char senderId[128], toUserId[128], message[4096], xtime[128];
                json_get(line,"senderId",senderId,sizeof(senderId));
                json_get(line,"toUserId",toUserId,sizeof(toUserId));
                json_get(line,"message",message,sizeof(message));
                json_get(line,"x_time",xtime,sizeof(xtime));

                if (senderId[0] == '\0' || toUserId[0] == '\0' ||
                    message[0] == '\0' || xtime[0] == '\0') {
                    const char *err = "{\"status\":\"ERROR\",\"detail\":\"invalid payload\"}\n";
                    send(fd, err, strlen(err), 0);
                } else {
                    // ----- HMAC disabled for testing -----
                    // char hmacClient[256];
                    // json_get(line,"HMAC",hmacClient,sizeof(hmacClient));
                    // verify signature ...

                    // Build msgId
                    char msgId[64];
                    snprintf(msgId, sizeof(msgId), "M%d", msg_counter++);

                    // store pending
                    int pidx = pending_alloc();
                    if (pidx<0) {
                        char resp[]="{\"status\":\"ERROR\",\"detail\":\"server busy\"}\n";
                        send(fd,resp,strlen(resp),0);
                    } else {
                        pending[pidx].used=1;
                        pending[pidx].client_fd=fd;
                        strcpy(pending[pidx].msgId,msgId);

                        // build UDP to sender:
                        // msgId|senderId|toUserId|x_time|message
                        char payload[BUFSZ];
                        snprintf(payload, sizeof(payload),
                                 "%s|%s|%s|%s|%s",
                                 msgId, senderId, toUserId, xtime, message);

                        sendto(udp, payload, strlen(payload), 0,
                               (void*)&sender_addr, sizeof(sender_addr));
                    }
                }

                start = nl + 1;
            }

            // shift buffer
            int remain = cl->buf + cl->len - start;
            if (remain > 0) {
                memmove(cl->buf, start, remain);
            }
            cl->len = remain;
        }
    }
}
