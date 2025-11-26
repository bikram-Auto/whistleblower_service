// sender_server.c  (NEW VERSION)
// Sender is now a TCP SERVER that Business Service connects to.
// It listens on BUSINESS_PORT (from .env), handles TCP client commands,
// sends UDP to consumer, receives replies, and sends DELIVERED over TCP.

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
#include <netdb.h>
#include <openssl/hmac.h>
#include "env.h"

#define MAX_EVENTS 128
#define BUFSZ 8192
#define HMAC_HEX_LEN (EVP_MAX_MD_SIZE*2)

static int make_nonblocking(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static int hmac_sha256_hex(const char *k, const char *d, char *out, size_t osz) {
    unsigned int len = 0;
    unsigned char *r = HMAC(EVP_sha256(), k, strlen(k),
                            (unsigned char*)d, strlen(d), NULL, &len);
    if (!r || osz < len*2+1) return -1;
    for (unsigned i=0; i<len; i++) sprintf(out + i*2, "%02x", r[i]);
    out[len*2] = 0;
    return 0;
}

static void strtrim(char *s) {
    while (*s==' '||*s=='\t'||*s=='\r') s++;
    size_t l = strlen(s);
    while (l && (s[l-1]==' '||s[l-1]=='\t'||s[l-1]=='\r')) s[--l]=0;
}

int main() {
    load_env_file(".env");

    const char *SECRET = get_env_value("SECRET_KEY");
    const char *SENDER_ID = get_env_value("SENDER_ID");
    const char *BUS_HOST = get_env_value("BUSINESS_HOST");
    const char *BUS_PORT_S = get_env_value("BUSINESS_PORT");
    const char *CONS_PORT_S = get_env_value("CONSUMER_PORT");

    if (!SECRET || !SENDER_ID) {
        fprintf(stderr, "Missing SECRET or SENDER_ID\n");
        return 1;
    }

    int listen_port = BUS_PORT_S ? atoi(BUS_PORT_S) : 7000;
    int consumer_port = CONS_PORT_S ? atoi(CONS_PORT_S) : 6000;

    printf("Sender TCP server starting on *:%d\n", listen_port);
    printf("Consumer: 127.0.0.1:%d\n", consumer_port);

    // UDP socket
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    make_nonblocking(udp);

    struct sockaddr_in consumer;
    memset(&consumer,0,sizeof(consumer));
    consumer.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &consumer.sin_addr);
    consumer.sin_port = htons(consumer_port);

    // TCP listening socket
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 16);
    make_nonblocking(srv);

    int ep = epoll_create1(0);

    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.fd = srv;
    epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev);

    ev.events = EPOLLIN; ev.data.fd = udp;
    epoll_ctl(ep, EPOLL_CTL_ADD, udp, &ev);

    printf("Sender ready. Waiting for Business Service TCP connection...\n");

    struct epoll_event events[MAX_EVENTS];
    char buf[BUFSZ];

    int client = -1;

    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        for (int i=0;i<n;i++) {
            int fd = events[i].data.fd;

            // NEW CLIENT CONNECTS
            if (fd == srv) {
                client = accept(srv, NULL, NULL);
                if (client >= 0) {
                    make_nonblocking(client);
                    ev.events = EPOLLIN;
                    ev.data.fd = client;
                    epoll_ctl(ep, EPOLL_CTL_ADD, client, &ev);
                    printf("Business connected (fd=%d)\n", client);
                }
                continue;
            }

            // UDP REPLY
            if (fd == udp) {
                struct sockaddr_in src;
                socklen_t sl = sizeof(src);
            
                int r = recvfrom(udp, buf, sizeof(buf)-1, 0, (void*)&src, &sl);
                if (r > 0 && client >= 0) {
                    buf[r] = 0;
            
                    char line[BUFSZ];
                    snprintf(line, sizeof(line), "DELIVERED %s %s\n", SENDER_ID, buf);
                    send(client, line, strlen(line), 0);
                }
                continue;
            }
            
            // TCP COMMAND FROM BUSINESS
            if (fd == client) {
                int r = recv(client, buf, sizeof(buf)-1, 0);
                if (r <= 0) {
                    printf("Business disconnected.\n");
                    close(client);
                    client=-1;
                    continue;
                }
                buf[r]=0;

                // Expect: SEND <receiver> <message>
                char receiver[256]={0};
                char message[4096]={0};

                if (sscanf(buf, "SEND %255s %4095[^\n]", receiver, message)==2) {
                    printf("SEND %s: %s\n", receiver, message);

                    // Build UDP payload
                    char data[BUFSZ];
                    snprintf(data, sizeof(data), "%s:%s:%s", SENDER_ID, receiver, message);

                    char hex[HMAC_HEX_LEN+1];
                    hmac_sha256_hex(SECRET, data, hex, sizeof(hex));

                    char payload[BUFSZ];
                    snprintf(payload, sizeof(payload), "%s:%s:%s:%s",
                             SENDER_ID, receiver, message, hex);

                    sendto(udp, payload, strlen(payload), 0,
                           (void*)&consumer, sizeof(consumer));
                }
            }
        }
    }
}
