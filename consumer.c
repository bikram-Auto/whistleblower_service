// consumer.c
// Usage: ./consumer <listen_port>
// listens on UDP port and replies to senders with regenerated HMAC
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
#include <openssl/hmac.h>
#include "env.h"

#define BUFSZ 4096
#define MAX_EVENTS 128
#define HMAC_HEX_LEN (EVP_MAX_MD_SIZE*2)

static int make_socket_non_blocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static void hmac_sha256_hex(const char *key, const char *data, char *out_hex, size_t out_size) {
    unsigned int len = 0;
    unsigned char *res = HMAC(EVP_sha256(), key, (int)strlen(key),
                              (unsigned char*)data, strlen(data), NULL, &len);
    if (!res) {
        out_hex[0] = '\0';
        return;
    }
    if (out_size < (size_t)(len*2 + 1)) {
        out_hex[0] = '\0';
        return;
    }
    for (unsigned int i=0;i<len;i++) sprintf(out_hex + i*2, "%02x", res[i]);
    out_hex[len*2] = '\0';
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <listen_port>\n", argv[0]);
        return 1;
    }
    load_env_file(".env");
    const char *SECRET = get_env_value("SECRET_KEY");
    int port = atoi(argv[1]);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    // allow reuse
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    if (make_socket_non_blocking(sock) < 0) {
        perror("fcntl");
        close(sock);
        return 1;
    }

    // increase recv buffer
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(sock); return 1; }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) < 0) { perror("epoll_ctl"); close(sock); return 1; }

    printf("consumer: listening on UDP port %d\n", port);

    struct epoll_event events[MAX_EVENTS];
    char buf[BUFSZ];

    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno==EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i=0;i<n;i++) {
            if (events[i].data.fd == sock) {
                while (1) {
                    struct sockaddr_in src;
                    socklen_t slen = sizeof(src);
                    ssize_t r = recvfrom(sock, buf, sizeof(buf)-1, 0, (struct sockaddr*)&src, &slen);
                    if (r <= 0) {
                        if (errno==EAGAIN || errno==EWOULDBLOCK) break;
                        break;
                    }
                    buf[r] = '\0';
                    // Expected payload: sender:receiver:message:hmac
                    char sender[128]={0}, receiver[128]={0}, message[2048]={0}, incoming_hmac[256]={0};
                    // careful parse: find last ':' for hmac (hmac hex has no ':')
                    // naive parse using sscanf (works if message has no ':')
                    // to be robust, parse manually
                    char *p1 = strchr(buf, ':');
                    if (!p1) continue;
                    char *p2 = strchr(p1+1, ':');
                    if (!p2) continue;
                    // find last ':' from end for hmac
                    char *plast = strrchr(buf, ':');
                    if (!plast || plast == p2) continue; // bad
                    // extract
                    size_t s_len = p1 - buf;
                    size_t r_len = p2 - (p1+1);
                    size_t m_len = plast - (p2+1);
                    if (s_len >= sizeof(sender)) s_len = sizeof(sender)-1;
                    if (r_len >= sizeof(receiver)) r_len = sizeof(receiver)-1;
                    if (m_len >= sizeof(message)) m_len = sizeof(message)-1;
                    memcpy(sender, buf, s_len); sender[s_len]=0;
                    memcpy(receiver, p1+1, r_len); receiver[r_len]=0;
                    memcpy(message, p2+1, m_len); message[m_len]=0;
                    strncpy(incoming_hmac, plast+1, sizeof(incoming_hmac)-1);

                    // verify HMAC over "sender:receiver:message"
                    char data_to_verify[4096];
                    snprintf(data_to_verify, sizeof(data_to_verify), "%s:%s:%s", sender, receiver, message);
                    char expected_hmac[HMAC_HEX_LEN+1];
                    hmac_sha256_hex(SECRET, data_to_verify, expected_hmac, sizeof(expected_hmac));
                    int valid = (strcmp(expected_hmac, incoming_hmac) == 0);
                    if (!valid) {
                        // invalid - ignore or optionally reply with error
                        // we still reply but mark hmac empty (optionally)
                        fprintf(stderr, "Invalid HMAC from %s:%d (sender=%s)\n", inet_ntoa(src.sin_addr), ntohs(src.sin_port), sender);
                    } else {
                        //printf("Valid message from %s -> receiver:%s msg:%s\n", sender, receiver, message);
                    }

                    // build reply: <sender_id>:<message>:<new_hmac>
                    char response_data[4096];
                    snprintf(response_data, sizeof(response_data), "%s:%s", sender, message);
                    char reply_hmac[HMAC_HEX_LEN+1];
                    hmac_sha256_hex(SECRET, response_data, reply_hmac, sizeof(reply_hmac));

                    char final_reply[8192];
                    snprintf(final_reply, sizeof(final_reply), "%s:%s:%s", sender, message, reply_hmac);

                    sendto(sock, final_reply, strlen(final_reply), 0, (struct sockaddr*)&src, slen);
                    // continue loop to drain socket
                }
            }
        }
    }

    close(sock);
    close(epfd);
    return 0;
}
