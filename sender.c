// sender.c
// Sender: connects to Business Service over TCP (non-blocking), receives SEND commands,
// sends UDP payloads to Consumer(s) with HMAC, listens for UDP replies and notifies Business Service.
//
// Usage: ./sender <consumer_ip>   (consumer_ip optional; can be overridden by Business Service)
// Example SEND command from Business Service (text framed by newline):
//    SEND <receiver_id> <message>\n
// Example delivered notification back to Business Service (we send):
//    DELIVERED <sender_id> <receiver_id> <message>\n

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
#include <time.h>
#include <openssl/hmac.h>
#include "env.h"

#define MAX_EVENTS 128
#define BUFSZ 8192
#define HMAC_HEX_LEN (EVP_MAX_MD_SIZE*2)
#define TCP_RECONNECT_DELAY_MS 2000
#define EPOLL_WAIT_MS -1

// Helper: make fd non-blocking
static int make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

// HMAC-SHA256 -> hex
static int hmac_sha256_hex(const char *key, const char *data, char *out_hex, size_t out_size) {
    unsigned int len = 0;
    unsigned char *res = HMAC(EVP_sha256(), key, (int)strlen(key),
                              (unsigned char*)data, strlen(data), NULL, &len);
    if (!res) return -1;
    if (out_size < (size_t)(len*2 + 1)) return -1;
    for (unsigned int i = 0; i < len; ++i) sprintf(out_hex + i*2, "%02x", res[i]);
    out_hex[len*2] = '\0';
    return 0;
}

// Connect non-blocking TCP to business service (returns fd or -1)
static int tcp_connect_nb(const char *host, int port) {
    struct addrinfo hints, *res = NULL, *rp;
    char sport[16];
    snprintf(sport, sizeof(sport), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // IPv4/IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, sport, &hints, &res) != 0) return -1;

    int sock = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        make_nonblocking(sock);
        // initiate connect (non-blocking)
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                close(sock);
                sock = -1;
                continue;
            }
            // EINPROGRESS - okay, in-progress
        }
        break;
    }
    freeaddrinfo(res);
    return sock;
}

// Send framed line (append '\n') on non-blocking TCP (simple, may send partial)
static ssize_t tcp_send_line(int fd, const char *line) {
    size_t len = strlen(line);
    char *buf = malloc(len + 2);
    if (!buf) return -1;
    memcpy(buf, line, len);
    buf[len] = '\n';
    buf[len+1] = '\0';
    size_t sent = 0;
    while (sent < len + 1) {
        ssize_t n = send(fd, buf + sent, (len + 1) - sent, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // can't send now - return how much sent so far
                free(buf);
                return (ssize_t)sent;
            } else {
                free(buf);
                return -1;
            }
        }
        sent += (size_t)n;
    }
    free(buf);
    return (ssize_t)sent;
}

// Minimal line buffer for TCP receive
typedef struct {
    char buf[BUFSZ];
    size_t used;
} linebuf_t;

static void linebuf_init(linebuf_t *lb) { lb->used = 0; }
static void linebuf_append(linebuf_t *lb, const char *data, ssize_t n) {
    if (n <= 0) return;
    size_t to_copy = (size_t)n;
    if (lb->used + to_copy >= sizeof(lb->buf) - 1) {
        // overflow: reset (avoid crash). In production, handle properly.
        lb->used = 0;
        return;
    }
    memcpy(lb->buf + lb->used, data, to_copy);
    lb->used += to_copy;
    lb->buf[lb->used] = '\0';
}

// Pop a line (without newline). Returns 1 if a full line returned.
static int linebuf_pop_line(linebuf_t *lb, char *out, size_t outsz) {
    for (size_t i = 0; i < lb->used; ++i) {
        if (lb->buf[i] == '\n') {
            size_t linelen = i;
            if (linelen >= outsz) linelen = outsz - 1;
            memcpy(out, lb->buf, linelen);
            out[linelen] = '\0';
            // shift remaining
            size_t remain = lb->used - (i + 1);
            memmove(lb->buf, lb->buf + i + 1, remain);
            lb->used = remain;
            lb->buf[lb->used] = '\0';
            return 1;
        }
    }
    return 0;
}

// Trim leading/trailing spaces
static void strtrim(char *s) {
    // left
    char *p = s;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    // right
    size_t len = strlen(s);
    while (len && (s[len-1] == ' ' || s[len-1] == '\t' || s[len-1] == '\r')) { s[len-1] = '\0'; len--; }
}

// Parse SEND command: "SEND <receiver_id> <message...>"
static int parse_send_cmd(const char *line, char *receiver_id, size_t rid_sz, char *message, size_t msg_sz) {
    if (!line) return -1;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "SEND ", 5) != 0) return -1;
    p += 5;
    // receiver id token
    const char *space = strchr(p, ' ');
    if (!space) return -1;
    size_t idlen = (size_t)(space - p);
    if (idlen >= rid_sz) idlen = rid_sz - 1;
    memcpy(receiver_id, p, idlen);
    receiver_id[idlen] = '\0';
    // message is rest
    const char *msgstart = space + 1;
    strncpy(message, msgstart, msg_sz - 1);
    message[msg_sz - 1] = '\0';
    strtrim(receiver_id);
    strtrim(message);
    return 0;
}

int main(int argc, char **argv) {
    // optional consumer ip passed on CLI; if not, Business Service must give it
    const char *cli_consumer_ip = NULL;
    if (argc >= 2) cli_consumer_ip = argv[1];

    // Load .env
    load_env_file(".env");
    const char *SECRET = get_env_value("SECRET_KEY");
    const char *SENDER_ID = get_env_value("SENDER_ID");
    const char *BUS_HOST = get_env_value("BUSINESS_HOST");
    const char *BUS_PORT_S = get_env_value("BUSINESS_PORT");

    if (!SECRET || strlen(SECRET) == 0) {
        fprintf(stderr, "SECRET_KEY missing in .env\n");
        return 1;
    }
    if (!SENDER_ID || strlen(SENDER_ID) == 0) {
        fprintf(stderr, "SENDER_ID missing in .env\n");
        return 1;
    }

    // default business host/port override by env
    char business_host[256] = "127.0.0.1";
    int business_port = 7000;
    if (BUS_HOST && strlen(BUS_HOST) > 0) strncpy(business_host, BUS_HOST, sizeof(business_host)-1);
    if (BUS_PORT_S && strlen(BUS_PORT_S) > 0) business_port = atoi(BUS_PORT_S);

    // UDP socket (for send/reply)
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) { perror("socket udp"); return 1; }

    // bind to ephemeral port to receive replies
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(udp_sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        perror("bind udp");
        close(udp_sock);
        return 1;
    }

    make_nonblocking(udp_sock);
    // tune buffers
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // epoll
    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(udp_sock); return 1; }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = udp_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, udp_sock, &ev);

    // stdin (optional) - allow manual sends for testing
    int fd_stdin = fileno(stdin);
    make_nonblocking(fd_stdin);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd_stdin;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd_stdin, &ev);

    // TCP -> Business Service connection: create non-blocking and add to epoll
    int tcp_fd = -1;
    linebuf_t tcp_recv_buf;
    linebuf_init(&tcp_recv_buf);
    int need_tcp_connect = 1;
    char consumer_ip_override[64] = {0}; // optionally provided by business service

    // consumer default ip/port (CLI or env)
    char default_consumer_ip[64] = "127.0.0.1";
    int default_consumer_port = 6000;
    if (cli_consumer_ip) strncpy(default_consumer_ip, cli_consumer_ip, sizeof(default_consumer_ip)-1);
    const char *env_cons_port = get_env_value("CONSUMER_PORT");
    if (env_cons_port && strlen(env_cons_port) > 0) default_consumer_port = atoi(env_cons_port);

    printf("Sender starting. Business Service: %s:%d, default consumer: %s:%d\n",
           business_host, business_port, default_consumer_ip, default_consumer_port);

    struct epoll_event events[MAX_EVENTS];
    char udp_buf[BUFSZ];
    char stdin_buf[BUFSZ];

    while (1) {
        // (re)connect TCP if needed
        if (need_tcp_connect) {
            if (tcp_fd != -1) { close(tcp_fd); tcp_fd = -1; }
            tcp_fd = tcp_connect_nb(business_host, business_port);
            if (tcp_fd < 0) {
                fprintf(stderr, "tcp connect in progress/failed, will retry in %d ms\n", TCP_RECONNECT_DELAY_MS);
                need_tcp_connect = 1;
                // sleep small time then continue loop to avoid busy loop
                struct timespec ts = {0, TCP_RECONNECT_DELAY_MS * 1000000};
                nanosleep(&ts, NULL);
            } else {
                // add tcp fd to epoll (we will read responses)
                ev.events = EPOLLIN | EPOLLET | EPOLLOUT;
                ev.data.fd = tcp_fd;
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, tcp_fd, &ev) < 0) {
                    // If it fails, close and mark to reconnect
                    perror("epoll_ctl add tcp_fd");
                    close(tcp_fd);
                    tcp_fd = -1;
                    need_tcp_connect = 1;
                    struct timespec ts = {0, TCP_RECONNECT_DELAY_MS * 1000000};
                    nanosleep(&ts, NULL);
                } else {
                    // connected or connecting; clear buffer
                    linebuf_init(&tcp_recv_buf);
                    need_tcp_connect = 0;
                    printf("TCP connected (or connecting) to Business Service fd=%d\n", tcp_fd);
                }
            }
        }

        int nfds = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_WAIT_MS);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;

            if (fd == udp_sock) {
                // drain all UDP datagrams
                while (1) {
                    struct sockaddr_in src;
                    socklen_t slen = sizeof(src);
                    ssize_t r = recvfrom(udp_sock, udp_buf, sizeof(udp_buf)-1, 0, (struct sockaddr*)&src, &slen);
                    if (r <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    udp_buf[r] = '\0';
                    // Expecting reply format: sender_id:message:reply_hmac or sender:receiver:message:hmac depending on consumer
                    // We'll simple parse: first token = sender_id, next token maybe message or receiver; to keep consistent
                    // our consumer replies: sender:message:reply_hmac
                    char r_sender[128] = {0}, r_message[4096] = {0}, r_hmac[256] = {0};
                    // parse by finding first ':' and last ':'
                    char *p1 = strchr(udp_buf, ':');
                    char *plast = strrchr(udp_buf, ':');
                    if (!p1 || !plast || p1 == plast) {
                        printf("[udp reply] malformed: %s\n", udp_buf);
                    } else {
                        size_t s_len = p1 - udp_buf;
                        size_t m_len = plast - (p1 + 1);
                        if (s_len >= sizeof(r_sender)) s_len = sizeof(r_sender)-1;
                        if (m_len >= sizeof(r_message)) m_len = sizeof(r_message)-1;
                        memcpy(r_sender, udp_buf, s_len); r_sender[s_len] = '\0';
                        memcpy(r_message, p1+1, m_len); r_message[m_len] = '\0';
                        strncpy(r_hmac, plast+1, sizeof(r_hmac)-1);
                        // verify HMAC if desired (we know SECRET and can compute)
                        char verify_data[8192];
                        snprintf(verify_data, sizeof(verify_data), "%s:%s", r_sender, r_message);
                        char expected_h[HMAC_HEX_LEN+1];
                        if (hmac_sha256_hex(SECRET, verify_data, expected_h, sizeof(expected_h)) == 0) {
                            if (strcmp(expected_h, r_hmac) != 0) {
                                fprintf(stderr, "Warning: reply HMAC mismatch for sender=%s\n", r_sender);
                            }
                        }
                        // Notify Business Service via TCP: "DELIVERED <sender_id> <receiver_id> <message>"
                        // Note: we don't have receiver_id in the reply; receiver_id is known at send time (we could track it).
                        // To keep simple: we will notify business: DELIVERED <SENDER_ID> <SENDER_FROM_REPLY> <message>
                        // If you need the original receiver_id, maintain an in-memory map of (transaction-id -> receiver).
                        char notify_line[BUFSZ];
                        snprintf(notify_line, sizeof(notify_line), "DELIVERED %s %s %s", SENDER_ID, r_sender, r_message);
                        if (tcp_fd >= 0 && !need_tcp_connect) {
                            ssize_t s = tcp_send_line(tcp_fd, notify_line);
                            if (s < 0) {
                                fprintf(stderr, "Failed send to Business Service, will reconnect\n");
                                // schedule reconnect
                                need_tcp_connect = 1;
                            }
                        } else {
                            fprintf(stderr, "No TCP connection to Business Service - cannot notify DELIVERED\n");
                        }
                    }
                }
            } else if (fd == fd_stdin) {
                // support manual send from stdin for testing: format: <receiver_id> <message>
                while (1) {
                    ssize_t r = read(fd_stdin, stdin_buf, sizeof(stdin_buf)-1);
                    if (r <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    stdin_buf[r] = '\0';
                    // may contain multiple lines
                    char *saveptr = NULL;
                    char *line = strtok_r(stdin_buf, "\n", &saveptr);
                    while (line) {
                        strtrim(line);
                        if (strlen(line) == 0) { line = strtok_r(NULL, "\n", &saveptr); continue; }
                        // parse: first token receiver_id, rest message
                        char *sp = strchr(line, ' ');
                        if (!sp) {
                            fprintf(stderr, "stdin: use: <receiver_id> <message>\n");
                        } else {
                            char receiver[128]; memset(receiver,0,sizeof(receiver));
                            char message[4096]; memset(message,0,sizeof(message));
                            size_t idlen = sp - line;
                            if (idlen >= sizeof(receiver)) idlen = sizeof(receiver)-1;
                            memcpy(receiver, line, idlen); receiver[idlen]=0;
                            strncpy(message, sp+1, sizeof(message)-1);
                            // send UDP
                            // build payload sender:receiver:message:hmac
                            char data[8192];
                            snprintf(data, sizeof(data), "%s:%s:%s", SENDER_ID, receiver, message);
                            char hmac_hex[HMAC_HEX_LEN+1];
                            if (hmac_sha256_hex(SECRET, data, hmac_hex, sizeof(hmac_hex)) != 0) {
                                fprintf(stderr, "HMAC compute failed\n");
                                continue;
                            }
                            char payload[16384];
                            snprintf(payload, sizeof(payload), "%s:%s:%s:%s", SENDER_ID, receiver, message, hmac_hex);
                            // determine consumer address - use override or default
                            struct sockaddr_in consumer_addr;
                            memset(&consumer_addr, 0, sizeof(consumer_addr));
                            consumer_addr.sin_family = AF_INET;
                            const char *target_ip = (consumer_ip_override[0] ? consumer_ip_override : default_consumer_ip);
                            inet_pton(AF_INET, target_ip, &consumer_addr.sin_addr);
                            consumer_addr.sin_port = htons(default_consumer_port);

                            ssize_t sent = sendto(udp_sock, payload, strlen(payload), 0,
                                                  (struct sockaddr*)&consumer_addr, sizeof(consumer_addr));
                            if (sent < 0) perror("sendto");
                            else printf("[manual sent] %s -> %s:%d\n", payload, target_ip, default_consumer_port);
                        }
                        line = strtok_r(NULL, "\n", &saveptr);
                    }
                }
            } else if (fd == tcp_fd) {
                // handle TCP events (in-progress connect, read incoming lines)
                // First, check for EPOLLOUT (connection completion)
                if (events[i].events & EPOLLERR) {
                    fprintf(stderr, "TCP socket error; reconnecting\n");
                    need_tcp_connect = 1;
                    epoll_ctl(epfd, EPOLL_CTL_DEL, tcp_fd, NULL);
                    close(tcp_fd);
                    tcp_fd = -1;
                    continue;
                }

                if (events[i].events & EPOLLOUT) {
                    // connection may have completed; check SO_ERROR
                    int soerr = 0; socklen_t len = sizeof(soerr);
                    if (getsockopt(tcp_fd, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0) {
                        if (soerr == 0) {
                            // connected
                            // modify epoll to remove EPOLLOUT interest; only EPOLLIN|ET
                            ev.events = EPOLLIN | EPOLLET;
                            ev.data.fd = tcp_fd;
                            epoll_ctl(epfd, EPOLL_CTL_MOD, tcp_fd, &ev);
                            printf("TCP connection established to Business Service (fd=%d)\n", tcp_fd);
                        } else {
                            fprintf(stderr, "TCP connect failed: %s\n", strerror(soerr));
                            need_tcp_connect = 1;
                            epoll_ctl(epfd, EPOLL_CTL_DEL, tcp_fd, NULL);
                            close(tcp_fd);
                            tcp_fd = -1;
                            continue;
                        }
                    }
                }

                if (events[i].events & EPOLLIN) {
                    // read all available data
                    while (1) {
                        ssize_t r = recv(tcp_fd, udp_buf, sizeof(udp_buf)-1, 0);
                        if (r < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                            perror("recv tcp");
                            need_tcp_connect = 1;
                            epoll_ctl(epfd, EPOLL_CTL_DEL, tcp_fd, NULL);
                            close(tcp_fd);
                            tcp_fd = -1;
                            break;
                        } else if (r == 0) {
                            // remote closed
                            fprintf(stderr, "Business Service closed TCP\n");
                            need_tcp_connect = 1;
                            epoll_ctl(epfd, EPOLL_CTL_DEL, tcp_fd, NULL);
                            close(tcp_fd);
                            tcp_fd = -1;
                            break;
                        } else {
                            // append to buffer and process lines
                            linebuf_append(&tcp_recv_buf, udp_buf, r);
                            char line[4096];
                            while (linebuf_pop_line(&tcp_recv_buf, line, sizeof(line))) {
                                strtrim(line);
                                if (strlen(line) == 0) continue;
                                // optional commands:
                                // SEND <receiver_id> <message...>
                                // SET_CONSUMER <ip> <port>
                                // Example: SET_CONSUMER 10.0.0.5 6000
                                if (strncmp(line, "SEND ", 5) == 0) {
                                    char receiver[128] = {0}, message[4096] = {0};
                                    if (parse_send_cmd(line, receiver, sizeof(receiver), message, sizeof(message)) == 0) {
                                        // build payload and send via UDP (same logic as manual)
                                        char data[8192];
                                        snprintf(data, sizeof(data), "%s:%s:%s", SENDER_ID, receiver, message);
                                        char hmac_hex[HMAC_HEX_LEN+1];
                                        if (hmac_sha256_hex(SECRET, data, hmac_hex, sizeof(hmac_hex)) != 0) {
                                            fprintf(stderr, "HMAC compute failed\n");
                                            continue;
                                        }
                                        char payload[16384];
                                        snprintf(payload, sizeof(payload), "%s:%s:%s:%s", SENDER_ID, receiver, message, hmac_hex);

                                        struct sockaddr_in consumer_addr;
                                        memset(&consumer_addr, 0, sizeof(consumer_addr));
                                        consumer_addr.sin_family = AF_INET;
                                        const char *target_ip = (consumer_ip_override[0] ? consumer_ip_override : default_consumer_ip);
                                        int target_port = default_consumer_port;
                                        inet_pton(AF_INET, target_ip, &consumer_addr.sin_addr);
                                        consumer_addr.sin_port = htons(target_port);

                                        ssize_t sent = sendto(udp_sock, payload, strlen(payload), 0,
                                                              (struct sockaddr*)&consumer_addr, sizeof(consumer_addr));
                                        if (sent < 0) perror("sendto");
                                        else printf("[sent -> %s:%d] %s\n", target_ip, target_port, payload);
                                    } else {
                                        fprintf(stderr, "Bad SEND command format\n");
                                    }
                                } else if (strncmp(line, "SET_CONSUMER ", 13) == 0) {
                                    // SET_CONSUMER <ip> <port>
                                    char ip[64] = {0}; int port = 0;
                                    if (sscanf(line + 13, "%63s %d", ip, &port) == 2) {
                                        strncpy(consumer_ip_override, ip, sizeof(consumer_ip_override)-1);
                                        default_consumer_port = port;
                                        printf("Consumer override set to %s:%d\n", consumer_ip_override, default_consumer_port);
                                    } else {
                                        fprintf(stderr, "Bad SET_CONSUMER format\n");
                                    }
                                } else {
                                    printf("Unknown command from Business Service: %s\n", line);
                                }
                            }
                        }
                    }
                }
            } else {
                // unknown fd
            }
        } // end events
    } // end main loop

    if (udp_sock >= 0) close(udp_sock);
    if (tcp_fd >= 0) close(tcp_fd);
    close(epfd);
    return 0;
}
