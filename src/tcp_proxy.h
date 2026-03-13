#ifndef IPT2SOCKS_TCP_PROXY_H
#define IPT2SOCKS_TCP_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "ev_types.h"

#define TCP_SPLICE_MAXLEN   (256 * 1024) /* match pipe buffer size */
#define TCP_PIPE_SIZE       (256 * 1024) /* F_SETPIPE_SZ target */

typedef struct tcp_context_t {
    evio_t   client_watcher;   // .data: points to parent tcp_context_t
    evio_t   socks5_watcher;   // .data: points to parent tcp_context_t
    int      client_pipefd[2]; // client pipe buffer
    int      socks5_pipefd[2]; // socks5 pipe buffer
    uint32_t client_length;    // remaining payload length
    uint32_t socks5_length;    // remaining payload length
    bool     client_eof;       // self eof
    bool     socks5_eof;       // peer eof
    union {
        uint8_t handshake_buf[320]; // Buffer for handshake messages
        struct {
            uint8_t req[290];       // Space for proxy request
            uint8_t resp[30];       // Space for proxy response
        } handshake;
    };
    struct tcp_context_t *prev;  // Doubly linked list for cleanup
    struct tcp_context_t *next;
} tcp_context_t;

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);

#endif
