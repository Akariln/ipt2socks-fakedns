#ifndef IPT2SOCKS_TCP_PROXY_H
#define IPT2SOCKS_TCP_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "ev_types.h"
#include "fakedns.h"
#include "socks5.h"

#define TCP_SPLICE_MAXLEN         (64 * 1024) /* PIPE_DEF_BUFSZ on x86-64 (16 * PAGE_SIZE) */
#define TCP_HANDSHAKE_TIMEOUT_SEC 15.0         /* ev_tstamp: socks5 handshake deadline */

/* socks5_domainreq_t(5) + domain(FAKEDNS_MAX_DOMAIN_LEN-1) + portno_t(2) */
#define TCP_HANDSHAKE_REQ_MAXLEN \
    (sizeof(socks5_domainreq_t) + (FAKEDNS_MAX_DOMAIN_LEN - 1) + sizeof(portno_t))

/* largest proxy response is IPv6: sizeof(socks5_ipv6resp_t) */
#define TCP_HANDSHAKE_RESP_MAXLEN (sizeof(socks5_ipv6resp_t))

typedef struct tcp_context_t {
    evio_t   client_watcher;   // .data: points to parent tcp_context_t
    evio_t   socks5_watcher;   // .data: points to parent tcp_context_t
    int      client_pipefd[2]; // client pipe buffer
    int      socks5_pipefd[2]; // socks5 pipe buffer
    bool     client_eof;       // self eof
    bool     socks5_eof;       // peer eof
    evtimer_t handshake_timer; // fired if socks5 handshake exceeds TCP_HANDSHAKE_TIMEOUT_SEC
    union {
        /* Active during SOCKS5 handshake (before tunnel is established) */
        struct {
            uint8_t  req[TCP_HANDSHAKE_REQ_MAXLEN];   // socks5 proxy request
            uint8_t  resp[TCP_HANDSHAKE_RESP_MAXLEN];  // socks5 handshake response
            uint32_t req_len;      // proxy request total length
            uint32_t io_offset;    // current send/recv byte offset
            uint32_t resp_expect;  // expected proxy response length (two-phase read)
        } hs;
        /* Active during payload forwarding (after tunnel is established) */
        struct {
            uint32_t client_pending; // bytes remaining in client→socks5 pipe
            uint32_t socks5_pending; // bytes remaining in socks5→client pipe
        } fwd;
    };
    struct tcp_context_t *prev;  // Doubly linked list for cleanup
    struct tcp_context_t *next;
} tcp_context_t;

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);

#endif
