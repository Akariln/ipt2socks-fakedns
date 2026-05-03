#ifndef IPT2SOCKS_TCP_PROXY_H
#define IPT2SOCKS_TCP_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "ev_types.h"
#include "fakedns.h"
#include "socks5.h"

#define TCP_SPLICE_MAXLEN         (64 * 1024)
#define TCP_HANDSHAKE_TIMEOUT_SEC 5.0

#define TCP_HANDSHAKE_REQ_MAXLEN \
    (sizeof(socks5_domainreq_t) + (FAKEDNS_MAX_DOMAIN_LEN - 1) + sizeof(portno_t))

#define TCP_HANDSHAKE_RESP_MAXLEN (sizeof(socks5_ipv6resp_t))

typedef struct tcp_session tcp_session_t;

struct tcp_session {
    evio_t    client_watcher;
    evio_t    socks5_watcher;
    int       client_pipefd[2];
    int       socks5_pipefd[2];
    evtimer_t handshake_timer;

    union {
        struct {
            uint8_t  req[TCP_HANDSHAKE_REQ_MAXLEN];
            uint8_t  resp[TCP_HANDSHAKE_RESP_MAXLEN];
            uint32_t req_len;
            uint32_t io_offset;
            uint32_t resp_expect;
        } handshake;
        struct {
            bool     client_eof;
            bool     socks5_eof;
            uint32_t client_to_socks5_pending;
            uint32_t socks5_to_client_pending;
        } fwd;
    };

    struct tcp_session *prev;
    struct tcp_session *next;
};

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);

#endif /* IPT2SOCKS_TCP_PROXY_H */
