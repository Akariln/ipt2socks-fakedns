#include "tcp_proxy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"
#include "socks5.h"

/* ── Compile-time layout assertions ── */

/* hs.resp[] must hold every SOCKS5 response received during handshake */
_Static_assert(sizeof(socks5_authresp_t)   <= TCP_HANDSHAKE_RESP_MAXLEN, "resp buffer too small for authresp");
_Static_assert(sizeof(socks5_usrpwdresp_t) <= TCP_HANDSHAKE_RESP_MAXLEN, "resp buffer too small for usrpwdresp");
_Static_assert(sizeof(socks5_ipv4resp_t)   <= TCP_HANDSHAKE_RESP_MAXLEN, "resp buffer too small for ipv4resp");
_Static_assert(sizeof(socks5_ipv6resp_t)   <= TCP_HANDSHAKE_RESP_MAXLEN, "resp buffer too small for ipv6resp");

/* hs.req[] must hold every SOCKS5 proxy request built during handshake */
_Static_assert(sizeof(socks5_ipv4req_t)    <= TCP_HANDSHAKE_REQ_MAXLEN,  "req buffer too small for ipv4req");
_Static_assert(sizeof(socks5_ipv6req_t)    <= TCP_HANDSHAKE_REQ_MAXLEN,  "req buffer too small for ipv6req");

/* splice() api */
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1

#undef  SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2

#define splice(fdin, offin, fdout, offout, len, flags) syscall(__NR_splice, fdin, offin, fdout, offout, len, flags)
#endif

/* Forward declarations */
static void tcp_handshake_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_send_authreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_stream_payload_forward_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);


static inline tcp_context_t* get_tcpctx_by_watcher(evio_t *watcher) {
    return (tcp_context_t *)watcher->data;
}

static inline void tcp_context_release(evloop_t *evloop, tcp_context_t *context, bool is_tcp_reset) {
    evio_t *client_watcher = &context->client_watcher;
    evio_t *socks5_watcher = &context->socks5_watcher;
    ev_io_stop(evloop, client_watcher);
    ev_io_stop(evloop, socks5_watcher);
    ev_timer_stop(evloop, &context->handshake_timer);
    if (is_tcp_reset) {
        tcp_close_by_rst(client_watcher->fd);
        tcp_close_by_rst(socks5_watcher->fd);
    } else {
        close(client_watcher->fd);
        close(socks5_watcher->fd);
    }

    if (context->client_pipefd[0] != -1) {
        close(context->client_pipefd[0]);
    }
    if (context->client_pipefd[1] != -1) {
        close(context->client_pipefd[1]);
    }
    if (context->socks5_pipefd[0] != -1) {
        close(context->socks5_pipefd[0]);
    }
    if (context->socks5_pipefd[1] != -1) {
        close(context->socks5_pipefd[1]);
    }

    /* Remove from session list */
    if (context->next) {
        context->next->prev = context->prev;
    }
    if (context->prev) {
        context->prev->next = context->next;
    } else {
        g_tcp_session_head = context->next;
    }

    mempool_free_sized(g_tcp_context_pool, context, sizeof(*context));
}

void tcp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[tcp_proxy_close_all_sessions] cleaning up remaining sessions...");
    tcp_context_t *curr = (tcp_context_t *)g_tcp_session_head;
    while (curr) {
        tcp_context_t *next = curr->next;
        tcp_context_release(evloop, curr, false);
        curr = next;
    }
}

static void tcp_handshake_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = (tcp_context_t *)watcher->data;
    LOGERR("[tcp_handshake_timeout_cb] socks5 handshake timed out (%gs), closing", TCP_HANDSHAKE_TIMEOUT_SEC);
    tcp_context_release(evloop, context, true);
}

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *accept_watcher = (evio_t *)watcher;
    bool isipv4 = (intptr_t)accept_watcher->data;
    skaddr6_t skaddr;
    char ipstr[IP6STRLEN];
    portno_t portno;

    int client_sockfd = tcp_accept(accept_watcher->fd, (void *)&skaddr, &(socklen_t) {
        sizeof(skaddr)
    });
    if (client_sockfd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_tproxy_accept_cb] accept tcp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_tproxy_accept_cb] source socket address: %s#%hu", ipstr, portno);
    }

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr, !(g_options & OPT_TCP_USE_REDIRECT))) {
        tcp_close_by_rst(client_sockfd);
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_tproxy_accept_cb] target socket address: %s#%hu", ipstr, portno);
    }

    /* FakeDNS reverse lookup for domain resolution */
    const char *fake_domain = NULL;
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        bool is_miss;
        fake_domain = fakedns_try_resolve(target_ip, &is_miss);
        if (is_miss) {
            LOGERR("[tcp_tproxy_accept_cb] fakedns miss for FakeIP: %u.%u.%u.%u, dropping connection",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
            tcp_close_by_rst(client_sockfd);
            return;
        }
        IF_VERBOSE if (fake_domain) {
            LOGINF_RAW("[tcp_tproxy_accept_cb] fakedns hit: %u.%u.%u.%u -> %s",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                       fake_domain);
        }
    }

    int socks5_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
    if (socks5_sockfd < 0) {
        LOGERR("[tcp_tproxy_accept_cb] new_tcp_connect_sockfd: %s", strerror(errno));
        tcp_close_by_rst(client_sockfd);
        return;
    }
    const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
    size_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
    ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

    if (!tcp_connect(socks5_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
        LOGERR("[tcp_tproxy_accept_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_close_by_rst(client_sockfd);
        close(socks5_sockfd);
        return;
    }
    if (tfo_nsend >= 0) {
        LOGINF("[tcp_tproxy_accept_cb] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
    } else {
        LOGINF("[tcp_tproxy_accept_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
    }

    tcp_context_t *context = mempool_alloc_sized(g_tcp_context_pool, sizeof(*context));
    if (!context) {
        LOGERR("[tcp_tproxy_accept_cb] mempool_alloc failed");
        tcp_close_by_rst(client_sockfd);
        close(socks5_sockfd);
        return;
    }
    context->client_pipefd[0] = context->client_pipefd[1] = -1;
    context->socks5_pipefd[0] = context->socks5_pipefd[1] = -1;
    context->client_eof = false;
    context->socks5_eof = false;

    /* Add to session list (prepend) */
    context->prev = NULL;
    context->next = (tcp_context_t *)g_tcp_session_head;
    if (context->next) {
        context->next->prev = context;
    }
    g_tcp_session_head = context;

    /* Link watcher data to parent context */
    context->client_watcher.data = context;
    context->socks5_watcher.data = context;

    evio_t *io_watcher = &context->client_watcher;
    ev_io_init(io_watcher, tcp_stream_payload_forward_cb, client_sockfd, EV_READ);

    /* build the ipv4/ipv6 proxy request (send to the socks5 proxy server) */
    size_t actual_len = 0;
    socks5_proxy_request_make(context->hs.req, &skaddr, fake_domain, &actual_len);
    context->hs.req_len = (uint32_t)actual_len;

    io_watcher = &context->socks5_watcher;
    if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
        ev_io_init(io_watcher, tcp_socks5_recv_authresp_cb, socks5_sockfd, EV_READ);
        tfo_nsend = 0; /* reset to zero for next send */
    } else {
        ev_io_init(io_watcher, tfo_nsend >= 0 ? tcp_socks5_send_authreq_cb : tcp_socks5_connect_cb, socks5_sockfd, EV_WRITE);
        tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
    }
    context->hs.io_offset = (uint32_t)tfo_nsend;
    ev_io_start(evloop, io_watcher);

    context->handshake_timer.data = context;
    ev_timer_init(&context->handshake_timer, tcp_handshake_timeout_cb, TCP_HANDSHAKE_TIMEOUT_SEC, 0.);
    ev_timer_start(evloop, &context->handshake_timer);
}

static void tcp_socks5_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    if (tcp_has_error(socks5_watcher->fd)) {
        LOGERR("[tcp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    LOGINF("[tcp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(socks5_watcher, tcp_socks5_send_authreq_cb);
    ev_invoke(evloop, socks5_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int tcp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, const void *data, size_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    const uint8_t *pdata = (const uint8_t *)data;
    ssize_t nsend = send(socks5_watcher->fd, pdata + context->hs.io_offset, datalen - context->hs.io_offset, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, nsend);
    context->hs.io_offset += (uint32_t)nsend;
    if (context->hs.io_offset >= datalen) {
        context->hs.io_offset = 0;
        return 1;
    }
    return 0;
}

/* return: -1(error_occurred); 0(partial_recv); 1(completely_recv) */
static int tcp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, void *data, size_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    uint8_t *pdata = (uint8_t *)data;
    ssize_t nrecv = recv(socks5_watcher->fd, pdata + context->hs.io_offset, datalen - context->hs.io_offset, 0);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    if (nrecv == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        tcp_context_release(evloop, context, true);
        return -1;
    }
    LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, nrecv);
    context->hs.io_offset += (uint32_t)nrecv;
    if (context->hs.io_offset >= datalen) {
        context->hs.io_offset = 0;
        return 1;
    }
    return 0;
}

static void tcp_socks5_send_authreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    if (tcp_socks5_send_request("tcp_socks5_send_authreq_cb", evloop, socks5_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t)) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_authresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_recv_response("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, context->hs.resp, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("tcp_socks5_recv_authresp_cb", (const socks5_authresp_t *)context->hs.resp)) {
        tcp_context_release(evloop, context, true);
        return;
    }
    const void *data = g_socks5_usrpwd_requestlen ? (const void *)&g_socks5_usrpwd_request : (const void *)context->hs.req;
    size_t datalen = g_socks5_usrpwd_requestlen ? g_socks5_usrpwd_requestlen : context->hs.req_len;
    int ret = tcp_socks5_send_request("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(socks5_watcher, g_socks5_usrpwd_requestlen ? tcp_socks5_recv_usrpwdresp_cb : tcp_socks5_recv_proxyresp_cb);
        if (!g_socks5_usrpwd_requestlen) {
            context->hs.resp_expect = SOCKS5_RESP_HEADER_PREFIX_LEN;
        }
    } else if (ret == 0) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, g_socks5_usrpwd_requestlen ? tcp_socks5_send_usrpwdreq_cb : tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    if (tcp_socks5_send_request("tcp_socks5_send_usrpwdreq_cb", evloop, socks5_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_usrpwdresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_recv_response("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, context->hs.resp, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("tcp_socks5_recv_usrpwdresp_cb", (const socks5_usrpwdresp_t *)context->hs.resp)) {
        tcp_context_release(evloop, context, true);
        return;
    }
    int ret = tcp_socks5_send_request("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, context->hs.req, context->hs.req_len);
    if (ret == 1) {
        ev_set_cb(socks5_watcher, tcp_socks5_recv_proxyresp_cb);
        context->hs.resp_expect = SOCKS5_RESP_HEADER_PREFIX_LEN;
    } else if (ret == 0) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_send_request("tcp_socks5_send_proxyreq_cb", evloop, socks5_watcher, context->hs.req, context->hs.req_len) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_proxyresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
    context->hs.resp_expect = SOCKS5_RESP_HEADER_PREFIX_LEN;
}

static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *socks5_watcher = (evio_t *)watcher;
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_recv_response("tcp_socks5_recv_proxyresp_cb", evloop, socks5_watcher, context->hs.resp, context->hs.resp_expect) != 1) {
        return;
    }

    /* If we just read the first 5 bytes (Header prefix) */
    if (context->hs.resp_expect == SOCKS5_RESP_HEADER_PREFIX_LEN) {
        uint8_t atype = ((socks5_resp_header_t *)context->hs.resp)->addrtype;
        size_t total_len;

        if (atype == SOCKS5_ADDRTYPE_IPV4) {
            total_len = sizeof(socks5_ipv4resp_t); // 10
        } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
            total_len = sizeof(socks5_ipv6resp_t); // 22
        } else {
            LOGERR("[tcp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
            tcp_context_release(evloop, context, true);
            return;
        }

        if (total_len > sizeof(context->hs.resp)) {
            LOGERR("[tcp_socks5_recv_proxyresp_cb] response too large: %zu", total_len);
            tcp_context_release(evloop, context, true);
            return;
        }

        /* Update length targets */
        context->hs.resp_expect = (uint32_t)total_len;
        context->hs.io_offset = SOCKS5_RESP_HEADER_PREFIX_LEN;

        /* Attempt to read the rest immediately */
        if (tcp_socks5_recv_response("tcp_socks5_recv_proxyresp_cb", evloop, socks5_watcher, context->hs.resp, context->hs.resp_expect) != 1) {
            return;
        }
    }

    if (!socks5_proxy_response_check("tcp_socks5_recv_proxyresp_cb", (const socks5_resp_header_t *)context->hs.resp)) {
        tcp_context_release(evloop, context, true);
        return;
    }

    /* === Phase transition: handshake → forwarding === */
    context->fwd.client_pending = 0;
    context->fwd.socks5_pending = 0;

    if (new_nonblock_pipefd(context->client_pipefd) < 0) {
        LOGERR("[tcp_socks5_recv_proxyresp_cb] failed to create client pipe");
        tcp_context_release(evloop, context, true);
        return;
    }
    if (new_nonblock_pipefd(context->socks5_pipefd) < 0) {
        LOGERR("[tcp_socks5_recv_proxyresp_cb] failed to create socks5 pipe");
        tcp_context_release(evloop, context, true);
        return;
    }

    ev_timer_stop(evloop, &context->handshake_timer);
    ev_io_start(evloop, &context->client_watcher);
    ev_set_cb(socks5_watcher, tcp_stream_payload_forward_cb);
    LOGINF("[tcp_socks5_recv_proxyresp_cb] tunnel is ready, start forwarding ...");
}

static void tcp_stream_payload_forward_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evio_t *self_watcher = (evio_t *)watcher;
    tcp_context_t *context = get_tcpctx_by_watcher(self_watcher);
    bool self_is_client = (self_watcher == &context->client_watcher);
    evio_t *peer_watcher = self_is_client ? &context->socks5_watcher : &context->client_watcher;
    bool *self_eof = self_is_client ? &context->client_eof : &context->socks5_eof;
    bool *peer_eof = self_is_client ? &context->socks5_eof : &context->client_eof;
    uint32_t *self_pending = self_is_client ? &context->fwd.client_pending : &context->fwd.socks5_pending;
    uint32_t *peer_pending = self_is_client ? &context->fwd.socks5_pending : &context->fwd.client_pending;

    if (revents & EV_READ) {
        int *self_pipefd = self_is_client ? context->client_pipefd : context->socks5_pipefd;
        ssize_t nrecv = splice(self_watcher->fd, NULL, self_pipefd[1], NULL, TCP_SPLICE_MAXLEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nrecv < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == ECONNRESET) {
                    IF_VERBOSE {
                        LOGINF_RAW("[tcp_stream_payload_forward_cb] recv from %s stream: %s, cascade RST", self_is_client ? "client" : "socks5", strerror(errno));
                    }
                } else {
                    IF_VERBOSE {
                        LOGERR("[tcp_stream_payload_forward_cb] recv from %s stream: %s", self_is_client ? "client" : "socks5", strerror(errno));
                    }
                }
                tcp_context_release(evloop, context, true);
                return;
            }
            goto DO_WRITE; // EAGAIN
        }
        if (nrecv == 0) {
            LOGINF("[tcp_stream_payload_forward_cb] recv FIN from %s stream", self_is_client ? "client" : "socks5");
            *self_eof = true;
            int new_events = self_watcher->events & ~EV_READ;
            ev_io_stop(evloop, self_watcher);
            if (new_events) {
                ev_io_set(self_watcher, self_watcher->fd, new_events);
                ev_io_start(evloop, self_watcher);
            }

            if (*self_pending == 0) {
                shutdown(peer_watcher->fd, SHUT_WR);
            }
        } else {
            ssize_t nsend = splice(self_pipefd[0], NULL, peer_watcher->fd, NULL, (size_t)nrecv, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (nsend < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (errno == EPIPE || errno == ECONNRESET) {
                        IF_VERBOSE {
                            LOGINF_RAW("[tcp_stream_payload_forward_cb] send to %s stream: %s, cascade RST", self_is_client ? "socks5" : "client", strerror(errno));
                        }
                    } else {
                        LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "socks5" : "client", strerror(errno));
                    }
                    tcp_context_release(evloop, context, true);
                    return;
                }
                nsend = 0; // EAGAIN
            }
            if (nsend < nrecv) {
                *self_pending = (uint32_t)(nrecv - nsend); // remain_length

                int new_self_events = self_watcher->events & ~EV_READ;
                ev_io_stop(evloop, self_watcher);
                if (new_self_events) {
                    ev_io_set(self_watcher, self_watcher->fd, new_self_events);
                    ev_io_start(evloop, self_watcher);
                }

                int new_peer_events = peer_watcher->events | EV_WRITE;
                ev_io_stop(evloop, peer_watcher);
                ev_io_set(peer_watcher, peer_watcher->fd, new_peer_events);
                ev_io_start(evloop, peer_watcher);
            }
        }
    }

DO_WRITE:
    if (revents & EV_WRITE) {
        int *peer_pipefd = self_is_client ? context->socks5_pipefd : context->client_pipefd;

        ssize_t nsend = splice(peer_pipefd[0], NULL, self_watcher->fd, NULL, *peer_pending, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == EPIPE || errno == ECONNRESET) {
                    IF_VERBOSE {
                        LOGINF_RAW("[tcp_stream_payload_forward_cb] send to %s stream: %s, cascade RST", self_is_client ? "client" : "socks5", strerror(errno));
                    }
                } else {
                    LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "client" : "socks5", strerror(errno));
                }
                tcp_context_release(evloop, context, true);
            }
            return;
        }
        if (nsend > 0) {
            *peer_pending -= (uint32_t)nsend;

            if (*peer_pending == 0) {
                int new_events = self_watcher->events & ~EV_WRITE;
                ev_io_stop(evloop, self_watcher);
                if (new_events) {
                    ev_io_set(self_watcher, self_watcher->fd, new_events);
                    ev_io_start(evloop, self_watcher);
                }

                if (!*peer_eof) {
                    int peer_new_events = peer_watcher->events | EV_READ;
                    ev_io_stop(evloop, peer_watcher);
                    ev_io_set(peer_watcher, peer_watcher->fd, peer_new_events);
                    ev_io_start(evloop, peer_watcher);
                } else {
                    shutdown(self_watcher->fd, SHUT_WR);
                }
            }
        }
    }

    if (context->client_eof && context->socks5_eof && context->fwd.client_pending == 0 && context->fwd.socks5_pending == 0) {
        LOGINF("[tcp_stream_payload_forward_cb] both streams are EOF and pipes are empty, release ctx");
        tcp_context_release(evloop, context, false);
    }
}
