#include "udp_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"
#include "socks5.h"

/* handshake payload must hold every SOCKS5 response received during handshake */
_Static_assert(sizeof(socks5_authresp_t)   <= sizeof(((udp_session_t *)0)->handshake.payload), "handshake payload too small for authresp");
_Static_assert(sizeof(socks5_usrpwdresp_t) <= sizeof(((udp_session_t *)0)->handshake.payload), "handshake payload too small for usrpwdresp");
_Static_assert(sizeof(socks5_ipv4resp_t)   <= sizeof(((udp_session_t *)0)->handshake.payload), "handshake payload too small for ipv4resp");
_Static_assert(sizeof(socks5_ipv6resp_t)   <= sizeof(((udp_session_t *)0)->handshake.payload), "handshake payload too small for ipv6resp");

/* MAX_SOCKS5_UDP_HEADER must cover the largest possible UDP encapsulation header */
_Static_assert(sizeof(socks5_udp4msg_t) <= MAX_SOCKS5_UDP_HEADER, "MAX_SOCKS5_UDP_HEADER too small for ipv4");
_Static_assert(sizeof(socks5_udp6msg_t) <= MAX_SOCKS5_UDP_HEADER, "MAX_SOCKS5_UDP_HEADER too small for ipv6");
_Static_assert(sizeof(socks5_udp_domainmsg_t) + MAX_DOMAIN_LEN + sizeof(portno_t) <= MAX_SOCKS5_UDP_HEADER,
               "MAX_SOCKS5_UDP_HEADER too small for domain");

/* symmetric_key is hashed as a whole struct; both endpoints must be tightly packed. */
_Static_assert(sizeof(udp_symmetric_key_t) == 2 * sizeof(udp_endpoint_key_t),
               "udp_symmetric_key_t must be tightly packed for memcmp hashing");

/* Forward declarations */
static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, size_t nrecv, char *buffer);
static void udp_socks5_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_send_authreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_authresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_session_close_indexed(evloop_t *evloop, udp_session_t *session);
static void udp_session_close_detached(evloop_t *evloop, udp_session_t *session);
static void udp_tproxy_entry_close(evloop_t *evloop, udp_tproxy_entry_t *entry);
static void udp_gc_on_tick(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static inline void udp_session_release(evloop_t *evloop, udp_session_t *session);
static void udp_session_free(evloop_t *evloop, udp_session_t *session);
static void udp_tproxy_entry_free(udp_tproxy_entry_t *entry);

static inline void udp_session_keepalive(evloop_t *evloop, udp_session_t *session) {
    if (session->fullcone_node) {
        session->fullcone_node->last_active = ev_now(evloop);
    } else {
        session->symmetric_node->last_active = ev_now(evloop);
    }
}

static inline udp_endpoint_key_t udp_endpoint_from_skaddr(const skaddr6_t *skaddr, bool is_ipv4) {
    udp_endpoint_key_t ep;
    memset(&ep, 0, sizeof(ep));
    if (is_ipv4) {
        const skaddr4_t *sa4 = (const skaddr4_t *)skaddr;
        ep.family = AF_INET;
        ep.port = sa4->sin_port;
        memcpy(ep.addr, &sa4->sin_addr.s_addr, IP4BINLEN);
    } else {
        ep.family = AF_INET6;
        ep.port = skaddr->sin6_port;
        memcpy(ep.addr, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
    }
    return ep;
}

static inline void udp_skaddr_from_endpoint(skaddr6_t *dst, const udp_endpoint_key_t *ep) {
    memset(dst, 0, sizeof(*dst));
    if (ep->family == AF_INET) {
        skaddr4_t *a = (void *)dst;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr.s_addr, ep->addr, IP4BINLEN);
        a->sin_port = ep->port;
    } else {
        dst->sin6_family = AF_INET6;
        memcpy(&dst->sin6_addr.s6_addr, ep->addr, IP6BINLEN);
        dst->sin6_port = ep->port;
    }
}

static inline void udp_endpoint_to_string(const udp_endpoint_key_t *ep, char ipstr[IP6STRLEN], portno_t *portno) {
    if (ep->family == AF_INET) {
        inet_ntop(AF_INET, ep->addr, ipstr, IP6STRLEN);
    } else {
        inet_ntop(AF_INET6, ep->addr, ipstr, IP6STRLEN);
    }
    *portno = ntohs(ep->port);
}

void udp_tproxy_recvmsg_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tprecv_watcher = (evio_t *)watcher;
    bool isipv4 = (intptr_t)tprecv_watcher->data;

    static __thread struct mmsghdr msgs[UDP_BATCH_SIZE];
    static __thread struct iovec iovs[UDP_BATCH_SIZE];
    static __thread char msg_control_buffers[UDP_BATCH_SIZE][UDP_CTRLMESG_BUFSIZ];
    static __thread skaddr6_t skaddrs[UDP_BATCH_SIZE];
    static __thread bool tproxy_recvmsg_initialized = false;

    if (!tproxy_recvmsg_initialized) {
        for (int i = 0; i < UDP_BATCH_SIZE; i++) {
            iovs[i].iov_base            = (uint8_t *)g_udp_batch_buffer[i] + MAX_SOCKS5_UDP_HEADER;
            iovs[i].iov_len             = UDP_DATAGRAM_MAXSIZ;
            msgs[i].msg_hdr.msg_name    = &skaddrs[i];
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;
            msgs[i].msg_hdr.msg_control = msg_control_buffers[i];
        }
        tproxy_recvmsg_initialized = true;
    }

    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        msgs[i].msg_hdr.msg_namelen    = sizeof(skaddr6_t);
        msgs[i].msg_hdr.msg_controllen = UDP_CTRLMESG_BUFSIZ;
    }

    int retval = recvmmsg(tprecv_watcher->fd, msgs, UDP_BATCH_SIZE, 0, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tproxy_recvmsg_cb] recvmmsg from udp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }

    if (retval == 0) {
        return;
    }

    for (int i = 0; i < retval; i++) {
        handle_udp_socket_msg(evloop, tprecv_watcher, &msgs[i].msg_hdr, (size_t)msgs[i].msg_len, g_udp_batch_buffer[i]);
    }
}

static char *build_socks5_udp_header(char *payload_start, const char *fake_domain, const skaddr6_t *skaddr, bool isipv4, size_t *out_headerlen) {
    char *header_start;
    size_t actual_headerlen;

    if (fake_domain) {
        size_t domain_len = strlen(fake_domain);
        if (domain_len > MAX_DOMAIN_LEN) {
            LOGERR("[build_socks5_udp_header] domain too long: %zu", domain_len);
            return NULL;
        }

        actual_headerlen = 4 + 1 + domain_len + 2;
        header_start = payload_start - actual_headerlen;

        socks5_udp_domainmsg_t *dmsg = (socks5_udp_domainmsg_t *)header_start;
        dmsg->reserved = 0;
        dmsg->fragment = 0;
        dmsg->addrtype = SOCKS5_ADDRTYPE_DOMAIN;
        dmsg->domain_len = (uint8_t)domain_len;
        memcpy(dmsg->domain_str, fake_domain, domain_len);

        portno_t port = isipv4 ? ((const skaddr4_t *)skaddr)->sin_port
                        : skaddr->sin6_port;
        memcpy(dmsg->domain_str + domain_len, &port, 2);
    } else {
        actual_headerlen = isipv4 ? sizeof(socks5_udp4msg_t) : sizeof(socks5_udp6msg_t);
        header_start = payload_start - actual_headerlen;

        socks5_udp4msg_t *udp4msg = (socks5_udp4msg_t *)header_start;
        udp4msg->reserved = 0;
        udp4msg->fragment = 0;
        udp4msg->addrtype = isipv4 ? SOCKS5_ADDRTYPE_IPV4 : SOCKS5_ADDRTYPE_IPV6;

        if (isipv4) {
            udp4msg->ipaddr4 = ((const skaddr4_t *)skaddr)->sin_addr.s_addr;
            udp4msg->portnum = ((const skaddr4_t *)skaddr)->sin_port;
        } else {
            socks5_udp6msg_t *udp6msg = (socks5_udp6msg_t *)header_start;
            memcpy(&udp6msg->ipaddr6, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
            udp6msg->portnum = skaddr->sin6_port;
        }
    }

    if (out_headerlen) {
        *out_headerlen = actual_headerlen;
    }
    return header_start;
}

static inline void build_symmetric_key(udp_symmetric_key_t *fk, const udp_endpoint_key_t *client, const udp_endpoint_key_t *target) {
    fk->client = *client;
    fk->target = *target;
}

static bool udp_session_register_fullcone(evloop_t *evloop __attribute__((unused)), udp_session_t *session, ev_tstamp now, udp_session_t **evicted) {
    udp_fullcone_node_t *node = mempool_alloc_sized(g_udp_fullcone_node_pool, sizeof(*node));
    if (!node) {
        LOGERR("[udp_session_register_fullcone] mempool alloc failed for fullcone node");
        return false;
    }

    node->key = session->client_endpoint;
    node->session = session;
    node->last_active = now;
    session->fullcone_node = node;
    session->symmetric_node = NULL;

    udp_fullcone_node_t *victim = udp_fullcone_node_add(&g_udp_fullcone_table, node);
    *evicted = victim ? victim->session : NULL;
    return true;
}

static bool udp_session_register_symmetric(evloop_t *evloop __attribute__((unused)), udp_session_t *session,
        const udp_symmetric_key_t *symmetric_key, ev_tstamp now,
        udp_session_t **evicted) {
    udp_symmetric_node_t *node = mempool_alloc_sized(g_udp_symmetric_node_pool, sizeof(*node));
    if (!node) {
        LOGERR("[udp_session_register_symmetric] mempool alloc failed for symmetric node");
        return false;
    }

    node->key = *symmetric_key;
    node->session = session;
    node->last_active = now;
    session->fullcone_node = NULL;
    session->symmetric_node = node;

    udp_symmetric_node_t *victim = udp_symmetric_node_add(&g_udp_symmetric_table, node);
    *evicted = victim ? victim->session : NULL;
    return true;
}

static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, size_t nrecv, char *buffer) {
    bool isipv4 = (intptr_t)tprecv_watcher->data;
    skaddr6_t skaddr;

    char *payload_start = buffer + MAX_SOCKS5_UDP_HEADER;

    if (msg->msg_namelen == sizeof(skaddr4_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr4_t));
    } else if (msg->msg_namelen == sizeof(skaddr6_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr6_t));
    } else {
        LOGERR("[handle_udp_socket_msg] invalid msg_namelen: %d", (int)msg->msg_namelen);
        return;
    }

    udp_endpoint_key_t key_ipport = udp_endpoint_from_skaddr(&skaddr, isipv4);

    IF_VERBOSE {
        char client_ipstr[IP6STRLEN];
        portno_t client_port;
        udp_endpoint_to_string(&key_ipport, client_ipstr, &client_port);
        LOGINF_RAW("[handle_udp_socket_msg] recv from %s#%hu, nrecv:%zd", client_ipstr, client_port, nrecv);
    }

    if (!get_udp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, msg, &skaddr)) {
        LOGERR("[handle_udp_socket_msg] destination address not found in udp msg");
        return;
    }

    const char *fake_domain = NULL;
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        bool is_miss;
        fake_domain = fakedns_try_resolve(target_ip, &is_miss);
        if (is_miss) {
            LOGERR("[handle_udp_socket_msg] fakedns miss for FakeIP: %u.%u.%u.%u, dropping packet",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
            return;
        }
        IF_VERBOSE if (fake_domain) {
            LOGINF_RAW("[handle_udp_socket_msg] fakedns hit: %u.%u.%u.%u -> %s",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                       fake_domain);
        }
    }

    udp_endpoint_key_t target_ipport = udp_endpoint_from_skaddr(&skaddr, isipv4);

    char *header_start;
    size_t actual_headerlen;

    header_start = build_socks5_udp_header(payload_start, fake_domain, &skaddr, isipv4, &actual_headerlen);
    if (!header_start) {
        LOGERR("[handle_udp_socket_msg] failed to build SOCKS5 UDP header");
        return;
    }
    if (nrecv > UDP_DATAGRAM_MAXSIZ - actual_headerlen) {
        LOGWAR("[handle_udp_socket_msg] packet too large to encapsulate (%zu+%zu > %d), dropping",
               nrecv, actual_headerlen, UDP_DATAGRAM_MAXSIZ);
        return;
    }

    udp_session_t *session = NULL;
    bool force_symmetric = false;

    udp_symmetric_key_t symmetric_key; /* built lazily by build_symmetric_key() — only needed on cold paths */

    if (fake_domain) {
        build_symmetric_key(&symmetric_key, &key_ipport, &target_ipport);
        udp_symmetric_node_t *symmetric_node = udp_symmetric_node_find(&g_udp_symmetric_table, &symmetric_key);
        session = symmetric_node ? symmetric_node->session : NULL;

        if (!session) {
            force_symmetric = true;
        }
    } else {
        udp_fullcone_node_t *fullcone_node = udp_fullcone_node_find(&g_udp_fullcone_table, &key_ipport);
        udp_session_t *fullcone_session = fullcone_node ? fullcone_node->session : NULL;

        if (fullcone_session) {
            if ((fullcone_session->original_target_endpoint.family == AF_INET) != isipv4) {
                udp_session_keepalive(evloop, fullcone_session);
                force_symmetric = true;
            } else {
                session = fullcone_session;
            }
        }

        if (!session) {
            build_symmetric_key(&symmetric_key, &key_ipport, &target_ipport);
            udp_symmetric_node_t *symmetric_node = udp_symmetric_node_find(&g_udp_symmetric_table, &symmetric_key);
            session = symmetric_node ? symmetric_node->session : NULL;
        }
    }

    if (!session) {
        int tcp_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
        if (tcp_sockfd < 0) {
            LOGERR("[handle_udp_socket_msg] new_tcp_connect_sockfd: %s", strerror(errno));
            return;
        }
        const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
        size_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
        ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

        if (!tcp_connect(tcp_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
            LOGERR("[handle_udp_socket_msg] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            close(tcp_sockfd);
            return;
        }
        if (tfo_nsend >= 0) {
            LOGINF("[handle_udp_socket_msg] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
        } else {
            LOGINF("[handle_udp_socket_msg] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
        }

        session = mempool_alloc_sized(g_udp_session_pool, sizeof(*session));
        if (!session) {
            LOGERR("[handle_udp_socket_msg] mempool alloc failed for session");
            close(tcp_sockfd);
            return;
        }
        memset(session, 0, sizeof(*session));
        session->client_endpoint = key_ipport;
        session->uses_fakedns = (fake_domain != NULL);
        session->original_target_endpoint = target_ipport;

        evio_t *watcher = &session->tcp_watcher;
        if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
            ev_io_init(watcher, udp_socks5_recv_authresp_cb, tcp_sockfd, EV_READ);
            tfo_nsend = 0;
        } else {
            ev_io_init(watcher, tfo_nsend >= 0 ? udp_socks5_send_authreq_cb : udp_socks5_connect_cb, tcp_sockfd, EV_WRITE);
            tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
        }
        session->handshake.nbytes = (uint16_t)tfo_nsend; /* nsend or nrecv */
        ev_io_start(evloop, watcher);

        size_t node_size = sizeof(udp_packet_node_t) + actual_headerlen + nrecv;
        udp_packet_node_t *node = malloc(node_size);
        if (!node) {
            LOGERR("[handle_udp_socket_msg] malloc failed for %zu bytes", node_size);
            ev_io_stop(evloop, watcher);
            close(tcp_sockfd);
            mempool_free_sized(g_udp_session_pool, session, sizeof(*session));
            return;
        }
        node->next = NULL;
        node->len = actual_headerlen + nrecv;
        memcpy(node->data, header_start, actual_headerlen + nrecv);

        session->pending_queue.head = node;
        session->pending_queue.tail = node;
        session->pending_queue.count = 1;
        session->udp_watcher.data = &session->pending_queue;

        session->handshake.step_len = SOCKS5_RESP_HEADER_PREFIX_LEN;

        udp_session_t *evicted_session = NULL;
        ev_tstamp now = ev_now(evloop);
        bool indexed;

        if (force_symmetric) {
            indexed = udp_session_register_symmetric(evloop, session, &symmetric_key, now, &evicted_session);
            IF_VERBOSE {
                char client_ipstr[IP6STRLEN];
                portno_t client_port;
                char target_ipstr[IP6STRLEN];
                portno_t target_port;
                udp_endpoint_to_string(&key_ipport, client_ipstr, &client_port);
                udp_endpoint_to_string(&target_ipport, target_ipstr, &target_port);
                LOGINF_RAW("[handle_udp_socket_msg] new symmetric session (%s): %s#%hu -> %s#%hu",
                           fake_domain ? "FakeDNS" : "RealIP",
                           client_ipstr, client_port, target_ipstr, target_port);
            }
        } else {
            IF_VERBOSE {
                char client_ipstr[IP6STRLEN];
                portno_t client_port;
                char target_ipstr[IP6STRLEN];
                portno_t target_port;
                udp_endpoint_to_string(&key_ipport, client_ipstr, &client_port);
                udp_endpoint_to_string(&target_ipport, target_ipstr, &target_port);
                LOGINF_RAW("[handle_udp_socket_msg] new fullcone session (RealIP): %s#%hu -> %s#%hu",
                           client_ipstr, client_port, target_ipstr, target_port);
            }

            indexed = udp_session_register_fullcone(evloop, session, now, &evicted_session);
        }

        if (!indexed) {
            udp_session_free(evloop, session);
            return;
        }

        if (evicted_session) {
            LOGINF("[handle_udp_socket_msg] session table full, evicting least active entry");
            udp_session_close_detached(evloop, evicted_session);
        }
        return;
    }

    if (session->udp_watcher.data) {
        udp_session_keepalive(evloop, session);

        udp_packet_queue_t *queue = &session->pending_queue;

        if (queue->count >= UDP_QUEUE_MAX_DEPTH) {
            LOGWAR("[handle_udp_socket_msg] packet queue full (%zu), dropping this msg", queue->count);
            return;
        }

        LOGINF("[handle_udp_socket_msg] tunnel is not ready, buffering this msg (queue: %zu)", queue->count);

        size_t node_size = sizeof(udp_packet_node_t) + actual_headerlen + nrecv;
        udp_packet_node_t *node = malloc(node_size);
        if (!node) {
            LOGERR("[handle_udp_socket_msg] malloc failed for %zu bytes", node_size);
            return;
        }
        node->next = NULL;
        node->len = actual_headerlen + nrecv;
        memcpy(node->data, header_start, actual_headerlen + nrecv);

        if (queue->tail) {
            queue->tail->next = node;
            queue->tail = node;
        } else {
            queue->head = node;
            queue->tail = node;
        }
        queue->count++;
        return;
    }

    udp_session_keepalive(evloop, session);

    ssize_t nsend = send(session->udp_watcher.fd, header_start, actual_headerlen + nrecv, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            char target_ipstr[IP6STRLEN];
            portno_t target_port;
            udp_endpoint_to_string(&target_ipport, target_ipstr, &target_port);
            LOGERR("[handle_udp_socket_msg] send to %s#%hu: %s", target_ipstr, target_port, strerror(errno));
            if (errno == EPIPE || errno == ECONNRESET) {
                LOGWAR("[handle_udp_socket_msg] fatal send error, releasing zombie session");
                udp_session_release(evloop, session);
            }
        }
        return;
    }
    IF_VERBOSE {
        char src_ipstr[IP6STRLEN];
        char dst_ipstr[IP6STRLEN];
        portno_t src_port, dst_port;
        udp_endpoint_to_string(&session->client_endpoint, src_ipstr, &src_port);
        udp_endpoint_to_string(&target_ipport, dst_ipstr, &dst_port);
        LOGINF_RAW("[handle_udp_socket_msg] send: %s#%hu -> %s#%hu, nsend:%zd",
                   src_ipstr, src_port, dst_ipstr, dst_port, nsend);
    }
}

static inline udp_session_t* get_udp_session_by_tcp(evio_t *tcp_watcher) {
    return (void *)((uint8_t *)tcp_watcher - offsetof(udp_session_t, tcp_watcher));
}

static inline void udp_session_release(evloop_t *evloop, udp_session_t *session) {
    LOGINF("[udp_session_release] manual release");
    udp_session_close_indexed(evloop, session);
}

static void udp_socks5_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    if (tcp_has_error(tcp_watcher->fd)) {
        LOGERR("[udp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        udp_session_release(evloop, get_udp_session_by_tcp(tcp_watcher));
        return;
    }
    LOGINF("[udp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(tcp_watcher, udp_socks5_send_authreq_cb);
    ev_invoke(evloop, tcp_watcher, EV_WRITE);
}

static int udp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, const void *data, size_t datalen) {
    udp_session_t *session = get_udp_session_by_tcp(tcp_watcher);
    uint16_t *nsend = &session->handshake.nbytes;
    const uint8_t *pdata = (const uint8_t *)data;
    ssize_t n = send(tcp_watcher->fd, pdata + *nsend, datalen - *nsend, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_session_release(evloop, session);
            return -1;
        }
        return 0;
    }
    LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nsend += (uint16_t)n;
    if (*nsend >= datalen) {
        *nsend = 0;
        return 1;
    }
    return 0;
}

static int udp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, void *data, size_t datalen) {
    udp_session_t *session = get_udp_session_by_tcp(tcp_watcher);
    uint16_t *nrecv = &session->handshake.nbytes;
    uint8_t *pdata = (uint8_t *)data;
    ssize_t n = recv(tcp_watcher->fd, pdata + *nrecv, datalen - *nrecv, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_session_release(evloop, session);
            return -1;
        }
        return 0;
    }
    if (n == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        udp_session_release(evloop, session);
        return -1;
    }
    LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nrecv += (uint16_t)n;
    if (*nrecv >= datalen) {
        *nrecv = 0;
        return 1;
    }
    return 0;
}

static void udp_socks5_send_authreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    if (udp_socks5_send_request("udp_socks5_send_authreq_cb", evloop, tcp_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t)) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_authresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_authresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    udp_session_t *session = get_udp_session_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, session->handshake.payload, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("udp_socks5_recv_authresp_cb", (const socks5_authresp_t *)session->handshake.payload)) {
        udp_session_release(evloop, session);
        return;
    }
    const void *data;
    size_t datalen;
    if (g_socks5_usrpwd_requestlen) {
        data = &g_socks5_usrpwd_request;
        datalen = g_socks5_usrpwd_requestlen;
    } else {
        bool isipv4 = session->original_target_endpoint.family == AF_INET;
        data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
        datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    }
    int ret = udp_socks5_send_request("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(tcp_watcher, g_socks5_usrpwd_requestlen ? udp_socks5_recv_usrpwdresp_cb : udp_socks5_recv_proxyresp_cb);
    } else if (ret == 0) {
        ev_io_stop(evloop, tcp_watcher);
        ev_io_init(tcp_watcher, g_socks5_usrpwd_requestlen ? udp_socks5_send_usrpwdreq_cb : udp_socks5_send_proxyreq_cb, tcp_watcher->fd, EV_WRITE);
        ev_io_start(evloop, tcp_watcher);
    }
}

static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    if (udp_socks5_send_request("udp_socks5_send_usrpwdreq_cb", evloop, tcp_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_usrpwdresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    udp_session_t *session = get_udp_session_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, session->handshake.payload, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("udp_socks5_recv_usrpwdresp_cb", (const socks5_usrpwdresp_t *)session->handshake.payload)) {
        udp_session_release(evloop, session);
        return;
    }
    bool isipv4 = session->original_target_endpoint.family == AF_INET;
    const void *data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    size_t datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    int ret = udp_socks5_send_request("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(tcp_watcher, udp_socks5_recv_proxyresp_cb);
    } else if (ret == 0) {
        ev_io_stop(evloop, tcp_watcher);
        ev_io_init(tcp_watcher, udp_socks5_send_proxyreq_cb, tcp_watcher->fd, EV_WRITE);
        ev_io_start(evloop, tcp_watcher);
    }
}

static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    udp_session_t *session = get_udp_session_by_tcp(tcp_watcher);
    bool isipv4 = session->original_target_endpoint.family == AF_INET;
    const void *request = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    size_t requestlen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    if (udp_socks5_send_request("udp_socks5_send_proxyreq_cb", evloop, tcp_watcher, request, requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_proxyresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    udp_session_t *session = get_udp_session_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_proxyresp_cb", evloop, tcp_watcher, session->handshake.payload, session->handshake.step_len) != 1) {
        return;
    }
    if (session->handshake.step_len == SOCKS5_RESP_HEADER_PREFIX_LEN) {
        uint8_t atype = ((socks5_resp_header_t *)session->handshake.payload)->addrtype;
        size_t total_len;

        if (atype == SOCKS5_ADDRTYPE_IPV4) {
            total_len = sizeof(socks5_ipv4resp_t); // 10
        } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
            total_len = sizeof(socks5_ipv6resp_t); // 22
        } else {
            LOGERR("[udp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
            udp_session_release(evloop, session);
            return;
        }

        if (total_len > sizeof(session->handshake.payload)) {
            LOGERR("[udp_socks5_recv_proxyresp_cb] response too large: %zu", total_len);
            udp_session_release(evloop, session);
            return;
        }

        session->handshake.step_len = (uint16_t)total_len;
        session->handshake.nbytes = SOCKS5_RESP_HEADER_PREFIX_LEN;

        if (udp_socks5_recv_response("udp_socks5_recv_proxyresp_cb", evloop, tcp_watcher, session->handshake.payload, total_len) != 1) {
            return;
        }
    }

    if (!socks5_proxy_response_check("udp_socks5_recv_proxyresp_cb", (const socks5_resp_header_t *)session->handshake.payload)) {
        udp_session_release(evloop, session);
        return;
    }

    portno_t relay_port;
    uint8_t atype = ((socks5_resp_header_t *)session->handshake.payload)->addrtype;
    if (atype == SOCKS5_ADDRTYPE_IPV4) {
        relay_port = ((socks5_ipv4resp_t *)session->handshake.payload)->portnum;
    } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
        relay_port = ((socks5_ipv6resp_t *)session->handshake.payload)->portnum;
    } else {
        LOGERR("[udp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
        udp_session_release(evloop, session);
        return;
    }

    skaddr6_t relay_addr;
    memcpy(&relay_addr, &g_server_skaddr, sizeof(g_server_skaddr));

    bool relay_isipv4 = relay_addr.sin6_family == AF_INET;
    if (relay_isipv4) {
        ((skaddr4_t *)&relay_addr)->sin_port = relay_port;
    } else {
        relay_addr.sin6_port = relay_port;
    }

    int udp_sockfd = new_udp_normal_sockfd(relay_addr.sin6_family);
    if (udp_sockfd < 0) {
        LOGERR("[udp_socks5_recv_proxyresp_cb] new_udp_normal_sockfd failed");
        udp_session_release(evloop, session);
        return;
    }
    if (connect(udp_sockfd, (void *)&relay_addr, relay_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        char ipstr[IP6STRLEN];
        portno_t portno;
        parse_socket_addr(&relay_addr, ipstr, &portno);
        LOGERR("[udp_socks5_recv_proxyresp_cb] connect to udp://%s#%u: %s", ipstr, (unsigned)portno, strerror(errno));
        udp_session_release(evloop, session);
        close(udp_sockfd);
        return;
    }

    udp_packet_queue_t *queue = &session->pending_queue;
    struct mmsghdr drain_msgs[UDP_QUEUE_MAX_DEPTH];
    struct iovec drain_iovs[UDP_QUEUE_MAX_DEPTH];
    int drain_count = 0;

    for (udp_packet_node_t *curr = queue->head; curr && drain_count < UDP_QUEUE_MAX_DEPTH; curr = curr->next) {
        drain_iovs[drain_count].iov_base               = curr->data;
        drain_iovs[drain_count].iov_len                = curr->len;
        drain_msgs[drain_count].msg_hdr.msg_name       = NULL;
        drain_msgs[drain_count].msg_hdr.msg_namelen    = 0;
        drain_msgs[drain_count].msg_hdr.msg_iov        = &drain_iovs[drain_count];
        drain_msgs[drain_count].msg_hdr.msg_iovlen     = 1;
        drain_msgs[drain_count].msg_hdr.msg_control    = NULL;
        drain_msgs[drain_count].msg_hdr.msg_controllen = 0;
        drain_count++;
    }

    if (drain_count > 0) {
        int sent = sendmmsg(udp_sockfd, drain_msgs, (unsigned int)drain_count, 0);
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[udp_socks5_recv_proxyresp_cb] sendmmsg drain failed: %s", strerror(errno));
            }
        } else if (sent < drain_count) {
            LOGWAR("[udp_socks5_recv_proxyresp_cb] partial drain %d/%d", sent, drain_count);
        }
    }

    udp_packet_node_t *curr = queue->head;
    while (curr) {
        udp_packet_node_t *next = curr->next;
        free(curr);
        curr = next;
    }

    session->pending_queue.head = NULL;
    session->pending_queue.tail = NULL;
    session->pending_queue.count = 0;
    session->udp_watcher.data = NULL;

    ev_set_cb(tcp_watcher, udp_socks5_recv_tcpmessage_cb);

    evio_t *udp_watcher_ptr = &session->udp_watcher;
    ev_io_init(udp_watcher_ptr, udp_socks5_recv_udpmessage_cb, udp_sockfd, EV_READ);
    ev_io_start(evloop, udp_watcher_ptr);

    udp_session_keepalive(evloop, session);
}

static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    char dummy_buf; /* Uninitialized single-byte local stack variable */

    ssize_t n = recv(tcp_watcher->fd, &dummy_buf, sizeof(dummy_buf), 0);

    if (n > 0) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv unknown msg from socks5 server, release session");
        udp_session_release(evloop, get_udp_session_by_tcp(tcp_watcher));
    } else if (n == 0) {
        LOGINF("[udp_socks5_recv_tcpmessage_cb] recv FIN from socks5 server, release session");
        udp_session_release(evloop, get_udp_session_by_tcp(tcp_watcher));
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv from socks5 server: %s", strerror(errno));
        udp_session_release(evloop, get_udp_session_by_tcp(tcp_watcher));
    }
}

static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *udp_watcher = (evio_t *)watcher;
    udp_session_t *session = (void *)((uint8_t *)udp_watcher - offsetof(udp_session_t, udp_watcher));

    static __thread struct mmsghdr msgs[UDP_BATCH_SIZE];
    static __thread struct mmsghdr send_msgs[UDP_BATCH_SIZE];
    static __thread struct iovec iovs[UDP_BATCH_SIZE];
    static __thread bool udpmsg_initialized = false;

    if (!udpmsg_initialized) {
        for (int i = 0; i < UDP_BATCH_SIZE; i++) {
            iovs[i].iov_base               = g_udp_batch_buffer[i];
            iovs[i].iov_len                = UDP_DATAGRAM_MAXSIZ;
            msgs[i].msg_hdr.msg_name       = NULL;
            msgs[i].msg_hdr.msg_namelen    = 0;
            msgs[i].msg_hdr.msg_iov        = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen     = 1;
            msgs[i].msg_hdr.msg_control    = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
        }
        udpmsg_initialized = true;
    }

    int retval = recvmmsg(udp_watcher->fd, msgs, UDP_BATCH_SIZE, 0, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recvmmsg: %s", strerror(errno));
        }
        return;
    }

    if (retval == 0) {
        return;
    }

    struct {
        udp_tproxy_entry_t *entry;
        struct mmsghdr msg;
        struct iovec iov;
        skaddr6_t addr;
    } batch_sends[UDP_BATCH_SIZE];
    int send_count = 0;

    udp_tproxy_entry_t *deferred_evict[UDP_BATCH_SIZE];
    int deferred_evict_count = 0;

    udp_session_keepalive(evloop, session);

    for (int i = 0; i < retval; i++) {
        char *buffer = g_udp_batch_buffer[i];
        size_t nrecv = (size_t)msgs[i].msg_len;

        if (nrecv < offsetof(socks5_udp4msg_t, ipaddr4)) {
            continue;
        }

        socks5_udp4msg_t *udp4msg = (void *)buffer;
        if (udp4msg->reserved != 0 || udp4msg->fragment != 0) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] invalid udp header: reserved=0x%04x fragment=0x%02x",
                   ntohs(udp4msg->reserved), udp4msg->fragment);
            continue;
        }

        bool isipv4 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV4;
        bool isipv6 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV6;

        size_t headerlen;
        if (isipv4) {
            headerlen = sizeof(socks5_udp4msg_t);
            if (nrecv < headerlen) {
                continue;
            }
        } else if (isipv6) {
            headerlen = sizeof(socks5_udp6msg_t);
            if (nrecv < headerlen) {
                continue;
            }
        } else {
            LOGERR("[udp_socks5_recv_udpmessage_cb] unsupported address type: 0x%02x", udp4msg->addrtype);
            continue;
        }

        udp_endpoint_key_t fromipport;
        bool dest_isipv4;

        if (session->uses_fakedns) {
            fromipport = session->original_target_endpoint;
            dest_isipv4 = fromipport.family == AF_INET;
        } else {
            memset(&fromipport, 0, sizeof(fromipport));
            if (isipv4) {
                fromipport.family = AF_INET;
                memcpy(fromipport.addr, &udp4msg->ipaddr4, IP4BINLEN);
                fromipport.port = udp4msg->portnum;
                dest_isipv4 = true;
            } else {
                socks5_udp6msg_t *udp6msg = (void *)buffer;
                fromipport.family = AF_INET6;
                memcpy(fromipport.addr, &udp6msg->ipaddr6, IP6BINLEN);
                fromipport.port = udp6msg->portnum;
                dest_isipv4 = false;
            }
        }

        udp_tproxy_entry_t *tproxy_entry = udp_tproxy_entry_find(&g_udp_tproxy_table, &fromipport);
        if (!tproxy_entry) {
            skaddr6_t fromskaddr;
            udp_skaddr_from_endpoint(&fromskaddr, &fromipport);
            int tproxy_sockfd = new_udp_tpsend_sockfd(dest_isipv4 ? AF_INET : AF_INET6);
            if (tproxy_sockfd < 0) {
                LOGERR("[udp_socks5_recv_udpmessage_cb] new_udp_tpsend_sockfd failed");
                continue;
            }
            if (bind(tproxy_sockfd, (void *)&fromskaddr, dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
                char ipstr[IP6STRLEN];
                portno_t portno;
                parse_socket_addr(&fromskaddr, ipstr, &portno);
                LOGERR("[udp_socks5_recv_udpmessage_cb] bind tproxy_sockfd to %s#%hu: %s", ipstr, portno, strerror(errno));
                close(tproxy_sockfd);
                continue;
            }
            tproxy_entry = mempool_alloc_sized(g_udp_tproxy_pool, sizeof(*tproxy_entry));
            if (!tproxy_entry) {
                LOGERR("[udp_socks5_recv_udpmessage_cb] mempool alloc failed for tproxy_entry");
                close(tproxy_sockfd);
                continue;
            }
            tproxy_entry->key = fromipport;
            tproxy_entry->udp_sockfd = tproxy_sockfd;
            tproxy_entry->last_active = ev_now(evloop);
            udp_tproxy_entry_t *evicted_entry = udp_tproxy_entry_add(&g_udp_tproxy_table, tproxy_entry);
            if (evicted_entry) {
                LOGINF("[udp_socks5_recv_udpmessage_cb] tproxy_entry table full, deferring eviction");
                deferred_evict[deferred_evict_count++] = evicted_entry;
            }
            IF_VERBOSE {
                char src_ipstr[IP6STRLEN];
                char dst_ipstr[IP6STRLEN];
                portno_t src_port;
                portno_t dst_port;
                udp_endpoint_to_string(&fromipport, src_ipstr, &src_port);
                udp_endpoint_to_string(&session->client_endpoint, dst_ipstr, &dst_port);
                LOGINF_RAW("[udp_socks5_recv_udpmessage_cb] new tproxy entry: %s#%hu <- %s#%hu",
                           dst_ipstr, dst_port, src_ipstr, src_port);
            }
        } else {
            tproxy_entry->last_active = ev_now(evloop);
        }

        udp_skaddr_from_endpoint(&batch_sends[send_count].addr, &session->client_endpoint);

        batch_sends[send_count].entry                      = tproxy_entry;
        batch_sends[send_count].iov.iov_base               = buffer + headerlen;
        batch_sends[send_count].iov.iov_len                = nrecv - headerlen;
        batch_sends[send_count].msg.msg_hdr.msg_name       = &batch_sends[send_count].addr;
        batch_sends[send_count].msg.msg_hdr.msg_namelen    = dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
        batch_sends[send_count].msg.msg_hdr.msg_iov        = &batch_sends[send_count].iov;
        batch_sends[send_count].msg.msg_hdr.msg_iovlen     = 1;
        batch_sends[send_count].msg.msg_hdr.msg_control    = NULL;
        batch_sends[send_count].msg.msg_hdr.msg_controllen = 0;

        send_count++;
    }

    if (send_count > 0) {
        uint16_t indices[UDP_BATCH_SIZE];
        for (int k = 0; k < send_count; k++) {
            indices[k] = (uint16_t)k;
        }

        for (int i = 0; i < send_count;) {
            udp_tproxy_entry_t *tproxy_entry = batch_sends[indices[i]].entry;
            int group_start = i;
            int group_count = 0;

            for (int j = i; j < send_count; j++) {
                if (batch_sends[indices[j]].entry == tproxy_entry) {
                    if (j != i + group_count) {
                        uint16_t tmp = indices[i + group_count];
                        indices[i + group_count] = indices[j];
                        indices[j] = tmp;
                    }
                    group_count++;
                }
            }

            for (int k = 0; k < group_count; k++) {
                send_msgs[k] = batch_sends[indices[group_start + k]].msg;
            }

            int sent = sendmmsg(tproxy_entry->udp_sockfd, send_msgs, (unsigned int)group_count, 0);
            if (sent < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOGERR("[udp_socks5_recv_udpmessage_cb] sendmmsg failed: %s", strerror(errno));
                }
            } else {
                IF_VERBOSE {
                    char src_ipstr[IP6STRLEN];
                    char dst_ipstr[IP6STRLEN];
                    portno_t src_port, dst_port;
                    udp_endpoint_to_string(&session->client_endpoint, dst_ipstr, &dst_port);
                    udp_endpoint_to_string(&tproxy_entry->key, src_ipstr, &src_port);
                    LOGINF_RAW("[udp_socks5_recv_udpmessage_cb] sendmmsg: %s#%hu <- %s#%hu, npackets:%d",
                               dst_ipstr, dst_port, src_ipstr, src_port, sent);
                }
                if (sent < group_count) {
                    LOGWAR("[udp_socks5_recv_udpmessage_cb] partial send %d/%d", sent, group_count);
                }
            }

            i += group_count;
        }
    }

    for (int i = 0; i < deferred_evict_count; i++) {
        udp_tproxy_entry_free(deferred_evict[i]);
    }
}

typedef enum {
    UDP_ENTRY_INDEXED,
    UDP_ENTRY_DETACHED,
} udp_entry_state_t;

static void udp_session_free(evloop_t *evloop, udp_session_t *session) {
    ev_io_stop(evloop, &session->tcp_watcher);
    close(session->tcp_watcher.fd);

    if (session->udp_watcher.data) {
        udp_packet_queue_t *queue = &session->pending_queue;
        udp_packet_node_t *curr = queue->head;
        while (curr) {
            udp_packet_node_t *next = curr->next;
            free(curr);
            curr = next;
        }
    } else {
        ev_io_stop(evloop, &session->udp_watcher);
        close(session->udp_watcher.fd);
    }

    mempool_free_sized(g_udp_session_pool, session, sizeof(*session));
}

static void udp_tproxy_entry_free(udp_tproxy_entry_t *entry) {
    close(entry->udp_sockfd);
    mempool_free_sized(g_udp_tproxy_pool, entry, sizeof(*entry));
}

static void udp_session_close(evloop_t *evloop, udp_session_t *session, udp_entry_state_t state) {
    if (session->fullcone_node) {
        udp_fullcone_node_t *node = session->fullcone_node;
        if (state == UDP_ENTRY_INDEXED) {
            udp_fullcone_node_del(&g_udp_fullcone_table, node);
        }
        mempool_free_sized(g_udp_fullcone_node_pool, node, sizeof(*node));
        session->fullcone_node = NULL;
    } else {
        udp_symmetric_node_t *node = session->symmetric_node;
        if (state == UDP_ENTRY_INDEXED) {
            udp_symmetric_node_del(&g_udp_symmetric_table, node);
        }
        mempool_free_sized(g_udp_symmetric_node_pool, node, sizeof(*node));
        session->symmetric_node = NULL;
    }
    udp_session_free(evloop, session);
}

static void udp_session_close_indexed(evloop_t *evloop, udp_session_t *session) {
    udp_session_close(evloop, session, UDP_ENTRY_INDEXED);
}

static void udp_session_close_detached(evloop_t *evloop, udp_session_t *session) {
    udp_session_close(evloop, session, UDP_ENTRY_DETACHED);
}

static void udp_tproxy_entry_close(evloop_t *evloop __attribute__((unused)), udp_tproxy_entry_t *entry) {
    udp_tproxy_entry_del(&g_udp_tproxy_table, entry);
    udp_tproxy_entry_free(entry);
}

#define GC_INTERVAL_SEC      10.0

static __thread evtimer_t g_gc_timer;

static inline bool udp_gc_is_idle(ev_tstamp now, ev_tstamp last_active, ev_tstamp timeout) {
    return (now - last_active) >= timeout;
}

static ev_tstamp udp_gc_tproxy_timeout(void) {
    return g_udp_idletimeout_sec >= 20
           ? (ev_tstamp)g_udp_idletimeout_sec / 2.0
           : 10.0;
}

static void udp_log_gc_evicted(const char *table_name, int evicted) {
    if (evicted > 0) {
        LOGINF("[udp_gc] %s evicted: %d", table_name, evicted);
    }
}

static int udp_gc_sweep_fullcone_sessions(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_fullcone_node_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_fullcone_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_session_close_indexed(evloop, cur->session);
            evicted++;
        }
    }
    return evicted;
}

static int udp_gc_sweep_symmetric_sessions(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_symmetric_node_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_symmetric_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_session_close_indexed(evloop, cur->session);
            evicted++;
        }
    }
    return evicted;
}

static int udp_gc_sweep_tproxy_entries(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_tproxy_entry_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_tproxy_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_tproxy_entry_close(evloop, cur);
            evicted++;
        }
    }
    return evicted;
}

static void udp_gc_on_tick(evloop_t *evloop, struct ev_watcher *watcher __attribute__((unused)), int revents __attribute__((unused))) {
    ev_tstamp now = ev_now(evloop);
    ev_tstamp session_timeout = (ev_tstamp)g_udp_idletimeout_sec;
    ev_tstamp tproxy_timeout = udp_gc_tproxy_timeout();

    udp_log_gc_evicted("fullcone table", udp_gc_sweep_fullcone_sessions(evloop, now, session_timeout));
    udp_log_gc_evicted("symmetric table", udp_gc_sweep_symmetric_sessions(evloop, now, session_timeout));
    udp_log_gc_evicted("tproxy table", udp_gc_sweep_tproxy_entries(evloop, now, tproxy_timeout));
}

void udp_proxy_gc_start(evloop_t *evloop) {
    ev_timer_init(&g_gc_timer, udp_gc_on_tick, GC_INTERVAL_SEC, GC_INTERVAL_SEC);
    ev_timer_start(evloop, &g_gc_timer);
}

void udp_proxy_gc_stop(evloop_t *evloop) {
    ev_timer_stop(evloop, &g_gc_timer);
}

static void udp_fullcone_session_clear_cb(void *evloop_arg, udp_fullcone_node_t *entry) {
    udp_session_close_indexed((evloop_t *)evloop_arg, entry->session);
}

static void udp_symmetric_session_clear_cb(void *evloop_arg, udp_symmetric_node_t *entry) {
    udp_session_close_indexed((evloop_t *)evloop_arg, entry->session);
}

static void udp_tproxy_entry_clear_cb(void *evloop_arg, udp_tproxy_entry_t *entry) {
    udp_tproxy_entry_close((evloop_t *)evloop_arg, entry);
}

void udp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[udp_proxy_close_all_sessions] cleaning up remaining sessions...");

    udp_proxy_gc_stop(evloop);
    udp_fullcone_node_clear(&g_udp_fullcone_table, udp_fullcone_session_clear_cb, evloop);
    udp_symmetric_node_clear(&g_udp_symmetric_table, udp_symmetric_session_clear_cb, evloop);
    udp_tproxy_entry_clear(&g_udp_tproxy_table, udp_tproxy_entry_clear_cb, evloop);
}
