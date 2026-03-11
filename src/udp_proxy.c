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

/* Forward declarations */
static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, ssize_t nrecv, char *buffer, udp_socks5ctx_t **out_context);
static void udp_socks5_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_send_authreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_authresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static inline void udp_socks5ctx_release(evloop_t *evloop, udp_socks5ctx_t *context);
static void udp_socks5_context_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void udp_tproxy_context_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);


void udp_tproxy_recvmsg_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tprecv_watcher = (evio_t *)watcher;
    bool isipv4 = (intptr_t)tprecv_watcher->data;

    /* Use maximum header size to allow building headers backward from payload */
    const size_t max_headerlen = MAX_SOCKS5_UDP_HEADER;

    struct mmsghdr msgs[UDP_BATCH_SIZE];
    struct iovec iovs[UDP_BATCH_SIZE];
    char msg_control_buffers[UDP_BATCH_SIZE][UDP_CTRLMESG_BUFSIZ];
    skaddr6_t skaddrs[UDP_BATCH_SIZE];

    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        iovs[i].iov_base = (uint8_t *)g_udp_batch_buffer[i] + max_headerlen;
        iovs[i].iov_len = UDP_DATAGRAM_MAXSIZ - max_headerlen;

        msgs[i].msg_hdr.msg_name = &skaddrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(skaddr6_t); // Use largest size
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        memset(msg_control_buffers[i], 0, UDP_CTRLMESG_BUFSIZ);
        msgs[i].msg_hdr.msg_control = msg_control_buffers[i];
        msgs[i].msg_hdr.msg_controllen = UDP_CTRLMESG_BUFSIZ;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    /* non-blocking receive */
    int retval = recvmmsg(tprecv_watcher->fd, msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tproxy_recvmsg_cb] recvmmsg from udp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }

    if (retval == 0) {
        return;
    }

    udp_socks5ctx_t *touched[UDP_BATCH_SIZE];
    int touched_count = 0;

    for (int i = 0; i < retval; i++) {
        udp_socks5ctx_t *ctx = NULL;
        handle_udp_socket_msg(evloop, tprecv_watcher, &msgs[i].msg_hdr, msgs[i].msg_len, g_udp_batch_buffer[i], &ctx);
        if (ctx) {
            /* Linear dedup — UDP_BATCH_SIZE is small (16) */
            bool dup = false;
            for (int j = 0; j < touched_count; j++) {
                if (touched[j] == ctx) {
                    dup = true;
                    break;
                }
            }
            if (!dup) touched[touched_count++] = ctx;
        }
    }

    /* Batch-end: single LRU touch + timer reset per unique context */
    for (int i = 0; i < touched_count; i++) {
        if (touched[i]->is_forked) {
            udp_socks5ctx_touch_fork(&g_udp_fork_table, touched[i]);
        } else {
            udp_socks5ctx_touch_main(&g_udp_socks5ctx_table, touched[i]);
        }
        ev_timer_again(evloop, &touched[i]->idle_timer);
    }
}

static char *build_socks5_udp_header(char *payload_start, const char *fake_domain, const skaddr6_t *skaddr, bool isipv4, size_t *out_headerlen) {
    char *header_start;
    size_t actual_headerlen;

    if (fake_domain) {
        /* DOMAIN format: [reserved(2)][fragment(1)][addrtype(1)][len(1)][domain(n)][port(2)] */
        size_t domain_len = strlen(fake_domain);
        if (domain_len > MAX_DOMAIN_LEN) {
            LOGERR("[build_socks5_udp_header] domain too long: %zu", domain_len);
            return NULL;
        }

        actual_headerlen = 4 + 1 + domain_len + 2;
        header_start = payload_start - actual_headerlen;

        /* Build DOMAIN header directly in the reserved space */
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
        /* IP format */
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

static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, ssize_t nrecv, char *buffer, udp_socks5ctx_t **out_context) {
    *out_context = NULL;
    bool isipv4 = (intptr_t)tprecv_watcher->data;
    skaddr6_t skaddr;
    char ipstr[IP6STRLEN];
    portno_t portno;

    /*
     * Memory layout optimization:
     * buffer points to start of g_udp_batch_buffer[i]
     * Payload is at fixed position: buffer + MAX_SOCKS5_UDP_HEADER
     * Header is built backward from payload position
     */
    char *payload_start = buffer + MAX_SOCKS5_UDP_HEADER;

    /* Restore skaddr from msg->msg_name (sender address) */
    if (msg->msg_namelen == sizeof(skaddr4_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr4_t));
    } else if (msg->msg_namelen == sizeof(skaddr6_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr6_t));
    } else {
        LOGERR("[handle_udp_socket_msg] invalid msg_namelen: %d", (int)msg->msg_namelen);
        return;
    }

    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[handle_udp_socket_msg] recv from %s#%hu, nrecv:%zd", ipstr, portno, nrecv);
    }

    ip_port_t key_ipport;
    memset(&key_ipport, 0, sizeof(key_ipport));
    if (isipv4) {
        key_ipport.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        key_ipport.port = ((skaddr4_t *)&skaddr)->sin_port;
    } else {
        memcpy(&key_ipport.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
        key_ipport.port = skaddr.sin6_port;
    }

    if (!get_udp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, msg, &skaddr)) {
        LOGERR("[handle_udp_socket_msg] destination address not found in udp msg");
        return;
    }

    /* FakeDNS reverse lookup for domain resolution */
    const char *fake_domain = NULL;
    char domain_buf[FAKEDNS_MAX_DOMAIN_LEN];
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        if (fakedns_is_fakeip(target_ip)) {
            if (fakedns_reverse_lookup(target_ip, domain_buf, sizeof(domain_buf))) {
                fake_domain = domain_buf;
                IF_VERBOSE {
                    LOGINF("[handle_udp_socket_msg] fakedns hit: %u.%u.%u.%u -> %s",
                           ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                           ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                           fake_domain);
                }
            } else {
                LOGERR("[handle_udp_socket_msg] fakedns miss for FakeIP: %u.%u.%u.%u, dropping packet",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
                return;
            }
        }
    }

    /* Build SOCKS5 UDP header backward from payload position (zero-copy optimization) */
    char *header_start;
    size_t actual_headerlen;

    header_start = build_socks5_udp_header(payload_start, fake_domain, &skaddr, isipv4, &actual_headerlen);
    if (!header_start) {
        LOGERR("[handle_udp_socket_msg] failed to build SOCKS5 UDP header");
        return;
    }

    udp_socks5ctx_t *context = NULL;
    bool force_fork = false;

    // Build fork key for unified lookup (works for IPv4 and IPv6, FakeDNS and standard)
    udp_fork_key_t fork_key;
    memset(&fork_key, 0, sizeof(fork_key));
    fork_key.client_ipport = key_ipport;
    fork_key.target_is_ipv4 = isipv4;

    if (isipv4) {
        fork_key.target_ipport.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        fork_key.target_ipport.port = ((skaddr4_t *)&skaddr)->sin_port;
    } else {
        memcpy(&fork_key.target_ipport.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
        fork_key.target_ipport.port = skaddr.sin6_port;
    }

    /*
     * Traffic Separation Strategy:
     * 1. FakeDNS Traffic: Symmetric-NAT behavior (1:1 mapping per Client IP:Port + Target IP:Port).
     *    Uses Fork Table exclusively. Skips Main Table to avoid pollution.
     * 2. Real IP Traffic: Preferred Full Cone behavior (1:N mapping).
     *    Uses Main Table (key: Client IP:Port only) first. Falls back to Fork Table on collision.
     */
    if (fake_domain) {
        /* Strategy A: FakeDNS Traffic -> Fork Table Only */
        context = udp_socks5ctx_fork_find(&g_udp_fork_table, &fork_key);

        if (!context) {
            /* Not found, new session needed. Force fork to ensure it goes to Fork Table on creation */
            force_fork = true;
            IF_VERBOSE {
                LOGINF("[handle_udp_socket_msg] new FakeDNS session (will fork): %s -> %s", ipstr, fake_domain);
            }
        } else {
            IF_VERBOSE {
                LOGINF("[handle_udp_socket_msg] reuse fork context (FakeDNS): %s -> %s", ipstr, fake_domain);
            }
        }
    } else {
        /* Strategy B: Real IP Traffic -> Main Table (Full Cone) -> Fork Table (Fallback) */

        /* Step 1: Check Main Table (Fast Path, Full Cone) */
        udp_socks5ctx_t *main_ctx = udp_socks5ctx_find(&g_udp_socks5ctx_table, &key_ipport);

        if (main_ctx) {
            /* Check for collisions that require forking:
             * 1. Protocol family mismatch (IPv4 vs IPv6)
             * 2. Type mismatch (FakeDNS session occupying main slot)
             */
            if ((main_ctx->dest_is_ipv4 != isipv4) || main_ctx->is_fakedns) {
                /* Protocol mismatch (e.g. client used same port for IPv4 and IPv6 dest)
                 * OR Type mismatch (FakeDNS session occupying main slot) */
                force_fork = true;
            } else {
                /* Match! Reuse Main Context (Full Cone NAT) */
                context = main_ctx;
                IF_VERBOSE {
                    char target_ipstr[IP6STRLEN];
                    portno_t target_port;
                    parse_socket_addr(&skaddr, target_ipstr, &target_port);
                    LOGINF("[handle_udp_socket_msg] reuse main context (RealIP): %s -> %s#%d", ipstr, target_ipstr, target_port);
                }
            }
        }

        /* Step 2: context is NULL means either Main Table missed, or collision occurred.
         * If collision (force_fork=true), try Fork Table; if also missed, create new Fork entry.
         * If no collision (force_fork=false), create new Main entry. */
        if (!context) {
            context = udp_socks5ctx_fork_find(&g_udp_fork_table, &fork_key);
            if (context) {
                IF_VERBOSE {
                    LOGINF("[handle_udp_socket_msg] reuse fork context (RealIP): %s -> RealIP", ipstr);
                }
            }
            /* If still NULL, creation logic below will use force_fork to decide which table */
        }
    }

    if (!context) {
        int tcp_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
        const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
        uint16_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
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

        context = mempool_calloc_sized(g_udp_context_pool, sizeof(*context));
        if (!context) {
            LOGERR("[handle_udp_socket_msg] mempool alloc failed for context");
            close(tcp_sockfd);
            return;
        }
        memcpy(&context->key_ipport, &key_ipport, sizeof(key_ipport));

        // Save original destination and protocol family
        context->dest_is_ipv4 = isipv4;
        context->is_fakedns = (fake_domain != NULL);
        if (isipv4) {
            context->orig_dstaddr.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
            context->orig_dstaddr.port = ((skaddr4_t *)&skaddr)->sin_port;
        } else {
            memcpy(&context->orig_dstaddr.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
            context->orig_dstaddr.port = skaddr.sin6_port;
        }

        evio_t *watcher = &context->tcp_watcher;
        if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
            ev_io_init(watcher, udp_socks5_recv_authresp_cb, tcp_sockfd, EV_READ);
            tfo_nsend = 0;
        } else {
            ev_io_init(watcher, tfo_nsend >= 0 ? udp_socks5_send_authreq_cb : udp_socks5_connect_cb, tcp_sockfd, EV_WRITE);
            tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
        }
        ev_io_start(evloop, watcher);
        context->handshake.nbytes = tfo_nsend >= 0 ? tfo_nsend : 0; /* nsend or nrecv */

        /* tunnel not ready if udp_watcher->data != NULL */
        size_t node_size = sizeof(udp_packet_node_t) + actual_headerlen + nrecv;
        udp_packet_node_t *node = mempool_alloc_sized(g_udp_packet_pool, node_size);
        if (!node) {
            LOGERR("[handle_udp_socket_msg] mempool_alloc_sized failed for %zu bytes", node_size);
            ev_io_stop(evloop, watcher);
            close(tcp_sockfd);
            mempool_free_sized(g_udp_context_pool, context, sizeof(*context));
            return;
        }
        node->next = NULL;
        node->len = actual_headerlen + nrecv;
        memcpy(node->data, header_start, actual_headerlen + nrecv);

        context->pending_queue.head = node;
        context->pending_queue.tail = node;
        context->pending_queue.count = 1;
        context->udp_watcher.data = &context->pending_queue;

        evtimer_t *timer = &context->idle_timer;
        ev_timer_init(timer, udp_socks5_context_timeout_cb, 0, g_udp_idletimeout_sec);
        context->handshake.step_len = 5; // Expected proxy response header length
        ev_timer_again(evloop, timer);

        udp_socks5ctx_t *del_context = NULL;

        // Always populate fork_key for all associations (needed for future Fork Table lookups)
        context->fork_key.client_ipport = key_ipport;
        context->fork_key.target_is_ipv4 = isipv4;

        if (isipv4) {
            context->fork_key.target_ipport.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
            context->fork_key.target_ipport.port = ((skaddr4_t *)&skaddr)->sin_port;
        } else {
            memcpy(&context->fork_key.target_ipport.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
            context->fork_key.target_ipport.port = skaddr.sin6_port;
        }

        if (force_fork) {
            context->is_forked = true;
            del_context = udp_socks5ctx_fork_add(&g_udp_fork_table, context);
            IF_VERBOSE {
                if (fake_domain) {
                    LOGINF("[handle_udp_socket_msg] new fork context created (FakeDNS): %s -> %s", ipstr, fake_domain);
                } else {
                    LOGINF("[handle_udp_socket_msg] new fork context created (RealIP Collision)");
                }
            }
        } else {
            IF_VERBOSE {
                LOGINF("[handle_udp_socket_msg] new main context created (RealIP)");
            }

            context->is_forked = false;
            del_context = udp_socks5ctx_add(&g_udp_socks5ctx_table, context);
        }

        if (del_context) {
            ev_invoke(evloop, &del_context->idle_timer, EV_CUSTOM);
        }
        return;
    }

    /* Tunnel not ready if udp_watcher.data != NULL */
    if (context->udp_watcher.data) {
        udp_packet_queue_t *queue = &context->pending_queue;

        if (queue->count >= UDP_QUEUE_MAX_DEPTH) {
            LOGWAR("[handle_udp_socket_msg] packet queue full (%zu), dropping this msg", queue->count);
            return;
        }

        LOGINF("[handle_udp_socket_msg] tunnel is not ready, buffering this msg (queue: %zu)", queue->count);

        size_t node_size = sizeof(udp_packet_node_t) + actual_headerlen + nrecv;
        udp_packet_node_t *node = mempool_alloc_sized(g_udp_packet_pool, node_size);
        if (!node) {
            LOGERR("[handle_udp_socket_msg] mempool_alloc_sized failed for %zu bytes", node_size);
            return;
        }
        node->next = NULL;
        node->len = actual_headerlen + nrecv;
        memcpy(node->data, header_start, actual_headerlen + nrecv);

        /* Append to the end of the list (O(1)) */
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

    /* LRU touch + timer reset deferred to batch-end in udp_tproxy_recvmsg_cb */
    *out_context = context;

    nrecv = send(context->udp_watcher.fd, header_start, actual_headerlen + nrecv, 0);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            parse_socket_addr(&skaddr, ipstr, &portno);
            LOGERR("[handle_udp_socket_msg] send to %s#%hu: %s", ipstr, portno, strerror(errno));
            if (errno == EPIPE || errno == ECONNRESET) {
                LOGWAR("[handle_udp_socket_msg] fatal send error, releasing zombie context");
                udp_socks5ctx_release(evloop, context);
                *out_context = NULL;
            }
        }
        return;
    }
    IF_VERBOSE {
        if (fake_domain) {
            portno = ntohs(((skaddr4_t *)&skaddr)->sin_port);
            LOGINF("[handle_udp_socket_msg] send to %s#%hu, nsend:%zd", fake_domain, portno, nrecv);
        } else {
            parse_socket_addr(&skaddr, ipstr, &portno);
            LOGINF("[handle_udp_socket_msg] send to %s#%hu, nsend:%zd", ipstr, portno, nrecv);
        }
    }
}

static inline udp_socks5ctx_t* get_udpsk5ctx_by_tcp(evio_t *tcp_watcher) {
    return (void *)((uint8_t *)tcp_watcher - offsetof(udp_socks5ctx_t, tcp_watcher));
}

static inline void udp_socks5ctx_release(evloop_t *evloop, udp_socks5ctx_t *context) {
    ev_invoke(evloop, &context->idle_timer, EV_CUSTOM);
}

static void udp_socks5_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    if (tcp_has_error(tcp_watcher->fd)) {
        LOGERR("[udp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    LOGINF("[udp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(tcp_watcher, udp_socks5_send_authreq_cb);
    ev_invoke(evloop, tcp_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int udp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, const void *data, size_t datalen) {
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    uint16_t *nsend = &context->handshake.nbytes;
    const uint8_t *pdata = (const uint8_t *)data;
    ssize_t n = send(tcp_watcher->fd, pdata + *nsend, datalen - *nsend, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
            return -1;
        }
        return 0;
    }
    LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nsend += (size_t)n;
    if (*nsend >= datalen) {
        *nsend = 0;
        return 1;
    }
    return 0;
}

/* return: -1(error_occurred); 0(partial_recv); 1(completely_recv) */
static int udp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, void *data, size_t datalen) {
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    uint16_t *nrecv = &context->handshake.nbytes;
    uint8_t *pdata = (uint8_t *)data;
    ssize_t n = recv(tcp_watcher->fd, pdata + *nrecv, datalen - *nrecv, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
            return -1;
        }
        return 0;
    }
    if (n == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return -1;
    }
    LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nrecv += (size_t)n;
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
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, context->handshake.payload, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("udp_socks5_recv_authresp_cb", (const socks5_authresp_t *)context->handshake.payload)) {
        udp_socks5ctx_release(evloop, context);
        return;
    }
    const void *data;
    uint16_t datalen;
    if (g_socks5_usrpwd_requestlen) {
        data = &g_socks5_usrpwd_request;
        datalen = g_socks5_usrpwd_requestlen;
    } else {
        bool isipv4 = context->dest_is_ipv4;
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
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, context->handshake.payload, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("udp_socks5_recv_usrpwdresp_cb", (const socks5_usrpwdresp_t *)context->handshake.payload)) {
        udp_socks5ctx_release(evloop, context);
        return;
    }
    bool isipv4 = context->dest_is_ipv4;
    const void *data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    uint16_t datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
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
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    bool isipv4 = context->dest_is_ipv4;
    const void *request = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    uint16_t requestlen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    if (udp_socks5_send_request("udp_socks5_send_proxyreq_cb", evloop, tcp_watcher, request, requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_proxyresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_proxyresp_cb", evloop, tcp_watcher, context->handshake.payload, context->handshake.step_len) != 1) {
        return;
    }
    /* If we just read the first 5 bytes (Header prefix) */
    if (context->handshake.step_len == 5) {
        uint8_t atype = ((socks5_ipv4resp_t *)context->handshake.payload)->addrtype;
        size_t total_len;

        if (atype == SOCKS5_ADDRTYPE_IPV4) {
            total_len = sizeof(socks5_ipv4resp_t); // 10
        } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
            total_len = sizeof(socks5_ipv6resp_t); // 22
        } else {
            LOGERR("[udp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
            udp_socks5ctx_release(evloop, context);
            return;
        }

        if (total_len > SOCKS5_RESPONSE_MAX_SIZE - 2) {
            LOGERR("[udp_socks5_recv_proxyresp_cb] response too large: %zu", total_len);
            udp_socks5ctx_release(evloop, context);
            return;
        }

        if (total_len > 5) {
            /* Update length targets */
            context->handshake.step_len = total_len;
            context->handshake.nbytes = 5; /* We already have 5 bytes */

            /* Attempt to read the rest immediately */
            if (udp_socks5_recv_response("udp_socks5_recv_proxyresp_cb", evloop, tcp_watcher, context->handshake.payload, total_len) != 1) {
                return;
            }
        }
    }

    if (!socks5_proxy_response_check("udp_socks5_recv_proxyresp_cb", (const socks5_ipv4resp_t *)context->handshake.payload)) {
        udp_socks5ctx_release(evloop, context);
        return;
    }

    portno_t relay_port;
    uint8_t atype = ((socks5_ipv4resp_t *)context->handshake.payload)->addrtype;
    if (atype == SOCKS5_ADDRTYPE_IPV4) {
        relay_port = ((socks5_ipv4resp_t *)context->handshake.payload)->portnum;
    } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
        relay_port = ((socks5_ipv6resp_t *)context->handshake.payload)->portnum;
    } else {
        LOGERR("[udp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
        udp_socks5ctx_release(evloop, context);
        return;
    }

    /* the address is usually the same as the socks5 server address (except for the port) */
    skaddr6_t relay_addr;
    memcpy(&relay_addr, &g_server_skaddr, sizeof(g_server_skaddr));

    /* update the port to the udp relay port */
    bool relay_isipv4 = relay_addr.sin6_family == AF_INET;
    if (relay_isipv4) {
        ((skaddr4_t *)&relay_addr)->sin_port = relay_port;
    } else {
        relay_addr.sin6_port = relay_port;
    }

    /* connect to the socks5 udp relay endpoint */
    int udp_sockfd = new_udp_normal_sockfd(relay_addr.sin6_family);
    if (udp_sockfd < 0) {
        LOGERR("[udp_socks5_recv_proxyresp_cb] new_udp_normal_sockfd failed");
        udp_socks5ctx_release(evloop, context);
        return;
    }
    if (connect(udp_sockfd, (void *)&relay_addr, relay_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        char ipstr[IP6STRLEN];
        portno_t portno;
        parse_socket_addr(&relay_addr, ipstr, &portno);
        LOGERR("[udp_socks5_recv_proxyresp_cb] connect to udp://%s#%u: %s", ipstr, (unsigned)portno, strerror(errno));
        udp_socks5ctx_release(evloop, context);
        close(udp_sockfd);
        return;
    }

    udp_packet_queue_t *queue = &context->pending_queue;
    udp_packet_node_t *curr = queue->head;
    while (curr) {
        ssize_t nsend = send(udp_sockfd, curr->data, curr->len, 0);
        if (nsend < 0 || unlikely(g_verbose)) {
            char ipstr[260];
            portno_t portno;
            uint8_t addrtype = ((socks5_udp4msg_t *)curr->data)->addrtype;

            if (addrtype == SOCKS5_ADDRTYPE_IPV4) {
                socks5_udp4msg_t *udp4msg = (void *)curr->data;
                inet_ntop(AF_INET, &udp4msg->ipaddr4, ipstr, sizeof(ipstr));
                portno = ntohs(udp4msg->portnum);
            } else if (addrtype == SOCKS5_ADDRTYPE_DOMAIN) {
                /* Domain format: extract domain and port for logging */
                uint8_t *msg = curr->data;
                uint8_t domain_len = msg[4];
                memcpy(ipstr, msg + 5, domain_len);
                ipstr[domain_len] = '\0';
                memcpy(&portno, msg + 5 + domain_len, 2);
                portno = ntohs(portno);
            } else {
                socks5_udp6msg_t *udp6msg = (void *)curr->data;
                inet_ntop(AF_INET6, &udp6msg->ipaddr6, ipstr, sizeof(ipstr));
                portno = ntohs(udp6msg->portnum);
            }
            if (nsend < 0) {
                LOGERR("[udp_socks5_recv_proxyresp_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
            } else {
                LOGINF("[udp_socks5_recv_proxyresp_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nsend);
            }
        }
        udp_packet_node_t *next = curr->next;
        size_t node_size = sizeof(udp_packet_node_t) + curr->len;
        mempool_free_sized(g_udp_packet_pool, curr, node_size);
        curr = next;
    }

    context->pending_queue.head = NULL;
    context->pending_queue.tail = NULL;
    context->pending_queue.count = 0;
    context->udp_watcher.data = NULL;

    ev_set_cb(tcp_watcher, udp_socks5_recv_tcpmessage_cb);

    evio_t *udp_watcher_ptr = &context->udp_watcher;
    ev_io_init(udp_watcher_ptr, udp_socks5_recv_udpmessage_cb, udp_sockfd, EV_READ);
    ev_io_start(evloop, udp_watcher_ptr);

    ev_timer_again(evloop, &context->idle_timer);
    if (context->is_forked) {
        udp_socks5ctx_touch_fork(&g_udp_fork_table, context);
    } else {
        udp_socks5ctx_touch_main(&g_udp_socks5ctx_table, context);
    }
}

static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tcp_watcher = (evio_t *)watcher;
    char dummy_buf; /* Uninitialized single-byte local stack variable */

    /* Pass stack address directly, avoiding implicit initialization and dynamic allocation overhead */
    ssize_t nrecv = recv(tcp_watcher->fd, &dummy_buf, sizeof(dummy_buf), 0);

    if (nrecv > 0) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv unknown msg from socks5 server, release ctx");
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    } else if (nrecv == 0) {
        LOGINF("[udp_socks5_recv_tcpmessage_cb] recv FIN from socks5 server, release ctx");
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv from socks5 server: %s", strerror(errno));
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    }
}

static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *udp_watcher = (evio_t *)watcher;
    udp_socks5ctx_t *socks5ctx = (void *)((uint8_t *)udp_watcher - offsetof(udp_socks5ctx_t, udp_watcher));

    struct mmsghdr msgs[UDP_BATCH_SIZE];
    struct iovec iovs[UDP_BATCH_SIZE];

    /* Prepare for recvmmsg batch receive */
    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        iovs[i].iov_base = g_udp_batch_buffer[i];
        iovs[i].iov_len = UDP_DATAGRAM_MAXSIZ;

        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = NULL; /* Connected socket, no address needed */
        msgs[i].msg_hdr.msg_namelen = 0;
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int retval = recvmmsg(udp_watcher->fd, msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recvmmsg: %s", strerror(errno));
        }
        return;
    }

    /* Process batch and prepare for sendmmsg */
    struct {
        udp_tproxyctx_t *ctx;
        struct mmsghdr msg;
        struct iovec iov;
        skaddr6_t addr;
        char *data;
        size_t len;
    } batch_sends[UDP_BATCH_SIZE];
    int send_count = 0;

    /* Track unique tproxy contexts for batch-end LRU touch */
    udp_tproxyctx_t *tproxy_touched[UDP_BATCH_SIZE];
    int tproxy_touched_count = 0;

    for (int i = 0; i < retval; i++) {
        char *buffer = g_udp_batch_buffer[i];
        ssize_t nrecv = msgs[i].msg_len;

        /* Parse SOCKS5 header - inline logic from handle_udp_socks5_response */
        if ((size_t)nrecv < sizeof(socks5_udp4msg_t)) {
            continue;
        }

        socks5_udp4msg_t *udp4msg = (void *)buffer;
        bool isipv4 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV4;
        bool isipv6 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV6;

        size_t headerlen;
        if (isipv4) {
            headerlen = sizeof(socks5_udp4msg_t);
            if ((size_t)nrecv < headerlen) {
                continue;
            }
        } else if (isipv6) {
            headerlen = sizeof(socks5_udp6msg_t);
            if ((size_t)nrecv < headerlen) {
                continue;
            }
        } else {
            LOGERR("[udp_socks5_recv_udpmessage_cb] unsupported address type: 0x%02x", udp4msg->addrtype);
            continue;
        }

        /* Determine source (bind) address */
        ip_port_t fromipport;
        memset(&fromipport, 0, sizeof(fromipport));
        bool dest_isipv4;

        if (socks5ctx->is_fakedns) {
            fromipport = socks5ctx->orig_dstaddr;
            dest_isipv4 = socks5ctx->dest_is_ipv4;
        } else {
            if (isipv4) {
                fromipport.ip.ip4 = udp4msg->ipaddr4;
                fromipport.port = udp4msg->portnum;
                dest_isipv4 = true;
            } else if (isipv6) {
                socks5_udp6msg_t *udp6msg = (void *)buffer;
                memcpy(&fromipport.ip.ip6, &udp6msg->ipaddr6, IP6BINLEN);
                fromipport.port = udp6msg->portnum;
                dest_isipv4 = false;
            } else {
                continue;  /* Unsupported type */
            }
        }

        /* Get or create tproxy context (FIND: no LRU bump, deferred to batch-end) */
        udp_tproxyctx_t *tproxyctx = udp_tproxyctx_find(&g_udp_tproxyctx_table, &fromipport);
        if (!tproxyctx) {
            skaddr6_t fromskaddr = {0};
            if (dest_isipv4) {
                skaddr4_t *addr = (void *)&fromskaddr;
                addr->sin_family = AF_INET;
                addr->sin_addr.s_addr = fromipport.ip.ip4;
                addr->sin_port = fromipport.port;
            } else {
                fromskaddr.sin6_family = AF_INET6;
                memcpy(&fromskaddr.sin6_addr.s6_addr, &fromipport.ip.ip6, IP6BINLEN);
                fromskaddr.sin6_port = fromipport.port;
            }
            int tproxy_sockfd = new_udp_tpsend_sockfd(dest_isipv4 ? AF_INET : AF_INET6);
            if (bind(tproxy_sockfd, (void *)&fromskaddr, dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
                char ipstr[IP6STRLEN];
                portno_t portno;
                parse_socket_addr(&fromskaddr, ipstr, &portno);
                LOGERR("[udp_socks5_recv_udpmessage_cb] bind tproxy_sockfd to %s#%hu: %s", ipstr, portno, strerror(errno));
                close(tproxy_sockfd);
                continue;
            }
            tproxyctx = mempool_calloc_sized(g_udp_tproxy_pool, sizeof(*tproxyctx));
            if (!tproxyctx) {
                LOGERR("[udp_socks5_recv_udpmessage_cb] mempool alloc failed for tproxyctx");
                close(tproxy_sockfd);
                continue;
            }
            memcpy(&tproxyctx->key_ipport, &fromipport, sizeof(fromipport));
            tproxyctx->udp_sockfd = tproxy_sockfd;
            evtimer_t *timer = &tproxyctx->idle_timer;
            ev_timer_init(timer, udp_tproxy_context_timeout_cb, 0, UDP_TPROXY_TIMEOUT_SEC);
            udp_tproxyctx_t *del_context = udp_tproxyctx_add(&g_udp_tproxyctx_table, tproxyctx);
            if (del_context) {
                ev_invoke(evloop, &del_context->idle_timer, EV_CUSTOM);
            }
            /* New entry is already at MRU end from _add; skip dedup to avoid redundant touch */
            goto skip_tproxy_dedup;
        }

        /* Track unique tproxy contexts for batch-end touch (linear dedup) */
        {
            bool dup = false;
            for (int j = 0; j < tproxy_touched_count; j++) {
                if (tproxy_touched[j] == tproxyctx) {
                    dup = true;
                    break;
                }
            }
            if (!dup && tproxy_touched_count < UDP_BATCH_SIZE) {
                tproxy_touched[tproxy_touched_count++] = tproxyctx;
            }
        }

skip_tproxy_dedup: ;

        /* Prepare destination address */
        ip_port_t *toipport = &socks5ctx->key_ipport;
        memset(&batch_sends[send_count].addr, 0, sizeof(skaddr6_t));
        if (dest_isipv4) {
            skaddr4_t *addr = (void *)&batch_sends[send_count].addr;
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = toipport->ip.ip4;
            addr->sin_port = toipport->port;
        } else {
            batch_sends[send_count].addr.sin6_family = AF_INET6;
            memcpy(&batch_sends[send_count].addr.sin6_addr.s6_addr, &toipport->ip.ip6, IP6BINLEN);
            batch_sends[send_count].addr.sin6_port = toipport->port;
        }

        /* Prepare send message */
        batch_sends[send_count].ctx = tproxyctx;
        batch_sends[send_count].data = buffer + headerlen;
        batch_sends[send_count].len = nrecv - headerlen;
        batch_sends[send_count].iov.iov_base = batch_sends[send_count].data;
        batch_sends[send_count].iov.iov_len = batch_sends[send_count].len;
        batch_sends[send_count].msg.msg_hdr.msg_name = &batch_sends[send_count].addr;
        batch_sends[send_count].msg.msg_hdr.msg_namelen = dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
        batch_sends[send_count].msg.msg_hdr.msg_iov = &batch_sends[send_count].iov;
        batch_sends[send_count].msg.msg_hdr.msg_iovlen = 1;
        batch_sends[send_count].msg.msg_hdr.msg_control = NULL;
        batch_sends[send_count].msg.msg_hdr.msg_controllen = 0;

        send_count++;
        if (send_count >= UDP_BATCH_SIZE) {
            break;  /* Safety: prevent overflow */
        }
    }

    /* Batch send using sendmmsg - group by tproxy socket */
    if (send_count > 0) {
        /* Sort by socket fd to maximize batch efficiency */
        /* Optimization: Use indirect sorting (indices) to avoid memcpy of large structures */
        uint16_t indices[UDP_BATCH_SIZE];
        for (int k = 0; k < send_count; k++) {
            indices[k] = k;
        }

        for (int i = 0; i < send_count;) {
            udp_tproxyctx_t *ctx = batch_sends[indices[i]].ctx;
            int group_start = i;
            int group_count = 0;

            /* Find all messages for this socket */
            for (int j = i; j < send_count; j++) {
                if (batch_sends[indices[j]].ctx == ctx) {
                    if (j != i + group_count) {
                        /* Swap indices only */
                        uint16_t tmp = indices[i + group_count];
                        indices[i + group_count] = indices[j];
                        indices[j] = tmp;
                    }
                    group_count++;
                }
            }

            /* Send batch for this socket */
            struct mmsghdr group_msgs[UDP_BATCH_SIZE];

            for (int k = 0; k < group_count; k++) {
                int idx = indices[group_start + k];
                group_msgs[k].msg_hdr.msg_name       = &batch_sends[idx].addr;
                group_msgs[k].msg_hdr.msg_namelen    = batch_sends[idx].msg.msg_hdr.msg_namelen;
                group_msgs[k].msg_hdr.msg_iov        = &batch_sends[idx].iov;
                group_msgs[k].msg_hdr.msg_iovlen     = 1;
                group_msgs[k].msg_hdr.msg_control    = NULL;
                group_msgs[k].msg_hdr.msg_controllen = 0;
                group_msgs[k].msg_hdr.msg_flags      = 0;
                group_msgs[k].msg_len                = 0;
            }

            int sent = sendmmsg(ctx->udp_sockfd, group_msgs, group_count, 0);
            if (sent < 0) {
                LOGERR("[udp_socks5_recv_udpmessage_cb] sendmmsg failed: %s", strerror(errno));
            } else {
#ifdef ENABLE_SENDTO_LOG
                char ipstr[IP6STRLEN];
                ip_port_t *client = &socks5ctx->key_ipport;
                /* Use dest protocol family as heuristic (client usually matches target) */
                if (socks5ctx->dest_is_ipv4) {
                    inet_ntop(AF_INET, &client->ip.ip4, ipstr, sizeof(ipstr));
                } else {
                    inet_ntop(AF_INET6, &client->ip.ip6, ipstr, sizeof(ipstr));
                }
                LOGINF("[udp_socks5_recv_udpmessage_cb] sendmmsg to %s#%hu: %d packets sent",
                       ipstr, ntohs(client->port), sent);
#endif
                if (sent < group_count) {
                    /* Fallback for unsent */
                    LOGWAR("[udp_socks5_recv_udpmessage_cb] partial send %d/%d, using fallback", sent, group_count);
                    for (int k = sent; k < group_count; k++) {
                        struct msghdr *hdr = &group_msgs[k].msg_hdr;
                        ssize_t n = sendto(ctx->udp_sockfd, hdr->msg_iov[0].iov_base,
                                           hdr->msg_iov[0].iov_len, 0, hdr->msg_name, hdr->msg_namelen);
#ifdef ENABLE_SENDTO_LOG
                        if (n > 0) {
                            char ipstr[IP6STRLEN];
                            portno_t portno;
                            parse_socket_addr((skaddr6_t *)hdr->msg_name, ipstr, &portno);
                            LOGINF("[udp_socks5_recv_udpmessage_cb] fallback sendto %s#%hu, nsend:%zd", ipstr, portno, n);
                        }
#endif
                        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            LOGERR("[udp_socks5_recv_udpmessage_cb] fallback sendto failed: %s", strerror(errno));
                        }
                    }
                }
            }

            i += group_count;
        }
    }

    /* Optimization: Update LRU only once per batch */
    if (retval > 0) {
        /* socks5ctx: single context per watcher */
        if (socks5ctx->is_forked) {
            udp_socks5ctx_touch_fork(&g_udp_fork_table, socks5ctx);
        } else {
            udp_socks5ctx_touch_main(&g_udp_socks5ctx_table, socks5ctx);
        }
        ev_timer_again(evloop, &socks5ctx->idle_timer);

        /* tproxyctx: batch-end touch for each unique context */
        for (int i = 0; i < tproxy_touched_count; i++) {
            udp_tproxyctx_touch(&g_udp_tproxyctx_table, tproxy_touched[i]);
            ev_timer_again(evloop, &tproxy_touched[i]->idle_timer);
        }
    }
}

static void udp_socks5_context_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evtimer_t *idle_timer = (evtimer_t *)watcher;
    LOGINF("[udp_socks5_context_timeout_cb] context will be released, reason: %s", revents & EV_CUSTOM ? "manual" : "timeout");

    udp_socks5ctx_t *context = (void *)((uint8_t *)idle_timer - offsetof(udp_socks5ctx_t, idle_timer));
    if (context->is_forked) {
        udp_socks5ctx_del(&g_udp_fork_table, context);
    } else {
        udp_socks5ctx_del(&g_udp_socks5ctx_table, context);
    }

    ev_timer_stop(evloop, idle_timer);

    ev_io_stop(evloop, &context->tcp_watcher);
    close(context->tcp_watcher.fd);

    if (context->udp_watcher.data) {
        udp_packet_queue_t *queue = &context->pending_queue;
        udp_packet_node_t *curr = queue->head;
        while (curr) {
            udp_packet_node_t *next = curr->next;
            size_t node_size = sizeof(udp_packet_node_t) + curr->len;
            mempool_free_sized(g_udp_packet_pool, curr, node_size);
            curr = next;
        }
    } else {
        ev_io_stop(evloop, &context->udp_watcher);
        close(context->udp_watcher.fd);
    }

    mempool_free_sized(g_udp_context_pool, context, sizeof(*context));
}

static void udp_tproxy_context_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evtimer_t *idle_timer = (evtimer_t *)watcher;
    LOGINF("[udp_tproxy_context_timeout_cb] context will be released, reason: %s", revents & EV_CUSTOM ? "manual" : "timeout");

    udp_tproxyctx_t *context = (void *)((uint8_t *)idle_timer - offsetof(udp_tproxyctx_t, idle_timer));
    udp_tproxyctx_del(&g_udp_tproxyctx_table, context);

    ev_timer_stop(evloop, idle_timer);
    close(context->udp_sockfd);
    mempool_free_sized(g_udp_tproxy_pool, context, sizeof(*context));
}

static void wrapper_socks5_timeout_cb(void *evloop_ctx, udp_socks5ctx_t *entry) {
    udp_socks5_context_timeout_cb((evloop_t *)evloop_ctx, (struct ev_watcher *)&entry->idle_timer, EV_CUSTOM);
}

static void wrapper_tproxy_timeout_cb(void *evloop_ctx, udp_tproxyctx_t *entry) {
    udp_tproxy_context_timeout_cb((evloop_t *)evloop_ctx, (struct ev_watcher *)&entry->idle_timer, EV_CUSTOM);
}

void udp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[udp_proxy_close_all_sessions] cleaning up remaining sessions...");

    /* Clean UDP SOCKS5 Main Table */
    udp_socks5ctx_clear_main(&g_udp_socks5ctx_table, wrapper_socks5_timeout_cb, evloop);

    /* Clean UDP SOCKS5 Fork Table */
    udp_socks5ctx_clear_fork(&g_udp_fork_table, wrapper_socks5_timeout_cb, evloop);

    /* Clean UDP TProxy Table */
    udp_tproxyctx_clear(&g_udp_tproxyctx_table, wrapper_tproxy_timeout_cb, evloop);
}
