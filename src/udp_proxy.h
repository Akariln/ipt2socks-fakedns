#ifndef IPT2SOCKS_UDP_PROXY_H
#define IPT2SOCKS_UDP_PROXY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ev_types.h"

#include "lrucache.h"
#include "netutils.h"

uint16_t udp_lrucache_get_fullcone_maxsize(void);
uint16_t udp_lrucache_get_symmetric_maxsize(void);
uint16_t udp_lrucache_get_tproxy_maxsize(void);
void udp_lrucache_set_maxsize(uint16_t base_size);

#define MEMPOOL_INITIAL_SIZE  128

#define UDP_QUEUE_MAX_DEPTH   16
#define UDP_BATCH_SIZE        16

#define MAX_DOMAIN_LEN        255
#define MAX_SOCKS5_UDP_HEADER 262

#define UDP_BATCH_BUFSIZ      (UDP_DATAGRAM_MAXSIZ + MAX_SOCKS5_UDP_HEADER)

typedef struct udp_packet_node {
    struct udp_packet_node *next;
    size_t                  len;
    uint8_t                 data[];
} udp_packet_node_t;

typedef struct {
    udp_packet_node_t *head;
    udp_packet_node_t *tail;
    size_t             count;
} udp_packet_queue_t;

typedef struct {
    uint16_t family;
    portno_t port;
    uint8_t  addr[16];
} udp_endpoint_key_t;

_Static_assert(sizeof(udp_endpoint_key_t) == 20,
               "udp_endpoint_key_t must be 20B with zero padding for memcmp hashing");

typedef struct {
    udp_endpoint_key_t client;
    udp_endpoint_key_t target;
} udp_symmetric_key_t;

typedef udp_endpoint_key_t udp_tproxy_key_t;

typedef struct udp_session udp_session_t;
typedef struct udp_fullcone_node udp_fullcone_node_t;
typedef struct udp_symmetric_node udp_symmetric_node_t;

struct udp_fullcone_node {
    udp_endpoint_key_t key;
    udp_session_t     *session;
    ev_tstamp          last_active;
    myhash_hh          hh;
};

struct udp_symmetric_node {
    udp_symmetric_key_t key;
    udp_session_t      *session;
    ev_tstamp           last_active;
    myhash_hh           hh;
};

struct udp_session {
    evio_t                tcp_watcher;
    evio_t                udp_watcher;
    udp_endpoint_key_t    client_endpoint;           /* reply destination */
    udp_endpoint_key_t    original_target_endpoint;  /* original destination */
    bool                  uses_fakedns;
    udp_fullcone_node_t  *fullcone_node;
    udp_symmetric_node_t *symmetric_node;

    union {
        uint8_t handshake_buf[32];
        struct {
            uint16_t nbytes;
            uint16_t step_len;
            uint8_t  payload[28];
        } handshake;
    };
    udp_packet_queue_t pending_queue;
};

typedef struct {
    udp_tproxy_key_t key;
    int              udp_sockfd;
    ev_tstamp        last_active;
    myhash_hh        hh;
} udp_tproxy_entry_t;

udp_fullcone_node_t* udp_fullcone_node_add(udp_fullcone_node_t **cache, udp_fullcone_node_t *entry);
udp_symmetric_node_t* udp_symmetric_node_add(udp_symmetric_node_t **cache, udp_symmetric_node_t *entry);
udp_tproxy_entry_t* udp_tproxy_entry_add(udp_tproxy_entry_t **cache, udp_tproxy_entry_t *entry);

udp_fullcone_node_t* udp_fullcone_node_find(udp_fullcone_node_t **cache, const udp_endpoint_key_t *keyptr);
udp_symmetric_node_t* udp_symmetric_node_find(udp_symmetric_node_t **cache, const udp_symmetric_key_t *keyptr);
udp_tproxy_entry_t* udp_tproxy_entry_find(udp_tproxy_entry_t **cache, const udp_tproxy_key_t *keyptr);

void udp_fullcone_node_del(udp_fullcone_node_t **cache, udp_fullcone_node_t *entry);
void udp_symmetric_node_del(udp_symmetric_node_t **cache, udp_symmetric_node_t *entry);
void udp_tproxy_entry_del(udp_tproxy_entry_t **cache, udp_tproxy_entry_t *entry);

typedef void (*udp_fullcone_node_cb_t)(void *ctx, udp_fullcone_node_t *entry);
typedef void (*udp_symmetric_node_cb_t)(void *ctx, udp_symmetric_node_t *entry);
typedef void (*udp_tproxy_entry_cb_t)(void *ctx, udp_tproxy_entry_t *entry);

void udp_fullcone_node_clear(udp_fullcone_node_t **cache, udp_fullcone_node_cb_t cb, void *ctx);
void udp_symmetric_node_clear(udp_symmetric_node_t **cache, udp_symmetric_node_cb_t cb, void *ctx);
void udp_tproxy_entry_clear(udp_tproxy_entry_t **cache, udp_tproxy_entry_cb_t cb, void *ctx);

void udp_tproxy_recvmsg_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void udp_proxy_close_all_sessions(evloop_t *evloop);
void udp_proxy_gc_start(evloop_t *evloop);
void udp_proxy_gc_stop(evloop_t *evloop);

#endif /* IPT2SOCKS_UDP_PROXY_H */
