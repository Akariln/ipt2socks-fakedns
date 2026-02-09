#ifndef IPT2SOCKS_LRUCACHE_H
#define IPT2SOCKS_LRUCACHE_H

#include "xxhash.h"
#define HASH_FUNCTION(key,len,hashv) { hashv = XXH32(key, len, 0); }
#include "uthash.h"
#include "netutils.h"

#include "../libev/ev.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    ip_port_t  client_ipport;
    bool       target_is_ipv4; // Protocol family flag for target
    ip_port_t  target_ipport;  // Target IP + Port (Full address for Symmetric NAT)
} udp_fork_key_t;

typedef struct {
    ip_port_t  key_ipport;   // Client IP:Port (Main Table key)
    udp_fork_key_t fork_key; // Client IP:Port + Target IP:Port (Fork Table key)
    ip_port_t  orig_dstaddr; // Original destination address (FakeIP or real IP)
    bool       dest_is_ipv4; // Protocol family flag for orig_dstaddr
    bool       is_forked;    // Is this session in the Fork Table?
    bool       is_fakedns;   // Is this a FakeDNS session?
    evio_t     tcp_watcher;  // .data: len(16bit) | recvbuff
    evio_t     udp_watcher;  // .data: len(16bit) | firstmsg
    evtimer_t  idle_timer;
    myhash_hh  hh;
} udp_socks5ctx_t;

typedef struct {
    ip_port_t  key_ipport; // (remote) source socket address
    int        udp_sockfd; // bind the above socket address
    evtimer_t  idle_timer;
    myhash_hh  hh;
} udp_tproxyctx_t;

uint16_t lrucache_get_main_maxsize(void);
uint16_t lrucache_get_fork_maxsize(void);
uint16_t lrucache_get_tproxy_maxsize(void);

void lrucache_set_main_maxsize(uint16_t maxsize);
void lrucache_set_fork_maxsize(uint16_t maxsize);
void lrucache_set_tproxy_maxsize(uint16_t maxsize);
void lrucache_set_maxsize(uint16_t maxsize);  /* Set all caches */

/* return the removed hashentry pointer */
udp_socks5ctx_t* udp_socks5ctx_add(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
udp_socks5ctx_t* udp_socks5ctx_fork_add(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
udp_tproxyctx_t* udp_tproxyctx_add(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry);

udp_socks5ctx_t* udp_socks5ctx_get(udp_socks5ctx_t **cache, const ip_port_t *keyptr);
udp_socks5ctx_t* udp_socks5ctx_fork_get(udp_socks5ctx_t **cache, const udp_fork_key_t *keyptr);
udp_tproxyctx_t* udp_tproxyctx_get(udp_tproxyctx_t **cache, const ip_port_t *keyptr);

void udp_socks5ctx_use(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
void udp_tproxyctx_use(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry);

void udp_socks5ctx_del(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
void udp_tproxyctx_del(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry);

#endif
