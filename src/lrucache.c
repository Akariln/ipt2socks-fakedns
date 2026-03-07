#include "lrucache.h"

#define FORK_SIZE_MULTIPLIER   2
#define TPROXY_SIZE_MULTIPLIER 4

static uint16_t g_main_cache_maxsize   = 256;
static uint16_t g_fork_cache_maxsize   = 256 * FORK_SIZE_MULTIPLIER;
static uint16_t g_tproxy_cache_maxsize = 256 * TPROXY_SIZE_MULTIPLIER;

uint16_t lrucache_get_main_maxsize(void) {
    return g_main_cache_maxsize;
}
uint16_t lrucache_get_fork_maxsize(void) {
    return g_fork_cache_maxsize;
}
uint16_t lrucache_get_tproxy_maxsize(void) {
    return g_tproxy_cache_maxsize;
}

/* Smart proportional sizing:
 * Main Table stays at base capacity.
 * Fork Table handles concurrent connection splitting, multiplying capacity (x2)
 * TProxy Table handles short-lived global proxy storms, expanding further (x4)
 * and is aggressively reclaimed by a short timeout mechanism.
 */
void lrucache_set_maxsize(uint16_t base_size) {
    g_main_cache_maxsize = base_size;

    // Use unsigned int to prevent overflow of uint16_t 65535 boundary
    unsigned int fork_size = base_size * FORK_SIZE_MULTIPLIER;
    g_fork_cache_maxsize = (fork_size > 65535) ? 65535 : (uint16_t)fork_size;

    unsigned int tproxy_size = base_size * TPROXY_SIZE_MULTIPLIER;
    g_tproxy_cache_maxsize = (tproxy_size > 65535) ? 65535 : (uint16_t)tproxy_size;
}

/* ── LRU operation templates ── */

#define DEFINE_LRU_ADD(func_name, type, key_field, maxsize_var)              \
type* func_name(type **cache, type *entry) {                                 \
    MYHASH_ADD(*cache, entry, &entry->key_field, sizeof(entry->key_field));   \
    if (MYHASH_CNT(*cache) > (maxsize_var)) {                                  \
        type *cur = NULL, *tmp = NULL;                                       \
        MYHASH_FOR(*cache, cur, tmp) {                                       \
            /* Do not call MYHASH_DEL here! The caller invokes the timeout callback */ \
            /* which will properly handle MYHASH_DEL and avoid double deletion. */ \
            return cur; /* return the oldest (LRU) entry */                  \
        }                                                                    \
    }                                                                        \
    return NULL;                                                             \
}

#define DEFINE_LRU_GET(func_name, type, key_type, key_field)                 \
type* func_name(type **cache, const key_type *keyptr) {                      \
    type *entry = NULL;                                                      \
    MYHASH_GET(*cache, entry, keyptr, sizeof(key_type));                      \
    if (entry) {                                                             \
        MYHASH_DEL(*cache, entry);                                           \
        MYHASH_ADD(*cache, entry, &entry->key_field, sizeof(entry->key_field)); \
    }                                                                        \
    return entry;                                                            \
}

#define DEFINE_LRU_DEL(func_name, type)                                      \
void func_name(type **cache, type *entry) {                                  \
    MYHASH_DEL(*cache, entry);                                               \
}

/* ── Instantiations ── */

DEFINE_LRU_ADD(udp_socks5ctx_add,      udp_socks5ctx_t, key_ipport, g_main_cache_maxsize)
DEFINE_LRU_ADD(udp_socks5ctx_fork_add, udp_socks5ctx_t, fork_key,   g_fork_cache_maxsize)
DEFINE_LRU_ADD(udp_tproxyctx_add,      udp_tproxyctx_t, key_ipport, g_tproxy_cache_maxsize)

DEFINE_LRU_GET(udp_socks5ctx_get,      udp_socks5ctx_t, ip_port_t,      key_ipport)
DEFINE_LRU_GET(udp_socks5ctx_fork_get, udp_socks5ctx_t, udp_fork_key_t, fork_key)
DEFINE_LRU_GET(udp_tproxyctx_get,      udp_tproxyctx_t, ip_port_t,      key_ipport)

DEFINE_LRU_DEL(udp_socks5ctx_del,      udp_socks5ctx_t)
DEFINE_LRU_DEL(udp_tproxyctx_del,      udp_tproxyctx_t)

/* ── use: kept as regular functions (already minimal / have unique signatures) ── */

void udp_socks5ctx_use(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry, const void *key, size_t key_len) {
    MYHASH_DEL(*cache, entry);
    MYHASH_ADD(*cache, entry, key, key_len);
}
void udp_tproxyctx_use(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry) {
    MYHASH_DEL(*cache, entry);
    MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
}
