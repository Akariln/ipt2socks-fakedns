#include "lrucache.h"    /* LRU_DEFINE_*                                   */
#include "udp_proxy.h"   /* udp_socks5ctx_t, udp_tproxyctx_t, ip_port_t, … */

/* ── udp_lrucache.c ────────────────────────────────────────────────────────
 * Single instantiation point for all typed LRU cache functions.
 * ──────────────────────────────────────────────────────────────────────── */

/* ════════════════════════════════════════════════════════════════════════
 * Cache Capacity Configuration & Globals
 * ════════════════════════════════════════════════════════════════════════ */

#define FORK_SIZE_MULTIPLIER   2
#define TPROXY_SIZE_MULTIPLIER 4

static uint16_t g_main_cache_maxsize   = 256;
static uint16_t g_fork_cache_maxsize   = 256 * FORK_SIZE_MULTIPLIER;
static uint16_t g_tproxy_cache_maxsize = 256 * TPROXY_SIZE_MULTIPLIER;

uint16_t udp_lrucache_get_main_maxsize(void)   {
    return g_main_cache_maxsize;
}
uint16_t udp_lrucache_get_fork_maxsize(void)   {
    return g_fork_cache_maxsize;
}
uint16_t udp_lrucache_get_tproxy_maxsize(void) {
    return g_tproxy_cache_maxsize;
}

/* Smart proportional sizing:
 *   Main Table  — base capacity
 *   Fork Table  — ×2
 *   TProxy Table— ×4
 */
void udp_lrucache_set_maxsize(uint16_t base_size) {
    g_main_cache_maxsize = base_size;

    unsigned int fork_size  = (unsigned int)base_size * FORK_SIZE_MULTIPLIER;
    unsigned int tproxy_size = (unsigned int)base_size * TPROXY_SIZE_MULTIPLIER;

    g_fork_cache_maxsize   = (fork_size   > 65535u) ? 65535u : (uint16_t)fork_size;
    g_tproxy_cache_maxsize = (tproxy_size > 65535u) ? 65535u : (uint16_t)tproxy_size;
}

/* ════════════════════════════════════════════════════════════════════════
 * Main Table  (key: client source IP:Port)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_ADD(udp_socks5ctx_add,
               udp_socks5ctx_t, key_ipport,
               udp_lrucache_get_main_maxsize(), last_active)

LRU_DEFINE_FIND(udp_socks5ctx_find,
                udp_socks5ctx_t, ip_port_t)

LRU_DEFINE_DEL(udp_socks5ctx_del,
               udp_socks5ctx_t)

/* ════════════════════════════════════════════════════════════════════════
 * Fork Table  (key: composite (client, target) pair; capacity ×2)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_ADD(udp_socks5ctx_fork_add,
               udp_socks5ctx_t, fork_key,
               udp_lrucache_get_fork_maxsize(), last_active)

LRU_DEFINE_FIND(udp_socks5ctx_fork_find,
                udp_socks5ctx_t, udp_fork_key_t)

/* Fork Table shares udp_socks5ctx_del with Main Table — no separate DEL needed */

/* ════════════════════════════════════════════════════════════════════════
 * TProxy Table  (key: remote source IP:Port; capacity ×4)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_ADD(udp_tproxyctx_add,
               udp_tproxyctx_t, key_ipport,
               udp_lrucache_get_tproxy_maxsize(), last_active)

LRU_DEFINE_FIND(udp_tproxyctx_find,
                udp_tproxyctx_t, ip_port_t)

LRU_DEFINE_DEL(udp_tproxyctx_del,
               udp_tproxyctx_t)

/* ════════════════════════════════════════════════════════════════════════
 * Clear All  (LRU_DEFINE_CLEAR)
 *
 * Provides a clean way to iterate over all entries and invoke a callback,
 * hiding the underlying uthash macros (HASH_ITER) from the rest of the
 * application.
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_CLEAR(udp_socks5ctx_clear_main, udp_socks5ctx_t)
LRU_DEFINE_CLEAR(udp_socks5ctx_clear_fork, udp_socks5ctx_t)
LRU_DEFINE_CLEAR(udp_tproxyctx_clear,      udp_tproxyctx_t)
