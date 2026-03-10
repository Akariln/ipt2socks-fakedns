#ifndef IPT2SOCKS_LRUCACHE_H
#define IPT2SOCKS_LRUCACHE_H

/* ── lrucache.h ────────────────────────────────────────────────────────────
 * Generic LRU-eviction layer.
 *
 * It provides:
 *   1. MYLRU_HASH_* wrappers around uthash (ADD / GET / DEL / CNT / FOR).
 *   2. Four LRU macro templates that callers instantiate once, in exactly
 *      one translation unit, to generate typed cache functions:
 *        LRU_DEFINE_ADD    — insert, evict LRU if over capacity
 *        LRU_DEFINE_GET    — lookup + bump to MRU end
 *        LRU_DEFINE_DEL    — unconditional removal
 *        LRU_DEFINE_TOUCH  — bump an existing entry to the MRU end (Touch)
 *        LRU_DEFINE_CLEAR  — iterate and invoke a callback on all entries
 * Requirements on the caller's struct:
 *   - must contain a field  `myhash_hh hh`  (the uthash bookkeeping handle)
 *   - key field(s) must be plain value types (no pointers-into-struct needed)
 * ──────────────────────────────────────────────────────────────────────── */

#include <stddef.h>
#include <stdint.h>

#include "xxhash.h"
#define HASH_FUNCTION(key, len, hashv) { (hashv) = XXH32((key), (len), 0); }
#include "uthash.h"

/* ── uthash handle typedef (keeps domain structs clean) ── */
typedef UT_hash_handle myhash_hh;

/* ── Thin uthash wrappers ── */
#define MYLRU_HASH_ADD(head, entry, keyptr, keylen) \
    HASH_ADD_KEYPTR(hh, (head), (keyptr), (keylen), (entry))

#define MYLRU_HASH_GET(head, out, keyptr, keylen) \
    HASH_FIND(hh, (head), (keyptr), (keylen), (out))

#define MYLRU_HASH_DEL(head, entry) \
    HASH_DELETE(hh, (head), (entry))

#define MYLRU_HASH_CNT(head) \
    HASH_COUNT(head)

/* Iterates in insertion order (oldest → newest) — used to find the LRU victim */
#define MYLRU_HASH_FOR(head, cur, tmp) \
    HASH_ITER(hh, (head), (cur), (tmp))

/* ════════════════════════════════════════════════════════════════════════
 * Generic LRU macro templates
 *
 * Instantiate each macro exactly once per (func_name, type) pair,
 * in a single .c file. Multiple inclusions of these macros in different
 * translation units will produce duplicate-symbol linker errors.
 *
 * LRU_DEFINE_ADD   — insert entry; if over capacity, returns the oldest
 *                    (LRU) entry so the caller can invoke its teardown
 *                    callback. The caller is responsible for MYLRU_HASH_DEL
 *                    + free on that returned pointer.
 *
 * LRU_DEFINE_GET   — lookup by key; on hit, re-inserts at tail (MRU end).
 *
 * LRU_DEFINE_DEL   — unconditional removal from the hash table.
 *
 * LRU_DEFINE_TOUCH — detach an already-inserted entry and re-insert it
 *                    at the MRU end (touch/bump).
 *
 *   Motivation: When an existing session receives new packets, we must reset
 *   its LRU eviction timer. Rather than doing a useless hash lookup (GET),
 *   we already have the pointer. We simply DEL and ADD it back.
 *   Because the ADD macro needs to know which key field to hash on, we
 *   instantiate one TOUCH function per key field:
 *
 *     LRU_DEFINE_TOUCH(udp_socks5ctx_touch_main, udp_socks5ctx_t, key_ipport)
 *     LRU_DEFINE_TOUCH(udp_socks5ctx_touch_fork, udp_socks5ctx_t, fork_key)
 *
 *   The compiler ensures we pass the correct object type to the right table's
 *   touch function.
 *
 * LRU_DEFINE_CLEAR — iterate over all entries and invoke a caller-supplied
 *                    teardown callback on each.
 *
 *   The callback MAY call the corresponding _del function on the current
 *   entry; doing so is safe because the iterator saves the next pointer
 *   before entering the loop body (HASH_ITER guarantee).
 *
 *   The callback MUST eventually remove each entry from the table (via _del
 *   or equivalent), either synchronously inside the callback or via a
 *   guaranteed-synchronous mechanism such as ev_invoke with EV_CUSTOM.
 *   Leaving entries in the table after clear completes is a bug.
 *
 *   Motivation: Abstract away `HASH_ITER` and `hh` so that business logic
 *   files never need to interact with uthash macros directly.
 * ════════════════════════════════════════════════════════════════════════ */

#define LRU_DEFINE_ADD(func_name, type, key_field, maxsize_expr)             \
type* func_name(type **cache, type *entry) {                                 \
    MYLRU_HASH_ADD(*cache, entry, &entry->key_field, sizeof(entry->key_field));  \
    if (MYLRU_HASH_CNT(*cache) > (maxsize_expr)) {                               \
        type *cur_ = NULL, *tmp_ = NULL;                                     \
        MYLRU_HASH_FOR(*cache, cur_, tmp_) {                                     \
            /* Return the oldest entry; caller owns teardown + DEL.        */ \
            /* Do NOT call MYLRU_HASH_DEL here — the timeout callback does it. */ \
            return cur_;                                                     \
        }                                                                    \
    }                                                                        \
    return NULL;                                                             \
}

#define LRU_DEFINE_GET(func_name, type, key_type, key_field)                 \
type* func_name(type **cache, const key_type *keyptr) {                      \
    type *entry = NULL;                                                      \
    MYLRU_HASH_GET(*cache, entry, keyptr, sizeof(key_type));                     \
    if (entry) {                                                             \
        /* Bump to MRU end */                                                \
        MYLRU_HASH_DEL(*cache, entry);                                           \
        MYLRU_HASH_ADD(*cache, entry, &entry->key_field, sizeof(entry->key_field)); \
    }                                                                        \
    return entry;                                                            \
}

#define LRU_DEFINE_DEL(func_name, type)                                      \
void func_name(type **cache, type *entry) {                                  \
    MYLRU_HASH_DEL(*cache, entry);                                               \
}

#define LRU_DEFINE_TOUCH(func_name, type, key_field)                         \
void func_name(type **cache, type *entry) {                                  \
    MYLRU_HASH_DEL(*cache, entry);                                               \
    MYLRU_HASH_ADD(*cache, entry, &entry->key_field, sizeof(entry->key_field));  \
}

#define LRU_DEFINE_CLEAR(func_name, type)                                    \
void func_name(type **cache, void (*cb)(void *, type *), void *ctx) {        \
    type *curr, *tmp;                                                        \
    MYLRU_HASH_FOR(*cache, curr, tmp) {                                      \
        cb(ctx, curr);                                                       \
    }                                                                        \
}

#endif /* IPT2SOCKS_LRUCACHE_H */
