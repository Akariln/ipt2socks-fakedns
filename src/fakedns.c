#define _GNU_SOURCE
#include "fakedns.h"
#include "xxhash.h"
#include "logutils.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>

typedef struct {
    uint32_t ip; /* Network Byte Order */
    uint32_t expire;
    uint32_t version; // Incremented atomically on domain overwrite
    char domain[FAKEDNS_MAX_DOMAIN_LEN];
} __attribute__((aligned(64))) fakedns_entry_t;

static fakedns_entry_t **g_fakedns_pool = NULL;
static pthread_rwlock_t g_fakedns_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static uint32_t g_fakeip_net_host = 0; /* Host byte order */
static uint32_t g_fakeip_mask_host = 0; /* Host byte order */
static uint32_t g_pool_size = 0;
static uint32_t g_pool_used = 0;
static uint32_t g_last_warn_used = 0;  /* for warning log throttling */
static char g_cidr_str[64] = {0};

/* Thread-local MRU cache (Pointer Array structure) for reverse lookup (lock-free optimization) */
#define FAKEDNS_MRU_SIZE 8
typedef struct {
    uint32_t ip;
    uint32_t version; // Shadows global entry->version for dirty checking
    bool valid;
    uint8_t _padding[3]; // Explicit padding to align domain to offset 12
    char domain[FAKEDNS_MAX_DOMAIN_LEN];
} __attribute__((aligned(64))) fakedns_mru_entry_t;

_Static_assert(sizeof(fakedns_entry_t) == 256, "fakedns_entry_t must be exactly 256B (4 cache lines)");
_Static_assert(sizeof(fakedns_entry_t) % 64 == 0, "fakedns_entry_t must be cache-line aligned");
_Static_assert(offsetof(fakedns_entry_t, domain) == 12, "metadata must occupy first 12B of CL#0");
_Static_assert(sizeof(fakedns_mru_entry_t) == 256, "fakedns_mru_entry_t must be exactly 256B");

static __thread fakedns_mru_entry_t g_fakedns_mru_data[FAKEDNS_MRU_SIZE] = {0};
static __thread fakedns_mru_entry_t *g_fakedns_mru_ptrs[FAKEDNS_MRU_SIZE] = {0};
static __thread bool g_fakedns_mru_init = false;

#ifdef FAKEDNS_MRU_STATS
static __thread uint64_t g_mru_hits = 0;
static __thread uint64_t g_mru_misses = 0;
static __thread int64_t g_mru_last_stat_time = 0;
#endif

static const uint32_t FAKEDNS_TTL = 43200; // 12 hours
#define FAKEDNS_TTL_REFRESH_THRESHOLD (int32_t)(FAKEDNS_TTL * 3 / 10)

// Pool usage warning thresholds
#define FAKEDNS_POOL_WARN_THRESHOLD   0.80f  // 80% usage warning
#define FAKEDNS_POOL_CRITICAL_THRESHOLD 0.95f  // 95% usage critical
static uint32_t g_max_probes = 0;

void fakedns_init(const char *cidr_str) {
    if (!cidr_str) {
        LOGERR("[fakedns_init] cidr_str is NULL");
        exit(1);
    }

    char ip_str[64];
    strncpy(ip_str, cidr_str, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    // Store global CIDR for persistence validation
    strncpy(g_cidr_str, cidr_str, sizeof(g_cidr_str) - 1);
    g_cidr_str[sizeof(g_cidr_str) - 1] = '\0';

    char *slash = strchr(ip_str, '/');
    if (!slash) {
        LOGERR("[fakedns_init] invalid cidr format: %s", cidr_str);
        exit(1);
    }
    *slash = '\0';
    char *endptr;
    long prefix_len = strtol(slash + 1, &endptr, 10);

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        LOGERR("[fakedns_init] invalid ip format: %s", ip_str);
        exit(1);
    }

    if (*endptr != '\0' || prefix_len < 8 || prefix_len > 24) {
        LOGERR("[fakedns_init] invalid prefix length %ld (must be between /8 and /24)", prefix_len);
        exit(1);
    }

    uint32_t ip_host = ntohl(addr.s_addr);
    uint32_t mask_host = (~0U) << (32 - prefix_len);

    g_fakeip_net_host = ip_host & mask_host;
    g_fakeip_mask_host = mask_host;
    g_pool_size = 1U << (32 - prefix_len);

    g_fakedns_pool = calloc(g_pool_size, sizeof(fakedns_entry_t *));
    if (!g_fakedns_pool) {
        LOGERR("[fakedns_init] failed to allocate memory for fakedns pool (size: %u)", g_pool_size);
        exit(1);
    }

    // Fix linear probing limit issue:
    // We limit Max Probing strictly to 128 (approx 0.95^128 < 0.002 probability of failure at 95% load)
    // to prevent CPU spinning and write-lock starvation on huge fake-ip CIDRs.
    g_max_probes = (g_pool_size < 128) ? g_pool_size : 128;

    LOG_ALWAYS_INF("[fakedns_init] IP range: %s/%ld", ip_str, prefix_len);
    LOG_ALWAYS_INF("[fakedns_init] Pool size: %u addresses (array: %.1f KB, max data: %.1f KB)",
                   g_pool_size,
                   (float)(g_pool_size * sizeof(fakedns_entry_t *)) / 1024.0f,
                   (float)(g_pool_size * sizeof(fakedns_entry_t)) / 1024.0f);
    LOG_ALWAYS_INF("[fakedns_init] High usage threshold: %.0f%% (%u entries)",
                   FAKEDNS_POOL_WARN_THRESHOLD * 100.0f, (uint32_t)(g_pool_size * FAKEDNS_POOL_WARN_THRESHOLD));
    LOG_ALWAYS_INF("[fakedns_init] Critically high usage threshold: %.0f%% (%u entries)",
                   FAKEDNS_POOL_CRITICAL_THRESHOLD * 100.0f, (uint32_t)(g_pool_size * FAKEDNS_POOL_CRITICAL_THRESHOLD));
    LOG_ALWAYS_INF("[fakedns_init] Max probe steps: %u", g_max_probes);
}

static uint32_t fakedns_lookup_domain(const char *domain, size_t len) {
    if (!domain || !g_pool_size) return 0;

    uint32_t pool_mask = g_pool_size - 1;
    uint64_t hash = XXH3_64bits(domain, len);
    uint32_t offset_start = (uint32_t)(hash & pool_mask);
    /* Double Hashing: Use upper 32 bits as step size. Must be odd (coprime to power-of-2 size). */
    uint32_t step = (uint32_t)(hash >> 32) | 1;

    uint32_t offset = offset_start;
    uint32_t now = (uint32_t)time(NULL);

    // Phase 1: Try read lock first for fast path (cache hit with valid TTL)
    pthread_rwlock_rdlock(&g_fakedns_rwlock);

    for (uint32_t i = 0; i < g_max_probes; ++i) {
        uint32_t ip_host = g_fakeip_net_host + offset;
        uint32_t ip_net = htonl(ip_host);

        fakedns_entry_t *entry = g_fakedns_pool[offset];

        if (!entry) {
            // Empty slot found, need write lock to insert
            break;
        } else if (strcmp(entry->domain, domain) == 0) {
            // Match found! Check if we need to update TTL
            uint32_t exp = __atomic_load_n(&entry->expire, __ATOMIC_RELAXED);
            int32_t remaining = (int32_t)(exp - now);

            // Lazy update: only update if TTL remaining < 30%
            if (remaining > FAKEDNS_TTL_REFRESH_THRESHOLD) {
                pthread_rwlock_unlock(&g_fakedns_rwlock);
                return ip_net;
            }

            __atomic_store_n(&entry->expire, now + FAKEDNS_TTL, __ATOMIC_RELAXED);

            pthread_rwlock_unlock(&g_fakedns_rwlock);
            return ip_net;
        } else {
            // Collision, continue probing (Double Hashing)
            offset = (offset + step) & pool_mask;
        }
    }

    pthread_rwlock_unlock(&g_fakedns_rwlock);

    // Phase 2: Acquire write lock for insert/update
    pthread_rwlock_wrlock(&g_fakedns_rwlock);

    // Reset offset for write path
    offset = offset_start;

    for (uint32_t i = 0; i < g_max_probes; ++i) {
        uint32_t ip_host = g_fakeip_net_host + offset;
        uint32_t ip_net = htonl(ip_host);

        fakedns_entry_t *entry = g_fakedns_pool[offset];

        if (!entry) {
            // Check if pool is full before adding new entry
            if (g_pool_used >= g_pool_size) {
                pthread_rwlock_unlock(&g_fakedns_rwlock);
                LOGERR("[fakedns_lookup_domain] pool is full (%u/%u), rejected: %s", g_pool_used, g_pool_size, domain);
                return 0;
            }

            // Found empty slot, insert new entry
            if (posix_memalign((void **)&entry, 64, sizeof(fakedns_entry_t)) != 0) {
                entry = NULL;
            }
            if (!entry) {
                pthread_rwlock_unlock(&g_fakedns_rwlock);
                LOGERR("[fakedns_lookup_domain] malloc failed for domain: %s", domain);
                return 0;
            }
            entry->ip = ip_net;
            size_t copy_len = len >= sizeof(entry->domain) ? sizeof(entry->domain) - 1 : len;
            memcpy(entry->domain, domain, copy_len);
            entry->domain[copy_len] = '\0';
            entry->expire = now + FAKEDNS_TTL;
            entry->version = 1;
            __atomic_store_n(&g_fakedns_pool[offset], entry, __ATOMIC_RELEASE);
            g_pool_used++;

            float usage = (float)g_pool_used / (float)g_pool_size;
            if (usage >= FAKEDNS_POOL_CRITICAL_THRESHOLD) {
                // Throttle critical warnings
                uint32_t warn_step = g_pool_size / 50;

                if (g_pool_used - g_last_warn_used >= warn_step) {
                    LOGERR("[fakedns] CRITICAL: pool usage is critically high: %.1f%% (%u/%u)", usage * 100.0f, g_pool_used, g_pool_size);
                    g_last_warn_used = g_pool_used;
                }
            } else if (usage >= FAKEDNS_POOL_WARN_THRESHOLD) {
                // Only warn every 5% increase to avoid spam
                uint32_t warn_step = g_pool_size / 20;

                if (g_pool_used - g_last_warn_used >= warn_step) {
                    LOGWAR("[fakedns] WARNING: pool usage is high: %.1f%% (%u/%u)", usage * 100.0f, g_pool_used, g_pool_size);
                    g_last_warn_used = g_pool_used;
                }
            }

            pthread_rwlock_unlock(&g_fakedns_rwlock);
            return ip_net;
        } else {
            // Slot occupied
            if (strcmp(entry->domain, domain) == 0) {
                // Match confirmed, update TTL
                entry->expire = now + FAKEDNS_TTL;
                pthread_rwlock_unlock(&g_fakedns_rwlock);

                return ip_net;
            } else {
                // Collision
                // Strategy A: Overwrite if expired
                int32_t remaining = (int32_t)(entry->expire - now);
                if (remaining < 0) {
                    LOGINF("[fakedns] overwrite expired entry: %s -> %s (IP: %u.%u.%u.%u)",
                           entry->domain, domain,
                           ((uint8_t*)&ip_net)[0], ((uint8_t*)&ip_net)[1], ((uint8_t*)&ip_net)[2], ((uint8_t*)&ip_net)[3]);

                    // Reset entry for new domain
                    size_t copy_len = len >= sizeof(entry->domain) ? sizeof(entry->domain) - 1 : len;
                    memcpy(entry->domain, domain, copy_len);
                    entry->domain[copy_len] = '\0';
                    entry->expire = now + FAKEDNS_TTL;
                    // Atomically increment version so all threaded MRU caches instantly know it's dirty
                    __atomic_add_fetch(&entry->version, 1, __ATOMIC_RELEASE);

                    pthread_rwlock_unlock(&g_fakedns_rwlock);
                    return ip_net;
                }

                // Still valid, linear probe (Double Hashing)
                offset = (offset + step) & pool_mask;
            }
        }
    }

    pthread_rwlock_unlock(&g_fakedns_rwlock);
    LOGERR("[fakedns_lookup_domain] max probes (%u) exhausted for domain: %s", g_max_probes, domain);
    return 0;
}

bool fakedns_is_fakeip(uint32_t ip_net) {
    if (!g_pool_size) return false;
    uint32_t ip_host = ntohl(ip_net);
    return ((ip_host & g_fakeip_mask_host) == g_fakeip_net_host);
}

bool fakedns_reverse_lookup(uint32_t ip, char *buffer, size_t buf_len) {
    if (!buffer || buf_len == 0) return false;

    // Prerequisite: Compute offset for global array validation
    uint32_t ip_host = ntohl(ip);
    if ((ip_host & g_fakeip_mask_host) != g_fakeip_net_host) return false;
    uint32_t offset = ip_host - g_fakeip_net_host;
    if (offset >= g_pool_size) return false;

    // Initialize MRU pointer array on first thread usage
    if (!g_fakedns_mru_init) {
        for (int i = 0; i < FAKEDNS_MRU_SIZE; ++i) {
            g_fakedns_mru_ptrs[i] = &g_fakedns_mru_data[i];
        }
        g_fakedns_mru_init = true;
    }

    /* 1. Fast Path: Check Thread-Local MRU Cache (Lock-Free) */
    for (int i = 0; i < FAKEDNS_MRU_SIZE; ++i) {
        fakedns_mru_entry_t *mru_item = g_fakedns_mru_ptrs[i];
        if (mru_item->valid && mru_item->ip == ip) {

            // [DIRTY CACHE PREVENTION] Lock-free generation check!
            // Global pool is strictly append-only or version-incremented on reuse.
            fakedns_entry_t *g_entry = __atomic_load_n(&g_fakedns_pool[offset], __ATOMIC_ACQUIRE);
            if (!g_entry || __atomic_load_n(&g_entry->version, __ATOMIC_ACQUIRE) != mru_item->version) {
                // The global slot was overwritten by a new domain. Cache is dirty.
                mru_item->valid = false;
                break; // Fall through to slow path which grabs global read lock
            }

            size_t len = strnlen(mru_item->domain, buf_len - 1);
            memcpy(buffer, mru_item->domain, len);
            buffer[len] = '\0';

            // Move-to-Front: promote found item to index 0
            if (i > 0) {
                // Shift [0..i-1] pointers to [1..i]
                memmove(&g_fakedns_mru_ptrs[1], &g_fakedns_mru_ptrs[0], i * sizeof(fakedns_mru_entry_t *));
                g_fakedns_mru_ptrs[0] = mru_item;
            }

#ifdef FAKEDNS_MRU_STATS
            g_mru_hits++;
            // Check time inside hit path every 512 hits to avoid time() syscall overhead
            if ((g_mru_hits & 511) == 0) {
                int64_t now_stat = (int64_t)time(NULL);
                if (g_mru_last_stat_time == 0) {
                    g_mru_last_stat_time = now_stat;
                } else if (now_stat - g_mru_last_stat_time >= 1800) {
                    uint64_t total = g_mru_hits + g_mru_misses;
                    float hp = (float)g_mru_hits / total * 100.0f;
                    LOG_ALWAYS_INF("[fakedns_score] Thread %p | Hits: %llu, Misses: %llu, WinRate: %.2f%%",
                                   (void*)pthread_self(), (unsigned long long)g_mru_hits, (unsigned long long)g_mru_misses, hp);
                    g_mru_hits = 0;
                    g_mru_misses = 0;
                    g_mru_last_stat_time = now_stat;
                }
            }
#endif
            return true;
        }
    }

#ifdef FAKEDNS_MRU_STATS
    g_mru_misses++;
#endif

    /* 2. Slow Path: Global Array Lookup (Read Lock) */
    char tmp_domain[FAKEDNS_MAX_DOMAIN_LEN];
    uint32_t tmp_version = 0;
    bool found = false;
    size_t dlen = 0;

    pthread_rwlock_rdlock(&g_fakedns_rwlock);
    fakedns_entry_t *entry = g_fakedns_pool[offset];
    if (entry) {
        dlen = strnlen(entry->domain, sizeof(tmp_domain) - 1);
        memcpy(tmp_domain, entry->domain, dlen);
        tmp_domain[dlen] = '\0';
        tmp_version = entry->version;
        found = true;
    }
    pthread_rwlock_unlock(&g_fakedns_rwlock);

    if (found) {
        size_t copy_len = dlen >= buf_len ? buf_len - 1 : dlen;
        memcpy(buffer, tmp_domain, copy_len);
        buffer[copy_len] = '\0';

        /* 3. Update MRU Cache: Insert at front */
        fakedns_mru_entry_t *evicted = g_fakedns_mru_ptrs[FAKEDNS_MRU_SIZE - 1];
        memmove(&g_fakedns_mru_ptrs[1], &g_fakedns_mru_ptrs[0], (FAKEDNS_MRU_SIZE - 1) * sizeof(fakedns_mru_entry_t *));

        g_fakedns_mru_ptrs[0] = evicted;
        evicted->ip = ip;
        evicted->version = tmp_version;
        memcpy(evicted->domain, tmp_domain, dlen);
        evicted->domain[dlen] = '\0';
        evicted->valid = true;
    }
    return found;
}

/* DNS Packet Layout
 * Header: 12 bytes
 * Question: Name (variable) + Type(2) + Class(2)
 */

size_t fakedns_process_query(const uint8_t *query, size_t qlen, uint8_t *buffer, size_t buflen) {
    if (qlen < 12 || buflen < qlen) return 0; // Too short or buffer too small to hold echo

    // Header parsing
    // ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
    //uint16_t id = (query[0] << 8) | query[1];
    uint16_t flags = (query[2] << 8) | query[3];
    uint16_t qdcount = (query[4] << 8) | query[5];

    // Valid query checks: QR=0, Opcode=0, QDCOUNT=1
    if ((flags & 0xF800) != 0 || qdcount != 1) return 0; // Not a standard query or multiple questions

    // Copy ID and set common flags for response (QR=1, RA=1, AA=0, RD from query)
    // RCODE=0 (Success) by default
    uint16_t resp_flags = 0x8180 | (flags & 0x0100); // QR=1, Opcode=0, AA=0, TC=0, RD=from_query, RA=1, Z=0, RCODE=0

    // Question parsing
    size_t offset = 12;
    // Walk through QNAME
    char domain[FAKEDNS_MAX_DOMAIN_LEN];
    size_t dom_len = 0;
    size_t label_count = 0;
    while (offset < qlen) {
        if (++label_count > 128) return 0; // Too many labels (loop limit safety)
        uint8_t len = query[offset];
        if (len == 0) {
            offset++;
            break;
        }
        if (len > 63) return 0; // RFC 1035: labels must be 63 octets or less

        if (offset + 1 + len > qlen) return 0; // Overflow

        // Enforce packed struct domain length limit
        if (dom_len + (dom_len > 0 ? 1 : 0) + len >= FAKEDNS_MAX_DOMAIN_LEN) return 0;

        if (dom_len > 0) domain[dom_len++] = '.';
        memcpy(domain + dom_len, query + offset + 1, len);
        dom_len += len;

        offset += 1 + len;
    }

    if (dom_len == 0) return 0; // Empty name
    domain[dom_len] = '\0';

    if (offset + 4 > qlen) return 0; // Malformed

    uint16_t qtype = (query[offset] << 8) | query[offset + 1];
    uint16_t qclass = (query[offset + 2] << 8) | query[offset + 3];

    // We only answer IN class (1)
    if (qclass != 1) {
        resp_flags |= 0x0005; // Set RCODE to 5 (Refused)

        // Construct header and return immediately (NODATA)
        if (offset + 4 > buflen) return 0;
        if (query != buffer) memcpy(buffer, query, offset + 4);

        buffer[2] = (resp_flags >> 8) & 0xFF;
        buffer[3] = resp_flags & 0xFF;
        buffer[6] = 0;
        buffer[7] = 0; // ANCOUNT = 0
        buffer[8] = 0;
        buffer[9] = 0; // NSCOUNT = 0
        buffer[10] = 0;
        buffer[11] = 0; // ARCOUNT = 0

        return offset + 4; // Return header + question only
    }

    // Construct buffer
    // Copy Header + Question
    if (offset + 4 > buflen) return 0;
    if (query != buffer) memcpy(buffer, query, offset + 4);

    // Update Header
    buffer[2] = (resp_flags >> 8) & 0xFF;
    buffer[3] = resp_flags & 0xFF;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0 by default
    buffer[6] = 0;
    buffer[7] = 0;
    buffer[8] = 0;
    buffer[9] = 0;
    buffer[10] = 0;
    buffer[11] = 0;

    size_t resp_len = offset + 4;

    if (qtype == 1) { /* A Record */
        uint32_t fakeip = fakedns_lookup_domain(domain, dom_len);
        if (fakeip) {
            // Add Answer
            // Ptr to name (0xC00C - Offset 12)
            if (resp_len + 16 > buflen) return 0; // 2(Ptr) + 2(Type) + 2(Class) + 4(TTL) + 2(Len) + 4(IP)

            buffer[resp_len++] = 0xC0;
            buffer[resp_len++] = 0x0C;

            buffer[resp_len++] = 0x00;
            buffer[resp_len++] = 0x01; // Type A
            buffer[resp_len++] = 0x00;
            buffer[resp_len++] = 0x01; // Class IN
            /* TTL */
            uint32_t ttl_n = htonl(FAKEDNS_TTL);
            memcpy(buffer + resp_len, &ttl_n, 4);
            resp_len += 4;
            /* RDLENGTH = 4 */
            buffer[resp_len++] = 0x00;
            buffer[resp_len++] = 0x04;
            /* RDATA */
            memcpy(buffer + resp_len, &fakeip, 4);
            resp_len += 4;

            // Set ANCOUNT = 1
            buffer[7] = 1;

            LOGINF("[fakedns] query: A %s -> %u.%u.%u.%u", domain,
                   ((uint8_t*)&fakeip)[0], ((uint8_t*)&fakeip)[1], ((uint8_t*)&fakeip)[2], ((uint8_t*)&fakeip)[3]);
        }
    } else if (qtype == 28) { /* AAAA Record */
        // Return NOERROR with 0 Answers (Handling dual-stack fallback)
        LOGINF("[fakedns] query: AAAA %s -> NODATA", domain);
    } else {
        // Other types -> NODATA
    }

    return resp_len;
}

static const uint32_t FAKEDNS_MAGIC = 0x464E5344; // "DNSF" Little Endian -> "FNSD"
static const uint32_t FAKEDNS_VERSION = 3;

void fakedns_save(const char *path) {
    if (!path || !g_fakedns_pool) return;

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        LOGERR("[fakedns_save] failed to open tmp file %s: %s", tmp_path, strerror(errno));
        return;
    }

    pthread_rwlock_rdlock(&g_fakedns_rwlock);  // Use read lock for saving

    // Count valid entries
    uint32_t count = g_pool_used;

    // Write Header
    if (fwrite(&FAKEDNS_MAGIC, 4, 1, fp) != 1 ||
            fwrite(&FAKEDNS_VERSION, 4, 1, fp) != 1 ||
            fwrite(&count, 4, 1, fp) != 1) {
        LOGERR("[fakedns_save] failed to write header to %s", tmp_path);
        pthread_rwlock_unlock(&g_fakedns_rwlock);
        fclose(fp);
        unlink(tmp_path);
        return;
    }

    // Version 3: Write CIDR
    uint16_t cidr_len = strlen(g_cidr_str);
    if (fwrite(&cidr_len, 2, 1, fp) != 1 ||
            fwrite(g_cidr_str, 1, cidr_len, fp) != cidr_len) {
        LOGERR("[fakedns_save] failed to write CIDR to %s", tmp_path);
        pthread_rwlock_unlock(&g_fakedns_rwlock);
        fclose(fp);
        unlink(tmp_path);
        return;
    }

    // Write Entries
    bool success = true;
    for (uint32_t i = 0; i < g_pool_size; ++i) {
        fakedns_entry_t *entry = g_fakedns_pool[i];
        if (entry) {
            uint16_t dlen = strlen(entry->domain);
            if (fwrite(&entry->ip, 4, 1, fp) != 1 ||
                    fwrite(&dlen, 2, 1, fp) != 1 ||
                    fwrite(entry->domain, 1, dlen, fp) != dlen) {
                LOGERR("[fakedns_save] failed to write entry to %s", tmp_path);
                success = false;
                break;
            }
        }
    }

    pthread_rwlock_unlock(&g_fakedns_rwlock);

    // Ensure data is flushed to disk
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        LOGERR("[fakedns_save] failed to flush/sync %s: %s", tmp_path, strerror(errno));
        success = false;
    }

    fclose(fp);

    if (success) {
        if (rename(tmp_path, path) != 0) {
            LOGERR("[fakedns_save] failed to rename %s to %s: %s", tmp_path, path, strerror(errno));
            unlink(tmp_path);
        } else {
            LOG_ALWAYS_INF("[fakedns_save] saved %u entries to %s", count, path);
        }
    } else {
        unlink(tmp_path);
    }
}

void fakedns_load(const char *path) {
    if (!path) return;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        if (errno != ENOENT) {
            LOGERR("[fakedns_load] failed to open %s: %s", path, strerror(errno));
        }
        return;
    }

    uint32_t magic, version, count;
    if (fread(&magic, 4, 1, fp) != 1 || fread(&version, 4, 1, fp) != 1 || fread(&count, 4, 1, fp) != 1) {
        LOGERR("[fakedns_load] header read error");
        fclose(fp);
        return;
    }

    if (magic != FAKEDNS_MAGIC) {
        LOGERR("[fakedns_load] invalid magic: %08x", magic);
        fclose(fp);
        return;
    }
    if (version != FAKEDNS_VERSION) {
        LOGERR("[fakedns_load] version mismatch: file %u, current %u", version, FAKEDNS_VERSION);
        fclose(fp);
        return;
    }

    // Version 3: Check CIDR
    uint16_t cidr_len;
    if (fread(&cidr_len, 2, 1, fp) != 1) {
        LOGERR("[fakedns_load] cidr len read error");
        fclose(fp);
        return;
    }
    if (cidr_len >= 64) {
        LOGERR("[fakedns_load] cidr len too long: %u", cidr_len);
        fclose(fp);
        return;
    }
    char file_cidr[64];
    if (fread(file_cidr, 1, cidr_len, fp) != cidr_len) {
        LOGERR("[fakedns_load] cidr read error");
        fclose(fp);
        return;
    }
    file_cidr[cidr_len] = '\0';

    if (strcmp(file_cidr, g_cidr_str) != 0) {
        LOGERR("[fakedns_load] CIDR mismatch. File: %s, Current: %s. Ignoring saved data.", file_cidr, g_cidr_str);
        fclose(fp);
        return;
    }

    pthread_rwlock_wrlock(&g_fakedns_rwlock);  // Use write lock for loading

    uint32_t now = (uint32_t)time(NULL);
    uint32_t loaded = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t ip;
        uint16_t dlen;

        // Version 3: No expire read
        if (fread(&ip, 4, 1, fp) != 1 || fread(&dlen, 2, 1, fp) != 1) {
            LOGERR("[fakedns_load] entry read error at %u", i);
            break;
        }

        // Validate IP in range
        // g_fakeip_net_host is host byte order, ip is network byte order
        uint32_t ip_host = ntohl(ip);
        uint32_t offset = ip_host - g_fakeip_net_host;
        if ((ip_host & g_fakeip_mask_host) != g_fakeip_net_host || offset >= g_pool_size) {
            if (fseek(fp, dlen, SEEK_CUR) != 0) {
                LOGERR("[fakedns_load] fseek failed for IP mismatch at %u", i);
                break;
            }
            // Even if CIDR matches string-wise, let's be double safe
            continue;
        }

        if (dlen >= FAKEDNS_MAX_DOMAIN_LEN) {
            LOGERR("[fakedns_load] domain too long: %u", dlen);
            if (fseek(fp, dlen, SEEK_CUR) != 0) {
                LOGERR("[fakedns_load] fseek failed for long domain at %u", i);
                break;
            }
            continue;
        }

        char domain[FAKEDNS_MAX_DOMAIN_LEN];
        if (fread(domain, 1, dlen, fp) != dlen) {
            LOGERR("[fakedns_load] domain read error at %u", i);
            break;
        }
        domain[dlen] = '\0';

        // Refresh TTL on load
        uint32_t expire = now + FAKEDNS_TTL;

        // Add to array
        fakedns_entry_t *entry = g_fakedns_pool[offset];
        if (!entry) {
            if (posix_memalign((void **)&entry, 64, sizeof(fakedns_entry_t)) != 0) {
                entry = NULL;
            }
            if (!entry) {
                LOGERR("[fakedns_load] malloc failed for domain: %s", domain);
                continue;
            }
            entry->ip = ip;
            memcpy(entry->domain, domain, dlen + 1);
            entry->expire = expire;
            entry->version = 1; // Base version on load
            g_fakedns_pool[offset] = entry;
            g_pool_used++;
            loaded++;
        } else {
            memcpy(entry->domain, domain, dlen + 1);
            entry->expire = expire;
        }
    }

    pthread_rwlock_unlock(&g_fakedns_rwlock);
    fclose(fp);
    LOG_ALWAYS_INF("[fakedns_load] loaded %u/%u entries from %s", loaded, count, path);
}
