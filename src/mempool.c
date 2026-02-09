#define _GNU_SOURCE
#include "mempool.h"
#include "logutils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * Memory Pool Implementation with Doubly Linked List Tracking
 * 
 * Design:
 * - Each allocated block has a 64-byte header for cache line alignment
 * - All blocks (pool + bypass) are tracked in a doubly linked list
 * - Pool blocks use an additional free_list for O(1) recycling
 * - On destroy, all blocks are freed via the tracking list
 * ============================================================================ */

#define MEMPOOL_MAGIC_POOL   0xDEADBEEF
#define MEMPOOL_MAGIC_MALLOC 0xCAFEBABE
#define MEMPOOL_MAGIC_FREE   0x00000000
#define CACHELINE_SIZE       64
#define EXPAND_BATCH_SIZE    32

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
/* 64-byte block header for cache line alignment */
#define BLOCK_HEADER_FIXED_SIZE (sizeof(uint32_t) * 2 + sizeof(void *) * 3)
#define BLOCK_HEADER_PADDING    (CACHELINE_SIZE - BLOCK_HEADER_FIXED_SIZE)

typedef struct block_header {
    uint32_t magic;              /* Magic number for validation */
    uint32_t data_size;          /* Actual data size for this block */
    struct block_header *prev;   /* Doubly linked list: prev */
    struct block_header *next;   /* Doubly linked list: next */
    struct block_header *next_free; /* Free list pointer (pool blocks only) */
    char padding[BLOCK_HEADER_PADDING]; /* Pad to 64 bytes */
} block_header_t;

_Static_assert(sizeof(block_header_t) == CACHELINE_SIZE, 
               "block_header_t must be 64 bytes");

/* Memory pool structure */
struct memory_pool {
    block_header_t *all_blocks;  /* Doubly linked list of ALL allocated blocks */
    block_header_t *free_list;   /* Singly linked list of free pool blocks */
    size_t block_size;           /* User data size per block */
    size_t total_size;           /* Total size including header (aligned) */
    size_t pool_blocks;          /* Number of pool blocks allocated */
    size_t max_blocks;           /* Maximum pool blocks allowed */
    size_t free_count;           /* Number of blocks in free_list */
    /* Statistics */
    size_t pool_allocs;          /* Allocations from pool */
    size_t pool_frees;           /* Frees to pool */
    size_t bypass_allocs;        /* Bypass allocations */
    size_t bypass_frees;         /* Bypass frees */
};

/* ----------------------------------------------------------------------------
 * Internal: Doubly Linked List Operations
 * ---------------------------------------------------------------------------- */

static inline void dll_insert(block_header_t **head, block_header_t *node) {
    node->prev = NULL;
    node->next = *head;
    if (*head) (*head)->prev = node;
    *head = node;
}

static inline void dll_remove(block_header_t **head, block_header_t *node) {
    if (node->prev) node->prev->next = node->next;
    else *head = node->next;
    if (node->next) node->next->prev = node->prev;
    node->prev = node->next = NULL;
}

/* Convert block header to user data pointer */
static inline void* block_to_data(block_header_t *header) {
    return (char *)header + sizeof(block_header_t);
}

/* ----------------------------------------------------------------------------
 * Internal: Allocate Physical Block
 * ---------------------------------------------------------------------------- */

static block_header_t* alloc_physical_block(memory_pool_t *pool, size_t size, int for_bypass) {
    size_t total = sizeof(block_header_t) + size;
    
    void *raw = NULL;
    if (posix_memalign(&raw, CACHELINE_SIZE, total) != 0) {
        LOGERR("[mempool] posix_memalign failed for size=%zu", total);
        return NULL;
    }
    
    block_header_t *header = (block_header_t *)raw;
    /* Only set magic for bypass blocks; pool blocks will be set by caller */
    header->magic = for_bypass ? MEMPOOL_MAGIC_MALLOC : MEMPOOL_MAGIC_FREE;
    header->data_size = for_bypass ? (uint32_t)size : (uint32_t)pool->block_size;
    header->next_free = NULL;
    
    /* Insert into all_blocks tracking list */
    dll_insert(&pool->all_blocks, header);
    
    return header;
}

/* ----------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------- */

memory_pool_t* mempool_create(size_t block_size, size_t initial_blocks, size_t max_blocks) {
    memory_pool_t *pool = calloc(1, sizeof(memory_pool_t));
    if (!pool) {
        LOGERR("[mempool] failed to allocate pool structure");
        return NULL;
    }
    
    pool->block_size = block_size;
    /* Align total size to cache line */
    pool->total_size = (block_size + CACHELINE_SIZE - 1) & ~(CACHELINE_SIZE - 1);
    pool->max_blocks = (max_blocks == 0) ? SIZE_MAX : max_blocks;
    
    /* Pre-allocate initial blocks */
    for (size_t i = 0; i < initial_blocks && pool->pool_blocks < pool->max_blocks; i++) {
        block_header_t *header = alloc_physical_block(pool, pool->total_size, 0);
        if (!header) break;
        
        /* Add to free list */
        header->next_free = pool->free_list;
        pool->free_list = header;
        pool->pool_blocks++;
        pool->free_count++;
    }
    
    LOG_ALWAYS_INF("[mempool] created: block_size=%zu, initial=%zu, max=%zu, memory=%zu KB",
           pool->total_size, pool->pool_blocks, pool->max_blocks,
           pool->pool_blocks * (sizeof(block_header_t) + pool->total_size) / 1024);
    
    return pool;
}

void* mempool_alloc_sized(memory_pool_t *pool, size_t size) {
    if (!pool) return NULL;
    
    /* Case A: Large object bypass */
    if (size > pool->block_size) {
        block_header_t *header = alloc_physical_block(pool, size, 1);
        if (!header) {
            LOGERR("[mempool] bypass allocation failed for size=%zu", size);
            return NULL;
        }
        pool->bypass_allocs++;
        return block_to_data(header);
    }
    
    /* Case B: Pool exhausted, try batch expansion */
    if (!pool->free_list && pool->pool_blocks < pool->max_blocks) {
        size_t remaining = pool->max_blocks - pool->pool_blocks;
        size_t expand_target = MIN(EXPAND_BATCH_SIZE, remaining);
        size_t added = 0;
        
        for (size_t i = 0; i < expand_target; i++) {
            block_header_t *header = alloc_physical_block(pool, pool->total_size, 0);
            if (!header) break;
            
            header->next_free = pool->free_list;
            pool->free_list = header;
            pool->pool_blocks++;
            pool->free_count++;
            added++;
        }
        
        if (added > 0) {
            LOGINF("[mempool] batch expanded: +%zu blocks (total: %zu/%zu)",
                   added, pool->pool_blocks, pool->max_blocks);
        }
    }
    
    /* Case C: Allocate from free list */
    if (pool->free_list) {
        block_header_t *header = pool->free_list;
        pool->free_list = header->next_free;
        
        /* Activate block: set magic to POOL, clear internal pointer */
        header->magic = MEMPOOL_MAGIC_POOL;
        header->next_free = NULL;
        
        pool->free_count--;
        pool->pool_allocs++;
        return block_to_data(header);
    }
    
    /* Pool exhausted */
    static int warn_counter = 0;
    if (warn_counter++ % 1000 == 0) {
        LOGWAR("[mempool] pool exhausted (%zu/%zu)", pool->pool_blocks, pool->max_blocks);
    }
    return NULL;
}

void* mempool_calloc_sized(memory_pool_t *pool, size_t size) {
    void *ptr = mempool_alloc_sized(pool, size);
    if (ptr) {
        /* Get header to retrieve correct data_size for zeroing */
        block_header_t *header = (block_header_t *)((char *)ptr - sizeof(block_header_t));
        memset(ptr, 0, header->data_size);
    }
    return ptr;
}

void mempool_free_sized(memory_pool_t *pool, void *ptr, size_t size) {
    (void)size;  /* Size kept for API compatibility */
    if (!pool || !ptr) return;
    
    block_header_t *header = (block_header_t *)((char *)ptr - sizeof(block_header_t));
    
    /* Validate magic */
    if (header->magic == MEMPOOL_MAGIC_FREE) {
        LOGERR("[mempool] double free detected! ptr=%p", ptr);
        return;
    }
    
    if (header->magic == MEMPOOL_MAGIC_MALLOC) {
        /* Bypass block: remove from tracking list and free */
        header->magic = MEMPOOL_MAGIC_FREE;
        dll_remove(&pool->all_blocks, header);
        pool->bypass_frees++;
        free(header);
        return;
    }
    
    if (header->magic == MEMPOOL_MAGIC_POOL) {
        /* Pool block: return to free list (keep in all_blocks) */
        header->magic = MEMPOOL_MAGIC_FREE;  /* Mark as free for double-free detection */
        header->next_free = pool->free_list;
        pool->free_list = header;
        pool->free_count++;
        pool->pool_frees++;
        return;
    }
    
    LOGERR("[mempool] invalid magic=0x%08X, ptr=%p (corruption?)", header->magic, ptr);
}

size_t mempool_destroy(memory_pool_t *pool) {
    if (!pool) return 0;
    
    /* Calculate leaks */
    size_t pool_leaks = pool->pool_allocs - pool->pool_frees;
    size_t bypass_leaks = pool->bypass_allocs - pool->bypass_frees;
    size_t total_leaks = pool_leaks + bypass_leaks;
    
    LOG_ALWAYS_INF("[mempool] destroy: pool_blocks=%zu, free=%zu, "
           "pool_alloc=%zu, pool_free=%zu, bypass_alloc=%zu, bypass_free=%zu, leaks=%zu",
           pool->pool_blocks, pool->free_count,
           pool->pool_allocs, pool->pool_frees,
           pool->bypass_allocs, pool->bypass_frees, total_leaks);
    
    if (total_leaks > 0) {
        LOGWAR("[mempool] detected leaks: pool=%zu, bypass=%zu", pool_leaks, bypass_leaks);
    }
    
    /* Free ALL blocks via tracking list */
    size_t freed = 0;
    block_header_t *curr = pool->all_blocks;
    while (curr) {
        block_header_t *next = curr->next;
        free(curr);
        freed++;
        curr = next;
    }
    
    /* Expected = pool blocks + unreleased bypass blocks */
    size_t expected = pool->pool_blocks + bypass_leaks;
    if (freed != expected) {
        LOGWAR("[mempool] freed %zu blocks but expected %zu", freed, expected);
    }
    
    free(pool);
    return total_leaks;
}

void mempool_get_stats(memory_pool_t *pool, size_t *total_blocks, 
                       size_t *free_blocks, size_t *alloc_count, 
                       size_t *free_count) {
    if (!pool) return;
    if (total_blocks) *total_blocks = pool->pool_blocks;
    if (free_blocks) *free_blocks = pool->free_count;
    if (alloc_count) *alloc_count = pool->pool_allocs;
    if (free_count) *free_count = pool->pool_frees;
}
