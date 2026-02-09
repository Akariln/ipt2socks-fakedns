#ifndef IPT2SOCKS_MEMPOOL_H
#define IPT2SOCKS_MEMPOOL_H

#include <stddef.h>
#include <stdbool.h>

/* Memory pool for UDP packet nodes */

typedef struct memory_pool memory_pool_t;

/**
 * Create a memory pool with fixed block size
 * 
 * THREAD-SAFETY: NOT thread-safe. Use __thread pools in multi-threaded code.
 * 
 * @param block_size Size of each block in bytes
 * @param initial_blocks Number of blocks to pre-allocate
 * @param max_blocks Maximum blocks allowed (0 = unlimited)
 * @return Pointer to created pool, or NULL on failure
 */
memory_pool_t* mempool_create(size_t block_size, size_t initial_blocks, size_t max_blocks);

/**
 * Allocate memory from pool with size awareness
 * - If size <= block_size: allocate from pool (fast path)
 * - If size > block_size: fallback to malloc (bypass)
 * @param pool Memory pool
 * @param size Requested size in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void* mempool_alloc_sized(memory_pool_t *pool, size_t size);

/**
 * Allocate zeroed memory from pool (like calloc)
 * Same as mempool_alloc_sized, but memory is zeroed before return
 * @param pool Memory pool
 * @param size Requested size in bytes
 * @return Pointer to zeroed memory, or NULL on failure
 */
void* mempool_calloc_sized(memory_pool_t *pool, size_t size);

/**
 * Free memory back to pool
 * @param pool Memory pool
 * @param block Pointer to memory block
 * @param size Original allocation size (kept for API compatibility, not used)
 */
void mempool_free_sized(memory_pool_t *pool, void *block, size_t size);

/**
 * Destroy memory pool and free all resources
 * @param pool Memory pool to destroy
 * @return Number of leaked allocations (pool + bypass)
 */
size_t mempool_destroy(memory_pool_t *pool);

/**
 * Get pool statistics (for monitoring)
 * @param pool Memory pool
 * @param total_blocks Output: total blocks in pool
 * @param free_blocks Output: available blocks
 * @param alloc_count Output: total allocations
 * @param free_count Output: total frees
 */
void mempool_get_stats(memory_pool_t *pool, size_t *total_blocks, 
                       size_t *free_blocks, size_t *alloc_count, 
                       size_t *free_count);

#endif /* IPT2SOCKS_MEMPOOL_H */
