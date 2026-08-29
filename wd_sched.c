// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2026 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 *
 * Scheduler: Simplified Pure Hash Table with Dynamic Context Expansion
 *
 * Key improvements:
 * - Single global hash table with (region_id, mode, op_type, prop) dimensions
 * - Segment list for non-contiguous ctx ranges
 * - Dual-domain queues for session key.
 * - Dynamic ctx expansion in HUNGRY mode based on load threshold
 * - Packet reception is handled through the active queues in the session key.
 * - Simplified sched_init: only allocate one sync + one async ctx
 * - Removed redundant wd_sched_info layer
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sched.h>
#include <numa.h>
#include <limits.h>
#include <pthread.h>
#include "wd_sched.h"
#include "wd_alg.h"
#include "wd_internal.h"

#define MAX_POLL_TIMES			1000
#define SKEY_CTX_MAX_NUM		16
#define SKEY_MAX_THREAD_NUM		64
#define SKEY_LOAD_UPDATE_INTERVAL 1
#define HW_QUEUE_FULL_DEPTH		1024

/* ============================================================================
 * Hash Table Configuration
 * ============================================================================
 */
#define WD_SCHED_MAX_BUCKETS		512
#define WD_SCHED_MIN_BUCKETS		32
#define HASH_PRIME1			73
#define HASH_PRIME2			13
#define HASH_PRIME3			7
#define HASH_PRIME4			11

/* ============================================================================
 * Scheduling Region Mode
 * ============================================================================
 */
enum sched_region_mode {
	SCHED_MODE_SYNC = 0,
	SCHED_MODE_ASYNC = 1,
	SCHED_MODE_BUTT
};

/* ============================================================================
 * Segment List for Domain Index Organization
 * ============================================================================
 */

/**
 * wd_sched_ctx_segment - Contiguous segment of ctx indices in domain
 * @begin: Start index of this segment
 * @end: End index of this segment (inclusive)
 * @next: Pointer to next segment in the linked list
 *
 * Supports non-contiguous ctx ranges via segment list.
 */
struct wd_sched_ctx_segment {
	__u32 begin;
	__u32 end;
	struct wd_sched_ctx_segment *next;
};

/* ============================================================================
 * Session key domain cache processing.
 * ============================================================================
 */

/**
 * wd_sched_domain_idx_cache - Simplified fixed array cache for skey domains
 *
 * Design principles:
 * - Fixed array for cache-friendly memory layout
 * - Atomic operations for lock-free load tracking
 * - Simple RR and load balancing strategies
 * - Maximum 16 queues per thread (typical usage)
 */
struct wd_sched_domain_idx_cache {
	/* Queue index array */
	__u32 idx_list[SKEY_CTX_MAX_NUM];	    /* Array of ctx indices */
	__u32 load_values[SKEY_CTX_MAX_NUM];	    /* Atomic load counters */
	__u32 valid_count;			    /* Number of valid queues */

	/* Scheduling state */
	__u32 rr_ptr;				    /* Round-robin pointer */
	__u32 min_load_idx;			    /* Cached min load index */
	__u32 op_counter;			    /* Operation counter for updates */
	__u8 load_decreased;			    /* Non-zero if poll ever decremented load */

	/* Configuration */
	__u32 update_interval;		    /* Min load update interval */
	__u8 policy;				/* Scheduling policy */

	/* Synchronization */
	pthread_mutex_t cache_lock;		    /* Lock for structure modifications */
};

/**
 * wd_sched_ctx_domain - Scheduling domain with four dimensions
 * @region_id: Region identifier (numa_id or device_id)
 * @mode: Context mode (SYNC/ASYNC)
 * @op_type: Operation type
 * @prop: Property (e.g., device type: HW, CE, SOFT)
 * @segments: Linked list of context ranges
 * @segment_count: Number of segments
 * @total_ctx_count: Total contexts across all segments
 * @current_segment: Current segment pointer for round-robin
 * @current_pos: Current position within segment
 * @valid: Domain validity flag
 * @lock: Synchronization spinlock
 */
struct wd_sched_ctx_domain {
	int region_id;
	__u8 mode;
	__u32 op_type;
	__u8 prop;

	struct wd_sched_ctx_segment *segments;
	__u32 segment_count;
	__u32 total_ctx_count;

	struct wd_sched_ctx_segment *current_segment;
	__u32 current_pos;
	bool valid;

	pthread_mutex_t lock;
};

/**
 * wd_sched_domain_hash_node - Hash table collision chain node
 */
struct wd_sched_domain_hash_node {
	struct wd_sched_ctx_domain domain;
	struct wd_sched_domain_hash_node *next;
};

/**
 * wd_sched_domain_hash_table - Pure dynamic hash table for scheduling domains
 * @buckets: Hash table bucket array
 * @bucket_size: Number of buckets
 * @lock: Read-write lock for concurrent access
 */
struct wd_sched_domain_hash_table {
	struct wd_sched_domain_hash_node **buckets;
	__u32 bucket_size;
	pthread_mutex_t lock;
};

/* ============================================================================
 * Dual-Domain Structure for Session Key
 * ============================================================================
 */

/**
 * wd_sched_key_domain - Session domain with min-heap
 * @idx_cache: Index cache with min-heap for load-based selection
 * @lock: Synchronization spinlock
 * @expanded_count: Track how many times ctx has been expanded
 */
struct wd_sched_key_domain {
	struct wd_sched_domain_idx_cache idx_cache;
	pthread_mutex_t lock;
	__u32 expanded_count;
};

/**
 * wd_sched_key - Session-level scheduling key
 * @region_id: Region identifier
 * @type: Operation type
 * @mode: Current mode (SYNC/ASYNC)
 * @dev_id: Device identifier (for SCHED_POLICY_DEV)
 * @ctx_prop: Context property
 * @is_stream: Stream mode flag
 * @prio_mode: Priority mode
 * @pkt_size: Current packet size
 * @sync_domain: Min-heap domain for sync contexts
 * @async_domain: Min-heap domain for async contexts
 * @lock: Synchronization spinlock
 */
struct wd_sched_key {
	int region_id;
	__u8 type;
	__u8 mode;
	__u32 dev_id;
	__u8 ctx_prop;
	__u16 is_stream;
	__u16 prio_mode;
	__u32 pkt_size;

	struct wd_sched_key_domain sync_domain;
	struct wd_sched_key_domain async_domain;

	pthread_mutex_t lock;
	__u32 poll_lock;
	__u32 refcount;

	/* Compat filtering parameters for session-ctx matching */
	const char *alg_name;
	struct wd_ctx_internal *ctxs;
};

/**
 * wd_sched_ctx - Main scheduler context
 * @policy: Scheduling policy type
 * @type_num: Number of operation types
 * @mode_num: Number of modes (SYNC/ASYNC)
 * @region_num: Number of regions (numa or devices)
 * @poll_func: Poll function for receiving responses
 * @domain_hash_table: Global hash table for all domains
 * @skey_num: Number of active session keys
 * @skey_lock: Lock for skey array
 * @skey: Array of session keys
 */
struct wd_sched_ctx {
	__u32 policy;
	__u32 type_num;
	__u32 mode_num;
	__u16 region_num;

	user_poll_func poll_func;
	struct wd_sched_domain_hash_table *domain_hash_table;

	__u32 skey_num;
	pthread_mutex_t skey_lock;
	struct wd_sched_key *skey[SKEY_MAX_THREAD_NUM];

	/* First ctx index per mode, used by SINGLE/NONE. */
	__u32 sync_idx;
	__u32 async_idx;
};

/* ============================================================================
 * Hash Table Core Operations
 * ============================================================================
 */

static bool wd_sched_is_prime(__u32 n)
{
	__u32 i;

	if (n <= 1)
		return false;
	if (n <= 3)
		return true;
	if (n % 2 == 0 || n % 3 == 0)
		return false;

	for (i = 5; i * i <= n; i += 6) {
		if (n % i == 0 || n % (i + 2) == 0)
			return false;
	}

	return true;
}

static __u32 wd_sched_find_prime(__u32 n)
{
	while (!wd_sched_is_prime(n))
		n++;
	return n;
}

static __u32 wd_sched_compute_bucket_size(__u32 estimated_entries)
{
	__u32 target_size;

	target_size = (estimated_entries * 4) / 3;

	if (target_size < WD_SCHED_MIN_BUCKETS)
		target_size = WD_SCHED_MIN_BUCKETS;
	if (target_size > WD_SCHED_MAX_BUCKETS)
		target_size = WD_SCHED_MAX_BUCKETS;

	return wd_sched_find_prime(target_size);
}

/**
 * wd_sched_hash_compute - Compute hash value for four-dimensional domain key
 * @region_id: Region identifier
 * @mode: Context mode
 * @op_type: Operation type
 * @prop: Property
 * @bucket_size: Hash table bucket count
 *
 * Combines four dimensions using prime number multipliers.
 */
static inline __u32 wd_sched_hash_compute(int region_id, __u8 mode,
					   __u32 op_type, __u8 prop, __u32 bucket_size)
{
	__u32 hash;

	hash = (region_id * HASH_PRIME1) + (mode * HASH_PRIME2) +
	       (op_type * HASH_PRIME3) + (prop * HASH_PRIME4);
	return hash % bucket_size;
}

static inline bool wd_sched_domain_key_match(
	int region_id1, __u8 mode1, __u32 op_type1, __u8 prop1,
	int region_id2, __u8 mode2, __u32 op_type2, __u8 prop2)
{
	return (region_id1 == region_id2 && mode1 == mode2 &&
		op_type1 == op_type2 && prop1 == prop2);
}

/**
 * wd_sched_hash_table_create - Create hash table
 * @estimated_entries: Estimated number of entries
 *
 * Returns: Initialized hash table or NULL on error
 */
static struct wd_sched_domain_hash_table *
wd_sched_hash_table_create(__u32 estimated_entries)
{
	struct wd_sched_domain_hash_table *table;
	__u32 bucket_size;
	int ret;

	table = calloc(1, sizeof(*table));
	if (!table)
		return NULL;

	bucket_size = wd_sched_compute_bucket_size(estimated_entries);

	table->buckets = calloc(bucket_size, sizeof(*table->buckets));
	if (!table->buckets) {
		free(table);
		return NULL;
	}

	table->bucket_size = bucket_size;
	ret = pthread_mutex_init(&table->lock, NULL);
	if (ret) {
		free(table->buckets);
		free(table);
		return NULL;
	}

	return table;
}

static void wd_sched_hash_table_destroy(struct wd_sched_domain_hash_table *table)
{
	struct wd_sched_domain_hash_node *node, *next;
	struct wd_sched_ctx_segment *seg, *next_seg;
	__u32 i;

	if (!table)
		return;

	for (i = 0; i < table->bucket_size; i++) {
		node = table->buckets[i];
		while (node) {
			next = node->next;

			/* Release segment linked list */
			seg = node->domain.segments;
			while (seg) {
				next_seg = seg->next;
				free(seg);
				seg = next_seg;
			}

			pthread_mutex_destroy(&node->domain.lock);
			free(node);
			node = next;
		}
	}

	pthread_mutex_destroy(&table->lock);
	free(table->buckets);
	free(table);
}

static struct wd_sched_ctx_domain *
wd_sched_hash_table_lookup(struct wd_sched_domain_hash_table *table,
			   int region_id, __u8 mode, __u32 op_type, __u8 prop)
{
	struct wd_sched_domain_hash_node *node;
	struct wd_sched_ctx_domain *domain = NULL;
	__u32 hash_idx;

	if (!table)
		return NULL;

	pthread_mutex_lock(&table->lock);
	hash_idx = wd_sched_hash_compute(region_id, mode, op_type, prop, table->bucket_size);
	node = table->buckets[hash_idx];
	while (node) {
		if (wd_sched_domain_key_match(
			node->domain.region_id, node->domain.mode, node->domain.op_type,
			node->domain.prop,	region_id, mode, op_type, prop)) {
			domain = &node->domain;
			break;
		}
		node = node->next;
	}
	pthread_mutex_unlock(&table->lock);

	return domain;
}

static struct wd_sched_ctx_domain *
wd_sched_hash_table_insert(struct wd_sched_domain_hash_table *table,
			   int region_id, __u8 mode, __u32 op_type, __u8 prop)
{
	struct wd_sched_domain_hash_node *new_node;
	struct wd_sched_ctx_domain *existing;
	__u32 hash_idx;
	int ret;

	if (!table)
		return NULL;

	existing = wd_sched_hash_table_lookup(table, region_id, mode, op_type, prop);
	if (existing)
		return existing;

	pthread_mutex_lock(&table->lock);
	hash_idx = wd_sched_hash_compute(region_id, mode, op_type, prop, table->bucket_size);
	/* Alloc and initialize new domain */
	new_node = calloc(1, sizeof(*new_node));
	if (!new_node) {
		pthread_mutex_unlock(&table->lock);
		return NULL;
	}

	/* Initialize new domain */
	new_node->domain.region_id = region_id;
	new_node->domain.mode = mode;
	new_node->domain.op_type = op_type;
	new_node->domain.prop = prop;
	new_node->domain.segments = NULL;
	new_node->domain.segment_count = 0;
	new_node->domain.total_ctx_count = 0;
	new_node->domain.current_segment = NULL;
	new_node->domain.current_pos = 0;
	new_node->domain.valid = false;

	ret = pthread_mutex_init(&new_node->domain.lock, NULL);
	if (ret) {
		pthread_mutex_unlock(&table->lock);
		free(new_node);
		return NULL;
	}

	new_node->next = table->buckets[hash_idx];
	table->buckets[hash_idx] = new_node;
	pthread_mutex_unlock(&table->lock);

	return &new_node->domain;
}

/* ============================================================================
 * Segment List Operations
 * ============================================================================
 */

/**
 * wd_sched_domain_add_segment - Add context range segment to domain
 * @domain: Target domain
 * @begin: Start context index
 * @end: End context index (inclusive)
 *
 * Supports non-contiguous context ranges via segment list.
 */
static int wd_sched_domain_add_segment(struct wd_sched_ctx_domain *domain,
				       __u32 begin, __u32 end)
{
	struct wd_sched_ctx_segment *seg, *new_seg;

	if (!domain || begin > end)
		return -WD_EINVAL;

	new_seg = calloc(1, sizeof(*new_seg));
	if (!new_seg)
		return -WD_ENOMEM;

	new_seg->begin = begin;
	new_seg->end = end;
	new_seg->next = NULL;

	pthread_mutex_lock(&domain->lock);

	/* Append to segment list tail */
	if (!domain->segments) {
		domain->segments = new_seg;
	} else {
		seg = domain->segments;
		while (seg->next)
			seg = seg->next;
		seg->next = new_seg;
	}

	domain->segment_count++;
	domain->total_ctx_count += (end - begin + 1);

	/* Initialize polling state */
	if (!domain->current_segment)
		domain->current_segment = domain->segments;

	pthread_mutex_unlock(&domain->lock);

	return WD_SUCCESS;
}

/**
 * wd_sched_domain_get_next_rr - Get next context via round-robin from domain
 * @domain: Source domain
 *
 * Returns: Next global queue index in round-robin order
 * Time complexity: O(1)
 */
static __u32 wd_sched_domain_get_next_rr(struct wd_sched_ctx_domain *domain)
{
	__u32 ctx_idx;
	__u32 pos;

	if (!domain || !domain->segments || !domain->total_ctx_count)
		return INVALID_POS;

	pthread_mutex_lock(&domain->lock);
	if (!domain->current_segment)
		domain->current_segment = domain->segments;

	pos = domain->current_pos;

	/* Calculate global queue number: segment.begin + relative position */
	ctx_idx = domain->current_segment->begin + pos;

	/* Move to next position */
	if (pos + 1 < domain->current_segment->end - domain->current_segment->begin + 1) {
		/* Within same segment */
		domain->current_pos = pos + 1;
	} else if (domain->current_segment->next) {
		/* Move to next segment */
		domain->current_segment = domain->current_segment->next;
		domain->current_pos = 0;
	} else {
		/* Loop back to beginning */
		domain->current_segment = domain->segments;
		domain->current_pos = 0;
	}

	pthread_mutex_unlock(&domain->lock);

	return ctx_idx;
}

/* ============================================================================
 * SKey Domain Cache Management Functions
 * ============================================================================
 */
/**
 * wd_sched_skey_cache_init - Initialize skey domain cache
 * @cache: Pointer to cache structure
 * @policy: Scheduling policy * @sched_type: Scheduling policy type (cannot modify per
 *          API contract)
 *
 * Initialize fixed array cache with invalid positions and zero loads.
 */
static int wd_sched_skey_cache_init(struct wd_sched_domain_idx_cache *cache,
		__u8 policy)
{
	int i;

	if (!cache) {
		WD_ERR("invalid: cache pointer is NULL!\n");
		return -WD_EINVAL;
	}

	/* Initialize array with invalid positions */
	for (i = 0; i < SKEY_CTX_MAX_NUM; i++) {
		cache->idx_list[i] = INVALID_POS;
		__atomic_store_n(&cache->load_values[i], 0, __ATOMIC_RELAXED);
	}

	/* Initialize atomic counters */
	__atomic_store_n(&cache->rr_ptr, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&cache->min_load_idx, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&cache->op_counter, 0, __ATOMIC_RELAXED);
	cache->load_decreased = 0;

	/* Set configuration */
	cache->valid_count = 0;
	cache->update_interval = SKEY_LOAD_UPDATE_INTERVAL;
	cache->policy = policy;

	/* Initialize structure lock */
	if (pthread_mutex_init(&cache->cache_lock, NULL)) {
		WD_ERR("failed to init cache lock!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}
/**
 * wd_sched_skey_cache_uninit - Cleanup skey domain cache
 * @cache: Pointer to cache structure
 *
 * Release resources and reset cache state.
 */
static void wd_sched_skey_cache_uninit(struct wd_sched_domain_idx_cache *cache)
{
	if (!cache)
		return;

	pthread_mutex_destroy(&cache->cache_lock);

	/* Reset cache state */
	for (int i = 0; i < SKEY_CTX_MAX_NUM; i++) {
		cache->idx_list[i] = INVALID_POS;
		__atomic_store_n(&cache->load_values[i], 0, __ATOMIC_RELAXED);
	}

	cache->valid_count = 0;
	cache->load_decreased = 0;
}
/**
 * wd_sched_skey_add_ctx - Add ctx to skey domain cache
 * @cache: Pointer to cache structure
 * @ctx_id: Context ID to add
 *
 * Add ctx to next available position in fixed array.
 * Returns 0 on success, negative error code on failure.
 */
static int wd_sched_skey_add_ctx(struct wd_sched_domain_idx_cache *cache,
		__u32 ctx_id)
{
	__u32 i;

	if (!cache || ctx_id == INVALID_POS) {
		WD_ERR("invalid: parameters are NULL!\n");
		return -WD_EINVAL;
	}

	pthread_mutex_lock(&cache->cache_lock);
	/* Check if cache is full */
	if (cache->valid_count >= SKEY_CTX_MAX_NUM) {
		pthread_mutex_unlock(&cache->cache_lock);
		WD_ERR("invalid: skey cache full, cannot add more queues!\n");
		return -WD_EINVAL;
	}

	/* Check for duplicate ctx_id */
	for (i = 0; i < cache->valid_count; i++) {
		if (cache->idx_list[i] == ctx_id) {
			WD_ERR("invalid: context %u already exists in skey cache at pos %u!\n",
			       ctx_id, i);
			pthread_mutex_unlock(&cache->cache_lock);
			return -WD_EEXIST;
		}
	}

	/* Update min load index if as the new ctx */
	__atomic_store_n(&cache->min_load_idx, cache->valid_count, __ATOMIC_RELAXED);

	/* Add to next available position */
	cache->idx_list[cache->valid_count] = ctx_id;
	__atomic_store_n(&cache->load_values[cache->valid_count], 0, __ATOMIC_RELAXED);
	cache->valid_count++;
	pthread_mutex_unlock(&cache->cache_lock);

	return WD_SUCCESS;
}

/**
 * wd_sched_skey_remove_ctx - Remove ctx from skey domain cache
 * @cache: Pointer to cache structure
 * @ctx_id: Context ID to remove
 *
 * Remove ctx by shifting array elements to maintain continuity.
 * Returns 0 on success, negative error code if not found.
 */
static int wd_sched_skey_remove_ctx(struct wd_sched_domain_idx_cache *cache,
				    __u32 ctx_id)
{
	__u32 i, current_min;
	int found = 0;

	if (!cache) {
		WD_ERR("invalid: cache pointer is NULL!\n");
		return -WD_EINVAL;
	}

	pthread_mutex_lock(&cache->cache_lock);
	/* Find and remove the ctx */
	for (i = 0; i < cache->valid_count; i++) {
		if (cache->idx_list[i] == ctx_id) {
			found = 1;
			break;
		}
	}

	if (!found) {
		WD_ERR("invalid: context %u not found in skey cache!\n", ctx_id);
		pthread_mutex_unlock(&cache->cache_lock);
		return -WD_ENODEV;
	}

	/* Shift remaining elements to fill the gap */
	for (; i < cache->valid_count - 1; i++) {
		cache->idx_list[i] = cache->idx_list[i + 1];
		__atomic_store_n(&cache->load_values[i],
			__atomic_load_n(&cache->load_values[i + 1], __ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
	}

	/* Clear last position */
	cache->idx_list[cache->valid_count - 1] = INVALID_POS;
	__atomic_store_n(&cache->load_values[cache->valid_count - 1], 0, __ATOMIC_RELAXED);
	cache->valid_count--;

	/* Reset pointers if cache becomes empty */
	if (!cache->valid_count) {
		__atomic_store_n(&cache->rr_ptr, 0, __ATOMIC_RELAXED);
		__atomic_store_n(&cache->min_load_idx, 0, __ATOMIC_RELAXED);
	} else {
		/* Adjust min load index if necessary */
		current_min = __atomic_load_n(&cache->min_load_idx, __ATOMIC_RELAXED);
		if (current_min >= cache->valid_count)
			__atomic_store_n(&cache->min_load_idx, 0, __ATOMIC_RELAXED);
	}
	pthread_mutex_unlock(&cache->cache_lock);

	return WD_SUCCESS;
}

/**
 * wd_sched_update_min_load - Update cached min load index
 * @cache: Pointer to cache structure
 * @ctxs: Context array for hw_load lookup, or NULL to use cache->load_values
 *
 * Scan valid queues to find the one with minimum load.
 * When ctxs is provided, reads per-ctx hw_load for cross-session accuracy.
 */
static void wd_sched_update_min_load(struct wd_sched_domain_idx_cache *cache,
				     struct wd_ctx_internal *ctxs)
{
	__u32 min_load = UINT_MAX;
	__u32 min_idx = 0;
	__u32 i, load;

	if (!cache->valid_count)
		return;

	for (i = 0; i < cache->valid_count; i++) {
		if (ctxs)
			load = __atomic_load_n(&ctxs[cache->idx_list[i]].hw_load,
					       __ATOMIC_RELAXED);
		else
			load = __atomic_load_n(&cache->load_values[i], __ATOMIC_RELAXED);
		if (load < min_load) {
			min_load = load;
			min_idx = i;
		}
	}

	__atomic_store_n(&cache->min_load_idx, min_idx, __ATOMIC_RELAXED);
}

/**
 * wd_sched_skey_pick_next - Pick next ctx from skey domain cache
 * @cache: Pointer to cache structure
 * @ctx_idx: Output index within cache array
 * @ctxs: Context array for hw_load lookup, or NULL
 *
 * Select next ctx based on scheduling policy:
 * - RR: Simple round-robin selection
 * - HUNGRY: Choose ctx with minimum load (hw_load if ctxs available)
 *
 * Returns selected ctx index, or INVALID_POS if no valid ctx.
 */
static __u32 wd_sched_skey_pick_next(struct wd_sched_domain_idx_cache *cache,
		__u32 *ctx_idx, struct wd_ctx_internal *ctxs)
{
	__u32 selected_idx;
	__u32 op_count;

	if (!cache || !cache->valid_count)
		return INVALID_POS;

	switch (cache->policy) {
	case SCHED_POLICY_RR:
	case SCHED_POLICY_NONE:
	case SCHED_POLICY_SINGLE:
	case SCHED_POLICY_DEV:
	case SCHED_POLICY_LOOP:
	case SCHED_POLICY_INSTR:
		/* Round-robin: atomic increment and module */
		selected_idx = __atomic_fetch_add(&cache->rr_ptr, 1, __ATOMIC_RELAXED) %
			       cache->valid_count;
		break;
	case SCHED_POLICY_HUNGRY:
		/* Update min load periodically */
		op_count = __atomic_fetch_add(&cache->op_counter, 1, __ATOMIC_RELAXED);
		if (op_count % cache->update_interval == 0)
			wd_sched_update_min_load(cache, ctxs);

		/* Load balancing: use cached min load index */
		selected_idx = __atomic_load_n(&cache->min_load_idx, __ATOMIC_RELAXED);
		break;
	default:
		WD_ERR("invalid: unknown scheduling policy %d!\n", cache->policy);
		selected_idx = INVALID_POS;
		break;
	}

	/* Ensure index is within valid range */
	if (selected_idx >= cache->valid_count)
		return INVALID_POS;

	*ctx_idx = selected_idx;
	return cache->idx_list[selected_idx];
}

/**
 * wd_sched_skey_update_load - Update load for a specific ctx
 * @cache: Pointer to cache structure
 * @ctx_idx: Context index in list
 * @delta: Load delta (positive for send, negative for receive)
 *
 * Atomically update load counter for the specified ctx.
 * Returns 0 on success, negative error code if ctx not found.
 */
static int wd_sched_skey_update_load(struct wd_sched_domain_idx_cache *cache,
				     __u32 ctx_idx, int delta)
{
	/* Atomic update without locking, ctx_idx's value is guaranteed by the caller. */
	if (delta > 0)
		__atomic_fetch_add(&cache->load_values[ctx_idx], delta, __ATOMIC_RELAXED);
	else {
		__atomic_fetch_sub(&cache->load_values[ctx_idx], -delta, __ATOMIC_RELAXED);
		if (unlikely(!cache->load_decreased))
			cache->load_decreased = 1;
	}
	return WD_SUCCESS;
}

/* ============================================================================
 * Session Key Domain Initialization
 * ============================================================================
 */

/**
 * wd_sched_skey_domain_init - Initialize session domain with min-heap
 * @key_domain: Target key domain
 * @ctx_idx: context indices idx
 * @policy: current session's policy
 *
 * Initializes dual-domain structure for session.
 */
static int wd_sched_skey_domain_init(struct wd_sched_key_domain *key_domain,
				     __u32 ctx_idx, __u8 policy)
{
	int ret;

	if (!key_domain)
		return -WD_EINVAL;

	ret = wd_sched_skey_cache_init(&key_domain->idx_cache, policy);
	if (ret)
		return ret;

	ret = wd_sched_skey_add_ctx(&key_domain->idx_cache, ctx_idx);
	if (ret)
		goto init_err;

	ret = pthread_mutex_init(&key_domain->lock, NULL);
	if (ret)
		goto add_ctx_err;

	key_domain->expanded_count = 0;

	return WD_SUCCESS;

add_ctx_err:
	wd_sched_skey_remove_ctx(&key_domain->idx_cache, ctx_idx);
init_err:
	wd_sched_skey_cache_uninit(&key_domain->idx_cache);
	return ret;
}

/**
 * wd_sched_skey_domain_destroy - Release session domain resources
 */
static void wd_sched_skey_domain_destroy(struct wd_sched_key_domain *key_domain)
{
	if (!key_domain)
		return;

	pthread_mutex_destroy(&key_domain->lock);
	wd_sched_skey_cache_uninit(&key_domain->idx_cache);
}

static __u32 wd_sched_find_compatible_ctx(struct wd_sched_ctx *sched_ctx,
					   struct wd_sched_key *skey,
					   int region, int sched_mode)
{
	struct wd_sched_ctx_domain *domain;
	__u32 i, ctx_idx, prop;

	for (prop = 0; prop < UADK_ALG_TYPE_MAX; prop++) {
		domain = wd_sched_hash_table_lookup(sched_ctx->domain_hash_table,
						    region, sched_mode, skey->type, prop);
		if (!domain || !domain->valid)
			continue;
		for (i = 0; i < domain->total_ctx_count; i++) {
			ctx_idx = wd_sched_domain_get_next_rr(domain);
			if (ctx_idx == INVALID_POS)
				continue;
			if (skey->ctxs[ctx_idx].drv &&
			    wd_alg_match_drv(skey->ctxs[ctx_idx].drv, skey->alg_name))
				return ctx_idx;
		}
	}

	return INVALID_POS;
}

static __u32 wd_sched_get_new_ctx(struct wd_sched_ctx *sched_ctx,
				  struct wd_sched_key *skey,
				  int sched_mode)
{
	int region_id = skey->region_id;
	__u8 ctx_prop = skey->ctx_prop;
	__u32 op_type = skey->type;
	__u32 ctx_idx;
	int r;

	if (sched_mode >= SCHED_MODE_BUTT ||
	    op_type >= sched_ctx->type_num || ctx_prop >= UADK_ALG_TYPE_MAX) {
		WD_ERR("invalid: region: %d, mode: %d, type: %u!, prop: %u\n",
		       region_id, sched_mode, op_type, ctx_prop);
		return INVALID_POS;
	}

	if (region_id < 0 ||
	    (sched_ctx->policy != SCHED_POLICY_DEV &&
	     region_id >= sched_ctx->region_num)) {
		WD_ERR("invalid: region_id is %d, region_num is %u!\n",
		       region_id, sched_ctx->region_num);
		return INVALID_POS;
	}

	if (!sched_ctx->domain_hash_table)
		return INVALID_POS;

	/* Try current region first */
	ctx_idx = wd_sched_find_compatible_ctx(sched_ctx, skey, region_id, sched_mode);
	if (ctx_idx != INVALID_POS)
		return ctx_idx;

	/* DEV policy must not cross region */
	if (sched_ctx->policy == SCHED_POLICY_DEV)
		return INVALID_POS;

	/* Cross-region fallback: try all other regions */
	for (r = 0; r < sched_ctx->region_num; r++) {
		if (r == region_id)
			continue;
		ctx_idx = wd_sched_find_compatible_ctx(sched_ctx, skey, r, sched_mode);
		if (ctx_idx != INVALID_POS)
			return ctx_idx;
	}

	return INVALID_POS;
}

/**
 * wd_sched_skey_compat_filter - Filter and replace incompatible ctxs in domain cache
 * @sched_ctx: Scheduler context
 * @skey: Session key with alg_name and ctxs
 * @domain: Target domain (sync or async)
 * @sched_mode: SCHED_MODE_SYNC or SCHED_MODE_ASYNC
 *
 * For each ctx in domain cache, check if it supports alg_name.
 * If not, find a compatible replacement from the global domain.
 */
static void wd_sched_skey_compat_filter(struct wd_sched_ctx *sched_ctx,
	struct wd_sched_key *skey, struct wd_sched_key_domain *domain, int sched_mode)
{
	__u32 ctx_idx, new_ctx;
	__u32 i;

	if (!skey || !skey->alg_name || !skey->ctxs || !domain)
		return;

	/* Skip uninitialized domains (no ctxs cached) */
	if (!domain->idx_cache.valid_count)
		return;

	pthread_mutex_lock(&domain->lock);

	for (i = 0; i < domain->idx_cache.valid_count; i++) {
		ctx_idx = domain->idx_cache.idx_list[i];

		/* Check if current ctx is compatible */
		if (skey->ctxs[ctx_idx].drv &&
		    wd_alg_match_drv(skey->ctxs[ctx_idx].drv, skey->alg_name)) {
			/* Compatible, keep unchanged */
			continue;
		}

		/* Not compatible, find a replacement from domain */
		new_ctx = wd_sched_get_new_ctx(sched_ctx, skey, sched_mode);
		if (new_ctx != INVALID_POS && new_ctx != ctx_idx) {
			/* Found compatible ctx, replace */
			domain->idx_cache.idx_list[i] = new_ctx;
			__atomic_store_n(&domain->idx_cache.load_values[i], 0, __ATOMIC_RELAXED);
		} else {
			/* No compatible ctx found, mark as invalid */
			domain->idx_cache.idx_list[i] = INVALID_POS;
			WD_INFO("info: no compatible ctx found for alg %s!\n", skey->alg_name);
		}
	}

	pthread_mutex_unlock(&domain->lock);
}

/**
 * wd_sched_poll_skey - Poll contexts for scheduler session
 * @sched_ctx: Scheduler context
 * @skey: Session key
 * @expect: Expected number of responses
 * @count: Actual response count (output)
 *
 * Polls all contexts in session domains and updates load values.
 */
static int wd_sched_poll_skey(struct wd_sched_ctx *sched_ctx, struct wd_sched_key *skey,
			 __u32 expect, __u32 *count)
{
	struct wd_sched_domain_idx_cache *cache;
	__u32 ctx_list_num = 0;
	__u32 sum_poll_num = 0;
	bool hungry_policy;
	__u32 poll_num;
	__u32 idx, i;
	int ret = 0;

	/* Get cache pointer and check if HUNGRY policy */
	cache = &skey->async_domain.idx_cache;
	ctx_list_num = cache->valid_count;
	hungry_policy = (cache->policy == SCHED_POLICY_HUNGRY);

	/* Poll async domain contexts */
	for (i = 0; i < ctx_list_num; i++) {
		idx = cache->idx_list[i];
		if (idx == INVALID_POS)
			continue;
		poll_num = 0;
		ret = sched_ctx->poll_func(idx, expect, &poll_num);
		if (poll_num > 0)
			sum_poll_num += poll_num;

		/* Update load value for this context */
		if (hungry_policy && poll_num > 0) {
			if (skey->ctxs)
				__atomic_fetch_sub(&skey->ctxs[idx].hw_load,
						   poll_num, __ATOMIC_RELAXED);
			wd_sched_skey_update_load(cache, i, -poll_num);
		}

		if (ret < 0 && ret != -WD_EAGAIN)
			break;
	}
	*count = sum_poll_num;

	return ret;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */
static inline bool sched_skey_get_ref(struct wd_sched_key *skey)
{
	if (!skey)
		return false;
	return __atomic_fetch_add(&skey->refcount, 1, __ATOMIC_ACQUIRE) > 0;
}

static inline bool sched_skey_put_ref(struct wd_sched_key *skey)
{
	return __atomic_fetch_sub(&skey->refcount, 1, __ATOMIC_RELEASE) == 1;
}

static int sched_skey_param_init(struct wd_sched_ctx *sched_ctx,
		struct wd_sched_key *skey)
{
	__u32 i;

	pthread_mutex_lock(&sched_ctx->skey_lock);
	for (i = 0; i < SKEY_MAX_THREAD_NUM; i++) {
		if (!sched_ctx->skey[i]) {
			sched_ctx->skey[i] = skey;
			if (sched_ctx->skey_num < SKEY_MAX_THREAD_NUM)
				sched_ctx->skey_num++;
			pthread_mutex_unlock(&sched_ctx->skey_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&sched_ctx->skey_lock);
	WD_ERR("invalid: skey node number exceeds SKEY_MAX_THREAD_NUM(%d)!\n",
	       SKEY_MAX_THREAD_NUM);
	return -WD_ENOMEM;
}

static void sched_skey_param_uninit(struct wd_sched_ctx *sched_ctx,
		struct wd_sched_key *skey)
{
	__u32 i;

	if (!sched_ctx || !skey)
		return;

	pthread_mutex_lock(&sched_ctx->skey_lock);
	for (i = 0; i < SKEY_MAX_THREAD_NUM; i++) {
		if (sched_ctx->skey[i] == skey) {
			sched_ctx->skey[i] = NULL;
			pthread_mutex_unlock(&sched_ctx->skey_lock);
			return;
		}
	}
	pthread_mutex_unlock(&sched_ctx->skey_lock);
	WD_ERR("warning: skey %p not found in sched_ctx array\n", skey);
}

static handle_t sched_session_common_init(struct wd_sched_ctx *sched_ctx,
	struct sched_params *param)
{
	struct wd_sched_key *skey;
	unsigned int node;

	if (getcpu(NULL, &node)) {
		WD_ERR("failed to get node, errno %d!\n", errno);
		return (handle_t)(-errno);
	}

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return (handle_t)(-WD_EINVAL);
	}

	skey = malloc(sizeof(struct wd_sched_key));
	if (!skey) {
		WD_ERR("failed to alloc memory for session sched key!\n");
		return (handle_t)(-WD_ENOMEM);
	}
	memset(skey, 0, sizeof(struct wd_sched_key));

	if (!param) {
		skey->region_id = node;
		if (wd_need_debug())
			WD_DEBUG("session don't set scheduler parameters!\n");
	} else {
		if (sched_ctx->policy == SCHED_POLICY_DEV)
			skey->region_id = param->dev_id;
		else if (param->numa_id >= 0)
			skey->region_id = param->numa_id;
		else
			skey->region_id = node;
		skey->type = param->type;
		skey->ctx_prop = param->ctx_prop;
	}
	__atomic_clear(&skey->poll_lock, __ATOMIC_RELEASE);
	__atomic_store_n(&skey->refcount, 1, __ATOMIC_RELAXED);

	return (handle_t)skey;
}

static __u16 sched_get_poll_skey_idx(struct wd_sched_ctx *sched_ctx)
{
	/* Thread-local sequence number with atomic global counter */
	static __thread __u32 thread_seq = UINT32_MAX;
	static __u32 global_seq_counter;
	__u32 skey_num = sched_ctx->skey_num;
	__u16 start_pos;

	if (unlikely(!sched_ctx || !skey_num))
		return skey_num;

	/* Assign unique sequence number on first call */
	if (unlikely(thread_seq == UINT32_MAX)) {
		thread_seq = __atomic_fetch_add(&global_seq_counter, 1, __ATOMIC_RELAXED);

		/* Basic overflow protection */
		if (thread_seq >= UINT32_MAX - 1)
			WD_DEBUG("Thread sequence counter approaching limit: %u\n", thread_seq);
	}

	/* Calculate start_pos based on thread_seq */
	start_pos = thread_seq % skey_num;

	return start_pos;
}

/**
 * session_sched_init_ctx - Pre-fetch single context from domain for session
 * @sched_ctx: Scheduler context
 * @skey: session scheduler param
 * @sched_mode: Mode (SYNC/ASYNC)
 *
 * Returns: Context index from domain (compatible with alg_name if skey provided)
 */
static __u32 session_sched_init_ctx(struct wd_sched_ctx *sched_ctx,
				    struct wd_sched_key *skey, int sched_mode)
{
	struct wd_sched_ctx_domain *domain = NULL;
	int region_id = skey->region_id;
	__u32 op_type = skey->type;
	__u8 prop = skey->ctx_prop;
	__u32 ctx_idx;
	__u16 r;

	if (sched_mode >= SCHED_MODE_BUTT ||
	    op_type >= sched_ctx->type_num || prop >= UADK_ALG_TYPE_MAX) {
		WD_ERR("invalid: region: %d, mode: %d, type: %u!, prop: %u\n",
		       region_id, sched_mode, op_type, prop);
		return INVALID_POS;
	}

	if (!sched_ctx->domain_hash_table)
		return INVALID_POS;

	/* Try current region first */
	if (region_id >= 0) {
		if (sched_ctx->policy == SCHED_POLICY_DEV ||
		    region_id < sched_ctx->region_num) {
			domain = wd_sched_hash_table_lookup(sched_ctx->domain_hash_table,
							    region_id, sched_mode, op_type, prop);
			if (domain && domain->valid)
				return wd_sched_domain_get_next_rr(domain);
		}
	}

	/* DEV policy must not cross region */
	if (sched_ctx->policy == SCHED_POLICY_DEV)
		return INVALID_POS;

	/* Cross-region fallback for other policies */
	for (r = 0; r < sched_ctx->region_num; r++) {
		if ((int)r == region_id)
			continue;
		domain = wd_sched_hash_table_lookup(sched_ctx->domain_hash_table,
						    r, sched_mode, op_type, prop);
		if (domain && domain->valid) {
			ctx_idx = wd_sched_domain_get_next_rr(domain);
			if (ctx_idx != INVALID_POS)
				return ctx_idx;
		}
	}

	return INVALID_POS;
}

/**
 * session_sched_domain_destroy - Destroy session domains
 * @skey: Session key to destroy domains for
 *
 * Releases all resources associated with session domains.
 */
static void session_sched_domain_destroy(struct wd_sched_key *skey)
{
	if (!skey)
		return;

	/* Destroy both sync and async domains */
	wd_sched_skey_domain_destroy(&skey->sync_domain);
	wd_sched_skey_domain_destroy(&skey->async_domain);
}

static inline void sched_skey_poll_release(struct wd_sched_key *skey)
{
	__u32 prev;

	if (!skey)
		return;

	prev = __atomic_fetch_sub(&skey->refcount, 1, __ATOMIC_ACQ_REL);
	if (prev == 1) {
		session_sched_domain_destroy(skey);
		free(skey);
	}
}

static void sched_session_uninit(handle_t h_sched_ctx, handle_t h_sched_key)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct wd_sched_key *skey = (struct wd_sched_key *)h_sched_key;

	if (!skey)
		return;

	/* Remove from skey array first to prevent new poll discovery.
	 * Poll threads already holding a pointer are protected by refcount.
	 */
	if (sched_ctx)
		sched_skey_param_uninit(sched_ctx, skey);

	/* Drop creator reference. If no poll holds a ref, free now.
	 * Otherwise the last poll thread will cleanup via poll_release.
	 */
	if (sched_skey_put_ref(skey)) {
		session_sched_domain_destroy(skey);
		free(skey);
	}
}

/**
 * session_sched_init_ctx_with_fallback - Pre-fetch a ctx for one sched_mode,
 *                                       trying user_prop first then falling
 *                                       back through other props in enum order.
 * @sched_ctx: Scheduler context
 * @skey: Session key (skey->ctx_prop is the user-specified prop; restored on return)
 * @sched_mode: SCHED_MODE_SYNC or SCHED_MODE_ASYNC
 *
 * Returns: ctx index, or INVALID_POS if no prop has a usable ctx.
 *
 * Falls back only when the user-specified prop's domain is unavailable
 * (e.g. HW driver unloaded). Stops at the first prop that yields a ctx;
 * does NOT accumulate ctxs across props.
 */
static __u32 session_sched_init_ctx_with_fallback(struct wd_sched_ctx *sched_ctx,
						   struct wd_sched_key *skey,
						   int sched_mode)
{
	__u8 user_prop = skey->ctx_prop;
	__u32 ctx_idx;
	__u8 p;

	/* Try user-specified prop first */
	ctx_idx = session_sched_init_ctx(sched_ctx, skey, sched_mode);
	if (ctx_idx != INVALID_POS)
		return ctx_idx;

	/* Fallback: target prop unavailable, try remaining props in enum order */
	for (p = 0; p < UADK_ALG_TYPE_MAX; p++) {
		if (p == user_prop)
			continue;
		skey->ctx_prop = p;
		ctx_idx = session_sched_init_ctx(sched_ctx, skey, sched_mode);
		if (ctx_idx != INVALID_POS)
			break;
	}

	/* Restore user_prop so skey state is not mutated */
	skey->ctx_prop = user_prop;
	return ctx_idx;
}

/**
 * session_sched_domain_init - Initialize session domains with sync/async
 * @sched_ctx: Scheduler context
 * @skey: Session key to initialize
 * @allow_fallback: If true, fall back to other props when skey->ctx_prop has
 *                  no usable domain; if false, only try skey->ctx_prop.
 *
 * Pre-fetches sync and async contexts and initializes corresponding domains.
 * Returns: 0 on success, negative error code on failure.
 */
static int session_sched_domain_init(struct wd_sched_ctx *sched_ctx,
				     struct wd_sched_key *skey,
				     bool allow_fallback)
{
	__u32 sync_ctx, async_ctx;

	if (!sched_ctx || !skey) {
		WD_ERR("invalid: sched_ctx or skey is NULL!\n");
		return -WD_EINVAL;
	}

	if (allow_fallback) {
		/* Pre-fetch with per-mode prop fallback */
		sync_ctx = session_sched_init_ctx_with_fallback(sched_ctx, skey,
								SCHED_MODE_SYNC);
		async_ctx = session_sched_init_ctx_with_fallback(sched_ctx, skey,
								 SCHED_MODE_ASYNC);
	} else {
		sync_ctx = session_sched_init_ctx(sched_ctx, skey, SCHED_MODE_SYNC);
		async_ctx = session_sched_init_ctx(sched_ctx, skey, SCHED_MODE_ASYNC);
	}

	if (sync_ctx == INVALID_POS && async_ctx == INVALID_POS) {
		WD_ERR("invalid: no valid sync_ctx or async_ctx domain!\n");
		return -WD_EINVAL;
	}

	/* Initialize sync domain if context is valid */
	if (sync_ctx != INVALID_POS) {
		if (wd_sched_skey_domain_init(&skey->sync_domain, sync_ctx, sched_ctx->policy)) {
			WD_ERR("failed to init sync domain!\n");
			return -WD_EINVAL;
		}
	}

	/* Initialize async domain if context is valid */
	if (async_ctx != INVALID_POS) {
		if (wd_sched_skey_domain_init(&skey->async_domain, async_ctx, sched_ctx->policy)) {
			WD_ERR("failed to init async domain!\n");
			/* Cleanup sync domain if async domain init failed */
			if (sync_ctx != INVALID_POS)
				wd_sched_skey_domain_destroy(&skey->sync_domain);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

/* ============================================================================
 * Scheduler Policy Functions
 * ============================================================================
 */
/**
 * round_robin_sched_init - Initialize session with single sync and async ctx
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @sched_param: Scheduling parameters (cannot modify per API contract)
 *
 * Allocates session key and pre-fetches one sync and one async context.
 */
static handle_t round_robin_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_params *param = (struct sched_params *)sched_param;
	struct wd_sched_key *skey;
	handle_t hskey;
	int ret = 0;

	hskey = sched_session_common_init(sched_ctx, param);
	if (WD_IS_ERR(hskey)) {
		WD_ERR("failed to init session schedule key!\n");
		return hskey;
	}

	skey = (struct wd_sched_key *)hskey;
	/* RR: allow prop fallback so session creation survives target prop unload */
	ret = session_sched_domain_init(sched_ctx, skey, true);
	if (ret) {
		WD_ERR("failed to initialize session domains!\n");
		free(skey);
		return (handle_t)(-WD_EINVAL);
	}

	ret = sched_skey_param_init(sched_ctx, skey);
	if (ret) {
		WD_ERR("failed to register skey in sched_ctx array!\n");
		session_sched_domain_destroy(skey);
		free(skey);
		return (handle_t)(-WD_ENOMEM);
	}

	return hskey;
}

/**
 * round_robin_pick_next_ctx - Pick context with load-based selection
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @sched_key: Session key (cannot modify per API contract)
 * @sched_mode: Mode (cannot modify per API contract)
 *
 * Returns: Context index with minimum load
 * Time complexity: O(1)
 */
static __u32 round_robin_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
					 const int sched_mode)
{
	struct wd_sched_key *skey = (struct wd_sched_key *)sched_key;
	struct wd_sched_key_domain *domain;
	__u32 min_ctx, ctx_idx;

	if (unlikely(!h_sched_ctx || !skey)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (sched_mode == SCHED_MODE_SYNC)
		domain = &skey->sync_domain;
	else
		domain = &skey->async_domain;

	/* Get current minimum load context */
	min_ctx = wd_sched_skey_pick_next(&domain->idx_cache, &ctx_idx, skey->ctxs);
	if (min_ctx == INVALID_POS)
		return INVALID_POS;

	return min_ctx;
}

/**
 * round_robin_poll_policy - Poll policy for session scheduler
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @expect: Expected number of responses (cannot modify per API contract)
 * @count: Actual response count (cannot modify per API contract)
 *
 * Returns: Status code
 */
static int round_robin_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct wd_sched_key *skey;
	__u16 i, tpos, start_pos;
	__u32 poll_num, skey_num;
	int ret = -WD_EAGAIN;
	__u32 sum_count = 0;

	if (unlikely(!count || !sched_ctx || !sched_ctx->poll_func)) {
		WD_ERR("invalid: sched ctx or poll_func is NULL or count is zero!\n");
		return -WD_EINVAL;
	}

	/* Randomize the initial query position. */
	skey_num = sched_ctx->skey_num;
	start_pos = sched_get_poll_skey_idx(sched_ctx);
	if (!skey_num || start_pos >= sched_ctx->skey_num) {
		*count = 0;
		return -WD_EAGAIN;
	}

	/* Query the queues on each skey separately. */
	for (i = 0; i < skey_num; i++) {
		tpos = (start_pos + i) % skey_num;
		skey = sched_ctx->skey[tpos];

		if (unlikely(!skey))
			continue;

		if (!sched_skey_get_ref(skey))
			continue;

		if (__atomic_test_and_set(&skey->poll_lock, __ATOMIC_ACQUIRE)) {
			sched_skey_poll_release(skey);
			continue;
		}

		ret = wd_sched_poll_skey(sched_ctx, skey, expect, &poll_num);
		__atomic_clear(&skey->poll_lock, __ATOMIC_RELEASE);
		sched_skey_poll_release(skey);

		sum_count += poll_num;
		if (unlikely(ret && ret != -WD_EAGAIN))
			goto poll_err;

		if (sum_count >= expect)
			break;
	}

poll_err:
	*count = sum_count;
	if (ret == -WD_EAGAIN)
		return 0;
	return ret;
}

static handle_t sched_none_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 sched_none_pick_next_ctx(handle_t h_sched_ctx,
				      void *sched_key, const int sched_mode)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return INVALID_POS;
	}

	return sched_mode == SCHED_MODE_SYNC ? sched_ctx->sync_idx : sched_ctx->async_idx;
}

static int sched_none_poll_policy(handle_t h_sched_ctx,
				  __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	__u32 loop_times = MAX_POLL_TIMES + expect;
	__u32 poll_num = 0, poll_idx;
	int ret;

	if (!sched_ctx || !sched_ctx->poll_func) {
		WD_ERR("invalid: sched ctx or poll_func is NULL!\n");
		return -WD_EINVAL;
	}

	poll_idx = sched_ctx->async_idx;
	if (poll_idx == INVALID_POS) {
		WD_ERR("invalid: no async ctx available to poll!\n");
		return -WD_EINVAL;
	}

	while (loop_times > 0) {
		loop_times--;
		ret = sched_ctx->poll_func(poll_idx, 1, &poll_num);
		if ((ret < 0) && (ret != -WD_EAGAIN))
			return ret;
		else if (ret == -WD_EAGAIN)
			continue;

		*count += poll_num;
		if (*count == expect)
			break;
	}

	return WD_SUCCESS;
}

static handle_t sched_single_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 sched_single_pick_next_ctx(handle_t h_sched_ctx,
					void *sched_key, const int sched_mode)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return INVALID_POS;
	}

	return sched_mode == SCHED_MODE_SYNC ? sched_ctx->sync_idx : sched_ctx->async_idx;
}

static int sched_single_poll_policy(handle_t h_sched_ctx,
				    __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	__u32 loop_times = MAX_POLL_TIMES + expect;
	__u32 poll_num = 0, poll_idx;
	int ret;

	if (!sched_ctx || !sched_ctx->poll_func) {
		WD_ERR("invalid: sched ctx or poll_func is NULL!\n");
		return -WD_EINVAL;
	}

	poll_idx = sched_ctx->async_idx;
	if (poll_idx == INVALID_POS) {
		WD_ERR("invalid: no async ctx available to poll!\n");
		return -WD_EINVAL;
	}

	while (loop_times > 0) {
		loop_times--;
		ret = sched_ctx->poll_func(poll_idx, 1, &poll_num);
		if ((ret < 0) && (ret != -WD_EAGAIN))
			return ret;
		else if (ret == -WD_EAGAIN)
			continue;

		*count += poll_num;
		if (*count == expect)
			break;
	}

	return WD_SUCCESS;
}

/**
 * sched_skey_domain_fill - Initialize or append ctx to session domain
 * @key_domain: Target domain (sync or async)
 * @ctx_idx: Context index to add
 * @policy: Scheduler policy
 * @inited: Pointer to boolean tracking whether domain has been initialized
 *
 * First call: full domain init via wd_sched_skey_domain_init().
 * Subsequent calls: append via wd_sched_skey_add_ctx().
 */
static void sched_skey_domain_fill(struct wd_sched_key_domain *key_domain,
				  __u32 ctx_idx, __u8 policy, bool *inited)
{
	int ret;

	if (ctx_idx == INVALID_POS)
		return;

	if (!*inited) {
		ret = wd_sched_skey_domain_init(key_domain, ctx_idx, policy);
		if (!ret)
			*inited = true;
		return;
	}

	(void)wd_sched_skey_add_ctx(&key_domain->idx_cache, ctx_idx);
}

/**
 * sched_skey_common_init - Common scheduler init with init-once + add-rest pattern
 * @h_sched_ctx: Scheduler handle
 * @sched_param: Scheduling parameters
 * @prop_begin: First prop type to iterate (inclusive)
 * @prop_end: Last prop type to iterate (inclusive)
 *
 * Shared by Loop, Hungry, and Instr scheduler init functions.
 * Iterates [prop_begin, prop_end], fetching sync/async ctxs per prop type.
 * First valid ctx initializes the domain, subsequent ctxs are appended.
 */
static handle_t sched_skey_common_init(handle_t h_sched_ctx, void *sched_param,
				       __u8 prop_begin, __u8 prop_end)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_params *param = (struct sched_params *)sched_param;
	struct wd_sched_key *skey;
	bool sync_inited = false;
	bool async_inited = false;
	__u32 sync_ctx, async_ctx;
	__u32 req_ctx_num = 0;
	handle_t hskey;
	__u8 def_prop;
	int ret, i;

	hskey = sched_session_common_init(sched_ctx, param);
	if (WD_IS_ERR(hskey)) {
		WD_ERR("failed to init session schedule key!\n");
		return hskey;
	}

	skey = (struct wd_sched_key *)hskey;
	def_prop = skey->ctx_prop;
	for (i = prop_begin; i <= prop_end; i++) {
		skey->ctx_prop = i;
		sync_ctx = session_sched_init_ctx(sched_ctx, skey, SCHED_MODE_SYNC);
		async_ctx = session_sched_init_ctx(sched_ctx, skey, SCHED_MODE_ASYNC);
		if (sync_ctx == INVALID_POS && async_ctx == INVALID_POS)
			continue;

		if (sync_ctx != INVALID_POS) {
			sched_skey_domain_fill(&skey->sync_domain, sync_ctx,
					       sched_ctx->policy, &sync_inited);
		}
		if (async_ctx != INVALID_POS)
			sched_skey_domain_fill(&skey->async_domain, async_ctx,
					       sched_ctx->policy, &async_inited);

		req_ctx_num += 2;
	}
	if (!req_ctx_num) {
		free(skey);
		return (handle_t)(-WD_EINVAL);
	}

	skey->ctx_prop = def_prop;
	ret = sched_skey_param_init(sched_ctx, skey);
	if (ret) {
		WD_ERR("failed to register skey in sched_ctx array!\n");
		session_sched_domain_destroy(skey);
		free(skey);
		return (handle_t)(-WD_ENOMEM);
	}

	return hskey;
}

/**
 * skey_sched_init - Initialize Hungry scheduler session
 */
static handle_t skey_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	handle_t hskey = sched_skey_common_init(h_sched_ctx, sched_param,
						0, UADK_ALG_TYPE_MAX - 1);
	return hskey;
}

/**
 * skey_sched_pick_next_ctx - Pick context from hungry scheduler with load awareness
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @sched_key: Session key (cannot modify per API contract)
 * @sched_mode: Mode (cannot modify per API contract)
 *
 * Returns: Context with minimum load, or expands if threshold exceeded
 * Time complexity: O(1) for selection, O(n) if expansion needed
 */
static __u32 skey_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
				      const int sched_mode)
{
	struct wd_sched_key *skey = (struct wd_sched_key *)sched_key;
	struct wd_sched_domain_idx_cache *idx_cache;
	struct wd_sched_key_domain *domain;
	__u32 min_ctx, min_load, ctx_idx;

	if (unlikely(!h_sched_ctx || !skey)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (sched_mode == SCHED_MODE_SYNC)
		domain = &skey->sync_domain;
	else
		domain = &skey->async_domain;

	idx_cache = &domain->idx_cache;
	if (sched_mode == SCHED_MODE_SYNC) {
		/* Sync: send+recv atomic, spinlock serialized, use RR */
		if (!idx_cache->valid_count)
			return INVALID_POS;

		ctx_idx = __atomic_fetch_add(&idx_cache->rr_ptr, 1, __ATOMIC_RELAXED) %
						  idx_cache->valid_count;
		return idx_cache->idx_list[ctx_idx];
	}

	/* Get current minimum load context */
	min_ctx = wd_sched_skey_pick_next(&domain->idx_cache, &ctx_idx, skey->ctxs);
	if (min_ctx == INVALID_POS)
		return INVALID_POS;

	if (skey->ctxs) {
		min_load = __atomic_load_n(&skey->ctxs[min_ctx].hw_load, __ATOMIC_RELAXED);
		if (min_load >= HW_QUEUE_FULL_DEPTH)
			return QUEUE_FULL_POS;
		__atomic_fetch_add(&skey->ctxs[min_ctx].hw_load, 1, __ATOMIC_RELAXED);
		wd_sched_skey_update_load(idx_cache, ctx_idx, 1);
	} else {
		min_load = __atomic_load_n(&idx_cache->load_values[ctx_idx], __ATOMIC_RELAXED);
		if (min_load >= HW_QUEUE_FULL_DEPTH && idx_cache->load_decreased > 0)
			return QUEUE_FULL_POS;
		wd_sched_skey_update_load(idx_cache, ctx_idx, 1);
	}
	/* Check if we need to expand context pool */

	return min_ctx;
}

/**
 * skey_sched_poll_policy - Poll policy for hungry scheduler
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @expect: Expected number of responses (cannot modify per API contract)
 * @count: Actual response count (cannot modify per API contract)
 *
 * Returns: Status code
 */
static int skey_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct wd_sched_key *skey;
	__u16 i, tpos, start_pos;
	__u32 poll_num, skey_num;
	int ret = -WD_EAGAIN;
	__u32 sum_count = 0;

	if (unlikely(!count || !sched_ctx || !sched_ctx->poll_func)) {
		WD_ERR("invalid: sched ctx or poll_func is NULL or count is zero!\n");
		return -WD_EINVAL;
	}

	/* Randomize the initial query position. */
	skey_num = sched_ctx->skey_num;
	start_pos = sched_get_poll_skey_idx(sched_ctx);
	if (!skey_num || start_pos >= sched_ctx->skey_num) {
		*count = 0;
		return -WD_EAGAIN;
	}

	/* Query the queues on each skey separately. */
	for (i = 0; i < skey_num; i++) {
		tpos = (start_pos + i) % skey_num;
		skey = sched_ctx->skey[tpos];

		if (unlikely(!skey))
			continue;

		if (!sched_skey_get_ref(skey))
			continue;

		if (__atomic_test_and_set(&skey->poll_lock, __ATOMIC_ACQUIRE)) {
			sched_skey_poll_release(skey);
			continue;
		}

		ret = wd_sched_poll_skey(sched_ctx, skey, expect, &poll_num);
		__atomic_clear(&skey->poll_lock, __ATOMIC_RELEASE);
		sched_skey_poll_release(skey);
		/*
		 * This query returned 0, indicating the hardware
		 * likely hasn't finished processing yet.
		 * Implementing a delay and releasing the CPU is a predictive optimization
		 */
		if (!poll_num)
			usleep(1);

		sum_count += poll_num;
		if (ret == -WD_EAGAIN)
			continue;
		if (unlikely(ret) || sum_count >= expect)
			break;
	}
	*count = sum_count;

	return ret;
}

/**
 * loop_sched_init - Initialize Loop scheduler session
 */
static handle_t loop_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	handle_t hskey = sched_skey_common_init(h_sched_ctx, sched_param,
						0, UADK_ALG_TYPE_MAX - 1);
	return hskey;
}

/**
 * loop_sched_pick_next_ctx - Pick context for loop scheduler
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @sched_key: Session key (cannot modify per API contract)
 * @sched_mode: Mode (cannot modify per API contract)
 *
 * Returns: Context index with minimum load
 * Time complexity: O(1)
 */
static __u32 loop_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
				      const int sched_mode)
{
	return round_robin_pick_next_ctx(h_sched_ctx, sched_key, sched_mode);
}

static int loop_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return round_robin_poll_policy(h_sched_ctx, expect, count);
}

/**
 * instr_sched_init - Initialize Instr scheduler session
 */
static handle_t instr_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	handle_t hskey = sched_skey_common_init(h_sched_ctx, sched_param,
						UADK_ALG_CE_INSTR,
						UADK_ALG_SVE_INSTR);
	return hskey;
}

static __u32 instr_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
				       const int sched_mode)
{
	struct wd_sched_key *skey = (struct wd_sched_key *)sched_key;
	struct wd_sched_key_domain *domain;
	__u32 min_ctx, ctx_idx;

	if (unlikely(!h_sched_ctx || !skey)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (sched_mode == SCHED_MODE_SYNC)
		domain = &skey->sync_domain;
	else
		domain = &skey->async_domain;

	/* Get current minimum load context */
	min_ctx = wd_sched_skey_pick_next(&domain->idx_cache, &ctx_idx, skey->ctxs);
	if (min_ctx == INVALID_POS)
		return INVALID_POS;

	return min_ctx;
}

/**
 * instr_sched_poll_policy - Poll policy for instruction scheduler
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @expect: Expected number of responses (cannot modify per API contract)
 * @count: Actual response count (cannot modify per API contract)
 *
 * Returns: Status code
 */
static int instr_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return round_robin_poll_policy(h_sched_ctx, expect, count);
}

static handle_t session_dev_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_params *param = (struct sched_params *)sched_param;
	struct wd_sched_key *skey;
	handle_t hskey;
	int ret = 0;

	if (!param) {
		WD_ERR("invalid: dev sched param is NULL!\n");
		return (handle_t)(-WD_EINVAL);
	}

	hskey = sched_session_common_init(sched_ctx, param);
	if (WD_IS_ERR(hskey)) {
		WD_ERR("failed to init session schedule key!\n");
		return hskey;
	}

	skey = (struct wd_sched_key *)hskey;
	skey->type = param->type;
	skey->dev_id = param->dev_id;

	/* DEV: pinned to a specific device, do not cross prop families */
	ret = session_sched_domain_init(sched_ctx, skey, false);
	if (ret) {
		WD_ERR("failed to initialize session domains!\n");
		free(skey);
		return (handle_t)(-WD_EINVAL);
	}

	ret = sched_skey_param_init(sched_ctx, skey);
	if (ret) {
		WD_ERR("failed to register skey in sched_ctx array!\n");
		session_sched_domain_destroy(skey);
		free(skey);
		return (handle_t)(-WD_ENOMEM);
	}

	return (handle_t)skey;
}

/**
 * wd_sched_set_param - Set scheduler parameters
 * @h_sched_ctx: Scheduler handle (cannot modify per API contract)
 * @sched_key: Session key (cannot modify per API contract)
 * @sched_param: Scheduling parameters (cannot modify per API contract)
 */

static void wd_sched_set_param(handle_t h_sched_ctx,
		void *sched_key, void *sched_param)
{
	struct wd_sched_params *params = (struct wd_sched_params *)sched_param;
	struct wd_sched_key *skey = (struct wd_sched_key *)sched_key;
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;

	if (unlikely(!params || !skey)) {
		WD_INFO("info: sched parmas or skey is NULL!\n");
		return;
	}

	skey->pkt_size = params->pkt_size;
	skey->is_stream = params->data_mode;
	skey->prio_mode = params->prio_mode;

	/* Store compat filtering parameters */
	skey->alg_name = params->alg_name;
	skey->ctxs = params->ctxs;

	/* If compat info provided, fix up pre-fetched ctxs */
	if (skey->alg_name && skey->ctxs) {
		wd_sched_skey_compat_filter(sched_ctx, skey,
			&skey->sync_domain, SCHED_MODE_SYNC);
		wd_sched_skey_compat_filter(sched_ctx, skey,
			&skey->async_domain, SCHED_MODE_ASYNC);
	}
}

static struct wd_sched sched_table[SCHED_POLICY_BUTT] = {
	{
		.name = "RR scheduler",
		.sched_policy = SCHED_POLICY_RR,
		.sched_init = round_robin_sched_init,
		.pick_next_ctx = round_robin_pick_next_ctx,
		.poll_policy = round_robin_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	}, {
		.name = "None scheduler",
		.sched_policy = SCHED_POLICY_NONE,
		.sched_init = sched_none_init,
		.pick_next_ctx = sched_none_pick_next_ctx,
		.poll_policy = sched_none_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	}, {
		.name = "Single scheduler",
		.sched_policy = SCHED_POLICY_SINGLE,
		.sched_init = sched_single_init,
		.pick_next_ctx = sched_single_pick_next_ctx,
		.poll_policy = sched_single_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	}, {
		.name = "Device RR scheduler",
		.sched_policy = SCHED_POLICY_DEV,
		.sched_init = session_dev_sched_init,
		.pick_next_ctx = round_robin_pick_next_ctx,
		.poll_policy = round_robin_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	}, {
		.name = "Loop scheduler",
		.sched_policy = SCHED_POLICY_LOOP,
		.sched_init = loop_sched_init,
		.pick_next_ctx = loop_sched_pick_next_ctx,
		.poll_policy = loop_sched_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	}, {
		.name = "Hungry scheduler",
		.sched_policy = SCHED_POLICY_HUNGRY,
		.sched_init = skey_sched_init,
		.pick_next_ctx = skey_sched_pick_next_ctx,
		.poll_policy = skey_sched_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	},  {
		.name = "Instr scheduler",
		.sched_policy = SCHED_POLICY_INSTR,
		.sched_init = instr_sched_init,
		.pick_next_ctx = instr_sched_pick_next_ctx,
		.poll_policy = instr_sched_poll_policy,
		.set_param = wd_sched_set_param,
		.sched_uninit = sched_session_uninit,
	},
};

static int numa_num_check(__u16 region_num)
{
	int max_node;

	max_node = numa_max_node() + 1;
	if (max_node <= 0) {
		WD_ERR("invalid: numa max node is %d!\n", max_node);
		return -WD_EINVAL;
	}

	if (!region_num || region_num > max_node) {
		WD_ERR("invalid: region number is %u!\n", region_num);
		return -WD_EINVAL;
	}

	return 0;
}

/**
 * wd_sched_rr_instance - External API for scheduling region instance
 * @sched: Scheduler (cannot modify per API contract)
 * @param: Scheduling parameters (cannot modify per API contract)
 *
 * Creates scheduling region for given parameters.
 */
int wd_sched_rr_instance(const struct wd_sched *sched, struct sched_params *param)
{
	struct wd_sched_ctx *sched_ctx = NULL;
	struct wd_sched_ctx_domain *domain;
	int region_key;
	__u8 mode;
	int ret;

	if (!sched || !sched->h_sched_ctx || !param) {
		WD_ERR("invalid: sched or sched_params is NULL!\n");
		return -WD_EINVAL;
	}

	if (param->begin > param->end) {
		WD_ERR("invalid: sched_params's begin is larger than end!\n");
		return -WD_EINVAL;
	}

	mode = param->mode;
	sched_ctx = (struct wd_sched_ctx *)sched->h_sched_ctx;

	if (sched_ctx->policy == SCHED_POLICY_DEV) {
		region_key = param->dev_id;
		if (region_key < 0) {
			WD_ERR("invalid: dev_id is %d!\n", region_key);
			return -WD_EINVAL;
		}
	} else {
		region_key = param->numa_id;
		if (region_key >= sched_ctx->region_num || region_key < 0) {
			WD_ERR("invalid: region_key is %d, region_num is %u!\n",
			       region_key, sched_ctx->region_num);
			return -WD_EINVAL;
		}
	}

	if (param->type >= sched_ctx->type_num) {
		WD_ERR("invalid: type is %u, type_num is %u!\n",
		       param->type, sched_ctx->type_num);
		return -WD_EINVAL;
	}

	if (mode >= SCHED_MODE_BUTT) {
		WD_ERR("invalid: mode is %u, mode_num is %u!\n",
		       mode, sched_ctx->mode_num);
		return -WD_EINVAL;
	}

	if (param->ctx_prop < 0 || param->ctx_prop >= UADK_ALG_TYPE_MAX) {
		WD_INFO("Info: ctx_prop %d exceeds max type!\n", param->ctx_prop);
		param->ctx_prop = UADK_ALG_HW;
	}

	domain = wd_sched_hash_table_insert(sched_ctx->domain_hash_table,
					    region_key, mode, param->type,
					    param->ctx_prop);
	if (!domain)
		return -WD_ENOMEM;

	ret = wd_sched_domain_add_segment(domain, param->begin, param->end);
	if (ret) {
		WD_ERR("failed to add segment to domain!\n");
		return ret;
	}
	domain->valid = true;

	/* SINGLE/NONE: record first ctx index per mode. */
	if (sched_ctx->policy == SCHED_POLICY_SINGLE ||
	    sched_ctx->policy == SCHED_POLICY_NONE) {
		if (mode == SCHED_MODE_SYNC && sched_ctx->sync_idx == INVALID_POS)
			sched_ctx->sync_idx = param->begin;
		else if (mode == SCHED_MODE_ASYNC && sched_ctx->async_idx == INVALID_POS)
			sched_ctx->async_idx = param->begin;
	}

	return WD_SUCCESS;
}

/**
 * wd_sched_rr_release - External API for scheduler release
 * @sched: Scheduler to release (cannot modify per API contract)
 *
 * Releases all scheduler resources.
 */
void wd_sched_rr_release(struct wd_sched *sched)
{
	struct wd_sched_ctx *sched_ctx;
	struct wd_sched_key *skey;
	__u32 i;

	if (!sched)
		return;

	sched_ctx = (struct wd_sched_ctx *)sched->h_sched_ctx;
	if (!sched_ctx)
		goto ctx_out;

	/* Release all session keys - iterate full array to catch residual entries */
	for (i = 0; i < SKEY_MAX_THREAD_NUM; i++) {
		skey = sched_ctx->skey[i];
		if (!skey)
			continue;

		sched_ctx->skey[i] = NULL;
		__atomic_store_n(&skey->refcount, 0, __ATOMIC_RELAXED);
		session_sched_domain_destroy(skey);
		free(skey);
	}
	sched_ctx->skey_num = 0;

	/* Release hash table */
	if (sched_ctx->domain_hash_table) {
		wd_sched_hash_table_destroy(sched_ctx->domain_hash_table);
		sched_ctx->domain_hash_table = NULL;
	}

	pthread_mutex_destroy(&sched_ctx->skey_lock);
	free(sched_ctx);

ctx_out:
	free(sched);
	return;
}

/**
 * wd_sched_rr_alloc - External API for scheduler allocation
 * @sched_type: Scheduling policy type (cannot modify per API contract)
 * @type_num: Number of operation types (cannot modify per API contract)
 * @region_num: Number of regions (cannot modify per API contract)
 * @func: Poll function (cannot modify per API contract)
 *
 * Allocates and initializes scheduler with single global hash table.
 */
struct wd_sched *wd_sched_rr_alloc(__u8 sched_type, __u8 type_num,
				   __u16 region_num, user_poll_func func)
{
	struct wd_sched_ctx *sched_ctx;
	struct wd_sched *sched;
	__u32 estimated_entries;
	__u32 i;

	if (sched_type >= SCHED_POLICY_BUTT || !type_num) {
		WD_ERR("invalid: sched_type is %u or type_num is %u!\n",
		       sched_type, type_num);
		return NULL;
	}

	sched = calloc(1, sizeof(struct wd_sched));
	if (!sched) {
		WD_ERR("failed to alloc memory for wd_sched!\n");
		return NULL;
	}

	sched_ctx = calloc(1, sizeof(struct wd_sched_ctx));
	if (!sched_ctx) {
		WD_ERR("failed to alloc memory for sched_ctx!\n");
		goto err_out;
	}

	/* Cache dimension parameters */
	sched_ctx->type_num = type_num;
	sched_ctx->mode_num = SCHED_MODE_BUTT;
	sched_ctx->region_num = region_num;
	sched_ctx->policy = sched_type;

	if (sched_type == SCHED_POLICY_DEV) {
		/* Device mode: region_num is actually device count */
		estimated_entries = region_num * type_num * SCHED_MODE_BUTT * UADK_ALG_TYPE_MAX;
	} else {
		/* NUMA mode: validate region_num */
		if (numa_num_check(region_num))
			goto err_out;
		estimated_entries = region_num * type_num * SCHED_MODE_BUTT * UADK_ALG_TYPE_MAX;
	}

	/* Create single global hash table */
	sched_ctx->domain_hash_table = wd_sched_hash_table_create(estimated_entries);
	if (!sched_ctx->domain_hash_table) {
		WD_ERR("failed to create hash table!\n");
		goto ctx_out;
	}

	sched_ctx->poll_func = func;

	for (i = 0; i < SKEY_MAX_THREAD_NUM; i++)
		sched_ctx->skey[i] = NULL;

	if (pthread_mutex_init(&sched_ctx->skey_lock, NULL)) {
		WD_ERR("failed to init skey_lock!\n");
		goto err_destroy_hash;
	}
	sched_ctx->skey_num = 0;
	sched_ctx->sync_idx = INVALID_POS;
	sched_ctx->async_idx = INVALID_POS;

	sched->h_sched_ctx = (handle_t)sched_ctx;
	sched->sched_init = sched_table[sched_type].sched_init;
	sched->sched_uninit = sched_table[sched_type].sched_uninit;
	sched->pick_next_ctx = sched_table[sched_type].pick_next_ctx;
	sched->poll_policy = sched_table[sched_type].poll_policy;
	sched->sched_policy = sched_type;
	sched->name = sched_table[sched_type].name;
	sched->set_param = sched_table[sched_type].set_param;

	return sched;

err_destroy_hash:
	wd_sched_hash_table_destroy(sched_ctx->domain_hash_table);
ctx_out:
	free(sched_ctx);
err_out:
	free(sched);
	return NULL;
}
