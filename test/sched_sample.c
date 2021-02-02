// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include "sched_sample.h"

#define MAX_POLL_TIMES 1000

enum sched_region_mode {
	SCHED_MODE_SYNC = 0,
	SCHED_MODE_ASYNC = 1,
	SCHED_MODE_BUTT
};

/**
 * struct sched_ctx_region - define a region of the total contexes.
 * All contexes are arranged in a one dimensional array in the config of
 * current process. The index of context of this array is used directly in
 * the region.
 * In the region, the indexes of contexts are continuous.
 * If there's only one context in the region, @begin should be equal to @end.
 * @begin: the start pos in the total contexes.
 * @end: the end pos in the total contexes.
 * @last: the latest context that is assigned to user app.
 */
struct sched_ctx_region {
	__u32 begin;
	__u32 end;
	__u32 last;
	bool valid;
	pthread_spinlock_t *locks;	/* locks for contexes */
};

/**
 * sample_sched_info - define the context of the scheduler.
 * @ctx_region: define the map for the comp ctxs, using for quickly search.
 *              the x range: two(sync and async), the y range:
 *              two(e.g. comp and uncomp) the map[x][y]'s value is the ctx
 *              begin and end pos.
 * @valid: the region used flag.
 */
struct sample_sched_info {
	struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT];
	bool valid;
};

struct sample_sched_ctx {
	__u32 policy;
	__u32 type_num;
	__u8  numa_num;
	user_poll_func poll_func;
	struct sample_sched_info sched_info[0];
};

struct cache {
    __u32 *buff;
    __u32 depth;
    __u32 head;
    __u32 tail;
    __u32 used_num;
};

int sched_cache_insert(struct cache *cache, __u32 value)
{
	if (cache->used_num >= cache->depth) {
		return -EPERM;
	}

	cache->buff[cache->tail] = value;

	cache->used_num++;
	cache->tail++;
	if (cache->tail == cache->depth)
		cache->tail = 0;

	return 0;
};

int sched_cache_get(struct cache *cache, __u32 *value)
{
	if (!cache->used_num)
		return -EPERM;

	*value = cache->buff[cache->head];

	cache->used_num--;
	cache->head++;
	if (cache->head == cache->depth)
		cache->head = 0;

	return 0;
}

struct cache* sched_cache_alloc(__u32 depth, __u32 size)
{
	struct cache *cache;

	if (!depth)
		return NULL;

	cache = calloc(1, sizeof(struct cache));
	if (!cache)
		return NULL;

	cache->buff = calloc(depth, sizeof(__u32));
	if (!cache->buff) {
		free(cache);
		return NULL;
	}

	cache->depth = depth;

	return cache;
}

void cache_free(struct cache *cache)
{
	if (!cache)
		return;

	if (!cache->buff) {
		free(cache);
		return;
	}

	free(cache->buff);
	free(cache);
}


/**
 * Fill privte para that the different mode needs, reserved for future.
 */
static void sample_get_para_rr(const void *req, void *para)
{
	return;
}

/**
 * sample_get_next_pos_rr - Get next resource pos by RR schedule.
 * The second para is reserved for future.
 */
static __u32 sample_get_next_pos_rr(struct sched_ctx_region *region,
				    void *para)
{
	__u32 pos;
	int offs, ret;

	pos = region->last;

	do {
		pos++;
		if (pos > region->end)
			pos = region->begin;
		offs = pos - region->begin;
		ret = pthread_spin_trylock(&region->locks[offs]);
	} while (ret);
	region->last = pos;

	return pos;
}

static int sample_poll_region(struct sample_sched_ctx *ctx, __u32 begin,
			      __u32 end, __u32 expect, __u32 *count)
{
	__u32 poll_num = 0;
	__u32 i;
	int ret;

	/* i is the pos of ctxs, the max is end */
	for (i = begin; i <= end; i++) {
		/* RR schedule, one time poll one */
		ret = ctx->poll_func(i, 1, &poll_num);
		if ((ret < 0) && (ret != -EAGAIN))
			return ret;
		else if (ret == -EAGAIN)
			continue;
		*count += poll_num;
		if (*count >= expect)
			break;
	}

	return 0;
}

static int sample_poll_policy_rr(struct sample_sched_ctx *ctx, int numa_id,
				 __u32 expect, __u32 *count)
{
	struct sched_ctx_region **region =
					ctx->sched_info[numa_id].ctx_region;
	__u32 loop_time = 0;
	__u32 begin, end;
	__u32 i;
	int ret;

	/* Traverse the async ctx */
	/* But if poll_num always be zero by unknow reason. This will be endless loop,
	 * we must add the escape way by recording the loop count, if it is bigger
	 * than MAX_POLL_TIMES, must stop and return the pool num */
	while (loop_time < MAX_POLL_TIMES) {
		loop_time++;
		for (i = 0; i < ctx->type_num; i++) {
			if (!region[SCHED_MODE_ASYNC][i].valid)
				continue;

			begin = region[SCHED_MODE_ASYNC][i].begin;
			end = region[SCHED_MODE_ASYNC][i].end;
			ret = sample_poll_region(ctx, begin, end, expect,
						 count);
			if (ret)
				return ret;

			if (*count >= expect)
				return 0;
		}
	}

	return 0;
}

/**
 * sample_sched_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
static struct sched_ctx_region *
sample_sched_get_ctx_range(struct sample_sched_ctx *ctx,
			   const struct sched_key *key)
{
	struct sample_sched_info *sched_info;
	int numa_id;

	sched_info = ctx->sched_info;
	if (sched_info[key->numa_id].ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ctx_region[key->mode][key->type];

	/* If the key->numa_id is not exist, we should scan for a region */
	for (numa_id = 0; numa_id < ctx->numa_num; numa_id++) {
		if (sched_info[numa_id].ctx_region[key->mode][key->type].valid)
			return &sched_info[numa_id].ctx_region[key->mode][key->type];
	}

	return NULL;
}

static bool sample_sched_key_valid(struct sample_sched_ctx *ctx,
				   const struct sched_key *key)
{
	if (key->numa_id >= ctx->numa_num || key->mode >= SCHED_MODE_BUTT ||
	    key->type >= ctx->type_num) {
		WD_ERR("ERROR: %s key error - %d,%u,%u !\n",
		       __FUNCTION__, key->numa_id, key->mode, key->type);
		return false;
	}

	return true;
}

static struct sched_ctx_region *
sample_sched_find_region(struct sample_sched_ctx *ctx, __u32 pos)
{
	struct sample_sched_info *sched_info = ctx->sched_info;
	struct sched_ctx_region *rgn;
	int numa, mode, type;

	for (numa = 0; numa < ctx->numa_num; numa++) {
		for (mode = 0; mode < SCHED_MODE_BUTT; mode++) {
			for (type = 0; type < ctx->type_num; type++) {
				rgn = &sched_info[numa].ctx_region[mode][type];
				if (!rgn->valid)
					continue;
				if (pos >= rgn->begin && pos <= rgn->end)
					return rgn;
			}
		}
	}
	return NULL;
}

/**
 * ssample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @cfg: The global resoure info.
 * @reg: The service request msg, different algorithm shoule support analysis
 *       function.
 * @key: The key of schedule region.
 *
 * The user must init the schdule info through sample_sched_fill_data, the
 * func interval will not check the valid, becouse it will affect performance.
 */
static __u32 sample_sched_pick_next_ctx(handle_t sched_ctx, const void *req,
					const struct sched_key *key)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)sched_ctx;
	struct sched_ctx_region *region = NULL;

	if (!ctx || !key || !req) {
		WD_ERR("ERROR: %s the pointer para is NULL !\n", __FUNCTION__);
		return INVALID_POS;
	}

	if (!sample_sched_key_valid(ctx, key)) {
		WD_ERR("ERROR: %s the key is invalid !\n", __FUNCTION__);
		return INVALID_POS;
	}

	region = sample_sched_get_ctx_range(ctx, key);
	if (!region)
		return INVALID_POS;

	/*
	 * Notice: The second para now is a stub, we must alloc memery for it
	 * before using
	 */
	sample_get_para_rr(req, NULL);
	return sample_get_next_pos_rr(region, NULL);
}

/**
 * sample_poll_policy - The polling policy matches the pick next ctx.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @cfg: The global resoure info.
 * @expect: User expect poll msg num.
 * @count: The actually poll num.
 *
 * The user must init the schdule info through sample_sched_fill_data, the
 * func interval will not check the valid, becouse it will affect performance.
 */
static int sample_sched_poll_policy(handle_t sched_ctx,
				    __u32 expect, __u32 *count)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)sched_ctx;
	struct sample_sched_info *sched_info;
	int numa_id;
	int ret;

	if (!sched_ctx || !count || !ctx) {
		WD_ERR("ERROR: %s the para is NULL !\n", __FUNCTION__);
		return -EINVAL;
	}

	sched_info = ctx->sched_info;

	for (numa_id = 0; numa_id < ctx->numa_num; numa_id++) {
		if (sched_info[numa_id].valid) {
			ret = sample_poll_policy_rr(ctx, numa_id, expect,
						    count);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int sample_sched_get_ctx(handle_t h_sched_ctx, __u32 pos)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)h_sched_ctx;
	struct sched_ctx_region *rgn;
	int offs;

	rgn = sample_sched_find_region(ctx, pos);
	if (!rgn) {
		WD_ERR("ERROR: %s can't find the region by pos %d\n",
		       __FUNCTION__, pos);
		return -EINVAL;
	}
	offs = pos - rgn->begin;
	pthread_spin_lock(&rgn->locks[offs]);
	return 0;
}

static int sample_sched_put_ctx(handle_t h_sched_ctx, __u32 pos)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)h_sched_ctx;
	struct sched_ctx_region *rgn;
	int offs;

	rgn = sample_sched_find_region(ctx, pos);
	if (!rgn) {
		WD_ERR("ERROR: %s can't find the region by pos %d\n",
		       __FUNCTION__, pos);
		return -EINVAL;
	}
	offs = pos - rgn->begin;
	pthread_spin_unlock(&rgn->locks[offs]);
	return 0;
}

struct sample_sched_table {
	const char *name;
	enum sched_policy_type type;
	__u32 (*pick_next_ctx)(handle_t h_sched_ctx, const void *req,
			       const struct sched_key *key);
	int (*poll_policy)(handle_t h_sched_ctx,
			   __u32 expect,
			   __u32 *count);
	int (*get_ctx)(handle_t h_sched_ctx, __u32 pos);
	int (*put_ctx)(handle_t h_sched_ctx, __u32 pos);
} sched_table[SCHED_POLICY_BUTT] = {
	{
		.name = "RR scheduler",
		.type = SCHED_POLICY_RR,
		.pick_next_ctx = sample_sched_pick_next_ctx,
		.poll_policy = sample_sched_poll_policy,
		.get_ctx = sample_sched_get_ctx,
		.put_ctx = sample_sched_put_ctx,
	},
};

int sample_sched_fill_data(const struct wd_sched *sched, int numa_id,
			   __u8 mode, __u8 type, __u32 begin, __u32 end)
{
	struct sample_sched_info *sched_info;
	struct sample_sched_ctx *sched_ctx;
	struct sched_ctx_region *rgn;
	int i;

	if (!sched || !sched->h_sched_ctx) {
		WD_ERR("ERROR: %s para err: sched of h_sched_ctx is null\n",
		       __FUNCTION__);
		return -EINVAL;
	}

	sched_ctx = (struct sample_sched_ctx*)sched->h_sched_ctx;

	if ((numa_id >= sched_ctx->numa_num) || (numa_id < 0) ||
		(mode >= SCHED_MODE_BUTT) ||
	    (type >= sched_ctx->type_num)) {
		WD_ERR("ERROR: %s para err: numa_id=%d, mode=%u, type=%u\n",
		       __FUNCTION__, numa_id, mode, type);
		return -EINVAL;
	}

	sched_info = sched_ctx->sched_info;

	if (!sched_info[numa_id].ctx_region[mode]) {
		WD_ERR("ERROR: %s para err: ctx_region:numa_id=%d, mode=%u is null\n",
		       __FUNCTION__, numa_id, mode);
		return -EINVAL;
	}

	rgn = &sched_info[numa_id].ctx_region[mode][type];
	rgn->locks = calloc(1, (end - begin + 1) * sizeof(pthread_spinlock_t));
	if (!rgn->locks) {
		WD_ERR("ERROR: %s fail to allocate array\n", __FUNCTION__);
		return -ENOMEM;
	}
	for (i = 0; i < end - begin + 1; i++)
		pthread_spin_init(&rgn->locks[i], PTHREAD_PROCESS_SHARED);
	rgn->begin = begin;
	rgn->end = end;
	rgn->last = begin;
	rgn->valid = true;
	sched_info[numa_id].valid = true;

	return 0;
}

void sample_sched_release(struct wd_sched *sched)
{
	struct sample_sched_info *sched_info;
	struct sample_sched_ctx *sched_ctx;
	struct sched_ctx_region *rgn;
	int i, j, k;

	if (!sched)
		return;

	sched_ctx = (struct sample_sched_ctx*)sched->h_sched_ctx;
	if (sched_ctx) {
		sched_info = sched_ctx->sched_info;
		for (i = 0; i < sched_ctx->numa_num; i++) {
			for (j = 0; j < SCHED_MODE_BUTT; j++) {
				if (!sched_info[i].ctx_region[j])
					continue;
				for (k = 0; k < sched_ctx->type_num; k++) {
					rgn = &sched_info[i].ctx_region[j][k];
					if (rgn && rgn->locks)
						free((void *)rgn->locks);
				}
				free(sched_info[i].ctx_region[j]);
			}
		}
	
		free(sched_ctx);
	}

	free(sched);

	return;
}

struct wd_sched *sample_sched_alloc(__u8 sched_type, __u8 type_num, __u8 numa_num,
				    user_poll_func func) 
{
	struct sample_sched_info *sched_info;
	struct sample_sched_ctx *sched_ctx;
	struct wd_sched *sched;
	int i, j;

	if (sched_type >= SCHED_POLICY_BUTT || !type_num) {
		WD_ERR("Error: %s sched_type = %u or type_num = %u is invalid!\n",
		       __FUNCTION__, sched_type, type_num);
		return NULL;
	}

	if (!func) {
		WD_ERR("Error: %s poll_func is null!\n", __FUNCTION__);
		return NULL;
	}

	if (!numa_num) {
		WD_ERR("Warning: %s set numa number as %d!\n", __FUNCTION__,
		       MAX_NUMA_NUM);
		numa_num = MAX_NUMA_NUM;
	}

	sched = calloc(1, sizeof(struct wd_sched));
	if (!sched) {
		WD_ERR("Error: %s wd_sched alloc error!\n", __FUNCTION__);
		return NULL;
	}

	sched_ctx = calloc(1, sizeof(struct sample_sched_ctx) +
			   sizeof(struct sample_sched_info) * numa_num);
	if (!sched_ctx) {
		WD_ERR("Error: %s sched_ctx alloc error!\n", __FUNCTION__);
		goto err_out;
	}

	sched_info = sched_ctx->sched_info;

	for (i = 0; i < numa_num; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			sched_info[i].ctx_region[j] =
			calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!sched_info[i].ctx_region[j])
				goto err_out;
		}
	}

	sched_ctx->poll_func = func;
	sched_ctx->policy = sched_type;
	sched_ctx->type_num = type_num;
	sched_ctx->numa_num = numa_num;

	sched->pick_next_ctx = sched_table[sched_type].pick_next_ctx;
	sched->poll_policy = sched_table[sched_type].poll_policy;
	sched->get_ctx = sched_table[sched_type].get_ctx;
	sched->put_ctx = sched_table[sched_type].put_ctx;
	sched->h_sched_ctx = (handle_t)sched_ctx;

	return sched;

err_out:
	sample_sched_release(sched);
	return NULL;
}
