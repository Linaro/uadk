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
 * struct sched_ctx_range - define one ctx pos.
 * @begin: the start pos in ctxs of config.
 * @end: the end pos in ctxx of config.
 * @last: the last one which be distributed.
 */
struct sched_ctx_region {
	__u32 begin;
	__u32 end;
	__u32 last;
	bool valid;
	pthread_mutex_t lock;
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

	pthread_mutex_lock(&region->lock);

	pos = region->last;

	if (pos < region->end) {
		region->last++;
	} else if (pos == region->last) {
		region->last = region->begin;
	} else {
		/*
		 * If the pos's value is out of range, we can output the error
		 * info and correct the error
		 */
		printf("ERROR:%s, pos = %u, begin = %u, end = %u\n",
		       __FUNCTION__, pos, region->begin, region->end);
		region->last = region->begin;
	}

	pthread_mutex_unlock(&region->lock);

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

static int sample_poll_policy_rr(struct sample_sched_ctx *ctx, __u32 numa_id,
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
sample_sched_get_ctx_range(struct sample_sched_info *sched_info,
			   const struct sched_key *key)
{
	if (sched_info[key->numa_id].ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ctx_region[key->mode][key->type];

	return NULL;
}

static bool sample_sched_key_valid(struct sample_sched_ctx *ctx,
				   const struct sched_key *key)
{
	if (key->numa_id >= ctx->numa_num || key->mode >= SCHED_MODE_BUTT ||
	    key->type >= ctx->type_num) {
		printf("ERROR: %s key error - %u,%u,%u !\n",
		       __FUNCTION__, key->numa_id, key->mode, key->type);
		return false;
	}

	return true;
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
	struct sample_sched_info *sched_info;

	if (!ctx || !key || !req) {
		printf("ERROR: %s the pointer para is NULL !\n", __FUNCTION__);
		return INVALID_POS;
	}

	if (!sample_sched_key_valid(ctx, key)) {
		printf("ERROR: %s the key is invalid !\n", __FUNCTION__);
		return INVALID_POS;
	}

	sched_info = ctx->sched_info;

	region = sample_sched_get_ctx_range(sched_info, key);
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
				    const struct wd_ctx_config *cfg,
				    __u32 expect, __u32 *count)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)sched_ctx;
	struct sample_sched_info *sched_info;
	__u8 numa_id;
	int ret;

	if (!count || !cfg || !ctx) {
		printf("ERROR: %s the para is NULL !\n", __FUNCTION__);
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

struct sample_sched_table {
	const char *name;
	enum sched_policy_type type;
	__u32 (*pick_next_ctx)(handle_t h_sched_ctx, const void *req,
			       const struct sched_key *key);
	int (*poll_policy)(handle_t h_sched_ctx,
			   const struct wd_ctx_config *config,
			   __u32 expect,
			   __u32 *count);
} sched_table[SCHED_POLICY_BUTT] = {
	{
		.name = "RR scheduler",
		.type = SCHED_POLICY_RR,
		.pick_next_ctx = sample_sched_pick_next_ctx,
		.poll_policy = sample_sched_poll_policy,
	},
};

int sample_sched_fill_data(const struct wd_sched *sched, __u8 numa_id,
			   __u8 mode, __u8 type, __u32 begin, __u32 end)
{
	struct sample_sched_info *sched_info;
	struct sample_sched_ctx *sched_ctx;

	if (!sched || !sched->h_sched_ctx) {
		printf("ERROR: %s para err: sched of h_sched_ctx is null\n",
		       __FUNCTION__);
		return -EINVAL;
	}

	sched_ctx = (struct sample_sched_ctx*)sched->h_sched_ctx;

	if ((numa_id >= sched_ctx->numa_num) || (mode >= SCHED_MODE_BUTT) ||
	    (type >= sched_ctx->type_num)) {
		printf("ERROR: %s para err: numa_id=%u, mode=%u, type=%u\n",
		       __FUNCTION__, numa_id, mode, type);
		return -EINVAL;
	}

	sched_info = sched_ctx->sched_info;

	if (!sched_info[numa_id].ctx_region[mode]) {
		printf("ERROR: %s para err: ctx_region:numa_id=%u, mode=%u is null\n",
		       __FUNCTION__, numa_id, mode);
		return -EINVAL;
	}

	sched_info[numa_id].ctx_region[mode][type].begin = begin;
	sched_info[numa_id].ctx_region[mode][type].end = end;
	sched_info[numa_id].ctx_region[mode][type].last = begin;
	sched_info[numa_id].ctx_region[mode][type].valid = true;
	sched_info[numa_id].valid = true;

	pthread_mutex_init(&sched_info[numa_id].ctx_region[mode][type].lock,
			   NULL);

	return 0;
}

void sample_sched_release(struct wd_sched *sched)
{
	struct sample_sched_info *sched_info;
	struct sample_sched_ctx *sched_ctx;
	int i, j;

	if (!sched)
		return;

	sched_ctx = (struct sample_sched_ctx*)sched->h_sched_ctx;
	if (sched_ctx) {
		sched_info = sched_ctx->sched_info;
		for (i = 0; i < sched_ctx->numa_num; i++) {
			for (j = 0; j < SCHED_MODE_BUTT; j++) {
				if (sched_info[i].ctx_region[j])
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
		printf("Error: %s sched_type = %u or type_num = %u is invalid!\n",
		       __FUNCTION__, sched_type, type_num);
		return NULL;
	}

	if (!func) {
		printf("Error: %s poll_func is null!\n", __FUNCTION__);
		return NULL;
	}

	if (!numa_num) {
		printf("Warning: %s set numa number as %d!\n", __FUNCTION__,
		       MAX_NUMA_NUM);
		numa_num = MAX_NUMA_NUM;
	}

	sched = calloc(1, sizeof(struct wd_sched));
	if (!sched) {
		printf("Error: %s wd_sched alloc error!\n", __FUNCTION__);
		return NULL;
	}

	sched_ctx = calloc(1, sizeof(struct sample_sched_ctx) +
			   sizeof(struct sample_sched_info) * numa_num);
	if (!sched_ctx) {
		printf("Error: %s sched_ctx alloc error!\n", __FUNCTION__);
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
	sched->h_sched_ctx = (handle_t)sched_ctx;

	return sched;

err_out:
	sample_sched_release(sched);
	return NULL;
}
