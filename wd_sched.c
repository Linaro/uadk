// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <sched.h>
#include <numa.h>
#include "wd_sched.h"

#define MAX_POLL_TIMES 1000

enum sched_region_mode {
	SCHED_MODE_SYNC = 0,
	SCHED_MODE_ASYNC = 1,
	SCHED_MODE_BUTT
};

/*
 * sched_key - The key if schedule region.
 * @numa_id: The schedule numa region id.
 * @mode: Sync mode:0, async_mode:1
 * @type: Service type , the value must smaller than type_num.
 * @sync_ctxid: alloc ctx id for sync mode
 * @async_ctxid: alloc ctx id for async mode
 */
struct sched_key {
	int numa_id;
	__u8 type;
	__u8 mode;
	__u32 sync_ctxid;
	__u32 async_ctxid;
};

/*
 * struct sched_ctx_range - define one ctx pos.
 * @begin: the start pos in ctxs of config.
 * @end: the end pos in ctxx of config.
 * @last: the last one which be distributed.
 * @valid: the region used flag.
 * @lock: lock the currentscheduling region.
 */
struct sched_ctx_region {
	__u32 begin;
	__u32 end;
	__u32 last;
	bool valid;
	pthread_mutex_t lock;
};

/*
 * wd_sched_info - define the context of the scheduler.
 * @ctx_region: define the map for the comp ctxs, using for quickly search.
 *              the x range: two(sync and async), the y range:
 *              two(e.g. comp and uncomp) the map[x][y]'s value is the ctx
 *              begin and end pos.
 * @valid: the region used flag.
 */
struct wd_sched_info {
	struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT];
	bool valid;
};

/*
 * wd_sched_ctx - define the context of the scheduler.
 * @policy: define the policy of the scheduler.
 * @numa_num: the max numa numbers of the scheduler.
 * @type_num: the max operation types of the scheduler.
 * @poll_func: the task's poll operation function.
 * @sched_info: the context of the scheduler
 */
struct wd_sched_ctx {
	__u32 policy;
	__u32 type_num;
	__u16  numa_num;
	user_poll_func poll_func;
	struct wd_sched_info sched_info[0];
};

static bool sched_key_valid(struct wd_sched_ctx *sched_ctx, const struct sched_key *key)
{
	if (key->numa_id >= sched_ctx->numa_num ||
	    key->mode >= SCHED_MODE_BUTT ||
	    key->type >= sched_ctx->type_num) {
		WD_ERR("invalid: sched key's numa: %d, mode: %u, type: %u!\n",
		       key->numa_id, key->mode, key->type);
		return false;
	}

	return true;
}

/*
 * sched_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
static struct sched_ctx_region *sched_get_ctx_range(struct wd_sched_ctx *sched_ctx,
						    const struct sched_key *key)
{
	struct wd_sched_info *sched_info;
	int numa_id;
	int type;

	sched_info = sched_ctx->sched_info;
	if (key->numa_id >= 0 &&
	    sched_info[key->numa_id].ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ctx_region[key->mode][key->type];

	/* If the key->numa_id is not exist, we should scan for a region */
	for (numa_id = 0; numa_id < sched_ctx->numa_num; numa_id++) {
		for (type = 0; type < sched_ctx->type_num; type++) {
			if (sched_info[numa_id].ctx_region[key->mode][type].valid)
				return &sched_info[numa_id].ctx_region[key->mode][type];
		}
	}

	return NULL;
}

/*
 * sched_get_next_pos_rr - Get next resource pos by RR schedule.
 * The second para is reserved for future.
 */
static __u32 sched_get_next_pos_rr(struct sched_ctx_region *region, void *para)
{
	__u32 pos;

	pthread_mutex_lock(&region->lock);

	pos = region->last;

	if (pos < region->end)
		region->last++;
	else
		region->last = region->begin;

	pthread_mutex_unlock(&region->lock);

	return pos;
}

/*
 * session_sched_init_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @sched_key: The key of schedule region.
 * @sched_mode: The sched async/sync mode.
 *
 * The user must init the schedule info through wd_sched_rr_instance
 */
static __u32 session_sched_init_ctx(handle_t h_sched_ctx, struct sched_key *key,
				    const int sched_mode)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_ctx_region *region = NULL;
	bool ret;

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return INVALID_POS;
	}

	key->mode = sched_mode;
	ret = sched_key_valid(sched_ctx, key);
	if (!ret)
		return INVALID_POS;

	region = sched_get_ctx_range(sched_ctx, key);
	if (!region)
		return INVALID_POS;

	return sched_get_next_pos_rr(region, NULL);
}

static int get_nearby_numa_id(handle_t h_sched_ctx)
{
#define MAX_NUMA_DISTANCE		1024
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct wd_sched_info *sched_info = sched_ctx->sched_info;
	int cpu = sched_getcpu();
	int node = numa_node_of_cpu(cpu);
	int dis = MAX_NUMA_DISTANCE;
	int i, tmp, valid_id = -1;

	for (i = 0; i < sched_ctx->numa_num; i++) {
		if (sched_info[i].valid) {
			tmp = numa_distance(node, i);
			if (dis > tmp) {
				valid_id = i;
				dis = tmp;
			}
		}
	}

	return valid_id;
}

static handle_t session_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	struct sched_params *param = (struct sched_params *)sched_param;
	struct sched_key *skey;

	skey = malloc(sizeof(struct sched_key));
	if (!skey) {
		WD_ERR("failed to alloc memory for session sched key!\n");
		return (handle_t)(-WD_ENOMEM);
	}

	if (!param || param->numa_id < 0) {
		memset(skey, 0, sizeof(struct sched_key));
		skey->numa_id = get_nearby_numa_id(h_sched_ctx);
		if (skey->numa_id < 0) {
			WD_ERR("failed to get valid sched numa region!\n");
			free(skey);
			return (handle_t)(-WD_ENOMEM);
		}
	} else {
		skey->type = param->type;
		skey->numa_id = param->numa_id;
	}

	skey->sync_ctxid = session_sched_init_ctx(h_sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid = session_sched_init_ctx(h_sched_ctx, skey, CTX_MODE_ASYNC);

	return (handle_t)skey;
}

/*
 * session_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @sched_key: The key of schedule region.
 * @sched_mode: The sched async/sync mode.
 *
 * The user must init the schedule info through session_sched_init
 */
static __u32 session_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
					    const int sched_mode)
{
	struct sched_key *key = (struct sched_key *)sched_key;

	if (unlikely(!h_sched_ctx || !key)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	/* return  in do task */
	if (sched_mode == CTX_MODE_SYNC)
		return key->sync_ctxid;
	return key->async_ctxid;
}

static int session_poll_region(struct wd_sched_ctx *sched_ctx, __u32 begin,
			       __u32 end, __u32 expect, __u32 *count)
{
	__u32 poll_num = 0;
	__u32 i;
	int ret;

	/* i is the pos of ctxs, the max is end */
	for (i = begin; i <= end; i++) {
		/*
		 * RR schedule, one time poll one package,
		 * poll_num is always not more than one here.
		 */
		ret = sched_ctx->poll_func(i, 1, &poll_num);
		if ((ret < 0) && (ret != -EAGAIN))
			return ret;
		else if (ret == -EAGAIN)
			continue;
		*count += poll_num;
		if (*count == expect)
			break;
	}

	return 0;
}

static int session_poll_policy_rr(struct wd_sched_ctx *sched_ctx, int numa_id,
				  __u32 expect, __u32 *count)
{
	struct sched_ctx_region **region = sched_ctx->sched_info[numa_id].ctx_region;
	__u32 begin, end;
	__u32 i;
	int ret;

	for (i = 0; i < sched_ctx->type_num; i++) {
		if (!region[SCHED_MODE_ASYNC][i].valid)
			continue;

		begin = region[SCHED_MODE_ASYNC][i].begin;
		end = region[SCHED_MODE_ASYNC][i].end;
		ret = session_poll_region(sched_ctx, begin, end, expect, count);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

/*
 * session_poll_policy - The polling policy matches the pick next ctx.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @cfg: The global resoure info.
 * @expect: User expect poll msg num.
 * @count: The actually poll num.
 *
 * The user must init the schedule info through wd_sched_rr_instance, the
 * func interval will not check the valid, becouse it will affect performance.
 */
static int session_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct wd_sched_info *sched_info;
	__u32 loop_time = 0;
	__u32 last_count = 0;
	__u16 i;
	int ret;

	if (unlikely(!count || !sched_ctx)) {
		WD_ERR("invalid: sched ctx is NULL or count is zero!\n");
		return -WD_EINVAL;
	}

	if (unlikely(sched_ctx->numa_num > NUMA_NUM_NODES)) {
		WD_ERR("invalid: ctx's numa number is %u!\n", sched_ctx->numa_num);
		return -WD_EINVAL;
	}

	sched_info = sched_ctx->sched_info;

	/*
	 * Try different numa's ctx if we can't receive any
	 * package last time, it is more efficient. In most
	 * bad situation, poll ends after MAX_POLL_TIMES loop.
	 */
	while (++loop_time < MAX_POLL_TIMES) {
		for (i = 0; i < sched_ctx->numa_num;) {
			/* If current numa is not valid, find next. */
			if (!sched_info[i].valid) {
				i++;
				continue;
			}

			last_count = *count;
			ret = session_poll_policy_rr(sched_ctx, i, expect, count);
			if (unlikely(ret))
				return ret;

			if (expect == *count)
				return 0;

			/*
			 * If no package is received, find next numa,
			 * otherwise, keep receiving packets at this node.
			 */
			if (last_count == *count)
				i++;
		}
	}

	return 0;
}

static struct wd_sched sched_table[SCHED_POLICY_BUTT] = {
	{
		.name = "RR scheduler",
		.sched_policy = SCHED_POLICY_RR,
		.sched_init = session_sched_init,
		.pick_next_ctx = session_sched_pick_next_ctx,
		.poll_policy = session_sched_poll_policy,
	},
};

int wd_sched_rr_instance(const struct wd_sched *sched, struct sched_params *param)
{
	struct wd_sched_info *sched_info = NULL;
	struct wd_sched_ctx *sched_ctx = NULL;
	__u8 type, mode;
	int  numa_id;

	if (!sched || !sched->h_sched_ctx || !param) {
		WD_ERR("invalid: sched or sched_params is NULL!\n");
		return -WD_EINVAL;
	}

	if (param->begin > param->end) {
		WD_ERR("invalid: sched_params's begin is larger than end!\n");
		return -WD_EINVAL;
	}

	numa_id = param->numa_id;
	type = param->type;
	mode = param->mode;
	sched_ctx = (struct wd_sched_ctx *)sched->h_sched_ctx;

	if (numa_id >= sched_ctx->numa_num || numa_id < 0) {
		WD_ERR("invalid: sched_ctx's numa_id is %d, numa_num is %u!\n",
		       numa_id, sched_ctx->numa_num);
		return -WD_EINVAL;
	}

	if (type >= sched_ctx->type_num) {
		WD_ERR("invalid: sched_ctx's type is %u, type_num is %u!\n",
		       type, sched_ctx->type_num);
		return -WD_EINVAL;
	}

	if (mode >= SCHED_MODE_BUTT) {
		WD_ERR("invalid: sched_ctx's mode is %u, mode_num is %d!\n",
		       mode, SCHED_MODE_BUTT);
		return -WD_EINVAL;
	}

	sched_info = sched_ctx->sched_info;

	if (!sched_info[numa_id].ctx_region[mode]) {
		WD_ERR("invalid: ctx_region is NULL, numa: %d, mode: %u!\n",
		       numa_id, mode);
		return -WD_EINVAL;
	}

	sched_info[numa_id].ctx_region[mode][type].begin = param->begin;
	sched_info[numa_id].ctx_region[mode][type].end = param->end;
	sched_info[numa_id].ctx_region[mode][type].last = param->begin;
	sched_info[numa_id].ctx_region[mode][type].valid = true;
	sched_info[numa_id].valid = true;

	pthread_mutex_init(&sched_info[numa_id].ctx_region[mode][type].lock,
			   NULL);

	return 0;
}

void wd_sched_rr_release(struct wd_sched *sched)
{
	struct wd_sched_info *sched_info;
	struct wd_sched_ctx *sched_ctx;
	int i, j;

	if (!sched)
		return;

	sched_ctx = (struct wd_sched_ctx *)sched->h_sched_ctx;
	if (!sched_ctx)
		goto out;

	sched_info = sched_ctx->sched_info;
	for (i = 0; i < sched_ctx->numa_num; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			if (sched_info[i].ctx_region[j]) {
				free(sched_info[i].ctx_region[j]);
				sched_info[i].ctx_region[j] = NULL;
			}
		}
	}

	free(sched_ctx);

out:
	free(sched);

	return;
}

static int numa_num_check(__u16 numa_num)
{
	int max_node;

	max_node = numa_max_node() + 1;
	if (max_node <= 0) {
		WD_ERR("invalid: numa max node is %d!\n", max_node);
		return -WD_EINVAL;
	}

	if (!numa_num || numa_num > max_node) {
		WD_ERR("invalid: numa number is %u!\n", numa_num);
		return -WD_EINVAL;
	}

	return 0;
}

struct wd_sched *wd_sched_rr_alloc(__u8 sched_type, __u8 type_num,
				   __u16 numa_num, user_poll_func func)
{
	struct wd_sched_info *sched_info;
	struct wd_sched_ctx *sched_ctx;
	struct wd_sched *sched;
	int i, j;

	if (numa_num_check(numa_num))
		return NULL;

	if (sched_type >= SCHED_POLICY_BUTT || !type_num) {
		WD_ERR("invalid: sched_type is %u or type_num is %u!\n", sched_type, type_num);
		return NULL;
	}

	sched = calloc(1, sizeof(struct wd_sched));
	if (!sched) {
		WD_ERR("failed to alloc memory for wd_sched!\n");
		return NULL;
	}

	sched_ctx = calloc(1, sizeof(struct wd_sched_ctx) +
			   sizeof(struct wd_sched_info) * numa_num);
	if (!sched_ctx) {
		WD_ERR("failed to alloc memory for sched_ctx!\n");
		goto err_out;
	}

	sched->h_sched_ctx = (handle_t)sched_ctx;
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

	sched->sched_init = sched_table[sched_type].sched_init;
	sched->pick_next_ctx = sched_table[sched_type].pick_next_ctx;
	sched->poll_policy = sched_table[sched_type].poll_policy;

	return sched;

err_out:
	wd_sched_rr_release(sched);
	return NULL;
}
