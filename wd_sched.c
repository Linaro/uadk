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
	__u8 ctx_prop;
	__u32 sync_ctxid;
	__u32 async_ctxid;
	__u32 sw_sync_ctxid;
	__u32 sw_async_ctxid;
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
	struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT]; // default as HW ctxs
	struct sched_ctx_region *ce_ctx_region[SCHED_MODE_BUTT];
	struct sched_ctx_region *sve_ctx_region[SCHED_MODE_BUTT];
	struct sched_ctx_region *soft_ctx_region[SCHED_MODE_BUTT];
	bool nm_valid;
	bool hw_valid;
	bool ce_valid;
	bool sve_valid;
	bool soft_valid;
};
#define SCHED_REGION_NUM	4
#define LOOP_SWITH_TIME	5

enum sched_send_type {
	SCHED_SEND_HW = 0,
	SCHED_SEND_SW = 1
};

struct wd_sched_balancer {
	int switch_slice;
	int next_send_type;
	__u32 hw_task_num;
	__u32 sw_task_num;
	__u32 hw_dfx_num;
	__u32 sw_dfx_num;
};

/*
 * wd_sched_ctx - define the context of the scheduler.
 * @policy: define the policy of the scheduler.
 * @numa_num: the max numa numbers of the scheduler.
 * @type_num: the max operation types of the scheduler.
 * @poll_func: the task's poll operation function.
 * @numa_map: a map of cpus to devices.
 * @sched_info: the context of the scheduler.
 */
struct wd_sched_ctx {
	__u32 policy;
	__u32 type_num;
	__u16  numa_num;
	user_poll_func poll_func;
	int numa_map[NUMA_NUM_NODES];
	struct wd_sched_balancer balancer;
	struct wd_sched_info sched_info[0];
};

static bool sched_key_valid(struct wd_sched_ctx *sched_ctx, const struct sched_key *key)
{
	if (key->numa_id >= sched_ctx->numa_num || key->mode >= SCHED_MODE_BUTT ||
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

	sched_info = sched_ctx->sched_info;
	if (key->numa_id >= 0 &&
	    sched_info[key->numa_id].ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ctx_region[key->mode][key->type];

	/* If the key->numa_id is not exist, we should scan for a region */
	for (numa_id = 0; numa_id < sched_ctx->numa_num; numa_id++) {
		if (sched_info[numa_id].ctx_region[key->mode][key->type].valid)
			return &sched_info[numa_id].ctx_region[key->mode][key->type];
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
static __u32 session_sched_init_ctx(struct wd_sched_ctx *sched_ctx, struct sched_key *key,
				    const int sched_mode)
{
	struct sched_ctx_region *region = NULL;
	bool ret;

	key->mode = sched_mode;
	ret = sched_key_valid(sched_ctx, key);
	if (!ret)
		return INVALID_POS;

	region = sched_get_ctx_range(sched_ctx, key);
	if (!region)
		return INVALID_POS;

	return sched_get_next_pos_rr(region, NULL);
}

static handle_t session_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_params *param = (struct sched_params *)sched_param;
	int cpu = sched_getcpu();
	int node = numa_node_of_cpu(cpu);
	struct sched_key *skey;

	if (node < 0) {
		WD_ERR("invalid: failed to get numa node!\n");
		return (handle_t)(-WD_EINVAL);
	}

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return (handle_t)(-WD_EINVAL);
	}

	skey = malloc(sizeof(struct sched_key));
	if (!skey) {
		WD_ERR("failed to alloc memory for session sched key!\n");
		return (handle_t)(-WD_ENOMEM);
	}

	if (!param) {
		memset(skey, 0, sizeof(struct sched_key));
		skey->numa_id = sched_ctx->numa_map[node];
		WD_INFO("session don't set scheduler parameters!\n");
	} else if (param->numa_id < 0) {
		skey->type = param->type;
		skey->numa_id = sched_ctx->numa_map[node];
	} else {
		skey->type = param->type;
		skey->numa_id = param->numa_id;
	}

	//if (skey->numa_id < 0) {
	//	WD_ERR("failed to get valid sched numa region!\n");
	//	goto out;
	//}
	skey->numa_id = 0;

	skey->sync_ctxid = session_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid = session_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	if (skey->sync_ctxid == INVALID_POS && skey->async_ctxid == INVALID_POS) {
		WD_ERR("failed to get valid sync_ctxid or async_ctxid!\n");
		goto out;
	}

	return (handle_t)skey;

out:
	free(skey);
	return (handle_t)(-WD_EINVAL);
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

	/* i is the pos of sched_ctxs, the max is end */
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

	if (unlikely(!count || !sched_ctx || !sched_ctx->poll_func)) {
		WD_ERR("invalid: sched ctx or poll_func is NULL or count is zero!\n");
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
			if (!sched_info[i].nm_valid) {
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

static handle_t sched_none_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 sched_none_pick_next_ctx(handle_t sched_ctx,
				      void *sched_key, const int sched_mode)
{
	return 0;
}

static int sched_none_poll_policy(handle_t h_sched_ctx,
				  __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	__u32 loop_times = MAX_POLL_TIMES + expect;
	__u32 poll_num = 0;
	int ret;

	if (!sched_ctx || !sched_ctx->poll_func) {
		WD_ERR("invalid: sched ctx or poll_func is NULL!\n");
		return -WD_EINVAL;
	}

	while (loop_times > 0) {
		/* Default use ctx 0 */
		loop_times--;
		ret = sched_ctx->poll_func(0, 1, &poll_num);
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

static handle_t sched_single_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 sched_single_pick_next_ctx(handle_t sched_ctx,
					void *sched_key, const int sched_mode)
{
#define CTX_ASYNC		1
#define CTX_SYNC		0

	if (sched_mode)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static int sched_single_poll_policy(handle_t h_sched_ctx,
				    __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	__u32 loop_times = MAX_POLL_TIMES + expect;
	__u32 poll_num = 0;
	int ret;

	if (!sched_ctx || !sched_ctx->poll_func) {
		WD_ERR("invalid: sched ctx or poll_func is NULL!\n");
		return -WD_EINVAL;
	}

	while (loop_times > 0) {
		/* Default async mode use ctx 1 */
		loop_times--;
		ret = sched_ctx->poll_func(1, 1, &poll_num);
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

/*
 * loop_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
static struct sched_ctx_region *loop_get_ctx_range(
	struct wd_sched_ctx *sched_ctx, const struct sched_key *key)
{
	struct wd_sched_info *sched_info;
	int ctx_prop = key->ctx_prop;
	int numa_id;

	sched_info = sched_ctx->sched_info;
	if (key->numa_id >= 0 && sched_info[key->numa_id].hw_valid && ctx_prop == UADK_CTX_HW &&
	    sched_info[key->numa_id].ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ctx_region[key->mode][key->type];
	else if (key->numa_id >= 0 && sched_info[key->numa_id].ce_valid && ctx_prop == UADK_CTX_CE_INS &&
	    sched_info[key->numa_id].ce_ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ce_ctx_region[key->mode][key->type];
	else if (key->numa_id >= 0 && sched_info[key->numa_id].sve_valid && ctx_prop == UADK_CTX_SVE_INS &&
	    sched_info[key->numa_id].sve_ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].sve_ctx_region[key->mode][key->type];
	else if (key->numa_id >= 0 && sched_info[key->numa_id].soft_valid && ctx_prop == UADK_CTX_SOFT &&
	    sched_info[key->numa_id].ce_ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ce_ctx_region[key->mode][key->type];

	/* If the key->numa_id is not exist, we should scan for a valid region */
	for (numa_id = 0; numa_id < sched_ctx->numa_num; numa_id++) {
		if (sched_info[numa_id].hw_valid)
			return &sched_info[numa_id].ctx_region[key->mode][key->type];

		if (sched_info[numa_id].ce_valid)
			return &sched_info[numa_id].ce_ctx_region[key->mode][key->type];

		if (sched_info[numa_id].sve_valid)
			return &sched_info[numa_id].sve_ctx_region[key->mode][key->type];

		if (sched_info[numa_id].soft_valid)
			return &sched_info[numa_id].soft_ctx_region[key->mode][key->type];
	}

	return NULL;
}

/*
 * loop_sched_init_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @sched_key: The key of schedule region.
 * @sched_mode: The sched async/sync mode.
 *
 * The user must init the schedule info through wd_sched_rr_instance
 */
static __u32 loop_sched_init_ctx(struct wd_sched_ctx *sched_ctx,
	struct sched_key *key, const int sched_mode)
{
	struct sched_ctx_region *region = NULL;
	bool ret;

	key->mode = sched_mode;
	ret = sched_key_valid(sched_ctx, key);
	if (!ret)
		return INVALID_POS;

	region = loop_get_ctx_range(sched_ctx, key);
	if (!region)
		return INVALID_POS;

	return sched_get_next_pos_rr(region, NULL);
}

static handle_t loop_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_params *param = (struct sched_params *)sched_param;
	int cpu = sched_getcpu();
	int node = numa_node_of_cpu(cpu);
	struct sched_key *skey;
	int ctx_prop;

	if (node < 0) {
		WD_ERR("invalid: failed to get numa node!\n");
		return (handle_t)(-WD_EINVAL);
	}

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return (handle_t)(-WD_EINVAL);
	}

	skey = malloc(sizeof(struct sched_key));
	if (!skey) {
		WD_ERR("failed to alloc memory for session sched key!\n");
		return (handle_t)(-WD_ENOMEM);
	}

	if (!param) {
		memset(skey, 0, sizeof(struct sched_key));
		//skey->numa_id = sched_ctx->numa_map[node];
		skey->numa_id = 0;
		skey->ctx_prop = UADK_CTX_HW;
		WD_INFO("loop don't set scheduler parameters!\n");
	} else if (param->numa_id < 0) {
		skey->type = param->type;
		//skey->numa_id = sched_ctx->numa_map[node];
		skey->numa_id = 0;
		skey->ctx_prop = param->ctx_prop;
	} else {
		skey->type = param->type;
		skey->numa_id = param->numa_id;
		skey->ctx_prop = param->ctx_prop;
	}

	//if (skey->numa_id < 0) {
	//	WD_ERR("failed to get valid sched numa region!\n");
	//	goto out;
	//}
	skey->numa_id = 0;

	skey->sync_ctxid = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	if (skey->sync_ctxid == INVALID_POS && skey->async_ctxid == INVALID_POS) {
		WD_ERR("failed to get valid sync_ctxid or async_ctxid!\n");
		goto out;
	}
	WD_ERR("sync_ctxid is: %u; async_ctxid is: %u!\n", skey->sync_ctxid, skey->async_ctxid);
	ctx_prop = skey->ctx_prop;
	skey->ctx_prop = UADK_CTX_CE_INS;
	skey->sw_sync_ctxid = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->sw_async_ctxid = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	skey->ctx_prop = ctx_prop;

	WD_ERR("fb ctxid is: %u, %u!\n", skey->sw_sync_ctxid, skey->sw_async_ctxid);

	return (handle_t)skey;

out:
	free(skey);
	return (handle_t)(-WD_EINVAL);
}

/*
 * loop_sched_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @sched_key: The key of schedule region.
 * @sched_mode: The sched async/sync mode.
 *
 * The user must init the schedule info through session_sched_init
 */
static __u32 loop_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
					 const int sched_mode)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_key *key = (struct sched_key *)sched_key;

	if (unlikely(!h_sched_ctx || !key)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (key->sw_sync_ctxid == INVALID_POS || key->sw_async_ctxid == INVALID_POS)
		return session_sched_pick_next_ctx(h_sched_ctx, sched_key, sched_mode);

	if (sched_mode == CTX_MODE_SYNC) {
		if (sched_ctx->balancer.switch_slice == LOOP_SWITH_TIME) {
			sched_ctx->balancer.switch_slice = 0;
			sched_ctx->balancer.hw_dfx_num++;
			/* run in HW */
			return key->sync_ctxid;
		} else {
			sched_ctx->balancer.switch_slice++;
			/* run  in soft CE */
			sched_ctx->balancer.sw_dfx_num++;
			return key->sw_sync_ctxid;
		}
	} else { // Async mode
		if (sched_ctx->balancer.hw_task_num > sched_ctx->balancer.sw_task_num)
			sched_ctx->balancer.next_send_type = SCHED_SEND_SW;
		else
			sched_ctx->balancer.next_send_type = SCHED_SEND_HW;

		if (sched_ctx->balancer.next_send_type == SCHED_SEND_HW) {
			/* run in HW */
			sched_ctx->balancer.hw_task_num++;
			sched_ctx->balancer.hw_dfx_num++;
			return key->async_ctxid;
		} else {
			/* run	in soft CE */
			sched_ctx->balancer.sw_task_num++;
			sched_ctx->balancer.sw_dfx_num++;
			return key->sw_async_ctxid;
		}
	}
}

static int loop_poll_policy_rr(struct wd_sched_ctx *sched_ctx, int numa_id,
				  __u32 expect, __u32 *count)
{
	struct sched_ctx_region **region;
	bool region_valid = false;
	__u32 begin, end;
	__u32 i, j;
	int ret;

	for (j = 0; j < SCHED_REGION_NUM; j++) {
		switch (j) {
		case 0:
			region = sched_ctx->sched_info[numa_id].ctx_region;
			region_valid = sched_ctx->sched_info[numa_id].hw_valid;
			break;
		case 1:
			region = sched_ctx->sched_info[numa_id].ce_ctx_region;
			region_valid = sched_ctx->sched_info[numa_id].ce_valid;
			break;
		case 2:
			region = sched_ctx->sched_info[numa_id].sve_ctx_region;
			region_valid = sched_ctx->sched_info[numa_id].sve_valid;
			break;
		case 3:
			region = sched_ctx->sched_info[numa_id].soft_ctx_region;
			region_valid = sched_ctx->sched_info[numa_id].soft_valid;
			break;
		}

		if (!region_valid)
			continue;

		for (i = 0; i < sched_ctx->type_num; i++) {
			if (!region[SCHED_MODE_ASYNC][i].valid)
				continue;

			begin = region[SCHED_MODE_ASYNC][i].begin;
			end = region[SCHED_MODE_ASYNC][i].end;
			//WD_ERR("session_poll_policy_rr from %u ---> %u!\n", begin, end);
			ret = session_poll_region(sched_ctx, begin, end, expect, count);
			if (unlikely(ret))
				return ret;
		}

		if (j == 0) {
			sched_ctx->balancer.hw_task_num -= *count;
		} else {
			sched_ctx->balancer.sw_task_num -= *count;
		}
	}

	return 0;
}

/*
 * loop_poll_policy - The polling policy matches the pick next ctx.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @cfg: The global resoure info.
 * @expect: User expect poll msg num.
 * @count: The actually poll num.
 *
 * The user must init the schedule info through wd_sched_rr_instance, the
 * func interval will not check the valid, becouse it will affect performance.
 */
static int loop_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct wd_sched_info *sched_info;
	__u32 loop_time = 0;
	__u32 last_count = 0;
	__u16 i;
	int ret;

	if (unlikely(!count || !sched_ctx || !sched_ctx->poll_func)) {
		WD_ERR("invalid: sched ctx or poll_func is NULL or count is zero!\n");
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
			if (!sched_info[i].nm_valid) {
				i++;
				continue;
			}

			last_count = *count;
			ret = loop_poll_policy_rr(sched_ctx, i, expect, count);
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

static handle_t loop_sched_rte_init(handle_t h_sched_ctx, void *sched_param)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_params *param = (struct sched_params *)sched_param;
	int cpu = sched_getcpu();
	int node = numa_node_of_cpu(cpu);
	struct sched_key *skey;
	int  ret;

	if (node < 0) {
		WD_ERR("invalid: failed to get numa node!\n");
		return (handle_t)(-WD_EINVAL);
	}

	if (!sched_ctx) {
		WD_ERR("invalid: sched ctx is NULL!\n");
		return (handle_t)(-WD_EINVAL);
	}

	skey = malloc(sizeof(struct sched_key));
	if (!skey) {
		WD_ERR("failed to alloc memory for session sched key!\n");
		return (handle_t)(-WD_ENOMEM);
	}

	if (!param) {
		memset(skey, 0, sizeof(struct sched_key));
		//skey->numa_id = sched_ctx->numa_map[node];
		skey->numa_id = 0;
		skey->ctx_prop = UADK_CTX_HW;
		WD_INFO("loop don't set scheduler parameters!\n");
	} else if (param->numa_id < 0) {
		skey->type = param->type;
		//skey->numa_id = sched_ctx->numa_map[node];
		skey->numa_id = 0;
		skey->ctx_prop = param->ctx_prop;
	} else {
		skey->type = param->type;
		skey->numa_id = param->numa_id;
		skey->ctx_prop = param->ctx_prop;
	}

	//if (skey->numa_id < 0) {
	//	WD_ERR("failed to get valid sched numa region!\n");
	//	goto out;
	//}
	skey->numa_id = 0;
	skey->sync_ctxid = INVALID_POS;
	skey->async_ctxid = INVALID_POS;
	skey->sw_sync_ctxid = INVALID_POS;
	skey->sw_async_ctxid = INVALID_POS;

	ret = sched_key_valid(sched_ctx, skey);
	if (!ret)
		goto out;

	return (handle_t)skey;
out:
	free(skey);
	return (handle_t)(-WD_EINVAL);
}

static __u32 loop_sched_rte_pick_ctx(struct wd_sched_ctx *sched_ctx,
	struct sched_key *key, const int sched_mode)
{
	struct sched_ctx_region *region = NULL;

	key->mode = sched_mode;
	region = loop_get_ctx_range(sched_ctx, key);
	if (!region)
		return INVALID_POS;

	return sched_get_next_pos_rr(region, NULL);
}

static __u32 loop_sched_rte_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
					 const int sched_mode)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_key *skey = (struct sched_key *)sched_key;
	__u32 rte_ctxid = INVALID_POS;

	if (unlikely(!h_sched_ctx || !skey)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (sched_ctx->balancer.switch_slice == LOOP_SWITH_TIME) {
		sched_ctx->balancer.switch_slice = 0;
		skey->ctx_prop = UADK_CTX_HW;
		/* run in HW */
		if (sched_mode == CTX_MODE_SYNC) {
			if (skey->sync_ctxid != INVALID_POS)
				rte_ctxid = skey->sync_ctxid;
			else {
				rte_ctxid = loop_sched_rte_pick_ctx(sched_ctx, skey, CTX_MODE_SYNC);
				skey->sync_ctxid = rte_ctxid;
			}
		} else {
			if (skey->async_ctxid != INVALID_POS)
				rte_ctxid = skey->async_ctxid;
			else {
				rte_ctxid = loop_sched_rte_pick_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
				skey->async_ctxid = rte_ctxid;
			}
		}
	} else {
		sched_ctx->balancer.switch_slice++;
		skey->ctx_prop = UADK_CTX_CE_INS;
		/* run  in soft CE */
		if (sched_mode == CTX_MODE_SYNC) {
			if (skey->sw_sync_ctxid != INVALID_POS)
				rte_ctxid = skey->sw_sync_ctxid;
			else {
				rte_ctxid = loop_sched_rte_pick_ctx(sched_ctx, skey, CTX_MODE_SYNC);
				skey->sw_sync_ctxid = rte_ctxid;
			}
		} else {
			if (skey->sw_async_ctxid != INVALID_POS)
				rte_ctxid = skey->sw_async_ctxid;
			else {
				rte_ctxid = loop_sched_rte_pick_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
				skey->sw_async_ctxid = rte_ctxid;
			}
		}
	}

	return rte_ctxid;
}

static struct wd_sched sched_table[SCHED_POLICY_BUTT] = {
	{
		.name = "RR scheduler",
		.sched_policy = SCHED_POLICY_RR,
		.sched_init = session_sched_init,
		.pick_next_ctx = session_sched_pick_next_ctx,
		.poll_policy = session_sched_poll_policy,
	}, {
		.name = "None scheduler",
		.sched_policy = SCHED_POLICY_NONE,
		.sched_init = sched_none_init,
		.pick_next_ctx = sched_none_pick_next_ctx,
		.poll_policy = sched_none_poll_policy,
	}, {
		.name = "Single scheduler",
		.sched_policy = SCHED_POLICY_SINGLE,
		.sched_init = sched_single_init,
		.pick_next_ctx = sched_single_pick_next_ctx,
		.poll_policy = sched_single_poll_policy,
	}, {
		.name = "Loop scheduler",
		.sched_policy = SCHED_POLICY_LOOP,
		.sched_init = loop_sched_init,
		.pick_next_ctx = loop_sched_pick_next_ctx,
		.poll_policy = loop_sched_poll_policy,
	}, {
		.name = "Loop rte scheduler",
		.sched_policy = SCHED_POLICY_RTE_LOOP,
		.sched_init = loop_sched_rte_init,
		.pick_next_ctx = loop_sched_rte_pick_next_ctx,
		.poll_policy = loop_sched_poll_policy,
	}, 
};

static int wd_sched_get_nearby_numa_id(struct wd_sched_info *sched_info, int node, int numa_num)
{
	int dis = INT32_MAX;
	int valid_id = -1;
	int i, tmp;

	for (i = 0; i < numa_num; i++) {
		if (sched_info[i].nm_valid) {
			tmp = numa_distance(node, i);
			if (dis > tmp) {
				valid_id = i;
				dis = tmp;
			}
		}
	}

	return valid_id;
}

static void wd_sched_map_cpus_to_dev(struct wd_sched_ctx *sched_ctx)
{
	struct wd_sched_info *sched_info = sched_ctx->sched_info;
	int i, numa_num = sched_ctx->numa_num;
	int *numa_map = sched_ctx->numa_map;

	for (i = 0; i < numa_num; i++) {
		if (sched_info[i].nm_valid)
			numa_map[i] = i;
		else
			numa_map[i] = wd_sched_get_nearby_numa_id(sched_info, i, numa_num);
	}
}

int wd_sched_rr_instance(const struct wd_sched *sched,
			 struct sched_params *param)
{
	struct wd_sched_info *sched_info = NULL;
	struct wd_sched_ctx *sched_ctx = NULL;
	__u8 type, mode, prop;
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

	prop = param->ctx_prop;
	if (prop > UADK_CTX_SOFT) {
		WD_ERR("invalid: sched_ctx's prop is %u\n", prop);
		return -WD_EINVAL;
	}

	sched_info = sched_ctx->sched_info;

	if (!sched_info[numa_id].ctx_region[mode]) {
		WD_ERR("invalid: ctx_region is NULL, numa: %d, mode: %u!\n",
		       numa_id, mode);
		return -WD_EINVAL;
	}

	WD_ERR("instance uadk ctx: numa id: %u, mode: %u, type: %u!\n", numa_id, mode, type);

	switch (prop) {
	case UADK_CTX_HW:
		sched_info[numa_id].ctx_region[mode][type].begin = param->begin;
		sched_info[numa_id].ctx_region[mode][type].end = param->end;
		sched_info[numa_id].ctx_region[mode][type].last = param->begin;
		sched_info[numa_id].ctx_region[mode][type].valid = true;
		sched_info[numa_id].hw_valid = true;
		pthread_mutex_init(&sched_info[numa_id].ctx_region[mode][type].lock,
			   NULL);
		WD_ERR("instance HW ctx: begin: %u ----> end: %u!\n", param->begin, param->end);
		break;
	case UADK_CTX_CE_INS:
		sched_info[numa_id].ce_ctx_region[mode][type].begin = param->begin;
		sched_info[numa_id].ce_ctx_region[mode][type].end = param->end;
		sched_info[numa_id].ce_ctx_region[mode][type].last = param->begin;
		sched_info[numa_id].ce_ctx_region[mode][type].valid = true;
		sched_info[numa_id].ce_valid = true;
		pthread_mutex_init(&sched_info[numa_id].ce_ctx_region[mode][type].lock,
			   NULL);
		WD_ERR("instance CE ctx: begin: %u ----> end: %u!\n", param->begin, param->end);
		break;
	case UADK_CTX_SVE_INS:
		sched_info[numa_id].sve_ctx_region[mode][type].begin = param->begin;
		sched_info[numa_id].sve_ctx_region[mode][type].end = param->end;
		sched_info[numa_id].sve_ctx_region[mode][type].last = param->begin;
		sched_info[numa_id].sve_ctx_region[mode][type].valid = true;
		sched_info[numa_id].sve_valid = true;
		pthread_mutex_init(&sched_info[numa_id].sve_ctx_region[mode][type].lock,
			   NULL);
		WD_ERR("instance SVE ctx: begin: %u ----> end: %u!\n", param->begin, param->end);
		break;
	case UADK_CTX_SOFT:
		sched_info[numa_id].soft_ctx_region[mode][type].begin = param->begin;
		sched_info[numa_id].soft_ctx_region[mode][type].end = param->end;
		sched_info[numa_id].soft_ctx_region[mode][type].last = param->begin;
		sched_info[numa_id].soft_ctx_region[mode][type].valid = true;
		sched_info[numa_id].soft_valid = true;
		pthread_mutex_init(&sched_info[numa_id].soft_ctx_region[mode][type].lock,
			   NULL);
		WD_ERR("instance Soft ctx: begin: %u ----> end: %u!\n", param->begin, param->end);
		break;
	}
	sched_info[numa_id].nm_valid = true;
	wd_sched_map_cpus_to_dev(sched_ctx);

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
		goto ctx_out;

	sched_info = sched_ctx->sched_info;
	if (!sched_info)
		goto info_out;

	for (i = 0; i < sched_ctx->numa_num; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			if (sched_info[i].ctx_region[j]) {
				free(sched_info[i].ctx_region[j]);
				sched_info[i].ctx_region[j] = NULL;
			}

			if (sched_info[i].ce_ctx_region[j]) {
				free(sched_info[i].ce_ctx_region[j]);
				sched_info[i].ce_ctx_region[j] = NULL;
			}

			if (sched_info[i].sve_ctx_region[j]) {
				free(sched_info[i].sve_ctx_region[j]);
				sched_info[i].sve_ctx_region[j] = NULL;
			}

			if (sched_info[i].soft_ctx_region[j]) {
				free(sched_info[i].soft_ctx_region[j]);
				sched_info[i].soft_ctx_region[j] = NULL;
			}
		}
	}

	/* Release sched dfx info */
	WD_ERR("scheduler balance hw task num: %u, sw task num: %u\n",
		sched_ctx->balancer.hw_dfx_num, sched_ctx->balancer.sw_dfx_num);

info_out:
	free(sched_ctx);
ctx_out:
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

static int wd_sched_region_init(struct wd_sched_ctx *sched_ctx,
	__u8 type_num, __u16 numa_num)
{
	struct wd_sched_info *sched_info = sched_ctx->sched_info;
	int i, j;
	int ri, idx;

	for (i = 0; i < numa_num; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			sched_info[i].ctx_region[j] =
			calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!sched_info[i].ctx_region[j])
				goto hw_err;

			sched_info[i].ce_ctx_region[j] =
			calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!sched_info[i].ce_ctx_region[j])
				goto ce_err;

			sched_info[i].sve_ctx_region[j] =
			calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!sched_info[i].sve_ctx_region[j])
				goto sve_err;

			sched_info[i].soft_ctx_region[j] =
			calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!sched_info[i].soft_ctx_region[j])
				goto soft_err;
		}
		sched_info[i].nm_valid = false;
		sched_info[i].hw_valid = false;
		sched_info[i].ce_valid = false;
		sched_info[i].sve_valid = false;
		sched_info[i].soft_valid = false;
	}

	return 0;

soft_err:
	free(sched_info[i].sve_ctx_region[j]);
	sched_info[i].sve_ctx_region[j] = NULL;
sve_err:
	free(sched_info[i].ce_ctx_region[j]);
	sched_info[i].ce_ctx_region[j] = NULL;
ce_err:
	free(sched_info[i].ctx_region[j]);
	sched_info[i].ctx_region[j] = NULL;
hw_err:
	for (ri = i - 1; ri >= 0; ri--) {
		for (idx = 0; idx < SCHED_MODE_BUTT; idx++) {
			free(sched_info[ri].ctx_region[idx]);
			sched_info[ri].ctx_region[idx] = NULL;

			free(sched_info[ri].ce_ctx_region[idx]);
			sched_info[ri].ce_ctx_region[idx] = NULL;

			free(sched_info[ri].sve_ctx_region[idx]);
			sched_info[ri].sve_ctx_region[idx] = NULL;

			free(sched_info[ri].soft_ctx_region[idx]);
			sched_info[ri].soft_ctx_region[idx] = NULL;
		}
	}

	return -WD_EINVAL;
}

struct wd_sched *wd_sched_rr_alloc(__u8 sched_type, __u8 type_num,
				   __u16 numa_num, user_poll_func func)
{
	struct wd_sched_ctx *sched_ctx;
	struct wd_sched *sched;
	int ret;

	if (numa_num_check(numa_num))
		return NULL;

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

	sched_ctx = calloc(1, sizeof(struct wd_sched_ctx) +
			   sizeof(struct wd_sched_info) * numa_num);
	if (!sched_ctx) {
		WD_ERR("failed to alloc memory for sched_ctx!\n");
		goto err_out;
	}
	sched_ctx->numa_num = numa_num;

	sched->h_sched_ctx = (handle_t)sched_ctx;
	if (sched_type == SCHED_POLICY_NONE ||
	    sched_type == SCHED_POLICY_SINGLE)
		goto simple_ok;

	ret = wd_sched_region_init(sched_ctx, type_num, numa_num);
	if (ret)
		goto err_out;

simple_ok:
	sched_ctx->poll_func = func;
	sched_ctx->policy = sched_type;
	sched_ctx->type_num = type_num;
	memset(sched_ctx->numa_map, -1, sizeof(int) * NUMA_NUM_NODES);

	sched->sched_init = sched_table[sched_type].sched_init;
	sched->pick_next_ctx = sched_table[sched_type].pick_next_ctx;
	sched->poll_policy = sched_table[sched_type].poll_policy;
	sched->sched_policy = sched_type;
	sched->name = sched_table[sched_type].name;

	return sched;

err_out:
	wd_sched_rr_release(sched);
	return NULL;
}
