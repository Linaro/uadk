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

struct wd_sched_balancer {
	int switch_slice;
	__u32 hw_task_num;
	__u32 sw_task_num;
	__u32 hw_dfx_num;
	__u32 sw_dfx_num;
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
	__u32 sync_ctxid[UADK_CTX_MAX];
	__u32 async_ctxid[UADK_CTX_MAX];
	struct wd_sched_balancer balancer;
};
#define LOOP_SWITH_TIME	5

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
 * @region_type: the region's property
 * @next_info: next scheduling domain
 */
struct wd_sched_info {
	struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT]; // default as HW ctxs
	int region_type;
	bool valid;
	struct wd_sched_info *next_info;
};
#define MAX_SKEY_REGION_NUM	64

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

	__u32 skey_num;
	pthread_mutex_t skey_lock;
	struct sched_key *skey[MAX_SKEY_REGION_NUM]; // supports up to 64 threads region
	__u32 poll_tid[MAX_SKEY_REGION_NUM];

	struct wd_sched_balancer balancer;
	struct wd_sched_info sched_info[0]; // It's an block memory based on numa nodes
};

#define nop() asm volatile("nop")
static void delay_us(int ustime)
{
	int cycle = 2600; // for 2.6GHz CPU
	int i, j;

	for (i = 0; i < ustime; i++) {
		for (j = 0; j < cycle; j++)
			nop();
	}
	usleep(1);
}

static void sched_skey_param_init(struct wd_sched_ctx *sched_ctx, struct sched_key *skey)
{
	__u32 i;

	pthread_mutex_lock(&sched_ctx->skey_lock);
	for (i = 0; i < MAX_SKEY_REGION_NUM; i++) {
		if (sched_ctx->skey[i] == NULL) {
			sched_ctx->skey[i] = skey;
			sched_ctx->skey_num++;
			pthread_mutex_unlock(&sched_ctx->skey_lock);
			WD_ERR("success: get valid skey node[%u]!\n", i);
			return;
		}
	}
	pthread_mutex_unlock(&sched_ctx->skey_lock);
	WD_ERR("invalid: skey node number is too much!\n");
}

static struct sched_key *sched_get_poll_skey(struct wd_sched_ctx *sched_ctx)
{
	__u32 tid = pthread_self();
	__u16 i, tidx = 0;

	/* Delay processing within 17us is performed */
	delay_us(tid % 17);
	/* Set mapping relationship between the recv tid and the send skey id */
	for (i = 0; i < sched_ctx->skey_num; i++) {
		if (sched_ctx->poll_tid[i] == tid) {
			//WD_ERR("poll tid ---> skey id:<%u, %u>!\n", i, tid);
			tidx = i;
			break;
		} else if (sched_ctx->poll_tid[i] == 0) {
			pthread_mutex_lock(&sched_ctx->skey_lock);
			if (sched_ctx->poll_tid[i] == 0) {
				//WD_ERR("poll tid<%u> <---> skey id:<%u>!\n", i, tid);
				sched_ctx->poll_tid[i] = tid;
				tidx = i;
			} else {
				pthread_mutex_unlock(&sched_ctx->skey_lock);
				return NULL;
			}
			pthread_mutex_unlock(&sched_ctx->skey_lock);
			break;
		}
	}

	return sched_ctx->skey[tidx];
}

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

	skey->sync_ctxid[0] = session_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid[0] = session_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	if (skey->sync_ctxid[0] == INVALID_POS && skey->async_ctxid[0] == INVALID_POS) {
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
		return key->sync_ctxid[0];
	return key->async_ctxid[0];
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

static struct sched_ctx_region *loop_get_near_region(
	struct wd_sched_ctx *sched_ctx, const struct sched_key *key)
{
	struct wd_sched_info *sched_info, *demon_info;
	int numa_id;

	/* If the key->numa_id is not exist, we should scan for a valid region */
	for (numa_id = 0; numa_id < sched_ctx->numa_num; numa_id++) {
		sched_info = sched_ctx->sched_info + numa_id;
		if (sched_info->valid) {
			demon_info = sched_info;
			while (demon_info) {
				if (demon_info->valid)
					return &demon_info->ctx_region[key->mode][key->type];
				demon_info = demon_info->next_info;
			}
		}
	}

	return NULL;
}

/*
 * loop_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
static struct sched_ctx_region *loop_get_ctx_range(
	struct wd_sched_ctx *sched_ctx, const struct sched_key *key)
{
	struct wd_sched_info *sched_region, *sched_info;
	int ctx_prop = key->ctx_prop;

	if (key->numa_id < 0)
		return loop_get_near_region(sched_ctx, key);

	sched_region = sched_ctx->sched_info;
	sched_info = sched_region + key->numa_id;
	while (sched_info) {
		if (sched_info->valid && ctx_prop == sched_info->region_type &&
	    	     sched_info->ctx_region[key->mode][key->type].valid)
			return &sched_info->ctx_region[key->mode][key->type];
		sched_info = sched_info->next_info;
	}

	WD_ERR("failed to get valid sched region!\n");
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

	memset(&skey->sync_ctxid, INVALID_POS, sizeof(__u32) * UADK_CTX_MAX);
	memset(&skey->async_ctxid, INVALID_POS, sizeof(__u32) * UADK_CTX_MAX);
	skey->sync_ctxid[0] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid[0] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	if (skey->sync_ctxid[0] == INVALID_POS && skey->async_ctxid[0] == INVALID_POS) {
		WD_ERR("failed to get valid sync_ctxid or async_ctxid!\n");
		goto out;
	}
	WD_ERR("sync_ctxid is: %u; async_ctxid is: %u!\n", skey->sync_ctxid[0], skey->async_ctxid[0]);
	ctx_prop = skey->ctx_prop;
	skey->ctx_prop = UADK_CTX_CE_INS;
	skey->sync_ctxid[UADK_CTX_CE_INS] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid[UADK_CTX_CE_INS] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	skey->ctx_prop = ctx_prop;
	if (skey->sync_ctxid[1] == INVALID_POS && skey->async_ctxid[1] == INVALID_POS) {
		WD_ERR("failed to get valid CE sync_ctxid or async_ctxid!\n");
		skey->sync_ctxid[1] = skey->sync_ctxid[0];
		skey->async_ctxid[1] = skey->async_ctxid[0];
	}

	WD_ERR("sw ctxid is: %u, %u!\n", skey->sync_ctxid[1], skey->async_ctxid[1]);

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
	struct wd_sched_balancer *balancer = &sched_ctx->balancer;

	if (unlikely(!h_sched_ctx || !key)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (key->sync_ctxid[UADK_CTX_HW] == INVALID_POS ||
	     key->async_ctxid[UADK_CTX_HW] == INVALID_POS)
		return session_sched_pick_next_ctx(h_sched_ctx, sched_key, sched_mode);

	if (sched_mode == CTX_MODE_SYNC) {
		if (balancer->switch_slice == LOOP_SWITH_TIME) {
			balancer->switch_slice = 0;
			balancer->hw_dfx_num++;
			/* run in HW */
			return key->sync_ctxid[UADK_CTX_HW];
		} else {
			balancer->switch_slice++;
			/* run  in soft CE */
			balancer->sw_dfx_num++;
			return key->sync_ctxid[UADK_CTX_CE_INS];
		}
	}
	// Async mode
	if (balancer->hw_task_num > balancer->sw_task_num >> 1) {
		/* run	in soft CE */
		balancer->sw_task_num++;

		return key->async_ctxid[UADK_CTX_CE_INS];
	} else {
		/* run in HW */
		balancer->hw_task_num++;

		return key->async_ctxid[UADK_CTX_HW];
	}
}

static int loop_poll_policy_rr(struct wd_sched_ctx *sched_ctx, int numa_id,
				  __u32 expect, __u32 *count)
{
	struct wd_sched_balancer *balancer = &sched_ctx->balancer;
	struct wd_sched_info *sched_info, *cur_info, *pnext_info;
	struct sched_ctx_region **region;
	__u32 begin, end;
	__u32 i;
	int ret;

	sched_info = sched_ctx->sched_info;
	cur_info = sched_info + numa_id;
	pnext_info = cur_info;
	while (pnext_info)	{
		if (!pnext_info->valid) {
			pnext_info = pnext_info->next_info;
			continue;
		}

		region = pnext_info->ctx_region;
		for (i = 0; i < sched_ctx->type_num; i++) {
			if (!region[SCHED_MODE_ASYNC][i].valid)
				continue;

			begin = region[SCHED_MODE_ASYNC][i].begin;
			end = region[SCHED_MODE_ASYNC][i].end;
			// WD_ERR("session_poll_policy_rr numa: %d,  from %u ---> %u!\n", numa_id, begin, end);
			ret = session_poll_region(sched_ctx, begin, end, expect, count);
			if (unlikely(ret))
				return ret;
		}

		/* run in HW */
		if (pnext_info->region_type == UADK_CTX_HW) {
			if (balancer->hw_task_num > *count)
				balancer->hw_task_num -= *count;
			else
				balancer->hw_task_num = 0;
			balancer->hw_dfx_num += *count;
		} else {
			if (balancer->sw_task_num > *count)
				balancer->sw_task_num -= *count;
			else
				balancer->sw_task_num = 0;
			balancer->sw_dfx_num += *count;
		}

		pnext_info = pnext_info->next_info;
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
			if (!sched_info[i].valid) {
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

static handle_t skey_sched_init(handle_t h_sched_ctx, void *sched_param)
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
	memset(&skey->balancer, 0x0, sizeof(struct wd_sched_balancer));
	skey->numa_id = 0;

	memset(&skey->sync_ctxid, INVALID_POS, sizeof(__u32) * UADK_CTX_MAX);
	memset(&skey->async_ctxid, INVALID_POS, sizeof(__u32) * UADK_CTX_MAX);
	skey->sync_ctxid[0] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid[0] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	if (skey->sync_ctxid[0] == INVALID_POS && skey->async_ctxid[0] == INVALID_POS) {
		WD_ERR("failed to get valid sync_ctxid or async_ctxid!\n");
		goto out;
	}
	WD_ERR("sync_ctxid is: %u; async_ctxid is: %u!\n", skey->sync_ctxid[0], skey->async_ctxid[0]);
	ctx_prop = skey->ctx_prop;
	skey->ctx_prop = UADK_CTX_CE_INS;
	skey->sync_ctxid[UADK_CTX_CE_INS] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid[UADK_CTX_CE_INS] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);
	skey->ctx_prop = ctx_prop;
	if (skey->sync_ctxid[1] == INVALID_POS && skey->async_ctxid[1] == INVALID_POS) {
		WD_ERR("failed to get valid CE sync_ctxid or async_ctxid!\n");
		skey->sync_ctxid[1] = skey->sync_ctxid[0];
		skey->async_ctxid[1] = skey->async_ctxid[0];
	}

	sched_skey_param_init(sched_ctx, skey);
	WD_ERR("sw ctxid is: %u, %u!\n", skey->sync_ctxid[1], skey->async_ctxid[1]);

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
static __u32 skey_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
					 const int sched_mode)
{
	struct sched_key *skey = (struct sched_key *)sched_key;

	if (unlikely(!h_sched_ctx || !skey)) {
		WD_ERR("invalid: sched ctx or key is NULL!\n");
		return INVALID_POS;
	}

	if (skey->sync_ctxid[UADK_CTX_HW] == INVALID_POS ||
	     skey->async_ctxid[UADK_CTX_HW] == INVALID_POS)
		return session_sched_pick_next_ctx(h_sched_ctx, sched_key, sched_mode);

	// Async mode
	if (sched_mode == CTX_MODE_ASYNC) {
		if (skey->balancer.hw_task_num > (skey->balancer.sw_task_num >> 1)) {
			/* run	in soft CE */
			skey->balancer.sw_task_num++;
			return skey->async_ctxid[UADK_CTX_CE_INS];
		 } else {
			/* run in HW */
			skey->balancer.hw_task_num++;
			return skey->async_ctxid[UADK_CTX_HW];
		 }
	}

	if (skey->balancer.switch_slice == LOOP_SWITH_TIME) {
		skey->balancer.switch_slice = 0;
		skey->balancer.hw_dfx_num++;
		/* run in HW */
		return skey->sync_ctxid[UADK_CTX_HW];
	} else {
		skey->balancer.switch_slice++;
		skey->balancer.sw_dfx_num++;
		/* run  in soft CE */
		return skey->sync_ctxid[UADK_CTX_CE_INS];
	}
}

static int skey_poll_ctx(struct wd_sched_ctx *sched_ctx, struct sched_key *skey,
			       __u32 expect, __u32 *count)
{
	__u32 hw_num = 0;
	__u32 sw_num = 0;
	__u32 poll_num;
	int i, ret;

	/*
	 * Collect hardware messages first, multi-threading performance is better;
	 * Collect software packets first, single-thread performance is better
	 */
	for (i = UADK_CTX_MAX - 1; i >= 0; i--) {
		if (skey->async_ctxid[i] == INVALID_POS)
			continue;

		poll_num = 0;
		ret = sched_ctx->poll_func(skey->async_ctxid[i], expect, &poll_num);
		if ((ret < 0) && (ret != -EAGAIN))
			return ret;
		else if (poll_num == 0)
			continue;

		if (i == 0)
			hw_num += poll_num;
		else
			sw_num += poll_num;
	}

	*count = *count + hw_num + sw_num;
	if (hw_num > 0) {
		if (skey->balancer.hw_task_num > hw_num)
			skey->balancer.hw_task_num -= hw_num;
		else
			skey->balancer.hw_task_num = 0;
		skey->balancer.hw_dfx_num += hw_num;
	}
	if (sw_num > 0) {
		if (skey->balancer.sw_task_num > sw_num)
			skey->balancer.sw_task_num -= sw_num;
		else
			skey->balancer.sw_task_num = 0;
		skey->balancer.sw_dfx_num += sw_num;
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
static int skey_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_key *skey;
	int ret;

	if (unlikely(!count || !sched_ctx || !sched_ctx->poll_func)) {
		WD_ERR("invalid: sched ctx or poll_func is NULL or count is zero!\n");
		return -WD_EINVAL;
	}

	skey = sched_get_poll_skey(sched_ctx);
	if (!skey)
		return -WD_EAGAIN;

	ret = skey_poll_ctx(sched_ctx, skey, expect, count);
	if (unlikely(ret))
		return ret;

	return 0;
}

static handle_t instr_sched_init(handle_t h_sched_ctx, void *sched_param)
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
		//skey->numa_id = sched_ctx->numa_map[node];
		skey->numa_id = 0;
		skey->ctx_prop = UADK_CTX_CE_INS;
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

	memset(&skey->sync_ctxid, INVALID_POS, sizeof(__u32) * UADK_CTX_MAX);
	memset(&skey->async_ctxid, INVALID_POS, sizeof(__u32) * UADK_CTX_MAX);
	skey->sync_ctxid[UADK_CTX_CE_INS] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_SYNC);
	skey->async_ctxid[UADK_CTX_CE_INS] = loop_sched_init_ctx(sched_ctx, skey, CTX_MODE_ASYNC);

	sched_skey_param_init(sched_ctx, skey);
	WD_ERR("sw ctxid is: %u, %u!\n", skey->sync_ctxid[1], skey->async_ctxid[1]);

	return (handle_t)skey;
}

/*
 * loop_sched_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @sched_key: The key of schedule region.
 * @sched_mode: The sched async/sync mode.
 *
 * The user must init the schedule info through session_sched_init
 */
static __u32 instr_sched_pick_next_ctx(handle_t h_sched_ctx, void *sched_key,
					 const int sched_mode)
{
	struct sched_key *key = (struct sched_key *)sched_key;

	//if (unlikely(!h_sched_ctx || !key)) {
	//	WD_ERR("invalid: sched ctx or key is NULL!\n");
	//	return INVALID_POS;
	//}

	key->balancer.sw_dfx_num++;
	if (sched_mode == CTX_MODE_SYNC) {
		/* run  in soft CE */
		return key->sync_ctxid[UADK_CTX_CE_INS];
	}
	// Async mode
	/* run	in soft CE */
	return key->async_ctxid[UADK_CTX_CE_INS];
}

static int instr_poll_policy_rr(struct wd_sched_ctx *sched_ctx, struct sched_key *skey,
				  __u32 expect, __u32 *count)
{
	__u32 recv_cnt, ctx_id;
	int ret;

	//WD_ERR("success: sched skey num: %u!\n", i);
	recv_cnt = 0;
	ctx_id = skey->async_ctxid[UADK_CTX_CE_INS];
	ret = sched_ctx->poll_func(ctx_id, expect, &recv_cnt);
	if ((ret < 0) && (ret != -EAGAIN))
		return ret;
	*count += recv_cnt;
	//WD_ERR("success: sched recv task num: %u!\n", *count);

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
static int instr_sched_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	struct wd_sched_ctx *sched_ctx = (struct wd_sched_ctx *)h_sched_ctx;
	struct sched_key *skey;
	int ret;

	if (unlikely(!count || !sched_ctx || !sched_ctx->poll_func)) {
		WD_ERR("invalid: sched ctx or poll_func is NULL or count is zero!\n");
		return -WD_EINVAL;
	}

	/* First poll the skey is NULL */
	skey = sched_get_poll_skey(sched_ctx);
	if (!skey)
		return -WD_EAGAIN;

	ret = instr_poll_policy_rr(sched_ctx, skey, expect, count);
	if (unlikely(ret))
		return ret;

	return ret;
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
		.name = "Hungry scheduler",
		.sched_policy = SCHED_POLICY_HUNGRY,
		.sched_init = skey_sched_init,
		.pick_next_ctx = skey_sched_pick_next_ctx,
		.poll_policy = skey_sched_poll_policy,
	},  {
		.name = "Instr scheduler",
		.sched_policy = SCHED_POLICY_INSTR,
		.sched_init = instr_sched_init,
		.pick_next_ctx = instr_sched_pick_next_ctx,
		.poll_policy = instr_sched_poll_policy,
	}, 
};

static int wd_sched_get_nearby_numa_id(struct wd_sched_info *sched_info, int node, int numa_num)
{
	int dis = INT32_MAX;
	int valid_id = -1;
	int i, tmp;

	for (i = 0; i < numa_num; i++) {
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

static void wd_sched_map_cpus_to_dev(struct wd_sched_ctx *sched_ctx)
{
	struct wd_sched_info *sched_info = sched_ctx->sched_info;
	int i, numa_num = sched_ctx->numa_num;
	int *numa_map = sched_ctx->numa_map;

	for (i = 0; i < numa_num; i++) {
		if (sched_info[i].valid)
			numa_map[i] = i;
		else
			numa_map[i] = wd_sched_get_nearby_numa_id(sched_info, i, numa_num);
	}
}

static int wd_sched_region_instance(struct wd_sched_info *sched_info,
	struct sched_params *param)
{
	struct wd_sched_info *next_info;
	__u8 type, mode;

	type = param->type;
	mode = param->mode;
	next_info = sched_info;
	while (next_info) {
		if (next_info->region_type == param->ctx_prop) {
			next_info->ctx_region[mode][type].begin = param->begin;
			next_info->ctx_region[mode][type].end = param->end;
			next_info->ctx_region[mode][type].last = param->begin;
			next_info->ctx_region[mode][type].valid = true;
			next_info->valid = true;
			pthread_mutex_init(&next_info->ctx_region[mode][type].lock, NULL);
			WD_ERR("instance numa<%d>, property<%d>, mode<%u>, type<%u> ctx: begin: %u ----> end: %u!\n",
				param->numa_id, param->ctx_prop, mode, type, param->begin, param->end);
			return 0;
		}
		next_info = next_info->next_info;
	}

	return -WD_EINVAL;
}

int wd_sched_rr_instance(const struct wd_sched *sched,
			 struct sched_params *param)
{
	struct wd_sched_info *sched_info = NULL;
	struct wd_sched_ctx *sched_ctx = NULL;
	__u8 type, mode;
	int  numa_id, ret;

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

	if (param->ctx_prop > UADK_CTX_SOFT) {
		WD_ERR("invalid: sched_ctx's prop is %d\n", param->ctx_prop);
		return -WD_EINVAL;
	}

	sched_info = sched_ctx->sched_info;
	if (!sched_info[numa_id].ctx_region[mode]) {
		WD_ERR("invalid: ctx_region is NULL, numa: %d, mode: %u!\n",
		       numa_id, mode);
		return -WD_EINVAL;
	}

	ret = wd_sched_region_instance(&sched_info[numa_id], param);
	if (ret) {
		WD_ERR("failed to instance ctx_region!\n");
		return ret;
	}

	wd_sched_map_cpus_to_dev(sched_ctx);

	return 0;
}

static void wd_sched_region_release(struct wd_sched_ctx *sched_ctx)
{
	struct wd_sched_info *sched_info, *next_info, *cur_info;
	__u32 i, j;

	sched_info = sched_ctx->sched_info;
	if (!sched_info)
		return;

	for (i = 0; i < sched_ctx->numa_num; i++) {
		cur_info = &sched_info[i];
		while (cur_info) {
			next_info = cur_info->next_info;
			for (j = 0; j < SCHED_MODE_BUTT; j++) {
				if (cur_info->ctx_region[j]) {
					free(cur_info->ctx_region[j]);
					cur_info->ctx_region[j] = NULL;
				}
			}
			/* First info region is alloced by sched ctx */
			if (cur_info->region_type != UADK_CTX_HW)
				free(cur_info);
			cur_info = next_info;
		}
	}
}


void wd_sched_rr_release(struct wd_sched *sched)
{
	struct wd_sched_ctx *sched_ctx;
	__u32 hw_dfx_num = 0;
	__u32 sw_dfx_num = 0;
	__u32 i;

	if (!sched)
		return;

	sched_ctx = (struct wd_sched_ctx *)sched->h_sched_ctx;
	if (!sched_ctx)
		goto ctx_out;

	for (i = 0; i < sched_ctx->skey_num; i++) {
		if (sched_ctx->skey[i] != NULL) {
			hw_dfx_num += sched_ctx->skey[i]->balancer.hw_dfx_num;
			sw_dfx_num += sched_ctx->skey[i]->balancer.sw_dfx_num;
		}
		sched_ctx->skey[i] = NULL;
	}
	hw_dfx_num += sched_ctx->balancer.hw_dfx_num;
	sw_dfx_num += sched_ctx->balancer.sw_dfx_num;
	sched_ctx->skey_num = 0;
	/* Release sched dfx info */
	WD_ERR("scheduler balance hw task num: %u, sw task num: %u\n",
		hw_dfx_num, sw_dfx_num);

	wd_sched_region_release(sched_ctx);
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
	struct wd_sched_info *cur_info;
	int i, j, k;

	for (i = 0; i < MAX_SKEY_REGION_NUM; i++) {
		sched_ctx->skey[i] = NULL;
		sched_ctx->poll_tid[i] = 0;
	}
	pthread_mutex_init(&sched_ctx->skey_lock, NULL);
	sched_ctx->skey_num = 0;
	memset(&sched_ctx->balancer, 0x0, sizeof(struct wd_sched_balancer));

	for (i = 0; i < numa_num; i++) {
		/* Init sched_info next list */
		cur_info = &sched_info[i];
		for (j = 0; j < UADK_CTX_MAX; j++) {
			for (k = 0; k < SCHED_MODE_BUTT; k++) {
				cur_info->ctx_region[k] =
				calloc(1, sizeof(struct sched_ctx_region) * type_num);
				if (!cur_info->ctx_region[k])
					goto sched_err;
			}
			cur_info->valid = false;
			cur_info->region_type = j;

			/* The last node point to NULL */
			if (j == UADK_CTX_MAX - 1) {
				cur_info->next_info = NULL;
				break;
			}
			cur_info->next_info = calloc(1, sizeof(*cur_info));
			if (!cur_info)
				goto sched_err;
			cur_info = cur_info->next_info;
		}
	}

	return 0;

sched_err:
	wd_sched_region_release(sched_ctx);

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

	WD_ERR("wd_sched numa number value: %u!\n", numa_num);
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
		goto ctx_out;

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

ctx_out:
	free(sched_ctx);
err_out:
	free(sched);
	return NULL;
}
