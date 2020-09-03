// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include "sched_sample.h"

#define CTX_NUM_OF_NUMA 100
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
	pthread_mutex_t mutex;
};

/**
 * sample_sched_info - define the context of the scheduler.
 * @ctx_region: define the map for the comp ctxs, using for quickly search.
				the x range: two(sync and async), the y range: two(comp and uncomp)
				the map[x][y]'s value is the ctx begin and end pos.
 * @valid: the region used flag.
 */
struct sample_sched_info {
	struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT];
	bool valid;
};


typedef void (*sched_get_para)(const void *req, void *para);
/**
 * g_sched_ops - Define the bonding operator of the scheduler.
 * @get_para: for the different sched modes to get their privte para.
 * @get_next_pos: pick one ctx's pos from all the ctx.
 * @poll_policy: the polling policy.
 */
struct sched_operator {
	__u32 (*get_next_pos)(struct sched_ctx_region *region, void *para);
	int (*poll_policy)(const struct wd_ctx_config *cfg, struct sched_ctx_region **region, __u32 expect, __u32 *count);
	sched_get_para get_para;
};

struct sample_sched_ctx {
	struct sample_sched_info sched_info[MAX_NUMA_NUM];
	user_poll_func poll_func;
	__u32 policy;
};

/* Service type num, config by user through init. */
int g_sched_type_num = 0;

/* The global schdule policy, default is RR mode. */
int g_sched_policy = SCHED_POLICY_RR;

/* The globel schedule info for MAX_NUMA_NUM, every numa has independent region. */
struct sample_sched_info g_sched_info[MAX_NUMA_NUM];

/* The ctx poll function of user underlying operating. */
user_poll_func g_sched_user_poll = NULL;

/**
 * Fill privte para that the different mode needs, reserved for future.
 */
static void sample_get_para_rr(const void *req, void *para)
{
	return;
}

/**
 * sample_get_next_pos_rr - Get next resource pos by RR schedule. The second para is reserved for future.
 */
static __u32 sample_get_next_pos_rr(struct sched_ctx_region *region, void *para)
{
	__u32 pos;

	pthread_mutex_lock(&region->mutex);

	pos = region->last;

	if (pos < region->end)
		region->last++;
	else if (pos == region->last)
		region->last = region->begin;
	else {
		/* If the pos's value is out of range, we can output the error info and correct the error */
		printf("ERROR:%s, pos = %u, begin = %u, end = %u\n", __FUNCTION__, pos, region->begin, region->end);
		region->last = region->begin;
	}

	pthread_mutex_unlock(&region->mutex);

	return pos;
}

static int sample_poll_region(const struct wd_ctx_config *cfg, __u32 begin, __u32 end, __u32 expect, __u32 *count)
{
	__u32 poll_num = 0;
	__u32 i;
	int ret;

	/* i is the pos of ctxs, the max is end */
	for (i = begin; i <= end; i++) {
		/* RR schedule, one time poll one */
		ret = g_sched_user_poll(cfg->ctxs[i].ctx, 1, &poll_num);
		if (ret)
			return SCHED_ERROR;

		*count += poll_num;
		if (*count >= expect)
			break;
	}

	return SCHED_SUCCESS;
}

static int sample_poll_policy_rr(struct wd_ctx_config const *cfg, struct sched_ctx_region **region,
										__u32 expect, __u32 *count)
{
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
		for (i = 0; i < g_sched_type_num; i++) {
			if (!region[SCHED_MODE_ASYNC][i].valid)
				continue;

			begin = region[SCHED_MODE_ASYNC][i].begin;
			end = region[SCHED_MODE_ASYNC][i].end;
			ret = sample_poll_region(cfg, begin, end, expect, count);
			if (ret)
				return ret;

			if (*count >= expect)
				return SCHED_SUCCESS;
		}
	}

	return SCHED_SUCCESS;
}

struct sched_operator g_sched_ops[SCHED_POLICY_BUTT] = {
	{
		.get_para = sample_get_para_rr,
		.get_next_pos = sample_get_next_pos_rr,
		.poll_policy = sample_poll_policy_rr,
	},
};

/**
 * sample_sched_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
static struct sched_ctx_region *sample_sched_get_ctx_range(struct sample_sched_info *sched_info, const struct sched_key *key)
{
	if (sched_info[key->numa_id].ctx_region[key->mode][key->type].valid)
		return &sched_info[key->numa_id].ctx_region[key->mode][key->type];

	return NULL;
}

static bool sample_sched_key_valid(const struct sched_key *key)
{
	if (key->numa_id >= MAX_NUMA_NUM || key->mode >= SCHED_MODE_BUTT || key->type >= g_sched_type_num) {
		printf("ERROR: %s key error - %u,%u,%u !\n", __FUNCTION__, key->numa_id, key->mode, key->type);
		return false;
	}

	return true;
}

/**
 * ssample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @cfg: The global resoure info.
 * @reg: The service request msg, different algorithm shoule support analysis function.
 * @key: The key of schedule region.
 *
 * The user must init the schdule info through sample_sched_fill_data, the func interval
 * will not check the valid, becouse it will affect performance.
 */
__u32 sample_sched_pick_next_ctx(handle_t sched_ctx, const void *req, const struct sched_key *key)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)sched_ctx;
	struct sched_ctx_region *region = NULL;
	struct sample_sched_info *sched_info;
	__u32 pos;

	if (!ctx || !key || !req) {
		printf("ERROR: %s the pointer para is NULL !\n", __FUNCTION__);
		return INVALID_POS;
	}

	if (!sample_sched_key_valid(key)) {
		printf("ERROR: %s the key is invalid !\n", __FUNCTION__);
		return INVALID_POS;
	}

	sched_info = ctx->sched_info;

	region = sample_sched_get_ctx_range(sched_info, key);
	if (!region)
		return INVALID_POS;

	/* Notice: The second para now is a stub, we must alloc memery for it before using */
	g_sched_ops[ctx->policy].get_para(req, NULL);
	pos = g_sched_ops[g_sched_policy].get_next_pos(region, NULL);

	return pos;
}

/**
 * sample_poll_policy - The polling policy matches the pick next ctx.
 * @sched_ctx: Schedule ctx, reference the struct sample_sched_ctx.
 * @cfg: The global resoure info.
 * @expect: User expect poll msg num.
 * @count: The actually poll num.
 *
 * The user must init the schdule info through sample_sched_fill_data, the func interval
 * will not check the valid, becouse it will affect performance.
 */
int sample_sched_poll_policy(handle_t sched_ctx, const struct wd_ctx_config *cfg, __u32 expect, __u32 *count)
{
	struct sample_sched_ctx *ctx = (struct sample_sched_ctx*)sched_ctx;
	struct sample_sched_info *sched_info;
	__u8 numa_id;
	int ret;

	if (!count || !cfg || !ctx) {
		printf("ERROR: %s the para is NULL !\n", __FUNCTION__);
		return SCHED_PARA_INVALID;
	}

	sched_info = ctx->sched_info;

	for (numa_id = 0; numa_id < MAX_NUMA_NUM; numa_id++) {
		if (sched_info[numa_id].valid) {
			ret = g_sched_ops[ctx->policy].poll_policy(cfg, sched_info[numa_id].ctx_region, expect, count);
			if (ret)
				return ret;
		}
	}

	return SCHED_SUCCESS;
}

/**
 * sample_sched_operator_cfg - user can define private schedule operator
 */
int sample_sched_operator_cfg(const struct sched_operator *op)
{
	if (!op) {
		printf("Error: %s op is null!\n", __FUNCTION__);
		return SCHED_PARA_INVALID;
	}

	g_sched_ops[g_sched_policy].get_next_pos = op->get_next_pos;
	g_sched_ops[g_sched_policy].get_para = op->get_para;
	g_sched_ops[g_sched_policy].poll_policy = op->poll_policy;

	return SCHED_SUCCESS;
}

/**
 * sample_sched_fill_data - Fill the schedule min region.
 * @sched: The schdule instance
 * @mode: Sync or async mode.  sync: 0, async: 1
 * @type: Service type , the value must smaller than type_num.
 * @begin: The begig ctx resource index for the region
 * @end:  The end ctx resource index for the region.
 *
 * The shedule indexed mode is NUMA -> MODE -> TYPE -> [BEGIN : END],
 * then select one index from begin to end.
 */
int sample_sched_fill_data(const struct wd_sched *sched, __u8 numa_id, __u8 mode, __u8 type, __u32 begin, __u32 end)
{
	struct sample_sched_info *sched_info;
	struct sample_sched_ctx *sched_ctx;

	if (!sched || !sched->h_sched_ctx) {
		printf("ERROR: %s para err: sched of h_sched_ctx is null\n", __FUNCTION__);
		return SCHED_PARA_INVALID;
	}

	if ((numa_id >= MAX_NUMA_NUM) || (mode >= SCHED_MODE_BUTT) || (type >= g_sched_type_num)) {
		printf("ERROR: %s para err: numa_id=%u, mode=%u, type=%u\n", __FUNCTION__, numa_id, mode, type);
		return SCHED_PARA_INVALID;
	}

	sched_ctx = (struct sample_sched_ctx*)sched->h_sched_ctx;
	sched_info = sched_ctx->sched_info;

	if (!sched_info[numa_id].ctx_region[mode]) {
		printf("ERROR: %s para err: ctx_region:numa_id=%u, mode=%u is null\n", __FUNCTION__, numa_id, mode);
		return SCHED_PARA_INVALID;
	}

	sched_info[numa_id].ctx_region[mode][type].begin = begin;
	sched_info[numa_id].ctx_region[mode][type].end = end;
	sched_info[numa_id].ctx_region[mode][type].last = begin;
	sched_info[numa_id].ctx_region[mode][type].valid = true;
	sched_info[numa_id].valid = true;

	(void)pthread_mutex_init(&g_sched_info[numa_id].ctx_region[mode][type].mutex, NULL);

	return SCHED_SUCCESS;
}

/**
 * sample_sched_release - Release schedule memory.
 */
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
		for (i = 0; i < MAX_NUMA_NUM; i++) {
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

/**
 * sample_sched_alloc - alloc a schedule instance.
 */
struct wd_sched *sample_sched_alloc(__u8 sched_type, __u8 type_num, user_poll_func func) 
{
	struct sample_sched_ctx *sched_ctx;
	struct sample_sched_info *sched_info;
	struct wd_sched *sched;
	int i, j;

	if (sched_type >= SCHED_POLICY_BUTT || !type_num) {
		printf("Error: %s sched_type = %u or type_num = %u is invalid!\n", __FUNCTION__, sched_type, type_num);
		return NULL;
	}

	if (!func) {
		printf("Error: %s poll_func is null!\n", __FUNCTION__);
		return NULL;
	}

	sched = calloc(1, sizeof(struct wd_sched));
	if (!sched) {
		printf("Error: %s wd_sched alloc error!\n", __FUNCTION__);
		goto err_out;
	}

	sched_ctx = calloc(1, sizeof(struct sample_sched_ctx));
	if (!sched_ctx) {
		printf("Error: %s sched_info alloc error!\n", __FUNCTION__);
		goto err_out;
	}

	sched_info = sched_ctx->sched_info;

	for (i = 0; i < MAX_NUMA_NUM; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			sched_info[i].ctx_region[j] = calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!sched_info[i].ctx_region[j])
				goto err_out;
		}
	}

	sched_ctx->poll_func = func;
	sched_ctx->policy = sched_type;

	sched->pick_next_ctx = sample_sched_pick_next_ctx;
	sched->poll_policy = sample_sched_poll_policy;
	sched->h_sched_ctx = (handle_t)sched_ctx;

	return sched;
err_out:
	sample_sched_release(sched);
	return NULL;
}
