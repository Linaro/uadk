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

#define MAX_NUMA_NUM 4
#define CTX_NUM_OF_NUMA 100
#define MAX_POLL_TIMES 10000

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
	int begin;
	int end;
	int last;
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

/**
 * g_sched_ops - Define the bonding operator of the scheduler.
 * @get_para: for the different sched modes to get their privte para.
 * @get_next_pos: pick one ctx's pos from all the ctx.
 * @poll_policy: the polling policy.
 */
struct sched_operator {
	void (*get_para)(void *req, void *para);
	int (*get_next_pos)(struct sched_ctx_region *region, void *para);
	int (*poll_policy)(struct wd_ctx_config *cfg, struct sched_ctx_region **region, __u32 expect, __u32 *count);
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
static void sample_get_para_rr(void *req, void *para)
{
	return;
}

/**
 * sample_get_next_pos_rr - Get next resource pos by RR schedule. The second para is reserved for future.
 */
static int sample_get_next_pos_rr(struct sched_ctx_region *region, void *para)
{
	int pos;

	pthread_mutex_lock(&region->mutex);

	pos = region->last;

	if (pos < region->end) {
		pos++;
	} else if (pos == region->last) {
		pos = region->begin;
	} else {
		/* If the pos's value is out of range, we can output the error info and correct the error */
		printf("ERROR:%s, pos = %d, begin = %d, end = %d\n", __FUNCTION__, pos, region->begin, region->end);
		pos = region->begin;
	}
	region->last = pos;

	pthread_mutex_unlock(&region->mutex);

	return pos;
}

static int sample_poll_policy_rr(struct wd_ctx_config *cfg, struct sched_ctx_region **region,
	__u32 expect, __u32 *count)
{
	__u32 poll_num = 0;
	int loop_time = 0;
	int begin, end;
	int i, j;
	int ret;

	*count = 0;

	/* Traverse the async ctx */
	for (i = 0; i < g_sched_type_num; i++) {
		if (!region[SCHED_MODE_ASYNC][i].valid) {
			continue;
		}

		begin = region[SCHED_MODE_ASYNC][i].begin;
		end = region[SCHED_MODE_ASYNC][i].end;
		for (j = begin; j <= end; j++) {
			/* RR schedule, one time poll one */
			ret = g_sched_user_poll(cfg->ctxs[j].ctx, 1, &poll_num);
			if (ret) {
				return SCHED_ERROR;
			}

			*count += poll_num;
			loop_time++;

			/* If poll_num always be zero by unknow reason. This will be endless loop,
			   we must add the escape way by recording the loop count, if it is bigger
			   than MAX_POLL_TIMES, must stop and return the pool num */
			if (*count >= expect || loop_time >= MAX_POLL_TIMES) {
				return SCHED_SUCCESS;
			}
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
static struct sched_ctx_region *sample_sched_get_ctx_range(struct sched_key *key)
{
	if (g_sched_info[key->numa_id].ctx_region[key->mode][key->type].valid) {
		return &g_sched_info[key->numa_id].ctx_region[key->mode][key->type];
	}

	return NULL;
}

static bool sample_sched_key_valid(struct sched_key *key)
{
	if (key->numa_id >= MAX_NUMA_NUM || key->mode >= SCHED_MODE_BUTT || key->type >= g_sched_type_num) {
		printf("ERROR: %s key error - %d,%d,%u !\n", __FUNCTION__, key->numa_id, key->mode, key->type);
		return false;
	}

	return true;
}

/**
 * sample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg
 */
handle_t sample_sched_pick_next_ctx(struct wd_ctx_config *cfg, void *req, struct sched_key *key)
{
	int pos;
	struct sched_ctx_region *region = NULL;

	if (!cfg || !key || !req) {
		printf("ERROR: %s the cfg or key or req is NULL !\n", __FUNCTION__);
		return (handle_t)NULL;
	}

	if (!sample_sched_key_valid(key)) {
		return (handle_t)NULL;
	}

	region = sample_sched_get_ctx_range(key);
	if (!region) {
		return (handle_t)NULL;
	}

	/* Notice: The second para now is a stub, we must alloc memery for it before using */
	g_sched_ops[g_sched_policy].get_para(req, NULL);
	pos = g_sched_ops[g_sched_policy].get_next_pos(region, NULL);

	return cfg->ctxs[pos].ctx;
}

/**
 * sample_poll_policy - The polling policy matches the pick next ctx
 */
int sample_sched_poll_policy(struct wd_ctx_config *cfg, __u32 expect, __u32 *count)
{
	int numa_id;

	if (!count) {
		printf("ERROR: %s the count is NULL !\n", __FUNCTION__);
		return SCHED_PARA_INVALID;
	}

	for (numa_id = 0; numa_id < MAX_NUMA_NUM; numa_id++) {
		if (g_sched_info[numa_id].valid) {
			g_sched_ops[g_sched_policy].poll_policy(cfg, g_sched_info[numa_id].ctx_region, expect, count);
		}
	}

	return SCHED_SUCCESS;
}

/**
 * sample_sched_fill_region - Fill the schedule min region.
 * @sched_ctx: The memery alloc by user which is consult with the sample_sched_get_size.
 * @mode: Sync or async mode.  sync: 0, async: 1
 * @type: Service type , the value must smaller than type_num.
 * @begin: The begig ctx resource index for the region
 * @end:  The end ctx resource index for the region.
 *
 * The shedule indexed mode is NUMA -> MODE -> TYPE -> [BEGIN : END],
 * then select one index from begin to end.
 */
int sample_sched_fill_region(int numa_id, int mode, int type, int begin, int end)
{
	if ((mode >= SCHED_MODE_BUTT) || (type >= g_sched_type_num)) {
		printf("ERROR: %s para err: mode=%d, type=%d\n", __FUNCTION__, mode, type);
		return SCHED_PARA_INVALID;
	}

	g_sched_info[numa_id].ctx_region[mode][type].begin = begin;
	g_sched_info[numa_id].ctx_region[mode][type].end = end;
	g_sched_info[numa_id].ctx_region[mode][type].last = begin;
	g_sched_info[numa_id].ctx_region[mode][type].valid = true;

	(void)pthread_mutex_init(&g_sched_info[numa_id].ctx_region[mode][type].mutex, NULL);

	return SCHED_SUCCESS;
}

/**
 * sample_sched_operator_cfg - user can define private schedule operator
 */
int sample_sched_operator_cfg(struct sched_operator *op)
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
 * sample_sched_init - initialize the global sched info
 */
int sample_sched_init(__u8 sched_type, int type_num, user_poll_func func)
{
	int i, j;

	if (sched_type >= SCHED_POLICY_BUTT) {
		printf("Error: %s sched_type = %d is invalid!\n", __FUNCTION__, sched_type);
		return SCHED_PARA_INVALID;
	}

	if (!func) {
		printf("Error: %s poll_func is null!\n", __FUNCTION__);
		return SCHED_PARA_INVALID;
	}

	g_sched_policy = sched_type;
	g_sched_type_num = type_num;

	memset(g_sched_info, 0, sizeof(g_sched_info));
	for (i = 0; i < MAX_NUMA_NUM; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			g_sched_info[i].ctx_region[j] = calloc(1, sizeof(struct sched_ctx_region) * type_num);
			if (!g_sched_info[i].ctx_region[j]) {
				goto err_out;
			}
		}
	}

	g_sched_user_poll = func;

	return SCHED_SUCCESS;
err_out:
	sample_sched_release();
	return SCHED_ERROR;
}

/**
 * sample_sched_release - Release schedule memory.
 */
void sample_sched_release()
{
	int i, j;

	for (i = 0; i < MAX_NUMA_NUM; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			if (g_sched_info[i].ctx_region[j]) {
				free(g_sched_info[i].ctx_region[j]);
			}
		}
	}

	return;
}
