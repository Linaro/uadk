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

#define MAX_CTX_NUM 1024
#define MAX_NUMA_NUM 4
#define CTX_NUM_OF_NUMA 100

enum sched_mode {
	SCHED_MODE_SYNC = 0,
	SCHED_MODE_ASYNC = 1,
	SCHED_MODE_BUTT
};

/**
 * struct sched_ctx_range - define one ctx pos.
 * @begin: the start pos in ctxs of config.
 * @end: the end pos in ctxx of config.
 * @last: the last one which be distributed
 */
struct sched_ctx_region {
	int begin;
	int end;
	int last;
	bool valid;
	pthread_mutex_t mutex;
};

/**
 * sample_sched_info - define the context of the scheduler
 * @ctx_region: define the map for the comp ctxs, using for quickly search
				the x range: two(sync and async), the y range: two(comp and uncomp)
				the map[x][y]'s value is the ctx begin and end pos
 * @last_pos: record the last one pos which be distributed in different type ctxs
 * @count: record the req count of ccontex
 */
struct sample_sched_info {
	struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT];
	int count[MAX_CTX_NUM];
	bool valid;
};

/**
 * g_sched_ops - Define the bonding operator of the scheduler.
 * @get_para: for the different sched modes to get their privte para.
 * @get_next_pos: pick one ctx's pos from all the ctx.
 * @poll_policy: the polling policy.
 */
struct sched_operator {
	void (*get_para)(void *req, void*para);
	int (*get_next_pos)(struct sched_ctx_region *region, void *para);
	__u32 (*poll_policy)(struct wd_ctx_config *cfg, struct sched_ctx_region **region);
	__u32 (*poll_func)(handle_t h_ctx, __u32 num);
};

/* service type num */
int g_sched_type_num = 0;
int g_sched_policy = SCHED_POLICY_RR;
struct sample_sched_info g_sched_info[MAX_NUMA_NUM];

/**
 * Fill para that the different mode needs
 */
void sample_get_para_rr(void *req, void *para)
{
	return;
}

int sample_get_next_pos_rr(struct sched_ctx_region *region, void *para) {
	int pos;

	pthread_mutex_lock(&region->mutex);

	pos = region->last;

	if (pos < region->end) {
		pos++;
	} else if (pos == region->last) {
		pos = region->begin;
	} else {
		/* If the pos's value is out of range, we can output the error info and correct the error */
		printf("ERROR: pos = %d, begin = %d, end = %d\n", pos, region->begin, region->end);
		pos = region->begin;
	}

	region->last = pos;

	pthread_mutex_unlock(&region->mutex);

	return pos;
}

__u32 sample_poll_policy_rr(struct wd_ctx_config *cfg, struct sched_ctx_region **region);

struct sched_operator g_sched_ops[SCHED_POLICY_BUTT] = {
	{.get_para = sample_get_para_rr,
	 .get_next_pos = sample_get_next_pos_rr,
     .poll_policy = sample_poll_policy_rr,
	 .poll_func = NULL,
	},
};

__u32 sample_poll_policy_rr(struct wd_ctx_config *cfg, struct sched_ctx_region **region)
{
	int i, j;
	int begin, end;

	/* Traverse the async ctx */
	for (i = 0; i < g_sched_type_num; i++) {
		begin = region[SCHED_MODE_ASYNC][i].begin;
		end = region[SCHED_MODE_ASYNC][i].end;
		for (j = begin; j <= end; j++) {
			g_sched_ops[g_sched_policy].poll_func(cfg->ctxs[j].ctx, 1);
		}
	}

	return 0;
}

/**
 * sample_sched_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
struct sched_ctx_region* sample_sched_get_ctx_range(struct sched_key *key)
{
	if (g_sched_info[key->numa_id].ctx_region[key->mode][key->type].valid) {
		return &g_sched_info[key->numa_id].ctx_region[key->mode][key->type];
	}

	return NULL;
}

bool sample_sched_key_valid(struct sched_key *key)
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
	void *para = NULL;
	struct sched_ctx_region *region = NULL;

	if (!cfg || !key) {
		printf("ERROR: %s the cfg or key is NULL !\n", __FUNCTION__);
		return (handle_t)NULL;
	}

	if (!sample_sched_key_valid(key)) {
		return (handle_t)NULL;
	}

	region = sample_sched_get_ctx_range(key);
	if (!region) {
		return (handle_t)NULL;
	}

	/* Notice: The "para" now is a stub, we must alloc memery for it before useing */
	g_sched_ops[g_sched_policy].get_para(req, para);
	pos = g_sched_ops[g_sched_policy].get_next_pos(region, para);

	g_sched_info->count[pos]++;

	return cfg->ctxs[pos].ctx;
}

/**
 * sample_poll_policy - The polling policy matches the pick next ctx
 */
__u32 sample_sched_poll_policy(struct wd_ctx_config *cfg)
{
	int numa_id;

	for (numa_id = 0; numa_id < MAX_NUMA_NUM; numa_id++) {
		if (g_sched_info[numa_id].valid) {
			g_sched_ops[g_sched_policy].poll_policy(cfg, g_sched_info[numa_id].ctx_region);
		}
	}

	return 0;
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
		return -1;
	}

	g_sched_info[numa_id].ctx_region[mode][type].begin = begin;
	g_sched_info[numa_id].ctx_region[mode][type].end = end;
	g_sched_info[numa_id].ctx_region[mode][type].last = begin;
	g_sched_info[numa_id].ctx_region[mode][type].valid = true;

	(void)pthread_mutex_init(&g_sched_info[numa_id].ctx_region[mode][type].mutex, NULL);

	return 0;
}

/**
 * sample_sched_operator_cfg - user can define private schedule operator
 */
void sample_sched_operator_cfg(struct sched_operator *op)
{
	return;
}

/**
 * sample_sched_init - initialize the global sched info
 */
int sample_sched_init(__u8 sched_type, int type_num, __u32 (*poll_func)(handle_t h_ctx, __u32 num))
{
	int i, j;

	if (sched_type >= SCHED_POLICY_BUTT) {
		printf("Error: sample_sched_init sched_type = %d is invalid!\n", sched_type);
		return -1;
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

	g_sched_ops[g_sched_policy].poll_func = poll_func;

	return 0;
err_out:
	for (i = 0; i < MAX_NUMA_NUM; i++) {
		for (j = 0; j < SCHED_MODE_BUTT; j++) {
			if (g_sched_info[i].ctx_region[j]) {
				free(g_sched_info[i].ctx_region[j]);
			}
		}
	}
	return -1;
}

