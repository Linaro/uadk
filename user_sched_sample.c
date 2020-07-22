#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include "wd_comp.h"

#define MAX_CTX_NUM 1024
#define MAX_NUMA_NUM 4

enum sched_x_pos {
	X_SYNC = 0,
	X_ASYNC = 1,
	X_BUTT
};

enum sched_y_pos {
	Y_COMP = 0,
	Y_UNCOMP = 1,
	Y_BUTT
};

enum sched_mode {
	SCHED_RR,
	SCHED_BUTT
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
	struct sched_ctx_region ctx_region[X_BUTT][Y_BUTT];
	int count[MAX_CTX_NUM];
	bool valid;
};

struct sched_operator {
	void (*get_para)(struct wd_comp_arg *req, void*para);
	int (*get_next_pos)(struct sched_ctx_region *region, void *para);
	__u32 (*poll_policy)(struct wd_ctx_config *cfg, struct sched_ctx_region (*region)[Y_BUTT]);
};

/**
 * Fill para that the different mode needs
 */
void sample_get_para_rr(struct wd_comp_arg *req, void *para)
{
	return;
}

int sample_get_next_pos_rr(struct sched_ctx_region *region, void *para) {
	int pos = region->last;

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

	return pos;
}

__u32 sample_poll_policy_rr(struct wd_ctx_config *cfg, struct sched_ctx_region (*region)[Y_BUTT])
{
	int i, j;
	int begin, end;

	/* Traverse the async ctx */
	for (i = 0; i < Y_BUTT; i++) {
		begin = region[X_ASYNC][i].begin;
		end = region[X_ASYNC][i].end;
		for (j = begin; j <= end; j++) {
			wd_comp_poll_ctx(cfg->ctxs[j].ctx, 1);
		}
	}

	return 0;
}

int g_sched_mode = SCHED_RR;

/**
 * sched_ops - Define the bonding operator of the scheduler.
 * @get_para: for the different sched modes to get their privte para.
 * @get_next_pos: pick one ctx's pos from all the ctx.
 * @poll_policy: the polling policy.
 */
struct sched_operator sched_ops[SCHED_BUTT] = {
	{.get_para = sample_get_para_rr,
	 .get_next_pos = sample_get_next_pos_rr,
     .poll_policy = sample_poll_policy_rr,
	},
};

/**
 * sample_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
struct sched_ctx_region* sample_get_ctx_range(struct wd_comp_arg *req,
	struct sched_ctx_region (*ctx_map)[Y_BUTT])
{
	return NULL;
}

/**
 * ssample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg
 *
 * This function will be registered to the wd comp
 */
handle_t sample_pick_next_ctx(struct wd_ctx_config *cfg, void *sched_ctx, struct wd_comp_arg *req)
{
	int pos;
	void *para = NULL;
	struct sched_ctx_region *region = NULL;
	struct sample_sched_info *sched_info = (struct sample_sched_info*)sched_ctx;

	region = sample_get_ctx_range(req, sched_info->ctx_region);
	if (!region) {
		return (handle_t)NULL;
	}

	/* Notice: The "para" now is a stub, we must alloc memery for it before useing it */
	sched_ops[g_sched_mode].get_para(req, para);
	pos = sched_ops[g_sched_mode].get_next_pos(region, para);

	sched_info->count[pos]++;

	return cfg->ctxs[pos].ctx;
}

/**
 * sample_poll_policy - The polling policy matches the pick next ctx
 *
 * This function will be registered to the wd comp
 */
__u32 sample_poll_policy(struct wd_ctx_config *cfg, void *sched_ctx)
{
	int numa_id;
	struct sample_sched_info *sched_info = NULL;

	for (numa_id = 0; numa_id < MAX_NUMA_NUM; numa_id++) {
		sched_ops[g_sched_mode].poll_policy(cfg, sched_info[numa_id].ctx_region);
	}

	return 0;
}

/**
 * sample_sched_init - initialize the global sched info
 */
void sample_sched_init(void *sched_ctx) {
	struct sample_sched_info *sched_info = (struct sample_sched_info*)sched_ctx;
	g_sched_mode = SCHED_RR;
	memset(sched_info, 0, sizeof(struct sample_sched_info) * MAX_NUMA_NUM);
	/* Initialize the global sched info base the ctx allocation of every numa */

	return;
}
