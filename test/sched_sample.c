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
#include "wd_comp.h"

#define MAX_CTX_NUM 1024
#define MAX_NUMA_NUM 4
#define CTX_NUM_OF_NUMA 100

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
	USER_SCHED_RR,
	USER_SCHED_BUTT
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
	struct sched_ctx_region ctx_region[X_BUTT][Y_BUTT];
	int count[MAX_CTX_NUM];
	bool valid;
};

struct sched_operator {
	void (*get_para)(struct wd_comp_req *req, void*para);
	int (*get_next_pos)(struct sched_ctx_region *region, void *para);
	__u32 (*poll_policy)(struct wd_ctx_config *cfg, struct sched_ctx_region (*region)[Y_BUTT]);
};

/**
 * Fill para that the different mode needs
 */
void sample_get_para_rr(struct wd_comp_req *req, void *para)
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

int g_sched_mode = USER_SCHED_RR;

/**
 * sched_ops - Define the bonding operator of the scheduler.
 * @get_para: for the different sched modes to get their privte para.
 * @get_next_pos: pick one ctx's pos from all the ctx.
 * @poll_policy: the polling policy.
 */
struct sched_operator sched_ops[USER_SCHED_BUTT] = {
	{.get_para = sample_get_para_rr,
	 .get_next_pos = sample_get_next_pos_rr,
     .poll_policy = sample_poll_policy_rr,
	},
};

/**
 * sample_get_ctx_range - Get ctx range from ctx_map by the wd comp arg
 */
struct sched_ctx_region* sample_get_ctx_range(struct wd_comp_req *req, struct sched_ctx_region (*ctx_map)[Y_BUTT])
{
	int x = req->flag;
	int y = req->status;

	return &ctx_map[x][y];
}

/**
 * ssample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg
 *
 * This function will be registered to the wd comp
 */
handle_t sample_pick_next_ctx(struct wd_ctx_config *cfg, void *sched_ctx, struct wd_comp_req *req, int numa_id)
{
	int pos;
	void *para = NULL;
	struct sched_ctx_region *region = NULL;
	struct sample_sched_info *sched_info = (struct sample_sched_info*)sched_ctx;

	region = sample_get_ctx_range(req, sched_info[numa_id].ctx_region);
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
	struct sample_sched_info *sched_info = (struct sample_sched_info *)sched_ctx;

	for (numa_id = 0; numa_id < MAX_NUMA_NUM; numa_id++) {
		if (sched_info[numa_id].valid) {
			sched_ops[g_sched_mode].poll_policy(cfg, sched_info[numa_id].ctx_region);
		}
	}

	return 0;
}

void sample_sched_fill_region(struct sample_sched_info *sched_info,
	int numa_id, int ctx_mode, int ctx_type, int begin, int end)
{
	sched_info[numa_id].ctx_region[ctx_mode][ctx_type].begin = begin;
	sched_info[numa_id].ctx_region[ctx_mode][ctx_type].end = end;
	sched_info[numa_id].ctx_region[ctx_mode][ctx_type].last = begin;

	(void)pthread_mutex_init(&sched_info[numa_id].ctx_region[ctx_mode][ctx_type].mutex, NULL);

	return;
}

/**
 * sample_sched_init - initialize the global sched info
 */
void sample_sched_ctx_init(void *sched_ctx)
{
	int i, base;
	struct sample_sched_info *sched_info = (struct sample_sched_info*)sched_ctx;
	g_sched_mode = USER_SCHED_RR;
	memset(sched_info, 0, sizeof(struct sample_sched_info) * MAX_NUMA_NUM);

	/* Initialize the global sched info base the ctx allocation of every numa */
	for (i = 0; i < MAX_NUMA_NUM; i++) {
		base = i * CTX_NUM_OF_NUMA;
		sample_sched_fill_region(sched_info, 0, X_SYNC, Y_COMP, base, base + 24);
		sample_sched_fill_region(sched_info, 0, X_SYNC, Y_UNCOMP, base + 25, base + 49);
		sample_sched_fill_region(sched_info, 0, X_ASYNC, Y_COMP, base + 50, base + 74);
		sample_sched_fill_region(sched_info, 0, X_ASYNC, Y_UNCOMP, base + 74, base + 99);
	}

	return;
}

void sample_ctx_alloc(char *node_path, int ctx_num, struct wd_ctx *ctxs, int base)
{
	int i;

	for (i = base; i < ctx_num + base; i++) {
		ctxs[i].ctx = wd_request_ctx(node_path);
	}

	return;
}

struct wd_ctx_config *g_ctx_cfg = NULL;

void sample_fill_ctx_type(int base, int end, bool ctx_mode, __u8 type)
{
	int i;

	for (i = base; i < end; i++) {
		g_ctx_cfg->ctxs[i].ctx_mode = ctx_mode;
		g_ctx_cfg->ctxs[i].op_type = type;

		g_ctx_cfg->ctxs[i + MAX_NUMA_NUM].ctx_mode = ctx_mode;
		g_ctx_cfg->ctxs[i + MAX_NUMA_NUM].op_type = type;

		g_ctx_cfg->ctxs[i + MAX_NUMA_NUM * 2].ctx_mode = ctx_mode;
		g_ctx_cfg->ctxs[i + MAX_NUMA_NUM * 2].op_type = type;

		g_ctx_cfg->ctxs[i + MAX_NUMA_NUM * 3].ctx_mode = ctx_mode;
		g_ctx_cfg->ctxs[i + MAX_NUMA_NUM * 3].op_type = type;
	}

	return;
}

/**
 * sample_global_config
 */
void sample_ctx_cfg_init()
{
	int numa_id;
	int offset = 0;
	char *node_path[MAX_NUMA_NUM] = {"dev/numa1_xxx", "dev/numa2_xxx", "dev/numa3_xxx", "dev/numa4_xxx"};

	g_ctx_cfg = (struct wd_ctx_config*)calloc(1, sizeof(struct wd_ctx_config));
	if (!g_ctx_cfg) {
		return;
	}

	g_ctx_cfg->ctxs = NULL;
	g_ctx_cfg->priv = NULL;
	g_ctx_cfg->ctx_num = MAX_NUMA_NUM * CTX_NUM_OF_NUMA;

	g_ctx_cfg->ctxs = (struct wd_ctx*)calloc(g_ctx_cfg->ctx_num, sizeof(struct wd_ctx));
	if (!g_ctx_cfg->ctxs) {
		free(g_ctx_cfg);
		return;
	}

	/* Alloc the ctx of one numa */
	for (numa_id = 0; numa_id < MAX_NUMA_NUM; numa_id++) {
		sample_ctx_alloc(node_path[numa_id], CTX_NUM_OF_NUMA, &g_ctx_cfg->ctxs[offset], offset);
		offset += CTX_NUM_OF_NUMA;
	}

	/* The different ctxs' region should be define by the user */
	sample_fill_ctx_type(0, 24, true, 0);
	sample_fill_ctx_type(25, 49, true, 1);
	sample_fill_ctx_type(50, 74, false, 0);
	sample_fill_ctx_type(75, 99, false, 1);

	return;
}

void sample_ctx_cfg_release()
{
	if (g_ctx_cfg) {
		if (g_ctx_cfg->ctxs) {
			free(g_ctx_cfg->ctxs);
		}

		free(g_ctx_cfg);
	}

	return;
}

struct wd_sched *g_sched = NULL;

void sample_sched_init()
{
	g_sched = (struct wd_sched*)calloc(1, sizeof(struct wd_sched));

	g_sched->sched_ctx_size = sizeof(struct sample_sched_info);
	g_sched->pick_next_ctx = sample_pick_next_ctx;
	g_sched->poll_policy = sample_poll_policy;

	return;
}

void sample_sched_release()
{
	return;
}
