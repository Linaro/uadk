#include <stdlib.h>
#include <wd_comp.h>


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

/**
 * struct sched_ctx_info - define one ctx pos.
 * @begin: the start pos in ctxs of config.
 * @end: the end pos in ctxx of config.
 */
struct sched_ctx_pos {
	int begin;
	int end;
};

/**
 * sched_ctx_map - define the map for the comp ctxs, using for quickly search
 *                 the x range: two(sync and async), the y range: two(comp and uncomp)
 *                 the map[x][y]'s value is the ctx begin and end pos
 */
int sched_ctx_map[X_BUTT][Y_BUTT] = {
	{0, 0}, {1, 1}, {2, 2}, {3, 3}
};

/* the send nums of every ctx */
int sched_send_num[4] = {0};

/**
 * sample_sched_init - initialize the global sched info
 */
void sample_sched_init(void *sched_ctx) {
	return;
}

/**
 * ssample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg
 * 
 * This function will be registered to the wd comp
 */
handle_t sample_pick_next_ctx(struct wd_ctx_config *cfg, void* sched_ctx, struct wd_comp_arg *arg)
{
	int x = X_SYNC;
	int y = Y_COMP;
	int pos = sched_ctx_map[x][y].begin;

	sched_send_num[pos]++;
	return cfg->ctxs[pos].ctx;
}

/**
 * sample_poll_policy - The polling policy matches the pick next ctx
 * 
 * This function will be registered to the wd comp 
 */
__u32 sample_poll_policy(struct wd_ctx_config *cfg, void* sched_ctx)
{
	int x, y, begin, end;
	int poll_num;
	int pos;

	x = X_ASYNC;
	
	for (y = 0; y < Y_BUTT; y++) {
		begin = sched_ctx_map[x][y].begin;
		end = sched_ctx_map[x][y].end;
		for (pos = begin; pos <= end; pos++) {
			poll_num = wd_comp_poll_ctx(cfg->ctxs[pos], sched_send_num[pos])
			if (poll_num != sched_send_num[pos]) {
				/* printf the error info */
			}
			sched_send_num[pos] = 0;
		}
	}
	
	return 0;
}
