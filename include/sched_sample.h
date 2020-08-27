// SPDX-License-Identifier: Apache-2.0
#ifndef SCHED_SAMPLE_h
#define SCHED_SAMPLE_h
#include "wd_alg_common.h"

/* The sched error number */
enum sched_err_num {
	SCHED_SUCCESS = 0,
	SCHED_ERROR = 1,
	SCHED_PARA_INVALID = 2,
};

/* The global policy type */
enum sched_policy_type {
	SCHED_POLICY_RR,
	SCHED_POLICY_BUTT
};

/**
 * sched_key - The key if schedule region.
 * @numa_id: The numa_id map the hardware.
 * @mode: Sync mode:0, async_mode:1
 * @type: Service type , the value must smaller than type_num.
 */
struct sched_key {
	int numa_id;
	int mode;
	__u8 type;
};

typedef int (*user_poll_func)(handle_t h_ctx, __u32 expect, __u32 *count);

/**
 * sample_sched_release - Release schedule memory.
 */
void sample_sched_release(void);

/**
 * sample_sched_fill_region - Fill the schedule min region.
 * @sched_ctx: The memery alloc by user which is consult with the sample_sched_get_size.
 * @mode: Sync or async mode.  sync: 0, async: 1.
 * @type: Service type , the value must smaller than type_num.
 * @begin: The begig ctx resource index for the region.
 * @end:  The end ctx resource index for the region.
 *
 * The shedule indexed mode is NUMA -> MODE -> TYPE -> [BEGIN : END],
 * then select one index from begin to end.
 */
int sample_sched_fill_region(int numa_id, int mode, int type, int begin, int end);

/**
 * ssample_pick_next_ctx - Get one ctx from ctxs by the sched_ctx and arg.
 * @cfg: The global resoure info.
 * @reg: The service request msg, different algorithm shoule support analysis function.
 * @key: The key of schedule region.
 */
handle_t sample_sched_pick_next_ctx(struct wd_ctx_config *cfg, void *req, struct sched_key *key);

/**
 * sample_poll_policy - The polling policy matches the pick next ctx
 * @cfg: The global resoure info.
 * @expect: User expect poll msg num.
 * @count: The actually poll num.
 */
int sample_sched_poll_policy(struct wd_ctx_config *cfg, __u32 expect, __u32 *count);

/**
 * sample_sched_init - Schedule Init function.
 * @sched_type: Reference sched_policy_type.
 * @type_num: The service type num of user's service. For example, the zip include comp and un comp, type nume is two.
 * @func: The ctx poll function of user underlying operating.
 */
int sample_sched_init(__u8 sched_type, int type_num, user_poll_func func);
#endif
