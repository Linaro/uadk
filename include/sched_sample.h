#ifndef HISI_SEC_USR_IF_H
#define HISI_SEC_USR_IF_H
#include "wd_comp.h"

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

/**
 * sample_sched_init - initialize the global sched info.
 * @sched_policy_type: the sched policy in the range of enum sched_mode.
 * @type_num: Service type num.
 *			  For example, ZIP include compress and uncompress, the num is two.
 */
int sample_sched_init(__u8 sched_type, int type_num);

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
void sample_sched_fill_region(int numa_id, int mode, int type, int begin, int end);

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
 */
__u32 sample_sched_poll_policy(struct wd_ctx_config *cfg);

#endif
