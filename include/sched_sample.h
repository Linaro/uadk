// SPDX-License-Identifier: Apache-2.0
#ifndef SCHED_SAMPLE_h
#define SCHED_SAMPLE_h
#include "wd_alg_common.h"

#define MAX_NUMA_NUM 4
#define INVALID_POS 0xFFFFFFFF
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

typedef int (*user_poll_func)(__u32 pos, __u32 expect, __u32 *count);

/*
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
int sample_sched_fill_data(const struct wd_sched *sched, __u8 numa_id, __u8 mode, __u8 type, __u32 begin, __u32 end);

/**
 * sample_sched_alloc - Schedule instance alloc.
 * @sched_type: Reference sched_policy_type.
 * @type_num: The service type num of user's service. For example, the zip include comp and un comp, type nume is two.
 * @func: The ctx poll function of user underlying operating.
 */
struct wd_sched *sample_sched_alloc(__u8 sched_type, __u8 type_num, user_poll_func func);

/**
 * sample_sched_release - Release schedule memory.
 */
void sample_sched_release(struct wd_sched *sched);

#endif
