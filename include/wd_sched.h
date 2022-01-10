// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef SCHED_SAMPLE_h
#define SCHED_SAMPLE_h
#include "wd_alg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_POS	0xFFFFFFFF

/* The global policy type */
enum sched_policy_type {
	/* requests will be sent to ctxs one by one */
	SCHED_POLICY_RR = 0,
	SCHED_POLICY_BUTT
};

struct sched_params {
	int numa_id;
	__u8 type;
	__u8 mode;
	__u32 begin;
	__u32 end;
};

typedef int (*user_poll_func)(__u32 pos, __u32 expect, __u32 *count);

/*
 * wd_sched_rr_instance - Instante the schedule min region.
 * @sched: The schedule instance
 * @param: input schedule parameters
 *
 * The shedule indexed mode is NUMA -> MODE -> TYPE -> [BEGIN : END],
 * then select one index from begin to end.
 */
int wd_sched_rr_instance(const struct wd_sched *sched,
				       struct sched_params *param);

/**
 * wd_sched_rr_alloc - Allocate a schedule instance.
 * @sched_type: Reference sched_policy_type.
 * @type_num: The service type num of user's service. For example, the zip
 *            include comp and decomp, type nume is two.
 * @numa_num: The number of numa that the user needs.
 * @func: The ctx poll function of user underlying operating.
 *
 */
struct wd_sched *wd_sched_rr_alloc(__u8 sched_type, __u8 type_num,
				   __u16 numa_num, user_poll_func func);

/**
 * wd_sched_rr_release - Release schedule memory.
 * @sched: The schedule which will be released.
 */
void wd_sched_rr_release(struct wd_sched *sched);

#ifdef __cplusplus
}
#endif

#endif
