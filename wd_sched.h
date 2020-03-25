/* SPDX-License-Identifier: Apache-2.0 */
/* the common drv header define the unified interface for wd */
#ifndef __WD_SCHED_H__
#define __WD_SCHED_H__

#include "wd.h"

struct wd_msg {
	void *data_in;
	void *data_out;
	void *msg;	/* the hw share buffer itself */
};

struct wd_scheduler {
	struct wd_queue *qs;
	int q_num;

	void * ss_region;
	size_t ss_region_size;

	struct wd_msg *msgs;
	int msg_cache_num;
	int msg_data_size;

	int c_h, c_t;	/* cache head and tail index */
	int q_h, q_t;	/* queue head and tail index */
	int cl;		/* cache left */

	void (*init_cache)(struct wd_scheduler *sched, int i, void *priv);
	int (*input)(struct wd_msg *msg, void *priv);
	int (*output)(struct wd_msg *msg, void*priv);

	void *priv;

	/* statistic */
	struct {
		int send;
		int send_retries;
		int recv;
		int recv_retries;
	} *stat;
};

extern int wd_sched_init(struct wd_scheduler *sched);
extern void wd_sched_fini(struct wd_scheduler *sched);
extern int wd_sched_work(struct wd_scheduler *sched, unsigned long have_input);

static inline bool wd_sched_empty(struct wd_scheduler *sched)
{
	return sched->cl == sched->msg_cache_num;
}

#endif
