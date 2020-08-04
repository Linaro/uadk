/* SPDX-License-Identifier: Apache-2.0 */
/* the common drv header define the unified interface for wd */
#ifndef __WD_SCHED_H__
#define __WD_SCHED_H__

#include <stdbool.h>
#include "wd.h"

struct wd_msg {
	void *swap_in;
	void *swap_out;
	void *next_in;
	void *next_out;
	void *msg;	/* the hw message frame */
};

struct wd_scheduler {
	handle_t *qs;
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
	int (*output)(struct wd_msg *msg, void *priv);
	handle_t (*hw_alloc)(char *node_path, void *priv, void **data);
	void (*hw_free)(handle_t h_ctx);
	int (*hw_send)(handle_t h_ctx, void *req, __u16 num);
	int (*hw_recv)(handle_t h_ctx, void **req);
	void *data;	// used by hw_alloc

	void *priv;

	/* statistic */
	struct {
		int send;
		int send_retries;
		int recv;
		int recv_retries;
	} *stat;
};

extern int wd_sched_init(struct wd_scheduler *sched, char *node_path);
extern void wd_sched_fini(struct wd_scheduler *sched);
extern int wd_sched_work(struct wd_scheduler *sched, unsigned long have_input);

static inline bool wd_sched_empty(struct wd_scheduler *sched)
{
	return sched->cl == sched->msg_cache_num;
}

#endif
