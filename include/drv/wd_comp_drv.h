/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_COMP_DRV_H
#define __WD_COMP_DRV_H

#include <pthread.h>
#include "../wd_comp.h"

enum wd_comp_strm_pos {
	WD_COMP_STREAM_NEW,
	WD_COMP_STREAM_OLD,
};

enum wd_comp_state {
	WD_COMP_STATEFUL,
	WD_COMP_STATELESS,
};

/* fixme wd_comp_msg */
struct wd_comp_msg {
	struct wd_comp_req req;
	/* Denoted HW ctx cache, for stream mode */
	void *ctx_buf;
	/* Denoted by enum wd_comp_alg_type */
	enum wd_comp_alg_type alg_type;
	/* Denoted by enum wd_comp_level */
	enum wd_comp_level comp_lv;
	/* Denoted by enum wd_comp_winsz_type */
	enum wd_comp_winsz_type win_sz;
	/* Denoted by enum wd_comp_state */
	enum wd_comp_state stream_mode;
	/* Denoted by enum wd_comp_strm_pos */
	enum wd_comp_strm_pos stream_pos;
	/* Denoted by enum wd_buff_type */
	enum wd_buff_type data_fmt;
	/* Output buffer size */
	__u32 avail_out;
	/* Consumed bytes of input data */
	__u32 in_cons;
	/* Produced bytes of current operation */
	__u32 produced;
	/* Denoted by gzip isize */
	__u32 isize;
	/* Denoted by zlib/gzip CRC */
	__u32 checksum;
	/* Request identifier */
	__u32 tag;
	/* Epoll flag */
	__u8 is_polled;
};

struct wd_comp_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config_internal *config, void *priv);
	void (*exit)(void *priv);
	int (*comp_send)(handle_t ctx, struct wd_comp_msg *msg, void *priv);
	int (*comp_recv)(handle_t ctx, struct wd_comp_msg *msg, void *priv);
};

void wd_comp_set_driver(struct wd_comp_driver *drv);
struct wd_comp_msg *wd_comp_get_msg(__u32 idx, __u32 tag);

#ifdef WD_STATIC_DRV
#define WD_COMP_SET_DRIVER(drv)						      \
extern const struct wd_comp_driver wd_comp_##drv __attribute__((alias(#drv)));\

#else
#define WD_COMP_SET_DRIVER(drv)						      \
static void __attribute__((constructor)) set_driver(void)		      \
{									      \
	wd_comp_set_driver(&drv);					      \
}
#endif

#endif /* __WD_COMP_DRV_H */
