/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_COMP_DRV_H
#define __WD_COMP_DRV_H

#include <pthread.h>
#include <asm/types.h>

#include "../wd_comp.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

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
};

#ifdef __cplusplus
}
#endif

#endif /* __WD_COMP_DRV_H */
