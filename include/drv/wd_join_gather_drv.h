/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_JOIN_GATHER_DRV_H
#define __WD_JOIN_GATHER_DRV_H

#include <asm/types.h>
#include "wd_join_gather.h"
#include "wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wd_join_gather_msg {
	__u32 tag;
	__u32 key_cols_num;
	__u32 result;
	__u32 input_row_num;
	__u32 output_row_num;
	__u32 consumed_row_num;
	__u32 produced_row_num;
	enum wd_join_gather_op_type op_type;
	enum multi_batch_index_type index_type;
	bool output_done;
	bool key_out_en;
	bool multi_batch_en;
	struct wd_join_gather_req req;
	struct wd_dae_hash_table hash_table;
	void *priv;
};

struct wd_join_gather_ops {
	int (*get_table_row_size)(struct wd_alg_driver *drv, void *priv);
	int (*get_batch_row_size)(struct wd_alg_driver *drv, void *priv,
				  __u32 *batch_row_size, __u32 size);
	int (*sess_init)(struct wd_alg_driver *drv,
			 struct wd_join_gather_sess_setup *setup, void **priv);
	void (*sess_uninit)(struct wd_alg_driver *drv, void *priv);
	int (*hash_table_init)(struct wd_alg_driver *drv,
			       struct wd_dae_hash_table *hash_table, void *priv);
};

struct wd_join_gather_msg *wd_join_gather_get_msg(__u32 idx, __u32 tag);

#ifdef __cplusplus
}
#endif

#endif /* __WD_JOIN_GATHER_DRV_H */
