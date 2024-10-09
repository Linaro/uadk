/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_AGG_DRV_H
#define __WD_AGG_DRV_H

#include <asm/types.h>
#include "wd_agg.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wd_agg_strm_pos {
	WD_AGG_STREAM_INPUT,
	WD_AGG_STREAM_OUTPUT,
	WD_AGG_REHASH_INPUT,
	WD_AGG_REHASH_OUTPUT,
};

struct wd_agg_msg {
	__u32 tag;
	__u32 key_cols_num;
	__u32 agg_cols_num;
	__u32 result;
	__u32 in_row_count;
	__u32 out_row_count;
	__u32 row_count;
	enum wd_agg_strm_pos pos;
	enum wd_dae_data_type count_all_data_type;
	bool output_done;
	bool is_count_all;
	struct wd_agg_req req;
	struct wd_dae_charset charset_info;
	struct wd_dae_hash_table hash_table;
	struct wd_key_col_info *key_cols_info;
	struct wd_agg_col_info *agg_cols_info;
	void *priv;
};

struct wd_agg_ops {
	int (*get_row_size)(void *priv);
	int (*sess_init)(struct wd_agg_sess_setup *setup, void **priv);
	void (*sess_uninit)(void *priv);
	int (*hash_table_init)(struct wd_dae_hash_table *hash_table, void *priv);
};

#ifdef __cplusplus
}
#endif

#endif /* __WD_AGG_DRV_H */
