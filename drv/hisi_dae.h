/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __HDAE_DRV_H__
#define __HDAE_DRV_H__

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <linux/types.h>

#include "config.h"
#include "wd_alg.h"
#include "wd_dae.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DAE_SQC_ALG_TYPE	2
#define DAE_EXT_SQE_SIZE	128

/* align size */
#define DAE_TABLE_ALIGN_SIZE	128
#define DAE_ADDR_ALIGN_SIZE	128
#define DAE_CHAR_ALIGN_SIZE	4

/* decimal infomartion */
#define DAE_DECIMAL_PRECISION_OFFSET	8
#define DAE_DECIMAL128_MAX_PRECISION	38
#define DAE_DECIMAL64_MAX_PRECISION	18

/* hash table */
#define HASH_EXT_TABLE_INVALID_OFFSET	5
#define HASH_EXT_TABLE_VALID		0x80
#define HASH_TABLE_HEAD_TAIL_SIZE	8
#define HASH_TABLE_EMPTY_SIZE		4
#define HASH_TABLE_WITDH_POWER		2
#define HASH_TABLE_MIN_WIDTH		10
#define HASH_TABLE_MAX_WIDTH		43
#define HASH_TABLE_OFFSET_3ROW		3
#define HASH_TABLE_OFFSET_1ROW		1

#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a)-1)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((uintptr_t)(p), (a)))

#define BIT(nr)			(1UL << (nr))
#define BITS_PER_LONG		(__SIZEOF_LONG__ * 8)
#define GENMASK(h, l)		(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/* DAE hardware protocol data */
enum dae_done_flag {
	DAE_HW_TASK_NOT_PROCESS = 0x0,
	DAE_HW_TASK_DONE = 0x1,
	DAE_HW_TASK_ERR = 0x2,
};

enum dae_error_type {
	DAE_TASK_SUCCESS = 0x0,
	DAE_TASK_BD_ERROR_MIN = 0x1,
	DAE_TASK_BD_ERROR_MAX = 0x7f,
	DAE_HASH_TABLE_NEED_REHASH = 0x82,
	DAE_HASH_TABLE_INVALID = 0x83,
	DAE_HASHAGG_VCHAR_OVERFLOW = 0x84,
	DAE_HASHAGG_RESULT_OVERFLOW = 0x85,
	DAE_TASK_BUS_ERROR = 0x86,
	DAE_HASHAGG_VCHAR_LEN_ERROR = 0x87,
};

enum dae_data_type {
	DAE_SINT32 = 0x0,
	DAE_SINT64 = 0x2,
	DAE_DECIMAL64 = 0x9,
	DAE_DECIMAL128 = 0xA,
	DAE_CHAR = 0xC,
	DAE_VCHAR = 0xD,
};

enum dae_date_type_size {
	SINT32_SIZE = 4,
	SINT64_SIZE = 8,
	DECIMAL128_SIZE = 16,
	DEFAULT_VCHAR_SIZE = 30,
};

enum dae_table_row_size {
	ROW_SIZE32 = 32,
	ROW_SIZE64 = 64,
	ROW_SIZE128 = 128,
	ROW_SIZE256 = 256,
	ROW_SIZE512 = 512,
};

enum dae_bd_type {
	DAE_BD_TYPE_V1 = 0x0,
	DAE_BD_TYPE_V2 = 0x1,
};

struct dae_sqe {
	__u32 bd_type : 6;
	__u32 resv1 : 2;
	__u32 task_type : 6;
	__u32 resv2 : 2;
	__u32 task_type_ext : 6;
	__u32 resv3 : 9;
	__u32 bd_invlid : 1;
	__u16 table_row_size;
	__u16 resv4;
	__u32 batch_num;
	__u32 low_tag;
	__u32 hi_tag;
	__u32 data_row_num;
	__u32 init_row_num;
	__u32 src_table_width : 6;
	__u32 dst_table_width : 6;
	__u32 key_out_en : 1;
	__u32 break_point_en : 1;
	__u32 multi_batch_en : 1;
	__u32 sva_prefetch_en : 1;
	__u32 counta_vld : 1;
	__u32 index_num : 5;
	__u32 resv5 : 8;
	__u32 index_batch_type : 1;
	__u32 resv6 : 1;
	__u8 key_data_type[16];
	__u8 agg_data_type[16];
	__u32 resv9[6];
	__u64 addr_ext;
	__u16 key_col_bitmap;
	__u16 has_empty;
	__u32 agg_col_bitmap;
	__u64 addr_list;
	__u32 done_flag : 3;
	__u32 output_end : 1;
	__u32 ext_err_type : 12;
	__u32 err_type : 8;
	__u32 wtype : 8;
	__u32 out_raw_num;
	__u32 data_row_offset;
	__u16 sum_overflow_cols;
	__u16 resv10;
};

struct dae_ext_sqe {
	/*
	 * If date type is char/vchar, data info fill data type size
	 * If data type is decimal64/decimal128, data info fill data precision
	 */
	__u16 key_data_info[16];
	__u16 agg_data_info[16];
	/* Aggregated output from input agg col index */
	__u64 out_from_in_idx;
	/* Aggregated output from input agg col operation, sum or count */
	__u64 out_optype;
	__u32 resv[12];
};

struct dae_col_addr {
	__u64 empty_addr;
	__u64 empty_size;
	__u64 value_addr;
	__u64 value_size;
};

struct dae_table_addr {
	__u64 std_table_addr;
	__u64 std_table_size;
	__u64 ext_table_addr;
	__u64 ext_table_size;
};

struct dae_probe_info_addr {
	__u64 batch_num_index;
	__u64 batch_addr_index;
	__u64 probe_index_addr;
	__u64 resv1;
	__u64 break_point_addr;
	__u64 resv2;
};

struct dae_addr_list {
	__u64 ext_sqe_addr;
	__u64 ext_sqe_size;
	struct dae_table_addr src_table;
	struct dae_table_addr dst_table;
	struct dae_probe_info_addr probe_info;
	struct dae_col_addr input_addr[32];
	struct dae_col_addr output_addr[32];
};

struct dae_extend_addr {
	struct dae_ext_sqe *ext_sqe;
	struct dae_addr_list *addr_list;
	__u8 *addr_status;
	__u16 addr_num;
	__u16 tail;
};

struct hash_table_data {
	void *std_table;
	void *ext_table;
	__u64 std_table_size;
	__u64 ext_table_size;
	__u32 table_width;
};

struct hisi_dae_ctx {
	struct wd_ctx_config_internal config;
};

void dae_exit(struct wd_alg_driver *drv);
int dae_init(struct wd_alg_driver *drv, void *conf);
int dae_hash_table_init(struct hash_table_data *hw_table,
			struct hash_table_data *rehash_table,
			struct wd_dae_hash_table *hash_table,
			__u32 row_size);
int get_free_ext_addr(struct dae_extend_addr *ext_addr);
void put_ext_addr(struct dae_extend_addr *ext_addr, int idx);
__u32 get_data_type_size(enum dae_data_type type, __u16 data_info);
int dae_decimal_precision_check(__u16 data_info, bool longdecimal);

#ifdef __cplusplus
}
#endif

#endif
