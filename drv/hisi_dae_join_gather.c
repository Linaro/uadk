// SPDX-License-Identifier: Apache-2.0
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "hisi_qm_udrv.h"
#include "../include/drv/wd_join_gather_drv.h"

#define DAE_SQC_ALG_TYPE	2
#define DAE_EXT_SQE_SIZE	128
#define DAE_CTX_Q_NUM_DEF	1

/* column information */
#define DAE_MAX_KEY_COLS	9
#define DAE_MAX_CHAR_SIZE	32
#define DAE_MAX_ROW_SIZE	512
#define DAE_JOIN_MAX_ROW_NUN	50000
#define DAE_JOIN_MAX_BATCH_NUM	2800
#define DAE_MAX_TABLE_NUM	16
#define BUILD_INDEX_ROW_SIZE	8
#define PROBE_INDEX_ROW_SIZE	4

/* align size */
#define DAE_CHAR_ALIGN_SIZE	4
#define DAE_KEY_ALIGN_SIZE	8
#define DAE_TABLE_ALIGN_SIZE	128
#define DAE_ADDR_ALIGN_SIZE	128
#define DAE_BREAKPOINT_SIZE	81920
#define DAE_ADDR_INDEX_SHIFT	1

/* hash table */
#define HASH_EXT_TABLE_INVALID_OFFSET	5
#define HASH_EXT_TABLE_VALID	0x80
#define HASH_TABLE_HEAD_TAIL_SIZE	8
#define HASH_TABLE_INDEX_NUM		1
#define HASH_TABLE_MAX_INDEX_NUM	15
#define HASH_TABLE_INDEX_SIZE		12
#define HASH_TABLE_EMPTY_SIZE	4
#define GATHER_ROW_BATCH_EMPTY_SIZE	2
#define HASH_TABLE_WITDH_POWER		2
#define HASH_TABLE_MIN_WIDTH	10
#define HASH_TABLE_MAX_WIDTH	43
#define HASH_TABLE_OFFSET_3ROW		3
#define HASH_TABLE_OFFSET_1ROW		1

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)
#define PTR_ALIGN(p, a)	((typeof(p))ALIGN((uintptr_t)(p), (a)))

#define BIT(nr)		(1UL << (nr))
#define BITS_PER_LONG	(__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/* DAE hardware protocol data */
enum dae_join_stage {
	DAE_JOIN_BUILD_HASH = 0x0,
	DAE_JOIN_REHASH = 0x6,
	DAE_JOIN_PROBE = 0x7,
};

enum dae_gather_stage {
	DAE_GATHER_CONVERT = 0x0,
	DAE_GATHER_COMPLETE = 0x7,
};

enum dae_task_type {
	DAE_HASH_JOIN = 0x1,
	DAE_GATHER = 0x2,
};

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
	DAE_JOIN_GATHER_BUS_ERROR = 0x86,
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
	/*
	 * high 4bits: compare mode if data type is char/vchar,
	 *             out type if operation is sum.
	 * low 4bits: input value type.
	 */
	__u8 key_data_type[16];
	__u32 resv7[10];
	__u64 addr_ext;
	__u16 key_col_bitmap;
	__u16 has_empty;
	__u32 resv8;
	__u64 addr_list;
	__u32 done_flag : 3;
	__u32 output_end : 1;
	__u32 ext_err_type : 12;
	__u32 err_type : 8;
	__u32 wtype : 8;
	__u32 out_raw_num;
	__u32 next_init_row_num;
	__u32 resv9;
};

struct dae_ext_sqe {
	/*
	 * If date type is char/vchar, data info fill data type size
	 * If data type is decimal64/decimal128, data info fill data precision
	 */
	__u16 key_data_info[16];
	__u16 resv1[16];
	__u64 resv2[2];
	__u32 resv3[12];
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

static enum dae_data_type hw_data_type_order[] = {
	DAE_VCHAR, DAE_CHAR, DAE_DECIMAL128,
	DAE_DECIMAL64, DAE_SINT64, DAE_SINT32,
};

struct hw_join_gather_data {
	enum dae_data_type hw_type;
	__u32 optype;
	__u32 usr_col_idx;
	__u16 data_info;
};

struct join_gather_col_data {
	struct hw_join_gather_data key_data[DAE_MAX_KEY_COLS];
	struct hw_join_gather_data gather_data[DAE_MAX_TABLE_NUM][DAE_MAX_KEY_COLS];

	__u32 key_num;
	__u32 gather_table_num;
	__u32 gather_cols_num[DAE_MAX_TABLE_NUM];
	__u16 has_empty[DAE_MAX_TABLE_NUM];
	__u8 index_num;
};

struct hash_table_data {
	void *std_table;
	void *ext_table;
	__u64 std_table_size;
	__u64 ext_table_size;
	__u32 table_width;
};

struct join_gather_ctx {
	struct join_gather_col_data cols_data;
	struct hash_table_data table_data;
	struct hash_table_data rehash_table;
	pthread_spinlock_t lock;
	__u32 hash_table_row_size;
	__u32 batch_row_size[DAE_MAX_TABLE_NUM];
};

struct hisi_dae_ctx {
	struct wd_ctx_config_internal config;
};

static int get_free_ext_addr(struct dae_extend_addr *ext_addr)
{
	__u16 addr_num = ext_addr->addr_num;
	__u16 idx = ext_addr->tail;
	__u16 cnt = 0;

	/* The addr_num is equal to sq_depth(1024). */
	while (__atomic_test_and_set(&ext_addr->addr_status[idx], __ATOMIC_ACQUIRE)) {
		idx = (idx + 1) % addr_num;
		cnt++;
		if (cnt == addr_num)
			return -WD_EBUSY;
	}

	ext_addr->tail = (idx + 1) % addr_num;

	return idx;
}

static void put_ext_addr(struct dae_extend_addr *ext_addr, int idx)
{
	__atomic_clear(&ext_addr->addr_status[idx], __ATOMIC_RELEASE);
}

static void fill_join_gather_misc_field(struct wd_join_gather_msg *msg,
					struct dae_sqe *sqe)
{
	struct join_gather_ctx *ctx = msg->priv;
	struct join_gather_col_data *cols_data = &ctx->cols_data;

	sqe->sva_prefetch_en = true;

	switch (msg->op_type) {
	case WD_JOIN_BUILD_HASH:
		sqe->task_type = DAE_HASH_JOIN;
		sqe->task_type_ext = DAE_JOIN_BUILD_HASH;
		sqe->data_row_num = msg->req.input_row_num;
		sqe->batch_num = msg->req.join_req.build_batch_index;
		sqe->init_row_num = msg->req.join_req.batch_row_offset;
		sqe->index_num = cols_data->index_num;
		break;
	case WD_JOIN_PROBE:
		sqe->task_type = DAE_HASH_JOIN;
		sqe->task_type_ext = DAE_JOIN_PROBE;
		sqe->data_row_num = msg->req.output_row_num;
		sqe->batch_num = msg->req.input_row_num;
		sqe->init_row_num = msg->req.join_req.batch_row_offset;
		sqe->index_num = cols_data->index_num;
		sqe->key_out_en = msg->key_out_en;
		sqe->break_point_en = sqe->init_row_num ? true : false;
		sqe->index_batch_type = msg->index_type;
		break;
	case WD_JOIN_REHASH:
		sqe->task_type = DAE_HASH_JOIN;
		sqe->task_type_ext = DAE_JOIN_REHASH;
		sqe->data_row_num = msg->req.output_row_num;
		sqe->index_num = cols_data->index_num;
		break;
	case WD_GATHER_CONVERT:
		sqe->task_type = DAE_GATHER;
		sqe->task_type_ext = DAE_GATHER_CONVERT;
		sqe->data_row_num = msg->req.input_row_num;
		break;
	case WD_GATHER_COMPLETE:
		sqe->task_type = DAE_GATHER;
		sqe->task_type_ext = DAE_GATHER_COMPLETE;
		sqe->multi_batch_en = msg->multi_batch_en;
		sqe->index_batch_type = msg->index_type;
		sqe->data_row_num = msg->req.output_row_num;
		break;
	default:
		break;
	}
}

static void fill_join_table_data(struct dae_sqe *sqe, struct dae_addr_list *addr_list,
				 struct wd_join_gather_msg *msg)
{
	struct join_gather_ctx *ctx = (struct join_gather_ctx *)msg->priv;
	struct dae_table_addr *hw_table_src = &addr_list->src_table;
	struct dae_table_addr *hw_table_dst = &addr_list->dst_table;
	struct hash_table_data *table_data_src, *table_data_dst;

	switch (msg->op_type) {
	case WD_JOIN_BUILD_HASH:
		table_data_src = NULL;
		table_data_dst = &ctx->table_data;
		break;
	case WD_JOIN_REHASH:
		table_data_src = &ctx->rehash_table;
		table_data_dst = &ctx->table_data;
		break;
	case WD_JOIN_PROBE:
		table_data_src = &ctx->table_data;
		table_data_dst = NULL;
		break;
	default:
		return;
	}

	sqe->table_row_size = ctx->hash_table_row_size;

	if (table_data_src) {
		sqe->src_table_width = table_data_src->table_width;
		hw_table_src->std_table_addr = (__u64)(uintptr_t)table_data_src->std_table;
		hw_table_src->std_table_size = table_data_src->std_table_size;
		hw_table_src->ext_table_addr = (__u64)(uintptr_t)table_data_src->ext_table;
		hw_table_src->ext_table_size = table_data_src->ext_table_size;
	}

	if (table_data_dst) {
		sqe->dst_table_width = table_data_dst->table_width;
		hw_table_dst->std_table_addr = (__u64)(uintptr_t)table_data_dst->std_table;
		hw_table_dst->std_table_size = table_data_dst->std_table_size;
		hw_table_dst->ext_table_addr = (__u64)(uintptr_t)table_data_dst->ext_table;
		hw_table_dst->ext_table_size = table_data_dst->ext_table_size;
	}
}

static void fill_join_key_data(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
			       struct dae_addr_list *addr_list,
			       struct wd_join_gather_msg *msg)
{
	struct dae_probe_info_addr *info = &addr_list->probe_info;
	struct join_gather_ctx *ctx = msg->priv;
	struct hw_join_gather_data *key_data = ctx->cols_data.key_data;
	struct wd_dae_col_addr *usr_key, *out_usr_key = NULL;
	struct dae_col_addr *hw_key, *out_hw_key = NULL;
	struct wd_join_req *req = &msg->req.join_req;
	struct wd_probe_out_info *output = &req->probe_output;
	__u16 usr_col_idx;
	__u64 offset;
	__u32 i;

	sqe->key_col_bitmap = GENMASK(msg->key_cols_num - 1, 0);

	for (i = 0; i < msg->key_cols_num; i++) {
		sqe->key_data_type[i] = key_data[i].hw_type;
		ext_sqe->key_data_info[i] = key_data[i].data_info;
	}

	switch (msg->op_type) {
	case WD_JOIN_BUILD_HASH:
		usr_key = req->key_cols;
		hw_key = addr_list->input_addr;
		if (msg->index_type == WD_BATCH_ADDR_INDEX)
			sqe->addr_ext = (__u64)(uintptr_t)req->build_batch_addr.addr;
		break;
	case WD_JOIN_PROBE:
		usr_key = req->key_cols;
		hw_key = addr_list->input_addr;
		if (msg->key_out_en) {
			out_usr_key = output->key_cols;
			out_hw_key = addr_list->output_addr;
		}

		info->batch_num_index = (__u64)(uintptr_t)output->build_index.addr;
		info->probe_index_addr = (__u64)(uintptr_t)output->probe_index.addr;
		info->break_point_addr = (__u64)(uintptr_t)output->breakpoint.addr;

		if (msg->index_type == WD_BATCH_ADDR_INDEX) {
			offset = (__u64)output->build_index.row_size * output->build_index.row_num;
			offset = offset >> DAE_ADDR_INDEX_SHIFT;
			info->batch_addr_index = info->batch_num_index + offset;
		}
		break;
	default:
		return;
	}

	for (i = 0; i < msg->key_cols_num; i++) {
		usr_col_idx = key_data[i].usr_col_idx;
		hw_key[i].empty_addr = (__u64)(uintptr_t)usr_key[usr_col_idx].empty;
		hw_key[i].empty_size = usr_key[usr_col_idx].empty_size;
		hw_key[i].value_addr = (__u64)(uintptr_t)usr_key[usr_col_idx].value;
		hw_key[i].value_size = usr_key[usr_col_idx].value_size;

		if (!out_usr_key)
			continue;
		out_hw_key[i].empty_addr = (__u64)(uintptr_t)out_usr_key[usr_col_idx].empty;
		out_hw_key[i].empty_size = out_usr_key[usr_col_idx].empty_size;
		/* The hardware does not output the empty data, set the data by software. */
		memset(out_usr_key[usr_col_idx].empty, 0, out_usr_key[usr_col_idx].empty_size);

		out_hw_key[i].value_addr = (__u64)(uintptr_t)out_usr_key[usr_col_idx].value;
		out_hw_key[i].value_size = out_usr_key[usr_col_idx].value_size;
	}
}

static void fill_gather_col_data(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				 struct dae_addr_list *addr_list,
				 struct wd_join_gather_msg *msg)
{
	struct dae_probe_info_addr *info = &addr_list->probe_info;
	struct join_gather_ctx *ctx = msg->priv;
	struct join_gather_col_data *cols_data = &ctx->cols_data;
	struct wd_gather_req *gather_req = &msg->req.gather_req;
	__u32 table_index = gather_req->table_index;
	struct hw_join_gather_data *gather_data = cols_data->gather_data[table_index];
	__u16 cols_num = cols_data->gather_cols_num[table_index];
	struct wd_dae_col_addr *usr_data;
	struct dae_col_addr *hw_data;
	__u16 usr_col_idx;
	void **batch_addr;
	__u64 offset;
	__u32 i;

	sqe->key_col_bitmap = GENMASK(cols_num - 1, 0);
	sqe->has_empty = cols_data->has_empty[table_index];
	sqe->table_row_size = ctx->batch_row_size[table_index];

	usr_data = gather_req->data_cols;
	batch_addr = gather_req->row_batchs.batch_addr;

	switch (msg->op_type) {
	case WD_GATHER_CONVERT:
		hw_data = addr_list->input_addr;
		/* Single batch tasks use the first element of the array. */
		addr_list->dst_table.std_table_addr = (__u64)(uintptr_t)batch_addr[0];
		break;
	case WD_GATHER_COMPLETE:
		hw_data = addr_list->output_addr;
		if (!msg->multi_batch_en) {
			info->probe_index_addr = (__u64)(uintptr_t)gather_req->index.addr;
			addr_list->src_table.std_table_addr = (__u64)(uintptr_t)batch_addr[0];
			break;
		}

		info->batch_num_index = (__u64)(uintptr_t)gather_req->index.addr;
		if (msg->index_type == WD_BATCH_ADDR_INDEX) {
			offset = (__u64)gather_req->index.row_size * gather_req->index.row_num;
			offset = offset >> DAE_ADDR_INDEX_SHIFT;
			info->batch_addr_index = info->batch_num_index + offset;
		} else {
			addr_list->src_table.std_table_addr = (__u64)(uintptr_t)batch_addr;
		}
		break;
	default:
		return;
	}

	for (i = 0; i < cols_num; i++) {
		sqe->key_data_type[i] = gather_data[i].hw_type;
		ext_sqe->key_data_info[i] = gather_data[i].data_info;

		usr_col_idx = gather_data[i].usr_col_idx;
		hw_data[i].empty_addr = (__u64)(uintptr_t)usr_data[usr_col_idx].empty;
		hw_data[i].empty_size = usr_data[usr_col_idx].empty_size;
		hw_data[i].value_addr = (__u64)(uintptr_t)usr_data[usr_col_idx].value;
		hw_data[i].value_size = usr_data[usr_col_idx].value_size;
	}
}

static void fill_join_gather_ext_addr(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				      struct dae_addr_list *addr_list)
{
	memset(ext_sqe, 0, DAE_EXT_SQE_SIZE);
	memset(addr_list, 0, sizeof(struct dae_addr_list));
	sqe->addr_list = (__u64)(uintptr_t)addr_list;
	addr_list->ext_sqe_addr = (__u64)(uintptr_t)ext_sqe;
	addr_list->ext_sqe_size = DAE_EXT_SQE_SIZE;
}

static void fill_join_gather_info(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				  struct dae_addr_list *addr_list,
				  struct wd_join_gather_msg *msg)
{
	fill_join_gather_ext_addr(sqe, ext_sqe, addr_list);
	sqe->bd_type = DAE_BD_TYPE_V2;

	switch (msg->op_type) {
	case WD_JOIN_BUILD_HASH:
	case WD_JOIN_PROBE:
	case WD_JOIN_REHASH:
		fill_join_table_data(sqe, addr_list, msg);
		fill_join_key_data(sqe, ext_sqe, addr_list, msg);
		break;
	case WD_GATHER_CONVERT:
	case WD_GATHER_COMPLETE:
		fill_gather_col_data(sqe, ext_sqe, addr_list, msg);
		break;
	default:
		break;
	}
}

static int check_join_gather_param(struct wd_join_gather_msg *msg)
{
	struct wd_probe_out_info *output = &msg->req.join_req.probe_output;
	struct wd_gather_req *greq = &msg->req.gather_req;
	__u64 row_num;
	__u64 size;

	if (!msg) {
		WD_ERR("invalid: input join gather msg is NULL!\n");
		return -WD_EINVAL;
	}

	switch (msg->op_type) {
	case WD_JOIN_BUILD_HASH:
		if (msg->req.input_row_num > DAE_JOIN_MAX_ROW_NUN) {
			WD_ERR("invalid: build table row count %u is more than %d!\n",
			       msg->req.input_row_num, DAE_JOIN_MAX_ROW_NUN);
			return -WD_EINVAL;
		}
		if (msg->index_type == WD_BATCH_NUMBER_INDEX) {
			if (msg->req.join_req.build_batch_index >= DAE_JOIN_MAX_BATCH_NUM) {
				WD_ERR("invalid: input join batch index is more than %d!\n",
				       DAE_JOIN_MAX_BATCH_NUM - 1);
				return -WD_EINVAL;
			}
		} else {
			if (!msg->req.join_req.build_batch_addr.addr ||
			    !msg->req.join_req.build_batch_addr.row_num ||
			    !msg->req.join_req.build_batch_addr.row_size) {
				WD_ERR("invalid: input join build batch addr is NULL!\n");
				return -WD_EINVAL;
			}
		}
		break;
	case WD_JOIN_PROBE:
		size = (__u64)output->breakpoint.row_size * output->breakpoint.row_num;
		if (!output->breakpoint.addr || size < DAE_BREAKPOINT_SIZE) {
			WD_ERR("invalid probe breakpoint size: %llu\n", size);
			return -WD_EINVAL;
		}
		if (msg->index_type == WD_BATCH_ADDR_INDEX) {
			row_num = msg->req.output_row_num << DAE_ADDR_INDEX_SHIFT;
			if (output->build_index.row_num < row_num) {
				WD_ERR("build index row number is less than: %llu\n",
				       row_num);
				return -WD_EINVAL;
			}
		}

		if (output->probe_index.row_size != PROBE_INDEX_ROW_SIZE ||
		    output->build_index.row_size != BUILD_INDEX_ROW_SIZE) {
			WD_ERR("build and probe index row size need be %d, %d!\n",
			       BUILD_INDEX_ROW_SIZE, PROBE_INDEX_ROW_SIZE);
			return -WD_EINVAL;
		}
		break;
	case WD_JOIN_REHASH:
	case WD_GATHER_CONVERT:
		break;
	case WD_GATHER_COMPLETE:
		if (!msg->multi_batch_en) {
			if (greq->index.row_size != PROBE_INDEX_ROW_SIZE) {
				WD_ERR("invalid: probe index row size need be %d!\n",
				       PROBE_INDEX_ROW_SIZE);
				return -WD_EINVAL;
			}
			break;
		}

		if (greq->index.row_size != BUILD_INDEX_ROW_SIZE) {
			WD_ERR("invalid: build index row size need be %d!\n",
			       BUILD_INDEX_ROW_SIZE);
			return -WD_EINVAL;
		}
		if (msg->index_type == WD_BATCH_NUMBER_INDEX) {
			if (greq->row_batchs.batch_num > DAE_JOIN_MAX_BATCH_NUM) {
				WD_ERR("invalid: gather row batch num is more than %d!\n",
				       DAE_JOIN_MAX_BATCH_NUM);
				return -WD_EINVAL;
			}
		} else {
			row_num = msg->req.output_row_num << DAE_ADDR_INDEX_SHIFT;
			if (greq->index.row_num < row_num) {
				WD_ERR("build index row number is less than: %llu\n",
				       row_num);
				return -WD_EINVAL;
			}
		}
		break;
	default:
		break;
	}

	return WD_SUCCESS;
}

static int join_gather_send(struct wd_alg_driver *drv, handle_t ctx, void *send_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct dae_extend_addr *ext_addr = qp->priv;
	struct wd_join_gather_msg *msg = send_msg;
	struct dae_addr_list *addr_list;
	struct dae_ext_sqe *ext_sqe;
	struct dae_sqe sqe = {0};
	__u16 send_cnt = 0;
	int ret, idx;

	ret = check_join_gather_param(msg);
	if (ret)
		return ret;

	fill_join_gather_misc_field(msg, &sqe);

	idx = get_free_ext_addr(ext_addr);
	if (idx < 0)
		return -WD_EBUSY;
	addr_list = &ext_addr->addr_list[idx];
	ext_sqe = &ext_addr->ext_sqe[idx];

	fill_join_gather_info(&sqe, ext_sqe, addr_list, msg);

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.low_tag = msg->tag;
	sqe.hi_tag = idx;

	ret = hisi_qm_send(h_qp, &sqe, 1, &send_cnt);
	if (ret) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send to hardware, ret = %d!\n", ret);
		put_ext_addr(ext_addr, idx);
		return ret;
	}

	return WD_SUCCESS;
}

static void fill_join_gather_task_done(struct dae_sqe *sqe, struct wd_join_gather_msg *msg,
				       struct wd_join_gather_msg *temp_msg,
				       struct join_gather_ctx *ctx)
{
	if (sqe->task_type == DAE_HASH_JOIN) {
		if (sqe->task_type_ext == DAE_JOIN_PROBE) {
			msg->consumed_row_num = sqe->next_init_row_num;
			msg->produced_row_num = sqe->out_raw_num;
			msg->output_done = sqe->output_end;
		} else if (sqe->task_type_ext == DAE_JOIN_REHASH) {
			msg->output_done = sqe->output_end;
		}
	}
}

static void fill_join_gather_task_err(struct dae_sqe *sqe, struct wd_join_gather_msg *msg,
				      struct wd_join_gather_msg *temp_msg,
				      struct join_gather_ctx *ctx)
{
	switch (sqe->err_type) {
	case DAE_TASK_BD_ERROR_MIN ... DAE_TASK_BD_ERROR_MAX:
		WD_ERR("failed to do join gather task, bd error=0x%x!\n", sqe->err_type);
		msg->result = WD_JOIN_GATHER_PARSE_ERROR;
		break;
	case DAE_HASH_TABLE_NEED_REHASH:
		msg->result = WD_JOIN_GATHER_NEED_REHASH;
		break;
	case DAE_HASH_TABLE_INVALID:
		msg->result = WD_JOIN_GATHER_INVALID_HASH_TABLE;
		break;
	case DAE_JOIN_GATHER_BUS_ERROR:
		WD_ERR("failed to do join gather task, bus error %u!\n", sqe->err_type);
		msg->result = WD_JOIN_GATHER_BUS_ERROR;
		break;
	default:
		WD_ERR("failed to do dae task! done_flag=0x%x, etype=0x%x, ext_type = 0x%x!\n",
			(__u32)sqe->done_flag, (__u32)sqe->err_type, (__u32)sqe->ext_err_type);
		msg->result = WD_JOIN_GATHER_PARSE_ERROR;
		break;
	}

	if (sqe->task_type == DAE_HASH_JOIN && sqe->task_type_ext == DAE_JOIN_PROBE) {
		msg->produced_row_num = sqe->out_raw_num;
		msg->consumed_row_num = sqe->next_init_row_num;
		msg->output_done = sqe->output_end;
	}
}

static int join_gather_recv(struct wd_alg_driver *drv, handle_t hctx, void *recv_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(hctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct dae_extend_addr *ext_addr = qp->priv;
	struct wd_join_gather_msg *msg = recv_msg;
	struct wd_join_gather_msg *temp_msg = msg;
	struct join_gather_ctx *ctx;
	struct dae_sqe sqe = {0};
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &recv_cnt);
	if (ret)
		return ret;

	ret = hisi_check_bd_id(h_qp, msg->tag, sqe.low_tag);
	if (ret)
		goto out;

	msg->tag = sqe.low_tag;
	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		temp_msg = wd_join_gather_get_msg(qp->q_info.idx, msg->tag);
		if (!temp_msg) {
			msg->result = WD_JOIN_GATHER_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
			       qp->q_info.idx, msg->tag);
			ret = -WD_EINVAL;
			goto out;
		}
	}

	ctx = (struct join_gather_ctx *)temp_msg->priv;
	msg->result = WD_JOIN_GATHER_TASK_DONE;
	msg->consumed_row_num = 0;

	if (likely(sqe.done_flag == DAE_HW_TASK_DONE)) {
		fill_join_gather_task_done(&sqe, msg, temp_msg, ctx);
	} else if (sqe.done_flag == DAE_HW_TASK_ERR) {
		fill_join_gather_task_err(&sqe, msg, temp_msg, ctx);
	} else {
		msg->result = WD_JOIN_GATHER_PARSE_ERROR;
		WD_ERR("failed to do join gather task, hardware doesn't process the task!\n");
	}

out:
	put_ext_addr(ext_addr, sqe.hi_tag);
	return ret;
}

static int join_check_params(struct wd_join_gather_col_info *key_info, __u32 cols_num)
{
	__u32 i;

	if (cols_num > DAE_MAX_KEY_COLS) {
		WD_ERR("invalid: join key cols num %u is more than device support %d!\n",
			cols_num, DAE_MAX_KEY_COLS);
		return -WD_EINVAL;
	}

	for (i = 0; i < cols_num; i++) {
		switch (key_info[i].data_type) {
		case WD_DAE_CHAR:
		case WD_DAE_VARCHAR:
			WD_ERR("invalid: key col %u, char or varchar isn't supported!\n", i);
			return -WD_EINVAL;
		default:
			break;
		}
	}

	return WD_SUCCESS;
}

static int gather_check_params(struct wd_join_gather_sess_setup *setup)
{
	struct wd_gather_table_info *table = setup->gather_tables;
	struct wd_join_gather_col_info *col;
	__u32 i, j;

	if (setup->gather_table_num > DAE_MAX_TABLE_NUM) {
		WD_ERR("invalid: gather table num %u is more than device support %d!\n",
		       setup->gather_table_num, DAE_MAX_TABLE_NUM);
		return -WD_EINVAL;
	}

	for (i = 0; i < setup->gather_table_num; i++) {
		col = table[i].cols;
		if (table[i].cols_num > DAE_MAX_KEY_COLS) {
			WD_ERR("invalid: gather cols num %u is more than device support %d!\n",
			       table[i].cols_num, DAE_MAX_KEY_COLS);
			return -WD_EINVAL;
		}
		for (j = 0; j < table[i].cols_num; i++) {
			switch (col[j].data_type) {
			case WD_DAE_CHAR:
				if (col[j].data_info > DAE_MAX_CHAR_SIZE) {
					WD_ERR("gather col %u, char size isn't supported!\n", i);
					return -WD_EINVAL;
				}
				break;
			case WD_DAE_VARCHAR:
				WD_ERR("invalid: gather col %u, varchar isn't supported!\n", i);
				return -WD_EINVAL;
			default:
				break;
			}
		}
	}

	return WD_SUCCESS;
}

static int join_gather_param_check(struct wd_join_gather_sess_setup *setup, __u16 hw_type)
{
	int ret;

	switch (setup->alg) {
	case WD_JOIN:
		return join_check_params(setup->join_table.build_key_cols,
					 setup->join_table.build_key_cols_num);
	case WD_GATHER:
		return gather_check_params(setup);
	case WD_JOIN_GATHER:
		ret = join_check_params(setup->join_table.build_key_cols,
					setup->join_table.build_key_cols_num);
		if (ret)
			return ret;

		return gather_check_params(setup);
	default:
		return -WD_EINVAL;
	}
}

static __u32 get_data_type_size(enum dae_data_type type, __u16 data_info)
{
	switch (type) {
	case DAE_SINT32:
		return SINT32_SIZE;
	case DAE_SINT64:
	case DAE_DECIMAL64:
		return SINT64_SIZE;
	case DAE_DECIMAL128:
		return DECIMAL128_SIZE;
	case DAE_CHAR:
		return ALIGN(data_info, DAE_CHAR_ALIGN_SIZE);
	default:
		break;
	}

	return 0;
}

static int transfer_col_info(struct wd_join_gather_col_info *cols,
			     struct hw_join_gather_data *data, __u32 col_num)
{
	__u32 i;

	for (i = 0; i < col_num; i++) {
		switch (cols[i].data_type) {
		case WD_DAE_CHAR:
			data[i].hw_type = DAE_CHAR;
			data[i].data_info = cols[i].data_info;
			break;
		case WD_DAE_LONG_DECIMAL:
			data[i].hw_type = DAE_DECIMAL128;
			break;
		case WD_DAE_SHORT_DECIMAL:
			data[i].hw_type = DAE_DECIMAL64;
			break;
		case WD_DAE_LONG:
			data[i].hw_type = DAE_SINT64;
			break;
		case WD_DAE_INT:
		case WD_DAE_DATE:
			data[i].hw_type = DAE_SINT32;
			break;
		default:
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int transfer_data_to_hw_type(struct join_gather_col_data *cols_data,
				    struct wd_join_gather_sess_setup *setup)
{
	struct hw_join_gather_data tmp_data[DAE_MAX_KEY_COLS] = {0};
	struct wd_gather_table_info *tables = setup->gather_tables;
	struct wd_join_gather_col_info *gather_cols;
	struct hw_join_gather_data *hw_data;
	__u32 type_num = ARRAY_SIZE(hw_data_type_order);
	__u32 n, i, j, k = 0;
	int ret;

	for (n = 0; n < setup->gather_table_num; n++) {
		gather_cols = tables[n].cols;
		hw_data = cols_data->gather_data[n];
		/* Set k to 0 for each table. */
		k = 0;
		ret = transfer_col_info(gather_cols, tmp_data, tables[n].cols_num);
		if (ret)
			return ret;

		for (i = 0; i < type_num; i++) {
			for (j = 0; j < tables[n].cols_num; j++) {
				if (hw_data_type_order[i] != tmp_data[j].hw_type)
					continue;
				hw_data[k].usr_col_idx = j;
				hw_data[k].hw_type = tmp_data[j].hw_type;
				hw_data[k++].data_info = tmp_data[j].data_info;
			}
		}

		cols_data->gather_cols_num[n] = tables[n].cols_num;
		for (j = 0; j < tables[n].cols_num; j++)
			if (gather_cols[j].has_empty)
				cols_data->has_empty[n] |= (1 << j);
	}

	return WD_SUCCESS;
}

static int transfer_key_to_hw_type(struct join_gather_col_data *cols_data,
				   struct wd_join_gather_sess_setup *setup)
{
	struct wd_join_gather_col_info *key_cols = setup->join_table.build_key_cols;
	struct hw_join_gather_data tmp_key_data[DAE_MAX_KEY_COLS] = {0};
	struct hw_join_gather_data *hw_key_data = cols_data->key_data;
	__u32 cols_num = setup->join_table.build_key_cols_num;
	__u32 type_num = ARRAY_SIZE(hw_data_type_order);
	__u32 i, j, k = 0;
	int ret;

	ret = transfer_col_info(key_cols, tmp_key_data, cols_num);
	if (ret)
		return ret;

	for (i = 0; i < type_num; i++) {
		for (j = 0; j < cols_num; j++) {
			if (hw_data_type_order[i] != tmp_key_data[j].hw_type)
				continue;
			hw_key_data[k].usr_col_idx = j;
			hw_key_data[k].hw_type = tmp_key_data[j].hw_type;
			hw_key_data[k++].data_info = tmp_key_data[j].data_info;
		}
	}

	cols_data->key_num = cols_num;

	return WD_SUCCESS;
}

static int join_get_table_rowsize(struct join_gather_col_data *cols_data,
				  struct wd_join_gather_sess_setup *setup)
{
	struct hw_join_gather_data *key_data = cols_data->key_data;
	__u32 key_num = cols_data->key_num;
	__u64 row_count_size = 0;
	__u32 i;

	cols_data->index_num = setup->join_table.hash_table_index_num;

	if (cols_data->index_num > HASH_TABLE_MAX_INDEX_NUM) {
		WD_ERR("invalid: hash table index num is not supported!\n");
		return -WD_EINVAL;
	} else if (!cols_data->index_num) {
		WD_INFO("Hash table index num is not set, set to default: 1!\n");
		cols_data->index_num = HASH_TABLE_INDEX_NUM;
	}

	/* With a restriction on the col number, the sum lengths will not overflow. */
	for (i = 0; i < key_num; i++)
		row_count_size += get_data_type_size(key_data[i].hw_type, 0);

	row_count_size = ALIGN(row_count_size, DAE_KEY_ALIGN_SIZE);
	row_count_size += HASH_TABLE_HEAD_TAIL_SIZE +
			  cols_data->index_num * HASH_TABLE_INDEX_SIZE;
	if (row_count_size > DAE_MAX_ROW_SIZE) {
		WD_ERR("invalid: hash table row size %llu, hash_table_index_num %u!\n",
		       row_count_size, cols_data->index_num);
		return -WD_EINVAL;
	}

	if (row_count_size <= ROW_SIZE32)
		return ROW_SIZE32;

	if (row_count_size <= ROW_SIZE64)
		return ROW_SIZE64;

	if (row_count_size <= ROW_SIZE128)
		return ROW_SIZE128;

	if (row_count_size <= ROW_SIZE256)
		return ROW_SIZE256;

	return ROW_SIZE512;
}

static void gather_get_batch_rowsize(struct join_gather_col_data *cols_data,
				     struct wd_join_gather_sess_setup *setup,
				     __u32 *batch_row_size)
{
	struct wd_gather_table_info *tables = setup->gather_tables;
	struct hw_join_gather_data *gather_data;
	__u32 row_count_size = 0;
	__u32 n, i;

	cols_data->gather_table_num = setup->gather_table_num;
	for (n = 0; n < setup->gather_table_num; n++) {
		row_count_size = 0;
		gather_data = cols_data->gather_data[n];

		/* With a restriction on the col number, the sum length will not overflow. */
		for (i = 0; i < tables[n].cols_num; i++)
			row_count_size += get_data_type_size(gather_data[i].hw_type,
							     gather_data[i].data_info);

		batch_row_size[n] = row_count_size + GATHER_ROW_BATCH_EMPTY_SIZE;
	}
}

static int join_gather_fill_ctx(struct join_gather_ctx *ctx,
				struct wd_join_gather_sess_setup *setup)
{
	struct join_gather_col_data *cols_data = &ctx->cols_data;
	int ret;

	if (setup->alg != WD_GATHER) {
		ret = transfer_key_to_hw_type(cols_data, setup);
		if (ret)
			return ret;

		ret = join_get_table_rowsize(cols_data, setup);
		if (ret < 0)
			return -WD_EINVAL;
		ctx->hash_table_row_size = ret;
	}

	if (setup->alg != WD_JOIN) {
		ret = transfer_data_to_hw_type(cols_data, setup);
		if (ret)
			return ret;

		gather_get_batch_rowsize(cols_data, setup, ctx->batch_row_size);
	}

	return WD_SUCCESS;
}

static void join_gather_sess_priv_uninit(struct wd_alg_driver *drv, void *priv)
{
	struct join_gather_ctx *ctx = priv;

	if (!ctx) {
		WD_ERR("invalid: dae sess uninit priv is NULL!\n");
		return;
	}

	pthread_spin_destroy(&ctx->lock);
	free(ctx);
}

static int join_gather_sess_priv_init(struct wd_alg_driver *drv,
				      struct wd_join_gather_sess_setup *setup, void **priv)
{
	struct wd_ctx_config_internal *config;
	struct hisi_dae_ctx *dae_priv;
	struct join_gather_ctx *ctx;
	struct hisi_qp *qp;
	handle_t h_qp;
	int ret;

	if (!drv || !drv->priv) {
		WD_ERR("invalid: dae drv is NULL!\n");
		return -WD_EINVAL;
	}

	if (!setup || !priv) {
		WD_ERR("invalid: dae sess priv is NULL!\n");
		return -WD_EINVAL;
	}

	dae_priv = (struct hisi_dae_ctx *)drv->priv;
	config = &dae_priv->config;
	h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[0].ctx);
	qp = (struct hisi_qp *)h_qp;

	ret = join_gather_param_check(setup, qp->q_info.hw_type);
	if (ret)
		return -WD_EINVAL;

	ctx = calloc(1, sizeof(struct join_gather_ctx));
	if (!ctx)
		return -WD_ENOMEM;

	ret = join_gather_fill_ctx(ctx, setup);
	if (ret)
		goto free_ctx;

	ret = pthread_spin_init(&ctx->lock, PTHREAD_PROCESS_SHARED);
	if (ret)
		goto free_ctx;

	*priv = ctx;

	return WD_SUCCESS;

free_ctx:
	free(ctx);
	return ret;
}

static void dae_uninit_qp_priv(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct dae_extend_addr *ext_addr = (struct dae_extend_addr *)qp->priv;

	free(ext_addr->addr_list);
	free(ext_addr->addr_status);
	free(ext_addr->ext_sqe);
	free(ext_addr);
	qp->priv = NULL;
}

static int dae_init_qp_priv(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	__u16 sq_depth = qp->q_info.sq_depth;
	struct dae_extend_addr *ext_addr;
	int ret = -WD_ENOMEM;

	ext_addr = calloc(1, sizeof(struct dae_extend_addr));
	if (!ext_addr)
		return ret;

	ext_addr->ext_sqe = aligned_alloc(DAE_ADDR_ALIGN_SIZE, DAE_EXT_SQE_SIZE * sq_depth);
	if (!ext_addr->ext_sqe)
		goto free_ext_addr;

	ext_addr->addr_status = calloc(1, sizeof(__u8) * sq_depth);
	if (!ext_addr->addr_status)
		goto free_ext_sqe;

	ext_addr->addr_list = aligned_alloc(DAE_ADDR_ALIGN_SIZE,
					    sizeof(struct dae_addr_list) * sq_depth);
	if (!ext_addr->addr_list)
		goto free_addr_status;

	ext_addr->addr_num = sq_depth;
	qp->priv = ext_addr;

	return WD_SUCCESS;

free_addr_status:
	free(ext_addr->addr_status);
free_ext_sqe:
	free(ext_addr->ext_sqe);
free_ext_addr:
	free(ext_addr);

	return ret;
}

static int join_get_table_row_size(struct wd_alg_driver *drv, void *param)
{
	struct join_gather_ctx *ctx = param;

	if (!ctx)
		return -WD_EINVAL;

	return ctx->hash_table_row_size;
}

static int gather_get_batch_row_size(struct wd_alg_driver *drv, void *param,
				     __u32 *row_size, __u32 size)
{
	struct join_gather_ctx *ctx = param;

	if (!ctx)
		return -WD_EINVAL;

	if (!size || size >  DAE_MAX_TABLE_NUM * sizeof(__u32))
		return -WD_EINVAL;

	memcpy(row_size, ctx->batch_row_size, size);

	return 0;
}

static __u32 dae_ext_table_rownum(void **ext_table, struct wd_dae_hash_table *table,
				  __u32 row_size)
{
	__u64 tlb_size, tmp_size, row_num;
	void *tmp_table;

	/*
	 * The first row of the extended hash table stores the hash table information,
	 * and the second row stores the aggregated data. The 128-bytes aligned address
	 * in the second row provides the optimal performance.
	 */
	tmp_table = PTR_ALIGN(table->ext_table, DAE_TABLE_ALIGN_SIZE);
	tlb_size = (__u64)table->table_row_size * table->ext_table_row_num;
	tmp_size = (__u64)(uintptr_t)tmp_table - (__u64)(uintptr_t)table->ext_table;
	if (tmp_size >= tlb_size)
		return 0;

	row_num = (tlb_size - tmp_size) / row_size;
	if (row_size == ROW_SIZE32) {
		if (tmp_size >= row_size) {
			tmp_table = (__u8 *)tmp_table - row_size;
			row_num += 1;
		} else {
			/*
			 * When row size is 32 bytes, the first 96 bytes are not used.
			 * Ensure that the address of the second row is 128 bytes aligned.
			 */
			if (row_num <= HASH_TABLE_OFFSET_3ROW)
				return 0;

			tmp_table = (__u8 *)tmp_table + HASH_TABLE_OFFSET_3ROW * row_size;
			row_num -= HASH_TABLE_OFFSET_3ROW;
		}
	} else if (row_size == ROW_SIZE64) {
		if (tmp_size >= row_size) {
			tmp_table = (__u8 *)tmp_table - row_size;
			row_num += 1;
		} else {
			/*
			 * When row size is 64 bytes, the first 64 bytes are not used.
			 * Ensure that the address of the second row is 128 bytes aligned.
			 */
			if (row_num <= HASH_TABLE_OFFSET_1ROW)
				return 0;

			tmp_table = (__u8 *)tmp_table + HASH_TABLE_OFFSET_1ROW * row_size;
			row_num -= HASH_TABLE_OFFSET_1ROW;
		}
	}

	*ext_table = tmp_table;

	return row_num;
}

static int dae_ext_table_init(struct join_gather_ctx *ctx,
			      struct wd_dae_hash_table *table, bool is_rehash)
{
	struct hash_table_data *hw_table = &ctx->table_data;
	__u64 ext_size = hw_table->ext_table_size;
	__u32 row_size = ctx->hash_table_row_size;
	__u64 tlb_size, row_num;
	void *ext_table;
	__u8 *ext_valid;
	__u64 *ext_row;

	row_num = dae_ext_table_rownum(&ext_table, table, row_size);
	if (row_num <= 1) {
		WD_ERR("invalid: extend table row num is less than device need!\n");
		return -WD_EINVAL;
	}

	tlb_size = row_num * row_size;
	if (is_rehash && tlb_size <= ext_size) {
		WD_ERR("rehash extend table size %llu is not longer than current %llu!\n",
			tlb_size, ext_size);
		return -WD_EINVAL;
	}

	/*
	 * If table has been initialized, save the previous data
	 * before replacing the new table.
	 */
	if (is_rehash)
		memcpy(&ctx->rehash_table, hw_table, sizeof(struct hash_table_data));

	/* Initialize the extend table value. */
	memset(ext_table, 0, tlb_size);
	ext_valid = (__u8 *)ext_table + HASH_EXT_TABLE_INVALID_OFFSET;
	*ext_valid = HASH_EXT_TABLE_VALID;
	ext_row = (__u64 *)ext_table + 1;
	*ext_row = row_num - 1;

	hw_table->ext_table = ext_table;
	hw_table->ext_table_size = tlb_size;

	return WD_SUCCESS;
}

static int dae_std_table_init(struct hash_table_data *hw_table,
			      struct wd_dae_hash_table *table, __u32 row_size)
{
	__u64 tlb_size, row_num, tmp_size;

	/*
	 * Hash table address must be 128-bytes aligned, and the number
	 * of rows in a standard hash table must be a power of 2.
	 */
	hw_table->std_table = PTR_ALIGN(table->std_table, DAE_TABLE_ALIGN_SIZE);
	tlb_size = (__u64)table->table_row_size * table->std_table_row_num;
	tmp_size = (__u64)(uintptr_t)hw_table->std_table - (__u64)(uintptr_t)table->std_table;
	if (tmp_size >= tlb_size) {
		WD_ERR("invalid: after aligned, standard table size is less than 0!\n");
		return -WD_EINVAL;
	}

	row_num = (tlb_size - tmp_size) / row_size;
	if (!row_num) {
		WD_ERR("invalid: standard table row num is 0!\n");
		return -WD_EINVAL;
	}

	hw_table->table_width = (__u32)log2(row_num);
	if (hw_table->table_width < HASH_TABLE_MIN_WIDTH ||
	    hw_table->table_width > HASH_TABLE_MAX_WIDTH) {
		WD_ERR("standard table width %u is out of device support range %d~%d!\n",
			hw_table->table_width, HASH_TABLE_MIN_WIDTH, HASH_TABLE_MAX_WIDTH);
		return -WD_EINVAL;
	}

	row_num = (__u64)pow(HASH_TABLE_WITDH_POWER, hw_table->table_width);
	hw_table->std_table_size = row_num * row_size;
	memset(hw_table->std_table, 0, hw_table->std_table_size);

	return WD_SUCCESS;
}

static int join_hash_table_init(struct wd_alg_driver *drv,
				struct wd_dae_hash_table *table, void *priv)
{
	struct join_gather_ctx *ctx = priv;
	struct hash_table_data *hw_table;
	bool is_rehash = false;
	int ret;

	if (!ctx || !table)
		return -WD_EINVAL;

	if (!ctx->hash_table_row_size || ctx->hash_table_row_size > table->table_row_size) {
		WD_ERR("invalid: row size %u is error, device need %u!\n",
			table->table_row_size, ctx->hash_table_row_size);
		return -WD_EINVAL;
	}

	/* hash_std_table is checked by caller */
	if (!table->ext_table || !table->ext_table_row_num) {
		WD_ERR("invalid: hash extend table is null!\n");
		return -WD_EINVAL;
	}

	hw_table = &ctx->table_data;
	if (hw_table->std_table_size)
		is_rehash = true;

	ret = dae_ext_table_init(ctx, table, is_rehash);
	if (ret)
		return ret;

	ret = dae_std_table_init(hw_table, table, ctx->hash_table_row_size);
	if (ret)
		goto update_table;

	return WD_SUCCESS;

update_table:
	if (is_rehash)
		memcpy(hw_table, &ctx->rehash_table, sizeof(struct hash_table_data));
	else
		memset(hw_table, 0, sizeof(struct hash_table_data));
	return ret;
}

static int dae_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = conf;
	struct hisi_qm_priv qm_priv;
	struct hisi_dae_ctx *priv;
	handle_t h_qp = 0;
	handle_t h_ctx;
	__u32 i, j;
	int ret;

	if (!config || !config->ctx_num) {
		WD_ERR("invalid: dae init config is null or ctx num is 0!\n");
		return -WD_EINVAL;
	}

	priv = malloc(sizeof(struct hisi_dae_ctx));
	if (!priv)
		return -WD_ENOMEM;

	qm_priv.op_type = DAE_SQC_ALG_TYPE;
	qm_priv.sqe_size = sizeof(struct dae_sqe);
	/* Allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		/* Setting the epoll en to 0 for ASYNC ctx */
		qm_priv.epoll_en = (qm_priv.qp_mode == CTX_MODE_SYNC) ?
				   config->epoll_en : 0;
		qm_priv.idx = i;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp) {
			ret = -WD_ENOMEM;
			goto out;
		}
		config->ctxs[i].sqn = qm_priv.sqn;
		ret = dae_init_qp_priv(h_qp);
		if (ret)
			goto free_h_qp;
	}
	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));
	drv->priv = priv;

	return WD_SUCCESS;

free_h_qp:
	hisi_qm_free_qp(h_qp);
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		dae_uninit_qp_priv(h_qp);
		hisi_qm_free_qp(h_qp);
	}
	free(priv);
	return ret;
}

static void dae_exit(struct wd_alg_driver *drv)
{
	struct wd_ctx_config_internal *config;
	struct hisi_dae_ctx *priv;
	handle_t h_qp;
	__u32 i;

	if (!drv || !drv->priv)
		return;

	priv = (struct hisi_dae_ctx *)drv->priv;
	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		dae_uninit_qp_priv(h_qp);
		hisi_qm_free_qp(h_qp);
	}

	free(priv);
	drv->priv = NULL;
}

static int join_gather_get_extend_ops(void *ops)
{
	struct wd_join_gather_ops *join_gather_ops = (struct wd_join_gather_ops *)ops;

	if (!join_gather_ops)
		return -WD_EINVAL;

	join_gather_ops->get_table_row_size = join_get_table_row_size;
	join_gather_ops->get_batch_row_size = gather_get_batch_row_size;
	join_gather_ops->hash_table_init = join_hash_table_init;
	join_gather_ops->sess_init = join_gather_sess_priv_init;
	join_gather_ops->sess_uninit = join_gather_sess_priv_uninit;

	return WD_SUCCESS;
}


#define GEN_JOIN_GATHER_DRIVER(dae_alg_name) \
{\
	.drv_name = "hisi_zip",\
	.alg_name = (dae_alg_name),\
	.calc_type = UADK_ALG_HW,\
	.priority = 100,\
	.queue_num = DAE_CTX_Q_NUM_DEF,\
	.op_type_num = 1,\
	.fallback = 0,\
	.init = dae_init,\
	.exit = dae_exit,\
	.send = join_gather_send,\
	.recv = join_gather_recv,\
	.get_extend_ops = join_gather_get_extend_ops,\
}

static struct wd_alg_driver join_gather_driver[] = {
	GEN_JOIN_GATHER_DRIVER("hashjoin"),
	GEN_JOIN_GATHER_DRIVER("gather"),
	GEN_JOIN_GATHER_DRIVER("join-gather"),
};

#ifdef WD_STATIC_DRV
void hisi_dae_join_gather_probe(void)
#else
static void __attribute__((constructor)) hisi_dae_join_gather_probe(void)
#endif
{
	__u32 alg_num = ARRAY_SIZE(join_gather_driver);
	int ret;
	__u32 i;

	WD_INFO("Info: register DAE hashjoin and gather alg drivers!\n");
	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&join_gather_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register %s failed!\n",
			       join_gather_driver[i].alg_name);
	}
}

#ifdef WD_STATIC_DRV
void hisi_dae_join_gather_remove(void)
#else
static void __attribute__((destructor)) hisi_dae_join_gather_remove(void)
#endif
{
	__u32 alg_num = ARRAY_SIZE(join_gather_driver);
	__u32 i;

	WD_INFO("Info: unregister DAE alg drivers!\n");
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&join_gather_driver[i]);
}
