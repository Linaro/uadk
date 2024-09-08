// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved. */

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
#include "../include/drv/wd_agg_drv.h"

#define DAE_HASH_AGG_TYPE	2
#define DAE_EXT_SQE_SIZE	128
#define DAE_CTX_Q_NUM_DEF	1

/* will remove in next version */
#define DAE_HASHAGG_SUM		0x1
#define DAE_HASHAGG_COUNT	0x2
#define DAE_HASH_COUNT_ALL	0x1

/* column information */
#define DAE_MAX_KEY_COLS	9
#define DAE_MAX_INPUT_COLS	9
#define DAE_MAX_OUTPUT_COLS	9
#define DAE_MAX_CHAR_COL_NUM	5
#define DAE_MAX_CHAR_SIZE	32
#define DAE_MAX_VCHAR_SIZE	30
#define DAE_MAX_8B_COLS_NUM	8
#define DAE_MAX_16B_COLS_NUM	8
#define DAE_MAX_ADDR_NUM	32
#define DAE_MIN_ROW_SIZE	11
#define DAE_MAX_ROW_SIZE	256
#define DAE_VCHAR_OFFSET_SIZE	2
#define DAE_COL_BIT_NUM		4
#define DAE_AGG_START_COL	16
#define DAE_HASHAGG_MAX_ROW_NUN	50000

/* align size */
#define DAE_CHAR_ALIGN_SIZE	4
#define DAE_TABLE_ALIGN_SIZE	128
#define DAE_ADDR_ALIGN_SIZE	128

/* decimal infomartion */
#define DAE_DECIMAL_PRECISION_OFFSET	8
#define DAE_DECIMAL128_MAX_PRECISION	38
#define DAE_DECIMAL64_MAX_PRECISION	18

/* hash table */
#define HASH_EXT_TABLE_INVALID_OFFSET	5
#define HASH_EXT_TABLE_VALID	0x80
#define HASH_TABLE_HEAD_TAIL_SIZE	8
#define HASH_TABLE_EMPTY_SIZE	4
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
enum dae_stage {
	DAE_HASH_AGGREGATE = 0x0,
	DAE_HASHAGG_OUTPUT = 0x7,
};

enum dae_op_type {
	DAE_COUNT = 0x1,
	DAE_SUM = 0x5,
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
	DAE_HASHAGG_VCHAR_OVERFLOW = 0x84,
	DAE_HASHAGG_RESULT_OVERFLOW = 0x85,
	DAE_HASHAGG_BUS_ERROR = 0x86,
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

enum dae_sum_optype {
	DECIMAL64_TO_DECIMAL64 = 0x2,
	DECIMAL64_TO_DECIMAL128 = 0x3,
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
	__u32 resv5;
	__u32 low_tag;
	__u32 hi_tag;
	__u32 row_num;
	__u32 resv6;
	__u32 src_table_width : 6;
	__u32 dst_table_width : 6;
	__u32 resv7 : 4;
	__u32 counta_vld : 1;
	__u32 resv8 : 15;
	/*
	 * high 4bits: compare mode if data type is char/vchar,
	 *             out type if operation is sum.
	 * low 4bits: input value type.
	 */
	__u8 key_data_type[16];
	__u8 agg_data_type[16];
	__u32 resv9[8];
	__u32 key_col_bitmap;
	__u32 agg_col_bitmap;
	__u64 addr_list;
	__u32 done_flag : 3;
	__u32 output_end : 1;
	__u32 ext_err_type : 12;
	__u32 err_type : 8;
	__u32 wtype : 8;
	__u32 out_raw_num;
	__u32 vchar_err_offset;
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

struct dae_addr_list {
	__u64 ext_sqe_addr;
	__u64 ext_sqe_size;
	struct dae_table_addr src_table;
	struct dae_table_addr dst_table;
	__u64 resv_addr[6];
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

struct hw_agg_data {
	enum dae_data_type hw_type;
	__u32 optype;
	__u32 usr_col_idx;
	__u16 data_info;
	__u8 sum_outtype;
};

struct hashagg_output_src {
	/* Aggregated output from input agg col index. */
	__u32 out_from_in_idx;
	/* Aggregated output from input agg col operation, sum or count. */
	__u32 out_optype;
};

struct hashagg_col_data {
	struct hw_agg_data key_data[DAE_MAX_KEY_COLS];
	struct hw_agg_data input_data[DAE_MAX_INPUT_COLS];
	struct hw_agg_data output_data[DAE_MAX_OUTPUT_COLS];
	struct hashagg_output_src normal_output[DAE_MAX_OUTPUT_COLS];
	struct hashagg_output_src rehash_output[DAE_MAX_OUTPUT_COLS];

	__u32 key_num;
	__u32 input_num;
	__u32 output_num;
	bool is_count_all;
};

struct hash_table_data {
	void *std_table;
	void *ext_table;
	__u64 std_table_size;
	__u64 ext_table_size;
	__u32 table_width;
};

struct hashagg_ctx {
	struct hashagg_col_data cols_data;
	struct hash_table_data table_data;
	struct hash_table_data rehash_table;
	pthread_spinlock_t lock;
	__u32 row_size;
	__u16 sum_overflow_cols;
};

struct hisi_dae_ctx {
	struct wd_ctx_config_internal config;
};

static int get_free_ext_addr(struct dae_extend_addr *ext_addr)
{
	__u16 addr_num = ext_addr->addr_num;
	__u16 idx = ext_addr->tail;
	__u16 cnt = 0;

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

static void fill_hashagg_task_type(struct wd_agg_msg *msg, struct dae_sqe *sqe)
{
	switch (msg->pos) {
	case WD_AGG_REHASH_INPUT:
	case WD_AGG_STREAM_INPUT:
		sqe->task_type_ext = DAE_HASH_AGGREGATE;
		break;
	case WD_AGG_STREAM_OUTPUT:
	case WD_AGG_REHASH_OUTPUT:
		sqe->task_type_ext = DAE_HASHAGG_OUTPUT;
		break;
	}
}

static void fill_hashagg_output_order(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				      struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = msg->priv;
	struct hashagg_col_data *cols_data = &agg_ctx->cols_data;
	struct hashagg_output_src *output_src = cols_data->normal_output;
	__u32 out_cols_num = cols_data->output_num;
	__u32 offset = 0;
	__u32 i;

	if (msg->pos == WD_AGG_REHASH_INPUT)
		output_src = cols_data->rehash_output;

	if (cols_data->is_count_all && msg->pos != WD_AGG_REHASH_INPUT) {
		sqe->counta_vld = DAE_HASH_COUNT_ALL;
		out_cols_num--;
	}

	for (i = 0; i < out_cols_num; i++) {
		ext_sqe->out_from_in_idx |= (__u64)output_src[i].out_from_in_idx << offset;
		ext_sqe->out_optype |= (__u64)output_src[i].out_optype << offset;
		offset += DAE_COL_BIT_NUM;
	}
}

static void fill_hashagg_table_data(struct dae_sqe *sqe, struct dae_addr_list *addr_list,
				 struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = (struct hashagg_ctx *)msg->priv;
	struct hash_table_data *table_data = NULL;
	struct dae_table_addr *hw_table = NULL;

	switch (msg->pos) {
	case WD_AGG_STREAM_INPUT:
	case WD_AGG_REHASH_INPUT:
		hw_table = &addr_list->dst_table;
		table_data = &agg_ctx->table_data;
		break;
	case WD_AGG_STREAM_OUTPUT:
		hw_table = &addr_list->src_table;
		table_data = &agg_ctx->table_data;
		break;
	case WD_AGG_REHASH_OUTPUT:
		hw_table = &addr_list->src_table;
		table_data = &agg_ctx->rehash_table;
		break;
	}

	sqe->table_row_size = agg_ctx->row_size;
	sqe->src_table_width = table_data->table_width;
	sqe->dst_table_width = table_data->table_width;

	hw_table->std_table_addr = (__u64)(uintptr_t)table_data->std_table;
	hw_table->std_table_size = table_data->std_table_size;
	hw_table->ext_table_addr = (__u64)(uintptr_t)table_data->ext_table;
	hw_table->ext_table_size = table_data->ext_table_size;
}

static void fill_hashagg_key_data(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				  struct dae_addr_list *addr_list, struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = msg->priv;
	struct hw_agg_data *key_data = agg_ctx->cols_data.key_data;
	struct wd_dae_col_addr *usr_key_addr;
	struct dae_col_addr *hw_key_addr;
	__u32 j = DAE_MAX_ADDR_NUM - 1;
	__u16 usr_col_idx;
	__u32 i;

	sqe->key_col_bitmap = GENMASK(msg->key_cols_num - 1, 0);

	if (msg->pos == WD_AGG_STREAM_INPUT || msg->pos == WD_AGG_REHASH_INPUT) {
		usr_key_addr = msg->req.key_cols;
		hw_key_addr = addr_list->input_addr;
	} else {
		usr_key_addr = msg->req.out_key_cols;
		hw_key_addr = addr_list->output_addr;
	}

	for (i = 0; i < msg->key_cols_num; i++) {
		sqe->key_data_type[i] = key_data[i].hw_type;
		ext_sqe->key_data_info[i] = key_data[i].data_info;
		usr_col_idx = key_data[i].usr_col_idx;
		hw_key_addr[i].empty_addr = (__u64)(uintptr_t)usr_key_addr[usr_col_idx].empty;
		hw_key_addr[i].empty_size = usr_key_addr[usr_col_idx].empty_size;

		hw_key_addr[i].value_addr = (__u64)(uintptr_t)usr_key_addr[usr_col_idx].value;
		hw_key_addr[i].value_size = usr_key_addr[usr_col_idx].value_size;
		/* offset is fill in final value addr */
		if (key_data[i].hw_type == DAE_VCHAR) {
			hw_key_addr[j].value_addr =
				(__u64)(uintptr_t)usr_key_addr[usr_col_idx].offset;
			hw_key_addr[j].value_size = usr_key_addr[usr_col_idx].offset_size;
			j--;
			/*
			 * Since vchar size may be 0, which causes the hardware abnormal.
			 * Therefore, the size is set to 1 according to hardware protocol.
			 */
			if (!hw_key_addr[i].value_size)
				hw_key_addr[i].value_size = 1;
		}
	}
}

static void fill_hashagg_normal_info(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				     struct hashagg_col_data *cols_data, __u32 agg_cols_num)
{
	struct hw_agg_data *agg_data = cols_data->input_data;
	__u32 i;

	for (i = 0; i < agg_cols_num; i++) {
		sqe->agg_data_type[i] = agg_data[i].hw_type;
		sqe->agg_data_type[i] |= agg_data[i].sum_outtype << DAE_COL_BIT_NUM;
		ext_sqe->agg_data_info[i] = agg_data[i].data_info;
	}

	sqe->agg_col_bitmap = GENMASK(agg_cols_num + DAE_AGG_START_COL - 1, DAE_AGG_START_COL);
}

static void fill_hashagg_rehash_info(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				     struct hw_agg_data *agg_data, __u32 agg_cols_num)
{
	__u32 i;

	for (i = 0; i < agg_cols_num; i++) {
		sqe->agg_data_type[i] = agg_data[i].hw_type;
		sqe->agg_data_type[i] |= agg_data[i].sum_outtype << DAE_COL_BIT_NUM;
		ext_sqe->agg_data_info[i] = agg_data[i].data_info;
	}

	sqe->agg_col_bitmap = GENMASK(agg_cols_num + DAE_AGG_START_COL - 1, DAE_AGG_START_COL);
}

static void fill_hashagg_input_data(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				    struct dae_addr_list *addr_list, struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = msg->priv;
	struct hashagg_col_data *cols_data = &agg_ctx->cols_data;
	struct wd_dae_col_addr *usr_agg_addr;
	struct dae_col_addr *hw_agg_addr;
	struct hw_agg_data *agg_data;
	__u32 agg_col_num = 0;
	__u32 i, usr_col_idx;

	switch (msg->pos) {
	case WD_AGG_STREAM_INPUT:
		agg_data = cols_data->input_data;
		hw_agg_addr = &addr_list->input_addr[DAE_AGG_START_COL];
		usr_agg_addr = msg->req.agg_cols;
		agg_col_num = msg->agg_cols_num;
		fill_hashagg_normal_info(sqe, ext_sqe, cols_data, agg_col_num);
		break;
	case WD_AGG_REHASH_INPUT:
		agg_data = cols_data->output_data;
		hw_agg_addr = &addr_list->input_addr[DAE_AGG_START_COL];
		usr_agg_addr = msg->req.agg_cols;
		agg_col_num = cols_data->output_num;
		fill_hashagg_rehash_info(sqe, ext_sqe, agg_data, agg_col_num);
		break;
	case WD_AGG_STREAM_OUTPUT:
	case WD_AGG_REHASH_OUTPUT:
		agg_data = cols_data->output_data;
		hw_agg_addr = &addr_list->output_addr[DAE_AGG_START_COL];
		usr_agg_addr = msg->req.out_agg_cols;
		agg_col_num = cols_data->output_num;
		fill_hashagg_normal_info(sqe, ext_sqe, cols_data, cols_data->input_num);
		break;
	}

	for (i = 0; i < agg_col_num; i++) {
		usr_col_idx = agg_data[i].usr_col_idx;
		hw_agg_addr[i].empty_addr = (__u64)(uintptr_t)usr_agg_addr[usr_col_idx].empty;
		hw_agg_addr[i].empty_size = usr_agg_addr[usr_col_idx].empty_size;
		hw_agg_addr[i].value_addr = (__u64)(uintptr_t)usr_agg_addr[usr_col_idx].value;
		/*
		 * If only the count is performed on this agg column, set data type to SINT64
		 * and change the value of size.
		 */
		if (msg->pos == WD_AGG_STREAM_INPUT && agg_data[i].optype == DAE_HASHAGG_COUNT)
			hw_agg_addr[i].value_size = (__u64)msg->row_count * SINT64_SIZE;
		else
			hw_agg_addr[i].value_size = usr_agg_addr[usr_col_idx].value_size;
	}
}

static void fill_hashagg_ext_addr(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
				  struct dae_addr_list *addr_list)
{
	memset(ext_sqe, 0, DAE_EXT_SQE_SIZE);
	memset(addr_list, 0, sizeof(struct dae_addr_list));
	sqe->addr_list = (__u64)(uintptr_t)addr_list;
	addr_list->ext_sqe_addr = (__u64)(uintptr_t)ext_sqe;
	addr_list->ext_sqe_size = DAE_EXT_SQE_SIZE;
}

static int check_hashagg_param(struct wd_agg_msg *msg)
{
	if (!msg) {
		WD_ERR("invalid: input hashagg msg is NULL!\n");
		return -WD_EINVAL;
	}

	if ((msg->pos == WD_AGG_STREAM_INPUT || msg->pos == WD_AGG_REHASH_INPUT) &&
	     msg->row_count > DAE_HASHAGG_MAX_ROW_NUN) {
		WD_ERR("invalid: input hashagg row count %u is more than %d!\n",
			msg->row_count, DAE_HASHAGG_MAX_ROW_NUN);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_send(struct wd_alg_driver *drv, handle_t ctx, void *hashagg_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct dae_extend_addr *ext_addr = qp->priv;
	struct wd_agg_msg *msg = hashagg_msg;
	struct dae_addr_list *addr_list;
	struct dae_ext_sqe *ext_sqe;
	struct dae_sqe sqe = {0};
	__u16 send_cnt = 0;
	int ret, idx;

	ret = check_hashagg_param(msg);
	if (ret)
		return ret;

	fill_hashagg_task_type(msg, &sqe);
	sqe.row_num = msg->row_count;

	idx = get_free_ext_addr(ext_addr);
	if (idx < 0)
		return -WD_EBUSY;
	addr_list = &ext_addr->addr_list[idx];
	ext_sqe = &ext_addr->ext_sqe[idx];

	fill_hashagg_ext_addr(&sqe, ext_sqe, addr_list);
	fill_hashagg_table_data(&sqe, addr_list, msg);
	fill_hashagg_key_data(&sqe, ext_sqe, addr_list, msg);
	fill_hashagg_input_data(&sqe, ext_sqe, addr_list, msg);
	fill_hashagg_output_order(&sqe, ext_sqe, msg);

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.low_tag = msg->tag;
	sqe.hi_tag = idx;

	ret = hisi_qm_send(h_qp, &sqe, 1, &send_cnt);
	if (unlikely(ret)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send to hardware, ret = %d!\n", ret);
		put_ext_addr(ext_addr, idx);
		return ret;
	}

	return WD_SUCCESS;
}

static void fill_sum_overflow_cols(struct dae_sqe *sqe, struct wd_agg_msg *msg,
				   struct hashagg_ctx *agg_ctx)
{
	__u32 i, output_num, usr_col_idx;
	struct hw_agg_data *agg_data;

	pthread_spin_lock(&agg_ctx->lock);
	agg_ctx->sum_overflow_cols |= sqe->sum_overflow_cols;
	if (!agg_ctx->sum_overflow_cols) {
		pthread_spin_unlock(&agg_ctx->lock);
		return;
	}
	pthread_spin_unlock(&agg_ctx->lock);

	if (msg->result == WD_AGG_TASK_DONE)
		msg->result = WD_AGG_SUM_OVERFLOW;

	if (!msg->req.sum_overflow_cols)
		return;

	agg_data = agg_ctx->cols_data.output_data;
	output_num = agg_ctx->cols_data.output_num;
	for (i = 0; i < output_num; i++) {
		usr_col_idx = agg_data[i].usr_col_idx;
		if (agg_ctx->sum_overflow_cols & BIT(i))
			msg->req.sum_overflow_cols[usr_col_idx] = 1;
		else
			msg->req.sum_overflow_cols[usr_col_idx] = 0;
	}
}

static void fill_hashagg_msg_task_done(struct dae_sqe *sqe, struct wd_agg_msg *msg,
				       struct wd_agg_msg *temp_msg, struct hashagg_ctx *agg_ctx)
{
	if (sqe->task_type_ext == DAE_HASHAGG_OUTPUT) {
		msg->out_row_count = sqe->out_raw_num;
		msg->output_done = sqe->output_end;
	} else {
		msg->in_row_count = temp_msg->row_count;
	}
}

static void fill_hashagg_msg_task_err(struct dae_sqe *sqe, struct wd_agg_msg *msg,
				      struct wd_agg_msg *temp_msg, struct hashagg_ctx *agg_ctx)
{
	switch (sqe->err_type) {
	case DAE_TASK_BD_ERROR_MIN ... DAE_TASK_BD_ERROR_MAX:
		WD_ERR("failed to do hashagg task, bd error! etype=0x%x!\n", sqe->err_type);
		msg->result = WD_AGG_PARSE_ERROR;
		break;
	case DAE_HASH_TABLE_NEED_REHASH:
		msg->result = WD_AGG_NEED_REHASH;
		break;
	case DAE_HASH_TABLE_INVALID:
		msg->result = WD_AGG_INVALID_HASH_TABLE;
		break;
	case DAE_HASHAGG_VCHAR_OVERFLOW:
		WD_ERR("failed to do hashagg task, vchar size overflow! consumed row num: %u!\n",
			sqe->vchar_err_offset);
		msg->result = WD_AGG_INVALID_VARCHAR;
		msg->in_row_count = sqe->vchar_err_offset;
		break;
	case DAE_HASHAGG_RESULT_OVERFLOW:
		msg->in_row_count = temp_msg->row_count;
		msg->result = WD_AGG_SUM_OVERFLOW;
		break;
	case DAE_HASHAGG_BUS_ERROR:
		WD_ERR("failed to do hashagg task, bus error! etype %u!\n", sqe->err_type);
		msg->result = WD_AGG_BUS_ERROR;
		break;
	case DAE_HASHAGG_VCHAR_LEN_ERROR:
		WD_ERR("failed to do hashagg task, vchar col size error!\n");
		msg->result = WD_AGG_PARSE_ERROR;
		break;
	default:
		WD_ERR("failed to do hashagg task! done_flag=0x%x, etype=0x%x, ext_type = 0x%x!\n",
			sqe->done_flag, sqe->err_type, sqe->ext_err_type);
		msg->result = WD_AGG_PARSE_ERROR;
		break;
	}

	if (sqe->task_type_ext == DAE_HASHAGG_OUTPUT) {
		msg->out_row_count = sqe->out_raw_num;
		msg->output_done = sqe->output_end;
	}
}

static int hashagg_recv(struct wd_alg_driver *drv, handle_t ctx, void *hashagg_msg)
{
	struct hisi_dae_ctx *priv = (struct hisi_dae_ctx *)drv->priv;
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct dae_extend_addr *ext_addr = qp->priv;
	struct wd_agg_msg *msg = hashagg_msg;
	struct wd_agg_msg *temp_msg = msg;
	struct hashagg_ctx *agg_ctx;
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
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, msg->tag);
		if (!temp_msg) {
			msg->result = WD_AGG_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
			       qp->q_info.idx, msg->tag);
			ret = -WD_EINVAL;
			goto out;
		}
	}

	agg_ctx = (struct hashagg_ctx *)temp_msg->priv;
	msg->result = WD_AGG_TASK_DONE;
	msg->in_row_count = 0;

	if (likely(sqe.done_flag == DAE_HW_TASK_DONE)) {
		fill_hashagg_msg_task_done(&sqe, msg, temp_msg, agg_ctx);
	} else if (sqe.done_flag == DAE_HW_TASK_ERR) {
		fill_hashagg_msg_task_err(&sqe, msg, temp_msg, agg_ctx);
	} else {
		msg->result = WD_AGG_PARSE_ERROR;
		WD_ERR("failed to do hashagg task, hardware does not process the task!\n");
	}

	fill_sum_overflow_cols(&sqe, temp_msg, agg_ctx);

out:
	put_ext_addr(ext_addr, sqe.hi_tag);
	return ret;
}

static int key_vchar_num_size_check(struct wd_key_col_info *key_info, __u32 cols_num)
{
	__u32 i, count = 0;

	for (i = 0; i < cols_num; i++) {
		switch (key_info[i].input_data_type) {
		case WD_DAE_CHAR:
			if (key_info[i].col_data_info > DAE_MAX_CHAR_SIZE) {
				WD_ERR("invalid: key %u char size %u is more than support %d!\n",
					i, key_info[i].col_data_info, DAE_MAX_CHAR_SIZE);
				return -WD_EINVAL;
			}
			count++;
			break;
		case WD_DAE_VARCHAR:
			if (key_info[i].col_data_info > DAE_MAX_VCHAR_SIZE) {
				WD_ERR("invalid: key %u vchar size %u is more than support %d!\n",
					i, key_info[i].col_data_info, DAE_MAX_VCHAR_SIZE);
				return -WD_EINVAL;
			}
			count++;
			break;
		default:
			break;
		}
	}

	if (count > DAE_MAX_CHAR_COL_NUM) {
		WD_ERR("invalid: key char and vchar col num %u is more than device support %d!\n",
			count, DAE_MAX_CHAR_COL_NUM);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int agg_get_output_num(enum wd_dae_data_type type,
			      __u32 *size8, __u32 *size16)
{
	switch (type) {
	case WD_DAE_LONG:
	case WD_DAE_SHORT_DECIMAL:
		(*size8)++;
		break;
	case WD_DAE_LONG_DECIMAL:
		(*size16)++;
		break;
	default:
		WD_ERR("invalid: output data type %d not support!\n", type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int agg_output_num_check(struct wd_agg_col_info *agg_cols, __u32 cols_num, bool is_count_all)
{
	__u32 size8 = 0, size16 = 0;
	__u32 i, j, count_num;
	int ret;

	for (i = 0; i < cols_num; i++) {
		for (j = 0; j < agg_cols[i].col_alg_num; j++) {
			ret = agg_get_output_num(agg_cols[i].output_data_types[j],
						 &size8, &size16);
			if (ret)
				return ret;
		}
	}

	if (is_count_all)
		size8++;

	if (size8 > DAE_MAX_8B_COLS_NUM || size16 > DAE_MAX_16B_COLS_NUM) {
		WD_ERR("invalid: output col num 8B-16B %u-%u is more than support %d-%d !\n",
			size8, size16, DAE_MAX_8B_COLS_NUM, DAE_MAX_16B_COLS_NUM);
		return -WD_EINVAL;
	}
	count_num = size8 + size16;
	if (count_num > DAE_MAX_OUTPUT_COLS) {
		WD_ERR("invalid: agg output cols num %u is more than device support %d!\n",
			count_num, DAE_MAX_OUTPUT_COLS);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_init_param_check(struct wd_agg_sess_setup *setup)
{
	int ret;

	if (setup->agg_cols_num > DAE_MAX_INPUT_COLS) {
		WD_ERR("invalid: agg input cols num %u is more than device support %d!\n",
			setup->agg_cols_num, DAE_MAX_INPUT_COLS);
		return -WD_EINVAL;
	}

	if (setup->key_cols_num > DAE_MAX_KEY_COLS) {
		WD_ERR("invalid: key cols num %u is more than device support %d!\n",
			setup->key_cols_num, DAE_MAX_KEY_COLS);
		return -WD_EINVAL;
	}

	if (setup->is_count_all && setup->count_all_data_type != WD_DAE_LONG) {
		WD_ERR("invalid: count all output data type %d error,  only support long!\n",
			setup->count_all_data_type);
		return -WD_EINVAL;
	}

	ret = key_vchar_num_size_check(setup->key_cols_info, setup->key_cols_num);
	if (ret)
		return -WD_EINVAL;

	return agg_output_num_check(setup->agg_cols_info, setup->agg_cols_num, setup->is_count_all);
}

static __u32 hashagg_get_data_type_size(enum dae_data_type type, __u16 data_info)
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
	case DAE_VCHAR:
		return data_info;
	}

	return 0;
}

static int transfer_key_col_info(struct wd_key_col_info *key_cols,
				 struct hw_agg_data *key_data, __u32 col_num)
{
	__u32 i;

	for (i = 0; i < col_num; i++) {
		switch (key_cols[i].input_data_type) {
		case WD_DAE_VARCHAR:
			if (!key_cols[i].col_data_info)
				key_data[i].data_info = ALIGN(DAE_MAX_VCHAR_SIZE +
						DAE_VCHAR_OFFSET_SIZE, DAE_CHAR_ALIGN_SIZE);
			else
				key_data[i].data_info = ALIGN(key_cols[i].col_data_info +
							DAE_VCHAR_OFFSET_SIZE, DAE_CHAR_ALIGN_SIZE);
			key_data[i].hw_type = DAE_VCHAR;
			break;
		case WD_DAE_CHAR:
			key_data[i].data_info = key_cols[i].col_data_info;
			key_data[i].hw_type = DAE_CHAR;
			break;
		case WD_DAE_LONG_DECIMAL:
			key_data[i].hw_type = DAE_DECIMAL128;
			break;
		case WD_DAE_SHORT_DECIMAL:
			key_data[i].hw_type = DAE_DECIMAL64;
			break;
		case WD_DAE_LONG:
			key_data[i].hw_type = DAE_SINT64;
			break;
		case WD_DAE_INT:
		case WD_DAE_DATE:
			key_data[i].hw_type = DAE_SINT32;
			break;
		default:
			WD_ERR("invalid: unsupport key col %u data type %d!\n",
				i, key_cols[i].input_data_type);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int transfer_key_to_hw_type(struct hashagg_col_data *cols_data,
				   struct wd_agg_sess_setup *setup)
{
	struct wd_key_col_info *key_cols = setup->key_cols_info;
	struct hw_agg_data *hw_key_data = cols_data->key_data;
	struct hw_agg_data tmp_key_data[DAE_MAX_KEY_COLS] = {0};
	__u32 type_num = ARRAY_SIZE(hw_data_type_order);
	__u32 cols_num = setup->key_cols_num;
	__u32 i, j, k = 0;
	int ret;

	ret = transfer_key_col_info(key_cols, tmp_key_data, cols_num);
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

static int hashagg_decimal_precision_check(__u16 data_info, bool longdecimal)
{
	__u8 all_precision;

	/*
	 * low 8bits: overall precision
	 * high 8bits: precision of the decimal part
	 */
	all_precision = data_info;
	if (longdecimal) {
		if (all_precision > DAE_DECIMAL128_MAX_PRECISION) {
			WD_ERR("invalid: longdecimal precision %u is more than support %d!\n",
				all_precision, DAE_DECIMAL128_MAX_PRECISION);
			return -WD_EINVAL;
		}
		return WD_SUCCESS;
	}

	if (all_precision > DAE_DECIMAL64_MAX_PRECISION) {
		WD_ERR("invalid: shortdecimal precision %u is more than support %d!\n",
			all_precision, DAE_DECIMAL64_MAX_PRECISION);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_check_sum_info(struct wd_agg_col_info *agg_col,
				  struct hw_agg_data *user_input_data,
				  struct hw_agg_data *user_output_data, __u32 index)
{
	int ret;

	switch (agg_col->input_data_type) {
	case WD_DAE_LONG:
		if (agg_col->output_data_types[index] != WD_DAE_LONG) {
			WD_ERR("invalid: long type do sum output data type %d error!\n",
				agg_col->output_data_types[index]);
			return -WD_EINVAL;
		}
		user_input_data->hw_type = DAE_SINT64;
		user_output_data->hw_type = DAE_SINT64;
		break;
	case WD_DAE_SHORT_DECIMAL:
		if (agg_col->output_data_types[index] == WD_DAE_SHORT_DECIMAL) {
			ret = hashagg_decimal_precision_check(agg_col->col_data_info, false);
			if (ret)
				return ret;
			user_input_data->sum_outtype = DECIMAL64_TO_DECIMAL64;
			user_output_data->hw_type = DAE_DECIMAL64;
			/* For rehash, rehash will do sum */
			user_output_data->sum_outtype = DECIMAL64_TO_DECIMAL64;
		} else if (agg_col->output_data_types[index] == WD_DAE_LONG_DECIMAL) {
			ret = hashagg_decimal_precision_check(agg_col->col_data_info, true);
			if (ret)
				return ret;
			user_input_data->sum_outtype = DECIMAL64_TO_DECIMAL128;
			user_output_data->hw_type = DAE_DECIMAL128;
		} else {
			WD_ERR("invalid: short decimal do sum output data type %d error!\n",
				agg_col->output_data_types[index]);
			return -WD_EINVAL;
		}
		user_input_data->hw_type = DAE_DECIMAL64;
		break;
	case WD_DAE_LONG_DECIMAL:
		if (agg_col->output_data_types[index] != WD_DAE_LONG_DECIMAL) {
			WD_ERR("invalid: long decimal do sum output data type %d error!\n",
				agg_col->output_data_types[index]);
			return -WD_EINVAL;
		}
		ret = hashagg_decimal_precision_check(agg_col->col_data_info, true);
		if (ret)
			return ret;
		user_input_data->hw_type = DAE_DECIMAL128;
		user_output_data->hw_type = DAE_DECIMAL128;
		break;
	default:
		WD_ERR("invalid: device not support col data type %d do sum!\n",
			agg_col->input_data_type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_check_count_info(enum wd_dae_data_type input_type,
				    enum wd_dae_data_type output_type)
{
	if (input_type > WD_DAE_VARCHAR) {
		WD_ERR("invalid: device not support agg col data type %d do count!\n", input_type);
		return -WD_EINVAL;
	}

	if (output_type != WD_DAE_LONG) {
		WD_ERR("invalid: input data type %d do count output data type %d error!\n",
			input_type, output_type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_check_input_data(struct wd_agg_col_info *agg_col,
					struct hw_agg_data *user_input_data,
					struct hw_agg_data *user_output_data, __u32 index)
{
	int ret;

	switch (agg_col->output_col_algs[index]) {
	case WD_AGG_SUM:
		ret = hashagg_check_sum_info(agg_col, user_input_data, user_output_data, index);
		if (ret)
			return ret;
		user_input_data->optype |= DAE_HASHAGG_SUM;
		user_output_data->optype = DAE_SUM;
		break;
	case WD_AGG_COUNT:
		ret = hashagg_check_count_info(agg_col->input_data_type,
					       agg_col->output_data_types[index]);
		if (ret)
			return ret;
		user_input_data->optype |= DAE_HASHAGG_COUNT;
		user_output_data->hw_type = DAE_SINT64;
		user_output_data->optype = DAE_COUNT;
		break;
	default:
		WD_ERR("invalid: device not support alg %d!\n", agg_col->output_col_algs[index]);
		return -WD_EINVAL;
	}
	user_output_data->data_info = agg_col->col_data_info;

	return WD_SUCCESS;
}

static int transfer_input_col_info(struct wd_agg_col_info *agg_cols,
				   struct hw_agg_data *user_input_data,
				   struct hw_agg_data *user_output_data,
				   __u32 cols_num, __u32 *output_num)
{
	__u32 i, j, k = 0;
	int ret;

	for (i = 0; i < cols_num; i++) {
		for (j = 0; j < agg_cols[i].col_alg_num; j++) {
			ret = hashagg_check_input_data(&agg_cols[i], &user_input_data[i],
						       &user_output_data[k], j);
			if (ret)
				return ret;
			user_output_data[k++].usr_col_idx = i;
		}
		user_input_data[i].data_info = agg_cols[i].col_data_info;
		/*
		 * If agg col only do count, change the type to DAE_SINT64 and
		 * send it to the hardware.
		 */
		if (user_input_data[i].optype == DAE_HASHAGG_COUNT)
			user_input_data[i].hw_type = DAE_SINT64;
	}

	*output_num = k;

	return WD_SUCCESS;
}

static void hashagg_swap_out_index(struct hw_agg_data *user_output_data,
				   __u32 cols_num, __u32 *usr_idx,
				   __u32 old_idx, __u32 new_idx)
{
	__u32 i;

	for (i = 0; i < cols_num; i++) {
		if (usr_idx[i] == old_idx)
			user_output_data[i].usr_col_idx = new_idx;
	}
}

static void transfer_input_to_hw_order(struct hashagg_col_data *cols_data,
				      struct hw_agg_data *user_input_data,
				      struct hw_agg_data *user_output_data)
{
	struct hw_agg_data *input_data = cols_data->input_data;
	__u32 type_num = ARRAY_SIZE(hw_data_type_order);
	__u32 cols_num = cols_data->input_num;
	__u32 usr_col_idx[DAE_MAX_INPUT_COLS];
	__u32 i, j, k = 0;

	/*
	 * Since device need input col idx, so save usr input idx,
	 * then update to send to hw idx.
	 */
	for (i = 0; i < cols_data->output_num; i++)
		usr_col_idx[i] = user_output_data[i].usr_col_idx;

	for (i = 0; i < type_num; i++) {
		for (j = 0; j < cols_num; j++) {
			if (hw_data_type_order[i] != user_input_data[j].hw_type)
				continue;
			/*
			 * Since aggregated output need input hardware agg index,
			 * so fill the final idx.
			 */
			hashagg_swap_out_index(user_output_data, cols_data->output_num,
					       usr_col_idx, j, k);
			input_data[k].usr_col_idx = j;
			input_data[k].sum_outtype = user_input_data[j].sum_outtype;
			input_data[k].data_info = user_input_data[j].data_info;
			input_data[k].hw_type = user_input_data[j].hw_type;
			input_data[k].optype = user_input_data[j].optype;
			k++;
		}
	}
}

static void transfer_output_to_hw_order(struct hashagg_col_data *cols_data,
					struct hw_agg_data *usr_output_data,
					bool is_count_all)
{
	struct hashagg_output_src *normal_output = cols_data->normal_output;
	struct hashagg_output_src *rehash_output = cols_data->rehash_output;
	struct hw_agg_data *output_data = cols_data->output_data;
	struct hw_agg_data *input_data = cols_data->input_data;
	__u32 type_num = ARRAY_SIZE(hw_data_type_order);
	__u32 cols_num = cols_data->output_num;
	__u32 i, j, k = 0;

	if (is_count_all) {
		/* Count all output will fill in the last column */
		output_data[cols_num].hw_type = DAE_SINT64;
		output_data[cols_num].usr_col_idx = cols_num;
		rehash_output[cols_num].out_optype = DAE_SUM;
		rehash_output[cols_num].out_from_in_idx = cols_num;
		cols_data->output_num++;
		cols_data->is_count_all = true;
	}

	for (i = 0; i < type_num; i++) {
		for (j = 0; j < cols_num; j++) {
			if (hw_data_type_order[i] != usr_output_data[j].hw_type)
				continue;
			/*
			 * Rehash only performs the sum operation. The number of output columns
			 * is the same as the number of input columns. The order does not
			 * need to be adjusted.
			 */
			rehash_output[k].out_from_in_idx = k;
			rehash_output[k].out_optype = DAE_SUM;

			normal_output[k].out_from_in_idx = usr_output_data[j].usr_col_idx;
			normal_output[k].out_optype = usr_output_data[j].optype;
			output_data[k].hw_type = usr_output_data[j].hw_type;
			output_data[k].usr_col_idx = j;
			output_data[k].data_info =
				input_data[usr_output_data[j].usr_col_idx].data_info;
			k++;
		}
	}
}

static int transfer_data_to_hw_type(struct hashagg_col_data *cols_data,
				    struct wd_agg_sess_setup *setup)
{
	struct hw_agg_data user_input_data[DAE_MAX_INPUT_COLS] = {0};
	struct hw_agg_data user_output_data[DAE_MAX_OUTPUT_COLS] = {0};
	struct wd_agg_col_info *agg_cols = setup->agg_cols_info;
	int ret;

	ret = transfer_input_col_info(agg_cols, user_input_data, user_output_data,
					setup->agg_cols_num, &cols_data->output_num);
	if (ret)
		return ret;

	cols_data->input_num = setup->agg_cols_num;

	transfer_input_to_hw_order(cols_data, user_input_data, user_output_data);
	transfer_output_to_hw_order(cols_data, user_output_data, setup->is_count_all);

	return WD_SUCCESS;
}

static int hashagg_get_table_rowsize(struct hashagg_col_data *cols_data)
{
	struct hw_agg_data *output_col = cols_data->output_data;
	struct hw_agg_data *key_data = cols_data->key_data;
	__u32 output_num = cols_data->output_num;
	__u32 key_num = cols_data->key_num;
	__u32 row_count_size = 0;
	__u32 i;

	for (i = 0; i < key_num; i++)
		row_count_size += hashagg_get_data_type_size(key_data[i].hw_type,
							     key_data[i].data_info);

	for (i = 0; i < output_num; i++)
		row_count_size += hashagg_get_data_type_size(output_col[i].hw_type,
							     output_col[i].data_info);

	row_count_size += HASH_TABLE_EMPTY_SIZE;
	if (row_count_size < DAE_MIN_ROW_SIZE || row_count_size > DAE_MAX_ROW_SIZE) {
		WD_ERR("invalid: device not support hash table row size %u!\n", row_count_size);
		return -WD_EINVAL;
	}

	row_count_size += HASH_TABLE_HEAD_TAIL_SIZE;
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

static int hashagg_fill_agg_ctx(struct hashagg_ctx *agg_ctx, struct wd_agg_sess_setup *setup)
{
	struct hashagg_col_data *cols_data = &agg_ctx->cols_data;
	int ret;

	ret = transfer_key_to_hw_type(cols_data, setup);
	if (ret)
		return ret;

	ret = transfer_data_to_hw_type(cols_data, setup);
	if (ret)
		return ret;

	ret = hashagg_get_table_rowsize(cols_data);
	if (ret < 0)
		return -WD_EINVAL;
	agg_ctx->row_size = ret;

	agg_ctx->sum_overflow_cols = 0;

	return WD_SUCCESS;
}

static void hashagg_sess_priv_uninit(void *priv)
{
	struct hashagg_ctx *agg_ctx = priv;

	if (!agg_ctx) {
		WD_ERR("invalid: dae sess uninit priv is NULL!\n");
		return;
	}

	pthread_spin_destroy(&agg_ctx->lock);
	free(agg_ctx);
}

static int hashagg_sess_priv_init(struct wd_agg_sess_setup *setup, void **priv)
{
	struct hashagg_ctx *agg_ctx;
	int ret;

	if (!setup || !priv) {
		WD_ERR("invalid: dae sess priv is NULL!\n");
		return -WD_EINVAL;
	}

	ret = hashagg_init_param_check(setup);
	if (ret)
		return -WD_EINVAL;

	agg_ctx = calloc(1, sizeof(struct hashagg_ctx));
	if (!agg_ctx)
		return -WD_ENOMEM;

	ret = hashagg_fill_agg_ctx(agg_ctx, setup);
	if (ret)
		goto free_agg_ctx;

	ret = pthread_spin_init(&agg_ctx->lock, PTHREAD_PROCESS_SHARED);
	if (ret)
		goto free_agg_ctx;

	*priv = agg_ctx;

	return WD_SUCCESS;

free_agg_ctx:
	free(agg_ctx);
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

static int dae_get_row_size(void *param)
{
	struct hashagg_ctx *agg_ctx = param;

	if (!agg_ctx)
		return -WD_EINVAL;

	return agg_ctx->row_size;
}

static __u32 dae_ext_table_rownum(void **ext_table, struct wd_dae_hash_table *hash_table,
				  __u32 row_size)
{
	__u64 tlb_size, tmp_size, row_num;
	void *tmp_table;

	/*
	 * The first row of the extended hash table stores the hash table information,
	 * and the second row stores the aggregated data. The 128-bytes aligned address
	 * in the second row provides the optimal performance.
	 */
	tmp_table = PTR_ALIGN(hash_table->ext_table, DAE_TABLE_ALIGN_SIZE);
	tlb_size = (__u64)hash_table->table_row_size * hash_table->ext_table_row_num;
	tmp_size = (__u64)(uintptr_t)tmp_table - (__u64)(uintptr_t)hash_table->ext_table;
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
			if (row_num > HASH_TABLE_OFFSET_3ROW) {
				tmp_table = (__u8 *)tmp_table + HASH_TABLE_OFFSET_3ROW * row_size;
				row_num -= HASH_TABLE_OFFSET_3ROW;
			} else {
				return 0;
			}
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
			if (row_num > HASH_TABLE_OFFSET_1ROW) {
				tmp_table = (__u8 *)tmp_table + HASH_TABLE_OFFSET_1ROW * row_size;
				row_num -= HASH_TABLE_OFFSET_1ROW;
			} else {
				return 0;
			}
		}
	}

	*ext_table = tmp_table;

	return row_num;
}

static int dae_ext_table_init(struct hashagg_ctx *agg_ctx,
			      struct wd_dae_hash_table *hash_table, bool is_rehash)
{
	struct hash_table_data *hw_table = &agg_ctx->table_data;
	__u64 ext_size = hw_table->ext_table_size;
	__u32 row_size = agg_ctx->row_size;
	__u64 tlb_size, row_num;
	void *ext_table;
	__u8 *ext_valid;
	__u64 *ext_row;

	row_num = dae_ext_table_rownum(&ext_table, hash_table, row_size);
	if (row_num <= 1) {
		WD_ERR("invalid: after aligned, extend table row num is less than device need!\n");
		return -WD_EINVAL;
	}

	tlb_size = row_num * row_size;
	if (is_rehash && tlb_size <= ext_size) {
		WD_ERR("invalid: rehash extend table size %llu is not longer than current %llu!\n",
			tlb_size, ext_size);
		return -WD_EINVAL;
	}

	/*
	 * If table has been initialized, save the previous data
	 * before replacing the new table.
	 */
	if (is_rehash)
		memcpy(&agg_ctx->rehash_table, hw_table, sizeof(struct hash_table_data));

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
			      struct wd_dae_hash_table *hash_table, __u32 row_size)
{
	__u64 tlb_size, row_num, tmp_size;

	/*
	 * Hash table address must be 128-bytes aligned, and the number
	 * of rows in a standard hash table must be a power of 2.
	 */
	hw_table->std_table = PTR_ALIGN(hash_table->std_table, DAE_TABLE_ALIGN_SIZE);
	tlb_size = (__u64)hash_table->table_row_size * hash_table->std_table_row_num;
	tmp_size = (__u64)(uintptr_t)hw_table->std_table - (__u64)(uintptr_t)hash_table->std_table;
	if (tmp_size >= tlb_size) {
		WD_ERR("invalid: after aligned, standard table size is less than 0!\n");
		return -WD_EINVAL;
	}

	row_num = (tlb_size - tmp_size) / row_size;
	if (!row_num) {
		WD_ERR("invalid: standard table row num is 0!\n");
		return -WD_EINVAL;
	}

	hw_table->table_width = log2(row_num);
	if (hw_table->table_width < HASH_TABLE_MIN_WIDTH ||
	    hw_table->table_width > HASH_TABLE_MAX_WIDTH) {
		WD_ERR("invalid: standard table width %u is out of device support range %d~%d!\n",
			hw_table->table_width, HASH_TABLE_MIN_WIDTH, HASH_TABLE_MAX_WIDTH);
		return -WD_EINVAL;
	}

	row_num = pow(HASH_TABLE_WITDH_POWER, hw_table->table_width);
	hw_table->std_table_size = row_num * row_size;
	memset(hw_table->std_table, 0, hw_table->std_table_size);

	return WD_SUCCESS;
}

static int dae_hash_table_init(struct wd_dae_hash_table *hash_table, void *priv)
{
	struct hashagg_ctx *agg_ctx = priv;
	struct hash_table_data *hw_table;
	bool is_rehash = false;
	int ret;

	if (!agg_ctx || !hash_table)
		return -WD_EINVAL;

	if (!agg_ctx->row_size || agg_ctx->row_size > hash_table->table_row_size) {
		WD_ERR("invalid: row size %u is error, device need %u!\n",
			hash_table->table_row_size, agg_ctx->row_size);
		return -WD_EINVAL;
	}

	/* hash_std_table is checked by caller */
	if (!hash_table->ext_table || !hash_table->ext_table_row_num) {
		WD_ERR("invalid: hash extend table is null!\n");
		return -WD_EINVAL;
	}

	hw_table = &agg_ctx->table_data;
	if (hw_table->std_table_size)
		is_rehash = true;

	ret = dae_ext_table_init(agg_ctx, hash_table, is_rehash);
	if (ret)
		return ret;

	ret = dae_std_table_init(hw_table, hash_table, agg_ctx->row_size);
	if (ret)
		goto update_table;

	return WD_SUCCESS;

update_table:
	if (is_rehash)
		memcpy(hw_table, &agg_ctx->rehash_table, sizeof(struct hash_table_data));
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

	qm_priv.op_type = DAE_HASH_AGG_TYPE;
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
	struct hisi_dae_ctx *priv = (struct hisi_dae_ctx *)drv->priv;
	struct wd_ctx_config_internal *config;
	handle_t h_qp;
	__u32 i;

	if (!priv)
		return;

	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		dae_uninit_qp_priv(h_qp);
		hisi_qm_free_qp(h_qp);
	}

	free(priv);
	drv->priv = NULL;
}

static int dae_get_usage(void *param)
{
	return 0;
}

static int dae_get_extend_ops(void *ops)
{
	struct wd_agg_ops *agg_ops = (struct wd_agg_ops *)ops;

	if (!agg_ops)
		return -WD_EINVAL;

	agg_ops->get_row_size = dae_get_row_size;
	agg_ops->hash_table_init = dae_hash_table_init;
	agg_ops->sess_init = hashagg_sess_priv_init;
	agg_ops->sess_uninit = hashagg_sess_priv_uninit;

	return WD_SUCCESS;
}

static struct wd_alg_driver hashagg_driver = {
	.drv_name = "hisi_zip",
	.alg_name = "hashagg",
	.calc_type = UADK_ALG_HW,
	.priority = 100,
	.queue_num = DAE_CTX_Q_NUM_DEF,
	.op_type_num = 1,
	.fallback = 0,
	.init = dae_init,
	.exit = dae_exit,
	.send = hashagg_send,
	.recv = hashagg_recv,
	.get_usage = dae_get_usage,
	.get_extend_ops = dae_get_extend_ops,
};

#ifdef WD_STATIC_DRV
void hisi_dae_probe(void)
#else
static void __attribute__((constructor)) hisi_dae_probe(void)
#endif
{
	int ret;

	WD_INFO("Info: register DAE alg drivers!\n");

	ret = wd_alg_driver_register(&hashagg_driver);
	if (ret && ret != -WD_ENODEV)
		WD_ERR("failed to register DAE hashagg driver!\n");
}

#ifdef WD_STATIC_DRV
void hisi_dae_remove(void)
#else
static void __attribute__((destructor)) hisi_dae_remove(void)
#endif
{
	WD_INFO("Info: unregister DAE alg drivers!\n");

	wd_alg_driver_unregister(&hashagg_driver);
}
