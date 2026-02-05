// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved. */

#include "hisi_qm_udrv.h"
#include "hisi_dae.h"
#include "../include/drv/wd_agg_drv.h"

#define DAE_EXT_SQE_SIZE	128
#define DAE_CTX_Q_NUM_DEF	1

/* will remove in next version */
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
#define DAE_HASHAGG_MAX_ROW_NUM	50000

/* align size */
#define DAE_CHAR_ALIGN_SIZE	4

/* hash table */
#define HASH_TABLE_HEAD_TAIL_SIZE	8

/* hash agg operations col max num */
#define DAE_AGG_COL_ALG_MAX_NUM		2

/* DAE hardware protocol data */
enum dae_stage {
	DAE_HASH_AGGREGATE = 0x0,
	DAE_HASHAGG_OUTPUT = 0x7,
	/* new platform rehash new operation */
	DAE_HASHAGG_MERGE = 0x6,
};

enum dae_op_type {
	DAE_COUNT = 0x1,
	DAE_MAX = 0x3,
	DAE_MIN = 0x4,
	DAE_SUM = 0x5,
};

enum dae_sum_optype {
	DECIMAL64_TO_DECIMAL64 = 0x2,
	DECIMAL64_TO_DECIMAL128 = 0x3,
};

enum dae_alg_optype {
	DAE_HASHAGG_SUM = 0x1,
	DAE_HASHAGG_COUNT = 0x2,
	DAE_HASHAGG_MAX = 0x4,
	DAE_HASHAGG_MIN = 0x8,
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

struct hashagg_ctx {
	struct hashagg_col_data cols_data;
	struct hash_table_data table_data;
	struct hash_table_data rehash_table;
	pthread_spinlock_t lock;
	__u32 row_size;
	__u16 sum_overflow_cols;
};

static void fill_hashagg_task_type(struct wd_agg_msg *msg, struct dae_sqe *sqe, __u16 hw_type)
{
	/*
	 * The variable 'pos' is enumeration type, and the case branches
	 * cover all values.
	 */
	switch (msg->pos) {
	case WD_AGG_REHASH_INPUT:
	case WD_AGG_STREAM_INPUT:
		sqe->task_type_ext = DAE_HASH_AGGREGATE;
		break;
	case WD_AGG_STREAM_OUTPUT:
		sqe->task_type_ext = DAE_HASHAGG_OUTPUT;
		break;
	case WD_AGG_REHASH_OUTPUT:
		if (hw_type >= HISI_QM_API_VER5_BASE)
			sqe->task_type_ext = DAE_HASHAGG_MERGE;
		else
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

static void fill_hashagg_merge_output_order(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
					    struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = msg->priv;
	struct hashagg_col_data *cols_data = &agg_ctx->cols_data;
	__u32 out_cols_num = cols_data->output_num;
	struct hashagg_output_src *output_src;
	__u32 offset = 0;
	__u32 i;

	output_src = cols_data->normal_output;
	if (cols_data->is_count_all) {
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
	struct hash_table_data *table_data = &agg_ctx->table_data;
	struct dae_table_addr *hw_table = &addr_list->src_table;

	/*
	 * The variable 'pos' is enumeration type, and the case branches
	 * cover all values.
	 */
	switch (msg->pos) {
	case WD_AGG_STREAM_INPUT:
	case WD_AGG_REHASH_INPUT:
		hw_table = &addr_list->dst_table;
		table_data = &agg_ctx->table_data;
		break;
	case WD_AGG_STREAM_OUTPUT:
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

static void fill_hashagg_merge_table_data(struct dae_sqe *sqe,
					  struct dae_addr_list *addr_list,
					  struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = (struct hashagg_ctx *)msg->priv;
	struct hash_table_data *table_data_src = &agg_ctx->rehash_table;
	struct hash_table_data *table_data_dst = &agg_ctx->table_data;
	struct dae_table_addr *hw_table_src = &addr_list->src_table;
	struct dae_table_addr *hw_table_dst = &addr_list->dst_table;

	sqe->table_row_size = agg_ctx->row_size;
	sqe->src_table_width = table_data_src->table_width;
	sqe->dst_table_width = table_data_dst->table_width;

	hw_table_dst->std_table_addr = (__u64)(uintptr_t)table_data_dst->std_table;
	hw_table_dst->std_table_size = table_data_dst->std_table_size;
	hw_table_dst->ext_table_addr = (__u64)(uintptr_t)table_data_dst->ext_table;
	hw_table_dst->ext_table_size = table_data_dst->ext_table_size;

	hw_table_src->std_table_addr = (__u64)(uintptr_t)table_data_src->std_table;
	hw_table_src->std_table_size = table_data_src->std_table_size;
	hw_table_src->ext_table_addr = (__u64)(uintptr_t)table_data_src->ext_table;
	hw_table_src->ext_table_size = table_data_src->ext_table_size;
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

static void fill_hashagg_merge_key_data(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
					struct dae_addr_list *addr_list, struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = msg->priv;
	struct hw_agg_data *key_data = agg_ctx->cols_data.key_data;
	__u32 i;

	sqe->key_col_bitmap = GENMASK(msg->key_cols_num - 1, 0);

	for (i = 0; i < msg->key_cols_num; i++) {
		sqe->key_data_type[i] = key_data[i].hw_type;
		ext_sqe->key_data_info[i] = key_data[i].data_info;
	}
}

static void fill_hashagg_data_info(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
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

	/*
	 * The variable 'pos' is enumeration type, and the case branches
	 * cover all values.
	 */
	switch (msg->pos) {
	case WD_AGG_STREAM_INPUT:
		agg_data = cols_data->input_data;
		hw_agg_addr = &addr_list->input_addr[DAE_AGG_START_COL];
		usr_agg_addr = msg->req.agg_cols;
		agg_col_num = msg->agg_cols_num;
		fill_hashagg_data_info(sqe, ext_sqe, agg_data, agg_col_num);
		break;
	case WD_AGG_REHASH_INPUT:
		agg_data = cols_data->output_data;
		hw_agg_addr = &addr_list->input_addr[DAE_AGG_START_COL];
		usr_agg_addr = msg->req.agg_cols;
		agg_col_num = cols_data->output_num;
		fill_hashagg_data_info(sqe, ext_sqe, agg_data, agg_col_num);
		break;
	case WD_AGG_STREAM_OUTPUT:
	case WD_AGG_REHASH_OUTPUT:
		agg_data = cols_data->output_data;
		hw_agg_addr = &addr_list->output_addr[DAE_AGG_START_COL];
		usr_agg_addr = msg->req.out_agg_cols;
		agg_col_num = cols_data->output_num;
		fill_hashagg_data_info(sqe, ext_sqe, cols_data->input_data, cols_data->input_num);
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

static void fill_hashagg_merge_input_data(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
					  struct dae_addr_list *addr_list, struct wd_agg_msg *msg)
{
	struct hashagg_ctx *agg_ctx = msg->priv;
	struct hashagg_col_data *cols_data = &agg_ctx->cols_data;

	fill_hashagg_data_info(sqe, ext_sqe, cols_data->input_data, msg->agg_cols_num);
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

static void fill_hashagg_info(struct dae_sqe *sqe, struct dae_ext_sqe *ext_sqe,
			      struct dae_addr_list *addr_list, struct wd_agg_msg *msg,
			      __u16 hw_type)
{
	fill_hashagg_ext_addr(sqe, ext_sqe, addr_list);

	if (hw_type >= HISI_QM_API_VER5_BASE)
		sqe->bd_type = DAE_BD_TYPE_V2;

	if (sqe->task_type_ext == DAE_HASHAGG_MERGE) {
		fill_hashagg_merge_table_data(sqe, addr_list, msg);
		fill_hashagg_merge_key_data(sqe, ext_sqe, addr_list, msg);
		fill_hashagg_merge_input_data(sqe, ext_sqe, addr_list, msg);
		fill_hashagg_merge_output_order(sqe, ext_sqe, msg);
	} else {
		fill_hashagg_table_data(sqe, addr_list, msg);
		fill_hashagg_key_data(sqe, ext_sqe, addr_list, msg);
		fill_hashagg_input_data(sqe, ext_sqe, addr_list, msg);
		fill_hashagg_output_order(sqe, ext_sqe, msg);
	}
}

static int check_hashagg_param(struct wd_agg_msg *msg)
{
	if (!msg) {
		WD_ERR("invalid: input hashagg msg is NULL!\n");
		return -WD_EINVAL;
	}

	if ((msg->pos == WD_AGG_STREAM_INPUT || msg->pos == WD_AGG_REHASH_INPUT) &&
	     msg->row_count > DAE_HASHAGG_MAX_ROW_NUM) {
		WD_ERR("invalid: input hashagg row count %u is more than %d!\n",
			msg->row_count, DAE_HASHAGG_MAX_ROW_NUM);
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

	if (qp->q_info.hw_type >= HISI_QM_API_VER5_BASE &&
	    qp->q_info.qp_mode == CTX_MODE_SYNC && msg->pos == WD_AGG_REHASH_INPUT)
		return WD_SUCCESS;

	fill_hashagg_task_type(msg, &sqe, qp->q_info.hw_type);
	sqe.data_row_num = msg->row_count;

	idx = get_free_ext_addr(ext_addr);
	if (idx < 0)
		return -WD_EBUSY;
	addr_list = &ext_addr->addr_list[idx];
	ext_sqe = &ext_addr->ext_sqe[idx];

	fill_hashagg_info(&sqe, ext_sqe, addr_list, msg, qp->q_info.hw_type);

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
	} else if (sqe->task_type_ext == DAE_HASHAGG_MERGE) {
		msg->output_done = sqe->output_end;
		if (!msg->output_done)
			msg->out_row_count = temp_msg->row_count;
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
			sqe->data_row_offset);
		msg->result = WD_AGG_INVALID_VARCHAR;
		msg->in_row_count = sqe->data_row_offset;
		break;
	case DAE_HASHAGG_RESULT_OVERFLOW:
		msg->in_row_count = temp_msg->row_count;
		msg->result = WD_AGG_SUM_OVERFLOW;
		break;
	case DAE_TASK_BUS_ERROR:
		WD_ERR("failed to do hashagg task, bus error! etype %u!\n", sqe->err_type);
		msg->result = WD_AGG_BUS_ERROR;
		break;
	case DAE_HASHAGG_VCHAR_LEN_ERROR:
		WD_ERR("failed to do hashagg task, vchar col size error!\n");
		msg->result = WD_AGG_PARSE_ERROR;
		break;
	default:
		WD_ERR("failed to do hashagg task! done_flag=0x%x, etype=0x%x, ext_type = 0x%x!\n",
			(__u32)sqe->done_flag, (__u32)sqe->err_type, (__u32)sqe->ext_err_type);
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
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct dae_extend_addr *ext_addr = qp->priv;
	struct wd_agg_msg *msg = hashagg_msg;
	struct wd_agg_msg *temp_msg = msg;
	struct hashagg_ctx *agg_ctx;
	struct dae_sqe sqe = {0};
	__u16 recv_cnt = 0;
	int ret;

	if (qp->q_info.hw_type >= HISI_QM_API_VER5_BASE &&
	    qp->q_info.qp_mode == CTX_MODE_SYNC && msg->pos == WD_AGG_REHASH_INPUT) {
		msg->result = WD_AGG_TASK_DONE;
		return WD_SUCCESS;
	}

	ret = hisi_qm_recv(h_qp, &sqe, 1, &recv_cnt);
	if (ret)
		return ret;

	ret = hisi_check_bd_id(h_qp, msg->tag, sqe.low_tag);
	if (ret)
		goto out;

	msg->tag = sqe.low_tag;
	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		temp_msg = wd_agg_get_msg(qp->q_info.idx, msg->tag);
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
		WD_ERR("invalid: output data type %u not support!\n", type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int agg_output_num_check(struct wd_agg_col_info *agg_cols, __u32 cols_num,
				bool is_count_all)
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
		WD_ERR("invalid: count all output data type %u error,  only support long!\n",
			setup->count_all_data_type);
		return -WD_EINVAL;
	}

	ret = key_vchar_num_size_check(setup->key_cols_info, setup->key_cols_num);
	if (ret)
		return -WD_EINVAL;

	return agg_output_num_check(setup->agg_cols_info, setup->agg_cols_num,
				    setup->is_count_all);
}

static int transfer_key_col_info(struct wd_key_col_info *key_cols,
				 struct hw_agg_data *key_data, __u32 col_num)
{
	__u32 i;
	int ret;

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
			ret = dae_decimal_precision_check(key_cols[i].col_data_info, true);
			if (ret)
				return ret;
			key_data[i].hw_type = DAE_DECIMAL128;
			break;
		case WD_DAE_SHORT_DECIMAL:
			ret = dae_decimal_precision_check(key_cols[i].col_data_info, false);
			if (ret)
				return ret;
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
			WD_ERR("invalid: unsupport key col %u data type %u!\n",
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

static int hashagg_check_sum_info(struct wd_agg_col_info *agg_col,
				  struct hw_agg_data *user_input_data,
				  struct hw_agg_data *user_output_data, __u32 index)
{
	int ret;

	switch (agg_col->input_data_type) {
	case WD_DAE_LONG:
		if (agg_col->output_data_types[index] != WD_DAE_LONG) {
			WD_ERR("invalid: long type do sum output data type %u error!\n",
				agg_col->output_data_types[index]);
			return -WD_EINVAL;
		}
		user_input_data->hw_type = DAE_SINT64;
		user_output_data->hw_type = DAE_SINT64;
		break;
	case WD_DAE_SHORT_DECIMAL:
		if (agg_col->output_data_types[index] == WD_DAE_SHORT_DECIMAL) {
			ret = dae_decimal_precision_check(agg_col->col_data_info, false);
			if (ret)
				return ret;
			user_input_data->sum_outtype = DECIMAL64_TO_DECIMAL64;
			user_output_data->hw_type = DAE_DECIMAL64;
			/* For rehash, rehash will do sum */
			user_output_data->sum_outtype = DECIMAL64_TO_DECIMAL64;
		} else if (agg_col->output_data_types[index] == WD_DAE_LONG_DECIMAL) {
			ret = dae_decimal_precision_check(agg_col->col_data_info, true);
			if (ret)
				return ret;
			user_input_data->sum_outtype = DECIMAL64_TO_DECIMAL128;
			user_output_data->hw_type = DAE_DECIMAL128;
		} else {
			WD_ERR("invalid: short decimal do sum output data type %u error!\n",
				agg_col->output_data_types[index]);
			return -WD_EINVAL;
		}
		user_input_data->hw_type = DAE_DECIMAL64;
		break;
	case WD_DAE_LONG_DECIMAL:
		if (agg_col->output_data_types[index] != WD_DAE_LONG_DECIMAL) {
			WD_ERR("invalid: long decimal do sum output data type %u error!\n",
				agg_col->output_data_types[index]);
			return -WD_EINVAL;
		}
		ret = dae_decimal_precision_check(agg_col->col_data_info, true);
		if (ret)
			return ret;
		user_input_data->hw_type = DAE_DECIMAL128;
		user_output_data->hw_type = DAE_DECIMAL128;
		break;
	default:
		WD_ERR("invalid: device not support col data type %u do sum!\n",
			agg_col->input_data_type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_check_count_info(enum wd_dae_data_type input_type,
				    enum wd_dae_data_type output_type)
{
	if (input_type > WD_DAE_VARCHAR) {
		WD_ERR("invalid: device not support agg col data type %u do count!\n", input_type);
		return -WD_EINVAL;
	}

	if (output_type != WD_DAE_LONG) {
		WD_ERR("invalid: input data type %u do count output data type %u error!\n",
			input_type, output_type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hashagg_check_max_min_info(struct wd_agg_col_info *agg_col,
				      struct hw_agg_data *user_input_data,
				      struct hw_agg_data *user_output_data)
{
	int ret;

	switch (agg_col->input_data_type) {
	case WD_DAE_LONG:
		user_input_data->hw_type = DAE_SINT64;
		user_output_data->hw_type = DAE_SINT64;
		break;
	case WD_DAE_SHORT_DECIMAL:
		ret = dae_decimal_precision_check(agg_col->col_data_info, false);
		if (ret)
			return ret;
		user_input_data->hw_type = DAE_DECIMAL64;
		user_output_data->hw_type = DAE_DECIMAL64;
		break;
	case WD_DAE_LONG_DECIMAL:
		ret = dae_decimal_precision_check(agg_col->col_data_info, true);
		if (ret)
			return ret;
		user_input_data->hw_type = DAE_DECIMAL128;
		user_output_data->hw_type = DAE_DECIMAL128;
		break;
	default:
		WD_ERR("invalid: device not support col data type %u do max or min!\n",
			agg_col->input_data_type);
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
	case WD_AGG_MAX:
		ret = hashagg_check_max_min_info(agg_col, user_input_data, user_output_data);
		if (ret)
			return ret;
		user_input_data->optype |= DAE_HASHAGG_MAX;
		user_output_data->optype = DAE_MAX;
		break;
	case WD_AGG_MIN:
		ret = hashagg_check_max_min_info(agg_col, user_input_data, user_output_data);
		if (ret)
			return ret;
		user_input_data->optype |= DAE_HASHAGG_MIN;
		user_output_data->optype = DAE_MIN;
		break;
	default:
		WD_ERR("invalid: device not support alg %u!\n", agg_col->output_col_algs[index]);
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
	__u32 tmp = *output_num;
	__u32 i, j, k = 0;
	int ret;

	for (i = 0; i < cols_num; i++) {
		if (agg_cols[i].col_alg_num > DAE_AGG_COL_ALG_MAX_NUM) {
			WD_ERR("invalid: col alg num(%u) more than 2!\n", agg_cols[i].col_alg_num);
			return -WD_EINVAL;
		}
		tmp += agg_cols[i].col_alg_num;
	}

	if (tmp > DAE_MAX_OUTPUT_COLS) {
		WD_ERR("invalid: output col num is more than %d!\n", DAE_MAX_OUTPUT_COLS);
		return -WD_EINVAL;
	}

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

	if (setup->is_count_all)
		cols_data->output_num++;

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
		row_count_size += get_data_type_size(key_data[i].hw_type,
						     key_data[i].data_info);

	for (i = 0; i < output_num; i++)
		row_count_size += get_data_type_size(output_col[i].hw_type,
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

static void hashagg_sess_priv_uninit(struct wd_alg_driver *drv, void *priv)
{
	struct hashagg_ctx *agg_ctx = priv;

	if (!agg_ctx) {
		WD_ERR("invalid: dae sess uninit priv is NULL!\n");
		return;
	}

	pthread_spin_destroy(&agg_ctx->lock);
	free(agg_ctx);
}

static int hashagg_sess_priv_init(struct wd_alg_driver *drv,
				  struct wd_agg_sess_setup *setup, void **priv)
{
	struct hashagg_ctx *agg_ctx;
	int ret;

	if (!drv || !drv->priv) {
		WD_ERR("invalid: dae drv is NULL!\n");
		return -WD_EINVAL;
	}

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

static int agg_get_row_size(struct wd_alg_driver *drv, void *param)
{
	struct hashagg_ctx *agg_ctx = param;

	if (!agg_ctx)
		return -WD_EINVAL;

	return agg_ctx->row_size;
}

static int agg_hash_table_init(struct wd_alg_driver *drv,
			       struct wd_dae_hash_table *hash_table, void *priv)
{
	struct hashagg_ctx *agg_ctx = priv;

	if (!agg_ctx || !hash_table)
		return -WD_EINVAL;

	return dae_hash_table_init(&agg_ctx->table_data, &agg_ctx->rehash_table,
				   hash_table, agg_ctx->row_size);
}

static int dae_get_extend_ops(void *ops)
{
	struct wd_agg_ops *agg_ops = (struct wd_agg_ops *)ops;

	if (!agg_ops)
		return -WD_EINVAL;

	agg_ops->get_row_size = agg_get_row_size;
	agg_ops->hash_table_init = agg_hash_table_init;
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
