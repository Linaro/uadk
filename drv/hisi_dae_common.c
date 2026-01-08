// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <math.h>
#include "hisi_qm_udrv.h"
#include "hisi_dae.h"

int dae_decimal_precision_check(__u16 data_info, bool longdecimal)
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

__u32 get_data_type_size(enum dae_data_type type, __u16 data_info)
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
	default:
		break;
	}

	return 0;
}

/* The caller ensures that the address pointer or num is not null. */
int get_free_ext_addr(struct dae_extend_addr *ext_addr)
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

void put_ext_addr(struct dae_extend_addr *ext_addr, int idx)
{
	__atomic_clear(&ext_addr->addr_status[idx], __ATOMIC_RELEASE);
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

static int dae_ext_table_init(struct hash_table_data *hw_table,
			      struct hash_table_data *rehash_table,
			      struct wd_dae_hash_table *hash_table,
			      __u32 row_size, bool is_rehash)
{
	__u64 ext_size = hw_table->ext_table_size;
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
		memcpy(rehash_table, hw_table, sizeof(struct hash_table_data));

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

	hw_table->table_width = (__u32)log2(row_num);
	if (hw_table->table_width < HASH_TABLE_MIN_WIDTH ||
	    hw_table->table_width > HASH_TABLE_MAX_WIDTH) {
		WD_ERR("invalid: standard table width %u is out of device support range %d~%d!\n",
			hw_table->table_width, HASH_TABLE_MIN_WIDTH, HASH_TABLE_MAX_WIDTH);
		return -WD_EINVAL;
	}

	row_num = (__u64)pow(HASH_TABLE_WITDH_POWER, hw_table->table_width);
	hw_table->std_table_size = row_num * row_size;
	memset(hw_table->std_table, 0, hw_table->std_table_size);

	return WD_SUCCESS;
}

int dae_hash_table_init(struct hash_table_data *hw_table,
			struct hash_table_data *rehash_table,
			struct wd_dae_hash_table *hash_table,
			__u32 row_size)
{
	bool is_rehash = false;
	int ret;

	if (!row_size || row_size > hash_table->table_row_size) {
		WD_ERR("invalid: row size %u is error, device need %u!\n",
			hash_table->table_row_size, row_size);
		return -WD_EINVAL;
	}

	/* hash_std_table is checked by caller */
	if (!hash_table->ext_table || !hash_table->ext_table_row_num) {
		WD_ERR("invalid: hash extend table is null!\n");
		return -WD_EINVAL;
	}

	if (hw_table->std_table_size)
		is_rehash = true;

	ret = dae_ext_table_init(hw_table, rehash_table, hash_table, row_size, is_rehash);
	if (ret)
		return ret;

	ret = dae_std_table_init(hw_table, hash_table, row_size);
	if (ret)
		goto update_table;

	return WD_SUCCESS;

update_table:
	if (is_rehash)
		memcpy(hw_table, rehash_table, sizeof(struct hash_table_data));
	else
		memset(hw_table, 0, sizeof(struct hash_table_data));
	return ret;
}

int dae_init(struct wd_alg_driver *drv, void *conf)
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
		if (h_qp) {
			dae_uninit_qp_priv(h_qp);
			hisi_qm_free_qp(h_qp);
		}
	}
	free(priv);
	return ret;
}

void dae_exit(struct wd_alg_driver *drv)
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
		if (h_qp) {
			dae_uninit_qp_priv(h_qp);
			hisi_qm_free_qp(h_qp);
		}
	}

	free(priv);
	drv->priv = NULL;
}

int dae_get_usage(void *param)
{
	struct hisi_dev_usage *dae_usage = (struct hisi_dev_usage *)param;
	struct wd_alg_driver *drv = dae_usage->drv;
	struct wd_ctx_config_internal *config;
	struct hisi_dae_ctx *priv;
	char *ctx_dev_name;
	handle_t ctx = 0;
	handle_t qp = 0;
	__u32 i;

	if (dae_usage->alg_op_type >= drv->op_type_num) {
		WD_ERR("invalid: alg_op_type %u is error!\n", dae_usage->alg_op_type);
		return -WD_EINVAL;
	}

	priv = (struct hisi_dae_ctx *)drv->priv;
	if (!priv)
		return -WD_EACCES;

	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		ctx_dev_name = wd_ctx_get_dev_name(config->ctxs[i].ctx);
		if (!strcmp(dae_usage->dev_name, ctx_dev_name)) {
			ctx = config->ctxs[i].ctx;
			break;
		}
	}

	if (ctx)
		qp = (handle_t)wd_ctx_get_priv(ctx);

	if (qp)
		return hisi_qm_get_usage(qp, DAE_SQC_ALG_TYPE);

	return -WD_EACCES;
}
