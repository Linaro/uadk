/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_AGG_H
#define __WD_AGG_H

#include <dlfcn.h>
#include <asm/types.h>
#include "wd_dae.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * wd_agg_alg - Aggregation operation type.
 */
enum wd_agg_alg {
	WD_AGG_SUM,
	WD_AGG_COUNT,
	WD_AGG_ALG_TYPE_MAX,
};

/**
 * wd_agg_task_error_type - Aggregation task error type.
 */
enum wd_agg_task_error_type {
	WD_AGG_TASK_DONE,
	WD_AGG_IN_EPARA,
	WD_AGG_NEED_REHASH,
	WD_AGG_SUM_OVERFLOW,
	WD_AGG_INVALID_HASH_TABLE,
	WD_AGG_INVALID_VARCHAR,
	WD_AGG_PARSE_ERROR,
	WD_AGG_BUS_ERROR,
};

/**
 * wd_key_col_info - Key column information.
 * @col_data_info: For CHAR, it is size of data, at least 1B.
 * For VARCHAR, it is size of data in hash table, 0 means the max size.
 * For DECIMAL, it is precision of data, high 8 bit: decimal part precision,
 * low 8 bit: the whole data precision.
 * @input_data_type: Key column data type.
 */
struct wd_key_col_info {
	__u16 col_data_info;
	enum wd_dae_data_type input_data_type;
};

/**
 * wd_agg_col_info - Agg column information.
 * @col_alg_num: Number of aggregation operations for this column.
 * @col_data_info: For CHAR, it is size of data, at least 1B.
 * For VARCHAR, it is size of data in hash table, 0 means the max size.
 * For DECIMAL, it is precision of data, high 8 bit: decimal part precision,
 * low 8 bit: the whole data precision.
 * @input_data_type: Agg column data type.
 * @output_data_types: Output agg column data type.
 * @output_col_algs: Output agg column operation type, the sequence must be
 * the same as that of output_data_types.
 */
struct wd_agg_col_info {
	__u32 col_alg_num;
	__u16 col_data_info;
	enum wd_dae_data_type input_data_type;
	enum wd_dae_data_type output_data_types[WD_AGG_ALG_TYPE_MAX];
	enum wd_agg_alg output_col_algs[WD_AGG_ALG_TYPE_MAX];
};

/**
 * wd_agg_sess_setup - Agg session setup information.
 * @key_cols_num: Number of key columns.
 * @key_cols_info: Information of key columns.
 * @agg_cols_num: Number of agg columns.
 * @agg_cols_info: Information of agg columns.
 * @is_count_all: Whether to perform the count(*) operation.
 * @count_all_data_types: Output agg column data type.
 * @charset_info: Charset information
 * @sched_param: Parameters of the scheduling policy,
 * usually allocated according to struct sched_params.
 */
struct wd_agg_sess_setup {
	__u32 key_cols_num;
	struct wd_key_col_info *key_cols_info;
	__u32 agg_cols_num;
	struct wd_agg_col_info *agg_cols_info;
	bool is_count_all;
	enum wd_dae_data_type count_all_data_type;
	struct wd_dae_charset charset_info;
	void *sched_param;
};

struct wd_agg_req;
typedef void *wd_alg_agg_cb_t(struct wd_agg_req *req, void *cb_param);

/**
 * wd_agg_req - Aggregation operation request.
 * @key_cols: Address of key columns.
 * @out_key_cols: Address of output key columns.
 * @agg_cols: Address of agg columns.
 * @out_agg_cols: Address of output agg columns. If count(*) exist,
 * count(*) output address must be the last column.
 * @key_cols_num: Number of key columns.
 * @out_key_cols_num: Number of output key columns.
 * @agg_cols_num: Number of agg columns.
 * @out_agg_cols_num: Number of output agg columns.
 * @in_row_count: Row count of input column.
 * @out_row_count: Expected row count of output column.
 * @real_in_row_count: Row count of input data that has been processed.
 * @real_out_row_count: Real row count of output column.
 * @cb: Callback function.
 * @cb_param: Parameters of the callback function.
 * @sum_overflow_cols: If sum result is overflow, the value will be true.
 * If the pointer is null, only the state is set to WD_AGG_SUM_OVERFLOW.
 * @state: Error information written back by the hardware.
 * @output_done: If all data in hash table has been output.
 * @priv: Private data from user(reserved).
 */
struct wd_agg_req {
	struct wd_dae_col_addr *key_cols;
	struct wd_dae_col_addr *out_key_cols;
	struct wd_dae_col_addr *agg_cols;
	struct wd_dae_col_addr *out_agg_cols;
	__u32 key_cols_num;
	__u32 out_key_cols_num;
	__u32 agg_cols_num;
	__u32 out_agg_cols_num;
	__u32 in_row_count;
	__u32 out_row_count;
	__u32 real_in_row_count;
	__u32 real_out_row_count;
	wd_alg_agg_cb_t *cb;
	void *cb_param;
	__u8 *sum_overflow_cols;
	enum wd_agg_task_error_type state;
	bool output_done;
	void *priv;
};

/**
 * wd_agg_init() - A simplify interface to initializate uadk
 * encryption and decryption. This interface keeps most functions of
 * wd_agg_init(). Users just need to descripe the deployment of
 * business scenarios. Then the initialization will request appropriate
 * resources to support the business scenarios.
 * To make the initializate simpler, ctx_params support set NULL.
 * And then the function will set them as driver's default.
 *
 * @alg: The algorithm users want to use.
 * @sched_type: The scheduling type users want to use.
 * @task_type: Task types, including soft computing, hardware and hybrid computing.
 * @ctx_params: The ctxs resources users want to use. Include per operation
 * type ctx numbers and business process run numa.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_agg_init(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params);

/**
 * wd_agg_uninit() - Uninitialise ctx configuration and scheduler.
 */
void wd_agg_uninit(void);

/**
 * wd_agg_alloc_sess() - Allocate a wd agg session
 * @setup: Parameters to setup this session.
 *
 * Return 0 if fail and others if succeed.
 */
handle_t wd_agg_alloc_sess(struct wd_agg_sess_setup *setup);

/**
 * wd_agg_free_sess() - Free the wd agg session
 * @sess: The session need to be freed.
 */
void wd_agg_free_sess(handle_t h_sess);

/**
 * wd_agg_set_hash_table() - Set hash table to the wd agg session
 * @sess, Session to be initialized.
 * @info, Hash table information to set.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_agg_set_hash_table(handle_t h_sess, struct wd_dae_hash_table *info);

/**
 * wd_agg_add_input_sync()/wd_agg_get_output_sync() - Input or output agg operation
 * @sess: Wd agg session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_agg_add_input_sync(handle_t h_sess, struct wd_agg_req *req);
int wd_agg_get_output_sync(handle_t h_sess, struct wd_agg_req *req);
int wd_agg_add_input_async(handle_t h_sess, struct wd_agg_req *req);
int wd_agg_get_output_async(handle_t h_sess, struct wd_agg_req *req);

/**
 * wd_agg_rehash_sync - Rehash operation, only the synchronous mode is supported.
 * @sess: Wd agg session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_agg_rehash_sync(handle_t h_sess, struct wd_agg_req *req);

/**
 * wd_agg_poll() - Poll finished request.
 * This function will call poll_policy function which is registered to wd_agg
 * by user.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_agg_poll(__u32 expt, __u32 *count);

/**
 * wd_agg_get_table_rowsize - Get the hash table's row size.
 * @h_sess: Wd agg session handler.
 *
 * Return negative value if fail and others if succeed.
 */
int wd_agg_get_table_rowsize(handle_t h_sess);

#ifdef __cplusplus
}
#endif

#endif /* __WD_AGG_H */
