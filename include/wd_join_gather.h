/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_JOIN_GATHER_H
#define __WD_JOIN_GATHER_H

#include <dlfcn.h>
#include <linux/types.h>

#include "wd_dae.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wd_join_gather_alg {
	WD_JOIN,
	WD_GATHER,
	WD_JOIN_GATHER,
	WD_JOIN_GATHER_ALG_MAX,
};

/**
 * wd_join_gather_op_type - operation type for hash join and gather.
 */
enum wd_join_gather_op_type {
	WD_JOIN_BUILD_HASH,
	WD_JOIN_PROBE,
	WD_JOIN_REHASH,
	WD_GATHER_CONVERT,
	WD_GATHER_COMPLETE,
	WD_JOIN_GATHER_OP_TYPE_MAX,
};

/**
 * wd_join_gather_task_error_type - hash join and gather task error type.
 */
enum wd_join_gather_task_error_type {
	WD_JOIN_GATHER_TASK_DONE,
	WD_JOIN_GATHER_IN_EPARA,
	WD_JOIN_GATHER_NEED_REHASH,
	WD_JOIN_GATHER_INVALID_HASH_TABLE,
	WD_JOIN_GATHER_PARSE_ERROR,
	WD_JOIN_GATHER_BUS_ERROR,
};

enum multi_batch_index_type {
	WD_BATCH_NUMBER_INDEX,
	WD_BATCH_ADDR_INDEX,
	WD_BATCH_INDEX_TYPE_MAX,
};

/**
 * wd_join_gather_col_info - column information.
 * @data_type: column data type.
 * @data_info: For CHAR, it is size of data, at least 1B.
 * For DECIMAL, it is precision of data, high 8 bit: decimal part precision,
 * low 8 bit: the whole data precision.
 * @has_empty: indicates whether the column contains empty data.
 */
struct wd_join_gather_col_info {
	enum wd_dae_data_type data_type;
	__u16	data_info;
	bool	has_empty;
};

/**
 * wd_gather_table_info - gather table information.
 * @cols: Information of gather table columns.
 * @cols_num: Number of gather table columns.
 * @is_multi_batch: indicates single or multi batch task.
 */
struct wd_gather_table_info {
	struct wd_join_gather_col_info *cols;
	__u32	cols_num;
	bool	is_multi_batch;
};

/**
 * wd_join_table_info - join table information.
 * @build_key_cols: Information of build table key columns.
 * @probe_key_cols: Information of probe table key columns.
 * @build_key_cols_num: Number of build table key columns.
 * @probe_key_cols_num: Number of probe table key columns.
 * @key_output_enable: Indicates whether output key columns.
 * @hash_table_index_num: Number of original rows can be stored
 * in each row of a hash table.
 */
struct wd_join_table_info {
	struct wd_join_gather_col_info *build_key_cols;
	struct wd_join_gather_col_info *probe_key_cols;
	__u32	build_key_cols_num;
	__u32	probe_key_cols_num;
	bool	key_output_enable;
	__u32	hash_table_index_num;
};

/**
 * wd_join_gather_sess_setup - Hash join and gather session setup information.
 * @join_table: Information of join table.
 * @gather_tables: Information of gather table.
 * @gather_table_num: Number of gather table.
 * @alg: Alg for this session.
 * @index_type: Indicates the index type, 0 for batch number and row number,
 * 1 for batch address and row number.
 * @charset_info: Charset information
 * @sched_param: Parameters of the scheduling policy,
 * usually allocated according to struct sched_params.
 */
struct wd_join_gather_sess_setup {
	struct wd_join_table_info	join_table;
	struct wd_gather_table_info	*gather_tables;
	__u32 gather_table_num;

	enum wd_join_gather_alg		alg;
	enum multi_batch_index_type	index_type;
	struct wd_dae_charset		charset_info;
	void	*sched_param;
};

struct wd_join_gather_req;
typedef void *wd_join_gather_cb_t(struct wd_join_gather_req *req, void *cb_param);

/**
 * wd_probe_out_info - Hash join probe output info.
 * @build_index: address information of multi batch index.
 * @probe_index: address information of single batch index.
 * @breakpoint: address information of probe breakpoint.
 * @key_cols: address information of output key columns.
 * @key_cols_num: number of output key columns.
 */
struct wd_probe_out_info {
	struct wd_dae_row_addr build_index;
	struct wd_dae_row_addr probe_index;
	struct wd_dae_row_addr breakpoint;
	struct wd_dae_col_addr *key_cols;
	__u32 key_cols_num;
};

/**
 * wd_join_req - Hash join request.
 * @build_batch_addr: Row-storaged batch address, the batch is used to store build
 * table data cols in row format. This field is only used for batch addr index.
 *
 * @probe_output: The information for hash join probe stage.
 * @key_cols: key columns from build table or probe table.
 * @key_cols_num: key columns number.
 * @batch_row_offset: Indicates the start row number of the input column.
 * @build_batch_index: build table batch index, start from 0.
 */
struct wd_join_req {
	struct wd_dae_row_addr		build_batch_addr;
	struct wd_probe_out_info	probe_output;
	struct wd_dae_col_addr		*key_cols;
	__u32 key_cols_num;
	__u32 batch_row_offset;
	__u32 build_batch_index;
};

/**
 * wd_row_batch_info - Information of some row-storaged batchs.
 * @batch_addr: Addr list of row batchs.
 * @batch_row_size: Row size of each row batch.
 * @batch_row_num: Row number of each row batch.
 * @batch_num: Total number of row batchs.
 */
struct wd_row_batch_info {
	void **batch_addr;
	__u32 *batch_row_size;
	__u32 *batch_row_num;
	__u32 batch_num;
};

/**
 * wd_gather_req - Hash join and gather operation request.
 * @index: address information of multi batch index or single batch index.
 * @row_batchs: address information of row batchs.
 * @data_cols: data columns from gather table.
 * @data_cols_num: columns number from gather table.
 * @table_index: The table index from the session's gather_tables to do tasks.
 */
struct wd_gather_req {
	struct wd_dae_row_addr index;
	struct wd_row_batch_info row_batchs;
	struct wd_dae_col_addr *data_cols;
	__u32 data_cols_num;
	__u32 table_index;
};

/**
 * wd_join_gather_req - Hash join and gather operation request.
 * @op_type: The operation type for hash join or gather task.
 * @join_req: The request for hash join.
 * @gather_req: The request for gather.
 * @input_row_num: Row count of input column.
 * @output_row_num: Expected row count of output column.
 * @consumed_row_num: Row count of input data that has been processed.
 * @produced_row_num: Real row count of output column.
 * @cb: Callback function for the asynchronous mode.
 * @cb_param: Parameters of the callback function.
 * @state: Error information written back by the hardware.
 * @output_done: For rehash, it indicates whether all data in hash table has been output.
 * For probe task, it indicates whether all data of one probe batch has been processed.
 * @priv: Private data from user(reserved).
 */
struct wd_join_gather_req {
	/* user fill-in fields */
	enum wd_join_gather_op_type	op_type;
	struct wd_join_req		join_req;
	struct wd_gather_req		gather_req;
	__u32 input_row_num;
	__u32 output_row_num;
	wd_join_gather_cb_t *cb;
	void *cb_param;
	void *priv;

	/* uadk driver writeback fields */
	enum wd_join_gather_task_error_type state;
	__u32	consumed_row_num;
	__u32	produced_row_num;
	bool	output_done;
};

/**
 * wd_join_gather_init() - A simplify interface to initializate uadk.
 * Users just need to descripe the deployment of business scenarios.
 * Then the initialization will request appropriate
 * resources to support the business scenarios.
 * To make the initializate simpler, ctx_params support set NULL.
 * And then the function will set them as driver's default.
 *
 * @alg: Supported algorithms: hashjoin, gather, join-gather.
 * @sched_type: The scheduling type users want to use.
 * @task_type: Task types, including soft computing, hardware and hybrid computing.
 * @ctx_params: The ctxs resources users want to use. Include per operation
 * type ctx numbers and business process run numa.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_join_gather_init(char *alg, __u32 sched_type, int task_type,
			struct wd_ctx_params *ctx_params);

/**
 * wd_join_gather_uninit() - Uninitialise ctx configuration and scheduler.
 */
void wd_join_gather_uninit(void);

/**
 * wd_join_gather_alloc_sess() - Allocate a hash join or gather session
 * @setup: Parameters to setup this session.
 *
 * Return 0 if fail and others if succeed.
 */
handle_t wd_join_gather_alloc_sess(struct wd_join_gather_sess_setup *setup);

/**
 * wd_join_gather_free_sess() - Free a hash join or gather session
 * @sess: The session need to be freed.
 */
void wd_join_gather_free_sess(handle_t h_sess);

/**
 * wd_join_set_hash_table() - Set hash table to the wd session
 * @sess, Session to be initialized.
 * @info, Hash table information to set.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_join_set_hash_table(handle_t h_sess, struct wd_dae_hash_table *info);

/**
 * wd_join_build_hash_sync()/wd_join_build_hash_async() - Build the hash table.
 * @sess: Wd session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_join_build_hash_sync(handle_t h_sess, struct wd_join_gather_req *req);
int wd_join_build_hash_async(handle_t h_sess, struct wd_join_gather_req *req);

/**
 * wd_join_probe_sync()/wd_join_probe_async() - Probe and output the index or key.
 * @sess: Wd session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_join_probe_sync(handle_t h_sess, struct wd_join_gather_req *req);
int wd_join_probe_async(handle_t h_sess, struct wd_join_gather_req *req);

/**
 * wd_gather_convert_sync()/wd_gather_convert_async() - Convert a column batch to a row batch.
 * @sess: Wd session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_gather_convert_sync(handle_t h_sess, struct wd_join_gather_req *req);
int wd_gather_convert_async(handle_t h_sess, struct wd_join_gather_req *req);

/**
 * wd_gather_complete_sync()/wd_gather_complete_async() - map the index with a row batch
 * and output the result to a column batch.
 * @sess: Wd session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_gather_complete_sync(handle_t h_sess, struct wd_join_gather_req *req);
int wd_gather_complete_async(handle_t h_sess, struct wd_join_gather_req *req);

/**
 * wd_join_rehash_sync - Rehash operation, only the synchronous mode is supported.
 * @sess: Wd hash join session
 * @req: Operational data.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_join_rehash_sync(handle_t h_sess, struct wd_join_gather_req *req);

/**
 * wd_join_gather_poll() - Poll finished request.
 * This function will call poll_policy function which is registered to wd
 * by user.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_join_gather_poll(__u32 expt, __u32 *count);

/**
 * wd_join_get_table_rowsize - Get the hash table's row size.
 * @h_sess: Wd session handler.
 *
 * Return negative value if fail and others if succeed.
 */
int wd_join_get_table_rowsize(handle_t h_sess);

/**
 * wd_gather_get_batch_rowsize - Get the batch row size.
 * @h_sess: Wd session handler.
 * @table_index: The table index from the session's gather_tables.
 *
 * Return negative value if fail and others if succeed.
 */
int wd_gather_get_batch_rowsize(handle_t h_sess, __u8 table_index);

#ifdef __cplusplus
}
#endif

#endif /* __WD_JOIN_GATHER_H */
