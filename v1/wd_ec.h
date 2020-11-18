/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_EC_H
#define __WD_EC_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"
#include "wd_ec_util.h"

enum wcrypto_ec_type {
	WCRYPTO_EC_MPCC = 0,
	WCRYPTO_EC_FLEXEC = 2,
};

enum wcrypto_ec_op_type {
	WCRYPTO_EC_GENERATE,
	WCRYPTO_EC_VALIDATE,
	WCRYPTO_EC_UPDATE,
	WCRYPTO_EC_RECONSTRUCT,
};

enum wcrypto_ec_alg_gran {
	WCRYPTO_EC_ALG_BLK512B,
	WCRYPTO_EC_ALG_BLK4K,
};

enum wcrypto_ec_cm_ctrl {
	WCRYPTO_EC_NO_CM_LOAD,
	WCRYPTO_EC_CM_LOAD,
};

enum wcrypto_ec_blksize {
	WCRYPTO_EC_BLK_512 = 512,
	WCRYPTO_EC_BLK_520 = 520,
	WCRYPTO_EC_BLK_4096 = 4096,
	WCRYPTO_EC_BLK_4104 = 4104,
	WCRYPTO_EC_BLK_4160 = 4160,
};

/**
 * different contexts for different users/threads
 * @ec_type: denoted by enum wcrypto_ec_type
 * @cb: call back functions of user
 * @data_fmt: denoted by enum wcrypto_buff_type
 * @ops: memory from user, it is given at ctx creating
 */
struct wcrypto_ec_ctx_setup {
	enum wcrypto_ec_type ec_type;
	wcrypto_cb cb;
	__u16 data_fmt;
	struct wd_mm_ops ops;
};

/**
 * operational data per I/O operation
 * @op_type: denoted by enum wcrypto_ec_op_type
 * @status: I/O operation return status
 * @coef_matrix: Coefficient matrix
 * @in: Input address
 * @out: Result address
 * @coef_matrix_load: coef_matrix reload control, 0: do not load, 1: load
 * @coef_matrix_len: length of loaded coe_matrix, equal to src_num
 * @in_disk_num: number of source disks
 * @out_disk_num: number of destination disks
 * @alg_blk_size: algorithm granularity, denoted by enum wd_ec_alg_gran
 * @block_size: denoted by enum wd_ec_blksize
 * @block_num: number of sector
 * @priv: private information for data extension
 */
struct wcrypto_ec_op_data {
	enum wcrypto_ec_op_type op_type;
	int status;
	__u8 *coef_matrix;
	void *in;
	void *out;
	__u8 coef_matrix_load;
	__u8 coef_matrix_len;
	__u8 in_disk_num;
	__u8 out_disk_num;
	__u8 alg_blk_size;
	__u16 block_size;
	__u16 block_num;
	void *priv;
};

/**
 * EC message format of Warpdrive
 *@alg_type: denoted by enum wcrypto_type
 *@ec_type: denoted by enum wcrypto_ec_type
 *@op_type: denoted by enum wcrypto_ec_op_type
 *@result: denoted by WD error code
 *@usr_data: wcrypto_ec_tag
 *@cid: ctx_id
 */
struct wcrypto_ec_msg {
	__u8 alg_type;
	__u8 ec_type;
	__u8 op_type;
	__u8 data_fmt;
	__u8 result;
	__u8 coef_matrix_load;
	__u8 coef_matrix_len;
	__u8 in_disk_num;
	__u8 out_disk_num;
	__u8 alg_blk_size;
	__u16 block_size;
	__u16 block_num;
	__u32 cid;
	__u8 *coef_matrix;
	void *in;
	void *out;
	__u64 usr_data;
};

/**
 * wcrypto_create_ec_ctx() - create a ec context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_ec_ctx(struct wd_queue *q,
		struct wcrypto_ec_ctx_setup *setup);

/**
 * wcrypto_do_ec() - syn/asynchronous flexec/mpcc operation
 * @ctx: context of user
 * @opdata: operational data
 * @tag: asynchronous:uesr_tag; synchronous:NULL.
 */
int wcrypto_do_ec(void *ctx, struct wcrypto_ec_op_data *opdata, void *tag);

/**
 * wcrypto_ec_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondings this poll has to get, 0 means get all finishings
 */
int wcrypto_ec_poll(struct wd_queue *q, int num);

/**
 * wcrypto_del_ec_ctx() - free ec context
 * @ctx: the context to be free
 */
void wcrypto_del_ec_ctx(void *ctx);

#endif
