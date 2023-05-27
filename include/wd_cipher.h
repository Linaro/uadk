/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H

#include <dlfcn.h>
#include "wd_alg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE	16
#define GCM_IV_SIZE	12
#define DES3_BLOCK_SIZE	8
#define MAX_CIPHER_KEY_SIZE	64
#define MAX_IV_SIZE	AES_BLOCK_SIZE

/**
 * config ctx operation type and task mode.
 *
 */
enum {
	CTX_TYPE_ENCRYPT = 0,
	CTX_TYPE_DECRYPT,
};

/**
 * wd_cipher_op_type - Algorithm type of option
 */
enum wd_cipher_op_type {
	WD_CIPHER_ENCRYPTION,
	WD_CIPHER_DECRYPTION,
};

/**
 * wd_cipher_type - Algorithm type of cipher
 */
enum wd_cipher_alg {
	WD_CIPHER_SM4,
	WD_CIPHER_AES,
	WD_CIPHER_DES,
	WD_CIPHER_3DES,
	WD_CIPHER_ALG_TYPE_MAX,
};

/**
 * wd_cipher_mode - Algorithm mode of cipher
 */
enum wd_cipher_mode {
	WD_CIPHER_ECB,
	WD_CIPHER_CBC,
	WD_CIPHER_CTR,
	WD_CIPHER_XTS,
	WD_CIPHER_OFB,
	WD_CIPHER_CFB,
	WD_CIPHER_CBC_CS1,
	WD_CIPHER_CBC_CS2,
	WD_CIPHER_CBC_CS3,
	WD_CIPHER_CCM,
	WD_CIPHER_GCM,
	WD_CIPHER_MODE_TYPE_MAX,
};

struct wd_cipher_sess_setup {
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
	void *sched_param;
};

struct wd_cipher_req;
typedef void *wd_alg_cipher_cb_t(struct wd_cipher_req *req, void *cb_param);

struct wd_cipher_req {
	enum wd_cipher_op_type op_type;
	union {
		struct wd_datalist *list_src;
		void *src;
	};
	union {
		struct wd_datalist *list_dst;
		void *dst;
	};
	void			*iv;
	__u32			in_bytes;
	__u32			iv_bytes;
	__u32			out_buf_bytes;
	__u32			out_bytes;
	__u16			state;
	__u8			type;
	__u8			data_fmt;
	wd_alg_cipher_cb_t	*cb;
	void			*cb_param;
};

/**
 * wd_cipher_init() Initialise ctx configuration and schedule.
 * @ config	    User defined ctx configuration.
 * @ sched	    User defined schedule.
 */
int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched);
void wd_cipher_uninit(void);

/**
 * wd_cipher_init2_() - A simplify interface to initializate uadk
 * encryption and decryption. This interface keeps most functions of
 * wd_cipher_init(). Users just need to descripe the deployment of
 * business scenarios. Then the initialization will request appropriate
 * resources to support the business scenarios.
 * To make the initializate simpler, ctx_params support set NULL.
 * And then the function will set them as driver's default.
 * Please do not use this interface with wd_cipher_init() together, or
 * some resources may be leak.
 *
 * @alg: The algorithm users want to use.
 * @sched_type: The scheduling type users want to use.
 * @task_type: Task types, including soft computing, hardware and hybrid computing.
 * @ctx_params: The ctxs resources users want to use. Include per operation
 * type ctx numbers and business process run numa.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_cipher_init2_(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params);

#define wd_cipher_init2(alg, sched_type, task_type) \
	wd_cipher_init2(alg, sched_type, task_type, NULL)

/**
 * wd_cipher_uninit2() - Uninitialise ctx configuration and scheduler.
 */
void wd_cipher_uninit2(void);

/**
 * wd_cipher_alloc_sess() Allocate a wd cipher session
 * @ setup Parameters to setup this session.
 */
handle_t wd_cipher_alloc_sess(struct wd_cipher_sess_setup *setup);

/**
 * wd_cipher_free_sess()
 * @ sess, need to be freed sess
 */
void wd_cipher_free_sess(handle_t h_sess);

/**
 * wd_cipher_set_key() Set cipher key to cipher msg.
 * @h_sess: wd cipher session.
 * @key: cipher key addr.
 * @key_len: cipher key length.
 */
int wd_cipher_set_key(handle_t h_sess, const __u8 *key, __u32 key_len);

/**
 * wd_do_cipher_sync()/ async() Syn/asynchronous cipher operation
 * @sess: wd cipher session
 * @req: operational data.
 */
int wd_do_cipher_sync(handle_t h_sess, struct wd_cipher_req *req);
int wd_do_cipher_async(handle_t h_sess, struct wd_cipher_req *req);
/**
 * wd_cipher_poll_ctx() poll operation for asynchronous operation
 * @idx: index of ctx which will be polled.
 * @expt: user expected num respondences
 * @count: how many respondences this poll has to get.
 */
int wd_cipher_poll_ctx(__u32 idx, __u32 expt, __u32 *count);
/**
 * wd_cipher_poll() Poll finished request.
 * this function will call poll_policy function which is registered to wd cipher
 * by user.
 */
int wd_cipher_poll(__u32 expt, __u32 *count);
/**
 * wd_cipher_env_init() - Init ctx and schedule resources according to wd cipher
 * environment variables.
 *
 * @sched: user's custom scheduler.
 * More information, please see docs/wd_environment_variable.
 */
int wd_cipher_env_init(struct wd_sched *sched);

/**
 * wd_cipher_env_uninit() - UnInit ctx and schedule resources set by above init.
 */
void wd_cipher_env_uninit(void);

/**
 * wd_cipher_ctx_num_init() - request ctx for cipher.
 * @node:       numa node id.
 * @type:       operation type.
 * @num:        ctx number.
 * @mode:       0: sync mode, 1: async mode
 */
int wd_cipher_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode);

/**
 * wd_cipher_ctx_num_uninit() - UnInit ctx and schedule resources
 * set by above init.
 *
 */
void wd_cipher_ctx_num_uninit(void);

/**
 * wd_cipher_get_env_param() - query the number of CTXs
 * that meet input attributes.
 *
 * @node:       numa node id.
 * @type:       operation type.
 * @mode:       0: sync mode, 1: async mode
 * @num:        return ctx num.
 * @is_enable   return enable inner poll flag.
 */
int wd_cipher_get_env_param(__u32 node, __u32 type, __u32 mode,
			    __u32 *num, __u8 *is_enable);

#ifdef __cplusplus
}
#endif

#endif /* __WD_CIPHER_H */
