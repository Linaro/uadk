/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef __WD_AEAD_H
#define __WD_AEAD_H

#include <dlfcn.h>
#include "wd_alg_common.h"
#include "wd_cipher.h"
#include "wd_digest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AIV_STREAM_LEN 64
/**
 * wd_aead_op_type - Algorithm type of option
 */
enum wd_aead_op_type {
	WD_CIPHER_ENCRYPTION_DIGEST,
	WD_CIPHER_DECRYPTION_DIGEST,
	WD_DIGEST_CIPHER_ENCRYPTION,
	WD_DIGEST_CIPHER_DECRYPTION,
};

/**
 * wd_cipher_alg - Algorithm type of cipher
 * statement in wd_cipher.h
 *
 * wd_cipher_mode - Algorithm mode of cipher
 * statement in wd_cipher.h
 */

struct wd_aead_sess_setup {
	enum wd_cipher_alg calg;
	enum wd_cipher_mode cmode;
	enum wd_digest_type dalg;
	enum wd_digest_mode dmode;
	void *sched_param;
};

/**
 * wd_aead_msg_state - Notify the message state
 * zero is message for block mode, non-zero is message for stream mode.
 */
enum wd_aead_msg_state {
	AEAD_MSG_BLOCK = 0x0,
	AEAD_MSG_FIRST,
	AEAD_MSG_MIDDLE,
	AEAD_MSG_END,
	AEAD_MSG_INVALID,
};

struct wd_aead_req;
typedef void *wd_alg_aead_cb_t(struct wd_aead_req *req, void *cb_param);

/**
 * struct wd_aead_req - Parameters for per aead operation.
 * @ op_type: denoted by enum wd_aead_op_type
 * @ src: input data pointer
 * @ dst: output data pointer
 * @ mac: mac data pointer
 * @ iv: input iv pointer
 * @ in_bytes: input data length
 * @ out_bytes: output data length
 * @ iv_bytes: input iv length
 * @ mac_bytes: mac data buffer length
 * @ assoc_bytes: input associated data length
 * @ state: operation result, denoted by WD error code
 * @ cb: callback function pointer
 * @ cb_param: callback function paramaters
 */
struct wd_aead_req {
	enum wd_aead_op_type op_type;
	union {
		struct wd_datalist *list_src;
		void *src;
	};
	union {
		struct wd_datalist *list_dst;
		void *dst;
	};
	void			*mac;
	void			*iv;
	__u32			in_bytes;
	__u32			out_bytes;
	__u16			iv_bytes;
	__u16			mac_bytes;
	__u16			assoc_bytes;
	__u16			state;
	__u8		    data_fmt;
	wd_alg_aead_cb_t	*cb;
	void			*cb_param;

	enum wd_aead_msg_state	msg_state;
};

/**
 * wd_aead_init() Initialise ctx configuration and schedule.
 * @ config	    User defined ctx configuration.
 * @ sched	    User defined schedule.
 */
int wd_aead_init(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_aead_uninit() uninitialized ctx configuration and schedule.
 */
void wd_aead_uninit(void);

/**
 * wd_aead_init2_() - A simplify interface to initializate uadk
 * aead operation. This interface keeps most functions of
 * wd_aead_init(). Users just need to descripe the deployment of
 * business scenarios. Then the initialization will request appropriate
 * resources to support the business scenarios.
 * To make the initializate simpler, ctx_params support set NULL.
 * And then the function will set them as driver's default.
 * Please do not use this interface with wd_aead_init() together, or
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
int wd_aead_init2_(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params);

#define wd_aead_init2(alg, sched_type, task_type) \
	wd_aead_init2_(alg, sched_type, task_type, NULL)

/**
 * wd_aead_uninit2() - Uninitialise ctx configuration and scheduler.
 */
void wd_aead_uninit2(void);
/**
 * wd_aead_alloc_sess() Allocate a wd aead session
 * @ setup Parameters to setup this session.
 */
handle_t wd_aead_alloc_sess(struct wd_aead_sess_setup *setup);

/**
 * wd_aead_free_sess()
 * @ sess, need to be freed sess
 */
void wd_aead_free_sess(handle_t h_sess);

/**
 * wd_aead_set_ckey() Set cipher key to aead session.
 * @h_sess: wd aead session.
 * @key: cipher key addr.
 * @key_len: cipher key length.
 */
int wd_aead_set_ckey(handle_t h_sess, const __u8 *key, __u16 key_len);

/**
 * wd_aead_set_akey() Set authenticate key to aead session.
 * @h_sess: wd aead session.
 * @key: authenticate key addr.
 * @key_len: authenticate key length.
 */
int wd_aead_set_akey(handle_t h_sess, const __u8 *key, __u16 key_len);

/**
 * wd_do_aead_sync() synchronous aead operation
 * @sess: wd aead session
 * @req: operational data.
 */
int wd_do_aead_sync(handle_t h_sess, struct wd_aead_req *req);

/**
 * wd_do_aead_async() asynchronous aead operation
 * @sess: wd aead session
 * @req: operational data.
 */
int wd_do_aead_async(handle_t h_sess, struct wd_aead_req *req);

/**
 * wd_aead_set_authsize() Set authenticate data length to aead session.
 * @h_sess: wd aead session.
 * @authsize: authenticate data length.
 */
int wd_aead_set_authsize(handle_t h_sess, __u16 authsize);

/**
 * wd_aead_get_authsize() Get authenticate data length from aead session.
 * @h_sess: wd aead session.
 */
int wd_aead_get_authsize(handle_t h_sess);

/**
 * wd_aead_get_maxauthsize() Get max authenticate data length from aead API.
 * @h_sess: wd aead session.
 */
int wd_aead_get_maxauthsize(handle_t h_sess);

/**
 * wd_aead_poll_ctx() poll operation for asynchronous operation
 * @idx: index of ctx which will be polled.
 * @expt: user expected num respondences
 * @count: how many respondences this poll has to get.
 */
int wd_aead_poll_ctx(__u32 idx, __u32 expt, __u32 *count);
int wd_aead_poll_ctx_(struct wd_sched *sched, __u32 idx, __u32 expt, __u32 *count);

/**
 * wd_aead_poll() Poll finished request.
 * this function will call poll_policy function which is registered to wd aead
 * by user.
 * @expt: user expected num respondences
 * @count: how many respondences this poll has to get.
 */
int wd_aead_poll(__u32 expt, __u32 *count);

/**
 * wd_aead_env_init() - Init ctx and schedule resources according to wd aead
 * environment variables.
 * @sched: user's custom scheduler.
 * More information, please see docs/wd_environment_variable.
 */
int wd_aead_env_init(struct wd_sched *sched);

/**
 *   wd_aead_env_uninit() - UnInit ctx and schedule resources set by above init.
 */
void wd_aead_env_uninit(void);

/**
 * wd_aead_ctx_num_init() - request ctx for aead.
 * @node:       numa node id.
 * @type:       operation type.
 * @num:        ctx number.
 * @mode:       0: sync mode, 1: async mode
 */
int wd_aead_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode);

/**
 * wd_aead_ctx_num_uninit() - UnInit ctx and schedule resources
 * set by above init.
 */
void wd_aead_ctx_num_uninit(void);

/**
 * wd_aead_get_env_param() - query the number of CTXs
 * that meet input attributes.
 * @node:       numa node id.
 * @type:       operation type.
 * @mode:       0: sync mode, 1: async mode
 * @num:        return ctx num.
 * @is_enable   return enable inner poll flag.
 *
 * If the current algorithm library does not require the type parameter,
 * the type parameter is invalid. The function returns 0 to indicate that
 * the value read is valid; otherwise, it returns a negative number.
 */
int wd_aead_get_env_param(__u32 node, __u32 type, __u32 mode,
			  __u32 *num, __u8 *is_enable);

#ifdef __cplusplus
}
#endif

#endif /* __WD_AEAD_H */
