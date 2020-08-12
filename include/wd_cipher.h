/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H

#include "config.h"
#include "wd.h"

#define AES_KEYSIZE_128 16
#define AES_KEYSIZE_192 24
#define AES_KEYSIZE_256 32
/**
 * config ctx operation type and task mode.
 *
 */
enum {
	CTX_TYPE_ENCRYPT = 0,
	CTX_TYPE_DECRYPT,
};

enum {
	CTX_MODE_SYNC = 0,
	CTX_MODE_ASYNC,
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
	WD_CIPHER_ALG_TYPE_NONE,
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
	WD_CIPHER_MODE_TYPE_NONE,
	WD_CIPHER_ECB,
	WD_CIPHER_CBC,
	WD_CIPHER_CTR,
	WD_CIPHER_XTS,
	WD_CIPHER_OFB,
	WD_CIPHER_CFB,
	WD_CIPHER_MODE_TYPE_MAX,
};

struct wd_cipher_sess_setup {
	char *alg_name;
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
};

typedef void *wd_alg_cipher_cb_t(void *cb_param);

struct wd_cipher_sess {
	char			*alg_name;
  	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
	char			node_path[MAX_DEV_NAME_LEN + 1];
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_cipher	*drv;
	void			*priv;
	void			*key;
	__u32			key_bytes;
};

struct wd_cipher_req {
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
	enum wd_cipher_op_type op_type;
	void			*src;
	void			*dst;
	void			*iv;
	void			*key;
	__u32			in_bytes;
	__u32			iv_bytes;
	__u32			out_bytes;
	__u32			key_bytes;
	wd_alg_cipher_cb_t	*cb;
	void			*cb_param;
};

struct wd_ctx {
	handle_t ctx;
	__u8 op_type;
	__u8 ctx_mode;
};

struct wd_ctx_config {
	__u32 ctx_num;
	struct wd_ctx *ctxs;
	void *priv;
};

struct wd_sched {
	const char *name;
	__u32 sched_ctx_size;
	handle_t (*pick_next_ctx)(struct wd_ctx_config *config,
				  void *sched_ctx, struct wd_cipher_req *req, int numa_id);
	__u32 (*poll_policy)(struct wd_ctx_config *config, void *sched_ctx);
};

/**
 * wd_cipher_init() Initialise ctx configuration and schedule.
 * @ config	    User defined ctx configuration.
 * @ sched	    User defined schedule.
 */
extern int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched);
extern void wd_cipher_uninit(void);
/**
 * wd_alloc_cipher_sess() Allocate a wd cipher session
 * @ setup Parameters to setup this session.
 */
extern handle_t wd_alloc_cipher_sess(struct wd_cipher_sess_setup *setup);
/**
 * wd_cipher_free_sess()
 * @ sess, need to be freed sess
 */
extern void wd_cipher_free_sess(handle_t h_sess);
extern int wd_cipher_set_key(struct wd_cipher_req *req, const __u8 *key, __u32 key_len);
extern int wd_do_cipher(handle_t sess, struct wd_cipher_req *req);
extern int wd_do_cipher_async(handle_t sess, struct wd_cipher_req *req);
extern int wd_cipher_poll_ctx(handle_t sess, __u32 count);
#endif /* __WD_CIPHER_H */
