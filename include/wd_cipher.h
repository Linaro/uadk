/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H

#include <dlfcn.h>
#include "wd.h"
#include "wd_alg_common.h"

#define AES_KEYSIZE_128 16
#define AES_KEYSIZE_192 24
#define AES_KEYSIZE_256 32
#define AES_BLOCK_SIZE 16
#define GCM_BLOCK_SIZE 12
#define DES3_BLOCK_SIZE 8

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
	WD_CIPHER_CCM,
	WD_CIPHER_GCM,
	WD_CIPHER_MODE_TYPE_MAX,
};

struct wd_cipher_sess_setup {
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
};

struct wd_cipher_req;
typedef void *wd_alg_cipher_cb_t(struct wd_cipher_req *req, void *cb_param);

struct wd_cipher_sess {
	char			*alg_name;
  	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_cipher	*drv;
	void			*priv;
	void			*key;
	__u32			key_bytes;
	int				numa;
};

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
 * @index: index of ctx which will be polled.
 * @expt: user expected num respondings
 * @count: how many respondings this poll has to get.
 */
int wd_cipher_poll_ctx(__u32 index, __u32 expt, __u32* count);
/**
 * wd_cipher_poll() Poll finished request.
 * this function will call poll_policy function which is registered to wd cipher
 * by user.
 */
int wd_cipher_poll(__u32 expt, __u32 *count);
#endif /* __WD_CIPHER_H */
