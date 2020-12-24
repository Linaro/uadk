/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_AEAD_H
#define __WD_AEAD_H

#include <dlfcn.h>
#include "wd_alg_common.h"
#include "config.h"
#include "wd_cipher.h"
#include "wd_digest.h"
#include "wd.h"

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
};

struct wd_aead_req;
typedef void *wd_alg_aead_cb_t(struct wd_aead_req *req, void *cb_param);

struct wd_aead_sess {
	char			*alg_name;
	enum wd_cipher_alg	calg;
	enum wd_cipher_mode	cmode;
	enum wd_digest_type	dalg;
	enum wd_digest_mode	dmode;
	void			*ckey;
	void			*akey;
	__u16			ckey_bytes;
	__u16			akey_bytes;
	__u16			auth_bytes;
	void			*priv;
};

/**
 * struct wd_aead_req - Parameters for per aead operation.
 * @ op_type: denoted by enum wd_aead_op_type
 * @ src: input data pointer
 * @ dst: output data pointer
 * @ iv: input iv pointer
 * @ in_bytes: input data length
 * @ out_bytes: output data length
 * @ out_buf_bytes: output data buffer length
 * @ iv_bytes: input iv length
 * @ assoc_bytes: input associated data length
 * @ state: operation result, denoted by WD error code
 * @ cb: callback function pointer
 * @ cb_param: callback function paramaters
 */
struct wd_aead_req {
	enum wd_aead_op_type op_type;
	union {
		struct wd_sgl *sgl_src;
		void *src;
	};
	union {
		struct wd_sgl *sgl_dst;
		void *dst;
	};
	void			*iv;
	__u32			in_bytes;
	__u32			out_bytes;
	__u32			out_buf_bytes;
	__u16			iv_bytes;
	__u16			assoc_bytes;
	__u16			state;
	__u8		    data_fmt;
	wd_alg_aead_cb_t	*cb;
	void			*cb_param;
};

/**
 * wd_aead_init() Initialise ctx configuration and schedule.
 * @ config	    User defined ctx configuration.
 * @ sched	    User defined schedule.
 */
int wd_aead_init(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_aead_uninit() uninitialise ctx configuration and schedule.
 */
void wd_aead_uninit(void);

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
 * @index: index of ctx which will be polled.
 * @expt: user expected num respondings
 * @count: how many respondings this poll has to get.
 */
int wd_aead_poll_ctx(__u32 index, __u32 expt, __u32* count);

/**
 * wd_aead_poll() Poll finished request.
 * this function will call poll_policy function which is registered to wd aead
 * by user.
 * @expt: user expected num respondings
 * @count: how many respondings this poll has to get.
 */
int wd_aead_poll(__u32 expt, __u32 *count);
#endif /* __WD_AEAD_H */
