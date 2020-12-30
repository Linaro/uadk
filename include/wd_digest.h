/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DIGEST_H
#define __WD_DIGEST_H
#include <dlfcn.h>

#include "wd_alg_common.h"
#include "wd.h"

/**
 * wd_digest_type - Algorithm type of digest
 * algorithm should be offered by struct wd_digest_arg
 */
enum wd_digest_type {
	WD_DIGEST_SM3,
	WD_DIGEST_MD5,
	WD_DIGEST_SHA1,
	WD_DIGEST_SHA256,
	WD_DIGEST_SHA224,
	WD_DIGEST_SHA384,
	WD_DIGEST_SHA512,
	WD_DIGEST_SHA512_224,
	WD_DIGEST_SHA512_256,
	WD_DIGEST_TYPE_MAX,
};

enum wd_digest_mac_len {
	WD_DIGEST_SM3_LEN	= 32,
	WD_DIGEST_MD5_LEN	= 16,
	WD_DIGEST_SHA1_LEN	= 20,
	WD_DIGEST_SHA256_LEN	= 32,
	WD_DIGEST_SHA224_LEN	= 28,
	WD_DIGEST_SHA384_LEN	= 48,
	WD_DIGEST_SHA512_LEN	= 64,
	WD_DIGEST_SHA512_224_LEN	= 28,
	WD_DIGEST_SHA512_256_LEN	= 32
};

/**
 * wd_digest_mode - Mode of digest
 * Mode should be offered by struct wd_digest_arg
 * @WD_DIGEST_NORMAL: Normal digest
 * @WD_DIGEST_HMAC: Keyed-Hashing, e.g. HMAC
 */
enum wd_digest_mode {
	WD_DIGEST_NORMAL,
	WD_DIGEST_HMAC,
	WD_DIGEST_MODE_MAX,
};

/**
 * wd_digest_sess_setup - Parameters which is used to allocate a digest session
 * @alg: digest algorithm type, denoted by enum wd_digest_type
 * @mode: digest algorithm mode, denoted by enum wd_digest_mode
 */
struct wd_digest_sess_setup {
	enum wd_digest_type alg;
	enum wd_digest_mode mode;
};

typedef void *wd_digest_cb_t(void *cb_param);

struct wd_digest_sess {
	char			*alg_name;
	enum wd_digest_type	alg;
	enum wd_digest_mode	mode;
	void			*priv;
	void			*key;
	__u32			key_bytes;
};

/**
 * struct wd_digest_arg - Parameters for per digest operation
 * @in: input data address
 * @out: output data address
 * @in_bytes: input data size
 * @out_bytes: output data size
 * @out_buf_bytes: actual output buffer size
 * @has_next: is there next data block
 * @cb: callback function for async mode
 * @cb_param: pointer of callback parameter
 *
 * Note: If there is a alg selected in session, alg below will be ignore
 *       otherwise, alg here will be used. Same as mode below.
 *
 * fix me: for hmac, seems we need *key also?
 */
struct wd_digest_req {
	union {
		void *in;
		struct wd_sgl *sgl_in;
	};
	void		*out;
	__u32		in_bytes;
	__u32		out_bytes;
	__u32		out_buf_bytes;
	__u16		state;
	__u16		has_next;
	__u8        data_fmt;
	wd_digest_cb_t	*cb;
	void		*cb_param;
};

struct wd_cb_tag {
	void *ctx;	/* user: context or other user relatives */
	void *tag;	/* to store user tag */
	int ctx_id;	/* user id: context ID or other user identifier */
};

/* Digest tag format of warpdrive */
struct wd_digest_tag {
	struct wd_cb_tag wd_tag;
	__u64 long_data_len;
	void *priv;
};

int wd_digest_init(struct wd_ctx_config *config, struct wd_sched *sched);
void wd_digest_uninit(void);

/**
 * wd_digest_alloc_sess() - Create a digest session.
 * @setup: Hold the parameters which are used to allocate a digest session
 *
 * Return handler of allocated session. Return 0 if failing.
 */
handle_t wd_digest_alloc_sess(struct wd_digest_sess_setup *setup);

/**
 * wd_alg_digest_free_sess() - Free digest session.
 * @h_sess: session handler which will be free
 */
void wd_digest_free_sess(handle_t h_sess);

/**
 * wd_do_digest_sync() - Do sync digest task.
 * @h_sess: Session handler
 * @req: Operation parameters.
 */
int wd_do_digest_sync(handle_t h_sess, struct wd_digest_req *req);

/**
 * wd_do_digest_async() - Do asynchronous digest task.
 * @h_sess: Session handler
 * @req: Operation parameters.
 */
int wd_do_digest_async(handle_t h_sess, struct wd_digest_req *req);

/**
 * wd_digest_set_key() - Set auth key to digest session.
 * @h_sess: Session handler
 * @key: Auth key addr
 * @key_len: Auth key length
 */
int wd_digest_set_key(handle_t h_sess, const __u8 *key, __u32 key_len);

/**
 * wd_digest_poll() - Poll operation for asynchronous operation.
 * @index: index of ctx which will be polled.
 * @expt: Count of polling
 * @count: recv poll nums.
 */
int wd_digest_poll_ctx(__u32 index, __u32 expt, __u32 *count);

/**
 * wd_digest_poll() - Poll operation for asynchronous operation.
 * @expt: Count of polling.
 * @count: recv poll nums.
 */
int wd_digest_poll(__u32 expt, __u32 *count);

#endif /* __WD_DIGEST_H */
