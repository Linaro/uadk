/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DIGEST_H
#define __WD_DIGEST_H
#include <dlfcn.h>

#include "include/wd_alg_common.h"
#include "config.h"
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
	wd_dev_mask_t		*dev_mask;
	struct wd_digest_driver *drv;
	void			*priv;
	void			*key;
	__u32			key_bytes;
};

/**
 * struct wd_digest_arg - Parameters for per digest operation
 * @alg: digest algorithm type, denoted by enum wd_digest_type
 * @mode:digest algorithm mode, denoted by enum wd_digest_mode
 * @in: input data address
 * @out: output data address
 * @key: input key address
 * @in_bytes: input data size
 * @out_bytes: output data size
 * @key_bytes: input key data size
 * @has_next: is there next data block
 * @cb: callback function for async mode
 * @cb_param: private information for data extension
 *
 * Note: If there is a alg selected in session, alg below will be ignore
 *       otherwise, alg here will be used. Same as mode below.
 *
 * fix me: for hmac, seems we need *key also?
 */
struct wd_digest_req {
	enum wd_digest_type alg;
	enum wd_digest_mode mode;

	void		*in;
	void		*out;
	void		*key;
	__u16		in_bytes;
	__u16		out_bytes;
	__u16		key_bytes;
	__u16		state;
	__u16		has_next;
	wd_digest_cb_t	*cb;
	void		*cb_param;
};

struct wd_digest_sched {
	const char *name;
	__u32 sched_ctx_size;
	handle_t (*pick_next_ctx)(struct wd_ctx_config *config,
		void *sched_ctx, struct wd_digest_req *req, int numa_id);
	int (*poll_policy)(struct wd_ctx_config *config, __u32 expect, __u32 *count);
};

struct wd_cb_tag {
	void *ctx;	/* user: context or other user relatives */
	void *tag;	/* to store user tag */
	int ctx_id;	/* user id: context ID or other user identifier */
};

/* Digest tag format */
struct wd_digest_tag {
	struct wd_cb_tag wd_tag;
	__u64 long_data_len;
	void *priv;
};

int wd_digest_init(struct wd_ctx_config *config, struct wd_digest_sched *sched);
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
 * @handle_t: session handler which will be free
 */
void wd_digest_free_sess(handle_t sess);

/**
 * wd_do_digest_sync() - Do sync digest task.
 * @sess: Session handler
 * @req: Operation parameters.
 */
int wd_do_digest_sync(handle_t sess, struct wd_digest_req *req);

/**
 * wd_do_digest_async() - Do asynchronous digest task.
 * @sess: Session handler
 * @req: Operation parameters.
 */
int wd_do_digest_async(handle_t sess, struct wd_digest_req *req);

/**
 * wd_set_digest_key() - Set auth key to digest session.
 * @req: Operation parameters.
 * @key: Auth key addr
 * @key_len: Auth key length
 */
int wd_set_digest_key(struct wd_digest_req *req, __u8 *key, __u32 key_len);

/**
 * wd_digest_poll() - Poll operation for asynchronous operation.
 * @h_ctx: context
 * @expt: Count of polling
 * @count: recv poll nums.
 */
int wd_digest_poll_ctx(handle_t h_ctx, __u32 expt, __u32 *count);

/**
 * wd_digest_poll() - Poll operation for asynchronous operation.
 * @expt: Count of polling.
 * @count: recv poll nums.
 */
int wd_digest_poll(__u32 expt, __u32 *count);

#endif /* __WD_DIGEST_H */
