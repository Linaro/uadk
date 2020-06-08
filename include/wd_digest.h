/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DIGEST_H
#define __WD_DIGEST_H

#include "config.h"
#include "wd.h"
#include "wd_alg_common.h"

/**
 * wd_digest_type - Algorithm type of digest
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
 * @WD_DIGEST_NORMAL: Normal digest
 * @WD_DIGEST_HMAC: Keyed-Hashing, e.g. HMAC
 */
enum wd_digest_mode {
	WD_DIGEST_NORMAL,
	WD_DIGEST_HMAC,
};

/**
 * wd_digest_sess_setup - Parameters which is used to allocate a digest session
 * @alg: digest algorithm type, denoted by enum wd_digest_type
 * @mode:digest algorithm mode, denoted by enum wd_digest_mode
 * @buff_type: data buff type, denoted by enum wd_buff_type
 */
struct wd_digest_sess_setup {
	enum wd_digest_type alg;
	enum wd_digest_mode mode;
	enum wd_buff_type buff_type;
};

typedef void *wd_alg_digest_cb_t(void *cb_param);
struct wd_alg_digest;

struct wd_digest_sess {
	char			*alg_name;
	char			node_path[MAX_DEV_NAME_LEN + 1];
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_digest	*drv;
	__u32			mode;
	void			*priv;
};

/**
 * struct wd_digest_arg - Parameters for per digest operation
 * @in: input data address
 * @out: output data address
 * @in_bytes: input data size
 * @out_bytes: output data size
 * @has_next: is there next data block
 * @cb: callback function for async mode
 * @priv: private information for data extension
 *
 * fix me: for hmac, seems we need *key also?
 */
struct wd_digest_arg {
	void *in;
	void *out;
	__u32 in_bytes;
	__u32 out_bytes;
	int has_next;
	wd_alg_digest_cb_t *cb;
	void *priv;
};

/**
 * wd_alg_digest_alloc_sess() - Create a digest session.
 * @setup: Hold the parameters which are used to allocate a digest session
 * @dev_mask: Specify the hardware device in which to allocate digest session
 *
 * Return handler of allocated session. Return 0 if failing.
 */
extern handle_t wd_alg_digest_alloc_sess(struct wd_digest_sess_setup *setup,
					 wd_dev_mask_t *dev_mask);

/**
 * wd_alg_digest_free_sess() - Free digest session.
 * @handle_t: session handler which will be free
 */
extern void wd_alg_digest_free_sess(handle_t handle);

/**
 * wd_alg_do_digest() - Do sync/asynchronous digest task.
 * @handle_t: Session handler
 * @arg: Operation parameters. If arg->cb is NULL, it is sync digest, otherwise,
 *       it is async digest.
 */
extern int wd_alg_do_digest(handle_t handle, struct wd_digest_arg *arg);

/**
 * wd_alg_set_digest_key() - Set auth key to digest session.
 * @handle_t: Session handler
 * @key: Auth key addr
 * @key_len: Auth key length
 */
extern int wd_alg_set_digest_key(handle_t handle, __u8 *key, __u32 key_len);

/**
 * wd_alg_digest_poll() - Poll operation for asynchronous operation.
 * @handle_t: session handler
 * @count: Count of polling, 0 means polling all finished tasks.
 */
extern int wd_alg_digest_poll(handle_t handle, __u32 count);

#endif /* __WD_DIGEST_H */
