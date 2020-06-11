/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#include "hisi_sec.h"

/* should be removed to qm module */
struct hisi_qp_ctx_temp {
	handle_t h_ctx;
	void *sq_base;
	void *cq_base;
	int sqe_size;
	void *mmio_base;
	void *db_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	bool cqc_phase;
	void *req_cache[QM_Q_DEPTH];
	int is_sq_full;
	int (*db)(struct hisi_qp_ctx_temp *qp_ctx, __u8 cmd, __u16 index,
		  __u8 priority);
};

/* fix me: should be removed to qm module */
struct hisi_qp_ctx_temp *hisi_qm_alloc_qp_ctx_t(handle_t h_ctx)
{
	return NULL;
}

void hisi_qm_free_ctx_t(struct hisi_qp_ctx_temp *qp_ctx)
{
}

int hisi_qm_send_t(struct hisi_qp_ctx_temp *qp_ctx, void *req)
{
	return 0;
}

int hisi_qm_recv_t(struct hisi_qp_ctx_temp *qp_ctx, void **resp)
{
	return 0;
}
/* fix me end */

struct hisi_sec_sess {
	struct hisi_qp_ctx_temp qp_ctx;
	char *node_path;
	void *key;
	__u32 key_len;
};

int hisi_sec_init(struct hisi_sec_sess *sec_sess)
{
	/* wd_request_ctx */
	sec_sess->qp_ctx.h_ctx = wd_request_ctx(sec_sess->node_path);
	
	/* alloc_qp_ctx */
	hisi_qm_alloc_qp_ctx_t(sec_sess->qp_ctx.h_ctx);

	/* update qm private info: sqe_size, op_type */

	/* update sec private info: something maybe */

	wd_ctx_start(sec_sess->qp_ctx.h_ctx);

	return 0;
}

void hisi_sec_exit(struct hisi_sec_sess *sec_sess)
{
	/* wd_ctx_stop */

	/* free alloc_qp_ctx */

	/* wd_release_ctx */
}

int hisi_sec_set_key(struct hisi_sec_sess *sess, const __u8 *key, __u32 key_len)
{
	/* store key to sess */
	memcpy(sess->key, key, key_len);

	return 0;
}

/* should define a struct to pass aead, cipher to this function */
int hisi_sec_encrypt(struct hisi_sec_sess *sess, int a)
{
	return 0;
}

/* same as above */
int hisi_sec_decrypt(struct hisi_sec_sess *sess, int a)
{
	return 0;
}

int hisi_cipher_init(struct wd_cipher_sess *sess)
{
	struct hisi_sec_sess *sec_sess;
	int ret = 0;

	sec_sess = calloc(1, sizeof(*sec_sess));
	if (!sec_sess)
		return -ENOMEM;

	sess->priv = sec_sess;
	sec_sess->node_path = strdup(sess->node_path);

	/* fix me: how to do with this? */
	ret = hisi_sec_init(sec_sess);
	if (ret < 0) {
		free(sec_sess);
		sess->priv = NULL;
	}

	return ret;
}

void hisi_cipher_exit(struct wd_cipher_sess *sess)
{
	struct hisi_sec_sess *sec_sess = sess->priv;

	hisi_sec_exit(sess->priv);

	free(sec_sess->node_path);
	free(sec_sess);
}

int hisi_cipher_prep(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	return 0;
}

void hisi_cipher_fini(struct wd_cipher_sess *sess)
{
}

int hisi_cipher_set_key(struct wd_cipher_sess *sess, const __u8 *key, __u32 key_len)
{
	return hisi_sec_set_key(sess->priv, key, key_len);
}

int hisi_cipher_encrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	/* this function may be reused by aead, should change to proper inputs */
	return hisi_sec_encrypt(sess->priv, 0);
}

int hisi_cipher_decrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	/* this function may be reused by aead, should change to proper inputs */
	return hisi_sec_decrypt(sess->priv, 0);
}

int hisi_cipher_poll(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	return 0;
}

int hisi_digest_init(struct wd_digest_sess *sess)
{
	struct hisi_sec_sess *sec_sess;
	int ret = 0;

	sec_sess = calloc(1, sizeof(*sec_sess));
	if (!sec_sess)
		return -ENOMEM;

	sess->priv = sec_sess;
	sec_sess->node_path = strdup(sess->node_path);

	ret = hisi_sec_init(sec_sess);
	if (ret < 0) {
		free(sec_sess);
		sess->priv = NULL;
	}

	return ret;
}

void hisi_digest_exit(struct wd_digest_sess *sess)
{
	struct hisi_sec_sess *sec_sess = sess->priv;

	hisi_sec_exit(sess->priv);

	free(sec_sess->node_path);
	free(sec_sess);
}

int hisi_digest_prep(struct wd_digest_sess *sess, struct wd_digest_arg *arg)
{
	return 0;
}

void hisi_digest_fini(struct wd_digest_sess *sess)
{
}

int hisi_digest_set_key(struct wd_digest_sess *sess, const __u8 *key, __u32 key_len)
{
	return hisi_sec_set_key(sess->priv, key, key_len);
}

int hisi_digest_digest(struct wd_digest_sess *sess, struct wd_digest_arg *arg)
{
	return 0;
}

int hisi_digest_poll(struct wd_digest_sess *sess, struct wd_digest_arg *arg)
{
	return 0;
}
