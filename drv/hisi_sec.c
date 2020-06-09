/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"

#if 0
/* should be removed to qm module */
struct hisi_qp_ctx {
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
	int (*db)(struct hisi_qm_queue_info *q, __u8 cmd, __u16 index,
		  __u8 priority);
};

/* fix me: should be removed to qm module */
struct hisi_qp_ctx *hisi_qm_alloc_qp_ctx_t(handle_t h_ctx)
{
	return NULL;
}

void hisi_qm_free_ctx_t(struct hisi_qp_ctx *qp_ctx)
{
}

int hisi_qm_send_t(struct hisi_qp_ctx *qp_ctx, void *req)
{
	return 0;
}

int hisi_qm_recv_t(struct hisi_qp_ctx *qp_ctx, void **resp)
{
}
/* fix me end */
#endif

struct hisi_sec_sess {
	struct hisi_qp_ctx qp_ctx;
};

int hisi_sec_init(struct hisi_sec_sess *sec_sess)
{
	/* wd_request_ctx */
	
	/* alloc_qp_ctx */

	return 0;
}

void hisi_sec_exit(struct hisi_sec_sess *sec_sess)
{
}

int hisi_sec_set_key(struct hisi_sec_sess *sess, const __u8 *key, __u32 key_len);
int hisi_sec_encrypt(struct hisi_sec_sess *sess, int a);
int hisi_sec_decrypt(struct hisi_sec_sess *sess, int a);

int hisi_cipher_init(struct wd_cipher_sess *sess)
{
	struct hisi_sec_sess *sec_sess;
	int ret = 0;

	sec_sess = calloc(1, sizeof(*sec_sess));
	if (!sec_sess)
		return -ENOMEM;

	sess->priv = sec_sess;

	ret = hisi_sec_init(sec_sess);
	if (ret < 0) {
		free(sec_sess);
		sess->priv = NULL;
	}

	return ret;
}

void hisi_cipher_exit(struct wd_cipher_sess *sess)
{
	return hisi_sec_exit(sess->priv);
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

	ret = hisi_sec_init(sec_sess);
	if (ret < 0) {
		free(sec_sess);
		sess->priv = NULL;
	}

	return ret;
}

void hisi_digest_exit(struct wd_digest_sess *sess)
{
	return hisi_sec_exit(sess->priv);
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
