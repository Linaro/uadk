/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"

struct hisi_comp_sess {
	handle_t		h_ctx;
};

int hisi_cipher_init(struct wd_cipher_sess *sess)
{
	return 0;
}

void hisi_cipher_exit(struct wd_cipher_sess *sess)
{
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
	return 0;
}

int hisi_cipher_encrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	return 0;
}

int hisi_cipher_decrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	return 0;
}

int hisi_cipher_poll(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	return 0;
}

int hisi_digest_init(struct wd_digest_sess *sess)
{
	return 0;
}

void hisi_digest_exit(struct wd_digest_sess *sess)
{
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
	return 0;
}

int hisi_digest_digest(struct wd_digest_sess *sess, struct wd_digest_arg *arg)
{
	return 0;
}

int hisi_digest_poll(struct wd_digest_sess *sess, struct wd_digest_arg *arg)
{
	return 0;
}
