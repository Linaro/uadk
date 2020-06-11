/* SPDX-License-Identifier: Apache-2.0 */
#ifndef	__HISI_SEC_H
#define	__HISI_SEC_H

#include "hisi_qm_udrv.h"
#include "wd.h"
#include "wd_cipher.h"
#include "wd_digest.h"

enum C_ALG {
	C_ALG_DES  = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES  = 0x2,
	C_ALG_SM4  = 0x3,
};

extern int hisi_cipher_init(struct wd_cipher_sess *sess);
extern void hisi_cipher_exit(struct wd_cipher_sess *sess);
extern int hisi_cipher_prep(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg);
extern void hisi_cipher_fini(struct wd_cipher_sess *sess);
extern int hisi_cipher_set_key(struct wd_cipher_sess *sess, const __u8 *key, __u32 key_len);
extern int hisi_cipher_encrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg);
extern int hisi_cipher_decrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg);
extern int hisi_cipher_poll(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg);

extern int hisi_digest_init(struct wd_digest_sess *sess);
extern void hisi_digest_exit(struct wd_digest_sess *sess);
extern int hisi_digest_prep(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
extern void hisi_digest_fini(struct wd_digest_sess *sess);
extern int hisi_digest_set_key(struct wd_digest_sess *sess, const __u8 *key, __u32 key_len);
extern int hisi_digest_digest(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
extern int hisi_digest_poll(struct wd_digest_sess *sess, struct wd_digest_arg *arg);

#endif	/* __HISI_SEC_H */
