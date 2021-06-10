/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_ECC_H
#define __WD_ECC_H

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>

#include "wd.h"
#include "wd_alg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wd_ecc_in;
struct wd_ecc_out;
struct wd_ecc_key;

typedef void (*wd_ecc_cb_t)(void *cb_param);
typedef int (*wd_rand)(char *out, size_t out_len, void *usr);
typedef int (*wd_hash)(const char *in, size_t in_len,
		       char *out, size_t out_len, void *usr);

struct wd_ecc_point {
	struct wd_dtb x; /* x affine coordinates */
	struct wd_dtb y; /* y affine coordinates */
};

/* ECC operational types */
enum wd_ecc_op_type {
	WD_EC_OP_INVALID, /* invalid ecc operation */
	WD_ECXDH_GEN_KEY, /* ECDH/X448/X25519 generate pubkey */
	WD_ECXDH_COMPUTE_KEY, /* ECDH/X448/X25519 compute share key */
	WD_ECDSA_SIGN, /* ECDSA sign */
	WD_ECDSA_VERIFY, /* ECDSA verify */
	WD_SM2_SIGN, /* SM2 sign */
	WD_SM2_VERIFY, /* SM2 verify */
	WD_SM2_ENCRYPT, /* SM2 encrypt */
	WD_SM2_DECRYPT, /* SM2 decrypt */
	WD_SM2_KG, /* SM2 key generate */
	WD_EC_OP_MAX
};

/* ECC operational types */
enum wd_ecc_curve_id {
	WD_SECP128R1 = 0x10, /* SECG 128 bit prime field */
	WD_SECP192K1 = 0x11, /* SECG 192 bit prime field */
	WD_SECP224R1 = 0x12, /* SECG 224 bit prime field */
	WD_SECP256K1 = 0x13, /* SECG 256 bit prime field */
	WD_BRAINPOOLP320R1 = 0x14, /* RFC5639 320 bit prime field */
	WD_BRAINPOOLP384R1 = 0x15, /* RFC5639 384 bit prime field */
	WD_SECP384R1 = 0x16, /* SECG 384 bit prime field */
	WD_SECP521R1 = 0x17, /* NIST/SECG 521 bit prime field */
};

/* ECC hash callback func types */
enum wd_ecc_hash_type {
	WD_HASH_SM3,
	WD_HASH_SHA1,
	WD_HASH_SHA224,
	WD_HASH_SHA256,
	WD_HASH_SHA384,
	WD_HASH_SHA512,
	WD_HASH_MD4,
	WD_HASH_MD5,
	WD_HASH_MAX
};

struct wd_ecc_curve {
	struct wd_dtb p; /* Prime field p */
	struct wd_dtb a; /* Elliptic curve equation a parameter */
	struct wd_dtb b; /* Elliptic curve equation b parameter */
	struct wd_ecc_point g; /* Elliptic curve G point */
	struct wd_dtb n; /* Elliptic curve order */
};

enum wd_ecc_curve_cfg_type {
	WD_CV_CFG_ID, /* set curve param by denote curve ID */
	WD_CV_CFG_PARAM /* set curve param by denote curve param */
};

struct wd_ecc_curve_cfg {
	__u32 type; /* denoted by enum wd_ecc_curve_cfg_type */
	union {
		enum wd_ecc_curve_id id; /* if WD_CV_CFG_ID */
		struct wd_ecc_curve *pparam; /* if WD_CV_CFG_PARAM */
	} cfg;
	__u8 resv[4]; /* reserve */
};

struct wd_rand_mt {
	wd_rand cb; /* rand callback */
	void *usr; /* user private param */
};

struct wd_hash_mt {
	wd_hash cb; /* rand callback */
	void *usr; /* user private param */
	__u8 type; /* hash type, denoted by enum wd_ecc_hash_type */
	__u8 rsv[3]; /* reserve */
};

/* ECC context setting up input parameters from user */
struct wd_ecc_sess_setup {
	/*
	 * Ec algorithm name,
	 * find "/sys/class/uacce/hisi_hpre-xx/algorithms"
	 */
	const char *alg;
	__u16 key_bits; /* ECC key bits */
	struct wd_ecc_curve_cfg cv; /* curve config denoted by user */
	struct wd_rand_mt rand; /* rand method from user */
	struct wd_hash_mt hash; /* hash method from user */
	__u8 mode; /* ecc sync or async mode, denoted by enum wd_ctx_mode */
};

struct wd_ecc_req {
	void *src; /* ecc operation input address */
	void *dst; /* ecc operation output address */
	__u32 src_bytes; /* ecc operation input bytes */
	__u32 dst_bytes; /* ecc operation output bytes */
	wd_ecc_cb_t cb;
	void *cb_param;
	int status; /* ecc operation status */
	__u8 data_fmt; /* data format denoted by enum wd_buff_type */
	__u8 op_type; /* ecc operation type */
};

/**
 * wd_ecc_get_key_bits() - Get key width.
 * @sess: Session handler.
 * Return key bit width, 0 otherwise.
 */
int wd_ecc_get_key_bits(handle_t sess);

/**
 * wd_ecc_get_ecc_key() - Get ecc key param handle.
 * @sess: Session handler.
 * Return key param handle, NULL otherwise.
 */
struct wd_ecc_key *wd_ecc_get_key(handle_t sess);

/**
 * wd_ecc_set_ecc_prikey() - Set ecc private key param.
 * @ecc_key: Ecc key param handle.
 * @prikey: Private key param.
 * Return 0, less than 0 otherwise.
 */
int wd_ecc_set_prikey(struct wd_ecc_key *ecc_key,
			     struct wd_dtb *prikey);


/**
 * wd_ecc_get_ecc_prikey() - Get ecc private key param.
 * @ecc_key: Ecc key param handle.
 * @prikey: Output private key param pointer.
 * Return 0, less than 0 otherwise.
 */
int wd_ecc_get_prikey(struct wd_ecc_key *ecc_key,
			     struct wd_dtb **prikey);

/**
 * wd_ecc_set_ecc_pubkey() - Set ecc public key param.
 * @ecc_key: Ecc key param handle.
 * @pubkey: Public key param.
 * Return 0, less than 0 otherwise.
 */
int wd_ecc_set_pubkey(struct wd_ecc_key *ecc_key,
			     struct wd_ecc_point *pubkey);

/**
 * wd_ecc_get_pubkey() - Get ecc public key param.
 * @ecc_key: Ecc key param handle.
 * @pubkey: Output public key param pointer.
 * Return 0, less than 0 otherwise.
 */
int wd_ecc_get_pubkey(struct wd_ecc_key *ecc_key,
			     struct wd_ecc_point **pubkey);

/**
 * wd_ecc_del_in() - Delete ecc input param handle.
 * @sess: Session handler.
 * @in: input param handle.
 */
void wd_ecc_del_in(handle_t sess, struct wd_ecc_in *in);

/**
 * wd_ecc_del_out() - Delete ecc output param handle.
 * @sess: Session handler.
 * @out: output param handle.
 */
void wd_ecc_del_out(handle_t sess,  struct wd_ecc_out *out);

/**
 * wd_ecc_get_prikey_params() - Get private key params.
 * @key: Ecc key param handle.
 * @p: curve param p pointer.
 * @a: curve param a pointer.
 * @b: curve param b pointer.
 * @n: curve param n pointer.
 * @g: curve param g pointer.
 * @d: private pointer.
 */
void wd_ecc_get_prikey_params(struct wd_ecc_key *key,
				     struct wd_dtb **p, struct wd_dtb **a,
				     struct wd_dtb **b, struct wd_dtb **n,
				     struct wd_ecc_point **g,
				     struct wd_dtb **d);

/**
 * wd_ecc_get_pubkey_params() - Get public key params.
 * @key: Ecc key param handle.
 * @p: curve param p pointer.
 * @a: curve param a pointer.
 * @b: curve param b pointer.
 * @n: curve param n pointer.
 * @g: curve param g pointer.
 * @pub: public key  pointer.
 */
void wd_ecc_get_pubkey_params(struct wd_ecc_key *key,
				     struct wd_dtb **p, struct wd_dtb **a,
				     struct wd_dtb **b, struct wd_dtb **n,
				     struct wd_ecc_point **g,
				     struct wd_ecc_point **pub);

/* APIs For ECXDH gen/comp */

/**
 * wd_ecxdh_new_in() - Create ECXDH input params handle in compute shared key.
 * @sess: Session handler.
 * @in: input param used for compute shared key.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_ecxdh_new_in(handle_t sess, struct wd_ecc_point *in);

/**
 * wd_ecxdh_new_out() - Create ECXDH output params handle.
 * @sess: Session handler.
 * Return output params handle, NULL otherwise.
 */
struct wd_ecc_out *wd_ecxdh_new_out(handle_t sess);

/**
 * wd_ecxdh_get_out_params() - Get ECXDH output params.
 * @out: Output param handle.
 * @pbk: ECXDH ouput param.
 */
void wd_ecxdh_get_out_params(struct wd_ecc_out *out, struct wd_ecc_point **pbk);


/* APIs For SM2 sign/verf/enc/dec/kg */

/**
 * wd_sm2_new_sign_in() - Create sm2 sign input params handle.
 * @sess: Session handler.
 * @e: sign input param digest or plaintext by is_dgst param.
 * @k: sign input param random.
 * @id: sign input param user identity ID.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_sm2_new_sign_in(handle_t sess,
					    struct wd_dtb *e,
					    struct wd_dtb *k,
					    struct wd_dtb *id,
					    __u8 is_dgst);

/**
 * wd_sm2_new_verf_in() - Create sm2 verification input params handle.
 * @sess: Session handler.
 * @e: verification input param digest or plaintext by is_dgst param.
 * @r: sign input param r.
 * @s: sign input param s.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_sm2_new_verf_in(handle_t sess,
					    struct wd_dtb *e,
					    struct wd_dtb *r,
					    struct wd_dtb *s,
					    struct wd_dtb *id,
					    __u8 is_dgst);

/**
 * wd_sm2_new_enc_in() - Create sm2 encrypt input params handle.
 * @sess: Session handler.
 * @k: encrypt input param random.
 * @plaintext: encrypt input param plaintext.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_sm2_new_enc_in(handle_t sess,
					   struct wd_dtb *k,
					   struct wd_dtb *plaintext);
/**
 * wd_sm2_new_dec_in() - Create sm2 decrypt input params handle.
 * @sess: Session handler.
 * @c1: decrypt input param C1.
 * @c2: decrypt input param C2.
 * @c3: decrypt input param C3.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_sm2_new_dec_in(handle_t sess,
					   struct wd_ecc_point *c1,
					   struct wd_dtb *c2,
					   struct wd_dtb *c3);

/**
 * wd_sm2_new_sign_out() - Create sm2 sign output params handle.
 * @sess: Session handler.
 * Return output params handle, NULL otherwise.
 */
struct wd_ecc_out *wd_sm2_new_sign_out(handle_t sess);

/**
 * wd_sm2_new_enc_out() - Create sm2 encrypt output params handle.
 * @sess: Session handler.
 * @plaintext_len: plaintext bytes.
 * Return output params handle, NULL otherwise.
 */
struct wd_ecc_out *wd_sm2_new_enc_out(handle_t sess,
					     __u32 plaintext_len);

/**
 * wd_sm2_new_dec_out() - Create sm2 decrypt output params handle.
 * @sess: Session handler.
 * @plaintext_len: plaintext bytes.
 * Return output params handle, NULL otherwise.
 */
struct wd_ecc_out *wd_sm2_new_dec_out(handle_t sess,
					     __u32 plaintext_len);

/**
 * wd_sm2_new_kg_out() - Create sm2 key generate output params handle.
 * @sess: Session handler.
 * Return output params handle.
 */
struct wd_ecc_out *wd_sm2_new_kg_out(handle_t sess);

/**
 * wd_sm2_get_sign_out_params() - Get sm2 sign output params.
 * @out: Output param handle.
 * @r: sm2 sign ouput param r.
 * @s: sm2 sign ouput param s.
 */
void wd_sm2_get_sign_out_params(struct wd_ecc_out *out,
				       struct wd_dtb **r,
				       struct wd_dtb **s);
/**
 * wd_sm2_get_kg_out_params() - Get sm2 key generate output params.
 * @out: output param handle.
 * @privkey: output private key.
 * @pubkey: output public key.
 */
void wd_sm2_get_kg_out_params(struct wd_ecc_out *out,
				     struct wd_dtb **privkey,
				     struct wd_ecc_point **pubkey);

/**
 * wd_sm2_get_enc_out_params() - Get sm2 encrypt output params.
 * @out: output param handle.
 * @c1: encrypt output C1.
 * @c2: encrypt output C2.
 * @c3: encrypt output C3.
 */
void wd_sm2_get_enc_out_params(struct wd_ecc_out *out,
				      struct wd_ecc_point **c1,
				      struct wd_dtb **c2,
				      struct wd_dtb **c3);

/**
 * wd_sm2_get_dec_out_params() - Get sm2 decrypt output params.
 * @out: output param handle.
 * @plaintext: decrypt output plaintext.
 */
void wd_sm2_get_dec_out_params(struct wd_ecc_out *out,
				      struct wd_dtb **plaintext);

/* APIs For ECDSA sign/verf */

/**
 * wd_ecdsa_new_sign_in() - Create ecdsa sign input params handle.
 * @sess: Session handler.
 * @dgst: sign input param digest.
 * @k: sign input param random.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_ecdsa_new_sign_in(handle_t sess,
				struct wd_dtb *dgst,
				struct wd_dtb *k);

/**
 * wd_ecdsa_new_verf_in() - Create ecdsa verification input params handle.
 * @sess: Session handler.
 * @dgst: verification input param digest.
 * @r: sign input param r.
 * @s: sign input param s.
 * Return input params handle, NULL otherwise.
 */
struct wd_ecc_in *wd_ecdsa_new_verf_in(handle_t sess,
				struct wd_dtb *dgst,
				struct wd_dtb *r,
				struct wd_dtb *s);

/**
 * wd_ecdsa_new_sign_out() - Create ecdsa sign output params handle.
 * @sess: Session handler.
 * Return output params handle, NULL otherwise.
 */
struct wd_ecc_out *wd_ecdsa_new_sign_out(handle_t sess);

/**
 * wd_ecdsa_get_sign_out_params() - Get ecdsa sign output params.
 * @out: Output param handle.
 * @r: sign ouput param r.
 * @s: sign ouput param s.
 */
void wd_ecdsa_get_sign_out_params(struct wd_ecc_out *out,
				struct wd_dtb **r,
				struct wd_dtb **s);

/**
 * wd_ecc_init() - Initialise ctx configuration and scheduler.
 * @ config:	    User defined ctx configuration.
 * @ sched:	    User defined scheduler.
 */
int wd_ecc_init(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_ecc_uninit() - Un-initialise ctx configuration and scheduler.
 */
void wd_ecc_uninit(void);


/**
 * wd_ecc_alloc_sess() - Allocate a wd ecc session.
 * @setup:	Parameters to setup this session.
 */
handle_t wd_ecc_alloc_sess(struct wd_ecc_sess_setup *setup);

/**
 * wd_ecc_free_sess() - Free  a wd ecc session.
 * @ sess: The sess to be freed.
 */
void wd_ecc_free_sess(handle_t sess);

/**
 * wd_ecc_poll() - Poll finished request.
 *
 * This function will call poll_policy function which is registered to wd ecc
 * by user.
 */
int wd_ecc_poll(__u32 expt, __u32 *count);

/**
 * wd_do_ecc() - Send a sync eccression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
int wd_do_ecc_sync(handle_t sess, struct wd_ecc_req *req);

/**
 * wd_do_ecc_async() - Send an async eccression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
int wd_do_ecc_async(handle_t sess, struct wd_ecc_req *req);


/**
 * wd_ecc_poll_ctx() - Poll a ctx.
 * @pos:	The ctx idx which will be polled.
 * @expt:	Max number of requests to poll. If 0, polled all finished
 *		requests in this ctx.
 * @count:	The number of polled requests.
 * Return:	0-succ others-fail.
 *
 * This is a help function which can be used by user's poll_policy function.
 * User defines polling policy in poll_policiy, when it needs to poll a
 * specific ctx, this function should be used.
 */
int wd_ecc_poll_ctx(__u32 idx, __u32 expt, __u32 *count);

#ifdef __cplusplus
}
#endif

#endif
