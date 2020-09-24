/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define DEBUG
//#define WITH_OPENSSL_DIR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <semaphore.h>
#include <getopt.h>
#include "hpre_test_sample.h"
#include "test_hisi_hpre.h"
#include "../../include/wd.h"
#include "../../include/wd_rsa.h"
#include "../../include/wd_dh.h"

#define HPRE_TST_PRT		printf
#define BN_ULONG		unsigned long
#define RSA_NO_PADDING		3
#define HPRE_TST_MAX_Q		1
#define HPRE_PADDING_SZ		16
#define TEST_MAX_THRD		128
#define MAX_TRY_TIMES		10000
#define LOG_INTVL_NUM		8
#define WD_RSA_CTX_MSG_NUM		64
#define WD_DH_CTX_MSG_NUM		64
#define DH_GENERATOR_2			2
#define DH_GENERATOR_5			5
#define TEST_CNT		10

typedef unsigned int u32;

pthread_mutex_t mute;

struct bignum_st {
	BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
					 * chunks. */
	int top;                    /* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;                   /* Size of the d array. */
	int neg;                    /* one if the number is negative */
	int flags;
};

typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;

/* stub structures */
struct rsa_st {
	int xxx;
};

struct dh_st {
	int xxx;
};

struct bn_gencb_st {
	int xxx;
};

struct test_hpre_pthread_dt {
	int cpu_id;
	enum alg_op_type op_type;
	const char *alg_name;
	int thread_num;
	float perf;
	struct timeval start_tval;
	u32 send_task_num;
	u32 recv_task_num;
};

struct ec_key_st {
	int xxx;
};

struct ec_point_st {
	int xxx;
};

struct ec_group_st {
	int xxx;
};

struct ec_method_st {
	int xxx;
};

struct ec_sig_st {
	int xxx;
};

/* stub definitions */
typedef struct rsa_st RSA;
typedef struct dh_st DH;
typedef struct bignum_st BIGNUM;
typedef struct bn_gencb_st BN_GENCB;

typedef struct ec_key_st EC_KEY;
typedef struct ec_point_st EC_POINT;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_method_st EC_METHOD;
typedef struct ec_sig_st ECDSA_SIG;

enum dh_check_index {
	DH_INVALID,
	DH_ALICE_PUBKEY,
	DH_BOB_PUBKEY,
	DH_ALICE_PRIVKEY
};

struct rsa_async_tag {
	handle_t sess;
	int thread_id;
	int cnt;
	struct test_hpre_pthread_dt *thread_info;
};

struct dh_user_tag_info {
	u32 op;
	int pid;
	int thread_id;
	void *test_ctx;
	void *thread_data;
};

struct async_test_openssl_param {
	RSA *rsa;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *e;
	BIGNUM *n;
	BIGNUM *d;
	BIGNUM *dp;
	BIGNUM *dq;
	BIGNUM *qinv;
	void *ssl_verify_result;
	void *ssl_sign_result;
	void *plantext;
	int size;
};

struct ecc_curve_tbl {
	const char *name;
	unsigned int nid;
	unsigned int curve_id;
};

struct hpre_test_config {
	__u32 key_bits;
	__u32 times;
	__u32 seconds;
	__u8 check;
	__u8 perf_test;
	__u8 soft_test;
	__u8 with_log;
	__u8 trd_num;
	__u64 core_mask[2];
	char alg_mode[10];
	char trd_mode[10];
	char op[10];
	char curve[20];
	char dev_path[PATH_STR_SIZE];
};

static struct hpre_test_config g_config = {
	.key_bits = 1024,
	.times = 100,
	.seconds = 0,
	.trd_num = 2,
	#ifdef WITH_OPENSSL_DIR	
	.check = 1,
	#else
	.check = 0,
	#endif
	.perf_test = 0,
	.with_log = 0,
	.soft_test = 0,
	.core_mask = {0, 0},
	.trd_mode = "sync",
	.op = "rsa-gen",
	.alg_mode = "com",
	.curve = "secp256k1",
	.dev_path = "/dev/hisi_hpre-0",
};

static volatile int asyn_thread_exit = 0;
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct test_hpre_pthread_dt test_thrds_data[TEST_MAX_THRD];
static struct async_test_openssl_param ssl_params;
struct wd_ctx_config g_ctx_cfg;

static bool is_exit(struct test_hpre_pthread_dt *pdata);

struct ecc_curve_tbl ecc_curve_tbls[] = {
#if 0 // will be added later ecc
	{"secp128R1", 706, WD_SECP128R1},
	{"secp192K1", 711, WD_SECP192K1},
	{"secp256K1", 714, WD_SECP256K1},
	{"brainpoolP320R1", 929, WD_BRAINPOOLP320R1},
	{"brainpoolP384R1", 931, WD_BRAINPOOLP384R1},
	{"secp521R1", 716, WD_SECP521R1},
	{"null", 0, 0},
#endif
};

enum dh_test_item {
	TEST_ITEM_INVALID,
	SW_GENERATE_KEY,
	SW_COMPUTE_KEY,
	HW_GENERATE_KEY,
	HW_COMPUTE_KEY,
};

struct hpre_dh_test_ctx_setup {
	void *x;
	void *p;
	void *g;
	void *except_pub_key;
	void *cp_pub_key;
	void *cp_share_key;
	u32 x_size;
	u32 p_size;
	u32 g_size;
	u32 cp_pub_key_size;
	u32 cp_share_key_size;
	u32 except_pub_key_size;
	u32 op_type;
	u32 generator;
	u32 key_bits;
	u32 key_from; //0 - Openssl  1 - Designed
	handle_t sess;
};

struct hpre_dh_sw_opdata {
	BIGNUM *except_pub_key;
	unsigned char *pub_key;
	u32 pub_key_size;
	unsigned char *share_key;
	u32 share_key_size;
};

struct hpre_dh_test_ctx {
	void *priv;
	void *req;
	unsigned char *cp_share_key;
	u32 cp_share_key_size;
	unsigned char *cp_pub_key;
	u32 cp_pub_key_size;
	u32 op;
	u32 key_size;
	void *pool;
};

struct hpre_rsa_test_key_in {
	void *e;
	void *p;
	void *q;
	u32 e_size;
	u32 p_size;
	u32 q_size;
	void *data[];
};

#define X25519_KEYLEN	32
#define X448_KEYLEN		56
#define ED448_KEYLEN         57
#define MAX_KEYLEN  ED448_KEYLEN

/* **************** x25519/x448 *******************/
#define NID_X25519              1034
#define NID_X448                1035
# define EVP_PKEY_X25519 NID_X25519
# define EVP_PKEY_X448 NID_X448

typedef struct {
	unsigned char pubkey[MAX_KEYLEN];
	unsigned char *privkey;
} ECX_KEY;

struct evp_pkey_ctx_st;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct evp_pkey_asn1_method_st {
	int pkey_id;
	int pkey_base_id;
	unsigned long pkey_flags;
};
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

struct engine_st {
};

typedef struct engine_st ENGINE;
//typedef _Atomic int CRYPTO_REF_COUNT;
typedef int CRYPTO_REF_COUNT;

struct evp_pkey_st {
	int type;
	int save_type;
	CRYPTO_REF_COUNT references;
	const EVP_PKEY_ASN1_METHOD *ameth;
	ENGINE *engine;
	ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
	union {
		void *ptr;
		# ifndef OPENSSL_NO_RSA
			struct rsa_st *rsa;     /* RSA */
		# endif
		# ifndef OPENSSL_NO_DSA
			struct dsa_st *dsa;     /* DSA */
		# endif
		# ifndef OPENSSL_NO_DH
			struct dh_st *dh;       /* DH */
		# endif
		# ifndef OPENSSL_NO_EC
			struct ec_key_st *ec;   /* ECC */
			ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
		# endif
	} pkey;
	int save_parameters;
	//   STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	//   CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

typedef struct evp_pkey_st EVP_PKEY;

struct evp_pkey_method_st;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;

struct evp_pkey_ctx_st {
	/* Method associated with this operation */
	const EVP_PKEY_METHOD *pmeth;
	/* Engine that implements this method or NULL if builtin */
	ENGINE *engine;
	/* Key: may be NULL */
	EVP_PKEY *pkey;
	/* Peer key for key agreement, may be NULL */
	EVP_PKEY *peerkey;
	/* Actual operation */
	int operation;
	/* Algorithm specific data */
	void *data;
	/* Application specific data */
	void *app_data;
	/* Keygen callback */
	//EVP_PKEY_gen_cb *pkey_gencb;
	/* implementation specific keygen data */
	int *keygen_info;
	int keygen_info_count;
} /* EVP_PKEY_CTX */ ;

struct evp_pkey_method_st {
	int pkey_id;
	int flags;
	int (*init) (EVP_PKEY_CTX *ctx);
	int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
	void (*cleanup) (EVP_PKEY_CTX *ctx);
	int (*paramgen_init) (EVP_PKEY_CTX *ctx);
	int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
	int (*keygen_init) (EVP_PKEY_CTX *ctx);
	int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
	int (*sign_init) (EVP_PKEY_CTX *ctx);
	int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen);
	int (*verify_init) (EVP_PKEY_CTX *ctx);
	int (*verify) (EVP_PKEY_CTX *ctx,
			const unsigned char *sig, size_t siglen,
			const unsigned char *tbs, size_t tbslen);
	int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
	int (*verify_recover) (EVP_PKEY_CTX *ctx,
				unsigned char *rout, size_t *routlen,
				const unsigned char *sig, size_t siglen);
	int (*signctx_init); // (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
	int (*signctx); /* (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
			EVP_MD_CTX *mctx); */
	int (*verifyctx_init); // (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
	int (*verifyctx); /* (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
			EVP_MD_CTX *mctx); */
	int (*encrypt_init) (EVP_PKEY_CTX *ctx);
	int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
			const unsigned char *in, size_t inlen);
	int (*decrypt_init) (EVP_PKEY_CTX *ctx);
	int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
			const unsigned char *in, size_t inlen);
	int (*derive_init) (EVP_PKEY_CTX *ctx);
	int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
	int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
	int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
	int (*digestsign);  /*(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen); */
	int (*digestverify); /* (EVP_MD_CTX *ctx, const unsigned char *sig,
				size_t siglen, const unsigned char *tbs,
				size_t tbslen); */
	int (*check) (EVP_PKEY *pkey);
	int (*public_check) (EVP_PKEY *pkey);
	int (*param_check) (EVP_PKEY *pkey);

    int (*digest_custom); // (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
} /* EVP_PKEY_METHOD */ ;

EVP_PKEY *EVP_PKEY_new(void);
EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);

int RAND_priv_bytes(unsigned char *buf, int num);
/* **************** x25519/x448 *******************/

/********************  ECC  *********************/
enum ecc_test_item {
	ECC_TEST_ITEM_INVALID,
	ECDH_SW_GENERATE,
	ECDH_SW_COMPUTE,
	ECDH_HW_GENERATE,
	ECDH_HW_COMPUTE,
	ECC_SW_SIGN,
	ECC_SW_VERF,
	ECC_HW_SIGN,
	ECC_HW_VERF,
	SM2_HW_ENC,
	SM2_HW_DEC,
	SM2_SW_ENC,
	SM2_SW_DEC,
	ECC_TEST_ITEM_MAX
};

struct ecc_test_ctx_setup {
	void *d; // prikey
	void *except_pub_key; // use in ecdh phase 2
	void *cp_pub_key; // use in ecdh phase 1
	void *cp_share_key; // use in ecdh phase 2
	void *degist; //ecdsa sign in
	void *kinv; //ecdsa sign in
	void *rp; //ecdsa sign in
	void *sign; // ecdsa sign out or verf in
	void *cp_sign; // use in ecdsa sign compare
	void *priv_key; // use in ecdsa sign
	void *pub_key; // use in ecdsa verf
	u32 d_size;
	u32 cp_pub_key_size;
	u32 cp_share_key_size;
	u32 except_pub_key_size;
	u32 degist_size;
	u32 kinv_size;
	u32 rp_size;
	u32 sign_size;
	u32 cp_sign_size;
	u32 priv_key_size;
	u32 pub_key_size;
	u32 op_type;
	u32 key_bits;
	u32 key_from; //0 - Openssl  1 - Designed
	u32 nid; //openssl ecc nid
	u32 curve_id; // WD ecc curve_id
	handle_t sess;
};

struct ecc_test_ctx {
	void *priv;
	void *priv1; // openssl key handle used in hpre sign and openssl verf
	void *req;
	unsigned char *cp_share_key;
	u32 cp_share_key_size;
	unsigned char *cp_pub_key;
	u32 cp_pub_key_size;
	u32 op;
	u32 key_size;
	void *pool;
	/* ecdsa sign*/
	unsigned char *cp_sign;
	u32 cp_sign_size;
	/* ecdsa verf*/
	u32 cp_verf_result;
	__u8 is_x25519_x448;
	struct ecc_test_ctx_setup setup;
};

struct ecdh_sw_opdata {
	EC_POINT *except_pub_key;
	unsigned char *pub_key;
	u32 pub_key_size;
	unsigned char *share_key;
	u32 share_key_size;

	/* ecdsa sign / verf */
	unsigned char *except_e;
	u32 except_e_size;
	BIGNUM *except_kinv;
	BIGNUM *except_rp;
	unsigned char *sign; // sign out or verf in
	u32 sign_size;

};

static __thread struct hpre_rsa_test_key_in *rsa_key_in = NULL;

void CRYPTO_free(void *ptr, const char *file, int line);

# define OPENSSL_free(addr) CRYPTO_free(addr, __FILE__, __LINE__)

/* OpenSSL RSA and BN APIs */
BIGNUM *BN_new(void);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
void BN_free(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
RSA *RSA_new(void);
void RSA_free(RSA *rsa);
int BN_set_word(BIGNUM *a, BN_ULONG w);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb);
void RSA_get0_key(const RSA *r,
				  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r,
						 const BIGNUM **dmp1, const BIGNUM **dmq1,
						 const BIGNUM **iqmp);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1,
						BIGNUM *iqmp);
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_public_encrypt(int flen, const unsigned char *from,
					   unsigned char *to, RSA *rsa, int padding);
int RSA_private_decrypt(int flen, const unsigned char *from,
						unsigned char *to, RSA *rsa, int padding);
DH *DH_new(void);
void DH_free(DH *r);
int DH_generate_parameters_ex(DH *dh, int prime_len, int generator,
							  BN_GENCB *cb);
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
				 const BIGNUM **g);
int DH_generate_key(DH *dh);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
				 const BIGNUM **priv_key);
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
void *_hpre_sys_test_thread(void *data);

EC_KEY *EC_KEY_new(void);
int EC_KEY_set_group(EC_KEY *key, EC_GROUP *group);
void EC_KEY_free(EC_KEY *key);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
int EC_KEY_generate_key(EC_KEY *key);
int ERR_load_CRYPTO_strings(void);
int ERR_load_SSL_strings(void);
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
int ecdh_compute_key(void *test_ctx, void *tag);
int ECDH_compute_key(void *out, size_t outlen, EC_POINT *pub_key,
                     EC_KEY *ecdh,
                     void *(*KDF) (void *in, size_t inlen,
                                   void *out, size_t *outlen));
EC_POINT *EC_GROUP_get0_generator(EC_GROUP *group);
int DHparams_print_fp(FILE *fp, DH *x);
int EC_KEY_set_private_key(EC_KEY *key, BIGNUM *priv_key);
EC_POINT *EC_POINT_bn2point(EC_GROUP *, BIGNUM *,
                            EC_POINT *, void *);
EC_POINT *EC_POINT_dup(EC_POINT *a, EC_GROUP *group);
EC_POINT *EC_KEY_get0_public_key(EC_KEY *key);
BIGNUM *EC_KEY_get0_private_key(EC_KEY *key);
int ECParameters_print_fp(FILE *fp, EC_KEY *x);
int EC_KEY_print_fp(FILE *fp, EC_KEY *x, int off);
int RSA_print_fp(FILE *fp, RSA *x, int off);
void EC_POINT_free(EC_POINT *point);
void EC_GROUP_free(EC_GROUP *group);
size_t EC_POINT_point2buf(EC_GROUP *group, EC_POINT *point,
                          __u32 form,
                          char **pbuf, void *ctx);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                                            const EC_POINT *p,
                                                            BIGNUM *x,
                                                            BIGNUM *y,
                                                            void *ctx);
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
               unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
                 const unsigned char *sig, int siglen, EC_KEY *eckey);
int RAND_priv_bytes(unsigned char *buf, int num);
int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
                  unsigned char *sig, unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
int ECDSA_sign_setup(EC_KEY *eckey, void *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
void ECDSA_SIG_free(ECDSA_SIG *sig);
ECDSA_SIG *ECDSA_SIG_new(void);
ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len,
                         EC_KEY *eckey);
const BIGNUM *ECDSA_SIG_get0_r(const ECDSA_SIG *sig);
const BIGNUM *ECDSA_SIG_get0_s(const ECDSA_SIG *sig);
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey);
int ECDSA_size(const EC_KEY *eckey);


#ifndef WITH_OPENSSL_DIR
BIGNUM *BN_new(void)
{
	return NULL;
}

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
	return 0;
}
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	void *buf;

	buf = malloc(len);
	if (!buf)
		return NULL;

	memcpy(buf, s, len);

	return buf;
}
void BN_free(BIGNUM *a)
{
	return;
}

BIGNUM *BN_dup(const BIGNUM *a)
{
	return NULL;
}

RSA *RSA_new(void)
{
	return NULL;
}

void RSA_free(RSA *rsa)
{
	return;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
	return 0;
}

int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
{
	return 0;
}

void RSA_get0_key(const RSA *r,
				  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	return;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
	return;
}

void RSA_get0_crt_params(const RSA *r,
						 const BIGNUM **dmp1, const BIGNUM **dmq1,
						 const BIGNUM **iqmp)
{
	return;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1,
						BIGNUM *iqmp)
{
	return 0;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	return 0;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
	return 0;
}

int RSA_public_encrypt(int flen, const unsigned char *from,
					   unsigned char *to, RSA *rsa, int padding)
{
	return 0;
}

int RSA_private_decrypt(int flen, const unsigned char *from,
						unsigned char *to, RSA *rsa, int padding)
{
	return 0;
}

int RSA_print_fp(FILE *fp, RSA *x, int off)
{
	return 0;
}

DH *DH_new(void)
{
	return NULL;
}

void DH_free(DH *r)
{
	return;
}

int DH_generate_parameters_ex(DH *dh, int prime_len, int generator,
							  BN_GENCB *cb)
{
	return 0;
}

void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
				 const BIGNUM **g)
{
	return;
}

int DH_generate_key(DH *dh)
{
	return 0;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
				 const BIGNUM **priv_key)
{
	return;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	return 0;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	return 0;
}

int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
	return 0;
}

EC_KEY *EC_KEY_new(void)
{
	return NULL;
}

int EC_KEY_set_group(EC_KEY *key, EC_GROUP *group)
{
	return 0;
}

void EC_KEY_free(EC_KEY *key)
{
	return;
}

EC_KEY *EC_KEY_new_by_curve_name(int nid)
{
	return NULL;
}

int EC_KEY_generate_key(EC_KEY *key)
{
	return 0;
}

int ERR_load_CRYPTO_strings(void)
{
	return 0;
}

int ERR_load_SSL_strings(void)
{
	return 0;
}

EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
{
	return NULL;
}

int ecdh_compute_key(void *test_ctx, void *tag)
{
	return 0;
}

int ECDH_compute_key(void *out, size_t outlen, EC_POINT *pub_key,
                     EC_KEY *ecdh,
                     void *(*KDF) (void *in, size_t inlen,
                                   void *out, size_t *outlen))
{
	return 0;
}

EC_POINT *EC_GROUP_get0_generator(EC_GROUP *group)
{
	return NULL;
}

int DHparams_print_fp(FILE *fp, DH *x)
{
	return 0;
}

int EC_KEY_set_private_key(EC_KEY *key, BIGNUM *priv_key)
{
	return 0;
}

EC_POINT *EC_POINT_bn2point(EC_GROUP *group, BIGNUM *bn,
                            EC_POINT *point, void *ff)
{
	return NULL;
}

EC_POINT *EC_POINT_dup(EC_POINT *a, EC_GROUP *group)
{
	return NULL;
}

EC_POINT *EC_KEY_get0_public_key(EC_KEY *key)
{
	return NULL;
}

BIGNUM *EC_KEY_get0_private_key(EC_KEY *key)
{
	return NULL;
}

int ECParameters_print_fp(FILE *fp, EC_KEY *x)
{
	return 0;
}

int EC_KEY_print_fp(FILE *fp, EC_KEY *x, int off)
{
	return 0;
}

void EC_POINT_free(EC_POINT *point)
{
	return;
}

void EC_GROUP_free(EC_GROUP *group)
{
	return;
}

size_t EC_POINT_point2buf(EC_GROUP *group, EC_POINT *point,
                          __u32 form,
                          char **pbuf, void *ctx)
{
	return 0;
}

int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                                            const EC_POINT *p,
                                                            BIGNUM *x,
                                                            BIGNUM *y,
                                                            void *ctx)
{
	return 0;
}

int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
               unsigned char *sig, unsigned int *siglen, EC_KEY *eckey)
{
	return 0;
}

int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
                 const unsigned char *sig, int siglen, EC_KEY *eckey)
{
	return 0;
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
	return 0;
}

int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
                  unsigned char *sig, unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey)
{
	return 0;
}

int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub)
{
	return 0;
}

int ECDSA_sign_setup(EC_KEY *eckey, void *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp)
{
	return 0;
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	return 0;
}

void ECDSA_SIG_free(ECDSA_SIG *sig)
{
	return;
}

ECDSA_SIG *ECDSA_SIG_new(void)
{
	return NULL;
}

ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len,
                         EC_KEY *eckey)
{
	return NULL;
}

const BIGNUM *ECDSA_SIG_get0_r(const ECDSA_SIG *sig)
{
	return NULL;
}

const BIGNUM *ECDSA_SIG_get0_s(const ECDSA_SIG *sig)
{
	return NULL;
}

int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey)
{
	return 0;
}

int ECDSA_size(const EC_KEY *eckey)
{
	return 0;
}

#endif



static void print_data(void *ptr, int size, const char *name)
{
	__u32 i = 0;
	__u8* p = ptr;

	printf("\n%s:start_addr=%p, size %d\n", name, ptr, size);
	for (i = 1; i <= size; i++) {
		printf("0x%02x ", p[i - 1]);
		if (i % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

#ifdef WITH_OPENSSL_DIR
static int crypto_bin_to_hpre_bin(char *dst, const char *src,
				int b_size, int d_size)
{
	int i = d_size - 1;
	int j = 0;

	if (!dst || !src || b_size <= 0 || d_size <= 0) {
		WD_ERR("crypto bin to hpre bin params err!\n");
		return -WD_EINVAL;
	}

	if (b_size < d_size) {
		WD_ERR("crypto bin to hpre bin param data is too long!\n");
		return  -WD_EINVAL;
	}

	if (b_size == d_size || (dst == src))
		return WD_SUCCESS;

	for (j = b_size - 1; j >= 0; j--, i--) {
		if (i >= 0)
			dst[j] = src[i];
		else
			dst[j] = 0;
	}

	return WD_SUCCESS;
}
#endif

static __u8 is_async_test(__u32 opType)
{
	if (opType == RSA_KEY_GEN || opType == RSA_PUB_EN || opType == RSA_PRV_DE ||
		opType == DH_GEN || opType == DH_COMPUTE ||
		opType == ECDSA_SIGN || opType == ECDSA_VERF ||
		opType == SM2_SIGN || opType == SM2_VERF ||
		opType == SM2_ENC || opType == SM2_DEC ||
		opType == ECDH_GEN || opType == ECDH_COMPUTE ||
		opType == X25519_GEN || opType == X25519_COMPUTE ||
		opType == X448_GEN || opType == X448_COMPUTE)
		return false;

	return true;
}

__u32 hpre_pick_next_ctx(handle_t sched_ctx,
				const void *req,
				const struct sched_key *key)
{
	static int last_ctx = 0;

	if (!strncmp(g_config.trd_mode, "async", 5))
		return 0;

	if (++last_ctx == g_ctx_cfg.ctx_num)
		last_ctx = 0;

	return last_ctx;
}

int rsa_poll_policy(handle_t h_sched_ctx, const struct wd_ctx_config *config,
		__u32 expect, __u32 *count)
{
	int ret;
	struct wd_ctx *ctxs;
	int i;

	while (1) {
		for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
			ctxs = &g_ctx_cfg.ctxs[i];
			if (ctxs->ctx_mode == CTX_MODE_ASYNC) {
				ret = wd_rsa_poll_ctx(i, 1, count);
				if (ret != -EAGAIN && ret < 0) {
					HPRE_TST_PRT("fail poll ctx %d!\n", i);	
					return ret;
				}
			}
		}

		break;
	}

	return 0;
}

int dh_poll_policy(handle_t h_sched_ctx, const struct wd_ctx_config *config,
		__u32 expect, __u32 *count)
{
	int ret;
	struct wd_ctx *ctxs;
	int i;

	while (1) {
		for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
			ctxs = &g_ctx_cfg.ctxs[i];
			if (ctxs->ctx_mode == CTX_MODE_ASYNC) {
				ret = wd_dh_poll_ctx(i, 1, count);
				if (ret != -EAGAIN && ret < 0) {
					HPRE_TST_PRT("fail poll ctx %d!\n", i);	
					return ret;
				}
			}
		}

		break;
	}

	return 0;
}

static __u32 get_alg_op_type(enum alg_op_type op_type)
{
	__u32 value = 0;

	switch (op_type) {
	case RSA_KEY_GEN:
	case RSA_ASYNC_GEN:
		value = WD_RSA_GENKEY;
		break;
	case RSA_PUB_EN:
	case RSA_ASYNC_EN:
		value = WD_RSA_VERIFY;
		break;
	case RSA_PRV_DE:
	case RSA_ASYNC_DE:
		value = WD_RSA_SIGN;
		break;
	default:
		break;
	}

	return value;
}

static struct uacce_dev_list *get_uacce_dev_by_alg(struct uacce_dev_list *list,
						   char *alg)
{
	while (list) {
		if (!strncmp(alg, list->dev->char_dev_path, strlen(alg)))
			break;
		else
			list = list->next;
	}

	return list;

}

static int init_hpre_global_config(__u32 op_type)
{
	struct uacce_dev_list *list = NULL;
	struct uacce_dev_list *uacce_node;
	struct wd_ctx *ctx_attr;
	struct wd_sched sched;
	int ctx_num = g_config.trd_num;
	int ret;
	int j;

#ifdef DEBUG
	HPRE_TST_PRT("%s req %d ctx!\n", g_config.dev_path, ctx_num);
#endif

	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE)
		list = wd_get_accel_list("rsa");
	else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE)
		list = wd_get_accel_list("dh");
	if (!list)
		return -ENODEV;

	uacce_node = get_uacce_dev_by_alg(list, g_config.dev_path);
	if (!uacce_node)
		return -ENODEV;

	ctx_attr = malloc(ctx_num * sizeof(struct wd_ctx));
	if (!ctx_attr) {
		HPRE_TST_PRT("malloc ctx_attr memory fail!\n");
		return -ENOMEM;
	}
	memset(ctx_attr, 0, ctx_num * sizeof(struct wd_ctx));

	for (j = 0; j < ctx_num; j++) {
		ctx_attr[j].ctx = wd_request_ctx(uacce_node->dev);
		if (!ctx_attr[j].ctx) {
			HPRE_TST_PRT("failed to request ctx!\n");
			return -1;
		}
		ctx_attr[j].ctx_mode = is_async_test(op_type);
		ctx_attr[j].op_type = get_alg_op_type(op_type);
	}

	g_ctx_cfg.ctx_num = ctx_num;
	g_ctx_cfg.ctxs = ctx_attr;
	sched.name = "hpre-sched-0";
	sched.pick_next_ctx = hpre_pick_next_ctx;
	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE) {
		sched.poll_policy = rsa_poll_policy;
		ret = wd_rsa_init(&g_ctx_cfg, &sched);
	} else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE) {
		sched.poll_policy = dh_poll_policy;
		ret = wd_dh_init(&g_ctx_cfg, &sched);
	}
	if (ret) {
		HPRE_TST_PRT("failed to init alg, ret %d!\n", ret);
		return -1;
	}

	wd_free_list_accels(list);

	return ret;

}

static void uninit_hpre_global_config(__u32 op_type)
{
	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE)
		wd_rsa_uninit();
	else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE)
		wd_dh_uninit();
}

static int init_opdata_param(struct wd_dh_req *req,
			     int key_size, enum dh_check_index step)
{
	unsigned char *ag_bin = NULL;

	memset(req, 0, sizeof(*req));
	if (step == DH_ALICE_PRIVKEY) {
		ag_bin = malloc(2 * key_size);
		if (!ag_bin)
			return -ENOMEM;
		memset(ag_bin, 0, 2 * key_size);
		req->pv = ag_bin;
	}

	req->x_p = malloc(2 * key_size);
	if (!req->x_p) {
		if (ag_bin)
			free(ag_bin);
		return -ENOMEM;
	}
	memset(req->x_p, 0, 2 * key_size);

	req->pri = malloc(2 * key_size);
	if (!req->pri) {
		if (ag_bin)
			free(ag_bin);
		free(req->x_p);
		return -ENOMEM;
	}
	memset(req->pri, 0, 2 * key_size);
	req->pri_bytes = 2 * key_size;

	return 0;
}


void hpre_dh_del_test_ctx(struct hpre_dh_test_ctx *test_ctx)
{
	if (!test_ctx)
		return;

	if (SW_GENERATE_KEY == test_ctx->op) {
		DH_free(test_ctx->priv);
	} else if (SW_COMPUTE_KEY == test_ctx->op) {
		struct hpre_dh_sw_opdata *req = test_ctx->req;

		free(req->except_pub_key);
		free(req->share_key);
		free(req);
		DH_free(test_ctx->priv);
	} else if (HW_GENERATE_KEY == test_ctx->op) {
		struct wd_dh_req *req = test_ctx->req;

		free(req->x_p);
		free(req->pri);
		free(req);
		free(test_ctx->cp_pub_key);
	} else if (HW_COMPUTE_KEY == test_ctx->op) {
		struct wd_dh_req *req = test_ctx->req;

		free(req->pv);
		free(req->x_p);
		free(req->pri);
		free(req);
		free(test_ctx->cp_share_key);
	} else {
		HPRE_TST_PRT("%s: no op %d\n", __func__, test_ctx->op);
	}

	free(test_ctx);
}

static struct hpre_dh_test_ctx *create_sw_gen_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	BIGNUM *p = NULL, *g = NULL, *x = NULL;
	struct hpre_dh_test_ctx *test_ctx;
	DH *dh = NULL;

	if (SW_GENERATE_KEY != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	dh = DH_new();
	if (!dh)
		return NULL;

	printf("dh %p\n", dh);

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		DH_free(dh);
		return NULL;
	}

	if (setup.key_from) {
		p = BN_bin2bn(setup.p, setup.p_size, NULL);
		g = BN_bin2bn(setup.g, setup.g_size, NULL);
		x = BN_bin2bn(setup.x, setup.x_size, NULL);
		DH_set0_pqg(dh, p, NULL, g);
		DH_set0_key(dh, NULL, x);
	} else {
		if (!DH_generate_parameters_ex(dh, setup.key_bits, setup.generator, NULL)) {
			HPRE_TST_PRT("DH_generate_parameters_ex fail!\n");
			DH_free(dh);
			free(test_ctx);
			return NULL;
		}
	}

	test_ctx->op = SW_GENERATE_KEY;
	test_ctx->priv = dh;
	test_ctx->key_size = setup.key_bits >> 3;

//#ifdef DEBUG
	DHparams_print_fp(stdout, dh);
//#endif

	return test_ctx;
}

static struct hpre_dh_test_ctx *create_sw_compute_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	struct hpre_dh_sw_opdata *req;
	struct hpre_dh_test_ctx *test_ctx;
	DH *dh = NULL;

	if (!setup.except_pub_key ||
		!setup.except_pub_key_size ||
		setup.op_type !=SW_COMPUTE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	dh = DH_new();
	if (!dh)
		return NULL;

	req = malloc(sizeof(struct hpre_dh_sw_opdata));
	if (!req) {
		DH_free(dh);
		return NULL;
	}
	memset(req, 0, sizeof(struct hpre_dh_sw_opdata));

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		DH_free(dh);
		free(req);
		return NULL;
	}
	memset(test_ctx, 0, sizeof(struct hpre_dh_test_ctx));

	req->share_key = malloc(setup.key_bits >> 3);
	if (!req->share_key) {
		DH_free(dh);
		free(req);
		free(test_ctx);
		return NULL;
	}

	if (setup.key_from) {
		BIGNUM *p = NULL, *g = NULL, *x = NULL;
		p = BN_bin2bn(setup.p, setup.p_size, NULL);
		g = BN_bin2bn(setup.g, setup.g_size, NULL);
		x = BN_bin2bn(setup.x, setup.x_size, NULL);
		DH_set0_pqg(dh, p, NULL, g);
		DH_set0_key(dh, NULL, x);

		req->except_pub_key = BN_bin2bn(setup.except_pub_key,
					setup.except_pub_key_size, NULL);

	} else {
		req->except_pub_key = BN_bin2bn(setup.except_pub_key,
			setup.except_pub_key_size, NULL);

		if (!DH_generate_parameters_ex(dh, setup.key_bits, setup.generator, NULL)) {
			HPRE_TST_PRT("DH_generate_parameters_ex fail!\n");
			goto exit_free;
		}

		if (!DH_generate_key(dh)) {
			HPRE_TST_PRT("Alice DH_generate_key fail!\n");
			goto exit_free;
		}
	}
#ifdef DEBUG
	//DHparams_print_fp(stdout, dh);
#endif
	test_ctx->op = SW_COMPUTE_KEY;
	test_ctx->priv = dh;
	test_ctx->req = req;
	test_ctx->key_size = setup.key_bits >> 3;

	return test_ctx;

exit_free:
	hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}

static struct hpre_dh_test_ctx *create_hw_gen_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	const BIGNUM *p = NULL, *g = NULL, *x = NULL;
	const BIGNUM *pub_key = NULL;
	struct wd_dh_req *req;
	struct hpre_dh_test_ctx *test_ctx;
	struct wd_dtb ctx_g;
	int ret;
	u32 key_size = setup.key_bits >> 3;
	DH *dh = NULL;

	if (setup.op_type != HW_GENERATE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_dh_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_dh_req));

	dh = DH_new();
	if (!dh) {
		free(req);
		return NULL;
	}

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		free(req);
		DH_free(dh);
		return NULL;
	}
	memset(test_ctx, 0, sizeof(struct hpre_dh_test_ctx));

	ctx_g.data = malloc(key_size);
	if (!ctx_g.data) {
		free(test_ctx);
		free(req);
		DH_free(dh);
		return NULL;
	}
	memset(ctx_g.data, 0, key_size);

	test_ctx->cp_pub_key = malloc(key_size);
	if (!test_ctx->cp_pub_key) {
		free(test_ctx);
		free(req);
		DH_free(dh);
		free(ctx_g.data);
		return NULL;
	}

	ret = init_opdata_param(req, key_size, DH_ALICE_PUBKEY);
	if (ret < 0) {
		HPRE_TST_PRT("init_opdata_param failed\n");
		free(test_ctx);
		free(req);
		DH_free(dh);
		free(ctx_g.data);
		return NULL;
	}

	if (setup.key_from) {
		if (!setup.x || !setup.x_size || !setup.p || !setup.cp_pub_key ||
			!setup.p_size || !setup.g || !setup.g_size || !setup.cp_pub_key_size) {
			HPRE_TST_PRT("%s: x/p/g parm err\n", __func__);
			goto exit_free;
		}

		memcpy(req->x_p, setup.x, setup.x_size);
		memcpy(req->x_p + key_size, setup.p, setup.p_size);
		memcpy(ctx_g.data, setup.g, setup.g_size);
		memcpy(test_ctx->cp_pub_key, setup.cp_pub_key, setup.cp_pub_key_size);
		req->pbytes = setup.p_size;
		req->xbytes = setup.x_size;
		ctx_g.dsize = setup.g_size;
		ctx_g.bsize = key_size;
		test_ctx->cp_pub_key_size = setup.cp_pub_key_size;
	} else {
		ret = DH_generate_parameters_ex(dh, setup.key_bits, setup.generator, NULL);
		if (!ret) {
			HPRE_TST_PRT("DH_generate_parameters_ex failed\n");
			goto exit_free;
		}

		if (!DH_generate_key(dh)) {
			HPRE_TST_PRT("DH_generate_key failed\n");
			goto exit_free;
		}

		DH_get0_pqg(dh, &p, NULL, &g);
		DH_get0_key(dh, &pub_key, &x);

		req->pbytes = BN_bn2bin(p, req->x_p + key_size);
		req->xbytes = BN_bn2bin(x, req->x_p);
		ctx_g.dsize = BN_bn2bin(g, (unsigned char*)ctx_g.data);
		ctx_g.bsize = key_size;
		test_ctx->cp_pub_key_size = BN_bn2bin(pub_key, test_ctx->cp_pub_key);
	}

#ifdef DEBUG
		print_data(ctx_g.data, ctx_g.dsize, "g");
		print_data(req->x_p, req->xbytes, "x");
		print_data(req->x_p + key_size, req->pbytes, "p");
		print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	req->op_type = WD_DH_PHASE1;
	test_ctx->req = req;
	test_ctx->op = setup.op_type;
	test_ctx->priv = (void *)setup.sess;
	test_ctx->key_size = key_size;

	ret = wd_dh_set_g((handle_t)test_ctx->priv, &ctx_g);
	if (ret) {
		HPRE_TST_PRT("wd_dh_set_g failed\n");
		goto exit_free;
	}


	DH_free(dh);
	free(ctx_g.data);

	return test_ctx;
exit_free:
	DH_free(dh);
	free(ctx_g.data);
	hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}

static struct hpre_dh_test_ctx *create_hw_compute_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	const BIGNUM *p = NULL, *g = NULL, *x = NULL;
	struct wd_dh_req *req;
	struct hpre_dh_test_ctx *test_ctx;
	int ret;
	u32 key_size = setup.key_bits >> 3;
	DH *dh = NULL;
	DH *b = NULL;

	if (setup.op_type !=HW_COMPUTE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_dh_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_dh_req));

	dh = DH_new();
	if (!dh) {
		free(req);
		return NULL;
	}

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		free(req);
		DH_free(dh);
		return NULL;
	}
	memset(test_ctx, 0, sizeof(struct hpre_dh_test_ctx));

	test_ctx->cp_share_key = malloc(key_size);
	if (!test_ctx->cp_share_key) {
		free(test_ctx);
		free(req);
		DH_free(dh);
		return NULL;
	}

	ret = init_opdata_param(req, key_size, DH_ALICE_PRIVKEY);
	if (ret < 0) {
		HPRE_TST_PRT("init_opdata_param failed\n");
		free(test_ctx);
		free(req);
		DH_free(dh);
		return NULL;
	}

	if (setup.key_from) {
		memcpy(req->x_p, setup.x, setup.x_size);
		memcpy(req->x_p + key_size, setup.p, setup.p_size);
		memcpy(req->pv, setup.except_pub_key, setup.except_pub_key_size);
		memcpy(test_ctx->cp_share_key, setup.cp_share_key, setup.cp_share_key_size);
		req->pbytes = setup.p_size;
		req->xbytes = setup.x_size;
		req->pvbytes = setup.except_pub_key_size;
		test_ctx->cp_share_key_size = setup.cp_share_key_size;
	} else {
		const BIGNUM *bp = NULL, *bg = NULL,
				*bpub_key = NULL, *bpriv_key = NULL;
		b = DH_new();

		ret = DH_generate_parameters_ex(dh, setup.key_bits, setup.generator, NULL);
		if (!ret) {
			HPRE_TST_PRT("DH_generate_parameters_ex fail!\n");
			goto exit_free;
		}

		if (!DH_generate_key(dh)) {
			HPRE_TST_PRT("Alice DH_generate_key fail!\n");
			goto exit_free;
		}

		DH_get0_pqg(dh, &p, NULL, &g);
		DH_get0_key(dh, NULL, &x);
		bp = BN_dup(p);
		bg = BN_dup(g);
		DH_set0_pqg(b, (BIGNUM *)bp, NULL, (BIGNUM *)bg);
		if (!DH_generate_key(b)) {
			HPRE_TST_PRT("a DH_generate_key fail!\n");
			ret = -1;
			goto exit_free;
		}
		DH_get0_key(b, &bpub_key, &bpriv_key);

		test_ctx->cp_share_key_size = DH_compute_key(test_ctx->cp_share_key, bpub_key, dh);
		if (!test_ctx->cp_share_key_size || test_ctx->cp_share_key_size == -1) {
			HPRE_TST_PRT("DH_compute_key fail!\n");
			goto exit_free;
		}

		req->pbytes = BN_bn2bin(p, req->x_p + key_size);
		req->xbytes = BN_bn2bin(x, req->x_p);
		req->pvbytes = setup.except_pub_key_size;
		req->pvbytes = BN_bn2bin(bpub_key, req->pv);
	}

	req->op_type = WD_DH_PHASE2;
	test_ctx->priv = (void *)setup.sess; //init ctx
	test_ctx->req = req;
	test_ctx->op = setup.op_type;
	test_ctx->key_size = key_size;

#ifdef DEBUG
	print_data(req->pv, req->pvbytes, "pv");
	print_data(req->x_p, req->xbytes, "x");
	print_data(req->x_p + key_size, req->pbytes, "p");
	print_data(test_ctx->cp_share_key, test_ctx->cp_share_key_size, "cp_share_key");
#endif

	DH_free(dh);
	if (b)
		DH_free(b);

	return test_ctx;
exit_free:
	DH_free(dh);
	if (b)
		DH_free(b);
	hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}


struct hpre_dh_test_ctx *hpre_dh_create_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	struct hpre_dh_test_ctx *test_ctx = NULL;

	switch (setup.op_type) {
		case SW_GENERATE_KEY:
		{
			test_ctx = create_sw_gen_key_test_ctx(setup);
		}
		break;
		case HW_GENERATE_KEY:
		{
			test_ctx = create_hw_gen_key_test_ctx(setup);
		}
		break;
		case SW_COMPUTE_KEY:
		{
			test_ctx = create_sw_compute_key_test_ctx(setup);
		}
		break;
		case HW_COMPUTE_KEY:
		{
			test_ctx = create_hw_compute_key_test_ctx(setup);
		}
		break;
		default:
		break;
	}

	return test_ctx;
}

int dh_generate_key(void *test_ctx, void *tag)
{
	struct hpre_dh_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == SW_GENERATE_KEY) {
		DH *dh = t_c->priv;

		if (!DH_generate_key(dh)) {
			HPRE_TST_PRT("DH_generate_key fail!\n");
			return -1;
		}

#ifdef DEBUG
		//DHparams_print_fp(stdout, dh);
#endif

	} else {
		struct wd_dh_req *req = t_c->req;
		handle_t sess = (handle_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_dh_async(sess, req);
		else
			ret = wd_do_dh_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_dh fail!\n");
			return -1;
		}
	}

	return 0;
}

int dh_compute_key(void *test_ctx, void *tag)
{
	struct hpre_dh_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == SW_COMPUTE_KEY) {
		struct hpre_dh_sw_opdata *req = t_c->req;
		DH *dh = t_c->priv;

		ret = DH_compute_key(req->share_key, req->except_pub_key, dh);
		if (ret <= 0) {
			HPRE_TST_PRT("DH_compute_key fail!\n");
			return -1;
		}
		req->share_key_size = ret;

#ifdef DEBUG
	//DHparams_print_fp(stdout, dh);
	//print_data(req->share_key, ret, "openssl share key");

#endif
	} else {
		struct wd_dh_req *req = t_c->req;
		handle_t sess = (uintptr_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_dh_async(sess, req);
		else
			ret = wd_do_dh_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_dh fail!\n");
			return -1;
		}
#ifdef DEBUG
		//print_data(req->pri, req->pri_bytes,"hpre share key");
#endif
	}

	return 0;
}

static bool is_exit(struct test_hpre_pthread_dt *pdata)
{
	struct timeval cur_tval;
	float time_used;

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - pdata->start_tval.tv_usec);

	if (g_config.seconds)
		return time_used >= g_config.seconds * 1000000;
	else if (g_config.times)
		return pdata->send_task_num >= g_config.times;

	return false;
}

static int dh_result_check(struct hpre_dh_test_ctx *test_ctx)
{
	struct wd_dh_req *req = test_ctx->req;
	unsigned char *cp_key;
	u32 cp_size;

	if (test_ctx->op == HW_GENERATE_KEY) {
		cp_key = test_ctx->cp_pub_key;
		cp_size = test_ctx->cp_pub_key_size;

	} else {
		cp_key = test_ctx->cp_share_key;
		cp_size = test_ctx->cp_share_key_size;
	}

	if (req->pri_bytes != cp_size || memcmp(cp_key, req->pri, cp_size)) {
		HPRE_TST_PRT("dh op %d mismatch!\n", test_ctx->op);

#ifdef DEBUG
	print_data(req->pri, req->pri_bytes, "hpre out");
	print_data(cp_key, cp_size, "openssl out");
#endif

		return -1;
	}

	return 0;

}

static bool is_allow_print(int cnt, enum alg_op_type opType, int thread_num)
{
	int intval_index = 0;
	unsigned int log_intval_adjust = 0;
	int log_intval[LOG_INTVL_NUM] = {0x1, 0xff, 0x3ff, 0x7ff, 0xfff, 0x1fff};

	if (!g_config.with_log || g_config.perf_test)
		return false;

	if (g_config.soft_test)
		return true;

	switch (opType) {
		case RSA_ASYNC_GEN:
		case RSA_ASYNC_EN:
		case RSA_ASYNC_DE:
		case DH_ASYNC_COMPUTE:
		case DH_ASYNC_GEN:
		case RSA_KEY_GEN:
		{
			intval_index = 0x04;
		}
		break;
		case ECDH_ASYNC_COMPUTE:
		case ECDH_ASYNC_GEN:
		case ECDSA_ASYNC_SIGN:
		case ECDSA_ASYNC_VERF:
		case ECDH_COMPUTE:
		case ECDH_GEN:
		{
			intval_index = 0x01;
		}
		break;
		case DH_COMPUTE:
		case DH_GEN:
		{
			intval_index = 0x00;
		}
		break;
		default:
		{
			intval_index = 0x01;
		}
		break;
	}

	if (!thread_num)
		return false;
	log_intval_adjust = log_intval[intval_index] * ((thread_num - 1) / 16 + 1);

	if (!(cnt % log_intval_adjust))
		return true;
	else
		return false;
}

static void _dh_perf_cb(void *req_t)
{
	struct wd_dh_req *req = req_t;
	struct dh_user_tag_info* pTag = (struct dh_user_tag_info*)req->cb_param;
	struct test_hpre_pthread_dt *thread_data = pTag->thread_data;

	thread_data->recv_task_num++;
	hpre_dh_del_test_ctx(pTag->test_ctx);
	free(pTag);
}

static void _dh_cb(void *req_t)
{
	struct wd_dh_req *req = req_t;
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)req->cb_param;
	struct timeval start_tval, end_tval;
	int pid, threadId;
	float time, speed;
	int ret;
	static int failTimes = 0;
	struct hpre_dh_test_ctx *test_ctx = pSwData->test_ctx;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;

	start_tval = thread_data->start_tval;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;

	if (req->status != WD_SUCCESS) {
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes fail!, status 0x%02x\n",
				 pid, threadId, thread_data->send_task_num, req->status);
		goto err;
	}

	if (g_config.check) {
		((struct wd_dh_req *)test_ctx->req)->pri_bytes = req->pri_bytes;
		ret = dh_result_check(test_ctx);
		if (ret) {
			failTimes++;
			HPRE_TST_PRT("TD-%d:dh %d result mismatching!\n",
				threadId, test_ctx->op);
		}
	}

	gettimeofday(&end_tval, NULL);
	if (is_allow_print(thread_data->send_task_num, DH_ASYNC_GEN, 1)) {
		time = (end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
					(end_tval.tv_usec - start_tval.tv_usec);
		speed = 1 / (time / thread_data->send_task_num) * 1000 * 1000;
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes,%f us, %0.3fps, fail %dtimes(all TD)\n",
				 pid, threadId, thread_data->send_task_num, time, speed, failTimes);
	}

err:
	if (is_allow_print(thread_data->send_task_num, DH_ASYNC_GEN, 1))
		HPRE_TST_PRT("thread %d do DH %dth time success!\n", threadId, thread_data->send_task_num);
	hpre_dh_del_test_ctx(test_ctx);
	if (pSwData)
		free(pSwData);
}


int dh_init_test_ctx_setup(struct hpre_dh_test_ctx_setup *setup)
{
	__u32 key_bits = g_config.key_bits;

	if (!setup)
		return -1;

	if (!strcmp(g_config.alg_mode, "g2"))
		setup->generator = DH_GENERATOR_2;
	else
		setup->generator = DH_GENERATOR_5;

	if (g_config.perf_test)
		setup->key_from = 1; //0 - Openssl  1 - Designed
	else
		setup->key_from = 0; //0 - Openssl  1 - Designed

	setup->key_bits = g_config.key_bits;

	if (key_bits == 768) {
		setup->x = dh_xa_768;
		setup->p = dh_p_768;
		setup->except_pub_key = dh_except_b_pubkey_768;
		setup->cp_pub_key = dh_except_a_pubkey_768;
		setup->cp_share_key = dh_share_key_768;
		setup->x_size = sizeof(dh_xa_768);
		setup->p_size = sizeof(dh_p_768);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_768);
		setup->cp_pub_key_size = sizeof(dh_except_a_pubkey_768);
		setup->cp_share_key_size = sizeof(dh_share_key_768);
	} else if (key_bits == 1024) {
		setup->x = dh_xa_1024;
		setup->p = dh_p_1024;
		setup->except_pub_key = dh_except_b_pubkey_1024;
		setup->cp_pub_key = dh_except_a_pubkey_1024;
		setup->cp_share_key = dh_share_key_1024;
		setup->x_size = sizeof(dh_xa_1024);
		setup->p_size = sizeof(dh_p_1024);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_1024);
		setup->cp_pub_key_size = sizeof(dh_except_a_pubkey_1024);
		setup->cp_share_key_size = sizeof(dh_share_key_1024);
	} else if (key_bits == 1536) {
		setup->x = dh_xa_1536;
		setup->p = dh_p_1536;
		setup->except_pub_key = dh_except_b_pubkey_1536;
		setup->cp_pub_key = dh_except_a_pubkey_1536;
		setup->cp_share_key = dh_share_key_1536;
		setup->x_size = sizeof(dh_xa_1536);
		setup->p_size = sizeof(dh_p_1536);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_1536);
		setup->cp_pub_key_size = sizeof(dh_except_a_pubkey_1536);
		setup->cp_share_key_size = sizeof(dh_share_key_1536);
	} else if (key_bits == 2048) {
		setup->x = dh_xa_2048;
		setup->p = dh_p_2048;
		setup->except_pub_key = dh_except_b_pubkey_2048;
		setup->cp_pub_key = dh_except_a_pubkey_2048;
		setup->cp_share_key = dh_share_key_2048;
		setup->x_size = sizeof(dh_xa_2048);
		setup->p_size = sizeof(dh_p_2048);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_2048);
		setup->cp_pub_key_size = sizeof(dh_except_a_pubkey_2048);
		setup->cp_share_key_size = sizeof(dh_share_key_2048);
	} else if (key_bits == 3072) {
		setup->x = dh_xa_3072;
		setup->p = dh_p_3072;
		setup->except_pub_key = dh_except_b_pubkey_3072;
		setup->cp_pub_key = dh_except_a_pubkey_3072;
		setup->cp_share_key = dh_share_key_3072;
		setup->x_size = sizeof(dh_xa_3072);
		setup->p_size = sizeof(dh_p_3072);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_3072);
		setup->cp_pub_key_size = sizeof(dh_except_a_pubkey_3072);
		setup->cp_share_key_size = sizeof(dh_share_key_3072);
	} else if (key_bits == 4096) {
		setup->x = dh_xa_4096;
		setup->p = dh_p_4096;
		setup->except_pub_key = dh_except_b_pubkey_4096;
		setup->cp_pub_key = dh_except_a_pubkey_4096;
		setup->cp_share_key = dh_share_key_4096;
		setup->x_size = sizeof(dh_xa_4096);
		setup->p_size = sizeof(dh_p_4096);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_4096);
		setup->cp_pub_key_size = sizeof(dh_except_a_pubkey_4096);
		setup->cp_share_key_size = sizeof(dh_share_key_4096);
	} else {
		HPRE_TST_PRT("not find this keybits %d\n", key_bits);
		return -1;
	}

	if (!strcmp(g_config.alg_mode, "g2")) {
		setup->g = dh_g_2;
	} else {
		setup->g = dh_g_5;
	}
	setup->g_size = 1;

	return 0;
}

static void *_hpre_dh_sys_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct dh_user_tag_info *pTag = NULL;
	struct hpre_dh_test_ctx *test_ctx;
	struct hpre_dh_test_ctx_setup setup;
	struct timeval cur_tval;
	enum alg_op_type opType;
	float time_used, speed = 0.0;
	int thread_num;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int ret, cpuid;
	handle_t sess = 0llu;
	struct wd_dh_sess_setup dh_setup;
	struct wd_dh_req *req;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	opType = pdata->op_type;
	thread_num = pdata->thread_num;

	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return NULL;
	}

	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	if (!g_config.soft_test) {
		memset(&dh_setup, 0, sizeof(dh_setup));
		dh_setup.key_bits = g_config.key_bits;
		if (!strcmp(g_config.alg_mode, "g2"))
			dh_setup.is_g2 = true;
		else
			dh_setup.is_g2 = false;

		sess = wd_dh_alloc_sess(&dh_setup);
		if (!sess) {
			HPRE_TST_PRT("wd_dh_alloc_ctx failed\n");
			return NULL;
		}
	}

	if (dh_init_test_ctx_setup(&setup)) {
		wd_dh_free_sess(sess);
		return NULL;
	}

	setup.sess = sess;

	if (opType == DH_ASYNC_GEN || opType == DH_GEN)
		setup.op_type = (g_config.soft_test) ? SW_GENERATE_KEY: HW_GENERATE_KEY;
	else
		setup.op_type = (g_config.soft_test) ? SW_COMPUTE_KEY: HW_COMPUTE_KEY;

new_test_again:
	test_ctx = hpre_dh_create_test_ctx(setup);
	if (!test_ctx) {
		HPRE_TST_PRT("hpre_dh_create_test_ctx failed\n");
		return NULL;
	}

	req = test_ctx->req;
	do {
		if (opType == DH_ASYNC_GEN ||
			opType == DH_ASYNC_COMPUTE) {

			pTag = malloc(sizeof(struct dh_user_tag_info));
			if (!pTag) {
				HPRE_TST_PRT("malloc pTag fail!\n");
				goto fail_release;
			}

			pTag->test_ctx = test_ctx;
			pTag->thread_data = pdata;
			pTag->pid = pid;
			pTag->thread_id = thread_id;
			if (g_config.perf_test)
				req->cb = _dh_perf_cb;
			else
				req->cb = _dh_cb;
			req->cb_param = pTag;
		}

		if (opType == DH_ASYNC_GEN || opType == DH_GEN) {
			if (dh_generate_key(test_ctx, pTag)) {
				goto fail_release;
			}
		} else {
			if (dh_compute_key(test_ctx, pTag)) {
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		if (opType == DH_GEN ||opType == DH_COMPUTE) {
			if (!g_config.perf_test && !g_config.soft_test) {
				if (dh_result_check(test_ctx))
					goto fail_release;

				if (is_allow_print(pdata->send_task_num, opType, thread_num)) {
					HPRE_TST_PRT("Proc-%d, %d-TD %s succ!\n",
						getpid(), (int)syscall(__NR_gettid), g_config.op);
				}

				hpre_dh_del_test_ctx(test_ctx);
				if (is_exit(pdata))
					return 0;
				goto new_test_again;
			}
		} else {
			if (is_exit(pdata))
				break;
			goto new_test_again;
		}

	}while(!is_exit(pdata));

	if (opType == DH_GEN || opType == DH_COMPUTE)
		pdata->recv_task_num = pdata->send_task_num;

	if (g_config.perf_test) {
		gettimeofday(&cur_tval, NULL);
		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds){
			speed = pdata->recv_task_num / time_used * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time_used;
		}
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
		pdata->perf = speed;
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num) {
		usleep(1000 * 1000);
		if (g_config.with_log)
			HPRE_TST_PRT("<< Proc-%d, %d-TD: total send %u: recv %u, wait recv finish...!\n",
				pid, thread_id, pdata->send_task_num, pdata->recv_task_num);			
	}

fail_release:
	if (opType == DH_ASYNC_GEN ||
		opType == DH_ASYNC_COMPUTE) {
		return NULL;
	}
	if (test_ctx->op == HW_COMPUTE_KEY || test_ctx->op == HW_GENERATE_KEY)
		wd_dh_free_sess((uintptr_t)test_ctx->priv);

	if (opType == DH_GEN || opType == DH_COMPUTE)
		hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}

static inline int _get_cpu_id(int thr, __u64 core_mask)
{
	__u64 i;
	int cnt = 0;


	for (i = 1; i < 64; i++) {
		if (core_mask & (0x1ull << i)) {
			if (thr == cnt)
				return i;
			cnt++;
		}
	}

	return 0;
}

static inline int _get_one_bits(__u64 val)
{
	int count = 0;

	while (val) {
		if (val % 2 == 1)
			count++;
		val = val / 2;
	}

	return count;
}

int hpre_test_write_to_file(__u8 *out, int size, char *out_file,
							int handle, int try_close)
{
	int fd = -1, bytes_write;

	if (!out || !size || !out_file) {
		HPRE_TST_PRT("para err while try to write file!\n");
		return -EINVAL;
	}

	if (handle < 0) {
		fd = open(out_file, O_WRONLY | O_CREAT,
				  S_IRUSR | S_IWUSR);
		if (fd < 0) {
			HPRE_TST_PRT("create %s file fail!\n", out_file);
			return fd;
		}
	} else
		fd = handle;

	bytes_write = write(fd, out, size);
	if (bytes_write < 0 || bytes_write < size) {
		if (try_close)
			close(fd);
		HPRE_TST_PRT("write data to %s file fail!\n", out_file);
		return -ENOMEM;
	}
	if (try_close)
		close(fd);

	/* to be fixed */
	return fd;
}

#ifndef WITH_OPENSSL_DIR
static int get_rsa_key_from_test_sample(handle_t sess, char *pubkey_file,
			char *privkey_file,
			char *crt_privkey_file, int is_file)
{
	int ret = -1, bits;
	const __u8 *p, *q, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	struct wd_dtb wd_e, wd_d, wd_n, wd_dq, wd_dp, wd_qinv, wd_q, wd_p;
	u32 key_size = g_config.key_bits >> 3;
	__u32 key_bits = g_config.key_bits;

	memset(&wd_e, 0, sizeof(wd_e));
	memset(&wd_d, 0, sizeof(wd_d));
	memset(&wd_n, 0, sizeof(wd_n));
	memset(&wd_dq, 0, sizeof(wd_dq));
	memset(&wd_dp, 0, sizeof(wd_dp));
	memset(&wd_qinv, 0, sizeof(wd_qinv));
	memset(&wd_q, 0, sizeof(wd_q));
	memset(&wd_p, 0, sizeof(wd_p));

	bits = wd_rsa_key_bits(sess);
	if (bits == 1024) {
		e = rsa_e_1024;
		p = rsa_p_1024;
		q = rsa_q_1024;
		dmp1 = rsa_dp_1024;
		dmq1 = rsa_dq_1024;
		iqmp = rsa_qinv_1024;
		d = rsa_d_1024;
		n = rsa_n_1024;
	} else if (bits == 2048) {
		e = rsa_e_2048;
		p = rsa_p_2048;
		q = rsa_q_2048;
		dmp1 = rsa_dp_2048;
		dmq1 = rsa_dq_2048;
		iqmp = rsa_qinv_2048;
		d = rsa_d_2048;
		n = rsa_n_2048;
	} else if (bits == 3072) {
		e = rsa_e_3072;
		p = rsa_p_3072;
		q = rsa_q_3072;
		dmp1 = rsa_dp_3072;
		dmq1 = rsa_dq_3072;
		iqmp = rsa_qinv_3072;
		d = rsa_d_3072;
		n = rsa_n_3072;
	} else if (bits == 4096) {
		e = rsa_e_4096;
		p = rsa_p_4096;
		q = rsa_q_4096;
		dmp1 = rsa_dp_4096;
		dmq1 = rsa_dq_4096;
		iqmp = rsa_qinv_4096;
		d = rsa_d_4096;
		n = rsa_n_4096;
	} else {
		HPRE_TST_PRT("invalid key bits = %d!\n", bits);
		return -1;
	}

	wd_e.bsize = key_size;
	wd_e.data = malloc(GEN_PARAMS_SZ(key_size));
	wd_n.bsize = wd_e.bsize;
	wd_n.data = wd_e.data + wd_e.bsize;

	memcpy(wd_e.data, e, key_size);
	wd_e.dsize = key_size;
	memcpy(wd_n.data, n, key_size);
	wd_n.dsize = key_size;
	if (wd_rsa_set_pubkey_params(sess, &wd_e, &wd_n))
	{
		HPRE_TST_PRT("set rsa pubkey failed %d!\n", ret);
		goto gen_fail;
	}
  
	if (pubkey_file && is_file) {
		ret = hpre_test_write_to_file((unsigned char *)wd_e.data, g_config.key_bits >> 2,
					  pubkey_file, -1, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("RSA public key was written to %s!\n",
					 privkey_file);
	}

	if (rsa_key_in) {
		memset(rsa_key_in->e, 0, key_size);
		memset(rsa_key_in->p, 0, key_size >> 1);
		memset(rsa_key_in->q, 0, key_size >> 1);
		memcpy(rsa_key_in->e, e, key_size);
		rsa_key_in->e_size = key_size;
		rsa_key_in->p_size = key_size / 2;
		rsa_key_in->q_size = key_size / 2;
		memcpy(rsa_key_in->p, p, key_size / 2);
		memcpy(rsa_key_in->q, q, key_size / 2);
	}

	if (wd_rsa_is_crt(sess)) {
		wd_dq.bsize = CRT_PARAM_SZ(key_size);
		wd_dq.data = malloc(CRT_PARAMS_SZ(key_size));
		wd_dp.bsize = CRT_PARAM_SZ(key_size);
		wd_dp.data = wd_dq.data + wd_dq.bsize;
		wd_q.bsize = CRT_PARAM_SZ(key_size);
		wd_q.data = wd_dp.data + wd_dp.bsize;
		wd_p.bsize = CRT_PARAM_SZ(key_size);
		wd_p.data = wd_q.data + wd_q.bsize;
		wd_qinv.bsize = CRT_PARAM_SZ(key_size);
		wd_qinv.data = wd_p.data + wd_p.bsize;

		/* CRT mode private key */
		wd_dq.dsize = key_size / 2;
		memcpy(wd_dq.data, dmq1, key_size / 2);

		wd_dp.dsize = key_size / 2;
		memcpy(wd_dp.data, dmp1, key_size / 2);

		wd_q.dsize = key_size / 2;
		memcpy(wd_q.data, q, key_size / 2);

		wd_p.dsize = key_size / 2;
		memcpy(wd_p.data, p, key_size / 2);

		wd_qinv.dsize = key_size / 2;
		memcpy(wd_qinv.data, iqmp, key_size / 2);

		if (wd_rsa_set_crt_prikey_params(sess, &wd_dq,
					&wd_dp, &wd_qinv,
					&wd_q, &wd_p))
		{
			HPRE_TST_PRT("set rsa crt prikey failed %d!\n", ret);
			goto gen_fail;
		}


		if (crt_privkey_file && is_file) {
			ret = hpre_test_write_to_file((unsigned char *)wd_dq.data,
						  (key_bits >> 4) * 5, crt_privkey_file, -1, 0);
			if (ret < 0)
				goto gen_fail;
			ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
						  (key_bits >> 2), crt_privkey_file, ret, 1);
			if (ret < 0)
				goto gen_fail;
			HPRE_TST_PRT("RSA CRT private key was written to %s!\n",
						 crt_privkey_file);
		} else if (crt_privkey_file && !is_file) {
			memcpy(crt_privkey_file, wd_dq.data, (key_bits >> 4) * 5);
			memcpy(crt_privkey_file + (key_bits >> 4) * 5,
				   wd_e.data, (key_bits >> 2));
		}

	} else {
			//wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
			wd_d.bsize = key_size;
			wd_d.data = malloc(GEN_PARAMS_SZ(key_size));
			wd_n.bsize = key_size;
			wd_n.data = wd_d.data + wd_d.bsize;

			/* common mode private key */
			wd_d.dsize = key_size;
			memcpy(wd_d.data, d, key_size);
			wd_n.dsize = key_size;
			memcpy(wd_n.data, n, key_size);

			if (wd_rsa_set_prikey_params(sess, &wd_d, &wd_n))
			{
				HPRE_TST_PRT("set rsa prikey failed %d!\n", ret);
				goto gen_fail;
			}


			if (privkey_file && is_file) {
				ret = hpre_test_write_to_file((unsigned char *)wd_d.data,
							  (key_size),
							  privkey_file, -1, 0);
				if (ret < 0)
					goto gen_fail;
				ret = hpre_test_write_to_file((unsigned char *)wd_n.data,
							  (key_size),
							  privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;

				ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
							  (key_size), privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;
				HPRE_TST_PRT("RSA common private key was written to %s!\n",
							 privkey_file);
			} else if (privkey_file && !is_file) {
				memcpy(privkey_file, wd_d.data, key_size);
				memcpy(privkey_file + key_size, wd_n.data, key_size);
				memcpy(privkey_file + 2 * key_size, wd_e.data, key_size);
                                memcpy(privkey_file + 3 * key_size, wd_n.data, key_size);
			}
	}

	if (wd_e.data)
		free(wd_e.data);

	if (wd_rsa_is_crt(sess)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

	return 0;
gen_fail:

	if (wd_e.data)
		free(wd_e.data);

	if (wd_rsa_is_crt(sess)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

	return ret;
}

#else

static int test_rsa_key_gen(handle_t sess, char *pubkey_file,
			char *privkey_file,
			char *crt_privkey_file, int is_file)
{
	int ret, bits;
	RSA *test_rsa;
	BIGNUM *p, *q, *e_value, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	//struct wd_dtb *wd_e, *wd_d, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	struct wd_dtb wd_e, wd_d, wd_n, wd_dq, wd_dp, wd_qinv, wd_q, wd_p;
	//struct wd_rsa_pubkey *pubkey;
	//struct wd_rsa_prikey *prikey;
	u32 key_size = g_config.key_bits >> 3;
	u32 key_bits = g_config.key_bits;
        char *tmp;

	memset(&wd_e, 0, sizeof(wd_e));
	memset(&wd_d, 0, sizeof(wd_d));
	memset(&wd_n, 0, sizeof(wd_n));
	memset(&wd_dq, 0, sizeof(wd_dq));
	memset(&wd_dp, 0, sizeof(wd_dp));
	memset(&wd_qinv, 0, sizeof(wd_qinv));
	memset(&wd_q, 0, sizeof(wd_q));
	memset(&wd_p, 0, sizeof(wd_p));

	bits = wd_rsa_key_bits(sess);
	test_rsa = RSA_new();
	if (!test_rsa || !bits) {
		HPRE_TST_PRT("RSA new fail!\n");
		return -ENOMEM;
	}
	e_value = BN_new();
	if (!e_value) {
		RSA_free(test_rsa);
		HPRE_TST_PRT("BN new e fail!\n");
		ret = -ENOMEM;
		return ret;
	}
	ret = BN_set_word(e_value, 65537);
	if (ret != 1) {
		HPRE_TST_PRT("BN_set_word fail!\n");
		ret = -1;
		goto gen_fail;
	}

	ret = RSA_generate_key_ex(test_rsa, g_config.key_bits, e_value, NULL);
	if (ret != 1) {
		HPRE_TST_PRT("RSA_generate_key_ex fail!\n");
		ret = -1;
		goto gen_fail;
	}
	RSA_get0_key((const RSA *)test_rsa, (const BIGNUM **)&n,
			 (const BIGNUM **)&e, (const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)test_rsa, (const BIGNUM **)&p,
			 (const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)test_rsa, (const BIGNUM **)&dmp1,
			(const BIGNUM **)&dmq1, (const BIGNUM **)&iqmp);

	wd_e.bsize = key_size;
	wd_e.data = malloc(GEN_PARAMS_SZ(key_size));
	wd_n.bsize = wd_e.bsize;
	wd_n.data = wd_e.data + wd_e.bsize;

	wd_e.dsize = BN_bn2bin(e, (unsigned char *)wd_e.data);
	if (wd_e.dsize > wd_e.bsize) {
		HPRE_TST_PRT("e bn to bin overflow!\n");
		goto gen_fail;
	}
	wd_n.dsize = BN_bn2bin(n, (unsigned char *)wd_n.data);
	if (wd_n.dsize > wd_n.bsize) {
		HPRE_TST_PRT("n bn to bin overflow!\n");
		goto gen_fail;
	}

	if (wd_rsa_set_pubkey_params(sess, &wd_e, &wd_n))
	{
		HPRE_TST_PRT("set rsa pubkey failed %d!\n", ret);
		goto gen_fail;
	}

        tmp = malloc(key_size);
        if (!tmp) {
        	HPRE_TST_PRT("failed to malloc!\n");
        	goto gen_fail;
        }
        
        memcpy(tmp, wd_e.data, wd_e.dsize);
        crypto_bin_to_hpre_bin(wd_e.data, tmp, wd_e.bsize, wd_e.dsize);
        memcpy(tmp, wd_n.data, wd_n.dsize);
        crypto_bin_to_hpre_bin(wd_n.data, tmp, wd_n.bsize, wd_n.dsize);
        wd_e.dsize = key_size;
        wd_n.dsize = key_size;

	if (pubkey_file && is_file) {
		ret = hpre_test_write_to_file((unsigned char *)wd_e.data, key_bits >> 2,
					  pubkey_file, -1, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("RSA public key was written to %s!\n",
					 privkey_file);
	}

	if (rsa_key_in) {
		memset(rsa_key_in->e, 0, key_size);
		memset(rsa_key_in->p, 0, key_size >> 1);
		memset(rsa_key_in->q, 0, key_size >> 1);
		rsa_key_in->e_size = BN_bn2bin(e, (unsigned char *)rsa_key_in->e);
		rsa_key_in->p_size = BN_bn2bin(p, (unsigned char *)rsa_key_in->p);
		rsa_key_in->q_size = BN_bn2bin(q, (unsigned char *)rsa_key_in->q);
	}

	//wd_rsa_get_prikey(ctx, &prikey);
	if (wd_rsa_is_crt(sess)) {
		//wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
		wd_dq.bsize = CRT_PARAM_SZ(key_size);
		wd_dq.data = malloc(CRT_PARAMS_SZ(key_size));
		wd_dp.bsize = CRT_PARAM_SZ(key_size);
		wd_dp.data = wd_dq.data + wd_dq.bsize;
		wd_q.bsize = CRT_PARAM_SZ(key_size);
		wd_q.data = wd_dp.data + wd_dp.bsize;
		wd_p.bsize = CRT_PARAM_SZ(key_size);
		wd_p.data = wd_q.data + wd_q.bsize;
		wd_qinv.bsize = CRT_PARAM_SZ(key_size);
		wd_qinv.data = wd_p.data + wd_p.bsize;

		/* CRT mode private key */
		wd_dq.dsize = BN_bn2bin(dmq1, (unsigned char *)wd_dq.data);
		if (wd_dq.dsize > wd_dq.bsize) {
			HPRE_TST_PRT("dq bn to bin overflow!\n");
			goto gen_fail;
		}

		wd_dp.dsize = BN_bn2bin(dmp1, (unsigned char *)wd_dp.data);
		if (wd_dp.dsize > wd_dp.bsize) {
			HPRE_TST_PRT("dp bn to bin overflow!\n");
			goto gen_fail;
		}

		wd_q.dsize = BN_bn2bin(q, (unsigned char *)wd_q.data);
		if (wd_q.dsize > wd_q.bsize) {
			HPRE_TST_PRT("q bn to bin overflow!\n");
			goto gen_fail;
		}

		wd_p.dsize = BN_bn2bin(p, (unsigned char *)wd_p.data);
		if (wd_p.dsize > wd_p.bsize) {
			HPRE_TST_PRT("p bn to bin overflow!\n");
			goto gen_fail;
		}

		wd_qinv.dsize = BN_bn2bin(iqmp, (unsigned char *)wd_qinv.data);
		if (wd_qinv.dsize > wd_qinv.bsize) {
			HPRE_TST_PRT("qinv bn to bin overflow!\n");
			goto gen_fail;
		}

		if (wd_rsa_set_crt_prikey_params(sess, &wd_dq,
					&wd_dp, &wd_qinv,
					&wd_q, &wd_p))
		{
			HPRE_TST_PRT("set rsa crt prikey failed %d!\n", ret);
			goto gen_fail;
		}

                memcpy(tmp, wd_dq.data, wd_dq.dsize);
                crypto_bin_to_hpre_bin(wd_dq.data, tmp, wd_dq.bsize, wd_dq.dsize);
                memcpy(tmp, wd_dp.data, wd_dp.dsize);
                crypto_bin_to_hpre_bin(wd_dp.data, tmp, wd_dp.bsize, wd_dp.dsize);
                memcpy(tmp, wd_q.data, wd_q.dsize);
                crypto_bin_to_hpre_bin(wd_q.data, tmp, wd_q.bsize, wd_q.dsize);
                memcpy(tmp, wd_p.data, wd_p.dsize);
                crypto_bin_to_hpre_bin(wd_p.data, tmp, wd_p.bsize, wd_p.dsize);
                memcpy(tmp, wd_qinv.data, wd_qinv.dsize);
                crypto_bin_to_hpre_bin(wd_qinv.data, tmp, wd_qinv.bsize, wd_qinv.dsize);
                wd_dq.dsize = key_size / 2;
                wd_dp.dsize = key_size / 2;
                wd_q.dsize = key_size / 2;
                wd_p.dsize = key_size / 2;
                wd_qinv.dsize = key_size / 2;


		if (crt_privkey_file && is_file) {
			ret = hpre_test_write_to_file((unsigned char *)wd_dq.data,
						  (key_bits >> 4) * 5, crt_privkey_file, -1, 0);
			if (ret < 0)
				goto gen_fail;
			ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
						  (key_bits >> 2), crt_privkey_file, ret, 1);
			if (ret < 0)
				goto gen_fail;
			HPRE_TST_PRT("RSA CRT private key was written to %s!\n",
						 crt_privkey_file);
		} else if (crt_privkey_file && !is_file) {
			memcpy(crt_privkey_file, wd_dq.data, (key_bits >> 4) * 5);
			memcpy(crt_privkey_file + (key_bits >> 4) * 5,
				   wd_e.data, (key_bits >> 2));
		}

	} else {
		//wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
			wd_d.bsize = key_size;
			wd_d.data = malloc(GEN_PARAMS_SZ(key_size));
			wd_n.bsize =key_size;
			wd_n.data = wd_d.data + wd_d.bsize;

			/* common mode private key */
			wd_d.dsize = BN_bn2bin(d, (unsigned char *)wd_d.data);
			wd_n.dsize = BN_bn2bin(n, (unsigned char *)wd_n.data);

			if (wd_rsa_set_prikey_params(sess, &wd_d, &wd_n))
			{
				HPRE_TST_PRT("set rsa prikey failed %d!\n", ret);
				goto gen_fail;
			}

                        memcpy(tmp, wd_d.data, wd_d.dsize);
                        crypto_bin_to_hpre_bin(wd_d.data, tmp, wd_d.bsize, wd_d.dsize);
                        memcpy(tmp, wd_n.data, wd_n.dsize);
                        crypto_bin_to_hpre_bin(wd_n.data, tmp, wd_n.bsize, wd_n.dsize);
                        wd_d.dsize = key_size;
                        wd_n.dsize = key_size;


			if (privkey_file && is_file) {
				ret = hpre_test_write_to_file((unsigned char *)wd_d.data,
							  (key_size),
							  privkey_file, -1, 0);
				if (ret < 0)
					goto gen_fail;
				ret = hpre_test_write_to_file((unsigned char *)wd_n.data,
							  (key_size),
							  privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;

				ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
							  (key_size), privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;
				HPRE_TST_PRT("RSA common private key was written to %s!\n",
							 privkey_file);
			} else if (privkey_file && !is_file) {
				memcpy(privkey_file, wd_d.data, key_size);
				memcpy(privkey_file + key_size, wd_n.data, key_size);
				memcpy(privkey_file + 2 * key_size, wd_e.data, key_size);
                                memcpy(privkey_file + 3 * key_size, wd_n.data, key_size);
			}
	}

	RSA_free(test_rsa);
	BN_free(e_value);

	if (wd_e.data)
		free(wd_e.data);

	if (wd_rsa_is_crt(sess)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

        free(tmp);
	return 0;
gen_fail:
	RSA_free(test_rsa);
	BN_free(e_value);

	if (wd_e.data)
		free(wd_e.data);

	if (wd_rsa_is_crt(sess)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

	return ret;
}

#endif

int hpre_test_fill_keygen_opdata(handle_t sess, struct wd_rsa_req *req)
{
	struct wd_dtb *e, *p, *q;
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
	struct wd_dtb t_e, t_p, t_q;

	wd_rsa_get_pubkey(sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &e, NULL);
	wd_rsa_get_prikey(sess, &prikey);

	if (wd_rsa_is_crt(sess)) {
		wd_rsa_get_crt_prikey_params(prikey, NULL , NULL, NULL, &q, &p);
	} else {
		e = &t_e;
		p = &t_p;
		q = &t_q;
		e->data = rsa_key_in->e;
		e->dsize = rsa_key_in->e_size;
		p->data = rsa_key_in->p;
		p->dsize = rsa_key_in->p_size;
		q->data = rsa_key_in->q;
		q->dsize = rsa_key_in->q_size;
	}

	req->src = wd_rsa_new_kg_in(sess, e, p, q);
	if (!req->src) {
		HPRE_TST_PRT("create rsa kgen in fail!\n");
		return -ENOMEM;
	}
	req->dst = wd_rsa_new_kg_out(sess);
	if (!req->dst) {
		HPRE_TST_PRT("create rsa kgen out fail!\n");
		return -ENOMEM;
	}
	return 0;
}

static BIGNUM *hpre_bin_to_bn(void *bin, int raw_size)
{
	if (!bin || !raw_size)
		return NULL;

	return BN_bin2bn((const unsigned char *)bin, raw_size, NULL);
}

int hpre_test_result_check(handle_t sess,  struct wd_rsa_req *req, void *key)
{
	struct wd_rsa_kg_out *out = (void *)req->dst;
	struct wd_rsa_prikey *prikey;
	int ret, keybits, key_size;
	void *ssl_out;
	BIGNUM *nn;
	BIGNUM *e;
        RSA *rsa;


	rsa = RSA_new();
	if (!rsa) {
		HPRE_TST_PRT("%s:RSA new fail!\n", __func__);
		return -ENOMEM;
	}

	wd_rsa_get_prikey(sess, &prikey);
	keybits = wd_rsa_key_bits(sess);
	key_size = keybits >> 3;
	if (req->op_type == WD_RSA_GENKEY) {
		if (wd_rsa_is_crt(sess)) {
			struct wd_dtb qinv, dq, dp;
			struct wd_dtb *s_qinv, *s_dq, *s_dp;

			wd_rsa_get_crt_prikey_params(prikey, &s_dq, &s_dp,
							&s_qinv, NULL, NULL);
			wd_rsa_get_kg_out_crt_params(out, &qinv, &dq, &dp);

			if (memcmp(s_qinv->data, qinv.data, s_qinv->dsize)) {
				HPRE_TST_PRT("keygen  qinv  mismatch!\n");
				return -EINVAL;
			}
			if (memcmp(s_dq->data, dq.data, s_dq->dsize)) {
				HPRE_TST_PRT("keygen  dq mismatch!\n");
				return -EINVAL;
			}
			if (memcmp(s_dp->data, dp.data, s_dp->dsize)) {
				HPRE_TST_PRT("keygen  dp  mismatch!\n");
				return -EINVAL;
			}
		} else {
			struct wd_dtb d, n;
			struct wd_dtb *s_d, *s_n;

			wd_rsa_get_kg_out_params(out, &d, &n);

			wd_rsa_get_prikey_params(prikey, &s_d, &s_n);

			/* check D */
			if (memcmp(s_n->data, n.data, s_n->dsize)) {
				HPRE_TST_PRT("key generate N result mismatching!\n");
				return -EINVAL;
			}
			if (memcmp(s_d->data, d.data, s_d->dsize)) {
				HPRE_TST_PRT("key generate D result mismatching!\n");
				return -EINVAL;
			}
		}
	} else if (req->op_type == WD_RSA_VERIFY) {
		ssl_out = malloc(key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("malloc ssl out fail!\n");
			return -ENOMEM;
		}
		if (key) {
			nn = hpre_bin_to_bn(key + key_size,
					    key_size);
			if (!nn) {
				HPRE_TST_PRT("n bin2bn err!\n");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key, key_size);
			if (!e) {
				HPRE_TST_PRT("e bin2bn err!\n");
				return -EINVAL;
			}
			ret = RSA_set0_key(rsa, nn, e, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("e set0_key err!\n");
				return -EINVAL;
			}
		}
		ret = RSA_public_encrypt(req->src_bytes, req->src, ssl_out,
					 rsa, RSA_NO_PADDING);
		if (ret != (int)req->src_bytes) {
			HPRE_TST_PRT("openssl pub encrypto fail!ret=%d\n", ret);
			return -ENOMEM;
		}
		if (!g_config.soft_test && memcmp(ssl_out, req->dst, key_size)) {
			HPRE_TST_PRT("pub encrypto result  mismatch!\n");
                        print_data(ssl_out, req->src_bytes, "openssl out");
                        print_data(req->dst, req->dst_bytes, "hpre out");
                        RSA_print_fp(stdout, rsa, 4);
			return -EINVAL;
		}
		free(ssl_out);
	} else {

		ssl_out = malloc(key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("malloc ssl out fail!\n");
			return -ENOMEM;
		}

		if (key && wd_rsa_is_crt(sess)) {
			BIGNUM *dp, *dq, *iqmp, *p, *q;
			int size = key_size / 2;

			dq = hpre_bin_to_bn(key, size);
			if (!dq) {
				HPRE_TST_PRT("dq bin2bn err!\n");
				return -EINVAL;
			}
			dp = hpre_bin_to_bn(key + size, size);
			if (!dp) {
				HPRE_TST_PRT("dp bin2bn err!\n");
				return -EINVAL;
			}
			q = hpre_bin_to_bn(key + 2 * size, size);
			if (!q) {
				HPRE_TST_PRT("q bin2bn err!\n");
				return -EINVAL;
			}
			p = hpre_bin_to_bn(key + 3 * size, size);
			if (!p) {
				HPRE_TST_PRT("p bin2bn err!\n");
				return -EINVAL;
			}
			iqmp = hpre_bin_to_bn(key + 4 * size, size);
			if (!iqmp) {
				HPRE_TST_PRT("iqmp bin2bn err!\n");
				return -EINVAL;
			}
			ret = RSA_set0_crt_params(rsa, dp, dq, iqmp);
			if (ret <= 0) {
				HPRE_TST_PRT("set0_crt_params err!\n");
				return -EINVAL;
			}
			ret = RSA_set0_factors(rsa, p, q);
			if (ret <= 0) {
				HPRE_TST_PRT("set0_factors err!\n");
				return -EINVAL;
			}
			nn = hpre_bin_to_bn(key + 7 * size, key_size);
			if (!nn) {
				HPRE_TST_PRT("n bin2bn err!\n");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key + 5 * size, key_size);
			if (!e) {
				HPRE_TST_PRT("e bin2bn err!\n");
				return -EINVAL;
			}
			ret = RSA_set0_key(rsa, nn, e, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("rsa set0_key crt err!\n");
				return -EINVAL;
			}

		} else if (key && !wd_rsa_is_crt(sess)) {
			BIGNUM *d;

			nn = hpre_bin_to_bn(key + key_size, key_size);
			if (!nn) {
				HPRE_TST_PRT("n bin2bn err!\n");
				return -EINVAL;
			}
			d = hpre_bin_to_bn(key, key_size);
			if (!d) {
				HPRE_TST_PRT("d bin2bn err!\n");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key + 2 * key_size, key_size);
			if (!e) {
				HPRE_TST_PRT("e bin2bn err!\n");
				return -EINVAL;
			}
			ret = RSA_set0_key(rsa, nn, e, d);
			if (ret <= 0) {
				HPRE_TST_PRT("d set0_key err!\n");
				return -EINVAL;
			}
		}

		ret = RSA_private_decrypt(req->src_bytes, req->src, ssl_out,
					rsa, RSA_NO_PADDING);
		if (ret != (int)req->src_bytes) {
			HPRE_TST_PRT("openssl priv decrypto fail!ret=%d\n", ret);
			return -ENOMEM;
		}
#ifdef DEBUG
		print_data(req->dst, 16, "out");
		print_data(req->src, 16, "in");
		print_data(ssl_out, 16, "ssl_out");
#endif

		if (!g_config.soft_test && memcmp(ssl_out, req->dst, ret)) {
			HPRE_TST_PRT("prv decrypto result  mismatch!\n");
                        print_data(ssl_out, req->src_bytes, "openssl out");
                        print_data(req->dst, req->dst_bytes, "hpre out");
                        RSA_print_fp(stdout, rsa, 4);  
			return -EINVAL;
		}
		free(ssl_out);

	}

        RSA_free(rsa);

	return 0;
}

int hpre_sys_func_test(struct test_hpre_pthread_dt * pdata)
{
	int pid = getpid(), ret = 0, i = 0;
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	handle_t sess;
	void *key_info = NULL;
	struct timeval cur_tval;
	float time = 0.0, speed = 0.0;
	const char *alg_name = pdata->alg_name;
	int key_size = g_config.key_bits >> 3;
        char m[] = {0x54, 0x85, 0x9b, 0x34, 0x2c, 0x49, 0xea, 0x2a};

	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return -1;
	}

new_test_again:

	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = g_config.key_bits;
	if (!strcmp(g_config.alg_mode, "crt"))
		setup.is_crt = true;
	else
		setup.is_crt = false;

	sess = wd_rsa_alloc_sess(&setup);
	if (!sess) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			     pid, thread_id, alg_name);
		ret = -EINVAL;
		goto fail_release;
	}

	/* Just make sure memory size is enough */
	key_info = malloc(key_size * 16);
	if (!key_info) {
		HPRE_TST_PRT("thrd-%d:malloc key!\n", thread_id);
		goto fail_release;
	}

	rsa_key_in = malloc(2 * key_size + sizeof(struct hpre_rsa_test_key_in));
	if (!rsa_key_in) {
		HPRE_TST_PRT("thrd-%d:malloc err!\n", thread_id);
		goto fail_release;
	}

	rsa_key_in->e = rsa_key_in + 1;
	rsa_key_in->p = rsa_key_in->e + key_size;
	rsa_key_in->q = rsa_key_in->p + (key_size >> 1);

	memset(key_info, 0, key_size * 16);

	#ifdef WITH_OPENSSL_DIR
		ret = test_rsa_key_gen(sess, NULL, key_info, key_info, 0);
		if (ret) {
			HPRE_TST_PRT("thrd-%d:Openssl key gen fail!\n", thread_id);
			goto fail_release;
		}
	#else
		ret = get_rsa_key_from_test_sample(sess, NULL, key_info, key_info, 0);
		if (ret) {
			HPRE_TST_PRT("thrd-%d:get sample key fail!\n", thread_id);
			goto fail_release;
		}
	#endif

	/* always key size bytes input */
	req.src_bytes = key_size;
	if (pdata->op_type == RSA_KEY_GEN) {
		req.op_type = WD_RSA_GENKEY;
	} else if (pdata->op_type == RSA_PUB_EN) {
		req.op_type = WD_RSA_VERIFY;
	} else if (pdata->op_type == RSA_PRV_DE) {
		req.op_type = WD_RSA_SIGN;
	} else {
		HPRE_TST_PRT("thrd-%d:optype=%d err!\n",
			  thread_id, pdata->op_type);
		goto fail_release;
	}

	if (req.op_type == WD_RSA_GENKEY) {
		ret = hpre_test_fill_keygen_opdata(sess, &req);
		if (ret){
			HPRE_TST_PRT("fill key gen req fail!\n");
			goto fail_release;
		}
	} else {
		req.src = malloc(key_size);
		if (!req.src) {
			HPRE_TST_PRT("alloc in buffer fail!\n");
			goto fail_release;
		}
		memset(req.src, 0, req.src_bytes);
                memcpy(req.src + key_size - sizeof(m), m, sizeof(m));
		req.dst = malloc(key_size);
		if (!req.dst) {
			HPRE_TST_PRT("alloc out buffer fail!\n");
			goto fail_release;
		}
		req.dst_bytes = key_size;
	}

	do {
		if (!g_config.soft_test) {
			ret = wd_do_rsa_sync(sess, &req);
			if (ret || req.status) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth status=%d fail!\n",
					 pid, thread_id,
					 g_config.op, i, req.status);
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		i++;
		if (g_config.check) {
			void *check_key;

			if (req.op_type == WD_RSA_SIGN)
				check_key = key_info;
			if (req.op_type == WD_RSA_VERIFY)
				if (wd_rsa_is_crt(sess))
					check_key = key_info + 5 * (g_config.key_bits >> 4);
				else
					check_key = key_info + 2 * key_size;
			else
				check_key = key_info;
			ret = hpre_test_result_check(sess, &req, check_key);
			if (ret) {
				HPRE_TST_PRT("P-%d,T-%d:hpre %s %dth mismth\n",
						 pid, thread_id,
						 g_config.op, i);
				goto fail_release;
			}
			else {
				if (req.op_type == WD_RSA_GENKEY) {
					if (is_allow_print(i, WD_RSA_GENKEY,  pdata->thread_num))
						HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
				}
			}
		}

		/* clean output buffer remainings in the last time operation */
		if (req.op_type == WD_RSA_GENKEY) {
			char *data;
			int len;

			len = wd_rsa_kg_out_data((void *)req.dst, &data);
			if (len < 0) {
				HPRE_TST_PRT("wd rsa get key gen out data fail!\n");
				goto fail_release;
			}
			memset(data, 0, len);
		} else {
#ifdef DEBUG
			print_data(req.dst, 16, "out");
#endif
		}
		if (is_allow_print(i, pdata->op_type, pdata->thread_num)) {
			gettimeofday(&cur_tval, NULL);
			time = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
						   (cur_tval.tv_usec - pdata->start_tval.tv_usec));
			speed = 1 / (time / i) * 1000;
			HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes,%0.0fus, %0.3fkops\n",
					 pid, thread_id, g_config.op,
					 i, time, speed);
		}

		if (!g_config.perf_test && !g_config.soft_test) {
			if (req.op_type == WD_RSA_GENKEY) {
				if (req.src)
					wd_rsa_del_kg_in(sess, req.src);
				if (req.dst)
					wd_rsa_del_kg_out(sess, req.dst);
			} else {
				if (req.src)
					free(req.src);
				if (req.dst)
					free(req.dst);
			}

			if (sess)
				wd_rsa_free_sess(sess);

			if (rsa_key_in)
				free(rsa_key_in);

			if (key_info)
				free(key_info);

			if (is_exit(pdata))
				return 0;

			goto new_test_again;
		}
	}while(!is_exit(pdata));

	pdata->recv_task_num = pdata->send_task_num;

	if (g_config.perf_test) {
		gettimeofday(&cur_tval, NULL);
		time = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds) {
			speed = pdata->recv_task_num / time * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time;
		}
		pdata->perf = speed;
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
	}

fail_release:
	if (req.op_type == WD_RSA_GENKEY) {
		if (req.src)
			wd_rsa_del_kg_in(sess, req.src);
		if (req.dst)
			wd_rsa_del_kg_out(sess, req.dst);
	} else {
		if (req.src)
			free(req.src);
		if (req.dst)
			free(req.dst);
	}
	if (sess)
		wd_rsa_free_sess(sess);
	if (key_info)
		free(key_info);
	if (rsa_key_in)
		free(rsa_key_in);


	return ret;
}

void *_hpre_rsa_sys_test_thread(void *data)
{
	int ret, cpuid;
	struct test_hpre_pthread_dt *pdata = data;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
					 sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
				 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
				pid, thread_id, cpuid);
	}
	ret = hpre_sys_func_test(pdata);
	if (ret)
		return NULL;

	return NULL;
}

static int hpre_sys_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type,
			char *dev_path, unsigned int node_msk)
{
	int i, ret, cnt = 0;
	int h_cpuid;
	float speed = 0.0;

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 0; i < cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _hpre_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 0; i < thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _hpre_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);
	HPRE_TST_PRT("<< test finish!\n");
	
	return 0;
}

static void  *_rsa_async_poll_test_thread(void *data)
{
	__u32 count = 0;
	__u32 expt = 0;
	int ret = 0;

	while (1) {
		ret = wd_rsa_poll(expt, &count);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	if (g_config.with_log)
		HPRE_TST_PRT("%s exit!\n", __func__);

	return NULL;
}
static void _rsa_cb(void *req_t)
{
	struct wd_rsa_req *req = req_t;
	int keybits, key_size;
	struct rsa_async_tag *tag = req->cb_param;
	handle_t sess = tag->sess;
	int thread_id = tag->thread_id;
	int cnt = tag->cnt;
	void *out = req->dst;
	enum wd_rsa_op_type  op_type = req->op_type;
	struct wd_rsa_prikey *prikey;
	struct test_hpre_pthread_dt *thread_info = tag->thread_info;

	wd_rsa_get_prikey(sess, &prikey);
	keybits = wd_rsa_key_bits(sess);
	key_size = keybits >> 3;

	thread_info->recv_task_num++;

	if (g_config.check) {
		if (op_type == WD_RSA_GENKEY) {
			struct wd_rsa_kg_out *kout = out;

			if (wd_rsa_is_crt(sess)) {
				struct wd_dtb qinv, dq, dp;
				struct wd_dtb *s_qinv, *s_dq, *s_dp;

				wd_rsa_get_crt_prikey_params(prikey, &s_dq, &s_dp,
								&s_qinv, NULL, NULL);
				wd_rsa_get_kg_out_crt_params(kout, &qinv, &dq, &dp);
				if (memcmp(s_qinv->data, qinv.data, s_qinv->bsize)) {
					HPRE_TST_PRT("keygen  qinv  mismatch!\n");
					return;
				}
				if (memcmp(s_dq->data, dq.data, s_dq->bsize)) {
					HPRE_TST_PRT("keygen  dq mismatch!\n");
					return;
				}
				if (memcmp(s_dp->data, dp.data, s_dp->bsize)) {
					HPRE_TST_PRT("keygen  dp  mismatch!\n");
					return;
				}

			} else {
				struct wd_dtb d, n;
				struct wd_dtb *s_d, *s_n;

				wd_rsa_get_prikey_params(prikey, &s_d, &s_n);
				wd_rsa_get_kg_out_params(kout, &d, &n);

				/* check D */
				if (memcmp(s_d->data, d.data, s_d->bsize)) {
					HPRE_TST_PRT("key generate D result mismatching!\n");
					return;
				}
				if (memcmp(s_n->data, n.data, s_n->bsize)) {
					HPRE_TST_PRT("key generate N result mismatching!\n");
					return;
				}
			}
			if (is_allow_print(cnt, DH_ASYNC_GEN, 1))
				HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
		} else if (op_type == WD_RSA_VERIFY) {
			if (!g_config.soft_test && memcmp(ssl_params.ssl_verify_result, out, key_size)) {
				HPRE_TST_PRT("pub encrypto result  mismatch!\n");
				return;
			}
		} else {
			if (wd_rsa_is_crt(sess))
				if (!g_config.soft_test && memcmp(ssl_params.ssl_sign_result, out, key_size)) {
					HPRE_TST_PRT("prv decrypto result  mismatch!\n");
					return;
				}
		}		
	}

	if (is_allow_print(cnt, op_type, 1))
		HPRE_TST_PRT("thread %d do RSA %dth time success!\n", thread_id, cnt);
	if (op_type == WD_RSA_GENKEY && out) {
		wd_rsa_del_kg_out(sess, out);
	}
	free(tag);
}

void *_rsa_async_op_test_thread(void *data)
{
	int ret = 0, i = 0, cpuid;
	struct test_hpre_pthread_dt *pdata = data;
	const char *alg_name = pdata->alg_name;
	cpu_set_t mask;
	enum alg_op_type op_type;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	handle_t sess;
	void *key_info = NULL;
	struct wd_rsa_prikey *prikey;
	struct wd_rsa_pubkey *pubkey;
	struct rsa_async_tag *tag;
	struct wd_dtb *wd_e, *wd_d, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	struct wd_dtb t_e, t_p, t_q;
	u32 key_size = g_config.key_bits >> 3;

	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return NULL;
	}

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	op_type = pdata->op_type;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
					 sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
				 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
				pid, thread_id, cpuid);
	}
	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = g_config.key_bits;
	if (!strcmp(g_config.alg_mode, "crt"))
		setup.is_crt = true;
	else
		setup.is_crt = false;

	sess = wd_rsa_alloc_sess(&setup);
	if (!sess) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			     pid, thread_id, alg_name);
		goto fail_release;
	}

	rsa_key_in = malloc(2 * key_size + sizeof(struct hpre_rsa_test_key_in));
	if (!rsa_key_in) {
		HPRE_TST_PRT("thrd-%d:malloc err!\n", thread_id);
		goto fail_release;
	}

	rsa_key_in->e = rsa_key_in + 1;
	rsa_key_in->p = rsa_key_in->e + key_size;
	rsa_key_in->q = rsa_key_in->p + (key_size >> 1);

	wd_rsa_get_pubkey(sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);

#ifdef WITH_OPENSSL_DIR
	wd_e->dsize = BN_bn2bin(ssl_params.e, (unsigned char *)wd_e->data);
	if (wd_e->dsize > wd_e->bsize) {
		HPRE_TST_PRT("e bn to bin overflow!\n");
		goto fail_release;
	}
	wd_n->dsize = BN_bn2bin(ssl_params.n, (unsigned char *)wd_n->data);
	if (wd_n->dsize > wd_n->bsize) {
		HPRE_TST_PRT("n bn to bin overflow!\n");
		goto fail_release;
	}
#else
	memcpy(wd_e->data, ssl_params.e, key_size);
	wd_e->dsize = key_size;
	memcpy(wd_n->data, ssl_params.n, key_size);
	wd_n->dsize = key_size;
#endif
	wd_rsa_get_prikey(sess, &prikey);
	if (wd_rsa_is_crt(sess)) {
		wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);

#ifdef WITH_OPENSSL_DIR
		/* CRT mode private key */
		wd_dq->dsize = BN_bn2bin(ssl_params.dq, (unsigned char *)wd_dq->data);
		if (wd_dq->dsize > wd_dq->bsize) {
			HPRE_TST_PRT("dq bn to bin overflow!\n");
			goto fail_release;
		}
		wd_dp->dsize = BN_bn2bin(ssl_params.dp, (unsigned char *)wd_dp->data);
		if (wd_dp->dsize > wd_dp->bsize) {
			HPRE_TST_PRT("dp bn to bin overflow!\n");
			goto fail_release;
		}
		wd_qinv->dsize = BN_bn2bin(ssl_params.qinv, (unsigned char *)wd_qinv->data);
		if (wd_qinv->dsize > wd_qinv->bsize) {
			HPRE_TST_PRT("qinv bn to bin overflow!\n");
			goto fail_release;
		}
		wd_q->dsize = BN_bn2bin(ssl_params.q, (unsigned char *)wd_q->data);
		if (wd_q->dsize > wd_q->bsize) {
			HPRE_TST_PRT("q bn to bin overflow!\n");
			goto fail_release;
		}
		wd_p->dsize = BN_bn2bin(ssl_params.p, (unsigned char *)wd_p->data);
		if (wd_p->dsize > wd_p->bsize) {
			HPRE_TST_PRT("p bn to bin overflow!\n");
			goto fail_release;
		}
#else
		memcpy(wd_dq->data, ssl_params.dq, key_size / 2);
		wd_dq->dsize = key_size / 2;
		memcpy(wd_dp->data, ssl_params.dp, key_size / 2);
		wd_dp->dsize = key_size / 2;
		memcpy(wd_qinv->data, ssl_params.qinv, key_size / 2);
		wd_qinv->dsize = key_size / 2;
		memcpy(wd_q->data, ssl_params.q, key_size / 2);
		wd_q->dsize = key_size / 2;
		memcpy(wd_p->data, ssl_params.p, key_size / 2);
		wd_p->dsize = key_size / 2;
#endif

	} else {
		wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);

#ifdef WITH_OPENSSL_DIR
		wd_d->dsize = BN_bn2bin(ssl_params.d, (unsigned char *)wd_d->data);
		wd_n->dsize = BN_bn2bin(ssl_params.n, (unsigned char *)wd_n->data);
#else
		memcpy(wd_d->data, ssl_params.d, key_size);
		wd_d->dsize = key_size;
		memcpy(wd_n->data, ssl_params.n, key_size);
		wd_n->dsize = key_size;
#endif
		wd_e = &t_e;
		wd_p = &t_p;
		wd_q = &t_q;
		memset(rsa_key_in->e, 0, key_size);
		memset(rsa_key_in->p, 0, key_size >> 1);
		memset(rsa_key_in->q, 0, key_size >> 1);
#ifdef WITH_OPENSSL_DIR
		rsa_key_in->e_size = BN_bn2bin(ssl_params.e, (unsigned char *)rsa_key_in->e);
		rsa_key_in->p_size = BN_bn2bin(ssl_params.p, (unsigned char *)rsa_key_in->p);
		rsa_key_in->q_size = BN_bn2bin(ssl_params.q, (unsigned char *)rsa_key_in->q);
#else
		memcpy(rsa_key_in->e, ssl_params.e, key_size);
		rsa_key_in->e_size = key_size;
		memcpy(rsa_key_in->p, ssl_params.p, key_size / 2);
		rsa_key_in->p_size = key_size / 2;
		memcpy(rsa_key_in->q, ssl_params.q, key_size / 2);
		rsa_key_in->q_size = key_size / 2;
#endif
		wd_e->data = rsa_key_in->e;
		wd_e->dsize = rsa_key_in->e_size;
		wd_p->data = rsa_key_in->p;
		wd_p->dsize = rsa_key_in->p_size;
		wd_q->data = rsa_key_in->q;
		wd_q->dsize = rsa_key_in->q_size;
	}

	/* always key size bytes input */
	req.src_bytes = key_size;
	req.cb = _rsa_cb;
	if (op_type == RSA_KEY_GEN || op_type == RSA_ASYNC_GEN) {
		req.op_type = WD_RSA_GENKEY;
	} else if (op_type == RSA_PUB_EN || op_type == RSA_ASYNC_EN) {
		req.op_type = WD_RSA_VERIFY;
	} else if (op_type == RSA_PRV_DE || op_type == RSA_ASYNC_DE) {
		req.op_type = WD_RSA_SIGN;
	} else {
		HPRE_TST_PRT("thrd-%d:optype=%d err!\n",
			  thread_id, op_type);
		goto fail_release;
	}

	if (req.op_type == WD_RSA_GENKEY) {
		req.src = (__u8 *)wd_rsa_new_kg_in(sess, wd_e, wd_p, wd_q);
		if (!req.src) {
			HPRE_TST_PRT("thrd-%d:fill key gen req fail!\n",
				     thread_id);
			goto fail_release;
		}
		//req.dst = wd_rsa_new_kg_out(ctx);
		//if (!req.dst) {
		//	HPRE_TST_PRT("create rsa kgen out fail!\n");
		//	goto fail_release;
		//}
	} else {
		req.src = malloc(key_size);
		if (!req.src) {
			HPRE_TST_PRT("alloc in buffer fail!\n");
			goto fail_release;
		}
		memset(req.src, 0, req.src_bytes);
		req.dst = malloc(key_size);
		if (!req.dst) {
			HPRE_TST_PRT("alloc out buffer fail!\n");
			goto fail_release;
		}
		memset(req.dst, 0, req.src_bytes);
		req.dst_bytes = key_size;
	}

	do {
			if (req.op_type == WD_RSA_GENKEY) {
				req.dst = wd_rsa_new_kg_out(sess);
				if (!req.dst) {
					HPRE_TST_PRT("create rsa kgen out fail!\n");
					goto fail_release;
				}
			}
			/* set the user tag */
			tag = malloc(sizeof(*tag));
			if (!tag)
				goto fail_release;
			tag->sess = sess;
			tag->thread_id = thread_id;
			tag->cnt = i;
			tag->thread_info = pdata;
			req.cb_param = tag;
try_do_again:
			ret = wd_do_rsa_async(sess, &req);
			if (ret == -WD_EBUSY) {
				usleep(100);
				goto try_do_again;
			} else if (ret) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth fail!\n",
					 pid, thread_id, g_config.op, i);
				goto fail_release;
			}
			//usleep(100);
			i++;
			pdata->send_task_num++;
	}while (!is_exit(pdata));

	if (g_config.perf_test) {
		struct timeval cur_tval;
		float speed = 0.0, time_used = 0.0;
		gettimeofday(&cur_tval, NULL);

		//printf("start: s %lu, us %lu\n", pdata->start_tval.tv_sec, pdata->start_tval.tv_usec);
		//printf("now: s %lu, us %lu\n", cur_tval.tv_sec, cur_tval.tv_usec);

		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds) {
			speed = pdata->recv_task_num / time_used * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time_used;
		}
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
		pdata->perf = speed;
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num) {
		usleep(1000 * 1000);
		if (g_config.with_log)
			HPRE_TST_PRT("<< Proc-%d, %d-TD: total send %u: recv %u, wait recv finish...!\n",
				pid, thread_id, pdata->send_task_num, pdata->recv_task_num);			
	}


fail_release:
	if (req.op_type == WD_RSA_GENKEY) {
		if (req.src)
			wd_rsa_del_kg_in(sess, req.src);
		//if (req.dst)
		//	wd_rsa_del_kg_out(ctx, req.dst);
	} else {
		if (req.src)
			free(req.src);
		if (req.dst)
			free(req.dst);
	}
	if (sess)
		wd_rsa_free_sess(sess);
	if (key_info)
		free(key_info);
	if (rsa_key_in)
		free(rsa_key_in);
	return NULL;
}

static int set_ssl_plantext(void)
{
	ssl_params.size = g_config.key_bits >> 3;
	ssl_params.plantext = malloc(ssl_params.size);
	if (!ssl_params.plantext)
		return -ENOMEM;
	memset(ssl_params.plantext, 0, ssl_params.size);
	return 0;
}

#ifdef WITH_OPENSSL_DIR
static int rsa_openssl_key_gen_for_async_test(void)
{
	int ret;

	ssl_params.rsa = RSA_new();
	if (!ssl_params.rsa) {
		HPRE_TST_PRT("RSA new fail!\n");
		return -ENOMEM;
	}
	ssl_params.e = BN_new();
	if (!ssl_params.e) {
		RSA_free(ssl_params.rsa);
		ssl_params.rsa = NULL;
		HPRE_TST_PRT("BN new e fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}
	ret = BN_set_word(ssl_params.e, 65537);
	if (ret != 1) {
		HPRE_TST_PRT("BN_set_word fail!\n");
		ret = -1;
		goto gen_fail;
	}

	/* Generate OpenSSL SW rsa parameters */
	ret = RSA_generate_key_ex(ssl_params.rsa, g_config.key_bits, ssl_params.e, NULL);
	if (ret != 1) {
		HPRE_TST_PRT("RSA_generate_key_ex fail!\n");
		ret = -1;
		goto gen_fail;
	}
	RSA_get0_key((const RSA *)ssl_params.rsa, (const BIGNUM **)&ssl_params.n,
			 (const BIGNUM **)&ssl_params.e, (const BIGNUM **)&ssl_params.d);
	RSA_get0_factors((const RSA *)ssl_params.rsa, (const BIGNUM **)&ssl_params.p,
			 (const BIGNUM **)&ssl_params.q);
	RSA_get0_crt_params((const RSA *)ssl_params.rsa, (const BIGNUM **)&ssl_params.dp,
			(const BIGNUM **)&ssl_params.dq, (const BIGNUM **)&ssl_params.qinv);

	/* Generate OpenSSL SW rsa verify and sign standard result
	 * for check in the next tests
	 */
	ret = set_ssl_plantext();
	if (ret) {
		HPRE_TST_PRT("set ssl plantext fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	ssl_params.ssl_verify_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_verify_result) {
		HPRE_TST_PRT("malloc verify result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	ret = RSA_public_encrypt(ssl_params.size, ssl_params.plantext,
				 ssl_params.ssl_verify_result,
				 ssl_params.rsa, RSA_NO_PADDING);
	if (ret != ssl_params.size) {
		HPRE_TST_PRT("openssl pub encrypto fail!ret=%d\n", ret);
		ret = -1;
		return ret;
	}
	ssl_params.ssl_sign_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_sign_result) {
		HPRE_TST_PRT("malloc sign result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	ret = RSA_private_decrypt(ssl_params.size, ssl_params.plantext,
				  ssl_params.ssl_sign_result,
				  ssl_params.rsa, RSA_NO_PADDING);
	if (ret != ssl_params.size) {
		HPRE_TST_PRT("openssl priv decrypto fail!ret=%d\n", ret);
		ret = -1;
		goto gen_fail;
	}

	return 0;

gen_fail:
	RSA_free(ssl_params.rsa);
	BN_free(ssl_params.e);
	if (ssl_params.plantext)
		free(ssl_params.plantext);
	if (ssl_params.ssl_verify_result)
		free(ssl_params.ssl_verify_result);
	if (ssl_params.ssl_sign_result)
		free(ssl_params.ssl_sign_result);
	return ret;
}

#else
static int rsa_sample_key_gen_for_async_test(void)
{
	const __u8 *p, *q, *n, *e, *d, *dp, *dq, *qinv;
	int key_bits = g_config.key_bits;
	int ret;

	if (g_config.key_bits == 1024) {
		e = rsa_e_1024;
		p = rsa_p_1024;
		q = rsa_q_1024;
		dp = rsa_dp_1024;
		dq = rsa_dq_1024;
		qinv = rsa_qinv_1024;
		d = rsa_d_1024;
		n = rsa_n_1024;
	} else if (key_bits == 2048) {
		e = rsa_e_2048;
		p = rsa_p_2048;
		q = rsa_q_2048;
		dp = rsa_dp_2048;
		dq = rsa_dq_2048;
		qinv = rsa_qinv_2048;
		d = rsa_d_2048;
		n = rsa_n_2048;
	} else if (key_bits == 3072) {
		e = rsa_e_3072;
		p = rsa_p_3072;
		q = rsa_q_3072;
		dp = rsa_dp_3072;
		dq = rsa_dq_3072;
		qinv = rsa_qinv_3072;
		d = rsa_d_3072;
		n = rsa_n_3072;
	} else if (key_bits == 4096) {
		e = rsa_e_4096;
		p = rsa_p_4096;
		q = rsa_q_4096;
		dp = rsa_dp_4096;
		dq = rsa_dq_4096;
		qinv = rsa_qinv_4096;
		d = rsa_d_4096;
		n = rsa_n_4096;
	} else {
		HPRE_TST_PRT("invalid key bits = %d!\n", key_bits);
		return -1;
	}

	ssl_params.e = BN_bin2bn(e, key_bits >> 3, NULL);
	if (!ssl_params.e) {
		HPRE_TST_PRT("Bin2bin e fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.d = BN_bin2bn(d, key_bits >> 3, NULL);
	if (!ssl_params.d) {
		HPRE_TST_PRT("Bin2bin d fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.n = BN_bin2bn(n, key_bits >> 3, NULL);
	if (!ssl_params.n) {
		HPRE_TST_PRT("Bin2bin n fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.p = BN_bin2bn(p, key_bits >> 4, NULL);
	if (!ssl_params.p) {
		HPRE_TST_PRT("Bin2bin p fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.q = BN_bin2bn(q, key_bits >> 4, NULL);
	if (!ssl_params.q) {
		HPRE_TST_PRT("Bin2bin q fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.dp = BN_bin2bn(dp, key_bits >> 4, NULL);
	if (!ssl_params.dp) {
		HPRE_TST_PRT("Bin2bin dp fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.dq = BN_bin2bn(dq, key_bits >> 4, NULL);
	if (!ssl_params.dq) {
		HPRE_TST_PRT("Bin2bin dq fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.qinv = BN_bin2bn(qinv, key_bits >> 4, NULL);
	if (!ssl_params.qinv) {
		HPRE_TST_PRT("Bin2bin qinv fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	/* Generate OpenSSL SW rsa verify and sign standard result
	 * for check in the next tests
	 */
	ret = set_ssl_plantext();
	if (ret) {
		HPRE_TST_PRT("set ssl plantext fail!!\n");
		ret = -1;
		goto gen_fail;
	}

	ssl_params.ssl_verify_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_verify_result) {
		HPRE_TST_PRT("malloc verify result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	ssl_params.ssl_sign_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_sign_result) {
		HPRE_TST_PRT("malloc sign result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}

	return 0;
gen_fail:
	if (ssl_params.e)
		BN_free(ssl_params.e);
	if (ssl_params.d)
		BN_free(ssl_params.d);
	if (ssl_params.n)
		BN_free(ssl_params.n);
	if (ssl_params.p)
		BN_free(ssl_params.p);
	if (ssl_params.q)
		BN_free(ssl_params.q);
	if (ssl_params.dp)
		BN_free(ssl_params.dp);
	if (ssl_params.dq)
		BN_free(ssl_params.dq);
	if (ssl_params.qinv)
		BN_free(ssl_params.qinv);
	if (ssl_params.plantext)
		free(ssl_params.plantext);
	if (ssl_params.ssl_verify_result)
		free(ssl_params.ssl_verify_result);
	if (ssl_params.ssl_sign_result)
		free(ssl_params.ssl_sign_result);
	return ret;
}
#endif

static int rsa_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	int ret = 0, cnt = 0, i;
	int h_cpuid;
	float speed = 0.0;

	/* Create poll thread at first */
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
		_rsa_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	#ifdef WITH_OPENSSL_DIR
	ret = rsa_openssl_key_gen_for_async_test();
	if(ret) {
		HPRE_TST_PRT("openssl genkey for async thread test fail!");
		return 0;
	}
	#else
	ret = rsa_sample_key_gen_for_async_test();
	if(ret) {
		HPRE_TST_PRT("sample genkey for async thread test fail!");
		return 0;
	}
	#endif

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i - 1, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _rsa_async_op_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i - 1, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _rsa_async_op_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 1; i <= thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);
	HPRE_TST_PRT("<< test finish!\n");
	return 0;
}

static void *_dh_async_poll_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	int ret, cpuid;
	int pid = getpid();
	cpu_set_t mask;
	int thread_id = (int)syscall(__NR_gettid);
	__u32 count = 0;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, poll thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	while (1) {
		ret = wd_dh_poll(0, &count);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	if (g_config.with_log)
		HPRE_TST_PRT("%s exit!\n", __func__);
	return NULL;
}

static int dh_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	int i, ret, cnt = 0;
	int h_cpuid;
	float speed = 0.0;

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	/* Create poll thread at first */
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	gettimeofday(&test_thrds_data[0].start_tval, NULL);
	ret = pthread_create(&system_test_thrds[0], NULL,
			     _dh_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i - 1, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _hpre_dh_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i - 1, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _hpre_dh_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);
	HPRE_TST_PRT("<< test finish!\n");
	
	return 0;
}

void *_hpre_sys_test_thread(void *data)
{
	enum alg_op_type op_type;
	struct test_hpre_pthread_dt *pdata = data;

	op_type = pdata->op_type;
	if (op_type > MAX_DH_TYPE && op_type < MAX_ECC_TYPE) {
		// return _ecc_sys_test_thread(data); will be added later
	} else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE) {
		return _hpre_dh_sys_test_thread(data);
	} else {
		return _hpre_rsa_sys_test_thread(data);
	}

	return NULL;
}

static void print_help(void);
static int parse_cmd_line(int argc, char *argv[])
{
        int option_index = 0;
        int optind_t;
	int ret = 0;
	int bits;
        int c;

        static struct option long_options[] = {
            {"op",     required_argument, 0,  0 },
            {"mode",  	required_argument, 0,  0 },
            {"dev_path",  required_argument, 0,  0 },
            {"key_bits", required_argument,       0,  0 },
            {"cycles",  required_argument, 0, 0},
            {"seconds",    required_argument, 0,  0 },
            {"log",    required_argument, 0,  0 },
            {"check",    required_argument, 0,  0 },
            {"soft",    no_argument, 0,  0 },
            {"perf",    no_argument, 0,  0 },
            {"trd_mode",    required_argument, 0,  0 },
            {"curve",    required_argument, 0,  0 },
            {"help",    no_argument, 0,  'h' },
            {0,         0,                 0,  0 }
        };

        while (1) {
        	optind_t = optind ? optind: 1;

        	c = getopt_long(argc, argv, "t:c:", long_options, &option_index);
        	if (c == -1) {
			if (optind_t < argc) {
				print_help();
				ret = -1;
			}
        		break;
		}

		switch (c) {
		case 0:
			if (!strncmp(long_options[option_index].name, "mode", 4)) {
				snprintf(g_config.alg_mode, sizeof(g_config.alg_mode), "%s", optarg);				
			} else if (!strncmp(long_options[option_index].name, "dev_path", 8)) {
				snprintf(g_config.dev_path, sizeof(g_config.dev_path), "%s", optarg);	
			} else if (!strncmp(long_options[option_index].name, "key_bits", 8)) {
				g_config.key_bits = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "cycles", 6)) {
				g_config.times = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "seconds", 7)) {
				g_config.seconds = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "log", 3)) {
				if (!strncmp(optarg, "y", 1) || !strncmp(optarg, "Y", 1))
					g_config.with_log = 1;
				else
					g_config.with_log = 0;
			} else if (!strncmp(long_options[option_index].name, "check", 5)) {
				if (!strncmp(optarg, "y", 1) || !strncmp(optarg, "Y", 1)) {
					g_config.check = 1;
				} else {
					g_config.check = 0;
				}
			} else if (!strncmp(long_options[option_index].name, "soft", 4)) {
				g_config.soft_test = 1;
			} else if (!strncmp(long_options[option_index].name, "perf", 4)) {
				g_config.perf_test = 1;
			} else if (!strncmp(long_options[option_index].name, "trd_mode", 8)) {
				snprintf(g_config.trd_mode, sizeof(g_config.trd_mode), "%s", optarg);	
			} else if (!strncmp(long_options[option_index].name, "op", 2)) {
				snprintf(g_config.op, sizeof(g_config.op), "%s", optarg);	
			}
			break;

		case 't':
			g_config.trd_num = strtoul((char *)optarg, NULL, 10);
			if (g_config.trd_num <= 0 || g_config.trd_num > TEST_MAX_THRD) {
				HPRE_TST_PRT("Invalid threads num:%d!\n",
								g_config.trd_num);
				HPRE_TST_PRT("Now set threads num as 2\n");
				g_config.trd_num = 2;
			}
			break;
		case 'c':
			if (optarg[0] != '0' || optarg[1] != 'x') {
				HPRE_TST_PRT("Err:coremask should be hex!\n");
				return -EINVAL;
			}

			if (strlen(optarg) > 34) {
				HPRE_TST_PRT("warn:coremask is cut!\n");
				optarg[34] = 0;
			}

			if (strlen(optarg) <= 18) {
				g_config.core_mask[0] = strtoull(optarg, NULL, 16);
				if (g_config.core_mask[0] & 0x1) {
					HPRE_TST_PRT("Warn:cannot bind to core 0,\n");
					HPRE_TST_PRT("now run without binding\n");
					g_config.core_mask[0] = 0x0; /* no binding */
				}
				g_config.core_mask[1] = 0;
			} else {
				int offset = 0;
				char *temp;

				offset = strlen(optarg) - 16;
				g_config.core_mask[0] = strtoull(&optarg[offset], NULL, 16);
				if (g_config.core_mask[0] & 0x1) {
					HPRE_TST_PRT("Warn:cannot bind to core 0,\n");
					HPRE_TST_PRT("now run without binding\n");
					g_config.core_mask[0] = 0x0; /* no binding */
				}
				temp = malloc(64);
				strcpy(temp, optarg);
				temp[offset] = 0;
				g_config.core_mask[1] = strtoull(temp, NULL, 16);
				free(temp);
			}
			bits = _get_one_bits(g_config.core_mask[0]);
			bits += _get_one_bits(g_config.core_mask[1]);
			if (g_config.trd_num > bits) {
				HPRE_TST_PRT("Coremask not covers all thrds,\n");
				HPRE_TST_PRT("Bind first %d thrds!\n", bits);
			} else if (g_config.trd_num < bits) {
				HPRE_TST_PRT("Coremask overflow,\n");
				HPRE_TST_PRT("Just try to bind all thrds!\n");
			};
			break;

		case '?':
		case 'h':
			print_help();
			ret = -1;
		    break;

		default:
		    printf("?? getopt returned character code 0%o ??\n", c);
		    break;
		}
        }

        if (g_config.perf_test)
        	g_config.check = 0;

	return ret;
}

int main(int argc, char *argv[])
{
	enum alg_op_type alg_op_type = HPRE_ALG_INVLD_TYPE;
	int ret = 0;

	ret = parse_cmd_line(argc, argv);
	if (ret)
		return -1;

	if (!strcmp(g_config.op, "rsa-gen")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = RSA_ASYNC_GEN;
		else
			alg_op_type = RSA_KEY_GEN;			
	} else if (!strcmp(g_config.op, "rsa-vrf")) {
		if (!strcmp(g_config.trd_mode, "async"))		
			alg_op_type = RSA_ASYNC_EN;
		else
			alg_op_type = RSA_PUB_EN;			
	} else if (!strcmp(g_config.op, "rsa-sgn")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = RSA_ASYNC_DE;
		else
			alg_op_type = RSA_PRV_DE;		
	} else if (!strcmp(g_config.op, "dh-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))	
			alg_op_type = DH_ASYNC_GEN;
		else
			alg_op_type = DH_GEN;		
	} else if (!strcmp(g_config.op, "dh-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = DH_ASYNC_COMPUTE;
		else
			alg_op_type = DH_COMPUTE;		
	} else if (!strcmp(g_config.op, "ecdh-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDH_ASYNC_GEN;
		else
			alg_op_type = ECDH_GEN;
	} else if (!strcmp(g_config.op, "ecdh-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDH_ASYNC_COMPUTE;
		else
			alg_op_type = ECDH_COMPUTE;
	} else if (!strcmp(g_config.op, "ecdsa-sign")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDSA_ASYNC_SIGN;
		else
			alg_op_type = ECDSA_SIGN;
	} else if (!strcmp(g_config.op, "ecdsa-verf")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDSA_ASYNC_VERF;
		else
			alg_op_type = ECDSA_VERF;
	} else if (!strcmp(g_config.op, "x25519-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X25519_ASYNC_GEN;
		else
			alg_op_type = X25519_GEN;
	} else if (!strcmp(g_config.op, "x25519-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X25519_ASYNC_COMPUTE;
		else
			alg_op_type = X25519_COMPUTE;
	} else if (!strcmp(g_config.op, "x448-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X448_ASYNC_GEN;
		else
			alg_op_type = X448_GEN;
	} else if (!strcmp(g_config.op, "x448-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X448_ASYNC_COMPUTE;
		else
			alg_op_type = X448_COMPUTE;
	} else {
	}

	if (alg_op_type >= X25519_GEN && alg_op_type <= X25519_ASYNC_COMPUTE)
		g_config.key_bits = 256;
	else if (alg_op_type >= X448_GEN && alg_op_type <= X448_ASYNC_COMPUTE)
		g_config.key_bits = 448;

  	ret = init_hpre_global_config(alg_op_type);
  	if (ret) {
  		HPRE_TST_PRT("failed to init_hpre_global_config, ret %d!\n", ret);
  		return -1;
  	}

	HPRE_TST_PRT(">> test start run %s :\n", g_config.op);
	HPRE_TST_PRT(">> key_bits = %u\n", g_config.key_bits);
	HPRE_TST_PRT(">> trd_mode = %s\n", g_config.trd_mode);
	HPRE_TST_PRT(">> trd_num = %u\n", g_config.trd_num);
	HPRE_TST_PRT(">> core_mask = [0x%llx][0x%llx]\n", g_config.core_mask[1],
		g_config.core_mask[0]);
	HPRE_TST_PRT(">> cycles = %u\n", g_config.times);
	HPRE_TST_PRT(">> seconds = %u\n", g_config.seconds);
	if (g_config.perf_test)
		HPRE_TST_PRT("perf test, check closed\n");

	if (alg_op_type < MAX_RSA_SYNC_TYPE ||
		alg_op_type == DH_GEN || alg_op_type == DH_COMPUTE ||
		alg_op_type == ECDH_GEN || alg_op_type == ECDH_COMPUTE ||
		alg_op_type == ECDSA_SIGN || alg_op_type == ECDSA_VERF ||
		alg_op_type == X25519_GEN || alg_op_type == X25519_COMPUTE ||
		alg_op_type == X448_GEN || alg_op_type == X448_COMPUTE)
			ret = hpre_sys_test(g_config.trd_num, g_config.core_mask[0],
				g_config.core_mask[1], alg_op_type, g_config.dev_path, 0);
	else if (alg_op_type > MAX_RSA_SYNC_TYPE && alg_op_type < MAX_RSA_ASYNC_TYPE)
		ret = rsa_async_test(g_config.trd_num, g_config.core_mask[0],
			g_config.core_mask[1], alg_op_type);
	else if (alg_op_type == DH_ASYNC_GEN || alg_op_type == DH_ASYNC_COMPUTE)
		ret = dh_async_test(g_config.trd_num, g_config.core_mask[0],
					      g_config.core_mask[1], alg_op_type);
	else if (alg_op_type == ECDH_ASYNC_GEN || alg_op_type == ECDH_ASYNC_COMPUTE ||
		alg_op_type == ECDSA_ASYNC_SIGN || alg_op_type == ECDSA_ASYNC_VERF ||
		alg_op_type == X25519_ASYNC_GEN || alg_op_type == X25519_ASYNC_COMPUTE ||
		alg_op_type == X448_ASYNC_GEN || alg_op_type == X448_ASYNC_COMPUTE)
		//return ecc_async_test(thread_num, core_mask[0],
		//      core_mask[1], alg_op_type); will be added later
		ret = 0;
	else
		ret = -1; /* to extend other test samples */

	uninit_hpre_global_config(alg_op_type);

	return ret;

}

static void print_help(void)
{
	HPRE_TST_PRT("UPDATE:2020-09-12\n");
	HPRE_TST_PRT("NAME\n");
	HPRE_TST_PRT("    test_hisi_hpre: test wd hpre function,etc\n");
	HPRE_TST_PRT("USAGE\n");
	HPRE_TST_PRT("    test_hisi_hpre [--op=] [-t] [-c] [--mode=] [--help]\n");
	HPRE_TST_PRT("    test_hisi_hpre [--dev_path=] [--curve] [--key_bits=]\n");
	HPRE_TST_PRT("    test_hisi_hpre [--seconds=] [--times [--trd_mode=]\n");
	HPRE_TST_PRT("DESCRIPTION\n");
	HPRE_TST_PRT("    [--op=]:\n");
	HPRE_TST_PRT("        rsa-gen  = RSA key generate test\n");
	HPRE_TST_PRT("        rsa-sgn  = RSA signature test\n");
	HPRE_TST_PRT("        rsa-vrf  = RSA verification test\n");
	HPRE_TST_PRT("        dh-gen1  = DH phase 1 key generate test\n");
	HPRE_TST_PRT("        dh-gen2  = DH phase 2 key generate test\n");
	HPRE_TST_PRT("        ecdh-gen1  = ECDH phase 1 key generate test\n");
	HPRE_TST_PRT("        ecdh-gen2  = ECDH phase 2 key generate test\n");
	HPRE_TST_PRT("    [-t]: start thread total\n");
	HPRE_TST_PRT("    [-c]: mask for bind cpu core, as 0x3 bind to cpu-1 and cpu-2\n");
	HPRE_TST_PRT("    [--log=]:\n");
	HPRE_TST_PRT("        y\n");
	HPRE_TST_PRT("        n\n");
	HPRE_TST_PRT("    [--perf]: use test algorithm perf\n");
	HPRE_TST_PRT("    [--check=]:\n");
	HPRE_TST_PRT("        y: check result compared with openssl\n");
	HPRE_TST_PRT("        n: no check\n");
	HPRE_TST_PRT("    [--key_bits=]:key size (bits)\n");
	HPRE_TST_PRT("    [--mode=]:\n");
	HPRE_TST_PRT("        g2  = DH G2 mode\n");
	HPRE_TST_PRT("        com  = common mode\n");
	HPRE_TST_PRT("        crt  = RSA CRT mode\n");
	HPRE_TST_PRT("    [--trd_mode=]:\n");
	HPRE_TST_PRT("        sync  = synchronize test\n");
	HPRE_TST_PRT("        async  = asynchronize test\n");
	HPRE_TST_PRT("    [--curve=]:\n");
	HPRE_TST_PRT("        secp128R1  = 128 bit\n");
	HPRE_TST_PRT("        secp192K1  = 192 bit\n");
	HPRE_TST_PRT("        secp256K1  = 256bit\n");
	HPRE_TST_PRT("        brainpoolP320R1  = 320bit\n");
	HPRE_TST_PRT("        brainpoolP385R1  = 384bit\n");
	HPRE_TST_PRT("        secp521R1  = 521bit\n");
	HPRE_TST_PRT("        null  = by set parameters\n");
	HPRE_TST_PRT("    [--dev_path=]: designed dev path\n");
	HPRE_TST_PRT("    [--seconds=]: test time set (s)\n");
	HPRE_TST_PRT("    [--cycles=]: test cycle set (times)\n");
	HPRE_TST_PRT("    [--help]  = usage\n");
}
