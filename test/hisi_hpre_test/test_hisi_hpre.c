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

#include <stdio.h>
#include <string.h>
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

#include "hpre_test_sample.h"
#include "test_hisi_hpre.h"
#include "../../include/wd.h"
//#include "../../wd_ecc.h"
#include "../../include/wd_rsa.h"
//#include "../../wd_dh.h"
//#include "../../wd_bmm.h"
//#include "../../wd_util.h"

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
	void *pool;
	void *q;
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
	void *ctx;
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

static int key_bits = 2048;
static int openssl_check;
static int only_soft;
static int performance_test = 1;
static int t_times = 10;
static int t_seconds = 0;
static int with_log;
static int is_system_test;
static int ctx_num_per_q = 1;
static int q_num = 1;
static char *g_mode = "-crt";
static volatile int asyn_thread_exit = 0;
static char *ecc_curve_name = "secp256k1";
static char g_dev_path[PATH_STR_SIZE] = "/dev/hisi_hpre-4";

static __thread u32 g_is_set_prikey; // ecdh used
static __thread u32 g_is_set_pubkey; // ecc used
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct test_hpre_pthread_dt test_thrds_data[TEST_MAX_THRD];
static struct async_test_openssl_param ssl_params;

static bool is_exit(struct test_hpre_pthread_dt *pdata);

static char *rsa_op_str[WD_RSA_GENKEY + 1] = {
	"invalid_op",
	"rsa_sign",
	"rsa_verify",
	"rsa_keygen",
};

static char *dh_op_str[] = {
	"ph1",
	"ph2"
};

static char *rsa_op_str_perf[WD_RSA_GENKEY + 1] = {
	"invalid_op",
	"sign",
	"verify",
	"gen",
};

struct ecc_curve_tbl ecc_curve_tbls[] = {
#if 0 // todo ecc
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
	void *pool;
	void *q;
	void *ctx;
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
	void *pool;
	void *q;
	void *ctx;
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

static char *ecc_op_str[ECC_TEST_ITEM_MAX] = {
	"invalid_op",
	"xdh sw gen",
	"xdh sw compute",
	"xdh hw gen",
	"xdh hw compute",
	"ecc sw sign",
	"ecc sw verf",
	"ecc hw sign",
	"ecc hw verf",
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

static __u32 get_ecc_min_blocksize(__u32 key_bits)
{
	__u32 size = 0;

	if (key_bits <= 256)
		size = 32;
	else if (key_bits <= 384)
		size = 48;
	else if (key_bits <= 576)
		size = 72;
	else
		WD_ERR("get min block size key_bits %d err!\n", key_bits);

	return size;
}

static __u8 is_async_test(__u32 opType)
{
	if (opType == ECDSA_SIGN || opType == ECDSA_VERF ||
		opType == SM2_SIGN || opType == SM2_VERF ||
		opType == SM2_ENC || opType == SM2_DEC ||
		opType == ECDH_GEN || opType == ECDH_COMPUTE ||
		opType == X25519_GEN || opType == X25519_COMPUTE ||
		opType == X448_GEN || opType == X448_COMPUTE)
		return false;

	return true;
}

handle_t rsa_pick_next_ctx(struct wd_ctx_config *config,
				struct wd_rsa_req *req, void *key)
{
  __u32 idx;
  
  if (req->op_type == WD_RSA_GENKEY)
    idx = 0;
  else if (req->op_type == WD_RSA_SIGN)
    idx = 1 % q_num;
  else
    idx = 2 % q_num;
	
  return config->ctxs[idx].ctx;
}

int poll_policy( struct wd_ctx_config *config, __u32 expect, __u32 *count)
{
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


static int init_hpre_global_config(void)
{
	struct wd_ctx *ctx_attr;
	struct wd_ctx_config ctx_cfg;
	struct wd_sched sched;
	int ctx_num = q_num;
	__u32 op_type = 0;
	int ret;
	int j;

#ifdef DEBUG
		HPRE_TST_PRT("%s req %d ctx!\n", g_dev_path, ctx_num);
#endif

	ctx_attr = malloc(ctx_num * sizeof(struct wd_ctx));
	if (!ctx_attr) {
		HPRE_TST_PRT("malloc ctx_attr memory fail!\n");
		return -ENOMEM;
	}
	memset(ctx_attr, 0, ctx_num * sizeof(struct wd_ctx));

	for (j = 0; j < ctx_num; j++) {
		ctx_attr[j].ctx = wd_request_ctx(g_dev_path);
		if (!ctx_attr[j].ctx) {
			HPRE_TST_PRT("failed to request ctx!\n");
			return -1;
		}
		ctx_attr[j].ctx_mode = is_async_test(op_type);
		ctx_attr[j].op_type = get_alg_op_type(op_type);
	}

	ctx_cfg.ctx_num = ctx_num;
	ctx_cfg.ctxs = ctx_attr;
	sched.name = "rsa-sched-0";
	sched.pick_next_ctx = rsa_pick_next_ctx;
	sched.poll_policy = poll_policy;
	sched.sched_ctx_size = 1; //todo
	ret = wd_rsa_init(&ctx_cfg, &sched);
	if (ret) {
		HPRE_TST_PRT("failed to init rsa, ret %d!\n", ret);
		return -1;
	}

	return ret;

}

static void uninit_hpre_global_config(void)
{
	wd_rsa_uninit();
}

#if 0 // todo dh
static int init_opdata_param(void *pool,
			     struct wd_dh_op_data *req,
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
		struct wd_dh_op_data *req = test_ctx->req;

		free(req->x_p);
		free(req->pri);
		free(req);
		free(test_ctx->cp_pub_key);
	} else if (HW_COMPUTE_KEY == test_ctx->op) {
		struct wd_dh_op_data *req = test_ctx->req;

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
	struct wd_dh_op_data *req;
	struct hpre_dh_test_ctx *test_ctx;
	struct wd_dtb ctx_g;
	int ret;
	u32 key_size = setup.key_bits >> 3;
	DH *dh = NULL;

	if (!setup.q || !setup.pool || setup.op_type !=HW_GENERATE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_dh_op_data));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct hpre_dh_sw_opdata));

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

	ret = init_opdata_param(setup.pool, req, key_size, DH_ALICE_PUBKEY);
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
	test_ctx->pool = setup.pool;
	test_ctx->op = setup.op_type;
	test_ctx->priv = setup.ctx; //init ctx
	test_ctx->key_size = key_size;

	ret = wd_set_dh_g(test_ctx->priv, &ctx_g);
	if (ret) {
		HPRE_TST_PRT("wd_set_dh_g failed\n");
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
	struct wd_dh_op_data *req;
	struct hpre_dh_test_ctx *test_ctx;
	int ret;
	u32 key_size = setup.key_bits >> 3;
	DH *dh = NULL;
	DH *b = NULL;

	if (!setup.q || !setup.pool || setup.op_type !=HW_COMPUTE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_dh_op_data));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_dh_op_data));

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

	ret = init_opdata_param(setup.pool, req, key_size, DH_ALICE_PRIVKEY);
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
	test_ctx->priv = setup.ctx; //init ctx
	test_ctx->req = req;
	test_ctx->pool = setup.pool;
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
		struct wd_dh_op_data *req = t_c->req;
		void* ctx = t_c->priv;
try_again:
		ret = wd_do_dh(ctx, req, tag);
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
		struct wd_dh_op_data *req = t_c->req;
		void* ctx = t_c->priv;
try_again:

		ret = wd_do_dh(ctx, req, tag);
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
#endif

static bool is_exit(struct test_hpre_pthread_dt *pdata)
{
	struct timeval cur_tval;
	float time_used;

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - pdata->start_tval.tv_usec);

	if (t_seconds)
		return time_used >= t_seconds * 1000000;
	else if (t_times)
		return pdata->send_task_num >= t_times;

	return false;
}

#if 0
static int dh_result_check(struct hpre_dh_test_ctx *test_ctx)
{
	struct wd_dh_op_data *req = test_ctx->req;
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
#endif

static bool is_allow_print(int cnt, enum alg_op_type opType, int thread_num)
{
	int intval_index = 0;
	unsigned int log_intval_adjust = 0;
	int log_intval[LOG_INTVL_NUM] = {0x1, 0xff, 0x3ff, 0x7ff, 0xfff, 0x1fff};

	if (!with_log)
		return false;

	if (only_soft)
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

#if 0 // todo dh
static void _dh_perf_cb(const void *message, void *tag)
{
	//const struct wd_dh_msg *msg = message;
	struct dh_user_tag_info* pTag = (struct dh_user_tag_info*)tag;
	struct test_hpre_pthread_dt *thread_data = pTag->thread_data;

	thread_data->recv_task_num++;
	hpre_dh_del_test_ctx(pTag->test_ctx);
	free(pTag);
}

static void _dh_cb(const void *message, void *tag)
{
	const struct wd_dh_msg *msg = message;
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)tag;
	struct timeval start_tval, end_tval;
	int pid, threadId;
	float time, speed;
	int ret;
	static int failTimes = 0;
	struct hpre_dh_test_ctx *test_ctx = pSwData->test_ctx;
	struct wd_dh_op_data *req = test_ctx->req;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;

	start_tval = thread_data->start_tval;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;

	if (req->status != WD_SUCCESS) {
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes fail!, status 0x%02x\n",
				 pid, threadId, thread_data->send_task_num, req->status);
		goto err;
	}

	if (openssl_check) {
		req->pri_bytes = msg->out_bytes;
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
	if (!setup)
		return -1;

	if (!strcmp(g_mode, "-g2"))
		setup->generator = DH_GENERATOR_2;
	else
		setup->generator = DH_GENERATOR_5;

	if (performance_test)
		setup->key_from = 1; //0 - Openssl  1 - Designed
	else
		setup->key_from = 0; //0 - Openssl  1 - Designed

	setup->key_bits = key_bits;

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

	if (!strcmp(g_mode, "-g2")) {
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
	float time_used, speed;
	int thread_num;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int ret, cpuid, opstr_idx = 0;
	struct wd_queue *q = NULL;
	void *pool = NULL;
	void *ctx = NULL;
	struct wd_dh_ctx_setup dh_setup;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	q = (struct wd_queue *)pdata->q;
	pool = pdata->pool;
	opType = pdata->op_type;
	thread_num = pdata->thread_num;

	if (performance_test && (!t_times && !t_seconds)) {
		HPRE_TST_PRT("t_times or  t_seconds err\n");
		return NULL;
	}

	if (!q || !pool) {
		HPRE_TST_PRT("q or pool null!\n");
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

	if (!only_soft) {
		memset(&dh_setup, 0, sizeof(dh_setup));
		dh_setup.key_bits = key_bits;
		if (performance_test)
			dh_setup.cb = _dh_perf_cb;
		else
			dh_setup.cb = _dh_cb;

		if (!strcmp(g_mode, "-g2"))
			dh_setup.is_g2 = true;
		else
			dh_setup.is_g2 = false;

		ctx = wd_create_dh_ctx(q, &dh_setup);
		if (!ctx) {
			HPRE_TST_PRT("wd_create_dh_ctx failed\n");
			return NULL;
		}
	}

	if (dh_init_test_ctx_setup(&setup)) {
		wd_del_dh_ctx(ctx);
		return NULL;
	}

	setup.pool = pool;
	setup.q = q;
	setup.ctx = ctx;

	if (opType == DH_ASYNC_GEN || opType == DH_GEN)
		setup.op_type = (only_soft) ? SW_GENERATE_KEY: HW_GENERATE_KEY;
	else
		setup.op_type = (only_soft) ? SW_COMPUTE_KEY: HW_COMPUTE_KEY;

new_test_again:
	test_ctx = hpre_dh_create_test_ctx(setup);
	if (!test_ctx) {
		HPRE_TST_PRT("hpre_dh_create_test_ctx failed\n");
		return NULL;
	}

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
		}

		if (opType == DH_ASYNC_GEN || opType == DH_GEN) {
			if (dh_generate_key(test_ctx, pTag)) {
				goto fail_release;
			}
			opstr_idx = 0;
		} else {
			if (dh_compute_key(test_ctx, pTag)) {
				goto fail_release;
			}
			opstr_idx = 1;
		}

		pdata->send_task_num++;
		if (opType == DH_GEN ||opType == DH_COMPUTE) {
			if (!performance_test && !only_soft) {
				if (dh_result_check(test_ctx))
					goto fail_release;

				if (is_allow_print(pdata->send_task_num, opType, thread_num)) {
					HPRE_TST_PRT("Proc-%d, %d-TD dh %s succ!\n",
						getpid(), (int)syscall(__NR_gettid), dh_op_str[opstr_idx]);
				}

				hpre_dh_del_test_ctx(test_ctx);
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

	if (performance_test) {
		gettimeofday(&cur_tval, NULL);
		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (t_seconds){
			speed = pdata->send_task_num / time_used * 1000000;
			HPRE_TST_PRT("Proc-%d, %d-TD: dh do %s send %u task, recv %u task, run %0.1f s at %0.3f ops\n",
				 pid, thread_id, dh_op_str[opstr_idx],
				pdata->send_task_num, pdata->recv_task_num,
				time_used / 1000000, speed);
		} else if (t_times) {
			speed = 1 / (time_used / t_times) * 1000;
			HPRE_TST_PRT("\r\nPID(%d)-thread-%d:%s g2 mode %dbits kgen %s time %0.0f us, pkt len ="
				" %d bytes, %0.3f Kops\n", getpid(), (int)syscall(__NR_gettid), "dh",
				key_bits, dh_op_str[opstr_idx],time_used, key_bits / 8, speed);
		}
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num)
		usleep(1000);

fail_release:
	if (opType == DH_ASYNC_GEN ||
		opType == DH_ASYNC_COMPUTE) {
		return NULL;
	}
	if (test_ctx->op == HW_COMPUTE_KEY || test_ctx->op == HW_GENERATE_KEY)
		wd_del_dh_ctx(test_ctx->priv);

	if (opType == DH_GEN || opType == DH_COMPUTE)
		hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}

static struct ecc_test_ctx *x_create_sw_gen_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
			printf("malloc failed.\n");
			return NULL;
	}

	test_ctx->op = ECDH_SW_GENERATE;
	test_ctx->key_size = setup.key_bits >> 3;

	return test_ctx;
}

static struct ecc_test_ctx *ecc_create_sw_gen_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	EC_KEY *key = NULL;
	EC_GROUP *group;
	int ret;

	if (ECDH_SW_GENERATE != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	key = EC_KEY_new();
	if (!key) {
		printf("EC_KEY_new err!\n");
		return NULL;
	}

	group = EC_GROUP_new_by_curve_name(setup.nid);
	if(!group) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		goto free_ec_key;
	}

	ret = EC_KEY_set_group(key, group);
	if(ret != 1) {
		printf("EC_KEY_set_group err.\n");
		goto free_ec_key;
	}

	EC_GROUP_free(group);

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
		goto free_ec_key;
	}

	if (setup.key_from) {
		BIGNUM *privKey;

		privKey = BN_bin2bn(setup.d, setup.d_size, NULL);
		ret = EC_KEY_set_private_key(key, privKey);
		if (ret != 1) {
			printf("EC_KEY_set_private_key failed\n");
			goto free_ctx;
		}
	} else {}

	test_ctx->op = ECDH_SW_GENERATE;
	test_ctx->priv = key;
	test_ctx->key_size = setup.key_bits >> 3;

#ifdef DEBUG
	ECParameters_print_fp(stdout, key);
	EC_KEY_print_fp(stdout, key, 0);
#endif

	return test_ctx;

free_ctx:
	free(test_ctx);
free_ec_key:
	EC_KEY_free(key);
	return NULL;
}

static struct ecc_test_ctx *x_create_sw_compute_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
			printf("malloc failed.\n");
			return NULL;
	}

	test_ctx->op = ECDH_SW_COMPUTE;
	test_ctx->key_size = setup.key_bits >> 3;

	return test_ctx;
}

static struct ecc_test_ctx *ecc_create_sw_compute_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	struct ecdh_sw_opdata *req;

	EC_KEY *key_a = NULL;
	EC_KEY *key_b = NULL;
	EC_GROUP *group_a, *group_b;
	BIGNUM *privKey, *pubKey;
	EC_POINT *point_tmp, *ptr;
	int ret;

	if (ECDH_SW_COMPUTE != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	key_a = EC_KEY_new();
	if (!key_a) {
		printf("EC_KEY_new err!\n");
		return NULL;
	}

	group_a = EC_GROUP_new_by_curve_name(setup.nid);
	if(!group_a) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		goto free_ec_key_a;
	}

	ret = EC_KEY_set_group(key_a, group_a);
	if(ret != 1) {
		printf("EC_KEY_set_group err.\n");
		goto free_ec_key_a;
	}

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
		goto free_ec_key_a;
	}

	req = malloc(sizeof(struct ecdh_sw_opdata));
	if (!req) {
		EC_KEY_free(key_a);
		free(test_ctx);
		goto free_ctx;
	}

	memset(req, 0, sizeof(struct ecdh_sw_opdata));
	test_ctx->req = req;

	req->share_key = malloc((setup.key_bits >> 3) * 3);
	if (!req->share_key) {
		goto free_opdata;
	}
	req->share_key_size = (setup.key_bits >> 3) * 3;

	if (setup.key_from) {
		point_tmp = EC_GROUP_get0_generator(group_a);
		pubKey = BN_bin2bn(setup.except_pub_key, setup.except_pub_key_size, NULL);
		ptr = EC_POINT_bn2point(group_a, pubKey, point_tmp, NULL);
		if (!ptr) {
			printf("EC_POINT_bn2point failed\n");
			BN_free(pubKey);
			goto free_opdata;
		}
		BN_free(pubKey);
		req->except_pub_key = point_tmp;
		privKey = BN_bin2bn(setup.d, setup.d_size, NULL);
		ret = EC_KEY_set_private_key(key_a, privKey);
		if (ret != 1) {
			printf("EC_KEY_set_private_key failed\n");
			goto free_opdata;
		}
		BN_free(privKey);
	} else {
		ret = EC_KEY_generate_key(key_a);
		if(ret != 1) {
			printf("EC_KEY_generate_key err.\n");
			goto free_share_key;
		}

		key_b = EC_KEY_new();
		if (!key_b) {
			printf("EC_KEY_new err!\n");
			goto free_share_key;
		}

		group_b = EC_GROUP_new_by_curve_name(setup.nid);
		if(!group_b) {
			printf("EC_GROUP_new_by_curve_name err!\n");
			goto free_ec_key_b;
		}

		ret = EC_KEY_set_group(key_b, group_b);
		if(ret != 1) {
			printf("EC_KEY_set_group err.\n");
			goto free_ec_key_b;
		}

		ret = EC_KEY_generate_key(key_b);
		if(ret != 1) {
			printf("EC_KEY_generate_key err.\n");
			goto free_ec_key_b;
		}

		req->except_pub_key = EC_POINT_dup(EC_KEY_get0_public_key(key_b), group_b);
		if (!req->except_pub_key) {
			printf("EC_KEY_get0_public_key err.\n");
			goto free_ec_key_b;
		}

		EC_GROUP_free(group_b);
#ifdef DEBUG
	printf("except_pub_key:\n");
	ECParameters_print_fp(stdout, key_b);
	EC_KEY_print_fp(stdout, key_b, 0);
#endif
		EC_KEY_free(key_b);
	}

	EC_GROUP_free(group_a);
	test_ctx->op = ECDH_SW_COMPUTE;
	test_ctx->priv = key_a;
	test_ctx->key_size = setup.key_bits >> 3;

#ifdef DEBUG
	ECParameters_print_fp(stdout, key_a);
	EC_KEY_print_fp(stdout, key_a, 0);
#endif
	return test_ctx;

free_ec_key_b:
	EC_KEY_free(key_b);
free_share_key:
	free(req->share_key);
free_opdata:
	free(test_ctx->req);
free_ctx:
	free(test_ctx);
free_ec_key_a:
	EC_KEY_free(key_a);

	return NULL;
}

/* id = 1: x25519, 32byte,
 * id = 2: x448, 56byte; */
#define KEYLENID(id)	(id == 1) ? 32 : 56
int x_genkey_by_openssl(struct ecc_test_ctx *test_ctx,
			struct wd_ecc_key *ecc_key,
			int key_size, int id)
{
	EVP_PKEY_METHOD *pmeth;
	EVP_PKEY_CTX ctx;
	struct wd_dtb d;
	EVP_PKEY pkey;
	int ret;

	memset(&pkey, 0, sizeof(EVP_PKEY));
	if (id == 1) {
		pkey.save_type = EVP_PKEY_X25519;
		pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519);
	} else { //if (id == 2)
		pkey.save_type = EVP_PKEY_X448;
		pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448);
	}
	ctx.pmeth = pmeth;
	ret = pmeth->keygen(&ctx, &pkey);
	if (ret <= 0) {
		return -1;
	}

	ECX_KEY *ecx = NULL;
	ecx = (ECX_KEY *)(pkey.pkey.ptr);
	char *data = calloc(key_size, sizeof(char));
	char data_pub[key_size];
	int i;

	memset(data_pub, 0, key_size);
	// ×ª´ó¶Ë£¬¸øHPREÓÃ
	for (i = 0; i < key_size; i++) {
		data[i] = ecx->privkey[key_size - i -1];
		data_pub[i] = ecx->pubkey[key_size - i -1];
	}
	d.data = data;
	d.dsize = key_size;
	d.bsize = key_size;

	ret = wd_set_ecc_prikey(ecc_key, &d);
	if (ret) {
		HPRE_TST_PRT("%s: set prikey err\n", __func__);
		return 0;
	}

	memcpy(test_ctx->cp_pub_key, data_pub, key_size);
	test_ctx->cp_pub_key_size = key_size;

	free(data);
    return 1;
}

static struct ecc_test_ctx *ecc_create_hw_gen_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_op_data *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_out *ecc_out;
	void *ctx = setup.ctx;
	struct wd_dtb d;
	int ret;
	u32 key_size;

	if (!setup.q || !setup.pool) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_ecc_op_data));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_op_data));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_opdata;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_get_ecc_key_bits(ctx) + 7) / 8;
	test_ctx->cp_pub_key = malloc(2 * key_size);
	if (!test_ctx->cp_pub_key) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_ctx;
	}

	ecc_out = wd_rsa_new_ecxdh_out(ctx);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_cp_key;
	}

	ecc_key = wd_get_ecc_key(ctx);

	if (setup.key_from) {  // performance || async ,the param is ready by curve
		if (!setup.d || !setup.cp_pub_key ||
			!setup.cp_pub_key_size) {
			HPRE_TST_PRT("%s: d parm err\n", __func__);
			goto del_ecc_out;
		}

		if ((!g_is_set_prikey && is_async_test(op_type)) || !is_async_test(op_type)) {
			d.data = setup.d;
			d.dsize = setup.d_size;
			d.bsize = setup.d_size;
			ret = wd_set_ecc_prikey(ecc_key, &d);
			if (ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				goto del_ecc_out;
			}
			g_is_set_prikey = true;
		}

		if (op_type >= X25519_GEN && op_type <= X448_ASYNC_COMPUTE) {
			memcpy(test_ctx->cp_pub_key, setup.cp_pub_key, key_size);
			test_ctx->cp_pub_key_size = setup.cp_pub_key_size;
		} else {
			memcpy(test_ctx->cp_pub_key, setup.cp_pub_key + 1, key_size * 2);
			test_ctx->cp_pub_key_size = setup.cp_pub_key_size - 1;
		}
	} else { // sync && not performance, the prikey/pubkey are from openssl
		if (op_type == X25519_GEN ||op_type == X25519_COMPUTE) { // x25519
			ret = x_genkey_by_openssl(test_ctx, ecc_key, key_size, 1);
			if (ret == 0) {
				return NULL;
			}
		} else if (op_type == X448_GEN ||op_type == X448_COMPUTE) { // x448
			ret = x_genkey_by_openssl(test_ctx, ecc_key, key_size, 2);
			if (ret == 0) {
				return NULL;
			}
		} else { // ecdh
			EC_KEY *key_a = NULL;
			EC_GROUP *group_a;
			EC_POINT *point;
			BIGNUM *d;
			struct wd_dtb dtb_d;
			char *tmp;
			size_t len;

			key_a = EC_KEY_new();
			if (!key_a) {
				printf("EC_KEY_new err!\n");
				goto del_ecc_out;
			}

			group_a = EC_GROUP_new_by_curve_name(setup.nid);
			if(!group_a) {
				printf("EC_GROUP_new_by_curve_name err!\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			ret = EC_KEY_set_group(key_a, group_a);
			if(ret != 1) {
				printf("EC_KEY_set_group err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			ret = EC_KEY_generate_key(key_a);
			if(ret != 1) {
				printf("EC_KEY_generate_key err.\n");
				ECParameters_print_fp(stdout, key_a);
				EC_KEY_print_fp(stdout, key_a, 4);
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			d = EC_KEY_get0_private_key(key_a);
			if (!d) {
				printf("EC_KEY_get0_private_key err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			tmp = malloc(key_size);
			if (!tmp) {
				printf("malloc fail!\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			memset(tmp, 0, key_size);
			dtb_d.dsize = BN_bn2bin(d, (void *)tmp);
			dtb_d.bsize = key_size;
			dtb_d.data = tmp;
			ret = wd_set_ecc_prikey(ecc_key, &dtb_d);
			if (ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				EC_KEY_free(key_a);
				free(tmp);
				goto del_ecc_out;
			}
			free(tmp);

			point = EC_KEY_get0_public_key(key_a);
			if (!point) {
				printf("EC_KEY_get0_public_key err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}
			len = EC_POINT_point2buf(group_a, point, 4, &tmp, NULL);
			memcpy(test_ctx->cp_pub_key, tmp + 1, 2 * key_size);
			test_ctx->cp_pub_key_size = len - 1;

			EC_GROUP_free(group_a);
			OPENSSL_free(tmp);
			EC_KEY_free(key_a);
		}
	}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_get_ecc_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	req->op_type = WD_ECXDH_GEN_KEY;
	req->dst = ecc_out;
	test_ctx->req = req;
	test_ctx->pool = setup.pool;
	test_ctx->op = setup.op_type;
	test_ctx->priv = ctx; //init ctx
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_out:
	(void)wd_del_ecc_out(ctx, ecc_out);
free_cp_key:
	free(test_ctx->cp_pub_key);
free_ctx:
	free(test_ctx);
free_opdata:
	free(req);

	return NULL;
}

/* return 1: ok;
 * return 0: err;
 */
int x_compkey_by_openssl(struct ecc_test_ctx *test_ctx, void *ctx,
			 struct wd_ecc_in **ecc_in,
			 struct wd_ecc_key *ecc_key,
			 size_t key_size, int id)
{
	/* gen prikey && pubkey */
	EVP_PKEY_METHOD *pmeth;
	EVP_PKEY_CTX pkey_ctx;
	struct wd_dtb d;
	EVP_PKEY pkey;
	int ret;

	memset(&pkey_ctx, 0, sizeof(EVP_PKEY_CTX));
	memset(&pkey, 0, sizeof(EVP_PKEY));

	if (id == 1) {
		pkey.save_type = EVP_PKEY_X25519;
		pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519);
	} else { // if (id == 2)
		pkey.save_type = EVP_PKEY_X448;
		pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448);
	}
	pkey_ctx.pmeth = pmeth;
	ret = pmeth->keygen(&pkey_ctx, &pkey);
	if (ret <= 0) {
		return -1;
	}

	ECX_KEY *ecx;
	/* ecx->privkey is prikey, ecx->pubkey is pubkey */
	ecx = (ECX_KEY *)(pkey.pkey.ptr);

	int i;

	char *data = calloc(key_size, sizeof(char));

	// ×ª´ó¶Ë - prikey
	for (i = 0; i < key_size; i++) {
		data[i] = ecx->privkey[key_size - i -1];
	}
	d.data = data;
	d.dsize = key_size;
	d.bsize = key_size;

	/* set the prikey */
	ret = wd_set_ecc_prikey(ecc_key, &d);
	if (ret) {
		HPRE_TST_PRT("%s: set prikey err\n", __func__);
		return 0;
	}

	/* set the pubkey(point_in) */
	struct wd_ecc_point tmp;

	// ×ª´ó¶Ë - x
	memset(data, 0, key_size);
	for (i = 0; i <key_size; i++) {
		data[i] = ecx->pubkey[key_size - i -1];
	}
	tmp.x.data = data;
	tmp.x.dsize = key_size;
	tmp.x.bsize = key_size;
	tmp.y.data = tmp.x.data; // + key_size;
	tmp.y.dsize = key_size;
	tmp.y.bsize = key_size;

	*ecc_in = wd_rsa_new_ecxdh_in(ctx, &tmp);
	if (!*ecc_in) {
		printf("%s, wd_rsa_new_ecxdh_in err.\n", __func__);
		return 0;
	}
	/* gen prikey && pubkey end */

	/* compute the key start*/
	memset(&pkey_ctx, 0, sizeof(EVP_PKEY_CTX));
	pkey_ctx.pkey = &pkey;
	pkey_ctx.peerkey = &pkey;

	/* out_shared_key: out shared key */
	uint8_t *out_shared_key = calloc(key_size, sizeof(char));

	ret = pmeth->derive(&pkey_ctx, out_shared_key, &key_size);
	if (ret == 0) {
		HPRE_TST_PRT("%s: pmeth->derive err.\n", __func__);
		return 0;
	}

	// ×ª´ó¶Ë - shared-key
	char share_big[key_size];
	memset(share_big, 0, key_size);
	for (i = 0; i <key_size; i++) {
		share_big[i] = out_shared_key[key_size - i -1];
	}
	/* get the expected_shared_key */
	memcpy(test_ctx->cp_share_key, share_big, key_size);
	test_ctx->cp_share_key_size = key_size;

	free(data);
	return 1;
}

static struct ecc_test_ctx *ecc_create_hw_compute_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_op_data *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_in *ecc_in;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_point tmp;
	void *ctx = setup.ctx;
	struct wd_dtb d;
	int ret;
	u32 key_size;
	size_t len;

	if (!setup.q || !setup.pool) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_ecc_op_data));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_op_data));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_opdata;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_get_ecc_key_bits(setup.ctx) + 7) / 8;
	test_ctx->cp_share_key = malloc(key_size * 4);
	if (!test_ctx->cp_share_key) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_ctx;
	}

	ecc_out = wd_rsa_new_ecxdh_out(ctx);
	if (!ecc_out) {
		goto free_cp_key;
	}

	ecc_key = wd_get_ecc_key(ctx);
	if (setup.key_from) {
		if (op_type == X25519_GEN || op_type == X25519_COMPUTE ||
		    op_type == X448_GEN || op_type == X448_COMPUTE ||
		    op_type == X25519_ASYNC_GEN || op_type == X25519_ASYNC_COMPUTE ||
		    op_type == X448_ASYNC_GEN || op_type == X448_ASYNC_COMPUTE) {
			tmp.x.data = setup.except_pub_key;
		} else {
			tmp.x.data = setup.except_pub_key + 1; // step 0x04
		}
		tmp.x.bsize = key_size;
		tmp.x.dsize = key_size;
		tmp.y.data = tmp.x.data + key_size;
		tmp.y.bsize = key_size;
		tmp.y.dsize = key_size;
		ecc_in = wd_rsa_new_ecxdh_in(ctx, &tmp);
		if (!ecc_in) {
			goto del_ecc_out;
		}

		if ((!g_is_set_prikey && is_async_test(op_type)) || !is_async_test(op_type)) {
			d.data = setup.d;
			d.dsize = setup.d_size;
			d.bsize = setup.d_size;
			ret = wd_set_ecc_prikey(ecc_key, &d);
			if (ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				goto del_ecc_in;
			}
			g_is_set_prikey = true;
		}

		memcpy(test_ctx->cp_share_key, setup.cp_share_key, setup.cp_share_key_size);
		test_ctx->cp_share_key_size = setup.cp_share_key_size;
	} else {
		if (op_type == X25519_GEN ||op_type == X25519_COMPUTE) { // x25519
			ret = x_compkey_by_openssl(test_ctx, ctx, &ecc_in, ecc_key, key_size, 1);
			if (ret == 0) {
				return NULL;
			}
		} else if (op_type == X448_GEN ||op_type == X448_COMPUTE) { // x448
			ret = x_compkey_by_openssl(test_ctx, ctx, &ecc_in, ecc_key, key_size, 2);
			if (ret == 0) {
				return NULL;
			}
		} else { // ecdh
			EC_KEY *key_a = NULL;
			EC_GROUP *group_a;
			EC_POINT *point;
			BIGNUM *d;
			struct wd_dtb dtb_d;
			char *buff;

			key_a = EC_KEY_new();
			if (!key_a) {
				printf("EC_KEY_new err!\n");
				goto del_ecc_out;
			}

			group_a = EC_GROUP_new_by_curve_name(setup.nid);
			if(!group_a) {
				printf("EC_GROUP_new_by_curve_name err!\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			ret = EC_KEY_set_group(key_a, group_a);
			if(ret != 1) {
				printf("EC_KEY_set_group err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			ret = EC_KEY_generate_key(key_a);
			if(ret != 1) {
				printf("EC_KEY_generate_key err.\n");
				ECParameters_print_fp(stdout, key_a);
				EC_KEY_print_fp(stdout, key_a, 4);
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			d = EC_KEY_get0_private_key(key_a);
			if (!d) {
				printf("EC_KEY_get0_private_key err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			buff = malloc(key_size);
			if (!buff) {
				printf("malloc fail!\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			dtb_d.dsize = BN_bn2bin(d, (void *)buff);
			dtb_d.bsize = key_size;
			dtb_d.data = buff;
			ret = wd_set_ecc_prikey(ecc_key, &dtb_d);
			if (ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				EC_KEY_free(key_a);
				free(buff);
				goto del_ecc_out;
			}
			free(buff);

			point = EC_KEY_get0_public_key(key_a);
			if (!point) {
				printf("EC_KEY_get0_public_key err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			len = EC_POINT_point2buf(group_a, point, 4, &buff, NULL);
			if (len != 2 * key_size + 1) {
				printf("EC_POINT_point2buf err.\n");
			}

			EC_GROUP_free(group_a);

			tmp.x.data = buff + 1;
			tmp.x.dsize = key_size;
			tmp.x.bsize = key_size;
			tmp.y.data = tmp.x.data + key_size;
			tmp.y.dsize = key_size;
			tmp.y.bsize = key_size;
			ecc_in = wd_rsa_new_ecxdh_in(ctx, &tmp);
			if (!ecc_in) {
				printf("wd_rsa_new_ecxdh_in err.\n");
				EC_KEY_free(key_a);
				free(buff);
				goto del_ecc_out;
			}

	#ifdef DEBUG
			//print_data(buff + 1, len - 1, "except_pub_key");
	#endif
			free(buff);

			ret = ECDH_compute_key(test_ctx->cp_share_key, key_size * 4,
				point, key_a, NULL);
			if (ret <= 0) {
				printf("ECDH_compute_key err.\n");
				EC_KEY_free(key_a);
				goto del_ecc_out;
			}

			test_ctx->cp_share_key_size = ret;
			EC_KEY_free(key_a);
		}
	}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_get_ecc_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_share_key, test_ctx->cp_share_key_size, "cp_share_key");
#endif

	req->op_type = WD_ECXDH_COMPUTE_KEY;
	req->src = ecc_in;
	req->dst = ecc_out;
	test_ctx->req = req;
	test_ctx->pool = setup.pool;
	test_ctx->op = setup.op_type;
	test_ctx->priv = setup.ctx; //init ctx
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_in:
	(void)wd_del_ecc_in(ctx, ecc_in);
del_ecc_out:
	(void)wd_del_ecc_out(ctx, ecc_out);
free_cp_key:
	free(test_ctx->cp_pub_key);
free_ctx:
	free(test_ctx);
free_opdata:
	free(req);

	return NULL;
}

/* for x25519/x448, to be added*/
int x_dh_init_test_ctx_setup(struct ecc_test_ctx_setup *setup, __u32 op_type)
{
	if (!setup)
		return -1;
	if (performance_test || is_async_test(op_type))
		setup->key_from = 1; //0 - Openssl  1 - Designed
	else
		setup->key_from = 0; //0 - Openssl  1 - Designed

	setup->key_bits = key_bits;

	if (!setup->key_from)
		return 0;

	if (op_type == X25519_GEN || op_type == X25519_COMPUTE ||
	    op_type == X25519_ASYNC_GEN || op_type == X25519_ASYNC_COMPUTE) {
		// ÓÃ´ó¶Ë
		setup->d = x25519_aprikey_big;
		setup->except_pub_key = x25519_bpubkey_big;
		setup->cp_pub_key = x25519_apubke_big;
		setup->cp_share_key = x25519_absharekey_big;
		setup->d_size = 32;
		setup->except_pub_key_size = 32;
		setup->cp_pub_key_size = 32;
		setup->cp_share_key_size = 32;
	} else if (op_type == X448_GEN || op_type == X448_COMPUTE ||
		   op_type == X448_ASYNC_GEN || op_type == X448_ASYNC_COMPUTE) {
		// ÓÃ´ó¶Ë
		setup->d = x448_aprikey_big;
		setup->except_pub_key = x448_bpubkey_big;
		setup->cp_pub_key = x448_apubkey_big;
		setup->cp_share_key = x448_absharekey_big;
		setup->d_size = 56;
		setup->except_pub_key_size = 56;
		setup->cp_pub_key_size = 56;
		setup->cp_share_key_size = 56;
	} else {
		HPRE_TST_PRT("init x25519/x448 test ctx setup not find this bits %d\n", key_bits);
		return -1;
	}

	return 0;
}

static struct ecc_test_ctx *ecc_create_sw_sign_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	struct ecdh_sw_opdata *req;
	EC_KEY *key_a = NULL;
	EC_GROUP *group_a;
	BIGNUM *kinv, *privKey, *rp;
	int size;
	int ret;

	if (ECC_SW_SIGN != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	key_a = EC_KEY_new();
	if (!key_a) {
		printf("EC_KEY_new err!\n");
		return NULL;
	}

	group_a = EC_GROUP_new_by_curve_name(setup.nid);
	if(!group_a) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		goto free_ec_key_a;
	}

	ret = EC_KEY_set_group(key_a, group_a);
	if(ret != 1) {
		printf("EC_KEY_set_group err.\n");
		goto free_ec_key_a;
	}
	EC_GROUP_free(group_a);

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
		goto free_ec_key_a;
	}

	req = malloc(sizeof(struct ecdh_sw_opdata));
	if (!req) {
		EC_KEY_free(key_a);
		free(test_ctx);
		goto free_ctx;
	}

	memset(req, 0, sizeof(struct ecdh_sw_opdata));
	test_ctx->req = req;
	size = ECDSA_size(key_a);
	req->sign = malloc(size);
	memset(req->sign, 0, size);
	if (!req->sign) {
		goto free_opdata;
	}

	if (setup.key_from) {
		req->except_e = setup.degist;
		req->except_e_size = setup.degist_size;
		kinv = BN_bin2bn(setup.kinv, setup.kinv_size, NULL); // kinv invalid, actual should 1/kinv
		req->except_kinv = kinv;
		rp = BN_bin2bn(setup.rp, setup.rp_size, NULL);
		req->except_rp = rp;
		privKey = BN_bin2bn(setup.d, setup.d_size, NULL);
		ret = EC_KEY_set_private_key(key_a, privKey);
		if (ret != 1) {
			printf("EC_KEY_set_private_key failed\n");
			goto free_sign;
		}
		BN_free(privKey);
	} else {}

	test_ctx->op = setup.op_type;
	test_ctx->priv = key_a;
	test_ctx->key_size = setup.key_bits >> 3;
#ifdef DEBUG
	ECParameters_print_fp(stdout, key_a);
	EC_KEY_print_fp(stdout, key_a, 0);
#endif
	return test_ctx;

free_sign:
	free(req->sign);
free_opdata:
	free(test_ctx->req);
free_ctx:
	free(test_ctx);
free_ec_key_a:
	EC_KEY_free(key_a);

	return NULL;
}

static struct ecc_test_ctx *ecc_create_sw_verf_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	struct ecdh_sw_opdata *req;
	EC_KEY *key_a = NULL;
	EC_GROUP *group_a;
	BIGNUM *pubkey;
	EC_POINT *point_tmp, *ptr;
	int ret;

	if (ECC_SW_VERF != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	key_a = EC_KEY_new();
	if (!key_a) {
		printf("EC_KEY_new err!\n");
		return NULL;
	}

	group_a = EC_GROUP_new_by_curve_name(setup.nid);
	if(!group_a) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		goto free_ec_key_a;
	}

	ret = EC_KEY_set_group(key_a, group_a);
	if(ret != 1) {
		printf("EC_KEY_set_group err.\n");
		goto free_ec_key_a;
	}

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
		goto free_ec_key_a;
	}

	req = malloc(sizeof(struct ecdh_sw_opdata));
	if (!req) {
		EC_KEY_free(key_a);
		free(test_ctx);
		goto free_ctx;
	}

	memset(req, 0, sizeof(struct ecdh_sw_opdata));
	test_ctx->req = req;

	if (setup.key_from) {
		req->except_e = setup.degist;
		req->except_e_size = setup.degist_size;
		req->sign = setup.sign;
		req->sign_size = setup.sign_size;

		point_tmp = EC_GROUP_get0_generator(group_a);
		pubkey = BN_bin2bn(setup.cp_pub_key, setup.cp_pub_key_size, NULL);
		ptr = EC_POINT_bn2point(group_a, pubkey, point_tmp, NULL);
		if (!ptr) {
			printf("EC_POINT_bn2point failed\n");
			BN_free(pubkey);
			goto free_opdata;
		}

		ret = EC_KEY_set_public_key(key_a, point_tmp);
		if (ret != 1) {
			printf("EC_KEY_set_public_key failed\n");
			BN_free(pubkey);
			goto free_opdata;
		}
		BN_free(pubkey);
	} else {}

	EC_GROUP_free(group_a);
	test_ctx->op = setup.op_type;
	test_ctx->priv = key_a;
	test_ctx->key_size = setup.key_bits >> 3;
#ifdef DEBUG
	ECParameters_print_fp(stdout, key_a);
	EC_KEY_print_fp(stdout, key_a, 0);
#endif
	return test_ctx;

free_opdata:
	free(test_ctx->req);
free_ctx:
	free(test_ctx);
free_ec_key_a:
	EC_KEY_free(key_a);

	return NULL;
}

static struct ecc_test_ctx *ecc_create_hw_sign_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{

	struct wd_ecc_op_data *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in = NULL;
	struct wd_ecc_point pub;
	EC_POINT *point_tmp, *ptr;
	EC_KEY *key_a = NULL;
	EC_GROUP *group_a;
	BIGNUM *pubKey;
	void *ctx = setup.ctx;
	struct wd_dtb d, e, k;
	int ret;
	u32 key_size;

	if (!setup.q || !setup.pool) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_ecc_op_data));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_op_data));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_opdata;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_get_ecc_key_bits(ctx) + 7) / 8;
	ecc_out = wd_rsa_new_ecdsa_sign_out(ctx);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}
	ecc_key = wd_get_ecc_key(ctx);
	if (!g_is_set_prikey || !is_async_test(op_type)) {
		d.data = setup.d;
		d.dsize = setup.d_size;
		d.bsize = setup.d_size;
		ret = wd_set_ecc_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("%s: set prikey err\n", __func__);
			goto del_ecc_out;
		}
		g_is_set_prikey = true;
	}

	if (!g_is_set_pubkey || !is_async_test(op_type)) {
		pub.x.data = setup.cp_pub_key + 1;
		pub.x.dsize = key_size;
		pub.x.bsize = key_size;
		pub.y.data = pub.x.data + key_size;
		pub.y.dsize = key_size;
		pub.y.bsize = key_size;
		ret = wd_set_ecc_pubkey(ecc_key, &pub);
		if (ret) {
			HPRE_TST_PRT("%s: set pubkey err\n", __func__);
			goto del_ecc_out;
		}
		g_is_set_pubkey = true;
	}

	e.data = setup.degist;
	e.dsize = setup.degist_size;
	e.bsize = key_size;

	if (setup.key_from) {
		k.data = setup.kinv;
		k.dsize = setup.kinv_size;
		k.bsize = key_size;
		ecc_in = wd_rsa_new_ecdsa_sign_in(ctx, &e, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
	} else {
		key_a = EC_KEY_new();
		if (!key_a) {
			printf("EC_KEY_new err!\n");
			goto del_ecc_out;
		}

		group_a = EC_GROUP_new_by_curve_name(setup.nid);
		if(!group_a) {
			printf("EC_GROUP_new_by_curve_name err!\n");
			EC_KEY_free(key_a);
			goto del_ecc_out;
		}

		ret = EC_KEY_set_group(key_a, group_a);
		if(ret != 1) {
			printf("EC_KEY_set_group err.\n");
			EC_KEY_free(key_a);
			EC_GROUP_free(group_a);
			goto del_ecc_out;
		}

		/* set pubkey */
		point_tmp = EC_GROUP_get0_generator(group_a);
		pubKey = BN_bin2bn(setup.cp_pub_key, setup.cp_pub_key_size, NULL);
		ptr = EC_POINT_bn2point(group_a, pubKey, point_tmp, NULL);
		if (!ptr) {
			printf("EC_POINT_bn2point failed\n");
			BN_free(pubKey);
			EC_KEY_free(key_a);
			EC_GROUP_free(group_a);
			goto del_ecc_out;
		}

		ret = EC_KEY_set_public_key(key_a, point_tmp);
		if (ret != 1) {
			printf("EC_KEY_set_public_key failed\n");
			BN_free(pubKey);
			EC_KEY_free(key_a);
			EC_GROUP_free(group_a);
			goto del_ecc_out;
		}
		BN_free(pubKey);
		EC_GROUP_free(group_a);

		ecc_in = wd_rsa_new_ecdsa_sign_in(ctx, &e, NULL);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
	}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_get_ecc_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	req->op_type = WD_ECDSA_SIGN;
	req->dst = ecc_out;
	req->src = ecc_in;
	test_ctx->req = req;
	test_ctx->pool = setup.pool;
	test_ctx->op = setup.op_type;
	test_ctx->priv = ctx; //init ctx
	test_ctx->key_size = key_size;
	test_ctx->priv1 = key_a;

	return test_ctx;

del_ecc_out:
	(void)wd_del_ecc_out(ctx, ecc_out);
free_ctx:
	free(test_ctx);
free_opdata:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *ecc_create_hw_verf_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_op_data *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_in *ecc_in;
	EC_KEY *key_a = NULL;
	EC_GROUP *group_a;
	BIGNUM *privKey;
	ECDSA_SIG *sig;
	BIGNUM *b_r, *b_s;
	unsigned char buf1[100];
	unsigned char buf2[100];
	void *ctx = setup.ctx;
	struct wd_dtb e, r, s;
	struct wd_ecc_point pub;
	int ret;
	u32 key_size;

	if (!setup.q || !setup.pool) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_ecc_op_data));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_op_data));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_opdata;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_get_ecc_key_bits(ctx) + 7) / 8;
	ecc_key = wd_get_ecc_key(ctx);
	if (!g_is_set_pubkey  || !is_async_test(op_type)) {
		pub.x.data = setup.cp_pub_key + 1;
		pub.x.dsize = key_size;
		pub.x.bsize = key_size;
		pub.y.data = pub.x.data + key_size;
		pub.y.dsize = key_size;
		pub.y.bsize = key_size;
		ret = wd_set_ecc_pubkey(ecc_key, &pub);
		if (ret) {
			HPRE_TST_PRT("%s: set pubkey err\n", __func__);
			goto free_ctx;
		}
		g_is_set_pubkey = true;
	}

	e.data = setup.degist;
	e.dsize = setup.degist_size;
	e.bsize = key_size;

	if (setup.key_from) {
		r.data = setup.sign + 4;
		r.dsize = key_size;
		r.bsize = key_size;
		s.data = r.data + key_size;
		s.dsize = key_size;
		s.bsize = key_size;
		ecc_in = wd_rsa_new_ecdsa_verf_in(ctx, &e, &r, &s);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto free_ctx;
		}
	} else {
		key_a = EC_KEY_new();
		if (!key_a) {
			printf("EC_KEY_new err!\n");
			goto free_ctx;
		}

		group_a = EC_GROUP_new_by_curve_name(setup.nid);
		if(!group_a) {
			printf("EC_GROUP_new_by_curve_name err!\n");
			EC_KEY_free(key_a);
			goto free_ctx;
		}

		ret = EC_KEY_set_group(key_a, group_a);
		if(ret != 1) {
			printf("EC_KEY_set_group err.\n");
			EC_KEY_free(key_a);
			EC_GROUP_free(group_a);
			goto free_ctx;
		}

		/* set prikey */
		privKey = BN_bin2bn(setup.d, setup.d_size, NULL);
		ret = EC_KEY_set_private_key(key_a, privKey);
		if (ret != 1) {
			printf("EC_KEY_set_private_key failed\n");
			EC_KEY_free(key_a);
			EC_GROUP_free(group_a);
			goto free_ctx;
		}
		BN_free(privKey);

		EC_GROUP_free(group_a);

		sig = ECDSA_SIG_new();
		if (!sig) {
			HPRE_TST_PRT("ECDSA_SIG_new fail!\n");
			EC_KEY_free(key_a);
			goto free_ctx;
		}

		/* openssl sign */
		sig = ECDSA_do_sign(setup.degist, setup.degist_size, key_a);
		if (!sig) {
			printf("ECDSA_do_sign failed\n");
			EC_KEY_free(key_a);
			ECDSA_SIG_free(sig);
			goto free_ctx;
		}

		/* get r s */
		b_r = (void *)ECDSA_SIG_get0_r((const ECDSA_SIG *)sig);
		ret = BN_bn2bin(b_r, buf1);
		r.data = (void *)buf1;
		r.dsize = ret;
		r.bsize = key_size;
		b_s = (void *)ECDSA_SIG_get0_s((const ECDSA_SIG *)sig);
		ret = BN_bn2bin(b_s, buf2);
		s.data = (void *)buf2;
		s.dsize = ret;
		s.bsize = key_size;
		ECDSA_SIG_free(sig);
		ecc_in = wd_rsa_new_ecdsa_verf_in(ctx, &e, &r, &s);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			EC_KEY_free(key_a);
			goto free_ctx;
		}
		EC_KEY_free(key_a);
	}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_get_ecc_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	req->op_type = WD_ECDSA_VERIFY;
	req->src = ecc_in;
	test_ctx->req = req;
	test_ctx->pool = setup.pool;
	test_ctx->op = setup.op_type;
	test_ctx->priv = ctx; //init ctx
	test_ctx->key_size = key_size;

	return test_ctx;

free_ctx:
	free(test_ctx);
free_opdata:
	free(req);

	return NULL;
}

int ecxdh_init_test_ctx_setup(struct ecc_test_ctx_setup *setup, __u32 op_type)
{
	int key_size = (key_bits + 7) / 8;

	if (!setup)
		return -1;

	if (performance_test || op_type == ECDH_ASYNC_GEN || op_type == ECDH_ASYNC_COMPUTE)
		setup->key_from = 1; //0 - Openssl  1 - Designed
	else
		setup->key_from = 0; //0 - Openssl  1 - Designed

	setup->key_bits = key_bits;

	if (setup->nid == 714 || key_bits == 256) { //NID_secp256k1
		setup->d = ecdh_da_secp256k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp256k1;
		setup->cp_pub_key = ecdh_cp_pubkey_secp256k1;
		setup->cp_share_key = ecdh_cp_sharekey_secp256k1;
		setup->d_size = sizeof(ecdh_da_secp256k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp256k1);
		setup->cp_pub_key_size = sizeof(ecdh_cp_pubkey_secp256k1);
		setup->cp_share_key_size = sizeof(ecdh_cp_sharekey_secp256k1);

		/* ecc sign */
		setup->degist = ecc_except_e_secp256k1;
		setup->degist_size = sizeof(ecc_except_e_secp256k1);
		setup->kinv = ecc_except_kinv_secp256k1;
		setup->kinv_size = sizeof(ecc_except_kinv_secp256k1);
		setup->rp = ecdh_cp_pubkey_secp256k1 + 1;
		setup->rp_size = key_size;
		setup->cp_sign = ecdh_cp_pubkey_secp256k1 + 1; //todo
		setup->cp_sign_size = 32; //todo

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
	} else if (setup->nid == 706 || key_bits == 128) {
		setup->d = ecdh_da_secp128k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp128k1;
		setup->cp_pub_key = ecdh_cp_pubkey_secp128k1;
		setup->cp_share_key = ecdh_cp_sharekey_secp128k1;
		setup->d_size = sizeof(ecdh_da_secp128k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp128k1);
		setup->cp_pub_key_size = sizeof(ecdh_cp_pubkey_secp128k1);
		setup->cp_share_key_size = sizeof(ecdh_cp_sharekey_secp128k1);

		/* ecc sign */
		setup->degist = ecc_except_e_secp128k1;
		setup->degist_size = sizeof(ecc_except_e_secp128k1);
		setup->kinv = ecc_except_kinv_secp128k1;
		setup->kinv_size = sizeof(ecc_except_kinv_secp128k1);
		setup->rp = ecdh_cp_pubkey_secp128k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else if (setup->nid == 711 || key_bits == 192) {
		setup->d = ecdh_da_secp192k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp192k1;
		setup->cp_pub_key = ecdh_cp_pubkey_secp192k1;
		setup->cp_share_key = ecdh_cp_sharekey_secp192k1;
		setup->d_size = sizeof(ecdh_da_secp192k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp192k1);
		setup->cp_pub_key_size = sizeof(ecdh_cp_pubkey_secp192k1);
		setup->cp_share_key_size = sizeof(ecdh_cp_sharekey_secp192k1);

		/* ecc sign */
		setup->degist = ecc_except_e_secp192k1;
		setup->degist_size = sizeof(ecc_except_e_secp192k1);
		setup->kinv = ecc_except_kinv_secp192k1;
		setup->kinv_size = sizeof(ecc_except_kinv_secp192k1);
		setup->rp = ecdh_cp_pubkey_secp192k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
	} else if (setup->nid == 929 || key_bits == 320) {
		setup->d = ecdh_da_secp320k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp320k1;
		setup->cp_pub_key = ecdh_cp_pubkey_secp320k1;
		setup->cp_share_key = ecdh_cp_sharekey_secp320k1;
		setup->d_size = sizeof(ecdh_da_secp320k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp320k1);
		setup->cp_pub_key_size = sizeof(ecdh_cp_pubkey_secp320k1);
		setup->cp_share_key_size = sizeof(ecdh_cp_sharekey_secp320k1);

		/* ecc sign */
		setup->degist = ecc_except_e_secp320k1;
		setup->degist_size = sizeof(ecc_except_e_secp320k1);
		setup->kinv = ecc_except_kinv_secp320k1;
		setup->kinv_size = sizeof(ecc_except_kinv_secp320k1);
		setup->rp = ecdh_cp_pubkey_secp192k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else if (setup->nid == 931 || key_bits == 384) {
		setup->d = ecdh_da_secp384k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp384k1;
		setup->cp_pub_key = ecdh_cp_pubkey_secp384k1;
		setup->cp_share_key = ecdh_cp_sharekey_secp384k1;
		setup->d_size = sizeof(ecdh_da_secp384k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp384k1);
		setup->cp_pub_key_size = sizeof(ecdh_cp_pubkey_secp384k1);
		setup->cp_share_key_size = sizeof(ecdh_cp_sharekey_secp384k1);

		/* ecc sign */
		setup->degist = ecc_except_e_secp384k1;
		setup->degist_size = sizeof(ecc_except_e_secp384k1);
		setup->kinv = ecc_except_kinv_secp384k1;
		setup->kinv_size = sizeof(ecc_except_kinv_secp384k1);
		setup->rp = ecdh_cp_pubkey_secp384k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else if (setup->nid == 716 || key_bits == 521) {
		setup->d = ecdh_da_secp521k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp521k1;
		setup->cp_pub_key = ecdh_cp_pubkey_secp521k1;
		setup->cp_share_key = ecdh_cp_sharekey_secp521k1;
		setup->d_size = sizeof(ecdh_da_secp521k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp521k1);
		setup->cp_pub_key_size = sizeof(ecdh_cp_pubkey_secp521k1);
		setup->cp_share_key_size = sizeof(ecdh_cp_sharekey_secp521k1);

		/* ecc sign */
		setup->degist = ecc_except_e_secp521k1;
		setup->degist_size = sizeof(ecc_except_e_secp521k1);
		setup->kinv = ecc_except_kinv_secp521k1;
		setup->kinv_size = sizeof(ecc_except_kinv_secp521k1);
		setup->rp = ecdh_cp_pubkey_secp521k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else {
		HPRE_TST_PRT("init test ctx setup not find this bits %d or nid %d\n",
				key_bits, setup->nid);
		return -1;
	}

	return 0;
}

static int get_ecc_nid(const char *name, __u32 *nid, __u32 *curve_id)
{
	int i;

	for (i = 0; i < sizeof(ecc_curve_tbls) / sizeof(ecc_curve_tbls[0]); i++) {

		if (!strcmp(name, ecc_curve_tbls[i].name)) {
			*nid = ecc_curve_tbls[i].nid;
			*curve_id = ecc_curve_tbls[i].curve_id;
			return 0;
		}
	}

	return -1;
}

struct ecc_test_ctx *ecc_create_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx = NULL;

	switch (setup.op_type) {
		case ECDH_SW_GENERATE:
		{
			if (optype == ECDH_GEN || optype == ECDH_ASYNC_GEN) {
				test_ctx = ecc_create_sw_gen_test_ctx(setup, optype);
			} else if (optype == X25519_GEN || optype == X25519_ASYNC_GEN ||
				   optype == X448_GEN || optype == X448_ASYNC_GEN) {
				test_ctx = x_create_sw_gen_test_ctx(setup, optype);
			}
		}
		break;
		case ECDH_HW_GENERATE:
		{
			test_ctx = ecc_create_hw_gen_test_ctx(setup, optype);
		}
		break;
		case ECDH_SW_COMPUTE:
		{
			if (optype == ECDH_COMPUTE || optype == ECDH_ASYNC_COMPUTE) {
				test_ctx = ecc_create_sw_compute_test_ctx(setup, optype);
			} else if (optype == X25519_COMPUTE || optype == X25519_ASYNC_COMPUTE ||
				optype == X448_COMPUTE || optype == X448_ASYNC_COMPUTE) {
				test_ctx = x_create_sw_compute_test_ctx(setup, optype);
			}
		}
		break;
		case ECDH_HW_COMPUTE:
		{
			test_ctx = ecc_create_hw_compute_test_ctx(setup, optype);
		}
		break;
		case ECC_HW_SIGN:
		{
			test_ctx = ecc_create_hw_sign_test_ctx(setup, optype);
		}
		break;
		case ECC_HW_VERF:
		{
			test_ctx = ecc_create_hw_verf_test_ctx(setup, optype);
		}
		break;
		case ECC_SW_SIGN:
		{
			test_ctx = ecc_create_sw_sign_test_ctx(setup, optype);
		}
		break;
		case ECC_SW_VERF:
		{
			test_ctx = ecc_create_sw_verf_test_ctx(setup, optype);
		}
		break;
		default:
		break;
	}


	if (test_ctx)
		test_ctx->setup = setup;

	return test_ctx;
}

int ecdh_generate_key(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == ECDH_SW_GENERATE) {
		if (t_c->is_x25519_x448){
			EVP_PKEY_METHOD *pmeth;
			EVP_PKEY_CTX pkey_ctx;
			size_t key_sz;
			EVP_PKEY pkey;
			ECX_KEY ecx;

			memset(&pkey_ctx, 0, sizeof(EVP_PKEY_CTX));
			memset(&pkey, 0, sizeof(EVP_PKEY));
			memset(&ecx, 0, sizeof(ECX_KEY));

			/* openssl ÓÃÐ¡¶Ë*/
			if (t_c->key_size == 32) { // x25519
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519);
				ecx.privkey = x25519_aprikey;
				memcpy(ecx.pubkey, x25519_x_param, 32);
			} else { // if (t_c->key_size == 56) { // x448
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448);
				ecx.privkey = x448_aprikey;
				memcpy(ecx.pubkey, x448_x_param, 56);
			}
			pkey.pkey.ecx = &ecx;
			pkey_ctx.pkey = &pkey;
			pkey_ctx.peerkey = &pkey;

			uint8_t *out_pub_key = calloc(t_c->key_size, sizeof(char));

			ret = pmeth->derive(&pkey_ctx, out_pub_key, &key_sz);
			if (ret == 0) {
				HPRE_TST_PRT("%s: pmeth->derive err.\n", __func__);
				return -1;
			}
			#if 0
			int i;
			for (i = 0; i < t_c->key_size; i++) {
				if (i % 12 == 0)
					printf("\n");
				printf("0x%x, ", out_pub_key[i]);
			}printf("\n");
			#endif
			free(out_pub_key);
		} else {

			EC_KEY *ec_key = t_c->priv;

			if (!EC_KEY_generate_key(ec_key)) {
				HPRE_TST_PRT("EC_KEY_generate_key fail!\n");
				return -1;
			}
		//#ifdef DEBUG
			ECParameters_print_fp(stdout, ec_key);
			EC_KEY_print_fp(stdout, ec_key, 0);
		//#endif
		}
	} else {
		struct wd_ecc_op_data *req = t_c->req;
		void* ctx = t_c->priv;
try_again:
		ret = wd_do_ecxdh(ctx, req, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecxdh fail!\n");
			return -1;
		}
	}

	return 0;
}

int ecdh_compute_key(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == ECDH_SW_COMPUTE) {
		if (t_c->is_x25519_x448){
			EVP_PKEY_METHOD *pmeth;
			EVP_PKEY_CTX pkey_ctx;
			EVP_PKEY pkey;
			ECX_KEY ecx;
			size_t key_sz;
			int ret;

			memset(&pkey_ctx, 0, sizeof(EVP_PKEY_CTX));
			memset(&pkey, 0, sizeof(EVP_PKEY));
			memset(&ecx, 0, sizeof(ECX_KEY));

			if (t_c->key_size == 32) { // x25519
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519);
				ecx.privkey = x25519_aprikey;
				memcpy(ecx.pubkey, x25519_bpubkey, 32);
			} else { // if (t_c->key_size == 56) { // x448
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448);
				ecx.privkey = x448_aprikey;
				memcpy(ecx.pubkey, x448_bpubkey, 56);
			}
			pkey.pkey.ecx = &ecx;
			pkey_ctx.pkey = &pkey;
			pkey_ctx.peerkey = &pkey;

			uint8_t *out_shared_key = calloc(t_c->key_size, sizeof(char));

			ret = pmeth->derive(&pkey_ctx, out_shared_key, &key_sz);
			if (ret <= 0) {
				HPRE_TST_PRT("%s: pmeth->derive err.\n", __func__);
				return -1;
			}
			#if 0
			int i;
			for (i = 0; i < t_c->key_size; i++) {
				if (i % 12 == 0)
					printf("\n");
				printf("0x%x, ", out_shared_key[i]);
			}printf("\n");
			#endif
			free(out_shared_key);
		} else {
			struct ecdh_sw_opdata *req = t_c->req;
			EC_KEY *ec_key = t_c->priv;
			ret = ECDH_compute_key(req->share_key, req->share_key_size,
				req->except_pub_key, ec_key, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("ECDH_compute_key fail!\n");
				return -1;
			}
			req->share_key_size = ret;
		}
#ifdef DEBUG
	//ECParameters_print_fp(stdout, ec_key);
	//print_data(req->share_key, ret, "openssl share key");

#endif
	} else {
		struct wd_ecc_op_data *req = t_c->req;
		void* ctx = t_c->priv;
try_again:

		ret = wd_do_ecxdh(ctx, req, tag);
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

int ecdsa_sign(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == ECC_SW_SIGN) {
		EC_KEY *ec_key = t_c->priv;
		struct ecdh_sw_opdata *req = t_c->req;

		if (!ECDSA_sign_ex(0, req->except_e, req->except_e_size,
			req->sign, &req->sign_size, req->except_kinv,
			req->except_rp, ec_key)) {
			HPRE_TST_PRT("ECDSA_sign_ex fail!\n");
			return -1;
		}

#ifdef DEBUG
	print_data(req->sign, req->sign_size, "openssl sign");
	ECParameters_print_fp(stdout, ec_key);
	EC_KEY_print_fp(stdout, ec_key, 0);
#endif

	} else {
		struct wd_ecc_op_data *req = t_c->req;
		void* ctx = t_c->priv;
try_again:
		ret = wd_do_ecdsa(ctx, req, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecdsa fail!\n");
			return -1;
		}

		if (tag)
			return 0;
#ifdef DEBUG
	struct wd_dtb *r, *s;
	wd_get_ecdsa_sign_out_params(req->dst, &r, &s);
	print_data(r->data, r->dsize, "hpre r");
	print_data(s->data, s->dsize, "hpre s");
#endif
	}

	return 0;
}

int sm2_sign(void *test_ctx, void *tag)
{
	return 0;
}

int ecdsa_verf(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == ECC_SW_VERF) {
		EC_KEY *ec_key = t_c->priv;
		struct ecdh_sw_opdata *req = t_c->req;

		ret = ECDSA_verify(0, req->except_e, req->except_e_size,
			req->sign, req->sign_size, ec_key);
		if (ret != 1) {
			HPRE_TST_PRT("ECDSA_verify fail = %d!\n", ret);
			return -1;
		}

#ifdef DEBUG
	ECParameters_print_fp(stdout, ec_key);
	EC_KEY_print_fp(stdout, ec_key, 0);
#endif

	} else {
		struct wd_ecc_op_data *req = t_c->req;
		void* ctx = t_c->priv;
try_again:
		ret = wd_do_ecdsa(ctx, req, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			//HPRE_TST_PRT("wd_do_ecdsa fail!\n");
			//return -1;
		}

		if (tag)
			return 0;
#ifdef DEBUG
	printf("hpre verf = %d\n", req->status);
#endif
	}

	return 0;
}

int sm2_verf(void *test_ctx, void *tag)
{
	return 0;
}

int sm2_enc(void *test_ctx, void *tag)
{
	return 0;
}

int sm2_dec(void *test_ctx, void *tag)
{
	return 0;
}

int ecc_point1buf(struct wd_ecc_point *in, int ksz, void *buf, int bsz)
{
	struct wd_dtb *x;
	int ret = 0;

	if (!buf || !in)
		return -1;

	x = &in->x;

	ret = x->dsize;
	if (ret > bsz)
		return -1;

	memcpy(buf, x->data, x->dsize);

	return ret;
}

int ecc_point2buf(struct wd_ecc_point *in, int ksz, void *buf, int bsz)
{
	struct wd_dtb *x, *y;
	int ret = 0;

	if (!buf || !in)
		return -1;

	x = &in->x;
	y = &in->y;

	ret = x->dsize + y->dsize;
	if (ret > bsz)
		return -1;
#ifdef DEBUG
	//print_data(x->data, x->dsize, "x");
	//print_data(y->data, y->dsize, "y");
#endif
	memcpy(buf, x->data, x->dsize);
	memcpy(buf + x->dsize, y->data, y->dsize);

	return ret;
}

static int ecc_sign_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_op_data *req = test_ctx->req;
	struct wd_ecc_in *ecc_in;
	void *ctx = test_ctx->priv;
	EC_KEY *ec_key = test_ctx->priv1;
	ECDSA_SIG *sig;
	struct wd_dtb *r, *s, e;
	BIGNUM *b_r, *b_s;
	int ret;

	/* openssl verf check*/
	sig = ECDSA_SIG_new();
	if (!sig) {
		HPRE_TST_PRT("ECDSA_SIG_new fail!\n");
		return -1;
	}

	wd_get_ecdsa_sign_out_params(req->dst, &r, &s);
	b_r = BN_bin2bn((void *)r->data, r->dsize, NULL);
	b_s = BN_bin2bn((void *)s->data, s->dsize, NULL);
	(void)ECDSA_SIG_set0(sig, b_r, b_s);
	wd_get_ecdsa_sign_in_params(req->src, &e, NULL);
	ret = ECDSA_do_verify((void*)test_ctx->setup.degist,
		test_ctx->setup.degist_size, sig, ec_key);
	if (ret != 1) {
		HPRE_TST_PRT("openssl verf fail = %d!\n", ret);
		print_data(r->data, r->dsize, "r");
		print_data(s->data, s->dsize, "s");
		ECParameters_print_fp(stdout, ec_key);
		EC_KEY_print_fp(stdout, ec_key, 0);
		ECDSA_SIG_free(sig);
		return -1;
	}

	ECDSA_SIG_free(sig);

	if (is_async)
		return 0;

	/* hpre verf check*/
	e.data = test_ctx->setup.degist;
	e.dsize = test_ctx->setup.degist_size;

	ecc_in = wd_rsa_new_ecdsa_verf_in(ctx, &e, r, s);
	if (!ecc_in) {
		HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
		return -1;
	}
	(void)wd_del_ecc_in(ctx, req->src);

	req->src = ecc_in;
	req->op_type = WD_ECDSA_VERIFY;
try_again:
	ret = wd_do_ecdsa(ctx, req, NULL);
	if (ret == -WD_EBUSY) {
		usleep(100);
		goto try_again;
	} else if (ret) {
		HPRE_TST_PRT("wd_do_ecdsa fail!\n");
		return -1;
	}

	return 0;
}

int ecc_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_op_data *req = test_ctx->req;
	void *ctx = test_ctx->priv;
	unsigned char *cp_key;
	u32 cp_size;
	u32 key_size = (wd_get_ecc_key_bits(ctx) + 7) / 8;
	void *o_buf;
	int ret;

	if (!openssl_check)
		return 0;

	if (test_ctx->op == ECDH_HW_GENERATE ||
		test_ctx->op == ECDH_HW_COMPUTE) {
		struct wd_ecc_point *key = NULL;
		BIGNUM *tmp;
		__u32 out_sz;

		if (test_ctx->op == ECDH_HW_GENERATE) {
			cp_key = test_ctx->cp_pub_key;
			cp_size = test_ctx->cp_pub_key_size;
		} else {
			cp_key = test_ctx->cp_share_key;
			cp_size = test_ctx->cp_share_key_size;
		}

		wd_get_ecxdh_out_params(req->dst, &key);
		if (test_ctx->is_x25519_x448)
			o_buf = malloc(key_size);
		else
			o_buf = malloc(key_size * 2);

		if (!o_buf) {
			HPRE_TST_PRT("malloc fail!\n");
			return -1;
		}

		if (test_ctx->op == ECDH_HW_GENERATE) {
			if (test_ctx->is_x25519_x448) {
				ret = ecc_point1buf(key, key_size, o_buf, key_size);
				if (ret < 0) {
					HPRE_TST_PRT("ecc_point1buf fail!\n");
					free(o_buf);
					return -1;
				}
			} else {
				ret = ecc_point2buf(key, key_size, o_buf, key_size * 2);
				if (ret < 0) {
					HPRE_TST_PRT("ecc_point2buf fail!\n");
					free(o_buf);
					return -1;
				}
			}
			out_sz = ret;
			tmp = BN_bin2bn(cp_key, key_size, NULL);
			ret = BN_bn2bin(tmp, cp_key);
			cp_size = ret;
			BN_free(tmp);
			if (!test_ctx->is_x25519_x448) {
				tmp = BN_bin2bn(cp_key + key_size, key_size, NULL);
				ret = BN_bn2bin(tmp, cp_key + ret);
				cp_size += ret;
				BN_free(tmp);
			}

		} else {
			ret = key->x.dsize;
			out_sz = ret;
			memcpy(o_buf, key->x.data, ret);
			tmp = BN_bin2bn(cp_key, key_size, NULL);
			ret = BN_bn2bin(tmp, cp_key);
			cp_size = ret;
			BN_free(tmp);
		}

		if (out_sz != cp_size || memcmp(cp_key, o_buf, cp_size)) {
			HPRE_TST_PRT("ecdh op %d mismatch!\n", test_ctx->op);

//#ifdef DEBUG
			struct wd_ecc_key *ecc_key;
			struct wd_dtb *p = NULL;

			ecc_key = wd_get_ecc_key(test_ctx->priv);
			wd_get_ecc_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);

			print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
			if (test_ctx->op == ECDH_HW_GENERATE)
				print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
			else
				print_data(test_ctx->cp_share_key, test_ctx->cp_share_key_size, "cp_share_key");
			print_data(o_buf, out_sz, "hpre out");
			print_data(cp_key, cp_size, "openssl out");
//#endif
			free(o_buf);
			return -1;
		}
		free(o_buf);
	} else if (test_ctx->op == ECC_HW_SIGN) {
		ret = ecc_sign_result_check(test_ctx, is_async);
		if (ret)
			return ret;
	} else if (test_ctx->op == ECC_HW_VERF) {
		if (req->status != 0) {
			HPRE_TST_PRT("hpre verf faild = %d!\n", req->status);
			return -1;
		}
	} else {}

	return 0;

}

void ecc_del_test_ctx(struct ecc_test_ctx *test_ctx)
{
	if (!test_ctx)
		return;

	if (ECDH_SW_GENERATE == test_ctx->op) {
		if (test_ctx->is_x25519_x448 == 1) {

		} else {
			EC_KEY_free(test_ctx->priv);
		}
	} else if (ECDH_SW_COMPUTE == test_ctx->op) {
		struct ecdh_sw_opdata *req = test_ctx->req;

		if (test_ctx->is_x25519_x448 == 1) {

		} else {
			free(req->share_key);
			free(req);
			EC_KEY_free(test_ctx->priv);
		}
	} else if (ECDH_HW_GENERATE == test_ctx->op) {
		struct wd_ecc_op_data *req = test_ctx->req;

		wd_del_ecc_out(test_ctx->priv, req->dst);
		free(req);
		free(test_ctx->cp_pub_key);
	} else if (ECDH_HW_COMPUTE == test_ctx->op) {
		struct wd_ecc_op_data *req = test_ctx->req;

		wd_del_ecc_out(test_ctx->priv, req->dst);
		wd_del_ecc_in(test_ctx->priv, req->src);
		free(req);
		free(test_ctx->cp_share_key);
	} else if (ECC_SW_SIGN == test_ctx->op) {
		struct ecdh_sw_opdata *req = test_ctx->req;

		free(req->sign);
		BN_free(req->except_kinv);
		free(req);
		EC_KEY_free(test_ctx->priv);
	} else if (ECC_HW_SIGN == test_ctx->op) {
		struct wd_ecc_op_data *req = test_ctx->req;

		if (test_ctx->priv1)
			EC_KEY_free(test_ctx->priv1);

		wd_del_ecc_out(test_ctx->priv, req->dst);
		wd_del_ecc_in(test_ctx->priv, req->src);
		free(req);
	} else if (ECC_SW_VERF == test_ctx->op) {
		struct ecdh_sw_opdata *req = test_ctx->req;

		free(req);
		EC_KEY_free(test_ctx->priv);
	} else if (ECC_HW_VERF == test_ctx->op) {
		struct wd_ecc_op_data *req = test_ctx->req;

		wd_del_ecc_in(test_ctx->priv, req->src);
		free(req);
	} else {
		HPRE_TST_PRT("%s: no op %d\n", __func__, test_ctx->op);
	}

	free(test_ctx);
}

static void _ecc_perf_cb(const void *message, void *tag)
{
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)tag;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;
	struct ecc_test_ctx *test_ctx = pSwData->test_ctx;
	//int pid, threadId;
	//int ret;

	//pid = pSwData->pid;
	//threadId = pSwData->thread_id;
	//ret = ecc_result_check(test_ctx);
	//if (ret) {
		//HPRE_TST_PRT("Proc-%d, %d-TD:%s result mismatching!\n",
			//pid, threadId, ecc_op_str[test_ctx->op]);
	//}

	thread_data->recv_task_num++;
	ecc_del_test_ctx(test_ctx);
	free(pSwData);
}

static void _ecc_cb(const void *message, void *tag)
{
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)tag;
	struct timeval start_tval, end_tval;
	struct wd_ecc_msg *resp = (void *)message;
	int pid, threadId;
	float time, speed;
	int ret;
	static int failTimes = 0;
	struct ecc_test_ctx *test_ctx = pSwData->test_ctx;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;

	start_tval = thread_data->start_tval;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;

	thread_data->recv_task_num++;

	if (resp->result != WD_SUCCESS) {
		HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes fail!, status 0x%02x\n",
			pid, threadId, ecc_op_str[test_ctx->op], thread_data->send_task_num, resp->result);
		goto err;
	}

	if (openssl_check) {
		ret = ecc_result_check(test_ctx, 1);
		if (ret) {
			failTimes++;
			HPRE_TST_PRT("TD-%d:%s result mismatching!\n",
				threadId, ecc_op_str[test_ctx->op]);
		}
	}

	gettimeofday(&end_tval, NULL);
	if (is_allow_print(thread_data->send_task_num, DH_ASYNC_GEN, 1)) {
		time = (end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
					(end_tval.tv_usec - start_tval.tv_usec);
		speed = 1 / (time / thread_data->send_task_num) * 1000 * 1000;
		HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes,%f us, %0.3fps, fail %dtimes(all TD)\n",
				pid, threadId, ecc_op_str[test_ctx->op],
				thread_data->send_task_num, time, speed, failTimes);
	}

err:
	ecc_del_test_ctx(test_ctx);
	if (pSwData)
		free(pSwData);
}

static int hpre_get_rand(char *out, size_t out_len, void *usr)
{
	int ret;

	if (!out) {
		return -1;
	}

	ret = RAND_priv_bytes((void *)out, out_len);
	if (ret != 1) {
		HPRE_TST_PRT("RAND_priv_bytes fail = %d\n", ret);
		return -1;
	}

	return 0;
}

void fill_ecdh_param_of_curve(struct wd_ecc_curve *param)
{
	__u32 key_size = (key_bits + 7) / 8;

	if (key_bits == 128) {
		param->a.data = ecdh_a_secp128k1;
		param->b.data = ecdh_b_secp128k1;
		param->p.data = ecdh_p_secp128k1;
		param->n.data = ecdh_n_secp128k1;
		param->g.x.data = ecdh_g_secp128k1;
		param->g.y.data = ecdh_g_secp128k1 + key_size;
	} else if (key_bits == 192) {
		param->a.data = ecdh_a_secp192k1;
		param->b.data = ecdh_b_secp192k1;
		param->p.data = ecdh_p_secp192k1;
		param->n.data = ecdh_n_secp192k1;
		param->g.x.data = ecdh_g_secp192k1;
		param->g.y.data = ecdh_g_secp192k1 + key_size;
	} else if (key_bits == 256) {
		param->a.data = ecdh_a_secp256k1;
		param->b.data = ecdh_b_secp256k1;
		param->p.data = ecdh_p_secp256k1;
		param->n.data = ecdh_n_secp256k1;
		param->g.x.data = ecdh_g_secp256k1;
		param->g.y.data = ecdh_g_secp256k1 + key_size;
	} else if (key_bits == 320) {
		param->a.data = ecdh_a_secp320k1;
		param->b.data = ecdh_b_secp320k1;
		param->p.data = ecdh_p_secp320k1;
		param->n.data = ecdh_n_secp320k1;
		param->g.x.data = ecdh_g_secp320k1;
		param->g.y.data = ecdh_g_secp320k1 + key_size;
	} else if (key_bits == 384) {
		param->a.data = ecdh_a_secp384k1;
		param->b.data = ecdh_b_secp384k1;
		param->p.data = ecdh_p_secp384k1;
		param->n.data = ecdh_n_secp384k1;
		param->g.x.data = ecdh_g_secp384k1;
		param->g.y.data = ecdh_g_secp384k1 + key_size;
	} else if (key_bits == 521) {
		param->a.data = ecdh_a_secp521k1;
		param->b.data = ecdh_b_secp521k1;
		param->p.data = ecdh_p_secp521k1;
		param->n.data = ecdh_n_secp521k1;
		param->g.x.data = ecdh_g_secp521k1;
		param->g.y.data = ecdh_g_secp521k1 + key_size;
	} else {
		HPRE_TST_PRT("key_bits %d not find\n", key_bits);
		return;
	}

	param->a.bsize = key_size;
	param->a.dsize = key_size;
	param->b.bsize = key_size;
	param->b.dsize = key_size;
	param->p.bsize = key_size;
	param->p.dsize = key_size;
	param->n.bsize = key_size;
	param->n.dsize = key_size;
	param->g.x.bsize = key_size;
	param->g.x.dsize = key_size;
	param->g.y.bsize = key_size;
	param->g.y.dsize = key_size;
}

static void *_ecc_sys_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct dh_user_tag_info *pTag = NULL;
	struct ecc_test_ctx *test_ctx;
	struct ecc_test_ctx_setup setup;
	struct timeval cur_tval;
	enum alg_op_type opType;
	float time_used, speed = 0.0;
	int thread_num;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int ret, cpuid;
	struct wd_queue *q = NULL;
	void *pool = NULL;
	void *ctx = NULL;
	struct wd_ecc_ctx_setup ctx_setup;
	struct wd_ecc_curve param;
	__u32 opstr_idx;
	__u32 free_num;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	q = (struct wd_queue *)pdata->q;
	pool = pdata->pool;
	opType = pdata->op_type;
	thread_num = pdata->thread_num;

	HPRE_TST_PRT("ecc sys test start!\n");

	if (performance_test && (!t_times && !t_seconds)) {
		HPRE_TST_PRT("t_times or  t_seconds err\n");
		return NULL;
	}

	if (!q || !pool) {
		HPRE_TST_PRT("q or pool null!\n");
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

	if (!(!strncmp(q->capa.alg, "x448", 4) || !strncmp(q->capa.alg, "x25519", 5))) {
		ret = get_ecc_nid(ecc_curve_name, &setup.nid, &setup.curve_id);
		if (ret < 0) {
			HPRE_TST_PRT("ecc sys test not find curve!\n");
			return NULL;
		}
	}

	if (!only_soft) {
		memset(&ctx_setup, 0, sizeof(ctx_setup));
		if (performance_test)
			ctx_setup.cb = _ecc_perf_cb;
		else
			ctx_setup.cb = _ecc_cb;

		if (!(!strncmp(q->capa.alg, "x448", 4) || !strncmp(q->capa.alg, "x25519", 5))) {
			if (!setup.curve_id) {
				ctx_setup.cv.type = WD_CV_CFG_PARAM;
				fill_ecdh_param_of_curve(&param);
				ctx_setup.cv.cfg.pparam = &param;
			} else {
				ctx_setup.cv.type = WD_CV_CFG_ID;
				ctx_setup.cv.cfg.id = setup.curve_id;
			}
		}

		ctx_setup.key_bits = key_bits;
		ctx_setup.rand.cb = hpre_get_rand;
	}

	if ((!strncmp(q->capa.alg, "x25519", 6)) || (!strncmp(q->capa.alg, "x448", 4))) {
		if (x_dh_init_test_ctx_setup(&setup, opType)) { // todo
			wd_del_ecc_ctx(ctx);
			return NULL;
		}
	} else if (ecxdh_init_test_ctx_setup(&setup, opType)) {
		wd_del_ecc_ctx(ctx);
		return NULL;
	}

	if (opType == ECDSA_SIGN || opType == SM2_SIGN || opType == ECDSA_ASYNC_SIGN)
		setup.op_type = (only_soft) ? ECC_SW_SIGN: ECC_HW_SIGN;
	else if (opType == ECDSA_VERF || opType == SM2_VERF || opType == ECDSA_ASYNC_VERF)
		setup.op_type = (only_soft) ? ECC_SW_VERF: ECC_HW_VERF;
	else if (opType == SM2_ENC)
		setup.op_type = (only_soft) ? SM2_SW_ENC: SM2_HW_ENC;
	else if (opType == SM2_DEC)
		setup.op_type = (only_soft) ? SM2_SW_DEC: SM2_HW_DEC;
	else if (opType == ECDH_ASYNC_GEN || opType == ECDH_GEN ||
		 opType == X25519_ASYNC_GEN || opType == X25519_GEN ||
		 opType == X448_ASYNC_GEN || opType == X448_GEN)
		setup.op_type = (only_soft) ? ECDH_SW_GENERATE: ECDH_HW_GENERATE;
	else if (opType == ECDH_ASYNC_COMPUTE || opType == ECDH_COMPUTE ||
		 opType == X25519_ASYNC_COMPUTE || opType == X25519_COMPUTE ||
		 opType == X448_ASYNC_COMPUTE || opType == X448_COMPUTE)
		setup.op_type = (only_soft) ? ECDH_SW_COMPUTE: ECDH_HW_COMPUTE;

new_test_again:

	if (!only_soft) {
		ctx = wd_create_ecc_ctx(q, &ctx_setup);
		if (!ctx) {
			HPRE_TST_PRT("wd_create_ecc_ctx failed\n");
			return NULL;
		}

		setup.pool = pool;
		setup.q = q;
		setup.ctx = ctx;
	}

new_test_with_no_req_ctx: // async test

	test_ctx = ecc_create_test_ctx(setup, opType);
	if (!test_ctx) {
		HPRE_TST_PRT("ecc_create_test_ctx failed\n");
		return NULL;
	}
	if (opType >= X25519_GEN && opType <= X448_ASYNC_COMPUTE)
		test_ctx->is_x25519_x448 = 1;

	opstr_idx = test_ctx->op;

	do {
		if (is_async_test(opType)) {
			pTag = malloc(sizeof(struct dh_user_tag_info));
			if (!pTag) {
				HPRE_TST_PRT("malloc pTag fail!\n");
				ret = -1;
				goto fail_release;
			}

			pTag->test_ctx = test_ctx;
			pTag->thread_data = pdata;
			pTag->pid = pid;
			pTag->thread_id = thread_id;
		}

		if (opType == ECDSA_ASYNC_SIGN || opType == ECDSA_SIGN) {
			if (ecdsa_sign(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_SIGN || opType == SM2_ASYNC_SIGN) {
			if (sm2_sign(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == ECDSA_VERF || opType == ECDSA_ASYNC_VERF) {
			if (ecdsa_verf(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_VERF || opType == SM2_ASYNC_VERF) {
			if (sm2_verf(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_ENC || opType == SM2_ASYNC_ENC) {
			if (sm2_enc(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_DEC || opType == SM2_ASYNC_DEC) {
			if (sm2_dec(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == ECDH_ASYNC_GEN || opType == ECDH_GEN ||
			   opType == X25519_ASYNC_GEN || opType == X25519_GEN ||
			   opType == X448_ASYNC_GEN || opType == X448_GEN) {
			if (ecdh_generate_key(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == ECDH_ASYNC_COMPUTE || opType == ECDH_COMPUTE ||
			   opType == X25519_ASYNC_COMPUTE || opType == X25519_COMPUTE ||
			   opType == X448_ASYNC_COMPUTE || opType == X448_COMPUTE) {
			if (ecdh_compute_key(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		if (!is_async_test(opType)) {

			if (only_soft && !performance_test) {
				ecc_del_test_ctx(test_ctx);
				goto new_test_with_no_req_ctx;
			} else if (!performance_test) {
				if (ecc_result_check(test_ctx, 0)) {
					ret = -1;
					goto fail_release;
				}

				wd_get_free_blk_num(pool, &free_num);
				if (is_allow_print(pdata->send_task_num, opType, thread_num)) {
					HPRE_TST_PRT("Proc-%d, %d-TD: %s %uth succ!, free_num = %d.\n",
						getpid(), (int)syscall(__NR_gettid),
						ecc_op_str[test_ctx->op], pdata->send_task_num, free_num);
				}

				ecc_del_test_ctx(test_ctx);
				wd_del_ecc_ctx(ctx);
				ctx = NULL;
				test_ctx = NULL;

				if (is_exit(pdata))
					goto func_test_exit;

				goto new_test_again;
				//goto new_test_with_no_req_ctx;
			}
		} else {
			if (is_exit(pdata))
				break;

			goto new_test_with_no_req_ctx;
		}
	} while(!is_exit(pdata));

	if (!is_async_test(opType))
		pdata->recv_task_num = pdata->send_task_num;

	if (performance_test) {
		gettimeofday(&cur_tval, NULL);
		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (t_seconds){
			speed = pdata->send_task_num / time_used * 1000000;
		} else if (t_times) {
			speed = 1 / (time_used / t_times) * 1000;
		}

		HPRE_TST_PRT("Proc-%d, %d-TD: ecc %s send %u task, recv %u task, run %0.1f s at %0.3f ops\n",
				pid, thread_id, ecc_op_str[test_ctx->op],
			pdata->send_task_num, pdata->recv_task_num,
			time_used / 1000000, speed);
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num)
		usleep(1000);

	ret = 0;

fail_release:

	if (!only_soft && !is_async_test(opType))
		wd_del_ecc_ctx(test_ctx->priv);

	if (!is_async_test(opType))
		ecc_del_test_ctx(test_ctx);

	if (ret)
		HPRE_TST_PRT("%s test fail!\n", ecc_op_str[opstr_idx]);
	else
		HPRE_TST_PRT("%s test succ!\n", ecc_op_str[opstr_idx]);

	HPRE_TST_PRT("ecc sys test end!\n");

	return NULL;

func_test_exit:
	HPRE_TST_PRT("%s test succ!\n", ecc_op_str[opstr_idx]);

	HPRE_TST_PRT("ecc sys test end!\n");

	return NULL;
}
#endif

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

int  hpre_test_get_file_size(char *in_file)
{
	int fd = -1, ret;
	struct stat file_info;

	if (!in_file) {
		HPRE_TST_PRT("para err while try to %s!\n", __func__);
		return -EINVAL;
	}
	fd = open(in_file, O_RDONLY, S_IRUSR) ;
	if (fd < 0) {
		HPRE_TST_PRT("Get %s file fail!\n", in_file);
		return fd;
	}
	ret = fstat(fd, &file_info);
	if (ret < 0) {
		close(fd);
		HPRE_TST_PRT("fstat file %s fail!\n", in_file);
		return -ret;
	}
	close(fd);
	return (int)file_info.st_size;
}

int  hpre_test_read_from_file(__u8 *out, char *in_file, int size)
{
	int fd = -1, bytes_rd;

	if (!out || !size || !in_file) {
		HPRE_TST_PRT("para err while try to write file!\n");
		return -EINVAL;
	}

	fd = open(in_file, O_RDONLY, S_IRUSR) ;
	if (fd < 0) {
		HPRE_TST_PRT("Get %s file fail!\n", in_file);
		return fd;
	}

	bytes_rd = read(fd, out, size);
	if (bytes_rd < 0) {
		close(fd);
		HPRE_TST_PRT("write data to %s file fail!\n", in_file);
		return -ENOMEM;
	}
	close(fd);

	/* to be fixed */
	return bytes_rd;
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

static int test_rsa_key_gen(void *ctx, char *pubkey_file,
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
	u32 key_size = key_bits >> 3;
        char *tmp;

	memset(&wd_e, 0, sizeof(wd_e));
	memset(&wd_d, 0, sizeof(wd_d));
	memset(&wd_n, 0, sizeof(wd_n));
	memset(&wd_dq, 0, sizeof(wd_dq));
	memset(&wd_dp, 0, sizeof(wd_dp));
	memset(&wd_qinv, 0, sizeof(wd_qinv));
	memset(&wd_q, 0, sizeof(wd_q));
	memset(&wd_p, 0, sizeof(wd_p));

	bits = wd_rsa_key_bits(ctx);
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

	ret = RSA_generate_key_ex(test_rsa, key_bits, e_value, NULL);
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

	if (wd_rsa_set_pubkey_params(ctx, &wd_e, &wd_n))
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
	if (wd_rsa_is_crt(ctx)) {
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

		if (wd_rsa_set_crt_prikey_params(ctx, &wd_dq,
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

			if (wd_rsa_set_prikey_params(ctx, &wd_d, &wd_n))
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

	if (wd_rsa_is_crt(ctx)) {
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

	if (wd_rsa_is_crt(ctx)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

	return ret;
}

int hpre_test_fill_keygen_opdata(void *ctx, struct wd_rsa_req *req)
{
	struct wd_dtb *e, *p, *q;
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
	struct wd_dtb t_e, t_p, t_q;

	wd_rsa_get_pubkey(ctx, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &e, NULL);
	wd_rsa_get_prikey(ctx, &prikey);

	if (wd_rsa_is_crt(ctx)) {
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

	req->src = wd_rsa_new_kg_in(ctx, e, p, q);
	if (!req->src) {
		HPRE_TST_PRT("create rsa kgen in fail!\n");
		return -ENOMEM;
	}
	req->dst = wd_rsa_new_kg_out(ctx);
	if (!req->dst) {
		HPRE_TST_PRT("create rsa kgen out fail!\n");
		return -ENOMEM;
	}
	return 0;
}

static BIGNUM *hpre_bin_to_bn(void *bin, int raw_size)
{
	int bin_size;

	if (!bin || !raw_size)
		return NULL;

	return BN_bin2bn((const unsigned char *)bin, raw_size, NULL);
}

int hpre_test_result_check(void *ctx,  struct wd_rsa_req *req, void *key)
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

	wd_rsa_get_prikey(ctx, &prikey);
	keybits = wd_rsa_key_bits(ctx);
	key_size = keybits >> 3;
	if (req->op_type == WD_RSA_GENKEY) {
		if (wd_rsa_is_crt(ctx)) {
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
		if (!only_soft && memcmp(ssl_out, req->dst, key_size)) {
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

		if (key && wd_rsa_is_crt(ctx)) {
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

		} else if (key && !wd_rsa_is_crt(ctx)) {
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

		if (!only_soft && memcmp(ssl_out, req->dst, ret)) {
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

#if 0
int hpre_dh_test(void *c, struct hpre_queue_mempool *pool)
{
	DH *a = NULL, *b = NULL;
	int ret, generator = DH_GENERATOR_5;
	struct wd_dh_op_data opdata_a;
	struct wd_dh_op_data opdata_b;
	const BIGNUM *ap = NULL, *ag = NULL,
			*apub_key = NULL, *apriv_key = NULL;
	const BIGNUM *bp = NULL, *bg = NULL,
			*bpub_key = NULL, *bpriv_key = NULL;
	unsigned char *ap_bin = NULL, *ag_bin = NULL,
			*apub_key_bin = NULL, *apriv_key_bin = NULL;
	unsigned char *bp_bin = NULL, *bg_bin = NULL,
			*bpub_key_bin = NULL, *bpriv_key_bin = NULL;
	unsigned char *abuf = NULL;
	struct wd_dtb g;

	__u32 gbytes;
	void *tag = NULL;
	int key_size, key_bits, bin_size = 0;

	if (!pool) {
		HPRE_TST_PRT("pool null!\n");
		return -1;
	}

	a = DH_new();
	b = DH_new();
	if (!a || !b) {
		HPRE_TST_PRT("New DH fail!\n");
		return -1;
	}

	if (wd_dh_is_g2(c))
		generator = DH_GENERATOR_2;

	key_bits = wd_dh_key_bits(c);
	key_size = key_bits >> 3;

	/* Alice generates DH parameters */
	ret = DH_generate_parameters_ex(a, key_bits, generator, NULL);
	if (!ret) {
		HPRE_TST_PRT("DH_generate_parameters_ex fail!\n");
		goto dh_err;
	}

	DH_get0_pqg(a, &ap, NULL, &ag);
	bp = BN_dup(ap);
	bg = BN_dup(ag);
	if (!bp || !bg) {
		HPRE_TST_PRT("bn dump fail!\n");
		ret = -1;
		goto dh_err;
	}

	/* Set the same parameters on Bob as Alice :) */
	DH_set0_pqg(b, (BIGNUM *)bp, NULL, (BIGNUM *)bg);
	if (!DH_generate_key(a)) {
		HPRE_TST_PRT("a DH_generate_key fail!\n");
		ret = -1;
		goto dh_err;
	}

	DH_get0_key(a, &apub_key, &apriv_key);
	ag_bin = malloc(key_size * 2);
	if (!ag_bin) {
		HPRE_TST_PRT("pool alloc ag_bin fail!\n");
		goto dh_err;
	}
	memset(ag_bin, 0, key_size * 2);
	apriv_key_bin = malloc(key_size * 2);
	if (!apriv_key_bin) {
		HPRE_TST_PRT("pool alloc apriv_key_bin fail!\n");
		goto dh_err;
	}
	memset(apriv_key_bin, 0, key_size * 2);

	/* The hpre_UM tells us key_addr contains xa and p,
	 * their addr should be together
	 */
	ap_bin= apriv_key_bin + key_size;

	gbytes = BN_bn2bin(ag, ag_bin);
	g.data = (char*)ag_bin;
	g.bsize = key_size;
	g.dsize = gbytes;
	opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
	opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
	ret = wd_set_dh_g(c, &g);
	if (ret) {
		HPRE_TST_PRT("Alice wd_set_dh_g fail!\n");
		goto dh_err;
	}
	opdata_a.x_p = apriv_key_bin;
	opdata_a.pri = malloc(key_size * 2);
	if (!opdata_a.pri) {
		HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
		goto dh_err;
	}
	memset(opdata_a.pri, 0, key_size * 2);

	opdata_a.op_type = WD_DH_PHASE1;

	/* Alice computes public key */
	ret = wd_do_dh(c, &opdata_a, tag);
	if (ret) {
		HPRE_TST_PRT("a wd_do_dh fail!\n");
		goto dh_err;
	}

	if (openssl_check) {
		apub_key_bin = malloc(key_size);
		if (!apub_key_bin) {
			HPRE_TST_PRT("malloc apub_key_bin fail!\n");
			ret = -ENOMEM;
			goto dh_err;
		}
		ret = BN_bn2bin(apub_key, apub_key_bin);
		if (!ret) {
			HPRE_TST_PRT("apub_key bn 2 bin fail!\n");
			ret = -1;
			goto dh_err;
		}
		bin_size = ret;

		if (memcmp(apub_key_bin, opdata_a.pri, bin_size)) {
			HPRE_TST_PRT("Alice HPRE DH key gen pub mismatch, dsize %d!\n", bin_size);
			ret = -EINVAL;
#ifdef DEBUG
			print_data(apub_key_bin, key_size, "SOFT");
			print_data(opdata_a.pri, key_size, "HARDWATE");
#endif
			goto dh_err;
		}
	}
	if (!DH_generate_key(b)) {
		HPRE_TST_PRT("b DH_generate_key fail!\n");
		ret = -1;
		goto dh_err;
	}
	DH_get0_key(b, &bpub_key, &bpriv_key);
	bg_bin = malloc(key_size * 2);
	if (!bg_bin) {
		HPRE_TST_PRT("pool alloc bg_bin fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(bg_bin, 0, key_size * 2);

	bpriv_key_bin= malloc(key_size * 2);
	if (!bpriv_key_bin) {
		HPRE_TST_PRT("pool alloc bpriv_key_bin fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(bpriv_key_bin, 0, key_size * 2);
	bp_bin = bpriv_key_bin + key_size;
	gbytes = BN_bn2bin(bg, bg_bin);
	g.data = (char*)bg_bin;
	g.bsize = gbytes;
	g.dsize = key_size;
	ret = wd_set_dh_g(c, &g);
	if (ret) {
		HPRE_TST_PRT("bob wd_set_dh_g fail!\n");
		goto dh_err;
	}
	opdata_b.pbytes = BN_bn2bin(bp, bp_bin);
	opdata_b.xbytes = BN_bn2bin(bpriv_key, bpriv_key_bin);
	opdata_b.x_p = bpriv_key_bin;
	opdata_b.pri = malloc(key_size * 2);
	if (!opdata_b.pri) {
		HPRE_TST_PRT("pool alloc opdata_b.pri fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(opdata_b.pri, 0, key_size * 2);
	opdata_b.op_type = WD_DH_PHASE1;

	/* Bob computes public key */
	ret = wd_do_dh(c, &opdata_b, tag);
	if (ret) {
		HPRE_TST_PRT("b wd_do_dh fail!\n");
		goto dh_err;
	}
	if (openssl_check) {
		bpub_key_bin = malloc(key_size);
		if (!bpub_key_bin) {
			HPRE_TST_PRT("malloc bpub_key_bin fail!\n");
			ret = -1;
			goto dh_err;
		}
		ret = BN_bn2bin(bpub_key, bpub_key_bin);
		if (!ret) {
			HPRE_TST_PRT("bpub_key bn 2 bin fail!\n");
			goto dh_err;
		}
		bin_size = ret;

		if (memcmp(bpub_key_bin, opdata_b.pri, bin_size)) {
			HPRE_TST_PRT("Bob HPRE DH key gen pub mismatch, dsize %d!\n", bin_size);
			ret = -EINVAL;
#ifdef DEBUG
			print_data(bpub_key_bin, key_size, "SOFT");
			print_data(opdata_b.pri, key_size, "HARDWATE");
#endif
			goto dh_err;
		}
	}
	/* Alice computes private key with OpenSSL */
	abuf = malloc(key_size);
	if (!abuf) {
		HPRE_TST_PRT("malloc abuf fail!\n");
		ret = -ENOMEM;
		goto dh_err;
	}

	memset(abuf, 0, key_size);
	if (openssl_check) {
		ret = DH_compute_key(abuf, bpub_key, a);
		if (!ret) {
			HPRE_TST_PRT("DH_compute_key fail!\n");
			ret = -1;
			goto dh_err;
		}
		bin_size = ret;
	}

	/* Alice computes private key with HW accelerator */
	memset(ag_bin, 0, key_size * 2);
	memset(apriv_key_bin, 0, key_size * 2);
	ap_bin = apriv_key_bin + key_size;
	memset(opdata_a.pri, 0, key_size * 2);

	opdata_a.pvbytes = BN_bn2bin(bpub_key, ag_bin);
	opdata_a.pv = ag_bin;/* bob's public key here */
	opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
	opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
	opdata_a.x_p = apriv_key_bin;
	opdata_a.pri = malloc(key_size * 2);
	if (!opdata_a.pri) {
		HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(opdata_a.pri, 0, key_size * 2);
	opdata_a.op_type = WD_DH_PHASE2;

	/* Alice computes private key with HPRE */
	ret = wd_do_dh(c, &opdata_a, tag);
	if (ret) {
		HPRE_TST_PRT("a wd_do_dh fail!\n");
		goto dh_err;
	}
	if (openssl_check) {
		if (memcmp(abuf, opdata_a.pri, bin_size)) {
			HPRE_TST_PRT("Alice HPRE DH gen privkey mismatch!\n");
			ret = -EINVAL;
#ifdef DEBUG
			print_data(abuf, key_size, "SOFT");
			print_data(opdata_a.pri, key_size, "HARDWATE");
#endif
			goto dh_err;
		}
	}

	ret = 0;
	HPRE_TST_PRT("HPRE DH generate key sucessfully!\n");
	dh_err:
	DH_free(a);
	DH_free(b);
	if (ag_bin)
		free(ag_bin);
	if (apriv_key_bin)
		free(apriv_key_bin);
	if (opdata_a.pri)
		free(opdata_a.pri);

	if (bg_bin)
		free(bg_bin);
	if (bpriv_key_bin)
		free(bpriv_key_bin);
	if (opdata_b.pri)
		free(opdata_b.pri);

	if (apub_key_bin)
		free(apub_key_bin);
	if (bpub_key_bin)
		free(bpub_key_bin);
	if (abuf)
		free(abuf);
	return ret;
}
#endif

#ifdef RSA_OP_DEBUG
int hpre_test_rsa_op(enum alg_op_type op_type, void *c, __u8 *in,
		    int in_size,  __u8 *out,  __u8 *key)
{
	struct wd_rsa_req req;
	int ret, move;
	void *tag;
	int key_bits, key_size;

	key_bits =  wd_dh_key_bits(c);
	key_size = key_bits >> 3;
	if (op_type == RSA_KEY_GEN) {
		/* use openSSL generate key and store them to files at first */
		ret = test_rsa_key_gen(c, (char *)in,
				      (char *)out, (char *)key, 1);
		if (ret < 0)
			return ret;
	} else {
		struct wd_rsa_pubkey pubkey;
		struct wd_rsa_prikey prvkey;

		if (!key)
			goto try_format_input;
		memset(&pubkey, 0, sizeof(pubkey));
		memset(&prvkey, 0, sizeof(prvkey));
		if (op_type == RSA_PUB_EN) {
			pubkey.e = key;
			pubkey.n = key + (key_bits >> 3);
			ret = wd_set_rsa_pubkey(c, &pubkey);
			if (ret) {
				HPRE_TST_PRT("wd_set_rsa_pubkey fail!\n");
				return ret;
			}
		}
		if (op_type == RSA_PRV_DE && wd_rsa_is_crt(c)) {
			prvkey.pkey2.dq = key;
			prvkey.pkey2.dp = key + (key_bits >> 4);
			prvkey.pkey2.q = key + (key_bits >> 3);
			prvkey.pkey2.p = key + (key_bits >> 4) * 3;
			prvkey.pkey2.qinv = key + (key_bits >> 2);
			ret = wd_set_rsa_prikey(c, &prvkey);
			if (ret) {
				HPRE_TST_PRT("wd_set_rsa_prikey crt fail!\n");
				return ret;
			}
		} else if (op_type == RSA_PRV_DE && !wd_rsa_is_crt(c)) {
			prvkey.pkey1.d = key;
			prvkey.pkey1.n = key + (key_bits >> 3);
			ret = wd_set_rsa_prikey(c, &prvkey);
			if (ret) {
				HPRE_TST_PRT("wd_set_rsa_prikey fail!\n");
				return ret;
			}
		}
try_format_input:
		/* Padding zero in this sample */
		if (in_size < key_size && op_type == RSA_PUB_EN) {
			move =  key_size - in_size;
			memmove(in + move, in, in_size);
			memset(in, 0, move);
		}
	}

	/* always key size bytes input */
	req.src_bytes = key_size;
	if (op_type == RSA_PRV_DE) {
		req.op_type = WD_RSA_SIGN;
	} else if (op_type == RSA_PUB_EN) {
		req.op_type = WD_RSA_VERIFY;
	} else if (op_type == RSA_KEY_GEN) {
		req.op_type = WD_RSA_GENKEY;
	} else {
		ret = -EINVAL;
		goto type_err;
	}
	if (op_type == RSA_KEY_GEN) {
		ret = hpre_test_fill_keygen_opdata(c, &req);
		if (ret)
			goto type_err;
	} else {
		req.src = in;
		req.dst = out;
	}
	tag = NULL;
	ret = wd_do_rsa_sync(c, &req);
	if (ret)
		goto type_err;
	if (openssl_check) {
		ret = hpre_test_result_check(c, &req, key);
		if (ret)
			goto type_err;
		else if (req->op_type == WD_RSA_GENKEY)
			HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
	} else if (!openssl_check && op_type == RSA_KEY_GEN) {
		HPRE_TST_PRT("HPRE hardware key generate finished!\n");
	}
	if (op_type == RSA_PRV_DE) {
		__u8 *tmp = req.dst;

		move = 0;
		while (!tmp[move])
			move++;
		req.dst_bytes -= move;
		memmove(out, out + move, req.dst_bytes);
	}
	return (int)req.dst_bytes;
type_err:
	return ret;
}
#endif

int hpre_sys_qmng_test(int thread_num)
{
	int pid = getpid(), i = 0, ret;
	int thread_id = (int)syscall(__NR_gettid);
	char *node_path = "hisi_hpre-0";
	handle_t h_ctx;

	while (1) {
		h_ctx = wd_request_ctx(node_path);
		if (!h_ctx) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:request queue t-%d fail!\n",
					 pid, thread_id, i);
			return -1;
		}
		i++;
		if (is_allow_print(i, HPRE_ALG_INVLD_TYPE, thread_num))
			HPRE_TST_PRT("Proc-%d, %d-TD request %dQs\n",
				     pid, thread_id, i);
		usleep(1);
		wd_release_ctx(h_ctx);
	}
	return 0;
}

int hpre_sys_func_test(struct test_hpre_pthread_dt * pdata)
{
	int pid = getpid(), ret = 0, i = 0;
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	void *ctx = NULL;
	void *tag = NULL;
	struct wd_queue *q = pdata->q;
	void *key_info = NULL;
	struct timeval cur_tval;
	float time, speed;
	char *alg_name = pdata->alg_name;
	int key_size = key_bits >> 3;
        char m[] = {0x54, 0x85, 0x9b, 0x34, 0x2c, 0x49, 0xea, 0x2a};

	if (performance_test && (!t_times && !t_seconds)) {
		HPRE_TST_PRT("t_times or  t_seconds err\n");
		return -1;
	}

new_test_again:

	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = key_bits;
	if (!strcmp(g_mode, "-crt"))
		setup.is_crt = true;
	else
		setup.is_crt = false;

	ctx = wd_rsa_alloc_sess(&setup);
	if (!ctx) {
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
	ret = test_rsa_key_gen(ctx, NULL, key_info, key_info, 0);
	if (ret) {
		HPRE_TST_PRT("thrd-%d:Openssl key gen fail!\n", thread_id);
		goto fail_release;
	}

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
		ret = hpre_test_fill_keygen_opdata(ctx, &req);
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
	}

	do {
		if (!only_soft) {
			ret = wd_do_rsa_sync(ctx, &req);
			if (ret || req.status) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth status=%d fail!\n",
					 pid, thread_id,
					 rsa_op_str[req.op_type], i, req.status);
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		i++;
		if (openssl_check) {
			void *check_key;

			if (req.op_type == WD_RSA_SIGN)
				check_key = key_info;
			if (req.op_type == WD_RSA_VERIFY)
				if (wd_rsa_is_crt(ctx))
					check_key = key_info + 5 * (key_bits >> 4);
				else
					check_key = key_info + 2 * key_size;
			else
				check_key = key_info;
			ret = hpre_test_result_check(ctx, &req, check_key);
			if (ret) {
				HPRE_TST_PRT("P-%d,T-%d:hpre %s %dth mismth\n",
						 pid, thread_id,
						 rsa_op_str[req.op_type], i);
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
					 pid, thread_id, rsa_op_str[req.op_type],
					 i, time, speed);
		}

		if (!performance_test && !only_soft) {
			if (req.op_type == WD_RSA_GENKEY) {
				if (req.src)
					wd_rsa_del_kg_in(ctx, req.src);
				if (req.dst)
					wd_rsa_del_kg_out(ctx, req.dst);
			} else {
				if (req.src)
					free(req.src);
				if (req.dst)
					free(req.dst);
			}

			if (ctx)
				wd_rsa_free_sess(ctx);

			if (rsa_key_in)
				free(rsa_key_in);

			if (key_info)
				free(key_info);

			goto new_test_again;
		}
	}while(!is_exit(pdata));

	pdata->recv_task_num = pdata->send_task_num;

	if (performance_test) {
		gettimeofday(&cur_tval, NULL);
		time = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (t_seconds) {
			speed = pdata->send_task_num / time * 1000000;
			HPRE_TST_PRT("Proc-%d, %d-TD: dh do %s send %u task, recv %u task, run %0.1f s at %0.3f ops\n",
				 pid, thread_id, rsa_op_str_perf[req.op_type],
				pdata->send_task_num, pdata->recv_task_num,
				time / 1000000, speed);
		} else if (t_times) {
			speed = 1 / (time / t_times) * 1000;
			HPRE_TST_PRT("\r\nPID(%d)-thread-%d:%s CRT mode %dbits %s time %0.0f us, pkt len ="
				" %d bytes, %0.3f Kops\n", getpid(), (int)syscall(__NR_gettid), "rsa",
				key_bits, rsa_op_str_perf[req.op_type], time, key_bits / 8, speed);
		}
	}

fail_release:
	if (req.op_type == WD_RSA_GENKEY) {
		if (req.src)
			wd_rsa_del_kg_in(ctx, req.src);
		if (req.dst)
			wd_rsa_del_kg_out(ctx, req.dst);
	} else {
		if (req.src)
			free(req.src);
		if (req.dst)
			free(req.dst);
	}
	if (ctx)
		wd_rsa_free_sess(ctx);
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
	enum alg_op_type op_type;
	int thread_num;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	op_type = pdata->op_type;
	thread_num = pdata->thread_num;
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
	if (op_type == HPRE_ALG_INVLD_TYPE) {
		ret = hpre_sys_qmng_test(thread_num);
		if (ret)
			return NULL;
	} else {
		ret = hpre_sys_func_test(pdata);
		if (ret)
			return NULL;
	}
	return NULL;
}

static int hpre_sys_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type,
			char *dev_path, unsigned int node_msk)
{
	int i, ret, cnt = 0, j;
	int h_cpuid, qidx;

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 0; i < cnt; i++) {
		qidx = i;
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

		qidx = (i + cnt);
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
	}

	return 0;
}

static void  *_rsa_async_poll_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	//struct wd_queue *q = pdata->q;
	int ret = 0;

	while (1) {
		//ret = wd_rsa_poll(q, 1);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	return NULL;
}
static void _rsa_cb(void *message, void *rsa_tag)
{
	int keybits, key_size;
	struct rsa_async_tag *tag = rsa_tag;
	void *ctx = tag->ctx;
	int thread_id = tag->thread_id;
	int cnt = tag->cnt;
	struct wd_rsa_msg *msg = message;
	void *out = NULL; // msg->req.dst; //todo
	enum wd_rsa_op_type  op_type = 0; //msg->req.op_type; //todo
	struct wd_rsa_prikey *prikey;
	struct test_hpre_pthread_dt *thread_info = tag->thread_info;

	wd_rsa_get_prikey(ctx, &prikey);
	keybits = wd_rsa_key_bits(ctx);
	key_size = keybits >> 3;

	thread_info->recv_task_num++;

	if (op_type == WD_RSA_GENKEY) {
		struct wd_rsa_kg_out *kout = out;

		if (wd_rsa_is_crt(ctx)) {
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
		if (!only_soft && memcmp(ssl_params.ssl_verify_result, out, key_size)) {
			HPRE_TST_PRT("pub encrypto result  mismatch!\n");
			return;
		}
	} else {
		if (wd_rsa_is_crt(ctx))
			if (!only_soft && memcmp(ssl_params.ssl_sign_result, out, key_size)) {
				HPRE_TST_PRT("prv decrypto result  mismatch!\n");
				return;
			}
	}

	if (is_allow_print(cnt, op_type, 1))
		HPRE_TST_PRT("thread %d do RSA %dth time success!\n", thread_id, cnt);
	if (op_type == WD_RSA_GENKEY && out) {
		wd_rsa_del_kg_out(ctx, out);
	}
	free(rsa_tag);
}

void *_rsa_async_op_test_thread(void *data)
{
	int ret = 0, i = 0, cpuid;
	struct test_hpre_pthread_dt *pdata = data;
	char *alg_name = pdata->alg_name;
	cpu_set_t mask;
	enum alg_op_type op_type;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	void *ctx = NULL;
	void *key_info = NULL;
	struct wd_rsa_prikey *prikey;
	struct wd_rsa_pubkey *pubkey;
	struct rsa_async_tag *tag;
	struct wd_dtb *wd_e, *wd_d, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	struct wd_dtb t_e, t_p, t_q;
	u32 key_size = key_bits >> 3;

	if (performance_test && (!t_times && !t_seconds)) {
		HPRE_TST_PRT("t_times or  t_seconds err\n");
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
	setup.key_bits = key_bits;
	if (!strcmp(g_mode, "-crt"))
		setup.is_crt = true;
	else
		setup.is_crt = false;

	ctx = wd_rsa_alloc_sess(&setup);
	if (!ctx) {
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

	wd_rsa_get_pubkey(ctx, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
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

	wd_rsa_get_prikey(ctx, &prikey);
	if (wd_rsa_is_crt(ctx)) {
		wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
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

	} else {
		wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);

		wd_d->dsize = BN_bn2bin(ssl_params.d, (unsigned char *)wd_d->data);
		wd_n->dsize = BN_bn2bin(ssl_params.n, (unsigned char *)wd_n->data);
		wd_e = &t_e;
		wd_p = &t_p;
		wd_q = &t_q;
		memset(rsa_key_in->e, 0, key_size);
		memset(rsa_key_in->p, 0, key_size >> 1);
		memset(rsa_key_in->q, 0, key_size >> 1);
		rsa_key_in->e_size = BN_bn2bin(ssl_params.e, (unsigned char *)rsa_key_in->e);
		rsa_key_in->p_size = BN_bn2bin(ssl_params.p, (unsigned char *)rsa_key_in->p);
		rsa_key_in->q_size = BN_bn2bin(ssl_params.q, (unsigned char *)rsa_key_in->q);
		wd_e->data = rsa_key_in->e;
		wd_e->dsize = rsa_key_in->e_size;
		wd_p->data = rsa_key_in->p;
		wd_p->dsize = rsa_key_in->p_size;
		wd_q->data = rsa_key_in->q;
		wd_q->dsize = rsa_key_in->q_size;
	}

	/* always key size bytes input */
	req.src_bytes = key_size;
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
		req.src = (__u8 *)wd_rsa_new_kg_in(ctx, wd_e, wd_p, wd_q);
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
	}

	do {
			if (req.op_type == WD_RSA_GENKEY) {
				req.dst = wd_rsa_new_kg_out(ctx);
				if (!req.dst) {
					HPRE_TST_PRT("create rsa kgen out fail!\n");
					goto fail_release;
				}
			}
			/* set the user tag */
			tag = malloc(sizeof(*tag));
			if (!tag)
				goto fail_release;
			tag->ctx = ctx;
			tag->thread_id = thread_id;
			tag->cnt = i;
			tag->thread_info = pdata;
try_do_again:
			ret = wd_do_rsa_sync(ctx, &req);
			if (ret == -WD_EBUSY) {
				usleep(100);
				goto try_do_again;
			} else if (ret) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth fail!\n",
					 pid, thread_id,
					 rsa_op_str[req.op_type], i);
				goto fail_release;
			}
			//usleep(100);
			i++;
			pdata->send_task_num++;
	}while (!is_exit(pdata));

	if (performance_test) {
		struct timeval cur_tval;
		float speed = 0.0, time_used = 0.0;
		gettimeofday(&cur_tval, NULL);

		printf("start: s %lu, us %lu\n", pdata->start_tval.tv_sec, pdata->start_tval.tv_usec);
		printf("now: s %lu, us %lu\n", cur_tval.tv_sec, cur_tval.tv_usec);

		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (t_seconds) {
			speed = pdata->recv_task_num / time_used * 1000000;
			HPRE_TST_PRT("Proc-%d, %d-TD: rsa do %s send %u task, recv %u task, run %0.1f s at %0.3f ops\n",
				 pid, thread_id, rsa_op_str[req.op_type],
				pdata->send_task_num, pdata->recv_task_num,
				time_used / 1000000, speed);
		} else if (t_times) {
			speed = 1 / (time_used / t_times) * 1000;
			HPRE_TST_PRT("\r\nPID(%d)-thread-%d:%s CRT mode %dbits %s time %0.0f us, pkt len ="
				" %d bytes, %0.3f Kops\n", getpid(), (int)syscall(__NR_gettid), "rsa",
				key_bits, rsa_op_str_perf[req.op_type], time_used, key_bits / 8, speed);
		}
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num)
		usleep(1000);


fail_release:
	if (req.op_type == WD_RSA_GENKEY) {
		if (req.src)
			wd_rsa_del_kg_in(ctx, req.src);
		//if (req.dst)
		//	wd_rsa_del_kg_out(ctx, req.dst);
	} else {
		if (req.src)
			free(req.src);
		if (req.dst)
			free(req.dst);
	}
	if (ctx)
		wd_rsa_free_sess(ctx);
	if (key_info)
		free(key_info);
	if (rsa_key_in)
		free(rsa_key_in);
	return NULL;
}

static int set_ssl_plantext(void)
{
	ssl_params.size = key_bits >> 3;
	ssl_params.plantext = malloc(ssl_params.size);
	if (!ssl_params.plantext)
		return -ENOMEM;
	memset(ssl_params.plantext, 0, ssl_params.size);
	return 0;
}

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
	ret = RSA_generate_key_ex(ssl_params.rsa, key_bits, ssl_params.e, NULL);
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


static int rsa_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	int ret = 0, cnt = 0, i;
	struct wd_sched sched;	int h_cpuid;

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

	ret = rsa_openssl_key_gen_for_async_test();
	if(ret) {
		HPRE_TST_PRT("openssl genkey for async thread test fail!");
		return 0;
	}

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
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	return 0;
}

#if 0
static void *_dh_async_poll_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct wd_queue *q = pdata->q;
	int ret, cpuid;
	int pid = getpid();
	cpu_set_t mask;
	int thread_id = (int)syscall(__NR_gettid);

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
		ret = wd_dh_poll(q, 1);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	HPRE_TST_PRT("%s exit!\n", __func__);
	return NULL;
}

static int dh_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	void *bufPool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0;
	int block_num = 1024*16;
	struct wd_queue *q;
	int h_cpuid;

	q = malloc(sizeof(struct wd_queue));
	if (!q) {
		HPRE_TST_PRT("malloc q memory fail!\n");
		return -ENOMEM;
	}
	memset(q, 0, sizeof(struct wd_queue));

	q->capa.alg = "dh";
	ret = wd_request_queue(q);
	if (ret) {
		HPRE_TST_PRT("request queue fail!\n");
		return ret;
	}
	memset(&setup, 0, sizeof(setup));
	setup.block_size = key_bits >> 2; // block_size;
	setup.block_num = block_num;
	setup.align_size = 64;

	bufPool = wd_blkpool_create(q, &setup);
	if (!bufPool) {
		HPRE_TST_PRT("%s(): create pool fail!\n", __func__);
		return -ENOMEM;
	}

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	/* Create poll thread at first */
	test_thrds_data[0].pool = bufPool;
	test_thrds_data[0].q = q;
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
			     _dh_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].pool = bufPool;
		test_thrds_data[i].q = q;
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

		test_thrds_data[i + cnt].pool = bufPool;
		test_thrds_data[i + cnt].q = q;
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
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	return 0;
}

static void *_ecc_async_poll_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct wd_queue *q = pdata->q;
	__u16 op = pdata->op_type;
	int ret, cpuid;
	int pid = getpid();
	cpu_set_t mask;
	int thread_id = (int)syscall(__NR_gettid);

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
		if (op == ECDH_ASYNC_GEN || op == ECDH_ASYNC_COMPUTE ||
		    op == X25519_ASYNC_GEN || op == X25519_ASYNC_COMPUTE ||
		    op == X448_ASYNC_GEN || op == X448_ASYNC_COMPUTE) {
			ret = wd_ecxdh_poll(q, 1);
		} else if (op == ECDSA_ASYNC_SIGN || op == ECDSA_ASYNC_VERF) {
			ret = wd_ecdsa_poll(q, 1);
		} else { // SM2, todo
			ret = -1;
		}

		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	HPRE_TST_PRT("%s exit!\n", __func__);
	return NULL;
}

static int ecc_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	void *bufPool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0;
	int block_num = 1024*16;
	struct wd_queue *q;
	int h_cpuid;

	q = malloc(sizeof(struct wd_queue));
	if (!q) {
		HPRE_TST_PRT("malloc q memory fail!\n");
		return -ENOMEM;
	}
	memset(q, 0, sizeof(struct wd_queue));

	if (op_type == ECDH_ASYNC_GEN || op_type == ECDH_ASYNC_COMPUTE) {
		q->capa.alg = "ecdh";
	} else if (op_type == X25519_ASYNC_GEN || op_type == X25519_ASYNC_COMPUTE) {
		q->capa.alg = "x25519";
	} else if (op_type == X448_ASYNC_GEN || op_type == X448_ASYNC_COMPUTE) {
		q->capa.alg = "x448";
	} else if (op_type == ECDSA_ASYNC_SIGN || op_type == ECDSA_ASYNC_VERF) {
		q->capa.alg = "ecdsa";
	} else {
		q->capa.alg = "sm2";
	}

	ret = wd_request_queue(q);
	if (ret) {
		HPRE_TST_PRT("request queue fail!\n");
		return ret;
	}

	memset(&setup, 0, sizeof(setup));
	setup.block_size = get_ecc_min_blocksize(key_bits) * 8;
	setup.block_num = block_num;
	setup.align_size = 64;

	bufPool = wd_blkpool_create(q, &setup);
	if (!bufPool) {
		HPRE_TST_PRT("%s(): create pool fail!\n", __func__);
		return -ENOMEM;
	}

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	/* Create poll thread at first */
	test_thrds_data[0].pool = bufPool;
	test_thrds_data[0].q = q;
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
			     _ecc_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].pool = bufPool;
		test_thrds_data[i].q = q;
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i - 1, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _ecc_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i - 1, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].pool = bufPool;
		test_thrds_data[i + cnt].q = q;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _ecc_sys_test_thread, &test_thrds_data[i + cnt]);
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
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	wd_release_queue(q);

	return 0;
}
#endif

void *_hpre_sys_test_thread(void *data)
{
	enum alg_op_type op_type;
	struct test_hpre_pthread_dt *pdata = data;

	op_type = pdata->op_type;
	if (op_type > MAX_DH_TYPE && op_type < MAX_ECC_TYPE) {
		// return _ecc_sys_test_thread(data); todo
	} else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE) {
		// return _hpre_dh_sys_test_thread(data); todo
	} else {
		return _hpre_rsa_sys_test_thread(data);
	}
}

void normal_register(const char *format, ...)
{
    printf("wd log:%s", format);
    return ;
}

void redirect_log_2_file(const char *format, ...)
{
    pthread_mutex_lock(&mute);
    FILE *fp;
    fp = fopen("file.txt", "a+");
    fprintf(fp,format,__FILE__, __LINE__, __func__);
    fclose(fp);
    pthread_mutex_unlock(&mute);
    return ;
}

void segmant_fault_register(const char *format, ...)
{
    int *ptr = NULL;
    *ptr = 0;
    return ;
}
int main(int argc, char *argv[])
	{
	enum alg_op_type alg_op_type = HPRE_ALG_INVLD_TYPE;
	enum alg_op_mode mode;
	__u8 *in = NULL, *tp_in, *temp_in = NULL;
	__u8 *out = NULL;
	__u8 *key = NULL;
	char *in_file = NULL;
	char *out_file = NULL;
	char *key_file = NULL;
	int ret = 0, in_size = 0, op_size;
	int priv_key_size, pub_key_size, key_info_size;
	int read_size, out_fd = -1, try_close = 1;
	struct wd_rsa_sess_setup setup;
	//struct wd_dh_ctx_setup dh_setup; //todo
	void *ctx = NULL;
	int thread_num, bits;
	__u64 core_mask[2];
	u32 value = 0;
	char dev_path[PATH_STR_SIZE] = {0};
	unsigned int node_msk = 0;
	char *alg_name;

	if (!argv[1] || !argv[6]) {
		HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
		return -EINVAL;
	}

	if (argv[7] && !strcmp(argv[7], "-check"))
		openssl_check = 1;
	if (argv[7] && !strcmp(argv[7], "-soft"))
		only_soft = 1;

	if (!strcmp(argv[argc-1], "-registerlog-0")){
	ret = wd_register_log(NULL);
	if (!ret){
		printf("illegel to register null log interface");
		return -EINVAL;
	}
	return 0;
	}
	if (!strcmp(argv[argc-1], "-registerlog-1")){
	ret = wd_register_log(redirect_log_2_file);
	if (ret){
		printf("fail to register log interface");
		return -EINVAL;
	}
	if (argc == 2){
		char *error_info = "q, info or dev_info NULL!";
		struct wd_queue *q = NULL;
		char content[1024];
		//wd_get_node_id(q);
		FILE *fp = NULL;
		fp = fopen("file.txt", "r");
		if (fgets(content,1024,fp) == NULL)
		return -EINVAL;
		if (strstr(content,error_info) == NULL){
		return -EINVAL;
		}
		return 0;
	}
	}
	if (!strcmp(argv[argc-1], "-registerlog-2")){
	ret = wd_register_log(normal_register);
	if (ret){
		printf("fail to register log interface");
		return -EINVAL;
	}
	if (!wd_register_log(normal_register)){
		printf("illegel to register dumplicate log interface");
		return -EINVAL;
	}
	return 0;
	}
	if (!strcmp(argv[argc-1], "-registerlog-3")){
	ret = wd_register_log(segmant_fault_register);
	if (ret){
		printf("fail to register log interface");
		return -EINVAL;
	}
	WD_ERR("segment fault");
	return 0;
	}

	if (!strcmp(argv[1], "-system-qt")) {
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system queue mng test!\n");
	} else if (!strcmp(argv[1], "-system-gen")) {
		alg_op_type = RSA_KEY_GEN;
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system key gen test!\n");
	} else if (!strcmp(argv[1], "-system-vrf")) {
		alg_op_type = RSA_PUB_EN;
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system verify test!\n");
	} else if (!strcmp(argv[1], "-system-sgn")) {
		alg_op_type = RSA_PRV_DE;
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system sign test!\n");
	} else if (!strcmp(argv[1], "-system-asgn")) {
		alg_op_type = RSA_ASYNC_DE;
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system rsa async sign test!\n");
	} else if (!strcmp(argv[1], "-system-avrf")) {
		alg_op_type = RSA_ASYNC_EN;
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system rsa async verify test!\n");
	} else if (!strcmp(argv[1], "-system-agen")) {
		alg_op_type = RSA_ASYNC_GEN;
		is_system_test = 1;
		HPRE_TST_PRT("Now doing system rsa async kgerate test!\n");
	} else if (!strcmp(argv[1], "-system-gen1")) {
		HPRE_TST_PRT("DH key generation\n");
		alg_op_type = DH_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen1")) {
		HPRE_TST_PRT("DH gen async\n");
		alg_op_type = DH_ASYNC_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen2")) {
		HPRE_TST_PRT("DH key generation\n");
		alg_op_type = DH_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen2")) {
		HPRE_TST_PRT("DH gen async\n");
		alg_op_type = DH_ASYNC_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen1-ecc")) {
		HPRE_TST_PRT("ECDH gen sync\n");
		alg_op_type = ECDH_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen2-ecc")) {
		HPRE_TST_PRT("ECDH gen2 sync\n");
		alg_op_type = ECDH_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen1-ecc")) {
		HPRE_TST_PRT("ECDH agen sync\n");
		alg_op_type = ECDH_ASYNC_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen2-ecc")) {
		HPRE_TST_PRT("ECDH agen2 sync\n");
		alg_op_type = ECDH_ASYNC_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-sign-ecc")) {
		HPRE_TST_PRT("ECDH sign sync\n");
		alg_op_type = ECDSA_SIGN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-verf-ecc")) {
		HPRE_TST_PRT("ECDH verf sync\n");
		alg_op_type = ECDSA_VERF;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-asign-ecc")) {
		HPRE_TST_PRT("ECDH sign sync\n");
		alg_op_type = ECDSA_ASYNC_SIGN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-averf-ecc")) {
		HPRE_TST_PRT("ECDH verf sync\n");
		alg_op_type = ECDSA_ASYNC_VERF;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen1-x25519")) {
		HPRE_TST_PRT("X25519 gen sync\n");
		alg_op_type = X25519_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen2-x25519")) {
		HPRE_TST_PRT("X25519 gen2 sync\n");
		alg_op_type = X25519_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen1-x25519")) {
		HPRE_TST_PRT("X25519 agen sync\n");
		alg_op_type = X25519_ASYNC_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen2-x25519")) {
		HPRE_TST_PRT("X25519 agen2 sync\n");
		alg_op_type = X25519_ASYNC_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen1-x448")) {
		HPRE_TST_PRT("X448 gen sync\n");
		alg_op_type = X448_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-gen2-x448")) {
		HPRE_TST_PRT("X448 gen2 sync\n");
		alg_op_type = X448_COMPUTE;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen1-x448")) {
		HPRE_TST_PRT("X448 agen sync\n");
		alg_op_type = X448_ASYNC_GEN;
		is_system_test = 1;
	} else if (!strcmp(argv[1], "-system-agen2-x448")) {
		HPRE_TST_PRT("x448 agen2 sync\n");
		alg_op_type = X448_ASYNC_COMPUTE;
		is_system_test = 1;
	} else {
		goto basic_function_test;
	}

	if (argv[8]) {
		key_bits = strtoul(argv[8], NULL, 10);
	} else {
		key_bits = 2048;
	}
	if (alg_op_type >= X25519_GEN && alg_op_type <= X25519_ASYNC_COMPUTE)
		key_bits = 256;
	else if (alg_op_type >= X448_GEN && alg_op_type <= X448_ASYNC_COMPUTE)
		key_bits = 448;

	/* Do sys test for performance and mult threads/process scenarioes */
	if (is_system_test) {
		if (!strcmp(argv[2], "-t")) {
			thread_num = strtoul((char *)argv[3], NULL, 10);
			if (thread_num <= 0 || thread_num > TEST_MAX_THRD) {
				HPRE_TST_PRT("Invalid threads num:%d!\n",
								thread_num);
				HPRE_TST_PRT("Now set threads num as 2\n");
				thread_num = 2;
			}
		} else {
			HPRE_TST_PRT("./test_hisi_hpre --help get details\n");
			return -EINVAL;
		}
		if (strcmp(argv[4], "-c")) {
			HPRE_TST_PRT("./test_hisi_hpre --help get details\n");
			return -EINVAL;
		}

		if (argv[5][0] != '0' || argv[5][1] != 'x') {
			HPRE_TST_PRT("Err:coremask should be hex!\n");
			return -EINVAL;
		}
		if (strlen(argv[5]) > 34) {
			HPRE_TST_PRT("Warning: coremask is cut!\n");
			argv[5][34] = 0;
		}
		if (strlen(argv[5]) <= 18) {
			core_mask[0] = strtoull(argv[5], NULL, 16);
			if (core_mask[0] & 0x1) {
				HPRE_TST_PRT("Warn:cannot bind to core 0,\n");
				HPRE_TST_PRT("now run without binding\n");
				core_mask[0] = 0x0; /* no binding */
			}
			core_mask[1] = 0;
		} else {
			int offset = 0;
			char *temp;

			offset = strlen(argv[5]) - 16;
			core_mask[0] = strtoull(&argv[5][offset], NULL, 16);
			if (core_mask[0] & 0x1) {
				HPRE_TST_PRT("Warn:cannot bind to core 0,\n");
				HPRE_TST_PRT("now run without binding\n");
				core_mask[0] = 0x0; /* no binding */
			}
			temp = malloc(64);
			strcpy(temp, argv[5]);
			temp[offset] = 0;
			core_mask[1] = strtoull(temp, NULL, 16);
		}
		bits = _get_one_bits(core_mask[0]);
		bits += _get_one_bits(core_mask[1]);
		if (thread_num > bits) {
			HPRE_TST_PRT("Coremask not covers all thrds,\n");
			HPRE_TST_PRT("Bind first %d thrds!\n", bits);
		} else if (thread_num < bits) {
			HPRE_TST_PRT("Coremask overflow,\n");
			HPRE_TST_PRT("Just try to bind all thrds!\n");
		}
		if (!strcmp(argv[6], "-log")) {
			with_log = 1;
			performance_test = 0;
			t_times = 0;
			t_seconds = 0;
		} else if (!strcmp(argv[6], "-performance")) {
			with_log = 0;
			openssl_check = 0;
			performance_test = 1;
		} else {
			with_log = 0;
			performance_test = 0;
		}

		if (argv[9]) {
			ctx_num_per_q = strtoul(argv[9], NULL, 10);
			if (ctx_num_per_q <= 0) {
				HPRE_TST_PRT("Invalid ctx num per queue:%s!\n",
						argv[9]);
				HPRE_TST_PRT("Now ctx num per queue is set as 1!\n");
				ctx_num_per_q = 1;
			}
		} else {
			HPRE_TST_PRT("Now  ctx num per queue is set as 1!\n");
			ctx_num_per_q = 1;
		}

		q_num = (thread_num - 1) / ctx_num_per_q + 1;

		if (argc == 13) {
			if (alg_op_type > MAX_DH_TYPE && alg_op_type < MAX_ECC_TYPE) {
				ecc_curve_name = argv[10];
			/* curve x25519/x448 has th only param which is denoted in drv */
			} else if (alg_op_type >= X25519_GEN && alg_op_type <= X25519_ASYNC_COMPUTE) {
				ecc_curve_name = "";
				key_bits = 256;
			} else if (alg_op_type >= X448_GEN && alg_op_type <= X448_ASYNC_COMPUTE) {
				ecc_curve_name = "";
				key_bits = 448;
			} else {
				if (!strcmp(argv[10], "-g2")) {
					g_mode = "-g2";
				} else if (!strcmp(argv[10], "-com")) {
					g_mode = "-com";
				} else if (!strcmp(argv[10], "-crt")) {
					g_mode = "-crt";
				} else {
					HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
					return -EINVAL;
				}
			}

			if (!strcmp(argv[11], "-seconds") ||
				!strcmp(argv[11], "-cycles")) {
				value = strtoul(argv[12], NULL, 10);
				if (!strcmp(argv[11], "-seconds")) {
					t_seconds = value;
				} else if (!strcmp(argv[11], "-cycles")) {
					t_times = value;
				} else {
					HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
					return -EINVAL;
				}
			} else if (!strcmp(argv[11], "-dev")) {
				strncpy(g_dev_path, argv[12], sizeof(g_dev_path));
			} else if (!strcmp(argv[11], "-node")) {
				node_msk = strtoul(argv[12], NULL, 16);
			} else {
				HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
				return -EINVAL;
			}
		}

		if (argc == 12) {
			if (!strcmp(argv[10], "-seconds") ||
				!strcmp(argv[10], "-cycles")) {
				value = strtoul(argv[11], NULL, 10);
				if (!strcmp(argv[10], "-seconds")) {
					t_seconds = value;
				} else if (!strcmp(argv[10], "-cycles")) {
					t_times = value;
				} else {
					HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
					return -EINVAL;
				}
			} else if (!strcmp(argv[10], "-dev")) {
				strncpy(g_dev_path, argv[11], sizeof(g_dev_path));
			} else if (!strcmp(argv[10], "-node")) {
				node_msk = strtoul(argv[11], NULL, 16);
			} else {
				HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
				return -EINVAL;
			}
		}

		if (argc == 11) {
			if (alg_op_type > MAX_DH_TYPE && alg_op_type < MAX_ECC_TYPE) {
				ecc_curve_name = argv[10];
			} else if (alg_op_type >= X25519_GEN && alg_op_type <= X25519_ASYNC_COMPUTE) {
				ecc_curve_name = "";
				key_bits = 256;
			} else if (alg_op_type >= X448_GEN && alg_op_type <= X448_ASYNC_COMPUTE) {
				ecc_curve_name = "";
				key_bits = 448;
			} else {
				if (!strcmp(argv[10], "-g2")) {
					g_mode = "-g2";
				} else if (!strcmp(argv[10], "-com")) {
					g_mode = "-com";
				} else if (!strcmp(argv[10], "-crt")) {
					g_mode = "-crt";
				} else {
					HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
					return -EINVAL;
				}
			}
		}

  	ret = init_hpre_global_config();
  	if (ret) {
  		HPRE_TST_PRT("failed to init_hpre_global_config, ret %d!\n", ret);
  		return -1;
  	}

		HPRE_TST_PRT("Proc-%d: starts %d threads bind to %s\n",
						getpid(), thread_num, argv[5]);
		HPRE_TST_PRT(" lcoremask=0x%llx, hcoremask=0x%llx\n",
						core_mask[0], core_mask[1]);
		if (alg_op_type < MAX_RSA_SYNC_TYPE ||
			alg_op_type == DH_GEN || alg_op_type == DH_COMPUTE ||
			alg_op_type == ECDH_GEN || alg_op_type == ECDH_COMPUTE ||
			alg_op_type == ECDSA_SIGN || alg_op_type == ECDSA_VERF ||
			alg_op_type == X25519_GEN || alg_op_type == X25519_COMPUTE ||
			alg_op_type == X448_GEN || alg_op_type == X448_COMPUTE)
			return hpre_sys_test(thread_num, core_mask[0],
						core_mask[1], alg_op_type, g_dev_path, node_msk);
		else if (alg_op_type > MAX_RSA_SYNC_TYPE && alg_op_type < MAX_RSA_ASYNC_TYPE)
			return rsa_async_test(thread_num, core_mask[0],
						core_mask[1], alg_op_type);
		else if (alg_op_type == DH_ASYNC_GEN || alg_op_type == DH_ASYNC_COMPUTE)
			return 0;
			//return dh_async_test(thread_num, core_mask[0],
					//      core_mask[1], alg_op_type); todo
		else if (alg_op_type == ECDH_ASYNC_GEN || alg_op_type == ECDH_ASYNC_COMPUTE ||
			alg_op_type == ECDSA_ASYNC_SIGN || alg_op_type == ECDSA_ASYNC_VERF ||
			alg_op_type == X25519_ASYNC_GEN || alg_op_type == X25519_ASYNC_COMPUTE ||
			alg_op_type == X448_ASYNC_GEN || alg_op_type == X448_ASYNC_COMPUTE)
			//return ecc_async_test(thread_num, core_mask[0],
					//      core_mask[1], alg_op_type); todo
			return 0;
		else
			return -1; /* to extend other test samples */
	}
	basic_function_test:
	if (!strcmp(argv[1], "-en")) {
		alg_op_type = RSA_PUB_EN;
		HPRE_TST_PRT("RSA public key encrypto\n");
	} else if (!strcmp(argv[1], "-de")) {
		alg_op_type = RSA_PRV_DE;
		HPRE_TST_PRT("RSA private key decrypto\n");
	} else if (!strcmp(argv[1], "-gen")) {
		HPRE_TST_PRT("RSA key generation\n");
		alg_op_type = RSA_KEY_GEN;
	} else if (!strcmp(argv[1], "-gen1")) {
		HPRE_TST_PRT("DH key generation\n");
		alg_op_type = DH_GEN;
	} else if (!strcmp(argv[1], "-x25519-gen1")) {
		alg_op_type = X25519_GEN;
		HPRE_TST_PRT("X25519 phase1 key generate.\n");
	} else if (!strcmp(argv[1], "-x25519-gen2")) {
		alg_op_type = X25519_COMPUTE;
		HPRE_TST_PRT("X25519 phase2 share-key generate.\n");
	} else if (!strcmp(argv[1], "-x448-gen1")) {
		alg_op_type = X448_GEN;
		HPRE_TST_PRT("X448 phase1 key generate.\n");
	} else if (!strcmp(argv[1], "-x448-gen2")) {
		alg_op_type = X448_COMPUTE;
		HPRE_TST_PRT("X448 phase2 share-key generate.\n");
	} else if (!strcmp(argv[1], "-rsa-num")) {
		//printf("num %d\n", wd_get_available_dev_num("rsa")); todo
		return 0;
	} else if (!strcmp(argv[1], "-dh-num")) {
		//printf("num %d\n", wd_get_available_dev_num("dh"));
		return 0;
	} else if (!strcmp(argv[1], "-zip-num")) {
		//printf("num %d\n", wd_get_available_dev_num("zip"));
		return 0;
	} else if (!strcmp(argv[1], "-ecxdh-num")) {
		//printf("num %d\n", wd_get_available_dev_num("ecdh"));
		return 0;
	} else if (!strcmp(argv[1], "-ec-num")) {
		//printf("num %d\n", wd_get_available_dev_num("ec"));
		return 0;
	} else if (!strcmp(argv[1], "-xx-num")) {
		//printf("num %d\n", wd_get_available_dev_num("xx"));
		return 0;
	} else if (!strcmp(argv[1], "--help")) {
		HPRE_TST_PRT("[version]:1.0\n");
		HPRE_TST_PRT("NAME\n");
		HPRE_TST_PRT("    test_hisi_hpre: test wd hpre function,etc\n");
		HPRE_TST_PRT("        example 1: test_hisi_hpre -system-asgn -t 1 -c 0x2 -performance -nocheck 2048 2\n");
		HPRE_TST_PRT("        example 2: test_hisi_hpre -gen1 256 -g2 public private crt_private -check hisi_hpre-0\n");
		HPRE_TST_PRT("        example 3: test_hisi_hpre -system-gen1-ecc -t 1 -c 0x2 -log -check 256 2 secp128R1\n");
		HPRE_TST_PRT("SYNOPSIS\n");
		HPRE_TST_PRT("    test_hisi_hpre [op_type] -t [thread_num] -c [core_mask] [log] [openssl_check] [key_bits]...[ctx_num_per_q] [mode] [others]\n");
		HPRE_TST_PRT("    test_hisi_hpre [op_type] -t [thread_num] -c [core_mask] [log] [openssl_check] [key_bits]...[ctx_num_per_q] [curve] [others]\n");
		HPRE_TST_PRT("    test_hisi_hpre [op_type] [key_bits] [mode] [in] [out] [key_file] [openssl_check] [dev_path]...[others]\n");
		HPRE_TST_PRT("DESCRIPTION\n");
		HPRE_TST_PRT("    [op_type]:\n");
		HPRE_TST_PRT("        -system-qt  = queue request and release test\n");
		HPRE_TST_PRT("        -system-gen  = RSA key generate synchronize test\n");
		HPRE_TST_PRT("        -system-agen  = RSA key generate c test\n");
		HPRE_TST_PRT("        -system-sgn  = RSA signature synchronize test\n");
		HPRE_TST_PRT("        -system-asgn  = RSA signature asynchronize test\n");
		HPRE_TST_PRT("        -system-vrf  = RSA verification synchronize test\n");
		HPRE_TST_PRT("        -system-avrf  = RSA verification asynchronize test\n");
		HPRE_TST_PRT("        -system-gen1  = DH phase 1 key generate synchronize test\n");
		HPRE_TST_PRT("        -system-agen1  = DH phase 1 key generate asynchronize test\n");
		HPRE_TST_PRT("        -system-gen2  = DH phase 2 key generate synchronize test\n");
		HPRE_TST_PRT("        -system-agen2  = DH phase 2 key generate asynchronize test\n");
		HPRE_TST_PRT("        -system-gen1-ecc  = ECXDH phase 1 key generate synchronize test\n");
		HPRE_TST_PRT("        -system-agen1-ecc  = ECXDH phase 1 key generate asynchronize test\n");
		HPRE_TST_PRT("        -system-gen2-ecc  = ECXDH phase 2 key generate synchronize test\n");
		HPRE_TST_PRT("        -system-agen2-ecc  = ECXDH phase 2 key generate asynchronize test\n");
		HPRE_TST_PRT("        -gen1  = DH share key generate test\n");
		HPRE_TST_PRT("        -registerlog-0  = register null log interface\n");
		HPRE_TST_PRT("        -registerlog-1  = register normal log interface\n");
		HPRE_TST_PRT("        -registerlog-2  = register dumplicate log interface\n");
		HPRE_TST_PRT("        -registerlog-3  = register unnormal log interface\n");
		HPRE_TST_PRT("    [thread_num]: start thread total\n");
		HPRE_TST_PRT("    [core_mask]: mask for bind cpu core, as 0x3 bind to cpu-1 and cpu-2\n");
		HPRE_TST_PRT("    [log]:\n");
		HPRE_TST_PRT("        -log\n");
		HPRE_TST_PRT("        -nolog\n");
		HPRE_TST_PRT("        -performance: use test DH and RSA perf\n");
		HPRE_TST_PRT("    [openssl_check]:\n");
		HPRE_TST_PRT("        1: check result compared with openssl\n");
		HPRE_TST_PRT("        0: no check\n");
		HPRE_TST_PRT("    [key_bits]:key size (bits)\n");
		HPRE_TST_PRT("    [ctx_num_per_q]:run ctx number per queue\n");
		HPRE_TST_PRT("    [mode]:\n");
		HPRE_TST_PRT("        -g2  = DH G2 mode\n");
		HPRE_TST_PRT("        -com  = common mode\n");
		HPRE_TST_PRT("        -crt  = RSA CRT mode\n");
		HPRE_TST_PRT("    [curve]:\n");
		HPRE_TST_PRT("        secp128R1  = 128 bit\n");
		HPRE_TST_PRT("        secp192K1  = 192 bit\n");
		HPRE_TST_PRT("        secp256K1  = 256bit\n");
		HPRE_TST_PRT("        brainpoolP320R1  = 320bit\n");
		HPRE_TST_PRT("        brainpoolP384R1  = 384bit\n");
		HPRE_TST_PRT("        secp521R1  = 521bit\n");
		HPRE_TST_PRT("        null  = by set parameters\n");
		HPRE_TST_PRT("    [dev_path]: designed dev path\n");
		HPRE_TST_PRT("    [others]:\n");
		HPRE_TST_PRT("        -seconds [10] = test time set (s), for 10s\n");
		HPRE_TST_PRT("        -cycles [10]  = test cycle set (times), for 10 times\n");
		HPRE_TST_PRT("        -dev [hisi_hpre-0]  = denote device path\n");
		HPRE_TST_PRT("        -node [1]  = denote device numa node\n");
		HPRE_TST_PRT("    [--help]  = usage\n");
		return 0;
	} else {
		HPRE_TST_PRT("Unknown option\n");
		HPRE_TST_PRT("<<use ./test_hisi_hpre --help get details>>\n");
		return -EINVAL;
	}
	if (argv[2]) {
		key_bits = strtoul(argv[2], NULL, 10);
		if (key_bits != 1024 && key_bits != 2048 &&
			key_bits != 3072 && key_bits != 4096) {
			key_bits = 2048;
		}
	} else {
		key_bits = 2048;
	}
	HPRE_TST_PRT("RSA/DH key size=%d bits\n", key_bits);
	if (!strcmp(argv[3], "-crt")) {
		HPRE_TST_PRT("RSA CRT mode\n");
		mode = RSA_CRT_MD;
	} else if (!strcmp(argv[3], "-com") && alg_op_type < MAX_RSA_ASYNC_TYPE) {
		HPRE_TST_PRT("RSA Common mode\n");
		mode = RSA_COM_MD;
	} else if (!strcmp(argv[3], "-com") && alg_op_type > MAX_RSA_ASYNC_TYPE) {
		HPRE_TST_PRT("DH Common mode\n");
		mode = DH_COM_MD;
	} else if (!strcmp(argv[3], "-g2")) {
		HPRE_TST_PRT("DH g2 mode\n");
		mode = DH_G2;
	} else {
		HPRE_TST_PRT("please input a mode:<-crt> <-com>for rsa!\n");
		HPRE_TST_PRT("and:<-g2> <-com>for dh!\n");
		return -EINVAL;
	}
	in_file = argv[4];
	out_file = argv[5];
	key_file = argv[6];
	if (argc >= 9) {
		strncpy(g_dev_path, argv[8], sizeof(g_dev_path));
		HPRE_TST_PRT("denote dev path:%s\n", argv[8]);
	}

	if (argc >= 10) {
		node_msk = strtoul(argv[9], NULL, 16);
		HPRE_TST_PRT("denote node_id %d\n", node_msk);
	}

	if (alg_op_type < MAX_RSA_ASYNC_TYPE && alg_op_type > HPRE_ALG_INVLD_TYPE) {
		alg_name = "rsa";
	} else if (alg_op_type < MAX_DH_TYPE &&
		alg_op_type > MAX_RSA_ASYNC_TYPE) {
		alg_name = "dh";
	} else {
		HPRE_TST_PRT("op type err!\n");
		return -EINVAL;
	}

	HPRE_TST_PRT("Get a WD HPRE queue of %s successfully!\n", alg_name);
	//memset(&dh_setup, 0, sizeof(dh_setup)); //todo
	memset(&setup, 0, sizeof(setup));
	if (alg_op_type < MAX_RSA_ASYNC_TYPE && mode == RSA_CRT_MD) {
		setup.is_crt = 1;
	} else if (alg_op_type < MAX_RSA_ASYNC_TYPE && mode == RSA_COM_MD) {
		setup.is_crt = 0;
	} else if (alg_op_type > MAX_RSA_ASYNC_TYPE &&
				alg_op_type < HPRE_MAX_OP_TYPE && mode == DH_COM_MD) {
		// dh_setup.is_g2 = 0; //todo
	} else if (alg_op_type > MAX_RSA_ASYNC_TYPE &&
				alg_op_type < HPRE_MAX_OP_TYPE && mode == DH_G2) {
		//dh_setup.is_g2 = 1; //todo
	} else {
		HPRE_TST_PRT("op type or mode err!\n");
		ret = -ENOMEM;
		goto release_q;
	}

	if (!strncmp(alg_name, "rsa", 3)) {
		setup.key_bits = key_bits;
		ctx = wd_rsa_alloc_sess(&setup);
		if (!ctx) {
			ret = -ENOMEM;
			HPRE_TST_PRT("create rsa ctx fail!\n");
			goto release_q;
		}
	} else if (!strncmp(alg_name, "dh", 2)) {
	#if 0 //todo
		dh_setup.key_bits = key_bits;
		ctx = wd_create_dh_ctx(&q, &dh_setup);
		if (!ctx) {
			ret = -ENOMEM;
			HPRE_TST_PRT("create dh ctx fail!\n");
			goto release_q;
		}
	#endif
	}

	if (alg_op_type == RSA_KEY_GEN) {
		/* As generate key, we take in_file for storing public key
			* and out_file for storing private key.
			*/
	#ifdef RSA_OP_DEBUG
		return  hpre_test_rsa_op(alg_op_type, ctx, (__u8 *)in_file,
						key_bits >> 3, (__u8 *)out_file, (__u8 *)key_file);
	#else
		HPRE_TST_PRT("hpre_test_rsa_op not supported currently!\n");
		return 0;
	#endif
	} else if (alg_op_type == DH_GEN) {
		// ret = hpre_dh_test(ctx, pool); todo
		// wd_del_dh_ctx(ctx); todo
		return ret;
	} else if (alg_op_type == RSA_PUB_EN && (mode == RSA_CRT_MD ||
			mode == RSA_COM_MD)) {
		read_size = pub_key_size = key_bits >> 2;
	} else if (alg_op_type == RSA_PRV_DE && mode == RSA_CRT_MD) {
		read_size = priv_key_size = (key_bits >> 4)  * 5;
	} else if (alg_op_type == RSA_PRV_DE && mode == RSA_COM_MD) {
		read_size = priv_key_size = key_bits >> 2;
	} else {
		HPRE_TST_PRT("op=%d mode=%d CMD err!\n", alg_op_type, mode);
		ret = -EINVAL;
		goto release_q;
	}
	if (openssl_check && alg_op_type != RSA_PUB_EN)
		key_info_size = read_size + (key_bits >> 2);
	else
		key_info_size = read_size;

	/* while we check the hw result, we need more info such as n and e */
	key = malloc(key_info_size);
	if (!key) {
		HPRE_TST_PRT("malloc key fail!\n");
		ret = -ENOMEM;
		goto release_q;
	}
	ret = hpre_test_read_from_file(key, key_file, key_info_size);
	if (ret < 0 || key_info_size != ret) {
		HPRE_TST_PRT("Fail to get key from %s!\n", key_file);
		HPRE_TST_PRT("Please input right RSA key!\n");
		goto release_q;
	}

	/* Try to get the input file size */
	read_size = hpre_test_get_file_size(in_file);
	if (read_size <= 0) {
		HPRE_TST_PRT("%s file is not valid!\n", in_file);
		goto release_q;
	}

	in = malloc(read_size + (key_bits >> 3));
	if (!in) {
		HPRE_TST_PRT("Fail to malloc mem for %s!\n", in_file);
		goto release_q;
	}
	memset(in, 0, read_size + (key_bits >> 3));
	ret = hpre_test_read_from_file(in, in_file, read_size);
	if (ret != read_size) {
		HPRE_TST_PRT("Fail to get data from %s!\n", in_file);
		goto release_q;
	}
	out = malloc(key_bits >> 3);
	if (!out) {
		HPRE_TST_PRT("Fail to malloc mem for output!\n");
		goto release_q;
	}
	memset(out, 0, key_bits >> 3);

	/* Initiated input Size */
	if (alg_op_type == RSA_PRV_DE) {
		in_size = key_bits >> 3;
	} else {
		in_size = (key_bits >> 3) - HPRE_PADDING_SZ;
		temp_in = malloc(key_bits >> 3);
		if (!temp_in) {
			HPRE_TST_PRT("Fail to malloc mem for temp in!\n");
			goto release_q;
		}
		memset(temp_in, 0, key_bits >> 3);
	}
	tp_in = in;
	do {
		/* While read_size is small the key size, it is finished */
		if (read_size - in_size > 0) {
			op_size = in_size;
			try_close = 0;
		} else {
			op_size = read_size;
			try_close = 1;
		}
	#ifdef RSA_OP_DEBUG
		if (alg_op_type == RSA_PUB_EN) {
			memcpy(temp_in, tp_in, op_size);
			ret = hpre_test_rsa_op(alg_op_type, ctx, temp_in, op_size, out, key);
		} else {
			ret = hpre_test_rsa_op(alg_op_type, ctx, tp_in, op_size, out, key);
		}
	#endif
		if (ret < 0) {
			HPRE_TST_PRT("HPRE operates failing!\n");
			goto release_q;
		}

		ret = hpre_test_write_to_file(out, ret, out_file,
										out_fd, try_close);
		if (ret < 0) {
			HPRE_TST_PRT("Fail to write output buffer to %s!\n",
							out_file);
			goto release_q;
		}
		if (key) {
			free(key);
			key = NULL;
		}
		if (try_close && openssl_check) {
			if (alg_op_type == RSA_PUB_EN)
				HPRE_TST_PRT("HPRE pub encrypt"\
				" %s to %s success!\n", in_file, out_file);
			else
				HPRE_TST_PRT("HPRE priv decrypt"\
				" %s to %s success!\n", in_file, out_file);
		} else if (try_close) {
			if (alg_op_type == RSA_PUB_EN)
				HPRE_TST_PRT("HPRE pub encrypt"\
				" %s to %s finished!\n", in_file, out_file);
			else
				HPRE_TST_PRT("HPRE priv decrypt"\
				" %s to %s finished!\n", in_file, out_file);
		}
		out_fd = ret;
		tp_in += op_size;
		read_size -= op_size;
	} while (!try_close);
	release_q:
	if (in)
		free(in);
	if (out)
		free(out);
	if (key)
		free(key);
	if (temp_in)
		free(temp_in);
	wd_rsa_free_sess(ctx);

	return ret;
	}
