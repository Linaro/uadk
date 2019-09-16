/* SPDX-License-Identifier: Apache-2.0 */
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

#include "test_hisi_hpre.h"
#include "../../wd.h"
#include "../../wd_rsa.h"
#include "../../wd_dh.h"
#include "../../wd_bmm.h"

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

struct bignum_st {
	BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
					 * chunks. */
	int top;                    /* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;                   /* Size of the d array. */
	int neg;                    /* one if the number is negative */
	int flags;
};

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
	int thread_num;
	void *pool;
	void *q;
};

/* stub definitions */
typedef struct rsa_st RSA;
typedef struct dh_st DH;
typedef struct bignum_st BIGNUM;
typedef struct bn_gencb_st BN_GENCB;

enum dh_check_index {
	DH_INVALID,
	DH_ALICE_PUBKEY,
	DH_BOB_PUBKEY,
	DH_ALICE_PRIVKEY
};

enum dh_ctxg_idx {
	DH_CTXG_ALICE,
	DH_CTXG_BOB,
	DH_CTXG_MAX
};

struct rsa_async_tag {
	void *ctx;
	int thread_id;
	int cnt;
};

struct dh_sw_alg_result {
	const BIGNUM *p;
	const BIGNUM *g;
	const BIGNUM *x;
	const BIGNUM *pub_key;//first step
	const unsigned char *priv_key;//second step, need user malloc
};

struct dh_user_tag_info {
	void *pool;
	struct timeval start_tval;
	enum dh_check_index steps;
	const void *pkey;
	int keySize;
	int pid;
	int thread_id;
	int times;
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

static int key_bits = 2048;
static int openssl_check;
static int only_soft;
static int with_log;
static int is_system_test;
static int ctx_num_per_q = 1;
static int q_num = 1;

static __thread RSA *hpre_test_rsa;
static __thread DH *alice = NULL;
static __thread DH *bob = NULL;
static __thread struct dh_sw_alg_result g_alicePara;
static __thread struct dh_sw_alg_result g_bobPara;
static __thread bool g_ctxg_set[DH_CTXG_MAX];
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct test_hpre_pthread_dt test_thrds_data[TEST_MAX_THRD];
static struct async_test_openssl_param ssl_params;

static char *rsa_op_str[WCRYPTO_RSA_GENKEY + 1] = {
		"invalid_op",
		"rsa_sign",
		"rsa_verify",
		"rsa_keygen",
};

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
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
void *_hpre_sys_test_thread(void *data);

#ifdef DEBUG
static void print_data(void *ptr, int size, const char *name)
{
	__u32 i = 0;
	__u8* p = ptr;

	printf("%s:start_addr=%p\n", name, ptr);
	for (i = 1; i <= size; i++) {
		printf("%02x", p[i - 1]);
		if (i % 16 == 0)
			printf("\n");
	}
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

static int hpre_bn_format(void *buff, int len, int buf_len)
{
	int i = buf_len - 1;
	int j = 0;
	unsigned char *buf = buff;

	if (!buf || len <= 0) {
		HPRE_TST_PRT("%s params err!\n", __func__);
		return -1;
	}
	if (len == buf_len)
		return 0;

	if (len < buf_len)
		return  -1;

	for (j = len - 1; j >= 0; j--, i--) {
		if (i >= 0)
			buf[j] = buf[i];
		else
			buf[j] = 0;
	}
	return 0;
}

static int test_rsa_key_gen(void *ctx, char *pubkey_file,
			char *privkey_file,
			char *crt_privkey_file, int is_file)
{
	int ret, bits;
	RSA *test_rsa;
	BIGNUM *p, *q, *e_value, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	struct wd_dtb *wd_e, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	struct wcrypto_rsa_pubkey *pubkey;
	struct wcrypto_rsa_prikey *prikey;

	bits = wcrypto_rsa_key_bits(ctx);
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
	wcrypto_get_rsa_pubkey(ctx, &pubkey);
	wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, &wd_n);
	wd_e->dsize = BN_bn2bin(e, (unsigned char *)wd_e->data);
	if (wd_e->dsize > wd_e->bsize) {
		HPRE_TST_PRT("e bn to bin overflow!\n");
		goto gen_fail;
	}
	wd_n->dsize = BN_bn2bin(n, (unsigned char *)wd_n->data);
	if (wd_n->dsize > wd_n->bsize) {
		HPRE_TST_PRT("n bn to bin overflow!\n");
		goto gen_fail;
	}
	if (pubkey_file && is_file) {
		ret = hpre_test_write_to_file((unsigned char *)wd_e->data, key_bits >> 2,
					  pubkey_file, -1, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("RSA public key was written to %s!\n",
					 privkey_file);
	}

	wcrypto_get_rsa_prikey(ctx, &prikey);
	wcrypto_get_rsa_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);

	/* CRT mode private key */
	wd_dq->dsize = BN_bn2bin(dmq1, (unsigned char *)wd_dq->data);
	if (wd_dq->dsize > wd_dq->bsize) {
		HPRE_TST_PRT("dq bn to bin overflow!\n");
		goto gen_fail;
	}
	wd_dp->dsize = BN_bn2bin(dmp1, (unsigned char *)wd_dp->data);
	if (wd_dp->dsize > wd_dp->bsize) {
		HPRE_TST_PRT("dp bn to bin overflow!\n");
		goto gen_fail;
	}
	wd_q->dsize = BN_bn2bin(q, (unsigned char *)wd_q->data);
	if (wd_q->dsize > wd_q->bsize) {
		HPRE_TST_PRT("q bn to bin overflow!\n");
		goto gen_fail;
	}
	wd_p->dsize = BN_bn2bin(p, (unsigned char *)wd_p->data);
	if (wd_p->dsize > wd_p->bsize) {
		HPRE_TST_PRT("p bn to bin overflow!\n");
		goto gen_fail;
	}
	wd_qinv->dsize = BN_bn2bin(iqmp, (unsigned char *)wd_qinv->data);
	if (wd_qinv->dsize > wd_qinv->bsize) {
		HPRE_TST_PRT("qinv bn to bin overflow!\n");
		goto gen_fail;
	}
	if (crt_privkey_file && is_file) {
		ret = hpre_test_write_to_file((unsigned char *)wd_dq->data,
					  (key_bits >> 4) * 5, crt_privkey_file, -1, 0);
		if (ret < 0)
			goto gen_fail;
		ret = hpre_test_write_to_file((unsigned char *)wd_e->data,
					  (key_bits >> 2), crt_privkey_file, ret, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("RSA CRT private key was written to %s!\n",
					 crt_privkey_file);
	} else if (crt_privkey_file && !is_file) {
		memcpy(crt_privkey_file, wd_dq->data, (key_bits >> 4) * 5);
		memcpy(crt_privkey_file + (key_bits >> 4) * 5,
			   wd_e->data, (key_bits >> 2));
	}

#ifdef NO_CRT_RSA /* no okay */

	/* common mode private key */
	prikey->pkey1.dbytes = BN_bn2bin(d, prikey->pkey1.d);
	prikey->pkey1.nbytes = BN_bn2bin(n, prikey->pkey1.n);
	if (privkey_file && is_file) {
		ret = hpre_test_write_to_file(prikey->pkey1.d,
					  (key_bits >> 2),
					  privkey_file, -1, 0);
		if (ret < 0)
			goto gen_fail;
		ret = hpre_test_write_to_file(pubkey->e,
					  (key_bits >> 2),
					  privkey_file, ret, 1);

		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("RSA common private key was written to %s!\n",
					 privkey_file);
	}
#endif
	RSA_free(test_rsa);
	BN_free(e_value);
	return 0;
gen_fail:
	RSA_free(test_rsa);
	BN_free(e_value);

	return ret;
}

int hpre_test_fill_keygen_opdata(void *ctx, struct wcrypto_rsa_op_data *opdata)
{
	struct wd_dtb *e, *p, *q;
	struct wcrypto_rsa_pubkey *pubkey;
	struct wcrypto_rsa_prikey *prikey;

	wcrypto_get_rsa_pubkey(ctx, &pubkey);
	wcrypto_get_rsa_pubkey_params(pubkey, &e, NULL);
	wcrypto_get_rsa_prikey(ctx, &prikey);
	wcrypto_get_rsa_crt_prikey_params(prikey, NULL , NULL, NULL, &q, &p);
	opdata->in = wcrypto_new_kg_in(ctx, e, p, q);
	if (!opdata->in) {
		HPRE_TST_PRT("create rsa kgen in fail!\n");
		return -ENOMEM;
	}
	opdata->out = wcrypto_new_kg_out(ctx);
	if (!opdata->out) {
		HPRE_TST_PRT("create rsa kgen out fail!\n");
		return -ENOMEM;
	}
	return 0;
}

static int hpre_test_get_bin_size(__u8 *bin, int csize)
{
	int i = csize - 1;
	int cut = 0;

	while (!(*(__u8 *)(bin + i)) && i >= 0) {
		i--;
		cut++;
	}

	return csize - cut;
}

static BIGNUM *hpre_bin_to_bn(void *bin, int raw_size)
{
	int bin_size;

	if (!bin || !raw_size)
		return NULL;
	bin_size = hpre_test_get_bin_size((__u8 *)bin, raw_size);
	return BN_bin2bn((const unsigned char *)bin, bin_size, NULL);
}

int hpre_test_result_check(void *ctx,  struct wcrypto_rsa_op_data *opdata, void *key)
{
	struct wcrypto_rsa_kg_out *out = (void *)opdata->out;
	struct wcrypto_rsa_prikey *prikey;
	int ret, keybits, key_size;
	void *ssl_out;
	BIGNUM *nn;
	BIGNUM *e;

	if (!hpre_test_rsa) {
		hpre_test_rsa = RSA_new();
		if (!hpre_test_rsa) {
			HPRE_TST_PRT("%s:RSA new fail!\n", __func__);
			return -ENOMEM;
		}
	}
	wcrypto_get_rsa_prikey(ctx, &prikey);
	keybits = wcrypto_rsa_key_bits(ctx);
	key_size = keybits >> 3;
	if (opdata->op_type == WCRYPTO_RSA_GENKEY) {
		if (wcrypto_rsa_is_crt(ctx)) {
			struct wd_dtb qinv, dq, dp;
			struct wd_dtb *s_qinv, *s_dq, *s_dp;

			wcrypto_get_rsa_crt_prikey_params(prikey, &s_dq, &s_dp,
							&s_qinv, NULL, NULL);
			wcrypto_get_rsa_kg_out_crt_params(out, &qinv, &dq, &dp);

			if (memcmp(s_qinv->data, qinv.data, s_qinv->bsize)) {
				HPRE_TST_PRT("keygen  qinv  mismatch!\n");
				return -EINVAL;
			}
			if (memcmp(s_dq->data, dq.data, s_dq->bsize)) {
				HPRE_TST_PRT("keygen  dq mismatch!\n");
				return -EINVAL;
			}
			if (memcmp(s_dp->data, dp.data, s_dp->bsize)) {
				HPRE_TST_PRT("keygen  dp  mismatch!\n");
				return -EINVAL;
			}
		} else {
			struct wd_dtb d, n;
			struct wd_dtb *s_d, *s_n;

			wcrypto_get_rsa_kg_out_params(out, &d, &n);

			wcrypto_get_rsa_prikey_params(prikey, &s_d, &s_n);

			/* check D */
			if (memcmp(s_n->data, n.data, s_n->bsize)) {
				HPRE_TST_PRT("key generate N result mismatching!\n");
				return -EINVAL;
			}
			if (memcmp(s_d->data, d.data, s_d->bsize)) {
				HPRE_TST_PRT("key generate D result mismatching!\n");
				return -EINVAL;
			}
		}
	} else if (opdata->op_type == WCRYPTO_RSA_VERIFY) {
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
			ret = RSA_set0_key(hpre_test_rsa, nn, e, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("e set0_key err!\n");
				return -EINVAL;
			}
		}
		ret = RSA_public_encrypt(opdata->in_bytes, opdata->in, ssl_out,
					 hpre_test_rsa, RSA_NO_PADDING);
		if (ret != (int)opdata->in_bytes) {
			HPRE_TST_PRT("openssl pub encrypto fail!ret=%d\n", ret);
			return -ENOMEM;
		}
		if (!only_soft && memcmp(ssl_out, opdata->out, key_size)) {
			HPRE_TST_PRT("pub encrypto result  mismatch!\n");
			return -EINVAL;
		}
		free(ssl_out);
	} else {
		ssl_out = malloc(key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("malloc ssl out fail!\n");
			return -ENOMEM;
		}
		if (key && wcrypto_rsa_is_crt(ctx)) {
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
			ret = RSA_set0_crt_params(hpre_test_rsa, dp, dq, iqmp);
			if (ret <= 0) {
				HPRE_TST_PRT("set0_crt_params err!\n");
				return -EINVAL;
			}
			ret = RSA_set0_factors(hpre_test_rsa, p, q);
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
			ret = RSA_set0_key(hpre_test_rsa, nn, e, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("rsa set0_key crt err!\n");
				return -EINVAL;
			}
		} else if (key && !wcrypto_rsa_is_crt(ctx)) {
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
			ret = RSA_set0_key(hpre_test_rsa, nn, e, d);
			if (ret <= 0) {
				HPRE_TST_PRT("d set0_key err!\n");
				return -EINVAL;
			}
		}
		ret = RSA_private_decrypt(opdata->in_bytes, opdata->in, ssl_out,
					hpre_test_rsa, RSA_NO_PADDING);
		if (ret != (int)opdata->in_bytes) {
			HPRE_TST_PRT("openssl priv decrypto fail!ret=%d\n", ret);
			return -ENOMEM;
		}
#ifdef DEBUG
		print_data(opdata->out, 16, "out");
		print_data(opdata->in, 16, "in");
		print_data(ssl_out, 16, "ssl_out");
#endif
		if (!only_soft && memcmp(ssl_out, opdata->out, ret)) {
			HPRE_TST_PRT("prv decrypto result  mismatch!\n");
			return -EINVAL;
		}
		free(ssl_out);
	}

	return 0;
}

static inline void set_alice_pg(const BIGNUM *p, const BIGNUM *g)
{
	g_alicePara.p = p;
	g_alicePara.g = g;
}

static inline void set_alice_x(const BIGNUM *x)
{
	g_alicePara.x = x;
}

static inline void set_alice_pubkey(const BIGNUM *pubkey)
{
	g_alicePara.pub_key = pubkey;
}

static inline const void* get_alice_privkey(void)
{
	return g_alicePara.priv_key;
}


static inline void set_bob_pg(const BIGNUM *p, const BIGNUM *g)
{
	g_bobPara.p = p;
	g_bobPara.g = g;
}

static inline void set_bob_x(const BIGNUM *x)
{
	g_bobPara.x = x;
}

static inline void set_bob_pubkey(const BIGNUM *pubkey)
{
	g_bobPara.pub_key = pubkey;
}

static inline void set_bob_privkey(const unsigned char *privkey)
{
	g_bobPara.priv_key = privkey;
}

static inline int init_openssl_dh_param(int keySize)
{
	if (keySize <= 0)
		return -1;

	if (!g_alicePara.priv_key)
		g_alicePara.priv_key = malloc(keySize);
	if (!g_bobPara.priv_key)
		g_bobPara.priv_key = malloc(keySize);

	if (!g_alicePara.priv_key || !g_bobPara.priv_key) {
		HPRE_TST_PRT("malloc fail!\n");
		return -1;
	}

	if (!alice)
		alice = DH_new();
	if (!bob)
		bob = DH_new();

	if (!alice || !bob) {
		HPRE_TST_PRT("New DH fail!\n");
		return -1;
	}
	return 0;
}

static inline void* get_alice_param(void)
{
	return &g_alicePara;
}

static inline void* get_bob_param(void)
{
	return &g_bobPara;
}

int dh_sw_generate_pubkey(void *ctx, __u32 isAlice)
{
	const BIGNUM *p = NULL, *g = NULL, *tp = NULL, *tg = NULL;
	const BIGNUM *pubkey = NULL, *privkey = NULL;
	struct dh_sw_alg_result *pdata = NULL;
	int keyBits = wcrypto_dh_key_bits(ctx);
	int generator;
	int ret = 0;

	if (!ctx) {
		HPRE_TST_PRT("%s->%d: ctx NULL!\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (wcrypto_dh_is_g2(ctx))
		generator = DH_GENERATOR_2;
	else
		generator = DH_GENERATOR_5;

	if (isAlice) {
		/* Alice generates DH parameters */
		keyBits = wcrypto_dh_key_bits(ctx);
		ret = DH_generate_parameters_ex(alice, keyBits, generator, NULL);
		if (!ret) {
			HPRE_TST_PRT("DH_generate_parameters_ex fail!\n");
			return ret;
		}
		DH_get0_pqg(alice, &p, NULL, &g);
		set_alice_pg(p, g);
		tp = BN_dup(p);
		tg = BN_dup(g);

		/* Set the same parameters on Bob as Alice :) */
		set_bob_pg(tp, tg);

		/* alice generate publickey */
		if (!DH_generate_key(alice)) {
			HPRE_TST_PRT("Alice DH_generate_key fail!\n");
			ret = -1;
			return ret;
		}
		DH_get0_key(alice, &pubkey, &privkey);
		set_alice_x(privkey);
		set_alice_pubkey(pubkey);
	} else {
		pdata = get_bob_param();
		DH_set0_pqg(bob, (BIGNUM *)pdata->p, NULL, (BIGNUM *)pdata->g);

		/* Bob uses the same parameters to generate pubkey */
		if (!DH_generate_key(bob)) {
			HPRE_TST_PRT("b DH_generate_key fail!\n");
			ret = -1;
			return ret;
		}
		DH_get0_key(bob, &pubkey, &privkey);
		set_bob_x(privkey);
		set_bob_pubkey(pubkey);
	}
	return 0;
}

int dh_sw_generate_privkey(void*ctx, __u32 isAlice)
{
	struct dh_sw_alg_result *pdata = NULL;
	int ret =0;

	if (!ctx) {
		return -EINVAL;
	}

	if (isAlice) {
		pdata = get_bob_param();
		ret = DH_compute_key((unsigned char *)get_alice_privkey(), pdata->pub_key, alice);
		if (!ret) {
			HPRE_TST_PRT("DH_compute_key fail!\n");
			return -1;
		}
		ret = 0;
	} else {
		HPRE_TST_PRT("bob dont generate privkey now!\n");
		ret = -1;
	}

	return ret;
}

int dh_hw_generate_pubkey(void* ctx, struct wcrypto_dh_op_data *opdata, __u32 isAlice, void* tag)
{
	struct dh_sw_alg_result *pSwData = NULL;
	struct wd_dtb g;
	unsigned char *p = NULL, *x = NULL;
	__u32 gbytes = 0, keyBits, keySize;
	int ret = 0;

	if (!ctx || !opdata)
		return -EINVAL;

	keyBits = wcrypto_dh_key_bits(ctx);
	keySize = keyBits >> 3;

	g.data = malloc(keySize);
	if (!g.data)
		return -ENOMEM;

	x = opdata->x_p;
	p = opdata->x_p + keySize;
	memset(g.data, 0, keySize);

	if (isAlice)
		pSwData = get_alice_param();
	else
		pSwData = get_bob_param();

	gbytes = BN_bn2bin(pSwData->g, (unsigned char*)g.data);
	g.dsize = gbytes;
	g.bsize = keySize;

	if ((isAlice && !g_ctxg_set[DH_CTXG_ALICE])
		|| (!isAlice && !g_ctxg_set[DH_CTXG_BOB])) {
		ret = wcrypto_set_dh_g(ctx, &g);
		if (ret) {
			HPRE_TST_PRT("wcrypto_set_dh_g fail!\n");
			return -1;
		}
		if (isAlice)
			g_ctxg_set[DH_CTXG_ALICE] = true;
		else
			g_ctxg_set[DH_CTXG_BOB] = true;
	}
	free(g.data);
	opdata->pbytes = BN_bn2bin(pSwData->p, p);
	opdata->xbytes = BN_bn2bin(pSwData->x, x);
	opdata->op_type = WCRYPTO_DH_PHASE1;

try_again:
	ret = wcrypto_do_dh(ctx, opdata, tag);
	if (ret == -WD_EBUSY) {
		usleep(100);
		goto try_again;
	}

	return ret;
}

int dh_hw_generate_privkey(void*ctx, struct wcrypto_dh_op_data* opdata, __u32 isAlice, void* tag)
{
	struct dh_sw_alg_result *pSwData_a = NULL, *pSwData_b;
	unsigned char *p = NULL, *x= NULL;
	__u32 keyBits, keySize;
	int ret;

	if (!ctx)
		return -EINVAL;

	keyBits = wcrypto_dh_key_bits(ctx);
	keySize = keyBits >> 3;
	pSwData_a = get_alice_param();
	pSwData_b = get_bob_param();
	x= opdata->x_p;
	p = opdata->x_p + keySize;
	opdata->pvbytes = BN_bn2bin(pSwData_b->pub_key, (unsigned char*)opdata->pv);
	opdata->pbytes = BN_bn2bin(pSwData_a->p, p);
	opdata->xbytes = BN_bn2bin(pSwData_a->x, x);
	opdata->op_type = WCRYPTO_DH_PHASE2;
try_again:
	ret = wcrypto_do_dh(ctx, opdata, tag);
	if (ret == -WD_EBUSY) {
		usleep(100);
		goto try_again;
	}

	return ret;
}

const void* get_check_sw_alg_result(enum dh_check_index idx)
{
	struct dh_sw_alg_result *pData = NULL;
	const void* pkey = NULL;
	
	switch (idx) {
		case DH_ALICE_PUBKEY:
		{
			pData = get_alice_param();
			pkey = pData->pub_key;
		}
		break;

		case DH_BOB_PUBKEY:
		{
			pData = get_bob_param();
			pkey = pData->pub_key;
		}
		break;

		case DH_ALICE_PRIVKEY:
		{
			pData = get_alice_param();
			pkey = pData->priv_key;
		}
		break;

		default:
		break;
	}

	return pkey;
}

static int test_hpre_bin_to_crypto_bin(char *dst, char *src, int para_size)
{
	int i = 0, j = 0, cnt = 0;

	if (!dst || !src || para_size <= 0) {
		HPRE_TST_PRT("%s params err!\n", __func__);
		return -WD_EINVAL;
	}
	while (!src[j])
		j++;
	if (j == 0 && src == dst)
		return WD_SUCCESS;
	for (i = 0, cnt = j; i < para_size; j++, i++) {
		if (i < para_size - cnt)
			dst[i] = src[j];
		else
			dst[i] = 0;
	}

	return WD_SUCCESS;
}

int dh_result_check(enum dh_check_index idx, int keySize,
					struct wcrypto_dh_op_data opdata, 
					const void *pkey)
{
	unsigned char *pkeyBin = NULL;
	int ret, needFree = 0, i;

	if (pkey == NULL) {
		HPRE_TST_PRT("pkey NULL!\n");
		return -1;
	}

	if (idx != DH_ALICE_PRIVKEY) {
		pkeyBin = malloc(keySize);
		if (!pkeyBin) {
			HPRE_TST_PRT("malloc pkeyBin fail!\n");
			ret = -ENOMEM;
			return ret;
		}

		needFree = 1;
		memset((void *)pkeyBin, 0, keySize);
		ret = BN_bn2bin((const BIGNUM *)pkey, pkeyBin);
		if (!ret) {
			HPRE_TST_PRT("apub_key bn 2 bin fail!\n");
			goto dh_err;
		}
	}
	else
		pkeyBin = (unsigned char *)pkey;

	for (i = keySize - 1; pkeyBin[i] == 0 && i >= 0; i--) {
		ret = test_hpre_bin_to_crypto_bin(opdata.pri, opdata.pri, keySize);
		if (ret) {
			HPRE_TST_PRT("dh out share key format fail!\n");
			goto dh_err;
		}
		break;
	}
	ret = 0;
	if (memcmp(pkeyBin, opdata.pri, keySize)) {
		HPRE_TST_PRT("key %d gen mismatch!\n", idx);
		ret = -EINVAL;
	}

#ifdef DEBUG
	if (ret) {
		print_data(pkeyBin, keySize, "SOFT");
		print_data(opdata.pri, keySize, "HARDWATE");
	}
#endif

	dh_err:
		if (pkeyBin && needFree) {
			free(pkeyBin);
			pkeyBin = NULL;
		}
	return ret;
}


int hpre_dh_test(void *c, struct hpre_queue_mempool *pool)
{
	DH *a = NULL, *b = NULL;
	int ret, generator = DH_GENERATOR_5;
	struct wcrypto_dh_op_data opdata_a;
	struct wcrypto_dh_op_data opdata_b;
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
	int key_size, key_bits, i;

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
	if (wcrypto_dh_is_g2(c))
		generator = DH_GENERATOR_2;

	key_bits = wcrypto_dh_key_bits(c);
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
	ag_bin = wd_alloc_blk(pool);
	if (!ag_bin) {
		HPRE_TST_PRT("pool alloc ag_bin fail!\n");
		goto dh_err;
	}
	memset(ag_bin, 0, key_size * 2);
	apriv_key_bin = wd_alloc_blk(pool);
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
	g.bsize = gbytes;
	g.dsize = key_size;
	opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
	opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
	ret = wcrypto_set_dh_g(c, &g);
	if (ret) {
		HPRE_TST_PRT("Alice wcrypto_set_dh_g fail!\n");
		goto dh_err;
	}
	opdata_a.x_p = apriv_key_bin;
	opdata_a.pri = wd_alloc_blk(pool);
	if (!opdata_a.pri) {
		HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
		goto dh_err;
	}
	memset(opdata_a.pri, 0, key_size * 2);

	opdata_a.op_type = WCRYPTO_DH_PHASE1;

	/* Alice computes public key */
	ret = wcrypto_do_dh(c, &opdata_a, tag);
	if (ret) {
		HPRE_TST_PRT("a wcrypto_do_dh fail!\n");
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
			goto dh_err;
		}
		ret = hpre_bn_format(apub_key_bin, key_size, key_size);
		if (ret) {
			HPRE_TST_PRT("hpre_bn_format bpub_key bin fail!\n");
			goto dh_err;
		}

		for (i = key_size - 1; apub_key_bin[i] == 0 && i >= 0; i--) {
			ret = test_hpre_bin_to_crypto_bin(opdata_a.pri, opdata_a.pri, key_size);
			if (ret) {
				HPRE_TST_PRT("dh out share key format fail!\n");
				goto dh_err;
			}
			ret = 0;
			break;
		}

		if (memcmp(apub_key_bin, opdata_a.pri, key_size)) {
			HPRE_TST_PRT("Alice HPRE DH key gen pub mismatch!\n");
			ret = -EINVAL;
			goto dh_err;
		}
	}
	if (!DH_generate_key(b)) {
		HPRE_TST_PRT("b DH_generate_key fail!\n");
		ret = -1;
		goto dh_err;
	}
	DH_get0_key(b, &bpub_key, &bpriv_key);
	bg_bin = wd_alloc_blk(pool);
	if (!bg_bin) {
		HPRE_TST_PRT("pool alloc bg_bin fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(bg_bin, 0, key_size * 2);

	bpriv_key_bin= wd_alloc_blk(pool);
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
	ret = wcrypto_set_dh_g(c, &g);
	if (ret) {
		HPRE_TST_PRT("bob wcrypto_set_dh_g fail!\n");
		goto dh_err;
	}
	opdata_b.pbytes = BN_bn2bin(bp, bp_bin);
	opdata_b.xbytes = BN_bn2bin(bpriv_key, bpriv_key_bin);
	opdata_b.x_p = bpriv_key_bin;
	opdata_b.pri = wd_alloc_blk(pool);
	if (!opdata_b.pri) {
		HPRE_TST_PRT("pool alloc opdata_b.pri fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(opdata_b.pri, 0, key_size * 2);
	opdata_b.op_type = WCRYPTO_DH_PHASE1;

	/* Bob computes public key */
	ret = wcrypto_do_dh(c, &opdata_b, tag);
	if (ret) {
		HPRE_TST_PRT("b wcrypto_do_dh fail!\n");
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
		ret = hpre_bn_format(bpub_key_bin, key_size, key_size);
		if (ret) {
			HPRE_TST_PRT("hpre_bn_format bpub_key bin fail!\n");
			goto dh_err;
		}

		for (i = key_size - 1; bpub_key_bin[i] == 0 && i >= 0; i--) {
			ret = test_hpre_bin_to_crypto_bin(opdata_b.pri, opdata_b.pri, key_size);
			if (ret) {
				HPRE_TST_PRT("dh out share key format fail!\n");
				goto dh_err;
			}
			ret = 0;
			break;
		}

		if (memcmp(bpub_key_bin, opdata_b.pri, key_size)) {
			HPRE_TST_PRT("Bob HPRE DH key gen pub mismatch!\n");
			ret = -EINVAL;
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
	opdata_a.pri = wd_alloc_blk(pool);
	if (!opdata_a.pri) {
		HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(opdata_a.pri, 0, key_size * 2);
	opdata_a.op_type = WCRYPTO_DH_PHASE2;

	/* Alice computes private key with HPRE */
	ret = wcrypto_do_dh(c, &opdata_a, tag);
	if (ret) {
		HPRE_TST_PRT("a wcrypto_do_dh fail!\n");
		goto dh_err;
	}
	if (openssl_check) {
		ret = hpre_bn_format(abuf, key_size, key_size);
		if (ret) {
			HPRE_TST_PRT("hpre_bn_format bpub_key bin fail!\n");
			goto dh_err;
		}

		for (i = key_size - 1; abuf[i] == 0 && i >= 0; i--) {
			ret = test_hpre_bin_to_crypto_bin(opdata_a.pri, opdata_a.pri, key_size);
			if (ret) {
				HPRE_TST_PRT("dh out share key format fail!\n");
				goto dh_err;
			}
			ret = 0;
			break;
		}

		if (memcmp(abuf, opdata_a.pri, key_size)) {
			HPRE_TST_PRT("Alice HPRE DH gen privkey mismatch!\n");
			ret = -EINVAL;
			goto dh_err;
		}
	}
	HPRE_TST_PRT("HPRE DH generate key sucessfully!\n");
	dh_err:
	DH_free(a);
	DH_free(b);
	if (ag_bin)
		wd_free_blk(pool, ag_bin);
	if (apriv_key_bin)
		wd_free_blk(pool, apriv_key_bin);
	if (opdata_a.pri)
		wd_free_blk(pool, opdata_a.pri);

	if (bg_bin)
		wd_free_blk(pool, bg_bin);
	if (bpriv_key_bin)
		wd_free_blk(pool, bpriv_key_bin);
	if (opdata_b.pri)
		wd_free_blk(pool, opdata_b.pri);

	if (apub_key_bin)
		free(apub_key_bin);
	if (bpub_key_bin)
		free(bpub_key_bin);
	if (abuf)
		free(abuf);
	return ret;
}

static bool is_allow_print(int cnt, enum alg_op_type opType, int thread_num)
{
	int intval_index = 0;
	unsigned int log_intval_adjust = 0;
	int log_intval[LOG_INTVL_NUM] = {0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff, 0x3fff,
										0x7fff, 0xffff};
	
	if (!with_log)
		return false;

	if (only_soft)
		return true;
	switch (opType) {
		case DH_GEN:
		case RSA_ASYNC_GEN:
		case RSA_KEY_GEN:
		case RSA_PUB_EN:
		{
			intval_index = 0x02;
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

#ifdef RSA_OP_DEBUG
int hpre_test_rsa_op(enum alg_op_type op_type, void *c, __u8 *in,
		    int in_size,  __u8 *out,  __u8 *key)
{
	struct wcrypto_rsa_op_data opdata;
	int ret, shift;
	void *tag;
	int key_bits, key_size;

	key_bits =  wcrypto_dh_key_bits(c);
	key_size = key_bits >> 3;
	if (op_type == RSA_KEY_GEN) {
		/* use openSSL generate key and store them to files at first */
		ret = test_rsa_key_gen(c, (char *)in,
				      (char *)out, (char *)key, 1);
		if (ret < 0)
			return ret;
	} else {
		struct wcrypto_rsa_pubkey pubkey;
		struct wcrypto_rsa_prikey prvkey;

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
		if (op_type == RSA_PRV_DE && wcrypto_rsa_is_crt(c)) {
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
		} else if (op_type == RSA_PRV_DE && !wcrypto_rsa_is_crt(c)) {
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
			shift =  key_size - in_size;
			memmove(in + shift, in, in_size);
			memset(in, 0, shift);
		}
	}

	/* always key size bytes input */
	opdata.in_bytes = key_size;
	if (op_type == RSA_PRV_DE) {
		opdata.op_type = WCRYPTO_RSA_SIGN;
	} else if (op_type == RSA_PUB_EN) {
		opdata.op_type = WCRYPTO_RSA_VERIFY;
	} else if (op_type == RSA_KEY_GEN) {
		opdata.op_type = WCRYPTO_RSA_GENKEY;
	} else {
		ret = -EINVAL;
		goto type_err;
	}
	if (op_type == RSA_KEY_GEN) {
		ret = hpre_test_fill_keygen_opdata(c, &opdata);
		if (ret)
			goto type_err;
	} else {
		opdata.in = in;
		opdata.out = out;
	}
	tag = NULL;
	ret = wcrypto_do_rsa(c, &opdata, tag);
	if (ret)
		goto type_err;
	if (openssl_check) {
		ret = hpre_test_result_check(c, &opdata, key);
		if (ret)
			goto type_err;
		else if (opdata->op_type == WCRYPTO_RSA_GENKEY)
			HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
	} else if (!openssl_check && op_type == RSA_KEY_GEN) {
		HPRE_TST_PRT("HPRE hardware key generate finished!\n");
	}
	if (op_type == RSA_PRV_DE) {
		__u8 *tmp = opdata.out;

		shift = 0;
		while (!tmp[shift])
			shift++;
		opdata.out_bytes -= shift;
		memmove(out, out + shift, opdata.out_bytes);
	}
	return (int)opdata.out_bytes;
type_err:
	return ret;
}
#endif

int hpre_sys_qmng_test(int thread_num)
{
	int pid = getpid(), i = 0, ret;
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_queue q;

	memset((void *)&q, 0, sizeof(q));
	q.capa.alg = "rsa";

	while (1) {
		ret = wd_request_queue(&q);
		if (ret) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:request queue t-%d fail!\n",
					 pid, thread_id, i);
			return ret;
		}
		i++;
		if (is_allow_print(i, HPRE_ALG_INVLD_TYPE, thread_num))
			HPRE_TST_PRT("Proc-%d, %d-TD request %dQs at %dnode\n",
				     pid, thread_id, i, wd_get_node_id(&q));
		usleep(1);
		wd_release_queue(&q);
	}
	return 0;
}

int hpre_sys_func_test(int thread_num, int cpuid, void *pool, void *queue,
			enum alg_op_type op_type)
{
	int pid = getpid(), ret = 0, i = 0;
	int thread_id = (int)syscall(__NR_gettid);
	struct wcrypto_rsa_ctx_setup setup;
	struct wcrypto_rsa_op_data opdata;
	void *ctx = NULL;
	void *tag = NULL;
	struct wd_queue *q = queue;
	void *key_info = NULL;
	struct timeval start_tval, end_tval;
	float time, speed;
	int key_size = key_bits >> 3;

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	setup.is_crt = 1;
	setup.key_bits = key_bits;

	setup.ops.alloc = (void *)wd_alloc_blk;
	setup.ops.free = (void *)wd_free_blk;
	setup.ops.dma_map = (void *)wd_blk_dma_map;
	setup.ops.dma_unmap = (void *)wd_blk_dma_unmap;
	setup.ops.usr = pool;
	ctx = wcrypto_create_rsa_ctx(q, &setup);
	if (!ctx) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			     pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		goto fail_release;
	}
	/* Just make sure memory size is enough */
	key_info = malloc(key_size * 16);
	if (!key_info) {
		HPRE_TST_PRT("thrd-%d:malloc key!\n", thread_id);
		goto fail_release;
	}
	memset(key_info, 0, key_size * 16);
	ret = test_rsa_key_gen(ctx, NULL, NULL, key_info, 0);
	if (ret) {
		HPRE_TST_PRT("thrd-%d:Openssl key gen fail!\n", thread_id);
		goto fail_release;
	}

	/* always key size bytes input */
	opdata.in_bytes = key_size;
	if (op_type == RSA_KEY_GEN) {
		opdata.op_type = WCRYPTO_RSA_GENKEY;
	} else if (op_type == RSA_PUB_EN) {
		opdata.op_type = WCRYPTO_RSA_VERIFY;
	} else if (op_type == RSA_PRV_DE) {
		opdata.op_type = WCRYPTO_RSA_SIGN;
	} else {
		HPRE_TST_PRT("thrd-%d:optype=%d err!\n",
			  thread_id, op_type);
		goto fail_release;
	}
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		ret = hpre_test_fill_keygen_opdata(ctx, &opdata);
		if (ret){
			HPRE_TST_PRT("fill key gen opdata fail!\n");
			goto fail_release;
		}
	} else {
		opdata.in = wd_alloc_blk(pool);
		if (!opdata.in) {
			HPRE_TST_PRT("alloc in buffer fail!\n");
			goto fail_release;
		}
		opdata.out = wd_alloc_blk(pool);
		if (!opdata.out) {
			HPRE_TST_PRT("alloc out buffer fail!\n");
			goto fail_release;
		}
	}
	gettimeofday(&start_tval, NULL);
	while (1) {
		if (!only_soft) {
			ret = wcrypto_do_rsa(ctx, &opdata, tag);
			if (ret || opdata.status) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth status=%d fail!\n",
					 pid, thread_id,
					 rsa_op_str[opdata.op_type], i, opdata.status);
				goto fail_release;
			}
		}
		i++;
		if (openssl_check || only_soft) {
			void *check_key;

			if (opdata.op_type == WCRYPTO_RSA_SIGN)
				check_key = key_info;
			if (opdata.op_type == WCRYPTO_RSA_VERIFY)
				check_key = key_info + 5 * (key_bits >> 4);
			else
				check_key = key_info;
			ret = hpre_test_result_check(ctx, &opdata, check_key);
			if (ret) {
				HPRE_TST_PRT("P-%d,T-%d:hpre %s %dth mismth\n",
						 pid, thread_id,
						 rsa_op_str[opdata.op_type], i);
				goto fail_release;
			}	
			else {
				if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
					if (is_allow_print(i, WCRYPTO_RSA_GENKEY, thread_num)) 
						HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
				}
			}
		}

		/* clean output buffer remainings in the last time operation */
		if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
			char *data;
			int len;

			len = wcrypto_rsa_kg_out_data((void *)opdata.out, &data);
			if (len < 0) {
				HPRE_TST_PRT("wd rsa get key gen out data fail!\n");
				goto fail_release;
			}
			memset(data, 0, len);
		} else {
#ifdef DEBUG
			print_data(opdata.out, 16, "out");
#endif
		}
		if (is_allow_print(i, op_type, thread_num)) {
			gettimeofday(&end_tval, NULL);
			time = (float)((end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
						   (end_tval.tv_usec - start_tval.tv_usec));
			speed = 1 / (time / i) * 1000;
			HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes,%0.0fus, %0.3fkops\n",
					 pid, thread_id, rsa_op_str[opdata.op_type],
					 i, time, speed);
		}
	}

fail_release:
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		if (opdata.in)
			wcrypto_del_kg_in(ctx, opdata.in);
		if (opdata.out)
			wcrypto_del_kg_out(ctx, opdata.out);
	} else {
		if (opdata.in)
			wd_free_blk(pool, opdata.in);
		if (opdata.out)
			wd_free_blk(pool, opdata.out);
	}
	if (ctx)
		wcrypto_del_rsa_ctx(ctx);
	if (key_info)
		free(key_info);

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
	void *pool, *q;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	op_type = pdata->op_type;
	q = pdata->q;
	pool = pdata->pool;
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
		ret = hpre_sys_func_test(thread_num, cpuid, pool, q, op_type);
		if (ret)
			return NULL;
	}
	return NULL;
}

static int hpre_sys_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	void **pool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0, j;
	int block_num = 512;
	struct wd_queue *q;
	int h_cpuid, qidx;

	q = malloc(q_num * sizeof(struct wd_queue));
	if (!q) {
		HPRE_TST_PRT("malloc q memory fail!\n");
		return -ENOMEM;
	}
	memset(q, 0, q_num * sizeof(struct wd_queue));

	/* create pool for every queue */
	pool = malloc(q_num * sizeof(pool));
	if (!pool) {
		HPRE_TST_PRT("malloc pool memory fail!\n");
		return -ENOMEM;
	}

	memset(pool, 0, q_num * sizeof(pool));

	if (op_type != HPRE_ALG_INVLD_TYPE) {
		for (j = 0; j < q_num; j++) {
			if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE)
				q[j].capa.alg = "dh";
			else
				q[j].capa.alg = "rsa";
			ret = wd_request_queue(&q[j]);
			if (ret) {
				HPRE_TST_PRT("request queue %d fail!\n", j);
				return ret;
			}
			memset(&setup, 0, sizeof(setup));
			if (!strncmp(q[j].capa.alg, "dh", 2))
				setup.block_size = key_bits >> 2;
			else if (!strncmp(q[j].capa.alg, "rsa", 3))
				setup.block_size = (key_bits >> 4) * 20;
			setup.block_num = block_num;
			setup.align_size = 64;

			pool[j] = wd_blkpool_create(&q[j], &setup);
			if (!pool[j]) {
				HPRE_TST_PRT("%s(): create %dth pool fail!\n", __func__, j);
				return -ENOMEM;
			}
		}
	}
	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 0; i < cnt; i++) {
		qidx = i / ctx_num_per_q;
		test_thrds_data[i].pool = pool[qidx];
		test_thrds_data[i].q = &q[qidx];
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
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

		qidx = (i + cnt) / ctx_num_per_q;
		test_thrds_data[i + cnt].pool = pool[qidx];
		test_thrds_data[i + cnt].q = &q[qidx];
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id =  h_cpuid;
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
	free(q);
	for (j = 0; j < q_num; j++)
		wd_blkpool_destroy(pool[i]);
	free(pool);
	return 0;
}

static void  *_rsa_async_poll_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct wd_queue *q = pdata->q;
	int ret;

	while (1) {
		ret = wcrypto_rsa_poll(q, 1);
		if (ret < 0) {
			break;
		}
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
	struct wcrypto_rsa_msg *msg = message;
	void *out = msg->out;
	enum wcrypto_rsa_op_type  op_type = msg->op_type;
	struct wcrypto_rsa_prikey *prikey;

	wcrypto_get_rsa_prikey(ctx, &prikey);
	keybits = wcrypto_rsa_key_bits(ctx);
	key_size = keybits >> 3;

	if (op_type == WCRYPTO_RSA_GENKEY) {
		struct wcrypto_rsa_kg_out *kout = out;

		if (wcrypto_rsa_is_crt(ctx)) {
			struct wd_dtb qinv, dq, dp;
			struct wd_dtb *s_qinv, *s_dq, *s_dp;

			wcrypto_get_rsa_crt_prikey_params(prikey, &s_dq, &s_dp,
							&s_qinv, NULL, NULL);
			wcrypto_get_rsa_kg_out_crt_params(kout, &qinv, &dq, &dp);
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

			wcrypto_get_rsa_prikey_params(prikey, &s_d, &s_n);
			wcrypto_get_rsa_kg_out_params(kout, &d, &n);

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
		if (is_allow_print(cnt, op_type, 1))
			HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
	} else if (op_type == WCRYPTO_RSA_VERIFY) {
		if (!only_soft && memcmp(ssl_params.ssl_verify_result, out, key_size)) {
			HPRE_TST_PRT("pub encrypto result  mismatch!\n");
			return;
		}
	} else {
		if (wcrypto_rsa_is_crt(ctx))
			if (!only_soft && memcmp(ssl_params.ssl_sign_result, out, key_size)) {
				HPRE_TST_PRT("prv decrypto result  mismatch!\n");
				return;
			}
	}
	if (is_allow_print(cnt, op_type, 1))
		HPRE_TST_PRT("thread %d do RSA %dth time success!\n", thread_id, cnt);
	free(rsa_tag);
}

void *_rsa_async_op_test_thread(void *data)
{
	int ret = 0, i = 0, cpuid;
	struct test_hpre_pthread_dt *pdata = data;
	cpu_set_t mask;
	enum alg_op_type op_type;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	void *pool;
	struct wcrypto_rsa_ctx_setup setup;
	struct wcrypto_rsa_op_data opdata;
	void *ctx = NULL;
	struct wd_queue *q;
	void *key_info = NULL;
	struct wcrypto_rsa_prikey *prikey;
	struct wcrypto_rsa_pubkey *pubkey;
	struct rsa_async_tag *tag;
	struct wd_dtb *wd_e, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	op_type = pdata->op_type;
	q = pdata->q;
	pool = pdata->pool;
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
	memset(&opdata, 0, sizeof(opdata));
	setup.is_crt = 1;
	setup.key_bits = key_bits;
	setup.cb = (void *)_rsa_cb;

	setup.ops.alloc = (void *)wd_alloc_blk;
	setup.ops.free =  (void *)wd_free_blk;
	setup.ops.dma_map = (void *)wd_blk_dma_map;
	setup.ops.dma_unmap = (void *)wd_blk_dma_unmap;
	setup.ops.usr = pool;
	ctx = wcrypto_create_rsa_ctx(q, &setup);
	if (!ctx) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			     pid, thread_id, q->capa.alg);
		goto fail_release;
	}
	wcrypto_get_rsa_pubkey(ctx, &pubkey);
	wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, &wd_n);
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
	wcrypto_get_rsa_prikey(ctx, &prikey);
	wcrypto_get_rsa_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
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

	/* always key size bytes input */
	opdata.in_bytes = (key_bits >> 3);
	if (op_type == RSA_KEY_GEN || op_type == RSA_ASYNC_GEN) {
		opdata.op_type = WCRYPTO_RSA_GENKEY;
	} else if (op_type == RSA_PUB_EN || op_type == RSA_ASYNC_EN) {
		opdata.op_type = WCRYPTO_RSA_VERIFY;
	} else if (op_type == RSA_PRV_DE || op_type == RSA_ASYNC_DE) {
		opdata.op_type = WCRYPTO_RSA_SIGN;
	} else {
		HPRE_TST_PRT("thrd-%d:optype=%d err!\n",
			  thread_id, op_type);
		goto fail_release;
	}

	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		opdata.in = (__u8 *)wcrypto_new_kg_in(ctx, wd_e, wd_p, wd_q);
		if (!opdata.in) {
			HPRE_TST_PRT("thrd-%d:fill key gen opdata fail!\n",
				     thread_id);
			goto fail_release;
		}
		opdata.out = wcrypto_new_kg_out(ctx);
		if (!opdata.out) {
			HPRE_TST_PRT("create rsa kgen out fail!\n");
			goto fail_release;
		}
	} else {
		opdata.in = wd_alloc_blk(pool);
		if (!opdata.in) {
			HPRE_TST_PRT("alloc in buffer fail!\n");
			goto fail_release;
		}
		memset(opdata.in, 0, opdata.in_bytes);
		opdata.out = wd_alloc_blk(pool);
		if (!opdata.out) {
			HPRE_TST_PRT("alloc out buffer fail!\n");
			goto fail_release;
		}
		memset(opdata.out, 0, opdata.in_bytes);
	}

	while (1) {
			/* set the user tag */
			tag = malloc(sizeof(*tag));
			if (!tag)
				goto fail_release;
			tag->ctx = ctx;
			tag->thread_id = thread_id;
			tag->cnt = i;
try_do_again:
			ret = wcrypto_do_rsa(ctx, &opdata, tag);
			if (ret == -WD_EBUSY) {
				usleep(100);
				goto try_do_again;
			} else if (ret) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth fail!\n",
					 pid, thread_id,
					 rsa_op_str[opdata.op_type], i);
				goto fail_release;
			}
			usleep(100);
			i++;
	}

fail_release:
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		if (opdata.in)
			wcrypto_del_kg_in(ctx, opdata.in);
		if (opdata.out)
			wcrypto_del_kg_out(ctx, opdata.out);
	} else {
		if (opdata.in)
			wd_free_blk(pool, opdata.in);
		if (opdata.out)
			wd_free_blk(pool, opdata.out);
	}
	if (ctx)
		wcrypto_del_rsa_ctx(ctx);
	if (key_info)
		free(key_info);
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
	unsigned int block_num = 512;
	void *pool;
	struct wd_blkpool_setup setup;
	struct wd_queue q;
	int ret = 0, cnt = 0, i;
	int h_cpuid;

	memset(&q, 0, sizeof(q));
	q.capa.alg = "rsa";
	ret = wd_request_queue(&q);
	if (ret) {
		HPRE_TST_PRT("%s:request queue fail!\n", __func__);
		return ret;
	}
	memset(&setup, 0, sizeof(setup));
	setup.block_size = (key_bits >> 4) * 20;
	setup.block_num = block_num;
	setup.align_size = 64;

	pool = wd_blkpool_create(&q, &setup);
	if (!pool) {
		HPRE_TST_PRT("%s(): create pool fail!\n", __func__);
		return -ENOMEM;
	}

	/* Create poll thread at first */
	test_thrds_data[0].pool = pool;
	test_thrds_data[0].q = &q;
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = _get_cpu_id(0, lcore_mask);
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
		test_thrds_data[i].pool = pool;
		test_thrds_data[i].q = &q;
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _rsa_async_op_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;
		test_thrds_data[i + cnt].pool = pool;
		test_thrds_data[i + cnt].q = &q;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _rsa_async_op_test_thread, &test_thrds_data[i + cnt]);
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
	wd_release_queue(&q);
	wd_blkpool_destroy(pool);
	return 0;
}

static void _dh_cb(const void *message, void *tag)
{
	void *pool = NULL;
	const struct wcrypto_dh_msg *msg = message;
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)tag;
	struct wcrypto_dh_op_data opdata;
	struct timeval start_tval, end_tval;
	int i, pid, threadId;
	const void *pkey = NULL;
	float time, speed;
	int ret;
	static int failTimes = 0;

	if (NULL == pSwData) {
		HPRE_TST_PRT("pSwData NULL!\n");
		return;
	}
	memset(&opdata, 0, sizeof(opdata));
	if (msg->op_type == WCRYPTO_DH_PHASE2)
		opdata.pv = (void *)msg->g;

	opdata.x_p = (void *)msg->x_p;

	opdata.pri = (void *)msg->out;
	opdata.pri_bytes = msg->out_bytes;
	opdata.status = msg->result;
	i = pSwData->times;
	start_tval = pSwData->start_tval;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;
	pkey = pSwData->pkey;
	pool = pSwData->pool;

	if (opdata.status != WD_SUCCESS) {
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes fail!, status 0x%02x\n",
				 pid, threadId, i, opdata.status);
		goto err;
	}

	if (openssl_check) {
		ret = dh_result_check(pSwData->steps, pSwData->keySize, opdata, pkey);
		if (ret) {
			failTimes++;
			HPRE_TST_PRT("TD-%d:dh steps %d result mismatching!\n",
				threadId, pSwData->steps);
		}
	}

	gettimeofday(&end_tval, NULL);
	if (is_allow_print(i, DH_ASYNC_GEN, 1)) {
		time = (end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
					(end_tval.tv_usec - start_tval.tv_usec);
		speed = 1 / (time / i) * 1000 * 1000;
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes,%f us, %0.3fps, fail %dtimes(all TD)\n",
				 pid, threadId, i, time, speed, failTimes);
	}

err:
	if (msg->op_type == WCRYPTO_DH_PHASE2 && opdata.pv)
		wd_free_blk(pool, opdata.pv);
	if (opdata.x_p)
		wd_free_blk(pool, opdata.x_p);
	if (opdata.pri)
		wd_free_blk(pool, opdata.pri);

	if (pSwData)
		free(pSwData);
}

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
		ret = wcrypto_dh_poll(q, 1);
		if (ret < 0) {
			break;
		}
	}

	HPRE_TST_PRT("%s exit!\n", __func__);
	return NULL;
}

static int init_opdata_param(void *pool,
			     struct wcrypto_dh_op_data *opdata,
			     int key_size, enum dh_check_index step)
{
	unsigned char *ag_bin = NULL;

	memset(opdata, 0, sizeof(*opdata));
	if (step == DH_ALICE_PRIVKEY) {
		ag_bin = wd_alloc_blk(pool);
		if (!ag_bin)
			return -ENOMEM;
		memset(ag_bin, 0, 2 * key_size);
		opdata->pv = ag_bin;
	}
	
	opdata->x_p = wd_alloc_blk(pool);
	if (!opdata->x_p) {
		if (ag_bin)
			wd_free_blk(pool, ag_bin);
		return -ENOMEM;
	}
	memset(opdata->x_p, 0, 2 * key_size);

	opdata->pri = wd_alloc_blk(pool);
	if (!opdata->pri) {
		if (ag_bin)
			wd_free_blk(pool, ag_bin);
		wd_free_blk(pool, opdata->x_p);
		return -ENOMEM;
	}
	memset(opdata->pri, 0, 2 * key_size);

	return 0;
}

static void *_hpre_dh_sys_test_thread(void *data)
{
	int ret, cpuid, i = 0, j = 0;
	struct test_hpre_pthread_dt *pdata = data;
	const BIGNUM *pkey = NULL;
	struct wd_queue *q = NULL;
	void *pool = NULL;
	struct wcrypto_dh_op_data opdata_a;
	struct wcrypto_dh_op_data opdata_b;
	cpu_set_t mask;
	struct wcrypto_dh_ctx_setup dh_setup;
	struct wcrypto_dh_ctx *ctx_alice = NULL, *ctx_bob = NULL, *ctx = NULL;
	struct dh_user_tag_info *pTag = NULL;
	struct wcrypto_dh_op_data *opdata;
	struct timeval start_tval, end_tval;
	enum alg_op_type opType;
	float time, speed;
	int steps = 0, failTimes = 0;
	int thread_num;
	int isHwTestPrehandler = 1, isNeedFreeBuf = 0;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int key_size = 0;
	__u32 isAlice;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	q = (struct wd_queue *)pdata->q;
	pool = pdata->pool;
	opType = pdata->op_type;
	thread_num = pdata->thread_num;


	if (!q || !pool) {
		HPRE_TST_PRT("q or pool null!\n");
		return NULL;
	}

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

	q->capa.alg = "dh";
	
	memset(&dh_setup, 0, sizeof(dh_setup));
	dh_setup.key_bits = key_bits;
	key_size = key_bits >> 3;
	dh_setup.cb = _dh_cb;

	dh_setup.ops.alloc = (void *)wd_alloc_blk;
	dh_setup.ops.free = (void *)wd_free_blk;
	dh_setup.ops.dma_map = (void *)wd_blk_dma_map;
	dh_setup.ops.dma_unmap = (void *)wd_blk_dma_unmap;
	dh_setup.ops.usr = pool;
	ctx_alice = wcrypto_create_dh_ctx(q, &dh_setup);
	ctx_bob = wcrypto_create_dh_ctx(q, &dh_setup);
	if (!ctx_alice || !ctx_bob) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
					 pid, thread_id, q->capa.alg);
		goto fail_release;
	}

	if (init_openssl_dh_param(key_size) < 0) {
		HPRE_TST_PRT("init_openssl_dh_param fail!\n");
		goto fail_release;
	}

usleep(1000*1000);
	while (1) {
		steps = i % 3 + 1;
		if (steps == DH_BOB_PUBKEY) {
			isAlice = false;
			opdata = &opdata_b;
			ctx = ctx_alice;
		} else {
			isAlice = true;
			opdata = &opdata_a;
			ctx = ctx_bob;
			if (i == 3) {
				isHwTestPrehandler = 0;//finish openssl dh generate
				gettimeofday(&start_tval, NULL);
			}
		}

		if (i >= 3)
			j = i - 3;
		else
			j = i;

		if (steps != DH_ALICE_PRIVKEY) {
			if (only_soft || isHwTestPrehandler) {
				ret = dh_sw_generate_pubkey(ctx, isAlice);
				if (ret) {
					HPRE_TST_PRT("dh_sw_generate_pubkey fail!\n");
					goto fail_release;
				}
			}

			if (!only_soft && !isHwTestPrehandler) {
				ret = init_opdata_param(pool, opdata, key_size, DH_ALICE_PUBKEY);
				if (ret < 0) {
					usleep(100);
					continue;
				}

				if (opType == DH_ASYNC_GEN) {
					pTag = malloc(sizeof(struct dh_user_tag_info));
					if (!pTag) {
						HPRE_TST_PRT("malloc pTag fail!\n");
						goto fail_release;
					}
					pTag->keySize = key_size;
					pTag->pid = pid;
					pTag->thread_id = thread_id;
					pTag->steps = steps;
					pTag->start_tval = start_tval;
					pTag->times = j + 1;
					pTag->pool = pool;
					pTag->pkey = get_check_sw_alg_result(steps);
				}

				isNeedFreeBuf = 1;
				ret = dh_hw_generate_pubkey(ctx, opdata, isAlice, pTag);
				if (opType == DH_GEN
					&& (ret || opdata->status != WD_SUCCESS)) {
					HPRE_TST_PRT("Proc-%d, T-%d:hpre dh %dth fail!,status %02x\n",
						pid, thread_id, j, opdata->status);
					if (ret) {
							if (opdata->pv) {
								wd_free_blk(pool, opdata->pv);
								opdata->pv = NULL;
							}

							if (opdata->x_p) {
								wd_free_blk(pool, opdata->x_p);
								opdata->x_p = NULL;
							}

							if (opdata->pri) {
								wd_free_blk(pool, opdata->pri);
								opdata->pri = NULL;
							}
						goto fail_release;
					}
				}
			}
		} else {
			if (only_soft || isHwTestPrehandler) {
				ret = dh_sw_generate_privkey(ctx, isAlice);
				if (ret) {
					HPRE_TST_PRT("dh_sw_generate_privkey fail!\n");
					goto fail_release;
				}
			}
			
			if (!only_soft && !isHwTestPrehandler) {
				ret = init_opdata_param(pool, opdata, key_size, DH_ALICE_PRIVKEY);
				if (ret < 0) {
					usleep(100);
					continue;
				}

				if (opType == DH_ASYNC_GEN) {
					pTag = malloc(sizeof(struct dh_user_tag_info));
					if (!pTag) {
						HPRE_TST_PRT("malloc pTag fail!\n");
						goto fail_release;
					}
					pTag->keySize = key_size;
					pTag->pid = pid;
					pTag->thread_id = thread_id;
					pTag->steps = steps;
					pTag->start_tval = start_tval;
					pTag->times = j + 1;
					pTag->pkey = get_check_sw_alg_result(steps);
					pTag->pool = pool;
				}

				isNeedFreeBuf = 1;
				ret = dh_hw_generate_privkey(ctx, opdata, isAlice, pTag);
				if (opType == DH_GEN && (
				    ret || opdata->status != WD_SUCCESS)) {
					HPRE_TST_PRT("Proc-%d, T-%d:hpre dh %dth fail!,status %02x\n",
						pid, thread_id, j, opdata->status);
					if (ret) {
							if (opdata->pv) {
								wd_free_blk(pool, opdata->pv);
								opdata->pv = NULL;
							}

							if (opdata->x_p) {
								wd_free_blk(pool, opdata->x_p);
								opdata->x_p = NULL;
							}

							if (opdata->pri) {
								wd_free_blk(pool, opdata->pri);
								opdata->pri = NULL;
							}
						goto fail_release;
					}
				}

			}
		}
		i++;
		if (!isHwTestPrehandler && opType == DH_GEN) {
			if (openssl_check) {
				pkey = (const BIGNUM *)get_check_sw_alg_result(steps);
				ret = dh_result_check(steps, key_size, *opdata, pkey);
				if (ret) {
					failTimes++;
					HPRE_TST_PRT("P-%d,T-%d:hpre dh %dth mismth\n",
								 pid, thread_id, j + 1);
				} 
			}

			if (is_allow_print(j+1, opType, thread_num)) {
				gettimeofday(&end_tval, NULL);
				time = (float)((end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
							   (end_tval.tv_usec - start_tval.tv_usec));
				speed = 1 / (time / (j + 1)) * 1000;
				HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes,%0.0fus, %0.3fkops, fail %dtimes\n",
						 pid, thread_id, j + 1, time, speed, failTimes);
			}

			if (isNeedFreeBuf) {
				if (opdata->pv) {
					wd_free_blk(pool, opdata->pv);
					opdata->pv = NULL;
				}

				if (opdata->x_p) {
					wd_free_blk(pool, opdata->x_p);
					opdata->x_p = NULL;
				}

				if (opdata->pri) {
					wd_free_blk(pool, opdata->pri);
					opdata->pri = NULL;
				}
				isNeedFreeBuf = 0;
			}
		}
	}

fail_release:
	if (ctx_alice)
		wcrypto_del_dh_ctx(ctx_alice);
	if (ctx_bob)
		wcrypto_del_dh_ctx(ctx_bob);

	if (g_alicePara.priv_key)
		free((void*)g_alicePara.priv_key);
	if (g_bobPara.priv_key)
		free((void*)g_bobPara.priv_key);
	g_alicePara.priv_key = NULL;
	g_bobPara.priv_key = NULL;
	if (alice)
		DH_free(alice);
	if (bob)
		DH_free(bob);
	return NULL;
}

static int dh_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	void *bufPool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0;
	int block_num = 1024;
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
	test_thrds_data[0].cpu_id = _get_cpu_id(0, lcore_mask);
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
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _hpre_dh_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].pool = bufPool;
		test_thrds_data[i + cnt].q = q;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _hpre_dh_sys_test_thread, &test_thrds_data[i + cnt]);
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
	
	free(q);
	wd_blkpool_destroy(bufPool);

	return 0;
}

void *_hpre_sys_test_thread(void *data)
{
	enum alg_op_type op_type;
	struct test_hpre_pthread_dt *pdata = data;
	
	op_type = pdata->op_type;
	if (op_type == DH_GEN || op_type == DH_ASYNC_GEN) {
		return _hpre_dh_sys_test_thread(data);
	} else {
		return _hpre_rsa_sys_test_thread(data);
	}
}

int main(int argc, char *argv[])
{
	void *pool = NULL;
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
	int block_num = 1024;
	struct wd_queue q;
	struct wcrypto_rsa_ctx_setup setup;
	struct wcrypto_dh_ctx_setup dh_setup;
	void *ctx = NULL;
	int thread_num, bits;
	__u64 core_mask[2];

	if (!argv[1] || !argv[6]) {
		HPRE_TST_PRT("pls use ./test_hisi_hpre -help get details!\n");
		return -EINVAL;
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
	} else {
		goto basic_function_test;
	}
	if (argv[7] && !strcmp(argv[7], "-check"))
		openssl_check = 1;
	if (argv[7] && !strcmp(argv[7], "-soft"))
		only_soft = 1;
	if (argv[8]) {
		key_bits = strtoul(argv[8], NULL, 10);
		if (key_bits != 1024 && key_bits != 2048 &&
			key_bits != 3072 && key_bits != 4096) {
			key_bits = 2048;
		}
	} else {
		key_bits = 2048;
	}

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
		if (!strcmp(argv[6], "-log"))
			with_log = 1;
		else
			with_log = 0;
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

		HPRE_TST_PRT("Proc-%d: starts %d threads bind to %s\n",
					 getpid(), thread_num, argv[5]);
		HPRE_TST_PRT(" lcoremask=0x%llx, hcoremask=0x%llx\n",
					 core_mask[0], core_mask[1]);
		if (alg_op_type < MAX_RSA_SYNC_TYPE || alg_op_type == DH_GEN)
			return hpre_sys_test(thread_num, core_mask[0],
					     core_mask[1], alg_op_type);
		else if (alg_op_type > MAX_RSA_SYNC_TYPE && alg_op_type < MAX_RSA_ASYNC_TYPE)
			return rsa_async_test(thread_num, core_mask[0],
					      core_mask[1], alg_op_type);
		else if (alg_op_type == DH_ASYNC_GEN)
			return dh_async_test(thread_num, core_mask[0],
					      core_mask[1], alg_op_type);
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
	} else if (!strcmp(argv[1], "-rsa-num")) {
		printf("num %d\n", wd_get_available_dev_num("rsa"));
		return 0;
	} else if (!strcmp(argv[1], "-dh-num")) {
		printf("num %d\n", wd_get_available_dev_num("dh"));
		return 0;
	} else if (!strcmp(argv[1], "-zip-num")) {
		printf("num %d\n", wd_get_available_dev_num("zip"));
		return 0;
	} else if (!strcmp(argv[1], "-xx-num")) {
		printf("num %d\n", wd_get_available_dev_num("xx"));
		return 0;
	} else if (!strcmp(argv[1], "--help")) {
		HPRE_TST_PRT("[version]:1.0\n");
		HPRE_TST_PRT("./test_hisi_hpre [op_type] [key_size] ");
		HPRE_TST_PRT("[mode] [in] [out] [key_file] [sw_check]\n");
		HPRE_TST_PRT("     [op_type]:\n");
		HPRE_TST_PRT("         -en  = rsa pubkey encrypto\n");
		HPRE_TST_PRT("         -de  = rsa priv key decrypto\n");
		HPRE_TST_PRT("         -gen1  = DH key generate\n");
		HPRE_TST_PRT("      [sw_check]:\n");
		HPRE_TST_PRT("         -check  = use openssl sw alg check\n");
		HPRE_TST_PRT("         --help  = usage\n");
		HPRE_TST_PRT("Example for rsa key2048bits encrypto");
		HPRE_TST_PRT(" in.txt for out.en:\n");
		HPRE_TST_PRT("./test_hisi_hpre -en 2048 -crt in.txt");
		HPRE_TST_PRT(" out.en pubkey\n");
		HPRE_TST_PRT("Example for system test:\n");
		HPRE_TST_PRT("./test_hisi_hpre -system-gen/system-vrf/system-");
		HPRE_TST_PRT("sgn/system-qt -t <thread_");
		HPRE_TST_PRT("num> -c <core_mask> -log/no-log -check\n");
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
	memset((void *)&q, 0, sizeof(q));
	if (argc >= 9) {
		strncpy(q.dev_path, argv[8], sizeof(q.dev_path));
		HPRE_TST_PRT("denote dev path:%s\n", argv[8]);
	}

	if (alg_op_type < MAX_RSA_ASYNC_TYPE && alg_op_type > HPRE_ALG_INVLD_TYPE) {
		q.capa.alg = "rsa";
	} else if (alg_op_type < MAX_DH_TYPE &&
		alg_op_type > MAX_RSA_ASYNC_TYPE) {
		q.capa.alg = "dh";
	} else {
		HPRE_TST_PRT("op type err!\n");
		return -EINVAL;
	}
	ret = wd_request_queue(&q);
	if (ret) {
		HPRE_TST_PRT("request queue fail!\n");
		return ret;
	}
	HPRE_TST_PRT("Get a WD HPRE queue of %s successfully!\n", q.capa.alg);
	memset(&dh_setup, 0, sizeof(dh_setup));
	memset(&setup, 0, sizeof(setup));
	if (alg_op_type < MAX_RSA_ASYNC_TYPE && mode == RSA_CRT_MD) {
		setup.is_crt = 1;
	} else if (alg_op_type < MAX_RSA_ASYNC_TYPE && mode == RSA_COM_MD) {
		setup.is_crt = 0;
	} else if (alg_op_type > MAX_RSA_ASYNC_TYPE &&
			   alg_op_type < HPRE_MAX_OP_TYPE && mode == DH_COM_MD) {
		dh_setup.is_g2 = 0;
	} else if (alg_op_type > MAX_RSA_ASYNC_TYPE &&
			   alg_op_type < HPRE_MAX_OP_TYPE && mode == DH_G2) {
		dh_setup.is_g2 = 1;
	} else {
		HPRE_TST_PRT("op type or mode err!\n");
		ret = -ENOMEM;
		goto release_q;
	}

	struct wd_blkpool_setup wsetup;
	memset(&wsetup, 0, sizeof(wsetup));
	if (!strncmp(q.capa.alg, "rsa", 3))
		wsetup.block_size = (key_bits >> 4) * 7;
	else if (!strncmp(q.capa.alg, "dh", 2))
		wsetup.block_size = key_bits >> 2;
	wsetup.block_num = block_num;
	wsetup.align_size = 64;

	pool = wd_blkpool_create(&q, &wsetup);
	if (!pool) {
		HPRE_TST_PRT("%s(): create ctx pool fail!\n", __func__);
		return -EINVAL;
	}
	
	if (!strncmp(q.capa.alg, "rsa", 3)) {
		setup.key_bits = key_bits;

		setup.ops.alloc = (void *)wd_alloc_blk;
		setup.ops.free = (void *)wd_free_blk;
		setup.ops.dma_map = (void *)wd_blk_dma_map;
		setup.ops.dma_unmap = (void *)wd_blk_dma_unmap;
		setup.ops.usr = pool;
		ctx = wcrypto_create_rsa_ctx(&q, &setup);
		if (!ctx) {
			ret = -ENOMEM;
			HPRE_TST_PRT("create rsa ctx fail!\n");
			goto release_q;
		}
	} else if (!strncmp(q.capa.alg, "dh", 2)) {
		dh_setup.key_bits = key_bits;

		dh_setup.ops.alloc = (void *)wd_alloc_blk;
		dh_setup.ops.free = (void *)wd_free_blk;
		dh_setup.ops.dma_map = (void *)wd_blk_dma_map;
		dh_setup.ops.dma_unmap = (void *)wd_blk_dma_unmap;
		dh_setup.ops.usr = pool;
		ctx = wcrypto_create_dh_ctx(&q, &dh_setup);
		if (!ctx) {
			ret = -ENOMEM;
			HPRE_TST_PRT("create dh ctx fail!\n");
			goto release_q;
		}
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
		return hpre_dh_test(ctx, pool);
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
	if (hpre_test_rsa)
		RSA_free(hpre_test_rsa);
	wcrypto_del_rsa_ctx(ctx);
	wd_blkpool_destroy(pool);
	wd_release_queue(&q);

	return ret;
}
