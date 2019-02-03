// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <semaphore.h>

#include "../../wd.h"
#include "../drv/hisi_qm_udrv.h"
#include "hpre_usr_if.h"
#include "test_hisi_hpre.h"


#define HPRE_TST_PRT		printf
#define BN_ULONG		unsigned long
#define RSA_NO_PADDING          3
#define HPRE_TST_MAX_Q		1
#define HPRE_PADDING_SZ		16

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

struct bn_gencb_st {
	int xxx;
};

/* stub definitions */
typedef struct rsa_st RSA;
typedef struct bignum_st BIGNUM;
typedef struct bn_gencb_st BN_GENCB;

enum alg_op_type {
	HPRE_ALG_INVLD_TYPE,
	RSA_KEY_GEN,
	RSA_PUB_EN,
	RSA_PRV_DE,
	MAX_RSA_TYPE,
	HPRE_MAX_OP_TYPE,
};

enum alg_op_mode {
	HPRE_ALG_INVLD_MODE,
	RSA_COM_MD,
	RSA_CRT_MD,
	HPRE_MAX_OP_MODE,
};

typedef unsigned long long (*v2p)(void *v);
typedef void * (*p2v)(unsigned long long p);

struct hpre_queue_mempool {
	struct wd_queue *q;
	void *base;
	unsigned int *bitmap;
	unsigned int block_size;
	unsigned int block_num;
	unsigned int mem_size;
	unsigned int block_align_size;
	unsigned int free_num;
	unsigned int fail_times;
	unsigned long long index;
	sem_t	sem;
	int dev;
	v2p virt_to_phy;
	p2v phy_to_virt;
};

struct wd_rsa_udata {
	void *tag;
	struct wd_rsa_op_data *opdata;
};

struct wd_rsa_ctx {
	struct wd_rsa_msg cache_msg;
	struct wd_queue *q;
	struct wd_rsa_msg *recv_msg;
	char  alg[32];
	wd_rsa_cb cb;
	__u32 key_size;
	__u16 is_crt;
	__u16 is_hw_key;
	struct wd_rsa_pubkey pubkey;
	struct wd_rsa_prikey prikey;
	struct hpre_queue_mempool *pool;
};

static int key_bits = 2048;
static int openssl_check;
static RSA *hpre_test_rsa;
/* OpenSSL RSA and BN APIs */
BIGNUM *BN_new(void);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
void BN_free(BIGNUM *a);
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

struct hpre_queue_mempool *hpre_test_mempool_create(struct wd_queue *q,
	unsigned int block_size, unsigned int block_num);
void hpre_test_mempool_destroy(struct hpre_queue_mempool *pool);
void *hpre_test_alloc_buf(struct hpre_queue_mempool *pool);
void hpre_test_free_buf(struct hpre_queue_mempool *pool, void *buf);


void hpre_sqe_dump(struct hisi_hpre_sqe *sqe)
{
	printf("sqe:alg=0x%x\n", sqe->alg);
	printf("sqe:etype=0x%x\n", sqe->etype);
	printf("sqe:done=0x%x\n", sqe->done);
	printf("sqe:task_len1=0x%x\n", sqe->task_len1);
	printf("sqe:task_len2=0x%x\n", sqe->task_len2);
	printf("sqe:mrttest_num=0x%x\n", sqe->mrttest_num);
	printf("sqe:low_key=0x%x\n", sqe->low_key);
	printf("sqe:hi_key=0x%x\n", sqe->hi_key);
	printf("sqe:low_in=0x%x\n", sqe->low_in);
	printf("sqe:hi_in=0x%x\n", sqe->hi_in);
	printf("sqe:low_out=0x%x\n", sqe->low_out);
	printf("sqe:hi_out=0x%x\n", sqe->hi_out);
	printf("sqe:tag=0x%x\n", sqe->tag);
}


/* Since our hardware data format is different form standard format */
static int hpre_bn_format(void *buff, int len)
{
	int i = len - 1, j;
	unsigned char *buf = buff;

	if (!buf || len <= 0) {
		HPRE_TST_PRT("%s params err!\n", __func__);
		return -1;
	}
	while (!buf[i] && i >= 0)
		i--;
	if (i == len - 1)
		return 0;

	for (j = len - 1; j >= 0; j--, i--) {
		if (i >= 0)
			buf[j] = buf[i];
		else
			buf[j] = 0;
	}
	return 0;
}

int  hpre_test_get_file_size(char *in_file)
{
	int fd = -1, ret;
	struct stat file_info;

	if (!in_file) {
		HPRE_TST_PRT("\npara err while try to %s!", __func__);
		return -EINVAL;
	}
	fd = open(in_file, O_RDONLY, S_IRUSR) ;
	if (fd < 0) {
		HPRE_TST_PRT("\nGet %s file fail!", in_file);
		return fd;
	}
	ret = fstat(fd, &file_info);
	if (ret < 0) {
		close(fd);
		HPRE_TST_PRT("\nfstat file %s fail!", in_file);
		return -ret;
	}
	close(fd);
	return (int)file_info.st_size;
}

int  hpre_test_read_from_file(__u8 *out, char *in_file, int size)
{
	int fd = -1, bytes_rd;

	if (!out || !size || !in_file) {
		HPRE_TST_PRT("\npara err while try to write file!");
		return -EINVAL;
	}

	fd = open(in_file, O_RDONLY, S_IRUSR) ;
	if (fd < 0) {
		HPRE_TST_PRT("\nGet %s file fail!", in_file);
		return fd;
	}

	bytes_rd = read(fd, out, size);
	if (bytes_rd < 0) {
		close(fd);
		HPRE_TST_PRT("\nwrite data to %s file fail!", in_file);
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
		HPRE_TST_PRT("\npara err while try to write file!");
		return -EINVAL;
	}

	if (handle < 0) {
		fd = open(out_file, O_WRONLY | O_CREAT,
			S_IRUSR | S_IWUSR);
		if (fd < 0) {
			HPRE_TST_PRT("\ncreate %s file fail!", out_file);
			return fd;
		}
	} else
		fd = handle;

	bytes_write = write(fd, out, size);
	if (bytes_write < 0 || bytes_write < size) {
		if (try_close)
			close(fd);
		HPRE_TST_PRT("\nwrite data to %s file fail!", out_file);
		return -ENOMEM;
	}
	if (try_close)
		close(fd);

	/* to be fixed */
	return fd;
}

static inline unsigned long long va_to_pa(struct wd_queue *q, void *va)
{
	return (unsigned long long)wd_get_pa_from_va(q, va);
}

static inline void *pa_to_va(struct wd_queue *q, unsigned long long pa)
{
	return wd_get_va_from_pa(q, (void *)pa);
}

static int hpre_fill_rsa_sqe(struct wd_rsa_ctx *ctx,
			     struct wd_rsa_msg *rsa_msg,
			     struct hisi_hpre_sqe *hw_msg)
{
	char *alg = ctx->alg;
	struct wd_queue *q = ctx->q;
	unsigned long long phy;
	struct hpre_queue_mempool *pool = ctx->pool;
	void *in_buf, *out_buf, *in = (void *)rsa_msg->in;
	__u16 n = rsa_msg->nbytes;

	if (strncmp(alg, "rsa", 3))  {
		HPRE_TST_PRT("\nalg=%s,rsa algorithm support only now!", alg);
		return -1;
	}

	if (rsa_msg->prikey_type == WD_RSA_PRIKEY2)
		hw_msg->alg = HPRE_ALG_NC_CRT;
	else if (rsa_msg->prikey_type == WD_RSA_PRIKEY1)
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	else
		return -1;
	hw_msg->task_len1 = rsa_msg->nbytes / 8 - 1;
	if (rsa_msg->op_type == WD_RSA_SIGN) {
		/* Since SVA and key SGLs is not supported now, we
		 * should copy
		 */
		if (hw_msg->alg == HPRE_ALG_NC_CRT) {
			struct wd_rsa_prikey2 *prikey2 =
			&((struct wd_rsa_prikey *)rsa_msg->prikey)->pkey2;

			if (!ctx->is_hw_key) {
				(void)hpre_bn_format(prikey2->dq, n / 2);
				(void)hpre_bn_format(prikey2->dp, n / 2);
				(void)hpre_bn_format(prikey2->q, n / 2);
				(void)hpre_bn_format(prikey2->p, n / 2);
				(void)hpre_bn_format(prikey2->qinv, n / 2);
				ctx->is_hw_key = 1;
			}
			phy = va_to_pa(q, prikey2->dq);
			hw_msg->low_key = (__u32)(phy & 0xffffffff);
			hw_msg->hi_key = (__u32)((phy >> 32) & 0xffffffff);
		} else {
			struct wd_rsa_prikey1 *prikey1 =
			&((struct wd_rsa_prikey *)rsa_msg->prikey)->pkey1;

			if (!ctx->is_hw_key) {
				(void)hpre_bn_format(prikey1->d, n);
				(void)hpre_bn_format(prikey1->n, n);
				ctx->is_hw_key = 1;
			}
			phy = va_to_pa(q, prikey1->d);
			hw_msg->low_key = (__u32)(phy & 0xffffffff);
			hw_msg->hi_key = (__u32)((phy >> 32) & 0xffffffff);
			hw_msg->alg = HPRE_ALG_NC_NCRT;
		}
	} else if (rsa_msg->op_type == WD_RSA_VERIFY) {
		struct wd_rsa_pubkey *pubkey = (void *)rsa_msg->pubkey;

		if (!ctx->is_hw_key) {
			(void)hpre_bn_format(pubkey->e, n);
			(void)hpre_bn_format(pubkey->n, n);
			ctx->is_hw_key = 1;
		}
		phy = va_to_pa(q, pubkey->e);
		hw_msg->low_key = (__u32)(phy & 0xffffffff);
		hw_msg->hi_key = (__u32)((phy >> 32) & 0xffffffff);
		hw_msg->alg = HPRE_ALG_NC_NCRT;

	} else if (rsa_msg->op_type == WD_RSA_GENKEY) {
		if (hw_msg->alg == HPRE_ALG_NC_CRT) {
			void *in_key;

			in_key = hpre_test_alloc_buf(pool);
			if (!in_key)
				return -1;
			memcpy(in_key, in, n * 2);
			(void)hpre_bn_format(in_key, n);
			(void)hpre_bn_format(in_key + n, n / 2);
			(void)hpre_bn_format(in_key + n * 3 / 2, n / 2);
			phy = va_to_pa(q, in_key);
			hw_msg->low_key = (__u32)(phy & 0xffffffff);
			hw_msg->hi_key = (__u32)((phy >> 32) & 0xffffffff);
			hw_msg->alg = HPRE_ALG_KG_CRT;
		} else {
			void *key;

			key = hpre_test_alloc_buf(pool);
			if (!key)
				return -1;
			memcpy(key, in, n * 2);
			(void)hpre_bn_format(key, n);
			(void)hpre_bn_format(key + n, n / 2);
			(void)hpre_bn_format(key + n * 3 / 2, n / 2);
			phy = va_to_pa(q, key);
			hw_msg->low_key = (__u32)(phy & 0xffffffff);
			hw_msg->hi_key = (__u32)((phy >> 32) & 0xffffffff);
			hw_msg->alg = HPRE_ALG_KG_STD;
		}
	} else {
		HPRE_TST_PRT("\nrsa ALG support only sign and verify now!");
		return -1;
	}

	if (rsa_msg->op_type != WD_RSA_GENKEY) {
		in_buf = hpre_test_alloc_buf(pool);
		if (!in_buf)
			return -ENOMEM;
		memcpy(in_buf, in, rsa_msg->inbytes);
		phy = va_to_pa(q, in_buf);
		hw_msg->low_in = (__u32)(phy & 0xffffffff);
		hw_msg->hi_in = (__u32)((phy >> 32) & 0xffffffff);
	} else {
		hw_msg->low_in = 0;
		hw_msg->hi_in = 0;
	}
	out_buf = hpre_test_alloc_buf(pool);
	if (!out_buf)
		return -ENOMEM;
	memset(out_buf, 0, pool->block_size);
	phy = va_to_pa(q, out_buf);
	hw_msg->low_out = (__u32)(phy & 0xffffffff);
	hw_msg->hi_out = (__u32)((phy >> 32) & 0xffffffff);

	/* This need more processing logic. to do more */
	hw_msg->tag = (__u32)rsa_msg->udata;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;

	return 0;
}

int hpre_test_wd_send(struct wd_rsa_ctx *ctx, struct wd_rsa_msg *msg)
{
	struct wd_queue *q = ctx->q;
	struct hisi_hpre_sqe *hw_msg;
	int ret;

	hw_msg = malloc(sizeof(struct hisi_hpre_sqe));
	if (!hw_msg)
		return -ENOMEM;
	memset((void *)hw_msg, 0, sizeof(struct hisi_hpre_sqe));
	ctx->recv_msg = msg;
	ctx->recv_msg->out = msg->out;
	ctx->recv_msg->udata = msg->udata;
	ret = hpre_fill_rsa_sqe(ctx, msg, hw_msg);
	if (ret)
		return ret;
	return wd_send(q, hw_msg);
}

int hpre_test_wd_recv(struct wd_rsa_ctx *ctx, struct wd_rsa_msg **resp)
{
	struct wd_queue *q = ctx->q;
	struct hisi_hpre_sqe *hw_msg;
	int ret;
	struct wd_rsa_msg *rsa_msg = ctx->recv_msg;
	unsigned long long phy;
	void *va;

	ret = wd_recv(q, (void **)&hw_msg);
	if (ret == -EAGAIN) {
		return 0;
	} else if (ret < 0) {
		HPRE_TST_PRT("wd_recv fail!\n");
		return ret;
	} else {
		ret = 1;
	}
	if (hw_msg->done != 0x3 || hw_msg->etype) {
		HPRE_TST_PRT("HPRE do %s fail!done=0x%x, etype=0x%x\n", "rsa",
		      hw_msg->done, hw_msg->etype);
		hpre_sqe_dump(hw_msg);
		return -1;
	}
	phy = (((__u64)(hw_msg->hi_out) << 32) | (hw_msg->low_out));
	va = pa_to_va(q, phy);
	if (hw_msg->alg == HPRE_ALG_KG_CRT) {
		rsa_msg->outbytes = ctx->key_size / 2 * 7;
	} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
		rsa_msg->outbytes = ctx->key_size * 2;
	} else {
		rsa_msg->outbytes = ctx->key_size;
	}
	memcpy((void *)rsa_msg->out, va, rsa_msg->outbytes);
	hpre_test_free_buf(ctx->pool, va);
	phy = (((__u64)(hw_msg->hi_in) << 32) | (hw_msg->low_in));
	if (phy) {
		va = pa_to_va(q, phy);
		hpre_test_free_buf(ctx->pool, va);
	}
	if (rsa_msg->op_type == WD_RSA_GENKEY) {
		phy = (((__u64)(hw_msg->hi_key) << 32) | (hw_msg->low_key));
		va = pa_to_va(q, phy);
		hpre_test_free_buf(ctx->pool, va);
	}
	*resp = rsa_msg;
	free(hw_msg);
	return ret;
}

/* Before initiate this context, we should get a queue from WD */
void *wd_create_rsa_ctx(struct wd_queue *q, struct wd_rsa_ctx_setup *setup)
{
	struct wd_rsa_ctx *ctx;
	__u32 prikey_size, pubkey_size;
	struct hpre_queue_mempool *pool;

	if (!q || !setup) {
		HPRE_TST_PRT("%s(): input param err!\n", __func__);
		return NULL;
	}
	if (strncmp(setup->alg, "rsa", 3) || strncmp(q->capa.alg, "rsa", 3)) {
		HPRE_TST_PRT("%s(): algorithm mismatching!\n", __func__);
		return NULL;
	}

	prikey_size = 5 * (setup->key_bits >> 4);
	prikey_size += 2 * (setup->key_bits >> 3);
	pubkey_size = 2 * (setup->key_bits >> 3);
	pool = hpre_test_mempool_create(q, sizeof(*ctx) + pubkey_size +
		prikey_size, 16);
	if (!pool) {
		HPRE_TST_PRT("create ctx pool fail!\n");
		return NULL;
	}
	ctx = hpre_test_alloc_buf(pool);
	if (!ctx) {
		HPRE_TST_PRT("Alloc ctx memory fail!\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(*ctx) + pubkey_size + prikey_size);
	ctx->q = q;
	ctx->pool = pool;
	strncpy(ctx->alg, q->capa.alg, strlen(q->capa.alg));
	if (setup->is_crt)
		ctx->cache_msg.prikey_type = WD_RSA_PRIKEY2;
	else
		ctx->cache_msg.prikey_type = WD_RSA_PRIKEY1;
	ctx->cache_msg.aflags = setup->aflags;
	ctx->cache_msg.pubkey = (__u64)&ctx->pubkey;
	ctx->pubkey.e = (__u8 *)ctx + sizeof(*ctx);
	ctx->pubkey.n = ctx->pubkey.e + (setup->key_bits >> 3);
	ctx->cache_msg.prikey = (__u64)&ctx->prikey;
	ctx->prikey.pkey2.dq = ctx->pubkey.n + (setup->key_bits >> 3);
	ctx->prikey.pkey2.dp = ctx->prikey.pkey2.dq + (setup->key_bits >> 4);
	ctx->prikey.pkey2.q = ctx->prikey.pkey2.dp + (setup->key_bits >> 4);
	ctx->prikey.pkey2.p = ctx->prikey.pkey2.q + (setup->key_bits >> 4);
	ctx->prikey.pkey2.qinv = ctx->prikey.pkey2.p + (setup->key_bits >> 4);
	ctx->prikey.pkey1.d = ctx->prikey.pkey2.qinv + (setup->key_bits >> 4);
	ctx->prikey.pkey1.n = ctx->prikey.pkey1.d + (setup->key_bits >> 3);
	ctx->cache_msg.nbytes = setup->key_bits >> 3;
	ctx->cache_msg.alg = ctx->alg;
	ctx->cb = setup->cb;
	ctx->is_crt = setup->is_crt;
	ctx->key_size = setup->key_bits >> 3;

	return ctx;
}

int wd_rsa_is_crt(void *ctx)
{
	if (ctx)
		return ((struct wd_rsa_ctx *)ctx)->is_crt;
	else
		return 0;
}

int wd_rsa_key_bits(void *ctx)
{
	if (ctx)
		return	(((struct wd_rsa_ctx *)ctx)->key_size) << 3;
	else
		return 0;
}

int wd_set_rsa_pubkey(void *ctx, struct wd_rsa_pubkey *pubkey)
{
	struct wd_rsa_pubkey *pk =
		(void *)((struct wd_rsa_ctx *)ctx)->cache_msg.pubkey;
	int key_size = ((struct wd_rsa_ctx *)ctx)->key_size;

	if (ctx && pubkey && pubkey->e && pubkey->n) {
		memcpy(pk->e,  pubkey->e, key_size);
		memcpy(pk->n,  pubkey->n, key_size);
		return 0;
	}

	return -EINVAL;
}

void wd_get_rsa_pubkey(void *ctx, struct wd_rsa_pubkey **pubkey)
{
	if (ctx && pubkey)
		*pubkey = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.pubkey;
}

int wd_set_rsa_prikey(void *ctx, struct wd_rsa_prikey *prikey)
{
	struct wd_rsa_prikey *pk;
	int key_size = ((struct wd_rsa_ctx *)ctx)->key_size;

	if (!ctx && !prikey)
		return -EINVAL;
	pk = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.prikey;
	if (wd_rsa_is_crt(ctx)) {
		if (!(prikey->pkey2.dp) || !(prikey->pkey2.dq) ||
		    !(prikey->pkey2.p) || !(prikey->pkey2.q) ||
		    !(prikey->pkey2.qinv))
			return -EINVAL;
		memcpy(pk->pkey2.dp,  prikey->pkey2.dp, key_size / 2);
		memcpy(pk->pkey2.dq,  prikey->pkey2.dq, key_size / 2);
		memcpy(pk->pkey2.p,  prikey->pkey2.p, key_size / 2);
		memcpy(pk->pkey2.q,  prikey->pkey2.q, key_size / 2);
		memcpy(pk->pkey2.qinv,  prikey->pkey2.qinv, key_size / 2);
		return 0;
	}
	if (!(prikey->pkey1.n) || !(prikey->pkey1.d))
		return -EINVAL;
	memcpy(pk->pkey1.n,  prikey->pkey1.n, key_size);
	memcpy(pk->pkey1.d,  prikey->pkey1.d, key_size);

	return 0;
}

void wd_get_rsa_prikey(void *ctx, struct wd_rsa_prikey **prikey)
{
	if (ctx && prikey)
		*prikey = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.prikey;
}

int wd_do_rsa(void *ctx, struct wd_rsa_op_data *opdata)
{
	struct wd_rsa_ctx *ctxt = ctx;
	struct wd_rsa_msg *resp;
	int ret, i = 0;

	if (opdata->op_type == WD_RSA_SIGN ||
	    opdata->op_type == WD_RSA_VERIFY ||
	    opdata->op_type == WD_RSA_GENKEY) {
		ctxt->cache_msg.in = (__u64)opdata->in;
		ctxt->cache_msg.inbytes = (__u16)opdata->in_bytes;
		ctxt->cache_msg.out = (__u64)opdata->out;
	} else {
		HPRE_TST_PRT("%s():opdata err!\n", __func__);
		return -EINVAL;
	}
	ctxt->cache_msg.op_type = (__u8)opdata->op_type;
	ctxt->cache_msg.status = -1;

	ret = hpre_test_wd_send(ctxt, &ctxt->cache_msg);
	if (ret) {
		HPRE_TST_PRT("%s():wd_send err!\n", __func__);
		return ret;
	}

recv_again:
	ret = hpre_test_wd_recv(ctxt, &resp);
	if (!ret) {
		i++;
		usleep(1 + i * 100);
		if (i < 400) {
			goto recv_again;
		}
	} else if (ret < 0) {
		return ret;
	}
	if (i >= 400) {
		HPRE_TST_PRT("%s:timeout err!\n", __func__);
		return -1;
	}
	opdata->out = (void *)resp->out;
	opdata->out_bytes = resp->outbytes;

	return 0;
}

int wd_rsa_op(void *ctx, struct wd_rsa_op_data *opdata, void *tag)
{
	struct wd_rsa_ctx *context = ctx;
	struct wd_rsa_msg *msg = &context->cache_msg;
	int ret;
	struct wd_rsa_udata *udata;

	if (!ctx || !opdata) {
		HPRE_TST_PRT("param err!\n");
		return -1;
	}
	msg->status = 0;

	/* malloc now, as need performance we should rewrite mem management */
	udata = malloc(sizeof(*udata));
	if (!udata) {
		HPRE_TST_PRT("malloc udata fail!\n");
		return -1;
	}
	udata->tag = tag;
	udata->opdata = opdata;
	if (opdata->op_type == WD_RSA_SIGN ||
	    opdata->op_type == WD_RSA_VERIFY) {
		msg->in = (__u64)opdata->in;
		msg->inbytes = (__u16)opdata->in_bytes;
		msg->out = (__u64)opdata->out;
	}
	msg->udata = (__u64)udata;
	msg->op_type = (__u8)opdata->op_type;
	ret = hpre_test_wd_send(context, (void *)msg);
	if (ret < 0) {
		HPRE_TST_PRT("wd send request fail!\n");
		return -1;
	}

	return 0;
}

int wd_rsa_poll(void *rsa_ctx, int num)
{
	int ret, count = 0;
	struct wd_rsa_msg *resp;
	struct wd_rsa_ctx *ctx = rsa_ctx;
	unsigned int status;
	struct wd_rsa_udata *udata;

	do {
		ret = hpre_test_wd_recv(ctx, &resp);
		if (ret < 1)
			break;
		count++;
		udata = (void *)resp->udata;
		udata->opdata->out_bytes = (__u32)resp->outbytes;
		status = resp->status;
		ctx->cb(udata->tag, status, udata->opdata);
		free(udata);
	} while (--num);

	return count;
}

void wd_del_rsa_ctx(void *rsa_ctx)
{
	struct wd_rsa_ctx *ctx = rsa_ctx;

	if (ctx)
		hpre_test_mempool_destroy(ctx->pool);
}

static int test_rsa_key_gen(void *ctx, char *pubkey_file,
			    char *privkey_file,
			    char *crt_privkey_file)
{
	int ret, bits;
	RSA *test_rsa;
	BIGNUM *p, *q, *e_value, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	struct wd_rsa_prikey *prikey;
	struct wd_rsa_pubkey *pubkey;

	bits = wd_rsa_key_bits(ctx);
	test_rsa = RSA_new();
	if (!test_rsa || !bits) {
		HPRE_TST_PRT("\n RSA new fail!");
		return -ENOMEM;
	}
	e_value = BN_new();
	if (!e_value) {
		RSA_free(test_rsa);
		HPRE_TST_PRT("\n BN new e fail!");
		ret = -ENOMEM;
		return ret;
	}
	ret = BN_set_word(e_value, 65537);
	if (ret != 1) {
		HPRE_TST_PRT("\n BN_set_word fail!");
		ret = -1;
		goto gen_fail;
	}
	ret = RSA_generate_key_ex(test_rsa, key_bits, e_value, NULL);
	if (ret != 1) {
		HPRE_TST_PRT("\n RSA_generate_key_ex fail!");
		ret = -1;
		goto gen_fail;
	}
	RSA_get0_key((const RSA *)test_rsa, (const BIGNUM **)&n,
		       (const BIGNUM **)&e, (const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)test_rsa, (const BIGNUM **)&p,
			 (const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)test_rsa, (const BIGNUM **)&dmp1,
			    (const BIGNUM **)&dmq1, (const BIGNUM **)&iqmp);

	wd_get_rsa_pubkey(ctx, &pubkey);
	wd_get_rsa_prikey(ctx, &prikey);

	BN_bn2bin(e, pubkey->e);
	BN_bn2bin(n, pubkey->n);
	if (pubkey_file) {
		ret = hpre_test_write_to_file(pubkey->e, key_bits >> 2,
					pubkey_file, -1, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("\nRSA public key was written to %s!",
				privkey_file);
	}

	/* CRT mode private key */
	BN_bn2bin(dmp1, prikey->pkey2.dp);
	BN_bn2bin(dmq1, prikey->pkey2.dq);
	BN_bn2bin(p, prikey->pkey2.p);
	BN_bn2bin(q, prikey->pkey2.q);
	BN_bn2bin(iqmp, prikey->pkey2.qinv);
	if (crt_privkey_file) {
		ret = hpre_test_write_to_file(prikey->pkey2.dq,
			(key_bits >> 4) * 5, crt_privkey_file, -1, 0);
		if (ret < 0)
			goto gen_fail;
		ret = hpre_test_write_to_file(pubkey->e,
			(key_bits >> 2), crt_privkey_file, ret, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("\nRSA CRT private key was written to %s!",
				crt_privkey_file);
	}

	/* common mode private key */
	BN_bn2bin(d, prikey->pkey1.d);
	BN_bn2bin(n, prikey->pkey1.n);
	if (privkey_file) {
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
		HPRE_TST_PRT("\nRSA common private key was written to %s!",
				privkey_file);
	}
	RSA_free(test_rsa);
	BN_free(e_value);
	return ret;
gen_fail:
	RSA_free(test_rsa);
	BN_free(e_value);

	return ret;
}

struct hpre_queue_mempool *hpre_test_mempool_create(struct wd_queue *q,
				unsigned int block_size, unsigned int block_num)
{
	void *addr;
	unsigned long rsv_mm_sz;
	struct hpre_queue_mempool *pool;
	unsigned int bitmap_sz;

	if (block_size > 4096) {
		HPRE_TST_PRT("\ncurrent blk size is bellow 4k :)");
		return NULL;
	}
	rsv_mm_sz = block_size * block_num;
	if (rsv_mm_sz > 0x400000) {
		HPRE_TST_PRT("\ncurrent mem size should be bellow 4M");
		return NULL;
	}
	addr = wd_reserve_memory(q, rsv_mm_sz);
	if (!addr) {
		HPRE_TST_PRT("\nrequest queue fail!");
		return NULL;
	}
	bitmap_sz = (block_num / 32 + 1) * sizeof(unsigned int);
	pool = malloc(sizeof(*pool) + bitmap_sz);
	if (!pool) {
		HPRE_TST_PRT("\nAlloc pool handle fail!");
		return NULL;
	}
	memset(pool, 0, sizeof(*pool) + bitmap_sz);
	pool->base = addr;
	memset(addr, 0, rsv_mm_sz);
	sem_init(&pool->sem, 0, 1);
	pool->block_size = block_size;
	pool->block_num = block_num;
	pool->free_num = block_num;
	pool->bitmap = (unsigned int *)(pool + 1);
	pool->mem_size = rsv_mm_sz;

	return pool;
}

void hpre_test_mempool_destroy(struct hpre_queue_mempool *pool)
{
	free(pool);
}

void *hpre_test_alloc_buf(struct hpre_queue_mempool *pool)
{
	__u64 i = 0;
	__u64 j = 0;
	__u64 tmp = 0;
	__u32 *pbm = NULL;

	(void)sem_wait(&pool->sem);
	pbm = pool->bitmap;
	tmp = pool->index;
	for (; pool->index < pool->block_num; pool->index++) {
		i = (pool->index >> 5);
		j = (pool->index & (32 - 1));
		if ((pbm[i] & ((__u32)0x1 << j)) == 0) {
			pbm[i] |= ((__u32)0x1 << j);
			tmp = pool->index;
			pool->index++;
			(void)sem_post(&pool->sem);
			return (void *)((char *)pool->base + (tmp *
					pool->block_size));
		}
	}
	for (pool->index = 0; pool->index < tmp; pool->index++) {
		i = (pool->index >> 5);
		j = (pool->index & (32 - 1));
		if ((pbm[i] & ((__u32)0x1 << j)) == 0) {
			pbm[i] |= ((__u32)0x1 << j);
			tmp = pool->index;
			pool->index++;
			(void)sem_post(&pool->sem);
			return (void *)((char *)pool->base +
					(tmp * pool->block_size));

		}
	}
	(void)sem_post(&pool->sem);

	return NULL;
}

int hpre_test_fill_keygen_opdata(struct wd_rsa_ctx *ctx,
			struct wd_rsa_op_data *opdata)
{
	int key_size = ctx->key_size;
	void *in, *out;
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;

	wd_get_rsa_pubkey(ctx, &pubkey);
	wd_get_rsa_prikey(ctx, &prikey);
	in  = malloc(key_size  * 2);
	if (!in) {
		HPRE_TST_PRT("%s:malloc in fail!", __func__);
		return -ENOMEM;
	}
	memset(in, 0, key_size * 2);
	memcpy(in, pubkey->e, key_size);
	memcpy(in + key_size, prikey->pkey2.p, key_size / 2);
	memcpy(in + key_size * 3 / 2, prikey->pkey2.q, key_size / 2);
	out = malloc(key_size * 4);
	if (!out) {
		free(in);
		HPRE_TST_PRT("%s:malloc crt out fail!", __func__);
		return -ENOMEM;
	}
	memset(out, 0, key_size * 4);
	opdata->in = in;
	opdata->out = out;
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

int hpre_test_result_check(struct wd_rsa_ctx *ctx,
			struct wd_rsa_op_data *opdata, void *key)
{
	void *d, *n;
	__u32 offset;
	void *out = opdata->out;
	int ret;
	void *ssl_out;
	BIGNUM *nn;
	BIGNUM *e;

	if (!hpre_test_rsa) {
		hpre_test_rsa = RSA_new();
		if (!hpre_test_rsa) {
			HPRE_TST_PRT("\n%s:RSA new fail!", __func__);
			return -ENOMEM;
		}
	}
	if (opdata->op_type == WD_RSA_GENKEY) {
		d = ctx->prikey.pkey1.d;
		n = ctx->prikey.pkey1.n;

		/* check D */
		if (memcmp(d, out, ctx->key_size)) {
			HPRE_TST_PRT("\nkey generate D result mismatching!");
			return -EINVAL;
		}
		offset = ctx->key_size;
		if (memcmp(n, out + offset, ctx->key_size)) {
			HPRE_TST_PRT("\nkey generate N result mismatching!");
			return -EINVAL;
		}

		if (ctx->is_crt) {
			void *dq, *dp, *qinv;

			offset += ctx->key_size;
			qinv = ctx->prikey.pkey2.qinv;
			if (memcmp(qinv, out + offset, ctx->key_size / 2)) {
				HPRE_TST_PRT("\nkeygen  N  mismatch!");
				return -EINVAL;
			}
			offset += (ctx->key_size / 2);
			dq = ctx->prikey.pkey2.dq;
			if (memcmp(dq, out + offset, ctx->key_size / 2)) {
				HPRE_TST_PRT("\nkeygen  dq mismatch!");
				return -EINVAL;
			}
			offset += (ctx->key_size / 2);
			dp = ctx->prikey.pkey2.dp;
			if (memcmp(dp, out + offset, ctx->key_size / 2)) {
				HPRE_TST_PRT("\nkeygen  dp  mismatch!");
				return -EINVAL;
			}
		}
		HPRE_TST_PRT("\nHPRE hardware key generate successfully!\n");
	} else if (opdata->op_type == WD_RSA_VERIFY) {
		ssl_out = malloc(ctx->key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("\nmalloc ssl out fail!");
			return -ENOMEM;
		}
		if (key) {
			nn = hpre_bin_to_bn(key + ctx->key_size,
					(int)ctx->key_size);
			if (!nn) {
				HPRE_TST_PRT("\nn bin2bn err!");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key, (int)ctx->key_size);
			if (!e) {
				HPRE_TST_PRT("\ne bin2bn err!");
				return -EINVAL;
			}
			ret = RSA_set0_key(hpre_test_rsa, nn, e, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("\ne set0_key err!");
				return -EINVAL;
			}
		}
		ret = RSA_public_encrypt(opdata->in_bytes, opdata->in, ssl_out,
			hpre_test_rsa, RSA_NO_PADDING);
		if (ret != (int)opdata->in_bytes) {
			HPRE_TST_PRT("\nopenssl pub encrypto fail!");
			return -ENOMEM;
		}
		if (memcmp(ssl_out, opdata->out, ctx->key_size)) {
			HPRE_TST_PRT("\npub encrypto result  mismatch!");
			return -EINVAL;
		}
		free(ssl_out);
	} else {
		ssl_out = malloc(ctx->key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("\nmalloc ssl out fail!");
			return -ENOMEM;
		}
		if (key && ctx->is_crt) {
			BIGNUM *dp, *dq, *iqmp, *p, *q;
			int size = (int)ctx->key_size / 2;

			dq = hpre_bin_to_bn(key, size);
			if (!dq) {
				HPRE_TST_PRT("\ndq bin2bn err!");
				return -EINVAL;
			}
			dp = hpre_bin_to_bn(key + size, size);
			if (!dp) {
				HPRE_TST_PRT("\ndp bin2bn err!");
				return -EINVAL;
			}
			q = hpre_bin_to_bn(key + 2 * size, size);
			if (!q) {
				HPRE_TST_PRT("\nq bin2bn err!");
				return -EINVAL;
			}
			p = hpre_bin_to_bn(key + 3 * size, size);
			if (!p) {
				HPRE_TST_PRT("\np bin2bn err!");
				return -EINVAL;
			}
			iqmp = hpre_bin_to_bn(key + 4 * size, size);
			if (!iqmp) {
				HPRE_TST_PRT("\niqmp bin2bn err!");
				return -EINVAL;
			}
			ret = RSA_set0_crt_params(hpre_test_rsa, dp, dq, iqmp);
			if (ret <= 0) {
				HPRE_TST_PRT("\nd set0_crt_params err!");
				return -EINVAL;
			}
			ret = RSA_set0_factors(hpre_test_rsa, p, q);
			if (ret <= 0) {
				HPRE_TST_PRT("\nd set0_factors err!");
				return -EINVAL;
			}
			nn = hpre_bin_to_bn(key + 7 * size,
				(int)ctx->key_size);
			if (!nn) {
				HPRE_TST_PRT("\nn bin2bn err!");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key + 5 * size, (int)ctx->key_size);
			if (!e) {
				HPRE_TST_PRT("\ne bin2bn err!");
				return -EINVAL;
			}
			ret = RSA_set0_key(hpre_test_rsa, nn, e, NULL);
			if (ret <= 0) {
				HPRE_TST_PRT("\ne set0_key crt err!");
				return -EINVAL;
			}
		} else if (key && !ctx->is_crt) {
			BIGNUM *d;

			nn = hpre_bin_to_bn(key + ctx->key_size,
				(int)ctx->key_size);
			if (!nn) {
				HPRE_TST_PRT("\nn bin2bn err!");
				return -EINVAL;
			}
			d = hpre_bin_to_bn(key, (int)ctx->key_size);
			if (!d) {
				HPRE_TST_PRT("\nd bin2bn err!");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key + 2 * ctx->key_size,
				(int)ctx->key_size);
			if (!e) {
				HPRE_TST_PRT("\ne bin2bn err!");
				return -EINVAL;
			}
			ret = RSA_set0_key(hpre_test_rsa, nn, e, d);
			if (ret <= 0) {
				HPRE_TST_PRT("\nd set0_key err!");
				return -EINVAL;
			}
		}
		ret = RSA_private_decrypt(opdata->in_bytes, opdata->in, ssl_out,
			hpre_test_rsa, RSA_NO_PADDING);
		if (ret != (int)opdata->in_bytes) {
				HPRE_TST_PRT("\nopenssl pub encrypto fail!");
			return -ENOMEM;
		}
		if (memcmp(ssl_out, opdata->out, ctx->key_size)) {
			HPRE_TST_PRT("\nprv decrypto result  mismatch!");
			return -EINVAL;
		}
		free(ssl_out);
	}

	return 0;
}

void hpre_test_free_buf(struct hpre_queue_mempool *pool, void *pbuf)
{
	__u32 *pbm = pool->bitmap;
	__u64  offset  = 0;
	__u32  bit_mask = 0;

	offset = (__u64)((unsigned long)pbuf - (unsigned long)pool->base);
	offset = offset / pool->block_size;
	if (pool->block_num <= offset) {
		HPRE_TST_PRT("offset = %lld, virtual address err!\n", offset);
		return;
	}
	bit_mask = ~(0x1u << (offset & 31));
	(void)sem_wait(&pool->sem);
	pbm[(offset >> 5)] &= bit_mask;
	(void)sem_post(&pool->sem);
}

/* return the output bytes of data */
int hpre_test_op(enum alg_op_type op_type, void *c, __u8 *in, int in_size,
		 __u8 *out, int key_bits, __u8 *key)
{
	struct wd_rsa_op_data opdata;
	struct wd_rsa_ctx *ctx = c;
	int ret, shift;

	if (op_type == RSA_KEY_GEN) {
		/* use openSSL generate key and store them to files at first */
		ret = test_rsa_key_gen(ctx, (char *)in, (char *)out, (char *)key);
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
			ret = wd_set_rsa_pubkey(ctx, &pubkey);
			if (ret) {
				HPRE_TST_PRT("\nwd_set_rsa_pubkey fail!");
				return ret;
			}
		}
		if (op_type == RSA_PRV_DE && ctx->is_crt) {
			prvkey.pkey2.dq = key;
			prvkey.pkey2.dp = key + (key_bits >> 4);
			prvkey.pkey2.q = key + (key_bits >> 3);
			prvkey.pkey2.p = key + (key_bits >> 4) * 3;
			prvkey.pkey2.qinv = key + (key_bits >> 2);
			ret = wd_set_rsa_prikey(ctx, &prvkey);
			if (ret) {
				HPRE_TST_PRT("\nwd_set_rsa_prikey crt fail!");
				return ret;
			}
		} else if (op_type == RSA_PRV_DE && !ctx->is_crt) {
			prvkey.pkey1.d = key;
			prvkey.pkey1.n = key + (key_bits >> 3);
			ret = wd_set_rsa_prikey(ctx, &prvkey);
			if (ret) {
				HPRE_TST_PRT("\nwd_set_rsa_prikey fail!");
				return ret;
			}
		}
try_format_input:
		/* Padding zero in this sample */
		if (in_size < ctx->key_size && op_type == RSA_PUB_EN) {
			shift =  ctx->key_size - in_size;
			memmove(in + shift, in, in_size);
			memset(in, 0, shift);
		}
	}

	/* always key size bytes input */
	opdata.in_bytes = ctx->key_size;
	if (op_type == RSA_PRV_DE) {
		opdata.op_type = WD_RSA_SIGN;
	} else if (op_type == RSA_PUB_EN) {
		opdata.op_type = WD_RSA_VERIFY;
	} else if (op_type == RSA_KEY_GEN) {
		opdata.op_type = WD_RSA_GENKEY;
	} else {
		ret = -EINVAL;
		goto type_err;
	}
	if (op_type == RSA_KEY_GEN) {
		ret = hpre_test_fill_keygen_opdata(ctx, &opdata);
		if (ret)
			goto type_err;
	} else {
		opdata.in = in;
		opdata.out = out;
	}
	ret = wd_do_rsa(ctx, &opdata);
	if (ret)
		goto type_err;
	if (openssl_check) {
		ret = hpre_test_result_check(ctx, &opdata, key);
		if (ret)
			goto type_err;
	} else if (!openssl_check && op_type == RSA_KEY_GEN) {
		HPRE_TST_PRT("\nHPRE hardware key generate finished!\n");
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

int main(int argc, char *argv[])
{
	enum alg_op_type alg_op_type;
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
	struct hisi_qm_priv *priv;
	struct wd_queue q;
	struct wd_rsa_ctx_setup setup;
	void *ctx = NULL;

	if (!argv[1] || !argv[6]) {
		HPRE_TST_PRT("pls use ./test_hisi_hpre -h get more details!\n");
		return -EINVAL;
	}
	if (argv[7] && !strcmp(argv[7], "-check"))
		openssl_check = 1;
	if (!strcmp(argv[1], "-en")) {
		alg_op_type = RSA_PUB_EN;
		HPRE_TST_PRT("RSA public key encrypto\n");
	} else if (!strcmp(argv[1], "-de")) {
		alg_op_type = RSA_PRV_DE;
		HPRE_TST_PRT("RSA private key decrypto\n");
	} else if (!strcmp(argv[1], "-gen")) {
		HPRE_TST_PRT("RSA key generation\n");
		alg_op_type = RSA_KEY_GEN;
	} else if (!strcmp(argv[1], "--help")) {
		HPRE_TST_PRT("[version]:1.0\n");
		HPRE_TST_PRT("./test_hisi_hpre [op_type] [key_size] ");
		HPRE_TST_PRT("[mode] [in] [out] [key_file] [sw_check]\n");
		HPRE_TST_PRT("     [op_type]:\n");
		HPRE_TST_PRT("         -en  = rsa pubkey encrypto\n");
		HPRE_TST_PRT("         -de  = rsa priv key decrypto\n");
		HPRE_TST_PRT("         -gen  = rsa key gen\n");
		HPRE_TST_PRT("         -check  = use openssl sw alg check\n");
		HPRE_TST_PRT("         --help  = usage\n");
		HPRE_TST_PRT("Example for rsa key2048bits encrypto");
		HPRE_TST_PRT(" in.txt for out.en:\n");
		HPRE_TST_PRT("./test_hisi_hpre -en 2048 -crt in.txt");
		HPRE_TST_PRT(" out.en pubkey\n");
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
	HPRE_TST_PRT("RSA key size=%d bits\n", key_bits);
	if (!strcmp(argv[3], "-crt")) {
		HPRE_TST_PRT("RSA CRT mode\n");
		mode = RSA_CRT_MD;
	} else if (!strcmp(argv[3], "-com")) {
		HPRE_TST_PRT("RSA Common mode\n");
		mode = RSA_COM_MD;
	} else {
		HPRE_TST_PRT("please input a mode:<-crt> <-com> for rsa!\n");
		return -EINVAL;
	}
	in_file = argv[4];
	out_file = argv[5];
	key_file = argv[6];
	memset((void *)&q, 0, sizeof(q));
	priv = (void *)q.capa.priv;
	if (alg_op_type < MAX_RSA_TYPE && alg_op_type > 0) {
		q.capa.alg = "rsa";
	} else {
		HPRE_TST_PRT("\nop type err!");
		return -EINVAL;
	}
	priv->sqe_size = sizeof(struct hisi_hpre_sqe);
	ret = wd_request_queue(&q);
	if (ret) {
		HPRE_TST_PRT("\nrequest queue fail!");
		return ret;
	}
	HPRE_TST_PRT("\nGet a WD HPRE queue of %s successfully!", q.capa.alg);
	setup.alg = q.capa.alg;
	setup.key_bits = key_bits;
	if (alg_op_type < MAX_RSA_TYPE && mode == RSA_CRT_MD) {
		setup.is_crt = 1;
	} else if (alg_op_type < MAX_RSA_TYPE && mode == RSA_COM_MD) {
		setup.is_crt = 0;
	} else {
		HPRE_TST_PRT("\nop type or mode err!");
		ret = -EINVAL;
		goto release_q;
	}
	ctx = wd_create_rsa_ctx(&q, &setup);
	if (!ctx) {
		ret = -ENOMEM;
		HPRE_TST_PRT("\ncreate rsa ctx fail!");
		goto release_q;
	}
	if (alg_op_type == RSA_KEY_GEN) {
		/* As generate key, we take in_file for storing public key
		 * and out_file for storing private key.
		 */
		return  hpre_test_op(alg_op_type, ctx, (__u8 *)in_file,
				     key_bits >> 3, (__u8 *)out_file,
				     key_bits, (__u8 *)key_file);
	}
	if (alg_op_type == RSA_PUB_EN && (mode == RSA_CRT_MD ||
		mode == RSA_COM_MD))
		read_size = pub_key_size = key_bits >> 2;
	else if (alg_op_type == RSA_PRV_DE && mode == RSA_CRT_MD)
		read_size = priv_key_size = (key_bits >> 4)  * 5;
	else if (alg_op_type == RSA_PRV_DE && mode == RSA_COM_MD)
		read_size = priv_key_size = key_bits >> 2;
	else {
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
		if (alg_op_type == RSA_PUB_EN) {
			memcpy(temp_in, tp_in, op_size);
			ret = hpre_test_op(alg_op_type, ctx, temp_in, op_size,
				out, key_bits, key);
		} else {
			ret = hpre_test_op(alg_op_type, ctx, tp_in, op_size,
				out, key_bits, key);
		}
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
				HPRE_TST_PRT("\nHPRE pub encrypt"\
				" %s to %s success!", in_file, out_file);
			else
				HPRE_TST_PRT("\nHPRE priv decrypt"\
				" %s to %s success!", in_file, out_file);
		} else if (try_close) {
			if (alg_op_type == RSA_PUB_EN)
				HPRE_TST_PRT("\nHPRE pub encrypt"\
				" %s to %s finished!", in_file, out_file);
			else
				HPRE_TST_PRT("\nHPRE priv decrypt"\
				" %s to %s finished!", in_file, out_file);
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
	wd_del_rsa_ctx(ctx);
	wd_release_queue(&q);

	return ret;
}
