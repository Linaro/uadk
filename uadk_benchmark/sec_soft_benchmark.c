/* SPDX-License-Identifier: Apache-2.0 */

#include "sec_soft_benchmark.h"

#include <openssl/async.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "include/wd_cipher.h"
#include "include/wd_digest.h"

#define SSL_TST_PRT printf

struct soft_bd {
	u8 *src;
	u8 *dst;
};

struct bd_pool {
	struct soft_bd *bds;
};

struct thread_pool {
	struct bd_pool *pool;
	u8 *iv;
	u8 *key;
} g_soft_pool;

typedef struct soft_thread_res {
	const EVP_CIPHER *evp_cipher;
	const EVP_MD *evp_md;
	u32 subtype;
	u32 mode;
	u32 keysize;
	u32 optype;
	u32 td_id;
	u32 engine_flag;
} soft_thread;

typedef struct soft_jobs_res {
	const EVP_CIPHER *evp_cipher;
	const EVP_MD *evp_md;
	u32 subtype;
	u32 mode;
	u32 keysize;
	u32 optype;
	u32 td_id;
	u32 jobid;
	u32 use_engine;
} jobs_data;

#define MAX_POOL_LENTH		4096
#define MAX_IVK_LENTH		64
#define DEF_IVK_DATA		0xAA
#define MAX_TRY_CNT		5000
#define SEND_USLEEP		100

static unsigned int g_thread_num;
static unsigned int g_ctxnum;
static unsigned int g_pktlen;

static int init_soft_bd_pool(void)
{
	unsigned long step;
	int fill_size;
	int i, j;

	// make the block not align to 4K
	step = sizeof(char) * g_pktlen * 2;
	if (g_pktlen > MAX_IVK_LENTH)
		fill_size = MAX_IVK_LENTH;
	else
		fill_size = g_pktlen;

	g_soft_pool.iv = malloc(g_thread_num * MAX_IVK_LENTH * sizeof(char));
	g_soft_pool.key = malloc(g_thread_num * MAX_IVK_LENTH * sizeof(char));

	g_soft_pool.pool = malloc(g_thread_num * sizeof(struct bd_pool));
	if (!g_soft_pool.pool) {
		SSL_TST_PRT("init openssl pool alloc thread failed!\n");
		return -ENOMEM;
	} else {
		for (i = 0; i < g_thread_num; i++) {
			g_soft_pool.pool[i].bds = malloc(MAX_POOL_LENTH *
							 sizeof(struct soft_bd));
			if (!g_soft_pool.pool[i].bds) {
				SSL_TST_PRT("init openssl bds alloc failed!\n");
				goto malloc_error1;
			}
			for (j = 0; j < MAX_POOL_LENTH; j++) {
				g_soft_pool.pool[i].bds[j].src = malloc(step);
				if (!g_soft_pool.pool[i].bds[j].src)
					goto malloc_error2;
				g_soft_pool.pool[i].bds[j].dst = malloc(step);
				if (!g_soft_pool.pool[i].bds[j].dst)
					goto malloc_error3;

				get_rand_data(g_soft_pool.pool[i].bds[j].src, fill_size);
				//get_rand_data(g_soft_pool.pool[i].bds[j].dst, 16);
			}
		}
	}

	return 0;

malloc_error3:
	free(g_soft_pool.pool[i].bds[j].src);
malloc_error2:
	for (j--; j >= 0; j--) {
		free(g_soft_pool.pool[i].bds[j].src);
		free(g_soft_pool.pool[i].bds[j].dst);
	}
malloc_error1:
	for (i--; i >= 0; i--) {
		for (j = 0; j < MAX_POOL_LENTH; j++) {
			free(g_soft_pool.pool[i].bds[j].src);
			free(g_soft_pool.pool[i].bds[j].dst);
		}
		free(g_soft_pool.pool[i].bds);
		g_soft_pool.pool[i].bds = NULL;
	}
	free(g_soft_pool.pool);
	g_soft_pool.pool = NULL;

	free(g_soft_pool.iv);
	free(g_soft_pool.key);

	SSL_TST_PRT("init openssl bd pool alloc failed!\n");
	return -ENOMEM;
}

static void free_soft_bd_pool(void)
{
	int i, j;

	for (i = 0; i < g_thread_num; i++) {
		if (g_soft_pool.pool[i].bds) {
			for (j = 0; j < MAX_POOL_LENTH; j++) {
				free(g_soft_pool.pool[i].bds[j].src);
				free(g_soft_pool.pool[i].bds[j].dst);
			}
		}
		free(g_soft_pool.pool[i].bds);
		g_soft_pool.pool[i].bds = NULL;
	}
	free(g_soft_pool.pool);
	g_soft_pool.pool = NULL;

	free(g_soft_pool.iv);
	free(g_soft_pool.key);
}

/*-------------------------------openssl benchmark main code-------------------------------------*/
static int sec_soft_param_parse(soft_thread *tddata, struct acc_option *options)
{
	u32 algtype = options->algtype;
	u32 optype = options->optype;
	u8 keysize = 0;
	u8 mode;

	tddata->evp_cipher = NULL;
	tddata->evp_md = NULL;

	switch(algtype) {
	case AES_128_ECB:
		keysize = 16;
		mode = WD_CIPHER_ECB;
		tddata->evp_cipher = EVP_aes_128_ecb();
		break;
	case AES_192_ECB:
		keysize = 24;
		mode = WD_CIPHER_ECB;
		tddata->evp_cipher = EVP_aes_192_ecb();
		break;
	case AES_256_ECB:
		keysize = 32;
		mode = WD_CIPHER_ECB;
		tddata->evp_cipher = EVP_aes_256_ecb();
		break;
	case AES_128_CBC:
		keysize = 16;
		mode = WD_CIPHER_CBC;
		tddata->evp_cipher = EVP_aes_128_cbc();
		break;
	case AES_192_CBC:
		keysize = 24;
		mode = WD_CIPHER_CBC;
		tddata->evp_cipher = EVP_aes_192_cbc();
		break;
	case AES_256_CBC:
		keysize = 32;
		mode = WD_CIPHER_CBC;
		tddata->evp_cipher = EVP_aes_256_cbc();
		break;
	case AES_128_CTR:
		keysize = 16;
		mode = WD_CIPHER_CTR;
		tddata->evp_cipher = EVP_aes_128_ctr();
		break;
	case AES_192_CTR:
		keysize = 24;
		mode = WD_CIPHER_CTR;
		tddata->evp_cipher = EVP_aes_192_ctr();
		break;
	case AES_256_CTR:
		keysize = 32;
		mode = WD_CIPHER_CTR;
		tddata->evp_cipher = EVP_aes_256_ctr();
		break;
	case AES_128_OFB:
		keysize = 16;
		mode = WD_CIPHER_OFB;
		tddata->evp_cipher = EVP_aes_128_ofb();
		break;
	case AES_192_OFB:
		keysize = 24;
		mode = WD_CIPHER_OFB;
		tddata->evp_cipher = EVP_aes_192_ofb();
		break;
	case AES_256_OFB:
		keysize = 32;
		mode = WD_CIPHER_OFB;
		tddata->evp_cipher = EVP_aes_256_ofb();
		break;
	case AES_128_CFB:
		keysize = 16;
		mode = WD_CIPHER_CFB;
		tddata->evp_cipher = EVP_aes_128_cfb();
		break;
	case AES_192_CFB:
		keysize = 24;
		mode = WD_CIPHER_CFB;
		tddata->evp_cipher = EVP_aes_192_cfb();
		break;
	case AES_256_CFB:
		keysize = 32;
		mode = WD_CIPHER_CFB;
		tddata->evp_cipher = EVP_aes_256_cfb();
		break;
	case AES_256_XTS:
		keysize = 32;
		mode = WD_CIPHER_XTS;
		tddata->evp_cipher = EVP_aes_128_xts();
		break;
	case AES_512_XTS:
		keysize = 64;
		mode = WD_CIPHER_XTS;
		tddata->evp_cipher = EVP_aes_256_xts();
		break;
	case DES3_128_ECB:
		keysize = 16;
		mode = WD_CIPHER_ECB;
		tddata->evp_cipher = EVP_des_ede_ecb();
		break;
	case DES3_192_ECB:
		keysize = 24;
		mode = WD_CIPHER_ECB;
		tddata->evp_cipher = EVP_des_ede3_ecb();
		break;
	case DES3_128_CBC:
		keysize = 16;
		mode = WD_CIPHER_CBC;
		tddata->evp_cipher = EVP_des_ede_cbc();
		break;
	case DES3_192_CBC:
		keysize = 24;
		mode = WD_CIPHER_CBC;
		tddata->evp_cipher = EVP_des_ede3_cbc();
		break;
	case SM4_128_ECB:
		keysize = 16;
		mode = WD_CIPHER_ECB;
		tddata->evp_cipher = EVP_sm4_ecb();
		break;
	case SM4_128_CBC:
		keysize = 16;
		mode = WD_CIPHER_CBC;
		tddata->evp_cipher = EVP_sm4_cbc();
		break;
	case SM4_128_CTR:
		keysize = 16;
		mode = WD_CIPHER_CTR;
		tddata->evp_cipher = EVP_sm4_ctr();
		break;
	case SM4_128_OFB:
		keysize = 16;
		mode = WD_CIPHER_OFB;
		tddata->evp_cipher = EVP_sm4_ofb();
		break;
	case SM4_128_CFB:
		keysize = 16;
		mode = WD_CIPHER_CFB;
		tddata->evp_cipher = EVP_sm4_cfb128();
		break;
	case SM4_128_XTS:
		keysize = 16;
		mode = WD_CIPHER_XTS;
		break;
	case AES_128_CCM:
		keysize = 16;
		mode = WD_CIPHER_CCM;
		tddata->evp_cipher = EVP_aes_128_ccm();
		break;
	case AES_192_CCM:
		keysize = 24;
		mode = WD_CIPHER_CCM;
		tddata->evp_cipher = EVP_aes_192_ccm();
		break;
	case AES_256_CCM:
		keysize = 32;
		mode = WD_CIPHER_CCM;
		tddata->evp_cipher = EVP_aes_256_ccm();
		break;
	case AES_128_GCM:
		keysize = 16;
		mode = WD_CIPHER_GCM;
		tddata->evp_cipher = EVP_aes_128_gcm();
		break;
	case AES_192_GCM:
		keysize = 24;
		mode = WD_CIPHER_GCM;
		tddata->evp_cipher = EVP_aes_192_gcm();
		break;
	case AES_256_GCM:
		keysize = 32;
		mode = WD_CIPHER_GCM;
		tddata->evp_cipher = EVP_aes_256_gcm();
		break;
	case SM4_128_CCM:
		keysize = 16;
		mode = WD_CIPHER_CCM;
		break;
	case SM4_128_GCM:
		keysize = 16;
		mode = WD_CIPHER_GCM;
		break;
	case SM3_ALG:		// digest mode is optype
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sm3();
		break;
	case MD5_ALG:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_md5();
		break;
	case SHA1_ALG:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha1();
		break;
	case SHA256_ALG:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha256();
		break;
	case SHA224_ALG:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha224();
		break;
	case SHA384_ALG:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha384();
		break;
	case SHA512_ALG:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha512();
		break;
	case SHA512_224:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha512_224();
		break;
	case SHA512_256:
		keysize = 4;
		mode = optype;
		tddata->evp_md = EVP_sha512_256();
		break;
	default:
		SSL_TST_PRT("Fail to set sec alg\n");
		return -EINVAL;
	}

	tddata->mode = mode;
	tddata->keysize = keysize;
	tddata->optype = options->optype;
	tddata->subtype = options->subtype;

	return 0;
}

static int sec_soft_jobfunc(void *args)
{
	jobs_data *jdata = (jobs_data *)args;
	const EVP_CIPHER *evp_cipher = jdata->evp_cipher;
	const EVP_MD *evp_md = jdata->evp_md;
	u32 optype = jdata->optype;
	u32 jid = jdata->jobid;
	struct bd_pool *soft_pool;
	u8 *priv_iv, *priv_key;
	int ret, outl, i = 0;
	EVP_CIPHER_CTX *ctx;
	EVP_MD_CTX *md_ctx;
	HMAC_CTX *hm_ctx;
	ASYNC_JOB *currjob;
	u8 faketag[16] = {0xcc};
	u8 aad[13] = {0xcc};
	u8 tag[12] = {0};
	u8 mac[EVP_MAX_MD_SIZE] = {0x00};
	u32 ssl_size = 0;
	u8 *src, *dst;

	currjob = ASYNC_get_current_job();
	if (!currjob) {
		SSL_TST_PRT("Error: not executing within a job\n");
		return 0;
	}

	if (!evp_cipher && !evp_md) {
		SSL_TST_PRT("Error: openssl not support!\n");
		return 0;
	}

	if (jdata->td_id > g_thread_num)
		return 0;

	soft_pool = &g_soft_pool.pool[jdata->td_id];
	priv_iv = &g_soft_pool.iv[jdata->td_id];
	priv_key = &g_soft_pool.key[jdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	switch(jdata->subtype) {
	case CIPHER_TYPE:
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
			return 0;

		EVP_CIPHER_CTX_set_padding(ctx, 0);

		ret = EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);
		if (ret != 1) {
			SSL_TST_PRT("Error: EVP_CipherInit_ex fail ret: %d\n", ret);
			break;
		}

		i = jid % MAX_POOL_LENTH;
		src = soft_pool->bds[i].src;
		dst = soft_pool->bds[i].dst;
		if (optype)
			ret = EVP_DecryptUpdate(ctx, dst, &outl, src, g_pktlen);
		else
			ret = EVP_EncryptUpdate(ctx, dst, &outl, src, g_pktlen);
		if (ret != 1)
			  EVP_CipherInit_ex(ctx, NULL, NULL, NULL, priv_iv, -1);

		if (optype)
			EVP_DecryptFinal_ex(ctx, dst, &outl);
		else
			EVP_EncryptFinal_ex(ctx, dst, &outl);

		EVP_CIPHER_CTX_free(ctx);
		break;
	case AEAD_TYPE:
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
			return 0;

		EVP_CIPHER_CTX_set_padding(ctx, 0);

		ret = EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);
		if (ret != 1) {
			SSL_TST_PRT("Error: AEAD EVP_CipherInit_ex fail ret: %d\n", ret);
			break;
		}

		if (jdata->mode == WD_CIPHER_CCM) {
			i = jid % MAX_POOL_LENTH;
			src = soft_pool->bds[i].src;
			dst = soft_pool->bds[i].dst;
			if (optype) {
				EVP_CIPHER_CTX_ctrl(ctx, 0x11, sizeof(tag), tag);
				/* reset iv */
				EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, priv_iv);
				EVP_DecryptUpdate(ctx, dst, &outl, src, g_pktlen);
			} else {
				/* restore iv length field */
				EVP_EncryptUpdate(ctx, NULL, &outl, NULL, g_pktlen);
				/* counter is reset on every update */
				EVP_EncryptUpdate(ctx, dst, &outl, src, g_pktlen);
			}

			if (optype)
				EVP_DecryptFinal_ex(ctx, dst, &outl);
			else
				EVP_EncryptFinal_ex(ctx, dst, &outl);
		} else {
			i = jid % MAX_POOL_LENTH;
			src = soft_pool->bds[i].src;
			dst = soft_pool->bds[i].dst;
			if (optype) {
				EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, priv_iv);
				EVP_CIPHER_CTX_ctrl(ctx, 0x11,
							  sizeof(faketag), tag);
				EVP_DecryptUpdate(ctx, NULL, &outl, aad, sizeof(aad));
				EVP_DecryptUpdate(ctx, dst, &outl, src, g_pktlen);
				EVP_DecryptFinal_ex(ctx, dst + outl, &outl);
			} else {
				EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, priv_iv);
				EVP_DecryptUpdate(ctx, NULL, &outl, aad, sizeof(aad));
				EVP_EncryptUpdate(ctx, NULL, &outl, NULL, g_pktlen);
				EVP_DecryptFinal_ex(ctx, dst + outl, &outl);
			}
		}
		EVP_CIPHER_CTX_free(ctx);

		break;
	case DIGEST_TYPE:
		if (!optype) { //normal mode
			md_ctx = EVP_MD_CTX_new();
			if (!md_ctx)
				return 0;

			i = jid % MAX_POOL_LENTH;
			src = soft_pool->bds[i].src;

			EVP_DigestInit_ex(md_ctx, evp_md, NULL);
			EVP_DigestUpdate(md_ctx, src, g_pktlen);
			EVP_DigestFinal_ex(md_ctx, mac, &ssl_size);
			// EVP_Digest(src, g_pktlen, mac, &ssl_size, evp_md, NULL);

			EVP_MD_CTX_free(md_ctx);
		} else { //hmac mode
			hm_ctx = HMAC_CTX_new();
			if (!hm_ctx)
				return 0;

			i = jid % MAX_POOL_LENTH;
			src = soft_pool->bds[i].src;

			HMAC_Init_ex(hm_ctx, priv_key, jdata->keysize, evp_md, NULL);
			HMAC_Update(hm_ctx, src, g_pktlen);
			HMAC_Final(hm_ctx, mac, &ssl_size);
			// HMAC(evp_md, priv_key, jdata->keysize, src, g_pktlen, mac, &ssl_size);

			HMAC_CTX_free(hm_ctx);
		}
		break;
	}

	return 0;
}

static void *sec_soft_async_run(void *arg)
{
	soft_thread *pdata = (soft_thread *)arg;
	ASYNC_WAIT_CTX *waitctx = NULL;
	ASYNC_JOB *job = NULL;
	int ret, jobret = 0;
	jobs_data jobdata;
	u32 count = 0;

	jobdata.evp_cipher = pdata->evp_cipher;
	jobdata.evp_md = pdata->evp_md;
	jobdata.keysize = pdata->keysize;
	jobdata.mode = pdata->mode;
	jobdata.optype = pdata->optype;
	jobdata.subtype = pdata->subtype;
	jobdata.td_id = pdata->td_id;

	waitctx = ASYNC_WAIT_CTX_new();
	if (!waitctx) {
		SSL_TST_PRT("Error: create ASYNC_WAIT_CTX failed\n");
		return NULL;
	}

	while (1) {
		jobdata.jobid = count;
		ret = ASYNC_start_job(&job, waitctx, &jobret, sec_soft_jobfunc,
			(void *)&jobdata, sizeof(jobs_data));
		switch(ret) {
		case ASYNC_ERR:
			SSL_TST_PRT("Error: start soft async job err. \n");
			goto exit_pause;
		case ASYNC_NO_JOBS:
			SSL_TST_PRT("Error: can't get soft async job from job pool. \n");
			goto exit_pause;
		case ASYNC_PAUSE:
			SSL_TST_PRT("Info: job was paused \n");
			break;
		case ASYNC_FINISH:
			break;
		default:
			SSL_TST_PRT("Error: do soft async job err. \n");
		}

		count++;
		if (get_run_state() == 0)
			break;
	}

exit_pause:
	ASYNC_WAIT_CTX_free(waitctx);

	add_recv_data(count);

	return NULL;
}

static void *sec_soft_sync_run(void *arg)
{
	soft_thread *pdata = (soft_thread *)arg;
	const EVP_CIPHER *evp_cipher = pdata->evp_cipher;
	const EVP_MD *evp_md = pdata->evp_md;
	u32 optype = pdata->optype;
	u8 mac[EVP_MAX_MD_SIZE] = {0x00};
	struct bd_pool *soft_pool;
	u8 *priv_iv, *priv_key;
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	HMAC_CTX *hm_ctx = NULL;
	u8 faketag[16] = {0xcc};
	u8 aad[13] = {0xcc};
	u8 tag[12] = {0};
	u32 ssl_size = 0;
	u32 count = 0;
	u8 *src, *dst;
	int ret, i = 0;
	int outl = 0;

	if (!evp_cipher && !evp_md) {
		SSL_TST_PRT("Error: openssl not support!\n");
		return NULL;
	}

	if (pdata->td_id > g_thread_num)
		return NULL;

	soft_pool = &g_soft_pool.pool[pdata->td_id];
	priv_iv = &g_soft_pool.iv[pdata->td_id];
	priv_key = &g_soft_pool.key[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	switch(pdata->subtype) {
	case CIPHER_TYPE:
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
			return NULL;

		EVP_CIPHER_CTX_set_padding(ctx, 0);

		while (1) {
			i = count % MAX_POOL_LENTH;
			src = soft_pool->bds[i].src;
			dst = soft_pool->bds[i].dst;

			(void)EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);

			if (optype)
				ret = EVP_DecryptUpdate(ctx, dst, &outl, src, g_pktlen);
			else
				ret = EVP_EncryptUpdate(ctx, dst, &outl, src, g_pktlen);
			if (ret != 1)
				EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);

			if (optype)
				EVP_DecryptFinal_ex(ctx, dst, &outl);
			else
				EVP_EncryptFinal_ex(ctx, dst, &outl);

			count++;
			if (get_run_state() == 0)
				break;
		}

		EVP_CIPHER_CTX_free(ctx);

		break;
	case AEAD_TYPE:
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
			return NULL;

		EVP_CIPHER_CTX_set_padding(ctx, 0);

		if (pdata->mode == WD_CIPHER_CCM) {
			while (1) {
				i = count % MAX_POOL_LENTH;
				src = soft_pool->bds[i].src;
				dst = soft_pool->bds[i].dst;

				(void)EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);

				if (optype) {
					EVP_CIPHER_CTX_ctrl(ctx, 0x11, sizeof(tag), tag);
					 /* reset iv */
	            			EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, priv_iv);
					ret = EVP_DecryptUpdate(ctx, dst, &outl, src, g_pktlen);
				} else {
					/* restore iv length field */
					EVP_EncryptUpdate(ctx, NULL, &outl, NULL, g_pktlen);
					/* counter is reset on every update */
					ret = EVP_EncryptUpdate(ctx, dst, &outl, src, g_pktlen);
				}
				if (ret != 1)
					EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);

				if (optype)
					EVP_DecryptFinal_ex(ctx, dst, &outl);
				else
					EVP_EncryptFinal_ex(ctx, dst, &outl);

				count++;
				if (get_run_state() == 0)
					break;
			}
		} else {
			while (1) {
				i = count % MAX_POOL_LENTH;
				src = soft_pool->bds[i].src;
				dst = soft_pool->bds[i].dst;

				(void)EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);

				if (optype) {
					EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, priv_iv);
					EVP_CIPHER_CTX_ctrl(ctx, 0x11,
								  sizeof(faketag), tag);
					EVP_DecryptUpdate(ctx, NULL, &outl, aad, sizeof(aad));
					EVP_DecryptUpdate(ctx, dst, &outl, src, g_pktlen);
					ret = EVP_DecryptFinal_ex(ctx, dst + outl, &outl);
				} else {
					EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, priv_iv);
					EVP_DecryptUpdate(ctx, NULL, &outl, aad, sizeof(aad));
					EVP_EncryptUpdate(ctx, NULL, &outl, NULL, g_pktlen);
					ret = EVP_DecryptFinal_ex(ctx, dst + outl, &outl);
				}
				if (ret != 1)
					EVP_CipherInit_ex(ctx, evp_cipher, NULL, priv_key, priv_iv, optype);

				count++;
				if (get_run_state() == 0)
					break;
			}
		}
		EVP_CIPHER_CTX_free(ctx);

		break;
	case DIGEST_TYPE:
		if (!optype) { //normal mode
			md_ctx = EVP_MD_CTX_new();
			if (!md_ctx)
				return NULL;

			while (1) {
				i = count % MAX_POOL_LENTH;
				src = soft_pool->bds[i].src;

				EVP_DigestInit_ex(md_ctx, evp_md, NULL);
				EVP_DigestUpdate(md_ctx, src, g_pktlen);
				EVP_DigestFinal_ex(md_ctx, mac, &ssl_size);
				// EVP_Digest(src, g_pktlen, mac, &ssl_size, evp_md, NULL);

				count++;
				if (get_run_state() == 0)
					break;
			}
			EVP_MD_CTX_free(md_ctx);
		} else { //hmac mode
			hm_ctx = HMAC_CTX_new();
			if (!hm_ctx)
				return NULL;

			while (1) {
				i = count % MAX_POOL_LENTH;
				src = soft_pool->bds[i].src;

				HMAC_Init_ex(hm_ctx, priv_key, pdata->keysize, evp_md, NULL);
				HMAC_Update(hm_ctx, src, g_pktlen);
				HMAC_Final(hm_ctx, mac, &ssl_size);
				// HMAC(evp_md, priv_key, pdata->keysize, src, g_pktlen, mac, &ssl_size);

				count++;
				if (get_run_state() == 0)
					break;
			}
			HMAC_CTX_free(hm_ctx);
		}
		break;
	}

	add_recv_data(count);

	return NULL;
}

int sec_soft_sync_threads(struct acc_option *options)
{
	soft_thread threads_args[THREADS_NUM];
	soft_thread threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = sec_soft_param_parse(&threads_option, options);
	if (ret)
		return ret;

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].evp_cipher = threads_option.evp_cipher;
		threads_args[i].evp_md = threads_option.evp_md;
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].keysize = threads_option.keysize;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		threads_args[i].engine_flag = options->engine_flag;
		ret = pthread_create(&tdid[i], NULL, sec_soft_sync_run, &threads_args[i]);
		if (ret) {
			SSL_TST_PRT("Create sync thread fail!\n");
			goto sync_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			SSL_TST_PRT("Join sync thread fail!\n");
			goto sync_error;
		}
	}

sync_error:
	return ret;

}

int sec_soft_async_threads(struct acc_option *options)
{
	soft_thread threads_args[THREADS_NUM];
	soft_thread threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = sec_soft_param_parse(&threads_option, options);
	if (ret)
		return ret;

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].evp_cipher = threads_option.evp_cipher;
		threads_args[i].evp_md = threads_option.evp_md;
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].keysize = threads_option.keysize;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		threads_args[i].engine_flag = options->engine_flag;
		ret = pthread_create(&tdid[i], NULL, sec_soft_async_run, &threads_args[i]);
		if (ret) {
			SSL_TST_PRT("Create async thread fail!\n");
			goto async_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			SSL_TST_PRT("Join async thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

static int uadk_engine_register(struct acc_option *options)
{
	ENGINE *e = NULL;

	if (!options->engine_flag)
		return 0;

	ERR_load_ENGINE_strings();
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL);

	e = ENGINE_by_id(options->engine);
	if (!e) {
		SSL_TST_PRT("setup uadk engine failed!\n");
		return -EINVAL;
	}

	ENGINE_init(e);
	switch(options->subtype) {
	case CIPHER_TYPE:
		ENGINE_register_ciphers(e);
		break;
	case AEAD_TYPE:
		SSL_TST_PRT("Openssl not support AEAD ALG!\n");
		return -EINVAL;
	case DIGEST_TYPE:
		ENGINE_register_digests(e);
		break;
	default:
		return -EINVAL;
	}
	ENGINE_free(e);

	return 0;
}

static void uadk_engine_unregister(struct acc_option *options)
{
	ENGINE *e = NULL;

	if (!options->engine_flag)
		return;

	e = ENGINE_by_id(options->engine);
	if (!e) {
		SSL_TST_PRT("Error: not find uadk engine \n");
		return;
	}

	ENGINE_init(e);
	switch(options->subtype) {
	case CIPHER_TYPE:
		ENGINE_unregister_ciphers(e);
		break;
	case AEAD_TYPE:
		// ENGINE_unregister_ciphers(e); //openssl not support aead
		break;
	case DIGEST_TYPE:
		ENGINE_unregister_digests(e);
		break;
	default:
		return;
	}
	ENGINE_free(e);
}

int sec_soft_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;
	g_pktlen = options->pktlen;
	g_ctxnum = options->ctxnums;
	if (options->optype > WD_CIPHER_DECRYPTION) {
		SSL_TST_PRT("SEC optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_soft_bd_pool();
	if (ret)
		return ret;

	ret = uadk_engine_register(options);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = sec_soft_async_threads(options);
	else
		ret = sec_soft_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	uadk_engine_unregister(options);
	free_soft_bd_pool();

	return 0;
}
