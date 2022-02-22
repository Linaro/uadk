/* SPDX-License-Identifier: Apache-2.0 */

#include "uadk_benchmark.h"
#include "sec_wd_benchmark.h"

#include "v1/wd.h"
#include "v1/wd_cipher.h"
#include "v1/wd_aead.h"
#include "v1/wd_digest.h"
#include "v1/wd_bmm.h"
#include "v1/wd_util.h"

#define SEC_TST_PRT printf

typedef struct wd_thread_res {
	u32 subtype;
	u32 alg;
	u32 mode;
	u32 keysize;
	u32 ivsize;
	u32 optype;
	u32 td_id;
} thread_data;

struct thread_bd_res {
	struct wd_queue *queue;
	void *pool;
	void **in;
	void **out;
	void **iv;
};

struct thread_queue_res {
	struct thread_bd_res *bd_res;
} g_thread_queue;

struct wcrypto_async_tag {
	void *ctx;
	char *out_buf;
	int thread_id;
	int cnt;
};

#define MAX_IVK_LENTH		64
#define DEF_IVK_DATA		0xAA
#define MAX_TRY_CNT		5000
#define SEND_USLEEP		100
#define TEST_MAX_THRD		128
#define SQE_SIZE		128
#define MAX_BLOCK_NM		4096

static unsigned int g_thread_num;
static unsigned int g_ctxnum;
static unsigned int g_pktlen;

static void *cipher_async_cb(void *message, void *cipher_tag)
{
	struct wcrypto_async_tag *async_tag = (struct wcrypto_async_tag *)cipher_tag;
	struct wcrypto_cipher_msg *req = (struct wcrypto_cipher_msg *)message;

	// no-sva data copy from uadk to user
	memcpy(async_tag->out_buf, req->out, g_pktlen);

	return NULL;
}

static void *aead_async_cb(void *message, void *aead_tag)
{
	struct wcrypto_async_tag *async_tag = (struct wcrypto_async_tag *)aead_tag;
	struct wcrypto_aead_msg *req = (struct wcrypto_aead_msg *)message;

	// no-sva data copy from uadk to user
	memcpy(async_tag->out_buf, req->out, g_pktlen);

	return NULL;
}

static void *digest_async_cb(void *message, void *digest_tag)
{
	struct wcrypto_async_tag *async_tag = (struct wcrypto_async_tag *)digest_tag;
	struct wcrypto_digest_msg *req = (struct wcrypto_digest_msg *)message;

	// no-sva data copy from uadk to user
	memcpy(async_tag->out_buf, req->out, 16);

	return NULL;
}

static int sec_wd_param_parse(thread_data *tddata, struct acc_option *options)
{
	u32 algtype = options->algtype;
	u32 optype = options->optype;
	u8 keysize = 0;
	u8 ivsize = 0;
	u8 mode;
	u8 alg;

	switch(algtype) {
	case AES_128_ECB:
		keysize = 16;
		ivsize = 0;
		mode = WCRYPTO_CIPHER_ECB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_ECB:
		keysize = 24;
		ivsize = 0;
		mode = WCRYPTO_CIPHER_ECB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_ECB:
		keysize = 32;
		ivsize = 0;
		mode = WCRYPTO_CIPHER_ECB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_128_CBC:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CBC;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_CBC:
		keysize = 24;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CBC;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_CBC:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CBC;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_128_CTR:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CTR;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_CTR:
		keysize = 24;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CTR;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_CTR:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CTR;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_128_OFB:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_OFB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_OFB:
		keysize = 24;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_OFB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_OFB:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_OFB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_128_CFB:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CFB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_CFB:
		keysize = 24;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CFB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_CFB:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CFB;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_XTS:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_XTS;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_512_XTS:
		keysize = 64;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_XTS;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case DES3_128_ECB:
		keysize = 16;
		ivsize = 0;
		mode = WCRYPTO_CIPHER_ECB;
		alg = WCRYPTO_CIPHER_3DES;
		break;
	case DES3_192_ECB:
		keysize = 24;
		ivsize = 0;
		mode = WCRYPTO_CIPHER_ECB;
		alg = WCRYPTO_CIPHER_3DES;
		break;
	case DES3_128_CBC:
		keysize = 16;
		ivsize = 8;
		mode = WCRYPTO_CIPHER_CBC;
		alg = WCRYPTO_CIPHER_3DES;
		break;
	case DES3_192_CBC:
		keysize = 24;
		ivsize = 8;
		mode = WCRYPTO_CIPHER_CBC;
		alg = WCRYPTO_CIPHER_3DES;
		break;
	case SM4_128_ECB:
		keysize = 16;
		ivsize = 0;
		mode = WCRYPTO_CIPHER_ECB;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM4_128_CBC:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CBC;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM4_128_CTR:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CTR;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM4_128_OFB:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_OFB;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM4_128_CFB:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CFB;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM4_128_XTS:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_XTS;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case AES_128_CCM:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CCM;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_CCM:
		keysize = 24;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CCM;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_CCM:
		keysize = 32;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CCM;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_128_GCM:
		keysize = 16;
		ivsize = 12;
		mode = WCRYPTO_CIPHER_GCM;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_192_GCM:
		keysize = 24;
		ivsize = 12;
		mode = WCRYPTO_CIPHER_GCM;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case AES_256_GCM:
		keysize = 32;
		ivsize = 12;
		mode = WCRYPTO_CIPHER_GCM;
		alg = WCRYPTO_CIPHER_AES;
		break;
	case SM4_128_CCM:
		keysize = 16;
		ivsize = 16;
		mode = WCRYPTO_CIPHER_CCM;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM4_128_GCM:
		keysize = 16;
		ivsize = 12;
		mode = WCRYPTO_CIPHER_GCM;
		alg = WCRYPTO_CIPHER_SM4;
		break;
	case SM3_ALG:		// digest mode is optype
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SM3;
		break;
	case MD5_ALG:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_MD5;
		break;
	case SHA1_ALG:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA1;
		break;
	case SHA256_ALG:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA256;
		break;
	case SHA224_ALG:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA224;
		break;
	case SHA384_ALG:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA384;
		break;
	case SHA512_ALG:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA512;
		break;
	case SHA512_224:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA512_224;
		break;
	case SHA512_256:
		keysize = 4;
		mode = optype;
		alg = WCRYPTO_SHA512_256;
		break;
	default:
		SEC_TST_PRT("Fail to set sec alg\n");
		return -EINVAL;
	}

	tddata->alg = alg;
	tddata->mode = mode;
	tddata->ivsize = ivsize;
	tddata->keysize = keysize;
	tddata->optype = options->optype;
	tddata->subtype = options->subtype;

	return 0;
}

static int init_wd_queue(struct acc_option *options)
{
	struct wd_blkpool_setup blksetup;
	int i, j, m, n, k, idx, ret;

	g_thread_queue.bd_res = malloc(g_thread_num * sizeof(struct thread_bd_res));
	if (!g_thread_queue.bd_res) {
		SEC_TST_PRT("malloc thread res memory fail!\n");
		return -ENOMEM;
	}

	for (i = 0; i < g_thread_num; i++) {
		g_thread_queue.bd_res[i].queue = malloc(sizeof(struct wd_queue));
		g_thread_queue.bd_res[i].queue->capa.alg = options->algclass;
		// 0 is ENC, 1 is DEC
		g_thread_queue.bd_res[i].queue->capa.priv.direction = options->optype;
		/* nodemask need to    be clean */
		g_thread_queue.bd_res[i].queue->node_mask = 0x0;
		memset(g_thread_queue.bd_res[i].queue->dev_path, 0x0, PATH_STR_SIZE);

		ret = wd_request_queue(g_thread_queue.bd_res[i].queue);
		if (ret) {
			SEC_TST_PRT("request queue %d fail!\n", i);
			goto queue_out;
		}
	}

	// use no-sva pbuffer
	memset(&blksetup, 0, sizeof(blksetup));
	blksetup.block_size = g_pktlen + SQE_SIZE; //aead need mac and aad out
	blksetup.block_num = MAX_BLOCK_NM * 4; //set pool  inv + key + in + out
	blksetup.align_size = SQE_SIZE;
	SEC_TST_PRT("create pool memory: %d KB\n", (MAX_BLOCK_NM * blksetup.block_size) >> 10);

	for (j = 0; j < g_thread_num; j++) {
		g_thread_queue.bd_res[j].pool = wd_blkpool_create(g_thread_queue.bd_res[j].queue, &blksetup);
		if (!g_thread_queue.bd_res[j].pool) {
			SEC_TST_PRT("create %dth pool fail!\n", j);
			ret = -ENOMEM;
			goto pool_err;
		}
	}

	// alloc in pbuffer res
	for (m = 0; m < g_thread_num; m++) {
		g_thread_queue.bd_res[m].in = malloc(MAX_BLOCK_NM * sizeof(void *));
		for (idx = 0; idx < MAX_BLOCK_NM; idx++) {
			g_thread_queue.bd_res[m].in[idx] = wd_alloc_blk(g_thread_queue.bd_res[m].pool);
			if (!g_thread_queue.bd_res[m].in[idx]) {
				SEC_TST_PRT("create pool %dth in memory fail!\n", m);
				for (idx--; idx >= 0; idx--)
					wd_free_blk(g_thread_queue.bd_res[m].pool,
							g_thread_queue.bd_res[m].in[idx]);
				ret = -ENOMEM;
				goto in_err;
			}
		}
	}

	// alloc out pbuffer res
	for (n = 0; n < g_thread_num; n++) {
		g_thread_queue.bd_res[n].out = malloc(MAX_BLOCK_NM * sizeof(void *));
		for (idx = 0; idx < MAX_BLOCK_NM; idx++) {
			g_thread_queue.bd_res[n].out[idx] = wd_alloc_blk(g_thread_queue.bd_res[n].pool);
			if (!g_thread_queue.bd_res[n].out[idx]) {
				SEC_TST_PRT("create pool %dth out memory fail!\n", n);
				for (idx--; idx >= 0; idx--)
					wd_free_blk(g_thread_queue.bd_res[n].pool,
							g_thread_queue.bd_res[n].out[idx]);
				ret = -ENOMEM;
				goto out_err;
			}
		}
	}

	// alloc iv pbuffer res
	for (k = 0; k < g_thread_num; k++) {
		g_thread_queue.bd_res[k].iv = malloc(MAX_BLOCK_NM * sizeof(void *));
		for (idx = 0; idx < MAX_BLOCK_NM; idx++) {
			g_thread_queue.bd_res[k].iv[idx] = wd_alloc_blk(g_thread_queue.bd_res[k].pool);
			if (!g_thread_queue.bd_res[k].iv[idx]) {
				SEC_TST_PRT("create pool %dth iv memory fail!\n", k);
				for (idx--; idx >= 0; idx--)
					wd_free_blk(g_thread_queue.bd_res[k].pool,
							g_thread_queue.bd_res[k].iv[idx]);
				ret = -ENOMEM;
				goto iv_err;
			}
			memset(g_thread_queue.bd_res[k].iv[idx], DEF_IVK_DATA, MAX_IVK_LENTH);
		}
	}

	return 0;

iv_err:
	for (k--; k >= 0; k--) {
		for (idx = 0; idx < MAX_BLOCK_NM; idx++)
			wd_free_blk(g_thread_queue.bd_res[k].pool,
					g_thread_queue.bd_res[k].iv[idx]);
		free(g_thread_queue.bd_res[k].iv);
	}
out_err:
	for (n--; n >= 0; n--) {
		for (idx = 0; idx < MAX_BLOCK_NM; idx++)
			wd_free_blk(g_thread_queue.bd_res[n].pool,
					g_thread_queue.bd_res[n].out[idx]);
		free(g_thread_queue.bd_res[n].out);
	}
in_err:
	for (m--; m >= 0; m--) {
		for (idx = 0; idx < MAX_BLOCK_NM; idx++)
			wd_free_blk(g_thread_queue.bd_res[m].pool,
					g_thread_queue.bd_res[m].in[idx]);
		free(g_thread_queue.bd_res[m].in);
	}
pool_err:
	for (j--; j >= 0; j--)
		wd_blkpool_destroy(g_thread_queue.bd_res[j].pool);
queue_out:
	for (i--; i >= 0; i--) {
		wd_release_queue(g_thread_queue.bd_res[i].queue);
		free(g_thread_queue.bd_res[i].queue);
	}
	free(g_thread_queue.bd_res);
	return ret;
}

static void uninit_wd_queue(void)
{
	int i, j, idx;

	for (i = 0; i < g_thread_num; i++) {
		for (idx = 0; idx < MAX_BLOCK_NM; idx++) {
			wd_free_blk(g_thread_queue.bd_res[i].pool, g_thread_queue.bd_res[i].iv[idx]);
			wd_free_blk(g_thread_queue.bd_res[i].pool, g_thread_queue.bd_res[i].in[idx]);
			wd_free_blk(g_thread_queue.bd_res[i].pool, g_thread_queue.bd_res[i].out[idx]);
		}
		free(g_thread_queue.bd_res[i].in);
		free(g_thread_queue.bd_res[i].out);
		free(g_thread_queue.bd_res[i].iv);
	}

	for (j = 0; j < g_thread_num; j++) {
		wd_blkpool_destroy(g_thread_queue.bd_res[j].pool);
		wd_release_queue(g_thread_queue.bd_res[j].queue);
	}

	free(g_thread_queue.bd_res);
}

/*-------------------------------uadk benchmark main code-------------------------------------*/

void *sec_wd_poll(void *data)
{
	typedef int (*poll_ctx)(struct wd_queue *q, unsigned int num);
	thread_data *pdata = (thread_data *)data;
	poll_ctx uadk_poll_ctx = NULL;
	u32 expt = ACC_QUEUE_SIZE * g_thread_num;
	u32 last_time = 2; /* poll need one more recv time */
	u32 id = pdata->td_id;
	u32 count = 0;
	u32 recv = 0;

	switch(pdata->subtype) {
	case CIPHER_TYPE:
		uadk_poll_ctx = wcrypto_cipher_poll;
		break;
	case AEAD_TYPE:
		uadk_poll_ctx = wcrypto_aead_poll;
		break;
	case DIGEST_TYPE:
		uadk_poll_ctx = wcrypto_digest_poll;
		break;
	default:
		SEC_TST_PRT("<<<<<<async poll interface is NULL!\n");
		return NULL;
	}

	if (id > g_thread_num)
		return NULL;

	while (last_time) {
		recv = uadk_poll_ctx(g_thread_queue.bd_res[id].queue, expt);
		/*
		 * warpdrive async mode poll easy to 100% with small package.
		 * SEC_TST_PRT("warpdrive poll %d recv: %u!\n", i, recv);
		 */
		if (unlikely(recv < 0)) {
			SEC_TST_PRT("poll ret: %u!\n", recv);
			goto recv_error;
		}
		count += recv;
		recv = 0;

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count);

	return NULL;
}

static void *sec_wd_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wcrypto_cipher_ctx_setup cipher_setup = {0};
	struct wcrypto_aead_ctx_setup aead_setup = {0};
	struct wcrypto_digest_ctx_setup digest_setup = {0};
	struct wcrypto_cipher_op_data copdata;
	struct wcrypto_aead_op_data aopdata;
	struct wcrypto_digest_op_data dopdata;
	struct wcrypto_async_tag *tag = NULL;
	char priv_key[MAX_IVK_LENTH];
	struct thread_bd_res *bd_res;
	char *src_data_buf = NULL;
	char *out_data_buf = NULL;
	struct wd_queue *queue;
	void *ctx = NULL;
	void **res_in;
	void **res_out;
	void **res_iv;
	u32 count = 0;
	int try_cnt = 0;
	u32 authsize;
	int ret, i = 0;
	void *pool;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_res = &g_thread_queue.bd_res[pdata->td_id];
	queue = bd_res->queue;
	pool = bd_res->pool;
	res_in = bd_res->in;
	res_out = bd_res->out;
	res_iv = bd_res->iv;

	/* create user data buffer */
	src_data_buf = malloc(g_pktlen * sizeof(char));
	if (!src_data_buf)
		return NULL;

	get_rand_data(src_data_buf, g_pktlen);
	out_data_buf = malloc(g_pktlen * sizeof(char));
	if (!out_data_buf) {
		free(src_data_buf);
		return NULL;
	}

	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);
	tag = malloc(sizeof(struct wcrypto_async_tag)); // set the user tag
	if (!tag) {
		SEC_TST_PRT("wcrypto async alloc tag fail!\n");
		free(src_data_buf);
		free(out_data_buf);
		return NULL;
	}
	tag->out_buf = out_data_buf;

	switch(pdata->subtype) {
	case CIPHER_TYPE:
		cipher_setup.alg = pdata->alg;
		cipher_setup.mode = pdata->mode;
		cipher_setup.cb = (void *)cipher_async_cb;
		cipher_setup.br.alloc = (void *)wd_alloc_blk;
		cipher_setup.br.free = (void *)wd_free_blk;
		cipher_setup.br.iova_map = (void *)wd_blk_iova_map;
		cipher_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		cipher_setup.br.get_bufsize = (void *)wd_blksize;
		cipher_setup.br.usr = pool;

		ctx = wcrypto_create_cipher_ctx(queue, &cipher_setup);
		if (!ctx) {
			SEC_TST_PRT("wd create cipher ctx fail!\n");
			goto async_err;
		}
		tag->ctx = ctx;

		ret = wcrypto_set_cipher_key(ctx, (__u8*)priv_key, (__u16)pdata->keysize);
		if (ret) {
			SEC_TST_PRT("wd cipher set key fail!\n");
			wcrypto_del_cipher_ctx(ctx);
			goto async_err;
		}

		if (queue->capa.priv.direction == 0)
			copdata.op_type = WCRYPTO_CIPHER_ENCRYPTION;
		else
			copdata.op_type = WCRYPTO_CIPHER_DECRYPTION;

		copdata.in_bytes = g_pktlen;
		copdata.out_bytes = g_pktlen;
		copdata.iv_bytes = pdata->ivsize;
		copdata.priv = NULL;

		tag->cnt = 0;
		copdata.in = res_in[0];
		copdata.out   = res_out[0];
		copdata.iv = res_iv[0];
		usleep(SEND_USLEEP);
		while(1) {
			if (get_run_state() == 0)
				break;

			// no-sva data copy to uadk
			memcpy(copdata.in, src_data_buf, g_pktlen);

			ret = wcrypto_do_cipher(ctx, &copdata, (void *)tag);
			if (ret == -WD_EBUSY) {
				usleep(SEND_USLEEP * try_cnt);
				try_cnt++;
				if (try_cnt > MAX_TRY_CNT) {
					SEC_TST_PRT("Test cipher send fail %d times!\n", MAX_TRY_CNT);
					try_cnt = 0;
				}
				continue;
			}

			count++;
			i = count % MAX_BLOCK_NM;
			tag->cnt = i;
			try_cnt = 0;
			copdata.in = res_in[i];
			copdata.out   = res_out[i];
			copdata.iv = res_iv[i];
		}

		break;
	case AEAD_TYPE: // just ccm and gcm
		aead_setup.calg = pdata->alg;
		aead_setup.cmode = pdata->mode;
		aead_setup.cb = (void *)aead_async_cb;
		aead_setup.br.alloc = (void *)wd_alloc_blk;
		aead_setup.br.free = (void *)wd_free_blk;
		aead_setup.br.iova_map = (void *)wd_blk_iova_map;
		aead_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		aead_setup.br.get_bufsize = (void *)wd_blksize;
		aead_setup.br.usr = pool;

		ctx = wcrypto_create_aead_ctx(queue, &aead_setup);
		if (!ctx) {
			SEC_TST_PRT("wd create aead ctx fail!\n");
			goto async_err;
		}
		tag->ctx = ctx;

		ret = wcrypto_set_aead_ckey(ctx, (__u8*)priv_key, (__u16)pdata->keysize);
		if (ret) {
			SEC_TST_PRT("wd aead set key fail!\n");
			wcrypto_del_aead_ctx(ctx);
			goto async_err;
		}

		authsize = 16; //set defaut size
		ret = wcrypto_aead_setauthsize(ctx, authsize);
		if (ret) {
			SEC_TST_PRT("set authsize fail!\n");
			wcrypto_del_aead_ctx(ctx);
			goto async_err;
		}

		if (queue->capa.priv.direction == 0) {
			aopdata.op_type = WCRYPTO_CIPHER_ENCRYPTION_DIGEST;
			aopdata.out_bytes = g_pktlen + 32; // aad + plen + authsize;
		} else {
			aopdata.op_type = WCRYPTO_CIPHER_DECRYPTION_DIGEST;
			aopdata.out_bytes = g_pktlen + 16; // aad + plen;
		}

		aopdata.assoc_size = 16;
		aopdata.in_bytes = g_pktlen;
		aopdata.out_bytes = g_pktlen;
		aopdata.iv_bytes = pdata->ivsize;
		aopdata.priv = NULL;
		aopdata.out_buf_bytes = g_pktlen * 2;

		tag->cnt = 0;
		aopdata.in = res_in[0];
		aopdata.out   = res_out[0];
		aopdata.iv = res_iv[0];
		usleep(SEND_USLEEP);
		while(1) {
			if (get_run_state() == 0)
				break;

			// no-sva data copy to uadk
			memcpy(aopdata.in, src_data_buf, g_pktlen);

			ret = wcrypto_do_aead(ctx, &aopdata, (void *)tag);
			if (ret == -WD_EBUSY) {
				usleep(SEND_USLEEP * try_cnt);
				try_cnt++;
				if (try_cnt > MAX_TRY_CNT) {
					SEC_TST_PRT("Test aead send fail %d times!\n", MAX_TRY_CNT);
					try_cnt = 0;
				}
				continue;
			}

			count++;
			i = count % MAX_BLOCK_NM;
			tag->cnt = i;
			try_cnt = 0;
			aopdata.in = res_in[i];
			aopdata.out   = res_out[i];
			aopdata.iv = res_iv[i];
		}

		break;
	case DIGEST_TYPE:
		digest_setup.alg = pdata->alg;
		digest_setup.mode = pdata->mode;
		digest_setup.cb = (void *)digest_async_cb;
		digest_setup.br.alloc = (void *)wd_alloc_blk;
		digest_setup.br.free = (void *)wd_free_blk;
		digest_setup.br.iova_map = (void *)wd_blk_iova_map;
		digest_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		digest_setup.br.get_bufsize = (void *)wd_blksize;
		digest_setup.br.usr = pool;

		ctx = wcrypto_create_digest_ctx(queue, &digest_setup);
		if (!ctx) {
			SEC_TST_PRT("wd create digest ctx fail!\n");
			goto async_err;
		}
		tag->ctx = ctx;

		if (digest_setup.mode == WCRYPTO_DIGEST_HMAC) {
			ret = wcrypto_set_digest_key(ctx, (__u8*)priv_key,
							    (__u16)pdata->keysize);
			if (ret) {
				SEC_TST_PRT("wd digest set key fail!\n");
				wcrypto_del_digest_ctx(ctx);
				goto async_err;
			}
		}

		dopdata.in_bytes = g_pktlen;
		dopdata.out_bytes = 16;
		dopdata.has_next = 0;
		dopdata.priv = NULL;

		tag->cnt = 0;
		dopdata.in = res_in[0];
		dopdata.out   = res_out[0];
		usleep(SEND_USLEEP);
		while(1) {
			if (get_run_state() == 0)
				break;

			// no-sva data copy to uadk
			memcpy(dopdata.in, src_data_buf, g_pktlen);

			ret = wcrypto_do_digest(ctx, &dopdata, (void *)tag);
			if (ret == -WD_EBUSY) {
				usleep(SEND_USLEEP * try_cnt);
				try_cnt++;
				if (try_cnt > MAX_TRY_CNT) {
					SEC_TST_PRT("Test digest send fail %d times!\n", MAX_TRY_CNT);
					try_cnt = 0;
				}
				continue;
			}

			count++;
			i = count % MAX_BLOCK_NM;
			tag->cnt = i;
			try_cnt = 0;
			dopdata.in = res_in[i];
			dopdata.out   = res_out[i];
		}

		break;
	}

	add_send_complete();

	while (1) {
		if (get_recv_time() == g_thread_num) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}

	switch(pdata->subtype) {
	case CIPHER_TYPE:
		wcrypto_del_cipher_ctx(ctx);
		break;
	case AEAD_TYPE:
		wcrypto_del_aead_ctx(ctx);
		break;
	case DIGEST_TYPE:
		wcrypto_del_digest_ctx(ctx);
		break;
	}

async_err:
	free(tag);
	free(src_data_buf);
	free(out_data_buf);
	return NULL;
}

static void *sec_wd_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wcrypto_cipher_ctx_setup cipher_setup = {0};
	struct wcrypto_aead_ctx_setup aead_setup = {0};
	struct wcrypto_digest_ctx_setup digest_setup = {0};
	struct wcrypto_cipher_op_data copdata;
	struct wcrypto_aead_op_data aopdata;
	struct wcrypto_digest_op_data dopdata;
	char priv_key[MAX_IVK_LENTH];
	struct thread_bd_res *bd_res;
	struct wd_queue *queue;
	char *src_data_buf = NULL;
	char *out_data_buf = NULL;
	void *ctx = NULL;
	void *tag = NULL;
	void **res_in;
	void **res_out;
	void **res_iv;
	u32 count = 0;
	int try_cnt = 0;
	u32 authsize;
	int ret, i = 0;
	void *pool;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_res = &g_thread_queue.bd_res[pdata->td_id];
	queue = bd_res->queue;
	pool = bd_res->pool;
	res_in = bd_res->in;
	res_out = bd_res->out;
	res_iv = bd_res->iv;

	/* create user data buffer */
	src_data_buf = malloc(g_pktlen * sizeof(char));
	if (!src_data_buf)
		return NULL;

	get_rand_data(src_data_buf, g_pktlen);
	out_data_buf = malloc(g_pktlen * sizeof(char));
	if (!out_data_buf) {
		free(src_data_buf);
		return NULL;
	}

	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	switch(pdata->subtype) {
	case CIPHER_TYPE:
		cipher_setup.alg = pdata->alg;
		cipher_setup.mode = pdata->mode;
		cipher_setup.br.alloc = (void *)wd_alloc_blk;
		cipher_setup.br.free = (void *)wd_free_blk;
		cipher_setup.br.iova_map = (void *)wd_blk_iova_map;
		cipher_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		cipher_setup.br.get_bufsize = (void *)wd_blksize;
		cipher_setup.br.usr = pool;

		ctx = wcrypto_create_cipher_ctx(queue, &cipher_setup);
		if (!ctx) {
			SEC_TST_PRT("wd create cipher ctx fail!\n");
			goto sync_err;
		}

		ret = wcrypto_set_cipher_key(ctx, (__u8*)priv_key, (__u16)pdata->keysize);
		if (ret) {
			SEC_TST_PRT("wd cipher set key fail!\n");
			wcrypto_del_cipher_ctx(ctx);
			goto sync_err;
		}

		if (queue->capa.priv.direction == 0)
			copdata.op_type = WCRYPTO_CIPHER_ENCRYPTION;
		else
			copdata.op_type = WCRYPTO_CIPHER_DECRYPTION;

		copdata.in_bytes = g_pktlen;
		copdata.out_bytes = g_pktlen;
		copdata.iv_bytes = pdata->ivsize;
		copdata.priv = NULL;

		copdata.in = res_in[0];
		copdata.out   = res_out[0];
		copdata.iv = res_iv[0];
		usleep(SEND_USLEEP);
		while(1) {
			if (get_run_state() == 0)
				break;

			// no-sva data copy to uadk
			memcpy(copdata.in, src_data_buf, g_pktlen);

			ret = wcrypto_do_cipher(ctx, &copdata, tag);
			if (ret == -WD_EBUSY) {
				usleep(SEND_USLEEP * try_cnt);
				try_cnt++;
				if (try_cnt > MAX_TRY_CNT) {
					SEC_TST_PRT("Test cipher send fail %d times!\n", MAX_TRY_CNT);
					try_cnt = 0;
				}
				continue;
			}

			count++;
			try_cnt = 0;
			i = count % MAX_BLOCK_NM;
			copdata.in = res_in[i];
			copdata.out   = res_out[i];
			copdata.iv = res_iv[i];

			// no-sva data copy from uadk to user
			memcpy(out_data_buf, copdata.out, g_pktlen);
		}
		wcrypto_del_cipher_ctx(ctx);

		break;
	case AEAD_TYPE: // just ccm and gcm
		aead_setup.calg = pdata->alg;
		aead_setup.cmode = pdata->mode;
		aead_setup.br.alloc = (void *)wd_alloc_blk;
		aead_setup.br.free = (void *)wd_free_blk;
		aead_setup.br.iova_map = (void *)wd_blk_iova_map;
		aead_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		aead_setup.br.get_bufsize = (void *)wd_blksize;
		aead_setup.br.usr = pool;

		ctx = wcrypto_create_aead_ctx(queue, &aead_setup);
		if (!ctx) {
			SEC_TST_PRT("wd create aead ctx fail!\n");
			goto sync_err;
		}

		ret = wcrypto_set_aead_ckey(ctx, (__u8*)priv_key, (__u16)pdata->keysize);
		if (ret) {
			SEC_TST_PRT("wd aead set key fail!\n");
			wcrypto_del_aead_ctx(ctx);
			goto sync_err;
		}

		authsize = 16; //set defaut size
		ret = wcrypto_aead_setauthsize(ctx, authsize);
		if (ret) {
			SEC_TST_PRT("set authsize fail!\n");
			wcrypto_del_aead_ctx(ctx);
			goto sync_err;
		}

		if (queue->capa.priv.direction == 0) {
			aopdata.op_type = WCRYPTO_CIPHER_ENCRYPTION_DIGEST;
			aopdata.out_bytes = g_pktlen + 32; // aad + plen + authsize;
		} else {
			aopdata.op_type = WCRYPTO_CIPHER_DECRYPTION_DIGEST;
			aopdata.out_bytes = g_pktlen + 16; // aad + plen;
		}

		aopdata.assoc_size = 16;
		aopdata.in_bytes = g_pktlen;
		aopdata.out_bytes = g_pktlen;
		aopdata.iv_bytes = pdata->ivsize;
		aopdata.priv = NULL;
		aopdata.out_buf_bytes = g_pktlen * 2;

		aopdata.in = res_in[0];
		aopdata.out   = res_out[0];
		aopdata.iv = res_iv[0];
		usleep(SEND_USLEEP);
		while(1) {
			if (get_run_state() == 0)
				break;

			// no-sva data copy to uadk
			memcpy(aopdata.in, src_data_buf, g_pktlen);

			ret = wcrypto_do_aead(ctx, &aopdata, tag);
			if (ret == -WD_EBUSY) {
				usleep(SEND_USLEEP * try_cnt);
				try_cnt++;
				if (try_cnt > MAX_TRY_CNT) {
					SEC_TST_PRT("Test aead send fail %d times!\n", MAX_TRY_CNT);
					try_cnt = 0;
				}
				continue;
			}

			count++;
			try_cnt = 0;
			i = count % MAX_BLOCK_NM;
			aopdata.in = res_in[i];
			aopdata.out   = res_out[i];
			aopdata.iv = res_iv[i];

			// no-sva data copy from uadk to user
			memcpy(out_data_buf, aopdata.out, g_pktlen);
		}
		wcrypto_del_aead_ctx(ctx);

		break;
	case DIGEST_TYPE:
		digest_setup.alg = pdata->alg;
		digest_setup.mode = pdata->mode;
		digest_setup.br.alloc = (void *)wd_alloc_blk;
		digest_setup.br.free = (void *)wd_free_blk;
		digest_setup.br.iova_map = (void *)wd_blk_iova_map;
		digest_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		digest_setup.br.get_bufsize = (void *)wd_blksize;
		digest_setup.br.usr = pool;

		ctx = wcrypto_create_digest_ctx(queue, &digest_setup);
		if (!ctx) {
			SEC_TST_PRT("wd create digest ctx fail!\n");
			goto sync_err;
		}

		if (digest_setup.mode == WCRYPTO_DIGEST_HMAC) {
			ret = wcrypto_set_digest_key(ctx, (__u8*)priv_key,
							    (__u16)pdata->keysize);
			if (ret) {
				SEC_TST_PRT("wd digest set key fail!\n");
				wcrypto_del_digest_ctx(ctx);
				goto sync_err;
			}
		}

		dopdata.in_bytes = g_pktlen;
		dopdata.out_bytes = 16;
		dopdata.has_next = 0;
		dopdata.priv = NULL;

		dopdata.in = res_in[0];
		dopdata.out   = res_out[0];
		usleep(SEND_USLEEP);
		while(1) {
			if (get_run_state() == 0)
				break;

			// no-sva data copy to uadk
			memcpy(dopdata.in, src_data_buf, g_pktlen);

			ret = wcrypto_do_digest(ctx, &dopdata, (void *)tag);
			if (ret == -WD_EBUSY) {
				usleep(SEND_USLEEP * try_cnt);
				try_cnt++;
				if (try_cnt > MAX_TRY_CNT) {
					SEC_TST_PRT("Test digest send fail %d times!\n", MAX_TRY_CNT);
					try_cnt = 0;
				}
				continue;
			}

			count++;
			try_cnt = 0;
			i = count % MAX_BLOCK_NM;
			dopdata.in = res_in[i];
			dopdata.out = res_out[i];

			// no-sva data copy from uadk to user
			memcpy(out_data_buf, dopdata.out, 16);
		}
		wcrypto_del_digest_ctx(ctx);
		break;
	}

	add_recv_data(count);

sync_err:
	free(src_data_buf);
	free(out_data_buf);
	return NULL;
}

int sec_wd_sync_threads(struct acc_option *options)
{
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = sec_wd_param_parse(&threads_option, options);
	if (ret)
		return ret;

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].alg = threads_option.alg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].keysize = threads_option.keysize;
		threads_args[i].ivsize = threads_option.ivsize;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, sec_wd_sync_run, &threads_args[i]);
		if (ret) {
			SEC_TST_PRT("Create sync thread fail!\n");
			goto sync_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sync thread fail!\n");
			goto sync_error;
		}
	}

sync_error:
	return ret;
}

int sec_wd_async_threads(struct acc_option *options)
{
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = sec_wd_param_parse(&threads_option, options);
	if (ret)
		return ret;

	/* poll thread */
	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].td_id = i;
		ret = pthread_create(&pollid[i], NULL, sec_wd_poll, &threads_args[i]);
		if (ret) {
			SEC_TST_PRT("Create poll thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].alg = threads_option.alg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].keysize = threads_option.keysize;
		threads_args[i].ivsize = threads_option.ivsize;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, sec_wd_async_run, &threads_args[i]);
		if (ret) {
			SEC_TST_PRT("Create async thread fail!\n");
			goto async_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join async thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join poll thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

int sec_wd_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;
	g_pktlen = options->pktlen;
	g_ctxnum = options->ctxnums;
	if (options->optype > WCRYPTO_CIPHER_DECRYPTION) {
		SEC_TST_PRT("SEC optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_wd_queue(options);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = sec_wd_async_threads(options);
	else
		ret = sec_wd_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	uninit_wd_queue();

	return 0;
}
