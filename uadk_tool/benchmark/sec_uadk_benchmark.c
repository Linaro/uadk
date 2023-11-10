/* SPDX-License-Identifier: Apache-2.0 */

#include <numa.h>
#include "uadk_benchmark.h"

#include "sec_uadk_benchmark.h"
#include "include/wd_cipher.h"
#include "include/wd_digest.h"
#include "include/wd_aead.h"
#include "include/wd_sched.h"

#define SEC_TST_PRT printf
#define MAX_IVK_LENTH		64
#define DEF_IVK_DATA		0xAA
#define SEC_AEAD_LEN		16
#define SEC_PERF_KEY_LEN		16
#define SEC_MAX_MAC_LEN		64
#define SEC_SAVE_FILE_LEN	64
#define SEC_PERF_AUTH_SIZE	16

char aead_key[] = "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
		  "\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf";

char aead_aad[] = "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
		  "\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf";
char g_save_mac[SEC_MAX_MAC_LEN];

struct uadk_bd {
	u8 *src;
	u8 *dst;
};

struct bd_pool {
	struct uadk_bd *bds;
};

struct thread_pool {
	struct bd_pool *pool;
	u8 **iv;
	u8 **key;
	u8 **mac;
	u8 **hash;
} g_uadk_pool;

typedef struct uadk_thread_res {
	u32 subtype;
	u32 alg;
	u32 mode;
	u32 keysize;
	u32 ivsize;
	u32 optype;
	u32 td_id;
	bool is_union;
	u32 dalg;
	u32 dmode;
} thread_data;

static struct wd_ctx_config g_ctx_cfg;
static struct wd_sched *g_sched;
static unsigned int g_thread_num;
static unsigned int g_ctxnum;
static unsigned int g_prefetch;
static unsigned int g_pktlen;
static unsigned int g_alg;
static unsigned int g_algtype;
static unsigned int g_optype;
static unsigned int g_maclen;

struct aead_alg_info {
	int index;
	char *name;
	unsigned int mac_len;
};

struct aead_alg_info aead_info[] = {
	{
		.index = AES_128_CCM,
		.name = "AES_128_CCM",
		.mac_len = 16,
	}, {
		.index = AES_128_GCM,
		.name = "AES_128_GCM",
		.mac_len = 16,
	}, {
		.index = AES_128_CBC_SHA256_HMAC,
		.name = "AES_128_CBC_SHA256_HMAC",
		.mac_len = 32,
	}, {
		.index = SM4_128_GCM,
		.name = "SM4_128_GCM",
		.mac_len = 16,
	}, {
		.index = SM4_128_CCM,
		.name = "SM4_128_CCM",
		.mac_len = 16,
	},
};

static u32 get_aead_mac_len(int algtype)
{
	int table_size = sizeof(aead_info) / sizeof(aead_info[0]);
	int i;

	for (i = 0; i < table_size; i++) {
		if (algtype == aead_info[i].index)
			return aead_info[i].mac_len;
	}

	SEC_TST_PRT("failed to get the aead mac len\n");

	return -1;
}

static char *get_aead_alg_name(int algtype)
{
	int table_size = sizeof(aead_info) / sizeof(aead_info[0]);
	int i;

	for (i = 0; i < table_size; i++) {
		if (algtype == aead_info[i].index)
			return aead_info[i].name;
	}

	SEC_TST_PRT("failed to get the aead alg name\n");

	return NULL;
}

static void *cipher_async_cb(struct wd_cipher_req *req, void *data)
{
	return NULL;
}

static void *aead_async_cb(struct wd_aead_req *req, void *data)
{
	return NULL;
}

static void *digest_async_cb(void *data)
{
	return NULL;
}

static int sec_uadk_param_parse(thread_data *tddata, struct acc_option *options)
{
	u32 algtype = options->algtype;
	u32 optype = options->optype;
	bool is_union = false;
	u8 keysize = 0;
	u8 ivsize = 0;
	u8 dmode;
	u8 dalg;
	u8 mode;
	u8 alg;

	switch(algtype) {
	case AES_128_ECB:
		keysize = 16;
		ivsize = 0;
		mode = WD_CIPHER_ECB;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_ECB:
		keysize = 24;
		ivsize = 0;
		mode = WD_CIPHER_ECB;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_ECB:
		keysize = 32;
		ivsize = 0;
		mode = WD_CIPHER_ECB;
		alg = WD_CIPHER_AES;
		break;
	case AES_128_CBC:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_CBC:
		keysize = 24;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_CBC:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_AES;
		break;
	case AES_128_CTR:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CTR;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_CTR:
		keysize = 24;
		ivsize = 16;
		mode = WD_CIPHER_CTR;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_CTR:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_CTR;
		alg = WD_CIPHER_AES;
		break;
	case AES_128_OFB:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_OFB;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_OFB:
		keysize = 24;
		ivsize = 16;
		mode = WD_CIPHER_OFB;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_OFB:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_OFB;
		alg = WD_CIPHER_AES;
		break;
	case AES_128_CFB:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CFB;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_CFB:
		keysize = 24;
		ivsize = 16;
		mode = WD_CIPHER_CFB;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_CFB:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_CFB;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_XTS:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_XTS;
		alg = WD_CIPHER_AES;
		break;
	case AES_512_XTS:
		keysize = 64;
		ivsize = 16;
		mode = WD_CIPHER_XTS;
		alg = WD_CIPHER_AES;
		break;
	case DES3_128_ECB:
		keysize = 16;
		ivsize = 0;
		mode = WD_CIPHER_ECB;
		alg = WD_CIPHER_3DES;
		break;
	case DES3_192_ECB:
		keysize = 24;
		ivsize = 0;
		mode = WD_CIPHER_ECB;
		alg = WD_CIPHER_3DES;
		break;
	case DES3_128_CBC:
		keysize = 16;
		ivsize = 8;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_3DES;
		break;
	case DES3_192_CBC:
		keysize = 24;
		ivsize = 8;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_3DES;
		break;
	case SM4_128_ECB:
		keysize = 16;
		ivsize = 0;
		mode = WD_CIPHER_ECB;
		alg = WD_CIPHER_SM4;
		break;
	case SM4_128_CBC:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_SM4;
		break;
	case SM4_128_CTR:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CTR;
		alg = WD_CIPHER_SM4;
		break;
	case SM4_128_OFB:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_OFB;
		alg = WD_CIPHER_SM4;
		break;
	case SM4_128_CFB:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CFB;
		alg = WD_CIPHER_SM4;
		break;
	case SM4_128_XTS:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_XTS;
		alg = WD_CIPHER_SM4;
		break;
	case AES_128_CCM:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CCM;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_CCM:
		keysize = 24;
		ivsize = 16;
		mode = WD_CIPHER_CCM;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_CCM:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_CCM;
		alg = WD_CIPHER_AES;
		break;
	case AES_128_GCM:
		keysize = 16;
		ivsize = 12;
		mode = WD_CIPHER_GCM;
		alg = WD_CIPHER_AES;
		break;
	case AES_192_GCM:
		keysize = 24;
		ivsize = 12;
		mode = WD_CIPHER_GCM;
		alg = WD_CIPHER_AES;
		break;
	case AES_256_GCM:
		keysize = 32;
		ivsize = 12;
		mode = WD_CIPHER_GCM;
		alg = WD_CIPHER_AES;
		break;
	case AES_128_CBC_SHA256_HMAC:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_AES;
		is_union = true;
		dalg = WD_DIGEST_SHA256;
		dmode = WD_DIGEST_HMAC;
		break;
	case AES_192_CBC_SHA256_HMAC:
		keysize = 24;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_AES;
		is_union = true;
		dalg = WD_DIGEST_SHA256;
		dmode = WD_DIGEST_HMAC;
		break;
	case AES_256_CBC_SHA256_HMAC:
		keysize = 32;
		ivsize = 16;
		mode = WD_CIPHER_CBC;
		alg = WD_CIPHER_AES;
		is_union = true;
		dalg = WD_DIGEST_SHA256;
		dmode = WD_DIGEST_HMAC;
		break;
	case SM4_128_CCM:
		keysize = 16;
		ivsize = 16;
		mode = WD_CIPHER_CCM;
		alg = WD_CIPHER_SM4;
		break;
	case SM4_128_GCM:
		keysize = 16;
		ivsize = 12;
		mode = WD_CIPHER_GCM;
		alg = WD_CIPHER_SM4;
		break;
	case SM3_ALG:		// digest mode is optype
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SM3;
		break;
	case MD5_ALG:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_MD5;
		break;
	case SHA1_ALG:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA1;
		break;
	case SHA256_ALG:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA256;
		break;
	case SHA224_ALG:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA224;
		break;
	case SHA384_ALG:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA384;
		break;
	case SHA512_ALG:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA512;
		break;
	case SHA512_224:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA512_224;
		break;
	case SHA512_256:
		keysize = 4;
		mode = optype;
		alg = WD_DIGEST_SHA512_256;
		break;
	default:
		SEC_TST_PRT("failed to set sec alg\n");
		return -EINVAL;
	}

	tddata->alg = alg;
	tddata->mode = mode;
	tddata->dalg = dalg;
	tddata->dmode = dmode;
	tddata->ivsize = ivsize;
	tddata->keysize = keysize;
	tddata->is_union = is_union;
	tddata->optype = options->optype;
	tddata->subtype = options->subtype;

	return 0;
}

static int init_ctx_config(char *alg, int subtype, int mode)
{
	struct sched_params param;
	struct uacce_dev *dev = NULL;
	int ret, max_node, i;

	max_node = numa_max_node() + 1;
	if (max_node <= 0)
		return -EINVAL;

	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = g_ctxnum;
	g_ctx_cfg.ctxs = calloc(g_ctxnum, sizeof(struct wd_ctx));
	if (!g_ctx_cfg.ctxs)
		return -ENOMEM;

	i = 0;
	while (i < g_ctxnum) {
		dev = wd_get_accel_dev(alg);
		if (!dev) {
			SEC_TST_PRT("failed to get %s device\n", alg);
			goto out;
		}

		for (; i < g_ctxnum; i++) {
			g_ctx_cfg.ctxs[i].ctx = wd_request_ctx(dev);
			if (!g_ctx_cfg.ctxs[i].ctx)
				break;

			g_ctx_cfg.ctxs[i].op_type = 0; // default op_type
			g_ctx_cfg.ctxs[i].ctx_mode = (__u8)mode;
		}

		free(dev);
	}

	switch(subtype) {
	case CIPHER_TYPE:
		g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1, max_node, wd_cipher_poll_ctx);
		break;
	case AEAD_TYPE:
		g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1, max_node, wd_aead_poll_ctx);
		break;
	case DIGEST_TYPE:
		g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1, max_node, wd_digest_poll_ctx);
		break;
	default:
		SEC_TST_PRT("failed to parse alg subtype!\n");
		return -EINVAL;
	}
	if (!g_sched) {
		SEC_TST_PRT("failed to alloc sched!\n");
		goto out;
	}

	g_sched->name = SCHED_SINGLE;
	param.numa_id = 0;
	param.type = 0;
	param.mode = mode;
	param.begin = 0;
	param.end = g_ctxnum - 1;
	ret = wd_sched_rr_instance(g_sched, &param);
	if (ret) {
		SEC_TST_PRT("failed to fill sched data!\n");
		goto out;
	}

	/* init */
	switch(subtype) {
	case CIPHER_TYPE:
		ret = wd_cipher_init(&g_ctx_cfg, g_sched);
		break;
	case AEAD_TYPE:
		ret = wd_aead_init(&g_ctx_cfg, g_sched);
		break;
	case DIGEST_TYPE:
		ret = wd_digest_init(&g_ctx_cfg, g_sched);
		break;
	}
	if (ret) {
		SEC_TST_PRT("failed to cipher ctx!\n");
		goto out;
	}

	return 0;

out:
	for (i--; i >= 0; i--)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);

	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);

	return ret;
}

static void uninit_ctx_config(int subtype)
{
	int i;

	/* uninit */
	switch(subtype) {
	case CIPHER_TYPE:
		wd_cipher_uninit();
		break;
	case AEAD_TYPE:
		wd_aead_uninit();
		break;
	case DIGEST_TYPE:
		wd_digest_uninit();
		break;
	default:
		SEC_TST_PRT("failed to parse alg subtype on uninit!\n");
		return;
	}

	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);
}

static void get_aead_data(u8 *addr, u32 size)
{
	memset(addr, 0, size);
	memcpy(addr, aead_aad, SEC_AEAD_LEN);
}

static void save_aead_dst_data(u8 *addr, u32 size)
{
	char file_name[SEC_SAVE_FILE_LEN] = {0};
	char *alg_name;
	FILE *fp;

	alg_name = get_aead_alg_name(g_algtype);
	if (!alg_name) {
		SEC_TST_PRT("failed to get the aead alg name!\n");
		return;
	}

	snprintf(file_name, SEC_SAVE_FILE_LEN, "ctext_%s_%u", alg_name, g_pktlen);

	fp = fopen(file_name, "w");
	if (!fp) {
		SEC_TST_PRT("failed to open the ctext file!\n");
		return;
	}

	memcpy(addr + size, g_uadk_pool.mac[0], SEC_PERF_AUTH_SIZE);

	for (int i = 0; i < size + SEC_PERF_AUTH_SIZE; i++)
		fputc((char)addr[i], fp);

	fclose(fp);
}

static void read_aead_dst_data(u8 *addr, u32 len)
{
	char file_name[SEC_SAVE_FILE_LEN] = {0};
	char *alg_name;
	FILE *fp;
	int size;

	alg_name = get_aead_alg_name(g_algtype);
	if (!alg_name) {
		SEC_TST_PRT("failed to get the aead alg name!\n");
		return;
	}

	snprintf(file_name, SEC_SAVE_FILE_LEN, "ctext_%s_%u", alg_name, g_pktlen);

	fp = fopen(file_name, "r");
	if (!fp) {
		SEC_TST_PRT("failed to open the ctext file!\n");
		return;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);

	rewind(fp);
	size = fread(addr, 1, size, fp);
	addr[size] = '\0';

	memcpy(g_save_mac, (char *)addr + len, SEC_MAX_MAC_LEN);

	fclose(fp);
}

static int init_ivkey_source(void)
{
	int i, j, k, m, idx;

	g_uadk_pool.iv = malloc(sizeof(char *) * g_thread_num);
	for (i = 0; i < g_thread_num; i++) {
		g_uadk_pool.iv[i] = calloc(MAX_IVK_LENTH, sizeof(char));
		if (!g_uadk_pool.iv[i])
			goto free_iv;
	}

	g_uadk_pool.key = malloc(sizeof(char *) * g_thread_num);
	for (j = 0; j < g_thread_num; j++) {
		g_uadk_pool.key[j] = calloc(MAX_IVK_LENTH, sizeof(char));
		if (!g_uadk_pool.key[j])
			goto free_key;

		memcpy(g_uadk_pool.key[j], aead_key, SEC_PERF_KEY_LEN);
	}

	g_uadk_pool.mac = malloc(sizeof(char *) * g_thread_num);
	for (k = 0; k < g_thread_num; k++) {
		g_uadk_pool.mac[k] = calloc(MAX_IVK_LENTH, sizeof(char));
		if (!g_uadk_pool.mac[k])
			goto free_mac;
	}

	g_uadk_pool.hash = malloc(sizeof(char *) * g_thread_num);
	for (m = 0; m < g_thread_num; m++) {
		g_uadk_pool.hash[m] = calloc(MAX_IVK_LENTH, sizeof(char));
		if (!g_uadk_pool.hash[m])
			goto free_hash;

		memcpy(g_uadk_pool.hash[m], aead_key, SEC_PERF_KEY_LEN);
	}

	return 0;

free_hash:
	for (idx = m - 1; idx >= 0; idx--)
		free(g_uadk_pool.hash[idx]);
	free(g_uadk_pool.hash);

free_mac:
	for (idx = k - 1; idx >= 0; idx--)
		free(g_uadk_pool.mac[idx]);

	free(g_uadk_pool.mac);

free_key:
	for (idx = j - 1; idx >= 0; idx--)
		free(g_uadk_pool.key[idx]);

	free(g_uadk_pool.key);
free_iv:
	for (idx = i - 1; idx >= 0; idx--)
		free(g_uadk_pool.iv[idx]);

	free(g_uadk_pool.iv);

	return -1;
}

static void free_ivkey_source(void)
{
	int i;

	for (i = 0; i < g_thread_num; i++) {
		free(g_uadk_pool.hash[i]);
		free(g_uadk_pool.mac[i]);
		free(g_uadk_pool.key[i]);
		free(g_uadk_pool.iv[i]);
	}

	free(g_uadk_pool.hash);
	free(g_uadk_pool.mac);
	free(g_uadk_pool.key);
	free(g_uadk_pool.iv);
}

static int init_uadk_bd_pool(void)
{
	unsigned long step;
	int i, j;
	int ret;

	// make the block not align to 4K
	step = sizeof(char) * g_pktlen * 2;

	ret = init_ivkey_source();
	if (ret) {
		SEC_TST_PRT("init uadk ivkey resource failed!\n");
		return -ENOMEM;
	}

	g_uadk_pool.pool = malloc(g_thread_num * sizeof(struct bd_pool));
	if (!g_uadk_pool.pool) {
		SEC_TST_PRT("init uadk pool alloc thread failed!\n");
		goto free_ivkey;
	} else {
		for (i = 0; i < g_thread_num; i++) {
			g_uadk_pool.pool[i].bds = malloc(MAX_POOL_LENTH *
							 sizeof(struct uadk_bd));
			if (!g_uadk_pool.pool[i].bds) {
				SEC_TST_PRT("init uadk bds alloc failed!\n");
				goto malloc_error1;
			}
			for (j = 0; j < MAX_POOL_LENTH; j++) {
				g_uadk_pool.pool[i].bds[j].src = malloc(step);
				if (!g_uadk_pool.pool[i].bds[j].src)
					goto malloc_error2;
				g_uadk_pool.pool[i].bds[j].dst = malloc(step);
				if (!g_uadk_pool.pool[i].bds[j].dst)
					goto malloc_error3;

				if (g_alg != AEAD_TYPE) {
					get_rand_data(g_uadk_pool.pool[i].bds[j].src, g_pktlen);
					if (g_prefetch)
						get_rand_data(g_uadk_pool.pool[i].bds[j].dst,
							      g_pktlen);
				} else {
					if (!g_optype)
						get_aead_data(g_uadk_pool.pool[i].bds[j].src,
							      g_pktlen + SEC_AEAD_LEN);
					else
						read_aead_dst_data(g_uadk_pool.pool[i].bds[j].src,
								   g_pktlen + SEC_AEAD_LEN);
				}
			}

			if (g_alg == AEAD_TYPE && g_optype)
				memcpy(g_uadk_pool.mac[i], g_save_mac, SEC_MAX_MAC_LEN);
		}
	}

	return 0;

malloc_error3:
	free(g_uadk_pool.pool[i].bds[j].src);
malloc_error2:
	for (j--; j >= 0; j--) {
		free(g_uadk_pool.pool[i].bds[j].src);
		free(g_uadk_pool.pool[i].bds[j].dst);
	}
malloc_error1:
	for (i--; i >= 0; i--) {
		for (j = 0; j < MAX_POOL_LENTH; j++) {
			free(g_uadk_pool.pool[i].bds[j].src);
			free(g_uadk_pool.pool[i].bds[j].dst);
		}
		free(g_uadk_pool.pool[i].bds);
		g_uadk_pool.pool[i].bds = NULL;
	}
	free(g_uadk_pool.pool);
	g_uadk_pool.pool = NULL;

free_ivkey:
	free_ivkey_source();

	SEC_TST_PRT("init uadk bd pool alloc failed!\n");
	return -ENOMEM;
}

static void free_uadk_bd_pool(void)
{
	int i, j;

	/* save aad + ctext + mac */
	if (g_alg == AEAD_TYPE && !g_optype)
		save_aead_dst_data(g_uadk_pool.pool[0].bds[0].dst,
				   g_pktlen + SEC_AEAD_LEN);

	for (i = 0; i < g_thread_num; i++) {
		if (g_uadk_pool.pool[i].bds) {
			for (j = 0; j < MAX_POOL_LENTH; j++) {
				free(g_uadk_pool.pool[i].bds[j].src);
				free(g_uadk_pool.pool[i].bds[j].dst);
			}
		}
		free(g_uadk_pool.pool[i].bds);
		g_uadk_pool.pool[i].bds = NULL;
	}
	free(g_uadk_pool.pool);
	g_uadk_pool.pool = NULL;

	free_ivkey_source();
}

/*-------------------------------uadk benchmark main code-------------------------------------*/

static void *sec_uadk_poll(void *data)
{
	typedef int (*poll_ctx)(__u32 idx, __u32 expt, __u32 *count);
	poll_ctx uadk_poll_ctx = NULL;
	thread_data *pdata = (thread_data *)data;
	u32 expt = ACC_QUEUE_SIZE * g_thread_num;
	u32 id = pdata->td_id;
	u32 last_time = 2; // poll need one more recv time
	u32 count = 0;
	u32 recv = 0;
	int  ret;

	if (id > g_ctxnum)
		return NULL;

	switch(pdata->subtype) {
	case CIPHER_TYPE:
		uadk_poll_ctx = wd_cipher_poll_ctx;
		break;
	case AEAD_TYPE:
		uadk_poll_ctx = wd_aead_poll_ctx;
		break;
	case DIGEST_TYPE:
		uadk_poll_ctx = wd_digest_poll_ctx;
		break;
	default:
		SEC_TST_PRT("<<<<<<async poll interface is NULL!\n");
		return NULL;
	}

	while (last_time) {
		ret = uadk_poll_ctx(id, expt, &recv);
		count += recv;
		recv = 0;
		if (unlikely(ret != -WD_EAGAIN && ret < 0)) {
			SEC_TST_PRT("poll ret: %u!\n", ret);
			goto recv_error;
		}

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *sec_uadk_cipher_async(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_cipher_sess_setup cipher_setup = {0};
	struct wd_cipher_req creq;
	struct bd_pool *uadk_pool;
	u8 *priv_iv, *priv_key;
	int try_cnt = 0;
	handle_t h_sess;
	u32 count = 0;
	int ret, i;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_uadk_pool.pool[pdata->td_id];
	priv_iv = g_uadk_pool.iv[pdata->td_id];
	priv_key = g_uadk_pool.key[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	cipher_setup.alg = pdata->alg;
	cipher_setup.mode = pdata->mode;
	h_sess = wd_cipher_alloc_sess(&cipher_setup);
	if (!h_sess)
		return NULL;
	ret = wd_cipher_set_key(h_sess, (const __u8*)priv_key, pdata->keysize);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		wd_cipher_free_sess(h_sess);
		return NULL;
	}

	creq.op_type = pdata->optype;
	creq.iv = priv_iv;
	creq.iv_bytes = pdata->ivsize;
	creq.in_bytes = g_pktlen;
	creq.out_bytes = g_pktlen;
	creq.out_buf_bytes = g_pktlen;
	creq.data_fmt = 0;
	creq.state = 0;
	creq.cb = cipher_async_cb;

	while(1) {
		if (get_run_state() == 0)
			break;
		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = uadk_pool->bds[i].dst;

		ret = wd_do_cipher_async(h_sess, &creq);
		if (ret < 0) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				SEC_TST_PRT("Test cipher send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		}
		count++;
	}
	wd_cipher_free_sess(h_sess);

	add_send_complete();

	return NULL;
}

static void *sec_uadk_aead_async(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_aead_sess_setup aead_setup = {0};
	u8 *priv_iv, *priv_key, *priv_mac, *priv_hash;
	u32 auth_size = SEC_PERF_AUTH_SIZE;
	struct wd_aead_req areq;
	struct bd_pool *uadk_pool;
	int try_cnt = 0;
	handle_t h_sess;
	u32 count = 0;
	int ret, i;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_uadk_pool.pool[pdata->td_id];
	priv_iv = g_uadk_pool.iv[pdata->td_id];
	priv_key = g_uadk_pool.key[pdata->td_id];
	priv_mac = g_uadk_pool.mac[pdata->td_id];
	priv_hash = g_uadk_pool.hash[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	aead_setup.calg = pdata->alg;
	aead_setup.cmode = pdata->mode;
	if (pdata->is_union) {
		aead_setup.dalg = pdata->dalg;
		aead_setup.dmode = pdata->dmode;
	}
	h_sess = wd_aead_alloc_sess(&aead_setup);
	if (!h_sess)
		return NULL;
	ret = wd_aead_set_ckey(h_sess, (const __u8*)priv_key, pdata->keysize);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		wd_aead_free_sess(h_sess);
		return NULL;
	}
	if (pdata->is_union) {
		ret = wd_aead_set_akey(h_sess, (const __u8*)priv_hash, HASH_ZISE);
		if (ret) {
			SEC_TST_PRT("test sec aead set akey is failed!\n");
			wd_aead_free_sess(h_sess);
			return NULL;
		}
	}
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: 16\n");
		wd_aead_free_sess(h_sess);
		return NULL;
	}

	areq.op_type = pdata->optype;
	areq.iv = priv_iv; // aead IV need update with param
	areq.mac = priv_mac;
	areq.iv_bytes = pdata->ivsize;
	areq.mac_bytes = auth_size;
	areq.assoc_bytes = SEC_AEAD_LEN;
	areq.in_bytes = g_pktlen;
	if (pdata->is_union)
		areq.mac_bytes = 32;
	if (areq.op_type) // decrypto
		areq.out_bytes = g_pktlen + 16; // aadsize = 16;
	else
		areq.out_bytes = g_pktlen + 32; // aadsize + authsize = 32;

	areq.data_fmt = 0;
	areq.state = 0;
	areq.cb = aead_async_cb;

	while(1) {
		if (get_run_state() == 0)
			break;
		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		areq.src = uadk_pool->bds[i].src;
		areq.dst = uadk_pool->bds[i].dst;

		ret = wd_do_aead_async(h_sess, &areq);
		if (ret < 0) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				SEC_TST_PRT("Test aead send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		}
		count++;
	}
	wd_aead_free_sess(h_sess);

	add_send_complete();

	return NULL;
}

static void *sec_uadk_digest_async(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_digest_sess_setup digest_setup = {0};
	struct wd_digest_req dreq;
	struct bd_pool *uadk_pool;
	u8 *priv_iv, *priv_key;
	int try_cnt = 0;
	handle_t h_sess;
	u32 count = 0;
	int ret, i;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_uadk_pool.pool[pdata->td_id];
	priv_iv = g_uadk_pool.iv[pdata->td_id];
	priv_key = g_uadk_pool.key[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	digest_setup.alg = pdata->alg;
	digest_setup.mode = pdata->mode; // digest mode is optype
	h_sess = wd_digest_alloc_sess(&digest_setup);
	if (!h_sess)
		return NULL;
	if (digest_setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8*)priv_key, 4);
		if (ret) {
			SEC_TST_PRT("test sec digest set key is failed!\n");
			wd_digest_free_sess(h_sess);
			return NULL;
		}
	}
	dreq.in_bytes = g_pktlen;
	dreq.out_bytes = 16;
	dreq.out_buf_bytes = 16;
	dreq.data_fmt = 0;
	dreq.state = 0;
	dreq.has_next = 0;
	dreq.cb = digest_async_cb;

	while(1) {
		if (get_run_state() == 0)
			break;
		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		dreq.in = uadk_pool->bds[i].src;
		dreq.out = uadk_pool->bds[i].dst;

		ret = wd_do_digest_async(h_sess, &dreq);
		if (ret < 0) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				SEC_TST_PRT("Test digest send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		}
		count++;
	}
	wd_digest_free_sess(h_sess);

	add_send_complete();

	return NULL;
}

static void *sec_uadk_cipher_sync(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_cipher_sess_setup cipher_setup = {0};
	struct wd_cipher_req creq;
	struct bd_pool *uadk_pool;
	u8 *priv_iv, *priv_key;
	handle_t h_sess;
	u32 count = 0;
	int ret, i;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_uadk_pool.pool[pdata->td_id];
	priv_iv = g_uadk_pool.iv[pdata->td_id];
	priv_key = g_uadk_pool.key[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	cipher_setup.alg = pdata->alg;
	cipher_setup.mode = pdata->mode;
	h_sess = wd_cipher_alloc_sess(&cipher_setup);
	if (!h_sess)
		return NULL;
	ret = wd_cipher_set_key(h_sess, (const __u8*)priv_key, pdata->keysize);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		wd_cipher_free_sess(h_sess);
		return NULL;
	}

	creq.op_type = pdata->optype;
	creq.iv = priv_iv;
	creq.iv_bytes = pdata->ivsize;
	creq.in_bytes = g_pktlen;
	creq.out_bytes = g_pktlen;
	creq.out_buf_bytes = g_pktlen;
	creq.data_fmt = 0;
	creq.state = 0;

	while(1) {
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = uadk_pool->bds[i].dst;
		ret = wd_do_cipher_sync(h_sess, &creq);
		if ((ret < 0 && ret != -WD_EBUSY) || creq.state)
			break;
		count++;
		if (get_run_state() == 0)
			break;
	}
	wd_cipher_free_sess(h_sess);

	cal_avg_latency(count);
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *sec_uadk_aead_sync(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_aead_sess_setup aead_setup = {0};
	u8 *priv_iv, *priv_key, *priv_mac, *priv_hash;
	u32 auth_size = SEC_PERF_AUTH_SIZE;
	struct wd_aead_req areq;
	struct bd_pool *uadk_pool;
	handle_t h_sess;
	u32 count = 0;
	int ret, i;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_uadk_pool.pool[pdata->td_id];

	priv_iv = g_uadk_pool.iv[pdata->td_id];
	priv_key = g_uadk_pool.key[pdata->td_id];
	priv_mac = g_uadk_pool.mac[pdata->td_id];
	priv_hash = g_uadk_pool.hash[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	aead_setup.calg = pdata->alg;
	aead_setup.cmode = pdata->mode;
	if (pdata->is_union) {
		aead_setup.dalg = WD_DIGEST_SHA256;
		aead_setup.dmode = WD_DIGEST_HMAC;
	}
	h_sess = wd_aead_alloc_sess(&aead_setup);
	if (!h_sess)
		return NULL;
	ret = wd_aead_set_ckey(h_sess, (const __u8*)priv_key, pdata->keysize);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		wd_aead_free_sess(h_sess);
		return NULL;
	}
	if (pdata->is_union) {
		ret = wd_aead_set_akey(h_sess, (const __u8*)priv_hash, HASH_ZISE);
		if (ret) {
			SEC_TST_PRT("test sec aead set akey is failed!\n");
			wd_aead_free_sess(h_sess);
			return NULL;
		}
	}
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: 16\n");
		wd_aead_free_sess(h_sess);
		return NULL;
	}

	areq.op_type = pdata->optype;
	areq.iv = priv_iv; // aead IV need update with param
	areq.mac = priv_mac;
	areq.iv_bytes = pdata->ivsize;
	areq.assoc_bytes = SEC_AEAD_LEN;
	areq.in_bytes = g_pktlen;
	areq.mac_bytes = g_maclen;
	if (areq.op_type) // decrypto
		areq.out_bytes = g_pktlen + 16; // aadsize = 16;
	else
		areq.out_bytes = g_pktlen + 32; // aadsize + authsize = 32;

	areq.data_fmt = 0;
	areq.state = 0;

	while(1) {
		i = count % MAX_POOL_LENTH;
		areq.src = uadk_pool->bds[i].src;
		areq.dst = uadk_pool->bds[i].dst;
		count++;

		ret = wd_do_aead_sync(h_sess, &areq);
		if (ret || areq.state)
			break;
		if (get_run_state() == 0)
			break;
	}
	wd_aead_free_sess(h_sess);

	cal_avg_latency(count);
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *sec_uadk_digest_sync(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_digest_sess_setup digest_setup = {0};
	struct wd_digest_req dreq;
	struct bd_pool *uadk_pool;
	u8 *priv_iv, *priv_key;
	handle_t h_sess;
	u32 count = 0;
	int ret, i;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_uadk_pool.pool[pdata->td_id];
	priv_iv = g_uadk_pool.iv[pdata->td_id];
	priv_key = g_uadk_pool.key[pdata->td_id];

	memset(priv_iv, DEF_IVK_DATA, MAX_IVK_LENTH);
	memset(priv_key, DEF_IVK_DATA, MAX_IVK_LENTH);

	digest_setup.alg = pdata->alg;
	digest_setup.mode = pdata->mode; // digest mode is optype
	h_sess = wd_digest_alloc_sess(&digest_setup);
	if (!h_sess)
		return NULL;
	if (digest_setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8*)priv_key, 4);
		if (ret) {
			SEC_TST_PRT("test sec digest set key is failed!\n");
			wd_digest_free_sess(h_sess);
			return NULL;
		}
	}
	dreq.in_bytes = g_pktlen;
	dreq.out_bytes = 16;
	dreq.out_buf_bytes = 16;
	dreq.data_fmt = 0;
	dreq.state = 0;
	dreq.has_next = 0;

	while(1) {
		i = count % MAX_POOL_LENTH;
		dreq.in = uadk_pool->bds[i].src;
		dreq.out = uadk_pool->bds[i].dst;
		ret = wd_do_digest_sync(h_sess, &dreq);
		if (ret || dreq.state)
			break;
		count++;
		if (get_run_state() == 0)
			break;
	}
	wd_digest_free_sess(h_sess);

	cal_avg_latency(count);
	add_recv_data(count, g_pktlen);

	return NULL;
}

int sec_uadk_sync_threads(struct acc_option *options)
{
	typedef void *(*sec_sync_run)(void *arg);
	sec_sync_run uadk_sec_sync_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = sec_uadk_param_parse(&threads_option, options);
	if (ret)
		return ret;

	switch (options->subtype) {
	case CIPHER_TYPE:
		uadk_sec_sync_run = sec_uadk_cipher_sync;
		break;
	case AEAD_TYPE:
		uadk_sec_sync_run = sec_uadk_aead_sync;
		break;
	case DIGEST_TYPE:
		uadk_sec_sync_run = sec_uadk_digest_sync;
		break;
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].alg = threads_option.alg;
		threads_args[i].dalg = threads_option.dalg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].is_union = threads_option.is_union;
		threads_args[i].keysize = threads_option.keysize;
		threads_args[i].ivsize = threads_option.ivsize;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, uadk_sec_sync_run, &threads_args[i]);
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

int sec_uadk_async_threads(struct acc_option *options)
{
	typedef void *(*sec_async_run)(void *arg);
	sec_async_run uadk_sec_async_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = sec_uadk_param_parse(&threads_option, options);
	if (ret)
		return ret;

	switch (options->subtype) {
	case CIPHER_TYPE:
		uadk_sec_async_run = sec_uadk_cipher_async;
		break;
	case AEAD_TYPE:
		uadk_sec_async_run = sec_uadk_aead_async;
		break;
	case DIGEST_TYPE:
		uadk_sec_async_run = sec_uadk_digest_async;
		break;
	}

	for (i = 0; i < g_ctxnum; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].td_id = i;
		/* poll thread */
		ret = pthread_create(&pollid[i], NULL, sec_uadk_poll, &threads_args[i]);
		if (ret) {
			SEC_TST_PRT("Create poll thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].alg = threads_option.alg;
		threads_args[i].dalg = threads_option.dalg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].is_union = threads_option.is_union;
		threads_args[i].keysize = threads_option.keysize;
		threads_args[i].ivsize = threads_option.ivsize;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, uadk_sec_async_run, &threads_args[i]);
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

	for (i = 0; i < g_ctxnum; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join poll thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

int sec_uadk_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;
	g_pktlen = options->pktlen;
	g_ctxnum = options->ctxnums;
	g_prefetch = options->prefetch;
	g_alg = options->subtype;
	g_optype = options->optype;
	g_algtype = options->algtype;

	if (g_alg == AEAD_TYPE) {
		g_maclen = get_aead_mac_len(g_algtype);
		if (g_maclen < 0) {
			SEC_TST_PRT("SEC algtype error: %u\n", g_algtype);
			return -EINVAL;
		}
	}

	if (options->optype > WD_CIPHER_DECRYPTION) {
		SEC_TST_PRT("SEC optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_ctx_config(options->algclass, options->subtype, options->syncmode);
	if (ret)
		return ret;

	ret = init_uadk_bd_pool();
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = sec_uadk_async_threads(options);
	else
		ret = sec_uadk_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	free_uadk_bd_pool();
	uninit_ctx_config(options->subtype);

	return 0;
}
