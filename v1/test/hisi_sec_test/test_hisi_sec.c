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

#include "test_hisi_sec.h"
#include "../../wd.h"
#include "../../wd_cipher.h"
#include "../../wd_aead.h"
#include "../../wd_digest.h"
#include "../../wd_bmm.h"
#include "../../wd_util.h"

#define  SEC_TST_PRT printf
#define TEST_MAX_THRD 128
#define SQE_SIZE 128
#define MAX_BLOCK_SZ	1024
#define MAX_BLOCK_NM	128
#define MAX_ALGO_PER_TYPE 12

typedef unsigned char u8;
typedef unsigned int u32;

static int q_num = 1;
static int ctx_num_per_q = 1;
static long long g_total_perf = 0;
enum alg_class g_algclass = CIPHER_CLASS;
enum cipher_op_type alg_op_type;

pthread_mutex_t perf_mutex;

struct test_sec_pthread_dt {
    int cpu_id;
    enum cipher_op_type op_type;
	int thread_num;
	void *pool;
	void *q;
	struct timeval start_tval;
	u32 send_task_num;
	u32 recv_task_num;
};

struct cipher_async_tag {
	void *ctx;
	int thread_id;
	int cnt;
	struct test_sec_pthread_dt *thread_info;
};

struct digest_async_tag {
	void *ctx;
	int thread_id;
	int cnt;
	struct test_sec_pthread_dt *thread_info;
};

/* OpenSSL Skcipher APIS */
static int t_times = 1000;
static int t_seconds = 0;
static int pktlen = 1024;
static int g_testalg = 0;

static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct  test_sec_pthread_dt test_thrds_data[TEST_MAX_THRD];
static volatile int asyn_thread_exit = 0;
static u32 g_keylen = 16;
static u32 g_ivlen = 16;

char *skcipher_names[MAX_ALGO_PER_TYPE] =
	{"ecb(aes)", "cbc(aes)", "xts(aes)", "ofb(aes)", "cfb(aes)", "ecb(des3_ede)",
	"cbc(des3_ede)", "cbc(sm4)", "xts(sm4)", "ofb(sm4)", "cfb(sm4)", NULL,};
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

static bool is_exit(struct test_sec_pthread_dt *pdata)
{
	struct timeval cur_tval;
	float time_used;

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - pdata->start_tval.tv_usec);
	if (t_seconds)
		return time_used >= t_seconds * t_times;
	else if (t_times)
		return pdata->send_task_num >= t_times;

	return false;
}

void hexdump(char *buf, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		printf("\\%02X", buf[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
	return;
}

int get_resource(struct cipher_testvec **alg_tv, int* alg, int* mode)
{
	struct cipher_testvec *tv;
	int alg_type;
	int mode_type;

	switch (g_testalg) {
		case 0:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_ECB;
			SEC_TST_PRT("test alg: %s\n", "ecb(aes)");
			switch (g_keylen) {
				case AES_KEYSIZE_128:
					tv = &aes_ecb_tv_template_128[0];
					break;
				case AES_KEYSIZE_192:
					tv = &aes_ecb_tv_template_192[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_ecb_tv_template_256[0];
					break;
				default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;
		case 1:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_CBC;
			SEC_TST_PRT("test alg: %s\n", "cbc(aes)");
			switch (g_keylen) {
				case AES_KEYSIZE_128:
					tv = &aes_cbc_tv_template_128[0];
					break;
				case AES_KEYSIZE_192:
					tv = &aes_cbc_tv_template_192[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_cbc_tv_template_256[0];
					break;
				default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;
		case 2:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_XTS;
			SEC_TST_PRT("test alg: %s\n", "xts(aes)");
			switch (g_keylen / 2) {
				case AES_KEYSIZE_128:
					tv = &aes_xts_tv_template_256[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_xts_tv_template_512[0];
					break;
				default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;
		case 3:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_OFB;
			SEC_TST_PRT("test alg: %s\n", "ofb(aes)");
			switch (g_keylen) {
				case AES_KEYSIZE_128:
					tv = &aes_ofb_tv_template_128[0];
					break;
				case AES_KEYSIZE_192:
					tv = &aes_ofb_tv_template_192[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_ofb_tv_template_256[0];
					break;
				default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;
		case 4:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_CFB;
			SEC_TST_PRT("test alg: %s\n", "cfb(aes)");
			switch (g_keylen) {
				case AES_KEYSIZE_128:
					tv = &aes_cfb_tv_template_128[0];
					break;
				case AES_KEYSIZE_192:
					tv = &aes_cfb_tv_template_192[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_cfb_tv_template_256[0];
					break;
				default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;

		case 5:
			alg_type = WCRYPTO_CIPHER_3DES;
			mode_type = WCRYPTO_CIPHER_ECB;
			SEC_TST_PRT("test alg: %s\n", "ecb(des3)");
			if (g_keylen == 16)
				tv = &des3_ecb_tv_template_128[0];
			else if (g_keylen == 24)
				tv = &des3_ecb_tv_template_192[0];
			else {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			break;
		case 6:
			alg_type = WCRYPTO_CIPHER_3DES;
			mode_type = WCRYPTO_CIPHER_CBC;
			SEC_TST_PRT("test alg: %s\n", "cbc(des3)");
			if (g_keylen == 16)
				tv = &des3_cbc_tv_template_128[0];
			else if (g_keylen == 24)
				tv = &des3_cbc_tv_template_192[0];
			else {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			break;
		case 7:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_CBC;
			SEC_TST_PRT("test alg: %s\n", "cbc(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cbc_tv_template[0];
			break;
		case 8:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_XTS;
			SEC_TST_PRT("test alg: %s\n", "xts(sm4)");
			if (g_keylen != 32) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_xts_tv_template[0];
			break;
		case 9:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_OFB;
			SEC_TST_PRT("test alg: %s\n", "ofb(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_ofb_tv_template_128[0];
			break;
		case 10:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_CFB;
			SEC_TST_PRT("test alg: %s\n", "cfb(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cfb_tv_template_128[0];
			break;

		default:
			SEC_TST_PRT("keylenth error, default test alg: %s\n", "ecb(aes)");
			return -EINVAL;
	}
	*alg = alg_type;
	*mode = mode_type;
	*alg_tv = tv;

	return 0;
}

int get_aead_resource(struct aead_testvec **alg_tv,
	int* alg, int* mode, int* dalg, int* dmode)
{
	struct aead_testvec *tv;
	int alg_type = 0;
	int mode_type = 0;
	int dalg_type = 0;
	int dmode_type = 0;

	switch (g_testalg) {
		case 0:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_CCM;
			SEC_TST_PRT("test alg: %s\n", "ccm(aes)");
			switch (g_keylen) {
			        case AES_KEYSIZE_128:
					tv = &aes_ccm_tv_template_128[0];
					break;
			        case AES_KEYSIZE_192:
					tv = &aes_ccm_tv_template_192[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_ccm_tv_template_256[0];
					break;
			        default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;
		case 1:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_GCM;
			SEC_TST_PRT("test alg: %s\n", "gcm(aes)");
			switch (g_keylen) {
			        case AES_KEYSIZE_128:
					tv = &aes_gcm_tv_template_128[0];
					break;
			        case AES_KEYSIZE_192:
					tv = &aes_gcm_tv_template_192[0];
					break;
				case AES_KEYSIZE_256:
					tv = &aes_gcm_tv_template_256[0];
					break;
			        default:
					SEC_TST_PRT("%s: input key err!\n", __func__);
					return -EINVAL;
			}
			break;
		case 2:
			alg_type = WCRYPTO_CIPHER_AES;
			mode_type = WCRYPTO_CIPHER_CBC;
			dalg_type = WCRYPTO_SHA256;
			dmode_type = WCRYPTO_DIGEST_HMAC;
			SEC_TST_PRT("test alg: %s\n", "hmac(sha256),cbc(aes)");
			tv = &hmac_sha256_aes_cbc_tv_temp[0];
			break;
		case 3:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_CCM;
			SEC_TST_PRT("test alg: %s\n", "ccm(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_ccm_tv_template_128[0];
			break;
		case 4:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_GCM;
			SEC_TST_PRT("test alg: %s\n", "gcm(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_gcm_tv_template_128[0];
			break;
		default:
			SEC_TST_PRT("keylenth error, default test alg: %s\n", "ccm(aes)");
			return -EINVAL;
	}
	*alg = alg_type;
	*mode = mode_type;
	*dalg = dalg_type;
	*dmode = dmode_type;
	*alg_tv = tv;

	return 0;
}

int sec_sync_test_set_iv(struct test_sec_pthread_dt *pdata,
                        struct wcrypto_cipher_op_data *opdata, struct cipher_testvec *tv)
{
	int ivlen;

	if (!tv->iv)
		return -1;

	ivlen = strlen(tv->iv);
	if (ivlen != AES_KEYSIZE_128 && ivlen != (AES_KEYSIZE_128 >> 1))
		ivlen = AES_KEYSIZE_128;

	tv->ivlen = ivlen;

	memset(opdata->iv, 0, tv->ivlen);
	memcpy(opdata->iv, tv->iv, tv->ivlen);

	opdata->iv_bytes = tv->ivlen;
	SEC_TST_PRT("dump set input IV! IV lenght:%d\n", ivlen);
	hexdump(opdata->iv, opdata->iv_bytes);

	return 0;
}

int sec_sync_func_test(struct test_sec_pthread_dt *pdata)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct wcrypto_cipher_ctx_setup setup;
	struct wcrypto_cipher_op_data *opdata = malloc(sizeof(struct wcrypto_cipher_op_data));
	struct wd_queue *q = pdata->q;
	struct timeval cur_tval;
	struct cipher_testvec *tv;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	void *tag = NULL;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(opdata, 0, sizeof(struct wcrypto_cipher_op_data));

	setup.alg = WCRYPTO_CIPHER_AES;
	setup.mode = WCRYPTO_CIPHER_CBC;
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pdata->pool;

	ret = get_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);
	if (ret)
		return -EINVAL;

	ctx = wcrypto_create_cipher_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	}
#ifdef DEBUG
	hexdump(tv->key, tv->klen);
#endif
	ret = wcrypto_set_cipher_key(ctx, (__u8*)tv->key, (__u16)tv->klen);
	if (ret) {
		SEC_TST_PRT("set key fail!\n");
		goto fail_release;
	}

	if (q->capa.priv.direction == 0) {
		opdata->op_type = WCRYPTO_CIPHER_ENCRYPTION;
	} else {
		opdata->op_type = WCRYPTO_CIPHER_DECRYPTION;
	}
	opdata->in = wd_alloc_blk(pdata->pool);
	if (!opdata->in) {
		SEC_TST_PRT("alloc in buffer fail!\n");
		goto fail_release;
	}

	memset(opdata->in, 0, tv->len);
	if (q->capa.priv.direction == 0) {
		memcpy(opdata->in, tv->ptext, tv->len);
		if (strlen(tv->ptext) > pktlen) {
			opdata->in_bytes = tv->len;
		} else {
			opdata->in_bytes = pktlen;
		}
	} else {
		memcpy(opdata->in, tv->ctext, tv->len);
		if (strlen(tv->ctext) > pktlen) {
			opdata->in_bytes = tv->len;
		} else {
			opdata->in_bytes = pktlen;
		}
	}

	SEC_TST_PRT("cipher len:%d\n", opdata->in_bytes);
#ifdef DEBUG
	hexdump(opdata->in, opdata->in_bytes);
#endif
	opdata->priv = NULL;
	opdata->out = wd_alloc_blk(pdata->pool);
	if (!opdata->out) {
		SEC_TST_PRT("alloc out buffer fail!\n");
		goto fail_release;
	}
	opdata->out_bytes = opdata->in_bytes;
	//set iv
	opdata->iv = wd_alloc_blk(pdata->pool);
	if (!opdata->iv) {
		SEC_TST_PRT("alloc iv buffer fail!\n");
		goto fail_release;
	}

	sec_sync_test_set_iv(pdata, opdata, tv);
	do {
		ret = wcrypto_do_cipher(ctx, opdata, tag);
		pdata->send_task_num++;
#ifdef DEBUG
		if (pdata->send_task_num == 1) {
			SEC_TST_PRT("dump output!\n");
			hexdump(opdata->out, opdata->out_bytes);
		}
#endif
	} while(!is_exit(pdata));

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, pdata->send_task_num++);
	if (t_seconds) {
		speed = pdata->send_task_num / time_used * 1000000;
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
			     thread_id, speed, Perf);
	} else if (t_times) {
		speed = 1 / (time_used / t_times) * 1000000;
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
			     thread_id, speed, Perf);
	}

fail_release:
	if (opdata->in)
		wd_free_blk(pdata->pool, opdata->in);
	if (opdata->iv)
		wd_free_blk(pdata->pool, opdata->iv);
	if (opdata->out)
		wd_free_blk(pdata->pool, opdata->out);
	if (ctx)
		wcrypto_del_cipher_ctx(ctx);
	free(opdata);

	return ret;
}

int get_digest_resource(struct hash_testvec **alg_tv, int* alg, int* mode)
{
	struct hash_testvec *tmp_tv;
	struct hash_testvec *tv = NULL;
	int alg_type;
	int mode_type;

	switch (g_testalg) {
		case 0:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sm3)");
					tv = &sm3_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sm3)");
					tv = &hmac_sm3_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WCRYPTO_SM3;
			break;
		case 1:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(md5)");
					tv = &md5_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(md5)");
					tv = &hmac_md5_tv_template[0];
					break;
			}
			tv->dsize = 16;
			alg_type = WCRYPTO_MD5;
			break;
		case 2:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha1)");
					tv = &sha1_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha1)");
					tv = &hmac_sha1_tv_template[0];
					break;
			}
			tv->dsize = 20;
			alg_type = WCRYPTO_SHA1;
			break;
		case 3:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha256)");
					tv = &sha256_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha256)");
					tv = &hmac_sha256_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WCRYPTO_SHA256;
			break;
		case 4:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha224)");
					tv = &sha224_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha224)");
					tv = &hmac_sha224_tv_template[0];
					break;
			}
			tv->dsize = 28;
			alg_type = WCRYPTO_SHA224;
			break;
		case 5:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha384)");
					tv = &sha384_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha384)");
					tv = &hmac_sha384_tv_template[0];
					break;
			}
			tv->dsize = 48;
			alg_type = WCRYPTO_SHA384;
			break;
		case 6:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha512)");
					tv = &sha512_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha512)");
					tv = &hmac_sha512_tv_template[0];
					break;
			}
			tv->dsize = 64;
			alg_type = WCRYPTO_SHA512;
			break;
		case 7:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha512_224)");
					tv = &sha512_224_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha512_224");
					tv = &hmac_sha512_224_tv_template[0];
					break;
			}
			tv->dsize = 28;
			alg_type = WCRYPTO_SHA512_224;
			break;
		case 8:
			switch (alg_op_type) {
				case 0:
					mode_type = WCRYPTO_DIGEST_NORMAL;
					SEC_TST_PRT("test alg: %s\n", "normal(sha512_256)");
					tv = &sha512_256_tv_template[0];
					break;
				case 1:
					mode_type = WCRYPTO_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha512_256)");
					tv = &hmac_sha512_256_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WCRYPTO_SHA512_256;
			break;
		default:
			SEC_TST_PRT("keylenth error, default test alg: %s\n", "normal(sm3)");
			return -EINVAL;
	}
	if (g_ivlen == 1) {
		tmp_tv = tv;
		tv = &long_hash_tv_template[0];
		tv->dsize = tmp_tv->dsize;
	} else if (g_ivlen == 2) {
		tmp_tv = tv;
		tv = &hmac_abnormal1024_tv_template[0];
		tv->dsize = tmp_tv->dsize;
	} else if (g_ivlen == 3) {
		tmp_tv = tv;
		tv = &hmac_abnormal512_tv_template[0];
		tv->dsize = tmp_tv->dsize;
	}

	*alg = alg_type;
	*mode = mode_type;
	*alg_tv = tv;

	return 0;
}

int wd_digests_doimpl(void *ctx, struct wcrypto_digest_op_data *opdata, u32 *trycount)
{
	int ret;
	*trycount = 0;

again:
	ret = wcrypto_do_digest(ctx, opdata, NULL);
	if (ret != WD_SUCCESS) {
		if (ret == -WD_EBUSY && *trycount <= 5) { // try 5 times
			SEC_TST_PRT("do digest busy, retry again!");
			(*trycount)++;
			goto again;
		} else {
			SEC_TST_PRT("do digest failed!");
			return -1;
		}
	}

	return 0;
}

int alloc_from_pool(struct wcrypto_digest_op_data *opdata, struct test_sec_pthread_dt *pdata)
{
	opdata->in = wd_alloc_blk(pdata->pool);
	if (!opdata->in) {
		SEC_TST_PRT("alloc in buffer fail!\n");
		return -1;
	}

	opdata->out = wd_alloc_blk(pdata->pool);
	if (!opdata->out) {
		SEC_TST_PRT("alloc out buffer fail!\n");
		return -1;
	}

	return 0;
}

int sec_sync_digest_test(struct test_sec_pthread_dt *pdata)
{
	struct wcrypto_digest_op_data *opdata = malloc(sizeof(struct wcrypto_digest_op_data));
	enum sec_digest_state state = SEC_DIGEST_INIT;
	int thread_id = (int)syscall(__NR_gettid);
	struct wcrypto_digest_ctx_setup setup;
	struct wd_queue *q = pdata->q;
	struct timeval cur_tval;
	struct hash_testvec *tv;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(opdata, 0, sizeof(struct wcrypto_digest_op_data));

	setup.alg = WCRYPTO_SM3;
	setup.mode = WCRYPTO_DIGEST_NORMAL;
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pdata->pool;

	ret = get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);
	if (ret)
		return -EINVAL;

	ctx = wcrypto_create_digest_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
				pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	} else {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx success!\n",
				pid, thread_id, q->capa.alg);
	}
	if (setup.mode == WCRYPTO_DIGEST_HMAC) {
		hexdump((char *)tv->key, tv->ksize);
		ret = wcrypto_set_digest_key(ctx, (__u8*)tv->key, (__u16)tv->ksize);
		if (ret) {
			SEC_TST_PRT("set key fail!\n");
			goto fail_release;
		}
	}

	ret = alloc_from_pool(opdata, pdata);
	if(ret)
		goto fail_release;

	memset(opdata->in, 0, tv->psize);
	memcpy(opdata->in, tv->plaintext, tv->psize);
	//	opdata->in_bytes = tv->psize;
	SEC_TST_PRT("digest len:%d\n", opdata->in_bytes);
	//	hexdump(tv->plaintext, tv->psize);
	opdata->priv = NULL;
	opdata->out_bytes = tv->dsize;
	memset(opdata->out, 0, opdata->out_bytes);
	opdata->has_next = 0;

	u32 last_update_bufflen = 0;
	u32 data_len = tv->psize;
	while (1) {
		if (state == SEC_DIGEST_INIT) {
			state = SEC_DIGEST_FIRST_UPDATING;
		} else if (state == SEC_DIGEST_FIRST_UPDATING)
			state = SEC_DIGEST_DOING;

		if (data_len > 256) {
			//memcpy(opdata->in, tv->plaintext + last_update_bufflen, 256);
			opdata->in_bytes = 256;
			last_update_bufflen += 256;
			data_len = tv->psize - last_update_bufflen;
		} else {
			state = SEC_DIGEST_FINAL;
			//memcpy(opdata->in, tv->plaintext + last_update_bufflen, data_len);
			opdata->in_bytes = data_len;
		}
		SEC_TST_PRT("data_len:%d  last_update_bufflen:%d\n", data_len, last_update_bufflen);
		hexdump(opdata->in, opdata->in_bytes);
		opdata->has_next = (state == SEC_DIGEST_FINAL) ? false : true;
		ret = wd_digests_doimpl(ctx, opdata, &pdata->send_task_num);
		if (ret)
			goto fail_release;

		SEC_TST_PRT("digest out data:\n");
		hexdump(opdata->out, 64);

		if (state == SEC_DIGEST_FINAL)
			break;
		else
			opdata->in += 256;
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, pdata->send_task_num++);
	speed = pdata->send_task_num / time_used * 1000000;
	Perf = speed * pktlen / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
			thread_id, speed, Perf);

fail_release:
	if (opdata->in)
		wd_free_blk(pdata->pool, opdata->in);
	if (opdata->out)
		wd_free_blk(pdata->pool, opdata->out);
	if (ctx)
		wcrypto_del_digest_ctx(ctx);
	free(opdata);

	return ret;
}

void *_sec_sys_test_thread(void *data)
{
	if (!data) {
		SEC_TST_PRT("test data input error!\n");
		return NULL;
	}
	struct test_sec_pthread_dt *pdata = data;

	if (!g_algclass)
		sec_sync_func_test(pdata);
	else
		sec_sync_digest_test(pdata);

	return NULL;
}

static int sec_cipher_sync_test(int thread_num, __u64 lcore_mask,
        __u64 hcore_mask, enum cipher_op_type op_type,
        char *dev_path, unsigned int node_mask)
{
	void **pool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0, j;
	int block_num = 128;
	struct wd_queue *q;
	int qidx;

	pthread_mutex_init(&perf_mutex, NULL);
	q = malloc(q_num * sizeof(struct wd_queue));
	if (!q) {
		SEC_TST_PRT("malloc q memory fail!\n");
		return -ENOMEM;
	}

	memset(q, 0, q_num * sizeof(struct wd_queue));

	/* create pool for every queue */
	SEC_TST_PRT("create pool memory: %d\n", block_num * setup.block_size);
	pool = malloc(q_num * sizeof(pool));
	if (!pool) {
		SEC_TST_PRT("malloc pool memory fail!\n");
		return -ENOMEM;
	}

	for (j = 0; j < q_num; j++) {
		if (!g_algclass){
			q[j].capa.alg = "cipher";
			if (op_type == ENCRYPTION) {
				q[j].capa.priv.direction = 0; //0 is ENC, 1 is DEC
			} else {
				q[j].capa.priv.direction = 1;
			}
		} else {
			q[j].capa.alg = "digest";
		}

		if (dev_path) {
			strncpy(q[j].dev_path, dev_path, sizeof(q[j].dev_path));
		}
		//q[j].node_mask = node_mask;

		ret = wd_request_queue(&q[j]);
		if (ret) {
			SEC_TST_PRT("request queue %d fail!\n", j);
			return ret;
	    }
	    memset(&setup, 0, sizeof(setup));
	    setup.block_size = MAX_BLOCK_SZ; //set pool  inv + key + in + out
	    setup.block_num = MAX_BLOCK_NM;
	    setup.align_size = SQE_SIZE;

		SEC_TST_PRT("create pool memory: %d\n", MAX_BLOCK_NM * setup.block_size);
	    pool[j] = wd_blkpool_create(&q[j], &setup);
	    if (!pool[j]) {
			SEC_TST_PRT("%s(): create %dth pool fail!\n", __func__, j);
			return -ENOMEM;
		}
	}

	//??? ???
	if (_get_one_bits(lcore_mask) == 0 &&
		_get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	else
		cnt = 1;

	for (i = 0 ; i < cnt; i++) {
		qidx = i / ctx_num_per_q;
		test_thrds_data[i].pool = pool[qidx];
		test_thrds_data[i].q = &q[qidx];
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);

		gettimeofday(&test_thrds_data[i].start_tval, NULL);

		ret = pthread_create(&system_test_thrds[i], NULL,
					 _sec_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			SEC_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}

	SEC_TST_PRT("%d-threads, total Perf: %lld KB/s\n", thread_num, g_total_perf);

	return 0;
}

static void  *_cipher_async_poll_test_thread(void *data)
{
	struct test_sec_pthread_dt *pdata = data;
	struct wd_queue *q = pdata->q;
	int ret;

	while (1) {
		if (!g_algclass)
			ret = wcrypto_cipher_poll(q, 1);
		else
			ret = wcrypto_digest_poll(q, 1);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	return NULL;
}

void _cipher_cb(void *message, void *cipher_tag)
{
	struct cipher_async_tag *tag = cipher_tag;
	struct test_sec_pthread_dt *thread_info = tag->thread_info;
	thread_info->recv_task_num++;
}

int sec_async_func_test(struct test_sec_pthread_dt *pdata)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct wcrypto_cipher_ctx_setup setup;
	struct wcrypto_cipher_op_data opdata;
	struct cipher_async_tag *tag = NULL; //async
	struct wd_queue *q = pdata->q;
	struct cipher_testvec *tv;
	struct timeval cur_tval;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	int i = 0;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));

	setup.alg = WCRYPTO_CIPHER_AES;
	setup.mode = WCRYPTO_CIPHER_CBC;

	ret = get_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);
	if (ret)
		return -EINVAL;

	setup.cb = (void *)_cipher_cb; //call back functions of user
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pdata->pool;

	ctx = wcrypto_create_cipher_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			     pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	}

	hexdump((char *)tv->key, tv->klen);
	ret = wcrypto_set_cipher_key(ctx, (__u8*)tv->key, (__u16)tv->klen);
	if (ret) {
		SEC_TST_PRT("set key fail!\n");
		goto fail_release;
	}
	if (q->capa.priv.direction == 0) {
		opdata.op_type = WCRYPTO_CIPHER_ENCRYPTION;
	} else {
		opdata.op_type = WCRYPTO_CIPHER_DECRYPTION;
	}
	opdata.in = wd_alloc_blk(pdata->pool);
	if (!opdata.in) {
		SEC_TST_PRT("alloc in buffer fail!\n");
		goto fail_release;
	}
	if (q->capa.priv.direction == 0) {
		memcpy(opdata.in, tv->ptext, strlen(tv->ptext));
		if (strlen(tv->ptext) > pktlen) {
			opdata.in_bytes = strlen(tv->ptext);
		} else {
			opdata.in_bytes = pktlen;
		}
	} else {
		memcpy(opdata.in, tv->ctext, strlen(tv->ctext));
		if (strlen(tv->ctext) > pktlen) {
			opdata.in_bytes = strlen(tv->ctext);
		} else {
			opdata.in_bytes = pktlen;
		}
	}

	opdata.priv = NULL;
	printf("ptext:\n");
	hexdump(opdata.in, opdata.in_bytes);
	opdata.out = wd_alloc_blk(pdata->pool);
	opdata.out_bytes = opdata.in_bytes;
	if (!opdata.out) {
		SEC_TST_PRT("alloc out buffer fail!\n");
		goto fail_release;
	}

	opdata.iv = wd_alloc_blk(pdata->pool);
	if (!opdata.iv) {
		SEC_TST_PRT("alloc iv buffer fail!\n");
		goto fail_release;
	}

	memcpy(opdata.iv, tv->iv, tv->ivlen);
	opdata.iv_bytes = tv->ivlen;

	do {
		tag = malloc(sizeof(struct cipher_async_tag)); // set the user tag
		if (!tag)
		    goto fail_release;
		tag->ctx = ctx;
		tag->thread_id = thread_id;
		tag->cnt = i;
		tag->thread_info = pdata;
	try_do_again:
		ret = wcrypto_do_cipher(ctx, &opdata, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			SEC_TST_PRT("wcrypto_do_cipher busy!\n");
			goto try_do_again;
		}
		pdata->send_task_num++;
		i++;
		if (pdata->send_task_num == 1) {
			SEC_TST_PRT("dump output!\n");
			hexdump(opdata.out, opdata.out_bytes);
		}
	} while(!is_exit(pdata));

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, pdata->send_task_num++);
	if (t_seconds) {
		speed = pdata->send_task_num / time_used * 1000000;
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid, thread_id, speed, Perf);
	} else if (t_times) {
		speed = (t_times / time_used) * 1000000; //ops
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid, thread_id, speed, Perf);
	}

fail_release:
	if (opdata.in)
		wd_free_blk(pdata->pool, opdata.in);
	if (opdata.iv)
		wd_free_blk(pdata->pool, opdata.iv);
	if (opdata.out)
		wd_free_blk(pdata->pool, opdata.out);
	if (ctx)
		wcrypto_del_cipher_ctx(ctx);
	if (tag)
		free(tag);

	return ret;
}

void _digest_cb(void *message, void *digest_tag)
{
	struct digest_async_tag *tag = digest_tag;
	struct test_sec_pthread_dt *thread_info = tag->thread_info;
	thread_info->recv_task_num++;
}

int sec_async_digest_test(struct test_sec_pthread_dt *pdata)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct wcrypto_digest_ctx_setup setup;
	struct wcrypto_digest_op_data opdata;
	struct hash_testvec *tv;
	struct timeval cur_tval;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	struct digest_async_tag *tag = NULL; //async
	struct wd_queue *q = pdata->q;
	int i = 0;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	/* default AES-CBC */
	setup.alg = WCRYPTO_SM3;
	setup.mode = WCRYPTO_DIGEST_NORMAL;

	ret = get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);
	if (ret)
		return -EINVAL;

	setup.cb = (void *)_digest_cb; //call back functions of user
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pdata->pool;

	ctx = wcrypto_create_digest_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
				pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	}

	if (setup.mode == WCRYPTO_DIGEST_HMAC) {
		ret = wcrypto_set_digest_key(ctx, (__u8*)tv->key,
				(__u16)tv->ksize);
		if (ret) {
			SEC_TST_PRT("set key fail!\n");
			goto fail_release;
		}
	}
#ifdef DEBUG
	hexdump(tv->key, tv->ksize);
#endif
	opdata.in = wd_alloc_blk(pdata->pool);
	if (!opdata.in) {
		SEC_TST_PRT("alloc in buffer fail!\n");
		goto fail_release;
	}
	memcpy(opdata.in, tv->plaintext, tv->psize);
	opdata.in_bytes = tv->psize;
	SEC_TST_PRT("cipher len:%d\n", opdata.in_bytes);
#ifdef DEBUG
	hexdump(opdata.in, opdata.in_bytes);
#endif
	opdata.priv = NULL;
	opdata.out = wd_alloc_blk(pdata->pool);
	opdata.out_bytes = tv->dsize;
	if (!opdata.out) {
		SEC_TST_PRT("alloc out buffer fail!\n");
		goto fail_release;
	}

	do {
		tag = malloc(sizeof(struct digest_async_tag)); //set the user tag is async
		if (!tag)
			goto fail_release;
		tag->ctx = ctx;
		tag->thread_id = thread_id;
		tag->cnt = i;
		tag->thread_info = pdata;
try_do_again:
		ret = wcrypto_do_digest(ctx, &opdata, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_do_again;
		}
		pdata->send_task_num++;
		i++;

	} while(!is_exit(pdata));

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, pdata->send_task_num++);
	if (t_seconds) {
		speed = pdata->send_task_num / time_used * 1000000;
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid, thread_id, speed, Perf);
	} else if (t_times) {
		speed = (t_times / time_used) * 1000000; //ops
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid, thread_id, speed, Perf);
	}

fail_release:
	if (opdata.in)
		wd_free_blk(pdata->pool, opdata.in);
	if (opdata.out)
		wd_free_blk(pdata->pool, opdata.out);
	if (ctx)
		wcrypto_del_digest_ctx(ctx);
	if (tag)
		free(tag);

	return ret;
}

void *_sec_async_test_thread(void *data)
{
	if (!data) {
		SEC_TST_PRT("test data input error!\n");
		return NULL;
	}
	struct test_sec_pthread_dt *pdata = data;
	if (!g_algclass)
		sec_async_func_test(pdata);
	else
		sec_async_digest_test(pdata);

	return NULL;
}

static int sec_cipher_async_test(int thread_num, __u64 lcore_mask,
		__u64 hcore_mask, enum cipher_op_type op_type,
		char *dev_path, unsigned int node_mask)
{
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0;
	struct wd_queue q;
	void **pool;

	memset(&q, 0, sizeof(q));

	if (!g_algclass){
		q.capa.alg = "cipher";
		if (op_type == ENCRYPTION) {
			q.capa.priv.direction = 0; //0 is ENC, 1 is DEC
		} else
			q.capa.priv.direction = 1;
	} else {
		q.capa.alg = "digest";
	}

	ret = wd_request_queue(&q);
	if (ret) {
		SEC_TST_PRT("request queue fail!\n");
		return ret;
	}
	memset(&setup, 0, sizeof(setup));
	/* set pool  inv + key + in + out */
	setup.block_size = MAX_BLOCK_SZ;
	setup.block_num = MAX_BLOCK_NM;
	setup.align_size = SQE_SIZE;

	/* create pool for every queue */
	SEC_TST_PRT("create pool memory: %d\n", MAX_BLOCK_NM * setup.block_size);
	pool = wd_blkpool_create(&q, &setup);
	if (!pool) {
		SEC_TST_PRT("%s(): create pool fail!\n", __func__);
		return -ENOMEM;
	}
	/* frist create the async poll thread! */
	test_thrds_data[0].pool = pool;
	test_thrds_data[0].q = &q;
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
		_cipher_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		SEC_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	//??? ???
	if (_get_one_bits(lcore_mask) == 0 &&
			_get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	else
		cnt = 1;
	printf("cnt:%d\n", cnt);
	for (i = 1 ; i <= cnt; i++) {
		test_thrds_data[i].pool = pool;
		test_thrds_data[i].q = &q;
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);

		gettimeofday(&test_thrds_data[i].start_tval, NULL);

		ret = pthread_create(&system_test_thrds[i], NULL,
					 _sec_async_test_thread, &test_thrds_data[i]);
		if (ret) {
			SEC_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	asyn_thread_exit = 1;
	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		SEC_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	wd_release_queue(&q);
	wd_blkpool_destroy(pool);
	return 0;
}

int sec_aead_sync_func_test(void *data)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct test_sec_pthread_dt *pdata = data;
	struct wcrypto_aead_ctx_setup setup;
	struct wcrypto_aead_op_data *opdata = malloc(sizeof(struct wcrypto_aead_op_data));
	struct wd_queue *q = pdata->q;
	struct timeval cur_tval;
	struct aead_testvec *tv;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	void *tag = NULL;
	int auth_size;
	int in_size;
	int iv_len;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(opdata, 0, sizeof(struct wcrypto_aead_op_data));

	setup.calg = WCRYPTO_CIPHER_AES;
	setup.cmode = WCRYPTO_CIPHER_CCM;
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pdata->pool;

	ret = get_aead_resource(&tv, (int *)&setup.calg,
		(int *)&setup.cmode, (int *)&setup.dalg, (int *)&setup.dmode);
	if (ret)
		return -EINVAL;

	ctx = wcrypto_create_aead_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	}

	hexdump((char *)tv->key, tv->klen);
	if (setup.cmode == WCRYPTO_CIPHER_CCM ||
		setup.cmode == WCRYPTO_CIPHER_GCM) {
		ret = wcrypto_set_aead_ckey(ctx, (__u8*)tv->key, (__u16)tv->klen);
		if (ret) {
			SEC_TST_PRT("set key fail!\n");
			goto fail_release;
		}
	}else {
		// AEAD template's cipher key is the tail data
		ret = wcrypto_set_aead_ckey(ctx, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set key fail!\n");
			goto fail_release;
		}
		// AEAD template's auth key is the mid data
		ret = wcrypto_set_aead_akey(ctx, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto fail_release;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	ret = wcrypto_aead_setauthsize(ctx, auth_size);
	if (ret) {
		SEC_TST_PRT("set authsize fail!\n");
		goto fail_release;
	}

	// test the auth size
	ret = wcrypto_aead_getauthsize(ctx);
	if (ret != auth_size) {
		SEC_TST_PRT("get authsize fail!\n");
		goto fail_release;
	}
	ret = wcrypto_aead_get_maxauthsize(ctx);
	if (ret < auth_size) {
		SEC_TST_PRT("get max authsize fail!\n");
		goto fail_release;
	}
	SEC_TST_PRT("max authsize : %d!\n", ret);

	if (q->capa.priv.direction == 0) {
		opdata->op_type = WCRYPTO_CIPHER_ENCRYPTION_DIGEST;
	} else {
		opdata->op_type = WCRYPTO_CIPHER_DECRYPTION_DIGEST;
	}

	opdata->assoc_size = tv->alen;
	opdata->in = wd_alloc_blk(pdata->pool);
	if (!opdata->in) {
		SEC_TST_PRT("alloc in buffer fail!\n");
		goto fail_release;
	}

	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > MAX_BLOCK_SZ) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto fail_release;
	}

	// copy the assoc data in the front of in data
	memset(opdata->in, 0, in_size);
	if (q->capa.priv.direction == 0) {
		memcpy(opdata->in, tv->assoc, tv->alen);
		memcpy((opdata->in + tv->alen), tv->ptext, tv->plen);
		opdata->in_bytes = tv->plen;
	} else {
		memcpy(opdata->in, tv->assoc, tv->alen);
		memcpy((opdata->in + tv->alen), tv->ctext, tv->clen);
		opdata->in_bytes = tv->clen - auth_size;
	}

	SEC_TST_PRT("aead input len:%d\n", tv->alen + opdata->in_bytes);
	hexdump(opdata->in, tv->alen + opdata->in_bytes);
	opdata->priv = NULL;
	opdata->out = wd_alloc_blk(pdata->pool);
	if (!opdata->out) {
		SEC_TST_PRT("alloc out buffer fail!\n");
		goto fail_release;
	}
	if (q->capa.priv.direction == 0) {
		opdata->out_bytes = tv->alen + tv->clen;
	} else {
		opdata->out_bytes = tv->alen + tv->plen;
	}
	opdata->out_buf_bytes = MAX_BLOCK_SZ;
	//set iv
	opdata->iv = wd_alloc_blk(pdata->pool);
	if (!opdata->iv) {
		SEC_TST_PRT("alloc iv buffer fail!\n");
		goto fail_release;
	}

	// if data is \0x00, the strlen will end and return
	// iv_len = strlen(tv->iv);
	if (setup.cmode == WCRYPTO_CIPHER_GCM) {
		iv_len = 12;
	} else {
		iv_len = 16;
	}
	memset(opdata->iv, 0, iv_len);
	memcpy(opdata->iv, tv->iv, iv_len);
	opdata->iv_bytes = iv_len;
	SEC_TST_PRT("dump set input IV! IV lenght:%d\n", iv_len);
	hexdump(opdata->iv, opdata->iv_bytes);

	do {
		ret = wcrypto_do_aead(ctx, opdata, tag);
		pdata->send_task_num++;
		if (pdata->send_task_num == 1) {
			SEC_TST_PRT("dump output!\n");
			hexdump(opdata->out, opdata->out_bytes + auth_size);
		}
	} while(!is_exit(pdata));

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, pdata->send_task_num++);
	speed = pdata->send_task_num / time_used * 1000000;
	Perf = speed * in_size / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
		thread_id, speed, Perf);

fail_release:
	if (opdata->in)
		wd_free_blk(pdata->pool, opdata->in);
	if (opdata->iv)
		wd_free_blk(pdata->pool, opdata->iv);
	if (opdata->out)
		wd_free_blk(pdata->pool, opdata->out);
	if (ctx)
		wcrypto_del_aead_ctx(ctx);
	free(opdata);

	return ret;
}

void *__sec_aead_sync_func_test(void *data)
{
	sec_aead_sync_func_test(data);

	return NULL;
}

static int sec_aead_sync_test(int thread_num, __u64 lcore_mask,
        __u64 hcore_mask, enum cipher_op_type op_type,
        char *dev_path, unsigned int node_mask)
{
	void **pool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0, j;
	struct wd_queue *q;
	int qidx;

	SEC_TST_PRT("SEC q_num is : %d!\n", q_num);
	q = malloc(q_num * sizeof(struct wd_queue));
	if (!q) {
		SEC_TST_PRT("malloc q memory fail!\n");
		return -ENOMEM;
	}

	memset(q, 0, q_num * sizeof(struct wd_queue));

	/* create pool for every queue */
	pool = malloc(q_num * sizeof(pool));
	if (!pool) {
		SEC_TST_PRT("malloc pool memory fail!\n");
		return -ENOMEM;
	}

	for (j = 0; j < q_num; j++) {
		q[j].capa.alg = "aead";
		if (op_type == ENCRYPTION) {
			q[j].capa.priv.direction = 0; //0 is ENC, 1 is DEC
		} else {
			q[j].capa.priv.direction = 1;
	    }

	    if (dev_path) {
			strncpy(q[j].dev_path, dev_path, sizeof(q[j].dev_path));
	    }
	    // q[j].node_mask = node_mask;

	    ret = wd_request_queue(&q[j]);
	    if (ret) {
			SEC_TST_PRT("request queue %d fail!\n", j);
			return ret;
	    }
	    memset(&setup, 0, sizeof(setup));
	    setup.block_size = MAX_BLOCK_SZ; //set pool  inv + key + in + out
	    setup.block_num = MAX_BLOCK_NM;
	    setup.align_size = SQE_SIZE;

	    SEC_TST_PRT("create pool memory: %d\n", MAX_BLOCK_NM * setup.block_size);
	    pool[j] = wd_blkpool_create(&q[j], &setup);
	    if (!pool[j]) {
			SEC_TST_PRT("%s(): create %dth pool fail!\n", __func__, j);
			return -ENOMEM;
		}
	}

	//Ïß³ÌÊý Óë°óºË
	if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	else
		cnt = 1;

	for (i = 0 ; i < cnt; i++) {
		qidx = i / ctx_num_per_q;
		test_thrds_data[i].pool = pool[qidx];
		test_thrds_data[i].q = &q[qidx];
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);

		gettimeofday(&test_thrds_data[i].start_tval, NULL);

		ret = pthread_create(&system_test_thrds[i], NULL,
					 __sec_aead_sync_func_test, &test_thrds_data[i]);
		if (ret) {
			SEC_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}

	return 0;
}

static void  *_aead_async_poll_test_thread(void *data)
{
	struct test_sec_pthread_dt *pdata = data;
	struct wd_queue *q = pdata->q;
	int ret;

	while (1) {
		ret = wcrypto_aead_poll(q, 1);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	return NULL;
}

int sec_aead_async_func_test(void *data)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct test_sec_pthread_dt *pdata = data;
	struct wcrypto_aead_ctx_setup setup;
	struct wcrypto_aead_op_data *opdata = malloc(sizeof(struct wcrypto_aead_op_data));
	struct cipher_async_tag *tag = NULL; //async
	struct wd_queue *q = pdata->q;
	struct timeval cur_tval;
	struct aead_testvec *tv;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	int auth_size;
	int in_size;
	int iv_len;
	int i = 0;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(opdata, 0, sizeof(struct wcrypto_aead_op_data));

	setup.calg = WCRYPTO_CIPHER_AES;
	setup.cmode = WCRYPTO_CIPHER_CCM;
	setup.cb = (void *)_cipher_cb; //call back functions of user
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pdata->pool;

	ret = get_aead_resource(&tv, (int *)&setup.calg,
		(int *)&setup.cmode, (int *)&setup.dalg, (int *)&setup.dmode);
	if (ret)
		return -EINVAL;

	ctx = wcrypto_create_aead_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	}

	hexdump((char *)tv->key, tv->klen);
	if (setup.cmode == WCRYPTO_CIPHER_CCM ||
		setup.cmode == WCRYPTO_CIPHER_GCM) {
		ret = wcrypto_set_aead_ckey(ctx, (__u8*)tv->key, (__u16)tv->klen);
		if (ret) {
			SEC_TST_PRT("set key fail!\n");
			goto fail_release;
		}
	}else {
		// AEAD template's cipher key is the tail data
		ret = wcrypto_set_aead_ckey(ctx, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set key fail!\n");
			goto fail_release;
		}
		// AEAD template's auth key is the mid data
		ret = wcrypto_set_aead_akey(ctx, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto fail_release;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	ret = wcrypto_aead_setauthsize(ctx, auth_size);
	if (ret) {
		SEC_TST_PRT("set authsize fail!\n");
		goto fail_release;
	}

	// test the auth size
	ret = wcrypto_aead_getauthsize(ctx);
	if (ret != auth_size) {
		SEC_TST_PRT("get authsize fail!\n");
		goto fail_release;
	}
	ret = wcrypto_aead_get_maxauthsize(ctx);
	if (ret < auth_size) {
		SEC_TST_PRT("get max authsize fail!\n");
		goto fail_release;
	}
	SEC_TST_PRT("max authsize : %d!\n", ret);

	if (q->capa.priv.direction == 0) {
		opdata->op_type = WCRYPTO_CIPHER_ENCRYPTION_DIGEST;
	} else {
		opdata->op_type = WCRYPTO_CIPHER_DECRYPTION_DIGEST;
	}

	opdata->assoc_size = tv->alen;
	opdata->in = wd_alloc_blk(pdata->pool);
	if (!opdata->in) {
		SEC_TST_PRT("alloc in buffer fail!\n");
		goto fail_release;
	}

	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > MAX_BLOCK_SZ) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto fail_release;
	}

	// copy the assoc data in the front of in data
	memset(opdata->in, 0, in_size);
	if (q->capa.priv.direction == 0) {
		memcpy(opdata->in, tv->assoc, tv->alen);
		memcpy((opdata->in + tv->alen), tv->ptext, tv->plen);
		opdata->in_bytes = tv->plen;
	} else {
		memcpy(opdata->in, tv->assoc, tv->alen);
		memcpy((opdata->in + tv->alen), tv->ctext, tv->clen);
		opdata->in_bytes = tv->clen - auth_size;
	}

	SEC_TST_PRT("aead input len:%d\n", tv->alen + opdata->in_bytes);
	hexdump(opdata->in, tv->alen + opdata->in_bytes);
	opdata->priv = NULL;
	opdata->out = wd_alloc_blk(pdata->pool);
	if (!opdata->out) {
		SEC_TST_PRT("alloc out buffer fail!\n");
		goto fail_release;
	}
	if (q->capa.priv.direction == 0) {
		opdata->out_bytes = tv->alen + tv->clen;
	} else {
		opdata->out_bytes = tv->alen + tv->plen;
	}
	opdata->out_buf_bytes = MAX_BLOCK_SZ;
	//set iv
	opdata->iv = wd_alloc_blk(pdata->pool);
	if (!opdata->iv) {
		SEC_TST_PRT("alloc iv buffer fail!\n");
		goto fail_release;
	}

	// if data is \0x00, the strlen will end and return
	// iv_len = strlen(tv->iv);
	if (setup.cmode == WCRYPTO_CIPHER_GCM) {
		iv_len = 12;
	} else {
		iv_len = 16;
	}
	memset(opdata->iv, 0, iv_len);
	memcpy(opdata->iv, tv->iv, iv_len);
	opdata->iv_bytes = iv_len;
	SEC_TST_PRT("dump set input IV! IV lenght:%d\n", iv_len);
	hexdump(opdata->iv, opdata->iv_bytes);

	do {
		tag = malloc(sizeof(struct cipher_async_tag)); // set the user tag
		if (!tag)
		    goto fail_release;

		tag->ctx = ctx;
		tag->thread_id = thread_id;
		tag->cnt = i;
		tag->thread_info = pdata;
	try_do_again:
		ret = wcrypto_do_aead(ctx, opdata, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			SEC_TST_PRT("wcrypto_do_aead busy!\n");
			goto try_do_again;
		}
		pdata->send_task_num++;
		i++;
		if (pdata->send_task_num == 1) {
			SEC_TST_PRT("dump output!\n");
			hexdump(opdata->out, opdata->out_bytes + auth_size);
		}
	} while(!is_exit(pdata));

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, pdata->send_task_num++);
	speed = pdata->send_task_num / time_used * 1000000;
	Perf = speed * in_size / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid, thread_id,
		speed, Perf);

fail_release:
	if (opdata->in)
		wd_free_blk(pdata->pool, opdata->in);
	if (opdata->iv)
		wd_free_blk(pdata->pool, opdata->iv);
	if (opdata->out)
		wd_free_blk(pdata->pool, opdata->out);
	if (ctx)
		wcrypto_del_aead_ctx(ctx);
	if (tag)
		free(tag);
	free(opdata);

	return ret;
}
void *__sec_aead_async_func_test(void *data)
{
	sec_aead_async_func_test(data);

	return NULL;
}

static int sec_aead_async_test(int thd_num, __u64 lcore_mask,
        __u64 hcore_mask, enum cipher_op_type op_type,
        char *dev_path, unsigned int node_mask)
{
	struct wd_blkpool_setup setup;
	int i, ret,cnt = 0;
	struct wd_queue q;
	void **pool;

	memset(&q, 0, sizeof(q));

	q.capa.alg = "aead";
	if (op_type == ENCRYPTION) {
		q.capa.priv.direction = 0; // 0 is ENC, 1 is DEC
	} else {
		q.capa.priv.direction = 1;
	}

	ret = wd_request_queue(&q);
	if (ret) {
		SEC_TST_PRT("request queue fail!\n");
		return ret;
	}
	memset(&setup, 0, sizeof(setup));
	/* set pool  inv + key + in + out */
	setup.block_size = MAX_BLOCK_SZ;
	setup.block_num = MAX_BLOCK_NM;
	setup.align_size = SQE_SIZE;

	/* create pool for every queue */
	SEC_TST_PRT("create pool memory: %d\n", MAX_BLOCK_NM * setup.block_size);
	pool = wd_blkpool_create(&q, &setup);
	if (!pool) {
		SEC_TST_PRT("%s(): create pool fail!\n", __func__);
		return -ENOMEM;
	}
	/* frist create the async poll thread! */
	test_thrds_data[0].pool = pool;
	test_thrds_data[0].q = &q;
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
		_aead_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		SEC_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	//Ïß³ÌÊý Óë°óºË
	if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thd_num;
	else
		cnt = 1;
	printf("cnt:%d\n", cnt);
	for (i = 1 ; i <= cnt; i++) {
		test_thrds_data[i].pool = pool;
		test_thrds_data[i].q = &q;
		test_thrds_data[i].thread_num = thd_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);

		gettimeofday(&test_thrds_data[i].start_tval, NULL);

		ret = pthread_create(&system_test_thrds[i], NULL,
					 __sec_aead_async_func_test, &test_thrds_data[i]);
		if (ret) {
			SEC_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thd_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	asyn_thread_exit = 1;
	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		SEC_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	wd_release_queue(&q);
	wd_blkpool_destroy(pool);
	return 0;
}


int main(int argc, char *argv[])
{
	__u64 lcore_mask = 0;
	__u64 hcore_mask = 0;
	int thread_num = 1;
	unsigned int node_msk = 0;
	int direction = 0;
	int value, pktsize, keylen, ivlen;

	if (!strcmp(argv[1], "-cipher")) {
		printf("cipher %d\n", wd_get_available_dev_num("cipher"));
		g_testalg = strtoul((char*)argv[2], NULL, 10);
		g_algclass = CIPHER_CLASS;
	} else if (!strcmp(argv[1], "-digest")) {
		printf("digest %d\n", wd_get_available_dev_num("digest"));
		g_testalg = strtoul((char*)argv[2], NULL, 10);
		g_algclass = DIGEST_CLASS;
	} else if (!strcmp(argv[1], "-aead")) {
		printf("aead %d\n", wd_get_available_dev_num("aead"));
		g_testalg = strtoul((char*)argv[2], NULL, 10);
		g_algclass = AEAD_CLASS;
	}

	if (!strcmp(argv[3], "-t")) {
		thread_num = strtoul((char*)argv[4], NULL, 10);
		if (thread_num <= 0 || thread_num > TEST_MAX_THRD) {
			SEC_TST_PRT("Invalid threads num:%d!\n", thread_num);
			SEC_TST_PRT("Now set threads num as 2\n");
			thread_num = 2;
		}
	}

	q_num = (thread_num - 1) / ctx_num_per_q + 1;
	if (!strcmp(argv[5], "-optype")) {
		direction = strtoul((char*)argv[6], NULL, 10);
	}
	printf("dirction is: %d\n", direction);
	if (direction == 0) {
		alg_op_type = ENCRYPTION;
	} else {
		alg_op_type = DECRYPTION;
	}
	/* tools supports time and freq test currently. */
	if (!strcmp(argv[7], "-seconds") || !strcmp(argv[7], "-cycles")) {
		value = strtoul((char*)argv[8], NULL, 10);
		if (!strcmp(argv[7], "-seconds")) {
			t_seconds = value;
		} else if (!strcmp(argv[7], "-cycles")) {
			t_times = value;
		} else {
			SEC_TST_PRT("pls use ./test_hisi_sec -help get details!\n");
			return -EINVAL;
		}
	}
	printf("test seconds:%d\n", t_seconds);
	if (!strcmp(argv[9], "-pktlen")) {
		pktsize = strtoul((char*)argv[10], NULL, 10);
		pktlen = pktsize;
	}
	if (!strcmp(argv[11], "-keylen")) {
		keylen = strtoul((char*)argv[12], NULL, 10);
		g_keylen = keylen;
	}
	if (!strcmp(argv[13], "-ivlen")) {
		ivlen = strtoul((char*)argv[14], NULL, 10);
		g_ivlen = ivlen;
	}

	printf("test set: key len:%d, iv len:%d\n", g_keylen, g_ivlen);

	q_num = thread_num * ctx_num_per_q;
	if (!strcmp(argv[15], "-sync")) {
		printf("test type is sync\n");
		if (g_algclass == CIPHER_CLASS || g_algclass == DIGEST_CLASS)
			sec_cipher_sync_test(thread_num, lcore_mask, hcore_mask,
			alg_op_type, NULL, node_msk);
		else if (g_algclass == AEAD_CLASS)
			sec_aead_sync_test(thread_num, lcore_mask, hcore_mask,
			alg_op_type, NULL, node_msk);
		else
			printf("test alg type not supported\n");
	} else if (!strcmp(argv[15], "-async")) {
		printf("test type is async\n");
		if (g_algclass == CIPHER_CLASS || g_algclass == DIGEST_CLASS)
			sec_cipher_async_test(thread_num, lcore_mask, hcore_mask,
			alg_op_type, NULL, node_msk);
		else if (g_algclass == AEAD_CLASS)
			sec_aead_async_test(thread_num, lcore_mask, hcore_mask,
			alg_op_type, NULL, node_msk);
		else
			printf("test alg type not supported\n");
	} else {
		SEC_TST_PRT("Now Please set the cipher test type! -sync or -async.\n");
	}

	return 0;
}
