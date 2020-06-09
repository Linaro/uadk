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
#include "../../wd_bmm.h"
#include "../../wd_util.h"

#define  SEC_TST_PRT printf
#define TEST_MAX_THRD 128
#define SQE_SIZE 128
#define MAX_ALGO_PER_TYPE 12

typedef unsigned char u8;
typedef unsigned int u32;

static int q_num = 1;
static int ctx_num_per_q = 1;
static int key_bits = 128;
static long long g_total_perf = 0;

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

/* OpenSSL Skcipher APIS */
static u32 t_times = 10;
static u32 t_seconds = 0;
static u32 pktlen = 1024;
static u32 g_testalg = 0;
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
		return time_used >= t_seconds * 1000000;
	else if (t_times)
		return pdata->send_task_num >= t_times;

	return false;
}

void hexdump(char *buf, int num)
{
	for (int i = 0; i < num; i++) {
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
					tv = &aes_ecb_tv_template_128;
				break;
				case AES_KEYSIZE_192:
					tv = &aes_ecb_tv_template_192;
				break;
				case AES_KEYSIZE_256:
					tv = &aes_ecb_tv_template_256;
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
					tv = &aes_cbc_tv_template_128;
				break;
				case AES_KEYSIZE_192:
					tv = &aes_cbc_tv_template_192;
				break;
				case AES_KEYSIZE_256:
					tv = &aes_cbc_tv_template_256;
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
					tv = &aes_xts_tv_template_256;
				break;
				case AES_KEYSIZE_256:
					tv = &aes_xts_tv_template_512;
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
					tv = &aes_ofb_tv_template_128;
				break;
				case AES_KEYSIZE_192:
					tv = &aes_ofb_tv_template_192;
				break;
				case AES_KEYSIZE_256:
					tv = &aes_ofb_tv_template_256;
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
					tv = &aes_cfb_tv_template_128;
				break;
				case AES_KEYSIZE_192:
					tv = &aes_cfb_tv_template_192;
				break;
				case AES_KEYSIZE_256:
					tv = &aes_cfb_tv_template_256;
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
			if (g_keylen != 24) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &des3_ecb_tv_template;
			break;
		case 6:
			alg_type = WCRYPTO_CIPHER_3DES;
			mode_type = WCRYPTO_CIPHER_CBC;
			SEC_TST_PRT("test alg: %s\n", "cbc(des3)");
			if (g_keylen != 24) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &des3_cbc_tv_template;
			break;
		case 7:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_CBC;
			SEC_TST_PRT("test alg: %s\n", "cbc(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cbc_tv_template;
			break;
		case 8:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_XTS;
			SEC_TST_PRT("test alg: %s\n", "xts(sm4)");
			if (g_keylen != 32) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_xts_tv_template;
			break;
		case 9:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_OFB;
			SEC_TST_PRT("test alg: %s\n", "ofb(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_ofb_tv_template_128;
			break;
		case 10:
			alg_type = WCRYPTO_CIPHER_SM4;
			mode_type = WCRYPTO_CIPHER_CFB;
			SEC_TST_PRT("test alg: %s\n", "cfb(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cfb_tv_template_128;
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

int sec_test_set_iv(struct test_sec_pthread_dt *pdata, 
		struct wcrypto_cipher_op_data *opdata, struct cipher_testvec *tv)
{
	if (!tv->iv)
	return -1;
	tv->ivlen = strlen(tv->iv);

	memset(opdata->iv, 0, g_ivlen);
	memcpy(opdata->iv, tv->iv, g_ivlen);
	opdata->iv_bytes = g_ivlen;
#ifdef DEBUG
	SEC_TST_PRT("dump set input IV!\n");
	hexdump(opdata->iv, g_ivlen);
#endif

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
	void *tag;
	int init_ctx, ret;

	memset(&setup, 0, sizeof(setup));
	memset(opdata, 0, sizeof(struct wcrypto_cipher_op_data));

	setup.alg = WCRYPTO_CIPHER_AES;
	setup.mode = WCRYPTO_CIPHER_CBC;
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.usr = pdata->pool;

	ret = get_resource(&tv, &setup.alg, &setup.mode);
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

	memset(opdata->in, 0, pktlen);
	if (q->capa.priv.direction == 0) {
		memcpy(opdata->in, tv->ptext, pktlen);
		opdata->in_bytes = pktlen;
	} else {
		memcpy(opdata->in, tv->ctext, pktlen);
		opdata->in_bytes = pktlen;
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
	sec_test_set_iv(pdata, opdata, tv);

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
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %lld KB/s\n", pid,
			   thread_id, speed, Perf);
	} else if (t_times) {
		speed = 1 / (time_used / t_times) * 1000000;
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %lld KB/s\n", pid,
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


void *_sec_sys_test_thread(void *data)
{
	int ret;
	if (!data) {
		SEC_TST_PRT("test data input error!\n");
		return;
	}
	struct test_sec_pthread_dt *pdata = data;

	ret = sec_sync_func_test(pdata);
}

static sec_cipher_sync_test(int thread_num, __u64 lcore_mask,
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
		q[j].capa.alg = "cipher";
		if (op_type == ENCRYPTION) {
			q[j].capa.priv.direction = 0; //0 is ENC, 1 is DEC
		} else {
			q[j].capa.priv.direction = 1; 
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
		setup.block_size = 1024; //set pool  inv + key + in + out
		setup.block_num = block_num;
		setup.align_size = SQE_SIZE;

		pool[j] = wd_blkpool_create(&q[j], &setup);
		if (!pool[j]) {
			SEC_TST_PRT("%s(): create %dth pool fail!\n", __func__, j);
			return -ENOMEM;
		}
	}

	//线程数 与绑核
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
		ret = wcrypto_cipher_poll(q, 1);
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
	struct cipher_testvec *tv;
	struct timeval cur_tval;
	float time_used, speed;
	unsigned long Perf = 0;
	int pid = getpid();
	void *ctx = NULL;
	struct cipher_async_tag *tag = NULL; //async
	struct wd_queue *q = pdata->q;
	int i = 0;
	int init_ctx, ret;

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	/* default AES-CBC */
	setup.alg = WCRYPTO_CIPHER_AES;
	setup.mode = WCRYPTO_CIPHER_CBC;

	ret = get_resource(&tv, &setup.alg, &setup.mode);
	if (ret)
		return -EINVAL;

	setup.cb = (void *)_cipher_cb; //call back functions of user
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.usr = pdata->pool;

	ctx = wcrypto_create_cipher_ctx(q, &setup);
	if (!ctx) {
		SEC_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		return ret;
	}

	ret = wcrypto_set_cipher_key(ctx, (__u8*)tv->key,
				(__u16)tv->klen);
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
		memcpy(opdata.in, tv->ptext, pktlen);
		opdata.in_bytes = pktlen;
	} else {
		memcpy(opdata.in, tv->ctext, pktlen);
		opdata.in_bytes = pktlen;
	}

	opdata.priv = NULL;
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

	sec_test_set_iv(pdata, &opdata, tv);

	do {
		tag = malloc(sizeof(struct cipher_async_tag)); //set the user tag is async
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
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %lld KB/s\n", pid, thread_id, speed, Perf);
	} else if (t_times) {
		speed = (t_times / time_used) * 1000000; //ops
		Perf = speed * pktlen / 1024; //B->KB
		pthread_mutex_lock(&perf_mutex);
		g_total_perf += Perf;
		pthread_mutex_unlock(&perf_mutex);
		SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %lld KB/s\n", pid, thread_id, speed, Perf);
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

void *_sec_async_test_thread(void *data)
{
	if (!data) {
		SEC_TST_PRT("test data input error!\n");
		return;
	}
	struct test_sec_pthread_dt *pdata = data;

	sec_async_func_test(pdata);
}

static sec_cipher_async_test(int thread_num, __u64 lcore_mask,
	__u64 hcore_mask, enum cipher_op_type op_type,
	char *dev_path, unsigned int node_mask)
{
	void **pool;
	struct wd_blkpool_setup setup;
	int i, ret, cnt = 0, j;
	int block_num = 128;
	struct wd_queue q;
	int qidx;

	memset(&q, 0, sizeof(q));

	q.capa.alg = "cipher";
	if (op_type == ENCRYPTION) {
		q.capa.priv.direction = 0; //0 is ENC, 1 is DEC
	} else {
		q.capa.priv.direction = 1;
	}

	ret = wd_request_queue(&q);
	if (ret) {
		SEC_TST_PRT("request queue %d fail!\n", j);
		return ret;
	}
	memset(&setup, 0, sizeof(setup));
	/* set pool  inv + key + in + out */
	setup.block_size = 1024;
	setup.block_num = block_num;
	setup.align_size = SQE_SIZE;

	/* create pool for every queue */
	SEC_TST_PRT("create pool memory: %d\n", block_num * setup.block_size);
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

	//线程数 与绑核
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

int main(int argc, char *argv[])
{
	enum cipher_op_type alg_op_type;
	char dev_path[PATH_STR_SIZE] = {0};
	int thread_num = 1;
	unsigned int node_msk = 0;
	int direction = 0;
	int value, pktsize, keylen, ivlen;
	__u64 core_mask[2];
	printf("the test is no sva vison, test vison tag:xx:xx\n");

	if (!strcmp(argv[1], "-cipher")) {
		printf("num %d\n", wd_get_available_dev_num("cipher"));
		g_testalg = strtoul((char*)argv[2], NULL, 10);
	} else if (!strcmp(argv[1], "-digist")) {
		printf("num %d\n", wd_get_available_dev_num("digist"));
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
	printf("dirction is:%d\n", direction);
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

	printf("test set: key len:%d, iv len:%d\n", g_keylen * 8, g_ivlen);
	__u64 lcore_mask = 0;
	__u64 hcore_mask = 0;
	if (!strcmp(argv[15], "-sync")) {
		printf("test type is sync\n");
		sec_cipher_sync_test(thread_num, lcore_mask, hcore_mask,
		alg_op_type, NULL, node_msk);
	} else if (!strcmp(argv[15], "-async")) {
		printf("test type is async\n");
		sec_cipher_async_test(thread_num, lcore_mask, hcore_mask,
		alg_op_type, NULL, node_msk);
	} else {
		/* eg: ./test_hisi_sec -cipher -t 3 -optype 0 -seconds 1 -pktlen 1024 -keylen 16 -ivlen 16 -sync */
		SEC_TST_PRT("Now Please set the cipher test type! -sync or -async.\n");
	}

	return 0;
}
