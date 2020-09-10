// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "test_hisi_sec.h"
#include "wd_cipher.h"
#include "wd_digest.h"
#include "wd_alg_common.h"

#define  SEC_TST_PRT printf
#define HW_CTX_SIZE (24 * 1024)
#define BUFF_SIZE 1024
#define IV_SIZE   256
#define	NUM_THREADS	128

#define SCHED_SINGLE "sched_single"
#define SCHED_NULL_CTX_SIZE	4
#define TEST_WORD_LEN	4096
#define MAX_ALGO_PER_TYPE 12

static struct wd_ctx_config g_ctx_cfg;
static struct wd_sched g_sched;
static struct wd_sched dg_sched;

//static struct wd_cipher_req g_async_req;
static long long int g_times;
static unsigned int g_thread_num;
static int g_count; // total packets
static unsigned int g_testalg;
static unsigned int g_keylen;
static unsigned int g_pktlen;
static unsigned int g_direction;
static unsigned int alg_op_type;
static unsigned int g_ivlen;

char *skcipher_names[MAX_ALGO_PER_TYPE] =
	{"ecb(aes)", "cbc(aes)", "xts(aes)", "ofb(aes)", "cfb(aes)", "ecb(des3_ede)",
	"cbc(des3_ede)", "cbc(sm4)", "xts(sm4)", "ofb(sm4)", "cfb(sm4)", NULL,};

typedef struct _thread_data_t {
	int     tid;
	int     flag;
	int	mode;
	struct wd_cipher_req	*req;
	struct wd_cipher_sess_setup *setup;
	struct wd_digest_req	*hreq;
	struct wd_digest_sess_setup *hsetup;
	int cpu_id;
	struct timeval start_tval;
	unsigned long long send_task_num;
	unsigned long long recv_task_num;
} thread_data_t;

//static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t system_test_thrds[NUM_THREADS];
static thread_data_t thr_data[NUM_THREADS];

static void hexdump(char *buff, unsigned int len)
{
	unsigned int i;
	if (!buff) {
		printf("hexdump input buff is NULL!");
		return;
	}

	for (i = 0; i < len; i++) {
		printf("\\0x%02x", buff[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
}

int get_cipher_resource(struct cipher_testvec **alg_tv, int* alg, int* mode)
{
	struct cipher_testvec *tv;
	int alg_type;
	int mode_type;

	switch (g_testalg) {
		case 0:
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_ECB;
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
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_CBC;
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
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_XTS;
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
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_OFB;
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
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_CFB;
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
			alg_type = WD_CIPHER_3DES;
			mode_type = WD_CIPHER_ECB;
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
			alg_type = WD_CIPHER_3DES;
			mode_type = WD_CIPHER_CBC;
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
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_CBC;
			SEC_TST_PRT("test alg: %s\n", "cbc(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cbc_tv_template[0];
			break;
		case 8:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_XTS;
			SEC_TST_PRT("test alg: %s\n", "xts(sm4)");
			if (g_keylen != 32) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_xts_tv_template[0];
			break;
		case 9:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_OFB;
			SEC_TST_PRT("test alg: %s\n", "ofb(sm4)");
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_ofb_tv_template_128[0];
			break;
		case 10:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_CFB;
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

static handle_t sched_single_pick_next_ctx(struct wd_ctx_config *cfg,
		void *sched_ctx, struct wd_cipher_req *req, int numa_id)
{
	return g_ctx_cfg.ctxs[0].ctx;
}

static int sched_single_poll_policy(struct wd_ctx_config *cfg, __u32 expect, __u32 *count)
{
	return 0;
}

static int init_sigle_ctx_config(int type, int mode, struct wd_sched *sched)
{
	struct uacce_dev_list *list;
	int ret;

	list = wd_get_accel_list("cipher");
	if (!list)
		return -ENODEV;

	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = 1;
	g_ctx_cfg.ctxs = calloc(1, sizeof(struct wd_ctx));
	if (!g_ctx_cfg.ctxs)
		return -ENOMEM;

	/* Just use first found dev to test here */
	g_ctx_cfg.ctxs[0].ctx = wd_request_ctx(list->dev);
	if (!g_ctx_cfg.ctxs[0].ctx) {
		ret = -EINVAL;
		printf("Fail to request ctx!\n");
		goto out;
	}
	g_ctx_cfg.ctxs[0].op_type = type;
	g_ctx_cfg.ctxs[0].ctx_mode = mode;

	sched->name = SCHED_SINGLE;
	sched->pick_next_ctx = sched_single_pick_next_ctx;

	sched->poll_policy = sched_single_poll_policy;
	/*cipher init*/
	ret = wd_cipher_init(&g_ctx_cfg, sched);
	if (ret) {
		printf("Fail to cipher ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;
out:
	free(g_ctx_cfg.ctxs);

	return ret;
}

static void uninit_config(void)
{
	int i;

	wd_cipher_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
}

static int test_sec_cipher_sync_once(void)
{
	struct cipher_testvec *tv = NULL;
	handle_t	h_sess = 0;
	struct wd_cipher_sess_setup	setup;
	struct wd_cipher_req req;
	int cnt = g_times;
	int ret;

	/* config setup */
	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC, &g_sched);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}
	/* config arg */
	memset(&req, 0, sizeof(struct wd_cipher_req));
	setup.alg = WD_CIPHER_AES;
	setup.mode = WD_CIPHER_CBC;
	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION;
	else {
		req.op_type = WD_CIPHER_DECRYPTION;
	}

	/* get resource */
	ret = get_cipher_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		printf("req src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.src, tv->ptext, g_pktlen);
	req.in_bytes = g_pktlen;

	printf("req src--------->:\n");
	hexdump(req.src, g_pktlen);
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		printf("req dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		printf("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.mode == WD_CIPHER_CBC || setup.mode == WD_CIPHER_XTS) {
		if (tv->iv)
			memcpy(req.iv, tv->iv, strlen(tv->iv));
		req.iv_bytes = strlen(tv->iv);
		printf("cipher req iv--------->:\n");
		hexdump(req.iv, req.iv_bytes);
	}
	h_sess = wd_cipher_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		printf("req set key failed!\n");
		goto out;
	}
	printf("cipher req key--------->:\n");
	// hexdump(h_sess->key, tv->klen);

	while (cnt) {
		ret = wd_do_cipher_sync(h_sess, &req);
		cnt--;
	}

	printf("Test cipher sync function: output dst-->\n");
	hexdump(req.dst, req.in_bytes);

out:
	if (req.src)
		free(req.src);
	if (req.dst)
		free(req.dst);
	if (req.iv)
		free(req.iv);
	if (h_sess)
		wd_cipher_free_sess(h_sess);
	uninit_config();

	return ret;
}

static void *async_cb(struct wd_cipher_req *req, void *data)
{
	// struct wd_cipher_req *req = (struct wd_cipher_req *)data;
	// memcpy(&g_async_req, req, sizeof(struct wd_cipher_req));

	return NULL;
}

static int test_sec_cipher_async_once(void)
{
	struct cipher_testvec *tv = NULL;
	struct wd_cipher_sess_setup setup;
	thread_data_t data;
	handle_t h_sess = 0;
	struct wd_cipher_req req;
	int cnt = g_times;
	__u32 num = 0;
	int ret;

	memset(&data, 0, sizeof(thread_data_t));
	data.req = &req;
	/* config setup */
	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC, &g_sched);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}
	/* config arg */
	memset(&req, 0, sizeof(struct wd_cipher_req));
	setup.alg = WD_CIPHER_AES;
	setup.mode = WD_CIPHER_CBC;

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION;
	else {
		req.op_type = WD_CIPHER_DECRYPTION;
	}

	/* get resource */
	ret = get_cipher_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		printf("req src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.src, tv->ptext, g_pktlen);
	req.in_bytes = g_pktlen;

	printf("req src--------->:\n");
	hexdump(req.src, g_pktlen);
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		printf("req dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		printf("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.mode == WD_CIPHER_CBC || setup.mode == WD_CIPHER_XTS) {
		if (tv->iv)
			memcpy(req.iv, tv->iv, strlen(tv->iv));
		req.iv_bytes = strlen(tv->iv);
		printf("cipher req iv--------->:\n");
		hexdump(req.iv, req.iv_bytes);
	}
	h_sess = wd_cipher_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		printf("req set key failed!\n");
		goto out;
	}
	printf("cipher req key--------->:\n");
	// hexdump(h_sess->key, tv->klen);
	while (cnt) {
		req.cb = async_cb;
		req.cb_param = &data;
		ret = wd_do_cipher_async(h_sess, &req);
		if (ret < 0) {
			usleep(100);
			continue;
		}
		/* poll thread */
try_again:
		num = 0;
		ret = wd_cipher_poll_ctx(g_ctx_cfg.ctxs[0].ctx, 1, &num);
		if (ret == -EAGAIN) {
			goto try_again; // loop poll
		}
		cnt--;
	}

	// printf("Test cipher async once function: output dst-->\n");
	// hexdump(req.dst, req.out_bytes);

	usleep(100000);
out:
	if (req.src)
		free(req.src);
	if (req.dst)
		free(req.dst);
	if (req.iv)
		free(req.iv);
	if (h_sess)
		wd_cipher_free_sess(h_sess);
	uninit_config();

	return ret;
}

static int test_sec_cipher_sync(void *arg)
{
	int thread_id = (int)syscall(__NR_gettid);
	thread_data_t *pdata = (thread_data_t *)arg;
	struct wd_cipher_sess_setup *setup = pdata->setup;

	struct wd_cipher_req *req = pdata->req;
	struct cipher_testvec *tv = NULL;

	struct timeval cur_tval;
	unsigned long Perf = 0, pktlen;
	handle_t	h_sess;
	float speed, time_used;
	int pid = getpid();
	int cnt = g_times;
	int ret;

	/* get resource */
	ret = get_cipher_resource(&tv, (int *)&setup->alg, (int *)&setup->mode);

	h_sess = wd_cipher_alloc_sess(setup);
	if (!h_sess) {
		ret = -1;
		return ret;
	}

	pktlen = req->in_bytes;
	printf("cipher req src--------->:\n");
	hexdump(req->src, req->in_bytes);

	printf("ivlen = %d, cipher req iv--------->:\n", req->iv_bytes);
	hexdump(req->iv, req->iv_bytes);

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		printf("test sec cipher set key is failed!\n");
		goto out;;
	}

	printf("cipher req key--------->:\n");
	// hexdump(h_sess->key, h_sess->key_bytes);

	pthread_mutex_lock(&mutex);
	// pthread_cond_wait(&cond, &mutex);
	/* run task */
	while (cnt) {
		ret = wd_do_cipher_sync(h_sess, req);
		cnt--;
		pdata->send_task_num++;
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);
	printf("time_used:%0.0f us, send task num:%lld\n", time_used, pdata->send_task_num++);
	speed = pdata->send_task_num / time_used * 1000000;
	Perf = speed * pktlen / 1024; //B->KB
	printf("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
			thread_id, speed, Perf);

#if 0
	printf("Test cipher sync function: output dst-->\n");
	hexdump(req->dst, req->in_bytes);
	printf("Test cipher sync function thread_id is:%d\n", thread_id);
#endif
	pthread_mutex_unlock(&mutex);

	ret = 0;
out:
	if (h_sess)
		wd_cipher_free_sess(h_sess);

	return ret;
}

static void *_test_sec_cipher_sync(void *data)
{
	test_sec_cipher_sync(data);

	return NULL;
}
/*
 * Create 2 threads. one threads are enc/dec, and the other
 * is polling.
 */
static int test_sync_create_threads(int thread_num, struct wd_cipher_req *reqs, struct wd_cipher_sess_setup *setups)
{
	pthread_attr_t attr;
	int i, ret;

	if (thread_num > NUM_THREADS - 1) {
		printf("can't creat %d threads", thread_num - 1);
		return -EINVAL;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < thread_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].setup = &setups[i];
		gettimeofday(&thr_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], &attr, _test_sec_cipher_sync, &thr_data[i]);
		if (ret) {
			printf("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	thr_data[i].tid = i;
	pthread_attr_destroy(&attr);
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
	}

	return 0;
}

static int sec_cipher_sync_test(void)
{
	struct wd_cipher_req	req[NUM_THREADS];
	struct wd_cipher_sess_setup setup[NUM_THREADS];
	void *src = NULL, *dst = NULL, *iv = NULL;
	int parallel = g_thread_num;
	struct cipher_testvec *tv = NULL;
	int test_alg, test_mode;
	int ret, i;

	memset(req, 0, sizeof(struct wd_cipher_req) * NUM_THREADS);
	memset(setup, 0, sizeof(struct wd_cipher_sess_setup) * NUM_THREADS);

	/* get resource */
	ret = get_cipher_resource(&tv, &test_alg, &test_mode);

	int step = sizeof(char) * TEST_WORD_LEN;
	src = malloc(step * NUM_THREADS);
	if (!src) {
		ret = -ENOMEM;
		goto out_thr;
	}
	dst = malloc(step * NUM_THREADS);
	if (!dst) {
		ret = -ENOMEM;
		goto out_thr;
	}
	iv = malloc(step * NUM_THREADS);
	if (!iv) {
		ret = -ENOMEM;
		goto out_thr;
	}

	for (i = 0; i < parallel; i++) {
		req[i].src = src + i * step;
		memset(req[i].src, 0, step);
		memcpy(req[i].src, tv->ptext, g_pktlen);
		req[i].in_bytes = g_pktlen;

		req[i].dst = dst + i * step;
		req[i].out_bytes = tv->len;

		req[i].iv = iv + i * step;
		memset(req[i].iv, 0, step);
		if (test_mode == WD_CIPHER_CBC || test_mode == WD_CIPHER_XTS) {
			memcpy(req[i].iv, tv->iv, strlen(tv->iv));
			req[i].iv_bytes = strlen(tv->iv);
		}

		/* config arg */
		setup[i].alg = test_alg;
		setup[i].mode = test_mode;

		if (g_direction == 0)
			req[i].op_type = WD_CIPHER_ENCRYPTION;
		else {
			req[i].op_type = WD_CIPHER_DECRYPTION;
		}
	}

	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC, &g_sched);
	if (ret) {
		printf("fail to init sigle ctx config!\n");
		goto out_thr;
	}

	ret = test_sync_create_threads(parallel, req, setup);
	if (ret < 0)
		goto out_config;

out_config:
	uninit_config();
out_thr:
	if (src)
		free(src);
	if (dst)
		free(dst);
	if (iv)
		free(iv);

	return ret;
}

static int test_sec_cipher_async(void *arg)
{
	int thread_id = (int)syscall(__NR_gettid);
	thread_data_t *pdata = (thread_data_t *)arg;
	struct wd_cipher_sess_setup *setup = pdata->setup;
	struct wd_cipher_req *req = pdata->req;
	struct cipher_testvec *tv = NULL;
	int cnt = g_times;
	handle_t h_sess;
	int ret;

	/* get resource */
	ret = get_cipher_resource(&tv, (int *)&setup->alg, (int *)&setup->mode);

	h_sess = wd_cipher_alloc_sess(setup);
	if (!h_sess) {
		ret = -1;
		return ret;
	}

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		printf("test sec cipher set key is failed!\n");
		goto out;;
	}

	pthread_mutex_lock(&mutex);
	// pthread_cond_wait(&cond, &mutex);
	/* run task */
	do {
try_do_again:
		ret = wd_do_cipher_async(h_sess, req);
		if (ret == -EBUSY) { // busy
			usleep(100);
			goto try_do_again;
		} else if (ret) {
			printf("test sec cipher send req is error!\n");
			goto out;
		}
		cnt--;
		g_count++; // g_count means data block numbers
	} while (cnt);

	printf("Test cipher async function thread_id is:%d\n", thread_id);

	pthread_mutex_unlock(&mutex);

	ret = 0;
out:
	if (h_sess)
		wd_cipher_free_sess(h_sess);

	return ret;
}

static void *_test_sec_cipher_async(void *data)
{
	test_sec_cipher_async(data);

	return NULL;
}

/* create poll threads */
static void *poll_func(void *arg)
{
	int ret;
	__u32 count = 0, index = 0;
	int i = 0;

	int expt = g_times * g_thread_num;

	while (1) {
		ret = wd_cipher_poll_ctx(g_ctx_cfg.ctxs[0].ctx, 1, &count);
		i++;
		// printf("cipher poll ctx: i=%d----------->\n", i);
		if (ret != -EAGAIN && ret < 0) {
			printf("poll ctx is error----------->\n");
			break;
		}

		index += count;
		count = 0;
		if (expt == index) {
			break;
		}
	}

	pthread_exit(NULL);
}

/*
 * Create 2 threads. one threads are enc/dec, and the other
 * is polling.
 */
static int test_async_create_threads(int thread_num, struct wd_cipher_req *reqs, struct wd_cipher_sess_setup *setups)
{
	pthread_attr_t attr;
	int i, ret;

	if (thread_num > NUM_THREADS - 1) {
		printf("can't creat %d threads", thread_num - 1);
		return -EINVAL;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < thread_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].setup = &setups[i];
		gettimeofday(&thr_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], &attr, _test_sec_cipher_async, &thr_data[i]);
		if (ret) {
			printf("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	ret = pthread_create(&system_test_thrds[i], &attr, poll_func, &thr_data[i]);

	pthread_attr_destroy(&attr);

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			printf("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	// asyn_thread_exit = 1;
	ret = pthread_join(system_test_thrds[i], NULL);
	if (ret) {
			printf("Join %dth thread fail!\n", i);
			return ret;
	}

	return 0;
}

static int sec_cipher_async_test(void)
{
	struct wd_cipher_req	req[NUM_THREADS];
	struct wd_cipher_sess_setup setup[NUM_THREADS];
	void *src = NULL, *dst = NULL, *iv = NULL;
	struct cipher_testvec *tv = NULL;
	thread_data_t datas[NUM_THREADS];
	int parallel = g_thread_num;
	int test_alg, test_mode;
	int i, ret;

	memset(datas, 0, sizeof(thread_data_t) * NUM_THREADS);
	memset(req, 0, sizeof(struct wd_cipher_req) * NUM_THREADS);
	/* get resource */
	ret = get_cipher_resource(&tv, &test_alg, &test_mode);
	int step = sizeof(char) * TEST_WORD_LEN;
	src = malloc(step * NUM_THREADS);
	if (!src) {
		ret = -ENOMEM;
		goto out_thr;
	}
	dst = malloc(step * NUM_THREADS);
	if (!dst) {
		ret = -ENOMEM;
		goto out_thr;
	}
	iv = malloc(step * NUM_THREADS);
	if (!iv) {
		ret = -ENOMEM;
		goto out_thr;
	}

	for (i = 0; i < parallel; i++) {
		req[i].src = src + i * step;
		memset(req[i].src, 0, step);
		memcpy(req[i].src, tv->ptext, g_pktlen);
		req[i].in_bytes = g_pktlen;

		req[i].dst = dst + i * step;
		req[i].out_bytes = tv->len;

		req[i].iv = iv + i * step;
		memset(req[i].iv, 0, step);
		if (test_mode == WD_CIPHER_CBC || test_mode == WD_CIPHER_XTS) {
			memcpy(req[i].iv, tv->iv, strlen(tv->iv));
			req[i].iv_bytes = strlen(tv->iv);
		}

		/* config arg */
		setup[i].alg = test_alg;
		setup[i].mode = test_mode;

		if (g_direction == 0)
			req[i].op_type = WD_CIPHER_ENCRYPTION;
		else {
			req[i].op_type = WD_CIPHER_DECRYPTION;
		}
		req[i].cb = async_cb;
		req[i].cb_param = &datas[i];
	}

	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC, &g_sched);
	if (ret) {
		printf("fail to init sigle ctx config!\n");
		goto out_thr;
	}

	ret = test_async_create_threads(parallel, req, setup);
	if (ret < 0)
		goto out_config;

out_config:
	uninit_config();
out_thr:
	if (src)
		free(src);
	if (dst)
		free(dst);
	if (iv)
		free(iv);

	return ret;
}

static __u32 sched_digest_pick_next_ctx(handle_t h_sched_ctx, const void *req, const struct sched_key *key)
{
	return 0;
}

static int init_digest_ctx_config(int type, int mode, struct wd_sched *sched)
{
	struct uacce_dev_list *list;
	int ret;

	list = wd_get_accel_list("digest");
	if (!list)
		return -ENODEV;


	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = 1;
	g_ctx_cfg.ctxs = calloc(1, sizeof(struct wd_ctx));
	if (!g_ctx_cfg.ctxs)
		return -ENOMEM;

	/* Just use first found dev to test here */
	g_ctx_cfg.ctxs[0].ctx = wd_request_ctx(list->dev);
	if (!g_ctx_cfg.ctxs[0].ctx) {
		ret = -EINVAL;
		printf("Fail to request ctx!\n");
		goto out;
	}
	g_ctx_cfg.ctxs[0].op_type = type;
	g_ctx_cfg.ctxs[0].ctx_mode = mode;

	sched->name = SCHED_SINGLE;
	sched->pick_next_ctx = sched_digest_pick_next_ctx;

	sched->poll_policy = sched_single_poll_policy;
	/*cipher init*/
	ret = wd_digest_init(&g_ctx_cfg, sched);
	if (ret) {
		printf("Fail to cipher ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;
out:
	free(g_ctx_cfg.ctxs);

	return ret;
}


static int test_sec_digest_sync_once(void)
{
	struct hash_testvec *tv = &sha256_tv_template[0];
	handle_t	h_sess = 0;
	struct wd_digest_sess_setup	setup;
	struct wd_digest_req req;
	int cnt = g_times;
	int ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC, &dg_sched);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	setup.alg = WD_DIGEST_SHA256;
	setup.mode = WD_DIGEST_NORMAL;
	printf("test alg: %s\n", "normal(sha256)");

	req.in  = malloc(BUFF_SIZE);
	if (!req.in) {
		printf("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;

	printf("req src in--------->:\n");
	hexdump(req.in, tv->psize);
	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		printf("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	req.out_bytes = tv->dsize;

	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* if mode is HMAC, should set key */
	//ret = wd_digest_set_key(&req, (const __u8*)tv->key, tv->ksize);
	//if (ret) {
	//	printf("req set key failed!\n");
	//	goto out;
	//}
	//printf("digest req key--------->:\n");
	//hexdump(req.key, tv->klen);

	while (cnt) {
		ret = wd_do_digest_sync(h_sess, &req);
		cnt--;
	}

	printf("Test digest sync function: output dst-->\n");
	hexdump(req.out, 64);

out:
	if (req.in)
		free(req.in);
	if (req.out)
		free(req.out);
	if (h_sess)
		wd_digest_free_sess(h_sess);
	uninit_config();

	return ret;
}

static void *digest_async_cb(void *data)
{
	// struct wd_digest_req *req = (struct wd_digest_req *)data;
	// memcpy(&g_async_req, req, sizeof(struct wd_digest_req));

	return NULL;
}

static int test_sec_digest_async_once(void)
{
	struct hash_testvec *tv = &sha256_tv_template[0];
	struct wd_digest_sess_setup	setup;
	handle_t	h_sess = 0;
	struct wd_digest_req req;
	int cnt = g_times;
	unsigned int recv = 0;
	int ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC, &dg_sched);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	setup.alg = WD_DIGEST_SHA256;
	setup.mode = WD_DIGEST_NORMAL;
	printf("test alg: %s\n", "normal(sha256)");

	req.in  = malloc(BUFF_SIZE);
	if (!req.in) {
		printf("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;

	printf("req src in--------->:\n");
	hexdump(req.in, tv->psize);
	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		printf("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	req.out_bytes = tv->dsize;

	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* if mode is HMAC, should set key */
	//ret = wd_digest_set_key(&req, (const __u8*)tv->key, tv->ksize);
	//if (ret) {
	//	printf("req set key failed!\n");
	//	goto out;
	//}
	//printf("digest req key--------->:\n");
	//hexdump(req.key, tv->klen);

	while (cnt) {
		req.cb = digest_async_cb;
		ret = wd_do_digest_async(h_sess, &req);
		if (ret < 0)
			goto out;
		cnt--;
	}

	/* poll thread */
	ret = wd_digest_poll_ctx(g_ctx_cfg.ctxs[0].ctx, g_times, &recv);

	printf("Test digest async : %u pkg ; output dst-->\n", recv);
	hexdump(req.out, 64);

out:
	if (req.in)
		free(req.in);
	if (req.out)
		free(req.out);
	if (h_sess)
		wd_digest_free_sess(h_sess);
	uninit_config();

	return ret;
}

int main(int argc, char *argv[])
{
	printf("this is a hisi sec test.\n");
	unsigned int algtype_class;
	g_thread_num = 1;
	int pktsize, keylen;

	if (!strcmp(argv[1], "-cipher")) {
		algtype_class = CIPHER_CLASS;
		g_testalg = strtoul((char*)argv[2], NULL, 10);
	} else if (!strcmp(argv[1], "-digest")) {
		algtype_class = DIGEST_CLASS;
		g_testalg = strtoul((char*)argv[2], NULL, 10);
	} else {
		printf("alg_class type error, please set a algorithm, cipher,"
		"digest, aead");
		return 0;
	}

	if (!strcmp(argv[3], "-optype")) {
		g_direction = strtoul((char*)argv[4], NULL, 10);
		if (algtype_class == DIGEST_CLASS) {
			//0 is normal mode, 1 is HMAC mode.
			alg_op_type = g_direction;
		}
	}

	if (!strcmp(argv[5], "-pktlen")) {
		pktsize = strtoul((char*)argv[6], NULL, 10);
		g_pktlen = pktsize;
	}
	if (!strcmp(argv[7], "-keylen")) {
		keylen = strtoul((char*)argv[8], NULL, 10);
		g_keylen = keylen;
	}

	if (!strcmp(argv[9], "-times")) {
		g_times = strtoul((char*)argv[10], NULL, 10);
	} else {
		g_times = 1;
	}
	printf("set global times is %lld\n", g_times);

	pthread_mutex_init(&mutex, NULL);
	if (!strcmp(argv[11], "-sync")) {
		if (algtype_class == CIPHER_CLASS) {
			if (!strcmp(argv[12], "-multi")) {
				g_thread_num = strtoul((char*)argv[13], NULL, 10);
				printf("currently cipher test is synchronize multi -%d threads!\n", g_thread_num);
				sec_cipher_sync_test();
			} else {
				test_sec_cipher_sync_once();
				printf("currently cipher test is synchronize once, one thread!\n");
			}
		} else if (algtype_class == DIGEST_CLASS) {
			if (!strcmp(argv[12], "-multi")) {
				g_thread_num = strtoul((char*)argv[13], NULL, 10);
				printf("currently digest test is synchronize multi -%d threads!\n", g_thread_num);
				//sec_digest_sync_test();
			} else {
				test_sec_digest_sync_once();
				printf("currently digest test is synchronize once, one thread!\n");
			}
		}
	} else if (!strcmp(argv[11], "-async")) {
		if (algtype_class == CIPHER_CLASS) {
			if (!strcmp(argv[12], "-multi")) {
				g_thread_num = strtoul((char*)argv[13], NULL, 10);
				printf("currently cipher test is asynchronous multi -%d threads!\n", g_thread_num);
				sec_cipher_async_test();
			} else {
				test_sec_cipher_async_once();
				printf("currently cipher test is asynchronous one, one thread!\n");
			}
		} else if (algtype_class == DIGEST_CLASS) {
			if (!strcmp(argv[12], "-multi")) {
				g_thread_num = strtoul((char*)argv[13], NULL, 10);
				printf("currently digest test is asynchronous multi -%d threads!\n", g_thread_num);
				//sec_digest_async_test();
			} else {
				test_sec_digest_async_once();
				printf("currently digest test is asynchronous one, one thread!\n");
			}
		}
	} else {
		printf("Please input a right session mode, -sync or -aync!\n");
		// ./test_hisi_sec -cipher 1 -optype 0 -pktlen 16 -keylen 16 -times 2 -sync -multi 1
		// ./test_hisi_sec -digest 0 -optype 0 -pktlen 16 -keylen 16 -times 2 -sync -multi 1
		return 0;
	}

	return 0;
}
