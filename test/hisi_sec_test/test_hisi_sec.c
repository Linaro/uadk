/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <getopt.h>

#include "test_hisi_sec.h"
#include "wd_cipher.h"
#include "wd_digest.h"
#include "sched_sample.h"

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
static struct wd_sched *g_sched;

static long long int g_times;
static unsigned int g_thread_num;
static int g_count; // total packets
static unsigned int g_testalg;
static unsigned int g_keylen;
static unsigned int g_pktlen;
static unsigned int g_direction;
static unsigned int g_alg_op_type;
static unsigned int g_ivlen;

char *skcipher_names[MAX_ALGO_PER_TYPE] =
	{"ecb(aes)", "cbc(aes)", "xts(aes)", "ofb(aes)", "cfb(aes)", "ecb(des3_ede)",
	"cbc(des3_ede)", "cbc(sm4)", "xts(sm4)", "ofb(sm4)", "cfb(sm4)", NULL,};

typedef struct _thread_data_t {
	int     tid;
	int     flag;
	int	mode;
	int	cpu_id;
	struct wd_cipher_req	*req;
	struct wd_cipher_sess_setup *setup;
	struct timeval start_tval;
	unsigned long long send_task_num;
	unsigned long long recv_task_num;
} thread_data_t;


typedef struct wd_thread_res {
	handle_t	h_sess;
	struct wd_digest_req	*req;
	unsigned long long send_num;
	unsigned long long recv_num;
	struct timeval start_tval;
	unsigned long long sum_perf;
} thread_data_d;

/**
 * struct test_sec_option - Define the test sec app option list.
 * @algclass: 0:cipher 1:digest
 * @algtype: The sub alg type, reference func get_cipher_resource.
 * @syncmode: 0:sync mode 1:async mode
 */
struct test_sec_option {
	__u32 algclass;
	__u32 algtype;
	__u32 optype;
	__u32 pktlen;
	__u32 keylen;
	__u32 times;
	__u32 syncmode;
	__u32 xmulti;
};

//static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t test_sec_mutex = PTHREAD_MUTEX_INITIALIZER;
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

static int sched_single_poll_policy(handle_t h_sched_ctx,
				    __u32 expect, __u32 *count)
{
	return 0;
}

static int init_sigle_ctx_config(int type, int mode)
{
	struct uacce_dev_list *list;
	int ret = 0;

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
	g_ctx_cfg.ctxs[0].ctx_mode = (__u8)mode;

	g_sched = sample_sched_alloc(SCHED_POLICY_RR, 1, MAX_NUMA_NUM, wd_cipher_poll_ctx);
	if (!g_sched) {
		printf("Fail to alloc sched!\n");
		goto out;
	}

	g_sched->name = SCHED_SINGLE;
	ret = sample_sched_fill_data(g_sched, list->dev->numa_id, mode, 0, 0, 0);
	if (ret) {
		printf("Fail to fill sched data!\n");
		goto out;
	}

	/*cipher init*/
	ret = wd_cipher_init(&g_ctx_cfg, g_sched);
	if (ret) {
		printf("Fail to cipher ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;
out:
	free(g_ctx_cfg.ctxs);
	sample_sched_release(g_sched);

	return ret;
}

static void uninit_config(void)
{
	int i;

	wd_cipher_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
	sample_sched_release(g_sched);
}

static void digest_uninit_config(void)
{
	int i;

	wd_digest_uninit();
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
	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
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
	req.out_bytes = tv->len;
	req.out_buf_bytes = BUFF_SIZE;

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
	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
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
	req.out_bytes = tv->len;
	req.out_buf_bytes = BUFF_SIZE;
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
		ret = wd_cipher_poll_ctx(0, 1, &num);
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

	pthread_mutex_lock(&test_sec_mutex);
	// pthread_cond_wait(&cond, &test_sec_mutex);
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

	pthread_mutex_unlock(&test_sec_mutex);

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
		req[i].out_buf_bytes = step;

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

	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
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

	pthread_mutex_lock(&test_sec_mutex);
	// pthread_cond_wait(&cond, &test_sec_mutex);
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
	pthread_mutex_unlock(&test_sec_mutex);
	printf("Test cipher async function thread_id is:%d\n", thread_id);

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
	__u32 count = 0;
	__u32 index = 0;
	int ret;

	int expt = g_times * g_thread_num;

	while (1) {
		ret = g_sched->poll_policy(g_sched->h_sched_ctx, 1, &count);
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
	int thread_id = (int)syscall(__NR_gettid);
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
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

	gettimeofday(&cur_tval, NULL);
	time_used = (double)((cur_tval.tv_sec - thr_data[0].start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - thr_data[0].start_tval.tv_usec);
	printf("time_used:%0.0f us, send task num:%llu\n", time_used, g_times * g_thread_num);
	speed = g_times * g_thread_num / time_used * 1000000;
	Perf = speed * g_pktlen / 1024; //B->KB
	printf("Pro-%d, thread_id-%d, speed:%f ops, Perf: %ld KB/s\n",
		getpid(), thread_id, speed, Perf);


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
		req[i].out_buf_bytes = step;

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

	ret = init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
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

/* ------------------digest alg, nomal mode and hmac mode------------------ */
static __u32 sched_digest_pick_next_ctx(handle_t h_sched_ctx, const void *req,
					const struct sched_key *key)
{
	/* alway return first ctx */
	return 0;
}

static int init_digest_ctx_config(int type, int mode)
{
	struct uacce_dev_list *list;
	struct wd_sched sched;
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

	sched.name = SCHED_SINGLE;
	sched.pick_next_ctx = sched_digest_pick_next_ctx;
	sched.poll_policy = sched_single_poll_policy;
	/* digest init */
	ret = wd_digest_init(&g_ctx_cfg, &sched);
	if (ret) {
		printf("Fail to digest ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;
out:
	free(g_ctx_cfg.ctxs);

	return ret;
}

int get_digest_resource(struct hash_testvec **alg_tv, int* alg, int* mode)
{
	struct hash_testvec *tmp_tv;
	struct hash_testvec *tv = NULL;
	int alg_type;
	int mode_type = 0;

	switch (g_testalg) {
		case 0:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sm3)");
					tv = &sm3_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sm3)");
					tv = &hmac_sm3_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WD_DIGEST_SM3;
			break;
		case 1:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(md5)");
					tv = &md5_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(md5)");
					tv = &hmac_md5_tv_template[0];
					break;
			}
			tv->dsize = 16;
			alg_type = WD_DIGEST_MD5;
			break;
		case 2:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha1)");
					tv = &sha1_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha1)");
					tv = &hmac_sha1_tv_template[0];
					break;
			}
			tv->dsize = 20;
			alg_type = WD_DIGEST_SHA1;
			break;
		case 3:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha256)");
					tv = &sha256_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha256)");
					tv = &hmac_sha256_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WD_DIGEST_SHA256;
			break;
		case 4:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha224)");
					tv = &sha224_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha224)");
					tv = &hmac_sha224_tv_template[0];
					break;
			}
			tv->dsize = 28;
			alg_type = WD_DIGEST_SHA224;
			break;
		case 5:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha384)");
					tv = &sha384_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha384)");
					tv = &hmac_sha384_tv_template[0];
					break;
			}
			tv->dsize = 48;
			alg_type = WD_DIGEST_SHA384;
			break;
		case 6:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha512)");
					tv = &sha512_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha512)");
					tv = &hmac_sha512_tv_template[0];
					break;
			}
			tv->dsize = 64;
			alg_type = WD_DIGEST_SHA512;
			break;
		case 7:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha512_224)");
					tv = &sha512_224_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha512_224");
					tv = &hmac_sha512_224_tv_template[0];
					break;
			}
			tv->dsize = 28;
			alg_type = WD_DIGEST_SHA512_224;
			break;
		case 8:
			switch (g_alg_op_type) {
				case 0:
					mode_type = WD_DIGEST_NORMAL;
					printf("test alg: %s\n", "normal(sha512_256)");
					tv = &sha512_256_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					printf("test alg: %s\n", "hmac(sha512_256)");
					tv = &hmac_sha512_256_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WD_DIGEST_SHA512_256;
			break;
		default:
			printf("keylenth error, default test alg: %s\n", "normal(sm3)");
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

static int sec_digest_sync_once(void)
{
	struct wd_digest_sess_setup setup;
	struct hash_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	struct timeval start_tval;
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	unsigned long cnt = g_times;
	int ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

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
	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;

	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* if mode is HMAC, should set key */
	if (setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8*)tv->key, tv->ksize);
		if (ret) {
			printf("sess set key failed!\n");
			goto out;
		}
		struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
		printf("------->tv key:%s\n", tv->key);
		printf("digest sess key--------->:\n");
		hexdump(sess->key, sess->key_bytes);
	}

	gettimeofday(&start_tval, NULL);
	while (cnt) {
		ret = wd_do_digest_sync(h_sess, &req);
		cnt--;
	}
	gettimeofday(&cur_tval, NULL);

	time_used = (float)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
		cur_tval.tv_usec - start_tval.tv_usec);
	speed = g_times / time_used * 1000000;
	Perf = speed * req.in_bytes / 1024;
	printf("time_used:%0.0f us, send task num:%lld\n", time_used, g_times);
	printf("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);
	hexdump(req.out, 64);

out:
	if (req.in)
		free(req.in);
	if (req.out)
		free(req.out);
	if (h_sess)
		wd_digest_free_sess(h_sess);
	digest_uninit_config();

	return ret;
}

static void *digest_async_cb(void *data)
{
	// struct wd_digest_req *req = (struct wd_digest_req *)data;
	// memcpy(&g_async_req, req, sizeof(struct wd_digest_req));

	return NULL;
}

void *digest_send_thread(void *data)
{
	thread_data_d *td_data = data;
	struct wd_digest_req *req = td_data->req;
	int try_cnt = 0;
	unsigned long cnt = 0;
	int ret;

	while (cnt < td_data->send_num) {
		req->cb = digest_async_cb;
		ret = wd_do_digest_async(td_data->h_sess, req);
		if (ret < 0) {
			usleep(100);
			try_cnt++;
			if (try_cnt > 100) {
				printf("Test digest current send fail 100 times !\n");
				break;
			}
			continue;
		}
		cnt++;
	}

	printf("Test digest multi send : %lu pkg !\n", cnt);
	return NULL;
}

void *digest_poll_thread(void *data)
{
	thread_data_d *td_data = data;
	struct wd_digest_req *req = td_data->req;
	unsigned int recv = 0;
	int expt = td_data->recv_num;
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	int cnt = 0;
	int ret;

	while (cnt < td_data->recv_num) {
		ret = wd_digest_poll_ctx(0, expt, &recv);
		if (ret < 0)
			usleep(100);

		if (recv == 0) {
			printf("current digest async poll --0-- pkg!\n");
			break;
		}
		expt -= recv;
		cnt += recv;
		recv = 0;
	}
	gettimeofday(&cur_tval, NULL);

	pthread_mutex_lock(&test_sec_mutex);
	time_used = (float)((cur_tval.tv_sec - td_data->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - td_data->start_tval.tv_usec);
	printf("time_used:%0.0f us, send task num:%d\n", time_used, cnt);
	speed = cnt / time_used * 1000000;
	Perf = speed * req->in_bytes / 1024; //B->KB
	printf("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);
	pthread_mutex_unlock(&test_sec_mutex);

	return NULL;
}

void *digest_sync_send_thread(void *data)
{
	thread_data_d *td_data = data;
	struct wd_digest_req *req = td_data->req;
	struct timeval cur_tval, start_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	int ret;
	int cnt = 0;

	gettimeofday(&start_tval, NULL);
	while (cnt < td_data->send_num) {
		ret = wd_do_digest_sync(td_data->h_sess, req);
		if (ret < 0) {
			usleep(100);
			printf("Test digest current send fail: have send %u pkg !\n", cnt);
			continue;
		}
		cnt++;
	}
	gettimeofday(&cur_tval, NULL);

	pthread_mutex_lock(&test_sec_mutex);
	time_used = (float)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - start_tval.tv_usec);
	printf("time_used:%0.0f us, send task num:%lld\n", time_used, td_data->send_num);
	speed = td_data->send_num / time_used * 1000000;
	Perf = speed * req->in_bytes / 1024; //B->KB
	printf("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);
	pthread_mutex_unlock(&test_sec_mutex);

	return NULL;
}

static int sec_digest_async_once(void)
{
	struct hash_testvec *tv = 0;
	struct wd_digest_sess_setup setup;
	static pthread_t send_td;
	static pthread_t poll_td;
	struct wd_digest_req req;
	thread_data_d td_data;
	handle_t h_sess = 0;
	int test_alg = 0;
	int test_mode = 0;
	int ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	get_digest_resource(&tv, &test_alg, &test_mode);
	memset(&req, 0, sizeof(struct wd_digest_req));
	setup.alg = test_alg;
	setup.mode = test_mode;

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
	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* send thread */
	td_data.req = &req;
	td_data.h_sess = h_sess;
	td_data.send_num = g_times;
	td_data.recv_num = g_times * g_thread_num;
	gettimeofday(&td_data.start_tval, NULL);
	ret = pthread_create(&send_td, NULL, digest_send_thread, &td_data);
	if (ret) {
		printf("kthread create fail at %s", __func__);
		goto out;
	}

	/* poll thread */
	ret = pthread_create(&poll_td, NULL, digest_poll_thread, &td_data);
	if (ret) {
		printf("kthread create fail at %s", __func__);
		goto out;
	}

	ret = pthread_join(send_td, NULL);
	if (ret) {
		printf("pthread_join fail at %s", __func__);
		goto out;
	}

	ret = pthread_join(poll_td, NULL);
	if (ret) {
		printf("pthread_join fail at %s", __func__);
		goto out;
	}

out:
	if (req.in)
		free(req.in);
	if (req.out)
		free(req.out);
	if (h_sess)
		wd_digest_free_sess(h_sess);
	digest_uninit_config();

	return ret;
}

static int sec_digest_sync_multi(void)
{
	struct wd_digest_sess_setup setup;
	struct hash_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	static pthread_t sendtd[64];
	thread_data_d td_data;
	int i, ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	req.in	= malloc(BUFF_SIZE);
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
	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* if mode is HMAC, should set key */
	if (setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8*)tv->key, tv->ksize);
		if (ret) {
			printf("sess set key failed!\n");
			goto out;
		}
		struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
		printf("------->tv key:%s\n", tv->key);
		printf("digest sess key--------->:\n");
		hexdump(sess->key, sess->key_bytes);
	}

	td_data.h_sess = h_sess;
	td_data.req = &req;

	/* send thread */
	td_data.send_num = g_times;
	td_data.recv_num = g_times;
	td_data.sum_perf = 0;
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_create(&sendtd[i], NULL, digest_sync_send_thread, &td_data);
		if (ret) {
			printf("Create send thread fail!\n");
			return ret;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			printf("Join sendtd thread fail!\n");
			return ret;
		}
	}

	printf("digest sync %u threads, speed:%llu ops, perf: %llu KB/s\n",
		g_thread_num, td_data.sum_perf,
		(td_data.sum_perf >> 10) * req.in_bytes);
	hexdump(req.out, 64);
out:
	if (req.in)
		free(req.in);
	if (req.out)
		free(req.out);
	if (h_sess)
		wd_digest_free_sess(h_sess);
	digest_uninit_config();

	return ret;
}


static int sec_digest_async_multi(void)
{
	struct hash_testvec *tv = 0;
	struct wd_digest_sess_setup	setup;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	static pthread_t sendtd[64];
	static pthread_t polltd;
	thread_data_d td_data;
	int test_alg = 0;
	int test_mode = 0;
	int i, ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		printf("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	get_digest_resource(&tv, &test_alg, &test_mode);
	memset(&req, 0, sizeof(struct wd_digest_req));
	setup.alg = test_alg;
	setup.mode = test_mode;

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

	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.has_next = 0;
	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	td_data.h_sess = h_sess;
	td_data.req = &req;

	/* send thread */
	td_data.send_num = g_times;
	td_data.recv_num = g_times * g_thread_num;
	td_data.sum_perf = 0;
	gettimeofday(&td_data.start_tval, NULL);
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_create(&sendtd[i], NULL, digest_send_thread, &td_data);
		if (ret) {
			printf("Create send thread fail!\n");
			return ret;
		}
	}

	/* poll thread */
	ret = pthread_create(&polltd, NULL, digest_poll_thread, &td_data);
	if (ret) {
		printf("Create poll thread fail!\n");
		return ret;
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			printf("Join sendtd thread fail!\n");
			return ret;
		}
	}
	ret = pthread_join(polltd, NULL);
	if (ret) {
		printf("Join polltd thread fail!\n");
		return ret;
	}

	hexdump(req.out, 64);
out:
	if (req.in)
		free(req.in);
	if (req.out)
		free(req.out);
	if (h_sess)
		wd_digest_free_sess(h_sess);
	digest_uninit_config();

	return ret;
}

static void test_sec_cmd_parse(int argc, char *argv[], struct test_sec_option *option)
{
    int option_index = 0;
	int c;

	static struct option long_options[] = {
        	{"cipher",    required_argument, 0,  1},
        	{"digest",    required_argument, 0,  2},
		{"optype",    required_argument, 0,  3},
		{"pktlen",    required_argument, 0,  4},
		{"keylen",    required_argument, 0,  5},
		{"times",     required_argument, 0,  6},
		{"sync",      no_argument,       0,  7},
		{"async",     no_argument,       0,  8},
		{"multi",     required_argument, 0,  9},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 1:
			option->algclass = CIPHER_CLASS;
			option->algtype = strtol(optarg, NULL, 0);
			break;
		case 2:
			option->algclass = DIGEST_CLASS;
			option->algtype = strtol(optarg, NULL, 0);
			break;
		case 3:
			option->optype = strtol(optarg, NULL, 0);
			break;
		case 4:
			option->pktlen = strtol(optarg, NULL, 0);
			break;
		case 5:
			option->keylen = strtol(optarg, NULL, 0);
			break;
		case 6:
			option->times = strtol(optarg, NULL, 0);
			break;
		case 7:
			option->syncmode = 0;
			break;
		case 8:
			option->syncmode = 1;
			break;
		case 9:
			option->xmulti = strtol(optarg, NULL, 0);
			break;
		default:
			printf("bad input parameter, exit\n");
			exit(-1);
		}
	}
}

static int test_sec_option_convert(struct test_sec_option *option)
{
	if (option->algclass > DIGEST_CLASS) {
		printf("alg_class type error, please set a algorithm, cipher or "
			   "digest. The aead is not support now.");
		return -EINVAL;
	}
	if (option->syncmode > 1) {
		printf("Please input a right session mode, 0:sync 1:async. \n");
		return -EINVAL;
	}

	g_testalg = option->algtype;
	g_pktlen = option->pktlen;
	g_keylen = option->keylen;
	g_times = option->times ? option->times : 1;
	printf("set global times is %lld\n", g_times);

	g_thread_num = option->xmulti ? option->xmulti : 1;

	g_direction = option->optype;
	if (option->algclass == DIGEST_CLASS) {
		//0 is normal mode, 1 is HMAC mode, 3 is long hash mode.
		g_alg_op_type = g_direction;
		if (g_direction == 3) {
			g_alg_op_type = 0;
			g_ivlen = 1;
		}
	}

	return 0;
}

static int test_sec_default_case()
{
	g_testalg = 0;
	g_times = 10;
	g_pktlen = 16;
	g_keylen = 16;
	printf("Test sec Cipher parameter default, alg:ecb(aes), set_times:10,"
		"set_pktlen:16 bytes, set_keylen:128 bit.\n");
	return	test_sec_cipher_sync_once();
}

static int test_sec_run(__u32 sync_mode, __u32 alg_class)
{
	int ret = 0;

	if (sync_mode == 0) {
		if (alg_class == CIPHER_CLASS) {
			if (g_thread_num > 1) {
				printf("currently cipher test is synchronize multi -%d threads!\n", g_thread_num);
				ret = sec_cipher_sync_test();
			} else {
				ret = test_sec_cipher_sync_once();
				printf("currently cipher test is synchronize once, one thread!\n");
			}
		} else if (alg_class == DIGEST_CLASS) {
			if (g_thread_num > 1) {
				printf("currently digest test is synchronize multi -%d threads!\n", g_thread_num);
				ret = sec_digest_sync_multi();
			} else {
				ret = sec_digest_sync_once();
				printf("currently digest test is synchronize once, one thread!\n");
			}
		}
	} else {
		if (alg_class == CIPHER_CLASS) {
			if (g_thread_num > 1) {
				printf("currently cipher test is asynchronous multi -%d threads!\n", g_thread_num);
				ret = sec_cipher_async_test();
			} else {
				ret = test_sec_cipher_async_once();
				printf("currently cipher test is asynchronous one, one thread!\n");
			}
		} else if (alg_class == DIGEST_CLASS) {
			if (g_thread_num > 1) {
				printf("currently digest test is asynchronous multi -%d threads!\n", g_thread_num);
				ret = sec_digest_async_multi();
			} else {
				ret = sec_digest_async_once();
				printf("currently digest test is asynchronous one, one thread!\n");
			}
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	struct test_sec_option option = {0};
	int ret = 0;

	printf("this is a hisi sec test.\n");

	g_thread_num = 1;
	if (!argv[1]) {
		return test_sec_default_case();
	}

	test_sec_cmd_parse(argc, argv, &option);
	ret = test_sec_option_convert(&option);
	if (ret)
		return ret;

	pthread_mutex_init(&test_sec_mutex, NULL);

	return test_sec_run(option.syncmode, option.algclass);
}
