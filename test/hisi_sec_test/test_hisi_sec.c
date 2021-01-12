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
#include "wd_aead.h"
#include "sched_sample.h"

#define SEC_TST_PRT printf
#define HW_CTX_SIZE (24 * 1024)
#define BUFF_SIZE 1024
#define IV_SIZE   256
#define THREADS_NUM	64
#define SVA_THREADS	64
#define USE_CTX_NUM	64
#define BYTES_TO_MB	20

#define SCHED_SINGLE "sched_single"
#define SCHED_NULL_CTX_SIZE	4
#define TEST_WORD_LEN	4096
#define MAX_ALGO_PER_TYPE 12
#define MIN_SVA_BD_NUM	1

static struct wd_ctx_config g_ctx_cfg;
static struct wd_sched *g_sched;

static long long int g_times;
static unsigned int g_thread_num;
static unsigned int g_testalg;
static unsigned int g_keylen;
static unsigned int g_pktlen;
static unsigned int g_block;
static unsigned int g_blknum;
static unsigned int g_direction;
static unsigned int g_alg_op_type;
static unsigned int g_ivlen;
static unsigned int g_syncmode;
static unsigned int g_ctxnum;
static unsigned int g_data_fmt = 0;
static unsigned int g_sgl_num = 0;
static pthread_spinlock_t lock = 0;
static __u32 last_ctx = 0;

char *skcipher_names[MAX_ALGO_PER_TYPE] =
	{"ecb(aes)", "cbc(aes)", "xts(aes)", "ofb(aes)", "cfb(aes)", "ecb(des3_ede)",
	"cbc(des3_ede)", "cbc(sm4)", "xts(sm4)", "ofb(sm4)", "cfb(sm4)", NULL,};
struct sva_bd {
	char *src;
	char *dst;
};

struct sva_bd_pool {
	struct sva_bd *bds;
};

typedef struct _thread_data_t {
	int     tid;
	int     flag;
	int	mode;
	int	cpu_id;
	struct sva_bd_pool *bd_pool;
	struct wd_cipher_req	*req;
	struct wd_cipher_sess_setup *setup;
	struct timeval start_tval;
	unsigned long long send_task_num;
	unsigned long long recv_task_num;
} thread_data_t;

typedef struct wd_thread_res {
	handle_t	h_sess;
	struct wd_digest_req	*req;
	struct wd_aead_req	*areq;
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
	__u32 ctxnum;
	__u32 block;
	__u32 blknum;
	__u32 sgl_num;
};

//static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t test_sec_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t system_test_thrds[THREADS_NUM];
static thread_data_t thr_data[THREADS_NUM];

static void hexdump(char *buff, unsigned int len)
{
	unsigned int i;
	if (!buff) {
		SEC_TST_PRT("hexdump input buff is NULL!");
		return;
	}

	for (i = 0; i < len; i++) {
		SEC_TST_PRT("\\0x%02x", buff[i]);
		if ((i + 1) % 8 == 0)
			SEC_TST_PRT("\n");
	}
	SEC_TST_PRT("\n");
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
			tv->ivlen = 16;
			break;
		case 3:
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_OFB;
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
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cbc_tv_template[0];
			break;
		case 8:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_XTS;
			if (g_keylen != 32) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_xts_tv_template[0];
			tv->ivlen = 16;
			break;
		case 9:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_OFB;
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_ofb_tv_template_128[0];
			break;
		case 10:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_CFB;
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_cfb_tv_template_128[0];
			break;
	case 16:
			alg_type = WD_CIPHER_AES;
			mode_type = WD_CIPHER_CBC;
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &aes_cbc_perf_128[0];
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

static int init_ctx_config(int type, int mode)
{
	struct uacce_dev_list *list;
	int ret = 0;
	int i;

	list = wd_get_accel_list("cipher");
	if (!list) {
		printf("Fail to get cipher device\n");
		return -ENODEV;
	}
	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = g_ctxnum;
	g_ctx_cfg.ctxs = calloc(g_ctxnum, sizeof(struct wd_ctx));
	if (!g_ctx_cfg.ctxs)
		return -ENOMEM;

	for (i = 0; i < g_ctxnum; i++) {
		g_ctx_cfg.ctxs[i].ctx = wd_request_ctx(list->dev);
		g_ctx_cfg.ctxs[i].op_type = type;
		g_ctx_cfg.ctxs[i].ctx_mode = (__u8)mode;
	}

	g_sched = sample_sched_alloc(SCHED_POLICY_RR, 1, MAX_NUMA_NUM, wd_cipher_poll_ctx);
	if (!g_sched) {
		printf("Fail to alloc sched!\n");
		goto out;
	}

	/* If there is no numa, we defualt config to zero */
	if (list->dev->numa_id < 0)
		list->dev->numa_id = 0;

	g_sched->name = SCHED_SINGLE;
	ret = sample_sched_fill_data(g_sched, list->dev->numa_id, mode, 0, 0, g_ctxnum - 1);
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

static void test_sec_sgl_free(__u8 data_fmt, void *buff)
{
	struct wd_datalist *sgl;
	struct wd_datalist *tmp;

	if (!buff || data_fmt != WD_SGL_BUF)
		return;

	sgl = (struct wd_datalist*)buff;
	while (sgl) {
		tmp = sgl;
		sgl = sgl->next;
		free(tmp);
	}
}

static void *test_sec_buff_create(__u8 data_fmt, void *buff, unsigned int size)
{
	struct wd_datalist *cur;
	struct wd_datalist *next;
	struct wd_datalist *head;
	int size_unit, i;
	unsigned int tail_size;

	if (data_fmt != WD_SGL_BUF)
		return buff;

	/* Divisible is guaranteed by the inputer */
	size_unit = size / g_sgl_num;
	tail_size = size % g_sgl_num;

	head = malloc(sizeof(struct wd_datalist));
	if (!head) {
		SEC_TST_PRT("Fail to alloc memory for sgl head!\n");
		return NULL;
	}

	head->data = buff;
	head->len = size_unit;
	head->next = NULL;
	cur = head;

	for (i = 1; i < g_sgl_num; i++) {
		next = malloc(sizeof(struct wd_datalist));
		if (!next) {
			SEC_TST_PRT("Fail to alloc memory for sgl!\n");
			test_sec_sgl_free(data_fmt, head);
			return NULL;
		}
		next->data = buff + i * size_unit;
		next->len = size_unit;
		if (i == g_sgl_num - 1)
			next->len += tail_size;

		next->next = NULL;
		cur->next = next;
		cur = next;
	}

	return head;
}

static int test_sec_cipher_sync_once(void)
{
	struct cipher_testvec *tv = NULL;
	handle_t	h_sess = 0;
	struct wd_cipher_sess_setup	setup;
	struct wd_cipher_req req;
	struct timeval bg_tval, cur_tval;
	int thread_id = (int)syscall(__NR_gettid);
	unsigned long Perf = 0;
	float speed, time_used;
	int pid = getpid();
	int cnt = g_times;
	int ret;
	void *src_bak = NULL;
	void *dst_bak = NULL;

	/* config setup */
	ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
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

	req.src = malloc(BUFF_SIZE);
	if (!req.src) {
		SEC_TST_PRT("req src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	src_bak = req.src;

	memcpy(req.src, tv->ptext, tv->len);
	req.in_bytes = g_pktlen;
	req.src = test_sec_buff_create(g_data_fmt, req.src, g_pktlen);
	if (!req.src)
		goto out;

	SEC_TST_PRT("req src--------->:\n");
	if (g_data_fmt == WD_SGL_BUF)
		hexdump(req.list_src->data, tv->len);
	else
		hexdump(req.src, g_pktlen);

	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		SEC_TST_PRT("req dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	dst_bak = req.dst;

	req.dst = test_sec_buff_create(g_data_fmt, req.dst, g_pktlen);
	if (!req.dst)
		goto out;

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.mode != WD_CIPHER_ECB) {
		req.iv_bytes = strlen(tv->iv);
		if (tv->ivlen > 0)
			req.iv_bytes = tv->ivlen;
		memset(req.iv, 0, req.iv_bytes);
		if (tv->iv)
			memcpy(req.iv, tv->iv, strlen(tv->iv));
		SEC_TST_PRT("cipher req iv--------->:\n");
		hexdump(req.iv, req.iv_bytes);
	}
	req.out_bytes = tv->len;
	req.out_buf_bytes = g_pktlen;
	req.data_fmt = g_data_fmt;

	h_sess = wd_cipher_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("req set key failed!\n");
		goto out;
	}
	SEC_TST_PRT("cipher req key--------->:\n");
	// hexdump(h_sess->key, tv->klen);

	gettimeofday(&bg_tval, NULL);
	while (cnt) {
		ret = wd_do_cipher_sync(h_sess, &req);
		cnt--;
	}
	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - bg_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - bg_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, g_times);
	speed = g_times / time_used * 1000000;
	Perf = speed * g_pktlen / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
			thread_id, speed, Perf);

	SEC_TST_PRT("Test cipher sync function: output dst-->\n");
	if (g_data_fmt == WD_SGL_BUF)
		hexdump(req.list_dst->data, req.out_bytes);
	else
		hexdump(req.dst, req.out_bytes);

out:
	test_sec_sgl_free(g_data_fmt, req.src);
	test_sec_sgl_free(g_data_fmt, req.dst);
	if (src_bak)
		free(src_bak);
	if (dst_bak)
		free(dst_bak);
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
	struct timeval bg_tval, cur_tval;
	int thread_id = (int)syscall(__NR_gettid);
	unsigned long Perf = 0;
	float speed, time_used;
	int pid = getpid();
	void *src_bak = NULL;
	void *dst_bak = NULL;

	int cnt = g_times;
	__u32 num = 0;
	int ret;

	memset(&data, 0, sizeof(thread_data_t));
	data.req = &req;
	/* config setup */
	ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
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
		SEC_TST_PRT("req src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	src_bak = req.src;

	memcpy(req.src, tv->ptext, g_pktlen);
	req.in_bytes = g_pktlen;
	SEC_TST_PRT("req src--------->:\n");
	hexdump(req.src, g_pktlen);
	req.src = test_sec_buff_create(g_data_fmt, req.src, g_pktlen);
	if (!req.src)
		goto out;

	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		SEC_TST_PRT("req dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	dst_bak = req.dst;

	req.dst = test_sec_buff_create(g_data_fmt, req.dst, g_pktlen);
	if (!req.dst)
		goto out;

	req.data_fmt = g_data_fmt;

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.mode != WD_CIPHER_ECB) {
		req.iv_bytes = strlen(tv->iv);
		if (tv->ivlen > 0)
			req.iv_bytes = tv->ivlen;
		memset(req.iv, 0, req.iv_bytes);
		if (tv->iv)
			memcpy(req.iv, tv->iv, strlen(tv->iv));
		SEC_TST_PRT("cipher req iv--------->:\n");
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
		SEC_TST_PRT("req set key failed!\n");
		goto out;
	}
	SEC_TST_PRT("cipher req key--------->:\n");
	// hexdump(h_sess->key, tv->klen);
	gettimeofday(&bg_tval, NULL);
	while (cnt) {
		req.cb = async_cb;
		req.cb_param = &data;
		ret = wd_do_cipher_async(h_sess, &req);
		if (ret < 0) {
			goto out;
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
	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - bg_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - bg_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, g_times);
	speed = g_times / time_used * 1000000;
	Perf = speed * g_pktlen / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
			thread_id, speed, Perf);

	usleep(100000);
out:
	test_sec_sgl_free(g_data_fmt, req.src);
	test_sec_sgl_free(g_data_fmt, req.dst);
	if (src_bak)
		free(src_bak);
	if (dst_bak)
		free(dst_bak);
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
	SEC_TST_PRT("cipher req src--------->:\n");
	if (req->data_fmt == WD_SGL_BUF) {
		hexdump(req->list_src->data, req->list_src->len);
	} else {
		hexdump(req->src, req->in_bytes);
	}

	SEC_TST_PRT("ivlen = %d, cipher req iv--------->:\n", req->iv_bytes);
	hexdump(req->iv, req->iv_bytes);

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		goto out;;
	}

	SEC_TST_PRT("cipher req key--------->:\n");

	pthread_mutex_lock(&test_sec_mutex);
	/* run task */
	while (cnt) {
		ret = wd_do_cipher_sync(h_sess, req);
		cnt--;
		pdata->send_task_num++;
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, pdata->send_task_num++);
	speed = pdata->send_task_num / time_used * 1000000;
	Perf = speed * pktlen / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", pid,
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

	if (thread_num > THREADS_NUM - 1) {
		SEC_TST_PRT("can't creat %d threads", thread_num - 1);
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
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
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
	struct wd_cipher_req	req[THREADS_NUM];
	struct wd_cipher_sess_setup setup[THREADS_NUM];
	void *src = NULL, *dst = NULL, *iv = NULL;
	int parallel = g_thread_num;
	struct cipher_testvec *tv = NULL;
	int test_alg, test_mode;
	int ret, i;
	unsigned int len;

	memset(req, 0, sizeof(struct wd_cipher_req) * THREADS_NUM);
	memset(setup, 0, sizeof(struct wd_cipher_sess_setup) * THREADS_NUM);

	/* get resource */
	ret = get_cipher_resource(&tv, &test_alg, &test_mode);

	int step = sizeof(char) * TEST_WORD_LEN;
	src = malloc(step * THREADS_NUM);
	if (!src) {
		ret = -ENOMEM;
		goto out_thr;
	}

	dst = malloc(step * THREADS_NUM);
	if (!dst) {
		ret = -ENOMEM;
		goto out_thr;
	}

	iv = malloc(step * THREADS_NUM);
	if (!iv) {
		ret = -ENOMEM;
		goto out_thr;
	}

	for (i = 0; i < parallel; i++) {
		req[i].src = src + i * step;
		memset(req[i].src, 0, step);

		len = g_pktlen < tv->len ? g_pktlen : tv->len;
		memcpy(req[i].src, tv->ptext, len);
		req[i].in_bytes = len;
		req[i].src = test_sec_buff_create(g_data_fmt, req[i].src, len);
		if (!req[i].src)
			goto out_thr;

		req[i].dst = dst + i * step;
		req[i].out_bytes = tv->len;
		req[i].out_buf_bytes = step;
		req[i].dst = test_sec_buff_create(g_data_fmt, req[i].dst, step);
		if (!req[i].dst)
			goto out_thr;

		req[i].data_fmt = g_data_fmt;

		req[i].iv = iv + i * step;
		memset(req[i].iv, 0, step);
		if (test_mode != WD_CIPHER_ECB) {
			req[i].iv_bytes = strlen(tv->iv);
			if (tv->ivlen > 0)
				req[i].iv_bytes = tv->ivlen;
			memcpy(req[i].iv, tv->iv, strlen(tv->iv));
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

	ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("fail to init sigle ctx config!\n");
		goto out_thr;
	}

	ret = test_sync_create_threads(parallel, req, setup);
	if (ret < 0)
		goto out_config;

out_config:
	uninit_config();
out_thr:
	for (i = 0; i < parallel; i++) {
		test_sec_sgl_free(g_data_fmt, req[i].src);
		test_sec_sgl_free(g_data_fmt, req[i].dst);
	}

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
		SEC_TST_PRT("test sec cipher set key is failed!\n");
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
			SEC_TST_PRT("test sec cipher send req is error!\n");
			goto out;
		}
		cnt--;
	} while (cnt);
	pthread_mutex_unlock(&test_sec_mutex);
	SEC_TST_PRT("Test cipher async function thread_id is:%d\n", thread_id);

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
			SEC_TST_PRT("poll ctx is error----------->\n");
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

	if (thread_num > THREADS_NUM - 1) {
		SEC_TST_PRT("can't creat %d threads", thread_num - 1);
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
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	ret = pthread_create(&system_test_thrds[i], &attr, poll_func, &thr_data[i]);

	pthread_attr_destroy(&attr);

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	// asyn_thread_exit = 1;
	ret = pthread_join(system_test_thrds[i], NULL);
	if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (double)((cur_tval.tv_sec - thr_data[0].start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - thr_data[0].start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%llu\n", time_used, g_times * g_thread_num);
	speed = g_times * g_thread_num / time_used * 1000000;
	Perf = speed * g_pktlen / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%f ops, Perf: %ld KB/s\n",
		getpid(), thread_id, speed, Perf);

	return 0;
}

static int sec_cipher_async_test(void)
{
	struct wd_cipher_req	req[THREADS_NUM];
	struct wd_cipher_sess_setup setup[THREADS_NUM];
	void *src = NULL, *dst = NULL, *iv = NULL;
	struct cipher_testvec *tv = NULL;
	thread_data_t datas[THREADS_NUM];
	int parallel = g_thread_num;
	int test_alg, test_mode;
	int i, ret;

	memset(datas, 0, sizeof(thread_data_t) * THREADS_NUM);
	memset(req, 0, sizeof(struct wd_cipher_req) * THREADS_NUM);
	/* get resource */
	ret = get_cipher_resource(&tv, &test_alg, &test_mode);
	int step = sizeof(char) * TEST_WORD_LEN;
	src = malloc(step * THREADS_NUM);
	if (!src) {
		ret = -ENOMEM;
		goto out_thr;
	}
	dst = malloc(step * THREADS_NUM);
	if (!dst) {
		ret = -ENOMEM;
		goto out_thr;
	}
	iv = malloc(step * THREADS_NUM);
	if (!iv) {
		ret = -ENOMEM;
		goto out_thr;
	}

	for (i = 0; i < parallel; i++) {
		req[i].src = src + i * step;
		memset(req[i].src, 0, step);
		memcpy(req[i].src, tv->ptext, g_pktlen);
		req[i].in_bytes = g_pktlen;
		req[i].src = test_sec_buff_create(g_data_fmt, req[i].src, g_pktlen);
		if (!req[i].src)
			goto out_thr;

		req[i].dst = dst + i * step;
		req[i].out_bytes = tv->len;
		req[i].out_buf_bytes = step;
		req[i].dst = test_sec_buff_create(g_data_fmt, req[i].dst, step);
		if (!req[i].dst)
			goto out_thr;

		req[i].data_fmt = g_data_fmt;

		req[i].iv = iv + i * step;
		memset(req[i].iv, 0, step);
		if (test_mode != WD_CIPHER_ECB) {
			req[i].iv_bytes = strlen(tv->iv);
			if (tv->ivlen > 0)
				req[i].iv_bytes = tv->ivlen;
			memcpy(req[i].iv, tv->iv, req[i].iv_bytes);
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

	ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("fail to init sigle ctx config!\n");
		goto out_thr;
	}

	ret = test_async_create_threads(parallel, req, setup);
	if (ret < 0)
		goto out_config;

out_config:
	uninit_config();
out_thr:
	for (i = 0; i < parallel; i++) {
		test_sec_sgl_free(g_data_fmt, req[i].src);
		test_sec_sgl_free(g_data_fmt, req[i].dst);
	}
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
		SEC_TST_PRT("Fail to request ctx!\n");
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
		SEC_TST_PRT("Fail to digest ctx!\n");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sm3)");
					tv = &sm3_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sm3)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(md5)");
					tv = &md5_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(md5)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha1)");
					tv = &sha1_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha1)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha256)");
					tv = &sha256_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha256)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha224)");
					tv = &sha224_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha224)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha384)");
					tv = &sha384_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha384)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha512)");
					tv = &sha512_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha512)");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha512_224)");
					tv = &sha512_224_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha512_224");
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
					SEC_TST_PRT("test alg: %s\n", "normal(sha512_256)");
					tv = &sha512_256_tv_template[0];
					break;
				case 1:
					mode_type = WD_DIGEST_HMAC;
					SEC_TST_PRT("test alg: %s\n", "hmac(sha512_256)");
					tv = &hmac_sha512_256_tv_template[0];
					break;
			}
			tv->dsize = 32;
			alg_type = WD_DIGEST_SHA512_256;
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
	void *bak_in = NULL;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	req.in = malloc(BUFF_SIZE);
	if (!req.in) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_in = req.in;

	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;
	req.in = test_sec_buff_create(g_data_fmt, req.in, req.in_bytes);
	if (!req.in) {
		ret = -1;
		goto out;
	}

	SEC_TST_PRT("req src in--------->:\n");
	hexdump(bak_in, tv->psize);

	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	printf("req.data_fmtaaaa = %u\n", g_data_fmt);
	req.data_fmt = g_data_fmt;
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
			SEC_TST_PRT("sess set key failed!\n");
			goto out;
		}
		struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
		SEC_TST_PRT("------->tv key:%s\n", tv->key);
		SEC_TST_PRT("digest sess key--------->:\n");
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
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, g_times);
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);
	hexdump(req.out, req.out_bytes);

out:
	test_sec_sgl_free(g_data_fmt, req.in);
	if (bak_in)
		free(bak_in);
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
				SEC_TST_PRT("Test digest current send fail 100 times !\n");
				break;
			}
			continue;
		}
		cnt++;
	}

	SEC_TST_PRT("Test digest multi send : %lu pkg !\n", cnt);
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
			SEC_TST_PRT("current digest async poll --0-- pkg!\n");
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
	SEC_TST_PRT("time_used:%0.0f us, send task num:%d\n", time_used, cnt);
	speed = cnt / time_used * 1000000;
	Perf = speed * req->in_bytes / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
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
			SEC_TST_PRT("Test digest current send fail: have send %u pkg !\n", cnt);
			continue;
		}
		cnt++;
	}
	gettimeofday(&cur_tval, NULL);

	pthread_mutex_lock(&test_sec_mutex);
	time_used = (float)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, td_data->send_num);
	speed = td_data->send_num / time_used * 1000000;
	Perf = speed * req->in_bytes / 1024; //B->KB
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
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
	void *bak_in = NULL;
	int test_alg = 0;
	int test_mode = 0;
	int ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	get_digest_resource(&tv, &test_alg, &test_mode);
	memset(&req, 0, sizeof(struct wd_digest_req));
	setup.alg = test_alg;
	setup.mode = test_mode;

	req.in = malloc(BUFF_SIZE);
	if (!req.in) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_in = req.in;

	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;
	req.in = test_sec_buff_create(g_data_fmt, req.in, req.in_bytes);
	if (!req.in) {
		ret = -1;
		goto out;
	}

	SEC_TST_PRT("req src in--------->:\n");
	hexdump(bak_in, tv->psize);

	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.has_next = 0;
	req.data_fmt = g_data_fmt;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* if mode is HMAC, should set key */
	if (setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8*)tv->key, tv->ksize);
		if (ret) {
			SEC_TST_PRT("sess set key failed!\n");
			goto out;
		}
		struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
		SEC_TST_PRT("------->tv key:%s\n", tv->key);
		SEC_TST_PRT("digest sess key--------->:\n");
		hexdump(sess->key, sess->key_bytes);
	}

	/* send thread */
	td_data.req = &req;
	td_data.h_sess = h_sess;
	td_data.send_num = g_times;
	td_data.recv_num = g_times * g_thread_num;
	gettimeofday(&td_data.start_tval, NULL);
	ret = pthread_create(&send_td, NULL, digest_send_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out;
	}

	/* poll thread */
	ret = pthread_create(&poll_td, NULL, digest_poll_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out;
	}

	ret = pthread_join(send_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out;
	}

	ret = pthread_join(poll_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out;
	}
	hexdump(req.out, req.out_bytes);
out:
	test_sec_sgl_free(g_data_fmt, req.in);
	if (bak_in)
		free(bak_in);
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
	void *bak_in = NULL;
	int i, ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	req.in	= malloc(BUFF_SIZE);
	if (!req.in) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	bak_in = req.in;

	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;
	req.in = test_sec_buff_create(g_data_fmt, req.in, req.in_bytes);
	if (!req.in) {
		ret = -1;
		goto out;
	}

	SEC_TST_PRT("req src in--------->:\n");
	hexdump(bak_in, tv->psize);

	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
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
			SEC_TST_PRT("sess set key failed!\n");
			goto out;
		}
		struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
		SEC_TST_PRT("------->tv key:%s\n", tv->key);
		SEC_TST_PRT("digest sess key--------->:\n");
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
			SEC_TST_PRT("Create send thread fail!\n");
			return ret;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sendtd thread fail!\n");
			return ret;
		}
	}

	SEC_TST_PRT("digest sync %u threads, speed:%llu ops, perf: %llu KB/s\n",
		g_thread_num, td_data.sum_perf,
		(td_data.sum_perf >> 10) * req.in_bytes);

	hexdump(req.out, req.out_bytes);
out:
	test_sec_sgl_free(g_data_fmt, req.in);
	if (bak_in)
		free(bak_in);
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
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	get_digest_resource(&tv, &test_alg, &test_mode);
	memset(&req, 0, sizeof(struct wd_digest_req));
	setup.alg = test_alg;
	setup.mode = test_mode;

	req.in  = malloc(BUFF_SIZE);
	if (!req.in) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;
	SEC_TST_PRT("req src in--------->:\n");
	hexdump(req.in, tv->psize);
	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
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
			SEC_TST_PRT("sess set key failed!\n");
			goto out;
		}
		struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
		SEC_TST_PRT("------->tv key:%s\n", tv->key);
		SEC_TST_PRT("digest sess key--------->:\n");
		hexdump(sess->key, sess->key_bytes);
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
			SEC_TST_PRT("Create send thread fail!\n");
			return ret;
		}
	}

	/* poll thread */
	ret = pthread_create(&polltd, NULL, digest_poll_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sendtd thread fail!\n");
			return ret;
		}
	}
	ret = pthread_join(polltd, NULL);
	if (ret) {
		SEC_TST_PRT("Join polltd thread fail!\n");
		return ret;
	}

	hexdump(req.out, req.out_bytes);
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

/* ------------------------------aead alg, ccm mode and gcm mode------------------ */
static __u32 sched_aead_pick_next_ctx(handle_t h_sched_ctx, const void *req,
	const struct sched_key *key)
{
	return 0;
}

static int init_aead_ctx_config(int type, int mode)
{
	struct uacce_dev_list *list;
	struct wd_sched sched;
	int ret;

	list = wd_get_accel_list("aead");
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
		SEC_TST_PRT("Fail to request ctx!\n");
		goto out;
	}
	g_ctx_cfg.ctxs[0].op_type = type;
	g_ctx_cfg.ctxs[0].ctx_mode = mode;

	sched.name = SCHED_SINGLE;
	sched.pick_next_ctx = sched_aead_pick_next_ctx;
	sched.poll_policy = sched_single_poll_policy;
	/* aead init*/
	ret = wd_aead_init(&g_ctx_cfg, &sched);
	if (ret) {
		SEC_TST_PRT("Fail to aead ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;

out:
	free(g_ctx_cfg.ctxs);
	return ret;
}

static void aead_uninit_config(void)
{
	int i;

	wd_aead_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
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
		alg_type = WD_CIPHER_AES;
		mode_type = WD_CIPHER_CCM;
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
		alg_type = WD_CIPHER_AES;
		mode_type = WD_CIPHER_GCM;
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
		alg_type = WD_CIPHER_AES;
		mode_type = WD_CIPHER_CBC;
		dalg_type = WD_DIGEST_SHA256;
		dmode_type = WD_DIGEST_HMAC;
		SEC_TST_PRT("test alg: %s\n", "hmac(sha256),cbc(aes)");
		tv = &hmac_sha256_aes_cbc_tv_temp[0];
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

static int sec_aead_sync_once(void)
{
	struct wd_aead_sess_setup setup;
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	struct timeval start_tval;
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	unsigned long cnt = g_times;
	void *bak_src = NULL;
	void *bak_dst = NULL;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int ret;

	/* config setup */
	ret = init_aead_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_aead_req));
	ret = get_aead_resource(&tv, (int *)&setup.calg,
		(int *)&setup.cmode,(int *)&setup.dalg, (int *)&setup.dmode);
	if (ret) {
		SEC_TST_PRT("get aead resource fail!\n");
		return ret;
	}

	h_sess = wd_aead_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* should set key */
	hexdump((char *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM ||
		setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out;
	}

	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	req.assoc_bytes = tv->alen;
	if (g_direction == 0) {
		in_size = req.assoc_bytes + tv->plen;
	} else {
		in_size = req.assoc_bytes + tv->clen;
	}
	if (in_size > BUFF_SIZE) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto out;
	}
	req.src  = malloc(in_size);
	if (!req.src) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_src = req.src;

	memset(req.src, 0, in_size);
	// copy the assoc data in the front of in data
	SEC_TST_PRT("aead set assoc_bytes: %u\n", req.assoc_bytes);
	if (g_direction == 0) {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + req.assoc_bytes), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + req.assoc_bytes), tv->ctext, tv->clen);
		req.in_bytes = tv->clen - auth_size;
	}

	if (g_direction == 0) {
		req.out_bytes = req.assoc_bytes + tv->clen;
	} else {
		req.out_bytes = req.assoc_bytes + tv->plen;
	}

	hexdump(req.src, in_size);
	req.src = test_sec_buff_create(g_data_fmt, req.src, in_size);
	if (!req.src) {
		ret = -1;
		goto out;
	}

	req.out_buf_bytes = req.out_bytes + auth_size;
	// alloc out buffer memory
	req.dst = malloc(req.out_buf_bytes);
	if (!req.dst) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	bak_dst = req.dst;
	req.dst = test_sec_buff_create(g_data_fmt, req.dst, req.out_buf_bytes);
	if (!req.dst) {
		ret = -1;
		goto out;
	}

	// set iv
	req.iv = malloc(AES_BLOCK_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_BLOCK_SIZE;
	else
		iv_len = AES_BLOCK_SIZE;
	req.iv_bytes = iv_len;
	memcpy(req.iv, tv->iv, iv_len);

	req.data_fmt = g_data_fmt;

	gettimeofday(&start_tval, NULL);
	while (cnt) {
		ret = wd_do_aead_sync(h_sess, &req);
		cnt--;
	}
	gettimeofday(&cur_tval, NULL);

	time_used = (float)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - start_tval.tv_usec);
	speed = g_times / time_used * 1000000;
	Perf = speed * req.in_bytes / 1024; //B->KB
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, g_times);
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);

	hexdump(bak_dst, req.out_bytes);
out:
	test_sec_sgl_free(g_data_fmt, req.src);
	test_sec_sgl_free(g_data_fmt, req.dst);
	if (bak_src)
		free(bak_src);
	if (bak_dst)
		free(bak_dst);
	if (req.iv)
		free(req.iv);
	if (h_sess)
		wd_aead_free_sess(h_sess);
	aead_uninit_config();

	return ret;
}

static void *aead_async_cb(struct wd_aead_req *req, void *cb_param)
{
	//struct wd_aead_req *req = (struct wd_aead_req *)data;
	//SEC_TST_PRT("Test digest callback run!\n");

	return NULL;
}

void *aead_send_thread(void *data)
{
	thread_data_d *td_data = data;
	struct wd_aead_req *req = td_data->areq;
	unsigned long cnt = 0;
	int try_cnt = 0;
	int ret;

	while (cnt < td_data->send_num) {
		req->cb = aead_async_cb;
		ret = wd_do_aead_async(td_data->h_sess, req);
		if (ret < 0) {
			usleep(100);
			try_cnt++;
			if (try_cnt > 100) {
				SEC_TST_PRT("Test aead current send fail 100 times !\n");
				break;
			}
			continue;
		}
		cnt++;
	}
	SEC_TST_PRT("Test aead multi send : %lu pkg !\n", cnt);

	return NULL;
}

void *aead_poll_thread(void *data)
{
	thread_data_d *td_data = data;
	struct wd_aead_req *req = td_data->areq;
	unsigned int recv = 0;
	int expt = td_data->recv_num;
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	unsigned long cnt = 0;
	int ret;

	while (cnt < td_data->recv_num) {
		ret = wd_aead_poll_ctx(0, expt, &recv);
		if (ret < 0)
			usleep(100);

		if (recv == 0) {
			SEC_TST_PRT("current aead async poll --0-- pkg!\n");
			break;
		}
		expt -= recv;
		cnt += recv;
		recv = 0;
	}
	gettimeofday(&cur_tval, NULL);

	SEC_TST_PRT("current aead async poll recv: %lu pkg!\n", cnt);
	pthread_mutex_lock(&test_sec_mutex);
	time_used = (float)((cur_tval.tv_sec - td_data->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - td_data->start_tval.tv_usec);
	speed = cnt / time_used * 1000000;
	Perf = speed * req->in_bytes / 1024; //B->KB
	pthread_mutex_unlock(&test_sec_mutex);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%ld\n", time_used, cnt);
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);

	return NULL;
}

void *aead_sync_send_thread(void *data)
{
	thread_data_d *td_data = data;
	struct wd_aead_req *req = td_data->areq;
	struct timeval cur_tval, start_tval;
	unsigned long Perf = 0;
	double speed, time_used;
	int ret;
	int cnt = 0;

	gettimeofday(&start_tval, NULL);
	while (cnt < td_data->send_num) {
		ret = wd_do_aead_sync(td_data->h_sess, req);
		if (ret < 0) {
			usleep(100);
			SEC_TST_PRT("Test aead current send fail: have send %u pkg !\n", cnt);
			continue;
		}
		cnt++;
	}
	gettimeofday(&cur_tval, NULL);

	pthread_mutex_lock(&test_sec_mutex);
	time_used = (double)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - start_tval.tv_usec);
	speed = td_data->send_num / time_used * 1000000;
	Perf = speed * req->in_bytes / 1024; //B->KB
	pthread_mutex_unlock(&test_sec_mutex);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%lld\n", time_used, td_data->
send_num);
	SEC_TST_PRT("Pro-%d, thread_id-%d, speed:%0.3f ops, Perf: %ld KB/s\n", getpid(),
			(int)syscall(__NR_gettid), speed, Perf);

	__atomic_add_fetch(&td_data->sum_perf, speed, __ATOMIC_RELAXED);

	return NULL;
}

static int sec_aead_async_once(void)
{
	struct wd_aead_sess_setup setup;
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	static pthread_t send_td;
	static pthread_t poll_td;
	thread_data_d td_data;
	void *bak_src = NULL;
	void *bak_dst = NULL;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int ret;

	/* config setup */
	ret = init_aead_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_aead_req));
	ret = get_aead_resource(&tv, (int *)&setup.calg, (int *)&setup.cmode,
				  (int *)&setup.dalg, (int *)&setup.dmode);
	if (ret) {
		SEC_TST_PRT("get aead resource fail!\n");
		return ret;
	}

	h_sess = wd_aead_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* should set key */
	hexdump((char *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM ||
		setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out;
	}
	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	req.assoc_bytes = tv->alen;
	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_src = req.src;

	// copy the assoc data in the front of in data
	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > BUFF_SIZE) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto out;
	}
	if (g_direction == 0) {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + tv->alen), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + tv->alen), tv->ctext, tv->clen);
		req.in_bytes = tv->clen - auth_size;
	}

	req.src = test_sec_buff_create(g_data_fmt, req.src, in_size);
	if (!req.src) {
		ret = -1;
		goto out;
	}

	SEC_TST_PRT("aead req src in--------->: %u\n", tv->alen + req.in_bytes);
	hexdump(bak_src, tv->alen + req.in_bytes);

	// alloc out buffer memory
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_dst = req.dst;

	req.out_buf_bytes = BUFF_SIZE;
	if (g_direction == 0)
		req.out_bytes = tv->alen + tv->clen;
	else
		req.out_bytes = tv->alen + tv->plen;

	req.dst = test_sec_buff_create(g_data_fmt, req.dst, req.out_bytes);
	if (!req.dst) {
		ret = -1;
		goto out;
	}

	// set iv
	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_BLOCK_SIZE;
	else
		iv_len = AES_BLOCK_SIZE;
	req.iv_bytes = iv_len;
	memcpy(req.iv, tv->iv, iv_len);

	req.data_fmt = g_data_fmt;

	/* send thread */
	td_data.areq = &req;
	td_data.h_sess = h_sess;
	td_data.send_num = g_times;
	td_data.recv_num = g_times * g_thread_num;
	gettimeofday(&td_data.start_tval, NULL);
	ret = pthread_create(&send_td, NULL, aead_send_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out;
	}

	/* poll thread */
	ret = pthread_create(&poll_td, NULL, aead_poll_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out;
	}

	ret = pthread_join(send_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out;
	}

	ret = pthread_join(poll_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out;
	}

	hexdump(bak_dst, req.out_bytes);
out:
	test_sec_sgl_free(g_data_fmt, req.src);
	test_sec_sgl_free(g_data_fmt, req.dst);
	if (bak_src)
		free(bak_src);
	if (bak_dst)
		free(bak_dst);
	if (req.iv)
		free(req.iv);
	if (h_sess)
		wd_aead_free_sess(h_sess);
	aead_uninit_config();

	return ret;
}

static int sec_aead_sync_multi(void)
{
	struct wd_aead_sess_setup setup;
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	static pthread_t sendtd[64];
	thread_data_d td_data;
	void *bak_src = NULL;
	void *bak_dst = NULL;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int i, ret;

	/* config setup */
	ret = init_aead_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_aead_req));
	ret = get_aead_resource(&tv, (int *)&setup.calg,
		(int *)&setup.cmode,(int *)&setup.dalg, (int *)&setup.dmode);
	if (ret) {
		SEC_TST_PRT("get aead resource fail!\n");
		return ret;
	}

	h_sess = wd_aead_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* should set key */
	hexdump((char *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM ||
		setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out;
	}
	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	req.assoc_bytes = tv->alen;
	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_src = req.src;

	// copy the assoc data in the front of in data
	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > BUFF_SIZE) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto out;
	}
	if (g_direction == 0) {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + tv->alen), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + tv->alen), tv->ctext, tv->clen);
		req.in_bytes = tv->clen - auth_size;
	}
	req.src = test_sec_buff_create(g_data_fmt, req.src, req.in_bytes);
	if (!req.src) {
		ret = -1;
		goto out;
	}

	SEC_TST_PRT("aead req src in--------->: %u\n", tv->alen + req.in_bytes);
	hexdump(req.src, tv->alen + req.in_bytes);

	// alloc out buffer memory
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_dst = req.dst;

	req.out_buf_bytes = BUFF_SIZE;
	if (g_direction == 0)
		req.out_bytes = tv->alen + tv->clen;
	else
		req.out_bytes = tv->alen + tv->plen;

	req.dst = test_sec_buff_create(g_data_fmt, req.dst, req.out_bytes);
	if (!req.dst) {
		ret = -1;
		goto out;
	}

	// set iv
	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_BLOCK_SIZE;
	else
		iv_len = AES_BLOCK_SIZE;
	req.iv_bytes = iv_len;
	memcpy(req.iv, tv->iv, iv_len);

	td_data.h_sess = h_sess;
	td_data.areq = &req;
	/* send thread */
	td_data.send_num = g_times;
	td_data.recv_num = g_times;
	td_data.sum_perf = 0;

	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_create(&sendtd[i], NULL, aead_sync_send_thread, &td_data);
		if (ret) {
			SEC_TST_PRT("Create send thread fail!\n");
			return ret;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sendtd thread fail!\n");
			return ret;
		}
	}

	hexdump(req.dst, req.out_bytes);
out:
	test_sec_sgl_free(g_data_fmt, req.src);
	test_sec_sgl_free(g_data_fmt, req.dst);
	if (bak_src)
		free(bak_src);
	if (bak_dst)
		free(bak_dst);
	if (req.iv)
		free(req.iv);
	if (h_sess)
		wd_aead_free_sess(h_sess);
	aead_uninit_config();

	return ret;
}

static int sec_aead_async_multi(void)
{
	struct wd_aead_sess_setup setup;
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	static pthread_t send_td[64];
	static pthread_t poll_td;
	thread_data_d td_data;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int i, ret;

	/* config setup */
	ret = init_aead_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_aead_req));
	ret = get_aead_resource(&tv, (int *)&setup.calg, (int *)&setup.cmode,
				  (int *)&setup.dalg, (int *)&setup.dmode);
	if (ret) {
		SEC_TST_PRT("get aead resource fail!\n");
		return ret;
	}

	h_sess = wd_aead_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}

	/* should set key */
	hexdump((char *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM ||
		setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out;
	}
	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	req.assoc_bytes = tv->alen;
	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	// copy the assoc data in the front of in data
	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > BUFF_SIZE) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto out;
	}
	if (g_direction == 0) {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + tv->alen), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(req.src, tv->assoc, tv->alen);
		memcpy((req.src + tv->alen), tv->ctext, tv->clen);
		req.in_bytes = tv->clen - auth_size;
	}

	SEC_TST_PRT("aead req src in--------->: %u\n", tv->alen + req.in_bytes);
	hexdump(req.src, tv->alen + req.in_bytes);

	// alloc out buffer memory
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	req.out_buf_bytes = BUFF_SIZE;
	if (g_direction == 0)
		req.out_bytes = tv->alen + tv->clen;
	else
		req.out_bytes = tv->alen + tv->plen;

	// set iv
	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_BLOCK_SIZE;
	else
		iv_len = AES_BLOCK_SIZE;
	req.iv_bytes = iv_len;
	memcpy(req.iv, tv->iv, iv_len);

	/* send thread */
	td_data.areq = &req;
	td_data.h_sess = h_sess;
	td_data.send_num = g_times;
	td_data.recv_num = g_times * g_thread_num;
	td_data.sum_perf = 0;
	gettimeofday(&td_data.start_tval, NULL);
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_create(&send_td[i], NULL, aead_send_thread, &td_data);
		if (ret) {
			SEC_TST_PRT("kthread create fail at %s", __func__);
			goto out;
		}
	}

	/* poll thread */
	ret = pthread_create(&poll_td, NULL, aead_poll_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out;
	}
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(send_td[i], NULL);
		if (ret) {
			SEC_TST_PRT("pthread_join fail at %s", __func__);
			goto out;
		}
	}

	ret = pthread_join(poll_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out;
	}

	hexdump(req.dst, req.out_bytes);
out:
	if (req.src)
		free(req.src);
	if (req.dst)
		free(req.dst);
	if (req.iv)
		free(req.iv);
	if (h_sess)
		wd_aead_free_sess(h_sess);
	aead_uninit_config();

	return ret;
}

/* --------------------------------------SVA perf  test-------------------------------*/
int init_bd_pool(thread_data_t *td)
{
	struct cipher_testvec *tv = &aes_cbc_tv_template_128[0];
	unsigned long step;
	int i;

	td->bd_pool = malloc(sizeof(struct sva_bd_pool));
	if (!td->bd_pool) {
		SEC_TST_PRT("init bd pool alloc thread failed!\n");
		free(td->bd_pool);
		return -ENOMEM;
	}
	td->bd_pool->bds = malloc(g_blknum * sizeof(struct sva_bd));
	// make the block not align to 4K
	step = sizeof(char) * g_block;
	for (i = 0; i < g_blknum; i++) {
		td->bd_pool->bds[i].src = (char *)malloc(step);
		td->bd_pool->bds[i].dst = (char *)malloc(step);
		memcpy(td->bd_pool->bds[i].src, tv->ptext, tv->len);
	}

	return 0;
}

void free_bd_pool(thread_data_t *td)
{
	int i;

	if (td->bd_pool) {
		if (td->bd_pool->bds) {
			for (i = 0; i < g_blknum; i++) {
				free(td->bd_pool->bds[i].src);
				free(td->bd_pool->bds[i].dst);
			}
			free(td->bd_pool->bds);
		}
		free(td->bd_pool);
	}
}

static void *sva_sec_cipher_async(void *arg)
{
	thread_data_t *pdata = (thread_data_t *)arg;
	struct wd_cipher_sess_setup *setup = pdata->setup;
	struct wd_cipher_req *req = pdata->req;
	struct cipher_testvec *tv = NULL;
	unsigned int count = 0;
	int cnt = g_times;
	handle_t h_sess;
	int ret;
	int j;

	/* get resource */
	ret = get_cipher_resource(&tv, (int *)&setup->alg, (int *)&setup->mode);

	h_sess = wd_cipher_alloc_sess(setup);
	if (!h_sess)
		return NULL;

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		goto out;;
	}

	/* run task */
	do {
try_do_again:
		j = count % g_blknum;
		req->src = pdata->bd_pool->bds[j].src;
		req->dst = pdata->bd_pool->bds[j].dst;
		ret = wd_do_cipher_async(h_sess, req);
		if (ret == -EBUSY) { // busy
			usleep(100);
			goto try_do_again;
		} else if (ret) {
			SEC_TST_PRT("test sec cipher send req is error!\n");
			goto out;
		}
		cnt--;
		count++; // count means data block numbers
	} while (cnt);

	ret = 0;
out:
	wd_cipher_free_sess(h_sess);
	return NULL;
}

/* create poll threads */
static void *sva_poll_func(void *arg)
{
	__u32 count = 0;
	__u32 recv = 0;
	int ret;

	int expt = g_times * g_thread_num;

	while (1) {
		ret = wd_cipher_poll(1, &count);
		if (ret < 0 && ret != -EAGAIN) {
			SEC_TST_PRT("poll ctx error: %d\n", ret);
			break;
		}
		recv += count;
		if (expt == recv)
			break;
	}

	pthread_exit(NULL);

	return NULL;
}

static int sva_async_create_threads(int thread_num, struct wd_cipher_req *reqs,
	struct wd_cipher_sess_setup *setups, thread_data_t *tds)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct timeval start_tval, cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	pthread_attr_t attr;
	int i, ret;

	if (thread_num > SVA_THREADS) {
		SEC_TST_PRT("can't creat %d threads", thread_num);
		return -EINVAL;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].setup = &setups[i];
		thr_data[i].bd_pool = tds[i].bd_pool;
		ret = pthread_create(&system_test_thrds[i], &attr, sva_sec_cipher_async, &thr_data[i]);
		if (ret) {
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	ret = pthread_create(&system_test_thrds[i], &attr, sva_poll_func, NULL);
	if (ret) {
		SEC_TST_PRT("Failed to create poll thread, ret:%d\n", ret);
		return ret;
	}
	pthread_attr_destroy(&attr);
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	// asyn_thread_exit = 1;
	ret = pthread_join(system_test_thrds[i], NULL);
	if (ret) {
		SEC_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (double)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%llu\n", time_used, g_times * g_thread_num);
	speed = g_times * g_thread_num / time_used * 1000000;
	Perf = speed * g_pktlen / 1024; //B->KB
	SEC_TST_PRT("Async mode Pro-%d, thread_id-%d, speed:%f ops, Perf: %ld KB/s\n",
		getpid(), thread_id, speed, Perf);

	return 0;
}

static void *sva_sec_cipher_sync(void *arg)
{
	thread_data_t *pdata = (thread_data_t *)arg;
	struct wd_cipher_sess_setup *setup = pdata->setup;
	struct wd_cipher_req *req = pdata->req;
	struct cipher_testvec *tv = NULL;
	unsigned int count = 0;
	handle_t h_sess;
	int cnt = g_times;
	int ret;
	int j;

	ret = get_cipher_resource(&tv, (int *)&setup->alg, (int *)&setup->mode);

	h_sess = wd_cipher_alloc_sess(setup);
	if (!h_sess)
		return NULL;

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		goto out;;
	}

	/* run task */
	while (cnt) {
		j = count % g_blknum;
		req->src = pdata->bd_pool->bds[j].src;
		req->dst = pdata->bd_pool->bds[j].dst;
		ret = wd_do_cipher_sync(h_sess, req);
		cnt--;
		pdata->send_task_num++;
		count++;
	}

out:
	wd_cipher_free_sess(h_sess);
	return NULL;
}

static int sva_sync_create_threads(int thread_num, struct wd_cipher_req *reqs,
	struct wd_cipher_sess_setup *setups, thread_data_t *tds)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct timeval start_tval, cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	pthread_attr_t attr;
	int i, ret;

	if (thread_num > SVA_THREADS) {
		SEC_TST_PRT("can't creat %d threads", thread_num);
		return -EINVAL;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].setup = &setups[i];
		thr_data[i].bd_pool = tds[i].bd_pool;
		ret = pthread_create(&system_test_thrds[i], &attr,
			sva_sec_cipher_sync, &thr_data[i]);
		if (ret) {
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	thr_data[i].tid = i;
	pthread_attr_destroy(&attr);
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (double)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%llu\n", time_used, g_times * g_thread_num);
	speed = g_times * g_thread_num / time_used * 1000000;
	Perf = speed * g_pktlen / 1024; //B->KB
	SEC_TST_PRT("Sync mode avg Pro-%d, thread_id-%d, speed:%f ops, Perf: %ld KB/s\n",
		getpid(), thread_id, speed, Perf);

	return 0;
}

static __u32 sva_sched_pick_next_ctx(handle_t h_sched_ctx, const void *req,
				     const struct sched_key *key)
{
	__u32 index;

	pthread_spin_lock(&lock);

	if (++last_ctx == g_ctx_cfg.ctx_num)
		last_ctx = 0;
	index = last_ctx;

	pthread_spin_unlock(&lock);

	return index;
}

static int sva_sched_poll_policy(handle_t h_sched_ctx, __u32 expect,
				 __u32 *count)
{
	int recv = 0;
	int ret = 0;
	__u32 cnt;
	int i;

	if (unlikely(g_ctx_cfg.ctxs[0].ctx_mode != CTX_MODE_ASYNC)) {
		SEC_TST_PRT("ctx mode is not AYNC!\n");
		*count = 0;
		return -1;
	}

	for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
		ret = wd_cipher_poll_ctx(i, 1, &cnt);
		/* ret is 0 means no error and recv 1 finished task */
		if (!ret)
			recv++;
		/* here is an error, return ret and recv num currently */
		else if (ret != -EAGAIN)
			break;
	}

	*count = recv;

	return ret;
}

static int sva_init_ctx_config(int type, int mode)
{
	struct uacce_dev_list *list;
	struct wd_sched sched;
	struct wd_ctx *ctx_attr;
	int ret;
	int i;

	list = wd_get_accel_list("cipher");
	if (!list)
		return -ENODEV;

	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	if (g_ctxnum > USE_CTX_NUM)
		SEC_TST_PRT("ctx nums request too much!\n");

	ctx_attr = malloc(g_ctxnum * sizeof(struct wd_ctx));
	if (!ctx_attr) {
		SEC_TST_PRT("malloc ctx_attr memory fail!\n");
		return -ENOMEM;
	}
	memset(ctx_attr, 0, g_ctxnum * sizeof(struct wd_ctx));

	/* Just use first found dev to test here */
	for (i = 0; i < g_ctxnum; i++) {
		ctx_attr[i].ctx = wd_request_ctx(list->dev);
		if (!ctx_attr[i].ctx) {
			ret = -EINVAL;
			SEC_TST_PRT("Fail to request ctx!\n");
			goto out;
		}
		ctx_attr[i].op_type = type;
		ctx_attr[i].ctx_mode = mode;
	}

	g_ctx_cfg.ctx_num = g_ctxnum;
	g_ctx_cfg.ctxs = ctx_attr;
	sched.name = "sched_multi";
	sched.pick_next_ctx = sva_sched_pick_next_ctx;
	sched.poll_policy = sva_sched_poll_policy;
	/*cipher init*/
	ret = wd_cipher_init(&g_ctx_cfg, &sched);
	if (ret) {
		SEC_TST_PRT("Fail to cipher ctx!\n");
		goto out;
	}
	wd_free_list_accels(list);

	return 0;
out:
	free(ctx_attr);
	return ret;
}

static void sva_uninit_config(void)
{
	int i;

	wd_cipher_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
}

static int sec_sva_test(void)
{
	struct wd_cipher_req	req[SVA_THREADS];
	struct wd_cipher_sess_setup setup[SVA_THREADS];
	thread_data_t datas[SVA_THREADS];
	struct cipher_testvec *tv = NULL;
	int threads = g_thread_num;
	int test_alg, test_mode;
	void *src = NULL;
	void *dst = NULL;
	void *iv = NULL;
	int i = 0;
	int j = 0;
	int step;
	int cpsize;
	int ret;

	memset(datas, 0, sizeof(thread_data_t) * g_thread_num);
	memset(req, 0, sizeof(struct wd_cipher_req) * g_thread_num);
	memset(setup, 0, sizeof(struct wd_cipher_sess_setup) * g_thread_num);

	if (g_syncmode == 0)
		ret = sva_init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	else
		ret = sva_init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("fail to init ctx config!\n");
		goto out_thr;
	}

	for (i = 0; i < threads; i++) {
		ret = init_bd_pool(&datas[i]);
		if (ret)
			goto out_thr;
	}

	ret = get_cipher_resource(&tv, &test_alg, &test_mode);
	step = sizeof(char) * g_pktlen;

	src = malloc(step * g_thread_num);
	if (!src) {
		ret = -ENOMEM;
		goto out_thr;
	}
	dst = malloc(step * g_thread_num);
	if (!dst) {
		ret = -ENOMEM;
		goto out_thr;
	}
	iv = malloc(step * g_thread_num);
	if (!iv) {
		ret = -ENOMEM;
		goto out_thr;
	}

	cpsize = step;
	if (step > BUFF_SIZE)
		cpsize = BUFF_SIZE;

	for (i = 0; i < threads; i++) {
		req[i].src = src + i * step;
		memcpy(req[i].src, tv->ptext, cpsize);
		req[i].in_bytes = step;

		req[i].dst = dst + i * step;
		req[i].out_bytes = tv->len;
		req[i].out_buf_bytes = step;

		req[i].iv = iv + i * step;
		memset(req[i].iv, 0, step);

		req[i].iv_bytes = strlen(tv->iv);
		if (tv->ivlen > 0)
			req[i].iv_bytes = tv->ivlen;
		memcpy(req[i].iv, tv->iv, req[i].iv_bytes);

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

	if (g_syncmode == 0)
		ret = sva_sync_create_threads(threads, req, setup, datas);
	else
		ret = sva_async_create_threads(threads, req, setup, datas);
	if (ret < 0)
		goto out_config;

out_config:
	sva_uninit_config();
out_thr:
	for (j = i - 1; j >= 0; j--) {
		free_bd_pool(&datas[j]);
	}

	if (src)
		free(src);
	if (dst)
		free(dst);
	if (iv)
		free(iv);

	return ret;
}

static void print_help(void)
{
	SEC_TST_PRT("NAME\n");
	SEC_TST_PRT("    test_hisi_sec: test wd sec function,etc\n");
	SEC_TST_PRT("USAGE\n");
	SEC_TST_PRT("    test_hisi_sec [--cipher] [--digest] [--aead] [--perf]\n");
	SEC_TST_PRT("    test_hisi_sec [--optype] [--pktlen] [--keylen] [--times]\n");
	SEC_TST_PRT("    test_hisi_sec [--multi] [--sync] [--async] [--help]\n");
	SEC_TST_PRT("    test_hisi_sec [--block] [--blknum] [--ctxnum]\n");
	SEC_TST_PRT("    numactl --cpubind=0  --membind=0,1 ./test_hisi_sec xxxx\n");
	SEC_TST_PRT("        specify numa nodes for cpu and memory\n");
	SEC_TST_PRT("DESCRIPTION\n");
	SEC_TST_PRT("    [--cipher ]:\n");
	SEC_TST_PRT("        specify symmetric cipher algorithm\n");
	SEC_TST_PRT("        0 : AES-ECB; 1 : AES-CBC;  2 : AES-XTS;  3 : AES-OFB\n");
	SEC_TST_PRT("        4 : AES-CFB; 5 : 3DES-ECB; 6 : 3DES-CBC; 7 : SM4-CBC\n");
	SEC_TST_PRT("        8 : SM4-XTS; 9 : SM4-OFB; 10 : SM4-CFB;\n");
	SEC_TST_PRT("    [--digest ]:\n");
	SEC_TST_PRT("        specify symmetric hash algorithm\n");
	SEC_TST_PRT("        0 : SM3;    1 : MD5;    2 : SHA1;   3 : SHA256\n");
	SEC_TST_PRT("        4 : SHA224; 5 : SHA384; 6 : SHA512; 7 : SHA512_224\n");
	SEC_TST_PRT("        8 : SHA512_256\n");
	SEC_TST_PRT("    [--aead ]:\n");
	SEC_TST_PRT("        specify symmetric aead algorithm\n");
	SEC_TST_PRT("        0 : AES-CCM; 1 : AES-GCM;  2 : Hmac(sha256),cbc(aes)\n");
	SEC_TST_PRT("    [--sync]: start synchronous mode test\n");
	SEC_TST_PRT("    [--async]: start asynchronous mode test\n");
	SEC_TST_PRT("    [--optype]:\n");
	SEC_TST_PRT("        0 : encryption operation or normal mode for hash\n");
	SEC_TST_PRT("        1 : decryption operation or hmac mode for hash\n");
	SEC_TST_PRT("    [--pktlen]:\n");
	SEC_TST_PRT("        set the length of BD message in bytes\n");
	SEC_TST_PRT("    [--keylen]:\n");
	SEC_TST_PRT("        set the key length in bytes\n");
	SEC_TST_PRT("    [--times]:\n");
	SEC_TST_PRT("        set the number of sent messages\n");
	SEC_TST_PRT("    [--multi]:\n");
	SEC_TST_PRT("        set the number of threads\n");
	SEC_TST_PRT("    [--block]:\n");
	SEC_TST_PRT("        set the memory size allocated for each BD message\n");
	SEC_TST_PRT("    [--blknum]:\n");
	SEC_TST_PRT("        the number of memory blocks in the pre-allocated BD message memory pool\n");
	SEC_TST_PRT("    [--ctxnum]:\n");
	SEC_TST_PRT("        the number of QP queues used by the entire test task\n");
	SEC_TST_PRT("    [--help]  = usage\n");
	SEC_TST_PRT("Example\n");
	SEC_TST_PRT("    ./test_hisi_sec --cipher 0 --sync --optype 0 \n");
	SEC_TST_PRT("    	     --pktlen 16 --keylen 16 --times 1 --multi 1\n");
	SEC_TST_PRT("    ./test_hisi_sec --perf --sync --pktlen 1024 --block 1024 \n");
	SEC_TST_PRT("    	     --blknum 100000 --times 10000 --multi 1 --ctxnum 1\n");
	SEC_TST_PRT("UPDATE:2020-11-06\n");
}

static void test_sec_cmd_parse(int argc, char *argv[], struct test_sec_option *option)
{
	int option_index = 0;
	int c;

	static struct option long_options[] = {
		{"cipher",    required_argument, 0,  1},
		{"digest",    required_argument, 0,  2},
		{"aead",      required_argument, 0,  3},
		{"perf",      no_argument,       0,  4},
		{"optype",    required_argument, 0,  5},
		{"pktlen",    required_argument, 0,  6},
		{"keylen",    required_argument, 0,  7},
		{"times",     required_argument, 0,  8},
		{"sync",      no_argument,       0,  9},
		{"async",     no_argument,       0, 10},
		{"multi",     required_argument, 0,  11},
		{"ctxnum",    required_argument, 0,  12},
		{"block",     required_argument, 0,  13},
		{"blknum",    required_argument, 0,  14},
		{"help",      no_argument,       0,  15},
		{"sglnum",    required_argument, 0,  16},
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
			option->algclass = AEAD_CLASS;
			option->algtype = strtol(optarg, NULL, 0);
			break;
		case 4:
			option->algclass = PERF_CLASS;
			break;
		case 5:
			option->optype = strtol(optarg, NULL, 0);
			break;
		case 6:
			option->pktlen = strtol(optarg, NULL, 0);
			break;
		case 7:
			option->keylen = strtol(optarg, NULL, 0);
			break;
		case 8:
			option->times = strtol(optarg, NULL, 0);
			break;
		case 9:
			option->syncmode = 0;
			break;
		case 10:
			option->syncmode = 1;
			break;
		case 11:
			option->xmulti = strtol(optarg, NULL, 0);
			break;
		case 12:
			option->ctxnum = strtol(optarg, NULL, 0);
			break;
		case 13:
			option->block = strtol(optarg, NULL, 0);
			break;
		case 14:
			option->blknum = strtol(optarg, NULL, 0);
			break;
		case 15:
			print_help();
			exit(-1);
		case 16:
			option->sgl_num = strtol(optarg, NULL, 0);
			break;
		default:
			SEC_TST_PRT("bad input parameter, exit\n");
			print_help();
			exit(-1);
		}
	}
}

static int test_sec_option_convert(struct test_sec_option *option)
{
	if (option->algclass > PERF_CLASS) {
		print_help();
		return -EINVAL;
	}
	if (option->syncmode > 1) {
		print_help();
		return -EINVAL;
	}

	if (option->algclass == PERF_CLASS) {
		g_testalg = 16;
		g_pktlen = option->pktlen ? option->pktlen : BUFF_SIZE;
		g_block = option->block;
		if (g_pktlen > g_block) {
			SEC_TST_PRT("block size too smaller, block set to: %u\n", g_pktlen);
			g_block = g_pktlen;
		}
		g_keylen = 16;
		g_times = option->times ? option->times :
			(BUFF_SIZE * BUFF_SIZE);

		g_thread_num = option->xmulti ? option->xmulti : 1;
		g_syncmode = option->syncmode;
		g_ctxnum = option->ctxnum;
		g_blknum = option->blknum > 0 ?
			option->blknum : MIN_SVA_BD_NUM;
		g_direction = 0;
		return 0;
	}

	g_testalg = option->algtype;
	g_pktlen = option->pktlen;
	g_keylen = option->keylen;
	g_times = option->times ? option->times : 1;
	g_ctxnum = option->ctxnum ? option->ctxnum : 1;
	g_data_fmt = option->sgl_num ? 1 : 0;
	g_sgl_num = option->sgl_num;

	SEC_TST_PRT("set global times is %lld\n", g_times);

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
	g_ctxnum = 1;
	g_testalg = 0;
	g_times = 10;
	g_pktlen = 16;
	g_keylen = 16;
	SEC_TST_PRT("Test sec Cipher parameter default, alg:ecb(aes), set_times:10,"
		"set_pktlen:16 bytes, set_keylen:128 bit.\n");
	return	test_sec_cipher_sync_once();
}

static int test_sec_run(__u32 sync_mode, __u32 alg_class)
{
	int ret = 0;

	if (sync_mode == 0) {
		if (alg_class == CIPHER_CLASS) {
			if (g_thread_num > 1) {
				SEC_TST_PRT("currently cipher test is synchronize multi -%d threads!\n", g_thread_num);
				ret = sec_cipher_sync_test();
			} else {
				ret = test_sec_cipher_sync_once();
				SEC_TST_PRT("currently cipher test is synchronize once, one thread!\n");
			}
		} else if (alg_class == DIGEST_CLASS) {
			if (g_thread_num > 1) {
				SEC_TST_PRT("currently digest test is synchronize multi -%d threads!\n", g_thread_num);
				ret = sec_digest_sync_multi();
			} else {
				ret = sec_digest_sync_once();
				SEC_TST_PRT("currently digest test is synchronize once, one thread!\n");
			}
		} else if (alg_class == AEAD_CLASS) {
			if (g_thread_num > 1) {
				SEC_TST_PRT("currently aead test is synchronize multi -%d threads!\n", g_thread_num);
				ret = sec_aead_sync_multi();
			} else {
				ret = sec_aead_sync_once();
				SEC_TST_PRT("currently aead test is synchronize once, one thread!\n");
			}
		}
	} else {
		if (alg_class == CIPHER_CLASS) {
			if (g_thread_num > 1) {
				SEC_TST_PRT("currently cipher test is asynchronous multi -%d threads!\n", g_thread_num);
				ret = sec_cipher_async_test();
			} else {
				ret = test_sec_cipher_async_once();
				SEC_TST_PRT("currently cipher test is asynchronous one, one thread!\n");
			}
		} else if (alg_class == DIGEST_CLASS) {
			if (g_thread_num > 1) {
				SEC_TST_PRT("currently digest test is asynchronous multi -%d threads!\n", g_thread_num);
				ret = sec_digest_async_multi();
			} else {
				ret = sec_digest_async_once();
				SEC_TST_PRT("currently digest test is asynchronous one, one thread!\n");
			}
		} else if (alg_class == AEAD_CLASS) {
			if (g_thread_num > 1) {
				SEC_TST_PRT("currently adad test is asynchronous multi -%d threads!\n", g_thread_num);
				ret = sec_aead_async_multi();
			} else {
				ret = sec_aead_async_once();
				SEC_TST_PRT("currently adad test is asynchronous one, one thread!\n");
			}
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	struct test_sec_option option = {0};
	int ret = 0;

	SEC_TST_PRT("this is a hisi sec test.\n");

	g_thread_num = 1;
	if (!argv[1]) {
		return test_sec_default_case();
	}

	test_sec_cmd_parse(argc, argv, &option);
	ret = test_sec_option_convert(&option);
	if (ret)
		return ret;
	if (option.algclass == PERF_CLASS)
		return sec_sva_test();

	pthread_mutex_init(&test_sec_mutex, NULL);

	return test_sec_run(option.syncmode, option.algclass);
}
