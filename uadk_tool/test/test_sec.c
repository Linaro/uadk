/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <getopt.h>
#include <numa.h>

#include "sec_template_tv.h"
#include "test_sec.h"
#include "include/wd_cipher.h"
#include "include/wd_digest.h"
#include "include/wd_aead.h"
#include "include/wd_sched.h"

#define SEC_TST_PRT printf
#define HW_CTX_SIZE (24 * 1024)
#define BUFF_SIZE 1024
#define IV_SIZE   256
#define THREADS_NUM	64
#define SVA_THREADS	64
#define USE_CTX_NUM	64
#define BYTES_TO_MB	20
#define SEC_ARGV_OFFSET	3

#define SCHED_SINGLE "sched_single"
#define SCHED_NULL_CTX_SIZE	4
#define TEST_WORD_LEN	4096
#define MAX_ALGO_PER_TYPE 16
#define MIN_SVA_BD_NUM	1
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32

#define SGL_ALIGNED_BYTES	64

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
static unsigned int g_stream;
static unsigned int g_alg_op_type;
static unsigned int g_ivlen;
static unsigned int g_syncmode;
static unsigned int g_use_env;
static unsigned int g_ctxnum;
static unsigned int g_data_fmt = WD_FLAT_BUF;
static unsigned int g_sgl_num = 0;
static unsigned int g_init;
static pthread_spinlock_t lock = 0;

static struct hash_testvec g_long_hash_tv;

char *skcipher_names[MAX_ALGO_PER_TYPE] =
	{"ecb(aes)", "cbc(aes)", "xts(aes)", "ofb(aes)", "cfb(aes)", "ecb(des3_ede)",
	"cbc(des3_ede)", "cbc(sm4)", "xts(sm4)", "ofb(sm4)", "cfb(sm4)", "ecb(sm4)",
	"cbc_cs1(aes)", "cbc_cs2(aes)", "cbc_cs3(aes)", NULL,};

enum digest_type {
	LOCAL_SM3,
	LOCAL_MD5,
	LOCAL_SHA1,
	LOCAL_SHA256,
	LOCAL_SHA224,
	LOCAL_SHA384,
	LOCAL_SHA512,
	LOCAL_SHA512_224,
	LOCAL_SHA512_256,
	LOCAL_AES_CMAC,
	LOCAL_AES_GMAC_128,
	LOCAL_AES_GMAC_192,
	LOCAL_AES_GMAC_256,
	LOCAL_AES_XCBC_MAC_96,
};

char *digest_names[MAX_ALGO_PER_TYPE] = {
	"sm3",
	"md5",
	"sha1",
	"sha256",
	"sha224",
	"sha384",
	"sha512",
	"sha512-224",
	"sha512-256",
	"cmac(aes)",
	"gmac(aes)", /* --digest 10: test aes-gmac-128 */
	"gmac(aes)", /* --digest 11: test aes-gmac-192 */
	"gmac(aes)", /* --digest 12: test aes-gmac-256 */
	"xcbc-mac-96(aes)",
	"xcbc-prf-128(aes)",
	"ccm(aes)", /* --digest 15: for error alg test */
};

char *aead_names[MAX_ALGO_PER_TYPE] = {
	"ccm(aes)",
	"gcm(aes)",
	"authenc(hmac(sha256),cbc(aes))",
	"ccm(sm4)",
	"gcm(sm4)",
	"authenc(hmac(sha256),cbc(sm4))",
	"sm3", /*--aead 6: for error alg test */
	"authenc(hmac(sha3),cbc(aes))", /* --aead 7: for error alg test */
};

struct sva_bd {
	char *src;
	char *dst;
};

struct sva_bd_pool {
	struct sva_bd *bds;
};

typedef struct _thread_data_t {
	int	tid;
	int	flag;
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
	__u32 stream_mode;
	__u32 sgl_num;
	__u32 use_env;
	__u32 init;
};

static pthread_mutex_t test_sec_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t system_test_thrds[THREADS_NUM];
static thread_data_t thr_data[THREADS_NUM];

/*
 * Calculate SGL unit size.
 */
static inline size_t cal_unit_sz(size_t sz, int sgl_num)
{
	return (sz + SGL_ALIGNED_BYTES - 1) & ~(SGL_ALIGNED_BYTES - 1);
}

/*
 * Create SGL or common memory buffer.
 */
static void *create_buf(int sgl, size_t sz, size_t unit_sz)
{
	struct wd_datalist *head, *p, *q;
	int i, tail_sz, sgl_num;
	void *buf;

	buf = calloc(sz, sizeof(char));
	if (!buf) {
		SEC_TST_PRT("Fail to allocate buffer %ld size!\n", sz);
		return NULL;
	}
	if (sgl == WD_FLAT_BUF)
		return buf;
	tail_sz = sz % unit_sz;
	sgl_num = sz / unit_sz;	/* the number with unit_sz bytes */

	/* the additional slot is for tail_sz */
	head = calloc(sgl_num + 1, sizeof(struct wd_datalist));
	if (!head) {
		SEC_TST_PRT("Fail to allocate memory for SGL head!\n");
		goto out;
	}
	for (i = 0, p = head, q = NULL; i < sgl_num;) {
		p->data = buf + i * unit_sz;
		p->len = unit_sz;
		if (q)
			q->next = p;
		q = p;
		p = &head[++i];
	}
	if (tail_sz) {
		p->data = buf + i * unit_sz;
		p->len = tail_sz;
		if (q)
			q->next = p;
	}
	return head;
out:
	free(buf);
	return NULL;
}

static void free_buf(int sgl, void *buf)
{
	struct wd_datalist *p;

	if (!buf)
		return;
	if (sgl == WD_FLAT_BUF) {
		free(buf);
		return;
	}
	p = (struct wd_datalist *)buf;
	/* free the whole data buffer of SGL */
	free(p->data);
	/* free SGL headers */
	free(buf);
}

static inline void copy_mem(int dst_sgl, void *dst, int src_sgl, void *src,
			    size_t len)
{
	struct wd_datalist *p, *q;
	size_t cnt = 0;

	if (dst_sgl == WD_FLAT_BUF && src_sgl == WD_FLAT_BUF) {
		memcpy(dst, src, len);
	} else if (dst_sgl == WD_FLAT_BUF && src_sgl == WD_SGL_BUF) {
		p = (struct wd_datalist *)src;
		while (p && len) {
			if (p->len > len) {
				memcpy(dst + cnt, p->data, len);
				cnt += len;
				len = 0;
			} else {
				memcpy(dst + cnt, p->data, p->len);
				cnt += p->len;
				len = len - p->len;
			}
			p = p->next;
		}
	} else if (dst_sgl == WD_SGL_BUF && src_sgl == WD_FLAT_BUF) {
		p = (struct wd_datalist *)dst;
		while (p && len) {
			if (p->len > len) {
				memcpy(p->data, src + cnt, len);
				cnt += len;
				len = 0;
			} else {
				memcpy(p->data, src + cnt, p->len);
				cnt += p->len;
				len = len - p->len;
			}
			p = p->next;
		}
	} else if (dst_sgl == WD_SGL_BUF && src_sgl == WD_SGL_BUF) {
		p = (struct wd_datalist *)dst;
		q = (struct wd_datalist *)src;
		while (p && q && len) {
			if (q->len > len) {
				memcpy(p->data, q->data, len);
				len = 0;
			} else {
				memcpy(p->data, q->data, q->len);
				len = len - q->len;
			}
			p = p->next;
			q = q->next;
		}
		if (len)
			SEC_TST_PRT("%ld bytes not copied from src to dst.\n",
				    len);
	} else
		SEC_TST_PRT("Not supported memory type for copy.\n");
}

static void dump_mem(const char *str, int sgl, unsigned char *buf, size_t len)
{
	struct wd_datalist *p;
	size_t i, tmp;

	if (!buf) {
		SEC_TST_PRT("Can't dump invalid buffer!");
		return;
	}

	SEC_TST_PRT("%s\n", str);

	if (sgl == WD_FLAT_BUF) {
		for (i = 0; i < len; i++) {
			SEC_TST_PRT("\\0x%02x", buf[i]);
			if ((i + 1) % 8 == 0)
				SEC_TST_PRT("\n");
		}
		SEC_TST_PRT("\n");
	} else if (sgl == WD_SGL_BUF) {
		p = (struct wd_datalist *)buf;
		for (i = 0, tmp = 0; i < len; i++, tmp++) {
			if (tmp == p->len) {
				p = p->next;
				tmp = 0;
			}
			if (!p) {
				SEC_TST_PRT("Left %ld bytes could not dump\n",
					    len - i);
				return;
			}
			SEC_TST_PRT("\\0x%02x", *((char *)p->data + i));
			if ((i + 1) % 8 == 0)
				SEC_TST_PRT("\n");
		}
		SEC_TST_PRT("\n");
	}
}

/*
 * Parse alg & mode from variable g_testalg.
 */
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
		case 11:
			alg_type = WD_CIPHER_SM4;
			mode_type = WD_CIPHER_ECB;
			if (g_keylen != 16) {
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			tv = &sm4_ecb_tv_template_128[0];
			break;
		case 12:
			alg_type = WD_CIPHER_AES;
			switch (g_keylen) {
			case AES_KEYSIZE_128:
				mode_type = WD_CIPHER_CBC_CS1;
				tv = &aes_cbc_cs1_tv_template_128[0];
				break;
			case AES_KEYSIZE_192:
				mode_type = WD_CIPHER_CBC_CS1;
				tv = &aes_cbc_cs1_tv_template_192[0];
				break;
			case AES_KEYSIZE_256:
				mode_type = WD_CIPHER_CBC_CS1;
				tv = &aes_cbc_cs1_tv_template_256[0];
				break;
			default:
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			break;
		case 13:
			alg_type = WD_CIPHER_AES;
			switch (g_keylen) {
			case AES_KEYSIZE_128:
				mode_type = WD_CIPHER_CBC_CS2;
				tv = &aes_cbc_cs1_tv_template_128[0];
				break;
			case AES_KEYSIZE_192:
				mode_type = WD_CIPHER_CBC_CS2;
				tv = &aes_cbc_cs1_tv_template_192[0];
				break;
			case AES_KEYSIZE_256:
				mode_type = WD_CIPHER_CBC_CS2;
				tv = &aes_cbc_cs1_tv_template_256[0];
				break;
			default:
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
			break;
		case 14:
			alg_type = WD_CIPHER_AES;
			switch (g_keylen) {
			case AES_KEYSIZE_128:
				mode_type = WD_CIPHER_CBC_CS3;
				tv = &aes_cbc_cs1_tv_template_128[0];
				break;
			case AES_KEYSIZE_192:
				mode_type = WD_CIPHER_CBC_CS3;
				tv = &aes_cbc_cs1_tv_template_192[0];
				break;
			case AES_KEYSIZE_256:
				mode_type = WD_CIPHER_CBC_CS3;
				tv = &aes_cbc_cs1_tv_template_256[0];
				break;
			default:
				SEC_TST_PRT("%s: input key err!\n", __func__);
				return -EINVAL;
			}
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
	struct sched_params param;
	int ret = 0;
	int i;

	list = wd_get_accel_list("cipher");
	if (!list) {
		printf("Fail to get cipher device\n");
		return -ENODEV;
	}

	/* If there is no numa, we default config to zero */
	if (list->dev->numa_id < 0)
		list->dev->numa_id = 0;

	g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1,
				    numa_max_node() + 1,
				    wd_cipher_poll_ctx);
	if (!g_sched) {
		printf("Fail to alloc sched!\n");
		goto out;
	}

	g_sched->name = SCHED_SINGLE;
	param.numa_id = list->dev->numa_id;
	param.mode = mode;
	param.type = 0;
	param.begin = 0;
	param.end = g_ctxnum - 1;
	ret = wd_sched_rr_instance(g_sched, &param);
	if (ret) {
		printf("Fail to fill sched data!\n");
		goto out;
	}

	if (g_use_env)
		return wd_cipher_env_init(g_sched);

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
	wd_sched_rr_release(g_sched);

	return ret;
}

static void uninit_config(void)
{
	int i;

	if (g_use_env) {
		wd_cipher_env_uninit();
		return;
	}

	wd_cipher_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);
}

static int test_sec_cipher_sync_once(void)
{
	struct cipher_testvec *tv = NULL;
	handle_t	h_sess = 0;
	struct wd_cipher_sess_setup	setup = {0};
	struct wd_cipher_req req;
	struct timeval bg_tval, cur_tval;
	int thread_id = (int)syscall(__NR_gettid);
	unsigned long Perf = 0;
	float speed, time_used;
	int pid = getpid();
	int cnt = g_times;
	size_t unit_sz, len;
	int ret;

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
	else
		req.op_type = WD_CIPHER_DECRYPTION;

	/* get resource */
	(void)get_cipher_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	len = g_pktlen < tv->len ? g_pktlen : tv->len;
	req.in_bytes = len;
	unit_sz = cal_unit_sz(req.in_bytes, g_sgl_num);
	req.src = create_buf(g_data_fmt, req.in_bytes, unit_sz);
	if (!req.src) {
		ret = -ENOMEM;
		goto out;
	}

	if (g_direction == 0)
		copy_mem(g_data_fmt, req.src, WD_FLAT_BUF,
			(void *)tv->ptext, (size_t)tv->len);
	else
		copy_mem(g_data_fmt, req.src, WD_FLAT_BUF,
			(void *)tv->ctext, (size_t)tv->len);

	dump_mem("req src--->:", g_data_fmt, req.src, req.in_bytes);
	SEC_TST_PRT("input_len: %u, ready to dump sgl ? fmt:%d\n", req.in_bytes, g_data_fmt);

	req.out_bytes = len;
	req.out_buf_bytes = len;
	req.data_fmt = g_data_fmt;
	req.dst = create_buf(g_data_fmt, req.out_buf_bytes, unit_sz);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		ret = -ENOMEM;
		goto out_iv;
	}
	if (setup.mode != WD_CIPHER_ECB) {
		req.iv_bytes = strlen(tv->iv);
		if (tv->ivlen > 0)
			req.iv_bytes = tv->ivlen;
		memset(req.iv, 0, req.iv_bytes);
		if (tv->iv)
			memcpy(req.iv, tv->iv, strlen(tv->iv));
		dump_mem("cipher req iv--->:", WD_FLAT_BUF, req.iv, req.iv_bytes);
	}

	h_sess = wd_cipher_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("req set key failed!\n");
		goto out_key;
	}

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

	dump_mem("Test cipher sync function: output dst-->", g_data_fmt, req.dst, req.out_bytes);

out_key:
	wd_cipher_free_sess(h_sess);
out_sess:
	free(req.iv);
out_iv:
	free_buf(g_data_fmt, req.dst);
out_dst:
	free_buf(g_data_fmt, req.src);
out:
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
	struct wd_cipher_sess_setup setup = {0};
	thread_data_t data;
	handle_t h_sess = 0;
	struct wd_cipher_req req;
	struct timeval bg_tval, cur_tval;
	int thread_id = (int)syscall(__NR_gettid);
	unsigned long Perf = 0;
	float speed, time_used;
	int pid = getpid();
	size_t unit_sz;

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
	(void)get_cipher_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	req.data_fmt = g_data_fmt;
	req.in_bytes = g_pktlen;
	unit_sz = cal_unit_sz(req.in_bytes, g_sgl_num);
	req.src = create_buf(g_data_fmt, req.in_bytes, unit_sz);
	if (!req.src) {
		ret = -ENOMEM;
		goto out;
	}

	if (g_direction == 0)
		copy_mem(g_data_fmt, req.src, WD_FLAT_BUF,
			(void *)tv->ptext, (size_t)tv->len);
	else
		copy_mem(g_data_fmt, req.src, WD_FLAT_BUF,
			(void *)tv->ctext, (size_t)tv->len);
	dump_mem("req src--->:", g_data_fmt, req.src, req.in_bytes);

	req.out_bytes = tv->len;
	req.out_buf_bytes = BUFF_SIZE;
	req.dst = create_buf(g_data_fmt, req.out_buf_bytes, unit_sz);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}


	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		ret = -ENOMEM;
		goto out_iv;
	}
	if (setup.mode != WD_CIPHER_ECB) {
		req.iv_bytes = strlen(tv->iv);
		if (tv->ivlen > 0)
			req.iv_bytes = tv->ivlen;
		memset(req.iv, 0, req.iv_bytes);
		if (tv->iv)
			memcpy(req.iv, tv->iv, strlen(tv->iv));
		dump_mem("cipher req iv--->:", WD_FLAT_BUF, req.iv, req.iv_bytes);
	}
	h_sess = wd_cipher_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out_sess;
	}

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("req set key failed!\n");
		goto out_key;
	}

	gettimeofday(&bg_tval, NULL);
	while (cnt) {
		req.cb = async_cb;
		req.cb_param = &data;
		ret = wd_do_cipher_async(h_sess, &req);
		if (ret < 0)
			goto out;

		if (g_use_env) {
			cnt--;
			continue;
		}
		/* poll thread */
try_again:
		num = 0;
		ret = wd_cipher_poll_ctx(0, 1, &num);
		if (ret < 0) {
			if (ret == -EAGAIN)
				goto try_again; // loop poll
			else
				goto out;
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

out_key:
	wd_cipher_free_sess(h_sess);
out_sess:
	free(req.iv);
out_iv:
	free_buf(g_data_fmt, req.dst);
out_dst:
	free_buf(g_data_fmt, req.src);
out:
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
	(void)get_cipher_resource(&tv, (int *)&setup->alg, (int *)&setup->mode);

	h_sess = wd_cipher_alloc_sess(setup);
	if (!h_sess) {
		ret = -1;
		return ret;
	}

	pktlen = req->in_bytes;
	dump_mem("cipher req src--->:", g_data_fmt, req->src, req->in_bytes);

	SEC_TST_PRT("ivlen = %d\n", req->iv_bytes);
	dump_mem("cipher req iv--->:", WD_FLAT_BUF, req->iv, req->iv_bytes);

	ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
	if (ret) {
		SEC_TST_PRT("test sec cipher set key is failed!\n");
		goto out;;
	}

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
	void *iv = NULL;
	int parallel = g_thread_num;
	struct cipher_testvec *tv = NULL;
	int test_alg, test_mode;
	int ret, i, j;
	unsigned int len;
	size_t unit_sz;

	memset(req, 0, sizeof(struct wd_cipher_req) * THREADS_NUM);
	memset(setup, 0, sizeof(struct wd_cipher_sess_setup) * THREADS_NUM);

	/* get resource */
	(void)get_cipher_resource(&tv, &test_alg, &test_mode);

	iv = calloc(1, IV_SIZE * THREADS_NUM);
	if (!iv) {
		ret = -ENOMEM;
		goto out_iv;
	}

	len = g_pktlen < tv->len ? g_pktlen : tv->len;
	unit_sz = cal_unit_sz(len, g_sgl_num);
	for (i = 0; i < parallel; i++) {
		req[i].src = create_buf(g_data_fmt, len, unit_sz);
		if (!req[i].src) {
			ret = -ENOMEM;
			goto out_src;
		}
		req[i].in_bytes = len;
		copy_mem(g_data_fmt, req[i].src, WD_FLAT_BUF,
			 (void *)tv->ptext, (size_t)tv->len);

		req[i].out_bytes = tv->len;
		req[i].out_buf_bytes = len;
		req[i].dst = create_buf(g_data_fmt, len, unit_sz);
		if (!req[i].dst) {
			ret = -ENOMEM;
			goto out_dst;
		}

		req[i].data_fmt = g_data_fmt;

		req[i].iv = iv + i * IV_SIZE;
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
		else
			req[i].op_type = WD_CIPHER_DECRYPTION;
	}

	ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("failed to init sigle ctx config!\n");
		goto out_cfg;
	}

	ret = test_sync_create_threads(parallel, req, setup);
	if (ret < 0)
		goto out_thr;

out_thr:
	uninit_config();
out_cfg:
	for (j = 0; j < i; j++) {
		free_buf(g_data_fmt, req[j].src);
		free_buf(g_data_fmt, req[j].dst);
	}
	free(iv);
	return ret;
out_dst:
	free_buf(g_data_fmt, req[i].src);
out_src:
	for (j = 0; j < i; j++) {
		free_buf(g_data_fmt, req[j].src);
		free_buf(g_data_fmt, req[j].dst);
	}
out_iv:
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
	(void)get_cipher_resource(&tv, (int *)&setup->alg, (int *)&setup->mode);

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
	/* run task */
	do {
try_do_again:
		ret = wd_do_cipher_async(h_sess, req);
		if (ret == -EBUSY) { // busy
			usleep(100);
			goto try_do_again;
		} else if (ret) {
			SEC_TST_PRT("test sec cipher send req is error!\n");
			pthread_mutex_unlock(&test_sec_mutex);
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
	struct wd_cipher_sess_setup setup[THREADS_NUM] = {{0}};
	void *iv = NULL;
	struct cipher_testvec *tv = NULL;
	thread_data_t datas[THREADS_NUM];
	int parallel = g_thread_num;
	int test_alg, test_mode;
	int i, j, ret;
	size_t unit_sz;

	memset(datas, 0, sizeof(thread_data_t) * THREADS_NUM);
	memset(req, 0, sizeof(struct wd_cipher_req) * THREADS_NUM);
	/* get resource */
	ret = get_cipher_resource(&tv, &test_alg, &test_mode);
	int step = sizeof(char) * TEST_WORD_LEN;
	iv = malloc(step * THREADS_NUM);
	if (!iv) {
		ret = -ENOMEM;
		goto out_iv;
	}

	unit_sz = cal_unit_sz(g_pktlen, g_sgl_num);
	for (i = 0; i < parallel; i++) {
		req[i].src = create_buf(g_data_fmt, g_pktlen, unit_sz);
		if (!req[i].src) {
			ret = -ENOMEM;
			goto out_src;
		}
		req[i].in_bytes = g_pktlen;
		copy_mem(g_data_fmt, req[i].src, WD_FLAT_BUF,
			 (void *)tv->ptext, (size_t)tv->len);

		req[i].dst = create_buf(g_data_fmt, g_pktlen, unit_sz);
		if (!req[i].dst) {
			ret = -ENOMEM;
			goto out_dst;
		}
		req[i].out_bytes = tv->len;
		req[i].out_buf_bytes = g_pktlen;

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
		else
			req[i].op_type = WD_CIPHER_DECRYPTION;
		req[i].cb = async_cb;
		req[i].cb_param = &datas[i];
	}

	ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("fail to init sigle ctx config!\n");
		goto out_cfg;
	}

	ret = test_async_create_threads(parallel, req, setup);
	if (ret < 0)
		goto out_thr;

out_thr:
	uninit_config();
out_cfg:
	for (j = 0; j < i; j++) {
		free_buf(g_data_fmt, req[j].src);
		free_buf(g_data_fmt, req[j].dst);
	}
	free(iv);
	return ret;
out_dst:
	free_buf(g_data_fmt, req[i].src);
out_src:
	for (j = 0; j < i; j++) {
		free_buf(g_data_fmt, req[j].src);
		free_buf(g_data_fmt, req[j].dst);
	}
out_iv:
	free(iv);
	return ret;
}

/* ------------------digest alg, nomal mode and hmac mode------------------ */
static handle_t sched_digest_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 sched_digest_pick_next_ctx(handle_t h_sched_ctx,
	void *sched_key, const int sched_mode)
{
	/* alway return first ctx */
	return 0;
}

static int digest_init1(int type, int mode)
{
	struct uacce_dev_list *list;
	struct wd_sched sched;
	int ret;

	if (g_use_env)
		return wd_digest_env_init(NULL);

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
	sched.sched_init = sched_digest_init;
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

static int digest_init2(int type, int mode)
{
	struct wd_ctx_params cparams = {0};
	struct wd_ctx_nums *ctx_set_num;
	int ret;

	if (g_testalg >= MAX_ALGO_PER_TYPE)
		return -WD_EINVAL;

	ctx_set_num = calloc(1, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		WD_ERR("failed to alloc ctx_set_size!\n");
		return -WD_ENOMEM;
	}

	cparams.op_type_num = 1;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		WD_ERR("failed to create nodemask!\n");
		ret = -WD_ENOMEM;
		goto out_freectx;
	}

	numa_bitmask_setall(cparams.bmp);

	if (mode == CTX_MODE_SYNC)
		ctx_set_num->sync_ctx_num = g_ctxnum;

	if (mode == CTX_MODE_ASYNC)
		ctx_set_num->async_ctx_num = g_ctxnum;

	ret = wd_digest_init2_(digest_names[g_testalg], 0, 0, &cparams);
	if (ret)
		goto out_freebmp;

out_freebmp:
	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);

	return ret;
}

static int init_digest_ctx_config(int type, int mode)
{
	int ret = -1;

	switch (g_init) {
	case 0:
	case 1:
		SEC_TST_PRT("uadk entry init1!\n");
		ret = digest_init1(type, mode);
		break;
	case 2:
		SEC_TST_PRT("uadk entry init2!\n");
		ret = digest_init2(type, mode);
		break;
	default:
		SEC_TST_PRT("unsupported init-type%u!\n", g_init);
		break;
	}

	return ret;
}

static void digest_uninit1(void)
{
	int i;

	if (g_use_env) {
		wd_digest_env_uninit();
		return;
	}

	wd_digest_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
}

static void digest_uninit2(void)
{
	wd_digest_uninit2();
}

static void digest_uninit_config(void)
{
	switch (g_init) {
	case 0:
	case 1:
		digest_uninit1();
		break;
	case 2:
		digest_uninit2();
		break;
	default:
		SEC_TST_PRT("unsupported uninit-type%u!\n", g_init);
	}
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
		case 9:
			switch (g_alg_op_type) {
			case 1:
				mode_type = WD_DIGEST_HMAC;
				SEC_TST_PRT("test alg: %s\n", "aes-cmac");
				tv = &aes_cmac_tv_template[0];
				break;
			}
			tv->dsize = 16;
			alg_type = WD_DIGEST_AES_CMAC;
			break;
		case 10:
			switch (g_alg_op_type) {
			case 1:
				mode_type = WD_DIGEST_HMAC;
				SEC_TST_PRT("test alg: %s\n", "aes-gmac-128");
				tv = &aes_gmac_128_tv_template[0];
				break;
			}
			tv->dsize = 16;
			alg_type = WD_DIGEST_AES_GMAC;
			break;
		case 11:
			switch (g_alg_op_type) {
			case 1:
				mode_type = WD_DIGEST_HMAC;
				SEC_TST_PRT("test alg: %s\n", "aes-gmac-192");
				tv = &aes_gmac_192_tv_template[0];
				break;
			}
			tv->dsize = 16;
			alg_type = WD_DIGEST_AES_GMAC;
			break;
		case 12:
			switch (g_alg_op_type) {
			case 1:
				mode_type = WD_DIGEST_HMAC;
				SEC_TST_PRT("test alg: %s\n", "aes-gmac-256");
				tv = &aes_gmac_256_tv_template[0];
				break;
			}
			tv->dsize = 16;
			alg_type = WD_DIGEST_AES_GMAC;
			break;
		case 13:
			switch (g_alg_op_type) {
			case 1:
				mode_type = WD_DIGEST_HMAC;
				SEC_TST_PRT("test alg: %s\n", "aes-xcbc-mac-96");
				tv = &aes_xcbc_mac_96_tv_template[0];
				break;
			}
			tv->dsize = 12;
			alg_type = WD_DIGEST_AES_XCBC_MAC_96;
			break;
		case 14:
			switch (g_alg_op_type) {
			case 1:
				mode_type = WD_DIGEST_HMAC;
				SEC_TST_PRT("test alg: %s\n", "aes-xcbc-prf-128");
				tv = &aes_xcbc_mac_96_tv_template[0];
				break;
			}
			tv->dsize = 16;
			alg_type = WD_DIGEST_AES_XCBC_PRF_128;
			break;

		default:
			SEC_TST_PRT("keylenth error, default test alg: %s\n", "normal(sm3)");
			return -EINVAL;
	}
	if (g_ivlen == 1) {
		tmp_tv = tv;
		tv = &g_long_hash_tv;
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
	struct wd_digest_sess_setup setup = {0};
	struct hash_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	struct timeval start_tval;
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	unsigned long cnt = g_times;
	int ret;
	size_t unit_sz;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	unit_sz = cal_unit_sz(BUFF_SIZE, g_sgl_num);
	req.in = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.in) {
		ret = -ENOMEM;
		goto out_src;
	}

	req.in_bytes = tv->psize;

	copy_mem(g_data_fmt, req.in, WD_FLAT_BUF,
		 (void *)tv->plaintext, tv->psize);
	dump_mem("req src in--->:", g_data_fmt, req.in, req.in_bytes);

	req.out = create_buf(WD_FLAT_BUF, BUFF_SIZE, unit_sz);
	if (!req.out) {
		ret = -ENOMEM;
		goto out_dst;
	}

	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	printf("req.data_fmtaaaa = %u\n", g_data_fmt);
	req.data_fmt = g_data_fmt;
	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}

	/* if mode is HMAC, should set key */
	if (setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
		if (ret) {
			SEC_TST_PRT("sess set key failed!\n");
			goto out_key;
		}

		if (g_testalg == LOCAL_AES_GMAC_128 ||
		    g_testalg == LOCAL_AES_GMAC_192 ||
		    g_testalg == LOCAL_AES_GMAC_256) {
			req.iv = malloc(sizeof(char) * 16);
			if (!req.iv) {
				SEC_TST_PRT("failed to alloc iv memory!\n");
				goto out_key;
			}
			memcpy(req.iv, tv->iv, 16);
			req.iv_bytes = 16;
		}
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
	dump_mem("req's out--->", WD_FLAT_BUF, req.out, req.out_bytes);

out_key:
	wd_digest_free_sess(h_sess);
out_sess:
	free_buf(WD_FLAT_BUF, req.out);
out_dst:
	free_buf(g_data_fmt, req.in);
out_src:
	digest_uninit_config();
	free(req.iv);

	return ret;
}

static int sec_digest_sync_stream_cmp(void)
{
	struct wd_digest_sess_setup setup = {0};
	struct hash_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	unsigned long cnt = g_times;
	int ret;
	size_t unit_sz;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	unit_sz = cal_unit_sz(BUFF_SIZE * 8, g_sgl_num);
	req.in = create_buf(g_data_fmt, BUFF_SIZE * 8, unit_sz);
	if (!req.in) {
		ret = -ENOMEM;
		goto out_src;
	}

	req.in_bytes = tv->psize;
	copy_mem(g_data_fmt, req.in, WD_FLAT_BUF,
		 (void *)tv->plaintext, tv->psize);

	req.out = create_buf(WD_FLAT_BUF, BUFF_SIZE, unit_sz);
	if (!req.out) {
		ret = -ENOMEM;
		goto out_dst;
	}

	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.data_fmt = g_data_fmt;
	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}

	/* if mode is HMAC, should set key */
	ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
	if (ret) {
		SEC_TST_PRT("sess set key failed!\n");
		goto out_key;
	}

	while (cnt) {
		ret = wd_do_digest_sync(h_sess, &req);
		cnt--;
	}

	char digest_str[] = "one hash BD dump the out memory, cmp the stream mode:";
	dump_mem(digest_str, WD_FLAT_BUF, req.out, 16);

out_key:
	wd_digest_free_sess(h_sess);
out_sess:
	free_buf(WD_FLAT_BUF, req.out);
out_dst:
	free_buf(g_data_fmt, req.in);
out_src:
	digest_uninit_config();

	return ret;
}

static int sec_digest_sync_stream_mode(void)
{
	struct wd_digest_sess_setup setup;
	struct hash_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	unsigned long cnt = g_times;
	int ret, data_len;
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

	req.in = malloc(BUFF_SIZE * 8);
	if (!req.in) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_in = req.in;

	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;

	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.data_fmt = g_data_fmt;
	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -1;
		goto out;
	}
	data_len = tv->psize;

	/* if mode is HMAC, should set key */
	ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
	if (ret) {
		SEC_TST_PRT("sess set key failed!\n");
		goto out;
	}

	while (cnt) {
		do {
			if (data_len > 256) { // soft block size
				req.in_bytes = 256;
				data_len -= 256;
				req.has_next = 1;
			} else {
				req.has_next = 0;
				req.in_bytes = data_len;
			}
			ret = wd_do_digest_sync(h_sess, &req);

			if (ret)
				goto out;

			if (req.has_next != 0)
				req.in += 256;
			else
				break;
		} while (true);
		data_len = tv->psize;
		req.has_next = 0;
		req.in = bak_in;
		memcpy(req.in, tv->plaintext, tv->psize);
		cnt--;
	}
	char digest_str[] = "long hash BD dump the out memory:--->:";
	dump_mem(digest_str, g_data_fmt, req.out, 16);

out:
	free(req.out);
	free(req.in);
	if (h_sess)
		wd_digest_free_sess(h_sess);

	digest_uninit_config();
	return ret;
}

void *digest_sync_stream_mode_send_td(void *data)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_digest_sess_setup setup = {0};
	struct hash_testvec *tv = NULL;
	unsigned long cnt = g_times;
	struct wd_digest_req req;
	int ret, data_len;
	void *bak_in = NULL;
	handle_t h_sess = 0;

	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		return NULL;
	}

	/* if mode is HMAC, should set key */
	ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
	if (ret) {
		SEC_TST_PRT("sess set key failed!\n");
		goto out_key;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));

	req.in = malloc(BUFF_SIZE * 8);
	if (!req.in) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	bak_in = req.in;

	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;

	req.out = malloc(BUFF_SIZE);
	if (!req.out) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.data_fmt = g_data_fmt;
	req.has_next = 0;

	data_len = tv->psize;

	while (cnt) {
		do {
			if (data_len > 256) { // soft block size
				req.in_bytes = 256;
				data_len -= 256;
				req.has_next = 1;
			} else {
				req.has_next = 0;
				req.in_bytes = data_len;
			}
			ret = wd_do_digest_sync(h_sess, &req);

			if (ret)
				goto out;

			if (req.has_next != 0)
				req.in += 256;
			else
				break;

		} while (true);
		data_len = tv->psize;
		req.has_next = 0;
		req.in = bak_in;
		memcpy(req.in, tv->plaintext, tv->psize);
		cnt--;
	}
	SEC_TST_PRT("Pid - %d, thread-id - %d\n",  getpid(), thread_id);
	dump_mem("long hash BD dump the out memory:", g_data_fmt, req.out, 16);
out_key:
	wd_digest_free_sess(h_sess);
out:
	if (req.out)
		free(req.out);
	if (bak_in)
		free(bak_in);
	return NULL;
}

static int sec_digest_sync_stream_mode_multi(void)
{
	static pthread_t sendtd[64];
	thread_data_d td_data;
	int i, ret;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* send thread */
	td_data.send_num = g_times;
	td_data.recv_num = g_times;
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_create(&sendtd[i], NULL, digest_sync_stream_mode_send_td, &td_data);
		if (ret) {
			SEC_TST_PRT("Create send thread fail!\n");
			goto out_thr;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sendtd thread fail!\n");
			goto out_thr;
		}
	}

out_thr:
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
	struct wd_digest_sess_setup setup = {0};
	static pthread_t send_td;
	static pthread_t poll_td;
	struct wd_digest_req req;
	thread_data_d td_data;
	handle_t h_sess = 0;
	int test_alg = 0;
	int test_mode = 0;
	int ret;
	size_t unit_sz;

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

	unit_sz = cal_unit_sz(BUFF_SIZE, g_sgl_num);
	req.in = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.in) {
		ret = -ENOMEM;
		goto out_src;
	}

	req.in_bytes = tv->psize;

	copy_mem(g_data_fmt, req.in, WD_FLAT_BUF,
		 (void *)tv->plaintext, (size_t)tv->psize);
	dump_mem("req src in--->:", g_data_fmt, req.in, req.in_bytes);

	req.out = create_buf(WD_FLAT_BUF, BUFF_SIZE, unit_sz);
	if (!req.out) {
		ret = -ENOMEM;
		goto out_dst;
	}
	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.has_next = 0;
	req.data_fmt = g_data_fmt;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}

	/* if mode is HMAC, should set key */
	if (setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
		if (ret) {
			SEC_TST_PRT("sess set key failed!\n");
			goto out_key;
		}
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
		goto out_thr;
	}

	/* poll thread */
	ret = pthread_create(&poll_td, NULL, digest_poll_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out_thr;
	}

	ret = pthread_join(send_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out_thr;
	}

	ret = pthread_join(poll_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out_thr;
	}
	dump_mem("req src out--->:", WD_FLAT_BUF, req.out, req.out_bytes);

out_thr:
out_key:
	wd_digest_free_sess(h_sess);
out_sess:
	free_buf(WD_FLAT_BUF, req.out);
out_dst:
	free_buf(g_data_fmt, req.in);
out_src:
	digest_uninit_config();

	return ret;
}

static int sec_digest_sync_multi(void)
{
	struct wd_digest_sess_setup setup = {0};
	struct hash_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_digest_req req;
	static pthread_t sendtd[64];
	thread_data_d td_data;
	int i, ret;
	size_t unit_sz;

	/* config setup */
	ret = init_digest_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	if (ret) {
		SEC_TST_PRT("Fail to init sigle ctx config!\n");
		return ret;
	}

	/* config arg */
	memset(&req, 0, sizeof(struct wd_digest_req));
	get_digest_resource(&tv, (int *)&setup.alg, (int *)&setup.mode);

	unit_sz = cal_unit_sz(BUFF_SIZE, g_sgl_num);
	req.in = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.in) {
		ret = -ENOMEM;
		goto out_src;
	}

	memcpy(req.in, tv->plaintext, tv->psize);
	req.in_bytes = tv->psize;

	dump_mem("req src in--->:", g_data_fmt, req.in, req.in_bytes);

	req.out = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.out) {
		ret = -ENOMEM;
		goto out_dst;
	}
	req.out_buf_bytes = BUFF_SIZE;
	req.out_bytes = tv->dsize;
	req.has_next = 0;

	h_sess = wd_digest_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}

	/* if mode is HMAC, should set key */
	if (setup.mode == WD_DIGEST_HMAC) {
		ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
		if (ret) {
			SEC_TST_PRT("sess set key failed!\n");
			goto out_key;
		}
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
			goto out_thr;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sendtd thread fail!\n");
			goto out_thr;
		}
	}

	SEC_TST_PRT("digest sync %u threads, speed:%llu ops, perf: %llu KB/s\n",
		g_thread_num, td_data.sum_perf,
		(td_data.sum_perf >> 10) * req.in_bytes);

	dump_mem("req src out--->:", g_data_fmt, req.out, req.out_bytes);
out_thr:
out_key:
	wd_digest_free_sess(h_sess);
out_sess:
	free_buf(g_data_fmt, req.out);
out_dst:
	free_buf(g_data_fmt, req.in);
out_src:
	digest_uninit_config();

	return ret;
}

static int sec_digest_async_multi(void)
{
	struct hash_testvec *tv = 0;
	struct wd_digest_sess_setup	setup = {0};
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
	dump_mem("req src in--->:", WD_FLAT_BUF, req.in, tv->psize);
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
		ret = wd_digest_set_key(h_sess, (const __u8 *)tv->key, tv->ksize);
		if (ret) {
			SEC_TST_PRT("sess set key failed!\n");
			goto out;
		}
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

	dump_mem("req src out--->:", WD_FLAT_BUF, req.out, req.out_bytes);
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
static handle_t sched_aead_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 sched_aead_pick_next_ctx(handle_t h_sched_ctx,
	void *sched_key, const int sched_mode)
{
	return 0;
}

static int aead_init1(int type, int mode)
{
	struct uacce_dev_list *list;
	struct wd_sched sched;
	int ret;

	if (g_use_env)
		return wd_aead_env_init(NULL);

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
	sched.sched_init = sched_aead_init;
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

static int aead_init2(int type, int mode)
{
	struct wd_ctx_params cparams = {0};
	struct wd_ctx_nums *ctx_set_num;
	int ret;

	if (g_testalg >= MAX_ALGO_PER_TYPE)
		return -WD_EINVAL;

	ctx_set_num = calloc(1, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		WD_ERR("failed to alloc ctx_set_size!\n");
		return -WD_ENOMEM;
	}

	cparams.op_type_num = 1;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		WD_ERR("failed to create nodemask!\n");
		ret = -WD_ENOMEM;
		goto out_freectx;
	}

	numa_bitmask_setall(cparams.bmp);

	if (mode == CTX_MODE_SYNC)
		ctx_set_num->sync_ctx_num = g_ctxnum;

	if (mode == CTX_MODE_ASYNC)
		ctx_set_num->async_ctx_num = g_ctxnum;

	ret = wd_aead_init2_(aead_names[g_testalg], 0, 0, &cparams);
	if (ret)
		goto out_freebmp;

out_freebmp:
	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);

	return ret;
}

static int init_aead_ctx_config(int type, int mode)
{
	int ret = -1;

	switch (g_init) {
	case 0:
	case 1:
		SEC_TST_PRT("uadk entry init1!\n");
		ret = aead_init1(type, mode);
		break;
	case 2:
		SEC_TST_PRT("uadk entry init2!\n");
		ret = aead_init2(type, mode);
		break;
	default:
		SEC_TST_PRT("unsupported aead init-type%u!\n", g_init);
		break;
	}

	return ret;
}

static void aead_uninit1(void)
{
	int i;

	if (g_use_env) {
		wd_aead_env_uninit();
		return;
	}

	wd_aead_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
}

static void aead_uninit2(void)
{
	wd_aead_uninit2();
}

static void aead_uninit_config(void)
{
	switch (g_init) {
	case 0:
	case 1:
		aead_uninit1();
		break;
	case 2:
		aead_uninit2();
		break;
	default:
		SEC_TST_PRT("unsupported aead uninit-type%u!\n", g_init);
	}
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
	struct wd_aead_sess_setup setup = {0};
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	struct timeval start_tval;
	struct timeval cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	unsigned long cnt = g_times;
	__u16 mac_bytes;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int ret;
	size_t unit_sz;

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
		ret = -EINVAL;
		goto out;
	}

	/* should set key */
	dump_mem("req src key--->:", WD_FLAT_BUF, (void *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out_key;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out_key;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out_key;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	mac_bytes = auth_size;
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out_key;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out_key;
	}

	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out_key;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);

	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM)
		mac_bytes = 16;

	req.mac = malloc(mac_bytes);
	if (!req.mac) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_key;
	}
	memset(req.mac, 0, mac_bytes);
	req.mac_bytes = mac_bytes;

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
		goto out_mac;
	}
	unit_sz = cal_unit_sz(in_size, g_sgl_num);
	void *src  = create_buf(WD_FLAT_BUF, in_size, unit_sz);
	if (!src) {
		ret = -ENOMEM;
		goto out_src;
	}

	memset(src, 0, in_size);
	// copy the assoc data in the front of in data
	SEC_TST_PRT("aead set assoc_bytes: %u\n", req.assoc_bytes);
	if (g_direction == 0) {
		memcpy(src, tv->assoc, tv->alen);
		memcpy((src + req.assoc_bytes), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(src, tv->assoc, tv->alen);
		memcpy(src + req.assoc_bytes, tv->ctext, tv->clen - auth_size);
		req.in_bytes = tv->clen - auth_size;
		memcpy(req.mac, tv->ctext + tv->clen - auth_size, auth_size);
	}

	dump_mem("mac addr src is:", 0, req.mac, auth_size);

	req.src = create_buf(g_data_fmt, in_size, unit_sz);
	if (!req.src) {
		ret = -ENOMEM;
		goto out_src;
	}
	copy_mem(g_data_fmt, req.src, WD_FLAT_BUF, src,
			(size_t)(req.in_bytes + tv->alen));
	free(src);
	SEC_TST_PRT("aead req src len: %u\n", tv->alen + req.in_bytes);
	dump_mem("aead req src in--->", g_data_fmt, req.src, tv->alen + req.in_bytes);

	if (g_direction == 0) {
		req.out_bytes = req.assoc_bytes + tv->clen - auth_size;
	} else {
		req.out_bytes = req.assoc_bytes + tv->plen;
	}

	// alloc out buffer memory
	unit_sz = cal_unit_sz(req.out_bytes, g_sgl_num);
	req.dst = create_buf(g_data_fmt, req.out_bytes, unit_sz);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}

	req.iv = malloc(AES_BLOCK_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_iv;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_IV_SIZE;
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

	dump_mem("aead dump out addr is:", g_data_fmt, req.dst, req.out_bytes);
	dump_mem("aead dump mac addr is:", 0, req.mac, auth_size);

	free(req.iv);
out_iv:
	free_buf(g_data_fmt, req.dst);
out_dst:
	free_buf(g_data_fmt, req.src);
out_src:
out_mac:
	free(req.mac);
out_key:
	wd_aead_free_sess(h_sess);
out:
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
	Perf = speed * req->in_bytes / 1024;
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
	struct wd_aead_sess_setup setup = {0};
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	static pthread_t send_td;
	static pthread_t poll_td;
	thread_data_d td_data;
	__u16 mac_bytes;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int ret;
	size_t unit_sz;

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
		goto out;
	}

	h_sess = wd_aead_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out;
	}

	/* should set key */
	dump_mem("aead dump aead key is:", WD_FLAT_BUF, (void *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out_key;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out_key;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out_key;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	mac_bytes = auth_size;
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out_key;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out_key;
	}
	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out_key;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);
	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM)
		mac_bytes = 16;

	req.mac = malloc(mac_bytes);
	if (!req.mac) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_key;
	}
	memset(req.mac, 0, mac_bytes);
	req.mac_bytes = mac_bytes;

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	// copy the assoc data in the front of in data
	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > BUFF_SIZE) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto out_mac;
	}
	req.assoc_bytes = tv->alen;
	unit_sz = cal_unit_sz(BUFF_SIZE, g_sgl_num);
	req.src = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.src) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_src;
	}
	void *src = create_buf(WD_FLAT_BUF, BUFF_SIZE, unit_sz);
	if (!src) {
		SEC_TST_PRT("req src in mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_src;
	}

	if (g_direction == 0) {
		memcpy(src, tv->assoc, tv->alen);
		memcpy((src + tv->alen), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(src, tv->assoc, tv->alen);
		memcpy(src + tv->alen, tv->ctext, tv->clen - auth_size);
		req.in_bytes = tv->clen - auth_size;
		memcpy(req.mac, tv->ctext + tv->clen - auth_size, auth_size);
	}

	copy_mem(g_data_fmt, req.src, WD_FLAT_BUF, src,
			(size_t)(req.in_bytes + tv->alen));
	free(src);
	SEC_TST_PRT("aead req alen--->: %u. in_bytes--->:%u\n", tv->alen, req.in_bytes);
	dump_mem("aead dump req in is:", g_data_fmt, req.src, tv->alen + req.in_bytes);

	// alloc out buffer memory
	req.dst = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}

	if (g_direction == 0)
		req.out_bytes = tv->alen + tv->clen;
	else
		req.out_bytes = tv->alen + tv->plen;

	// set iv
	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_iv;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_IV_SIZE;
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
		goto out_thr;
	}

	/* poll thread */
	ret = pthread_create(&poll_td, NULL, aead_poll_thread, &td_data);
	if (ret) {
		SEC_TST_PRT("kthread create fail at %s", __func__);
		goto out_thr;
	}

	ret = pthread_join(send_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out_thr;
	}

	ret = pthread_join(poll_td, NULL);
	if (ret) {
		SEC_TST_PRT("pthread_join fail at %s", __func__);
		goto out_thr;
	}

	dump_mem("dump aead dst data", g_data_fmt, req.dst, req.out_bytes);
	dump_mem("dump aead dst mac", g_data_fmt, req.mac, 8);
out_thr:
	free(req.iv);
out_iv:
	free_buf(g_data_fmt, req.dst);
out_dst:
	free_buf(g_data_fmt, req.src);
out_src:
out_mac:
	free(req.mac);
out_key:
	wd_aead_free_sess(h_sess);
out:
	aead_uninit_config();

	return ret;
}

static int sec_aead_sync_multi(void)
{
	struct wd_aead_sess_setup setup = {0};
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	static pthread_t sendtd[64];
	thread_data_d td_data;
	__u16 mac_bytes;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int i, ret;
	size_t unit_sz;

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
		goto out;
	}

	h_sess = wd_aead_alloc_sess(&setup);
	if (!h_sess) {
		ret = -EINVAL;
		goto out;
	}

	/* should set key */
	dump_mem("dump aead key", WD_FLAT_BUF, (void *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM) {
		ret = wd_aead_set_ckey(h_sess, (const __u8*)tv->key, tv->klen);
		if (ret) {
			SEC_TST_PRT("aead sess set key failed!\n");
			goto out_key;
		}
	} else {
		// AEAD template's cipher key is the tail data
		ret = wd_aead_set_ckey(h_sess, (__u8*)tv->key + 0x28, 0x10);
		if (ret) {
			SEC_TST_PRT("set cipher key fail!\n");
			goto out_key;
		}
		// AEAD template's auth key is the mid data
		ret = wd_aead_set_akey(h_sess, (__u8*)tv->key + 0x08, 0x20);
		if (ret) {
			SEC_TST_PRT("set auth key fail!\n");
			goto out_key;
		}
	}

	auth_size = (__u16)(tv->clen - tv->plen);
	mac_bytes = auth_size;
	ret = wd_aead_set_authsize(h_sess, auth_size);
	if (ret) {
		SEC_TST_PRT("set auth size fail, authsize: %u\n", auth_size);
		goto out_key;
	}

	// test the auth size
	ret = wd_aead_get_authsize(h_sess);
	if (ret != auth_size) {
		SEC_TST_PRT("get auth size fail!\n");
		goto out_key;
	}
	ret = wd_aead_get_maxauthsize(h_sess);
	if (ret < auth_size) {
		SEC_TST_PRT("get max auth size fail!\n");
		goto out_key;
	}
	SEC_TST_PRT("aead get max auth size: %u\n", ret);

	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM)
		mac_bytes = 16;

	req.mac = malloc(mac_bytes);
	if (!req.mac) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_key;
	}
	memset(req.mac, 0, mac_bytes);
	req.mac_bytes = mac_bytes;

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	req.assoc_bytes = tv->alen;
	// copy the assoc data in the front of in data
	in_size = tv->alen + tv->plen + auth_size;
	if (in_size > BUFF_SIZE) {
		SEC_TST_PRT("alloc in buffer block size too small!\n");
		goto out_mac;
	}
	unit_sz = cal_unit_sz(BUFF_SIZE, g_sgl_num);
	void *src  = create_buf(WD_FLAT_BUF, BUFF_SIZE, unit_sz);
	if (!src) {
		ret = -ENOMEM;
		goto out_src;
	}

	if (g_direction == 0) {
		memcpy(src, tv->assoc, tv->alen);
		memcpy((src + tv->alen), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(src, tv->assoc, tv->alen);
		memcpy(src + tv->alen, tv->ctext, tv->clen - auth_size);
		req.in_bytes = tv->clen - auth_size;
		memcpy(req.mac, tv->ctext + tv->clen - auth_size, auth_size);
	}

	req.src = create_buf(g_data_fmt, in_size, unit_sz);
	if (!req.src) {
		ret = -ENOMEM;
		goto out_src;
	}

	copy_mem(g_data_fmt, req.src, WD_FLAT_BUF, src,
			(size_t)(req.in_bytes + tv->alen));
	free(src);

	SEC_TST_PRT(" alen:%u, input len:%d\n", tv->alen, req.in_bytes);
	dump_mem("aead req src in--->:", g_data_fmt, req.src, tv->alen + req.in_bytes);

	// alloc out buffer memory
	req.dst = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}

	if (g_direction == 0)
		req.out_bytes = tv->alen + tv->clen;
	else
		req.out_bytes = tv->alen + tv->plen;

	// set iv
	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		SEC_TST_PRT("req iv mem malloc failed!\n");
		ret = -ENOMEM;
		goto out_iv;
	}
	if (setup.cmode == WD_CIPHER_GCM)
		iv_len = GCM_IV_SIZE;
	else
		iv_len = AES_BLOCK_SIZE;
	req.iv_bytes = iv_len;
	memcpy(req.iv, tv->iv, iv_len);
	req.data_fmt = g_data_fmt;

	td_data.h_sess = h_sess;
	td_data.areq = &req;
	/* send thread */
	td_data.send_num = g_times;
	td_data.recv_num = g_times;
	td_data.sum_perf = 0;

	printf("%s, req->in_bytes:%d\n", __func__, req.in_bytes);
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_create(&sendtd[i], NULL, aead_sync_send_thread, &td_data);
		if (ret) {
			SEC_TST_PRT("Create send thread fail!\n");
			goto out_thr;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(sendtd[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join sendtd thread fail!\n");
			goto out_thr;
		}
	}

	dump_mem("aead req src out--->:", g_data_fmt, req.dst, req.out_bytes);
out_thr:
	free(req.iv);
out_iv:
	free_buf(g_data_fmt, req.dst);
out_dst:
	free_buf(g_data_fmt, req.src);
out_src:
out_mac:
	free(req.mac);
out_key:
	wd_aead_free_sess(h_sess);
out:
	aead_uninit_config();

	return ret;
}

static int sec_aead_async_multi(void)
{
	struct wd_aead_sess_setup setup = {0};
	struct aead_testvec *tv = NULL;
	handle_t h_sess = 0;
	struct wd_aead_req req;
	static pthread_t send_td[64];
	static pthread_t poll_td;
	thread_data_d td_data;
	__u16 mac_bytes;
	__u16 auth_size;
	__u16 in_size;
	__u16 iv_len;
	int i, ret;
	size_t unit_sz;

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
	dump_mem("aead set key--->:", WD_FLAT_BUF, (void *)tv->key, tv->klen);
	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM) {
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
	mac_bytes = auth_size;
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

	if (setup.cmode == WD_CIPHER_CCM || setup.cmode == WD_CIPHER_GCM)
		mac_bytes = 16;

	req.mac = malloc(mac_bytes);
	if (req.mac == NULL)
		goto out;
	memset(req.mac, 0, mac_bytes);
	req.mac_bytes = mac_bytes;

	if (g_direction == 0)
		req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	req.assoc_bytes = tv->alen;
	void *src = malloc(BUFF_SIZE);
	if (!src) {
		SEC_TST_PRT("src in mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	unit_sz = cal_unit_sz(BUFF_SIZE, g_sgl_num);
	req.src  = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.src) {
		SEC_TST_PRT(" req src in mem malloc failed!\n");
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
		memcpy(src, tv->assoc, tv->alen);
		memcpy((src + tv->alen), tv->ptext, tv->plen);
		req.in_bytes = tv->plen;
	} else {
		memcpy(src, tv->assoc, tv->alen);
		memcpy(src + tv->alen, tv->ctext, tv->clen - auth_size);
		req.in_bytes = tv->clen - auth_size;
		memcpy(req.mac, tv->ctext + (tv->clen - auth_size), auth_size);
	}

	copy_mem(g_data_fmt, req.src, WD_FLAT_BUF, src,
			(size_t)(req.in_bytes + tv->alen));
	free(src);
	SEC_TST_PRT("src len: %u\n", tv->alen + req.in_bytes);
	dump_mem("aead req src in--->", g_data_fmt, req.src, tv->alen + req.in_bytes);

	// alloc out buffer memory
	req.dst = create_buf(g_data_fmt, BUFF_SIZE, unit_sz);
	if (!req.dst) {
		SEC_TST_PRT("req dst out mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (g_direction == 0)
		req.out_bytes = tv->alen + tv->clen - auth_size;
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
		iv_len = GCM_IV_SIZE;
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

	dump_mem("aead req src out--->", g_data_fmt, req.dst, req.out_bytes);
out:
	if (req.mac)
		free(req.mac);
	if (req.src)
		free_buf(g_data_fmt, req.src);
	if (req.dst)
		free_buf(g_data_fmt, req.dst);
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
	int ret;

	int expt = g_times * g_thread_num;

	do {
		ret = wd_cipher_poll(expt, &count);
		if (ret < 0 && ret != -EAGAIN) {
			SEC_TST_PRT("poll ctx error: %d\n", ret);
			break;
		}
	} while (expt - count);

	pthread_exit(NULL);

	return NULL;
}

static int sva_async_create_threads(int thread_num,
				    thread_data_t *tds)
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
		ret = pthread_create(&system_test_thrds[i], &attr,
				     sva_sec_cipher_async, &tds[i]);
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

static int sva_sync_create_threads(int thread_num, thread_data_t *tds)
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
		ret = pthread_create(&system_test_thrds[i], &attr,
				     sva_sec_cipher_sync, &tds[i]);
		if (ret) {
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

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
		ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	else
		ret = init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
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

		datas[i].tid = i;
		datas[i].req = &req[i];
		datas[i].setup = &setup[i];
	}

	if (g_syncmode == 0)
		ret = sva_sync_create_threads(threads, datas);
	else
		ret = sva_async_create_threads(threads, datas);
	if (ret < 0)
		goto out_config;

out_config:
	uninit_config();
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
	SEC_TST_PRT("	uadk_tool test --m sec: test wd sec function,etc\n");
	SEC_TST_PRT("USAGE\n");
	SEC_TST_PRT("    uadk_tool test --m sec [--cipher] [--digest] [--aead] [--perf]\n");
	SEC_TST_PRT("    uadk_tool test --m sec [--optype] [--pktlen] [--keylen] [--times]\n");
	SEC_TST_PRT("    uadk_tool test --m sec [--multi] [--sync] [--async] [--help]\n");
	SEC_TST_PRT("    uadk_tool test --m sec [--block] [--blknum] [--ctxnum]\n");
	SEC_TST_PRT("    numactl --cpubind=0  --membind=0,1 ./uadk_tool test --m sec xxxx\n");
	SEC_TST_PRT("        specify numa nodes for cpu and memory\n");
	SEC_TST_PRT("DESCRIPTION\n");
	SEC_TST_PRT("    [--cipher ]:\n");
	SEC_TST_PRT("        specify symmetric cipher algorithm\n");
	SEC_TST_PRT("        0 : AES-ECB; 1 : AES-CBC;  2 : AES-XTS;  3 : AES-OFB\n");
	SEC_TST_PRT("        4 : AES-CFB; 5 : 3DES-ECB; 6 : 3DES-CBC; 7 : SM4-CBC\n");
	SEC_TST_PRT("        8 : SM4-XTS; 9 : SM4-OFB; 10 : SM4-CFB; 11 : SM4-ECB\n");
	SEC_TST_PRT("        12 : AES-CBC_CS1; 13 : AES-CBC_CS2; 14 : AES-CBC_CS3\n");
	SEC_TST_PRT("    [--digest ]:\n");
	SEC_TST_PRT("        specify symmetric hash algorithm\n");
	SEC_TST_PRT("        0 : SM3;    1 : MD5;    2 : SHA1;   3 : SHA256\n");
	SEC_TST_PRT("        4 : SHA224; 5 : SHA384; 6 : SHA512; 7 : SHA512_224\n");
	SEC_TST_PRT("        8 : SHA512_256; 9 : AES_CMAC; 10 : AES_GMAC_128\n");
	SEC_TST_PRT("        11 : AES_GMAC_192; 12 : AES_GMAC_256; 13 : AES_XCBC_MAC_96\n");
	SEC_TST_PRT("        14 : AES_XCBC_PRF_128\n");
	SEC_TST_PRT("    [--aead ]:\n");
	SEC_TST_PRT("        specify symmetric aead algorithm\n");
	SEC_TST_PRT("        0 : AES-CCM; 1 : AES-GCM;  2 : Hmac(sha256),cbc(aes)\n");
	SEC_TST_PRT("    [--sync]: start synchronous mode test\n");
	SEC_TST_PRT("    [--async]: start asynchronous mode test\n");
	SEC_TST_PRT("    [--optype]:\n");
	SEC_TST_PRT("        0 : encryption operation or normal mode for hash\n");
	SEC_TST_PRT("        1 : decryption operation or hmac mode for hash\n");
	SEC_TST_PRT("        3 : hmac mode for stream hash mode\n");
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
	SEC_TST_PRT("    [--stream]:\n");
	SEC_TST_PRT("        set the steam mode for digest\n");
	SEC_TST_PRT("    [--sglnum]:\n");
	SEC_TST_PRT("        the number of scatterlist number used by the entire test task\n");
	SEC_TST_PRT("    [--help]  = usage\n");
	SEC_TST_PRT("Example\n");
	SEC_TST_PRT("    ./uadk_tool test --m sec --cipher 0 --sync --optype 0\n");
	SEC_TST_PRT("--pktlen 16 --keylen 16 --times 1 --multi 1\n");
	SEC_TST_PRT("    ./uadk_tool test --m sec --digest 0 --sync --optype 0\n");
	SEC_TST_PRT("--pktlen 16 --keylen 16 --times 1 --multi 2 --stream\n");
	SEC_TST_PRT("    ./uadk_tool test --m sec --digest 1 --sync --optype 0\n");
	SEC_TST_PRT("--pktlen 16 --keylen 16 --times 1 --multi 2 --stream\n");
	SEC_TST_PRT("    ./uadk_tool test --m sec --perf --sync --pktlen 1024 --block 1024\n");
	SEC_TST_PRT("--blknum 100000 --times 10000 --multi 1 --ctxnum 1\n");
	SEC_TST_PRT("UPDATE:2022-12-16\n");
}

static void test_sec_cmd_parse(int argc, char *argv[], struct test_sec_option *option)
{
	int option_index = 0;
	int c;

	static struct option long_options[] = {
		{"help",      no_argument,       0,  0},
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
		{"stream",    no_argument,       0,  15},
		{"sglnum",    required_argument, 0,  16},
		{"use_env",   no_argument,       0,  17},
		{"init",      required_argument, 0,  18},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			print_help();
			exit(-1);
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
			option->stream_mode = 1;
			break;
		case 16:
			option->sgl_num = strtol(optarg, NULL, 0);
			break;
		case 17:
			option->use_env = 1;
			break;
		case 18:
			option->init = strtol(optarg, NULL, 0);
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
	g_use_env = option->use_env;
	g_times = option->times ? option->times : 1;
	g_ctxnum = option->ctxnum ? option->ctxnum : 1;
	g_data_fmt = option->sgl_num ? WD_SGL_BUF : WD_FLAT_BUF;
	g_sgl_num = option->sgl_num;
	g_stream = option->stream_mode;
	g_init = option->init;
	SEC_TST_PRT("set global times is %lld\n", g_times);

	g_thread_num = option->xmulti ? option->xmulti : 1;
	g_direction = option->optype;
	if (option->algclass == DIGEST_CLASS) {
		//0 is normal mode, 1 is HMAC mode
		g_alg_op_type = g_direction;
		if (g_stream)
			g_ivlen = 1;
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

static void long_hash_data_init(void)
{
	g_long_hash_tv.plaintext = malloc(g_pktlen);
	if (g_long_hash_tv.plaintext == NULL)
		return;

	g_long_hash_tv.psize = g_pktlen;

	g_long_hash_tv.key = malloc(16);
	if (g_long_hash_tv.key == NULL) {
		free(g_long_hash_tv.plaintext);
		return;
	}
	g_long_hash_tv.ksize = 16;
}

static void long_hash_data_uninit(void)
{
	free(g_long_hash_tv.plaintext);
	free(g_long_hash_tv.key);
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
			SEC_TST_PRT("hisi_sec HMAC-digest mode.\n");
			long_hash_data_init();
			if (g_thread_num > 1 && g_direction != 3) {
				SEC_TST_PRT("currently digest test is synchronize psize:%u, multi -%d threads!\n", g_pktlen, g_thread_num);
				ret = sec_digest_sync_multi();
			} else if (g_thread_num > 1 && g_stream) {
				ret = sec_digest_sync_stream_mode_multi();
				(void)sec_digest_sync_stream_cmp();
				SEC_TST_PRT("currently digest long hash mode, psize:%u, multi thread!\n", g_pktlen);
			} else if (g_thread_num == 1 && g_stream) {
				if (g_ivlen == 1) {
					ret = sec_digest_sync_stream_mode();
					(void)sec_digest_sync_stream_cmp();
					SEC_TST_PRT("currently digest long hash mode, psize:%u, one thread!\n", g_pktlen);
				}
			} else {
				ret = sec_digest_sync_once();
				SEC_TST_PRT("currently digest test is synchronize once, one thread!\n");
			}
			long_hash_data_uninit();
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

int test_sec_entry(int argc, char *argv[])
{
	struct test_sec_option option = {0};
	int ret = 0;

	SEC_TST_PRT("this is a hisi sec test.\n");

	g_thread_num = 1;
	if (!argv[1 + SEC_ARGV_OFFSET])
		return test_sec_default_case();

	test_sec_cmd_parse(argc, argv, &option);
	ret = test_sec_option_convert(&option);
	if (ret)
		return ret;

	if (option.algclass == PERF_CLASS)
		return sec_sva_test();

	pthread_mutex_init(&test_sec_mutex, NULL);

	return test_sec_run(option.syncmode, option.algclass);
}
