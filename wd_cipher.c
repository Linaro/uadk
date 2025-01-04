/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <limits.h>
#include "include/drv/wd_cipher_drv.h"
#include "wd_cipher.h"
#include "adapter.h"

#define XTS_MODE_KEY_SHIFT	1
#define XTS_MODE_KEY_LEN_MASK	0x1

#define DES_WEAK_KEY_NUM	16

static const unsigned char des_weak_keys[DES_WEAK_KEY_NUM][DES_KEY_SIZE] = {
	/* weak keys */
	{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
	{0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
	{0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
	{0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},
	/* semi-weak keys */
	{0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
	{0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01},
	{0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1},
	{0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E},
	{0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1},
	{0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01},
	{0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE},
	{0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E},
	{0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E},
	{0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01},
	{0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE},
	{0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1}
};

static char *wd_cipher_alg_name[WD_CIPHER_ALG_TYPE_MAX][WD_CIPHER_MODE_TYPE_MAX] = {
	{"ecb(sm4)", "cbc(sm4)", "ctr(sm4)", "xts(sm4)", "ofb(sm4)",
	 "cfb(sm4)", "cbc-cs1(sm4)", "cbc-cs2(sm4)", "cbc-cs3(sm4)",
	 "", "", "xts(sm4)"},
	{"ecb(aes)", "cbc(aes)", "ctr(aes)", "xts(aes)", "ofb(aes)",
	 "cfb(aes)", "cbc-cs1(aes)", "cbc-cs2(aes)", "cbc-cs3(aes)"},
	{"ecb(des)", "cbc(des)",},
	{"ecb(des3_ede)", "cbc(des3_ede)",}
};

struct wd_cipher_setting {
	enum wd_status status;
	void *dlhandle;
	void *dlh_list;
	struct uadk_adapter *adapter;
} wd_cipher_setting;

struct wd_cipher_sess {
	char			*alg_name;
	enum wd_cipher_alg	alg;
	enum wd_cipher_mode	mode;
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_cipher	*drv;
	void			*priv;
	unsigned char		key[MAX_CIPHER_KEY_SIZE];
	__u32			key_bytes;
	void			**sched_key;
	struct uadk_adapter_worker *worker;
	pthread_spinlock_t worker_lock;
	int worker_looptime;
};

struct wd_env_config wd_cipher_env_config;
static struct wd_init_attrs wd_cipher_init_attrs;

void wd_cipher_switch_worker(struct wd_cipher_sess *sess, int para)
{
	struct uadk_adapter_worker *worker;

	pthread_spin_lock(&sess->worker_lock);
	worker = uadk_adapter_switch_worker(wd_cipher_setting.adapter,
					    sess->worker, para);
	if (worker)
		sess->worker = worker;
	sess->worker_looptime = 0;
	pthread_spin_unlock(&sess->worker_lock);
}

static void wd_cipher_close_driver(int init_type)
{
#ifndef WD_STATIC_DRV
	if (init_type == WD_TYPE_V2) {
		wd_dlclose_drv(wd_cipher_setting.dlh_list);
		return;
	}

	if (wd_cipher_setting.dlhandle) {
		dlclose(wd_cipher_setting.dlhandle);
		wd_cipher_setting.dlhandle = NULL;
	}
#else
	hisi_sec2_remove();
#endif
}

static int wd_cipher_open_driver(int init_type)
{
#ifndef WD_STATIC_DRV
	char lib_path[PATH_MAX];
	int ret;

	if (init_type == WD_TYPE_V2) {
		/*
		 * Driver lib file path could set by env param.
		 * then open tham by wd_dlopen_drv()
		 * use NULL means dynamic query path
		 */
		wd_cipher_setting.dlh_list = wd_dlopen_drv(NULL);
		if (!wd_cipher_setting.dlh_list) {
			WD_ERR("fail to open driver lib files.\n");
			return -WD_EINVAL;
		}

		return WD_SUCCESS;
	}

	ret = wd_get_lib_file_path("libhisi_sec.so", lib_path, false);
	if (ret)
		return ret;

	wd_cipher_setting.dlhandle = dlopen(lib_path, RTLD_NOW);
	if (!wd_cipher_setting.dlhandle) {
		WD_ERR("failed to open libhisi_sec.so, %s\n", dlerror());
		return -WD_EINVAL;
	}
#else
	hisi_sec2_probe();
	if (init_type == WD_TYPE_V2)
		return WD_SUCCESS;
#endif

	return WD_SUCCESS;
}

static bool is_des_weak_key(const __u8 *key)
{
	int i;

	for (i = 0; i < DES_WEAK_KEY_NUM; i++) {
		if (memcmp(des_weak_keys[i], key, DES_KEY_SIZE) == 0)
			return true;
	}

	return false;
}

static int aes_key_len_check(__u32 length)
{
	switch (length) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		return 0;
	default:
		return -WD_EINVAL;
	}
}

static int cipher_key_len_check(struct wd_cipher_sess *sess, __u32 length)
{
	__u32 key_len = length;
	int ret = 0;

	if (sess->mode == WD_CIPHER_XTS || sess->mode == WD_CIPHER_XTS_GB) {
		if (length & XTS_MODE_KEY_LEN_MASK) {
			WD_ERR("invalid: unsupported XTS key length, length = %u!\n", length);
			return -WD_EINVAL;
		}
		key_len = length >> XTS_MODE_KEY_SHIFT;

		if (key_len == AES_KEYSIZE_192) {
			WD_ERR("invalid: unsupported XTS key length, length = %u!\n", length);
			return -WD_EINVAL;
		}
	}

	switch (sess->alg) {
	case WD_CIPHER_SM4:
		if (key_len != SM4_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_AES:
		ret = aes_key_len_check(key_len);
		break;
	case WD_CIPHER_DES:
		if (key_len != DES_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_3DES:
		if (key_len != DES3_2KEY_SIZE && key_len != DES3_3KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	default:
		WD_ERR("cipher input alg err, alg = %d\n", sess->alg);
		return -WD_EINVAL;
	}

	return ret;
}

static bool wd_cipher_alg_check(const char *alg_name)
{
	int i, j;

	for (i = 0; i < WD_CIPHER_ALG_TYPE_MAX; i++) {
		for (j = 0; j < WD_CIPHER_MODE_TYPE_MAX; j++) {
			/* Some algorithms do not support all modes */
			if (!wd_cipher_alg_name[i][j] ||
			     !strlen(wd_cipher_alg_name[i][j]))
				continue;
			if (!strcmp(alg_name, wd_cipher_alg_name[i][j]))
				return true;
		}
	}

	return false;
}

int wd_cipher_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	int ret;

	if (!key || !sess) {
		WD_ERR("invalid: cipher set key input param err!\n");
		return -WD_EINVAL;
	}

	ret = cipher_key_len_check(sess, key_len);
	if (ret) {
		WD_ERR("cipher set key input key length err!\n");
		return -WD_EINVAL;
	}
	if (sess->alg == WD_CIPHER_DES && is_des_weak_key(key)) {
		WD_ERR("input des key is weak key!\n");
		return -WD_EINVAL;
	}

	sess->key_bytes = key_len;
	memcpy(sess->key, key, key_len);

	return 0;
}

handle_t wd_cipher_alloc_sess(struct wd_cipher_sess_setup *setup)
{
	struct uadk_adapter_worker *worker;
	struct wd_cipher_sess *sess = NULL;
	int nb = wd_cipher_setting.adapter->workers_nb;
	int ret, i;

	if (unlikely(!setup)) {
		WD_ERR("invalid: cipher input setup is NULL!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_cipher_sess));
	if (!sess) {
		WD_ERR("failed to alloc session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_cipher_sess));

	if (setup->alg >= WD_CIPHER_ALG_TYPE_MAX ||
	     setup->mode >= WD_CIPHER_MODE_TYPE_MAX) {
		WD_ERR("failed to check algorithm!\n");
		goto err_sess;
	}

	worker = sess->worker = &wd_cipher_setting.adapter->workers[0];
	worker->valid = true;

	sess->worker_looptime = 0;
	sess->alg_name = wd_cipher_alg_name[setup->alg][setup->mode];
	ret = wd_drv_alg_support(sess->alg_name, worker->driver);
	if (!ret) {
		WD_ERR("failed to support this algorithm: %s!\n", sess->alg_name);
		goto err_sess;
	}
	sess->alg = setup->alg;
	sess->mode = setup->mode;

	sess->sched_key = (void **)calloc(nb, sizeof(void *));
	for (i = 0; i < nb; i++) {
		worker = &wd_cipher_setting.adapter->workers[i];

		sess->sched_key[i] = (void *)worker->sched->sched_init(
				worker->sched->h_sched_ctx, setup->sched_param);
		if (WD_IS_ERR(sess->sched_key[i])) {
			WD_ERR("failed to init session schedule key!\n");
			goto err_sess;
		}
	}

	return (handle_t)sess;

err_sess:
	if (sess->sched_key) {
		for (i = 0; i < nb; i++)
			free(sess->sched_key[i]);
		free(sess->sched_key);
	}
	free(sess);
	return (handle_t)0;
}

void wd_cipher_free_sess(handle_t h_sess)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("invalid: cipher input h_sess is NULL!\n");
		return;
	}

	wd_memset_zero(sess->key, sess->key_bytes);

	if (sess->sched_key) {
		for (int i = 0; i < wd_cipher_setting.adapter->workers_nb; i++)
			free(sess->sched_key[i]);
		free(sess->sched_key);
	}
	free(sess);
}

static void wd_cipher_clear_status(void)
{
	wd_alg_clear_init(&wd_cipher_setting.status);
}

static int wd_cipher_common_init(struct uadk_adapter_worker *worker,
				 struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_CIPHER_EPOLL_EN",
			      &worker->config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&worker->config, worker->ctx_config);
	if (ret < 0)
		return ret;

	worker->config.pool = &worker->pool;
	sched->worker = worker;
	worker->sched = sched;

	/* allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&worker->pool,
					 worker->ctx_config, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_cipher_msg));
	if (ret < 0)
		goto out_clear_ctx_config;

	ret = wd_alg_init_driver(&worker->config, worker->driver);
	if (ret)
		goto out_clear_pool;

	return 0;

out_clear_pool:
	wd_uninit_async_request_pool(&worker->pool);
out_clear_ctx_config:
	wd_clear_ctx_config(&worker->config);
	return ret;
}

static int wd_cipher_common_uninit(void)
{
	struct uadk_adapter_worker *worker;
	enum wd_status status;

	wd_alg_get_init(&wd_cipher_setting.status, &status);
	if (status == WD_UNINIT)
		return -WD_EINVAL;

	/* uninit async request pool */
	for (int i = 0; i < wd_cipher_setting.adapter->workers_nb; i++) {
		worker = &wd_cipher_setting.adapter->workers[i];
		wd_uninit_async_request_pool(&worker->pool);
		wd_alg_uninit_driver(&worker->config, worker->driver);
	}

	return 0;
}

int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	char *alg = "cbc(aes)";
	int ret;

	pthread_atfork(NULL, NULL, wd_cipher_clear_status);

	ret = wd_alg_try_init(&wd_cipher_setting.status);
	if (ret)
		return ret;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_clear_init;

	wd_cipher_setting.adapter = adapter;

	ret = wd_cipher_open_driver(WD_TYPE_V1);
	if (ret)
		goto out_clear_init;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_close_driver;

	worker = &adapter->workers[0];
	worker->ctx_config = config;

	ret = wd_cipher_common_init(worker, sched);
	if (ret)
		goto out_close_driver;

	wd_alg_set_init(&wd_cipher_setting.status);

	return 0;

out_close_driver:
	wd_cipher_close_driver(WD_TYPE_V1);
out_clear_init:
	free(adapter);
	wd_alg_clear_init(&wd_cipher_setting.status);
	return ret;
}

void wd_cipher_uninit(void)
{
	int ret;

	ret = wd_cipher_common_uninit();
	if (ret)
		return;

	free(wd_cipher_setting.adapter);
	wd_cipher_close_driver(WD_TYPE_V1);
	wd_alg_clear_init(&wd_cipher_setting.status);
}

int wd_cipher_init2_(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_nums cipher_ctx_num[WD_CIPHER_DECRYPTION + 1] = {0};
	struct wd_ctx_params cipher_ctx_params = {0};
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	int state, ret = -WD_EINVAL;
	bool flag;
	int i;

	pthread_atfork(NULL, NULL, wd_cipher_clear_status);

	state = wd_alg_try_init(&wd_cipher_setting.status);
	if (state)
		return state;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	     task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		goto out_uninit;
	}

	flag = wd_cipher_alg_check(alg);
	if (!flag) {
		WD_ERR("invalid: cipher:%s unsupported!\n", alg);
		goto out_uninit;
	}

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_uninit;
	wd_cipher_setting.adapter = adapter;

	state = wd_cipher_open_driver(WD_TYPE_V2);
	if (state)
		goto out_uninit;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_driver;

	for (i = 0; i < adapter->workers_nb; i++) {
		worker = &adapter->workers[i];

		cipher_ctx_params.ctx_set_num = cipher_ctx_num;
		ret = wd_ctx_param_init(&cipher_ctx_params, ctx_params, worker->driver,
					WD_CIPHER_TYPE, WD_CIPHER_DECRYPTION + 1);
		if (ret) {
			WD_ERR("fail to init ctx param\n");
			goto out_driver;
		}

		wd_cipher_init_attrs.alg = alg;
		wd_cipher_init_attrs.ctx_params = &cipher_ctx_params;
		wd_cipher_init_attrs.alg_init = wd_cipher_common_init;
		wd_cipher_init_attrs.alg_poll_ctx = wd_cipher_poll_ctx_;
		ret = wd_alg_attrs_init(worker, &wd_cipher_init_attrs);
		wd_ctx_param_uninit(&cipher_ctx_params);
		if (ret) {
			WD_ERR("fail to init alg attrs.\n");
			goto out_driver;
		}
	}

	wd_alg_set_init(&wd_cipher_setting.status);

	return 0;

out_driver:
	wd_cipher_close_driver(WD_TYPE_V2);
out_uninit:
	free(adapter);
	wd_alg_clear_init(&wd_cipher_setting.status);
	return ret;
}

void wd_cipher_uninit2(void)
{
	struct uadk_adapter_worker *worker;
	int ret;

	ret = wd_cipher_common_uninit();
	if (ret)
		return;

	for (int i = 0; i < wd_cipher_setting.adapter->workers_nb; i++) {
		worker = &wd_cipher_setting.adapter->workers[i];
		wd_alg_attrs_uninit(worker);
	}

	free(wd_cipher_setting.adapter);
	wd_cipher_close_driver(WD_TYPE_V2);
	wd_cipher_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_cipher_setting.status);
}

static void fill_request_msg(struct wd_cipher_msg *msg,
			     struct wd_cipher_req *req,
			     struct wd_cipher_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_cipher_req));

	msg->alg_type = WD_CIPHER;
	msg->alg = sess->alg;
	msg->mode = sess->mode;
	msg->op_type = req->op_type;
	msg->in = req->src;
	msg->in_bytes = req->in_bytes;
	msg->out = req->dst;
	msg->out_bytes = req->out_bytes;
	msg->key = sess->key;
	msg->key_bytes = sess->key_bytes;
	msg->iv = req->iv;
	msg->iv_bytes = req->iv_bytes;
	msg->data_fmt = req->data_fmt;
}

static int cipher_iv_len_check(struct wd_cipher_req *req,
			       struct wd_cipher_sess *sess)
{
	int ret = 0;

	/* Only the ECB mode does not need iv. */
	if (sess->mode == WD_CIPHER_ECB)
		return 0;

	if (!req->iv) {
		WD_ERR("invalid: cipher input iv is NULL!\n");
		return -WD_EINVAL;
	}

	switch (sess->alg) {
	case WD_CIPHER_AES:
	case WD_CIPHER_SM4:
		if (req->iv_bytes != AES_BLOCK_SIZE) {
			WD_ERR("AES or SM4 input iv bytes is err, size = %u\n",
				req->iv_bytes);
			ret = -WD_EINVAL;
		}
		break;
	case WD_CIPHER_3DES:
	case WD_CIPHER_DES:
		if (req->iv_bytes != DES3_BLOCK_SIZE) {
			WD_ERR("3DES or DES input iv bytes is err, size = %u\n",
				req->iv_bytes);
			ret = -WD_EINVAL;
		}
		break;
	default:
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int cipher_in_len_check(handle_t h_sess, struct wd_cipher_req *req)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	int ret = 0;

	if (!req->in_bytes) {
		WD_ERR("invalid: cipher input length is zero!\n");
		return -WD_EINVAL;
	}

	if (sess->alg != WD_CIPHER_AES && sess->alg != WD_CIPHER_SM4)
		return 0;

	switch (sess->mode) {
	case WD_CIPHER_ECB:
	case WD_CIPHER_CBC:
		if (req->in_bytes & (AES_BLOCK_SIZE - 1))
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_CBC_CS1:
	case WD_CIPHER_CBC_CS2:
	case WD_CIPHER_CBC_CS3:
		if (req->in_bytes < AES_BLOCK_SIZE)
			ret = -WD_EINVAL;
		break;
	default:
		break;
	}

	if (ret)
		WD_ERR("invalid: %s input bytes is %u!\n",
		       wd_cipher_alg_name[sess->alg][sess->mode], req->in_bytes);

	return ret;
}

static int wd_cipher_check_params(handle_t h_sess,
				  struct wd_cipher_req *req, __u8 mode)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	int ret;

	if (unlikely(!h_sess || !req)) {
		WD_ERR("invalid: cipher input sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_ASYNC && !req->cb)) {
		WD_ERR("invalid: cipher req cb is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->in_bytes)) {
		WD_ERR("cipher set out_buf_bytes is error, size = %u\n",
			req->out_buf_bytes);
		return -WD_EINVAL;
	}

	ret = cipher_in_len_check(h_sess, req);
	if (unlikely(ret))
		return ret;

	if (req->data_fmt == WD_SGL_BUF) {
		ret = wd_check_datalist(req->list_src, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist, len = %u\n",
				req->in_bytes);
			return -WD_EINVAL;
		}

		/* cipher dst len is equal to src len */
		ret = wd_check_datalist(req->list_dst, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the dst datalist, len = %u\n",
				req->in_bytes);
			return -WD_EINVAL;
		}
	} else {
		ret = wd_check_src_dst(req->src, req->in_bytes, req->dst, req->out_bytes);
		if (unlikely(ret)) {
			WD_ERR("invalid: src/dst addr is NULL when src/dst size is non-zero!\n");
			return -WD_EINVAL;
		}
	}

	return cipher_iv_len_check(req, sess);
}

static int send_recv_sync(struct uadk_adapter_worker *worker, struct wd_ctx_internal *ctx,
			  struct wd_cipher_msg *msg)
{
	struct wd_msg_handle msg_handle;
	int ret;

	msg_handle.send = worker->driver->send;
	msg_handle.recv = worker->driver->recv;

	wd_ctx_spin_lock(ctx, worker->driver->calc_type);
	ret = wd_handle_msg_sync(worker->driver, &msg_handle, ctx->ctx,
				 msg, NULL, worker->config.epoll_en);
	wd_ctx_spin_unlock(ctx, worker->driver->calc_type);

	return ret;
}

int wd_do_cipher_sync(handle_t h_sess, struct wd_cipher_req *req)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg msg;
	__u32 idx;
	int ret;

	ret = wd_cipher_check_params(h_sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check cipher params!\n");
		return ret;
	}

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	memset(&msg, 0, sizeof(struct wd_cipher_msg));
	fill_request_msg(&msg, req, sess);
	req->state = 0;

	idx = worker->sched->pick_next_ctx(
		     worker->sched->h_sched_ctx,
		     sess->sched_key[worker->idx], CTX_MODE_SYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);
	ctx = worker->config.ctxs + idx;

	ret = send_recv_sync(worker, ctx, &msg);
	req->state = msg.result;

	if (ret) {
		wd_cipher_switch_worker(sess, 1);
		sess->worker_looptime++;
		return ret;
	}

	if ((sess->worker_looptime != 0) ||
	    (wd_cipher_setting.adapter->mode == UADK_ADAPT_MODE_ROUNDROBIN)) {
		sess->worker_looptime++;
	}

	if (sess->worker_looptime >= wd_cipher_setting.adapter->looptime)
		wd_cipher_switch_worker(sess, 0);

	return ret;
}

int wd_do_cipher_async(handle_t h_sess, struct wd_cipher_req *req)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg *msg;
	int msg_id, ret;
	__u32 idx;

	ret = wd_cipher_check_params(h_sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check cipher params!\n");
		return ret;
	}

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	if (worker->driver->mode == UADK_DRV_SYNCONLY) {
		ret = wd_do_cipher_sync(h_sess, req);
		if (!ret) {
			pthread_mutex_lock(&worker->mutex);
			worker->async_recv++;
			pthread_mutex_unlock(&worker->mutex);
			req->cb(req, req->cb_param);
		}
		return ret;
	}

	idx = worker->sched->pick_next_ctx(
		     worker->sched->h_sched_ctx,
		     sess->sched_key[worker->idx], CTX_MODE_ASYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = worker->config.ctxs + idx;

	msg_id = wd_get_msg_from_pool(&worker->pool, idx, (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("failed to get msg from pool!\n");
		return msg_id;
	}

	fill_request_msg(msg, req, sess);
	msg->tag = msg_id;

	ret = wd_alg_driver_send(worker->driver, ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("wd cipher async send err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);
	ret = wd_add_task_to_async_queue(&wd_cipher_env_config, idx);
	if (ret)
		goto fail_with_msg;

	if ((sess->worker_looptime != 0) ||
	    (wd_cipher_setting.adapter->mode == UADK_ADAPT_MODE_ROUNDROBIN))
		sess->worker_looptime++;

	if (sess->worker_looptime >= wd_cipher_setting.adapter->looptime)
		wd_cipher_switch_worker(sess, 0);

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&worker->pool, idx, msg->tag);
	wd_cipher_switch_worker(sess, 1);
	sess->worker_looptime++;
	return ret;
}

int wd_cipher_poll_ctx_(struct wd_sched *sched, __u32 idx, __u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg resp_msg, *msg;
	struct wd_cipher_req *req;
	__u64 recv_count = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count || !expt)) {
		WD_ERR("invalid: cipher poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

	/* back-compatible with init1 api */
	if (sched == NULL)
		worker = &wd_cipher_setting.adapter->workers[0];
	else
		worker = sched->worker;

	*count = 0;

	if (worker->driver->mode == UADK_DRV_SYNCONLY) {
		pthread_mutex_lock(&worker->mutex);
		if (worker->async_recv > 0) {
			*count = worker->async_recv > expt ? expt : worker->async_recv;
			worker->async_recv -= *count;
		}
		pthread_mutex_unlock(&worker->mutex);
		return 0;
	}

	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = worker->config.ctxs + idx;

	do {
		ret = wd_alg_driver_recv(worker->driver, ctx->ctx, &resp_msg);
		if (ret == -WD_EAGAIN)
			return ret;
		else if (ret < 0) {
			WD_ERR("wd cipher recv hw err!\n");
			return ret;
		}
		recv_count++;
		msg = wd_find_msg_in_pool(&worker->pool, idx,
					  resp_msg.tag);
		if (!msg) {
			WD_ERR("failed to find msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->tag = resp_msg.tag;
		msg->req.state = resp_msg.result;
		req = &msg->req;

		req->cb(req, req->cb_param);
		/* free msg cache to msg_pool */
		wd_put_msg_to_pool(&worker->pool, idx, resp_msg.tag);
		*count = recv_count;
	} while (--tmp);

	return ret;
}

int wd_cipher_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	return wd_cipher_poll_ctx_(NULL, idx, expt, count);
}

int wd_cipher_poll(__u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	__u32 recv = 0;
	int ret = WD_SUCCESS;

	if (unlikely(!count)) {
		WD_ERR("invalid: cipher poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	for (int i = 0; i < wd_cipher_setting.adapter->workers_nb; i++) {
		worker = &wd_cipher_setting.adapter->workers[i];

		if (worker->valid) {
			struct wd_sched *sched = worker->sched;

			ret = worker->sched->poll_policy(sched, expt, &recv);
			if (ret)
				return ret;

			*count += recv;
			expt -= recv;

			if (expt == 0)
				break;
		}
	}

	return ret;
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_CIPHER_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_CIPHER_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_cipher_ops = {
	.alg_name = "cipher",
	.op_type_num = 1,
	.alg_init = wd_cipher_init,
	.alg_uninit = wd_cipher_uninit,
	.alg_poll_ctx = wd_cipher_poll_ctx
};

int wd_cipher_env_init(struct wd_sched *sched)
{
	wd_cipher_env_config.sched = sched;

	return wd_alg_env_init(&wd_cipher_env_config, table,
				&wd_cipher_ops, ARRAY_SIZE(table), NULL);
}

void wd_cipher_env_uninit(void)
{
	wd_alg_env_uninit(&wd_cipher_env_config, &wd_cipher_ops);
}

int wd_cipher_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_cipher_env_config, table,
			       &wd_cipher_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_cipher_ctx_num_uninit(void)
{
	wd_alg_env_uninit(&wd_cipher_env_config, &wd_cipher_ops);
}

int wd_cipher_get_env_param(__u32 node, __u32 type, __u32 mode,
			    __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_cipher_env_config,
				    ctx_attr, num, is_enable);
}
