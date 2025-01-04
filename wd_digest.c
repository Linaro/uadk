/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include <limits.h>
#include "include/drv/wd_digest_drv.h"
#include "wd_digest.h"
#include "adapter.h"

#define GMAC_IV_LEN		16
#define MAX_BLOCK_SIZE		128

static __u32 g_digest_mac_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_LEN,
	WD_DIGEST_SHA256_LEN, WD_DIGEST_SHA224_LEN,
	WD_DIGEST_SHA384_LEN, WD_DIGEST_SHA512_LEN,
	WD_DIGEST_SHA512_224_LEN, WD_DIGEST_SHA512_256_LEN,
	WD_DIGEST_AES_XCBC_MAC_96_LEN, WD_DIGEST_AES_XCBC_PRF_128_LEN,
	WD_DIGEST_AES_CMAC_LEN, WD_DIGEST_AES_GMAC_LEN
};

static __u32 g_digest_mac_full_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_FULL_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_FULL_LEN,
	WD_DIGEST_SHA256_FULL_LEN, WD_DIGEST_SHA224_FULL_LEN,
	WD_DIGEST_SHA384_FULL_LEN, WD_DIGEST_SHA512_FULL_LEN,
	WD_DIGEST_SHA512_224_FULL_LEN, WD_DIGEST_SHA512_256_FULL_LEN
};

/* These algs's name need correct match with digest alg type */
static char *wd_digest_alg_name[WD_DIGEST_TYPE_MAX] = {
	"sm3", "md5", "sha1", "sha256", "sha224", "sha384",
	"sha512", "sha512-224", "sha512-256", "xcbc-mac-96(aes)",
	"xcbc-prf-128(aes)", "cmac(aes)", "gmac(aes)"
};

struct wd_digest_setting {
	enum wd_status status;
	void *dlhandle;
	void *dlh_list;
	struct uadk_adapter *adapter;
} wd_digest_setting;

struct wd_digest_stream_data {
	/* Long hash mode, first and middle block misaligned data */
	unsigned char partial_block[MAX_BLOCK_SIZE];
	__u32 partial_bytes;
	/* Total data length for stream mode */
	__u64 long_data_len;
	/*
	 * Notify the stream message state, zero is first message,
	 * non-zero is middle or final message.
	 */
	int msg_state;
};

struct wd_digest_sess {
	char			*alg_name;
	enum wd_digest_type	alg;
	enum wd_digest_mode	mode;
	void			*priv;
	unsigned char		key[MAX_HMAC_KEY_SIZE];
	__u32			key_bytes;
	void			**sched_key;
	struct wd_digest_stream_data stream_data;
	struct uadk_adapter_worker *worker;
	pthread_spinlock_t worker_lock;
	int worker_looptime;
};

void wd_digest_switch_worker(struct wd_digest_sess *sess, int para)
{
	struct uadk_adapter_worker *worker;

	pthread_spin_lock(&sess->worker_lock);
	worker = uadk_adapter_switch_worker(wd_digest_setting.adapter,
					    sess->worker, para);
	if (worker)
		sess->worker = worker;
	sess->worker_looptime = 0;
	pthread_spin_unlock(&sess->worker_lock);
}

struct wd_env_config wd_digest_env_config;
static struct wd_init_attrs wd_digest_init_attrs;

static void wd_digest_close_driver(int init_type)
{
#ifndef WD_STATIC_DRV
	if (init_type == WD_TYPE_V2) {
		wd_dlclose_drv(wd_digest_setting.dlh_list);
		return;
	}

	if (wd_digest_setting.dlhandle) {
		dlclose(wd_digest_setting.dlhandle);
		wd_digest_setting.dlhandle = NULL;
	}
#else
	hisi_sec2_remove();
#endif
}

static int wd_digest_open_driver(int init_type)
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
		wd_digest_setting.dlh_list = wd_dlopen_drv(NULL);
		if (!wd_digest_setting.dlh_list) {
			WD_ERR("fail to open driver lib files.\n");
			return -WD_EINVAL;
		}

		return WD_SUCCESS;
	}

	ret = wd_get_lib_file_path("libhisi_sec.so", lib_path, false);
	if (ret)
		return ret;

	wd_digest_setting.dlhandle = dlopen(lib_path, RTLD_NOW);
	if (!wd_digest_setting.dlhandle) {
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

int wd_digest_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
	int ret;

	if (!key || !sess) {
		WD_ERR("invalid: failed to check input param, sess or key is NULL!\n");
		return -WD_EINVAL;
	}

	if ((sess->alg <= WD_DIGEST_SHA224 && key_len >
		MAX_HMAC_KEY_SIZE >> 1) || key_len == 0 ||
		key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("failed to check digest key length, size = %u\n",
			key_len);
		return -WD_EINVAL;
	}

	if (sess->alg == WD_DIGEST_AES_GMAC) {
		ret = aes_key_len_check(key_len);
		if (ret) {
			WD_ERR("failed to check aes-gmac key length, size = %u\n",
				key_len);
			return ret;
		}
	}

	sess->key_bytes = key_len;
	memcpy(sess->key, key, key_len);

	return 0;
}

handle_t wd_digest_alloc_sess(struct wd_digest_sess_setup *setup)
{
	struct wd_digest_sess *sess = NULL;
	struct uadk_adapter_worker *worker;
	int nb = wd_digest_setting.adapter->workers_nb;
	int ret, i;

	if (unlikely(!setup)) {
		WD_ERR("failed to check alloc sess param!\n");
		return (handle_t)0;
	}

	if (setup->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("failed to check algorithm setup!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_digest_sess));
	if (!sess)
		return (handle_t)0;
	memset(sess, 0, sizeof(struct wd_digest_sess));

	worker = sess->worker = &wd_digest_setting.adapter->workers[0];
	worker->valid = true;
	sess->worker_looptime = 0;
	sess->alg_name = wd_digest_alg_name[setup->alg];
	sess->alg = setup->alg;
	sess->mode = setup->mode;

	ret = wd_drv_alg_support(sess->alg_name, worker->driver);
	if (!ret) {
		WD_ERR("failed to support this algorithm: %s!\n", sess->alg_name);
		goto err_sess;
	}

	sess->sched_key = (void **)calloc(nb, sizeof(void *));
	for (i = 0; i < nb; i++) {
		worker = &wd_digest_setting.adapter->workers[i];

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

void wd_digest_free_sess(handle_t h_sess)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("failed to check free sess param!\n");
		return;
	}

	wd_memset_zero(sess->key, sess->key_bytes);
	if (sess->sched_key) {
		for (int i = 0; i < wd_digest_setting.adapter->workers_nb; i++)
			free(sess->sched_key[i]);
		free(sess->sched_key);
	}
	free(sess);
}

static void wd_digest_clear_status(void)
{
	wd_alg_clear_init(&wd_digest_setting.status);
}

static int wd_digest_init_nolock(struct uadk_adapter_worker *worker,
				 struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_DIGEST_EPOLL_EN",
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
					 sizeof(struct wd_digest_msg));
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

int wd_digest_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	char *alg = "sm3";
	int ret;

	pthread_atfork(NULL, NULL, wd_digest_clear_status);

	ret = wd_alg_try_init(&wd_digest_setting.status);
	if (ret)
		return ret;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_clear_init;

	wd_digest_setting.adapter = adapter;

	ret = wd_digest_open_driver(WD_TYPE_V1);
	if (ret)
		goto out_clear_init;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_close_driver;

	worker = &adapter->workers[0];
	worker->ctx_config = config;
	ret = wd_digest_init_nolock(worker, sched);
	if (ret)
		goto out_close_driver;

	wd_alg_set_init(&wd_digest_setting.status);

	return 0;

out_close_driver:
	wd_digest_close_driver(WD_TYPE_V1);
out_clear_init:
	free(adapter);
	wd_alg_clear_init(&wd_digest_setting.status);
	return ret;
}

static int wd_digest_uninit_nolock(void)
{
	enum wd_status status;

	wd_alg_get_init(&wd_digest_setting.status, &status);
	if (status == WD_UNINIT)
		return -WD_EINVAL;

	for (int i = 0; i < wd_digest_setting.adapter->workers_nb; i++) {
		struct uadk_adapter_worker *worker = &wd_digest_setting.adapter->workers[i];

		wd_uninit_async_request_pool(&worker->pool);
		wd_alg_uninit_driver(&worker->config, worker->driver);
	}

	return 0;
}

void wd_digest_uninit(void)
{
	int ret;

	ret = wd_digest_uninit_nolock();
	if (ret)
		return;

	free(wd_digest_setting.adapter);
	wd_digest_close_driver(WD_TYPE_V1);
	wd_alg_clear_init(&wd_digest_setting.status);
}

static bool wd_digest_algs_check(const char *alg)
{
	for (int i = 0; i < WD_DIGEST_TYPE_MAX; i++) {
		if (!strcmp(alg, wd_digest_alg_name[i]))
			return true;
	}

	return false;
}

int wd_digest_init2_(char *alg, __u32 sched_type, int task_type,
		     struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_params digest_ctx_params = {0};
	struct wd_ctx_nums digest_ctx_num = {0};
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	int state, ret = -WD_EINVAL;
	int i;

	pthread_atfork(NULL, NULL, wd_digest_clear_status);

	state = wd_alg_try_init(&wd_digest_setting.status);
	if (state)
		return state;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	     task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		goto out_uninit;
	}

	if (!wd_digest_algs_check(alg)) {
		WD_ERR("invalid: digest:%s unsupported!\n", alg);
		goto out_uninit;
	}

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_uninit;
	wd_digest_setting.adapter = adapter;

	state = wd_digest_open_driver(WD_TYPE_V2);
	if (state)
		goto out_uninit;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_dlclose;

	for (i = 0; i < adapter->workers_nb; i++) {
		worker = &adapter->workers[i];

		digest_ctx_params.ctx_set_num = &digest_ctx_num;
		ret = wd_ctx_param_init(&digest_ctx_params, ctx_params,
					worker->driver, WD_DIGEST_TYPE, 1);
		if (ret) {
			WD_ERR("fail to init ctx param\n");
			goto out_dlclose;
		}

		wd_digest_init_attrs.alg = alg;
		wd_digest_init_attrs.ctx_params = &digest_ctx_params;
		wd_digest_init_attrs.alg_init = wd_digest_init_nolock;
		wd_digest_init_attrs.alg_poll_ctx = wd_digest_poll_ctx_;
		ret = wd_alg_attrs_init(worker, &wd_digest_init_attrs);
		wd_ctx_param_uninit(&digest_ctx_params);
		if (ret) {
			WD_ERR("fail to init alg attrs.\n");
			goto out_dlclose;
		}
	}

	wd_alg_set_init(&wd_digest_setting.status);
	return 0;

out_dlclose:
	wd_digest_close_driver(WD_TYPE_V2);
out_uninit:
	free(adapter);
	wd_alg_clear_init(&wd_digest_setting.status);
	return ret;
}

void wd_digest_uninit2(void)
{
	struct uadk_adapter_worker *worker;
	int ret;

	ret = wd_digest_uninit_nolock();
	if (ret)
		return;

	for (int i = 0; i < wd_digest_setting.adapter->workers_nb; i++) {
		worker = &wd_digest_setting.adapter->workers[i];
		wd_alg_attrs_uninit(worker);
	}

	free(wd_digest_setting.adapter);
	wd_digest_close_driver(WD_TYPE_V2);
	wd_digest_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_digest_setting.status);
}

static int wd_aes_hmac_length_check(struct wd_digest_sess *sess,
				    struct wd_digest_req *req)
{
	switch (sess->alg) {
	case WD_DIGEST_AES_XCBC_MAC_96:
	case WD_DIGEST_AES_XCBC_PRF_128:
	case WD_DIGEST_AES_CMAC:
		if (!req->in_bytes) {
			WD_ERR("failed to check 0 packet length, alg = %d\n",
				sess->alg);
			return -WD_EINVAL;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int wd_mac_length_check(struct wd_digest_sess *sess,
			       struct wd_digest_req *req)
{
	if (unlikely(req->out_bytes == 0)) {
		WD_ERR("invalid: digest alg:%d mac length is 0.\n", sess->alg);
		return -WD_EINVAL;
	}

	switch (req->has_next) {
	case WD_DIGEST_END:
	case WD_DIGEST_STREAM_END:
		if (unlikely(req->out_bytes > g_digest_mac_len[sess->alg])) {
			WD_ERR("invalid: digest mac length, alg = %d, out_bytes = %u\n",
			       sess->alg, req->out_bytes);
			return -WD_EINVAL;
		}
		break;
	case WD_DIGEST_DOING:
	case WD_DIGEST_STREAM_DOING:
		/* User need to input full mac buffer in first and middle hash */
		if (unlikely(req->out_bytes != g_digest_mac_full_len[sess->alg])) {
			WD_ERR("invalid: digest mac full length, alg = %d, out_bytes = %u\n",
			       sess->alg, req->out_bytes);
			return -WD_EINVAL;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int wd_digest_param_check(struct wd_digest_sess *sess,
				 struct wd_digest_req *req)
{
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("invalid: digest input sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->out_bytes)) {
		WD_ERR("failed to check digest out buffer length, size = %u\n",
			req->out_buf_bytes);
		return -WD_EINVAL;
	}

	if (unlikely(sess->alg >= WD_DIGEST_TYPE_MAX)) {
		WD_ERR("invalid: check digest type, alg = %d\n", sess->alg);
		return -WD_EINVAL;
	}

	ret = wd_mac_length_check(sess, req);
	if (ret)
		return ret;

	if (unlikely(sess->alg == WD_DIGEST_AES_GMAC &&
	    (!req->iv || req->iv_bytes != GMAC_IV_LEN))) {
		WD_ERR("failed to check digest aes_gmac iv length, iv_bytes = %u\n",
			req->iv_bytes);
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		ret = wd_check_datalist(req->list_in, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist, size = %u\n",
				req->in_bytes);
			return -WD_EINVAL;
		}

		ret = wd_check_src_dst(NULL, 0, req->out, req->out_bytes);
		if (unlikely(ret)) {
			WD_ERR("invalid: out addr is NULL when out size is non-zero!\n");
			return -WD_EINVAL;
		}
	} else {
		ret = wd_check_src_dst(req->in, req->in_bytes, req->out, req->out_bytes);
		if (unlikely(ret)) {
			WD_ERR("invalid: in/out addr is NULL when in/out size is non-zero!\n");
			return -WD_EINVAL;
		}
	}

	return wd_aes_hmac_length_check(sess, req);
}

static void fill_request_msg(struct wd_digest_msg *msg,
			     struct wd_digest_req *req,
			     struct wd_digest_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_digest_req));

	if (unlikely(req->has_next == WD_DIGEST_STREAM_END)) {
		sess->stream_data.long_data_len = req->long_data_len;
		sess->stream_data.msg_state = WD_DIGEST_DOING;
		req->has_next = WD_DIGEST_END;
	} else if (unlikely(req->has_next == WD_DIGEST_STREAM_DOING)) {
		sess->stream_data.long_data_len = req->long_data_len;
		sess->stream_data.msg_state = WD_DIGEST_DOING;
		req->has_next = WD_DIGEST_DOING;
	}

	msg->alg_type = WD_DIGEST;
	msg->alg = sess->alg;
	msg->mode = sess->mode;
	msg->key = sess->key;
	msg->key_bytes = sess->key_bytes;
	msg->iv = req->iv;
	msg->in = req->in;
	msg->in_bytes = req->in_bytes;
	msg->out = req->out;
	msg->out_bytes = req->out_bytes;
	msg->data_fmt = req->data_fmt;
	msg->has_next = req->has_next;
	msg->long_data_len = sess->stream_data.long_data_len + req->in_bytes;
	msg->partial_block = sess->stream_data.partial_block;
	msg->partial_bytes = sess->stream_data.partial_bytes;

	/* Use iv_bytes to store the stream message state */
	msg->iv_bytes = sess->stream_data.msg_state;
}

static int send_recv_sync(struct uadk_adapter_worker *worker, struct wd_ctx_internal *ctx,
			  struct wd_digest_sess *dsess, struct wd_digest_msg *msg)
{
	struct wd_msg_handle msg_handle;
	int ret;

	msg_handle.send = worker->driver->send;
	msg_handle.recv = worker->driver->recv;

	wd_ctx_spin_lock(ctx, worker->driver->calc_type);
	ret = wd_handle_msg_sync(worker->driver, &msg_handle, ctx->ctx,
				 msg, NULL, worker->config.epoll_en);
	wd_ctx_spin_unlock(ctx, worker->driver->calc_type);
	if (unlikely(ret))
		return ret;

	/*
	 * After a stream mode job was done, update session
	 * long_data_len and partial_bytes.
	 */
	if (msg->has_next) {
		/* Long hash(first and middle message) */
		dsess->stream_data.long_data_len += msg->in_bytes;
		dsess->stream_data.partial_bytes = msg->partial_bytes;
	} else if (msg->iv_bytes) {
		/* Long hash(final message) */
		dsess->stream_data.long_data_len = 0;
		dsess->stream_data.partial_bytes = 0;
	}

	/* Update session message state */
	dsess->stream_data.msg_state = msg->has_next;

	return 0;
}

int wd_do_digest_sync(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg msg;
	__u32 idx;
	int ret;

	ret = wd_digest_param_check(dsess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	pthread_spin_lock(&dsess->worker_lock);
	worker = dsess->worker;
	pthread_spin_unlock(&dsess->worker_lock);

	memset(&msg, 0, sizeof(struct wd_digest_msg));
	fill_request_msg(&msg, req, dsess);
	req->state = 0;

	idx = worker->sched->pick_next_ctx(
		worker->sched->h_sched_ctx,
		dsess->sched_key[worker->idx], CTX_MODE_SYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);
	ctx = worker->config.ctxs + idx;
	ret = send_recv_sync(worker, ctx, dsess, &msg);
	req->state = msg.result;

	if (ret) {
		wd_digest_switch_worker(dsess, 1);
		dsess->worker_looptime++;
		return ret;
	}

	if ((dsess->worker_looptime != 0) ||
	    (wd_digest_setting.adapter->mode == UADK_ADAPT_MODE_ROUNDROBIN))
		dsess->worker_looptime++;

	if (dsess->worker_looptime >= wd_digest_setting.adapter->looptime)
		wd_digest_switch_worker(dsess, 0);

	return ret;
}

int wd_do_digest_async(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg *msg;
	int msg_id, ret;
	__u32 idx;

	ret = wd_digest_param_check(dsess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	if (unlikely(!req->cb)) {
		WD_ERR("invalid: digest input req cb is NULL!\n");
		return -WD_EINVAL;
	}

	pthread_spin_lock(&dsess->worker_lock);
	worker = dsess->worker;
	pthread_spin_unlock(&dsess->worker_lock);

	if (worker->driver->mode == UADK_DRV_SYNCONLY) {
		ret = wd_do_digest_sync(h_sess, req);
		if (!ret) {
			pthread_mutex_lock(&worker->mutex);
			worker->async_recv++;
			pthread_mutex_unlock(&worker->mutex);
			req->cb(req);
		}
		return ret;
	}

	idx = worker->sched->pick_next_ctx(
		worker->sched->h_sched_ctx,
		dsess->sched_key[worker->idx], CTX_MODE_ASYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = worker->config.ctxs + idx;

	msg_id = wd_get_msg_from_pool(&worker->pool, idx,
				   (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("failed to get msg from pool!\n");
		return msg_id;
	}

	fill_request_msg(msg, req, dsess);
	msg->tag = msg_id;

	ret = wd_alg_driver_send(worker->driver, ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send BD, hw is err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);
	ret = wd_add_task_to_async_queue(&wd_digest_env_config, idx);
	if (ret)
		goto fail_with_msg;

	if ((dsess->worker_looptime != 0) ||
	    (wd_digest_setting.adapter->mode == UADK_ADAPT_MODE_ROUNDROBIN))
		dsess->worker_looptime++;

	if (dsess->worker_looptime >= wd_digest_setting.adapter->looptime)
		wd_digest_switch_worker(dsess, 0);

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&worker->pool, idx, msg->tag);
	wd_digest_switch_worker(dsess, 1);
	dsess->worker_looptime++;
	return ret;
}

int wd_digest_poll_ctx_(struct wd_sched *sched, __u32 idx, __u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg recv_msg, *msg;
	struct wd_digest_req *req;
	__u32 recv_cnt = 0;
	__u32 tmp = expt;
	int ret;

	/* back-compatible with init1 api */
	if (sched == NULL)
		worker = &wd_digest_setting.adapter->workers[0];
	else
		worker = sched->worker;

	if (unlikely(!count || !expt)) {
		WD_ERR("invalid: digest poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

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
		ret = wd_alg_driver_recv(worker->driver, ctx->ctx, &recv_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("wd recv err!\n");
			return ret;
		}

		recv_cnt++;

		msg = wd_find_msg_in_pool(&worker->pool, idx,
					  recv_msg.tag);
		if (!msg) {
			WD_ERR("failed to find msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->req.state = recv_msg.result;
		req = &msg->req;
		if (likely(req))
			req->cb(req);

		wd_put_msg_to_pool(&worker->pool, idx,
				   recv_msg.tag);
		*count = recv_cnt;
	} while (--tmp);

	return ret;
}

int wd_digest_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	return wd_digest_poll_ctx_(NULL, idx, expt, count);
}

int wd_digest_poll(__u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	__u32 recv = 0;
	int ret = WD_SUCCESS;

	if (unlikely(!count)) {
		WD_ERR("invalid: digest poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	for (int i = 0; i < wd_digest_setting.adapter->workers_nb; i++) {
		worker = &wd_digest_setting.adapter->workers[i];

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
	{ .name = "WD_DIGEST_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_DIGEST_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_digest_ops = {
	.alg_name = "digest",
	.op_type_num = 1,
	.alg_init = wd_digest_init,
	.alg_uninit = wd_digest_uninit,
	.alg_poll_ctx = wd_digest_poll_ctx
};

int wd_digest_env_init(struct wd_sched *sched)
{
	wd_digest_env_config.sched = sched;

	return wd_alg_env_init(&wd_digest_env_config, table,
			       &wd_digest_ops, ARRAY_SIZE(table), NULL);
}

void wd_digest_env_uninit(void)
{
	wd_alg_env_uninit(&wd_digest_env_config, &wd_digest_ops);
}

int wd_digest_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_digest_env_config, table,
			       &wd_digest_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_digest_ctx_num_uninit(void)
{
	wd_alg_env_uninit(&wd_digest_env_config, &wd_digest_ops);
}

int wd_digest_get_env_param(__u32 node, __u32 type, __u32 mode,
			    __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_digest_env_config,
				    ctx_attr, num, is_enable);
}
