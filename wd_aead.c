/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include <limits.h>
#include "include/drv/wd_aead_drv.h"
#include "wd_aead.h"
#include "adapter.h"

#define WD_AEAD_CCM_GCM_MIN	4U
#define WD_AEAD_CCM_GCM_MAX	16

static int g_aead_mac_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_LEN,
	WD_DIGEST_SHA256_LEN, WD_DIGEST_SHA224_LEN,
	WD_DIGEST_SHA384_LEN, WD_DIGEST_SHA512_LEN,
	WD_DIGEST_SHA512_224_LEN, WD_DIGEST_SHA512_256_LEN
};

/* These algs's name need correct match with alg/mode type */
static char *wd_aead_alg_name[WD_CIPHER_ALG_TYPE_MAX][WD_CIPHER_MODE_TYPE_MAX] = {
	{"", "authenc(hmac(sha256),cbc(sm4))", "", "", "", "", "", "", "",
	"ccm(sm4)", "gcm(sm4)"},
	{"", "authenc(hmac(sha256),cbc(aes))", "", "", "", "", "", "", "",
	"ccm(aes)", "gcm(aes)"}
};

struct wd_aead_setting {
	enum wd_status status;
	void *dlhandle;
	void *dlh_list;
	struct uadk_adapter *adapter;
} wd_aead_setting;

struct wd_aead_sess {
	char			*alg_name;
	enum wd_cipher_alg	calg;
	enum wd_cipher_mode	cmode;
	enum wd_digest_type	dalg;
	enum wd_digest_mode	dmode;
	unsigned char		ckey[MAX_CIPHER_KEY_SIZE];
	unsigned char		akey[MAX_HMAC_KEY_SIZE];
	/* Mac data pointer for decrypto as stream mode */
	unsigned char		mac_bak[WD_AEAD_CCM_GCM_MAX];
	__u16			ckey_bytes;
	__u16			akey_bytes;
	__u16			auth_bytes;
	void			*priv;
	void			**sched_key;
	/* Stored the counter for gcm stream mode */
	__u8			iv[MAX_IV_SIZE];
	/* Total of data for stream mode */
	__u64			long_data_len;
	struct uadk_adapter_worker *worker;
	pthread_spinlock_t worker_lock;
	int worker_looptime;
};

struct wd_env_config wd_aead_env_config;
static struct wd_init_attrs wd_aead_init_attrs;

static void wd_aead_close_driver(int init_type)
{
#ifndef WD_STATIC_DRV
	if (init_type == WD_TYPE_V2) {
		wd_dlclose_drv(wd_aead_setting.dlh_list);
		return;
	}

	if (wd_aead_setting.dlhandle) {
		dlclose(wd_aead_setting.dlhandle);
		wd_aead_setting.dlhandle = NULL;
	}
#else
	hisi_sec2_remove();
#endif
}

static int wd_aead_open_driver(int init_type)
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
		wd_aead_setting.dlh_list = wd_dlopen_drv(NULL);
		if (!wd_aead_setting.dlh_list) {
			WD_ERR("fail to open driver lib files.\n");
			return -WD_EINVAL;
		}

		return WD_SUCCESS;
	}

	ret = wd_get_lib_file_path("libhisi_sec.so", lib_path, false);
	if (ret)
		return ret;

	wd_aead_setting.dlhandle = dlopen(lib_path, RTLD_NOW);
	if (!wd_aead_setting.dlhandle) {
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

static int cipher_key_len_check(enum wd_cipher_alg alg, __u16 length)
{
	int ret = 0;

	switch (alg) {
	case WD_CIPHER_SM4:
		if (length != SM4_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_AES:
		ret = aes_key_len_check(length);
		break;
	default:
		WD_ERR("failed to set the cipher alg, alg = %d\n", alg);
		return -WD_EINVAL;
	}

	return ret;
}

static unsigned int get_iv_block_size(int mode)
{
	int ret;

	/* AEAD just used AES and SM4 algorithm */
	switch (mode) {
	case WD_CIPHER_CBC:
	case WD_CIPHER_CCM:
		ret = AES_BLOCK_SIZE;
		break;
	case WD_CIPHER_GCM:
		ret = GCM_IV_SIZE;
		break;
	default:
		ret = AES_BLOCK_SIZE;
	}

	return ret;
}

int wd_aead_set_ckey(handle_t h_sess, const __u8 *key, __u16 key_len)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;
	int ret;

	if (unlikely(!key || !sess)) {
		WD_ERR("failed to check cipher key input param!\n");
		return -WD_EINVAL;
	}

	ret = cipher_key_len_check(sess->calg, key_len);
	if (ret) {
		WD_ERR("failed to check cipher key length!\n");
		return -WD_EINVAL;
	}

	sess->ckey_bytes = key_len;
	memcpy(sess->ckey, key, key_len);

	return 0;
}

int wd_aead_set_akey(handle_t h_sess, const __u8 *key, __u16 key_len)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (unlikely(!key || !sess)) {
		WD_ERR("failed to check authenticate key param!\n");
		return -WD_EINVAL;
	}

	if (key_len == 0)
		goto err_key_len;

	/*
	 * Here dalg only supports sha1, sha256, sha512,
	 * and should check key length with different max length.
	 */
	if (sess->dalg > WD_DIGEST_SHA256) {
		if (key_len > MAX_HMAC_KEY_SIZE)
			goto err_key_len;
	} else {
		if (key_len > MAX_HMAC_KEY_SIZE >> 1)
			goto err_key_len;
	}

	sess->akey_bytes = key_len;
	memcpy(sess->akey, key, key_len);

	return 0;

err_key_len:
	WD_ERR("failed to check authenticate key length, size = %u\n", key_len);
	return -WD_EINVAL;
}

int wd_aead_set_authsize(handle_t h_sess, __u16 authsize)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess) {
		WD_ERR("invalid: aead input sess is NULL!\n");
		return -WD_EINVAL;
	}

	if (sess->cmode == WD_CIPHER_CCM) {
		if (authsize < WD_AEAD_CCM_GCM_MIN ||
		    authsize > WD_AEAD_CCM_GCM_MAX ||
		    authsize % (WD_AEAD_CCM_GCM_MIN >> 1)) {
			WD_ERR("failed to check aead CCM authsize, size = %u\n",
				authsize);
			return -WD_EINVAL;
		}
	} else if (sess->cmode == WD_CIPHER_GCM) {
		if (authsize < WD_AEAD_CCM_GCM_MIN << 1 ||
		    authsize > WD_AEAD_CCM_GCM_MAX) {
			WD_ERR("failed to check aead GCM authsize, size = %u\n",
				authsize);
			return -WD_EINVAL;
		}
	} else {
		if (sess->dalg >= WD_DIGEST_TYPE_MAX ||
		    authsize & (WD_AEAD_CCM_GCM_MAX - 1) ||
		    authsize > g_aead_mac_len[sess->dalg]) {
			WD_ERR("failed to check aead mac authsize, size = %u\n",
				authsize);
			return -WD_EINVAL;
		}
	}

	sess->auth_bytes = authsize;

	return 0;
}

int wd_aead_get_authsize(handle_t h_sess)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess) {
		WD_ERR("invalid: aead input sess is NULL!\n");
		return -WD_EINVAL;
	}

	return sess->auth_bytes;
}

int wd_aead_get_maxauthsize(handle_t h_sess)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess || sess->dalg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("invalid: aead input sess is NULL or invalid alg type!\n");
		return -WD_EINVAL;
	}

	if (sess->cmode == WD_CIPHER_CCM || sess->cmode == WD_CIPHER_GCM)
		return WD_AEAD_CCM_GCM_MAX;

	return g_aead_mac_len[sess->dalg];
}

handle_t wd_aead_alloc_sess(struct wd_aead_sess_setup *setup)
{
	struct wd_aead_sess *sess = NULL;
	struct uadk_adapter_worker *worker;
	int nb = wd_aead_setting.adapter->workers_nb;
	int ret, i;

	if (unlikely(!setup)) {
		WD_ERR("failed to check session input parameter!\n");
		return (handle_t)0;
	}

	if (setup->calg >= WD_CIPHER_ALG_TYPE_MAX ||
	     setup->cmode >= WD_CIPHER_MODE_TYPE_MAX) {
		WD_ERR("failed to check algorithm setup!\n");
		return (handle_t)0;
	}

	worker = sess->worker = &wd_aead_setting.adapter->workers[0];
	worker->valid = true;
	sess->worker_looptime = 0;

	sess = malloc(sizeof(struct wd_aead_sess));
	if (!sess) {
		WD_ERR("failed to alloc session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_aead_sess));

	sess->alg_name = wd_aead_alg_name[setup->calg][setup->cmode];
	sess->calg = setup->calg;
	sess->cmode = setup->cmode;
	sess->dalg = setup->dalg;
	sess->dmode = setup->dmode;
	ret = wd_drv_alg_support(sess->alg_name, worker->driver);
	if (!ret) {
		WD_ERR("failed to support this algorithm: %s!\n", sess->alg_name);
		goto err_sess;
	}

	sess->sched_key = (void **)calloc(nb, sizeof(void *));
	for (i = 0; i < nb; i++) {
		worker = &wd_aead_setting.adapter->workers[i];

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

void wd_aead_free_sess(handle_t h_sess)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("invalid: aead input sess is NULL!\n");
		return;
	}

	wd_memset_zero(sess->ckey, sess->ckey_bytes);
	wd_memset_zero(sess->akey, sess->akey_bytes);

	if (sess->sched_key) {
		for (int i = 0; i < wd_aead_setting.adapter->workers_nb; i++)
			free(sess->sched_key[i]);
		free(sess->sched_key);
	}
	free(sess);
}

static int wd_aead_param_check(struct wd_aead_sess *sess,
			       struct wd_aead_req *req)
{
	__u64 len;
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("invalid: aead input sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!req->iv || !req->mac)) {
		WD_ERR("invalid: aead input iv or mac is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(sess->cmode == WD_CIPHER_CBC && req->in_bytes == 0)) {
		WD_ERR("aead input data length is zero!\n");
		return -WD_EINVAL;
	}

	if (unlikely(sess->cmode == WD_CIPHER_CBC &&
	   (req->in_bytes & (AES_BLOCK_SIZE - 1)))) {
		WD_ERR("failed to check aead input data length, size = %u\n",
			req->in_bytes);
		return -WD_EINVAL;
	}

	if (unlikely(req->iv_bytes != get_iv_block_size(sess->cmode))) {
		WD_ERR("failed to check aead IV length, size = %u\n",
			req->iv_bytes);
		return -WD_EINVAL;
	}

	if (unlikely(req->mac_bytes < sess->auth_bytes)) {
		WD_ERR("failed to check aead mac length, size = %u\n", req->mac_bytes);
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		len = (__u64)req->in_bytes + req->assoc_bytes;
		ret = wd_check_datalist(req->list_src, len);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist, size = %llu\n", len);
			return -WD_EINVAL;
		}

		ret = wd_check_datalist(req->list_dst, req->out_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the dst datalist, size = %u\n",
				req->out_bytes);
			return -WD_EINVAL;
		}
	} else {
		ret = wd_check_src_dst(req->src, req->in_bytes, req->dst, req->out_bytes);
		if (unlikely(ret)) {
			WD_ERR("invalid: src/dst addr is NULL when src/dst size is non-zero!\n");
			return -WD_EINVAL;
		}
	}

	return 0;
}

static void wd_aead_clear_status(void)
{
	wd_alg_clear_init(&wd_aead_setting.status);
}

static int wd_aead_init_nolock(struct uadk_adapter_worker *worker, struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_AEAD_EPOLL_EN",
			      &worker->config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&worker->config, worker->ctx_config);
	if (ret)
		return ret;

	worker->config.pool = &worker->pool;
	sched->worker = worker;
	worker->sched = sched;

	/* init async request pool */
	ret = wd_init_async_request_pool(&worker->pool,
					 worker->ctx_config, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_aead_msg));
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

int wd_aead_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	char *alg = "gcm(aes)";
	int ret;

	pthread_atfork(NULL, NULL, wd_aead_clear_status);

	ret = wd_alg_try_init(&wd_aead_setting.status);
	if (ret)
		return ret;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_clear_init;

	wd_aead_setting.adapter = adapter;

	ret = wd_aead_open_driver(WD_TYPE_V1);
	if (ret)
		goto out_clear_init;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_close_driver;

	worker = &adapter->workers[0];
	worker->ctx_config = config;

	ret = wd_aead_init_nolock(worker, sched);
	if (ret)
		goto out_close_driver;

	wd_alg_set_init(&wd_aead_setting.status);

	return 0;

out_close_driver:
	wd_aead_close_driver(WD_TYPE_V1);
out_clear_init:
	free(adapter);
	wd_alg_clear_init(&wd_aead_setting.status);
	return ret;
}

static int wd_aead_uninit_nolock(void)
{
	struct uadk_adapter_worker *worker;
	enum wd_status status;

	wd_alg_get_init(&wd_aead_setting.status, &status);
	if (status == WD_UNINIT)
		return -WD_EINVAL;

	for (int i = 0; i < wd_aead_setting.adapter->workers_nb; i++) {
		worker = &wd_aead_setting.adapter->workers[i];

		wd_uninit_async_request_pool(&worker->pool);
		wd_alg_uninit_driver(&worker->config, worker->driver);
	}

	return 0;
}

void wd_aead_uninit(void)
{
	int ret;

	ret = wd_aead_uninit_nolock();
	if (ret)
		return;

	free(wd_aead_setting.adapter);
	wd_aead_close_driver(WD_TYPE_V1);
	wd_alg_clear_init(&wd_aead_setting.status);
}

static bool wd_aead_algs_check(const char *alg)
{
	for (int i = 0; i < WD_CIPHER_ALG_TYPE_MAX; i++) {
		for (int j = 0; j < WD_CIPHER_MODE_TYPE_MAX; j++) {
			if (!wd_aead_alg_name[i][j])
				continue;
			if (!strcmp(alg, wd_aead_alg_name[i][j]))
				return true;
		}
	}

	return false;
}

int wd_aead_init2_(char *alg, __u32 sched_type, int task_type,
		   struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_nums aead_ctx_num[WD_DIGEST_CIPHER_DECRYPTION + 1] = {0};
	struct wd_ctx_params aead_ctx_params = {0};
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	int state, ret = -WD_EINVAL;
	int i;

	pthread_atfork(NULL, NULL, wd_aead_clear_status);

	state = wd_alg_try_init(&wd_aead_setting.status);
	if (state)
		return state;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	     task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		goto out_uninit;
	}

	if (!wd_aead_algs_check(alg)) {
		WD_ERR("invalid: aead:%s unsupported!\n", alg);
		goto out_uninit;
	}

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_uninit;
	wd_aead_setting.adapter = adapter;

	state = wd_aead_open_driver(WD_TYPE_V2);
	if (state)
		goto out_uninit;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_dlopen;

	for (i = 0; i < adapter->workers_nb; i++) {
		worker = &adapter->workers[i];

		aead_ctx_params.ctx_set_num = aead_ctx_num;
		ret = wd_ctx_param_init(&aead_ctx_params, ctx_params,
					worker->driver, WD_AEAD_TYPE,
					WD_DIGEST_CIPHER_DECRYPTION + 1);
		if (ret) {
			WD_ERR("fail to init ctx param\n");
			goto out_dlopen;
		}

		wd_aead_init_attrs.alg = alg;
		wd_aead_init_attrs.ctx_params = &aead_ctx_params;
		wd_aead_init_attrs.alg_init = wd_aead_init_nolock;
		wd_aead_init_attrs.alg_poll_ctx = wd_aead_poll_ctx_;
		ret = wd_alg_attrs_init(worker, &wd_aead_init_attrs);
		wd_ctx_param_uninit(&aead_ctx_params);
		if (ret) {
			WD_ERR("failed to init alg attrs.\n");
			goto out_dlopen;
		}
	}

	wd_alg_set_init(&wd_aead_setting.status);

	return 0;

out_dlopen:
	wd_aead_close_driver(WD_TYPE_V2);
out_uninit:
	free(adapter);
	wd_alg_clear_init(&wd_aead_setting.status);
	return ret;
}

void wd_aead_uninit2(void)
{
	struct uadk_adapter_worker *worker;
	int ret;

	ret = wd_aead_uninit_nolock();
	if (ret)
		return;

	for (int i = 0; i < wd_aead_setting.adapter->workers_nb; i++) {
		worker = &wd_aead_setting.adapter->workers[i];
		wd_alg_attrs_uninit(worker);
	}

	free(wd_aead_setting.adapter);
	wd_aead_close_driver(WD_TYPE_V2);
	wd_aead_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_aead_setting.status);
}

static void fill_stream_msg(struct wd_aead_msg *msg, struct wd_aead_req *req,
			    struct wd_aead_sess *sess)
{
	switch (req->msg_state) {
	case AEAD_MSG_FIRST:
		/* Stream iv is extended to 16 bytes and last 4 bytes must be zero */
		memset(sess->iv, 0, MAX_IV_SIZE);
		memcpy(sess->iv, req->iv, GCM_IV_SIZE);

		if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST)
			msg->mac = sess->mac_bak;
		break;
	case AEAD_MSG_MIDDLE:
		/* Middle messages need to store the stream's total length to session */
		sess->long_data_len += req->in_bytes;

		msg->long_data_len = sess->long_data_len;

		if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST)
			msg->mac = sess->mac_bak;
		break;
	case AEAD_MSG_END:
		if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
			/* Sets the original mac for final message */
			msg->dec_mac = req->mac;
			msg->mac = sess->mac_bak;
		}

		msg->long_data_len = sess->long_data_len + req->in_bytes;
		/* Reset the session's long_data_len */
		sess->long_data_len = 0;
		break;
	default:
		return;
	}

	msg->iv = sess->iv;
}

static void fill_request_msg(struct wd_aead_msg *msg, struct wd_aead_req *req,
			     struct wd_aead_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_aead_req));

	msg->alg_type = WD_AEAD;
	msg->calg = sess->calg;
	msg->cmode = sess->cmode;
	msg->dalg = sess->dalg;
	msg->dmode = sess->dmode;
	msg->op_type = req->op_type;
	msg->in = req->src;
	msg->in_bytes = req->in_bytes;
	msg->out = req->dst;
	msg->out_bytes = req->out_bytes;
	msg->ckey = sess->ckey;
	msg->ckey_bytes = sess->ckey_bytes;
	msg->akey = sess->akey;
	msg->akey_bytes = sess->akey_bytes;
	msg->iv = req->iv;
	msg->iv_bytes = req->iv_bytes;
	msg->assoc_bytes = req->assoc_bytes;
	msg->mac = req->mac;
	msg->auth_bytes = sess->auth_bytes;
	msg->data_fmt = req->data_fmt;

	msg->msg_state = req->msg_state;
	fill_stream_msg(msg, req, sess);
}

static int send_recv_sync(struct uadk_adapter_worker *worker, struct wd_ctx_internal *ctx,
			  struct wd_aead_msg *msg)
{
	struct wd_msg_handle msg_handle;
	int ret;

	msg_handle.send = worker->driver->send;
	msg_handle.recv = worker->driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(worker->driver, &msg_handle, ctx->ctx,
				 msg, NULL, worker->config.epoll_en);
	pthread_spin_unlock(&ctx->lock);

	return ret;
}

int wd_do_aead_sync(handle_t h_sess, struct wd_aead_req *req)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_aead_msg msg;
	__u32 idx;
	int ret;

	ret = wd_aead_param_check(sess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	memset(&msg, 0, sizeof(struct wd_aead_msg));
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

	return ret;
}

int wd_do_aead_async(handle_t h_sess, struct wd_aead_req *req)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_aead_msg *msg;
	int msg_id, ret;
	__u32 idx;

	ret = wd_aead_param_check(sess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	if (unlikely(!req->cb)) {
		WD_ERR("invalid: aead input req cb is NULL!\n");
		return -WD_EINVAL;
	}

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	idx = worker->sched->pick_next_ctx(
		     worker->sched->h_sched_ctx,
		     sess->sched_key[worker->idx], CTX_MODE_ASYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = worker->config.ctxs + idx;

	msg_id = wd_get_msg_from_pool(&worker->pool,
				     idx, (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("failed to get msg from pool!\n");
		return msg_id;
	}

	fill_request_msg(msg, req, sess);
	msg->tag = msg_id;

	ret = wd_alg_driver_send(worker->driver, ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send BD, hw is err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);
	ret = wd_add_task_to_async_queue(&wd_aead_env_config, idx);
	if (ret)
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&worker->pool, idx, msg->tag);
	return ret;
}

int wd_aead_poll_ctx_(struct wd_sched *sched, __u32 idx, __u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	struct wd_aead_msg resp_msg, *msg;
	struct wd_aead_req *req;
	__u64 recv_count = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count || !expt)) {
		WD_ERR("invalid: aead poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

	/* back-compatible with init1 api */
	if (sched == NULL)
		worker = &wd_aead_setting.adapter->workers[0];
	else
		worker = sched->worker;

	*count = 0;

	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = worker->config.ctxs + idx;

	do {
		ret = wd_alg_driver_recv(worker->driver, ctx->ctx, &resp_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("wd aead recv hw err!\n");
			return ret;
		}

		recv_count++;
		msg = wd_find_msg_in_pool(&worker->pool,
					    idx, resp_msg.tag);
		if (!msg) {
			WD_ERR("failed to find msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->tag = resp_msg.tag;
		msg->req.state = resp_msg.result;
		req = &msg->req;
		req->cb(req, req->cb_param);
		wd_put_msg_to_pool(&worker->pool, idx, resp_msg.tag);
		*count = recv_count;
	} while (--tmp);

	return ret;
}

int wd_aead_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	return wd_aead_poll_ctx_(NULL, idx, expt, count);
}

int wd_aead_poll(__u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	__u32 recv = 0;
	int ret = WD_SUCCESS;

	if (unlikely(!count)) {
		WD_ERR("invalid: aead poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	for (int i = 0; i < wd_aead_setting.adapter->workers_nb; i++) {
		worker = &wd_aead_setting.adapter->workers[i];

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
	{ .name = "WD_AEAD_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_AEAD_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_aead_ops = {
        .alg_name = "aead",
        .op_type_num = 1,
        .alg_init = wd_aead_init,
        .alg_uninit = wd_aead_uninit,
        .alg_poll_ctx = wd_aead_poll_ctx
};

int wd_aead_env_init(struct wd_sched *sched)
{
	wd_aead_env_config.sched = sched;

	return wd_alg_env_init(&wd_aead_env_config, table,
			       &wd_aead_ops, ARRAY_SIZE(table), NULL);
}

void wd_aead_env_uninit(void)
{
	wd_alg_env_uninit(&wd_aead_env_config, &wd_aead_ops);
}

int wd_aead_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_aead_env_config, table,
			       &wd_aead_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_aead_ctx_num_uninit(void)
{
	wd_alg_env_uninit(&wd_aead_env_config, &wd_aead_ops);
}

int wd_aead_get_env_param(__u32 node, __u32 type, __u32 mode,
			  __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_aead_env_config,
				    ctx_attr, num, is_enable);
}
