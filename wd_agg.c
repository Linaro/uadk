/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <limits.h>
#include "include/drv/wd_agg_drv.h"
#include "adapter.h"
#include "wd_agg.h"

#define DECIMAL_PRECISION_OFFSET	8
#define DAE_INT_SIZE			4
#define DAE_LONG_SIZE			8
#define DAE_LONG_DECIMAL_SIZE		16

/* Sum of the max row number of standard and external hash table */
#define MAX_HASH_TABLE_ROW_NUM		0x1FFFFFFFE

enum wd_agg_sess_state {
	WD_AGG_SESS_UNINIT, /* Uninit session */
	WD_AGG_SESS_INIT, /* Hash table has been set */
	WD_AGG_SESS_INPUT, /* Input stage has started */
	WD_AGG_SESS_RESET, /* Hash table has been reset */
	WD_AGG_SESS_REHASH, /* Rehash stage has started */
	WD_AGG_SESS_OUTPUT, /* Output stage has started */
};

struct wd_agg_setting {
	enum wd_status status;
	void *priv;
	void *dlhandle;
	void *dlh_list;
	struct uadk_adapter *adapter;
} wd_agg_setting;

struct wd_agg_sess_key_conf {
	__u32 cols_num;
	__u64 *data_size;
	struct wd_key_col_info *cols_info;
};

struct wd_agg_sess_agg_conf {
	__u32 cols_num;
	__u32 out_cols_num;
	__u64 *data_size;
	__u64 *out_data_size;
	struct wd_agg_col_info *cols_info;
	bool is_count_all;
	enum wd_dae_data_type count_all_data_type;
};

struct wd_agg_sess {
	char *alg_name;
	wd_dev_mask_t *dev_mask;
	struct wd_alg_agg *drv;
	void *priv;
	void **sched_key;
	enum wd_agg_sess_state state;
	struct wd_agg_ops ops;
	struct wd_agg_sess_key_conf key_conf;
	struct wd_agg_sess_agg_conf agg_conf;
	struct wd_dae_charset charset_info;
	struct wd_dae_hash_table hash_table;
	struct wd_dae_hash_table rehash_table;
	struct uadk_adapter_worker *worker;
	pthread_spinlock_t worker_lock;
	int worker_looptime;
};

static char *wd_agg_alg_name = "hashagg";
static struct wd_init_attrs wd_agg_init_attrs;
static int wd_agg_poll_ctx(struct wd_sched *sched, __u32 idx, __u32 expt, __u32 *count);

static void wd_agg_close_driver(void)
{
#ifndef WD_STATIC_DRV
	wd_dlclose_drv(wd_agg_setting.dlh_list);
#else
	hisi_dae_remove();
#endif
}

static int wd_agg_open_driver(void)
{
#ifndef WD_STATIC_DRV
	/*
	 * Driver lib file path could set by env param.
	 * then open tham by wd_dlopen_drv()
	 * use NULL means dynamic query path
	 */
	wd_agg_setting.dlh_list = wd_dlopen_drv(NULL);
	if (!wd_agg_setting.dlh_list) {
		WD_ERR("fail to open driver lib files.\n");
		return -WD_EINVAL;
	}
#else
	hisi_dae_probe();
#endif
	return WD_SUCCESS;
}

static bool wd_agg_alg_check(const char *alg_name)
{
	if (!strcmp(alg_name, wd_agg_alg_name))
		return true;
	return false;
}

static int check_count_out_data_type(enum wd_dae_data_type type)
{
	switch (type) {
	case WD_DAE_INT:
	case WD_DAE_LONG:
	case WD_DAE_SHORT_DECIMAL:
	case WD_DAE_LONG_DECIMAL:
		break;
	case WD_DAE_DATE:
	case WD_DAE_CHAR:
	case WD_DAE_VARCHAR:
	default:
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int check_col_data_info(enum wd_dae_data_type type, __u16 col_data_info)
{
	__u8 all_precision, decimal_precision;

	switch (type) {
	case WD_DAE_DATE:
	case WD_DAE_INT:
	case WD_DAE_LONG:
	case WD_DAE_VARCHAR:
		break;
	case WD_DAE_SHORT_DECIMAL:
	case WD_DAE_LONG_DECIMAL:
		/* High 8 bit: decimal part precision, low 8 bit: the whole data precision */
		all_precision = col_data_info;
		decimal_precision = col_data_info >> DECIMAL_PRECISION_OFFSET;
		if (!all_precision || decimal_precision > all_precision) {
			WD_ERR("failed to check agg data precision, all: %u, decimal: %u!\n",
			       all_precision, decimal_precision);
			return -WD_EINVAL;
		}
		break;
	case WD_DAE_CHAR:
		if (!col_data_info) {
			WD_ERR("invalid: agg char length is zero!\n");
			return -WD_EINVAL;
		}
		break;
	default:
		WD_ERR("invalid: agg data type is %d!\n", type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int get_col_data_type_size(enum wd_dae_data_type type, __u16 col_data_info,
				  __u64 *col, __u32 idx)
{
	switch (type) {
	case WD_DAE_DATE:
	case WD_DAE_INT:
		col[idx] = DAE_INT_SIZE;
		break;
	case WD_DAE_LONG:
	case WD_DAE_SHORT_DECIMAL:
		col[idx] = DAE_LONG_SIZE;
		break;
	case WD_DAE_LONG_DECIMAL:
		col[idx] = DAE_LONG_DECIMAL_SIZE;
		break;
	case WD_DAE_CHAR:
		col[idx] = col_data_info;
		break;
	case WD_DAE_VARCHAR:
		col[idx] = 0;
		break;
	default:
		return -WD_EINVAL;
	}
	return WD_SUCCESS;
}

static int check_key_cols_info(struct wd_agg_sess_setup *setup)
{
	struct wd_key_col_info *info = setup->key_cols_info;
	__u32 i;
	int ret;

	for (i = 0; i < setup->key_cols_num; i++) {
		ret = check_col_data_info(info[i].input_data_type, info[i].col_data_info);
		if (ret) {
			WD_ERR("failed to check agg key col data info! col idx: %u\n", i);
			return ret;
		}
	}

	return WD_SUCCESS;
}

static int check_agg_cols_info(struct wd_agg_sess_setup *setup, __u32 *out_agg_cols_num)
{
	struct wd_agg_col_info *info = setup->agg_cols_info;
	__u32 alg_cnt[WD_AGG_ALG_TYPE_MAX];
	enum wd_agg_alg alg;
	__u32 i, j, k;
	int ret;

	/* When there is only a count(*) task, it returns */
	if (!info)
		return 0;

	for (i = 0, k = 0; i < setup->agg_cols_num; i++) {
		ret = check_col_data_info(info[i].input_data_type, info[i].col_data_info);
		if (ret) {
			WD_ERR("failed to check agg col data info! col idx: %u\n", i);
			return ret;
		}

		if (!info[i].col_alg_num || info[i].col_alg_num > WD_AGG_ALG_TYPE_MAX) {
			WD_ERR("failed to check agg col_alg_num: %u! col idx: %u\n",
			       info[i].col_alg_num, i);
			return -WD_EINVAL;
		}

		memset(alg_cnt, 0,  sizeof(alg_cnt));
		for (j = 0; j < info[i].col_alg_num; j++, k++) {
			if (info[i].output_data_types[j] >= WD_DAE_DATA_TYPE_MAX) {
				WD_ERR("failed to check agg col output data type! col idx: %u\n",
				       i);
				return -WD_EINVAL;
			}
			alg = info[i].output_col_algs[j];
			if (alg >= WD_AGG_ALG_TYPE_MAX || alg_cnt[alg]) {
				WD_ERR("invalid agg output col alg type: %d, col idx: %u\n",
				       alg, i);
				return -WD_EINVAL;
			}
			alg_cnt[alg] += 1;
		}
	}

	*out_agg_cols_num += k;

	return WD_SUCCESS;
}

static int wd_agg_check_sess_params(struct wd_agg_sess_setup *setup, __u32 *out_agg_cols_num)
{
	if (!setup) {
		WD_ERR("invalid: agg sess setup is NULL!\n");
		return -WD_EINVAL;
	}

	if (!setup->key_cols_num || !setup->key_cols_info) {
		WD_ERR("invalid: agg key cols is NULL, num: %u\n", setup->key_cols_num);
		return -WD_EINVAL;
	}

	if (!setup->is_count_all) {
		if (!setup->agg_cols_num || !setup->agg_cols_info) {
			WD_ERR("invalid: agg input cols is NULL, num: %u\n", setup->agg_cols_num);
			return -WD_EINVAL;
		}
	} else {
		if (setup->agg_cols_num && !setup->agg_cols_info) {
			WD_ERR("invalid: agg cols info address is NULL!\n");
			return -WD_EINVAL;
		}
		if (check_count_out_data_type(setup->count_all_data_type)) {
			WD_ERR("invalid: agg count all output data type: %u\n",
			       setup->count_all_data_type);
			return -WD_EINVAL;
		}
		*out_agg_cols_num = 1;
	}

	if (check_key_cols_info(setup)) {
		WD_ERR("failed to check agg setup key cols info!\n");
		return -WD_EINVAL;
	}

	if (check_agg_cols_info(setup, out_agg_cols_num)) {
		WD_ERR("failed to check agg setup agg cols info!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_agg_session(struct wd_agg_sess *sess, struct wd_agg_sess_setup *setup)
{
	__u64 key_size, agg_size, key_data_size, agg_data_size, out_agg_data_size;
	struct wd_key_col_info *key = setup->key_cols_info;
	struct wd_agg_col_info *agg = setup->agg_cols_info;
	__u32 i, j, k;

	key_size = setup->key_cols_num * sizeof(struct wd_key_col_info);
	agg_size = setup->agg_cols_num * sizeof(struct wd_agg_col_info);
	sess->key_conf.cols_info = malloc(key_size);
	if (!sess->key_conf.cols_info)
		return -WD_ENOMEM;
	sess->agg_conf.cols_info = malloc(agg_size);
	if (!sess->agg_conf.cols_info)
		goto out_key;

	memcpy(sess->key_conf.cols_info, key, key_size);
	memcpy(sess->agg_conf.cols_info, agg, agg_size);

	key_data_size = setup->key_cols_num * sizeof(__u64);
	agg_data_size = setup->agg_cols_num * sizeof(__u64);
	out_agg_data_size = sess->agg_conf.out_cols_num * sizeof(__u64);
	sess->key_conf.data_size = malloc(key_data_size + agg_data_size + out_agg_data_size);
	if (!sess->key_conf.data_size)
		goto out_agg;

	for (i = 0; i < setup->key_cols_num; i++)
		(void)get_col_data_type_size(key[i].input_data_type, key[i].col_data_info,
					     sess->key_conf.data_size, i);

	sess->agg_conf.data_size = sess->key_conf.data_size + setup->key_cols_num;
	for (i = 0; i < setup->agg_cols_num; i++)
		(void)get_col_data_type_size(agg[i].input_data_type, agg[i].col_data_info,
					     sess->agg_conf.data_size, i);

	sess->agg_conf.out_data_size = sess->agg_conf.data_size + setup->agg_cols_num;
	for (i = 0, k = 0; i < setup->agg_cols_num; i++)
		for (j = 0; j < agg[i].col_alg_num; j++, k++)
			(void)get_col_data_type_size(agg[i].output_data_types[j],
						     agg[i].col_data_info,
						     sess->agg_conf.out_data_size, k);

	sess->key_conf.cols_num = setup->key_cols_num;
	sess->agg_conf.cols_num = setup->agg_cols_num;
	sess->agg_conf.is_count_all = setup->is_count_all;
	sess->agg_conf.count_all_data_type = setup->count_all_data_type;
	__atomic_store_n(&sess->state, WD_AGG_SESS_UNINIT, __ATOMIC_RELEASE);

	return WD_SUCCESS;
out_agg:
	free(sess->agg_conf.cols_info);
out_key:
	free(sess->key_conf.cols_info);
	return -WD_ENOMEM;
}

static int wd_agg_init_sess_priv(struct wd_agg_sess *sess, struct wd_agg_sess_setup *setup)
{
	int ret;

	if (sess->ops.sess_init) {
		if (!sess->ops.sess_uninit) {
			WD_ERR("failed to get session uninit ops!\n");
			return -WD_EINVAL;
		}
		ret = sess->ops.sess_init(setup, &sess->priv);
		if (ret) {
			WD_ERR("failed to init session priv!\n");
			return ret;
		}
	}

	if (sess->ops.get_row_size) {
		ret = sess->ops.get_row_size(sess->priv);
		if (ret <= 0) {
			if (sess->ops.sess_uninit)
				sess->ops.sess_uninit(sess->priv);
			WD_ERR("failed to get hash table row size: %d!\n", ret);
			return ret;
		}
		sess->hash_table.table_row_size = ret;
	}

	return WD_SUCCESS;
}

handle_t wd_agg_alloc_sess(struct wd_agg_sess_setup *setup)
{
	struct uadk_adapter_worker *worker;
	int nb = wd_agg_setting.adapter->workers_nb;
	__u32 out_agg_cols_num = 0;
	struct wd_agg_sess *sess;
	int ret, i;

	ret = wd_agg_check_sess_params(setup, &out_agg_cols_num);
	if (ret)
		return (handle_t)0;

	sess = malloc(sizeof(struct wd_agg_sess));
	if (!sess) {
		WD_ERR("failed to alloc agg session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_agg_sess));
	sess->agg_conf.out_cols_num = out_agg_cols_num;

	worker = sess->worker = &wd_agg_setting.adapter->workers[0];
	worker->valid = true;
	sess->worker_looptime = 0;

	sess->alg_name = wd_agg_alg_name;
	ret = wd_drv_alg_support(sess->alg_name, worker->driver);
	if (!ret) {
		WD_ERR("failed to support agg algorithm: %s!\n", sess->alg_name);
		goto err_sess;
	}

	sess->sched_key = (void **)calloc(nb, sizeof(void *));
	for (i = 0; i < nb; i++) {
		worker = &wd_agg_setting.adapter->workers[i];

		sess->sched_key[i] = (void *)worker->sched->sched_init(
				worker->sched->h_sched_ctx, setup->sched_param);
		if (WD_IS_ERR(sess->sched_key[i])) {
			WD_ERR("failed to init session schedule key!\n");
			goto err_sess;
		}
	}

	ret = worker->driver->get_extend_ops(&sess->ops);
	if (ret) {
		WD_ERR("failed to get agg extend ops!\n");
		goto err_sess;
	}

	ret = wd_agg_init_sess_priv(sess, setup);
	if (ret)
		goto err_sess;

	ret = fill_agg_session(sess, setup);
	if (ret) {
		WD_ERR("failed to fill agg session!\n");
		goto uninit_priv;
	}

	return (handle_t)sess;

uninit_priv:
	if (sess->ops.sess_uninit)
		sess->ops.sess_uninit(sess->priv);
err_sess:
	if (sess->sched_key) {
		for (i = 0; i < nb; i++)
			free(sess->sched_key[i]);
		free(sess->sched_key);
	}
	free(sess);
	return (handle_t)0;
}

void wd_agg_free_sess(handle_t h_sess)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("invalid: agg input sess is NULL!\n");
		return;
	}

	free(sess->key_conf.cols_info);
	free(sess->agg_conf.cols_info);
	free(sess->key_conf.data_size);

	if (sess->ops.sess_uninit)
		sess->ops.sess_uninit(sess->priv);
	if (sess->sched_key) {
		for (int i = 0; i < wd_agg_setting.adapter->workers_nb; i++)
			free(sess->sched_key[i]);
		free(sess->sched_key);
	}

	free(sess);
}

int wd_agg_get_table_rowsize(handle_t h_sess)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("invalid: agg input sess is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!sess->hash_table.table_row_size)) {
		WD_ERR("invalid: agg sess hash table row size is 0!\n");
		return -WD_EINVAL;
	}

	return sess->hash_table.table_row_size;
}

static int wd_agg_check_sess_state(struct wd_agg_sess *sess, enum wd_agg_sess_state *expected)
{
	enum wd_agg_sess_state next;
	int ret;

	if (sess->hash_table.std_table) {
		*expected = WD_AGG_SESS_INPUT;
		next = WD_AGG_SESS_RESET;
	} else {
		*expected = WD_AGG_SESS_UNINIT;
		next = WD_AGG_SESS_INIT;
	}

	ret = __atomic_compare_exchange_n(&sess->state, expected, next,
					  true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
	if (!ret) {
		WD_ERR("invalid: agg sess state is %d!\n", *expected);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wd_agg_set_hash_table(handle_t h_sess, struct wd_dae_hash_table *info)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;
	struct wd_dae_hash_table *hash_table, *rehash_table;
	enum wd_agg_sess_state expected;
	int ret;

	if (!sess || !info) {
		WD_ERR("invalid: agg sess or hash table is NULL!\n");
		return -WD_EINVAL;
	}

	ret = wd_agg_check_sess_state(sess, &expected);
	if (ret)
		return ret;

	if (info->table_row_size != sess->hash_table.table_row_size) {
		WD_ERR("invalid: agg hash table row size is not equal, expt: %u, real: %u!\n",
		       sess->hash_table.table_row_size, info->table_row_size);
		ret = -WD_EINVAL;
		goto out;
	}

	if (!info->std_table) {
		WD_ERR("invalid: agg standard hash table is NULL!\n");
		ret = -WD_EINVAL;
		goto out;
	}

	if (info->std_table_row_num < sess->hash_table.std_table_row_num) {
		WD_ERR("invalid: agg standard hash table is too small, expt: %u, real: %u!\n",
		       sess->hash_table.std_table_row_num, info->std_table_row_num);
		ret = -WD_EINVAL;
		goto out;
	}

	if (!info->ext_table_row_num || !info->ext_table)
		WD_INFO("info: agg extern hash table is NULL!\n");

	hash_table = &sess->hash_table;
	rehash_table = &sess->rehash_table;

	memcpy(rehash_table, hash_table, sizeof(struct wd_dae_hash_table));
	memcpy(hash_table, info, sizeof(struct wd_dae_hash_table));

	if (sess->ops.hash_table_init) {
		ret = sess->ops.hash_table_init(hash_table, sess->priv);
		if (ret) {
			memcpy(hash_table, rehash_table, sizeof(struct wd_dae_hash_table));
			memset(rehash_table, 0, sizeof(struct wd_dae_hash_table));
			goto out;
		}
	}

	return WD_SUCCESS;

out:
	__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
	return ret;
}

static void wd_agg_clear_status(void)
{
	wd_alg_clear_init(&wd_agg_setting.status);
}

static int wd_agg_alg_init(struct uadk_adapter_worker *worker, struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_AGG_EPOLL_EN", &worker->config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&worker->config, worker->ctx_config);
	if (ret < 0)
		return ret;

	worker->config.pool = &worker->pool;
	sched->worker = worker;
	worker->sched = sched;

	/* Allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&worker->pool,
					 worker->ctx_config, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_agg_msg));
	if (ret < 0)
		goto out_clear_ctx_config;

	ret = wd_alg_init_driver(&worker->config, worker->driver);
	if (ret)
		goto out_clear_pool;

	return WD_SUCCESS;

out_clear_pool:
	wd_uninit_async_request_pool(&worker->pool);
out_clear_ctx_config:
	wd_clear_ctx_config(&worker->config);
	return ret;
}

int wd_agg_init(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_params agg_ctx_params = {0};
	struct wd_ctx_nums agg_ctx_num = {0};
	struct uadk_adapter_worker *worker;
	struct uadk_adapter *adapter = NULL;
	int ret = -WD_EINVAL;
	int state, i;
	bool flag;

	pthread_atfork(NULL, NULL, wd_agg_clear_status);

	state = wd_alg_try_init(&wd_agg_setting.status);
	if (state)
		return state;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	    task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: agg init input param is wrong!\n");
		goto out_uninit;
	}

	flag = wd_agg_alg_check(alg);
	if (!flag) {
		WD_ERR("invalid: agg: %s unsupported!\n", alg);
		goto out_uninit;
	}

	adapter = calloc(1, sizeof(*adapter));
	if (adapter == NULL)
		goto out_uninit;
	wd_agg_setting.adapter = adapter;

	state = wd_agg_open_driver();
	if (state)
		goto out_uninit;

	ret = uadk_adapter_add_workers(adapter, alg);
	if (ret)
		goto out_dlopen;

	for (i = 0; i < adapter->workers_nb; i++) {
		worker = &adapter->workers[i];

		agg_ctx_params.ctx_set_num = &agg_ctx_num;
		ret = wd_ctx_param_init(&agg_ctx_params, ctx_params, worker->driver,
					WD_AGG_TYPE, 1);
		if (ret) {
			WD_ERR("fail to init ctx param\n");
			goto out_dlopen;
		}

		wd_agg_init_attrs.alg = alg;
		wd_agg_init_attrs.ctx_params = &agg_ctx_params;
		wd_agg_init_attrs.alg_init = wd_agg_alg_init;
		wd_agg_init_attrs.alg_poll_ctx = wd_agg_poll_ctx;
		ret = wd_alg_attrs_init(worker, &wd_agg_init_attrs);
		wd_ctx_param_uninit(&agg_ctx_params);
		if (ret) {
			WD_ERR("fail to init alg attrs.\n");
			goto out_dlopen;
		}
	}

	wd_alg_set_init(&wd_agg_setting.status);

	return WD_SUCCESS;

out_dlopen:
	wd_agg_close_driver();
out_uninit:
	wd_alg_clear_init(&wd_agg_setting.status);
	return ret;
}

void wd_agg_uninit(void)
{
	struct uadk_adapter_worker *worker;

	for (int i = 0; i < wd_agg_setting.adapter->workers_nb; i++) {
		worker = &wd_agg_setting.adapter->workers[i];
		wd_alg_attrs_uninit(worker);
		wd_uninit_async_request_pool(&worker->pool);
		wd_alg_uninit_driver(&worker->config, worker->driver);
	}

	wd_agg_close_driver();
	wd_agg_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_agg_setting.status);
}

static void fill_request_msg_input(struct wd_agg_msg *msg, struct wd_agg_req *req,
				     struct wd_agg_sess *sess, bool is_rehash)
{
	memcpy(&msg->req, req, sizeof(struct wd_agg_req));

	msg->key_cols_num = sess->key_conf.cols_num;
	msg->agg_cols_num = sess->agg_conf.cols_num;
	memcpy(&msg->hash_table, &sess->hash_table, sizeof(struct wd_dae_hash_table));
	msg->row_count = req->in_row_count;
	msg->priv = sess->priv;
	if (!is_rehash) {
		msg->pos = WD_AGG_STREAM_INPUT;
		msg->agg_cols_info = sess->agg_conf.cols_info;
		msg->key_cols_info = sess->key_conf.cols_info;
		msg->is_count_all = sess->agg_conf.is_count_all;
		msg->count_all_data_type = sess->agg_conf.count_all_data_type;
	} else {
		msg->pos = WD_AGG_REHASH_INPUT;
	}
}

static void fill_request_msg_output(struct wd_agg_msg *msg, struct wd_agg_req *req,
				    struct wd_agg_sess *sess, bool is_rehash)
{
	memcpy(&msg->req, req, sizeof(struct wd_agg_req));

	msg->key_cols_num = sess->key_conf.cols_num;
	msg->agg_cols_num = sess->agg_conf.cols_num;
	msg->priv = sess->priv;
	if (!is_rehash) {
		msg->pos = WD_AGG_STREAM_OUTPUT;
		msg->is_count_all = sess->agg_conf.is_count_all;
		msg->count_all_data_type = sess->agg_conf.count_all_data_type;
		memcpy(&msg->hash_table, &sess->hash_table, sizeof(struct wd_dae_hash_table));
	} else {
		msg->pos = WD_AGG_REHASH_OUTPUT;
		memcpy(&msg->hash_table, &sess->rehash_table, sizeof(struct wd_dae_hash_table));
	}
	msg->key_cols_info = sess->key_conf.cols_info;
	msg->agg_cols_info = sess->agg_conf.cols_info;
	msg->row_count = req->out_row_count;
}

static int wd_agg_check_common_params(struct wd_agg_sess *sess, struct wd_agg_req *req, __u8 mode)
{
	if (unlikely(!sess)) {
		WD_ERR("invalid: agg session is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!sess->key_conf.data_size || !sess->agg_conf.data_size ||
		     !sess->agg_conf.out_data_size)) {
		WD_ERR("invalid: agg session data size is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!req)) {
		WD_ERR("invalid: agg input req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_ASYNC && !req->cb)) {
		WD_ERR("invalid: agg req cb is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int check_out_col_addr(struct wd_dae_col_addr *col, __u32 row_count,
			      enum wd_dae_data_type type, __u64 data_size)
{
	if (unlikely(!col->empty || col->empty_size < row_count * sizeof(col->empty[0]))) {
		WD_ERR("failed to check agg empty col, size: %llu!\n", col->empty_size);
		return -WD_EINVAL;
	}
	if (unlikely(!col->value)) {
		WD_ERR("invalid: agg value col addr is NULL!\n");
		return -WD_EINVAL;
	}
	/* Only VARCHAR type use offset col to indicate the length of value col */
	if (type == WD_DAE_VARCHAR) {
		/* Offset col row count should be 1 more than row_count */
		if (unlikely(!col->offset ||
			     col->offset_size < (row_count + 1) * sizeof(col->offset[0]))) {
			WD_ERR("failed to check agg offset col, size: %llu!\n",
			       col->offset_size);
			return -WD_EINVAL;
		}
	} else {
		if (unlikely(col->value_size < row_count * data_size)) {
			WD_ERR("failed to check agg value col size: %llu!\n", col->value_size);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int check_in_col_addr(struct wd_dae_col_addr *col, __u32 row_count,
			     enum wd_dae_data_type type, __u64 data_size)
{
	__u32 offset_len;

	if (unlikely(!col->empty || col->empty_size != row_count * sizeof(col->empty[0]))) {
		WD_ERR("failed to check agg empty col addr, size: %llu!\n", col->empty_size);
		return -WD_EINVAL;
	}

	if (unlikely(!col->value)) {
		WD_ERR("invalid: agg value col addr is NULL!\n");
		return -WD_EINVAL;
	}
	/* Only VARCHAR type use offset col to indicate the length of value col */
	if (type == WD_DAE_VARCHAR) {
		/* Offset col row count should be 1 more than row_count */
		offset_len = row_count + 1;
		if (unlikely(!col->offset ||
			     col->offset_size != offset_len * sizeof(col->offset[0]))) {
			WD_ERR("failed to check agg offset col addr, size: %llu!\n",
			       col->offset_size);
			return -WD_EINVAL;
		}
		if (unlikely(col->offset[offset_len - 1] < col->offset[0] ||
			     col->offset[offset_len - 1] - col->offset[0] != col->value_size)) {
			WD_ERR("failed to check agg varchar value col size: %llu!\n",
			       col->value_size);
			return -WD_EINVAL;
		}
	} else {
		if (unlikely(col->value_size != row_count * data_size)) {
			WD_ERR("failed to check agg value col size: %llu!\n", col->value_size);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int check_key_col_addr(struct wd_dae_col_addr *cols, __u32 cols_num,
			      struct wd_agg_sess *sess, __u32 row_count, bool is_input)
{
	int (*func)(struct wd_dae_col_addr *col, __u32 row_count,
		    enum wd_dae_data_type type, __u64 data_size);
	__u32 i;
	int ret;

	if (sess->key_conf.cols_num != cols_num) {
		WD_ERR("agg req key cols num is wrong!\n");
		return -WD_EINVAL;
	}

	if (is_input)
		func = check_in_col_addr;
	else
		func = check_out_col_addr;

	for (i = 0; i < cols_num; i++) {
		ret = func(cols + i, row_count, sess->key_conf.cols_info[i].input_data_type,
			   sess->key_conf.data_size[i]);
		if (unlikely(ret)) {
			WD_ERR("failed to check agg req key col! col idx: %u\n", i);
			return ret;
		}
	}

	return WD_SUCCESS;
}

static int check_agg_col_addr(struct wd_dae_col_addr *cols, __u32 cols_num,
			      struct wd_agg_sess *sess, __u32 row_count)
{
	__u32 i;
	int ret;

	/* When there is only a count(*) task, it returns */
	if (!cols)
		return 0;

	if (sess->agg_conf.cols_num != cols_num) {
		WD_ERR("agg req input agg cols num is wrong!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < cols_num; i++) {
		ret = check_in_col_addr(cols + i, row_count,
					sess->agg_conf.cols_info[i].input_data_type,
					sess->agg_conf.data_size[i]);
		if (unlikely(ret)) {
			WD_ERR("failed to check agg req input agg col! col idx: %u\n", i);
			return ret;
		}
	}

	return WD_SUCCESS;
}

static int check_out_agg_col_addr(struct wd_dae_col_addr *cols, __u32 cols_num,
				  struct wd_agg_sess *sess, __u32 row_count)
{
	__u32 i, j, k;
	int ret;

	if (sess->agg_conf.out_cols_num != cols_num) {
		WD_ERR("agg req output agg cols num is wrong!\n");
		return -WD_EINVAL;
	}

	for (i = 0, k = 0; i < sess->agg_conf.cols_num; i++) {
		for (j = 0; j < sess->agg_conf.cols_info[i].col_alg_num; j++, k++) {
			ret = check_out_col_addr(cols + k, row_count,
						 sess->agg_conf.cols_info[i].output_data_types[j],
						 sess->agg_conf.out_data_size[k]);
			if (unlikely(ret)) {
				WD_ERR("failed to check agg req output agg col! col idx: %u\n", i);
				return ret;
			}
		}
	}
	return WD_SUCCESS;
}

static int wd_agg_check_input_req(struct wd_agg_sess *sess, struct wd_agg_req *req)
{
	int ret;

	if (unlikely(req->key_cols_num != sess->key_conf.cols_num)) {
		WD_ERR("invalid: agg req key_cols_num is not equal!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->agg_cols_num != sess->agg_conf.cols_num)) {
		WD_ERR("invalid: agg req agg_cols_num is not equal!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!req->key_cols)) {
		WD_ERR("invalid: agg req key_cols is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->agg_cols_num && !req->agg_cols)) {
		WD_ERR("invalid: agg req agg_cols is NULL!\n");
		return -WD_EINVAL;
	}

	if (!req->in_row_count) {
		WD_ERR("agg req input row count is zero!\n");
		return -WD_EINVAL;
	}

	ret = check_key_col_addr(req->key_cols, req->key_cols_num, sess, req->in_row_count, true);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg req key cols addr!\n");
		return -WD_EINVAL;
	}

	ret = check_agg_col_addr(req->agg_cols, req->agg_cols_num, sess, req->in_row_count);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg req agg cols addr!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_agg_check_input_params(struct wd_agg_sess *sess, struct wd_agg_req *req, __u8 mode)
{
	int ret;

	ret = wd_agg_check_common_params(sess, req, mode);
	if (ret)
		return ret;

	return wd_agg_check_input_req(sess, req);
}

static int wd_agg_check_output_req(struct wd_agg_sess *sess, struct wd_agg_req *req)
{
	int ret;

	if (unlikely(req->out_key_cols_num != sess->key_conf.cols_num)) {
		WD_ERR("invalid: agg req out_key_cols_num is not equal!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_agg_cols_num != sess->agg_conf.out_cols_num)) {
		WD_ERR("invalid: agg req out_agg_cols_num is not equal!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!req->out_key_cols)) {
		WD_ERR("invalid: agg req out_key_cols is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!req->out_agg_cols)) {
		WD_ERR("invalid: agg req out_agg_cols is NULL!\n");
		return -WD_EINVAL;
	}

	if (!req->out_row_count) {
		WD_ERR("agg req output row count is zero!\n");
		return -WD_EINVAL;
	}

	ret = check_key_col_addr(req->out_key_cols, req->out_key_cols_num, sess,
				 req->out_row_count, false);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg req out key cols addr!\n");
		return -WD_EINVAL;
	}

	ret = check_out_agg_col_addr(req->out_agg_cols, req->out_agg_cols_num, sess,
				     req->out_row_count);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg req out agg cols addr!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_agg_check_output_params(struct wd_agg_sess *sess, struct wd_agg_req *req, __u8 mode)
{
	int ret;

	ret = wd_agg_check_common_params(sess, req, mode);
	if (ret)
		return ret;

	return wd_agg_check_output_req(sess, req);
}

static int wd_agg_check_rehash_params(struct wd_agg_sess *sess, struct wd_agg_req *req)
{
	int ret;

	ret = wd_agg_check_common_params(sess, req, CTX_MODE_SYNC);
	if (ret)
		return ret;

	ret = wd_agg_check_output_req(sess, req);
	if (ret)
		WD_ERR("failed to check agg output req for rehash!\n");

	return ret;
}

static int wd_agg_sync_job(struct uadk_adapter_worker *worker, struct wd_agg_sess *sess,
			   struct wd_agg_req *req, struct wd_agg_msg *msg)
{
	struct wd_msg_handle msg_handle;
	struct wd_ctx_internal *ctx;
	__u32 idx;
	int ret;

	idx = worker->sched->pick_next_ctx(worker->sched->h_sched_ctx,
					   sess->sched_key[worker->idx],
					   CTX_MODE_SYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);
	ctx = worker->config.ctxs + idx;

	msg_handle.send = worker->driver->send;
	msg_handle.recv = worker->driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(worker->driver, &msg_handle, ctx->ctx,
				 msg, NULL, worker->config.epoll_en);
	pthread_spin_unlock(&ctx->lock);

	return ret;
}

static int wd_agg_input_try_init(struct wd_agg_sess *sess, enum wd_agg_sess_state *expected)
{
	(void)__atomic_compare_exchange_n(&sess->state, expected, WD_AGG_SESS_INPUT,
					  true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
	switch (*expected) {
	case WD_AGG_SESS_INIT:
	case WD_AGG_SESS_INPUT:
		break;
	default:
		WD_ERR("invalid: agg input sess state is %d!\n", *expected);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_agg_check_msg_result(__u32 result)
{
	switch (result) {
	case WD_AGG_TASK_DONE:
	case WD_AGG_SUM_OVERFLOW:
		return 0;
	case WD_AGG_IN_EPARA:
	case WD_AGG_NEED_REHASH:
	case WD_AGG_INVALID_HASH_TABLE:
	case WD_AGG_INVALID_VARCHAR:
	case WD_AGG_PARSE_ERROR:
	case WD_AGG_BUS_ERROR:
		WD_ERR("failed to check agg message state: %u!\n", result);
		return -WD_EIO;
	default:
		return -WD_EINVAL;
	}
}

int wd_agg_add_input_sync(handle_t h_sess, struct wd_agg_req *req)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;
	enum wd_agg_sess_state expected = WD_AGG_SESS_INIT;
	struct uadk_adapter_worker *worker;
	struct wd_agg_msg msg;
	int ret;

	ret = wd_agg_check_input_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg input params!\n");
		return ret;
	}

	ret = wd_agg_input_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	memset(&msg, 0, sizeof(struct wd_agg_msg));
	fill_request_msg_input(&msg, req, sess, false);
	req->state = 0;

	ret = wd_agg_sync_job(worker, sess, req, &msg);
	if (unlikely(ret)) {
		if (expected == WD_AGG_SESS_INIT)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do agg add input sync job!\n");
		return ret;
	}

	req->state = msg.result;
	req->real_in_row_count = msg.in_row_count;

	return WD_SUCCESS;
}

static int wd_agg_async_job(struct wd_agg_sess *sess, struct wd_agg_req *req, bool is_input)
{
	struct uadk_adapter_worker *worker;
	struct wd_ctx_internal *ctx;
	__u32 idx;
	int msg_id, ret;
	struct wd_agg_msg *msg;

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	idx = worker->sched->pick_next_ctx(worker->sched->h_sched_ctx,
					   sess->sched_key[worker->idx], CTX_MODE_ASYNC);
	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (unlikely(ret))
		return ret;

	ctx = worker->config.ctxs + idx;

	msg_id = wd_get_msg_from_pool(&worker->pool, idx,
				   (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("failed to get agg msg from pool!\n");
		return msg_id;
	}

	if (is_input)
		fill_request_msg_input(msg, req, sess, false);
	else
		fill_request_msg_output(msg, req, sess, false);
	msg->tag = msg_id;
	ret = wd_alg_driver_send(worker->driver, ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("wd agg async send err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(&worker->config, WD_CTX_CNT_NUM, idx);

	return WD_SUCCESS;

fail_with_msg:
	wd_put_msg_to_pool(&worker->pool, idx, msg->tag);
	return ret;
}

int wd_agg_add_input_async(handle_t h_sess, struct wd_agg_req *req)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;
	enum wd_agg_sess_state expected = WD_AGG_SESS_INIT;
	int ret;

	ret = wd_agg_check_input_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg async input params!\n");
		return ret;
	}

	ret = wd_agg_input_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	ret = wd_agg_async_job(sess, req, true);
	if (unlikely(ret)) {
		if (expected == WD_AGG_SESS_INIT)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do agg add input async job!\n");
	}

	return ret;
}

static int wd_agg_output_try_init(struct wd_agg_sess *sess, enum wd_agg_sess_state *expected)
{
	(void)__atomic_compare_exchange_n(&sess->state, expected, WD_AGG_SESS_OUTPUT,
					  true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
	switch (*expected) {
	case WD_AGG_SESS_OUTPUT:
	case WD_AGG_SESS_INPUT:
		break;
	default:
		WD_ERR("invalid: agg output sess state is %d!\n", *expected);
		return -WD_EINVAL;
	}
	return WD_SUCCESS;
}

int wd_agg_get_output_sync(handle_t h_sess, struct wd_agg_req *req)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;
	enum wd_agg_sess_state expected = WD_AGG_SESS_INPUT;
	struct uadk_adapter_worker *worker;
	struct wd_agg_msg msg;
	int ret;

	ret = wd_agg_check_output_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg output params!\n");
		return ret;
	}

	ret = wd_agg_output_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	memset(&msg, 0, sizeof(struct wd_agg_msg));
	fill_request_msg_output(&msg, req, sess, false);
	req->state = 0;

	ret = wd_agg_sync_job(worker, sess, req, &msg);
	if (unlikely(ret)) {
		if (expected == WD_AGG_SESS_INPUT)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do agg get output sync job!\n");
		return ret;
	}

	req->state = msg.result;
	req->real_out_row_count = msg.out_row_count;
	req->output_done = msg.output_done;

	return WD_SUCCESS;
}

int wd_agg_get_output_async(handle_t h_sess, struct wd_agg_req *req)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;
	enum wd_agg_sess_state expected = WD_AGG_SESS_INPUT;
	int ret;

	ret = wd_agg_check_output_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg async output params!\n");
		return ret;
	}

	ret = wd_agg_output_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	ret = wd_agg_async_job(sess, req, false);
	if (unlikely(ret)) {
		if (expected == WD_AGG_SESS_INPUT)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do agg get output async job!\n");
	}

	return ret;
}

static int set_col_size_inner(struct wd_dae_col_addr *col, struct wd_dae_col_addr *expt,
			      __u32 row_count, __u64 data_size, enum wd_dae_data_type type)
{
	col->empty_size = expt->empty_size;
	if (type != WD_DAE_VARCHAR) {
		col->value_size = row_count * data_size;
		return WD_SUCCESS;
	}

	if (unlikely(!col->offset || col->offset[row_count] < col->offset[0])) {
		WD_ERR("invalid: hashagg offset col param is wrong!\n");
		return -WD_EINVAL;
	}

	col->offset_size = expt->offset_size;
	col->value_size = col->offset[row_count] - col->offset[0];

	return WD_SUCCESS;
}

static int wd_agg_set_keycol_size(struct wd_agg_sess *sess, struct wd_dae_col_addr *key,
				  struct wd_dae_col_addr *expt, __u32 row_count)
{
	__u32 i;
	int ret;

	for (i = 0; i < sess->key_conf.cols_num; i++) {
		ret = set_col_size_inner(key + i, expt, row_count, sess->key_conf.data_size[i],
					 sess->key_conf.cols_info[i].input_data_type);
		if (unlikely(ret))
			return ret;
	}

	return WD_SUCCESS;
}

static int wd_agg_set_aggcol_size(struct wd_agg_sess *sess, struct wd_dae_col_addr *agg,
				  struct wd_dae_col_addr *expt, __u32 row_count)
{
	__u64 data_size = 0;
	__u32 i, j, k;
	int ret;

	for (i = 0, k = 0; i < sess->agg_conf.cols_num; i++) {
		for (j = 0; j < sess->agg_conf.cols_info[i].col_alg_num; j++, k++) {
			ret = set_col_size_inner(agg + k, expt, row_count,
						 sess->agg_conf.out_data_size[k],
						 sess->agg_conf.cols_info[i].output_data_types[j]);
			if (unlikely(ret))
				return ret;
		}
	}

	if (sess->agg_conf.is_count_all) {
		(void)get_col_data_type_size(sess->agg_conf.count_all_data_type, 0, &data_size, 0);
		ret = set_col_size_inner(agg + k, expt, row_count, data_size,
					 sess->agg_conf.count_all_data_type);
		if (unlikely(ret))
			return ret;
	}

	return WD_SUCCESS;
}

static int wd_agg_set_col_size(struct wd_agg_sess *sess, struct wd_agg_req *req,
			       __u32 row_count)
{
	struct wd_dae_col_addr expt = {0};
	int ret;

	expt.empty_size = sizeof(__u8) * row_count;
	expt.offset_size = sizeof(__u32) * (row_count + 1);

	ret = wd_agg_set_keycol_size(sess, req->key_cols, &expt, row_count);
	if (unlikely(ret))
		return ret;

	ret = wd_agg_set_aggcol_size(sess, req->agg_cols, &expt, row_count);
	if (unlikely(ret))
		return ret;

	return WD_SUCCESS;
}

static int wd_agg_rehash_sync_inner(struct uadk_adapter_worker *worker,
				    struct wd_agg_sess *sess,
				    struct wd_agg_req *req)
{
	struct wd_agg_msg msg = {0};
	bool output_done;
	int ret;

	fill_request_msg_output(&msg, req, sess, true);
	req->state = 0;

	ret = wd_agg_sync_job(worker, sess, req, &msg);
	if (unlikely(ret))
		return ret;

	ret = wd_agg_check_msg_result(msg.result);
	if (unlikely(ret))
		return ret;

	req->real_out_row_count = msg.out_row_count;
	output_done = msg.output_done;
	if (!msg.out_row_count) {
		req->output_done = true;
		return WD_SUCCESS;
	}

	req->key_cols = req->out_key_cols;
	req->agg_cols = req->out_agg_cols;
	req->key_cols_num = req->out_key_cols_num;
	req->agg_cols_num = req->out_agg_cols_num;
	wd_agg_set_col_size(sess, req, req->real_out_row_count);
	req->in_row_count = req->real_out_row_count;

	memset(&msg, 0, sizeof(struct wd_agg_msg));
	fill_request_msg_input(&msg, req, sess, true);

	ret = wd_agg_sync_job(worker, sess, req, &msg);
	if (unlikely(ret))
		return ret;

	ret = wd_agg_check_msg_result(msg.result);
	if (unlikely(ret))
		return ret;

	req->state = msg.result;
	req->output_done = output_done;

	return WD_SUCCESS;
}

static int wd_agg_rehash_try_init(struct wd_agg_sess *sess, enum wd_agg_sess_state *expected)
{
	int ret;

	ret = __atomic_compare_exchange_n(&sess->state, expected, WD_AGG_SESS_REHASH,
					  true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
	if (!ret) {
		WD_ERR("invalid: agg rehash sess state is %d!\n", *expected);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wd_agg_rehash_sync(handle_t h_sess, struct wd_agg_req *req)
{
	struct wd_agg_sess *sess = (struct wd_agg_sess *)h_sess;
	enum wd_agg_sess_state expected = WD_AGG_SESS_RESET;
	struct uadk_adapter_worker *worker;
	struct wd_agg_req src_req;
	__u64 cnt = 0;
	__u64 max_cnt;
	int ret;

	ret = wd_agg_check_rehash_params(sess, req);
	if (unlikely(ret)) {
		WD_ERR("failed to check agg rehash params!\n");
		return ret;
	}

	ret = wd_agg_rehash_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	pthread_spin_lock(&sess->worker_lock);
	worker = sess->worker;
	pthread_spin_unlock(&sess->worker_lock);

	memcpy(&src_req, req, sizeof(struct wd_agg_req));
	max_cnt = MAX_HASH_TABLE_ROW_NUM / req->out_row_count;
	while (cnt < max_cnt) {
		ret = wd_agg_rehash_sync_inner(worker, sess, &src_req);
		if (ret) {
			__atomic_store_n(&sess->state, WD_AGG_SESS_RESET, __ATOMIC_RELEASE);
			WD_ERR("failed to do agg rehash task!\n");
			return ret;
		}
		if (src_req.output_done)
			break;
		cnt++;
	}

	__atomic_store_n(&sess->state, WD_AGG_SESS_INPUT, __ATOMIC_RELEASE);
	return WD_SUCCESS;
}

static int wd_agg_poll_ctx(struct wd_sched *sched, __u32 idx, __u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker = sched->worker;
	struct wd_agg_msg resp_msg, *msg;
	struct wd_ctx_internal *ctx;
	struct wd_agg_req *req;
	__u64 recv_count = 0;
	__u32 tmp = expt;
	int ret;

	*count = 0;

	ret = wd_check_ctx(&worker->config, CTX_MODE_ASYNC, idx);
	if (unlikely(ret))
		return ret;

	ctx = worker->config.ctxs + idx;

	do {
		ret = wd_alg_driver_recv(worker->driver, ctx->ctx, &resp_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (unlikely(ret < 0)) {
			WD_ERR("wd agg recv hw err!\n");
			return ret;
		}
		recv_count++;
		msg = wd_find_msg_in_pool(&worker->pool, idx, resp_msg.tag);
		if (unlikely(!msg)) {
			WD_ERR("failed to get agg msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->tag = resp_msg.tag;
		msg->req.state = resp_msg.result;
		msg->req.real_in_row_count = resp_msg.in_row_count;
		msg->req.real_out_row_count = resp_msg.out_row_count;
		msg->req.output_done = resp_msg.output_done;
		req = &msg->req;

		req->cb(req, req->cb_param);
		/* Free msg cache to msg_pool */
		wd_put_msg_to_pool(&worker->pool, idx, resp_msg.tag);
		*count = recv_count;
	} while (--tmp);

	return ret;
}

int wd_agg_poll(__u32 expt, __u32 *count)
{
	struct uadk_adapter_worker *worker;
	__u32 recv = 0;
	int ret = WD_SUCCESS;

	if (unlikely(!expt || !count)) {
		WD_ERR("invalid: agg poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	for (int i = 0; i < wd_agg_setting.adapter->workers_nb; i++) {
		worker = &wd_agg_setting.adapter->workers[i];

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
