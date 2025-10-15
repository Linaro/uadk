/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <limits.h>
#include "include/drv/wd_join_gather_drv.h"
#include "wd_join_gather.h"

#define DECIMAL_PRECISION_OFFSET	8
#define DAE_INT_SIZE			4
#define DAE_LONG_SIZE			8
#define DAE_LONG_DECIMAL_SIZE		16

/* Sum of the max row number of standard and external hash table */
#define MAX_HASH_TABLE_ROW_NUM		0x1FFFFFFFE

enum wd_join_sess_state {
	WD_JOIN_SESS_UNINIT, /* Uninit session */
	WD_JOIN_SESS_INIT, /* Hash table has been set */
	WD_JOIN_SESS_BUILD_HASH, /* Input stage has started */
	WD_JOIN_SESS_PREPARE_REHASH, /* New hash table has been set */
	WD_JOIN_SESS_REHASH, /* Rehash stage has started */
	WD_JOIN_SESS_PROBE, /* Output stage has started */
};

struct wd_join_gather_setting {
	enum wd_status status;
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	struct wd_async_msg_pool pool;
	struct wd_alg_driver *driver;
	void *priv;
	void *dlhandle;
	void *dlh_list;
};

struct wd_join_cols_conf {
	struct wd_join_gather_col_info *cols;
	__u64 *data_size;
	__u32 cols_num;
	bool key_output_enable;
};

struct wd_gather_tables_conf {
	struct wd_gather_table_info *tables;
	__u32 *batch_row_size;
	__u64 **data_size;
	__u32 table_num;
};

struct wd_join_gather_sess {
	enum multi_batch_index_type index_type;
	enum wd_join_sess_state state;
	enum wd_join_gather_alg alg;
	struct wd_join_gather_ops ops;
	struct wd_join_cols_conf join_conf;
	struct wd_gather_tables_conf gather_conf;
	struct wd_dae_hash_table hash_table;
	wd_dev_mask_t *dev_mask;
	void *sched_key;
	void *priv;
};

static const char *wd_join_gather_alg[WD_JOIN_GATHER_ALG_MAX] = {
	"hashjoin", "gather", "join-gather"
};

static struct wd_init_attrs wd_join_gather_init_attrs;
static struct wd_join_gather_setting wd_join_gather_setting;
static int wd_join_gather_poll_ctx(__u32 idx, __u32 expt, __u32 *count);

static void wd_join_gather_close_driver(void)
{
#ifndef WD_STATIC_DRV
	wd_dlclose_drv(wd_join_gather_setting.dlh_list);
	wd_join_gather_setting.dlh_list = NULL;
#else
	wd_release_drv(wd_join_gather_setting.driver);
	hisi_dae_join_gather_remove();
#endif
}

static int wd_join_gather_open_driver(void)
{
#ifndef WD_STATIC_DRV
	/*
	 * Driver lib file path could set by env param.
	 * then open tham by wd_dlopen_drv()
	 * use NULL means dynamic query path
	 */
	wd_join_gather_setting.dlh_list = wd_dlopen_drv(NULL);
	if (!wd_join_gather_setting.dlh_list) {
		WD_ERR("fail to open driver lib files.\n");
		return -WD_EINVAL;
	}
#else
	hisi_dae_join_gather_probe();
#endif
	return WD_SUCCESS;
}

static bool wd_join_gather_check_inner(void)
{
	struct uacce_dev_list *list;

	list = wd_get_accel_list("hashjoin");
	if (!list)
		goto out;
	wd_free_list_accels(list);

	list = wd_get_accel_list("gather");
	if (!list)
		goto out;
	wd_free_list_accels(list);

	return true;
out:
	WD_ERR("invalid: the device cannot support hashjoin and gather!\n");
	return false;
}

static bool wd_join_gather_alg_check(const char *alg_name)
{
	__u32 i;

	/* Check for the virtual algorithms */
	if (!strcmp(alg_name, "join-gather"))
		return wd_join_gather_check_inner();

	for (i = 0; i < WD_JOIN_GATHER_ALG_MAX; i++) {
		/* Some algorithms do not support all modes */
		if (!wd_join_gather_alg[i] || !strlen(wd_join_gather_alg[i]))
			continue;
		if (!strcmp(alg_name, wd_join_gather_alg[i]))
			return true;
	}

	return false;
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
			WD_ERR("failed to check data precision, all: %u, decimal: %u!\n",
			       all_precision, decimal_precision);
			return -WD_EINVAL;
		}
		break;
	case WD_DAE_CHAR:
		if (!col_data_info) {
			WD_ERR("invalid: char length is zero!\n");
			return -WD_EINVAL;
		}
		break;
	default:
		WD_ERR("invalid: data type %u is not supported!\n", type);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int get_data_type_size(enum wd_dae_data_type type, __u16 col_data_info,
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

static int check_key_cols_info(struct wd_join_gather_sess_setup *setup)
{
	struct wd_join_table_info *table = &setup->join_table;
	struct wd_join_gather_col_info *build = table->build_key_cols;
	__u32 i;
	int ret;

	if (table->build_key_cols_num != table->probe_key_cols_num) {
		WD_ERR("invalid: build key_cols_num: %u, probe key_cols_num: %u!\n",
		       table->build_key_cols_num, table->probe_key_cols_num);
		return -WD_EINVAL;
	}

	ret = memcmp(table->build_key_cols, table->probe_key_cols,
		     table->build_key_cols_num * sizeof(struct wd_join_gather_col_info));
	if (ret) {
		WD_ERR("invalid: build and probe table key infomation is not same!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < table->build_key_cols_num; i++) {
		if (!build[i].has_empty) {
			WD_ERR("invalid: key col has no empty data! col: %u\n", i);
			return -WD_EINVAL;
		}
		ret = check_col_data_info(build[i].data_type, build[i].data_info);
		if (ret) {
			WD_ERR("failed to check key col data info! col: %u\n", i);
			return ret;
		}
	}

	return WD_SUCCESS;
}

static int wd_join_check_params(struct wd_join_gather_sess_setup *setup)
{
	struct wd_join_table_info *table = &setup->join_table;

	if (!table->build_key_cols_num || !table->build_key_cols) {
		WD_ERR("invalid: build key cols is NULL or key_cols_num is 0!\n");
		return -WD_EINVAL;
	}

	if (!table->probe_key_cols_num || !table->probe_key_cols) {
		WD_ERR("invalid: probe key cols is NULL or key_cols_num is 0!\n");
		return -WD_EINVAL;
	}

	if (setup->index_type >= WD_BATCH_INDEX_TYPE_MAX) {
		WD_ERR("failed to check batch index type!\n");
		return -WD_EINVAL;
	}

	if (check_key_cols_info(setup)) {
		WD_ERR("failed to check join setup key cols info!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_gather_check_params(struct wd_join_gather_sess_setup *setup)
{
	struct wd_gather_table_info *table = setup->gather_tables;
	struct wd_join_gather_col_info *col;
	__u32 i, j;
	int ret;

	if (!setup->gather_tables || !setup->gather_table_num) {
		WD_ERR("invalid: gather table is NULL, table num: %u\n", setup->gather_table_num);
		return -WD_EINVAL;
	}

	if (setup->index_type >= WD_BATCH_INDEX_TYPE_MAX) {
		WD_ERR("failed to check gather batch index type!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < setup->gather_table_num; i++) {
		if (!table[i].cols || !table[i].cols_num) {
			WD_ERR("failed to check gather table cols, num: %u\n", table[i].cols_num);
			return -WD_EINVAL;
		}
		col = table[i].cols;
		for (j = 0; j < table[i].cols_num; j++) {
			ret = check_col_data_info(col[j].data_type, col[j].data_info);
			if (ret) {
				WD_ERR("failed to check gather info! col: %u, table: %u\n", j, i);
				return ret;
			}
		}
	}

	return WD_SUCCESS;
}

static int wd_join_gather_check_params(struct wd_join_gather_sess_setup *setup)
{
	int ret;

	if (!setup) {
		WD_ERR("invalid: hashjoin or gather sess setup is NULL!\n");
		return -WD_EINVAL;
	}

	switch (setup->alg) {
	case WD_JOIN:
		return wd_join_check_params(setup);
	case WD_GATHER:
		return wd_gather_check_params(setup);
	case WD_JOIN_GATHER:
		ret = wd_join_check_params(setup);
		if (ret)
			return ret;

		return wd_gather_check_params(setup);
	default:
		WD_ERR("invalid: hashjoin sess setup alg is wrong!\n");
		return -WD_EINVAL;
	}
}

static void sess_data_size_uninit(struct wd_join_gather_sess *sess)
{
	__u32 i;

	if (sess->join_conf.cols)
		free(sess->join_conf.cols);

	if (sess->gather_conf.tables) {
		for (i = 0; i < sess->gather_conf.table_num; i++)
			free(sess->gather_conf.data_size[i]);

		free(sess->gather_conf.tables);
	}
}

static int sess_data_size_init(struct wd_join_gather_sess *sess,
			       struct wd_join_gather_sess_setup *setup)
{
	struct wd_gather_table_info *gtable = setup->gather_tables;
	struct wd_join_table_info *jtable = &setup->join_table;
	struct wd_join_gather_col_info *key = jtable->build_key_cols;
	__u64 key_size, key_data_size, gather_size, gather_data_size;
	__u32 i, j;

	__atomic_store_n(&sess->state, WD_JOIN_SESS_UNINIT, __ATOMIC_RELEASE);

	if (setup->alg != WD_GATHER) {
		key_size = jtable->build_key_cols_num * sizeof(struct wd_join_gather_col_info);
		key_data_size = jtable->build_key_cols_num * sizeof(__u64);
		sess->join_conf.cols = malloc(key_size + key_data_size);
		if (!sess->join_conf.cols)
			return -WD_ENOMEM;
		memcpy(sess->join_conf.cols, key, key_size);

		sess->join_conf.data_size = (void *)sess->join_conf.cols + key_size;
		for (i = 0; i < jtable->build_key_cols_num; i++)
			(void)get_data_type_size(key[i].data_type, key[i].data_info,
						 sess->join_conf.data_size, i);
		sess->join_conf.cols_num = jtable->build_key_cols_num;

		if (setup->alg == WD_JOIN)
			return WD_SUCCESS;
	}

	gather_size = setup->gather_table_num * sizeof(struct wd_gather_table_info);
	gather_data_size = setup->gather_table_num * sizeof(__u64 *);
	sess->gather_conf.tables = malloc(gather_size + gather_data_size);
	if (!sess->gather_conf.tables)
		goto free_join;
	memcpy(sess->gather_conf.tables, gtable, gather_size);

	sess->gather_conf.data_size = (void *)sess->gather_conf.tables + gather_size;
	for (i = 0; i < setup->gather_table_num; i++) {
		sess->gather_conf.data_size[i] = malloc(gtable[i].cols_num * sizeof(__u64));
		if (!sess->gather_conf.data_size[i])
			goto free_gather;
	}

	for (i = 0; i < setup->gather_table_num; i++)
		for (j = 0; j < gtable[i].cols_num; j++)
			(void)get_data_type_size(gtable[i].cols[j].data_type,
						 gtable[i].cols[j].data_info,
						 sess->gather_conf.data_size[i], j);
	sess->gather_conf.table_num = setup->gather_table_num;

	return WD_SUCCESS;

free_gather:
	for (j = 0; j < i; j++)
		free(sess->gather_conf.data_size[j]);
	free(sess->gather_conf.tables);
free_join:
	if (setup->alg != WD_GATHER)
		free(sess->join_conf.cols);
	return -WD_ENOMEM;
}

static void wd_join_gather_uninit_sess(struct wd_join_gather_sess *sess)
{
	if (sess->gather_conf.batch_row_size)
		free(sess->gather_conf.batch_row_size);

	if (sess->ops.sess_uninit)
		sess->ops.sess_uninit(wd_join_gather_setting.driver, sess->priv);
}

static int wd_join_gather_init_sess(struct wd_join_gather_sess *sess,
				    struct wd_join_gather_sess_setup *setup)
{
	struct wd_alg_driver *drv = wd_join_gather_setting.driver;
	__u32 array_size;
	int ret;

	if (sess->ops.sess_init) {
		if (!sess->ops.sess_uninit) {
			WD_ERR("failed to get session uninit ops!\n");
			return -WD_EINVAL;
		}
		ret = sess->ops.sess_init(drv, setup, &sess->priv);
		if (ret) {
			WD_ERR("failed to init session priv!\n");
			return ret;
		}
	}

	if (sess->ops.get_table_row_size && setup->alg != WD_GATHER) {
		ret = sess->ops.get_table_row_size(drv, sess->priv);
		if (ret <= 0) {
			WD_ERR("failed to get hash table row size: %d!\n", ret);
			goto uninit;
		}
		sess->hash_table.table_row_size = ret;
	}

	if (sess->ops.get_batch_row_size && setup->alg != WD_JOIN) {
		array_size = setup->gather_table_num * sizeof(__u32);
		sess->gather_conf.batch_row_size = malloc(array_size);
		if (!sess->gather_conf.batch_row_size)
			goto uninit;

		ret = sess->ops.get_batch_row_size(drv, sess->priv,
						   sess->gather_conf.batch_row_size,
						   array_size);
		if (ret) {
			WD_ERR("failed to get batch table row size!\n");
			goto free_batch;
		}
	}

	return WD_SUCCESS;

free_batch:
	free(sess->gather_conf.batch_row_size);
uninit:
	if (sess->ops.sess_uninit)
		sess->ops.sess_uninit(drv, sess->priv);
	return -WD_EINVAL;
}

handle_t wd_join_gather_alloc_sess(struct wd_join_gather_sess_setup *setup)
{
	struct wd_join_gather_sess *sess;
	int ret;

	ret = wd_join_gather_check_params(setup);
	if (ret)
		return (handle_t)0;

	sess = malloc(sizeof(struct wd_join_gather_sess));
	if (!sess) {
		WD_ERR("failed to alloc join gather session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_join_gather_sess));

	sess->alg = setup->alg;
	sess->index_type = setup->index_type;
	sess->join_conf.key_output_enable = setup->join_table.key_output_enable;

	ret = wd_drv_alg_support(wd_join_gather_alg[sess->alg], wd_join_gather_setting.driver);
	if (!ret) {
		WD_ERR("failed to check driver alg: %s!\n", wd_join_gather_alg[sess->alg]);
		goto free_sess;
	}

	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_join_gather_setting.sched.sched_init(
		wd_join_gather_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init join_gather session schedule key!\n");
		goto free_sess;
	}

	if (wd_join_gather_setting.driver->get_extend_ops) {
		ret = wd_join_gather_setting.driver->get_extend_ops(&sess->ops);
		if (ret) {
			WD_ERR("failed to get join gather extend ops!\n");
			goto free_key;
		}
	}

	ret = wd_join_gather_init_sess(sess, setup);
	if (ret)
		goto free_key;

	ret = sess_data_size_init(sess, setup);
	if (ret) {
		WD_ERR("failed to init join gather session data size!\n");
		goto uninit_sess;
	}

	return (handle_t)sess;

uninit_sess:
	wd_join_gather_uninit_sess(sess);
free_key:
	free(sess->sched_key);
free_sess:
	free(sess);
	return (handle_t)0;
}

void wd_join_gather_free_sess(handle_t h_sess)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;

	if (!sess) {
		WD_ERR("invalid: join gather input sess is NULL!\n");
		return;
	}

	sess_data_size_uninit(sess);

	wd_join_gather_uninit_sess(sess);

	if (sess->sched_key)
		free(sess->sched_key);

	free(sess);
}

int wd_gather_get_batch_rowsize(handle_t h_sess, __u8 table_index)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;

	if (!sess || !sess->gather_conf.batch_row_size) {
		WD_ERR("invalid: gather sess or batch_row_size is NULL!\n");
		return -WD_EINVAL;
	}

	if (table_index >= sess->gather_conf.table_num) {
		WD_ERR("invalid: gather table index(%u) is larger than %u!\n",
		       table_index, sess->gather_conf.table_num);
		return -WD_EINVAL;
	}

	return sess->gather_conf.batch_row_size[table_index];
}

int wd_join_get_table_rowsize(handle_t h_sess)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;

	if (!sess) {
		WD_ERR("invalid: hashjoin input sess is NULL!\n");
		return -WD_EINVAL;
	}

	if (sess->alg != WD_JOIN && sess->alg != WD_JOIN_GATHER) {
		WD_ERR("invalid: the session is not used for hashjoin!\n");
		return -WD_EINVAL;
	}

	if (!sess->hash_table.table_row_size) {
		WD_ERR("invalid:  hashjoin sess hash table row size is 0!\n");
		return -WD_EINVAL;
	}

	return sess->hash_table.table_row_size;
}

static int wd_join_init_sess_state(struct wd_join_gather_sess *sess,
				   enum wd_join_sess_state *expected)
{
	enum wd_join_sess_state next;
	int ret;

	if (sess->hash_table.std_table) {
		*expected = WD_JOIN_SESS_BUILD_HASH;
		next = WD_JOIN_SESS_PREPARE_REHASH;
	} else {
		*expected = WD_JOIN_SESS_UNINIT;
		next = WD_JOIN_SESS_INIT;
	}

	ret = __atomic_compare_exchange_n(&sess->state, expected, next,
					  false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
	if (!ret) {
		WD_ERR("invalid: join sess state is %u!\n", *expected);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wd_join_set_hash_table(handle_t h_sess, struct wd_dae_hash_table *info)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	enum wd_join_sess_state expected;
	int ret;

	if (!sess || !info) {
		WD_ERR("invalid: hashjoin sess or hash table is NULL!\n");
		return -WD_EINVAL;
	}

	if (sess->alg != WD_JOIN && sess->alg != WD_JOIN_GATHER) {
		WD_ERR("invalid: the session is not used for hashjoin!\n");
		return -WD_EINVAL;
	}

	ret = wd_join_init_sess_state(sess, &expected);
	if (ret)
		return ret;

	if (info->table_row_size != sess->hash_table.table_row_size) {
		WD_ERR("invalid: hash table row size is not equal, expt: %u, real: %u!\n",
		       sess->hash_table.table_row_size, info->table_row_size);
		ret = -WD_EINVAL;
		goto out;
	}

	if (!info->std_table) {
		WD_ERR("invalid: standard hash table is NULL!\n");
		ret = -WD_EINVAL;
		goto out;
	}

	if (info->std_table_row_num < sess->hash_table.std_table_row_num) {
		WD_ERR("invalid: standard hash table is too small, expt: %u, real: %u!\n",
		       sess->hash_table.std_table_row_num, info->std_table_row_num);
		ret = -WD_EINVAL;
		goto out;
	}

	if (!info->ext_table_row_num || !info->ext_table)
		WD_INFO("info: extern hash table is NULL!\n");

	if (sess->ops.hash_table_init) {
		ret = sess->ops.hash_table_init(wd_join_gather_setting.driver,
						info, sess->priv);
		if (ret)
			goto out;
	}

	memcpy(&sess->hash_table, info, sizeof(struct wd_dae_hash_table));

	return WD_SUCCESS;

out:
	__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
	return ret;
}

static void wd_join_gather_clear_status(void)
{
	wd_alg_clear_init(&wd_join_gather_setting.status);
}

static int wd_join_gather_alg_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_JOIN_GATHER_EPOLL_EN", &wd_join_gather_setting.config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&wd_join_gather_setting.config, config);
	if (ret < 0)
		return ret;

	ret = wd_init_sched(&wd_join_gather_setting.sched, sched);
	if (ret < 0)
		goto out_clear_ctx_config;

	/* Allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_join_gather_setting.pool, config, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_join_gather_msg));
	if (ret < 0)
		goto out_clear_sched;

	ret = wd_alg_init_driver(&wd_join_gather_setting.config, wd_join_gather_setting.driver);
	if (ret)
		goto out_clear_pool;

	return WD_SUCCESS;

out_clear_pool:
	wd_uninit_async_request_pool(&wd_join_gather_setting.pool);
out_clear_sched:
	wd_clear_sched(&wd_join_gather_setting.sched);
out_clear_ctx_config:
	wd_clear_ctx_config(&wd_join_gather_setting.config);
	return ret;
}

static int wd_join_gather_alg_uninit(void)
{
	enum wd_status status;

	wd_alg_get_init(&wd_join_gather_setting.status, &status);
	if (status == WD_UNINIT)
		return -WD_EINVAL;

	/* Uninit async request pool */
	wd_uninit_async_request_pool(&wd_join_gather_setting.pool);

	/* Unset config, sched, driver */
	wd_clear_sched(&wd_join_gather_setting.sched);

	wd_alg_uninit_driver(&wd_join_gather_setting.config, wd_join_gather_setting.driver);

	return WD_SUCCESS;
}

int wd_join_gather_init(char *alg, __u32 sched_type, int task_type,
			struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_params join_gather_ctx_params = {0};
	struct wd_ctx_nums join_gather_ctx_num = {0};
	int ret = -WD_EINVAL;
	int state;
	bool flag;

	pthread_atfork(NULL, NULL, wd_join_gather_clear_status);

	state = wd_alg_try_init(&wd_join_gather_setting.status);
	if (state)
		return state;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	    task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: join_gathe init input param is wrong!\n");
		goto out_uninit;
	}

	flag = wd_join_gather_alg_check(alg);
	if (!flag) {
		WD_ERR("invalid: alg: %s is unsupported!\n", alg);
		goto out_uninit;
	}

	state = wd_join_gather_open_driver();
	if (state)
		goto out_uninit;

	while (ret != 0) {
		memset(&wd_join_gather_setting.config, 0, sizeof(struct wd_ctx_config_internal));

		/* Get alg driver and dev name */
		wd_join_gather_setting.driver = wd_alg_drv_bind(task_type, alg);
		if (!wd_join_gather_setting.driver) {
			WD_ERR("failed to bind %s driver.\n", alg);
			goto out_dlopen;
		}

		join_gather_ctx_params.ctx_set_num = &join_gather_ctx_num;
		ret = wd_ctx_param_init(&join_gather_ctx_params, ctx_params,
					wd_join_gather_setting.driver,
					WD_JOIN_GATHER_TYPE, 1);
		if (ret) {
			if (ret == -WD_EAGAIN) {
				wd_disable_drv(wd_join_gather_setting.driver);
				wd_alg_drv_unbind(wd_join_gather_setting.driver);
				continue;
			}
			goto out_driver;
		}

		(void)strcpy(wd_join_gather_init_attrs.alg, alg);
		wd_join_gather_init_attrs.sched_type = sched_type;
		wd_join_gather_init_attrs.driver = wd_join_gather_setting.driver;
		wd_join_gather_init_attrs.ctx_params = &join_gather_ctx_params;
		wd_join_gather_init_attrs.alg_init = wd_join_gather_alg_init;
		wd_join_gather_init_attrs.alg_poll_ctx = wd_join_gather_poll_ctx;
		ret = wd_alg_attrs_init(&wd_join_gather_init_attrs);
		if (ret) {
			if (ret == -WD_ENODEV) {
				wd_disable_drv(wd_join_gather_setting.driver);
				wd_alg_drv_unbind(wd_join_gather_setting.driver);
				wd_ctx_param_uninit(&join_gather_ctx_params);
				continue;
			}
			WD_ERR("fail to init alg attrs.\n");
			goto out_params_uninit;
		}
	}

	wd_alg_set_init(&wd_join_gather_setting.status);
	wd_ctx_param_uninit(&join_gather_ctx_params);

	return WD_SUCCESS;

out_params_uninit:
	wd_ctx_param_uninit(&join_gather_ctx_params);
out_driver:
	wd_alg_drv_unbind(wd_join_gather_setting.driver);
out_dlopen:
	wd_join_gather_close_driver();
out_uninit:
	wd_alg_clear_init(&wd_join_gather_setting.status);
	return ret;
}

void wd_join_gather_uninit(void)
{
	int ret;

	ret = wd_join_gather_alg_uninit();
	if (ret)
		return;

	wd_alg_attrs_uninit(&wd_join_gather_init_attrs);
	wd_alg_drv_unbind(wd_join_gather_setting.driver);
	wd_join_gather_close_driver();
	wd_alg_clear_init(&wd_join_gather_setting.status);
}

static void fill_build_hash_msg(struct wd_join_gather_msg *msg,
				struct wd_join_gather_sess *sess)
{
	msg->index_type = sess->index_type;
	msg->key_cols_num = sess->join_conf.cols_num;
}

static void fill_probe_msg(struct wd_join_gather_msg *msg,
			   struct wd_join_gather_sess *sess)
{
	msg->key_cols_num = sess->join_conf.cols_num;
	msg->index_type = sess->index_type;
	msg->key_out_en = sess->join_conf.key_output_enable;
}

static void fill_rehash_msg(struct wd_join_gather_msg *msg,
			    struct wd_join_gather_sess *sess)
{
	msg->key_cols_num = sess->join_conf.cols_num;
}

static void fill_complete_msg(struct wd_join_gather_msg *msg,
			      struct wd_join_gather_sess *sess)
{
	__u32 table_index = msg->req.gather_req.table_index;

	msg->index_type = sess->index_type;
	msg->multi_batch_en = sess->gather_conf.tables[table_index].is_multi_batch;
}


static void fill_join_gather_msg(struct wd_join_gather_msg *msg, struct wd_join_gather_req *req,
				 struct wd_join_gather_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_join_gather_req));
	msg->priv = sess->priv;
	msg->op_type = req->op_type;

	switch (req->op_type) {
	case WD_JOIN_BUILD_HASH:
		fill_build_hash_msg(msg, sess);
		break;
	case WD_JOIN_PROBE:
		fill_probe_msg(msg, sess);
		break;
	case WD_JOIN_REHASH:
		fill_rehash_msg(msg, sess);
		break;
	case WD_GATHER_CONVERT:
		break;
	case WD_GATHER_COMPLETE:
		fill_complete_msg(msg, sess);
		break;
	default:
		break;
	}
}

static int wd_join_gather_check_common(struct wd_join_gather_sess *sess,
				       struct wd_join_gather_req *req,
				       __u8 mode, bool is_join)
{
	if (!sess) {
		WD_ERR("invalid: join or gather session is NULL!\n");
		return -WD_EINVAL;
	}

	if (!req) {
		WD_ERR("invalid: join input req is NULL!\n");
		return -WD_EINVAL;
	}

	if (mode == CTX_MODE_ASYNC && !req->cb) {
		WD_ERR("invalid: join gather req cb is NULL!\n");
		return -WD_EINVAL;
	}

	switch (sess->alg) {
	case WD_JOIN:
		if (!is_join || !sess->join_conf.data_size) {
			WD_ERR("invalid: join session data size is NULL!\n");
			return -WD_EINVAL;
		}
		break;
	case WD_GATHER:
		if (is_join || !sess->gather_conf.data_size) {
			WD_ERR("invalid: gather session data size is NULL!\n");
			return -WD_EINVAL;
		}
		break;
	case WD_JOIN_GATHER:
		if (mode == CTX_MODE_ASYNC) {
			WD_ERR("join-gather session does not support the async mode!\n");
			return -WD_EINVAL;
		}

		if (!sess->join_conf.data_size || !sess->gather_conf.data_size) {
			WD_ERR("invalid: join or gather session data size is NULL!\n");
			return -WD_EINVAL;
		}
		break;
	default:
		WD_ERR("invalid: session alg is not supported!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int check_in_col_addr(struct wd_dae_col_addr *col, __u32 row_count,
			     enum wd_dae_data_type type, __u64 data_size)
{
	if (!col->empty || col->empty_size != row_count * sizeof(col->empty[0])) {
		WD_ERR("failed to check input empty col, size: %llu!\n", col->empty_size);
		return -WD_EINVAL;
	}

	if (!col->value || col->value_size != row_count * data_size) {
		WD_ERR("failed to check input value col size: %llu!\n", col->value_size);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int check_out_col_addr(struct wd_dae_col_addr *col, __u32 row_count,
			      enum wd_dae_data_type type, __u64 data_size)
{
	if (!col->empty || col->empty_size < row_count * sizeof(col->empty[0])) {
		WD_ERR("failed to check output empty col, size: %llu!\n", col->empty_size);
		return -WD_EINVAL;
	}

	if (!col->value || col->value_size < row_count * data_size) {
		WD_ERR("failed to check output value col size: %llu!\n", col->value_size);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int check_key_col_addr(struct wd_dae_col_addr *cols, __u32 cols_num,
			      struct wd_join_gather_sess *sess, __u32 row_count, bool is_input)
{
	int (*func)(struct wd_dae_col_addr *col, __u32 row_count,
		    enum wd_dae_data_type type, __u64 data_size);
	__u32 i;
	int ret;

	func = is_input ? check_in_col_addr : check_out_col_addr;

	for (i = 0; i < cols_num; i++) {
		ret = func(cols + i, row_count, sess->join_conf.cols[i].data_type,
			   sess->join_conf.data_size[i]);
		if (ret) {
			WD_ERR("failed to check req key col! col idx: %u\n", i);
			return ret;
		}
	}

	return WD_SUCCESS;
}

static int check_data_col_addr(struct wd_gather_req *req, struct wd_join_gather_sess *sess,
			       __u32 row_count, bool is_input)
{
	struct wd_gather_table_info *table = &sess->gather_conf.tables[req->table_index];
	__u64 *data_size = sess->gather_conf.data_size[req->table_index];
	int (*func)(struct wd_dae_col_addr *col, __u32 row_count,
		    enum wd_dae_data_type type, __u64 data_size);
	__u32 i;
	int ret;

	if (!data_size) {
		WD_ERR("invalid: gather session data size is NULL!\n");
		return -WD_EINVAL;
	}

	if (!row_count) {
		WD_ERR("invalid: gather data row number is 0!\n");
		return -WD_EINVAL;
	}

	func = is_input ? check_in_col_addr : check_out_col_addr;

	for (i = 0; i < req->data_cols_num; i++) {
		ret = func(&req->data_cols[i], row_count, table->cols[i].data_type,
			   data_size[i]);
		if (ret) {
			WD_ERR("failed to check req data col! col idx: %u\n", i);
			return ret;
		}
	}

	return WD_SUCCESS;
}

static int check_probe_out_addr(struct wd_probe_out_info *output,
				struct wd_join_gather_sess *sess, __u32 row_num)
{
	if (!output->build_index.addr || !output->build_index.row_size) {
		WD_ERR("probe multi index is not set!\n");
		return -WD_EINVAL;
	}

	if (!output->probe_index.addr || !output->probe_index.row_size) {
		WD_ERR("probe single index is not set!\n");
		return -WD_EINVAL;
	}

	if (output->build_index.row_num < row_num || output->probe_index.row_num < row_num) {
		WD_ERR("build: %u, probe: %u, row num is less than output row_num: %u!\n",
		       output->build_index.row_num, output->probe_index.row_num, row_num);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_join_common_check_req(struct wd_join_gather_sess *sess,
				    struct wd_join_gather_req *req)
{
	struct wd_join_req *join_req = &req->join_req;
	int ret;

	if (join_req->key_cols_num != sess->join_conf.cols_num) {
		WD_ERR("invalid: join table key_cols_num is not equal!\n");
		return -WD_EINVAL;
	}

	if (!join_req->key_cols) {
		WD_ERR("invalid: join table key_cols is NULL!\n");
		return -WD_EINVAL;
	}

	if (!req->input_row_num) {
		WD_ERR("invalid: join table input row number is zero!\n");
		return -WD_EINVAL;
	}

	ret = check_key_col_addr(join_req->key_cols, join_req->key_cols_num, sess,
				 req->input_row_num, true);
	if (ret) {
		WD_ERR("failed to check join table key cols addr!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_build_hash_check_params(struct wd_join_gather_sess *sess,
				      struct wd_join_gather_req *req, __u8 mode)
{
	int ret;

	ret = wd_join_gather_check_common(sess, req, mode, true);
	if (ret)
		return ret;

	if (req->op_type != WD_JOIN_BUILD_HASH) {
		WD_ERR("failed to check req op_type for build hash task!\n");
		return -WD_EINVAL;
	}

	ret = wd_join_common_check_req(sess, req);
	if (ret)
		WD_ERR("failed to check join req for build hash task!\n");

	return ret;
}

static int wd_join_probe_check_req(struct wd_join_gather_sess *sess,
				   struct wd_join_gather_req *req)
{
	struct wd_join_req *jreq = &req->join_req;
	struct wd_probe_out_info *probe_output = &jreq->probe_output;
	int ret;

	if (req->op_type != WD_JOIN_PROBE) {
		WD_ERR("failed to check req op_type for probe task!\n");
		return -WD_EINVAL;
	}

	ret = wd_join_common_check_req(sess, req);
	if (ret) {
		WD_ERR("failed to check join req for probe task!\n");
		return ret;
	}

	if (!req->output_row_num) {
		WD_ERR("probe output row number is zero!\n");
		return -WD_EINVAL;
	}

	if (sess->join_conf.key_output_enable) {
		if (probe_output->key_cols_num != sess->join_conf.cols_num ||
		    !probe_output->key_cols) {
			WD_ERR("invalid: probe out key_cols_num is not equal!\n");
			return -WD_EINVAL;
		}
		ret = check_key_col_addr(probe_output->key_cols, probe_output->key_cols_num,
					 sess, req->output_row_num, false);
		if (ret) {
			WD_ERR("failed to check porbe output key cols addr!\n");
			return -WD_EINVAL;
		}
	}

	ret = check_probe_out_addr(probe_output, sess, req->output_row_num);
	if (ret) {
		WD_ERR("failed to check porbe output addr!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_join_probe_check_params(struct wd_join_gather_sess *sess,
				      struct wd_join_gather_req *req, __u8 mode)
{
	int ret;

	ret = wd_join_gather_check_common(sess, req, mode, true);
	if (ret)
		return ret;

	return wd_join_probe_check_req(sess, req);
}

static int wd_join_rehash_check_params(struct wd_join_gather_sess *sess,
				       struct wd_join_gather_req *req)
{
	int ret;

	ret = wd_join_gather_check_common(sess, req, CTX_MODE_SYNC, true);
	if (ret)
		return ret;

	if (req->op_type != WD_JOIN_REHASH) {
		WD_ERR("failed to check req op_type for rehash task!\n");
		return -WD_EINVAL;
	}

	if (!req->output_row_num) {
		WD_ERR("invalid: req output_row_num is 0 for join rehash!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_join_gather_sync_job(struct wd_join_gather_sess *sess,
				   struct wd_join_gather_req *req,
				   struct wd_join_gather_msg *msg)
{
	struct wd_join_gather_setting *setting = &wd_join_gather_setting;
	struct wd_ctx_config_internal *config = &setting->config;
	struct wd_msg_handle msg_handle;
	struct wd_ctx_internal *ctx;
	__u32 idx;
	int ret;

	memset(msg, 0, sizeof(struct wd_join_gather_msg));
	fill_join_gather_msg(msg, req, sess);
	req->state = 0;

	idx = setting->sched.pick_next_ctx(setting->sched.h_sched_ctx,
					   sess->sched_key, CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	msg_handle.send = setting->driver->send;
	msg_handle.recv = setting->driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(setting->driver, &msg_handle, ctx->ctx,
				 msg, NULL, config->epoll_en);
	pthread_spin_unlock(&ctx->lock);

	return ret;
}

static int wd_build_hash_try_init(struct wd_join_gather_sess *sess,
				  enum wd_join_sess_state *expected)
{
	enum wd_join_sess_state state;

	(void)__atomic_compare_exchange_n(&sess->state, expected, WD_JOIN_SESS_BUILD_HASH,
					  false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
	state = __atomic_load_n(&sess->state, __ATOMIC_RELAXED);
	if (state != WD_JOIN_SESS_BUILD_HASH) {
		WD_ERR("failed to set join sess state: %u!\n", state);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_join_gather_check_result(__u32 result)
{
	switch (result) {
	case WD_JOIN_GATHER_TASK_DONE:
		return WD_SUCCESS;
	case WD_JOIN_GATHER_IN_EPARA:
	case WD_JOIN_GATHER_NEED_REHASH:
	case WD_JOIN_GATHER_INVALID_HASH_TABLE:
	case WD_JOIN_GATHER_PARSE_ERROR:
	case WD_JOIN_GATHER_BUS_ERROR:
		WD_ERR("failed to check join gather message state: %u!\n", result);
		return -WD_EIO;
	default:
		return -WD_EINVAL;
	}
}

int wd_join_build_hash_sync(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	enum wd_join_sess_state expected = WD_JOIN_SESS_INIT;
	struct wd_join_gather_msg msg;
	int ret;

	ret = wd_build_hash_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check hashjoin build hash params!\n");
		return ret;
	}

	ret = wd_build_hash_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	ret = wd_join_gather_sync_job(sess, req, &msg);
	if (unlikely(ret)) {
		if (expected == WD_JOIN_SESS_INIT)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do hashjoin build hash sync job!\n");
		return ret;
	}

	req->consumed_row_num = msg.consumed_row_num;
	req->state = msg.result;

	return WD_SUCCESS;
}

static int wd_join_gather_async_job(struct wd_join_gather_sess *sess,
				    struct wd_join_gather_req *req)
{
	struct wd_join_gather_setting *setting = &wd_join_gather_setting;
	struct wd_ctx_config_internal *config = &setting->config;
	struct wd_join_gather_msg *msg;
	struct wd_ctx_internal *ctx;
	int msg_id, ret;
	__u32 idx;

	idx = setting->sched.pick_next_ctx(setting->sched.h_sched_ctx,
					   sess->sched_key, CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;
	msg_id = wd_get_msg_from_pool(&setting->pool, idx, (void **)&msg);
	if (msg_id < 0) {
		WD_ERR("failed to get join gather msg from pool!\n");
		return msg_id;
	}

	fill_join_gather_msg(msg, req, sess);
	msg->tag = msg_id;
	ret = wd_alg_driver_send(setting->driver, ctx->ctx, msg);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("wd join gather async send err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);

	return WD_SUCCESS;

fail_with_msg:
	wd_put_msg_to_pool(&setting->pool, idx, msg->tag);
	return ret;
}

int wd_join_build_hash_async(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	enum wd_join_sess_state expected = WD_JOIN_SESS_INIT;
	int ret;

	ret = wd_build_hash_check_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check build hash async params!\n");
		return ret;
	}

	ret = wd_build_hash_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	ret = wd_join_gather_async_job(sess, req);
	if (unlikely(ret)) {
		if (expected == WD_JOIN_SESS_INIT)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do join build hash async job!\n");
	}

	return ret;
}

static int wd_join_probe_try_init(struct wd_join_gather_sess *sess,
				  enum wd_join_sess_state *expected)
{
	enum wd_join_sess_state state;

	(void)__atomic_compare_exchange_n(&sess->state, expected, WD_JOIN_SESS_PROBE,
					  false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
	state = __atomic_load_n(&sess->state, __ATOMIC_RELAXED);
	if (state != WD_JOIN_SESS_PROBE) {
		WD_ERR("failed to set join sess state: %u!\n", state);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wd_join_probe_sync(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	enum wd_join_sess_state expected = WD_JOIN_SESS_BUILD_HASH;
	struct wd_join_gather_msg msg;
	int ret;

	ret = wd_join_probe_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check join probe params!\n");
		return ret;
	}

	ret = wd_join_probe_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	ret = wd_join_gather_sync_job(sess, req, &msg);
	if (unlikely(ret)) {
		if (expected == WD_JOIN_SESS_BUILD_HASH)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do join probe sync job!\n");
		return ret;
	}

	req->consumed_row_num = msg.consumed_row_num;
	req->produced_row_num = msg.produced_row_num;
	req->output_done = msg.output_done;
	req->state = msg.result;

	return WD_SUCCESS;
}

int wd_join_probe_async(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	enum wd_join_sess_state expected = WD_JOIN_SESS_BUILD_HASH;
	int ret;

	ret = wd_join_probe_check_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check join probe params!\n");
		return ret;
	}

	ret = wd_join_probe_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	ret = wd_join_gather_async_job(sess, req);
	if (unlikely(ret)) {
		if (expected == WD_JOIN_SESS_BUILD_HASH)
			__atomic_store_n(&sess->state, expected, __ATOMIC_RELEASE);
		WD_ERR("failed to do join probe async job!\n");
	}

	return ret;
}

static int wd_join_rehash_sync_inner(struct wd_join_gather_sess *sess,
				     struct wd_join_gather_req *req)
{
	struct wd_join_gather_msg msg = {0};
	int ret;

	ret = wd_join_gather_sync_job(sess, req, &msg);
	if (ret)
		return ret;

	ret = wd_join_gather_check_result(msg.result);
	if (ret)
		return ret;

	req->output_done = msg.output_done;

	return WD_SUCCESS;
}

static int wd_join_rehash_try_init(struct wd_join_gather_sess *sess,
				   enum wd_join_sess_state *expected)
{
	int ret;

	ret = __atomic_compare_exchange_n(&sess->state, expected, WD_JOIN_SESS_REHASH,
					  false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
	if (!ret) {
		WD_ERR("invalid: join rehash sess state is %u!\n", *expected);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wd_join_rehash_sync(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	enum wd_join_sess_state expected = WD_JOIN_SESS_PREPARE_REHASH;
	__u64 max_cnt, cnt = 0;
	int ret;

	ret = wd_join_rehash_check_params(sess, req);
	if (unlikely(ret)) {
		WD_ERR("failed to check join rehash params!\n");
		return ret;
	}

	ret = wd_join_rehash_try_init(sess, &expected);
	if (unlikely(ret))
		return ret;

	max_cnt = MAX_HASH_TABLE_ROW_NUM / req->output_row_num;
	while (cnt < max_cnt) {
		ret = wd_join_rehash_sync_inner(sess, req);
		if (unlikely(ret)) {
			__atomic_store_n(&sess->state, WD_JOIN_SESS_PREPARE_REHASH,
					 __ATOMIC_RELEASE);
			WD_ERR("failed to do join rehash task!\n");
			return ret;
		}
		if (req->output_done)
			break;
		cnt++;
	}

	__atomic_store_n(&sess->state, WD_JOIN_SESS_BUILD_HASH, __ATOMIC_RELEASE);
	return WD_SUCCESS;
}

static int wd_gather_common_check_req(struct wd_join_gather_sess *sess,
				      struct wd_join_gather_req *req)
{
	struct wd_gather_req *gather_req = &req->gather_req;
	struct wd_gather_table_info *tables;
	__u32 table_index;

	if (!sess->gather_conf.tables) {
		WD_ERR("invalid: session gather tables is NULL!\n");
		return -WD_EINVAL;
	}
	tables = sess->gather_conf.tables;
	table_index = gather_req->table_index;

	if (table_index >= sess->gather_conf.table_num) {
		WD_ERR("invalid: gather table index(%u) is too big!\n", table_index);
		return -WD_EINVAL;
	}

	if (gather_req->data_cols_num != tables[table_index].cols_num) {
		WD_ERR("invalid: gather table data_cols_num is not equal!\n");
		return -WD_EINVAL;
	}

	if (!gather_req->data_cols) {
		WD_ERR("invalid: gather table data_cols is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_gather_convert_check_req(struct wd_join_gather_sess *sess,
				       struct wd_join_gather_req *req)
{
	struct wd_gather_req *gather_req = &req->gather_req;
	__u32 expt_size, table_index;
	int ret;

	if (req->op_type != WD_GATHER_CONVERT) {
		WD_ERR("failed to check req op_type for gather convert task!\n");
		return -WD_EINVAL;
	}

	ret = wd_gather_common_check_req(sess, req);
	if (ret)
		return ret;

	table_index = gather_req->table_index;

	ret = check_data_col_addr(gather_req, sess, req->input_row_num, true);
	if (ret) {
		WD_ERR("failed to check gather convert data cols addr!\n");
		return -WD_EINVAL;
	}

	if (gather_req->row_batchs.batch_num != 1 || !gather_req->row_batchs.batch_addr ||
	    !gather_req->row_batchs.batch_addr[0]) {
		WD_ERR("invalid: gather convert only support one batch!\n");
		return -WD_EINVAL;
	}

	if (!gather_req->row_batchs.batch_row_num || !gather_req->row_batchs.batch_row_size) {
		WD_ERR("invalid: gather convert batchs row_num or row_size is NULL!\n");
		return -WD_EINVAL;
	}

	expt_size = sess->gather_conf.batch_row_size[table_index];
	if (gather_req->row_batchs.batch_row_num[0] != req->input_row_num ||
	    gather_req->row_batchs.batch_row_size[0] != expt_size) {
		WD_ERR("invalid: gather convert row batchs, row_size: %u, row_num: %u\n",
		       gather_req->row_batchs.batch_row_size[0],
		       gather_req->row_batchs.batch_row_num[0]);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_gather_complete_check_req(struct wd_join_gather_sess *sess,
					struct wd_join_gather_req *req)
{
	struct wd_gather_req *gather_req = &req->gather_req;
	struct wd_gather_table_info *tables;
	struct wd_dae_row_addr *index_addr;
	__u32 table_index, expt_size, i;
	int ret;

	if (req->op_type != WD_GATHER_COMPLETE) {
		WD_ERR("failed to check req op_type for gather complete task!\n");
		return -WD_EINVAL;
	}

	ret = wd_gather_common_check_req(sess, req);
	if (ret)
		return ret;

	tables = sess->gather_conf.tables;
	table_index = gather_req->table_index;

	ret = check_data_col_addr(gather_req, sess, req->output_row_num, false);
	if (ret) {
		WD_ERR("failed to check gather complete data cols addr!\n");
		return -WD_EINVAL;
	}

	index_addr = &gather_req->index;
	if (!index_addr->addr || index_addr->row_num < req->output_row_num) {
		WD_ERR("invalid: gather index is NULL or index row number is small!\n");
		return -WD_EINVAL;
	}

	/* The row batch information is stored to index, no need to check. */
	if (sess->index_type == WD_BATCH_ADDR_INDEX && tables[table_index].is_multi_batch)
		return WD_SUCCESS;

	if (!gather_req->row_batchs.batch_num || !gather_req->row_batchs.batch_addr) {
		WD_ERR("invalid: gather row batch is NULL or batch addr number is 0!\n");
		return -WD_EINVAL;
	}

	if (!gather_req->row_batchs.batch_row_num || !gather_req->row_batchs.batch_row_size) {
		WD_ERR("invalid: gather row batch row_num or row_size is NULL!\n");
		return -WD_EINVAL;
	}

	if (!tables[table_index].is_multi_batch) {
		if (gather_req->row_batchs.batch_num != 1) {
			WD_ERR("invalid: single gather row batch addr num should be 1!\n");
			return -WD_EINVAL;
		}
	}

	for (i = 0; i < gather_req->row_batchs.batch_num; i++) {
		if (!gather_req->row_batchs.batch_addr[i] ||
		    !gather_req->row_batchs.batch_row_num[i]) {
			WD_ERR("invalid: row batch addr or row_num is null! idx: %u\n", i);
			return -WD_EINVAL;
		}
		expt_size = sess->gather_conf.batch_row_size[table_index];
		if (gather_req->row_batchs.batch_row_size[i] != expt_size) {
			WD_ERR("invalid row batch row_size: %u, batch idx: %u\n",
			       gather_req->row_batchs.batch_row_size[i], i);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int wd_gather_convert_check_params(struct wd_join_gather_sess *sess,
					  struct wd_join_gather_req *req, __u8 mode)
{
	int ret;

	ret = wd_join_gather_check_common(sess, req, mode, false);
	if (ret)
		return ret;

	return wd_gather_convert_check_req(sess, req);
}

static int wd_gather_complete_check_params(struct wd_join_gather_sess *sess,
					   struct wd_join_gather_req *req, __u8 mode)
{
	int ret;

	ret = wd_join_gather_check_common(sess, req, mode, false);
	if (ret)
		return ret;

	return wd_gather_complete_check_req(sess, req);
}

int wd_gather_convert_sync(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	struct wd_join_gather_msg msg;
	int ret;

	ret = wd_gather_convert_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check gather convert params!\n");
		return ret;
	}

	ret = wd_join_gather_sync_job(sess, req, &msg);
	if (unlikely(ret)) {
		WD_ERR("failed to do gather convert sync job!\n");
		return ret;
	}

	req->consumed_row_num = msg.consumed_row_num;
	req->state = msg.result;

	return WD_SUCCESS;
}

int wd_gather_convert_async(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	int ret;

	ret = wd_gather_convert_check_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check gather convert async params!\n");
		return ret;
	}

	ret = wd_join_gather_async_job(sess, req);
	if (unlikely(ret))
		WD_ERR("failed to do gather convert async job!\n");

	return ret;
}

int wd_gather_complete_sync(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	struct wd_join_gather_msg msg;
	int ret;

	ret = wd_gather_complete_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check gather complete params!\n");
		return ret;
	}

	ret = wd_join_gather_sync_job(sess, req, &msg);
	if (unlikely(ret)) {
		WD_ERR("failed to do gather complete sync job!\n");
		return ret;
	}

	req->produced_row_num = msg.produced_row_num;
	req->state = msg.result;

	return WD_SUCCESS;
}

int wd_gather_complete_async(handle_t h_sess, struct wd_join_gather_req *req)
{
	struct wd_join_gather_sess *sess = (struct wd_join_gather_sess *)h_sess;
	int ret;

	ret = wd_gather_complete_check_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check gather complete params!\n");
		return ret;
	}

	ret = wd_join_gather_async_job(sess, req);
	if (unlikely(ret))
		WD_ERR("failed to do gather complete async job!\n");

	return ret;
}

struct wd_join_gather_msg *wd_join_gather_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_join_gather_setting.pool, idx, tag);
}

static int wd_join_gather_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_join_gather_setting.config;
	struct wd_join_gather_msg resp_msg = {0};
	struct wd_join_gather_msg *msg;
	struct wd_ctx_internal *ctx;
	struct wd_join_gather_req *req;
	__u64 recv_count = 0;
	__u32 tmp = expt;
	int ret;

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (unlikely(ret))
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_alg_driver_recv(wd_join_gather_setting.driver, ctx->ctx, &resp_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("wd join_gather recv hw err!\n");
			return ret;
		}
		recv_count++;
		msg = wd_find_msg_in_pool(&wd_join_gather_setting.pool, idx, resp_msg.tag);
		if (!msg) {
			WD_ERR("failed to get join gather msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->req.state = resp_msg.result;
		msg->req.consumed_row_num = resp_msg.consumed_row_num;
		msg->req.produced_row_num = resp_msg.produced_row_num;
		msg->req.output_done = resp_msg.output_done;
		req = &msg->req;

		req->cb(req, req->cb_param);
		/* Free msg cache to msg_pool */
		wd_put_msg_to_pool(&wd_join_gather_setting.pool, idx, resp_msg.tag);
		*count = recv_count;
	} while (--tmp);

	return ret;
}

int wd_join_gather_poll(__u32 expt, __u32 *count)
{
	handle_t h_ctx = wd_join_gather_setting.sched.h_sched_ctx;
	struct wd_sched *sched = &wd_join_gather_setting.sched;

	if (!expt || !count) {
		WD_ERR("invalid: join gather poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	return sched->poll_policy(h_ctx, expt, count);
}
