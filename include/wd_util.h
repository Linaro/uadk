// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef __WD_UTIL_H
#define __WD_UTIL_H

#include <numa.h>
#include <stdbool.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <asm/types.h>

#include "wd.h"
#include "wd_sched.h"
#include "wd_alg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WD_POOL_MAX_ENTRIES    1024

#define FOREACH_NUMA(i, config, config_numa) \
	for ((i) = 0, (config_numa) = (config)->config_per_numa; \
	     (i) < (config)->numa_num; (config_numa)++, (i)++)

enum wd_status {
	WD_UNINIT,
	WD_INITING,
	WD_INIT,
};

enum wd_type {
	WD_COMP_TYPE = 0,
	WD_CIPHER_TYPE,
	WD_DIGEST_TYPE,
	WD_AEAD_TYPE,
	WD_RSA_TYPE,
	WD_DH_TYPE,
	WD_ECC_TYPE,
	WD_TYPE_MAX,
};

struct wd_async_msg_pool {
	struct msg_pool *pools;
	__u32 pool_num;
};

struct wd_ctx_range {
	__u32 begin;
	__u32 end;
	__u32 size;
};

struct wd_env_config_per_numa {
	/* Config begin */
	int node;
	__u32 sync_ctx_num;
	__u32 async_ctx_num;

	/*
	 * +---------+-----------------+---------------+
	 * |         |       sync      |      async    |
	 * +---------+-----------------+---------------+
	 * | op_type |  begine    end  |  begin    end |
	 * |         |                 |               |
	 *   ...
	 */
	__u8 op_type_num;
	struct wd_ctx_range **ctx_table;

	/* Resource begin */
	struct uacce_dev *dev;
	int dev_num;
	/* This can be made statically currently */
	unsigned long async_poll_num;
	void *async_task_queue_array;
};

struct wd_env_config {
	struct wd_env_config_per_numa *config_per_numa;
	/* Let's make it as a gobal config, not per numa */
	bool enable_internal_poll;

	/* resource config */
	struct wd_sched *sched;
	bool internal_sched;
	struct wd_ctx_config *ctx_config;
	const struct wd_config_variable *table;
	__u32 table_size;
	__u16 numa_num;
	__u8 op_type_num;
};

struct wd_config_variable {
	const char *name;
	char *def_val;
	int (*parse_fn)(struct wd_env_config *, const char *);
};

struct wd_alg_ops {
	char *alg_name;
	__u8 op_type_num;
	int (*alg_init)(struct wd_ctx_config *, struct wd_sched *);
	void (*alg_uninit)(void);
	int (*alg_poll_ctx)(__u32, __u32, __u32 *);
};

struct wd_ctx_attr {
	__u32 node;
	__u32 type;
	__u32 num;
	__u8 mode;
};

struct op_ctx {
	handle_t ctx;
	__u32 ctx_id;
	__u8 mode;
};

struct wd_msg_handle {
	int (*send)(struct wd_alg_driver *drv, handle_t ctx, void *drv_msg);
	int (*recv)(struct wd_alg_driver *drv, handle_t ctx, void *drv_msg);
};

struct wd_init_attrs {
	__u32 sched_type;
	char *alg;
	struct wd_alg_driver *driver;
	struct wd_sched *sched;
	struct wd_ctx_params *ctx_params;
	struct wd_ctx_config *ctx_config;
	wd_alg_init alg_init;
	wd_alg_poll_ctx alg_poll_ctx;
};

/*
 * wd_init_ctx_config() - Init internal ctx configuration.
 * @in:	ctx configuration in global setting.
 * @cfg: ctx configuration input by user.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_init_ctx_config(struct wd_ctx_config_internal *in,
		       struct wd_ctx_config *cfg);

/*
 * wd_init_sched() - Init internal scheduler configuration.
 * @in: Scheduler configuration in global setting.
 * @from: Scheduler configuration input by user.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_init_sched(struct wd_sched *in, struct wd_sched *from);

/*
 * wd_clear_sched() - Clear internal scheduler configuration.
 * @in: Scheduler configuration in global setting.
 */
void wd_clear_sched(struct wd_sched *in);

/*
 * wd_clear_ctx_config() - Clear internal ctx configuration.
 * @in: ctx configuration in global setting.
 */
void wd_clear_ctx_config(struct wd_ctx_config_internal *in);

/*
 * wd_memset_zero() - memset the data to zero.
 * @data: the data memory addr.
 * @size: the data length.
 */
void wd_memset_zero(void *data, __u32 size);

/*
 * wd_init_async_request_pool() - Init async message pools.
 * @pool: Pointer of message pool.
 * @config: ctx configuration input by user.
 * @msg_num: Message entry number in one pool.
 * @msg_size: Size of each message entry.
 *
 * Return 0 if successful or less than 0 otherwise.
 *
 * pool
 *   pools
 *         +-------+-------+----+-------+ -+-
 *         | msg_0 | msg_1 |... | n - 1 |  |
 *         +-------+-------+----+-------+
 *         ...                             pool_num
 *         +-------+-------+----+-------+
 *         | msg_0 | msg_1 |... | n - 1 |  |
 *         +-------+-------+----+-------+ -+-
 *         |<------- msg_num ---------->|
 */
int wd_init_async_request_pool(struct wd_async_msg_pool *pool,
			       struct wd_ctx_config *config,
			       __u32 msg_num, __u32 msg_size);

/*
 * wd_uninit_async_request_pool() - Uninit message pools.
 * @pool: Pool which will be uninit.
 */
void wd_uninit_async_request_pool(struct wd_async_msg_pool *pool);

/*
 * wd_get_msg_from_pool() - Get a free message from pool.
 * @pool: Pointer of global pools.
 * @ctx_idx: Index of pool. Should be 0 ~ (pool_num - 1).
 * @msg: Put pointer of got message into *msg.
 *
 * Return tag of got message. This tag can be used to put a message and
 * find a message in wd_put_msg_to_pool() and wd_find_msg_in_pool(). Returned
 * tag will be in 1 ~ msg_num indicating msg_0 ~ msg_n-1; tag value 0 will NOT
 * be used to avoid possible error; -WD_EBUSY will return if related message pool
 * is full.
 */
int wd_get_msg_from_pool(struct wd_async_msg_pool *pool, int ctx_idx,
			 void **msg);

/*
 * wd_put_msg_to_pool() - Put a message to pool.
 * @pool: Pointer of global pools.
 * @ctx_idx: Index of pool. Should be 0 ~ (pool_num - 1).
 * @tag: Tag of put message.
 */
void wd_put_msg_to_pool(struct wd_async_msg_pool *pool, int ctx_idx,
			__u32 tag);

/*
 * wd_find_msg_in_pool() - Find a message in pool.
 * @pool: Pointer of global pools.
 * @ctx_idx: Index of pool. Should be 0 ~ (pool_num - 1).
 * @tag: Tag of expected message.
 *
 * Return pointer of message whose tag is input tag.
 */
void *wd_find_msg_in_pool(struct wd_async_msg_pool *pool, int ctx_idx,
			  __u32 tag);

/*
 * wd_check_src_dst() - Check the request input and output
 * @src: input data pointer.
 * @in_bytes: input data length.
 * @dst: output data pointer.
 * @out_bytes: output data length.
 *
 * Return -WD_EINVAL when in_bytes or out_bytes is non-zero, the
 * corresponding input or output pointers is NULL, otherwise return 0.
 */
int wd_check_src_dst(void *src, __u32 in_bytes, void *dst, __u32 out_bytes);

/*
 * wd_check_datalist() - Check the data list length
 * @head: Data list's head pointer.
 * @size: The size which is expected.
 *
 * Return 0 if the datalist is not less than expected size.
 */
int wd_check_datalist(struct wd_datalist *head, __u32 size);


/*
 * wd_parse_ctx_num() - Parse wd ctx type environment variable and store it.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @s: Related environment variable string.
 *
 * More information, please see docs/wd_environment_variable.
 */
int wd_parse_ctx_num(struct wd_env_config *config, const char *s);

/*
 * wd_parse_async_poll_en() - Parse async polling thread related environment
 * 			      variable and store it.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @s: Related environment variable string.
 *
 * More information, please see docs/wd_environment_variable.
 */
int wd_parse_async_poll_en(struct wd_env_config *config, const char *s);

/*
 * wd_parse_async_poll_num() - Parse async polling thread related environment
 *                            variable and store it.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @s: Related environment variable string.
 *
 * More information, please see docs/wd_environment_variable.
 */
int wd_parse_async_poll_num(struct wd_env_config *config, const char *s);

/*
 * wd_alg_env_init() - Init wd algorithm environment variable configurations.
 * 		       This is a help function which can be used by specific
 * 		       wd algorithm APIs.
 * @env_config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @table: Table which is used to define specific environment variable、its
 * 	   default value and related parsing operations.
 * @ops: Define functions which will be used by specific wd algorithm
 * 	 environment init.
 * @table_size: Size of above table.
 */
int wd_alg_env_init(struct wd_env_config *env_config,
		    const struct wd_config_variable *table,
		    const struct wd_alg_ops *ops,
		    __u32 table_size,
		    struct wd_ctx_attr *ctx_attr);

/*
 * wd_alg_env_uninit() - uninit specific wd algorithm environment configuration.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @ops: Define functions which will be used by specific wd algorithm
 *	 environment init.
 */
void wd_alg_env_uninit(struct wd_env_config *env_config,
		       const struct wd_alg_ops *ops);

/*
 * wd_add_task_to_async_queue() - Add an async request to its related async
 * 				  task queue.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @idx: Index of ctx in config.
 */
int wd_add_task_to_async_queue(struct wd_env_config *config, __u32 idx);

/*
 * dump_env_info() - dump wd algorithm ctx info.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 */
void dump_env_info(struct wd_env_config *config);

/**
 * wd_alg_get_env_param() - get specific ctx number.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @attr: ctx attributes.
 * @num: save ctx number.
 * @is_enable: save enable inner poll flag.
 */
int wd_alg_get_env_param(struct wd_env_config *env_config,
			 struct wd_ctx_attr attr,
			 __u32 *num, __u8 *is_enable);

/**
 * wd_set_ctx_attr() - set node type and mode for ctx
 * @ctx_attr: ctx attributes pointer.
 * @node: numa id.
 * @type: operation type.
 * @mode: synchronous or asynchronous mode.
 * @num: ctx number.
 */
int wd_set_ctx_attr(struct wd_ctx_attr *ctx_attr,
		    __u32 node, __u32 type, __u8 mode, __u32 num);

/**
 * wd_check_ctx() - check ctx mode and index
 * @config: ctx config pointer.
 * @mode: synchronous or asynchronous mode.
 * @idx: ctx index.
 */
int wd_check_ctx(struct wd_ctx_config_internal *config, __u8 mode, __u32 idx);

/**
 * wd_set_epoll_en() - set epoll enable flag from environment variable value.
 * @var_name: Environment variable name string.
 * @epoll_en: epoll enable flag.
 *
 * Return 0 if the value is 0 or 1, otherwise return -WD_EINVAL.
 */
int wd_set_epoll_en(const char *var_name, bool *epoll_en);

/**
 * wd_handle_msg_sync() - recv msg from hardware
 * @drv: the driver to handle msg.
 * @msg_handle: callback of msg handle ops.
 * @ctx: the handle of context.
 * @msg: the msg of task.
 * @balance: estimated number of receiving msg.
 * @epoll_en: whether to enable epoll.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_handle_msg_sync(struct wd_alg_driver *drv, struct wd_msg_handle *msg_handle,
		       handle_t ctx, void *msg, __u64 *balance, bool epoll_en);

/**
 * wd_init_check() - Check input parameters for wd_<alg>_init.
 * @config: Ctx configuration input by user.
 * @sched: Scheduler configuration input by user.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_init_param_check(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_alg_try_init() - Check the algorithm status and set it as WD_INITING
 * if need initialization.
 * @status: algorithm initialization status.
 *
 * Return 0 if need initialization.
 * Return -WD_EEXIST if the algorithm has been initialized.
 * Return -WD_ETIMEDOUT if wait timeout.
 */
int wd_alg_try_init(enum wd_status *status);

/**
 * wd_alg_set_init() - Set the algorithm status as WD_INIT.
 * @status: algorithm initialization status.
 */
static inline void wd_alg_set_init(enum wd_status *status)
{
	enum wd_status setting = WD_INIT;

	__atomic_store(status, &setting, __ATOMIC_RELAXED);
}

/**
 * wd_alg_get_init() - Get the algorithm status.
 * @status: algorithm initialization status.
 * @value: value of algorithm initialization status.
 */
static inline void wd_alg_get_init(enum wd_status *status, enum wd_status *value)
{
	__atomic_load(status, value, __ATOMIC_RELAXED);
}

/**
 * wd_alg_clear_init() - Set the algorithm status as WD_UNINIT.
 * @status: algorithm initialization status.
 */
static inline void wd_alg_clear_init(enum wd_status *status)
{
	enum wd_status setting = WD_UNINIT;

	__atomic_store(status, &setting, __ATOMIC_RELAXED);
}

/**
 * wd_ctx_param_init() - Initialize the current device driver according
 *			to the obtained queue resource and the applied driver.
 * @ctx_params: wd_ctx_params to be initialized.
 * @user_ctx_params: user input wd_ctx_params.
 * @driver: device driver for the current algorithm application.
 * @type: algorithm type.
 * @max_op_type: algorithm max operation type.
 *
 * Return 0 if succeed and other error number if fail.
 */
int wd_ctx_param_init(struct wd_ctx_params *ctx_params,
		      struct wd_ctx_params *user_ctx_params,
		      struct wd_alg_driver *driver,
		      enum wd_type type, int max_op_type);

void wd_ctx_param_uninit(struct wd_ctx_params *ctx_params);

/**
 * wd_alg_attrs_init() - Request the ctxs and initialize the sched_domain
 *                     with the given devices list, ctxs number and numa mask.
 * @attrs: the algorithm initialization parameters.
 *
 * Return device if succeed and other error number if fail.
 */
int wd_alg_attrs_init(struct wd_init_attrs *attrs);
void wd_alg_attrs_uninit(struct wd_init_attrs *attrs);

/**
 * wd_alg_drv_bind() - Request the ctxs and initialize the sched_domain
 *                     with the given devices list, ctxs number and numa mask.
 * @task_type: the type of task specified by the current algorithm.
 * @alg_name: the name of the algorithm specified by the task.
 *
 * Return device driver if succeed and other NULL if fail.
 */
struct wd_alg_driver *wd_alg_drv_bind(int task_type, char *alg_name);
void wd_alg_drv_unbind(struct wd_alg_driver *drv);

/**
 * wd_alg_init_driver() - Initialize the current device driver according
 *			to the obtained queue resource and the applied driver.
 * @config: device resources requested by the current algorithm.
 * @driver: device driver for the current algorithm application.
 *
 * Return 0 if succeed and other error number if fail.
 */
int wd_alg_init_driver(struct wd_ctx_config_internal *config,
		       struct wd_alg_driver *driver);
void wd_alg_uninit_driver(struct wd_ctx_config_internal *config,
			  struct wd_alg_driver *driver);

/**
 * wd_dlopen_drv() - Open the dynamic library file of the device driver.
 * @cust_lib_dir: the file path of the dynamic library file.
 */
void *wd_dlopen_drv(const char *cust_lib_dir);
void wd_dlclose_drv(void *dlh_list);

/**
 * wd_get_lib_file_path() - Find the path of the dynamic library file in
 *			the current system.
 * @lib_file: the name of the library file.
 * @lib_path: the found dynamic library file path.
 * @is_dir: Specify whether to query the file dir or the file path.
 */
int wd_get_lib_file_path(char *lib_file, char *lib_path, bool is_dir);

/**
 * wd_dfx_msg_cnt() - Message counter interface for ctx
 * @config: Ctx configuration in global setting.
 * @numSize: Number of elements.
 * @index: Indicates the CTX index.
 */
static inline void wd_dfx_msg_cnt(struct wd_ctx_config_internal *config,
				  __u32 numsize, __u32 idx)
{
	__u16 sqn;
	bool ret;

	ret = wd_need_info();
	if (idx > numsize || !ret)
		return;

	sqn = config->ctxs[idx].sqn;
	config->msg_cnt[sqn]++;
}

#ifdef __cplusplus
}
#endif

#endif /* __WD_UTIL_H */
