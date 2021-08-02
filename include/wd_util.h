// SPDX-License-Identifier: Apache-2.0
#ifndef __WD_UTIL_H
#define __WD_UTIL_H

#include <stdbool.h>
#include "wd_alg_common.h"

#define FOREACH_NUMA(i, config, config_numa) \
	for (i = 0, config_numa = config->config_per_numa; \
	     i < config->numa_num; config_numa++, i++)

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
	unsigned long node;
	unsigned long sync_ctx_num;
	unsigned long async_ctx_num;
	/*
	 * Define which polling thread to poll each async ctx, polling thread
	 * number stars from 0.
	 *
	 * async_ctx_poll: 0, 0, 0, 1, 1, means polling thread 0 polls async
	 * ctx 0, 1, 2, polling thread 1 polls async ctx 3, 4.
	 */
	unsigned long *async_ctx_poll;

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
	struct uacce_dev dev;
	/* This can be made statically currently */
	unsigned long async_poll_num;
	struct async_task_queue *async_task_queue_array;
};

struct wd_env_config {
	unsigned long numa_num;
	struct wd_env_config_per_numa *config_per_numa;
	/* Let's make it as a gobal config, not per numa */
	bool enable_internal_poll;
	__u8 disable_env;
	__u8 op_type_num;
	int (*alg_poll_ctx)(__u32, __u32, __u32 *);
	void (*alg_uninit)(void);

	/* resource config */
	struct wd_sched *sched;
	struct wd_ctx_config *ctx_config;
	const struct wd_config_variable *table;
	__u32 table_size;
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
 * wd_init_async_request_pool() - Init message pools.
 * @pool: Pointer of message pool.
 * @pool_num: Message pool number.
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
int wd_init_async_request_pool(struct wd_async_msg_pool *pool, __u32 pool_num,
			       __u32 msg_num, __u32 msg_size);

/*
 * wd_uninit_async_request_pool() - Uninit message pools.
 * @pool: Pool which will be uninit.
 */
void wd_uninit_async_request_pool(struct wd_async_msg_pool *pool);

/*
 * wd_get_msg_from_pool() - Get a free message from pool.
 * @pool: Pointer of global pools.
 * @index: Index of pool. Should be 0 ~ (pool_num - 1).
 * @msg: Put pointer of got message into *msg.
 *
 * Return tag of got message. This tag can be used to put a message and
 * find a message in wd_put_msg_to_pool() and wd_find_msg_in_pool(). Returned
 * tag will be in 1 ~ msg_num indicating msg_0 ~ msg_n-1; tag value 0 will NOT
 * be used to avoid possible error; -WD_EBUSY will return if related message pool
 * is full.
 */
int wd_get_msg_from_pool(struct wd_async_msg_pool *pool, int index, void **msg);

/*
 * wd_put_msg_to_pool() - Put a message to pool.
 * @pool: Pointer of global pools.
 * @index: Index of pool. Should be 0 ~ (pool_num - 1).
 * @tag: Tag of put message.
 */
void wd_put_msg_to_pool(struct wd_async_msg_pool *pool, int index, __u32 tag);

/*
 * wd_find_msg_in_pool() - Find a message in pool.
 * @pool: Pointer of global pools.
 * @index: Index of pool. Should be 0 ~ (pool_num - 1).
 * @tag: Tag of expected message.
 *
 * Return pointer of message whose tag is input tag.
 */
void *wd_find_msg_in_pool(struct wd_async_msg_pool *pool, int index, __u32 tag);

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
 * wd_alg_env_init() - Init wd algorithm environment variable configurations.
 * 		       This is a help function which can be used by specific
 * 		       wd algorithm APIs.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @table: Table which is used to define specific environment variable、its
 * 	   default value and related parsing operations.
 * @ops: Define functions which will be used by specific wd algorithm
 * 	 environment init.
 * @table_size: Size of above table.
 */
int wd_alg_env_init(struct wd_env_config *config,
		    const struct wd_config_variable *table,
		    const struct wd_alg_ops *ops,
		    __u32 table_size,
		    struct wd_ctx_attr *ctx_attr);

/*
 * wd_alg_env_uninit() - uninit specific wd algorithm environment configuration.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 */
void wd_alg_env_uninit(struct wd_env_config *env_config);

/*
 * wd_add_task_to_async_queue() - Add an async request to its related async
 * 				  task queue.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @index: Index of ctx in config.
 */
int wd_add_task_to_async_queue(struct wd_env_config *config, __u32 index);

/*
 * dump_env_info() - dump wd algorithm ctx info.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 */
void dump_env_info(struct wd_env_config *config);

/*
 * wd_alg_get_env_param() - get specific ctx number.
 * @config: Pointer of wd_env_config which is used to store environment
 *          variable information.
 * @ctx_attr: ctx attributes.
 * @num: save ctx number.
 * @is_enable: save enable inner poll flag.
 */
int wd_alg_get_env_param(struct wd_env_config *env_config,
			 struct wd_ctx_attr ctx_attr,
			 __u32 *num, __u8 *is_enable);

/*
 * wd_set_ctx_attr() - set node type and mode for ctx
 * @ctx_attr: ctx attributes pointer.
 * @node: numa id.
 * @type: operation type.
 * @mode: synchronous or asynchronous mode.
 * @num: ctx number.
 */
int wd_set_ctx_attr(struct wd_ctx_attr *ctx_attr,
		    __u32 node, __u32 type, __u8 mode, __u32 num);

/*
 * wd_check_ctx() - check ctx mode and index
 * @config: ctx config pointer.
 * @mode: synchronous or asynchronous mode.
 * @idx: ctx index.
 */
int wd_check_ctx(struct wd_ctx_config_internal *config, __u8 mode, __u32 idx);

#endif /* __WD_UTIL_H */
