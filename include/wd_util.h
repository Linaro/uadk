// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef __WD_UTIL_H
#define __WD_UTIL_H

#include <stdbool.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <asm/types.h>

#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__
#define dsb(opt)        { asm volatile("dsb " #opt : : : "memory"); }
#define rmb() dsb(ld) /* read fence */
#define wmb() dsb(st) /* write fence */
#define mb() dsb(sy) /* rw fence */
#else
#define rmb() __sync_synchronize() /* read fence */
#define wmb() __sync_synchronize() /* write fence */
#define mb() __sync_synchronize() /* rw fence */
#endif

static inline uint32_t wd_ioread32(void *addr)
{
	uint32_t ret;

	ret = *((volatile uint32_t *)addr);
	rmb();
	return ret;
}

static inline uint64_t wd_ioread64(void *addr)
{
	uint64_t ret;

	ret = *((volatile uint64_t *)addr);
	rmb();
	return ret;
}

static inline void wd_iowrite32(void *addr, uint32_t value)
{
	wmb();
	*((volatile uint32_t *)addr) = value;
}

static inline void wd_iowrite64(void *addr, uint64_t value)
{
	wmb();
	*((volatile uint64_t *)addr) = value;
}

/**
 * wd_ctx_start() - Start a context.
 * @h_ctx: The handle of context which will be started.
 *
 * Return 0 if successful or less than 0 otherwise.
 *
 * Context will be started after calling this function. If necessary resource
 * (e.g. MMIO and DUS) already got, tasks can be received by context.
 */
int wd_ctx_start(handle_t h_ctx);

/**
 * wd_release_ctx_force() - Release a context forcely.
 * @h_ctx: The handle of context which will be released.
 *
 * Return 0 if successful or less than 0 otherwise.
 *
 * Context will be stopped and related hardware will be released, which avoids
 * release delay in wd_release_ctx(). After calling this function, context
 * related hardware resource will be released, however, fd is still there.
 * wd_release_ctx mush be used to release context finally, other APIs about
 * context can not work with this context after calling wd_release_ctx_force.
 */
int wd_release_ctx_force(handle_t h_ctx);

/**
 * wd_ctx_set_priv() - Store some information in context.
 * @h_ctx: The handle of context.
 * @priv: The pointer of memory which stores above information.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_ctx_set_priv(handle_t h_ctx, void *priv);

/**
 * wd_ctx_get_priv() - Get stored information in context.
 * @h_ctx: The handle of context.
 *
 * Return pointer of memory of stored information if successful or NULL
 * otherwise.
 */
void *wd_ctx_get_priv(handle_t h_ctx);

/**
 * wd_ctx_get_api() - Get api string of context.
 * @h_ctx: The handle of context.
 *
 * Return api string or NULL otherwise.
 *
 * This function is a wrapper of reading /sys/class/uacce/<dev>/api, which is
 * used to define api version between user space and kernel driver.
 */
char *wd_ctx_get_api(handle_t h_ctx);

/**
 * wd_ctx_mmap_qfr() - Map and get the base address of one context region.
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h
 *
 * Return pointer of context region if successful or NULL otherwise.
 *
 * Normally, UACCE_QFRT_MMIO is for MMIO registers of one context,
 * UACCE_QFRT_DUS is for task communication memory of one context.
 */
void *wd_ctx_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);

/**
 * wd_ctx_unmap_qfr() - Unmap one context region.
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h.
 */
void wd_ctx_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);

/**
 * wd_ctx_set_io_cmd() - Send ioctl command to context.
 * @h_ctx: The handle of context.
 * @cmd: ioctl command which could be found in Linux kernel head file,
 *       include/uapi/misc/uacce/uacce.h, hisi_qm.h...
 * @arg: Command output buffer if some information will be got from kernel or
 *       NULL otherwise.
 *
 * This function is a wrapper of ioctl.
 */
int wd_ctx_set_io_cmd(handle_t h_ctx, unsigned long cmd, void *arg);

/**
 * wd_ctx_get_region_size() - Get region offset size
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h
 * Return device region size.
 */
unsigned long wd_ctx_get_region_size(handle_t h_ctx, enum uacce_qfrt qfrt);

struct wd_ctx_internal {
	handle_t ctx;
	__u8 op_type;
	__u8 ctx_mode;
	pthread_spinlock_t lock;
};

struct wd_ctx_config_internal {
	__u32 ctx_num;
	struct wd_ctx_internal *ctxs;
	void *priv;
	int pid;
	bool epoll_en;
	unsigned long *msg_cnt;
};

#define FOREACH_NUMA(i, config, config_numa) \
	for ((i) = 0, (config_numa) = (config)->config_per_numa; \
	     (i) < (config)->numa_num; (config_numa)++, (i)++)

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

struct wd_msg_handle {
	int (*send)(handle_t sess, void *msg);
	int (*recv)(handle_t sess, void *msg);
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
 * @msg_handle: callback of msg handle ops.
 * @ctx: the handle of context.
 * @msg: the msg of task.
 * @balance: estimated number of receiving msg.
 * @epoll_en: whether to enable epoll.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_handle_msg_sync(struct wd_msg_handle *msg_handle, handle_t ctx,
		void *msg, __u64 *balance, bool epoll_en);

/**
 * wd_init_check() - Check input parameters for wd_<alg>_init.
 * @config: Ctx configuration input by user.
 * @sched: Scheduler configuration input by user.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_init_param_check(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_dfx_msg_cnt() - Message counter interface for ctx
 * @msg: Shared memory addr.
 * @numSize: Number of elements.
 * @index: Indicates the CTX index.
 */
static inline void wd_dfx_msg_cnt(unsigned long *msg, __u32 numsize, __u32 idx)
{
	bool ret;

	ret = wd_need_info();
	if (idx > numsize || !ret)
		return;

	msg[idx]++;
}

#ifdef __cplusplus
}
#endif

#endif /* __WD_UTIL_H */
