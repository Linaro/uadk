// SPDX-License-Identifier: Apache-2.0
#ifndef __WD_UTIL_H
#define __WD_UTIL_H

struct wd_async_msg_pool {
	struct msg_pool *pools;
	__u32 pool_num;
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
 * be used to avoid possible error; -EBUSY will return if related message pool
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

#endif /* __WD_UTIL_H */
