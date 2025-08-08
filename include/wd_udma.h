/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_UDMA_H
#define __WD_UDMA_H

#include <stdbool.h>

#include "wd_alg_common.h"

typedef void (*wd_udma_cb_t)(void *cb_param);

/**
 * wd_udma_op_type - Algorithm type of option.
 */
enum wd_udma_op_type {
	WD_UDMA_MEMCPY,
	WD_UDMA_MEMSET,
	WD_UDMA_OP_MAX
};

/**
 * wd_udma_sess_setup - udma session setup information.
 * @sched_param: Parameters of the scheduling policy,
 * usually allocated according to struct sched_params.
 */
struct wd_udma_sess_setup {
	void *sched_param;
};

/**
 * wd_data_addr - addr information of UDMA.
 * @addr: Indicates the start address of the operation.
 * @addr_size: Maximum size of the addr, in bytes.
 * @count: Number of bytes to be set.
 */
struct wd_data_addr {
	void *addr;
	size_t addr_size;
	size_t data_size;
};

/**
 * wd_udma_req - udma operation request.
 * @src: pointer to input address.
 * @dst: pointer to output address, for WD_UDMA_MEMSET, only one of src and dst can be set.
 * @addr_num: Number of address.
 * @value: Value to be written for WD_UDMA_MEMSET.
 * @op_type: udma operation type.
 * @cb: Callback function.
 * @cb_param: Parameters of the callback function.
 * @state: operation result written back by the driver.
 */
struct wd_udma_req {
	struct wd_data_addr *src;
	struct wd_data_addr *dst;
	int addr_num;
	int value;
	enum wd_udma_op_type op_type;
	wd_udma_cb_t cb;
	void *cb_param;
	int status;
};

/**
 * wd_udma_init() - A simplify interface to initializate ecc.
 * To make the initializate simpler, ctx_params support set NULL.
 * And then the function will set them as driver's default.
 *
 * @alg: The algorithm users want to use.
 * @sched_type: The scheduling type users want to use.
 * @task_type: Task types, including soft computing, hardware and hybrid computing.
 * @ctx_params: The ctxs resources users want to use. Include per operation
 * type ctx numbers and business process run numa.
 *
 * Return 0 if succeed and others if fail.
 */
int wd_udma_init(const char *alg, __u32 sched_type,
		 int task_type, struct wd_ctx_params *ctx_params);

/**
 * wd_udma_uninit() - Uninitialise ctx configuration and scheduler.
 */
void wd_udma_uninit(void);

/**
 * wd_udma_alloc_sess() - Allocate a wd udma session.
 * @setup:	Parameters to setup this session.
 *
 * Return 0 if failed.
 */
handle_t wd_udma_alloc_sess(struct wd_udma_sess_setup *setup);

/**
 * wd_udma_free_sess() - Free a wd udma session.
 * @ sess: The sess to be freed.
 */
void wd_udma_free_sess(handle_t sess);

/**
 * wd_do_udma_sync() - Send a sync udma request.
 * @h_sess: The session which request will be sent to.
 * @req: Request.
 */
int wd_do_udma_sync(handle_t h_sess, struct wd_udma_req *req);

/**
 * wd_do_udma_async() - Send an async udma request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
int wd_do_udma_async(handle_t h_sess, struct wd_udma_req *req);

/**
 * wd_udma_poll() - Poll finished request.
 *
 * This function will call poll_policy function which is registered to wd udma
 * by user.
 */
int wd_udma_poll(__u32 expt, __u32 *count);

#endif /* __WD_UDMA_H */
