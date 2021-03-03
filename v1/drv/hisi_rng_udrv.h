/*
 * Copyright 2018-2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HISI_RNG_UDRV_H__
#define __HISI_RNG_UDRV_H__

#include <linux/types.h>
#include "config.h"
#include "v1/wd.h"
#include "v1/wd_util.h"
#include "v1/wd_rng.h"

#define TRNG_Q_DEPTH	256

typedef unsigned char __u8;

struct rng_queue_info {
	void *mmio_base;
	void *req_cache[TRNG_Q_DEPTH];
	__u8  send_idx;
	__u8 recv_idx;
	struct wd_lock lock;
};

int rng_init_queue(struct wd_queue *q);
void rng_uninit_queue(struct wd_queue *q);
int rng_send(struct wd_queue *q, void **req, __u32 num);
int rng_recv(struct wd_queue *q, void **resp, __u32 num);

#endif
