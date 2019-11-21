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

#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "hisi_rng_udrv.h"

#define HISI_RNG_BYTES		4
#define MAX_RETRY_COUNTS	8
#define RNG_NUM_OFFSET		0x00F0

int rng_init_queue(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct rng_queue_info *info;

	info = calloc(1, sizeof(*info));
	if (!info) {
		WD_ERR("no mem!\n");
		return -ENOMEM;
	}

	qinfo->priv = info;
	info->mmio_base = wd_drv_mmap_qfr(q, UACCE_QFRT_MMIO,
					UACCE_QFRT_DKO, 0);
	if (info->mmio_base == MAP_FAILED) {
		info->mmio_base = NULL;
		free(qinfo->priv);
		qinfo->priv = NULL;
		WD_ERR("mmap trng mmio fail\n");
		return -ENOMEM;
	}

	return 0;
}

void rng_uninit_queue(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct rng_queue_info *info = qinfo->priv;

	wd_drv_unmmap_qfr(q, info->mmio_base, UACCE_QFRT_MMIO,
					UACCE_QFRT_DKO, 0);

	free(qinfo->priv);
	qinfo->priv = NULL;
}

int rng_send(struct wd_queue *q, void *req)
{
	struct q_info *qinfo = q->qinfo;
	struct rng_queue_info *info = qinfo->priv;

	wd_spinlock(&info->lock);
	if (!info->req_cache[info->send_idx]) {
		info->req_cache[info->send_idx] = req;
		info->send_idx++;
		wd_unspinlock(&info->lock);
		return 0;
	}
	wd_unspinlock(&info->lock);

	WD_ERR("queue is full!\n");
	return -WD_EBUSY;
}

static int rng_read(struct rng_queue_info *info, struct wcrypto_rng_msg *msg)
{
	int max = msg->in_bytes;
	int currsize = 0;
	int recv_count = 0;
	int val;

	do {
recv_again:
		val = wd_reg_read((void *)((uintptr_t)info->mmio_base +
						RNG_NUM_OFFSET));
		if (!val) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				WD_ERR("read random data timeout\n");
				break;
			}
			usleep(1);
			goto recv_again;
		}

		recv_count = 0;
		if (max - currsize >= HISI_RNG_BYTES) {
			memcpy(msg->out + currsize, &val, HISI_RNG_BYTES);
			currsize += HISI_RNG_BYTES;
			if (currsize == max)
				break;
			continue;
		}

		memcpy(msg->out + currsize, &val, max - currsize);
		currsize = max;
	} while (currsize < max);

	return currsize;
}

int rng_recv(struct wd_queue *q, void **resp)
{
	struct q_info *qinfo = q->qinfo;
	struct rng_queue_info *info = qinfo->priv;
	__u16 usr = (__u16)(uintptr_t)*resp;
	struct wcrypto_rng_msg *msg;
	struct wcrypto_cb_tag *tag;
	int ret;

	wd_spinlock(&info->lock);
	msg = info->req_cache[info->recv_idx];
	if (!msg) {
		wd_unspinlock(&info->lock);
		return 0;
	}

	info->req_cache[info->recv_idx] = NULL;
	info->recv_idx++;
	wd_unspinlock(&info->lock);

	tag = (void *)(uintptr_t)msg->usr_tag;
	if (usr && tag->ctx_id != usr)
		return 0;

	ret = rng_read(info, msg);
	if (!ret) {
		WD_ERR("random data err!\n");
		return -WD_EINVAL;
	}

	msg->out_bytes = ret;
	*resp = msg;

	return 1;
}
