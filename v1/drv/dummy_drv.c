/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <linux/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "v1/wd_util.h"
#include "dummy_drv.h"

struct dummy_q_priv {
	int ver;
	int head;		/* queue head */
	int resp_tail;		/* resp tail in the queue */
	/* so in the user side: when add to queue, head++ but don't exceed resp_tail.
	 * when get back from the queue, resp_tail++ but don't exceed tail.
	 * in the kernel side: when get from queue, tail++ but don't exceed head-1 */

	struct dummy_hw_queue_reg *reg;
	uint64_t *db;
};

int dummy_set_queue_dio(struct wd_queue *q)
{
	int ret = 0;
	struct dummy_q_priv *priv;
	struct q_info *qinfo = q->qinfo;

	priv = calloc(1, sizeof(*priv));
	if (!priv) {
		DUMMY_ERR("No memory for dummy queue!\n");
		ret = -ENOMEM;
		goto out;
	}
	qinfo->priv = priv;
	priv->head = 0;
	priv->resp_tail = 0;
	priv->ver = qinfo->qfrs_offset[WD_UACCE_QFRT_DUS] == WD_UACCE_QFRT_INVALID ?
			1 : 2;

	printf("dummy_set_queue_dio ver=%d\n", priv->ver);
	if (priv->ver == 2) {
		priv->db = wd_drv_mmap_qfr(q, WD_UACCE_QFRT_MMIO, 0);
		if (priv->db == MAP_FAILED) {
			DUMMY_ERR("mmap db fail (%d)\n", errno);
			if (errno)
				ret = errno;
			else
				ret = -EIO;
			goto out_with_priv;
		}
	}

	priv->reg = wd_drv_mmap_qfr(q,
			priv->ver == 1 ? WD_UACCE_QFRT_MMIO : WD_UACCE_QFRT_DUS, 0);
	if (priv->reg == MAP_FAILED) {
		DUMMY_ERR("mmap bd fail (%d)\n", errno);
		if (errno)
			ret = errno;
		else
			ret = -EIO;
		goto out_with_db_map;
	}

	/* detect hardware for v1 (v2 can be detected only after start) */
	if (priv->ver == 1 &&
	    memcmp(priv->reg->hw_tag, DUMMY_HW_TAG, DUMMY_HW_TAG_SZ)) {
		DUMMY_ERR("hw detection fail\n");
		ret = -EIO;
		goto out_with_bd_map;
	}

	return 0;

out_with_bd_map:
	if (priv->ver == 1)
		wd_drv_unmmap_qfr(q, priv->reg, WD_UACCE_QFRT_MMIO, 0);
	else
		wd_drv_unmmap_qfr(q, priv->reg, WD_UACCE_QFRT_DUS, 0);
out_with_db_map:
	if (priv->ver == 2)
		wd_drv_unmmap_qfr(q, priv->db, WD_UACCE_QFRT_MMIO, 0);
out_with_priv:
	free(priv);
	qinfo->priv = NULL;
out:
	return ret;
}

void dummy_unset_queue_dio(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct dummy_q_priv *priv = (struct dummy_q_priv *)qinfo->priv;

	ASSERT(priv);

	munmap(priv->reg, sizeof(struct dummy_hw_queue_reg));
	free(priv);
	qinfo->priv = NULL;
}

int dummy_add_to_dio_q(struct wd_queue *q, void **req, __u32 num)
{
	struct q_info *qinfo = q->qinfo;
	struct dummy_q_priv *priv = (struct dummy_q_priv *)qinfo->priv;
	int bd_num;

	ASSERT(priv);

	bd_num = priv->reg->ring_bd_num;

	if ((priv->head + 1) % bd_num == priv->resp_tail)
		return -EBUSY; /* the queue is full */
	else {
		priv->reg->ring[priv->head] = *((struct ring_bd *)(req[0]));
		priv->reg->ring[priv->head].ptr = req[0];
		priv->head = (priv->head + 1) % bd_num;
		wd_reg_write(&priv->reg->head, priv->head);
		printf("add to queue, new head=%d, %d\n", priv->head, priv->reg->head);

		if (priv->ver == 2)
			wd_reg_write(priv->db, 1);
	}

	return 0;
}

int dummy_get_from_dio_q(struct wd_queue *q, void **resp, __u32 num)
{
	struct q_info *qinfo = q->qinfo;
	struct dummy_q_priv *priv = (struct dummy_q_priv *)qinfo->priv;
	int bd_num = priv->reg->ring_bd_num;
	int ret;
	int tail;

	ASSERT(priv);

	tail = wd_reg_read(&priv->reg->tail);
	printf("get queue tail=%d,%d\n", tail, priv->resp_tail);
	if (priv->resp_tail == tail) {
		return -EBUSY;
	} else {
		ret = priv->reg->ring[priv->resp_tail].ret;
		*resp = priv->reg->ring[priv->resp_tail].ptr;
		priv->resp_tail = (priv->resp_tail + 1) % bd_num;
		printf("get resp %d, %d\n", ret, priv->resp_tail);
		return ret;
	}
}

void dummy_flush(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct dummy_q_priv *priv = (struct dummy_q_priv *)qinfo->priv;

	if (priv->ver == 1)
		ioctl(qinfo->fd, DUMMY_CMD_FLUSH);
	else
		wd_reg_write(priv->db, 1);
}
