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

#include "hisi_qm_udrv.h"
#include "hisi_zip_udrv.h"
#include "hisi_hpre_udrv.h"
#include "hisi_sec_udrv.h"
#include "hisi_rde_udrv.h"


/* Only Hi1620 ES, we just need version 1 doorbell. */
int qm_db_v1(struct qm_queue_info *q, __u8 cmd,
	       __u16 idx, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell;

	doorbell = (__u64)sqn | ((__u64)cmd << QM_DBELL_CMD_SHIFT);
	doorbell |= ((__u64)idx | ((__u64)priority << QM_DBELL_CMD_SHIFT)) <<
		    QM_DBELL_HLF_SHIFT;
	*((__u64 *)base) = doorbell;

	return 0;
}

/* Only Hi1620 CS, we just need version 2 doorbell. */
static int qm_db_v2(struct qm_queue_info *q, __u8 cmd,
		      __u16 idx, __u8 priority)
{
	__u16 sqn = q->sqn & QM_DBELL_SQN_MASK;
	void *base = q->doorbell_base;
	__u64 doorbell;

	doorbell = (__u64)sqn | ((__u64)(cmd & QM_DBELL_CMD_MASK) <<
		   QM_V2_DBELL_CMD_SHIFT);
	doorbell |= ((__u64)idx | ((__u64)priority << QM_DBELL_CMD_SHIFT)) <<
		    QM_DBELL_HLF_SHIFT;
	*((__u64 *)base) = doorbell;

	return 0;
}

static int qm_set_queue_regions(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info = qinfo->priv;

	info->sq_base = wd_drv_mmap_qfr(q, UACCE_QFRT_DUS, UACCE_QFRT_SS, 0);
	if (info->sq_base == MAP_FAILED) {
		info->sq_base = NULL;
		WD_ERR("mmap dus fail\n");
		return -ENOMEM;
	}

	info->mmio_base = wd_drv_mmap_qfr(q, UACCE_QFRT_MMIO,
					UACCE_QFRT_DUS, 0);
	if (info->mmio_base == MAP_FAILED) {
		info->mmio_base = NULL;
		WD_ERR("mmap mmio fail\n");
		return -ENOMEM;
	}

	return 0;
}

static void qm_unset_queue_regions(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info = qinfo->priv;

	wd_drv_unmmap_qfr(q, info->mmio_base, UACCE_QFRT_MMIO,
			UACCE_QFRT_DUS, 0);
	wd_drv_unmmap_qfr(q, info->sq_base, UACCE_QFRT_DUS, UACCE_QFRT_SS, 0);
}

static int qm_set_queue_alg_info(struct wd_queue *q)
{
	const char *alg = q->capa.alg;
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info = qinfo->priv;
	struct wcrypto_paras *priv = &q->capa.priv;
	int ret = -WD_EINVAL;

	if (!strncmp(alg, "rsa", strlen("rsa"))) {
		qinfo->atype = WCRYPTO_RSA;
		info->sqe_size = QM_HPRE_BD_SIZE;
		info->sqe_fill[WCRYPTO_RSA] = qm_fill_rsa_sqe;
		info->sqe_parse[WCRYPTO_RSA] = qm_parse_rsa_sqe;
		ret = WD_SUCCESS;
	} else if (!strncmp(alg, "dh", strlen("dh"))) {
		qinfo->atype = WCRYPTO_DH;
		info->sqe_size = QM_HPRE_BD_SIZE;
		info->sqe_fill[WCRYPTO_DH] = qm_fill_dh_sqe;
		info->sqe_parse[WCRYPTO_DH] = qm_parse_dh_sqe;
		ret = WD_SUCCESS;
	} else if (!strncmp(alg, "zlib", strlen("zlib")) ||
				!strncmp(alg, "gzip", strlen("gzip"))) {
		qinfo->atype = WCRYPTO_COMP;
		info->sqe_size = QM_ZIP_BD_SIZE;
		info->sqe_fill[WCRYPTO_COMP] = qm_fill_zip_sqe;
		info->sqe_parse[WCRYPTO_COMP] = qm_parse_zip_sqe;
		ret = WD_SUCCESS;
	} else if (!strncmp(alg, "cipher", strlen("cipher"))) {
		qinfo->atype = WCRYPTO_CIPHER;
		info->sqe_size = QM_SEC_BD_SIZE;
		info->sqe_fill[WCRYPTO_CIPHER] = qm_fill_cipher_sqe;
		info->sqe_parse[WCRYPTO_CIPHER] = qm_parse_cipher_sqe;
		ret = WD_SUCCESS;
	} else if (!strncmp(alg, "digest", strlen("digest"))) {
		qinfo->atype = WCRYPTO_DIGEST;
		info->sqe_size = QM_SEC_BD_SIZE;
		info->sqe_fill[WCRYPTO_DIGEST] = qm_fill_digest_sqe;
		info->sqe_parse[WCRYPTO_DIGEST] = qm_parse_digest_sqe;
		ret = WD_SUCCESS;
	} else if (!strncmp(alg, "ec", strlen("ec"))) {
		qinfo->atype = WCRYPTO_EC;
		info->sqe_size = QM_RDE_BD_SIZE;
		info->sqe_fill[WCRYPTO_EC] = qm_fill_rde_sqe;
		info->sqe_parse[WCRYPTO_EC] = qm_parse_rde_sqe;
		ret = WD_SUCCESS;
	} else if (!strncmp(alg, "xts(aes)", strlen("xts(aes)")) ||
		!strncmp(alg, "xts(sm4)", strlen("xts(sm4)"))) {
		qinfo->atype = WCRYPTO_CIPHER;
		if (strstr(q->dev_path, "zip")) {
			info->sqe_size = QM_ZIP_BD_SIZE;
			info->sqe_fill[WCRYPTO_CIPHER] = qm_fill_zip_cipher_sqe;
			info->sqe_parse[WCRYPTO_CIPHER] = qm_parse_zip_cipher_sqe;
			ret = WD_SUCCESS;
		} else if (strstr(q->dev_path, "sec")) {
			priv->direction = 0;
			info->sqe_size = QM_SEC_BD_SIZE;
			info->sqe_fill[WCRYPTO_CIPHER] = qm_fill_cipher_sqe;
			info->sqe_parse[WCRYPTO_CIPHER] = qm_parse_cipher_sqe;
			ret = WD_SUCCESS;
		} else { /* To be extended */
			WD_ERR("queue xts alg engine err!\n");
		}
	} else { /* To be extended */
		WD_ERR("queue alg err!\n");
	}

	return ret;
}

static int qm_set_queue_info(struct wd_queue *q)
{
	struct wcrypto_paras *priv = &q->capa.priv;
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info = qinfo->priv;
	struct hisi_qp_ctx qp_ctx;
	int ret;

	ret = qm_set_queue_regions(q);
	if (ret)
		return -EINVAL;
	if (!info->sqe_size) {
		WD_ERR("sqe size =%d err!\n", info->sqe_size);
		return -EINVAL;
	}
	info->cq_base = (void *)((uintptr_t)info->sq_base +
			info->sqe_size * QM_Q_DEPTH);

	/* The last 32 bits of DUS show device or qp statuses */
	info->ds_base = info->sq_base + qinfo->qfrs_offset[UACCE_QFRT_SS] -
		qinfo->qfrs_offset[UACCE_QFRT_DUS] - sizeof(uint32_t);
	if (strstr(qinfo->hw_type, HISI_QM_API_VER2_BASE)) {
		info->db = qm_db_v2;
		info->doorbell_base = info->mmio_base + QM_V2_DOORBELL_OFFSET;
	} else if (strstr(qinfo->hw_type, HISI_QM_API_VER_BASE)) {
		info->db = qm_db_v1;
		info->doorbell_base = info->mmio_base + QM_DOORBELL_OFFSET;
	} else {
		WD_ERR("hw version mismatch!\n");
		return -EINVAL;
	}
	info->sq_tail_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;
	info->used = 0;
	qp_ctx.qc_type = priv->direction;
	qp_ctx.id = 0;
	ret = ioctl(qinfo->fd, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_ERR("hisi qm set qc_type fail, use default!\n");
		return ret;
	}
	info->sqn = qp_ctx.id;

	return ret;
}

int qm_init_queue(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info;
	int ret = -ENOMEM;

	info = calloc(1, sizeof(*info));
	if (!info) {
		WD_ERR("no mem!\n");
		return ret;
	}
	info->q = q;
	qinfo->priv = info;
	ret = qm_set_queue_alg_info(q);
	if (ret < 0)
		goto err_with_regions;
	ret = qm_set_queue_info(q);
	if (ret < 0)
		goto err_with_regions;

	return 0;

err_with_regions:
	qm_unset_queue_regions(q);
	free(qinfo->priv);
	qinfo->priv = NULL;
	return ret;
}

void qm_uninit_queue(struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;

	qm_unset_queue_regions(q);
	free(qinfo->priv);
	qinfo->priv = NULL;
}

static void qm_tx_update(struct qm_queue_info *info, __u16 idx)
{
	if (idx == QM_Q_DEPTH - 1)
		idx = 0;
	else
		idx++;
	info->db(info, DOORBELL_CMD_SQ, idx, 0);
	info->sq_tail_index = idx;
	__atomic_add_fetch(&info->used, 1, __ATOMIC_RELAXED);
}

int qm_send(struct wd_queue *q, void *req)
{
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info = qinfo->priv;
	__u16 i;
	int ret;

	if (wd_reg_read(info->ds_base) == 1) {
		WD_ERR("wd queue hw error happened before qm send!\n");
		return -WD_HW_EACCESS;
	}
	wd_spinlock(&info->sd_lock);
	if (__atomic_load_n(&info->used, __ATOMIC_RELAXED) == QM_Q_DEPTH) {
		wd_unspinlock(&info->sd_lock);
		WD_ERR("queue is full!\n");
		return -WD_EBUSY;
	}

	i = info->sq_tail_index;

	ret = info->sqe_fill[qinfo->atype](req, qinfo->priv, i);
	if (ret != WD_SUCCESS) {
		wd_unspinlock(&info->sd_lock);
		WD_ERR("sqe fill error, ret %d!\n", ret);
		return -WD_EINVAL;
	}

	/* make sure the request is all in memory before doorbell */
	mb();
	qm_tx_update(info, i);
	wd_unspinlock(&info->sd_lock);
	if (wd_reg_read(info->ds_base) == 1) {
		WD_ERR("wd queue hw error happened in qm send!\n");
		return -WD_HW_EACCESS;
	}

	return WD_SUCCESS;
}

static void qm_rx_update(struct qm_queue_info *info, void **resp, __u16 idx)
{
	*resp = info->req_cache[idx];
	info->req_cache[idx] = NULL;

	if (idx == QM_Q_DEPTH - 1) {
		info->cqc_phase = !(info->cqc_phase);
		idx = 0;
	} else {
		idx++;
	}

	info->db(info, DOORBELL_CMD_CQ, idx, 0);

	info->cq_head_index = idx;
	__atomic_sub_fetch(&info->used, 1, __ATOMIC_RELAXED);
}
static void qm_rx_from_cache(struct qm_queue_info *info, void **resp, __u16 idx)
{
	*resp = info->req_cache[idx];
	info->req_cache[idx] = NULL;

	if (idx == QM_Q_DEPTH - 1) {
		info->cqc_phase = !(info->cqc_phase);
		idx = 0;
	} else {
		idx++;
	}

	info->cq_head_index = idx;
	__atomic_sub_fetch(&info->used, 1, __ATOMIC_RELAXED);
}
int qm_recv(struct wd_queue *q, void **resp)
{
	struct q_info *qinfo = q->qinfo;
	struct qm_queue_info *info = qinfo->priv;
	void *sqe = NULL;
	struct cqe *cqe;
	__u16 i, j;
	int ret;

	if (wd_reg_read(info->ds_base) == 1) {
		qm_rx_from_cache(info, resp, info->cq_head_index);
		return -WD_HW_EACCESS;
	}

	wd_spinlock(&info->rc_lock);
	i = info->cq_head_index;
	cqe = info->cq_base + i * sizeof(struct cqe);
	if (info->cqc_phase == CQE_PHASE(cqe)) {
		mb();  /* make sure the data is all in memory before read */
		j = CQE_SQ_HEAD_INDEX(cqe);
		if (j >= QM_Q_DEPTH) {
			wd_unspinlock(&info->rc_lock);
			WD_ERR("CQE_SQ_HEAD_INDEX(%u) error\n", j);
			return -WD_EIO;
		}
		sqe = (void *)((uintptr_t)info->sq_base + j * info->sqe_size);
		ret = info->sqe_parse[qinfo->atype](sqe,
				(const struct qm_queue_info *)info,
				i, (__u16)(uintptr_t)*resp);
		if (!ret) {
			wd_unspinlock(&info->rc_lock);
			return 0;
		} else if (ret < 0)
			WD_ERR("recv sqe error %u\n", j);
	} else {
		wd_unspinlock(&info->rc_lock);
		return 0;
	}
	qm_rx_update(info, resp, i);
	wd_unspinlock(&info->rc_lock);

	if (wd_reg_read(info->ds_base) == 1) {
		WD_ERR("wd queue hw error happened in qm receive!\n");
		return -WD_HW_EACCESS;
	}

	return ret;
}
