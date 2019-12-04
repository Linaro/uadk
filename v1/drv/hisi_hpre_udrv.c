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
#include "wd_util.h"
#include "hisi_hpre_udrv.h"

static int qm_crypto_bin_to_hpre_bin(char *dst, const char *src,
				int para_size, int data_len)
{
	int i = data_len - 1, j = 0;

	if (!dst || !src || para_size <= 0 || data_len <= 0) {
		WD_ERR("crypto bin to hpre bin params err!\n");
		return -WD_EINVAL;
	}
	if (para_size == data_len || (dst == src && src[para_size - 1]))
		return WD_SUCCESS;

	if (para_size < data_len) {
		WD_ERR("crypto bin to hpre bin param data is too long!\n");
		return  -WD_EINVAL;
	}
	for (j = para_size - 1; j >= 0; j--, i--) {
		if (i >= 0)
			dst[j] = src[i];
		else
			dst[j] = 0;
	}
	return WD_SUCCESS;
}

static int qm_hpre_bin_to_crypto_bin(char *dst, const char *src, int para_size)
{
	int i, j = 0, cnt;

	if (!dst || !src || para_size <= 0) {
		WD_ERR("%s params err!\n", __func__);
		return -WD_EINVAL;
	}
	while (!src[j])
		j++;
	if (j == 0 && src == dst)
		return WD_SUCCESS;
	for (i = 0, cnt = j; i < para_size; j++, i++) {
		if (i < para_size - cnt)
			dst[i] = src[j];
		else
			dst[i] = 0;
	}

	return WD_SUCCESS;
}

static int qm_fill_rsa_crt_prikey2(struct wcrypto_rsa_prikey *prikey, void **data)
{
	struct wd_dtb *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	int ret;

	wcrypto_get_rsa_crt_prikey_params(prikey, &wd_dq, &wd_dp,
				&wd_qinv, &wd_q, &wd_p);
	ret = qm_crypto_bin_to_hpre_bin(wd_dq->data, (const char *)wd_dq->data,
				wd_dq->bsize, wd_dq->dsize);
	if (ret) {
		WD_ERR("rsa crt dq format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(wd_dp->data, (const char *)wd_dp->data,
				wd_dp->bsize, wd_dp->dsize);
	if (ret) {
		WD_ERR("rsa crt dp format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(wd_q->data, (const char *)wd_q->data,
				wd_q->bsize, wd_q->dsize);
	if (ret) {
		WD_ERR("rsa crt q format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(wd_p->data,
		(const char *)wd_p->data, wd_p->bsize, wd_p->dsize);
	if (ret) {
		WD_ERR("rsa crt p format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(wd_qinv->data,
		(const char *)wd_qinv->data, wd_qinv->bsize, wd_qinv->dsize);
	if (ret) {
		WD_ERR("rsa crt qinv format fail!\n");
		return ret;
	}
	*data = wd_dq->data;
	return (int)(wd_dq->bsize + wd_qinv->bsize + wd_p->bsize +
			wd_q->bsize + wd_dp->bsize);
}

static int qm_fill_rsa_prikey1(struct wcrypto_rsa_prikey *prikey, void **data)
{
	struct wd_dtb *wd_d, *wd_n;
	int ret;

	wcrypto_get_rsa_prikey_params(prikey, &wd_d, &wd_n);
	ret = qm_crypto_bin_to_hpre_bin(wd_d->data, (const char *)wd_d->data,
				wd_d->bsize, wd_d->dsize);
	if (ret) {
		WD_ERR("rsa prikey1 d format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize);
	if (ret) {
		WD_ERR("rsa prikey1 n format fail!\n");
		return ret;
	}
	*data = wd_d->data;
	return (int)(wd_n->bsize + wd_d->bsize);
}

static int qm_fill_rsa_pubkey(struct wcrypto_rsa_pubkey *pubkey, void **data)
{
	struct wd_dtb *wd_e, *wd_n;
	int ret;

	wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, &wd_n);
	ret = qm_crypto_bin_to_hpre_bin(wd_e->data, (const char *)wd_e->data,
				wd_e->bsize, wd_e->dsize);
	if (ret) {
		WD_ERR("rsa pubkey e format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize);
	if (ret) {
		WD_ERR("rsa pubkey n format fail!\n");
		return ret;
	}
	*data = wd_e->data;
	return (int)(wd_n->bsize + wd_e->bsize);
}

static int qm_fill_rsa_genkey_in(struct wcrypto_rsa_kg_in *genkey)
{
	struct wd_dtb e, q, p;
	int ret;

	wcrypto_get_rsa_kg_in_params(genkey, &e, &q, &p);

	ret = qm_crypto_bin_to_hpre_bin(e.data, (const char *)e.data,
				e.bsize, e.dsize);
	if (ret) {
		WD_ERR("rsa genkey e format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(q.data, (const char *)q.data,
				q.bsize, q.dsize);
	if (ret) {
		WD_ERR("rsa genkey q format fail!\n");
		return ret;
	}
	ret = qm_crypto_bin_to_hpre_bin(p.data, (const char *)p.data,
				p.bsize, p.dsize);
	if (ret) {
		WD_ERR("rsa genkey p format fail!\n");
		return ret;
	}
	return WD_SUCCESS;
}

static int qm_tri_bin_transfer(struct wd_dtb *bin0, struct wd_dtb *bin1,
				struct wd_dtb *bin2)
{
	int ret;

	ret = qm_hpre_bin_to_crypto_bin(bin0->data, (const char *)bin0->data,
				bin0->bsize);
	if (ret)
		return ret;
	ret = qm_hpre_bin_to_crypto_bin(bin1->data, (const char *)bin1->data,
				bin1->bsize);
	if (ret)
		return ret;
	if (bin2) {
		ret = qm_hpre_bin_to_crypto_bin(bin2->data,
			(const char *)bin2->data, bin2->bsize);
		if (ret)
			return ret;
	}
	return WD_SUCCESS;
}

static int qm_rsa_out_transfer(struct wcrypto_rsa_msg *msg,
				struct hisi_hpre_sqe *hw_msg,
				size_t *in_len,
				size_t *out_len)
{
	struct wcrypto_rsa_kg_out *key = (void *)msg->out;
	__u16 kbytes = msg->key_bytes;
	struct wd_dtb qinv, dq, dp;
	struct wd_dtb d, n;
	int ret;

	wcrypto_get_rsa_kg_out_params(key, &n, &d);

	msg->result = WD_SUCCESS;
	if (hw_msg->alg == HPRE_ALG_KG_CRT) {
		msg->out_bytes = CRT_GEN_PARAMS_SZ(kbytes);
		*in_len = GEN_PARAMS_SZ(kbytes);
		*out_len = msg->out_bytes;
		wcrypto_get_rsa_kg_out_crt_params(key, &qinv, &dq, &dp);
		ret = qm_tri_bin_transfer(&d, &n, NULL);
		if (ret) {
			WD_ERR("parse rsa genkey2 d&&n format fail!\n");
			return ret;
		}
		ret = qm_tri_bin_transfer(&qinv, &dq, &dp);
		if (ret) {
			WD_ERR("parse rsa genkey qinv&&dq&&dp format fail!\n");
			return ret;
		}
	} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
		msg->out_bytes = GEN_PARAMS_SZ(kbytes);
		*out_len = msg->out_bytes;
		*in_len = GEN_PARAMS_SZ(kbytes);

		ret = qm_tri_bin_transfer(&d, &n, NULL);
		if (ret) {
			WD_ERR("parse rsa genkey1 d&&n format fail!\n");
			return ret;
		}
	} else {
		*in_len = kbytes;
		msg->out_bytes = kbytes;
		*out_len = msg->out_bytes;
	}
	return WD_SUCCESS;
}

static int qm_rsa_prepare_key(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg)
{
	int ret;
	void *data;
	uintptr_t phy;

	if (msg->op_type == WCRYPTO_RSA_SIGN) {
		if (hw_msg->alg == HPRE_ALG_NC_CRT) {
			ret = qm_fill_rsa_crt_prikey2((void *)msg->key, &data);
			if (ret <= 0)
				return ret;
		} else {
			ret = qm_fill_rsa_prikey1((void *)msg->key, &data);
			if (ret < 0)
				return ret;
			hw_msg->alg = HPRE_ALG_NC_NCRT;
		}
	} else if (msg->op_type == WCRYPTO_RSA_VERIFY) {
		ret = qm_fill_rsa_pubkey((void *)msg->key, &data);
		if (ret < 0)
			return ret;
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	} else if (msg->op_type == WCRYPTO_RSA_GENKEY) {
		ret = qm_fill_rsa_genkey_in((void *)msg->key);
		if (ret)
			return ret;
		ret = wcrypto_rsa_kg_in_data((void *)msg->key, (char **)&data);
		if (ret < 0) {
			WD_ERR("Get rsa gen key data in fail!\n");
			return ret;
		}
		if (hw_msg->alg == HPRE_ALG_NC_CRT)
			hw_msg->alg = HPRE_ALG_KG_CRT;
		else
			hw_msg->alg = HPRE_ALG_KG_STD;
	} else {
		WD_ERR("Invalid rsa operatin type!\n");
		return -WD_EINVAL;
	}

	phy  = (uintptr_t)drv_iova_map(q, msg->key, ret);
	if (!phy) {
		WD_ERR("Dma map rsa key fail!\n");
		return -WD_ENOMEM;
	}

	phy += (uintptr_t)data - (uintptr_t)msg->key;

	hw_msg->low_key = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_key = HI_U32(phy);
	return WD_SUCCESS;
}

static int qm_rsa_prepare_iot(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_rsa_kg_out *kout = (void *)msg->out;
	int ret = WD_SUCCESS;
	uintptr_t phy;
	void *out;

	if (msg->op_type != WCRYPTO_RSA_GENKEY) {
		phy = (uintptr_t)drv_iova_map(q, msg->in, msg->key_bytes);
		if (!phy) {
			WD_ERR("Get rsa in buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		hw_msg->low_in = (__u32)(phy & QM_L32BITS_MASK);
		hw_msg->hi_in = HI_U32(phy);
		phy = (uintptr_t)drv_iova_map(q, msg->out, msg->key_bytes);
		if (!phy) {
			WD_ERR("Get rsa out key dma address fail!\n");
			return -WD_ENOMEM;
		}
	} else {
		hw_msg->low_in = 0;
		hw_msg->hi_in = 0;
		ret = wcrypto_rsa_kg_out_data(kout, (char **)&out);
		if (ret < 0)
			return ret;
		phy = (uintptr_t)drv_iova_map(q, kout, ret);
		if (!phy) {
			WD_ERR("Get rsa out buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		phy += (uintptr_t)out - (uintptr_t)kout;
	}
	hw_msg->low_out = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_out = HI_U32(phy);
	return ret;
}

int qm_fill_rsa_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_hpre_sqe *hw_msg;
	struct wcrypto_rsa_msg *msg = message;
	struct wcrypto_cb_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	uintptr_t sqe;
	int ret;

	sqe = (uintptr_t)info->sq_base + i * info->sqe_size;
	hw_msg = (struct hisi_hpre_sqe *)sqe;

	if (msg->key_type == WCRYPTO_RSA_PRIKEY1 || msg->key_type == WCRYPTO_RSA_PUBKEY)
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	else if (msg->key_type == WCRYPTO_RSA_PRIKEY2)
		hw_msg->alg = HPRE_ALG_NC_CRT;
	else
		return -WD_EINVAL;
	hw_msg->task_len1 = msg->key_bytes / BYTE_BITS - 0x1;

	/* prepare rsa key */
	ret = qm_rsa_prepare_key(msg, q, hw_msg);
	if (ret < 0)
		return ret;

	/* prepare in/out put */
	ret = qm_rsa_prepare_iot(msg, q, hw_msg);
	if (ret < 0)
		return ret;

	/* This need more processing logic. to do more */
	if (tag)
		hw_msg->tag = tag->ctx_id;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;
	ASSERT(!info->req_cache[i]);
	info->req_cache[i] = msg;

	return WD_SUCCESS;
}

int qm_parse_rsa_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr)
{
	struct wcrypto_rsa_msg *rsa_msg = info->req_cache[i];
	struct hisi_hpre_sqe *hw_msg = msg;
	struct wd_queue *q = info->q;
	__u64 dma_out, dma_in;
	size_t ilen = 0, olen = 0;
	__u16 kbytes;
	int ret;

	ASSERT(rsa_msg);

	/* if this hw msg not belong to me, then try again */
	if (usr && hw_msg->tag != usr)
		return 0;
	kbytes = rsa_msg->key_bytes;
	if (hw_msg->done != HPRE_HW_TASK_DONE || hw_msg->etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "rsa",
			hw_msg->done, hw_msg->etype);
		if (hw_msg->done == HPRE_HW_TASK_INIT) {
			rsa_msg->result = WD_EINVAL;
			ret = -WD_EINVAL;
		} else { /* Need to indentify which hw err happened */
			rsa_msg->result = WD_IN_EPARA;
			ret = -WD_IN_EPARA;
		}

		if (hw_msg->alg == HPRE_ALG_KG_CRT) {
			olen = CRT_GEN_PARAMS_SZ(kbytes);
			ilen = GEN_PARAMS_SZ(kbytes);
		} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
			olen = GEN_PARAMS_SZ(kbytes);
			ilen = GEN_PARAMS_SZ(kbytes);
		} else {
			olen = kbytes;
			ilen = kbytes;
		}
	} else {

		ret = qm_rsa_out_transfer(rsa_msg, hw_msg, &ilen, &olen);
		if (ret) {
			WD_ERR("qm rsa out transfer fail!\n");
			rsa_msg->result = WD_OUT_EPARA;
		} else {
			rsa_msg->result = WD_SUCCESS;
		}
	}

	ret = 1;
	dma_out = DMA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	dma_in = DMA_ADDR(hw_msg->hi_key, hw_msg->low_key);
	drv_iova_unmap(q, rsa_msg->out, (void *)(uintptr_t)dma_out, olen);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_in, ilen);
	return ret;
}

static int qm_fill_dh_xp_params(struct wd_queue *q, struct wcrypto_dh_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	void *x, *p;
	uintptr_t phy;
	int ret;

	x = msg->x_p;
	p = msg->x_p + msg->key_bytes;
	ret = qm_crypto_bin_to_hpre_bin(x, (const char *)x,
				msg->key_bytes, msg->xbytes);
	if (ret) {
		WD_ERR("dh x para format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(p, (const char *)p,
				msg->key_bytes, msg->pbytes);
	if (ret) {
		WD_ERR("dh p para format fail!\n");
		return ret;
	}

	phy = (uintptr_t)drv_iova_map(q, (void *)x,
				GEN_PARAMS_SZ(msg->key_bytes));
	if (!phy) {
		WD_ERR("get dh xp para dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_key = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_key = HI_U32(phy);

	return WD_SUCCESS;
}

static int qm_final_fill_dh_sqe(struct wd_queue *q, struct wcrypto_dh_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_cb_tag *tag = (void *)(uintptr_t)msg->usr_data;
	uintptr_t phy;

	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->key_bytes);
	if (!phy) {
		WD_ERR("Get dh out buf dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_out = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_out = HI_U32(phy);

	/* This need more processing logic. to do more */
	if (tag)
		hw_msg->tag = tag->ctx_id;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;

	return WD_SUCCESS;
}

static int qm_dh_out_transfer(struct wcrypto_dh_msg *msg)
{
	int i = 0;

	while (!msg->out[i])
		i++;
	msg->out_bytes = msg->key_bytes - i;

	return qm_hpre_bin_to_crypto_bin((char *)msg->out,
		(const char *)msg->out, msg->key_bytes);
}

int qm_fill_dh_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_hpre_sqe *hw_msg;
	struct wcrypto_dh_msg *msg = message;
	struct wd_queue *q = info->q;
	uintptr_t phy, sqe;
	int ret;

	sqe = (uintptr_t)info->sq_base + i * info->sqe_size;
	hw_msg = (struct hisi_hpre_sqe *)sqe;

	if (msg->is_g2 && msg->op_type != WCRYPTO_DH_PHASE2)
		hw_msg->alg = HPRE_ALG_DH_G2;
	else
		hw_msg->alg = HPRE_ALG_DH;
	hw_msg->task_len1 = msg->key_bytes / BYTE_BITS - 0x1;
	if (msg->op_type == WCRYPTO_DH_PHASE1 ||
	  msg->op_type == WCRYPTO_DH_PHASE2) {
		if (msg->is_g2 && msg->op_type == WCRYPTO_DH_PHASE1) {
			hw_msg->low_in = 0;
			hw_msg->hi_in = 0;
		} else {

			ret = qm_crypto_bin_to_hpre_bin((char *)msg->g,
				(const char *)msg->g, msg->key_bytes,
				msg->gbytes);
			if (ret) {
				WD_ERR("dh g para format fail!\n");
				return ret;
			}
			phy = (uintptr_t)drv_iova_map(q, (void *)msg->g,
						msg->key_bytes);
			if (!phy) {
				WD_ERR("Get dh g para dma address fail!\n");
				return -WD_ENOMEM;
			}
			hw_msg->low_in = (__u32)(phy & QM_L32BITS_MASK);
			hw_msg->hi_in = HI_U32(phy);
		}

		ret = qm_fill_dh_xp_params(q, msg, hw_msg);
		if (ret)
			return ret;
	}
	ASSERT(!info->req_cache[i]);
	info->req_cache[i] = msg;
	return qm_final_fill_dh_sqe(q, msg, hw_msg);
}

int qm_parse_dh_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr)
{
	struct wcrypto_dh_msg *dh_msg = info->req_cache[i];
	struct hisi_hpre_sqe *hw_msg = msg;
	struct wd_queue *q = info->q;
	__u64 dma_out, dma_in, dma_key;
	int ret;

	ASSERT(dh_msg);
	if (usr && hw_msg->tag != usr)
		return 0;
	if (hw_msg->done != HPRE_HW_TASK_DONE || hw_msg->etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "dh",
			hw_msg->done, hw_msg->etype);
		if (hw_msg->done == HPRE_HW_TASK_INIT) {
			dh_msg->result = WD_EINVAL;
			ret = -WD_EINVAL;
		} else { /* Need to indentify which hw err happened */
			dh_msg->result = WD_IN_EPARA;
			ret = -WD_IN_EPARA;
		}
	} else {
		ret = qm_dh_out_transfer(dh_msg);
		if (ret) {
			dh_msg->result = WD_OUT_EPARA;
			WD_ERR("parse dh format fail!\n");
		} else {
			dh_msg->result = WD_SUCCESS;
		}
	}

	ret = 1;
	dma_out = DMA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	dma_key = DMA_ADDR(hw_msg->hi_key, hw_msg->low_key);
	dma_in = DMA_ADDR(hw_msg->hi_in, hw_msg->hi_in);
	drv_iova_unmap(q, dh_msg->out, (void *)(uintptr_t)dma_out,
				dh_msg->key_bytes);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_in,
		GEN_PARAMS_SZ(dh_msg->key_bytes));
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_key, dh_msg->key_bytes);
	return ret;
}

