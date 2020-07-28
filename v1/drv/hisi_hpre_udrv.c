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

static bool is_hpre_bin_fmt(const char *data, int dsz, int bsz)
{
	const char *temp = data + dsz;
	int lens = bsz - dsz;
	int i = 0;

	while (i < lens) {
		if (temp[i] && !data[i])
			return true;
		i++;
	}

	return false;
}

static int qm_crypto_bin_to_hpre_bin(char *dst, const char *src,
				int b_size, int d_size)
{
	int i = d_size - 1;
	bool is_hpre_bin;
	int j = 0;

	if (!dst || !src || b_size <= 0 || d_size <= 0) {
		WD_ERR("crypto bin to hpre bin params err!\n");
		return -WD_EINVAL;
	}

	if (b_size < d_size) {
		WD_ERR("crypto bin to hpre bin param data is too long!\n");
		return  -WD_EINVAL;
	}

	is_hpre_bin = is_hpre_bin_fmt(src, d_size, b_size);
	if (b_size == d_size || (dst == src && is_hpre_bin))
		return WD_SUCCESS;

	for (j = b_size - 1; j >= 0; j--, i--) {
		if (i >= 0)
			dst[j] = src[i];
		else
			dst[j] = 0;
	}
	return WD_SUCCESS;
}

static int qm_hpre_bin_to_crypto_bin(char *dst, const char *src, int b_size)
{
	int i, cnt;
	int j = 0;
	int k = 0;

	if (!dst || !src || b_size <= 0) {
		WD_ERR("%s params err!\n", __func__);
		return 0;
	}

	while (!src[j] && k < (b_size - 1))
		k = ++j;

	if (j == 0 && src == dst)
		return b_size;

	for (i = 0, cnt = j; i < b_size; j++, i++) {
		if (i < b_size - cnt)
			dst[i] = src[j];
		else
			dst[i] = 0;
	}

	return b_size - k;
}

static int qm_fill_rsa_crt_prikey2(struct wcrypto_rsa_prikey *prikey,
				   void **data)
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
	if (!ret)
		return -WD_EINVAL;

	bin0->dsize = ret;

	if (bin1) {
		ret = qm_hpre_bin_to_crypto_bin(bin1->data,
			(const char *)bin1->data,
					bin1->bsize);
		if (!ret)
			return -WD_EINVAL;

		bin1->dsize = ret;
	}

	if (bin2) {
		ret = qm_hpre_bin_to_crypto_bin(bin2->data,
			(const char *)bin2->data, bin2->bsize);
		if (!ret)
			return -WD_EINVAL;

		bin2->dsize = ret;
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

	msg->result = WD_SUCCESS;
	if (hw_msg->alg == HPRE_ALG_KG_CRT) {
		msg->out_bytes = CRT_GEN_PARAMS_SZ(kbytes);
		*in_len = GEN_PARAMS_SZ(kbytes);
		*out_len = msg->out_bytes;
		wcrypto_get_rsa_kg_out_crt_params(key, &qinv, &dq, &dp);
		ret = qm_tri_bin_transfer(&qinv, &dq, &dp);
		if (ret) {
			WD_ERR("parse rsa genkey qinv&&dq&&dp format fail!\n");
			return ret;
		}

		wcrypto_set_rsa_kg_out_crt_psz(key, qinv.dsize,
					       dq.dsize, dp.dsize);
	} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
		msg->out_bytes = GEN_PARAMS_SZ(kbytes);
		*out_len = msg->out_bytes;
		*in_len = GEN_PARAMS_SZ(kbytes);

		wcrypto_get_rsa_kg_out_params(key, &d, &n);
		ret = qm_tri_bin_transfer(&d, &n, NULL);
		if (ret) {
			WD_ERR("parse rsa genkey1 d&&n format fail!\n");
			return ret;
		}

		wcrypto_set_rsa_kg_out_psz(key, d.dsize, n.dsize);
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

	memset(hw_msg, 0, sizeof(struct hisi_hpre_sqe));

	if (msg->key_type == WCRYPTO_RSA_PRIKEY1 ||
	    msg->key_type == WCRYPTO_RSA_PUBKEY)
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
	size_t ilen = 0;
	size_t olen = 0;
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
		} else { /* Need to indentify which hw err happened */
			rsa_msg->result = WD_IN_EPARA;
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

	dma_out = DMA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	dma_in = DMA_ADDR(hw_msg->hi_key, hw_msg->low_key);
	drv_iova_unmap(q, rsa_msg->out, (void *)(uintptr_t)dma_out, olen);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_in, ilen);
	return 1;
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
	int ret;

	ret = qm_hpre_bin_to_crypto_bin((char *)msg->out,
		(const char *)msg->out, msg->key_bytes);
	if (!ret)
		return -WD_EINVAL;

	msg->out_bytes = ret;

	return WD_SUCCESS;
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

	memset(hw_msg, 0, sizeof(struct hisi_hpre_sqe));

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

	dma_out = DMA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	dma_key = DMA_ADDR(hw_msg->hi_key, hw_msg->low_key);
	dma_in = DMA_ADDR(hw_msg->hi_in, hw_msg->hi_in);
	drv_iova_unmap(q, dh_msg->out, (void *)(uintptr_t)dma_out,
				dh_msg->key_bytes);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_in,
		GEN_PARAMS_SZ(dh_msg->key_bytes));
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_key, dh_msg->key_bytes);
	return 1;
}

static int qm_ecc_prepare_alg(struct hisi_hpre_sqe *hw_msg,
			      struct wcrypto_ecc_msg *msg)
{
	switch (msg->op_type) {
	case WCRYPTO_ECXDH_GEN_KEY:
	case WCRYPTO_ECXDH_COMPUTE_KEY:
		if (msg->alg_type == WCRYPTO_X448 ||
		    msg->alg_type == WCRYPTO_X25519)
			hw_msg->alg = HPRE_ALG_X_DH_MULTIPLY;
		else if (msg->alg_type == WCRYPTO_ECDH)
			hw_msg->alg = HPRE_ALG_ECDH_MULTIPLY;
		break;
	case WCRYPTO_ECDSA_SIGN:
		hw_msg->alg = HPRE_ALG_ECDSA_SIGN;
		break;
	case WCRYPTO_ECDSA_VERIFY:
		hw_msg->alg = HPRE_ALG_ECDSA_VERF;
		break;
	default:
		return -WD_EINVAL;
	}

	return 0;
}

static int trans_cv_param_to_hpre_bin(struct wd_dtb *p, struct wd_dtb *a,
				      struct wd_dtb *b, struct wd_dtb *n,
				      struct wcrypto_ecc_point *g)
{
	int ret;

	ret = qm_crypto_bin_to_hpre_bin(p->data, (const char *)p->data,
					p->bsize, p->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: priv p format error!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(a->data, (const char *)a->data,
					a->bsize, a->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: priv a format error!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(b->data, (const char *)b->data,
					b->bsize, b->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: priv b format error!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(n->data, (const char *)n->data,
					n->bsize, n->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: priv n format error!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(g->x.data, (const char *)g->x.data,
					g->x.bsize, g->x.dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: priv gx format error!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(g->y.data, (const char *)g->y.data,
					g->y.bsize, g->y.dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: priv gy format error!\n");
		return ret;
	}

	return 0;
}

static int trans_d_to_hpre_bin(struct wd_dtb *d)
{
	int ret;

	ret = qm_crypto_bin_to_hpre_bin(d->data, (const char *)d->data,
					d->bsize, d->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: d format error!\n");
		return ret;
	}

	return 0;
}

static bool less_than_latter(struct wd_dtb *d, struct wd_dtb *n)
{
	char *temp = NULL;
	int ret, shift;

	if (d->dsize > n->dsize)
		return false;
	else if (d->dsize < n->dsize)
		return true;

	shift = n->bsize - n->dsize;
	ret = memcmp(d->data + shift, n->data + shift, n->dsize);
	if (ret < 0)
		return true;
	else
		return false;
}

static int ecc_prepare_prikey(struct wcrypto_ecc_key *key, void **data, int id)
{
	struct wcrypto_ecc_point *g = NULL;
	struct wd_dtb *p = NULL;
	struct wd_dtb *a = NULL;
	struct wd_dtb *b = NULL;
	struct wd_dtb *n = NULL;
	struct wd_dtb *d = NULL;
	char bsize, dsize;
	char *dat;
	int ret;

	wcrypto_get_ecc_prikey_params((void *)key, &p, &a, &b, &n, &g, &d);

	ret = trans_cv_param_to_hpre_bin(p, a, b, n, g);
	if (ret)
		return ret;

	ret = trans_d_to_hpre_bin(d);
	if (ret)
		return ret;

	/*
	 * This is a pretreatment of x25519/x448, as described in RFC7748
	 * hpre is big-endian, so the byte is opposite.
	 */
	dat = d->data;
	bsize = d->bsize;
	dsize = d->dsize;
	if (id == WCRYPTO_X25519) {
		dat[31] &= 248;
		dat[0] &= 127;
		dat[0] |= 64;
	} else if (id == WCRYPTO_X448) {
		dat[55 + bsize - dsize] &= 252;
		dat[0 + bsize - dsize] |= 128;
	}

	if (!less_than_latter(d, n)) {
		WD_ERR("failed to prepare ecc prikey: d >= n!\n");
		return -WD_EINVAL;
	}

	*data = p->data;

	return 0;
}

static int trans_pub_to_hpre_bin(struct wcrypto_ecc_point *pub)
{
	struct wd_dtb *temp = NULL;
	int ret;

	temp = &pub->x;
	ret = qm_crypto_bin_to_hpre_bin(temp->data, (const char *)temp->data,
					temp->bsize, temp->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: pub x format error!\n");
		return ret;
	}

	temp = &pub->y;
	ret = qm_crypto_bin_to_hpre_bin(temp->data, (const char *)temp->data,
					temp->bsize, temp->dsize);
	if (ret) {
		WD_ERR("failed to hpre bin: pub y format error!\n");
		return ret;
	}

	return 0;
}

static int ecc_prepare_pubkey(struct wcrypto_ecc_key *key, void **data)
{
	struct wcrypto_ecc_point *pub = NULL;
	struct wcrypto_ecc_point *g = NULL;
	struct wd_dtb *p = NULL;
	struct wd_dtb *a = NULL;
	struct wd_dtb *b = NULL;
	struct wd_dtb *n = NULL;
	int ret;

	wcrypto_get_ecc_pubkey_params((void *)key, &p, &a, &b, &n, &g, &pub);

	ret = trans_cv_param_to_hpre_bin(p, a, b, n, g);
	if (ret)
		return ret;

	ret = trans_pub_to_hpre_bin(pub);
	if (ret)
		return ret;

	*data = p->data;

	return 0;
}

static int qm_ecc_prepare_key(struct wcrypto_ecc_msg *msg, struct wd_queue *q,
			      struct hisi_hpre_sqe *hw_msg)
{
	uintptr_t phy;
	void *data;
	size_t ksz;
	int ret;

	if (msg->op_type == WCRYPTO_ECXDH_GEN_KEY ||
	    msg->op_type == WCRYPTO_ECXDH_COMPUTE_KEY ||
	    msg->op_type == WCRYPTO_ECDSA_SIGN) {
		if (msg->op_type == WCRYPTO_ECXDH_GEN_KEY ||
		    msg->op_type == WCRYPTO_ECXDH_COMPUTE_KEY) {
			if (msg->alg_type == WCRYPTO_X25519 ||
			    msg->alg_type == WCRYPTO_X448)
				ksz = X_DH_HW_KEY_SZ(msg->key_bytes);
			else
				ksz = ECDH_HW_KEY_SZ(msg->key_bytes);
		} else {
			ksz = ECC_PRIKEY_SZ(msg->key_bytes);
		}

		ret = ecc_prepare_prikey((void *)msg->key, &data,
					 msg->alg_type);
		if (ret)
			return ret;
	} else if (msg->op_type == WCRYPTO_ECDSA_VERIFY) {
		ksz = ECC_PUBKEY_SZ(msg->key_bytes);
		ret = ecc_prepare_pubkey((void *)msg->key, &data);
		if (ret)
			return ret;
	} else {
		return -WD_EINVAL;
	}

	phy  = (uintptr_t)drv_iova_map(q, data, ksz);
	if (!phy) {
		WD_ERR("Dma map ecc key fail!\n");
		return -WD_ENOMEM;
	}

	hw_msg->low_key = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_key = HI_U32(phy);

	return 0;
}

static void qm_ecc_get_io_len(__u32 atype, __u32 hsz, size_t *ilen,
			      size_t *olen)
{
	if (atype == HPRE_ALG_ECDH_MULTIPLY) {
		*olen = ECDH_OUT_PARAMS_SZ(hsz);
		*ilen = *olen;
	} else if (atype == HPRE_ALG_X_DH_MULTIPLY) {
		*olen = X_DH_OUT_PARAMS_SZ(hsz);
		*ilen = *olen;
	} else if (atype == HPRE_ALG_ECDSA_SIGN) {
		*olen = ECC_SIGN_OUT_PARAMS_SZ(hsz);
		*ilen = ECC_SIGN_IN_PARAMS_SZ(hsz);
	} else if (atype == HPRE_ALG_ECDSA_VERF) {
		*olen = ECC_VERF_OUT_PARAMS_SZ;
		*ilen = ECC_VERF_IN_PARAMS_SZ(hsz);
	} else {
		*olen = hsz;
		*ilen = hsz;
	}
}

static int ecc_prepare_dh_compute_in(struct wcrypto_ecc_in *in, void **data)
{
	struct wcrypto_ecc_point *pbk = NULL;
	int ret;

	wcrypto_get_ecxdh_in_params(in, &pbk);
	if (!pbk) {
		WD_ERR("failed to get ecxdh in param!\n");
		return -WD_EINVAL;
	}

	ret = qm_crypto_bin_to_hpre_bin(pbk->x.data, (const char *)pbk->x.data,
					pbk->x.bsize, pbk->x.dsize);
	if (ret) {
		WD_ERR("ecc dh compute in x format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(pbk->y.data, (const char *)pbk->y.data,
					pbk->y.bsize, pbk->y.dsize);
	if (ret) {
		WD_ERR("ecc dh compute in y format fail!\n");
		return ret;
	}

	*data = pbk->x.data;

	return 0;
}

static void correct_random(struct wd_dtb *k)
{
	int lens = k->bsize - k->dsize;

	k->data[lens] = 0;
}

static int ecc_prepare_sign_in(struct wcrypto_ecc_msg *msg, void **data)
{
	struct wcrypto_ecc_in *in = (struct wcrypto_ecc_in *)msg->in;
	struct wd_dtb *n = NULL;
	struct wd_dtb *e = NULL;
	struct wd_dtb *k = NULL;
	__u8 k_set;
	int ret;

	wcrypto_get_ecdsa_sign_in_params(in, &e, &k);
	if (!e || !k) {
		WD_ERR("failed to get ecdsa sign in param!\n");
		return -WD_EINVAL;
	}

	k_set = *(__u8 *)(k + 1);
	if (!k_set) {
		WD_ERR("random k not set!\n");
		return -WD_EINVAL;
	}

	ret = qm_crypto_bin_to_hpre_bin(e->data, (const char *)e->data,
					e->bsize, e->dsize);
	if (ret) {
		WD_ERR("ecc sign in e format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(k->data, (const char *)k->data,
					k->bsize, k->dsize);
	if (ret) {
		WD_ERR("ecc sign in k format fail!\n");
		return ret;
	}

	wcrypto_get_ecc_prikey_params((void *)msg->key, NULL, NULL, NULL,
				      &n, NULL, NULL);
	if (!less_than_latter(k, n))
		correct_random(k);

	*data = e->data;

	return 0;
}

static int ecc_prepare_verf_in(struct wcrypto_ecc_in *in, void **data)
{
	struct wd_dtb *e = NULL;
	struct wd_dtb *s = NULL;
	struct wd_dtb *r = NULL;
	int ret;

	wcrypto_get_ecdsa_verf_in_params(in, &e, &s, &r);
	if (!e || !r || !s) {
		WD_ERR("failed to get verf in param!\n");
		return -WD_EINVAL;
	}

	ret = qm_crypto_bin_to_hpre_bin(e->data, (const char *)e->data,
					e->bsize, e->dsize);
	if (ret) {
		WD_ERR("ecc sign in e format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(s->data, (const char *)s->data,
					s->bsize, s->dsize);
	if (ret) {
		WD_ERR("ecc sign in s format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(r->data, (const char *)r->data,
					r->bsize, r->dsize);
	if (ret) {
		WD_ERR("ecc sign in r format fail!\n");
		return ret;
	}

	*data = e->data;

	return 0;
}

static int ecc_prepare_dh_gen_in(struct wcrypto_ecc_point *in, void **data)
{
	int ret;

	ret = qm_crypto_bin_to_hpre_bin(in->x.data, (const char *)in->x.data,
					in->x.bsize, in->x.dsize);
	if (ret) {
		WD_ERR("ecc dh gen in x format fail!\n");
		return ret;
	}

	ret = qm_crypto_bin_to_hpre_bin(in->y.data, (const char *)in->y.data,
					in->y.bsize, in->y.dsize);
	if (ret) {
		WD_ERR("ecc dh gen in y format fail!\n");
		return ret;
	}

	*data = in->x.data;

	return 0;
}

static int u_is_in_p(struct wcrypto_ecc_msg *msg)
{
	struct wcrypto_ecc_in *in =  (struct wcrypto_ecc_in *)msg->in;
	struct wcrypto_ecc_point *pbk = NULL;
	struct wd_dtb *p = NULL;

	wcrypto_get_ecc_prikey_params((void *)msg->key, &p, NULL, NULL,
				      NULL, NULL, NULL);

	wcrypto_get_ecxdh_in_params(in, &pbk);
	if (!pbk) {
		WD_ERR("failed to get ecxdh in param!\n");
		return -WD_EINVAL;
	}

	/*
	 * In big-endian order, when receving u-array, implementations of X25519
	 * shold mask the most significant bit in the 1st byte.
	 * See RFC7748 for details;
	 */
	if (msg->alg_type == WCRYPTO_X25519)
		pbk->x.data[0] &= 0x7f;

	if (!less_than_latter(&pbk->x, p)) {
		WD_ERR("ux is out of p!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int qm_ecc_prepare_in(struct wcrypto_ecc_msg *msg, void **data)
{
	struct wcrypto_ecc_in *in = (struct wcrypto_ecc_in *)msg->in;
	int ret = -WD_EINVAL;

	switch (msg->op_type) {
	case WCRYPTO_ECXDH_GEN_KEY:
		ret = ecc_prepare_dh_gen_in((struct wcrypto_ecc_point *)in,
					    data);
		break;
	case WCRYPTO_ECXDH_COMPUTE_KEY:
		ret = ecc_prepare_dh_compute_in(in, data);

		/*
		 * when compute x25519/x448, we should guarantee u < p,
		 * or it is invalid.
		 */
		if (ret == 0 && (msg->alg_type == WCRYPTO_X25519 ||
		    msg->alg_type == WCRYPTO_X448))
			ret = u_is_in_p(msg);

		break;
	case WCRYPTO_ECDSA_SIGN:
		ret = ecc_prepare_sign_in(msg, data);
		break;
	case WCRYPTO_ECDSA_VERIFY:
		ret = ecc_prepare_verf_in(in, data);
		break;
	default:
		break;
	}

	return ret;
}

static int ecc_prepare_dh_out(struct wcrypto_ecc_out *out, void **data)
{
	struct wcrypto_ecc_point *dh_out = NULL;

	wcrypto_get_ecxdh_out_params(out, &dh_out);
	if (!dh_out) {
		WD_ERR("failed to get ecxdh out param!\n");
		return -WD_EINVAL;
	}

	*data = dh_out->x.data;

	return 0;
}

static int ecc_prepare_sign_out(struct wcrypto_ecc_out *out, void **data)
{
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;

	wcrypto_get_ecdsa_sign_out_params(out, &r, &s);
	if (!r || !s) {
		WD_ERR("failed to get ecdsa sign out param!\n");
		return -WD_EINVAL;
	}

	*data = r->data;

	return 0;
}

static int qm_ecc_prepare_out(struct wcrypto_ecc_msg *msg, void **data)
{
	struct wcrypto_ecc_out *out = (struct wcrypto_ecc_out *)msg->out;
	int ret = -WD_EINVAL;

	switch (msg->op_type) {
	case WCRYPTO_ECXDH_GEN_KEY:
	case WCRYPTO_ECXDH_COMPUTE_KEY:
		ret = ecc_prepare_dh_out(out, data);
		break;

	case WCRYPTO_ECDSA_SIGN:
		ret = ecc_prepare_sign_out(out, data);
		break;

	case WCRYPTO_ECDSA_VERIFY:
		ret = 0;
		break;
	}

	return ret;
}

/* prepare in/out hw msg */
static int qm_ecc_prepare_iot(struct wcrypto_ecc_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg)
{
	size_t i_sz, o_sz;
	void *data = NULL;
	uintptr_t phy;
	__u16 kbytes;
	int ret;

	kbytes = msg->key_bytes;
	qm_ecc_get_io_len(hw_msg->alg, kbytes, &i_sz, &o_sz);
	ret = qm_ecc_prepare_in(msg, &data);
	if (ret) {
		WD_ERR("qm_ecc_prepare_in fail!\n");
		return ret;
	}

	phy = (uintptr_t)drv_iova_map(q, data, i_sz);
	if (!phy) {
		WD_ERR("Get ecc in buf dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_in = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_in = HI_U32(phy);

	ret = qm_ecc_prepare_out(msg, &data);
	if (ret) {
		WD_ERR("qm_ecc_prepare_out fail!\n");
		return ret;
	}

	if (!data)
		return 0;

	phy = (uintptr_t)drv_iova_map(q, data, o_sz);
	if (!phy) {
		WD_ERR("Get ecc out key dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_out = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_out = HI_U32(phy);

	return 0;
}

static int ecdh_out_transfer(struct wcrypto_ecc_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_ecc_out *out = (void *)msg->out;
	struct wcrypto_ecc_point *key;
	struct wd_dtb *y = NULL;
	int ret;

	wcrypto_get_ecxdh_out_params(out, &key);

	if (hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY)
		y = &key->y;

	ret = qm_tri_bin_transfer(&key->x, y, NULL);
	if (ret) {
		WD_ERR("parse ecdh out format fail!\n");
		return ret;
	}

	return WD_SUCCESS;
}

static int ecc_sign_out_transfer(struct wcrypto_ecc_msg *msg,
				 struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_ecc_out *out = (void *)msg->out;
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	int ret;

	wcrypto_get_ecdsa_sign_out_params(out, &r, &s);
	if (!r || !s) {
		WD_ERR("failed to get ecdsa sign out param!\n");
		return -WD_EINVAL;
	}

	ret = qm_tri_bin_transfer(r, s, NULL);
	if (ret) {
		WD_ERR("parse ecc sign out format fail!\n");
		return ret;
	}

	return WD_SUCCESS;
}

static int ecc_verf_out_transfer(struct wcrypto_ecc_msg *msg,
				 struct hisi_hpre_sqe *hw_msg)
{
	__u32 result = hw_msg->low_out;

	result >>= 1;
	result &= 1;
	if (!result)
		msg->result = WD_VERIFY_ERR;

	return WD_SUCCESS;
}

static int qm_ecc_out_transfer(struct wcrypto_ecc_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	int ret = -WD_EINVAL;

	if (hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY ||
	    hw_msg->alg == HPRE_ALG_X_DH_MULTIPLY)
		ret = ecdh_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_ECDSA_SIGN)
		ret = ecc_sign_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_ECDSA_VERF)
		ret = ecc_verf_out_transfer(msg, hw_msg);
	else
		WD_ERR("ecc out trans fail alg %d error!\n", hw_msg->alg);

	return ret;
}

int qm_fill_ecc_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_ecc_msg *msg = message;
	struct wcrypto_cb_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	struct hisi_hpre_sqe *hw_msg;
	uintptr_t sqe;
	int ret;

	sqe = (uintptr_t)info->sq_base + i * info->sqe_size;
	hw_msg = (struct hisi_hpre_sqe *)sqe;

	memset(hw_msg, 0, sizeof(struct hisi_hpre_sqe));
	hw_msg->task_len1 = msg->key_bytes / BYTE_BITS - 0x1;

	/* prepare alg */
	ret = qm_ecc_prepare_alg(hw_msg, msg);
	if (ret)
		return ret;

	/* prepare key */
	ret = qm_ecc_prepare_key(msg, q, hw_msg);
	if (ret)
		return ret;

	/* prepare in/out put */
	ret = qm_ecc_prepare_iot(msg, q, hw_msg);
	if (ret)
		return ret;

	/* This need more processing logic. to do more */
	if (tag)
		hw_msg->tag = tag->ctx_id;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;
	ASSERT(!info->req_cache[i]);
	info->req_cache[i] = msg;

	ASSERT(!info->req_cache[i]);
	info->req_cache[i] = msg;

	return WD_SUCCESS;
}

int qm_parse_ecc_sqe(void *msg, const struct qm_queue_info *info,
		     __u16 i, __u16 usr)
{
	struct wcrypto_ecc_msg *ecc_msg = info->req_cache[i];
	struct hisi_hpre_sqe *hw_msg = msg;
	__u64 dma_out, dma_in, dma_key;
	struct wd_queue *q = info->q;
	size_t ilen = 0;
	size_t olen = 0;
	__u16 kbytes;
	int ret;

	ASSERT(ecc_msg);

	/* if this hw msg not belong to me, then try again */
	if (usr && hw_msg->tag != usr)
		return 0;

	kbytes = ecc_msg->key_bytes;
	qm_ecc_get_io_len(hw_msg->alg, kbytes, &ilen, &olen);
	if (hw_msg->done != HPRE_HW_TASK_DONE || hw_msg->etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "ecc",
			hw_msg->done, hw_msg->etype);

		if (hw_msg->done == HPRE_HW_TASK_INIT)
			ecc_msg->result = WD_EINVAL;
		else /* Need to indentify which hw err happened */
			ecc_msg->result = WD_IN_EPARA;
	} else {
		ecc_msg->result = WD_SUCCESS;
		ret = qm_ecc_out_transfer(ecc_msg, hw_msg);
		if (ret) {
			WD_ERR("qm ecc out transfer fail!\n");
			ecc_msg->result = WD_OUT_EPARA;
		}
	}

	dma_out = DMA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	dma_key = DMA_ADDR(hw_msg->hi_key, hw_msg->low_key);
	dma_in = DMA_ADDR(hw_msg->hi_in, hw_msg->hi_in);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_in, olen);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_out, olen);
	drv_iova_unmap(q, NULL, (void *)(uintptr_t)dma_key, kbytes);

	return 1;
}

