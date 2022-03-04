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
#include "v1/wd_util.h"
#include "hisi_hpre_udrv.h"

#define MAX_WAIT_CNT			10000000
#define SM2_KEY_SIZE			32
#define MAX_HASH_LENS			BITS_TO_BYTES(521)
#define HW_PLAINTEXT_BYTES_MAX		BITS_TO_BYTES(4096)

/* realize with hardware ecc multiplication, avoid conflict with wd_ecc.h */
#define HPRE_SM2_ENC	0xE
#define HPRE_SM2_DEC	0xF

#define SM2_SQE_NUM			2

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
				     int b_size, int d_size, const char *p_name)
{
	int i = d_size - 1;
	bool is_hpre_bin;
	int j;

	if (unlikely(!dst || !src || b_size <= 0 || d_size <= 0)) {
		WD_ERR("%s trans to hpre bin: parameters err!\n", p_name);
		return -WD_EINVAL;
	}

	if (unlikely(b_size < d_size)) {
		WD_ERR("%s trans to hpre bin: parameter data is too long!\n", p_name);
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

static int qm_hpre_bin_to_crypto_bin(char *dst, const char *src, int b_size,
				     const char *p_name)
{
	int i, cnt;
	int j = 0;
	int k = 0;

	if (unlikely(!dst || !src || b_size <= 0)) {
		WD_ERR("%s trans to crypto bin: parameters err!\n", p_name);
		return 0;
	}

	while (!src[j] && k < b_size - 1)
		k = ++j;

	if (!j && src == dst)
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
	struct wd_dtb *wd_qinv = NULL;
	struct wd_dtb *wd_dq = NULL;
	struct wd_dtb *wd_dp = NULL;
	struct wd_dtb *wd_q = NULL;
	struct wd_dtb *wd_p = NULL;
	int ret;

	wcrypto_get_rsa_crt_prikey_params(prikey, &wd_dq, &wd_dp,
				&wd_qinv, &wd_q, &wd_p);
	if (unlikely(!wd_dq || !wd_dp || !wd_qinv || !wd_q || !wd_p)) {
		WD_ERR("failed to get rsa crt prikey params!\n");
		return -WD_EINVAL;
	}

	ret = qm_crypto_bin_to_hpre_bin(wd_dq->data, (const char *)wd_dq->data,
				wd_dq->bsize, wd_dq->dsize, "rsa crt dq");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(wd_dp->data, (const char *)wd_dp->data,
				wd_dp->bsize, wd_dp->dsize, "rsa crt dp");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(wd_q->data, (const char *)wd_q->data,
				wd_q->bsize, wd_q->dsize, "rsa crt q");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(wd_p->data,
		(const char *)wd_p->data, wd_p->bsize, wd_p->dsize, "rsa crt p");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(wd_qinv->data,
		(const char *)wd_qinv->data, wd_qinv->bsize,
		wd_qinv->dsize, "rsa crt qinv");
	if (unlikely(ret))
		return ret;

	*data = wd_dq->data;
	return (int)(wd_dq->bsize + wd_qinv->bsize + wd_p->bsize +
			wd_q->bsize + wd_dp->bsize);
}

static int qm_fill_rsa_prikey1(struct wcrypto_rsa_prikey *prikey, void **data)
{
	struct wd_dtb *wd_d = NULL;
	struct wd_dtb *wd_n = NULL;
	int ret;

	wcrypto_get_rsa_prikey_params(prikey, &wd_d, &wd_n);
	if (unlikely(!wd_d || !wd_n)) {
		WD_ERR("failed to get rsa prikey params!\n");
		return -WD_EINVAL;
	}

	ret = qm_crypto_bin_to_hpre_bin(wd_d->data, (const char *)wd_d->data,
				wd_d->bsize, wd_d->dsize, "rsa prikey1 d");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize, "rsa prikey1 n");
	if (unlikely(ret))
		return ret;

	*data = wd_d->data;
	return (int)(wd_n->bsize + wd_d->bsize);
}

static int qm_fill_rsa_pubkey(struct wcrypto_rsa_pubkey *pubkey, void **data)
{
	struct wd_dtb *wd_e = NULL;
	struct wd_dtb *wd_n = NULL;
	int ret;

	wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, &wd_n);
	ret = qm_crypto_bin_to_hpre_bin(wd_e->data, (const char *)wd_e->data,
				wd_e->bsize, wd_e->dsize, "rsa pubkey e");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize, "rsa pubkey n");
	if (unlikely(ret))
		return ret;

	*data = wd_e->data;
	return (int)(wd_n->bsize + wd_e->bsize);
}

static int qm_fill_rsa_genkey_in(struct wcrypto_rsa_kg_in *genkey)
{
	struct wd_dtb e = {0};
	struct wd_dtb q = {0};
	struct wd_dtb p = {0};
	int ret;

	wcrypto_get_rsa_kg_in_params(genkey, &e, &q, &p);
	ret = qm_crypto_bin_to_hpre_bin(e.data, (const char *)e.data,
				e.bsize, e.dsize, "rsa kg e");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(q.data, (const char *)q.data,
				q.bsize, q.dsize, "rsa kg q");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(p.data, (const char *)p.data,
				p.bsize, p.dsize, "rsa kg p");
	if (unlikely(ret))
		return ret;

	return WD_SUCCESS;
}

static int qm_tri_bin_transfer(struct wd_dtb *bin0, struct wd_dtb *bin1,
				struct wd_dtb *bin2, const char *p_name)
{
	int ret;

	ret = qm_hpre_bin_to_crypto_bin(bin0->data, (const char *)bin0->data,
				bin0->bsize, p_name);
	if (unlikely(!ret))
		return -WD_EINVAL;

	bin0->dsize = ret;

	if (bin1) {
		ret = qm_hpre_bin_to_crypto_bin(bin1->data,
			(const char *)bin1->data, bin1->bsize, p_name);
		if (unlikely(!ret))
			return -WD_EINVAL;

		bin1->dsize = ret;
	}

	if (bin2) {
		ret = qm_hpre_bin_to_crypto_bin(bin2->data,
			(const char *)bin2->data, bin2->bsize, p_name);
		if (unlikely(!ret))
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
	struct wd_dtb qinv = {0};
	struct wd_dtb dq = {0};
	struct wd_dtb dp = {0};
	struct wd_dtb d = {0};
	struct wd_dtb n = {0};
	int ret;

	msg->result = WD_SUCCESS;
	if (hw_msg->alg == HPRE_ALG_KG_CRT) {
		msg->out_bytes = CRT_GEN_PARAMS_SZ(kbytes);
		*in_len = GEN_PARAMS_SZ(kbytes);
		*out_len = msg->out_bytes;
		wcrypto_get_rsa_kg_out_crt_params(key, &qinv, &dq, &dp);
		ret = qm_tri_bin_transfer(&qinv, &dq, &dp, "rsa kg qinv&dp&dq");
		if (unlikely(ret))
			return ret;

		wcrypto_set_rsa_kg_out_crt_psz(key, qinv.dsize,
					       dq.dsize, dp.dsize);
	} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
		msg->out_bytes = GEN_PARAMS_SZ(kbytes);
		*out_len = msg->out_bytes;
		*in_len = GEN_PARAMS_SZ(kbytes);

		wcrypto_get_rsa_kg_out_params(key, &d, &n);
		ret = qm_tri_bin_transfer(&d, &n, NULL, "rsa kg d & n");
		if (unlikely(ret))
			return ret;

		wcrypto_set_rsa_kg_out_psz(key, d.dsize, n.dsize);
	} else {
		*in_len = kbytes;
		msg->out_bytes = kbytes;
		*out_len = msg->out_bytes;
	}
	return WD_SUCCESS;
}

static void rsa_key_unmap(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
			  struct hisi_hpre_sqe *hw_msg,
			  const void *va, int size)
{
	struct wcrypto_rsa_kg_out *key = (void *)msg->key;
	uintptr_t phy;

	phy = DMA_ADDR(hw_msg->low_key, hw_msg->hi_key);
	phy -= (uintptr_t)va - (uintptr_t)key;

	drv_iova_unmap(q, msg->key, (void *)phy, size);
}

static int rsa_prepare_sign_key(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg, void **va)
{
	void *data = NULL;
	int ret;

	if (hw_msg->alg == HPRE_ALG_NC_CRT) {
		ret = qm_fill_rsa_crt_prikey2((void *)msg->key, &data);
		if (unlikely(ret <= 0))
			return 0;
	} else {
		ret = qm_fill_rsa_prikey1((void *)msg->key, &data);
		if (unlikely(ret <= 0))
			return 0;
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	}

	*va = data;

	return ret;
}

static int rsa_prepare_kg_key(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
			      struct hisi_hpre_sqe *hw_msg, void **va)
{
	void *data = NULL;
	int ret;

	ret = qm_fill_rsa_genkey_in((void *)msg->key);
	if (unlikely(ret))
		return 0;

	ret = wcrypto_rsa_kg_in_data((void *)msg->key, (char **)&data);
	if (unlikely(ret <= 0)) {
		WD_ERR("Get rsa gen key data in fail!\n");
		return 0;
	}
	if (hw_msg->alg == HPRE_ALG_NC_CRT)
		hw_msg->alg = HPRE_ALG_KG_CRT;
	else
		hw_msg->alg = HPRE_ALG_KG_STD;

	*va = data;

	return ret;
}

static int qm_rsa_prepare_key(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg,
				void **va, int *size)
{
	void *data = NULL;
	uintptr_t phy;
	int ret;

	if (msg->op_type == WCRYPTO_RSA_SIGN) {
		ret = rsa_prepare_sign_key(msg, q, hw_msg, &data);
		if (unlikely(ret <= 0))
			return -WD_EINVAL;
	} else if (msg->op_type == WCRYPTO_RSA_VERIFY) {
		ret = qm_fill_rsa_pubkey((void *)msg->key, &data);
		if (unlikely(ret <= 0))
			return -WD_EINVAL;
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	} else if (msg->op_type == WCRYPTO_RSA_GENKEY) {
		ret = rsa_prepare_kg_key(msg, q, hw_msg, &data);
		if (unlikely(ret <= 0))
			return -WD_EINVAL;
	} else {
		WD_ERR("Invalid rsa operation type!\n");
		return -WD_EINVAL;
	}

	phy  = (uintptr_t)drv_iova_map(q, msg->key, ret);
	if (unlikely(!phy)) {
		WD_ERR("Dma map rsa key fail!\n");
		return -WD_ENOMEM;
	}

	phy += (uintptr_t)data - (uintptr_t)msg->key;

	hw_msg->low_key = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_key = HI_U32(phy);
	*va = data;
	*size = ret;

	return WD_SUCCESS;
}

static int qm_rsa_prepare_iot(struct wcrypto_rsa_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_rsa_kg_out *kout = (void *)msg->out;
	uintptr_t phy;
	void *out;
	int ret;

	if (msg->op_type != WCRYPTO_RSA_GENKEY) {
		phy = (uintptr_t)drv_iova_map(q, msg->in, msg->key_bytes);
		if (!phy) {
			WD_ERR("Get rsa in buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		hw_msg->low_in = (__u32)(phy & QM_L32BITS_MASK);
		hw_msg->hi_in = HI_U32(phy);
		phy = (uintptr_t)drv_iova_map(q, msg->out, msg->key_bytes);
		if (unlikely(!phy)) {
			WD_ERR("Get rsa out key dma address fail!\n");
			phy = DMA_ADDR(hw_msg->hi_in, hw_msg->low_in);
			drv_iova_unmap(q, msg->in, (void *)phy, msg->key_bytes);
			return -WD_ENOMEM;
		}
	} else {
		hw_msg->low_in = 0;
		hw_msg->hi_in = 0;
		ret = wcrypto_rsa_kg_out_data(kout, (char **)&out);
		if (unlikely(ret <= 0))
			return -WD_EINVAL;
		phy = (uintptr_t)drv_iova_map(q, kout, ret);
		if (!phy) {
			WD_ERR("Get rsa out buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		phy += (uintptr_t)out - (uintptr_t)kout;
	}
	hw_msg->low_out = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_out = HI_U32(phy);
	return WD_SUCCESS;
}

int qm_fill_rsa_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_hpre_sqe *hw_msg;
	struct wcrypto_rsa_msg *msg = message;
	struct wcrypto_cb_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	void *va = NULL;
	uintptr_t sqe;
	int size = 0;
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
	ret = qm_rsa_prepare_key(msg, q, hw_msg, &va, &size);
	if (unlikely(ret))
		return ret;

	/* prepare in/out put */
	ret = qm_rsa_prepare_iot(msg, q, hw_msg);
	if (unlikely(ret)) {
		rsa_key_unmap(msg, q, hw_msg, va, size);
		return ret;
	}

	/* This need more processing logic. */
	if (tag)
		hw_msg->low_tag = tag->ctx_id;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;
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

	if (unlikely(!rsa_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	/* if this hardware message not belong to me, then try again */
	if (usr && LOW_U16(hw_msg->low_tag) != usr)
		return 0;
	kbytes = rsa_msg->key_bytes;
	if (hw_msg->done != HPRE_HW_TASK_DONE || hw_msg->etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "rsa",
			hw_msg->done, hw_msg->etype);
		if (hw_msg->done == HPRE_HW_TASK_INIT) {
			rsa_msg->result = WD_EINVAL;
		} else { /* Need to identify which hw err happened */
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
		if (unlikely(ret)) {
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

static int fill_dh_g_param(struct wd_queue *q, struct wcrypto_dh_msg *msg,
			    struct hisi_hpre_sqe *hw_msg)
{
	uintptr_t phy;
	int ret;

	ret = qm_crypto_bin_to_hpre_bin((char *)msg->g,
		(const char *)msg->g, msg->key_bytes,
		msg->gbytes, "dh g");
	if (unlikely(ret))
		return ret;

	phy = (uintptr_t)drv_iova_map(q, (void *)msg->g,
				msg->key_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Get dh g parameter dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_in = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_in = HI_U32(phy);

	return 0;
}

static void dh_g_unmap(struct wcrypto_dh_msg *msg, struct wd_queue *q,
		       struct hisi_hpre_sqe *hw_msg)
{
	uintptr_t phy = DMA_ADDR(hw_msg->low_in, hw_msg->hi_in);
	if (phy)
		drv_iova_unmap(q, msg->g, (void *)phy, msg->key_bytes);
}

static void dh_xp_unmap(struct wcrypto_dh_msg *msg, struct wd_queue *q,
			struct hisi_hpre_sqe *hw_msg)
{
	uintptr_t phy = DMA_ADDR(hw_msg->low_key, hw_msg->hi_key);

	drv_iova_unmap(q, msg->x_p, (void *)phy, GEN_PARAMS_SZ(msg->key_bytes));
}

static int qm_fill_dh_xp_params(struct wd_queue *q, struct wcrypto_dh_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	uintptr_t phy;
	void *x, *p;
	int ret;

	x = msg->x_p;
	p = msg->x_p + msg->key_bytes;
	ret = qm_crypto_bin_to_hpre_bin(x, (const char *)x,
				msg->key_bytes, msg->xbytes, "dh x");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(p, (const char *)p,
				msg->key_bytes, msg->pbytes, "dh p");
	if (unlikely(ret))
		return ret;

	phy = (uintptr_t)drv_iova_map(q, (void *)x,
				GEN_PARAMS_SZ(msg->key_bytes));
	if (unlikely(!phy)) {
		WD_ERR("get dh xp parameter dma address fail!\n");
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
	if (unlikely(!phy)) {
		WD_ERR("Get dh out buffer dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_out = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_out = HI_U32(phy);

	/* This need more processing logic. */
	if (tag)
		hw_msg->low_tag = tag->ctx_id;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;

	return WD_SUCCESS;
}

static int qm_dh_out_transfer(struct wcrypto_dh_msg *msg)
{
	int ret;

	ret = qm_hpre_bin_to_crypto_bin((char *)msg->out,
		(const char *)msg->out, msg->key_bytes, "dh out");
	if (unlikely(!ret))
		return -WD_EINVAL;

	msg->out_bytes = ret;

	return WD_SUCCESS;
}

int qm_fill_dh_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_dh_msg *msg = message;
	struct hisi_hpre_sqe *hw_msg;
	struct wd_queue *q = info->q;
	uintptr_t sqe;
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
			ret = fill_dh_g_param(q, msg, hw_msg);
			if (unlikely(ret))
				return ret;
		}

		ret = qm_fill_dh_xp_params(q, msg, hw_msg);
		if (unlikely(ret))
			goto map_xp_fail;
	}
	info->req_cache[i] = msg;

	ret = qm_final_fill_dh_sqe(q, msg, hw_msg);
	if (unlikely(ret))
		goto map_out_fail;

	return 0;

map_out_fail:
	dh_xp_unmap(msg, q, hw_msg);
map_xp_fail:
	dh_g_unmap(msg, q, hw_msg);

	return ret;
}

int qm_parse_dh_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr)
{
	struct wcrypto_dh_msg *dh_msg = info->req_cache[i];
	struct hisi_hpre_sqe *hw_msg = msg;
	__u64 dma_out, dma_in, dma_key;
	struct wd_queue *q = info->q;
	int ret;

	if (unlikely(!dh_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	if (usr && LOW_U16(hw_msg->low_tag) != usr)
		return 0;
	if (hw_msg->done != HPRE_HW_TASK_DONE || hw_msg->etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "dh",
			hw_msg->done, hw_msg->etype);
		if (hw_msg->done == HPRE_HW_TASK_INIT) {
			dh_msg->result = WD_EINVAL;
			ret = -WD_EINVAL;
		} else { /* Need to identify which hw err happened */
			dh_msg->result = WD_IN_EPARA;
			ret = -WD_IN_EPARA;
		}
	} else {
		ret = qm_dh_out_transfer(dh_msg);
		if (unlikely(ret)) {
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
	case HPRE_SM2_ENC: /* fall through */
	case HPRE_SM2_DEC: /* fall through */
		hw_msg->alg = HPRE_ALG_ECDH_MULTIPLY;
		break;
	case WCRYPTO_ECDSA_SIGN:
		hw_msg->alg = HPRE_ALG_ECDSA_SIGN;
		break;
	case WCRYPTO_ECDSA_VERIFY:
		hw_msg->alg = HPRE_ALG_ECDSA_VERF;
		break;
	case WCRYPTO_SM2_ENCRYPT:
		hw_msg->alg = HPRE_ALG_SM2_ENC;
		break;
	case WCRYPTO_SM2_DECRYPT:
		hw_msg->alg = HPRE_ALG_SM2_DEC;
		break;
	case WCRYPTO_SM2_SIGN:
		hw_msg->alg = HPRE_ALG_SM2_SIGN;
		break;
	case WCRYPTO_SM2_VERIFY:
		hw_msg->alg = HPRE_ALG_SM2_VERF;
		break;
	case WCRYPTO_SM2_KG:
		hw_msg->alg = HPRE_ALG_SM2_KEY_GEN;
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
					p->bsize, p->dsize, "cv p");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(a->data, (const char *)a->data,
					a->bsize, a->dsize, "cv a");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(b->data, (const char *)b->data,
					b->bsize, b->dsize, "cv b");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(n->data, (const char *)n->data,
					n->bsize, n->dsize, "cv n");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(g->x.data, (const char *)g->x.data,
					g->x.bsize, g->x.dsize, "cv gx");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(g->y.data, (const char *)g->y.data,
					g->y.bsize, g->y.dsize, "cv gy");
	if (unlikely(ret))
		return ret;

	return 0;
}

static int trans_d_to_hpre_bin(struct wd_dtb *d)
{
	int ret;

	ret = qm_crypto_bin_to_hpre_bin(d->data, (const char *)d->data,
					d->bsize, d->dsize, "ecc d");
	if (unlikely(ret))
		return ret;

	return 0;
}

static bool less_than_latter(struct wd_dtb *d, struct wd_dtb *n)
{
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
	if (unlikely(ret))
		return ret;

	ret = trans_d_to_hpre_bin(d);
	if (unlikely(ret))
		return ret;

	dat = d->data;
	bsize = d->bsize;
	dsize = d->dsize;

	/*
	 * This is a pretreatment of X25519/X448, as described in RFC 7748:
	 * For X25519, in order to decode 32 random bytes as an integer
	 * scaler, set the three LSB of the first byte and MSB of the last
	 * to zero, set the second MSB of the last byte to 1.
	 * For X448, set the two LSB of the first byte to 0, and MSB of the
	 * last byte to 1. Decode in little-endian mode.
	 * HPRE hardware module uses big-endian mode, so the bytes to be
	 * set are reversed compared to RFC 7748:
	 * For example, dat[0] of X25519 in RFC 7748 is reversed to dat[31]
	 * in HPRE specification, so does X448.
	 */
	if (id == WCRYPTO_X25519) {
		dat[31] &= 248;
		dat[0] &= 127;
		dat[0] |= 64;
	} else if (id == WCRYPTO_X448) {
		dat[55 + bsize - dsize] &= 252;
		dat[0 + bsize - dsize] |= 128;
	}

	if (id != WCRYPTO_X25519 && id != WCRYPTO_X448 &&
	    !less_than_latter(d, n)) {
		WD_ERR("failed to prepare ecc prikey: d >= n!\n");
		return -WD_EINVAL;
	}

	*data = p->data;

	return 0;
}

static int trans_pub_to_hpre_bin(struct wcrypto_ecc_point *pub)
{
	struct wd_dtb *temp;
	int ret;

	temp = &pub->x;
	ret = qm_crypto_bin_to_hpre_bin(temp->data, (const char *)temp->data,
					temp->bsize, temp->dsize, "ecc pub x");
	if (unlikely(ret))
		return ret;

	temp = &pub->y;
	ret = qm_crypto_bin_to_hpre_bin(temp->data, (const char *)temp->data,
					temp->bsize, temp->dsize, "ecc pub y");
	if (unlikely(ret))
		return ret;

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
	if (unlikely(ret))
		return ret;

	ret = trans_pub_to_hpre_bin(pub);
	if (unlikely(ret))
		return ret;

	*data = p->data;

	return 0;
}

static __u32 ecc_get_prikey_size(struct wcrypto_ecc_msg *msg)
{
	if (msg->op_type == WCRYPTO_SM2_SIGN ||
		msg->op_type == WCRYPTO_ECDSA_SIGN ||
		msg->op_type == WCRYPTO_SM2_DECRYPT)
		return ECC_PRIKEY_SZ(msg->key_bytes);
	else if (msg->alg_type == WCRYPTO_X25519 ||
		msg->alg_type == WCRYPTO_X448)
		return X_DH_HW_KEY_SZ(msg->key_bytes);
	else
		return ECDH_HW_KEY_SZ(msg->key_bytes);
}

static void ecc_key_unmap(struct wcrypto_ecc_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg,
				void *va, int size)
{
	uintptr_t phy;

	phy = DMA_ADDR(hw_msg->low_key, hw_msg->hi_key);
	drv_iova_unmap(q, va, (void *)phy, size);
}

static bool is_prikey_used(__u8 op_type)
{
	return op_type == WCRYPTO_ECXDH_GEN_KEY ||
	       op_type == WCRYPTO_ECXDH_COMPUTE_KEY ||
	       op_type == WCRYPTO_ECDSA_SIGN ||
	       op_type == WCRYPTO_SM2_DECRYPT ||
	       op_type == WCRYPTO_SM2_SIGN ||
	       op_type == HPRE_SM2_ENC ||
	       op_type == HPRE_SM2_DEC;
}

static int qm_ecc_prepare_key(struct wcrypto_ecc_msg *msg, struct wd_queue *q,
			      struct hisi_hpre_sqe *hw_msg,
			      void **va, int *size)
{
	__u8 op_type = msg->op_type;
	void *data = NULL;
	uintptr_t phy;
	size_t ksz;
	int ret;

	if (unlikely(!op_type || (op_type >= WCRYPTO_EC_OP_MAX &&
		op_type != HPRE_SM2_ENC && op_type != HPRE_SM2_DEC))) {
		WD_ERR("op_type = %u error!\n", op_type);
		return -WD_EINVAL;
	}

	if (is_prikey_used(msg->op_type)) {
		ksz = ecc_get_prikey_size(msg);
		ret = ecc_prepare_prikey((void *)msg->key, &data,
					 msg->alg_type);
		if (unlikely(ret))
			return ret;
	} else {
		ksz = ECC_PUBKEY_SZ(msg->key_bytes);
		ret = ecc_prepare_pubkey((void *)msg->key, &data);
		if (unlikely(ret))
			return ret;
	}

	phy  = (uintptr_t)drv_iova_map(q, data, ksz);
	if (unlikely(!phy)) {
		WD_ERR("Dma map ecc key fail!\n");
		return -WD_ENOMEM;
	}

	hw_msg->low_key = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_key = HI_U32(phy);
	*va = data;
	*size = ksz;

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
	if (unlikely(!pbk)) {
		WD_ERR("failed to get ecxdh in param!\n");
		return -WD_EINVAL;
	}

	ret = qm_crypto_bin_to_hpre_bin(pbk->x.data, (const char *)pbk->x.data,
		pbk->x.bsize, pbk->x.dsize, "ecdh pbk x");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(pbk->y.data, (const char *)pbk->y.data,
		pbk->y.bsize, pbk->y.dsize, "ecdh pbk y");
	if (unlikely(ret))
		return ret;

	*data = pbk->x.data;

	return 0;
}

static void correct_random(struct wd_dtb *k)
{
	int lens = k->bsize - k->dsize;

	k->data[lens] = 0;
}

static bool is_all_zero(struct wd_dtb *e, struct wcrypto_ecc_msg *msg,
			const char *p_name)
{
	int i;

	for (i = 0; i < e->dsize && i < msg->key_bytes; i++) {
		if (e->data[i])
			return false;
	}

	WD_ERR("error: %s all zero!\n", p_name);

	return true;
}

static int ecc_prepare_sign_in(struct wcrypto_ecc_msg *msg,
			       struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wcrypto_ecc_sign_in *in = (void *)msg->in;
	struct wd_dtb *n = NULL;
	struct wd_dtb *e = NULL;
	struct wd_dtb *k = NULL;
	int ret;

	if (!in->dgst_set) {
		WD_ERR("hash not set!\n");
		return -WD_EINVAL;
	}

	k = &in->k;
	e = &in->dgst;
	if (!in->k_set) {
		if (msg->op_type != WCRYPTO_SM2_SIGN) {
			WD_ERR("random k not set!\n");
			return -WD_EINVAL;
		}
		hw_msg->sm2_ksel = 1;
	} else if (is_all_zero(k, msg, "ecc sgn k")) {
		return -WD_EINVAL;
	}

	if (is_all_zero(e, msg, "ecc sgn e"))
		return -WD_EINVAL;

	ret = qm_crypto_bin_to_hpre_bin(e->data, (const char *)e->data,
					e->bsize, e->dsize, "ecc sgn e");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(k->data, (const char *)k->data,
					k->bsize, k->dsize, "ecc sgn k");
	if (unlikely(ret))
		return ret;

	wcrypto_get_ecc_prikey_params((void *)msg->key, NULL, NULL, NULL,
				      &n, NULL, NULL);
	if (!less_than_latter(k, n))
		correct_random(k);

	*data = e->data;

	return 0;
}

static int ecc_prepare_verf_in(struct wcrypto_ecc_msg *msg, void **data)
{
	struct wcrypto_ecc_verf_in *vin = (void *)msg->in;
	struct wd_dtb *e = NULL;
	struct wd_dtb *s = NULL;
	struct wd_dtb *r = NULL;
	int ret;

	if (!vin->dgst_set) {
		WD_ERR("hash not set!\n");
		return -WD_EINVAL;
	}

	e = &vin->dgst;
	s = &vin->s;
	r = &vin->r;

	if (is_all_zero(e, msg, "ecc vrf e"))
		return -WD_EINVAL;

	ret = qm_crypto_bin_to_hpre_bin(e->data, (const char *)e->data,
					e->bsize, e->dsize, "ecc vrf e");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(s->data, (const char *)s->data,
					s->bsize, s->dsize, "ecc vrf s");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(r->data, (const char *)r->data,
					r->bsize, r->dsize, "ecc vrf r");
	if (unlikely(ret))
		return ret;

	*data = e->data;

	return 0;
}

static int ecc_prepare_dh_gen_in(struct wcrypto_ecc_point *in, void **data)
{
	int ret;

	ret = qm_crypto_bin_to_hpre_bin(in->x.data, (const char *)in->x.data,
					in->x.bsize, in->x.dsize, "ecdh gen x");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(in->y.data, (const char *)in->y.data,
					in->y.bsize, in->y.dsize, "ecdh gen y");
	if (unlikely(ret))
		return ret;

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
	if (unlikely(!pbk)) {
		WD_ERR("failed to get ecxdh in param!\n");
		return -WD_EINVAL;
	}

	/*
	 * In big-endian order, when receiving u-array, implementations of X25519
	 * should mask the most significant bit in the 1st byte.
	 * See RFC 7748 for details;
	 */
	if (msg->alg_type == WCRYPTO_X25519)
		pbk->x.data[0] &= 0x7f;

	if (!less_than_latter(&pbk->x, p)) {
		WD_ERR("ux is out of p!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int ecc_prepare_sm2_enc_in(struct wcrypto_ecc_msg *msg,
				  struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wcrypto_sm2_enc_in *ein = (void *)msg->in;
	struct wd_dtb *k = &ein->k;
	int ret;

	if (ein->k_set) {
		if (is_all_zero(k, msg, "sm2 enc k"))
			return -WD_EINVAL;

		ret = qm_crypto_bin_to_hpre_bin(k->data, (const char *)k->data,
						k->bsize, k->dsize, "sm2 enc k");
		if (unlikely(ret))
			return ret;
	} else {
		hw_msg->sm2_ksel = 1;
	}

	hw_msg->sm2_mlen = ein->plaintext.dsize - 1;
	*data = k->data;

	return 0;
}

static int ecc_prepare_sm2_dec_in(struct wcrypto_ecc_msg *msg,
				  struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wcrypto_sm2_dec_in *din = (void *)msg->in;
	struct wcrypto_ecc_point *c1 = &din->c1;
	int ret;

	ret = qm_crypto_bin_to_hpre_bin(c1->x.data, (const char *)c1->x.data,
		c1->x.bsize, c1->x.dsize, "sm2 dec c1 x");
	if (unlikely(ret))
		return ret;

	ret = qm_crypto_bin_to_hpre_bin(c1->y.data, (const char *)c1->y.data,
		c1->y.bsize, c1->y.dsize, "sm2 dec c1 y");
	if (unlikely(ret))
		return ret;

	hw_msg->sm2_mlen = din->c2.dsize - 1;
	*data = c1->x.data;

	return 0;
}

static int qm_ecc_prepare_in(struct wcrypto_ecc_msg *msg,
			     struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wcrypto_ecc_in *in = (struct wcrypto_ecc_in *)msg->in;
	int ret = -WD_EINVAL;

	switch (msg->op_type) {
	case HPRE_SM2_ENC: /* fall through */
	case HPRE_SM2_DEC: /* fall through */
		hw_msg->bd_rsv2 = 1; /* fall through */
	case WCRYPTO_ECXDH_GEN_KEY: /* fall through */
	case WCRYPTO_SM2_KG:
		ret = ecc_prepare_dh_gen_in((struct wcrypto_ecc_point *)in,
					    data);
		break;
	case WCRYPTO_ECXDH_COMPUTE_KEY:
		/*
		 * when compute x25519/x448, we should guarantee u < p,
		 * or it is invalid.
		 */
		ret = ecc_prepare_dh_compute_in(in, data);
		if (ret == 0 && (msg->alg_type == WCRYPTO_X25519 ||
		    msg->alg_type == WCRYPTO_X448))
			ret = u_is_in_p(msg);
		break;
	case WCRYPTO_ECDSA_SIGN:
	case WCRYPTO_SM2_SIGN:
		ret = ecc_prepare_sign_in(msg, hw_msg, data);
		break;
	case WCRYPTO_ECDSA_VERIFY:
	case WCRYPTO_SM2_VERIFY:
		ret = ecc_prepare_verf_in(msg, data);
		break;
	case WCRYPTO_SM2_ENCRYPT:
		ret = ecc_prepare_sm2_enc_in(msg, hw_msg, data);
		break;
	case WCRYPTO_SM2_DECRYPT:
		ret = ecc_prepare_sm2_dec_in(msg, hw_msg, data);
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
	if (unlikely(!dh_out)) {
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
	if (unlikely(!r || !s)) {
		WD_ERR("failed to get ecdsa sign out param!\n");
		return -WD_EINVAL;
	}

	*data = r->data;

	return 0;
}

static int ecc_prepare_sm2_enc_out(struct wcrypto_ecc_out *out, void **data)
{
	struct wcrypto_ecc_point *c1 = NULL;

	wcrypto_get_sm2_enc_out_params(out, &c1, NULL, NULL);
	if (unlikely(!c1)) {
		WD_ERR("failed to get sm2 enc out param!\n");
		return -WD_EINVAL;
	}

	*data = c1->x.data;

	return 0;
}

static int ecc_prepare_sm2_dec_out(struct wcrypto_ecc_out *out, void **data)
{
	struct wd_dtb *m = NULL;

	wcrypto_get_sm2_dec_out_params(out, &m);
	if (unlikely(!m)) {
		WD_ERR("failed to get sm2 dec out param!\n");
		return -WD_EINVAL;
	}

	*data = m->data;

	return 0;
}

static int ecc_prepare_sm2_kg_out(struct wcrypto_ecc_out *out, void **data)
{
	struct wcrypto_ecc_point *pub = NULL;

	wcrypto_get_sm2_kg_out_params(out, NULL, &pub);
	if (unlikely(!pub)) {
		WD_ERR("failed to get sm2 kg out param!\n");
		return -WD_EINVAL;
	}

	*data = pub->x.data;

	return 0;
}
static int qm_ecc_prepare_out(struct wcrypto_ecc_msg *msg, void **data)
{
	struct wcrypto_ecc_out *out = (struct wcrypto_ecc_out *)msg->out;
	int ret = 0;

	switch (msg->op_type) {
	case WCRYPTO_ECXDH_GEN_KEY:
	case WCRYPTO_ECXDH_COMPUTE_KEY:
	case HPRE_SM2_ENC: /* fall through */
	case HPRE_SM2_DEC: /* fall through */
		if (msg->op_type == HPRE_SM2_ENC ||
			msg->op_type == HPRE_SM2_DEC)
			*data = out;
		else
			ret = ecc_prepare_dh_out(out, data);
		break;
	case WCRYPTO_ECDSA_SIGN:
	case WCRYPTO_SM2_SIGN:
		ret = ecc_prepare_sign_out(out, data);
		break;
	case WCRYPTO_ECDSA_VERIFY:
	case WCRYPTO_SM2_VERIFY:
		break;
	case WCRYPTO_SM2_ENCRYPT:
		ret = ecc_prepare_sm2_enc_out(out, data);
		break;
	case WCRYPTO_SM2_DECRYPT:
		ret = ecc_prepare_sm2_dec_out(out, data);
		break;
	case WCRYPTO_SM2_KG:
		ret = ecc_prepare_sm2_kg_out(out, data);
		break;
	}

	return ret;
}

/* prepare in/out hardware message */
static int qm_ecc_prepare_iot(struct wcrypto_ecc_msg *msg, struct wd_queue *q,
				struct hisi_hpre_sqe *hw_msg)
{
	void *data = NULL;
	size_t i_sz = 0;
	size_t o_sz = 0;
	uintptr_t phy;
	__u16 kbytes;
	void *va;
	int ret;

	kbytes = msg->key_bytes;
	qm_ecc_get_io_len(hw_msg->alg, kbytes, &i_sz, &o_sz);
	ret = qm_ecc_prepare_in(msg, hw_msg, &data);
	if (unlikely(ret)) {
		WD_ERR("qm_ecc_prepare_in fail!\n");
		return ret;
	}

	va = data;
	phy = (uintptr_t)drv_iova_map(q, va, i_sz);
	if (unlikely(!phy)) {
		WD_ERR("Get ecc in buf dma address fail!\n");
		return -WD_ENOMEM;
	}
	hw_msg->low_in = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_in = HI_U32(phy);

	ret = qm_ecc_prepare_out(msg, &data);
	if (unlikely(ret)) {
		WD_ERR("qm_ecc_prepare_out fail!\n");
		goto map_fail;
	}

	if (!data)
		return 0;

	phy = (uintptr_t)drv_iova_map(q, data, o_sz);
	if (unlikely(!phy)) {
		WD_ERR("Get ecc out key dma address fail!\n");
		ret = -WD_ENOMEM;
		goto map_fail;
	}
	hw_msg->low_out = (__u32)(phy & QM_L32BITS_MASK);
	hw_msg->hi_out = HI_U32(phy);

	return 0;

map_fail:
	phy = DMA_ADDR(hw_msg->hi_in, hw_msg->low_in);
	drv_iova_unmap(q, va, (void *)phy, i_sz);

	return ret;
}

static int ecdh_out_transfer(struct wcrypto_ecc_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_ecc_out *out = (void *)msg->out;
	struct wcrypto_ecc_point *key = NULL;
	struct wd_dtb *y = NULL;

	if (msg->op_type == HPRE_SM2_DEC || msg->op_type == HPRE_SM2_ENC)
		return WD_SUCCESS;

	wcrypto_get_ecxdh_out_params(out, &key);
	if (unlikely(!key)) {
		WD_ERR("failed to get ecxdh out param!\n");
		return -WD_EINVAL;
	}

	if (hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY)
		y = &key->y;

	return qm_tri_bin_transfer(&key->x, y, NULL, "ecdh out x & y");
}

static int ecc_sign_out_transfer(struct wcrypto_ecc_msg *msg,
				 struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_ecc_out *out = (void *)msg->out;
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;

	wcrypto_get_ecdsa_sign_out_params(out, &r, &s);
	if (unlikely(!r || !s)) {
		WD_ERR("failed to get ecdsa sign out param!\n");
		return -WD_EINVAL;
	}

	return qm_tri_bin_transfer(r, s, NULL, "ecc sign r&s");
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

static int sm2_kg_out_transfer(struct wcrypto_ecc_msg *msg,
			       struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_ecc_out *out = (void *)msg->out;
	struct wcrypto_ecc_point *pubkey = NULL;
	struct wd_dtb *prk = NULL;

	wcrypto_get_sm2_kg_out_params(out, &prk, &pubkey);
	if (unlikely(!prk || !pubkey)) {
		WD_ERR("failed to get sm2 kg out param!\n");
		return -WD_EINVAL;
	}

	return qm_tri_bin_transfer(prk, &pubkey->x, &pubkey->y, "sm2 kg out");
}

static int sm2_enc_out_transfer(struct wcrypto_ecc_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wcrypto_ecc_out *out = (void *)msg->out;
	struct wcrypto_ecc_point *c1 = NULL;

	wcrypto_get_sm2_enc_out_params(out, &c1, NULL, NULL);
	if (unlikely(!c1)) {
		WD_ERR("failed to get sm2 enc out param!\n");
		return -WD_EINVAL;
	}

	return qm_tri_bin_transfer(&c1->x, &c1->y, NULL, "sm2 enc out");
}

static int qm_ecc_out_transfer(struct wcrypto_ecc_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	int ret = -WD_EINVAL;

	if (hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY ||
	    hw_msg->alg == HPRE_ALG_X_DH_MULTIPLY)
		ret = ecdh_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_ECDSA_SIGN ||
		hw_msg->alg == HPRE_ALG_SM2_SIGN)
		ret = ecc_sign_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_ECDSA_VERF ||
		hw_msg->alg == HPRE_ALG_SM2_VERF)
		ret = ecc_verf_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_SM2_ENC)
		ret = sm2_enc_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_SM2_DEC)
		ret = 0;
	else if (hw_msg->alg == HPRE_ALG_SM2_KEY_GEN)
		ret = sm2_kg_out_transfer(msg, hw_msg);
	else
		WD_ERR("ecc out trans fail alg %u error!\n", hw_msg->alg);

	return ret;
}

static int qm_fill_ecc_sqe_general(void *message, struct qm_queue_info *info,
				  __u16 i)
{
	struct wcrypto_ecc_msg *msg = message;
	struct wcrypto_cb_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	struct hisi_hpre_sqe *hw_msg;
	void *va = NULL;
	uintptr_t sqe;
	int size = 0;
	int ret;

	sqe = (uintptr_t)info->sq_base + i * info->sqe_size;
	hw_msg = (struct hisi_hpre_sqe *)sqe;

	memset(hw_msg, 0, sizeof(struct hisi_hpre_sqe));
	hw_msg->task_len1 = msg->key_bytes / BYTE_BITS - 0x1;

	/* prepare algorithm */
	ret = qm_ecc_prepare_alg(hw_msg, msg);
	if (unlikely(ret))
		return ret;

	/* prepare key */
	ret = qm_ecc_prepare_key(msg, q, hw_msg, &va, &size);
	if (unlikely(ret))
		return ret;

	/* prepare in/out put */
	ret = qm_ecc_prepare_iot(msg, q, hw_msg);
	if (unlikely(ret))
		goto map_key_fail;

	/* This need more processing logic. */
	if (tag)
		hw_msg->low_tag = tag->ctx_id;
	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;
	info->req_cache[i] = msg;

	return WD_SUCCESS;

map_key_fail:
	ecc_key_unmap(msg, q, hw_msg, va, size);

	return ret;
}

static void init_prikey(struct wcrypto_ecc_prikey *prikey, __u32 bsz)
{
	prikey->p.dsize = 0;
	prikey->p.bsize = bsz;
	prikey->p.data = prikey->data;
	prikey->a.dsize = 0;
	prikey->a.bsize = bsz;
	prikey->a.data = prikey->p.data + bsz;
	prikey->d.dsize = 0;
	prikey->d.bsize = bsz;
	prikey->d.data = prikey->a.data + bsz;
	prikey->b.dsize = 0;
	prikey->b.bsize = bsz;
	prikey->b.data = prikey->d.data + bsz;
	prikey->n.dsize = 0;
	prikey->n.bsize = bsz;
	prikey->n.data = prikey->b.data + bsz;
	prikey->g.x.dsize = 0;
	prikey->g.x.bsize = bsz;
	prikey->g.x.data = prikey->n.data + bsz;
	prikey->g.y.dsize = 0;
	prikey->g.y.bsize = bsz;
	prikey->g.y.data = prikey->g.x.data + bsz;
}

static int set_param(struct wd_dtb *dst, const struct wd_dtb *src,
		     const char *p_name)
{
	if (unlikely(!src || !src->data)) {
		WD_ERR("%s: src or data NULL!\n", p_name);
		return -WD_EINVAL;
	}

	if (unlikely(!src->dsize || src->dsize > dst->bsize)) {
		WD_ERR("%s: src dsz = %u error, dst bsz = %u!\n",
			p_name, src->dsize, dst->bsize);
		return -WD_EINVAL;
	}

	dst->dsize = src->dsize;
	memset(dst->data, 0, dst->bsize);
	memcpy(dst->data, src->data, src->dsize);

	return 0;
}

static int set_prikey(struct wcrypto_ecc_prikey *prikey,
		      struct wcrypto_ecc_msg *req)
{
	struct wcrypto_ecc_key *key = (struct wcrypto_ecc_key *)req->key;
	struct wcrypto_sm2_enc_in *ein = (void *)req->in;
	struct wcrypto_ecc_pubkey *pubkey = key->pubkey;
	int ret;

	ret = set_param(&prikey->p, &pubkey->p, "p");
	if (unlikely(ret))
		return ret;

	ret = set_param(&prikey->a, &pubkey->a, "a");
	if (unlikely(ret))
		return ret;

	ret = set_param(&prikey->d, &ein->k, "k");
	if (unlikely(ret))
		return ret;

	ret = set_param(&prikey->b, &pubkey->b, "b");
	if (unlikely(ret))
		return ret;

	ret = set_param(&prikey->n, &pubkey->n, "n");
	if (unlikely(ret))
		return ret;

	ret = set_param(&prikey->g.x, &pubkey->g.x, "gx");
	if (unlikely(ret))
		return ret;

	return set_param(&prikey->g.y, &pubkey->g.y, "gy");
}

static int init_req(struct wcrypto_ecc_msg *dst, struct wcrypto_ecc_msg *src,
		     struct wcrypto_ecc_key *key, struct qm_queue_info *info,
		     __u8 req_idx)
{
	struct wcrypto_ecc_key *ecc_key = (struct wcrypto_ecc_key *)src->key;
	struct wcrypto_ecc_pubkey *pubkey = ecc_key->pubkey;
	struct q_info *qinfo = info->q->qinfo;
	struct wd_mm_br *br = &qinfo->br;
	__u32 ksz = src->key_bytes;

	memcpy(dst, src, sizeof(*dst));
	dst->key = (void *)key;
	dst->op_type = HPRE_SM2_ENC;
	*(struct wcrypto_ecc_msg **)(dst + 1) = src;

	dst->out = br->alloc(br->usr, ECDH_OUT_PARAMS_SZ(ksz));
	if (unlikely(!dst->out))
		return -WD_ENOMEM;

	if (!req_idx)
		dst->in = (void *)&pubkey->g;
	else
		dst->in = (void *)&pubkey->pub;

	return 0;
}

static struct wcrypto_ecc_msg *create_req(struct wcrypto_ecc_msg *src,
					  struct qm_queue_info *info,
					  __u8 req_idx)
{
	struct q_info *qinfo = info->q->qinfo;
	struct wcrypto_ecc_prikey *prikey;
	struct wd_mm_br *br = &qinfo->br;
	struct wcrypto_ecc_key *ecc_key;
	struct wcrypto_ecc_msg *dst;
	int ret;

	/* dst last store point "struct wcrypto_ecc_msg *" */
	dst = malloc(sizeof(*dst) + sizeof(struct wcrypto_ecc_msg *));
	if (unlikely(!dst))
		return NULL;

	ecc_key = malloc(sizeof(*ecc_key) + sizeof(*prikey));
	if (unlikely(!ecc_key))
		goto fail_alloc_key;

	prikey = (struct wcrypto_ecc_prikey *)(ecc_key + 1);
	ecc_key->prikey = prikey;
	prikey->data = br->alloc(br->usr, ECC_PRIKEY_SZ(src->key_bytes));
	if (unlikely(!prikey->data)) {
		WD_ERR("failed to br alloc\n");
		goto fail_alloc_key_data;
	}
	init_prikey(prikey, src->key_bytes);
	ret = set_prikey(prikey, src);
	if (unlikely(ret))
		goto fail_set_prikey;

	ret = init_req(dst, src, ecc_key, info, req_idx);
	if (unlikely(ret)) {
		WD_ERR("failed to init req, ret = %d\n", ret);
		goto fail_set_prikey;
	}

	return dst;

fail_set_prikey:
	br->free(br->usr, prikey->data);
fail_alloc_key_data:
	free(ecc_key);
fail_alloc_key:
	free(dst);

	return NULL;
}

static void free_req(struct qm_queue_info *info, struct wcrypto_ecc_msg *req)
{
	struct wcrypto_ecc_key *key = (void *)req->key;
	struct q_info *qinfo = info->q->qinfo;
	struct wd_mm_br *br = &qinfo->br;

	br->free(br->usr, key->prikey->data);
	free(req->key);
	br->free(br->usr, req->out);
	free(req);
}

static int split_req(struct qm_queue_info *info,
		     struct wcrypto_ecc_msg *src, struct wcrypto_ecc_msg **dst)
{
	/* k * G */
	dst[0] = create_req(src, info, 0);
	if (unlikely(!dst[0]))
		return -WD_ENOMEM;

	/* k * pub */
	dst[1] = create_req(src, info, 1);
	if (unlikely(!dst[1])) {
		free_req(info, dst[0]);
		return -WD_ENOMEM;
	}

	return 0;
}

static int fill_sm2_enc_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_hash_mt *hash = &((struct q_info *)info->q->qinfo)->hash;
	struct wcrypto_ecc_msg *req_src = message;
	struct wcrypto_sm2_enc_in *ein = (void *)req_src->in;
	struct wcrypto_ecc_msg *req_dst[2] = {NULL};
	struct wd_dtb *plaintext = &ein->plaintext;
	int ret;

	if (plaintext->dsize <= HW_PLAINTEXT_BYTES_MAX &&
		req_src->hash_type == WCRYPTO_HASH_SM3)
		return qm_fill_ecc_sqe_general(req_src, info, i);

	if (unlikely(!ein->k_set)) {
		WD_ERR("error: k not set\n");
		return -WD_EINVAL;
	}

	if (unlikely(!hash->cb || hash->type >= WCRYPTO_HASH_MAX)) {
		WD_ERR("hash parameter error, type = %u\n", hash->type);
		return -WD_EINVAL;
	}

	if (unlikely(__atomic_load_n(&info->used, __ATOMIC_RELAXED) >
		    QM_Q_DEPTH - SM2_SQE_NUM - 1)) {
		WD_ERR("fill sm2 enc sqe: queue is full!\n");
		return -WD_EBUSY;
	}

	/* split message into two inner request msg
	 * firest msg used to compute k * g
	 * second msg used to compute k * pb
	 */
	ret = split_req(info, req_src, req_dst);
	if (unlikely(ret)) {
		WD_ERR("failed to split req, ret = %d\n", ret);
		return ret;
	}

	ret = qm_fill_ecc_sqe_general(req_dst[0], info,  i);
	if (unlikely(ret)) {
		WD_ERR("failed to fill 1th sqe, ret = %d\n", ret);
		goto fail_fill_sqe;
	}

	i = (i + 1) % QM_Q_DEPTH;
	ret = qm_fill_ecc_sqe_general(req_dst[1], info, i);
	if (unlikely(ret)) {
		WD_ERR("failed to fill 2th sqe, ret = %d\n", ret);
		goto fail_fill_sqe;
	}

	/* make sure the request is all in memory before doorbell */
	mb();
	info->sq_tail_index = i;
	qm_tx_update(info, 1);

	return ret;

fail_fill_sqe:
	free_req(info, req_dst[0]);
	free_req(info, req_dst[1]);

	return ret;
}

static int fill_sm2_dec_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_hash_mt *hash = &((struct q_info *)info->q->qinfo)->hash;
	struct wcrypto_ecc_msg *req_src = message;
	struct wcrypto_sm2_dec_in *din = (void *)req_src->in;
	struct q_info *qinfo = info->q->qinfo;
	struct wd_mm_br *br = &qinfo->br;
	__u32 ksz = req_src->key_bytes;
	struct wcrypto_ecc_msg *dst;
	int ret;

	/* c2 data lens <= 4096 bit */
	if (din->c2.dsize <= BITS_TO_BYTES(4096) &&
		req_src->hash_type == WCRYPTO_HASH_SM3)
		return qm_fill_ecc_sqe_general(req_src, info, i);

	if (unlikely(!hash->cb || hash->type >= WCRYPTO_HASH_MAX)) {
		WD_ERR("hash parameter error, type = %u\n", hash->type);
		return -WD_EINVAL;
	}

	/* dst last store point "struct wcrypto_ecc_msg *" */
	dst = malloc(sizeof(*dst) + sizeof(struct wcrypto_ecc_msg *));
	if (unlikely(!dst))
		return -WD_ENOMEM;

	/* compute d * c1 */
	memcpy(dst, req_src, sizeof(*dst));

	dst->op_type = HPRE_SM2_DEC;
	*(struct wcrypto_ecc_msg **)(dst + 1) = req_src;
	dst->in = (void *)&din->c1;
	dst->out = br->alloc(br->usr, ECDH_OUT_PARAMS_SZ(ksz));
	if (unlikely(!dst->out)) {
		ret = -WD_ENOMEM;
		goto free_dst;
	}

	ret = qm_fill_ecc_sqe_general(dst, info, i);
	if (ret)
		goto free_out;

	return ret;

free_out:
	br->free(br->usr, dst->out);
free_dst:
	free(dst);
	return ret;
}

int qm_fill_ecc_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_ecc_msg *msg = message;

	if (msg->op_type == WCRYPTO_SM2_ENCRYPT)
		return fill_sm2_enc_sqe(message, info, i);
	else if (msg->op_type == WCRYPTO_SM2_DECRYPT)
		return fill_sm2_dec_sqe(message, info, i);
	else
		return qm_fill_ecc_sqe_general(message, info, i);
}

static int qm_parse_ecc_sqe_general(void *msg, const struct qm_queue_info *info,
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

	if (unlikely(!ecc_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	/* if this hw msg not belong to me, then try again */
	if (usr && LOW_U16(hw_msg->low_tag) != usr)
		return 0;

	kbytes = ecc_msg->key_bytes;
	qm_ecc_get_io_len(hw_msg->alg, kbytes, &ilen, &olen);
	if (hw_msg->done != HPRE_HW_TASK_DONE ||
			hw_msg->etype || hw_msg->etype1) {
		WD_ERR("HPRE do ecc fail!done=0x%x, etype=0x%x, etype1=0x%x\n",
			hw_msg->done, hw_msg->etype, hw_msg->etype1);

		if (hw_msg->done == HPRE_HW_TASK_INIT)
			ecc_msg->result = WD_EINVAL;
		else /* Need to indentify which hw err happened */
			ecc_msg->result = WD_IN_EPARA;
	} else {
		ecc_msg->result = WD_SUCCESS;
		ret = qm_ecc_out_transfer(ecc_msg, hw_msg);
		if (unlikely(ret)) {
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

static int parse_first_sqe(void *hw_msg, struct qm_queue_info *info, __u16 i,
			   __u16 usr)
{
	struct wcrypto_ecc_msg *msg = info->req_cache[i];
	struct wcrypto_ecc_msg *msg_src;
	int ret;

	ret = qm_parse_ecc_sqe_general(hw_msg, info, i, usr);
	if (!ret)
		return ret;

	msg_src = *(struct wcrypto_ecc_msg **)(msg + 1);
	msg_src->result = msg->result;
	info->req_cache[i] = NULL;
	if (i == QM_Q_DEPTH - 1) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else {
		i++;
	}

	if (msg->result != WD_SUCCESS)
		WD_ERR("first BD error = %u\n", msg->result);

	info->cq_head_index = i;
	qm_rx_update(info, 1);

	return 1;
}

static int parse_second_sqe(void *hw_msg, struct qm_queue_info *info, __u16 i,
			    __u16 usr, struct wcrypto_ecc_msg *msg_src)
{
	struct wcrypto_ecc_msg *msg;
	int ret = -WD_EIO;
	void *sqe = NULL;
	struct cqe *cqe;
	int cnt = 0;
	void *resp;
	__u16 j;

	while (1) {
		/* continue recv second cqe */
		cqe = info->cq_base + i * sizeof(struct cqe);
		if (info->cqc_phase == CQE_PHASE(cqe)) {
			/* make sure the request is all in memory before doorbell */
			mb();
			j = CQE_SQ_HEAD_INDEX(cqe);
			if (j >= QM_Q_DEPTH) {
				WD_ERR("2th CQE_SQ_HEAD_INDEX(%u) error\n", j);
				return ret;
			}

			msg = info->req_cache[i];
			sqe = (void *)((uintptr_t)info->sq_base +
				j * info->sqe_size);
			ret = qm_parse_ecc_sqe_general(sqe, info, i, usr);
			if (unlikely(!ret))
				return ret;
			break;
		}

		if (unlikely(wd_reg_read(info->ds_rx_base) == 1)) {
			qm_rx_from_cache(info, &resp, 1);
			return -WD_HW_EACCESS;
		}

		if (cnt++ > MAX_WAIT_CNT)
			return 0;
		usleep(1);
	}

	if (msg->result) {
		WD_ERR("second BD error = %u\n", msg->result);
		msg_src->result = WD_OUT_EPARA;
	}

	return ret;
}

static __u32 get_hash_bytes(__u8 type)
{
	__u32 val = 0;

	switch (type) {
	case WCRYPTO_HASH_SHA1:
		val = BITS_TO_BYTES(160);
		break;
	case WCRYPTO_HASH_SHA256:
	case WCRYPTO_HASH_SM3:
		val = BITS_TO_BYTES(256);
		break;
	case WCRYPTO_HASH_MD4:
	case WCRYPTO_HASH_MD5:
		val = BITS_TO_BYTES(128);
		break;
	case WCRYPTO_HASH_SHA224:
		val = BITS_TO_BYTES(224);
		break;
	case WCRYPTO_HASH_SHA384:
		val = BITS_TO_BYTES(384);
		break;
	case WCRYPTO_HASH_SHA512:
		val = BITS_TO_BYTES(512);
		break;
	default:
		WD_ERR("get hash bytes: type %u error!\n", type);
		break;
	}

	return val;
}

static void msg_pack(char *dst, __u64 *out_len,
		     const void *src, __u32 src_len)
{
	if (unlikely(!src || !src_len))
		return;

	memcpy(dst + *out_len, src, src_len);
	*out_len += src_len;
}

static int sm2_kdf(struct wd_dtb *out, struct wcrypto_ecc_point *x2y2,
		   __u64 m_len, struct q_info *q_info)
{
	struct wcrypto_hash_mt *hash = &q_info->hash;
	char p_out[MAX_HASH_LENS] = {0};
	__u32 h_bytes, x2y2_len;
	char *tmp = out->data;
	__u64 in_len, lens;
	char *p_in, *t_out;
	__u8 ctr[4];
	__u32 i = 1;
	int ret;

	h_bytes = get_hash_bytes(hash->type);
	if (unlikely(!h_bytes))
		return -WD_EINVAL;

	x2y2_len = x2y2->x.dsize + x2y2->y.dsize;
	lens = x2y2_len + sizeof(ctr);
	p_in = malloc(lens);
	if (unlikely(!p_in))
		return -WD_ENOMEM;

	out->dsize = m_len;

	/*
	 * Use big-endian mode to store the value of counter i in ctr,
	 * i >> 8/16/24 for intercepts 8-bits whole-byte data.
	 */
	while (1) {
		ctr[3] = i & 0xFF;
		ctr[2] = (i >> 8) & 0xFF;
		ctr[1] = (i >> 16) & 0xFF;
		ctr[0] = (i >> 24) & 0xFF;
		in_len = 0;
		msg_pack(p_in, &in_len, x2y2->x.data, x2y2_len);
		msg_pack(p_in, &in_len, ctr, sizeof(ctr));

		t_out = m_len >= h_bytes ? tmp : p_out;
		ret = hash->cb(p_in, in_len, t_out, h_bytes, hash->usr);
		if (ret) {
			WD_ERR("failed to hash cb, ret = %d!\n", ret);
			break;
		}

		if (m_len >= h_bytes) {
			tmp += h_bytes;
			m_len -= h_bytes;
			if (!m_len)
				break;
		} else {
			memcpy(tmp, p_out, m_len);
			break;
		}

		i++;
	}

	free(p_in);

	return ret;
}

static void sm2_xor(struct wd_dtb *val1, struct wd_dtb *val2)
{
	int i;

	for (i = 0; i < val1->dsize; ++i)
		val1->data[i] = (char)((__u8)val1->data[i] ^
			(__u8)val2->data[i]);
}

static int is_equal(struct wd_dtb *src, struct wd_dtb *dst)
{
	if (src->dsize == dst->dsize &&
		!memcmp(src->data, dst->data, src->dsize)) {
		return 0;
	}

	return -1;
}

static int sm2_hash(struct wd_dtb *out, struct wcrypto_ecc_point *x2y2,
		    struct wd_dtb *msg, struct q_info *q_info)
{
	struct wcrypto_hash_mt *hash = &q_info->hash;
	__u64 lens = (__u64)msg->dsize + 2 * (__u64)x2y2->x.dsize;
	char hash_out[MAX_HASH_LENS] = {0};
	__u64 in_len = 0;
	__u32 h_bytes;
	char *p_in;
	int ret;

	h_bytes = get_hash_bytes(hash->type);
	if (unlikely(!h_bytes))
		return -WD_EINVAL;

	p_in = malloc(lens);
	if (unlikely(!p_in))
		return -WD_ENOMEM;

	msg_pack(p_in, &in_len, x2y2->x.data, x2y2->x.dsize);
	msg_pack(p_in, &in_len, msg->data, msg->dsize);
	msg_pack(p_in, &in_len, x2y2->y.data, x2y2->y.dsize);
	ret = hash->cb(p_in, in_len, hash_out, h_bytes, hash->usr);
	if (unlikely(ret)) {
		WD_ERR("failed to hash cb, ret = %d!\n", ret);
		goto fail;
	}

	out->dsize = h_bytes;
	memcpy(out->data, hash_out, out->dsize);

fail:
	free(p_in);

	return ret;
}

static int sm2_convert_enc_out(struct wcrypto_ecc_msg *src,
			       struct wcrypto_ecc_msg *first,
			       struct wcrypto_ecc_msg *second, void *q_info)
{
	struct wcrypto_ecc_out *out = (void *)src->out;
	struct wcrypto_ecc_in *in = (void *)src->in;
	struct wcrypto_sm2_enc_out *eout = &out->param.eout;
	struct wcrypto_sm2_enc_in *ein = &in->param.ein;
	struct wcrypto_ecc_point x2y2;
	__u32 ksz = src->key_bytes;
	struct wd_dtb *kdf_out;
	int ret;

	/* enc origin out data fmt:
	 * | x1y1(2*256bit) | x2y2(2*256bit) | other |
	 * final out data fmt:
	 * | c1(2*256bit)   | c2(plaintext size) | c3(256bit) |
	 */
	x2y2.x.data = (void *)second->out;
	x2y2.x.dsize = ksz;
	x2y2.y.dsize = ksz;
	x2y2.y.data = (void *)(second->out + ksz);

	/* C1 */
	memcpy(eout->c1.x.data, first->out, ksz + ksz);

	/* C3 = hash(x2 || M || y2) */
	ret = sm2_hash(&eout->c3, &x2y2, &ein->plaintext, q_info);
	if (unlikely(ret)) {
		WD_ERR("failed to sm2 hash, ret = %d!\n", ret);
		return ret;
	}

	/* t = KDF(x2 || y2, klen) */
	kdf_out = &eout->c2;
	ret = sm2_kdf(kdf_out, &x2y2, ein->plaintext.dsize, q_info);
	if (unlikely(ret)) {
		WD_ERR("failed to sm2 kdf, ret = %d!\n", ret);
		return ret;
	}

	/* C2 = M XOR t */
	sm2_xor(kdf_out, &ein->plaintext);

	return ret;
}

static int sm2_convert_dec_out(struct wcrypto_ecc_msg *src,
			       struct wcrypto_ecc_msg *dst, void *q_info)
{
	struct wcrypto_ecc_out *out = (void *)src->out;
	struct wcrypto_sm2_dec_out *dout = &out->param.dout;
	struct wcrypto_ecc_in *in = (void *)src->in;
	struct wcrypto_sm2_dec_in *din = &in->param.din;
	struct wcrypto_ecc_point x2y2;
	__u32 ksz = dst->key_bytes;
	int ret;

	/* dec origin out data fmt:
	 * | x2y2(2*256bit) |   other      |
	 * final out data fmt:
	 * |         plaintext             |
	 */

	/* x2y2 :copy x2y2 into din->c1 */
	x2y2.x.data = (void *)dst->out;
	x2y2.y.data = (void *)(dst->out + ksz);
	x2y2.x.dsize = ksz;
	x2y2.y.dsize = ksz;

	/* t = KDF(x2 || y2, klen) */
	ret = sm2_kdf(&dout->plaintext, &x2y2, din->c2.dsize, q_info);
	if (unlikely(ret)) {
		WD_ERR("failed to sm2 kdf, ret = %d!\n", ret);
		return ret;
	}

	/* M' = C2 XOR t */
	sm2_xor(&dout->plaintext, &din->c2);

	/* u = hash(x2 || M' || y2), save u to din->c2 */
	ret = sm2_hash(&din->c1.x, &x2y2, &dout->plaintext, q_info);
	if (unlikely(ret)) {
		WD_ERR("failed to compute c3, ret = %d!\n", ret);
		return ret;
	}

	/* u == c3 */
	ret = is_equal(&din->c1.x, &din->c3);
	if (ret)
		WD_ERR("failed to dec sm2, u != C3!\n");

	return ret;
}

static int parse_sm2_enc_sqe(void *hw_msg, struct qm_queue_info *info,
			     __u16 i, __u16 usr)
{
	struct wcrypto_ecc_msg *first = info->req_cache[i];
	struct wcrypto_ecc_msg *src, *second;
	int ret;

	ret = parse_first_sqe(hw_msg, info, i, usr);
	if (!ret)
		return ret;

	src = *(struct wcrypto_ecc_msg **)(first + 1);
	second = info->req_cache[info->cq_head_index];
	ret = parse_second_sqe(hw_msg, info, info->cq_head_index, usr, src);
	if (unlikely(!ret)) {
		WD_ERR("failed to parse second sqe, timeout!\n");
		goto fail;
	} else if (unlikely(ret < 0)) {
		WD_ERR("failed to parse second sqe, ret = %d!\n", ret);
		goto fail;
	}

	src->op_type = WCRYPTO_SM2_ENCRYPT;
	info->req_cache[info->cq_head_index] = src;
	ret = sm2_convert_enc_out(src, first, second, info->q->qinfo);
	if (unlikely(ret)) {
		WD_ERR("failed to convert sm2 std fmt, ret = %d!\n", ret);
		src->result = WD_OUT_EPARA;
	}

	ret = 1;
fail:
	free_req(info, first);
	free_req(info, second);

	return ret;
}

static int parse_sm2_dec_sqe(void *hw_msg, struct qm_queue_info *info,
			     __u16 i, __u16 usr)
{
	struct wcrypto_ecc_msg *dst = info->req_cache[i];
	struct q_info *qinfo = info->q->qinfo;
	struct wd_mm_br *br = &qinfo->br;
	struct wcrypto_ecc_msg *src;
	int ret;

	ret = qm_parse_ecc_sqe_general(hw_msg, info, i, usr);
	if (!ret)
		return ret;

	src = *(struct wcrypto_ecc_msg **)(dst + 1);
	src->op_type = WCRYPTO_SM2_DECRYPT;
	src->result = dst->result;
	info->req_cache[i] = src;

	if (dst->result != WD_SUCCESS) {
		WD_ERR("msg result error = %u!\n", dst->result);
		src->result = WD_OUT_EPARA;
		goto fail;
	}

	ret = sm2_convert_dec_out(src, dst, info->q->qinfo);
	if (unlikely(ret)) {
		WD_ERR("failed to convert sm2 dec out, ret = %d!\n", ret);
		src->result = WD_OUT_EPARA;
	}

fail:
	br->free(br->usr, dst->out);
	free(dst);

	return 1;
}

int qm_parse_ecc_sqe(void *message, const struct qm_queue_info *info,
		     __u16 i, __u16 usr)
{
	struct wcrypto_ecc_msg *msg = info->req_cache[i];

	if (msg->op_type == HPRE_SM2_ENC)
		return parse_sm2_enc_sqe(message, (void *)info, i, usr);
	else if (msg->op_type == HPRE_SM2_DEC)
		return parse_sm2_dec_sqe(message, (void *)info, i, usr);

	return qm_parse_ecc_sqe_general(message, (void *)info, i, usr);
}
