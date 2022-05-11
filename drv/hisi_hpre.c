/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

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
#include "wd.h"
#include "../include/drv/wd_rsa_drv.h"
#include "../include/drv/wd_dh_drv.h"
#include "../include/drv/wd_ecc_drv.h"

#define HPRE_HW_TASK_DONE	3
#define HPRE_HW_TASK_INIT	1

#define HPRE_HW_V2_ALG_TYPE	0
#define HPRE_HW_V3_ECC_ALG_TYPE	1

#define HPRE_HW_SVA_ERROR	(1u << 5)

/* realize with hardware ECC multiplication, avoid conflict with wd_ecc.h */
#define HPRE_SM2_ENC	0xE
#define HPRE_SM2_DEC	0xF

#define SM2_SQE_NUM	2

#define MAX_WAIT_CNT			10000000
#define SM2_KEY_SIZE			32
#define SM2_PONIT_SIZE			64
#define MAX_HASH_LENS			BITS_TO_BYTES(521)
#define HW_PLAINTEXT_BYTES_MAX		BITS_TO_BYTES(4096)

#define CRT_PARAMS_SZ(key_size)		((5 * (key_size)) >> 1)
#define CRT_GEN_PARAMS_SZ(key_size)	((7 * (key_size)) >> 1)
#define GEN_PARAMS_SZ(key_size)		((key_size) << 1)
#define CRT_PARAM_SZ(key_size)		((key_size) >> 1)

#define container_of(ptr, type, member) ({ \
		typeof(((type *)0)->member)(*__mptr) = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); })

enum hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_PRIME = 0x6,
	HPRE_ALG_MOD = 0x7,
	HPRE_ALG_MOD_INV = 0x8,
	HPRE_ALG_MUL = 0x9,
	HPRE_ALG_COPRIME = 0xA,
	HPRE_ALG_ECC_CURVE_TEST = 0xB,
	HPRE_ALG_ECDH_PLUS = 0xC,
	HPRE_ALG_ECDH_MULTIPLY = 0xD,
	HPRE_ALG_ECDSA_SIGN = 0xE,
	HPRE_ALG_ECDSA_VERF = 0xF,
	HPRE_ALG_X_DH_MULTIPLY = 0x10,
	HPRE_ALG_SM2_KEY_GEN = 0x11,
	HPRE_ALG_SM2_SIGN = 0x12,
	HPRE_ALG_SM2_VERF = 0x13,
	HPRE_ALG_SM2_ENC = 0x14,
	HPRE_ALG_SM2_DEC = 0x15
};

/* put vendor hardware message as a user interface is not suitable here */
struct hisi_hpre_sqe {
	__u32 alg	: 5;

	/* error type */
	__u32 etype	: 11;
	__u32 etype1	: 14;
	__u32 done	: 2;
	__u32 task_len1	: 8;
	__u32 task_len2	: 8;
	__u32 mrttest_num : 8;
	__u32 uwkey_enb : 1;
	__u32 sm2_ksel	: 1;
	__u32 sva_bypass: 1;
	__u32 sva_status: 4;
	__u32 bd_rsv2	: 1;
	__u32 low_key;
	__u32 hi_key;
	__u32 low_in;
	__u32 hi_in;
	__u32 low_out;
	__u32 hi_out;
	__u32 low_tag;
	__u32 hi_tag;
	__u32 sm2_mlen	: 9;
	__u32 rsvd1	: 7;
	__u32 uwkey_sel	: 4;
	__u32 wrap_num	: 3;
	__u32 resv2	: 9;
	__u32 kek_key;
	__u32 rsvd3[4];
};

struct hisi_hpre_ctx {
	struct wd_ctx_config_internal	config;
};

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

static int crypto_bin_to_hpre_bin(char *dst, const char *src,
				  __u32 b_size, __u32 d_size, const char *p_name)
{
	int i = d_size - 1;
	bool is_hpre_bin;
	int j;

	if (!dst || !src || b_size <= 0 || d_size <= 0) {
		WD_ERR("invalid: %s trans to hpre bin parameters err!\n", p_name);
		return -WD_EINVAL;
	}

	if (b_size < d_size) {
		WD_ERR("invalid: %s trans to hpre bin data too long!\n", p_name);
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

static int hpre_bin_to_crypto_bin(char *dst, const char *src, int b_size,
				  const char *p_name)
{
	int i, cnt;
	int j = 0;
	int k = 0;

	if (!dst || !src || b_size <= 0) {
		WD_ERR("invalid: %s trans to crypto bin parameters err!\n", p_name);
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

static int fill_rsa_crt_prikey2(struct wd_rsa_prikey *prikey,
				   void **data)
{
	struct wd_dtb *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	int ret;

	wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp,
				&wd_qinv, &wd_q, &wd_p);
	ret = crypto_bin_to_hpre_bin(wd_dq->data, (const char *)wd_dq->data,
				wd_dq->bsize, wd_dq->dsize, "rsa crt dq");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(wd_dp->data, (const char *)wd_dp->data,
				wd_dp->bsize, wd_dp->dsize, "rsa crt dp");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(wd_q->data, (const char *)wd_q->data,
				wd_q->bsize, wd_q->dsize, "rsa crt q");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(wd_p->data,
		(const char *)wd_p->data, wd_p->bsize, wd_p->dsize, "rsa crt p");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(wd_qinv->data,
		(const char *)wd_qinv->data, wd_qinv->bsize,
		wd_qinv->dsize, "rsa crt qinv");
	if (ret)
		return ret;

	*data = wd_dq->data;

	return WD_SUCCESS;
}

static int fill_rsa_prikey1(struct wd_rsa_prikey *prikey, void **data)
{
	struct wd_dtb *wd_d, *wd_n;
	int ret;

	wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
	ret = crypto_bin_to_hpre_bin(wd_d->data, (const char *)wd_d->data,
				wd_d->bsize, wd_d->dsize, "rsa d");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize, "rsa n");
	if (ret)
		return ret;

	*data = wd_d->data;

	return WD_SUCCESS;
}

static int fill_rsa_pubkey(struct wd_rsa_pubkey *pubkey, void **data)
{
	struct wd_dtb *wd_e, *wd_n;
	int ret;

	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
	ret = crypto_bin_to_hpre_bin(wd_e->data, (const char *)wd_e->data,
				wd_e->bsize, wd_e->dsize, "rsa e");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize, "rsa n");
	if (ret)
		return ret;

	*data = wd_e->data;

	return WD_SUCCESS;
}

static int fill_rsa_genkey_in(struct wd_rsa_kg_in *genkey)
{
	struct wd_dtb e, q, p;
	int ret;

	wd_rsa_get_kg_in_params(genkey, &e, &q, &p);

	ret = crypto_bin_to_hpre_bin(e.data, (const char *)e.data,
				e.bsize, e.dsize, "rsa kg e");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(q.data, (const char *)q.data,
				q.bsize, q.dsize, "rsa kg q");
	if (ret)
		return ret;

	return crypto_bin_to_hpre_bin(p.data, (const char *)p.data,
				p.bsize, p.dsize, "rsa kg p");
}

static int hpre_tri_bin_transfer(struct wd_dtb *bin0, struct wd_dtb *bin1,
				struct wd_dtb *bin2)
{
	int ret;

	ret = hpre_bin_to_crypto_bin(bin0->data, (const char *)bin0->data,
				bin0->bsize, "hpre");
	if (!ret)
		return -WD_EINVAL;

	bin0->dsize = ret;

	if (bin1) {
		ret = hpre_bin_to_crypto_bin(bin1->data,
			(const char *)bin1->data,
			bin1->bsize, "hpre");
		if (!ret)
			return -WD_EINVAL;

		bin1->dsize = ret;
	}

	if (bin2) {
		ret = hpre_bin_to_crypto_bin(bin2->data,
			(const char *)bin2->data, bin2->bsize, "hpre");
		if (!ret)
			return -WD_EINVAL;

		bin2->dsize = ret;
	}

	return WD_SUCCESS;
}

static int rsa_out_transfer(struct wd_rsa_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wd_rsa_req *req = &msg->req;
	struct wd_rsa_kg_out *key = req->dst;
	__u16 kbytes = msg->key_bytes;
	struct wd_dtb qinv, dq, dp;
	struct wd_dtb d, n;
	void *data;
	int ret;

	if (hw_msg->alg == HPRE_ALG_KG_CRT || hw_msg->alg == HPRE_ALG_KG_STD) {
		/* async */
		if (LW_U16(hw_msg->low_tag)) {
			data = VA_ADDR(hw_msg->hi_out, hw_msg->low_out);
			key = container_of(data, struct wd_rsa_kg_out, data);
		} else {
			key = req->dst;
		}
	}

	msg->result = WD_SUCCESS;
	if (hw_msg->alg == HPRE_ALG_KG_CRT) {
		req->dst_bytes = CRT_GEN_PARAMS_SZ(kbytes);
		wd_rsa_get_kg_out_crt_params(key, &qinv, &dq, &dp);
		ret = hpre_tri_bin_transfer(&qinv, &dq, &dp);
		if (ret) {
			WD_ERR("failed to parse rsa genkey qinv&&dq&&dp format!\n");
			return ret;
		}

		wd_rsa_set_kg_out_crt_psz(key, qinv.dsize,
					       dq.dsize, dp.dsize);
	} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
		req->dst_bytes = GEN_PARAMS_SZ(kbytes);

		wd_rsa_get_kg_out_params(key, &d, &n);
		ret = hpre_tri_bin_transfer(&d, &n, NULL);
		if (ret) {
			WD_ERR("failed to parse rsa genkey1 d&&n format!\n");
			return ret;
		}

		wd_rsa_set_kg_out_psz(key, d.dsize, n.dsize);
	} else {
		req->dst_bytes = kbytes;
	}

	return WD_SUCCESS;
}

static int rsa_prepare_key(struct wd_rsa_msg *msg,
			      struct hisi_hpre_sqe *hw_msg)
{
	struct wd_rsa_req *req = &msg->req;
	void *data;
	int ret;

	if (req->op_type == WD_RSA_SIGN) {
		if (hw_msg->alg == HPRE_ALG_NC_CRT) {
			ret = fill_rsa_crt_prikey2((void *)msg->key, &data);
			if (ret)
				return ret;
		} else {
			ret = fill_rsa_prikey1((void *)msg->key, &data);
			if (ret)
				return ret;
			hw_msg->alg = HPRE_ALG_NC_NCRT;
		}
	} else if (req->op_type == WD_RSA_VERIFY) {
		ret = fill_rsa_pubkey((void *)msg->key, &data);
		if (ret)
			return ret;
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	} else if (req->op_type == WD_RSA_GENKEY) {
		ret = fill_rsa_genkey_in((void *)msg->key);
		if (ret)
			return ret;
		ret = wd_rsa_kg_in_data((void *)msg->key, (char **)&data);
		if (ret < 0) {
			WD_ERR("failed to get rsa gen key data!\n");
			return ret;
		}
		if (hw_msg->alg == HPRE_ALG_NC_CRT)
			hw_msg->alg = HPRE_ALG_KG_CRT;
		else
			hw_msg->alg = HPRE_ALG_KG_STD;
	} else {
		WD_ERR("invalid: rsa operatin type %u is error!\n", req->op_type);
		return -WD_EINVAL;
	}

	hw_msg->low_key = LW_U32((uintptr_t)data);
	hw_msg->hi_key = HI_U32((uintptr_t)data);

	return WD_SUCCESS;
}

static int rsa_prepare_iot(struct wd_rsa_msg *msg,
			      struct hisi_hpre_sqe *hw_msg)
{
	struct wd_rsa_req *req = &msg->req;
	struct wd_rsa_kg_out *kout = req->dst;
	int ret = WD_SUCCESS;
	void *out = NULL;

	if (req->op_type != WD_RSA_GENKEY) {
		hw_msg->low_in = LW_U32((uintptr_t)req->src);
		hw_msg->hi_in = HI_U32((uintptr_t)req->src);
		out = req->dst;
	} else {
		hw_msg->low_in = 0;
		hw_msg->hi_in = 0;
		ret = wd_rsa_kg_out_data(kout, (char **)&out);
		if (ret < 0)
			return ret;
	}

	hw_msg->low_out = LW_U32((uintptr_t)out);
	hw_msg->hi_out = HI_U32((uintptr_t)out);

	return ret;
}

static int hpre_init(struct wd_ctx_config_internal *config, void *priv, const char *alg_name)
{
	struct hisi_hpre_ctx *hpre_ctx = (struct hisi_hpre_ctx *)priv;
	struct hisi_qm_priv qm_priv;
	handle_t h_ctx, h_qp;
	int i, j;

	memcpy(&hpre_ctx->config, config, sizeof(*config));

	/* allocate qp for each context */
	qm_priv.sqe_size = sizeof(struct hisi_hpre_sqe);

	/* DH/RSA: qm sqc_type = 0, ECC: qm sqc_type = 1; */
	if (!strcmp(alg_name, "ecc"))
		qm_priv.op_type = HPRE_HW_V3_ECC_ALG_TYPE;
	else
		qm_priv.op_type = HPRE_HW_V2_ALG_TYPE;

	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		/* Setting the epoll en to 0 for ASYNC ctx */
		qm_priv.epoll_en = (qm_priv.qp_mode == CTX_MODE_SYNC) ?
				   config->epoll_en : 0;
		qm_priv.idx = i;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp) {
			WD_ERR("failed to alloc qp!\n");
			goto out;
		}
	}

	return 0;
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}

	return -WD_EINVAL;
}

static void hpre_exit(void *priv)
{
	struct hisi_hpre_ctx *hpre_ctx = (struct hisi_hpre_ctx *)priv;
	struct wd_ctx_config_internal *config = &hpre_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
}

static int rsa_send(handle_t ctx, struct wd_rsa_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg;
	__u16 send_cnt = 0;
	int ret;

	memset(&hw_msg, 0, sizeof(struct hisi_hpre_sqe));

	if (msg->key_type == WD_RSA_PRIKEY1 ||
	msg->key_type == WD_RSA_PUBKEY)
		hw_msg.alg = HPRE_ALG_NC_NCRT;
	else if (msg->key_type == WD_RSA_PRIKEY2)
		hw_msg.alg = HPRE_ALG_NC_CRT;
	else
		return -WD_EINVAL;

	hw_msg.task_len1 = msg->key_bytes / BYTE_BITS - 0x1;

	ret = rsa_prepare_key(msg, &hw_msg);
	if (ret < 0)
		return ret;

	/* prepare in/out put */
	ret = rsa_prepare_iot(msg, &hw_msg);
	if (ret < 0)
		return ret;

	hisi_set_msg_id(h_qp, &msg->tag);
	hw_msg.done = 0x1;
	hw_msg.etype = 0x0;
	hw_msg.low_tag = msg->tag;

	return hisi_qm_send(h_qp, &hw_msg, 1, &send_cnt);
}

static int rsa_recv(handle_t ctx, struct wd_rsa_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg = {0};
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &hw_msg, 1, &recv_cnt);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, msg->tag, hw_msg.low_tag);
	if (ret)
		return ret;

	if (hw_msg.done != HPRE_HW_TASK_DONE ||
			hw_msg.etype || hw_msg.etype1) {
		WD_ERR("failed to do rsa task! done=0x%x, etype=0x%x, etype1=0x%x!\n",
			hw_msg.done, hw_msg.etype, hw_msg.etype1);
		if (hw_msg.etype1 & HPRE_HW_SVA_ERROR)
			WD_ERR("failed to SVA prefetch: status=%u!\n",
				hw_msg.sva_status);
		if (hw_msg.done == HPRE_HW_TASK_INIT)
			msg->result = WD_EINVAL;
		else
			msg->result = WD_IN_EPARA;
	} else {
		msg->tag = LW_U16(hw_msg.low_tag);
		ret = rsa_out_transfer(msg, &hw_msg);
		if (ret) {
			WD_ERR("failed to transfer out rsa BD!\n");
			msg->result = WD_OUT_EPARA;
		} else {
			msg->result = WD_SUCCESS;
		}
	}

	return 0;
}

static struct wd_rsa_driver rsa_hisi_hpre = {
	.drv_name		= "hisi_hpre",
	.alg_name		= "rsa",
	.drv_ctx_size		= sizeof(struct hisi_hpre_ctx),
	.init			= hpre_init,
	.exit			= hpre_exit,
	.send			= rsa_send,
	.recv			= rsa_recv,
};

static int fill_dh_xp_params(struct wd_dh_msg *msg,
			     struct hisi_hpre_sqe *hw_msg)
{
	struct wd_dh_req *req = &msg->req;
	void *x, *p;
	int ret;

	x = req->x_p;
	p = req->x_p + msg->key_bytes;
	ret = crypto_bin_to_hpre_bin(x, (const char *)x,
				msg->key_bytes, req->xbytes, "dh x");
	if (ret) {
		WD_ERR("failed to transfer dh x para format to hpre bin!\n");
		return ret;
	}

	ret = crypto_bin_to_hpre_bin(p, (const char *)p,
				msg->key_bytes, req->pbytes, "dh p");
	if (ret) {
		WD_ERR("failed to transfer dh p para format to hpre bin!\n");
		return ret;
	}

	hw_msg->low_key = LW_U32((uintptr_t)x);
	hw_msg->hi_key = HI_U32((uintptr_t)x);

	return WD_SUCCESS;
}

static int dh_out_transfer(struct wd_dh_msg *msg,
			   struct hisi_hpre_sqe *hw_msg)
{
	__u16 key_bytes = (hw_msg->task_len1 + 1) * BYTE_BITS;
	struct wd_dh_req *req = &msg->req;
	void *out;
	int ret;

	/* async */
	if (LW_U16(hw_msg->low_tag))
		out = VA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	else
		out = req->pri;

	ret = hpre_bin_to_crypto_bin((char *)out,
		(const char *)out, key_bytes, "dh out");
	if (!ret)
		return -WD_EINVAL;

	req->pri_bytes = ret;

	return WD_SUCCESS;
}

static int dh_send(handle_t ctx, struct wd_dh_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_dh_req *req = &msg->req;
	struct hisi_hpre_sqe hw_msg;
	__u16 send_cnt = 0;
	int ret;

	memset(&hw_msg, 0, sizeof(struct hisi_hpre_sqe));

	if (msg->is_g2 && req->op_type != WD_DH_PHASE2)
		hw_msg.alg = HPRE_ALG_DH_G2;
	else
		hw_msg.alg = HPRE_ALG_DH;

	hw_msg.task_len1 = msg->key_bytes / BYTE_BITS - 0x1;

	if (!(msg->is_g2 && req->op_type == WD_DH_PHASE1)) {
		ret = crypto_bin_to_hpre_bin((char *)msg->g,
			(const char *)msg->g, msg->key_bytes,
			msg->gbytes, "dh g");
		if (ret) {
			WD_ERR("failed to transfer dh g para format to hpre bin!\n");
			return ret;
		}

		hw_msg.low_in = LW_U32((uintptr_t)msg->g);
		hw_msg.hi_in = HI_U32((uintptr_t)msg->g);
	}

	ret = fill_dh_xp_params(msg, &hw_msg);
	if (ret)
		return ret;

	hisi_set_msg_id(h_qp, &msg->tag);
	hw_msg.low_out = LW_U32((uintptr_t)req->pri);
	hw_msg.hi_out = HI_U32((uintptr_t)req->pri);
	hw_msg.done = 0x1;
	hw_msg.etype = 0x0;
	hw_msg.low_tag = msg->tag;

	return hisi_qm_send(h_qp, &hw_msg, 1, &send_cnt);
}

static int dh_recv(handle_t ctx, struct wd_dh_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg = {0};
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &hw_msg, 1, &recv_cnt);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, msg->tag, hw_msg.low_tag);
	if (ret)
		return ret;

	if (hw_msg.done != HPRE_HW_TASK_DONE ||
			hw_msg.etype || hw_msg.etype1) {
		WD_ERR("failed to do dh task! done=0x%x, etype=0x%x, etype1=0x%x!\n",
			hw_msg.done, hw_msg.etype, hw_msg.etype1);
		if (hw_msg.etype1 & HPRE_HW_SVA_ERROR)
			WD_ERR("failed to SVA prefetch: status=%u!\n",
				hw_msg.sva_status);
		if (hw_msg.done == HPRE_HW_TASK_INIT)
			msg->result = WD_EINVAL;
		else
			msg->result = WD_IN_EPARA;
	} else {
		msg->tag = LW_U16(hw_msg.low_tag);
		ret = dh_out_transfer(msg, &hw_msg);
		if (ret) {
			WD_ERR("failed to transfer out dh BD!\n");
			msg->result = WD_OUT_EPARA;
		} else {
			msg->result = WD_SUCCESS;
		}
	}

	return 0;
}

static struct wd_dh_driver dh_hisi_hpre = {
	.drv_name		= "hisi_hpre",
	.alg_name		= "dh",
	.drv_ctx_size		= sizeof(struct hisi_hpre_ctx),
	.init			= hpre_init,
	.exit			= hpre_exit,
	.send			= dh_send,
	.recv			= dh_recv,
};

static int ecc_prepare_alg(struct wd_ecc_msg *msg,
			   struct hisi_hpre_sqe *hw_msg)
{
	switch (msg->req.op_type) {
	case WD_SM2_SIGN:
		hw_msg->alg = HPRE_ALG_SM2_SIGN;
		break;
	case WD_ECDSA_SIGN:
		hw_msg->alg = HPRE_ALG_ECDSA_SIGN;
		break;
	case WD_SM2_VERIFY:
		hw_msg->alg = HPRE_ALG_SM2_VERF;
		break;
	case WD_ECDSA_VERIFY:
		hw_msg->alg = HPRE_ALG_ECDSA_VERF;
		break;
	case WD_SM2_ENCRYPT:
		hw_msg->alg = HPRE_ALG_SM2_ENC;
		break;
	case WD_SM2_DECRYPT:
		hw_msg->alg = HPRE_ALG_SM2_DEC;
		break;
	case WD_SM2_KG:
		hw_msg->alg = HPRE_ALG_SM2_KEY_GEN;
		break;
	case WD_ECXDH_GEN_KEY: /* fall through */
	case HPRE_SM2_ENC: /* fall through */
	case HPRE_SM2_DEC: /* fall through */
	case WD_ECXDH_COMPUTE_KEY:
		if (msg->curve_id == WD_X448 || msg->curve_id == WD_X25519)
			hw_msg->alg = HPRE_ALG_X_DH_MULTIPLY;
		else
			hw_msg->alg = HPRE_ALG_ECDH_MULTIPLY;
		break;
	default:
		return -WD_EINVAL;
	}

	return 0;
}


static int trans_cv_param_to_hpre_bin(struct wd_dtb *p, struct wd_dtb *a,
				      struct wd_dtb *b, struct wd_dtb *n,
				      struct wd_ecc_point *g)
{
	int ret;

	ret = crypto_bin_to_hpre_bin(p->data, (const char *)p->data,
					p->bsize, p->dsize, "cv p");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(a->data, (const char *)a->data,
					a->bsize, a->dsize, "cv a");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(b->data, (const char *)b->data,
					b->bsize, b->dsize, "cv b");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(n->data, (const char *)n->data,
					n->bsize, n->dsize, "cv n");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(g->x.data, (const char *)g->x.data,
					g->x.bsize, g->x.dsize, "cv gx");
	if (ret)
		return ret;

	return crypto_bin_to_hpre_bin(g->y.data, (const char *)g->y.data,
					g->y.bsize, g->y.dsize, "cv gy");
}

static int trans_d_to_hpre_bin(struct wd_dtb *d)
{
	return crypto_bin_to_hpre_bin(d->data, (const char *)d->data,
				      d->bsize, d->dsize, "ecc d");
}

static bool big_than_one(const char *data, __u32 data_sz)
{
	int i;

	for (i = 0; i < data_sz - 1; i++) {
		if (data[i] > 0)
			return true;
	}

	if (data[i] == 0 || data[i] == 1)
		return false;

	return true;
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

static int ecc_prepare_prikey(struct wd_ecc_key *key, void **data, int id)
{
	struct wd_ecc_point *g = NULL;
	struct wd_dtb *p = NULL;
	struct wd_dtb *a = NULL;
	struct wd_dtb *b = NULL;
	struct wd_dtb *n = NULL;
	struct wd_dtb *d = NULL;
	char bsize, dsize;
	char *dat;
	int ret;

	wd_ecc_get_prikey_params((void *)key, &p, &a, &b, &n, &g, &d);

	ret = trans_cv_param_to_hpre_bin(p, a, b, n, g);
	if (ret)
		return ret;

	ret = trans_d_to_hpre_bin(d);
	if (ret)
		return ret;

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
	dat = d->data;
	bsize = d->bsize;
	dsize = d->dsize;
	if (id == WD_X25519) {
		dat[31] &= 248;
		dat[0] &= 127;
		dat[0] |= 64;
	} else if (id == WD_X448) {
		dat[55 + bsize - dsize] &= 252;
		dat[0 + bsize - dsize] |= 128;
	}

	if (!big_than_one(dat, bsize)) {
		WD_ERR("failed to prepare ecc prikey: d <= 1!\n");
		return -WD_EINVAL;
	}

	if (id != WD_X25519 && id != WD_X448 &&
		!less_than_latter(d, n)) {
		WD_ERR("failed to prepare ecc prikey: d >= n!\n");
		return -WD_EINVAL;
	}

	*data = p->data;

	return 0;
}

static int trans_pub_to_hpre_bin(struct wd_ecc_point *pub)
{
	struct wd_dtb *temp;
	int ret;

	temp = &pub->x;
	ret = crypto_bin_to_hpre_bin(temp->data, (const char *)temp->data,
				     temp->bsize, temp->dsize, "ecc pub x");
	if (ret)
		return ret;

	temp = &pub->y;
	return crypto_bin_to_hpre_bin(temp->data, (const char *)temp->data,
				      temp->bsize, temp->dsize, "ecc pub y");
}

static int ecc_prepare_pubkey(struct wd_ecc_key *key, void **data)
{
	struct wd_ecc_point *pub = NULL;
	struct wd_ecc_point *g = NULL;
	struct wd_dtb *p = NULL;
	struct wd_dtb *a = NULL;
	struct wd_dtb *b = NULL;
	struct wd_dtb *n = NULL;
	int ret;

	wd_ecc_get_pubkey_params((void *)key, &p, &a, &b, &n, &g, &pub);

	ret = trans_cv_param_to_hpre_bin(p, a, b, n, g);
	if (ret)
		return ret;

	ret = trans_pub_to_hpre_bin(pub);
	if (ret)
		return ret;

	*data = p->data;

	return 0;
}

static bool is_prikey_used(__u8 op_type)
{
	return op_type == WD_ECXDH_GEN_KEY ||
	       op_type == WD_ECXDH_COMPUTE_KEY ||
	       op_type == WD_ECDSA_SIGN ||
	       op_type == WD_SM2_DECRYPT ||
	       op_type == WD_SM2_SIGN ||
	       op_type == HPRE_SM2_ENC ||
	       op_type == HPRE_SM2_DEC;
}

static int ecc_prepare_key(struct wd_ecc_msg *msg,
			   struct hisi_hpre_sqe *hw_msg)
{
	void *data = NULL;
	int ret;

	if (is_prikey_used(msg->req.op_type)) {
		ret = ecc_prepare_prikey((void *)msg->key, &data, msg->curve_id);
		if (ret)
			return ret;
	} else {
		ret = ecc_prepare_pubkey((void *)msg->key, &data);
		if (ret)
			return ret;
	}

	hw_msg->low_key = LW_U32((uintptr_t)data);
	hw_msg->hi_key = HI_U32((uintptr_t)data);

	return 0;
}

static void ecc_get_io_len(__u32 atype, __u32 hsz, size_t *ilen,
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

static bool is_all_zero(struct wd_dtb *e, struct wd_ecc_msg *msg)
{
	int i;

	for (i = 0; i < e->dsize && i < msg->key_bytes; i++) {
		if (e->data[i])
			return false;
	}

	return true;
}

static void correct_random(struct wd_dtb *k)
{
	int lens = k->bsize - k->dsize;

	k->data[lens] = 0;
}

static int ecc_prepare_sign_in(struct wd_ecc_msg *msg,
			       struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wd_ecc_sign_in *in = msg->req.src;
	struct wd_dtb *n = NULL;
	struct wd_dtb *e, *k;
	int ret;

	if (!in->dgst_set) {
		WD_ERR("invalid: prepare sign_in, hash not set!\n");
		return -WD_EINVAL;
	}

	e = &in->dgst;
	k = &in->k;
	if (!in->k_set) {
		if (msg->req.op_type == WD_ECDSA_SIGN) {
			WD_ERR("invalid: random k not set!\n");
			return -WD_EINVAL;
		}
		hw_msg->sm2_ksel = 1;
	} else if (is_all_zero(k, msg)) {
		WD_ERR("invalid: ecc sign in k all zero!\n");
		return -WD_EINVAL;
	}

	if (is_all_zero(e, msg)) {
		WD_ERR("invalid: ecc sign in e all zero!\n");
		return -WD_EINVAL;
	}

	ret = crypto_bin_to_hpre_bin(e->data, (const char *)e->data,
					e->bsize, e->dsize, "ecc sgn e");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(k->data, (const char *)k->data,
					k->bsize, k->dsize, "ecc sgn k");
	if (ret)
		return ret;

	wd_ecc_get_prikey_params((void *)msg->key, NULL, NULL, NULL,
				 &n, NULL, NULL);
	if (!less_than_latter(k, n))
		correct_random(k);

	*data = e->data;

	return 0;
}

static int ecc_prepare_verf_in(struct wd_ecc_msg *msg,
			       struct hisi_hpre_sqe *hw_msg, void **data)

{
	struct wd_ecc_verf_in *vin = msg->req.src;
	struct wd_dtb *e, *s, *r;
	int ret;

	if (!vin->dgst_set) {
		WD_ERR("invalid: prepare verf_in, hash not set!\n");
		return -WD_EINVAL;
	}

	e = &vin->dgst;
	s = &vin->s;
	r = &vin->r;

	if (is_all_zero(e, msg)) {
		WD_ERR("invalid: ecc verf in e all zero!\n");
		return -WD_EINVAL;
	}

	ret = crypto_bin_to_hpre_bin(e->data, (const char *)e->data,
					e->bsize, e->dsize, "ecc vrf e");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(s->data, (const char *)s->data,
					s->bsize, s->dsize, "ecc vrf s");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(r->data, (const char *)r->data,
					r->bsize, r->dsize, "ecc vrf r");
	if (ret)
		return ret;

	*data = e->data;

	return 0;
}

static int sm2_prepare_enc_in(struct wd_ecc_msg *msg,
			      struct hisi_hpre_sqe *hw_msg, void **data)

{
	struct wd_sm2_enc_in *ein = msg->req.src;
	struct wd_dtb *k = &ein->k;
	int ret;

	if (ein->k_set) {
		ret = crypto_bin_to_hpre_bin(k->data, (const char *)k->data,
					     k->bsize, k->dsize, "sm2 encode k");
		if (ret)
			return ret;
	} else {
		hw_msg->sm2_ksel = 1;
	}

	hw_msg->sm2_mlen = ein->plaintext.dsize - 1;
	*data = k->data;

	return 0;
}

static int sm2_prepare_dec_in(struct wd_ecc_msg *msg,
			      struct hisi_hpre_sqe *hw_msg, void **data)

{
	struct wd_sm2_dec_in *din = msg->req.src;
	struct wd_ecc_point *c1 = &din->c1;
	int ret;

	ret = crypto_bin_to_hpre_bin(c1->x.data, (const char *)c1->x.data,
		c1->x.bsize, c1->x.dsize, "sm2 decode c1 x");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(c1->y.data, (const char *)c1->y.data,
		c1->y.bsize, c1->y.dsize, "sm2 decode c1 y");
	if (ret)
		return ret;

	hw_msg->sm2_mlen = din->c2.dsize - 1;
	*data = c1->x.data;

	return 0;
}

static int ecc_prepare_dh_gen_in(struct wd_ecc_msg *msg,
				 struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wd_ecc_point *in = msg->req.src;
	int ret;

	ret = crypto_bin_to_hpre_bin(in->x.data, (const char *)in->x.data,
					in->x.bsize, in->x.dsize, "ecdh gen x");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(in->y.data, (const char *)in->y.data,
					in->y.bsize, in->y.dsize, "ecdh gen y");
	if (ret)
		return ret;

	*data = in->x.data;

	return 0;
}

static int ecc_prepare_dh_compute_in(struct wd_ecc_msg *msg,
				     struct hisi_hpre_sqe *hw_msg, void **data)
{
	struct wd_ecc_dh_in *dh_in = msg->req.src;
	struct wd_ecc_point *pbk = &dh_in->pbk;
	int ret;

	ret = crypto_bin_to_hpre_bin(pbk->x.data, (const char *)pbk->x.data,
				     pbk->x.bsize, pbk->x.dsize, "ecdh compute x");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(pbk->y.data, (const char *)pbk->y.data,
				     pbk->y.bsize, pbk->y.dsize, "ecdh compute y");
	if (ret)
		return ret;

	*data = pbk->x.data;

	return 0;
}

static int u_is_in_p(struct wd_ecc_msg *msg)
{
	struct wd_ecc_in *ecc_in = (struct wd_ecc_in *)msg->req.src;
	struct wd_ecc_dh_in *in = &ecc_in->param.dh_in;
	struct wd_ecc_point *pbk = &in->pbk;
	struct wd_dtb *p = NULL;

	wd_ecc_get_prikey_params((void *)msg->key, &p, NULL, NULL, NULL,
				 NULL, NULL);
	if (unlikely(!p)) {
		WD_ERR("failed to get param p!\n");
		return -WD_EINVAL;
	}
	/*
	 * In big-endian order, when receiving u-array, implementations
	 * of X25519 (but not X448) should mask the most significant bit
	 * in the 1st byte.
	 * See RFC7748 for details.
	 */
	if (msg->curve_id == WD_X25519)
		pbk->x.data[0] &= 0x7f;
	if (!less_than_latter(&pbk->x, p)) {
		WD_ERR("invalid: ux is out of p!\n");
		return -WD_EINVAL;
	}

	if (is_all_zero(&pbk->x, msg)) {
		WD_ERR("invalid: ux is zero!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int ecc_prepare_in(struct wd_ecc_msg *msg,
			  struct hisi_hpre_sqe *hw_msg, void **data)
{
	int ret = -WD_EINVAL;

	switch (msg->req.op_type) {
	case HPRE_SM2_ENC: /* fall through */
	case HPRE_SM2_DEC:
		/* driver to identify sm2 algorithm when async receive */
		hw_msg->sm2_mlen = msg->req.op_type;
		hw_msg->bd_rsv2 = 1; /* fall through */
	case WD_SM2_KG: /* fall through */
	case WD_ECXDH_GEN_KEY:
		ret = ecc_prepare_dh_gen_in(msg, hw_msg, data);
		break;
	case WD_ECXDH_COMPUTE_KEY:
		ret = ecc_prepare_dh_compute_in(msg, hw_msg, data);
		if (!ret && (msg->curve_id == WD_X25519 ||
		    msg->curve_id == WD_X448))
			ret = u_is_in_p(msg);
		break;
	case WD_ECDSA_SIGN: /* fall through */
	case WD_SM2_SIGN:
		ret = ecc_prepare_sign_in(msg, hw_msg, data);
		break;
	case WD_ECDSA_VERIFY: /* fall through */
	case WD_SM2_VERIFY:
		ret = ecc_prepare_verf_in(msg, hw_msg, data);
		break;
	case WD_SM2_ENCRYPT:
		ret = sm2_prepare_enc_in(msg, hw_msg, data);
		break;
	case WD_SM2_DECRYPT:
		ret = sm2_prepare_dec_in(msg, hw_msg, data);
		break;
	default:
		break;
	}

	return ret;
}

static int ecc_prepare_dh_out(struct wd_ecc_out *out, void **data)
{
	struct wd_ecc_point *dh_out = NULL;

	wd_ecxdh_get_out_params(out, &dh_out);
	if (!dh_out) {
		WD_ERR("failed to get ecxdh out param!\n");
		return -WD_EINVAL;
	}

	*data = dh_out->x.data;

	return 0;
}

static int ecc_prepare_out(struct wd_ecc_msg *msg, void **data)
{
	struct wd_ecc_out *out = (struct wd_ecc_out *)msg->req.dst;
	struct wd_ecc_sign_out *sout = &out->param.sout;
	struct wd_sm2_enc_out *eout = &out->param.eout;
	struct wd_sm2_dec_out *dout = &out->param.dout;
	struct wd_sm2_kg_out *kout = &out->param.kout;
	int ret = 0;

	switch (msg->req.op_type) {
	case WD_ECXDH_GEN_KEY: /* fall through */
	case HPRE_SM2_ENC: /* fall through */
	case HPRE_SM2_DEC: /* fall through */
	case WD_ECXDH_COMPUTE_KEY:
		ret = ecc_prepare_dh_out(out, data);
		break;
	case WD_ECDSA_SIGN:
	case WD_SM2_SIGN:
		*data = sout->r.data;
		break;
	case WD_ECDSA_VERIFY:
	case WD_SM2_VERIFY:
		break;
	case WD_SM2_ENCRYPT:
		*data = eout->c1.x.data;
		break;
	case WD_SM2_DECRYPT:
		*data = dout->plaintext.data;
		break;
	case WD_SM2_KG:
		*data = kout->pub.x.data;
		break;
	/* fall-through */
	}

	return ret;
}

/* prepare in/out hw message */
static int ecc_prepare_iot(struct wd_ecc_msg *msg,
			   struct hisi_hpre_sqe *hw_msg)
{
	void *data = NULL;
	size_t i_sz = 0;
	size_t o_sz = 0;
	__u16 kbytes;
	int ret;

	kbytes = msg->key_bytes;
	ecc_get_io_len(hw_msg->alg, kbytes, &i_sz, &o_sz);
	ret = ecc_prepare_in(msg, hw_msg, &data);
	if (ret) {
		WD_ERR("failed to prepare ecc in!\n");
		return ret;
	}
	hw_msg->low_in = LW_U32((uintptr_t)data);
	hw_msg->hi_in = HI_U32((uintptr_t)data);

	ret = ecc_prepare_out(msg, &data);
	if (ret) {
		WD_ERR("failed to prepare ecc out!\n");
		return ret;
	}

	if (!data)
		return 0;

	hw_msg->low_out = LW_U32((uintptr_t)data);
	hw_msg->hi_out = HI_U32((uintptr_t)data);

	return 0;
}

static __u32 get_hw_keysz(__u32 ksz)
{
	__u32 size = 0;

	if (ksz <= BITS_TO_BYTES(256))
		size = BITS_TO_BYTES(256);
	else if (ksz <= BITS_TO_BYTES(384))
		size = BITS_TO_BYTES(384);
	else if (ksz <= BITS_TO_BYTES(576))
		size = BITS_TO_BYTES(576);
	else
		WD_ERR("invalid: keysize %u is error!\n", ksz);

	return size;
}

static void init_prikey(struct wd_ecc_prikey *prikey, __u32 bsz)
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
		WD_ERR("invalid: %s src or data NULL!\n", p_name);
		return -WD_EINVAL;
	}

	if (unlikely(!src->dsize || src->dsize > dst->bsize)) {
		WD_ERR("invalid: %s src dsz %u, dst bsz %u is error!\n",
			p_name, src->dsize, dst->bsize);
		return -WD_EINVAL;
	}

	dst->dsize = src->dsize;
	memset(dst->data, 0, dst->bsize);
	memcpy(dst->data, src->data, src->dsize);

	return 0;
}

static int set_prikey(struct wd_ecc_prikey *prikey,
		      struct wd_ecc_msg *msg)
{
	struct wd_ecc_key *key = (struct wd_ecc_key *)msg->key;
	struct wd_ecc_pubkey *pubkey = key->pubkey;
	struct wd_sm2_enc_in *ein = msg->req.src;
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

static struct wd_ecc_out *create_ecdh_out(struct wd_ecc_msg *msg)
{
	__u32 hsz = get_hw_keysz(msg->key_bytes);
	__u32 data_sz = ECDH_OUT_PARAMS_SZ(hsz);
	__u32 len = sizeof(struct wd_ecc_out) + data_sz +
		sizeof(struct wd_ecc_msg *);
	struct wd_ecc_dh_out *dh_out;
	struct wd_ecc_out *out;

	if (!hsz) {
		WD_ERR("failed to get msg key size!\n");
		return NULL;
	}

	out = malloc(len);
	if (!out) {
		WD_ERR("failed to alloc out memory, sz = %u!\n", len);
		return NULL;
	}

	out->size = data_sz;
	dh_out = (void *)out;
	dh_out->out.x.data = out->data;
	dh_out->out.x.dsize = msg->key_bytes;
	dh_out->out.x.bsize = hsz;
	dh_out->out.y.data = out->data;
	dh_out->out.y.dsize = msg->key_bytes;
	dh_out->out.y.bsize = hsz;
	out->size = data_sz;

	memcpy(out->data + data_sz, &msg, sizeof(void *));

	return out;
}

static int init_req(struct wd_ecc_msg *dst, struct wd_ecc_msg *src,
		    struct wd_ecc_key *key, __u8 req_idx)
{
	struct wd_ecc_key *ecc_key = (struct wd_ecc_key *)src->key;
	struct wd_ecc_pubkey *pubkey = ecc_key->pubkey;

	memcpy(dst, src, sizeof(*dst));
	memcpy(dst + 1, src, sizeof(struct wd_ecc_msg));
	dst->key = (void *)key;
	dst->req.op_type = HPRE_SM2_ENC;

	dst->req.dst = create_ecdh_out(dst);
	if (unlikely(!dst->req.dst))
		return -WD_ENOMEM;

	if (!req_idx)
		dst->req.src = (void *)&pubkey->g;
	else
		dst->req.src = (void *)&pubkey->pub;

	return 0;
}

static struct wd_ecc_msg *create_req(struct wd_ecc_msg *src, __u8 req_idx)
{
	struct wd_ecc_prikey *prikey;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_msg *dst;
	int ret;

	dst = malloc(sizeof(*dst) + sizeof(*src));
	if (unlikely(!dst)) {
		WD_ERR("failed to alloc dst!\n");
		return NULL;
	}

	ecc_key = malloc(sizeof(*ecc_key) + sizeof(*prikey));
	if (unlikely(!ecc_key)) {
		WD_ERR("failed to alloc ecc_key!\n");
		goto fail_alloc_key;
	}

	prikey = (struct wd_ecc_prikey *)(ecc_key + 1);
	ecc_key->prikey = prikey;
	prikey->data = malloc(ECC_PRIKEY_SZ(src->key_bytes));
	if (unlikely(!prikey->data)) {
		WD_ERR("failed to alloc prikey data!\n");
		goto fail_alloc_key_data;
	}
	init_prikey(prikey, src->key_bytes);
	ret = set_prikey(prikey, src);
	if (unlikely(ret))
		goto fail_set_prikey;

	ret = init_req(dst, src, ecc_key, req_idx);
	if (unlikely(ret)) {
		WD_ERR("failed to init req, ret = %d!\n", ret);
		goto fail_set_prikey;
	}

	return dst;

fail_set_prikey:
	free(prikey->data);
fail_alloc_key_data:
	free(ecc_key);
fail_alloc_key:
	free(dst);

	return NULL;
}

static void free_req(struct wd_ecc_msg *msg)
{
	struct wd_ecc_key *key = (void *)msg->key;

	free(key->prikey->data);
	free(key);
	free(msg->req.dst);
	free(msg);
}

static int split_req(struct wd_ecc_msg *src, struct wd_ecc_msg **dst)
{
	/* k * G */
	dst[0] = create_req(src, 0);
	if (unlikely(!dst[0]))
		return -WD_ENOMEM;

	/* k * pub */
	dst[1] = create_req(src, 1);
	if (unlikely(!dst[1])) {
		free_req(dst[0]);
		return -WD_ENOMEM;
	}

	return 0;
}

static int ecc_fill(struct wd_ecc_msg *msg, struct hisi_hpre_sqe *hw_msg)
{
	__u32 hw_sz = get_hw_keysz(msg->key_bytes);
	__u8 op_type = msg->req.op_type;
	int ret;

	if (unlikely(!op_type || (op_type >= WD_EC_OP_MAX &&
		op_type != HPRE_SM2_ENC && op_type != HPRE_SM2_DEC))) {
		WD_ERR("invalid: input op_type %u is error!\n", op_type);
		return -WD_EINVAL;
	}

	if (!hw_sz) {
		WD_ERR("failed to get msg key size!\n");
		return -WD_EINVAL;
	}

	memset(hw_msg, 0, sizeof(*hw_msg));

	/* prepare algorithm */
	ret = ecc_prepare_alg(msg, hw_msg);
	if (ret)
		return ret;

	/* prepare key */
	ret = ecc_prepare_key(msg, hw_msg);
	if (ret)
		return ret;

	/* prepare in/out put */
	ret = ecc_prepare_iot(msg, hw_msg);
	if (ret)
		return ret;

	hw_msg->done = 0x1;
	hw_msg->etype = 0x0;
	hw_msg->low_tag = msg->tag;
	hw_msg->task_len1 = hw_sz / BYTE_BITS - 0x1;

	return ret;
}

static int ecc_general_send(handle_t ctx, struct wd_ecc_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg;
	__u16 send_cnt = 0;
	int ret;

	ret = ecc_fill(msg, &hw_msg);
	if (ret)
		return ret;

	return hisi_qm_send(h_qp, &hw_msg, 1, &send_cnt);
}


static int sm2_enc_send(handle_t ctx, struct wd_ecc_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_sm2_enc_in *ein = msg->req.src;
	struct wd_ecc_msg *msg_dst[2] = {NULL};
	struct hisi_hpre_sqe hw_msg[2] = {0};
	struct wd_hash_mt *hash = &msg->hash;
	__u16 send_cnt = 0;
	int ret;

	if (ein->plaintext.dsize <= HW_PLAINTEXT_BYTES_MAX &&
		hash->type == WD_HASH_SM3)
		return ecc_general_send(ctx, msg);

	if (unlikely(!ein->k_set)) {
		WD_ERR("invalid: k not set!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!hash->cb || hash->type >= WD_HASH_MAX)) {
		WD_ERR("invalid: input hash type %u is error!\n", hash->type);
		return -WD_EINVAL;
	}

	/*
	 * split message into two inner request message
	 * first message used to compute k * g
	 * second message used to compute k * pb
	 */
	ret = split_req(msg, msg_dst);
	if (unlikely(ret)) {
		WD_ERR("failed to split req, ret = %d!\n", ret);
		return ret;
	}

	ret = ecc_fill(msg_dst[0], &hw_msg[0]);
	if (unlikely(ret)) {
		WD_ERR("failed to fill 1th sqe, ret = %d!\n", ret);
		goto fail_fill_sqe;
	}

	ret = ecc_fill(msg_dst[1], &hw_msg[1]);
	if (unlikely(ret)) {
		WD_ERR("failed to fill 2th sqe, ret = %d!\n", ret);
		goto fail_fill_sqe;
	}

	ret = hisi_qm_get_free_sqe_num(h_qp);
	if (ret < SM2_SQE_NUM) {
		ret = -WD_EBUSY;
		goto fail_fill_sqe;
	}

	ret = hisi_qm_send(h_qp, &hw_msg, SM2_SQE_NUM, &send_cnt);
	if (unlikely(ret))
		goto fail_fill_sqe;

	return ret;

fail_fill_sqe:
	free_req(msg_dst[0]);
	free_req(msg_dst[1]);

	return ret;
}

static int sm2_dec_send(handle_t ctx, struct wd_ecc_msg *msg)
{
	struct wd_sm2_dec_in *din = (void *)msg->req.src;
	struct wd_hash_mt *hash = &msg->hash;
	struct wd_ecc_msg *dst;
	int ret;

	/* c2 data lens <= 4096 bit */
	if (din->c2.dsize <= BITS_TO_BYTES(4096) &&
		hash->type == WD_HASH_SM3)
		return ecc_general_send(ctx, msg);

	if (unlikely(!hash->cb || hash->type >= WD_HASH_MAX)) {
		WD_ERR("invalid: input hash type %u is error!\n", hash->type);
		return -WD_EINVAL;
	}

	/* dst last store point "struct wd_ecc_msg *" */
	dst = malloc(sizeof(*dst) + sizeof(*msg));
	if (unlikely(!dst))
		return -WD_ENOMEM;

	/* compute d * c1 */
	memcpy(dst, msg, sizeof(*dst));
	memcpy(dst + 1, msg, sizeof(struct wd_ecc_msg));

	dst->req.op_type = HPRE_SM2_DEC;
	dst->req.src = (void *)&din->c1;

	/* dst->req.dst last store point "struct wd_ecc_msg *" */
	dst->req.dst = create_ecdh_out(dst);
	if (unlikely(!dst->req.dst)) {
		ret = -WD_ENOMEM;
		goto free_dst;
	}

	ret = ecc_general_send(ctx, dst);
	if (unlikely(ret))
		goto free_req_dst;

	return ret;

free_req_dst:
	free(dst->req.dst);
free_dst:
	free(dst);
	return ret;
}

static int ecc_send(handle_t ctx, struct wd_ecc_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);

	hisi_set_msg_id(h_qp, &msg->tag);
	if (msg->req.op_type == WD_SM2_ENCRYPT)
		return sm2_enc_send(ctx, msg);
	else if (msg->req.op_type == WD_SM2_DECRYPT)
		return sm2_dec_send(ctx, msg);

	return ecc_general_send(ctx, msg);
}

static int ecdh_out_transfer(struct wd_ecc_msg *msg, struct hisi_hpre_sqe *hw_msg)
{
	struct wd_ecc_out *out = (void *)msg->req.dst;
	struct wd_ecc_point *key = NULL;
	struct wd_dtb *y = NULL;
	int ret;

	if (msg->req.op_type == HPRE_SM2_DEC ||
		msg->req.op_type == HPRE_SM2_ENC)
		return WD_SUCCESS;

	wd_ecxdh_get_out_params(out, &key);

	if (hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY)
		y = &key->y;

	ret = hpre_tri_bin_transfer(&key->x, y, NULL);
	if (ret) {
		WD_ERR("failed to transfer ecdh format to crypto bin!\n");
		return ret;
	}

	return WD_SUCCESS;
}

static int ecc_sign_out_transfer(struct wd_ecc_msg *msg,
				 struct hisi_hpre_sqe *hw_msg)
{
	struct wd_ecc_out *out = (void *)msg->req.dst;
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	int ret;

	wd_sm2_get_sign_out_params(out, &r, &s);
	if (!r || !s) {
		WD_ERR("failed to get ecc sign out param!\n");
		return -WD_EINVAL;
	}

	ret = hpre_tri_bin_transfer(r, s, NULL);
	if (ret)
		WD_ERR("failed to tri ecc sign out r&s!\n");

	return ret;
}

static int ecc_verf_out_transfer(struct wd_ecc_msg *msg,
				 struct hisi_hpre_sqe *hw_msg)
{
	__u32 result = hw_msg->low_out;

	result >>= 1;
	result &= 1;
	if (!result)
		msg->result = WD_VERIFY_ERR;

	return WD_SUCCESS;
}

static int sm2_kg_out_transfer(struct wd_ecc_msg *msg,
			       struct hisi_hpre_sqe *hw_msg)
{
	struct wd_ecc_out *out = (void *)msg->req.dst;
	struct wd_ecc_point *pbk = NULL;
	struct wd_dtb *prk = NULL;
	int ret;

	wd_sm2_get_kg_out_params(out, &prk, &pbk);
	if (!prk || !pbk) {
		WD_ERR("failed to get sm2 kg out param!\n");
		return -WD_EINVAL;
	}

	ret = hpre_tri_bin_transfer(prk, &pbk->x, &pbk->y);
	if (ret)
		WD_ERR("failed to tri sm2 kg out param!\n");

	return ret;
}

static int sm2_enc_out_transfer(struct wd_ecc_msg *msg,
				struct hisi_hpre_sqe *hw_msg)
{
	struct wd_ecc_out *out = (void *)msg->req.dst;
	struct wd_ecc_point *c1 = NULL;
	int ret;

	wd_sm2_get_enc_out_params(out, &c1, NULL, NULL);
	if (!c1) {
		WD_ERR("failed to get sm2 encode out param!\n");
		return -WD_EINVAL;
	}

	ret = hpre_tri_bin_transfer(&c1->x, &c1->y, NULL);
	if (ret)
		WD_ERR("failed to tri sm2 encode out param!\n");

	return ret;
}

static int ecc_out_transfer(struct wd_ecc_msg *msg,
			    struct hisi_hpre_sqe *hw_msg)
{
	int ret = -WD_EINVAL;
	void *va;

	/* async */
	if (LW_U16(hw_msg->low_tag)) {
		va = VA_ADDR(hw_msg->hi_out, hw_msg->low_out);
		msg->req.dst = container_of(va, struct wd_ecc_out, data);
	}

	if (hw_msg->alg == HPRE_ALG_SM2_SIGN ||
		hw_msg->alg == HPRE_ALG_ECDSA_SIGN)
		ret = ecc_sign_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_SM2_VERF ||
		hw_msg->alg == HPRE_ALG_ECDSA_VERF)
		ret = ecc_verf_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_SM2_ENC)
		ret = sm2_enc_out_transfer(msg, hw_msg);
	else if (hw_msg->alg == HPRE_ALG_SM2_DEC)
		ret = 0;
	else if (hw_msg->alg == HPRE_ALG_SM2_KEY_GEN)
		ret = sm2_kg_out_transfer(msg, hw_msg);
	else if	(hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY ||
		 hw_msg->alg == HPRE_ALG_X_DH_MULTIPLY)
		ret = ecdh_out_transfer(msg, hw_msg);
	else
		WD_ERR("invalid: algorithm type %u is error!\n", hw_msg->alg);

	return ret;
}


static __u32 get_hash_bytes(__u8 type)
{
	__u32 val = 0;

	switch (type) {
	case WD_HASH_SHA1:
		val = BITS_TO_BYTES(160);
		break;
	case WD_HASH_SHA256: /* fall through */
	case WD_HASH_SM3:
		val = BITS_TO_BYTES(256);
		break;
	case WD_HASH_MD4: /* fall through */
	case WD_HASH_MD5:
		val = BITS_TO_BYTES(128);
		break;
	case WD_HASH_SHA224:
		val = BITS_TO_BYTES(224);
		break;
	case WD_HASH_SHA384:
		val = BITS_TO_BYTES(384);
		break;
	case WD_HASH_SHA512:
		val = BITS_TO_BYTES(512);
		break;
	default:
		WD_ERR("invalid: hash type %u is error!\n", type);
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

static int sm2_kdf(struct wd_dtb *out, struct wd_ecc_point *x2y2,
		   __u64 m_len, struct wd_hash_mt *hash)
{
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

	/*
	 * Use big-endian mode to store the value of counter i in ctr,
	 * i >> 8/16/24 for intercepts 8-bits whole-byte data.
	 */
	out->dsize = m_len;
	while (1) {
		in_len = 0;
		ctr[3] = i & 0xFF;
		ctr[2] = (i >> 8) & 0xFF;
		ctr[1] = (i >> 16) & 0xFF;
		ctr[0] = (i >> 24) & 0xFF;
		msg_pack(p_in, &in_len, x2y2->x.data, x2y2_len);
		msg_pack(p_in, &in_len, ctr, sizeof(ctr));

		t_out = m_len >= h_bytes ? tmp : p_out;
		ret = hash->cb(p_in, in_len, t_out, h_bytes, hash->usr);
		if (ret) {
			WD_ERR("%s failed to do hash cb, ret = %d!\n", __func__, ret);
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

	return -WD_EINVAL;
}

static int sm2_hash(struct wd_dtb *out, struct wd_ecc_point *x2y2,
		    struct wd_dtb *msg, struct wd_hash_mt *hash)
{
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
		WD_ERR("%s failed to do hash cb, ret = %d!\n", __func__, ret);
		goto fail;
	}

	out->dsize = h_bytes;
	memcpy(out->data, hash_out, out->dsize);

fail:
	free(p_in);

	return ret;
}

static int sm2_convert_enc_out(struct wd_ecc_msg *src,
			       struct wd_ecc_msg *first,
			       struct wd_ecc_msg *second)
{
	struct wd_ecc_out *out = (void *)src->req.dst;
	struct wd_ecc_in *in = (void *)src->req.src;
	struct wd_sm2_enc_out *eout = &out->param.eout;
	struct wd_sm2_enc_in *ein = &in->param.ein;
	struct wd_hash_mt *hash = &src->hash;
	struct wd_ecc_dh_out *dh_out;
	__u32 ksz = src->key_bytes;
	struct wd_ecc_point x2y2;
	struct wd_dtb *kdf_out;
	int ret;

	/*
	 * encode origin out data format:
	 * | x1y1(2*256bit) | x2y2(2*256bit) | other |
	 * final out data format:
	 * | c1(2*256bit)   | c2(plaintext size) | c3(256bit) |
	 */
	dh_out = second->req.dst;
	x2y2.x.data = (void *)dh_out->out.x.data;
	x2y2.x.dsize = ksz;
	x2y2.y.dsize = ksz;
	x2y2.y.data = (void *)(x2y2.x.data + ksz);

	/* C1 */
	dh_out = first->req.dst;
	memcpy(eout->c1.x.data, dh_out->out.x.data, ksz + ksz);

	/* C3 = hash(x2 || M || y2) */
	ret = sm2_hash(&eout->c3, &x2y2, &ein->plaintext, hash);
	if (unlikely(ret)) {
		WD_ERR("failed to do sm2 hash, ret = %d!\n", ret);
		return ret;
	}

	/* t = KDF(x2 || y2, klen) */
	kdf_out = &eout->c2;
	ret = sm2_kdf(kdf_out, &x2y2, ein->plaintext.dsize, hash);
	if (unlikely(ret)) {
		WD_ERR("%s failed to do sm2 kdf, ret = %d!\n", __func__, ret);
		return ret;
	}

	/* C2 = M XOR t */
	sm2_xor(kdf_out, &ein->plaintext);

	return ret;
}

static int sm2_convert_dec_out(struct wd_ecc_msg *src,
			       struct wd_ecc_msg *dst)
{
	struct wd_ecc_out *out = (void *)src->req.dst;
	struct wd_sm2_dec_out *dout = &out->param.dout;
	struct wd_ecc_in *in = (void *)src->req.src;
	struct wd_sm2_dec_in *din = &in->param.din;
	struct wd_ecc_dh_out *dh_out;
	__u32 ksz = dst->key_bytes;
	struct wd_ecc_point x2y2;
	struct wd_dtb tmp = {0};
	char buff[64] = {0};
	int ret;

	/*
	 * decode origin out data format:
	 * | x2y2(2*256bit) |   other      |
	 * final out data format:
	 * |         plaintext             |
	 */

	dh_out = dst->req.dst;
	x2y2.x.data = (void *)dh_out->out.x.data;
	x2y2.y.data = (void *)(x2y2.x.data + ksz);
	x2y2.x.dsize = ksz;
	x2y2.y.dsize = ksz;

	tmp.data = buff;

	/* t = KDF(x2 || y2, klen) */
	ret = sm2_kdf(&dout->plaintext, &x2y2, din->c2.dsize, &src->hash);
	if (unlikely(ret)) {
		WD_ERR("%s failed to do sm2 kdf, ret = %d!\n", __func__, ret);
		return ret;
	}

	/* M' = C2 XOR t */
	sm2_xor(&dout->plaintext, &din->c2);

	/* u = hash(x2 || M' || y2), save u to din->c2 */
	ret = sm2_hash(&tmp, &x2y2, &dout->plaintext, &src->hash);
	if (unlikely(ret)) {
		WD_ERR("failed to compute c3, ret = %d!\n", ret);
		return ret;
	}

	/* u == c3 */
	ret = is_equal(&tmp, &din->c3);
	if (ret)
		WD_ERR("failed to decode sm2, u != C3!\n");

	return ret;
}

static int ecc_sqe_parse(struct wd_ecc_msg *msg, struct hisi_hpre_sqe *hw_msg)
{
	int ret;

	if (hw_msg->done != HPRE_HW_TASK_DONE ||
			hw_msg->etype || hw_msg->etype1) {
		WD_ERR("failed to do ecc task! done=0x%x, etype=0x%x, etype1=0x%x!\n",
			hw_msg->done, hw_msg->etype, hw_msg->etype1);
		if (hw_msg->etype1 & HPRE_HW_SVA_ERROR)
			WD_ERR("failed to SVA prefetch: status=%u!\n",
				hw_msg->sva_status);

		if (hw_msg->done == HPRE_HW_TASK_INIT)
			ret = -WD_EINVAL;
		else
			ret = -WD_IN_EPARA;
	} else {
		msg->result = WD_SUCCESS;
		ret = ecc_out_transfer(msg, hw_msg);
		if (ret) {
			msg->result = WD_OUT_EPARA;
			WD_ERR("failed to transfer out ecc BD, ret = %d!\n", ret);
		}
		msg->tag = LW_U16(hw_msg->low_tag);
	}

	return ret;
}

static int parse_second_sqe(handle_t h_qp,
			    struct wd_ecc_msg *msg,
			    struct wd_ecc_msg **second)
{
	struct hisi_hpre_sqe hw_msg;
	struct wd_ecc_msg *dst;
	__u16 recv_cnt = 0;
	int cnt = 0;
	void *data;
	__u32 hsz;
	int ret;

	while (1) {
		ret = hisi_qm_recv(h_qp, &hw_msg, 1, &recv_cnt);
		if (ret == -WD_EAGAIN) {
			if (cnt++ > MAX_WAIT_CNT)
				return ret;
			usleep(1);
			continue;
		} else if (ret) {
			return ret;
		}
		break;
	}

	data = VA_ADDR(hw_msg.hi_out, hw_msg.low_out);
	hsz = (hw_msg.task_len1 + 1) * BYTE_BITS;
	dst = *(struct wd_ecc_msg **)((uintptr_t)data +
		hsz * ECDH_OUT_PARAM_NUM);
	hw_msg.low_tag = 0; /* use sync mode */
	ret = ecc_sqe_parse(dst, &hw_msg);
	msg->result = dst->result;
	*second = dst;

	return ret;
}

static int sm2_enc_parse(handle_t h_qp,
			 struct wd_ecc_msg *msg, struct hisi_hpre_sqe *hw_msg)
{
	__u16 tag = LW_U16(hw_msg->low_tag);
	struct wd_ecc_msg *second = NULL;
	struct wd_ecc_msg *first;
	struct wd_ecc_msg src;
	void *data;
	__u32 hsz;
	int ret;

	data = VA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	hsz = (hw_msg->task_len1 + 1) * BYTE_BITS;
	first = *(struct wd_ecc_msg **)((uintptr_t)data +
		hsz * ECDH_OUT_PARAM_NUM);
	memcpy(&src, first + 1, sizeof(src));

	/* parse first sqe */
	hw_msg->low_tag = 0; /* use sync mode */
	ret = ecc_sqe_parse(first, hw_msg);
	if (ret) {
		WD_ERR("failed to parse first BD, ret = %d!\n", ret);
		goto free_first;
	}

	/* parse second sqe */
	ret = parse_second_sqe(h_qp, msg, &second);
	if (unlikely(ret)) {
		WD_ERR("failed to parse second BD, ret = %d!\n", ret);
		goto free_first;
	}

	ret = sm2_convert_enc_out(&src, first, second);
	if (unlikely(ret)) {
		WD_ERR("failed to convert sm2 std format, ret = %d!\n", ret);
		goto free_second;
	}
free_second:
	free_req(second);
free_first:
	free_req(first);
	msg->tag = tag;
	return ret;
}

static int sm2_dec_parse(handle_t ctx, struct wd_ecc_msg *msg,
			 struct hisi_hpre_sqe *hw_msg)
{
	__u16 tag = LW_U16(hw_msg->low_tag);
	struct wd_ecc_msg *dst;
	struct wd_ecc_msg src;
	void *data;
	__u32 hsz;
	int ret;

	data = VA_ADDR(hw_msg->hi_out, hw_msg->low_out);
	hsz = (hw_msg->task_len1 + 1) * BYTE_BITS;
	dst = *(struct wd_ecc_msg **)((uintptr_t)data +
		hsz * ECDH_OUT_PARAM_NUM);
	memcpy(&src, dst + 1, sizeof(src));

	/* parse first sqe */
	hw_msg->low_tag = 0; /* use sync mode */
	ret = ecc_sqe_parse(dst, hw_msg);
	if (ret) {
		WD_ERR("failed to parse decode BD, ret = %d!\n", ret);
		goto fail;
	}
	msg->result = dst->result;

	ret = sm2_convert_dec_out(&src, dst);
	if (unlikely(ret)) {
		WD_ERR("failed to convert sm2 decode out, ret = %d!\n", ret);
		goto fail;
	}
fail:
	msg->tag = tag;
	free(dst->req.dst);
	free(dst);

	return ret;
}

static int ecc_recv(handle_t ctx, struct wd_ecc_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg;
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &hw_msg, 1, &recv_cnt);
	if (ret)
		return ret;

	ret = hisi_check_bd_id(h_qp, msg->tag, hw_msg.low_tag);
	if (ret)
		return ret;

	if (hw_msg.alg == HPRE_ALG_ECDH_MULTIPLY &&
		hw_msg.sm2_mlen == HPRE_SM2_ENC)
		return sm2_enc_parse(h_qp, msg, &hw_msg);
	else if (hw_msg.alg == HPRE_ALG_ECDH_MULTIPLY &&
		hw_msg.sm2_mlen == HPRE_SM2_DEC)
		return sm2_dec_parse(h_qp, msg, &hw_msg);

	return ecc_sqe_parse(msg, &hw_msg);
}

static struct wd_ecc_driver ecc_hisi_hpre = {
	.drv_name		= "hisi_hpre",
	.alg_name		= "ecc",
	.drv_ctx_size		= sizeof(struct hisi_hpre_ctx),
	.init			= hpre_init,
	.exit			= hpre_exit,
	.send			= ecc_send,
	.recv			= ecc_recv,
};

WD_RSA_SET_DRIVER(rsa_hisi_hpre);
WD_DH_SET_DRIVER(dh_hisi_hpre);
WD_ECC_SET_DRIVER(ecc_hisi_hpre);
