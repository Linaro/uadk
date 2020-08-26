/* SPDX-License-Identifier: Apache-2.0 */
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
#include "../include/drv/wd_rsa_drv.h"

#define HPRE_HW_TASK_DONE	3
#define HPRE_HW_TASK_INIT	1

#define QM_L32BITS_MASK		0xffffffff
#define QM_HADDR_SHIFT		32
#define LW_U32(pa)	((__u32)((pa) & QM_L32BITS_MASK))
#define HI_U32(pa)	((__u32)(((pa) >> QM_HADDR_SHIFT) & QM_L32BITS_MASK))

#include "hisi_qm_udrv.h"
#include "smm.h"
#include "wd.h"
#include "wd_sched.h"

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT		3
#define CRT_PARAMS_SZ(key_size)		((5 * (key_size)) >> 1)
#define CRT_GEN_PARAMS_SZ(key_size)	((7 * (key_size)) >> 1)
#define GEN_PARAMS_SZ(key_size)		((key_size) << 1)
#define CRT_PARAM_SZ(key_size)		((key_size) >> 1)
#define GET_NEGATIVE(val)	(0 - (val))
#define XTS_MODE_KEY_DIVISOR	2
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define CTX_ID_MAX_NUM		64

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

/* I think put venodr hw msg as a user interface is not suitable here */
struct hisi_hpre_sqe {
	__u32 alg	: 5;

	/* error type */
	__u32 etype	:11;
	__u32 resv0	: 14;
	__u32 done	: 2;
	__u32 task_len1	: 8;
	__u32 task_len2	: 8;
	__u32 mrttest_num : 8;
	__u32 resv1	: 8;
	__u32 low_key;
	__u32 hi_key;
	__u32 low_in;
	__u32 hi_in;
	__u32 low_out;
	__u32 hi_out;
	__u32 tag	:16;
	__u32 resv2	:16;
	__u32 rsvd1[7];
};

struct hisi_hpre_ctx {
	struct wd_ctx_config	config;
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

static int hpre_bin_to_crypto_bin(char *dst, const char *src, int b_size)
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

static int fill_rsa_crt_prikey2(struct wd_rsa_prikey *prikey,
				   void **data)
{
	struct wd_dtb *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	int ret;

	wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp,
				&wd_qinv, &wd_q, &wd_p);
	ret = crypto_bin_to_hpre_bin(wd_dq->data, (const char *)wd_dq->data,
				wd_dq->bsize, wd_dq->dsize);
	if (ret) {
		WD_ERR("rsa crt dq format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(wd_dp->data, (const char *)wd_dp->data,
				wd_dp->bsize, wd_dp->dsize);
	if (ret) {
		WD_ERR("rsa crt dp format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(wd_q->data, (const char *)wd_q->data,
				wd_q->bsize, wd_q->dsize);
	if (ret) {
		WD_ERR("rsa crt q format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(wd_p->data,
		(const char *)wd_p->data, wd_p->bsize, wd_p->dsize);
	if (ret) {
		WD_ERR("rsa crt p format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(wd_qinv->data,
		(const char *)wd_qinv->data, wd_qinv->bsize, wd_qinv->dsize);
	if (ret) {
		WD_ERR("rsa crt qinv format fail!\n");
		return ret;
	}
	*data = wd_dq->data;

	return (int)(wd_dq->bsize + wd_qinv->bsize + wd_p->bsize +
			wd_q->bsize + wd_dp->bsize);
}

static int fill_rsa_prikey1(struct wd_rsa_prikey *prikey, void **data)
{
	struct wd_dtb *wd_d, *wd_n;
	int ret;

	wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
	ret = crypto_bin_to_hpre_bin(wd_d->data, (const char *)wd_d->data,
				wd_d->bsize, wd_d->dsize);
	if (ret) {
		WD_ERR("rsa prikey1 d format fail!\n");
		return ret;
	}

	ret = crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize);
	if (ret) {
		WD_ERR("rsa prikey1 n format fail!\n");
		return ret;
	}
	*data = wd_d->data;

	return (int)(wd_n->bsize + wd_d->bsize);
}

static int fill_rsa_pubkey(struct wd_rsa_pubkey *pubkey, void **data)
{
	struct wd_dtb *wd_e, *wd_n;
	int ret;

	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
	ret = crypto_bin_to_hpre_bin(wd_e->data, (const char *)wd_e->data,
				wd_e->bsize, wd_e->dsize);
	if (ret) {
		WD_ERR("rsa pubkey e format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize);
	if (ret) {
		WD_ERR("rsa pubkey n format fail!\n");
		return ret;
	}
	*data = wd_e->data;
	return (int)(wd_n->bsize + wd_e->bsize);
}

static int fill_rsa_genkey_in(struct wd_rsa_kg_in *genkey)
{
	struct wd_dtb e, q, p;
	int ret;

	wd_rsa_get_kg_in_params(genkey, &e, &q, &p);

	ret = crypto_bin_to_hpre_bin(e.data, (const char *)e.data,
				e.bsize, e.dsize);
	if (ret) {
		WD_ERR("rsa genkey e format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(q.data, (const char *)q.data,
				q.bsize, q.dsize);
	if (ret) {
		WD_ERR("rsa genkey q format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(p.data, (const char *)p.data,
				p.bsize, p.dsize);
	if (ret) {
		WD_ERR("rsa genkey p format fail!\n");
		return ret;
	}

	return WD_SUCCESS;
}

static int hpre_tri_bin_transfer(struct wd_dtb *bin0, struct wd_dtb *bin1,
				struct wd_dtb *bin2)
{
	int ret;

	ret = hpre_bin_to_crypto_bin(bin0->data, (const char *)bin0->data,
				bin0->bsize);
	if (!ret)
		return -WD_EINVAL;

	bin0->dsize = ret;

	if (bin1) {
		ret = hpre_bin_to_crypto_bin(bin1->data,
			(const char *)bin1->data,
					bin1->bsize);
		if (!ret)
			return -WD_EINVAL;

		bin1->dsize = ret;
	}

	if (bin2) {
		ret = hpre_bin_to_crypto_bin(bin2->data,
			(const char *)bin2->data, bin2->bsize);
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
	int ret;

	msg->result = WD_SUCCESS;
	if (hw_msg->alg == HPRE_ALG_KG_CRT) {
		req->dst_bytes = CRT_GEN_PARAMS_SZ(kbytes);
		wd_rsa_get_kg_out_crt_params(key, &qinv, &dq, &dp);
		ret = hpre_tri_bin_transfer(&qinv, &dq, &dp);
		if (ret) {
			WD_ERR("parse rsa genkey qinv&&dq&&dp format fail!\n");
			return ret;
		}

		wd_rsa_set_kg_out_crt_psz(key, qinv.dsize,
					       dq.dsize, dp.dsize);
	} else if (hw_msg->alg == HPRE_ALG_KG_STD) {
		req->dst_bytes = GEN_PARAMS_SZ(kbytes);

		wd_rsa_get_kg_out_params(key, &d, &n);
		ret = hpre_tri_bin_transfer(&d, &n, NULL);
		if (ret) {
			WD_ERR("parse rsa genkey1 d&&n format fail!\n");
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
			if (ret <= 0)
				return ret;
		} else {
			ret = fill_rsa_prikey1((void *)msg->key, &data);
			if (ret < 0)
				return ret;
			hw_msg->alg = HPRE_ALG_NC_NCRT;
		}
	} else if (req->op_type == WD_RSA_VERIFY) {
		ret = fill_rsa_pubkey((void *)msg->key, &data);
		if (ret < 0)
			return ret;
		hw_msg->alg = HPRE_ALG_NC_NCRT;
	} else if (req->op_type == WD_RSA_GENKEY) {
		ret = fill_rsa_genkey_in((void *)msg->key);
		if (ret)
			return ret;
		ret = wd_rsa_kg_in_data((void *)msg->key, (char **)&data);
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

static int hisi_hpre_init(struct wd_ctx_config *config, void *priv)
{
	struct hisi_hpre_ctx *hpre_ctx = (struct hisi_hpre_ctx *)priv;
	struct hisi_qm_priv qm_priv;
	handle_t h_ctx, h_qp;
	int i, j;

	/* allocate qp for each context */
	qm_priv.sqe_size = sizeof(struct hisi_hpre_sqe);
	qm_priv.op_type = 0;
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp) {
			WD_ERR("failed to alloc qp!\n");
			goto out;
		}

		memcpy(&hpre_ctx->config, config, sizeof(struct wd_ctx_config));
	}

	return 0;
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}

	return -EINVAL;
}

static void hisi_hpre_exit(void *priv)
{
	struct hisi_hpre_ctx *hpre_ctx = (struct hisi_hpre_ctx *)priv;
	struct wd_ctx_config *config = &hpre_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
}

static int hisi_hpre_send(handle_t ctx, struct wd_rsa_msg *msg)
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

	hw_msg.done = 0x1;
	hw_msg.etype = 0x0;
	hw_msg.tag = msg->tag;

	ret = hisi_qm_send(h_qp, &hw_msg, 1, &send_cnt);
	if (ret < 0)
		WD_ERR("hisi_qm_send is err(%d)!\n", ret);

	return ret;
}

static int hisi_hpre_recv(handle_t ctx, struct wd_rsa_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg = {0};
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &hw_msg, 1, &recv_cnt);
	if (ret < 0) {
		if (ret != -EAGAIN)
			WD_ERR("hisi_qm_recv is err(%d)!\n", ret);

		return ret;
	}

	if (hw_msg.done != HPRE_HW_TASK_DONE || hw_msg.etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "rsa",
			hw_msg.done, hw_msg.etype);
		if (hw_msg.done == HPRE_HW_TASK_INIT)
			msg->result = WD_EINVAL;
		else
			msg->result = WD_IN_EPARA;
	} else {
		msg->tag = hw_msg.tag;
		ret = rsa_out_transfer(msg, &hw_msg);
		if (ret) {
			WD_ERR("qm rsa out transfer fail!\n");
			msg->result = WD_OUT_EPARA;
		} else {
			msg->result = WD_SUCCESS;
		}
	}

	return 0;
}

static struct wd_rsa_driver hisi_hpre = {
	.drv_name		= "hisi_hpre",
	.alg_name		= "rsa",
	.drv_ctx_size		= sizeof(struct hisi_hpre_ctx),
	.init			= hisi_hpre_init,
	.exit			= hisi_hpre_exit,
	.send			= hisi_hpre_send,
	.recv			= hisi_hpre_recv,
};

WD_RSA_SET_DRIVER(hisi_hpre);
