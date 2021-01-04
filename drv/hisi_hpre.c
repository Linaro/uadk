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
#include "hisi_qm_udrv.h"
#include "wd.h"
#include "../include/drv/wd_rsa_drv.h"
#include "../include/drv/wd_dh_drv.h"
#include "../include/drv/wd_ecc_drv.h"

#define HPRE_HW_TASK_DONE	3
#define HPRE_HW_TASK_INIT	1

#define HPRE_HW_V2_ALG_TYPE	0
#define HPRE_HW_V3_ECC_ALG_TYPE	1

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

/* I think put venodr hw msg as a user interface is not suitable here */
struct hisi_hpre_sqe {
	__u32 alg	: 5;

	/* error type */
	__u32 etype	: 11;
	__u32 resv0	: 14;
	__u32 done	: 2;
	__u32 task_len1	: 8;
	__u32 task_len2	: 8;
	__u32 mrttest_num : 8;
	__u32 uwkey_enb : 1;
	__u32 sm2_ksel	: 1;
	__u32 resv1	: 6;
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
				  int b_size, int d_size, const char *p_name)
{
	int i = d_size - 1;
	bool is_hpre_bin;
	int j;

	if (!dst || !src || b_size <= 0 || d_size <= 0) {
		WD_ERR("%s: trans to hpre bin params err!\n", p_name);
		return -WD_EINVAL;
	}

	if (b_size < d_size) {
		WD_ERR("%s: trans to hpre bin param data is too long!\n", p_name);
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
		WD_ERR("%s trans to crypto bin: params err!\n", p_name);
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

	return (int)(wd_dq->bsize + wd_qinv->bsize + wd_p->bsize +
			wd_q->bsize + wd_dp->bsize);
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

	return (int)(wd_n->bsize + wd_d->bsize);
}

static int fill_rsa_pubkey(struct wd_rsa_pubkey *pubkey, void **data)
{
	struct wd_dtb *wd_e, *wd_n;
	int ret;

	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
	ret = crypto_bin_to_hpre_bin(wd_e->data, (const char *)wd_e->data,
				wd_e->bsize, wd_e->dsize, "rsa e");
	if (ret) {
		WD_ERR("rsa pubkey e format fail!\n");
		return ret;
	}
	ret = crypto_bin_to_hpre_bin(wd_n->data, (const char *)wd_n->data,
				wd_n->bsize, wd_n->dsize, "rsa n");
	if (ret)
		return ret;

	*data = wd_e->data;
	return (int)(wd_n->bsize + wd_e->bsize);
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
	if (!strncmp(alg_name, "ecc", sizeof("ecc")))
		qm_priv.op_type = HPRE_HW_V3_ECC_ALG_TYPE;
	else
		qm_priv.op_type = HPRE_HW_V2_ALG_TYPE;

	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
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

	return -EINVAL;
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

	if (hw_msg.done != HPRE_HW_TASK_DONE || hw_msg.etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "rsa",
			hw_msg.done, hw_msg.etype);
		if (hw_msg.done == HPRE_HW_TASK_INIT)
			msg->result = WD_EINVAL;
		else
			msg->result = WD_IN_EPARA;
	} else {
		msg->tag = LW_U16(hw_msg.low_tag);
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
		WD_ERR("dh x para format fail!\n");
		return ret;
	}

	ret = crypto_bin_to_hpre_bin(p, (const char *)p,
				msg->key_bytes, req->pbytes, "dh p");
	if (ret) {
		WD_ERR("dh p para format fail!\n");
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
			WD_ERR("dh g para format fail!\n");
			return ret;
		}

		hw_msg.low_in = LW_U32((uintptr_t)msg->g);
		hw_msg.hi_in = HI_U32((uintptr_t)msg->g);
	}

	ret = fill_dh_xp_params(msg, &hw_msg);
	if (ret)
		return ret;

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

	if (hw_msg.done != HPRE_HW_TASK_DONE || hw_msg.etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "dh",
			hw_msg.done, hw_msg.etype);
		if (hw_msg.done == HPRE_HW_TASK_INIT)
			msg->result = WD_EINVAL;
		else
			msg->result = WD_IN_EPARA;
	} else {
		msg->tag = LW_U16(hw_msg.low_tag);
		ret = dh_out_transfer(msg, &hw_msg);
		if (ret) {
			WD_ERR("dh out transfer fail!\n");
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
	case WD_SM2_VERIFY:
		hw_msg->alg = HPRE_ALG_SM2_VERF;
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
	case WD_ECXDH_COMPUTE_KEY:
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
	 * This is a pretreatment of x25519/x448, as described in RFC7748
	 * hpre is big-endian, so the byte is opposite.
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

static int ecc_prepare_key(struct wd_ecc_msg *msg,
			      struct hisi_hpre_sqe *hw_msg)
{
	void *data = NULL;
	int ret;

	if (msg->req.op_type >= WD_EC_OP_MAX) {
		WD_ERR("op_type = %u error!\n", msg->req.op_type);
		return -WD_EINVAL;
	}

	if (msg->req.op_type == WD_SM2_DECRYPT ||
		msg->req.op_type == WD_ECDSA_SIGN ||
		msg->req.op_type == WD_SM2_SIGN ||
		msg->req.op_type == WD_ECXDH_GEN_KEY ||
		msg->req.op_type == WD_ECXDH_COMPUTE_KEY) {
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
	struct wd_ecc_sign_in *in = (void *)msg->req.src;
	struct wd_dtb *n = NULL;
	struct wd_dtb *e = NULL;
	struct wd_dtb *k = NULL;
	int ret;

	if (!in->dgst_set) {
		WD_ERR("prepare sign_in, !\n");
		return -WD_EINVAL;
	}

	if (!in->k_set) {
		if (msg->req.op_type == WD_ECDSA_SIGN) {
			WD_ERR("random k not set!\n");
			return -WD_EINVAL;
		}
		hw_msg->sm2_ksel = 1;
	}

	e = &in->dgst;
	k = &in->k;

	if (is_all_zero(e, msg)) {
		WD_ERR("ecc sign in e all zero!\n");
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
	struct wd_ecc_verf_in *vin = (void *)msg->req.src;
	struct wd_dtb *e = NULL;
	struct wd_dtb *s = NULL;
	struct wd_dtb *r = NULL;
	int ret;

	if (!vin->dgst_set) {
		WD_ERR("prepare verf_in, hash not set!\n");
		return -WD_EINVAL;
	}

	e = &vin->dgst;
	s = &vin->s;
	r = &vin->r;

	if (is_all_zero(e, msg)) {
		WD_ERR("ecc verf in e all zero!\n");
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
	struct wd_sm2_enc_in *ein = (void *)msg->req.src;
	struct wd_dtb *k = &ein->k;
	int ret;

	if (ein->k_set) {
		ret = crypto_bin_to_hpre_bin(k->data, (const char *)k->data,
					     k->bsize, k->dsize, "sm2 enc k");
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
	struct wd_sm2_dec_in *din = (void *)msg->req.src;
	struct wd_ecc_point *c1 = &din->c1;
	int ret;

	ret = crypto_bin_to_hpre_bin(c1->x.data, (const char *)c1->x.data,
		c1->x.bsize, c1->x.dsize, "sm2 dec c1 x");
	if (ret)
		return ret;

	ret = crypto_bin_to_hpre_bin(c1->y.data, (const char *)c1->y.data,
		c1->y.bsize, c1->y.dsize, "sm2 dec c1 y");
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
	struct wd_ecc_in *in = msg->req.src;
	struct wd_ecc_point *pbk = NULL;
	int ret;

	wd_ecxdh_get_in_params(in, &pbk);
	if (!pbk) {
		WD_ERR("failed to get ecxdh in param!\n");
		return -WD_EINVAL;
	}

	ret = crypto_bin_to_hpre_bin(pbk->x.data, (const char *)pbk->x.data,
				     pbk->x.bsize, pbk->x.dsize, "ecdh compute x");
	if (ret) {
		WD_ERR("ecc dh compute in x format fail!\n");
		return ret;
	}

	ret = crypto_bin_to_hpre_bin(pbk->y.data, (const char *)pbk->y.data,
				     pbk->y.bsize, pbk->y.dsize, "ecdh compute y");
	if (ret) {
		WD_ERR("ecc dh compute in y format fail!\n");
		return ret;
	}

	*data = pbk->x.data;

	return 0;
}

static int ecc_prepare_in(struct wd_ecc_msg *msg,
			     struct hisi_hpre_sqe *hw_msg, void **data)
{
	int ret = -WD_EINVAL;

	switch (msg->req.op_type) {
	case WD_SM2_KG: /*fall through */
	case WD_ECXDH_GEN_KEY:
		ret = ecc_prepare_dh_gen_in(msg, hw_msg, data);
		break;
	case WD_ECXDH_COMPUTE_KEY:
		ret = ecc_prepare_dh_compute_in(msg, hw_msg, data);
		break;
	case WD_ECDSA_SIGN: /*fall through */
	case WD_SM2_SIGN:
		ret = ecc_prepare_sign_in(msg, hw_msg, data);
		break;
	case WD_ECDSA_VERIFY: /*fall through */
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

/* prepare in/out hw msg */
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
		WD_ERR("ecc_prepare_in fail!\n");
		return ret;
	}
	hw_msg->low_in = LW_U32((uintptr_t)data);
	hw_msg->hi_in = HI_U32((uintptr_t)data);

	ret = ecc_prepare_out(msg, &data);
	if (ret) {
		WD_ERR("ecc_prepare_out fail!\n");
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
		WD_ERR("failed to get hw keysize : ksz = %d.\n", ksz);

	return size;
}

static int ecc_send(handle_t ctx, struct wd_ecc_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg;
	__u16 send_cnt = 0;
	__u32 hw_sz;
	int ret;

	memset(&hw_msg, 0, sizeof(struct hisi_hpre_sqe));
	hw_sz = get_hw_keysz(msg->key_bytes);
	hw_msg.task_len1 = hw_sz / BYTE_BITS - 0x1;

	/* prepare alg */
	ret = ecc_prepare_alg(msg, &hw_msg);
	if (ret)
		return ret;

	/* prepare key */
	ret = ecc_prepare_key(msg, &hw_msg);
	if (ret)
		return ret;

	/* prepare in/out put */
	ret = ecc_prepare_iot(msg, &hw_msg);
	if (ret)
		return ret;

	hw_msg.done = 0x1;
	hw_msg.etype = 0x0;
	hw_msg.low_tag = msg->tag;

	return hisi_qm_send(h_qp, &hw_msg, 1, &send_cnt);
}

static int ecdh_out_transfer(struct wd_ecc_msg *msg, struct hisi_hpre_sqe *hw_msg)
{
	struct wd_ecc_out *out = (void *)msg->req.dst;
	struct wd_ecc_point *key = NULL;
	struct wd_dtb *y = NULL;
	int ret;

	wd_ecxdh_get_out_params(out, &key);

	if (hw_msg->alg == HPRE_ALG_ECDH_MULTIPLY)
		y = &key->y;

	ret = hpre_tri_bin_transfer(&key->x, y, NULL);
	if (ret) {
		WD_ERR("parse ecdh out format fail!\n");
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
		WD_ERR("fail to tri ecc sign out r&s!\n");

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
		WD_ERR("fail to tri sm2 kg out param!\n");

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
		WD_ERR("failed to get sm2 enc out param!\n");
		return -WD_EINVAL;
	}

	ret = hpre_tri_bin_transfer(&c1->x, &c1->y, NULL);
	if (ret)
		WD_ERR("fail to tri sm2 enc out param!\n");

	return ret;
}

static int ecc_out_transfer(struct wd_ecc_msg *msg,
			    struct hisi_hpre_sqe *hw_msg)
{
	int ret = -WD_EINVAL;

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
		WD_ERR("ecc out trans fail alg %u error!\n", hw_msg->alg);

	return ret;
}

static int ecc_recv(handle_t ctx, struct wd_ecc_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_hpre_sqe hw_msg = {0};
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &hw_msg, 1, &recv_cnt);
	if (ret < 0)
		return ret;

	if (hw_msg.done != HPRE_HW_TASK_DONE || hw_msg.etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "ecc",
			hw_msg.done, hw_msg.etype);
		if (hw_msg.done == HPRE_HW_TASK_INIT)
			msg->result = WD_EINVAL;
		else
			msg->result = WD_IN_EPARA;
	} else {
		msg->tag = LW_U16(hw_msg.low_tag);
		msg->result = WD_SUCCESS;
		ret = ecc_out_transfer(msg, &hw_msg);
		if (ret) {
			WD_ERR("ecc out transfer fail!\n");
			msg->result = WD_OUT_EPARA;
		}
	}

	return 0;
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
