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

#include "hisi_sec_udrv.h"

#define DES_KEY_SIZE 8
#define SEC_3DES_2KEY_SIZE (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE (3 * DES_KEY_SIZE)

#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32

#define SEC_HW_TASK_DONE  1
#define SQE_WORD_NUMS 32
#define XTS_MODE_KEY_DIVISOR 2
#define CTR_MODE_LEN_SHIFT 4
#define WORD_BYTES 4
#define U64_DATA_BYTES 8

static int g_digest_a_alg[WCRYPTO_MAX_DIGEST_TYPE] = {
	A_ALG_SM3, A_ALG_MD5, A_ALG_SHA1, A_ALG_SHA256, A_ALG_SHA224,
	A_ALG_SHA384, A_ALG_SHA512, A_ALG_SHA512_224, A_ALG_SHA512_256
};
static int g_hmac_a_alg[WCRYPTO_MAX_DIGEST_TYPE] = {
	A_ALG_HMAC_SM3, A_ALG_HMAC_MD5, A_ALG_HMAC_SHA1,
	A_ALG_HMAC_SHA256, A_ALG_HMAC_SHA224, A_ALG_HMAC_SHA384,
	A_ALG_HMAC_SHA512, A_ALG_HMAC_SHA512_224, A_ALG_HMAC_SHA512_256
};

#ifdef DEBUG_LOG
static void sec_dump_bd(unsigned int *bd, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		WD_ERR("Word[%d] 0x%x\n", i, bd[i]);
	WD_ERR("\n");
}
#endif

static int qm_fill_cipher_alg(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	int ret = WD_SUCCESS;
	__u16 len = 0;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->type2.c_alg = C_ALG_SM4;
		sqe->type2.c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
		len = msg->key_bytes;
		if (msg->mode == WCRYPTO_CIPHER_XTS)
			len = len / XTS_MODE_KEY_DIVISOR;
		if (len == AES_KEYSIZE_128)
			sqe->type2.c_key_len = CKEY_LEN_128_BIT;
		else if (len == AES_KEYSIZE_192)
			sqe->type2.c_key_len = CKEY_LEN_192_BIT;
		else if (len == AES_KEYSIZE_256)
			sqe->type2.c_key_len = CKEY_LEN_256_BIT;
		else {
			WD_ERR("Invalid AES key size!\n");
			ret = -WD_EINVAL;
		}
		break;
	case WCRYPTO_CIPHER_DES:
		sqe->type2.c_alg = C_ALG_DES;
		sqe->type2.c_key_len = CKEY_LEN_DES;
		break;
	case WCRYPTO_CIPHER_3DES:
		sqe->type2.c_alg = C_ALG_3DES;
		if (msg->key_bytes == SEC_3DES_2KEY_SIZE)
			sqe->type2.c_key_len = CKEY_LEN_3DES_2KEY;
		else if (msg->key_bytes == SEC_3DES_3KEY_SIZE)
			sqe->type2.c_key_len = CKEY_LEN_3DES_3KEY;
		else {
			WD_ERR("Invalid 3DES key size!\n");
			ret = -WD_EINVAL;
		}
		break;
	default:
		WD_ERR("Invalid cipher type!\n");
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int qm_fill_cipher_mode(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	int ret = WD_SUCCESS;

	if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION
		|| msg->mode == WCRYPTO_CIPHER_OFB)
		sqe->cipher = CIPHER_ENCRYPT;
	else if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION) {
		sqe->cipher = CIPHER_DECRYPT;
	} else {
		WD_ERR("Invalid cipher op type!\n");
		return -WD_EINVAL;
	}

	switch (msg->mode) {
	case WCRYPTO_CIPHER_ECB:
		sqe->type2.c_mode = C_MODE_ECB;
		break;
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
		sqe->type2.c_mode = C_MODE_CBC;
		break;
	case WCRYPTO_CIPHER_CTR:
		sqe->type2.c_mode = C_MODE_CTR;
		break;
	case WCRYPTO_CIPHER_XTS:
		sqe->type2.c_mode = C_MODE_XTS;
		break;
	default:
		WD_ERR("Invalid cipher alg type!\n");
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

/* increment counter (128-bit int) by c */
static void ctr_iv_inc(__u8 *counter, __u32 c)
{
	__u32 n = 16;

	do {
		--n;
		c += counter[n];
		counter[n] = (__u8)c;
		c >>= BYTE_BITS;
	} while (n);
}

static void update_iv(struct wcrypto_cipher_msg *msg)
{
	switch (msg->mode) {
	case WCRYPTO_CIPHER_CBC:
		if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION)
			memcpy(msg->iv, msg->out + msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes);
		else
			memcpy(msg->iv, msg->in + msg->in_bytes -
				msg->iv_bytes, msg->iv_bytes);
		break;
	case WCRYPTO_CIPHER_OFB:
		memcpy(msg->iv, msg->out + msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes);
		break;
	case WCRYPTO_CIPHER_CTR:
		ctr_iv_inc(msg->iv, msg->in_bytes >> CTR_MODE_LEN_SHIFT);
		break;
	default:
		break;
	}
}

static int fill_cipher_bd1_type(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION
		|| msg->mode == WCRYPTO_CIPHER_OFB)
		sqe->cipher = CIPHER_ENCRYPT;
	else if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION) {
		sqe->cipher = CIPHER_DECRYPT;
	} else {
		WD_ERR("Invalid cipher op type for bd1!\n");
		return -WD_EINVAL;
	}

	if (msg->data_fmt < WD_FLAT_BUF || msg->data_fmt > WD_SGL_BUF) {
		WD_ERR("Invalid data format for bd1!\n");
		return -WD_EINVAL;
	}

	sqe->src_addr_type = msg->data_fmt;
	sqe->dst_addr_type = msg->data_fmt;

	if (msg->mode == WCRYPTO_CIPHER_XTS)
		sqe->type1.ci_gen = CI_GEN_BY_LBA;
	else
		sqe->type1.ci_gen = CI_GEN_BY_ADDR;

	return WD_SUCCESS;
}

static int fill_cipher_bd1_alg(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	int ret = WD_SUCCESS;
	__u16 len = 0;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->type1.c_alg = C_ALG_SM4;
		sqe->type1.c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->type1.c_alg = C_ALG_AES;
		len = msg->key_bytes;
		if (msg->mode == WCRYPTO_CIPHER_XTS)
			len = len / XTS_MODE_KEY_DIVISOR;
		if (len == AES_KEYSIZE_128)
			sqe->type1.c_key_len = CKEY_LEN_128_BIT;
		else if (len == AES_KEYSIZE_192)
			sqe->type1.c_key_len = CKEY_LEN_192_BIT;
		else if (len == AES_KEYSIZE_256)
			sqe->type1.c_key_len = CKEY_LEN_256_BIT;
		else {
			WD_ERR("Invalid AES key size for bd1\n");
			ret = -WD_EINVAL;
		}
		break;
	case WCRYPTO_CIPHER_DES:
		sqe->type1.c_alg = C_ALG_DES;
		sqe->type1.c_key_len = CKEY_LEN_DES;
		break;
	case WCRYPTO_CIPHER_3DES:
		sqe->type1.c_alg = C_ALG_3DES;
		if (msg->key_bytes == SEC_3DES_2KEY_SIZE)
			sqe->type1.c_key_len = CKEY_LEN_3DES_2KEY;
		else if (msg->key_bytes == SEC_3DES_3KEY_SIZE)
			sqe->type1.c_key_len = CKEY_LEN_3DES_3KEY;
		else {
			WD_ERR("Invalid 3DES key size for bd1\n");
			ret = -WD_EINVAL;
		}
		break;
	default:
		WD_ERR("Invalid cipher type for bd1\n");
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int fill_cipher_bd1_mode(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	switch (msg->mode) {
	case WCRYPTO_CIPHER_ECB:
		sqe->type1.c_mode = C_MODE_ECB;
		break;
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
		sqe->type1.c_mode = C_MODE_CBC;
		break;
	case WCRYPTO_CIPHER_CTR:
		sqe->type1.c_mode = C_MODE_CTR;
		break;
	case WCRYPTO_CIPHER_XTS:
		sqe->type1.c_mode = C_MODE_XTS;
		break;
	default:
		WD_ERR("Invalid cipher alg type for bd1\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_cipher_bd1_udata(struct hisi_sec_sqe *sqe,
		struct wd_sec_udata *udata)
{
	sqe->type1.gran_num = udata->gran_num;
	sqe->type1.src_skip_data_len = udata->src_offset;
	sqe->type1.dst_skip_data_len = udata->dst_offset;
	sqe->type1.gen_ver_val = udata->dif.ver;
	sqe->type1.gen_app_val = udata->dif.app;
	sqe->type1.gen_page_pad_ctrl = udata->dif.ctrl.gen.page_layout_gen_type;
	sqe->type1.gen_grd_ctrl = udata->dif.ctrl.gen.grd_gen_type;
	sqe->type1.gen_ver_ctrl = udata->dif.ctrl.gen.ver_gen_type;
	sqe->type1.gen_app_ctrl = udata->dif.ctrl.gen.app_gen_type;
	sqe->type1.gen_ref_ctrl = udata->dif.ctrl.gen.ref_gen_type;
	sqe->type1.page_pad_type = udata->dif.ctrl.gen.page_layout_pad_type;

	sqe->type1.block_size = udata->block_size;
	sqe->type1.private_info = udata->dif.priv_info;
	sqe->type1.chk_grd_ctrl = udata->dif.ctrl.verify.grd_verify_type;
	sqe->type1.chk_ref_ctrl = udata->dif.ctrl.verify.ref_verify_type;
	sqe->type1.lba_l = udata->dif.lba & QM_L32BITS_MASK;
	sqe->type1.lba_h = udata->dif.lba >> QM_HADDR_SHIFT;

	return WD_SUCCESS;
}

static int fill_cipher_bd1_addr(struct wd_queue *q,
		struct wcrypto_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy;

	/*for storage scene, data address using physical address*/
	phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
	if (!phy) {
		WD_ERR("Get key dma address fail for bd1\n");
		return -WD_ENOMEM;
	}
	sqe->type1.c_key_addr_l = phy & QM_L32BITS_MASK;
	sqe->type1.c_key_addr_h = phy >> QM_HADDR_SHIFT;
	phy = (uintptr_t)msg->in;
	sqe->type1.data_src_addr_l = phy & QM_L32BITS_MASK;
	sqe->type1.data_src_addr_h = phy >> QM_HADDR_SHIFT;
	phy = (uintptr_t)msg->out;
	sqe->type1.data_dst_addr_l = phy & QM_L32BITS_MASK;
	sqe->type1.data_dst_addr_h = phy >> QM_HADDR_SHIFT;

	return WD_SUCCESS;
}

static int fill_cipher_bd1(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *msg, struct wcrypto_cipher_tag *tag)
{
	int ret = WD_SUCCESS;
	struct wd_sec_udata *udata = tag->priv;

	sqe->type = BD_TYPE1;
	sqe->scene = SCENE_STORAGE;
	sqe->de = DATA_DST_ADDR_ENABLE;

	ret = fill_cipher_bd1_type(msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	ret = fill_cipher_bd1_alg(msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	ret = fill_cipher_bd1_mode(msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	ret = fill_cipher_bd1_udata(sqe, udata);
	if (ret != WD_SUCCESS)
		return ret;

	ret = fill_cipher_bd1_addr(q, msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	sqe->type1.tag = tag->wcrypto_tag.ctx_id;

	return ret;
}

static int fill_cipher_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *msg, struct wcrypto_cipher_tag *tag)
{
	int ret = WD_SUCCESS;
	uintptr_t phy;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	sqe->de = DATA_DST_ADDR_ENABLE;
	sqe->type2.c_len = msg->in_bytes;

	ret = qm_fill_cipher_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("qm_fill_cipher_alg fail!\n");
		return ret;
	}

	ret = qm_fill_cipher_mode(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("qm_fill_cipher_mode fail!\n");
		return ret;
	}

	if (msg->mode == WCRYPTO_CIPHER_OFB) {
		if (msg->in == msg->out) {
			WD_ERR("Not support for src override for OFB\n");
			return -WD_EINVAL;
		}
		memset(msg->out, 0, msg->out_bytes);
		phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	} else
		phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("Get msg out dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_dst_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_dst_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
	if (!phy) {
		WD_ERR("Get key dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.c_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.c_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->iv, msg->iv_bytes);
	if (!phy) {
		WD_ERR("Get iv dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.c_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.c_ivin_addr_h = HI_U32(phy);

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

	return ret;
}

int qm_fill_cipher_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_sec_sqe *sqe;
	struct wcrypto_cipher_msg *msg = message;
	struct wd_queue *q = info->q;
	struct wcrypto_cipher_tag *tag = (void *)(uintptr_t)msg->usr_data;
	uintptr_t temp;
	int ret;

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	if (tag && tag->priv)
		ret = fill_cipher_bd1(q, sqe, msg, tag);
	else
		ret = fill_cipher_bd2(q, sqe, msg, tag);

	if (ret != WD_SUCCESS)
		return ret;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned int *)sqe, SQE_WORD_NUMS);
#endif

	return ret;
}

static int qm_fill_digest_alg(struct wcrypto_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	if (msg->alg < WCRYPTO_SM3 || msg->alg >= WCRYPTO_MAX_DIGEST_TYPE) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	sqe->type2.mac_len = msg->out_bytes / WORD_BYTES;
	if (msg->mode == WCRYPTO_DIGEST_NORMAL)
		sqe->type2.a_alg = g_digest_a_alg[msg->alg];
	else if (msg->mode == WCRYPTO_DIGEST_HMAC)
		sqe->type2.a_alg = g_hmac_a_alg[msg->alg];
	else {
		WD_ERR("Invalid digest mode!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void qm_fill_digest_long_bd(struct wcrypto_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	__u64 total_bits = 0;
	struct wcrypto_digest_tag *digest_tag = (void *)(uintptr_t)msg->usr_data;

	if (msg->has_next && (msg->iv_bytes == 0)) {
		/*LOGN BD FIRST*/
		sqe->type2.ai_gen = AI_GEN_INNER;
		sqe->type2.a_pad = AUTHPAD_NOPAD;
		msg->iv_bytes = msg->out_bytes;
	} else if (msg->has_next && (msg->iv_bytes != 0)) {
		/*LONG BD MIDDLE*/
		sqe->type2.ai_gen = AI_GEN_IVIN_ADDR;
		sqe->type2.a_pad = AUTHPAD_NOPAD;
		sqe->type2.a_ivin_addr_h = sqe->type2.mac_addr_h;
		sqe->type2.a_ivin_addr_l = sqe->type2.mac_addr_l;
		msg->iv_bytes = msg->out_bytes;
	} else if (!msg->has_next && (msg->iv_bytes != 0)) {
		/*LOGN BD END*/
		sqe->type2.ai_gen = AI_GEN_IVIN_ADDR;
		sqe->type2.a_pad = AUTHPAD_PAD;
		sqe->type2.a_ivin_addr_h = sqe->type2.mac_addr_h;
		sqe->type2.a_ivin_addr_l = sqe->type2.mac_addr_l;
		total_bits = digest_tag->long_data_len * BYTE_BITS;
		sqe->type2.long_a_data_len_l = total_bits & QM_L32BITS_MASK;
		sqe->type2.long_a_data_len_h = HI_U32(total_bits);
		msg->iv_bytes = 0;
	} else {
		/*SHORT BD*/
		msg->iv_bytes = 0;
	}
}

int qm_fill_digest_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_sec_sqe *sqe;
	struct wcrypto_digest_msg *msg = message;
	struct wd_queue *q = info->q;
	struct wcrypto_digest_tag *tag = (void *)(uintptr_t)msg->usr_data;
	int ret;
	uintptr_t temp;
	uintptr_t phy;

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->type2.a_len = msg->in_bytes;

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy);

	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("Get msg out dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.mac_addr_h = HI_U32(phy);

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		sqe->type2.a_key_len = msg->key_bytes / WORD_BYTES;
		phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
		if (!phy) {
			WD_ERR("Get hmac key dma address fail!\n");
			return -WD_ENOMEM;
		}
		sqe->type2.a_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
		sqe->type2.a_key_addr_h = HI_U32(phy);
	}

	ret = qm_fill_digest_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("qm_fill_digest_alg fail!\n");
		return ret;
	}
	qm_fill_digest_long_bd(msg, sqe);

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned int *)sqe, SQE_WORD_NUMS);
#endif

	return WD_SUCCESS;
}

static void parse_cipher_bd1(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *cipher_msg)
{
	__u64 dma_addr;

	if (sqe->type1.done != SEC_HW_TASK_DONE	|| sqe->type1.error_type) {
		WD_ERR("SEC BD1 %s fail!done=0x%x, etype=0x%x\n", "cipher",
		sqe->type1.done, sqe->type1.error_type);
		cipher_msg->result = WD_IN_EPARA;
	} else
		cipher_msg->result = WD_SUCCESS;

	dma_addr = DMA_ADDR(sqe->type2.c_key_addr_h,
			sqe->type2.c_key_addr_l);
	drv_iova_unmap(q, cipher_msg->key, (void *)(uintptr_t)dma_addr,
			cipher_msg->key_bytes);
}

static void parse_cipher_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *cipher_msg)
{
	__u64 dma_addr;
	__u32 index = 0;

	if (sqe->type2.done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD2 %s fail!done=0x%x, etype=0x%x\n", "cipher",
		sqe->type2.done, sqe->type2.error_type);
		cipher_msg->result = WD_IN_EPARA;
	} else
		cipher_msg->result = WD_SUCCESS;

	dma_addr = DMA_ADDR(sqe->type2.data_src_addr_h,
			sqe->type2.data_src_addr_l);
	drv_iova_unmap(q, cipher_msg->in, (void *)(uintptr_t)dma_addr,
			cipher_msg->in_bytes);
	dma_addr = DMA_ADDR(sqe->type2.data_dst_addr_h,
			sqe->type2.data_dst_addr_l);
	drv_iova_unmap(q, cipher_msg->out, (void *)(uintptr_t)dma_addr,
			cipher_msg->out_bytes);
	dma_addr = DMA_ADDR(sqe->type2.c_key_addr_h,
			sqe->type2.c_key_addr_l);
	drv_iova_unmap(q, cipher_msg->key, (void *)(uintptr_t)dma_addr,
			cipher_msg->key_bytes);
	dma_addr = DMA_ADDR(sqe->type2.c_ivin_addr_h,
			sqe->type2.c_ivin_addr_l);
	drv_iova_unmap(q, cipher_msg->iv, (void *)(uintptr_t)dma_addr,
			cipher_msg->iv_bytes);

	update_iv(cipher_msg);

	if (cipher_msg->mode == WCRYPTO_CIPHER_OFB) {
		__u64 *in_data = (__u64 *)cipher_msg->in;
		__u64 *out_data = (__u64 *)cipher_msg->out;
		__u32 max_index = cipher_msg->out_bytes / U64_DATA_BYTES;

		for (index = 0; index < max_index; index++)
			out_data[index] = in_data[index] ^ out_data[index];

		for (index = index * U64_DATA_BYTES;
			index < cipher_msg->out_bytes; index++) {
			cipher_msg->out[index] = cipher_msg->in[index]
						^ cipher_msg->out[index];
		}
	}
}

int qm_parse_cipher_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_cipher_msg *cipher_msg = info->req_cache[i];
	struct hisi_sec_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (sqe->type == BD_TYPE2) {
		if (usr && sqe->type2.tag != usr)
			return 0;
		parse_cipher_bd2(q, sqe, cipher_msg);
	} else if (sqe->type == BD_TYPE1) {
		if (usr && sqe->type1.tag != usr)
			return 0;
		parse_cipher_bd1(q, sqe, cipher_msg);
	} else {
		WD_ERR("SEC BD Type error\n");
		cipher_msg->result = WD_IN_EPARA;
	}

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned int *)sqe, SQE_WORD_NUMS);
#endif

	return 1;
}
int qm_parse_digest_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_digest_msg *digest_msg = info->req_cache[i];
	struct hisi_sec_sqe *sqe = msg;
	struct wd_queue *q = info->q;
	__u64 dma_addr;

	/* if this hw msg not belong to me, then try again */
	if (usr && sqe->type2.tag != usr)
		return 0;

	if (sqe->type == BD_TYPE2) {
		if (sqe->type2.done != SEC_HW_TASK_DONE
			|| sqe->type2.error_type) {
			WD_ERR("SEC %s fail!done=0x%x, etype=0x%x\n", "digest",
			sqe->type2.done, sqe->type2.error_type);
			digest_msg->result = WD_IN_EPARA;
#ifdef DEBUG_LOG
			sec_dump_bd((unsigned int *)sqe, SQE_WORD_NUMS);
#endif
		} else
			digest_msg->result = WD_SUCCESS;

		dma_addr = DMA_ADDR(sqe->type2.data_src_addr_h,
				sqe->type2.data_src_addr_l);
		drv_iova_unmap(q, digest_msg->in, (void *)(uintptr_t)dma_addr,
				digest_msg->in_bytes);
		dma_addr = DMA_ADDR(sqe->type2.mac_addr_h,
				sqe->type2.mac_addr_l);
		drv_iova_unmap(q, digest_msg->out, (void *)(uintptr_t)dma_addr,
				digest_msg->out_bytes);
		if (digest_msg->mode == WCRYPTO_DIGEST_HMAC) {
			dma_addr = DMA_ADDR(sqe->type2.a_key_addr_h,
				sqe->type2.a_key_addr_h);
			drv_iova_unmap(q, digest_msg->key,
				(void *)(uintptr_t)dma_addr, digest_msg->key_bytes);
		}
	}

	return 1;
}
