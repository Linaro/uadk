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

#define SEC_HW_TASK_DONE  1
#define SQE_BYTES_NUMS 32
#define CTR_MODE_LEN_SHIFT 4
#define WORD_BYTES 4
#define U64_DATA_BYTES 8
#define CTR_128BIT_COUNTER	16
#define DIF_VERIFY_FAIL 2
#define WCRYPTO_CIPHER_THEN_DIGEST	0
#define WCRYPTO_DIGEST_THEN_CIPHER	1

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
static void sec_dump_bd(unsigned char *bd, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		WD_ERR("\\%02x", bd[i]);
		if ((i + 1) % WORD_BYTES == 0)
			WD_ERR("\n");
	}
	WD_ERR("\n");
}
#endif

static int get_aes_c_key_len(struct wcrypto_cipher_msg *msg, __u8 *c_key_len)
{
	__u16 len;

	len = msg->key_bytes;
	if (msg->mode == WCRYPTO_CIPHER_XTS)
		len = len / XTS_MODE_KEY_DIVISOR;

	if (len == AES_KEYSIZE_128)
		*c_key_len = CKEY_LEN_128_BIT;
	else if (len == AES_KEYSIZE_192)
		*c_key_len = CKEY_LEN_192_BIT;
	else if (len == AES_KEYSIZE_256)
		*c_key_len = CKEY_LEN_256_BIT;
	else {
		WD_ERR("Invalid AES key size!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int get_3des_c_key_len(struct wcrypto_cipher_msg *msg, __u8 *c_key_len)
{
	if (msg->key_bytes == SEC_3DES_2KEY_SIZE)
		*c_key_len = CKEY_LEN_3DES_2KEY;
	else if (msg->key_bytes == SEC_3DES_3KEY_SIZE)
		*c_key_len = CKEY_LEN_3DES_3KEY;
	else {
		WD_ERR("Invalid 3DES key size!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_cipher_bd2_alg(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	int ret = WD_SUCCESS;
	__u8 c_key_len = 0;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->type2.c_alg = C_ALG_SM4;
		sqe->type2.c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->type2.c_key_len = c_key_len;
		break;
	case WCRYPTO_CIPHER_DES:
		sqe->type2.c_alg = C_ALG_DES;
		sqe->type2.c_key_len = CKEY_LEN_DES;
		break;
	case WCRYPTO_CIPHER_3DES:
		sqe->type2.c_alg = C_ALG_3DES;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->type2.c_key_len = c_key_len;
		break;
	default:
		WD_ERR("Invalid cipher type!\n");
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int fill_cipher_bd2_mode(struct wcrypto_cipher_msg *msg,
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
	__u32 n = CTR_128BIT_COUNTER;

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
	case WCRYPTO_CIPHER_CFB:
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
	__u8 c_key_len = 0;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->type1.c_alg = C_ALG_SM4;
		sqe->type1.c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->type1.c_alg = C_ALG_AES;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->type2.c_key_len = c_key_len;
		break;
	case WCRYPTO_CIPHER_DES:
		sqe->type1.c_alg = C_ALG_DES;
		sqe->type1.c_key_len = CKEY_LEN_DES;
		break;
	case WCRYPTO_CIPHER_3DES:
		sqe->type1.c_alg = C_ALG_3DES;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->type2.c_key_len = c_key_len;
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

	if (msg->iv) {
		phy = (uintptr_t)drv_iova_map(q, msg->iv, msg->iv_bytes);
		if (!phy) {
			WD_ERR("Get IV dma address fail for bd1\n");
			return -WD_ENOMEM;
		}
		sqe->type1.c_ivin_addr_l = phy & QM_L32BITS_MASK;
		sqe->type1.c_ivin_addr_h = phy >> QM_HADDR_SHIFT;
	}

	return WD_SUCCESS;
}

static int fill_cipher_bd1(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *msg, struct wcrypto_cipher_tag *tag)
{
	int ret;
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

static int fill_cipher_bd2_addr(struct wd_queue *q,
		struct wcrypto_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy;

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

	return WD_SUCCESS;
}

static int fill_cipher_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *msg, struct wcrypto_cipher_tag *tag)
{
	int ret;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	sqe->de = DATA_DST_ADDR_ENABLE;
	sqe->type2.c_len = msg->in_bytes;

	ret = fill_cipher_bd2_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_cipher_bd2_alg fail!\n");
		return ret;
	}

	ret = fill_cipher_bd2_mode(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_cipher_bd2_mode fail!\n");
		return ret;
	}

	ret = fill_cipher_bd2_addr(q, msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

	return ret;
}

static int fill_cipher_bd3_alg(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_bd3_sqe *sqe)
{
	int ret = WD_SUCCESS;
	__u8 c_key_len = 0;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->c_alg = C_ALG_SM4;
		sqe->c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->c_alg = C_ALG_AES;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->c_key_len = c_key_len;
		break;
	case WCRYPTO_CIPHER_DES:
		sqe->c_alg = C_ALG_DES;
		sqe->c_key_len = CKEY_LEN_DES;
		break;
	case WCRYPTO_CIPHER_3DES:
		sqe->c_alg = C_ALG_3DES;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->c_key_len = c_key_len;
		break;
	default:
		WD_ERR("Invalid cipher type.\n");
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int fill_cipher_bd3_area(struct wd_queue *q,
		struct wcrypto_cipher_msg *msg, struct hisi_sec_bd3_sqe *sqe)
{
	uintptr_t phy;

	if (msg->mode == WCRYPTO_CIPHER_OFB) {
		if (msg->in == msg->out) {
			WD_ERR("Not support for src override for OFB.\n");
			return -WD_EINVAL;
		}
		memset(msg->out, 0, msg->out_bytes);
		phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	} else
		phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("Fail to get msg in dma address.\n");
		return -WD_ENOMEM;
	}
	sqe->data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_src_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("Fail to get msg out dma address.\n");
		return -WD_ENOMEM;
	}
	sqe->data_dst_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_dst_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
	if (!phy) {
		WD_ERR("Fail to get key dma address.\n");
		return -WD_ENOMEM;
	}
	sqe->c_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->c_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->iv, msg->iv_bytes);
	if (!phy) {
		WD_ERR("Fail to get iv dma address\n");
		return -WD_ENOMEM;
	}
	sqe->ipsec_scene.c_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->ipsec_scene.c_ivin_addr_h = HI_U32(phy);

	return WD_SUCCESS;
}

static int fill_cipher_bd3_mode(struct wcrypto_cipher_msg *msg,
		struct hisi_sec_bd3_sqe *sqe)
{
	int ret = WD_SUCCESS;

	if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION)
		sqe->cipher = CIPHER_ENCRYPT;
	else if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION) {
		sqe->cipher = CIPHER_DECRYPT;
	} else {
		WD_ERR("Invalid cipher op type!\n");
		return -WD_EINVAL;
	}

	switch (msg->mode) {
	case WCRYPTO_CIPHER_ECB:
		sqe->c_mode = C_MODE_ECB;
		break;
	case WCRYPTO_CIPHER_CBC:
		sqe->c_mode = C_MODE_CBC;
		break;
	case WCRYPTO_CIPHER_OFB:
		sqe->c_mode = C_MODE_OFB;
		break;
	case WCRYPTO_CIPHER_CTR:
		sqe->c_mode = C_MODE_CTR;
		break;
	case WCRYPTO_CIPHER_XTS:
		sqe->c_mode = C_MODE_XTS;
		break;
	case WCRYPTO_CIPHER_CFB:
		sqe->c_mode = C_MODE_CFB;
		break;
	default:
		WD_ERR("Invalid cipher alg type!\n");
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int fill_cipher_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_cipher_msg *msg, struct wcrypto_cipher_tag *tag)
{
	int ret;

	sqe->type = BD_TYPE3;
	sqe->scene = SCENE_IPSEC;

	sqe->de = DATA_DST_ADDR_ENABLE;
	if (msg->in_bytes > MAX_CIPHER_LENGTH) {
		WD_ERR("input data is too large.\n");
		return -WD_EINVAL;
	}
	sqe->c_len = msg->in_bytes;

	ret = fill_cipher_bd3_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to fill_cipher_bd3_alg.\n");
		return ret;
	}

	ret = fill_cipher_bd3_mode(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to fill_cipher_bd3_mode.\n");
		return ret;
	}

	ret = fill_cipher_bd3_area(q, msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to fill_cipher_bd3_addr.\n");
		return ret;
	}

	if (tag)
		sqe->tag_l= tag->wcrypto_tag.ctx_id;

	return ret;
}

static int sm4_mode_check(int mode)
{
	switch (mode) {
	case WCRYPTO_CIPHER_ECB:
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
	case WCRYPTO_CIPHER_CFB:
	case WCRYPTO_CIPHER_CTR:
	case WCRYPTO_CIPHER_XTS:
	case WCRYPTO_CIPHER_CCM:
	case WCRYPTO_CIPHER_GCM:
		return WD_SUCCESS;
	default:
		return -WD_EINVAL;
	}
}

static int aes_mode_check(int mode)
{
	switch (mode) {
	case WCRYPTO_CIPHER_ECB:
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
	case WCRYPTO_CIPHER_CFB:
	case WCRYPTO_CIPHER_CTR:
	case WCRYPTO_CIPHER_XTS:
	case WCRYPTO_CIPHER_CCM:
	case WCRYPTO_CIPHER_GCM:
		return WD_SUCCESS;
	default:
		return -WD_EINVAL;
	}
}

static int des_mode_check(int mode)
{
	switch (mode) {
	case WCRYPTO_CIPHER_ECB:
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
		return WD_SUCCESS;
	default:
		return -WD_EINVAL;
	}
}

static int triple_des_mode_check(int mode)
{
	switch (mode) {
	case WCRYPTO_CIPHER_ECB:
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
		return WD_SUCCESS;
	default:
		return -WD_EINVAL;
	}
}

static int cipher_para_check(struct wcrypto_cipher_msg *msg)
{
	int ret = WD_SUCCESS;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		ret = sm4_mode_check(msg->mode);
		break;
	case WCRYPTO_CIPHER_AES:
		ret = aes_mode_check(msg->mode);
		break;
	case WCRYPTO_CIPHER_DES:
		ret = des_mode_check(msg->mode);
		break;
	case WCRYPTO_CIPHER_3DES:
		ret = triple_des_mode_check(msg->mode);
		break;
	default:
		return -WD_EINVAL;
	}

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

	ret = cipher_para_check(msg);
	if (ret) {
		WD_ERR("Invalid cipher alg = %d and mode = %d combination\n",
			msg->alg, msg->mode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_sqe));

	if (tag && tag->priv)
		ret = fill_cipher_bd1(q, sqe, msg, tag);
	else
		ret = fill_cipher_bd2(q, sqe, msg, tag);

	if (ret != WD_SUCCESS)
		return ret;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return ret;
}

int qm_fill_cipher_bd3_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_sec_bd3_sqe *sqe;
	struct wcrypto_cipher_msg *msg = message;
	struct wd_queue *q = info->q;
	struct wcrypto_cipher_tag *tag = (void *)(uintptr_t)msg->usr_data;
	uintptr_t temp;
	int ret;

	ret = cipher_para_check(msg);
	if (ret) {
		WD_ERR("Invalid cipher alg = %d and mode = %d combination\n",
			msg->alg, msg->mode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_bd3_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_bd3_sqe));

	if (tag)
		ret = fill_cipher_bd3(q, sqe, msg, tag);

	if (ret != WD_SUCCESS)
		return ret;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return ret;
}

static int fill_digest_bd2_alg(struct wcrypto_digest_msg *msg,
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

static int fill_digest_bd1_alg(struct wcrypto_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	if (msg->alg < WCRYPTO_SM3 || msg->alg >= WCRYPTO_MAX_DIGEST_TYPE) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	sqe->type1.mac_len = msg->out_bytes / WORD_BYTES;
	if (msg->mode == WCRYPTO_DIGEST_NORMAL)
		sqe->type1.a_alg = g_digest_a_alg[msg->alg];
	else if (msg->mode == WCRYPTO_DIGEST_HMAC)
		sqe->type1.a_alg = g_hmac_a_alg[msg->alg];
	else {
		WD_ERR("Invalid digest mode for BD1\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_digest_bd1_addr(struct wd_queue *q,
		struct wcrypto_digest_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy;

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		sqe->type1.a_key_len = msg->key_bytes / WORD_BYTES;
		phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
		if (!phy) {
			WD_ERR("Get hmac key dma address fail for bd1\n");
			return -WD_ENOMEM;
		}
		sqe->type1.a_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
		sqe->type1.a_key_addr_h = HI_U32(phy);
	}

	/*for storage scene, data address using physical address*/
	phy = (uintptr_t)msg->in;
	sqe->type1.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type1.data_src_addr_h = HI_U32(phy);

	phy = (uintptr_t)msg->out;
	sqe->type1.mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type1.mac_addr_h = HI_U32(phy);

	return WD_SUCCESS;
}

static int fill_digest_bd1_udata(struct hisi_sec_sqe *sqe,
		struct wd_sec_udata *udata)
{
	sqe->type1.gran_num = udata->gran_num;
	sqe->type1.src_skip_data_len = udata->src_offset;
	sqe->type1.block_size = udata->block_size;
	sqe->type1.private_info = udata->dif.priv_info;
	sqe->type1.chk_grd_ctrl = udata->dif.ctrl.verify.grd_verify_type;
	sqe->type1.chk_ref_ctrl = udata->dif.ctrl.verify.ref_verify_type;
	sqe->type1.lba_l = udata->dif.lba & QM_L32BITS_MASK;
	sqe->type1.lba_h = udata->dif.lba >> QM_HADDR_SHIFT;

	return WD_SUCCESS;
}

static int fill_digest_bd1(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_digest_msg *msg, struct wcrypto_digest_tag *tag)
{
	struct wd_sec_udata *udata = tag->priv;
	int ret = WD_SUCCESS;

	sqe->type = BD_TYPE1;
	sqe->scene = SCENE_STORAGE;
	sqe->auth = AUTH_MAC_CALCULATE;

	/* Input data using input data fmt, MAC output using pBuffer */
	sqe->src_addr_type = msg->data_fmt;
	sqe->mac_addr_type = WD_FLAT_BUF;

	ret = fill_digest_bd1_alg(msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	ret = fill_digest_bd1_udata(sqe, udata);
	if (ret != WD_SUCCESS)
		return ret;

	ret = fill_digest_bd1_addr(q, msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	sqe->type1.tag = tag->wcrypto_tag.ctx_id;

	return ret;
}

static int fill_digest_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_digest_msg *msg, struct wcrypto_digest_tag *tag)
{
	uintptr_t phy;
	int ret;

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

	ret = fill_digest_bd2_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_digest_bd2_alg fail!\n");
		return ret;
	}
	qm_fill_digest_long_bd(msg, sqe);

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

	return ret;
}

/*
 * According to wcrypto_digest_poll(), the return number mean:
 * 0: parse failed
 * 1: parse a BD successfully
 */
int qm_fill_digest_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_sec_sqe *sqe;
	struct wcrypto_digest_msg *msg = message;
	struct wd_queue *q = info->q;
	struct wcrypto_digest_tag *tag = (void *)(uintptr_t)msg->usr_data;
	int ret;
	uintptr_t temp;

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_sqe));

	if (tag && tag->priv)
		ret = fill_digest_bd1(q, sqe, msg, tag);
	else
		ret = fill_digest_bd2(q, sqe, msg, tag);

	if (ret != WD_SUCCESS)
		return ret;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return WD_SUCCESS;
}

static void qm_fill_digest_long_bd3(struct wcrypto_digest_msg *msg,
		struct hisi_sec_bd3_sqe *sqe)
{
	struct wcrypto_digest_tag *digest_tag = (void *)(uintptr_t)msg->usr_data;
	__u64 total_bits = 0;

	/* iv_bytes is multiplexed as a flag bit to determine whether it is LOGN BD FIRST */
	if (msg->has_next && msg->iv_bytes == 0) {
		/* LOGN BD FIRST */
		sqe->ai_gen = AI_GEN_INNER;
		sqe->stream_scene.auth_pad = AUTHPAD_NOPAD;
		msg->iv_bytes = msg->out_bytes;
	} else if (msg->has_next && msg->iv_bytes != 0) {
		/* LONG BD MIDDLE */
		sqe->ai_gen = AI_GEN_IVIN_ADDR;
		sqe->stream_scene.auth_pad = AUTHPAD_NOPAD;
		sqe->auth_ivin.a_ivin_addr_h = sqe->mac_addr_h;
		sqe->auth_ivin.a_ivin_addr_l = sqe->mac_addr_l;
		msg->iv_bytes = msg->out_bytes;
	} else if (!msg->has_next && msg->iv_bytes != 0) {
		/* LOGN BD END */
		sqe->ai_gen = AI_GEN_IVIN_ADDR;
		sqe->stream_scene.auth_pad = AUTHPAD_PAD;
		sqe->auth_ivin.a_ivin_addr_h = sqe->mac_addr_h;
		sqe->auth_ivin.a_ivin_addr_l = sqe->mac_addr_l;
		total_bits = digest_tag->long_data_len * BYTE_BITS;
		sqe->stream_scene.long_a_data_len_l = total_bits & QM_L32BITS_MASK;
		sqe->stream_scene.long_a_data_len_h = HI_U32(total_bits);
		msg->iv_bytes = 0;
	} else {
		/* SHORT BD */
		msg->iv_bytes = 0;
	}
}

static int fill_digest_bd3_alg(struct wcrypto_digest_msg *msg,
		struct hisi_sec_bd3_sqe *sqe)
{
	if (msg->alg < WCRYPTO_SM3 || msg->alg >= WCRYPTO_MAX_DIGEST_TYPE) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	sqe->mac_len = msg->out_bytes / WORD_BYTES;
	if (msg->mode == WCRYPTO_DIGEST_NORMAL)
		sqe->a_alg = g_digest_a_alg[msg->alg];
	else if (msg->mode == WCRYPTO_DIGEST_HMAC)
		sqe->a_alg = g_hmac_a_alg[msg->alg];
	else {
		WD_ERR("Invalid digest mode!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_digest_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_digest_msg *msg, struct wcrypto_digest_tag *tag)
{
	uintptr_t phy;
	int ret;

	sqe->type = BD_TYPE3;
	sqe->scene = SCENE_STREAM;

	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->a_len = msg->in_bytes;

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_src_addr_h = HI_U32(phy);

	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("Get msg out dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->mac_addr_h = HI_U32(phy);

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		sqe->a_key_len = msg->key_bytes / WORD_BYTES;
		phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
		if (!phy) {
			WD_ERR("Get hmac key dma address fail!\n");
			return -WD_ENOMEM;
		}
		sqe->a_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
		sqe->a_key_addr_h = HI_U32(phy);
	}

	ret = fill_digest_bd3_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_digest_bd3_alg fail!\n");
		return ret;
	}
	qm_fill_digest_long_bd3(msg, sqe);

	if (tag)
		sqe->tag_l = tag->wcrypto_tag.ctx_id;

	return ret;
}

int qm_fill_digest_bd3_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_digest_msg *msg = message;
	struct wcrypto_digest_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct hisi_sec_bd3_sqe *sqe;
	struct wd_queue *q = info->q;
	uintptr_t temp;
	int ret;

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_bd3_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_bd3_sqe));

	if (tag) {
		ret = fill_digest_bd3(q, sqe, msg, tag);
		if (ret != WD_SUCCESS)
			return ret;
	}

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned int *)sqe, SQE_BYTES_NUMS);
#endif

	return WD_SUCCESS;
}

static void parse_cipher_bd1(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *cipher_msg)
{
	__u64 dma_addr;

	if (sqe->type1.done != SEC_HW_TASK_DONE || sqe->type1.error_type) {
		WD_ERR("SEC BD1 %s fail!done=0x%x, etype=0x%x\n", "cipher",
		sqe->type1.done, sqe->type1.error_type);
		cipher_msg->result = WD_IN_EPARA;
	} else {
		if (sqe->type1.dif_check == DIF_VERIFY_FAIL)
			cipher_msg->result = WD_VERIFY_ERR;
		else
			cipher_msg->result = WD_SUCCESS;
	}

	dma_addr = DMA_ADDR(sqe->type1.c_key_addr_h,
			sqe->type1.c_key_addr_l);
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

static void parse_cipher_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_cipher_msg *cipher_msg)
{
	__u64 dma_addr;
	__u32 index = 0;

	if (sqe->done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("Fail to parse SEC BD3 %s, done=0x%x, etype=0x%x\n", "cipher",
		sqe->done, sqe->error_type);
		cipher_msg->result = WD_IN_EPARA;
	} else {
		cipher_msg->result = WD_SUCCESS;
	}

	dma_addr = DMA_ADDR(sqe->data_src_addr_h,
			sqe->data_src_addr_l);
	drv_iova_unmap(q, cipher_msg->in, (void *)(uintptr_t)dma_addr,
			cipher_msg->in_bytes);
	dma_addr = DMA_ADDR(sqe->data_dst_addr_h,
			sqe->data_dst_addr_l);
	drv_iova_unmap(q, cipher_msg->out, (void *)(uintptr_t)dma_addr,
			cipher_msg->out_bytes);
	dma_addr = DMA_ADDR(sqe->c_key_addr_h,
			sqe->c_key_addr_l);
	drv_iova_unmap(q, cipher_msg->key, (void *)(uintptr_t)dma_addr,
			cipher_msg->key_bytes);
	dma_addr = DMA_ADDR(sqe->ipsec_scene.c_ivin_addr_h,
			sqe->ipsec_scene.c_ivin_addr_l);
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

/*
 * According to wcrypto_cipher_poll(), the return number mean:
 * 0: parse failed
 * 1: parse a BD successfully
 */
int qm_parse_cipher_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_cipher_msg *cipher_msg = info->req_cache[i];
	struct hisi_sec_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (unlikely(!cipher_msg)) {
		WD_ERR("info->req_cache is null at index:%d\n", i);
		return 0;
	}

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
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return 1;
}

int qm_parse_cipher_bd3_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_cipher_msg *cipher_msg = info->req_cache[i];
	struct hisi_sec_bd3_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (unlikely(!cipher_msg)) {
		WD_ERR("info->req_cache is null at index:%d\n", i);
		return 0;
	}

	if (likely(sqe->type == BD_TYPE3)) {
		if (unlikely(usr && sqe->tag_l != usr))
			return 0;
		parse_cipher_bd3(q, sqe, cipher_msg);
	} else {
		WD_ERR("SEC BD Type error\n");
		cipher_msg->result = WD_IN_EPARA;
	}

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return 1;
}

static void parse_digest_bd1(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_digest_msg *digest_msg)
{
	__u64 dma_addr;

	if (sqe->type1.done != SEC_HW_TASK_DONE
		|| sqe->type1.error_type) {
		WD_ERR("SEC BD1 %s fail!done=0x%x, etype=0x%x\n", "digest",
		sqe->type1.done, sqe->type1.error_type);
		digest_msg->result = WD_IN_EPARA;
	} else {
		if (sqe->type1.dif_check == DIF_VERIFY_FAIL)
			digest_msg->result = WD_VERIFY_ERR;
		else
			digest_msg->result = WD_SUCCESS;
	}

	if (digest_msg->mode == WCRYPTO_DIGEST_HMAC) {
		dma_addr = DMA_ADDR(sqe->type1.a_key_addr_h,
			sqe->type1.a_key_addr_h);
		drv_iova_unmap(q, digest_msg->key,
			(void *)(uintptr_t)dma_addr, digest_msg->key_bytes);
	}
}

static void parse_digest_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_digest_msg *digest_msg)
{
	__u64 dma_addr;

	if (sqe->type2.done != SEC_HW_TASK_DONE
		|| sqe->type2.error_type) {
		WD_ERR("SEC BD2 %s fail!done=0x%x, etype=0x%x\n", "digest",
		sqe->type2.done, sqe->type2.error_type);
		digest_msg->result = WD_IN_EPARA;
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

int qm_parse_digest_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_digest_msg *digest_msg = info->req_cache[i];
	struct hisi_sec_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (unlikely(!digest_msg)) {
		WD_ERR("info->req_cache is null at index:%d\n", i);
		return 0;
	}

	if (sqe->type == BD_TYPE2) {
		if (usr && sqe->type2.tag != usr)
			return 0;
		parse_digest_bd2(q, sqe, digest_msg);
	} else if (sqe->type == BD_TYPE1) {
		if (usr && sqe->type1.tag != usr)
			return 0;
		parse_digest_bd1(q, sqe, digest_msg);
	} else {
		WD_ERR("SEC Digest BD Type error\n");
		digest_msg->result = WD_IN_EPARA;
	}

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return 1;
}

static int fill_aead_bd3_alg(struct wcrypto_aead_msg *msg,
		struct hisi_sec_bd3_sqe *sqe)
{
	int ret = WD_SUCCESS;
	__u8 c_key_len = 0;

	switch (msg->calg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->c_alg = C_ALG_SM4;
		sqe->c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->c_alg = C_ALG_AES;
		if (msg->ckey_bytes == AES_KEYSIZE_128)
			c_key_len = CKEY_LEN_128_BIT;
		else if (msg->ckey_bytes == AES_KEYSIZE_192)
			c_key_len = CKEY_LEN_192_BIT;
		else if (msg->ckey_bytes == AES_KEYSIZE_256) {
			c_key_len = CKEY_LEN_256_BIT;
		} else {
			WD_ERR("Invalid AES key size!\n");
			return -WD_EINVAL;
		}
		sqe->c_key_len = c_key_len;
		break;
	default:
		WD_ERR("Invalid cipher type!\n");
		ret = -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WCRYPTO_CIPHER_CCM ||
		msg->cmode == WCRYPTO_CIPHER_GCM)
		return ret;

	sqe->mac_len = msg->auth_bytes / SEC_SQE_LEN_RATE;
	sqe->a_key_len = msg->akey_bytes / SEC_SQE_LEN_RATE;

	switch (msg->dalg) {
	case WCRYPTO_SHA1:
		sqe->a_alg = A_ALG_HMAC_SHA1;
		break;
	case WCRYPTO_SHA256:
		sqe->a_alg = A_ALG_HMAC_SHA256;
		break;
	case WCRYPTO_SHA512:
		sqe->a_alg = A_ALG_HMAC_SHA512;
		break;
	default:
		WD_ERR("Invalid digest type!\n");
		ret = -WD_EINVAL;
	}

	return ret;
}

static int fill_aead_bd3_mode(struct wcrypto_aead_msg *msg,
		struct hisi_sec_bd3_sqe *sqe)
{
	int ret = WD_SUCCESS;

	if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION_DIGEST) {
		sqe->cipher = CIPHER_ENCRYPT;
		sqe->seq = WCRYPTO_CIPHER_THEN_DIGEST;
	} else if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION_DIGEST) {
		sqe->cipher = CIPHER_DECRYPT;
		sqe->seq = WCRYPTO_DIGEST_THEN_CIPHER;
	} else {
		WD_ERR("Invalid cipher op type!\n");
		return -WD_EINVAL;
	}

	switch (msg->cmode) {
	case WCRYPTO_CIPHER_ECB:
		sqe->c_mode = C_MODE_ECB;
		break;
	case WCRYPTO_CIPHER_CBC:
		sqe->c_mode = C_MODE_CBC;
		break;
	case WCRYPTO_CIPHER_CTR:
		sqe->c_mode = C_MODE_CTR;
		break;
	case WCRYPTO_CIPHER_CCM:
		sqe->c_mode = C_MODE_CCM;
		sqe->auth = NO_AUTH;
		sqe->a_len = msg->assoc_bytes;
		sqe->c_icv_len = msg->auth_bytes;
		break;
	case WCRYPTO_CIPHER_GCM:
		sqe->c_mode = C_MODE_GCM;
		sqe->auth = NO_AUTH;
		sqe->a_len = msg->assoc_bytes;
		sqe->c_icv_len = msg->auth_bytes;
		break;
	default:
		WD_ERR("Invalid cipher cmode type!\n");
		ret = -WD_EINVAL;
	}

	return ret;
}

static int set_aead_auth_iv(struct wd_queue *q,
		struct wcrypto_aead_msg *msg, struct hisi_sec_bd3_sqe *sqe)
{
#define IV_LAST_BYTE1		1
#define IV_LAST_BYTE2		2
#define IV_CTR_INIT		1
#define IV_CM_CAL_NUM		2
#define IV_CL_MASK		0x7
#define IV_FLAGS_OFFSET	0x6
#define IV_CM_OFFSET		0x3
#define IV_LAST_BYTE2_MASK	0xFF00
#define IV_LAST_BYTE1_MASK	0xFF

	__u8 flags = 0x00;
	uintptr_t phy;
	__u8 cl, cm;

	/* CCM need to cal a_iv, GCM same as c_iv */
	memcpy(msg->aiv, msg->iv, msg->iv_bytes);
	if (msg->cmode == WCRYPTO_CIPHER_CCM) {
		msg->iv[msg->iv_bytes - IV_LAST_BYTE2] = 0x00;
		msg->iv[msg->iv_bytes - IV_LAST_BYTE1] = IV_CTR_INIT;

		/* the last 3bit is L' */
		cl = msg->iv[0] & IV_CL_MASK;
		flags |= cl;

		/* the M' is bit3~bit5, the Flags is bit6 */
		cm = (msg->auth_bytes - IV_CM_CAL_NUM) / IV_CM_CAL_NUM;
		flags |= cm << IV_CM_OFFSET;
		if (msg->assoc_bytes > 0)
			flags |= 0x01 << IV_FLAGS_OFFSET;

		msg->aiv[0] = flags;
		/*
		  * the last 32bit is counter's initial number,
		  * but the nonce uses the first 16bit
		  * the tail 16bit fill with the cipher length
		  */
		msg->aiv[msg->iv_bytes - IV_LAST_BYTE2] =
			msg->in_bytes & IV_LAST_BYTE2_MASK;
		msg->aiv[msg->iv_bytes - IV_LAST_BYTE1] =
			msg->in_bytes & IV_LAST_BYTE1_MASK;
	}

	phy = (uintptr_t)drv_iova_map(q, msg->aiv, msg->iv_bytes);
	if (!phy) {
		WD_ERR("fail to get auth iv dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->auth_ivin.a_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->auth_ivin.a_ivin_addr_h = HI_U32(phy);

	return WD_SUCCESS;
}

static int fill_aead_bd3_addr(struct wd_queue *q,
		struct wcrypto_aead_msg *msg, struct hisi_sec_bd3_sqe *sqe)
{
	uintptr_t phy;

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("fail to get msg in dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_src_addr_h = HI_U32(phy);

	/* AEAD input MAC addr use in addr */
	if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION_DIGEST) {
		phy = phy + msg->assoc_bytes + msg->in_bytes;
		sqe->mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
		sqe->mac_addr_h = HI_U32(phy);
	}

	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("fail to get msg out dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->data_dst_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_dst_addr_h = HI_U32(phy);

	/* AEAD output MAC addr use out addr */
	if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION_DIGEST) {
		phy = phy + msg->out_bytes - msg->auth_bytes;
		sqe->mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
		sqe->mac_addr_h = HI_U32(phy);
	}

	phy = (uintptr_t)drv_iova_map(q, msg->ckey, msg->ckey_bytes);
	if (!phy) {
		WD_ERR("fail to get key dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->c_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->c_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->akey, msg->akey_bytes);
	if (!phy) {
		WD_ERR("fail to get auth key dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->a_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->a_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->iv, msg->iv_bytes);
	if (!phy) {
		WD_ERR("fail to get iv dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->ipsec_scene.c_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->ipsec_scene.c_ivin_addr_h = HI_U32(phy);

	/* CCM/GCM should init a_iv */
	return set_aead_auth_iv(q, msg, sqe);
}

static int fill_aead_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_aead_msg *msg, struct wcrypto_aead_tag *tag)
{
	int ret;

	sqe->type = BD_TYPE3;
	sqe->scene = SCENE_IPSEC;
	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->de = DATA_DST_ADDR_ENABLE;
	if (msg->in_bytes > MAX_CIPHER_LENGTH) {
		WD_ERR("fail to check input data length\n");
		return -WD_EINVAL;
	}
	sqe->c_len = msg->in_bytes;
	sqe->cipher_src_offset = msg->assoc_bytes;
	sqe->a_len = msg->in_bytes + msg->assoc_bytes;

	ret = fill_aead_bd3_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to fill_aead_bd3_alg!\n");
		return ret;
	}

	ret = fill_aead_bd3_mode(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to fill_aead_bd3_mode!\n");
		return ret;
	}

	ret = fill_aead_bd3_addr(q, msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to fill_aead_bd3_addr!\n");
		return ret;
	}

	if (tag)
		sqe->tag_l = tag->wcrypto_tag.ctx_id;

	return ret;
}

static int aead_para_check(struct wcrypto_aead_msg *msg)
{
	int ret = WD_SUCCESS;

	switch (msg->calg) {
	case WCRYPTO_CIPHER_SM4:
		ret = sm4_mode_check(msg->cmode);
		break;
	case WCRYPTO_CIPHER_AES:
		ret = aes_mode_check(msg->cmode);
		break;
	default:
		return -WD_EINVAL;
	}

	return ret;
}

int qm_fill_aead_bd3_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_aead_msg *msg = message;
	struct wcrypto_aead_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	struct hisi_sec_bd3_sqe *sqe;
	uintptr_t temp;
	int ret;

	ret = aead_para_check(msg);
	if (ret) {
		WD_ERR("Invalid aead cipher alg = %d and mode = %d combination\n",
			msg->calg, msg->cmode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_bd3_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_bd3_sqe));

	if (tag)
		ret = fill_aead_bd3(q, sqe, msg, tag);

	if (ret != WD_SUCCESS)
		return ret;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return ret;
}

static void parse_aead_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_aead_msg *msg)
{
	__u64 dma_addr;

	if (sqe->done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("SEC BD3 %s fail!done=0x%x, etype=0x%x\n", "aead",
		sqe->done, sqe->error_type);
		msg->result = WD_IN_EPARA;
	} else
		msg->result = WD_SUCCESS;

	dma_addr = DMA_ADDR(sqe->data_src_addr_h,
			sqe->data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)dma_addr,
			msg->in_bytes);
	dma_addr = DMA_ADDR(sqe->data_dst_addr_h,
			sqe->data_dst_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)dma_addr,
			msg->out_bytes);
	dma_addr = DMA_ADDR(sqe->c_key_addr_h,
			sqe->c_key_addr_l);
	drv_iova_unmap(q, msg->ckey, (void *)(uintptr_t)dma_addr,
			msg->ckey_bytes);
	dma_addr = DMA_ADDR(sqe->a_key_addr_h,
			sqe->a_key_addr_l);
	drv_iova_unmap(q, msg->akey, (void *)(uintptr_t)dma_addr,
			msg->akey_bytes);
	dma_addr = DMA_ADDR(sqe->ipsec_scene.c_ivin_addr_h,
			sqe->ipsec_scene.c_ivin_addr_l);
	drv_iova_unmap(q, msg->iv, (void *)(uintptr_t)dma_addr,
			msg->iv_bytes);
	dma_addr = DMA_ADDR(sqe->auth_ivin.a_ivin_addr_h,
			sqe->auth_ivin.a_ivin_addr_l);
	drv_iova_unmap(q, msg->aiv, (void *)(uintptr_t)dma_addr,
			msg->iv_bytes);
}

/*
 * According to wcrypto_aead_poll(), the return number mean:
 * 0: parse failed
 * 1: parse a BD successfully
 */
int qm_parse_aead_bd3_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_aead_msg *aead_msg = info->req_cache[i];
	struct hisi_sec_bd3_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (unlikely(!aead_msg)) {
		WD_ERR("info->req_cache is null at index:%d\n", i);
		return 0;
	}

	if (sqe->type == BD_TYPE3) {
		if (usr && sqe->tag_l != usr)
			return 0;
		parse_aead_bd3(q, sqe, aead_msg);
	} else {
		WD_ERR("SEC BD Type error\n");
		aead_msg->result = WD_IN_EPARA;
	}

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return 1;
}

static void parse_digest_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_digest_msg *digest_msg)
{
	__u64 dma_addr;

	if (sqe->done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("SEC BD3 %s fail!done=0x%x, etype=0x%x\n", "digest",
		sqe->done, sqe->error_type);
		digest_msg->result = WD_IN_EPARA;
	} else {
		digest_msg->result = WD_SUCCESS;
	}

	dma_addr = DMA_ADDR(sqe->data_src_addr_h,
			sqe->data_src_addr_l);
	drv_iova_unmap(q, digest_msg->in, (void *)(uintptr_t)dma_addr,
			digest_msg->in_bytes);
	dma_addr = DMA_ADDR(sqe->mac_addr_h,
			sqe->mac_addr_l);
	drv_iova_unmap(q, digest_msg->out, (void *)(uintptr_t)dma_addr,
			digest_msg->out_bytes);
	if (digest_msg->mode == WCRYPTO_DIGEST_HMAC) {
		dma_addr = DMA_ADDR(sqe->a_key_addr_h,
			sqe->a_key_addr_h);
		drv_iova_unmap(q, digest_msg->key,
			(void *)(uintptr_t)dma_addr, digest_msg->key_bytes);
	}
}

int qm_parse_digest_bd3_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_digest_msg *digest_msg = info->req_cache[i];
	struct hisi_sec_bd3_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (unlikely(!digest_msg)) {
		WD_ERR("info->req_cache is null at index:%d\n", i);
		return 0;
	}

	if (sqe->type == BD_TYPE3) {
		if (usr && sqe->tag_l != usr)
			return 0;
		parse_digest_bd3(q, sqe, digest_msg);
	} else {
		WD_ERR("SEC Digest BD Type error\n");
		digest_msg->result = WD_IN_EPARA;
	}

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned int *)sqe, SQE_BYTES_NUMS);
#endif

	return 1;
}
