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

#define SEC_HW_TASK_DONE	1
#define SQE_BYTES_NUMS		128
#define CTR_MODE_LEN_SHIFT	4
#define WORD_BYTES		4
#define WORD_ALIGNMENT_MASK	0x3
#define U64_DATA_BYTES		8
#define U64_DATA_SHIFT		3
#define CTR_128BIT_COUNTER	16
#define DIF_VERIFY_FAIL		2
#define AES_BLOCK_SIZE		16
#define WCRYPTO_CIPHER_THEN_DIGEST	0
#define WCRYPTO_DIGEST_THEN_CIPHER	1
#define CBC_3DES_BLOCK_SIZE	8
#define CBC_AES_BLOCK_SIZE	16

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

static void update_iv_from_res(__u8 *dst, __u8 *src, size_t offset, __u16 bytes,
			       __u8 data_fmt)
{
	__u8 *dst1;
	int ret;

	if (data_fmt == WD_SGL_BUF) {
		dst1 = wd_get_first_sge_buf((struct wd_sgl *)dst);
		if (unlikely(!dst1))
			return;
		ret = wd_sgl_cp_to_pbuf((struct wd_sgl *)src, offset, dst1, bytes);
		if (unlikely(ret))
			return;
	} else {
		memcpy(dst, src + offset, bytes);
	}
}

static void update_iv(struct wcrypto_cipher_msg *msg)
{
	switch (msg->mode) {
	case WCRYPTO_CIPHER_CBC:
		if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION &&
			msg->out_bytes >= msg->iv_bytes)
			update_iv_from_res(msg->iv, msg->out,
					   msg->out_bytes - msg->iv_bytes,
					   msg->iv_bytes, msg->data_fmt);
		if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION &&
			msg->in_bytes >= msg->iv_bytes)
			update_iv_from_res(msg->iv, msg->in,
					   msg->in_bytes - msg->iv_bytes,
					   msg->iv_bytes, msg->data_fmt);
		break;
	case WCRYPTO_CIPHER_OFB:
	case WCRYPTO_CIPHER_CFB:
		if (msg->out_bytes >= msg->iv_bytes)
			update_iv_from_res(msg->iv, msg->out,
					   msg->out_bytes - msg->iv_bytes,
					   msg->iv_bytes, msg->data_fmt);
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

	if (msg->data_fmt > WD_SGL_BUF) {
		WD_ERR("Invalid data format for bd1!\n");
		return -WD_EINVAL;
	}

	if (msg->data_fmt == WD_SGL_BUF) {
		sqe->src_addr_type = HISI_SGL_BUF;
		sqe->dst_addr_type = HISI_SGL_BUF;
	} else {
		sqe->src_addr_type = HISI_FLAT_BUF;
		sqe->dst_addr_type = HISI_FLAT_BUF;
	}

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

static int map_addr(struct wd_queue *q, __u8 *key, __u16 len,
			 __u32 *addr_l, __u32 *addr_h, __u8 data_fmt)
{
	uintptr_t phy;
	void *p;

	/* 'msg->key' and 'msg->iv' use pBuffer, so when 'data_fmt' is sgl,
	 * we use its first buffer as pBuffer, and 'buf_sz > key_sz' is needed.
	 */
	if (data_fmt == WD_SGL_BUF) {
		if (unlikely(!key))
			return -WD_ENOMEM;
		p = drv_get_sgl_pri((struct wd_sgl *)key);
		phy = ((struct hisi_sgl *)p)->sge_entries[0].buf;
	} else {
		phy = (uintptr_t)drv_iova_map(q, key, len);
	}
	if (unlikely(!phy)) {
		WD_ERR("Get key dma address fail!\n");
		return -WD_ENOMEM;
	}

	*addr_l = (__u32)(phy & QM_L32BITS_MASK);
	*addr_h = HI_U32(phy);

	return WD_SUCCESS;
}

static void unmap_addr(struct wd_queue *q, __u8 *key, __u16 len,
		__u32 addr_l, __u32 addr_h, __u8 data_fmt)
{
	uintptr_t phy;

	if (data_fmt == WD_FLAT_BUF) {
		phy = DMA_ADDR(addr_h, addr_l);
		drv_iova_unmap(q, key, (void *)(uintptr_t)phy, len);
	}
}

static int fill_cipher_bd1_addr(struct wd_queue *q,
		struct wcrypto_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy;
	int ret;

	ret = map_addr(q, msg->key, msg->key_bytes, &sqe->type1.c_key_addr_l,
			    &sqe->type1.c_key_addr_h, msg->data_fmt);
	if (unlikely(ret)) {
		WD_ERR("Get key dma address fail for bd1\n");
		return ret;
	}

	phy = (uintptr_t)msg->in;
	sqe->type1.data_src_addr_l = phy & QM_L32BITS_MASK;
	sqe->type1.data_src_addr_h = phy >> QM_HADDR_SHIFT;
	phy = (uintptr_t)msg->out;
	sqe->type1.data_dst_addr_l = phy & QM_L32BITS_MASK;
	sqe->type1.data_dst_addr_h = phy >> QM_HADDR_SHIFT;

	if (msg->iv) {
		ret = map_addr(q, msg->iv, msg->iv_bytes,
				    &sqe->type1.c_ivin_addr_l,
				    &sqe->type1.c_ivin_addr_h,
				    msg->data_fmt);
		if (unlikely(ret)) {
			WD_ERR("Get IV dma address fail for bd1\n");
			goto map_key_error;
		}
	}

	return WD_SUCCESS;

map_key_error:
	unmap_addr(q, msg->key, msg->key_bytes, sqe->type1.c_key_addr_l,
		   sqe->type1.c_key_addr_h, msg->data_fmt);
	return -WD_ENOMEM;
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
	int ret = -WD_ENOMEM;
	uintptr_t phy;

	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Get msg out dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_dst_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_dst_addr_h = HI_U32(phy);

	if (msg->mode == WCRYPTO_CIPHER_OFB) {
		if (msg->in == msg->out) {
			WD_ERR("Not support for src override for OFB\n");
			ret = -WD_EINVAL;
			goto map_in_error;
		}
		/* While using OFB mode of cipher, out memory should be clear */
		if (msg->data_fmt == WD_SGL_BUF)
			wd_sgl_memset((struct wd_sgl *)msg->out, 0);
		else
			memset(msg->out, 0, msg->out_bytes);
	} else {
		phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
		if (unlikely(!phy)) {
			WD_ERR("Get msg in dma address fail!\n");
			goto map_in_error;
		}
	}
	sqe->type2.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy);

	ret = map_addr(q, msg->key, msg->key_bytes, &sqe->type2.c_key_addr_l,
			    &sqe->type2.c_key_addr_h, msg->data_fmt);
	if (unlikely(ret)) {
		WD_ERR("Get key dma address fail!\n");
		goto map_key_error;
	}

	if (msg->iv_bytes == 0)
		return WD_SUCCESS;
	ret = map_addr(q, msg->iv, msg->iv_bytes, &sqe->type2.c_ivin_addr_l,
			    &sqe->type2.c_ivin_addr_h, msg->data_fmt);
	if (unlikely(ret)) {
		WD_ERR("Get iv dma address fail!\n");
		goto map_iv_error;
	}

	return WD_SUCCESS;

map_iv_error:
	unmap_addr(q, msg->key, msg->key_bytes, sqe->type2.c_key_addr_l,
		   sqe->type2.c_key_addr_h, msg->data_fmt);
map_key_error:
	if (msg->mode != WCRYPTO_CIPHER_OFB) {
		phy = DMA_ADDR(sqe->type2.data_src_addr_h,
				sqe->type2.data_src_addr_l);
		drv_iova_unmap(q, msg->in, (void *)(uintptr_t)phy,
				msg->in_bytes);
	}
map_in_error:
	phy = DMA_ADDR(sqe->type2.data_dst_addr_h,
			sqe->type2.data_dst_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)phy,
			msg->out_bytes);
	return ret;
}

static int cipher_param_check(struct wcrypto_cipher_msg *msg)
{
	if (unlikely(msg->in_bytes > MAX_CIPHER_LENGTH)) {
		WD_ERR("input cipher len is too large!\n");
		return -WD_EINVAL;
	}

	if (msg->mode == WCRYPTO_CIPHER_OFB || msg->mode == WCRYPTO_CIPHER_CFB)
		return WD_SUCCESS;

	if (msg->alg == WCRYPTO_CIPHER_3DES ||
			msg->alg == WCRYPTO_CIPHER_DES) {
		if (unlikely(msg->in_bytes & (CBC_3DES_BLOCK_SIZE - 1))) {
			WD_ERR("input 3DES or DES cipher parameter is error!\n");
			return -WD_EINVAL;
		}
	}

	if (msg->alg == WCRYPTO_CIPHER_AES ||
			msg->alg == WCRYPTO_CIPHER_SM4) {
		if (unlikely(msg->in_bytes & (CBC_AES_BLOCK_SIZE - 1))) {
			WD_ERR("input AES or SM4 cipher parameter is error!\n");
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int fill_cipher_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *msg, struct wcrypto_cipher_tag *tag)
{
	int ret;

	ret = cipher_param_check(msg);
	if (unlikely(ret))
		return ret;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	sqe->de = DATA_DST_ADDR_ENABLE;

	sqe->type2.c_len = msg->in_bytes;

	if (msg->data_fmt == WD_SGL_BUF) {
		sqe->src_addr_type = HISI_SGL_BUF;
		sqe->dst_addr_type = HISI_SGL_BUF;
	} else {
		sqe->src_addr_type = HISI_FLAT_BUF;
		sqe->dst_addr_type = HISI_FLAT_BUF;
	}

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

	ret = cipher_param_check(msg);
	if (unlikely(ret))
		return ret;

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

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Fail to get msg in dma address.\n");
		return -WD_ENOMEM;
	}
	sqe->data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_src_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Fail to get msg out dma address.\n");
		goto map_out_error;
	}
	sqe->data_dst_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_dst_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Fail to get key dma address.\n");
		goto map_key_error;
	}
	sqe->c_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->c_key_addr_h = HI_U32(phy);
	if (msg->iv_bytes == 0)
		return WD_SUCCESS;
	phy = (uintptr_t)drv_iova_map(q, msg->iv, msg->iv_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Fail to get iv dma address\n");
		goto map_iv_error;
	}
	sqe->ipsec_scene.c_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->ipsec_scene.c_ivin_addr_h = HI_U32(phy);

	return WD_SUCCESS;

map_iv_error:
	phy = DMA_ADDR(sqe->c_key_addr_h, sqe->c_key_addr_l);
	drv_iova_unmap(q, msg->key, (void *)(uintptr_t)phy,
			msg->key_bytes);
map_key_error:
	phy = DMA_ADDR(sqe->data_dst_addr_h, sqe->data_dst_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)phy,
			msg->out_bytes);
map_out_error:
	phy = DMA_ADDR(sqe->data_src_addr_h,
			sqe->data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)phy,
			msg->in_bytes);
	return -WD_ENOMEM;
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
		sqe->tag_l = tag->wcrypto_tag.ctx_id;

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

static int cipher_comb_param_check(struct wcrypto_cipher_msg *msg)
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

	ret = cipher_comb_param_check(msg);
	if (ret) {
		WD_ERR("Invalid cipher alg = %hhu and mode = %hhu combination\n",
			msg->alg, msg->mode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_sqe));

	if (tag->priv)
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

	ret = cipher_comb_param_check(msg);
	if (ret) {
		WD_ERR("Invalid cipher alg = %hhu and mode = %hhu combination\n",
			msg->alg, msg->mode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_bd3_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_bd3_sqe));

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
	if (unlikely(msg->alg >= WCRYPTO_MAX_DIGEST_TYPE)) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->in_bytes == 0 ||
	    msg->in_bytes > MAX_CIPHER_LENGTH)) {
		WD_ERR("Invalid digest in_bytes!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->out_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("Invalid digest out_bytes!\n");
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
	if (unlikely(msg->alg >= WCRYPTO_MAX_DIGEST_TYPE)) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->in_bytes == 0 ||
	    msg->in_bytes > MAX_CIPHER_LENGTH)) {
		WD_ERR("Invalid digest in_bytes!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->out_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("Invalid digest out_bytes!\n");
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
	int ret;

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		if (unlikely(msg->key_bytes & WORD_ALIGNMENT_MASK)) {
			WD_ERR("Invalid digest key_bytes!\n");
			return -WD_EINVAL;
		}
		sqe->type1.a_key_len = msg->key_bytes / WORD_BYTES;

		ret = map_addr(q, msg->key, msg->key_bytes,
				    &sqe->type1.a_key_addr_l,
				    &sqe->type1.a_key_addr_h, msg->data_fmt);
		if (unlikely(ret)) {
			WD_ERR("Get hmac key dma address fail for bd1\n");
			return -WD_ENOMEM;
		}
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

	/* 'src' and 'dst' data using input data fmt, MAC output using pBuffer */
	sqe->mac_addr_type = HISI_FLAT_BUF;

	if (msg->data_fmt == WD_SGL_BUF) {
		sqe->src_addr_type = HISI_SGL_BUF;
		sqe->dst_addr_type = HISI_SGL_BUF;
	} else {
		sqe->src_addr_type = HISI_FLAT_BUF;
		sqe->dst_addr_type = HISI_FLAT_BUF;
	}

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
	int ret = -WD_ENOMEM;
	uintptr_t phy;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->type2.a_len = msg->in_bytes;

	if (msg->data_fmt == WD_SGL_BUF) {
		sqe->src_addr_type = HISI_SGL_BUF;
		sqe->dst_addr_type = HISI_SGL_BUF;
	} else {
		sqe->src_addr_type = HISI_FLAT_BUF;
		sqe->dst_addr_type = HISI_FLAT_BUF;
	}

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy);

	ret = map_addr(q, msg->out, msg->out_bytes, &sqe->type2.mac_addr_l,
			    &sqe->type2.mac_addr_h, msg->data_fmt);
	if (unlikely(ret)) {
		WD_ERR("Get msg out dma address fail!\n");
		goto map_out_error;
	}

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		if (unlikely(msg->key_bytes & WORD_ALIGNMENT_MASK)) {
			WD_ERR("Invalid digest key_bytes!\n");
			ret = -WD_EINVAL;
			goto map_key_error;
		}
		sqe->type2.a_key_len = msg->key_bytes / WORD_BYTES;

		ret = map_addr(q, msg->key, msg->key_bytes,
				    &sqe->type2.a_key_addr_l,
				    &sqe->type2.a_key_addr_h, msg->data_fmt);
		if (unlikely(ret)) {
			WD_ERR("Get hmac key dma address fail!\n");
			goto map_key_error;
		}
	}

	ret = fill_digest_bd2_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_digest_bd2_alg fail!\n");
		goto map_alg_error;
	}
	qm_fill_digest_long_bd(msg, sqe);

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

	return ret;

map_alg_error:
	unmap_addr(q, msg->key, msg->key_bytes, sqe->type2.a_key_addr_l,
		  sqe->type2.a_key_addr_h, msg->data_fmt);
map_key_error:
	unmap_addr(q, msg->out, msg->out_bytes, sqe->type2.mac_addr_l,
		  sqe->type2.mac_addr_h, msg->data_fmt);
map_out_error:
	phy = DMA_ADDR(sqe->type2.data_src_addr_h,
			sqe->type2.data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)phy, msg->in_bytes);
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

	if (tag->priv)
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
	if (unlikely(msg->alg >= WCRYPTO_MAX_DIGEST_TYPE)) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->in_bytes == 0 ||
	    msg->in_bytes > MAX_CIPHER_LENGTH)) {
		WD_ERR("Invalid digest in_bytes!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->out_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("Invalid digest out_bytes!\n");
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
	int ret = -WD_ENOMEM;
	uintptr_t phy;

	sqe->type = BD_TYPE3;
	sqe->scene = SCENE_STREAM;

	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->a_len = msg->in_bytes;

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->data_src_addr_h = HI_U32(phy);

	phy = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (unlikely(!phy)) {
		WD_ERR("Get msg out dma address fail!\n");
		goto map_out_error;
	}
	sqe->mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->mac_addr_h = HI_U32(phy);

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		if (unlikely(msg->key_bytes & WORD_ALIGNMENT_MASK)) {
			WD_ERR("Invalid digest key_bytes!\n");
			ret = -WD_EINVAL;
			goto map_key_error;
		}
		sqe->a_key_len = msg->key_bytes / WORD_BYTES;
		phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
		if (unlikely(!phy)) {
			WD_ERR("Get hmac key dma address fail!\n");
			goto map_key_error;
		}
		sqe->a_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
		sqe->a_key_addr_h = HI_U32(phy);
	}

	ret = fill_digest_bd3_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_digest_bd3_alg fail!\n");
		goto map_alg_error;
	}
	qm_fill_digest_long_bd3(msg, sqe);

	if (tag)
		sqe->tag_l = tag->wcrypto_tag.ctx_id;

	return ret;

map_alg_error:
	phy = DMA_ADDR(sqe->a_key_addr_h, sqe->a_key_addr_l);
	drv_iova_unmap(q, msg->key, (void *)(uintptr_t)phy, msg->key_bytes);
map_key_error:
	phy = DMA_ADDR(sqe->mac_addr_h, sqe->mac_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)phy, msg->out_bytes);
map_out_error:
	phy = DMA_ADDR(sqe->data_src_addr_h, sqe->data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)phy, msg->in_bytes);
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

	ret = fill_digest_bd3(q, sqe, msg, tag);
	if (ret != WD_SUCCESS)
		return ret;

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

static void cipher_ofb_data_handle(struct wcrypto_cipher_msg *msg)
{
	__u64 *in_data, *out_data;
	__u32 bufsz = 0;
	__u8 *in, *out;
	__u32 i, j;
	int ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = wd_get_sgl_bufsize((struct wd_sgl *)msg->out, &bufsz);
		if (unlikely(ret))
			return;

		/* When SGL pool creating, 'bufsz' is at least 4096, and align_sz
		 * is at least 8, so 'bufsz' is an integer multiple of 8.
		 */
		for (i = 1; i < msg->out_bytes / bufsz + 1; i++) {
			in_data = wd_get_sge_buf((struct wd_sgl *)msg->in, i);
			out_data = wd_get_sge_buf((struct wd_sgl *)msg->out, i);
			for (j = 0; j < (bufsz >> U64_DATA_SHIFT) + 1; j++)
				out_data[j] = in_data[j] ^ out_data[j];
		}

		in = wd_get_sge_buf((struct wd_sgl *)msg->in, i);
		out = wd_get_sge_buf((struct wd_sgl *)msg->out, i);
		for (j = 0; j < msg->out_bytes - bufsz * (i - 1); j++)
			out[j] = in[j] ^ out[j];
	} else {
		out_data = (__u64 *)msg->out;
		in_data = (__u64 *)msg->in;

		for (i = 0; i < msg->out_bytes >> U64_DATA_SHIFT; i++)
			out_data[i] = in_data[i] ^ out_data[i];
		for (i = i * U64_DATA_BYTES; i < msg->out_bytes; i++)
			msg->out[i] = msg->in[i] ^ msg->out[i];
	}
}

static void parse_cipher_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_cipher_msg *cipher_msg)
{
	__u64 dma_addr;

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
	if (cipher_msg->iv_bytes != 0)
		drv_iova_unmap(q, cipher_msg->iv, (void *)(uintptr_t)dma_addr,
			cipher_msg->iv_bytes);

	update_iv(cipher_msg);

	if (cipher_msg->mode == WCRYPTO_CIPHER_OFB)
		cipher_ofb_data_handle(cipher_msg);
}

static void parse_cipher_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_cipher_msg *cipher_msg)
{
	__u64 dma_addr;

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
	if (cipher_msg->iv_bytes != 0)
		drv_iova_unmap(q, cipher_msg->iv,
			(void *)(uintptr_t)dma_addr, cipher_msg->iv_bytes);

	update_iv(cipher_msg);
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
		WD_ERR("info->req_cache is null at index:%hu\n", i);
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
		WD_ERR("info->req_cache is null at index:%hu\n", i);
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
		WD_ERR("info->req_cache is null at index:%hu\n", i);
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
		return -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WCRYPTO_CIPHER_CCM ||
	    msg->cmode == WCRYPTO_CIPHER_GCM)
		return WD_SUCCESS;

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
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
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

#define IV_LAST_BYTE1		1
#define IV_LAST_BYTE2		2
#define IV_CTR_INIT		1
#define IV_CM_CAL_NUM		2
#define IV_CL_MASK		0x7
#define IV_FLAGS_OFFSET	0x6
#define IV_CM_OFFSET		0x3
#define IV_LAST_BYTE2_MASK	0xFF00
#define IV_LAST_BYTE1_MASK	0xFF

static void set_aead_auth_iv(struct wcrypto_aead_msg *msg)
{
	__u8 flags = 0x00;
	__u8 *iv, *aiv;
	__u8 cl, cm;

	if (msg->data_fmt == WD_SGL_BUF) {
		/* CCM need to cal a_iv, GCM same as c_iv */
		iv = wd_get_first_sge_buf((struct wd_sgl *)msg->iv);
		aiv = wd_get_first_sge_buf((struct wd_sgl *)msg->aiv);
	} else {
		iv = msg->iv;
		aiv = msg->aiv;
	}

	memcpy(aiv, iv, msg->iv_bytes);
	if (msg->cmode == WCRYPTO_CIPHER_CCM) {
		iv[msg->iv_bytes - IV_LAST_BYTE2] = 0x00;
		iv[msg->iv_bytes - IV_LAST_BYTE1] = IV_CTR_INIT;

		/* the last 3bit is L' */
		cl = iv[0] & IV_CL_MASK;
		flags |= cl;

		/* the M' is bit3~bit5, the Flags is bit6 */
		cm = (msg->auth_bytes - IV_CM_CAL_NUM) / IV_CM_CAL_NUM;
		flags |= cm << IV_CM_OFFSET;
		if (msg->assoc_bytes > 0)
			flags |= 0x01 << IV_FLAGS_OFFSET;

		aiv[0] = flags;
		/*
		 * the last 32bit is counter's initial number,
		 * but the nonce uses the first 16bit
		 * the tail 16bit fill with the cipher length
		 */
		aiv[msg->iv_bytes - IV_LAST_BYTE2] =
			msg->in_bytes & IV_LAST_BYTE2_MASK;
		aiv[msg->iv_bytes - IV_LAST_BYTE1] =
			msg->in_bytes & IV_LAST_BYTE1_MASK;
	}
}

static int fill_aead_bd3_addr(struct wd_queue *q,
		struct wcrypto_aead_msg *msg, struct hisi_sec_bd3_sqe *sqe)
{
	uintptr_t phy;

	phy = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (unlikely(!phy)) {
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
	if (unlikely(!phy)) {
		WD_ERR("fail to get msg out dma address!\n");
		goto map_out_error;
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
	if (unlikely(!phy)) {
		WD_ERR("fail to get key dma address!\n");
		goto map_ckey_error;
	}
	sqe->c_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->c_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->akey, msg->akey_bytes);
	if (unlikely(!phy)) {
		WD_ERR("fail to get auth key dma address!\n");
		goto map_akey_error;
	}
	sqe->a_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->a_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_iova_map(q, msg->iv, msg->iv_bytes);
	if (unlikely(!phy)) {
		WD_ERR("fail to get iv dma address!\n");
		goto map_civ_error;
	}
	sqe->ipsec_scene.c_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->ipsec_scene.c_ivin_addr_h = HI_U32(phy);

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);
	phy = (uintptr_t)drv_iova_map(q, msg->aiv, msg->iv_bytes);
	if (unlikely(!phy)) {
		WD_ERR("fail to get auth iv dma address!\n");
		goto map_aiv_error;
	}
	sqe->auth_ivin.a_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->auth_ivin.a_ivin_addr_h = HI_U32(phy);

	return WD_SUCCESS;

map_aiv_error:
	phy = DMA_ADDR(sqe->ipsec_scene.c_ivin_addr_h,
			sqe->ipsec_scene.c_ivin_addr_l);
	drv_iova_unmap(q, msg->iv, (void *)(uintptr_t)phy, msg->iv_bytes);
map_civ_error:
	phy = DMA_ADDR(sqe->a_key_addr_h, sqe->a_key_addr_l);
	drv_iova_unmap(q, msg->akey, (void *)(uintptr_t)phy, msg->akey_bytes);
map_akey_error:
	phy = DMA_ADDR(sqe->c_key_addr_h, sqe->c_key_addr_l);
	drv_iova_unmap(q, msg->ckey, (void *)(uintptr_t)phy, msg->ckey_bytes);
map_ckey_error:
	phy = DMA_ADDR(sqe->data_dst_addr_h, sqe->data_dst_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)phy, msg->out_bytes);
map_out_error:
	phy = DMA_ADDR(sqe->data_src_addr_h, sqe->data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)phy, msg->in_bytes);
	return -WD_ENOMEM;
}

static int fill_aead_bd3(struct wd_queue *q, struct hisi_sec_bd3_sqe *sqe,
		struct wcrypto_aead_msg *msg, struct wcrypto_aead_tag *tag)
{
	int ret;

	sqe->type = BD_TYPE3;
	sqe->scene = SCENE_IPSEC;
	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->de = DATA_DST_ADDR_ENABLE;
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

static int aead_comb_param_check(struct wcrypto_aead_msg *msg)
{
	int ret;

	if (unlikely(msg->in_bytes == 0 ||
	    msg->in_bytes > MAX_CIPHER_LENGTH)) {
		WD_ERR("fail to check input data length\n");
		return -WD_EINVAL;
	}

	if (msg->cmode == WCRYPTO_CIPHER_CCM) {
		if (unlikely(msg->auth_bytes < WORD_BYTES ||
		    msg->auth_bytes > AES_BLOCK_SIZE ||
		    msg->auth_bytes % (WORD_BYTES >> 1))) {
		    WD_ERR("Invalid aead ccm mode auth_bytes!\n");
		    return -WD_EINVAL;
		}
		return WD_SUCCESS;
	}
	if (msg->cmode == WCRYPTO_CIPHER_GCM) {
		if (unlikely(msg->auth_bytes < U64_DATA_BYTES ||
		    msg->auth_bytes > AES_BLOCK_SIZE)) {
		    WD_ERR("Invalid aead gcm mode auth_bytes!\n");
		    return -WD_EINVAL;
		}
		return WD_SUCCESS;
	}

	if (unlikely(msg->assoc_bytes & (AES_BLOCK_SIZE - 1))) {
		WD_ERR("Invalid aead assoc_bytes!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->auth_bytes != AES_BLOCK_SIZE &&
	    msg->auth_bytes != AES_BLOCK_SIZE << 1)) {
		WD_ERR("Invalid aead auth_bytes!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->akey_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("Invalid aead auth key bytes!\n");
		return -WD_EINVAL;
	}

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

	ret = aead_comb_param_check(msg);
	if (ret) {
		WD_ERR("Invalid aead cipher alg = %hhu and mode = %hhu combination\n",
			msg->calg, msg->cmode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_bd3_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_bd3_sqe));

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
		WD_ERR("SEC BD3 %s fail! done=0x%x, etype=0x%x\n", "aead",
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
		WD_ERR("info->req_cache is null at index:%hu\n", i);
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
		WD_ERR("info->req_cache is null at index:%hu\n", i);
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

static int fill_aead_bd2_alg(struct wcrypto_aead_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	__u8 c_key_len = 0;

	switch (msg->calg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->type2.c_alg = C_ALG_SM4;
		sqe->type2.c_key_len = CKEY_LEN_SM4;
		break;
	case WCRYPTO_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
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
		sqe->type2.c_key_len = c_key_len;
		break;
	default:
		WD_ERR("Invalid cipher type!\n");
		return -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WCRYPTO_CIPHER_CCM ||
	    msg->cmode == WCRYPTO_CIPHER_GCM)
		return WD_SUCCESS;

	sqe->type2.mac_len = msg->auth_bytes / SEC_SQE_LEN_RATE;
	sqe->type2.a_key_len = msg->akey_bytes / SEC_SQE_LEN_RATE;

	switch (msg->dalg) {
	case WCRYPTO_SHA1:
		sqe->type2.a_alg = A_ALG_HMAC_SHA1;
		break;
	case WCRYPTO_SHA256:
		sqe->type2.a_alg = A_ALG_HMAC_SHA256;
		break;
	case WCRYPTO_SHA512:
		sqe->type2.a_alg = A_ALG_HMAC_SHA512;
		break;
	default:
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_aead_bd2_mode(struct wcrypto_aead_msg *msg,
		struct hisi_sec_sqe *sqe)
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
		sqe->type2.c_mode = C_MODE_ECB;
		break;
	case WCRYPTO_CIPHER_CBC:
		sqe->type2.c_mode = C_MODE_CBC;
		break;
	case WCRYPTO_CIPHER_CCM:
		sqe->type2.c_mode = C_MODE_CCM;
		sqe->auth = NO_AUTH;
		sqe->type2.a_len = msg->assoc_bytes;
		sqe->type2.c_icv_len = msg->auth_bytes;
		break;
	case WCRYPTO_CIPHER_GCM:
		sqe->type2.c_mode = C_MODE_GCM;
		sqe->auth = NO_AUTH;
		sqe->type2.a_len = msg->assoc_bytes;
		sqe->type2.c_icv_len = msg->auth_bytes;
		break;
	default:
		WD_ERR("Invalid cipher cmode type!\n");
		ret = -WD_EINVAL;
	}

	return ret;
}

static int fill_aead_bd2_addr_src(struct wd_queue *q,
		struct wcrypto_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy1, phy2;
	void *p;

	phy1 = (uintptr_t)drv_iova_map(q, msg->in, msg->in_bytes);
	if (unlikely(!phy1)) {
		WD_ERR("fail to get msg in dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_src_addr_l = (__u32)(phy1 & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy1);

	/* AEAD input MAC addr use in addr */
	if (msg->op_type == WCRYPTO_CIPHER_DECRYPTION_DIGEST) {
		if (msg->data_fmt == WD_SGL_BUF) {
			/* if 'msg->in' uses sgl, we should get its 'buf' addr */
			p = drv_get_sgl_pri((struct wd_sgl *)msg->in);
			phy2 = ((struct hisi_sgl *)p)->sge_entries[0].buf;
			if (unlikely(!phy2)) {
				WD_ERR("fail to get sgl msg_in dma address!\n");
				drv_iova_unmap(q, msg->in,
					(void *)(uintptr_t)phy1, msg->in_bytes);
				return -WD_ENOMEM;
			}
			phy2 = phy2 + msg->assoc_bytes + msg->in_bytes;
		} else {
			phy2 = phy1 + msg->assoc_bytes + msg->in_bytes;
		}
		sqe->type2.mac_addr_l = (__u32)(phy2 & QM_L32BITS_MASK);
		sqe->type2.mac_addr_h = HI_U32(phy2);
	}

	return WD_SUCCESS;
}

static int fill_aead_bd2_addr_dst(struct wd_queue *q,
		struct wcrypto_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy1, phy2;
	void *p;

	phy1 = (uintptr_t)drv_iova_map(q, msg->out, msg->out_bytes);
	if (unlikely(!phy1)) {
		WD_ERR("fail to get msg out dma address!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_dst_addr_l = (__u32)(phy1 & QM_L32BITS_MASK);
	sqe->type2.data_dst_addr_h = HI_U32(phy1);

	/* AEAD output MAC addr use out addr */
	if (msg->op_type == WCRYPTO_CIPHER_ENCRYPTION_DIGEST) {
		/* if 'msg->out' uses sgl, we should get its 'buf' addr */
		if (msg->data_fmt == WD_SGL_BUF) {
			p = drv_get_sgl_pri((struct wd_sgl *)msg->out);
			phy2 = ((struct hisi_sgl *)p)->sge_entries[0].buf;
			if (unlikely(!phy2)) {
				WD_ERR("fail to get sgl msg_out dma address!\n");
				drv_iova_unmap(q, msg->out,
					(void *)(uintptr_t)phy1, msg->out_bytes);
				return -WD_ENOMEM; /* unmap msg->out */
			}
			phy2 = phy2 + msg->assoc_bytes + msg->in_bytes;
		} else {
			phy2 = phy1 + msg->assoc_bytes + msg->in_bytes;
		}
		sqe->type2.mac_addr_l = (__u32)(phy2 & QM_L32BITS_MASK);
		sqe->type2.mac_addr_h = HI_U32(phy2);
	}

	return WD_SUCCESS;
}

static int fill_aead_bd2_addr(struct wd_queue *q,
		struct wcrypto_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	uintptr_t phy;
	int ret;

	ret = fill_aead_bd2_addr_src(q, msg, sqe);
	if (unlikely(ret))
		return ret;

	ret = fill_aead_bd2_addr_dst(q, msg, sqe);
	if (unlikely(ret))
		goto map_out_error;

	ret = map_addr(q, msg->ckey, msg->ckey_bytes, &sqe->type2.c_key_addr_l,
			    &sqe->type2.c_key_addr_h, msg->data_fmt);
	if (unlikely(ret))
		goto map_ckey_error;

	ret = map_addr(q, msg->akey, msg->akey_bytes, &sqe->type2.a_key_addr_l,
			    &sqe->type2.a_key_addr_h, msg->data_fmt);
	if (unlikely(ret))
		goto map_akey_error;

	ret = map_addr(q, msg->iv, msg->iv_bytes, &sqe->type2.c_ivin_addr_l,
			    &sqe->type2.c_ivin_addr_h, msg->data_fmt);
	if (unlikely(ret))
		goto map_civ_error;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	ret = map_addr(q, msg->aiv, msg->iv_bytes, &sqe->type2.a_ivin_addr_l,
			    &sqe->type2.a_ivin_addr_h, msg->data_fmt);
	if (unlikely(ret))
		goto map_aiv_error;

	return WD_SUCCESS;

map_aiv_error:
	unmap_addr(q, msg->iv, msg->iv_bytes, sqe->type2.c_ivin_addr_l,
		  sqe->type2.c_ivin_addr_h, msg->data_fmt);
map_civ_error:
	unmap_addr(q, msg->akey, msg->akey_bytes, sqe->type2.a_key_addr_l,
		  sqe->type2.a_key_addr_h, msg->data_fmt);
map_akey_error:
	unmap_addr(q, msg->ckey, msg->ckey_bytes, sqe->type2.c_key_addr_l,
		  sqe->type2.c_key_addr_h, msg->data_fmt);
map_ckey_error:
	phy = DMA_ADDR(sqe->type2.data_dst_addr_h,
			sqe->type2.data_dst_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)phy, msg->out_bytes);
map_out_error:
	phy = DMA_ADDR(sqe->type2.data_src_addr_h,
			sqe->type2.data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)phy, msg->in_bytes);
	return -WD_ENOMEM;
}

static int fill_aead_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_aead_msg *msg, struct wcrypto_aead_tag *tag)
{
	int ret;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;
	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->de = DATA_DST_ADDR_ENABLE;

	if (msg->data_fmt == WD_SGL_BUF) {
		sqe->src_addr_type = HISI_SGL_BUF;
		sqe->dst_addr_type = HISI_SGL_BUF;
	} else {
		sqe->src_addr_type = HISI_FLAT_BUF;
		sqe->dst_addr_type = HISI_FLAT_BUF;
	}

	sqe->type2.c_len = msg->in_bytes;
	sqe->type2.cipher_src_offset = msg->assoc_bytes;
	sqe->type2.a_len = msg->in_bytes + msg->assoc_bytes;

	ret = fill_aead_bd2_alg(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_cipher_bd2_alg fail!\n");
		return ret;
	}

	ret = fill_aead_bd2_mode(msg, sqe);
	if (ret != WD_SUCCESS) {
		WD_ERR("fill_cipher_bd2_mode fail!\n");
		return ret;
	}

	ret = fill_aead_bd2_addr(q, msg, sqe);
	if (ret != WD_SUCCESS)
		return ret;

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

	return ret;
}

int qm_fill_aead_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct wcrypto_aead_msg *msg = message;
	struct wcrypto_aead_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	struct hisi_sec_sqe *sqe;
	uintptr_t temp;
	int ret;

	ret = aead_comb_param_check(msg);
	if (ret) {
		WD_ERR("Invalid aead cipher alg = %hhu and mode = %hhu combination\n",
			msg->calg, msg->cmode);
		return ret;
	}

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	memset(sqe, 0, sizeof(struct hisi_sec_sqe));

	ret = fill_aead_bd2(q, sqe, msg, tag);
	if (ret != WD_SUCCESS)
		return ret;

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return ret;
}

static void parse_aead_bd2(struct wd_queue *q, struct hisi_sec_sqe *sqe,
		struct wcrypto_aead_msg *msg)
{
	__u64 dma_addr;

	if (sqe->type2.done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD2 %s fail! done=0x%x, etype=0x%x\n", "aead",
		sqe->type2.done, sqe->type2.error_type);
		msg->result = WD_IN_EPARA;
	} else
		msg->result = WD_SUCCESS;

	dma_addr = DMA_ADDR(sqe->type2.data_src_addr_h,
			sqe->type2.data_src_addr_l);
	drv_iova_unmap(q, msg->in, (void *)(uintptr_t)dma_addr,
			msg->in_bytes);
	dma_addr = DMA_ADDR(sqe->type2.data_dst_addr_h,
			sqe->type2.data_dst_addr_l);
	drv_iova_unmap(q, msg->out, (void *)(uintptr_t)dma_addr,
			msg->out_bytes);
	dma_addr = DMA_ADDR(sqe->type2.c_key_addr_h,
			sqe->type2.c_key_addr_l);
	drv_iova_unmap(q, msg->ckey, (void *)(uintptr_t)dma_addr,
			msg->ckey_bytes);
	dma_addr = DMA_ADDR(sqe->type2.a_key_addr_h,
			sqe->type2.a_key_addr_l);
	drv_iova_unmap(q, msg->akey, (void *)(uintptr_t)dma_addr,
			msg->akey_bytes);
	dma_addr = DMA_ADDR(sqe->type2.c_ivin_addr_h,
			sqe->type2.c_ivin_addr_l);
	drv_iova_unmap(q, msg->iv, (void *)(uintptr_t)dma_addr,
			msg->iv_bytes);
	dma_addr = DMA_ADDR(sqe->type2.a_ivin_addr_h,
			sqe->type2.a_ivin_addr_l);
	drv_iova_unmap(q, msg->aiv, (void *)(uintptr_t)dma_addr,
			msg->iv_bytes);
}

/*
 * According to wcrypto_aead_poll(), the return number mean:
 * 0: parse failed
 * 1: parse a BD successfully
 */
int qm_parse_aead_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_aead_msg *aead_msg = info->req_cache[i];
	struct hisi_sec_sqe *sqe = msg;
	struct wd_queue *q = info->q;

	if (unlikely(!aead_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	if (sqe->type == BD_TYPE2) {
		if (usr && sqe->type2.tag != usr)
			return 0;
		parse_aead_bd2(q, sqe, aead_msg);
	} else {
		WD_ERR("SEC BD Type error\n");
		aead_msg->result = WD_IN_EPARA;
	}

#ifdef DEBUG_LOG
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif

	return 1;
}