// SPDX-License-Identifier: Apache-2.0
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
		sqe->type2.c_mode = C_MODE_ECB;
		break;
	case WCRYPTO_CIPHER_CBC:
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
	case WCRYPTO_CIPHER_CTR:
		ctr_iv_inc(msg->iv, msg->in_bytes >> CTR_MODE_LEN_SHIFT);
		break;
	default:
		break;
	}
}

int qm_fill_cipher_sqe(void *message, struct qm_queue_info *info, __u16 i)
{
	struct hisi_sec_sqe *sqe;
	struct wcrypto_cipher_msg *msg = message;
	struct wd_queue *q = info->q;
	struct wcrypto_cipher_tag *tag = (void *)(uintptr_t)msg->usr_data;
	uintptr_t temp;
	uintptr_t phy;
	int ret = WD_SUCCESS;

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	if (msg->in == msg->out)
		sqe->de = DATA_DST_ADDR_DISABLE;
	else
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

	phy = (uintptr_t)drv_dma_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_dma_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("Get msg out dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_dst_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_dst_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_dma_map(q, msg->key, msg->key_bytes);
	if (!phy) {
		WD_ERR("Get key dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.c_key_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.c_key_addr_h = HI_U32(phy);
	phy = (uintptr_t)drv_dma_map(q, msg->iv, msg->iv_bytes);
	if (!phy) {
		WD_ERR("Get iv dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.c_ivin_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.c_ivin_addr_h = HI_U32(phy);

	if (tag)
		sqe->type2.tag = tag->wcrypto_tag.ctx_id;

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
	struct wcrypto_digest_tag *digest_tag = (void *)msg->usr_data;

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
	int ret = WD_SUCCESS;
	uintptr_t temp;
	uintptr_t phy;

	temp = (uintptr_t)info->sq_base + i * info->sqe_size;
	sqe = (struct hisi_sec_sqe *)temp;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;

	sqe->auth = AUTH_MAC_CALCULATE;
	sqe->type2.a_len = msg->in_bytes;

	phy = (uintptr_t)drv_dma_map(q, msg->in, msg->in_bytes);
	if (!phy) {
		WD_ERR("Get msg in dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.data_src_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.data_src_addr_h = HI_U32(phy);

	phy = (uintptr_t)drv_dma_map(q, msg->out, msg->out_bytes);
	if (!phy) {
		WD_ERR("Get msg out dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->type2.mac_addr_l = (__u32)(phy & QM_L32BITS_MASK);
	sqe->type2.mac_addr_h = HI_U32(phy);

	if (msg->mode == WCRYPTO_DIGEST_HMAC) {
		sqe->type2.a_key_len = msg->key_bytes / WORD_BYTES;
		phy = (uintptr_t)drv_dma_map(q, msg->key, msg->key_bytes);
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

int qm_parse_cipher_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr)
{
	struct wcrypto_cipher_msg *cipher_msg = info->req_cache[i];
	struct hisi_sec_sqe *sqe = msg;
	struct wd_queue *q = info->q;
	__u64 dma_addr;

	/* if this hw msg not belong to me, then try again */
	if (usr && sqe->type2.tag != usr)
		return 0;

	if (sqe->type == BD_TYPE2) {
		if (sqe->type2.done != SEC_HW_TASK_DONE
			|| sqe->type2.error_type) {
			WD_ERR("SEC %s fail!done=0x%x, etype=0x%x\n", "cipher",
			sqe->type2.done, sqe->type2.error_type);
			cipher_msg->result = WD_IN_EPARA;
#ifdef DEBUG_LOG
			sec_dump_bd((unsigned int *)sqe, SQE_WORD_NUMS);
#endif
			return -WD_EIO;
		} else
			cipher_msg->result = WD_SUCCESS;

		dma_addr = DMA_ADDR(sqe->type2.data_src_addr_h,
				sqe->type2.data_src_addr_l);
		drv_dma_unmap(q, cipher_msg->in, (void *)dma_addr,
				cipher_msg->in_bytes);
		dma_addr = DMA_ADDR(sqe->type2.data_dst_addr_h,
				sqe->type2.data_dst_addr_l);
		drv_dma_unmap(q, cipher_msg->out, (void *)dma_addr,
				cipher_msg->out_bytes);
		dma_addr = DMA_ADDR(sqe->type2.c_key_addr_h,
				sqe->type2.c_key_addr_l);
		drv_dma_unmap(q, cipher_msg->key, (void *)dma_addr,
				cipher_msg->key_bytes);
		dma_addr = DMA_ADDR(sqe->type2.c_ivin_addr_h,
				sqe->type2.c_ivin_addr_l);
		drv_dma_unmap(q, cipher_msg->iv, (void *)dma_addr,
				cipher_msg->iv_bytes);
	}

	update_iv(cipher_msg);

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
			return -WD_EIO;
		} else
			digest_msg->result = WD_SUCCESS;

		dma_addr = DMA_ADDR(sqe->type2.data_src_addr_h,
				sqe->type2.data_src_addr_l);
		drv_dma_unmap(q, digest_msg->in, (void *)dma_addr,
				digest_msg->in_bytes);
		dma_addr = DMA_ADDR(sqe->type2.mac_addr_h,
				sqe->type2.mac_addr_l);
		drv_dma_unmap(q, digest_msg->out, (void *)dma_addr,
				digest_msg->out_bytes);
		if (digest_msg->mode == WCRYPTO_DIGEST_HMAC) {
			dma_addr = DMA_ADDR(sqe->type2.a_key_addr_h,
				sqe->type2.a_key_addr_h);
			drv_dma_unmap(q, digest_msg->key, (void *)dma_addr,
				digest_msg->key_bytes);
		}
	}

	return 1;
}
