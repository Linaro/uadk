/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include "../include/drv/wd_cipher_drv.h"
#include "../include/drv/wd_digest_drv.h"
#include "../include/drv/wd_aead_drv.h"
#include "hisi_qm_udrv.h"
#include "wd_cipher.h"
#include "wd_digest.h"
#include "wd_aead.h"
#include "wd.h"

#define SEC_DIGEST_ALG_OFFSET	11
#define WORD_ALIGNMENT_MASK	0x3
#define CTR_MODE_LEN_SHIFT	4
#define WORD_BYTES		4
#define BYTE_BITS		8
#define SQE_BYTES_NUMS		128
#define SEC_FLAG_OFFSET		7
#define SEC_AUTH_KEY_OFFSET	5
#define SEC_HW_ICV_ERR		0x2
#define SEC_HW_TASK_DONE	0x1
#define SEC_DONE_MASK		0x0001
#define SEC_ICV_MASK		0x000E
#define SEC_AUTH_MASK		0x3F

#define SEC_IPSEC_SCENE		0x1
#define SEC_STREAM_SCENE	0x7
#define SEC_SCENE_OFFSET	  3
#define SEC_DE_OFFSET		  1
#define SEC_AUTH_OFFSET  	  6
#define SEC_CMODE_OFFSET	  12
#define SEC_CKEY_OFFSET		  9
#define SEC_CIPHER_OFFSET	  4
#define XTS_MODE_KEY_DIVISOR	  2
#define SEC_CTR_CNT_OFFSET	  25
#define SEC_CTR_CNT_ROLLOVER	  2

#define SEC_DE_OFFSET_V3	9
#define SEC_SCENE_OFFSET_V3	5
#define SEC_CKEY_OFFSET_V3	13
#define SEC_CALG_OFFSET_V3	4
#define SEC_AKEY_OFFSET_V3	9
#define SEC_MAC_OFFSET_V3	4
#define SEC_AUTH_ALG_OFFSET_V3	15
#define SEC_CIPHER_AUTH_V3	0xbf
#define SEC_AUTH_CIPHER_V3	0x40
#define SEC_AI_GEN_OFFSET_V3	2
#define SEC_SEQ_OFFSET_V3	6
#define SEC_AUTH_MASK_V3	0xFFFFFFFC

#define SEC_SGL_MODE_MASK_V3 0x4800
#define SEC_PBUFF_MODE_MASK_V3 0x800
#define SEC_SGL_SDS_MASK 0x80
#define SEC_SGL_SDM_MASK 0x04
#define SEC_MAC_LEN_MASK	0x1F
#define SEC_AUTH_LEN_MASK	0x3F

#define DES_KEY_SIZE		  8
#define SEC_3DES_2KEY_SIZE	  (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE	  (3 * DES_KEY_SIZE)
#define AES_KEYSIZE_128		  16
#define AES_KEYSIZE_192		  24
#define AES_KEYSIZE_256		  32

#define DES3_BLOCK_SIZE		8
#define AES_BLOCK_SIZE		16
#define CTR_128BIT_COUNTER	16

/* The max BD data length is 16M-512B */
#define MAX_INPUT_DATA_LEN	0xFFFE00
#define MAX_CCM_AAD_LEN		65279

#define AUTHPAD_OFFSET		2
#define AUTHTYPE_OFFSET		6
#define MAC_LEN_OFFSET		5
#define AUTH_ALG_OFFSET		11
#define WD_CIPHER_THEN_DIGEST		0x0
#define WD_DIGEST_THEN_CIPHER		0x1

enum C_ALG {
	C_ALG_DES  = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES  = 0x2,
	C_ALG_SM4  = 0x3,
};

enum A_ALG {
	A_ALG_SHA1	 = 0x0,
	A_ALG_SHA256 = 0x1,
	A_ALG_MD5	 = 0x2,
	A_ALG_SHA224 = 0x3,
	A_ALG_SHA384 = 0x4,
	A_ALG_SHA512 = 0x5,
	A_ALG_SHA512_224 = 0x6,
	A_ALG_SHA512_256 = 0x7,
	A_ALG_HMAC_SHA1   = 0x10,
	A_ALG_HMAC_SHA256 = 0x11,
	A_ALG_HMAC_MD5	  = 0x12,
	A_ALG_HMAC_SHA224 = 0x13,
	A_ALG_HMAC_SHA384 = 0x14,
	A_ALG_HMAC_SHA512 = 0x15,
	A_ALG_HMAC_SHA512_224 = 0x16,
	A_ALG_HMAC_SHA512_256 = 0x17,
	A_ALG_AES_XCBC_MAC_96  = 0x20,
	A_ALG_AES_XCBC_PRF_128 = 0x20,
	A_ALG_AES_CMAC = 0x21,
	A_ALG_AES_GMAC = 0x22,
	A_ALG_SM3	   = 0x25,
	A_ALG_HMAC_SM3 = 0x26
};

enum C_MODE {
	C_MODE_ECB	  = 0x0,
	C_MODE_CBC	  = 0x1,
	C_MODE_CFB	  = 0x2,
	C_MODE_OFB	  = 0x3,
	C_MODE_CTR	  = 0x4,
	C_MODE_CCM	  = 0x5,
	C_MODE_GCM	  = 0x6,
	C_MODE_XTS	  = 0x7,
	C_MODE_CBC_CS     = 0x9,
};

enum C_KEY_LEN {
	CKEY_LEN_128BIT = 0x0,
	CKEY_LEN_192BIT = 0x1,
	CKEY_LEN_256BIT = 0x2,
	CKEY_LEN_SM4    = 0x0,
	CKEY_LEN_DES    = 0x1,
	CKEY_LEN_3DES_3KEY = 0x1,
	CKEY_LEN_3DES_2KEY = 0x3,
};

enum {
	NO_AUTH		= 0x0,
	AUTH_HMAC_CALCULATE	= 0x1,
	AUTH_MAC_VERIFY	= 0x2,
};

enum {
	DATA_DST_ADDR_DISABLE	= 0x0,
	DATA_DST_ADDR_ENABLE	= 0x1,
};

enum {
	AI_GEN_INNER		= 0x0,
	AI_GEN_IVIN_ADDR	= 0x1,
	AI_GEN_CAL_IV_ADDR	= 0x2,
	AI_GEN_TRNG		= 0x3,
};

enum {
	AUTHPAD_PAD	= 0x0,
	AUTHPAD_NOPAD	= 0x1,
};

enum sec_cipher_dir {
	SEC_CIPHER_ENC = 0x1,
	SEC_CIPHER_DEC = 0x2,
};

enum sec_bd_type {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
	BD_TYPE3 = 0x3,
};

struct hisi_sec_ctx {
	struct wd_ctx_config_internal config;
};

struct hisi_sec_sqe_type2 {
	/*
	 * mac_len: 0~4 bits
	 * a_key_len: 5~10 bits
	 * a_alg: 11~16 bits
	 */
	__u32 mac_key_alg;

	/*
	 * c_icv_len: 0~5 bits
	 * c_width: 6~8 bits
	 * c_key_len: 9~11 bits
	 * c_mode: 12~15 bits
	 */
	__u16 icvw_kmode;

	/* c_alg: 0~3 bits */
	__u8 c_alg;

	__u8 rsvd4;
	/*
	 * a_len: 0~23 bits
	 * iv_offset_l: 24~31 bits
	 */
	__u32 alen_ivllen;

	/*
	 * c_len: 0~23 bits
	 * iv_offset_h: 24~31 bits
	 */
	__u32 clen_ivhlen;

	__u16 auth_src_offset;
	__u16 cipher_src_offset;
	__u16 cs_ip_header_offset;
	__u16 cs_udp_header_offset;
	__u16 pass_word_len;
	__u16 dk_len;
	__u8 salt3;
	__u8 salt2;
	__u8 salt1;
	__u8 salt0;

	__u16 tag;
	__u16 rsvd5;

	/*
	 * c_pad_type: 0~3 bits
	 * c_pad_len: 4~11 bits
	 * c_pad_data_type: 12~15 bits
	 */
	__u16 cph_pad;
	/* c_pad_len_field: 0~1 bits */

	__u16 c_pad_len_field;

	__u64 long_a_data_len;
	__u64 a_ivin_addr;

	__u64 a_key_addr;

	__u64 mac_addr;
	__u64 c_ivin_addr;
	__u64 c_key_addr;

	__u64 data_src_addr;
	__u64 data_dst_addr;

	/*
	 * done: 0 bit
	 * icv: 1~3 bits
	 * csc: 4~6 bits
	 * flag: 7~10 bits
	 * dif_check: 11~13 bits
	 */
	__u16 done_flag;

	__u8 error_type;
	__u8 warning_type;
	__u8 mac_i3;
	__u8 mac_i2;
	__u8 mac_i1;
	__u8 mac_i0;
	__u16 check_sum_i;
	__u8 tls_pad_len_i;
	__u8 rsvd12;
	__u32 counter;
};

struct hisi_sec_sqe {
	/*
	 * type:  0~3 bits;
	 * cipher: 4~5 bits;
	 * auth: 6~7 bits;
	 */
	__u8 type_auth_cipher;
	/*
	 * seq: 0 bits;
	 * de: 1~2 bits;
	 * scene: 3~6 bits;
	 * src_addr_type: 7 bits;
	 */
	__u8 sds_sa_type;
	/*
	 * src_addr_type: 0~1 bits not used now.
	 * dst_addr_type: 2~4 bits;
	 * mac_addr_type: 5~7 bits;
	 */
	__u8 sdm_addr_type;

	__u8 rsvd0;
	/*
	 * nonce_len(type): 0~3 bits;
	 */
	__u8 huk_ci_key;
	/*
	 * ai_gen: 0~1 bits;
	 */
	__u8 ai_apd_cs;
	/*
	 * rhf(type2): 0 bit;
	 * c_key_type: 1~2 bits;
	 * a_key_type: 3~4 bits
	 * write_frame_len(type2): 5~7bits;
	 */
	__u8 rca_key_frm;

	__u8 iv_tls_ld;

	struct hisi_sec_sqe_type2 type2;
};

struct bd3_auth_ivin {
	__le64 a_ivin_addr;
	__le32 rsvd0;
	__le32 rsvd1;
} __attribute__((packed, aligned(4)));

struct bd3_skip_data {
	__le32 rsvd0;

	/*
	 * gran_num: 0~15 bits
	 * reserved: 16~31 bits
	 */
	__le32 gran_num;

	/*
	 * src_skip_data_len: 0~24 bits
	 * reserved: 25~31 bits
	 */
	__le32 src_skip_data_len;

	/*
	 * dst_skip_data_len: 0~24 bits
	 * reserved: 25~31 bits
	 */
	__le32 dst_skip_data_len;
};

struct bd3_stream_scene {
	__le64 c_ivin_addr;
	__le64 long_a_data_len;

	/*
	 * auth_pad: 0~1 bits
	 * stream_protocol: 2~4 bits
	 * reserved: 5~7 bits
	 */
	__u8 stream_auth_pad;
	__u8 plaintext_type;
	__le16 pad_len_1p3;
} __attribute__((packed, aligned(4)));

struct bd3_no_scene {
	__le64 c_ivin_addr;
	__le32 rsvd0;
	__le32 rsvd1;
	__le32 rsvd2;
} __attribute__((packed, aligned(4)));

struct bd3_check_sum {
	__u8 rsvd0;
	__u8 hac_sva_status;
	__le16 check_sum_i;
};

struct bd3_tls_type_back {
	__u8 tls_1p3_type_back;
	__u8 hac_sva_status;
	__le16 pad_len_1p3_back;
};

struct hisi_sec_sqe3 {
	/*
	 * type: 0~3 bit
	 * bd_invalid: 4 bit
	 * scene: 5~8 bit
	 * de: 9~10 bit
	 * src_addr_type: 11~13 bit
	 * dst_addr_type: 14~16 bit
	 * mac_addr_type: 17~19 bit
	 * reserved: 20~31 bits
	 */
	__le32 bd_param;

	/*
	 * cipher: 0~1 bits
	 * ci_gen: 2~3 bit
	 * c_icv_len: 4~9 bit
	 * c_width: 10~12 bits
	 * c_key_len: 13~15 bits
	 */
	__le16 c_icv_key;

	/*
	 * c_mode : 0~3 bits
	 * c_alg : 4~7 bits
	 */
	__u8 c_mode_alg;

	/*
	 * nonce_len : 0~3 bits
	 * huk : 4 bits
	 * cal_iv_addr_en : 5 bits
	 * seq : 6 bits
	 * reserved : 7 bits
	 */
	__u8 huk_iv_seq;

	__le64 tag;
	__le64 data_src_addr;
	__le64 a_key_addr;
	union {
		struct bd3_auth_ivin auth_ivin;
		struct bd3_skip_data skip_data;
	};

	__le64 c_key_addr;

	/*
	 * auth: 0~1 bits
	 * ai_gen: 2~3 bits
	 * mac_len: 4~8 bits
	 * akey_len: 9~14 bits
	 * a_alg: 15~20 bits
	 * key_sel: 21~24 bits
	 * ctr_count_mode/sm4_xts: 25~26 bits
	 * sva_prefetch: 27 bits
	 * key_wrap_num:28~30 bits
	 * update_key: 31 bits
	 */
	__le32 auth_mac_key;
	__le32 salt;
	__le16 auth_src_offset;
	__le16 cipher_src_offset;

	/*
	 * auth_len: 0~23 bit
	 * auth_key_offset: 24~31 bits
	 */
	__le32 a_len_key;

	/*
	 * cipher_len: 0~23 bit
	 * auth_ivin_offset: 24~31 bits
	 */
	__le32 c_len_ivin;
	__le64 data_dst_addr;
	__le64 mac_addr;
	union {
		struct bd3_stream_scene stream_scene;
		struct bd3_no_scene no_scene;
	};

	/*
	 * done: 0 bit
	 * icv: 1~3 bit
	 * csc: 4~6 bit
	 * flag: 7~10 bit
	 * reserved: 11~15 bit
	 */
	__le16 done_flag;
	__u8 error_type;
	__u8 warning_type;
	union {
		__le32 mac_i;
		__le32 kek_key_addr_l;
	};

	union {
		__le32 kek_key_addr_h;
		struct bd3_check_sum check_sum;
		struct bd3_tls_type_back tls_type_back;
	};
	__le32 counter;
} __attribute__((packed, aligned(4)));

static int g_digest_a_alg[WD_DIGEST_TYPE_MAX] = {
	A_ALG_SM3, A_ALG_MD5, A_ALG_SHA1, A_ALG_SHA256, A_ALG_SHA224,
	A_ALG_SHA384, A_ALG_SHA512, A_ALG_SHA512_224, A_ALG_SHA512_256
};
static int g_hmac_a_alg[WD_DIGEST_TYPE_MAX] = {
	A_ALG_HMAC_SM3, A_ALG_HMAC_MD5, A_ALG_HMAC_SHA1,
	A_ALG_HMAC_SHA256, A_ALG_HMAC_SHA224, A_ALG_HMAC_SHA384,
	A_ALG_HMAC_SHA512, A_ALG_HMAC_SHA512_224, A_ALG_HMAC_SHA512_256
};

int hisi_sec_init(struct wd_ctx_config_internal *config, void *priv);
void hisi_sec_exit(void *priv);

#ifdef DEBUG
static void sec_dump_bd(unsigned char *bd, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		WD_ERR("\\0x%02x", bd[i]);
		if ((i + 1) % WORD_BYTES == 0)
			WD_ERR("\n");
	}
	WD_ERR("\n");
}
#endif

/* increment counter (128-bit int) by software */
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

static void update_iv(struct wd_cipher_msg *msg)
{
	switch (msg->mode) {
	case WD_CIPHER_CBC:
		if (msg->op_type == WD_CIPHER_ENCRYPTION &&
		    msg->out_bytes >= msg->iv_bytes)
			memcpy(msg->iv, msg->out + msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes);
		if (msg->op_type == WD_CIPHER_DECRYPTION &&
		    msg->in_bytes >= msg->iv_bytes)
			memcpy(msg->iv, msg->in + msg->in_bytes -
				msg->iv_bytes, msg->iv_bytes);
		break;
	case WD_CIPHER_OFB:
	case WD_CIPHER_CFB:
		if (msg->out_bytes >= msg->iv_bytes)
			memcpy(msg->iv, msg->out + msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes);
		break;
	case WD_CIPHER_CTR:
			ctr_iv_inc(msg->iv, msg->iv_bytes >>
				CTR_MODE_LEN_SHIFT);
		break;
	default:
		break;
	}
}

static void update_iv_sgl(struct wd_cipher_msg *msg)
{
	switch (msg->mode) {
	case WD_CIPHER_CBC:
		if (msg->op_type == WD_CIPHER_ENCRYPTION &&
		    msg->out_bytes >= msg->iv_bytes)
			hisi_qm_sgl_copy(msg->iv, msg->out, msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes, COPY_SGL_TO_PBUFF);
		if (msg->op_type == WD_CIPHER_DECRYPTION &&
		    msg->in_bytes >= msg->iv_bytes)
			hisi_qm_sgl_copy(msg->iv, msg->in, msg->in_bytes -
				msg->iv_bytes, msg->iv_bytes, COPY_SGL_TO_PBUFF);
		break;
	case WD_CIPHER_OFB:
	case WD_CIPHER_CFB:
		if (msg->out_bytes >= msg->iv_bytes)
			hisi_qm_sgl_copy(msg->iv, msg->out, msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes, COPY_SGL_TO_PBUFF);
		break;
	case WD_CIPHER_CTR:
			ctr_iv_inc(msg->iv, msg->iv_bytes >>
				CTR_MODE_LEN_SHIFT);
		break;
	default:
		break;
	}
}

static int get_3des_c_key_len(struct wd_cipher_msg *msg, __u8 *c_key_len)
{
	if (msg->key_bytes == SEC_3DES_2KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_2KEY;
	} else if (msg->key_bytes == SEC_3DES_3KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_3KEY;
	} else {
		WD_ERR("invalid 3des key size!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int get_aes_c_key_len(struct wd_cipher_msg *msg, __u8 *c_key_len)
{
	__u16 len;

	len = msg->key_bytes;
	if (msg->mode == WD_CIPHER_XTS)
		len = len / XTS_MODE_KEY_DIVISOR;

	switch (len) {
	case AES_KEYSIZE_128:
		*c_key_len = CKEY_LEN_128BIT;
		break;
	case AES_KEYSIZE_192:
		*c_key_len = CKEY_LEN_192BIT;
		break;
	case AES_KEYSIZE_256:
		*c_key_len = CKEY_LEN_256BIT;
		break;
	default:
		WD_ERR("invalid AES key size!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_cipher_bd2_alg(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u8 c_key_len = 0;
	int ret = 0;

	switch (msg->alg) {
	case WD_CIPHER_SM4:
		sqe->type2.c_alg = C_ALG_SM4;
		sqe->type2.icvw_kmode = CKEY_LEN_SM4 << SEC_CKEY_OFFSET;
		break;
	case WD_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	case WD_CIPHER_DES:
		sqe->type2.c_alg = C_ALG_DES;
		sqe->type2.icvw_kmode = CKEY_LEN_DES;
		break;
	case WD_CIPHER_3DES:
		sqe->type2.c_alg = C_ALG_3DES;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	default:
		WD_ERR("invalid cipher type!\n");
		return -WD_EINVAL;
	}

	return ret;
}

static int fill_cipher_bd2_mode(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u16 c_mode;

	switch (msg->mode) {
	case WD_CIPHER_ECB:
		if (msg->alg == WD_CIPHER_SM4) {
			WD_ERR("kunpeng 920 not support ECB(SM4)!\n");
			return -WD_EINVAL;
		}
		c_mode = C_MODE_ECB;
		break;
	case WD_CIPHER_CBC:
		c_mode = C_MODE_CBC;
		break;
	case WD_CIPHER_XTS:
		c_mode = C_MODE_XTS;
		break;
	default:
		WD_ERR("invalid cipher mode type!\n");
		return -WD_EINVAL;
	}
	sqe->type2.icvw_kmode |= (__u16)(c_mode) << SEC_CMODE_OFFSET;

	return 0;
}

static void fill_cipher_bd2_addr(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	sqe->type2.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->type2.data_dst_addr = (__u64)(uintptr_t)msg->out;
	sqe->type2.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->type2.c_key_addr = (__u64)(uintptr_t)msg->key;

	/*
	 * Because some special algorithms need to update IV
	 * after receiving the BD, and the relevant information
	 * is in the send message, so the BD field segment is
	 * needed to return the message pointer.
	 * The Cipher algorithm does not use the mac_addr segment
	 * in the BD domain and the hardware will copy all the
	 * field values of the send BD when returning, so we use
	 * mac_addr to carry the message pointer here.
	 */
	sqe->type2.mac_addr = (__u64)(uintptr_t)msg;
}

static void parse_cipher_bd2(struct hisi_sec_sqe *sqe, struct wd_cipher_msg *recv_msg)
{
	struct wd_cipher_msg *rmsg;
	__u16 done;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD %s fail! done=0x%x, etype=0x%x\n", "cipher",
		done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	rmsg = (struct wd_cipher_msg *)(uintptr_t)sqe->type2.mac_addr;

	if (rmsg->data_fmt != WD_SGL_BUF)
		update_iv(rmsg);
	else
		update_iv_sgl(rmsg);

	recv_msg->data_fmt = rmsg->data_fmt;
	recv_msg->alg_type = rmsg->alg_type;
	recv_msg->in = rmsg->in;
	recv_msg->out = rmsg->out;
}

static int cipher_len_check(struct wd_cipher_msg *msg)
{
	if (msg->in_bytes > MAX_INPUT_DATA_LEN ||
	    !msg->in_bytes) {
		WD_ERR("input cipher length is error!\n");
		return -WD_EINVAL;
	}

	if (msg->mode == WD_CIPHER_OFB ||
	    msg->mode == WD_CIPHER_CFB ||
	    msg->mode == WD_CIPHER_CTR)
		return 0;

	if (msg->mode == WD_CIPHER_XTS) {
		if (msg->in_bytes < AES_BLOCK_SIZE) {
			WD_ERR("input cipher length is too small!\n");
			return -WD_EINVAL;
		}
		return 0;
	}

	if (msg->alg == WD_CIPHER_3DES || msg->alg == WD_CIPHER_DES) {
		if (msg->in_bytes & (DES3_BLOCK_SIZE - 1)) {
			WD_ERR("input 3DES or DES cipher parameter is error!\n");
			return -WD_EINVAL;
		}
		return 0;
	} else if (msg->alg == WD_CIPHER_AES || msg->alg == WD_CIPHER_SM4) {
		if (msg->in_bytes & (AES_BLOCK_SIZE - 1)) {
			WD_ERR("input AES or SM4 cipher parameter is error!\n");
			return -WD_EINVAL;
		}
		return 0;
	}

	return 0;
}

static __u8 hisi_sec_get_data_fmt_v3(__u32 bd_param)
{
	/* Only check the src addr type */
	if (bd_param & SEC_PBUFF_MODE_MASK_V3)
		return WD_SGL_BUF;

	return WD_FLAT_BUF;
}

static __u8 hisi_sec_get_data_fmt_v2(__u32 sds_sa_type)
{
	/* Only check the src addr type */
	if (sds_sa_type & SEC_SGL_SDS_MASK)
		return WD_SGL_BUF;

	return WD_FLAT_BUF;
}

static void hisi_sec_put_sgl(handle_t h_qp, __u8 alg_type, void *in, void *out)
{
	handle_t h_sgl_pool;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (!h_sgl_pool)
		return;

	hisi_qm_put_hw_sgl(h_sgl_pool, in);

	if (alg_type != WD_DIGEST)
		hisi_qm_put_hw_sgl(h_sgl_pool, out);
}

static int hisi_sec_fill_sgl(handle_t h_qp, __u8 **in, __u8 **out,
		struct hisi_sec_sqe *sqe, __u8 type)
{
	handle_t h_sgl_pool;
	void *hw_sgl_in;
	void *hw_sgl_out;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (!h_sgl_pool) {
		WD_ERR("failed to get sglpool for hw_v2!\n");
		return -WD_EINVAL;
	}

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, (struct wd_datalist*)(*in));
	if (!hw_sgl_in) {
		WD_ERR("failed to get sgl in for hw_v2!\n");
		return -WD_EINVAL;
	}

	if (type == WD_DIGEST) {
		hw_sgl_out = *out;
	} else {
		hw_sgl_out = hisi_qm_get_hw_sgl(h_sgl_pool, (struct wd_datalist*)(*out));
		if (!hw_sgl_out) {
			WD_ERR("failed to get hw sgl out!\n");
			hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_in);
			return -WD_EINVAL;
		}

		sqe->sdm_addr_type |= SEC_SGL_SDM_MASK;
	}

	sqe->sds_sa_type |= SEC_SGL_SDS_MASK;
	*in = hw_sgl_in;
	*out = hw_sgl_out;

	return 0;
}

static int hisi_sec_fill_sgl_v3(handle_t h_qp, __u8 **in, __u8 **out,
				struct hisi_sec_sqe3 *sqe, __u8 type)
{
	handle_t h_sgl_pool;
	void *hw_sgl_in;
	void *hw_sgl_out;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (!h_sgl_pool) {
		WD_ERR("failed to get sglpool for hw_v3!\n");
		return -WD_EINVAL;
	}

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, (struct wd_datalist*)(*in));
	if (!hw_sgl_in) {
		WD_ERR("failed to get sgl in for hw_v3!\n");
		return -WD_EINVAL;
	}

	if (type == WD_DIGEST) {
		hw_sgl_out = *out;
		sqe->bd_param |= SEC_PBUFF_MODE_MASK_V3;
	} else {
		hw_sgl_out = hisi_qm_get_hw_sgl(h_sgl_pool, (struct wd_datalist*)(*out));
		if (!hw_sgl_out) {
			WD_ERR("failed to get hw sgl out!\n");
			hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_in);
			return -WD_EINVAL;
		}

		/*
		 * src_addr_type: 11~13 bit
		 * dst_addr_type: 14~16 bit
		 */
		sqe->bd_param |= SEC_SGL_MODE_MASK_V3;
	}

	*in = hw_sgl_in;
	*out = hw_sgl_out;

	return 0;
}

static int fill_cipher_bd2(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u8 scene, cipher, de;
	int ret;

	/* config BD type */
	sqe->type_auth_cipher = BD_TYPE2;
	/* config scene */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET;
	sqe->sds_sa_type = (__u8)(de | scene);

	if (msg->op_type == WD_CIPHER_ENCRYPTION)
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
	else
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;

	sqe->type_auth_cipher |= cipher;

	ret = cipher_len_check(msg);
	if (ret)
		return ret;

	ret = fill_cipher_bd2_alg(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill bd alg!\n");
		return ret;
	}

	ret = fill_cipher_bd2_mode(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill bd mode!\n");
		return ret;
	}

	return 0;
}

int hisi_sec_cipher_send(handle_t ctx, struct wd_cipher_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("input cipher msg is NULL!\n");
		return -WD_EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	ret = fill_cipher_bd2(msg, &sqe);
	if (ret)
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret) {
			WD_ERR("failed to get sgl!\n");
			return ret;
		}
	}

	sqe.type2.clen_ivhlen |= (__u32)msg->in_bytes;
	sqe.type2.tag = (__u16)msg->tag;
	fill_cipher_bd2_addr(msg, &sqe);

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("cipher send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);
	}

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

int hisi_sec_cipher_recv(handle_t ctx, struct wd_cipher_msg *recv_msg)
{
	struct hisi_sec_sqe sqe;
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	parse_cipher_bd2(&sqe, recv_msg);
	recv_msg->tag = sqe.type2.tag;

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
				recv_msg->out);

	return 0;
}

static struct wd_cipher_driver hisi_cipher_driver = {
		.drv_name	= "hisi_sec2",
		.alg_name	= "cipher",
		.drv_ctx_size	= sizeof(struct hisi_sec_ctx),
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
};

WD_CIPHER_SET_DRIVER(hisi_cipher_driver);

static int fill_cipher_bd3_alg(struct wd_cipher_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	__u8 c_key_len = 0;
	int ret = 0;

	switch (msg->alg) {
	case WD_CIPHER_SM4:
		sqe->c_mode_alg |= C_ALG_SM4 << SEC_CALG_OFFSET_V3;
		sqe->c_icv_key |= CKEY_LEN_SM4 << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_AES:
		sqe->c_mode_alg |= C_ALG_AES << SEC_CALG_OFFSET_V3;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->c_icv_key |= (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_DES:
		sqe->c_mode_alg |= C_ALG_DES << SEC_CALG_OFFSET_V3;
		sqe->c_icv_key |= CKEY_LEN_DES << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_3DES:
		sqe->c_mode_alg |= C_ALG_3DES << SEC_CALG_OFFSET_V3;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->c_icv_key |= (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	default:
		WD_ERR("invalid cipher type!\n");
		return -WD_EINVAL;
	}

	return ret;
}

static int fill_cipher_bd3_mode(struct wd_cipher_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	__u16 c_mode;

	switch (msg->mode) {
	case WD_CIPHER_ECB:
		c_mode = C_MODE_ECB;
		break;
	case WD_CIPHER_CBC:
		c_mode = C_MODE_CBC;
		break;
	case WD_CIPHER_OFB:
		c_mode = C_MODE_OFB;
		break;
	case WD_CIPHER_CTR:
		c_mode = C_MODE_CTR;
		/* Set the CTR counter mode is 128bit rollover */
		sqe->auth_mac_key = (__u32)(SEC_CTR_CNT_ROLLOVER <<
						SEC_CTR_CNT_OFFSET);
		break;
	case WD_CIPHER_XTS:
		c_mode = C_MODE_XTS;
		break;
	case WD_CIPHER_CFB:
		c_mode = C_MODE_CFB;
		break;
	default:
		WD_ERR("invalid cipher mode type!\n");
		return -WD_EINVAL;
	}
	sqe->c_mode_alg |= (__u16)c_mode;

	return 0;
}

static void fill_cipher_bd3_addr(struct wd_cipher_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	sqe->data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->data_dst_addr = (__u64)(uintptr_t)msg->out;
	sqe->no_scene.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->c_key_addr = (__u64)(uintptr_t)msg->key;

	/*
	 * Because some special algorithms need to update IV
	 * after receiving the BD, and the relevant information
	 * is in the send message, so the BD field segment is
	 * needed to return the message pointer.
	 * The Cipher algorithm does not use the mac_addr segment
	 * in the BD domain and the hardware will copy all the
	 * field values of the send BD when returning, so we use
	 * mac_addr to carry the message pointer here.
	 */
	sqe->mac_addr = (__u64)(uintptr_t)msg;
}

static int fill_cipher_bd3(struct wd_cipher_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	__u16 scene, de;
	int ret;

	/* config BD type */
	sqe->bd_param = BD_TYPE3;
	/* config scene */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET_V3;
	sqe->bd_param |= (__u16)(de | scene);

	if (msg->op_type == WD_CIPHER_ENCRYPTION)
		sqe->c_icv_key = SEC_CIPHER_ENC;
	else
		sqe->c_icv_key = SEC_CIPHER_DEC;

	ret = cipher_len_check(msg);
	if (ret)
		return ret;

	ret = fill_cipher_bd3_alg(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill bd alg!\n");
		return ret;
	}

	ret = fill_cipher_bd3_mode(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill bd mode!\n");
		return ret;
	}

	return 0;
}

int hisi_sec_cipher_send_v3(handle_t ctx, struct wd_cipher_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("input cipher msg is NULL!\n");
		return -WD_EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	ret = fill_cipher_bd3(msg, &sqe);
	if (ret)
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl_v3(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret) {
			WD_ERR("failed to get sgl!\n");
			return ret;
		}
	}

	sqe.c_len_ivin = (__u32)msg->in_bytes;
	sqe.tag = (__u64)(uintptr_t)msg->tag;
	fill_cipher_bd3_addr(msg, &sqe);

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("cipher send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);
	}

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

static void parse_cipher_bd3(struct hisi_sec_sqe3 *sqe, struct wd_cipher_msg *recv_msg)
{
	struct wd_cipher_msg *rmsg;
	__u16 done;

	done = sqe->done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("SEC BD3 %s fail! done=0x%x, etype=0x%x\n", "cipher",
		done, sqe->error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	rmsg = (struct wd_cipher_msg *)(uintptr_t)sqe->mac_addr;
	if (rmsg->data_fmt != WD_SGL_BUF)
		update_iv(rmsg);
	else
		update_iv_sgl(rmsg);

	recv_msg->data_fmt = rmsg->data_fmt;
	recv_msg->alg_type = rmsg->alg_type;
	recv_msg->in = rmsg->in;
	recv_msg->out = rmsg->out;
}

int hisi_sec_cipher_recv_v3(handle_t ctx, struct wd_cipher_msg *recv_msg)
{
	struct hisi_sec_sqe3 sqe;
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	parse_cipher_bd3(&sqe, recv_msg);
	recv_msg->tag = sqe.tag;

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
				recv_msg->out);

	return 0;
}

static int fill_digest_bd2_alg(struct wd_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	if (msg->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("invalid digest type!\n");
		return -WD_EINVAL;
	}

	sqe->type2.mac_key_alg = msg->out_bytes / WORD_BYTES;
	if (msg->mode == WD_DIGEST_NORMAL)
		sqe->type2.mac_key_alg |=
		(__u32)g_digest_a_alg[msg->alg] << AUTH_ALG_OFFSET;
	else if (msg->mode == WD_DIGEST_HMAC) {
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("invalid digest key_bytes!\n");
			return -WD_EINVAL;
		}
		sqe->type2.mac_key_alg |= (__u32)(msg->key_bytes /
			WORD_BYTES) << MAC_LEN_OFFSET;
		sqe->type2.a_key_addr = (__u64)(uintptr_t)msg->key;

		sqe->type2.mac_key_alg |=
		(__u32)g_hmac_a_alg[msg->alg] << AUTH_ALG_OFFSET;
	} else {
		WD_ERR("invalid digest mode!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void qm_fill_digest_long_bd(struct wd_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	struct wd_digest_tag *digest_tag = (void *)(uintptr_t)msg->usr_data;
	__u64 total_bits;

	if (msg->has_next && (msg->iv_bytes == 0)) {
		/* LONG BD FIRST */
		sqe->ai_apd_cs = AI_GEN_INNER;
		sqe->ai_apd_cs |= AUTHPAD_NOPAD << AUTHPAD_OFFSET;
		msg->iv_bytes = msg->out_bytes;
	} else if (msg->has_next && (msg->iv_bytes != 0)) {
		/* LONG BD MIDDLE */
		sqe->ai_apd_cs = AI_GEN_IVIN_ADDR;
		sqe->ai_apd_cs |= AUTHPAD_NOPAD << AUTHPAD_OFFSET;
		sqe->type2.a_ivin_addr = sqe->type2.mac_addr;
		msg->iv_bytes = msg->out_bytes;
	} else if (!msg->has_next && (msg->iv_bytes != 0)) {
		/* LONG BD END */
		sqe->ai_apd_cs = AI_GEN_IVIN_ADDR;
		sqe->ai_apd_cs |= AUTHPAD_PAD << AUTHPAD_OFFSET;
		sqe->type2.a_ivin_addr = sqe->type2.mac_addr;
		total_bits = digest_tag->long_data_len * BYTE_BITS;
		sqe->type2.long_a_data_len = total_bits;
		msg->iv_bytes = 0;
	} else {
		/* SHORT BD */
		msg->iv_bytes = 0;
	}
}

static void parse_digest_bd2(struct hisi_sec_sqe *sqe, struct wd_digest_msg *recv_msg)
{
	__u16 done;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD %s fail! done=0x%x, etype=0x%x\n", "digest",
		done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->type2.tag;

	recv_msg->data_fmt = hisi_sec_get_data_fmt_v2(sqe->sds_sa_type);
	recv_msg->in = (__u8 *)(uintptr_t)sqe->type2.data_src_addr;
	recv_msg->alg_type = WD_DIGEST;

#ifdef DEBUG
	WD_ERR("Dump digest recv sqe-->!\n");
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif
}

static int digest_len_check(struct wd_digest_msg *msg, enum sec_bd_type type)
{
	if (type == BD_TYPE2 && msg->in_bytes == 0) {
		WD_ERR("digest bd2 not supports 0 packet!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->in_bytes > MAX_INPUT_DATA_LEN)) {
		WD_ERR("failed to check digest input data length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->out_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check digest out length!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int hisi_sec_digest_send(handle_t ctx, struct wd_digest_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	__u8 scene;
	__u8 de;
	int ret;

	if (!msg) {
		WD_ERR("input digest msg is NULL!\n");
		return -WD_EINVAL;
	}

	ret = digest_len_check(msg, BD_TYPE2);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	/* config BD type */
	sqe.type_auth_cipher = BD_TYPE2;
	sqe.type_auth_cipher |= AUTH_HMAC_CALCULATE << AUTHTYPE_OFFSET;

	/* config scene */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = DATA_DST_ADDR_DISABLE << SEC_DE_OFFSET;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret) {
			WD_ERR("failed to get sgl!\n");
			return ret;
		}
	}

	sqe.sds_sa_type |= (__u8)(de | scene);
	sqe.type2.alen_ivllen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe.type2.mac_addr = (__u64)(uintptr_t)msg->out;

	ret = fill_digest_bd2_alg(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill digest bd alg!\n");
		return ret;
	}

	qm_fill_digest_long_bd(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump digest send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	sqe.type2.tag = msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("digest send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);
	}

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

int hisi_sec_digest_recv(handle_t ctx, struct wd_digest_msg *recv_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	parse_digest_bd2(&sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
			recv_msg->out);

	return 0;
}

static struct wd_digest_driver hisi_digest_driver = {
		.drv_name	= "hisi_sec2",
		.alg_name	= "digest",
		.drv_ctx_size	= sizeof(struct hisi_sec_ctx),
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
};

WD_DIGEST_SET_DRIVER(hisi_digest_driver);

static int fill_digest_bd3_alg(struct wd_digest_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	if (msg->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	sqe->auth_mac_key |= (msg->out_bytes / WORD_BYTES) <<
				SEC_MAC_OFFSET_V3;
	if (msg->mode == WD_DIGEST_NORMAL) {
		sqe->auth_mac_key |=
		(__u32)g_digest_a_alg[msg->alg] << SEC_AUTH_ALG_OFFSET_V3;
	} else if (msg->mode == WD_DIGEST_HMAC) {
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("Invalid digest key_bytes!\n");
			return -WD_EINVAL;
		}
		sqe->auth_mac_key |= (__u32)(msg->key_bytes /
			WORD_BYTES) << SEC_AKEY_OFFSET_V3;
		sqe->a_key_addr = (__u64)(uintptr_t)msg->key;
		sqe->auth_mac_key |=
		(__u32)g_hmac_a_alg[msg->alg] << SEC_AUTH_ALG_OFFSET_V3;
	} else {
		WD_ERR("Invalid digest mode!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void qm_fill_digest_long_bd3(struct wd_digest_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	struct wd_digest_tag *digest_tag = (void *)(uintptr_t)msg->usr_data;
	__u64 total_bits;

	if (msg->has_next && (msg->iv_bytes == 0)) {
		/* LONG BD FIRST */
		sqe->auth_mac_key |= AI_GEN_INNER << SEC_AI_GEN_OFFSET_V3;
		sqe->stream_scene.stream_auth_pad = AUTHPAD_NOPAD;
		msg->iv_bytes = msg->out_bytes;
	} else if (msg->has_next && (msg->iv_bytes != 0)) {
		/* LONG BD MIDDLE */
		sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
		sqe->stream_scene.stream_auth_pad = AUTHPAD_NOPAD;
		sqe->auth_ivin.a_ivin_addr = sqe->mac_addr;
		msg->iv_bytes = msg->out_bytes;
	} else if (!msg->has_next && (msg->iv_bytes != 0)) {
		/* LONG BD END */
		sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
		sqe->stream_scene.stream_auth_pad = AUTHPAD_PAD;
		sqe->auth_ivin.a_ivin_addr = sqe->mac_addr;
		total_bits = digest_tag->long_data_len * BYTE_BITS;
		sqe->stream_scene.long_a_data_len = total_bits;
		msg->iv_bytes = 0;
	} else {
		/* SHORT BD */
		msg->iv_bytes = 0;
	}
}

int hisi_sec_digest_send_v3(handle_t ctx, struct wd_digest_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	__u16 scene;
	__u16 de;
	int ret;

	if (!msg) {
		WD_ERR("input digest msg is NULL!\n");
		return -WD_EINVAL;
	}

	ret = digest_len_check(msg, BD_TYPE3);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	/* config BD type */
	sqe.bd_param = BD_TYPE3;
	sqe.auth_mac_key = AUTH_HMAC_CALCULATE;

	/* config scene */
	scene = SEC_STREAM_SCENE << SEC_SCENE_OFFSET_V3;
	de = DATA_DST_ADDR_DISABLE << SEC_DE_OFFSET_V3;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl_v3(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret) {
			WD_ERR("failed to get sgl!\n");
			return ret;
		}
	}

	sqe.bd_param |= (__u16)(de | scene);
	sqe.a_len_key = (__u32)msg->in_bytes;
	sqe.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe.mac_addr = (__u64)(uintptr_t)msg->out;

	ret = fill_digest_bd3_alg(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill digest bd alg!\n");
		return ret;
	}

	qm_fill_digest_long_bd3(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump digest send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	sqe.tag = (__u64)(uintptr_t)msg->tag;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("digest send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);
	}

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

static void parse_digest_bd3(struct hisi_sec_sqe3 *sqe,
				struct wd_digest_msg *recv_msg)
{
	__u16 done;

	done = sqe->done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("SEC BD3 %s fail! done=0x%x, etype=0x%x\n", "digest",
		done, sqe->error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->tag;

	recv_msg->data_fmt = hisi_sec_get_data_fmt_v3(sqe->bd_param);
	recv_msg->in = (__u8 *)(uintptr_t)sqe->data_src_addr;
	recv_msg->alg_type = WD_DIGEST;

#ifdef DEBUG
	WD_ERR("Dump digest recv sqe-->!\n");
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif
}

int hisi_sec_digest_recv_v3(handle_t ctx, struct wd_digest_msg *recv_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	parse_digest_bd3(&sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp,  recv_msg->alg_type, recv_msg->in,
				recv_msg->out);

	return 0;
}

static int aead_get_aes_key_len(struct wd_aead_msg *msg, __u8 *key_len)
{
	switch (msg->ckey_bytes) {
	case AES_KEYSIZE_128:
		*key_len = CKEY_LEN_128BIT;
		break;
	case AES_KEYSIZE_192:
		*key_len = CKEY_LEN_192BIT;
		break;
	case AES_KEYSIZE_256:
		*key_len = CKEY_LEN_256BIT;
		break;
	default:
		WD_ERR("failed to check AES key size!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_aead_bd2_alg(struct wd_aead_msg *msg,
	struct hisi_sec_sqe *sqe)
{
	__u8 c_key_len = 0;
	__u32 d_alg = 0;
	int ret = 0;

	switch (msg->calg) {
	case WD_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
		ret = aead_get_aes_key_len(msg, &c_key_len);
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	default:
		WD_ERR("failed to check aead calg type!\n");
		ret = -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WD_CIPHER_CCM ||
	    msg->cmode == WD_CIPHER_GCM)
		return ret;

	if (unlikely(msg->auth_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth_bytes!\n");
		return -WD_EINVAL;
	}
	sqe->type2.mac_key_alg = msg->auth_bytes / WORD_BYTES;

	if (unlikely(msg->akey_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth key bytes!\n");
		return -WD_EINVAL;
	}
	sqe->type2.mac_key_alg |= (__u32)(msg->akey_bytes /
		WORD_BYTES) << MAC_LEN_OFFSET;

	switch (msg->dalg) {
	case WD_DIGEST_SHA1:
		d_alg = A_ALG_HMAC_SHA1 << AUTH_ALG_OFFSET;
		break;
	case WD_DIGEST_SHA256:
		d_alg = A_ALG_HMAC_SHA256 << AUTH_ALG_OFFSET;
		break;
	case WD_DIGEST_SHA512:
		d_alg = A_ALG_HMAC_SHA512 << AUTH_ALG_OFFSET;
		break;
	default:
		WD_ERR("failed to check aead dalg type!\n");
		ret = -WD_EINVAL;
	}
	sqe->type2.mac_key_alg |= d_alg;

	return ret;
}

static int fill_aead_bd2_mode(struct wd_aead_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	__u16 c_mode;

	switch (msg->cmode) {
	case WD_CIPHER_CBC:
		c_mode = C_MODE_CBC;
		break;
	case WD_CIPHER_CCM:
		c_mode = C_MODE_CCM;
		sqe->type_auth_cipher &= SEC_AUTH_MASK;
		sqe->type2.alen_ivllen = msg->assoc_bytes;
		sqe->type2.icvw_kmode |= msg->auth_bytes;
		break;
	case WD_CIPHER_GCM:
		c_mode = C_MODE_GCM;
		sqe->type_auth_cipher &= SEC_AUTH_MASK;
		sqe->type2.alen_ivllen = msg->assoc_bytes;
		sqe->type2.icvw_kmode |= msg->auth_bytes;
		break;
	default:
		WD_ERR("failed to check aead cmode type!\n");
		return -WD_EINVAL;
	}
	sqe->type2.icvw_kmode |= (__u16)(c_mode) << SEC_CMODE_OFFSET;

	return 0;
}

static void set_aead_auth_iv(struct wd_aead_msg *msg)
{
#define IV_LAST_BYTE1		1
#define IV_LAST_BYTE2		2
#define IV_CTR_INIT		1
#define IV_CM_CAL_NUM		2
#define IV_CL_MASK		0x7
#define IV_FLAGS_OFFSET	0x6
#define IV_CM_OFFSET		0x3
#define IV_LAST_BYTE_MASK	0xFF
#define IV_BYTE_OFFSET		0x8

	__u32 data_size = msg->in_bytes;
	__u8 flags = 0x00;
	__u8 cl, cm;

	/* CCM need to cal a_iv, GCM same as c_iv */
	memcpy(msg->aiv, msg->iv, msg->iv_bytes);
	if (msg->cmode == WD_CIPHER_CCM) {
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
		msg->aiv[msg->iv_bytes - IV_LAST_BYTE1] =
			data_size & IV_LAST_BYTE_MASK;
		data_size >>= IV_BYTE_OFFSET;
		msg->aiv[msg->iv_bytes - IV_LAST_BYTE2] =
			data_size & IV_LAST_BYTE_MASK;
	}
}

static void fill_aead_mac_addr_pbuff(struct wd_aead_msg *msg, __u64 *mac_addr)
{
	__u64 addr = 0;

	if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST)
		addr = (__u64)(uintptr_t)msg->in + msg->in_bytes + msg->assoc_bytes;

	/* AEAD output MAC addr use out addr */
	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST)
		addr = (__u64)(uintptr_t)msg->out + msg->out_bytes - msg->auth_bytes;

	*mac_addr = addr;
}

static void fill_aead_mac_addr_sgl(struct wd_aead_msg *msg, __u64 *mac_addr)
{
	msg->mac = calloc(1, msg->auth_bytes);
	if (!msg->mac) {
		WD_ERR("failed to alloc mac memory!\n");
		return;
	}

	if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST)
		hisi_qm_sgl_copy(msg->mac, msg->in,
				msg->in_bytes + msg->assoc_bytes,
				msg->auth_bytes, COPY_SGL_TO_PBUFF);

	*mac_addr = (__u64)(uintptr_t)msg->mac;
}

static void fill_aead_bd2_addr(struct wd_aead_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	sqe->type2.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->type2.data_dst_addr = (__u64)(uintptr_t)msg->out;

	/* AEAD input MAC addr use in addr */
	if (msg->data_fmt == WD_FLAT_BUF)
		fill_aead_mac_addr_pbuff(msg, &sqe->type2.mac_addr);
	else
		fill_aead_mac_addr_sgl(msg, &sqe->type2.mac_addr);

	sqe->type2.c_key_addr = (__u64)(uintptr_t)msg->ckey;
	sqe->type2.a_key_addr = (__u64)(uintptr_t)msg->akey;
	sqe->type2.c_ivin_addr = (__u64)(uintptr_t)msg->iv;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	sqe->type2.a_ivin_addr = (__u64)(uintptr_t)msg->aiv;
}

static int aead_len_check(struct wd_aead_msg *msg)
{
	if (unlikely(msg->in_bytes + msg->assoc_bytes > MAX_INPUT_DATA_LEN)) {
		WD_ERR("aead input data length is too long!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->cmode == WD_CIPHER_CCM &&
	    msg->assoc_bytes > MAX_CCM_AAD_LEN)) {
		WD_ERR("failed to check ccm aad len, input is too long!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_aead_bd2(struct wd_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u8 scene, cipher, de;
	int ret;

	/* config BD type */
	sqe->type_auth_cipher = BD_TYPE2;
	/* config scene */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET;

	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
		sqe->sds_sa_type = WD_CIPHER_THEN_DIGEST;
		sqe->type_auth_cipher |= AUTH_HMAC_CALCULATE <<
					 SEC_AUTH_OFFSET;
	} else if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;
		sqe->sds_sa_type = WD_DIGEST_THEN_CIPHER;
		sqe->type_auth_cipher |= AUTH_MAC_VERIFY <<
					 SEC_AUTH_OFFSET;
	} else {
		WD_ERR("failed to check aead op type!\n");
		return -WD_EINVAL;
	}
	sqe->sds_sa_type |= (__u8)(de | scene);
	sqe->type_auth_cipher |= cipher;

	sqe->type2.clen_ivhlen = msg->in_bytes;
	sqe->type2.cipher_src_offset = msg->assoc_bytes;
	sqe->type2.alen_ivllen = msg->in_bytes + msg->assoc_bytes;

	ret = fill_aead_bd2_alg(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd alg!\n");
		return ret;
	}

	ret = fill_aead_bd2_mode(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd mode!\n");
		return ret;
	}

	return 0;
}

int hisi_sec_aead_send(handle_t ctx, struct wd_aead_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	if (unlikely(!msg)) {
		WD_ERR("failed to check input aead msg!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->cmode != WD_CIPHER_CBC && msg->in_bytes == 0)) {
		WD_ERR("ccm or gcm not supports 0 packet size at hw_v2!\n");
		return -WD_EINVAL;
	}

	ret = aead_len_check(msg);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	ret = fill_aead_bd2(msg, &sqe);
	if (unlikely(ret))
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl(h_qp, &msg->in, &msg->out, &sqe, msg->alg_type);
		if (ret) {
			WD_ERR("failed to get sgl!\n");
			return ret;
		}
	}

	fill_aead_bd2_addr(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump aead send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	sqe.type2.tag = (__u16)msg->tag;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("aead send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);
	}

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

static void parse_aead_bd2(struct hisi_sec_sqe *sqe,
	struct wd_aead_msg *recv_msg)
{
	__u16 done, icv;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	icv = (sqe->type2.done_flag & SEC_ICV_MASK) >> 1;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type ||
	    icv == SEC_HW_ICV_ERR) {
		WD_ERR("SEC BD aead fail! done=0x%x, etype=0x%x, icv=0x%x\n",
			done, sqe->type2.error_type, icv);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->type2.tag;

	recv_msg->data_fmt = hisi_sec_get_data_fmt_v2(sqe->sds_sa_type);
	recv_msg->in = (__u8 *)(uintptr_t)sqe->type2.data_src_addr;
	recv_msg->out = (__u8 *)(uintptr_t)sqe->type2.data_dst_addr;
	recv_msg->alg_type = WD_AEAD;
	recv_msg->mac = (__u8 *)(uintptr_t)sqe->type2.mac_addr;
	recv_msg->auth_bytes = (sqe->type2.mac_key_alg &
			       SEC_MAC_LEN_MASK) * WORD_BYTES;
	if (recv_msg->auth_bytes == 0)
		recv_msg->auth_bytes = sqe->type2.icvw_kmode &
				       SEC_AUTH_LEN_MASK;
	recv_msg->out_bytes = sqe->type2.clen_ivhlen + recv_msg->auth_bytes +
			      sqe->type2.cipher_src_offset;

#ifdef DEBUG
	WD_ERR("Dump aead recv sqe-->!\n");
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif
}

int hisi_sec_aead_recv(handle_t ctx, struct wd_aead_msg *recv_msg)
{
	struct hisi_sec_sqe sqe;
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	parse_aead_bd2(&sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF) {
		if (sqe.type_auth_cipher & (SEC_CIPHER_ENC << SEC_CIPHER_OFFSET))
			hisi_qm_sgl_copy(recv_msg->mac, recv_msg->out,
					recv_msg->out_bytes - recv_msg->auth_bytes,
					recv_msg->auth_bytes, COPY_PBUFF_TO_SGL);

		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
				recv_msg->out);
	}

	return 0;
}

static struct wd_aead_driver hisi_aead_driver = {
	.drv_name	= "hisi_sec2",
	.alg_name	= "aead",
	.drv_ctx_size	= sizeof(struct hisi_sec_ctx),
	.init		= hisi_sec_init,
	.exit		= hisi_sec_exit,
};

WD_AEAD_SET_DRIVER(hisi_aead_driver);

static int aead_bd3_msg_check(struct wd_aead_msg *msg)
{
	if (unlikely(!msg->in_bytes)) {
		WD_ERR("failed to check aead in_bytes 0 length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->auth_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth_bytes!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->akey_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth key bytes!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_aead_bd3_alg(struct wd_aead_msg *msg,
	struct hisi_sec_sqe3 *sqe)
{
	__u8 c_key_len = 0;
	__u32 d_alg = 0;
	int ret = 0;

	switch (msg->calg) {
	case WD_CIPHER_SM4:
		sqe->c_mode_alg |= C_ALG_SM4 << SEC_CALG_OFFSET_V3;
		sqe->c_icv_key |= CKEY_LEN_SM4 << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_AES:
		sqe->c_mode_alg |= C_ALG_AES << SEC_CALG_OFFSET_V3;
		ret = aead_get_aes_key_len(msg, &c_key_len);
		sqe->c_icv_key |= (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead calg type!\n");
		ret = -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WD_CIPHER_CCM || msg->cmode == WD_CIPHER_GCM)
		return ret;

	ret = aead_bd3_msg_check(msg);
	if (ret)
		return ret;

	sqe->auth_mac_key |= (msg->auth_bytes /
		WORD_BYTES) << SEC_MAC_OFFSET_V3;

	sqe->auth_mac_key |= (msg->akey_bytes /
		WORD_BYTES) << SEC_AKEY_OFFSET_V3;

	switch (msg->dalg) {
	case WD_DIGEST_SHA1:
		d_alg = A_ALG_HMAC_SHA1 << SEC_AUTH_ALG_OFFSET_V3;
		break;
	case WD_DIGEST_SHA256:
		d_alg = A_ALG_HMAC_SHA256 << SEC_AUTH_ALG_OFFSET_V3;
		break;
	case WD_DIGEST_SHA512:
		d_alg = A_ALG_HMAC_SHA512 << SEC_AUTH_ALG_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead dalg type!\n");
		ret = -WD_EINVAL;
	}
	sqe->auth_mac_key |= d_alg;

	return ret;
}

static int fill_aead_bd3_mode(struct wd_aead_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	switch (msg->cmode) {
	case WD_CIPHER_CBC:
		sqe->c_mode_alg |= C_MODE_CBC;
		break;
	case WD_CIPHER_CCM:
		sqe->c_mode_alg |= C_MODE_CCM;
		sqe->auth_mac_key &= SEC_AUTH_MASK_V3;
		sqe->a_len_key = msg->assoc_bytes;
		sqe->c_icv_key |= msg->auth_bytes << SEC_MAC_OFFSET_V3;
		break;
	case WD_CIPHER_GCM:
		sqe->c_mode_alg |= C_MODE_GCM;
		sqe->auth_mac_key &= SEC_AUTH_MASK_V3;
		sqe->a_len_key = msg->assoc_bytes;
		sqe->c_icv_key |= msg->auth_bytes << SEC_MAC_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead cmode type!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static void fill_aead_bd3_addr(struct wd_aead_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	__u64 mac_addr;

	sqe->data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->data_dst_addr = (__u64)(uintptr_t)msg->out;

	/* AEAD input MAC addr use in and out addr */
	if (msg->data_fmt == WD_FLAT_BUF)
		fill_aead_mac_addr_pbuff(msg, &mac_addr);
	else
		fill_aead_mac_addr_sgl(msg, &mac_addr);

	sqe->mac_addr = mac_addr;
	sqe->c_key_addr = (__u64)(uintptr_t)msg->ckey;
	sqe->a_key_addr = (__u64)(uintptr_t)msg->akey;
	sqe->no_scene.c_ivin_addr = (__u64)(uintptr_t)msg->iv;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	sqe->auth_ivin.a_ivin_addr = (__u64)(uintptr_t)msg->aiv;
}


static int fill_aead_bd3(struct wd_aead_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	__u16 scene, de;
	int ret;

	/* config BD type */
	sqe->bd_param = BD_TYPE3;
	/* config scene */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET_V3;

	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		sqe->c_icv_key = SEC_CIPHER_ENC;
		sqe->auth_mac_key = AUTH_HMAC_CALCULATE;
		sqe->huk_iv_seq = WD_CIPHER_THEN_DIGEST << SEC_SEQ_OFFSET_V3;
	} else if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
		sqe->c_icv_key = SEC_CIPHER_DEC;
		sqe->auth_mac_key = AUTH_MAC_VERIFY;
		sqe->huk_iv_seq = WD_DIGEST_THEN_CIPHER << SEC_SEQ_OFFSET_V3;
	} else {
		WD_ERR("failed to check aead op type!\n");
		return -WD_EINVAL;
	}
	sqe->bd_param |= (__u16)(de | scene);

	sqe->c_len_ivin = msg->in_bytes;
	sqe->cipher_src_offset = msg->assoc_bytes;
	sqe->a_len_key = msg->in_bytes + msg->assoc_bytes;

	ret = fill_aead_bd3_alg(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd alg!\n");
		return ret;
	}

	ret = fill_aead_bd3_mode(msg, sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd mode!\n");
		return ret;
	}

	return 0;
}


int hisi_sec_aead_send_v3(handle_t ctx, struct wd_aead_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("failed to check input aead msg!\n");
		return -WD_EINVAL;
	}

	ret = aead_len_check(msg);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	ret = fill_aead_bd3(msg, &sqe);
	if (unlikely(ret))
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl_v3(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret) {
			WD_ERR("failed to get sgl!\n");
			return ret;
		}
	}

	fill_aead_bd3_addr(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump aead send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	sqe.tag = msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("aead send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);
	}

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

static void parse_aead_bd3(struct hisi_sec_sqe3 *sqe,
	struct wd_aead_msg *recv_msg)
{
	__u16 done, icv;

	done = sqe->done_flag & SEC_DONE_MASK;
	icv = (sqe->done_flag & SEC_ICV_MASK) >> 1;
	if (done != SEC_HW_TASK_DONE || sqe->error_type ||
	    icv == SEC_HW_ICV_ERR) {
		WD_ERR("SEC BD3 aead fail! done=0x%x, etype=0x%x, icv=0x%x\n",
			done, sqe->error_type, icv);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->tag;

	recv_msg->data_fmt = hisi_sec_get_data_fmt_v3(sqe->bd_param);
	recv_msg->in = (__u8 *)(uintptr_t)sqe->data_src_addr;
	recv_msg->out = (__u8 *)(uintptr_t)sqe->data_dst_addr;
	recv_msg->alg_type = WD_AEAD;
	recv_msg->mac = (__u8 *)(uintptr_t)sqe->mac_addr;
	recv_msg->auth_bytes = ((sqe->auth_mac_key >> SEC_MAC_OFFSET_V3) &
			       SEC_MAC_LEN_MASK) * WORD_BYTES;
	if (recv_msg->auth_bytes == 0)
		recv_msg->auth_bytes = (sqe->c_icv_key >> SEC_MAC_OFFSET_V3) &
				       SEC_MAC_LEN_MASK;
	recv_msg->out_bytes = sqe->c_len_ivin + recv_msg->auth_bytes +
			      sqe->cipher_src_offset;

#ifdef DEBUG
	WD_ERR("Dump aead recv sqe-->!\n");
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif
}

int hisi_sec_aead_recv_v3(handle_t ctx, struct wd_aead_msg *recv_msg)
{
	struct hisi_sec_sqe3 sqe;
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	parse_aead_bd3(&sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF) {
		if (sqe.c_icv_key & SEC_CIPHER_ENC)
			hisi_qm_sgl_copy(recv_msg->mac, recv_msg->out,
				recv_msg->out_bytes - recv_msg->auth_bytes,
				recv_msg->auth_bytes, COPY_PBUFF_TO_SGL);

		hisi_sec_put_sgl(h_qp, recv_msg->alg_type,
			recv_msg->in, recv_msg->out);
	}

	return 0;
}

static void hisi_sec_driver_adapter(struct hisi_qp *qp)
{
	struct hisi_qm_queue_info q_info = qp->q_info;

	if (q_info.hw_type == HISI_QM_API_VER2_BASE) {
		WD_ERR("hisi sec init Kunpeng920!\n");
		hisi_cipher_driver.cipher_send = hisi_sec_cipher_send;
		hisi_cipher_driver.cipher_recv = hisi_sec_cipher_recv;

		hisi_digest_driver.digest_send = hisi_sec_digest_send;
		hisi_digest_driver.digest_recv = hisi_sec_digest_recv;

		hisi_aead_driver.aead_send = hisi_sec_aead_send;
		hisi_aead_driver.aead_recv = hisi_sec_aead_recv;
	} else {
		WD_ERR("hisi sec init Kunpeng930!\n");
		hisi_cipher_driver.cipher_send = hisi_sec_cipher_send_v3;
		hisi_cipher_driver.cipher_recv = hisi_sec_cipher_recv_v3;

		hisi_digest_driver.digest_send = hisi_sec_digest_send_v3;
		hisi_digest_driver.digest_recv = hisi_sec_digest_recv_v3;

		hisi_aead_driver.aead_send = hisi_sec_aead_send_v3;
		hisi_aead_driver.aead_recv = hisi_sec_aead_recv_v3;
	}
}

int hisi_sec_init(struct wd_ctx_config_internal *config, void *priv)
{
	struct hisi_sec_ctx *sec_ctx = priv;
	struct hisi_qm_priv qm_priv;
	handle_t h_qp = 0;
	handle_t h_ctx;
	int i, j;

	qm_priv.sqe_size = sizeof(struct hisi_sec_sqe);
	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.op_type = config->ctxs[i].op_type;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		qm_priv.idx = i;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp)
			goto out;
	}
	memcpy(&sec_ctx->config, config, sizeof(struct wd_ctx_config_internal));
	hisi_sec_driver_adapter((struct hisi_qp *)h_qp);

	return 0;

out:
	for (j = i - 1; j >= 0; j--) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}
	return -WD_EINVAL;
}

void hisi_sec_exit(void *priv)
{
	if (!priv) {
		WD_ERR("hisi sec exit input parameter is err!\n");
		return;
	}

	struct hisi_sec_ctx *sec_ctx = priv;
	struct wd_ctx_config_internal *config = &sec_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
}
