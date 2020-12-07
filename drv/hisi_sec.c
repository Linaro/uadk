/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
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
#define SEC_HW_TASK_DONE	0x1
#define SEC_DONE_MASK		0x0001
#define SEC_FLAG_MASK		0x780
#define SEC_TYPE_MASK		0x0f

#define SEC_IPSEC_SCENE		0x1
#define SEC_SCENE_OFFSET	  3
#define SEC_DE_OFFSET		  1
#define SEC_AUTH_OFFSET  	  6
#define SEC_CMODE_OFFSET	  12
#define SEC_CKEY_OFFSET		  9
#define SEC_CIPHER_OFFSET	  4
#define XTS_MODE_KEY_DIVISOR	  2

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
	 * scece: 3~6 bits;
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
	__le16 check_sum_i;
	__u8 tls_pad_len_i;
	__u8 rsvd0;
};

struct bd3_tls_type_back {
	__u8 tls_1p3_type_back;
	__u8 rsvd0;
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
	 * updata_key: 25 bits
	 * reserved: 26~31 bits
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
	__le32 mac_i;
	union {
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
		if (msg->iv_bytes >= AES_BLOCK_SIZE)
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
		WD_ERR("Invalid 3des key size!\n");
		return -EINVAL;
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
		WD_ERR("Invalid AES key size!\n");
		return -EINVAL;
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
		WD_ERR("Invalid cipher type!\n");
		return -EINVAL;
	}

	return ret;
}

static int fill_cipher_bd2_mode(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u16 c_mode;

	switch (msg->mode) {
	case WD_CIPHER_ECB:
		c_mode = C_MODE_ECB;
		break;
	case WD_CIPHER_CBC:
		c_mode = C_MODE_CBC;
		break;
	case WD_CIPHER_XTS:
		c_mode = C_MODE_XTS;
		break;
	default:
		WD_ERR("Invalid cipher mode type!\n");
		return -EINVAL;
	}
	sqe->type2.icvw_kmode |= (__u16)(c_mode) << SEC_CMODE_OFFSET;

	return 0;
}

static void parse_cipher_bd2(struct hisi_sec_sqe *sqe, struct wd_cipher_msg *recv_msg)
{
	__u16 done;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD %s fail! done=0x%x, etype=0x%x\n", "cipher",
		done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	update_iv(recv_msg);
}

static int cipher_len_check(struct wd_cipher_msg *msg)
{
	if (msg->in_bytes > MAX_INPUT_DATA_LEN) {
		WD_ERR("input cipher len is too large!\n");
		return -EINVAL;
	}

	if (msg->mode == WD_CIPHER_XTS) {
		if (msg->in_bytes < AES_BLOCK_SIZE) {
			WD_ERR("input cipher length is too small!\n");
			return -EINVAL;
		}
	}

	if (msg->alg == WD_CIPHER_3DES || msg->alg == WD_CIPHER_DES) {
		if (msg->in_bytes & (DES3_BLOCK_SIZE - 1)) {
			WD_ERR("input 3DES or DES cipher parameter is error!\n");
			return -EINVAL;
		}
		return 0;
	} else if (msg->alg == WD_CIPHER_AES || msg->alg == WD_CIPHER_SM4) {
		if (msg->in_bytes & (AES_BLOCK_SIZE - 1)) {
			WD_ERR("input AES or SM4 cipher parameter is error!\n");
			return -EINVAL;
		}
		return 0;
	}

	return 0;
}

static int cipher_iv_check(struct wd_cipher_msg *msg)
{
	if (msg->alg == WD_CIPHER_AES || msg->alg == WD_CIPHER_SM4) {
		if (msg->iv_bytes < AES_BLOCK_SIZE) {
			WD_ERR("AES or SM4 input iv bytes is err!\n");
			return -EINVAL;
		}
	} else if (msg->alg == WD_CIPHER_3DES || msg->alg == WD_CIPHER_DES) {
		if (msg->iv_bytes < DES3_BLOCK_SIZE) {
			WD_ERR("3DES or DES input iv bytes is err!\n");
			return -EINVAL;
		}
	}

	return 0;
}

int hisi_sec_cipher_send(handle_t ctx, struct wd_cipher_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u8 scene, cipher, de;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("input cipher msg is NULL!\n");
		return -EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	/* config BD type */
	sqe.type_auth_cipher = BD_TYPE2;
	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET;
	sqe.sds_sa_type = (__u8)(de | scene);

	if (msg->op_type == WD_CIPHER_ENCRYPTION)
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
	else
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;

	sqe.type_auth_cipher |= cipher;

	ret = cipher_len_check(msg);
	if (ret)
		return ret;
	if (msg->mode == WD_CIPHER_CBC || msg->mode == WD_CIPHER_XTS) {
		ret = cipher_iv_check(msg);
		if (ret)
			return ret;
	}

	ret = fill_cipher_bd2_alg(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill bd alg!\n");
		return ret;
	}

	ret = fill_cipher_bd2_mode(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill bd mode!\n");
		return ret;
	}

	sqe.type2.clen_ivhlen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)msg->in;
	sqe.type2.data_dst_addr = (__u64)msg->out;
	sqe.type2.c_ivin_addr = (__u64)msg->iv;
	sqe.type2.c_key_addr = (__u64)msg->key;
	sqe.type2.tag = (__u16)msg->tag;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		return ret;
	}

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

	return 0;
}

static struct wd_cipher_driver hisi_cipher_driver = {
		.drv_name	= "hisi_sec2",
		.alg_name	= "cipher",
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
		sqe->c_mode_alg = C_ALG_SM4 << SEC_CALG_OFFSET_V3;
		sqe->c_icv_key = CKEY_LEN_SM4 << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_AES:
		sqe->c_mode_alg = C_ALG_AES << SEC_CALG_OFFSET_V3;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->c_icv_key = (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_DES:
		sqe->c_mode_alg = C_ALG_DES << SEC_CALG_OFFSET_V3;
		sqe->c_icv_key = CKEY_LEN_DES << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_3DES:
		sqe->c_mode_alg = C_ALG_3DES;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->c_icv_key = (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	default:
		WD_ERR("Invalid cipher type!\n");
		return -EINVAL;
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
		break;
	case WD_CIPHER_XTS:
		c_mode = C_MODE_XTS;
		break;
	case WD_CIPHER_CFB:
		c_mode = C_MODE_CFB;
		break;
	default:
		WD_ERR("Invalid cipher mode type!\n");
		return -EINVAL;
	}
	sqe->c_mode_alg |= (__u16)c_mode;

	return 0;
}

int hisi_sec_cipher_send_v3(handle_t ctx, struct wd_cipher_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe3 sqe;
	__u16 scene, de;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("input cipher msg is NULL!\n");
		return -EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	/* config BD type */
	sqe.bd_param = BD_TYPE3;
	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET_V3;
	sqe.bd_param |= (__u16)(de | scene);

	if (msg->op_type == WD_CIPHER_ENCRYPTION)
		sqe.c_icv_key = SEC_CIPHER_ENC;
	else
		sqe.c_icv_key = SEC_CIPHER_DEC;

	ret = cipher_len_check(msg);
	if (ret)
		return ret;
	if (msg->mode == WD_CIPHER_CBC || msg->mode == WD_CIPHER_XTS) {
		ret = cipher_iv_check(msg);
		if (ret)
			return ret;
	}

	ret = fill_cipher_bd3_alg(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill bd alg!\n");
		return ret;
	}

	ret = fill_cipher_bd3_mode(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill bd mode!\n");
		return ret;
	}

	sqe.c_len_ivin |= (__u32)msg->in_bytes;
	sqe.data_src_addr = (__u64)msg->in;
	sqe.data_dst_addr = (__u64)msg->out;
	sqe.no_scene.c_ivin_addr = (__u64)msg->iv;
	sqe.c_key_addr = (__u64)msg->key;
	sqe.tag = (__u64)msg->tag;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

static void parse_cipher_bd3(struct hisi_sec_sqe3 *sqe, struct wd_cipher_msg *recv_msg)
{
	__u16 done;

	done = sqe->done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("SEC BD3 %s fail! done=0x%x, etype=0x%x\n", "cipher",
		done, sqe->error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	update_iv(recv_msg);
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

	return 0;
}

static int fill_digest_bd2_alg(struct wd_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	if (msg->alg < WD_DIGEST_SM3 || msg->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	if (msg->out_bytes & WORD_ALIGNMENT_MASK) {
		WD_ERR("Invalid digest out_bytes!\n");
		return -WD_EINVAL;
	}

	sqe->type2.mac_key_alg = msg->out_bytes / WORD_BYTES;
	if (msg->mode == WD_DIGEST_NORMAL)
		sqe->type2.mac_key_alg |=
		g_digest_a_alg[msg->alg] << AUTH_ALG_OFFSET;
	else if (msg->mode == WD_DIGEST_HMAC) {
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("Invalid digest key_bytes!\n");
			return -WD_EINVAL;
		}
		sqe->type2.mac_key_alg |= (__u32)(msg->key_bytes /
			WORD_BYTES) << MAC_LEN_OFFSET;
		sqe->type2.a_key_addr = (__u64)msg->key;

		sqe->type2.mac_key_alg |=
		(__u32)(g_hmac_a_alg[msg->alg] << AUTH_ALG_OFFSET);
	} else {
		WD_ERR("Invalid digest mode!\n");
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
		/* LOGN BD FIRST */
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
		/* LOGN BD END */
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

#ifdef DEBUG
	WD_ERR("Dump digest recv sqe-->!\n");
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif
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
		return -EINVAL;
	}
	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	/* config BD type */
	sqe.type_auth_cipher = BD_TYPE2;
	sqe.type_auth_cipher |= AUTH_HMAC_CALCULATE << AUTHTYPE_OFFSET;

	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = DATA_DST_ADDR_DISABLE << SEC_DE_OFFSET;

	if (msg->in_bytes == 0 ||
		msg->in_bytes > MAX_INPUT_DATA_LEN) {
		WD_ERR("failed to check input data length!\n");
		return -EINVAL;
	}
	sqe.sds_sa_type = (__u8)(de | scene);
	sqe.type2.alen_ivllen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)msg->in;
	sqe.type2.mac_addr = (__u64)msg->out;

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
		WD_ERR("hisi qm send is err(%d)!\n", ret);
		return ret;
	}

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

	return 0;
}

static struct wd_digest_driver hisi_digest_driver = {
		.drv_name	= "hisi_sec2",
		.alg_name	= "digest",
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
};

WD_DIGEST_SET_DRIVER(hisi_digest_driver);

static int fill_digest_bd3_alg(struct wd_digest_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	if (msg->alg < WD_DIGEST_SM3 || msg->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("Invalid digest type!\n");
		return -WD_EINVAL;
	}

	if (msg->out_bytes & WORD_ALIGNMENT_MASK) {
		WD_ERR("Invalid digest out_bytes!\n");
		return -WD_EINVAL;
	}

	sqe->auth_mac_key = (msg->out_bytes / WORD_BYTES) <<
				SEC_MAC_OFFSET_V3;
	if (msg->mode == WD_DIGEST_NORMAL) {
		sqe->auth_mac_key |=
		(__u32)(g_digest_a_alg[msg->alg] << SEC_AUTH_ALG_OFFSET_V3);
	} else if (msg->mode == WD_DIGEST_HMAC) {
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("Invalid digest key_bytes!\n");
			return -WD_EINVAL;
		}
		sqe->auth_mac_key |= (__u32)(msg->key_bytes /
			WORD_BYTES) << SEC_MAC_OFFSET_V3;
		sqe->a_key_addr = (__u64)msg->key;
		sqe->auth_mac_key |=
		(__u32)(g_hmac_a_alg[msg->alg] << SEC_AUTH_ALG_OFFSET_V3);
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
		/* LOGN BD FIRST */
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
		/* LOGN BD END */
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
		return -EINVAL;
	}
	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	/* config BD type */
	sqe.bd_param = BD_TYPE3;
	sqe.auth_mac_key = AUTH_HMAC_CALCULATE;

	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	de = DATA_DST_ADDR_DISABLE << SEC_DE_OFFSET_V3;

	if (msg->in_bytes == 0 ||
		msg->in_bytes > MAX_INPUT_DATA_LEN) {
		WD_ERR("failed to check input data length!\n");
		return -EINVAL;
	}
	sqe.bd_param |= (__u16)(de | scene);
	sqe.c_len_ivin |= (__u32)msg->in_bytes;
	sqe.data_src_addr = (__u64)msg->in;
	sqe.mac_addr = (__u64)msg->out;

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

	sqe.tag = (__u64)msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		WD_ERR("hisi qm send is err(%d)!\n", ret);
		return ret;
	}

	return ret;
}

static void parse_digest_bd3(struct hisi_sec_sqe3 *sqe, struct wd_digest_msg *recv_msg)
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
		return -EINVAL;
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
	case WD_CIPHER_SM4:
		sqe->type2.c_alg = C_ALG_SM4;
		sqe->type2.icvw_kmode = CKEY_LEN_SM4 << SEC_CKEY_OFFSET;
		break;
	case WD_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
		ret = aead_get_aes_key_len(msg, &c_key_len);
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	default:
		WD_ERR("failed to check aead calg type!\n");
		ret = -EINVAL;
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
		sqe->type_auth_cipher &= ~(AUTH_HMAC_CALCULATE <<
			SEC_AUTH_OFFSET);
		sqe->type2.alen_ivllen = msg->assoc_bytes;
		sqe->type2.icvw_kmode |= msg->auth_bytes;
		break;
	case WD_CIPHER_GCM:
		c_mode = C_MODE_GCM;
		sqe->type_auth_cipher &= ~(AUTH_HMAC_CALCULATE <<
			SEC_AUTH_OFFSET);
		sqe->type2.alen_ivllen = msg->assoc_bytes;
		sqe->type2.icvw_kmode |= msg->auth_bytes;
		break;
	default:
		WD_ERR("failed to check aead cmode type!\n");
		return -EINVAL;
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
#define IV_LAST_BYTE2_MASK	0xFF00
#define IV_LAST_BYTE1_MASK	0xFF

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
		msg->aiv[msg->iv_bytes - IV_LAST_BYTE2] =
			msg->in_bytes & IV_LAST_BYTE2_MASK;
		msg->aiv[msg->iv_bytes - IV_LAST_BYTE1] =
			msg->in_bytes & IV_LAST_BYTE1_MASK;
	}
}

static void fill_aead_bd2_addr(struct wd_aead_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	__u64 addr;

	sqe->type2.data_src_addr = (__u64)msg->in;
	sqe->type2.data_dst_addr = (__u64)msg->out;

	/* AEAD input MAC addr use in addr */
	if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
	    addr = (__u64)msg->in + msg->in_bytes + msg->assoc_bytes;
		sqe->type2.mac_addr = addr;
	}

	/* AEAD output MAC addr use out addr */
	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
	    addr = (__u64)msg->out + msg->out_bytes - msg->auth_bytes;
		sqe->type2.mac_addr = addr;
	}

	sqe->type2.c_key_addr = (__u64)msg->ckey;
	sqe->type2.a_key_addr = (__u64)msg->akey;
	sqe->type2.c_ivin_addr = (__u64)msg->iv;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	sqe->type2.a_ivin_addr = (__u64)msg->aiv;
}

int hisi_sec_aead_send(handle_t ctx, struct wd_aead_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u8 scene, cipher, de, auth;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("failed to check input aead msg!\n");
		return -EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	/* config BD type */
	sqe.type_auth_cipher = BD_TYPE2;
	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET;
	auth = AUTH_HMAC_CALCULATE << SEC_AUTH_OFFSET;
	sqe.type_auth_cipher |= auth;

	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
		sqe.sds_sa_type = WD_CIPHER_THEN_DIGEST;
	} else if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;
		sqe.sds_sa_type = WD_DIGEST_THEN_CIPHER;
	} else {
		WD_ERR("failed to check aead op type!\n");
		return -EINVAL;
	}
	sqe.sds_sa_type |= (__u8)(de | scene);
	sqe.type_auth_cipher |= cipher;

	if (msg->in_bytes == 0 ||
		msg->in_bytes > MAX_INPUT_DATA_LEN) {
		WD_ERR("failed to check aead input data length!\n");
		return -EINVAL;
	}
	sqe.type2.clen_ivhlen = msg->in_bytes;
	sqe.type2.cipher_src_offset = msg->assoc_bytes;
	sqe.type2.alen_ivllen = msg->in_bytes + msg->assoc_bytes;

	ret = fill_aead_bd2_alg(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd alg!\n");
		return ret;
	}

	ret = fill_aead_bd2_mode(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd mode!\n");
		return ret;
	}

	fill_aead_bd2_addr(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump aead send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	sqe.type2.tag = (__u16)msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		WD_ERR("hisi qm send is err(%d)!\n", ret);
		return ret;
	}

	return ret;
}

static void parse_aead_bd2(struct hisi_sec_sqe *sqe,
	struct wd_aead_msg *recv_msg)
{
	__u16 done;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD %s fail! done=0x%x, etype=0x%x\n", "aead",
			done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->aiv = (__u8 *)(uintptr_t)sqe->type2.a_ivin_addr;
	recv_msg->tag = sqe->type2.tag;

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

	return 0;
}

static struct wd_aead_driver hisi_aead_driver = {
	.drv_name	= "hisi_sec2",
	.alg_name	= "aead",
	.init		= hisi_sec_init,
	.exit		= hisi_sec_exit,
};

WD_AEAD_SET_DRIVER(hisi_aead_driver);

static int fill_aead_bd3_alg(struct wd_aead_msg *msg,
	struct hisi_sec_sqe3 *sqe)
{
	__u8 c_key_len = 0;
	__u32 d_alg = 0;
	int ret = 0;

	switch (msg->calg) {
	case WD_CIPHER_SM4:
		sqe->c_mode_alg = C_ALG_SM4 << SEC_CALG_OFFSET_V3;
		sqe->c_icv_key = CKEY_LEN_SM4 << SEC_CKEY_OFFSET_V3;
		break;
	case WD_CIPHER_AES:
		sqe->c_mode_alg = C_ALG_AES << SEC_CALG_OFFSET_V3;
		ret = aead_get_aes_key_len(msg, &c_key_len);
		sqe->c_icv_key = (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead calg type!\n");
		ret = -EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WD_CIPHER_CCM ||
	    msg->cmode == WD_CIPHER_GCM)
		return ret;

	if (unlikely(msg->auth_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth_bytes!\n");
		return -WD_EINVAL;
	}
	sqe->auth_mac_key |= (msg->auth_bytes /
		WORD_BYTES) << SEC_MAC_OFFSET_V3;

	if (unlikely(msg->akey_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth key bytes!\n");
		return -WD_EINVAL;
	}
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
		sqe->c_mode_alg = C_MODE_CBC;
		break;
	case WD_CIPHER_CCM:
		sqe->c_mode_alg = C_MODE_CCM;
		sqe->auth_mac_key &= ~(AUTH_HMAC_CALCULATE);
		sqe->a_len_key = msg->assoc_bytes;
		sqe->c_icv_key |= msg->auth_bytes << SEC_MAC_OFFSET_V3;
		break;
	case WD_CIPHER_GCM:
		sqe->c_mode_alg = C_MODE_GCM;
		sqe->auth_mac_key &= ~(AUTH_HMAC_CALCULATE);
		sqe->a_len_key = msg->assoc_bytes;
		sqe->c_icv_key |= msg->auth_bytes << SEC_MAC_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead cmode type!\n");
		return -EINVAL;
	}

	return 0;
}

static void fill_aead_bd3_addr(struct wd_aead_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	__u64 addr;

	sqe->data_src_addr = (__u64)msg->in;
	sqe->data_dst_addr = (__u64)msg->out;

	/* AEAD input MAC addr use in addr */
	if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
	    addr = (__u64)msg->in + msg->in_bytes + msg->assoc_bytes;
		sqe->mac_addr = addr;
	}

	/* AEAD output MAC addr use out addr */
	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
	    addr = (__u64)msg->out + msg->out_bytes - msg->auth_bytes;
		sqe->mac_addr = addr;
	}

	sqe->c_key_addr = (__u64)msg->ckey;
	sqe->a_key_addr = (__u64)msg->akey;
	sqe->no_scene.c_ivin_addr = (__u64)msg->iv;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	sqe->auth_ivin.a_ivin_addr = (__u64)msg->aiv;
}

int hisi_sec_aead_send_v3(handle_t ctx, struct wd_aead_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe3 sqe;
	__u16 scene, de;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("failed to check input aead msg!\n");
		return -EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	/* config BD type */
	sqe.bd_param = BD_TYPE3;
	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET_V3;
	sqe.auth_mac_key = AUTH_HMAC_CALCULATE;

	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		sqe.c_icv_key = SEC_CIPHER_ENC;
		sqe.huk_iv_seq = WD_CIPHER_THEN_DIGEST << SEC_SEQ_OFFSET_V3;
	} else if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
		sqe.c_icv_key = SEC_CIPHER_DEC;
		sqe.huk_iv_seq = WD_DIGEST_THEN_CIPHER << SEC_SEQ_OFFSET_V3;
	} else {
		WD_ERR("failed to check aead op type!\n");
		return -EINVAL;
	}
	sqe.bd_param |= (__u16)(de | scene);

	if (msg->in_bytes == 0 ||
		msg->in_bytes > MAX_INPUT_DATA_LEN) {
		WD_ERR("failed to check aead input data length!\n");
		return -EINVAL;
	}
	sqe.c_len_ivin = msg->in_bytes;
	sqe.cipher_src_offset = msg->assoc_bytes;
	sqe.a_len_key = msg->in_bytes + msg->assoc_bytes;

	ret = fill_aead_bd3_alg(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd alg!\n");
		return ret;
	}

	ret = fill_aead_bd3_mode(msg, &sqe);
	if (ret) {
		WD_ERR("failed to fill aead bd mode!\n");
		return ret;
	}

	fill_aead_bd3_addr(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump aead send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	sqe.tag = msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		WD_ERR("hisi qm send is err(%d)!\n", ret);
		return ret;
	}

	return ret;
}

static void parse_aead_bd3(struct hisi_sec_sqe3 *sqe,
	struct wd_aead_msg *recv_msg)
{
	__u16 done;

	done = sqe->done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("SEC BD3 %s fail! done=0x%x, etype=0x%x\n", "aead",
			done, sqe->error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->aiv = (__u8 *)(uintptr_t)sqe->auth_ivin.a_ivin_addr;
	recv_msg->tag = sqe->tag;

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
	return -EINVAL;
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
