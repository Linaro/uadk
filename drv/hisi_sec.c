/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include "drv/wd_cipher_drv.h"
#include "drv/wd_digest_drv.h"
#include "drv/wd_aead_drv.h"
#include "crypto/aes.h"
#include "crypto/galois.h"
#include "hisi_qm_udrv.h"

#define BIT(nr)			(1UL << (nr))
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
#define SEC_CWIDTH_OFFSET_V3	10
#define SEC_CKEY_OFFSET_V3	13
#define SEC_CALG_OFFSET_V3	4
#define SEC_AKEY_OFFSET_V3	9
#define SEC_MAC_OFFSET_V3	4
#define SEC_SM4_XTS_STD_V3	25
#define SEC_SM4_XTS_GB_V3	0x1
#define SEC_AUTH_ALG_OFFSET_V3	15
#define SEC_SVA_PREFETCH_OFFSET	27
#define SEC_ENABLE_SVA_PREFETCH	0x1
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

#define DES3_BLOCK_SIZE		8
#define AES_BLOCK_SIZE		16
#define CTR_128BIT_COUNTER	16
#define GCM_FINAL_COUNTER	0x1000000
#define GCM_FINAL_COUNTER_LEN	4
#define GCM_STREAM_MAC_OFFSET	32
#define GCM_FULL_MAC_LEN	16
#define GCM_AUTH_MAC_OFFSET	47
#define GCM_BLOCK_SIZE		AES_BLOCK_SIZE
#define GCM_BLOCK_OFFSET	(AES_BLOCK_SIZE - 1)
#define AKEY_LEN(c_key_len)	(2 * (c_key_len) + 0x4)
#define MAC_LEN			4
#define LONG_AUTH_DATA_OFFSET   24

/* The max BD data length is 16M-512B */
#define MAX_INPUT_DATA_LEN	0xFFFE00
#define MAX_CCM_AAD_LEN		65279
#define SHA1_ALIGN_SZ		64U
#define SHA512_ALIGN_SZ		128U

#define AUTHPAD_OFFSET		2
#define AUTHTYPE_OFFSET		6
#define MAC_LEN_OFFSET		5
#define AUTH_ALG_OFFSET		11
#define WD_CIPHER_THEN_DIGEST		0x0
#define WD_DIGEST_THEN_CIPHER		0x1

#define SEC_CTX_Q_NUM_DEF		1

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

/* The long hash mode requires full-length mac output */
enum SEC_MAX_MAC_LEN {
	SEC_HMAC_SM3_MAC_LEN = 0x8,
	SEC_HMAC_MD5_MAC_LEN = 0x4,
	SEC_HMAC_SHA1_MAC_LEN = 0x5,
	SEC_HMAC_SHA256_MAC_LEN = 0x8,
	SEC_HMAC_SHA224_MAC_LEN = 0x7,
	SEC_HMAC_SHA384_MAC_LEN = 0xc,
	SEC_HMAC_SHA512_MAC_LEN = 0x10,
	SEC_HMAC_SHA512_224_MAC_LEN = 0x7,
	SEC_HMAC_SHA512_256_MAC_LEN = 0x8
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
	SEC_NO_CIPHER = 0x0,
	SEC_CIPHER_ENC = 0x1,
	SEC_CIPHER_DEC = 0x2,
	SEC_CIPHER_COPY = 0x3,
};

enum sec_bd_type {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
	BD_TYPE3 = 0x3,
};

enum sec_c_width {
	C_WIDTH_CS1 = 0x1,
	C_WIDTH_CS2 = 0x2,
	C_WIDTH_CS3 = 0x3,
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
	 * mac_sel: 5 bits
	 * reserved: 6~7 bits
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

static __u32 g_digest_a_alg[WD_DIGEST_TYPE_MAX] = {
	A_ALG_SM3, A_ALG_MD5, A_ALG_SHA1, A_ALG_SHA256, A_ALG_SHA224,
	A_ALG_SHA384, A_ALG_SHA512, A_ALG_SHA512_224, A_ALG_SHA512_256
};

static __u32 g_hmac_a_alg[WD_DIGEST_TYPE_MAX] = {
	A_ALG_HMAC_SM3, A_ALG_HMAC_MD5, A_ALG_HMAC_SHA1,
	A_ALG_HMAC_SHA256, A_ALG_HMAC_SHA224, A_ALG_HMAC_SHA384,
	A_ALG_HMAC_SHA512, A_ALG_HMAC_SHA512_224, A_ALG_HMAC_SHA512_256,
	A_ALG_AES_XCBC_MAC_96, A_ALG_AES_XCBC_PRF_128, A_ALG_AES_CMAC,
	A_ALG_AES_GMAC
};

static __u32 g_sec_hmac_full_len[WD_DIGEST_TYPE_MAX] = {
	SEC_HMAC_SM3_MAC_LEN, SEC_HMAC_MD5_MAC_LEN, SEC_HMAC_SHA1_MAC_LEN,
	SEC_HMAC_SHA256_MAC_LEN, SEC_HMAC_SHA224_MAC_LEN, SEC_HMAC_SHA384_MAC_LEN,
	SEC_HMAC_SHA512_MAC_LEN, SEC_HMAC_SHA512_224_MAC_LEN, SEC_HMAC_SHA512_256_MAC_LEN
};

static int hisi_sec_init(struct wd_alg_driver *drv, void *conf);
static void hisi_sec_exit(struct wd_alg_driver *drv);

static int hisi_sec_cipher_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_cipher_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_cipher_send_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_cipher_recv_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);

static int hisi_sec_digest_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_digest_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_digest_send_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_digest_recv_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);

static int hisi_sec_aead_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_aead_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_aead_send_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);
static int hisi_sec_aead_recv_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg);

static int cipher_send(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)wd_ctx_get_priv(ctx);

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE)
		return hisi_sec_cipher_send(drv, ctx, msg);
	return hisi_sec_cipher_send_v3(drv, ctx, msg);
}

static int cipher_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)wd_ctx_get_priv(ctx);

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE)
		return hisi_sec_cipher_recv(drv, ctx, msg);
	return hisi_sec_cipher_recv_v3(drv, ctx, msg);
}

static int digest_send(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)wd_ctx_get_priv(ctx);

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE)
		return hisi_sec_digest_send(drv, ctx, msg);
	return hisi_sec_digest_send_v3(drv, ctx, msg);
}

static int digest_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)wd_ctx_get_priv(ctx);

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE)
		return hisi_sec_digest_recv(drv, ctx, msg);
	return hisi_sec_digest_recv_v3(drv, ctx, msg);
}

static int aead_send(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)wd_ctx_get_priv(ctx);

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE)
		return hisi_sec_aead_send(drv, ctx, msg);
	return hisi_sec_aead_send_v3(drv, ctx, msg);
}

static int aead_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)wd_ctx_get_priv(ctx);

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE)
		return hisi_sec_aead_recv(drv, ctx, msg);
	return hisi_sec_aead_recv_v3(drv, ctx, msg);
}

static int hisi_sec_get_usage(void *param)
{
	return 0;
}

#define GEN_SEC_ALG_DRIVER(sec_alg_name, alg_type) \
{\
	.drv_name = "hisi_sec2",\
	.alg_name = (sec_alg_name),\
	.calc_type = UADK_ALG_HW,\
	.priority = 100,\
	.queue_num = SEC_CTX_Q_NUM_DEF,\
	.op_type_num = 1,\
	.fallback = 0,\
	.init = hisi_sec_init,\
	.exit = hisi_sec_exit,\
	.send = alg_type##_send,\
	.recv = alg_type##_recv,\
	.get_usage = hisi_sec_get_usage,\
}

static struct wd_alg_driver cipher_alg_driver[] = {
	GEN_SEC_ALG_DRIVER("ecb(aes)", cipher),
	GEN_SEC_ALG_DRIVER("cbc(aes)", cipher),
	GEN_SEC_ALG_DRIVER("xts(aes)", cipher),
	GEN_SEC_ALG_DRIVER("ecb(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("cbc(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("ctr(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("xts(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("ecb(des)", cipher),
	GEN_SEC_ALG_DRIVER("cbc(des)", cipher),
	GEN_SEC_ALG_DRIVER("ecb(des3_ede)", cipher),
	GEN_SEC_ALG_DRIVER("cbc(des3_ede)", cipher),

	GEN_SEC_ALG_DRIVER("ctr(aes)", cipher),
	GEN_SEC_ALG_DRIVER("ofb(aes)", cipher),
	GEN_SEC_ALG_DRIVER("cfb(aes)", cipher),
	GEN_SEC_ALG_DRIVER("cbc-cs1(aes)", cipher),
	GEN_SEC_ALG_DRIVER("cbc-cs2(aes)", cipher),
	GEN_SEC_ALG_DRIVER("cbc-cs3(aes)", cipher),
	GEN_SEC_ALG_DRIVER("ofb(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("cfb(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("cbc-cs1(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("cbc-cs2(sm4)", cipher),
	GEN_SEC_ALG_DRIVER("cbc-cs3(sm4)", cipher),
};

static struct wd_alg_driver digest_alg_driver[] = {
	GEN_SEC_ALG_DRIVER("sm3", digest),
	GEN_SEC_ALG_DRIVER("md5", digest),
	GEN_SEC_ALG_DRIVER("sha1", digest),
	GEN_SEC_ALG_DRIVER("sha224", digest),
	GEN_SEC_ALG_DRIVER("sha256", digest),
	GEN_SEC_ALG_DRIVER("sha384", digest),
	GEN_SEC_ALG_DRIVER("sha512", digest),
	GEN_SEC_ALG_DRIVER("sha512-224", digest),
	GEN_SEC_ALG_DRIVER("sha512-256", digest),
	GEN_SEC_ALG_DRIVER("xcbc-mac-96(aes)", digest),
	GEN_SEC_ALG_DRIVER("xcbc-prf-128(aes)", digest),
	GEN_SEC_ALG_DRIVER("cmac(aes)", digest),
	GEN_SEC_ALG_DRIVER("gmac(aes)", digest),
};

static struct wd_alg_driver aead_alg_driver[] = {
	GEN_SEC_ALG_DRIVER("ccm(aes)", aead),
	GEN_SEC_ALG_DRIVER("gcm(aes)", aead),
	GEN_SEC_ALG_DRIVER("authenc(hmac(sha256),cbc(aes))", aead),
	GEN_SEC_ALG_DRIVER("ccm(sm4)", aead),
	GEN_SEC_ALG_DRIVER("gcm(sm4)", aead),
};

static void dump_sec_msg(void *msg, const char *alg)
{
	struct wd_cipher_msg *cmsg;
	struct wd_digest_msg *dmsg;
	struct wd_aead_msg *amsg;

	WD_ERR("dump %s alg message after a task error occurs.\n", alg);

	if (!strcmp(alg, "cipher")) {
		cmsg = (struct wd_cipher_msg *)msg;
		WD_ERR("type:%u alg:%u op_type:%u mode:%u data_fmt:%u\n",
			cmsg->alg_type, cmsg->alg, cmsg->op_type, cmsg->mode,
			cmsg->data_fmt);
		WD_ERR("key_bytes:%u iv_bytes:%u in_bytes:%u out_bytes:%u\n",
			cmsg->key_bytes, cmsg->iv_bytes, cmsg->in_bytes, cmsg->out_bytes);
	} else if (!strcmp(alg, "digest")) {
		dmsg = (struct wd_digest_msg *)msg;
		WD_ERR("type:%u alg:%u has_next:%u mode:%u data_fmt:%u\n",
			dmsg->alg_type, dmsg->alg, dmsg->has_next, dmsg->mode, dmsg->data_fmt);
		WD_ERR("key_bytes:%u iv_bytes:%u in_bytes:%u out_bytes:%u\n",
			dmsg->key_bytes, dmsg->iv_bytes, dmsg->in_bytes, dmsg->out_bytes);
	} else if (!strcmp(alg, "aead")) {
		amsg = (struct wd_aead_msg *)msg;
		WD_ERR("MSG_STATE:%u\n", amsg->msg_state);
		WD_ERR("type:%u calg:%u op_type:%u cmode:%u\n",
			amsg->alg_type, amsg->calg, amsg->op_type, amsg->cmode);
		WD_ERR("data_fmt:%u ckey_bytes:%u auth_bytes:%u\n",
			amsg->data_fmt, amsg->ckey_bytes, amsg->auth_bytes);
		WD_ERR("assoc_bytes:%u in_bytes:%u  out_bytes:%u\n",
			amsg->assoc_bytes, amsg->in_bytes, amsg->out_bytes);
	}
}

static __u8 get_data_fmt_v3(__u32 bd_param)
{
	/* Only check the src addr type */
	if (bd_param & SEC_PBUFF_MODE_MASK_V3)
		return WD_SGL_BUF;

	return WD_FLAT_BUF;
}

static __u8 get_data_fmt_v2(__u32 sds_sa_type)
{
	/* Only check the src addr type */
	if (sds_sa_type & SEC_SGL_SDS_MASK)
		return WD_SGL_BUF;

	return WD_FLAT_BUF;
}

/* increment counter (128-bit int) by software */
static void ctr_iv_inc(__u8 *counter, __u32 len)
{
	__u32 n = CTR_128BIT_COUNTER;
	__u32 c = len;

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
	case WD_CIPHER_CBC_CS1:
	case WD_CIPHER_CBC_CS2:
	case WD_CIPHER_CBC_CS3:
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
			hisi_qm_sgl_copy(msg->iv, msg->out,
					 msg->out_bytes - msg->iv_bytes,
					 msg->iv_bytes, COPY_SGL_TO_PBUFF);

		if (msg->op_type == WD_CIPHER_DECRYPTION &&
		    msg->in_bytes >= msg->iv_bytes)
			hisi_qm_sgl_copy(msg->iv, msg->in,
					 msg->in_bytes - msg->iv_bytes,
					 msg->iv_bytes, COPY_SGL_TO_PBUFF);

		break;
	case WD_CIPHER_OFB:
	case WD_CIPHER_CFB:
		if (msg->out_bytes >= msg->iv_bytes)
			hisi_qm_sgl_copy(msg->iv, msg->out,
					 msg->out_bytes - msg->iv_bytes,
					 msg->iv_bytes, COPY_SGL_TO_PBUFF);

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
	if (msg->key_bytes == DES3_2KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_2KEY;
	} else if (msg->key_bytes == DES3_3KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_3KEY;
	} else {
		WD_ERR("failed to check 3des key size, size = %u\n",
		       msg->key_bytes);
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
		WD_ERR("failed to check AES key size, size = %u\n", len);
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_cipher_bd2_alg(struct wd_cipher_msg *msg,
			       struct hisi_sec_sqe *sqe)
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
		WD_ERR("failed to check cipher alg type, alg = %u\n", msg->alg);
		return -WD_EINVAL;
	}

	return ret;
}

static int fill_cipher_bd2_mode(struct wd_cipher_msg *msg,
				struct hisi_sec_sqe *sqe)
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
		WD_ERR("failed to check cipher mode type, mode = %u\n",
		       msg->mode);
		return -WD_EINVAL;
	}
	sqe->type2.icvw_kmode |= (__u16)(c_mode) << SEC_CMODE_OFFSET;

	return 0;
}

static void fill_cipher_bd2_addr(struct wd_cipher_msg *msg,
				 struct hisi_sec_sqe *sqe)
{
	sqe->type2.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->type2.data_dst_addr = (__u64)(uintptr_t)msg->out;
	sqe->type2.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->type2.c_key_addr = (__u64)(uintptr_t)msg->key;
}

static void parse_cipher_bd2(struct wd_alg_driver *drv, struct hisi_qp *qp,
			     struct hisi_sec_sqe *sqe, struct wd_cipher_msg *recv_msg)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_cipher_msg *temp_msg;
	__u16 done;
	__u32 tag;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("failed to parse cipher BD2! done=0x%x, etype=0x%x\n",
		       done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	tag = sqe->type2.tag;
	recv_msg->tag = tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg->alg_type = WD_CIPHER;
		recv_msg->data_fmt = get_data_fmt_v2(sqe->sds_sa_type);
		recv_msg->in = (__u8 *)(uintptr_t)sqe->type2.data_src_addr;
		recv_msg->out = (__u8 *)(uintptr_t)sqe->type2.data_dst_addr;
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, tag);
		if (!temp_msg) {
			recv_msg->result = WD_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
				qp->q_info.idx, tag);
			return;
		}
	} else {
		/* The synchronization mode uses the same message */
		temp_msg = recv_msg;
	}

	if (temp_msg->data_fmt != WD_SGL_BUF)
		update_iv(temp_msg);
	else
		update_iv_sgl(temp_msg);

	if (unlikely(recv_msg->result != WD_SUCCESS))
		dump_sec_msg(temp_msg, "cipher");
}

static int aes_len_check(struct wd_cipher_msg *msg)
{
	if (msg->in_bytes <= AES_BLOCK_SIZE &&
	    (msg->mode == WD_CIPHER_CBC_CS1 ||
	     msg->mode == WD_CIPHER_CBC_CS2 ||
	     msg->mode == WD_CIPHER_CBC_CS3)) {
		WD_ERR("failed to check input bytes of AES_CBC_CS_X, size = %u\n",
		       msg->in_bytes);
		return -WD_EINVAL;
	}

	return 0;
}

static int cipher_len_check(struct wd_cipher_msg *msg)
{
	int ret;

	if (msg->in_bytes > MAX_INPUT_DATA_LEN) {
		WD_ERR("input cipher length is error, size = %u\n",
		       msg->in_bytes);
		return -WD_EINVAL;
	}

	if (msg->mode == WD_CIPHER_OFB ||
	    msg->mode == WD_CIPHER_CFB ||
	    msg->mode == WD_CIPHER_CTR)
		return 0;

	if (msg->mode == WD_CIPHER_XTS || msg->mode == WD_CIPHER_XTS_GB) {
		if (msg->in_bytes < AES_BLOCK_SIZE) {
			WD_ERR("input cipher length is too small, size = %u\n",
			       msg->in_bytes);
			return -WD_EINVAL;
		}
		return 0;
	}

	if (msg->alg == WD_CIPHER_3DES || msg->alg == WD_CIPHER_DES) {
		if (msg->in_bytes & (DES3_BLOCK_SIZE - 1)) {
			WD_ERR("failed to check input bytes of 3DES or DES, size = %u\n",
			       msg->in_bytes);
			return -WD_EINVAL;
		}
		return 0;
	}

	if (msg->alg == WD_CIPHER_AES) {
		ret = aes_len_check(msg);
		if (ret)
			return ret;
	}

	return 0;
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

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, (struct wd_datalist *)(*in));
	if (!hw_sgl_in) {
		WD_ERR("failed to get sgl in for hw_v2!\n");
		return -WD_EINVAL;
	}

	if (type == WD_DIGEST) {
		hw_sgl_out = *out;
	} else {
		hw_sgl_out = hisi_qm_get_hw_sgl(h_sgl_pool,
						(struct wd_datalist *)(*out));
		if (!hw_sgl_out) {
			WD_ERR("failed to get hw sgl out for hw_v2!\n");
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

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, (struct wd_datalist *)(*in));
	if (!hw_sgl_in) {
		WD_ERR("failed to get sgl in for hw_v3!\n");
		return -WD_EINVAL;
	}

	if (type == WD_DIGEST) {
		hw_sgl_out = *out;
		sqe->bd_param |= SEC_PBUFF_MODE_MASK_V3;
	} else {
		hw_sgl_out = hisi_qm_get_hw_sgl(h_sgl_pool,
						(struct wd_datalist *)(*out));
		if (!hw_sgl_out) {
			WD_ERR("failed to get hw sgl out for hw_v3!\n");
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

static int hisi_sec_cipher_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_cipher_msg *msg = wd_msg;
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("invalid: input cipher msg is NULL!\n");
		return -WD_EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	ret = fill_cipher_bd2(msg, &sqe);
	if (ret)
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret)
			return ret;
	}

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.type2.clen_ivhlen |= (__u32)msg->in_bytes;
	sqe.type2.tag = (__u16)msg->tag;
	fill_cipher_bd2_addr(msg, &sqe);

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("cipher send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in,
					 msg->out);

		return ret;
	}

	return 0;
}

static int hisi_sec_cipher_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_cipher_msg *recv_msg = wd_msg;
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, (__u16)recv_msg->tag, sqe.type2.tag);
	if (ret)
		return ret;

	parse_cipher_bd2(drv, (struct hisi_qp *)h_qp, &sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
				 recv_msg->out);

	return 0;
}

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
		WD_ERR("failed to check cipher alg type, alg = %u\n", msg->alg);
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
	case WD_CIPHER_XTS_GB:
		c_mode = C_MODE_XTS;
		sqe->auth_mac_key |= (__u32)(SEC_SM4_XTS_GB_V3 << SEC_SM4_XTS_STD_V3);
		break;
	case WD_CIPHER_CFB:
		c_mode = C_MODE_CFB;
		break;
	case WD_CIPHER_CBC_CS1:
		c_mode = C_MODE_CBC_CS;
		sqe->c_icv_key |= C_WIDTH_CS1 << SEC_CWIDTH_OFFSET_V3;
		break;
	case WD_CIPHER_CBC_CS2:
		c_mode = C_MODE_CBC_CS;
		sqe->c_icv_key |= C_WIDTH_CS2 << SEC_CWIDTH_OFFSET_V3;
		break;
	case WD_CIPHER_CBC_CS3:
		c_mode = C_MODE_CBC_CS;
		sqe->c_icv_key |= C_WIDTH_CS3 << SEC_CWIDTH_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check cipher mode type, mode = %u\n",
		       msg->mode);
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

	sqe->auth_mac_key |= (__u32)SEC_ENABLE_SVA_PREFETCH << SEC_SVA_PREFETCH_OFFSET;

	return 0;
}

static int hisi_sec_cipher_send_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_cipher_msg *msg = wd_msg;
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("invalid: input cipher msg is NULL!\n");
		return -WD_EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	ret = fill_cipher_bd3(msg, &sqe);
	if (ret)
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl_v3(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret)
			return ret;
	}

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.c_len_ivin = (__u32)msg->in_bytes;
	sqe.tag = (__u64)(uintptr_t)msg->tag;
	fill_cipher_bd3_addr(msg, &sqe);

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("cipher send sqe is err(%d)!\n", ret);

		if (msg->data_fmt == WD_SGL_BUF)
			hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in,
					 msg->out);

		return ret;
	}

	return 0;
}

static void parse_cipher_bd3(struct wd_alg_driver *drv, struct hisi_qp *qp,
			     struct hisi_sec_sqe3 *sqe, struct wd_cipher_msg *recv_msg)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_cipher_msg *temp_msg;
	__u16 done;
	__u32 tag;

	done = sqe->done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("failed to parse cipher BD3! done=0x%x, etype=0x%x, sva_status=0x%x\n",
		       done, sqe->error_type, sqe->check_sum.hac_sva_status);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	tag = sqe->tag;

	recv_msg->tag = tag;
	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg->alg_type = WD_CIPHER;
		recv_msg->data_fmt = get_data_fmt_v3(sqe->bd_param);
		recv_msg->in = (__u8 *)(uintptr_t)sqe->data_src_addr;
		recv_msg->out = (__u8 *)(uintptr_t)sqe->data_dst_addr;
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, tag);
		if (!temp_msg) {
			recv_msg->result = WD_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
				qp->q_info.idx, tag);
			return;
		}
	} else {
		/* The synchronization mode uses the same message */
		temp_msg = recv_msg;
	}

	if (temp_msg->data_fmt != WD_SGL_BUF)
		update_iv(temp_msg);
	else
		update_iv_sgl(temp_msg);

	if (unlikely(recv_msg->result != WD_SUCCESS))
		dump_sec_msg(temp_msg, "cipher");
}

static int hisi_sec_cipher_recv_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_cipher_msg *recv_msg = wd_msg;
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, recv_msg->tag, sqe.tag);
	if (ret)
		return ret;

	parse_cipher_bd3(drv, (struct hisi_qp *)h_qp, &sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
				recv_msg->out);

	return 0;
}

static int fill_digest_bd2_alg(struct wd_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	if (msg->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("failed to check digest alg type, alg = %u\n", msg->alg);
		return -WD_EINVAL;
	}

	/*
	 * Long hash mode must config full output length, 0 mac len indicates
	 * the output full length.
	 */
	if (!msg->has_next)
		sqe->type2.mac_key_alg = msg->out_bytes / WORD_BYTES;

	/* SM3 can't config 0 in normal mode */
	if (msg->has_next && msg->mode == WD_DIGEST_NORMAL &&
	    msg->alg == WD_DIGEST_SM3)
		sqe->type2.mac_key_alg = g_sec_hmac_full_len[msg->alg];

	if (msg->has_next && msg->mode == WD_DIGEST_HMAC)
		sqe->type2.mac_key_alg = g_sec_hmac_full_len[msg->alg];

	if (msg->mode == WD_DIGEST_NORMAL)
		sqe->type2.mac_key_alg |=
		g_digest_a_alg[msg->alg] << AUTH_ALG_OFFSET;
	else if (msg->mode == WD_DIGEST_HMAC) {
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("failed to check digest key_bytes, size = %u\n",
			       msg->key_bytes);
			return -WD_EINVAL;
		}
		sqe->type2.mac_key_alg |= (__u32)(msg->key_bytes /
			WORD_BYTES) << MAC_LEN_OFFSET;
		sqe->type2.a_key_addr = (__u64)(uintptr_t)msg->key;

		sqe->type2.mac_key_alg |=
		g_hmac_a_alg[msg->alg] << AUTH_ALG_OFFSET;
	} else {
		WD_ERR("failed to check digest mode, mode = %u\n", msg->mode);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int long_hash_param_check(handle_t h_qp, struct wd_digest_msg *msg)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC && msg->has_next) {
		WD_ERR("invalid: async mode not supports long hash!\n");
		return -WD_EINVAL;
	}

	if (msg->data_fmt == WD_SGL_BUF && msg->has_next) {
		WD_ERR("invalid: sgl mode not supports long hash!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_digest_long_hash(handle_t h_qp, struct wd_digest_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	enum hash_block_type block_type = get_hash_block_type(msg);
	__u64 total_bits;
	int ret;

	ret = long_hash_param_check(h_qp, msg);
	if (ret)
		return ret;

	if (block_type == HASH_FIRST_BLOCK) {
		/* Long hash first */
		sqe->ai_apd_cs = AI_GEN_INNER;
		sqe->ai_apd_cs |= AUTHPAD_NOPAD << AUTHPAD_OFFSET;
	}

	if (block_type == HASH_MIDDLE_BLOCK) {
		/* Long hash middle */
		sqe->ai_apd_cs = AI_GEN_IVIN_ADDR;
		sqe->ai_apd_cs |= AUTHPAD_NOPAD << AUTHPAD_OFFSET;
		sqe->type2.a_ivin_addr = sqe->type2.mac_addr;
	}

	if (block_type == HASH_END_BLOCK) {
		/* Long hash end */
		sqe->ai_apd_cs = AI_GEN_IVIN_ADDR;
		sqe->ai_apd_cs |= AUTHPAD_PAD << AUTHPAD_OFFSET;
		sqe->type2.a_ivin_addr = sqe->type2.mac_addr;

		/* The max total_bits length is LONG_MAX */
		total_bits = msg->long_data_len * BYTE_BITS;
		sqe->type2.long_a_data_len = total_bits;
	}

	return 0;
}

static void parse_digest_bd2(struct wd_alg_driver *drv, struct hisi_qp *qp,
			     struct hisi_sec_sqe *sqe, struct wd_digest_msg *recv_msg)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_digest_msg *temp_msg;
	__u16 done;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("failed to parse digest BD2! done=0x%x, etype=0x%x\n",
		       done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->type2.tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg->alg_type = WD_DIGEST;
		recv_msg->data_fmt = get_data_fmt_v2(sqe->sds_sa_type);
		recv_msg->in = (__u8 *)(uintptr_t)sqe->type2.data_src_addr;
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, recv_msg->tag);
		if (!temp_msg) {
			recv_msg->result = WD_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
				qp->q_info.idx, recv_msg->tag);
			return;
		}
	} else {
		/* The synchronization mode uses the same message */
		temp_msg = recv_msg;
	}

	if (unlikely(recv_msg->result != WD_SUCCESS))
		dump_sec_msg(temp_msg, "digest");
}

static int digest_long_bd_align_check(struct wd_digest_msg *msg)
{
	__u32 alg_align_sz;

	alg_align_sz = msg->alg >= WD_DIGEST_SHA384 ?
		       SHA512_ALIGN_SZ - 1 : SHA1_ALIGN_SZ - 1;

	if (msg->in_bytes & alg_align_sz)
		return -WD_EINVAL;

	return 0;
}

static int digest_bd2_type_check(struct wd_digest_msg *msg)
{
	enum hash_block_type type = get_hash_block_type(msg);

	/* Long hash first and middle bd */
	if (type == HASH_FIRST_BLOCK || type == HASH_MIDDLE_BLOCK) {
		WD_ERR("hardware v2 not supports 0 size in long hash!\n");
		return -WD_EINVAL;
	}

	/* Block mode hash bd */
	if (type == HASH_SINGLE_BLOCK) {
		WD_ERR("hardware v2 not supports 0 size in block hash!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int digest_bd3_type_check(struct wd_digest_msg *msg)
{
	enum hash_block_type type = get_hash_block_type(msg);
	/* Long hash first and middle bd */
	if (type == HASH_FIRST_BLOCK || type == HASH_MIDDLE_BLOCK) {
		WD_ERR("invalid: hardware v3 not supports 0 size in long hash!\n");
		return -WD_EINVAL;
	}

	if (msg->alg == WD_DIGEST_AES_XCBC_MAC_96 ||
		msg->alg == WD_DIGEST_AES_XCBC_PRF_128 ||
		msg->alg == WD_DIGEST_AES_CMAC) {
		WD_ERR("invalid: digest mode %u not supports 0 size!\n", msg->alg);
		return -WD_EINVAL;
	}

	return 0;
}

static int digest_len_check(struct wd_digest_msg *msg,  enum sec_bd_type type)
{
	int ret = 0;

	/*
	 * Hardware needs to check the zero byte packet in the block
	 * and long hash mode. First and middle bd not support 0 size,
	 * final bd not need to check it.
	 */
	if (unlikely(!msg->in_bytes)) {
		if (type == BD_TYPE2)
			ret = digest_bd2_type_check(msg);
		else if (type == BD_TYPE3)
			ret = digest_bd3_type_check(msg);

		if (ret)
			return ret;
	} else if (unlikely(msg->in_bytes > MAX_INPUT_DATA_LEN)) {
		WD_ERR("digest input length is too long, size = %u\n", msg->in_bytes);
		return -WD_EINVAL;
	}

	if (unlikely(msg->out_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("digest out length is error, size = %u\n",
		       msg->out_bytes);
		return -WD_EINVAL;
	}

	if (msg->has_next) {
		ret = digest_long_bd_align_check(msg);
		if (ret) {
			WD_ERR("input data isn't aligned, size = %u\n",
			       msg->in_bytes);
			return -WD_EINVAL;
		}
	}

	return 0;
}

static int hisi_sec_digest_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_digest_msg *msg = wd_msg;
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	__u8 scene;
	__u8 de;
	int ret;

	if (!msg) {
		WD_ERR("invalid: input digest msg is NULL!\n");
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
		if (ret)
			return ret;
	}

	sqe.sds_sa_type |= (__u8)(de | scene);
	sqe.type2.alen_ivllen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe.type2.mac_addr = (__u64)(uintptr_t)msg->out;

	ret = fill_digest_bd2_alg(msg, &sqe);
	if (ret)
		goto put_sgl;

	ret = fill_digest_long_hash(h_qp, msg, &sqe);
	if (ret)
		goto put_sgl;

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.type2.tag = (__u16)msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("digest send sqe is err(%d)!\n", ret);

		goto put_sgl;
	}

	return 0;

put_sgl:
	if (msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);

	return ret;
}

static int hisi_sec_digest_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_digest_msg *recv_msg = wd_msg;
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, (__u16)recv_msg->tag, sqe.type2.tag);
	if (ret)
		return ret;

	parse_digest_bd2(drv, (struct hisi_qp *)h_qp, &sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
			recv_msg->out);

	return 0;
}

static int hmac_key_len_check(struct wd_digest_msg *msg)
{
	switch (msg->alg) {
	case WD_DIGEST_AES_XCBC_MAC_96:
	case WD_DIGEST_AES_XCBC_PRF_128:
	case WD_DIGEST_AES_CMAC:
		if (msg->key_bytes != AES_KEYSIZE_128) {
			WD_ERR("failed to check digest key bytes, size = %u\n",
			       msg->key_bytes);
			return -WD_EINVAL;
		}
		break;
	default:
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("failed to check digest key bytes, size = %u\n",
			       msg->key_bytes);
			return -WD_EINVAL;
		}
		break;
	}

	return 0;
}

static int fill_digest_bd3_alg(struct wd_digest_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	int ret;

	if (msg->alg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("failed to check digest type, alg = %u\n", msg->alg);
		return -WD_EINVAL;
	}

	/*
	 * Long hash mode must config full output length, 0 mac len indicates
	 * the output full length.
	 */
	if (!msg->has_next)
		sqe->auth_mac_key |= (msg->out_bytes / WORD_BYTES) <<
				SEC_MAC_OFFSET_V3;

	/* SM3 can't config 0 in normal mode */
	if (msg->has_next && msg->mode == WD_DIGEST_NORMAL &&
	    msg->alg == WD_DIGEST_SM3)
		sqe->auth_mac_key |= g_sec_hmac_full_len[msg->alg] <<
				SEC_MAC_OFFSET_V3;

	if (msg->has_next && msg->mode == WD_DIGEST_HMAC)
		sqe->auth_mac_key |= g_sec_hmac_full_len[msg->alg] <<
				SEC_MAC_OFFSET_V3;

	if (msg->mode == WD_DIGEST_NORMAL) {
		sqe->auth_mac_key |=
		g_digest_a_alg[msg->alg] << SEC_AUTH_ALG_OFFSET_V3;
	} else if (msg->mode == WD_DIGEST_HMAC) {
		ret = hmac_key_len_check(msg);
		if (ret)
			return ret;

		sqe->auth_mac_key |= (__u32)(msg->key_bytes /
			WORD_BYTES) << SEC_AKEY_OFFSET_V3;
		sqe->a_key_addr = (__u64)(uintptr_t)msg->key;
		sqe->auth_mac_key |=
		g_hmac_a_alg[msg->alg] << SEC_AUTH_ALG_OFFSET_V3;

		if (msg->alg == WD_DIGEST_AES_GMAC) {
			sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
			sqe->auth_ivin.a_ivin_addr = (__u64)(uintptr_t)msg->iv;
		}
	} else {
		WD_ERR("failed to check digest mode, mode = %u\n", msg->mode);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int aes_auth_long_hash_check(struct wd_digest_msg *msg)
{
	if ((msg->alg == WD_DIGEST_AES_XCBC_MAC_96 ||
	     msg->alg == WD_DIGEST_AES_XCBC_PRF_128 ||
	     msg->alg == WD_DIGEST_AES_CMAC ||
	     msg->alg == WD_DIGEST_AES_GMAC) && msg->has_next) {
		WD_ERR("aes auth algs not supports long hash mode!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int fill_digest_long_hash3(handle_t h_qp, struct wd_digest_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	enum hash_block_type block_type = get_hash_block_type(msg);
	__u64 total_bits;
	int ret;

	ret = long_hash_param_check(h_qp, msg);
	if (ret)
		return ret;

	ret = aes_auth_long_hash_check(msg);
	if (ret)
		return ret;

	if (block_type == HASH_FIRST_BLOCK) {
		/* Long hash first */
		sqe->auth_mac_key |= AI_GEN_INNER << SEC_AI_GEN_OFFSET_V3;
		sqe->stream_scene.stream_auth_pad = AUTHPAD_NOPAD;
	}

	if (block_type == HASH_MIDDLE_BLOCK) {
		/* Long hash middle */
		sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
		sqe->stream_scene.stream_auth_pad = AUTHPAD_NOPAD;
		sqe->auth_ivin.a_ivin_addr = sqe->mac_addr;
	}

	if (block_type == HASH_END_BLOCK) {
		/* Long hash end */
		sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
		sqe->stream_scene.stream_auth_pad = AUTHPAD_PAD;
		sqe->auth_ivin.a_ivin_addr = sqe->mac_addr;

		/* The max total_bits length is LONG_MAX */
		total_bits = msg->long_data_len * BYTE_BITS;
		sqe->stream_scene.long_a_data_len = total_bits;
	}

	return 0;
}

static void fill_digest_v3_scene(struct hisi_sec_sqe3 *sqe,
				 struct wd_digest_msg *msg)
{
	__u16 scene, de;

	/* config BD type */
	sqe->bd_param = BD_TYPE3;

	/* config scene */
	if (msg->alg == WD_DIGEST_AES_GMAC)
		scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	else
		scene = SEC_STREAM_SCENE << SEC_SCENE_OFFSET_V3;

	de = DATA_DST_ADDR_DISABLE << SEC_DE_OFFSET_V3;

	sqe->bd_param |= (__u16)(de | scene);
}

static int hisi_sec_digest_send_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_digest_msg *msg = wd_msg;
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("invalid: input digest msg is NULL!\n");
		return -WD_EINVAL;
	}

	ret = digest_len_check(msg, BD_TYPE3);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	fill_digest_v3_scene(&sqe, msg);

	sqe.auth_mac_key = AUTH_HMAC_CALCULATE;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl_v3(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret)
			return ret;
	}

	sqe.a_len_key = (__u32)msg->in_bytes;
	sqe.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe.mac_addr = (__u64)(uintptr_t)msg->out;

	ret = fill_digest_bd3_alg(msg, &sqe);
	if (ret)
		goto put_sgl;

	ret = fill_digest_long_hash3(h_qp, msg, &sqe);
	if (ret)
		goto put_sgl;

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.tag = (__u64)(uintptr_t)msg->tag;
	sqe.auth_mac_key |= (__u32)SEC_ENABLE_SVA_PREFETCH << SEC_SVA_PREFETCH_OFFSET;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("digest send sqe is err(%d)!\n", ret);

		goto put_sgl;
	}

	return 0;

put_sgl:
	if (msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);

	return ret;
}

static void parse_digest_bd3(struct wd_alg_driver *drv, struct hisi_qp *qp,
			     struct hisi_sec_sqe3 *sqe, struct wd_digest_msg *recv_msg)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_digest_msg *temp_msg;
	__u16 done;

	done = sqe->done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		WD_ERR("failed to parse digest BD3! done=0x%x, etype=0x%x, sva_status=0x%x\n",
		       done, sqe->error_type, sqe->check_sum.hac_sva_status);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg->alg_type = WD_DIGEST;
		recv_msg->data_fmt = get_data_fmt_v3(sqe->bd_param);
		recv_msg->in = (__u8 *)(uintptr_t)sqe->data_src_addr;
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, recv_msg->tag);
		if (!temp_msg) {
			recv_msg->result = WD_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
				qp->q_info.idx, recv_msg->tag);
			return;
		}
	} else {
		/* The synchronization mode uses the same message */
		temp_msg = recv_msg;
	}

	if (unlikely(recv_msg->result != WD_SUCCESS))
		dump_sec_msg(temp_msg, "digest");
}

static int hisi_sec_digest_recv_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_digest_msg *recv_msg = wd_msg;
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, recv_msg->tag, sqe.tag);
	if (ret)
		return ret;

	parse_digest_bd3(drv, (struct hisi_qp *)h_qp, &sqe, recv_msg);

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
		WD_ERR("failed to check AES key size, size = %u\n",
		       msg->ckey_bytes);
		return -WD_EINVAL;
	}

	return 0;
}

static int aead_akey_len_check(struct wd_aead_msg *msg)
{
	if (unlikely(msg->akey_bytes & WORD_ALIGNMENT_MASK)) {
		WD_ERR("failed to check aead auth key bytes, size = %u\n",
		       msg->akey_bytes);
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
		if (ret)
			return ret;
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	default:
		WD_ERR("failed to check aead calg type, calg = %u\n",
		       msg->calg);
		return -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WD_CIPHER_CCM || msg->cmode == WD_CIPHER_GCM)
		return ret;

	sqe->type2.mac_key_alg = msg->auth_bytes / WORD_BYTES;

	ret = aead_akey_len_check(msg);
	if (ret)
		return ret;

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
		WD_ERR("failed to check aead dalg type, dalg = %u\n",
		       msg->dalg);
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
		if ((msg->msg_state == AEAD_MSG_FIRST) && !msg->assoc_bytes) {
			WD_ERR("invalid: first bd assoc bytes is 0!\n");
			return -WD_EINVAL;
		}
		sqe->type2.alen_ivllen = msg->assoc_bytes;
		sqe->type2.icvw_kmode |= msg->auth_bytes;
		break;
	default:
		WD_ERR("failed to check aead cmode type, cmode = %u\n",
		       msg->cmode);
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

static void fill_aead_bd2_addr(struct wd_aead_msg *msg,
		struct hisi_sec_sqe *sqe)
{
	sqe->type2.data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->type2.data_dst_addr = (__u64)(uintptr_t)msg->out;
	sqe->type2.mac_addr = (__u64)(uintptr_t)msg->mac;
	sqe->type2.c_key_addr = (__u64)(uintptr_t)msg->ckey;
	sqe->type2.a_key_addr = (__u64)(uintptr_t)msg->akey;
	sqe->type2.c_ivin_addr = (__u64)(uintptr_t)msg->iv;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	sqe->type2.a_ivin_addr = (__u64)(uintptr_t)msg->aiv;
}

static int aead_len_check(struct wd_aead_msg *msg, enum sec_bd_type type)
{
	if (msg->msg_state == AEAD_MSG_MIDDLE) {
		if ((!msg->in_bytes || (msg->in_bytes & (AES_BLOCK_SIZE - 1)))) {
			WD_ERR("invalid: middle bd input size is 0 or not 16 bytes aligned!\n");
			return -WD_EINVAL;
		}
	}

	if (msg->cmode == WD_CIPHER_GCM || msg->cmode == WD_CIPHER_CCM) {
		if (msg->msg_state == AEAD_MSG_BLOCK && type == BD_TYPE2 && !msg->in_bytes) {
			WD_ERR("invalid: ccm/gcm block mode input size is 0 for hw_v2!\n");
			return -WD_EINVAL;
		}
	}

	if (unlikely((__u64)msg->in_bytes + msg->assoc_bytes > MAX_INPUT_DATA_LEN)) {
		WD_ERR("aead input data length is too long, size = %llu\n",
		       (__u64)msg->in_bytes + msg->assoc_bytes);
		return -WD_EINVAL;
	}

	if (unlikely(msg->cmode == WD_CIPHER_CCM &&
	    msg->assoc_bytes > MAX_CCM_AAD_LEN)) {
		WD_ERR("aead ccm aad length is too long, size = %u\n",
		       msg->assoc_bytes);
		return -WD_EINVAL;
	}

	return 0;
}

static void fill_gcm_akey_len(struct wd_aead_msg *msg, void *sqe, enum sec_bd_type type)
{
	struct hisi_sec_sqe3 *sqe3;
	struct hisi_sec_sqe *sqe2;
	__u8 c_key_len = 0;

	aead_get_aes_key_len(msg, &c_key_len);

	if (type == BD_TYPE2) {
		sqe2 = (struct hisi_sec_sqe *)sqe;
		sqe2->type2.mac_key_alg |= (__u32)AKEY_LEN(c_key_len) << MAC_LEN_OFFSET;
	} else if (type == BD_TYPE3) {
		sqe3 = (struct hisi_sec_sqe3 *)sqe;
		sqe3->auth_mac_key |= (__u32)AKEY_LEN(c_key_len) << SEC_AKEY_OFFSET_V3;
	}
}

static void gcm_auth_ivin(struct wd_aead_msg *msg)
{
	__u32 final_counter = GCM_FINAL_COUNTER;

	/* auth_ivin = {cipher_ivin(16B), null(16B), auth_mac(16B), null(16B)} */
	memset(msg->aiv_stream, 0, AIV_STREAM_LEN);

	memcpy(msg->aiv_stream, msg->iv, GCM_IV_SIZE);
	/* The last 4 bytes of c_ivin are counters */
	memcpy(msg->aiv_stream + GCM_IV_SIZE, &final_counter, GCM_FINAL_COUNTER_LEN);

	/* Fill auth_ivin with the mac of last MIDDLE BD */
	memcpy(msg->aiv_stream + GCM_STREAM_MAC_OFFSET, msg->mac, GCM_FULL_MAC_LEN);

	/* Use the user's origin mac for decrypt icv check */
	if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST)
		memcpy(msg->mac, msg->dec_mac, msg->auth_bytes);
}

static void fill_gcm_first_bd2(struct wd_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	sqe->ai_apd_cs = AI_GEN_INNER;
	sqe->ai_apd_cs |= AUTHPAD_NOPAD << AUTHPAD_OFFSET;
	sqe->type_auth_cipher &= ~(SEC_CIPHER_COPY << SEC_CIPHER_OFFSET);
	sqe->type_auth_cipher |= AUTH_HMAC_CALCULATE << AUTHTYPE_OFFSET;
	sqe->type2.mac_key_alg = MAC_LEN;
	fill_gcm_akey_len(msg, sqe, BD_TYPE2);
	sqe->type2.mac_key_alg |= A_ALG_AES_GMAC << AUTH_ALG_OFFSET;
	sqe->type2.clen_ivhlen = 0;
	sqe->type2.icvw_kmode = 0;
	sqe->type2.a_ivin_addr = 0;
	sqe->type2.c_key_addr = 0;
	sqe->type2.c_alg  = 0;
	sqe->type2.auth_src_offset = 0;
	sqe->type2.alen_ivllen = msg->assoc_bytes;
	sqe->type2.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->type2.a_key_addr = (__u64)(uintptr_t)msg->ckey;
}

static void fill_gcm_middle_bd2(struct wd_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	sqe->ai_apd_cs = AI_GEN_IVIN_ADDR;
	sqe->ai_apd_cs |= AUTHPAD_NOPAD << AUTHPAD_OFFSET;
	sqe->type_auth_cipher |= NO_AUTH << AUTHTYPE_OFFSET;
	sqe->type2.cipher_src_offset = 0;
	sqe->type2.auth_src_offset = 0;
	fill_gcm_akey_len(msg, sqe, BD_TYPE2);
	sqe->type2.alen_ivllen = 0;
	sqe->type2.a_ivin_addr = sqe->type2.mac_addr;
	sqe->type2.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->type2.a_key_addr = (__u64)(uintptr_t)msg->ckey;
}

static void get_galois_vector_s(struct wd_aead_msg *msg, __u8 *s)
{
	__u8 a_c[GCM_BLOCK_SIZE] = {0};
	__u64 cipher_len, aad_len;
	__u32 i;

	aad_len = msg->assoc_bytes * BYTE_BITS;
	memcpy(&a_c[BYTE_BITS], &aad_len, sizeof(__u64));

	cipher_len = msg->long_data_len * BYTE_BITS;
	memcpy(&a_c[0], &cipher_len, sizeof(__u64));

	/* Based the little-endian operation */
	for (i = 0; i < GCM_BLOCK_SIZE; i++)
		s[i] = a_c[i] ^ msg->aiv_stream[(__u8)(GCM_AUTH_MAC_OFFSET - i)];
}

static int gcm_do_soft_mac(struct wd_aead_msg *msg)
{
	__u8 ctr_r[GCM_BLOCK_SIZE] = {0};
	__u8 data[GCM_BLOCK_SIZE] = {0};
	__u8 H[GCM_BLOCK_SIZE] = {0};
	__u8 K[GCM_BLOCK_SIZE] = {0};
	__u8 S[GCM_BLOCK_SIZE] = {0};
	__u8 g[GCM_BLOCK_SIZE] = {0};
	__u8 G[GCM_BLOCK_SIZE] = {0};
	__u32 i, len, block, offset;
	__u8 *out;
	int ret;

	aes_encrypt(msg->ckey, msg->ckey_bytes, data, H);

	len = msg->in_bytes;
	offset = 0;
	while (len) {
		memset(data, 0, GCM_BLOCK_SIZE);
		block = len >= GCM_BLOCK_SIZE ? GCM_BLOCK_SIZE : len;
		memcpy(data, msg->in + offset, block);
		ctr_iv_inc(msg->iv, GCM_BLOCK_SIZE >> CTR_MODE_LEN_SHIFT);
		aes_encrypt(msg->ckey, msg->ckey_bytes, msg->iv, K);
		out = msg->out + offset;
		for (i = 0; i < block; i++)
			out[i] = K[i] ^ data[i];

		if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST)
			memcpy(data, out, block);

		/*
		 * Mac and data is based on big-endian, the first argument of galois_compute
		 * must be converted to little-endian.
		 */
		for (i = 0; i < GCM_BLOCK_SIZE; i++)
			G[i] = data[GCM_BLOCK_OFFSET - i] ^
			       msg->aiv_stream[(__u8)(GCM_AUTH_MAC_OFFSET - i)];

		galois_compute(G, H, msg->aiv_stream + GCM_STREAM_MAC_OFFSET, GCM_BLOCK_SIZE);
		len -= block;
		offset += block;
	}

	get_galois_vector_s(msg, S);

	galois_compute(S, H, g, GCM_BLOCK_SIZE);

	/* Encrypt ctr0 based on AES_ECB */
	aes_encrypt(msg->ckey, msg->ckey_bytes, msg->aiv_stream, ctr_r);

	/* Get the GMAC tag final */
	for (i = 0; i < GCM_BLOCK_SIZE; i++)
		msg->mac[i] = g[i] ^ ctr_r[i];

	if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
		ret = memcmp(msg->mac, msg->dec_mac, msg->auth_bytes);
		if (ret) {
			msg->result = WD_IN_EPARA;
			WD_ERR("failed to do the gcm authentication!\n");
			return -WD_EINVAL;
		}
	}

	msg->result = WD_SUCCESS;

	return WD_SOFT_COMPUTING;
}

static int fill_stream_bd2(struct wd_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	int ret = 0;

	switch (msg->msg_state) {
	case AEAD_MSG_FIRST:
		if (msg->cmode == WD_CIPHER_GCM)
			fill_gcm_first_bd2(msg, sqe);
		break;
	case AEAD_MSG_MIDDLE:
		if (msg->cmode == WD_CIPHER_GCM)
			fill_gcm_middle_bd2(msg, sqe);
		break;
	case AEAD_MSG_END:
		if (msg->cmode == WD_CIPHER_GCM) {
			gcm_auth_ivin(msg);
			ret = gcm_do_soft_mac(msg);
		}
		break;
	default:
		break;
	}

	return ret;
}

static int fill_aead_bd2(struct wd_aead_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u8 scene, cipher, de;
	int ret;

	sqe->type_auth_cipher = BD_TYPE2;

	if (msg->msg_state == AEAD_MSG_BLOCK)
		scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	else
		scene = SEC_STREAM_SCENE << SEC_SCENE_OFFSET;

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
		WD_ERR("failed to check aead op type, op = %u\n", msg->op_type);
		return -WD_EINVAL;
	}

	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET;
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

int aead_msg_state_check(struct wd_aead_msg *msg)
{
	if (msg->cmode == WD_CIPHER_GCM) {
		if (unlikely(msg->msg_state >= AEAD_MSG_INVALID)) {
			WD_ERR("invalid: GCM input msg state is wrong!\n");
			return -WD_EINVAL;
		}
	} else {
		if (unlikely(msg->msg_state != AEAD_MSG_BLOCK)) {
			WD_ERR("invalid: cmode not support stream msg state!\n");
			return -WD_EINVAL;
		}
	}

	if (unlikely(msg->msg_state != AEAD_MSG_BLOCK && msg->data_fmt == WD_SGL_BUF)) {
		WD_ERR("invalid: sgl mode not supports stream mode!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int hisi_sec_aead_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_aead_msg *msg = wd_msg;
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	if (unlikely(!msg)) {
		WD_ERR("failed to check input aead msg!\n");
		return -WD_EINVAL;
	}

	ret = aead_msg_state_check(msg);
	if (unlikely(ret))
		return ret;

	ret = aead_len_check(msg, BD_TYPE2);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	ret = fill_aead_bd2(msg, &sqe);
	if (unlikely(ret))
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl(h_qp, &msg->in, &msg->out,
					&sqe, msg->alg_type);
		if (ret)
			return ret;
	}

	fill_aead_bd2_addr(msg, &sqe);

	ret = fill_stream_bd2(msg, &sqe);
	if (ret == WD_SOFT_COMPUTING) {
		ret = 0;
		goto put_sgl;
	} else if (unlikely(ret)) {
		goto put_sgl;
	}

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.type2.tag = (__u16)msg->tag;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("aead send sqe is err(%d)!\n", ret);

		goto put_sgl;
	}

	return 0;

put_sgl:
	if (msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);

	return ret;
}

static void update_stream_counter(struct wd_aead_msg *recv_msg)
{
	if (recv_msg->cmode == WD_CIPHER_GCM) {
		/*
		 * The counter of the first middle BD is set to 1.
		 * Other middle BDs and tail BD are set based on
		 * cipher_len and the counter of the previous BD.
		 */
		if (recv_msg->msg_state == AEAD_MSG_FIRST)
			recv_msg->iv[MAX_IV_SIZE - 1] = 0x1;
		else if (recv_msg->msg_state == AEAD_MSG_MIDDLE)
			ctr_iv_inc(recv_msg->iv, recv_msg->in_bytes >> CTR_MODE_LEN_SHIFT);
	}
}

static void parse_aead_bd2(struct wd_alg_driver *drv, struct hisi_qp *qp,
			   struct hisi_sec_sqe *sqe, struct wd_aead_msg *recv_msg)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_aead_msg *temp_msg;
	__u16 done, icv;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	icv = (sqe->type2.done_flag & SEC_ICV_MASK) >> 1;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type ||
	    icv == SEC_HW_ICV_ERR) {
		WD_ERR("failed to parse aead BD2! done=0x%x, etype=0x%x, icv=0x%x\n",
		       done, sqe->type2.error_type, icv);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->type2.tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg->alg_type = WD_AEAD;
		recv_msg->data_fmt = get_data_fmt_v2(sqe->sds_sa_type);
		recv_msg->in = (__u8 *)(uintptr_t)sqe->type2.data_src_addr;
		recv_msg->out = (__u8 *)(uintptr_t)sqe->type2.data_dst_addr;
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, recv_msg->tag);
		if (!temp_msg) {
			recv_msg->result = WD_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
				qp->q_info.idx, recv_msg->tag);
			return;
		}
	} else {
		/* The synchronization mode uses the same message */
		temp_msg = recv_msg;
	}

	update_stream_counter(temp_msg);

	if (unlikely(recv_msg->result != WD_SUCCESS))
		dump_sec_msg(temp_msg, "aead");
}

static bool soft_compute_check(struct hisi_qp *qp, struct wd_aead_msg *msg)
{
	/* Asynchronous mode does not use the sent message, so ignores it */
	if (msg->cmode == WD_CIPHER_GCM)
		return (msg->msg_state == AEAD_MSG_END) && qp->q_info.qp_mode == CTX_MODE_SYNC;

	return false;
}

static int hisi_sec_aead_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_aead_msg *recv_msg = wd_msg;
	struct hisi_sec_sqe sqe;
	__u16 count = 0;
	int ret;

	if (soft_compute_check((struct hisi_qp *)h_qp, recv_msg))
		return 0;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, (__u16)recv_msg->tag, sqe.type2.tag);
	if (ret)
		return ret;

	parse_aead_bd2(drv, (struct hisi_qp *)h_qp, &sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type, recv_msg->in,
				recv_msg->out);

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
		if (ret)
			return ret;
		sqe->c_icv_key |= (__u16)c_key_len << SEC_CKEY_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead calg type, calg = %u\n",
		       msg->calg);
		return -WD_EINVAL;
	}

	/* CCM/GCM this region is set to 0 */
	if (msg->cmode == WD_CIPHER_CCM || msg->cmode == WD_CIPHER_GCM)
		return ret;

	ret = aead_akey_len_check(msg);
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
		WD_ERR("failed to check aead dalg type, dalg = %u\n",
		       msg->dalg);
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
		if ((msg->msg_state == AEAD_MSG_FIRST) && !msg->assoc_bytes) {
			WD_ERR("invalid: first bd assoc bytes is 0!\n");
			return -WD_EINVAL;
		}
		sqe->a_len_key = msg->assoc_bytes;
		sqe->c_icv_key |= msg->auth_bytes << SEC_MAC_OFFSET_V3;
		break;
	default:
		WD_ERR("failed to check aead cmode type, cmode = %u\n",
		       msg->cmode);
		return -WD_EINVAL;
	}

	return 0;
}

static void fill_aead_bd3_addr(struct wd_aead_msg *msg,
		struct hisi_sec_sqe3 *sqe)
{
	sqe->data_src_addr = (__u64)(uintptr_t)msg->in;
	sqe->data_dst_addr = (__u64)(uintptr_t)msg->out;

	sqe->mac_addr = (__u64)(uintptr_t)msg->mac;
	sqe->c_key_addr = (__u64)(uintptr_t)msg->ckey;
	sqe->a_key_addr = (__u64)(uintptr_t)msg->akey;
	sqe->no_scene.c_ivin_addr = (__u64)(uintptr_t)msg->iv;

	/* CCM/GCM should init a_iv */
	set_aead_auth_iv(msg);

	sqe->auth_ivin.a_ivin_addr = (__u64)(uintptr_t)msg->aiv;
}

static void fill_gcm_first_bd3(struct wd_aead_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	sqe->auth_mac_key |= AI_GEN_INNER << SEC_AI_GEN_OFFSET_V3;
	sqe->stream_scene.stream_auth_pad = AUTHPAD_NOPAD;
	sqe->stream_scene.stream_auth_pad |= BIT(5);
	sqe->c_icv_key &= ~0x3;
	sqe->auth_mac_key = AUTH_HMAC_CALCULATE;
	sqe->auth_mac_key |= MAC_LEN << SEC_MAC_OFFSET_V3;
	fill_gcm_akey_len(msg, sqe, BD_TYPE3);
	sqe->auth_mac_key |= A_ALG_AES_GMAC << SEC_AUTH_ALG_OFFSET_V3;
	sqe->c_len_ivin = 0;
	sqe->auth_ivin.a_ivin_addr = 0;
	sqe->c_key_addr = 0;
	sqe->c_mode_alg &= ~(0x7 << SEC_CALG_OFFSET_V3);
	sqe->auth_src_offset = 0;
	sqe->a_len_key = msg->assoc_bytes;
	sqe->stream_scene.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->a_key_addr = (__u64)(uintptr_t)msg->ckey;
}

static void fill_gcm_middle_bd3(struct wd_aead_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
	sqe->stream_scene.stream_auth_pad = AUTHPAD_NOPAD;
	sqe->stream_scene.stream_auth_pad |= BIT(5);
	sqe->auth_mac_key |= NO_AUTH;
	sqe->cipher_src_offset = 0;
	sqe->auth_src_offset = 0;
	fill_gcm_akey_len(msg, sqe, BD_TYPE3);
	sqe->a_len_key = 0;
	sqe->auth_ivin.a_ivin_addr = sqe->mac_addr;
	sqe->stream_scene.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->a_key_addr = (__u64)(uintptr_t)msg->ckey;
}

static void fill_gcm_final_bd3(struct wd_aead_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	sqe->auth_mac_key |= AI_GEN_IVIN_ADDR << SEC_AI_GEN_OFFSET_V3;
	sqe->stream_scene.stream_auth_pad = AUTHPAD_PAD;
	sqe->stream_scene.stream_auth_pad |= BIT(5);
	sqe->auth_mac_key |= NO_AUTH;
	sqe->cipher_src_offset = 0;
	sqe->auth_src_offset = 0;
	fill_gcm_akey_len(msg, sqe, BD_TYPE3);
	sqe->a_len_key = 0;
	sqe->stream_scene.long_a_data_len = msg->assoc_bytes;
	sqe->stream_scene.long_a_data_len |= msg->long_data_len << LONG_AUTH_DATA_OFFSET;
	sqe->stream_scene.c_ivin_addr = (__u64)(uintptr_t)msg->iv;
	sqe->a_key_addr = (__u64)(uintptr_t)msg->ckey;
	sqe->auth_ivin.a_ivin_addr = (__u64)(uintptr_t)msg->aiv_stream;
}

static int fill_stream_bd3(handle_t h_qp, struct wd_aead_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	int ret = 0;

	switch (msg->msg_state) {
	case AEAD_MSG_FIRST:
		if (msg->cmode == WD_CIPHER_GCM)
			fill_gcm_first_bd3(msg, sqe);
		break;
	case AEAD_MSG_MIDDLE:
		if (msg->cmode == WD_CIPHER_GCM)
			fill_gcm_middle_bd3(msg, sqe);
		break;
	case AEAD_MSG_END:
		if (msg->cmode == WD_CIPHER_GCM) {
			gcm_auth_ivin(msg);
			/* Due to hardware limitations, software compute is required. */
			if (qp->q_info.hw_type <= HISI_QM_API_VER3_BASE || !msg->in_bytes)
				ret = gcm_do_soft_mac(msg);
			else
				fill_gcm_final_bd3(msg, sqe);
		}
		break;
	default:
		break;
	}

	return ret;
}

static int fill_aead_bd3(struct wd_aead_msg *msg, struct hisi_sec_sqe3 *sqe)
{
	__u16 scene, de;
	int ret;

	sqe->bd_param = BD_TYPE3;

	if (msg->msg_state == AEAD_MSG_BLOCK)
		scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET_V3;
	else
		scene = SEC_STREAM_SCENE << SEC_SCENE_OFFSET_V3;

	if (msg->op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		sqe->c_icv_key = SEC_CIPHER_ENC;
		sqe->auth_mac_key = AUTH_HMAC_CALCULATE;
		sqe->huk_iv_seq = WD_CIPHER_THEN_DIGEST << SEC_SEQ_OFFSET_V3;
	} else if (msg->op_type == WD_CIPHER_DECRYPTION_DIGEST) {
		sqe->c_icv_key = SEC_CIPHER_DEC;
		sqe->auth_mac_key = AUTH_MAC_VERIFY;
		sqe->huk_iv_seq = WD_DIGEST_THEN_CIPHER << SEC_SEQ_OFFSET_V3;
	} else {
		WD_ERR("failed to check aead op type, op = %u\n", msg->op_type);
		return -WD_EINVAL;
	}

	de = DATA_DST_ADDR_ENABLE << SEC_DE_OFFSET_V3;
	sqe->bd_param |= (__u16)(de | scene);

	sqe->c_len_ivin = msg->in_bytes;
	sqe->cipher_src_offset = msg->assoc_bytes;
	sqe->a_len_key = msg->in_bytes + msg->assoc_bytes;
	sqe->auth_mac_key |= (__u32)SEC_ENABLE_SVA_PREFETCH << SEC_SVA_PREFETCH_OFFSET;

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

static int hisi_sec_aead_send_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_aead_msg *msg = wd_msg;
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("failed to check input aead msg!\n");
		return -WD_EINVAL;
	}

	ret = aead_msg_state_check(msg);
	if (unlikely(ret))
		return ret;

	ret = aead_len_check(msg, BD_TYPE3);
	if (unlikely(ret))
		return ret;

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe3));
	ret = fill_aead_bd3(msg, &sqe);
	if (unlikely(ret))
		return ret;

	if (msg->data_fmt == WD_SGL_BUF) {
		ret = hisi_sec_fill_sgl_v3(h_qp, &msg->in, &msg->out, &sqe,
					msg->alg_type);
		if (ret)
			return ret;
	}

	fill_aead_bd3_addr(msg, &sqe);
	ret = fill_stream_bd3(h_qp, msg, &sqe);
	if (ret == WD_SOFT_COMPUTING) {
		ret = 0;
		goto put_sgl;
	} else if (unlikely(ret)) {
		goto put_sgl;
	}

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.tag = msg->tag;
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		if (ret != -WD_EBUSY)
			WD_ERR("aead send sqe is err(%d)!\n", ret);

		goto put_sgl;
	}

	return 0;

put_sgl:
	if (msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, msg->alg_type, msg->in, msg->out);

	return ret;
}

static void parse_aead_bd3(struct wd_alg_driver *drv, struct hisi_qp *qp,
			   struct hisi_sec_sqe3 *sqe, struct wd_aead_msg *recv_msg)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_aead_msg *temp_msg;
	__u16 done, icv;

	done = sqe->done_flag & SEC_DONE_MASK;
	icv = (sqe->done_flag & SEC_ICV_MASK) >> 1;
	if (done != SEC_HW_TASK_DONE || sqe->error_type ||
	    icv == SEC_HW_ICV_ERR) {
		WD_ERR("failed to parse aead BD3!\n"
		       "done=0x%x, etype=0x%x, icv=0x%x, sva_status=0x%x\n",
		       done, sqe->error_type, icv, sqe->check_sum.hac_sva_status);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

	recv_msg->tag = sqe->tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg->alg_type = WD_AEAD;
		recv_msg->data_fmt = get_data_fmt_v3(sqe->bd_param);
		recv_msg->in = (__u8 *)(uintptr_t)sqe->data_src_addr;
		recv_msg->out = (__u8 *)(uintptr_t)sqe->data_dst_addr;
		temp_msg = wd_find_msg_in_pool(priv->config.pool, qp->q_info.idx, recv_msg->tag);
		if (!temp_msg) {
			recv_msg->result = WD_IN_EPARA;
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
				qp->q_info.idx, recv_msg->tag);
			return;
		}
	} else {
		/* The synchronization mode uses the same message */
		temp_msg = recv_msg;
	}

	update_stream_counter(temp_msg);

	if (unlikely(recv_msg->result != WD_SUCCESS))
		dump_sec_msg(temp_msg, "aead");
}

static int hisi_sec_aead_recv_v3(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct wd_aead_msg *recv_msg = wd_msg;
	struct hisi_sec_sqe3 sqe;
	__u16 count = 0;
	int ret;

	if (soft_compute_check((struct hisi_qp *)h_qp, recv_msg))
		return 0;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	ret = hisi_check_bd_id(h_qp, recv_msg->tag, sqe.tag);
	if (ret)
		return ret;

	parse_aead_bd3(drv, (struct hisi_qp *)h_qp, &sqe, recv_msg);

	if (recv_msg->data_fmt == WD_SGL_BUF)
		hisi_sec_put_sgl(h_qp, recv_msg->alg_type,
			recv_msg->in, recv_msg->out);

	return 0;
}

static int hisi_sec_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = conf;
	struct hisi_qm_priv qm_priv;
	struct hisi_sec_ctx *priv;
	handle_t h_qp = 0;
	handle_t h_ctx;
	__u32 i, j;

	if (!config->ctx_num) {
		WD_ERR("invalid: sec init config ctx num is 0!\n");
		return -WD_EINVAL;
	}

	priv = malloc(sizeof(struct hisi_sec_ctx));
	if (!priv)
		return -WD_EINVAL;

	qm_priv.sqe_size = sizeof(struct hisi_sec_sqe);
	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		/* setting the type is 0 for sqc_type */
		qm_priv.op_type = 0;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		/* Setting the epoll en to 0 for ASYNC ctx */
		qm_priv.epoll_en = (qm_priv.qp_mode == CTX_MODE_SYNC) ?
				   config->epoll_en : 0;
		qm_priv.idx = i;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp)
			goto out;
		config->ctxs[i].sqn = qm_priv.sqn;
	}
	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));
	drv->priv = priv;

	return 0;

out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}
	free(priv);
	return -WD_EINVAL;
}

static void hisi_sec_exit(struct wd_alg_driver *drv)
{
	struct hisi_sec_ctx *priv = (struct hisi_sec_ctx *)drv->priv;
	struct wd_ctx_config_internal *config;
	handle_t h_qp;
	__u32 i;

	if (!priv) {
		/* return if already exit */
		return;
	}

	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
	free(priv);
	drv->priv = NULL;
}

#ifdef WD_STATIC_DRV
void hisi_sec2_probe(void)
#else
static void __attribute__((constructor)) hisi_sec2_probe(void)
#endif
{
	int alg_num;
	int i, ret;

	WD_INFO("Info: register SEC alg drivers!\n");

	alg_num = ARRAY_SIZE(cipher_alg_driver);
	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&cipher_alg_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register SEC %s failed!\n",
				cipher_alg_driver[i].alg_name);
	}

	alg_num = ARRAY_SIZE(digest_alg_driver);
	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&digest_alg_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register SEC %s failed!\n",
				digest_alg_driver[i].alg_name);
	}

	alg_num = ARRAY_SIZE(aead_alg_driver);
	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&aead_alg_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register SEC %s failed!\n",
				aead_alg_driver[i].alg_name);
	}
}

#ifdef WD_STATIC_DRV
void hisi_sec2_remove(void)
#else
static void __attribute__((destructor)) hisi_sec2_remove(void)
#endif
{
	int alg_num;
	int i;

	WD_INFO("Info: unregister SEC alg drivers!\n");
	alg_num = ARRAY_SIZE(cipher_alg_driver);
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&cipher_alg_driver[i]);

	alg_num = ARRAY_SIZE(digest_alg_driver);
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&digest_alg_driver[i]);

	alg_num = ARRAY_SIZE(aead_alg_driver);
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&aead_alg_driver[i]);
}
