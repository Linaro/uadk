/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#include <pthread.h>
#include "../include/drv/wd_cipher_drv.h"
#include "../include/drv/wd_digest_drv.h"

#define SEC_DIGEST_ALG_OFFSET	11
#define WORD_ALIGNMENT_MASK	0x3
#define BD_TYPE2		0x2
#define WORD_BYTES		4
#define BYTE_BITS		8
#define SQE_BYTES_NUMS		128
#define SEC_FLAG_OFFSET	7
#define SEC_AUTH_OFFSET	6
#define SEC_AUTH_KEY_OFFSET	5
#define SEC_HW_TASK_DONE	0x1
#define SEC_DONE_MASK		0x0001
#define SEC_FLAG_MASK		0x780
#define SEC_TYPE_MASK		0x0f

#define SEC_COMM_SCENE		  0
#define SEC_IPSEC_SCENE	  1
#define SEC_SCENE_OFFSET	  3
#define SEC_DE_OFFSET		  1
#define SEC_CMODE_OFFSET	  12
#define SEC_CKEY_OFFSET	  9
#define SEC_CIPHER_OFFSET	  4
#define XTS_MODE_KEY_DIVISOR	  2

#define DES_KEY_SIZE		  8
#define SEC_3DES_2KEY_SIZE	  (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE	  (3 * DES_KEY_SIZE)
#define AES_KEYSIZE_128		  16
#define AES_KEYSIZE_192		  24
#define AES_KEYSIZE_256		  32

#define DES3_BLOCK_SIZE	8
#define	AES_BLOCK_SIZE		16
#define	MAX_CIPHER_LEN		16776704

#define AUTHPAD_OFFSET		2
#define AUTHTYPE_OFFSET	6
#define MAC_LEN_OFFSET		4
#define AUTH_ALG_OFFSET	11

#include "hisi_qm_udrv.h"
#include "wd.h"
#include "wd_cipher.h"
#include "wd_digest.h"

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
	NO_AUTH,
	AUTH_HMAC_CALCULATE,
	AUTH_MAC_VERIFY,
};

enum {
	AI_GEN_INNER,
	AI_GEN_IVIN_ADDR,
	AI_GEN_CAL_IV_ADDR,
	AI_GEN_TRNG,
};

enum {
	AUTHPAD_PAD,
	AUTHPAD_NOPAD,
};

enum sec_cipher_dir {
	SEC_CIPHER_ENC = 0x1,
	SEC_CIPHER_DEC = 0x2,
};

struct hisi_sec_ctx {
	struct wd_ctx_config config;
};

struct hisi_sec_sqe_type2 {
	/*
	 * mac_len: 0~4 bits
	 * a_key_len : 5~10 bits
	 * a_alg : 11~16 bits
	 */
	__u32 mac_key_alg;

	/*
	 * c_icv_len: 0~5 bits
	 * c_width: 6~8 bits
	 * c_key_len: 9~11 bits
	 * c_mode: 12~15 bits
	 */
	__u16 icvw_kmode;

	/* c_alg; 0~3 bits */
	__u8 c_alg;

	__u8 rsvd4;
	/*
	 * a_len: 0~23 bits
	 * iv_offset_l:24~31 bits
	 */
	__u32 alen_ivllen;

	/*
	 * a_len: 0~23 bits
	 * iv_offset_h:24~31 bits
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
	 * c_pad_len : 4~11 bits
	 * c_pad_data_type:12~15 bits
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
	 *  csc:4~6 bits
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
	 * cipher : 4~5 bits;
	 * auth : 6~7 bits;
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
	 * src_addr_type 0~1 bits not used now.
	 * dst_addr_type 2~4 bits;
	 * mac_addr_type 5~7 bits;
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
	 * write_frame_len(type2):5~7bits;
	 */
	__u8 rca_key_frm;

	__u8 iv_tls_ld;
	
	struct hisi_sec_sqe_type2 type2;
};

static int g_digest_a_alg[WD_DIGEST_TYPE_MAX] = {
	A_ALG_SM3, A_ALG_MD5, A_ALG_SHA1, A_ALG_SHA256, A_ALG_SHA224,
	A_ALG_SHA384, A_ALG_SHA512, A_ALG_SHA512_224, A_ALG_SHA512_256
};
static int g_hmac_a_alg[WD_DIGEST_TYPE_MAX] = {
	A_ALG_HMAC_SM3, A_ALG_HMAC_MD5, A_ALG_HMAC_SHA1,
	A_ALG_HMAC_SHA256, A_ALG_HMAC_SHA224, A_ALG_HMAC_SHA384,
	A_ALG_HMAC_SHA512, A_ALG_HMAC_SHA512_224, A_ALG_HMAC_SHA512_256
};

/* fix me */
#define SEC_QP_NUM_PER_PROCESS	  1
#define MAX_CIPHER_RETRY_CNT	  20000000

#ifdef DEBUG
static void hexdump(char *buff, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		printf("\\0x%02x", buff[i]);
		if ((i + 1) % (WORD_BYTES << 1) == 0)
			printf("\n");
	}
	printf("\n");
}

static void sec_dump_bd(unsigned char *bd, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		WD_ERR("\\%02x", bd[i]);
		if ((i + 1) % (WORD_BYTES << 1) == 0)
			WD_ERR("\n");
	}
	WD_ERR("\n");
}
#endif

static void update_iv(struct wd_cipher_msg *msg)
{

}

int hisi_sec_init(struct wd_ctx_config *config, void *priv)
{
	/* allocate qp for each context */
	struct hisi_qm_priv qm_priv;
	struct hisi_sec_ctx *sec_ctx = (struct hisi_sec_ctx *)priv;
	handle_t h_ctx, h_qp;
	int i, j;

	qm_priv.sqe_size = sizeof(struct hisi_sec_sqe);
	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.op_type = config->ctxs[i].op_type;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp)
			goto out;
		memcpy(&sec_ctx->config, config, sizeof(struct wd_ctx_config));
	}
	memcpy(&sec_ctx->config, config, sizeof(struct wd_ctx_config));
	return 0;
out:
	for (j = 0; j < i; j++) {
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

	struct hisi_sec_ctx *sec_ctx = (struct hisi_sec_ctx *)priv;
	struct wd_ctx_config *config = &sec_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
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
	case WD_CIPHER_CTR:
		c_mode = C_MODE_CTR;
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
	if (msg->in_bytes > MAX_CIPHER_LEN) {
		WD_ERR("input cipher len is too large!\n");
		return -EINVAL;
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
	de = 0x1 << SEC_DE_OFFSET;
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
		WD_ERR("faile to fill bd alg!\n");
		return ret;
	}

	ret = fill_cipher_bd2_mode(msg, &sqe);
	if (ret) {
		WD_ERR("faile to fill bd mode!\n");
		return ret;
	}

	sqe.type2.clen_ivhlen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)msg->in;
	sqe.type2.data_dst_addr = (__u64)msg->out;
	sqe.type2.c_ivin_addr = (__u64)msg->iv;
	sqe.type2.c_key_addr = (__u64)msg->key;

	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		WD_ERR("hisi qm send is err(%d)!\n", ret);
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

	/* parser cipher sqe */
	parse_cipher_bd2(&sqe, recv_msg);

	return 1;
}

static struct wd_cipher_driver hisi_cipher_driver = {
		.drv_name	= "hisi_sec2",
		.alg_name	= "cipher",
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
		.cipher_send	= hisi_sec_cipher_send,
		.cipher_recv	= hisi_sec_cipher_recv,
};

WD_CIPHER_SET_DRIVER(hisi_cipher_driver);

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
	else if (msg->mode == WD_DIGEST_HMAC)
		sqe->type2.mac_key_alg |=
		g_hmac_a_alg[msg->alg] << AUTH_ALG_OFFSET;
	else {
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

#ifdef DEBUG
	WD_ERR("Dump digest recv sqe-->!\n");
	sec_dump_bd((unsigned char *)sqe, SQE_BYTES_NUMS);
#endif
}

int hisi_sec_digest_send(handle_t ctx, struct wd_digest_msg *msg)
{
	struct wd_digest_tag *tag = (void *)(uintptr_t)msg->usr_data;
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
	de = 0x0 << SEC_DE_OFFSET;

	sqe.sds_sa_type = (__u8)(de | scene);
	sqe.type2.alen_ivllen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)msg->in;
	sqe.type2.mac_addr = (__u64)msg->out;

	if (msg->mode == WD_DIGEST_HMAC) {
		if (msg->key_bytes & WORD_ALIGNMENT_MASK) {
			WD_ERR("Invalid digest key_bytes!\n");
			return -WD_EINVAL;
		}
		sqe.type2.mac_key_alg = (msg->key_bytes /
			WORD_BYTES) << MAC_LEN_OFFSET;
		sqe.type2.c_key_addr = (__u64)msg->key;
	}

	ret = fill_digest_bd2_alg(msg, &sqe);
	if (ret) {
		WD_ERR("Fail to fill digest bd alg!\n");
		return ret;
	}

	qm_fill_digest_long_bd(msg, &sqe);

#ifdef DEBUG
	WD_ERR("Dump digest send sqe-->!\n");
	sec_dump_bd((unsigned char *)&sqe, SQE_BYTES_NUMS);
#endif

	if (tag)
		sqe.type2.tag = tag->wd_tag.ctx_id;

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
		.digest_send	= hisi_sec_digest_send,
		.digest_recv	= hisi_sec_digest_recv,
};

WD_DIGEST_SET_DRIVER(hisi_digest_driver);

