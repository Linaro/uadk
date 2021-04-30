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

#ifndef __HISI_SEC_DRV_H__
#define __HISI_SEC_DRV_H__

#include <linux/types.h>
#include "config.h"
#include "v1/wd.h"
#include "v1/wd_util.h"
#include "v1/wd_cipher.h"
#include "v1/wd_digest.h"
#include "v1/wd_aead.h"

#include "v1/drv/hisi_qm_udrv.h"

typedef unsigned int __u32;
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned long long __u64;

/* The max BD cipher length is 16M-512B */
#define MAX_CIPHER_LENGTH		16776704
#define SEC_SQE_LEN_RATE	4

struct hisi_sec_sqe_type1 {
	__u32 rsvd2:6;
	__u32 ci_gen:2;
	__u32 ai_gen:2;
	__u32 rsvd1:7;
	__u32 c_key_type:2;
	__u32 a_key_type:2;
	__u32 rsvd0:10;
	__u32 inveld:1;
	__u32 mac_len:5;
	__u32 a_key_len:6;
	__u32 a_alg:6;
	__u32 rsvd3:15;
	__u32 c_icv_len:6;
	__u32 c_width:3;
	__u32 c_key_len:3;
	__u32 c_mode:4;
	__u32 c_alg:4;
	__u32 rsvd4:12;
	__u32 dw4;
	__u32 dw5;
	__u32 auth_src_offset:16;
	__u32 cipher_src_offset:16;
	__u32 gran_num:16;
	__u32 rsvd5:16;
	__u32 src_skip_data_len:24;
	__u32 rsvd6:8;
	__u32 dst_skip_data_len:24;
	__u32 rsvd7:8;
	__u32 tag:16;
	__u32 rsvd8:16;
	__u32 gen_page_pad_ctrl:4;
	__u32 gen_grd_ctrl:4;
	__u32 gen_ver_ctrl:4;
	__u32 gen_app_ctrl:4;
	__u32 gen_ver_val:8;
	__u32 gen_app_val:8;
	__u32 private_info;
	__u32 gen_ref_ctrl:4;
	__u32 page_pad_type:2;
	__u32 rsvd9:2;
	__u32 chk_grd_ctrl:4;
	__u32 chk_ref_ctrl:4;
	__u32 block_size:16;
	__u32 lba_l;
	__u32 lba_h;
	__u32 a_key_addr_l;
	__u32 a_key_addr_h;
	__u32 mac_addr_l;
	__u32 mac_addr_h;
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 c_key_addr_l;
	__u32 c_key_addr_h;
	__u32 data_src_addr_l;
	__u32 data_src_addr_h;
	__u32 data_dst_addr_l;
	__u32 data_dst_addr_h;
	__u32 done:1;
	__u32 icv:3;
	__u32 rsvd11:3;
	__u32 flag:4;
	__u32 dif_check:3;
	__u32 rsvd10:2;
	__u32 error_type:8;
	__u32 warning_type:8;
	__u32 dw29;
	__u32 dw30;
	__u32 dw31;
};

struct hisi_sec_sqe_type2 {
	__u32 nonce_len:4;
	__u32 huk:1;
	__u32 key_s:1;
	__u32 ci_gen:2;
	__u32 ai_gen:2;
	__u32 a_pad:2;
	__u32 c_s:2;
	__u32 rsvd1:2;
	__u32 rhf:1;
	__u32 c_key_type:2;
	__u32 a_key_type:2;
	__u32 write_frame_len:3;
	__u32 cal_iv_addr_en:1;
	__u32 tls_up:1;
	__u32 rsvd0:5;
	__u32 inveld:1;
	__u32 mac_len:5;
	__u32 a_key_len:6;
	__u32 a_alg:6;
	__u32 rsvd3:15;
	__u32 c_icv_len:6;
	__u32 c_width:3;
	__u32 c_key_len:3;
	__u32 c_mode:4;
	__u32 c_alg:4;
	__u32 rsvd4:12;
	__u32 a_len:24;
	__u32 iv_offset_l:8;
	__u32 c_len:24;
	__u32 iv_offset_h:8;
	__u32 auth_src_offset:16;
	__u32 cipher_src_offset:16;
	__u32 cs_ip_header_offset:16;
	__u32 cs_udp_header_offset:16;
	__u32 pass_word_len:16;
	__u32 dk_len:16;
	__u32 salt3:8;
	__u32 salt2:8;
	__u32 salt1:8;
	__u32 salt0:8;
	__u32 tag:16;
	__u32 rsvd5:16;
	__u32 c_pad_type:4;
	__u32 c_pad_len:8;
	__u32 c_pad_data_type:4;
	__u32 c_pad_len_field:2;
	__u32 rsvd6:14;
	__u32 long_a_data_len_l;
	__u32 long_a_data_len_h;
	__u32 a_ivin_addr_l;
	__u32 a_ivin_addr_h;
	__u32 a_key_addr_l;
	__u32 a_key_addr_h;
	__u32 mac_addr_l;
	__u32 mac_addr_h;
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 c_key_addr_l;
	__u32 c_key_addr_h;
	__u32 data_src_addr_l;
	__u32 data_src_addr_h;
	__u32 data_dst_addr_l;
	__u32 data_dst_addr_h;
	__u32 done:1;
	__u32 icv:3;
	__u32 rsvd11:3;
	__u32 flag:4;
	__u32 rsvd10:5;
	__u32 error_type:8;
	__u32 warning_type:8;
	__u32 mac_i3:8;
	__u32 mac_i2:8;
	__u32 mac_i1:8;
	__u32 mac_i0:8;
	__u32 check_sum_i:16;
	__u32 tls_pad_len_i:8;
	__u32 rsvd12:8;
	__u32 counter;
};

struct hisi_sec_sqe {
	__u32 type:4;
	__u32 cipher:2;
	__u32 auth:2;
	__u32 seq:1;
	__u32 de:2;
	__u32 scene:4;
	__u32 src_addr_type:3;
	__u32 dst_addr_type:3;
	__u32 mac_addr_type:3;
	__u32 rsvd0:8;
	union {
		struct hisi_sec_sqe_type1 type1; /* storage scene */
		struct hisi_sec_sqe_type2 type2; /* the other scene */
	};
};

struct bd3_auth_key_iv {
	__u32 a_key_addr_l;
	__u32 a_key_addr_h;
	__u32 a_ivin_addr_l;
	__u32 a_ivin_addr_h;
	__u32 rsvd0;
	__u32 rsvd1;
};

struct bd3_skip_data {
	__u32 c_iv_a_key_l;
	__u32 c_iv_a_key_h;
	__u32 rsvd0;
	__u32 gran_num:16;
	__u32 rsvd1:16;
	__u32 src_skip_data_len:25;
	__u32 rsvd2:7;
	__u32 dst_skip_data_len:25;
	__u32 rsvd3:7;
};

struct bd3_ipsec_scene {
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 c_s:2;
	__u32 deal_esp_ah:4;
	__u32 protocol_type:4;
	__u32 mode:2;
	__u32 ip_type:2;
	__u32 mac_sel:1;
	__u32 rsvd0:1;
	__u32 next_header:8;
	__u32 pad_len:8;
	__u32 iv_offset:16;
	__u32 rsvd1:16;
	__u32 cs_ip_header_offset:16;
	__u32 cs_udp_header_offset:16;
};

struct bd3_pbkdf2_scene {
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 pbkdf2_salt_len:24;
	__u32 rsvd0:8;
	__u32 c_num:24;
	__u32 rsvd1:8;
	__u32 pass_word_len:16;
	__u32 dk_len:16;
};

struct bd3_stream_scene {
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 long_a_data_len_l;
	__u32 long_a_data_len_h;
	__u32 auth_pad:2;
	__u32 stream_protocol:3;
	__u32 mac_sel:1;
	__u32 rsvd0:2;
	__u32 plaintext_type:8;
	__u32 pad_len_1p3:16;
};

struct bd3_dtls_scene {
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 sn_l;
	__u32 sn_h;
	__u32 c_pad_type:4;
	__u32 c_pad_len:8;
	__u32 c_pad_data_type:4;
	__u32 c_pad_len_field:2;
	__u32 tls_len_update:1;
	__u32 rsvd0:13;
};

struct bd3_tls1p3_scene {
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 a_ivin_addr_l;
	__u32 a_ivin_addr_h;
	__u32 deal_tls_1p3:3;
	__u32 mac_sel:1;
	__u32 rsvd0:4;
	__u32 plaintext_type:8;
	__u32 pad_len_1p3:16;
};

struct bd3_storage_scene {
	__u32 lba_l;
	__u32 lba_h;
	__u32 gen_page_pad_ctrl:4;
	__u32 gen_grd_ctrl:4;
	__u32 gen_ver_ctrl:4;
	__u32 gen_app_ctrl:4;
	__u32 gen_ver_val:8;
	__u32 gen_app_val:8;
	__u32 private_info;
	__u32 gen_ref_ctrl:4;
	__u32 page_pad_type:2;
	__u32 pagePadNogen:1;
	__u32 pagePadNocheck:1;
	__u32 chk_grd_ctrl:4;
	__u32 chk_ref_ctrl:4;
	__u32 block_size:16;
};

struct bd3_no_scene {
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 rsvd0;
	__u32 rsvd1;
	__u32 rsvd2;
};

struct bd3_check_sum {
	__u32 rsvd0:8;
	__u32 hac_sva_status:8;
	__u32 check_sum_i:16;
};

struct bd3_tls_type_back {
	__u32 tls_1p3_type_back:8;
	__u32 hac_sva_status:8;
	__u32 pad_len_1p3_back:16;
};

/* the kp930 sence */
struct hisi_sec_bd3_sqe {
	__u32 type:4;
	__u32 inveld:1;
	__u32 scene:4;
	__u32 de:2;
	__u32 src_addr_type:3;
	__u32 dst_addr_type:3;
	__u32 mac_addr_type:3;
	__u32 rsvd:12;

	__u32 cipher:2;
	__u32 ci_gen:2;
	__u32 c_icv_len:6;
	__u32 c_width:3;
	__u32 c_key_len:3;
	__u32 c_mode:4;
	__u32 c_alg:4;
	__u32 nonce_len:4;
	__u32 rsv:1;
	__u32 cal_iv_addr_en:1;
	__u32 seq:1;
	__u32 rsvd0:1;

	__u32 tag_l;
	__u32 tag_h;
	__u32 data_src_addr_l;
	__u32 data_src_addr_h;

	union {
		struct bd3_auth_key_iv auth_key_iv;
		struct bd3_skip_data skip_data;
	};

	__u32 c_key_addr_l;
	__u32 c_key_addr_h;
	__u32 auth:2;
	__u32 ai_gen:2;
	__u32 mac_len:5;
	__u32 a_key_len:6;
	__u32 a_alg:6;
	__u32 key_sel:4;
	__u32 ctr_counter_mode:2;
	__u32 sva_prefetch:1;
	__u32 key_wrap_num:3;
	__u32 update_key:1;

	__u32 salt3:8;
	__u32 salt2:8;
	__u32 salt1:8;
	__u32 salt0:8;
	__u32 auth_src_offset:16;
	__u32 cipher_src_offset:16;
	__u32 a_len:24;
	__u32 auth_key_offset:8;
	__u32 c_len:24;
	__u32 auth_ivin_offset:8;
	__u32 data_dst_addr_l;
	__u32 data_dst_addr_h;
	__u32 mac_addr_l;
	__u32 mac_addr_h;
	union {
		struct bd3_ipsec_scene ipsec_scene;
		struct bd3_pbkdf2_scene pbkdf2_scene;
		struct bd3_stream_scene stream_scene;
		struct bd3_dtls_scene dtls_scene;
		struct bd3_tls1p3_scene tls1p3_scene;
		struct bd3_storage_scene storage_scene;
		struct bd3_no_scene no_scene;
	};

	__u32 done:1;
	__u32 icv:3;
	__u32 csc:3;
	__u32 flag:4;
	__u32 dc:3;
	__u32 rsvd10:2;
	__u32 error_type:8;
	__u32 warning_type:8;
	union {
		__u32 mac_i;
		__u32 kek_key_addr_l;
	};
	union {
		__u32 kek_key_addr_h;
		struct bd3_check_sum check_sum;
		struct bd3_tls_type_back tls_type_back;
	};
	__u32 counter;
};

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
	C_MODE_CBC_CS	= 0x9
};

enum CKEY_LEN {
	CKEY_LEN_128_BIT = 0x0,
	CKEY_LEN_192_BIT = 0x1,
	CKEY_LEN_256_BIT = 0x2,
	CKEY_LEN_SM4	 = 0x0,
	CKEY_LEN_DES	 = 0x1,
	CKEY_LEN_3DES_3KEY = 0x1,
	CKEY_LEN_3DES_2KEY = 0x3,
};

enum {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
	BD_TYPE3 = 0x3,
};

enum {
	NO_CIPHER,
	CIPHER_ENCRYPT,
	CIPHER_DECRYPT,
	REPORT_COPY,
};

enum {
	NO_AUTH,
	AUTH_MAC_CALCULATE,
	AUTH_MAC_VERIFY,
};

enum {
	DATA_DST_ADDR_DISABLE,
	DATA_DST_ADDR_ENABLE,
};

enum {
	SCENE_NOTHING = 0x0,
	SCENE_IPSEC = 0x1,
	SCENE_SSL_TLS = 0x3,
	SCENE_DTLS = 0x4,
	SCENE_STORAGE = 0x5,
	SCENE_NAS = 0x6,
	SCENE_STREAM = 0x7,
	SCENE_PBKDF2 = 0x8,
	SCENE_SMB = 0x9,
};

enum {
	CI_GEN_BY_ADDR = 0x0,
	CI_GEN_BY_LBA  = 0X3,
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

int qm_fill_cipher_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_fill_digest_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_fill_aead_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_fill_cipher_bd3_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_fill_aead_bd3_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_fill_digest_bd3_sqe(void *message, struct qm_queue_info *info, __u16 i);

int qm_parse_cipher_sqe(void *msg, const struct qm_queue_info *info,
			__u16 i, __u16 usr);
int qm_parse_digest_sqe(void *msg, const struct qm_queue_info *info,
			__u16 i, __u16 usr);
int qm_parse_aead_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr);
int qm_parse_cipher_bd3_sqe(void *msg, const struct qm_queue_info *info,
			__u16 i, __u16 usr);
int qm_parse_aead_bd3_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr);
int qm_parse_digest_bd3_sqe(void *msg, const struct qm_queue_info *info,
		__u16 i, __u16 usr);
#endif
