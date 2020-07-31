/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HISI_SEC_USR_IF_H
#define HISI_SEC_USR_IF_H

#include <asm/types.h>

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

#endif
