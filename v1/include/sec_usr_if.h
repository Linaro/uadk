/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_SEC_USR_IF_H
#define HISI_SEC_USR_IF_H

typedef unsigned int __u32;

struct hisi_sec_sqe_type1 {
	__u32 rsvd2:6;
	__u32 ci_gen:2;
	__u32 ai_gen:2;
	__u32 rsvd1:7;
	__u32 c_key_type:2;
	__u32 a_key_type:2;
	__u32 rsvd0:10;
	__u32 inveld:1;
	__u32 mac_len:6;
	__u32 a_key_len:5;
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
		struct hisi_sec_sqe_type1 type1; /* storage sence */
		struct hisi_sec_sqe_type2 type2; /* the other sence */
	};
};

enum C_MODE {
	ECB = 0x0,
	CBC = 0x1,
	CTR = 0x4,
	CCM = 0x5,
	GCM = 0x6,
	XTS = 0x7,
};

enum C_ALG {
	DES = 0x0,
	TRIPLEDES = 0x1,
	AES = 0x2,
	SM4 = 0x3,
};

#endif
