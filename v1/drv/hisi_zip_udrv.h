/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HISI_ZIP_USR_IF_H
#define HISI_ZIP_USR_IF_H

#include "hisi_qm_udrv.h"

enum hw_comp_alg_type {
	HW_ZLIB  = 0x02,
	HW_GZIP,
};

enum hw_flush {
	HZ_SYNC_FLUSH,
	HZ_FINISH,
};

struct hisi_zip_sqe {
	__u32 consumed;
	__u32 produced;
	__u32 comp_data_length;
	__u32 dw3;
	__u32 input_data_length;
	__u32 lba_l;
	__u32 lba_h;
	__u32 dw7;
	__u32 dw8;
	__u32 dw9;
	__u32 dw10;
	__u32 priv_info;
	__u32 dw12;
	__u32 tag;
	__u32 dest_avail_out;
	__u32 ctx_dw0;
	__u32 comp_head_addr_l;
	__u32 comp_head_addr_h;
	__u32 source_addr_l;
	__u32 source_addr_h;
	__u32 dest_addr_l;
	__u32 dest_addr_h;
	__u32 stream_ctx_addr_l;
	__u32 stream_ctx_addr_h;
	__u32 cipher_key1_addr_l;
	__u32 cipher_key1_addr_h;
	__u32 cipher_key2_addr_l;
	__u32 cipher_key2_addr_h;
	__u32 ctx_dw1;
	__u32 ctx_dw2;
	__u32 isize;
	__u32 checksum;

};
#define DECOMP_STREAM_END 0x113
#define DECOMP_STREAM_END_MASK 0x1ff
#define STREAM_FLUSH_SHIFT 25

int qm_fill_zip_sqe(void *smsg, struct qm_queue_info *info, __u16 i);
int qm_parse_zip_sqe(void *msg,
		     const struct qm_queue_info *info, __u16 i, __u16 usr);
#endif
