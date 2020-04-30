/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_RDE_USR_IF_H
#define HISI_RDE_USR_IF_H

#include <linux/types.h>

struct hisi_rde_sqe {
	__u64 rsvd0: 16;
	__u64 op_tag: 16;
	__u64 alg_blk_size: 2;
	__u64 cm_type: 1;
	__u64 cm_le: 1;
	__u64 abort: 1;
	__u64 src_nblks: 6;
	__u64 dst_nblks: 5;
	__u64 chk_dst_ref_ctrl: 4;
	__u64 chk_dst_grd_ctrl: 4;
	__u64 op_type: 8;
	__u64 block_size: 16;
	__u64 page_pad_type: 2;
	__u64 dif_type: 1;
	__u64 rsvd1: 3;
	__u64 crciv_sei: 1;
	__u64 crciv_en: 1;
	__u64 status: 8;
	__u64 rsvd2: 10;
	__u64 cm_len: 6;
	__u64 transfer_size: 16;
	__u64 coef_matrix_addr;
	__u64 src_addr;
	__u64 src_tag_addr;
	__u64 dst_addr;
	__u64 dst_tag_addr;
	__u64 dw7;
};

#endif
