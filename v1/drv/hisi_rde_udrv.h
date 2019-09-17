/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __HISI_RDE_UDRV_H__
#define __HISI_RDE_UDRV_H__

#include <linux/types.h>
#include "hisi_qm_udrv.h"

#define RDE_FLEXEC_CMSIZE		1024
#define RDE_MPCC_CMSIZE		2176
#define RDE_PER_SRC_COEF_SIZE	32
#define RDE_PER_SRC_COEF_TIMES	4
#define RDE_MEM_SAVE_SHIFT		2
#define RDE_BUF_TYPE_SHIFT		3
#define RDE_EC_TYPE_SHIFT		5
#define RDE_UPD_GN_FLAG		0x80
#define RDE_UPD_PARITY_SHIFT		7
#define RDE_SGL_OFFSET_SHIFT		8
#define RDE_COEF_GF_SHIFT		32
#define RDE_LBA_BLK			8
#define RDE_LBA_DWORD_CNT		5
#define DIF_CHK_GRD_CTRL_SHIFT	4
#define DIF_CHK_REF_CTRL_SHIFT	32
#define DIF_LBA_SHIFT			32
#define DIF_GEN_PAD_CTRL_SHIFT	32
#define DIF_GEN_REF_CTRL_SHIFT	35
#define DIF_GEN_APP_CTRL_SHIFT	38
#define DIF_GEN_VER_CTRL_SHIFT	41
#define DIF_GEN_GRD_CTRL_SHIFT	44
#define DIF_APP_TAG_SHIFT		48
#define DIF_VERSION_SHIFT		56
#define RDE_TASK_STATUS		0x80
#define RDE_STATUS_MSK		0x7f
#define RDE_DONE_MSK			0x1
#define RDE_DONE_SHIFT		7

#define RDE_GN_CNT(i)	(((i + 1) % 2 == 0) ? (i + 1) >> 1 : (i + 2) >> 1)
#define RDE_GN_FLAG(i)		(((i + 1) % 2 == 0) ? 2 : 1)
#define RDE_GN_SHIFT(x)	(RDE_COEF_GF_SHIFT * (x == 1 ? 1 : 0))
#define RDE_LBA_CNT(i)	((i % 2 == 0) ? (i >> 1) : ((i - 1) >> 1))

enum {
	CM_ENCODE = 0, /* encode type */
	CM_DECODE = 1, /* decode type */
};

enum {
	NO_ABORT = 0, /* don't abort the io */
	ABORT = 1, /* abort the io */
};

enum {
	NO_CRCIV = 0, /* default IV is 0 */
	CRCIV = 1, /* IV is register's value */
};

enum {
	CRCIV0 = 0, /* select crc16_iv0 of register */
	CRCIV1 = 1, /* select crc16_iv1 of register */
};

enum {
	NO_RDE_DIF = 0, /* without DIF */
	RDE_DIF = 1, /* DIF */
};

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
	__u64 crciv_sel: 1;
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

/**
 * @brief sgl structure for rde.
 * @note
 * parity is just valid in update mode
 */
struct rde_sgl {
	/* source and destination data block SGL address */
	struct wd_sgl *ctrl;
	/* offset of per data disk in the SGL chain */
	__u32 buf_offset;
	/* data disk is 0, parity disk is 1 */
	__u8 parity;
	__u8 reserve;
	/* the index corresponding to src and dst disk */
	__u8 column;
};

int qm_fill_rde_sqe(void *rmsg, struct qm_queue_info *info, __u16 i);
int qm_parse_rde_sqe(void *hw_msg, const struct qm_queue_info *info,
	__u16 i, __u16 usr);

#endif
