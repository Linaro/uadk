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

#ifndef __HISI_RDE_UDRV_H__
#define __HISI_RDE_UDRV_H__

#include <linux/types.h>
#include "hisi_qm_udrv.h"

#define RDE_FLEXEC_CMSIZE	1024
#define RDE_MPCC_CMSIZE		2176
#define RDE_MPCC_MAX_CMLEN	17
#define RDE_FLEXEC_MAX_CMLEN	32
#define RDE_PER_SRC_COEF_SIZE	32
#define RDE_PER_SRC_COEF_TIMES	4
#define RDE_MEM_SAVE_SHIFT	2
#define RDE_BUF_TYPE_SHIFT	3
#define RDE_EC_TYPE_SHIFT	5
#define RDE_SGL_OFFSET_SHIFT	8
#define DIF_CHK_REF_CTRL_SHIFT	32
#define DIF_GEN_PAD_CTRL_SHIFT	32
#define DIF_GEN_REF_CTRL_SHIFT	35
#define DIF_GEN_APP_CTRL_SHIFT	38
#define DIF_GEN_VER_CTRL_SHIFT	41
#define DIF_GEN_GRD_CTRL_SHIFT	44
#define DIF_APP_TAG_SHIFT	48
#define DIF_VERSION_SHIFT	56
#define RDE_TASK_STATUS		0x80
#define RDE_STATUS_MSK		0x7f
#define RDE_DONE_MSK		0x1
#define RDE_DONE_SHIFT		7


#define RDE_UPDATE_GN(mode, parity) \
	((WCRYPTO_EC_UPDATE ^ mode) ? 0 : (0x80 & (parity << 7)))
#define RDE_GN_CNT(i)   (((i + 1) % 2 == 0) ? (i + 1) >> 1 : (i + 2) >> 1)
#define RDE_GN_FLAG(i)  (((i + 1) % 2 == 0) ? 2 : 1)
#define RDE_GN_SHIFT(i) (32 * (i == 1 ? 1 : 0))
#define RDE_LBA_CNT(i)  ((i / 8 + 1) + \
	((i % 2 == 0) ? (i >> 1) : ((i - 1) >> 1)))
#define RDE_CHK_CTRL_CNT(i)    ((i / 8) * 5)
#define RDE_LBA_SHIFT(i)       (32 * ((i % 2) ^ 1))
#define RDE_CHK_CTRL_VALUE(grd, ref, i) \
	((__u64)(grd << 4 | ref) << (8 * (i % 8)))

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

struct hisi_rde_hw_error {
	__u8 status;
	const char *msg;
};

enum {
	RDE_STATUS_NULL = 0,
	RDE_BD_ADDR_NO_ALIGN = 0x2,
	RDE_BD_RD_BUS_ERR = 0x3,
	RDE_IO_ABORT = 0x4,
	RDE_BD_ERR = 0x5,
	RDE_ECC_ERR = 0x6,
	RDE_SGL_ADDR_ERR = 0x7,
	RDE_SGL_PARA_ERR = 0x8,
	RDE_DATA_RD_BUS_ERR = 0x1c,
	RDE_DATA_WR_BUS_ERR = 0x1d,
	RDE_CRC_CHK_ERR = 0x1e,
	RDE_REF_CHK_ERR = 0x1f,
	RDE_DISK0_VERIFY = 0x20,
	RDE_DISK1_VERIFY = 0x21,
	RDE_DISK2_VERIFY = 0x22,
	RDE_DISK3_VERIFY = 0x23,
	RDE_DISK4_VERIFY = 0x24,
	RDE_DISK5_VERIFY = 0x25,
	RDE_DISK6_VERIFY = 0x26,
	RDE_DISK7_VERIFY = 0x27,
	RDE_DISK8_VERIFY = 0x28,
	RDE_DISK9_VERIFY = 0x29,
	RDE_DISK10_VERIFY = 0x2a,
	RDE_DISK11_VERIFY = 0x2b,
	RDE_DISK12_VERIFY = 0x2c,
	RDE_DISK13_VERIFY = 0x2d,
	RDE_DISK14_VERIFY = 0x2e,
	RDE_DISK15_VERIFY = 0x2f,
	RDE_DISK16_VERIFY = 0x30,
	RDE_CHAN_TMOUT = 0x31,
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

struct blk_dif_gen {
	__u32 page_layout_gen_type:4;
	__u32 grd_gen_type:4;
	__u32 ver_gen_type:4;
	__u32 app_gen_type:4;
	__u32 ref_gen_type:4;
	__u32 page_layout_pad_type:2;
	__u32 reserved:10;
};

struct blk_dif_verify {
	__u16 page_layout_pad_type:2;
	__u16 grd_verify_type:4;
	__u16 ref_verify_type:4;
	__u16 reserved:6;
};

struct blk_dif_ctrl {
	struct blk_dif_gen gen;
	struct blk_dif_verify verify;
};

struct wd_ec_dif {
	__u64 lba;
	__u32 priv;
	__u8 ver;
	__u8 app;
	struct blk_dif_ctrl ctrl;
};

struct wd_ec_sgl {
	struct wd_sgl *ctrl;
	__u32 buf_offset;
	__u8 parity;
	__u8 reserve;
	__u8 column;
};

struct wd_ec_udata {
	void *src_data;
	void *dst_data;
	__u32 src_num;
	__u32 dst_num;
	__u32 block_size;
	__u32 input_block;
	__u32 data_len;
	__u32 buf_type;
	struct wd_ec_dif src_dif;
	struct wd_ec_dif dst_dif;
	__u8 cm_load;
	__u8 cm_len;
	__u8 alg_blk_size;
	__u8 mem_saving;
	void *coe_matrix;
	void *priv;
};

int qm_fill_rde_sqe(void *rmsg, struct qm_queue_info *info, __u16 i);
int qm_parse_rde_sqe(void *hw_msg, const struct qm_queue_info *info,
	__u16 i, __u16 usr);

#endif
