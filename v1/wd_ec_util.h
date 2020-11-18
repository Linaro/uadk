/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_EC_UTIL_H
#define __WD_EC_UTIL_H

#include <linux/types.h>

#define SRC_ADDR_TABLE_NUM		48
#define SRC_DIF_TABLE_NUM		20
#define DST_ADDR_TABLE_NUM		26
#define DST_DIF_TABLE_NUM		17
#define RDE_TLB_MEMSIZE		4096

/* src data addr table, should be 64byte aligned.*/
struct rde_src_tbl {
	__u64 content[SRC_ADDR_TABLE_NUM];
};

/* src data dif table, should be 64byte aligned.*/
struct rde_src_tag_tbl {
	__u64 content[SRC_DIF_TABLE_NUM];
	__u64 reserve[4];
};

/* dst data addr table, should be 64byte aligned.*/
struct rde_dst_tbl {
	__u64 content[DST_ADDR_TABLE_NUM];
	__u64 reserve[6];
};

/* dst data dif table, should be 64byte aligned.*/
struct rde_dst_tag_tbl {
	__u64 content[DST_DIF_TABLE_NUM];
	__u64 reserve[7];
};

struct wcrypto_ec_table {
	struct rde_src_tbl *src_addr;
	__u64 src_addr_pa;
	struct rde_dst_tbl *dst_addr;
	__u64 dst_addr_pa;
	struct rde_src_tag_tbl *src_tag_addr;
	__u64 src_tag_addr_pa;
	struct rde_dst_tag_tbl *dst_tag_addr;
	__u64 dst_tag_addr_pa;
	__u8 *matrix;
	__u64 matrix_pa;
};

/**
 * @brief dif pad type
 */
enum DIF_PAGE_LAYOUT_PAD_TYPE_E {
	DIF_PAGE_LAYOUT_PAD_NONE = 0x0,
	DIF_PAGE_LAYOUT_PAD_AHEAD_DIF = 0x1, /* 4096+56+8 */
	DIF_PAGE_LAYOUT_PAD_BEHIND_DIF = 0x2, /* 4096+8+56 */
	DIF_PAGE_LAYOUT_PAD_BUTT
};

/**
 * @brief dif pad gen mode enumeration, rde only support 0,3,5.
 */
enum DIF_PAGE_LAYOUT_PAD_GEN_CTRL_E {
	DIF_PAGE_LAYOUT_PAD_GEN_NONE = 0x0,
	DIF_PAGE_LAYOUT_PAD_GEN_FROM_ZERO = 0x3,
	DIF_PAGE_LAYOUT_PAD_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_PAGE_LAYOUT_PAD_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_PAGE_LAYOUT_PAD_GEN_BUTT
};

/**
 * @brief dif grd gen mode enumeration.
 */
enum DIF_GRD_GEN_CTRL_E {
	DIF_GRD_GEN_NONE = 0x0,
	DIF_GRD_GEN_FROM_T10CRC = 0x1,
	DIF_GRD_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_GRD_GEN_BUTT
};

/**
 * @brief dif ver gen mode enumeration, rde only support 0 or 1.
 */
enum DIF_VER_GEN_CTRL_E {
	DIF_VER_GEN_NONE = 0x0,
	DIF_VER_GEN_FROM_INPUT = 0x1,
	DIF_VER_GEN_FROM_ZERO = 0x3,
	DIF_VER_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_VER_GEN_BUTT
};

/**
 * @brief dif app gen mode enumeration, rde only support 0,1,5.
 */
enum DIF_APP_GEN_CTRL_E {
	DIF_APP_GEN_NONE = 0x0,
	DIF_APP_GEN_FROM_INPUT = 0x1,
	DIF_APP_GEN_FROM_ZERO = 0x3,
	DIF_APP_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_APP_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_APP_GEN_BUTT
};

/**
 * @brief dif ref gen mode enumeration, rde only support 0,1,2,5.
 */
enum DIF_REF_GEN_CTRL_E {
	DIF_REF_GEN_NONE = 0x0,
	DIF_REF_GEN_FROM_INPUT_LBA = 0x1,
	DIF_REF_GEN_FROM_PRIVATE_INFO = 0x2,
	DIF_REF_GEN_FROM_ZERO = 0x3,
	DIF_REF_GEN_FROM_SOURCE_DATA = 0x4,
	DIF_REF_GEN_FROM_RAID_OR_EC = 0x5,
	DIF_REF_GEN_BUTT
};

/**
 * @brief dif verify mode enumeration, grd: rde only support 0,1,2.
 */
enum DIF_VERIFY_CTRL_E {
	DIF_VERIFY_NONE = 0x0,
	DIF_VERIFY_DO_NOT_VERIFY = 0x1,
	DIF_VERIFY_ALL_BLOCK = 0x2,
	DIF_VERIFY_BY_PRIVATE_INFO = 0x3,
	DIF_VERIFY_BUTT
};

/**
 * @brief sge structure, should fill buf and len.
 * @note
 * usually, just need to fill buf and len
 */
struct sgl_entry_hw {
	__u8 *buf;	/* Start address of page data, 64bit */
	void *page_ctrl;
	__u32 len;	/* Valid data length in Byte */
	__u32 pad;
	__u32 pad0;
	__u32 pad1;
};

/**
 * @brief sgl  structure.
 * @note
 * usually, just need to  fill next, entry_sum_in_chain, entry_sum_in_sgl,
 *	entry_num_in_sgl and entry
 * entry_sum_in_chain is valid from the first sgl
 * entry_sum_in_sgl <= entry_num_in_sgl
 * sgl_entry point is determined by entry_sum_in_sgl
 */
struct sgl_hw {
	/* next sgl point, to make up chain, 64bit */
	struct sgl_hw *next;
	/* sum of entry_sum_in_sgl in sgl chain */
	__u16 entry_sum_in_chain;
	/* valid sgl_entry num in this sgl */
	__u16 entry_sum_in_sgl;
	/* sgl_entry num in this sgl */
	__u16 entry_num_in_sgl;
	__u8 pad0[2];
	__u64 serial_num;
	__u32 flag;
	__u32 cpu_id;
	__u8 pad1[8];
	__u8 reserved[24];
	/* sgl_entry point */
	struct sgl_entry_hw entries[0];
};

/**
 * @brief sgl structure for rde.
 * @note
 * parity is just valid in update mode
 */
struct rde_sgl {
	/* source and destination data block SGL address */
	struct sgl_hw *ctrl;
	/* offset of per data disk in the SGL chain */
	__u32 buf_offset;
	/* data disk is 0, parity disk is 1 */
	__u8 parity;
	__u8 reserve;
	/* the index corresponding to src and dst disk */
	__u8 column;
};

/**
 * @brief dif data structure.
 */
struct dif_data {
	__u16 grd;  /*16bit gurad tag */
	__u8 ver;   /* 8bit version */
	__u8 app;   /* 8bit application information field */
	__u32 ref;  /* 32bit reference tag */
};

/**
 * @brief dif gen ctrl structure.
 */
struct dif_gen {
	/* DIF_PAGE_LAYOUT_PAD_GEN_CTRL_E */
	__u32 page_layout_gen_type:4;
	/* DIF_GRD_GEN_CTRL_E */
	__u32 grd_gen_type:4;
	/* DIF_VER_GEN_CTRL_E */
	__u32 ver_gen_type:4;
	/* DIF_APP_GEN_CTRL_E */
	__u32 app_gen_type:4;
	/* DIF_REF_GEN_CTRL_E */
	__u32 ref_gen_type:4;
	/* DIF_PAGE_LAYOUT_PAD_TYPE_E */
	__u32 page_layout_pad_type:2;
	__u32 reserved:10;
};

/**
 * @brief dif verify ctrl structure.
 * @note
 * just need to fill grd_verify_type and ref_verify_type
 */
struct dif_verify {
	__u16 page_layout_pad_type:2;
	__u16 grd_verify_type:4; /* DIF_VERIFY_CTRL_E */
	__u16 ref_verify_type:4; /* DIF_VERIFY_CTRL_E */
	__u16 reserved:6;
};

/**
 * @brief dif ctrl structure.
 */
struct dif_ctrl {
	struct dif_gen gen;
	struct dif_verify verify;
};

/**
 * @brief general dif structure.
 * @note
 * RDE need not to fill lba
 */
struct hw_dif {
	__u64 lba; /* lba for dif ref field */
	__u32 priv; /* private info for dif ref field */
	__u8 ver; /* 8bit version */
	__u8 app; /* 8bit application information field */
	struct dif_ctrl ctrl;
};

struct wcrypto_ec_priv_data {
	struct hw_dif src_dif;
	struct hw_dif dst_dif;
};

#endif
