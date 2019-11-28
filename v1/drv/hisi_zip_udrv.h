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

#ifndef HISI_ZIP_USR_IF_H
#define HISI_ZIP_USR_IF_H

#include "hisi_qm_udrv.h"

enum hw_comp_alg_type {
	HW_ZLIB  = 0x02,
	HW_GZIP,
};

enum hw_zip_cipher_alg_type {
	HW_XTS_AES_128 = 0x10,
	HW_XTS_AES_256 = 0x20,
	HW_XTS_SM4_128 = 0x30,
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

#define HZ_BUF_TYPE_SHIFT 8
#define HZ_ALIGN_SIZE_SHIFT 16
#define HZ_GRD_GTYPE_SHIFT 4
#define HZ_VER_GTYPE_SHIFT 8
#define HZ_APP_GTYPE_SHIFT 12
#define HZ_APP_SHIFT 16
#define HZ_VER_SHIFT 24
#define HZ_PAD_TYPE_SHIFT 4
#define HZ_GRD_VTYPE_SHIFT 8
#define HZ_REF_VTYPE_SHIFT 12
#define HZ_BLK_SIZE_SHIFT 16
#define HZ_CTX_ST_MASK 0x000f
#define HZ_LSTBLK_MASK 0x0100
#define HZ_STATUS_MASK 0xff
#define HZ_REQ_TYPE_MASK 0xff

int qm_fill_zip_sqe(void *smsg, struct qm_queue_info *info, __u16 i);
int qm_parse_zip_sqe(void *msg,
		     const struct qm_queue_info *info, __u16 i, __u16 usr);
int qm_fill_zip_cipher_sqe(void *smsg, struct qm_queue_info *info, __u16 i);
int qm_parse_zip_cipher_sqe(void *hw_msg, const struct qm_queue_info *info,
		     __u16 i, __u16 usr);

#endif
