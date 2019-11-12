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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include "wd_util.h"
#include "wd_ec.h"
#include "hisi_rde_udrv.h"

static __u16 g_ref_cnt;

static const struct hisi_rde_hw_error g_rde_hw_error[] = {
	{.status = RDE_BD_ADDR_NO_ALIGN, .msg = "rde bd addr no align err"},
	{.status = RDE_BD_RD_BUS_ERR, .msg = "rde bd read bus err"},
	{.status = RDE_IO_ABORT, .msg = "rde io abort err"},
	{.status = RDE_BD_ERR, .msg = "rde bd config err"},
	{.status = RDE_ECC_ERR, .msg = "rde ecc err"},
	{.status = RDE_SGL_ADDR_ERR, .msg = "rde sgl/prp read bus err"},
	{.status = RDE_SGL_PARA_ERR, .msg = "rde sgl/prp config err"},
	{.status = RDE_DATA_RD_BUS_ERR, .msg = "rde data read bus err"},
	{.status = RDE_DATA_WR_BUS_ERR, .msg = "rde data write bus err"},
	{.status = RDE_CRC_CHK_ERR, .msg = "rde data or parity disk grd err"},
	{.status = RDE_REF_CHK_ERR, .msg = "rde data or parity disk ref err"},
	{.status = RDE_DISK0_VERIFY, .msg = "rde parity disk0 err"},
	{.status = RDE_DISK1_VERIFY, .msg = "rde parity disk1 err"},
	{.status = RDE_DISK2_VERIFY, .msg = "rde parity disk2 err"},
	{.status = RDE_DISK3_VERIFY, .msg = "rde parity disk3 err"},
	{.status = RDE_DISK4_VERIFY, .msg = "rde parity disk4 err"},
	{.status = RDE_DISK5_VERIFY, .msg = "rde parity disk5 err"},
	{.status = RDE_DISK6_VERIFY, .msg = "rde parity disk6 err"},
	{.status = RDE_DISK7_VERIFY, .msg = "rde parity disk7 err"},
	{.status = RDE_DISK8_VERIFY, .msg = "rde parity disk8 err"},
	{.status = RDE_DISK9_VERIFY, .msg = "rde parity disk9 err"},
	{.status = RDE_DISK10_VERIFY, .msg = "rde parity disk10 err"},
	{.status = RDE_DISK11_VERIFY, .msg = "rde parity disk11 err"},
	{.status = RDE_DISK12_VERIFY, .msg = "rde parity disk12 err"},
	{.status = RDE_DISK13_VERIFY, .msg = "rde parity disk13 err"},
	{.status = RDE_DISK14_VERIFY, .msg = "rde parity disk14 err"},
	{.status = RDE_DISK15_VERIFY, .msg = "rde parity disk15 err"},
	{.status = RDE_DISK16_VERIFY, .msg = "rde parity disk16 err"},
	{.status = RDE_CHAN_TMOUT, .msg = "rde channel timeout err"},
	{ /* sentinel */ }
};

#ifdef DEBUG_LOG
static void rde_dump_sqe(struct hisi_rde_sqe *sqe)
{
	int i;

	WD_ERR("[%s][%d]sqe info:\n", __func__, __LINE__);
	for (i = 0; i < sizeof(struct hisi_rde_sqe) / sizeof(__u64); i++)
		WD_ERR("sqe-word[%d]: 0x%llx.\n", i, *((__u64 *)sqe + i));
}

static void rde_dump_table(struct wcrypto_ec_table *tbl)
{
	int i;

	for (i = 0; i < SRC_ADDR_TABLE_NUM; i++) {
		if (tbl->src_addr->content[i])
			WD_ERR("table0 info[%d] is 0x%llx\n",
				i, tbl->src_addr->content[i]);
	}

	for (i = 0; i < SRC_DIF_TABLE_NUM; i++) {
		if (tbl->src_tag_addr->content[i])
			WD_ERR("table1 info[%d] is 0x%llx\n",
				i, tbl->src_tag_addr->content[i]);
	}

	for (i = 0; i < DST_ADDR_TABLE_NUM; i++) {
		if (tbl->dst_addr->content[i])
			WD_ERR("table2 info[%d] is 0x%llx\n",
				i, tbl->dst_addr->content[i]);
	}

	for (i = 0; i < DST_DIF_TABLE_NUM; i++) {
		if (tbl->dst_tag_addr->content[i])
			WD_ERR("table3 info[%d] is 0x%llx\n",
				i, tbl->dst_tag_addr->content[i]);
	}
}
#endif

static __u32 rde_get_matrix_len(__u8 ec_type, __u8 cm_len)
{
	__u32 len = 0;

	switch (ec_type) {
	case WCRYPTO_EC_MPCC:
		len = (RDE_PER_SRC_COEF_SIZE *
			RDE_PER_SRC_COEF_TIMES * cm_len);
		break;
	case WCRYPTO_EC_FLEXEC:
		len = RDE_PER_SRC_COEF_SIZE * cm_len;
		break;
	default:
		WD_ERR("%s(): error ec type.\n", __func__);
		break;
	}

	return len;
}

static void rde_fill_src_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i, gn;
	__u32 sgl_data;
	__u32 gn_cnt, gn_flag, cur_cnt;
	__u8 num = msg->in_disk_num;
	struct wd_rde_sgl *rde_sgl = (struct wd_rde_sgl *)msg->in;
	__u8 mode = msg->op_type;

	for (i = 0; i < num; i++) {
		gn = rde_sgl->column + RDE_UPDATE_GN(mode, rde_sgl->parity);
		sgl_data = (rde_sgl->buf_offset <<
			RDE_SGL_OFFSET_SHIFT) | (__u32)gn;
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		tbl->src_addr->content[cur_cnt] |=
			((__u64)sgl_data << RDE_GN_SHIFT(gn_flag));
		tbl->src_addr->content[gn_cnt] = (uintptr_t)(rde_sgl->sgl);
		rde_sgl++;
	}
}

static void rde_fill_dst_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i, gn;
	__u32 sgl_data;
	__u32 gn_cnt, gn_flag, cur_cnt;
	__u8 num = msg->out_disk_num;
	struct wd_rde_sgl *rde_sgl = (struct wd_rde_sgl *)msg->out;

	for (i = 0; i < num; i++) {
		gn = rde_sgl->column;
		sgl_data = (rde_sgl->buf_offset <<
			RDE_SGL_OFFSET_SHIFT) | (__u32)gn;
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		tbl->dst_addr->content[cur_cnt] |=
			((__u64)sgl_data << RDE_GN_SHIFT(gn_flag));
		tbl->dst_addr->content[gn_cnt] = (uintptr_t)(rde_sgl->sgl);
		rde_sgl++;
	}
}

static void rde_fill_src_dif_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i;
	__u32 cur_cnt1 = 0, cur_cnt2 = 0;
	__u8 num = msg->in_disk_num;
	struct wcrypto_ec_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_rde_udata *pdata = tag->priv;
	__u8 grd = pdata->src_dif.ctrl.verify.grd_verify_type;
	__u8 ref = pdata->src_dif.ctrl.verify.ref_verify_type;

	for (i = 0; i < num; i++) {
		cur_cnt1 = RDE_CHK_CTRL_CNT(i);
		cur_cnt2 = RDE_LBA_CNT(i);
		tbl->src_tag_addr->content[cur_cnt1] |=
			RDE_CHK_CTRL_VALUE(grd, ref, i);
		tbl->src_tag_addr->content[cur_cnt2] |=
			((__u64)pdata->src_dif.priv_info << RDE_LBA_SHIFT(i));
	}
}

static void rde_fill_dst_dif_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i;
	__u8 num = msg->out_disk_num;
	struct wcrypto_ec_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_rde_udata *pdata = tag->priv;

	for (i = 0; i < num; i++) {
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ctrl.gen.page_layout_gen_type)
			<< DIF_GEN_PAD_CTRL_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ctrl.gen.ref_gen_type) <<
			DIF_GEN_REF_CTRL_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ctrl.gen.app_gen_type) <<
			DIF_GEN_APP_CTRL_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ctrl.gen.ver_gen_type) <<
			DIF_GEN_VER_CTRL_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ctrl.gen.grd_gen_type) <<
			DIF_GEN_GRD_CTRL_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			(__u64)pdata->dst_dif.priv_info;
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.app) << DIF_APP_TAG_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ver) << DIF_VERSION_SHIFT);
	}
}

static void rde_table_package(struct hisi_rde_sqe *sqe,
	struct wd_rde_udata *pdata,
	struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	memset(tbl->src_addr, 0, sizeof(struct src_tbl));
	memset(tbl->dst_addr, 0, sizeof(struct dst_tbl));
	memset(tbl->src_tag_addr, 0, sizeof(struct src_tag_tbl));
	memset(tbl->dst_tag_addr, 0, sizeof(struct dst_tag_tbl));
	rde_fill_src_table(msg, tbl);
	rde_fill_dst_table(msg, tbl);
	if (pdata) {
		if (msg->op_type == WCRYPTO_EC_VALIDATE) {
			sqe->chk_dst_grd_ctrl =
				pdata->dst_dif.ctrl.verify.ref_verify_type;
			sqe->chk_dst_ref_ctrl =
				pdata->dst_dif.ctrl.verify.grd_verify_type;
		}
		sqe->page_pad_type =
			pdata->dst_dif.ctrl.gen.page_layout_pad_type;
		sqe->dif_type = (pdata->dst_dif.ctrl.gen.grd_gen_type) ?
			RDE_DIF : NO_RDE_DIF;
		if (sqe->dif_type == RDE_DIF) {
			rde_fill_src_dif_table(msg, tbl);
			rde_fill_dst_dif_table(msg, tbl);
		}
	}
}

static int rde_check_sqe_para(struct wcrypto_ec_msg *msg)
{
	if (!msg->block_num || !msg->coef_matrix_len) {
		WD_ERR("wrong transfer_size or coef_matrix_len.\n");
		return -WD_EINVAL;
	}

	if (msg->coef_matrix_load && !msg->coef_matrix) {
		WD_ERR("wrong coef_matrix addr.\n");
		return -WD_EINVAL;
	}

	if (!msg->in || !msg->out) {
		WD_ERR("wrong in or out addr.\n");
		return -WD_EINVAL;
	}

	if (msg->ec_type == WCRYPTO_EC_MPCC) {
		if (msg->coef_matrix_len > RDE_MPCC_MAX_CMLEN) {
			WD_ERR("wrong mpcc cm len.\n");
			return -WD_EINVAL;
		}
	} else if (msg->ec_type == WCRYPTO_EC_FLEXEC) {
		if (msg->coef_matrix_len > RDE_FLEXEC_MAX_CMLEN) {
			WD_ERR("wrong flexec cm len.\n");
			return -WD_EINVAL;
		}
	}

	return 0;
}

int qm_fill_rde_sqe(void *rmsg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_rde_sqe *sqe = (struct hisi_rde_sqe *)info->sq_base + i;
	struct wcrypto_ec_msg *msg = rmsg;
	struct wcrypto_ec_tag *tag = (void *)(uintptr_t)msg->usr_data;
	struct wcrypto_ec_table *tbl = (void *)(uintptr_t)tag->tbl_addr;
	struct wd_rde_udata *pdata = tag->priv;
	__u32 len;

	if (rde_check_sqe_para(msg))
		return -WD_EINVAL;

	memset((void *)sqe, 0, sizeof(*sqe));
	sqe->op_tag = __sync_fetch_and_add(&g_ref_cnt, 1);
	sqe->alg_blk_size = msg->alg_blk_size;
	sqe->cm_type = ((msg->op_type == WCRYPTO_EC_RECONSTRUCT) ?
		CM_DECODE : CM_ENCODE);
	sqe->cm_le = msg->coef_matrix_load;
	if (msg->coef_matrix_load) {
		len = rde_get_matrix_len(msg->ec_type, msg->coef_matrix_len);
		memcpy(tbl->matrix, msg->coef_matrix, len);
	}
	sqe->abort = NO_ABORT;
	sqe->src_nblks = msg->in_disk_num;
	sqe->dst_nblks = msg->out_disk_num;
	sqe->op_type = msg->op_type |
		msg->data_fmt << RDE_BUF_TYPE_SHIFT |
		msg->ec_type << RDE_EC_TYPE_SHIFT;
	sqe->block_size = msg->block_size;
	sqe->crciv_sel =  CRCIV1;
	sqe->crciv_en = CRCIV;
	sqe->cm_len = msg->coef_matrix_len;
	sqe->transfer_size = msg->block_num - 1;
	sqe->coef_matrix_addr = tbl->matrix_pa;
	sqe->src_addr = tbl->src_addr_pa;
	sqe->src_tag_addr = tbl->src_tag_addr_pa;
	sqe->dst_addr = tbl->dst_addr_pa;
	sqe->dst_tag_addr = tbl->dst_tag_addr_pa;
	rde_table_package(sqe, pdata, msg, tbl);

	info->req_cache[i] = msg;

#ifdef DEBUG_LOG
	rde_dump_sqe(sqe);
	rde_dump_table(tbl);
#endif

	return 0;
}

static __u8 rde_hw_error_log(__u8 err_sts)
{
	const struct hisi_rde_hw_error *err = g_rde_hw_error;

	while (err->msg) {
		if (err_sts == err->status) {
			WD_ERR("%s [error status=0x%x] found.\n",
				err->msg, err->status);
			break;
		}

		err++;
	}

	if (err_sts < RDE_CRC_CHK_ERR || err_sts > RDE_DISK16_VERIFY)
		return WCRYPTO_EC_IN_EPARA;
	else if (err_sts >= RDE_CRC_CHK_ERR && err_sts <= RDE_REF_CHK_ERR)
		return WCRYPTO_EC_DIF_CHK_ERR;
	else
		return WCRYPTO_EC_DATA_VERIFY_ERR;
}

int qm_parse_rde_sqe(void *hw_msg,
	const struct qm_queue_info *info, __u16 i, __u16 usr)
{
	struct wcrypto_ec_msg *recv_msg;
	struct hisi_rde_sqe *sqe;
	__u8 err_status;

	if (!info->req_cache[i])
		return -WD_EINVAL;

	recv_msg = info->req_cache[i];
	sqe = hw_msg;
	if (usr && usr != recv_msg->cid)
		return 0;

	err_status = sqe->status & RDE_STATUS_MSK;
	recv_msg->result = 0;
	if (sqe->status != RDE_TASK_STATUS) {
		recv_msg->result = rde_hw_error_log(err_status);
#ifdef DEBUG_LOG
		rde_dump_sqe(sqe);
#endif
	}

	return 1;
}

