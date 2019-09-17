// SPDX-License-Identifier: Apache-2.0
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
#include "wd.h"
#include "wd_util.h"
#include "wd_ec.h"
#include "hisi_rde_udrv.h"

static __u16 g_ref_cnt;

static void rde_dump_sqe(struct hisi_rde_sqe *sqe)
{
	int i;

	WD_ERR("[%s][%d]sqe info:\n", __func__, __LINE__);
	for (i = 0; i < sizeof(struct hisi_rde_sqe) / sizeof(__u64); i++)
		WD_ERR("sqe-word[%d]: 0x%llx.\n", i, *((__u64 *)sqe + i));
}

#ifdef DEBUG
static void rde_dump_table(struct wcrypto_ec_table *tbl)
{
	int i;

	for (i = 0; i < SRC_ADDR_TABLE_NUM; i++) {
		if (tbl->src_addr->content[i])
			WD_ERR("src addr info[%d] content is 0x%llx\n",
				i, tbl->src_addr->content[i]);
	}

	for (i = 0; i < DST_ADDR_TABLE_NUM; i++) {
		if (tbl->dst_addr->content[i])
			WD_ERR("dst addr info[%d] content is 0x%llx\n",
				i, tbl->dst_addr->content[i]);
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
	struct rde_sgl *sgl_src = (struct rde_sgl *)msg->in;
	__u8 mode = msg->op_type;

	for (i = 0; i < num; i++) {
		gn = sgl_src->column +
			((WCRYPTO_EC_UPDATE ^ mode) ? 0 : (RDE_UPD_GN_FLAG &
			(sgl_src->parity << RDE_UPD_PARITY_SHIFT)));
		sgl_data = (sgl_src->buf_offset <<
			RDE_SGL_OFFSET_SHIFT) | (__u32)gn;
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		tbl->src_addr->content[cur_cnt] |=
			((__u64)sgl_data << RDE_GN_SHIFT(gn_flag));
		tbl->src_addr->content[gn_cnt] = (__u64)(sgl_src->ctrl);
		sgl_src++;
	}
}

static void rde_fill_dst_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i, gn;
	__u32 sgl_data;
	__u32 gn_cnt, gn_flag, cur_cnt;
	__u8 num = msg->out_disk_num;
	struct rde_sgl *sgl_dst = (struct rde_sgl *)msg->out;

	for (i = 0; i < num; i++) {
		gn = sgl_dst->column;
		sgl_data = (sgl_dst->buf_offset <<
			RDE_SGL_OFFSET_SHIFT) | (__u32)gn;
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		tbl->dst_addr->content[cur_cnt] |=
			((__u64)sgl_data << RDE_GN_SHIFT(gn_flag));
		tbl->dst_addr->content[gn_cnt] = (__u64)(sgl_dst->ctrl);
		sgl_dst++;
	}
}

static void rde_fill_src_dif_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i;
	__u32 lba_info_cnt = 0, chk_info_cnt = 0;
	__u32 cur_cnt1 = 0, cur_cnt2 = 0;
	__u8 num = msg->in_disk_num;
	struct wcrypto_ec_tag *tag = (void *)msg->usr_data;
	struct wcrypto_ec_priv_data *pdata = (void *)tag->priv_data;
	__u8 grd = pdata->src_dif.ctrl.verify.grd_verify_type;
	__u8 ref = pdata->src_dif.ctrl.verify.ref_verify_type;

	for (i = 0; i < num; i++) {
		chk_info_cnt = i / RDE_LBA_BLK + 1;
		lba_info_cnt = RDE_LBA_CNT(i);
		cur_cnt1 = (i / RDE_LBA_BLK) * RDE_LBA_DWORD_CNT;
		cur_cnt2 = chk_info_cnt + lba_info_cnt;
		tbl->src_tag_addr->content[cur_cnt1] |=
			((__u64)(grd << DIF_CHK_GRD_CTRL_SHIFT | ref) <<
			(RDE_LBA_BLK * (i % RDE_LBA_BLK)));
		tbl->src_tag_addr->content[cur_cnt2] |=
			((__u64)pdata->src_dif.priv <<
			(DIF_LBA_SHIFT * ((i % 2) ^ 1)));
	}
}

static void rde_fill_dst_dif_table(struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_table *tbl)
{
	__u8 i;
	__u8 num = msg->out_disk_num;
	struct wcrypto_ec_tag *tag = (void *)msg->usr_data;
	struct wcrypto_ec_priv_data *pdata = (void *)tag->priv_data;

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
		tbl->dst_tag_addr->content[i] |= (__u64)pdata->dst_dif.priv;
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.app) << DIF_APP_TAG_SHIFT);
		tbl->dst_tag_addr->content[i] |=
			((__u64)(pdata->dst_dif.ver) << DIF_VERSION_SHIFT);
	}
}

static void rde_table_package(struct hisi_rde_sqe *sqe,
	struct wcrypto_ec_priv_data *pdata,
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
		rde_fill_src_dif_table(msg, tbl);
		rde_fill_dst_dif_table(msg, tbl);
	}
}

int qm_fill_rde_sqe(void *rmsg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_rde_sqe *sqe = (struct hisi_rde_sqe *)info->sq_base + i;
	struct wcrypto_ec_msg *msg = rmsg;
	struct wcrypto_ec_tag *tag = (void *)msg->usr_data;
	struct wcrypto_ec_table *tbl = (void *)tag->tbl_addr;
	struct wcrypto_ec_priv_data *pdata = (void *)tag->priv_data;
	__u32 len;

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

#ifdef DEBUG
	rde_dump_sqe(sqe);
	rde_dump_table(tbl);
#endif

	return 0;
}

int qm_parse_rde_sqe(void *hw_msg,
	const struct qm_queue_info *info, __u16 i, __u16 usr)
{
	struct wcrypto_ec_msg *recv_msg;
	struct hisi_rde_sqe *sqe;

	if (!info->req_cache[i])
		return -WD_EINVAL;

	recv_msg = info->req_cache[i];
	sqe = hw_msg;
	if (usr && usr != recv_msg->cid)
		return 0;

	if (sqe->status != RDE_TASK_STATUS) {
		WD_ERR("task done flag is 0x%x, err status is 0x%x.\n",
			(sqe->status >> RDE_DONE_SHIFT) & RDE_DONE_MSK,
			sqe->status & RDE_STATUS_MSK);
		rde_dump_sqe(sqe);
	}

	recv_msg->result = (sqe->status & RDE_STATUS_MSK);

	return 1;
}

