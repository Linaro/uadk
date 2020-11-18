/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HISI_HPRE_UDRV_H
#define HISI_HPRE_UDRV_H

#include "hisi_qm_udrv.h"

enum hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_PRIME = 0x6,
	HPRE_ALG_MOD = 0x7,
	HPRE_ALG_MOD_INV = 0x8,
	HPRE_ALG_MUL = 0x9,
	HPRE_ALG_COPRIME = 0xA
};

int qm_fill_dh_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_parse_dh_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr);
int qm_fill_rsa_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_parse_rsa_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr);


#endif
