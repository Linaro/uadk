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
	HPRE_ALG_COPRIME = 0xA,
	HPRE_ALG_ECC_CURVE_TEST = 0xB,
	HPRE_ALG_ECDH_PLUS = 0xC,
	HPRE_ALG_ECDH_MULTIPLY = 0xD,
	HPRE_ALG_ECDSA_SIGN = 0xE,
	HPRE_ALG_ECDSA_VERF = 0xF,
	HPRE_ALG_X_DH_MULTIPLY = 0x10,
	HPRE_ALG_X_DH_CURVE_TEST = 0x11,
	HPRE_ALG_SM2_SIGN = 0x12,
	HPRE_ALG_SM2_VERF = 0x13,
	HPRE_ALG_SM2_ENC = 0x14,
	HPRE_ALG_SM2_DEC = 0x15
};

int qm_fill_dh_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_parse_dh_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr);
int qm_fill_rsa_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_parse_rsa_sqe(void *msg, const struct qm_queue_info *info,
				__u16 i, __u16 usr);
int qm_fill_ecc_sqe(void *message, struct qm_queue_info *info, __u16 i);
int qm_parse_ecc_sqe(void *msg, const struct qm_queue_info *info,
		     __u16 i, __u16 usr);
#endif
