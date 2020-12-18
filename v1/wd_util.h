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

/* the common drv header define the unified interface for wd */
#ifndef __WD_UTIL_H__
#define __WD_UTIL_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/queue.h>

#include "wd.h"
#include "wd_ecc.h"
#include "wd_adapter.h"

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT		3
#define CRT_PARAMS_SZ(key_size)		((5 * (key_size)) >> 1)
#define CRT_GEN_PARAMS_SZ(key_size)	((7 * (key_size)) >> 1)
#define GEN_PARAMS_SZ(key_size)		((key_size) << 1)
#define CRT_PARAM_SZ(key_size)		((key_size) >> 1)
#define GET_NEGATIVE(val)	(0 - (val))
#define XTS_MODE_KEY_DIVISOR	2
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define CTX_ID_MAX_NUM		64

/* ECC */
#define ECDH_IN_PARAM_NUM		2
#define ECDH_OUT_PARAM_NUM		2
#define ECC_SIGN_IN_PARAM_NUM		2
#define ECC_SIGN_OUT_PARAM_NUM		2
#define ECC_VERF_IN_PARAM_NUM		3
#define ECC_PRIKEY_PARAM_NUM		7
#define ECDH_HW_KEY_PARAM_NUM		5
#define ECC_PUBKEY_PARAM_NUM		8
#define SM2_KG_OUT_PARAM_NUM		3
#define ECC_POINT_PARAM_NUM		2

#define ECDH_HW_KEY_SZ(hsz)		((hsz) * ECDH_HW_KEY_PARAM_NUM)
#define ECC_PRIKEY_SZ(hsz)		((hsz) * ECC_PRIKEY_PARAM_NUM)
#define ECC_PUBKEY_SZ(hsz)		((hsz) * ECC_PUBKEY_PARAM_NUM)
#define ECDH_OUT_PARAMS_SZ(hsz)		((hsz) * ECDH_OUT_PARAM_NUM)

/* x25519/x448 */
#define X_DH_OUT_PARAM_NUM		1
#define X_DH_HW_KEY_PARAM_NUM		3

#define X_DH_OUT_PARAMS_SZ(hsz)		((hsz) * X_DH_OUT_PARAM_NUM)
#define X_DH_HW_KEY_SZ(hsz)		((hsz) * X_DH_HW_KEY_PARAM_NUM)
#define SM2_KG_OUT_PARAMS_SZ(hsz)	((hsz) * SM2_KG_OUT_PARAM_NUM)
#define BITS_TO_BYTES(bits)		(((bits) + 7) >> 3)
#define ECC_SIGN_IN_PARAMS_SZ(hsz)	((hsz) * ECC_SIGN_IN_PARAM_NUM)
#define ECC_SIGN_OUT_PARAMS_SZ(hsz)	((hsz) * ECC_SIGN_OUT_PARAM_NUM)
#define ECC_VERF_IN_PARAMS_SZ(hsz)	((hsz) * ECC_VERF_IN_PARAM_NUM)
#define ECC_VERF_OUT_PARAMS_SZ		1

/* Required compiler attributes */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#define MIN(a, b)	(((a) < (b)) ? (a) : (b))
#define offsetof(t, m) ((size_t)(uintptr_t)&((t *)0)->m)

struct wd_lock {
	__u32 lock;
};

struct wd_ss_region {
	void *va;
	unsigned long long pa;
	size_t size;

	TAILQ_ENTRY(wd_ss_region) next;
};

TAILQ_HEAD(wd_ss_region_list, wd_ss_region);

struct q_info {
	const char *hw_type;
	int hw_type_id;
	int ref;
	void *priv; /* private data used by the drv layer */
	const void *dev_info;
	void *ss_va;
	int fd;
	int iommu_type;
	struct wd_ss_region_list ss_list;
	struct wd_ss_region_list *head;
	unsigned int dev_flags;
	unsigned int ss_size;
	enum wcrypto_type atype;
	int ctx_num;
	struct wd_mm_br br;
	struct wcrypto_hash_mt hash;
	unsigned long qfrs_offset[WD_UACCE_QFRT_MAX];
	struct wd_lock qlock;

	volatile __u8 ctx_id[CTX_ID_MAX_NUM];
};

struct wd_dif_gen {
	__u32 page_layout_gen_type:4;
	__u32 grd_gen_type:4;
	__u32 ver_gen_type:4;
	__u32 app_gen_type:4;
	__u32 ref_gen_type:4;
	__u32 page_layout_pad_type:2;
	__u32 reserved:10;
};

struct wd_dif_verify {
	__u16 page_layout_pad_type:2;
	__u16 grd_verify_type:4;
	__u16 ref_verify_type:4;
	__u16 reserved:6;
};

struct wd_dif_ctrl {
	struct wd_dif_gen gen;
	struct wd_dif_verify verify;
	__u8 dif_comp_ctrl;
};

struct wd_dif {
	__u64 lba;
	__u32 priv_info;
	__u8 ver;
	__u8 app;
	struct wd_dif_ctrl ctrl;
};

struct wd_sec_udata {
	__u32 src_offset;
	__u32 dst_offset;
	struct wd_dif dif;
	__u16 block_size;
	__u16 gran_num;
	__u16 key_bytes;
	__u8 *key;
};

/* Digest tag format of Warpdrive */
struct wcrypto_digest_tag {
	struct wcrypto_cb_tag wcrypto_tag;
	__u64 long_data_len;
	void *priv;
};

/* Cipher tag format of Warpdrive */
struct wcrypto_cipher_tag {
	struct wcrypto_cb_tag wcrypto_tag;
	void *priv;
};

/* AEAD tag format of Warpdrive */
struct wcrypto_aead_tag {
	struct wcrypto_cb_tag wcrypto_tag;
	void *priv;
};

/* EC tag format of Warpdrive */
struct wcrypto_ec_tag {
	struct wcrypto_cb_tag wcrypto_tag;
	__u64 tbl_addr;
	void *priv;
};

/* COMP tag format of Warpdrive */
struct wcrypto_comp_tag {
	struct wcrypto_cb_tag wcrypto_tag;
	void *priv;
};

/* ecc */
struct wcrypto_ecc_pubkey {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb b;
	struct wd_dtb n;
	struct wcrypto_ecc_point g;
	struct wcrypto_ecc_point pub;
	__u32 size;
	void *data;
};

struct wcrypto_ecc_prikey {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb d;
	struct wd_dtb b;
	struct wd_dtb n;
	struct wcrypto_ecc_point g;
	__u32 size;
	void *data;
};

struct wcrypto_ecc_key {
	struct wcrypto_ecc_pubkey *pubkey;
	struct wcrypto_ecc_prikey *prikey;
	struct wcrypto_ecc_curve *cv;
	struct wcrypto_ecc_point *pub;
	struct wd_dtb *d;
};

struct wcrypto_ecc_dh_in {
	struct wcrypto_ecc_point pbk;
};

struct wcrypto_ecc_sign_in {
	struct wd_dtb dgst; /* hash msg */
	struct wd_dtb k; /* random */
	struct wd_dtb plaintext; /* original text before hash */
	__u8 k_set; /* 1 - k param set  0 - not set */
	__u8 dgst_set; /* 1 - dgst param set  0 - not set */
};

struct wcrypto_ecc_verf_in {
	struct wd_dtb dgst; /* hash msg */
	struct wd_dtb s; /* signature s param */
	struct wd_dtb r; /* signature r param */
	struct wd_dtb plaintext; /* original text before hash */
	__u8 dgst_set; /* 1 - dgst param set  0 - not set */
};

struct wcrypto_ecc_dh_out {
	struct wcrypto_ecc_point out;
};

struct wcrypto_ecc_sign_out {
	struct wd_dtb r; /* signature r param */
	struct wd_dtb s; /* signature s param */
};

struct wcrypto_sm2_enc_in {
	struct wd_dtb k; /* random */
	struct wd_dtb plaintext; /* original text */
	__u8 k_set; /* 0 - not set 1 - set */
};

struct wcrypto_sm2_enc_out {
	struct wcrypto_ecc_point c1;
	struct wd_dtb c2;
	struct wd_dtb c3;
};

struct wcrypto_sm2_dec_in {
	struct wcrypto_ecc_point c1;
	struct wd_dtb c2;
	struct wd_dtb c3;
};

struct wcrypto_sm2_kg_in {
	struct wcrypto_ecc_point g;
};

struct wcrypto_sm2_dec_out {
	struct wd_dtb plaintext;
};

struct wcrypto_sm2_kg_out {
	struct wcrypto_ecc_point pub;
	struct wd_dtb priv;
};

typedef union {
	struct wcrypto_ecc_dh_in dh_in;
	struct wcrypto_ecc_sign_in sin;
	struct wcrypto_ecc_verf_in vin;
	struct wcrypto_sm2_enc_in ein;
	struct wcrypto_sm2_dec_in din;
	struct wcrypto_sm2_kg_in kin;
} wcrypto_ecc_in_param;

typedef union {
	struct wcrypto_ecc_dh_out dh_out;
	struct wcrypto_ecc_sign_out sout;
	struct wcrypto_sm2_enc_out eout;
	struct wcrypto_sm2_dec_out dout;
	struct wcrypto_sm2_kg_out kout;
} wcrypto_ecc_out_param;

struct wcrypto_ecc_in {
	wcrypto_ecc_in_param param;
	__u32 size;
	char data[];
};

struct wcrypto_ecc_out {
	wcrypto_ecc_out_param param;
	__u32 size;
	char data[];
};

#ifdef DEBUG_LOG
#define dbg(msg, ...) fprintf(stderr, msg, ##__VA_ARGS__)
#else
#define dbg(msg, ...)
#endif

#ifdef DEBUG
#define ASSERT(f) assert(f)
#else
#define ASSERT(f)
#endif

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__

#define dsb(opt)	{ asm volatile("dsb " #opt : : : "memory"); }
#define rmb()		dsb(ld)	/* read fence */
#define wmb()		dsb(st)	/* write fence */
#define mb()		dsb(sy)	/* rw fence */

#else

#define rmb()	/* read fence */
#define wmb()	/* write fence */
#define mb()	/* rw fence */
#ifndef __UT__
#error "no platform mb, define one before compiling"
#endif

#endif

static inline void wd_reg_write(void *reg_addr, uint32_t value)
{
	*((uint32_t *)reg_addr) = value;
	wmb();	/* load fence */
}

static inline uint32_t wd_reg_read(void *reg_addr)
{
	uint32_t temp;

	temp = *((uint32_t *)reg_addr);
	rmb();	/* load fence */

	return temp;
}

void wd_spinlock(struct wd_lock *lock);
void wd_unspinlock(struct wd_lock *lock);
void *wd_drv_mmap_qfr(struct wd_queue *q, enum uacce_qfrt qfrt, size_t size);
void wd_drv_unmmap_qfr(struct wd_queue *q, void *addr,
		       enum uacce_qfrt qfrt, size_t size);
void *drv_iova_map(struct wd_queue *q, void *va, size_t sz);
void drv_iova_unmap(struct wd_queue *q, void *va, void *dma, size_t sz);
int wd_alloc_ctx_id(struct wd_queue *q, int max_num);
void wd_free_ctx_id(struct wd_queue *q, int ctx_id);
const char *wd_get_drv(struct wd_queue *q);
int wd_burst_send(struct wd_queue *q, void **req, __u32 num);
int wd_burst_recv(struct wd_queue *q, void **resp, __u32 num);

void drv_set_sgl_sge_pri(struct wd_sgl *sgl, int num, void *priv);
void *drv_get_sgl_sge_pri(struct wd_sgl *sgl, int num);
void drv_set_sgl_pri(struct wd_sgl *sgl, void *priv);
void *drv_get_sgl_pri(struct wd_sgl *sgl);
struct wd_mm_br *drv_get_br(void *pool);
void wd_sgl_memset(struct wd_sgl *sgl, int ch);

#endif
