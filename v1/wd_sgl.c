/*
 * Copyright 2020 Huawei Technologies Co.,Ltd.All rights reserved.
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

/* SGL Memory Menagament (lib): A SGL memory algorithm */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "wd.h"
#include "wd_adapter.h"
#include "wd_bmm.h"
#include "wd_util.h"
#include "wd_sgl.h"

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)
#define ILLEGAL_ALIGN_SZ(x) ((((x)-1) & (x)))

#define MAX(a, b)	(((a) > (b)) ? (a) : (b))

#define FLAG_SGE_CHAIN  0x01UL
#define FLAG_SGE_END    0x02UL

#define SGL_NUM_MAX	2048
#define SGE_NUM_MAX	60
#define BUF_SIZE_MAX	2048
#define ALIGN_SIZE_MIN	0x8
#define ALIGN_SIZE_MAX	0x1000

struct wd_sge {
	/* 'priv' is used by driver, which may be a hardware sgl address */
	void *priv;
	void *buf;
	__u32 data_len;
	__u32 flag;
	void *sgl;
};

struct wd_sgl {
	/* 'priv' is hardware sgl address */
	void *priv;
	__u8 sge_num;
	__u8 buf_num;
	__u16 buf_sum;
	__u32 sum_data_bytes;

	struct wd_sglpool *pool;
	struct wd_sgl *next;

	/* user config, 60 sges max */
	struct wd_sge sge[];
};

struct wd_sglpool {
	struct wd_queue *q;
	struct wd_lock sgl_lock;

	/* get 'act_align_sz' from hardware's 'align_sz' and user's 'align_sz' */
	__u32 act_align_sz;
	__u32 act_buf_sz;
	__u32 act_buf_num;
	size_t sgl_mem_sz;

	/* Unused sgl/buffer number in the pool */
	__u32 free_sgl_num;
	__u32 alloc_failures;
	__u32 free_buf_num;

	struct wd_blkpool *buf_pool;
	struct wd_blkpool *sgl_pool;
	struct wd_sgl **sgl_blk;
	/* used for driver to 'alloc' and 'dma_map' in 'buf_pool' */
	struct wd_mm_br buf_br;

	struct wd_sglpool_setup setup;
};

static void sgl_init(struct wd_sgl *sgl, struct wd_sglpool *pool)
{
	struct wd_sglpool_setup *sp = &pool->setup;

	sgl->sge_num = sp->sge_num_in_sgl;
	sgl->buf_num = sp->buf_num_in_sgl;
	sgl->buf_sum = sp->buf_num_in_sgl;
	sgl->sum_data_bytes = 0;
	sgl->next = NULL;
	sgl->pool = pool;
}

static void sgl_sge_init(struct wd_sgl *sgl, __u8 num, void *buf)
{
	sgl->sge[num].buf = buf;
	sgl->sge[num].data_len = 0;
	sgl->sge[num].sgl = sgl;

	if (num != sgl->pool->setup.buf_num_in_sgl - 1)
		sgl->sge[num].flag &= ~FLAG_SGE_END;
	else
		sgl->sge[num].flag |= FLAG_SGE_END;

	sgl->sge[num].flag &= ~FLAG_SGE_CHAIN;
}

static int sgl_chain_build(struct wd_queue *q, struct wd_sglpool *pool)
{
	struct wd_sglpool_setup *sp = &pool->setup;
	struct wd_mm_br br = pool->buf_br;
	struct wd_sgl **sgl_blk;
	int ret = -WD_ENOMEM;
	int i, j, m, n;
	void *buf;

	sgl_blk = calloc(sp->sgl_num, sizeof(struct wd_sgl *));
	if (!sgl_blk)
		return ret;

	for (i = 0; i < sp->sgl_num; i++) {
		sgl_blk[i] = wd_alloc_blk(pool->sgl_pool);
		if (!sgl_blk[i]) {
			WD_ERR("alloc for sgl failed !\n");
			goto alloc_sgl_err;
		}

		sgl_init(sgl_blk[i], pool);

		for (j = 0; j < sgl_blk[i]->buf_num; j++) {
			buf = br.alloc(br.usr, sp->buf_size);
			if (!buf) {
				WD_ERR("alloc for sgl_buf failed, j = %d!\n", j);
				goto alloc_buf_err;
			}
			sgl_sge_init(sgl_blk[i], j, buf);
		}

		ret = drv_init_sgl(q, pool, sgl_blk[i]);
		if (ret) {
			i++;
			WD_ERR("init hardware sgl failed, ret = %d\n", ret);
			goto alloc_sgl_err;
		}
	}

	for (m = i - 1; m >= 0; m--)
		wd_free_blk(pool->sgl_pool, sgl_blk[m]);

	pool->sgl_blk = sgl_blk;
	return WD_SUCCESS;

alloc_buf_err:
	for (n = j - 1; n >= 0; n--)
		br.free(br.usr, sgl_blk[i]->sge[n].buf);
	wd_free_blk(pool->sgl_pool, sgl_blk[i]);
alloc_sgl_err:
	for (m = i - 1; m >= 0; m--) {
		for (n = sgl_blk[m]->buf_num - 1; n >= 0; n--)
			br.free(br.usr, sgl_blk[m]->sge[n].buf);
		if (sgl_blk[m]->priv)
			drv_uninit_sgl(q, pool, sgl_blk[m]);
		wd_free_blk(pool->sgl_pool, sgl_blk[m]);
	}

	free(sgl_blk);
	return ret;
}

static void *sgl_buf_pool_init(struct wd_queue *q, struct wd_sglpool *pool)
{
	struct wd_sglpool_setup *sp = &pool->setup;
	struct wd_blkpool_setup blk_setup;
	void *p;

	blk_setup.block_size = pool->act_buf_sz;
	blk_setup.block_num = pool->act_buf_num + sp->sgl_num;
	blk_setup.align_size = pool->act_align_sz;
	memcpy(&blk_setup.br, &sp->br, sizeof(struct wd_mm_br));

	p = wd_blkpool_create(q, &blk_setup);
	if (!p) {
		WD_ERR("wd failed to create block pool for buffers!\n");
		return NULL;
	}

	pool->buf_br.alloc = (void *)wd_alloc_blk;
	pool->buf_br.free = (void *)wd_free_blk;
	pool->buf_br.iova_map = (void *)wd_blk_iova_map;
	pool->buf_br.iova_unmap = (void *)wd_blk_iova_unmap;
	pool->buf_br.get_bufsize = (void *)wd_blksize;
	pool->buf_br.usr = p;

	return p;
}

static void *sgl_mem_alloc(void *usr, size_t size)
{
	return calloc(1, size);
}

static void sgl_mem_free(void *usr, void *va)
{
	free(va);
}

static void *sgl_mem_iova_map(void *usr, void *va, size_t sz)
{
	/* DMA address is not needed, 'return' is only for format. */
	return va;
}

static void sgl_mem_iova_unmap(void *usr, void *va, void *dma, size_t sz)
{
	/* do nothting */
}

static void *sgl_blk_pool_init(struct wd_queue *q, struct wd_sglpool *pool)
{
	struct wd_sglpool_setup *sgl_sp = &pool->setup;
	struct wd_blkpool_setup sp;
	__u32 asz;

	asz = sgl_sp->align_size;

	sp.br.alloc = sgl_mem_alloc;
	sp.br.free = sgl_mem_free;
	sp.br.iova_map = sgl_mem_iova_map;
	sp.br.iova_unmap = sgl_mem_iova_unmap;
	sp.align_size = 64;
	sp.block_num = sgl_sp->sgl_num;
	sp.block_size = ALIGN(sizeof(struct wd_sgl), asz) +
		sgl_sp->sge_num_in_sgl * ALIGN(sizeof(struct wd_sge), asz);

	return wd_blkpool_create(q, &sp);
}

static void sgl_blk_pool_uninit(void *sgl_pool)
{
	wd_blkpool_destroy(sgl_pool);
}

static void sgl_buf_pool_uninit(void *buf_pool)
{
	wd_blkpool_destroy(buf_pool);
}

static int sgl_pool_init(struct wd_queue *q, struct wd_sglpool *pool)
{
	struct wd_sglpool_setup sp = pool->setup;
	void *sgl_pool, *buf_pool;
	int ret = -WD_ENOMEM;

	sgl_pool = sgl_blk_pool_init(q, pool);
	if (!sgl_pool) {
		WD_ERR("failed to create wd sgl pool.\n");
		return ret;
	}
	pool->sgl_pool = sgl_pool;

	buf_pool = sgl_buf_pool_init(q, pool);
	if (!buf_pool) {
		WD_ERR("failed to create hardware buf pool.\n");
		goto err;
	}
	pool->buf_pool = buf_pool;

	ret = sgl_chain_build(q, pool);
	if (ret) {
		WD_ERR("failed to build sgl chain, ret = %d.\n", ret);
		sgl_buf_pool_uninit(buf_pool);
		goto err;
	}

	pool->q = q;
	wd_get_free_blk_num(buf_pool, &pool->free_buf_num);
	pool->free_buf_num = MIN(pool->free_buf_num,
		sp.buf_num - sp.sgl_num * sp.buf_num_in_sgl);
	wd_blk_alloc_failures(sgl_pool, &pool->alloc_failures);
	pool->free_sgl_num = pool->setup.sgl_num;
	pool->sgl_mem_sz = sp.buf_num_in_sgl * sp.buf_size;

	return WD_SUCCESS;
err:
	sgl_blk_pool_uninit(sgl_pool);
	return ret;
}

static int sgl_params_check(struct wd_sglpool_setup *setup)
{
	struct wd_sglpool_setup *sp = setup;
	__u32 buf_num_need;

	if (!sp->buf_num ||  !sp->sgl_num || !sp->sge_num_in_sgl ||
	    !sp->buf_num_in_sgl || sp->buf_size < BUF_SIZE_MAX ||
	    sp->buf_num_in_sgl > sp->sge_num_in_sgl ||
	    sp->sgl_num > SGL_NUM_MAX || sp->sge_num_in_sgl > SGE_NUM_MAX) {
		WD_ERR("invalid size or num in sgl!\n");
		return -WD_EINVAL;
	}

	if (sp->align_size < ALIGN_SIZE_MIN || sp->align_size > ALIGN_SIZE_MAX ||
	    ILLEGAL_ALIGN_SZ(sp->align_size)) {
		WD_ERR("invalid align_size, %u!\n", sp->align_size);
		return -WD_EINVAL;
	}

	buf_num_need = sp->sgl_num * sp->buf_num_in_sgl;
	if (sp->buf_num < buf_num_need) {
		WD_ERR("'buf_num' u need at least is <%u>!\n", buf_num_need);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int sgl_hw_params_check(struct hw_sgl_info *hw_sgl_info)
{
	struct hw_sgl_info *info = hw_sgl_info;

	if (info->sge_align_sz < ALIGN_SIZE_MIN ||
	    info->sge_align_sz > ALIGN_SIZE_MAX ||
	    ILLEGAL_ALIGN_SZ(info->sge_align_sz)) {
		WD_ERR("invalid sge align size: %u!\n", info->sge_align_sz);
		return -WD_EINVAL;
	}

	if (info->sgl_align_sz < ALIGN_SIZE_MIN ||
	    info->sgl_align_sz > ALIGN_SIZE_MAX ||
	    ILLEGAL_ALIGN_SZ(info->sgl_align_sz)) {
		WD_ERR("invalid sgl align size: %u!\n", info->sgl_align_sz);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int sgl_pool_pre_layout(struct wd_sglpool *p, struct wd_sglpool_setup *sp,
			       struct hw_sgl_info *hw_sgl_info)
{
	__u32 hw_sgl_size;
	int ret;

	ret = sgl_params_check(sp);
	if (ret)
		return ret;

	ret = sgl_hw_params_check(hw_sgl_info);
	if (ret)
		return ret;

	p->act_align_sz = MAX(sp->align_size, hw_sgl_info->sge_align_sz);
	p->act_align_sz = MAX(p->act_align_sz, hw_sgl_info->sgl_align_sz);

	p->act_buf_sz = ALIGN(sp->buf_size, p->act_align_sz);

	hw_sgl_size = hw_sgl_info->sgl_sz +
		      sp->sge_num_in_sgl * hw_sgl_info->sge_sz;
	hw_sgl_size = ALIGN(hw_sgl_size, p->act_align_sz);
	if (sp->buf_size < hw_sgl_size) {
		WD_ERR("'buf_size' should be lager than (%u)!\n", hw_sgl_size);
		return -WD_EINVAL;
	}

/* 'buf_num = 1.15 * buf_num' is needed in 'wd_blkpool_create' to create pool */
#define NUM_TIMES(x)	(100 * (x) / 87)
	p->act_buf_num = NUM_TIMES(sp->buf_num);

	return WD_SUCCESS;
}

void *wd_sglpool_create(struct wd_queue *q, struct wd_sglpool_setup *setup)
{
	struct hw_sgl_info hw_sgl_info;
	struct wd_sglpool *pool;
	int ret;

	if (!q || !setup) {
		WD_ERR("q or setup is NULL.\n");
		return NULL;
	}

	ret = drv_get_sgl_info(q, &hw_sgl_info);
	if (ret) {
		WD_ERR("get hardware sgl size err, ret = %d.\n", ret);
		return NULL;
	}

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		WD_ERR("failed to malloc pool!\n");
		return NULL;
	}

	ret = sgl_pool_pre_layout(pool, setup, &hw_sgl_info);
	if (ret)
		goto err_pool_alloc;

	memcpy(&pool->setup, setup, sizeof(*setup));

	if (sgl_pool_init(q, pool))
		goto err_pool_alloc;

	return pool;

err_pool_alloc:
	free(pool);
	return NULL;
}

void wd_sglpool_destroy(void *pool)
{
	struct wd_sglpool *p = pool;
	struct wd_sglpool_setup sp;
	struct wd_sgl *sgl;
	int i, j;

	if (!p || !p->sgl_blk || !p->buf_pool || !p->sgl_pool) {
		WD_ERR("pool param is err!\n");
		return;
	}

	sp = p->setup;
	if (p->free_sgl_num != sp.sgl_num) {
		WD_ERR("sgl is still in use!\n");
		return;
	}

	for (i = 0; i < sp.sgl_num; i++) {
		sgl = p->sgl_blk[i];
		drv_uninit_sgl(p->q, pool, sgl);

		for (j = 0; j < sp.buf_num_in_sgl; j++)
			wd_free_blk(p->buf_pool, sgl->sge[j].buf);
	}

	wd_blkpool_destroy(p->sgl_pool);
	p->sgl_pool = NULL;
	wd_blkpool_destroy(p->buf_pool);
	p->buf_pool = NULL;
	free(p->sgl_blk);
	p->sgl_blk = NULL;

	free(p);
}

struct wd_sgl *wd_alloc_sgl(void *pool, __u32 size)
{
	struct wd_sglpool *p = pool;
	struct wd_sgl *sg1, *sg2;
	int ret;

	if (unlikely(!p || !size)) {
		WD_ERR("pool is null!\n");
		return NULL;
	}

	if (size > p->sgl_mem_sz * 2) {
		WD_ERR("Size you need is bigger than a 2 * SGL!\n");
		return NULL;
	}

	sg1 = wd_alloc_blk(p->sgl_pool);
	if (!sg1) {
		WD_ERR("alloc for sg1 failed!\n");
		__atomic_add_fetch(&p->alloc_failures, 1, __ATOMIC_RELAXED);
		return NULL;
	}

	__atomic_sub_fetch(&p->free_sgl_num, 1, __ATOMIC_RELAXED);

	if (size > p->sgl_mem_sz) {
		sg2 = wd_alloc_blk(p->sgl_pool);
		if (!sg2) {
			WD_ERR("alloc for sg2 failed!\n");
			__atomic_add_fetch(&p->alloc_failures, 1,
					   __ATOMIC_RELAXED);
			return NULL;
		}
		__atomic_sub_fetch(&p->free_sgl_num, 1, __ATOMIC_RELAXED);

		ret = wd_sgl_merge(sg1, sg2);
		if (ret) {
			WD_ERR("merge two sgls failed for u!, ret = %d.\n", ret);
			return NULL;
		}
	}

	return sg1;
}

void wd_free_sgl(void *pool, struct wd_sgl *sgl)
{
	struct wd_sglpool *p = pool;
	struct wd_sgl *next;

	if (unlikely(!p || !sgl)) {
		WD_ERR("pool or sgl is null!\n");
		return;
	}

	do {
		next = sgl->next;
		sgl->buf_sum = sgl->buf_num;
		sgl->next = NULL;

		/* have to update current 'wd_sgl' before free it */
		wd_free_blk(p->sgl_pool, sgl);
		wd_get_free_blk_num(p->sgl_pool, &p->free_sgl_num);
		sgl = next;
	} while (next);
}

/* Merge two SGLs (dst_sgl, src_sgl) into 'dst_sgl' */
int wd_sgl_merge(struct wd_sgl *dst_sgl, struct wd_sgl *src_sgl)
{
	struct wd_sglpool *dst_pool, *src_pool;
	int ret;

	if (unlikely(!dst_sgl || !src_sgl || dst_sgl == src_sgl)) {
		WD_ERR("dst_sgl or src_sgl is null, or they are the same!\n");
		return -WD_EINVAL;
	}

	if (unlikely(dst_sgl->next || src_sgl->next)) {
		WD_ERR("dst_sgl or src_sgl has two sgls!\n");
		return -WD_EINVAL;
	}

	dst_pool = dst_sgl->pool;
	src_pool = src_sgl->pool;
	if (unlikely(!dst_pool || !src_pool || dst_pool != src_pool ||
	    dst_sgl->sge_num != src_sgl->sge_num)) {
		WD_ERR("dst_sgl or src_sgl is error!\n");
		return -WD_EINVAL;
	}

	dst_sgl->sge[dst_sgl->buf_num].flag |= FLAG_SGE_CHAIN;
	dst_sgl->buf_sum += src_sgl->buf_sum;
	dst_sgl->sum_data_bytes += src_sgl->sum_data_bytes;

	ret = drv_sgl_merge(dst_pool->q, dst_pool, dst_sgl, src_sgl);
	if (ret)
		return  ret;

	dst_sgl->next = src_sgl;
	return WD_SUCCESS;
}

static void sgl_cp_to_pbuf(struct wd_sgl *sgl, int strtsg, int strtad,
			   void *pbuf, size_t size)
{
	__u32 sz = sgl->pool->setup.buf_size;
	__u32 act_sz = MIN(size, sz - strtad);
	int i;

	memcpy(pbuf, sgl->sge[strtsg].buf + strtad, act_sz);
	if (act_sz == size)
		return;

	size -= sz - strtad;
	pbuf += sz - strtad;
	for (i = strtsg + 1; i < sgl->buf_num - 1 && size > sz; i++) {
		memcpy(pbuf + (i - strtsg - 1) * sz, sgl->sge[i].buf, sz);
		size -= sz;
	}
	if (size <= sz || sgl->next == NULL) {
		memcpy(pbuf + (i - strtsg - 1) * sz, sgl->sge[i].buf, size);
	} else {
		sgl = sgl->next;
		for (i = 0; i < sgl->buf_num - 1 && size > sz; i++) {
			memcpy(pbuf + (i + sgl->buf_num - strtsg - 1) * sz,
			       sgl->sge[i].buf, sz);
			size -= sz;
		}
		memcpy(pbuf + (i + sgl->buf_num - strtsg - 1) * sz,
			       sgl->sge[i].buf, size);
	}
}

/*
 * Copy the ‘size’ bytes in ‘pbuf’ from the SGL at the start address of ‘offset’
 * Return:
 *  = 0：copy size bytes from SGL to pbuf successfully；
 *  > 0：copy the return value bytes from SGL to pbuf successfully；
 *  < 0: failing, and copy nothing;
 */
int wd_sgl_cp_to_pbuf(struct wd_sgl *sgl, size_t offset, void *pbuf, size_t size)
{
	size_t strtsg, strtad, sz;

	if (unlikely(!sgl || !pbuf || !sgl->pool || !size || !sgl->buf_num ||
	    !sgl->pool->setup.buf_size)) {
		WD_ERR("sgl is null, or sgl is not a legal sgl!\n");
		return -WD_EINVAL;
	}

	sz = sgl->pool->sgl_mem_sz;
	strtsg = offset / sgl->pool->setup.buf_size;
	strtad = offset % sgl->pool->setup.buf_size;

	sgl->next ? sz <<= 1 : sz;

	if (unlikely(offset >= sz)) {
		WD_ERR("'offset' is out of memory!\n");
		return -WD_EINVAL;
	}

	if (sz - offset < size) {
		sgl_cp_to_pbuf(sgl, strtsg, strtad, pbuf, sz - offset);
		return sz - offset;
	}

	sgl_cp_to_pbuf(sgl, strtsg, strtad, pbuf, size);
	return 0;
}

static void sgl_cp_from_pbuf(struct wd_sgl *sgl, int strtsg, int strtad,
			     void *pbuf, size_t size)
{
	__u32 sz = sgl->pool->setup.buf_size;
	__u32 act_sz = MIN(size, sz - strtad);
	int i;

	memcpy(sgl->sge[strtsg].buf + strtad, pbuf, act_sz);
	sgl->sge[strtsg].data_len = act_sz;
	if (act_sz == size)
		return;

	size -= sz - strtad;
	pbuf += sz - strtad;
	for (i = strtsg + 1; i < sgl->buf_num - 1 && size > sz; i++) {
		memcpy(sgl->sge[i].buf, pbuf + (i - strtsg - 1) * sz, sz);
		sgl->sge[i].data_len = sz;
		size -= sz;
	}

	if (size <= sz || sgl->next == NULL) {
		memcpy(sgl->sge[i].buf, pbuf + (i - strtsg - 1) * sz, size);
	} else {
		sgl = sgl->next;
		for (i = 0; i < sgl->buf_num - 1 && size > sz; i++) {
			memcpy(sgl->sge[i].buf,
			       pbuf + (i + sgl->buf_num - strtsg - 1) * sz, sz);
			sgl->sge[i].data_len = sz;
			size -= sz;
		}
		memcpy(sgl->sge[i].buf,
		       pbuf + (i + sgl->buf_num - strtsg - 1) * sz, sz);
	}
	sgl->sge[i].data_len = size;
}


int wd_sgl_cp_from_pbuf(struct wd_sgl *sgl, size_t offset,
			void *pbuf, size_t size)
{
	size_t strtsg, strtad, sz;
	int i;

	if (unlikely(!sgl || !pbuf || !sgl->pool || !size || !sgl->buf_num ||
	    !sgl->pool->setup.buf_size)) {
		WD_ERR("sgl is null, or sgl is not a legal sgl!\n");
		return -WD_EINVAL;
	}

	sz = sgl->pool->sgl_mem_sz;
	strtsg = offset / sgl->pool->setup.buf_size;
	strtad = offset % sgl->pool->setup.buf_size;

	sgl->next ? sz <<= 1 : sz;

	if (unlikely(offset >= sz)) {
		WD_ERR("'offset' is out of memory!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < sgl->buf_num; i++)
		sgl->sge[i].data_len = 0;

	if (sgl->next) {
		for (i = 0; i < sgl->buf_num; i++)
			sgl->next->sge[i].data_len = 0;
	}

	if (sz - offset < size) {
		sgl_cp_from_pbuf(sgl, strtsg, strtad, pbuf, sz - offset);
		sgl->sum_data_bytes = sz - offset;
		return sz - offset;
	}

	sgl_cp_from_pbuf(sgl, strtsg, strtad, pbuf, size);
	sgl->sum_data_bytes = size;
	return 0;
}

void *wd_sgl_iova_map(void *pool, struct wd_sgl *sgl, size_t sz)
{
	struct wd_sglpool *p = pool;

	if (unlikely(!p || !sgl)) {
		WD_ERR("pool or sgl is null!\n");
		return NULL;
	}

	return (void *)((uintptr_t)wd_blk_iova_map(p->buf_pool, sgl->priv));
}

void wd_sgl_iova_unmap(void *pool, void *sgl_iova, struct wd_sgl *sgl)
{
	/* do nothing */
}

void *wd_get_last_sge_buf(struct wd_sgl *sgl)
{
	if (unlikely(!sgl || !sgl->buf_num)) {
		WD_ERR("sgl or buf_num in sgl is null!\n");
		return NULL;
	}

	if (sgl->next)
		sgl = sgl->next;

	return sgl->sge[sgl->buf_num - 1].buf;
}

void *wd_get_first_sge_buf(struct wd_sgl *sgl)
{
	if (unlikely(!sgl)) {
		WD_ERR("sgl is null!\n");
		return NULL;
	}

	return sgl->sge[0].buf;
}

int wd_get_sgl_sge_num(struct wd_sgl *sgl)
{
	if (unlikely(!sgl)) {
		WD_ERR("sgl is null!\n");
		return -WD_EINVAL;
	}

	return sgl->sge_num;
}

int wd_get_sgl_buf_num(struct wd_sgl *sgl)
{
	if (unlikely(!sgl)) {
		WD_ERR("sgl is null!\n");
		return -WD_EINVAL;
	}

	return sgl->buf_num;
}

/* 'num' starts from 1 */
void *wd_get_sge_buf(struct wd_sgl *sgl, int num)
{
	if (unlikely(!sgl || !num || num > sgl->sge_num)) {
		WD_ERR("sgl is null, or num is valid, num = %d!\n", num);
		return NULL;
	}

	return sgl->sge[num - 1].buf;
}

int wd_get_sgl_buf_sum(struct wd_sgl *sgl)
{
	if (unlikely(!sgl)) {
		WD_ERR("sgl is null!\n");
		return -WD_EINVAL;
	}

	return sgl->buf_sum;
}

int wd_get_sgl_mem_size(struct wd_sgl *sgl, size_t *size)
{
	if (unlikely(!sgl || !sgl->pool)) {
		WD_ERR("sgl param err!\n");
		return -WD_EINVAL;
	}

	*size = sgl->pool->sgl_mem_sz;

	return WD_SUCCESS;
}

int wd_get_free_sgl_num(void *pool, __u32 *free_sgl_num)
{
	struct wd_sglpool *p = pool;

	if (unlikely(!p)) {
		WD_ERR("pool is null!\n");
		return -WD_EINVAL;
	}

	*free_sgl_num = __atomic_load_n(&p->free_sgl_num, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

int wd_get_free_sgl_sge_num(struct wd_sgl *sgl, __u32 *free_sgl_sge_num)
{
	if (unlikely(!sgl)) {
		WD_ERR("sgl is null!\n");
		return -WD_EINVAL;
	}

	*free_sgl_sge_num = sgl->sge_num - sgl->buf_num;

	return WD_SUCCESS;
}

int wd_get_free_buf_num(void *pool, __u32 *free_buf_num)
{
	struct wd_sglpool *p = pool;

	if (unlikely(!p)) {
		WD_ERR("pool is null!\n");
		return -WD_EINVAL;
	}

	*free_buf_num = __atomic_load_n(&p->free_buf_num, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

/* if sgl is a chain(has two sgl), the sgl_datalen is the data_len in chain */
int wd_get_sgl_datalen(struct wd_sgl *sgl, __u32 *dtsize)
{
	if (unlikely(!sgl)) {
		WD_ERR("sgl is null!\n");
		return -WD_EINVAL;
	}

	*dtsize = sgl->sum_data_bytes;
	return WD_SUCCESS;
}

/* get 'num'th' sge datalen in sgl */
int wd_get_sge_datalen(struct wd_sgl *sgl, __u32 num, __u32 *dtsize)
{
	if (unlikely(!sgl || !num || num > sgl->sge_num)) {
		WD_ERR("sgl or num is invalid!\n");
		return -WD_EINVAL;
	}

	*dtsize = sgl->sge[num - 1].data_len;
	return WD_SUCCESS;
}

int wd_get_sgl_bufsize(struct wd_sgl *sgl, __u32 *bufsz)
{
	if (unlikely(!sgl || !sgl->pool)) {
		WD_ERR("sgl is null, or sgl pool is null!\n");
		return -WD_EINVAL;
	}

	*bufsz = sgl->pool->setup.buf_size;
	return WD_SUCCESS;
}

/* internal interface */
/* set sgl.sge[num].priv as 'addr'm num starts '0' */
void drv_set_sgl_sge_pri(struct wd_sgl *sgl, int num, void *priv)
{
	sgl->sge[num].priv = priv;
}

void *drv_get_sgl_sge_pri(struct wd_sgl *sgl, int num)
{
	return sgl->sge[num].priv;
}

void drv_set_sgl_pri(struct wd_sgl *sgl, void *priv)
{
	sgl->priv = priv;
}

void *drv_get_sgl_pri(struct wd_sgl *sgl)
{
	return sgl->priv;
}

struct wd_mm_br *drv_get_br(void *pool)
{
	struct wd_sglpool *p = pool;

	return &p->buf_br;
}