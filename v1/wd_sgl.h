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

#ifndef _WD_SGL_H
#define _WD_SGL_H

#ifdef __cplusplus
extern "C" {
#endif

struct wd_sgl;
struct wd_sglpool_setup {
	/* Total number of SGEs with buffer slices */
	__u32 buf_num;
	/* memory size of entry buffer */
	__u32 buf_size;
	/* Fixed SGE number in the SGL of the pool */
	__u8 sge_num_in_sgl;
	/* Initiated buf number in the SGL of the pool, changeable */
	__u8 buf_num_in_sgl;
	/* Total number of sgl for entries and buffers */
	__u16 sgl_num;
	/* SGE data buffer starting address align size */
	__u32 align_size;
	/* memory from user if don't use WD memory */
	struct wd_mm_br br;
};

void *wd_sglpool_create(struct wd_queue *q, struct wd_sglpool_setup *setup);
void wd_sglpool_destroy(void *pool);
struct wd_sgl *wd_alloc_sgl(void *pool, __u32 size);
void wd_free_sgl(void *pool, struct wd_sgl *sgl);
int wd_sgl_merge(struct wd_sgl *dst_sgl, struct wd_sgl *src_sgl);
int wd_sgl_cp_to_pbuf(struct wd_sgl *sgl, size_t offset, void *pbuf, size_t size);
int wd_sgl_cp_from_pbuf(struct wd_sgl *sgl, size_t offset, void *pbuf, size_t size);
void *wd_sgl_iova_map(void *pool, struct wd_sgl *sgl, size_t sz);
void wd_sgl_iova_unmap(void *pool, void *sgl_iova, struct wd_sgl *sgl);

void *wd_get_last_sge_buf(struct wd_sgl *sgl);
void *wd_get_first_sge_buf(struct wd_sgl *sgl);
int wd_get_sgl_sge_num(struct wd_sgl *sgl);
int wd_get_sgl_buf_num(struct wd_sgl *sgl);
void *wd_get_sge_buf(struct wd_sgl *sgl, __u32 num);
int wd_get_sgl_buf_sum(struct wd_sgl *sgl);
int wd_get_sgl_mem_size(struct wd_sgl *sgl, size_t *size);
int wd_get_free_sgl_num(void *pool, __u32 *free_sgl_num);
int wd_get_free_sgl_sge_num(struct wd_sgl *sgl, __u32 *free_sgl_sge_num);
int wd_get_free_buf_num(void *pool, __u32 *free_buf_num);
int wd_get_sgl_datalen(struct wd_sgl *sgl, __u32 *dtsize);
int wd_get_sge_datalen(struct wd_sgl *sgl, __u32 num, __u32 *dtsize);
int wd_get_sgl_bufsize(struct wd_sgl *sgl, __u32 *bufsz);

#ifdef __cplusplus
}
#endif

#endif /* _WD_SGL_H */
