/*
 * Copyright 2018-2019 Huawei Technologies Co.,Ltd.All rights reserved.
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
#ifndef __WD_ADAPTER_H__
#define __WD_ADAPTER_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"
#include "wd_sgl.h"

/* Use to describe hardware SGL, different hardware has different SGL format */
struct hw_sgl_info {
	__u32 sgl_sz;
	__u32 sgl_align_sz;
	__u32 sge_sz;
	__u32 sge_align_sz;
};

struct wd_drv_dio_if {
	/* vendor tag which is used to select right vendor driver */
	char *hw_type;
	/* user space WD queue initiation */
	int (*open)(struct wd_queue *q);
	/* user space WD queue uninitiation */
	void (*close)(struct wd_queue *q);
	/* Send WCRYPTO message to WD queue */
	int (*send)(struct wd_queue *q, void **req, __u32 num);
	/* Receive WCRYPTO msg from WD queue */
	int (*recv)(struct wd_queue *q, void **req, __u32 num);

	/* Get hardware sgl infomation from WD queue */
	int (*get_sgl_info)(struct wd_queue *q, struct hw_sgl_info *info);
	/* Initialize hardware sgl from WD queue */
	int (*init_sgl)(struct wd_queue *q, void *pool, struct wd_sgl *sgl);
	/* Uninitialize hardware sgl from WD queue */
	int (*uninit_sgl)(struct wd_queue *q, void *pool, struct wd_sgl *sgl);
	/* Merge two hardware sgls to 'dst_sgl' from WD queue */
	int (*sgl_merge)(struct wd_queue *q, void *pool,
			 struct wd_sgl *dst_sgl, struct wd_sgl *src_sgl);
};

int drv_open(struct wd_queue *q);
void drv_close(struct wd_queue *q);
int drv_send(struct wd_queue *q, void **req, __u32 num);
int drv_recv(struct wd_queue *q, void **req, __u32 num);
void drv_flush(struct wd_queue *q);
void *drv_reserve_mem(struct wd_queue *q, size_t size);
void drv_unmap_reserve_mem(struct wd_queue *q, void *addr, size_t size);
int drv_get_sgl_info(struct wd_queue *q, struct hw_sgl_info *info);
int drv_init_sgl(struct wd_queue *q, void *pool, struct wd_sgl *sgl);
int drv_uninit_sgl(struct wd_queue *q, void *pool, struct wd_sgl *sgl);
int drv_sgl_merge(struct wd_queue *q, void *pool,
		  struct wd_sgl *dst_sgl, struct wd_sgl *src_sgl);

#endif
