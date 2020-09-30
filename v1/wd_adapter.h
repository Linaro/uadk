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
};

extern int drv_open(struct wd_queue *q);
extern void drv_close(struct wd_queue *q);
extern int drv_send(struct wd_queue *q, void **req, __u32 num);
extern int drv_recv(struct wd_queue *q, void **req, __u32 num);
extern void drv_flush(struct wd_queue *q);
extern void *drv_reserve_mem(struct wd_queue *q, size_t size);
extern void drv_unmap_reserve_mem(struct wd_queue *q, void *addr, size_t size);

#endif
