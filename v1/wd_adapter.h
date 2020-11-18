/* SPDX-License-Identifier: Apache-2.0 */
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
	char *hw_type;
	int (*open)(struct wd_queue *q);
	void (*close)(struct wd_queue *q);
	int (*send)(struct wd_queue *q, void *req);
	int (*recv)(struct wd_queue *q, void **req);
	void (*flush)(struct wd_queue *q);
};

extern int drv_open(struct wd_queue *q);
extern void drv_close(struct wd_queue *q);
extern int drv_send(struct wd_queue *q, void *req);
extern int drv_recv(struct wd_queue *q, void **req);
extern void drv_flush(struct wd_queue *q);
extern void *drv_reserve_mem(struct wd_queue *q, size_t size);
extern void drv_unmap_reserve_mem(struct wd_queue *q, void *addr, size_t size);

#endif
