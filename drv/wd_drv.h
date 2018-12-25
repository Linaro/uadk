#ifndef __WD_DRV_H
#define __WD_DRV_H

#include "wd.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#endif

static inline void *wd_drv_mmap(struct wd_queue *q, size_t size, size_t off)
{
	return mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, off);
}

#endif
