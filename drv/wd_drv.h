#ifndef __WD_DRV_H
#define __WD_DRV_H

#include "wd.h"

static inline void *wd_drv_mmap_qfr(struct wd_queue *q, enum uacce_qfrt qfrt,
				    size_t size)
{
	off_t off = qfrt * getpagesize();

	if (q->qfrs_offset[qfrt] != 0)
		size = q->qfrs_offset[qfrt];

	return mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, off);
}

static inline void wd_drv_unmmap_qfr(struct wd_queue *q, void *addr,
				     enum uacce_qfrt qfrt, size_t size)
{
	if (q->qfrs_offset[qfrt] != 0)
		size = q->qfrs_offset[qfrt];

	munmap(addr, size);
}
#endif
