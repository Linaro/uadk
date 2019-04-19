#ifndef __WD_DRV_H
#define __WD_DRV_H

#include "wd.h"

static inline void *wd_drv_mmap_qfr(struct wd_queue *q, enum uacce_qfrt qfrt,
				    enum uacce_qfrt qfrt_next, size_t size)
{
	off_t off;

	off = q->qfrs_offset[qfrt];

	if (qfrt_next != UACCE_QFRT_INVALID)
		size = q->qfrs_offset[qfrt_next] - q->qfrs_offset[qfrt];

	return mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, off);
}

static inline void wd_drv_unmmap_qfr(struct wd_queue *q, void *addr,
				     enum uacce_qfrt qfrt,
				     enum uacce_qfrt qfrt_next, size_t size)
{
	if (qfrt_next != UACCE_QFRT_INVALID)
		size = q->qfrs_offset[qfrt_next] - q->qfrs_offset[qfrt];

	munmap(addr, size);
}
#endif
