#ifndef __WD_DRV_H
#define __WD_DRV_H

#include "wd.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#endif

static inline void *wd_drv_mmap_qfr(struct wd_queue *q, enum uacce_qfrt qfrt,
				    enum uacce_qfrt qfrt_next, size_t size)
{
	off_t off;

	off = q->qfrs_pg_start[qfrt] << PAGE_SHIFT;

	if (qfrt_next != UACCE_QFRT_INVALID) {
		size = q->qfrs_pg_start[qfrt_next] - q->qfrs_pg_start[qfrt];
		size <<= PAGE_SHIFT;
	}

	return mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, off);
}

static inline void wd_drv_unmmap_qfr(struct wd_queue *q, void *addr,
				     enum uacce_qfrt qfrt,
				     enum uacce_qfrt qfrt_next, size_t size)
{
	if (qfrt_next != UACCE_QFRT_INVALID) {
		size = q->qfrs_pg_start[qfrt_next] - q->qfrs_pg_start[qfrt];
		size <<= PAGE_SHIFT;
	}
	munmap(addr, size);
}

#endif
