/* SPDX-License-Identifier: GPL-2.0 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>


#include "wd_adapter.h"
#include "./drv/dummy_drv.h"
#include "./drv/hisi_qm_udrv.h"
#include "./drv/wd_drv.h"

static struct wd_drv_dio_if hw_dio_tbl[] = { {
		.hw_type = "dummy_v1",
		.ss_offset = DUMMY_SS_START,
		.open = dummy_set_queue_dio,
		.close = dummy_unset_queue_dio,
		.send = dummy_add_to_dio_q,
		.recv = dummy_get_from_dio_q,
		.flush = dummy_flush,
	}, {
		.hw_type = HISI_QM_API_VER_BASE UACCE_API_VER_NOIOMMU_SUBFIX,
		.ss_offset = QM_SS_START,
		.open = hisi_qm_set_queue_dio,
		.close = hisi_qm_unset_queue_dio,
		.send = hisi_qm_add_to_dio_q,
		.recv = hisi_qm_get_from_dio_q,
	}, {
		.hw_type = HISI_QM_API_VER_BASE,
		.ss_offset = QM_SS_START,
		.open = hisi_qm_set_queue_dio,
		.close = hisi_qm_unset_queue_dio,
		.send = hisi_qm_add_to_dio_q,
		.recv = hisi_qm_get_from_dio_q,
	},
};

/* todo: there should be some stable way to match the device and the driver */
#define MAX_HW_TYPE (sizeof(hw_dio_tbl) / sizeof(hw_dio_tbl[0]))

int drv_open(struct wd_queue *q)
{
	int i;

	//todo: try to find another dev if the user driver is not available
	for (i = 0; i < MAX_HW_TYPE; i++) {
		if (!strcmp(q->hw_type,
			hw_dio_tbl[i].hw_type)) {
			q->hw_type_id = i;
			return hw_dio_tbl[q->hw_type_id].open(q);
		}
	}
	WD_ERR("No matched driver to use (%s)!\n", q->hw_type);
	errno = ENODEV;
	return -ENODEV;
}

void drv_close(struct wd_queue *q)
{
	hw_dio_tbl[q->hw_type_id].close(q);
}

int drv_send(struct wd_queue *q, void *req)
{
	return hw_dio_tbl[q->hw_type_id].send(q, req);
}

int drv_recv(struct wd_queue *q, void **req)
{
	return hw_dio_tbl[q->hw_type_id].recv(q, req);
}

void drv_flush(struct wd_queue *q)
{
	if (hw_dio_tbl[q->hw_type_id].flush)
		hw_dio_tbl[q->hw_type_id].flush(q);
}

void *drv_reserve_mem(struct wd_queue *q, size_t size)
{
	q->ss_va = wd_drv_mmap(q, size, hw_dio_tbl[q->hw_type_id].ss_offset);

	if (q->ss_va == MAP_FAILED)
		return NULL;

	if (q->dev_flags & UACCE_DEV_NOIOMMU) {
		errno = (long)ioctl(q->fd, UACCE_CMD_GET_SS_PA, &q->ss_pa);
		if (errno)
			return NULL;
	} else
		q->ss_pa = q->ss_va;

	return q->ss_va;
}
