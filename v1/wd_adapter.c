// SPDX-License-Identifier: Apache-2.0
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include "wd_util.h"
#include "wd_adapter.h"
#include "./drv/dummy_drv.h"
#include "./drv/hisi_qm_udrv.h"

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)

static struct wd_drv_dio_if hw_dio_tbl[] = { {
		.hw_type = "dummy_v1",
		.open = dummy_set_queue_dio,
		.close = dummy_unset_queue_dio,
		.send = dummy_add_to_dio_q,
		.recv = dummy_get_from_dio_q,
		.flush = dummy_flush,
	}, {
		.hw_type = "dummy_v2",
		.open = dummy_set_queue_dio,
		.close = dummy_unset_queue_dio,
		.send = dummy_add_to_dio_q,
		.recv = dummy_get_from_dio_q,
		.flush = dummy_flush,
	}, {
		.hw_type = HISI_QM_API_VER_BASE UACCE_API_VER_NOIOMMU_SUBFIX,
		.open = qm_init_queue,
		.close = qm_uninit_queue,
		.send = qm_send,
		.recv = qm_recv,
	}, {
		.hw_type = HISI_QM_API_VER2_BASE UACCE_API_VER_NOIOMMU_SUBFIX,
		.open = qm_init_queue,
		.close = qm_uninit_queue,
		.send = qm_send,
		.recv = qm_recv,
	}, {
		.hw_type = HISI_QM_API_VER_BASE,
		.open = qm_init_queue,
		.close = qm_uninit_queue,
		.send = qm_send,
		.recv = qm_recv,
	}, {
		.hw_type = HISI_QM_API_VER2_BASE,
		.open = qm_init_queue,
		.close = qm_uninit_queue,
		.send = qm_send,
		.recv = qm_recv,
	},
};

/* todo: there should be some stable way to match the device and the driver */
#define MAX_HW_TYPE (sizeof(hw_dio_tbl) / sizeof(hw_dio_tbl[0]))

int drv_open(struct wd_queue *q)
{
	struct q_info *qinfo = q->info;
	int i;

	/* todo: try to find another dev if the user driver is not available */
	for (i = 0; i < MAX_HW_TYPE; i++) {
		if (!strcmp(qinfo->hw_type,
			hw_dio_tbl[i].hw_type)) {
			qinfo->hw_type_id = i;
			return hw_dio_tbl[qinfo->hw_type_id].open(q);
		}
	}
	WD_ERR("No matched driver to use (%s)!\n", qinfo->hw_type);
	errno = ENODEV;
	return -ENODEV;
}

void drv_close(struct wd_queue *q)
{
	struct q_info *qinfo = q->info;

	hw_dio_tbl[qinfo->hw_type_id].close(q);
}

int drv_send(struct wd_queue *q, void *req)
{
	struct q_info *qinfo = q->info;

	return hw_dio_tbl[qinfo->hw_type_id].send(q, req);
}

int drv_recv(struct wd_queue *q, void **req)
{
	struct q_info *qinfo = q->info;

	return hw_dio_tbl[qinfo->hw_type_id].recv(q, req);
}

void drv_add_slice(struct wd_queue *q, struct wd_ss_region *rgn)
{
	struct q_info *qinfo = q->info;
	struct wd_ss_region *rg;

	rg = TAILQ_LAST(&qinfo->ss_list, wd_ss_region_list);
	if (rg) {
		if (rg->pa + rg->size == rgn->pa) {
			rg->size += rgn->size;
			free(rgn);
			return;
		}
	}
	TAILQ_INSERT_TAIL(&qinfo->ss_list, rgn, next);
}

void drv_show_ss_slices(struct wd_queue *q)
{
	struct q_info *qinfo = q->info;
	struct wd_ss_region *rgn;
	int i = 0;

	TAILQ_FOREACH(rgn, qinfo->head, next) {
		WD_ERR("slice-%d:va=%p,pa=0x%llx,size=0x%lx\n",
		       i, rgn->va, rgn->pa, rgn->size);
		i++;
	}
}

void *drv_reserve_mem(struct wd_queue *q, size_t size)
{
	struct wd_ss_region *rgn = NULL;
	struct q_info *qinfo = q->info;
	unsigned long info = 0;
	unsigned long i = 0;
	void *ptr = NULL;
	int ret = 1;

	/* Make sure mmap granulity size align */
	size = ALIGN(size, UACCE_GRAN_SIZE);

	ptr = wd_drv_mmap_qfr(q, UACCE_QFRT_SS, UACCE_QFRT_INVALID, size);
	if (ptr == MAP_FAILED) {
		WD_ERR("wd drv mmap fail!(errno=%d)\n", errno);
		return NULL;
	}
	qinfo->ss_va = ptr;
	qinfo->ss_size = size;
	if (qinfo->dev_flags & UACCE_DEV_NOIOMMU) {
		size = 0;
		while (ret > 0) {
			info = (unsigned long)i;
			ret = ioctl(qinfo->fd, UACCE_CMD_GET_SS_PA, &info);
			if (ret < 0) {
				drv_show_ss_slices(q);
				WD_ERR("get PA fail!\n");
				return NULL;
			}
			rgn = malloc(sizeof(*rgn));
			if (!rgn) {
				WD_ERR("alloc ss region fail!\n");
				return NULL;
			}
			memset(rgn, 0, sizeof(*rgn));
			rgn->size = (info & UACCE_GRAN_NUM_MASK) <<
				    UACCE_GRAN_SHIFT;
			rgn->pa = info - (rgn->size >> UACCE_GRAN_SHIFT);
			rgn->va = ptr + size;
			size += rgn->size;
			drv_add_slice(q, rgn);
			i++;
		}
	}

	return ptr;
}

void drv_unmap_reserve_mem(struct wd_queue *q, void *addr, size_t size)
{
	wd_drv_unmmap_qfr(q, addr, UACCE_QFRT_SS, UACCE_QFRT_INVALID, size);
}
