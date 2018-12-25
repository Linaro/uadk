/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __SMM_H
#define __SMM_H

#include <stddef.h>

extern int smm_init(void *pt_addr, size_t size, int align_mask);
extern void *smm_alloc(void *pt_addr, size_t size);
extern void smm_free(void *pt_addr, void *ptr);

#ifndef NDEBUG
extern void smm_dump(void *pt_addr);
extern int smm_get_freeblock_num(void *pt_addr);
#endif

#endif
