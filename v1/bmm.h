/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _BMM_H
#define _BMM_H

int bmm_init(void *addr_base, unsigned int mem_size, unsigned int block_size,
	     unsigned int align_size);
void *bmm_alloc(void *pool);
void bmm_free(void *pool, const void *buf);

#endif
