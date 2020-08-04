/* SPDX-License-Identifier: Apache-2.0 */
#ifndef	__HISI_COMP_H
#define	__HISI_COMP_H

#include "hisi_qm_udrv.h"
#include "include/zip_usr_if.h"
#include "smm.h"
#include "wd.h"
#include "wd_comp.h"
#include "wd_sched.h"

#define	ZLIB		0
#define	GZIP		1

#define DEFLATE		0
#define INFLATE		1

#define ASIZE		(2 * 512 * 1024)
#define HW_CTX_SIZE	(64*1024)

#endif	/* __HISI_COMP_H */
