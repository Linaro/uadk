/* SPDX-License-Identifier: Apache-2.0 */
#ifndef	__HISI_COMP_H
#define	__HISI_COMP_H

#include "wd_comp.h"

extern int hisi_comp_init(struct wd_comp_sess *sess);
extern void hisi_comp_exit(struct wd_comp_sess *sess);
extern int hisi_comp_deflate(struct wd_comp_sess *sess);
extern int hisi_comp_inflate(struct wd_comp_sess *sess);
extern int hisi_comp_poll(struct wd_comp_sess *sess);

#endif	/* __HISI_COMP_H */
