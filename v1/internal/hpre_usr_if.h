/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_HPRE_USR_IF_H
#define HISI_HPRE_USR_IF_H

/* I think put venodr hw msg as a user interface is not suitable here */
struct hisi_hpre_sqe {
	__u32 alg	: 5;

	/* error type */
	__u32 etype	:11;
	__u32 resv0	: 14;
	__u32 done	: 2;
	__u32 task_len1	: 8;
	__u32 task_len2	: 8;
	__u32 mrttest_num : 8;
	__u32 uwkey_enb	: 1;
	__u32 sm2_ksel	: 1;
	__u32 resv1	: 6;
	__u32 low_key;
	__u32 hi_key;
	__u32 low_in;
	__u32 hi_in;
	__u32 low_out;
	__u32 hi_out;
	__u32 tag	:16;
	__u32 resv2	:16;
	__u32 rsvd1[7];
};

#endif
