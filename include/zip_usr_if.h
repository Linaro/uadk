/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_ZIP_USR_IF_H
#define HISI_ZIP_USR_IF_H

struct hisi_zip_sqe {
	__u32 consumed;
	__u32 produced;
	__u32 comp_data_length;
	__u32 dw3;
	__u32 input_data_length;
	__u32 lba_l;
	__u32 lba_h;
	__u32 dw7;
	__u32 dw8;
	__u32 dw9;
	__u32 dw10;
	__u32 priv_info;
	__u32 dw12;
	__u32 tag;
	__u32 dest_avail_out;
	__u32 ctx_dw0;
	__u32 comp_head_addr_l;
	__u32 comp_head_addr_h;
	__u32 source_addr_l;
	__u32 source_addr_h;
	__u32 dest_addr_l;
	__u32 dest_addr_h;
	__u32 stream_ctx_addr_l;
	__u32 stream_ctx_addr_h;
	__u32 cipher_key1_addr_l;
	__u32 cipher_key1_addr_h;
	__u32 cipher_key2_addr_l;
	__u32 cipher_key2_addr_h;
	__u32 ctx_dw1;
	__u32 ctx_dw2;
	__u32 isize;
	__u32 checksum;

};

/* Flush types */
enum wd_comp_flush {
	WD_INVALID_FLUSH,

	/* output as much data as we can to improve performance */
	WD_NO_FLUSH,

	/* output as bytes aligning or some other conditions satisfied */
	WD_SYNC_FLUSH,

	/* indicates the end of the file/data */
	WD_FINISH,
};

#define STREAM_FLUSH_SHIFT	25

enum alg_type {
	HW_ZLIB  = 0x02,
	HW_GZIP,
};
enum hw_comp_op {
	HW_DEFLATE,
	HW_INFLATE,
};
enum hw_flush {
	HZ_SYNC_FLUSH,
	HZ_FINISH,
};

enum hw_state {
	STATELESS,
	STATEFUL,
};

enum hw_stream_status {
	STREAM_OLD,
	STREAM_NEW,
};

#endif
