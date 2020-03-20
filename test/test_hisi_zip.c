// SPDX-License-Identifier: GPL-2.0+
#include "config.h"
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <getopt.h>
#include "hisi_qm_udrv.h"
#include "test_lib.h"
#include "wd_sched.h"

#define ZLIB_HEADER "\x78\x9c"
#define ZLIB_HEADER_SZ 2

/*
 * We use a extra field for gzip block length. So the fourth byte is \x04.
 * This is necessary because our software don't know the size of block when
 * using an hardware decompresser (It is known by hardware). This help our
 * decompresser to work and helpfully, compatible with gzip.
 */
#define GZIP_HEADER "\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ 10
#define GZIP_EXTRA_SZ 10
#define GZIP_TAIL_SZ 8

/* bytes of data for a request */
static int block_size = 512000;
static int req_cache_num = 4;
static int q_num = 1;

static struct hizip_priv {
	int alg_type;
	int op_type;
	int dw9;
	int total_len;
	struct hisi_zip_sqe *msgs;
	FILE *sfile, *dfile;

} hizip_priv;

static struct wd_scheduler sched = {
	.priv = &hizip_priv,
};

static void hizip_wd_sched_init_cache(struct wd_scheduler *sched, int i,
				      void *priv)
{
	struct wd_msg *wd_msg = &sched->msgs[i];
	struct hisi_zip_sqe *msg;
	struct hizip_priv *ctx = priv;
	void *data_in, *data_out;

	msg = wd_msg->msg = &ctx->msgs[i];
	msg->dw9 = ctx->dw9;
	msg->dest_avail_out = sched->msg_data_size;

	if (wd_is_nosva(&sched->qs[0])) {
		data_in = wd_get_dma_from_va(&sched->qs[0], wd_msg->data_in);
		data_out = wd_get_dma_from_va(&sched->qs[0], wd_msg->data_out);
	} else {
		data_in = wd_msg->data_in;
		data_out = wd_msg->data_out;
	}
	msg->source_addr_l = (__u64)data_in & 0xffffffff;
	msg->source_addr_h = (__u64)data_in >> 32;
	msg->dest_addr_l = (__u64)data_out & 0xffffffff;
	msg->dest_addr_h = (__u64)data_out >> 32;

	dbg("init sched cache %d: %p, %p\n", i, wd_msg, msg);
}

static int hizip_wd_sched_input(struct wd_msg *msg, void *priv)
{
	size_t ilen, templen, real_len, sz;
	struct hisi_zip_sqe *m = msg->msg;

	ilen = hizip_priv.total_len > block_size ?
		block_size : hizip_priv.total_len;
	templen = ilen;
	hizip_priv.total_len -= ilen;
	if (hizip_priv.op_type == INFLATE) {
		if (hizip_priv.alg_type == ZLIB) {
			sz = fread(msg->data_in, 1, ZLIB_HEADER_SZ,
				   hizip_priv.sfile);
			SYS_ERR_COND(sz != ZLIB_HEADER_SZ, "read");
			ilen -= ZLIB_HEADER_SZ;
		} else {
			sz = fread(msg->data_in, 1, GZIP_HEADER_SZ,
				   hizip_priv.sfile);
			SYS_ERR_COND(sz != GZIP_HEADER_SZ, "read");
			ilen -= GZIP_HEADER_SZ;
			if (*((char *)msg->data_in + 3) == 0x04) {
				sz = fread(msg->data_in, 1, GZIP_EXTRA_SZ,
					   hizip_priv.sfile);
				memcpy(&ilen, msg->data_in + 6, 4);
				dbg("gzip iuput len %ld\n", ilen);
				SYS_ERR_COND(ilen > block_size * 2,
				    "gzip protocol_len(%ld) > dmabuf_size(%d)\n",
				    ilen, block_size);
				real_len = GZIP_HEADER_SZ
					+ GZIP_EXTRA_SZ + ilen;
				hizip_priv.total_len = hizip_priv.total_len
					+ templen - real_len;
			}
		}
	}

	sz = fread(msg->data_in, 1, ilen, hizip_priv.sfile);
	SYS_ERR_COND(sz != ilen, "read");

	m->input_data_length = ilen;

	dbg("zip input(%p, %p): %x, %x, %x, %x, %d, %d\n",
	    msg, m,
	    m->source_addr_l, m->source_addr_h,
	    m->dest_addr_l, m->dest_addr_h,
	    m->dest_avail_out, m->input_data_length);

	return 0;
}

static int hizip_wd_sched_output(struct wd_msg *msg, void *priv)
{
	size_t sz;
	struct hisi_zip_sqe *m = msg->msg;
	__u32 status = m->dw3 & 0xff;
	__u32 type = m->dw9 & 0xff;
	char gzip_extra[GZIP_EXTRA_SZ] = {0x08, 0x00, 0x48, 0x69, 0x04, 0x00,
					  0x00, 0x00, 0x00, 0x00};

	dbg("zip output(%p, %p): %x, %x, %x, %x, %d, %d, consume=%d, out=%d\n",
	    msg, m,
	    m->source_addr_l, m->source_addr_h,
	    m->dest_addr_l, m->dest_addr_h,
	    m->dest_avail_out, m->input_data_length, m->consumed, m->produced);

	SYS_ERR_COND(status != 0 && status != 0x0d, "bad status (s=%d, t=%d)\n",
		     status, type);
	if (hizip_priv.op_type == DEFLATE) {

		if (hizip_priv.alg_type == ZLIB) {
			sz = fwrite(ZLIB_HEADER, 1, ZLIB_HEADER_SZ,
				    hizip_priv.dfile);
			SYS_ERR_COND(sz != ZLIB_HEADER_SZ, "write");
		} else {
			sz = fwrite(GZIP_HEADER, 1, GZIP_HEADER_SZ,
				    hizip_priv.dfile);
			SYS_ERR_COND(sz != GZIP_HEADER_SZ, "write");
			memcpy(gzip_extra + 6, &m->produced, 4);
			sz = fwrite(gzip_extra, 1, GZIP_EXTRA_SZ,
				    hizip_priv.dfile);
			SYS_ERR_COND(sz != GZIP_EXTRA_SZ, "write");
		}
	}
	sz = fwrite(msg->data_out, 1, m->produced, hizip_priv.dfile);
	SYS_ERR_COND(sz != m->produced, "write");
	return 0;
}

int hizip_init(int alg_type, int op_type)
{
	int ret = -ENOMEM;

	sched.q_num = q_num;
	sched.ss_region_size = 0; /* let system make decision */
	sched.msg_cache_num = req_cache_num;
	sched.msg_data_size = block_size * 2; /* use twice size of the input
						 data, hope it is engouth for
						 output */
	sched.init_cache = hizip_wd_sched_init_cache;
	sched.input = hizip_wd_sched_input;
	sched.output = hizip_wd_sched_output;
	sched.hw_alloc = hisi_qm_alloc_ctx;
	sched.hw_free = hisi_qm_free_ctx;
	sched.hw_send = hisi_qm_send;
	sched.hw_recv = hisi_qm_recv;

	sched.qs = calloc(q_num, sizeof(*sched.qs));
	if (!sched.qs)
		return -ENOMEM;

	hizip_priv.msgs = calloc(req_cache_num, sizeof(*hizip_priv.msgs));
	if (!hizip_priv.msgs)
		goto err_with_qs;


	hizip_priv.alg_type = alg_type;
	hizip_priv.op_type = op_type;
	if (alg_type == ZLIB) {
		hizip_priv.dw9 = 2;
	} else {
		hizip_priv.dw9 = 3;
	}

	ret = wd_sched_init(&sched, "/dev/hisi_zip-0");
	if (ret)
		goto err_with_msgs;

	return 0;

err_with_msgs:
	free(hizip_priv.msgs);
err_with_qs:
	free(sched.qs);
	return ret;
}

void hizip_fini(void)
{
	wd_sched_fini(&sched);
	free(hizip_priv.msgs);
	free(sched.qs);
}

void hizip_deflate(FILE *source, FILE *dest)
{
	int fd;
	struct stat s;
	int ret, i, j;
	struct hisi_qm_capa capa;
	struct hisi_qm_priv *qm_priv;

	sched.data = &capa;
	qm_priv = (struct hisi_qm_priv *)&capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = hizip_priv.op_type;

	if (hizip_priv.alg_type == ZLIB)
		capa.alg = "zlib";
	else
		capa.alg = "gzip";

	for (i = 0; i < sched.q_num; i++) {
		ret = sched.hw_alloc(&sched.qs[i], sched.data);
		if (ret)
			goto out;
		ret = wd_start_ctx(&sched.qs[i]);
		if (ret)
			goto out_start;
	}

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	hizip_priv.total_len = s.st_size;
	SYS_ERR_COND(!hizip_priv.total_len, "input file length zero");
	hizip_priv.sfile = source;
	hizip_priv.dfile = dest;

	/* ZLIB engine can do only one time with buffer less than 16M */
	if (hizip_priv.alg_type == ZLIB) {
		SYS_ERR_COND(hizip_priv.total_len > block_size,
			     "zip total_len(%d) > block_size(%d)\n",
			     hizip_priv.total_len, block_size);
		SYS_ERR_COND(block_size > 16 * 1024 * 1024,
			     "block_size (%d) > 16MB hw limit!\n",
			     hizip_priv.total_len);
	}

	while (hizip_priv.total_len || !wd_sched_empty(&sched)) {
		dbg("request loop: total_len=%d\n", hizip_priv.total_len);
		ret = wd_sched_work(&sched, hizip_priv.total_len);
		SYS_ERR_COND(ret < 0, "wd_sched_work");
	}

	fclose(dest);
	return;
out_start:
	sched.hw_free(&sched.qs[i]);
out:
	for (j = i - 1; j >= 0; j--) {
		wd_stop_ctx(&sched.qs[j]);
		sched.hw_free(&sched.qs[j]);
	}
}

void hizip_def(FILE *source, FILE *dest, int alg_type, int op_type)
{
	int ret;

	ret = hizip_init(alg_type, op_type);
	SYS_ERR_COND(ret, "hizip init fail\n");

	hizip_deflate(stdin, stdout);

	hizip_fini();
}

int main(int argc, char *argv[])
{
	int alg_type = GZIP;
	int op_type = DEFLATE;
	int opt;
	int show_help = 0;

	while ((opt = getopt(argc, argv, "zghq:b:dc:")) != -1) {
		switch (opt) {
		case 'z':
			alg_type = ZLIB;
			break;
		case 'g':
			alg_type = GZIP;
			break;
		case 'q':
			q_num = atoi(optarg);
			if (q_num <= 0)
				show_help = 1;
			break;
		case 'b':
			block_size = atoi(optarg);
			if (block_size  <= 0)
				show_help = 1;
			break;
		case 'c':
			req_cache_num = atoi(optarg);
			if (req_cache_num <= 0)
				show_help = 1;
			break;
		case 'd':
			op_type = INFLATE;
			SYS_ERR_COND(0, "decompress function to be added\n");
			break;
		default:
			show_help = 1;
			break;
		}
	}

	SYS_ERR_COND(show_help || optind > argc,
		     "test_hisi_zip -[g|z] [-q q_num] < in > out\n");

	hizip_def(stdin, stdout, alg_type, op_type);

	return EXIT_SUCCESS;
}
