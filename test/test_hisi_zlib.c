// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include "wd.h"
#include "hisi_qm_udrv.h"
#include "zip_usr_if.h"
#include "smm.h"

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)

#define ASIZE (2*512*1024)	/*512K*/

#define SYS_ERR_COND(cond, msg, ...) \
do { \
	if (cond) { \
		if (errno) \
			perror(msg); \
		else \
			fprintf(stderr, msg, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} \
} while (0)


#define ZLIB 0
#define GZIP 1

#define HW_CTX_SIZE (64*1024)

#define Z_OK            0
#define Z_STREAM_END    1
#define Z_ERRNO (-1)
#define Z_STREAM_ERROR (-EIO)

#define STREAM_CHUNK 1024
#define STREAM_CHUNK_OUT (64*1024)

#define swab32(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swab32(x)

struct zip_stream {
	handle_t	h_ctx;
	int		alg_type;
	int		stream_pos;
	void *next_in;   /* next input byte */
	void *next_in_pa;   /* next input byte */
	void *temp_in_pa;   /* temp input byte */
	unsigned long  avail_in;  /* number of bytes available at next_in */
	unsigned long    total_in;  /* total nb of input bytes read so far */
	void  *next_out;  /* next output byte should be put there */
	void  *next_out_pa;  /* next output byte should be put there */
	unsigned long avail_out; /* remaining free space at next_out */
	unsigned long    total_out; /* total nb of bytes output so far */
	char     *msg;      /* last error message, NULL if no error */
	void     *workspace; /* memory allocated for this stream */
	int     data_type;  /*the data type: ascii or binary */
	void *ctx_buf;
	int ctx_dw0;
	int ctx_dw1;
	int ctx_dw2;
	int isize;
	int checksum;
	unsigned long   adler;      /* adler32 value of the uncompressed data */
	unsigned long   reserved;   /* reserved for future use */
};

int hw_init(struct zip_stream *zstrm, int alg_type, int comp_optype)
{
	int ret = 0;
	void *dma_buf;
	size_t ss_region_size;
	struct hisi_qm_priv *priv;
	struct hisi_qm_capa capa;

	switch (alg_type) {
	case 0:
		zstrm->alg_type = HW_ZLIB;
		capa.alg = "zlib";
		break;
	case 1:
		zstrm->alg_type = HW_GZIP;
		capa.alg = "gzip";
		break;
	default:
		zstrm->alg_type = HW_ZLIB;
		capa.alg = "zlib";
	}
	priv = (struct hisi_qm_priv *)capa.priv;
	priv->sqe_size = sizeof(struct hisi_zip_sqe);
	priv->op_type = comp_optype;

	zstrm->h_ctx = hisi_qm_alloc_ctx("/dev/hisi_zip-0", &capa);
	if (!zstrm->h_ctx)
		goto out;

	ss_region_size = 4096+ASIZE*2+HW_CTX_SIZE;

	if (wd_is_nosva(zstrm->h_ctx)) {
		dma_buf = wd_reserve_mem(zstrm->h_ctx, ss_region_size);
		if (!dma_buf) {
			fprintf(stderr, "fail to reserve %ld dmabuf\n",
				ss_region_size);
			ret = -ENOMEM;
			goto out_alloc;
		}
		ret = smm_init(dma_buf, ss_region_size, 0xF);
		if (ret)
			goto out_alloc;

		zstrm->next_in = smm_alloc(dma_buf, ASIZE);
		zstrm->next_out = smm_alloc(dma_buf, ASIZE);
		zstrm->ctx_buf = smm_alloc(dma_buf, HW_CTX_SIZE);
		zstrm->next_in_pa = wd_get_dma_from_va(zstrm->h_ctx,
						       zstrm->next_in);
		zstrm->next_out_pa = wd_get_dma_from_va(zstrm->h_ctx,
							zstrm->next_out);
		zstrm->ctx_buf = wd_get_dma_from_va(zstrm->h_ctx,
						    zstrm->ctx_buf);
		zstrm->workspace = dma_buf;
	} else {
		zstrm->next_in = malloc(ASIZE);
		zstrm->next_out = malloc(ASIZE);
		zstrm->ctx_buf = malloc(HW_CTX_SIZE);
		zstrm->next_in_pa = zstrm->next_in;
		zstrm->next_out_pa = zstrm->next_out;
	}

	if (!zstrm->next_in || !zstrm->next_out) {
		dbg("not enough data ss_region memory for cache 1 (bs=%d)\n",
			ASIZE);
			goto out_buf;
	}


	zstrm->temp_in_pa = zstrm->next_in_pa;
	return Z_OK;
out_buf:
	if (!wd_is_nosva(zstrm->h_ctx)) {
		free(zstrm->next_in);
		free(zstrm->next_out);
		free(zstrm->ctx_buf);
	}
out_alloc:
	hisi_qm_free_ctx(zstrm->h_ctx);
out:
	return ret;
}

void hw_end(struct zip_stream *zstrm)
{
	if (!wd_is_nosva(zstrm->h_ctx)) {
		hisi_qm_free_ctx(zstrm->h_ctx);
		free(zstrm->next_in);
		free(zstrm->next_out);
		free(zstrm->ctx_buf);
	} else
		hisi_qm_free_ctx(zstrm->h_ctx);
}

unsigned int bit_reverse(register unsigned int x)
{
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

	return((x >> 16) | (x << 16));
}

/* output an empty store block */
int append_store_block(struct zip_stream *zstrm, int flush)
{
	char store_block[5] = {0x1, 0x00, 0x00, 0xff, 0xff};
	__u32 checksum = zstrm->checksum;
	__u32 isize = zstrm->isize;

	memcpy(zstrm->next_out, store_block, 5);
	zstrm->total_out += 5;
	zstrm->avail_out -= 5;
	if (flush != WD_FINISH)
		return Z_STREAM_END;

	if (zstrm->alg_type == HW_ZLIB) { /*if zlib, ADLER32*/
		checksum = (__u32) cpu_to_be32(checksum);
		memcpy(zstrm->next_out + 5, &checksum, 4);
		zstrm->total_out += 4;
		zstrm->avail_out -= 4;
	} else if (zstrm->alg_type == HW_GZIP) {  /*if gzip, CRC32 and ISIZE*/
		checksum = ~checksum;
		checksum = bit_reverse(checksum);
		memcpy(zstrm->next_out + 5, &checksum, 4);
		memcpy(zstrm->next_out + 9, &isize, 4);
		zstrm->total_out += 8;
		zstrm->avail_out -= 8;
	} else
		fprintf(stderr, "in append store block, wrong alg type %d.\n",
				zstrm->alg_type);

	return Z_STREAM_END;
}

int hw_send_and_recv(struct zip_stream *zstrm, int flush, int comp_optype)
{
	struct hisi_zip_sqe *msg, *recv_msg;
	int ret = 0;
	__u32 status, type;
	__u64 stream_mode, stream_new, flush_type;

	if (zstrm->avail_in == 0)
		return append_store_block(zstrm, flush);

	msg = malloc(sizeof(*msg));
	if (!msg) {
		fputs("alloc msg fail!\n", stderr);
		goto msg_free;
	}

	stream_mode = STATEFUL;
	stream_new = zstrm->stream_pos;
	flush_type = (flush == WD_FINISH) ? HZ_FINISH : HZ_SYNC_FLUSH;

	memset((void *)msg, 0, sizeof(*msg));
	msg->dw9 = zstrm->alg_type;
	msg->dw7 |= ((stream_new << 2 | stream_mode << 1 |
			flush_type)) << STREAM_FLUSH_SHIFT;
	msg->source_addr_l = (__u64)zstrm->next_in_pa & 0xffffffff;
	msg->source_addr_h = (__u64)zstrm->next_in_pa >> 32;
	msg->dest_addr_l = (__u64)zstrm->next_out_pa & 0xffffffff;
	msg->dest_addr_h = (__u64)zstrm->next_out_pa >> 32;
	msg->input_data_length = zstrm->avail_in;
	msg->dest_avail_out = zstrm->avail_out;

	if (comp_optype == HW_INFLATE) {
		msg->stream_ctx_addr_l = (__u64)zstrm->ctx_buf & 0xffffffff;
		msg->stream_ctx_addr_h = (__u64)zstrm->ctx_buf >> 32;
	}
	msg->ctx_dw0 = zstrm->ctx_dw0;
	msg->ctx_dw1 = zstrm->ctx_dw1;
	msg->ctx_dw2 = zstrm->ctx_dw2;
	msg->isize = zstrm->isize;
	msg->checksum = zstrm->checksum;
	if (zstrm->stream_pos == STREAM_NEW) {
		zstrm->stream_pos = STREAM_OLD;
		zstrm->total_out = 0;
	}

	ret = hisi_qm_send(zstrm->h_ctx, msg);
	if (ret == -EBUSY) {
		usleep(1);
		goto recv_again;
	}

	SYS_ERR_COND(ret, "send fail!\n");
recv_again:
	ret = hisi_qm_recv(zstrm->h_ctx, (void **)&recv_msg);
	if (ret == -EIO) {
		fputs(" wd_recv fail!\n", stderr);
		goto msg_free;
	/* synchronous mode, if get none, then get again */
	} else if (ret == -EAGAIN)
		goto recv_again;
	status = recv_msg->dw3 & 0xff;
	type = recv_msg->dw9 & 0xff;
	SYS_ERR_COND(status != 0 && status != 0x0d && status != 0x13,
		     "bad status (s=%d, t=%d)\n", status, type);
	zstrm->avail_out -= recv_msg->produced;
	zstrm->total_out += recv_msg->produced;
	zstrm->avail_in -= recv_msg->consumed;
	zstrm->ctx_dw0 = recv_msg->ctx_dw0;
	zstrm->ctx_dw1 = recv_msg->ctx_dw1;
	zstrm->ctx_dw2 = recv_msg->ctx_dw2;
	zstrm->isize = recv_msg->isize;
	zstrm->checksum = recv_msg->checksum;
	if (zstrm->avail_out == 0)
		zstrm->next_in_pa +=  recv_msg->consumed;
	if (zstrm->avail_out > 0) {
		zstrm->avail_in = 0;
		zstrm->next_in_pa = zstrm->temp_in_pa;
	}

	if (ret == 0 && flush == WD_FINISH)
		ret = Z_STREAM_END;
	else if (ret == 0 &&  (recv_msg->dw3 & 0x1ff) == 0x113)
		ret = Z_STREAM_END;    /* decomp_is_end  region */

msg_free:
	free(msg);
	return ret;
}

int hw_deflate_ex(struct zip_stream *zstrm, int flush)
{
	return hw_send_and_recv(zstrm, flush, HW_DEFLATE);
}

int hw_inflate_ex(struct zip_stream *zstrm, int flush)
{
	return hw_send_and_recv(zstrm, flush, HW_INFLATE);
}

int hw_stream_def(FILE *source, FILE *dest,  int alg_type)
{
	int flush, have;
	int ret;
	struct zip_stream zstrm;
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x03};

	ret = hw_init(&zstrm, alg_type, HW_DEFLATE);
	if (ret != Z_OK)
		return ret;
	/* add zlib compress head and write head + compressed date to a file */
	if (alg_type == ZLIB)
		fwrite(zip_head, 1, 2, dest);
	else
		fwrite(gzip_head, 1, 10, dest);

	zstrm.stream_pos = STREAM_NEW;
	do {

		zstrm.avail_in =  fread(zstrm.next_in, 1, STREAM_CHUNK, source);
		flush = feof(source) ? WD_FINISH : WD_SYNC_FLUSH;
		do {
			zstrm.avail_out = STREAM_CHUNK_OUT;
			ret = hw_deflate_ex(&zstrm, flush);
			assert(ret != Z_STREAM_ERROR);
			have = STREAM_CHUNK_OUT - zstrm.avail_out;
			if (fwrite(zstrm.next_out, 1, have, dest) != have ||
				ferror(dest)) {
				fprintf(stderr, "errno =%d\n", errno);
				(void)hw_end(&zstrm);
				return Z_ERRNO;
			}
		} while (zstrm.avail_out == 0);
		assert(zstrm.avail_in == 0);   /* all input will be used */

		/* done when last data in file processed */
	} while (flush != WD_FINISH);

	assert(ret == Z_STREAM_END);       /* stream will be complete */
	hw_end(&zstrm);

	return Z_OK;
}

int hw_stream_inf(FILE *source, FILE *dest,  int alg_type)
{
	int have;
	int ret;
	char zip_head[2] = {0};
	char gzip_head[10] = {0};
	struct zip_stream zstrm;

	hw_init(&zstrm, alg_type, HW_INFLATE);
	if (alg_type == ZLIB)
		zstrm.avail_in = fread(zip_head, 1, 2, source);
	else
		zstrm.avail_in = fread(gzip_head, 1, 10, source);

	zstrm.stream_pos = STREAM_NEW;
	do {
		zstrm.avail_in = fread(zstrm.next_in, 1, STREAM_CHUNK, source);
		if (ferror(source)) {
			hw_end(&zstrm);
			return Z_ERRNO;
		}
		if (zstrm.avail_in == 0)
			break;
		/* finish compression if all of source has been read in */
		do {
			zstrm.avail_out = STREAM_CHUNK_OUT;
			ret = hw_inflate_ex(&zstrm, WD_SYNC_FLUSH);
			assert(ret != Z_STREAM_ERROR);
			have = STREAM_CHUNK_OUT - zstrm.avail_out;
			if (fwrite(zstrm.next_out, 1, have, dest) != have ||
				ferror(dest)) {
				hw_end(&zstrm);
				return Z_ERRNO;
			}

		} while (zstrm.avail_out == 0);
		assert(zstrm.avail_in == 0);    /* all input will be used */

		/* done when last data in file processed */
	} while (ret != Z_STREAM_END);

	assert(ret == Z_STREAM_END);            /* stream will be complete */
	hw_end(&zstrm);
	return Z_OK;
}

int main(int argc, char *argv[])
{
	int alg_type = 0;
	int cmd = 0;
	int ret;

	/* avoid end-of-line conversions */
	SET_BINARY_MODE(stdin);
	SET_BINARY_MODE(stdout);

	if (!argv[1]) {
		fputs("<<use ./test_hisi_zlib -h get more details>>\n", stderr);
		goto EXIT;
	}

	if (!strcmp(argv[1], "-z")) {
		alg_type = ZLIB;
		cmd = 0;
	} else if (!strcmp(argv[1], "-g")) {
		alg_type = GZIP;
		cmd = 0;
	} else if (!strcmp(argv[1], "-zd")) {
		alg_type = ZLIB;
		cmd = 1;
	} else if (!strcmp(argv[1], "-gd")) {
		alg_type = GZIP;
		cmd = 1;
	} else if (!strcmp(argv[1], "-h")) {
		fputs("[version]:1.0.2\n", stderr);
		fputs("[usage]: ./test_hisi_zlib [type] <src_file> dest_file\n",
			stderr);
		fputs("     [type]:\n", stderr);
		fputs("            -z  = zlib stream compress\n", stderr);
		fputs("            -zd = zlib stream decompress\n", stderr);
		fputs("            -g  = gzip stream compress\n", stderr);
		fputs("            -gd = gzip stream decompress\n", stderr);
		fputs("            -h  = usage\n", stderr);
		fputs("Example:\n", stderr);
		fputs("./test_hisi_zlib -z < test.data > out.data\n", stderr);
		goto EXIT;
	} else {
		fputs("Unknown option\n", stderr);
		fputs("<<use ./test_hisi_zlib -h get more details>>\n",
			stderr);
		goto EXIT;
	}

	switch (cmd) {
	case 0:
		ret = hw_stream_def(stdin, stdout, alg_type);
		if (ret)
			fputs("hw_stream_deflate error!\n", stderr);
		break;
	case 1:
		ret = hw_stream_inf(stdin, stdout, alg_type);
		if (ret)
			fputs("hw_stream_inflate error!\n", stderr);
		break;
	default:
		fputs("default cmd!\n", stderr);
	}
EXIT:
	return EXIT_SUCCESS;
}
