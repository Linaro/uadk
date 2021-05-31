/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/poll.h>

#include "../../wd.h"
#include "../../wd_util.h" /* It is not API head, to be deleted */
#include "wd_sched_sgl.h"
#include "../../wd_comp.h"
#include "../../wd_bmm.h"
#include "../../wd_sgl.h"

#include "zip_alg_sgl.h"
#include "../smm.h"


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
#define BLOCK_SIZE (1024 * 1024)
#define REQ_CACHE_NUM 4
#define Q_NUM 1

struct hizip_priv {
	int alg_type;
	int op_type;
	int block_size;
	int dw9;
	int total_len;
	int out_len;
	struct wcrypto_comp_msg *msgs;
	void *src, *dst;
	int is_fd;
};

enum alg_op_type {
	COMPRESS,
	DECOMPRESS,
};

/* block mode api use wd_schedule interface */

static void hizip_wd_sched_init_cache(struct wd_scheduler *sched, int i, int data_fmt)
{
	struct wd_msg *wd_msg = &sched->msgs[i];
	struct wcrypto_comp_msg *msg;
	struct hizip_priv *priv = sched->priv;

	msg = wd_msg->msg = &priv->msgs[i];
	msg->alg_type = priv->alg_type;
	msg->avail_out = sched->msg_data_size;
	msg->data_fmt = data_fmt;

	msg->src = wd_msg->data_in;
	msg->dst = wd_msg->data_out;

	dbg("init sched cache %d: %p, %p\n", i, wd_msg, msg);
}

static int hizip_wd_sched_input(struct wd_msg *msg, void *priv)
{
	size_t ilen, templen, real_len;
	struct wcrypto_comp_msg *m = msg->msg;
	struct hizip_priv *zip_priv = priv;

	ilen = zip_priv->total_len > zip_priv->block_size ?
		zip_priv->block_size : zip_priv->total_len;
	templen = ilen;
	zip_priv->total_len -= ilen;
	if (zip_priv->op_type == WCRYPTO_INFLATE) {
		if (zip_priv->alg_type == WCRYPTO_ZLIB) {
			zip_priv->src += ZLIB_HEADER_SZ;
			ilen -= ZLIB_HEADER_SZ;
		} else {
			ilen -= GZIP_HEADER_SZ;
			if (*((char *)zip_priv->src + 3) == 0x04) {
				zip_priv->src += GZIP_HEADER_SZ;
				memcpy(&ilen, zip_priv->src + 6, 4);
				zip_priv->src += GZIP_EXTRA_SZ;
				dbg("gzip iuput len %ld\n", ilen);
				SYS_ERR_COND(ilen > zip_priv->block_size * 2,
				"gzip protocol_len(%ld) > dmabuf_size(%d)\n",
				ilen, zip_priv->block_size);
				real_len = GZIP_HEADER_SZ +
							GZIP_EXTRA_SZ + ilen;
				zip_priv->total_len = zip_priv->total_len +
					      templen - real_len;
			} else
				zip_priv->src += GZIP_HEADER_SZ;
		}
	}

	if (m->data_fmt == WD_FLAT_BUF) /* use pbuffer */
		memcpy(msg->data_in, zip_priv->src, ilen);
	else   /* use sgl */
		wd_sgl_cp_from_pbuf(msg->data_in, 0, zip_priv->src, ilen);

	zip_priv->src += ilen;

	m->in_size = ilen;
	dbg("zip input ilen= %lu, block_size= %d, total_len= %d\n",
	    ilen, zip_priv->block_size, zip_priv->total_len);

	dbg("zip input(%p, %p): %p, %p, %d, %d\n",
	    msg, m, m->src, m->dst, m->avail_out, m->in_size);

	return 0;
}

static int hizip_wd_sched_output(struct wd_msg *msg, void *priv)
{
	struct wcrypto_comp_msg *m = msg->msg;
	struct hizip_priv *zip_priv = priv;
	char gzip_extra[GZIP_EXTRA_SZ] = {0x00, 0x07, 0x48, 0x69, 0x00, 0x04,
					  0x00, 0x00, 0x00, 0x00};

	dbg("%s()(%p, %p): %p, %p, inlen=%d, outlen=%d, coms=%d, out=%d\n",
	    __func__, msg, m, m->src, m->dst,
	    m->in_size, m->avail_out, m->in_cons, m->produced);

	if (zip_priv->op_type == WCRYPTO_DEFLATE) {

		if (zip_priv->alg_type == WCRYPTO_ZLIB) {
			memcpy(zip_priv->dst,
				       ZLIB_HEADER, ZLIB_HEADER_SZ);
			zip_priv->dst += ZLIB_HEADER_SZ;
			zip_priv->out_len += ZLIB_HEADER_SZ;
		} else {
			memcpy(gzip_extra + 6, &m->produced, 4);
			memcpy(zip_priv->dst, GZIP_HEADER,
				      GZIP_HEADER_SZ);
			zip_priv->dst += GZIP_HEADER_SZ;
			zip_priv->out_len += GZIP_HEADER_SZ;
			memcpy(zip_priv->dst, gzip_extra,
					GZIP_EXTRA_SZ);
			zip_priv->dst += GZIP_EXTRA_SZ;
			zip_priv->out_len += GZIP_EXTRA_SZ;
		}
	}

	if (m->data_fmt == WD_FLAT_BUF) /* use pbuffer */
		memcpy(zip_priv->dst, msg->data_out, m->produced);
	else   /* use sgl */
		wd_sgl_cp_to_pbuf(msg->data_out, 0, zip_priv->dst, m->produced);

	zip_priv->dst += m->produced;
	zip_priv->out_len += m->produced;

	return 0;
}

static int hizip_init(struct wd_scheduler *sched, int alg_type, int op_type,
		      int blk_size, int data_fmt)
{
	int ret = -ENOMEM, i;
	char *alg;
	struct wcrypto_paras *priv;
	struct hizip_priv *zip_priv;

	sched->q_num = Q_NUM;
	sched->ss_region_size = 0; /* let system make decision */
	sched->msg_cache_num = 1;
	/* use twice size of the input data, hope it is engouth for output */
	sched->msg_data_size = blk_size * 2;
	sched->init_cache = hizip_wd_sched_init_cache;
	sched->input = hizip_wd_sched_input;
	sched->output = hizip_wd_sched_output;

	sched->qs = calloc(sched->q_num, sizeof(struct wd_queue));
	if (!sched->qs)
		return -ENOMEM;

	zip_priv = calloc(1, sizeof(struct hizip_priv));
	if (!zip_priv)
		goto err_with_qs;

	zip_priv->msgs = calloc(sched->msg_cache_num,
				sizeof(struct wcrypto_comp_msg));
	if (!zip_priv->msgs)
		goto err_with_priv;

	zip_priv->alg_type = alg_type;
	zip_priv->op_type = op_type;
	zip_priv->block_size = blk_size;
	if (alg_type == WCRYPTO_ZLIB)
		alg = "zlib";
	else
		alg = "gzip";

	for (i = 0; i < sched->q_num; i++) {
		sched->qs[i].capa.alg = alg;
		priv = &sched->qs[i].capa.priv;
		priv->direction = zip_priv->op_type;
	}

	sched->priv = zip_priv;
	ret = wd_sched_init(sched, data_fmt);
	if (ret)
		goto err_with_msgs;

	return 0;

err_with_msgs:
	free(zip_priv->msgs);
err_with_priv:
	free(zip_priv);
err_with_qs:
	free(sched->qs);
	return ret;
}

static void hizip_fini(struct wd_scheduler *sched, int data_fmt)
{
	struct hizip_priv *zip_priv = sched->priv;

	wd_sched_fini(sched, data_fmt);
	free(zip_priv->msgs);
	free(zip_priv);
	free(sched->qs);
}

/**
 * compress() - compress memory buffer.
 * @alg_type: alg_type.
 *
 * This function compress memory buffer.
 */
int hw_blk_compress(int alg_type, int blksize,
		    unsigned char *dst, ulong *dstlen,
		    unsigned char *src, ulong srclen, int data_fmt)
{
	int ret;
	struct wd_scheduler sched;
	struct hizip_priv *zip_priv;

	if (blksize < 0 || dst == NULL || src == NULL)
		return -EINVAL;
	memset(&sched, 0, sizeof(struct wd_scheduler));
	//ret = hizip_init(&sched, alg_type, WCRYPTO_DEFLATE, blksize);
	ret = hizip_init(&sched, alg_type, WCRYPTO_DEFLATE, srclen, data_fmt);
	if (ret) {
		WD_ERR("fail to hizip init!\n");
		return ret;
	}
	zip_priv = sched.priv;
	zip_priv->total_len = srclen;
	zip_priv->src = src;
	zip_priv->dst = dst;
	zip_priv->is_fd = 0;

	while (zip_priv->total_len || !wd_sched_empty(&sched)) {
		dbg("request loop: total_len=%d\n", zip_priv->total_len);
		ret = wd_sched_work(&sched, zip_priv->total_len);
		if (ret < 0) {
			WD_ERR("wd_sched_work fail, ret=%d!\n", ret);
			return ret;
		}
	}

	*dstlen = zip_priv->out_len;
	hizip_fini(&sched, data_fmt);

	return ret;
}

int hw_blk_decompress(int alg_type, int blksize,
		      unsigned char *dst, ulong *dstlen,
		      unsigned char *src, ulong srclen, int data_fmt)
{
	int ret;
	struct wd_scheduler sched;
	struct hizip_priv *zip_priv;

	if (blksize < 0 || dst == NULL || src == NULL)
		return -EINVAL;
	memset(&sched, 0, sizeof(struct wd_scheduler));
	//ret = hizip_init(&sched, alg_type, WCRYPTO_INFLATE, blksize);
	ret = hizip_init(&sched, alg_type, WCRYPTO_INFLATE, srclen, data_fmt);
	if (ret) {
		WD_ERR("fail to hizip init!\n");
		return ret;
	}
	zip_priv = sched.priv;
	zip_priv->total_len = srclen;
	zip_priv->src = src;
	zip_priv->dst = dst;
	zip_priv->is_fd = 0;

	while (zip_priv->total_len || !wd_sched_empty(&sched)) {
		dbg("request loop: total_len=%d\n", zip_priv->total_len);
		ret = wd_sched_work(&sched, zip_priv->total_len);
		if (ret < 0) {
			WD_ERR("wd_sched_work fail, ret=%d!\n", ret);
			return ret;
		}
	}

	*dstlen = zip_priv->out_len;
	hizip_fini(&sched, data_fmt);

	return ret;
}

/* stream api  */
#define ST_ZLIB_HEADER "\x78\x9c"
#define ST_GZIP_HEADER "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"

#define ST_ZLIB_HEADER_SZ 2
#define ST_GZIP_HEADER_SZ 10

#define EMPTY_ZLIB_APPEND "\x03\x00\x00\x00\x00\x01"
#define EMPTY_ZLIB_SZ 6
#define EMPTY_GZIP_APPEND "\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define EMPTY_GZIP_SZ 10


#define Z_OK            0
#define Z_STREAM_END    1
#define Z_STREAM_NEED_AGAIN   2

#define Z_ERRNO (-1)
#define Z_STREAM_ERROR (-EIO)

#define swab32(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swab32(x)

/*wrap as zlib basic interface */
#define HZLIB_VERSION "1.0.1"

#ifndef MAX_WBITS
#define MAX_WBITS   15 /* 32K LZ77 window */
#endif

/* compression levels */
#define Z_NO_COMPRESSION         0
#define Z_BEST_SPEED             1
#define Z_BEST_COMPRESSION       9
#define Z_DEFAULT_COMPRESSION  (-1)


/* Maximum value for memLevel in deflateInit2 */
#ifndef MAX_MEM_LEVEL
#ifdef MAXSEG_64K
#define MAX_MEM_LEVEL 8
#else
#define MAX_MEM_LEVEL 9
#endif
#endif

/* default memLevel */
#ifndef DEF_MEM_LEVEL
#if MAX_MEM_LEVEL >= 8
#define DEF_MEM_LEVEL 8
#else
#define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#endif
#endif

/* compression strategy; see deflateInit2() below for details */
#define Z_DEFAULT_STRATEGY    0

/* default windowBits for decompression. MAX_WBITS is for compression only */
#ifndef DEF_WBITS
#define DEF_WBITS MAX_WBITS
#endif

/* The deflate compression method (the only one supported in this version) */
#define Z_DEFLATED   8

struct zip_stream {
	void *next_in;   /* next input byte */
	unsigned long  avail_in;  /* number of bytes available at next_in */
	unsigned long  total_in;  /* total nb of input bytes read so far */
	void  *next_out;  /* next output byte should be put there */
	unsigned long avail_out; /* remaining free space at next_out */
	unsigned long    total_out; /* total nb of bytes output so far */
	char     *msg;      /* last error message, NULL if no error */
	void     *workspace; /* memory allocated for this stream */
	int     data_type;  /*the data type: ascii or binary */
	unsigned long   adler;      /* adler32 value of the uncompressed data */
	void *reserved;   /* reserved for future use */
	int data_fmt;
};

struct zip_ctl {
	void *pool;
	void *in;
	void *out;
	void *ctxbuf;
	void *queue;
	void *ctx;
	void *opdata;
};

#define hw_deflateInit(strm, level) \
	hw_deflateInit_(strm, level, HZLIB_VERSION, sizeof(struct zip_stream))
#define hw_inflateInit(strm) \
	hw_inflateInit_(strm, HZLIB_VERSION, (int)sizeof(struct zip_stream))
#define hw_deflateInit2(strm, level, method, windowBits, memLevel, strategy) \
	hw_deflateInit2_(strm, level, method, windowBits, memLevel,\
		     (strategy), HZLIB_VERSION, (int)sizeof(struct zip_stream))
#define hw_inflateInit2(strm, windowBits) \
	hw_inflateInit2_(strm, windowBits, HZLIB_VERSION, \
		     (int)sizeof(struct zip_stream))

static int stream_chunk = 1024 * 64;

static int hw_init(struct zip_stream *zstrm, int alg_type, int comp_optype)
{
	struct wcrypto_comp_ctx_setup ctx_setup;
	struct wcrypto_comp_op_data *opdata;
	struct wd_blkpool_setup mm_setup;
	struct wd_sglpool_setup sp;
	unsigned int block_mm_num = 3;
	struct wcrypto_paras *priv;
	struct zip_ctl *ctl;
	void *in, *out;
	struct wd_queue *q;
	void *zip_ctx;
	void *pool;
	int ret;

	q = calloc(1, sizeof(struct wd_queue));
	if (q == NULL) {
		ret = -ENOMEM;
		fprintf(stderr, "alloc q fail, ret =%d\n", ret);
		return ret;
	}

	switch (alg_type) {
	case WCRYPTO_ZLIB:
		q->capa.alg = "zlib";
		break;
	case WCRYPTO_GZIP:
		q->capa.alg = "gzip";
		break;
	default:
		ret = -EINVAL;
		goto hw_q_free;
	}

	q->capa.latency = 0;
	q->capa.throughput = 0;

	priv = &q->capa.priv;
	priv->direction = comp_optype;
	ret = wd_request_queue(q);
	if (ret) {
		fprintf(stderr, "wd_request_queue fail, ret =%d\n", ret);
		goto hw_q_free;
	}
	SYS_ERR_COND(ret, "wd_request_queue");

#ifdef CONFIG_IOMMU_SVA
	in = calloc(1, DMEMSIZE);
	out = calloc(1, DMEMSIZE);
	ctx_buf = calloc(1, HW_CTX_SIZE);
	if (in == NULL || out == NULL || ctx_buf == NULL) {
		dbg("not enough data ss_region memory for cache (bs=%d)\n",
			DMEMSIZE);
		goto buf_free;
	}

#else
	if (zstrm->data_fmt == WD_FLAT_BUF) { /* use pbuffer */
		memset(&mm_setup, 0, sizeof(mm_setup));
		mm_setup.block_size = DMEMSIZE;
		mm_setup.block_num = block_mm_num;
		mm_setup.align_size = 128;
		pool = wd_blkpool_create(q, &mm_setup);
		if (!pool) {
			WD_ERR("%s(): create pool fail!\n", __func__);
			ret = -ENOMEM;
			goto release_q;
		}
		in = wd_alloc_blk(pool);
		out = wd_alloc_blk(pool);

		if (in == NULL || out == NULL) {
			dbg("not enough data ss_region memory for cache (bs=%d)\n",
				DMEMSIZE);
			goto buf_free;
		}
	} else {   /* use sgl */
		memset(&sp, 0, sizeof(sp));
		sp.buf_num = 200;
		sp.buf_size = 1024 * 1024 * 7;
		sp.align_size = 64;
		sp.sge_num_in_sgl = 20; //(DMEMSIZE / 1024 / sp.buf_size * 10 + 1) * 2;
		sp.buf_num_in_sgl = sp.sge_num_in_sgl;
		sp.sgl_num = block_mm_num;

		pool = wd_sglpool_create(q, &sp);
		if (!pool) {
			WD_ERR("%s(): create pool fail!\n", __func__);
			ret = -ENOMEM;
			goto release_q;
		}
		in = wd_alloc_sgl(pool, zstrm->avail_in);
		out = wd_alloc_sgl(pool, zstrm->avail_in);

		if (in == NULL || out == NULL) {
			dbg("not enough data ss_region memory for cache (bs=%d)\n",
				DMEMSIZE);
			goto buf_free;
		}
	}

#endif

	dbg("%s():va_in=%p, va_out=%p!\n", __func__, in, out);
	memset(&ctx_setup, 0, sizeof(ctx_setup));
	ctx_setup.alg_type = alg_type;
	ctx_setup.stream_mode = WCRYPTO_COMP_STATEFUL;
	if (zstrm->data_fmt == WD_FLAT_BUF) { /* use pbuffer */
		ctx_setup.data_fmt = WD_FLAT_BUF;
		ctx_setup.br.alloc = (void *)wd_alloc_blk;
		ctx_setup.br.free = (void *)wd_free_blk;
		ctx_setup.br.iova_map = (void *)wd_blk_iova_map;
		ctx_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
		ctx_setup.br.get_bufsize = (void *)wd_blksize;
		ctx_setup.br.usr = pool;
	} else {  /* WD_SGL_BUF */
		ctx_setup.data_fmt = WD_SGL_BUF;
		ctx_setup.br.alloc = (void *)wd_alloc_sgl;
		ctx_setup.br.free = (void *)wd_free_sgl;
		ctx_setup.br.iova_map = (void *)wd_sgl_iova_map;
		ctx_setup.br.iova_unmap = (void *)wd_sgl_iova_unmap;
		ctx_setup.br.usr = pool;
	}

	zip_ctx = wcrypto_create_comp_ctx(q, &ctx_setup);
	if (!zip_ctx) {
		fprintf(stderr, "zip_alloc_comp_ctx fail, ret =%d\n", ret);
		goto buf_free;
	}

	opdata = calloc(1, sizeof(struct wcrypto_comp_op_data));
	if (opdata == NULL) {
		ret = -ENOMEM;
		fprintf(stderr, "alloc opdata fail, ret =%d\n", ret);
		goto comp_ctx_free;
	}
	opdata->in = in;
	opdata->out = out;
	opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata->alg_type = ctx_setup.alg_type;

	ctl = calloc(1, sizeof(struct zip_ctl));
	if (ctl == NULL) {
		ret = -ENOMEM;
		fprintf(stderr, "alloc ctl fail, ret =%d\n", ret);
		goto comp_opdata_free;
	}
	ctl->pool = pool;
	ctl->in = in;  /* temp for opdata->in*/
	ctl->out = out;
	ctl->ctx = zip_ctx;
	ctl->queue = q;
	ctl->opdata = opdata;

	zstrm->next_in = in;
	zstrm->next_out = out;
	zstrm->reserved = ctl;

	return Z_OK;

comp_opdata_free:
	free(opdata);

comp_ctx_free:
	wcrypto_del_comp_ctx(zip_ctx);

buf_free:
#ifdef CONFIG_IOMMU_SVA
	if (in)
		free(in);
	if (out)
		free(out);
#else
	if (zstrm->data_fmt == WD_FLAT_BUF) { /* use pbuffer */
		if (in)
			wd_free_blk(pool, in);
		if (out)
			wd_free_blk(pool, out);

		wd_blkpool_destroy(pool);
	} else {   /* use sgl */
		if (in)
			wd_free_sgl(pool, in);
		if (out)
			wd_free_sgl(pool, out);

		wd_sglpool_destroy(pool);
	}

#endif
release_q:
	wd_release_queue(q);
hw_q_free:
	free(q);

	return ret;
}

static void hw_end(struct zip_stream *zstrm)
{
	struct zip_ctl *ctl = zstrm->reserved;
	struct wcrypto_comp_op_data *opdata = ctl->opdata;

#ifdef CONFIG_IOMMU_SVA
		if (ctl->in)
			free(ctl->in);
		if (ctl->out)
			free(ctl->out);
#else
	if (zstrm->data_fmt == WD_FLAT_BUF) { /* use pbuffer */
		if (ctl->in)
			wd_free_blk(ctl->pool, ctl->in);
		if (ctl->out)
			wd_free_blk(ctl->pool, ctl->out);
	} else {  /* use sgl */
		if (ctl->in)
			wd_free_sgl(ctl->pool, ctl->in);
		if (ctl->out)
			wd_free_sgl(ctl->pool, ctl->out);
	}
#endif

	if (ctl->ctx)
		wcrypto_del_comp_ctx(ctl->ctx);

	if (zstrm->data_fmt == WD_FLAT_BUF) /* use pbuffer */
		wd_blkpool_destroy(ctl->pool);
	else   /* use sgl */
		wd_sglpool_destroy(ctl->pool);

	if (ctl->queue) {
		wd_release_queue(ctl->queue);
		free(ctl->queue);
	}

	free(opdata);
	free(ctl);
}

static unsigned int bit_reverse(register unsigned int x)
{
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

	return((x >> 16) | (x << 16));
}

/* output an empty store block */
static int append_store_block(struct zip_stream *zstrm, int flush)
{
	char store_block[5] = {0x1, 0x00, 0x00, 0xff, 0xff};
	struct zip_ctl *ctl = zstrm->reserved;
	struct wcrypto_comp_op_data *opdata = ctl->opdata;
	__u32 checksum = opdata->checksum;
	__u32 isize = opdata->isize;

	memcpy(zstrm->next_out, store_block, 5);
	zstrm->total_out += 5;
	zstrm->avail_out -= 5;
	if (flush != WCRYPTO_FINISH)
		return Z_STREAM_END;

	if (opdata->alg_type == WCRYPTO_ZLIB) { /*if zlib, ADLER32*/
		checksum = (__u32) cpu_to_be32(checksum);
		memcpy(zstrm->next_out + 5, &checksum, 4);
		zstrm->total_out += 4;
		zstrm->avail_out -= 4;
	} else if (opdata->alg_type == WCRYPTO_GZIP) {
		checksum = ~checksum;
		checksum = bit_reverse(checksum);
		/* if gzip, CRC32 and ISIZE */
		memcpy(zstrm->next_out + 5, &checksum, 4);
		memcpy(zstrm->next_out + 9, &isize, 4);
		zstrm->total_out += 8;
		zstrm->avail_out -= 8;
	} else
		fprintf(stderr, "in append store block, wrong alg type %d.\n",
			opdata->alg_type);

	return Z_STREAM_END;
}

static int hw_send_and_recv(struct zip_stream *zstrm, int flush)
{
	struct zip_ctl *ctl = zstrm->reserved;
	struct wcrypto_comp_op_data *opdata = ctl->opdata;
	void *zip_ctx = ctl->ctx;
	int ret = 0;

	if (zstrm->avail_in == 0 && flush == WCRYPTO_FINISH)
		return append_store_block(zstrm, flush);

	opdata->flush = flush;
	opdata->in_len = zstrm->avail_in;
	opdata->avail_out = zstrm->avail_out;

	dbg("%s():input ,opdata->in_len=%u, zstrm->avail_out=%lu!\n",
	    __func__, opdata->in_len, zstrm->avail_out);

	ret = wcrypto_do_comp(zip_ctx, opdata, NULL);
	if (ret < 0)
		return ret;
	if (opdata->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
		opdata->stream_pos = WCRYPTO_COMP_STREAM_OLD;
		zstrm->total_out = 0;
	}

	dbg("%s():output, inlen=%d, coms=%d, produced=%d, avail_out=%lu!\n",
	    __func__, opdata->in_len, opdata->consumed,
	    opdata->produced, zstrm->avail_out);

	zstrm->avail_in = opdata->in_len - opdata->consumed;
	zstrm->avail_out -= opdata->produced;
	zstrm->total_out += opdata->produced;

	if (zstrm->avail_in > 0)
		opdata->in += opdata->consumed;
	if (zstrm->avail_in == 0)
		opdata->in = ctl->in;  /* origin addr in */

	if (ret == 0 && flush == WCRYPTO_FINISH)
		ret = Z_STREAM_END;
	else if (ret == 0 && opdata->status == WCRYPTO_DECOMP_END_NOSPACE)
		ret = Z_STREAM_NEED_AGAIN;    /* decomp_is_end region */
	else if (ret == 0 && opdata->status == WCRYPTO_DECOMP_END)
		ret = Z_STREAM_END;    /* decomp_is_end region */
	else if (ret == 0 && opdata->status == WD_VERIFY_ERR)
		ret = -WD_VERIFY_ERR;    /* crc err */
	else if (ret == 0 && opdata->status == WD_IN_EPARA)
		ret = -WD_IN_EPARA;    /* msg err */

	return ret;
}

int hw_deflateInit2_(struct zip_stream *zstrm, int level, int method,
		  int windowBits, int memLevel, int strategy,
		  const char *version, int stream_size)
{
	int alg_type;
	int wrap = 0;

	if (windowBits < 0) { /* suppress zlib wrapper */
		wrap = 0;
		windowBits = -windowBits;
	} else if (windowBits > 15) {
		wrap = 2;		/* write gzip wrapper instead */
		windowBits -= 16;
	}

	if (wrap & 0x02)
		alg_type = WCRYPTO_GZIP;
	else
		alg_type = WCRYPTO_ZLIB;

	return hw_init(zstrm, alg_type, WCRYPTO_DEFLATE);

}

int hw_deflateInit_(struct zip_stream *zstrm, int level, const char *version,
		 int stream_size)
{
	if (zstrm == NULL)
		return -EINVAL;

	return hw_deflateInit2_(zstrm, level, Z_DEFLATED,
				MAX_WBITS, DEF_MEM_LEVEL,
				Z_DEFAULT_STRATEGY, version, stream_size);
}

int hw_deflate(struct zip_stream *zstrm, int flush)
{
	int ret;

	if (zstrm == NULL)
		return -EINVAL;
	ret = hw_send_and_recv(zstrm, flush);
	if (ret < 0)
		return Z_STREAM_ERROR;
	return ret;
}

int hw_deflateEnd(struct zip_stream *zstrm)
{
	if (zstrm == NULL)
		return -EINVAL;
	hw_end(zstrm);
	return 0;
}

int hw_inflateInit2_(struct zip_stream *zstrm, int windowBits,
		  const char *version, int stream_size)
{
	int wrap, alg_type;

	/* extract wrap request from windowBits parameter */
	if (windowBits < 0) {
		wrap = 0;
		windowBits = -windowBits;
	} else {
		wrap = (windowBits >> 4) + 5;

	}
	if (wrap & 0x01)
		alg_type = WCRYPTO_ZLIB;
	if (wrap & 0x02)
		alg_type = WCRYPTO_GZIP;

	return hw_init(zstrm, alg_type, WCRYPTO_INFLATE);
}

int hw_inflateInit_(struct zip_stream *zstrm,
		    const char *version, int stream_size)
{
	if (zstrm == NULL)
		return -EINVAL;
	return hw_inflateInit2_(zstrm, DEF_WBITS, version, stream_size);
}

int hw_inflate(struct zip_stream *zstrm, int flush)
{
	int ret;

	if (zstrm == NULL)
		return -EINVAL;
	ret = hw_send_and_recv(zstrm, flush);
	if (ret < 0)
		return Z_STREAM_ERROR;
	return ret;
}

int hw_inflateEnd(struct zip_stream *zstrm)
{
	if (zstrm == NULL)
		return -EINVAL;
	hw_end(zstrm);
	return 0;
}

int hw_stream_compress(int alg_type, int blksize,
		       unsigned char *dst, ulong *dstlen,
		       unsigned char *src, ulong srclen, int data_fmt)
{
	int flush, have;
	int ret;
	int level = 0;
	struct zip_stream zstrm;
	int windowBits = 15;
	int GZIP_ENCODING = 16;

	if (blksize < 0 || dst == NULL || src == NULL)
		return -EINVAL;
	stream_chunk = 10240;  // blksize;
	*dstlen = 0;

	zstrm.data_fmt = data_fmt;
	/* add zlib compress head and write head + compressed date to a file */
	if (alg_type == WCRYPTO_ZLIB) {
		ret = hw_deflateInit(&zstrm, level);
		if (ret != Z_OK)
			return ret;
		memcpy(dst, ST_ZLIB_HEADER, ST_ZLIB_HEADER_SZ);
		dst += ST_ZLIB_HEADER_SZ;
		*dstlen += ST_ZLIB_HEADER_SZ;
	} else {
		/* deflate for gzip data */
		ret = hw_deflateInit2(&zstrm, Z_DEFAULT_COMPRESSION,
				   Z_DEFLATED, windowBits | GZIP_ENCODING, 8,
				   Z_DEFAULT_STRATEGY);
		if (ret != Z_OK)
			return ret;
		memcpy(dst, ST_GZIP_HEADER, ST_GZIP_HEADER_SZ);
		dst += ST_GZIP_HEADER_SZ;
		*dstlen += ST_GZIP_HEADER_SZ;
	}

	do {
		if (srclen > stream_chunk) {
			if (data_fmt == WD_FLAT_BUF)  /* use pbuffer */
				memcpy(zstrm.next_in, src, stream_chunk);
			else  /* use sgl */
				wd_sgl_cp_from_pbuf((struct wd_sgl *)zstrm.next_in, 0, src, stream_chunk);

			src += stream_chunk;
			zstrm.avail_in = stream_chunk;
			srclen -= stream_chunk;
		} else {
			if (data_fmt == WD_FLAT_BUF)  /* use pbuffer */
				memcpy(zstrm.next_in, src, srclen);
			else  /* use sgl */
				wd_sgl_cp_from_pbuf((struct wd_sgl *)zstrm.next_in, 0, src, srclen);

			zstrm.avail_in = srclen;
			srclen = 0;
		}
		flush = srclen ? WCRYPTO_SYNC_FLUSH : WCRYPTO_FINISH;
		do {
			zstrm.avail_out = stream_chunk;
			ret = hw_deflate(&zstrm, flush);
			ASSERT(ret != Z_STREAM_ERROR);
			if (ret < 0) {
				hw_end(&zstrm);
				return ret;
			}
			have = stream_chunk - zstrm.avail_out;
			if (data_fmt == WD_FLAT_BUF)  /* use pbuffer */
				memcpy(dst, zstrm.next_out, have);
			else  /* use sgl */
				wd_sgl_cp_to_pbuf((struct wd_sgl *)zstrm.next_out, 0, dst, have);

			dst += have;
			*dstlen += have;
		} while (zstrm.avail_in > 0);
		ASSERT(zstrm.avail_in == 0);   /* all input will be used */

		/* done when last data in file processed */
	} while (flush != WCRYPTO_FINISH);

	dbg("%s, end strm->total = %ld\n", __func__, zstrm.total_out);

	ASSERT(ret == Z_STREAM_END);       /* stream will be complete */
	hw_end(&zstrm);

	return Z_OK;
}

int hw_stream_decompress(int alg_type, int blksize,
			 unsigned char *dst, ulong *dstlen,
			 unsigned char *src, ulong srclen, int data_fmt)
{
	struct zip_stream zstrm;
	ulong out_size = 0;
	int have;
	int ret;

	if (blksize < 0 || dst == NULL || src == NULL)
		return -EINVAL;
	stream_chunk = 10240;  //blksize;

	zstrm.data_fmt = data_fmt;

	if (alg_type == WCRYPTO_ZLIB) {
		ret = hw_inflateInit(&zstrm);
		if (ret != Z_OK)
			return ret;
		src += ST_ZLIB_HEADER_SZ;
		srclen -= ST_ZLIB_HEADER_SZ;
	} else {
		ret = hw_inflateInit2(&zstrm, 16 + MAX_WBITS);
		if (ret != Z_OK)
			return ret;
		src += ST_GZIP_HEADER_SZ;
		srclen -= ST_GZIP_HEADER_SZ;
	}
	do {
		if (srclen > stream_chunk) {
			if (data_fmt == WD_FLAT_BUF)  /* use pbuffer */
				memcpy(zstrm.next_in, src, stream_chunk);
			else  /* use sgl */
				wd_sgl_cp_from_pbuf((struct wd_sgl *)zstrm.next_in, 0, src, stream_chunk);

			src += stream_chunk;
			zstrm.avail_in = stream_chunk;
			srclen -= stream_chunk;
		} else {
			if (data_fmt == WD_FLAT_BUF)  /* use pbuffer */
				memcpy(zstrm.next_in, src, srclen);
			else  /* use sgl */
				wd_sgl_cp_from_pbuf((struct wd_sgl *)zstrm.next_in, 0, src, srclen);

			zstrm.avail_in = srclen;
			srclen = 0;
		}
/*
 *		if (zstrm.avail_in == 0) {
 *			ret = Z_STREAM_END;
 *			break;
 *		}
 */
		/* finish compression if all of source has been read in */
		do {
			zstrm.avail_out = stream_chunk;
			ret = hw_inflate(&zstrm, WCRYPTO_SYNC_FLUSH);
			ASSERT(ret != Z_STREAM_ERROR);
			if (ret < 0) {
				hw_end(&zstrm);
				return ret;
			}
			have = stream_chunk - zstrm.avail_out;
			if (zstrm.total_out > *dstlen) {
				hw_end(&zstrm);
				return -ENOMEM;
			}
			if (data_fmt == WD_FLAT_BUF)  /* use pbuffer */
				memcpy(dst, zstrm.next_out, have);
			else  /* use sgl */
				wd_sgl_cp_to_pbuf((struct wd_sgl *)zstrm.next_out, 0, dst, have);

			dst += have;
			out_size += have;
		} while (zstrm.avail_in > 0);
		ASSERT(zstrm.avail_in == 0);    /* all input will be used */

		/* done when last data in file processed */
	} while (ret != Z_STREAM_END);

	dbg("%s, end strm->total = %ld\n", __func__, zstrm.total_out);

	*dstlen = out_size

	ASSERT(ret == Z_STREAM_END);            /* stream will be complete */
	hw_end(&zstrm);
	return Z_OK;
}

int hw_stream_def(FILE *source, FILE *dest,  int alg_type)
{
	int flush, have;
	int ret;
	int level = 0;
	struct zip_stream zstrm;
	int windowBits = 15;
	int GZIP_ENCODING = 16;
	int fd, file_len;
	struct stat s;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	file_len = s.st_size;
	if (!file_len) {
		if (alg_type == WCRYPTO_ZLIB) {
			fwrite(ST_ZLIB_HEADER, 1, ST_ZLIB_HEADER_SZ, dest);
			fwrite(EMPTY_ZLIB_APPEND, 1, EMPTY_ZLIB_SZ, dest);
			return Z_OK;
		} else if (alg_type == WCRYPTO_GZIP) {
			fwrite(ST_GZIP_HEADER, 1, ST_GZIP_HEADER_SZ, dest);
			fwrite(EMPTY_GZIP_APPEND, 1, EMPTY_GZIP_SZ, dest);
			return Z_OK;
		} else
			return -EINVAL;
	}
	/* add zlib compress head and write head + compressed date to a file */
	if (alg_type == WCRYPTO_ZLIB) {
		ret = hw_deflateInit(&zstrm, level);
		if (ret != Z_OK)
			return ret;
		fwrite(ST_ZLIB_HEADER, 1, ST_ZLIB_HEADER_SZ, dest);
	} else {
		/* deflate for gzip data */
		ret = hw_deflateInit2(&zstrm, Z_DEFAULT_COMPRESSION,
				   Z_DEFLATED, windowBits | GZIP_ENCODING, 8,
				   Z_DEFAULT_STRATEGY);
		if (ret != Z_OK)
			return ret;
		fwrite(ST_GZIP_HEADER, 1, ST_GZIP_HEADER_SZ, dest);
	}
	do {

		zstrm.avail_in =  fread(zstrm.next_in, 1, stream_chunk, source);
		flush = feof(source) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
		do {
			zstrm.avail_out = stream_chunk;
			ret = hw_deflate(&zstrm, flush);
			ASSERT(ret != Z_STREAM_ERROR);
			if (ret < 0) {
				hw_end(&zstrm);
				return ret;
			}
			have = stream_chunk - zstrm.avail_out;
			if (fwrite(zstrm.next_out, 1, have, dest) != have ||
				ferror(dest)) {
				fprintf(stderr, "errno =%d\n", errno);
				(void)hw_end(&zstrm);
				return Z_ERRNO;
			}
		} while (zstrm.avail_in > 0);
		ASSERT(zstrm.avail_in == 0);   /* all input will be used */

		/* done when last data in file processed */
	} while (flush != WCRYPTO_FINISH);

	dbg("%s, end strm->total = %ld\n", __func__, zstrm.total_out);

	ASSERT(ret == Z_STREAM_END);       /* stream will be complete */
	hw_end(&zstrm);

	return Z_OK;
}

int hw_stream_inf(FILE *source, FILE *dest,  int alg_type)
{
	int have;
	int ret;
	struct zip_stream zstrm;

	if (alg_type == WCRYPTO_ZLIB) {
		ret = hw_inflateInit(&zstrm);
		if (ret != Z_OK)
			return ret;
		fseek(source, ST_ZLIB_HEADER_SZ, SEEK_SET);
	} else {
		ret = hw_inflateInit2(&zstrm, 16 + MAX_WBITS);
		if (ret != Z_OK)
			return ret;
		fseek(source, ST_GZIP_HEADER_SZ, SEEK_SET);
	}
	do {
		zstrm.avail_in = fread(zstrm.next_in, 1, stream_chunk, source);
		if (ferror(source)) {
			hw_end(&zstrm);
			return Z_ERRNO;
		}
/*
 *		if (zstrm.avail_in == 0)
 *			break;
 */
		/* finish compression if all of source has been read in */
		do {
			zstrm.avail_out = stream_chunk;
			ret = hw_inflate(&zstrm, WCRYPTO_SYNC_FLUSH);
			ASSERT(ret != Z_STREAM_ERROR);
			if (ret < 0) {
				hw_end(&zstrm);
				return ret;
			}
			have = stream_chunk - zstrm.avail_out;
			if (fwrite(zstrm.next_out, 1, have, dest) != have ||
				ferror(dest)) {
				hw_end(&zstrm);
				return Z_ERRNO;
			}

		} while (zstrm.avail_in > 0);
		ASSERT(zstrm.avail_in == 0);    /* all input will be used */

		/* done when last data in file processed */
	} while (ret != Z_STREAM_END);

	dbg("%s, end strm->total = %ld\n", __func__, zstrm.total_out);

	ASSERT(ret == Z_STREAM_END);            /* stream will be complete */
	hw_end(&zstrm);
	return Z_OK;
}

