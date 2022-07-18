/* SPDX-License-Identifier: Apache-2.0 */

#include <numa.h>
#include "uadk_benchmark.h"

#include "zip_wd_benchmark.h"
#include "v1/wd_comp.h"
#include "v1/wd.h"
#include "v1/wd_bmm.h"
#include "v1/wd_util.h"
#include "include/fse.h"

#define ZIP_TST_PRT printf
#define PATH_SIZE	64
#define ZIP_FILE	"./zip"
#define WCRYPTO_DIR_MAX	(WCRYPTO_INFLATE + 1)
#define ALIGN_SIZE		64

#define COMP_LEN_RATE		2
#define DECOMP_LEN_RATE		2

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)

struct wd_bd {
	u8 *src;
	u8 *dst;
	u32 src_len;
	u32 dst_len;
};

struct thread_bd_res {
	struct wd_queue *queue;
	void *pool;
	struct wd_bd *bds;
};

struct thread_queue_res {
	struct thread_bd_res *bd_res;
};

static struct thread_queue_res g_thread_queue;

enum ZIP_OP_MODE {
	BLOCK_MODE,
	STREAM_MODE
};

struct zip_async_tag {
	void *ctx;
	u32 td_id;
	u32 bd_idx;
	u32 cm_len;
	void *priv;
	ZSTD_CCtx *cctx;
};

typedef struct uadk_thread_res {
	u32 alg;
	u32 mode; // block/stream
	u32 optype;
	u32 td_id;
} thread_data;

struct zip_file_head {
	u32 file_size;
	u32 block_num;
	u32 blk_sz[MAX_POOL_LENTH];
};

static unsigned int g_thread_num;
static unsigned int g_pktlen;

#ifndef ZLIB_FSE
static ZSTD_CCtx* zstd_soft_fse_init(unsigned    int level)
{
	return NULL;
}

static int zstd_soft_fse(void *Ftuple, ZSTD_inBuffer *input, ZSTD_outBuffer *output, ZSTD_CCtx * cctx, ZSTD_EndDirective cmode)
{
	return input->size;
}
#endif

static int save_file_data(const char *alg, u32 pkg_len, u32 optype)
{
	struct zip_file_head *fhead = NULL;
	char file_path[PATH_SIZE];
	u32 total_file_size = 0;
	double comp_rate = 0.0;
	u32 full_size;
	ssize_t size;
	int j, fd;
	int ret = 0;

	optype = optype % WCRYPTO_DIR_MAX;
	if (optype != WCRYPTO_DEFLATE) //compress
		return 0;

	ret = snprintf(file_path, PATH_SIZE, "%s_%u.%s", ZIP_FILE, pkg_len, alg);
	if (ret < 0)
		return -EINVAL;

	ret = access(file_path, F_OK);
	if (!ret) {
		ZIP_TST_PRT("compress data file: %s has exist!\n", file_path);
		return 0;
	}

	fd = open(file_path, O_WRONLY|O_CREAT, 0777);
	if (fd < 0) {
		ZIP_TST_PRT("compress data file open %s failed (%d)!\n", file_path, -errno);
		return -ENODEV;
	}

	fhead = malloc(sizeof(*fhead));
	if (!fhead) {
		ZIP_TST_PRT("failed to alloc file head memory\n");
		ret = -ENOMEM;
		goto fd_error;
	}

	// init file head informations
	for (j = 0; j < MAX_POOL_LENTH; j++) {
		fhead->blk_sz[j] = g_thread_queue.bd_res[0].bds[j].dst_len;
		total_file_size += fhead->blk_sz[j];
	}
	fhead->block_num = MAX_POOL_LENTH;
	fhead->file_size = total_file_size;
	size = write(fd, fhead, sizeof(*fhead));
	if (size < 0) {
		ZIP_TST_PRT("compress write file head failed: %lu!\n", size);
		ret = -ENODEV;
		goto write_error;
	}

	// write data for one buffer one buffer to file line.
	for (j = 0; j < MAX_POOL_LENTH; j++) {
		size = write(fd, g_thread_queue.bd_res[0].bds[j].dst,
				fhead->blk_sz[j]);
		if (size < 0) {
			ZIP_TST_PRT("compress write data error size: %lu!\n", size);
			ret = -ENODEV;
			break;
		}
	}

write_error:
	free(fhead);
fd_error:
	close(fd);

	full_size = g_pktlen * MAX_POOL_LENTH;
	comp_rate = (double) total_file_size / full_size;
	ZIP_TST_PRT("compress data rate: %.1f%%!\n", comp_rate * 100);

	return ret;
}

static int load_file_data(const char *alg, u32 pkg_len, u32 optype)
{
	struct zip_file_head *fhead = NULL;
	char file_path[PATH_SIZE];
	ssize_t size = 0xff;
	int i, j, fd;
	int ret;

	optype = optype % WCRYPTO_DIR_MAX;
	if (optype != WCRYPTO_INFLATE) //decompress
		return 0;

	ret = snprintf(file_path, PATH_SIZE, "%s_%u.%s", ZIP_FILE, pkg_len, alg);
	if (ret < 0)
		return -EINVAL;

	ret = access(file_path, F_OK);
	if (ret) {
		ZIP_TST_PRT("Decompress data file: %s not exist!\n", file_path);
		return -EINVAL;
	}

	// read data from file
	fd = open(file_path, O_RDONLY, 0);
	if (fd < 0) {
		ZIP_TST_PRT("Decompress data file open %s fail (%d)!\n", file_path, -errno);
		return -ENODEV;
	}

	fhead = malloc(sizeof(*fhead));
	if (!fhead) {
		ZIP_TST_PRT("failed to alloc file head memory\n");
		ret = -ENOMEM;
		goto fd_err;
	}
	size = read(fd, fhead, sizeof(*fhead));
	if (size < 0 || fhead->block_num != MAX_POOL_LENTH) {
		ZIP_TST_PRT("failed to read file head\n");
		ret = -EINVAL;
		goto read_err;
	}

	// read data for one buffer one buffer from file line
	for (j = 0; j < MAX_POOL_LENTH; j++) {
		memset(g_thread_queue.bd_res[0].bds[j].src, 0x0,
			g_thread_queue.bd_res[0].bds[j].src_len);
		if (size != 0) { // zero size buffer no need to read;
			size = read(fd, g_thread_queue.bd_res[0].bds[j].src,
					fhead->blk_sz[j]);
			if (size < 0) {
				ZIP_TST_PRT("Decompress read data error size: %lu!\n", size);
				ret = -EINVAL;
				goto read_err;
			} else if (size == 0) {
				ZIP_TST_PRT("Read file to the end!");
			}
		}
		g_thread_queue.bd_res[0].bds[j].src_len = size;
	}

	for (i = 1; i < g_thread_num; i++) {
		for (j = 0; j < MAX_POOL_LENTH; j++) {
			if (g_thread_queue.bd_res[0].bds[j].src_len)
				memcpy(g_thread_queue.bd_res[i].bds[j].src,
					g_thread_queue.bd_res[0].bds[j].src,
					g_thread_queue.bd_res[0].bds[j].src_len);
			g_thread_queue.bd_res[i].bds[j].src_len =
				g_thread_queue.bd_res[0].bds[j].src_len;
		}
	}

read_err:
	free(fhead);
fd_err:
	close(fd);

	return ret;
}

static int zip_wd_param_parse(thread_data *tddata, struct acc_option *options)
{
	u32 algtype = options->algtype;
	u32 optype = options->optype;
	u8 mode = BLOCK_MODE;
	u8 alg;

	if (optype >= WCRYPTO_DIR_MAX << 1) {
		ZIP_TST_PRT("Fail to get zip optype!\n");
		return -EINVAL;
	} else if (optype > WCRYPTO_INFLATE) {
		mode = STREAM_MODE;
	}

	optype = optype % WCRYPTO_DIR_MAX;

	switch(algtype) {
	case ZLIB:
		alg = WCRYPTO_ZLIB;
		break;
	case GZIP:
		alg = WCRYPTO_GZIP;
		break;
	case DEFLATE:
		alg = WCRYPTO_RAW_DEFLATE;
		break;
	case LZ77_ZSTD:
		alg = WCRYPTO_LZ77_ZSTD;
		if (optype == WCRYPTO_INFLATE)
			ZIP_TST_PRT("Zip LZ77_ZSTD just support compress!\n");
		optype = WCRYPTO_DEFLATE;
		break;
	default:
		ZIP_TST_PRT("Fail to set zip alg\n");
		return -EINVAL;
	}

	tddata->alg = alg;
	tddata->mode = mode;
	tddata->optype = optype;

	return 0;
}

static int init_zip_wd_queue(struct acc_option *options)
{
	struct wd_blkpool_setup blksetup;
	struct wd_bd *bds = NULL;
	void *pool = NULL;
	u32 outsize;
	u32 insize;
	u8 op_type;
	int i, j;
	int ret = 0;

	op_type = options->optype % WCRYPTO_DIR_MAX;
	if (op_type == WCRYPTO_DEFLATE) {//compress
		insize = g_pktlen;
		outsize = g_pktlen * COMP_LEN_RATE;
	} else { // decompress
		insize = g_pktlen;
		outsize = g_pktlen * DECOMP_LEN_RATE;
	}

	g_thread_queue.bd_res = malloc(g_thread_num * sizeof(struct thread_bd_res));
	if (!g_thread_queue.bd_res) {
		ZIP_TST_PRT("malloc thread res memory fail!\n");
		return -ENOMEM;
	}

	for (i = 0; i < g_thread_num; i++) {
		g_thread_queue.bd_res[i].queue = malloc(sizeof(struct wd_queue));
		g_thread_queue.bd_res[i].queue->capa.alg = options->algclass;
		// 0 is compress, 1 is decompress
		g_thread_queue.bd_res[i].queue->capa.priv.direction = op_type;
		/* nodemask need to    be clean */
		g_thread_queue.bd_res[i].queue->node_mask = 0x0;
		memset(g_thread_queue.bd_res[i].queue->dev_path, 0x0, PATH_STR_SIZE);

		ret = wd_request_queue(g_thread_queue.bd_res[i].queue);
		if (ret) {
			ZIP_TST_PRT("request queue %d fail!\n", i);
			ret = -EINVAL;
			goto queue_out;
		}
	}

	// use no-sva pbuffer, MAX_BLOCK_NM at least 4 times of MAX_POOL_LENTH
	memset(&blksetup, 0, sizeof(blksetup));
	outsize = ALIGN(outsize, ALIGN_SIZE);
	blksetup.block_size = outsize;
	blksetup.block_num = MAX_BLOCK_NM;
	blksetup.align_size = ALIGN_SIZE;
	// ZIP_TST_PRT("create pool memory: %d KB\n", (MAX_BLOCK_NM * blksetup.block_size) >> 10);

	for (j = 0; j < g_thread_num; j++) {
		g_thread_queue.bd_res[j].pool = wd_blkpool_create(g_thread_queue.bd_res[j].queue, &blksetup);
		if (!g_thread_queue.bd_res[j].pool) {
			ZIP_TST_PRT("create %dth pool fail!\n", j);
			ret = -ENOMEM;
			goto pool_err;
		}
		pool = g_thread_queue.bd_res[j].pool;

		g_thread_queue.bd_res[j].bds = malloc(sizeof(struct wd_bd) * MAX_POOL_LENTH);
		if (!g_thread_queue.bd_res[j].bds)
			goto bds_error;
		bds = g_thread_queue.bd_res[j].bds;

		for (i = 0; i < MAX_POOL_LENTH; i++) {
			bds[i].src = wd_alloc_blk(pool);
			if (!bds[i].src) {
				ret = -ENOMEM;
				goto blk_error2;
			}
			bds[i].src_len = insize;

			bds[i].dst = wd_alloc_blk(pool);
			if (!bds[i].dst) {
				ret = -ENOMEM;
				goto blk_error3;
			}
			bds[i].dst_len = outsize;

			get_rand_data(bds[i].src, insize);
		}

	}

	return 0;

blk_error3:
	wd_free_blk(pool, bds[i].src);
blk_error2:
	for (i--; i >= 0; i--) {
		wd_free_blk(pool, bds[i].src);
		wd_free_blk(pool, bds[i].dst);
	}
bds_error:
	wd_blkpool_destroy(g_thread_queue.bd_res[j].pool);
pool_err:
	for (j--; j >= 0; j--) {
		pool = g_thread_queue.bd_res[j].pool;
		bds = g_thread_queue.bd_res[j].bds;
		for (i = 0; i < MAX_POOL_LENTH; i++) {
			wd_free_blk(pool, bds[i].src);
			wd_free_blk(pool, bds[i].dst);
		}
		free(bds);
		wd_blkpool_destroy(pool);
	}
queue_out:
	for (i--; i >= 0; i--) {
		wd_release_queue(g_thread_queue.bd_res[i].queue);
		free(g_thread_queue.bd_res[i].queue);
	}
	free(g_thread_queue.bd_res);
	return ret;
}

static void uninit_zip_wd_queue(void)
{
	struct wd_bd *bds = NULL;
	void *pool = NULL;
	int j, i;

	for (j = 0; j < g_thread_num; j++) {
		pool = g_thread_queue.bd_res[j].pool;
		bds = g_thread_queue.bd_res[j].bds;
		for (i = 0; i < MAX_POOL_LENTH; i++) {
			wd_free_blk(pool, bds[i].src);
			wd_free_blk(pool, bds[i].dst);
		}

		free(bds);
		wd_blkpool_destroy(pool);
		wd_release_queue(g_thread_queue.bd_res[j].queue);
	}

	free(g_thread_queue.bd_res);
}

/*-------------------------------uadk benchmark main code-------------------------------------*/
static void zip_lz77_async_cb(const void *message, void *data)
{
	const struct wcrypto_comp_msg *cbmsg = message;
	struct zip_async_tag *tag = data;
	ZSTD_CCtx *cctx = tag->cctx;
	ZSTD_inBuffer zstd_input;
	ZSTD_outBuffer zstd_output;
	struct wd_bd *bd_pool;
	int td_id = tag->td_id;
	int idx = tag->bd_idx;
	size_t fse_size;

	bd_pool = g_thread_queue.bd_res[td_id].bds;
	bd_pool[idx].dst_len = cbmsg->produced;

	zstd_input.src = cbmsg->src;
	zstd_input.size = cbmsg->in_size;
	zstd_input.pos = 0;
	zstd_output.dst = bd_pool[idx].dst;
	zstd_output.size = tag->cm_len;
	zstd_output.pos = 0;
	fse_size = zstd_soft_fse(tag->priv, &zstd_input, &zstd_output, cctx, ZSTD_e_end);

	bd_pool[idx].dst_len = fse_size;
}

static void zip_async_cb(const void *message, void *data)
{
	const struct wcrypto_comp_msg *cbmsg = message;
	struct zip_async_tag *tag = data;
	struct wd_bd *bd_pool;
	int td_id = tag->td_id;
	int idx = tag->bd_idx;

	bd_pool = g_thread_queue.bd_res[td_id].bds;
	bd_pool[idx].dst_len = cbmsg->produced;
}

static void *zip_wd_poll(void *data)
{
	thread_data *pdata = (thread_data *)data;
	u32 expt = ACC_QUEUE_SIZE * g_thread_num;
	struct wd_queue *queue;
	u32 id = pdata->td_id;
	u32 last_time = 2; // poll need one more recv time
	u32 count = 0;
	int recv = 0;

	if (id > g_thread_num)
		return NULL;

	queue = g_thread_queue.bd_res[id].queue;
	while (last_time) {
		recv = wcrypto_comp_poll(queue, expt);
		if (unlikely(recv != -WD_EAGAIN && recv < 0)) {
			ZIP_TST_PRT("poll ret: %u!\n", recv);
			goto recv_error;
		}

		count += recv;
		recv = 0;

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *zip_wd_blk_lz77_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	ZSTD_CCtx *cctx = zstd_soft_fse_init(15);
	ZSTD_inBuffer zstd_input = {0};
	ZSTD_outBuffer zstd_output = {0};
	COMP_TUPLE_TAG *ftuple = NULL;
	struct wcrypto_comp_ctx_setup comp_setup;
	struct wcrypto_comp_op_data opdata;
	struct wcrypto_comp_ctx *ctx;
	struct wd_queue *queue;
	struct wd_bd *bd_pool;
	u8 *hw_buff_out = NULL;
	size_t fse_size;
	u32 first_len = 0;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_pool = g_thread_queue.bd_res[pdata->td_id].bds;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&opdata, 0, sizeof(opdata));

	comp_setup.br.alloc = (void *)wd_alloc_blk;
	comp_setup.br.free = (void *)wd_free_blk;
	comp_setup.br.iova_map = (void *)wd_blk_iova_map;
	comp_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	comp_setup.br.get_bufsize = (void *)wd_blksize;
	comp_setup.br.usr = g_thread_queue.bd_res[pdata->td_id].pool;

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WCRYPTO_COMP_L8;
	comp_setup.win_size = WCRYPTO_COMP_WS_8K;
	comp_setup.stream_mode = WCRYPTO_COMP_STATELESS;

	ctx = wcrypto_create_comp_ctx(queue, &comp_setup);
	if (!ctx)
		return NULL;

	opdata.stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata.alg_type = pdata->alg;
	opdata.priv = NULL;
	opdata.status = 0;
	if (pdata->optype == WCRYPTO_INFLATE)
		opdata.flush = WCRYPTO_SYNC_FLUSH;
	else
		opdata.flush = WCRYPTO_FINISH;

	out_len = bd_pool[0].dst_len;

	ftuple = malloc(sizeof(COMP_TUPLE_TAG) * MAX_POOL_LENTH);
	if (!ftuple)
		goto fse_err;

	hw_buff_out = malloc(out_len * MAX_POOL_LENTH);
	if (!hw_buff_out)
		goto hw_buff_err;
	memset(hw_buff_out, 0x0, out_len * MAX_POOL_LENTH);

	while(1) {
		i = count % MAX_POOL_LENTH;
		opdata.in = bd_pool[i].src;
		opdata.out = &hw_buff_out[i]; //temp out
		opdata.in_len = bd_pool[i].src_len;
		opdata.avail_out = out_len;
		opdata.priv = &ftuple[i];

		ret = wcrypto_do_comp(ctx, &opdata, NULL);
		if (ret || opdata.status == WCRYPTO_DECOMP_END_NOSPACE ||
		     opdata.status == WD_IN_EPARA || opdata.status == WD_VERIFY_ERR)
			break;

		count++;
		zstd_input.src = opdata.in;
		zstd_input.size = opdata.in_len;
		zstd_input.pos = 0;
		zstd_output.dst = bd_pool[i].dst;
		zstd_output.size = out_len;
		zstd_output.pos = 0;
		fse_size = zstd_soft_fse(opdata.priv, &zstd_input, &zstd_output, cctx, ZSTD_e_end);

		bd_pool[i].dst_len = fse_size;
		if (unlikely(i == 0))
			first_len = fse_size;
		if (get_run_state() == 0)
			break;
	}

hw_buff_err:
	free(hw_buff_out);
fse_err:
	free(ftuple);
	wcrypto_del_comp_ctx(ctx);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, opdata.produced);
	if (pdata->optype == WCRYPTO_DEFLATE)
		add_recv_data(count, opdata.in_len);
	else
		add_recv_data(count, first_len);

	return NULL;
}

static void *zip_wd_stm_lz77_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	ZSTD_CCtx *cctx = zstd_soft_fse_init(15);
	ZSTD_inBuffer zstd_input = {0};
	ZSTD_outBuffer zstd_output = {0};
	COMP_TUPLE_TAG *ftuple = NULL;
	struct wcrypto_comp_ctx_setup comp_setup;
	struct wcrypto_comp_op_data opdata;
	struct wcrypto_comp_ctx *ctx;
	struct wd_queue *queue;
	struct wd_bd *bd_pool;
	u8 *hw_buff_out = NULL;
	size_t fse_size;
	u32 first_len = 0;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_pool = g_thread_queue.bd_res[pdata->td_id].bds;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&opdata, 0, sizeof(opdata));

	comp_setup.br.alloc = (void *)wd_alloc_blk;
	comp_setup.br.free = (void *)wd_free_blk;
	comp_setup.br.iova_map = (void *)wd_blk_iova_map;
	comp_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	comp_setup.br.get_bufsize = (void *)wd_blksize;
	comp_setup.br.usr = g_thread_queue.bd_res[pdata->td_id].pool;

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WCRYPTO_COMP_L8;
	comp_setup.win_size = WCRYPTO_COMP_WS_8K;
	comp_setup.stream_mode = WCRYPTO_COMP_STATEFUL;

	ctx = wcrypto_create_comp_ctx(queue, &comp_setup);
	if (!ctx)
		return NULL;

	opdata.stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata.alg_type = pdata->alg;
	opdata.priv = NULL;
	opdata.status = 0;
	if (pdata->optype == WCRYPTO_INFLATE)
		opdata.flush = WCRYPTO_SYNC_FLUSH;
	else
		opdata.flush = WCRYPTO_FINISH;

	out_len = bd_pool[0].dst_len;

	ftuple = malloc(sizeof(COMP_TUPLE_TAG) * MAX_POOL_LENTH);
	if (!ftuple)
		goto fse_err;

	hw_buff_out = malloc(out_len * MAX_POOL_LENTH);
	if (!hw_buff_out)
		goto hw_buff_err;
	memset(hw_buff_out, 0x0, out_len * MAX_POOL_LENTH);

	while(1) {
		i = count % MAX_POOL_LENTH;
		opdata.in = bd_pool[i].src;
		opdata.out = &hw_buff_out[i]; //temp out
		opdata.in_len = bd_pool[i].src_len;
		opdata.avail_out = out_len;
		opdata.priv = &ftuple[i];

		ret = wcrypto_do_comp(ctx, &opdata, NULL);
		if (ret || opdata.status == WCRYPTO_DECOMP_END_NOSPACE ||
		     opdata.status == WD_IN_EPARA || opdata.status == WD_VERIFY_ERR) {
			ZIP_TST_PRT("wd comp, invalid or incomplete data! "
			       "ret(%d), req.status(%u)\n", ret, opdata.status);
			break;
		}

		count++;
		zstd_input.src = opdata.in;
		zstd_input.size = opdata.in_len;
		zstd_input.pos = 0;
		zstd_output.dst = opdata.out;
		zstd_output.size = out_len;
		zstd_output.pos = 0;
		fse_size = zstd_soft_fse(opdata.priv, &zstd_input, &zstd_output, cctx, ZSTD_e_end);

		bd_pool[i].dst_len = fse_size;
		if (unlikely(i == 0))
			first_len = fse_size;
		if (get_run_state() == 0)
			break;
	}

hw_buff_err:
	free(hw_buff_out);
fse_err:
	free(ftuple);
	wcrypto_del_comp_ctx(ctx);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, opdata.produced);
	if (pdata->optype == WCRYPTO_DEFLATE)
		add_recv_data(count, opdata.in_len);
	else
		add_recv_data(count, first_len);

	return NULL;
}

static void *zip_wd_blk_lz77_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	ZSTD_CCtx *cctx = zstd_soft_fse_init(15);
	COMP_TUPLE_TAG *ftuple = NULL;
	struct wcrypto_comp_ctx_setup comp_setup;
	struct wcrypto_comp_op_data opdata;
	struct wcrypto_comp_ctx *ctx;
	struct zip_async_tag *tag;
	u8 *hw_buff_out = NULL;
	struct wd_queue *queue;
	struct wd_bd *bd_pool;
	u32 out_len = 0;
	u32 count = 0;
	u32 try_cnt = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_pool = g_thread_queue.bd_res[pdata->td_id].bds;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&opdata, 0, sizeof(opdata));

	comp_setup.br.alloc = (void *)wd_alloc_blk;
	comp_setup.br.free = (void *)wd_free_blk;
	comp_setup.br.iova_map = (void *)wd_blk_iova_map;
	comp_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	comp_setup.br.get_bufsize = (void *)wd_blksize;
	comp_setup.br.usr = g_thread_queue.bd_res[pdata->td_id].pool;

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WCRYPTO_COMP_L8;
	comp_setup.win_size = WCRYPTO_COMP_WS_8K;
	comp_setup.stream_mode = WCRYPTO_COMP_STATELESS;
	comp_setup.cb = zip_lz77_async_cb;

	ctx = wcrypto_create_comp_ctx(queue, &comp_setup);
	if (!ctx)
		return NULL;

	opdata.stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata.alg_type = pdata->alg;
	opdata.priv = NULL;
	opdata.status = 0;
	if (pdata->optype == WCRYPTO_INFLATE)
		opdata.flush = WCRYPTO_SYNC_FLUSH;
	else
		opdata.flush = WCRYPTO_FINISH;

	out_len = bd_pool[0].dst_len;

	ftuple = malloc(sizeof(COMP_TUPLE_TAG) * MAX_POOL_LENTH);
	if (!ftuple)
		goto fse_err;

	hw_buff_out = malloc(out_len * MAX_POOL_LENTH);
	if (!hw_buff_out)
		goto hw_buff_err;
	memset(hw_buff_out, 0x0, out_len * MAX_POOL_LENTH);

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		ZIP_TST_PRT("failed to malloc zip tag!\n");
		goto tag_err;
	}

	while(1) {
		if (get_run_state() == 0)
				break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		opdata.in = bd_pool[i].src;
		opdata.out = &hw_buff_out[i]; //temp out
		opdata.in_len = bd_pool[i].src_len;
		opdata.avail_out = out_len;
		opdata.priv = &ftuple[i];

		tag[i].td_id = pdata->td_id;
		tag[i].ctx = ctx;
		tag[i].td_id = pdata->td_id;
		tag[i].cm_len = out_len;
		tag[i].cctx = cctx;
		tag[i].priv = opdata.priv;

		ret = wcrypto_do_comp(ctx, &opdata, &tag[i]);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				ZIP_TST_PRT("Test LZ77 compress send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if   (ret || opdata.status == WCRYPTO_DECOMP_END_NOSPACE ||
			opdata.status == WD_IN_EPARA || opdata.status == WD_VERIFY_ERR) {
			break;
		}
		count++;
	}

	while (1) {
		if (get_recv_time() > 0) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}

tag_err:
	free(tag);
hw_buff_err:
	free(hw_buff_out);
fse_err:
	free(ftuple);
	wcrypto_del_comp_ctx(ctx);

	// ZIP_TST_PRT("LZ77 valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, opdata.produced);

	add_send_complete();

	return NULL;
}

static void *zip_wd_blk_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wcrypto_comp_ctx_setup comp_setup;
	struct wcrypto_comp_op_data opdata;
	struct wcrypto_comp_ctx *ctx;
	struct wd_queue *queue;
	struct wd_bd *bd_pool;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_pool = g_thread_queue.bd_res[pdata->td_id].bds;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&opdata, 0, sizeof(opdata));

	comp_setup.br.alloc = (void *)wd_alloc_blk;
	comp_setup.br.free = (void *)wd_free_blk;
	comp_setup.br.iova_map = (void *)wd_blk_iova_map;
	comp_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	comp_setup.br.get_bufsize = (void *)wd_blksize;
	comp_setup.br.usr = g_thread_queue.bd_res[pdata->td_id].pool;

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WCRYPTO_COMP_L8;
	comp_setup.win_size = WCRYPTO_COMP_WS_8K;
	comp_setup.stream_mode = WCRYPTO_COMP_STATELESS;

	ctx = wcrypto_create_comp_ctx(queue, &comp_setup);
	if (!ctx)
		return NULL;

	opdata.stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata.alg_type = pdata->alg;
	opdata.priv = NULL;
	opdata.status = 0;
	if (pdata->optype == WCRYPTO_INFLATE)
		opdata.flush = WCRYPTO_SYNC_FLUSH;
	else
		opdata.flush = WCRYPTO_FINISH;

	out_len = bd_pool[0].dst_len;

	while(1) {
		i = count % MAX_POOL_LENTH;
		opdata.in = bd_pool[i].src;
		opdata.out = bd_pool[i].dst;
		opdata.in_len = bd_pool[i].src_len;
		opdata.avail_out = out_len;

		ret = wcrypto_do_comp(ctx, &opdata, NULL);
		if (ret || opdata.status == WCRYPTO_DECOMP_END_NOSPACE ||
		     opdata.status == WD_IN_EPARA || opdata.status == WD_VERIFY_ERR)
			break;

		count++;
		bd_pool[i].dst_len = opdata.produced;
		if (get_run_state() == 0)
			break;
	}
	wcrypto_del_comp_ctx(ctx);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, opdata.produced);
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *zip_wd_stm_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wcrypto_comp_ctx_setup comp_setup;
	struct wcrypto_comp_op_data opdata;
	struct wcrypto_comp_ctx *ctx;
	struct wd_queue *queue;
	struct wd_bd *bd_pool;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_pool = g_thread_queue.bd_res[pdata->td_id].bds;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&opdata, 0, sizeof(opdata));

	comp_setup.br.alloc = (void *)wd_alloc_blk;
	comp_setup.br.free = (void *)wd_free_blk;
	comp_setup.br.iova_map = (void *)wd_blk_iova_map;
	comp_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	comp_setup.br.get_bufsize = (void *)wd_blksize;
	comp_setup.br.usr = g_thread_queue.bd_res[pdata->td_id].pool;

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WCRYPTO_COMP_L8;
	comp_setup.win_size = WCRYPTO_COMP_WS_8K;
	comp_setup.stream_mode = WCRYPTO_COMP_STATEFUL;

	ctx = wcrypto_create_comp_ctx(queue, &comp_setup);
	if (!ctx)
		return NULL;

	opdata.stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata.alg_type = pdata->alg;
	opdata.priv = NULL;
	opdata.status = 0;
	if (pdata->optype == WCRYPTO_INFLATE)
		opdata.flush = WCRYPTO_SYNC_FLUSH;
	else
		opdata.flush = WCRYPTO_FINISH;

	out_len = bd_pool[0].dst_len;

	while(1) {
		i = count % MAX_POOL_LENTH;
		opdata.in = bd_pool[i].src;
		opdata.out = bd_pool[i].dst;
		opdata.in_len = bd_pool[i].src_len;
		opdata.avail_out = out_len;

		ret = wcrypto_do_comp(ctx, &opdata, NULL);
		if (ret || opdata.status == WCRYPTO_DECOMP_END_NOSPACE ||
		     opdata.status == WD_IN_EPARA || opdata.status == WD_VERIFY_ERR) {
			ZIP_TST_PRT("wd comp, invalid or incomplete data! "
			       "ret(%d), req.status(%u)\n", ret, opdata.status);
			break;
		}

		count++;
		bd_pool[i].dst_len = opdata.produced;
		if (get_run_state() == 0)
			break;
	}
	wcrypto_del_comp_ctx(ctx);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, opdata.produced);
	add_recv_data(count, g_pktlen);

	return NULL;

}

static void *zip_wd_blk_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wcrypto_comp_ctx_setup comp_setup;
	struct wcrypto_comp_op_data opdata;
	struct wcrypto_comp_ctx *ctx;
	struct zip_async_tag *tag;
	struct wd_queue *queue;
	struct wd_bd *bd_pool;
	int try_cnt = 0;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	bd_pool = g_thread_queue.bd_res[pdata->td_id].bds;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&opdata, 0, sizeof(opdata));

	comp_setup.br.alloc = (void *)wd_alloc_blk;
	comp_setup.br.free = (void *)wd_free_blk;
	comp_setup.br.iova_map = (void *)wd_blk_iova_map;
	comp_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	comp_setup.br.get_bufsize = (void *)wd_blksize;
	comp_setup.br.usr = g_thread_queue.bd_res[pdata->td_id].pool;

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WCRYPTO_COMP_L8;
	comp_setup.win_size = WCRYPTO_COMP_WS_8K;
	comp_setup.stream_mode = WCRYPTO_COMP_STATELESS;
	comp_setup.cb = zip_async_cb;

	ctx = wcrypto_create_comp_ctx(queue, &comp_setup);
	if (!ctx)
		return NULL;

	opdata.stream_pos = WCRYPTO_COMP_STREAM_NEW;
	opdata.alg_type = pdata->alg;
	opdata.priv = NULL;
	opdata.status = 0;
	if (pdata->optype == WCRYPTO_INFLATE)
		opdata.flush = WCRYPTO_SYNC_FLUSH;
	else
		opdata.flush = WCRYPTO_FINISH;

	out_len = bd_pool[0].dst_len;
	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		ZIP_TST_PRT("failed to malloc zip tag!\n");
		goto tag_release;
	}

	while(1) {
		if (get_run_state() == 0)
			break;

		i = count % MAX_POOL_LENTH;
		opdata.in = bd_pool[i].src;
		opdata.out = bd_pool[i].dst;
		opdata.in_len = bd_pool[i].src_len;
		opdata.avail_out = out_len;

		try_cnt = 0;
		tag[i].ctx = ctx;
		tag[i].td_id = pdata->td_id;
		tag[i].bd_idx = i;

		ret = wcrypto_do_comp(ctx, &opdata, &tag[i]);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				ZIP_TST_PRT("Test compress send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret || opdata.status == WCRYPTO_DECOMP_END_NOSPACE ||
		     opdata.status == WD_IN_EPARA || opdata.status == WD_VERIFY_ERR) {
			break;
		}

		count++;
	}

	while (1) {
		if (get_recv_time() > 0) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}

tag_release:
	free(tag);
	wcrypto_del_comp_ctx(ctx);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, opdata.produced);

	add_send_complete();

	return NULL;
}

static int zip_wd_sync_threads(struct acc_option *options)
{
	typedef void *(*zip_sync_run)(void *arg);
	zip_sync_run wd_zip_sync_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = zip_wd_param_parse(&threads_option, options);
	if (ret)
		return ret;

	if (threads_option.mode == 1) {// stream mode
		if (threads_option.alg == LZ77_ZSTD)
			wd_zip_sync_run = zip_wd_stm_lz77_sync_run;
		else
			wd_zip_sync_run = zip_wd_stm_sync_run;
	} else {
		if (threads_option.alg == LZ77_ZSTD)
			wd_zip_sync_run = zip_wd_blk_lz77_sync_run;
		else
			wd_zip_sync_run = zip_wd_blk_sync_run;
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].alg = threads_option.alg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, wd_zip_sync_run, &threads_args[i]);
		if (ret) {
			ZIP_TST_PRT("Create sync thread fail!\n");
			goto sync_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			ZIP_TST_PRT("Join sync thread fail!\n");
			goto sync_error;
		}
	}

sync_error:
	return ret;
}

static int zip_wd_async_threads(struct acc_option *options)
{
	typedef void *(*zip_async_run)(void *arg);
	zip_async_run wd_zip_async_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = zip_wd_param_parse(&threads_option, options);
	if (ret)
		return ret;

	if (threads_option.mode == STREAM_MODE) {// stream mode
		ZIP_TST_PRT("Stream mode can't support async mode!\n");
		return 0;
	}

	if (threads_option.alg == LZ77_ZSTD)
		wd_zip_async_run = zip_wd_blk_lz77_async_run;
	else
		wd_zip_async_run = zip_wd_blk_async_run;

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].td_id = i;
		/* poll thread */
		ret = pthread_create(&pollid[i], NULL, zip_wd_poll, &threads_args[i]);
		if (ret) {
			ZIP_TST_PRT("Create poll thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].alg = threads_option.alg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, wd_zip_async_run, &threads_args[i]);
		if (ret) {
			ZIP_TST_PRT("Create async thread fail!\n");
			goto async_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			ZIP_TST_PRT("Join async thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			ZIP_TST_PRT("Join poll thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

int zip_wd_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;
	g_pktlen = options->pktlen;

	if (options->optype >= WCRYPTO_DIR_MAX * 2) {
		ZIP_TST_PRT("ZIP optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_zip_wd_queue(options);
	if (ret)
		return ret;

	ret = load_file_data(options->algname, options->pktlen, options->optype);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = zip_wd_async_threads(options);
	else
		ret = zip_wd_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	ret = save_file_data(options->algname, options->pktlen, options->optype);
	if (ret)
		return ret;

	uninit_zip_wd_queue();

	return 0;
}
