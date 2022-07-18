/* SPDX-License-Identifier: Apache-2.0 */

#include <numa.h>
#include "uadk_benchmark.h"

#include "zip_uadk_benchmark.h"
#include "include/wd_comp.h"
#include "include/wd_sched.h"
#include "include/fse.h"

#define ZIP_TST_PRT printf
#define PATH_SIZE	64
#define ZIP_FILE	"./zip"
#define COMP_LEN_RATE		2
#define DECOMP_LEN_RATE		2

struct uadk_bd {
	u8 *src;
	u8 *dst;
	u32 src_len;
	u32 dst_len;
};

struct bd_pool {
	struct uadk_bd *bds;
};

struct thread_pool {
	struct bd_pool *pool;
} g_zip_pool;

enum ZIP_OP_MODE {
	BLOCK_MODE,
	STREAM_MODE
};

struct zip_async_tag {
	handle_t sess;
	u32 td_id;
	u32 bd_idx;
	u32 cm_len;
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

static struct wd_ctx_config g_ctx_cfg;
static struct wd_sched *g_sched;
static unsigned int g_thread_num;
static unsigned int g_ctxnum;
static unsigned int g_pktlen;
static unsigned int g_prefetch;

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

	optype = optype % WD_DIR_MAX;
	if (optype != WD_DIR_COMPRESS) //compress
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
		ZIP_TST_PRT("compress data file open %s fail (%d)!\n", file_path, -errno);
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
		fhead->blk_sz[j] = g_zip_pool.pool[0].bds[j].dst_len;
		total_file_size += fhead->blk_sz[j];
	}
	fhead->block_num = MAX_POOL_LENTH;
	fhead->file_size = total_file_size;
	size = write(fd, fhead, sizeof(*fhead));
	if (size < 0) {
		ZIP_TST_PRT("compress write file head failed: %lu!\n", size);
		ret = -EINVAL;
		goto write_error;
	}

	// write data for one buffer one buffer to file line.
	for (j = 0; j < MAX_POOL_LENTH; j++) {
		size = write(fd, g_zip_pool.pool[0].bds[j].dst,
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

	optype = optype % WD_DIR_MAX;
	if (optype != WD_DIR_DECOMPRESS) //decompress
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
		memset(g_zip_pool.pool[0].bds[j].src, 0x0,
			g_zip_pool.pool[0].bds[j].src_len);
		if (size != 0) { // zero size buffer no need to read;
			size = read(fd, g_zip_pool.pool[0].bds[j].src,
					fhead->blk_sz[j]);
			if (size < 0) {
				ZIP_TST_PRT("Decompress read data error size: %lu!\n", size);
				ret = -EINVAL;
				goto read_err;
			} else if (size == 0) {
				ZIP_TST_PRT("Read file to the end!");
			}
		}
		g_zip_pool.pool[0].bds[j].src_len = size;
	}

	for (i = 1; i < g_thread_num; i++) {
		for (j = 0; j < MAX_POOL_LENTH; j++) {
			if (g_zip_pool.pool[0].bds[j].src_len)
				memcpy(g_zip_pool.pool[i].bds[j].src,
					g_zip_pool.pool[0].bds[j].src,
					g_zip_pool.pool[0].bds[j].src_len);
			g_zip_pool.pool[i].bds[j].src_len =
				g_zip_pool.pool[0].bds[j].src_len;
		}
	}

read_err:
	free(fhead);
fd_err:
	close(fd);

	return ret;
}

static int zip_uadk_param_parse(thread_data *tddata, struct acc_option *options)
{
	u32 algtype = options->algtype;
	u32 optype = options->optype;
	u8 mode = BLOCK_MODE;
	u8 alg;

	if (optype >= WD_DIR_MAX << 1) {
		ZIP_TST_PRT("Fail to get zip optype!\n");
		return -EINVAL;
	} else if (optype >= WD_DIR_MAX) {
		mode = STREAM_MODE;
	}

	optype = optype % WD_DIR_MAX;

	switch(algtype) {
	case ZLIB:
		alg = WD_ZLIB;
		break;
	case GZIP:
		alg = WD_GZIP;
		break;
	case DEFLATE:
		alg = WD_DEFLATE;
		break;
	case LZ77_ZSTD:
		alg = WD_LZ77_ZSTD;
		if (optype == WD_DIR_DECOMPRESS)
			ZIP_TST_PRT("Zip LZ77_ZSTD just support compress!\n");
		optype = WD_DIR_COMPRESS;
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

static int init_ctx_config(char *alg, int mode, int optype)
{
	struct uacce_dev_list *list;
	struct sched_params param;
	int i, max_node;
	int ret = 0;

	max_node = numa_max_node() + 1;
	if (max_node <= 0)
		return -EINVAL;

	list = wd_get_accel_list(alg);
	if (!list) {
		ZIP_TST_PRT("Fail to get %s device\n", alg);
		return -ENODEV;
	}
	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = g_ctxnum;
	g_ctx_cfg.ctxs = calloc(g_ctxnum, sizeof(struct wd_ctx));
	if (!g_ctx_cfg.ctxs)
		return -ENOMEM;

	g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 2, max_node, wd_comp_poll_ctx);
	if (!g_sched) {
		ZIP_TST_PRT("Fail to alloc sched!\n");
		goto out;
	}

	/* If there is no numa, we defualt config to zero */
	if (list->dev->numa_id < 0)
		list->dev->numa_id = 0;

	for (i = 0; i < g_ctxnum; i++) {
		g_ctx_cfg.ctxs[i].ctx = wd_request_ctx(list->dev);
		g_ctx_cfg.ctxs[i].op_type = 0; // default op_type
		g_ctx_cfg.ctxs[i].ctx_mode = (__u8)mode;
	}
	g_sched->name = SCHED_SINGLE;

	/*
	 * All contexts for 2 modes & 2 types.
	 * The test only uses one kind of contexts at the same time.
	 */
	optype = optype % WD_DIR_MAX;
	param.numa_id = list->dev->numa_id;
	param.type = optype;
	param.mode = mode;
	param.begin = 0;
	param.end = g_ctxnum - 1;
	ret = wd_sched_rr_instance(g_sched, &param);
	if (ret) {
		ZIP_TST_PRT("Fail to fill sched data!\n");
		goto out;
	}

	/* init */
	ret = wd_comp_init(&g_ctx_cfg, g_sched);
	if (ret) {
		ZIP_TST_PRT("Fail to cipher ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;
out:
	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);

	return ret;
}

static void uninit_ctx_config(void)
{
	int i;

	/* uninit */
	wd_comp_uninit();

	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);
}

static int init_uadk_bd_pool(u32 optype)
{
	u32 outsize;
	u32 insize;
	int i, j;

	// make the block not align to 4K
	optype = optype % WD_DIR_MAX;
	if (optype == WD_DIR_COMPRESS) {//compress
		insize = g_pktlen;
		outsize = g_pktlen * COMP_LEN_RATE;
	} else { // decompress
		insize = g_pktlen;
		outsize = g_pktlen * DECOMP_LEN_RATE;
	}

	g_zip_pool.pool = malloc(g_thread_num * sizeof(struct bd_pool));
	if (!g_zip_pool.pool) {
		ZIP_TST_PRT("init uadk pool alloc thread failed!\n");
		return -ENOMEM;
	} else {
		for (i = 0; i < g_thread_num; i++) {
			g_zip_pool.pool[i].bds = malloc(MAX_POOL_LENTH *
							 sizeof(struct uadk_bd));
			if (!g_zip_pool.pool[i].bds) {
				ZIP_TST_PRT("init uadk bds alloc failed!\n");
				goto malloc_error1;
			}
			for (j = 0; j < MAX_POOL_LENTH; j++) {
				g_zip_pool.pool[i].bds[j].src = malloc(insize);
				if (!g_zip_pool.pool[i].bds[j].src)
					goto malloc_error2;
				g_zip_pool.pool[i].bds[j].src_len = insize;

				g_zip_pool.pool[i].bds[j].dst = malloc(outsize);
				if (!g_zip_pool.pool[i].bds[j].dst)
					goto malloc_error3;
				g_zip_pool.pool[i].bds[j].dst_len = outsize;

				get_rand_data(g_zip_pool.pool[i].bds[j].src, insize);
				if (g_prefetch)
					get_rand_data(g_zip_pool.pool[i].bds[j].dst, outsize);
			}
		}
	}

	return 0;

malloc_error3:
	free(g_zip_pool.pool[i].bds[j].src);
malloc_error2:
	for (j--; j >= 0; j--) {
		free(g_zip_pool.pool[i].bds[j].src);
		free(g_zip_pool.pool[i].bds[j].dst);
	}
malloc_error1:
	for (i--; i >= 0; i--) {
		for (j = 0; j < MAX_POOL_LENTH; j++) {
			free(g_zip_pool.pool[i].bds[j].src);
			free(g_zip_pool.pool[i].bds[j].dst);
		}
		free(g_zip_pool.pool[i].bds);
		g_zip_pool.pool[i].bds = NULL;
	}
	free(g_zip_pool.pool);
	g_zip_pool.pool = NULL;

	ZIP_TST_PRT("init uadk bd pool alloc failed!\n");
	return -ENOMEM;
}

static void free_uadk_bd_pool(void)
{
	int i, j;

	for (i = 0; i < g_thread_num; i++) {
		if (g_zip_pool.pool[i].bds) {
			for (j = 0; j < MAX_POOL_LENTH; j++) {
				free(g_zip_pool.pool[i].bds[j].src);
				free(g_zip_pool.pool[i].bds[j].dst);
			}
		}
		free(g_zip_pool.pool[i].bds);
		g_zip_pool.pool[i].bds = NULL;
	}
	free(g_zip_pool.pool);
	g_zip_pool.pool = NULL;
}

/*-------------------------------uadk benchmark main code-------------------------------------*/
static void *zip_lz77_async_cb(struct wd_comp_req *req, void *data)
{
	struct zip_async_tag *tag = req->cb_param;
	struct bd_pool *uadk_pool;
	int td_id = tag->td_id;
	int idx = tag->bd_idx;
	ZSTD_inBuffer zstd_input;
	ZSTD_outBuffer zstd_output;
	ZSTD_CCtx *cctx = tag->cctx;
	size_t fse_size;

	uadk_pool = &g_zip_pool.pool[td_id];
	uadk_pool->bds[idx].dst_len = req->dst_len;

	zstd_input.src = req->src;
	zstd_input.size = req->src_len;
	zstd_input.pos = 0;
	zstd_output.dst = uadk_pool->bds[idx].dst;
	zstd_output.size = tag->cm_len;
	zstd_output.pos = 0;
	fse_size = zstd_soft_fse(req->priv, &zstd_input, &zstd_output, cctx, ZSTD_e_end);

	uadk_pool->bds[idx].dst_len = fse_size;

	return NULL;
}

static void *zip_async_cb(struct wd_comp_req *req, void *data)
{
	struct zip_async_tag *tag = req->cb_param;
	struct bd_pool *uadk_pool;
	int td_id = tag->td_id;
	int idx = tag->bd_idx;

	uadk_pool = &g_zip_pool.pool[td_id];
	uadk_pool->bds[idx].dst_len = req->dst_len;

	return NULL;
}

static void *zip_uadk_poll(void *data)
{
	thread_data *pdata = (thread_data *)data;
	u32 expt = ACC_QUEUE_SIZE * g_thread_num;
	u32 id = pdata->td_id;
	u32 last_time = 2; // poll need one more recv time
	u32 count = 0;
	u32 recv = 0;
	int  ret;

	if (id > g_ctxnum)
		return NULL;

	while (last_time) {
		ret = wd_comp_poll_ctx(id, expt, &recv);
		count += recv;
		recv = 0;
		if (unlikely(ret != -WD_EAGAIN && ret < 0)) {
			ZIP_TST_PRT("poll ret: %u!\n", ret);
			goto recv_error;
		}

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *zip_uadk_blk_lz77_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_comp_sess_setup comp_setup = {0};
	ZSTD_CCtx *cctx = zstd_soft_fse_init(15);
	ZSTD_inBuffer zstd_input = {0};
	ZSTD_outBuffer zstd_output = {0};
	COMP_TUPLE_TAG *ftuple = NULL;
	struct bd_pool *uadk_pool;
	struct wd_comp_req creq;
	char *hw_buff_out = NULL;
	size_t fse_size;
	handle_t h_sess;
	u32 first_len = 0;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_zip_pool.pool[pdata->td_id];
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&creq, 0, sizeof(creq));

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WD_COMP_L8;
	comp_setup.win_sz = WD_COMP_WS_8K;
	h_sess = wd_comp_alloc_sess(&comp_setup);
	if (!h_sess)
		return NULL;

	creq.op_type = pdata->optype;
	creq.src_len = g_pktlen;
	out_len = uadk_pool->bds[0].dst_len;

	creq.cb = NULL;
	creq.data_fmt = 0;
	creq.status = 0;

	ftuple = malloc(sizeof(COMP_TUPLE_TAG) * MAX_POOL_LENTH);
	if (!ftuple)
		goto fse_err;

	hw_buff_out = malloc(out_len * MAX_POOL_LENTH);
	if (!hw_buff_out)
		goto hw_buff_err;
	memset(hw_buff_out, 0x0, out_len * MAX_POOL_LENTH);

	while(1) {
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = &hw_buff_out[i]; //temp out
		creq.src_len = uadk_pool->bds[i].src_len;
		creq.dst_len = out_len;
		creq.priv = &ftuple[i];

		ret = wd_do_comp_sync(h_sess, &creq);
		if (ret || creq.status)
			break;

		count++;
		zstd_input.src = creq.src;
		zstd_input.size = creq.src_len;
		zstd_input.pos = 0;
		zstd_output.dst = uadk_pool->bds[i].dst;
		zstd_output.size = out_len;
		zstd_output.pos = 0;
		fse_size = zstd_soft_fse(creq.priv, &zstd_input, &zstd_output, cctx, ZSTD_e_end);

		uadk_pool->bds[i].dst_len = fse_size;
		if (unlikely(i == 0))
			first_len = fse_size;
		if (get_run_state() == 0)
			break;
	}

hw_buff_err:
	free(hw_buff_out);
fse_err:
	free(ftuple);
	wd_comp_free_sess(h_sess);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, creq.dst_len);
	if (pdata->optype == WD_DIR_COMPRESS)
		add_recv_data(count, creq.src_len);
	else
		add_recv_data(count, first_len);

	return NULL;
}

static void *zip_uadk_stm_lz77_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_comp_sess_setup comp_setup = {0};
	ZSTD_CCtx *cctx = zstd_soft_fse_init(15);
	ZSTD_inBuffer zstd_input = {0};
	ZSTD_outBuffer zstd_output = {0};
	COMP_TUPLE_TAG *ftuple = NULL;
	struct bd_pool *uadk_pool;
	struct wd_comp_req creq;
	char *hw_buff_out = NULL;
	size_t fse_size;
	handle_t h_sess;
	u32 first_len = 0;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_zip_pool.pool[pdata->td_id];
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&creq, 0, sizeof(creq));

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WD_COMP_L8;
	comp_setup.win_sz = WD_COMP_WS_8K;
	h_sess = wd_comp_alloc_sess(&comp_setup);
	if (!h_sess)
		return NULL;

	creq.op_type = pdata->optype;
	creq.src_len = g_pktlen;
	out_len = uadk_pool->bds[0].dst_len;

	creq.cb = NULL;
	creq.data_fmt = 0;
	creq.status = 0;

	ftuple = malloc(sizeof(COMP_TUPLE_TAG) * MAX_POOL_LENTH);
	if (!ftuple)
		goto fse_err;

	hw_buff_out = malloc(out_len * MAX_POOL_LENTH);
	if (!hw_buff_out)
		goto hw_buff_err;
	memset(hw_buff_out, 0x0, out_len * MAX_POOL_LENTH);

	while(1) {
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = &hw_buff_out[i]; //temp out
		creq.src_len = uadk_pool->bds[i].src_len;
		creq.dst_len = out_len;
		creq.priv = &ftuple[i];

		ret = wd_do_comp_strm(h_sess, &creq);
		if (ret < 0 || creq.status == WD_IN_EPARA) {
			ZIP_TST_PRT("wd comp, invalid or incomplete data! "
			       "ret(%d), req.status(%u)\n", ret, creq.status);
			break;
		}

		count++;
		zstd_input.src = creq.src;
		zstd_input.size = creq.src_len;
		zstd_input.pos = 0;
		zstd_output.dst = uadk_pool->bds[i].dst;
		zstd_output.size = out_len;
		zstd_output.pos = 0;
		fse_size = zstd_soft_fse(creq.priv, &zstd_input, &zstd_output, cctx, ZSTD_e_end);

		uadk_pool->bds[i].dst_len = fse_size;
		if (unlikely(i == 0))
			first_len = fse_size;
		if (get_run_state() == 0)
			break;
	}

hw_buff_err:
	free(hw_buff_out);
fse_err:
	free(ftuple);
	wd_comp_free_sess(h_sess);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, creq.dst_len);
	if (pdata->optype == WD_DIR_COMPRESS)
		add_recv_data(count, creq.src_len);
	else
		add_recv_data(count, first_len);

	return NULL;
}

static void *zip_uadk_blk_lz77_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_comp_sess_setup comp_setup = {0};
	ZSTD_CCtx *cctx = zstd_soft_fse_init(15);
	COMP_TUPLE_TAG *ftuple = NULL;
	struct bd_pool *uadk_pool;
	struct wd_comp_req creq;
	struct zip_async_tag *tag;
	char *hw_buff_out = NULL;
	handle_t h_sess;
	u32 out_len = 0;
	u32 count = 0;
	u32 try_cnt = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_zip_pool.pool[pdata->td_id];
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&creq, 0, sizeof(creq));

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WD_COMP_L8;
	comp_setup.win_sz = WD_COMP_WS_8K;
	h_sess = wd_comp_alloc_sess(&comp_setup);
	if (!h_sess)
		return NULL;

	creq.op_type = pdata->optype;
	creq.src_len = g_pktlen;
	out_len = uadk_pool->bds[0].dst_len;

	creq.cb = zip_lz77_async_cb;
	creq.data_fmt = 0;
	creq.status = 0;

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
		creq.src = uadk_pool->bds[i].src;
		creq.dst = &hw_buff_out[i]; //temp out
		creq.src_len = uadk_pool->bds[i].src_len;
		creq.dst_len = out_len;
		creq.priv = &ftuple[i];

		tag[i].td_id = pdata->td_id;
		tag[i].bd_idx = i;
		tag[i].cm_len = out_len;
		tag[i].cctx = cctx;
		creq.cb_param = &tag[i];

		ret = wd_do_comp_async(h_sess, &creq);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				ZIP_TST_PRT("Test LZ77 compress send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret || creq.status) {
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
	wd_comp_free_sess(h_sess);

	// ZIP_TST_PRT("LZ77 valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, creq.dst_len);

	add_send_complete();

	return NULL;
}

static void *zip_uadk_blk_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_comp_sess_setup comp_setup = {0};
	struct bd_pool *uadk_pool;
	struct wd_comp_req creq;
	handle_t h_sess;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_zip_pool.pool[pdata->td_id];
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&creq, 0, sizeof(creq));

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WD_COMP_L8;
	comp_setup.win_sz = WD_COMP_WS_8K;
	h_sess = wd_comp_alloc_sess(&comp_setup);
	if (!h_sess)
		return NULL;

	creq.op_type = pdata->optype;
	creq.src_len = g_pktlen;
	out_len = uadk_pool->bds[0].dst_len;

	creq.cb = NULL;
	creq.data_fmt = 0;
	creq.priv = 0;
	creq.status = 0;

	while(1) {
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = uadk_pool->bds[i].dst;
		creq.src_len = uadk_pool->bds[i].src_len;
		creq.dst_len = out_len;

		ret = wd_do_comp_sync(h_sess, &creq);
		if (ret || creq.status)
			break;

		count++;
		uadk_pool->bds[i].dst_len = creq.dst_len;
		if (get_run_state() == 0)
			break;
	}
	wd_comp_free_sess(h_sess);

	//ZIP_TST_PRT("valid pool len: %u, send count BD: %u, input len: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, creq.src_len, g_pktlen);
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *zip_uadk_stm_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_comp_sess_setup comp_setup = {0};
	struct bd_pool *uadk_pool;
	struct wd_comp_req creq;
	handle_t h_sess;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_zip_pool.pool[pdata->td_id];
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&creq, 0, sizeof(creq));

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WD_COMP_L8;
	comp_setup.win_sz = WD_COMP_WS_8K;
	h_sess = wd_comp_alloc_sess(&comp_setup);
	if (!h_sess)
		return NULL;

	creq.op_type = pdata->optype;
	creq.src_len = g_pktlen;
	out_len = uadk_pool->bds[0].dst_len;

	creq.cb = NULL;
	creq.data_fmt = 0;
	creq.priv = 0;
	creq.status = 0;

	while(1) {
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = uadk_pool->bds[i].dst;
		creq.src_len = uadk_pool->bds[i].src_len;
		creq.dst_len = out_len;

		ret = wd_do_comp_strm(h_sess, &creq);
		if (ret < 0 || creq.status == WD_IN_EPARA) {
			ZIP_TST_PRT("wd comp, invalid or incomplete data! "
			       "ret(%d), req.status(%u)\n", ret, creq.status);
			break;
		}

		count++;
		uadk_pool->bds[i].dst_len = creq.dst_len;

		if (get_run_state() == 0)
			break;
	}
	wd_comp_free_sess(h_sess);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, creq.dst_len);
	add_recv_data(count, g_pktlen);

	return NULL;
}

static void *zip_uadk_blk_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	struct wd_comp_sess_setup comp_setup = {0};
	struct bd_pool *uadk_pool;
	struct zip_async_tag *tag;
	struct wd_comp_req creq;
	handle_t h_sess;
	int try_cnt = 0;
	u32 out_len = 0;
	u32 count = 0;
	int ret, i = 0;

	if (pdata->td_id > g_thread_num)
		return NULL;

	uadk_pool = &g_zip_pool.pool[pdata->td_id];
	memset(&comp_setup, 0, sizeof(comp_setup));
	memset(&creq, 0, sizeof(creq));

	comp_setup.alg_type = pdata->alg;
	comp_setup.op_type = pdata->optype;
	comp_setup.comp_lv = WD_COMP_L8;
	comp_setup.win_sz = WD_COMP_WS_8K;
	h_sess = wd_comp_alloc_sess(&comp_setup);
	if (!h_sess)
		return NULL;

	creq.op_type = pdata->optype;
	creq.src_len = g_pktlen;
	out_len = uadk_pool->bds[0].dst_len;

	creq.cb = zip_async_cb;
	creq.data_fmt = 0;
	creq.priv = 0;
	creq.status = 0;

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		ZIP_TST_PRT("failed to malloc zip tag!\n");
		wd_comp_free_sess(h_sess);
		return NULL;
	}

	while(1) {
		if (get_run_state() == 0)
				break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		creq.src = uadk_pool->bds[i].src;
		creq.dst = uadk_pool->bds[i].dst;
		creq.src_len = uadk_pool->bds[i].src_len;
		creq.dst_len = out_len;

		tag[i].td_id = pdata->td_id;
		tag[i].bd_idx = i;
		creq.cb_param = &tag[i];

		ret = wd_do_comp_async(h_sess, &creq);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				ZIP_TST_PRT("Test compress send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret || creq.status) {
			break;
		}
		count++;
	}

	while (1) {
		if (get_recv_time() > 0) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}

	free(tag);
	wd_comp_free_sess(h_sess);

	// ZIP_TST_PRT("valid pool len: %u, send count BD: %u, output len: %u!\n",
	//		MAX_POOL_LENTH, count, creq.dst_len);

	add_send_complete();

	return NULL;
}

static int zip_uadk_sync_threads(struct acc_option *options)
{
	typedef void *(*zip_sync_run)(void *arg);
	zip_sync_run uadk_zip_sync_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = zip_uadk_param_parse(&threads_option, options);
	if (ret)
		return ret;

	if (threads_option.mode == 1) {// stream mode
		if (threads_option.alg == LZ77_ZSTD)
			uadk_zip_sync_run = zip_uadk_stm_lz77_sync_run;
		else
			uadk_zip_sync_run = zip_uadk_stm_sync_run;
	} else {
		if (threads_option.alg == LZ77_ZSTD)
			uadk_zip_sync_run = zip_uadk_blk_lz77_sync_run;
		else
			uadk_zip_sync_run = zip_uadk_blk_sync_run;
	}
	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].alg = threads_option.alg;
		threads_args[i].mode = threads_option.mode;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, uadk_zip_sync_run, &threads_args[i]);
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

static int zip_uadk_async_threads(struct acc_option *options)
{
	typedef void *(*zip_async_run)(void *arg);
	zip_async_run uadk_zip_async_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	ret = zip_uadk_param_parse(&threads_option, options);
	if (ret)
		return ret;

	if (threads_option.mode == STREAM_MODE) {// stream mode
		ZIP_TST_PRT("Stream mode can't support async mode!\n");
		return 0;
	}

	if (threads_option.alg == LZ77_ZSTD)
		uadk_zip_async_run = zip_uadk_blk_lz77_async_run;
	else
		uadk_zip_async_run = zip_uadk_blk_async_run;

	for (i = 0; i < g_ctxnum; i++) {
		threads_args[i].td_id = i;
		/* poll thread */
		ret = pthread_create(&pollid[i], NULL, zip_uadk_poll, &threads_args[i]);
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
		ret = pthread_create(&tdid[i], NULL, uadk_zip_async_run, &threads_args[i]);
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

	for (i = 0; i < g_ctxnum; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			ZIP_TST_PRT("Join poll thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

int zip_uadk_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;
	g_pktlen = options->pktlen;
	g_ctxnum = options->ctxnums;
	g_prefetch = options->prefetch;

	if (options->optype >= WD_DIR_MAX * 2) {
		ZIP_TST_PRT("ZIP optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_ctx_config(options->algclass, options->syncmode, options->optype);
	if (ret)
		return ret;

	ret = init_uadk_bd_pool(options->optype);
	if (ret)
		return ret;

	ret = load_file_data(options->algname, options->pktlen, options->optype);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = zip_uadk_async_threads(options);
	else
		ret = zip_uadk_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	ret = save_file_data(options->algname, options->pktlen, options->optype);
	if (ret)
		return ret;

	free_uadk_bd_pool();
	uninit_ctx_config();

	return 0;
}
