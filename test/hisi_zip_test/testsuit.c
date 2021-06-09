// SPDX-License-Identifier: Apache-2.0

#include "test_lib.h"

/* PADDING could avoid blocking in HW inflation */
#define HIZIP_PADDING	16

static void *sw_dfl_hw_ifl(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_ifl;
	void *tbuf;
	size_t tbuf_sz;
	chunk_list_t *tlist;
	comp_md5_t final_md5 = {0};
	int i, ret;
	__u32 tout_sz;

	tbuf_sz = tdata->src_sz * EXPANSION_RATIO;
	tbuf = mmap_alloc(tbuf_sz);
	if (!tbuf)
		return (void *)(uintptr_t)(-ENOMEM);
	tlist = create_chunk_list(tbuf, tbuf_sz,
				  info->in_chunk_sz * EXPANSION_RATIO);
	if (!tlist) {
		ret = -ENOMEM;
		goto out;
	}
	if (opts->is_stream) {
		/* STREAM mode: only one entry in the list */
		init_chunk_list(tdata->in_list, tdata->src,
				tdata->src_sz, tdata->src_sz);
		for (i = 0; i < opts->compact_run_num; i++) {
			init_chunk_list(tlist, tbuf, tbuf_sz, tbuf_sz);
			init_chunk_list(tdata->out_list, tdata->dst,
					tdata->dst_sz, tdata->dst_sz);
			ret = sw_deflate2(tdata->in_list, tlist, opts);
			if (ret) {
				printf("Fail to deflate by zlib: %d\n", ret);
				goto out_strm;
			}
			tout_sz = tdata->dst_sz;
			ret = hw_stream_decompress(opts->alg_type,
						   opts->block_size,
						   opts->data_fmt,
						   tdata->dst,
						   &tout_sz,
						   tlist->addr,
						   tlist->size);
			if (ret) {
				printf("Fail to inflate by HW: %d\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&tdata->md5, tdata->in_list->addr,
					    tdata->in_list->size);
			if (ret) {
				printf("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&final_md5, tdata->out_list->addr,
					    tout_sz);
			if (ret) {
				printf("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = cmp_md5(&tdata->md5, &final_md5);
			if (ret) {
				printf("MD5 is unmatched (%d) at %dth times on "
					"thread %d\n", ret, i, tdata->tid);
				goto out_strm;
			}
		}
		free_chunk_list(tlist);
		mmap_free(tbuf, tbuf_sz);
		return NULL;
	}

	/* BLOCK mode */
        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_DECOMPRESS;

	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl) {
		ret = -EINVAL;
		goto out_strm;
	}

	init_chunk_list(tdata->in_list, tdata->src, tdata->src_sz,
			info->in_chunk_sz);
	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tlist, tbuf, tbuf_sz,
			       	info->in_chunk_sz * EXPANSION_RATIO);
		init_chunk_list(tdata->out_list, tdata->dst, tdata->dst_sz,
				info->out_chunk_sz);
		ret = sw_deflate2(tdata->in_list, tlist, opts);
		if (ret) {
			printf("Fail to deflate by zlib: %d\n", ret);
			goto out_run;
		}
		ret = hw_inflate4(h_ifl, tlist, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			printf("Fail to inflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		if (ret) {
			printf("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&final_md5, tdata->dst, tdata->dst_sz);
		if (ret) {
			printf("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = cmp_md5(&tdata->md5, &final_md5);
		if (ret) {
			printf("MD5 is unmatched (%d) at %dth times on "
				"thread %d\n", ret, i, tdata->tid);
			goto out_run;
		}
	}
	wd_comp_free_sess(h_ifl);
	free_chunk_list(tlist);
	mmap_free(tbuf, tbuf_sz);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out_run:
	wd_comp_free_sess(h_ifl);
out_strm:
	free_chunk_list(tlist);
out:
	mmap_free(tbuf, tbuf_sz);
	return (void *)(uintptr_t)(ret);
}

static void *hw_dfl_sw_ifl(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_dfl;
	void *tbuf;
	size_t tbuf_sz;
	chunk_list_t *tlist;
	comp_md5_t final_md5 = {0};
	int i, ret;
	__u32 tmp_sz;

	tbuf_sz = tdata->src_sz * EXPANSION_RATIO;
	tbuf = mmap_alloc(tbuf_sz);
	if (!tbuf)
		return (void *)(uintptr_t)(-ENOMEM);
	tlist = create_chunk_list(tbuf, tbuf_sz,
				  opts->block_size * EXPANSION_RATIO);
	if (!tlist) {
		ret = -ENOMEM;
		goto out;
	}
	if (opts->is_stream) {
		/* STREAM mode: only one entry in the list */
		init_chunk_list(tdata->in_list, tdata->src,
				tdata->src_sz, tdata->src_sz);
		for (i = 0; i < opts->compact_run_num; i++) {
			init_chunk_list(tlist, tbuf, tbuf_sz, tbuf_sz);
			init_chunk_list(tdata->out_list, tdata->dst,
					tdata->dst_sz, tdata->dst_sz);
			tmp_sz = tbuf_sz;
			ret = hw_stream_compress(opts->alg_type,
						 opts->block_size,
						 opts->data_fmt,
						 tlist->addr,
						 &tmp_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				printf("Fail to deflate by HW: %d\n", ret);
				goto out_strm;
			}
			tlist->size = tmp_sz;	// write back
			ret = sw_inflate2(tlist, tdata->out_list, opts);
			if (ret) {
				printf("Fail to inflate by zlib: %d\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&tdata->md5, tdata->in_list->addr,
					    tdata->in_list->size);
			if (ret) {
				printf("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&final_md5, tdata->out_list->addr,
					    tdata->out_list->size);
			if (ret) {
				printf("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = cmp_md5(&tdata->md5, &final_md5);
			if (ret) {
				printf("MD5 is unmatched (%d) at %dth times on "
					"thread %d\n", ret, i, tdata->tid);
				goto out_strm;
			}
		}
		free_chunk_list(tlist);
		mmap_free(tbuf, tbuf_sz);
		return NULL;
	}

	/* BLOCK mode */
        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_COMPRESS;

	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl) {
		ret = -EINVAL;
		goto out_strm;
	}

	init_chunk_list(tdata->in_list, tdata->src, tdata->src_sz,
			info->in_chunk_sz);
	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tlist, tbuf, tbuf_sz,
			       	opts->block_size * EXPANSION_RATIO);
		init_chunk_list(tdata->out_list, tdata->dst, tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate4(h_dfl, tdata->in_list, tlist, opts,
				  &tdata->sem);
		if (ret) {
			printf("Fail to deflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = sw_inflate2(tlist, tdata->out_list, opts);
		if (ret) {
			printf("Fail to inflate by zlib: %d\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		if (ret) {
			printf("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&final_md5, tdata->dst, tdata->dst_sz);
		if (ret) {
			printf("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = cmp_md5(&tdata->md5, &final_md5);
		if (ret) {
			printf("MD5 is unmatched (%d) at %dth times on "
				"thread %d\n", ret, i, tdata->tid);
			goto out_run;
		}
	}
	wd_comp_free_sess(h_dfl);
	free_chunk_list(tlist);
	mmap_free(tbuf, tbuf_sz);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out_run:
	wd_comp_free_sess(h_dfl);
out_strm:
	free_chunk_list(tlist);
out:
	mmap_free(tbuf, tbuf_sz);
	return (void *)(uintptr_t)(ret);
}

static void *hw_dfl_hw_ifl(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_dfl, h_ifl;
	void *tbuf;
	size_t tbuf_sz;
	chunk_list_t *tlist;
	comp_md5_t final_md5 = {0};
	int i, ret;
	__u32 tmp_sz, tout_sz;

	tbuf_sz = tdata->src_sz * EXPANSION_RATIO;
	tbuf = mmap_alloc(tbuf_sz);
	if (!tbuf)
		return (void *)(uintptr_t)(-ENOMEM);
	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tmp_sz = tbuf_sz;
			ret = hw_stream_compress(opts->alg_type,
						 opts->block_size,
						 opts->data_fmt,
						 tbuf,
						 &tmp_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				printf("Fail to deflate by HW: %d\n", ret);
				goto out;
			}
			tout_sz = tdata->dst_sz;
			ret = hw_stream_decompress(opts->alg_type,
						   opts->block_size,
						   opts->data_fmt,
						   tdata->dst,
						   &tout_sz,
						   tbuf,
						   tmp_sz);
			if (ret) {
				printf("Fail to inflate by HW: %d\n", ret);
				goto out;
			}
			ret = calculate_md5(&tdata->md5, tdata->in_list->addr,
					    tdata->in_list->size);
			if (ret) {
				printf("Fail to generate MD5 (%d)\n", ret);
				goto out;
			}
			ret = calculate_md5(&final_md5, tdata->dst, tout_sz);
			if (ret) {
				printf("Fail to generate MD5 (%d)\n", ret);
				goto out;
			}
			ret = cmp_md5(&tdata->md5, &final_md5);
			if (ret) {
				printf("MD5 is unmatched (%d) at %dth times on "
					"thread %d\n", ret, i, tdata->tid);
				goto out;
			}
		}
		mmap_free(tbuf, tbuf_sz);
		return NULL;
	}

	/* BLOCK mode */
	tlist = create_chunk_list(tbuf, tbuf_sz,
				  opts->block_size * EXPANSION_RATIO);
	if (!tlist) {
		ret = -ENOMEM;
		goto out;
	}
        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_COMPRESS;

	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl) {
		ret = -EINVAL;
		goto out_dfl;
	}

	setup.op_type = WD_DIR_DECOMPRESS;
	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl) {
		ret = -EINVAL;
		goto out_ifl;
	}

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tlist, tbuf, tbuf_sz,
			       	opts->block_size * EXPANSION_RATIO);
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate4(h_dfl, tdata->in_list, tlist, opts,
				  &tdata->sem);
		if (ret) {
			printf("Fail to deflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = hw_inflate4(h_ifl, tlist, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			printf("Fail to inflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		if (ret) {
			printf("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&final_md5, tdata->dst, tdata->dst_sz);
		if (ret) {
			printf("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = cmp_md5(&tdata->md5, &final_md5);
		if (ret) {
			printf("MD5 is unmatched (%d) at %dth times on "
				"thread %d\n", ret, i, tdata->tid);
			goto out_run;
		}
	}
	wd_comp_free_sess(h_ifl);
	wd_comp_free_sess(h_dfl);
	free_chunk_list(tlist);
	mmap_free(tbuf, tbuf_sz);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out_run:
	wd_comp_free_sess(h_ifl);
out_ifl:
	wd_comp_free_sess(h_dfl);
out_dfl:
	free_chunk_list(tlist);
out:
	mmap_free(tbuf, tbuf_sz);
	return (void *)(uintptr_t)(ret);
}

static void *hw_dfl_perf(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_dfl;
	int i, ret;
	uint32_t tout_sz;

	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tout_sz = tdata->dst_sz;
			ret = hw_stream_compress(opts->alg_type,
						 opts->block_size,
						 opts->data_fmt,
						 tdata->dst,
						 &tout_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				printf("Fail to deflate by HW: %d\n", ret);
				return (void *)(uintptr_t)ret;
			}
		}
		tdata->out_list->addr = tdata->dst;
		tdata->out_list->size = tout_sz;
		tdata->out_list->next = NULL;
		return NULL;
	}

        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_COMPRESS;

	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl)
		return (void *)(uintptr_t)(-EINVAL);

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate4(h_dfl, tdata->in_list, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			printf("Fail to deflate by HW: %d\n", ret);
			goto out;
		}
	}
	wd_comp_free_sess(h_dfl);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out:
	wd_comp_free_sess(h_dfl);
	return (void *)(uintptr_t)(ret);
}

static void *hw_ifl_perf(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_ifl;
	int i, ret;
	uint32_t tout_sz;

	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tout_sz = tdata->dst_sz;
			ret = hw_stream_decompress(opts->alg_type,
						   opts->block_size,
						   opts->data_fmt,
						   tdata->dst,
						   &tout_sz,
						   tdata->src,
						   tdata->src_sz);
			if (ret) {
				printf("Fail to inflate by HW: %d\n", ret);
				return (void *)(uintptr_t)ret;
			}
			tdata->out_list->addr = tdata->dst;
			tdata->out_list->size = tout_sz;
			tdata->out_list->next = NULL;
		}
		return NULL;
	}

        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_DECOMPRESS;

	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl)
		return (void *)(uintptr_t)(-EINVAL);

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_inflate4(h_ifl, tdata->in_list, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			printf("Fail to inflate by HW: %d\n", ret);
			goto out;
		}
	}
	wd_comp_free_sess(h_ifl);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out:
	wd_comp_free_sess(h_ifl);
	return (void *)(uintptr_t)(ret);
}

/* BATCH mode is used */
void *hw_dfl_perf3(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_dfl;
	int i, ret;
	uint32_t tout_sz;

	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tout_sz = tdata->dst_sz;
			ret = hw_stream_compress(opts->alg_type,
						 opts->block_size,
						 opts->data_fmt,
						 tdata->dst,
						 &tout_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				printf("Fail to deflate by HW: %d\n", ret);
				return (void *)(uintptr_t)ret;
			}
		}
		tdata->out_list->addr = tdata->dst;
		tdata->out_list->size = tout_sz;
		tdata->out_list->next = NULL;
		return NULL;
	}

        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_COMPRESS;

	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl)
		return (void *)(uintptr_t)(-EINVAL);

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate5(h_dfl, tdata->in_list, tdata->out_list,
				  tdata);
		if (ret) {
			printf("Fail to deflate by HW: %d\n", ret);
			goto out;
		}
	}
	wd_comp_free_sess(h_dfl);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out:
	wd_comp_free_sess(h_dfl);
	return (void *)(uintptr_t)(ret);
}

/* BATCH mode is used */
void *hw_ifl_perf3(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	handle_t h_ifl;
	int i, ret;
	uint32_t tout_sz;

	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tout_sz = tdata->dst_sz;
			ret = hw_stream_decompress(opts->alg_type,
						   opts->block_size,
						   opts->data_fmt,
						   tdata->dst,
						   &tout_sz,
						   tdata->src,
						   tdata->src_sz);
			if (ret) {
				printf("Fail to inflate by HW: %d\n", ret);
				return (void *)(uintptr_t)ret;
			}
			tdata->out_list->addr = tdata->dst;
			tdata->out_list->size = tout_sz;
			tdata->out_list->next = NULL;
		}
		return NULL;
	}

        setup.alg_type = opts->alg_type;
        setup.mode = opts->sync_mode ? CTX_MODE_ASYNC : CTX_MODE_SYNC;
        setup.op_type = WD_DIR_DECOMPRESS;

	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl)
		return (void *)(uintptr_t)(-EINVAL);

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_inflate5(h_ifl, tdata->in_list, tdata->out_list,
				  tdata);
		if (ret) {
			printf("Fail to inflate by HW: %d\n", ret);
			goto out;
		}
	}
	wd_comp_free_sess(h_ifl);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out:
	wd_comp_free_sess(h_ifl);
	return (void *)(uintptr_t)(ret);
}

/*
 * Load both ilist file.
 */
int load_ilist(struct hizip_test_info *info, char *model)
{
	struct test_options *opts = info->opts;
	thread_data_t *tdata = &info->tdatas[0];
	chunk_list_t *p;
	size_t sum = 0;
	ssize_t file_sz = 0;
	void *addr;

	if (!strcmp(model, "hw_ifl_perf")) {
		if (!opts->is_stream) {
			if (opts->fd_ilist < 0) {
				printf("Missing IN list file!\n");
				return -EINVAL;
			}
			p = tdata->in_list;
			addr = info->in_buf;
			while (p) {
				file_sz = read(opts->fd_ilist, p,
						sizeof(chunk_list_t));
				if (file_sz < 0)
					return -EFAULT;
				p->addr = addr;
				sum += file_sz;
				if (p->next)
					p->next = p + 1;
				addr += p->size;
				p = p->next;
			}
		}
	}
	return (int)sum;
}

/*
 * Load compression/decompression content.
 */
int load_file_data(struct hizip_test_info *info)
{
	struct test_options *opts = info->opts;
	size_t file_sz;

	file_sz = read(opts->fd_in, info->in_buf, info->in_size);
	if (file_sz < info->in_size) {
		printf("Expect to read %ld bytes. "
		       "But only read %ld bytes!\n",
		       info->in_size, file_sz);
		return -EFAULT;
	}
	return (int)file_sz;
}

/*
 * Store both olist file. opts->is_file must be enabled first.
 */
int store_olist(struct hizip_test_info *info, char *model)
{
	struct test_options *opts = info->opts;
	thread_data_t *tdata = &info->tdatas[0];
	chunk_list_t *p;
	size_t sum = 0;
	ssize_t file_sz = 0;

	if (!opts->is_stream) {
		if (opts->fd_olist >= 0) {
			/* compress with BLOCK */
			p = tdata->out_list;
			while (p) {
				file_sz = write(opts->fd_olist, p,
						sizeof(chunk_list_t));
				if (file_sz < sizeof(chunk_list_t))
					return -EFAULT;
				file_sz = write(opts->fd_out, p->addr,
						p->size);
				if (file_sz < p->size)
					return -EFAULT;
				p = p->next;
				sum += file_sz;
			}
		} else {
			/* decompress with BLOCK */
			p = tdata->out_list;
			while (p) {
				file_sz = write(opts->fd_out, p->addr,
						p->size);
				if (file_sz < p->size)
					return -EFAULT;
				p = p->next;
				sum += file_sz;
			}
		}
	} else if (opts->is_stream) {
		p = tdata->out_list;
		file_sz = write(opts->fd_out, p->addr, p->size);
		if (file_sz < p->size)
			return -EFAULT;
		sum = file_sz;
	}
	return (int)sum;
}

int test_hw(struct test_options *opts, char *model)
{
	struct hizip_test_info info = {0};
	struct timeval start_tvl, end_tvl;
	struct wd_sched *sched = NULL;
	double ilen, usec, speed;
	char zbuf[120];
	int ret, zbuf_idx, ifl_flag = 0;
	void *(*func)(void *);
	size_t tbuf_sz = 0;
	void *tbuf = NULL;
	struct stat statbuf;
	chunk_list_t *tlist;
	int div;

	if (!opts || !model) {
		ret = -EINVAL;
		goto out;
	}
	info.opts = opts;
	memset(zbuf, 0, 120);
	if (!strcmp(model, "sw_dfl_hw_ifl")) {
		func = sw_dfl_hw_ifl;
		info.in_size = opts->total_len;
		if (opts->is_stream)
			info.out_size = opts->total_len + HIZIP_PADDING;
		else
			info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size;
		zbuf_idx = sprintf(zbuf, "Mix SW deflate and HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_sw_ifl")) {
		func = hw_dfl_sw_ifl;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size;
		zbuf_idx = sprintf(zbuf, "Mix HW %s %s deflate and SW inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_hw_ifl")) {
		func = hw_dfl_hw_ifl;
		info.in_size = opts->total_len;
		if (opts->is_stream)
			info.out_size = opts->total_len + HIZIP_PADDING;
		else
			info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size;
		zbuf_idx = sprintf(zbuf,
				   "Mix HW %s %s deflate and HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_perf")) {
		func = hw_dfl_perf;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len * EXPANSION_RATIO;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size * EXPANSION_RATIO;
		zbuf_idx = sprintf(zbuf, "HW %s %s deflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_perf3")) {
		func = hw_dfl_perf3;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len * EXPANSION_RATIO;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size * EXPANSION_RATIO;
		zbuf_idx = sprintf(zbuf, "HW %s %s deflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_ifl_perf")) {
		func = hw_ifl_perf;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len * INFLATION_RATIO;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size * INFLATION_RATIO;
		zbuf_idx = sprintf(zbuf, "HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
		ifl_flag = 1;
	} else if (!strcmp(model, "hw_ifl_perf3")) {
		func = hw_ifl_perf3;
		info.in_size = opts->total_len * EXPANSION_RATIO;
		info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size * INFLATION_RATIO;
		zbuf_idx = sprintf(zbuf, "HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
		ifl_flag = 1;
	} else {
		printf("Wrong model is specified:%s\n", model);
		ret = -EINVAL;
		goto out;
	}

	info.list = get_dev_list(opts, 1);
	if (!info.list) {
		ret = -EINVAL;
		goto out;
	}
	ret = init_ctx_config(opts, &info, &sched);
	if (ret)
		goto out_cfg;
	if (opts->is_file) {
		ret = fstat(opts->fd_in, &statbuf);
		if (!ret) {
			opts->total_len = statbuf.st_size;
			info.in_size = opts->total_len;
			if (ifl_flag) {
				info.out_size = ALIGN(opts->total_len,
						      opts->block_size);
				info.out_size *= INFLATION_RATIO;
			} else {
				info.out_size = opts->total_len *
						EXPANSION_RATIO;
			}
		}
		/*
		 * If fd_ilist exists, it's inflation.
		 * Make sure block inflation has enough room.
		 */
		if (opts->fd_ilist >= 0) {
			ret = fstat(opts->fd_ilist, &statbuf);
			if (!ret) {
				div = statbuf.st_size / sizeof(chunk_list_t);
				info.in_chunk_sz = (info.in_size + div - 1) /
						   div;
			}
		}
	}
	info.in_buf = mmap_alloc(info.in_size);
	if (!info.in_buf) {
		ret = -ENOMEM;
		goto out_src;
	}
	ret = create_send_tdata(opts, &info);
	if (ret)
		goto out_send;
	ret = create_poll_tdata(opts, &info, opts->poll_num);
	if (ret)
		goto out_poll;
	if (opts->is_file) {
		/* in_list is created by create_send3_threads(). */
		ret = load_file_data(&info);
		if (ret < 0)
			goto out_buf;
		ret = load_ilist(&info, model);
		if (ret < 0)
			goto out_buf;
	} else {
		if (ifl_flag) {
			thread_data_t *tdata = info.tdatas;
			tbuf_sz = info.in_size / EXPANSION_RATIO;
			tbuf = mmap_alloc(tbuf_sz);
			if (!tbuf) {
				ret = -ENOMEM;
				goto out_buf;
			}
			tlist = create_chunk_list(tbuf, tbuf_sz,
						  opts->block_size /
						  EXPANSION_RATIO);
			init_chunk_list(tlist, tbuf, tbuf_sz,
					opts->block_size / EXPANSION_RATIO);
			gen_random_data(tbuf, tbuf_sz);
			ret = sw_deflate2(tlist, tdata[0].in_list, opts);
			if (ret)
				goto out_dfl;
			mmap_free(tbuf, tbuf_sz);
		} else
			gen_random_data(info.in_buf, info.in_size);
	}
	gettimeofday(&start_tvl, NULL);
	ret = attach2_threads(opts, &info, func, poll2_thread_func);
	if (ret)
		goto out_poll;
	gettimeofday(&end_tvl, NULL);
	timersub(&end_tvl, &start_tvl, &start_tvl);
	if (opts->is_file)
		store_olist(&info, model);

	usec = (double)(start_tvl.tv_sec * 1000000 + start_tvl.tv_usec);
	ilen = opts->total_len * opts->thread_num * opts->compact_run_num;
	speed = ilen * 1000 * 1000 / 1024 / 1024 / usec;
	if (opts->sync_mode) {
		zbuf_idx += sprintf(zbuf + zbuf_idx,
				    " with %d send + %d poll threads",
				    opts->thread_num,
				    opts->poll_num);
	} else {
		zbuf_idx += sprintf(zbuf + zbuf_idx,
				    " with %d send threads",
				    opts->thread_num);
	}
	printf("%s at %.2fMB/s in %f usec (BLK:%d, Bnum:%d).\n",
	       zbuf, speed, usec, opts->block_size, opts->batch_num);
	uninit_config(&info, sched);
	free_threads(&info);
	wd_free_list_accels(info.list);
	usleep(1000);
	return 0;
out_buf:
out_poll:
	free_threads(&info);
out_send:
out_dfl:
	if (ifl_flag && tbuf && tbuf_sz)
		mmap_free(tbuf, tbuf_sz);
out_src:
	uninit_config(&info, sched);
out_cfg:
	wd_free_list_accels(info.list);
out:
	printf("Fail to run %s() (%d)!\n", model, ret);
	return ret;
}

int run_self_test(void)
{
	struct test_options opts = {
		.alg_type		= WD_ZLIB,
		.data_fmt		= WD_FLAT_BUF,
		.sync_mode		= 0,
		.thread_num		= 16,
		.q_num			= 16,
		.block_size		= 8192,
		.total_len		= 8192 * 10,
		.compact_run_num	= 1000,
	};
	int i, f_ret = 0;

	printf("Start to run self test!\n");
	for (i = 0; i < 10; i++) {
		opts.sync_mode = 0;
		switch (i) {
		case 0:
			opts.thread_num = 1;
			break;
		case 1:
			opts.thread_num = 2;
			break;
		case 2:
			opts.thread_num = 4;
			break;
		case 3:
			opts.thread_num = 8;
			break;
		case 4:
			opts.thread_num = 16;
			break;
		case 5:
			opts.thread_num = 1;
			opts.is_stream = 1;
			break;
		case 6:
			opts.thread_num = 2;
			opts.is_stream = 1;
			break;
		case 7:
			opts.thread_num = 4;
			opts.is_stream = 1;
			break;
		case 8:
			opts.thread_num = 8;
			opts.is_stream = 1;
			break;
		case 9:
			opts.thread_num = 16;
			opts.is_stream = 1;
			break;
		}
		f_ret |= test_hw(&opts, "hw_dfl_perf");
		f_ret |= test_hw(&opts, "hw_ifl_perf");
	}
	opts.is_stream = 0;	/* restore to BLOCK mode */
	for (i = 0; i < 10; i++) {
		opts.thread_num = 8;
		switch (i) {
		case 0:
			opts.sync_mode = 0;
			opts.block_size = 8192; opts.total_len = 8192 * 10;
			break;
		case 1:
			opts.sync_mode = 1; 	opts.poll_num = 1;
			opts.block_size = 8192; opts.total_len = 8192 * 10;
			break;
		case 2:
			opts.sync_mode = 1; 	opts.poll_num = 2;
			opts.block_size = 8192; opts.total_len = 8192 * 10;
			break;
		case 3:
			opts.sync_mode = 1;	opts.poll_num = 4;
			opts.block_size = 8192;	opts.total_len = 8192 * 10;
			break;
		case 4:
			opts.sync_mode = 1; 	opts.poll_num = 8;
			opts.block_size = 8192; opts.total_len = 8192 * 10;
			break;
		case 5:
			opts.sync_mode = 0;
			opts.block_size = 1024; opts.total_len = 8192 * 10;
			break;
		case 6:
			opts.sync_mode = 1; 	opts.poll_num = 1;
			opts.block_size = 1024; opts.total_len = 8192 * 10;
			break;
		case 7:
			opts.sync_mode = 1; 	opts.poll_num = 2;
			opts.block_size = 1024; opts.total_len = 8192 * 10;
			break;
		case 8:
			opts.sync_mode = 1;	opts.poll_num = 4;
			opts.block_size = 1024;	opts.total_len = 8192 * 10;
			break;
		case 9:
			opts.sync_mode = 1; 	opts.poll_num = 8;
			opts.block_size = 1024; opts.total_len = 8192 * 10;
			break;
		default:
			return -EINVAL;
		}
		f_ret |= test_hw(&opts, "sw_dfl_hw_ifl");
		f_ret |= test_hw(&opts, "hw_dfl_sw_ifl");
		f_ret |= test_hw(&opts, "hw_dfl_hw_ifl");
		f_ret |= test_hw(&opts, "hw_dfl_perf");
		f_ret |= test_hw(&opts, "hw_ifl_perf");
	}
	if (!f_ret)
		printf("Run self test successfully!\n");
	return f_ret;
}

static int set_default_opts(struct test_options *opts)
{
	if (!opts->block_size)
		opts->block_size = 8192;
	if (!opts->total_len) {
		if (opts->block_size)
			opts->total_len = opts->block_size * 10;
		else
			opts->total_len = 8192 * 10;
	}
	if (!opts->thread_num)
		opts->thread_num = 1;
	if (!opts->q_num)
		opts->q_num = opts->thread_num;
	if (!opts->compact_run_num)
		opts->compact_run_num = 1;
	if (!opts->poll_num)
		opts->poll_num = 1;
	if (opts->alg_type == WD_COMP_ALG_MAX)
		opts->alg_type = WD_GZIP;
	return 0;
}

int run_cmd(struct test_options *opts)
{
	int ret;

	set_default_opts(opts);
	if (opts->op_type == WD_DIR_COMPRESS) {
		if (opts->verify)
			ret = test_hw(opts, "hw_dfl_sw_ifl");
		else
			ret = test_hw(opts, "hw_dfl_perf");
	} else {
		if (opts->verify)
			ret = test_hw(opts, "sw_dfl_hw_ifl");
		else
			ret = test_hw(opts, "hw_ifl_perf");
	}
	return ret;
}
