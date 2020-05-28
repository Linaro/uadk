/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_comp.h"

#define BLOCK_SIZE	(1 << 19)
#define CACHE_NUM	1	//4

#define ZLIB_HEADER	"\x78\x9c"
#define ZLIB_HEADER_SZ	2

/*
 * We use a extra field for gzip block length. So the fourth byte is \x04.
 * This is necessary because our software don't know the size of block when
 * using an hardware decompresser (It is known by hardware). This help our
 * decompresser to work and helpfully, compatible with gzip.
 */
#define GZIP_HEADER	"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ	10
#define GZIP_EXTRA_SZ	10
#define GZIP_TAIL_SZ	8

#define BLOCK_MIN		(1 << 10)
#define BLOCK_MIN_MASK		0x3FF
#define BLOCK_MAX		(1 << 20)
#define BLOCK_MAX_MASK		0xFFFFF
#define STREAM_MIN		(1 << 10)
#define STREAM_MIN_MASK		0x3FF
#define STREAM_MAX		(1 << 20)
#define STREAM_MAX_MASK		0xFFFFF

#define Z_OK            0
#define Z_STREAM_END    1
#define Z_ERRNO		(-1)
#define Z_STREAM_ERROR	(-EIO)

#define swab32(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swab32(x)

struct hisi_strm_info {
	struct wd_comp_arg	*arg;
	void	*next_in;
	void	*next_out;
	void	*swap_in;
	void	*swap_out;
	size_t	size_in;	// the size of IN buf
	size_t	loaded_in;	// data size in IN buf for current transaction
	size_t	avail_in;	// the size that is free to use in IN buf
	size_t	avail_out;
	void	*ctx_buf;
	void	*ss_region;
	size_t	ss_region_size;
	int	stream_pos;
	int	alg_type;
	int	op_type;
	int	dw9;
	int	ctx_dw0;
	int	ctx_dw1;
	int	ctx_dw2;
	int	isize;
	int	checksum;
	int	load_head;
	struct hisi_zip_sqe	*msg;
	int	undrained;
	int	skipped;	// inflate
};

struct hisi_comp_sess {
	handle_t		h_ctx;
	struct wd_scheduler	sched;
	struct hisi_qm_capa	capa;
	struct hisi_strm_info	strm;
	int	inited;
};

struct hisi_sched {
	int	alg_type;
	int	op_type;
	int	dw9;
	struct hisi_zip_sqe	*msgs;
	struct wd_comp_arg	*arg;
	size_t		total_out;
	int	load_head;
	size_t	avail_in;
	size_t	avail_out;
	int	undrained;
	int	stream_pos;
	int	msg_data_size;
};

static inline int blk_is_new_src(struct wd_msg *msg,
				 struct hisi_sched *hpriv,
				 struct wd_comp_arg *arg)
{
	/* If all previous src data are consumed, next_in should be cleared to
	 * NULL.
	 */
	if (!msg->next_in)
		return 1;
	return 0;
}

static inline int blk_is_new_dst(struct wd_msg *msg,
				 struct hisi_sched *hpriv,
				 struct wd_comp_arg *arg)
{
	if (!msg->next_out)
		return 1;
	return 0;
}

/*
 * Compare the range with mask.
 * Notice: Avoid to compare them just after hardware operation.
 * It's better to compare swap with (addr - consumed/produced bytes).
 */
static inline int blk_is_in_swap(struct wd_msg *msg, void *addr, void *swap)
{
	/* NOSVA */
	if (msg->swap_in) {
		return 1;
	} else {
		if (((uint64_t)addr & ~STREAM_MIN_MASK) ==
		    ((uint64_t)swap & ~STREAM_MIN_MASK))
			return 1;
	}
	return 0;
}

static inline int blk_need_swap(struct wd_msg *msg,
				struct hisi_sched *hpriv,
				int buf_size)
{
	/* NOSVA */
	if (msg->swap_in)
		return 1;
	return 0;
}

static inline int blk_need_split(struct wd_msg *msg,
				 struct hisi_sched *hpriv,
				 int buf_size)
{
	if (buf_size > BLOCK_MAX)
		return 1;
	return 0;
}

/*
 * sched cuts a large frame from user App to multiple messages.
 * sched doesn't need to consider minimum block size.
 *
 */
static void hisi_sched_init(struct wd_scheduler *sched, int i, void *priv)
{
	struct wd_msg	*wd_msg = &sched->msgs[i];
	struct hisi_sched	*hpriv = sched->priv;

	wd_msg->msg = &hpriv->msgs[i];

	hpriv->avail_in = 0;
	hpriv->avail_out = 0;
	hpriv->load_head = 0;
	hpriv->undrained = 0;
	hpriv->total_out = 0;
}

static int hisi_sched_input(struct wd_msg *msg, void *priv)
{
	struct hisi_zip_sqe	*m = msg->msg;
	struct hisi_sched	*hpriv = (struct hisi_sched *)priv;
	struct wd_comp_arg	*arg = hpriv->arg;
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0, 0x0,
				    0x0, 0x0, 0x0, 0x0, 0x03};
	int templen, skipped = 0;
	void *addr;

	if (blk_need_swap(msg, hpriv, arg->dst_len)) {
		hpriv->avail_out = BLOCK_MAX;
		if (blk_is_new_dst(msg, hpriv, arg) || !hpriv->undrained)
			msg->next_out = msg->swap_out;
	} else {
		msg->next_out = arg->dst;
		hpriv->avail_out = arg->dst_len;
	}
	if (!hpriv->load_head && hpriv->op_type == DEFLATE) {
		if (hpriv->alg_type == ZLIB) {
			memcpy(msg->next_out, &zip_head, 2);
			templen = 2;
		} else {
			memcpy(msg->next_out, &gzip_head, 10);
			templen = 10;
		}
		msg->next_out += templen;
		hpriv->avail_out -= templen;
		hpriv->undrained += templen;
		hpriv->stream_pos = STREAM_NEW;
		hpriv->load_head = 1;
	}
	if (blk_is_new_src(msg, hpriv, arg) && arg->src_len) {
		if (blk_need_swap(msg, hpriv, arg->src_len)) {
			if (arg->src_len > BLOCK_MAX)
				templen = BLOCK_MAX;
			else
				templen = arg->src_len;
			msg->next_in = msg->swap_in;
			memcpy(msg->next_in + hpriv->avail_in,
			       arg->src,
			       templen);
			hpriv->avail_in += templen;
			m->input_data_length = templen;
			arg->src += templen;
			arg->src_len -= templen;
		} else if (blk_need_split(msg, hpriv, arg->src_len)) {
			msg->next_in = arg->src;
			hpriv->avail_in += BLOCK_MAX;
			m->input_data_length = BLOCK_MAX;
			arg->src += BLOCK_MAX;
			arg->src_len -= BLOCK_MAX;
		} else {
			msg->next_in = arg->src;
			hpriv->avail_in = arg->src_len;
			m->input_data_length = arg->src_len;
			arg->src += arg->src_len;
			arg->src_len = 0;
		}
	} else if (arg->src_len) {
		/* some data is cached in next_in buffer */
		if (blk_is_in_swap(msg, msg->next_in, msg->swap_in)) {
			templen = msg->swap_in + BLOCK_MAX -
				  msg->next_in - hpriv->avail_in;
			if (templen > arg->src_len)
				templen = arg->src_len;
			memcpy(msg->next_in + hpriv->avail_in,
			       arg->src,
			       templen);
			hpriv->avail_in += templen;
		} else {
			if (blk_need_split(msg, hpriv, arg->src_len))
				templen = STREAM_MAX;
			else
				templen = arg->src_len;
			msg->next_in = arg->src;
			hpriv->avail_in = templen;
		}
		arg->src += templen;
		arg->src_len -= templen;
		m->input_data_length = templen;
	}
	if (!hpriv->load_head && hpriv->op_type == INFLATE) {
		if (hpriv->alg_type == ZLIB)
			skipped = 2;
		else
			skipped = 10;
		msg->next_in += skipped;
		hpriv->avail_in -= skipped;
		m->input_data_length -= skipped;
		hpriv->stream_pos = STREAM_NEW;
		hpriv->load_head = 1;
	}
	addr = wd_get_dma_from_va(msg->h_ctx, msg->next_in);
	m->source_addr_l = (__u64)addr & 0xffffffff;
	m->source_addr_h = (__u64)addr >> 32;
	addr = wd_get_dma_from_va(msg->h_ctx, msg->next_out);
	m->dest_addr_l = (__u64)addr & 0xffffffff;
	m->dest_addr_h = (__u64)addr >> 32;
	m->dest_avail_out = hpriv->avail_out;
	m->dw9 = hpriv->dw9;
	return 0;
}

static int hisi_sched_output(struct wd_msg *msg, void *priv)
{
	struct hisi_zip_sqe	*m = msg->msg;
	struct hisi_sched	*hpriv = (struct hisi_sched *)priv;
	struct wd_comp_arg	*arg = hpriv->arg;
	int	templen;

	if (blk_is_in_swap(msg, msg->next_out, msg->swap_out)) {
		if (hpriv->undrained + m->produced > arg->dst_len)
			templen = arg->dst_len + m->produced;
		else
			templen = hpriv->undrained + m->produced;
		memcpy(arg->dst, msg->next_out - hpriv->undrained,
		       templen);
		hpriv->total_out += templen;
		hpriv->avail_in -= m->consumed;
		arg->dst += templen;
		arg->dst_len = templen;
	} else {
		/* drain next_out first */
		hpriv->total_out += hpriv->undrained + m->produced;
		hpriv->avail_in -= m->consumed;
		arg->dst += hpriv->undrained + m->produced;
		arg->dst_len = hpriv->undrained + m->produced;
	}
	hpriv->undrained = 0;
	arg->status |= STATUS_OUT_READY;
	if (hpriv->avail_in) {
		arg->status |= STATUS_IN_PART_USE;
	} else {
		arg->status |= STATUS_IN_EMPTY | STATUS_OUT_DRAINED;
		msg->next_out = NULL;
	}
	if (arg->status & STATUS_IN_EMPTY)
		msg->next_in = NULL;
	return 0;
}

static int hisi_comp_block_init(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	struct hisi_qm_capa	*capa;
	int	ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	capa = &priv->capa;
	sched->data = capa;
	sched->q_num = 1;
	sched->ss_region_size = 0; /* let system make decision */
	sched->msg_cache_num = CACHE_NUM;
	/* use double size of the input data */
	sched->msg_data_size = BLOCK_MAX;
	sched->init_cache = hisi_sched_init;
	sched->input = hisi_sched_input;
	sched->output = hisi_sched_output;
	sched->hw_alloc = hisi_qm_alloc_ctx;
	sched->hw_free = hisi_qm_free_ctx;
	sched->hw_send = hisi_qm_send;
	sched->hw_recv = hisi_qm_recv;

	sched->qs = malloc(sizeof(*sched->qs) * sched->q_num);
	if (!sched->qs)
		return -ENOMEM;

	sched_priv = malloc(sizeof(struct hisi_sched));
	if (!sched_priv)
		goto out_priv;
	sched_priv->msgs = malloc(sizeof(struct hisi_zip_sqe) * CACHE_NUM);
	if (!sched_priv->msgs)
		goto out_msg;
	if (!strncmp(sess->alg_name, "zlib", strlen("zlib"))) {
		sched_priv->alg_type = ZLIB;
		sched_priv->dw9 = 2;
		capa->alg = "zlib";
	} else {	// gzip
		sched_priv->alg_type = GZIP;
		sched_priv->dw9 = 3;
		capa->alg = "gzip";
	}
	sched_priv->msg_data_size = sched->msg_data_size;
	sched_priv->total_out = 0;
	sched_priv->load_head = 0;
	sched->priv = sched_priv;
	ret = wd_sched_init(sched, sess->node_path);
	if (ret < 0)
		goto out_sched;
	return 0;
out_sched:
	free(sched_priv->msgs);
out_msg:
	free(sched_priv);
out_priv:
	free(sched->qs);
	return ret;
}

static int hisi_comp_block_prep(struct wd_comp_sess *sess,
				 struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	struct hisi_qm_capa	*capa;
	struct hisi_qm_priv	*qm_priv;
	int	i, j, ret = -EINVAL;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	sched_priv = sched->priv;
	capa = &priv->capa;
	sched->data = capa;

	sched_priv->op_type = (arg->flag & FLAG_DEFLATE) ? DEFLATE: INFLATE;
	sched_priv->arg = arg;

	qm_priv = (struct hisi_qm_priv *)&priv->capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = sched_priv->op_type;
	for (i = 0; i < sched->q_num; i++) {
		ret = sched->hw_alloc(sched->qs[i], sched->data);
		if (ret)
			goto out_hw;
		ret = wd_ctx_start(sched->qs[i]);
		if (ret)
			goto out_start;
	}
	if (!sched->ss_region_size)
		sched->ss_region_size = 4096 + /* add 1 page extra */
			sched->msg_cache_num * sched->msg_data_size * 2;
	if (wd_is_nosva(sched->qs[0])) {
		sched->ss_region = wd_reserve_mem(sched->qs[0],
						  sched->ss_region_size);
		if (!sched->ss_region) {
			ret = -ENOMEM;
			goto out_region;
		}
		ret = smm_init(sched->ss_region, sched->ss_region_size, 0xF);
		if (ret)
			goto out_smm;
		for (i = 0; i < sched->msg_cache_num; i++) {
			sched->msgs[i].h_ctx = sched->qs[0];
			sched->msgs[i].swap_in =
				smm_alloc(sched->ss_region,
					  sched->msg_data_size);
			sched->msgs[i].swap_out =
				smm_alloc(sched->ss_region,
					  sched->msg_data_size);
			if (!sched->msgs[i].swap_in ||
			    !sched->msgs[i].swap_out) {
				dbg("not enough ss_region memory for cache %d "
				    "(bs=%d)\n", i, sched->msg_data_size);
				goto out_swap;
			}
		}
	} else {
		for (i = 0; i < sched->msg_cache_num; i++)
			sched->msgs[i].h_ctx = sched->qs[0];
	}
	return ret;
out_swap:
	for (j = i; j >= 0; j--) {
		if (sched->msgs[j].swap_in)
			smm_free(sched->ss_region, sched->msgs[j].swap_in);
		if (sched->msgs[j].swap_out)
			smm_free(sched->ss_region, sched->msgs[j].swap_out);
	}
out_smm:
	if (wd_is_nosva(sched->qs[0]) && sched->ss_region) {
		wd_drv_unmap_qfr(sched->qs[0], UACCE_QFRT_SS, sched->ss_region);
	}
out_region:
	for (j = i - 1; j >= 0; j--) {
		wd_ctx_stop(sched->qs[j]);
		sched->hw_free(sched->qs[j]);
	}
out_start:
	sched->hw_free(sched->qs[i]);
out_hw:
	for (j = i - 1; j >= 0; j--) {
		wd_ctx_stop(sched->qs[j]);
		sched->hw_free(sched->qs[j]);
	}
	return ret;
}

static void hisi_comp_block_exit(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	int	i;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;

	for (i = 0; i < sched->msg_cache_num; i++) {
		if (sched->msgs[i].swap_in)
			smm_free(sched->ss_region, sched->msgs[i].swap_in);
		if (sched->msgs[i].swap_out)
			smm_free(sched->ss_region, sched->msgs[i].swap_out);
	}
	if (wd_is_nosva(sched->qs[0]) && sched->ss_region) {
		wd_drv_unmap_qfr(sched->qs[0],
				 UACCE_QFRT_SS,
				 sched->ss_region);
	}
	for (i = 0; i < sched->q_num; i++) {
		wd_ctx_stop(sched->qs[i]);
		sched->hw_free(sched->qs[i]);
	}
	wd_sched_fini(sched);
	sched_priv = sched->priv;
	free(sched_priv->msgs);
	free(sched_priv);
	free(sched->qs);
}

static int hisi_comp_block_deflate(struct wd_comp_sess *sess,
				    struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	int	ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	sched_priv = sched->priv;

	if (!(arg->flag & FLAG_INPUT_FINISH) && (arg->src_len < BLOCK_MAX))
		return -EINVAL;

	while (arg->src_len || !wd_sched_empty(sched)) {
		ret = wd_sched_work(sched, arg->src_len);
		if (ret == -EAGAIN)
			continue;
		if (ret < 0) {
			WD_ERR("fail to deflate by wd_sched (%d)\n", ret);
			return ret;
		}
	}
	arg->dst_len = sched_priv->total_out;
	arg->status = STATUS_IN_EMPTY | STATUS_OUT_READY | STATUS_OUT_DRAINED;
	sched_priv->total_out = 0;
	return 0;
}

static int hisi_comp_block_inflate(struct wd_comp_sess *sess,
				    struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	int	ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	sched_priv = sched->priv;
	/* ZLIB engine can do only one time with buffer less than 16M */
	if (sched_priv->alg_type == ZLIB) {
		if (BLOCK_SIZE > 16 << 20) {
			WD_ERR("BLOCK_SIZE(%ld) > HW limitation (16MB)\n",
				arg->src_len);
			return -EINVAL;
		}
	}

	while (arg->src_len || !wd_sched_empty(sched)) {
		ret = wd_sched_work(sched, arg->src_len);
		if (ret == -EAGAIN)
			continue;
		if (ret < 0) {
			WD_ERR("fail to inflate by wd_sched (%d)\n", ret);
			return ret;
		}
	}
	arg->dst_len = sched_priv->total_out;
	arg->status = STATUS_IN_EMPTY | STATUS_OUT_READY | STATUS_OUT_DRAINED;
	sched_priv->total_out = 0;
	return 0;
}

static inline int is_new_src(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;

	/* If all previous src data are consumed, next_in should be cleared to
	 * NULL.
	 */
	if (!strm->next_in)
		return 1;
	return 0;
}

static inline int is_new_dst(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;

	if (!strm->next_out)
		return 1;
	return 0;
}

/*
 * Compare the range with mask.
 * Notice: Avoid to compare them just after hardware operation.
 * It's better to compare swap with (addr - consumed/produced bytes).
 */
static inline int is_in_swap(struct wd_comp_sess *sess, void *addr, void *swap)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;

	if (wd_is_nosva(priv->h_ctx)) {
		return 1;
	} else {
		if (((uint64_t)addr & ~STREAM_MIN_MASK) ==
		    ((uint64_t)swap & ~STREAM_MIN_MASK))
			return 1;
	}
	return 0;
}

/*
 * If arg->src buffer is too small, need to copy them into swap_in buffer.
 */
static inline int need_swap(struct wd_comp_sess *sess, int buf_size)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;

	if (wd_is_nosva(priv->h_ctx))
		return 1;
	if (buf_size < STREAM_MIN)
		return 1;
	return 0;
}

static inline int need_split(struct wd_comp_sess *sess, int buf_size)
{
	if (buf_size > STREAM_MAX)
		return 1;
	return 0;
}

static int hisi_comp_strm_init(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;

	if (strm->alg_type == ZLIB) {
		priv->capa.alg = "zlib";
		strm->alg_type = ZLIB;
		strm->dw9 = 2;
	} else {
		priv->capa.alg = "gzip";
		strm->alg_type = GZIP;
		strm->dw9 = 3;
	}
	strm->msg = calloc(1, sizeof(struct hisi_strm_info));
	if (!strm->msg)
		return -ENOMEM;
	priv->h_ctx = wd_request_ctx(sess->node_path);
	if (!priv->h_ctx)
		free(strm->msg);
	return 0;
}

static int hisi_comp_strm_prep(struct wd_comp_sess *sess,
			       struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;
	struct hisi_qm_priv	*qm_priv;
	int	ret;

	qm_priv = (struct hisi_qm_priv *)&priv->capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = (arg->flag & FLAG_DEFLATE) ? DEFLATE: INFLATE;
	ret = hisi_qm_alloc_ctx(priv->h_ctx, &priv->capa);
	if (ret)
		goto out;
	ret = wd_ctx_start(priv->h_ctx);
	if (ret)
		goto out_ctx;
	strm->load_head = 0;
	strm->undrained = 0;
	strm->skipped = 0;
	strm->loaded_in = 0;
	strm->avail_in = 0;
	strm->size_in = STREAM_MAX;
	strm->op_type = qm_priv->op_type;
	if (wd_is_nosva(priv->h_ctx)) {
		strm->ss_region_size = 4096 + STREAM_MAX * 2 + HW_CTX_SIZE;
		strm->ss_region = wd_reserve_mem(priv->h_ctx,
					sizeof(char) * strm->ss_region_size);
		if (!strm->ss_region) {
			WD_ERR("fail to allocate memory for SS region\n");
			ret = -ENOMEM;
			goto out_ss;
		}
		ret = smm_init(strm->ss_region, strm->ss_region_size, 0xF);
		if (ret)
			goto out_smm;
		ret = -ENOMEM;
		strm->swap_in = smm_alloc(strm->ss_region, STREAM_MAX);
		if (!strm->swap_in)
			goto out_smm;
		strm->swap_out = smm_alloc(strm->ss_region, STREAM_MAX);
		if (!strm->swap_out)
			goto out_smm_out;
		strm->ctx_buf = smm_alloc(strm->ss_region, HW_CTX_SIZE);
		if (!strm->ctx_buf)
			goto out_smm_ctx;
		strm->next_in = strm->swap_in;
		strm->next_out = strm->swap_out;
	} else {
		strm->swap_in = malloc(STREAM_MIN);
		if (!strm->swap_in)
			goto out_in;
		strm->swap_out = malloc(STREAM_MIN);
		if (!strm->swap_out)
			goto out_out;
		strm->ctx_buf = malloc(HW_CTX_SIZE);
		if (!strm->ctx_buf)
			goto out_buf;
		strm->next_in = NULL;
		strm->next_out = NULL;
	}
	return 0;
out_smm_ctx:
	smm_free(strm->ss_region, strm->swap_out);
out_smm_out:
	smm_free(strm->ss_region, strm->swap_in);
out_smm:
	free(strm->ss_region);
out_ss:
	wd_ctx_stop(priv->h_ctx);
out_ctx:
	hisi_qm_free_ctx(priv->h_ctx);
out:
	return ret;
out_buf:
	free(strm->next_out);
out_out:
	free(strm->next_in);
out_in:
	wd_ctx_stop(priv->h_ctx);
	hisi_qm_free_ctx(priv->h_ctx);
	return -ENOMEM;
}

static void hisi_comp_strm_exit(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct hisi_strm_info	*strm;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;

	wd_ctx_stop(priv->h_ctx);
	if (wd_is_nosva(priv->h_ctx)) {
		smm_free(strm->ss_region, strm->swap_in);
		smm_free(strm->ss_region, strm->swap_out);
		smm_free(strm->ss_region, strm->ctx_buf);
	} else {
		free(strm->swap_in);
		free(strm->swap_out);
		free(strm->ctx_buf);
	}
	hisi_qm_free_ctx(priv->h_ctx);
	wd_release_ctx(priv->h_ctx);
	free(strm->msg);
}

static int hisi_strm_comm(struct wd_comp_sess *sess, int flush)
{
	struct hisi_comp_sess	*priv;
	struct hisi_zip_sqe	*msg, *recv_msg;
	struct hisi_strm_info	*strm;
	uint32_t	status, type;
	uint64_t	flush_type;
	uint64_t	addr;
	size_t	templen;
	int	ret = 0;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;

	flush_type = (flush == WD_FINISH) ? HZ_FINISH : HZ_SYNC_FLUSH;

	msg = strm->msg;
	memset((void *)msg, 0, sizeof(*msg));
	msg->dw9 = strm->dw9;
	msg->dw7 |= ((strm->stream_pos << 2 | STATEFUL << 1 | flush_type)) <<
		    STREAM_FLUSH_SHIFT;
	if (strm->stream_pos == STREAM_NEW) {
		strm->stream_pos = STREAM_OLD;
		if (strm->skipped) {
			strm->next_in += strm->skipped;
			strm->loaded_in -= strm->skipped;
			strm->skipped = 0;
		}
	}
	if (wd_is_nosva(priv->h_ctx)) {
		addr = (uint64_t)wd_get_dma_from_va(priv->h_ctx, strm->next_in);
		msg->source_addr_l = (uint64_t)addr & 0xffffffff;
		msg->source_addr_h = (uint64_t)addr >> 32;
		addr = (uint64_t)wd_get_dma_from_va(priv->h_ctx,
						    strm->next_out);
		msg->dest_addr_l = (uint64_t)addr & 0xffffffff;
		msg->dest_addr_h = (uint64_t)addr >> 32;
	} else {
		msg->source_addr_l = (uint64_t)strm->next_in & 0xffffffff;
		msg->source_addr_h = (uint64_t)strm->next_in >> 32;
		msg->dest_addr_l = (uint64_t)strm->next_out & 0xffffffff;
		msg->dest_addr_h = (uint64_t)strm->next_out >> 32;
	}
	msg->input_data_length = strm->loaded_in;
	msg->dest_avail_out = strm->avail_out;

	if (strm->op_type == INFLATE) {
		if (wd_is_nosva(priv->h_ctx)) {
			addr = (uint64_t)wd_get_dma_from_va(priv->h_ctx,
							    strm->ctx_buf);
			msg->stream_ctx_addr_l = (uint64_t)addr & 0xffffffff;
			msg->stream_ctx_addr_h = (uint64_t)addr >> 32;
		} else {
			msg->stream_ctx_addr_l = (uint64_t)strm->ctx_buf &
						0xffffffff;
			msg->stream_ctx_addr_h = (uint64_t)strm->ctx_buf >> 32;
		}
	}
	msg->ctx_dw0 = strm->ctx_dw0;
	msg->ctx_dw1 = strm->ctx_dw1;
	msg->ctx_dw2 = strm->ctx_dw2;
	msg->isize = strm->isize;
	msg->checksum = strm->checksum;

	ret = hisi_qm_send(priv->h_ctx, msg);
	if (ret == -EBUSY) {
		usleep(1);
		goto recv_again;
	}
	if (ret) {
		WD_ERR("send failure (%d)\n", ret);
		goto out;
	}

recv_again:
	ret = hisi_qm_recv(priv->h_ctx, (void **)&recv_msg);
	if (ret == -EIO) {
		fputs(" wd_recv fail!\n", stderr);
		goto out;
	/* synchronous mode, if get none, then get again */
	} else if (ret == -EAGAIN)
		goto recv_again;
	status = recv_msg->dw3 & 0xff;
	type = recv_msg->dw9 & 0xff;
	if (!status || (status == 0x0d) || (status == 0x13)) {
		strm->undrained += recv_msg->produced;
		strm->next_in += recv_msg->consumed;
		strm->next_out += recv_msg->produced;
		strm->avail_out -= recv_msg->produced;
		strm->ctx_dw0 = recv_msg->ctx_dw0;
		strm->ctx_dw1 = recv_msg->ctx_dw1;
		strm->ctx_dw2 = recv_msg->ctx_dw2;
		strm->isize = recv_msg->isize;
		strm->checksum = recv_msg->checksum;

		templen = strm->loaded_in - recv_msg->consumed;
		strm->avail_in += templen;
		/* only partial source data is consumed */
		if (templen && (strm->arg->status & STATUS_IN_EMPTY)) {
			strm->arg->status &= ~STATUS_IN_EMPTY;
			strm->arg->status |= STATUS_IN_PART_USE;
			strm->arg->src -= templen;
			strm->arg->src_len = templen;
		}
		/* after one transaction, always load data to IN buf again */
		strm->loaded_in = 0;
		strm->avail_in = 0;

		if (ret == 0 && flush == WD_FINISH)
			ret = Z_STREAM_END;
		else if (ret == 0 &&  (recv_msg->dw3 & 0x1ff) == 0x113)
			ret = Z_STREAM_END;    /* decomp_is_end  region */
	} else
		WD_ERR("bad status (s=%d, t=%d)\n", status, type);
out:
	return ret;
}

static void hisi_strm_pre_buf(struct wd_comp_sess *sess,
			      struct wd_comp_arg *arg,
			      int *full)
{
	struct hisi_comp_sess	*priv;
	struct hisi_strm_info	*strm;
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0, 0x0,
				    0x0, 0x0, 0x0, 0x0, 0x03};
	int templen, skipped;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;

	/* reset strm->avail_in */
	if (strm->avail_in < STREAM_MIN) {
		if (wd_is_nosva(priv->h_ctx)) {
			strm->next_in = strm->swap_in;
			strm->size_in = STREAM_MAX;
			strm->avail_in = STREAM_MAX;
			strm->loaded_in = 0;
		} else if (need_swap(sess, arg->src_len) &&
			   (strm->size_in != STREAM_MIN)) {
			strm->next_in = strm->swap_in;
			strm->size_in = STREAM_MIN;
			strm->avail_in = STREAM_MIN;
			strm->loaded_in = 0;
		} else if (strm->size_in != STREAM_MIN) {
			strm->next_in = arg->src;
			strm->size_in = STREAM_MAX;
			strm->avail_in = STREAM_MAX;
			strm->loaded_in = 0;
		}
	}

	/* full & skipped are used in IN, strm->undrained is used in OUT */
	if (need_swap(sess, arg->dst_len)) {
		if (wd_is_nosva(priv->h_ctx))
			strm->avail_out = STREAM_MAX;
		else
			strm->avail_out = STREAM_MIN;
		if (is_new_dst(sess, arg) || !strm->undrained)
			strm->next_out = strm->swap_out;
	} else if (need_split(sess, arg->dst_len)) {
		strm->next_out = arg->dst;
		strm->avail_out = STREAM_MAX;
	} else {
		strm->next_out = arg->dst;
		strm->avail_out = arg->dst_len;
	}

	if (!strm->load_head && strm->op_type == DEFLATE) {
		if (strm->alg_type == ZLIB) {
			memcpy(strm->next_out, &zip_head, 2);
			templen = 2;
		} else {
			memcpy(strm->next_out, &gzip_head, 10);
			templen = 10;
		}
		strm->next_out += templen;
		strm->avail_out -= templen;
		strm->undrained += templen;
		strm->stream_pos = STREAM_NEW;
		strm->load_head = 1;
	}
	if (arg->src_len) {
		if (arg->src_len >= strm->avail_in) {
			templen = strm->avail_in;
			*full = 1;
		} else {
			templen = arg->src_len;
		}
		if (need_swap(sess, arg->src_len)) {
			memcpy(strm->next_in + strm->loaded_in,
			       arg->src,
			       templen);
		}
		strm->loaded_in += templen;
		strm->avail_in -= templen;
		arg->src += templen;
		arg->src_len -= templen;
	}

	if (!strm->load_head && strm->op_type == INFLATE) {
		if (strm->alg_type == ZLIB)
			skipped = 2;
		else
			skipped = 10;
		if (strm->loaded_in >= skipped) {
			strm->skipped = skipped;
			strm->stream_pos = STREAM_NEW;
			strm->load_head = 1;
		}
	}
}

static void hisi_strm_post_buf(struct wd_comp_sess *sess,
			       struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct hisi_strm_info	*strm;
	int templen;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;

	if (strm->undrained) {
		if (is_in_swap(sess, strm->next_out, strm->swap_out)) {
			if (strm->undrained > arg->dst_len)
				templen = arg->dst_len;
			else
				templen = strm->undrained;
			memcpy(arg->dst, strm->next_out - strm->undrained,
			       templen);
			arg->dst += templen;
			arg->dst_len = templen;
			strm->undrained -= templen;
		} else {
			/* drain next_out first */
			arg->dst += strm->undrained;
			arg->dst_len = strm->undrained;
			strm->undrained = 0;
		}
		arg->status |= STATUS_OUT_READY;
	}
	if (!strm->undrained && !strm->loaded_in) {
		arg->status |= STATUS_OUT_DRAINED;
		strm->next_out = NULL;
	}
}

static int hisi_comp_strm_deflate(struct wd_comp_sess *sess,
				  struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct hisi_strm_info	*strm;
	int	ret, flush = 0;
	int	full = 0;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;
	strm->arg = arg;
	strm->op_type = DEFLATE;

	hisi_strm_pre_buf(sess, arg, &full);
	arg->status &= ~STATUS_IN_PART_USE;
	arg->status |= STATUS_IN_EMPTY;
	if (strm->loaded_in) {
		if (arg->flag & FLAG_INPUT_FINISH)
			flush = WD_FINISH;
		else if (full)
			flush = WD_SYNC_FLUSH;
		else {
			hisi_strm_post_buf(sess, arg);
			return 0;
		}
		ret = hisi_strm_comm(sess, flush);
		if (ret < 0)
			return ret;
	}
	hisi_strm_post_buf(sess, arg);
	return 0;
}

static int hisi_comp_strm_inflate(struct wd_comp_sess *sess,
				  struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct hisi_strm_info	*strm;
	int	flush = 0, full = 0, ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;
	strm->arg = arg;
	strm->op_type = INFLATE;

	hisi_strm_pre_buf(sess, arg, &full);
	arg->status &= ~STATUS_IN_PART_USE;
	arg->status |= STATUS_IN_EMPTY;
	if (strm->loaded_in) {
		if (arg->flag & FLAG_INPUT_FINISH)
			flush = WD_FINISH;
		else if (full)
			flush = WD_SYNC_FLUSH;
		else {
			hisi_strm_post_buf(sess, arg);
			return 0;
		}
		ret = hisi_strm_comm(sess, flush);
		if (ret < 0)
			return ret;
	}
	hisi_strm_post_buf(sess, arg);
	return 0;
}

int hisi_comp_init(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;

	priv = calloc(1, sizeof(struct hisi_comp_sess));
	if (!priv)
		return -ENOMEM;
	priv->inited = 0;
	sess->priv = priv;
	if (sess->mode & MODE_STREAM)
		hisi_comp_strm_init(sess);
	else
		hisi_comp_block_init(sess);
	return 0;
}

void hisi_comp_exit(struct wd_comp_sess *sess)
{
	if (sess->mode & MODE_STREAM) {
		hisi_comp_strm_exit(sess);
	} else {
		hisi_comp_block_exit(sess);
	}
	free(sess->priv);
	sess->priv = NULL;
}

int hisi_comp_prep(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = sess->priv;
	int	ret;

	if (priv->inited)
		return 0;
	if (sess->mode & MODE_STREAM)
		ret = hisi_comp_strm_prep(sess, arg);
	else
		ret = hisi_comp_block_prep(sess, arg);
	if (!ret)
		priv->inited = 1;
	return ret;
}

int hisi_comp_deflate(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	int	ret;

	if (sess->mode & MODE_STREAM)
		ret = hisi_comp_strm_deflate(sess, arg);
	else
		ret = hisi_comp_block_deflate(sess, arg);
	return ret;
}

int hisi_comp_inflate(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	int	ret;

	if (sess->mode & MODE_STREAM)
		ret = hisi_comp_strm_inflate(sess, arg);
	else
		ret = hisi_comp_block_inflate(sess, arg);
	return ret;
}

int hisi_comp_poll(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	return 0;
}
