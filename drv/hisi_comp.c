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

#define HISI_SCHED_INPUT	0
#define HISI_SCHED_OUTPUT	1

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

#ifndef container_of
#define container_of(ptr, type, member) \
	(type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

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
	/* struct hisi_qp must be set in the first property */
	struct hisi_qp		*qp;
	struct wd_scheduler	sched;
	struct hisi_strm_info	strm;
	struct hisi_qm_capa	capa;
	int	inited;
};

struct hisi_sched {
	struct wd_comp_sess	*sess;
	int	alg_type;
	int	op_type;
	int	dw9;
	struct hisi_zip_sqe	*msgs;
	struct wd_comp_arg	*arg;
	size_t		total_out;
	int	load_head;
	size_t	avail_in;	// the size that is free to use in IN buf
	size_t	avail_out;
	size_t	size_in;
	size_t	loaded_in;
	int	undrained;
	int	skipped;
	int	full;
	int	stream_pos;
	int	msg_data_size;
	int	dir;		// input or output
};

static inline int is_nosva(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct wd_scheduler	*sched = &priv->sched;
	struct hisi_sched	*hsched = sched->priv;
	struct hisi_qp		*qp = priv->qp;
	handle_t	h_ctx = 0;

	if (sess->mode & MODE_STREAM) {
		h_ctx = qp->h_ctx;
	} else {
		if (hsched->dir == HISI_SCHED_INPUT)
			h_ctx = sched->qs[sched->q_h];
		else
			h_ctx = sched->qs[sched->q_t];
	}
	/* If context handle is NULL, always consider it as NOSVA. */
	if (!h_ctx)
		return 1;
	return wd_is_nosva(h_ctx);
}

static inline int is_new_src(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;
	struct wd_scheduler	*sched = &priv->sched;
	struct hisi_sched	*hsched = sched->priv;
	struct wd_msg		*msgs = sched->msgs;
	void	*next_in = NULL;

	if (sess->mode & MODE_STREAM) {
		next_in = strm->next_in;
	} else {
		/* BLOCK mode */
		if (hsched->dir == HISI_SCHED_INPUT)
			next_in = msgs[sched->c_h].next_in;
		else
			next_in = msgs[sched->c_t].next_in;
	}
	/*
	 * If all previous src data are consumed, next_in should be cleared to
	 * NULL.
	 */
	if (!next_in)
		return 1;
	return 0;
}

static inline int is_new_dst(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;
	struct wd_scheduler	*sched = &priv->sched;
	struct hisi_sched	*hsched = sched->priv;
	struct wd_msg		*msgs = sched->msgs;
	void	*next_out = NULL;

	if (sess->mode & MODE_STREAM) {
		next_out = strm->next_out;
	} else {
		if (hsched->dir == HISI_SCHED_INPUT)
			next_out = msgs[sched->c_h].next_out;
		else
			next_out = msgs[sched->c_t].next_out;
	}
	if (!next_out)
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
	if (is_nosva(sess))
		return 1;
	else {
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
	if (is_nosva(sess))
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

/*
 * sched cuts a large frame from user App to multiple messages.
 * sched doesn't need to consider minimum block size.
 *
 */
static void hisi_sched_init(struct wd_scheduler *sched, int i, void *priv)
{
	struct hisi_sched	*hsched = sched->priv;
	int j;

	for (j = 0; j < sched->msg_cache_num; j++)
		sched->msgs[j].msg = &hsched->msgs[j];

	hsched->avail_in = 0;
	hsched->avail_out = 0;
	hsched->load_head = 0;
	hsched->undrained = 0;
	hsched->total_out = 0;
	hsched->loaded_in = 0;
	hsched->size_in = STREAM_MAX;
	hsched->full = 0;
	hsched->skipped = 0;
}

static int hisi_sched_input(struct wd_msg *msg, void *priv)
{
	struct hisi_zip_sqe	*m = msg->msg;
	struct hisi_sched	*hsched = (struct hisi_sched *)priv;
	struct wd_comp_sess	*sess = hsched->sess;
	struct hisi_comp_sess	*hsess = (struct hisi_comp_sess *)sess->priv;
	struct wd_scheduler	*sched = &hsess->sched;
	struct wd_comp_arg	*arg = hsched->arg;
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0, 0x0,
				    0x0, 0x0, 0x0, 0x0, 0x03};
	int templen, skipped = 0;
	handle_t h_ctx;
	void *addr;

	/* reset hsched->avail_in */
	if (hsched->avail_in < STREAM_MIN) {
		if (is_nosva(sess)) {
			msg->next_in = msg->swap_in;
			hsched->size_in = STREAM_MAX;
			hsched->avail_in = STREAM_MAX;
			hsched->loaded_in = 0;
		} else {
			msg->next_in = arg->src;
			hsched->size_in = STREAM_MAX;
			hsched->avail_in = STREAM_MAX;
			hsched->loaded_in = 0;
		}
	}

	if (need_swap(sess, arg->dst_len)) {
		hsched->avail_out = STREAM_MAX;
		if (is_new_dst(sess, arg) || !hsched->undrained)
			msg->next_out = msg->swap_out;
	} else if (need_split(sess, arg->dst_len)) {
		msg->next_out = arg->dst;
		hsched->avail_out = STREAM_MAX;
	} else {
		msg->next_out = arg->dst;
		hsched->avail_out = arg->dst_len;
	}

	if (!hsched->load_head && hsched->op_type == DEFLATE) {
		if (hsched->alg_type == ZLIB) {
			memcpy(msg->next_out, &zip_head, 2);
			templen = 2;
		} else {
			memcpy(msg->next_out, &gzip_head, 10);
			templen = 10;
		}
		msg->next_out += templen;
		hsched->avail_out -= templen;
		hsched->undrained += templen;
		hsched->stream_pos = STREAM_NEW;
		hsched->load_head = 1;
	}

	if (arg->src_len) {
		if (arg->src_len >= hsched->avail_in) {
			templen = hsched->avail_in;
			hsched->full = 1;
		} else {
			templen = arg->src_len;
		}
		if (need_swap(sess, arg->src_len)) {
			memcpy(msg->next_in + hsched->loaded_in,
			       arg->src,
			       templen);
		}
		hsched->loaded_in += templen;
		hsched->avail_in -= templen;
		arg->src += templen;
		m->input_data_length = templen;
	}

	if (!hsched->load_head && hsched->op_type == INFLATE) {
		if (hsched->alg_type == ZLIB)
			skipped = 2;
		else
			skipped = 10;
		if (hsched->loaded_in >= skipped) {
			hsched->skipped = skipped;
			hsched->stream_pos = STREAM_NEW;
			hsched->load_head = 1;
			m->input_data_length -= skipped;
			msg->next_in += skipped;
		}
	}

	if (hsched->dir == HISI_SCHED_INPUT)
		h_ctx = sched->qs[sched->q_h];
	else
		h_ctx = sched->qs[sched->q_t];

	addr = wd_get_dma_from_va(h_ctx, msg->next_in);
	m->source_addr_l = (__u64)addr & 0xffffffff;
	m->source_addr_h = (__u64)addr >> 32;
	addr = wd_get_dma_from_va(h_ctx, msg->next_out);
	m->dest_addr_l = (__u64)addr & 0xffffffff;
	m->dest_addr_h = (__u64)addr >> 32;
	m->dest_avail_out = hsched->avail_out;
	m->dw9 = hsched->dw9;
	return 0;
}

static int hisi_sched_output(struct wd_msg *msg, void *priv)
{
	struct hisi_zip_sqe	*m = msg->msg;
	struct hisi_sched	*hsched = (struct hisi_sched *)priv;
	struct wd_comp_sess	*sess = hsched->sess;
	struct wd_comp_arg	*arg = hsched->arg;
	uint32_t	status, type;
	int	templen;

	status = m->dw3 & 0xff;
	type = m->dw9 & 0xff;
	if (!status || (status == 0x0d) || (status == 0x13)) {
		hsched->undrained += m->produced;
		msg->next_in += m->consumed;
		msg->next_out += m->produced;
		hsched->avail_out -= m->produced;

		templen = hsched->loaded_in - m->consumed;
		hsched->avail_in += templen;
		if (templen && (arg->status & STATUS_IN_EMPTY)) {
			arg->status &= ~STATUS_IN_EMPTY;
			arg->status |= STATUS_IN_PART_USE;
			arg->src -= templen;
			arg->src_len = m->consumed + hsched->skipped;
		} else
			arg->src_len = m->consumed + hsched->skipped;
		hsched->loaded_in = 0;
		hsched->avail_in = 0;
		if (hsched->stream_pos == STREAM_NEW) {
			hsched->stream_pos = STREAM_OLD;
			hsched->skipped = 0;
		}
	} else {
		WD_ERR("bad status (s=%d, t=%d)\n", status, type);
		return -EIO;
	}
	if (hsched->undrained) {
		if (is_in_swap(sess, msg->next_out, msg->swap_out)) {
			if (hsched->undrained > arg->dst_len)
				templen = arg->dst_len;
			else
				templen = hsched->undrained;
			memcpy(arg->dst,
			       msg->next_out - hsched->undrained,
			       templen);
			arg->dst += templen;
			arg->dst_len = templen;
			hsched->undrained -= templen;
		} else {
			/* drain next_out first */
			arg->dst += hsched->undrained;
			arg->dst_len = hsched->undrained;
			hsched->undrained = 0;
		}
		arg->status |= STATUS_OUT_READY;
	}
	if (!hsched->undrained && ~hsched->loaded_in) {
		arg->status |= STATUS_OUT_DRAINED;
		msg->next_out = NULL;
	}
	return 0;
}

static int hisi_comp_block_init(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*hsched;
	struct hisi_qm_capa	*capa;
	int	ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	capa = &priv->capa;
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

	hsched = malloc(sizeof(struct hisi_sched));
	if (!hsched)
		goto out_priv;
	hsched->sess = sess;
	hsched->msgs = malloc(sizeof(struct hisi_zip_sqe) * CACHE_NUM);
	if (!hsched->msgs)
		goto out_msg;
	if (!strncmp(sess->alg_name, "zlib", strlen("zlib"))) {
		hsched->alg_type = ZLIB;
		hsched->dw9 = 2;
		capa->alg = strdup("zlib");
	} else if (!strncmp(sess->alg_name, "gzip", strlen("gzip"))) {
		hsched->alg_type = GZIP;
		hsched->dw9 = 3;
		capa->alg = strdup("gzip");
	} else
		goto out_sched;
	hsched->msg_data_size = sched->msg_data_size;
	hsched->total_out = 0;
	hsched->load_head = 0;
	sched->priv = hsched;
	ret = wd_sched_init(sched, sess->node_path);
	if (ret < 0)
		goto out_sched;
	return 0;
out_sched:
	free(hsched->msgs);
out_msg:
	free(hsched);
out_priv:
	free(sched->qs);
	return ret;
}

static int hisi_comp_block_prep(struct wd_comp_sess *sess,
				 struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*hsched;
	struct hisi_qm_priv	*qm_priv;
	int	i, j, ret = 0;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	hsched = sched->priv;
	sched->data = priv->qp;

	hsched->op_type = (arg->flag & FLAG_DEFLATE) ? DEFLATE: INFLATE;
	hsched->arg = arg;

	qm_priv = (struct hisi_qm_priv *)&priv->capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = hsched->op_type;
	for (i = 0; i < sched->q_num; i++) {
		sched->qs[i] = sched->hw_alloc(sess->node_path,
					       (void *)qm_priv,
					       &sched->data);
		if (!sched->qs[i]) {
			ret = -EINVAL;
			goto out_hw;
		}
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
		if (ret) {
			ret = -EFAULT;
			goto out_smm;
		}
		for (i = 0; i < sched->msg_cache_num; i++) {
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
				ret = -ENOMEM;
				goto out_swap;
			}
		}
	} else {
		for (i = 0; i < sched->msg_cache_num; i++) {
			sched->msgs[i].swap_in = malloc(sched->msg_data_size);
			sched->msgs[i].swap_out = malloc(sched->msg_data_size);
			if (!sched->msgs[i].swap_in ||
			    !sched->msgs[i].swap_out) {
				dbg("not enough memory for cache %d\n", i);
				ret = -ENOMEM;
				goto out_swap2;
			}
		}
	}
	return ret;
out_swap2:
	for (j = i; j >= 0; j--) {
		if (sched->msgs[j].swap_in)
			free(sched->msgs[j].swap_in);
		if (sched->msgs[j].swap_out)
			free(sched->msgs[j].swap_out);
	}
	for (j = i - 1; j >= 0; j--) {
		sched->hw_free(sched->qs[j]);
	}
	sched->hw_free(sched->qs[i]);
	for (j = i - 1; j >= 0; j--) {
		sched->hw_free(sched->qs[j]);
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
		sched->hw_free(sched->qs[j]);
	}
	sched->hw_free(sched->qs[i]);
out_hw:
	for (j = i - 1; j >= 0; j--) {
		sched->hw_free(sched->qs[j]);
	}
	return ret;
}

static void hisi_comp_block_exit(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*hsched;
	int	i, is_nosva;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;

	is_nosva = wd_is_nosva(sched->qs[0]);
	for (i = 0; i < sched->q_num; i++) {
		sched->hw_free(sched->qs[i]);
	}
	for (i = 0; i < sched->msg_cache_num; i++) {
		if (is_nosva) {
			if (sched->msgs[i].swap_in)
				smm_free(sched->ss_region,
					 sched->msgs[i].swap_in);
			if (sched->msgs[i].swap_out)
				smm_free(sched->ss_region,
					 sched->msgs[i].swap_out);
		} else {
			free(sched->msgs[i].swap_in);
			free(sched->msgs[i].swap_out);
		}
	}
	if (is_nosva && sched->ss_region) {
		wd_drv_unmap_qfr(sched->qs[0],
				 UACCE_QFRT_SS,
				 sched->ss_region);
	}
	wd_sched_fini(sched);
	hsched = sched->priv;
	free(hsched->msgs);
	free(hsched);
	free(sched->qs);
}

static int hisi_comp_block_deflate(struct wd_comp_sess *sess,
				    struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	int	ret;
	size_t	src_len;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;

	if (!(arg->flag & FLAG_INPUT_FINISH) && (arg->src_len < BLOCK_MAX))
		return -EINVAL;

	src_len = arg->src_len;
	while (src_len || !wd_sched_empty(sched)) {
		ret = wd_sched_work(sched, src_len);
		if (ret == -EAGAIN)
			continue;
		if (ret < 0) {
			WD_ERR("fail to deflate by wd_sched (%d)\n", ret);
			return ret;
		}
		if (src_len == 0)
			break;
		src_len -= arg->src_len;
		arg->src_len = src_len;
	}
	arg->status = STATUS_IN_EMPTY | STATUS_OUT_READY | STATUS_OUT_DRAINED;
	return 0;
}

static int hisi_comp_block_inflate(struct wd_comp_sess *sess,
				    struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*hsched;
	int	ret;
	size_t	src_len;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	hsched = sched->priv;
	/* ZLIB engine can do only one time with buffer less than 16M */
	if (hsched->alg_type == ZLIB) {
		if (BLOCK_SIZE > 16 << 20) {
			WD_ERR("BLOCK_SIZE(%ld) > HW limitation (16MB)\n",
				arg->src_len);
			return -EINVAL;
		}
	}

	src_len = arg->src_len;
	while (src_len || !wd_sched_empty(sched)) {
		ret = wd_sched_work(sched, src_len);
		if (ret == -EAGAIN)
			continue;
		if (ret < 0) {
			WD_ERR("fail to inflate by wd_sched (%d)\n", ret);
			return ret;
		}
		if (src_len == 0)
			break;
		src_len -= arg->src_len;
		arg->src_len = src_len;
	}
	arg->status = STATUS_IN_EMPTY | STATUS_OUT_READY | STATUS_OUT_DRAINED;
	return 0;
}


static int hisi_comp_strm_init(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;
	struct hisi_qm_capa	*capa = &priv->capa;

	if (!strncmp(sess->alg_name, "zlib", strlen("zlib"))) {
		capa->alg = strdup("zlib");
		strm->alg_type = ZLIB;
		strm->dw9 = 2;
	} else if (!strncmp(sess->alg_name, "gzip", strlen("gzip"))) {
		capa->alg = strdup("gzip");
		strm->alg_type = GZIP;
		strm->dw9 = 3;
	} else
		return -EINVAL;
	strm->msg = calloc(1, sizeof(struct hisi_strm_info));
	if (!strm->msg)
		return -ENOMEM;
	return 0;
}

static int hisi_comp_strm_prep(struct wd_comp_sess *sess,
			       struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv = (struct hisi_comp_sess *)sess->priv;
	struct hisi_strm_info	*strm = &priv->strm;
	struct hisi_qm_priv	*qm_priv;
	handle_t h_ctx;
	int	ret;

	qm_priv = (struct hisi_qm_priv *)&priv->capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = (arg->flag & FLAG_DEFLATE) ? DEFLATE: INFLATE;
	h_ctx = hisi_qm_alloc_ctx(sess->node_path,
				  (void *)qm_priv,
				  (void **)&priv->qp);
	if (!h_ctx) {
		ret = -EINVAL;
		goto out;
	}
	strm->load_head = 0;
	strm->undrained = 0;
	strm->skipped = 0;
	strm->loaded_in = 0;
	strm->avail_in = 0;
	strm->size_in = STREAM_MAX;
	strm->op_type = qm_priv->op_type;
	if (wd_is_nosva(h_ctx)) {
		strm->ss_region_size = 4096 + STREAM_MAX * 2 + HW_CTX_SIZE;
		strm->ss_region = wd_reserve_mem(h_ctx,
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
	hisi_qm_free_ctx(h_ctx);
out:
	return ret;
out_buf:
	free(strm->next_out);
out_out:
	free(strm->next_in);
out_in:
	hisi_qm_free_ctx(h_ctx);
	return -ENOMEM;
}

static void hisi_comp_strm_exit(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct hisi_strm_info	*strm;
	struct hisi_qp		*qp;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;
	qp = priv->qp;

	if (wd_is_nosva(qp->h_ctx)) {
		smm_free(strm->ss_region, strm->swap_in);
		smm_free(strm->ss_region, strm->swap_out);
		smm_free(strm->ss_region, strm->ctx_buf);
	} else {
		free(strm->swap_in);
		free(strm->swap_out);
		free(strm->ctx_buf);
	}
	hisi_qm_free_ctx(qp->h_ctx);
	free(strm->msg);
}

static int hisi_strm_comm(struct wd_comp_sess *sess, int flush)
{
	struct hisi_comp_sess	*priv;
	struct hisi_qp		*qp;
	struct hisi_zip_sqe	*msg, *recv_msg;
	struct hisi_strm_info	*strm;
	uint32_t	status, type;
	uint64_t	flush_type;
	uint64_t	addr;
	size_t	templen;
	int	ret = 0;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;
	qp = priv->qp;

	flush_type = (flush == WD_FINISH) ? HZ_FINISH : HZ_SYNC_FLUSH;

	msg = strm->msg;
	memset((void *)msg, 0, sizeof(*msg));
	msg->dw9 = strm->dw9;
	msg->dw7 |= ((strm->stream_pos << 2 | STATEFUL << 1 | flush_type)) <<
		    STREAM_FLUSH_SHIFT;
	if (strm->stream_pos == STREAM_NEW) {
		if (strm->skipped) {
			strm->next_in += strm->skipped;
			strm->loaded_in -= strm->skipped;
		}
	} else
		strm->skipped = 0;
	if (wd_is_nosva(qp->h_ctx)) {
		addr = (uint64_t)wd_get_dma_from_va(qp->h_ctx, strm->next_in);
		msg->source_addr_l = (uint64_t)addr & 0xffffffff;
		msg->source_addr_h = (uint64_t)addr >> 32;
		addr = (uint64_t)wd_get_dma_from_va(qp->h_ctx, strm->next_out);
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
		if (wd_is_nosva(qp->h_ctx)) {
			addr = (uint64_t)wd_get_dma_from_va(qp->h_ctx,
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

	ret = hisi_qm_send(qp->h_ctx, msg);
	if (ret == -EBUSY) {
		usleep(1);
		goto recv_again;
	}
	if (ret) {
		WD_ERR("send failure (%d)\n", ret);
		goto out;
	}

recv_again:
	ret = hisi_qm_recv(qp->h_ctx, (void **)&recv_msg);
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
			strm->arg->src_len = recv_msg->consumed + strm->skipped;
		} else {
			/* all source data is consumed */
			strm->arg->src_len = recv_msg->consumed + strm->skipped;
		}
		/* after one transaction, always load data to IN buf again */
		strm->loaded_in = 0;
		strm->avail_in = 0;
		if (strm->stream_pos == STREAM_NEW) {
			strm->stream_pos = STREAM_OLD;
			strm->skipped = 0;
		}

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
	struct hisi_qp		*qp;
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0, 0x0,
				    0x0, 0x0, 0x0, 0x0, 0x03};
	int templen, skipped;

	priv = (struct hisi_comp_sess *)sess->priv;
	strm = &priv->strm;
	qp = priv->qp;

	/* reset strm->avail_in */
	if (strm->avail_in < STREAM_MIN) {
		if (wd_is_nosva(qp->h_ctx)) {
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
		if (wd_is_nosva(qp->h_ctx))
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

int hisi_strm_deflate(struct wd_comp_sess *sess, struct wd_comp_strm *strm)
{
	struct wd_comp_arg	*arg = &strm->arg;
	int	ret, src_len;

	src_len = strm->in_sz;
	if (strm->in_sz > STREAM_MAX)
		strm->in_sz = STREAM_MAX;

	/*
	 * Before deflation, in_sz means the size of IN and out_sz means the
	 * size of OUT.
	 * After deflation, in_sz means the size of consumed data in IN and
	 * out_sz means the size of produced data in OUT.
	 */
	ret = hisi_comp_strm_deflate(sess, arg);
	if (ret < 0)
		return ret;
	if (arg->src_len && (arg->src_len < src_len)) {
		arg->status &= ~STATUS_IN_EMPTY;
		arg->status |= STATUS_IN_PART_USE;
	}
	if (arg->status & STATUS_IN_PART_USE)
		src_len = arg->src_len;
	else if (arg->status & STATUS_IN_EMPTY)
		src_len = arg->src_len;
	else
		src_len = 0;
	strm->in += src_len;
	strm->in_sz = src_len;
	if (arg->status & STATUS_OUT_READY) {
		strm->out += arg->dst_len;
		strm->out_sz = arg->dst_len;
		strm->total_out += arg->dst_len;
	}
	return 0;
}

int hisi_strm_inflate(struct wd_comp_sess *sess, struct wd_comp_strm *strm)
{
	struct wd_comp_arg	*arg = &strm->arg;
	int	ret, src_len;

	src_len = strm->in_sz;
	if (strm->in_sz > STREAM_MAX)
		strm->in_sz = STREAM_MAX;

	/*
	 * Before inflation, in_sz means the size of IN and out_sz means the
	 * size of OUT.
	 * After inflation, in_sz means the size of consumed data in IN and
	 * out_sz means the size of produced data in OUT.
	 */
	ret = hisi_comp_strm_inflate(sess, arg);
	if (ret < 0)
		return ret;
	if (arg->src_len && (arg->src_len < src_len)) {
		arg->status &= ~STATUS_IN_EMPTY;
		arg->status |= STATUS_IN_PART_USE;
	}
	if (arg->status & STATUS_IN_PART_USE)
		src_len = arg->src_len;
	else if (arg->status & STATUS_IN_EMPTY)
		src_len = arg->src_len;
	else
		src_len = 0;
	strm->in += src_len;
	strm->in_sz = src_len;
	if (arg->status & STATUS_OUT_READY) {
		strm->out += arg->dst_len;
		strm->out_sz = arg->dst_len;
		strm->total_out += arg->dst_len;
	}
	return 0;
}

/* new code */
int hisi_zip_init(struct wd_ctx_config *config, void *priv)
{
	return 0;
}

void hisi_zip_exit(void *priv)
{}
