/* SPDX-License-Identifier: Apache-2.0 */

#include <numa.h>
#include "uadk_benchmark.h"

#include "hpre_wd_benchmark.h"
#include "hpre_protocol_data.h"
#include "v1/wd.h"
#include "v1/wd_ecc.h"
#include "v1/wd_rsa.h"
#include "v1/wd_dh.h"
#include "v1/wd_bmm.h"
#include "v1/wd_util.h"

#define ECC_CURVE_ID		0x3 /* def set secp256k1 */
#define HPRE_TST_PRT 		printf
#define ERR_OPTYPE		0xFF
#define SM2_DG_SZ		1024
#define SEND_USLEEP		100
#define ALIGN_SIZE		128

static   char rsa_m[8] = {0x54, 0x85, 0x9b, 0x34, 0x2c, 0x49, 0xea, 0x2a};

struct hpre_rsa_key_in {
	void *e;
	void *p;
	void *q;
	u32 e_size;
	u32 p_size;
	u32 q_size;
	void *data[];
};
static __thread struct hpre_rsa_key_in *rsa_key_in = NULL;

struct rsa_async_tag {
	void *ctx;
	int cnt;
	int optype;
};

//----------------------------------RSA param--------------------------------------//
struct hpre_dh_param {
	const void *x;
	const void *p;
	const void *g;
	const void *except_pub_key;
	const void *pub_key;
	const void *share_key;
	void *pool;
	u32 x_size;
	u32 p_size;
	u32 g_size;
	u32 pub_key_size;
	u32 share_key_size;
	u32 except_pub_key_size;
	u32 key_bits;
	u32 optype;
};

//----------------------------------DH param-------------------------------------//
struct hpre_ecc_setup {
	void *except_pub_key; // use in ecdh phase 2
	const void *pub_key; // use in ecdh phase 1
	const void *share_key; // use in ecdh phase 2
	const void *degist; //ecdsa sign in
	const void *k; //ecdsa sign in
	const void *rp; //ecdsa sign in
	const void *sign; // ecdsa sign out or verf in
	const void *priv_key; // use in ecdsa sign
	void *msg; // sm2 plaintext,ciphertext or digest input
	const void *userid; // sm2 user id
	const void *ciphertext; // sm2 ciphertext
	const void *plaintext; // sm2 plaintext
	u32 key_size;
	u32 share_key_size;
	u32 except_pub_key_size;
	u32 degist_size;
	u32 k_size;
	u32 rp_size;
	u32 sign_size;
	u32 priv_key_size;
	u32 pub_key_size;
	u32 msg_size;
	u32 userid_size;
	u32 ciphertext_size;
	u32 plaintext_size;
	u32 op_type;
	u32 key_bits;
	u32 nid;
	u32 curve_id; // WD ecc curve_id
};

//----------------------------------ECC param-------------------------------------//
struct thread_bd_res {
	struct wd_queue *queue;
	void *pool;
};

struct thread_queue_res {
	struct thread_bd_res *bd_res;
};

typedef struct uadk_thread_res {
	u32 subtype;
	u32 keybits;
	u32 kmode;
	u32 optype;
	u32 td_id;
} thread_data;

static unsigned int g_thread_num;
static struct thread_queue_res g_thread_queue;

static const char* const alg_operations[] = {
	"GenKey", "ShareKey", "Encrypt", "Decrypt", "Sign", "Verify",
};

static void get_rsa_param(u32 algtype, u32 *keysize, u32 *mode)
{
	switch(algtype) {
	case RSA_1024:
		*keysize = 1024;
		*mode = 0;
		break;
	case RSA_2048:
		*keysize = 2048;
		*mode = 0;
		break;
	case RSA_3072:
		*keysize = 3072;
		*mode = 0;
		break;
	case RSA_4096:
		*keysize = 4096;
		*mode = 0;
		break;
	case RSA_1024_CRT:
		*keysize = 1024;
		*mode = 1;
		break;
	case RSA_2048_CRT:
		*keysize = 2048;
		*mode = 1;
		break;
	case RSA_3072_CRT:
		*keysize = 3072;
		*mode = 1;
		break;
	case RSA_4096_CRT:
		*keysize = 4096;
		*mode = 1;
		break;
	}
}

static u32 get_rsa_optype(u32 optype)
{
	u32 op_type = 0;

	switch(optype) {
	case 0:	//GENKEY1
		op_type = WCRYPTO_RSA_GENKEY;
		break;
	case 4: //Sign
		op_type = WCRYPTO_RSA_SIGN;
		break;
	case 5: //Verf
		op_type = WCRYPTO_RSA_VERIFY;
		break;
	default:
		HPRE_TST_PRT("failed to set rsa op_type\n");
		HPRE_TST_PRT("RSA Gen:  0\n");
		HPRE_TST_PRT("RSA Sign: 4\n");
		HPRE_TST_PRT("RSA Verf: 5\n");
		return ERR_OPTYPE;
	}

	return op_type;
}

static void get_dh_param(u32 algtype, u32 *keysize)
{
	switch(algtype) {
	case DH_768:
		*keysize = 768;
		break;
	case DH_1024:
		*keysize = 1024;
		break;
	case DH_1536:
		*keysize = 1536;
		break;
	case DH_2048:
		*keysize = 2048;
		break;
	case DH_3072:
		*keysize = 3072;
		break;
	case DH_4096:
		*keysize = 4096;
		break;
	}
}

static u32 get_dh_optype(u32 optype)
{
	u32 op_type = 0;

	switch(optype) {
	case 0:	//GENKEY1
		op_type = WCRYPTO_DH_PHASE1;
		break;
	case 1: //GENKEY12
		op_type = WCRYPTO_DH_PHASE2;
		break;
	default:
		HPRE_TST_PRT("failed to set dh op_type\n");
		HPRE_TST_PRT("DH Gen1: 0\n");
		HPRE_TST_PRT("DH Gen2: 1\n");
		return ERR_OPTYPE;
	}

	return op_type;
}

static void get_ecc_param(u32 algtype, u32 *keysize)
{
	switch(algtype) {
	case ECDH_256:
		*keysize = 256;
		break;
	case ECDH_384:
		*keysize = 384;
		break;
	case ECDH_521:
		*keysize = 521;
		break;
	case ECDSA_256:
		*keysize = 256;
		break;
	case ECDSA_384:
		*keysize = 384;
		break;
	case ECDSA_521:
		*keysize = 521;
		break;
	case SM2_ALG:
		*keysize = 256;
		break;
	case X25519_ALG:
		*keysize = 256;
		break;
	case X448_ALG:
		*keysize = 448;
		break;
	}
}

static u32 get_ecc_optype(u32 subtype, u32 optype)
{
	u32 op_type = 0;

	if (subtype == SM2_TYPE) {
		switch (optype) {
		case 0:
			op_type = WCRYPTO_SM2_KG;
			break;
		case 2:
			op_type = WCRYPTO_SM2_ENCRYPT;
			break;
		case 3:
			op_type = WCRYPTO_SM2_DECRYPT;
			break;
		case 4:
			op_type = WCRYPTO_SM2_SIGN;
			break;
		case 5:
			op_type = WCRYPTO_SM2_VERIFY;
			break;
		default:
			HPRE_TST_PRT("failed to set SM2 op_type\n");
			HPRE_TST_PRT("SM2 KeyGen:  0\n");
			HPRE_TST_PRT("SM2 Encrypt: 2\n");
			HPRE_TST_PRT("SM2 Decrypt: 3\n");
			HPRE_TST_PRT("SM2 Sign:    4\n");
			HPRE_TST_PRT("SM2 Verify:  5\n");
			return ERR_OPTYPE;
		}
	} else if (subtype == ECDH_TYPE ||
	    subtype == X25519_TYPE || subtype == X448_TYPE) {
		switch(optype) {
		case 0:	//GENKEY
			op_type = WCRYPTO_ECXDH_GEN_KEY;
			break;
		case 1: //COMPUTEKEY
			op_type = WCRYPTO_ECXDH_COMPUTE_KEY;
			break;
		default:
			HPRE_TST_PRT("failed to set ECDH op_type\n");
			HPRE_TST_PRT("ECDH GenKey:   0\n");
			HPRE_TST_PRT("ECDH ShareKey: 1\n");
			return ERR_OPTYPE;
		}
	}  else if (subtype == ECDSA_TYPE) {
		switch(optype) {
		case 4:	//Sign
			op_type = WCRYPTO_ECDSA_SIGN;
			break;
		case 5: //Verf
			op_type = WCRYPTO_ECDSA_VERIFY;
			break;
		default:
			HPRE_TST_PRT("failed to set ECDSA op_type\n");
			HPRE_TST_PRT("ECDSA Sign: 4\n");
			HPRE_TST_PRT("ECDSA Verf: 5\n");
			return ERR_OPTYPE;
		}
	}

	return op_type;
}

static int hpre_wd_param_parse(thread_data *tddata, struct acc_option *options)
{
	u32 algtype = options->algtype;
	u32 optype = 0;
	u32 keysize = 0;
	u32 mode = 0;

	if (algtype >= RSA_1024 && algtype <= RSA_4096_CRT) {
		get_rsa_param(algtype, &keysize, &mode);
		optype = get_rsa_optype(options->optype);
	} else if (algtype <= DH_4096) {
		get_dh_param(algtype, &keysize);
		optype = get_dh_optype(options->optype);
	} else if (algtype <= X448_ALG) {
		get_ecc_param(algtype, &keysize);
		optype = get_ecc_optype(options->subtype, options->optype);
	} else {
		HPRE_TST_PRT("failed to set hpre alg!\n");
		return -EINVAL;
	}

	if (optype == ERR_OPTYPE)
		return -EINVAL;

	/* HPRE package   length is keybits */
	options->pktlen = keysize >> 3;
	tddata->keybits = keysize;
	tddata->kmode = mode;
	tddata->optype = optype;

	HPRE_TST_PRT("%s to run %s task!\n", options->algclass,
			alg_operations[options->optype]);

	return 0;
}

static int hpre_wd_get_block(u32 algtype)
{
	int block_size = 512;

	switch(algtype) {
	case RSA_1024:
		block_size = 1280;
		break;
	case RSA_2048:
		block_size = 2560;
		break;
	case RSA_3072:
		block_size = 3840;
		break;
	case RSA_4096:
		block_size = 5120;
		break;
	case RSA_1024_CRT:
		block_size = 1280;
		break;
	case RSA_2048_CRT:
		block_size = 2560;
		break;
	case RSA_3072_CRT:
		block_size = 3840;
		break;
	case RSA_4096_CRT:
		block_size = 5120;
		break;
	case DH_768:
		block_size = 1536;
		break;
	case DH_1024:
		block_size = 2048;
		break;
	case DH_1536:
		block_size = 3072;
		break;
	case DH_2048:
		block_size = 4096;
		break;
	case DH_3072:
		block_size = 6144;
		break;
	case DH_4096:
		block_size = 8192;
		break;
	case ECDH_256:
		block_size = 256;
		break;
	case ECDH_384:
		block_size = 384;
		break;
	case ECDH_521:
		block_size = 576;
		break;
	case ECDSA_256:
		block_size = 256;
		break;
	case ECDSA_384:
		block_size = 384;
		break;
	case ECDSA_521:
		block_size = 576;
		break;
	case SM2_ALG:
		block_size = 4352;
		break;
	case X25519_ALG:
		block_size = 256;
		break;
	case X448_ALG:
		block_size = 384;
		break;
	}

	return block_size;
}

static int init_hpre_wd_queue(struct acc_option *options)
{
	u32 blocksize = hpre_wd_get_block(options->algtype);
	struct wd_blkpool_setup blksetup;
	int i, j,   ret;

	g_thread_queue.bd_res = malloc(g_thread_num * sizeof(struct thread_bd_res));
	if (!g_thread_queue.bd_res) {
		HPRE_TST_PRT("malloc thread res memory fail!\n");
		return -ENOMEM;
	}

	for (i = 0; i < g_thread_num; i++) {
		g_thread_queue.bd_res[i].queue = malloc(sizeof(struct wd_queue));
		g_thread_queue.bd_res[i].queue->capa.alg = options->algclass;
		// 0 is ENC, 1 is DEC
		g_thread_queue.bd_res[i].queue->capa.priv.direction = options->optype;
		/* nodemask need to    be clean */
		g_thread_queue.bd_res[i].queue->node_mask = 0x0;
		memset(g_thread_queue.bd_res[i].queue->dev_path, 0x0, PATH_STR_SIZE);

		ret = wd_request_queue(g_thread_queue.bd_res[i].queue);
		if (ret) {
			HPRE_TST_PRT("request queue %d fail!\n", i);
			goto queue_out;
		}
	}

	// use no-sva pbuffer, MAX_BLOCK_NM at least 4 times of thread inside alloc
	memset(&blksetup, 0, sizeof(blksetup));
	blksetup.block_size = blocksize;
	blksetup.block_num = MAX_BLOCK_NM;
	blksetup.align_size = ALIGN_SIZE;
	// HPRE_TST_PRT("create pool memory: %d KB\n", (MAX_BLOCK_NM * blksetup.block_size) >> 10);

	for (j = 0; j < g_thread_num; j++) {
		g_thread_queue.bd_res[j].pool = wd_blkpool_create(g_thread_queue.bd_res[j].queue, &blksetup);
		if (!g_thread_queue.bd_res[j].pool) {
			HPRE_TST_PRT("create %dth pool fail!\n", j);
			ret = -ENOMEM;
			goto pool_err;
		}
	}

	return 0;

pool_err:
	for (j--; j >= 0; j--)
		wd_blkpool_destroy(g_thread_queue.bd_res[j].pool);
queue_out:
	for (i--; i >= 0; i--) {
		wd_release_queue(g_thread_queue.bd_res[i].queue);
		free(g_thread_queue.bd_res[i].queue);
	}
	free(g_thread_queue.bd_res);
	return ret;
}

static void uninit_hpre_wd_queue(void)
{
	int j;

	for (j = 0; j < g_thread_num; j++) {
		wd_blkpool_destroy(g_thread_queue.bd_res[j].pool);
		wd_release_queue(g_thread_queue.bd_res[j].queue);
	}

	free(g_thread_queue.bd_res);
}

/*-------------------------------uadk benchmark main code-------------------------------------*/

void *hpre_wd_poll(void *data)
{
	typedef int (*poll_ctx)(struct wd_queue *q, unsigned int num);
	thread_data *pdata = (thread_data *)data;
	u32 expt = ACC_QUEUE_SIZE * g_thread_num;
	poll_ctx wd_poll_ctx = NULL;
	struct wd_queue *queue;
	u32 id = pdata->td_id;
	u32 last_time = 2; // poll need one more recv time
	u32 count = 0;
	int recv = 0;

	if (id > g_thread_num)
		return NULL;

	queue = g_thread_queue.bd_res[id].queue;
	switch(pdata->subtype) {
	case RSA_TYPE:
		wd_poll_ctx = wcrypto_rsa_poll;
		break;
	case DH_TYPE:
		wd_poll_ctx = wcrypto_dh_poll;
		break;
	case ECDH_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		wd_poll_ctx = wcrypto_ecxdh_poll;
		break;
	case ECDSA_TYPE:
		wd_poll_ctx = wcrypto_ecdsa_poll;
		break;
	case SM2_TYPE:
		wd_poll_ctx = wcrypto_sm2_poll;
		break;
	default:
		HPRE_TST_PRT("wd async poll interface is NULL!\n");
		return NULL;
	}

	while (last_time) {
		recv = wd_poll_ctx(queue, expt);
		/*
		 * async mode poll easy to 100% with small package.
		 * SEC_TST_PRT("poll %d recv: %u!\n", i, recv);
		 */

		if (unlikely(recv < 0)) {
			HPRE_TST_PRT("poll ret: %u!\n", recv);
			goto recv_error;
		}
		count += recv;
		recv = 0;

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count, pdata->keybits >> 3);

	return NULL;
}

static int get_rsa_key_from_sample(void *ctx, char *privkey_file,
	char *crt_privkey_file, u32 key_bits, u32 is_crt)
{
	struct wd_dtb wd_e, wd_d, wd_n, wd_dq, wd_dp, wd_qinv, wd_q, wd_p;
	int e_bytes, d_bytes, n_bytes, q_bytes, p_bytes, qinv_bytes;
	u8 *p, *q, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	int dq_bytes, dp_bytes, bits, wd_lenth;
	u32 key_size = key_bits >> 3;
	char *wd_mem;
	int ret = 0;

	memset(&wd_e, 0, sizeof(wd_e));
	memset(&wd_d, 0, sizeof(wd_d));
	memset(&wd_n, 0, sizeof(wd_n));
	memset(&wd_dq, 0, sizeof(wd_dq));
	memset(&wd_dp, 0, sizeof(wd_dp));
	memset(&wd_qinv, 0, sizeof(wd_qinv));
	memset(&wd_q, 0, sizeof(wd_q));
	memset(&wd_p, 0, sizeof(wd_p));

	bits = wcrypto_rsa_key_bits(ctx);
	switch (bits) {
	case 1024:
		e = rsa_e_1024;
		n = rsa_n_1024;
		p = rsa_p_1024;
		q = rsa_q_1024;
		dmp1 = rsa_dp_1024;
		dmq1 = rsa_dq_1024;
		iqmp = rsa_qinv_1024;
		d = rsa_d_1024;
		e_bytes = ARRAY_SIZE(rsa_e_1024);
		n_bytes = ARRAY_SIZE(rsa_n_1024);
		q_bytes = ARRAY_SIZE(rsa_q_1024);
		p_bytes = ARRAY_SIZE(rsa_p_1024);
		dq_bytes = ARRAY_SIZE(rsa_dq_1024);
		dp_bytes = ARRAY_SIZE(rsa_dp_1024);
		qinv_bytes = ARRAY_SIZE(rsa_qinv_1024);
		d_bytes = ARRAY_SIZE(rsa_d_1024);
		break;
	case 2048:
		e = rsa_e_2048;
		n = rsa_n_2048;
		p = rsa_p_2048;
		q = rsa_q_2048;
		dmp1 = rsa_dp_2048;
		dmq1 = rsa_dq_2048;
		iqmp = rsa_qinv_2048;
		d = rsa_d_2048;
		e_bytes = ARRAY_SIZE(rsa_e_2048);
		n_bytes = ARRAY_SIZE(rsa_n_2048);
		q_bytes = ARRAY_SIZE(rsa_q_2048);
		p_bytes = ARRAY_SIZE(rsa_p_2048);
		dq_bytes = ARRAY_SIZE(rsa_dq_2048);
		dp_bytes = ARRAY_SIZE(rsa_dp_2048);
		qinv_bytes = ARRAY_SIZE(rsa_qinv_2048);
		d_bytes = ARRAY_SIZE(rsa_d_2048);
		break;
	case 3072:
		e = rsa_e_3072;
		n = rsa_n_3072;
		p = rsa_p_3072;
		q = rsa_q_3072;
		dmp1 = rsa_dp_3072;
		dmq1 = rsa_dq_3072;
		iqmp = rsa_qinv_3072;
		d = rsa_d_3072;
		e_bytes = ARRAY_SIZE(rsa_e_3072);
		n_bytes = ARRAY_SIZE(rsa_n_3072);
		q_bytes = ARRAY_SIZE(rsa_q_3072);
		p_bytes = ARRAY_SIZE(rsa_p_3072);
		dq_bytes = ARRAY_SIZE(rsa_dq_3072);
		dp_bytes = ARRAY_SIZE(rsa_dp_3072);
		qinv_bytes = ARRAY_SIZE(rsa_qinv_3072);
		d_bytes = ARRAY_SIZE(rsa_d_3072);
		break;
	case 4096:
		e = rsa_e_4096;
		n = rsa_n_4096;
		p = rsa_p_4096;
		q = rsa_q_4096;
		dmp1 = rsa_dp_4096;
		dmq1 = rsa_dq_4096;
		iqmp = rsa_qinv_4096;
		d = rsa_d_4096;
		e_bytes = ARRAY_SIZE(rsa_e_4096);
		n_bytes = ARRAY_SIZE(rsa_n_4096);
		q_bytes = ARRAY_SIZE(rsa_q_4096);
		p_bytes = ARRAY_SIZE(rsa_p_4096);
		dq_bytes = ARRAY_SIZE(rsa_dq_4096);
		dp_bytes = ARRAY_SIZE(rsa_dp_4096);
		qinv_bytes = ARRAY_SIZE(rsa_qinv_4096);
		d_bytes = ARRAY_SIZE(rsa_d_4096);
		break;
	default:
		HPRE_TST_PRT("invalid key bits = %d!\n", bits);
		return -EINVAL;
	}

	wd_lenth = e_bytes + n_bytes + q_bytes + p_bytes  + dq_bytes +
		     dp_bytes + qinv_bytes + d_bytes;
	wd_mem = malloc(wd_lenth);
	if (!wd_mem) {
		HPRE_TST_PRT("failed to alloc rsa key memory!\n");
		return -EINVAL;
	}

	wd_e.data = wd_mem;
	wd_n.data = wd_e.data + e_bytes;

	memcpy(wd_e.data, e, e_bytes);
	wd_e.dsize = e_bytes;
	memcpy(wd_n.data, n, n_bytes);
	wd_n.dsize = n_bytes;
	if (wcrypto_set_rsa_pubkey_params(ctx, &wd_e, &wd_n)) {
		HPRE_TST_PRT("failed to set rsa pubkey!\n");
		ret = -EINVAL;
		goto gen_fail;
	}

	if (rsa_key_in) {
		memcpy(rsa_key_in->e, e, e_bytes);
		memcpy(rsa_key_in->p, p, p_bytes);
		memcpy(rsa_key_in->q, q, q_bytes);
		rsa_key_in->e_size = e_bytes;
		rsa_key_in->p_size = p_bytes;
		rsa_key_in->q_size = q_bytes;
	}

	if (is_crt) {
		wd_q.data = wd_n.data + n_bytes;
		wd_p.data = wd_q.data + q_bytes;
		wd_dq.data = wd_p.data + p_bytes;
		wd_dp.data = wd_dq.data + dq_bytes;
		wd_qinv.data = wd_dp.data + dp_bytes;

		/* CRT mode private key */
		wd_dq.dsize = dq_bytes;
		memcpy(wd_dq.data, dmq1, dq_bytes);

		wd_dp.dsize = dp_bytes;
		memcpy(wd_dp.data, dmp1, dp_bytes);

		wd_q.dsize = q_bytes;
		memcpy(wd_q.data, q, q_bytes);

		wd_p.dsize = p_bytes;
		memcpy(wd_p.data, p, p_bytes);

		wd_qinv.dsize = qinv_bytes;
		memcpy(wd_qinv.data, iqmp, qinv_bytes);

		if (wcrypto_set_rsa_crt_prikey_params(ctx, &wd_dq,
					&wd_dp, &wd_qinv,
					&wd_q, &wd_p)) {
			HPRE_TST_PRT("failed to set rsa crt prikey!\n");
			ret = -EINVAL;
			goto gen_fail;
		}


		if (crt_privkey_file) {
			memcpy(crt_privkey_file, wd_dq.data, (key_bits >> 4) * 5);
			memcpy(crt_privkey_file + (key_bits >> 4) * 5,
				   wd_e.data, (key_bits >> 2));
		}

	} else {
		//wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
		wd_d.data = wd_mem + (wd_lenth - d_bytes);

		/* common mode private key */
		wd_d.dsize = d_bytes;
		memcpy(wd_d.data, d, d_bytes);

		if (wcrypto_set_rsa_prikey_params(ctx, &wd_d, &wd_n)) {
			HPRE_TST_PRT("failed to set rsa prikey!\n");
			ret = -EINVAL;
			goto gen_fail;
		}

		if (privkey_file) {
			memcpy(privkey_file, wd_d.data, key_size);
			memcpy(privkey_file + key_size, wd_n.data, key_size);
			memcpy(privkey_file + 2 * key_size, wd_e.data, key_size);
                        memcpy(privkey_file + 3 * key_size, wd_n.data, key_size);
		}
	}

gen_fail:
	free(wd_mem);

	return ret;
}

static int get_hpre_keygen_opdata(void *ctx,
	struct wcrypto_rsa_op_data *opdata)
{
	struct wcrypto_rsa_pubkey *pubkey;
	struct wcrypto_rsa_prikey *prikey;
	struct wd_dtb t_e, t_p, t_q;
	struct wd_dtb *e, *p, *q;

	wcrypto_get_rsa_pubkey(ctx, &pubkey);
	wcrypto_get_rsa_pubkey_params(pubkey, &e, NULL);
	wcrypto_get_rsa_prikey(ctx, &prikey);

	if (wcrypto_rsa_is_crt(ctx)) {
		wcrypto_get_rsa_crt_prikey_params(prikey, NULL , NULL, NULL, &q, &p);
	} else {
		e = &t_e;
		p = &t_p;
		q = &t_q;
		e->data = rsa_key_in->e;
		e->dsize = rsa_key_in->e_size;
		p->data = rsa_key_in->p;
		p->dsize = rsa_key_in->p_size;
		q->data = rsa_key_in->q;
		q->dsize = rsa_key_in->q_size;
	}

	opdata->in = wcrypto_new_kg_in(ctx, e, p, q);
	if (!opdata->in) {
		HPRE_TST_PRT("failed to create rsa kgen in!\n");
		return -ENOMEM;
	}
	opdata->out = wcrypto_new_kg_out(ctx);
	if (!opdata->out) {
		HPRE_TST_PRT("failed to create rsa kgen out!\n");
		wcrypto_del_kg_in(ctx, opdata->in);
		return -ENOMEM;
	}

	return 0;
}

static void *rsa_wd_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wcrypto_rsa_ctx_setup setup;
	struct wcrypto_rsa_op_data opdata;
	struct wd_queue *queue;
	void *key_info = NULL;
	void *ctx = NULL;
	void *tag = NULL;
	void *pool;
	u32 count = 0;
	int  ret;

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	pool = g_thread_queue.bd_res[pdata->td_id].pool;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;

	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pool;
	setup.key_bits = pdata->keybits;
	setup.is_crt = pdata->kmode;

	ctx = wcrypto_create_rsa_ctx(queue, &setup);
	if (!ctx)
		return NULL;

	key_info = malloc(key_size * 16);
	if (!key_info) {
		HPRE_TST_PRT("failed to alloc RSA key info!\n");
		return NULL;
	}
	memset(key_info, 0, key_size * 16);

	rsa_key_in = malloc(2 * key_size + sizeof(struct hpre_rsa_key_in));
	if (!rsa_key_in) {
		HPRE_TST_PRT("failed to alloc RSA key input param!\n");
		goto key_release;
	}
	rsa_key_in->e = rsa_key_in + 1;
	rsa_key_in->p = rsa_key_in->e + key_size;
	rsa_key_in->q = rsa_key_in->p + (key_size >> 1);

	ret = get_rsa_key_from_sample(ctx, key_info, key_info,
					pdata->keybits, pdata->kmode);
	if (ret) {
		HPRE_TST_PRT("failed to get sample key data!\n");
		goto sample_release;
	}

	opdata.in_bytes = key_size;
	opdata.out_bytes = key_size;
	opdata.op_type = pdata->optype;
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		ret = get_hpre_keygen_opdata(ctx, &opdata);
		if (ret){
			HPRE_TST_PRT("failed to fill rsa key gen req!\n");
			goto sample_release;
		}
	} else {
		opdata.in = wd_alloc_blk(pool);
		if (!opdata.in) {
			HPRE_TST_PRT("failed to alloc rsa in buffer!\n");
			goto sample_release;
		}
		memset(opdata.in, 0, opdata.in_bytes);
		memcpy(opdata.in + key_size - sizeof(rsa_m), rsa_m, sizeof(rsa_m));

		opdata.out = wd_alloc_blk(pool);
		if (!opdata.out) {
			HPRE_TST_PRT("failed to alloc rsa out buffer!\n");
			goto in_release;
		}
	}

	do {
		ret = wcrypto_do_rsa(ctx, &opdata, tag);
		if (ret || opdata.status) {
			HPRE_TST_PRT("failed to do rsa task, status: %d\n", opdata.status);
			goto out_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while(true);

	/* clean output buffer remainings in the last time operation */
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		char *data;
		int len;

		len = wcrypto_rsa_kg_out_data((void *)opdata.out, &data);
		if (len < 0) {
			HPRE_TST_PRT("failed to wd rsa get key gen out data!\n");
			goto out_release;
		}
		memset(data, 0, len);

		wcrypto_del_kg_in(ctx, opdata.in);
		opdata.in = NULL;
		wcrypto_del_kg_out(ctx, opdata.out);
		opdata.out = NULL;
	}

out_release:
	if (opdata.out)
		wd_free_blk(pool, opdata.out);
in_release:
	if (opdata.in)
		wd_free_blk(pool, opdata.in);
sample_release:
	free(rsa_key_in);
key_release:
	free(key_info);

	wcrypto_del_rsa_ctx(ctx);
	add_recv_data(count, key_size);

	return NULL;
}

static void rsa_async_cb(const void *msg, void *tag)
{
	//struct wcrypto_rsa_msg *massage = msg;
	//struct rsa_async_tag *ptag = tag;
	//u32 op_type = tag->op_type;
	//void *ctx = tag->ctx;

	return;
}

static void *rsa_wd_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wcrypto_rsa_ctx_setup setup;
	struct wcrypto_rsa_op_data opdata;
	struct rsa_async_tag *tag = NULL;
	struct wd_queue *queue;
	void *key_info = NULL;
	void *ctx = NULL;
	int try_cnt = 0;
	void *pool;
	u32 count = 0;
	int i,  ret;

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	pool = g_thread_queue.bd_res[pdata->td_id].pool;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;

	setup.cb = (void *)rsa_async_cb;
	setup.br.alloc = (void *)wd_alloc_blk;
	setup.br.free = (void *)wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	setup.br.get_bufsize = (void *)wd_blksize;
	setup.br.usr = pool;
	setup.key_bits = pdata->keybits;
	setup.is_crt = pdata->kmode;

	ctx = wcrypto_create_rsa_ctx(queue, &setup);
	if (!ctx)
		return NULL;

	key_info = malloc(key_size * 16);
	if (!key_info) {
		HPRE_TST_PRT("failed to alloc RSA key info!\n");
		return NULL;
	}
	memset(key_info, 0, key_size * 16);

	rsa_key_in = malloc(2 * key_size + sizeof(struct hpre_rsa_key_in));
	if (!rsa_key_in) {
		HPRE_TST_PRT("failed to alloc RSA key input param!\n");
		goto key_release;
	}
	rsa_key_in->e = rsa_key_in + 1;
	rsa_key_in->p = rsa_key_in->e + key_size;
	rsa_key_in->q = rsa_key_in->p + (key_size >> 1);

	ret = get_rsa_key_from_sample(ctx,	key_info, key_info,
					pdata->keybits, pdata->kmode);
	if (ret) {
		HPRE_TST_PRT("failed to get sample key data!\n");
		goto sample_release;
	}

	opdata.in_bytes = key_size;
	opdata.out_bytes = key_size;
	opdata.op_type = pdata->optype;
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		ret = get_hpre_keygen_opdata(ctx, &opdata);
		if (ret){
			HPRE_TST_PRT("failed to fill rsa key gen req!\n");
			goto sample_release;
		}
	} else {
		opdata.in = wd_alloc_blk(pool);
		if (!opdata.in) {
			HPRE_TST_PRT("failed to alloc rsa in buffer!\n");
			goto sample_release;
		}
		memset(opdata.in, 0, opdata.in_bytes);
		memcpy(opdata.in + key_size - sizeof(rsa_m), rsa_m, sizeof(rsa_m));

		opdata.out = wd_alloc_blk(pool);
		if (!opdata.out) {
			HPRE_TST_PRT("failed to alloc rsa out buffer!\n");
			goto in_release;
		}
	}

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		HPRE_TST_PRT("failed to malloc rsa tag!\n");
		goto out_release;
	}

	do {
		if (get_run_state() == 0)
			break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		tag[i].ctx = ctx;
		tag[i].cnt = i;
		tag[i].optype = opdata.op_type;

		ret = wcrypto_do_rsa(ctx, &opdata, &tag[i]);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				HPRE_TST_PRT("Test RSA send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret) {
			HPRE_TST_PRT("failed to do rsa async task!\n");
			goto tag_release;
		}
		count++;
	} while(true);

	/* clean output buffer remainings in the last time operation */
	if (opdata.op_type == WCRYPTO_RSA_GENKEY) {
		char *data;
		int len;

		len = wcrypto_rsa_kg_out_data((void *)opdata.out, &data);
		if (len < 0) {
			HPRE_TST_PRT("failed to wd rsa get key gen out data!\n");
			goto out_release;
		}
		memset(data, 0, len);

		wcrypto_del_kg_in(ctx, opdata.in);
		opdata.in = NULL;
		wcrypto_del_kg_out(ctx, opdata.out);
		opdata.out = NULL;
	}

tag_release:
	free(tag);
out_release:
	if (opdata.out)
		wd_free_blk(pool, opdata.out);
in_release:
	if (opdata.in)
		wd_free_blk(pool, opdata.in);
sample_release:
	free(rsa_key_in);
key_release:
	free(key_info);

	while (1) {
		if (get_recv_time() > 0) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}
	wcrypto_del_rsa_ctx(ctx);

	add_send_complete();

	return NULL;
}

static int get_dh_param_from_sample(struct hpre_dh_param *setup,
	u32 key_bits, u8 is_g2)
{
	setup->key_bits = key_bits;

	switch (key_bits) {
	case 768:
		setup->x = dh_xa_768;
		setup->p = dh_p_768;
		setup->except_pub_key = dh_except_b_pubkey_768;
		setup->pub_key = dh_except_a_pubkey_768;
		setup->share_key = dh_share_key_768;
		setup->x_size = sizeof(dh_xa_768);
		setup->p_size = sizeof(dh_p_768);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_768);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_768);
		setup->share_key_size = sizeof(dh_share_key_768);
		break;
	case 1024:
		setup->x = dh_xa_1024;
		setup->p = dh_p_1024;
		setup->except_pub_key = dh_except_b_pubkey_1024;
		setup->pub_key = dh_except_a_pubkey_1024;
		setup->share_key = dh_share_key_1024;
		setup->x_size = sizeof(dh_xa_1024);
		setup->p_size = sizeof(dh_p_1024);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_1024);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_1024);
		setup->share_key_size = sizeof(dh_share_key_1024);
		break;
	case 1536:
		setup->x = dh_xa_1536;
		setup->p = dh_p_1536;
		setup->except_pub_key = dh_except_b_pubkey_1536;
		setup->pub_key = dh_except_a_pubkey_1536;
		setup->share_key = dh_share_key_1536;
		setup->x_size = sizeof(dh_xa_1536);
		setup->p_size = sizeof(dh_p_1536);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_1536);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_1536);
		setup->share_key_size = sizeof(dh_share_key_1536);
		break;
	case 2048:
		setup->x = dh_xa_2048;
		setup->p = dh_p_2048;
		setup->except_pub_key = dh_except_b_pubkey_2048;
		setup->pub_key = dh_except_a_pubkey_2048;
		setup->share_key = dh_share_key_2048;
		setup->x_size = sizeof(dh_xa_2048);
		setup->p_size = sizeof(dh_p_2048);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_2048);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_2048);
		setup->share_key_size = sizeof(dh_share_key_2048);
		break;
	case 3072:
		setup->x = dh_xa_3072;
		setup->p = dh_p_3072;
		setup->except_pub_key = dh_except_b_pubkey_3072;
		setup->pub_key = dh_except_a_pubkey_3072;
		setup->share_key = dh_share_key_3072;
		setup->x_size = sizeof(dh_xa_3072);
		setup->p_size = sizeof(dh_p_3072);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_3072);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_3072);
		setup->share_key_size = sizeof(dh_share_key_3072);
		break;
	case 4096:
		setup->x = dh_xa_4096;
		setup->p = dh_p_4096;
		setup->except_pub_key = dh_except_b_pubkey_4096;
		setup->pub_key = dh_except_a_pubkey_4096;
		setup->share_key = dh_share_key_4096;
		setup->x_size = sizeof(dh_xa_4096);
		setup->p_size = sizeof(dh_p_4096);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_4096);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_4096);
		setup->share_key_size = sizeof(dh_share_key_4096);
		break;
	default:
		HPRE_TST_PRT("failed to find dh keybits %u\n", key_bits);
		return -EINVAL;
	}

	if (is_g2) {
		setup->g = dh_g_2;
	} else {
		setup->g = dh_g_5;
	}
	setup->g_size = 1;

	return 0;
}

static int get_dh_opdata_param(void *ctx, struct wcrypto_dh_op_data *opdata,
	struct hpre_dh_param *setup, int key_size)
{
	unsigned char *ag_bin = NULL;
	void *pool = setup->pool;
	struct wd_dtb ctx_g;
	int ret;

	ag_bin = wd_alloc_blk(pool);
	if (!ag_bin)
		return -ENOMEM;

	memset(ag_bin, 0, 2 * key_size);
	opdata->pv = ag_bin;

	opdata->x_p = wd_alloc_blk(pool);
	if (!opdata->x_p)
		goto ag_error;

	memset(opdata->x_p, 0, 2 * key_size);

	opdata->pri = wd_alloc_blk(pool);
	if (!opdata->pri)
		goto xp_error;

	memset(opdata->pri, 0, 2 * key_size);
	opdata->pri_bytes = 2 * key_size;

	ctx_g.data = malloc(key_size);
	if (!ctx_g.data)
		goto ctx_release;

	if (setup->optype == WCRYPTO_DH_PHASE1) { // GEN1
		memcpy(opdata->x_p, setup->x, setup->x_size);
		memcpy(opdata->x_p + key_size, setup->p, setup->p_size);
		memcpy(ctx_g.data, setup->g, setup->g_size);
		opdata->pbytes = setup->p_size;
		opdata->xbytes = setup->x_size;
		ctx_g.dsize = setup->g_size;
		ctx_g.bsize = key_size;

		ret = wcrypto_set_dh_g(ctx, &ctx_g);
		if (ret)
			HPRE_TST_PRT("wd_dh_set_g run failed\n");
	} else { // GEN1
		memcpy(opdata->x_p, setup->x, setup->x_size);
		memcpy(opdata->x_p + key_size, setup->p, setup->p_size);
		memcpy(opdata->pv, setup->except_pub_key, setup->except_pub_key_size);
		opdata->pbytes = setup->p_size;
		opdata->xbytes = setup->x_size;
		opdata->pvbytes = setup->except_pub_key_size;
	}

	free(ctx_g.data);

	return 0;

ctx_release:
	wd_free_blk(pool, opdata->pri);
xp_error:
	wd_free_blk(pool, opdata->x_p);
ag_error:
	wd_free_blk(pool, opdata->pv);

	return -ENOMEM;
}

static void *dh_wd_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wcrypto_dh_ctx_setup dh_setup;
	struct wcrypto_dh_op_data opdata;
	struct hpre_dh_param setup;
	struct wd_queue *queue;
	void *ctx = NULL;
	void *tag = NULL;
	void *pool;
	u32 count = 0;
	int  ret;

	memset(&dh_setup, 0, sizeof(dh_setup));
	memset(&opdata, 0, sizeof(opdata));

	pool = g_thread_queue.bd_res[pdata->td_id].pool;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	dh_setup.key_bits = pdata->keybits;
	dh_setup.br.alloc = (void *)wd_alloc_blk;
	dh_setup.br.free = (void *)wd_free_blk;
	dh_setup.br.iova_map = (void *)wd_blk_iova_map;
	dh_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	dh_setup.br.get_bufsize = (void *)wd_blksize;
	dh_setup.br.usr = pool;
	if (pdata->optype == WCRYPTO_DH_PHASE2)
		dh_setup.is_g2 = true; // G1 is 0; G2 is 1;

	ctx = wcrypto_create_dh_ctx(queue, &dh_setup);
	if (!ctx)
		return NULL;

	ret = get_dh_param_from_sample(&setup, pdata->keybits, pdata->kmode);
	if (ret)
		goto ctx_release;

	setup.optype = pdata->optype;
	setup.pool = pool;
	opdata.op_type = pdata->optype;
	ret = get_dh_opdata_param(ctx, &opdata, &setup, key_size);
	if (ret){
		HPRE_TST_PRT("failed to fill dh key gen req!\n");
		goto param_release;
	}

	do {
		ret = wcrypto_do_dh(ctx, &opdata, tag);
		if (ret || opdata.status) {
			HPRE_TST_PRT("failed to do dh task, status: %d\n", opdata.status);
			goto param_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while(true);

param_release:
	wd_free_blk(pool, opdata.x_p);
	wd_free_blk(pool, opdata.pv);
	wd_free_blk(pool, opdata.pri);
ctx_release:
	wcrypto_del_dh_ctx(ctx);
	add_recv_data(count, key_size);

	return NULL;
}

static void dh_async_cb(const void *msg, void *tag)
{
	//struct wcrypto_dh_msg *massage = msg;
	//struct rsa_async_tag *ptag = tag;
	//u32 op_type = tag->op_type;
	//void *ctx = tag->ctx;

	return;
}

static void *dh_wd_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wcrypto_dh_ctx_setup dh_setup;
	struct wcrypto_dh_op_data opdata;
	struct rsa_async_tag *tag = NULL;
	struct hpre_dh_param setup;
	struct wd_queue *queue;
	void *ctx = NULL;
	int try_cnt = 0;
	void *pool;
	u32 count = 0;
	int  i, ret;

	memset(&dh_setup, 0, sizeof(dh_setup));
	memset(&opdata, 0, sizeof(opdata));

	pool = g_thread_queue.bd_res[pdata->td_id].pool;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	dh_setup.key_bits = pdata->keybits;
	dh_setup.br.alloc = (void *)wd_alloc_blk;
	dh_setup.br.free = (void *)wd_free_blk;
	dh_setup.br.iova_map = (void *)wd_blk_iova_map;
	dh_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	dh_setup.br.get_bufsize = (void *)wd_blksize;
	dh_setup.cb = (void *)dh_async_cb;
	dh_setup.br.usr = pool;
	if (pdata->optype == WCRYPTO_DH_PHASE2)
		dh_setup.is_g2 = true; // G1 is 0; G2 is 1;

	ctx = wcrypto_create_dh_ctx(queue, &dh_setup);
	if (!ctx)
		return NULL;

	ret = get_dh_param_from_sample(&setup, pdata->keybits, pdata->kmode);
	if (ret)
		goto ctx_release;

	setup.optype = pdata->optype;
	setup.pool = pool;
	opdata.op_type = pdata->optype;
	ret = get_dh_opdata_param(ctx, &opdata, &setup, key_size);
	if (ret){
		HPRE_TST_PRT("failed to fill dh key gen req!\n");
		goto param_release;
	}

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		HPRE_TST_PRT("failed to malloc dh tag!\n");
		goto param_release;
	}

	do {
		if (get_run_state() == 0)
			break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		tag[i].ctx = ctx;
		tag[i].cnt = i;
		tag[i].optype = opdata.op_type;

		ret = wcrypto_do_dh(ctx, &opdata, &tag[i]);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				HPRE_TST_PRT("Test DH send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret) {
			HPRE_TST_PRT("failed to do rsa async task!\n");
			goto tag_release;
		}

		count++;
	} while(true);

tag_release:
	free(tag);
param_release:
	wd_free_blk(pool, opdata.x_p);
	wd_free_blk(pool, opdata.pv);
	wd_free_blk(pool, opdata.pri);
ctx_release:
	while (1) {
		if (get_recv_time() > 0) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}

	wcrypto_del_dh_ctx(ctx);
	add_send_complete();

	return NULL;
}

static int get_ecc_curve(struct hpre_ecc_setup *setup, u32 cid)
{
	switch (cid) {
	case 0: // secp128R1
		setup->nid = 706;
		setup->curve_id = WCRYPTO_SECP128R1;
		break;
	case 1: // secp192K1
		setup->nid = 711;
		setup->curve_id = WCRYPTO_SECP192K1;
		break;
	case 2: // secp256K1
		setup->nid = 714;
		setup->curve_id = WCRYPTO_SECP256K1;
		break;
	case 3: // brainpoolP320R1
		setup->nid = 929;
		setup->curve_id = WCRYPTO_BRAINPOOLP320R1;
		break;
	case 4: // brainpoolP384R1
		setup->nid = 931;
		setup->curve_id = WCRYPTO_BRAINPOOLP384R1;
		break;
	case 5: // secp521R1
		setup->nid = 716;
		setup->curve_id = WCRYPTO_SECP521R1;
		break;
	default:
		HPRE_TST_PRT("failed to get ecc curve id!\n");
		return -EINVAL;
	}

	return 0;
}

static int    get_ecc_key_param(struct wcrypto_ecc_curve *param, u32 key_bits)
{
	u32 key_size = (key_bits + 7) / 8;

	switch (key_bits) {
	case 128:
		param->a.data = ecdh_a_secp128r1;
		param->b.data = ecdh_b_secp128r1;
		param->p.data = ecdh_p_secp128r1;
		param->n.data = ecdh_n_secp128r1;
		param->g.x.data = ecdh_g_secp128r1;
		param->g.y.data = ecdh_g_secp128r1 + key_size;
	case 192:
		param->a.data = ecdh_a_secp192k1;
		param->b.data = ecdh_b_secp192k1;
		param->p.data = ecdh_p_secp192k1;
		param->n.data = ecdh_n_secp192k1;
		param->g.x.data = ecdh_g_secp192k1;
		param->g.y.data = ecdh_g_secp192k1 + key_size;
	case 224:
		param->a.data = ecdh_a_secp224r1;
		param->b.data = ecdh_b_secp224r1;
		param->p.data = ecdh_p_secp224r1;
		param->n.data = ecdh_n_secp224r1;
		param->g.x.data = ecdh_g_secp224r1;
		param->g.y.data = ecdh_g_secp224r1 + key_size;
	case 256:
		param->a.data = ecdh_a_secp256k1;
		param->b.data = ecdh_b_secp256k1;
		param->p.data = ecdh_p_secp256k1;
		param->n.data = ecdh_n_secp256k1;
		param->g.x.data = ecdh_g_secp256k1;
		param->g.y.data = ecdh_g_secp256k1 + key_size;
	case 320:
		param->a.data = ecdh_a_secp320k1;
		param->b.data = ecdh_b_secp320k1;
		param->p.data = ecdh_p_secp320k1;
		param->n.data = ecdh_n_secp320k1;
		param->g.x.data = ecdh_g_secp320k1;
		param->g.y.data = ecdh_g_secp320k1 + key_size;
	case 384:
		param->a.data = ecdh_a_secp384r1;
		param->b.data = ecdh_b_secp384r1;
		param->p.data = ecdh_p_secp384r1;
		param->n.data = ecdh_n_secp384r1;
		param->g.x.data = ecdh_g_secp384r1;
		param->g.y.data = ecdh_g_secp384r1 + key_size;
	case 521:
		param->a.data = ecdh_a_secp521r1;
		param->b.data = ecdh_b_secp521r1;
		param->p.data = ecdh_p_secp521r1;
		param->n.data = ecdh_n_secp521r1;
		param->g.x.data = ecdh_g_secp521r1;
		param->g.y.data = ecdh_g_secp521r1 + key_size;
	default:
		HPRE_TST_PRT("key_bits %d not find\n", key_bits);
		return -EINVAL;
	}

	param->a.bsize = key_size;
	param->a.dsize = key_size;
	param->b.bsize = key_size;
	param->b.dsize = key_size;
	param->p.bsize = key_size;
	param->p.dsize = key_size;
	param->n.bsize = key_size;
	param->n.dsize = key_size;
	param->g.x.bsize = key_size;
	param->g.x.dsize = key_size;
	param->g.y.bsize = key_size;
	param->g.y.dsize = key_size;

	return 0;
}

static int ecc_get_rand(char *out, size_t out_len, void *usr)
{
	//int ret;

	get_rand_data((u8 *)out, out_len);
	//ret = RAND_priv_bytes((void *)out, out_len);
	//if (ret != 1) {
	//	HPRE_TST_PRT("failed to get ecc rand data:%d\n", ret);
	//	return -EINVAL;
	//}

	return 0;
}

static int ecc_compute_hash(const char *in, size_t in_len,
		       char *out, size_t out_len, void *usr)
{
	/* perf test for none hash check */
	return 0;
}

static int get_ecc_param_from_sample(struct hpre_ecc_setup *setup,
	u32 subtype, u32 key_bits)
{
	int key_size = (key_bits + 7) / 8;
	u32 len;

	setup->key_bits = key_bits;

	if (setup->nid == 714 || key_bits == 256) { // NID_secp256k1
		/* sm2 */
		if (subtype == SM2_TYPE) {
			setup->priv_key = sm2_priv;
			setup->priv_key_size = sizeof(sm2_priv);
			setup->pub_key = sm2_pubkey;
			setup->pub_key_size = sizeof(sm2_pubkey);

			len = SM2_DG_SZ;
			setup->msg = malloc(len);
			if (!setup->msg)
				return -1;
			memset(setup->msg, 0xFF, len);

			if (true) { // for msg_sigest mode
				memcpy(setup->msg, sm2_digest, sizeof(sm2_digest));
				setup->msg_size = sizeof(sm2_digest);
			} else {
				memcpy(setup->msg, sm2_plaintext, sizeof(sm2_plaintext));
				setup->msg_size = sizeof(sm2_plaintext);
			}

			if (setup->msg_size > 512) {
				setup->ciphertext = sm2_ciphertext_l;
				setup->ciphertext_size = sizeof(sm2_ciphertext_l);
				setup->plaintext = sm2_plaintext_l;
				setup->plaintext_size = sizeof(sm2_plaintext_l);
			} else {
				setup->ciphertext = sm2_ciphertext;
				setup->ciphertext_size = sizeof(sm2_ciphertext);
				setup->plaintext = sm2_plaintext;
				setup->plaintext_size = sizeof(sm2_plaintext);
			}

			setup->k = sm2_k;
			setup->k_size = sizeof(sm2_k);
			setup->userid = sm2_id;
			setup->userid_size = sizeof(sm2_id);
			setup->sign = sm2_sign_data;
			setup->sign_size = sizeof(sm2_sign_data);

		} else {
			setup->priv_key = ecdh_da_secp256k1;
			setup->except_pub_key = ecdh_except_b_pubkey_secp256k1;
			setup->pub_key = ecdh_cp_pubkey_secp256k1;
			setup->share_key = ecdh_cp_sharekey_secp256k1;
			setup->priv_key_size = sizeof(ecdh_da_secp256k1);
			setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp256k1);
			setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp256k1);
			setup->share_key_size = sizeof(ecdh_cp_sharekey_secp256k1);

			/* ecc sign */
			setup->msg = ecc_except_e_secp256k1;
			setup->msg_size = sizeof(ecc_except_e_secp256k1);
			setup->k = ecc_except_kinv_secp256k1;
			setup->k_size = sizeof(ecc_except_kinv_secp256k1);
			setup->rp = ecdh_cp_pubkey_secp256k1 + 1;
			setup->rp_size = key_size;

			/* ecc verf */
			setup->sign = ecc_cp_sign_secp256k1;
			setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
		}
	} else if (setup->nid == 706 || key_bits == 128) {
		setup->priv_key = ecdh_da_secp128r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp128r1;
		setup->pub_key = ecdh_cp_pubkey_secp128r1;
		setup->share_key = ecdh_cp_sharekey_secp128r1;
		setup->priv_key_size = sizeof(ecdh_da_secp128r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp128r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp128r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp128r1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp128r1;
		setup->msg_size = sizeof(ecc_except_e_secp128r1);
		setup->k = ecc_except_kinv_secp128r1;
		setup->k_size = sizeof(ecc_except_kinv_secp128r1);
		setup->rp = ecdh_cp_pubkey_secp128r1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp128r1;
		setup->sign_size = sizeof(ecc_cp_sign_secp128r1);

	} else if (setup->nid == 711 || key_bits == 192) {
		setup->priv_key = ecdh_da_secp192k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp192k1;
		setup->pub_key = ecdh_cp_pubkey_secp192k1;
		setup->share_key = ecdh_cp_sharekey_secp192k1;
		setup->priv_key_size = sizeof(ecdh_da_secp192k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp192k1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp192k1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp192k1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp192k1;
		setup->msg_size = sizeof(ecc_except_e_secp192k1);
		setup->k = ecc_except_kinv_secp192k1;
		setup->k_size = sizeof(ecc_except_kinv_secp192k1);
		setup->rp = ecdh_cp_pubkey_secp192k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
	} else if (setup->nid == 712 || key_bits == 224) {
		setup->priv_key = ecdh_da_secp224r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp224r1;
		setup->pub_key = ecdh_cp_pubkey_secp224r1;
		setup->share_key = ecdh_cp_sharekey_secp224r1;
		setup->priv_key_size = sizeof(ecdh_da_secp224r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp224r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp224r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp224r1);
	} else if (setup->nid == 929 || key_bits == 320) {
		setup->priv_key = ecdh_da_secp320k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp320k1;
		setup->pub_key = ecdh_cp_pubkey_secp320k1;
		setup->share_key = ecdh_cp_sharekey_secp320k1;
		setup->priv_key_size = sizeof(ecdh_da_secp320k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp320k1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp320k1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp320k1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp320k1;
		setup->msg_size = sizeof(ecc_except_e_secp320k1);
		setup->k = ecc_except_kinv_secp320k1;
		setup->k_size = sizeof(ecc_except_kinv_secp320k1);
		setup->rp = ecdh_cp_pubkey_secp192k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else if (setup->nid == 931 || key_bits == 384) {
		setup->priv_key = ecdh_da_secp384r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp384r1;
		setup->pub_key = ecdh_cp_pubkey_secp384r1;
		setup->share_key = ecdh_cp_sharekey_secp384r1;
		setup->priv_key_size = sizeof(ecdh_da_secp384r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp384r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp384r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp384r1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp384r1;
		setup->msg_size = sizeof(ecc_except_e_secp384r1);
		setup->k = ecc_except_kinv_secp384r1;
		setup->k_size = sizeof(ecc_except_kinv_secp384r1);
		setup->rp = ecdh_cp_pubkey_secp384r1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
	} else if (setup->nid == 716 || key_bits == 521) {
		setup->priv_key = ecdh_da_secp521r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp521r1;
		setup->pub_key = ecdh_cp_pubkey_secp521r1;
		setup->share_key = ecdh_cp_sharekey_secp521r1;
		setup->priv_key_size = sizeof(ecdh_da_secp521r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp521r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp521r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp521r1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp521r1;
		setup->msg_size = sizeof(ecc_except_e_secp521r1);
		setup->k = ecc_except_kinv_secp521r1;
		setup->k_size = sizeof(ecc_except_kinv_secp521r1);
		setup->rp = ecdh_cp_pubkey_secp521r1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else {
		HPRE_TST_PRT("init test sess setup not find this bits %d or nid %d\n",
				key_bits, setup->nid);
		return -EINVAL;
	}

	return 0;
}

static int ecdsa_param_fill(void *ctx, struct wcrypto_ecc_op_data *opdata,
	struct wcrypto_ecc_key *ecc_key, struct hpre_ecc_setup *setup,
	thread_data *pdata)
{
	int key_insize = (pdata->keybits + 7) / 8;
	u32 optype = pdata->optype;
	struct wcrypto_ecc_out *ecc_out = NULL;
	struct wcrypto_ecc_in *ecc_in = NULL;
	struct wcrypto_ecc_point pub;
	struct wd_dtb d, e, k;
	int ret = 0;

	if (optype == WCRYPTO_ECDSA_SIGN) {// Sign
		ecc_out = wcrypto_new_ecdsa_sign_out(ctx);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to get ecdsa out!\n");
			return -ENOMEM;
		}

		d.data = (void *)setup->priv_key;
		d.dsize = setup->priv_key_size;
		d.bsize = setup->priv_key_size;
		ret = wcrypto_set_ecc_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("failed to set ecdsa prikey!\n");
			goto del_ecc_out;
		}

		pub.x.data = (void *)setup->pub_key + 1;
		pub.x.dsize = key_insize;
		pub.x.bsize = key_insize;
		pub.y.data = pub.x.data + key_insize;
		pub.y.dsize = key_insize;
		pub.y.bsize = key_insize;
		ret = wcrypto_set_ecc_pubkey(ecc_key, &pub);
		if (ret) {
			HPRE_TST_PRT("failed to set ecdsa pubkey!\n");
			goto del_ecc_out;
		}

		e.data = (void *)setup->msg;
		e.dsize = setup->msg_size;
		e.bsize = key_insize;

		k.data = (void *)setup->k;
		k.dsize = setup->k_size;
		k.bsize = key_insize;
		ecc_in = wcrypto_new_ecdsa_sign_in(ctx, &e, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to get ecdsa sign in!\n");
			ret = -ENOMEM;
			goto del_ecc_out;
		}

		opdata->in = ecc_in;
		opdata->out = ecc_out;
	} else { // Verf
		pub.x.data = (void *)setup->pub_key + 1;
		pub.x.dsize = key_insize;
		pub.x.bsize = key_insize;
		pub.y.data = pub.x.data + key_insize;
		pub.y.dsize = key_insize;
		pub.y.bsize = key_insize;
		ret = wcrypto_set_ecc_pubkey(ecc_key, &pub);
		if (ret) {
			HPRE_TST_PRT("failed to set ecdsa pubkey!\n");
			return -ENOMEM;
		}

		e.data = (void *)setup->msg;
		e.dsize = setup->msg_size;
		e.bsize = key_insize;

		d.data = (void *)setup->sign;
		d.dsize = key_insize;
		d.bsize = key_insize;
		k.data = d.data + key_insize;
		k.dsize = key_insize;
		k.bsize = key_insize;
		ecc_in = wcrypto_new_ecdsa_verf_in(ctx, &e, &d, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to get ecdsa verf ecc in!\n");
			return -ENOMEM;
		}

		opdata->in = ecc_in;
	}

	return 0;
del_ecc_out:
	if (ecc_out)
		(void)wcrypto_del_ecc_out(ctx, ecc_out);
	return ret;
}

static int sm2_param_fill(void *ctx, struct wcrypto_ecc_op_data *opdata,
	struct hpre_ecc_setup *setup, thread_data *pdata)
{
	int key_insize = (pdata->keybits + 7) / 8;
	u32 optype = pdata->optype;
	struct wcrypto_ecc_out *ecc_out = NULL;
	struct wcrypto_ecc_in *ecc_in = NULL;
	struct wcrypto_ecc_point tmp;
	struct wd_dtb d, e, k;

	switch (optype) {
	case WCRYPTO_SM2_SIGN:// Sign
		ecc_out = wcrypto_new_sm2_sign_out(ctx);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			return -ENOMEM;
		}

		e.data = (void *)setup->msg;
		e.dsize = setup->msg_size;
		e.bsize = setup->msg_size;
		k.data = (void *)setup->k;
		k.dsize = setup->k_size;
		k.bsize = key_insize;
		ecc_in = wcrypto_new_sm2_sign_in(ctx, &e, &k, NULL, 1);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			goto del_ecc_out;
		}
		opdata->in = ecc_in;
		opdata->out = ecc_out;
		break;
	case WCRYPTO_SM2_VERIFY: // Verf
		ecc_out = wcrypto_new_sm2_sign_out(ctx);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			return -ENOMEM;
		}

		e.data = (void *)setup->msg;
		e.dsize = setup->msg_size;
		e.bsize = key_insize;
		d.data = (void *)setup->sign;
		d.dsize = key_insize;
		d.bsize = key_insize;
		k.data = d.data + key_insize;
		k.dsize = key_insize;
		k.bsize = key_insize;
		ecc_in = wcrypto_new_sm2_verf_in(ctx, &e, &d, &k, NULL, 1);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			goto del_ecc_out;
		}

		opdata->in = ecc_in;
		opdata->out = ecc_out;
		break;
	case WCRYPTO_SM2_ENCRYPT: // Enc
		ecc_out = wcrypto_new_sm2_enc_out(ctx, setup->msg_size);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			return -ENOMEM;
		}

		e.data = (void *)setup->plaintext;
		e.dsize = setup->plaintext_size;
		e.bsize = setup->plaintext_size;
		k.data = (void *)setup->k;
		k.dsize = setup->k_size;
		k.bsize = key_insize;
		ecc_in = wcrypto_new_sm2_enc_in(ctx, &e, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			goto del_ecc_out;
		}
		opdata->in = ecc_in;
		opdata->out = ecc_out;
		break;
	case WCRYPTO_SM2_DECRYPT: // Dec
		tmp.x.data = (void *)setup->ciphertext;
		tmp.x.dsize = 32;
		tmp.y.data = tmp.x.data + 32;
		tmp.y.dsize = 32;
		e.data = tmp.y.data + 32;
		e.dsize = 32;
		d.data = e.data + 32;
		d.dsize = setup->ciphertext_size - 32 * 3;
		ecc_in = wcrypto_new_sm2_dec_in(ctx, &tmp, &d, &e);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			return -ENOMEM;
		}

		ecc_out = wcrypto_new_sm2_dec_out(ctx, d.dsize);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			goto del_ecc_in;
		}

		opdata->in = ecc_in;
		opdata->out = ecc_out;
		break;
	case WCRYPTO_SM2_KG: // KG
		ecc_out = wcrypto_new_sm2_kg_out(ctx);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			return -ENOMEM;
		}

		opdata->out = ecc_out;
		break;
	default:
		HPRE_TST_PRT("failed to match sm2 optype!\n");
		return -ENOMEM;
	}

	return 0;

del_ecc_in:
	if (ecc_in)
		(void)wcrypto_del_ecc_in(ctx, ecc_in);
del_ecc_out:
	if (ecc_out)
		(void)wcrypto_del_ecc_out(ctx, ecc_out);

	return -ENOMEM;
}

static int ecc_param_fill(void *ctx, struct wcrypto_ecc_op_data *opdata,
	struct wcrypto_ecc_key *ecc_key, struct hpre_ecc_setup *setup,
	thread_data *pdata)
{
	int key_insize = (pdata->keybits + 7) / 8;
	u32 subtype = pdata->subtype;
	u32 optype = pdata->optype;
	struct wcrypto_ecc_out *ecc_out = NULL;
	struct wcrypto_ecc_in *ecc_in = NULL;
	struct wcrypto_ecc_point tmp;
	struct wd_dtb d;
	int ret = 0;

	ecc_out = wcrypto_new_ecxdh_out(ctx);
	if (!ecc_out) {
		HPRE_TST_PRT("failed to alloc ecxdh out!\n");
		return -ENOMEM;
	}
	if (optype == WCRYPTO_ECXDH_GEN_KEY) { // gen
		d.data = (void *)setup->priv_key;
		d.dsize = setup->priv_key_size;
		d.bsize = setup->priv_key_size;
		ret = wcrypto_set_ecc_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("failed to set ecc prikey!\n");
			goto del_ecc_out;
		}

		opdata->out = ecc_out;
	} else { // compute
		if (subtype == ECDH_TYPE)
			tmp.x.data = setup->except_pub_key;
		else
			tmp.x.data = setup->except_pub_key + 1;
		tmp.x.bsize = key_insize;
		tmp.x.dsize = key_insize;
		tmp.y.data = tmp.x.data + key_insize;
		tmp.y.bsize = key_insize;
		tmp.y.dsize = key_insize;
		ecc_in = wcrypto_new_ecxdh_in(ctx, &tmp);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to get ecxdh sign in!\n");
			goto del_ecc_out;
		}

		d.data = (void *)setup->priv_key;
		d.dsize = setup->priv_key_size;
		d.bsize = setup->priv_key_size;
		ret = wcrypto_set_ecc_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("failed to set ecc prikey!\n");
			goto del_ecc_out;
		}

		opdata->in = ecc_in;
		opdata->out = ecc_out;
	}

	return 0;

del_ecc_out:
	if (ecc_out)
		(void)wcrypto_del_ecc_out(ctx, ecc_out);

	return ret;
}

static void *ecc_wd_sync_run(void *arg)
{
	typedef int (*wd_do)(void *ctx, struct wcrypto_ecc_op_data *opdata,
					void *tag);
	wd_do wcrypto_do_ecc = NULL;
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	u32 subtype = pdata->subtype;
	struct wcrypto_ecc_ctx_setup ctx_setup;
	struct wcrypto_ecc_op_data opdata;
	struct wcrypto_ecc_curve param;
	struct hpre_ecc_setup setup;
	struct wcrypto_ecc_key *ecc_key;
	struct wcrypto_ecc_point pbk;
	struct wd_queue *queue;
	struct wd_dtb prk;
	void *ctx = NULL;
	void *tag = NULL;
	void *pool;
	u32 cid = ECC_CURVE_ID;
	u32 count = 0;
	int ret;

	memset(&ctx_setup,	0, sizeof(ctx_setup));
	memset(&param,	   0, sizeof(param));
	memset(&opdata,	 0, sizeof(opdata));

	pool = g_thread_queue.bd_res[pdata->td_id].pool;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;

	memset(&setup,	   0, sizeof(setup));
	if (subtype != X448_TYPE || subtype != X25519_TYPE) {
		ret = get_ecc_curve(&setup, cid);
		if (ret)
			return NULL;
	}

	ctx_setup.br.alloc = (void *)wd_alloc_blk;
	ctx_setup.br.free = (void *)wd_free_blk;
	ctx_setup.br.iova_map = (void *)wd_blk_iova_map;
	ctx_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	ctx_setup.br.get_bufsize = (void *)wd_blksize;
	ctx_setup.br.usr = pool;

	ctx_setup.key_bits = pdata->keybits;
	if (subtype == ECDH_TYPE || subtype == ECDSA_TYPE) {
		if (cid > ECC_CURVE_ID) {
			ctx_setup.cv.type = WCRYPTO_CV_CFG_PARAM;
			get_ecc_key_param(&param, pdata->keybits);
			ctx_setup.cv.cfg.pparam = &param;
		} else {
			ctx_setup.cv.type = WCRYPTO_CV_CFG_ID;
			ctx_setup.cv.cfg.id = setup.curve_id;
		}
	}

	ctx_setup.rand.cb = ecc_get_rand;
	// set def setting;
	ctx_setup.hash.cb = ecc_compute_hash;
	ctx_setup.hash.type = WCRYPTO_HASH_SHA256;

	ret = get_ecc_param_from_sample(&setup, subtype, pdata->keybits);
	if (ret)
		return NULL;

	ctx = wcrypto_create_ecc_ctx(queue, &ctx_setup);
	if (!ctx)
		goto msg_release;

	prk.data = (void *)setup.priv_key;
	prk.dsize = setup.priv_key_size;
	prk.bsize = setup.priv_key_size;
	pbk.x.data = (char *)setup.pub_key + 1;
	pbk.x.dsize = key_size;
	pbk.x.bsize = key_size;
	pbk.y.data = pbk.x.data + key_size;
	pbk.y.dsize = key_size;
	pbk.y.bsize = key_size;

	ecc_key = wcrypto_get_ecc_key(ctx);
	ret = wcrypto_set_ecc_prikey(ecc_key, &prk);
	if (ret) {
		HPRE_TST_PRT("failed to set ecc prikey!\n");
		goto sess_release;
	}

	ret = wcrypto_set_ecc_pubkey(ecc_key, &pbk);
	if (ret) {
		HPRE_TST_PRT("failed to set ecc pubkey!\n");
		goto sess_release;
	}

	opdata.op_type = pdata->optype;
	switch (subtype) {
	case ECDSA_TYPE: // ECC alg
		ret = ecdsa_param_fill(ctx, &opdata, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		wcrypto_do_ecc = wcrypto_do_ecdsa;
		break;
	case SM2_TYPE: // SM2 alg
		ret = sm2_param_fill(ctx, &opdata, &setup, pdata);
		if (ret)
			goto src_release;
		wcrypto_do_ecc = wcrypto_do_sm2;
		break;
	default: // ECDH, X25519, X448 alg
		ret = ecc_param_fill(ctx, &opdata, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		wcrypto_do_ecc = wcrypto_do_ecxdh;
		break;
	}

	do {
		ret = wcrypto_do_ecc(ctx, &opdata, tag);
		if (ret || opdata.status) {
			HPRE_TST_PRT("failed to do ecc task, status: %d\n", opdata.status);
			goto src_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while(true);

src_release:
	if (opdata.in)
		(void)wcrypto_del_ecc_in(ctx, opdata.in);
	if (opdata.out)
		(void)wcrypto_del_ecc_out(ctx, opdata.out);
sess_release:
	wcrypto_del_ecc_ctx(ctx);
msg_release:
	if (subtype == SM2_TYPE)
		free(setup.msg);
	add_recv_data(count, key_size);

	return NULL;
}

static void ecc_async_cb(const void *msg, void *tag)
{
	//struct wcrypto_ecc_msg *massage = msg;
	//struct rsa_async_tag *ptag = tag;
	//u32 op_type = tag->op_type;
	//void *ctx = tag->ctx;

	return;
}

static void *ecc_wd_async_run(void *arg)
{
	typedef int (*wd_do)(void *ctx, struct wcrypto_ecc_op_data *opdata,
					void *tag);
	wd_do wcrypto_do_ecc = NULL;
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	u32 subtype = pdata->subtype;
	struct rsa_async_tag *tag = NULL;
	struct wcrypto_ecc_ctx_setup ctx_setup;
	struct wcrypto_ecc_op_data opdata;
	struct wcrypto_ecc_curve param;
	struct hpre_ecc_setup setup;
	struct wcrypto_ecc_key *ecc_key;
	struct wcrypto_ecc_point pbk;
	struct wd_queue *queue;
	struct wd_dtb prk;
	void *ctx = NULL;
	int try_cnt = 0;
	void *pool;
	u32 cid = ECC_CURVE_ID;
	u32 count = 0;
	int i, ret;

	memset(&ctx_setup,	0, sizeof(ctx_setup));
	memset(&param,	   0, sizeof(param));
	memset(&opdata,  0, sizeof(opdata));

	pool = g_thread_queue.bd_res[pdata->td_id].pool;
	queue = g_thread_queue.bd_res[pdata->td_id].queue;

	memset(&setup,	   0, sizeof(setup));
	if (subtype != X448_TYPE || subtype != X25519_TYPE) {
		ret = get_ecc_curve(&setup, cid);
		if (ret)
			return NULL;
	}

	ctx_setup.cb = (void *)ecc_async_cb;
	ctx_setup.br.alloc = (void *)wd_alloc_blk;
	ctx_setup.br.free = (void *)wd_free_blk;
	ctx_setup.br.iova_map = (void *)wd_blk_iova_map;
	ctx_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	ctx_setup.br.get_bufsize = (void *)wd_blksize;
	ctx_setup.br.usr = pool;

	ctx_setup.key_bits = pdata->keybits;
	if (subtype == ECDH_TYPE || subtype == ECDSA_TYPE) {
		if (cid > ECC_CURVE_ID) {
			ctx_setup.cv.type = WCRYPTO_CV_CFG_PARAM;
			get_ecc_key_param(&param, pdata->keybits);
			ctx_setup.cv.cfg.pparam = &param;
		} else {
			ctx_setup.cv.type = WCRYPTO_CV_CFG_ID;
			ctx_setup.cv.cfg.id = setup.curve_id;
		}
	}

	ctx_setup.rand.cb = ecc_get_rand;
	// set def setting;
	ctx_setup.hash.cb = ecc_compute_hash;
	ctx_setup.hash.type = WCRYPTO_HASH_SHA256;

	ret = get_ecc_param_from_sample(&setup, subtype, pdata->keybits);
	if (ret)
		return NULL;

	ctx = wcrypto_create_ecc_ctx(queue, &ctx_setup);
	if (!ctx)
		goto msg_release;

	prk.data = (void *)setup.priv_key;
	prk.dsize = setup.priv_key_size;
	prk.bsize = setup.priv_key_size;
	pbk.x.data = (char *)setup.pub_key + 1;
	pbk.x.dsize = key_size;
	pbk.x.bsize = key_size;
	pbk.y.data = pbk.x.data + key_size;
	pbk.y.dsize = key_size;
	pbk.y.bsize = key_size;

	ecc_key = wcrypto_get_ecc_key(ctx);
	ret = wcrypto_set_ecc_prikey(ecc_key, &prk);
	if (ret) {
		HPRE_TST_PRT("failed to set ecc prikey!\n");
		goto sess_release;
	}

	ret = wcrypto_set_ecc_pubkey(ecc_key, &pbk);
	if (ret) {
		HPRE_TST_PRT("failed to set ecc pubkey!\n");
		goto sess_release;
	}

	opdata.op_type = pdata->optype;
	switch (subtype) {
	case ECDSA_TYPE: // ECC alg
		ret = ecdsa_param_fill(ctx, &opdata, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		wcrypto_do_ecc = wcrypto_do_ecdsa;
		break;
	case SM2_TYPE: // SM2 alg
		ret = sm2_param_fill(ctx, &opdata, &setup, pdata);
		if (ret)
			goto src_release;
		wcrypto_do_ecc = wcrypto_do_sm2;
		break;
	default: // ECDH, X25519, X448 alg
		ret = ecc_param_fill(ctx, &opdata, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		wcrypto_do_ecc = wcrypto_do_ecxdh;
		break;
	}

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		HPRE_TST_PRT("failed to malloc ecc tag!\n");
		goto src_release;
	}

	do {
		if (get_run_state() == 0)
			break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		tag[i].ctx = ctx;
		tag[i].cnt = i;
		tag[i].optype = opdata.op_type;

		ret = wcrypto_do_ecc(ctx, &opdata, &tag[i]);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				HPRE_TST_PRT("Test ECC send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret) {
			HPRE_TST_PRT("failed to do rsa async task!\n");
			goto tag_release;
		}
		count++;
	} while(true);

tag_release:
	free(tag);
src_release:
	if (opdata.in)
		(void)wcrypto_del_ecc_in(ctx, opdata.in);
	if (opdata.out)
		(void)wcrypto_del_ecc_out(ctx, opdata.out);
sess_release:
	while (1) {
		if (get_recv_time() > 0) // wait Async mode finish recv
			break;
		usleep(SEND_USLEEP);
	}

	wcrypto_del_ecc_ctx(ctx);
msg_release:
	if (subtype == SM2_TYPE)
		free(setup.msg);
	add_send_complete();

	return NULL;
}

static int hpre_wd_sync_threads(struct acc_option *options)
{
	typedef void *(*hpre_sync_run)(void *arg);
	hpre_sync_run wd_hpre_sync_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	threads_option.subtype = options->subtype;
	threads_option.td_id = 0;
	ret = hpre_wd_param_parse(&threads_option, options);
	if (ret)
		return ret;

	switch (options->subtype) {
	case RSA_TYPE:
		wd_hpre_sync_run = rsa_wd_sync_run;
		break;
	case DH_TYPE:
		wd_hpre_sync_run = dh_wd_sync_run;
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		wd_hpre_sync_run = ecc_wd_sync_run;
		break;
	default:
		HPRE_TST_PRT("failed to parse alg subtype on uninit!\n");
		return -EINVAL;
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].kmode = threads_option.kmode;
		threads_args[i].keybits = threads_option.keybits;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, wd_hpre_sync_run, &threads_args[i]);
		if (ret) {
			HPRE_TST_PRT("Create sync thread fail!\n");
			goto sync_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join sync thread fail!\n");
			goto sync_error;
		}
	}

sync_error:
	return ret;
}

static int hpre_wd_async_threads(struct acc_option *options)
{
	typedef void *(*hpre_async_run)(void *arg);
	hpre_async_run wd_hpre_async_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	threads_option.subtype = options->subtype;
	threads_option.td_id = 0;
	ret = hpre_wd_param_parse(&threads_option, options);
	if (ret)
		return ret;

	switch (options->subtype) {
	case RSA_TYPE:
		wd_hpre_async_run = rsa_wd_async_run;
		break;
	case DH_TYPE:
		wd_hpre_async_run = dh_wd_async_run;
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		wd_hpre_async_run = ecc_wd_async_run;
		break;
	default:
		HPRE_TST_PRT("failed to parse alg subtype on uninit!\n");
		return -EINVAL;
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].td_id = i;
		/* poll thread */
		ret = pthread_create(&pollid[i], NULL, hpre_wd_poll, &threads_args[i]);
		if (ret) {
			HPRE_TST_PRT("Create poll thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].kmode = threads_option.kmode;
		threads_args[i].keybits = threads_option.keybits;
		threads_args[i].optype = threads_option.optype;
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, wd_hpre_async_run, &threads_args[i]);
		if (ret) {
			HPRE_TST_PRT("Create async thread fail!\n");
			goto async_error;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join async thread fail!\n");
			goto async_error;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join poll thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

int hpre_wd_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;

	if (options->optype >= (WCRYPTO_EC_OP_MAX - WCRYPTO_ECDSA_VERIFY)) {
		HPRE_TST_PRT("HPRE optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_hpre_wd_queue(options);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = hpre_wd_async_threads(options);
	else
		ret = hpre_wd_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	uninit_hpre_wd_queue();

	return 0;
}
