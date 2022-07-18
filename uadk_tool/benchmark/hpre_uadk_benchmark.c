/* SPDX-License-Identifier: Apache-2.0 */

#include <numa.h>
#include "uadk_benchmark.h"

#include "hpre_uadk_benchmark.h"
#include "hpre_protocol_data.h"
#include "include/wd.h"
#include "include/wd_rsa.h"
#include "include/wd_dh.h"
#include "include/wd_ecc.h"
#include "include/wd_sched.h"

#define ECC_CURVE_ID		0x3 /* def set secp256k1 */
#define HPRE_TST_PRT 		printf
#define ERR_OPTYPE		0xFF
#define SM2_DG_SZ		1024

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
static const char rsa_m[8] = {0x54, 0x85, 0x9b, 0x34, 0x2c, 0x49, 0xea, 0x2a};

struct rsa_async_tag {
	handle_t sess;
};

//----------------------------------RSA param--------------------------------------//
struct hpre_dh_param {
	const void *x;
	const void *p;
	const void *g;
	const void *except_pub_key;
	const void *pub_key;
	const void *share_key;
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
	const void *digest; //use in ecdsa sign
	const void *k; // ecdsa sign in
	const void *rp; // x coordinate of k*generator used in ecdsa
	const void *sign; // ecdsa sign out or verf in
	const void *priv_key; // use in ecdsa sign
	void *msg; // sm2 plaintext,ciphertext or digest input
	const void *userid; // sm2 user id
	const void *ciphertext; // sm2 ciphertext
	const void *plaintext; // sm2 plaintext
	u32 key_size;
	u32 share_key_size;
	u32 except_pub_key_size;
	u32 digest_size;
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

typedef struct uadk_thread_res {
	u32 subtype;
	u32 keybits;
	u32 kmode;
	u32 optype;
	u32 td_id;
} thread_data;

static struct wd_ctx_config g_ctx_cfg;
static struct wd_sched *g_sched;
static unsigned int g_thread_num;
static unsigned int g_ctxnum;

static const char* const alg_operations[] = {
	"GenKey", "ShareKey", "Encrypt", "Decrypt", "Sign", "Verify",
};

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
		op_type = WD_DH_PHASE1;
		break;
	case 1: //GENKEY12
		op_type = WD_DH_PHASE2;
		break;
	default:
		HPRE_TST_PRT("failed to set dh op_type\n");
		HPRE_TST_PRT("DH Gen1: 0\n");
		HPRE_TST_PRT("DH Gen2: 1\n");
		return ERR_OPTYPE;
	}

	return op_type;
}

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
		op_type = WD_RSA_GENKEY;
		break;
	case 4: //Sign
		op_type = WD_RSA_SIGN;
		break;
	case 5: //Verf
		op_type = WD_RSA_VERIFY;
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
			op_type = WD_SM2_KG;
			break;
		case 2:
			op_type = WD_SM2_ENCRYPT;
			break;
		case 3:
			op_type = WD_SM2_DECRYPT;
			break;
		case 4:
			op_type = WD_SM2_SIGN;
			break;
		case 5:
			op_type = WD_SM2_VERIFY;
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
			op_type = WD_ECXDH_GEN_KEY;
			break;
		case 1: //COMPUTEKEY
			op_type = WD_ECXDH_COMPUTE_KEY;
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
			op_type = WD_ECDSA_SIGN;
			break;
		case 5: //Verf
			op_type = WD_ECDSA_VERIFY;
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

static int hpre_uadk_param_parse(thread_data *tddata, struct acc_option *options)
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

static int init_hpre_ctx_config(char *alg, int subtype, int mode)
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
		HPRE_TST_PRT("failed to get %s device\n", alg);
		return -ENODEV;
	}
	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = g_ctxnum;
	g_ctx_cfg.ctxs = calloc(g_ctxnum, sizeof(struct wd_ctx));
	if (!g_ctx_cfg.ctxs)
		return -ENOMEM;

	for (i = 0; i < g_ctxnum; i++) {
		g_ctx_cfg.ctxs[i].ctx = wd_request_ctx(list->dev);
		g_ctx_cfg.ctxs[i].op_type = 0; // default op_type
		g_ctx_cfg.ctxs[i].ctx_mode = (__u8)mode;
	}

	switch(subtype) {
	case RSA_TYPE:
		g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1, max_node, wd_rsa_poll_ctx);
		break;
	case DH_TYPE:
		g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1, max_node, wd_dh_poll_ctx);
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		g_sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 1, max_node, wd_ecc_poll_ctx);
		break;
	default:
		HPRE_TST_PRT("failed to parse alg subtype!\n");
		g_sched = NULL;
	}
	if (!g_sched) {
		HPRE_TST_PRT("failed to alloc sched!\n");
		goto out;
	}

	/* If there is no numa, we defualt config to zero */
	if (list->dev->numa_id < 0)
		list->dev->numa_id = 0;

	g_sched->name = SCHED_SINGLE;
	param.numa_id = list->dev->numa_id;
	param.type = 0;
	param.mode = mode;
	param.begin = 0;
	param.end = g_ctxnum - 1;
	ret = wd_sched_rr_instance(g_sched, &param);
	if (ret) {
		HPRE_TST_PRT("failed to fill hpre sched data!\n");
		goto out;
	}

	/* init */
	switch(subtype) {
	case RSA_TYPE:
		ret = wd_rsa_init(&g_ctx_cfg, g_sched);
		break;
	case DH_TYPE:
		ret = wd_dh_init(&g_ctx_cfg, g_sched);
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		ret = wd_ecc_init(&g_ctx_cfg, g_sched);
		break;
	default:
		ret =  -EINVAL;
	}
	if (ret) {
		HPRE_TST_PRT("failed to get hpre ctx!\n");
		goto out;
	}

	wd_free_list_accels(list);

	return 0;
out:
	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);

	return ret;
}

static void uninit_hpre_ctx_config(int subtype)
{
	int i;

	/* uninit */
	switch(subtype) {
	case RSA_TYPE:
		wd_rsa_uninit();
		break;
	case DH_TYPE:
		wd_dh_uninit();
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		wd_ecc_uninit();
		break;
	default:
		HPRE_TST_PRT("failed to parse alg subtype on uninit!\n");
		return;
	}

	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
	wd_sched_rr_release(g_sched);
}

/*-------------------------------uadk benchmark main code-------------------------------------*/

void *hpre_uadk_poll(void *data)
{
	typedef int (*poll_ctx)(__u32 idx, __u32 expt, __u32 *count);
	poll_ctx uadk_poll_ctx = NULL;
	thread_data *pdata = (thread_data *)data;
	u32 expt = ACC_QUEUE_SIZE * g_thread_num;
	u32 id = pdata->td_id;
	u32 last_time = 2; // poll need one more recv time
	u32 count = 0;
	u32 recv = 0;
	int  ret;

	if (id > g_ctxnum)
		return NULL;

	switch(pdata->subtype) {
	case RSA_TYPE:
		uadk_poll_ctx = wd_rsa_poll_ctx;
		break;
	case DH_TYPE:
		uadk_poll_ctx = wd_dh_poll_ctx;
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		uadk_poll_ctx = wd_ecc_poll_ctx;
		break;
	default:
		HPRE_TST_PRT("<<<<<<async poll interface is NULL!\n");
		return NULL;
	}

	while (last_time) {
		ret = uadk_poll_ctx(id, expt, &recv);
		count += recv;
		recv = 0;
		if (unlikely(ret != -WD_EAGAIN && ret < 0)) {
			HPRE_TST_PRT("poll ret: %u!\n", ret);
			goto recv_error;
		}

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count, pdata->keybits >> 3);

	return NULL;
}

static int get_rsa_key_from_sample(handle_t sess, char *privkey_file,
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

	bits = wd_rsa_get_key_bits(sess);
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
	if (wd_rsa_set_pubkey_params(sess, &wd_e, &wd_n)) {
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

		if (wd_rsa_set_crt_prikey_params(sess, &wd_dq,
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

		if (wd_rsa_set_prikey_params(sess, &wd_d, &wd_n)) {
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

static int get_hpre_keygen_opdata(handle_t sess, struct wd_rsa_req *req)
{
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
	struct wd_dtb t_e, t_p, t_q;
	struct wd_dtb *e, *p, *q;

	wd_rsa_get_pubkey(sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &e, NULL);
	wd_rsa_get_prikey(sess, &prikey);

	if (wd_rsa_is_crt(sess)) {
		wd_rsa_get_crt_prikey_params(prikey, NULL , NULL, NULL, &q, &p);
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

	req->src = wd_rsa_new_kg_in(sess, e, p, q);
	if (!req->src) {
		HPRE_TST_PRT("failed to create rsa kgen in!\n");
		return -ENOMEM;
	}
	req->dst = wd_rsa_new_kg_out(sess);
	if (!req->dst) {
		HPRE_TST_PRT("failed to create rsa kgen out!\n");
		wd_rsa_del_kg_in(sess, req->src);
		return -ENOMEM;
	}

	return 0;
}

static int get_ecc_curve(struct hpre_ecc_setup *setup, u32 cid)
{
	switch (cid) {
	case 0: // secp128R1
		setup->nid = 706;
		setup->curve_id = WD_SECP128R1;
		break;
	case 1: // secp192K1
		setup->nid = 711;
		setup->curve_id = WD_SECP192K1;
		break;
	case 2: // secp224R1
		setup->nid = 712;
		setup->curve_id = WD_SECP224R1;
		break;
	case 3: // secp256K1
		setup->nid = 714;
		setup->curve_id = WD_SECP256K1;
		break;
	case 4: // brainpoolP320R1
		setup->nid = 929;
		setup->curve_id = WD_BRAINPOOLP320R1;
		break;
	case 5: // secp384R1
		setup->nid = 715;
		setup->curve_id = WD_SECP384R1;
		break;
	case 6: // secp521R1
		setup->nid = 716;
		setup->curve_id = WD_SECP521R1;
		break;
	default:
		HPRE_TST_PRT("failed to get ecc curve id!\n");
		return -EINVAL;
	}

	return 0;
}

static int    get_ecc_key_param(struct wd_ecc_curve *param, u32 key_bits)
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

static void *rsa_uadk_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	void *key_info = NULL;
	handle_t h_sess;
	u32 count = 0;
	int ret;

	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = pdata->keybits;
	setup.is_crt = pdata->kmode;

	h_sess = wd_rsa_alloc_sess(&setup);
	if (!h_sess)
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

	ret = get_rsa_key_from_sample(h_sess,    	key_info, key_info,
					pdata->keybits, pdata->kmode);
	if (ret) {
		HPRE_TST_PRT("failed to get sample key data!\n");
		goto sample_release;
	}

	req.src_bytes = key_size;
	req.dst_bytes = key_size;
	req.op_type = pdata->optype;
	if (req.op_type == WD_RSA_GENKEY) {
		ret = get_hpre_keygen_opdata(h_sess, &req);
		if (ret){
			HPRE_TST_PRT("failed to fill rsa key gen req!\n");
			goto sample_release;
		}
	} else {
		req.src = malloc(key_size);
		if (!req.src) {
			HPRE_TST_PRT("failed to alloc rsa in buffer!\n");
			goto sample_release;
		}
		memset(req.src, 0, req.src_bytes);
                memcpy(req.src + key_size - sizeof(rsa_m), rsa_m, sizeof(rsa_m));
		req.dst = malloc(key_size);
		if (!req.dst) {
			HPRE_TST_PRT("failed to alloc rsa out buffer!\n");
			goto src_release;
		}
	}

	do {
		ret = wd_do_rsa_sync(h_sess, &req);
		if (ret || req.status) {
			HPRE_TST_PRT("failed to do rsa task, status: %d\n", req.status);
			goto dst_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while(true);

	/* clean output buffer remainings in the last time operation */
	if (req.op_type == WD_RSA_GENKEY) {
		char *data;
		int len;

		len = wd_rsa_kg_out_data((void *)req.dst, &data);
		if (len < 0) {
			HPRE_TST_PRT("failed to wd rsa get key gen out data!\n");
			goto sample_release;
		}
		memset(data, 0, len);

		wd_rsa_del_kg_in(h_sess, req.src);
		req.src = NULL;
		wd_rsa_del_kg_out(h_sess, req.dst);
		req.dst = NULL;
	}

dst_release:
	if (req.dst)
		free(req.dst);
src_release:
	if (req.src)
		free(req.src);
sample_release:
	free(rsa_key_in);
key_release:
	free(key_info);

	wd_rsa_free_sess(h_sess);
	add_recv_data(count, key_size);

	return NULL;
}

static void rsa_async_cb(void *req_t)
{
	//struct wd_rsa_req *req = req_t;
	//struct rsa_async_tag *tag = req->cb_param;
	//enum wd_rsa_op_type   	 op_type = req->op_type;
	//handle_t h_sess = tag->sess;

	return;
}

static void *rsa_uadk_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct rsa_async_tag *tag;
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	void *key_info = NULL;
	int try_cnt = 0;
	handle_t h_sess;
	u32 count = 0;
	int i, ret;

	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = pdata->keybits;
	setup.is_crt = pdata->kmode;

	h_sess = wd_rsa_alloc_sess(&setup);
	if (!h_sess)
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

	ret = get_rsa_key_from_sample(h_sess,		key_info, key_info,
					pdata->keybits, pdata->kmode);
	if (ret) {
		HPRE_TST_PRT("failed to get sample key data!\n");
		goto sample_release;
	}

	req.src_bytes = key_size;
	req.dst_bytes = key_size;
	req.op_type = pdata->optype;
	if (req.op_type == WD_RSA_GENKEY) {
		ret = get_hpre_keygen_opdata(h_sess, &req);
		if (ret){
			HPRE_TST_PRT("failed to fill rsa key gen req!\n");
			goto sample_release;
		}
	} else {
		req.src = malloc(key_size);
		if (!req.src) {
			HPRE_TST_PRT("failed to alloc rsa in buffer!\n");
			goto sample_release;
		}
		memset(req.src, 0, req.src_bytes);
                memcpy(req.src + key_size - sizeof(rsa_m), rsa_m, sizeof(rsa_m));
		req.dst = malloc(key_size);
		if (!req.dst) {
			HPRE_TST_PRT("failed to alloc rsa out buffer!\n");
			goto src_release;
		}
	}

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		HPRE_TST_PRT("failed to malloc rsa tag!\n");
		goto dst_release;
	}
	req.cb = rsa_async_cb;

	do {
		if (get_run_state() == 0)
			break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		tag[i].sess = h_sess;
		req.cb_param = &tag[i];

		ret = wd_do_rsa_async(h_sess, &req);
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
	if (req.op_type == WD_RSA_GENKEY) {
		char *data;
		int len;

		len = wd_rsa_kg_out_data((void *)req.dst, &data);
		if (len < 0) {
			HPRE_TST_PRT("failed to wd rsa get key gen out data!\n");
			goto tag_release;
		}
		memset(data, 0, len);

		wd_rsa_del_kg_in(h_sess, req.src);
		req.src = NULL;
		wd_rsa_del_kg_out(h_sess, req.dst);
		req.dst = NULL;
	}

tag_release:
	free(tag);
dst_release:
	if (req.dst)
		free(req.dst);
src_release:
	if (req.src)
		free(req.src);
sample_release:
	free(rsa_key_in);
key_release:
	free(key_info);

	wd_rsa_free_sess(h_sess);
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

static int get_dh_opdata_param(handle_t h_sess, struct wd_dh_req *req,
	struct hpre_dh_param *setup, int key_size)
{
	unsigned char *ag_bin = NULL;
	struct wd_dtb ctx_g;
	int ret;

	ag_bin = malloc(2 * key_size);
	if (!ag_bin)
		return -ENOMEM;

	memset(ag_bin, 0, 2 * key_size);
	req->pv = ag_bin;

	req->x_p = malloc(2 * key_size);
	if (!req->x_p)
		goto ag_error;

	memset(req->x_p, 0, 2 * key_size);

	req->pri = malloc(2 * key_size);
	if (!req->pri)
		goto xp_error;

	memset(req->pri, 0, 2 * key_size);
	req->pri_bytes = 2 * key_size;

	ctx_g.data = malloc(key_size);
	if (!ctx_g.data)
		goto ctx_release;

	if (setup->optype == WD_DH_PHASE1) { // GEN1
		memcpy(req->x_p, setup->x, setup->x_size);
		memcpy(req->x_p + key_size, setup->p, setup->p_size);
		memcpy(ctx_g.data, setup->g, setup->g_size);
		req->pbytes = setup->p_size;
		req->xbytes = setup->x_size;
		ctx_g.dsize = setup->g_size;
		ctx_g.bsize = key_size;

		ret = wd_dh_set_g(h_sess, &ctx_g);
		if (ret)
			HPRE_TST_PRT("wd_dh_set_g run failed\n");
	} else { // GEN1
		memcpy(req->x_p, setup->x, setup->x_size);
		memcpy(req->x_p + key_size, setup->p, setup->p_size);
		memcpy(req->pv, setup->except_pub_key, setup->except_pub_key_size);
		req->pbytes = setup->p_size;
		req->xbytes = setup->x_size;
		req->pvbytes = setup->except_pub_key_size;
	}

	free(ctx_g.data);

	return 0;

ctx_release:
	free(req->pri);
xp_error:
	free(req->x_p);
ag_error:
	free(req->pv);

	return -ENOMEM;
}

static void dh_async_cb(void *req_t)
{
	//struct wd_dh_req *req = req_t;
	//struct rsa_async_tag *tag = req->cb_param;
	//enum wd_rsa_op_type op_type = req->op_type;
	//handle_t h_sess = tag->sess;

	return;
}

static void *dh_uadk_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wd_dh_sess_setup dh_setup;
	struct rsa_async_tag *tag;
	struct hpre_dh_param param;
	struct wd_dh_req req;
	handle_t h_sess;
	int try_cnt = 0;
	u32 count = 0;
	int i, ret;

	memset(&dh_setup, 0, sizeof(dh_setup));
	memset(&req, 0, sizeof(req));
	dh_setup.key_bits = pdata->keybits;
	if (pdata->optype == WD_DH_PHASE2)
		dh_setup.is_g2 = true; // G1 is 0; G2 is 1;

	h_sess = wd_dh_alloc_sess(&dh_setup);
	if (!h_sess)
		return NULL;

	ret = get_dh_param_from_sample(&param, pdata->keybits, pdata->kmode);
	if (ret)
		goto sess_release;

	param.optype = pdata->optype;
	req.op_type = pdata->optype;
	ret = get_dh_opdata_param(h_sess, &req, &param, key_size);
	if (ret){
		HPRE_TST_PRT("failed to fill dh key gen req!\n");
		goto param_release;
	}

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		HPRE_TST_PRT("failed to malloc rsa tag!\n");
		goto param_release;
	}
	req.cb = dh_async_cb;

	do {
		if (get_run_state() == 0)
			break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		tag[i].sess = h_sess;
		req.cb_param = &tag[i];

		ret = wd_do_dh_async(h_sess, &req);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				HPRE_TST_PRT("Test DH send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret) {
			HPRE_TST_PRT("failed to do DH async task!\n");
			goto tag_release;
		}
		count++;
	} while(true);

tag_release:
	free(tag);
param_release:
	free(req.x_p);
	free(req.pv);
	free(req.pri);
sess_release:
	wd_dh_free_sess(h_sess);
	add_send_complete();

	return NULL;
}

static void *dh_uadk_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	struct wd_dh_sess_setup dh_setup;
	struct hpre_dh_param setup;
	struct wd_dh_req req;
	handle_t h_sess;
	u32 count = 0;
	int ret;

	memset(&dh_setup, 0, sizeof(dh_setup));
	memset(&req, 0, sizeof(req));
	dh_setup.key_bits = pdata->keybits;
	if (pdata->optype == WD_DH_PHASE2)
		dh_setup.is_g2 = true; // G1 is 0; G2 is 1;

	h_sess = wd_dh_alloc_sess(&dh_setup);
	if (!h_sess)
		return NULL;

	ret = get_dh_param_from_sample(&setup, pdata->keybits, pdata->kmode);
	if (ret)
		goto sess_release;

	setup.optype = pdata->optype;
	req.op_type = pdata->optype;
	ret = get_dh_opdata_param(h_sess, &req, &setup, key_size);
	if (ret){
		HPRE_TST_PRT("failed to fill dh key gen req!\n");
		goto param_release;
	}

	do {
		ret = wd_do_dh_sync(h_sess, &req);
		if (ret || req.status) {
			HPRE_TST_PRT("failed to do dh task, status: %d\n", req.status);
			goto param_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while(true);

param_release:
	free(req.x_p);
	free(req.pv);
	free(req.pri);
sess_release:
	wd_dh_free_sess(h_sess);
	add_recv_data(count, key_size);

	return NULL;
}

static int hpre_compute_hash(const char *in, size_t in_len,
		       char *out, size_t out_len, void *usr)
{
	/* perf test for none hash check */
	return 0;
}

static int ecdsa_param_fill(handle_t h_sess, struct wd_ecc_req *req,
	struct wd_ecc_key *ecc_key, struct hpre_ecc_setup *setup,
	thread_data *pdata)
{
	int key_insize = (pdata->keybits + 7) / 8;
	u32 optype = pdata->optype;
	struct wd_ecc_out *ecc_out = NULL;
	struct wd_ecc_in *ecc_in = NULL;
	struct wd_ecc_point pub;
	struct wd_dtb d, e, k;
	int ret = 0;

	if (optype == WD_ECDSA_SIGN) {// Sign
		ecc_out = wd_ecdsa_new_sign_out(h_sess);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to get ecdsa out!\n");
			return -ENOMEM;
		}

		d.data = (void *)setup->priv_key;
		d.dsize = setup->priv_key_size;
		d.bsize = setup->priv_key_size;
		ret = wd_ecc_set_prikey(ecc_key, &d);
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
		ret = wd_ecc_set_pubkey(ecc_key, &pub);
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
		ecc_in = wd_ecdsa_new_sign_in(h_sess, &e, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to get ecdsa sign in!\n");
			ret = -ENOMEM;
			goto del_ecc_out;
		}

		req->src = ecc_in;
		req->dst = ecc_out;
	} else { // Verf
		pub.x.data = (void *)setup->pub_key + 1;
		pub.x.dsize = key_insize;
		pub.x.bsize = key_insize;
		pub.y.data = pub.x.data + key_insize;
		pub.y.dsize = key_insize;
		pub.y.bsize = key_insize;
		ret = wd_ecc_set_pubkey(ecc_key, &pub);
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
		ecc_in = wd_ecdsa_new_verf_in(h_sess, &e, &d, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to get ecdsa verf ecc in!\n");
			return -ENOMEM;
		}

		req->src = ecc_in;
	}

	return 0;
del_ecc_out:
	if (ecc_out)
		(void)wd_ecc_del_out(h_sess, ecc_out);
	return ret;
}

static int sm2_param_fill(handle_t h_sess, struct wd_ecc_req *req,
	struct hpre_ecc_setup *setup, thread_data *pdata)
{
	int key_insize = (pdata->keybits + 7) / 8;
	u32 optype = pdata->optype;
	struct wd_ecc_out *ecc_out = NULL;
	struct wd_ecc_in *ecc_in = NULL;
	struct wd_ecc_point tmp;
	struct wd_dtb d, e, k;

	switch (optype) {
	case WD_SM2_SIGN:// Sign
		ecc_out = wd_sm2_new_sign_out(h_sess);
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
		ecc_in = wd_sm2_new_sign_in(h_sess, &e, &k, NULL, 1);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			goto del_ecc_out;
		}
		req->src = ecc_in;
		req->dst = ecc_out;
		break;
	case WD_SM2_VERIFY: // Verf
		ecc_out = wd_sm2_new_sign_out(h_sess);
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
		ecc_in = wd_sm2_new_verf_in(h_sess, &e, &d, &k, NULL, 1);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			goto del_ecc_out;
		}

		req->src = ecc_in;
		req->dst = ecc_out;
		break;
	case WD_SM2_ENCRYPT: // Enc
		ecc_out = wd_sm2_new_enc_out(h_sess, setup->msg_size);
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
		ecc_in = wd_sm2_new_enc_in(h_sess, &e, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			goto del_ecc_out;
		}
		req->src = ecc_in;
		req->dst = ecc_out;
		break;
	case WD_SM2_DECRYPT: // Dec
		tmp.x.data = (void *)setup->ciphertext;
		tmp.x.dsize = 32;
		tmp.y.data = tmp.x.data + 32;
		tmp.y.dsize = 32;
		e.data = tmp.y.data + 32;
		e.dsize = 32;
		d.data = e.data + 32;
		d.dsize = setup->ciphertext_size - 32 * 3;
		ecc_in = wd_sm2_new_dec_in(h_sess, &tmp, &d, &e);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to alloc sm2 ecc in!\n");
			return -ENOMEM;
		}

		ecc_out = wd_sm2_new_dec_out(h_sess, d.dsize);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			goto del_ecc_in;
		}

		req->src = ecc_in;
		req->dst = ecc_out;
		break;
	case WD_SM2_KG: // KG
		ecc_out = wd_sm2_new_kg_out(h_sess);
		if (!ecc_out) {
			HPRE_TST_PRT("failed to alloc sm2 ecc out!\n");
			return -ENOMEM;
		}

		req->dst = ecc_out;
		break;
	default:
		HPRE_TST_PRT("failed to match sm2 optype!\n");
		return -ENOMEM;
	}

	return 0;

del_ecc_in:
	if (ecc_in)
		(void)wd_ecc_del_in(h_sess, ecc_in);
del_ecc_out:
	if (ecc_out)
		(void)wd_ecc_del_out(h_sess, ecc_out);

	return -ENOMEM;
}

static int ecc_param_fill(handle_t h_sess, struct wd_ecc_req *req,
	struct wd_ecc_key *ecc_key, struct hpre_ecc_setup *setup,
	thread_data *pdata)
{
	int key_insize = (pdata->keybits + 7) / 8;
	u32 subtype = pdata->subtype;
	u32 optype = pdata->optype;
	struct wd_ecc_out *ecc_out = NULL;
	struct wd_ecc_in *ecc_in = NULL;
	struct wd_ecc_point tmp;
	struct wd_dtb d;
	int ret = 0;

	ecc_out = wd_ecxdh_new_out(h_sess);
	if (!ecc_out) {
		HPRE_TST_PRT("failed to alloc ecc out!\n");
		return -ENOMEM;
	}
	if (optype == WD_ECXDH_GEN_KEY) { // gen
		d.data = (void *)setup->priv_key;
		d.dsize = setup->priv_key_size;
		d.bsize = setup->priv_key_size;
		ret = wd_ecc_set_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("failed to set ecxdh prikey!\n");
			goto del_ecc_out;
		}

		req->dst = ecc_out;
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
		ecc_in = wd_ecxdh_new_in(h_sess, &tmp);
		if (!ecc_in) {
			HPRE_TST_PRT("failed to get ecxdh sign in!\n");
			goto del_ecc_out;
		}

		d.data = (void *)setup->priv_key;
		d.dsize = setup->priv_key_size;
		d.bsize = setup->priv_key_size;
		ret = wd_ecc_set_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("failed to set ecc prikey!\n");
			goto del_ecc_out;
		}

		req->src = ecc_in;
		req->dst = ecc_out;
	}

	return 0;

del_ecc_out:
	if (ecc_out)
		(void)wd_ecc_del_out(h_sess, ecc_out);

	return ret;
}

static void *ecc_uadk_sync_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	u32 subtype = pdata->subtype;
	struct wd_ecc_sess_setup sess_setup;
	struct hpre_ecc_setup setup;
	struct wd_ecc_curve param;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_point pbk;
	struct wd_dtb prk;
	struct wd_ecc_req req;
	u32 cid = ECC_CURVE_ID;
	handle_t h_sess;
	u32 count = 0;
	int ret;

	memset(&sess_setup,     0, sizeof(sess_setup));
	memset(&param,     0, sizeof(param));
	memset(&req,     0, sizeof(req));

	memset(&setup,     0, sizeof(setup));
	if (subtype != X448_TYPE || subtype != X25519_TYPE) {
		ret = get_ecc_curve(&setup, cid);
		if (ret)
			return NULL;
	}

	sess_setup.key_bits = pdata->keybits;
	if (subtype == ECDH_TYPE || subtype == ECDSA_TYPE) {
		if (cid > ECC_CURVE_ID) {
			sess_setup.cv.type = WD_CV_CFG_PARAM;
			get_ecc_key_param(&param, pdata->keybits);
			sess_setup.cv.cfg.pparam = &param;
		} else {
			sess_setup.cv.type = WD_CV_CFG_ID;
			sess_setup.cv.cfg.id = setup.curve_id;
		}
	}

	sess_setup.rand.cb = ecc_get_rand;
	switch (subtype) {
	case SM2_TYPE:
		sess_setup.alg = "sm2";
		break;
	case ECDH_TYPE:
		sess_setup.alg = "ecdh";
		break;
	case ECDSA_TYPE:
		sess_setup.alg = "ecdsa";
		break;
	}

	// set def setting;
	sess_setup.hash.cb = hpre_compute_hash;
	sess_setup.hash.type = WD_HASH_SHA256;

	ret = get_ecc_param_from_sample(&setup, subtype, pdata->keybits);
	if (ret)
		return NULL;

	h_sess = wd_ecc_alloc_sess(&sess_setup);
	if (!h_sess)
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

	ecc_key = wd_ecc_get_key(h_sess);
	ret = wd_ecc_set_prikey(ecc_key, &prk);
	if (ret) {
		HPRE_TST_PRT("failed to pre set ecc prikey!\n");
		goto sess_release;
	}

	ret = wd_ecc_set_pubkey(ecc_key, &pbk);
	if (ret) {
		HPRE_TST_PRT("failed to pre set ecc pubkey!\n");
		goto sess_release;
	}

	req.op_type = pdata->optype;
	switch (subtype) {
	case ECDSA_TYPE: // ECC alg
		ret = ecdsa_param_fill(h_sess, &req, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		break;
	case SM2_TYPE: // SM2 alg
		ret = sm2_param_fill(h_sess, &req, &setup, pdata);
		if (ret)
			goto src_release;
		break;
	default: // ECDH, X25519, X448 alg
		ret = ecc_param_fill(h_sess, &req, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		break;
	}

	do {
		ret = wd_do_ecc_sync(h_sess, &req);
		if (ret || req.status) {
			HPRE_TST_PRT("failed to do ecc task, status: %d\n", req.status);
			goto src_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while(true);

src_release:
	if (req.src)
		(void)wd_ecc_del_in(h_sess, req.src);
	if (req.dst)
		(void)wd_ecc_del_out(h_sess, req.dst);
sess_release:
	wd_ecc_free_sess(h_sess);
msg_release:
	if (subtype == SM2_TYPE)
		free(setup.msg);

	add_recv_data(count, key_size);

	return NULL;
}

static void ecc_async_cb(void *req_t)
{
	//struct wd_ecc_req *req = req_t;
	//struct rsa_async_tag *tag = req->cb_param;
	//enum wd_rsa_op_type op_type = req->op_type;
	//handle_t h_sess = tag->sess;

	return;
}

static void *ecc_uadk_async_run(void *arg)
{
	thread_data *pdata = (thread_data *)arg;
	int key_size = pdata->keybits >> 3;
	u32 subtype = pdata->subtype;
	struct wd_ecc_sess_setup sess_setup;
	struct rsa_async_tag *tag;
	struct hpre_ecc_setup setup;
	struct wd_ecc_curve param;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_point pbk;
	struct wd_ecc_req req;
	struct wd_dtb prk;
	u32 cid = ECC_CURVE_ID;
	handle_t h_sess;
	int try_cnt = 0;
	u32 count = 0;
	int i, ret;

	memset(&sess_setup,	0, sizeof(sess_setup));
	memset(&param,	   0, sizeof(param));
	memset(&req,	 0, sizeof(req));

	memset(&setup,	   0, sizeof(setup));
	if (subtype != X448_TYPE || subtype != X25519_TYPE) {
		ret = get_ecc_curve(&setup, cid);
		if (ret)
			return NULL;
	}

	sess_setup.key_bits = pdata->keybits;
	if (subtype == ECDH_TYPE || subtype == ECDSA_TYPE) {
		if (cid > ECC_CURVE_ID) {
			sess_setup.cv.type = WD_CV_CFG_PARAM;
			get_ecc_key_param(&param, pdata->keybits);
			sess_setup.cv.cfg.pparam = &param;
		} else {
			sess_setup.cv.type = WD_CV_CFG_ID;
			sess_setup.cv.cfg.id = setup.curve_id;
		}
	}

	sess_setup.rand.cb = ecc_get_rand;
	switch (subtype) {
	case SM2_TYPE:
		sess_setup.alg = "sm2";
		break;
	case ECDH_TYPE:
		sess_setup.alg = "ecdh";
		break;
	case ECDSA_TYPE:
		sess_setup.alg = "ecdsa";
		break;
	}

	// set def setting;
	sess_setup.hash.cb = hpre_compute_hash;
	sess_setup.hash.type = WD_HASH_SHA256;

	ret = get_ecc_param_from_sample(&setup, subtype, pdata->keybits);
	if (ret)
		return NULL;

	h_sess = wd_ecc_alloc_sess(&sess_setup);
	if (!h_sess)
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

	ecc_key = wd_ecc_get_key(h_sess);
	ret = wd_ecc_set_prikey(ecc_key, &prk);
	if (ret) {
		HPRE_TST_PRT("failed to pre set ecc prikey!\n");
		goto sess_release;
	}

	ret = wd_ecc_set_pubkey(ecc_key, &pbk);
	if (ret) {
		HPRE_TST_PRT("failed to pre set ecc pubkey!\n");
		goto sess_release;
	}

	req.op_type = pdata->optype;
	switch (subtype) {
	case ECDSA_TYPE: // ECC alg
		ret = ecdsa_param_fill(h_sess, &req, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		break;
	case SM2_TYPE: // SM2 alg
		ret = sm2_param_fill(h_sess, &req, &setup, pdata);
		if (ret)
			goto src_release;
		break;
	default: // ECDH, X25519, X448 alg
		ret = ecc_param_fill(h_sess, &req, ecc_key, &setup, pdata);
		if (ret)
			goto src_release;
		break;
	}

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		HPRE_TST_PRT("failed to malloc rsa tag!\n");
		goto  src_release;
	}
	req.cb = ecc_async_cb;

	do {
		if (get_run_state() == 0)
			break;

		try_cnt = 0;
		i = count % MAX_POOL_LENTH;
		tag[i].sess = h_sess;
		req.cb_param = &tag[i];

		ret = wd_do_ecc_sync(h_sess, &req);
		if (ret == -WD_EBUSY) {
			usleep(SEND_USLEEP * try_cnt);
			try_cnt++;
			if (try_cnt > MAX_TRY_CNT) {
				HPRE_TST_PRT("Test ECC send fail %d times!\n", MAX_TRY_CNT);
				try_cnt = 0;
			}
			continue;
		} else if (ret) {
			HPRE_TST_PRT("failed to do ECC async task!\n");
			goto tag_release;
		}
		count++;
	} while(true);

tag_release:
	free(tag);
src_release:
	if (req.src)
		(void)wd_ecc_del_in(h_sess, req.src);
	if (req.dst)
		(void)wd_ecc_del_out(h_sess, req.dst);
sess_release:
	wd_ecc_free_sess(h_sess);
msg_release:
	if (subtype == SM2_TYPE)
		free(setup.msg);

	add_send_complete();

	return NULL;
}

static int hpre_uadk_sync_threads(struct acc_option *options)
{
	typedef void *(*hpre_sync_run)(void *arg);
	hpre_sync_run uadk_hpre_sync_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	threads_option.subtype = options->subtype;
	threads_option.td_id = 0;
	ret = hpre_uadk_param_parse(&threads_option, options);
	if (ret)
		return ret;

	switch (options->subtype) {
	case RSA_TYPE:
		uadk_hpre_sync_run = rsa_uadk_sync_run;
		break;
	case DH_TYPE:
		uadk_hpre_sync_run = dh_uadk_sync_run;
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		uadk_hpre_sync_run = ecc_uadk_sync_run;
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
		ret = pthread_create(&tdid[i], NULL, uadk_hpre_sync_run, &threads_args[i]);
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

static int hpre_uadk_async_threads(struct acc_option *options)
{
	typedef void *(*hpre_async_run)(void *arg);
	hpre_async_run uadk_hpre_async_run = NULL;
	thread_data threads_args[THREADS_NUM];
	thread_data threads_option;
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	/* alg param parse and set to thread data */
	threads_option.subtype = options->subtype;
	threads_option.td_id = 0;
	ret = hpre_uadk_param_parse(&threads_option, options);
	if (ret)
		return ret;

	switch (options->subtype) {
	case RSA_TYPE:
		uadk_hpre_async_run = rsa_uadk_async_run;
		break;
	case DH_TYPE:
		uadk_hpre_async_run = dh_uadk_async_run;
		break;
	case ECDH_TYPE:
	case ECDSA_TYPE:
	case SM2_TYPE:
	case X25519_TYPE:
	case X448_TYPE:
		uadk_hpre_async_run = ecc_uadk_async_run;
		break;
	default:
		HPRE_TST_PRT("failed to parse alg subtype on uninit!\n");
		return -EINVAL;
	}

	for (i = 0; i < g_ctxnum; i++) {
		threads_args[i].subtype = threads_option.subtype;
		threads_args[i].td_id = i;
		/* poll thread */
		ret = pthread_create(&pollid[i], NULL, hpre_uadk_poll, &threads_args[i]);
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
		ret = pthread_create(&tdid[i], NULL, uadk_hpre_async_run, &threads_args[i]);
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

	for (i = 0; i < g_ctxnum; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join poll thread fail!\n");
			goto async_error;
		}
	}

async_error:
	return ret;
}

int hpre_uadk_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;
	g_ctxnum = options->ctxnums;

	if (options->optype >= (WD_EC_OP_MAX - WD_ECDSA_VERIFY)) {
		HPRE_TST_PRT("HPRE optype error: %u\n", options->optype);
		return -EINVAL;
	}

	ret = init_hpre_ctx_config(options->algclass, options->subtype,
					  options->syncmode);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		ret = hpre_uadk_async_threads(options);
	else
		ret = hpre_uadk_sync_threads(options);
	cal_perfermance_data(options, ptime);
	if (ret)
		return ret;

	uninit_hpre_ctx_config(options->subtype);

	return 0;
}
