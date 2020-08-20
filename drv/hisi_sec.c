/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#include <pthread.h>
#include "hisi_sec.h"
#include "../include/drv/wd_cipher_drv.h"

#define SEC_DIGEST_ALG_OFFSET 11
#define BD_TYPE2 	      0x2
#define WORD_BYTES	      4
#define SEC_FLAG_OFFSET	      7
#define SEC_AUTH_OFFSET	      6
#define SEC_AUTH_KEY_OFFSET   5
#define SEC_HW_TASK_DONE      0x1
#define SEC_DONE_MASK	      0x0001
#define SEC_FLAG_MASK	      0x780
#define SEC_TYPE_MASK	      0x0f

#define SEC_COMM_SCENE		  0
#define SEC_IPSEC_SCENE		  1
#define SEC_SCENE_OFFSET	  3
#define SEC_DE_OFFSET		  1
#define SEC_CMODE_OFFSET	  12
#define SEC_CKEY_OFFSET		  9
#define SEC_CIPHER_OFFSET	  4
#define XTS_MODE_KEY_DIVISOR	  2

#define DES_KEY_SIZE		  8
#define SEC_3DES_2KEY_SIZE	  (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE	  (3 * DES_KEY_SIZE)
#define AES_KEYSIZE_128		  16
#define AES_KEYSIZE_192		  24
#define AES_KEYSIZE_256		  32

/* fix me */
#define SEC_QP_NUM_PER_PROCESS	  1
#define MAX_CIPHER_RETRY_CNT	  20000000
/* should be remove to qm module */
struct hisi_qp_req {
	void (*callback)(void *parm);
};

struct hisi_qp_task_pool {
	pthread_mutex_t task_pool_lock;
	struct hisi_qp_req *queue;
	__u32 tail;
	__u32 head;
	__u32 depth;
};

struct hisi_qp_async {
	struct hisi_qp_task_pool task_pool;
	struct hisi_qp *qp;
};

/* session like request ctx */
struct hisi_sec_sess {
	struct hisi_qp *qp;
	struct hisi_qp_async *qp_async;
	char *node_path;
};

struct hisi_qp_async_list {
	struct hisi_qp_async *qp;
	struct hisi_qp_async_list *next;
};

struct hisi_sec_qp_async_pool {
	pthread_mutex_t lock;
	struct hisi_qp_async_list head;
} hisi_sec_qp_async_pool;
#ifdef DEBUG
static void hexdump(char *buff, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		printf("\\0x%02x", buff[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
}

static void sec_dump_bd(unsigned int *bd, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		WD_ERR("Word[%d] 0x%x\n", i, bd[i]);
	WD_ERR("\n");
}
#endif

static void update_iv(struct wd_cipher_msg *msg)
{

}

int hisi_sec_init(struct wd_ctx_config *config, void *priv)
{
	/* allocate qp for each context */
	struct hisi_qm_priv qm_priv;
	struct hisi_sec_ctx *sec_ctx = (struct hisi_sec_ctx *)priv;
	handle_t h_ctx, h_qp;
	int i, j, ret = 0;

	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.sqe_size = sizeof(struct hisi_sec_sqe);
		qm_priv.op_type = config->ctxs[i].op_type;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp) {
			ret = -EINVAL;
			goto out;
		}
		memcpy(&sec_ctx->config, config, sizeof(struct wd_ctx_config));
	}

	return 0;
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}
	return ret;
}

void hisi_sec_exit(void *priv)
{

	struct hisi_sec_ctx *sec_ctx = (struct hisi_sec_ctx *)priv;
	struct wd_ctx_config *config = &sec_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
}

static int get_3des_c_key_len(struct wd_cipher_msg *msg, __u8 *c_key_len)
{
	if (msg->key_bytes == SEC_3DES_2KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_2KEY;
	} else if (msg->key_bytes == SEC_3DES_3KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_3KEY;
	} else {
		WD_ERR("Invalid 3des key size!\n");
		return -EINVAL;
	}

	return 0;
}

static int get_aes_c_key_len(struct wd_cipher_msg *msg, __u8 *c_key_len)
{
	__u16 len;
	len = msg->key_bytes;
	if (msg->mode == WD_CIPHER_XTS)
		len = len / XTS_MODE_KEY_DIVISOR;

	switch (len) {
		case AES_KEYSIZE_128:
			*c_key_len = CKEY_LEN_128BIT;
			break;
		case AES_KEYSIZE_192:
			*c_key_len = CKEY_LEN_192BIT;
			break;
		case AES_KEYSIZE_256:
			*c_key_len = CKEY_LEN_256BIT;
			break;
		default:
			WD_ERR("Invalid AES key size!\n");
			return -EINVAL;
	}

	return 0;
}

static int fill_cipher_bd2_alg(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	int ret = 0;
	__u8 c_key_len = 0;

	switch (msg->alg) {
	case WD_CIPHER_SM4:
		sqe->type2.c_alg = C_ALG_SM4;
		sqe->type2.icvw_kmode = CKEY_LEN_SM4 << SEC_CKEY_OFFSET;
		break;
	case WD_CIPHER_AES:
		sqe->type2.c_alg = C_ALG_AES;
		ret = get_aes_c_key_len(msg, &c_key_len);
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	case WD_CIPHER_DES:
		sqe->type2.c_alg = C_ALG_DES;
		sqe->type2.icvw_kmode = CKEY_LEN_DES;
		break;
	case WD_CIPHER_3DES:
		sqe->type2.c_alg = C_ALG_3DES;
		ret = get_3des_c_key_len(msg, &c_key_len);
		sqe->type2.icvw_kmode = (__u16)c_key_len << SEC_CKEY_OFFSET;
		break;
	default:
		WD_ERR("Invalid cipher type!\n");
		return -EINVAL;
		break;
	}

	return ret;
}

static int fill_cipher_bd2_mode(struct wd_cipher_msg *msg, struct hisi_sec_sqe *sqe)
{
	__u16 c_mode;

	switch (msg->mode) {
		case WD_CIPHER_ECB:
			c_mode = C_MODE_ECB;
			break;
		case WD_CIPHER_CBC:
			c_mode = C_MODE_CBC;
			break;
		case WD_CIPHER_CTR:
			c_mode = C_MODE_CTR;
			break;
		case WD_CIPHER_XTS:
			c_mode = C_MODE_XTS;
			break;
		default:
			WD_ERR("Invalid cipher mode type!\n");
			return -EINVAL;
	}
	sqe->type2.icvw_kmode |= (__u16)(c_mode) << SEC_CMODE_OFFSET;

	return 0;
}

static void parse_cipher_bd2(struct hisi_sec_sqe *sqe, struct wd_cipher_msg *recv_msg)
{
	__u16 done;

	done = sqe->type2.done_flag & SEC_DONE_MASK;
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		WD_ERR("SEC BD %s fail! done=0x%x, etype=0x%x\n", "cipher",
		done, sqe->type2.error_type);
		recv_msg->result = WD_IN_EPARA;
	} else {
		recv_msg->result = WD_SUCCESS;
	}

#ifdef DEBUG
	WD_ERR("Dump cipher recv sqe-->!\n");
	hexdump(sqe->type2.data_dst_addr, 16);
#endif
	update_iv(recv_msg);
}

int hisi_sec_cipher_send(handle_t ctx, struct wd_cipher_msg *msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_sec_sqe sqe;
	__u8 scene, cipher, de;
	__u16 count = 0;
	int ret;

	if (!msg) {
		WD_ERR("input cipher msg is NULL!\n");
		return -EINVAL;
	}

	memset(&sqe, 0, sizeof(struct hisi_sec_sqe));
	/* config BD type */
	sqe.type_auth_cipher = BD_TYPE2;
	/* config scence */
	scene = SEC_IPSEC_SCENE << SEC_SCENE_OFFSET;
	de = 0x1 << SEC_DE_OFFSET;
	sqe.sds_sa_type = (__u8)(de | scene);
	sqe.type2.clen_ivhlen |= (__u32)msg->in_bytes;
	sqe.type2.data_src_addr = (__u64)msg->in;
	sqe.type2.data_dst_addr = (__u64)msg->out;
	sqe.type2.c_ivin_addr = (__u64)msg->iv;
	sqe.type2.c_key_addr = (__u64)msg->key;

	if (msg->op_type == WD_CIPHER_ENCRYPTION) {
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
	} else {
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;
	}
	sqe.type_auth_cipher |= cipher;

	/* fill cipher bd2 alg */
	ret = fill_cipher_bd2_alg(msg, &sqe);
	if (ret) {
		WD_ERR("faile to fill bd alg!\n");
		return ret;
	}

	/* fill cipher bd2 mode */
	ret = fill_cipher_bd2_mode(msg, &sqe);
	if (ret) {
		WD_ERR("faile to fill bd mode!\n");
		return ret;
	}
#ifdef DEBUG 
	WD_ERR("#######dump send bd############!\n");
	sec_dump_bd((unsigned int *)&sqe, 32);
#endif
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0) {
		WD_ERR("hisi qm send is err(%d)!\n", ret);
		return ret;
	}

	return ret;
}

int hisi_sec_cipher_recv(handle_t ctx, struct wd_cipher_msg *recv_msg) {
	struct hisi_sec_sqe sqe;
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;
#ifdef DEBUG
	WD_ERR("#######dump recv bd############!\n");
	sec_dump_bd((unsigned int *)&sqe, 32);
#endif
	/* parser cipher sqe */
	parse_cipher_bd2(&sqe, recv_msg);

	return 1;
}

static struct wd_cipher_driver hisi_cipher_driver = {
		.drv_name	= "hisi_sec2",
		.alg_name	= "cipher",
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
		.cipher_send	= hisi_sec_cipher_send,
		.cipher_recv	= hisi_sec_cipher_recv,
};

WD_CIPHER_SET_DRIVER(hisi_cipher_driver);
