/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#include <pthread.h>
#include "hisi_sec.h"

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

static int hisi_qm_send_async(struct hisi_qp_async *qp, void *req,
			      void (*callback)(void *parm))
{
	/* store req callback in task pool */

	/* send request */

	return 0;
}

static void hisi_qm_poll_async_qp(struct hisi_qp_async *qp, __u32 num)
{
	/* hisi_qm_recv */

	/* find related task in task pool and call its cb */
}
/* end qm demo */

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

static int get_qp_num_in_pool(void)
{
	return 0;
}
 
static void hisi_sec_add_qp_to_pool(struct hisi_sec_qp_async_pool *pool,
				    struct hisi_qp_async *qp)
{

}

int hisi_sec_init(struct wd_ctx_config *config, void *priv)
{
	/* allocate qp for each context */
	return 0;
}

void hisi_sec_exit(void *priv)
{

	/* free alloc_qp */
}

static int get_aes_c_key_len(struct wd_cipher_sess *sess, __u8 *c_key_len)
{
	return 0;
}

static int get_3des_c_key_len(struct wd_cipher_sess *sess, __u8 *c_key_len)
{

	return 0;
}

static int fill_cipher_bd2_alg(struct wd_cipher_sess *sess, struct hisi_sec_sqe *sqe)
{


	return 0;
}

static int fill_cipher_bd2_mode(struct wd_cipher_sess *sess, struct hisi_sec_sqe *sqe)
{
	return 0;
}

static int hisi_cipher_create_request(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg,
				struct hisi_sec_sqe *sqe)
{
	return 0;
}

/* should define a struct to pass aead, cipher to this function */
int hisi_sec_crypto(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
	return 0;

}

int hisi_sec_encrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
  return 0;
}

int hisi_sec_decrypt(struct wd_cipher_sess *sess, struct wd_cipher_arg *arg)
{
  return 0;
}

int hisi_cipher_init(struct wd_cipher_sess *sess)
{
	return 0;
}

void hisi_cipher_exit(struct wd_cipher_sess *sess)
{

}

int hisi_cipher_set_key(struct wd_cipher_sess *sess, const __u8 *key, __u32 key_len)
{
  
}

int hisi_cipher_encrypt(struct wd_cipher_sess *sess, struct wd_cipher_req *req)
{
	/* this function may be reused by aead, should change to proper inputs */
	return 0;
}

int hisi_cipher_decrypt(struct wd_cipher_sess *sess, struct wd_cipher_req *req)
{
	/* this function may be reused by aead, should change to proper inputs */
	return 0;
}

int hisi_cipher_poll(handle_t ctx, __u32 count)
{
	return 0;
}

int hisi_digest_init(struct wd_digest_sess *sess)
{
	return 0;
}

void hisi_digest_exit(struct wd_digest_sess *sess)
{

}

static void qm_fill_digest_alg(struct wd_digest_sess *sess,
			       struct wd_digest_arg *arg,
			       struct hisi_sec_sqe *sqe)
{
}


int hisi_digest_digest(struct wd_digest_sess *sess, struct wd_digest_arg *arg)
{

	return 0;
}

int hisi_sec_cipher_sync(handle_t ctx, struct wd_cipher_req *req)
{
	return 0;
}

int hisi_sec_cipher_async(handle_t ctx, struct wd_cipher_req *req)
{
	return 0;
}

int hisi_sec_cipher_recv_async(handle_t ctx, struct wd_cipher_req *req)
{
	return 0;
}

int hisi_hisi_sec_poll(handle_t ctx, __u32 num)
{
	return 0;
}
