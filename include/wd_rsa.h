/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_RSA_H
#define __WD_RSA_H

#include <stdbool.h>

#include "wd.h"
#include "wd_alg_common.h"

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT			3
#define CRT_PARAMS_SZ(key_size)		((5 * (key_size)) >> 1)
#define CRT_GEN_PARAMS_SZ(key_size)	((7 * (key_size)) >> 1)
#define GEN_PARAMS_SZ(key_size)		((key_size) << 1)
#define CRT_PARAM_SZ(key_size)		((key_size) >> 1)
#define GET_NEGATIVE(val)		(0 - (val))

typedef void (*wd_rsa_cb_t)(void *cb_param);

struct wd_rsa_req {
	void *src; /* rsa operation input address */
	void *dst; /* rsa operation output address */
	__u32 src_bytes; /* rsa operation input bytes */
	__u32 dst_bytes; /* rsa operation output bytes */
	wd_rsa_cb_t cb;
	void *cb_param;
	int status; /* rsa operation status */
	__u8 data_fmt; /* data format denoted by enum wd_buff_type */
	__u8 op_type; /* rsa operation type */
};

struct wd_rsa_kg_in; /* rsa key generation input parameters */
struct wd_rsa_kg_out; /* rsa key generation output parameters */
struct wd_rsa_pubkey; /* rsa public key */
struct wd_rsa_prikey; /* rsa private key */

/* RSA operational types */
enum wd_rsa_op_type  {
	WD_RSA_INVALID, /* invalid rsa operation */
	WD_RSA_SIGN, /* RSA sign */
	WD_RSA_VERIFY, /* RSA verify */
	WD_RSA_GENKEY, /* RSA key generation */
};

/* RSA key types */
enum wd_rsa_key_type {
	WD_RSA_INVALID_KEY, /* invalid rsa key type */
	WD_RSA_PUBKEY, /* rsa publick key type */
	WD_RSA_PRIKEY1, /* invalid rsa private common key type */
	WD_RSA_PRIKEY2, /* invalid rsa private CRT key type */
};

/* RSA context setting up input parameters from user */
struct wd_rsa_sess_setup {
	__u16 key_bits; /* RSA key bits */
	bool is_crt; /* CRT mode or not */
	int numa;
};

bool wd_rsa_is_crt(handle_t sess);
__u32 wd_rsa_key_bits(handle_t sess);
void wd_rsa_get_pubkey(handle_t sess, struct wd_rsa_pubkey **pubkey);
void wd_rsa_get_prikey(handle_t sess, struct wd_rsa_prikey **prikey);
int wd_rsa_set_pubkey_params(handle_t sess, struct wd_dtb *e, struct wd_dtb *n);
void wd_rsa_get_pubkey_params(struct wd_rsa_pubkey *pbk,
			struct wd_dtb **e, struct wd_dtb **n);
int wd_rsa_set_prikey_params(handle_t sess, struct wd_dtb *d, struct wd_dtb *n);
void wd_rsa_get_prikey_params(struct wd_rsa_prikey *pvk, struct wd_dtb **d,
			struct wd_dtb **n);
int wd_rsa_set_crt_prikey_params(handle_t sess, struct wd_dtb *dq,
			struct wd_dtb *dp,
			struct wd_dtb *qinv,
			struct wd_dtb *q,
			struct wd_dtb *p);
void wd_rsa_get_crt_prikey_params(struct wd_rsa_prikey *pvk,
			struct wd_dtb **dq, struct wd_dtb **dp,
			struct wd_dtb **qinv, struct wd_dtb **q,
			struct wd_dtb **p);

/* APIs For RSA key generate  */
struct wd_rsa_kg_in *wd_rsa_new_kg_in(handle_t sess, struct wd_dtb *e,
			struct wd_dtb *p, struct wd_dtb *q);
void wd_rsa_del_kg_in(handle_t sess, struct wd_rsa_kg_in *ki);
void wd_rsa_get_kg_in_params(struct wd_rsa_kg_in *kin, struct wd_dtb *e,
			struct wd_dtb *q, struct wd_dtb *p);

struct wd_rsa_kg_out *wd_rsa_new_kg_out(handle_t sess);
void wd_rsa_del_kg_out(handle_t sess,  struct wd_rsa_kg_out *kout);
void wd_rsa_get_kg_out_params(struct wd_rsa_kg_out *kout,
			struct wd_dtb *d,
			struct wd_dtb *n);
void wd_rsa_get_kg_out_crt_params(struct wd_rsa_kg_out *kout,
			struct wd_dtb *qinv,
			struct wd_dtb *dq, struct wd_dtb *dp);

int wd_rsa_kg_in_data(struct wd_rsa_kg_in *ki, char **data);
int wd_rsa_kg_out_data(struct wd_rsa_kg_out *ko, char **data);
void wd_rsa_set_kg_out_crt_psz(struct wd_rsa_kg_out *kout,
				    size_t qinv_sz,
				    size_t dq_sz,
				    size_t dp_sz);
void wd_rsa_set_kg_out_psz(struct wd_rsa_kg_out *kout,
				size_t d_sz,
				size_t n_sz);

/**
 * wd_rsa_init() - Initialise ctx configuration and scheduler.
 * @ config:	    User defined ctx configuration.
 * @ sched:	    User defined scheduler.
 */
int wd_rsa_init(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_rsa_uninit() - Un-initialise ctx configuration and scheduler.
 */
void wd_rsa_uninit(void);


/**
 * wd_rsa_alloc_sess() - Allocate a wd rsa session.
 * @setup:	Parameters to setup this session.
 */
handle_t wd_rsa_alloc_sess(struct wd_rsa_sess_setup *setup);

/**
 * wd_rsa_free_sess() - Free  a wd rsa session.
 * @ sess: The sess to be freed.
 */
void wd_rsa_free_sess(handle_t sess);

int wd_do_rsa_async(handle_t sess, struct wd_rsa_req *req);

int wd_rsa_poll(__u32 expt, __u32 *count);

/**
 * wd_do_rsa() - Send a sync rsaression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
int wd_do_rsa_sync(handle_t sess, struct wd_rsa_req *req);

/**
 * wd_do_rsa_async() - Send an async rsaression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
int wd_do_rsa_async(handle_t sess, struct wd_rsa_req *req);

/**
 * wd_rsa_poll() - Poll finished request.
 *
 * This function will call poll_policy function which is registered to wd rsa
 * by user.

__u32 wd_rsa_poll(void);
*/


/**
 * wd_rsa_poll_ctx() - Poll a ctx.
 * @pos:	The ctx idx which will be polled.
 * @expt:	Max number of requests to poll. If 0, polled all finished
 * 		requests in this ctx.
 * @count:	The number of polled requests.
 * Return:	0-succ others-fail.
 *
 * This is a help function which can be used by user's poll_policy function.
 * User defines polling policy in poll_policiy, when it needs to poll a
 * specific ctx, this function should be used.
 */
int wd_rsa_poll_ctx(__u32 idx, __u32 expt, __u32 *count);

/**
 * wd_rsa_env_init() - Init ctx and schedule resources according to wd rsa
 * environment variables.
 *
 * More information, please see docs/wd_environment_variable.
 */
int wd_rsa_env_init(void);

/**
 * wd_rsa_env_uninit() - UnInit ctx and schedule resources set by above init.
 */
void wd_rsa_env_uninit(void);

/**
 * wd_rsa_ctx_num() - request ctx for rsa.
 * @node:       numa node id.
 * @type:       operation type.
 * @num:        ctx number.
 * @mode:       0: sync mode, 1: async mode
 */
int wd_rsa_ctx_num(__u32 node, __u32 type, __u32 num, __u8 mode);

/**
 * wd_rsa_ctx_num_uninit() - UnInit ctx and schedule resources set by above init.
 */
void wd_rsa_ctx_num_uninit(void);

/**
 * wd_rsa_get_evn_param() - query the number of CTXs that meet input attributes.
 * @node:       numa node id.
 * @type:       operation type.
 * @mode:       0: sync mode, 1: async mode
 * @num:        return ctx num.
 * @is_enable   return enable inner poll flag.
 */
int wd_rsa_get_evn_param(__u32 node, __u32 type, __u32 mode,
			 __u32 *num, __u8 *is_enable);

#endif /* __WD_RSA_H */
