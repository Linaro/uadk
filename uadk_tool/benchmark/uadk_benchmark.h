/* SPDX-License-Identifier: Apache-2.0 */
#ifndef UADK_BENCHMARK_H
#define UADK_BENCHMARK_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <sys/time.h>

#define ACC_TST_PRT printf
#define PROCESS_NUM	32
#define THREADS_NUM	64
#define MAX_CTX_NUM	64
#define MAX_TIME_SECONDS	128
#define BYTES_TO_MB	20
#define MAX_OPT_TYPE	6
#define MAX_DATA_SIZE	(15 * 1024 * 1024)
#define MAX_ALG_NAME 64
#define ACC_QUEUE_SIZE	1024

#define MAX_BLOCK_NM		16384 /* BLOCK_NUM must 4 times of POOL_LENTH */
#define MAX_POOL_LENTH		4096
#define MAX_TRY_CNT		5000
#define SEND_USLEEP		100
#define SEC_2_USEC		1000000
#define HASH_ZISE		16

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define SCHED_SINGLE "sched_single"
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define gettid() syscall(__NR_gettid)

/**
 * struct acc_option - Define the test acc app option list.
 * @algclass: 0:cipher 1:digest
 * @acctype: The sub alg type, reference func get_cipher_resource.
 * @syncmode: 0:sync mode 1:async mode
 * @modetype: sva, no-sva, soft mode
 * @optype: enc/dec, comp/decomp
 * @prefetch: write allocated memory to prevent page faults
 * @latency: test packet running time
 */
struct acc_option {
	char algname[64];
	char algclass[64];
	char engine[64];
	u32 algtype;
	u32 modetype;
	u32 optype;
	u32 syncmode;
	u32 pktlen;
	u32 times;
	u32 threads;
	u32 multis;
	u32 ctxnums;
	u32 acctype;
	u32 subtype;
	u32 engine_flag;
	u32 prefetch;
	u32 winsize;
	u32 complevel;
	u32 inittype;
	bool latency;
};

enum acc_type {
	SEC_TYPE,
	HPRE_TYPE,
	ZIP_TYPE,
	TRNG_TYPE,
};

enum acc_init_type {
	INIT_TYPE = 0,
	INIT2_TYPE,
	MAX_TYPE,
};

enum alg_type {
	DEFAULT_TYPE,
	CIPHER_TYPE,
	AEAD_TYPE,
	DIGEST_TYPE,
	RSA_TYPE,
	DH_TYPE,
	ECDH_TYPE,
	ECDSA_TYPE,
	SM2_TYPE,
	X25519_TYPE,
	X448_TYPE,
};

enum sync_type {
	SYNC_MODE,
	ASYNC_MODE,
};

enum test_alg {
	ZLIB, // zlib alg
	GZIP, // gzip
	DEFLATE, // deflate
	LZ77_ZSTD, // lz77_zstd
	RSA_1024, // rsa
	RSA_2048,
	RSA_3072,
	RSA_4096,
	RSA_1024_CRT,
	RSA_2048_CRT,
	RSA_3072_CRT,
	RSA_4096_CRT,
	DH_768, // dh
	DH_1024,
	DH_1536,
	DH_2048,
	DH_3072,
	DH_4096,
	ECDH_256, // ecdh
	ECDH_384,
	ECDH_521,
	ECDSA_256, // ecdsa
	ECDSA_384,
	ECDSA_521,
	SM2_ALG, // sm2, just support key 256
	X25519_ALG, // x25519, just support key 256
	X448_ALG, // x448, just support key 448
	AES_128_ECB, // cipher
	AES_192_ECB,
	AES_256_ECB,
	AES_128_CBC,
	AES_192_CBC,
	AES_256_CBC,
	AES_128_CBC_CS1,
	AES_128_CBC_CS2,
	AES_128_CBC_CS3,
	AES_192_CBC_CS1,
	AES_192_CBC_CS2,
	AES_192_CBC_CS3,
	AES_256_CBC_CS1,
	AES_256_CBC_CS2,
	AES_256_CBC_CS3,
	AES_128_CTR,
	AES_192_CTR,
	AES_256_CTR,
	AES_128_OFB,
	AES_192_OFB,
	AES_256_OFB,
	AES_128_CFB,
	AES_192_CFB,
	AES_256_CFB,
	AES_256_XTS,
	AES_512_XTS,
	DES3_128_ECB,
	DES3_192_ECB,
	DES3_128_CBC,
	DES3_192_CBC,
	SM4_128_ECB,
	SM4_128_CBC,
	SM4_128_CTR,
	SM4_128_OFB,
	SM4_128_CFB,
	SM4_128_XTS,
	SM4_128_XTS_GB,
	AES_128_CCM, // aead
	AES_192_CCM,
	AES_256_CCM,
	AES_128_GCM,
	AES_192_GCM,
	AES_256_GCM,
	AES_128_CBC_SHA256_HMAC,
	AES_192_CBC_SHA256_HMAC,
	AES_256_CBC_SHA256_HMAC,
	SM4_128_CCM,
	SM4_128_GCM,
	SM3_ALG, // digest
	MD5_ALG,
	SHA1_ALG,
	SHA256_ALG,
	SHA224_ALG,
	SHA384_ALG,
	SHA512_ALG,
	SHA512_224,
	SHA512_256, // digest key all set 4 Bytes
	TRNG,
	ALG_MAX,
};

extern void mdelay(u32 ms);
extern int get_pid_cpu_time(u32 *ptime);
extern void cal_perfermance_data(struct acc_option *option, u32 sttime);
extern void time_start(u32 seconds);
extern int get_run_state(void);
extern void set_run_state(int state);
extern void get_rand_data(u8 *addr, u32 size);
extern void add_recv_data(u32 cnt, u32 pkglen);
extern void add_send_complete(void);
extern u32 get_recv_time(void);
extern void cal_avg_latency(u32 count);
extern int get_alg_name(int alg, char *alg_name);

int acc_cmd_parse(int argc, char *argv[], struct acc_option *option);
int acc_default_case(struct acc_option *option);
int acc_option_convert(struct acc_option *option);
int acc_benchmark_run(struct acc_option *option);

#endif /* UADK_BENCHMARK_H */
