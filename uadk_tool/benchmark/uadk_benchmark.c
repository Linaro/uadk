/* SPDX-License-Identifier: Apache-2.0 */

#include <sys/types.h>
#include <sys/wait.h>
#include "include/wd_alg_common.h"
#include "include/wd_sched.h"

#include "uadk_benchmark.h"
#include "sec_uadk_benchmark.h"
#include "sec_wd_benchmark.h"
#include "sec_soft_benchmark.h"

#include "hpre_uadk_benchmark.h"
#include "hpre_wd_benchmark.h"

#include "zip_uadk_benchmark.h"
#include "zip_wd_benchmark.h"

#include "trng_wd_benchmark.h"

#define TABLE_SPACE_SIZE	8

/*----------------------------------------head struct--------------------------------------------------------*/
static unsigned int g_run_state = 1;
static struct acc_option *g_run_options;
static pthread_mutex_t acc_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct _recv_data {
	double pkg_len;
	u64 send_cnt;
	u64 recv_cnt;
	u32 send_times;
	u32 recv_times;
} g_recv_data;

/* SVA mode and NOSVA mode change need re_insmod driver ko */
enum test_type {
	SVA_MODE = 0x1,
	NOSVA_MODE = 0x2,
	SOFT_MODE = 0x4,
	SVA_SOFT = 0x5,
	NOSVA_SOFT = 0x6,
	INSTR_MODE = 0x7,
	MULTIBUF_MODE = 0x8,
	INVALID_MODE = 0x9,
};

struct acc_sva_item {
	char *name;
	u32 type;
};

static struct acc_sva_item sys_name_item[] = {
	{"sva", SVA_MODE},
	{"nosva", NOSVA_MODE},
	{"soft", SOFT_MODE},
	{"sva-soft", SVA_SOFT},
	{"nosva-soft", NOSVA_SOFT},
	{"instr", INSTR_MODE},
	{"multibuff", MULTIBUF_MODE},
};

struct acc_alg_item {
	char *type;
	char *name;
	int alg;
};

static struct acc_alg_item alg_options[] = {
	{"zlib",		"zlib",			ZLIB},
	{"gzip",		"gzip",			GZIP},
	{"deflate",		"deflate",		DEFLATE},
	{"lz77_zstd",		"lz77_zstd",		LZ77_ZSTD},
	{"rsa",			"rsa-1024",		RSA_1024},
	{"rsa",			"rsa-2048",		RSA_2048},
	{"rsa",			"rsa-3072",		RSA_3072},
	{"rsa",			"rsa-4096",		RSA_4096},
	{"rsa",			"rsa-1024-crt",		RSA_1024_CRT},
	{"rsa",			"rsa-2048-crt",		RSA_2048_CRT},
	{"rsa",			"rsa-3072-crt",		RSA_3072_CRT},
	{"rsa",			"rsa-4096-crt",		RSA_4096_CRT},
	{"dh",			"dh-768",		DH_768},
	{"dh",			"dh-1024",		DH_1024},
	{"dh",			"dh-1536",		DH_1536},
	{"dh",			"dh-2048",		DH_2048},
	{"dh",			"dh-3072",		DH_3072},
	{"dh",			"dh-4096",		DH_4096},
	{"ecdh",		"ecdh-256",		ECDH_256},
	{"ecdh",		"ecdh-384",		ECDH_384},
	{"ecdh",		"ecdh-521",		ECDH_521},
	{"ecdsa",		"ecdsa-256",		ECDSA_256},
	{"ecdsa",		"ecdsa-384",		ECDSA_384},
	{"ecdsa",		"ecdsa-521",		ECDSA_521},
	{"sm2",			"sm2",			SM2_ALG},
	{"x25519",		"x25519",		X25519_ALG},
	{"x448",		"x448",			X448_ALG},
	{"ecb(aes)",		"aes-128-ecb",		AES_128_ECB},
	{"ecb(aes)",		"aes-192-ecb",		AES_192_ECB},
	{"ecb(aes)",		"aes-256-ecb",		AES_256_ECB},
	{"cbc(aes)",		"aes-128-cbc",		AES_128_CBC},
	{"cbc(aes)",		"aes-192-cbc",		AES_192_CBC},
	{"cbc(aes)",		"aes-256-cbc",		AES_256_CBC},
	{"cbc-cs1(aes)",	"aes-128-cbc-cs1",	AES_128_CBC_CS1},
	{"cbc-cs2(aes)",	"aes-128-cbc-cs2",	AES_128_CBC_CS2},
	{"cbc-cs3(aes)",	"aes-128-cbc-cs3",	AES_128_CBC_CS3},
	{"cbc-cs1(aes)",	"aes-192-cbc-cs1",	AES_192_CBC_CS1},
	{"cbc-cs2(aes)",	"aes-192-cbc-cs2",	AES_192_CBC_CS2},
	{"cbc-cs3(aes)",	"aes-192-cbc-cs3",	AES_192_CBC_CS3},
	{"cbc-cs1(aes)",	"aes-256-cbc-cs1",	AES_256_CBC_CS1},
	{"cbc-cs2(aes)",	"aes-256-cbc-cs2",	AES_256_CBC_CS2},
	{"cbc-cs3(aes)",	"aes-256-cbc-cs3",	AES_256_CBC_CS3},
	{"ctr(aes)",		"aes-128-ctr",		AES_128_CTR},
	{"ctr(aes)",		"aes-192-ctr",		AES_192_CTR},
	{"ctr(aes)",		"aes-256-ctr",		AES_256_CTR},
	{"ofb(aes)",		"aes-128-ofb",		AES_128_OFB},
	{"ofb(aes)",		"aes-192-ofb",		AES_192_OFB},
	{"ofb(aes)",		"aes-256-ofb",		AES_256_OFB},
	{"cfb(aes)",		"aes-128-cfb",		AES_128_CFB},
	{"cfb(aes)",		"aes-192-cfb",		AES_192_CFB},
	{"cfb(aes)",		"aes-256-cfb",		AES_256_CFB},
	{"xts(aes)",		"aes-256-xts",		AES_256_XTS},
	{"xts(aes)",		"aes-512-xts",		AES_512_XTS},
	{"ecb(des3_ede)",	"3des-128-ecb",		DES3_128_ECB},
	{"ecb(des3_ede)",	"3des-192-ecb",		DES3_192_ECB},
	{"cbc(des3_ede)",	"3des-128-cbc",		DES3_128_CBC},
	{"cbc(des3_ede)",	"3des-192-cbc",		DES3_192_CBC},
	{"ecb(sm4)",		"sm4-128-ecb",		SM4_128_ECB},
	{"cbc(sm4)",		"sm4-128-cbc",		SM4_128_CBC},
	{"cbc-cs1(sm4)",	"sm4-128-cbc-cs1",	SM4_128_CBC_CS1},
	{"cbc-cs2(sm4)",	"sm4-128-cbc-cs2",	SM4_128_CBC_CS2},
	{"cbc-cs3(sm4)",	"sm4-128-cbc-cs3",	SM4_128_CBC_CS3},
	{"ctr(sm4)",		"sm4-128-ctr",		SM4_128_CTR},
	{"ofb(sm4)",		"sm4-128-ofb",		SM4_128_OFB},
	{"cfb(sm4)",		"sm4-128-cfb",		SM4_128_CFB},
	{"xts(sm4)",		"sm4-128-xts",		SM4_128_XTS},
	{"xts(sm4)",		"sm4-128-xts-gb",	SM4_128_XTS_GB},
	{"ccm(aes)",		"aes-128-ccm",		AES_128_CCM},
	{"ccm(aes)",		"aes-192-ccm",		AES_192_CCM},
	{"ccm(aes)",		"aes-256-ccm",		AES_256_CCM},
	{"gcm(aes)",		"aes-128-gcm",		AES_128_GCM},
	{"gcm(aes)",		"aes-192-gcm",		AES_192_GCM},
	{"gcm(aes)",		"aes-256-gcm",		AES_256_GCM},
	{"authenc(hmac(sha256),cbc(aes))", "aes-128-cbc-sha256-hmac", AES_128_CBC_SHA256_HMAC},
	{"authenc(hmac(sha256),cbc(aes))", "aes-192-cbc-sha256-hmac", AES_192_CBC_SHA256_HMAC},
	{"authenc(hmac(sha256),cbc(aes))", "aes-256-cbc-sha256-hmac", AES_256_CBC_SHA256_HMAC},
	{"ccm(sm4)",		"sm4-128-ccm",		SM4_128_CCM},
	{"gcm(sm4)",		"sm4-128-gcm",		SM4_128_GCM},
	{"sm3",			"sm3",			SM3_ALG},
	{"md5",			"md5",			MD5_ALG},
	{"sha1",		"sha1",			SHA1_ALG},
	{"sha256",		"sha256",		SHA256_ALG},
	{"sha224",		"sha224",		SHA224_ALG},
	{"sha384",		"sha384",		SHA384_ALG},
	{"sha512",		"sha512",		SHA512_ALG},
	{"sha512-224",		"sha512-224",		SHA512_224},
	{"sha512-256",		"sha512-256",		SHA512_256},
	{"trng",		"trng",			TRNG},
	{"",			"",			ALG_MAX}
};

/*-------------------------------------tool code------------------------------------------------------*/
void add_send_complete(void)
{
	__atomic_add_fetch(&g_recv_data.send_times, 1, __ATOMIC_RELAXED);
}

void add_recv_data(u32 cnt, u32 pkglen)
{
	pthread_mutex_lock(&acc_mutex);
	g_recv_data.recv_cnt += cnt;
	if (g_recv_data.pkg_len == 0)
		g_recv_data.pkg_len = pkglen;
	else
		g_recv_data.pkg_len = ((double)pkglen + g_recv_data.pkg_len) / 2;
	g_recv_data.recv_times++;
	pthread_mutex_unlock(&acc_mutex);
}

u32 get_recv_time(void)
{
	return g_recv_data.recv_times;
}

void init_recv_data(void)
{
	g_recv_data.send_cnt = 0;
	g_recv_data.recv_cnt = 0;
	g_recv_data.pkg_len = 0.0;
	g_recv_data.send_times = 0;
	g_recv_data.recv_times = 0;
}

int get_run_state(void)
{
	return g_run_state;
}

void set_run_state(int state)
{
	g_run_state = state;
}

static int get_alg_type(const char *alg_name)
{
	int alg = ALG_MAX;
	int i;

	for (i = 0; i < ALG_MAX; i++) {
		if (strcmp(alg_name, alg_options[i].name) == 0) {
			alg = alg_options[i].alg;
			break;
		}
	}

	return alg;
}

int get_alg_name(int alg, char *alg_name)
{
	int i;

	for (i = 0; i < ALG_MAX; i++) {
		if (alg == alg_options[i].alg) {
			strcpy(alg_name, alg_options[i].type);
			return 0;
		}
	}

	return -EINVAL;
}

static int get_mode_type(const char *mode_name)
{
	u32 modetype = INVALID_MODE;
	int i;

	for (i = 0; i < ARRAY_SIZE(sys_name_item); i++) {
		if (strcmp(mode_name, sys_name_item[i].name) == 0) {
			modetype = sys_name_item[i].type;
			break;
		}
	}

	return modetype;
}

int get_pid_cpu_time(u32 *ptime)
{
	u64 caltime[8] = {0};
	int pid = getpid();
	char dev_path[64];
	char buf[256];
	int i, fd, ret, bgidx;

	memset(dev_path, 0, 64);
	snprintf(dev_path, 64, "/proc/%d/stat", pid);
	fd = open(dev_path, O_RDONLY, 0);
	if (fd < 0) {
		printf("open cpu dir fail!\n");
		*ptime = 0;
		return -1;
	}

	memset(buf, 0, 256);
	ret = read(fd, buf, 255);
	if (ret <= 0) {
		printf("read data fail!\n");
		*ptime = 0;
		return -1;
	}
	close(fd);

	bgidx = 13; // process time data begin with index 13
	for (i = 0; i < ret; i++) {
		if (buf[i] == ' ') {
			bgidx--;
			if (bgidx == 0)
				break;
		}
	}
	ret = sscanf(&buf[i], "%llu %llu %llu %llu", &caltime[0], &caltime[1],
		&caltime[2], &caltime[3]);
	*ptime = caltime[0] + caltime[1] + caltime[2] + caltime[3];

	return 0;
}

static void alarm_end(int sig)
{
	if (sig == SIGALRM) {
		set_run_state(0);
		alarm(0);
	}
	signal(SIGALRM, alarm_end);
	alarm(1);
}

void time_start(u32 seconds)
{
	set_run_state(1);
	init_recv_data();
	signal(SIGALRM, alarm_end);
	alarm(seconds);
}

void get_rand_data(u8 *addr, u32 size)
{
	unsigned short rand_state[3] = {
		(0xae >> 16) & 0xffff, 0xae & 0xffff, 0x330e};
	static __thread u64 rand_seed = 0x330eabcd;
	u64 rand48 = 0;
	int i;

	// only 32bit valid, other 32bit is zero
	for (i = 0; i < size >> 3; i++) {
		rand_state[0] = (u16)rand_seed;
		rand_state[1] = (u16)(rand_seed >> 16);
		rand48 = nrand48(rand_state);
		*((u64 *)addr + i) = rand48;
		rand_seed = rand48;
	}
}

void cal_avg_latency(u32 count)
{
	double latency;

	if (!g_run_options || !g_run_options->latency)
		return;

	latency = (double)g_run_options->times * SEC_2_USEC / count;
	ACC_TST_PRT("thread<%lu> avg latency: %.1fus\n", gettid(), latency);
}

void segmentfault_handler(int sig)
{
#define BUF_SZ 64
	void *array[BUF_SZ];
	size_t size;

	/* Get void*'s for all entries on the stack */
	size = backtrace(array, BUF_SZ);

	/* Print out all the frames to stderr */
	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(array, size, STDERR_FILENO);
	exit(1);
}

/*-------------------------------------main code------------------------------------------------------*/
static void parse_alg_param(struct acc_option *option)
{
	switch(option->algtype) {
	case ZLIB:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "zlib");
		option->acctype = ZIP_TYPE;
		option->subtype = DEFAULT_TYPE;
		break;
	case GZIP:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "gzip");
		option->acctype = ZIP_TYPE;
		option->subtype = DEFAULT_TYPE;
		break;
	case DEFLATE:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "deflate");
		option->acctype = ZIP_TYPE;
		option->subtype = DEFAULT_TYPE;
		break;
	case LZ77_ZSTD:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "lz77_zstd");
		option->acctype = ZIP_TYPE;
		option->subtype = DEFAULT_TYPE;
		break;
	case SM2_ALG:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "sm2");
		option->acctype = HPRE_TYPE;
		option->subtype = SM2_TYPE;
		break;
	case X25519_ALG:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "x25519");
		option->acctype = HPRE_TYPE;
		option->subtype = X25519_TYPE;
		break;
	case X448_ALG:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "x448");
		option->acctype = HPRE_TYPE;
		option->subtype = X448_TYPE;
		break;
	case TRNG:
		snprintf(option->algclass, MAX_ALG_NAME, "%s", "trng");
		option->acctype = TRNG_TYPE;
		option->subtype = DEFAULT_TYPE;
		break;
	default:
		if (option->algtype <= RSA_4096_CRT) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "rsa");
			option->acctype = HPRE_TYPE;
			option->subtype = RSA_TYPE;
		} else if (option->algtype <= DH_4096) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "dh");
			option->acctype = HPRE_TYPE;
			option->subtype = DH_TYPE;
		} else if (option->algtype <= ECDH_521) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "ecdh");
			option->acctype = HPRE_TYPE;
			option->subtype = ECDH_TYPE;
		} else if (option->algtype <= ECDSA_521) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "ecdsa");
			option->acctype = HPRE_TYPE;
			option->subtype = ECDSA_TYPE;
		} else if (option->algtype <= SM4_128_XTS_GB) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "cipher");
			if (option->modetype == INSTR_MODE)
				option->subtype = CIPHER_INSTR_TYPE;
			else
				option->subtype = CIPHER_TYPE;
			option->acctype = SEC_TYPE;
		} else if (option->algtype <= SM4_128_GCM) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "aead");
			option->acctype = SEC_TYPE;
			option->subtype = AEAD_TYPE;
		} else if (option->algtype <= SHA512_256) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "digest");
			option->subtype = DIGEST_TYPE;
			option->acctype = SEC_TYPE;
			if (option->modetype == INSTR_MODE) {
				option->sched_type = SCHED_POLICY_NONE;
				option->task_type = TASK_INSTR;
			} else if (option->modetype == MULTIBUF_MODE) {
				option->sched_type = SCHED_POLICY_SINGLE;
				option->task_type = TASK_INSTR;
			}
		}
	}
}

void cal_perfermance_data(struct acc_option *option, u32 sttime)
{
	u8 palgname[MAX_ALG_NAME];
	char *unit = "KiB/s";
	double perfermance;
	double cpu_rate;
	u32 ttime = 1000;
	double perfdata;
	double perfops;
	double ops;
	u32 ptime;
	int i, len;

	get_pid_cpu_time(&ptime);

	while(ttime) {
		if (option->syncmode == SYNC_MODE) {
			if (get_recv_time() == option->threads)
				break;
		} else {
			if (get_recv_time() == 1)
				break;
		}
		usleep(1000);
		ttime--;
	}

	memset(palgname, ' ', MAX_ALG_NAME);
	len = strlen(option->algname);
	for (i = 0; i < len; i++) {
		palgname[i] = option->algname[i];
	}
	if (len <= TABLE_SPACE_SIZE)
		palgname[TABLE_SPACE_SIZE] = '\0';
	else
		palgname[i] = '\0';

	ptime = ptime - sttime;
	cpu_rate = (double)ptime / option->times;

	perfdata = g_recv_data.pkg_len * g_recv_data.recv_cnt / 1024.0;
	perfermance = perfdata / option->times;

	perfops = g_recv_data.recv_cnt / 1000.0;
	ops = perfops / option->times;

	ACC_TST_PRT("algname:\tlength:\t\tperf:\t\tiops:\t\tCPU_rate:\n"
		    "%s\t%-2uBytes \t%.2f%s\t%.1fKops \t%.2f%%\n",
		    palgname, option->pktlen, perfermance, unit, ops, cpu_rate);
}

static int benchmark_run(struct acc_option *option)
{
	int ret = 0;

	switch(option->acctype) {
	case SEC_TYPE:
		if ((option->modetype == SVA_MODE) ||
		    (option->modetype == INSTR_MODE) ||
		    (option->modetype == MULTIBUF_MODE)) {
			ret = sec_uadk_benchmark(option);
		} else if (option->modetype == NOSVA_MODE) {
			ret = sec_wd_benchmark(option);
		}
		usleep(20000);
#ifdef HAVE_CRYPTO
		if (option->modetype == SOFT_MODE) {
			ret = sec_soft_benchmark(option);
		}
#endif
		break;
	case HPRE_TYPE:
		if (option->modetype == SVA_MODE) {
			ret = hpre_uadk_benchmark(option);
		} else if (option->modetype == NOSVA_MODE) {
			ret = hpre_wd_benchmark(option);
		}
		break;
	case ZIP_TYPE:
		if (option->modetype == SVA_MODE) {
			ret = zip_uadk_benchmark(option);
		} else if (option->modetype == NOSVA_MODE) {
			ret = zip_wd_benchmark(option);
		}
		break;
	case TRNG_TYPE:
		if (option->modetype == SVA_MODE)
			ACC_TST_PRT("TRNG not support sva mode..\n");
		else if (option->modetype == NOSVA_MODE)
			ret = trng_wd_benchmark(option);

		break;
	}

	return ret;
}

static void dump_param(struct acc_option *option)
{
	ACC_TST_PRT("    [--algname]: %s\n", option->algname);
	ACC_TST_PRT("    [--mode]:    %u\n", option->modetype);
	ACC_TST_PRT("    [--optype]:  %u\n", option->optype);
	ACC_TST_PRT("    [--syncmode]:%u\n", option->syncmode);
	ACC_TST_PRT("    [--pktlen]:  %u\n", option->pktlen);
	ACC_TST_PRT("    [--seconds]: %u\n", option->times);
	ACC_TST_PRT("    [--thread]:  %u\n", option->threads);
	ACC_TST_PRT("    [--multi]:   %u\n", option->multis);
	ACC_TST_PRT("    [--ctxnum]:  %u\n", option->ctxnums);
	ACC_TST_PRT("    [--algclass]:%s\n", option->algclass);
	ACC_TST_PRT("    [--acctype]: %u\n", option->acctype);
	ACC_TST_PRT("    [--prefetch]:%u\n", option->prefetch);
	ACC_TST_PRT("    [--engine]:  %s\n", option->engine);
	ACC_TST_PRT("    [--latency]: %u\n", option->latency);
	ACC_TST_PRT("    [--init2]:   %u\n", option->inittype);
	ACC_TST_PRT("    [--device]:  %s\n", option->device);
}

int acc_benchmark_run(struct acc_option *option)
{
	int nr_children = 0;
	pid_t *pids, pid;
	int i, ret = 0;
	int status;

	option->sched_type = SCHED_POLICY_RR;
	option->task_type = TASK_HW;
	parse_alg_param(option);
	dump_param(option);
	g_run_options = option;

	pthread_mutex_init(&acc_mutex, NULL);
	if (option->multis <= 1) {
		ret = benchmark_run(option);
		return ret;
	}

	pids = calloc(option->multis, sizeof(pid_t));
	if (!pids)
		return -ENOMEM;

	for (i = 0; i < option->multis; i++) {
		pid = fork();
		if (pid < 0) {
			ACC_TST_PRT("acc cannot fork: %d\n", errno);
			break;
		} else if (pid > 0) {
			/* Parent */
			pids[nr_children++] = pid;
			continue;
		}

		/* Child */
		exit(benchmark_run(option));
	}

	ACC_TST_PRT("%d children uadk_benchmark spawned\n", nr_children);
	for (i = 0; i < nr_children; i++) {
		pid = pids[i];

		ret = waitpid(pid, &status, 0);
		if (ret < 0) {
			ACC_TST_PRT("wait(pid=%d) error %d\n", pid, errno);
			continue;
		}

		if (WIFEXITED(status)) {
			ret = WEXITSTATUS(status);
			if (ret) {
				ACC_TST_PRT("child %d returned with %d\n", pid, ret);
			}
		} else if (WIFSIGNALED(status)) {
			ret = WTERMSIG(status);
			ACC_TST_PRT("child %d killed by sig %d\n", pid, ret);
		} else {
			ACC_TST_PRT("unexpected status for child %d\n", pid);
		}
	}
	free(pids);

	return ret;
}

int acc_default_case(struct acc_option *option)
{
	ACC_TST_PRT("Test sec Cipher parameter default, alg: aes-128-cbc, set_times:3,"
			"set_pktlen:1024 bytes, sync mode, one process, one thread.\n");

	strcpy(option->algname, "aes-128-cbc");
	option->algtype = AES_128_CBC;
	option->syncmode = SYNC_MODE;
	option->modetype = SVA_MODE;
	option->optype = 0;
	option->pktlen = 1024;
	option->times = 3;
	option->threads = 1;
	option->multis = 1;
	option->ctxnums = 2;
	option->inittype = INIT_TYPE;

	return acc_benchmark_run(option);
}

static void print_help(void)
{
	ACC_TST_PRT("NAME\n");
	ACC_TST_PRT("    benchmark: test UADK acc performance,etc\n");
	ACC_TST_PRT("USAGE\n");
	ACC_TST_PRT("    benchmark [--alg aes-128-cbc] [--alg rsa-2048]\n");
	ACC_TST_PRT("    benchmark [--mode] [--pktlen] [--keylen] [--seconds]\n");
	ACC_TST_PRT("    benchmark [--multi] [--sync] [--async] [--help]\n");
	ACC_TST_PRT("    numactl --cpubind=0  --membind=0,1 ./uadk_benchmark xxxx\n");
	ACC_TST_PRT("        specify numa nodes for cpu and memory\n");
	ACC_TST_PRT("DESCRIPTION\n");
	ACC_TST_PRT("    [--alg aes-128-cbc ]:\n");
	ACC_TST_PRT("        The name of the algorithm for benchmarking\n");
	ACC_TST_PRT("    [--mode sva/nosva/soft/sva-soft/nosva-soft/instr/multibuff]: start UADK or Warpdrive or Openssl or Instruction mode test\n");
	ACC_TST_PRT("    [--sync/--async]: start asynchronous/synchronous mode test\n");
	ACC_TST_PRT("    [--opt 0,1,2,3,4,5]:\n");
	ACC_TST_PRT("        SEC: cipher,aead: 0/1:encryption/decryption; digest: 0/1:normal/hmac\n");
	ACC_TST_PRT("        ZIP: 0~1:block compression, block decompression; 2~3:stream compression, stream decompression\n");
	ACC_TST_PRT("        HPRE: 0~5:keygen, key compute, Enc, Dec, Sign, Verify\n");
	ACC_TST_PRT("    [--pktlen]:\n");
	ACC_TST_PRT("        set the length of BD message in bytes\n");
	ACC_TST_PRT("    [--seconds]:\n");
	ACC_TST_PRT("        set the test times\n");
	ACC_TST_PRT("    [--multi]:\n");
	ACC_TST_PRT("        set the number of threads\n");
	ACC_TST_PRT("    [--thread]:\n");
	ACC_TST_PRT("        set the number of threads\n");
	ACC_TST_PRT("    [--ctxnum]:\n");
	ACC_TST_PRT("        the number of QP queues used by the entire test task\n");
	ACC_TST_PRT("    [--prefetch]:\n");
	ACC_TST_PRT("        in SVA mode, Enable prefetch can reduce page faults and improve performance\n");
	ACC_TST_PRT("    [--engine]:\n");
	ACC_TST_PRT("        set the test openssl engine\n");
	ACC_TST_PRT("    [--alglist]:\n");
	ACC_TST_PRT("        list the all support alg\n");
	ACC_TST_PRT("    [--latency]:\n");
	ACC_TST_PRT("        test the running time of packets\n");
	ACC_TST_PRT("    [--init2]:\n");
	ACC_TST_PRT("        select init2 mode in the init interface of UADK SVA\n");
	ACC_TST_PRT("    [--device]:\n");
	ACC_TST_PRT("        select device to do task\n");
	ACC_TST_PRT("    [--help]  = usage\n");
	ACC_TST_PRT("Example\n");
	ACC_TST_PRT("    ./uadk_tool benchmark --alg aes-128-cbc --mode sva --opt 0 --sync\n");
	ACC_TST_PRT("    	     --pktlen 1024 --seconds 1 --multi 1 --thread 1 --ctxnum 2\n");
	ACC_TST_PRT("UPDATE:2022-3-28\n");
}

static void print_support_alg(void)
{
	int i;

	ACC_TST_PRT("UADK benchmark supported ALG:\n");
	for (i = 0; i < ALG_MAX; i++) {
		ACC_TST_PRT("%s\n", alg_options[i].name);
	}
}

int acc_cmd_parse(int argc, char *argv[], struct acc_option *option)
{
	int option_index = 0;
	int c;

	static struct option long_options[] = {
		{"help",	no_argument,		0, 0},
		{"alg",		required_argument,	0, 1},
		{"mode",	required_argument,	0, 2},
		{"opt",		required_argument,	0, 3},
		{"sync",	no_argument,		0, 4},
		{"async",	no_argument,		0, 5},
		{"pktlen",	required_argument,	0, 6},
		{"seconds",	required_argument,	0, 7},
		{"thread",	required_argument,	0, 8},
		{"multi",	required_argument,	0, 9},
		{"ctxnum",	required_argument,	0, 10},
		{"prefetch",	no_argument,		0, 11},
		{"engine",	required_argument,	0, 12},
		{"alglist",	no_argument,		0, 13},
		{"latency",	no_argument,		0, 14},
		{"winsize",	required_argument,	0, 15},
		{"complevel",	required_argument,	0, 16},
		{"init2",	no_argument,		0, 17},
		{"device",	required_argument,	0, 18},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			print_help();
			goto to_exit;
		case 1:
			option->algtype = get_alg_type(optarg);
			strcpy(option->algname, optarg);
			break;
		case 2:
			option->modetype = get_mode_type(optarg);
			break;
		case 3:
			option->optype = strtol(optarg, NULL, 0);
			break;
		case 4:
			option->syncmode = SYNC_MODE;
			break;
		case 5:
			option->syncmode = ASYNC_MODE;
			break;
		case 6:
			option->pktlen = strtol(optarg, NULL, 0);
			break;
		case 7:
			option->times = strtol(optarg, NULL, 0);
			break;
		case 8:
			option->threads = strtol(optarg, NULL, 0);
			break;
		case 9:
			option->multis = strtol(optarg, NULL, 0);
			break;
		case 10:
			option->ctxnums = strtol(optarg, NULL, 0);
			break;
		case 11:
			option->prefetch = 1;
			break;
		case 12:
			strcpy(option->engine, optarg);
			break;
		case 13:
			print_support_alg();
			goto to_exit;
		case 14:
			option->latency = true;
			break;
		case 15:
			option->winsize = strtol(optarg, NULL, 0);
			break;
		case 16:
			option->complevel = strtol(optarg, NULL, 0);
			break;
		case 17:
			option->inittype = INIT2_TYPE;
			break;
		case 18:
			if (strlen(optarg) >= MAX_DEVICE_NAME) {
				ACC_TST_PRT("invalid: device name is %s\n", optarg);
				goto to_exit;
			}
			strcpy(option->device, optarg);
			break;
		default:
			ACC_TST_PRT("invalid: bad input parameter!\n");
			print_help();
			goto to_exit;
		}
	}

	return 0;

to_exit:
	return -EINVAL;
}

int acc_option_convert(struct acc_option *option)
{
	if (option->algtype >= ALG_MAX) {
		ACC_TST_PRT("invalid: input algname is wrong!\n");
		goto param_err;
	}

	if (option->modetype >= INVALID_MODE)
		goto param_err;

	if (option->optype >= MAX_OPT_TYPE)
		goto param_err;

	/* Min test package size is 64Bytes */
	if (option->pktlen > MAX_DATA_SIZE)
		goto param_err;
	else if (option->pktlen < 16)
		option->pktlen = 16;

	if (option->times > MAX_TIME_SECONDS) {
		ACC_TST_PRT("uadk benchmark max test times to 128 seconds\n");
		goto param_err;
	} else if (!option->times)
		option->times = 3;

	if (option->threads > THREADS_NUM) {
		ACC_TST_PRT("uadk benchmark max threads is 64\n");
		goto param_err;
	} else if (!option->threads)
		option->threads = 3;

	if (option->multis > PROCESS_NUM) {
		ACC_TST_PRT("uadk benchmark max process is 32\n");
		goto param_err;
	} else if (!option->multis)
		option->multis = 1;

	if (option->ctxnums > MAX_CTX_NUM) {
		ACC_TST_PRT("uadk benchmark every process max ctx num is 64\n");
		goto param_err;
	} else if (!option->ctxnums)
		option->ctxnums = 1;

	option->engine_flag = true;
	if (!strlen(option->engine)) {
		option->engine_flag = false;
		return 0;
	} else if (strcmp(option->engine, "uadk_engine")) {
		option->engine_flag = false;
		ACC_TST_PRT("uadk benchmark just support engine: uadk_engine\n");
		goto param_err;
	}

	if (option->syncmode == ASYNC_MODE && option->latency) {
		ACC_TST_PRT("uadk benchmark async mode can't test latency\n");
		goto param_err;
	}

	if (option->inittype == INIT2_TYPE && option->modetype != SVA_MODE) {
		ACC_TST_PRT("uadk benchmark No-SVA mode can't use init2\n");
		goto param_err;
	}

	return 0;

param_err:
	ACC_TST_PRT("input parameter error, please input --help\n");
	return -EINVAL;
}
