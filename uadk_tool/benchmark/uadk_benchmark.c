/* SPDX-License-Identifier: Apache-2.0 */

#include <sys/types.h>
#include <sys/wait.h>

#include "uadk_benchmark.h"
#include "sec_uadk_benchmark.h"
#include "sec_wd_benchmark.h"
#include "sec_soft_benchmark.h"

#include "hpre_uadk_benchmark.h"
#include "hpre_wd_benchmark.h"

#include "zip_uadk_benchmark.h"
#include "zip_wd_benchmark.h"

#define TABLE_SPACE_SIZE	8

/*----------------------------------------head struct--------------------------------------------------------*/
static unsigned int g_run_state = 1;
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
	INVALID_MODE = 0x8,
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
};

struct acc_alg_item {
	char *name;
	int alg;
};

static struct acc_alg_item alg_options[] = {
	{"zlib",   ZLIB},
	{"gzip",   GZIP},
	{"deflate",    DEFLATE},
	{"lz77_zstd", LZ77_ZSTD},
	{"rsa-1024",    RSA_1024},
	{"rsa-2048",    RSA_2048},
	{"rsa-3072",    RSA_3072},
	{"rsa-4096",    RSA_4096},
	{"rsa-1024-crt", RSA_1024_CRT},
	{"rsa-2048-crt", RSA_2048_CRT},
	{"rsa-3072-crt", RSA_3072_CRT},
	{"rsa-4096-crt", RSA_4096_CRT},
	{"dh-768", DH_768},
	{"dh-1024",    DH_1024},
	{"dh-1536",    DH_1536},
	{"dh-2048", DH_2048},
	{"dh-3072",    DH_3072},
	{"dh-4096",    DH_4096},
	{"ecdh-256",    ECDH_256},
	{"ecdh-384",    ECDH_384},
	{"ecdh-521",    ECDH_521},
	{"ecdsa-256",    ECDSA_256},
	{"ecdsa-384",    ECDSA_384},
	{"ecdsa-521",    ECDSA_521},
	{"sm2",    SM2_ALG},
	{"x25519",    X25519_ALG},
	{"x448",    X448_ALG},
	{"aes-128-ecb", AES_128_ECB},
	{"aes-192-ecb", AES_192_ECB},
	{"aes-256-ecb", AES_256_ECB},
	{"aes-128-cbc", AES_128_CBC},
	{"aes-192-cbc", AES_192_CBC},
	{"aes-256-cbc", AES_256_CBC},
	{"aes-128-ctr", AES_128_CTR},
	{"aes-192-ctr", AES_192_CTR},
	{"aes-256-ctr", AES_256_CTR},
	{"aes-128-ofb", AES_128_OFB},
	{"aes-192-ofb", AES_192_OFB},
	{"aes-256-ofb", AES_256_OFB},
	{"aes-128-cfb", AES_128_CFB},
	{"aes-192-cfb", AES_192_CFB},
	{"aes-256-cfb", AES_256_CFB},
	{"aes-256-xts", AES_256_XTS},
	{"aes-512-xts", AES_512_XTS},
	{"3des-128-ecb", DES3_128_ECB},
	{"3des-192-ecb", DES3_192_ECB},
	{"3des-128-cbc", DES3_128_CBC},
	{"3des-192-cbc", DES3_192_CBC},
	{"sm4-128-ecb", SM4_128_ECB},
	{"sm4-128-cbc", SM4_128_CBC},
	{"sm4-128-ctr", SM4_128_CTR},
	{"sm4-128-ofb", SM4_128_OFB},
	{"sm4-128-cfb", SM4_128_CFB},
	{"sm4-128-xts", SM4_128_XTS},
	{"aes-128-ccm", AES_128_CCM},
	{"aes-192-ccm", AES_192_CCM},
	{"aes-256-ccm", AES_256_CCM},
	{"aes-128-gcm", AES_128_GCM},
	{"aes-192-gcm", AES_192_GCM},
	{"aes-256-gcm", AES_256_GCM},
	{"sm4-128-ccm", SM4_128_CCM},
	{"sm4-128-gcm", SM4_128_GCM},
	{"sm3",    SM3_ALG},
	{"md5",    MD5_ALG},
	{"sha1",    SHA1_ALG},
	{"sha256",    SHA256_ALG},
	{"sha224",    SHA224_ALG},
	{"sha384",    SHA384_ALG},
	{"sha512",    SHA512_ALG},
	{"sha512-224",    SHA512_224},
	{"sha512-256",    SHA512_256},
	{"", ALG_MAX}
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
			alg = 	alg_options[i].alg;
			break;
		}
	}

	return alg;
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

void mdelay(u32 ms)
{
	int clock_tcy = 2600000000; // 2.6Ghz CPU;
	int i;

	while(ms) {
		i++;
		if (i == clock_tcy)
			ms--;
	}
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
	int i;

#if 1
	// only 32bit valid, other 32bit is zero
	for (i = 0; i < size >> 3; i++)
		*((u64 *)addr + i) = nrand48(rand_state);
#else
	// full 64bit valid
	for (i = 0; i < size >> 2; i++)
		*((u32 *)addr + i) = nrand48(rand_state);
#endif
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
		} else if (option->algtype <= SM4_128_XTS) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "cipher");
			option->acctype = SEC_TYPE;
			option->subtype = CIPHER_TYPE;
		} else if (option->algtype <= SM4_128_GCM) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "aead");
			option->acctype = SEC_TYPE;
			option->subtype = AEAD_TYPE;
		} else if (option->algtype <= SHA512_256) {
			snprintf(option->algclass, MAX_ALG_NAME, "%s", "digest");
			option->acctype = SEC_TYPE;
			option->subtype = DIGEST_TYPE;
		}
	}
}

void cal_perfermance_data(struct acc_option *option, u32 sttime)
{
	u8 palgname[MAX_ALG_NAME];
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
		} else { // ASYNC_MODE
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
	perfdata = g_recv_data.pkg_len * g_recv_data.recv_cnt / 1024.0;
	perfops = (double)(g_recv_data.recv_cnt) / 1000.0;
	perfermance = perfdata / option->times;
	ops = perfops / option->times;
	cpu_rate = (double)ptime / option->times;
	ACC_TST_PRT("algname:	length:		perf:		iops:		CPU_rate:\n"
			"%s	%-2uBytes 	%.1fKB/s 	%.1fKops 	%.2f%%\n",
			palgname, option->pktlen, perfermance, ops, cpu_rate);
}

static int benchmark_run(struct acc_option *option)
{
	int ret = 0;

	switch(option->acctype) {
	case SEC_TYPE:
		if (option->modetype & SVA_MODE) {
			ret = sec_uadk_benchmark(option);
		} else if (option->modetype & NOSVA_MODE) {
			ret = sec_wd_benchmark(option);
		}
		usleep(20000);
#ifdef WITH_OPENSSL_DIR
		if (option->modetype & SOFT_MODE) {
			ret = sec_soft_benchmark(option);
		}
#endif
		break;
	case HPRE_TYPE:
		if (option->modetype & SVA_MODE) {
			ret = hpre_uadk_benchmark(option);
		} else if (option->modetype & NOSVA_MODE) {
			ret = hpre_wd_benchmark(option);
		}
		break;
	case ZIP_TYPE:
		if (option->modetype & SVA_MODE) {
			ret = zip_uadk_benchmark(option);
		} else if (option->modetype & NOSVA_MODE) {
			ret = zip_wd_benchmark(option);
		}
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
}

int acc_benchmark_run(struct acc_option *option)
{
	int nr_children = 0;
	pid_t *pids, pid;
	int i, ret = 0;
	int status;

	ACC_TST_PRT("start UADK benchmark test.\n");
	parse_alg_param(option);
	dump_param(option);

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

	return	 acc_benchmark_run(option);
}

static void print_help(void)
{
	ACC_TST_PRT("NAME\n");
	ACC_TST_PRT("    uadk_tool benchmark: test UADK acc performance,etc\n");
	ACC_TST_PRT("USAGE\n");
	ACC_TST_PRT("    uadk_tool benchmark [--alg aes-128-cbc] [--alg rsa-2048]\n");
	ACC_TST_PRT("    uadk_tool benchmark [--mode] [--pktlen] [--keylen] [--seconds]\n");
	ACC_TST_PRT("    uadk_tool benchmark [--multi] [--sync] [--async] [--help]\n");
	ACC_TST_PRT("    numactl --cpubind=0  --membind=0,1 ./uadk_tool benchmark xxxx\n");
	ACC_TST_PRT("        specify numa nodes for cpu and memory\n");
	ACC_TST_PRT("DESCRIPTION\n");
	ACC_TST_PRT("    [--alg aes-128-cbc ]:\n");
	ACC_TST_PRT("        The name of the algorithm for benchmarking\n");
	ACC_TST_PRT("    [--mode sva/nosva/soft/sva-soft/nosva-soft]: start UADK or Warpdrive or Openssl mode test\n");
	ACC_TST_PRT("    [--sync/--async]: start asynchronous/synchronous mode test\n");
	ACC_TST_PRT("    [--opt 0,1,2,3,4,5]:\n");
	ACC_TST_PRT("        SEC/ZIP: 0/1:encryption/decryption or compression/decompression\n");
	ACC_TST_PRT("        HPRE: 0~5:keygen, key compute, Enc, Dec, Sign, Verify\n");
	ACC_TST_PRT("    [--pktlen]:\n");
	ACC_TST_PRT("        set the length of BD message in bytes\n");
	ACC_TST_PRT("    [--seconds]:\n");
	ACC_TST_PRT("        set the test times\n");
	ACC_TST_PRT("    [--multi]:\n");
	ACC_TST_PRT("        set the number of process\n");
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
	ACC_TST_PRT("    [--help]  = usage\n");
	ACC_TST_PRT("Example\n");
	ACC_TST_PRT("    ./uadk_tool benchmark --alg aes-128-cbc --mode sva --opt 0 --sync\n");
	ACC_TST_PRT("    	     --pktlen 1024 --seconds 1 --multi 1 --thread 1 --ctxnum 4\n");
	ACC_TST_PRT("UPDATE:2022-7-18\n");
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
		{"alg",       required_argument, 0, 2},
		{"mode",      required_argument, 0, 3},
		{"opt",       required_argument, 0, 4},
		{"sync",      no_argument,       0, 5},
		{"async",     no_argument,       0, 6},
		{"pktlen",    required_argument, 0, 7},
		{"seconds",   required_argument, 0, 8},
		{"thread",    required_argument, 0, 9},
		{"multi",     required_argument, 0, 10},
		{"ctxnum",    required_argument, 0, 11},
		{"prefetch",     no_argument,    0, 12},
		{"engine",    required_argument, 0, 13},
		{"alglist",      no_argument,    0, 14},
		{"help",      no_argument,       0, 15},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 2:
			option->algtype = get_alg_type(optarg);
			strcpy(option->algname, optarg);
			break;
		case 3:
			option->modetype = get_mode_type(optarg);
			break;
		case 4:
			option->optype = strtol(optarg, NULL, 0);
			break;
		case 5:
			option->syncmode = SYNC_MODE;
			break;
		case 6:
			option->syncmode = ASYNC_MODE;
			break;
		case 7:
			option->pktlen = strtol(optarg, NULL, 0);
			break;
		case 8:
			option->times = strtol(optarg, NULL, 0);
			break;
		case 9:
			option->threads = strtol(optarg, NULL, 0);
			break;
		case 10:
			option->multis = strtol(optarg, NULL, 0);
			break;
		case 11:
			option->ctxnums = strtol(optarg, NULL, 0);
			break;
		case 12:
			option->prefetch = 1;
			break;
		case 13:
			strcpy(option->engine, optarg);
			break;
		case 14:
			print_support_alg();
			goto to_exit;
		case 15:
			print_help();
			goto to_exit;
		default:
			ACC_TST_PRT("bad input test parameter!\n");
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
	} else if (strcmp(option->engine, "uadk")) {
		option->engine_flag = false;
		ACC_TST_PRT("uadk benchmark just support engine: uadk\n");
		goto param_err;
	}

	return 0;

param_err:
	ACC_TST_PRT("input parameter error, please input --help\n");
	return -EINVAL;
}
