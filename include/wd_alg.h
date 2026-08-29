// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_ALG_H
#define __WD_ALG_H
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define handle_t uintptr_t
#define ALG_NAME_SIZE		128
#define DEV_NAME_LEN		128

/*
 * Macros related to arm platform:
 * ARM puts the feature bits for Crypto Extensions in AT_HWCAP2, whereas
 * AArch64 used AT_HWCAP.
 */
#ifndef AT_HWCAP
# define AT_HWCAP               16
#endif

#ifndef AT_HWCAP2
# define AT_HWCAP2              26
#endif

#if defined(__arm__) || defined(__arm)
# define HWCAP                  AT_HWCAP
# define HWCAP_NEON             (1 << 12)

# define HWCAP_CE               AT_HWCAP2
# define HWCAP_CE_AES           (1 << 0)
# define HWCAP_CE_PMULL         (1 << 1)
# define HWCAP_CE_SHA1          (1 << 2)
# define HWCAP_CE_SHA256        (1 << 3)
#elif defined(__aarch64__)
# define HWCAP                  AT_HWCAP
# define HWCAP_NEON             (1 << 1)

# define HWCAP_CE               HWCAP
# define HWCAP_CE_AES           (1 << 3)
# define HWCAP_CE_PMULL         (1 << 4)
# define HWCAP_CE_SHA1          (1 << 5)
# define HWCAP_CE_SHA256        (1 << 6)
# define HWCAP_CPUID            (1 << 11)
# define HWCAP_SHA3             (1 << 17)
# define HWCAP_CE_SM3           (1 << 18)
# define HWCAP_CE_SM4           (1 << 19)
# define HWCAP_CE_SHA512        (1 << 21)
# define HWCAP_SVE              (1 << 22)
/* AT_HWCAP2 */
# define HWCAP2                 26
# define HWCAP2_SVE2            (1 << 1)
# define HWCAP2_RNG             (1 << 16)
#else
/* Define as 0 on non-ARM architectures */
# define HWCAP_CE_SM3           0
# define HWCAP_CE_SM4           0
# define HWCAP_SVE              0
#endif

enum alg_dev_type {
	UADK_ALG_HW,
	UADK_ALG_CE_INSTR,
	UADK_ALG_SVE_INSTR,
	UADK_ALG_SOFT,
	UADK_ALG_NPU,
	UADK_ALG_GPU,
	UADK_ALG_TYPE_MAX,
};

enum alg_drv_type {
	ALG_DRV_HW = 0x0,
	ALG_DRV_CE_INS,
	ALG_DRV_SVE_INS,
	ALG_DRV_SOFT,
	ALG_DRV_INS,
	ALG_DRV_FB,
};

/**
 * struct wd_ctx_alloc_params - Minimal parameters for single context allocation.
 *
 * Used to pass only necessary information to driver's alloc_ctx callback.
 * Keeps driver layer simple and focused.
 *
 * @ctx_mode: CTX_MODE_SYNC or CTX_MODE_ASYNC
 * @op_type: Operation type
 * @bmp: NUMA node bitmask (optional, NULL if not needed)
 */
struct wd_drv_ctx_params {
	__u8 ctx_mode;
	__u8 op_type;
	int numa_id;
	bool epoll_en;
	struct bitmask *bmp;
};

/**
 * @drv_name: name of the current device driver
 * @alg_name: name of the algorithm supported by the driver
 * @priority: priority of the type of algorithm supported by the driver
 *	    the larger the value of priority, the higher the priority of the driver,
 *	    it will be used first when selecting a driver.
 *	    soft calculation can be defined as 0.
 *	    hard calculation can be defined as a value above 100.
 *	    instruction acceleration can define a higher value according to
 *	    the performance situation, such as 400.
 * @calc_type: the calculation method of algorithm supported by the driver
 * @queue_num: number of device queues required by the device to
 *		 execute the algorithm task
 * @op_type_num: number of modes in which the device executes the
 *		 algorithm business and requires queues to be executed separately
 * @priv_size: parameter memory size passed between the internal
 *		 interfaces of the driver
 * @fallback: soft calculation driver handle when performing soft
 *		 calculation supplement
 * @init: callback interface for initializing device drivers
 * @exit: callback interface for destroying device drivers
 * @send: callback interface used to send task packets to
 *	    hardware devices.
 * @recv: callback interface used to retrieve the calculation
 *	    result of the task   packets from the hardware device.
 * @get_usage: callback interface used to obtain the
 *	    utilization rate of devices.
 * @get_extend_ops: callback interface to get private operation of drivers.
 * @alloc_ctx: Allocate contexts for this driver.
 *		HW drivers use wd_hw_alloc_ctx.
 *		Non-HW drivers use wd_drv_alloc_ctx_array.
 * @free_ctx: Release all resources allocated by alloc_ctx.
 */
struct wd_alg_driver {
	const char	*drv_name;
	const char	*alg_name;
	int	priority;
	int	calc_type;
	int	queue_num;
	int	op_type_num;
	int	priv_size;
	int	ops_size;
	int	*drv_data;
	void	*extend_ops;
	handle_t fallback;

	int (*init)(void *conf, void *priv);
	void (*exit)(void *priv);
	int (*send)(handle_t ctx, void *drv_msg);
	int (*recv)(handle_t ctx, void *drv_msg);
	int (*get_usage)(void *param);
	int (*get_extend_ops)(void *ops);

	int  (*alloc_ctx)(char *alg_name, void *params, handle_t *ctx);
	void (*free_ctx)(handle_t ctx);
};

struct hisi_dev_usage {
	struct wd_alg_driver *drv;
	const char *dev_name;
	__u8 alg_op_type;
};

/*
 * wd_alg_driver_register() - Register a device driver.
 * @wd_alg_driver: a device driver that supports an algorithm.
 *
 * Return the execution result, non-zero means error code.
 */
int wd_alg_driver_register(struct wd_alg_driver *drv);
void wd_alg_driver_unregister(struct wd_alg_driver *drv);

#define MAX_DRV_ALG_NUM 64
/**
 * Secondary structure: Algorithm entry (only algorithm-specific attributes)
 * @alg_name: Specific algorithm name, e.g., "cbc(aes)"
 * @avaiblable: Availability depends on specific CE/SVE instructions
 */
struct wd_alg_entry {
	char alg_name[ALG_NAME_SIZE];
	bool available;
};

/**
 * Primary structure: Driver node (List backbone, contains driver-level shared attributes)
 * @drv_name: name of the current device driver e.g., "hisi_sec"
 * @alg_type: Algorithm class, e.g., "cipher" (Promoted to driver level)
 * @available: Indicates whether the current driver still has resources available
 * @priority: priority of the type of algorithm supported by the driver
 * @calc_type: Driver calc type (HW, CE, SVE, SOFT)
 * @refcnt: Driver-level global reference count
 *
 * @drv: Pointer to driver implementation
 * @algs: Static array for supported algorithms
 * @alg_count: Current number of registered algorithms
 * @next: pointer to the next node of the algorithm linked list
 */
struct wd_drv_node {
	char drv_name[DEV_NAME_LEN];
	char alg_type[ALG_NAME_SIZE];
	int priority;
	int calc_type;
	int refcnt;
	struct wd_alg_driver *drv;
	struct wd_alg_entry algs[MAX_DRV_ALG_NUM];
	int alg_count;
	struct wd_drv_node *next;
};

int wd_get_drv_array(const char *alg_type, int task_type, const char *drv_name,
		     struct wd_alg_driver ***drv_array, __u32 *drv_count);
void wd_put_drv_array(struct wd_alg_driver **drv_array, __u32 drv_count);

void wd_alg_drv_ref_inc(struct wd_alg_driver **drv_array, __u32 drv_count);
void wd_alg_drv_ref_dec(struct wd_alg_driver **drv_array, __u32 drv_count);

/**
 * wd_request_drv() - Apply for an algorithm driver.
 * @alg_name: task algorithm name.
 * @drv_type: the type of shield hardware device drivers.
 *
 * Returns the applied algorithm driver, non means error.
 */
struct wd_alg_driver *wd_request_drv(const char	*alg_name, int drv_type);

/**
 * wd_drv_alg_support() - Check the algorithms supported by the driver.
 * @alg_name: task algorithm name.
 * @param: a device queue parameters.
 *
 * Return check result.
 */
bool wd_drv_alg_support(const char *alg_name, void *param);

/**
 * wd_alg_match_drv() - Check if a given algorithm matches a specific driver.
 * @drv: Pointer to the driver instance
 * @alg_name: Specific algorithm name to check (e.g., "cbc(aes)")
 *
 * Return: true if supported and available, false otherwise.
 */
bool wd_alg_match_drv(struct wd_alg_driver *drv, const char *alg_name);

int wd_alg_get_dev_usage(const char *dev_name, const char *alg_type, __u8 op_type);
int wd_get_alg_type(const char *alg_name, char *alg_type);

struct wd_drv_node *wd_get_alg_head(void);

#ifdef WD_STATIC_DRV
/**
 * duplicate drivers will be skipped when it register to alg_list
 */
void hisi_sec2_probe(void);
void hisi_hpre_probe(void);
void hisi_zip_probe(void);
void hisi_dae_probe(void);
void hisi_udma_probe(void);
void hisi_dae_join_gather_probe(void);

void hisi_sec2_remove(void);
void hisi_hpre_remove(void);
void hisi_zip_remove(void);
void hisi_dae_remove(void);
void hisi_udma_remove(void);
void hisi_dae_join_gather_remove(void);

#endif

#ifdef __cplusplus
}
#endif

#endif
