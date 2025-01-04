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
#endif

enum alg_dev_type {
	UADK_ALG_SOFT = 0x0,
	UADK_ALG_CE_INSTR = 0x1,
	UADK_ALG_SVE_INSTR = 0x2,
	UADK_ALG_HW = 0x3
};

enum alg_drv_mode {
	UADK_DRV_NORMAL = 0x0,
	UADK_DRV_SYNCONLY = 0x1,
};

/*
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
 * @priv: pointer of priv ctx
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
 */
struct wd_alg_driver {
	const char	*drv_name;
	const char	*alg_name;
	int	priority;
	int	calc_type;
	int	mode;
	int	queue_num;
	int	op_type_num;
	void	*priv;
	handle_t fallback;

	int (*init)(struct wd_alg_driver *drv, void *conf);
	void (*exit)(struct wd_alg_driver *drv);
	int (*send)(struct wd_alg_driver *drv, handle_t ctx, void *drv_msg);
	int (*recv)(struct wd_alg_driver *drv, handle_t ctx, void *drv_msg);
	int (*get_usage)(void *param);
	int (*get_extend_ops)(void *ops);
};

inline int wd_alg_driver_init(struct wd_alg_driver *drv, void *conf)
{
	return drv->init(drv, conf);
}

inline void wd_alg_driver_exit(struct wd_alg_driver *drv)
{
	drv->exit(drv);
}

inline int wd_alg_driver_send(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	return drv->send(drv, ctx, msg);
}

inline int wd_alg_driver_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	return drv->recv(drv, ctx, msg);
}

/*
 * wd_alg_driver_register() - Register a device driver.
 * @wd_alg_driver: a device driver that supports an algorithm.
 *
 * Return the execution result, non-zero means error code.
 */
int wd_alg_driver_register(struct wd_alg_driver *drv);
void wd_alg_driver_unregister(struct wd_alg_driver *drv);

/*
 * @alg_name: name of the algorithm supported by the driver
 * @drv_name: name of the current device driver
 * @available: Indicates whether the current driver still has resources available
 * @priority: priority of the type of algorithm supported by the driver
 * @calc_type: the calculation method of algorithm supported by the driver
 * @refcnt: the number of times the algorithm driver is being cited by the task
 *
 * @drv: device Drivers Supporting Algorithms
 * @next: pointer to the next node of the algorithm linked list
 */
struct wd_alg_list {
	char alg_name[ALG_NAME_SIZE];
	char drv_name[DEV_NAME_LEN];
	bool available;
	int	priority;
	int	calc_type;
	int	refcnt;

	struct wd_alg_driver *drv;
	struct wd_alg_list *next;
};

/*
 * wd_request_drv() - Apply for an algorithm driver.
 * @alg_name: task algorithm name.
 * @hw_mask: the flag of shield hardware device drivers.
 *
 * Returns the applied algorithm driver, non means error.
 */
struct wd_alg_driver *wd_request_drv(const char	*alg_name, bool hw_mask);
void wd_release_drv(struct wd_alg_driver *drv);

/*
 * wd_drv_alg_support() - Check the algorithms supported by the driver.
 * @alg_name: task algorithm name.
 * @drv: a device driver that supports an algorithm.
 *
 * Return check result.
 */
bool wd_drv_alg_support(const char *alg_name,
	struct wd_alg_driver *drv);

/*
 * wd_enable_drv() - Re-enable use of the current device driver.
 * @drv: a device driver that supports an algorithm.
 */
void wd_enable_drv(struct wd_alg_driver *drv);
void wd_disable_drv(struct wd_alg_driver *drv);
struct wd_alg_driver *wd_find_drv(char *drv_name, char *alg_name, int idx);

struct wd_alg_list *wd_get_alg_head(void);

#ifdef WD_STATIC_DRV
/*
 * duplicate drivers will be skipped when it register to alg_list
 */
void hisi_sec2_probe(void);
void hisi_hpre_probe(void);
void hisi_zip_probe(void);
void hisi_dae_probe(void);

void hisi_sec2_remove(void);
void hisi_hpre_remove(void);
void hisi_zip_remove(void);
void hisi_dae_remove(void);

#endif

#ifdef __cplusplus
}
#endif

#endif
