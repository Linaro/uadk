/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_malloc_heap.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_string_fns.h>
#ifdef RTE_LIBRTE_IXGBE_PMD
#include <rte_pmd_ixgbe.h>
#endif
#ifdef RTE_LIBRTE_PDUMP
#include <rte_pdump.h>
#endif
#include <rte_flow.h>
#include <rte_metrics.h>
#ifdef RTE_LIBRTE_BITRATE
#include <rte_bitrate.h>
#endif
#ifdef RTE_LIBRTE_LATENCY_STATS
#include <rte_latencystats.h>
#endif

#include "testpmd.h"

#include "../../../warpdrive/wd.h"
#include "../../../warpdrive/wd_rsa.h"
#include "../../../warpdrive/wd_dh.h"
#include "../../../warpdrive/wd_bmm.h"


int testpmd_fd_copy = 500; /* the copy of STDIN_FILENO */

#ifndef MAP_HUGETLB
/* FreeBSD may not have MAP_HUGETLB (in fact, it probably doesn't) */
#define HUGE_FLAG (0x40000)
#else
#define HUGE_FLAG MAP_HUGETLB
#endif

#ifndef MAP_HUGE_SHIFT
/* older kernels (or FreeBSD) will not have this define */
#define HUGE_SHIFT (26)
#else
#define HUGE_SHIFT MAP_HUGE_SHIFT
#endif

#define EXTMEM_HEAP_NAME "extmem"
#define MULTIPLE_PROCESS_HANDLE

uint16_t verbose_level = 0; /**< Silent by default. */
int testpmd_logtype; /**< Log type for testpmd logs */

/* use master core for command line ? */
uint8_t interactive = 0;
uint8_t auto_start = 0;
uint8_t tx_first;
char cmdline_filename[PATH_MAX] = {0};

/*
 * NUMA support configuration.
 * When set, the NUMA support attempts to dispatch the allocation of the
 * RX and TX memory rings, and of the DMA memory buffers (mbufs) for the
 * probed ports among the CPU sockets 0 and 1.
 * Otherwise, all memory is allocated from CPU socket 0.
 */
uint8_t numa_support = 1; /**< numa enabled by default */

/*
 * In UMA mode,all memory is allocated from socket 0 if --socket-num is
 * not configured.
 */
uint8_t socket_num = UMA_NO_CONFIG;

/*
 * Select mempool allocation type:
 * - native: use regular DPDK memory
 * - anon: use regular DPDK memory to create mempool, but populate using
 *         anonymous memory (may not be IOVA-contiguous)
 * - xmem: use externally allocated hugepage memory
 */
uint8_t mp_alloc_type = MP_ALLOC_NATIVE;

/*
 * Store specified sockets on which memory pool to be used by ports
 * is allocated.
 */
uint8_t port_numa[RTE_MAX_ETHPORTS];

/*
 * Store specified sockets on which RX ring to be used by ports
 * is allocated.
 */
uint8_t rxring_numa[RTE_MAX_ETHPORTS];

int proc_id = 0;
unsigned num_procs = 1;

/*
 * Store specified sockets on which TX ring to be used by ports
 * is allocated.
 */
uint8_t txring_numa[RTE_MAX_ETHPORTS];

/*
 * Record the Ethernet address of peer target ports to which packets are
 * forwarded.
 * Must be instantiated with the ethernet addresses of peer traffic generator
 * ports.
 */
struct rte_ether_addr peer_eth_addrs[RTE_MAX_ETHPORTS];
portid_t nb_peer_eth_addrs = 0;

/*
 * Probed Target Environment.
 */
struct rte_port *ports;	       /**< For all probed ethernet ports. */
portid_t nb_ports;             /**< Number of probed ethernet ports. */
struct fwd_lcore **fwd_lcores; /**< For all probed logical cores. */
lcoreid_t nb_lcores;           /**< Number of probed logical cores. */

portid_t ports_ids[RTE_MAX_ETHPORTS]; /**< Store all port ids. */

/*
 * Test Forwarding Configuration.
 *    nb_fwd_lcores <= nb_cfg_lcores <= nb_lcores
 *    nb_fwd_ports  <= nb_cfg_ports  <= nb_ports
 */
lcoreid_t nb_cfg_lcores; /**< Number of configured logical cores. */
lcoreid_t nb_fwd_lcores; /**< Number of forwarding logical cores. */
portid_t  nb_cfg_ports;  /**< Number of configured ports. */
portid_t  nb_fwd_ports;  /**< Number of forwarding ports. */

unsigned int fwd_lcores_cpuids[RTE_MAX_LCORE]; /**< CPU ids configuration. */
portid_t fwd_ports_ids[RTE_MAX_ETHPORTS];      /**< Port ids configuration. */

struct fwd_stream **fwd_streams; /**< For each RX queue of each port. */
streamid_t nb_fwd_streams;       /**< Is equal to (nb_ports * nb_rxq). */

/*
 * Forwarding engines.
 */
struct fwd_engine * fwd_engines[] = {
	&io_fwd_engine,
	&mac_fwd_engine,
	&mac_swap_engine,
	&flow_gen_engine,
	&rx_only_engine,
	&tx_only_engine,
	&csum_fwd_engine,
	&icmp_echo_engine,
	&noisy_vnf_engine,
#if defined RTE_LIBRTE_PMD_SOFTNIC
	&softnic_fwd_engine,
#endif
#ifdef RTE_LIBRTE_IEEE1588
	&ieee1588_fwd_engine,
#endif
	NULL,
};

struct rte_mempool *mempools[RTE_MAX_NUMA_NODES];
uint16_t mempool_flags;

struct fwd_config cur_fwd_config;
struct fwd_engine *cur_fwd_eng = &io_fwd_engine; /**< IO mode by default. */
uint32_t retry_enabled;
uint32_t burst_tx_delay_time = BURST_TX_WAIT_US;
uint32_t burst_tx_retry_num = BURST_TX_RETRIES;

uint16_t mbuf_data_size = DEFAULT_MBUF_DATA_SIZE; /**< Mbuf data space size. */
uint32_t param_total_num_mbufs = 0;  /**< number of mbufs in all pools - if
                                      * specified on command-line. */
uint16_t stats_period; /**< Period to show statistics (disabled by default) */

/*
 * In container, it cannot terminate the process which running with 'stats-period'
 * option. Set flag to exit stats period loop after received SIGINT/SIGTERM.
 */
uint8_t f_quit;

/*
 * Configuration of packet segments used by the "txonly" processing engine.
 */
uint16_t tx_pkt_length = TXONLY_DEF_PACKET_LEN; /**< TXONLY packet length. */
uint16_t tx_pkt_seg_lengths[RTE_MAX_SEGS_PER_PKT] = {
	TXONLY_DEF_PACKET_LEN,
};
uint8_t  tx_pkt_nb_segs = 1; /**< Number of segments in TXONLY packets */

enum tx_pkt_split tx_pkt_split = TX_PKT_SPLIT_OFF;
/**< Split policy for packets to TX. */

uint8_t txonly_multi_flow;
/**< Whether multiple flows are generated in TXONLY mode. */

uint16_t nb_pkt_per_burst = DEF_PKT_BURST; /**< Number of packets per burst. */
uint16_t mb_mempool_cache = DEF_MBUF_CACHE; /**< Size of mbuf mempool cache. */

/* current configuration is in DCB or not,0 means it is not in DCB mode */
uint8_t dcb_config = 0;

/* Whether the dcb is in testing status */
uint8_t dcb_test = 0;

/*
 * Configurable number of RX/TX queues.
 */
queueid_t nb_rxq = 1; /**< Number of RX queues per port. */
queueid_t nb_txq = 1; /**< Number of TX queues per port. */

/*
 * Configurable number of RX/TX ring descriptors.
 * Defaults are supplied by drivers via ethdev.
 */
#define RTE_TEST_RX_DESC_DEFAULT 0
#define RTE_TEST_TX_DESC_DEFAULT 0
uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT; /**< Number of RX descriptors. */
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT; /**< Number of TX descriptors. */

#define RTE_PMD_PARAM_UNSET -1
/*
 * Configurable values of RX and TX ring threshold registers.
 */

int8_t rx_pthresh = RTE_PMD_PARAM_UNSET;
int8_t rx_hthresh = RTE_PMD_PARAM_UNSET;
int8_t rx_wthresh = RTE_PMD_PARAM_UNSET;

int8_t tx_pthresh = RTE_PMD_PARAM_UNSET;
int8_t tx_hthresh = RTE_PMD_PARAM_UNSET;
int8_t tx_wthresh = RTE_PMD_PARAM_UNSET;

/*
 * Configurable value of RX free threshold.
 */
int16_t rx_free_thresh = RTE_PMD_PARAM_UNSET;

/*
 * Configurable value of RX drop enable.
 */
int8_t rx_drop_en = RTE_PMD_PARAM_UNSET;

/*
 * Configurable value of TX free threshold.
 */
int16_t tx_free_thresh = RTE_PMD_PARAM_UNSET;

/*
 * Configurable value of TX RS bit threshold.
 */
int16_t tx_rs_thresh = RTE_PMD_PARAM_UNSET;

/*
 * Configurable value of buffered packets before sending.
 */
uint16_t noisy_tx_sw_bufsz;

/*
 * Configurable value of packet buffer timeout.
 */
uint16_t noisy_tx_sw_buf_flush_time;

/*
 * Configurable value for size of VNF internal memory area
 * used for simulating noisy neighbour behaviour
 */
uint64_t noisy_lkup_mem_sz;

/*
 * Configurable value of number of random writes done in
 * VNF simulation memory area.
 */
uint64_t noisy_lkup_num_writes;

/*
 * Configurable value of number of random reads done in
 * VNF simulation memory area.
 */
uint64_t noisy_lkup_num_reads;

/*
 * Configurable value of number of random reads/writes done in
 * VNF simulation memory area.
 */
uint64_t noisy_lkup_num_reads_writes;

/*
 * Receive Side Scaling (RSS) configuration.
 */
uint64_t rss_hf = ETH_RSS_IP; /* RSS IP by default. */

/*
 * Port topology configuration
 */
uint16_t port_topology = PORT_TOPOLOGY_PAIRED; /* Ports are paired by default */

/*
 * Avoids to flush all the RX streams before starts forwarding.
 */
uint8_t no_flush_rx = 0; /* flush by default */

/*
 * Flow API isolated mode.
 */
uint8_t flow_isolate_all;

/*
 * Avoids to check link status when starting/stopping a port.
 */
uint8_t no_link_check = 0; /* check by default */

/*
 * Don't automatically start all ports in interactive mode.
 */
uint8_t no_device_start = 0;

/*
 * Enable link status change notification
 */
uint8_t lsc_interrupt = 1; /* enabled by default */

/*
 * Enable device removal notification.
 */
uint8_t rmv_interrupt = 1; /* enabled by default */

uint8_t hot_plug = 0; /**< hotplug disabled by default. */

/* After attach, port setup is called on event or by iterator */
bool setup_on_probe_event = true;

/* Pretty printing of ethdev events */
static const char * const eth_event_desc[] = {
	[RTE_ETH_EVENT_UNKNOWN] = "unknown",
	[RTE_ETH_EVENT_INTR_LSC] = "link state change",
	[RTE_ETH_EVENT_QUEUE_STATE] = "queue state",
	[RTE_ETH_EVENT_INTR_RESET] = "reset",
	[RTE_ETH_EVENT_VF_MBOX] = "VF mbox",
	[RTE_ETH_EVENT_IPSEC] = "IPsec",
	[RTE_ETH_EVENT_MACSEC] = "MACsec",
	[RTE_ETH_EVENT_INTR_RMV] = "device removal",
	[RTE_ETH_EVENT_NEW] = "device probed",
	[RTE_ETH_EVENT_DESTROY] = "device released",
	[RTE_ETH_EVENT_MAX] = NULL,
};

/*
 * Display or mask ether events
 * Default to all events except VF_MBOX
 */
uint32_t event_print_mask = (UINT32_C(1) << RTE_ETH_EVENT_UNKNOWN) |
			    (UINT32_C(1) << RTE_ETH_EVENT_INTR_LSC) |
			    (UINT32_C(1) << RTE_ETH_EVENT_QUEUE_STATE) |
			    (UINT32_C(1) << RTE_ETH_EVENT_INTR_RESET) |
			    (UINT32_C(1) << RTE_ETH_EVENT_IPSEC) |
			    (UINT32_C(1) << RTE_ETH_EVENT_MACSEC) |
			    (UINT32_C(1) << RTE_ETH_EVENT_INTR_RMV);
/*
 * Decide if all memory are locked for performance.
 */
int do_mlockall = 0;

/*
 * NIC bypass mode configuration options.
 */

#if defined RTE_LIBRTE_IXGBE_PMD && defined RTE_LIBRTE_IXGBE_BYPASS
/* The NIC bypass watchdog timeout. */
uint32_t bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_OFF;
#endif


#ifdef RTE_LIBRTE_LATENCY_STATS

/*
 * Set when latency stats is enabled in the commandline
 */
uint8_t latencystats_enabled;

/*
 * Lcore ID to serive latency statistics.
 */
lcoreid_t latencystats_lcore_id = -1;

#endif

/*
 * Ethernet device configuration.
 */
struct rte_eth_rxmode rx_mode = {
	.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		/**< Default maximum frame length. */
};

struct rte_eth_txmode tx_mode = {
	.offloads = DEV_TX_OFFLOAD_MBUF_FAST_FREE,
};

struct rte_fdir_conf fdir_conf = {
	.mode = RTE_FDIR_MODE_NONE,
	.pballoc = RTE_FDIR_PBALLOC_64K,
	.status = RTE_FDIR_REPORT_STATUS,
	.mask = {
		.vlan_tci_mask = 0xFFEF,
		.ipv4_mask     = {
			.src_ip = 0xFFFFFFFF,
			.dst_ip = 0xFFFFFFFF,
		},
		.ipv6_mask     = {
			.src_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
			.dst_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
		},
		.src_port_mask = 0xFFFF,
		.dst_port_mask = 0xFFFF,
		.mac_addr_byte_mask = 0xFF,
		.tunnel_type_mask = 1,
		.tunnel_id_mask = 0xFFFFFFFF,
	},
	.drop_queue = 127,
};

volatile int test_done = 1; /* stop packet forwarding when set to 1. */

struct queue_stats_mappings tx_queue_stats_mappings_array[MAX_TX_QUEUE_STATS_MAPPINGS];
struct queue_stats_mappings rx_queue_stats_mappings_array[MAX_RX_QUEUE_STATS_MAPPINGS];

struct queue_stats_mappings *tx_queue_stats_mappings = tx_queue_stats_mappings_array;
struct queue_stats_mappings *rx_queue_stats_mappings = rx_queue_stats_mappings_array;

uint16_t nb_tx_queue_stats_mappings = 0;
uint16_t nb_rx_queue_stats_mappings = 0;

/*
 * Display zero values by default for xstats
 */
uint8_t xstats_hide_zero;

unsigned int num_sockets = 0;
unsigned int socket_ids[RTE_MAX_NUMA_NODES];

#ifdef RTE_LIBRTE_BITRATE
/* Bitrate statistics */
struct rte_stats_bitrates *bitrate_data;
lcoreid_t bitrate_lcore_id;
uint8_t bitrate_enabled;
#endif

struct gro_status gro_ports[RTE_MAX_ETHPORTS];
uint8_t gro_flush_cycles = GRO_DEFAULT_FLUSH_CYCLES;

struct vxlan_encap_conf vxlan_encap_conf = {
	.select_ipv4 = 1,
	.select_vlan = 0,
	.select_tos_ttl = 0,
	.vni = "\x00\x00\x00",
	.udp_src = 0,
	.udp_dst = RTE_BE16(4789),
	.ipv4_src = RTE_IPV4(127, 0, 0, 1),
	.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
	.ipv6_src = "\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x01",
	.ipv6_dst = "\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x11\x11",
	.vlan_tci = 0,
	.ip_tos = 0,
	.ip_ttl = 255,
	.eth_src = "\x00\x00\x00\x00\x00\x00",
	.eth_dst = "\xff\xff\xff\xff\xff\xff",
};

struct nvgre_encap_conf nvgre_encap_conf = {
	.select_ipv4 = 1,
	.select_vlan = 0,
	.tni = "\x00\x00\x00",
	.ipv4_src = RTE_IPV4(127, 0, 0, 1),
	.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
	.ipv6_src = "\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x01",
	.ipv6_dst = "\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x11\x11",
	.vlan_tci = 0,
	.eth_src = "\x00\x00\x00\x00\x00\x00",
	.eth_dst = "\xff\xff\xff\xff\xff\xff",
};

/* Forward function declarations */
static void setup_attached_port(portid_t pi);
static void map_port_queue_stats_mapping_registers(portid_t pi,
						   struct rte_port *port);
static void check_all_ports_link_status(uint32_t port_mask);
static int eth_event_callback(portid_t port_id,
			      enum rte_eth_event_type type,
			      void *param, void *ret_param);
static void dev_event_callback(const char *device_name,
				enum rte_dev_event_type type,
				void *param);

/*
 * Check if all the ports are started.
 * If yes, return positive value. If not, return zero.
 */
static int all_ports_started(void);

struct gso_status gso_ports[RTE_MAX_ETHPORTS];
uint16_t gso_max_segment_size = RTE_ETHER_MAX_LEN - RTE_ETHER_CRC_LEN;

/*
 * Helper function to check if socket is already discovered.
 * If yes, return positive value. If not, return zero.
 */
int
new_socket_id(unsigned int socket_id)
{
	unsigned int i;

	for (i = 0; i < num_sockets; i++) {
		if (socket_ids[i] == socket_id)
			return 0;
	}
	return 1;
}

/*
 * Setup default configuration.
 */
static void
set_default_fwd_lcores_config(void)
{
	unsigned int i;
	unsigned int nb_lc;
	unsigned int sock_num;

	nb_lc = 0;
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;
		sock_num = rte_lcore_to_socket_id(i);
		if (new_socket_id(sock_num)) {
			if (num_sockets >= RTE_MAX_NUMA_NODES) {
				rte_exit(EXIT_FAILURE,
					 "Total sockets greater than %u\n",
					 RTE_MAX_NUMA_NODES);
			}
			socket_ids[num_sockets++] = sock_num;
		}
		if (i == rte_get_master_lcore())
			continue;
		fwd_lcores_cpuids[nb_lc++] = i;
	}
	nb_lcores = (lcoreid_t) nb_lc;
	nb_cfg_lcores = nb_lcores;
	nb_fwd_lcores = 1;
}

static void
set_def_peer_eth_addrs(void)
{
	portid_t i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		peer_eth_addrs[i].addr_bytes[0] = RTE_ETHER_LOCAL_ADMIN_ADDR;
		peer_eth_addrs[i].addr_bytes[5] = i;
	}
}

static void
set_default_fwd_ports_config(void)
{
	portid_t pt_id;
	int i = 0;

	RTE_ETH_FOREACH_DEV(pt_id) {
		fwd_ports_ids[i++] = pt_id;

		/* Update sockets info according to the attached device */
		int socket_id = rte_eth_dev_socket_id(pt_id);
		if (socket_id >= 0 && new_socket_id(socket_id)) {
			if (num_sockets >= RTE_MAX_NUMA_NODES) {
				rte_exit(EXIT_FAILURE,
					 "Total sockets greater than %u\n",
					 RTE_MAX_NUMA_NODES);
			}
			socket_ids[num_sockets++] = socket_id;
		}
	}

	nb_cfg_ports = nb_ports;
	nb_fwd_ports = nb_ports;
}

void
set_def_fwd_config(void)
{
	set_default_fwd_lcores_config();
	set_def_peer_eth_addrs();
	set_default_fwd_ports_config();
}

/* extremely pessimistic estimation of memory required to create a mempool */
static int
calc_mem_size(uint32_t nb_mbufs, uint32_t mbuf_sz, size_t pgsz, size_t *out)
{
	unsigned int n_pages, mbuf_per_pg, leftover;
	uint64_t total_mem, mbuf_mem, obj_sz;

	/* there is no good way to predict how much space the mempool will
	 * occupy because it will allocate chunks on the fly, and some of those
	 * will come from default DPDK memory while some will come from our
	 * external memory, so just assume 128MB will be enough for everyone.
	 */
	uint64_t hdr_mem = 128 << 20;

	/* account for possible non-contiguousness */
	obj_sz = rte_mempool_calc_obj_size(mbuf_sz, 0, NULL);
	if (obj_sz > pgsz) {
		TESTPMD_LOG(ERR, "Object size is bigger than page size\n");
		return -1;
	}

	mbuf_per_pg = pgsz / obj_sz;
	leftover = (nb_mbufs % mbuf_per_pg) > 0;
	n_pages = (nb_mbufs / mbuf_per_pg) + leftover;

	mbuf_mem = n_pages * pgsz;

	total_mem = RTE_ALIGN(hdr_mem + mbuf_mem, pgsz);

	if (total_mem > SIZE_MAX) {
		TESTPMD_LOG(ERR, "Memory size too big\n");
		return -1;
	}
	*out = (size_t)total_mem;

	return 0;
}

static int
pagesz_flags(uint64_t page_sz)
{
	/* as per mmap() manpage, all page sizes are log2 of page size
	 * shifted by MAP_HUGE_SHIFT
	 */
	int log2 = rte_log2_u64(page_sz);

	return (log2 << HUGE_SHIFT);
}

static void *
alloc_mem(size_t memsz, size_t pgsz, bool huge)
{
	void *addr;
	int flags;

	/* allocate anonymous hugepages */
	flags = MAP_ANONYMOUS | MAP_PRIVATE;
	if (huge)
		flags |= HUGE_FLAG | pagesz_flags(pgsz);

	addr = mmap(NULL, memsz, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (addr == MAP_FAILED)
		return NULL;

	return addr;
}

struct extmem_param {
	void *addr;
	size_t len;
	size_t pgsz;
	rte_iova_t *iova_table;
	unsigned int iova_table_len;
};

static int
create_extmem(uint32_t nb_mbufs, uint32_t mbuf_sz, struct extmem_param *param,
		bool huge)
{
	uint64_t pgsizes[] = {RTE_PGSIZE_2M, RTE_PGSIZE_1G, /* x86_64, ARM */
			RTE_PGSIZE_16M, RTE_PGSIZE_16G};    /* POWER */
	unsigned int cur_page, n_pages, pgsz_idx;
	size_t mem_sz, cur_pgsz;
	rte_iova_t *iovas = NULL;
	void *addr;
	int ret;

	for (pgsz_idx = 0; pgsz_idx < RTE_DIM(pgsizes); pgsz_idx++) {
		/* skip anything that is too big */
		if (pgsizes[pgsz_idx] > SIZE_MAX)
			continue;

		cur_pgsz = pgsizes[pgsz_idx];

		/* if we were told not to allocate hugepages, override */
		if (!huge)
			cur_pgsz = sysconf(_SC_PAGESIZE);

		ret = calc_mem_size(nb_mbufs, mbuf_sz, cur_pgsz, &mem_sz);
		if (ret < 0) {
			TESTPMD_LOG(ERR, "Cannot calculate memory size\n");
			return -1;
		}

		/* allocate our memory */
		addr = alloc_mem(mem_sz, cur_pgsz, huge);

		/* if we couldn't allocate memory with a specified page size,
		 * that doesn't mean we can't do it with other page sizes, so
		 * try another one.
		 */
		if (addr == NULL)
			continue;

		/* store IOVA addresses for every page in this memory area */
		n_pages = mem_sz / cur_pgsz;

		iovas = malloc(sizeof(*iovas) * n_pages);

		if (iovas == NULL) {
			TESTPMD_LOG(ERR, "Cannot allocate memory for iova addresses\n");
			goto fail;
		}
		/* lock memory if it's not huge pages */
		if (!huge)
			mlock(addr, mem_sz);

		/* populate IOVA addresses */
		for (cur_page = 0; cur_page < n_pages; cur_page++) {
			rte_iova_t iova;
			size_t offset;
			void *cur;

			offset = cur_pgsz * cur_page;
			cur = RTE_PTR_ADD(addr, offset);

			/* touch the page before getting its IOVA */
			*(volatile char *)cur = 0;

			iova = rte_mem_virt2iova(cur);

			iovas[cur_page] = iova;
		}

		break;
	}
	/* if we couldn't allocate anything */
	if (iovas == NULL)
		return -1;

	param->addr = addr;
	param->len = mem_sz;
	param->pgsz = cur_pgsz;
	param->iova_table = iovas;
	param->iova_table_len = n_pages;

	return 0;
fail:
	if (iovas)
		free(iovas);
	if (addr)
		munmap(addr, mem_sz);

	return -1;
}

static int
setup_extmem(uint32_t nb_mbufs, uint32_t mbuf_sz, bool huge)
{
	struct extmem_param param;
	int socket_id, ret;

	memset(&param, 0, sizeof(param));

	/* check if our heap exists */
	socket_id = rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
	if (socket_id < 0) {
		/* create our heap */
		ret = rte_malloc_heap_create(EXTMEM_HEAP_NAME);
		if (ret < 0) {
			TESTPMD_LOG(ERR, "Cannot create heap\n");
			return -1;
		}
	}

	ret = create_extmem(nb_mbufs, mbuf_sz, &param, huge);
	if (ret < 0) {
		TESTPMD_LOG(ERR, "Cannot create memory area\n");
		return -1;
	}

	/* we now have a valid memory area, so add it to heap */
	ret = rte_malloc_heap_memory_add(EXTMEM_HEAP_NAME,
			param.addr, param.len, param.iova_table,
			param.iova_table_len, param.pgsz);

	/* when using VFIO, memory is automatically mapped for DMA by EAL */

	/* not needed any more */
	free(param.iova_table);

	if (ret < 0) {
		TESTPMD_LOG(ERR, "Cannot add memory to heap\n");
		munmap(param.addr, param.len);
		return -1;
	}

	/* success */

	TESTPMD_LOG(DEBUG, "Allocated %zuMB of external memory\n",
			param.len >> 20);

	return 0;
}
static void
dma_unmap_cb(struct rte_mempool *mp __rte_unused, void *opaque __rte_unused,
	     struct rte_mempool_memhdr *memhdr, unsigned mem_idx __rte_unused)
{
	uint16_t pid = 0;
	int ret;

	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_eth_dev *dev =
			&rte_eth_devices[pid];

		ret = rte_dev_dma_unmap(dev->device, memhdr->addr, 0,
					memhdr->len);
		if (ret) {
			TESTPMD_LOG(DEBUG,
				    "unable to DMA unmap addr 0x%p "
				    "for device %s\n",
				    memhdr->addr, dev->data->name);
		}
	}
	ret = rte_extmem_unregister(memhdr->addr, memhdr->len);
	if (ret) {
		TESTPMD_LOG(DEBUG,
			    "unable to un-register addr 0x%p\n", memhdr->addr);
	}
}

static void
dma_map_cb(struct rte_mempool *mp __rte_unused, void *opaque __rte_unused,
	   struct rte_mempool_memhdr *memhdr, unsigned mem_idx __rte_unused)
{
	uint16_t pid = 0;
	size_t page_size = sysconf(_SC_PAGESIZE);
	int ret;

	ret = rte_extmem_register(memhdr->addr, memhdr->len, NULL, 0,
				  page_size);
	if (ret) {
		TESTPMD_LOG(DEBUG,
			    "unable to register addr 0x%p\n", memhdr->addr);
		return;
	}
	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_eth_dev *dev =
			&rte_eth_devices[pid];

		ret = rte_dev_dma_map(dev->device, memhdr->addr, 0,
				      memhdr->len);
		if (ret) {
			TESTPMD_LOG(DEBUG,
				    "unable to DMA map addr 0x%p "
				    "for device %s\n",
				    memhdr->addr, dev->data->name);
		}
	}
}

/*
 * Configuration initialisation done once at init time.
 */
static struct rte_mempool *
mbuf_pool_create(uint16_t mbuf_seg_size, unsigned nb_mbuf,
		 unsigned int socket_id)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *rte_mp = NULL;
	uint32_t mb_size;

	mb_size = sizeof(struct rte_mbuf) + mbuf_seg_size;
	mbuf_poolname_build(socket_id, pool_name, sizeof(pool_name));

	TESTPMD_LOG(INFO,
		"create a new mbuf pool <%s>: n=%u, size=%u, socket=%u\n",
		pool_name, nb_mbuf, mbuf_seg_size, socket_id);

	switch (mp_alloc_type) {
	case MP_ALLOC_NATIVE:
		{
			/* wrapper to rte_mempool_create() */
			TESTPMD_LOG(INFO, "preferred mempool ops selected: %s\n",
					rte_mbuf_best_mempool_ops());
#ifdef MULTIPLE_PROCESS_HANDLE
			if (rte_eal_process_type() == RTE_PROC_PRIMARY){
			rte_mp = rte_pktmbuf_pool_create(pool_name, nb_mbuf,
				mb_mempool_cache, 0, mbuf_seg_size, socket_id);
			}else {
			rte_mp = rte_mempool_lookup(pool_name);
			}
#else
			rte_mp = rte_pktmbuf_pool_create(pool_name, nb_mbuf,
				mb_mempool_cache, 0, mbuf_seg_size, socket_id);
#endif
			break;
		}
	case MP_ALLOC_ANON:
		{
#ifdef MULTIPLE_PROCESS_HANDLE
			if (rte_eal_process_type() == RTE_PROC_PRIMARY){
			rte_mp = rte_mempool_create_empty(pool_name, nb_mbuf,
				mb_size, (unsigned int) mb_mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, 0);
			}else {
			rte_mp = rte_mempool_lookup(pool_name);
			}
#else
			rte_mp = rte_mempool_create_empty(pool_name, nb_mbuf,
				mb_size, (unsigned int) mb_mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, mempool_flags);
#endif
			if (rte_mp == NULL)
				goto err;

			if (rte_mempool_populate_anon(rte_mp) == 0) {
				rte_mempool_free(rte_mp);
				rte_mp = NULL;
				goto err;
			}
			rte_pktmbuf_pool_init(rte_mp, NULL);
			rte_mempool_obj_iter(rte_mp, rte_pktmbuf_init, NULL);
			rte_mempool_mem_iter(rte_mp, dma_map_cb, NULL);
			break;
		}
	case MP_ALLOC_XMEM:
	case MP_ALLOC_XMEM_HUGE:
		{
			int heap_socket;
			bool huge = mp_alloc_type == MP_ALLOC_XMEM_HUGE;

			if (setup_extmem(nb_mbuf, mbuf_seg_size, huge) < 0)
				rte_exit(EXIT_FAILURE, "Could not create external memory\n");

			heap_socket =
				rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
			if (heap_socket < 0)
				rte_exit(EXIT_FAILURE, "Could not get external memory socket ID\n");

			TESTPMD_LOG(INFO, "preferred mempool ops selected: %s\n",
					rte_mbuf_best_mempool_ops());
#ifdef MULTIPLE_PROCESS_HANDLE
			if (rte_eal_process_type() == RTE_PROC_PRIMARY){
			rte_mp = rte_pktmbuf_pool_create(pool_name, nb_mbuf,
					mb_mempool_cache, 0, mbuf_seg_size,
					heap_socket);
			}else {
			rte_mp = rte_mempool_lookup(pool_name);
			}
#else
			rte_mp = rte_pktmbuf_pool_create(pool_name, nb_mbuf,
					mb_mempool_cache, 0, mbuf_seg_size,
					heap_socket);
#endif
			break;
		}
	default:
		{
			rte_exit(EXIT_FAILURE, "Invalid mempool creation mode\n");
		}
	}

err:
	if (rte_mp == NULL) {
		rte_exit(EXIT_FAILURE,
			"Creation of mbuf pool for socket %u failed: %s\n",
			socket_id, rte_strerror(rte_errno));
	} else if (verbose_level > 0) {
		rte_mempool_dump(stdout, rte_mp);
	}
	return rte_mp;
}

/*
 * Check given socket id is valid or not with NUMA mode,
 * if valid, return 0, else return -1
 */
static int
check_socket_id(const unsigned int socket_id)
{
	static int warning_once = 0;

	if (new_socket_id(socket_id)) {
		if (!warning_once && numa_support)
			printf("Warning: NUMA should be configured manually by"
			       " using --port-numa-config and"
			       " --ring-numa-config parameters along with"
			       " --numa.\n");
		warning_once = 1;
		return -1;
	}
	return 0;
}

/*
 * Get the allowed maximum number of RX queues.
 * *pid return the port id which has minimal value of
 * max_rx_queues in all ports.
 */
queueid_t
get_allowed_max_nb_rxq(portid_t *pid)
{
	queueid_t allowed_max_rxq = MAX_QUEUE_ID;
	bool max_rxq_valid = false;
	portid_t pi;
	struct rte_eth_dev_info dev_info;

	RTE_ETH_FOREACH_DEV(pi) {
		if (eth_dev_info_get_print_err(pi, &dev_info) != 0)
			continue;

		max_rxq_valid = true;
		if (dev_info.max_rx_queues < allowed_max_rxq) {
			allowed_max_rxq = dev_info.max_rx_queues;
			*pid = pi;
		}
	}
	return max_rxq_valid ? allowed_max_rxq : 0;
}

/*
 * Check input rxq is valid or not.
 * If input rxq is not greater than any of maximum number
 * of RX queues of all ports, it is valid.
 * if valid, return 0, else return -1
 */
int
check_nb_rxq(queueid_t rxq)
{
	queueid_t allowed_max_rxq;
	portid_t pid = 0;

	allowed_max_rxq = get_allowed_max_nb_rxq(&pid);
	if (rxq > allowed_max_rxq) {
		printf("Fail: input rxq (%u) can't be greater "
		       "than max_rx_queues (%u) of port %u\n",
		       rxq,
		       allowed_max_rxq,
		       pid);
		return -1;
	}
	return 0;
}

/*
 * Get the allowed maximum number of TX queues.
 * *pid return the port id which has minimal value of
 * max_tx_queues in all ports.
 */
queueid_t
get_allowed_max_nb_txq(portid_t *pid)
{
	queueid_t allowed_max_txq = MAX_QUEUE_ID;
	bool max_txq_valid = false;
	portid_t pi;
	struct rte_eth_dev_info dev_info;

	RTE_ETH_FOREACH_DEV(pi) {
		if (eth_dev_info_get_print_err(pi, &dev_info) != 0)
			continue;

		max_txq_valid = true;
		if (dev_info.max_tx_queues < allowed_max_txq) {
			allowed_max_txq = dev_info.max_tx_queues;
			*pid = pi;
		}
	}
	return max_txq_valid ? allowed_max_txq : 0;
}

/*
 * Check input txq is valid or not.
 * If input txq is not greater than any of maximum number
 * of TX queues of all ports, it is valid.
 * if valid, return 0, else return -1
 */
int
check_nb_txq(queueid_t txq)
{
	queueid_t allowed_max_txq;
	portid_t pid = 0;

	allowed_max_txq = get_allowed_max_nb_txq(&pid);
	if (txq > allowed_max_txq) {
		printf("Fail: input txq (%u) can't be greater "
		       "than max_tx_queues (%u) of port %u\n",
		       txq,
		       allowed_max_txq,
		       pid);
		return -1;
	}
	return 0;
}

static void
init_config(void)
{
	portid_t pid;
	struct rte_port *port;
	struct rte_mempool *mbp;
	unsigned int nb_mbuf_per_pool;
	lcoreid_t  lc_id;
	uint8_t port_per_socket[RTE_MAX_NUMA_NODES];
	struct rte_gro_param gro_param;
	uint32_t gso_types;
	uint16_t data_size;
	bool warning = 0;
	int k;
	int ret;

	memset(port_per_socket,0,RTE_MAX_NUMA_NODES);

	/* Configuration of logical cores. */
	fwd_lcores = rte_zmalloc("testpmd: fwd_lcores",
				sizeof(struct fwd_lcore *) * nb_lcores,
				RTE_CACHE_LINE_SIZE);
	if (fwd_lcores == NULL) {
		rte_exit(EXIT_FAILURE, "rte_zmalloc(%d (struct fwd_lcore *)) "
							"failed\n", nb_lcores);
	}
	for (lc_id = 0; lc_id < nb_lcores; lc_id++) {
		fwd_lcores[lc_id] = rte_zmalloc("testpmd: struct fwd_lcore",
					       sizeof(struct fwd_lcore),
					       RTE_CACHE_LINE_SIZE);
		if (fwd_lcores[lc_id] == NULL) {
			rte_exit(EXIT_FAILURE, "rte_zmalloc(struct fwd_lcore) "
								"failed\n");
		}
		fwd_lcores[lc_id]->cpuid_idx = lc_id;
	}

	RTE_ETH_FOREACH_DEV(pid) {
		port = &ports[pid];
		/* Apply default TxRx configuration for all ports */
		port->dev_conf.txmode = tx_mode;
		port->dev_conf.rxmode = rx_mode;

		ret = eth_dev_info_get_print_err(pid, &port->dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_info_get() failed\n");

		if (!(port->dev_info.tx_offload_capa &
		      DEV_TX_OFFLOAD_MBUF_FAST_FREE))
			port->dev_conf.txmode.offloads &=
				~DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		if (!(port->dev_info.tx_offload_capa &
			DEV_TX_OFFLOAD_MATCH_METADATA))
			port->dev_conf.txmode.offloads &=
				~DEV_TX_OFFLOAD_MATCH_METADATA;
		if (numa_support) {
			if (port_numa[pid] != NUMA_NO_CONFIG)
				port_per_socket[port_numa[pid]]++;
			else {
				uint32_t socket_id = rte_eth_dev_socket_id(pid);

				/*
				 * if socket_id is invalid,
				 * set to the first available socket.
				 */
				if (check_socket_id(socket_id) < 0)
					socket_id = socket_ids[0];
				port_per_socket[socket_id]++;
			}
		}

		/* Apply Rx offloads configuration */
		for (k = 0; k < port->dev_info.max_rx_queues; k++)
			port->rx_conf[k].offloads =
				port->dev_conf.rxmode.offloads;
		/* Apply Tx offloads configuration */
		for (k = 0; k < port->dev_info.max_tx_queues; k++)
			port->tx_conf[k].offloads =
				port->dev_conf.txmode.offloads;

		/* set flag to initialize port/queue */
		port->need_reconfig = 1;
		port->need_reconfig_queues = 1;
		port->tx_metadata = 0;

		/* Check for maximum number of segments per MTU. Accordingly
		 * update the mbuf data size.
		 */
		if (port->dev_info.rx_desc_lim.nb_mtu_seg_max != UINT16_MAX &&
				port->dev_info.rx_desc_lim.nb_mtu_seg_max != 0) {
			data_size = rx_mode.max_rx_pkt_len /
				port->dev_info.rx_desc_lim.nb_mtu_seg_max;

			if ((data_size + RTE_PKTMBUF_HEADROOM) >
							mbuf_data_size) {
				mbuf_data_size = data_size +
						 RTE_PKTMBUF_HEADROOM;
				warning = 1;
			}
		}
	}

	if (warning)
		TESTPMD_LOG(WARNING, "Configured mbuf size %hu\n",
			    mbuf_data_size);

	/*
	 * Create pools of mbuf.
	 * If NUMA support is disabled, create a single pool of mbuf in
	 * socket 0 memory by default.
	 * Otherwise, create a pool of mbuf in the memory of sockets 0 and 1.
	 *
	 * Use the maximum value of nb_rxd and nb_txd here, then nb_rxd and
	 * nb_txd can be configured at run time.
	 */
	if (param_total_num_mbufs)
		nb_mbuf_per_pool = param_total_num_mbufs;
	else {
		nb_mbuf_per_pool = RTE_TEST_RX_DESC_MAX +
			(nb_lcores * mb_mempool_cache) +
			RTE_TEST_TX_DESC_MAX + MAX_PKT_BURST;
		nb_mbuf_per_pool *= RTE_MAX_ETHPORTS;
	}

	if (numa_support) {
		uint8_t i;

		for (i = 0; i < num_sockets; i++)
			mempools[i] = mbuf_pool_create(mbuf_data_size,
						       nb_mbuf_per_pool,
						       socket_ids[i]);
	} else {
		if (socket_num == UMA_NO_CONFIG)
			mempools[0] = mbuf_pool_create(mbuf_data_size,
						       nb_mbuf_per_pool, 0);
		else
			mempools[socket_num] = mbuf_pool_create
							(mbuf_data_size,
							 nb_mbuf_per_pool,
							 socket_num);
	}

	init_port_config();

	gso_types = DEV_TX_OFFLOAD_TCP_TSO | DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
		DEV_TX_OFFLOAD_GRE_TNL_TSO | DEV_TX_OFFLOAD_UDP_TSO;
	/*
	 * Records which Mbuf pool to use by each logical core, if needed.
	 */
	for (lc_id = 0; lc_id < nb_lcores; lc_id++) {
		mbp = mbuf_pool_find(
			rte_lcore_to_socket_id(fwd_lcores_cpuids[lc_id]));

		if (mbp == NULL)
			mbp = mbuf_pool_find(0);
		fwd_lcores[lc_id]->mbp = mbp;
		/* initialize GSO context */
		fwd_lcores[lc_id]->gso_ctx.direct_pool = mbp;
		fwd_lcores[lc_id]->gso_ctx.indirect_pool = mbp;
		fwd_lcores[lc_id]->gso_ctx.gso_types = gso_types;
		fwd_lcores[lc_id]->gso_ctx.gso_size = RTE_ETHER_MAX_LEN -
			RTE_ETHER_CRC_LEN;
		fwd_lcores[lc_id]->gso_ctx.flag = 0;
	}

	/* Configuration of packet forwarding streams. */
	if (init_fwd_streams() < 0)
		rte_exit(EXIT_FAILURE, "FAIL from init_fwd_streams()\n");

	fwd_config_setup();

	/* create a gro context for each lcore */
	gro_param.gro_types = RTE_GRO_TCP_IPV4;
	gro_param.max_flow_num = GRO_MAX_FLUSH_CYCLES;
	gro_param.max_item_per_flow = MAX_PKT_BURST;
	for (lc_id = 0; lc_id < nb_lcores; lc_id++) {
		gro_param.socket_id = rte_lcore_to_socket_id(
				fwd_lcores_cpuids[lc_id]);
		fwd_lcores[lc_id]->gro_ctx = rte_gro_ctx_create(&gro_param);
		if (fwd_lcores[lc_id]->gro_ctx == NULL) {
			rte_exit(EXIT_FAILURE,
					"rte_gro_ctx_create() failed\n");
		}
	}

#if defined RTE_LIBRTE_PMD_SOFTNIC
	if (strcmp(cur_fwd_eng->fwd_mode_name, "softnic") == 0) {
		RTE_ETH_FOREACH_DEV(pid) {
			port = &ports[pid];
			const char *driver = port->dev_info.driver_name;

			if (strcmp(driver, "net_softnic") == 0)
				port->softport.fwd_lcore_arg = fwd_lcores;
		}
	}
#endif

}


void
reconfig(portid_t new_port_id, unsigned socket_id)
{
	struct rte_port *port;
	int ret;

	/* Reconfiguration of Ethernet ports. */
	port = &ports[new_port_id];

	ret = eth_dev_info_get_print_err(new_port_id, &port->dev_info);
	if (ret != 0)
		return;

	/* set flag to initialize port/queue */
	port->need_reconfig = 1;
	port->need_reconfig_queues = 1;
	port->socket_id = socket_id;

	init_port_config();
}


int
init_fwd_streams(void)
{
	portid_t pid;
	struct rte_port *port;
	streamid_t sm_id, nb_fwd_streams_new;
	queueid_t q;

	/* set socket id according to numa or not */
	RTE_ETH_FOREACH_DEV(pid) {
		port = &ports[pid];
		if (nb_rxq > port->dev_info.max_rx_queues) {
			printf("Fail: nb_rxq(%d) is greater than "
				"max_rx_queues(%d)\n", nb_rxq,
				port->dev_info.max_rx_queues);
			return -1;
		}
		if (nb_txq > port->dev_info.max_tx_queues) {
			printf("Fail: nb_txq(%d) is greater than "
				"max_tx_queues(%d)\n", nb_txq,
				port->dev_info.max_tx_queues);
			return -1;
		}
		if (numa_support) {
			if (port_numa[pid] != NUMA_NO_CONFIG)
				port->socket_id = port_numa[pid];
			else {
				port->socket_id = rte_eth_dev_socket_id(pid);

				/*
				 * if socket_id is invalid,
				 * set to the first available socket.
				 */
				if (check_socket_id(port->socket_id) < 0)
					port->socket_id = socket_ids[0];
			}
		}
		else {
			if (socket_num == UMA_NO_CONFIG)
				port->socket_id = 0;
			else
				port->socket_id = socket_num;
		}
	}

	q = RTE_MAX(nb_rxq, nb_txq);
	if (q == 0) {
		printf("Fail: Cannot allocate fwd streams as number of queues is 0\n");
		return -1;
	}
	nb_fwd_streams_new = (streamid_t)(nb_ports * q);
	if (nb_fwd_streams_new == nb_fwd_streams)
		return 0;
	/* clear the old */
	if (fwd_streams != NULL) {
		for (sm_id = 0; sm_id < nb_fwd_streams; sm_id++) {
			if (fwd_streams[sm_id] == NULL)
				continue;
			rte_free(fwd_streams[sm_id]);
			fwd_streams[sm_id] = NULL;
		}
		rte_free(fwd_streams);
		fwd_streams = NULL;
	}

	/* init new */
	nb_fwd_streams = nb_fwd_streams_new;
	if (nb_fwd_streams) {
		fwd_streams = rte_zmalloc("testpmd: fwd_streams",
			sizeof(struct fwd_stream *) * nb_fwd_streams,
			RTE_CACHE_LINE_SIZE);
		if (fwd_streams == NULL)
			rte_exit(EXIT_FAILURE, "rte_zmalloc(%d"
				 " (struct fwd_stream *)) failed\n",
				 nb_fwd_streams);

		for (sm_id = 0; sm_id < nb_fwd_streams; sm_id++) {
			fwd_streams[sm_id] = rte_zmalloc("testpmd:"
				" struct fwd_stream", sizeof(struct fwd_stream),
				RTE_CACHE_LINE_SIZE);
			if (fwd_streams[sm_id] == NULL)
				rte_exit(EXIT_FAILURE, "rte_zmalloc"
					 "(struct fwd_stream) failed\n");
		}
	}

	return 0;
}

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
static void
pkt_burst_stats_display(const char *rx_tx, struct pkt_burst_stats *pbs)
{
	unsigned int total_burst;
	unsigned int nb_burst;
	unsigned int burst_stats[3];
	uint16_t pktnb_stats[3];
	uint16_t nb_pkt;
	int burst_percent[3];

	/*
	 * First compute the total number of packet bursts and the
	 * two highest numbers of bursts of the same number of packets.
	 */
	total_burst = 0;
	burst_stats[0] = burst_stats[1] = burst_stats[2] = 0;
	pktnb_stats[0] = pktnb_stats[1] = pktnb_stats[2] = 0;
	for (nb_pkt = 0; nb_pkt < MAX_PKT_BURST; nb_pkt++) {
		nb_burst = pbs->pkt_burst_spread[nb_pkt];
		if (nb_burst == 0)
			continue;
		total_burst += nb_burst;
		if (nb_burst > burst_stats[0]) {
			burst_stats[1] = burst_stats[0];
			pktnb_stats[1] = pktnb_stats[0];
			burst_stats[0] = nb_burst;
			pktnb_stats[0] = nb_pkt;
		} else if (nb_burst > burst_stats[1]) {
			burst_stats[1] = nb_burst;
			pktnb_stats[1] = nb_pkt;
		}
	}
	if (total_burst == 0)
		return;
	burst_percent[0] = (burst_stats[0] * 100) / total_burst;
	printf("  %s-bursts : %u [%d%% of %d pkts", rx_tx, total_burst,
	       burst_percent[0], (int) pktnb_stats[0]);
	if (burst_stats[0] == total_burst) {
		printf("]\n");
		return;
	}
	if (burst_stats[0] + burst_stats[1] == total_burst) {
		printf(" + %d%% of %d pkts]\n",
		       100 - burst_percent[0], pktnb_stats[1]);
		return;
	}
	burst_percent[1] = (burst_stats[1] * 100) / total_burst;
	burst_percent[2] = 100 - (burst_percent[0] + burst_percent[1]);
	if ((burst_percent[1] == 0) || (burst_percent[2] == 0)) {
		printf(" + %d%% of others]\n", 100 - burst_percent[0]);
		return;
	}
	printf(" + %d%% of %d pkts + %d%% of others]\n",
	       burst_percent[1], (int) pktnb_stats[1], burst_percent[2]);
}
#endif /* RTE_TEST_PMD_RECORD_BURST_STATS */

static void
fwd_stream_stats_display(streamid_t stream_id)
{
	struct fwd_stream *fs;
	static const char *fwd_top_stats_border = "-------";

	fs = fwd_streams[stream_id];
	if ((fs->rx_packets == 0) && (fs->tx_packets == 0) &&
	    (fs->fwd_dropped == 0))
		return;
	printf("\n  %s Forward Stats for RX Port=%2d/Queue=%2d -> "
	       "TX Port=%2d/Queue=%2d %s\n",
	       fwd_top_stats_border, fs->rx_port, fs->rx_queue,
	       fs->tx_port, fs->tx_queue, fwd_top_stats_border);
	printf("  RX-packets: %-14"PRIu64" TX-packets: %-14"PRIu64
	       " TX-dropped: %-14"PRIu64,
	       fs->rx_packets, fs->tx_packets, fs->fwd_dropped);

	/* if checksum mode */
	if (cur_fwd_eng == &csum_fwd_engine) {
		printf("  RX- bad IP checksum: %-14"PRIu64
		       "  Rx- bad L4 checksum: %-14"PRIu64
		       " Rx- bad outer L4 checksum: %-14"PRIu64"\n",
			fs->rx_bad_ip_csum, fs->rx_bad_l4_csum,
			fs->rx_bad_outer_l4_csum);
	} else {
		printf("\n");
	}

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	pkt_burst_stats_display("RX", &fs->rx_burst_stats);
	pkt_burst_stats_display("TX", &fs->tx_burst_stats);
#endif
}

void
fwd_stats_display(void)
{
	static const char *fwd_stats_border = "----------------------";
	static const char *acc_stats_border = "+++++++++++++++";
	struct {
		struct fwd_stream *rx_stream;
		struct fwd_stream *tx_stream;
		uint64_t tx_dropped;
		uint64_t rx_bad_ip_csum;
		uint64_t rx_bad_l4_csum;
		uint64_t rx_bad_outer_l4_csum;
	} ports_stats[RTE_MAX_ETHPORTS];
	uint64_t total_rx_dropped = 0;
	uint64_t total_tx_dropped = 0;
	uint64_t total_rx_nombuf = 0;
	struct rte_eth_stats stats;
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t fwd_cycles = 0;
#endif
	uint64_t total_recv = 0;
	uint64_t total_xmit = 0;
	struct rte_port *port;
	streamid_t sm_id;
	portid_t pt_id;
	int i;

	memset(ports_stats, 0, sizeof(ports_stats));

	for (sm_id = 0; sm_id < cur_fwd_config.nb_fwd_streams; sm_id++) {
		struct fwd_stream *fs = fwd_streams[sm_id];

		if (cur_fwd_config.nb_fwd_streams >
		    cur_fwd_config.nb_fwd_ports) {
			fwd_stream_stats_display(sm_id);
		} else {
			ports_stats[fs->tx_port].tx_stream = fs;
			ports_stats[fs->rx_port].rx_stream = fs;
		}

		ports_stats[fs->tx_port].tx_dropped += fs->fwd_dropped;

		ports_stats[fs->rx_port].rx_bad_ip_csum += fs->rx_bad_ip_csum;
		ports_stats[fs->rx_port].rx_bad_l4_csum += fs->rx_bad_l4_csum;
		ports_stats[fs->rx_port].rx_bad_outer_l4_csum +=
				fs->rx_bad_outer_l4_csum;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
		fwd_cycles += fs->core_cycles;
#endif
	}
	for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++) {
		uint8_t j;

		pt_id = fwd_ports_ids[i];
		port = &ports[pt_id];

		rte_eth_stats_get(pt_id, &stats);
		stats.ipackets -= port->stats.ipackets;
		stats.opackets -= port->stats.opackets;
		stats.ibytes -= port->stats.ibytes;
		stats.obytes -= port->stats.obytes;
		stats.imissed -= port->stats.imissed;
		stats.oerrors -= port->stats.oerrors;
		stats.rx_nombuf -= port->stats.rx_nombuf;

		total_recv += stats.ipackets;
		total_xmit += stats.opackets;
		total_rx_dropped += stats.imissed;
		total_tx_dropped += ports_stats[pt_id].tx_dropped;
		total_tx_dropped += stats.oerrors;
		total_rx_nombuf  += stats.rx_nombuf;

		printf("\n  %s Forward statistics for port %-2d %s\n",
		       fwd_stats_border, pt_id, fwd_stats_border);

		if (!port->rx_queue_stats_mapping_enabled &&
		    !port->tx_queue_stats_mapping_enabled) {
			printf("  RX-packets: %-14"PRIu64
			       " RX-dropped: %-14"PRIu64
			       "RX-total: %-"PRIu64"\n",
			       stats.ipackets, stats.imissed,
			       stats.ipackets + stats.imissed);

			if (cur_fwd_eng == &csum_fwd_engine)
				printf("  Bad-ipcsum: %-14"PRIu64
				       " Bad-l4csum: %-14"PRIu64
				       "Bad-outer-l4csum: %-14"PRIu64"\n",
				       ports_stats[pt_id].rx_bad_ip_csum,
				       ports_stats[pt_id].rx_bad_l4_csum,
				       ports_stats[pt_id].rx_bad_outer_l4_csum);
			if (stats.ierrors + stats.rx_nombuf > 0) {
				printf("  RX-error: %-"PRIu64"\n",
				       stats.ierrors);
				printf("  RX-nombufs: %-14"PRIu64"\n",
				       stats.rx_nombuf);
			}

			printf("  TX-packets: %-14"PRIu64
			       " TX-dropped: %-14"PRIu64
			       "TX-total: %-"PRIu64"\n",
			       stats.opackets, ports_stats[pt_id].tx_dropped,
			       stats.opackets + ports_stats[pt_id].tx_dropped);
		} else {
			printf("  RX-packets:             %14"PRIu64
			       "    RX-dropped:%14"PRIu64
			       "    RX-total:%14"PRIu64"\n",
			       stats.ipackets, stats.imissed,
			       stats.ipackets + stats.imissed);

			if (cur_fwd_eng == &csum_fwd_engine)
				printf("  Bad-ipcsum:%14"PRIu64
				       "    Bad-l4csum:%14"PRIu64
				       "    Bad-outer-l4csum: %-14"PRIu64"\n",
				       ports_stats[pt_id].rx_bad_ip_csum,
				       ports_stats[pt_id].rx_bad_l4_csum,
				       ports_stats[pt_id].rx_bad_outer_l4_csum);
			if ((stats.ierrors + stats.rx_nombuf) > 0) {
				printf("  RX-error:%"PRIu64"\n", stats.ierrors);
				printf("  RX-nombufs:             %14"PRIu64"\n",
				       stats.rx_nombuf);
			}

			printf("  TX-packets:             %14"PRIu64
			       "    TX-dropped:%14"PRIu64
			       "    TX-total:%14"PRIu64"\n",
			       stats.opackets, ports_stats[pt_id].tx_dropped,
			       stats.opackets + ports_stats[pt_id].tx_dropped);
		}

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
		if (ports_stats[pt_id].rx_stream)
			pkt_burst_stats_display("RX",
				&ports_stats[pt_id].rx_stream->rx_burst_stats);
		if (ports_stats[pt_id].tx_stream)
			pkt_burst_stats_display("TX",
				&ports_stats[pt_id].tx_stream->tx_burst_stats);
#endif

		if (port->rx_queue_stats_mapping_enabled) {
			printf("\n");
			for (j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++) {
				printf("  Stats reg %2d RX-packets:%14"PRIu64
				       "     RX-errors:%14"PRIu64
				       "    RX-bytes:%14"PRIu64"\n",
				       j, stats.q_ipackets[j],
				       stats.q_errors[j], stats.q_ibytes[j]);
			}
			printf("\n");
		}
		if (port->tx_queue_stats_mapping_enabled) {
			for (j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++) {
				printf("  Stats reg %2d TX-packets:%14"PRIu64
				       "                                 TX-bytes:%14"
				       PRIu64"\n",
				       j, stats.q_opackets[j],
				       stats.q_obytes[j]);
			}
		}

		printf("  %s--------------------------------%s\n",
		       fwd_stats_border, fwd_stats_border);
	}

	printf("\n  %s Accumulated forward statistics for all ports"
	       "%s\n",
	       acc_stats_border, acc_stats_border);
	printf("  RX-packets: %-14"PRIu64" RX-dropped: %-14"PRIu64"RX-total: "
	       "%-"PRIu64"\n"
	       "  TX-packets: %-14"PRIu64" TX-dropped: %-14"PRIu64"TX-total: "
	       "%-"PRIu64"\n",
	       total_recv, total_rx_dropped, total_recv + total_rx_dropped,
	       total_xmit, total_tx_dropped, total_xmit + total_tx_dropped);
	if (total_rx_nombuf > 0)
		printf("  RX-nombufs: %-14"PRIu64"\n", total_rx_nombuf);
	printf("  %s++++++++++++++++++++++++++++++++++++++++++++++"
	       "%s\n",
	       acc_stats_border, acc_stats_border);
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	if (total_recv > 0)
		printf("\n  CPU cycles/packet=%u (total cycles="
		       "%"PRIu64" / total RX packets=%"PRIu64")\n",
		       (unsigned int)(fwd_cycles / total_recv),
		       fwd_cycles, total_recv);
#endif
}

void
fwd_stats_reset(void)
{
	streamid_t sm_id;
	portid_t pt_id;
	int i;

	for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++) {
		pt_id = fwd_ports_ids[i];
		rte_eth_stats_get(pt_id, &ports[pt_id].stats);
	}
	for (sm_id = 0; sm_id < cur_fwd_config.nb_fwd_streams; sm_id++) {
		struct fwd_stream *fs = fwd_streams[sm_id];

		fs->rx_packets = 0;
		fs->tx_packets = 0;
		fs->fwd_dropped = 0;
		fs->rx_bad_ip_csum = 0;
		fs->rx_bad_l4_csum = 0;
		fs->rx_bad_outer_l4_csum = 0;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
		memset(&fs->rx_burst_stats, 0, sizeof(fs->rx_burst_stats));
		memset(&fs->tx_burst_stats, 0, sizeof(fs->tx_burst_stats));
#endif
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
		fs->core_cycles = 0;
#endif
	}
}

static void
flush_fwd_rx_queues(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	portid_t  rxp;
	portid_t port_id;
	queueid_t rxq;
	uint16_t  nb_rx;
	uint16_t  i;
	uint8_t   j;
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	uint64_t timer_period;

	/* convert to number of cycles */
	timer_period = rte_get_timer_hz(); /* 1 second timeout */

	for (j = 0; j < 2; j++) {
		for (rxp = 0; rxp < cur_fwd_config.nb_fwd_ports; rxp++) {
			for (rxq = 0; rxq < nb_rxq; rxq++) {
				port_id = fwd_ports_ids[rxp];
				/**
				* testpmd can stuck in the below do while loop
				* if rte_eth_rx_burst() always returns nonzero
				* packets. So timer is added to exit this loop
				* after 1sec timer expiry.
				*/
				prev_tsc = rte_rdtsc();
				do {
					nb_rx = rte_eth_rx_burst(port_id, rxq,
						pkts_burst, MAX_PKT_BURST);
					for (i = 0; i < nb_rx; i++)
						rte_pktmbuf_free(pkts_burst[i]);

					cur_tsc = rte_rdtsc();
					diff_tsc = cur_tsc - prev_tsc;
					timer_tsc += diff_tsc;
				} while ((nb_rx > 0) &&
					(timer_tsc < timer_period));
				timer_tsc = 0;
			}
		}
		rte_delay_ms(10); /* wait 10 milli-seconds before retrying */
	}
}

static void
run_pkt_fwd_on_lcore(struct fwd_lcore *fc, packet_fwd_t pkt_fwd)
{
	struct fwd_stream **fsm;
	streamid_t nb_fs;
	streamid_t sm_id;
#ifdef RTE_LIBRTE_BITRATE
	uint64_t tics_per_1sec;
	uint64_t tics_datum;
	uint64_t tics_current;
	uint16_t i, cnt_ports;

	cnt_ports = nb_ports;
	tics_datum = rte_rdtsc();
	tics_per_1sec = rte_get_timer_hz();
#endif
	fsm = &fwd_streams[fc->stream_idx];
	nb_fs = fc->stream_nb;
	do {
		for (sm_id = 0; sm_id < nb_fs; sm_id++)
			(*pkt_fwd)(fsm[sm_id]);
#ifdef RTE_LIBRTE_BITRATE
		if (bitrate_enabled != 0 &&
				bitrate_lcore_id == rte_lcore_id()) {
			tics_current = rte_rdtsc();
			if (tics_current - tics_datum >= tics_per_1sec) {
				/* Periodic bitrate calculation */
				for (i = 0; i < cnt_ports; i++)
					rte_stats_bitrate_calc(bitrate_data,
						ports_ids[i]);
				tics_datum = tics_current;
			}
		}
#endif
#ifdef RTE_LIBRTE_LATENCY_STATS
		if (latencystats_enabled != 0 &&
				latencystats_lcore_id == rte_lcore_id())
			rte_latencystats_update();
#endif

	} while (! fc->stopped);
}

static int
start_pkt_forward_on_core(void *fwd_arg)
{
	run_pkt_fwd_on_lcore((struct fwd_lcore *) fwd_arg,
			     cur_fwd_config.fwd_eng->packet_fwd);
	return 0;
}

/*
 * Run the TXONLY packet forwarding engine to send a single burst of packets.
 * Used to start communication flows in network loopback test configurations.
 */
static int
run_one_txonly_burst_on_core(void *fwd_arg)
{
	struct fwd_lcore *fwd_lc;
	struct fwd_lcore tmp_lcore;

	fwd_lc = (struct fwd_lcore *) fwd_arg;
	tmp_lcore = *fwd_lc;
	tmp_lcore.stopped = 1;
	run_pkt_fwd_on_lcore(&tmp_lcore, tx_only_engine.packet_fwd);
	return 0;
}

/*
 * Launch packet forwarding:
 *     - Setup per-port forwarding context.
 *     - launch logical cores with their forwarding configuration.
 */
static void
launch_packet_forwarding(lcore_function_t *pkt_fwd_on_lcore)
{
	port_fwd_begin_t port_fwd_begin;
	unsigned int i;
	unsigned int lc_id;
	int diag;

	port_fwd_begin = cur_fwd_config.fwd_eng->port_fwd_begin;
	if (port_fwd_begin != NULL) {
		for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++)
			(*port_fwd_begin)(fwd_ports_ids[i]);
	}
	for (i = 0; i < cur_fwd_config.nb_fwd_lcores; i++) {
		lc_id = fwd_lcores_cpuids[i];
		if ((interactive == 0) || (lc_id != rte_lcore_id())) {
			fwd_lcores[i]->stopped = 0;
			diag = rte_eal_remote_launch(pkt_fwd_on_lcore,
						     fwd_lcores[i], lc_id);
			if (diag != 0)
				printf("launch lcore %u failed - diag=%d\n",
				       lc_id, diag);
		}
	}
}

/*
 * Launch packet forwarding configuration.
 */
void
start_packet_forwarding(int with_tx_first)
{
	port_fwd_begin_t port_fwd_begin;
	port_fwd_end_t  port_fwd_end;
	struct rte_port *port;
	unsigned int i;
	portid_t   pt_id;

	if (strcmp(cur_fwd_eng->fwd_mode_name, "rxonly") == 0 && !nb_rxq)
		rte_exit(EXIT_FAILURE, "rxq are 0, cannot use rxonly fwd mode\n");

	if (strcmp(cur_fwd_eng->fwd_mode_name, "txonly") == 0 && !nb_txq)
		rte_exit(EXIT_FAILURE, "txq are 0, cannot use txonly fwd mode\n");

	if ((strcmp(cur_fwd_eng->fwd_mode_name, "rxonly") != 0 &&
		strcmp(cur_fwd_eng->fwd_mode_name, "txonly") != 0) &&
		(!nb_rxq || !nb_txq))
		rte_exit(EXIT_FAILURE,
			"Either rxq or txq are 0, cannot use %s fwd mode\n",
			cur_fwd_eng->fwd_mode_name);

	if (all_ports_started() == 0) {
		printf("Not all ports were started\n");
		return;
	}
	if (test_done == 0) {
		printf("Packet forwarding already started\n");
		return;
	}


	if(dcb_test) {
		for (i = 0; i < nb_fwd_ports; i++) {
			pt_id = fwd_ports_ids[i];
			port = &ports[pt_id];
			if (!port->dcb_flag) {
				printf("In DCB mode, all forwarding ports must "
                                       "be configured in this mode.\n");
				return;
			}
		}
		if (nb_fwd_lcores == 1) {
			printf("In DCB mode,the nb forwarding cores "
                               "should be larger than 1.\n");
			return;
		}
	}
	test_done = 0;

	fwd_config_setup();

	if(!no_flush_rx)
		flush_fwd_rx_queues();

	pkt_fwd_config_display(&cur_fwd_config);
	rxtx_config_display();

	fwd_stats_reset();
	for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++) {
		pt_id = fwd_ports_ids[i];
		port = &ports[pt_id];
		map_port_queue_stats_mapping_registers(pt_id, port);
	}
	if (with_tx_first) {
		port_fwd_begin = tx_only_engine.port_fwd_begin;
		if (port_fwd_begin != NULL) {
			for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++)
				(*port_fwd_begin)(fwd_ports_ids[i]);
		}
		while (with_tx_first--) {
			launch_packet_forwarding(
					run_one_txonly_burst_on_core);
			rte_eal_mp_wait_lcore();
		}
		port_fwd_end = tx_only_engine.port_fwd_end;
		if (port_fwd_end != NULL) {
			for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++)
				(*port_fwd_end)(fwd_ports_ids[i]);
		}
	}
	launch_packet_forwarding(start_pkt_forward_on_core);
}

void
stop_packet_forwarding(void)
{
	port_fwd_end_t port_fwd_end;
	lcoreid_t lc_id;
	portid_t pt_id;
	int i;

	if (test_done) {
		printf("Packet forwarding not started\n");
		return;
	}
	printf("Telling cores to stop...");
	for (lc_id = 0; lc_id < cur_fwd_config.nb_fwd_lcores; lc_id++)
		fwd_lcores[lc_id]->stopped = 1;
	printf("\nWaiting for lcores to finish...\n");
	rte_eal_mp_wait_lcore();
	port_fwd_end = cur_fwd_config.fwd_eng->port_fwd_end;
	if (port_fwd_end != NULL) {
		for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++) {
			pt_id = fwd_ports_ids[i];
			(*port_fwd_end)(pt_id);
		}
	}

	fwd_stats_display();

	printf("\nDone.\n");
	test_done = 1;
}

void
dev_set_link_up(portid_t pid)
{
	if (rte_eth_dev_set_link_up(pid) < 0)
		printf("\nSet link up fail.\n");
}

void
dev_set_link_down(portid_t pid)
{
	if (rte_eth_dev_set_link_down(pid) < 0)
		printf("\nSet link down fail.\n");
}

static int
all_ports_started(void)
{
	portid_t pi;
	struct rte_port *port;

	RTE_ETH_FOREACH_DEV(pi) {
		port = &ports[pi];
		/* Check if there is a port which is not started */
		if ((port->port_status != RTE_PORT_STARTED) &&
			(port->slave_flag == 0))
			return 0;
	}

	/* No port is not started */
	return 1;
}

int
port_is_stopped(portid_t port_id)
{
	struct rte_port *port = &ports[port_id];

	if ((port->port_status != RTE_PORT_STOPPED) &&
	    (port->slave_flag == 0))
		return 0;
	return 1;
}

int
all_ports_stopped(void)
{
	portid_t pi;

	RTE_ETH_FOREACH_DEV(pi) {
		if (!port_is_stopped(pi))
			return 0;
	}

	return 1;
}

int
port_is_started(portid_t port_id)
{
	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return 0;

	if (ports[port_id].port_status != RTE_PORT_STARTED)
		return 0;

	return 1;
}

int
start_port(portid_t pid)
{
	int diag, need_check_link_status = -1;
	portid_t pi;
	queueid_t qi;
	struct rte_port *port;
	struct rte_ether_addr mac_addr;

	if (port_id_is_invalid(pid, ENABLED_WARN))
		return 0;

	if(dcb_config)
		dcb_test = 1;
	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		need_check_link_status = 0;
		port = &ports[pi];
		if (rte_atomic16_cmpset(&(port->port_status), RTE_PORT_STOPPED,
						 RTE_PORT_HANDLING) == 0) {
			printf("Port %d is now not stopped\n", pi);
			continue;
		}

		if (port->need_reconfig > 0) {
			port->need_reconfig = 0;

			if (flow_isolate_all) {
				int ret = port_flow_isolate(pi, 1);
				if (ret) {
					printf("Failed to apply isolated"
					       " mode on port %d\n", pi);
					return -1;
				}
			}
			configure_rxtx_dump_callbacks(0);
			printf("Configuring Port %d (socket %u)\n", pi,
					port->socket_id);
			/* configure port */
			if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
				diag = rte_eth_dev_configure(pi, nb_rxq, nb_txq,
							&(port->dev_conf));
				if (diag != 0) {
					if (rte_atomic16_cmpset(&(port->port_status),
					RTE_PORT_HANDLING, RTE_PORT_STOPPED) == 0)
						printf("Port %d can not be set back "
								"to stopped\n", pi);
					printf("Fail to configure port %d\n", pi);
					/* try to reconfigure port next time */
					port->need_reconfig = 1;
					return -1;
				}
			}
		}
		if (port->need_reconfig_queues > 0 &&
			rte_eal_process_type() == RTE_PROC_PRIMARY) {
			port->need_reconfig_queues = 0;
			/* setup tx queues */
			for (qi = 0; qi < nb_txq; qi++) {
				if ((numa_support) &&
					(txring_numa[pi] != NUMA_NO_CONFIG))
					diag = rte_eth_tx_queue_setup(pi, qi,
						port->nb_tx_desc[qi],
						txring_numa[pi],
						&(port->tx_conf[qi]));
				else
					diag = rte_eth_tx_queue_setup(pi, qi,
						port->nb_tx_desc[qi],
						port->socket_id,
						&(port->tx_conf[qi]));

				if (diag == 0)
					continue;

				/* Fail to setup tx queue, return */
				if (rte_atomic16_cmpset(&(port->port_status),
							RTE_PORT_HANDLING,
							RTE_PORT_STOPPED) == 0)
					printf("Port %d can not be set back "
							"to stopped\n", pi);
				printf("Fail to configure port %d tx queues\n",
				       pi);
				/* try to reconfigure queues next time */
				port->need_reconfig_queues = 1;
				return -1;
			}
			for (qi = 0; qi < nb_rxq; qi++) {
				/* setup rx queues */
				if ((numa_support) &&
					(rxring_numa[pi] != NUMA_NO_CONFIG)) {
					struct rte_mempool * mp =
						mbuf_pool_find(rxring_numa[pi]);
					if (mp == NULL) {
						printf("Failed to setup RX queue:"
							"No mempool allocation"
							" on the socket %d\n",
							rxring_numa[pi]);
						return -1;
					}

					diag = rte_eth_rx_queue_setup(pi, qi,
					     port->nb_rx_desc[qi],
					     rxring_numa[pi],
					     &(port->rx_conf[qi]),
					     mp);
				} else {
					struct rte_mempool *mp =
						mbuf_pool_find(port->socket_id);
					if (mp == NULL) {
						printf("Failed to setup RX queue:"
							"No mempool allocation"
							" on the socket %d\n",
							port->socket_id);
						return -1;
					}
					diag = rte_eth_rx_queue_setup(pi, qi,
					     port->nb_rx_desc[qi],
					     port->socket_id,
					     &(port->rx_conf[qi]),
					     mp);
				}
				if (diag == 0)
					continue;

				/* Fail to setup rx queue, return */
				if (rte_atomic16_cmpset(&(port->port_status),
							RTE_PORT_HANDLING,
							RTE_PORT_STOPPED) == 0)
					printf("Port %d can not be set back "
							"to stopped\n", pi);
				printf("Fail to configure port %d rx queues\n",
				       pi);
				/* try to reconfigure queues next time */
				port->need_reconfig_queues = 1;
				return -1;
			}
		}
		configure_rxtx_dump_callbacks(verbose_level);
		/* start port */
		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			diag = rte_eth_dev_start(pi);
			if (diag < 0) {
				printf("Fail to start port %d\n", pi);

				/* Fail to setup rx queue, return */
				if (rte_atomic16_cmpset(&(port->port_status),
					RTE_PORT_HANDLING, RTE_PORT_STOPPED) == 0)
					printf("Port %d can not be set back to "
								"stopped\n", pi);
				continue;
			}
		}

		if (rte_atomic16_cmpset(&(port->port_status),
			RTE_PORT_HANDLING, RTE_PORT_STARTED) == 0)
			printf("Port %d can not be set into started\n", pi);

		if (eth_macaddr_get_print_err(pi, &mac_addr) == 0)
			printf("Port %d: %02X:%02X:%02X:%02X:%02X:%02X\n", pi,
				mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
				mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
				mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);

		/* at least one port started, need checking link status */
		need_check_link_status = 1;
	}

	if (need_check_link_status == 1 && !no_link_check)
		check_all_ports_link_status(RTE_PORT_ALL);
	else if (need_check_link_status == 0)
		printf("Please stop the ports first\n");

	printf("Done\n");
	return 0;
}

void
stop_port(portid_t pid)
{
	portid_t pi;
	struct rte_port *port;
	int need_check_link_status = 0;

	if (dcb_test) {
		dcb_test = 0;
		dcb_config = 0;
	}

	if (port_id_is_invalid(pid, ENABLED_WARN))
		return;

	printf("Stopping ports...\n");

	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		if (port_is_forwarding(pi) != 0 && test_done == 0) {
			printf("Please remove port %d from forwarding configuration.\n", pi);
			continue;
		}

		if (port_is_bonding_slave(pi)) {
			printf("Please remove port %d from bonded device.\n", pi);
			continue;
		}

		port = &ports[pi];
		if (rte_atomic16_cmpset(&(port->port_status), RTE_PORT_STARTED,
						RTE_PORT_HANDLING) == 0)
			continue;
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			rte_eth_dev_stop(pi);

		if (rte_atomic16_cmpset(&(port->port_status),
			RTE_PORT_HANDLING, RTE_PORT_STOPPED) == 0)
			printf("Port %d can not be set into stopped\n", pi);
		need_check_link_status = 1;
	}
	if (need_check_link_status && !no_link_check)
		check_all_ports_link_status(RTE_PORT_ALL);

	printf("Done\n");
}

static void
remove_invalid_ports_in(portid_t *array, portid_t *total)
{
	portid_t i;
	portid_t new_total = 0;

	for (i = 0; i < *total; i++)
		if (!port_id_is_invalid(array[i], DISABLED_WARN)) {
			array[new_total] = array[i];
			new_total++;
		}
	*total = new_total;
}

static void
remove_invalid_ports(void)
{
	remove_invalid_ports_in(ports_ids, &nb_ports);
	remove_invalid_ports_in(fwd_ports_ids, &nb_fwd_ports);
	nb_cfg_ports = nb_fwd_ports;
}

void
close_port(portid_t pid)
{
	portid_t pi;
	struct rte_port *port;

	if (port_id_is_invalid(pid, ENABLED_WARN))
		return;

	printf("Closing ports...\n");

	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		if (port_is_forwarding(pi) != 0 && test_done == 0) {
			printf("Please remove port %d from forwarding configuration.\n", pi);
			continue;
		}

		if (port_is_bonding_slave(pi)) {
			printf("Please remove port %d from bonded device.\n", pi);
			continue;
		}

		port = &ports[pi];
		if (rte_atomic16_cmpset(&(port->port_status),
			RTE_PORT_CLOSED, RTE_PORT_CLOSED) == 1) {
			printf("Port %d is already closed\n", pi);
			continue;
		}

		if (rte_atomic16_cmpset(&(port->port_status),
			RTE_PORT_STOPPED, RTE_PORT_HANDLING) == 0) {
			printf("Port %d is now not stopped\n", pi);
			continue;
		}

		if (port->flow_list)
			port_flow_flush(pi);
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			rte_eth_dev_close(pi);

		remove_invalid_ports();

		if (rte_atomic16_cmpset(&(port->port_status),
			RTE_PORT_HANDLING, RTE_PORT_CLOSED) == 0)
			printf("Port %d cannot be set to closed\n", pi);
	}

	printf("Done\n");
}

void
reset_port(portid_t pid)
{
	int diag;
	portid_t pi;
	struct rte_port *port;

	if (port_id_is_invalid(pid, ENABLED_WARN))
		return;

	if ((pid == (portid_t)RTE_PORT_ALL && !all_ports_stopped()) ||
		(pid != (portid_t)RTE_PORT_ALL && !port_is_stopped(pid))) {
		printf("Can not reset port(s), please stop port(s) first.\n");
		return;
	}

	printf("Resetting ports...\n");

	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		if (port_is_forwarding(pi) != 0 && test_done == 0) {
			printf("Please remove port %d from forwarding "
			       "configuration.\n", pi);
			continue;
		}

		if (port_is_bonding_slave(pi)) {
			printf("Please remove port %d from bonded device.\n",
			       pi);
			continue;
		}

		diag = rte_eth_dev_reset(pi);
		if (diag == 0) {
			port = &ports[pi];
			port->need_reconfig = 1;
			port->need_reconfig_queues = 1;
		} else {
			printf("Failed to reset port %d. diag=%d\n", pi, diag);
		}
	}

	printf("Done\n");
}

void
attach_port(char *identifier)
{
	portid_t pi;
	struct rte_dev_iterator iterator;

	printf("Attaching a new port...\n");

	if (identifier == NULL) {
		printf("Invalid parameters are specified\n");
		return;
	}

	if (rte_dev_probe(identifier) < 0) {
		TESTPMD_LOG(ERR, "Failed to attach port %s\n", identifier);
		return;
	}

	/* first attach mode: event */
	if (setup_on_probe_event) {
		/* new ports are detected on RTE_ETH_EVENT_NEW event */
		for (pi = 0; pi < RTE_MAX_ETHPORTS; pi++)
			if (ports[pi].port_status == RTE_PORT_HANDLING &&
					ports[pi].need_setup != 0)
				setup_attached_port(pi);
		return;
	}

	/* second attach mode: iterator */
	RTE_ETH_FOREACH_MATCHING_DEV(pi, identifier, &iterator) {
		/* setup ports matching the devargs used for probing */
		if (port_is_forwarding(pi))
			continue; /* port was already attached before */
		setup_attached_port(pi);
	}
}

static void
setup_attached_port(portid_t pi)
{
	unsigned int socket_id;
	int ret;

	socket_id = (unsigned)rte_eth_dev_socket_id(pi);
	/* if socket_id is invalid, set to the first available socket. */
	if (check_socket_id(socket_id) < 0)
		socket_id = socket_ids[0];
	reconfig(pi, socket_id);
	ret = rte_eth_promiscuous_enable(pi);
	if (ret != 0)
		printf("Error during enabling promiscuous mode for port %u: %s - ignore\n",
			pi, rte_strerror(-ret));

	ports_ids[nb_ports++] = pi;
	fwd_ports_ids[nb_fwd_ports++] = pi;
	nb_cfg_ports = nb_fwd_ports;
	ports[pi].need_setup = 0;
	ports[pi].port_status = RTE_PORT_STOPPED;

	printf("Port %d is attached. Now total ports is %d\n", pi, nb_ports);
	printf("Done\n");
}

void
detach_port_device(portid_t port_id)
{
	struct rte_device *dev;
	portid_t sibling;

	printf("Removing a device...\n");

	dev = rte_eth_devices[port_id].device;
	if (dev == NULL) {
		printf("Device already removed\n");
		return;
	}

	if (ports[port_id].port_status != RTE_PORT_CLOSED) {
		if (ports[port_id].port_status != RTE_PORT_STOPPED) {
			printf("Port not stopped\n");
			return;
		}
		printf("Port was not closed\n");
		if (ports[port_id].flow_list)
			port_flow_flush(port_id);
	}

	if (rte_dev_remove(dev) < 0) {
		TESTPMD_LOG(ERR, "Failed to detach device %s\n", dev->name);
		return;
	}
	RTE_ETH_FOREACH_DEV_OF(sibling, dev) {
		/* reset mapping between old ports and removed device */
		rte_eth_devices[sibling].device = NULL;
		if (ports[sibling].port_status != RTE_PORT_CLOSED) {
			/* sibling ports are forced to be closed */
			ports[sibling].port_status = RTE_PORT_CLOSED;
			printf("Port %u is closed\n", sibling);
		}
	}

	remove_invalid_ports();

	printf("Device of port %u is detached\n", port_id);
	printf("Now total ports is %d\n", nb_ports);
	printf("Done\n");
	return;
}

void
detach_device(char *identifier)
{
	struct rte_dev_iterator iterator;
	struct rte_devargs da;
	portid_t port_id;

	printf("Removing a device...\n");

	memset(&da, 0, sizeof(da));
	if (rte_devargs_parsef(&da, "%s", identifier)) {
		printf("cannot parse identifier\n");
		if (da.args)
			free(da.args);
		return;
	}

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, identifier, &iterator) {
		if (ports[port_id].port_status != RTE_PORT_CLOSED) {
			if (ports[port_id].port_status != RTE_PORT_STOPPED) {
				printf("Port %u not stopped\n", port_id);
				return;
			}

			/* sibling ports are forced to be closed */
			if (ports[port_id].flow_list)
				port_flow_flush(port_id);
			ports[port_id].port_status = RTE_PORT_CLOSED;
			printf("Port %u is now closed\n", port_id);
		}
	}

	if (rte_eal_hotplug_remove(da.bus->name, da.name) != 0) {
		TESTPMD_LOG(ERR, "Failed to detach device %s(%s)\n",
			    da.name, da.bus->name);
		return;
	}

	remove_invalid_ports();

	printf("Device %s is detached\n", identifier);
	printf("Now total ports is %d\n", nb_ports);
	printf("Done\n");
}

void
pmd_test_exit(void)
{
	portid_t pt_id;
	int ret;
	int i;

	if (test_done == 0)
		stop_packet_forwarding();

	for (i = 0 ; i < RTE_MAX_NUMA_NODES ; i++) {
		if (mempools[i]) {
			if (mp_alloc_type == MP_ALLOC_ANON)
				rte_mempool_mem_iter(mempools[i], dma_unmap_cb,
						     NULL);
		}
	}
	if (ports != NULL) {
		no_link_check = 1;
		RTE_ETH_FOREACH_DEV(pt_id) {
			printf("\nStopping port %d...\n", pt_id);
			fflush(stdout);
			stop_port(pt_id);
		}
		RTE_ETH_FOREACH_DEV(pt_id) {
			printf("\nShutting down port %d...\n", pt_id);
			fflush(stdout);
			close_port(pt_id);
		}
	}

	if (hot_plug) {
		ret = rte_dev_event_monitor_stop();
		if (ret) {
			RTE_LOG(ERR, EAL,
				"fail to stop device event monitor.");
			return;
		}

		ret = rte_dev_event_callback_unregister(NULL,
			dev_event_callback, NULL);
		if (ret < 0) {
			RTE_LOG(ERR, EAL,
				"fail to unregister device event callback.\n");
			return;
		}

		ret = rte_dev_hotplug_handle_disable();
		if (ret) {
			RTE_LOG(ERR, EAL,
				"fail to disable hotplug handling.\n");
			return;
		}
	}
	for (i = 0 ; i < RTE_MAX_NUMA_NODES ; i++) {
		if (rte_eal_process_type() == RTE_PROC_PRIMARY && mempools[i])
			rte_mempool_free(mempools[i]);
	}

	printf("\nBye...\n");
}

typedef void (*cmd_func_t)(void);
struct pmd_test_command {
	const char *cmd_name;
	cmd_func_t cmd_func;
};

#define PMD_TEST_CMD_NB (sizeof(pmd_test_menu) / sizeof(pmd_test_menu[0]))

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	portid_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. speed %u Mbps- %s\n",
					portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
		}

		if (lsc_interrupt)
			break;
	}
}

/*
 * This callback is for remove a port for a device. It has limitation because
 * it is not for multiple port removal for a device.
 * TODO: the device detach invoke will plan to be removed from user side to
 * eal. And convert all PMDs to free port resources on ether device closing.
 */
static void
rmv_port_callback(void *arg)
{
	int need_to_start = 0;
	int org_no_link_check = no_link_check;
	portid_t port_id = (intptr_t)arg;

	RTE_ETH_VALID_PORTID_OR_RET(port_id);

	if (!test_done && port_is_forwarding(port_id)) {
		need_to_start = 1;
		stop_packet_forwarding();
	}
	no_link_check = 1;
	stop_port(port_id);
	no_link_check = org_no_link_check;
	close_port(port_id);
	detach_port_device(port_id);
	if (need_to_start)
		start_packet_forwarding(0);
}

/* This function is used by the interrupt thread */
static int
eth_event_callback(portid_t port_id, enum rte_eth_event_type type, void *param,
		  void *ret_param)
{
	RTE_SET_USED(param);
	RTE_SET_USED(ret_param);

	if (type >= RTE_ETH_EVENT_MAX) {
		fprintf(stderr, "\nPort %" PRIu16 ": %s called upon invalid event %d\n",
			port_id, __func__, type);
		fflush(stderr);
	} else if (event_print_mask & (UINT32_C(1) << type)) {
		printf("\nPort %" PRIu16 ": %s event\n", port_id,
			eth_event_desc[type]);
		fflush(stdout);
	}

	switch (type) {
	case RTE_ETH_EVENT_NEW:
		ports[port_id].need_setup = 1;
		ports[port_id].port_status = RTE_PORT_HANDLING;
		break;
	case RTE_ETH_EVENT_INTR_RMV:
		if (port_id_is_invalid(port_id, DISABLED_WARN))
			break;
		if (rte_eal_alarm_set(100000,
				rmv_port_callback, (void *)(intptr_t)port_id))
			fprintf(stderr, "Could not set up deferred device removal\n");
		break;
	default:
		break;
	}
	return 0;
}

static int
register_eth_event_callback(void)
{
	int ret;
	enum rte_eth_event_type event;

	for (event = RTE_ETH_EVENT_UNKNOWN;
			event < RTE_ETH_EVENT_MAX; event++) {
		ret = rte_eth_dev_callback_register(RTE_ETH_ALL,
				event,
				eth_event_callback,
				NULL);
		if (ret != 0) {
			TESTPMD_LOG(ERR, "Failed to register callback for "
					"%s event\n", eth_event_desc[event]);
			return -1;
		}
	}

	return 0;
}

/* This function is used by the interrupt thread */
static void
dev_event_callback(const char *device_name, enum rte_dev_event_type type,
			     __rte_unused void *arg)
{
	uint16_t port_id;
	int ret;

	if (type >= RTE_DEV_EVENT_MAX) {
		fprintf(stderr, "%s called upon invalid event %d\n",
			__func__, type);
		fflush(stderr);
	}

	switch (type) {
	case RTE_DEV_EVENT_REMOVE:
		RTE_LOG(DEBUG, EAL, "The device: %s has been removed!\n",
			device_name);
		ret = rte_eth_dev_get_port_by_name(device_name, &port_id);
		if (ret) {
			RTE_LOG(ERR, EAL, "can not get port by device %s!\n",
				device_name);
			return;
		}
		/*
		 * Because the user's callback is invoked in eal interrupt
		 * callback, the interrupt callback need to be finished before
		 * it can be unregistered when detaching device. So finish
		 * callback soon and use a deferred removal to detach device
		 * is need. It is a workaround, once the device detaching be
		 * moved into the eal in the future, the deferred removal could
		 * be deleted.
		 */
		if (rte_eal_alarm_set(100000,
				rmv_port_callback, (void *)(intptr_t)port_id))
			RTE_LOG(ERR, EAL,
				"Could not set up deferred device removal\n");
		break;
	case RTE_DEV_EVENT_ADD:
		RTE_LOG(ERR, EAL, "The device: %s has been added!\n",
			device_name);
		/* TODO: After finish kernel driver binding,
		 * begin to attach port.
		 */
		break;
	default:
		break;
	}
}

static int
set_tx_queue_stats_mapping_registers(portid_t port_id, struct rte_port *port)
{
	uint16_t i;
	int diag;
	uint8_t mapping_found = 0;

	for (i = 0; i < nb_tx_queue_stats_mappings; i++) {
		if ((tx_queue_stats_mappings[i].port_id == port_id) &&
				(tx_queue_stats_mappings[i].queue_id < nb_txq )) {
			diag = rte_eth_dev_set_tx_queue_stats_mapping(port_id,
					tx_queue_stats_mappings[i].queue_id,
					tx_queue_stats_mappings[i].stats_counter_id);
			if (diag != 0)
				return diag;
			mapping_found = 1;
		}
	}
	if (mapping_found)
		port->tx_queue_stats_mapping_enabled = 1;
	return 0;
}

static int
set_rx_queue_stats_mapping_registers(portid_t port_id, struct rte_port *port)
{
	uint16_t i;
	int diag;
	uint8_t mapping_found = 0;

	for (i = 0; i < nb_rx_queue_stats_mappings; i++) {
		if ((rx_queue_stats_mappings[i].port_id == port_id) &&
				(rx_queue_stats_mappings[i].queue_id < nb_rxq )) {
			diag = rte_eth_dev_set_rx_queue_stats_mapping(port_id,
					rx_queue_stats_mappings[i].queue_id,
					rx_queue_stats_mappings[i].stats_counter_id);
			if (diag != 0)
				return diag;
			mapping_found = 1;
		}
	}
	if (mapping_found)
		port->rx_queue_stats_mapping_enabled = 1;
	return 0;
}

static void
map_port_queue_stats_mapping_registers(portid_t pi, struct rte_port *port)
{
	int diag = 0;

	diag = set_tx_queue_stats_mapping_registers(pi, port);
	if (diag != 0) {
		if (diag == -ENOTSUP) {
			port->tx_queue_stats_mapping_enabled = 0;
			printf("TX queue stats mapping not supported port id=%d\n", pi);
		}
		else
			rte_exit(EXIT_FAILURE,
					"set_tx_queue_stats_mapping_registers "
					"failed for port id=%d diag=%d\n",
					pi, diag);
	}

	diag = set_rx_queue_stats_mapping_registers(pi, port);
	if (diag != 0) {
		if (diag == -ENOTSUP) {
			port->rx_queue_stats_mapping_enabled = 0;
			printf("RX queue stats mapping not supported port id=%d\n", pi);
		}
		else
			rte_exit(EXIT_FAILURE,
					"set_rx_queue_stats_mapping_registers "
					"failed for port id=%d diag=%d\n",
					pi, diag);
	}
}

static void
rxtx_port_config(struct rte_port *port)
{
	uint16_t qid;
	uint64_t offloads;

	for (qid = 0; qid < nb_rxq; qid++) {
		offloads = port->rx_conf[qid].offloads;
		port->rx_conf[qid] = port->dev_info.default_rxconf;
		if (offloads != 0)
			port->rx_conf[qid].offloads = offloads;

		/* Check if any Rx parameters have been passed */
		if (rx_pthresh != RTE_PMD_PARAM_UNSET)
			port->rx_conf[qid].rx_thresh.pthresh = rx_pthresh;

		if (rx_hthresh != RTE_PMD_PARAM_UNSET)
			port->rx_conf[qid].rx_thresh.hthresh = rx_hthresh;

		if (rx_wthresh != RTE_PMD_PARAM_UNSET)
			port->rx_conf[qid].rx_thresh.wthresh = rx_wthresh;

		if (rx_free_thresh != RTE_PMD_PARAM_UNSET)
			port->rx_conf[qid].rx_free_thresh = rx_free_thresh;

		if (rx_drop_en != RTE_PMD_PARAM_UNSET)
			port->rx_conf[qid].rx_drop_en = rx_drop_en;

		port->nb_rx_desc[qid] = nb_rxd;
	}

	for (qid = 0; qid < nb_txq; qid++) {
		offloads = port->tx_conf[qid].offloads;
		port->tx_conf[qid] = port->dev_info.default_txconf;
		if (offloads != 0)
			port->tx_conf[qid].offloads = offloads;

		/* Check if any Tx parameters have been passed */
		if (tx_pthresh != RTE_PMD_PARAM_UNSET)
			port->tx_conf[qid].tx_thresh.pthresh = tx_pthresh;

		if (tx_hthresh != RTE_PMD_PARAM_UNSET)
			port->tx_conf[qid].tx_thresh.hthresh = tx_hthresh;

		if (tx_wthresh != RTE_PMD_PARAM_UNSET)
			port->tx_conf[qid].tx_thresh.wthresh = tx_wthresh;

		if (tx_rs_thresh != RTE_PMD_PARAM_UNSET)
			port->tx_conf[qid].tx_rs_thresh = tx_rs_thresh;

		if (tx_free_thresh != RTE_PMD_PARAM_UNSET)
			port->tx_conf[qid].tx_free_thresh = tx_free_thresh;

		port->nb_tx_desc[qid] = nb_txd;
	}
}

void
init_port_config(void)
{
	portid_t pid;
	struct rte_port *port;
	int ret;

	RTE_ETH_FOREACH_DEV(pid) {
		port = &ports[pid];
		port->dev_conf.fdir_conf = fdir_conf;

		ret = eth_dev_info_get_print_err(pid, &port->dev_info);
		if (ret != 0)
			return;

		if (nb_rxq > 1) {
			port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
			port->dev_conf.rx_adv_conf.rss_conf.rss_hf =
				rss_hf & port->dev_info.flow_type_rss_offloads;
		} else {
			port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
			port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
		}

		if (port->dcb_flag == 0) {
			if( port->dev_conf.rx_adv_conf.rss_conf.rss_hf != 0)
				port->dev_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
			else
				port->dev_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
		}

		rxtx_port_config(port);

		ret = eth_macaddr_get_print_err(pid, &port->eth_addr);
		if (ret != 0)
			return;

		map_port_queue_stats_mapping_registers(pid, port);
#if defined RTE_LIBRTE_IXGBE_PMD && defined RTE_LIBRTE_IXGBE_BYPASS
		rte_pmd_ixgbe_bypass_init(pid);
#endif

		if (lsc_interrupt &&
		    (rte_eth_devices[pid].data->dev_flags &
		     RTE_ETH_DEV_INTR_LSC))
			port->dev_conf.intr_conf.lsc = 1;
		if (rmv_interrupt &&
		    (rte_eth_devices[pid].data->dev_flags &
		     RTE_ETH_DEV_INTR_RMV))
			port->dev_conf.intr_conf.rmv = 1;
	}
}

void set_port_slave_flag(portid_t slave_pid)
{
	struct rte_port *port;

	port = &ports[slave_pid];
	port->slave_flag = 1;
}

void clear_port_slave_flag(portid_t slave_pid)
{
	struct rte_port *port;

	port = &ports[slave_pid];
	port->slave_flag = 0;
}

uint8_t port_is_bonding_slave(portid_t slave_pid)
{
	struct rte_port *port;

	port = &ports[slave_pid];
	if ((rte_eth_devices[slave_pid].data->dev_flags &
	    RTE_ETH_DEV_BONDED_SLAVE) || (port->slave_flag == 1))
		return 1;
	return 0;
}

const uint16_t vlan_tags[] = {
		0,  1,  2,  3,  4,  5,  6,  7,
		8,  9, 10, 11,  12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
};

static  int
get_eth_dcb_conf(portid_t pid, struct rte_eth_conf *eth_conf,
		 enum dcb_mode_enable dcb_mode,
		 enum rte_eth_nb_tcs num_tcs,
		 uint8_t pfc_en)
{
	uint8_t i;
	int32_t rc;
	struct rte_eth_rss_conf rss_conf;

	/*
	 * Builds up the correct configuration for dcb+vt based on the vlan tags array
	 * given above, and the number of traffic classes available for use.
	 */
	if (dcb_mode == DCB_VT_ENABLED) {
		struct rte_eth_vmdq_dcb_conf *vmdq_rx_conf =
				&eth_conf->rx_adv_conf.vmdq_dcb_conf;
		struct rte_eth_vmdq_dcb_tx_conf *vmdq_tx_conf =
				&eth_conf->tx_adv_conf.vmdq_dcb_tx_conf;

		/* VMDQ+DCB RX and TX configurations */
		vmdq_rx_conf->enable_default_pool = 0;
		vmdq_rx_conf->default_pool = 0;
		vmdq_rx_conf->nb_queue_pools =
			(num_tcs ==  ETH_4_TCS ? ETH_32_POOLS : ETH_16_POOLS);
		vmdq_tx_conf->nb_queue_pools =
			(num_tcs ==  ETH_4_TCS ? ETH_32_POOLS : ETH_16_POOLS);

		vmdq_rx_conf->nb_pool_maps = vmdq_rx_conf->nb_queue_pools;
		for (i = 0; i < vmdq_rx_conf->nb_pool_maps; i++) {
			vmdq_rx_conf->pool_map[i].vlan_id = vlan_tags[i];
			vmdq_rx_conf->pool_map[i].pools =
				1 << (i % vmdq_rx_conf->nb_queue_pools);
		}
		for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
			vmdq_rx_conf->dcb_tc[i] = i % num_tcs;
			vmdq_tx_conf->dcb_tc[i] = i % num_tcs;
		}

		/* set DCB mode of RX and TX of multiple queues */
		eth_conf->rxmode.mq_mode = ETH_MQ_RX_VMDQ_DCB;
		eth_conf->txmode.mq_mode = ETH_MQ_TX_VMDQ_DCB;
	} else {
		struct rte_eth_dcb_rx_conf *rx_conf =
				&eth_conf->rx_adv_conf.dcb_rx_conf;
		struct rte_eth_dcb_tx_conf *tx_conf =
				&eth_conf->tx_adv_conf.dcb_tx_conf;

		memset(&rss_conf, 0, sizeof(rss_conf));
		rc = rte_eth_dev_rss_hash_conf_get(pid, &rss_conf);
		if (rc != 0)
			return rc;

		rx_conf->nb_tcs = num_tcs;
		tx_conf->nb_tcs = num_tcs;

		for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
			rx_conf->dcb_tc[i] = i % num_tcs;
			tx_conf->dcb_tc[i] = i % num_tcs;
		}

		eth_conf->rxmode.mq_mode = ETH_MQ_RX_DCB_RSS;
		eth_conf->rx_adv_conf.rss_conf = rss_conf;
		eth_conf->txmode.mq_mode = ETH_MQ_TX_DCB;
	}

	if (pfc_en)
		eth_conf->dcb_capability_en =
				ETH_DCB_PG_SUPPORT | ETH_DCB_PFC_SUPPORT;
	else
		eth_conf->dcb_capability_en = ETH_DCB_PG_SUPPORT;

	return 0;
}

int
init_port_dcb_config(portid_t pid,
		     enum dcb_mode_enable dcb_mode,
		     enum rte_eth_nb_tcs num_tcs,
		     uint8_t pfc_en)
{
	struct rte_eth_conf port_conf;
	struct rte_port *rte_port;
	int retval;
	uint16_t i;

	rte_port = &ports[pid];

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));
	/* Enter DCB configuration status */
	dcb_config = 1;

	port_conf.rxmode = rte_port->dev_conf.rxmode;
	port_conf.txmode = rte_port->dev_conf.txmode;

	/*set configuration of DCB in vt mode and DCB in non-vt mode*/
	retval = get_eth_dcb_conf(pid, &port_conf, dcb_mode, num_tcs, pfc_en);
	if (retval < 0)
		return retval;
	port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_FILTER;

	/* re-configure the device . */
	retval = rte_eth_dev_configure(pid, nb_rxq, nb_rxq, &port_conf);
	if (retval < 0)
		return retval;

	retval = eth_dev_info_get_print_err(pid, &rte_port->dev_info);
	if (retval != 0)
		return retval;

	/* If dev_info.vmdq_pool_base is greater than 0,
	 * the queue id of vmdq pools is started after pf queues.
	 */
	if (dcb_mode == DCB_VT_ENABLED &&
	    rte_port->dev_info.vmdq_pool_base > 0) {
		printf("VMDQ_DCB multi-queue mode is nonsensical"
			" for port %d.", pid);
		return -1;
	}

	/* Assume the ports in testpmd have the same dcb capability
	 * and has the same number of rxq and txq in dcb mode
	 */
	if (dcb_mode == DCB_VT_ENABLED) {
		if (rte_port->dev_info.max_vfs > 0) {
			nb_rxq = rte_port->dev_info.nb_rx_queues;
			nb_txq = rte_port->dev_info.nb_tx_queues;
		} else {
			nb_rxq = rte_port->dev_info.max_rx_queues;
			nb_txq = rte_port->dev_info.max_tx_queues;
		}
	} else {
		/*if vt is disabled, use all pf queues */
		if (rte_port->dev_info.vmdq_pool_base == 0) {
			nb_rxq = rte_port->dev_info.max_rx_queues;
			nb_txq = rte_port->dev_info.max_tx_queues;
		} else {
			nb_rxq = (queueid_t)num_tcs;
			nb_txq = (queueid_t)num_tcs;

		}
	}
	rx_free_thresh = 64;

	memcpy(&rte_port->dev_conf, &port_conf, sizeof(struct rte_eth_conf));

	rxtx_port_config(rte_port);
	/* VLAN filter */
	rte_port->dev_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_FILTER;
	for (i = 0; i < RTE_DIM(vlan_tags); i++)
		rx_vft_set(pid, vlan_tags[i], 1);

	retval = eth_macaddr_get_print_err(pid, &rte_port->eth_addr);
	if (retval != 0)
		return retval;

	map_port_queue_stats_mapping_registers(pid, rte_port);

	rte_port->dcb_flag = 1;

	return 0;
}

static void
init_port(void)
{
	/* Configuration of Ethernet ports. */
	ports = rte_zmalloc("testpmd: ports",
			    sizeof(struct rte_port) * RTE_MAX_ETHPORTS,
			    RTE_CACHE_LINE_SIZE);
	if (ports == NULL) {
		rte_exit(EXIT_FAILURE,
				"rte_zmalloc(%d struct rte_port) failed\n",
				RTE_MAX_ETHPORTS);
	}

	/* Initialize ports NUMA structures */
	memset(port_numa, NUMA_NO_CONFIG, RTE_MAX_ETHPORTS);
	memset(rxring_numa, NUMA_NO_CONFIG, RTE_MAX_ETHPORTS);
	memset(txring_numa, NUMA_NO_CONFIG, RTE_MAX_ETHPORTS);
}

static void
print_stats(void)
{
	uint8_t i;
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char top_left[] = { 27, '[', '1', ';', '1', 'H', '\0' };

	/* Clear screen and move to top left */
	printf("%s%s", clr, top_left);

	printf("\nPort statistics ====================================");
	for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++)
		nic_stats_display(fwd_ports_ids[i]);

	fflush(stdout);
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\nSignal %d received, preparing to exit...\n",
				signum);
#ifdef RTE_LIBRTE_PDUMP
		/* uninitialize packet capture framework */
		rte_pdump_uninit();
#endif
#ifdef RTE_LIBRTE_LATENCY_STATS
		if (latencystats_enabled != 0)
			rte_latencystats_uninit();
#endif
		/* Set flag to indicate the force termination. */
		f_quit = 1;
		if (interactive == 1) {
			dup2(testpmd_cl->s_in, testpmd_fd_copy);
			close(testpmd_cl->s_in);
		} else {
			dup2(0, testpmd_fd_copy);
			close(0);
		}

	}
}
#define TEST_MEMZONE_NAME(suffix) "MZ_TEST_" suffix
#define HPRE_TST_PRT		printf
#define BN_ULONG		unsigned long
#define RSA_NO_PADDING		3
#define HPRE_TST_MAX_Q		1
#define HPRE_PADDING_SZ		16
#define TEST_MAX_THRD		128
#define MAX_TRY_TIMES		10000
#define LOG_INTVL_NUM		8
#define WD_RSA_CTX_MSG_NUM		64
#define WD_DH_CTX_MSG_NUM		64
#define DH_GENERATOR_2			2
#define DH_GENERATOR_5			5
#define TEST_CNT		10



static int openssl_check;

#define offsetof(t, m) ((size_t) &((t *)0)->m)
#define container_of(ptr, type, member) ({ \
		typeof(((type *)0)->member)(*__mptr) = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); })

/* stub structures */
struct rsa_st {
	int xxx;
};

struct dh_st {
	int xxx;
};

struct bn_gencb_st {
	int xxx;
};

struct bignum_st {
	BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
					 * chunks. */
	int top;                    /* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;                   /* Size of the d array. */
	int neg;                    /* one if the number is negative */
	int flags;
};

/* stub definitions */
typedef struct rsa_st RSA;
typedef struct dh_st DH;
typedef struct bignum_st BIGNUM;
typedef struct bn_gencb_st BN_GENCB;

BIGNUM *BN_new(void);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
void BN_free(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
RSA *RSA_new(void);
void RSA_free(RSA *rsa);
int BN_set_word(BIGNUM *a, BN_ULONG w);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb);
void RSA_get0_key(const RSA *r,
				  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r,
						 const BIGNUM **dmp1, const BIGNUM **dmq1,
						 const BIGNUM **iqmp);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1,
						BIGNUM *iqmp);
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_public_encrypt(int flen, const unsigned char *from,
					   unsigned char *to, RSA *rsa, int padding);
int RSA_private_decrypt(int flen, const unsigned char *from,
						unsigned char *to, RSA *rsa, int padding);
DH *DH_new(void);
void DH_free(DH *r);
int DH_generate_parameters_ex(DH *dh, int prime_len, int generator,
							  BN_GENCB *cb);
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
				 const BIGNUM **g);
int DH_generate_key(DH *dh);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
				 const BIGNUM **priv_key);
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

static struct wd_blkpool* g_pool = NULL;
static struct rte_memzone *g_mz = NULL;


void* third_mem_alloc(void *usr, size_t size)
{
	g_mz = rte_memzone_reserve(TEST_MEMZONE_NAME("flag_zone_2M"),
			1, SOCKET_ID_ANY, RTE_MEMZONE_2MB);

	if (g_mz == NULL) {
		printf("MEMZONE FLAG 2M\n");
		return NULL;
	}

	if (g_mz->hugepage_sz != RTE_PGSIZE_2M) {
		printf("hugepage_sz not equal 2M\n");
		return NULL;
	}

	printf("%s->%d: 0x%llx, 0x%x, 0x%llx, 0x%llx\n", __func__, __LINE__,
		g_mz, g_mz->hugepage_sz, g_mz->addr, g_mz->phys_addr);


	printf("%s succ!\n", __func__);

	return g_mz->addr;
}

void third_mem_free(void *usr, void *va)
{
	if (rte_memzone_free(g_mz)) {
		printf("Fail memzone free\n");
	}
}

void* third_mem_map(void *usr, void *va, size_t sz)
{
	return g_mz->phys_addr + va - g_mz->addr;
}

void third_mem_unmap(void *usr, void *va, void *dma, size_t sz)
{
	return;
}

int hpre_dh_test(void *c, struct hpre_queue_mempool *pool)
{
	DH *a = NULL, *b = NULL;
	int ret, generator = DH_GENERATOR_5;
	struct wcrypto_dh_op_data opdata_a;
	struct wcrypto_dh_op_data tmp_opdata_a;
	struct wcrypto_dh_op_data opdata_b;
	const BIGNUM *ap = NULL, *ag = NULL,
			*apub_key = NULL, *apriv_key = NULL;
	const BIGNUM *bp = NULL, *bg = NULL,
			*bpub_key = NULL, *bpriv_key = NULL;
	unsigned char *ap_bin = NULL, *ag_bin = NULL,
			*apub_key_bin = NULL, *apriv_key_bin = NULL;
	unsigned char *bp_bin = NULL, *bg_bin = NULL,
			*bpub_key_bin = NULL, *bpriv_key_bin = NULL;
	unsigned char *abuf = NULL;
	struct wd_dtb g;
	__u32 gbytes;
	void *tag = NULL;
	int key_size, key_bits, i;

	memset(&opdata_a, 0, sizeof(opdata_a));
	memset(&opdata_b, 0, sizeof(opdata_b));

	a = DH_new();
	b = DH_new();
	if (!a || !b) {
		printf("New DH fail!\n");
		return -1;
	}
	if (wcrypto_dh_is_g2(c))
		generator = DH_GENERATOR_2;

	key_bits = wcrypto_dh_key_bits(c);
	key_size = key_bits >> 3;

	/* Alice generates DH parameters */
	ret = DH_generate_parameters_ex(a, key_bits, generator, NULL);
	if (!ret) {
		printf("DH_generate_parameters_ex fail!\n");
		goto dh_err;
	}
	DH_get0_pqg(a, &ap, NULL, &ag);
	bp = BN_dup(ap);
	bg = BN_dup(ag);
	if (!bp || !bg) {
		printf("bn dump fail!\n");
		ret = -1;
		goto dh_err;
	}
	/* Set the same parameters on Bob as Alice :) */
	DH_set0_pqg(b, (BIGNUM *)bp, NULL, (BIGNUM *)bg);
	if (!DH_generate_key(a)) {
		printf("a DH_generate_key fail!\n");
		ret = -1;
		goto dh_err;
	}
	DH_get0_key(a, &apub_key, &apriv_key);
	ag_bin = wd_alloc_blk(pool);
	if (!ag_bin) {
		printf("pool alloc ag_bin fail!\n");
		goto dh_err;
	}
	memset(ag_bin, 0, key_size * 2);
	apriv_key_bin = wd_alloc_blk(pool);
	if (!apriv_key_bin) {
		printf("pool alloc apriv_key_bin fail!\n");
		goto dh_err;
	}
	memset(apriv_key_bin, 0, key_size * 2);

	/* The hpre_UM tells us key_addr contains xa and p,
	 * their addr should be together
	 */
	ap_bin= apriv_key_bin + key_size;

	gbytes = BN_bn2bin(ag, ag_bin);
	g.data = (char*)ag_bin;
	g.bsize = gbytes;
	g.dsize = key_size;
	opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
	opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
	ret = wcrypto_set_dh_g(c, &g);
	if (ret) {
		printf("Alice wcrypto_set_dh_g fail!\n");
		goto dh_err;
	}
	opdata_a.x_p = apriv_key_bin;
	opdata_a.pri = wd_alloc_blk(pool);
	if (!opdata_a.pri) {
		printf("pool alloc opdata_a.pri fail!\n");
		goto dh_err;
	}
	memset(opdata_a.pri, 0, key_size * 2);

	opdata_a.op_type = WCRYPTO_DH_PHASE1;

	/* Alice computes public key */
	ret = wcrypto_do_dh(c, &opdata_a, tag);
	if (ret) {
		printf("a wcrypto_do_dh fail!\n");
		goto dh_err;
	}
	if (openssl_check) {
		apub_key_bin = malloc(key_size);
		if (!apub_key_bin) {
			printf("malloc apub_key_bin fail!\n");
			ret = -ENOMEM;
			goto dh_err;
		}
		ret = BN_bn2bin(apub_key, apub_key_bin);
		if (!ret) {
			printf("apub_key bn 2 bin fail!\n");
			goto dh_err;
		}
		ret = hpre_bn_format(apub_key_bin, key_size, key_size);
		if (ret) {
			printf("hpre_bn_format bpub_key bin fail!\n");
			goto dh_err;
		}

		for (i = key_size - 1; apub_key_bin[i] == 0 && i >= 0; i--) {
			ret = test_hpre_bin_to_crypto_bin(opdata_a.pri, opdata_a.pri, key_size);
			if (ret) {
				printf("dh out share key format fail!\n");
				goto dh_err;
			}
			ret = 0;
			break;
		}

		if (memcmp(apub_key_bin, opdata_a.pri, key_size)) {
			printf("Alice HPRE DH key gen pub mismatch!\n");
			ret = -EINVAL;
			goto dh_err;
		}
	}
	if (!DH_generate_key(b)) {
		printf("b DH_generate_key fail!\n");
		ret = -1;
		goto dh_err;
	}
	DH_get0_key(b, &bpub_key, &bpriv_key);
	bg_bin = wd_alloc_blk(pool);
	if (!bg_bin) {
		printf("pool alloc bg_bin fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(bg_bin, 0, key_size * 2);

	bpriv_key_bin= wd_alloc_blk(pool);
	if (!bpriv_key_bin) {
		printf("pool alloc bpriv_key_bin fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(bpriv_key_bin, 0, key_size * 2);
	bp_bin = bpriv_key_bin + key_size;
	gbytes = BN_bn2bin(bg, bg_bin);
	g.data = (char*)bg_bin;
	g.bsize = gbytes;
	g.dsize = key_size;
	ret = wcrypto_set_dh_g(c, &g);
	if (ret) {
		printf("bob wcrypto_set_dh_g fail!\n");
		goto dh_err;
	}
	opdata_b.pbytes = BN_bn2bin(bp, bp_bin);
	opdata_b.xbytes = BN_bn2bin(bpriv_key, bpriv_key_bin);
	opdata_b.x_p = bpriv_key_bin;
	opdata_b.pri = wd_alloc_blk(pool);
	if (!opdata_b.pri) {
		printf("pool alloc opdata_b.pri fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(opdata_b.pri, 0, key_size * 2);
	opdata_b.op_type = WCRYPTO_DH_PHASE1;

	/* Bob computes public key */
	ret = wcrypto_do_dh(c, &opdata_b, tag);
	if (ret) {
		printf("b wcrypto_do_dh fail!\n");
		goto dh_err;
	}
	if (openssl_check) {
		bpub_key_bin = malloc(key_size);
		if (!bpub_key_bin) {
			printf("malloc bpub_key_bin fail!\n");
			ret = -1;
			goto dh_err;
		}
		ret = BN_bn2bin(bpub_key, bpub_key_bin);
		if (!ret) {
			printf("bpub_key bn 2 bin fail!\n");
			goto dh_err;
		}
		ret = hpre_bn_format(bpub_key_bin, key_size, key_size);
		if (ret) {
			printf("hpre_bn_format bpub_key bin fail!\n");
			goto dh_err;
		}

		for (i = key_size - 1; bpub_key_bin[i] == 0 && i >= 0; i--) {
			ret = test_hpre_bin_to_crypto_bin(opdata_b.pri, opdata_b.pri, key_size);
			if (ret) {
				printf("dh out share key format fail!\n");
				goto dh_err;
			}
			ret = 0;
			break;
		}

		if (memcmp(bpub_key_bin, opdata_b.pri, key_size)) {
			printf("Bob HPRE DH key gen pub mismatch!\n");
			ret = -EINVAL;
			goto dh_err;
		}
	}
	/* Alice computes private key with OpenSSL */
	abuf = malloc(key_size);
	if (!abuf) {
		printf("malloc abuf fail!\n");
		ret = -ENOMEM;
		goto dh_err;
	}
	memset(abuf, 0, key_size);
	if (openssl_check) {
		ret = DH_compute_key(abuf, bpub_key, a);
		if (!ret) {
			printf("DH_compute_key fail!\n");
			ret = -1;
			goto dh_err;
		}
	}

	/* Alice computes private key with HW accelerator */
	memset(ag_bin, 0, key_size * 2);
	memset(apriv_key_bin, 0, key_size * 2);
	ap_bin = apriv_key_bin + key_size;
	memset(opdata_a.pri, 0, key_size * 2);

	memcpy(&tmp_opdata_a, &opdata_a, sizeof(tmp_opdata_a));
	opdata_a.pvbytes = BN_bn2bin(bpub_key, ag_bin);
	opdata_a.pv = ag_bin;/* bob's public key here */
	opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
	opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
	opdata_a.x_p = apriv_key_bin;
	opdata_a.pri = wd_alloc_blk(pool);
	if (!opdata_a.pri) {
		printf("pool alloc opdata_a.pri fail!\n");
		ret = -1;
		goto dh_err;
	}
	memset(opdata_a.pri, 0, key_size * 2);
	opdata_a.op_type = WCRYPTO_DH_PHASE2;

	/* Alice computes private key with HPRE */
	ret = wcrypto_do_dh(c, &opdata_a, tag);
	if (ret) {
		printf("a wcrypto_do_dh fail!\n");
		goto dh_err;
	}
	if (openssl_check) {
		ret = hpre_bn_format(abuf, key_size, key_size);
		if (ret) {
			printf("hpre_bn_format bpub_key bin fail!\n");
			goto dh_err;
		}

		for (i = key_size - 1; abuf[i] == 0 && i >= 0; i--) {
			ret = test_hpre_bin_to_crypto_bin(opdata_a.pri, opdata_a.pri, key_size);
			if (ret) {
				printf("dh out share key format fail!\n");
				goto dh_err;
			}
			ret = 0;
			break;
		}

		if (memcmp(abuf, opdata_a.pri, key_size)) {
			printf("Alice HPRE DH gen privkey mismatch!\n");
			ret = -EINVAL;
			goto dh_err;
		}
	}
	printf("HPRE DH generate key sucessfully!\n");
	dh_err:
	DH_free(a);
	DH_free(b);

	wcrypto_del_dh_ctx(c);

	if (ag_bin)
		wd_free_blk(pool, ag_bin);
	if (apriv_key_bin)
		wd_free_blk(pool, apriv_key_bin);
	if (opdata_a.pri)
		wd_free_blk(pool, opdata_a.pri);

	if (bg_bin)
		wd_free_blk(pool, bg_bin);
	if (bpriv_key_bin)
		wd_free_blk(pool, bpriv_key_bin);
	if (opdata_b.pri)
		wd_free_blk(pool, opdata_b.pri);

	if (tmp_opdata_a.pri)
		wd_free_blk(pool, tmp_opdata_a.pri);

	if (apub_key_bin)
		free(apub_key_bin);
	if (bpub_key_bin)
		free(bpub_key_bin);
	if (abuf)
		free(abuf);


	return ret;
}

int third_mem_create_blk_pool(void)
{
	struct wd_blkpool_setup blk_setup;
	int ret;

	memset(&blk_setup, 0, sizeof(blk_setup));

	blk_setup.align_size = 64;
	blk_setup.block_num = 10;
	blk_setup.block_size = 2048;
	blk_setup.br.alloc = third_mem_alloc;
	blk_setup.br.free = third_mem_free;
	blk_setup.br.iova_map = third_mem_map;
	blk_setup.br.iova_unmap = third_mem_unmap;
	g_pool = wd_blkpool_create(NULL, &blk_setup);
	if (!g_pool) {
		printf("%s(): create ctx pool fail!\n", __func__);
		return -EINVAL;
	}

	return 0;
	
}

void third_mem_destroy_blk_pool(void)
{
	__u32 free_num = 0;

	wd_get_free_blk_num(g_pool, &free_num);

	printf("free blk num %d\n", free_num);
	wd_blkpool_destroy(g_pool);

}

int third_mem_do_dh(void)
{
	struct wcrypto_dh_ctx_setup setup;
	struct wd_queue q;
	void *ctx = NULL;
	int ret;

	memset(&q, 0, sizeof(q));
	q.capa.alg = "dh";

	ret = wd_request_queue(&q);
	if (ret) {
		printf("request queue fail!\n");
		return ret;
	}

	memset(&setup, 0, sizeof(setup));
	setup.br.alloc = wd_alloc_blk;
	setup.br.free = wd_free_blk;
	setup.br.iova_map = (void *)wd_blk_iova_map;
	setup.br.iova_unmap = wd_blk_iova_unmap;
	setup.br.usr = g_pool;
	setup.key_bits = 1024;
	ctx = wcrypto_create_dh_ctx(&q, &setup);
	if (!ctx) {
		ret = -ENOMEM;
		printf("create dh ctx fail!\n");
		return ret;
	}
	
	return hpre_dh_test(ctx, g_pool);

}


int
main(int argc, char** argv)
{
	int diag;
	portid_t port_id;
	uint16_t count;
	int ret;
	int s;
	const struct rte_memzone *mz;
	char* ptr;
	size_t size = 1;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	testpmd_logtype = rte_log_register("testpmd");
	if (testpmd_logtype < 0)
		rte_exit(EXIT_FAILURE, "Cannot register log type");
	rte_log_set_level(testpmd_logtype, RTE_LOG_DEBUG);

	diag = rte_eal_init(argc, argv);
	if (diag < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL: %s\n",
			 rte_strerror(rte_errno));

	ret = third_mem_create_blk_pool();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "create pool err: %d\n", ret);


	ret = third_mem_do_dh();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "do dh err: %d\n", ret);

	third_mem_destroy_blk_pool();


#if 0
	mz = rte_memzone_reserve(TEST_MEMZONE_NAME("flag_zone_1G"),
			size, SOCKET_ID_ANY, RTE_MEMZONE_1GB);
	if (mz == NULL) {
		printf("MEMZONE FLAG 16MB\n");
		return -1;
	}

	printf("%s->%d: 0x%x, 0x%llx, 0x%llx\n", __func__, __LINE__, mz->hugepage_sz,
		mz->addr, mz->phys_addr);

	if (mz->hugepage_sz != RTE_PGSIZE_1G) {
		printf("hugepage_sz not equal 1G\n");
		return -1;
	}
	printf("%s->%d: xxx\n", __func__, __LINE__);

	ptr = mz->addr;
	*ptr = 0xEF;

	printf("%s->%d: *ptr %d\n", __func__, __LINE__, *ptr);


	if (rte_memzone_free(mz)) {
		printf("Fail memzone free\n");
		return -1;
	}
	printf("%s->%d: xxx\n", __func__, __LINE__);


#endif
	








	sleep(10000);

	ret = register_eth_event_callback();
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Cannot register for ethdev events");

#ifdef RTE_LIBRTE_PDUMP
	/* initialize packet capture framework */
	rte_pdump_init();
#endif

	count = 0;
	RTE_ETH_FOREACH_DEV(port_id) {
		ports_ids[count] = port_id;
		count++;
	}
	nb_ports = (portid_t) count;
	if (nb_ports == 0)
		TESTPMD_LOG(WARNING, "No probed ethernet devices\n");

	/* allocate port structures, and init them */
	init_port();

	set_def_fwd_config();
	if (nb_lcores == 0)
		rte_exit(EXIT_FAILURE, "No cores defined for forwarding\n"
			 "Check the core mask argument\n");

	/* Bitrate/latency stats disabled by default */
#ifdef RTE_LIBRTE_BITRATE
	bitrate_enabled = 0;
#endif
#ifdef RTE_LIBRTE_LATENCY_STATS
	latencystats_enabled = 0;
#endif

	/* on FreeBSD, mlockall() is disabled by default */
#ifdef RTE_EXEC_ENV_FREEBSD
	do_mlockall = 0;
#else
	do_mlockall = 1;
#endif

	argc -= diag;
	argv += diag;
	if (argc > 1)
		launch_args_parse(argc, argv);

	if (do_mlockall && mlockall(MCL_CURRENT | MCL_FUTURE)) {
		TESTPMD_LOG(NOTICE, "mlockall() failed with error \"%s\"\n",
			strerror(errno));
	}

	if (tx_first && interactive)
		rte_exit(EXIT_FAILURE, "--tx-first cannot be used on "
				"interactive mode.\n");

	if (tx_first && lsc_interrupt) {
		printf("Warning: lsc_interrupt needs to be off when "
				" using tx_first. Disabling.\n");
		lsc_interrupt = 0;
	}

	if (!nb_rxq && !nb_txq)
		printf("Warning: Either rx or tx queues should be non-zero\n");

	if (nb_rxq > 1 && nb_rxq > nb_txq)
		printf("Warning: nb_rxq=%d enables RSS configuration, "
		       "but nb_txq=%d will prevent to fully test it.\n",
		       nb_rxq, nb_txq);

	init_config();

	if (hot_plug) {
		ret = rte_dev_hotplug_handle_enable();
		if (ret) {
			RTE_LOG(ERR, EAL,
				"fail to enable hotplug handling.");
			return -1;
		}

		ret = rte_dev_event_monitor_start();
		if (ret) {
			RTE_LOG(ERR, EAL,
				"fail to start device event monitoring.");
			return -1;
		}

		ret = rte_dev_event_callback_register(NULL,
			dev_event_callback, NULL);
		if (ret) {
			RTE_LOG(ERR, EAL,
				"fail  to register device event callback\n");
			return -1;
		}
	}

	if (!no_device_start && start_port(RTE_PORT_ALL) != 0) {
		pmd_test_exit();
		rte_exit(EXIT_FAILURE, "Start ports failed\n");
	}

	/* set all ports to promiscuous mode by default */
	RTE_ETH_FOREACH_DEV(port_id) {
		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			printf("Error during enabling promiscuous mode for port %u: %s - ignore\n",
				port_id, rte_strerror(-ret));
	}

	/* Init metrics library */
	rte_metrics_init(rte_socket_id());

#ifdef RTE_LIBRTE_LATENCY_STATS
	if (latencystats_enabled != 0) {
		int ret = rte_latencystats_init(1, NULL);
		if (ret)
			printf("Warning: latencystats init()"
				" returned error %d\n",	ret);
		printf("Latencystats running on lcore %d\n",
			latencystats_lcore_id);
	}
#endif

	/* Setup bitrate stats */
#ifdef RTE_LIBRTE_BITRATE
	if (bitrate_enabled != 0) {
		bitrate_data = rte_stats_bitrate_create();
		if (bitrate_data == NULL)
			rte_exit(EXIT_FAILURE,
				"Could not allocate bitrate data.\n");
		rte_stats_bitrate_reg(bitrate_data);
	}
#endif

#ifdef RTE_LIBRTE_CMDLINE
	if (strlen(cmdline_filename) != 0)
		cmdline_read_from_file(cmdline_filename);

	if (interactive == 1) {
		if (auto_start) {
			printf("Start automatic packet forwarding\n");
			start_packet_forwarding(0);
		}
		prompt();
		pmd_test_exit();
		if (unlikely(f_quit == 1)) {
			prompt_exit();
		}
	} else
#endif
	{
		char c;
		int rc;

		f_quit = 0;

		printf("No commandline core given, start packet forwarding\n");
		start_packet_forwarding(tx_first);
		if (stats_period != 0) {
			uint64_t prev_time = 0, cur_time, diff_time = 0;
			uint64_t timer_period;

			/* Convert to number of cycles */
			timer_period = stats_period * rte_get_timer_hz();

			while (f_quit == 0) {
				cur_time = rte_get_timer_cycles();
				diff_time += cur_time - prev_time;

				if (diff_time >= timer_period) {
					print_stats();
					/* Reset the timer */
					diff_time = 0;
				}
				/* Sleep to avoid unnecessary checks */
				prev_time = cur_time;
				sleep(1);
			}
		}

		printf("Press enter to exit\n");
		rc = read(0, &c, 1);
		pmd_test_exit();
		if (unlikely(f_quit == 1)) {
			dup2(testpmd_fd_copy, 0);
			close(testpmd_fd_copy);
			prompt_exit();
		}
		if (rc < 0)
			return 1;
	}

	return 0;
}
