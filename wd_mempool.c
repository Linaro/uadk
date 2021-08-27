/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <dirent.h>
#include <errno.h>
#include <numa.h>
#include <numaif.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/queue.h>
#include "wd.h"

#define SYSFS_NODE_PATH			"/sys/devices/system/node/node"
#define MAX_HP_STR_SIZE			64
#define MISC_DVE_UACCE_CTRL		"/dev/uacce_ctrl"
#define HUGETLB_FLAG_ENCODE_SHIFT	26

#define BITS_PER_LONG			((int)sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(bits) \
	(((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define BIT_MASK(nr)			((unsigned long)(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)			((nr) / BITS_PER_LONG)
#define BITMAP_FIRST_WORD_MASK(start) \
	(~0UL << ((start) & (BITS_PER_LONG - 1)))

#define __round_mask(x, y)		((__typeof__(x))((y)-1))
#define round_down(x, y)		((x) & ~__round_mask(x, y))
#define __maybe_unused			__attribute__((__unused__))
#define WD_MEMPOOL_BLOCK_SIZE		((unsigned long)1 << 12)
#define WD_MEMPOOL_SIZE_MASK		(WD_MEMPOOL_BLOCK_SIZE - 1)
#define WD_MEMPOOL_NO_NUMA		-1
#define WD_HUNDRED			100

struct wd_lock {
	__u32 lock;
};

static inline void wd_spinlock(struct wd_lock *lock)
{
	while (__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE))
		while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED));
}

static inline void wd_unspinlock(struct wd_lock *lock)
{
	__atomic_clear(&lock->lock, __ATOMIC_RELEASE);
}

struct wd_ref {
	__u32 ref;
};

/*
 * wd_atomic_test_add - add unless the number is already a given value
 * @ref: pointer of type struct wd_ref
 * @a: the amount to add to ref->ref...
 * @u: ...unless ref->ref is equal to u.
 *
 * Return number of ref->ref if successful; On error, u is returned.
 */
static inline int wd_atomic_test_add(struct wd_ref *ref, int a, int u)
{
	int c;

	do {
		c = __atomic_load_n(&ref->ref, __ATOMIC_RELAXED);
		if (c == u)
			break;
	} while (! __atomic_compare_exchange_n(&ref->ref, &c, c + a, true,
					       __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	return c;
}

static inline void wd_atomic_add(struct wd_ref *ref, int a)
{
	__atomic_add_fetch(&ref->ref, a, __ATOMIC_RELAXED);
}

static inline void wd_atomic_sub(struct wd_ref *ref, int a)
{
	__atomic_sub_fetch(&ref->ref, a, __ATOMIC_RELAXED);
}

static inline int wd_atomic_load(struct wd_ref *ref)
{
	return __atomic_load_n(&ref->ref, __ATOMIC_RELAXED);
}

/*
 * one memzone may include some continuous block in mempool
 * @addr: Base address of blocks in this memzone
 * @blk_num: Number of blocks in this memzone
 * @begin: Begin position in mempool bitmap
 * @end: End position in mempool bitmap
 */
struct memzone {
	void *addr;
	size_t blk_num;
	size_t begin;
	size_t end;
	TAILQ_ENTRY(memzone) node;
};
TAILQ_HEAD(memzone_list, memzone);

/*
 * @blk_elem: All the block unit addrs saved in blk_elem
 * @depth: The block pool deph, stack depth
 * @top: The stack top pos for blk_elem
 * @blk_size: The size of one block
 * @mp: Record from which mempool
 * @mz_list: List of memzone allocated from mempool
 * @free_block_num: Number of free blocks currently
 * @lock: lock of blkpool
 * @ref: ref of blkpool
 */
struct blkpool {
	void **blk_elem;
	size_t depth;
	size_t top;
	size_t blk_size;
	struct mempool *mp;
	struct memzone_list mz_list;
	unsigned long free_block_num;
	struct wd_lock lock;
	struct wd_ref ref;
};

struct sys_hugepage_config {
	/* unit is Byte */
	unsigned long page_size;
	size_t total_num;
	size_t free_num;
	TAILQ_ENTRY(sys_hugepage_config) node;
};
TAILQ_HEAD(sys_hugepage_list, sys_hugepage_config);

struct bitmap {
	unsigned long *map;
	unsigned long bits;
	unsigned long map_byte;
};

struct mempool {
	enum wd_page_type page_type;
	unsigned long page_size;
	unsigned int page_num;
	unsigned long blk_size;
	unsigned int blk_num;
	/* numa node id */
	int node;
	/* fd for page pin */
	int fd;
	int mp_ref;
	void *addr;
	size_t size;
	size_t real_size;
	struct bitmap *bitmap;
	/* use self-define lock to avoid to use pthread lib in libwd */
	struct wd_lock lock;
	struct wd_ref ref;
	struct sys_hugepage_list hp_list;
	unsigned long free_blk_num;
};

/*
 * This function is copied from kernel head file. It finds first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long wd_ffs(unsigned long word)
{
	int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static struct bitmap *create_bitmap(int bits)
{
	struct bitmap *bm = calloc(1, sizeof(*bm));
	if (!bm)
		return NULL;

	bm->map = calloc(BITS_TO_LONGS(bits), sizeof(unsigned long));
	if (!bm->map) {
		free(bm);
		return NULL;
	}

	bm->bits = bits;
	bm->map_byte = BITS_TO_LONGS(bits);

	return bm;
}

static void destroy_bitmap(struct bitmap *bm)
{
	free(bm->map);
	free(bm);
}

static unsigned long _find_next_bit(unsigned long *map, unsigned long bits,
				    unsigned long start, unsigned long invert)
{
	unsigned long tmp, mask, next_bit;

	if (start >= bits)
		return bits;

	tmp = map[start / BITS_PER_LONG];
	tmp ^= invert;

	mask = BITMAP_FIRST_WORD_MASK(start);
	tmp &= mask;
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start > bits)
			return bits;

		tmp = map[start / BITS_PER_LONG];
		tmp ^= invert;
	}

	next_bit = start + wd_ffs(tmp);
	return MIN(next_bit, bits);
}

static unsigned long find_next_zero_bit(struct bitmap *bm, unsigned long start)
{
	return _find_next_bit(bm->map, bm->bits, start, ~0UL);
}

static void set_bit(struct bitmap *bm, int pos)
{
	unsigned long *map = bm->map;
	unsigned long mask = BIT_MASK(pos);
	unsigned long *p = map + BIT_WORD(pos);

	*p |= mask;
}

static void clear_bit(struct bitmap *bm, int pos)
{
	unsigned long *map = bm->map;
	unsigned long mask = BIT_MASK(pos);
	unsigned long *p = map + BIT_WORD(pos);

	*p &= ~mask;
}

static int test_bit(struct bitmap *bm, int nr)
{
	unsigned long *p = bm->map + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);

	return !(*p & mask);
}

inline static size_t wd_get_page_size(void)
{
	return sysconf(_SC_PAGESIZE);
}

void *wd_block_alloc(handle_t blkpool)
{
	struct blkpool *bp = (struct blkpool*)blkpool;
	void *p;

	if (!bp)
		return NULL;

	if (!wd_atomic_test_add(&bp->ref, 1, 0)) {
		return NULL;
	}

	wd_spinlock(&bp->lock);
	if (bp->top > 0) {
		bp->top--;
		bp->free_block_num--;
		p = bp->blk_elem[bp->top];
		wd_unspinlock(&bp->lock);
		return p;
	}

	wd_unspinlock(&bp->lock);
	wd_atomic_sub(&bp->ref, 1);

	return NULL;
}

void wd_block_free(handle_t blkpool, void *addr)
{
	struct blkpool *bp = (struct blkpool*)blkpool;

	if (!bp || !addr)
		return;

	wd_spinlock(&bp->lock);
	if (bp->top < bp->depth) {
		bp->blk_elem[bp->top] = addr;
		bp->top++;
		bp->free_block_num++;
		wd_unspinlock(&bp->lock);
		wd_atomic_sub(&bp->ref, 1);
		return;
	}

	wd_unspinlock(&bp->lock);
}

static int alloc_memzone(struct blkpool *bp, void *addr, size_t blk_num,
			 size_t begin, size_t end)
{
	struct memzone *zone;

	zone = calloc(1, sizeof(struct memzone));
	if (!zone) {
		return -ENOMEM;
	}

	zone->addr = addr;
	zone->blk_num = blk_num;
	zone->begin = begin;
	zone->end = end;
	TAILQ_INSERT_TAIL(&bp->mz_list, zone, node);

	return 0;
}

static void free_mem_to_mempool_nolock(struct blkpool *bp)
{
	struct mempool *mp = bp->mp;
	struct memzone *iter;
	size_t blks;
	int i;

	while ((iter = TAILQ_LAST(&bp->mz_list, memzone_list))) {
		for (i = iter->begin; i <= iter->end; i++)
			clear_bit(mp->bitmap, i);
		blks = iter->end - iter->begin + 1;
		mp->free_blk_num += blks;
		mp->real_size += blks * mp->blk_size;

		TAILQ_REMOVE(&bp->mz_list, iter, node);
		free(iter);
	}
}

static void free_mem_to_mempool(struct blkpool *bp)
{
	struct mempool *mp = bp->mp;

	wd_spinlock(&mp->lock);
	free_mem_to_mempool_nolock(bp);
	wd_unspinlock(&mp->lock);
}

static int check_mempool_real_size(struct mempool *mp, struct blkpool *bp)
{
	if (bp->blk_size * bp->depth > mp->real_size) {
		WD_ERR("WD_MMEPOOL: Failed to create blkpool as mempool too small: %lu\n",
		       mp->real_size);
		return -ENOMEM;
	}

	return 0;
}

static int alloc_block_from_mempool(struct mempool *mp,
					struct blkpool *bp,
					int pos,
					int mem_combined_num,
					int mem_splited_num)
{
	int pos_first = pos;
	int pos_last = pos;
	int i, ret;

	do {
		pos_first = find_next_zero_bit(mp->bitmap, pos_last);
		if (pos_first == mp->bitmap->bits)
			return -ENOMEM;

		pos_last = pos_first;
		for (i = 0; i < mem_combined_num - 1; i++) {
			if (!test_bit(mp->bitmap, ++pos_last))
				break;
		}
	} while (i != mem_combined_num - 1);

	for (i = pos_last; i >= pos_first; i--)
		set_bit(mp->bitmap, i);

	ret = alloc_memzone(bp, mp->addr + pos_first * mp->blk_size,
				mem_splited_num, pos_first, pos_last);
	if (ret < 0)
		goto err_clear_bit;

	return pos_last;

err_clear_bit:
	for (i = pos_last; i >= pos_first; i--)
		clear_bit(mp->bitmap, i);
	return -ENOMEM;
}

/* In this case, multiple blocks are in one mem block */
static int alloc_mem_multi_in_one(struct mempool *mp, struct blkpool *bp)
{
	int mem_splited_num = mp->blk_size / bp->blk_size;
	int blk_num = bp->depth;
	int ret = -ENOMEM;
	int pos = 0;

	wd_spinlock(&mp->lock);
	if (check_mempool_real_size(mp, bp))
		goto err_check_size;

	while (blk_num > 0) {
		ret = alloc_block_from_mempool(mp, bp, pos, 1,
						MIN(blk_num, mem_splited_num));
		if (ret < 0)
			goto err_free_memzone;

		mp->free_blk_num--;
		mp->real_size -= mp->blk_size;
		blk_num -= mem_splited_num;
		pos = ret;
	}

	wd_unspinlock(&mp->lock);
	return 0;

err_free_memzone:
	free_mem_to_mempool_nolock(bp);
err_check_size:
	wd_unspinlock(&mp->lock);
	return ret;
}

/*
 * In this case, multiple continuous mem blocks should be allocated for one
 * block in blkpool
 */
static int alloc_mem_one_need_multi(struct mempool *mp, struct blkpool *bp)
{
	int mem_combined_num = bp->blk_size / mp->blk_size +
				 (bp->blk_size % mp->blk_size ? 1 : 0);
	int blk_num = bp->depth;
	int pos = 0;
	int ret;

	wd_spinlock(&mp->lock);
	if (check_mempool_real_size(mp, bp)) {
		ret = -ENOMEM;
		goto err_check_size;
	}

	while (blk_num > 0) {
		ret = alloc_block_from_mempool(mp, bp, pos,
						mem_combined_num, 1);
		if (ret < 0)
			goto err_free_memzone;

		pos = ret;
		blk_num--;
		mp->free_blk_num -= mem_combined_num;
		mp->real_size -= mp->blk_size * mem_combined_num;
	}

	wd_unspinlock(&mp->lock);
	return 0;

err_free_memzone:
	free_mem_to_mempool_nolock(bp);
err_check_size:
	wd_unspinlock(&mp->lock);
	return ret;
}

static int alloc_mem_from_mempool(struct mempool *mp, struct blkpool *bp)
{
	TAILQ_INIT(&bp->mz_list);

	if (mp->blk_size >= bp->blk_size)
		return alloc_mem_multi_in_one(mp, bp);

	return alloc_mem_one_need_multi(mp, bp);
}

static int init_blkpool_elem(struct blkpool *bp)
{
	struct memzone *iter;
	int idx = 0;
	int i;

	bp->blk_elem = calloc(bp->depth, sizeof(void *));
	if (!bp->blk_elem)
		return -ENOMEM;

	TAILQ_FOREACH(iter, &bp->mz_list, node) {
		for (i = 0; i < iter->blk_num; i++)
			bp->blk_elem[idx++] = iter->addr + i * bp->blk_size;
	}

	return 0;
}

handle_t wd_blockpool_create(handle_t mempool, size_t block_size,
			     size_t block_num)
{
	struct mempool *mp = (struct mempool*)mempool;
	struct blkpool *bp;
	int ret;

	if (!mp || !block_size || !block_num) {
		WD_ERR("WD_MMEPOOL: Input parameter is invalid value\n");
		return (handle_t)(-WD_EINVAL);
	}

	if (!wd_atomic_test_add(&mp->ref, 1, 0))
		return (handle_t)(-WD_EBUSY);

	bp = calloc(1, sizeof(struct blkpool));
	if (!bp)
		return (handle_t)(-WD_ENOMEM);

	bp->top = block_num;
	bp->depth = block_num;
	bp->blk_size = block_size;
	bp->free_block_num = block_num;
	bp->mp = mp;

	ret = alloc_mem_from_mempool(mp, bp);
	if (ret < 0) {
		WD_ERR("WD_MMEPOOL: Failed to allocate memory from mempool\n");
		goto err_free_bp;
	}

	ret = init_blkpool_elem(bp);
	if (ret < 0) {
		WD_ERR("WD_MMEPOOL: Failed to init blkpool\n");
		goto err_free_mem;
	}

	wd_atomic_add(&bp->ref, 1);
	return (handle_t)bp;

err_free_mem:
	free_mem_to_mempool(bp);
err_free_bp:
	free(bp);
	wd_atomic_sub(&mp->ref, 1);
	return ret;
}

void wd_blockpool_destroy(handle_t blkpool)
{
	struct blkpool *bp = (struct blkpool *)blkpool;
	struct mempool *mp;

	if (!bp) {
		WD_ERR("WD_MMEPOOL: Blkpool is NULL\n");
		return;
	}

	mp = bp->mp;
	wd_atomic_sub(&bp->ref, 1);
	while(wd_atomic_load(&bp->ref));
	free_mem_to_mempool(bp);
	free(bp->blk_elem);
	free(bp);
	wd_atomic_sub(&mp->ref, 1);
}

static int get_value_from_sysfs(char *path)
{
	char buf[MAX_ATTR_STR_SIZE];
	ssize_t size;
	int fd;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		WD_ERR("WD_MMEPOOL: Failed to open %s\n", path);
		goto err_open;
	}

	size = read(fd, buf, sizeof(buf));
	if (size <= 0) {
		WD_ERR("WD_MMEPOOL: Failed to read %s\n", path);
		goto err_read;
	}

	close(fd);
	return strtol(buf, NULL, 10);

err_read:
	close(fd);
err_open:
	return -errno;
}

/* hp_dir is e.g. /sys/devices/system/node/nodex/hugepages/hugepages-64kB */
static int get_hugepage_info_per_type(char *hugepage_path,
	struct dirent *hp_dir, struct sys_hugepage_config *cfg)
{
	char path[MAX_ATTR_STR_SIZE];
	char *name = hp_dir->d_name;
	unsigned long size;
	char *size_pos;
	int ret;

	size_pos = index(name, '-');
	if (!size_pos)
		return -1;
	size_pos++;

	errno = 0;
	size = strtol(size_pos, NULL, 10);
	if (errno)
		return -errno;
	cfg->page_size = size << 10;

	snprintf(path, sizeof(path), "%s/%s/nr_hugepages", hugepage_path,
		 name);
	ret = get_value_from_sysfs(path);
	if (ret < 0)
		return ret;
	cfg->total_num = ret;

	snprintf(path, sizeof(path), "%s/%s/free_hugepages", hugepage_path,
		 name);
	ret = get_value_from_sysfs(path);
	if (ret < 0)
		return ret;
	cfg->free_num = ret;

	return 1;
}

static void put_hugepage_info(struct mempool *mp)
{
	struct sys_hugepage_config *tmp;

	while ((tmp = TAILQ_LAST(&mp->hp_list, sys_hugepage_list))) {
		TAILQ_REMOVE(&mp->hp_list, tmp, node);
		free(tmp);
	}
}

/* This function also sorts hugepage from small to big */
static int get_hugepage_info(struct mempool *mp)
{
	struct sys_hugepage_config *tmp, *iter;
	char hugepage_path[MAX_HP_STR_SIZE];
	struct dirent *hp_dir;
	DIR *dir;
	int ret;

	if (mp->node == -1)
		return -EINVAL;

	snprintf(hugepage_path, sizeof(hugepage_path), "%s%d/hugepages",
		 SYSFS_NODE_PATH, mp->node);
	dir = opendir(hugepage_path);
	if (!dir) {
		WD_ERR("WD_MMEPOOL: WD_MMEPOOL: Failed to open %s\n",
			hugepage_path);
		return -errno;
	}

	TAILQ_INIT(&mp->hp_list);
	for (hp_dir = readdir(dir); hp_dir != NULL; hp_dir = readdir(dir)) {
		if (!strncmp(hp_dir->d_name, ".", 1) ||
		    !strncmp(hp_dir->d_name, "..", 2))
			continue;

		tmp = calloc(1, sizeof(*tmp));
		if (!tmp) {
			WD_ERR("WD_MMEPOOL: WD_MMEPOOL: Failed to allocate memory\n");
			goto err_free_list;
		}
		ret = get_hugepage_info_per_type(hugepage_path, hp_dir, tmp);
		if (ret < 0) {
			WD_ERR("WD_MMEPOOL: Failed to get hugepage info\n");
			goto err_free;
		}

		/* list: page size small -> big */
		TAILQ_FOREACH(iter, &mp->hp_list, node) {
			if (tmp->page_size < iter->page_size) {
				TAILQ_INSERT_BEFORE(iter, tmp, node);
				break;
			}
		}

		if (!iter)
			TAILQ_INSERT_TAIL(&mp->hp_list, tmp, node);
	}

	closedir(dir);

	return 0;

err_free:
	free(tmp);
err_free_list:
	put_hugepage_info(mp);

	closedir(dir);
	return -WD_EIO;
}

static int mbind_memory(void *addr, size_t size, int node)
{
	unsigned long max_node = numa_max_node() + 2;
	unsigned long node_mask;
	int ret = 0;

	/*
	 * if node is equal to -1, the memory is not bound to numa node by default
	 * or the system does not support numa.
	 */
	if (node == -1)
		return ret;

	node_mask = 1 << node;
	ret = mbind(addr, size, MPOL_BIND, &node_mask, max_node, 0);
	if (ret < 0) {
		WD_ERR("WD_MMEPOOL: Failed to mbind memory, %d\n", ret);
		return ret;
	}

	return ret;
}

static int alloc_mem_from_hugepage(struct mempool *mp)
{
	struct sys_hugepage_config *iter;
	unsigned long bits = sizeof(iter->page_size) * 8;
	size_t page_num, real_size;
	int flags = 0;
	void *p;
	int ret;

	ret = get_hugepage_info(mp);
	if (ret < 0)
		return ret;

	/* find proper hugepage: use small huge page if possible */
	TAILQ_FOREACH(iter, &mp->hp_list, node) {
		if (iter->page_size * iter->free_num >= mp->size)
			break;
	}
	if (!iter) {
		WD_ERR("WD_MMEPOOL: Failed to find proper hugepage\n");
		ret = -ENOMEM;
		goto err_put_info;
	}

	/* alloc hugepage and bind */
	page_num = mp->size / iter->page_size +
		   (mp->size % iter->page_size ? 1 : 0);
	real_size = page_num * iter->page_size;
	/*
	 * man mmap will tell, flags of mmap can be used to indicate hugepage
	 * size. In fact, after kernel 3.18, it has been supported. See more
	 * in kernel header file: linux/include/uapi/linux/mman.h. As related
	 * macro has not been put into glibc, we caculate them here, e.g.
	 * flags for 64KB is 16 << 26.
	 */
	flags = _find_next_bit(&iter->page_size, bits, 0, 0UL) <<
		HUGETLB_FLAG_ENCODE_SHIFT;
	p = mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_PRIVATE |
		 MAP_ANONYMOUS | MAP_HUGETLB | flags, -1, 0);
	if (p == MAP_FAILED) {
		WD_ERR("WD_MMEPOOL: Failed to allocate huge page\n");
		ret = -ENOMEM;
		goto err_put_info;
	}

	ret = mbind_memory(p, real_size, mp->node);
	if (ret < 0)
		goto err_unmap;

	mp->page_type = WD_HUGE_PAGE;
	mp->page_size = iter->page_size;
	mp->page_num = page_num;
	mp->addr = p;
	mp->real_size = real_size;

	return 0;

err_unmap:
	munmap(p, real_size);
err_put_info:
	put_hugepage_info(mp);
	return ret;
}

static void free_hugepage_mem(struct mempool *mp)
{
	munmap(mp->addr, mp->page_size * mp->page_num);
	put_hugepage_info(mp);
}

static int alloc_mempool_memory(struct mempool *mp)
{
	int ret;

	ret = alloc_mem_from_hugepage(mp);
	if (ret) {
		WD_ERR("WD_MMEPOOL: Failed to alloc memory from hugepage\n");
		return -ENOMEM;
	}

	return 0;
}

static void free_mempool_memory(struct mempool *mp)
{
	free_hugepage_mem(mp);
}

static int init_mempool(struct mempool *mp)
{
	/* size of mp should align to 4KB */
	int bits = mp->size / mp->blk_size;
	struct bitmap *bm;

	bm = create_bitmap(bits);
	if (!bm)
		return -ENOMEM;
	mp->bitmap = bm;
	mp->free_blk_num = bits;
	mp->blk_num = bits;

	return 0;
}

static void uninit_mempool(struct mempool *mp)
{
	destroy_bitmap(mp->bitmap);
	mp->bitmap = NULL;
}

handle_t wd_mempool_create(size_t size, int node)
{
	struct mempool *mp;
	int ret;

	if (!size || node < WD_MEMPOOL_NO_NUMA || node > numa_max_node())
		return (handle_t)(-WD_EINVAL);

	if (WD_MEMPOOL_SIZE_MASK & size)
		size += WD_MEMPOOL_BLOCK_SIZE - (WD_MEMPOOL_SIZE_MASK & size);

	mp = calloc(1, sizeof(*mp));
	if (!mp)
		return (handle_t)(-WD_ENOMEM);

	mp->node = node;
	mp->size = size;
	mp->blk_size = WD_MEMPOOL_BLOCK_SIZE;

	ret = alloc_mempool_memory(mp);
	if (ret < 0)
		goto free_pool;

	ret = init_mempool(mp);
	if (ret < 0)
		goto free_pool_memory;

	wd_atomic_add(&mp->ref, 1);
	return (handle_t)mp;

free_pool_memory:
	free_mempool_memory(mp);
free_pool:
	free(mp);
	return ret;
}

void wd_mempool_destroy(handle_t mempool)
{
	struct mempool *mp = (struct mempool *)mempool;

	if (!mp) {
		WD_ERR("WD_MMEPOOL: Mempool is NULL\n");
		return;
	}

	wd_atomic_sub(&mp->ref, 1);
	while(wd_atomic_load(&mp->ref));
	uninit_mempool(mp);
	free_mempool_memory(mp);
	free(mp);
}

void wd_mempool_stats(handle_t mempool, struct wd_mempool_stats *stats)
{
	struct mempool *mp = (struct mempool *)mempool;

	if (!mp) {
		WD_ERR("WD_MMEPOOL: Mempool is NULL\n");
		return;
	}

	wd_spinlock(&mp->lock);

	stats->page_type = mp->page_type;
	stats->page_size = mp->page_size;
	stats->page_num = mp->page_num;
	stats->blk_size = mp->blk_size;
	stats->blk_num = mp->blk_num;
	stats->free_blk_num = mp->free_blk_num;
	stats->blk_usage_rate = (stats->blk_num - mp->free_blk_num) * WD_HUNDRED /
				stats->blk_num;

	wd_unspinlock(&mp->lock);
}

void wd_blockpool_stats(handle_t blkpool, struct wd_blockpool_stats *stats)
{
	struct blkpool *bp = (struct blkpool*)blkpool;
	unsigned long size = 0;
	struct memzone *iter;

	if (!bp || !stats) {
		WD_ERR("WD_MMEPOOL: Blkpool or Stats is NULL\n");
		return;
	}

	wd_spinlock(&bp->lock);

	stats->block_size = bp->blk_size;
	stats->block_num = bp->depth;
	stats->free_block_num = bp->free_block_num;
	stats->block_usage_rate = (bp->depth - bp->free_block_num) * WD_HUNDRED /
				  bp->depth;

	TAILQ_FOREACH(iter, &bp->mz_list, node) {
		size += (iter->end - iter->begin + 1) * bp->mp->blk_size;
	}

	if (!size) {
		WD_ERR("WD_MMEPOOL: Blkpool size is zero\n");
		wd_unspinlock(&bp->lock);
		return;
	}

	stats->mem_waste_rate = (size - bp->blk_size * bp->depth) * WD_HUNDRED / size;

	wd_unspinlock(&bp->lock);
}
