#ifndef _LINUX_SWAP_H
#define _LINUX_SWAP_H

#include <linux/config.h>
#include <linux/spinlock.h>
#include <linux/linkage.h>
#include <linux/mmzone.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <asm/page.h>

#define SWAP_FLAG_PREFER	0x8000	/* set if swap priority specified */
#define SWAP_FLAG_PRIO_MASK	0x7fff
#define SWAP_FLAG_PRIO_SHIFT	0

static inline int current_is_kswapd(void)
{
	return current->flags & PF_KSWAPD;
}

/*
 * MAX_SWAPFILES defines the maximum number of swaptypes: things which can
 * be swapped to.  The swap type and the offset into that swap type are
 * encoded into pte's and into pgoff_t's in the swapcache.  Using five bits
 * for the type means that the maximum number of swapcache pages is 27 bits
 * on 32-bit-pgoff_t architectures.  And that assumes that the architecture packs
 * the type/offset into the pte as 5/27 as well.
 */
#define MAX_SWAPFILES_SHIFT	5
#define MAX_SWAPFILES		(1 << MAX_SWAPFILES_SHIFT)

/*
 * Magic header for a swap area. The first part of the union is
 * what the swap magic looks like for the old (limited to 128MB)
 * swap area format, the second part of the union adds - in the
 * old reserved area - some extra information. Note that the first
 * kilobyte is reserved for boot loader or disk label stuff...
 *
 * Having the magic at the end of the PAGE_SIZE makes detecting swap
 * areas somewhat tricky on machines that support multiple page sizes.
 * For 2.5 we'll probably want to move the magic to just beyond the
 * bootbits...
 */
/**
 * 每个交换区的第一个页槽用来永久存放有关交换区的信息，用本结构表示。
 */
union swap_header {
	struct {
		char reserved[PAGE_SIZE - 10];
		/**
		 * 交换区标识，一般是"SWAPSPACE2"
		 */
		char magic[10];			/* SWAP-SPACE or SWAPSPACE2 */
	} magic;
	struct {
		/**
		 * 不用于交换算法。存放分区数据、磁盘标签等。
		 */
		char	     bootbits[1024];	/* Space for disklabel etc. */
		/**
		 * 交换区的版本。
		 */
		unsigned int version;
		/**
		 * 可有效使用的最后一个页槽。
		 */
		unsigned int last_page;
		/**
		 * 有缺陷的页槽个数。
		 */
		unsigned int nr_badpages;
		/**
		 * 填充字段。
		 */
		unsigned int padding[125];
		/**
		 * 共637个字节，用来指定有缺陷页槽的位置。
		 */
		unsigned int badpages[1];
	} info;
};

 /* A swap entry has to fit into a "unsigned long", as
  * the entry is hidden in the "index" field of the
  * swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

/*
 * current->reclaim_state points to one of these when a task is running
 * memory reclaim
 */
struct reclaim_state {
	unsigned long reclaimed_slab;
};

#ifdef __KERNEL__

struct address_space;
struct sysinfo;
struct writeback_control;
struct zone;

/*
 * A swap extent maps a range of a swapfile's PAGE_SIZE pages onto a range of
 * disk blocks.  A list of swap extents maps the entire swapfile.  (Where the
 * term `swapfile' refers to either a blockdevice or an IS_REG file.  Apart
 * from setup, they're handled identically.
 *
 * We always assume that blocks are of size PAGE_SIZE.
 */
/**
 * 交换子区。一个交换区由一个或者多个子区组成。每个子区是由一组物理相邻的页槽组成。
 */
struct swap_extent {
	/**
	 * 子区链表指针。
	 */
	struct list_head list;
	/**
	 * 子区的首页索引。
	 */
	pgoff_t start_page;
	/**
	 * 子区页数。
	 */
	pgoff_t nr_pages;
	/**
	 * 子区的起始磁盘区号。
	 */
	sector_t start_block;
};

/*
 * Max bad pages in the new format..
 */
#define __swapoffset(x) ((unsigned long)&((union swap_header *)0)->x)
#define MAX_SWAP_BADPAGES \
	((__swapoffset(magic.magic) - __swapoffset(info.badpages)) / sizeof(int))

/**
 * 交换区标志
 */
enum {
	/**
	 * 交换区是活动的，则该值为1.
	 */
	SWP_USED	= (1 << 0),	/* is slot in swap_info[] used? */
	/**
	 * 交换区是可写的，则该值为1.
	 */
	SWP_WRITEOK	= (1 << 1),	/* ok to write to this swap?	*/
	/**
	 * 这是前两个字段的组合。
	 */
	SWP_ACTIVE	= (SWP_USED | SWP_WRITEOK),
};

#define SWAP_CLUSTER_MAX 32

#define SWAP_MAP_MAX	0x7fff
#define SWAP_MAP_BAD	0x8000

/*
 * The in-memory structure used to track swap areas.
 * extent_list.prev points at the lowest-index extent.  That list is
 * sorted.
 */
/**
 * 交换区描述符
 */
struct swap_info_struct {
	/**
	 * 交换区标志
	 */
	unsigned int flags;
	/** 
	 * 保护交换区的自旋锁。
	 */
	spinlock_t sdev_lock;
	/**
	 * 指针，指向存放交换区的普通文件或设备文件的文件对象。
	 */
	struct file *swap_file;
	/**
	 * 存放交换区的块设备描述符。
	 */
	struct block_device *bdev;
	/**
	 * 指向交换区的子区链表的头部。
	 */
	struct list_head extent_list;
	/**
	 * 组成交换区的子区数量。
	 */
	int nr_extents;
	/**
	 * 指向最近使用的子区描述符的指针。
	 */
	struct swap_extent *curr_swap_extent;
	/**
	 * 存放交换区的磁盘分区自然块大小。
	 */
	unsigned old_block_size;
	/**
	 * 指向计数器数组的指针，交换区的每个页槽对应一个数组元素。
	 */
	unsigned short * swap_map;
	/**
	 * 在搜索一个空闲页槽时要扫描的第一个页槽。
	 */
	unsigned int lowest_bit;
	/**
	 * 在搜索一个空闲页槽时要扫描的最后一个页槽。
	 */
	unsigned int highest_bit;
	/**
	 * 在搜索一个空闲页槽时要扫描的下一个页槽。
	 */
	unsigned int cluster_next;
	/**
	 * 在从头重新开始扫描之前空闲页槽的分配次数?
	 */
	unsigned int cluster_nr;
	/**
	 * 交换区优先级。
	 */
	int prio;			/* swap priority */
	/**
	 * 可用页槽的个数。
	 */
	int pages;
	/**
	 * 交换区的大小，以页为单位。
	 */
	unsigned long max;
	/**
	 * 交换区内已用页槽数。
	 */
	unsigned long inuse_pages;
	/**
	 * 指向下一个交换区描述符的指针。
	 */
	int next;			/* next entry on swap list */
};

struct swap_list_t {
	/**
	 * 第一个链表元素在swap_info数组中的下标。
	 */
	int head;	/* head of priority-ordered swapfile list */
	/**
	 * 为换出页所选中的下一个交换区的描述符在swap_info数组中的下标。
	 * 该字段用于在具有空闲页槽的最大优先级的交换区之间实现轮询算法。
	 */
	int next;	/* swapfile to be used next */
};

/* Swap 50% full? Release swapcache more aggressively.. */
#define vm_swap_full() (nr_swap_pages*2 < total_swap_pages)

/* linux/mm/oom_kill.c */
extern void out_of_memory(int gfp_mask);

/* linux/mm/memory.c */
extern void swapin_readahead(swp_entry_t, unsigned long, struct vm_area_struct *);

/* linux/mm/page_alloc.c */
extern unsigned long totalram_pages;
extern unsigned long totalhigh_pages;
extern long nr_swap_pages;
extern unsigned int nr_free_pages(void);
extern unsigned int nr_free_pages_pgdat(pg_data_t *pgdat);
extern unsigned int nr_free_buffer_pages(void);
extern unsigned int nr_free_pagecache_pages(void);

/* linux/mm/swap.c */
extern void FASTCALL(lru_cache_add(struct page *));
extern void FASTCALL(lru_cache_add_active(struct page *));
extern void FASTCALL(activate_page(struct page *));
extern void FASTCALL(mark_page_accessed(struct page *));
extern void lru_add_drain(void);
extern int rotate_reclaimable_page(struct page *page);
extern void swap_setup(void);

/* linux/mm/vmscan.c */
extern int try_to_free_pages(struct zone **, unsigned int, unsigned int);
extern int shrink_all_memory(int);
extern int vm_swappiness;

#ifdef CONFIG_MMU
/* linux/mm/shmem.c */
extern int shmem_unuse(swp_entry_t entry, struct page *page);
#endif /* CONFIG_MMU */

extern void swap_unplug_io_fn(struct backing_dev_info *, struct page *);

#ifdef CONFIG_SWAP
/* linux/mm/page_io.c */
extern int swap_readpage(struct file *, struct page *);
extern int swap_writepage(struct page *page, struct writeback_control *wbc);
extern int rw_swap_page_sync(int, swp_entry_t, struct page *);

/* linux/mm/swap_state.c */
extern struct address_space swapper_space;
#define total_swapcache_pages  swapper_space.nrpages
extern void show_swap_cache_info(void);
extern int add_to_swap(struct page *);
extern void __delete_from_swap_cache(struct page *);
extern void delete_from_swap_cache(struct page *);
extern int move_to_swap_cache(struct page *, swp_entry_t);
extern int move_from_swap_cache(struct page *, unsigned long,
		struct address_space *);
extern void free_page_and_swap_cache(struct page *);
extern void free_pages_and_swap_cache(struct page **, int);
extern struct page * lookup_swap_cache(swp_entry_t);
extern struct page * read_swap_cache_async(swp_entry_t, struct vm_area_struct *vma,
					   unsigned long addr);
/* linux/mm/swapfile.c */
extern long total_swap_pages;
extern unsigned int nr_swapfiles;
extern struct swap_info_struct swap_info[];
extern void si_swapinfo(struct sysinfo *);
extern swp_entry_t get_swap_page(void);
extern int swap_duplicate(swp_entry_t);
extern int valid_swaphandles(swp_entry_t, unsigned long *);
extern void swap_free(swp_entry_t);
extern void free_swap_and_cache(swp_entry_t);
extern sector_t map_swap_page(struct swap_info_struct *, pgoff_t);
extern struct swap_info_struct *get_swap_info_struct(unsigned);
extern int can_share_swap_page(struct page *);
extern int remove_exclusive_swap_page(struct page *);
struct backing_dev_info;

extern struct swap_list_t swap_list;
extern spinlock_t swaplock;

#define swap_list_lock()	spin_lock(&swaplock)
#define swap_list_unlock()	spin_unlock(&swaplock)
#define swap_device_lock(p)	spin_lock(&p->sdev_lock)
#define swap_device_unlock(p)	spin_unlock(&p->sdev_lock)

/* linux/mm/thrash.c */
/**
 * 交换标记
 */
extern struct mm_struct * swap_token_mm;
extern unsigned long swap_token_default_timeout;
extern void grab_swap_token(void);
extern void __put_swap_token(struct mm_struct *);

static inline int has_swap_token(struct mm_struct *mm)
{
	return (mm == swap_token_mm);
}

static inline void put_swap_token(struct mm_struct *mm)
{
	if (has_swap_token(mm))
		__put_swap_token(mm);
}

#else /* CONFIG_SWAP */

#define total_swap_pages			0
#define total_swapcache_pages			0UL

#define si_swapinfo(val) \
	do { (val)->freeswap = (val)->totalswap = 0; } while (0)
#define free_page_and_swap_cache(page) \
	page_cache_release(page)
#define free_pages_and_swap_cache(pages, nr) \
	release_pages((pages), (nr), 0);

#define show_swap_cache_info()			/*NOTHING*/
#define free_swap_and_cache(swp)		/*NOTHING*/
#define swap_duplicate(swp)			/*NOTHING*/
#define swap_free(swp)				/*NOTHING*/
#define read_swap_cache_async(swp,vma,addr)	NULL
#define lookup_swap_cache(swp)			NULL
#define valid_swaphandles(swp, off)		0
#define can_share_swap_page(p)			0
#define move_to_swap_cache(p, swp)		1
#define move_from_swap_cache(p, i, m)		1
#define __delete_from_swap_cache(p)		/*NOTHING*/
#define delete_from_swap_cache(p)		/*NOTHING*/
#define swap_token_default_timeout		0

static inline int remove_exclusive_swap_page(struct page *p)
{
	return 0;
}

static inline swp_entry_t get_swap_page(void)
{
	swp_entry_t entry;
	entry.val = 0;
	return entry;
}

/* linux/mm/thrash.c */
#define put_swap_token(x) do { } while(0)
#define grab_swap_token()  do { } while(0)
#define has_swap_token(x) 0

#endif /* CONFIG_SWAP */
#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
