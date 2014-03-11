/*
 *  linux/mm/swapfile.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/shm.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/acct.h>
#include <linux/backing-dev.h>
#include <linux/syscalls.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/swapops.h>

/**
 * 防止在多处理器系统中对交换区链表的并发访问。
 */
DEFINE_SPINLOCK(swaplock);
/**
 * 交换区数组中所使用交换区描述符的最后一个元素的索引。并不是活动交换区的个数。
 */
unsigned int nr_swapfiles;
/**
 * 交换区中所有页槽(含有缺陷的页槽)
 */
long total_swap_pages;
static int swap_overflow;

EXPORT_SYMBOL(total_swap_pages);

static const char Bad_file[] = "Bad swap file entry ";
static const char Unused_file[] = "Unused swap file entry ";
static const char Bad_offset[] = "Bad swap offset entry ";
static const char Unused_offset[] = "Unused swap offset entry ";

struct swap_list_t swap_list = {-1, -1};

/**
 * 交换区描述符数组。
 */
struct swap_info_struct swap_info[MAX_SWAPFILES];

static DECLARE_MUTEX(swapon_sem);

/*
 * We need this because the bdev->unplug_fn can sleep and we cannot
 * hold swap_list_lock while calling the unplug_fn. And swap_list_lock
 * cannot be turned into a semaphore.
 */
static DECLARE_RWSEM(swap_unplug_sem);

#define SWAPFILE_CLUSTER 256

void swap_unplug_io_fn(struct backing_dev_info *unused_bdi, struct page *page)
{
	swp_entry_t entry;

	down_read(&swap_unplug_sem);
	entry.val = page->private;
	if (PageSwapCache(page)) {
		struct block_device *bdev = swap_info[swp_type(entry)].bdev;
		struct backing_dev_info *bdi;

		/*
		 * If the page is removed from swapcache from under us (with a
		 * racy try_to_unuse/swapoff) we need an additional reference
		 * count to avoid reading garbage from page->private above. If
		 * the WARN_ON triggers during a swapoff it maybe the race
		 * condition and it's harmless. However if it triggers without
		 * swapoff it signals a problem.
		 */
		WARN_ON(page_count(page) <= 1);

		bdi = bdev->bd_inode->i_mapping->backing_dev_info;
		bdi->unplug_io_fn(bdi, page);
	}
	up_read(&swap_unplug_sem);
}

/**
 * 用来在给定的交换区中查找一个空闲页槽。返回一个空闲页槽索引。
 *		si:		在该交换区描述符中进行查找。
 */
static inline int scan_swap_map(struct swap_info_struct *si)
{
	unsigned long offset;
	/* 
	 * We try to cluster swap pages by allocating them
	 * sequentially in swap.  Once we've allocated
	 * SWAPFILE_CLUSTER pages this way, however, we resort to
	 * first-free allocation, starting a new cluster.  This
	 * prevents us from scattering swap pages all over the entire
	 * swap partition, so that we reduce overall disk seek times
	 * between swap pages.  -- sct */
	/**
	 * 首先试图使用当前簇。如果交换区描述符的cluster_nr是正数，就从cluster_next处的元素开始对计数器的swap_map数组进行扫描。查找一个空项。
	 */
	if (si->cluster_nr) {
		while (si->cluster_next <= si->highest_bit) {
			offset = si->cluster_next++;
			if (si->swap_map[offset])
				continue;
			/**
			 * 找到一个空项。
			 */
			si->cluster_nr--;
			goto got_page;
		}
	}
	/**
	 * 执行到这里，说明cluster_nr字段为空。或者从cluster_next没有搜索到空项。
	 * 开始第二阶段的混合查找。
	 */
	si->cluster_nr = SWAPFILE_CLUSTER;

	/* try to find an empty (even not aligned) cluster. */
	/**
	 * 从lowest_bit开始扫描，以便找到有SWAPFILE_CLUSTER个空闲页槽的一个组。
	 */
	offset = si->lowest_bit;
 check_next_cluster:
	if (offset+SWAPFILE_CLUSTER-1 <= si->highest_bit)
	{
		unsigned long nr;
		for (nr = offset; nr < offset+SWAPFILE_CLUSTER; nr++)
			if (si->swap_map[nr])
			{
				offset = nr+1;
				goto check_next_cluster;
			}
		/* We found a completly empty cluster, so start
		 * using it.
		 */
		/**
		 * 找到SWAPFILE_CLUSTER个连续空闲页槽。
		 */
		goto got_page;
	}
	/* No luck, so now go finegrined as usual. -Andrea */
	/**
	 * 没有找到联系的空闲页槽。从头到尾找一个空页槽。
	 */
	for (offset = si->lowest_bit; offset <= si->highest_bit ; offset++) {
		if (si->swap_map[offset])
			continue;
		/**
		 * 找到空闲页。
		 */
		si->lowest_bit = offset+1;
	got_page:
		if (offset == si->lowest_bit)
			si->lowest_bit++;
		if (offset == si->highest_bit)
			si->highest_bit--;
		/**
		 * 满了。
		 */
		if (si->lowest_bit > si->highest_bit) {
			si->lowest_bit = si->max;
			si->highest_bit = 0;
		}
		/**
		 * 置占用标志。
		 */
		si->swap_map[offset] = 1;
		si->inuse_pages++;
		nr_swap_pages--;
		si->cluster_next = offset+1;
		return offset;
	}
	/**
	 * 没有找到空闲槽，将lowest_bit设置为最大值，并将highest_bit设置成0，并返回0.
	 */
	si->lowest_bit = si->max;
	si->highest_bit = 0;
	return 0;
}

/**
 * 搜索所有活动交换区来查找一个空闲页槽。
 * 返回一个新近分配页槽的换出页标识符。如果所有交换区都满，就返回0.
 * 该函数会考虑不同交换的优先级。
 * 进行两遍扫描，以便在容易发现页槽时节约运行时间。
 * 第一遍是部分的，只适用于只有相同优先级的交换区。该函数以轮询方式在这种交换区中查找一个空闲页槽。
 * 如果没有找到空闲页槽，就从交换区链表的起始位置开始进行第二遍扫描。在第二遍扫描中，要对所有的交换区都进行检查。
 */
swp_entry_t get_swap_page(void)
{
	struct swap_info_struct * p;
	unsigned long offset;
	swp_entry_t entry;
	int type, wrapped = 0;

	entry.val = 0;	/* Out of memory */
	swap_list_lock();
	type = swap_list.next;
	/**
	 * 没有活动交换区，退出。
	 */
	if (type < 0)
		goto out;
	/**
	 * 没有空闲页槽，退出。
	 */
	if (nr_swap_pages <= 0)
		goto out;

	while (1) {
		/**
		 * 首先从swap_list.next这个交换区开始查找。
		 */
		p = &swap_info[type];
		/**
		 * 如果该交换区是活动的，就在其中查找空闲页槽。
		 */
		if ((p->flags & SWP_ACTIVE) == SWP_ACTIVE) {
			swap_device_lock(p);
			/**
			 * 在交换区中找空闲页槽。
			 */
			offset = scan_swap_map(p);
			swap_device_unlock(p);
			/**
			 * 找到空闲页槽。
			 */
			if (offset) {
				entry = swp_entry(type,offset);
				/**
				 * 找下一个交换区。
				 */
				type = swap_info[type].next;
				/**
				 * 没有下一个交换区，或者下一个交换区的优先级与当前交换区优先级不同，就将swap_list.next设置成swap_list.head;
				 * 这样，下一次就将从第一个交换区(优先级最高)开始查找。
				 */
				if (type < 0 ||
					p->prio != swap_info[type].prio) {
						swap_list.next = swap_list.head;
				} else {
					/**
					 * 否则，下一次不再从本交换区开始查找，而是从相同优先级的下一个交换区中查找。
					 */
					swap_list.next = type;
				}
				goto out;
			}
		}
		/**
		 * 当前交换区不是活动的，或者没有可用空闲页槽了。
		 */
		type = p->next;
		if (!wrapped) {
			/**
			 * 没有下一个交换区或者其优先级与当前交换区优先级不相同。则从头开始查找。
			 */
			if (type < 0 || p->prio != swap_info[type].prio) {
				type = swap_list.head;
				wrapped = 1;
			}
		} else
			if (type < 0)/* 都满了 */
				goto out;	/* out of swap space */
	}
out:
	swap_list_unlock();
	return entry;
}

static struct swap_info_struct * swap_info_get(swp_entry_t entry)
{
	struct swap_info_struct * p;
	unsigned long offset, type;

	if (!entry.val)
		goto out;
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_nofile;
	p = & swap_info[type];
	if (!(p->flags & SWP_USED))
		goto bad_device;
	offset = swp_offset(entry);
	if (offset >= p->max)
		goto bad_offset;
	if (!p->swap_map[offset])
		goto bad_free;
	swap_list_lock();
	if (p->prio > swap_info[swap_list.next].prio)
		swap_list.next = type;
	swap_device_lock(p);
	return p;

bad_free:
	printk(KERN_ERR "swap_free: %s%08lx\n", Unused_offset, entry.val);
	goto out;
bad_offset:
	printk(KERN_ERR "swap_free: %s%08lx\n", Bad_offset, entry.val);
	goto out;
bad_device:
	printk(KERN_ERR "swap_free: %s%08lx\n", Unused_file, entry.val);
	goto out;
bad_nofile:
	printk(KERN_ERR "swap_free: %s%08lx\n", Bad_file, entry.val);
out:
	return NULL;
}	

static void swap_info_put(struct swap_info_struct * p)
{
	swap_device_unlock(p);
	swap_list_unlock();
}

static int swap_entry_free(struct swap_info_struct *p, unsigned long offset)
{
	int count = p->swap_map[offset];

	if (count < SWAP_MAP_MAX) {
		count--;
		p->swap_map[offset] = count;
		if (!count) {
			if (offset < p->lowest_bit)
				p->lowest_bit = offset;
			if (offset > p->highest_bit)
				p->highest_bit = offset;
			nr_swap_pages++;
			p->inuse_pages--;
		}
	}
	return count;
}

/*
 * Caller has made sure that the swapdevice corresponding to entry
 * is still around or has not been recycled.
 */
/**
 * 当换入页时，释放空闲页槽。
 * 		entry:		要换入的页标识符。
 */
void swap_free(swp_entry_t entry)
{
	struct swap_info_struct * p;

	/**
	 * 根据页标识符获得交换区索引和页槽索引。
	 * 并获得交换区描述符的地址。
	 */
	p = swap_info_get(entry);
	/**
	 * 如果交换区是不活动的，就退出。
	 */
	if (p) {
		/**
		 * 如果页槽计数器小于SWAP_MAP_MAX，就减少这个计数器的值。
		 * 如果计数器变成0，则页槽可用，就增加nr_swap_pages的值并减少inuse_pages字段的值。
		 * 如果有必要，同时修改交换区描述符的lowest_bit和highest_bit字段。
		 */
		swap_entry_free(p, swp_offset(entry));
		swap_info_put(p);
	}
}

/*
 * Check if we're the only user of a swap page,
 * when the page is locked.
 */
static int exclusive_swap_page(struct page *page)
{
	int retval = 0;
	struct swap_info_struct * p;
	swp_entry_t entry;

	entry.val = page->private;
	p = swap_info_get(entry);
	if (p) {
		/* Is the only swap cache user the cache itself? */
		if (p->swap_map[swp_offset(entry)] == 1) {
			/* Recheck the page count with the swapcache lock held.. */
			spin_lock_irq(&swapper_space.tree_lock);
			if (page_count(page) == 2)
				retval = 1;
			spin_unlock_irq(&swapper_space.tree_lock);
		}
		swap_info_put(p);
	}
	return retval;
}

/*
 * We can use this swap cache entry directly
 * if there are no other references to it.
 *
 * Here "exclusive_swap_page()" does the real
 * work, but we opportunistically check whether
 * we need to get all the locks first..
 */
int can_share_swap_page(struct page *page)
{
	int retval = 0;

	if (!PageLocked(page))
		BUG();
	switch (page_count(page)) {
	case 3:
		if (!PagePrivate(page))
			break;
		/* Fallthrough */
	case 2:
		if (!PageSwapCache(page))
			break;
		retval = exclusive_swap_page(page);
		break;
	case 1:
		if (PageReserved(page))
			break;
		retval = 1;
	}
	return retval;
}

/*
 * Work out if there are any other processes sharing this
 * swap cache page. Free it if you can. Return success.
 */
int remove_exclusive_swap_page(struct page *page)
{
	int retval;
	struct swap_info_struct * p;
	swp_entry_t entry;

	BUG_ON(PagePrivate(page));
	BUG_ON(!PageLocked(page));

	if (!PageSwapCache(page))
		return 0;
	if (PageWriteback(page))
		return 0;
	if (page_count(page) != 2) /* 2: us + cache */
		return 0;

	entry.val = page->private;
	p = swap_info_get(entry);
	if (!p)
		return 0;

	/* Is the only swap cache user the cache itself? */
	retval = 0;
	if (p->swap_map[swp_offset(entry)] == 1) {
		/* Recheck the page count with the swapcache lock held.. */
		spin_lock_irq(&swapper_space.tree_lock);
		if ((page_count(page) == 2) && !PageWriteback(page)) {
			__delete_from_swap_cache(page);
			SetPageDirty(page);
			retval = 1;
		}
		spin_unlock_irq(&swapper_space.tree_lock);
	}
	swap_info_put(p);

	if (retval) {
		swap_free(entry);
		page_cache_release(page);
	}

	return retval;
}

/*
 * Free the swap entry like above, but also try to
 * free the page cache entry if it is the last user.
 */
/**
 * 释放一个交换表项，并检查该表项引用的页是否在交换高速缓存。
 * 如果没有用户态进程(除了当前进程)引用该页，或者超过50%的交换表项在用，则从交换高速缓存中释放该页。
 */
void free_swap_and_cache(swp_entry_t entry)
{
	struct swap_info_struct * p;
	struct page *page = NULL;

	p = swap_info_get(entry);
	if (p) {
		if (swap_entry_free(p, swp_offset(entry)) == 1) {
			spin_lock_irq(&swapper_space.tree_lock);
			page = radix_tree_lookup(&swapper_space.page_tree,
				entry.val);
			if (page && TestSetPageLocked(page))
				page = NULL;
			spin_unlock_irq(&swapper_space.tree_lock);
		}
		swap_info_put(p);
	}
	if (page) {
		int one_user;

		BUG_ON(PagePrivate(page));
		page_cache_get(page);
		one_user = (page_count(page) == 2);
		/* Only cache user (+us), or swap space full? Free it! */
		if (!PageWriteback(page) && (one_user || vm_swap_full())) {
			delete_from_swap_cache(page);
			SetPageDirty(page);
		}
		unlock_page(page);
		page_cache_release(page);
	}
}

/*
 * The swap entry has been read in advance, and we return 1 to indicate
 * that the page has been used or is no longer needed.
 *
 * Always set the resulting pte to be nowrite (the same as COW pages
 * after one process has exited).  We don't know just how many PTEs will
 * share this swap entry, so be cautious and let do_wp_page work out
 * what to do if a write is requested later.
 */
/* vma->vm_mm->page_table_lock is held */
static void
unuse_pte(struct vm_area_struct *vma, unsigned long address, pte_t *dir,
	swp_entry_t entry, struct page *page)
{
	vma->vm_mm->rss++;
	get_page(page);
	set_pte(dir, pte_mkold(mk_pte(page, vma->vm_page_prot)));
	page_add_anon_rmap(page, vma, address);
	swap_free(entry);
	acct_update_integrals();
	update_mem_hiwater();
}

/* vma->vm_mm->page_table_lock is held */
static unsigned long unuse_pmd(struct vm_area_struct *vma, pmd_t *dir,
	unsigned long address, unsigned long end,
	swp_entry_t entry, struct page *page)
{
	pte_t *pte;
	pte_t swp_pte = swp_entry_to_pte(entry);

	if (pmd_none(*dir))
		return 0;
	if (pmd_bad(*dir)) {
		pmd_ERROR(*dir);
		pmd_clear(dir);
		return 0;
	}
	pte = pte_offset_map(dir, address);
	do {
		/*
		 * swapoff spends a _lot_ of time in this loop!
		 * Test inline before going to call unuse_pte.
		 */
		if (unlikely(pte_same(*pte, swp_pte))) {
			unuse_pte(vma, address, pte, entry, page);
			pte_unmap(pte);

			/*
			 * Move the page to the active list so it is not
			 * immediately swapped out again after swapon.
			 */
			activate_page(page);

			/* add 1 since address may be 0 */
			return 1 + address;
		}
		address += PAGE_SIZE;
		pte++;
	} while (address < end);
	pte_unmap(pte - 1);
	return 0;
}

/* vma->vm_mm->page_table_lock is held */
static unsigned long unuse_pud(struct vm_area_struct *vma, pud_t *pud,
        unsigned long address, unsigned long end,
	swp_entry_t entry, struct page *page)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long foundaddr;

	if (pud_none(*pud))
		return 0;
	if (pud_bad(*pud)) {
		pud_ERROR(*pud);
		pud_clear(pud);
		return 0;
	}
	pmd = pmd_offset(pud, address);
	do {
		next = (address + PMD_SIZE) & PMD_MASK;
		if (next > end || !next)
			next = end;
		foundaddr = unuse_pmd(vma, pmd, address, next, entry, page);
		if (foundaddr)
			return foundaddr;
		address = next;
		pmd++;
	} while (address < end);
	return 0;
}

/* vma->vm_mm->page_table_lock is held */
static unsigned long unuse_pgd(struct vm_area_struct *vma, pgd_t *pgd,
	unsigned long address, unsigned long end,
	swp_entry_t entry, struct page *page)
{
	pud_t *pud;
	unsigned long next;
	unsigned long foundaddr;

	if (pgd_none(*pgd))
		return 0;
	if (pgd_bad(*pgd)) {
		pgd_ERROR(*pgd);
		pgd_clear(pgd);
		return 0;
	}
	pud = pud_offset(pgd, address);
	do {
		next = (address + PUD_SIZE) & PUD_MASK;
		if (next > end || !next)
			next = end;
		foundaddr = unuse_pud(vma, pud, address, next, entry, page);
		if (foundaddr)
			return foundaddr;
		address = next;
		pud++;
	} while (address < end);
	return 0;
}

/* vma->vm_mm->page_table_lock is held */
static unsigned long unuse_vma(struct vm_area_struct *vma,
	swp_entry_t entry, struct page *page)
{
	pgd_t *pgd;
	unsigned long address, next, end;
	unsigned long foundaddr;

	if (page->mapping) {
		address = page_address_in_vma(page, vma);
		if (address == -EFAULT)
			return 0;
		else
			end = address + PAGE_SIZE;
	} else {
		address = vma->vm_start;
		end = vma->vm_end;
	}
	pgd = pgd_offset(vma->vm_mm, address);
	do {
		next = (address + PGDIR_SIZE) & PGDIR_MASK;
		if (next > end || !next)
			next = end;
		foundaddr = unuse_pgd(vma, pgd, address, next, entry, page);
		if (foundaddr)
			return foundaddr;
		address = next;
		pgd++;
	} while (address < end);
	return 0;
}

static int unuse_process(struct mm_struct * mm,
			swp_entry_t entry, struct page* page)
{
	struct vm_area_struct* vma;
	unsigned long foundaddr = 0;

	/*
	 * Go through process' page directory.
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		/*
		 * Our reference to the page stops try_to_unmap_one from
		 * unmapping its ptes, so swapoff can make progress.
		 */
		unlock_page(page);
		down_read(&mm->mmap_sem);
		lock_page(page);
	}
	spin_lock(&mm->page_table_lock);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->anon_vma) {
			foundaddr = unuse_vma(vma, entry, page);
			if (foundaddr)
				break;
		}
	}
	spin_unlock(&mm->page_table_lock);
	up_read(&mm->mmap_sem);
	/*
	 * Currently unuse_process cannot fail, but leave error handling
	 * at call sites for now, since we change it from time to time.
	 */
	return 0;
}

/*
 * Scan swap_map from current position to next entry still in use.
 * Recycle to start on reaching the end, returning 0 when empty.
 */
static int find_next_to_unuse(struct swap_info_struct *si, int prev)
{
	int max = si->max;
	int i = prev;
	int count;

	/*
	 * No need for swap_device_lock(si) here: we're just looking
	 * for whether an entry is in use, not modifying it; false
	 * hits are okay, and sys_swapoff() has already prevented new
	 * allocations from this area (while holding swap_list_lock()).
	 */
	for (;;) {
		if (++i >= max) {
			if (!prev) {
				i = 0;
				break;
			}
			/*
			 * No entries in use at top of swap_map,
			 * loop back to start and recheck there.
			 */
			max = prev + 1;
			prev = 0;
			i = 1;
		}
		count = si->swap_map[i];
		if (count && count != SWAP_MAP_BAD)
			break;
	}
	return i;
}

/*
 * We completely avoid races by reading each swap page in advance,
 * and then search for the process using it.  All the necessary
 * page table adjustments can then be made atomically.
 */
/**
 * 换入交换区中的页，更新已经换出页的进程的所有页表。
 * 它访问所有内核线程和进程的地址空间。
 *		type:		被清空的交换区索引。
 */
static int try_to_unuse(unsigned int type)
{
	struct swap_info_struct * si = &swap_info[type];
	struct mm_struct *start_mm;
	unsigned short *swap_map;
	unsigned short swcount;
	struct page *page;
	swp_entry_t entry;
	int i = 0;
	int retval = 0;
	int reset_overflow = 0;
	int shmem;

	/*
	 * When searching mms for an entry, a good strategy is to
	 * start at the first mm we freed the previous entry from
	 * (though actually we don't notice whether we or coincidence
	 * freed the entry).  Initialize this start_mm with a hold.
	 *
	 * A simpler strategy would be to start at the last mm we
	 * freed the previous entry from; but that would take less
	 * advantage of mmlist ordering, which clusters forked mms
	 * together, child after parent.  If we race with dup_mmap(), we
	 * prefer to resolve parent before child, lest we miss entries
	 * duplicated after we scanned child: using last mm would invert
	 * that.  Though it's only a serious concern when an overflowed
	 * swap count is reset from SWAP_MAP_MAX, preventing a rescan.
	 */
	start_mm = &init_mm;
	atomic_inc(&init_mm.mm_users);

	/*
	 * Keep on scanning until all entries have gone.  Usually,
	 * one pass through swap_map is enough, but not necessarily:
	 * there are races when an instance of an entry might be missed.
	 */
	/**
	 * 扫描交换区的所有换出页。
	 */
	while ((i = find_next_to_unuse(si, i)) != 0) {
		/**
		 * 本函数执行时间比较长，信号可能得不到及时处理，在此检查一下是否有信号需要处理。
		 */
		if (signal_pending(current)) {
			retval = -EINTR;
			break;
		}

		/* 
		 * Get a page for the entry, using the existing swap
		 * cache page if there is one.  Otherwise, get a clean
		 * page and read the swap into it. 
		 */
		swap_map = &si->swap_map[i];
		entry = swp_entry(type, i);
		/**
		 * read_swap_cache_async函数换入页，可能还会分配一个新页。用存放在页槽中的数据填充新页框。
		 * 并把这个页存放在交换高速缓存。
		 */
		page = read_swap_cache_async(entry, NULL, 0);
		if (!page) {
			/*
			 * Either swap_duplicate() failed because entry
			 * has been freed independently, and will not be
			 * reused since sys_swapoff() already disabled
			 * allocation from here, or alloc_page() failed.
			 */
			if (!*swap_map)
				continue;
			retval = -ENOMEM;
			break;
		}

		/*
		 * Don't hold on to start_mm if it looks like exiting.
		 */
		if (atomic_read(&start_mm->mm_users) == 1) {
			mmput(start_mm);
			start_mm = &init_mm;
			atomic_inc(&init_mm.mm_users);
		}

		/*
		 * Wait for and lock page.  When do_swap_page races with
		 * try_to_unuse, do_swap_page can handle the fault much
		 * faster than try_to_unuse can locate the entry.  This
		 * apparently redundant "wait_on_page_locked" lets try_to_unuse
		 * defer to do_swap_page in such a case - in some tests,
		 * do_swap_page and try_to_unuse repeatedly compete.
		 */
		/**
		 * 等待，直到用磁盘中的数据适当的更新了新页，然后锁住它。
		 */
		wait_on_page_locked(page);
		wait_on_page_writeback(page);
		lock_page(page);
		wait_on_page_writeback(page);

		/*
		 * Remove all references to entry.
		 * Whenever we reach init_mm, there's no address space
		 * to search, but use it as a reminder to search shmem.
		 */
		shmem = 0;
		swcount = *swap_map;
		if (swcount > 1) {
			if (start_mm == &init_mm)
				shmem = shmem_unuse(entry, page);
			else
				retval = unuse_process(start_mm, entry, page);
		}
		/**
		 * 由于在上一步中，进程可能被挂起，为此，再次检查页槽引用计数器是否变为空。
		 * 如果为空，就继续处理下一个页槽。否则处理该页槽。
		 */
		if (*swap_map > 1) {
			int set_start_mm = (*swap_map >= swcount);
			struct list_head *p = &start_mm->mmlist;
			struct mm_struct *new_start_mm = start_mm;
			struct mm_struct *prev_mm = start_mm;
			struct mm_struct *mm;

			atomic_inc(&new_start_mm->mm_users);
			atomic_inc(&prev_mm->mm_users);
			spin_lock(&mmlist_lock);
			/**
			 * 对每个内存描述符，调用unuse_process。
			 */
			while (*swap_map > 1 && !retval &&
					(p = p->next) != &start_mm->mmlist) {
				mm = list_entry(p, struct mm_struct, mmlist);
				if (atomic_inc_return(&mm->mm_users) == 1) {
					atomic_dec(&mm->mm_users);
					continue;
				}
				spin_unlock(&mmlist_lock);
				mmput(prev_mm);
				prev_mm = mm;

				cond_resched();

				swcount = *swap_map;
				if (swcount <= 1)
					;
				else if (mm == &init_mm) {
					set_start_mm = 1;
					/**
					 * 检查换出的页是否用于IPC共享内存资源，并适当的处理IPC。
					 */
					shmem = shmem_unuse(entry, page);
				} else
					/**
					 * unuse_process扫描进程所有页表项，并用这个新页框的物理地址替换页表中每个出现的换出页标识符。
					 */
					retval = unuse_process(mm, entry, page);
				if (set_start_mm && *swap_map < swcount) {
					mmput(new_start_mm);
					atomic_inc(&mm->mm_users);
					new_start_mm = mm;
					set_start_mm = 0;
				}
				spin_lock(&mmlist_lock);
			}
			spin_unlock(&mmlist_lock);
			mmput(prev_mm);
			mmput(start_mm);
			start_mm = new_start_mm;
		}
		if (retval) {
			unlock_page(page);
			page_cache_release(page);
			break;
		}

		/*
		 * How could swap count reach 0x7fff when the maximum
		 * pid is 0x7fff, and there's no way to repeat a swap
		 * page within an mm (except in shmem, where it's the
		 * shared object which takes the reference count)?
		 * We believe SWAP_MAP_MAX cannot occur in Linux 2.4.
		 *
		 * If that's wrong, then we should worry more about
		 * exit_mmap() and do_munmap() cases described above:
		 * we might be resetting SWAP_MAP_MAX too early here.
		 * We know "Undead"s can happen, they're okay, so don't
		 * report them; but do report if we reset SWAP_MAP_MAX.
		 */
		/**
		 * 如果页槽引用计数器为SWAP_MAP_MAX，强制置为1.这样随后就可以将它减为0了。
		 */
		if (*swap_map == SWAP_MAP_MAX) {
			swap_device_lock(si);
			*swap_map = 1;
			swap_device_unlock(si);
			reset_overflow = 1;
		}

		/*
		 * If a reference remains (rare), we would like to leave
		 * the page in the swap cache; but try_to_unmap could
		 * then re-duplicate the entry once we drop page lock,
		 * so we might loop indefinitely; also, that page could
		 * not be swapped out to other storage meanwhile.  So:
		 * delete from cache even if there's another reference,
		 * after ensuring that the data has been saved to disk -
		 * since if the reference remains (rarer), it will be
		 * read from disk into another page.  Splitting into two
		 * pages would be incorrect if swap supported "shared
		 * private" pages, but they are handled by tmpfs files.
		 *
		 * Note shmem_unuse already deleted a swappage from
		 * the swap cache, unless the move to filepage failed:
		 * in which case it left swappage in cache, lowered its
		 * swap count to pass quickly through the loops above,
		 * and now we must reincrement count to try again later.
		 */
		/**
		 * 检查页是否属于交换高速缓存。并且为脏。
		 */
		if ((*swap_map > 1) && PageDirty(page) && PageSwapCache(page)) {
			struct writeback_control wbc = {
				.sync_mode = WB_SYNC_NONE,
			};

			/**
			 * 将页的内容刷新到磁盘。
			 */
			swap_writepage(page, &wbc);
			lock_page(page);
			wait_on_page_writeback(page);
		}
		if (PageSwapCache(page)) {
			if (shmem)
				swap_duplicate(entry);
			else
				delete_from_swap_cache(page);/* 将页交换高速缓存从缓存中删除。 */
		}

		/*
		 * So we could skip searching mms once swap count went
		 * to 1, we did not mark any present ptes as dirty: must
		 * mark page dirty so shrink_list will preserve it.
		 */
		/**
		 * 设置页描述符的PG_dirty标志，打开页框的锁，递减它的引用计数器。
		 */
		SetPageDirty(page);
		unlock_page(page);
		page_cache_release(page);

		/*
		 * Make sure that we aren't completely killing
		 * interactive performance.
		 */
		/**
		 * 增加调度点。
		 */
		cond_resched();
	}

	mmput(start_mm);
	if (reset_overflow) {
		printk(KERN_WARNING "swapoff: cleared swap entry overflow\n");
		swap_overflow = 0;
	}
	return retval;
}

/*
 * After a successful try_to_unuse, if no swap is now in use, we know we
 * can empty the mmlist.  swap_list_lock must be held on entry and exit.
 * Note that mmlist_lock nests inside swap_list_lock, and an mm must be
 * added to the mmlist just after page_duplicate - before would be racy.
 */
static void drain_mmlist(void)
{
	struct list_head *p, *next;
	unsigned int i;

	for (i = 0; i < nr_swapfiles; i++)
		if (swap_info[i].inuse_pages)
			return;
	spin_lock(&mmlist_lock);
	list_for_each_safe(p, next, &init_mm.mmlist)
		list_del_init(p);
	spin_unlock(&mmlist_lock);
}

/*
 * Use this swapdev's extent info to locate the (PAGE_SIZE) block which
 * corresponds to page offset `offset'.
 */
sector_t map_swap_page(struct swap_info_struct *sis, pgoff_t offset)
{
	struct swap_extent *se = sis->curr_swap_extent;
	struct swap_extent *start_se = se;

	for ( ; ; ) {
		struct list_head *lh;

		if (se->start_page <= offset &&
				offset < (se->start_page + se->nr_pages)) {
			return se->start_block + (offset - se->start_page);
		}
		lh = se->list.prev;
		if (lh == &sis->extent_list)
			lh = lh->prev;
		se = list_entry(lh, struct swap_extent, list);
		sis->curr_swap_extent = se;
		BUG_ON(se == start_se);		/* It *must* be present */
	}
}

/*
 * Free all of a swapdev's extent information
 */
static void destroy_swap_extents(struct swap_info_struct *sis)
{
	while (!list_empty(&sis->extent_list)) {
		struct swap_extent *se;

		se = list_entry(sis->extent_list.next,
				struct swap_extent, list);
		list_del(&se->list);
		kfree(se);
	}
	sis->nr_extents = 0;
}

/*
 * Add a block range (and the corresponding page range) into this swapdev's
 * extent list.  The extent list is kept sorted in block order.
 *
 * This function rather assumes that it is called in ascending sector_t order.
 * It doesn't look for extent coalescing opportunities.
 */
static int
add_swap_extent(struct swap_info_struct *sis, unsigned long start_page,
		unsigned long nr_pages, sector_t start_block)
{
	struct swap_extent *se;
	struct swap_extent *new_se;
	struct list_head *lh;

	lh = sis->extent_list.next;	/* The highest-addressed block */
	while (lh != &sis->extent_list) {
		se = list_entry(lh, struct swap_extent, list);
		if (se->start_block + se->nr_pages == start_block &&
		    se->start_page  + se->nr_pages == start_page) {
			/* Merge it */
			se->nr_pages += nr_pages;
			return 0;
		}
		lh = lh->next;
	}

	/*
	 * No merge.  Insert a new extent, preserving ordering.
	 */
	new_se = kmalloc(sizeof(*se), GFP_KERNEL);
	if (new_se == NULL)
		return -ENOMEM;
	new_se->start_page = start_page;
	new_se->nr_pages = nr_pages;
	new_se->start_block = start_block;

	lh = sis->extent_list.prev;	/* The lowest block */
	while (lh != &sis->extent_list) {
		se = list_entry(lh, struct swap_extent, list);
		if (se->start_block > start_block)
			break;
		lh = lh->prev;
	}
	list_add_tail(&new_se->list, lh);
	sis->nr_extents++;
	return 0;
}

/*
 * A `swap extent' is a simple thing which maps a contiguous range of pages
 * onto a contiguous range of disk blocks.  An ordered list of swap extents
 * is built at swapon time and is then used at swap_writepage/swap_readpage
 * time for locating where on disk a page belongs.
 *
 * If the swapfile is an S_ISBLK block device, a single extent is installed.
 * This is done so that the main operating code can treat S_ISBLK and S_ISREG
 * swap files identically.
 *
 * Whether the swapdev is an S_ISREG file or an S_ISBLK blockdev, the swap
 * extent list operates in PAGE_SIZE disk blocks.  Both S_ISREG and S_ISBLK
 * swapfiles are handled *identically* after swapon time.
 *
 * For S_ISREG swapfiles, setup_swap_extents() will walk all the file's blocks
 * and will parse them into an ordered extent list, in PAGE_SIZE chunks.  If
 * some stray blocks are found which do not fall within the PAGE_SIZE alignment
 * requirements, they are simply tossed out - we will never use those blocks
 * for swapping.
 *
 * For S_ISREG swapfiles we hold i_sem across the life of the swapon.  This
 * prevents root from shooting her foot off by ftruncating an in-use swapfile,
 * which will scribble on the fs.
 *
 * The amount of disk space which a single swap extent represents varies.
 * Typically it is in the 1-4 megabyte range.  So we can have hundreds of
 * extents in the list.  To avoid much list walking, we cache the previous
 * search location in `curr_swap_extent', and start new searches from there.
 * This is extremely effective.  The average number of iterations in
 * map_swap_page() has been measured at about 0.3 per page.  - akpm.
 */
static int setup_swap_extents(struct swap_info_struct *sis)
{
	struct inode *inode;
	unsigned blocks_per_page;
	unsigned long page_no;
	unsigned blkbits;
	sector_t probe_block;
	sector_t last_block;
	int ret;

	inode = sis->swap_file->f_mapping->host;
	if (S_ISBLK(inode->i_mode)) {
		ret = add_swap_extent(sis, 0, sis->max, 0);
		goto done;
	}

	blkbits = inode->i_blkbits;
	blocks_per_page = PAGE_SIZE >> blkbits;

	/*
	 * Map all the blocks into the extent list.  This code doesn't try
	 * to be very smart.
	 */
	probe_block = 0;
	page_no = 0;
	last_block = i_size_read(inode) >> blkbits;
	while ((probe_block + blocks_per_page) <= last_block &&
			page_no < sis->max) {
		unsigned block_in_page;
		sector_t first_block;

		first_block = bmap(inode, probe_block);
		if (first_block == 0)
			goto bad_bmap;

		/*
		 * It must be PAGE_SIZE aligned on-disk
		 */
		if (first_block & (blocks_per_page - 1)) {
			probe_block++;
			goto reprobe;
		}

		for (block_in_page = 1; block_in_page < blocks_per_page;
					block_in_page++) {
			sector_t block;

			block = bmap(inode, probe_block + block_in_page);
			if (block == 0)
				goto bad_bmap;
			if (block != first_block + block_in_page) {
				/* Discontiguity */
				probe_block++;
				goto reprobe;
			}
		}

		/*
		 * We found a PAGE_SIZE-length, PAGE_SIZE-aligned run of blocks
		 */
		ret = add_swap_extent(sis, page_no, 1,
				first_block >> (PAGE_SHIFT - blkbits));
		if (ret)
			goto out;
		page_no++;
		probe_block += blocks_per_page;
reprobe:
		continue;
	}
	ret = 0;
	if (page_no == 0)
		ret = -EINVAL;
	sis->max = page_no;
	sis->highest_bit = page_no - 1;
done:
	sis->curr_swap_extent = list_entry(sis->extent_list.prev,
					struct swap_extent, list);
	goto out;
bad_bmap:
	printk(KERN_ERR "swapon: swapfile has holes\n");
	ret = -EINVAL;
out:
	return ret;
}

#if 0	/* We don't need this yet */
#include <linux/backing-dev.h>
int page_queue_congested(struct page *page)
{
	struct backing_dev_info *bdi;

	BUG_ON(!PageLocked(page));	/* It pins the swap_info_struct */

	if (PageSwapCache(page)) {
		swp_entry_t entry = { .val = page->private };
		struct swap_info_struct *sis;

		sis = get_swap_info_struct(swp_type(entry));
		bdi = sis->bdev->bd_inode->i_mapping->backing_dev_info;
	} else
		bdi = page->mapping->backing_dev_info;
	return bdi_write_congested(bdi);
}
#endif

/**
 * 使指定的交换区无效。
 */
asmlinkage long sys_swapoff(const char __user * specialfile)
{
	struct swap_info_struct * p = NULL;
	unsigned short *swap_map;
	struct file *swap_file, *victim;
	struct address_space *mapping;
	struct inode *inode;
	char * pathname;
	int i, type, prev;
	int err;

	/**
	 * 验证当前进程是否具有CAP_SYS_ADMIN权限。
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/**
	 * 拷贝用户态空间的specialfile参数。
	 */
	pathname = getname(specialfile);
	err = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;

	/**
	 * 打开文件。返回文件对象地址。
	 */
	victim = filp_open(pathname, O_RDWR|O_LARGEFILE, 0);
	putname(pathname);
	err = PTR_ERR(victim);
	if (IS_ERR(victim))
		goto out;

	mapping = victim->f_mapping;
	prev = -1;
	swap_list_lock();
	/**
	 * 扫描交换区描述符链表，比较文件对象地址与活动交换区描述符的swap_file。如果不一致，说明传给函数的是一个无效参数，返回错误码。
	 */
	for (type = swap_list.head; type >= 0; type = swap_info[type].next) {
		p = swap_info + type;
		if ((p->flags & SWP_ACTIVE) == SWP_ACTIVE) {
			if (p->swap_file->f_mapping == mapping)
				break;
		}
		prev = type;
	}
	if (type < 0) {
		err = -EINVAL;
		swap_list_unlock();
		goto out_dput;
	}
	/**
	 * 调用security_vm_enough_memory，检查是否有足够的空闲页框把交换区上存放的所有页换入。
	 */
	if (!security_vm_enough_memory(p->pages))
		vm_unacct_memory(p->pages);
	else {
		err = -ENOMEM;
		swap_list_unlock();
		goto out_dput;
	}
	/**
	 * 将交换区从swap_list中删除。
	 */
	if (prev < 0) {
		swap_list.head = p->next;
	} else {
		swap_info[prev].next = p->next;
	}
	if (type == swap_list.next) {
		/* just pick something that's safe... */
		swap_list.next = swap_list.head;
	}
	/**
	 * 调整两个全局变量。
	 */
	nr_swap_pages -= p->pages;
	total_swap_pages -= p->pages;
	/**
	 * 清除该标志后，将不会再向交换区换出更多的页。
	 */
	p->flags &= ~SWP_WRITEOK;
	swap_list_unlock();
	current->flags |= PF_SWAPOFF;
	/**
	 * 调用try_to_unuse函数强制把这个交换区中剩余的所有页都移到RAM中。并相应地修改这些页的进程的页表。
	 * 当执行该函数时，当前进程的PF_SWAPOFF标志置位。
	 */
	err = try_to_unuse(type);
	current->flags &= ~PF_SWAPOFF;

	/* wait for any unplug function to finish */
	/**
	 * 等待交换区所在的块设备驱动器被卸载，这样在交换区被禁用前，try_to_unuse发出的读请求会被驱动器处理。
	 */
	down_write(&swap_unplug_sem);
	up_write(&swap_unplug_sem);

	/**
	 * try_to_unuse返回失败。不能关闭交换区。
	 */
	if (err) {
		/* re-insert swap space back into swap_list */
		swap_list_lock();
		/**
		 * 将交换区重新插入到swap_list链表。
		 */
		for (prev = -1, i = swap_list.head; i >= 0; prev = i, i = swap_info[i].next)
			if (p->prio >= swap_info[i].prio)
				break;
		p->next = i;
		if (prev < 0)
			swap_list.head = swap_list.next = p - swap_info;
		else
			swap_info[prev].next = p - swap_info;
		/**
		 * 调整全局变量。
		 */
		nr_swap_pages += p->pages;
		total_swap_pages += p->pages;
		p->flags |= SWP_WRITEOK;
		swap_list_unlock();
		goto out_dput;
	}
	/**
	 * 运行到这里，说明所有页槽都已经被成功传送到RAM中。
	 */
	down(&swapon_sem);
	swap_list_lock();
	drain_mmlist();
	swap_device_lock(p);
	swap_file = p->swap_file;
	p->swap_file = NULL;
	p->max = 0;
	swap_map = p->swap_map;
	p->swap_map = NULL;
	p->flags = 0;
	/**
	 * 释放子区描述符。
	 */
	destroy_swap_extents(p);
	swap_device_unlock(p);
	swap_list_unlock();
	up(&swapon_sem);
	/**
	 * 释放swap_map数组。
	 */
	vfree(swap_map);
	inode = mapping->host;
	if (S_ISBLK(inode->i_mode)) {
		/**
		 * 交换区在磁盘分区，恢复块大小为原值。
		 */
		struct block_device *bdev = I_BDEV(inode);
		set_blocksize(bdev, p->old_block_size);
		/**
		 * 交换区不再占有该块设备。
		 */
		bd_release(bdev);
	} else {
		/**
		 * 交换区在普通文件中，则把文件索引节点的S_SWAPFILE标志清0.
		 */
		down(&inode->i_sem);
		inode->i_flags &= ~S_SWAPFILE;
		up(&inode->i_sem);
	}
	/**
	 * 关闭两个文件:swap_file和victim。
	 */
	filp_close(swap_file, NULL);
	err = 0;

out_dput:
	filp_close(victim, NULL);
out:
	return err;
}

#ifdef CONFIG_PROC_FS
/* iterator */
static void *swap_start(struct seq_file *swap, loff_t *pos)
{
	struct swap_info_struct *ptr = swap_info;
	int i;
	loff_t l = *pos;

	down(&swapon_sem);

	for (i = 0; i < nr_swapfiles; i++, ptr++) {
		if (!(ptr->flags & SWP_USED) || !ptr->swap_map)
			continue;
		if (!l--)
			return ptr;
	}

	return NULL;
}

static void *swap_next(struct seq_file *swap, void *v, loff_t *pos)
{
	struct swap_info_struct *ptr = v;
	struct swap_info_struct *endptr = swap_info + nr_swapfiles;

	for (++ptr; ptr < endptr; ptr++) {
		if (!(ptr->flags & SWP_USED) || !ptr->swap_map)
			continue;
		++*pos;
		return ptr;
	}

	return NULL;
}

static void swap_stop(struct seq_file *swap, void *v)
{
	up(&swapon_sem);
}

static int swap_show(struct seq_file *swap, void *v)
{
	struct swap_info_struct *ptr = v;
	struct file *file;
	int len;

	if (v == swap_info)
		seq_puts(swap, "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");

	file = ptr->swap_file;
	len = seq_path(swap, file->f_vfsmnt, file->f_dentry, " \t\n\\");
	seq_printf(swap, "%*s%s\t%d\t%ld\t%d\n",
		       len < 40 ? 40 - len : 1, " ",
		       S_ISBLK(file->f_dentry->d_inode->i_mode) ?
				"partition" : "file\t",
		       ptr->pages << (PAGE_SHIFT - 10),
		       ptr->inuse_pages << (PAGE_SHIFT - 10),
		       ptr->prio);
	return 0;
}

static struct seq_operations swaps_op = {
	.start =	swap_start,
	.next =		swap_next,
	.stop =		swap_stop,
	.show =		swap_show
};

static int swaps_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &swaps_op);
}

static struct file_operations proc_swaps_operations = {
	.open		= swaps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init procswaps_init(void)
{
	struct proc_dir_entry *entry;

	entry = create_proc_entry("swaps", 0, NULL);
	if (entry)
		entry->proc_fops = &proc_swaps_operations;
	return 0;
}
__initcall(procswaps_init);
#endif /* CONFIG_PROC_FS */

/*
 * Written 01/25/92 by Simmule Turner, heavily changed by Linus.
 *
 * The swapon system call
 */
/**
 *激活交换区系统调用。
 *		specialfile:		设备文件或分区的路径径名(用户态地址空间)，或指向实现交换区的普通文件的路径名。
 *		swap_flags:			由一个单独的SWAP_FLAG_PREFER位加上交换区优先级的31位组成。只有在SWAP_FLAG_PREFER位置位时，优先级才有效。
 */
asmlinkage long sys_swapon(const char __user * specialfile, int swap_flags)
{
	struct swap_info_struct * p;
	char *name = NULL;
	struct block_device *bdev = NULL;
	struct file *swap_file = NULL;
	struct address_space *mapping;
	unsigned int type;
	int i, prev;
	int error;
	static int least_priority;
	union swap_header *swap_header = NULL;
	int swap_header_version;
	int nr_good_pages = 0;
	unsigned long maxpages = 1;
	int swapfilesize;
	unsigned short *swap_map;
	struct page *page = NULL;
	struct inode *inode = NULL;
	int did_down = 0;

	/**
	 * 检查当前进程是否具有CAP_SYS_ADMIN权限。
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	swap_list_lock();
	p = swap_info;
	/**
	 * 在交换区数据组中查找SWP_USED标志为0的第一个一个描述符。
	 */
	for (type = 0 ; type < nr_swapfiles ; type++,p++)
		if (!(p->flags & SWP_USED))
			break;
	error = -EPERM;
	/*
	 * Test if adding another swap device is possible. There are
	 * two limiting factors: 1) the number of bits for the swap
	 * type swp_entry_t definition and 2) the number of bits for
	 * the swap type in the swap ptes as defined by the different
	 * architectures. To honor both limitations a swap entry
	 * with swap offset 0 and swap type ~0UL is created, encoded
	 * to a swap pte, decoded to a swp_entry_t again and finally
	 * the swap type part is extracted. This will mask all bits
	 * from the initial ~0UL that can't be encoded in either the
	 * swp_entry_t or the architecture definition of a swap pte.
	 */
	if (type > swp_type(pte_to_swp_entry(swp_entry_to_pte(swp_entry(~0UL,0))))) {
		swap_list_unlock();
		goto out;
	}
	if (type >= nr_swapfiles)
		nr_swapfiles = type+1;
	INIT_LIST_HEAD(&p->extent_list);
	/**
	 * 找到交换区索引，初始化描述符。
	 */
	p->flags = SWP_USED;
	p->nr_extents = 0;
	p->swap_file = NULL;
	p->old_block_size = 0;
	p->swap_map = NULL;
	p->lowest_bit = 0;
	p->highest_bit = 0;
	p->cluster_nr = 0;
	p->inuse_pages = 0;
	spin_lock_init(&p->sdev_lock);
	p->next = -1;
	/**
	 * 如果参数为新交换区指定了优先级，则设置描述符的prio字段。
	 */
	if (swap_flags & SWAP_FLAG_PREFER) {
		p->prio =
		  (swap_flags & SWAP_FLAG_PRIO_MASK)>>SWAP_FLAG_PRIO_SHIFT;
	} else {
		/**
		 * 否则将交换区的优先级设置为当前优先级中最低优先级再减一。也就是说，新交换区是最低优先级。
		 */
		p->prio = --least_priority;
	}
	swap_list_unlock();
	/**
	 * 从用户态地址空间复制specialfile参数所指向的字符串。
	 */
	name = getname(specialfile);
	error = PTR_ERR(name);
	if (IS_ERR(name)) {
		name = NULL;
		goto bad_swap_2;
	}
	/**
	 * 打开指定的文件。
	 */
	swap_file = filp_open(name, O_RDWR|O_LARGEFILE, 0);
	error = PTR_ERR(swap_file);
	if (IS_ERR(swap_file)) {
		swap_file = NULL;
		goto bad_swap_2;
	}

	/**
	 * 将打开的文件描述符存放在swap_file中。
	 */
	p->swap_file = swap_file;
	mapping = swap_file->f_mapping;
	inode = mapping->host;

	error = -EBUSY;
	/**
	 * 检查交换区，以确认该交换区没有被激活。
	 */
	for (i = 0; i < nr_swapfiles; i++) {
		struct swap_info_struct *q = &swap_info[i];

		if (i == type || !q->swap_file)
			continue;
		if (mapping == q->swap_file->f_mapping)
			goto bad_swap;
	}

	error = -EINVAL;
	/**
	 * 检查打开文件是否为一个块设备文件。
	 */
	if (S_ISBLK(inode->i_mode)) {
		bdev = I_BDEV(inode);
		/**
		 * bd_claim将交换子系统设置成块设备的占有者。如果块设备已经有一个占有者，则返回错误码。
		 */
		error = bd_claim(bdev, sys_swapon);
		if (error < 0) {
			bdev = NULL;
			goto bad_swap;
		}
		/**
		 * 把块设备的当前块大小存放在交换区描述符的old_block_size字段，然后把设备的块设备大小设成页的大小。
		 */
		p->old_block_size = block_size(bdev);
		error = set_blocksize(bdev, PAGE_SIZE);
		if (error < 0)
			goto bad_swap;
		/**
		 * 将块设备描述符存入交换区描述符的bdev字段。
		 */
		p->bdev = bdev;
	} else if (S_ISREG(inode->i_mode)) {
		/**
		 * 交换区是一个普通文件。
		 */
		p->bdev = inode->i_sb->s_bdev;
		down(&inode->i_sem);
		did_down = 1;
		/**
		 * 检查文件索引节点i_flags字段中的S_SWAPFILE字段。如果该标志置位，说明文件已经用做交换区，返回失败。
		 */
		if (IS_SWAPFILE(inode)) {
			error = -EBUSY;
			goto bad_swap;
		}
	} else {
		goto bad_swap;
	}

	swapfilesize = i_size_read(inode) >> PAGE_SHIFT;

	/*
	 * Read the swap header.
	 */
	if (!mapping->a_ops->readpage) {
		error = -EINVAL;
		goto bad_swap;
	}
	/**
	 * 读取存放在交换区页槽0中的swap_header描述符。
	 */
	page = read_cache_page(mapping, 0,
			(filler_t *)mapping->a_ops->readpage, swap_file);
	if (IS_ERR(page)) {
		error = PTR_ERR(page);
		goto bad_swap;
	}
	wait_on_page_locked(page);
	if (!PageUptodate(page))
		goto bad_swap;
	kmap(page);
	swap_header = page_address(page);

	/**
	 * 检查最后10个字符，以确定版本号。
	 */
	if (!memcmp("SWAP-SPACE",swap_header->magic.magic,10))
		swap_header_version = 1;
	else if (!memcmp("SWAPSPACE2",swap_header->magic.magic,10))
		swap_header_version = 2;
	else {
		printk("Unable to find swap-space signature\n");
		error = -EINVAL;
		goto bad_swap;
	}
	
	switch (swap_header_version) {
	case 1:
		printk(KERN_ERR "version 0 swap is no longer supported. "
			"Use mkswap -v1 %s\n", name);
		error = -EINVAL;
		goto bad_swap;
	case 2:
		/* Check the swap header's sub-version and the size of
                   the swap file and bad block lists */
		if (swap_header->info.version != 1) {
			printk(KERN_WARNING
			       "Unable to handle swap header version %d\n",
			       swap_header->info.version);
			error = -EINVAL;
			goto bad_swap;
		}

		p->lowest_bit  = 1;
		/*
		 * Find out how many pages are allowed for a single swap
		 * device. There are two limiting factors: 1) the number of
		 * bits for the swap offset in the swp_entry_t type and
		 * 2) the number of bits in the a swap pte as defined by
		 * the different architectures. In order to find the
		 * largest possible bit mask a swap entry with swap type 0
		 * and swap offset ~0UL is created, encoded to a swap pte,
		 * decoded to a swp_entry_t again and finally the swap
		 * offset is extracted. This will mask all the bits from
		 * the initial ~0UL mask that can't be encoded in either
		 * the swp_entry_t or the architecture definition of a
		 * swap pte.
		 */
		maxpages = swp_offset(pte_to_swp_entry(swp_entry_to_pte(swp_entry(0,~0UL)))) - 1;
		/**
		 * 根据last_page确定交换区的大小。
		 */
		if (maxpages > swap_header->info.last_page)
			maxpages = swap_header->info.last_page;
		/**
		 * 根据交换区大小设置lowest_bit和highest_bit
		 */
		p->highest_bit = maxpages - 1;

		error = -EINVAL;
		if (swap_header->info.nr_badpages > MAX_SWAP_BADPAGES)
			goto bad_swap;
		
		/* OK, set up the swap map and apply the bad block list */
		/**
		 * 分配新交换区相关的计数器数组。并将它存放在交换区描述符的swap_map中。
		 */
		if (!(p->swap_map = vmalloc(maxpages * sizeof(short)))) {
			error = -ENOMEM;
			goto bad_swap;
		}

		error = 0;
		/**
		 * 根据bad_pages字段中存放的有缺陷的页槽链表把计数器数组元素初始化成0或者SWAP_MAP_BAD。
		 */
		memset(p->swap_map, 0, maxpages * sizeof(short));
		for (i=0; i<swap_header->info.nr_badpages; i++) {
			int page = swap_header->info.badpages[i];
			if (page <= 0 || page >= swap_header->info.last_page)
				error = -EINVAL;
			else
				p->swap_map[page] = SWAP_MAP_BAD;
		}
		/**
		 * 计算可用页槽数。
		 */
		nr_good_pages = swap_header->info.last_page -
				swap_header->info.nr_badpages -
				1 /* header page */;
		if (error) 
			goto bad_swap;
	}
	
	if (swapfilesize && maxpages > swapfilesize) {
		printk(KERN_WARNING
		       "Swap area shorter than signature indicates\n");
		error = -EINVAL;
		goto bad_swap;
	}
	if (!nr_good_pages) {
		printk(KERN_WARNING "Empty swap-file\n");
		error = -EINVAL;
		goto bad_swap;
	}
	p->swap_map[0] = SWAP_MAP_BAD;
	p->max = maxpages;
	p->pages = nr_good_pages;

	/**
	 * 为新交换区建立子区链表，并设置交换区描述符的nr_externs和curr_swap_extent字段。
	 */
	error = setup_swap_extents(p);
	if (error)
		goto bad_swap;

	down(&swapon_sem);
	swap_list_lock();
	swap_device_lock(p);
	/**
	 * 设置flag标志为SWP_ACTIVE，然后更新几个全局变量。
	 */
	p->flags = SWP_ACTIVE;
	nr_swap_pages += nr_good_pages;
	total_swap_pages += nr_good_pages;
	printk(KERN_INFO "Adding %dk swap on %s.  Priority:%d extents:%d\n",
		nr_good_pages<<(PAGE_SHIFT-10), name,
		p->prio, p->nr_extents);

	/* insert swap space into swap_list: */
	/**
	 * 将交换区插入swap_list链表中。
	 */
	prev = -1;
	for (i = swap_list.head; i >= 0; i = swap_info[i].next) {
		if (p->prio >= swap_info[i].prio) {
			break;
		}
		prev = i;
	}
	p->next = i;
	if (prev < 0) {
		swap_list.head = swap_list.next = p - swap_info;
	} else {
		swap_info[prev].next = p - swap_info;
	}
	swap_device_unlock(p);
	swap_list_unlock();
	up(&swapon_sem);
	error = 0;
	goto out;
bad_swap:
	if (bdev) {
		set_blocksize(bdev, p->old_block_size);
		bd_release(bdev);
	}
bad_swap_2:
	swap_list_lock();
	swap_map = p->swap_map;
	p->swap_file = NULL;
	p->swap_map = NULL;
	p->flags = 0;
	if (!(swap_flags & SWAP_FLAG_PREFER))
		++least_priority;
	swap_list_unlock();
	destroy_swap_extents(p);
	vfree(swap_map);
	if (swap_file)
		filp_close(swap_file, NULL);
out:
	if (page && !IS_ERR(page)) {
		kunmap(page);
		page_cache_release(page);
	}
	if (name)
		putname(name);
	if (did_down) {
		if (!error)
			inode->i_flags |= S_SWAPFILE;
		up(&inode->i_sem);
	}
	return error;
}

void si_swapinfo(struct sysinfo *val)
{
	unsigned int i;
	unsigned long nr_to_be_unused = 0;

	swap_list_lock();
	for (i = 0; i < nr_swapfiles; i++) {
		if (!(swap_info[i].flags & SWP_USED) ||
		     (swap_info[i].flags & SWP_WRITEOK))
			continue;
		nr_to_be_unused += swap_info[i].inuse_pages;
	}
	val->freeswap = nr_swap_pages + nr_to_be_unused;
	val->totalswap = total_swap_pages + nr_to_be_unused;
	swap_list_unlock();
}

/*
 * Verify that a swap entry is valid and increment its swap map count.
 *
 * Note: if swap_map[] reaches SWAP_MAP_MAX the entries are treated as
 * "permanent", but will be reclaimed by the next swapoff.
 */
/**
 * 当试图换出一个已经换出的页时就会调用此函数。
 * 本函数验证参数传递的换出页标识符是否有效，并增加相应的swap_map计数器的值。
 */
int swap_duplicate(swp_entry_t entry)
{
	struct swap_info_struct * p;
	unsigned long offset, type;
	int result = 0;

	/**
	 * 从参数中取出交换区号和页槽索引。
	 */
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_file;
	p = type + swap_info;
	offset = swp_offset(entry);

	swap_device_lock(p);
	/**
	 * 检查页槽索引号，以及该页槽是否已经交换过。
	 */
	if (offset < p->max && p->swap_map[offset]) {
		/**
		 * 还没有达到最大换出次数。还不是永久换出。
		 */
		if (p->swap_map[offset] < SWAP_MAP_MAX - 1) {
			/**
			 * 增加换出次数。
			 */
			p->swap_map[offset]++;
			result = 1;
		} else if (p->swap_map[offset] <= SWAP_MAP_MAX) {/* 溢出了，会出现这种情况?? */
			if (swap_overflow++ < 5)
				printk(KERN_WARNING "swap_dup: swap entry overflow\n");
			p->swap_map[offset] = SWAP_MAP_MAX;
			result = 1;
		}
	}
	swap_device_unlock(p);
out:
	return result;

bad_file:
	printk(KERN_ERR "swap_dup: %s%08lx\n", Bad_file, entry.val);
	goto out;
}

struct swap_info_struct *
get_swap_info_struct(unsigned type)
{
	return &swap_info[type];
}

/*
 * swap_device_lock prevents swap_map being freed. Don't grab an extra
 * reference on the swaphandle, it doesn't matter if it becomes unused.
 */
int valid_swaphandles(swp_entry_t entry, unsigned long *offset)
{
	int ret = 0, i = 1 << page_cluster;
	unsigned long toff;
	struct swap_info_struct *swapdev = swp_type(entry) + swap_info;

	if (!page_cluster)	/* no readahead */
		return 0;
	toff = (swp_offset(entry) >> page_cluster) << page_cluster;
	if (!toff)		/* first page is swap header */
		toff++, i--;
	*offset = toff;

	swap_device_lock(swapdev);
	do {
		/* Don't read-ahead past the end of the swap area */
		if (toff >= swapdev->max)
			break;
		/* Don't read in free or bad pages */
		if (!swapdev->swap_map[toff])
			break;
		if (swapdev->swap_map[toff] == SWAP_MAP_BAD)
			break;
		toff++;
		ret++;
	} while (--i);
	swap_device_unlock(swapdev);
	return ret;
}
