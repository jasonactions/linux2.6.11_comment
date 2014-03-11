#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/sched.h>
#include <linux/errno.h>

#ifdef __KERNEL__

#include <linux/config.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mmzone.h>
#include <linux/rbtree.h>
#include <linux/prio_tree.h>
#include <linux/fs.h>

struct mempolicy;
struct anon_vma;

#ifndef CONFIG_DISCONTIGMEM          /* Don't use mapnrs, do it properly */
extern unsigned long max_mapnr;
#endif

extern unsigned long num_physpages;
extern void * high_memory;
extern unsigned long vmalloc_earlyreserve;
extern int page_cluster;

#ifdef CONFIG_SYSCTL
extern int sysctl_legacy_va_layout;
#else
#define sysctl_legacy_va_layout 0
#endif

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/atomic.h>

#ifndef MM_VM_SIZE
#define MM_VM_SIZE(mm)	((TASK_SIZE + PGDIR_SIZE - 1) & PGDIR_MASK)
#endif

#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))

/*
 * Linux kernel virtual memory manager primitives.
 * The idea being to have a "virtual" mm in the same way
 * we have a virtual fs - giving a cleaner interface to the
 * mm details, and allowing different kinds of memory mappings
 * (from shared memory to executable loading to arbitrary
 * mmap() functions).
 */

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
/**
 * 线性区描述符。
 */
struct vm_area_struct {
	/**
	 * 指向线性区所在的内存描述符。
	 */
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	/**
	 * 线性区内的第一个线性地址。
	 */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	/**
	 * 线性区之后的第一个线性地址。
	 */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	/**
	 * 进程链表中的下一个线性区。
	 */
	struct vm_area_struct *vm_next;

	/**
	 * 线性区中页框的访问许可权。
	 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/**
	 * 线性区的标志。
	 */
	unsigned long vm_flags;		/* Flags, listed below. */

	/**
	 * 用于红黑树的数据。
	 */
	struct rb_node vm_rb;

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/**
	 * 链接到反映射所使用的数据结构。
	 */
	union {
		/**
		 * 如果在优先搜索树中，存在两个节点的基索引、堆索引、大小索引完全相同，那么这些相同的节点会被链接到一个链表，而vm_set就是这个链表的元素。
		 */
		struct {
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;

		/**
		 * 如果是文件映射，那么prio_tree_node用于将线性区插入到优先搜索树中。作为搜索树的一个节点。
		 */
		struct raw_prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.  A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/**
	 * 指向匿名线性区链表的指针(参见"映射页的反映射")。
	 * 页框结构有一个anon_vma指针，指向该页的第一个线性区，随后的线性区通过此字段链接起来。
	 * 通过此字段，可以将线性区链接到此链表中。
	 */
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	/**
	 * 指向anon_vma数据结构的指针(参见"映射页的反映射")。此指针也存放在页结构的mapping字段中。
	 */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/**
	 * 指向线性区的方法。
	 */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	/**
	 * 在映射文件中的偏移量(以页为单位)。对匿名页，它等于0或vm_start/PAGE_SIZE
	 */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	/**
	 * 指向映射文件的文件对象(如果有的话)
	 */
	struct file * vm_file;		/* File we map to (can be NULL). */
	/**
	 * 指向内存区的私有数据。
	 */
	void * vm_private_data;		/* was vm_pte (shared mem) */
	/**
	 * 释放非线性文件内存映射中的一个线性地址区间时使用。
	 */
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

/*
 * This struct defines the per-mm list of VMAs for uClinux. If CONFIG_MMU is
 * disabled, then there's a single shared list of VMAs maintained by the
 * system, and mm's subscribe to these individually
 */
struct vm_list_struct {
	struct vm_list_struct	*next;
	struct vm_area_struct	*vma;
};

#ifndef CONFIG_MMU
extern struct rb_root nommu_vma_tree;
extern struct rw_semaphore nommu_vma_sem;

extern unsigned int kobjsize(const void *objp);
#endif

/*
 * vm_flags..
 */
/**
 * 线性区中页是可读的。
 */
#define VM_READ		0x00000001	/* currently active flags */
/**
 * 线性区中页是可写的。
 */
#define VM_WRITE	0x00000002
/**
 * 线性区中页是可执行的。
 */
#define VM_EXEC		0x00000004
/**
 * 线性区中页可以由几个进程共享。
 */
#define VM_SHARED	0x00000008

/**
 * 可以设置VM_READ标志。
 */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
/**
 * 可以设置VM_WRITE标志。
 */
#define VM_MAYWRITE	0x00000020
/**
 * 可以设置VM_EXEC标志。
 */
#define VM_MAYEXEC	0x00000040
/**
 * 可以设置VM_SHARED标志。
 */
#define VM_MAYSHARE	0x00000080

/**
 * 线性区可以向低地址扩展
 */
#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
/**
 * 线性区可以向高地址扩展
 */
#define VM_GROWSUP	0x00000200
/**
 * 线性区用于IPC共享内存。
 */
#define VM_SHM		0x00000400	/* shared memory area, don't swap out */
/**
 * 线性区映射一个不能打开用于写的文件。
 */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

/**
 * 线性区映射一个可执行文件。
 */
#define VM_EXECUTABLE	0x00001000
/**
 * 线性区中的页被锁住，且不能换出。
 */
#define VM_LOCKED	0x00002000
/**
 * 线性区映射设备的IO地址空间。
 */
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
/**
 * 应用程序顺序的访问页。
 */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
/**
 * 应用程序以真正的随机顺序访问页。
 */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */
/**
 * 当创建一个新进程时不拷贝线性区。
 */
#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
/**
 * 通过mremap系统调用禁止线性区扩展。
 */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
/**
 * 线性区是特殊的(如它映射某个设备的IO地址空间)，因此它的页不能被交换出去。
 */
#define VM_RESERVED	0x00080000	/* Don't unmap it from swap_out */
/**
 * 创建IPC共享线性区时检查是否有足够的空闲内存用于映射。
 */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
/**
 * 通过扩展分页机制处理线性区中的页。
 */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
/**
 * 线性区实现非线性文件映射。
 */
#define VM_NONLINEAR	0x00800000	/* Is non-linear (remap_file_pages) */

#ifndef VM_STACK_DEFAULT_FLAGS		/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK_FLAGS	(VM_GROWSUP | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#else
#define VM_STACK_FLAGS	(VM_GROWSDOWN | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#endif

#define VM_READHINTMASK			(VM_SEQ_READ | VM_RAND_READ)
#define VM_ClearReadHint(v)		(v)->vm_flags &= ~VM_READHINTMASK
#define VM_NormalReadHint(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_SequentialReadHint(v)	((v)->vm_flags & VM_SEQ_READ)
#define VM_RandomReadHint(v)		((v)->vm_flags & VM_RAND_READ)

/*
 * mapping from the currently active vm_flags protection bits (the
 * low four bits) to a page protection mask..
 */
extern pgprot_t protection_map[16];


/*
 * These are the virtual MM functions - opening of an area, closing and
 * unmapping it (needed to keep files on disk up-to-date etc), pointer
 * to the functions called when a no-page or a wp-page exception occurs. 
 */
/**
 * 线性区的方法。
 */
struct vm_operations_struct {
	/**
	 * 当把线性区增加到进程所拥有的线性区集合时调用。
	 */
	void (*open)(struct vm_area_struct * area);
	/**
	 * 当从进程所拥有的线性区集合删除线性区时调用。
	 */
	void (*close)(struct vm_area_struct * area);
	/**
	 * 当进程试图访问RAM中不存在的一个页，但该页的线性地址属于线性区时，由缺页异常处理程序调用。
	 */
	struct page * (*nopage)(struct vm_area_struct * area, unsigned long address, int *type);
	/**
	 * 设置线性区的线性地址(预缺页)所对应的页表项时调用。主要用于非线性文件内存映射。
	 */
	int (*populate)(struct vm_area_struct * area, unsigned long address, unsigned long len, pgprot_t prot, unsigned long pgoff, int nonblock);
#ifdef CONFIG_NUMA
	int (*set_policy)(struct vm_area_struct *vma, struct mempolicy *new);
	struct mempolicy *(*get_policy)(struct vm_area_struct *vma,
					unsigned long addr);
#endif
};

struct mmu_gather;
struct inode;

#ifdef ARCH_HAS_ATOMIC_UNSIGNED
typedef unsigned page_flags_t;
#else
typedef unsigned long page_flags_t;
#endif

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page.
 */
struct page {
	/**
	 * 一组标志，也对页框所在的管理区进行编号
	 * 在不支持NUMA的机器上，flags中字段中管理索引占两位，节点索引占一位。
	 * 在支持NUMA的32位机器上，flags中管理索引占用两位。节点数目占6位。
	 * 在支持NUMA的64位机器上，64位的flags字段中，管理区索引占用两位，节点数目占用10位。
	 */
	page_flags_t flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/**
	 * 页框的引用计数。当小于0表示没有人使用。
	 * Page_count返回_count+1表示正在使用的人数。
	 */
	atomic_t _count;		/* Usage count, see below. */
	/**
	 * 页框中的页表项数目（没有则为-1）
	 *		-1:		表示没有页表项引用该页框。
	 *		0:		表明页是非共享的。
	 *		>0:		表示而是共享共享的。
	 */
	atomic_t _mapcount;		/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
	/**
	 * 可用于正在使用页的内核成分（如在缓冲页的情况下，它是一个缓冲器头指针。）
	 * 如果页是空闲的，则该字段由伙伴系统使用。
	 * 当用于伙伴系统时，如果该页是一个2^k的空闲页块的第一个页，那么它的值就是k.
	 * 这样，伙伴系统可以查找相邻的伙伴，以确定是否可以将空闲块合并成2^(k+1)大小的空闲块。
	 */
	unsigned long private;		/* Mapping-private opaque data:
					 * usually used for buffer_heads
					 * if PagePrivate set; used for
					 * swp_entry_t if PageSwapCache
					 * When page is free, this indicates
					 * order in the buddy system.
					 */
	/**
	 * 当页被插入页高速缓存时使用或者当页属于匿名页时使用）。
	 * 		如果mapping字段为空，则该页属于交换高速缓存。
	 *		如果mapping字段不为空，且最低位为1，表示该页为匿名页。同时该字段中存放的是指向anon_vma描述符的指针。
	 *		如果mapping字段不为空，且最低位为0，表示该页为映射页。同时该字段指向对应文件的address_space对象。
	 */
	struct address_space *mapping;	/* If low bit clear, points to
					 * inode address_space, or NULL.
					 * If page mapped as anonymous
					 * memory, low bit is set, and
					 * it points to anon_vma object:
					 * see PAGE_MAPPING_ANON below.
					 */
	/**
	 * 作为不同的含义被几种内核成分使用。
	 * 在页磁盘映象或匿名区中表示存放在页框中的数据的位置。
	 * 或者它存放在一个换出页标志符。
	 */
	pgoff_t index;			/* Our offset within mapping. */
	/**
	 * 包含页的最近最少使用的双向链表的指针。
	 */
	struct list_head lru;		/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	/**
	 * 如果进行了内存映射，就是虚拟地址。对存在高端内存的系统来说有意义。
	 */
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

/*
 * FIXME: take this include out, include page-flags.h in
 * files which need it (119 of them)
 */
#include <linux/page-flags.h>

/*
 * Methods to modify the page usage count.
 *
 * What counts for a page usage:
 * - cache mapping   (page->mapping)
 * - private data    (page->private)
 * - page mapped in a task's page tables, each mapping
 *   is counted separately
 *
 * Also, many kernel routines increase the page count before a critical
 * routine so they can be sure the page doesn't go away from under them.
 *
 * Since 2.6.6 (approx), a free page has ->_count = -1.  This is so that we
 * can use atomic_add_negative(-1, page->_count) to detect when the page
 * becomes free and so that we can also use atomic_inc_and_test to atomically
 * detect when we just tried to grab a ref on a page which some other CPU has
 * already deemed to be freeable.
 *
 * NO code should make assumptions about this internal detail!  Use the provided
 * macros which retain the old rules: page_count(page) == 0 is a free page.
 */

/*
 * Drop a ref, return true if the logical refcount fell to zero (the page has
 * no users)
 */
#define put_page_testzero(p)				\
	({						\
		BUG_ON(page_count(p) == 0);		\
		atomic_add_negative(-1, &(p)->_count);	\
	})

/*
 * Grab a ref, return true if the page previously had a logical refcount of
 * zero.  ie: returns true if we just grabbed an already-deemed-to-be-free page
 */
#define get_page_testone(p)	atomic_inc_and_test(&(p)->_count)

#define set_page_count(p,v) 	atomic_set(&(p)->_count, v - 1)
#define __put_page(p)		atomic_dec(&(p)->_count)

extern void FASTCALL(__page_cache_release(struct page *));

#ifdef CONFIG_HUGETLB_PAGE

static inline int page_count(struct page *p)
{
	if (PageCompound(p))
		p = (struct page *)p->private;
	return atomic_read(&(p)->_count) + 1;
}

static inline void get_page(struct page *page)
{
	if (unlikely(PageCompound(page)))
		page = (struct page *)page->private;
	atomic_inc(&page->_count);
}

void put_page(struct page *page);

#else		/* CONFIG_HUGETLB_PAGE */

/**
 * 页框使用者数目。
 * 注意_count为0表示有一个使用在使用该页框。
 */
#define page_count(p)		(atomic_read(&(p)->_count) + 1)

static inline void get_page(struct page *page)
{
	atomic_inc(&page->_count);
}

static inline void put_page(struct page *page)
{
	if (!PageReserved(page) && put_page_testzero(page))
		__page_cache_release(page);
}

#endif		/* CONFIG_HUGETLB_PAGE */

/*
 * Multiple processes may "see" the same page. E.g. for untouched
 * mappings of /dev/null, all processes see the same page full of
 * zeroes, and text pages of executables and shared libraries have
 * only one copy in memory, at most, normally.
 *
 * For the non-reserved pages, page_count(page) denotes a reference count.
 *   page_count() == 0 means the page is free.
 *   page_count() == 1 means the page is used for exactly one purpose
 *   (e.g. a private data page of one process).
 *
 * A page may be used for kmalloc() or anyone else who does a
 * __get_free_page(). In this case the page_count() is at least 1, and
 * all other fields are unused but should be 0 or NULL. The
 * management of this page is the responsibility of the one who uses
 * it.
 *
 * The other pages (we may call them "process pages") are completely
 * managed by the Linux memory manager: I/O, buffers, swapping etc.
 * The following discussion applies only to them.
 *
 * A page may belong to an inode's memory mapping. In this case,
 * page->mapping is the pointer to the inode, and page->index is the
 * file offset of the page, in units of PAGE_CACHE_SIZE.
 *
 * A page contains an opaque `private' member, which belongs to the
 * page's address_space.  Usually, this is the address of a circular
 * list of the page's disk buffers.
 *
 * For pages belonging to inodes, the page_count() is the number of
 * attaches, plus 1 if `private' contains something, plus one for
 * the page cache itself.
 *
 * All pages belonging to an inode are in these doubly linked lists:
 * mapping->clean_pages, mapping->dirty_pages and mapping->locked_pages;
 * using the page->list list_head. These fields are also used for
 * freelist managemet (when page_count()==0).
 *
 * There is also a per-mapping radix tree mapping index to the page
 * in memory if present. The tree is rooted at mapping->root.  
 *
 * All process pages can do I/O:
 * - inode pages may need to be read from disk,
 * - inode pages which have been modified and are MAP_SHARED may need
 *   to be written to disk,
 * - private pages which have been modified may need to be swapped out
 *   to swap space and (later) to be read back into memory.
 */

/*
 * The zone field is never updated after free_area_init_core()
 * sets it, so none of the operations on it need to be atomic.
 * We'll have up to (MAX_NUMNODES * MAX_NR_ZONES) zones total,
 * so we use (MAX_NODES_SHIFT + MAX_ZONES_SHIFT) here to get enough bits.
 */
#define NODEZONE_SHIFT (sizeof(page_flags_t)*8 - MAX_NODES_SHIFT - MAX_ZONES_SHIFT)
#define NODEZONE(node, zone)	((node << ZONES_SHIFT) | zone)

static inline unsigned long page_zonenum(struct page *page)
{
	return (page->flags >> NODEZONE_SHIFT) & (~(~0UL << ZONES_SHIFT));
}
static inline unsigned long page_to_nid(struct page *page)
{
	return (page->flags >> (NODEZONE_SHIFT + ZONES_SHIFT));
}

struct zone;
extern struct zone *zone_table[];

/**
 * 接收一个页描述符的地址作为它的参数，它读取页描述符的flags字段的高位，并通过zone_table数组来确定相应管理区描述符的地址
 */
static inline struct zone *page_zone(struct page *page)
{
	return zone_table[page->flags >> NODEZONE_SHIFT];
}

static inline void set_page_zone(struct page *page, unsigned long nodezone_num)
{
	page->flags &= ~(~0UL << NODEZONE_SHIFT);
	page->flags |= nodezone_num << NODEZONE_SHIFT;
}

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

static inline void *lowmem_page_address(struct page *page)
{
	return __va(page_to_pfn(page) << PAGE_SHIFT);
}

#if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
#define HASHED_PAGE_VIRTUAL
#endif

#if defined(WANT_PAGE_VIRTUAL)
#define page_address(page) ((page)->virtual)
#define set_page_address(page, address)			\
	do {						\
		(page)->virtual = (address);		\
	} while(0)
#define page_address_init()  do { } while(0)
#endif

#if defined(HASHED_PAGE_VIRTUAL)
void *page_address(struct page *page);
void set_page_address(struct page *page, void *virtual);
void page_address_init(void);
#endif

#if !defined(HASHED_PAGE_VIRTUAL) && !defined(WANT_PAGE_VIRTUAL)
#define page_address(page) lowmem_page_address(page)
#define set_page_address(page, address)  do { } while(0)
#define page_address_init()  do { } while(0)
#endif

/*
 * On an anonymous page mapped into a user virtual memory area,
 * page->mapping points to its anon_vma, not to a struct address_space;
 * with the PAGE_MAPPING_ANON bit set to distinguish it.
 *
 * Please note that, confusingly, "page_mapping" refers to the inode
 * address_space which maps the page from disk; whereas "page_mapped"
 * refers to user virtual address space into which the page is mapped.
 */
#define PAGE_MAPPING_ANON	1

extern struct address_space swapper_space;
static inline struct address_space *page_mapping(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (unlikely(PageSwapCache(page)))
		mapping = &swapper_space;
	else if (unlikely((unsigned long)mapping & PAGE_MAPPING_ANON))
		mapping = NULL;
	return mapping;
}

static inline int PageAnon(struct page *page)
{
	return ((unsigned long)page->mapping & PAGE_MAPPING_ANON) != 0;
}

/*
 * Return the pagecache index of the passed page.  Regular pagecache pages
 * use ->index whereas swapcache pages use ->private
 */
static inline pgoff_t page_index(struct page *page)
{
	if (unlikely(PageSwapCache(page)))
		return page->private;
	return page->index;
}

/*
 * The atomic page->_mapcount, like _count, starts from -1:
 * so that transitions both from it and to it can be tracked,
 * using atomic_inc_and_test and atomic_add_negative(-1).
 */
static inline void reset_page_mapcount(struct page *page)
{
	atomic_set(&(page)->_mapcount, -1);
}

/**
 * 接收页描述符地址，返回_mapcount+1
 * 这样，如果返回为1，表明是某个进程的用户态址空间中存放的一个非共享页。
 */
static inline int page_mapcount(struct page *page)
{
	return atomic_read(&(page)->_mapcount) + 1;
}

/*
 * Return true if this page is mapped into pagetables.
 */
static inline int page_mapped(struct page *page)
{
	return atomic_read(&(page)->_mapcount) >= 0;
}

/*
 * Error return values for the *_nopage functions
 */
#define NOPAGE_SIGBUS	(NULL)
#define NOPAGE_OOM	((struct page *) (-1))

/*
 * Different kinds of faults, as returned by handle_mm_fault().
 * Used to decide whether a process gets delivered SIGBUS or
 * just gets major/minor fault counters bumped up.
 */
#define VM_FAULT_OOM	(-1)
#define VM_FAULT_SIGBUS	0
#define VM_FAULT_MINOR	1
#define VM_FAULT_MAJOR	2

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

extern void show_free_areas(void);

#ifdef CONFIG_SHMEM
struct page *shmem_nopage(struct vm_area_struct *vma,
			unsigned long address, int *type);
int shmem_set_policy(struct vm_area_struct *vma, struct mempolicy *new);
struct mempolicy *shmem_get_policy(struct vm_area_struct *vma,
					unsigned long addr);
int shmem_lock(struct file *file, int lock, struct user_struct *user);
#else
#define shmem_nopage filemap_nopage
#define shmem_lock(a, b, c) 	({0;})	/* always in memory, no need to lock */
#define shmem_set_policy(a, b)	(0)
#define shmem_get_policy(a, b)	(NULL)
#endif
struct file *shmem_file_setup(char *name, loff_t size, unsigned long flags);

int shmem_zero_setup(struct vm_area_struct *);

static inline int can_do_mlock(void)
{
	if (capable(CAP_IPC_LOCK))
		return 1;
	if (current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur != 0)
		return 1;
	return 0;
}
extern int user_shm_lock(size_t, struct user_struct *);
extern void user_shm_unlock(size_t, struct user_struct *);

/*
 * Parameter block passed down to zap_pte_range in exceptional cases.
 */
struct zap_details {
	struct vm_area_struct *nonlinear_vma;	/* Check page->index if set */
	struct address_space *check_mapping;	/* Check page->mapping if set */
	pgoff_t	first_index;			/* Lowest page->index to unmap */
	pgoff_t last_index;			/* Highest page->index to unmap */
	spinlock_t *i_mmap_lock;		/* For unmap_mapping_range: */
	unsigned long break_addr;		/* Where unmap_vmas stopped */
	unsigned long truncate_count;		/* Compare vm_truncate_count */
};

void zap_page_range(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *);
int unmap_vmas(struct mmu_gather **tlbp, struct mm_struct *mm,
		struct vm_area_struct *start_vma, unsigned long start_addr,
		unsigned long end_addr, unsigned long *nr_accounted,
		struct zap_details *);
void clear_page_range(struct mmu_gather *tlb, unsigned long addr, unsigned long end);
int copy_page_range(struct mm_struct *dst, struct mm_struct *src,
			struct vm_area_struct *vma);
int zeromap_page_range(struct vm_area_struct *vma, unsigned long from,
			unsigned long size, pgprot_t prot);
void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows);

static inline void unmap_shared_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen)
{
	unmap_mapping_range(mapping, holebegin, holelen, 0);
}

extern int vmtruncate(struct inode * inode, loff_t offset);
extern pud_t *FASTCALL(__pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address));
extern pmd_t *FASTCALL(__pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address));
extern pte_t *FASTCALL(pte_alloc_kernel(struct mm_struct *mm, pmd_t *pmd, unsigned long address));
extern pte_t *FASTCALL(pte_alloc_map(struct mm_struct *mm, pmd_t *pmd, unsigned long address));
extern int install_page(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, struct page *page, pgprot_t prot);
extern int install_file_pte(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, unsigned long pgoff, pgprot_t prot);
extern int handle_mm_fault(struct mm_struct *mm,struct vm_area_struct *vma, unsigned long address, int write_access);
extern int make_pages_present(unsigned long addr, unsigned long end);
extern int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
void install_arg_page(struct vm_area_struct *, struct page *, unsigned long);

int get_user_pages(struct task_struct *tsk, struct mm_struct *mm, unsigned long start,
		int len, int write, int force, struct page **pages, struct vm_area_struct **vmas);

int __set_page_dirty_buffers(struct page *page);
int __set_page_dirty_nobuffers(struct page *page);
int redirty_page_for_writepage(struct writeback_control *wbc,
				struct page *page);
int FASTCALL(set_page_dirty(struct page *page));
int set_page_dirty_lock(struct page *page);
int clear_page_dirty_for_io(struct page *page);

extern unsigned long do_mremap(unsigned long addr,
			       unsigned long old_len, unsigned long new_len,
			       unsigned long flags, unsigned long new_addr);

/*
 * Prototype to add a shrinker callback for ageable caches.
 * 
 * These functions are passed a count `nr_to_scan' and a gfpmask.  They should
 * scan `nr_to_scan' objects, attempting to free them.
 *
 * The callback must the number of objects which remain in the cache.
 *
 * The callback will be passes nr_to_scan == 0 when the VM is querying the
 * cache size, so a fastpath for that case is appropriate.
 */
typedef int (*shrinker_t)(int nr_to_scan, unsigned int gfp_mask);

/*
 * Add an aging callback.  The int is the number of 'seeks' it takes
 * to recreate one of the objects that these functions age.
 */

#define DEFAULT_SEEKS 2
struct shrinker;
extern struct shrinker *set_shrinker(int, shrinker_t);
extern void remove_shrinker(struct shrinker *shrinker);

/*
 * On a two-level or three-level page table, this ends up being trivial. Thus
 * the inlining and the symmetry break with pte_alloc_map() that does all
 * of this out-of-line.
 */
/*
 * The following ifdef needed to get the 4level-fixup.h header to work.
 * Remove it when 4level-fixup.h has been removed.
 */
#ifdef CONFIG_MMU
#ifndef __ARCH_HAS_4LEVEL_HACK 
static inline pud_t *pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	if (pgd_none(*pgd))
		return __pud_alloc(mm, pgd, address);
	return pud_offset(pgd, address);
}

static inline pmd_t *pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	if (pud_none(*pud))
		return __pmd_alloc(mm, pud, address);
	return pmd_offset(pud, address);
}
#endif
#endif /* CONFIG_MMU */

extern void free_area_init(unsigned long * zones_size);
extern void free_area_init_node(int nid, pg_data_t *pgdat,
	unsigned long * zones_size, unsigned long zone_start_pfn, 
	unsigned long *zholes_size);
extern void memmap_init_zone(unsigned long, int, unsigned long, unsigned long);
extern void mem_init(void);
extern void show_mem(void);
extern void si_meminfo(struct sysinfo * val);
extern void si_meminfo_node(struct sysinfo *val, int nid);

/* prio_tree.c */
void vma_prio_tree_add(struct vm_area_struct *, struct vm_area_struct *old);
void vma_prio_tree_insert(struct vm_area_struct *, struct prio_tree_root *);
void vma_prio_tree_remove(struct vm_area_struct *, struct prio_tree_root *);
struct vm_area_struct *vma_prio_tree_next(struct vm_area_struct *vma,
	struct prio_tree_iter *iter);

/**
 * 在优先搜索树中搜索线性区。用于页面反向映射。
 */
#define vma_prio_tree_foreach(vma, iter, root, begin, end)	\
	for (prio_tree_iter_init(iter, root, begin, end), vma = NULL;	\
		(vma = vma_prio_tree_next(vma, iter)); )

static inline void vma_nonlinear_insert(struct vm_area_struct *vma,
					struct list_head *list)
{
	vma->shared.vm_set.parent = NULL;
	list_add_tail(&vma->shared.vm_set.list, list);
}

/* mmap.c */
extern int __vm_enough_memory(long pages, int cap_sys_admin);
extern void vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert);
extern struct vm_area_struct *vma_merge(struct mm_struct *,
	struct vm_area_struct *prev, unsigned long addr, unsigned long end,
	unsigned long vm_flags, struct anon_vma *, struct file *, pgoff_t,
	struct mempolicy *);
extern struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *);
extern int split_vma(struct mm_struct *,
	struct vm_area_struct *, unsigned long addr, int new_below);
extern int insert_vm_struct(struct mm_struct *, struct vm_area_struct *);
extern void __vma_link_rb(struct mm_struct *, struct vm_area_struct *,
	struct rb_node **, struct rb_node *);
extern struct vm_area_struct *copy_vma(struct vm_area_struct **,
	unsigned long addr, unsigned long len, pgoff_t pgoff);
extern void exit_mmap(struct mm_struct *);

extern unsigned long get_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);

extern unsigned long do_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff);

/**
 * 为当前进程创建并初始化一个新的线性区。
 * 分配成功后，可以把这个新的线性区与进程已有的其他线性区进行合并。
 * file,offset-如果新的线性区将把一个文件映射到内存，则使用文件描述符指针file和文件偏移量offset.当不需要内存映射时，file和offset都会为空
 * addr-这个线性地址指定从休息开始查找一个空闲的区间。
 * len-线性地址区间的长度。
 * prot-这个参数指定这个线性区所包含页的访问权限。可能的标志有PROT_READ,PROT_WRITE,PROT_EXEC和PROT_NONE.前三个标志与VM_READ,VM_WRITE,WM_EXEC一样。PROT_NONE表示没有以上权限中的任意一个
 * flag-这个参数指定线性区的其他标志。MAP_GROWSDOWN,MAP_LOCKED,MAP_DENYWRITE,MAP_EXECURABLE
 */
static inline unsigned long do_mmap(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long offset)
{
	unsigned long ret = -EINVAL;
	/**
	 * 首先检查是否溢出。
	 */
	if ((offset + PAGE_ALIGN(len)) < offset)
		goto out;
	/**
	 * 检查是否对齐页。
	 */
	if (!(offset & ~PAGE_MASK))
		ret = do_mmap_pgoff(file, addr, len, prot, flag, offset >> PAGE_SHIFT);
out:
	return ret;
}

extern int do_munmap(struct mm_struct *, unsigned long, size_t);

extern unsigned long do_brk(unsigned long, unsigned long);

/* filemap.c */
extern unsigned long page_unuse(struct page *);
extern void truncate_inode_pages(struct address_space *, loff_t);

/* generic vm_area_ops exported for stackable file systems */
extern struct page *filemap_nopage(struct vm_area_struct *, unsigned long, int *);
extern int filemap_populate(struct vm_area_struct *, unsigned long,
		unsigned long, pgprot_t, unsigned long, int);

/* mm/page-writeback.c */
int write_one_page(struct page *page, int wait);

/* readahead.c */
#define VM_MAX_READAHEAD	128	/* kbytes */
#define VM_MIN_READAHEAD	16	/* kbytes (includes current page) */
#define VM_MAX_CACHE_HIT    	256	/* max pages in a row in cache before
					 * turning readahead off */

int do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read);
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read);
unsigned long  page_cache_readahead(struct address_space *mapping,
			  struct file_ra_state *ra,
			  struct file *filp,
			  unsigned long offset,
			  unsigned long size);
void handle_ra_miss(struct address_space *mapping, 
		    struct file_ra_state *ra, pgoff_t offset);
unsigned long max_sane_readahead(unsigned long nr);

/* Do stack extension */
extern int expand_stack(struct vm_area_struct * vma, unsigned long address);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
extern struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr);
extern struct vm_area_struct * find_vma_prev(struct mm_struct * mm, unsigned long addr,
					     struct vm_area_struct **pprev);

/* Look up the first VMA which intersects the interval start_addr..end_addr-1,
   NULL if none.  Assume start_addr < end_addr. */
/**
 * find_vma_intersection函数查找与给定的线性地址区间相重叠的第一个线性区。
 * mm-进程的内存描述符。
 * start_addr-要查找的区间的起始地址。
 * end_addr-要查找的区间的结束地址。
 */
static inline struct vm_area_struct * find_vma_intersection(struct mm_struct * mm, unsigned long start_addr, unsigned long end_addr)
{
	struct vm_area_struct * vma = find_vma(mm,start_addr);

	/**
	 * 如果没有这样的线性区存在就返回NULL。
	 * 如果所找到的线性区是从地址区间的末尾开始的，也返回0.
	 */
	if (vma && end_addr <= vma->vm_start)
		vma = NULL;
	return vma;
}

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

extern struct vm_area_struct *find_extend_vma(struct mm_struct *mm, unsigned long addr);

extern struct page * vmalloc_to_page(void *addr);
extern unsigned long vmalloc_to_pfn(void *addr);
extern struct page * follow_page(struct mm_struct *mm, unsigned long address,
		int write);
extern int check_user_page_readable(struct mm_struct *mm, unsigned long address);
int remap_pfn_range(struct vm_area_struct *, unsigned long,
		unsigned long, unsigned long, pgprot_t);

#ifdef CONFIG_PROC_FS
void __vm_stat_account(struct mm_struct *, unsigned long, struct file *, long);
#else
static inline void __vm_stat_account(struct mm_struct *mm,
			unsigned long flags, struct file *file, long pages)
{
}
#endif /* CONFIG_PROC_FS */

static inline void vm_stat_account(struct vm_area_struct *vma)
{
	__vm_stat_account(vma->vm_mm, vma->vm_flags, vma->vm_file,
							vma_pages(vma));
}

static inline void vm_stat_unaccount(struct vm_area_struct *vma)
{
	__vm_stat_account(vma->vm_mm, vma->vm_flags, vma->vm_file,
							-vma_pages(vma));
}

/* update per process rss and vm hiwater data */
extern void update_mem_hiwater(void);

#ifndef CONFIG_DEBUG_PAGEALLOC
static inline void
kernel_map_pages(struct page *page, int numpages, int enable)
{
}
#endif

extern struct vm_area_struct *get_gate_vma(struct task_struct *tsk);
#ifdef	__HAVE_ARCH_GATE_AREA
int in_gate_area_no_task(unsigned long addr);
int in_gate_area(struct task_struct *task, unsigned long addr);
#else
int in_gate_area_no_task(unsigned long addr);
#define in_gate_area(task, addr) ({(void)task; in_gate_area_no_task(addr);})
#endif	/* __HAVE_ARCH_GATE_AREA */

#endif /* __KERNEL__ */
#endif /* _LINUX_MM_H */
