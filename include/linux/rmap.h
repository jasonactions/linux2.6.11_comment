#ifndef _LINUX_RMAP_H
#define _LINUX_RMAP_H
/*
 * Declarations for Reverse Mapping functions in mm/rmap.c
 */

#include <linux/config.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

/*
 * The anon_vma heads a list of private "related" vmas, to scan if
 * an anonymous page pointing to this anon_vma needs to be unmapped:
 * the vmas on the list will be related by forking, or by splitting.
 *
 * Since vmas come and go as they are split and merged (particularly
 * in mprotect), the mapping field of an anonymous page cannot point
 * directly to a vma: instead it points to an anon_vma, on whose list
 * the related vmas can be easily linked or unlinked.
 *
 * After unlinking the last vma on the list, we must garbage collect
 * the anon_vma object itself: we're guaranteed no page can be
 * pointing to this anon_vma once its vma list is empty.
 */
/**
 * 用于共享匿名页的反射映射。
 *		当创建新进程时，父进程的所有页框，包含匿名页，都同时分配给子进程。
 *		当进程创建线性区时，如果指定了MAP_ANONYMOUS和MAP_SHARED，则这个区域内的页将由该进程后面的子进程共享。
 * 当内核为一个匿名线性区分配第一页时，内核创建一个新的anon_vma数据结构。
 */
struct anon_vma {
	/**
	 * 保护本结构的锁。
	 */
	spinlock_t lock;	/* Serialize access to vma list */
	/**
	 * 线性区描述符双向循环链表的头部。
	 */ 
	struct list_head head;	/* List of private "related" vmas */
};

#ifdef CONFIG_MMU

extern kmem_cache_t *anon_vma_cachep;

static inline struct anon_vma *anon_vma_alloc(void)
{
	return kmem_cache_alloc(anon_vma_cachep, SLAB_KERNEL);
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
	kmem_cache_free(anon_vma_cachep, anon_vma);
}

static inline void anon_vma_lock(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	if (anon_vma)
		spin_lock(&anon_vma->lock);
}

static inline void anon_vma_unlock(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	if (anon_vma)
		spin_unlock(&anon_vma->lock);
}

/*
 * anon_vma helper functions.
 */
void anon_vma_init(void);	/* create anon_vma_cachep */
int  anon_vma_prepare(struct vm_area_struct *);
void __anon_vma_merge(struct vm_area_struct *, struct vm_area_struct *);
void anon_vma_unlink(struct vm_area_struct *);
void anon_vma_link(struct vm_area_struct *);
void __anon_vma_link(struct vm_area_struct *);

/*
 * rmap interfaces called when adding or removing pte of page
 */
void page_add_anon_rmap(struct page *, struct vm_area_struct *, unsigned long);
void page_add_file_rmap(struct page *);
void page_remove_rmap(struct page *);

/**
 * page_dup_rmap - duplicate pte mapping to a page
 * @page:	the page to add the mapping to
 *
 * For copy_page_range only: minimal extract from page_add_rmap,
 * avoiding unnecessary tests (already checked) so it's quicker.
 */
static inline void page_dup_rmap(struct page *page)
{
	atomic_inc(&page->_mapcount);
}

/*
 * Called from mm/vmscan.c to handle paging out
 */
int page_referenced(struct page *, int is_locked, int ignore_token);
int try_to_unmap(struct page *);

/*
 * Used by swapoff to help locate where page is expected in vma.
 */
unsigned long page_address_in_vma(struct page *, struct vm_area_struct *);

#else	/* !CONFIG_MMU */

#define anon_vma_init()		do {} while (0)
#define anon_vma_prepare(vma)	(0)
#define anon_vma_link(vma)	do {} while (0)

#define page_referenced(page,l,i) TestClearPageReferenced(page)
#define try_to_unmap(page)	SWAP_FAIL

#endif	/* CONFIG_MMU */

/*
 * Return values of try_to_unmap
 */
#define SWAP_SUCCESS	0
#define SWAP_AGAIN	1
#define SWAP_FAIL	2

#endif	/* _LINUX_RMAP_H */
