/*
 * mm/mmap.c
 *
 * Written by obz.
 *
 * Address space accounting code	<alan@redhat.com>
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/profile.h>
#include <linux/module.h>
#include <linux/acct.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>

/*
 * WARNING: the debugging will use recursive algorithms so never enable this
 * unless you know what you are doing.
 */
#undef DEBUG_MM_RB

/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type	prot
 *		PROT_NONE	PROT_READ	PROT_WRITE	PROT_EXEC
 * MAP_SHARED	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (yes) yes	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *		
 * MAP_PRIVATE	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (copy) copy	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 */
/**
 * 线性区的访问权限有16种组合，每种组合所对应的页的保护位存放在protection_map数组中。
 */
pgprot_t protection_map[16] = {
	__P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
	__S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111
};

int sysctl_overcommit_memory = OVERCOMMIT_GUESS;  /* heuristic overcommit */
int sysctl_overcommit_ratio = 50;	/* default is 50% */
int sysctl_max_map_count = DEFAULT_MAX_MAP_COUNT;
atomic_t vm_committed_space = ATOMIC_INIT(0);

/*
 * Check that a process has enough memory to allocate a new virtual
 * mapping. 0 means there is enough memory for the allocation to
 * succeed and -ENOMEM implies there is not.
 *
 * We currently support three overcommit policies, which are set via the
 * vm.overcommit_memory sysctl.  See Documentation/vm/overcommit-accounting
 *
 * Strict overcommit modes added 2002 Feb 26 by Alan Cox.
 * Additional code 2002 Jul 20 by Robert Love.
 *
 * cap_sys_admin is 1 if the process has admin privileges, 0 otherwise.
 *
 * Note this is a helper function intended to be used by LSMs which
 * wish to use this logic.
 */
/**
 * 检查是否有足够的空闲页框把交换区上存放的所有页换入。
 */
int __vm_enough_memory(long pages, int cap_sys_admin)
{
	unsigned long free, allowed;

	vm_acct_memory(pages);

	/*
	 * Sometimes we want to use more memory than we have
	 */
	if (sysctl_overcommit_memory == OVERCOMMIT_ALWAYS)
		return 0;

	if (sysctl_overcommit_memory == OVERCOMMIT_GUESS) {
		unsigned long n;

		free = get_page_cache_size();
		free += nr_swap_pages;

		/*
		 * Any slabs which are created with the
		 * SLAB_RECLAIM_ACCOUNT flag claim to have contents
		 * which are reclaimable, under pressure.  The dentry
		 * cache and most inode caches should fall into this
		 */
		free += atomic_read(&slab_reclaim_pages);

		/*
		 * Leave the last 3% for root
		 */
		if (!cap_sys_admin)
			free -= free / 32;

		if (free > pages)
			return 0;

		/*
		 * nr_free_pages() is very expensive on large systems,
		 * only call if we're about to fail.
		 */
		n = nr_free_pages();
		if (!cap_sys_admin)
			n -= n / 32;
		free += n;

		if (free > pages)
			return 0;
		vm_unacct_memory(pages);
		return -ENOMEM;
	}

	allowed = (totalram_pages - hugetlb_total_pages())
	       	* sysctl_overcommit_ratio / 100;
	/*
	 * Leave the last 3% for root
	 */
	if (!cap_sys_admin)
		allowed -= allowed / 32;
	allowed += total_swap_pages;

	/* Don't let a single process grow too big:
	   leave 3% of the size of this process for other processes */
	allowed -= current->mm->total_vm / 32;

	if (atomic_read(&vm_committed_space) < allowed)
		return 0;

	vm_unacct_memory(pages);

	return -ENOMEM;
}

EXPORT_SYMBOL(sysctl_overcommit_memory);
EXPORT_SYMBOL(sysctl_overcommit_ratio);
EXPORT_SYMBOL(sysctl_max_map_count);
EXPORT_SYMBOL(vm_committed_space);
EXPORT_SYMBOL(__vm_enough_memory);

/*
 * Requires inode->i_mapping->i_mmap_lock
 */
static void __remove_shared_vm_struct(struct vm_area_struct *vma,
		struct file *file, struct address_space *mapping)
{
	if (vma->vm_flags & VM_DENYWRITE)
		atomic_inc(&file->f_dentry->d_inode->i_writecount);
	if (vma->vm_flags & VM_SHARED)
		mapping->i_mmap_writable--;

	flush_dcache_mmap_lock(mapping);
	if (unlikely(vma->vm_flags & VM_NONLINEAR))
		list_del_init(&vma->shared.vm_set.list);
	else
		vma_prio_tree_remove(vma, &mapping->i_mmap);
	flush_dcache_mmap_unlock(mapping);
}

/*
 * Remove one vm structure and free it.
 */
static void remove_vm_struct(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;

	might_sleep();
	if (file) {
		struct address_space *mapping = file->f_mapping;
		spin_lock(&mapping->i_mmap_lock);
		__remove_shared_vm_struct(vma, file, mapping);
		spin_unlock(&mapping->i_mmap_lock);
	}
	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);
	if (file)
		fput(file);
	anon_vma_unlink(vma);
	mpol_free(vma_policy(vma));
	kmem_cache_free(vm_area_cachep, vma);
}

/*
 *  sys_brk() for the most part doesn't need the global kernel
 *  lock, except when an application is doing something nasty
 *  like trying to un-brk an area that has already been mapped
 *  to a regular file.  in this case, the unmapping will need
 *  to invoke file system routines that need the global lock.
 */
/**
 * brk系统调用的实现函数。
 */
asmlinkage unsigned long sys_brk(unsigned long brk)
{
	unsigned long rlim, retval;
	unsigned long newbrk, oldbrk;
	struct mm_struct *mm = current->mm;

	down_write(&mm->mmap_sem);

	/**
	 * 首先验证addr参数是否位于进程代码所在的线性区。
	 * 如果是，则立即返回。因为堆不能与进程代码所在的线性区重叠。
	 */
	if (brk < mm->end_code)
		goto out;
	/**
	 * 由于brk系统调用作用于某一个线性区，它分配和释放完整的页。
	 * 因此，把addr高速为PAGE_SIZE的整数倍。然后把调整的结束与内存描述符的brk字段的值进行比较。
	 */
	newbrk = PAGE_ALIGN(brk);
	oldbrk = PAGE_ALIGN(mm->brk);
	if (oldbrk == newbrk)
		goto set_brk;

	/* Always allow shrinking brk. */
	/**
	 * 如果是请求缩小堆，则调用do_munmap函数完成任务。并返回。
	 */
	if (brk <= mm->brk) {
		if (!do_munmap(mm, newbrk, oldbrk-newbrk))
			goto set_brk;
		goto out;
	}

	/* Check against rlimit.. */
	/**
	 * 如果是请求扩大堆，则首先检查是否允许进程这么做。
	 */
	rlim = current->signal->rlim[RLIMIT_DATA].rlim_cur;
	if (rlim < RLIM_INFINITY && brk - mm->start_data > rlim)
		goto out;

	/* Check against existing mmap mappings. */
	/**
	 * 然后检查扩大后的堆是否与进程其他线性区重叠。如果是，不做任何事情就返回。
	 */
	if (find_vma_intersection(mm, oldbrk, newbrk+PAGE_SIZE))
		goto out;

	/* Ok, looks good - let it rip. */
	/**
	 * 如果一切顺利，则调用do_brk函数。该函数其实是do_mmap的简化版。
	 * 如果它返回oldbrk，则分配成功且sys_brk返回addr的值，否则返回mm->brk值。
	 */
	if (do_brk(oldbrk, newbrk-oldbrk) != oldbrk)
		goto out;
set_brk:
	mm->brk = brk;
out:
	retval = mm->brk;
	up_write(&mm->mmap_sem);
	return retval;
}


#ifdef DEBUG_MM_RB
static int browse_rb(struct rb_root *root)
{
	int i = 0, j;
	struct rb_node *nd, *pn = NULL;
	unsigned long prev = 0, pend = 0;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		if (vma->vm_start < prev)
			printk("vm_start %lx prev %lx\n", vma->vm_start, prev), i = -1;
		if (vma->vm_start < pend)
			printk("vm_start %lx pend %lx\n", vma->vm_start, pend);
		if (vma->vm_start > vma->vm_end)
			printk("vm_end %lx < vm_start %lx\n", vma->vm_end, vma->vm_start);
		i++;
		pn = nd;
	}
	j = 0;
	for (nd = pn; nd; nd = rb_prev(nd)) {
		j++;
	}
	if (i != j)
		printk("backwards %d, forwards %d\n", j, i), i = 0;
	return i;
}

void validate_mm(struct mm_struct *mm)
{
	int bug = 0;
	int i = 0;
	struct vm_area_struct *tmp = mm->mmap;
	while (tmp) {
		tmp = tmp->vm_next;
		i++;
	}
	if (i != mm->map_count)
		printk("map_count %d vm_next %d\n", mm->map_count, i), bug = 1;
	i = browse_rb(&mm->mm_rb);
	if (i != mm->map_count)
		printk("map_count %d rb %d\n", mm->map_count, i), bug = 1;
	if (bug)
		BUG();
}
#else
#define validate_mm(mm) do { } while (0)
#endif

/**
 * 确定新里子节点在与给定线性地址对应的红黑树中的位置。并返回前一个线性区的地址和要插入的叶子节点的父节点的地址
 */
static struct vm_area_struct *
find_vma_prepare(struct mm_struct *mm, unsigned long addr,
		struct vm_area_struct **pprev, struct rb_node ***rb_link,
		struct rb_node ** rb_parent)
{
	struct vm_area_struct * vma;
	struct rb_node ** __rb_link, * __rb_parent, * rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;
	vma = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			vma = vma_tmp;
			if (vma_tmp->vm_start <= addr)
				return vma;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return vma;
}

static inline void
__vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	if (prev) {
		vma->vm_next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			vma->vm_next = rb_entry(rb_parent,
					struct vm_area_struct, vm_rb);
		else
			vma->vm_next = NULL;
	}
}

void __vma_link_rb(struct mm_struct *mm, struct vm_area_struct *vma,
		struct rb_node **rb_link, struct rb_node *rb_parent)
{
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);
	rb_insert_color(&vma->vm_rb, &mm->mm_rb);
}

static inline void __vma_link_file(struct vm_area_struct *vma)
{
	struct file * file;

	file = vma->vm_file;
	if (file) {
		struct address_space *mapping = file->f_mapping;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&file->f_dentry->d_inode->i_writecount);
		if (vma->vm_flags & VM_SHARED)
			mapping->i_mmap_writable++;

		flush_dcache_mmap_lock(mapping);
		if (unlikely(vma->vm_flags & VM_NONLINEAR))
			vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
		else
			vma_prio_tree_insert(vma, &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
	}
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	__anon_vma_link(vma);
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent)
{
	struct address_space *mapping = NULL;

	if (vma->vm_file)
		mapping = vma->vm_file->f_mapping;

	if (mapping) {
		spin_lock(&mapping->i_mmap_lock);
		vma->vm_truncate_count = mapping->truncate_count;
	}
	anon_vma_lock(vma);

	__vma_link(mm, vma, prev, rb_link, rb_parent);
	__vma_link_file(vma);

	anon_vma_unlock(vma);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	mm->map_count++;
	validate_mm(mm);
}

/*
 * Helper for vma_adjust in the split_vma insert case:
 * insert vm structure into list and rbtree and anon_vma,
 * but it has already been inserted into prio_tree earlier.
 */
static void
__insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	struct rb_node ** rb_link, * rb_parent;

	__vma = find_vma_prepare(mm, vma->vm_start,&prev, &rb_link, &rb_parent);
	if (__vma && __vma->vm_start < vma->vm_end)
		BUG();
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	mm->map_count++;
}

/**
 * 从内存描述符链表和红黑树中删除vma。
 *     mm-内存描述符的地址。
 *     vma,prev-两个线性区对象。都应当属于mm。prev应当在线性区的排序中位于vma之前。
 */
static inline void
__vma_unlink(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev)
{
	/**
	 * 在内存描述符链表中删除vma。
	 */
	prev->vm_next = vma->vm_next;
	/**
	 * 从红黑树中删除vma。
	 */
	rb_erase(&vma->vm_rb, &mm->mm_rb);
	/**
	 * 如果mmap_cache指向要被删除的线性区，就对其更新。
	 */
	if (mm->mmap_cache == vma)
		mm->mmap_cache = prev;
}

/*
 * We cannot adjust vm_start, vm_end, vm_pgoff fields of a vma that
 * is already present in an i_mmap tree without adjusting the tree.
 * The following helper function should be used when such adjustments
 * are necessary.  The "insert" vma (if any) is to be inserted
 * before we drop the necessary locks.
 */
void vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *next = vma->vm_next;
	struct vm_area_struct *importer = NULL;
	struct address_space *mapping = NULL;
	struct prio_tree_root *root = NULL;
	struct file *file = vma->vm_file;
	struct anon_vma *anon_vma = NULL;
	long adjust_next = 0;
	int remove_next = 0;

	if (next && !insert) {
		if (end >= next->vm_end) {
			/*
			 * vma expands, overlapping all the next, and
			 * perhaps the one after too (mprotect case 6).
			 */
again:			remove_next = 1 + (end > next->vm_end);
			end = next->vm_end;
			anon_vma = next->anon_vma;
			importer = vma;
		} else if (end > next->vm_start) {
			/*
			 * vma expands, overlapping part of the next:
			 * mprotect case 5 shifting the boundary up.
			 */
			adjust_next = (end - next->vm_start) >> PAGE_SHIFT;
			anon_vma = next->anon_vma;
			importer = vma;
		} else if (end < vma->vm_end) {
			/*
			 * vma shrinks, and !insert tells it's not
			 * split_vma inserting another: so it must be
			 * mprotect case 4 shifting the boundary down.
			 */
			adjust_next = - ((vma->vm_end - end) >> PAGE_SHIFT);
			anon_vma = next->anon_vma;
			importer = next;
		}
	}

	if (file) {
		mapping = file->f_mapping;
		if (!(vma->vm_flags & VM_NONLINEAR))
			root = &mapping->i_mmap;
		spin_lock(&mapping->i_mmap_lock);
		if (importer &&
		    vma->vm_truncate_count != next->vm_truncate_count) {
			/*
			 * unmap_mapping_range might be in progress:
			 * ensure that the expanding vma is rescanned.
			 */
			importer->vm_truncate_count = 0;
		}
		if (insert) {
			insert->vm_truncate_count = vma->vm_truncate_count;
			/*
			 * Put into prio_tree now, so instantiated pages
			 * are visible to arm/parisc __flush_dcache_page
			 * throughout; but we cannot insert into address
			 * space until vma start or end is updated.
			 */
			__vma_link_file(insert);
		}
	}

	/*
	 * When changing only vma->vm_end, we don't really need
	 * anon_vma lock: but is that case worth optimizing out?
	 */
	if (vma->anon_vma)
		anon_vma = vma->anon_vma;
	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		/*
		 * Easily overlooked: when mprotect shifts the boundary,
		 * make sure the expanding vma has anon_vma set if the
		 * shrinking vma had, to cover any anon pages imported.
		 */
		if (importer && !importer->anon_vma) {
			importer->anon_vma = anon_vma;
			__anon_vma_link(importer);
		}
	}

	if (root) {
		flush_dcache_mmap_lock(mapping);
		vma_prio_tree_remove(vma, root);
		if (adjust_next)
			vma_prio_tree_remove(next, root);
	}

	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_pgoff = pgoff;
	if (adjust_next) {
		next->vm_start += adjust_next << PAGE_SHIFT;
		next->vm_pgoff += adjust_next;
	}

	if (root) {
		if (adjust_next)
			vma_prio_tree_insert(next, root);
		vma_prio_tree_insert(vma, root);
		flush_dcache_mmap_unlock(mapping);
	}

	if (remove_next) {
		/*
		 * vma_merge has merged next into vma, and needs
		 * us to remove next before dropping the locks.
		 */
		__vma_unlink(mm, next, vma);
		if (file)
			__remove_shared_vm_struct(next, file, mapping);
		if (next->anon_vma)
			__anon_vma_merge(vma, next);
	} else if (insert) {
		/*
		 * split_vma has split insert from vma, and needs
		 * us to insert it before dropping the locks
		 * (it may either follow vma or precede it).
		 */
		__insert_vm_struct(mm, insert);
	}

	if (anon_vma)
		spin_unlock(&anon_vma->lock);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	if (remove_next) {
		if (file)
			fput(file);
		mm->map_count--;
		mpol_free(vma_policy(next));
		kmem_cache_free(vm_area_cachep, next);
		/*
		 * In mprotect's case 6 (see comments on vma_merge),
		 * we must remove another next too. It would clutter
		 * up the code too much to do both in one go.
		 */
		if (remove_next == 2) {
			next = vma->vm_next;
			goto again;
		}
	}

	validate_mm(mm);
}

/*
 * If the vma has a ->close operation then the driver probably needs to release
 * per-vma resources, so we don't attempt to merge those.
 */
#define VM_SPECIAL (VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_RESERVED)

static inline int is_mergeable_vma(struct vm_area_struct *vma,
			struct file *file, unsigned long vm_flags)
{
	if (vma->vm_flags != vm_flags)
		return 0;
	if (vma->vm_file != file)
		return 0;
	if (vma->vm_ops && vma->vm_ops->close)
		return 0;
	return 1;
}

static inline int is_mergeable_anon_vma(struct anon_vma *anon_vma1,
					struct anon_vma *anon_vma2)
{
	return !anon_vma1 || !anon_vma2 || (anon_vma1 == anon_vma2);
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * in front of (at a lower virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We don't check here for the merged mmap wrapping around the end of pagecache
 * indices (16TB on ia32) because do_mmap_pgoff() does not permit mmap's which
 * wrap, nor mmaps which cover the final page at index -1UL.
 */
static int
can_vma_merge_before(struct vm_area_struct *vma, unsigned long vm_flags,
	struct anon_vma *anon_vma, struct file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma)) {
		if (vma->vm_pgoff == vm_pgoff)
			return 1;
	}
	return 0;
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * beyond (at a higher virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 */
static int
can_vma_merge_after(struct vm_area_struct *vma, unsigned long vm_flags,
	struct anon_vma *anon_vma, struct file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma)) {
		pgoff_t vm_pglen;
		vm_pglen = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		if (vma->vm_pgoff + vm_pglen == vm_pgoff)
			return 1;
	}
	return 0;
}

/*
 * Given a mapping request (addr,end,vm_flags,file,pgoff), figure out
 * whether that can be merged with its predecessor or its successor.
 * Or both (it neatly fills a hole).
 *
 * In most cases - when called for mmap, brk or mremap - [addr,end) is
 * certain not to be mapped by the time vma_merge is called; but when
 * called for mprotect, it is certain to be already mapped (either at
 * an offset within prev, or at the start of next), and the flags of
 * this area are about to be changed to vm_flags - and the no-change
 * case has already been eliminated.
 *
 * The following mprotect cases have to be considered, where AAAA is
 * the area passed down from mprotect_fixup, never extending beyond one
 * vma, PPPPPP is the prev vma specified, and NNNNNN the next vma after:
 *
 *     AAAA             AAAA                AAAA          AAAA
 *    PPPPPPNNNNNN    PPPPPPNNNNNN    PPPPPPNNNNNN    PPPPNNNNXXXX
 *    cannot merge    might become    might become    might become
 *                    PPNNNNNNNNNN    PPPPPPPPPPNN    PPPPPPPPPPPP 6 or
 *    mmap, brk or    case 4 below    case 5 below    PPPPPPPPXXXX 7 or
 *    mremap move:                                    PPPPNNNNNNNN 8
 *        AAAA
 *    PPPP    NNNN    PPPPPPPPPPPP    PPPPPPPPNNNN    PPPPNNNNNNNN
 *    might become    case 1 below    case 2 below    case 3 below
 *
 * Odd one out? Case 8, because it extends NNNN but needs flags of XXXX:
 * mprotect_fixup updates vm_flags & vm_page_prot on successful return.
 */
struct vm_area_struct *vma_merge(struct mm_struct *mm,
			struct vm_area_struct *prev, unsigned long addr,
			unsigned long end, unsigned long vm_flags,
		     	struct anon_vma *anon_vma, struct file *file,
			pgoff_t pgoff, struct mempolicy *policy)
{
	pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
	struct vm_area_struct *area, *next;

	/*
	 * We later require that vma->vm_flags == vm_flags,
	 * so this tests vma->vm_flags & VM_SPECIAL, too.
	 */
	if (vm_flags & VM_SPECIAL)
		return NULL;

	if (prev)
		next = prev->vm_next;
	else
		next = mm->mmap;
	area = next;
	if (next && next->vm_end == end)		/* cases 6, 7, 8 */
		next = next->vm_next;

	/*
	 * Can it merge with the predecessor?
	 */
	if (prev && prev->vm_end == addr &&
  			mpol_equal(vma_policy(prev), policy) &&
			can_vma_merge_after(prev, vm_flags,
						anon_vma, file, pgoff)) {
		/*
		 * OK, it can.  Can we now merge in the successor as well?
		 */
		if (next && end == next->vm_start &&
				mpol_equal(policy, vma_policy(next)) &&
				can_vma_merge_before(next, vm_flags,
					anon_vma, file, pgoff+pglen) &&
				is_mergeable_anon_vma(prev->anon_vma,
						      next->anon_vma)) {
							/* cases 1, 6 */
			vma_adjust(prev, prev->vm_start,
				next->vm_end, prev->vm_pgoff, NULL);
		} else					/* cases 2, 5, 7 */
			vma_adjust(prev, prev->vm_start,
				end, prev->vm_pgoff, NULL);
		return prev;
	}

	/*
	 * Can this new request be merged in front of next?
	 */
	if (next && end == next->vm_start &&
 			mpol_equal(policy, vma_policy(next)) &&
			can_vma_merge_before(next, vm_flags,
					anon_vma, file, pgoff+pglen)) {
		if (prev && addr < prev->vm_end)	/* case 4 */
			vma_adjust(prev, prev->vm_start,
				addr, prev->vm_pgoff, NULL);
		else					/* cases 3, 8 */
			vma_adjust(area, addr, next->vm_end,
				next->vm_pgoff - pglen, NULL);
		return area;
	}

	return NULL;
}

/*
 * find_mergeable_anon_vma is used by anon_vma_prepare, to check
 * neighbouring vmas for a suitable anon_vma, before it goes off
 * to allocate a new anon_vma.  It checks because a repetitive
 * sequence of mprotects and faults may otherwise lead to distinct
 * anon_vmas being allocated, preventing vma merge in subsequent
 * mprotect.
 */
struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *near;
	unsigned long vm_flags;

	near = vma->vm_next;
	if (!near)
		goto try_prev;

	/*
	 * Since only mprotect tries to remerge vmas, match flags
	 * which might be mprotected into each other later on.
	 * Neither mlock nor madvise tries to remerge at present,
	 * so leave their flags as obstructing a merge.
	 */
	vm_flags = vma->vm_flags & ~(VM_READ|VM_WRITE|VM_EXEC);
	vm_flags |= near->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);

	if (near->anon_vma && vma->vm_end == near->vm_start &&
 			mpol_equal(vma_policy(vma), vma_policy(near)) &&
			can_vma_merge_before(near, vm_flags,
				NULL, vma->vm_file, vma->vm_pgoff +
				((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)))
		return near->anon_vma;
try_prev:
	/*
	 * It is potentially slow to have to call find_vma_prev here.
	 * But it's only on the first write fault on the vma, not
	 * every time, and we could devise a way to avoid it later
	 * (e.g. stash info in next's anon_vma_node when assigning
	 * an anon_vma, or when trying vma_merge).  Another time.
	 */
	if (find_vma_prev(vma->vm_mm, vma->vm_start, &near) != vma)
		BUG();
	if (!near)
		goto none;

	vm_flags = vma->vm_flags & ~(VM_READ|VM_WRITE|VM_EXEC);
	vm_flags |= near->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);

	if (near->anon_vma && near->vm_end == vma->vm_start &&
  			mpol_equal(vma_policy(near), vma_policy(vma)) &&
			can_vma_merge_after(near, vm_flags,
				NULL, vma->vm_file, vma->vm_pgoff))
		return near->anon_vma;
none:
	/*
	 * There's no absolute need to look only at touching neighbours:
	 * we could search further afield for "compatible" anon_vmas.
	 * But it would probably just be a waste of time searching,
	 * or lead to too many vmas hanging off the same anon_vma.
	 * We're trying to allow mprotect remerging later on,
	 * not trying to minimize memory used for anon_vmas.
	 */
	return NULL;
}

#ifdef CONFIG_PROC_FS
void __vm_stat_account(struct mm_struct *mm, unsigned long flags,
						struct file *file, long pages)
{
	const unsigned long stack_flags
		= VM_STACK_FLAGS & (VM_GROWSUP|VM_GROWSDOWN);

#ifdef CONFIG_HUGETLB
	if (flags & VM_HUGETLB) {
		if (!(flags & VM_DONTCOPY))
			mm->shared_vm += pages;
		return;
	}
#endif /* CONFIG_HUGETLB */

	if (file) {
		mm->shared_vm += pages;
		if ((flags & (VM_EXEC|VM_WRITE)) == VM_EXEC)
			mm->exec_vm += pages;
	} else if (flags & stack_flags)
		mm->stack_vm += pages;
	if (flags & (VM_RESERVED|VM_IO))
		mm->reserved_vm += pages;
}
#endif /* CONFIG_PROC_FS */

/*
 * The caller must hold down_write(current->mm->mmap_sem).
 */
/**
 * do_mmap的辅助函数。
 */
unsigned long do_mmap_pgoff(struct file * file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, unsigned long pgoff)
{
	struct mm_struct * mm = current->mm;
	struct vm_area_struct * vma, * prev;
	struct inode *inode;
	unsigned int vm_flags;
	int correct_wcount = 0;
	int error;
	struct rb_node ** rb_link, * rb_parent;
	int accountable = 1;
	unsigned long charged = 0;

	if (file) {
		if (is_file_hugepages(file))
			accountable = 0;

		/**
		 * 检查是否为要映射的文件定义了mmap文件操作。如果没有，就返回一个错误码。
		 * 如果文件操作表的mmap为NULL说明相应的文件不能被映射(例如，这是一个目录).
		 */
		if (!file->f_op || !file->f_op->mmap)
			return -ENODEV;

		if ((prot & PROT_EXEC) &&
		    (file->f_vfsmnt->mnt_flags & MNT_NOEXEC))
			return -EPERM;
	}
	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC?
	 *
	 * (the exception is when the underlying filesystem is noexec
	 *  mounted, in which case we dont add PROT_EXEC.)
	 */
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && (file->f_vfsmnt->mnt_flags & MNT_NOEXEC)))
			prot |= PROT_EXEC;

	/**
	 * 检查长度为0
	 */
	if (!len)
		return addr;

	/* Careful about overflows.. */
	/**
	 * 检查包含的地址大于TASK_SIZE
	 */
	len = PAGE_ALIGN(len);
	if (!len || len > TASK_SIZE)
		return -EINVAL;

	/* offset overflow? */
	/**
	 * 是否越界了
	 */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EINVAL;

	/* Too many mappings? */
	/**
	 * 进程映射了过多的线性区。
	 */
	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	/**
	 * get_unmapped_area获得新线性区的线性地址区间。
	 * 这个函数可能会调用文件对象的get_unapped_area方法。
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
	if (addr & ~PAGE_MASK)
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	/**
	 * 通过prot和flag计算新线性区描述符的标志。
	 * mm->def_flags是线性区的默认标志。它只能由mlockall系统调用修改。这个调用可以设置VM_LOCKED标志。由此锁住以后申请的RAM中的有页。
	 */
	vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	/**
	 * flag参数指定新线性区地址区间的页必须被锁在RAM中，但不允许进程创建上锁的线性区
	 */
	if (flags & MAP_LOCKED) {
		if (!can_do_mlock())
			return -EPERM;
		vm_flags |= VM_LOCKED;
	}
	/* mlock MCL_FUTURE? */
	/**
	 * 或者进程加锁页的总数超过了保存在进程描述符的rlim[RLIMIT_MEMLOCK].rlim_cur字段中的值。
	 * 也直接返回错误。
	 */
	if (vm_flags & VM_LOCKED) {
		unsigned long locked, lock_limit;
		locked = mm->locked_vm << PAGE_SHIFT;
		lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
		locked += len;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return -EAGAIN;
	}

	inode = file ? file->f_dentry->d_inode : NULL;

	if (file) {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			/**
			 * 如果请求一个共享可写的内存映射，就检查文件是否为写入而打开的。
			 */
			if ((prot&PROT_WRITE) && !(file->f_mode&FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure we don't allow writing to an append-only
			 * file..
			 */
			/**
			 * 如果节点仅仅允许追加写，但是文件以写方式打开，则返回错误。
			 */
			if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure there are no mandatory locks on the file.
			 */
			/**
			 * 如果请求一个共享内存映射，就检查文件上没有强制锁。
			 */
			if (locks_verify_locked(inode))
				return -EAGAIN;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			/**
			 * 如果文件没有写权限，那么相应的线性区也不会有写权限。
			 */
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);

			/* fall through */
			/**
			 * 此处没有调用break，也就是说，即便是共享映射，也要进行下面的映射。
			 */
		case MAP_PRIVATE:
			/**
			 * 不论是共享映射还是私有映射，都要检查文件的读权限。
			 */
			if (!(file->f_mode & FMODE_READ))
				return -EACCES;
			break;

		default:
			return -EINVAL;
		}
	} else {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			vm_flags |= VM_SHARED | VM_MAYSHARE;
			break;
		case MAP_PRIVATE:
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}

	error = security_file_mmap(file, prot, flags);
	if (error)
		return error;
		
	/* Clear old maps */
	error = -ENOMEM;
munmap_back:
	/**
	 * find_vma_prepare确定处于新区间前的线性区对象的位置，以及在红黑树中新线性区的位置。
	 */
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	/**
	 * 检查是否还存在与新区间重叠的线性区。
	 */
	if (vma && vma->vm_start < addr + len) {
		/**
		 * 重叠了，就调用do_munmap删除新的线性区，然后重复整个步骤。
		 */
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limit. */
	/**
	 * 检查进程地址空间的大小mm->total_vm << PAGE_SHIFT) + len是否超过允许的值。
	 * 此检查不能被提前，因为上一步分配的线性区可能和已有线性区重叠，不能被加入线性区链表。
	 */
	if ((mm->total_vm << PAGE_SHIFT) + len
	    > current->signal->rlim[RLIMIT_AS].rlim_cur)
		return -ENOMEM;

	/**
	 * 没有MAP_NORESERVE表示需要检查空闲页框的数目。
	 */
	if (accountable && (!(flags & MAP_NORESERVE) ||
			    sysctl_overcommit_memory == OVERCOMMIT_NEVER)) {
		if (vm_flags & VM_SHARED) {
			/* Check memory availability in shmem_file_setup? */
			vm_flags |= VM_ACCOUNT;
		} else if (vm_flags & VM_WRITE) {
			/*
			 * Private writable mapping: check memory availability
			 */
			/**
			 * 需要检查空闲页框数目，并且新的线性区是私有可写页
			 */
			charged = len >> PAGE_SHIFT;
			/**
			 * 如果没有足够的空闲页框，就返回ENOMEM
			 */
			if (security_vm_enough_memory(charged))
				return -ENOMEM;
			vm_flags |= VM_ACCOUNT;
		}
	}

	/*
	 * Can we just expand an old private anonymous mapping?
	 * The VM_SHARED test is necessary because shmem_zero_setup
	 * will create the file object for a shared anonymous map below.
	 */
	/**
	 * 不是文件映射，并且新区间是私有的，那么就调用vma_merge
	 * 它会检查前一个线性区是否可扩展，以包含新区间。
	 * 当新区间正好是两个区间之间的空洞时，它会将三个区间合并起来。
	 */
	if (!file && !(vm_flags & VM_SHARED) &&
	    vma_merge(mm, prev, addr, addr + len, vm_flags,
					NULL, NULL, pgoff, NULL))
		goto out;

	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	/**
	 * 运行到此，说明没有发生线性区合并。
	 * 首先调用kmem_cache_alloc为新的线性区分配一个vm_area_struct
	 */
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}
	/**
	 * 初始化新vma对象。
	 */
	memset(vma, 0, sizeof(*vma));

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = protection_map[vm_flags & 0x0f];
	vma->vm_pgoff = pgoff;

	if (file) {
		error = -EINVAL;
		if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
			goto free_vma;
		if (vm_flags & VM_DENYWRITE) {
			error = deny_write_access(file);
			if (error)
				goto free_vma;
			correct_wcount = 1;
		}
		/**
		 * 用文件对象的地址初始化线性区描述符的vm_file字段，并增加文件的引用计数。
		 */
		vma->vm_file = file;
		get_file(file);
		/**
		 * 对映射的文件调用mmap方法，对于大多数文件系统，该方法由generic_file_mmap实现。它执行以下步骤:
		 *     将当前时间赋给文件索引节点对象的i_atime字段，并将该索引节点标记为脏。
		 *     用generic_file_vm_ops表的地址初始化线性区描述符的vm_ops字段，在这个表中的方法，除了nopage和populate方法外，其他所有都为空。
		 *          其中nopage方法由filemap_nopage实现，而populate方法由filemap_populate实现。
		 */
		error = file->f_op->mmap(file, vma);
		if (error)
			goto unmap_and_free_vma;
	} else if (vm_flags & VM_SHARED) {
		/**
		 * 新线性区有VM_SHARED标志，又不是映射磁盘上的文件。则该线性区是一个共享匿名区。
		 * shmem_zero_setup对它进行初始化。共享匿名区主要用于进程间通信。
		 */
		error = shmem_zero_setup(vma);
		if (error)
			goto free_vma;
	}

	/* We set VM_ACCOUNT in a shared mapping's vm_flags, to inform
	 * shmem_zero_setup (perhaps called through /dev/zero's ->mmap)
	 * that memory reservation must be checked; but that reservation
	 * belongs to shared memory object, not to vma: so now clear it.
	 */
	if ((vm_flags & (VM_SHARED|VM_ACCOUNT)) == (VM_SHARED|VM_ACCOUNT))
		vma->vm_flags &= ~VM_ACCOUNT;

	/* Can addr have changed??
	 *
	 * Answer: Yes, several device drivers can do it in their
	 *         f_op->mmap method. -DaveM
	 */
	addr = vma->vm_start;
	pgoff = vma->vm_pgoff;
	vm_flags = vma->vm_flags;

	if (!file || !vma_merge(mm, prev, addr, vma->vm_end,
			vma->vm_flags, NULL, file, pgoff, vma_policy(vma))) {
		file = vma->vm_file;
		/**
		 * vma_link将新线性区插入到线性区链表和红黑树中。
		 */
		vma_link(mm, vma, prev, rb_link, rb_parent);
		if (correct_wcount)
			atomic_inc(&inode->i_writecount);
	} else {
		if (file) {
			/**
			 * 增加文件索引节点对象的i_writecount
			 */
			if (correct_wcount)
				atomic_inc(&inode->i_writecount);
			fput(file);
		}
		mpol_free(vma_policy(vma));
		kmem_cache_free(vm_area_cachep, vma);
	}
out:	
	/**
	 * 增加进程地址空间的大小。
	 */
	mm->total_vm += len >> PAGE_SHIFT;
	__vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT);
	/**
	 * VM_LOCKED标志被设置，就调用make_pages_present连续分配线性区的所有页，并将所有页锁在RAM中。
	 */
	if (vm_flags & VM_LOCKED) {
		mm->locked_vm += len >> PAGE_SHIFT;
		/**
		 * make_pages_present在所有页上循环，对其中每个页，调用follow_page检查当前页表中是否有到物理页的映射。
		 * 如果没有这样的页存在，就调用handle_mm_fault。这个函数分配一个页框并根据内存描述符的vm_flags字段设置它的页表项。
		 */
		make_pages_present(addr, addr + len);
	}
	if (flags & MAP_POPULATE) {
		up_write(&mm->mmap_sem);
		sys_remap_file_pages(addr, len, 0,
					pgoff, flags & MAP_NONBLOCK);
		down_write(&mm->mmap_sem);
	}
	acct_update_integrals();
	update_mem_hiwater();
	return addr;

unmap_and_free_vma:
	if (correct_wcount)
		atomic_inc(&inode->i_writecount);
	vma->vm_file = NULL;
	fput(file);

	/* Undo any partial mapping done by a device driver. */
	zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start, NULL);
free_vma:
	kmem_cache_free(vm_area_cachep, vma);
unacct_error:
	if (charged)
		vm_unacct_memory(charged);
	return error;
}

EXPORT_SYMBOL(do_mmap_pgoff);

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
#ifndef HAVE_ARCH_UNMAPPED_AREA
/**
 * 分配从低端地址向高端地址移动的线性区(xie.baoyou注：如堆而不是栈)
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;

	/**
	 * 当然了，只要是普通进程地址，就不能超过TASK_SIZE(一般就是3G)
	 */
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (addr) {
		/**
		 * 如果地址不是0，就从addr处开始分配
		 * 当然，需要将addr按4K取整
		 */
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		/**
		 * TASK_SIZE - len >= addr而不是addr + len <= TASK_SIZE
		 */
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;/* 没有被映射，这块区间可以使用。 */
	}

	/**
	 * 如果addr==0或者前面的搜索失败
	 * 从free_area_cache开始搜索，这个值初始为用户态空间的1/3处（即1G处），它也是为正文段、数据段、BSS段保留的
	 */
	start_addr = addr = mm->free_area_cache;

full_search:
	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			/**
			 * 没有找到，从TASK_UNMAPPED_BASE(1G)处开始找
			 */
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = addr = TASK_UNMAPPED_BASE;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			/**
			 * 找到了，记下本次找到的地方，下次从addr+len处开始找
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		addr = vma->vm_end;
	}
}
#endif	

void arch_unmap_area(struct vm_area_struct *area)
{
	/*
	 * Is this a new hole at the lowest possible address?
	 */
	if (area->vm_start >= TASK_UNMAPPED_BASE &&
			area->vm_start < area->vm_mm->free_area_cache)
		area->vm_mm->free_area_cache = area->vm_start;
}

/*
 * This mmap-allocator allocates new areas top-down from below the
 * stack's low limit (the base):
 */
#ifndef HAVE_ARCH_UNMAPPED_AREA_TOPDOWN
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma, *prev_vma;
	struct mm_struct *mm = current->mm;
	unsigned long base = mm->mmap_base, addr = addr0;
	int first_time = 1;

	/* requested length too big for entire address space */
	if (len > TASK_SIZE)
		return -ENOMEM;

	/* dont allow allocations above current base */
	if (mm->free_area_cache > base)
		mm->free_area_cache = base;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

try_again:
	/* make sure it can fit in the remaining address space */
	if (mm->free_area_cache < len)
		goto fail;

	/* either no address requested or cant fit in requested address hole */
	addr = (mm->free_area_cache - len) & PAGE_MASK;
	do {
		/*
		 * Lookup failure means no vma is above this address,
		 * i.e. return with success:
		 */
 	 	if (!(vma = find_vma_prev(mm, addr, &prev_vma)))
			return addr;

		/*
		 * new region fits between prev_vma->vm_end and
		 * vma->vm_start, use it:
		 */
		if (addr+len <= vma->vm_start &&
				(!prev_vma || (addr >= prev_vma->vm_end)))
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr);
		else
			/* pull free_area_cache down to the first hole */
			if (mm->free_area_cache == vma->vm_end)
				mm->free_area_cache = vma->vm_start;

		/* try just below the current vma->vm_start */
		addr = vma->vm_start-len;
	} while (len <= vma->vm_start);

fail:
	/*
	 * if hint left us with no space for the requested
	 * mapping then try again:
	 */
	if (first_time) {
		mm->free_area_cache = base;
		first_time = 0;
		goto try_again;
	}
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	mm->free_area_cache = TASK_UNMAPPED_BASE;
	addr = arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
	/*
	 * Restore the topdown base:
	 */
	mm->free_area_cache = base;

	return addr;
}
#endif

void arch_unmap_area_topdown(struct vm_area_struct *area)
{
	/*
	 * Is this a new hole at the highest possible address?
	 */
	if (area->vm_end > area->vm_mm->free_area_cache)
		area->vm_mm->free_area_cache = area->vm_end;
}

/**
 * 搜索进程的地址空间以找到一个可以使用的线性地址区间。
 * len-区间的长度。
 * addr-指定必须从哪个地址开始进行查找。如果查找成功，函数返回这个新区间的起始地址。否则返回错误码-ENOMEM.
 */
unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	if (flags & MAP_FIXED) {
		unsigned long ret;

		/**
		 * 如果addr不等于0,就检查指定的地址是否在用户态空间。
		 * 这是为了避免用户态程序绕过安全检查而影响内核地址空间。
		 */
		if (addr > TASK_SIZE - len)
			return -ENOMEM;
		/**
		 * 检查是否与页边界对齐。
		 */
		if (addr & ~PAGE_MASK)
			return -EINVAL;

		if (file && is_file_hugepages(file))  {
			/*
			 * Check if the given range is hugepage aligned, and
			 * can be made suitable for hugepages.
			 */
			ret = prepare_hugepage_range(addr, len);
		} else {
			/*
			 * Ensure that a normal request is not falling in a
			 * reserved hugepage range.  For some archs like IA-64,
			 * there is a separate region for hugepages.
			 */
			ret = is_hugepage_only_range(addr, len);
		}
		if (ret)
			return -EINVAL;
		return addr;
	}

	/**
	 * 检查线性地址区间是否应该用于文件内存映射或匿名内存映射。
	 * 分别调用文件和内存的get_unmapped_area操作。
	 */
	if (file && file->f_op && file->f_op->get_unmapped_area)
		return file->f_op->get_unmapped_area(file, addr, len,
						pgoff, flags);

	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

EXPORT_SYMBOL(get_unmapped_area);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
/**
 * 查找给定地址的最邻近区。
 * 它查找线性区的vm_end字段大于addr的第一个线性区的位置。并返回这个线性区描述符的地址。
 * 如果没有这样的线性区存在，就返回NULL。
 * 由find_vma函数所选择的线性区并不一定要包含addr，因为addr可能位于任何线性区之外。
 *     mm-进程内存描述符地址
 *     addr-线性地址。
 */
struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct *vma = NULL;

	if (mm) {
		/* Check the cache first. */
		/* (Cache hit rate is typically around 35%.) */
		/**
		 * mmap_cache指向最后一个引用的线性区对象。
		 * 引入这个附加的字段是为了减少查找一个给定线性地址所在线性区而花费的时间。
		 * 程序中引用地址的局部性使这种情况出现的可能性非常大:
		 *    如果检查的最后一个线性地址属于某一给定的线性区。那么下一个要检查的线性地址也属于这一个线性区。
		 */
		vma = mm->mmap_cache;
		/**
		 * 首先检查mmap_cache指定的线性区是否包含addr，如果是就返回这个线性区描述符的指针。
		 */
		if (!(vma && vma->vm_end > addr && vma->vm_start <= addr)) {
			/**
			 * 进入这里，说明mmap_cache中没有包含addr。就扫描进程的线性区。并在红黑树中查找线性区。
			 */
			struct rb_node * rb_node;

			rb_node = mm->mm_rb.rb_node;
			vma = NULL;

			while (rb_node) {
				struct vm_area_struct * vma_tmp;

				/**
				 * rb_entry从指向红黑树中一个节点的指针导出相应线性区描述符的指针。
				 */
				vma_tmp = rb_entry(rb_node,
						struct vm_area_struct, vm_rb);

				/**
				 * 视情况在左右子树中查找。
				 */
				if (vma_tmp->vm_end > addr) {
					vma = vma_tmp;
					/**
					 * 当前线性区包含addr,退出循环并返回vma.
					 */
					if (vma_tmp->vm_start <= addr)
						break;
					/**
					 * 否则在左子树中继续
					 */
					rb_node = rb_node->rb_left;
				} else/* 在右子树中继续 */
					rb_node = rb_node->rb_right;
			}
			/**
			 * 如果有必要，记录下mmap_cache。这样，下次就从mmap_cache继续查找。
			 */
			if (vma)
				mm->mmap_cache = vma;
		}
	}
	return vma;
}

EXPORT_SYMBOL(find_vma);

/* Same as find_vma, but also return a pointer to the previous VMA in *pprev. */
/**
 * 与find_vma类似，不同的是它把函数选中的前一个线性区描述符的指针赋给附加参数ppre。
 */
struct vm_area_struct *
find_vma_prev(struct mm_struct *mm, unsigned long addr,
			struct vm_area_struct **pprev)
{
	struct vm_area_struct *vma = NULL, *prev = NULL;
	struct rb_node * rb_node;
	if (!mm)
		goto out;

	/* Guard against addr being lower than the first VMA */
	vma = mm->mmap;

	/* Go through the RB tree quickly. */
	rb_node = mm->mm_rb.rb_node;

	while (rb_node) {
		struct vm_area_struct *vma_tmp;
		vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

		if (addr < vma_tmp->vm_end) {
			rb_node = rb_node->rb_left;
		} else {
			prev = vma_tmp;
			if (!prev->vm_next || (addr < prev->vm_next->vm_end))
				break;
			rb_node = rb_node->rb_right;
		}
	}

out:
	*pprev = prev;
	return prev ? prev->vm_next : vma;
}

/*
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 */
static int acct_stack_growth(struct vm_area_struct * vma, unsigned long size, unsigned long grow)
{
	struct mm_struct *mm = vma->vm_mm;
	struct rlimit *rlim = current->signal->rlim;

	/* address space limit tests */
	if (mm->total_vm + grow > rlim[RLIMIT_AS].rlim_cur >> PAGE_SHIFT)
		return -ENOMEM;

	/* Stack limit test */
	if (size > rlim[RLIMIT_STACK].rlim_cur)
		return -ENOMEM;

	/* mlock limit tests */
	if (vma->vm_flags & VM_LOCKED) {
		unsigned long locked;
		unsigned long limit;
		locked = mm->locked_vm + grow;
		limit = rlim[RLIMIT_MEMLOCK].rlim_cur >> PAGE_SHIFT;
		if (locked > limit && !capable(CAP_IPC_LOCK))
			return -ENOMEM;
	}

	/*
	 * Overcommit..  This must be the final test, as it will
	 * update security statistics.
	 */
	if (security_vm_enough_memory(grow))
		return -ENOMEM;

	/* Ok, everything looks good - let it rip */
	mm->total_vm += grow;
	if (vma->vm_flags & VM_LOCKED)
		mm->locked_vm += grow;
	__vm_stat_account(mm, vma->vm_flags, vma->vm_file, grow);
	acct_update_integrals();
	update_mem_hiwater();
	return 0;
}

#ifdef CONFIG_STACK_GROWSUP
/*
 * vma is the first one with address > vma->vm_end.  Have to extend vma.
 */
int expand_stack(struct vm_area_struct * vma, unsigned long address)
{
	int error;

	if (!(vma->vm_flags & VM_GROWSUP))
		return -EFAULT;

	/*
	 * We must make sure the anon_vma is allocated
	 * so that the anon_vma locking is not a noop.
	 */
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;
	anon_vma_lock(vma);

	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_sem in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 */
	address += 4 + PAGE_SIZE - 1;
	address &= PAGE_MASK;
	error = 0;

	/* Somebody else might have raced and expanded it already */
	if (address > vma->vm_end) {
		unsigned long size, grow;

		size = address - vma->vm_start;
		grow = (address - vma->vm_end) >> PAGE_SHIFT;

		error = acct_stack_growth(vma, size, grow);
		if (!error)
			vma->vm_end = address;
	}
	anon_vma_unlock(vma);
	return error;
}

struct vm_area_struct *
find_extend_vma(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma, *prev;

	addr &= PAGE_MASK;
	vma = find_vma_prev(mm, addr, &prev);
	if (vma && (vma->vm_start <= addr))
		return vma;
	if (!prev || expand_stack(prev, addr))
		return NULL;
	if (prev->vm_flags & VM_LOCKED) {
		make_pages_present(addr, prev->vm_end);
	}
	return prev;
}
#else
/*
 * vma is the first one with address < vma->vm_start.  Have to extend vma.
 */
/**
 * 当进程操作堆栈时，遇到地址访问错误，那么，将调用本过程，扩展用户态程序的堆栈空间。
 */
int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
	int error;

	/*
	 * We must make sure the anon_vma is allocated
	 * so that the anon_vma locking is not a noop.
	 */
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;
	anon_vma_lock(vma);

	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_sem in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 */
	address &= PAGE_MASK;
	error = 0;

	/* Somebody else might have raced and expanded it already */
	if (address < vma->vm_start) {
		unsigned long size, grow;

		size = vma->vm_end - address;
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = acct_stack_growth(vma, size, grow);
		if (!error) {
			vma->vm_start = address;
			vma->vm_pgoff -= grow;
		}
	}
	anon_vma_unlock(vma);
	return error;
}

struct vm_area_struct *
find_extend_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct * vma;
	unsigned long start;

	addr &= PAGE_MASK;
	vma = find_vma(mm,addr);
	if (!vma)
		return NULL;
	if (vma->vm_start <= addr)
		return vma;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		return NULL;
	start = vma->vm_start;
	if (expand_stack(vma, addr))
		return NULL;
	if (vma->vm_flags & VM_LOCKED) {
		make_pages_present(addr, start);
	}
	return vma;
}
#endif

/*
 * Try to free as many page directory entries as we can,
 * without having to work very hard at actually scanning
 * the page tables themselves.
 *
 * Right now we try to free page tables if we have a nice
 * PGDIR-aligned area that got free'd up. We could be more
 * granular if we want to, but this is fast and simple,
 * and covers the bad cases.
 *
 * "prev", if it exists, points to a vma before the one
 * we just free'd - but there's no telling how much before.
 */
static void free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *prev,
	unsigned long start, unsigned long end)
{
	unsigned long first = start & PGDIR_MASK;
	unsigned long last = end + PGDIR_SIZE - 1;
	struct mm_struct *mm = tlb->mm;

	if (last > MM_VM_SIZE(mm) || last < end)
		last = MM_VM_SIZE(mm);

	if (!prev) {
		prev = mm->mmap;
		if (!prev)
			goto no_mmaps;
		if (prev->vm_end > start) {
			if (last > prev->vm_start)
				last = prev->vm_start;
			goto no_mmaps;
		}
	}
	for (;;) {
		struct vm_area_struct *next = prev->vm_next;

		if (next) {
			if (next->vm_start < start) {
				prev = next;
				continue;
			}
			if (last > next->vm_start)
				last = next->vm_start;
		}
		if (prev->vm_end > first)
			first = prev->vm_end;
		break;
	}
no_mmaps:
	if (last < first)	/* for arches with discontiguous pgd indices */
		return;
	if (first < FIRST_USER_PGD_NR * PGDIR_SIZE)
		first = FIRST_USER_PGD_NR * PGDIR_SIZE;
	/* No point trying to free anything if we're in the same pte page */
	if ((first & PMD_MASK) < (last & PMD_MASK)) {
		clear_page_range(tlb, first, last);
		flush_tlb_pgtables(mm, first, last);
	}
}

/* Normal function to fix up a mapping
 * This function is the default for when an area has no specific
 * function.  This may be used as part of a more specific routine.
 *
 * By the time this function is called, the area struct has been
 * removed from the process mapping list.
 */
static void unmap_vma(struct mm_struct *mm, struct vm_area_struct *area)
{
	size_t len = area->vm_end - area->vm_start;

	area->vm_mm->total_vm -= len >> PAGE_SHIFT;
	if (area->vm_flags & VM_LOCKED)
		area->vm_mm->locked_vm -= len >> PAGE_SHIFT;
	vm_stat_unaccount(area);
	area->vm_mm->unmap_area(area);
	remove_vm_struct(area);
}

/*
 * Update the VMA and inode share lists.
 *
 * Ok - we have the memory areas we should free on the 'free' list,
 * so release them, and do the vma updates.
 */
static void unmap_vma_list(struct mm_struct *mm,
	struct vm_area_struct *mpnt)
{
	do {
		struct vm_area_struct *next = mpnt->vm_next;
		unmap_vma(mm, mpnt);
		mpnt = next;
	} while (mpnt != NULL);
	validate_mm(mm);
}

/*
 * Get rid of page table information in the indicated region.
 *
 * Called with the page table lock held.
 */
/**
 * 遍历线性区链表并释放它们的页框。
 * mm-内存描述符指针
 * vma-指向第一个被删除线性区描述符的指针。
 * prev-指向vma前面的线性区的指针。
 * start,end-界定被删除线性地址区间的范围。
 */
static void unmap_region(struct mm_struct *mm,
	struct vm_area_struct *vma,
	struct vm_area_struct *prev,
	unsigned long start,
	unsigned long end)
{
	struct mmu_gather *tlb;
	unsigned long nr_accounted = 0;

	lru_add_drain();
	/**
	 * tlb_gather_mmu初始化每CPU变量mmu_gathers。mmu_gather的值依赖于体系结构。
	 * 通常该变量应该存放成功更新进程页表项所需要的所有信息。
	 * 在x86中，该函数只是简单地把内存描述符指针mm的值赋给本地CPU的mmu_gather变量
	 */
	tlb = tlb_gather_mmu(mm, 0);
	/**
	 * 调用unmap_vmas扫描线性地址空间的所有页表项。
	 * 如果只有一个CPU，就调用free_swap_and_cache反复释放相应的页。
	 */
	unmap_vmas(&tlb, mm, vma, start, end, &nr_accounted, NULL);
	vm_unacct_memory(nr_accounted);

	/**
	 * free_pgtables回收已经清空的进程页表。
	 */
	if (is_hugepage_only_range(start, end - start))
		hugetlb_free_pgtables(tlb, prev, start, end);
	else
		free_pgtables(tlb, prev, start, end);
	/**
	 * 刷新TLB
	 */
	tlb_finish_mmu(tlb, start, end);
}

/*
 * Create a list of vma's touched by the unmap, removing them from the mm's
 * vma list as we go..
 */
/**
 * 从进程的线性地址空间中删除位于线性地址区间中的线性区。
 * 要删除的线性区的描述放在一个排好序的链表中，局部变量mpnt指向
 * 该链表的头。
 */
static void
detach_vmas_to_be_unmapped(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, unsigned long end)
{
	struct vm_area_struct **insertion_point;
	struct vm_area_struct *tail_vma = NULL;

	insertion_point = (prev ? &prev->vm_next : &mm->mmap);
	do {
		rb_erase(&vma->vm_rb, &mm->mm_rb);
		mm->map_count--;
		tail_vma = vma;
		vma = vma->vm_next;
	} while (vma && vma->vm_start < end);
	*insertion_point = vma;
	tail_vma->vm_next = NULL;
	mm->mmap_cache = NULL;		/* Kill the cache. */
}

/*
 * Split a vma into two pieces at address 'addr', a new vma is allocated
 * either for the first part or the the tail.
 */
/**
 * 把与线性地址区间交叉的线性区划分成两个较小的区。一个在线性地址区间外部，另一个在区间的内部。
 * mm-内存描述符指针。
 * vma-要被划分的线性区。
 * addr-区间与线性区之间交叉点的地址。
 * new_below-表示区间与线性区之间交叉点在区间超始处还是结束处的标志。
 */
int split_vma(struct mm_struct * mm, struct vm_area_struct * vma,
	      unsigned long addr, int new_below)
{
	struct mempolicy *pol;
	struct vm_area_struct *new;

	if (is_vm_hugetlb_page(vma) && (addr & ~HPAGE_MASK))
		return -EINVAL;

	if (mm->map_count >= sysctl_max_map_count)
		return -ENOMEM;

	/**
	 * 获得线性区描述符。如果没有可用的空闲空间，就返回-ENOMEM
	 */
	new = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!new)
		return -ENOMEM;

	/* most fields are the same, copy all, and then fixup */
	*new = *vma;

	if (new_below)
		/**
		 * 如果new_below为1,表示线性地址区间的结束地址在vma线性区的内部。
		 * 因此把新线性区放在vma线性区的前面。因此把new->vm_end和vma->vm_start设置成addr.
		 */
		new->vm_end = addr;
	else {
		/**
		 * 线性地址区间的起始地址在vma线性区的内部。因此必须把新线性区放在vma线性区之后。
		 * 因此把new->vm_start和vma->vm_end设置成addr.
		 */
		new->vm_start = addr;
		new->vm_pgoff += ((addr - vma->vm_start) >> PAGE_SHIFT);
	}

	pol = mpol_copy(vma_policy(vma));
	if (IS_ERR(pol)) {
		kmem_cache_free(vm_area_cachep, new);
		return PTR_ERR(pol);
	}
	vma_set_policy(new, pol);

	if (new->vm_file)
		get_file(new->vm_file);

	/**
	 * 如果定义了新线性区的open方法，就执行它。
	 */
	if (new->vm_ops && new->vm_ops->open)
		new->vm_ops->open(new);

	/**
	 * 把新线性区链接到线性区链表和红黑树中。
	 */
	if (new_below)
		vma_adjust(vma, addr, vma->vm_end, vma->vm_pgoff +
			((addr - new->vm_start) >> PAGE_SHIFT), new);
	else
		vma_adjust(vma, vma->vm_start, addr, vma->vm_pgoff, new);

	return 0;
}

/* Munmap is split into 2 main parts -- this part which finds
 * what needs doing, and the areas themselves, which do the
 * work.  This now handles partial unmappings.
 * Jeremy Fitzhardinge <jeremy@goop.org>
 */
/**
 * 从当前进程的地址空间中删除一个线性地址区间。
 * 要删除的区间并不总是对应一个线性区。它或者是一个线性区的一部分，或者是多个线性区。
 * mm-进程内存描述符。
 * start-要删除的地址区间的起始地址。
 * len-要删除的长度。
 */
int do_munmap(struct mm_struct *mm, unsigned long start, size_t len)
{
	unsigned long end;
	struct vm_area_struct *mpnt, *prev, *last;

	/**
	 * 初步检查：线性区地址不能大于TASK_SIZE，start必须是4096的整数倍。
	 */
	if ((start & ~PAGE_MASK) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;

	/**
	 * len也不能为0
	 */
	if ((len = PAGE_ALIGN(len)) == 0)
		return -EINVAL;

	/* Find the first overlapping VMA */
	/**
	 * mpnt是要删除的线性地址区间之后第一个线性区的位置。mpnt->end>start
	 */
	mpnt = find_vma_prev(mm, start, &prev);
	/**
	 * 没有这样的线性区
	 */
	if (!mpnt)
		return 0;
	/* we have  start < mpnt->vm_end  */

	/* if it doesn't overlap, we have nothing.. */
	end = start + len;
	/**
	 * 也没有与线性地址区间重叠的线性区，就不必做什么了。
	 */
	if (mpnt->vm_start >= end)
		return 0;

	/*
	 * If we need to split any vma, do it now to save pain later.
	 *
	 * Note: mremap's move_vma VM_ACCOUNT handling assumes a partially
	 * unmapped vm_area_struct will remain in use: so lower split_vma
	 * places tmp vma above, and higher split_vma places tmp vma below.
	 */
	/**
	 * 线性区的起始地址在mpnt内，就调用split_vma把线性区mpnt划分成两个较小的区：一个区在线性地址区间外部，而另一个区间内部
	 */
	if (start > mpnt->vm_start) {
		int error = split_vma(mm, mpnt, start, 0);
		if (error)
			return error;
		/**
		 * prev以前存储的是指向线性区mpnt前面一个线性区的指针。
		 * 现在它指向mpnt，即指向线性地址区间外部的那个新线性区。
		 * 这样，prev仍然指向要删除的那个线性区前面的那个线性区。
		 */
		prev = mpnt;
	}

	/* Does it split the last one? */
	last = find_vma(mm, end);
	/**
	 * 如果线性地址空间的结束地址在一个线性区内部，就再次调用split_vma把最后重叠的那个线性区划分成两个较小的区。
	 */
	if (last && end > last->vm_start) {
		int error = split_vma(mm, last, end, 1);
		if (error)
			return error;
	}
	/**
	 * 更新mpnt，使它指向线性地址区间的第一个线性区。
	 * 如果prev为空，即没有，就从mm->mmap获得第一个线性区的地址。
	 */
	mpnt = prev? prev->vm_next: mm->mmap;

	/*
	 * Remove the vma's, and unmap the actual pages
	 */
	/**
	 * detach_vmas_to_be_unmapped从进程的线性地址空间中删除位于线性地址区间中的线性区。
	 * 这可能是一个链表。
	 */
	detach_vmas_to_be_unmapped(mm, mpnt, prev, end);
	spin_lock(&mm->page_table_lock);
	/**
	 * unmap_region清除与线性地址区间对应的页表项并释放相应的页框。
	 */
	unmap_region(mm, mpnt, prev, start, end);
	spin_unlock(&mm->page_table_lock);

	/* Fix up all other VM information */
	/**
	 * 释放detach_vmas_to_be_unmapped收集的位于线性区间内的线性区描述符
	 */
	unmap_vma_list(mm, mpnt);

	return 0;
}

EXPORT_SYMBOL(do_munmap);

asmlinkage long sys_munmap(unsigned long addr, size_t len)
{
	int ret;
	struct mm_struct *mm = current->mm;

	profile_munmap(addr);

	down_write(&mm->mmap_sem);
	ret = do_munmap(mm, addr, len);
	up_write(&mm->mmap_sem);
	return ret;
}

static inline void verify_mm_writelocked(struct mm_struct *mm)
{
#ifdef CONFIG_DEBUG_KERNEL
	if (unlikely(down_read_trylock(&mm->mmap_sem))) {
		WARN_ON(1);
		up_read(&mm->mmap_sem);
	}
#endif
}

/*
 *  this is really a simplified "do_mmap".  it only handles
 *  anonymous maps.  eventually we may be able to do some
 *  brk-specific accounting here.
 */
/**
 * 它其实是do_mmap的简化版，但是它比do_mmap快，因为它假定线性区不映射磁盘上的文件。从而避免了检查线性区对象上的几个字段。
 */
unsigned long do_brk(unsigned long addr, unsigned long len)
{
	struct mm_struct * mm = current->mm;
	struct vm_area_struct * vma, * prev;
	unsigned long flags;
	struct rb_node ** rb_link, * rb_parent;
	pgoff_t pgoff = addr >> PAGE_SHIFT;

	len = PAGE_ALIGN(len);
	if (!len)
		return addr;

	if ((addr + len) > TASK_SIZE || (addr + len) < addr)
		return -EINVAL;

	/*
	 * mlock MCL_FUTURE?
	 */
	if (mm->def_flags & VM_LOCKED) {
		unsigned long locked, lock_limit;
		locked = mm->locked_vm << PAGE_SHIFT;
		lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
		locked += len;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return -EAGAIN;
	}

	/*
	 * mm->mmap_sem is required to protect against another thread
	 * changing the mappings in case we sleep.
	 */
	verify_mm_writelocked(mm);

	/*
	 * Clear old maps.  this also does some error checking for us
	 */
 munmap_back:
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limits *after* clearing old maps... */
	if ((mm->total_vm << PAGE_SHIFT) + len
	    > current->signal->rlim[RLIMIT_AS].rlim_cur)
		return -ENOMEM;

	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	if (security_vm_enough_memory(len >> PAGE_SHIFT))
		return -ENOMEM;

	flags = VM_DATA_DEFAULT_FLAGS | VM_ACCOUNT | mm->def_flags;

	/* Can we just expand an old private anonymous mapping? */
	if (vma_merge(mm, prev, addr, addr + len, flags,
					NULL, NULL, pgoff, NULL))
		goto out;

	/*
	 * create a vma struct for an anonymous mapping
	 */
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma) {
		vm_unacct_memory(len >> PAGE_SHIFT);
		return -ENOMEM;
	}
	memset(vma, 0, sizeof(*vma));

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_pgoff = pgoff;
	vma->vm_flags = flags;
	vma->vm_page_prot = protection_map[flags & 0x0f];
	vma_link(mm, vma, prev, rb_link, rb_parent);
out:
	mm->total_vm += len >> PAGE_SHIFT;
	if (flags & VM_LOCKED) {
		mm->locked_vm += len >> PAGE_SHIFT;
		make_pages_present(addr, addr + len);
	}
	acct_update_integrals();
	update_mem_hiwater();
	return addr;
}

EXPORT_SYMBOL(do_brk);

/* Release all mmaps. */
void exit_mmap(struct mm_struct *mm)
{
	struct mmu_gather *tlb;
	struct vm_area_struct *vma;
	unsigned long nr_accounted = 0;

	lru_add_drain();

	spin_lock(&mm->page_table_lock);

	tlb = tlb_gather_mmu(mm, 1);
	flush_cache_mm(mm);
	/* Use ~0UL here to ensure all VMAs in the mm are unmapped */
	mm->map_count -= unmap_vmas(&tlb, mm, mm->mmap, 0,
					~0UL, &nr_accounted, NULL);
	vm_unacct_memory(nr_accounted);
	BUG_ON(mm->map_count);	/* This is just debugging */
	clear_page_range(tlb, FIRST_USER_PGD_NR * PGDIR_SIZE, MM_VM_SIZE(mm));
	
	tlb_finish_mmu(tlb, 0, MM_VM_SIZE(mm));

	vma = mm->mmap;
	mm->mmap = mm->mmap_cache = NULL;
	mm->mm_rb = RB_ROOT;
	mm->rss = 0;
	mm->total_vm = 0;
	mm->locked_vm = 0;

	spin_unlock(&mm->page_table_lock);

	/*
	 * Walk the list again, actually closing and freeing it
	 * without holding any MM locks.
	 */
	while (vma) {
		struct vm_area_struct *next = vma->vm_next;
		remove_vm_struct(vma);
		vma = next;
	}
}

/* Insert vm structure into process list sorted by address
 * and into the inode's i_mmap tree.  If vm_file is non-NULL
 * then i_mmap_lock is taken here.
 */
/**
 * 在线性区对象链表和内存描述符的红黑树中插入一个vm_area_struct结构。
 * mm-指定进程内存描述符的地址。
 * vmp-指定要插入的vm_area_struct对象的地址。要求线性区对象的vm_start和vm_end字段必须被初始化。
 */
int insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	struct rb_node ** rb_link, * rb_parent;

	/*
	 * The vm_pgoff of a purely anonymous vma should be irrelevant
	 * until its first write fault, when page's anon_vma and index
	 * are set.  But now set the vm_pgoff it will almost certainly
	 * end up with (unless mremap moves it elsewhere before that
	 * first wfault), so /proc/pid/maps tells a consistent story.
	 *
	 * By setting it to reflect the virtual start address of the
	 * vma, merges and splits can happen in a seamless way, just
	 * using the existing file pgoff checks and manipulations.
	 * Similarly in do_mmap_pgoff and in do_brk.
	 */
	if (!vma->vm_file) {
		BUG_ON(vma->anon_vma);
		vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
	}
	/**
	 * 调用find_vma_prepare确定在红黑树中vma应该位于何处。
	 */
	__vma = find_vma_prepare(mm,vma->vm_start,&prev,&rb_link,&rb_parent);
	if (__vma && __vma->vm_start < vma->vm_end)
		return -ENOMEM;
	/**
	 * 调用vma_link执行以下操作:
	 *     在mm->mmap所指向的链表中插入线性区。
	 *     在红黑树中插入线性区。
	 *     如果线性区是匿名的，就把它插入相应的anon_vma数据结构作为头节点的链表中。
	 *     递增mm->map_count计数器。
	 *     如果线性区包含一个内存映射文件，则vma_link执行其他与内存映射文件相关的任务。
	 */
	vma_link(mm, vma, prev, rb_link, rb_parent);
	return 0;
}

/*
 * Copy the vma structure to a new location in the same mm,
 * prior to moving page table entries, to effect an mremap move.
 */
struct vm_area_struct *copy_vma(struct vm_area_struct **vmap,
	unsigned long addr, unsigned long len, pgoff_t pgoff)
{
	struct vm_area_struct *vma = *vmap;
	unsigned long vma_start = vma->vm_start;
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *new_vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	struct mempolicy *pol;

	/*
	 * If anonymous vma has not yet been faulted, update new pgoff
	 * to match new location, to increase its chance of merging.
	 */
	if (!vma->vm_file && !vma->anon_vma)
		pgoff = addr >> PAGE_SHIFT;

	find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	new_vma = vma_merge(mm, prev, addr, addr + len, vma->vm_flags,
			vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma));
	if (new_vma) {
		/*
		 * Source vma may have been merged into new_vma
		 */
		if (vma_start >= new_vma->vm_start &&
		    vma_start < new_vma->vm_end)
			*vmap = new_vma;
	} else {
		new_vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
		if (new_vma) {
			*new_vma = *vma;
			pol = mpol_copy(vma_policy(vma));
			if (IS_ERR(pol)) {
				kmem_cache_free(vm_area_cachep, new_vma);
				return NULL;
			}
			vma_set_policy(new_vma, pol);
			new_vma->vm_start = addr;
			new_vma->vm_end = addr + len;
			new_vma->vm_pgoff = pgoff;
			if (new_vma->vm_file)
				get_file(new_vma->vm_file);
			if (new_vma->vm_ops && new_vma->vm_ops->open)
				new_vma->vm_ops->open(new_vma);
			vma_link(mm, new_vma, prev, rb_link, rb_parent);
		}
	}
	return new_vma;
}
