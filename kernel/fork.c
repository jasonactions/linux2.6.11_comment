/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also entry.S and others).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/namespace.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/security.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/acct.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

/*
 * Protected counters by write_lock_irq(&tasklist_lock)
 */
unsigned long total_forks;	/* Handle normal Linux uptimes. */
int nr_threads; 		/* The idle threads do not count.. */

int max_threads;		/* tunable limit on nr_threads */

DEFINE_PER_CPU(unsigned long, process_counts) = 0;

 __cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */

EXPORT_SYMBOL(tasklist_lock);

int nr_processes(void)
{
	int cpu;
	int total = 0;

	for_each_online_cpu(cpu)
		total += per_cpu(process_counts, cpu);

	return total;
}

#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR

/**
 * 为新进程获取进程描述符
 */
#define alloc_task_struct()	kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
#define free_task_struct(tsk)	kmem_cache_free(task_struct_cachep, (tsk))
static kmem_cache_t *task_struct_cachep;
#endif

void free_task(struct task_struct *tsk)
{
	free_thread_info(tsk->thread_info);
	free_task_struct(tsk);
}
EXPORT_SYMBOL(free_task);

void __put_task_struct(struct task_struct *tsk)
{
	WARN_ON(!(tsk->exit_state & (EXIT_DEAD | EXIT_ZOMBIE)));
	WARN_ON(atomic_read(&tsk->usage));
	WARN_ON(tsk == current);

	if (unlikely(tsk->audit_context))
		audit_free(tsk);
	security_task_free(tsk);
	free_uid(tsk->user);
	put_group_info(tsk->group_info);

	if (!profile_handoff_task(tsk))
		free_task(tsk);
}

void __init fork_init(unsigned long mempages)
{
#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
#ifndef ARCH_MIN_TASKALIGN
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES
#endif
	/* create a slab on which task_structs can be allocated */
	task_struct_cachep =
		kmem_cache_create("task_struct", sizeof(struct task_struct),
			ARCH_MIN_TASKALIGN, SLAB_PANIC, NULL, NULL);
#endif

	/*
	 * The default maximum number of threads is set to a safe
	 * value: the thread structures can take up at most half
	 * of memory.
	 */
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);

	/*
	 * we need to allow at least 20 threads to boot a system
	 */
	if(max_threads < 20)
		max_threads = 20;

	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;
}

/**
 * 为子进程获取进程描述符。
 */
static struct task_struct *dup_task_struct(struct task_struct *orig)
{
	struct task_struct *tsk;
	struct thread_info *ti;

	/**
	 * prepare_to_copy中会调用unlazy_fpu。
	 * 它把FPU、MMX和SSE/SSE2寄存器的内容保存到父进程的thread_info结构中。
	 * 稍后，dup_task_struct将把这些值复制到子进程的thread_info中。
	 */
	prepare_to_copy(orig);

	/**
	 * alloc_task_struct宏为新进程获取进程描述符，并将描述符保存到tsk局部变量中。
	 */
	tsk = alloc_task_struct();
	if (!tsk)
		return NULL;

	/**
	 * alloc_thread_info宏获取一块空闲内存区，用来存放新进程的thread_info结构和内核栈。
	 * 这块内存区字段的大小是8KB或者4KB。
	 */
	ti = alloc_thread_info(tsk);
	if (!ti) {
		free_task_struct(tsk);
		return NULL;
	}

	/** 
	 * 将current进程描述符的内容复制到tsk所指向的task_struct结构中，然后把tsk_thread_info置为ti
	 * 将current进程的thread_info内容复制给ti指向的结构中，并将ti_task置为tsk.
	 */
	*ti = *orig->thread_info;
	*tsk = *orig;
	tsk->thread_info = ti;
	ti->task = tsk;

	/* One for us, one for whoever does the "release_task()" (usually parent) */
	/**
	 * 把新进程描述符的使用计数器usage设置为2，用来表示描述符正在被使用而且其相应的进程处于活动状态。
	 * 进程状态既不是EXIT_ZOMBIE，也不是EXIT_DEAD
	 */
	atomic_set(&tsk->usage,2);
	return tsk;
}

#ifdef CONFIG_MMU
/**
 * 既复制父进程的线性区，也复制它的页表。
 */
static inline int dup_mmap(struct mm_struct * mm, struct mm_struct * oldmm)
{
	struct vm_area_struct * mpnt, *tmp, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;
	unsigned long charge;
	struct mempolicy *pol;

	down_write(&oldmm->mmap_sem);
	flush_cache_mm(current->mm);
	mm->locked_vm = 0;
	mm->mmap = NULL;
	mm->mmap_cache = NULL;
	mm->free_area_cache = oldmm->mmap_base;
	mm->map_count = 0;
	mm->rss = 0;
	mm->anon_rss = 0;
	cpus_clear(mm->cpu_vm_mask);
	mm->mm_rb = RB_ROOT;
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;

	/**
	 * 复制父进程的每一个vm_area_struct线性区描述符，并把复制品插入到子进程的线性区链表和红黑树中。
	 */
	for (mpnt = current->mm->mmap ; mpnt ; mpnt = mpnt->vm_next) {
		struct file *file;

		if (mpnt->vm_flags & VM_DONTCOPY) {
			__vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,
							-vma_pages(mpnt));
			continue;
		}
		charge = 0;
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned int len = (mpnt->vm_end - mpnt->vm_start) >> PAGE_SHIFT;
			if (security_vm_enough_memory(len))
				goto fail_nomem;
			charge = len;
		}
		tmp = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
		if (!tmp)
			goto fail_nomem;
		*tmp = *mpnt;
		pol = mpol_copy(vma_policy(mpnt));
		retval = PTR_ERR(pol);
		if (IS_ERR(pol))
			goto fail_nomem_policy;
		vma_set_policy(tmp, pol);
		tmp->vm_flags &= ~VM_LOCKED;
		tmp->vm_mm = mm;
		tmp->vm_next = NULL;
		anon_vma_link(tmp);
		file = tmp->vm_file;
		if (file) {
			struct inode *inode = file->f_dentry->d_inode;
			get_file(file);
			if (tmp->vm_flags & VM_DENYWRITE)
				atomic_dec(&inode->i_writecount);
      
			/* insert tmp into the share list, just after mpnt */
			spin_lock(&file->f_mapping->i_mmap_lock);
			tmp->vm_truncate_count = mpnt->vm_truncate_count;
			flush_dcache_mmap_lock(file->f_mapping);
			vma_prio_tree_add(tmp, mpnt);
			flush_dcache_mmap_unlock(file->f_mapping);
			spin_unlock(&file->f_mapping->i_mmap_lock);
		}

		/*
		 * Link in the new vma and copy the page table entries:
		 * link in first so that swapoff can see swap entries,
		 * and try_to_unmap_one's find_vma find the new vma.
		 */
		spin_lock(&mm->page_table_lock);
		*pprev = tmp;
		pprev = &tmp->vm_next;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		/**
		 * copy_page_range创建必要的页表来映射线性区所包含的一组页。并且初始化新页表的表项。
		 * 对私有、可写的页（无VM_SHARED标志，有VM_MAYWRITE标志），对父子进程都标记为只读的。
		 * 为写时复制进行处理。
		 */
		retval = copy_page_range(mm, current->mm, tmp);
		spin_unlock(&mm->page_table_lock);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}
	retval = 0;

out:
	flush_tlb_mm(current->mm);
	up_write(&oldmm->mmap_sem);
	return retval;
fail_nomem_policy:
	kmem_cache_free(vm_area_cachep, tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto out;
}

static inline int mm_alloc_pgd(struct mm_struct * mm)
{
	mm->pgd = pgd_alloc(mm);
	if (unlikely(!mm->pgd))
		return -ENOMEM;
	return 0;
}

static inline void mm_free_pgd(struct mm_struct * mm)
{
	pgd_free(mm->pgd);
}
#else
#define dup_mmap(mm, oldmm)	(0)
#define mm_alloc_pgd(mm)	(0)
#define mm_free_pgd(mm)
#endif /* CONFIG_MMU */

 __cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);

#define allocate_mm()	(kmem_cache_alloc(mm_cachep, SLAB_KERNEL))
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))

#include <linux/init_task.h>

static struct mm_struct * mm_init(struct mm_struct * mm)
{
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	init_rwsem(&mm->mmap_sem);
	INIT_LIST_HEAD(&mm->mmlist);
	mm->core_waiters = 0;
	mm->nr_ptes = 0;
	spin_lock_init(&mm->page_table_lock);
	rwlock_init(&mm->ioctx_list_lock);
	mm->ioctx_list = NULL;
	mm->default_kioctx = (struct kioctx)INIT_KIOCTX(mm->default_kioctx, *mm);
	mm->free_area_cache = TASK_UNMAPPED_BASE;

	if (likely(!mm_alloc_pgd(mm))) {
		mm->def_flags = 0;
		return mm;
	}
	free_mm(mm);
	return NULL;
}

/*
 * Allocate and initialize an mm_struct.
 */
/**
 * 用来获得一个新内存描述符
 */
struct mm_struct * mm_alloc(void)
{
	struct mm_struct * mm;

	mm = allocate_mm();
	if (mm) {
		memset(mm, 0, sizeof(*mm));
		mm = mm_init(mm);
	}
	return mm;
}

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void fastcall __mmdrop(struct mm_struct *mm)
{
	BUG_ON(mm == &init_mm);
	mm_free_pgd(mm);
	destroy_context(mm);
	free_mm(mm);
}

/*
 * Decrement the use count and release all resources for an mm.
 */
void mmput(struct mm_struct *mm)
{
	if (atomic_dec_and_test(&mm->mm_users)) {
		exit_aio(mm);
		exit_mmap(mm);
		if (!list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			list_del(&mm->mmlist);
			spin_unlock(&mmlist_lock);
		}
		/**
		 * 如果进程拥有交换标记，则释放它。
		 */
		put_swap_token(mm);
		mmdrop(mm);
	}
}
EXPORT_SYMBOL_GPL(mmput);

/**
 * get_task_mm - acquire a reference to the task's mm
 *
 * Returns %NULL if the task has no mm.  Checks PF_BORROWED_MM (meaning
 * this kernel workthread has transiently adopted a user mm with use_mm,
 * to do its AIO) is not set and if so returns a reference to it, after
 * bumping up the use count.  User must release the mm via mmput()
 * after use.  Typically used by /proc and ptrace.
 */
struct mm_struct *get_task_mm(struct task_struct *task)
{
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_BORROWED_MM)
			mm = NULL;
		else
			atomic_inc(&mm->mm_users);
	}
	task_unlock(task);
	return mm;
}
EXPORT_SYMBOL_GPL(get_task_mm);

/* Please note the differences between mmput and mm_release.
 * mmput is called whenever we stop holding onto a mm_struct,
 * error success whatever.
 *
 * mm_release is called after a mm_struct has been removed
 * from the current process.
 *
 * This difference is important for error handling, when we
 * only half set up a mm_struct for a new process and need to restore
 * the old one.  Because we mmput the new mm_struct before
 * restoring the old one. . .
 * Eric Biederman 10 January 1998
 */
void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	struct completion *vfork_done = tsk->vfork_done;

	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);

	/* notify parent sleeping on vfork() */
	if (vfork_done) {
		tsk->vfork_done = NULL;
		complete(vfork_done);
	}
	if (tsk->clear_child_tid && atomic_read(&mm->mm_users) > 1) {
		u32 __user * tidptr = tsk->clear_child_tid;
		tsk->clear_child_tid = NULL;

		/*
		 * We don't check the error code - if userspace has
		 * not set up a proper pointer then tough luck.
		 */
		put_user(0, tidptr);
		sys_futex(tidptr, FUTEX_WAKE, 1, NULL, NULL, 0);
	}
}

/**
 * 当创建一个新的进程时，内核调用copy_mm函数，
 * 这个函数通过建立新进程的所有页表和内存描述符来创建进程的地址空间。
 * 通常，每个进程都有自己的地址空间，但是轻量级进程共享同一地址空间，即允许它们对同一组页进行寻址。
 */
static int copy_mm(unsigned long clone_flags, struct task_struct * tsk)
{
	struct mm_struct * mm, *oldmm;
	int retval;

	tsk->min_flt = tsk->maj_flt = 0;
	tsk->nvcsw = tsk->nivcsw = 0;

	tsk->mm = NULL;
	tsk->active_mm = NULL;

	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
	oldmm = current->mm;
	/**
	 * 内核线程？？
	 */
	if (!oldmm)
		return 0;

	/**
	 * 指定了CLONE_VM标志，表示创建线程。
	 */
	if (clone_flags & CLONE_VM) {
		/**
		 * 新线程共享父进程的地址空间，所以需要将mm_users加一。
		 */
		atomic_inc(&oldmm->mm_users);
		mm = oldmm;
		/*
		 * There are cases where the PTL is held to ensure no
		 * new threads start up in user mode using an mm, which
		 * allows optimizing out ipis; the tlb_gather_mmu code
		 * is an example.
		 */
		/**
		 * 如果其他CPU持有进程页表自旋锁，就通过spin_unlock_wait保证在释放锁前，缺页处理程序不会结果。
		 * 实际上，这个锁除了保护页表，还必须禁止创建新的轻量级进程。因为它们共享mm描述符
		 */
		spin_unlock_wait(&oldmm->page_table_lock);
		/**
		 * 在good_mm中，将父进程的地址空间赋给子进程。
		 * 注意前面对mm的赋值，表示了新线程使用的mm
		 * 完了，就这么简单
		 */
		goto good_mm;
	}

	/**
	 * 没有CLONE_VM标志，就必须创建一个新的地址空间。
	 * 必须要有地址空间，即使此时并没有分配内存。
	 */
	retval = -ENOMEM;
	/**
	 * 分配一个新的内存描述符。把它的地址存放在新进程的mm中。
	 */
	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;

	/* Copy the current MM stuff.. */
	/**
	 * 并从当前进程复制mm的内容。
	 */
	memcpy(mm, oldmm, sizeof(*mm));
	if (!mm_init(mm))
		goto fail_nomem;

	/**
	 * 调用依赖于体系结构的init_new_context。
	 * 对于80X86来说，该函数检查当前进程是否有定制的局部描述符表。
	 * 如果有，就复制一份局部描述符表并把它插入tsk的地址空间
	 */
	if (init_new_context(tsk,mm))
		goto fail_nocontext;

	/**
	 * dup_mmap不但复制了线程区和页表，也设置了mm的一些属性.
	 * 它也会改变父进程的私有，可写的页为只读的，以使写时复制机制生效。
	 */
	retval = dup_mmap(mm, oldmm);
	if (retval)
		goto free_pt;

	mm->hiwater_rss = mm->rss;
	mm->hiwater_vm = mm->total_vm;

good_mm:
	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;

free_pt:
	mmput(mm);
fail_nomem:
	return retval;

fail_nocontext:
	/*
	 * If init_new_context() failed, we cannot use mmput() to free the mm
	 * because it calls destroy_context()
	 */
	mm_free_pgd(mm);
	free_mm(mm);
	return retval;
}

static inline struct fs_struct *__copy_fs_struct(struct fs_struct *old)
{
	struct fs_struct *fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	/* We don't need to lock fs - think why ;-) */
	if (fs) {
		atomic_set(&fs->count, 1);
		rwlock_init(&fs->lock);
		fs->umask = old->umask;
		read_lock(&old->lock);
		fs->rootmnt = mntget(old->rootmnt);
		fs->root = dget(old->root);
		fs->pwdmnt = mntget(old->pwdmnt);
		fs->pwd = dget(old->pwd);
		if (old->altroot) {
			fs->altrootmnt = mntget(old->altrootmnt);
			fs->altroot = dget(old->altroot);
		} else {
			fs->altrootmnt = NULL;
			fs->altroot = NULL;
		}
		read_unlock(&old->lock);
	}
	return fs;
}

struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
	return __copy_fs_struct(old);
}

EXPORT_SYMBOL_GPL(copy_fs_struct);


static inline int copy_fs(unsigned long clone_flags, struct task_struct * tsk)
{
	if (clone_flags & CLONE_FS) {
		atomic_inc(&current->fs->count);
		return 0;
	}
	tsk->fs = __copy_fs_struct(current->fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}

static int count_open_files(struct files_struct *files, int size)
{
	int i;

	/* Find the last open fd */
	for (i = size/(8*sizeof(long)); i > 0; ) {
		if (files->open_fds->fds_bits[--i])
			break;
	}
	i = (i+1) * 8 * sizeof(long);
	return i;
}

/**
 * 复制进程文件描述符
 */
static int copy_files(unsigned long clone_flags, struct task_struct * tsk)
{
	struct files_struct *oldf, *newf;
	struct file **old_fds, **new_fds;
	int open_files, size, i, error = 0, expand;

	/*
	 * A background process may not have any files ...
	 */
	oldf = current->files;
	if (!oldf)
		goto out;

	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	/*
	 * Note: we may be using current for both targets (See exec.c)
	 * This works because we cache current->files (old) as oldf. Don't
	 * break this.
	 */
	tsk->files = NULL;
	error = -ENOMEM;
	newf = kmem_cache_alloc(files_cachep, SLAB_KERNEL);
	if (!newf) 
		goto out;

	atomic_set(&newf->count, 1);

	spin_lock_init(&newf->file_lock);
	newf->next_fd	    = 0;
	newf->max_fds	    = NR_OPEN_DEFAULT;
	newf->max_fdset	    = __FD_SETSIZE;
	newf->close_on_exec = &newf->close_on_exec_init;
	newf->open_fds	    = &newf->open_fds_init;
	newf->fd	    = &newf->fd_array[0];

	spin_lock(&oldf->file_lock);

	open_files = count_open_files(oldf, oldf->max_fdset);
	expand = 0;

	/*
	 * Check whether we need to allocate a larger fd array or fd set.
	 * Note: we're not a clone task, so the open count won't  change.
	 */
	if (open_files > newf->max_fdset) {
		newf->max_fdset = 0;
		expand = 1;
	}
	if (open_files > newf->max_fds) {
		newf->max_fds = 0;
		expand = 1;
	}

	/* if the old fdset gets grown now, we'll only copy up to "size" fds */
	if (expand) {
		spin_unlock(&oldf->file_lock);
		spin_lock(&newf->file_lock);
		error = expand_files(newf, open_files-1);
		spin_unlock(&newf->file_lock);
		if (error < 0)
			goto out_release;
		spin_lock(&oldf->file_lock);
	}

	old_fds = oldf->fd;
	new_fds = newf->fd;

	memcpy(newf->open_fds->fds_bits, oldf->open_fds->fds_bits, open_files/8);
	memcpy(newf->close_on_exec->fds_bits, oldf->close_on_exec->fds_bits, open_files/8);

	for (i = open_files; i != 0; i--) {
		struct file *f = *old_fds++;
		if (f) {
			get_file(f);
		} else {
			/*
			 * The fd may be claimed in the fd bitmap but not yet
			 * instantiated in the files array if a sibling thread
			 * is partway through open().  So make sure that this
			 * fd is available to the new process.
			 */
			FD_CLR(open_files - i, newf->open_fds);
		}
		*new_fds++ = f;
	}
	spin_unlock(&oldf->file_lock);

	/* compute the remainder to be cleared */
	size = (newf->max_fds - open_files) * sizeof(struct file *);

	/* This is long word aligned thus could use a optimized version */ 
	memset(new_fds, 0, size); 

	if (newf->max_fdset > open_files) {
		int left = (newf->max_fdset-open_files)/8;
		int start = open_files / (8 * sizeof(unsigned long));

		memset(&newf->open_fds->fds_bits[start], 0, left);
		memset(&newf->close_on_exec->fds_bits[start], 0, left);
	}

	tsk->files = newf;
	error = 0;
out:
	return error;

out_release:
	free_fdset (newf->close_on_exec, newf->max_fdset);
	free_fdset (newf->open_fds, newf->max_fdset);
	free_fd_array(newf->fd, newf->max_fds);
	kmem_cache_free(files_cachep, newf);
	goto out;
}

/*
 *	Helper to unshare the files of the current task.
 *	We don't want to expose copy_files internals to
 *	the exec layer of the kernel.
 */

int unshare_files(void)
{
	struct files_struct *files  = current->files;
	int rc;

	if(!files)
		BUG();

	/* This can race but the race causes us to copy when we don't
	   need to and drop the copy */
	if(atomic_read(&files->count) == 1)
	{
		atomic_inc(&files->count);
		return 0;
	}
	rc = copy_files(0, current);
	if(rc)
		current->files = files;
	return rc;
}

EXPORT_SYMBOL(unshare_files);

static inline int copy_sighand(unsigned long clone_flags, struct task_struct * tsk)
{
	struct sighand_struct *sig;

	if (clone_flags & (CLONE_SIGHAND | CLONE_THREAD)) {
		atomic_inc(&current->sighand->count);
		return 0;
	}
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	tsk->sighand = sig;
	if (!sig)
		return -ENOMEM;
	spin_lock_init(&sig->siglock);
	atomic_set(&sig->count, 1);
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));
	return 0;
}

static inline int copy_signal(unsigned long clone_flags, struct task_struct * tsk)
{
	struct signal_struct *sig;

	if (clone_flags & CLONE_THREAD) {
		atomic_inc(&current->signal->count);
		atomic_inc(&current->signal->live);
		return 0;
	}
	sig = kmem_cache_alloc(signal_cachep, GFP_KERNEL);
	tsk->signal = sig;
	if (!sig)
		return -ENOMEM;
	atomic_set(&sig->count, 1);
	atomic_set(&sig->live, 1);
	init_waitqueue_head(&sig->wait_chldexit);
	sig->flags = 0;
	sig->group_exit_code = 0;
	sig->group_exit_task = NULL;
	sig->group_stop_count = 0;
	sig->curr_target = NULL;
	init_sigpending(&sig->shared_pending);
	INIT_LIST_HEAD(&sig->posix_timers);

	sig->tty = current->signal->tty;
	sig->pgrp = process_group(current);
	sig->session = current->signal->session;
	sig->leader = 0;	/* session leadership doesn't inherit */
	sig->tty_old_pgrp = 0;

	sig->utime = sig->stime = sig->cutime = sig->cstime = cputime_zero;
	sig->nvcsw = sig->nivcsw = sig->cnvcsw = sig->cnivcsw = 0;
	sig->min_flt = sig->maj_flt = sig->cmin_flt = sig->cmaj_flt = 0;

	task_lock(current->group_leader);
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);
	task_unlock(current->group_leader);

	return 0;
}

static inline void copy_flags(unsigned long clone_flags, struct task_struct *p)
{
	unsigned long new_flags = p->flags;

	new_flags &= ~PF_SUPERPRIV;
	new_flags |= PF_FORKNOEXEC;
	if (!(clone_flags & CLONE_PTRACE))
		p->ptrace = 0;
	p->flags = new_flags;
}

asmlinkage long sys_set_tid_address(int __user *tidptr)
{
	current->clear_child_tid = tidptr;

	return current->pid;
}

/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
/**
 * 创建进程描述符以及子进程执行所需要的所有其他数据结构
 * 它的参数与do_fork相同。外加子进程的PID。
 */
static task_t *copy_process(unsigned long clone_flags,
				 unsigned long stack_start,
				 struct pt_regs *regs,
				 unsigned long stack_size,
				 int __user *parent_tidptr,
				 int __user *child_tidptr,
				 int pid)
{
	int retval;
	struct task_struct *p = NULL;

	/**
	 * 检查clone_flags所传标志的一致性。
	 */

	/**
	 * 如果CLONE_NEWNS和CLONE_FS标志都被设置，返回错误
	 */
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	/**
	 * CLONE_THREAD标志被设置，并且CLONE_SIGHAND没有设置。
	 * (同一线程组中的轻量级进程必须共享信号)
	 */
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	/**
	 * CLONE_SIGHAND被设置，但是CLONE_VM没有设置。
	 * (共享信号处理程序的轻量级进程也必须共享内存描述符)
	 */
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

	/**
	 * 通过调用security_task_create以及稍后调用security_task_alloc执行所有附加的安全检查。
	 * LINUX2.6提供扩展安全性的钩子函数，与传统unix相比，它具有更加强壮的安全模型。
	 */
	retval = security_task_create(clone_flags);
	if (retval)
		goto fork_out;

	retval = -ENOMEM;
	/**
	 * 调用dup_task_struct为子进程获取进程描述符。
	 */
	p = dup_task_struct(current);
	if (!p)
		goto fork_out;

	/**
	 * 检查存放在current->sigal->rlim[RLIMIT_NPROC].rlim_cur中的限制值，是否小于或者等于用户所拥有的进程数。
	 * 如果是，则返回错误码。当然，有root权限除外。
	 * p->user表示进程的拥有者，p->user->processes表示进程拥有者当前进程数
	 * xie.baoyou注：此处比较是用>=而不是>
	 */
	retval = -EAGAIN;
	if (atomic_read(&p->user->processes) >=
			p->signal->rlim[RLIMIT_NPROC].rlim_cur) {
		/**
		 * 当然，用户有root权限就另当别论了
		 */
		if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RESOURCE) &&
				p->user != &root_user)
			goto bad_fork_free;
	}

	/**
	 * 递增user结构的使用计数器
	 */
	atomic_inc(&p->user->__count);
	/**
	 * 增加用户拥有的进程计数。
	 */
	atomic_inc(&p->user->processes);
	get_group_info(p->group_info);

	/*
	 * If multiple threads are within copy_process(), then this check
	 * triggers too late. This doesn't hurt, the check is only there
	 * to stop root fork bombs.
	 */
	/**
	 * 检查系统中的进程数量（nr_threads）是否超过max_threads
	 * max_threads的缺省值是由系统内存容量决定的。总的原则是：所有的thread_info描述符和内核栈所占用的空间
	 * 不能超过物理内存的1/8。不过，系统管理可以通过写/proc/sys/kernel/thread-max文件来改变这个值。
	 */
	if (nr_threads >= max_threads)
		goto bad_fork_cleanup_count;

	/**
	 * 如果新进程的执行域和可招待格式的内核函数都包含在内核中模块中，
	 * 就递增它们的使用计数器。
	 */
	if (!try_module_get(p->thread_info->exec_domain->module))
		goto bad_fork_cleanup_count;

	if (p->binfmt && !try_module_get(p->binfmt->module))
		goto bad_fork_cleanup_put_domain;

	/**
	 * 设置几个与进程状态相关的关键字段。
	 */

	/**
	 * did_exec是进程发出的execve系统调用的次数，初始为0
	 */
	p->did_exec = 0;
	/**
	 * 更新从父进程复制到tsk_flags字段中的一些标志。
	 * 首先清除PF_SUPERPRIV。该标志表示进程是否使用了某种超级用户权限。
	 * 然后设置PF_FORKNOEXEC标志。它表示子进程还没有发出execve系统调用。
	 */
	copy_flags(clone_flags, p);
	/**
	 * 保存新进程的pid值。
	 */
	p->pid = pid;
	retval = -EFAULT;
	/**
	 * 如果CLONE_PARENT_SETTID标志被设置，就将子进程的PID复制到参数parent_tidptr指向的用户态变量中。
	 * xie.baoyou:想想我们常常调用的pid = fork()语句吧。
	 */
	if (clone_flags & CLONE_PARENT_SETTID)
		if (put_user(p->pid, parent_tidptr))
			goto bad_fork_cleanup;

	p->proc_dentry = NULL;

	/**
	 * 初始化子进程描述符中的list_head数据结构和自旋锁。
	 * 并为挂起信号，定时器及时间统计表相关的几个字段赋初值。
	 */
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
	p->vfork_done = NULL;
	spin_lock_init(&p->alloc_lock);
	spin_lock_init(&p->proc_lock);

	clear_tsk_thread_flag(p, TIF_SIGPENDING);
	init_sigpending(&p->pending);

	p->it_real_value = 0;
	p->it_real_incr = 0;
	p->it_virt_value = cputime_zero;
	p->it_virt_incr = cputime_zero;
	p->it_prof_value = cputime_zero;
	p->it_prof_incr = cputime_zero;
	init_timer(&p->real_timer);
	p->real_timer.data = (unsigned long) p;

	p->utime = cputime_zero;
	p->stime = cputime_zero;
	p->rchar = 0;		/* I/O counter: bytes read */
	p->wchar = 0;		/* I/O counter: bytes written */
	p->syscr = 0;		/* I/O counter: read syscalls */
	p->syscw = 0;		/* I/O counter: write syscalls */
	acct_clear_integrals(p);

	/**
	 * 把大内核锁计数器初始化为-1
	 */
	p->lock_depth = -1;		/* -1 = no lock */
	do_posix_clock_monotonic_gettime(&p->start_time);
	p->security = NULL;
	p->io_context = NULL;
	p->io_wait = NULL;
	p->audit_context = NULL;
#ifdef CONFIG_NUMA
 	p->mempolicy = mpol_copy(p->mempolicy);
 	if (IS_ERR(p->mempolicy)) {
 		retval = PTR_ERR(p->mempolicy);
 		p->mempolicy = NULL;
 		goto bad_fork_cleanup;
 	}
#endif

	p->tgid = p->pid;
	if (clone_flags & CLONE_THREAD)
		p->tgid = current->tgid;

	if ((retval = security_task_alloc(p)))
		goto bad_fork_cleanup_policy;
	if ((retval = audit_alloc(p)))
		goto bad_fork_cleanup_security;
	/* copy all the process information */
	/**
	 * copy_semundo，copy_files，copy_fs，copy_sighand，copy_signal
	 * copy_mm，copy_keys，copy_namespace创建新的数据结构，并把父进程相应数据结构的值复制到新数据结构中。
	 * 除非clone_flags参数指出它们有不同的值。
	 */
	if ((retval = copy_semundo(clone_flags, p)))
		goto bad_fork_cleanup_audit;
	if ((retval = copy_files(clone_flags, p)))
		goto bad_fork_cleanup_semundo;
	if ((retval = copy_fs(clone_flags, p)))
		goto bad_fork_cleanup_files;
	if ((retval = copy_sighand(clone_flags, p)))
		goto bad_fork_cleanup_fs;
	if ((retval = copy_signal(clone_flags, p)))
		goto bad_fork_cleanup_sighand;
	if ((retval = copy_mm(clone_flags, p)))
		goto bad_fork_cleanup_signal;
	if ((retval = copy_keys(clone_flags, p)))
		goto bad_fork_cleanup_mm;
	if ((retval = copy_namespace(clone_flags, p)))
		goto bad_fork_cleanup_keys;
	/**
	 * 调用copy_thread，用发出clone系统调用时CPU寄存器的值（它们保存在父进程的内核栈中）
	 * 来初始化子进程的内核栈。不过，copy_thread把eax寄存器对应字段的值（这是fork和clone系统调用在子进程中的返回值）
	 * 强行置为0。子进程描述符的thread.esp字段初始化为子进程内核栈的基地址。ret_from_fork的地址存放在thread.eip中。
	 * 如果父进程使用IO权限位图。则子进程获取该位图的一个拷贝。
	 * 最后，如果CLONE_SETTLS标志被置位，则子进程获取由CLONE系统调用的参数tls指向的用户态数据结构所表示的TLS段。
	 */
	retval = copy_thread(0, clone_flags, stack_start, stack_size, p, regs);
	if (retval)
		goto bad_fork_cleanup_namespace;

	/**
	 * 如果clone_flags参数的值被置为CLONE_CHILD_SETTID或CLONE_CHILD_CLEARTID
	 * 就把child_tidptr参数的值分别复制到set_child_tid或clear_child_tid字段。
	 * 这些标志说明：必须改变子进程用户态地址空间的dhild_tidptr所指向的变量的值
	 * 不过实际的写操作要稍后再执行。
	 */
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	/*
	 * Clear TID on mm_release()?
	 */
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr: NULL;

	/*
	 * Syscall tracing should be turned off in the child regardless
	 * of CLONE_PTRACE.
	 */
	/**
	 * 清除TIF_SYSCALL_TRACE标志。使ret_from_fork函数不会把系统调用结束的消息通知给调试进程。
	 * 也不应该通知给调试进程，因为子进程并没有调用fork.
	 */
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);

	/* Our parent execution domain becomes current domain
	   These must match for thread signalling to apply */
	   
	p->parent_exec_id = p->self_exec_id;

	/* ok, now we should be set up.. */
	/**
	 * 用clone_flags参数低位的信号数据编码统建始化tsk_exit_signal字段。
	 * 如CLONE_THREAD标志被置位，就把exit_signal字段初始化为-1。
	 * 这样做是因为：当创建线程时，即使被创建的线程死亡，都不应该给领头进程的父进程发送信号。
	 * 而应该是领头进程死亡后，才向其领头进程的父进程发送信号。
	 */
	p->exit_signal = (clone_flags & CLONE_THREAD) ? -1 : (clone_flags & CSIGNAL);
	p->pdeath_signal = 0;
	p->exit_state = 0;

	/* Perform scheduler related setup */
	/**
	 * 调用sched_fork完成对新进程调度程序数据结构的初始化。
	 * 该函数把新进程的状态置为TASK_RUNNING，并把thread_info结构的preempt_count字段设置为1，
	 * 从而禁止抢占。
	 * 此外，为了保证公平调度，父子进程共享父进程的时间片。
	 */
	sched_fork(p);

	/*
	 * Ok, make it visible to the rest of the system.
	 * We dont wake it up yet.
	 */
	p->group_leader = p;
	INIT_LIST_HEAD(&p->ptrace_children);
	INIT_LIST_HEAD(&p->ptrace_list);

	/* Need tasklist lock for parent etc handling! */
	write_lock_irq(&tasklist_lock);

	/*
	 * The task hasn't been attached yet, so cpus_allowed mask cannot
	 * have changed. The cpus_allowed mask of the parent may have
	 * changed after it was copied first time, and it may then move to
	 * another CPU - so we re-copy it here and set the child's CPU to
	 * the parent's CPU. This avoids alot of nasty races.
	 */
	p->cpus_allowed = current->cpus_allowed;
	/**
	 * 初始化子线程的cpu字段。
	 */
	set_task_cpu(p, smp_processor_id());

	/*
	 * Check for pending SIGKILL! The new thread should not be allowed
	 * to slip out of an OOM kill. (or normal SIGKILL.)
	 */
	if (sigismember(&current->pending.signal, SIGKILL)) {
		write_unlock_irq(&tasklist_lock);
		retval = -EINTR;
		goto bad_fork_cleanup_namespace;
	}

	/* CLONE_PARENT re-uses the old parent */
	/**
	 * 初始化表示亲子关系的字段，如果CLONE_PARENT或者CLONE_THREAD被设置了
	 * 就用current->real_parent初始化，否则，当前进程就是初创建进程的父进程。
	 */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD))
		p->real_parent = current->real_parent;
	else
		p->real_parent = current;
	p->parent = p->real_parent;

	if (clone_flags & CLONE_THREAD) {
		spin_lock(&current->sighand->siglock);
		/*
		 * Important: if an exit-all has been started then
		 * do not create this new thread - the whole thread
		 * group is supposed to exit anyway.
		 */
		if (current->signal->flags & SIGNAL_GROUP_EXIT) {
			spin_unlock(&current->sighand->siglock);
			write_unlock_irq(&tasklist_lock);
			retval = -EAGAIN;
			goto bad_fork_cleanup_namespace;
		}
		p->group_leader = current->group_leader;

		if (current->signal->group_stop_count > 0) {
			/*
			 * There is an all-stop in progress for the group.
			 * We ourselves will stop as soon as we check signals.
			 * Make the new thread part of that group stop too.
			 */
			current->signal->group_stop_count++;
			set_tsk_thread_flag(p, TIF_SIGPENDING);
		}

		spin_unlock(&current->sighand->siglock);
	}

	/** 
	 * 把新进程加入到进程链表
	 */
	SET_LINKS(p);

	/**
	 * PT_PTRACED表示子进程必须被跟踪，就把current->parent赋给tsk->parent，并将子进程插入调试程序的跟踪链表中。
	 */
	if (unlikely(p->ptrace & PT_PTRACED))
		__ptrace_link(p, current->parent);

	/**
	 * 把新进程描述符的PID插入pidhash散列表中。
	 */
	attach_pid(p, PIDTYPE_PID, p->pid);
	attach_pid(p, PIDTYPE_TGID, p->tgid);

	/**
	 * 如果子进程是线程组的领头进程(CLONE_THREAD标志被清0)
	 */
	if (thread_group_leader(p)) {
		/**
		 * 将进程插入相应的散列表。
		 */
		attach_pid(p, PIDTYPE_PGID, process_group(p));
		attach_pid(p, PIDTYPE_SID, p->signal->session);
		if (p->pid)
			__get_cpu_var(process_counts)++;
	}

	/**
	 * 计数
	 */
	nr_threads++;
	total_forks++;
	write_unlock_irq(&tasklist_lock);
	retval = 0;

fork_out:
	if (retval)
		return ERR_PTR(retval);
	return p;

bad_fork_cleanup_namespace:
	exit_namespace(p);
bad_fork_cleanup_keys:
	exit_keys(p);
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
bad_fork_cleanup_signal:
	exit_signal(p);
bad_fork_cleanup_sighand:
	exit_sighand(p);
bad_fork_cleanup_fs:
	exit_fs(p); /* blocking */
bad_fork_cleanup_files:
	exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
	exit_sem(p);
bad_fork_cleanup_audit:
	audit_free(p);
bad_fork_cleanup_security:
	security_task_free(p);
bad_fork_cleanup_policy:
#ifdef CONFIG_NUMA
	mpol_free(p->mempolicy);
#endif
bad_fork_cleanup:
	if (p->binfmt)
		module_put(p->binfmt->module);
bad_fork_cleanup_put_domain:
	module_put(p->thread_info->exec_domain->module);
bad_fork_cleanup_count:
	put_group_info(p->group_info);
	atomic_dec(&p->user->processes);
	free_uid(p->user);
bad_fork_free:
	free_task(p);
	goto fork_out;
}

struct pt_regs * __devinit __attribute__((weak)) idle_regs(struct pt_regs *regs)
{
	memset(regs, 0, sizeof(struct pt_regs));
	return regs;
}

task_t * __devinit fork_idle(int cpu)
{
	task_t *task;
	struct pt_regs regs;

	task = copy_process(CLONE_VM, 0, idle_regs(&regs), 0, NULL, NULL, 0);
	if (!task)
		return ERR_PTR(-ENOMEM);
	init_idle(task, cpu);
	unhash_process(task);
	return task;
}

static inline int fork_traceflag (unsigned clone_flags)
{
	if (clone_flags & CLONE_UNTRACED)
		return 0;
	else if (clone_flags & CLONE_VFORK) {
		if (current->ptrace & PT_TRACE_VFORK)
			return PTRACE_EVENT_VFORK;
	} else if ((clone_flags & CSIGNAL) != SIGCHLD) {
		if (current->ptrace & PT_TRACE_CLONE)
			return PTRACE_EVENT_CLONE;
	} else if (current->ptrace & PT_TRACE_FORK)
		return PTRACE_EVENT_FORK;

	return 0;
}

/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 */
/**
 * 负责处理clone,fork,vfork系统调用。
 * clone_flags-与clone的flag参数相同
 * stack_start-与clone的child_stack相同
 * regs-指向通用寄存器的值。是在从用户态切换到内核态时被保存到内核态堆栈中的。
 * stack_size-未使用,总是为0
 * parent_tidptr,child_tidptr-clone中对应参数ptid,ctid相同
 */
long do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      struct pt_regs *regs,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr)
{
	struct task_struct *p;
	int trace = 0;
	/**
	 * 通过查找pidmap_array位图,为子进程分配新的pid参数.
	 */
	long pid = alloc_pidmap();

	if (pid < 0)
		return -EAGAIN;
	/**
	 * 如果父进程正在被跟踪,就检查debugger程序是否想跟踪子进程.并且子进程不是内核进程(CLONE_UNTRACED未设置)
	 * 那么就设置CLONE_PTRACE标志.
	 */
	if (unlikely(current->ptrace)) {
		trace = fork_traceflag (clone_flags);
		if (trace)
			clone_flags |= CLONE_PTRACE;
	}

	/**
	 * copy_process复制进程描述符.如果所有必须的资源都是可用的,该函数返回刚创建的task_struct描述符的地址.
	 * 这是创建进程的关键步骤.
	 */
	p = copy_process(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr, pid);
	/*
	 * Do this prior waking up the new thread - the thread pointer
	 * might get invalid after that point, if the thread exits quickly.
	 */
	if (!IS_ERR(p)) {
		struct completion vfork;

		if (clone_flags & CLONE_VFORK) {
			p->vfork_done = &vfork;
			init_completion(&vfork);
		}

		/**
		 * 如果设置了CLONE_STOPPED,或者必须跟踪子进程.
		 * 就设置子进程为TASK_STOPPED状态,并发送SIGSTOP信号挂起它.
		 */
		if ((p->ptrace & PT_PTRACED) || (clone_flags & CLONE_STOPPED)) {
			/*
			 * We'll start up with an immediate SIGSTOP.
			 */
			sigaddset(&p->pending.signal, SIGSTOP);
			set_tsk_thread_flag(p, TIF_SIGPENDING);
		}

		/**
		 * 没有设置CLONE_STOPPED,就调用wake_up_new_task
		 * 它调整父进程和子进程的调度参数.
		 * 如果父子进程运行在同一个CPU上,并且不能共享同一组页表(CLONE_VM标志被清0).那么,就把子进程插入父进程运行队列.
		 * 并且子进程插在父进程之前.这样做的目的是:如果子进程在创建之后执行新程序,就可以避免写时复制机制执行不必要时页面复制.
		 * 否则,如果运行在不同的CPU上,或者父子进程共享同一组页表.就把子进程插入父进程运行队列的队尾.
		 */
		if (!(clone_flags & CLONE_STOPPED))
			wake_up_new_task(p, clone_flags);
		else/*如果CLONE_STOPPED标志被设置，就把子进程设置为TASK_STOPPED状态。*/
			p->state = TASK_STOPPED;

		/**
		 * 如果进程正被跟踪,则把子进程的PID插入到父进程的ptrace_message,并调用ptrace_notify
		 * ptrace_notify使当前进程停止运行,并向当前进程的父进程发送SIGCHLD信号.子进程的祖父进程是跟踪父进程的debugger进程.
		 * dubugger进程可以通过ptrace_message获得被创建子进程的PID.
		 */
		if (unlikely (trace)) {
			current->ptrace_message = pid;
			ptrace_notify ((trace << 8) | SIGTRAP);
		}

		/**
		 * 如果设置了CLONE_VFORK,就把父进程插入等待队列,并挂起父进程直到子进程结束或者执行了新的程序.
		 */
		if (clone_flags & CLONE_VFORK) {
			wait_for_completion(&vfork);
			if (unlikely (current->ptrace & PT_TRACE_VFORK_DONE))
				ptrace_notify ((PTRACE_EVENT_VFORK_DONE << 8) | SIGTRAP);
		}
	} else {
		free_pidmap(pid);
		pid = PTR_ERR(p);
	}
	return pid;
}

/* SLAB cache for signal_struct structures (tsk->signal) */
kmem_cache_t *signal_cachep;

/* SLAB cache for sighand_struct structures (tsk->sighand) */
kmem_cache_t *sighand_cachep;

/* SLAB cache for files_struct structures (tsk->files) */
kmem_cache_t *files_cachep;

/* SLAB cache for fs_struct structures (tsk->fs) */
kmem_cache_t *fs_cachep;

/* SLAB cache for vm_area_struct structures */
kmem_cache_t *vm_area_cachep;

/* SLAB cache for mm_struct structures (tsk->mm) */
kmem_cache_t *mm_cachep;

void __init proc_caches_init(void)
{
	sighand_cachep = kmem_cache_create("sighand_cache",
			sizeof(struct sighand_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	signal_cachep = kmem_cache_create("signal_cache",
			sizeof(struct signal_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	files_cachep = kmem_cache_create("files_cache", 
			sizeof(struct files_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	fs_cachep = kmem_cache_create("fs_cache", 
			sizeof(struct fs_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	vm_area_cachep = kmem_cache_create("vm_area_struct",
			sizeof(struct vm_area_struct), 0,
			SLAB_PANIC, NULL, NULL);
	mm_cachep = kmem_cache_create("mm_struct",
			sizeof(struct mm_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
}
