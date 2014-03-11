/*
 *  linux/arch/i386/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>		/* For unblank_screen() */
#include <linux/highmem.h>
#include <linux/module.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/desc.h>
#include <asm/kdebug.h>

extern void die(const char *,struct pt_regs *,long);

/*
 * Unlock any spinlocks which will prevent us from getting the
 * message out 
 */
void bust_spinlocks(int yes)
{
	int loglevel_save = console_loglevel;

	if (yes) {
		oops_in_progress = 1;
		return;
	}
#ifdef CONFIG_VT
	unblank_screen();
#endif
	oops_in_progress = 0;
	/*
	 * OK, the message is on the console.  Now we call printk()
	 * without oops_in_progress set so that printk will give klogd
	 * a poke.  Hold onto your hats...
	 */
	console_loglevel = 15;		/* NMI oopser may have shut the console up */
	printk(" ");
	console_loglevel = loglevel_save;
}

/*
 * Return EIP plus the CS segment base.  The segment limit is also
 * adjusted, clamped to the kernel/user address space (whichever is
 * appropriate), and returned in *eip_limit.
 *
 * The segment is checked, because it might have been changed by another
 * task between the original faulting instruction and here.
 *
 * If CS is no longer a valid code segment, or if EIP is beyond the
 * limit, or if it is a kernel address when CS is not a kernel segment,
 * then the returned value will be greater than *eip_limit.
 * 
 * This is slow, but is very rarely executed.
 */
static inline unsigned long get_segment_eip(struct pt_regs *regs,
					    unsigned long *eip_limit)
{
	unsigned long eip = regs->eip;
	unsigned seg = regs->xcs & 0xffff;
	u32 seg_ar, seg_limit, base, *desc;

	/* The standard kernel/user address space limit. */
	*eip_limit = (seg & 3) ? USER_DS.seg : KERNEL_DS.seg;

	/* Unlikely, but must come before segment checks. */
	if (unlikely((regs->eflags & VM_MASK) != 0))
		return eip + (seg << 4);
	
	/* By far the most common cases. */
	if (likely(seg == __USER_CS || seg == __KERNEL_CS))
		return eip;

	/* Check the segment exists, is within the current LDT/GDT size,
	   that kernel/user (ring 0..3) has the appropriate privilege,
	   that it's a code segment, and get the limit. */
	__asm__ ("larl %3,%0; lsll %3,%1"
		 : "=&r" (seg_ar), "=r" (seg_limit) : "0" (0), "rm" (seg));
	if ((~seg_ar & 0x9800) || eip > seg_limit) {
		*eip_limit = 0;
		return 1;	 /* So that returned eip > *eip_limit. */
	}

	/* Get the GDT/LDT descriptor base. 
	   When you look for races in this code remember that
	   LDT and other horrors are only used in user space. */
	if (seg & (1<<2)) {
		/* Must lock the LDT while reading it. */
		down(&current->mm->context.sem);
		desc = current->mm->context.ldt;
		desc = (void *)desc + (seg & ~7);
	} else {
		/* Must disable preemption while reading the GDT. */
		desc = (u32 *)&per_cpu(cpu_gdt_table, get_cpu());
		desc = (void *)desc + (seg & ~7);
	}

	/* Decode the code segment base from the descriptor */
	base = get_desc_base((unsigned long *)desc);

	if (seg & (1<<2)) { 
		up(&current->mm->context.sem);
	} else
		put_cpu();

	/* Adjust EIP and segment limit, and clamp at the kernel limit.
	   It's legitimate for segments to wrap at 0xffffffff. */
	seg_limit += base;
	if (seg_limit < *eip_limit && seg_limit >= base)
		*eip_limit = seg_limit;
	return eip + base;
}

/* 
 * Sometimes AMD Athlon/Opteron CPUs report invalid exceptions on prefetch.
 * Check that here and ignore it.
 */
static int __is_prefetch(struct pt_regs *regs, unsigned long addr)
{ 
	unsigned long limit;
	unsigned long instr = get_segment_eip (regs, &limit);
	int scan_more = 1;
	int prefetch = 0; 
	int i;

	for (i = 0; scan_more && i < 15; i++) { 
		unsigned char opcode;
		unsigned char instr_hi;
		unsigned char instr_lo;

		if (instr > limit)
			break;
		if (__get_user(opcode, (unsigned char *) instr))
			break; 

		instr_hi = opcode & 0xf0; 
		instr_lo = opcode & 0x0f; 
		instr++;

		switch (instr_hi) { 
		case 0x20:
		case 0x30:
			/* Values 0x26,0x2E,0x36,0x3E are valid x86 prefixes. */
			scan_more = ((instr_lo & 7) == 0x6);
			break;
			
		case 0x60:
			/* 0x64 thru 0x67 are valid prefixes in all modes. */
			scan_more = (instr_lo & 0xC) == 0x4;
			break;		
		case 0xF0:
			/* 0xF0, 0xF2, and 0xF3 are valid prefixes */
			scan_more = !instr_lo || (instr_lo>>1) == 1;
			break;			
		case 0x00:
			/* Prefetch instruction is 0x0F0D or 0x0F18 */
			scan_more = 0;
			if (instr > limit)
				break;
			if (__get_user(opcode, (unsigned char *) instr)) 
				break;
			prefetch = (instr_lo == 0xF) &&
				(opcode == 0x0D || opcode == 0x18);
			break;			
		default:
			scan_more = 0;
			break;
		} 
	}
	return prefetch;
}

static inline int is_prefetch(struct pt_regs *regs, unsigned long addr,
			      unsigned long error_code)
{
	if (unlikely(boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		     boot_cpu_data.x86 >= 6)) {
		/* Catch an obscure case of prefetch inside an NX page. */
		if (nx_enabled && (error_code & 16))
			return 0;
		return __is_prefetch(regs, addr);
	}
	return 0;
} 

fastcall void do_invalid_op(struct pt_regs *, unsigned long);

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 */
/**
 * 缺页中断服务程序。
 * regs-发生异常时寄存器的值
 * error_code-当异常发生时，控制单元压入栈中的错误代码。
 *			  当第0位被清0时，则异常是由一个不存在的页所引起的。否则是由无效的访问权限引起的。
 *			  如果第1位被清0，则异常由读访问或者执行访问所引起，如果被设置，则异常由写访问引起。
 *			  如果第2位被清0，则异常发生在内核态，否则异常发生在用户态。
 */
fastcall void do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct * vma;
	unsigned long address;
	unsigned long page;
	int write;
	siginfo_t info;

	/* get the address */
	/**
	 * 读取引起异常的线性地址。CPU控制单元把这个值存放在cr2控制寄存器中。
	 */
	__asm__("movl %%cr2,%0":"=r" (address));

	if (notify_die(DIE_PAGE_FAULT, "page fault", regs, error_code, 14,
					SIGSEGV) == NOTIFY_STOP)
		return;
	/* It's safe to allow irq's after cr2 has been saved */
	/**
	 * 只在保存了cr2就可以打开中断了。
	 * 如果中断发生前是允许中断的，或者运行在虚拟8086模式，就打开中断。
	 */
	if (regs->eflags & (X86_EFLAGS_IF|VM_MASK))
		local_irq_enable();

	tsk = current;

	info.si_code = SEGV_MAPERR;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 1) == 0.
	 */
	/**
	 * 根据异常地址，判断是访问内核态地址还是用户态地址发生了异常。
	 * xie.baoyou注：这并不代表异常发生在用户态还是内核态。
	 */
	if (unlikely(address >= TASK_SIZE)) { 
		if (!(error_code & 5))
			/**
			 * 内核态访问了一个不存在的页框，这可能是由于内核态访问非连续内存区而引起的。
			 * 注:vmalloc可能打乱了内核页表，而进程切换后，并没有随着修改这些页表项。这可能会引起异常，而这种异常其实不是程序逻辑错误。
			 */
			goto vmalloc_fault;
		/* 
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock.
		 */
		/**
		 * 否则，第0位或者第2位设置了，可能是没有访问权限或者用户态程序访问了内核态地址。
		 */
		goto bad_area_nosemaphore;
	} 

	mm = tsk->mm;

	/*
	 * If we're in an interrupt, have no user context or are running in an
	 * atomic region then we must not take the fault..
	 */
	/**
	 * 内核是否在执行一些关键例程，或者是内核线程出错了。
	 * in_atomic表示内核现在禁止抢占，一般是中断处理程序、可延迟函数、临界区或内核线程中。
	 * 一般来说，这些程序不会去访问用户空间地址。因为访问这些地址总是可能造成导致阻塞。
	 * 而这些地方是不允许阻塞的。
	 * 总之，问题有点严重。
	 */
	if (in_atomic() || !mm)
		goto bad_area_nosemaphore;

	/* When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in the
	 * kernel and should generate an OOPS.  Unfortunatly, in the case of an
	 * erroneous fault occuring in a code path which already holds mmap_sem
	 * we will deadlock attempting to validate the fault against the
	 * address space.  Luckily the kernel only validly references user
	 * space from well defined areas of code, which are listed in the
	 * exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibilty of a deadlock.
	 * Attempt to lock the address space, if we cannot we then validate the
	 * source.  If this is invalid we can skip the address space check,
	 * thus avoiding the deadlock.
	 */
	/**
	 * 缺页没有发生在中断处理程序、可延迟函数、临界区、内核线程中
	 * 那么，就需要检查进程所拥有的线性区，以决定引起缺页的线性地址是否包含在进程的地址空间中
	 * 为此，必须获得进程的mmap_sem读写信号量。
	 */

	/**
	 * 既然不是内核BUG，也不是硬件故障，那么缺页发生时，当前进程就还没有为写而获得信号量mmap_sem.
	 * 但是为了稳妥起见，还是调用down_read_trylock确保mmap_sem没有被其他地方占用。
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		/**
		 * 一般不会运行到这里来。
		 * 运行到这里表示:信号被关闭了。
		 */
		if ((error_code & 4) == 0 &&
		    !search_exception_tables(regs->eip))
		    /**
		     * 内核态异常，在异常处理表中又没有对应的处理函数。
		     * 转到bad_area_nosemaphore，它会再检查一下：是否是使用作为系统调用参数被传递给内核的线性地址。
		     * 请回想一下,access_ok只是作了简单的检查，并不确保线性地址空间真的存在（只要是用户态地址就行了）
		     * 也就是说：用户态程序在调用系统调用的时候，可能传递了一个非法的用户态地址给内核。
		     * 而内核试图读写这个地址的时候，就出错了
		     * 的确，这里就会处理这个情况。
		     */
			goto bad_area_nosemaphore;
		/**
		 * 否则，不是内核异常或者严重的硬件故障。并且信号量被其他线程占用了，等待其他线程释放信号量后继续。
		 */
		down_read(&mm->mmap_sem);
	}

	/**
	 * 运行到此，就已经获得了mmap_sem信号量。
	 * 可以放心的操作mm了。
	 * 现在开始搜索出错地址所在的线性区。
	 */
	vma = find_vma(mm, address);

	/**
	 * 如果vma为空，说明在出错地址后面没有线性区了，说明错误的地址肯定是无效的。
	 */ 
	if (!vma)
		goto bad_area;
	/**
	 * vma在address后面，并且它的起始地址在address前面，说明线性区包含了这个地址。
	 * 谢天谢地，这很可能不是真的错误，可能是COW机制起作用了，也可能是需要调页了。
	 */
	if (vma->vm_start <= address)
		goto good_area;

	/**
	 * 运行到此，说明地址并不在线性区中。
	 * 但是我们还要再判断一下，有可能是push指令引起的异常。和vma==NULL还不太一样。
	 * 直接转到bad_area是不正确的。
	 */
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	/**
	 * 运行到此，说明address地址后面的vma有VM_GROWSDOWN标志，表示它是一个堆栈区
	 * 请注意，如果是内核态访问用户态的堆栈空间，就应该直接扩展堆栈，而不判断if (address + 32 < regs->esp)
	 */
	if (error_code & 4) {
		/*
		 * accessing the stack below %esp is always a bug.
		 * The "+ 32" is there due to some instructions (like
		 * pusha) doing post-decrement on the stack and that
		 * doesn't show up until later..
		 */
		/**
		 * 虽然下一个线性区是堆栈，可是离非法地址太远了，不可能是操作堆栈引起的错误
		 * xie.baoyou注：32而不是4是考虑到pusha的存在。
		 */
		if (address + 32 < regs->esp)
			goto bad_area;
	}
	/**
	 * 线程堆栈空间不足，就扩展一下，一般会成功的，不会运行到bad_area.
	 * 注意:如果异常发生在内核态，说明内核正在访问用户态的栈，就直接扩展用户栈。
	 */
	if (expand_stack(vma, address))
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
/**
 * 处理地址空间内的错误地址。其实可能并不是错误地址。
 */
good_area:
	info.si_code = SEGV_ACCERR;
	write = 0;
	switch (error_code & 3) {/* 错误是由写访问引起的 */
		/**
		 * 无权写？？
		 */
		default:	/* 3: write, present */
#ifdef TEST_VERIFY_AREA
			if (regs->cs == KERNEL_CS)
				printk("WP fault at %08lx\n", regs->eip);
#endif
			/* fall through */
		/**
		 * 写访问出错。
		 */
		case 2:		/* write, not present */
			/**
			 * 但是线性区不允许写，难道是想写只读数据区或者代码段？？？
			 * 注意，当errcode==3也会到这里
			 */
			if (!(vma->vm_flags & VM_WRITE))
				goto bad_area;
			/**
			 * 线性区可写，但是此时发生了写访问错误。
			 * 说明可以启动写时复制或请求调页了。将write++其实就是将它置1
			 */
			write++;
			break;
		/**
		 * 没有读权限？？
		 * 可能是由于进程试图访问一个有特权的页框。
		 */
		case 1:		/* read, present */
			goto bad_area;
		/**
		 * 要读的页不存在，检查是否真的可读或者可执行
		 */
		case 0:		/* read, not present */
			/**
			 * 要读的页不存在，也不允许读和执行，那也是一种错误
			 */
			if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
				goto bad_area;
			/**
			 * 运行到这里，说明要读的页不存在，但是线性区允许读，说明是需要调页了。
			 */
	}

/**
 * 幸免于难，可能不是真正的错误。
 * 呵呵，找块毛巾擦擦汗。
 */
 survive:
	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	/**
	 * 线性区的访问权限与引起异常的类型相匹配，调用handle_mm_fault分配一个新页框。
	 * handle_mm_fault中会处理请求调页和写时复制两种机制。
	 */
	switch (handle_mm_fault(mm, vma, address, write)) {
		/**
		 * VM_FAULT_MINOR表示没有阻塞当前进程，即次缺页。
		 */
		case VM_FAULT_MINOR:
			tsk->min_flt++;
			break;
		/**
		 * VM_FAULT_MAJOR表示阻塞了当前进程，即主缺页。
		 * 很可能是由于当用磁盘上的数据填充所分配的页框时花费了时间。
		 */			
		case VM_FAULT_MAJOR:
			tsk->maj_flt++;
			break;
		/**
		 * VM_FAULT_SIGBUS表示其他错误。
		 * do_sigbus会向进程发送SIGBUS信号。
		 */
		case VM_FAULT_SIGBUS:
			goto do_sigbus;
		/**
		 * VM_FAULT_OOM表示没有足够的内存
		 * 如果不是init进程，就杀死它，否则就调度其他进程运行，等待内存被释放出来。
		 */
		case VM_FAULT_OOM:
			goto out_of_memory;
		default:
			BUG();
	}

	/*
	 * Did it hit the DOS screen memory VA from vm86 mode?
	 */
	if (regs->eflags & VM_MASK) {
		unsigned long bit = (address - 0xA0000) >> PAGE_SHIFT;
		if (bit < 32)
			tsk->thread.screen_bitmap |= 1 << bit;
	}
	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
/**
 * 处理地址空间以外的错误地址。
 * 当要访问的地址不在进程的地址空间内时，执行到此。
 */
bad_area:
	up_read(&mm->mmap_sem);

/**
 * 用户态程序访问了内核态地址，或者访问了没有权限的页框。
 * 或者是内核态线程出错了，也或者是当前有很紧要的操作
 * 总之，运行到这里可不是什么好事。
 */
bad_area_nosemaphore:
	/* User mode accesses just cause a SIGSEGV */
	/**
	 * 发生在用户态的错误地址。
	 * 就发生一个SIGSEGV信号给current进程，并结束函数。
	 */
	if (error_code & 4) {
		/* 
		 * Valid to do another page fault here because this one came 
		 * from user space.
		 */
		if (is_prefetch(regs, address, error_code))
			return;

		tsk->thread.cr2 = address;
		/* Kernel addresses are always protection faults */
		tsk->thread.error_code = error_code | (address >= TASK_SIZE);
		tsk->thread.trap_no = 14;
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		/* info.si_code has been set above */
		info.si_addr = (void __user *)address;
		/**
		 * force_sig_info确信进程不忽略或阻塞SIGSEGV信号
		 * SEGV_MAPERR或SEGV_ACCERR已经被设置在info.si_code中。
		 */
		force_sig_info(SIGSEGV, &info, tsk);
		return;
	}

#ifdef CONFIG_X86_F00F_BUG
	/*
	 * Pentium F0 0F C7 C8 bug workaround.
	 */
	if (boot_cpu_data.f00f_bug) {
		unsigned long nr;
		
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return;
		}
	}
#endif
	/**
	 * 异常发生在内核态。
	 */
no_context:
	/* Are we prepared to handle this kernel fault?  */
	/**
	 * 异常的引起是因为把某个线性地址作为系统调用的参数传递给内核。
	 * 调用fixup_exception判断这种情况，如果是这样的话，那谢天谢地，还有修复的可能。
	 * 典型的：fixup_exception可能会向进程发送SIGSEGV信号或者用一个适当的出错码终止系统调用处理程序。
	 */
	if (fixup_exception(regs))
		return;

	/* 
	 * Valid to do another page fault here, because if this fault
	 * had been triggered by is_prefetch fixup_exception would have 
	 * handled it.
	 */
 	if (is_prefetch(regs, address, error_code))
 		return;

/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */

	bust_spinlocks(1);

#ifdef CONFIG_X86_PAE
	if (error_code & 16) {
		pte_t *pte = lookup_address(address);

		if (pte && pte_present(*pte) && !pte_exec_kernel(*pte))
			printk(KERN_CRIT "kernel tried to execute NX-protected page - exploit attempt? (uid: %d)\n", current->uid);
	}
#endif
	/**
	 * 但愿程序不要运行到这里来，著名的oops出现了^-^
	 * 不过oops算什么呢，真正的内核高手在等着解决这些错误呢
	 */
	if (address < PAGE_SIZE)
		printk(KERN_ALERT "Unable to handle kernel NULL pointer dereference");
	else
		printk(KERN_ALERT "Unable to handle kernel paging request");
	printk(" at virtual address %08lx\n",address);
	printk(KERN_ALERT " printing eip:\n");
	printk("%08lx\n", regs->eip);
	asm("movl %%cr3,%0":"=r" (page));
	page = ((unsigned long *) __va(page))[address >> 22];
	printk(KERN_ALERT "*pde = %08lx\n", page);
	/*
	 * We must not directly access the pte in the highpte
	 * case, the page table might be allocated in highmem.
	 * And lets rather not kmap-atomic the pte, just in case
	 * it's allocated already.
	 */
#ifndef CONFIG_HIGHPTE
	if (page & 1) {
		page &= PAGE_MASK;
		address &= 0x003ff000;
		page = ((unsigned long *) __va(page))[address >> PAGE_SHIFT];
		printk(KERN_ALERT "*pte = %08lx\n", page);
	}
#endif
	die("Oops", regs, error_code);
	bust_spinlocks(0);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
/**
 * 缺页了，但是没有内存了，就杀死进程（init除外）
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (tsk->pid == 1) {
		yield();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", tsk->comm);
	if (error_code & 4)
		do_exit(SIGKILL);
	goto no_context;

/**
 * 缺页了，但是分配页时出现了错误，就向进程发送SIGBUS信号。
 */
do_sigbus:
	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die */
	if (!(error_code & 4))
		goto no_context;

	/* User space => ok to do another page fault */
	if (is_prefetch(regs, address, error_code))
		return;

	tsk->thread.cr2 = address;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 14;
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = BUS_ADRERR;
	info.si_addr = (void __user *)address;
	force_sig_info(SIGBUS, &info, tsk);
	return;

/**
 * 内核访问了不存在的页框。
 * 内核在更新非连续内存区对应的页表项时是非常懒惰的。实际上，vmalloc和vfree函数只把自己限制在更新主内核页表（即全局目录和它的子页表）。
 * 但是，如果内核真的访问到了vmalloc的空间，就需要把页表项补充完整了。
 */
vmalloc_fault:
	{
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk" here. We might be inside
		 * an interrupt in the middle of a task switch..
		 */
		int index = pgd_index(address);
		unsigned long pgd_paddr;
		pgd_t *pgd, *pgd_k;
		pud_t *pud, *pud_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		/**
		 * 把cr3中当前进程页全局目录的物理地址赋给局部变量pgd_paddr。
		 * 注：内核不使用current->mm->pgd导出当前进程的页全局目录地址。因为这种缺页可能在任何时刻发生，甚至在进程切换期间发生。
		 */
		asm("movl %%cr3,%0":"=r" (pgd_paddr));
		pgd = index + (pgd_t *)__va(pgd_paddr);
		/**
		 * 把主内核页全局目录的线性地址赋给pgd_k
		 */
		pgd_k = init_mm.pgd + index;

		/**
		 * pgd_k对应的主内核页全局目录项为空。说明不是非连续内存区产生的错误。
		 * 因为非连续内存区产生的缺页仅仅是没有页表项，而不会缺少目录项。
		 */
		if (!pgd_present(*pgd_k))
			goto no_context;

		/*
		 * set_pgd(pgd, *pgd_k); here would be useless on PAE
		 * and redundant with the set_pmd() on non-PAE. As would
		 * set_pud.
		 */

		/**
		 * 检查了全局目录项，还必须检查主内核页上级目录项和中间目录项。
		 * 如果它们中有一个为空，也转到no_context
		 */
		pud = pud_offset(pgd, address);
		pud_k = pud_offset(pgd_k, address);
		if (!pud_present(*pud_k))
			goto no_context;
		
		pmd = pmd_offset(pud, address);
		pmd_k = pmd_offset(pud_k, address);
		if (!pmd_present(*pmd_k))
			goto no_context;
		/**
		 * 目录项不为空，说明真的是在访问非连续内存区。就把主目录项复制到进程页中间目录的相应项中。
		 */
		set_pmd(pmd, *pmd_k);

		pte_k = pte_offset_kernel(pmd_k, address);
		if (!pte_present(*pte_k))
			goto no_context;
		return;
	}
}
