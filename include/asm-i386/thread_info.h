/* thread_info.h: i386 low-level thread information
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds and Dave Miller
 */

#ifndef _ASM_THREAD_INFO_H
#define _ASM_THREAD_INFO_H

#ifdef __KERNEL__

#include <linux/config.h>
#include <linux/compiler.h>
#include <asm/page.h>

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#endif

/*
 * low level task data that entry.S needs immediate access to
 * - this struct should fit entirely inside of one cache line
 * - this struct shares the supervisor stack pages
 * - if the contents of this structure are changed, the assembly constants must also be changed
 */
#ifndef __ASSEMBLY__

struct thread_info {
	struct task_struct	*task;		/* main task structure */
	struct exec_domain	*exec_domain;	/* execution domain */
	/**
	 * 如果有TIF_NEED_RESCHED标志，则必须调用调度程序。
	 */
	unsigned long		flags;		/* low level flags */
	/**
	 * 线程标志:
	 *     TS_USEDFPU:表示进程在当前执行过程中，是否使用过FPU、MMX和XMM寄存器。
	 */
	unsigned long		status;		/* thread-synchronous flags */
	/**
	 * 可运行进程所在运行队列的CPU逻辑号。
	 */
	__u32			cpu;		/* current CPU */
	__s32			preempt_count; /* 0 => preemptable, <0 => BUG */


	mm_segment_t		addr_limit;	/* thread address space:
					 	   0-0xBFFFFFFF for user-thead
						   0-0xFFFFFFFF for kernel-thread
						*/
	struct restart_block    restart_block;

	unsigned long           previous_esp;   /* ESP of the previous stack in case
						   of nested (IRQ) stacks
						*/
	__u8			supervisor_stack[0];
};

#else /* !__ASSEMBLY__ */

#include <asm/asm_offsets.h>

#endif

#define PREEMPT_ACTIVE		0x10000000
#ifdef CONFIG_4KSTACKS
#define THREAD_SIZE            (4096)
#else
#define THREAD_SIZE		(8192)
#endif

#define STACK_WARN             (THREAD_SIZE/8)
/*
 * macros/functions for gaining access to the thread information structure
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
#ifndef __ASSEMBLY__

#define INIT_THREAD_INFO(tsk)			\
{						\
	.task		= &tsk,			\
	.exec_domain	= &default_exec_domain,	\
	.flags		= 0,			\
	.cpu		= 0,			\
	.preempt_count	= 1,			\
	.addr_limit	= KERNEL_DS,		\
	.restart_block = {			\
		.fn = do_no_restart_syscall,	\
	},					\
}

#define init_thread_info	(init_thread_union.thread_info)
#define init_stack		(init_thread_union.stack)


/* how to get the thread information struct from C */
/**
 * 获得当前线程基本信息。
 */
static inline struct thread_info *current_thread_info(void)
{
	struct thread_info *ti;
	__asm__("andl %%esp,%0; ":"=r" (ti) : "0" (~(THREAD_SIZE - 1)));
	return ti;
}

/* how to get the current stack pointer from C */
register unsigned long current_stack_pointer asm("esp") __attribute_used__;

/* thread information allocation */

/**
 * alloc_thread_info分配一个thread_info
 */
#ifdef CONFIG_DEBUG_STACK_USAGE
#define alloc_thread_info(tsk)					\
	({							\
		struct thread_info *ret;			\
								\
		ret = kmalloc(THREAD_SIZE, GFP_KERNEL);		\
		if (ret)					\
			memset(ret, 0, THREAD_SIZE);		\
		ret;						\
	})
#else
#define alloc_thread_info(tsk) kmalloc(THREAD_SIZE, GFP_KERNEL)
#endif

/**
 * 释放thread_info，及内核栈
 */
#define free_thread_info(info)	kfree(info)
#define get_thread_info(ti) get_task_struct((ti)->task)
#define put_thread_info(ti) put_task_struct((ti)->task)

#else /* !__ASSEMBLY__ */

/* how to get the thread information struct from ASM */
#define GET_THREAD_INFO(reg) \
	movl $-THREAD_SIZE, reg; \
	andl %esp, reg

/* use this one if reg already contains %esp */
#define GET_THREAD_INFO_WITH_ESP(reg) \
	andl $-THREAD_SIZE, reg

#endif

/*
 * thread information flags
 * - these are process state flags that various assembly files may need to access
 * - pending work-to-be-done flags are in LSW
 * - other flags in MSW
 */
/**
 * 正在跟踪系统调用
 * 在do_fork中，强制将子进程的这个标志清除。因为子进程返回时要进入ret_from_fork。
 * ret_from_fork会进入异常处理退出流程。如果不清除这个标志，就可能给调试进程发送系统调用结束的消息。
 */
#define TIF_SYSCALL_TRACE	0	/* syscall trace active */
/**
 * X86上未用
 */
#define TIF_NOTIFY_RESUME	1	/* resumption notification requested */
/**
 * 进程有挂起信号
 */
#define TIF_SIGPENDING		2	/* signal pending */
/**
 * 在返回用户态前，需要进行调度
 */
#define TIF_NEED_RESCHED	3	/* rescheduling necessary */
/**
 * 在返回用户态前，恢复单步执行
 */
#define TIF_SINGLESTEP		4	/* restore singlestep on return to user mode */
/**
 * 通过iret而不是sysexit返回用户态
 */
#define TIF_IRET		5	/* return with iret */
/**
 * 系统调用正被审计??
 */
#define TIF_SYSCALL_AUDIT	7	/* syscall auditing active */
/**
 * idle进程在轮询TIF_NEED_RESHED标志。
 */
#define TIF_POLLING_NRFLAG	16	/* true if poll_idle() is polling TIF_NEED_RESCHED */
/**
 * 当内存不足时，当前进程正被杀死，以回收内存。
 */
#define TIF_MEMDIE		17

#define _TIF_SYSCALL_TRACE	(1<<TIF_SYSCALL_TRACE)
#define _TIF_NOTIFY_RESUME	(1<<TIF_NOTIFY_RESUME)
#define _TIF_SIGPENDING		(1<<TIF_SIGPENDING)
#define _TIF_NEED_RESCHED	(1<<TIF_NEED_RESCHED)
#define _TIF_SINGLESTEP		(1<<TIF_SINGLESTEP)
#define _TIF_IRET		(1<<TIF_IRET)
#define _TIF_SYSCALL_AUDIT	(1<<TIF_SYSCALL_AUDIT)
#define _TIF_POLLING_NRFLAG	(1<<TIF_POLLING_NRFLAG)

/* work to do on interrupt/exception return */
#define _TIF_WORK_MASK \
  (0x0000FFFF & ~(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SINGLESTEP))
#define _TIF_ALLWORK_MASK	0x0000FFFF	/* work to do on any return to u-space */

/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
/**
 * 表示进程在当前执行过程中，是否使用过FPU、MMX和XMM寄存器。
 */
#define TS_USEDFPU		0x0001	/* FPU was used by this task this quantum (SMP) */

#endif /* __KERNEL__ */

#endif /* _ASM_THREAD_INFO_H */
