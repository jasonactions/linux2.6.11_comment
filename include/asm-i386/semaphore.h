#ifndef _I386_SEMAPHORE_H
#define _I386_SEMAPHORE_H

#include <linux/linkage.h>

#ifdef __KERNEL__

/*
 * SMP- and interrupt-safe semaphores..
 *
 * (C) Copyright 1996 Linus Torvalds
 *
 * Modified 1996-12-23 by Dave Grothe <dave@gcom.com> to fix bugs in
 *                     the original code and to make semaphore waits
 *                     interruptible so that processes waiting on
 *                     semaphores can be killed.
 * Modified 1999-02-14 by Andrea Arcangeli, split the sched.c helper
 *		       functions in asm/sempahore-helper.h while fixing a
 *		       potential and subtle race discovered by Ulrich Schmid
 *		       in down_interruptible(). Since I started to play here I
 *		       also implemented the `trylock' semaphore operation.
 *          1999-07-02 Artur Skawina <skawina@geocities.com>
 *                     Optimized "0(ecx)" -> "(ecx)" (the assembler does not
 *                     do this). Changed calling sequences from push/jmp to
 *                     traditional call/ret.
 * Modified 2001-01-01 Andreas Franck <afranck@gmx.de>
 *		       Some hacks to ensure compatibility with recent
 *		       GCC snapshots, to avoid stack corruption when compiling
 *		       with -fomit-frame-pointer. It's not sure if this will
 *		       be fixed in GCC, as our previous implementation was a
 *		       bit dubious.
 *
 * If you would like to see an analysis of this implementation, please
 * ftp to gcom.com and download the file
 * /pub/linux/src/semaphore/semaphore-2.0.24.tar.gz.
 *
 */

#include <asm/system.h>
#include <asm/atomic.h>
#include <linux/wait.h>
#include <linux/rwsem.h>

/**
 * 内核信号量结构
 */
struct semaphore {
	/**
	 * 如果该值大于0，表示资源是空闲的。如果等于0，表示信号量是忙的，但是没有进程在等待这个资源。
	 * 如果count为负，表示资源忙，并且至少有一个进程在等待。
	 * 但是请注意，负值并不代表等待的进程数量。
	 */
	atomic_t count;
	/**
	 * 存放一个标志，表示是否有一些进程在信号量上睡眠。
	 */
	int sleepers;
	/**
	 * 存放等待队列链表的地址。当前等待资源的所有睡眠进程都放在这个链表中。
	 * 如果count>=0，那么这个链表就应该是空的。
	 */
	wait_queue_head_t wait;
};


#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.count		= ATOMIC_INIT(n),				\
	.sleepers	= 0,						\
	.wait		= __WAIT_QUEUE_HEAD_INITIALIZER((name).wait)	\
}

#define __MUTEX_INITIALIZER(name) \
	__SEMAPHORE_INITIALIZER(name,1)

#define __DECLARE_SEMAPHORE_GENERIC(name,count) \
	struct semaphore name = __SEMAPHORE_INITIALIZER(name,count)

/**
 * DECLARE_MUTEX静态分配semaphore结构的变量，并将count字段初始化为1
 */
#define DECLARE_MUTEX(name) __DECLARE_SEMAPHORE_GENERIC(name,1)
/**
 * DECLARE_MUTEX静态分配semaphore结构的变量，并将count字段初始化为0
 */
#define DECLARE_MUTEX_LOCKED(name) __DECLARE_SEMAPHORE_GENERIC(name,0)

static inline void sema_init (struct semaphore *sem, int val)
{
/*
 *	*sem = (struct semaphore)__SEMAPHORE_INITIALIZER((*sem),val);
 *
 * i'd rather use the more flexible initialization above, but sadly
 * GCC 2.7.2.3 emits a bogus warning. EGCS doesn't. Oh well.
 */
	atomic_set(&sem->count, val);
	sem->sleepers = 0;
	init_waitqueue_head(&sem->wait);
}

/**
 * 初始化semaphore将count字段初始化为1
 */
static inline void init_MUTEX (struct semaphore *sem)
{
	sema_init(sem, 1);
}

/**
 * 初始化semaphore将count字段初始化为0
 */
static inline void init_MUTEX_LOCKED (struct semaphore *sem)
{
	sema_init(sem, 0);
}

fastcall void __down_failed(void /* special register calling convention */);
fastcall int  __down_failed_interruptible(void  /* params in registers */);
fastcall int  __down_failed_trylock(void  /* params in registers */);
fastcall void __up_wakeup(void /* special register calling convention */);

fastcall void __down(struct semaphore * sem);
fastcall int  __down_interruptible(struct semaphore * sem);
fastcall int  __down_trylock(struct semaphore * sem);
fastcall void __up(struct semaphore * sem);

/*
 * This is ugly, but we want the default case to fall through.
 * "__down_failed" is a special asm handler that calls the C
 * routine that actually waits. See arch/i386/kernel/semaphore.c
 */
/**
 * 当进程希望获得内核信号量锁时，调用down函数。
 */
static inline void down(struct semaphore * sem)
{
	might_sleep();
	__asm__ __volatile__(
		"# atomic down operation\n\t"
		/**
		 * 首先减少并检查sem->count的值
		 * 如果为负（说明减少前就是0或负）就挂起
		 * 这里的减一操作是原子的
		 * 请注意当count<0时，此时-1是不正确的，因为调用进程会被挂起，而没有真正的获得信号量。
		 * 它恢复count值的时机，不在down中，在__down中。
		 */
		LOCK "decl %0\n\t"     /* --sem->count */
		"js 2f\n"
		"1:\n"
		/**
		 * 为负了，调用__down_failed
		 * __down_failed会保存参数并调用__down
		 */
		LOCK_SECTION_START("")
		"2:\tlea %0,%%eax\n\t"
		"call __down_failed\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		:"=m" (sem->count)
		:
		:"memory","ax");
}

/*
 * Interruptible try to acquire a semaphore.  If we obtained
 * it, return zero.  If we were interrupted, returns -EINTR
 */
static inline int down_interruptible(struct semaphore * sem)
{
	int result;

	might_sleep();
	__asm__ __volatile__(
		"# atomic interruptible down operation\n\t"
		LOCK "decl %1\n\t"     /* --sem->count */
		"js 2f\n\t"
		"xorl %0,%0\n"
		"1:\n"
		LOCK_SECTION_START("")
		"2:\tlea %1,%%eax\n\t"
		"call __down_failed_interruptible\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		:"=a" (result), "=m" (sem->count)
		:
		:"memory");
	return result;
}

/*
 * Non-blockingly attempt to down() a semaphore.
 * Returns zero if we acquired it
 */
static inline int down_trylock(struct semaphore * sem)
{
	int result;

	__asm__ __volatile__(
		"# atomic interruptible down operation\n\t"
		LOCK "decl %1\n\t"     /* --sem->count */
		"js 2f\n\t"
		"xorl %0,%0\n"
		"1:\n"
		LOCK_SECTION_START("")
		"2:\tlea %1,%%eax\n\t"
		"call __down_failed_trylock\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		:"=a" (result), "=m" (sem->count)
		:
		:"memory");
	return result;
}

/*
 * Note! This is subtle. We jump to wake people up only if
 * the semaphore was negative (== somebody was waiting on it).
 * The default case (no contention) will result in NO
 * jumps for both down() and up().
 */
/**
 * 释放信号量
 */
static inline void up(struct semaphore * sem)
{
	__asm__ __volatile__(
		"# atomic up operation\n\t"
		/**
		 * 首先增加count的值
		 */
		LOCK "incl %0\n\t"     /* ++sem->count */
		/**
		 * 测试count值，如果当前小于等于0，那么有进程在等待，跳到2f，唤醒等待进程。
		 */
		"jle 2f\n"
		/**
		 * 运行到这里表示count>0，不用做任何事情，返回。
		 * 注意1后面的代码在单独的段中。此处就是函数的结束处。
		 */
		"1:\n"
		LOCK_SECTION_START("")
		/**
		 * 调用__up_wakeup，注意它是从寄存器传参的。
		 * 它最终调用的是__up，再调用wakeup。
		 * eax寄存器中传递的是第一个参数sem
		 */
		"2:\tlea %0,%%eax\n\t"
		"call __up_wakeup\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		".subsection 0\n"
		:"=m" (sem->count)
		:
		:"memory","ax");
}

#endif
#endif
