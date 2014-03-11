/*
 * i386 semaphore implementation.
 *
 * (C) Copyright 1999 Linus Torvalds
 *
 * Portions Copyright 1999 Red Hat, Inc.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 * rw semaphores implemented November 1999 by Benjamin LaHaise <bcrl@redhat.com>
 */
#include <linux/config.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/init.h>
#include <asm/semaphore.h>

/*
 * Semaphores are implemented using a two-way counter:
 * The "count" variable is decremented for each process
 * that tries to acquire the semaphore, while the "sleeping"
 * variable is a count of such acquires.
 *
 * Notably, the inline "up()" and "down()" functions can
 * efficiently test if they need to do any extra work (up
 * needs to do something only if count was negative before
 * the increment operation.
 *
 * "sleeping" and the contention routine ordering is protected
 * by the spinlock in the semaphore's waitqueue head.
 *
 * Note that these functions are only called when there is
 * contention on the lock, and as such all this is the
 * "non-critical" part of the whole semaphore business. The
 * critical part is the inline stuff in <asm/semaphore.h>
 * where we want to avoid any extra jumps and calls.
 */

/*
 * Logic:
 *  - only on a boundary condition do we need to care. When we go
 *    from a negative count to a non-negative, we wake people up.
 *  - when we go from a non-negative count to a negative do we
 *    (a) synchronize with the "sleeper" count and (b) make sure
 *    that we're on the wakeup list before we synchronize so that
 *    we cannot lose wakeup events.
 */

fastcall void __up(struct semaphore *sem)
{
	wake_up(&sem->wait);
}

/**
 * 当申请信号量失败时，调用__down使线程挂起。直到信号量可用。
 * 本质上，它将线程设置为TASK_UNINTERRUPTIBLE并将进程放到信号量的等待队列。
 */
fastcall void __sched __down(struct semaphore * sem)
{
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	unsigned long flags;

	/**
	 * 设置状态为TASK_UNINTERRUPTIBLE。
	 */
	tsk->state = TASK_UNINTERRUPTIBLE;
	/**
	 * 在将进程放到等待队列前，先获得锁，并禁止本地中断。
	 */
	spin_lock_irqsave(&sem->wait.lock, flags);
	/**
	 * 等待队列的__locked版本假设在调用函数前已经获得了自旋锁。
	 * 请注意加到等待队列上的睡眠进程是互斥的。这样wakeup最多唤醒一个进程。
	 * 如果唤醒多个进程，会扰乱sleeper和count的值。考虑下面注释中的第三种情况。
	 */
	add_wait_queue_exclusive_locked(&sem->wait, &wait);

	/**
	 * sleepers是__down函数的精髓。它既是准确的，同时还是高效的。
	 * 它并不是表示在此信号量上睡眠的线程数。它仅仅表示是否有线程在信号量上面等待。
	 * 请注意它与count的关系。
	 * 当信号量可用时，其COUNT>=1，sleeper=0,此时__down根本不会被执行。
	 * 当信号量不可用时，没有睡眠的进程，则count==0,sleeper==0
	 *     则down会将count设置为-1,且此时sleeper==0，进入本函数后面的for循环后，
	 *     atomic_add_negative执行原子加，但是加的值为0，atomic_add_negative变成检查count值是否为负。
	 *     如果为负，就将sleeper重新置为1。否则说明信号量可用，就将sleeper设置为0。并从循环退出。
	 * 当信号量不可用时，并且有其他进程在等待时，count==-1，sleeper==1。则进入时，count被减1，即count==-2,sleeper(暂时)==2
	 *     此时atomic_add_negative执行原子加，此时加的值是sleeper-1即1.
	 *     并且此时用的是临时变量，linux中经常需要这样将数据存到临时变量中，只有临时变量中的值才是可靠的。其他的都有可能被其他线程或者中断改变。
	 *     加sleeper-1是因为sem->sleepers++;一句后，到atomic_add_negative检查count前，count可能被其他进程加上1了。这样就可以检查出这种情况。
	 *     如果加1后count为负，说明信号仍然不可用，此时count被恢复成-1了，请记住，down中将count减1，此时将它补回去。因为线程并没有获得信号量，而count多减了1
	 *     如果加1后，count不为负，（xie.baoyou注：应该就是0，不应该是正值）。也把sleeper重新置为0。并唤醒另一个线程。
	 *     此时count==0,sleeper==0，看起来是错的。其实是正确的。因为新进程被唤醒了，新进程醒来时，sleeper==0，加sleeper-1就相当于是将count减去1。
	 *     新进程在调用schedule前，将sleeper又设置成1了。
	 */
	sem->sleepers++;
	for (;;) {
		int sleepers = sem->sleepers;

		/*
		 * Add "everybody else" into it. They aren't
		 * playing, because we own the spinlock in
		 * the wait_queue_head.
		 */
		if (!atomic_add_negative(sleepers - 1, &sem->count)) {
			sem->sleepers = 0;
			break;
		}
		sem->sleepers = 1;	/* us - see -1 above */
		spin_unlock_irqrestore(&sem->wait.lock, flags);

		schedule();

		spin_lock_irqsave(&sem->wait.lock, flags);
		tsk->state = TASK_UNINTERRUPTIBLE;
	}

	/**
	 * 请注意上面循环中，spin_lock_irqsave和配对使用情况，运行到这里时，还是锁住的。
	 * 所以可以调用remove_wait_queue的locked版本。
	 */
	remove_wait_queue_locked(&sem->wait, &wait);
	/**
	 * 在获得信号量后，还需要唤醒等待队列上的下一个进程。只唤醒下一个，而不会是多个进程。
	 */
	wake_up_locked(&sem->wait);
	spin_unlock_irqrestore(&sem->wait.lock, flags);
	tsk->state = TASK_RUNNING;
}

/**
 * 它通常用在设备驱动中，而不是用在中断服务程序或者软中断。
 * 意思是可以被信号中断的down.它允许在信号量上被阻塞的进程被信号打断。
 * 被打断后，它在获得资源前被唤醒的话，它会增加count字段的值并返回-EINTR。
 * 所以，设备驱动程序可以判断返回值如果是-EINTR，就放弃IO操作。
 */
fastcall int __sched __down_interruptible(struct semaphore * sem)
{
	int retval = 0;
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	unsigned long flags;

	tsk->state = TASK_INTERRUPTIBLE;
	spin_lock_irqsave(&sem->wait.lock, flags);
	add_wait_queue_exclusive_locked(&sem->wait, &wait);

	sem->sleepers++;
	for (;;) {
		int sleepers = sem->sleepers;

		/*
		 * With signals pending, this turns into
		 * the trylock failure case - we won't be
		 * sleeping, and we* can't get the lock as
		 * it has contention. Just correct the count
		 * and exit.
		 */
		if (signal_pending(current)) {
			retval = -EINTR;
			sem->sleepers = 0;
			atomic_add(sleepers, &sem->count);
			break;
		}

		/*
		 * Add "everybody else" into it. They aren't
		 * playing, because we own the spinlock in
		 * wait_queue_head. The "-1" is because we're
		 * still hoping to get the semaphore.
		 */
		if (!atomic_add_negative(sleepers - 1, &sem->count)) {
			sem->sleepers = 0;
			break;
		}
		sem->sleepers = 1;	/* us - see -1 above */
		spin_unlock_irqrestore(&sem->wait.lock, flags);

		schedule();

		spin_lock_irqsave(&sem->wait.lock, flags);
		tsk->state = TASK_INTERRUPTIBLE;
	}
	remove_wait_queue_locked(&sem->wait, &wait);
	wake_up_locked(&sem->wait);
	spin_unlock_irqrestore(&sem->wait.lock, flags);

	tsk->state = TASK_RUNNING;
	return retval;
}

/*
 * Trylock failed - make sure we correct for
 * having decremented the count.
 *
 * We could have done the trylock with a
 * single "cmpxchg" without failure cases,
 * but then it wouldn't work on a 386.
 */
/**
 * 只有异常处理程序和系统调用服务程序，才可以调用down。中断处理程序和可延迟函数不能调用down。而应该是down_trylock。
 * 它们的区别是会不会引起睡眠。
 */
fastcall int __down_trylock(struct semaphore * sem)
{
	int sleepers;
	unsigned long flags;

	spin_lock_irqsave(&sem->wait.lock, flags);
	sleepers = sem->sleepers + 1;
	sem->sleepers = 0;

	/*
	 * Add "everybody else" and us into it. They aren't
	 * playing, because we own the spinlock in the
	 * wait_queue_head.
	 */
	if (!atomic_add_negative(sleepers, &sem->count)) {
		wake_up_locked(&sem->wait);
	}

	spin_unlock_irqrestore(&sem->wait.lock, flags);
	return 1;
}


/*
 * The semaphore operations have a special calling sequence that
 * allow us to do a simpler in-line version of them. These routines
 * need to convert that sequence back into the C sequence when
 * there is contention on the semaphore.
 *
 * %eax contains the semaphore pointer on entry. Save the C-clobbered
 * registers (%eax, %edx and %ecx) except %eax whish is either a return
 * value or just clobbered..
 */
asm(
".section .sched.text\n"
".align 4\n"
".globl __down_failed\n"
"__down_failed:\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"pushl %ebp\n\t"
	"movl  %esp,%ebp\n\t"
#endif
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __down\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"movl %ebp,%esp\n\t"
	"popl %ebp\n\t"
#endif
	"ret"
);

asm(
".section .sched.text\n"
".align 4\n"
".globl __down_failed_interruptible\n"
"__down_failed_interruptible:\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"pushl %ebp\n\t"
	"movl  %esp,%ebp\n\t"
#endif
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __down_interruptible\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"movl %ebp,%esp\n\t"
	"popl %ebp\n\t"
#endif
	"ret"
);

asm(
".section .sched.text\n"
".align 4\n"
".globl __down_failed_trylock\n"
"__down_failed_trylock:\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"pushl %ebp\n\t"
	"movl  %esp,%ebp\n\t"
#endif
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __down_trylock\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"movl %ebp,%esp\n\t"
	"popl %ebp\n\t"
#endif
	"ret"
);

asm(
".section .sched.text\n"
".align 4\n"
".globl __up_wakeup\n"
"__up_wakeup:\n\t"
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __up\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
	"ret"
);

/*
 * rw spinlock fallbacks
 */
#if defined(CONFIG_SMP)
asm(
".section .sched.text\n"
".align	4\n"
".globl	__write_lock_failed\n"
"__write_lock_failed:\n\t"
	LOCK "addl	$" RW_LOCK_BIAS_STR ",(%eax)\n"
"1:	rep; nop\n\t"
	"cmpl	$" RW_LOCK_BIAS_STR ",(%eax)\n\t"
	"jne	1b\n\t"
	LOCK "subl	$" RW_LOCK_BIAS_STR ",(%eax)\n\t"
	"jnz	__write_lock_failed\n\t"
	"ret"
);

/**
 * 在内核禁止抢占，并且申请读锁失败时，会运行到这里来。
 */
asm(
".section .sched.text\n"
".align	4\n"
".globl	__read_lock_failed\n"
"__read_lock_failed:\n\t"
	/**
	 * 在__build_read_lock_ptr中调用了subl将读锁加一。
	 * 既然读锁申请失败了，调用inc，将读锁减一。
	 */
	LOCK "incl	(%eax)\n"
	/**
	 * 再次重申，此处的nop是不可能少的。是为避免锁死总线。
	 */
"1:	rep; nop\n\t"
	/**
	 * 循环，直到lock值变成正数
	 */
	"cmpl	$1,(%eax)\n\t"
	"js	1b\n\t"
	/**
	 * lock值变成正数或者0了，再减1，如果是0,dec后lock又会变成负数。
	 * 请注意lock前缀。感觉这时候lock的值就象风一样飘忽不定。
	 */
	LOCK "decl	(%eax)\n\t"
	/**
	 * dec后，变成负数了，说明另外一个线程又在本线程前抢占到了写错，还是回到__read_lock_failed
	 * 否则调用ret，结束最外层的read_lock
	 */
	"js	__read_lock_failed\n\t"
	"ret"
);
#endif
