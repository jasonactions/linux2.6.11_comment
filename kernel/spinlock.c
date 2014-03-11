/*
 * Copyright (2004) Linus Torvalds
 *
 * Author: Zwane Mwaikambo <zwane@fsmlabs.com>
 *
 * Copyright (2004) Ingo Molnar
 */

#include <linux/config.h>
#include <linux/linkage.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/module.h>

/*
 * Generic declaration of the raw read_trylock() function,
 * architectures are supposed to optimize this:
 */
int __lockfunc generic_raw_read_trylock(rwlock_t *lock)
{
	_raw_read_lock(lock);
	return 1;
}
EXPORT_SYMBOL(generic_raw_read_trylock);

int __lockfunc _spin_trylock(spinlock_t *lock)
{
	preempt_disable();
	if (_raw_spin_trylock(lock))
		return 1;
	
	preempt_enable();
	return 0;
}
EXPORT_SYMBOL(_spin_trylock);

int __lockfunc _read_trylock(rwlock_t *lock)
{
	preempt_disable();
	if (_raw_read_trylock(lock))
		return 1;

	preempt_enable();
	return 0;
}
EXPORT_SYMBOL(_read_trylock);

int __lockfunc _write_trylock(rwlock_t *lock)
{
	preempt_disable();
	if (_raw_write_trylock(lock))
		return 1;

	preempt_enable();
	return 0;
}
EXPORT_SYMBOL(_write_trylock);

#ifndef CONFIG_PREEMPT

/**
 * 在没有配置内核抢占时，read_lock的实现。
 */
void __lockfunc _read_lock(rwlock_t *lock)
{
	preempt_disable();
	_raw_read_lock(lock);
}
EXPORT_SYMBOL(_read_lock);

unsigned long __lockfunc _spin_lock_irqsave(spinlock_t *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();
	_raw_spin_lock_flags(lock, flags);
	return flags;
}
EXPORT_SYMBOL(_spin_lock_irqsave);

void __lockfunc _spin_lock_irq(spinlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	_raw_spin_lock(lock);
}
EXPORT_SYMBOL(_spin_lock_irq);

void __lockfunc _spin_lock_bh(spinlock_t *lock)
{
	local_bh_disable();
	preempt_disable();
	_raw_spin_lock(lock);
}
EXPORT_SYMBOL(_spin_lock_bh);

unsigned long __lockfunc _read_lock_irqsave(rwlock_t *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();
	_raw_read_lock(lock);
	return flags;
}
EXPORT_SYMBOL(_read_lock_irqsave);

void __lockfunc _read_lock_irq(rwlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	_raw_read_lock(lock);
}
EXPORT_SYMBOL(_read_lock_irq);

void __lockfunc _read_lock_bh(rwlock_t *lock)
{
	local_bh_disable();
	preempt_disable();
	_raw_read_lock(lock);
}
EXPORT_SYMBOL(_read_lock_bh);

unsigned long __lockfunc _write_lock_irqsave(rwlock_t *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();
	_raw_write_lock(lock);
	return flags;
}
EXPORT_SYMBOL(_write_lock_irqsave);

void __lockfunc _write_lock_irq(rwlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	_raw_write_lock(lock);
}
EXPORT_SYMBOL(_write_lock_irq);

void __lockfunc _write_lock_bh(rwlock_t *lock)
{
	local_bh_disable();
	preempt_disable();
	_raw_write_lock(lock);
}
EXPORT_SYMBOL(_write_lock_bh);

void __lockfunc _spin_lock(spinlock_t *lock)
{
	preempt_disable();
	_raw_spin_lock(lock);
}

EXPORT_SYMBOL(_spin_lock);

void __lockfunc _write_lock(rwlock_t *lock)
{
	preempt_disable();
	_raw_write_lock(lock);
}

EXPORT_SYMBOL(_write_lock);

#else /* CONFIG_PREEMPT: */

/*
 * This could be a long-held lock. We both prepare to spin for a long
 * time (making _this_ CPU preemptable if possible), and we also signal
 * towards that other CPU that it should break the lock ASAP.
 *
 * (We do this in a function because inlining it would be excessive.)
 */
/**
 * 通过BUILD_LOCK_OPS(spin, spinlock);定义了_spin_lock，进而实现了spin_lock
 * 这是在具有内核抢占时，spin_lock的实现。
 */
#define BUILD_LOCK_OPS(op, locktype)					\
void __lockfunc _##op##_lock(locktype##_t *lock)			\
{									\
	/**
	 * preempt_disable禁用内核抢占。
	 * 必须在测试spinlock的值前，先禁止抢占，原因很简单，在测试值时如果发生抢占会是什么后果。
	 */
	preempt_disable();						\
	for (;;) {							\
		/**
	     * 调用_raw_spin_trylock,它对自旋锁的slock字段进行原子性的测试和设置。
		 * 本质上它执行以下代码：
		 *     movb $0,%al
		 *     xchgb %al, slp->slock
		 * xchgb原子性的交换al和slp->slock内存单元的内容。如果原值>0，就返回1，否则返回0
		 * 换句话说，如果原来的锁是开着的，就关掉它，它返回成功标志。如果原来就是锁着的，再次设置锁标志，并返回0。
		 */
		if (likely(_raw_##op##_trylock(lock)))			\
			/**
		     * 如果旧值是正的，表示锁是打开的，宏结束，已经获得自旋锁了。
			 * 注意：返回后，本函数的一个负作用就是禁用抢占了。配对使用unlock时再打开抢占。
			 * 请想一下禁用抢占的必要性。
			 */
			break;						\
		/**
		 * 否则，无法获得自旋锁，就循环一直到其他CPU释放自旋锁。
		 * 在循环前，暂时打开preempt_enable。也就是说，在等待自旋锁的中间，进程是可能被抢占的。
		 */
		preempt_enable();					\
		/**
		 * break_lock表示有其他进程在等待锁。
		 * 拥有锁的进程可以判断这个标志，提前释放锁。
		 * 但是，哪个进程会判断这个标志呢？？
		 * 另外一个问题是：加判断做什么呢？不如果直接设置break_lock为1，效率还稍微高一点。
		 */
		if (!(lock)->break_lock)				\
			(lock)->break_lock = 1;				\
		/**
		 * 执行等待循环，cpu_relax简化成一条pause指令。
		 * 为什么要加入cpu_relax，是有原因的，表面上看，可以用一段死循环的汇编来代替这个循环
		 * 但是实际上是不能那样的的，那样会锁住总线，unlock想设置值都不能了。
		 * cpu_relax就是要让CPU休息一下，把总线暂时让出来。
		 */
		while (!op##_can_lock(lock) && (lock)->break_lock)	\
			cpu_relax();					\
		/**
		 * 上面的死循环lock的值已经变化了。那么关抢占后，再次调用_raw_spin_trylock
		 * 真正的获得锁还是在_raw_spin_trylock中。
		 */
		preempt_disable();					\
	}								\
}									\
									\
EXPORT_SYMBOL(_##op##_lock);						\
									\
unsigned long __lockfunc _##op##_lock_irqsave(locktype##_t *lock)	\
{									\
	unsigned long flags;						\
									\
	preempt_disable();						\
	for (;;) {							\
		local_irq_save(flags);					\
		if (likely(_raw_##op##_trylock(lock)))			\
			break;						\
		local_irq_restore(flags);				\
									\
		preempt_enable();					\
		if (!(lock)->break_lock)				\
			(lock)->break_lock = 1;				\
		while (!op##_can_lock(lock) && (lock)->break_lock)	\
			cpu_relax();					\
		preempt_disable();					\
	}								\
	return flags;							\
}									\
									\
EXPORT_SYMBOL(_##op##_lock_irqsave);					\
									\
void __lockfunc _##op##_lock_irq(locktype##_t *lock)			\
{									\
	_##op##_lock_irqsave(lock);					\
}									\
									\
EXPORT_SYMBOL(_##op##_lock_irq);					\
									\
void __lockfunc _##op##_lock_bh(locktype##_t *lock)			\
{									\
	unsigned long flags;						\
									\
	/*							*/	\
	/* Careful: we must exclude softirqs too, hence the	*/	\
	/* irq-disabling. We use the generic preemption-aware	*/	\
	/* function:						*/	\
	/**/								\
	flags = _##op##_lock_irqsave(lock);				\
	local_bh_disable();						\
	local_irq_restore(flags);					\
}									\
									\
EXPORT_SYMBOL(_##op##_lock_bh)

/*
 * Build preemption-friendly versions of the following
 * lock-spinning functions:
 *
 *         _[spin|read|write]_lock()
 *         _[spin|read|write]_lock_irq()
 *         _[spin|read|write]_lock_irqsave()
 *         _[spin|read|write]_lock_bh()
 */
BUILD_LOCK_OPS(spin, spinlock);
BUILD_LOCK_OPS(read, rwlock);
BUILD_LOCK_OPS(write, rwlock);

#endif /* CONFIG_PREEMPT */

void __lockfunc _spin_unlock(spinlock_t *lock)
{
	_raw_spin_unlock(lock);
	preempt_enable();
}
EXPORT_SYMBOL(_spin_unlock);
/**
 * 释放写锁。
 */
void __lockfunc _write_unlock(rwlock_t *lock)
{
	/**
	 * 调用汇编lock ; addl $0x01000000, rwlp把字段中的未锁标志置位。
	 */
	_raw_write_unlock(lock);
	/**
	 * 当然了，在获得锁时是禁用抢占的，此时要把抢占打开。
	 * 另外，注意它的顺序，是与lock时相反。
	 */
	preempt_enable();
}
EXPORT_SYMBOL(_write_unlock);

void __lockfunc _read_unlock(rwlock_t *lock)
{
	_raw_read_unlock(lock);
	preempt_enable();
}
EXPORT_SYMBOL(_read_unlock);

void __lockfunc _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	_raw_spin_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}
EXPORT_SYMBOL(_spin_unlock_irqrestore);

void __lockfunc _spin_unlock_irq(spinlock_t *lock)
{
	_raw_spin_unlock(lock);
	local_irq_enable();
	preempt_enable();
}
EXPORT_SYMBOL(_spin_unlock_irq);

void __lockfunc _spin_unlock_bh(spinlock_t *lock)
{
	_raw_spin_unlock(lock);
	preempt_enable();
	local_bh_enable();
}
EXPORT_SYMBOL(_spin_unlock_bh);

void __lockfunc _read_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
	_raw_read_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}
EXPORT_SYMBOL(_read_unlock_irqrestore);

void __lockfunc _read_unlock_irq(rwlock_t *lock)
{
	_raw_read_unlock(lock);
	local_irq_enable();
	preempt_enable();
}
EXPORT_SYMBOL(_read_unlock_irq);

void __lockfunc _read_unlock_bh(rwlock_t *lock)
{
	_raw_read_unlock(lock);
	preempt_enable();
	local_bh_enable();
}
EXPORT_SYMBOL(_read_unlock_bh);

void __lockfunc _write_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
	_raw_write_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}
EXPORT_SYMBOL(_write_unlock_irqrestore);

void __lockfunc _write_unlock_irq(rwlock_t *lock)
{
	_raw_write_unlock(lock);
	local_irq_enable();
	preempt_enable();
}
EXPORT_SYMBOL(_write_unlock_irq);

void __lockfunc _write_unlock_bh(rwlock_t *lock)
{
	_raw_write_unlock(lock);
	preempt_enable();
	local_bh_enable();
}
EXPORT_SYMBOL(_write_unlock_bh);

int __lockfunc _spin_trylock_bh(spinlock_t *lock)
{
	local_bh_disable();
	preempt_disable();
	if (_raw_spin_trylock(lock))
		return 1;

	preempt_enable();
	local_bh_enable();
	return 0;
}
EXPORT_SYMBOL(_spin_trylock_bh);

int in_lock_functions(unsigned long addr)
{
	/* Linker adds these: start and end of __lockfunc functions */
	extern char __lock_text_start[], __lock_text_end[];

	return addr >= (unsigned long)__lock_text_start
	&& addr < (unsigned long)__lock_text_end;
}
EXPORT_SYMBOL(in_lock_functions);
