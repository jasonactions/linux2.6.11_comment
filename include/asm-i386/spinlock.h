#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <asm/atomic.h>
#include <asm/rwlock.h>
#include <asm/page.h>
#include <linux/config.h>
#include <linux/compiler.h>

asmlinkage int printk(const char * fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

/*
 * Your basic SMP spinlocks, allowing only a single CPU anywhere
 */

typedef struct {
	/**
	 * 该字段表示自旋锁的状态，值为1表示未加锁，任何负数和0都表示加锁
	 */
	volatile unsigned int slock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned magic;
#endif
#ifdef CONFIG_PREEMPT
	/**
	 * 表示进程正在忙等待自旋锁。
	 * 只有内核支持SMP和内核抢占时才使用本标志。
	 */
	unsigned int break_lock;
#endif
} spinlock_t;

#define SPINLOCK_MAGIC	0xdead4ead

#ifdef CONFIG_DEBUG_SPINLOCK
#define SPINLOCK_MAGIC_INIT	, SPINLOCK_MAGIC
#else
#define SPINLOCK_MAGIC_INIT	/* */
#endif

#define SPIN_LOCK_UNLOCKED (spinlock_t) { 1 SPINLOCK_MAGIC_INIT }

/**
 * 把自旋锁置为1（未锁）
 */
#define spin_lock_init(x)	do { *(x) = SPIN_LOCK_UNLOCKED; } while(0)

/*
 * Simple spin lock operations.  There are two variants, one clears IRQ's
 * on the local processor, one does not.
 *
 * We make no fairness assumptions. They have a cost.
 */

/**
 * 如果自旋锁被置为1（未锁），返回0，否则返回1
 */
#define spin_is_locked(x)	(*(volatile signed char *)(&(x)->slock) <= 0)
/**
 * 等待，直到自旋锁变成都市（未锁）
 */
#define spin_unlock_wait(x)	do { barrier(); } while(spin_is_locked(x))

#define spin_lock_string \
	"\n1:\t" \
	/**
	 * decb递减自旋锁的值。它有lock前缀，因此是原子的。
	 */
	"lock ; decb %0\n\t" \
	/**
	 * 如果结果为0（不是负数），说明锁是打开的，跳到3f处继续执行。
	 */
	"jns 3f\n" \
	/**
	 * 否则，结果为负，说明锁是关闭的。就执行死循环，等待它的值变化。
	 * 需要注意的是rep后面跟了一句nop,这是不能省略的。否则，总线可能被锁死。
	 */
	"2:\t" \
	"rep;nop\n\t" \
	/**
	 * 比较lock值，直到它变化，才跳到开头，试图再次获得锁。
	 * 否则，继续死循环等lock值变化。
	 */
	"cmpb $0,%0\n\t" \
	"jle 2b\n\t" \
	"jmp 1b\n" \
	"3:\n\t"

#define spin_lock_string_flags \
	"\n1:\t" \
	"lock ; decb %0\n\t" \
	"jns 4f\n\t" \
	"2:\t" \
	"testl $0x200, %1\n\t" \
	"jz 3f\n\t" \
	"sti\n\t" \
	"3:\t" \
	"rep;nop\n\t" \
	"cmpb $0, %0\n\t" \
	"jle 3b\n\t" \
	"cli\n\t" \
	"jmp 1b\n" \
	"4:\n\t"

/*
 * This works. Despite all the confusion.
 * (except on PPro SMP or if we are using OOSTORE)
 * (PPro errata 66, 92)
 */

#if !defined(CONFIG_X86_OOSTORE) && !defined(CONFIG_X86_PPRO_FENCE)

#define spin_unlock_string \
	"movb $1,%0" \
		:"=m" (lock->slock) : : "memory"


static inline void _raw_spin_unlock(spinlock_t *lock)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(lock->magic != SPINLOCK_MAGIC);
	BUG_ON(!spin_is_locked(lock));
#endif
	__asm__ __volatile__(
		spin_unlock_string
	);
}

#else

#define spin_unlock_string \
	"xchgb %b0, %1" \
		:"=q" (oldval), "=m" (lock->slock) \
		:"0" (oldval) : "memory"

static inline void _raw_spin_unlock(spinlock_t *lock)
{
	char oldval = 1;
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(lock->magic != SPINLOCK_MAGIC);
	BUG_ON(!spin_is_locked(lock));
#endif
	__asm__ __volatile__(
		spin_unlock_string
	);
}

#endif

static inline int _raw_spin_trylock(spinlock_t *lock)
{
	char oldval;
	__asm__ __volatile__(
		"xchgb %b0,%1"
		:"=q" (oldval), "=m" (lock->slock)
		:"0" (0) : "memory");
	return oldval > 0;
}

/**
 * 对自旋锁的slock字段执行原子性的测试和设置操作。
 */
static inline void _raw_spin_lock(spinlock_t *lock)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	if (unlikely(lock->magic != SPINLOCK_MAGIC)) {
		printk("eip: %p\n", __builtin_return_address(0));
		BUG();
	}
#endif
	__asm__ __volatile__(
		spin_lock_string
		:"=m" (lock->slock) : : "memory");
}

static inline void _raw_spin_lock_flags (spinlock_t *lock, unsigned long flags)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	if (unlikely(lock->magic != SPINLOCK_MAGIC)) {
		printk("eip: %p\n", __builtin_return_address(0));
		BUG();
	}
#endif
	__asm__ __volatile__(
		spin_lock_string_flags
		:"=m" (lock->slock) : "r" (flags) : "memory");
}

/*
 * Read-write spinlocks, allowing multiple readers
 * but only one writer.
 *
 * NOTE! it is quite common to have readers in interrupts
 * but no interrupt writers. For those circumstances we
 * can "mix" irq-safe locks - any writer needs to get a
 * irq-safe write-lock, but readers can get non-irqsafe
 * read-locks.
 */
/**
 * 读写自旋锁
 */
typedef struct {
	/**
	 * 这个锁标志与自旋锁不一样，自旋锁的lock标志只能取0和1两种值。
	 * 读写自旋锁的lock分两部分：
	 *     0-23位：表示并发读的数量。数据以补码的形式存放。
	 *     24位：未锁标志。如果没有读或写时设置该，否则清0
	 * 注意：如果自旋锁为空（设置了未锁标志并且无读者），则lock字段为0x01000000
	 *     如果写者获得了锁，则lock为0x00000000（未锁标志清0，表示已经锁，但是无读者）
	 *     如果一个或者多个进程获得了读锁，那么lock的值为0x00ffffff,0x00fffffe等（未锁标志清0，后面跟读者数量的补码）
	 */
	volatile unsigned int lock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned magic;
#endif
#ifdef CONFIG_PREEMPT
	/**
	 * 表示进程正在忙等待自旋锁。
	 * 只有内核支持SMP和内核抢占时才使用本标志。
	 */
	unsigned int break_lock;
#endif
} rwlock_t;

#define RWLOCK_MAGIC	0xdeaf1eed

#ifdef CONFIG_DEBUG_SPINLOCK
#define RWLOCK_MAGIC_INIT	, RWLOCK_MAGIC
#else
#define RWLOCK_MAGIC_INIT	/* */
#endif

/**
 * 初始化读写自旋锁的lock字段为0x0100000（未锁），break_lock为0
 */
#define RW_LOCK_UNLOCKED (rwlock_t) { RW_LOCK_BIAS RWLOCK_MAGIC_INIT }

#define rwlock_init(x)	do { *(x) = RW_LOCK_UNLOCKED; } while(0)

/**
 * read_can_lock - would read_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define read_can_lock(x) ((int)(x)->lock > 0)

/**
 * write_can_lock - would write_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define write_can_lock(x) ((x)->lock == RW_LOCK_BIAS)

/*
 * On x86, we implement read-write locks as a 32-bit counter
 * with the high bit (sign) being the "contended" bit.
 *
 * The inline assembly is non-obvious. Think about it.
 *
 * Changed to use the same technique as rw semaphores.  See
 * semaphore.h for details.  -ben
 */
/* the spinlock helpers are in arch/i386/kernel/semaphore.c */

/**
 * 在没有配置内核抢占时，read_lock调用它。
 */
static inline void _raw_read_lock(rwlock_t *rw)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(rw->magic != RWLOCK_MAGIC);
#endif
	__build_read_lock(rw, "__read_lock_failed");
}

static inline void _raw_write_lock(rwlock_t *rw)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(rw->magic != RWLOCK_MAGIC);
#endif
	__build_write_lock(rw, "__write_lock_failed");
}

#define _raw_read_unlock(rw)		asm volatile("lock ; incl %0" :"=m" ((rw)->lock) : : "memory")
#define _raw_write_unlock(rw)	asm volatile("lock ; addl $" RW_LOCK_BIAS_STR ",%0":"=m" ((rw)->lock) : : "memory")

static inline int _raw_read_trylock(rwlock_t *lock)
{
	/**
	 * 将lock字段当成原子数进行访问。
	 * 不过，仅仅是对lock的访问是原子的。
	 * 函数并不是原子的，甚至在return 1前，lock值都可能变化。
	 */
	atomic_t *count = (atomic_t *)lock;
	/**
	 * 此处减1，是因为atomic_t是当成无符号数处理。
	 * 将它减1，其实是将读者数加一。请注意补码的特点。
	 */
	atomic_dec(count);

	/**
	 * 在return 1前，lock可能会变化，可是没有关系。
	 * 只有在递减前，lock值为负数或者>0，它的值才>=0
	 * 因为要让lock<0，只有当dec前，它的值为0才行。
	 * 只有一种情况lock才为0,就是有一个写者。
	 * 当然，有写者时，是不应该返回0，而应该返回0。
	 * 从理论上讲，这段代码也不是没有出错的可能：
	 *     假设有0x01000000个读者调用了read_lock，将一个空锁的lock值减成1了，而这时竟然没有一个进程调用unlock。
	 *     但是，有这种情况吗？你等得到这种情况发生吗？
	 */
	if (atomic_read(count) >= 0)
		return 1;
	/**
	 * 既然没有申请到读锁，那就恢复atomic_dec带来的影响吧。
	 */
	atomic_inc(count);
	return 0;
}

/**
 * 当内核支持抢占时，BUILD_LOCK_OPS宏产生的代码实现write_lock，
 * write_lock会调用它_raw_write_trylock
 */
static inline int _raw_write_trylock(rwlock_t *lock)
{
	/**
	 * 不论如何，都需要将lock转成atomic_t，这样对它的操作才能保证是绝对原子的。
	 */
	atomic_t *count = (atomic_t *)lock;
	/**
	 * 从lock中减去0x01000000
	 * 只有当lock==0x01000000时，才表示当前锁既然没有读者，也没有写者。
	 */
	if (atomic_sub_and_test(RW_LOCK_BIAS, count))
		return 1;
	/**
	 * 既然没有申请到写锁，就将sub的值恢复。
	 */
	atomic_add(RW_LOCK_BIAS, count);
	return 0;
}

#endif /* __ASM_SPINLOCK_H */
