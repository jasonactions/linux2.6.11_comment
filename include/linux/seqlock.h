#ifndef __LINUX_SEQLOCK_H
#define __LINUX_SEQLOCK_H
/*
 * Reader/writer consistent mechanism without starving writers. This type of
 * lock for data where the reader wants a consitent set of information
 * and is willing to retry if the information changes.  Readers never
 * block but they may have to retry if a writer is in
 * progress. Writers do not wait for readers. 
 *
 * This is not as cache friendly as brlock. Also, this will not work
 * for data that contains pointers, because any writer could
 * invalidate a pointer that a reader was following.
 *
 * Expected reader usage:
 * 	do {
 *	    seq = read_seqbegin(&foo);
 * 	...
 *      } while (read_seqretry(&foo, seq));
 *
 *
 * On non-SMP the spin locks disappear but the writer still needs
 * to increment the sequence variables because an interrupt routine could
 * change the state of the data.
 *
 * Based on x86_64 vsyscall gettimeofday 
 * by Keith Owens and Andrea Arcangeli
 */

#include <linux/config.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>

/**
 * 顺序锁描述符。
 */
typedef struct {
	/**
	 * 顺序计数器。每个读者需要在读数据前后两次读顺序计数器。只有在这个值没有变化时
	 * 才说明读取到的数据是有效的。
	 */
	unsigned sequence;
	/**
	 * 保护结构的自旋锁。
	 */
	spinlock_t lock;
} seqlock_t;

/*
 * These macros triggered gcc-3.x compile-time problems.  We think these are
 * OK now.  Be cautious.
 */
/**
 * 顺序锁的初始值，表示未上锁状态。
 */
#define SEQLOCK_UNLOCKED { 0, SPIN_LOCK_UNLOCKED }
/**
 * 将顺序锁初始化成未上锁状态。
 */
#define seqlock_init(x)	do { *(x) = (seqlock_t) SEQLOCK_UNLOCKED; } while (0)


/* Lock out other writers and update the count.
 * Acts like a normal spin_lock/unlock.
 * Don't need preempt_disable() because that is in the spin_lock already.
 */
/**
 * 为写获得顺序锁。
 */
static inline void write_seqlock(seqlock_t *sl)
{
	/**
	 * 获得自旋锁后将顺序值加一。
	 * 注意，在unlock时也会加一。
	 * 这样，只要读者和写者交错执行，就会造成读者重复读者，直到写者退出。
	 * 请再注意spin_lock和spin_unlock的用法。并且spin_lock会禁用抢占。
	 * 不禁用抢占当然会有问题。
	 */
	spin_lock(&sl->lock);
	++sl->sequence;
	smp_wmb();			
}	

/**
 * 释放写顺序锁
 */
static inline void write_sequnlock(seqlock_t *sl) 
{
	smp_wmb();
	/**
	 * 再将顺序值加一，这样，如果一个控制路径在读内核数据时，写锁重新写入值了。
	 * 它就会判断到值已经发了变化，会再读一次新值。
	 */
	sl->sequence++;
	spin_unlock(&sl->lock);
}

static inline int write_tryseqlock(seqlock_t *sl)
{
	int ret = spin_trylock(&sl->lock);

	if (ret) {
		++sl->sequence;
		smp_wmb();			
	}
	return ret;
}

/* Start of read calculation -- fetch last complete writer token */
/**
 * 和read_seqretry配对使用。
 * 它返回当前顺序号。
 */
static inline unsigned read_seqbegin(const seqlock_t *sl)
{
	unsigned ret = sl->sequence;
	smp_rmb();
	return ret;
}

/* Test if reader processed invalid data.
 * If initial values is odd, 
 *	then writer had already started when section was entered
 * If sequence value changed
 *	then writer changed data while in section
 *    
 * Using xor saves one conditional branch.
 */
/**
 * 判断是否有写者改变了顺序锁
 */
static inline int read_seqretry(const seqlock_t *sl, unsigned iv)
{
	smp_rmb();
	/**
	 * iv为奇数，说明在读者调用read_seqbegin后，有写者更新了数据结构。
	 * 写者调用write_seqlock后，iv一定是奇数。直到write_sequnlock才会变成偶数。
	 * sl->sequence ^ iv是判断read_seqbegin的值是否发生了变化。
	 * 要判断这两种情况，是因为：read_seqbegin和write_seqlock的调用顺序不一定。
	 * 可能是write_seqlock先调用，也可能是read_seqbegin先调用。
	 */
	return (iv & 1) | (sl->sequence ^ iv);
}


/*
 * Version using sequence counter only.
 * This can be used when code has its own mutex protecting the
 * updating starting before the write_seqcountbeqin() and ending
 * after the write_seqcount_end().
 */

typedef struct seqcount {
	unsigned sequence;
} seqcount_t;

#define SEQCNT_ZERO { 0 }
#define seqcount_init(x)	do { *(x) = (seqcount_t) SEQCNT_ZERO; } while (0)

/* Start of read using pointer to a sequence counter only.  */
static inline unsigned read_seqcount_begin(const seqcount_t *s)
{
	unsigned ret = s->sequence;
	smp_rmb();
	return ret;
}

/* Test if reader processed invalid data.
 * Equivalent to: iv is odd or sequence number has changed.
 *                (iv & 1) || (*s != iv)
 * Using xor saves one conditional branch.
 */
static inline int read_seqcount_retry(const seqcount_t *s, unsigned iv)
{
	smp_rmb();
	return (iv & 1) | (s->sequence ^ iv);
}


/*
 * Sequence counter only version assumes that callers are using their
 * own mutexing.
 */
static inline void write_seqcount_begin(seqcount_t *s)
{
	s->sequence++;
	smp_wmb();
}

static inline void write_seqcount_end(seqcount_t *s)
{
	smp_wmb();
	s->sequence++;
}

/*
 * Possible sw/hw IRQ protected versions of the interfaces.
 */
#define write_seqlock_irqsave(lock, flags)				\
	do { local_irq_save(flags); write_seqlock(lock); } while (0)
#define write_seqlock_irq(lock)						\
	do { local_irq_disable();   write_seqlock(lock); } while (0)
#define write_seqlock_bh(lock)						\
        do { local_bh_disable();    write_seqlock(lock); } while (0)

#define write_sequnlock_irqrestore(lock, flags)				\
	do { write_sequnlock(lock); local_irq_restore(flags); } while(0)
#define write_sequnlock_irq(lock)					\
	do { write_sequnlock(lock); local_irq_enable(); } while(0)
#define write_sequnlock_bh(lock)					\
	do { write_sequnlock(lock); local_bh_enable(); } while(0)

#define read_seqbegin_irqsave(lock, flags)				\
	({ local_irq_save(flags);   read_seqbegin(lock); })

#define read_seqretry_irqrestore(lock, iv, flags)			\
	({								\
		int ret = read_seqretry(lock, iv);			\
		local_irq_restore(flags);				\
		ret;							\
	})

#endif /* __LINUX_SEQLOCK_H */
