/* interrupt.h */
#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/preempt.h>
#include <linux/cpumask.h>
#include <linux/hardirq.h>
#include <asm/atomic.h>
#include <asm/ptrace.h>
#include <asm/system.h>

/*
 * For 2.4.x compatibility, 2.4.x can use
 *
 *	typedef void irqreturn_t;
 *	#define IRQ_NONE
 *	#define IRQ_HANDLED
 *	#define IRQ_RETVAL(x)
 *
 * To mix old-style and new-style irq handler returns.
 *
 * IRQ_NONE means we didn't handle it.
 * IRQ_HANDLED means that we did have a valid interrupt and handled it.
 * IRQ_RETVAL(x) selects on the two depending on x being non-zero (for handled)
 */
typedef int irqreturn_t;

#define IRQ_NONE	(0)
#define IRQ_HANDLED	(1)
#define IRQ_RETVAL(x)	((x) != 0)

struct irqaction {
	irqreturn_t (*handler)(int, void *, struct pt_regs *);
	unsigned long flags;
	cpumask_t mask;
	const char *name;
	void *dev_id;
	struct irqaction *next;
	int irq;
	struct proc_dir_entry *dir;
};

extern irqreturn_t no_action(int cpl, void *dev_id, struct pt_regs *regs);
extern int request_irq(unsigned int,
		       irqreturn_t (*handler)(int, void *, struct pt_regs *),
		       unsigned long, const char *, void *);
extern void free_irq(unsigned int, void *);


#ifdef CONFIG_GENERIC_HARDIRQS
extern void disable_irq_nosync(unsigned int irq);
extern void disable_irq(unsigned int irq);
extern void enable_irq(unsigned int irq);
#endif

/*
 * Temporary defines for UP kernels, until all code gets fixed.
 */
#ifndef CONFIG_SMP
static inline void __deprecated cli(void)
{
	local_irq_disable();
}
static inline void __deprecated sti(void)
{
	local_irq_enable();
}
static inline void __deprecated save_flags(unsigned long *x)
{
	local_save_flags(*x);
}
#define save_flags(x) save_flags(&x);
static inline void __deprecated restore_flags(unsigned long x)
{
	local_irq_restore(x);
}

static inline void __deprecated save_and_cli(unsigned long *x)
{
	local_irq_save(*x);
}
#define save_and_cli(x)	save_and_cli(&x)
#endif /* CONFIG_SMP */

/* SoftIRQ primitives.  */
#define local_bh_disable() \
		do { add_preempt_count(SOFTIRQ_OFFSET); barrier(); } while (0)
#define __local_bh_enable() \
		do { barrier(); sub_preempt_count(SOFTIRQ_OFFSET); } while (0)

extern void local_bh_enable(void);

/* PLEASE, avoid to allocate new softirqs, if you need not _really_ high
   frequency threaded job scheduling. For almost all the purposes
   tasklets are more than enough. F.e. all serial device BHs et
   al. should be converted to tasklets, not to softirqs.
 */

enum
{
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	SCSI_SOFTIRQ,
	TASKLET_SOFTIRQ
};

/* softirq mask and active fields moved to irq_cpustat_t in
 * asm/hardirq.h to get better cache usage.  KAO
 */

struct softirq_action
{
	/**
	 * 软中断处理函数
	 */
	void	(*action)(struct softirq_action *);
	/**
	 * 回传给软中断处理函数的数据。
	 */
	void	*data;
};

asmlinkage void do_softirq(void);
extern void open_softirq(int nr, void (*action)(struct softirq_action*), void *data);
extern void softirq_init(void);
#define __raise_softirq_irqoff(nr) do { local_softirq_pending() |= 1UL << (nr); } while (0)
extern void FASTCALL(raise_softirq_irqoff(unsigned int nr));
extern void FASTCALL(raise_softirq(unsigned int nr));


/* Tasklets --- multithreaded analogue of BHs.

   Main feature differing them of generic softirqs: tasklet
   is running only on one CPU simultaneously.

   Main feature differing them of BHs: different tasklets
   may be run simultaneously on different CPUs.

   Properties:
   * If tasklet_schedule() is called, then tasklet is guaranteed
     to be executed on some cpu at least once after this.
   * If the tasklet is already scheduled, but its excecution is still not
     started, it will be executed only once.
   * If this tasklet is already running on another CPU (or schedule is called
     from tasklet itself), it is rescheduled for later.
   * Tasklet is strictly serialized wrt itself, but not
     wrt another tasklets. If client needs some intertask synchronization,
     he makes it with spinlocks.
 */

/**
 * taskletra描述符
 */
struct tasklet_struct
{
	/**
	 * 指向下一个描述符
	 */
	struct tasklet_struct *next;
	/**
	 * tasklet的状态。
	 * 
	 */
	unsigned long state;
	/**
	 * 锁计数器。
	 */
	atomic_t count;
	/**
	 * tasklet功能函数
	 */
	void (*func)(unsigned long);
	/**
	 * 传给功能函数的参数。
	 */
	unsigned long data;
};

#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }


/**
 * tasklet状态
 */
enum
{
	/**
	 * 该标志被设置时，表示tasklet是挂起的（曾被调度执行）。
	 * 也意味着它被插入到tasklet_vec或者tasklet_hi_vec中
	 */
	TASKLET_STATE_SCHED,	/* Tasklet is scheduled for execution */
	/**
	 * 该标志被设置时，表示tasklet正在被执行。在UP上不使用它。
	 * 它被用来确保tasklet不会在多个CPU上同时执行。
	 */
	TASKLET_STATE_RUN	/* Tasklet is running (SMP only) */
};

#ifdef CONFIG_SMP
static inline int tasklet_trylock(struct tasklet_struct *t)
{
	return !test_and_set_bit(TASKLET_STATE_RUN, &(t)->state);
}

static inline void tasklet_unlock(struct tasklet_struct *t)
{
	smp_mb__before_clear_bit(); 
	clear_bit(TASKLET_STATE_RUN, &(t)->state);
}

static inline void tasklet_unlock_wait(struct tasklet_struct *t)
{
	while (test_bit(TASKLET_STATE_RUN, &(t)->state)) { barrier(); }
}
#else
#define tasklet_trylock(t) 1
#define tasklet_unlock_wait(t) do { } while (0)
#define tasklet_unlock(t) do { } while (0)
#endif

extern void FASTCALL(__tasklet_schedule(struct tasklet_struct *t));

/**
 * 调度tasklet，将其挂到软中断中。
 */
static inline void tasklet_schedule(struct tasklet_struct *t)
{
	/**
	 * 检查任务的TASKLET_STATE_SCHED标志，如果已经设置，就退出。
	 * 设置了TASKLET_STATE_SCHED，表示它已经被调度到软中断上了，现在处于挂起状态
	 * 不能(也不用)再调度了。
	 *
	 * 既然TASKLET_STATE_SCHED标志已经保证一个tasklet不会在多个CPU上同时被插入到链表中，为什么还需要TASKLET_STATE_RUN标志呢？
	 * 这是因为在调用回调函数前，TASKLET_STATE_SCHED可能被清除，如果只有TASKLET_STATE_SCHED这个标志的话，可能还是会造成过程重入。
	 */
	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
		__tasklet_schedule(t);
}

extern void FASTCALL(__tasklet_hi_schedule(struct tasklet_struct *t));

static inline void tasklet_hi_schedule(struct tasklet_struct *t)
{
	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
		__tasklet_hi_schedule(t);
}


/**
 * 禁止tasklet，并不等待被禁止的tasklet运行结束
 */
static inline void tasklet_disable_nosync(struct tasklet_struct *t)
{
	atomic_inc(&t->count);
	smp_mb__after_atomic_inc();
}

/**
 * 禁止tasklet，并且等待被禁止的tasklet运行结束
 */
static inline void tasklet_disable(struct tasklet_struct *t)
{
	tasklet_disable_nosync(t);
	tasklet_unlock_wait(t);
	smp_mb();
}

/**
 * 激活tasklet
 */
static inline void tasklet_enable(struct tasklet_struct *t)
{
	smp_mb__before_atomic_dec();
	atomic_dec(&t->count);
}

static inline void tasklet_hi_enable(struct tasklet_struct *t)
{
	smp_mb__before_atomic_dec();
	atomic_dec(&t->count);
}

extern void tasklet_kill(struct tasklet_struct *t);
extern void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu);
extern void tasklet_init(struct tasklet_struct *t,
			 void (*func)(unsigned long), unsigned long data);

/*
 * Autoprobing for irqs:
 *
 * probe_irq_on() and probe_irq_off() provide robust primitives
 * for accurate IRQ probing during kernel initialization.  They are
 * reasonably simple to use, are not "fooled" by spurious interrupts,
 * and, unlike other attempts at IRQ probing, they do not get hung on
 * stuck interrupts (such as unused PS2 mouse interfaces on ASUS boards).
 *
 * For reasonably foolproof probing, use them as follows:
 *
 * 1. clear and/or mask the device's internal interrupt.
 * 2. sti();
 * 3. irqs = probe_irq_on();      // "take over" all unassigned idle IRQs
 * 4. enable the device and cause it to trigger an interrupt.
 * 5. wait for the device to interrupt, using non-intrusive polling or a delay.
 * 6. irq = probe_irq_off(irqs);  // get IRQ number, 0=none, negative=multiple
 * 7. service the device to clear its pending interrupt.
 * 8. loop again if paranoia is required.
 *
 * probe_irq_on() returns a mask of allocated irq's.
 *
 * probe_irq_off() takes the mask as a parameter,
 * and returns the irq number which occurred,
 * or zero if none occurred, or a negative irq number
 * if more than one irq occurred.
 */

#if defined(CONFIG_GENERIC_HARDIRQS) && !defined(CONFIG_GENERIC_IRQ_PROBE) 
static inline unsigned long probe_irq_on(void)
{
	return 0;
}
static inline int probe_irq_off(unsigned long val)
{
	return 0;
}
static inline unsigned int probe_irq_mask(unsigned long val)
{
	return 0;
}
#else
extern unsigned long probe_irq_on(void);	/* returns 0 on failure */
extern int probe_irq_off(unsigned long);	/* returns 0 or negative on failure */
extern unsigned int probe_irq_mask(unsigned long);	/* returns mask of ISA interrupts */
#endif

#endif
