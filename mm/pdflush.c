/*
 * mm/pdflush.c - worker threads for writing back filesystem data
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * 09Apr2002	akpm@zip.com.au
 *		Initial version
 * 29Feb2004	kaos@sgi.com
 *		Move worker thread creation to kthread to avoid chewing
 *		up stack space with nested calls to kernel_thread.
 */

#include <linux/sched.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>		// Needed by writeback.h
#include <linux/writeback.h>	// Prototypes pdflush_operation()
#include <linux/kthread.h>


/*
 * Minimum and maximum number of pdflush instances
 */
#define MIN_PDFLUSH_THREADS	2
#define MAX_PDFLUSH_THREADS	8

static void start_one_pdflush_thread(void);


/*
 * The pdflush threads are worker threads for writing back dirty data.
 * Ideally, we'd like one thread per active disk spindle.  But the disk
 * topology is very hard to divine at this level.   Instead, we take
 * care in various places to prevent more than one pdflush thread from
 * performing writeback against a single filesystem.  pdflush threads
 * have the PF_FLUSHER flag set in current->flags to aid in this.
 */

/*
 * All the pdflush threads.  Protected by pdflush_lock
 */
/**
 * 所有pdflush内核线程的描述符链表。通过pdflush_lock自旋锁保护。
 */
static LIST_HEAD(pdflush_list);
static DEFINE_SPINLOCK(pdflush_lock);

/*
 * The count of currently-running pdflush threads.  Protected
 * by pdflush_lock.
 *
 * Readable by sysctl, but not writable.  Published to userspace at
 * /proc/sys/vm/nr_pdflush_threads.
 */
/**
 * 存放空闲pdflush线程的总数。
 */
int nr_pdflush_threads = 0;

/*
 * The time at which the pdflush thread pool last went empty
 */
/**
 * pdflush线程链表变为空的时间(以jiffies表示)
 */
static unsigned long last_empty_jifs;

/*
 * The pdflush thread.
 *
 * Thread pool management algorithm:
 * 
 * - The minimum and maximum number of pdflush instances are bound
 *   by MIN_PDFLUSH_THREADS and MAX_PDFLUSH_THREADS.
 * 
 * - If there have been no idle pdflush instances for 1 second, create
 *   a new one.
 * 
 * - If the least-recently-went-to-sleep pdflush thread has been asleep
 *   for more than one second, terminate a thread.
 */

/*
 * A structure for passing work to a pdflush thread.  Also for passing
 * state information between pdflush threads.  Protected by pdflush_lock.
 */
/**
 * 描述pdflush线程的描述符
 */
struct pdflush_work {
	/**
	 * 指向内核线程描述符的指针
	 */
	struct task_struct *who;	/* The thread */
	/**
	 * 内核线程所执行的回调函数。
	 */
	void (*fn)(unsigned long);	/* A callback function */
	/**
	 * 给回调函数的参数。
	 */
	unsigned long arg0;		/* An argument to the callback */
	/**
	 * 通过此结构链接到pdflush_list。
	 */
	struct list_head list;		/* On pdflush_list, when idle */
	/**
	 * 内核线程可用的时间。
	 */
	unsigned long when_i_went_to_sleep;
};

/**
 * pdflus内核线程的执行函数。
 */
static int __pdflush(struct pdflush_work *my_work)
{
	current->flags |= PF_FLUSHER;
	my_work->fn = NULL;
	my_work->who = current;
	INIT_LIST_HEAD(&my_work->list);

	spin_lock_irq(&pdflush_lock);
	nr_pdflush_threads++;
	for ( ; ; ) {
		struct pdflush_work *pdf;

		/**
		 *  pdflush线程刚执行时，即将自己插入空闲链表，并开始睡眠。
		 */
		set_current_state(TASK_INTERRUPTIBLE);
		list_move(&my_work->list, &pdflush_list);
		/**
		 * 进程开始睡眠时间
		 */
		my_work->when_i_went_to_sleep = jiffies;
		spin_unlock_irq(&pdflush_lock);

		schedule();
		if (try_to_freeze(PF_FREEZE)) {
			spin_lock_irq(&pdflush_lock);
			continue;
		}

		spin_lock_irq(&pdflush_lock);
		if (!list_empty(&my_work->list)) {
			printk("pdflush: bogus wakeup!\n");
			my_work->fn = NULL;
			continue;
		}
		if (my_work->fn == NULL) {
			printk("pdflush: NULL work function\n");
			continue;
		}
		spin_unlock_irq(&pdflush_lock);

		/**
		 * 被其他过程唤醒后，执行回调函数进行刷新脏页。
		 */
		(*my_work->fn)(my_work->arg0);

		/*
		 * Thread creation: For how long have there been zero
		 * available threads?
		 */
		/**
		 * pdflush_list链表中的最后一项对应的pdflush内核线程空闲时间超过了1秒
		 */
		if (jiffies - last_empty_jifs > 1 * HZ) {
			/* unlocked list_empty() test is OK here */
			if (list_empty(&pdflush_list)) {/* 空闲链表为空 */
				/* unlocked test is OK here */
				/**
				 * 系统中的pdflush线程数量小于8个，就新建一个pdflush线程。
				 */
				if (nr_pdflush_threads < MAX_PDFLUSH_THREADS)
					start_one_pdflush_thread();
			}
		}

		spin_lock_irq(&pdflush_lock);
		my_work->fn = NULL;

		/*
		 * Thread destruction: For how long has the sleepiest
		 * thread slept?
		 */
		if (list_empty(&pdflush_list))
			continue;
		if (nr_pdflush_threads <= MIN_PDFLUSH_THREADS)
			continue;
		pdf = list_entry(pdflush_list.prev, struct pdflush_work, list);
		/**
		 * 如果空闲线程链表中上一个线程的空闲时间超过1秒，就退出线程。
		 */
		if (jiffies - pdf->when_i_went_to_sleep > 1 * HZ) {
			/* Limit exit rate */
			pdf->when_i_went_to_sleep = jiffies;
			break;					/* exeunt */
		}
	}
	nr_pdflush_threads--;
	spin_unlock_irq(&pdflush_lock);
	return 0;
}

/*
 * Of course, my_work wants to be just a local in __pdflush().  It is
 * separated out in this manner to hopefully prevent the compiler from
 * performing unfortunate optimisations against the auto variables.  Because
 * these are visible to other tasks and CPUs.  (No problem has actually
 * been observed.  This is just paranoia).
 */
static int pdflush(void *dummy)
{
	struct pdflush_work my_work;

	/*
	 * pdflush can spend a lot of time doing encryption via dm-crypt.  We
	 * don't want to do that at keventd's priority.
	 */
	set_user_nice(current, 0);
	return __pdflush(&my_work);
}

/*
 * Attempt to wake up a pdflush thread, and get it to do some work for you.
 * Returns zero if it indeed managed to find a worker thread, and passed your
 * payload to it.
 */
/**
 * 激活空闲的pdflush线程。
 * fn:		由pdflush执行的函数。
 * arg0:	参数
 */
int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0)
{
	unsigned long flags;
	int ret = 0;

	if (fn == NULL)
		BUG();		/* Hard to diagnose if it's deferred */

	spin_lock_irqsave(&pdflush_lock, flags);
	if (list_empty(&pdflush_list)) {/* 没有空闲的pdflush线程 */
		spin_unlock_irqrestore(&pdflush_lock, flags);
		ret = -1;
	} else {
		struct pdflush_work *pdf;

		/**
		 * 从空闲链表中取出第一个空闲pdflush线程。
		 */
		pdf = list_entry(pdflush_list.next, struct pdflush_work, list);
		list_del_init(&pdf->list);
		if (list_empty(&pdflush_list))
			last_empty_jifs = jiffies;
		/**
		 * 设置内核线程的回调函数。
		 */
		pdf->fn = fn;
		pdf->arg0 = arg0;
		/**
		 * 唤醒空闲线程。
		 */
		wake_up_process(pdf->who);
		spin_unlock_irqrestore(&pdflush_lock, flags);
	}
	return ret;
}

static void start_one_pdflush_thread(void)
{
	kthread_run(pdflush, NULL, "pdflush");
}

static int __init pdflush_init(void)
{
	int i;

	for (i = 0; i < MIN_PDFLUSH_THREADS; i++)
		start_one_pdflush_thread();
	return 0;
}

module_init(pdflush_init);
