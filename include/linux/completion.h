#ifndef __LINUX_COMPLETION_H
#define __LINUX_COMPLETION_H

/*
 * (C) Copyright 2001 Linus Torvalds
 *
 * Atomic wait-for-completion handler data structures.
 * See kernel/sched.c for details.
 */

#include <linux/wait.h>

/**
 * 补充原语。
 * 它的功能与信号量类似。
 * 如果在SMP上，线程A创建一个EMPTY的MUTEX，并把其地址传给进程B。
 * 然后A在其上执行DOWN，被唤醒后即撤销信号量，另一进程B在其上执行UP
 * 但是，信号量允许up和down在同一信号量上并发进行。这就可能造成B访问不存在的结构。
 * 如果改变信号量的up和down，会影响性能，所以为了这种情况，引入补充原语。
 * 二者的真正区别在于如何使用wait上的自旋锁。
 * 补充原语确保complete和wait_for_completion不会同时执行。
 * 信号量的自旋锁用于避免并发执行down使得信号量的数据结构被弄乱。
 */
struct completion {
	unsigned int done;
	wait_queue_head_t wait;
};

#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }

#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)

static inline void init_completion(struct completion *x)
{
	x->done = 0;
	init_waitqueue_head(&x->wait);
}

extern void FASTCALL(wait_for_completion(struct completion *));
extern int FASTCALL(wait_for_completion_interruptible(struct completion *x));
extern unsigned long FASTCALL(wait_for_completion_timeout(struct completion *x,
						   unsigned long timeout));
extern unsigned long FASTCALL(wait_for_completion_interruptible_timeout(
			struct completion *x, unsigned long timeout));

extern void FASTCALL(complete(struct completion *));
extern void FASTCALL(complete_all(struct completion *));

#define INIT_COMPLETION(x)	((x).done = 0)

#endif
