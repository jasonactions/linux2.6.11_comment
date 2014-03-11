/*
 * workqueue.h --- work queue handling for Linux.
 */

#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/timer.h>
#include <linux/linkage.h>
#include <linux/bitops.h>

struct workqueue_struct;

/**
 * 工作队列中，每个被挂起函数的描述符
 */
struct work_struct {
	/**
	 * 如果函数已经在工作队列链表中，该字段值设为1，否则为0
	 */
	unsigned long pending;
	/**
	 * 指向挂起函数链表前一个或后一个元素的指针
	 */
	struct list_head entry;
	/**
	 * 挂起函数的地址
	 */
	void (*func)(void *);
	/**
	 * 传递给挂起函数的参数
	 */
	void *data;
	/**
	 * 通常指向cpu_workqueue_struct结构
	 */
	void *wq_data;
	/**
	 * 用于延迟挂起函数执行的软定时器
	 */
	struct timer_list timer;
};

#define __WORK_INITIALIZER(n, f, d) {				\
        .entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	.data = (d),						\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}

#define DECLARE_WORK(n, f, d)					\
	struct work_struct n = __WORK_INITIALIZER(n, f, d)

/*
 * initialize a work-struct's func and data pointers:
 */
#define PREPARE_WORK(_work, _func, _data)			\
	do {							\
		(_work)->func = _func;				\
		(_work)->data = _data;				\
	} while (0)

/*
 * initialize all of a work-struct:
 */
#define INIT_WORK(_work, _func, _data)				\
	do {							\
		INIT_LIST_HEAD(&(_work)->entry);		\
		(_work)->pending = 0;				\
		PREPARE_WORK((_work), (_func), (_data));	\
		init_timer(&(_work)->timer);			\
	} while (0)

extern struct workqueue_struct *__create_workqueue(const char *name,
						    int singlethread);

/**
 * 接收一个字符串作为参数，返回新创建工作队列的地址，该函数还创建n个工作者线程。
 * 并根据传递给函数的字符串为工作者线程命名。
 */
#define create_workqueue(name) __create_workqueue((name), 0)
/**
 * 与create_workqueue相似，但是不管系统中有多少个CPU，都只创建一个工作者线程。
 */
#define create_singlethread_workqueue(name) __create_workqueue((name), 1)

extern void destroy_workqueue(struct workqueue_struct *wq);

extern int FASTCALL(queue_work(struct workqueue_struct *wq, struct work_struct *work));
extern int FASTCALL(queue_delayed_work(struct workqueue_struct *wq, struct work_struct *work, unsigned long delay));
extern void FASTCALL(flush_workqueue(struct workqueue_struct *wq));

extern int FASTCALL(schedule_work(struct work_struct *work));
extern int FASTCALL(schedule_delayed_work(struct work_struct *work, unsigned long delay));

extern int schedule_delayed_work_on(int cpu, struct work_struct *work, unsigned long delay);
extern void flush_scheduled_work(void);
extern int current_is_keventd(void);
extern int keventd_up(void);

extern void init_workqueues(void);

/*
 * Kill off a pending schedule_delayed_work().  Note that the work callback
 * function may still be running on return from cancel_delayed_work().  Run
 * flush_scheduled_work() to wait on it.
 */
/**
 * queue_delayed_work依靠软定时器把work_struct插入工作队列链表中。
 * 如果work_struct某个时候还没有插入队列（定时器还没有运行），cancel_delayed_work就删除这个工作队列函数。
 * xie.baoyou注：也就是说，定时器不生效了。
 */
static inline int cancel_delayed_work(struct work_struct *work)
{
	int ret;

	ret = del_timer_sync(&work->timer);
	if (ret)
		clear_bit(0, &work->pending);
	return ret;
}

#endif
