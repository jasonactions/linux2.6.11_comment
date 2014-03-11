/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 * Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>

#include <asm/irq.h>
/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
 */

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif

/**
 * 所有的软中断，目前使用了前六个。数组的下标就是软中断的优先级。
 * 下标越低，优先级越高。
 */
static struct softirq_action softirq_vec[32] __cacheline_aligned_in_smp;

static DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static inline void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __get_cpu_var(ksoftirqd);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}

/*
 * We restart softirq processing MAX_SOFTIRQ_RESTART times,
 * and we fall back to softirqd after that.
 *
 * This number has been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_RESTART 10

/**
 * __do_softirq的帮助函数，处理挂起的软中断
 */
asmlinkage void __do_softirq(void)
{
	struct softirq_action *h;
	__u32 pending;
	/**
	 * 最多处理MAX_SOFTIRQ_RESTART次（而不是MAX_SOFTIRQ_RESTART个）软中断，超过的软中断留到内核线程处理。
	 * 当然，内核线程的优先级不一定高，至少可能比我们的一些实时线程低。
	 */
	int max_restart = MAX_SOFTIRQ_RESTART;
	int cpu;

	/**
	 * 复制软中断掩码到局部变量中，这是有必要的。
	 * 因为local_softirq_pending中的值在开中断后将不再可靠。我们必须先将它保存起来。
	 */
	pending = local_softirq_pending();

	/**
	 * 在do_softirq中已经调用了local_irq_save(flags);
	 * 又在这里调用local_bh_disable();，看起来有违常识
	 * 不过，这是非常有用的：这是因为，我们调用软中断处理钩子时，这些钩子一般运行在开中断状态下。
	 * 所以执行本过程时，可能会产生新中断。
	 * 当do_irq调用irq_exit宏时，可能有另外一个__do_softirq实例正在执行。
	 * 由于软中断在某个CPU上必须串行执行，因此，第一个实例调用local_bh_disable，第二个实例就会在一进入do_softirq时就退出。
	 * 另外，需要注意的是：local_irq_save是关本地CPU的中断，而local_bh_disable是增加抢占计数中的软中断计数。
	 * local_bh_disable才是避免软中断在同一个CPU上重入的关键。
	 */
	local_bh_disable();
	cpu = smp_processor_id();
restart:
	/* Reset the pending bitmask before enabling irqs */
	/**
	 * 清除软中断标志。必须要在local_irq_enable前清除。
	 */
	local_softirq_pending() = 0;

	/**
	 * 强开中断，这是为数不多的强开中断的地方。
	 */
	local_irq_enable();

	/**
	 * 这段代码是根据pending标志，调用软中断处理函数。简单明了，不用多讲。
	 */
	h = softirq_vec;

	do {
		if (pending & 1) {
			h->action(h);
			rcu_bh_qsctr_inc(cpu);
		}
		h++;
		pending >>= 1;
	} while (pending);

	/**
	 * 强关中断
	 */
	local_irq_disable();

	/**
	 * 检查在软中断执行期间，是否有新的软中断挂起了。
	 */
	pending = local_softirq_pending();
	/**
	 * 检查次数是有限的，这是为了避免用户态线程长时间得不到执行。
	 */
	if (pending && --max_restart)
		goto restart;

	/**
	 * 运行到这里，说明要么是没有挂起的软中断了，要么是检查次数超过10次了。
	 */

	/**
	 * 还有挂起的软中断，说明我们已经检查很多次了，都还有软中断，
	 * 那么对不起，内核罢工了，让ksoftirqd内核线程来接手吧。
	 * 用户态线程还等待着运行呢。
	 * xie.baoyou注：但是让人不解的是：回到用户态又能做什么呢？既然中断这么频繁，不是马上又回来么？？？？
	 */
	if (pending)
		wakeup_softirqd();

	/**
	 * 既然一次执行完了，让把软中断计数减1吧，要是马上又来中断，又产生软中断，可以放心进入本函数了。
	 * 不用担心重入了。
	 */
	__local_bh_enable();
}

#ifndef __ARCH_HAS_DO_SOFTIRQ

asmlinkage void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	pending = local_softirq_pending();

	if (pending)
		__do_softirq();

	local_irq_restore(flags);
}

EXPORT_SYMBOL(do_softirq);

#endif

/**
 * 激活本地CPU的软中断
 */
void local_bh_enable(void)
{
	WARN_ON(irqs_disabled());
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
 	/**
 	 * 将preempt_count中，softirq对应的计数器减一。
 	 * 注意，这里不是sub_preempt_count(SOFTIRQ_OFFSET);
 	 * 所以，它还会将抢占计数加1，以禁止抢占。
 	 * 换句话说，它将softirq对应位减一，同时将抢占计数加一。
 	 * 除非抢占计数达到了SOFTIRQ_OFFSET - 1,会吗？可能永远等不到那个时候。
 	 */
 	sub_preempt_count(SOFTIRQ_OFFSET - 1);

	/**
	 * 既没有在中断上下文，又有软中断被挂起，就执行软中断
	 */
	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	/**
	 * 将抢占计数减一，还原sub_preempt_count(SOFTIRQ_OFFSET - 1);一句对抢占计数的影响。
	 */
	dec_preempt_count();
	/**
	 * 如果有必要，就调用一次。
	 */
	preempt_check_resched();
}
EXPORT_SYMBOL(local_bh_enable);

#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
# define invoke_softirq()	__do_softirq()
#else
# define invoke_softirq()	do_softirq()
#endif

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	account_system_vtime(current);
	sub_preempt_count(IRQ_EXIT_OFFSET);
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();
	preempt_enable_no_resched();
}

/*
 * This function must run with irqs disabled!
 */
inline fastcall void raise_softirq_irqoff(unsigned int nr)
{
	/**
	 * 标记nr对应的软中断为挂起状态。
	 */
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	/**
	 * in_interrupt是判断是否在中断上下文中。
	 * 程序在中断上下文中，表示：要么当前禁用了软中断，要么处在硬中断嵌套中，此时都不用唤醒ksoftirqd内核线程。
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}

EXPORT_SYMBOL(raise_softirq_irqoff);

/**
 * 激活软中断
 * nr-要激活的软中断下标
 */
void fastcall raise_softirq(unsigned int nr)
{
	unsigned long flags;

	/**
	 * 禁用本地CPU中断。
	 */
	local_irq_save(flags);
	/**
	 * raise_softirq_irqoff是本函数的执行体，不过它是在关中断下运行。
	 */
	raise_softirq_irqoff(nr);
	/**
	 * 打开本地中断
	 */
	local_irq_restore(flags);
}
/**
 * 初始化软中断
 * nr-软中断下标
 * action-软中断处理函数
 * data-软中断处理函数的参数。执行处理函数时，将它回传给软中断。
*/

void open_softirq(int nr, void (*action)(struct softirq_action*), void *data)
{
	softirq_vec[nr].data = data;
	softirq_vec[nr].action = action;
}

EXPORT_SYMBOL(open_softirq);

/* Tasklets */
struct tasklet_head
{
	struct tasklet_struct *list;
};

/* Some compilers disobey section attribute on statics when not
   initialized -- RR */
static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec) = { NULL };
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec) = { NULL };

void fastcall __tasklet_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	/**
	 * 首先禁止本地中断。
	 */
	local_irq_save(flags);
	/**
	 * 将tasklet挂到tasklet_vec[n]链表的头。
	 */
	t->next = __get_cpu_var(tasklet_vec).list;
	__get_cpu_var(tasklet_vec).list = t;
	/**
	 * raise_softirq_irqoff激活TASKLET_SOFTIRQ软中断。
	 * 它与raise_soft相似，但是它假设已经关本地中断了。
	 */
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	/**
	 * 恢复IF标志。
	 */
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_schedule);

void fastcall __tasklet_hi_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = __get_cpu_var(tasklet_hi_vec).list;
	__get_cpu_var(tasklet_hi_vec).list = t;
	raise_softirq_irqoff(HI_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_hi_schedule);

/**
 * 执行tasklet。它的上下文是软中断。
 */
static void tasklet_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	/**
	 * 禁用本地中断。
	 */
	local_irq_disable();
	/**
	 * 将tasklet链表取到局部变量中，并清除tasklet链表。
	 */
	list = __get_cpu_var(tasklet_vec).list;
	__get_cpu_var(tasklet_vec).list = NULL;
	local_irq_enable();

	/**
	 * 对list中的每个tasklet，进行处理。
	 */
	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		/**
		 * tasklet_trylock检查并设置tasklet的TASKLET_STATE_RUN标志。
		 * 确保tasklet不会在多个CPU上执行。
		 */
		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				/**
				 * 检查并设置TASKLET_STATE_SCHED标志。
				 * 应该说，挂接到软中断的tasklet，都是有TASKLET_STATE_SCHED标志的。
				 * 难道有人会直接将tasklet插入链表，而不是通过tasklet_schedule插入的？？？？？？
				 * 当然，test_and_clear_bit除了检查TASKLET_STATE_SCHED标志外，也会清除这个标志。
				 * 所以说，为了保证tasklet不会重入，需要TASKLET_STATE_SCHED和TASKLET_STATE_RUN两个标志。
				 */
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();

				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			/**
			 * 运行到此，说明t->count>0，tasklet被禁止了。
			 * tasklet_unlock会清除TASKLET_STATE_RUN标志。
			 */
			tasklet_unlock(t);
		}

		/**
		 * 运行到这里，说明tasklet_trylock失败(tasklet已经在其他CPU上运行)，或者count>0(表示被禁止了)
		 * 那么就将tasklet重新放回链表，并激活相应的软中断。
		 */
		local_irq_disable();
		t->next = __get_cpu_var(tasklet_vec).list;
		__get_cpu_var(tasklet_vec).list = t;
		__raise_softirq_irqoff(TASKLET_SOFTIRQ);
		local_irq_enable();
	}
}

static void tasklet_hi_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __get_cpu_var(tasklet_hi_vec).list;
	__get_cpu_var(tasklet_hi_vec).list = NULL;
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = __get_cpu_var(tasklet_hi_vec).list;
		__get_cpu_var(tasklet_hi_vec).list = t;
		__raise_softirq_irqoff(HI_SOFTIRQ);
		local_irq_enable();
	}
}

/**
 * 初始化tasklet.
 */
void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->data = data;
}

EXPORT_SYMBOL(tasklet_init);

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		printk("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		do
			yield();
		while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}

EXPORT_SYMBOL(tasklet_kill);

void __init softirq_init(void)
{
	open_softirq(TASKLET_SOFTIRQ, tasklet_action, NULL);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action, NULL);
}

static int ksoftirqd(void * __bind_cpu)
{
	set_user_nice(current, 19);
	current->flags |= PF_NOFREEZE;

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		/**
		 * 没有挂起的中断，调度出去。
		 */
		if (!local_softirq_pending())
			schedule();

		/**
		 * 在上次循环结尾处，可能设置状态为TASK_INTERRUPTIBLE，现在把它改过来。
		 */
		__set_current_state(TASK_RUNNING);

		while (local_softirq_pending()) {
			/* Preempt disable stops cpu going offline.
			   If already offline, we'll be on wrong CPU:
			   don't process */
			/**
			 * 现在是增加抢占计数，而不是软中断计数。
			 * 增加软中断计数，防止软中断重入是在do_softirq中。
			 */
			preempt_disable();
			if (cpu_is_offline((long)__bind_cpu))
				goto wait_to_die;
			/**
			 * 回想一下，do_softirq会设置软中断计数标志，而ininterrupt会根据这个标志返回是否处于中断上下文。
			 * 其实，现在我们是在线程上下文执行do_softirq。
			 * 所以说，ininterrupt有点名不符实。
			 */
			do_softirq();
			preempt_enable();
			/**
			 * 增加一个调度点，仅此而已。
			 */
			cond_resched();
		}

		/**
		 * 没有挂起的软中断，就将状态设置为TASK_INTERRUPTIBLE
		 * 下次循环时，就会调度出去。
		 */
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;

wait_to_die:
	preempt_enable();
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * tasklet_kill_immediate is called to remove a tasklet which can already be
 * scheduled for execution on @cpu.
 *
 * Unlike tasklet_kill, this function removes the tasklet
 * _immediately_, even if the tasklet is in TASKLET_STATE_SCHED state.
 *
 * When this function is called, @cpu must be in the CPU_DEAD state.
 */
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu)
{
	struct tasklet_struct **i;

	BUG_ON(cpu_online(cpu));
	BUG_ON(test_bit(TASKLET_STATE_RUN, &t->state));

	if (!test_bit(TASKLET_STATE_SCHED, &t->state))
		return;

	/* CPU is dead, so no lock needed. */
	for (i = &per_cpu(tasklet_vec, cpu).list; *i; i = &(*i)->next) {
		if (*i == t) {
			*i = t->next;
			return;
		}
	}
	BUG();
}

static void takeover_tasklets(unsigned int cpu)
{
	struct tasklet_struct **i;

	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	for (i = &__get_cpu_var(tasklet_vec).list; *i; i = &(*i)->next);
	*i = per_cpu(tasklet_vec, cpu).list;
	per_cpu(tasklet_vec, cpu).list = NULL;
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	for (i = &__get_cpu_var(tasklet_hi_vec).list; *i; i = &(*i)->next);
	*i = per_cpu(tasklet_hi_vec, cpu).list;
	per_cpu(tasklet_hi_vec, cpu).list = NULL;
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __devinit cpu_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
		BUG_ON(per_cpu(tasklet_vec, hotcpu).list);
		BUG_ON(per_cpu(tasklet_hi_vec, hotcpu).list);
		p = kthread_create(ksoftirqd, hcpu, "ksoftirqd/%d", hotcpu);
		if (IS_ERR(p)) {
			printk("ksoftirqd for %i failed\n", hotcpu);
			return NOTIFY_BAD;
		}
		kthread_bind(p, hotcpu);
  		per_cpu(ksoftirqd, hotcpu) = p;
 		break;
	case CPU_ONLINE:
		wake_up_process(per_cpu(ksoftirqd, hotcpu));
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(ksoftirqd, hotcpu), smp_processor_id());
	case CPU_DEAD:
		p = per_cpu(ksoftirqd, hotcpu);
		per_cpu(ksoftirqd, hotcpu) = NULL;
		kthread_stop(p);
		takeover_tasklets(hotcpu);
		break;
#endif /* CONFIG_HOTPLUG_CPU */
 	}
	return NOTIFY_OK;
}

static struct notifier_block __devinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

__init int spawn_ksoftirqd(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);
	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
	register_cpu_notifier(&cpu_nfb);
	return 0;
}
