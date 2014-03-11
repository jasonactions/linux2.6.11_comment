/*
 * linux/kernel/irq/handle.c
 *
 * Copyright (C) 1992, 1998-2004 Linus Torvalds, Ingo Molnar
 *
 * This file contains the core interrupt handling code.
 */

#include <linux/irq.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include "internals.h"

/*
 * Linux has a controller-independent interrupt architecture.
 * Every controller has a 'controller-template', that is used
 * by the main code to do the right thing. Each driver-visible
 * interrupt source is transparently wired to the apropriate
 * controller. Thus drivers need not be aware of the
 * interrupt-controller.
 *
 * The code is designed to be easily extended with new/different
 * interrupt controllers, without having to do assembly magic or
 * having to touch the generic code.
 *
 * Controller mappings for all interrupt sources:
 */
irq_desc_t irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handler = &no_irq_type,
		.lock = SPIN_LOCK_UNLOCKED
	}
};

/*
 * Generic 'no controller' code
 */
static void end_none(unsigned int irq) { }
static void enable_none(unsigned int irq) { }
static void disable_none(unsigned int irq) { }
static void shutdown_none(unsigned int irq) { }
static unsigned int startup_none(unsigned int irq) { return 0; }

static void ack_none(unsigned int irq)
{
	/*
	 * 'what should we do if we get a hw irq event on an illegal vector'.
	 * each architecture has to answer this themself.
	 */
	ack_bad_irq(irq);
}

struct hw_interrupt_type no_irq_type = {
	.typename = 	"none",
	.startup = 	startup_none,
	.shutdown = 	shutdown_none,
	.enable = 	enable_none,
	.disable = 	disable_none,
	.ack = 		ack_none,
	.end = 		end_none,
	.set_affinity = NULL
};

/*
 * Special, empty irq handler:
 */
irqreturn_t no_action(int cpl, void *dev_id, struct pt_regs *regs)
{
	return IRQ_NONE;
}

/*
 * Have got an event to handle:
 */
/**
 * 执行中断服务例程
 */
fastcall int handle_IRQ_event(unsigned int irq, struct pt_regs *regs,
				struct irqaction *action)
{
	int ret, retval = 0, status = 0;

	/**
	 * 如果没有设置SA_INTERRUPT，说明中断处理程序是可以在开中断情况下执行的
	 * 这也是程序中少见的，调用local_irq_enable的地方。
	 * 一般来说，调用local_irq_enable是危险的，不允许，绝不允许。这里只是例外。
	 */
	if (!(action->flags & SA_INTERRUPT))
		local_irq_enable();

	/**
	 * 一开始，action是irqaction链表的头，irqaction表示一个ISR
	 */
	do {
		/**
		 * handler是中断服务例程的处理函数。它接收三个参数：
		 * irq-IRQ号，它允许一个ISR处理几条IRQ。
		 * dev_id-设备号，注册中断服务例程时指定，此时回传给处理函数。它允许一个ISR处理几个同类型的设备。
		 * regs-指向内核栈的pt_regs。它允许ISR访问内核执行上下文。可是，哪个ISR会用它呢？
		 */
		ret = action->handler(irq, action->dev_id, regs);
		if (ret == IRQ_HANDLED)
			status |= action->flags;
		/**
		 * 一般来说，handler处理了本次中断，就会返回1
		 * 返回0和1是有用的，这样可以让内核判断中断是否被处理了。
		 * 如果过多的中断没有被处理，就说明硬件有问题，产生了伪中断。
		 */
		retval |= ret;
		action = action->next;
	} while (action);

	/**
	 * 如果中断是随机数的产生源，就添加一个随机因子。
	 */
	if (status & SA_SAMPLE_RANDOM)
		add_interrupt_randomness(irq);

	/**
	 * 退出时，总是会关中断，这里不判断if (!(action->flags & SA_INTERRUPT))
	 * 是因为：判断的汇编指令比直接执行cli费时，既然无论如何都是需要保证处于关中断状态，为什么多作那些判断呢。
	 */
	local_irq_disable();

	return retval;
}

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs)
{
	irq_desc_t *desc = irq_desc + irq;
	struct irqaction * action;
	unsigned int status;

	/**
	 * 中断发生次数计数.
	 */
	kstat_this_cpu.irqs[irq]++;
	if (desc->status & IRQ_PER_CPU) {
		irqreturn_t action_ret;

		/*
		 * No locking required for CPU-local interrupts:
		 */
		desc->handler->ack(irq);
		action_ret = handle_IRQ_event(irq, regs, desc->action);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		desc->handler->end(irq);
		return 1;
	}

	/**
	 * 虽然中断是关闭的,但是还是需要使用自旋锁保护desc
	 */
	spin_lock(&desc->lock);
	/**
	 * 如果是旧的8259A PIC,ack就是mask_and_ack_8259A,它应答PIC上的中断并禁用这条IRQ线.屏蔽IRQ线是为了确保在这个中断处理程序结束前,
	 * CPU不进一步接受这种中断的出现.
	 * do_IRQ是以禁止本地中断运行,事实上,CPU控制单元自动清eflags寄存器的IF标志.因为中断处理程序是通过IDT中断门调用的.
	 * 不过,内核在执行这个中断的中断服务例程之前可能会重新激活本地中断.
	 * 在使用APIC时,应答中断信赖于中断类型,可能是ack,也可能延迟到中断处理程序结束(也就是应答由end方法去做).
	 * 无论如何,中断处理程序结束前,本地APIC不进一步接收这种中断,尽管这种中断可能会被其他CPU接受.
	 */
	desc->handler->ack(irq);
	/*
	 * REPLAY is when Linux resends an IRQ that was dropped earlier
	 * WAITING is used by probe to mark irqs that are being tested
	 */
	/**
	 * 初始化主IRQ描述符的几个标志.设置IRQ_PENDING标志.也清除IRQ_WAITING和IRQ_REPLAY
	 * 这几个标志可以很好的解决中断重入的问题.
	 * IRQ_REPLAY标志是"挽救丢失的中断"所用.在此不详述.
	 */
	status = desc->status & ~(IRQ_REPLAY | IRQ_WAITING);
	status |= IRQ_PENDING; /* we _want_ to handle it */

	/*
	 * If the IRQ is disabled for whatever reason, we cannot
	 * use the action we have.
	 */
	action = NULL;
	/**
	 * IRQ_DISABLED和IRQ_INPROGRESS被设置时,什么都不做(action==NULL)
	 * 即使IRQ线被禁止,CPU也可能执行do_IRQ函数.首先,可能是因为挽救丢失的中断,其次,也可能是有问题的主板产生伪中断.
	 * 所以,是否真的执行中断代码,需要根据IRQ_DISABLED标志来判断,而不仅仅是禁用IRQ线.
	 * IRQ_INPROGRESS标志的作用是:如果一个CPU正在处理一个中断,那么它会设置它的IRQ_INPROGRESS.这样,其他CPU上发生同样的中断
	 * 就可以检查是否在其他CPU上正在处理同种类型的中断,如果是,就什么都不做,这样做有以下好处:
	 * 一是使内核结构简单,驱动程序的中断服务例程式不必是可重入的.二是可以避免弄脏当前CPU的硬件高速缓存.
	 */
	if (likely(!(status & (IRQ_DISABLED | IRQ_INPROGRESS)))) {
		action = desc->action;
		status &= ~IRQ_PENDING; /* we commit to handling */
		status |= IRQ_INPROGRESS; /* we are handling it */
	}
	desc->status = status;

	/*
	 * If there is no IRQ handler or it was disabled, exit early.
	 * Since we set PENDING, if another processor is handling
	 * a different instance of this same irq, the other processor
	 * will take care of it.
	 */
	/**
	 * 当前面两种情况出现时,不需要(或者是不需要马上)处理中断.就退出
	 * 或者没有相关的中断服务例程时,也退出.当内核正在检测硬件设备时就会发生这种情况.
	 */
	if (unlikely(!action))
		goto out;

	/*
	 * Edge triggered interrupts need to remember
	 * pending events.
	 * This applies to any hw interrupts that allow a second
	 * instance of the same irq to arrive while we are in do_IRQ
	 * or in the handler. But the code here only handles the _second_
	 * instance of the irq, not the third or fourth. So it is mostly
	 * useful for irq hardware that does not mask cleanly in an
	 * SMP environment.
	 */
	/**
	 * 这里是需要循环处理的,并不是说调用一次handle_IRQ_event就行了.
	 */
	for (;;) {
		irqreturn_t action_ret;

		/**
		 * 现在打开自旋锁了,那么,其他CPU可能也接收到同类中断,并设置IRQ_PENDING标志.
		 * xie.baoyou注:请注意开关锁的使用方法.有点巧妙,不可言传.
		 */
		spin_unlock(&desc->lock);

		/**
		 * 调用中断服务例程.
		 */
		action_ret = handle_IRQ_event(irq, regs, action);

		spin_lock(&desc->lock);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		/**
		 * 如果其他CPU没有接收到同类中断,就退出
		 * 否则,继续处理同类中断.
		 */
		if (likely(!(desc->status & IRQ_PENDING)))
			break;
		/**
		 * 清除了IRQ_PENDING,如果再出现IRQ_PENDING,就说明是其他CPU上接收到了同类中断.
		 * 注意,IRQ_PENDING仅仅是一个标志,如果在调用中断处理函数的过程中,来了多次的同类中断,则意味着只有一次被处理,其余的都丢失了.
		 */
		desc->status &= ~IRQ_PENDING;
	}
	desc->status &= ~IRQ_INPROGRESS;

out:
	/*
	 * The ->end() handler has to deal with interrupts which got
	 * disabled while the handler was running.
	 */
	/**
	 * 现在准备退出了,end方法可能是应答中断(APIC),也可能是通过end_8259A_irq方法重新激活IRQ(只要不是伪中断).
	 */
	desc->handler->end(irq);
	/**
	 * 好,工作已经全部完成了,释放自旋锁吧.注意两个锁的配对使用方法.
	 */
	spin_unlock(&desc->lock);

	return 1;
}

