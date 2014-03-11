/*
 *	linux/arch/i386/kernel/irq.c
 *
 *	Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the lowest level x86-specific interrupt
 * entry, irq-stacks and irq statistics code. All the remaining
 * irq logic is done by the generic kernel/irq/ code and
 * by the x86-specific irq controller code. (e.g. i8259.c and
 * io_apic.c.)
 */

#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#ifndef CONFIG_X86_LOCAL_APIC
/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
	printk("unexpected IRQ trap at vector %02x\n", irq);
}
#endif

#ifdef CONFIG_4KSTACKS
/*
 * per-CPU IRQ handling contexts (thread information and stack)
 */
union irq_ctx {
	struct thread_info      tinfo;
	u32                     stack[THREAD_SIZE/sizeof(u32)];
};

static union irq_ctx *hardirq_ctx[NR_CPUS];
static union irq_ctx *softirq_ctx[NR_CPUS];
#endif

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
/** 
 * do_IRQ执行与一个中断相关的所有中断服务例程.
 */
fastcall unsigned int do_IRQ(struct pt_regs *regs)
{	
	/* high bits used in ret_from_ code */
	int irq = regs->orig_eax & 0xff;
#ifdef CONFIG_4KSTACKS
	union irq_ctx *curctx, *irqctx;
	u32 *isp;
#endif

	/**
	 * irq_enter增加中断嵌套计数
	 */
	irq_enter();
#ifdef CONFIG_DEBUG_STACKOVERFLOW
	/* Debugging check for stack overflow: is there less than 1KB free? */
	{
		long esp;

		__asm__ __volatile__("andl %%esp,%0" :
					"=r" (esp) : "0" (THREAD_SIZE - 1));
		if (unlikely(esp < (sizeof(struct thread_info) + STACK_WARN))) {
			printk("do_IRQ: stack overflow: %ld\n",
				esp - sizeof(struct thread_info));
			dump_stack();
		}
	}
#endif

#ifdef CONFIG_4KSTACKS

	/**
	 * 如果中断栈使用不同的的栈,就需要切换栈.
	 */
	curctx = (union irq_ctx *) current_thread_info();
	irqctx = hardirq_ctx[smp_processor_id()];

	/*
	 * this is where we switch to the IRQ stack. However, if we are
	 * already using the IRQ stack (because we interrupted a hardirq
	 * handler) we can't do that and just have to keep using the
	 * current stack (which is the irq stack already after all)
	 */
	/**
	 * 当前在使用内核栈,而不是硬中断请求栈.就需要切换栈
	 */
	if (curctx != irqctx) {
		int arg1, arg2, ebx;

		/* build the stack frame on the IRQ stack */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));
		/**
		 * 保存当前进程描述符指针
		 */
		irqctx->tinfo.task = curctx->tinfo.task;
		/**
		 * 把esp栈指针寄存器的当前值存入irqctx的thread_info(内核oops时使用)
		 */
		irqctx->tinfo.previous_esp = current_stack_pointer;

		/**
		 * 将中断请求栈的栈顶装入esp,isp即为中断栈顶
		 * 调用完__do_IRQ后,从ebx中恢复esp
		 */
		asm volatile(
			"       xchgl   %%ebx,%%esp      \n"
			"       call    __do_IRQ         \n"
			"       movl   %%ebx,%%esp      \n"
			: "=a" (arg1), "=d" (arg2), "=b" (ebx)
			:  "0" (irq),   "1" (regs),  "2" (isp)
			: "memory", "cc", "ecx"
		);
	} else/* 否则,发生了中断嵌套,不用切换 */
#endif
		__do_IRQ(irq, regs);

	/**
	 * 递减中断计数器并检查是否有可延迟函数
	 */
	irq_exit();

	/**
	 * 结束后,会返回ret_from_intr函数. 
	 */
	return 1;
}

#ifdef CONFIG_4KSTACKS

/*
 * These should really be __section__(".bss.page_aligned") as well, but
 * gcc's 3.0 and earlier don't handle that correctly.
 */
static char softirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__aligned__(THREAD_SIZE)));

static char hardirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__aligned__(THREAD_SIZE)));

/*
 * allocate per-cpu stacks for hardirq and for softirq processing
 */
void irq_ctx_init(int cpu)
{
	union irq_ctx *irqctx;

	if (hardirq_ctx[cpu])
		return;

	irqctx = (union irq_ctx*) &hardirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = HARDIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	hardirq_ctx[cpu] = irqctx;

	irqctx = (union irq_ctx*) &softirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = SOFTIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	softirq_ctx[cpu] = irqctx;

	printk("CPU %u irqstacks, hard=%p soft=%p\n",
		cpu,hardirq_ctx[cpu],softirq_ctx[cpu]);
}

extern asmlinkage void __do_softirq(void);

/**
 * 处理挂起的软中断
 */
asmlinkage void do_softirq(void)
{
	unsigned long flags;
	struct thread_info *curctx;
	union irq_ctx *irqctx;
	u32 *isp;

	/**
	 * 如果in_interrupt返回真，说明系统要么是处于中断中，要么是禁用了软中断。
	 * 请注意in_interrupt()的实现代码：preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK)
	 * 它判断当前是否在硬件中断中，或者是否在软中断中。
	 */
	if (in_interrupt())
		return;

	/**
	 * 在此时需要关闭中断，因为接下来我们需要将判断是否有挂起的中断
	 * 如果不在关中断的情况下访问这个标志，那么，这个标志就可能被中断程序修改。
	 * 从另一个方面来说，我们还会在后面切换堆栈，这也需要在关中断中进行。
	 * 开中断的时机在__do_softirq中。当然，本函数结束时，也会恢复中断标志。
	 */
	local_irq_save(flags);

	if (local_softirq_pending()) {/* 有挂起的软中断 */
		/**
		 * 根据配置来确定是否切换堆栈(请注意，本段代码受宏CONFIG_4KSTACKS的控制)。
		 * 当然，这里用的是softirq_ctx而不是hardirq_ctx来保存当前进程。
		 */
		curctx = current_thread_info();
		irqctx = softirq_ctx[smp_processor_id()];
		irqctx->tinfo.task = curctx->task;
		irqctx->tinfo.previous_esp = current_stack_pointer;

		/* build the stack frame on the softirq stack */
		/**
		 * isp保存的是软中断栈的栈顶。
		 * 可以放心的是，软中断在单个CPU上不会重入，而softirq_ctx是每CPU变量
		 * 所以，在这里我们可以放心的切换栈顶了。
		 */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));

		/**
		 * 切换栈到isp，并调用__do_softirq.
		 * 然后再恢复栈（可能是恢复到中断栈、进程内核栈、内核线程栈）。
		 */
		asm volatile(
			"       xchgl   %%ebx,%%esp     \n"
			"       call    __do_softirq    \n"
			"       movl    %%ebx,%%esp     \n"
			: "=b"(isp)
			: "0"(isp)
			: "memory", "cc", "edx", "ecx", "eax"
		);
	}

	local_irq_restore(flags);
}

EXPORT_SYMBOL(do_softirq);
#endif

/*
 * Interrupt statistics:
 */

atomic_t irq_err_count;

/*
 * /proc/interrupts printing:
 */

int show_interrupts(struct seq_file *p, void *v)
{
	int i = *(loff_t *) v, j;
	struct irqaction * action;
	unsigned long flags;

	if (i == 0) {
		seq_printf(p, "           ");
		for (j=0; j<NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "CPU%d       ",j);
		seq_putc(p, '\n');
	}

	if (i < NR_IRQS) {
		spin_lock_irqsave(&irq_desc[i].lock, flags);
		action = irq_desc[i].action;
		if (!action)
			goto skip;
		seq_printf(p, "%3d: ",i);
#ifndef CONFIG_SMP
		seq_printf(p, "%10u ", kstat_irqs(i));
#else
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", kstat_cpu(j).irqs[i]);
#endif
		seq_printf(p, " %14s", irq_desc[i].handler->typename);
		seq_printf(p, "  %s", action->name);

		for (action=action->next; action; action = action->next)
			seq_printf(p, ", %s", action->name);

		seq_putc(p, '\n');
skip:
		spin_unlock_irqrestore(&irq_desc[i].lock, flags);
	} else if (i == NR_IRQS) {
		seq_printf(p, "NMI: ");
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", nmi_count(j));
		seq_putc(p, '\n');
#ifdef CONFIG_X86_LOCAL_APIC
		seq_printf(p, "LOC: ");
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ",
					irq_stat[j].apic_timer_irqs);
		seq_putc(p, '\n');
#endif
		seq_printf(p, "ERR: %10u\n", atomic_read(&irq_err_count));
#if defined(CONFIG_X86_IO_APIC)
		seq_printf(p, "MIS: %10u\n", atomic_read(&irq_mis_count));
#endif
	}
	return 0;
}
