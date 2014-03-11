/*
 *  linux/arch/i386/kernel/signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-11-28  Modified for POSIX.1b signals by Richard Henderson
 *  2000-06-20  Pentium III FXSR, SSE support by Gareth Hughes
 */

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/personality.h>
#include <linux/suspend.h>
#include <linux/ptrace.h>
#include <linux/elf.h>
#include <asm/processor.h>
#include <asm/ucontext.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include "sigframe.h"

#define DEBUG_SIG 0

#define _BLOCKABLE (~(sigmask(SIGKILL) | sigmask(SIGSTOP)))

/*
 * Atomically swap in the new signal mask, and wait for a signal.
 */
asmlinkage int
sys_sigsuspend(int history0, int history1, old_sigset_t mask)
{
	struct pt_regs * regs = (struct pt_regs *) &history0;
	sigset_t saveset;

	mask &= _BLOCKABLE;
	spin_lock_irq(&current->sighand->siglock);
	saveset = current->blocked;
	siginitset(&current->blocked, mask);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	regs->eax = -EINTR;
	while (1) {
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		if (do_signal(regs, &saveset))
			return -EINTR;
	}
}

asmlinkage int
sys_rt_sigsuspend(struct pt_regs regs)
{
	sigset_t saveset, newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (regs.ecx != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&newset, (sigset_t __user *)regs.ebx, sizeof(newset)))
		return -EFAULT;
	sigdelsetmask(&newset, ~_BLOCKABLE);

	spin_lock_irq(&current->sighand->siglock);
	saveset = current->blocked;
	current->blocked = newset;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	regs.eax = -EINTR;
	while (1) {
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		if (do_signal(&regs, &saveset))
			return -EINTR;
	}
}

/**
 * sigaction系统调用的服务例程。
 * sig-信号编号
 * act-act表，虽然类型是old_sigaction，可是它却表示新的操作。真是令人费解
 * oact-用来保存以前设置的操作。可以为空。
 */
asmlinkage int 
sys_sigaction(int sig, const struct old_sigaction __user *act,
	      struct old_sigaction __user *oact)
{
	struct k_sigaction new_ka, old_ka;
	int ret;

	/**
	 * 首先检查act的有效性
	 * act==NULL是合法的。这表示用户仅仅希望看一下以前的设置。
	 */
	if (act) {
		old_sigset_t mask;
		/**
		 * 先检查用户传递的参数是否正确。
		 */
		if (verify_area(VERIFY_READ, act, sizeof(*act)) ||
		    __get_user(new_ka.sa.sa_handler, &act->sa_handler) ||
		    __get_user(new_ka.sa.sa_restorer, &act->sa_restorer))
			return -EFAULT;
		__get_user(new_ka.sa.sa_flags, &act->sa_flags);
		__get_user(mask, &act->sa_mask);
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	/**
	 * do_sigaction真正进行设置操作。
	 */
	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	/**
	 * 将前次设置的值写到用户空间中去。
	 */
	if (!ret && oact) {
		if (verify_area(VERIFY_WRITE, oact, sizeof(*oact)) ||
		    __put_user(old_ka.sa.sa_handler, &oact->sa_handler) ||
		    __put_user(old_ka.sa.sa_restorer, &oact->sa_restorer))
			return -EFAULT;
		__put_user(old_ka.sa.sa_flags, &oact->sa_flags);
		__put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask);
	}

	return ret;
}

asmlinkage int
sys_sigaltstack(unsigned long ebx)
{
	/* This is needed to make gcc realize it doesn't own the "struct pt_regs" */
	struct pt_regs *regs = (struct pt_regs *)&ebx;
	const stack_t __user *uss = (const stack_t __user *)ebx;
	stack_t __user *uoss = (stack_t __user *)regs->ecx;

	return do_sigaltstack(uss, uoss, regs->esp);
}


/*
 * Do a signal return; undo the signal stack.
 */

static int
restore_sigcontext(struct pt_regs *regs, struct sigcontext __user *sc, int *peax)
{
	unsigned int err = 0;

	/* Always make any pending restarted system calls return -EINTR */
	current_thread_info()->restart_block.fn = do_no_restart_syscall;

#define COPY(x)		err |= __get_user(regs->x, &sc->x)

#define COPY_SEG(seg)							\
	{ unsigned short tmp;						\
	  err |= __get_user(tmp, &sc->seg);				\
	  regs->x##seg = tmp; }

#define COPY_SEG_STRICT(seg)						\
	{ unsigned short tmp;						\
	  err |= __get_user(tmp, &sc->seg);				\
	  regs->x##seg = tmp|3; }

#define GET_SEG(seg)							\
	{ unsigned short tmp;						\
	  err |= __get_user(tmp, &sc->seg);				\
	  loadsegment(seg,tmp); }

#define	FIX_EFLAGS	(X86_EFLAGS_AC | X86_EFLAGS_OF | X86_EFLAGS_DF | \
			 X86_EFLAGS_TF | X86_EFLAGS_SF | X86_EFLAGS_ZF | \
			 X86_EFLAGS_AF | X86_EFLAGS_PF | X86_EFLAGS_CF)

	GET_SEG(gs);
	GET_SEG(fs);
	COPY_SEG(es);
	COPY_SEG(ds);
	COPY(edi);
	COPY(esi);
	COPY(ebp);
	COPY(esp);
	COPY(ebx);
	COPY(edx);
	COPY(ecx);
	COPY(eip);
	COPY_SEG_STRICT(cs);
	COPY_SEG_STRICT(ss);
	
	{
		unsigned int tmpflags;
		err |= __get_user(tmpflags, &sc->eflags);
		regs->eflags = (regs->eflags & ~FIX_EFLAGS) | (tmpflags & FIX_EFLAGS);
		regs->orig_eax = -1;		/* disable syscall checks */
	}

	{
		struct _fpstate __user * buf;
		err |= __get_user(buf, &sc->fpstate);
		if (buf) {
			if (verify_area(VERIFY_READ, buf, sizeof(*buf)))
				goto badframe;
			err |= restore_i387(buf);
		} else {
			struct task_struct *me = current;
			if (used_math()) {
				clear_fpu(me);
				clear_used_math();
			}
		}
	}

	err |= __get_user(*peax, &sc->eax);
	return err;

badframe:
	return 1;
}

/**
 * 用户态信号处理函数返回后，会进入到本过程。绕了一圈，又回到内核态了。
 */
asmlinkage int sys_sigreturn(unsigned long __unused)
{
	/**
	 * pt_regs数据结构中包含了用户态进程的硬件上下文。
	 * 我们需要根据pt_regs的esp值，在用户态堆栈中找到我们保存的原始pt_regs
	 */
	struct pt_regs *regs = (struct pt_regs *) &__unused;
	/**
	 * setup_frame建立的栈帧。
	 */
	struct sigframe __user *frame = (struct sigframe __user *)(regs->esp - 8);
	sigset_t set;
	int eax;

	if (verify_area(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	/**
	 * 获得调用信号处理函数前所阻塞的信号的位数组。
	 * 注意frame是一个用户态地址，这里的&frame->sc.oldmask并不是真正要执行frame->sc.oldmask
	 * 而是将frame地址加上sc.oldmask的偏移量，形成一个新的用户态地址。
	 */
	if (__get_user(set.sig[0], &frame->sc.oldmask)
	    || (_NSIG_WORDS > 1
		&& __copy_from_user(&set.sig[1], &frame->extramask,
				    sizeof(frame->extramask))))
		goto badframe;

	/**
	 * 重新设置阻塞掩码。
	 */ 
	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	/**
	 * 恢复setup_frame保存的进程硬件上下文。并从用户态堆栈中删除帧。
	 * 这个上下文是保存在用户态堆栈的sc中的。这样，从系统调用sys_sigreturn返回时，
	 * 并不会返回到信号处理函数（虽然是从信号处理函数中进入的），而会返回到被信号中断的用户态程序
	 */
	if (restore_sigcontext(regs, &frame->sc, &eax))
		goto badframe;
	return eax;

badframe:
	force_sig(SIGSEGV, current);
	return 0;
}	

asmlinkage int sys_rt_sigreturn(unsigned long __unused)
{
	struct pt_regs *regs = (struct pt_regs *) &__unused;
	struct rt_sigframe __user *frame = (struct rt_sigframe __user *)(regs->esp - 4);
	sigset_t set;
	int eax;

	if (verify_area(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)))
		goto badframe;

	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
	
	if (restore_sigcontext(regs, &frame->uc.uc_mcontext, &eax))
		goto badframe;

	if (do_sigaltstack(&frame->uc.uc_stack, NULL, regs->esp) == -EFAULT)
		goto badframe;

	return eax;

badframe:
	force_sig(SIGSEGV, current);
	return 0;
}	

/*
 * Set up a signal frame.
 */

static int
setup_sigcontext(struct sigcontext __user *sc, struct _fpstate __user *fpstate,
		 struct pt_regs *regs, unsigned long mask)
{
	int tmp, err = 0;

	tmp = 0;
	__asm__("movl %%gs,%0" : "=r"(tmp): "0"(tmp));
	err |= __put_user(tmp, (unsigned int __user *)&sc->gs);
	__asm__("movl %%fs,%0" : "=r"(tmp): "0"(tmp));
	err |= __put_user(tmp, (unsigned int __user *)&sc->fs);

	err |= __put_user(regs->xes, (unsigned int __user *)&sc->es);
	err |= __put_user(regs->xds, (unsigned int __user *)&sc->ds);
	err |= __put_user(regs->edi, &sc->edi);
	err |= __put_user(regs->esi, &sc->esi);
	err |= __put_user(regs->ebp, &sc->ebp);
	err |= __put_user(regs->esp, &sc->esp);
	err |= __put_user(regs->ebx, &sc->ebx);
	err |= __put_user(regs->edx, &sc->edx);
	err |= __put_user(regs->ecx, &sc->ecx);
	err |= __put_user(regs->eax, &sc->eax);
	err |= __put_user(current->thread.trap_no, &sc->trapno);
	err |= __put_user(current->thread.error_code, &sc->err);
	err |= __put_user(regs->eip, &sc->eip);
	err |= __put_user(regs->xcs, (unsigned int __user *)&sc->cs);
	err |= __put_user(regs->eflags, &sc->eflags);
	err |= __put_user(regs->esp, &sc->esp_at_signal);
	err |= __put_user(regs->xss, (unsigned int __user *)&sc->ss);

	tmp = save_i387(fpstate);
	if (tmp < 0)
	  err = 1;
	else
	  err |= __put_user(tmp ? fpstate : NULL, &sc->fpstate);

	/* non-iBCS2 extensions.. */
	err |= __put_user(mask, &sc->oldmask);
	err |= __put_user(current->thread.cr2, &sc->cr2);

	return err;
}

/*
 * Determine which stack to use..
 */
static inline void __user *
get_sigframe(struct k_sigaction *ka, struct pt_regs * regs, size_t frame_size)
{
	unsigned long esp;

	/* Default to using normal stack */
	esp = regs->esp;

	/* This is the X/Open sanctioned signal stack switching.  */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (sas_ss_flags(esp) == 0)
			esp = current->sas_ss_sp + current->sas_ss_size;
	}

	/* This is the legacy signal stack switching. */
	else if ((regs->xss & 0xffff) != __USER_DS &&
		 !(ka->sa.sa_flags & SA_RESTORER) &&
		 ka->sa.sa_restorer) {
		esp = (unsigned long) ka->sa.sa_restorer;
	}

	return (void __user *)((esp - frame_size) & -8ul);
}

/* These symbols are defined with the addresses in the vsyscall page.
   See vsyscall-sigreturn.S.  */
extern void __user __kernel_sigreturn;
extern void __user __kernel_rt_sigreturn;


/**
 * 在用户态堆栈中，建立信号处理所需要的帧。
 * 把frame数据结构推进用户态堆栈中，它含有处理信号所需要的信息。并确保正确返回到handle_signal函数。
 * sig-信号编号
 * ka-与信号相关的k_sigaction表示地址
 * oldset-阻塞信号的位掩码数组的地址。因为在返回到用户态后，内核态再不能保存阻塞信号掩码，所以借用用户态堆栈保存这个值。
 *        这个值的重要目的是：保证信号处理函数不会重入。
 * regs-用户态寄存器的内容保存在内核态堆栈区的地址。
 */
static void setup_frame(int sig, struct k_sigaction *ka,
			sigset_t *set, struct pt_regs * regs)
{
	void __user *restorer;
	/**
	 * 要压入用户态堆栈中的栈帧，模拟信号处理程序的参数。
	 */
	struct sigframe __user *frame;
	int err = 0;
	int usig;

	/**
	 * get_sigframe计算帧的第一个内存单元。
	 * 本质上，它返回(regs->esp - frame_size) & -8ul
	 * 即：从当前栈顶向下frame_size,然后再8字节对齐。
	 */
	frame = get_sigframe(ka, regs, sizeof(*frame));

	/**
	 * 没有办法操作用户栈了，可能是用户态空间不足了。
	 * 转到give_sigsegv，它会将信号处理函数设置成DFL，然后发一个段错误
	 * 呵呵，不就是明摆着要把线程给杀死吗？？
	 */
	if (!access_ok(VERIFY_WRITE, frame, sizeof(*frame)))
		goto give_sigsegv;

	/**
	 * 信号编号。这是信号处理函数的唯一参数。
	 * 在__kernel_sigreturn中，通过popl %eax被弹出。
	 */
	usig = current_thread_info()->exec_domain
		&& current_thread_info()->exec_domain->signal_invmap
		&& sig < 32
		? current_thread_info()->exec_domain->signal_invmap[sig]
		: sig;

	/**
	 * 反复调用__put_user，向用户态堆栈中压入内容。
	 * 这些内容是用户态进入内核态时的现场，由于信号处理程序执行完毕后会返回到内核态
	 * 会形成一个新的现场，所以需要保存前一次的现场，这里是借用用户态堆栈来保存。
	 */
	err = __put_user(usig, &frame->sig);
	if (err)
		goto give_sigsegv;

	err = setup_sigcontext(&frame->sc, &frame->fpstate, regs, set->sig[0]);
	if (err)
		goto give_sigsegv;

	if (_NSIG_WORDS > 1) {
		err = __copy_to_user(&frame->extramask, &set->sig[1],
				      sizeof(frame->extramask));
		if (err)
			goto give_sigsegv;
	}

	/**
	 * 信号处理程序的返回地址：__kernel_sigreturn，它会调用int $80回到内核。
	 * 当信号处理函数的ret指令执行时，会弹出这个地址作为返回地址。
	 */
	restorer = &__kernel_sigreturn;
	if (ka->sa.sa_flags & SA_RESTORER)
		restorer = ka->sa.sa_restorer;

	/* Set up to return from userspace.  */
	err |= __put_user(restorer, &frame->pretcode);
	/*
	 * This is popl %eax ; movl $,%eax ; int $0x80
	 *
	 * WE DO NOT USE IT ANY MORE! It's only left here for historical
	 * reasons and because gdb uses it as a signature to notice
	 * signal handler stack frames.
	 */
	/**
	 * 信号处理程序的堆栈构造完了，下面填写返回地址处的指令
	 * 不过这段指令已经不用了，它们仅仅被调试程序用来识别信号处理帧。
	 */
	err |= __put_user(0xb858, (short __user *)(frame->retcode+0));
	err |= __put_user(__NR_sigreturn, (int __user *)(frame->retcode+2));
	err |= __put_user(0x80cd, (short __user *)(frame->retcode+6));

	if (err)
		goto give_sigsegv;

	/**
	 * 修改内核态堆栈的regs区，这样，当current恢复它在用户态的执行时，控制权将传递给信号处理程序。
	 */
	/* Set up registers for signal handler */
	regs->esp = (unsigned long) frame;
	/**
	 * 这个最重要，保证了sa_handler的执行。
	 */
	regs->eip = (unsigned long) ka->sa.sa_handler;
	regs->eax = (unsigned long) sig;
	regs->edx = (unsigned long) 0;
	regs->ecx = (unsigned long) 0;

	set_fs(USER_DS);
	regs->xds = __USER_DS;
	regs->xes = __USER_DS;
	regs->xss = __USER_DS;
	regs->xcs = __USER_CS;

	/*
	 * Clear TF when entering the signal handler, but
	 * notify any tracer that was single-stepping it.
	 * The tracer may want to single-step inside the
	 * handler too.
	 */
	regs->eflags &= ~TF_MASK;
	if (test_thread_flag(TIF_SINGLESTEP))
		ptrace_notify(SIGTRAP);

#if DEBUG_SIG
	printk("SIG deliver (%s:%d): sp=%p pc=%p ra=%p\n",
		current->comm, current->pid, frame, regs->eip, frame->pretcode);
#endif

	return;

give_sigsegv:
	force_sigsegv(sig, current);
}

static void setup_rt_frame(int sig, struct k_sigaction *ka, siginfo_t *info,
			   sigset_t *set, struct pt_regs * regs)
{
	void __user *restorer;
	struct rt_sigframe __user *frame;
	int err = 0;
	int usig;

	frame = get_sigframe(ka, regs, sizeof(*frame));

	if (!access_ok(VERIFY_WRITE, frame, sizeof(*frame)))
		goto give_sigsegv;

	usig = current_thread_info()->exec_domain
		&& current_thread_info()->exec_domain->signal_invmap
		&& sig < 32
		? current_thread_info()->exec_domain->signal_invmap[sig]
		: sig;

	err |= __put_user(usig, &frame->sig);
	err |= __put_user(&frame->info, &frame->pinfo);
	err |= __put_user(&frame->uc, &frame->puc);
	err |= copy_siginfo_to_user(&frame->info, info);
	if (err)
		goto give_sigsegv;

	/* Create the ucontext.  */
	err |= __put_user(0, &frame->uc.uc_flags);
	err |= __put_user(0, &frame->uc.uc_link);
	err |= __put_user(current->sas_ss_sp, &frame->uc.uc_stack.ss_sp);
	err |= __put_user(sas_ss_flags(regs->esp),
			  &frame->uc.uc_stack.ss_flags);
	err |= __put_user(current->sas_ss_size, &frame->uc.uc_stack.ss_size);
	err |= setup_sigcontext(&frame->uc.uc_mcontext, &frame->fpstate,
			        regs, set->sig[0]);
	err |= __copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));
	if (err)
		goto give_sigsegv;

	/* Set up to return from userspace.  */
	restorer = &__kernel_rt_sigreturn;
	if (ka->sa.sa_flags & SA_RESTORER)
		restorer = ka->sa.sa_restorer;
	err |= __put_user(restorer, &frame->pretcode);
	 
	/*
	 * This is movl $,%eax ; int $0x80
	 *
	 * WE DO NOT USE IT ANY MORE! It's only left here for historical
	 * reasons and because gdb uses it as a signature to notice
	 * signal handler stack frames.
	 */
	err |= __put_user(0xb8, (char __user *)(frame->retcode+0));
	err |= __put_user(__NR_rt_sigreturn, (int __user *)(frame->retcode+1));
	err |= __put_user(0x80cd, (short __user *)(frame->retcode+5));

	if (err)
		goto give_sigsegv;

	/* Set up registers for signal handler */
	regs->esp = (unsigned long) frame;
	regs->eip = (unsigned long) ka->sa.sa_handler;
	regs->eax = (unsigned long) usig;
	regs->edx = (unsigned long) &frame->info;
	regs->ecx = (unsigned long) &frame->uc;

	set_fs(USER_DS);
	regs->xds = __USER_DS;
	regs->xes = __USER_DS;
	regs->xss = __USER_DS;
	regs->xcs = __USER_CS;

	/*
	 * Clear TF when entering the signal handler, but
	 * notify any tracer that was single-stepping it.
	 * The tracer may want to single-step inside the
	 * handler too.
	 */
	regs->eflags &= ~TF_MASK;
	if (test_thread_flag(TIF_SINGLESTEP))
		ptrace_notify(SIGTRAP);

#if DEBUG_SIG
	printk("SIG deliver (%s:%d): sp=%p pc=%p ra=%p\n",
		current->comm, current->pid, frame, regs->eip, frame->pretcode);
#endif

	return;

give_sigsegv:
	force_sigsegv(sig, current);
}

/*
 * OK, we're invoking a handler
 */	
/**
 * 调用用户态信号处理函数，处理信号
 * 这个程序太复杂，并且也危险，象是过独木桥。
 * 复杂性表现在：信号处理函数是在用户态定义的。在恢复正常流程前，需要先执行信号处理函数。
 * 另外，信号处理函数可以调用系统调用。
 * 这样，执行完系统调用后，控制权需要返回到信号处理程序，而不是回到应用代码。
 * 回想一下，从中断和异常返回时的处理流程。
 */
static void
handle_signal(unsigned long sig, siginfo_t *info, struct k_sigaction *ka,
	      sigset_t *oldset,	struct pt_regs * regs)
{
	/* Are we from a system call? */
	/**
	 * 如果信号被捕获了，并且系统处于系统调用中。就需要继续分析系统调用的返回值。
	 * 请注意ERESTART_RESTARTBLOCK，在信号没有被捕获时，它是另外一种处理办法，而这里是返回EINTR
	 * 这显示：sleep调用会因此而表现出不同的行为。
	 */
	if (regs->orig_eax >= 0) {
		/* If so, check system call restarting.. */
		switch (regs->eax) {
		        case -ERESTART_RESTARTBLOCK:
			case -ERESTARTNOHAND:
				regs->eax = -EINTR;
				break;

			case -ERESTARTSYS:
				if (!(ka->sa.sa_flags & SA_RESTART)) {
					regs->eax = -EINTR;
					break;
				}
			/* fallthrough */
			case -ERESTARTNOINTR:
				regs->eax = regs->orig_eax;
				regs->eip -= 2;
		}
	}

	/* Set up the stack frame */
	/**
	 * 为执行信号处理程序，建立栈帧。
	 * setup_rt_frame与setup_frame的区别在于是否需要在栈帧中保存info.
	 */
	if (ka->sa.sa_flags & SA_SIGINFO)
		setup_rt_frame(sig, ka, info, oldset, regs);
	else
		setup_frame(sig, ka, oldset, regs);

	/**
	 * 建立了用户态堆栈后，检查相关标志。
	 * 如果没有设置SA_NODEFER,在信号处理期间，必须阻塞sa_mask中的信号。
	 * SA_NODEFER应该是表示信号处理函数是否允许重入的标志。
	 * 一般来说，信号处理函数因为是异常的，需要特别小心的处理，如果再支持重入，就更不容易了，估计没有谁都会设置这个标志。
	 */
	if (!(ka->sa.sa_flags & SA_NODEFER)) {
		spin_lock_irq(&current->sighand->siglock);
		sigorsets(&current->blocked,&current->blocked,&ka->sa.sa_mask);
		sigaddset(&current->blocked,sig);
		recalc_sigpending();
		spin_unlock_irq(&current->sighand->siglock);
	}
	/**
	 * 结束了，准备返回到do_signal,并返回到中断处理的下半部。
	 * 由于EIP已经被修改了，一回到用户态，就会执行信号处理程序了。
	 * 嘿嘿，万事俱备，只欠返回用户态了。
	 */

	/**
	 * 再罗嗦两句，你一定想知道信号处理完后，又会到哪里。
	 * 想想吧，我们设置的返回地址是：__kernel_sigreturn。
	 * 我猜想，这段代码可能被OS设置成象DLL那样，允许应用程序共享吧。
	 * 好，我们就看看__kernel_sigreturn具体是什么吧。
	 */
}

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 */
/**
 * 在从异常或者中断返回到用户态前，处理非阻塞的挂起信号。
 * regs-栈区的地址，当前进程在用户态下寄存器的内容。
 * oldset-变量的地址。可能是阻塞信号的位掩码或者为NULL
 */
int fastcall do_signal(struct pt_regs *regs, sigset_t *oldset)
{
	siginfo_t info;
	int signr;
	struct k_sigaction ka;

	/*
	 * We want the common case to go fast, which
	 * is why we may in certain cases get here from
	 * kernel mode. Just return without doing anything
	 * if so.
	 */
	/**
	 * 通常只是在CPU要返回到用户态时才调用do_signal函数
	 * 因此，如果中断处理程序调用do_signal，则该函数立刻返回。
	 */
	if ((regs->xcs & 3) != 3)
		return 1;

	/**
	 * 进程被冻结了。
	 */
	if (current->flags & PF_FREEZE) {
		refrigerator(0);
		goto no_signal;
	}

	/**
	 * oldset为NULL就用进程的阻塞信号掩码对它初始化。
	 */
	if (!oldset)
		oldset = &current->blocked;

	/**
	 * get_signal_to_deliver在信号队列（两个队列）中循环找一个需要处理的信号。
	 * 如果信号是默认处理或者忽略，它不会返回这样的信号。
	 * 返回的仅仅是设置了信号处理程序的信号
	 * get_signal_to_deliver会反复调用dequeue_signal，直到私有挂起信号队列和共享挂起信号队列中都没有非阻塞的信号
	 */
	signr = get_signal_to_deliver(&info, &ka, regs, NULL);

	/**
	 * get_signal_to_deliver返回0表示挂起信号已经全部被处理。
	 * 否则表示还有挂起信号正等待处理，并且是需要调用用户定义的程序。必须返回到用户态。
	 */
	if (signr > 0) {
		/* Reenable any watchpoints before delivering the
		 * signal to user space. The processor register will
		 * have been cleared if the watchpoint triggered
		 * inside the kernel.
		 */
		if (unlikely(current->thread.debugreg[7])) {
			__asm__("movl %0,%%db7"	: : "r" (current->thread.debugreg[7]));
		}

		/* Whee!  Actually deliver the signal.  */
		/**
		 * 执行用户定义的信号处理函数。这个过程很复杂，所以专门写了一个大函数来处理。
		 * 复杂性表现在：当前进程恢复正常执行前，需要执行用户态的信号处理程序。
		 * 而且，信号处理程序可以调用系统调用。这种情况下，执行了系统调用的服务例程以后，控制权必须返回到信号处理程序而不是被中断程序的正常代码流。
		 */
		handle_signal(signr, &info, &ka, oldset, regs);
		return 1;
	}

 no_signal:
	/* Did we come from a system call? */
	/**
	 * 信号被显式的忽略，或者执行了缺省的操作。而此时进程可能正在执行系统调用。
	 * 想一想，在接收信号前，用户可能调用了sleep这样的系统调用，由于它是TASK_INTERRUPTIBLE状态，由于信号的到来，
	 * 它变成TASK_RUNNING状态。这时，被中断的系统调用怎么办呢？
	 */
	if (regs->orig_eax >= 0) {/* orig_eax>=0表示系统调用，中断或者异常时，这个值小于0 */
		/* Restart the system call - no handlers present */
		/**
		 * eax是系统调用的返回值。当系统调用被信号打断时，它可能返回ERESTARTNOHAND，ERESTARTSYS，ERESTARTNOINTR
		 * 这几种返回值需要重新调用int指令。
		 */
		if (regs->eax == -ERESTARTNOHAND ||
		    regs->eax == -ERESTARTSYS ||
		    regs->eax == -ERESTARTNOINTR) {
			regs->eax = regs->orig_eax;
			/**
			 * int和sysenter指令都是两个字节长，所以回到用户态后，会重新调用int或者sysenter指令。
			 */
			regs->eip -= 2;
		}
		/**
		 * ERESTART_RESTARTBLOCK的处理不同，此时eax中存放的是restart_syscall
		 * 它执行__NR_restart_syscall调用。请参见nanosleep系统调用。
		 * 请注意：restore_sigcontext中current_thread_info()->restart_block.fn，这个回调会返回EINTR
		 */
		if (regs->eax == -ERESTART_RESTARTBLOCK){
			/**
			 * 主要用于时间相关的系统调用。当重新执行这些系统调用时，需要调整用户态参数。典型的例子是nanosleep
			 * 它设置了current_thread_info()->restart_block->fn=nanosleep_restart;
			 * 在nanosleep_restart会调整已经睡眠的时间。
			 * 在__NR_restart_syscall中会回调这个回调函数。
			 */
			regs->eax = __NR_restart_syscall;
			regs->eip -= 2;
		}
	}
	return 0;
}

/*
 * notification of userspace execution resumption
 * - triggered by current->work.notify_resume
 */
/**
 * 处理挂起信号和单步执行。
 */
__attribute__((regparm(3)))
void do_notify_resume(struct pt_regs *regs, sigset_t *oldset,
		      __u32 thread_info_flags)
{
	/* Pending single-step? */
	if (thread_info_flags & _TIF_SINGLESTEP) {
		regs->eflags |= TF_MASK;
		clear_thread_flag(TIF_SINGLESTEP);
	}
	/* deal with pending signal delivery */
	if (thread_info_flags & _TIF_SIGPENDING)
		do_signal(regs,oldset);
	
	clear_thread_flag(TIF_IRET);
}
