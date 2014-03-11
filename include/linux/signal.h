#ifndef _LINUX_SIGNAL_H
#define _LINUX_SIGNAL_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/signal.h>
#include <asm/siginfo.h>

#ifdef __KERNEL__

#define MAX_SIGPENDING	1024

/*
 * Real Time signals may be queued.
 */
/**
 * 实时信号队列。
 */
struct sigqueue {
	/**
	 * 链表
	 */
	struct list_head list;
	/**
	 * 与挂起信号相应的信号处理程序描述中siglock字段的指针。
	 */
	spinlock_t *lock;
	/**
	 * 标志？？？
	 */
	int flags;
	/**
	 * 描述产生信号的事件。
	 */
	siginfo_t info;
	/**
	 * 存放进程拥有者的每用户数据结构的指针。
	 */
	struct user_struct *user;
};

/* flags values. */
#define SIGQUEUE_PREALLOC	1

/**
 * 挂起信号队列。
 */
struct sigpending {
	/**
	 * 包含sigqueue结构的双向链表。
	 */
	struct list_head list;
	/**
	 * 挂起信号的位掩码。
	 */
	sigset_t signal;
};

/*
 * Define some primitives to manipulate sigset_t.
 */

#ifndef __HAVE_ARCH_SIG_BITOPS
#include <linux/bitops.h>

/* We don't use <linux/bitops.h> for these because there is no need to
   be atomic.  */
/**
 * 把nsig信号在set变量中对应的位置为1
 */
static inline void sigaddset(sigset_t *set, int _sig)
{
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		set->sig[0] |= 1UL << sig;
	else
		set->sig[sig / _NSIG_BPW] |= 1UL << (sig % _NSIG_BPW);
}

/**
 * 把nsig信号在set变量中对应的位置为1
 */
static inline void sigdelset(sigset_t *set, int _sig)
{
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		set->sig[0] &= ~(1UL << sig);
	else
		set->sig[sig / _NSIG_BPW] &= ~(1UL << (sig % _NSIG_BPW));
}

/**
 * 返回nsig信号在set变量中对应位的值
 */
static inline int sigismember(sigset_t *set, int _sig)
{
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		return 1 & (set->sig[0] >> sig);
	else
		return 1 & (set->sig[sig / _NSIG_BPW] >> (sig % _NSIG_BPW));
}

static inline int sigfindinword(unsigned long word)
{
	return ffz(~word);
}

#endif /* __HAVE_ARCH_SIG_BITOPS */

/**
 * 产生nsig信号的位索引
 */
#define sigmask(sig)	(1UL << ((sig) - 1))

#ifndef __HAVE_ARCH_SIG_SETOPS
#include <linux/string.h>

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
	unsigned long a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	    case 4:							\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
	    case 2:							\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
	    case 1:							\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}

#define _sig_or(x,y)	((x) | (y))
/**
 * 在sl和sl变量之间执行逻辑或。其结果保存在d中。
 */
_SIG_SET_BINOP(sigorsets, _sig_or)

#define _sig_and(x,y)	((x) & (y))
/**
 * 在sl和sl变量之间执行逻辑与。其结果保存在d中。
 */
_SIG_SET_BINOP(sigandsets, _sig_and)

#define _sig_nand(x,y)	((x) & ~(y))
/**
 * 在sl和sl变量之间执行逻辑与非。其结果保存在d中。
 */
_SIG_SET_BINOP(signandsets, _sig_nand)

#undef _SIG_SET_BINOP
#undef _sig_or
#undef _sig_and
#undef _sig_nand

#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
									\
	switch (_NSIG_WORDS) {						\
	    case 4: set->sig[3] = op(set->sig[3]);			\
		    set->sig[2] = op(set->sig[2]);			\
	    case 2: set->sig[1] = op(set->sig[1]);			\
	    case 1: set->sig[0] = op(set->sig[0]);			\
		    break;						\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}

#define _sig_not(x)	(~(x))
_SIG_SET_OP(signotset, _sig_not)

#undef _SIG_SET_OP
#undef _sig_not

/**
 * 把set变量中的位置为0
 */
static inline void sigemptyset(sigset_t *set)
{
	switch (_NSIG_WORDS) {
	default:
		memset(set, 0, sizeof(sigset_t));
		break;
	case 2: set->sig[1] = 0;
	case 1:	set->sig[0] = 0;
		break;
	}
}
/**
 * 把set变量中的位置为1
 */
static inline void sigfillset(sigset_t *set)
{
	switch (_NSIG_WORDS) {
	default:
		memset(set, -1, sizeof(sigset_t));
		break;
	case 2: set->sig[1] = -1;
	case 1:	set->sig[0] = -1;
		break;
	}
}

/* Some extensions for manipulating the low 32 signals in particular.  */

/**
 * 把mask中的位在set变量中对应的所有位置为1
 * 仅针对1-32之间的信号
 */
static inline void sigaddsetmask(sigset_t *set, unsigned long mask)
{
	set->sig[0] |= mask;
}
/**
 * 把mask中的位在set变量中对应的所有位置为0
 * 仅针对1-32之间的信号
 */
static inline void sigdelsetmask(sigset_t *set, unsigned long mask)
{
	set->sig[0] &= ~mask;
}

/**
 * 如果mask在set中任何一位被设置，就返回1，否则返回0。仅适用于编号为1-32的信号。
 */
static inline int sigtestsetmask(sigset_t *set, unsigned long mask)
{
	return (set->sig[0] & mask) != 0;
}

/**
 * 用mask中的位初始化1-32之间的信号。并将高位清0。
 */
static inline void siginitset(sigset_t *set, unsigned long mask)
{
	set->sig[0] = mask;
	switch (_NSIG_WORDS) {
	default:
		memset(&set->sig[1], 0, sizeof(long)*(_NSIG_WORDS-1));
		break;
	case 2: set->sig[1] = 0;
	case 1: ;
	}
}


/**
 * 用mask中的位初始化1-32之间的信号。并把高位置1。
 */
static inline void siginitsetinv(sigset_t *set, unsigned long mask)
{
	set->sig[0] = ~mask;
	switch (_NSIG_WORDS) {
	default:
		memset(&set->sig[1], -1, sizeof(long)*(_NSIG_WORDS-1));
		break;
	case 2: set->sig[1] = -1;
	case 1: ;
	}
}

#endif /* __HAVE_ARCH_SIG_SETOPS */


static inline void init_sigpending(struct sigpending *sig)
{
	sigemptyset(&sig->signal);
	INIT_LIST_HEAD(&sig->list);
}

extern int group_send_sig_info(int sig, struct siginfo *info, struct task_struct *p);
extern long do_sigpending(void __user *, unsigned long);
extern int sigprocmask(int, sigset_t *, sigset_t *);

#ifndef HAVE_ARCH_GET_SIGNAL_TO_DELIVER
struct pt_regs;
extern int get_signal_to_deliver(siginfo_t *info, struct k_sigaction *return_ka, struct pt_regs *regs, void *cookie);
#endif

#endif /* __KERNEL__ */

#endif /* _LINUX_SIGNAL_H */
