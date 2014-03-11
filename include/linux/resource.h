#ifndef _LINUX_RESOURCE_H
#define _LINUX_RESOURCE_H

#include <linux/time.h>

/*
 * Resource control/accounting header file for linux
 */

/*
 * Definition of struct rusage taken from BSD 4.3 Reno
 * 
 * We don't support all of these yet, but we might as well have them....
 * Otherwise, each time we add new items, programs which depend on this
 * structure will lose.  This reduces the chances of that happening.
 */
#define	RUSAGE_SELF	0
#define	RUSAGE_CHILDREN	(-1)
#define RUSAGE_BOTH	(-2)		/* sys_wait4() uses this */

struct	rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
	long	ru_maxrss;		/* maximum resident set size */
	long	ru_ixrss;		/* integral shared memory size */
	long	ru_idrss;		/* integral unshared data size */
	long	ru_isrss;		/* integral unshared stack size */
	long	ru_minflt;		/* page reclaims */
	long	ru_majflt;		/* page faults */
	long	ru_nswap;		/* swaps */
	long	ru_inblock;		/* block input operations */
	long	ru_oublock;		/* block output operations */
	long	ru_msgsnd;		/* messages sent */
	long	ru_msgrcv;		/* messages received */
	long	ru_nsignals;		/* signals received */
	long	ru_nvcsw;		/* voluntary context switches */
	long	ru_nivcsw;		/* involuntary " */
};

/**
 * 进程资源限制。current->signal->rlim是一个数组，每个元素对应一个rlimit描述符。
 */
struct rlimit {
	/**
	 * 资源的当前限制值。
	 */
	unsigned long	rlim_cur;
	/**
	 * 资源限制所允许的最大值。
	 * 用户能够利用getrlimit和setrlimit系统调用，将一些资源的rlim_cur限制值增加到rlim_max。
	 * 但是，只有超级用户或者具有CAP_SYS_RESOURCE权限的用户才能改变rlim_max字段、或者将rlim_cur
	 * 设置成大于rlim_max字段的值。
	 */
	unsigned long	rlim_max;
};

#define	PRIO_MIN	(-20)
#define	PRIO_MAX	20

#define	PRIO_PROCESS	0
#define	PRIO_PGRP	1
#define	PRIO_USER	2

/*
 * Limit the stack by to some sane default: root can always
 * increase this limit if needed..  8MB seems reasonable.
 */
#define _STK_LIM	(8*1024*1024)

/*
 * GPG wants 32kB of mlocked memory, to make sure pass phrases
 * and other sensitive information are never written to disk.
 */
#define MLOCK_LIMIT	(8 * PAGE_SIZE)

/*
 * Due to binary compatibility, the actual resource numbers
 * may be different for different linux versions..
 */
#include <asm/resource.h>

#endif
