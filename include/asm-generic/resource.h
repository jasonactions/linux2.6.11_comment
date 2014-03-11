#ifndef _ASM_GENERIC_RESOURCE_H
#define _ASM_GENERIC_RESOURCE_H

/*
 * Resource limits
 */

/* Allow arch to control resource order */
#ifndef __ARCH_RLIMIT_ORDER
/**
 * 进程使用CPU的最长时间(以秒为单位)。如果进程超过了这个限制。内核就向它发一个SIGXCPU信号。
 * 如果进程还不终止，再发一个SIGKILL信号。
 */
#define RLIMIT_CPU		0	/* CPU time in ms */
/**
 * 文件大小的最大值(以字节为单位)。如果进程试图把一个文件的大小扩充到大于这个值。内核就给这个进程发SIGXFS信号。
 */
#define RLIMIT_FSIZE		1	/* Maximum filesize */
/**
 * 堆大小的最大值(以字节为单位)。在扩充进程的堆之前，内核检查这个值。
 */
#define RLIMIT_DATA		2	/* max data size */
/**
 * 栈大小的最大值(以字节为单位)。内核在扩充进程的用户态堆栈之前检查这个值。
 */
#define RLIMIT_STACK		3	/* max stack size */
/**
 * 内存信息转储文件的大小(以字节为单位)。当一个进程异常终止时，内核在进程的当前目录下
 * 创建内存信息转储文件之前检查这个值。如果这个值这为0,内核就不创建文件。
 */
#define RLIMIT_CORE		4	/* max core file size */
/**
 * 进程所拥有的页框最大数。目前是非强制的。
 */
#define RLIMIT_RSS		5	/* max resident set size */
/**
 * 用户能拥有的进程最大数。
 */
#define RLIMIT_NPROC		6	/* max number of processes */
/**
 * 打开文件描述符的最大数。
 * 当打开一个新文件或复制一个文件描述符时，内核检查这个值。
 */
#define RLIMIT_NOFILE		7	/* max number of open files */
/**
 * 非交换内存的最大值(以字节为单位)。
 * 当进程试图通过mlloc或mlockall系统调用锁住一个页框时，内核检查这个值。
 */
#define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
/**
 * 进程地址空间的最大数(以字节为单位)。当进程使用malloc或相关函数扩大它的地址空间时，内核检查这个值。
 */ 
#define RLIMIT_AS		9	/* address space limit */
/**
 * 文件锁的最大值。目前是非强制的。
 */
#define RLIMIT_LOCKS		10	/* maximum file locks held */
/**
 * 进程挂起信号的最大数。
 */
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
/**
 * POSIX消息队列中的最大字节数。
 */
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */

#define RLIM_NLIMITS		13
#endif

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 */
#ifndef RLIM_INFINITY
#define RLIM_INFINITY	(~0UL)
#endif

#ifndef _STK_LIM_MAX
#define _STK_LIM_MAX	RLIM_INFINITY
#endif

#ifdef __KERNEL__

#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_DATA]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {      _STK_LIM, _STK_LIM_MAX  },	\
	[RLIMIT_CORE]		= {             0, RLIM_INFINITY },	\
	[RLIMIT_RSS]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {             0,             0 },	\
	[RLIMIT_NOFILE]		= {      INR_OPEN,     INR_OPEN  },	\
	[RLIMIT_MEMLOCK]	= {   MLOCK_LIMIT,   MLOCK_LIMIT },	\
	[RLIMIT_AS]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { MAX_SIGPENDING, MAX_SIGPENDING },	\
	[RLIMIT_MSGQUEUE]	= { MQ_BYTES_MAX, MQ_BYTES_MAX },	\
}

#endif	/* __KERNEL__ */

#endif
