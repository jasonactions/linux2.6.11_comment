#ifndef _ASMi386_PARAM_H
#define _ASMi386_PARAM_H

#ifdef __KERNEL__
/**
 * HZ产生每秒时钟中断的近似个数，也就是时钟中断的频率。
 * 在PC上，这个值一般是1000
 */
# define HZ		1000		/* Internal kernel timer frequency */
# define USER_HZ	100		/* .. some user interfaces are in "ticks" */
# define CLOCKS_PER_SEC		(USER_HZ)	/* like times() */
#endif

#ifndef HZ
#define HZ 100
#endif

#define EXEC_PAGESIZE	4096

#ifndef NOGROUP
#define NOGROUP		(-1)
#endif

#define MAXHOSTNAMELEN	64	/* max length of hostname */
#define COMMAND_LINE_SIZE 256

#endif
