#ifndef __I386_MMAN_H__
#define __I386_MMAN_H__

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */

/**
 * 线性区中的页可以被几个进程共享。
 */
#define MAP_SHARED	0x01		/* Share changes */
/**
 * 与MAP_SHARED相反
 * 当进程创建的映射只是为读文件，而不是写文件时才会使用此种映射。为此，私有映射的效率要比共享映射的效率要高。
 * 但是对私有映射页的任何写操作都会使内核停止映射该文件中的页。
 */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
/**
 * 区间的起始地址必须由参数addr指定。
 */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
/**
 * 没有文件与线性区关联
 * 但是，如果线性区同时有MAP_SHARED标志，那么线性区会在tmpfs文件系统中映射一个特殊的文件(即IPC共享)
 */
#define MAP_ANONYMOUS	0x20		/* don't use a file */

#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */
/**
 * 函数不必预先检查空闲页框的数目。
 */
#define MAP_NORESERVE	0x4000		/* don't check for reservations */
/**
 * 函数应该为线性区建立的映射提前分配需要的页框。该标志仅对映射文件的线性区和IPC共享线性区有意义。
 */
#define MAP_POPULATE	0x8000		/* populate (prefault) pagetables */
/**
 * 只有在MAP_POPULATE标志置位时才有意义。提前分配页框时，函数肯定不阻塞。
 */
#define MAP_NONBLOCK	0x10000		/* do not block on IO */

#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */

#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */

#define MADV_NORMAL	0x0		/* default page-in behavior */
#define MADV_RANDOM	0x1		/* page-in minimum required */
#define MADV_SEQUENTIAL	0x2		/* read-ahead aggressively */
#define MADV_WILLNEED	0x3		/* pre-fault pages */
#define MADV_DONTNEED	0x4		/* discard these pages */

/* compatibility flags */
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_FILE	0

#endif /* __I386_MMAN_H__ */
