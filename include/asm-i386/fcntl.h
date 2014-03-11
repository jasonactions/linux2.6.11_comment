#ifndef _I386_FCNTL_H
#define _I386_FCNTL_H

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	   0003
#define O_RDONLY	     00/* 只读 */
#define O_WRONLY	     01/* 只写 */
#define O_RDWR		     02/* 读写 */
#define O_CREAT		   0100	/* 不存在则创建 *//* not fcntl */
#define O_EXCL		   0200	/* 对O_CREAT标志，如果文件存在，则失败 *//* not fcntl */
#define O_NOCTTY	   0400	/* 从不把文件看作控制终端 *//* not fcntl */
#define O_TRUNC		  01000	/* 截断文件，删除现有内容 *//* not fcntl */
#define O_APPEND	  02000/* 在文件末尾开始写 */
#define O_NONBLOCK	  04000/* 非阻塞读 */
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		 010000/* 同步写 */
#define FASYNC		 020000	/* 通过信号发出IO事件通告 *//* fcntl, for BSD compatibility */
#define O_DIRECT	 040000	/* 直接IO *//* direct disk access hint */
#define O_LARGEFILE	0100000/* 大型文件，大小超过2G */
#define O_DIRECTORY	0200000/* 如果文件不是目录，则失败 */	/* must be a directory */
#define O_NOFOLLOW	0400000 /* 不解释路径名末尾的符号链接 *//* don't follow links */
#define O_NOATIME	01000000/* 不更新索引节点的访问时间 */

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7

#define F_SETOWN	8	/*  for sockets. */
#define F_GETOWN	9	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#define F_GETLK64	12	/*  using 'struct flock64' */
#define F_SETLK64	13
#define F_SETLKW64	14

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
/**
 * 申请一个共享读锁。
 */
#define LOCK_SH		1	/* shared lock */
/**
 * 申请一个排它锁，即写锁。
 */
#define LOCK_EX		2	/* exclusive lock */
/**
 * 当申请文件锁时，如果不能立即申请到，则不阻塞返回。
 */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
/**
 * 释放文件劝告锁。
 */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

/**
 * 用户态建立FL_POSIX锁时，向内核传递的参数。
 */
struct flock {
	/**
	 * 请求类型
	 */
	short l_type;
	/**
	 * 从什么地方开始加锁。
	 */
	short l_whence;
	/**
	 * 申请的偏移量
	 */
	off_t l_start;
	/**
	 * 加锁区域的长度。
	 */
	off_t l_len;
	/**
	 * 拥有者的PID
	 */
	pid_t l_pid;
};

struct flock64 {
	short  l_type;
	short  l_whence;
	loff_t l_start;
	loff_t l_len;
	pid_t  l_pid;
};

#define F_LINUX_SPECIFIC_BASE	1024

#endif
