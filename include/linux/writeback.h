/*
 * include/linux/writeback.h.
 */
#ifndef WRITEBACK_H
#define WRITEBACK_H

struct backing_dev_info;

extern spinlock_t inode_lock;
/**
 * 正在使用的索引节点链表。不脏且i_count不为0.
 */
extern struct list_head inode_in_use;
/**
 * 有效未使用的索引节点链表。不脏且i_count为0.用于磁盘高速缓存。
 */
extern struct list_head inode_unused;

/*
 * Yes, writeback.h requires sched.h
 * No, sched.h is not included from here.
 */
static inline int current_is_pdflush(void)
{
	return current->flags & PF_FLUSHER;
}

/*
 * fs/fs-writeback.c
 */
enum writeback_sync_modes {
	WB_SYNC_NONE,	/* Don't wait on anything */
	WB_SYNC_ALL,	/* Wait on every mapping */
	WB_SYNC_HOLD,	/* Hold the inode on sb_dirty for sys_sync() */
};

/*
 * A control structure which tells the writeback code what to do.  These are
 * always on the stack, and hence need no locking.  They are always initialised
 * in a manner such that unspecified fields are set to zero.
 */
/**
 * 脏页刷新控制结构。
 */
struct writeback_control {
	/**
	 * 如果不为空，即指向一个backing_dev_info结构。此时，只有属于基本块设备的脏页将会被刷新。
	 */
	struct backing_dev_info *bdi;	/* If !NULL, only write back this
					   queue */
	/**
	 * 同步模式。
	 *     WB_SYNC_ALL:表示如果遇到一个上锁的索引节点，必须等待而不能略过它。
	 *     WB_SYNC_HOLD:表示把上锁的索引节点放入稍后的链表中。
	 *     WB_SYNC_NONE:表示简单的略过上锁的索引节点。
	 */
	enum writeback_sync_modes sync_mode;
	/**
	 * 如果不为空，就表示应该略过比指定值还新的索引节点。
	 */
	unsigned long *older_than_this;	/* If !NULL, only write back inodes
					   older than this */
	/**
	 * 当前执行流中仍然要写的脏页数量。
	 */ 
	long nr_to_write;		/* Write this many pages, and decrement
					   this for each page written */
	long pages_skipped;		/* Pages which were not written */

	/*
	 * For a_ops->writepages(): is start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
	loff_t start;
	loff_t end;

	/**
	 * 如果被设置，就不能阻塞进程。
	 */
	unsigned nonblocking:1;			/* Don't get stuck on request queues */
	unsigned encountered_congestion:1;	/* An output: a queue is full */
	unsigned for_kupdate:1;			/* A kupdate writeback */
	unsigned for_reclaim:1;			/* Invoked from the page allocator */
};

/*
 * ->writepage() return values (make these much larger than a pagesize, in
 * case some fs is returning number-of-bytes-written from writepage)
 */
#define WRITEPAGE_ACTIVATE	0x80000	/* IO was not started: activate page */

/*
 * fs/fs-writeback.c
 */	
void writeback_inodes(struct writeback_control *wbc);
void wake_up_inode(struct inode *inode);
int inode_wait(void *);
void sync_inodes_sb(struct super_block *, int wait);
void sync_inodes(int wait);

/* writeback.h requires fs.h; it, too, is not included from here. */
static inline void wait_on_inode(struct inode *inode)
{
	might_sleep();
	wait_on_bit(&inode->i_state, __I_LOCK, inode_wait,
							TASK_UNINTERRUPTIBLE);
}

/*
 * mm/page-writeback.c
 */
int wakeup_bdflush(long nr_pages);
void laptop_io_completion(void);
void laptop_sync_completion(void);

/* These are exported to sysctl. */
extern int dirty_background_ratio;
extern int vm_dirty_ratio;
extern int dirty_writeback_centisecs;
extern int dirty_expire_centisecs;
extern int block_dump;
extern int laptop_mode;

struct ctl_table;
struct file;
int dirty_writeback_centisecs_handler(struct ctl_table *, int, struct file *,
				      void __user *, size_t *, loff_t *);

void page_writeback_init(void);
void balance_dirty_pages_ratelimited(struct address_space *mapping);
int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0);
int do_writepages(struct address_space *mapping, struct writeback_control *wbc);
int sync_page_range(struct inode *inode, struct address_space *mapping,
			loff_t pos, size_t count);
int sync_page_range_nolock(struct inode *inode, struct address_space
		*mapping, loff_t pos, size_t count);

/* pdflush.c */
extern int nr_pdflush_threads;	/* Global so it can be exported to sysctl
				   read-only. */


#endif		/* WRITEBACK_H */
