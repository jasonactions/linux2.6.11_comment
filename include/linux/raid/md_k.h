/*
   md_k.h : kernel internal structure of the Linux MD driver
          Copyright (C) 1996-98 Ingo Molnar, Gadi Oxman
	  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.
   
   You should have received a copy of the GNU General Public License
   (for example /usr/src/linux/COPYING); if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
*/

#ifndef _MD_K_H
#define _MD_K_H

#define MD_RESERVED       0UL
#define LINEAR            1UL
#define RAID0             2UL
#define RAID1             3UL
#define RAID5             4UL
#define TRANSLUCENT       5UL
#define HSM               6UL
#define MULTIPATH         7UL
#define RAID6		  8UL
#define	RAID10		  9UL
#define FAULTY		  10UL
#define MAX_PERSONALITY   11UL

#define	LEVEL_MULTIPATH		(-4)
#define	LEVEL_LINEAR		(-1)
#define	LEVEL_FAULTY		(-5)

#define MaxSector (~(sector_t)0)
#define MD_THREAD_NAME_MAX 14

static inline int pers_to_level (int pers)
{
	switch (pers) {
		case FAULTY:		return LEVEL_FAULTY;
		case MULTIPATH:		return LEVEL_MULTIPATH;
		case HSM:		return -3;
		case TRANSLUCENT:	return -2;
		case LINEAR:		return LEVEL_LINEAR;
		case RAID0:		return 0;
		case RAID1:		return 1;
		case RAID5:		return 5;
		case RAID6:		return 6;
		case RAID10:		return 10;
	}
	BUG();
	return MD_RESERVED;
}

static inline int level_to_pers (int level)
{
	switch (level) {
		case LEVEL_FAULTY: return FAULTY;
		case LEVEL_MULTIPATH: return MULTIPATH;
		case -3: return HSM;
		case -2: return TRANSLUCENT;
		case LEVEL_LINEAR: return LINEAR;
		case 0: return RAID0;
		case 1: return RAID1;
		case 4:
		case 5: return RAID5;
		case 6: return RAID6;
		case 10: return RAID10;
	}
	return MD_RESERVED;
}

typedef struct mddev_s mddev_t;
typedef struct mdk_rdev_s mdk_rdev_t;

#define MAX_MD_DEVS  256	/* Max number of md dev */

/*
 * options passed in raidrun:
 */

#define MAX_CHUNK_SIZE (4096*1024)

/*
 * default readahead
 */

static inline int disk_faulty(mdp_disk_t * d)
{
	return d->state & (1 << MD_DISK_FAULTY);
}

static inline int disk_active(mdp_disk_t * d)
{
	return d->state & (1 << MD_DISK_ACTIVE);
}

static inline int disk_sync(mdp_disk_t * d)
{
	return d->state & (1 << MD_DISK_SYNC);
}

static inline int disk_spare(mdp_disk_t * d)
{
	return !disk_sync(d) && !disk_active(d) && !disk_faulty(d);
}

static inline int disk_removed(mdp_disk_t * d)
{
	return d->state & (1 << MD_DISK_REMOVED);
}

static inline void mark_disk_faulty(mdp_disk_t * d)
{
	d->state |= (1 << MD_DISK_FAULTY);
}

static inline void mark_disk_active(mdp_disk_t * d)
{
	d->state |= (1 << MD_DISK_ACTIVE);
}

static inline void mark_disk_sync(mdp_disk_t * d)
{
	d->state |= (1 << MD_DISK_SYNC);
}

static inline void mark_disk_spare(mdp_disk_t * d)
{
	d->state = 0;
}

static inline void mark_disk_removed(mdp_disk_t * d)
{
	d->state = (1 << MD_DISK_FAULTY) | (1 << MD_DISK_REMOVED);
}

static inline void mark_disk_inactive(mdp_disk_t * d)
{
	d->state &= ~(1 << MD_DISK_ACTIVE);
}

static inline void mark_disk_nonsync(mdp_disk_t * d)
{
	d->state &= ~(1 << MD_DISK_SYNC);
}

/*
 * MD's 'extended' device
 */
/* SCSI设备中的磁盘描述符 */
struct mdk_rdev_s
{
	/* 通过此字段链接到SCSI设备的磁盘链表中 */
	struct list_head same_set;	/* RAID devices within the same set */

	/* 设备的磁盘扇区长度 */
	sector_t size;			/* Device size (in blocks) */
	/* 所属SCSI设备 */
	mddev_t *mddev;			/* RAID array if running */
	/* IO事件时间戳，用于判断SCSI设备最近是否空闲 */
	unsigned long last_events;	/* IO event timestamp */

	/* 磁盘的块设备描述符 */
	struct block_device *bdev;	/* block device handle */

	/* 保存磁盘超级块的页面 */
	struct page	*sb_page;
	/* 如果为1，表示该磁盘的RAID超级块已经读入内存 */
	int		sb_loaded;
	/* 磁盘阵列数据的起始位置 */
	sector_t	data_offset;	/* start of data in array */
	/* 超级块在磁盘上的起始扇区号 */
	sector_t	sb_offset;
	/* 次设备号 */
	int		preferred_minor;	/* autorun support */

	/* A device can be in one of three states based on two flags:
	 * Not working:   faulty==1 in_sync==0
	 * Fully working: faulty==0 in_sync==1
	 * Working, but not
	 * in sync with array
	 *                faulty==0 in_sync==0
	 *
	 * It can never have faulty==1, in_sync==1
	 * This reduces the burden of testing multiple flags in many cases
	 */
	int faulty;			/* if faulty do not issue IO requests */
	int in_sync;			/* device is a full member of the array */

	/* 本磁盘在MS超级块中的描述符索引 */
	int desc_nr;			/* descriptor index in the superblock */
	/* 在磁盘阵列中的角色 */
	int raid_disk;			/* role of device in array */

	/* 正在处理的请求数目  */
	atomic_t	nr_pending;	/* number of pending requests.
					 * only maintained for arrays that
					 * support hot removal
					 */
};

typedef struct mdk_personality_s mdk_personality_t;

/* RAID设备描述符 */
struct mddev_s
{
	/* 不同RAID级别的个性化设置 */
	void				*private;
	/* 个性化回调函数 */
	mdk_personality_t		*pers;
	/* 设备号 */
	dev_t				unit;
	/* 次设备号 */
	int				md_minor;
	/* 这个设备的所有成员设备链表 */
	struct list_head 		disks;
	int				sb_dirty;
	/* 0表示可写，1表示只读，2表示只读，但是在第一次写时自动转换为可写 */
	int				ro;

	/* 通用磁盘描述符 */
	struct gendisk			*gendisk;

	/* Superblock information */
	/* 超级块的主版本号、次版本号、补丁号 */
	int				major_version,
					minor_version,
					patch_version;
	/* 是否有持久化的超级块 */
	int				persistent;
	/* 条带长度 */
	int				chunk_size;
	/* MD设备的创建时间、超级块的修改时间 */
	time_t				ctime, utime;
	/* MD设备的级别、布局(仅适用于某些RAID级别) */
	int				level, layout;
	/* 成员磁盘个数 */
	int				raid_disks;
	/* 最大的磁盘成员个数 */
	int				max_disks;
	/* 长度 */
	sector_t			size; /* used size of component devices */
	/* 导出的阵列长度 */
	sector_t			array_size; /* exported array size */
	/* MD设备的更新计数器，在创建时设置为0，每发生一次重要事件加1 */
	__u64				events;

	/* 设备标识 */
	char				uuid[16];

	/* 管理线程描述符，仅对某些级别的RAID有用 */
	struct mdk_thread_s		*thread;	/* management thread */
	/* 同步线程描述符 */
	struct mdk_thread_s		*sync_thread;	/* doing resync or reconstruct */
	/* 最近已经调度的块 */
	sector_t			curr_resync;	/* blocks scheduled */
	/* 最近采集点的时间戳，用于计算同步速度 */
	unsigned long			resync_mark;	/* a recent timestamp */
	/* 最近采集点的已同步块数 */
	sector_t			resync_mark_cnt;/* blocks written at resync_mark */

	/* 所需要同步的最大扇区数 */
	sector_t			resync_max_sectors; /* may be set by personality */
	/* recovery/resync flags 
	 * NEEDED:   we might need to start a resync/recover
	 * RUNNING:  a thread is running, or about to be started
	 * SYNC:     actually doing a resync, not a recovery
	 * ERR:      and IO error was detected - abort the resync/recovery
	 * INTR:     someone requested a (clean) early abort.
	 * DONE:     thread is done and is waiting to be reaped
	 */
#define	MD_RECOVERY_RUNNING	0
#define	MD_RECOVERY_SYNC	1
#define	MD_RECOVERY_ERR		2
#define	MD_RECOVERY_INTR	3
#define	MD_RECOVERY_DONE	4
#define	MD_RECOVERY_NEEDED	5
	/* 同步/恢复标志 */
	unsigned long			recovery;

	/* 如果为1，表示这个RAID处于同步状态，不需要同步。当开始写时将其设置为0，所有单元都成功写入后设置为1 */
	int				in_sync;	/* know to not need resync */
	/* 配置时使用的信号量 */
	struct semaphore		reconfig_sem;
	/* 引用计数 */
	atomic_t			active;

	/* 如果为1，表示需要重新读入分区信息 */
	int				changed;	/* true if we might need to reread partition info */
	/* 有故障的磁盘数 */
	int				degraded;	/* whether md should consider
							 * adding a spare
							 */

	/* 已经调度，但没有写入的块数。在提交同步请求时增加，完成回调中减少 */
	atomic_t			recovery_active; /* blocks scheduled, but not written */
	/* 同步等待队列 */
	wait_queue_head_t		recovery_wait;
	/* 上次同步的位置，下次启动时可以从这个位置开始继续同步。 */
	sector_t			recovery_cp;
	/* 安全模式，在没有写入操作时总是更新超级块 */
	unsigned int			safemode;	/* if set, update "clean" superblock
							 * when no writes pending.
							 */ 
	/* 用于安全模式的超时时间 */
	unsigned int			safemode_delay;
	/* 安全模式的定时器 */
	struct timer_list		safemode_timer;
	/* 目前正在处理的写请求数目。 */
	atomic_t			writes_pending; 
	/* 请求队列 */
	request_queue_t			*queue;	/* for plugging ... */

	/* 通过此字段链接到所有SCSI设备的链表 */
	struct list_head		all_mddevs;
};


static inline void rdev_dec_pending(mdk_rdev_t *rdev, mddev_t *mddev)
{
	int faulty = rdev->faulty;
	if (atomic_dec_and_test(&rdev->nr_pending) && faulty)
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
}

static inline void md_sync_acct(struct block_device *bdev, unsigned long nr_sectors)
{
        atomic_add(nr_sectors, &bdev->bd_contains->bd_disk->sync_io);
}

/* RAID级别描述符 */
struct mdk_personality_s
{
	/* 级别名称 */
	char *name;
	/* 所属模块 */
	struct module *owner;
	/* 在将请求传递给MD设备时调用，执行特有的逻辑 */
	int (*make_request)(request_queue_t *q, struct bio *bio);
	/* 在启动该RAID级别时使用 */
	int (*run)(mddev_t *mddev);
	/* 停止该RAID级别时使用 */
	int (*stop)(mddev_t *mddev);
	/* 查询状态时回调 */
	void (*status)(struct seq_file *seq, mddev_t *mddev);
	/* error_handler must set ->faulty and clear ->in_sync
	 * if appropriate, and should abort recovery if needed 
	 */
	/* MD设备检测到某个磁盘发生故障时调用，如果没有容错能力的，则该指针为NULL */
	void (*error_handler)(mddev_t *mddev, mdk_rdev_t *rdev);
	/* 动态添加磁盘时调用 */
	int (*hot_add_disk) (mddev_t *mddev, mdk_rdev_t *rdev);
	/* 动态移除磁盘时调用 */
	int (*hot_remove_disk) (mddev_t *mddev, int number);
	/* 设备从故障中恢复，需要激活备用盘时调用 */
	int (*spare_active) (mddev_t *mddev);
	/* 同步时调用，如果不支持冗余，则为NULL */
	int (*sync_request)(mddev_t *mddev, sector_t sector_nr, int go_faster);
	/* 变量设备容量时调用 */
	int (*resize) (mddev_t *mddev, sector_t sectors);
	int (*reshape) (mddev_t *mddev, int raid_disks);
	int (*reconfig) (mddev_t *mddev, int layout, int chunk_size);
};


static inline char * mdname (mddev_t * mddev)
{
	return mddev->gendisk ? mddev->gendisk->disk_name : "mdX";
}

extern mdk_rdev_t * find_rdev_nr(mddev_t *mddev, int nr);

/*
 * iterates through some rdev ringlist. It's safe to remove the
 * current 'rdev'. Dont touch 'tmp' though.
 */
#define ITERATE_RDEV_GENERIC(head,rdev,tmp)				\
									\
	for ((tmp) = (head).next;					\
		(rdev) = (list_entry((tmp), mdk_rdev_t, same_set)),	\
			(tmp) = (tmp)->next, (tmp)->prev != &(head)	\
		; )
/*
 * iterates through the 'same array disks' ringlist
 */
#define ITERATE_RDEV(mddev,rdev,tmp)					\
	ITERATE_RDEV_GENERIC((mddev)->disks,rdev,tmp)

/*
 * Iterates through 'pending RAID disks'
 */
#define ITERATE_RDEV_PENDING(rdev,tmp)					\
	ITERATE_RDEV_GENERIC(pending_raid_disks,rdev,tmp)

/* RAID守护线程描述符 */
typedef struct mdk_thread_s {
	/* 线程处理函数指针 */
	void			(*run) (mddev_t *mddev);
	/* MD设备描述符的指针 */
	mddev_t			*mddev;
	/* 守护线程每执行一次，就将自己挂到该队列上，等待下一次唤醒或超时 */
	wait_queue_head_t	wqueue;
	/* 标志，当前仅支持THREAD_WAKEUP */
	unsigned long           flags;
	struct completion	*event;
	/* 进程描述符 */
	struct task_struct	*tsk;
	const char		*name;
} mdk_thread_t;

#define THREAD_WAKEUP  0

#define __wait_event_lock_irq(wq, condition, lock, cmd) 		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_UNINTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		spin_unlock_irq(&lock);					\
		cmd;							\
		schedule();						\
		spin_lock_irq(&lock);					\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_lock_irq(wq, condition, lock, cmd) 			\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event_lock_irq(wq, condition, lock, cmd);		\
} while (0)

#endif

