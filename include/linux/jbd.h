/*
 * linux/include/linux/jbd.h
 * 
 * Written by Stephen C. Tweedie <sct@redhat.com>
 *
 * Copyright 1998-2000 Red Hat, Inc --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Definitions for transaction data structures for the buffer cache
 * filesystem journaling support.
 */

#ifndef _LINUX_JBD_H
#define _LINUX_JBD_H

#if defined(CONFIG_JBD) || defined(CONFIG_JBD_MODULE) || !defined(__KERNEL__)

/* Allow this file to be included directly into e2fsprogs */
#ifndef __KERNEL__
#include "jfs_compat.h"
#define JFS_DEBUG
#define jfs_debug jbd_debug
#else

#include <linux/buffer_head.h>
#include <linux/journal-head.h>
#include <linux/stddef.h>
#include <asm/semaphore.h>
#endif

#define journal_oom_retry 1

/*
 * Define JBD_PARANIOD_IOFAIL to cause a kernel BUG() if ext3 finds
 * certain classes of error which can occur due to failed IOs.  Under
 * normal use we want ext3 to continue after such errors, because
 * hardware _can_ fail, but for debugging purposes when running tests on
 * known-good hardware we may want to trap these errors.
 */
#undef JBD_PARANOID_IOFAIL

/*
 * The default maximum commit age, in seconds.
 */
#define JBD_DEFAULT_MAX_COMMIT_AGE 5

#ifdef CONFIG_JBD_DEBUG
/*
 * Define JBD_EXPENSIVE_CHECKING to enable more expensive internal
 * consistency checks.  By default we don't do this unless
 * CONFIG_JBD_DEBUG is on.
 */
#define JBD_EXPENSIVE_CHECKING
extern int journal_enable_debug;

#define jbd_debug(n, f, a...)						\
	do {								\
		if ((n) <= journal_enable_debug) {			\
			printk (KERN_DEBUG "(%s, %d): %s: ",		\
				__FILE__, __LINE__, __FUNCTION__);	\
		  	printk (f, ## a);				\
		}							\
	} while (0)
#else
#define jbd_debug(f, a...)	/**/
#endif

extern void * __jbd_kmalloc (const char *where, size_t size, int flags, int retry);
#define jbd_kmalloc(size, flags) \
	__jbd_kmalloc(__FUNCTION__, (size), (flags), journal_oom_retry)
#define jbd_rep_kmalloc(size, flags) \
	__jbd_kmalloc(__FUNCTION__, (size), (flags), 1)

#define JFS_MIN_JOURNAL_BLOCKS 1024

#ifdef __KERNEL__

/**
 * typedef handle_t - The handle_t type represents a single atomic update being performed by some process.
 *
 * All filesystem modifications made by the process go
 * through this handle.  Recursive operations (such as quota operations)
 * are gathered into a single update.
 *
 * The buffer credits field is used to account for journaled buffers
 * being modified by the running process.  To ensure that there is
 * enough log space for all outstanding operations, we need to limit the
 * number of outstanding buffers possible at any time.  When the
 * operation completes, any buffer credits not used are credited back to
 * the transaction, so that at all times we know how many buffers the
 * outstanding updates on a transaction might possibly touch. 
 * 
 * This is an opaque datatype.
 **/
typedef struct handle_s		handle_t;	/* Atomic operation type */


/**
 * typedef journal_t - The journal_t maintains all of the journaling state information for a single filesystem.
 *
 * journal_t is linked to from the fs superblock structure.
 * 
 * We use the journal_t to keep track of all outstanding transaction
 * activity on the filesystem, and to manage the state of the log
 * writing process.
 *
 * This is an opaque datatype.
 **/
typedef struct journal_s	journal_t;	/* Journal control structure */
#endif

/*
 * Internal structures used by the logging mechanism:
 */

#define JFS_MAGIC_NUMBER 0xc03b3998U /* The first 4 bytes of /dev/random! */

/*
 * On-disk structures
 */

/* 
 * Descriptor block types:
 */

/**
 * 日志块，其数据来自于文件系统，并且要写回文件系统 
 * 参见journal_block_tag_s
 */
#define JFS_DESCRIPTOR_BLOCK	1
/**
 * 提交块 
 *
 */
#define JFS_COMMIT_BLOCK	2
/** 日志超级块
 * 参见journal_superblock_s
 */
#define JFS_SUPERBLOCK_V1	3
#define JFS_SUPERBLOCK_V2	4
/* 撤销块 */
#define JFS_REVOKE_BLOCK	5

/*
 * Standard header for all descriptor blocks:
 */
/**
 * 描述符块的头
 */
typedef struct journal_header_s
{
	/**
	 * 描述符的魔术值，如:
	 *		JFS_MAGIC_NUMBER
	 */
	__be32		h_magic;
	/**
	 * 描述符块的类型，如:
	 *		JFS_DESCRIPTOR_BLOCK
	 */
	__be32		h_blocktype;
	/**
	 * 事务序号
	 */
	__be32		h_sequence;
} journal_header_t;


/* 
 * The block tag: used to describe a single buffer in the journal 
 */
typedef struct journal_block_tag_s
{
	/**
	 * 数据在文件系统中的磁盘块号
	 */
	__be32		t_blocknr;	/* The on-disk block number */
	/**
	 * 标志，如JFS_FLAG_ESCAPE
	 */
	__be32		t_flags;	/* See below */
} journal_block_tag_t;

/* 
 * The revoke descriptor: used on disk to describe a series of blocks to
 * be revoked from the log 
 */
typedef struct journal_revoke_header_s
{
	journal_header_t r_header;
	/* 占用字节数，含头 */
	__be32		 r_count;	/* Count of bytes used in the block */
} journal_revoke_header_t;


/* Definitions for the journal tag flags word: */
/* 数据被转义，写回前需要转回去 */
#define JFS_FLAG_ESCAPE		1	/* on-disk block is escaped */
/* 与上一个描述符块的UUID相同 */
#define JFS_FLAG_SAME_UUID	2	/* block has same uuid as previous */
/* 未用 */
#define JFS_FLAG_DELETED	4	/* block deleted by this transaction */
/* 结束符，表示一个事务的结束 */
#define JFS_FLAG_LAST_TAG	8	/* last tag in this descriptor block */


/*
 * The journal superblock.  All fields are in big-endian byte order.
 */
/**
 * 日志超级块描述符
 */
typedef struct journal_superblock_s
{
/* 0x0000 */
	/**
	 * 日志块描述，应该用超级块的描述块
	 */
	journal_header_t s_header;

/* 0x000C */
	/* Static information describing the journal */
	/* 日志设备的块大小 */
	__be32	s_blocksize;		/* journal device blocksize */
	/* 日志总块数 */
	__be32	s_maxlen;		/* total blocks in journal file */
	/**
	 * 日志块的第一个块号 
	 * 初始为1
	 */
	__be32	s_first;		/* first block of log information */

/* 0x0018 */
	/* Dynamic information describing the current state of the log */
	/* 最老的事务编号 */
	__be32	s_sequence;		/* first commit ID expected in log */
	/* 日志开始的块号，为0表示日志为空 */
	__be32	s_start;		/* blocknr of start of log */

/* 0x0020 */
	/* Error value, as set by journal_abort(). */
	__be32	s_errno;

/* 0x0024 */
	/* Remaining fields are only valid in a version-2 superblock */
	__be32	s_feature_compat; 	/* compatible feature set */
	__be32	s_feature_incompat; 	/* incompatible feature set */
	__be32	s_feature_ro_compat; 	/* readonly-compatible feature set */
/* 0x0030 */
	__u8	s_uuid[16];		/* 128-bit uuid for journal */

/* 0x0040 */
	__be32	s_nr_users;		/* Nr of filesystems sharing log */

	__be32	s_dynsuper;		/* Blocknr of dynamic superblock copy*/

/* 0x0048 */
	__be32	s_max_transaction;	/* Limit of journal blocks per trans.*/
	__be32	s_max_trans_data;	/* Limit of data blocks per trans. */

/* 0x0050 */
	__u32	s_padding[44];

/* 0x0100 */
	__u8	s_users[16*48];		/* ids of all fs'es sharing the log */
/* 0x0400 */
} journal_superblock_t;

#define JFS_HAS_COMPAT_FEATURE(j,mask)					\
	((j)->j_format_version >= 2 &&					\
	 ((j)->j_superblock->s_feature_compat & cpu_to_be32((mask))))
#define JFS_HAS_RO_COMPAT_FEATURE(j,mask)				\
	((j)->j_format_version >= 2 &&					\
	 ((j)->j_superblock->s_feature_ro_compat & cpu_to_be32((mask))))
#define JFS_HAS_INCOMPAT_FEATURE(j,mask)				\
	((j)->j_format_version >= 2 &&					\
	 ((j)->j_superblock->s_feature_incompat & cpu_to_be32((mask))))

#define JFS_FEATURE_INCOMPAT_REVOKE	0x00000001

/* Features known to this kernel version: */
#define JFS_KNOWN_COMPAT_FEATURES	0
#define JFS_KNOWN_ROCOMPAT_FEATURES	0
#define JFS_KNOWN_INCOMPAT_FEATURES	JFS_FEATURE_INCOMPAT_REVOKE

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/bug.h>

#define JBD_ASSERTIONS
#ifdef JBD_ASSERTIONS
#define J_ASSERT(assert)						\
do {									\
	if (!(assert)) {						\
		printk (KERN_EMERG					\
			"Assertion failure in %s() at %s:%d: \"%s\"\n",	\
			__FUNCTION__, __FILE__, __LINE__, # assert);	\
		BUG();							\
	}								\
} while (0)

#if defined(CONFIG_BUFFER_DEBUG)
void buffer_assertion_failure(struct buffer_head *bh);
#define J_ASSERT_BH(bh, expr)						\
	do {								\
		if (!(expr))						\
			buffer_assertion_failure(bh);			\
		J_ASSERT(expr);						\
	} while (0)
#define J_ASSERT_JH(jh, expr)	J_ASSERT_BH(jh2bh(jh), expr)
#else
#define J_ASSERT_BH(bh, expr)	J_ASSERT(expr)
#define J_ASSERT_JH(jh, expr)	J_ASSERT(expr)
#endif

#else
#define J_ASSERT(assert)	do { } while (0)
#endif		/* JBD_ASSERTIONS */

#if defined(JBD_PARANOID_IOFAIL)
#define J_EXPECT(expr, why...)		J_ASSERT(expr)
#define J_EXPECT_BH(bh, expr, why...)	J_ASSERT_BH(bh, expr)
#define J_EXPECT_JH(jh, expr, why...)	J_ASSERT_JH(jh, expr)
#else
#define __journal_expect(expr, why...)					     \
	({								     \
		int val = (expr);					     \
		if (!val) {						     \
			printk(KERN_ERR					     \
				"EXT3-fs unexpected failure: %s;\n",# expr); \
			printk(KERN_ERR why "\n");			     \
		}							     \
		val;							     \
	})
#define J_EXPECT(expr, why...)		__journal_expect(expr, ## why)
#define J_EXPECT_BH(bh, expr, why...)	__journal_expect(expr, ## why)
#define J_EXPECT_JH(jh, expr, why...)	__journal_expect(expr, ## why)
#endif

enum jbd_state_bits {
	BH_JBD			/* Has an attached ext3 journal_head */
	  = BH_PrivateStart,
	BH_JWrite,		/* Being written to log (@@@ DEBUGGING) */
	BH_Freed,		/* Has been freed (truncated) */
	BH_Revoked,		/* Has been revoked from the log */
	BH_RevokeValid,		/* Revoked flag is valid */
	BH_JBDDirty,		/* Is dirty but journaled */
	BH_State,		/* Pins most journal_head state */
	BH_JournalHead,		/* Pins bh->b_private and jh->b_bh */
	BH_Unshadow,		/* Dummy bit, for BJ_Shadow wakeup filtering */
};

BUFFER_FNS(JBD, jbd)
BUFFER_FNS(JWrite, jwrite)
BUFFER_FNS(JBDDirty, jbddirty)
TAS_BUFFER_FNS(JBDDirty, jbddirty)
BUFFER_FNS(Revoked, revoked)
TAS_BUFFER_FNS(Revoked, revoked)
BUFFER_FNS(RevokeValid, revokevalid)
TAS_BUFFER_FNS(RevokeValid, revokevalid)
BUFFER_FNS(Freed, freed)

static inline struct buffer_head *jh2bh(struct journal_head *jh)
{
	return jh->b_bh;
}

static inline struct journal_head *bh2jh(struct buffer_head *bh)
{
	return bh->b_private;
}

static inline void jbd_lock_bh_state(struct buffer_head *bh)
{
	bit_spin_lock(BH_State, &bh->b_state);
}

static inline int jbd_trylock_bh_state(struct buffer_head *bh)
{
	return bit_spin_trylock(BH_State, &bh->b_state);
}

static inline int jbd_is_locked_bh_state(struct buffer_head *bh)
{
	return bit_spin_is_locked(BH_State, &bh->b_state);
}

static inline void jbd_unlock_bh_state(struct buffer_head *bh)
{
	bit_spin_unlock(BH_State, &bh->b_state);
}

static inline void jbd_lock_bh_journal_head(struct buffer_head *bh)
{
	bit_spin_lock(BH_JournalHead, &bh->b_state);
}

static inline void jbd_unlock_bh_journal_head(struct buffer_head *bh)
{
	bit_spin_unlock(BH_JournalHead, &bh->b_state);
}

struct jbd_revoke_table_s;

/**
 * struct handle_s - The handle_s type is the concrete type associated with
 *     handle_t.
 * @h_transaction: Which compound transaction is this update a part of?
 * @h_buffer_credits: Number of remaining buffers we are allowed to dirty.
 * @h_ref: Reference count on this handle
 * @h_err: Field for caller's use to track errors through large fs operations
 * @h_sync: flag for sync-on-close
 * @h_jdata: flag to force data journaling
 * @h_aborted: flag indicating fatal error on handle
 **/

/* Docbook can't yet cope with the bit fields, but will leave the documentation
 * in so it can be fixed later. 
 */
/**
 * 代表JBD中一个原子操作
 * 可以包含多个磁盘块
 */
struct handle_s 
{
	/* Which compound transaction is this update a part of? */
	/**
	 * 本原子操作属于哪个事务
	 */
	transaction_t		*h_transaction;

	/* Number of remaining buffers we are allowed to dirty: */
	/**
	 * 本原子操作可用的额度，也就是还可以用多少个磁盘块
	 */
	int			h_buffer_credits;

	/* Reference count on this handle */
	/**
	 * 引用计数
	 */
	int			h_ref;

	/* Field for caller's use to track errors through large fs */
	/* operations */
	int			h_err;

	/* Flags [no locking] */
	/**
	 * 处理完原子操作后，立即提交事务
	 */
	unsigned int	h_sync:		1;	/* sync-on-close */
	unsigned int	h_jdata:	1;	/* force data journaling */
	unsigned int	h_aborted:	1;	/* fatal error on handle */
};


/* The transaction_t type is the guts of the journaling mechanism.  It
 * tracks a compound transaction through its various states:
 *
 * RUNNING:	accepting new updates
 * LOCKED:	Updates still running but we don't accept new ones
 * RUNDOWN:	Updates are tidying up but have finished requesting
 *		new buffers to modify (state not used for now)
 * FLUSH:       All updates complete, but we are still writing to disk
 * COMMIT:      All data on disk, writing commit record
 * FINISHED:	We still have to keep the transaction for checkpointing.
 *
 * The transaction keeps track of all of the buffers modified by a
 * running transaction, and all of the buffers committed but not yet
 * flushed to home for finished transactions.
 */

/*
 * Lock ranking:
 *
 *    j_list_lock
 *      ->jbd_lock_bh_journal_head()	(This is "innermost")
 *
 *    j_state_lock
 *    ->jbd_lock_bh_state()
 *
 *    jbd_lock_bh_state()
 *    ->j_list_lock
 *
 *    j_state_lock
 *    ->t_handle_lock
 *
 *    j_state_lock
 *    ->j_list_lock			(journal_unmap_buffer)
 *
 */
/**
 * 一个完整的事务，可以包含多个原子操作。
 */
struct transaction_s 
{
	/* Pointer to the journal for this transaction. [no locking] */
	/**
	 * 所属的日志
	 */
	journal_t		*t_journal;

	/* Sequence number for this transaction [no locking] */
	/**
	 * 本事务的序号
	 */
	tid_t			t_tid;

	/*
	 * Transaction's current state
	 * [no locking - only kjournald alters this]
	 * FIXME: needs barriers
	 * KLUDGE: [use j_state_lock]
	 */
	/**
	 * 事务当前的状态
	 */
	enum {
		/*
		 * 事务正在运行，可以接收新的原子操作。
		 */
		T_RUNNING,
		/**
		 * 事务已经被锁，不接收新的原子操作。
		 */
		T_LOCKED,
		T_RUNDOWN,
		/**
		 * 事务正准备被提交到日志中。
		 * 新的原子操作，需要放到新的事务中。
		 * 同时正在将数据块提交到磁盘
		 */
		T_FLUSH,
		/**
		 * 正在将事务的元数据提交到日志中。
		 */
		T_COMMIT,
		T_FINISHED 
	}			t_state;

	/*
	 * Where in the log does this transaction's commit start? [no locking]
	 */
	/**
	 * 本事务从日志的哪一个块开始
	 */
	unsigned long		t_log_start;

	/* Number of buffers on the t_buffers list [j_list_lock] */
	/**
	 * 本事务中缓冲区的个数
	 */
	int			t_nr_buffers;

	/*
	 * Doubly-linked circular list of all buffers reserved but not yet
	 * modified by this transaction [j_list_lock]
	 */
	/**
	 * 被事务所保留，但是没有使用的缓冲区
	 * 在提交事务前被释放
	 */
	struct journal_head	*t_reserved_list;

	/*
	 * Doubly-linked circular list of all buffers under writeout during
	 * commit [j_list_lock]
	 */
	/**
	 * 被锁住的缓冲区
	 * 这些缓冲区在文件系统中被暂缓提交
	 * 直到日志被提交后才提交。
	 */
	struct journal_head	*t_locked_list;

	/*
	 * Doubly-linked circular list of all metadata buffers owned by this
	 * transaction [j_list_lock]
	 */
	/**
	 * 所有元数据缓冲区的链表。
	 */
	struct journal_head	*t_buffers;

	/*
	 * Doubly-linked circular list of all data buffers still to be
	 * flushed before this transaction can be committed [j_list_lock]
	 */
	/**
	 * 与当前事务相关的数据缓冲区。
	 * 在ordered模式下，应当首先将其写入磁盘，再写入元数据。
	 */
	struct journal_head	*t_sync_datalist;

	/*
	 * Doubly-linked circular list of all forget buffers (superseded
	 * buffers which we can un-checkpoint once this transaction commits)
	 * [j_list_lock]
	 */
	/**
	 * 一旦本事务被提交，就可以废弃的缓冲区。
	 * 主要是与前面的事务共享的元数据缓冲区。
	 */
	struct journal_head	*t_forget;

	/*
	 * Doubly-linked circular list of all buffers still to be flushed before
	 * this transaction can be checkpointed. [j_list_lock]
	 */
	/**
	 * 在checkpoint时，已经提交进行IO的缓冲区链表
	 */
	struct journal_head	*t_checkpoint_list;

	/*
	 * Doubly-linked circular list of temporary buffers currently undergoing
	 * IO in the log [j_list_lock]
	 */
	/**
	 * 当前正在等待IO写入的链表。
	 * 此链表中的数据，包含了要写入到日志中的元数据缓冲区。
	 * 以及撤销表等等
	 * 需要等待此链表中数据全部写入后，才能写入提交块
	 */
	struct journal_head	*t_iobuf_list;

	/*
	 * Doubly-linked circular list of metadata buffers being shadowed by log
	 * IO.  The IO buffers on the iobuf list and the shadow buffers on this
	 * list match each other one for one at all times. [j_list_lock]
	 */
	/**
	 * 与t_iobuf_list一起构成了元数据链表
	 * 这些缓冲区都会被写入日志
	 * 处理转义??
	 */
	struct journal_head	*t_shadow_list;

	/*
	 * Doubly-linked circular list of control buffers being written to the
	 * log. [j_list_lock]
	 */
	/**
	 * 等待写入IO的链表。
	 * 此链表中的数据，包含要写入到日志中的控制块。
	 */
	struct journal_head	*t_log_list;

	/*
	 * Protects info related to handles
	 */
	/**
	 * 保护原子操作的锁
	 */
	spinlock_t		t_handle_lock;

	/*
	 * Number of outstanding updates running on this transaction
	 * [t_handle_lock]
	 */
	/**
	 * 正在使用本事务的原子操作数量
	 * 在提交前，需要等待其值为0，表示没有原子操作向它提交请求。
	 * 在journal_start时加1，journal_stop减1
	 */
	int			t_updates;

	/*
	 * Number of buffers reserved for use by all handles in this transaction
	 * handle but not yet modified. [t_handle_lock]
	 */
	/**
	 * 保留给原子操作使用，但是还没有被使用的缓冲区额度
	 * 在写日志时递减
	 */
	int			t_outstanding_credits;

	/*
	 * Forward and backward links for the circular list of all transactions
	 * awaiting checkpoint. [j_list_lock]
	 */
	/**
	 * 通过这两个指针
	 * 将事务链接到日志的checkpoint队列中
	 */
	transaction_t		*t_cpnext, *t_cpprev;

	/*
	 * When will the transaction expire (become due for commit), in jiffies?
	 * [no locking]
	 */
	/**
	 * 事务的超时时间
	 * 当超过此时间时，即使事务中缓冲区较少，也会提交。
	 */
	unsigned long		t_expires;

	/*
	 * How many handles used this transaction? [t_handle_lock]
	 */
	/**
	 * 本事务中包含了多少个原子操作
	 */
	int t_handle_count;

};

/**
 * struct journal_s - The journal_s type is the concrete type associated with
 *     journal_t.
 * @j_flags:  General journaling state flags
 * @j_errno:  Is there an outstanding uncleared error on the journal (from a
 *     prior abort)? 
 * @j_sb_buffer: First part of superblock buffer
 * @j_superblock: Second part of superblock buffer
 * @j_format_version: Version of the superblock format
 * @j_barrier_count:  Number of processes waiting to create a barrier lock
 * @j_barrier: The barrier lock itself
 * @j_running_transaction: The current running transaction..
 * @j_committing_transaction: the transaction we are pushing to disk
 * @j_checkpoint_transactions: a linked circular list of all transactions
 *  waiting for checkpointing
 * @j_wait_transaction_locked: Wait queue for waiting for a locked transaction
 *  to start committing, or for a barrier lock to be released
 * @j_wait_logspace: Wait queue for waiting for checkpointing to complete
 * @j_wait_done_commit: Wait queue for waiting for commit to complete 
 * @j_wait_checkpoint:  Wait queue to trigger checkpointing
 * @j_wait_commit: Wait queue to trigger commit
 * @j_wait_updates: Wait queue to wait for updates to complete
 * @j_checkpoint_sem: Semaphore for locking against concurrent checkpoints
 * @j_head: Journal head - identifies the first unused block in the journal
 * @j_tail: Journal tail - identifies the oldest still-used block in the
 *  journal.
 * @j_free: Journal free - how many free blocks are there in the journal?
 * @j_first: The block number of the first usable block 
 * @j_last: The block number one beyond the last usable block
 * @j_dev: Device where we store the journal
 * @j_blocksize: blocksize for the location where we store the journal.
 * @j_blk_offset: starting block offset for into the device where we store the
 *     journal
 * @j_fs_dev: Device which holds the client fs.  For internal journal this will
 *     be equal to j_dev
 * @j_maxlen: Total maximum capacity of the journal region on disk.
 * @j_inode: Optional inode where we store the journal.  If present, all journal
 *     block numbers are mapped into this inode via bmap().
 * @j_tail_sequence:  Sequence number of the oldest transaction in the log 
 * @j_transaction_sequence: Sequence number of the next transaction to grant
 * @j_commit_sequence: Sequence number of the most recently committed
 *  transaction
 * @j_commit_request: Sequence number of the most recent transaction wanting
 *     commit 
 * @j_uuid: Uuid of client object.
 * @j_task: Pointer to the current commit thread for this journal
 * @j_max_transaction_buffers:  Maximum number of metadata buffers to allow in a
 *     single compound commit transaction
 * @j_commit_interval: What is the maximum transaction lifetime before we begin
 *  a commit?
 * @j_commit_timer:  The timer used to wakeup the commit thread
 * @j_revoke: The revoke table - maintains the list of revoked blocks in the
 *     current transaction.
 */
/**
 * 日志描述符
 */
struct journal_s
{
	/* General journaling state flags [j_state_lock] */
	/* 日志的状态标志*/
	unsigned long		j_flags;

	/*
	 * Is there an outstanding uncleared error on the journal (from a prior
	 * abort)? [j_state_lock]
	 */
	int			j_errno;

	/* The superblock buffer */
	/* 日志的超级块缓冲区 */
	struct buffer_head	*j_sb_buffer;
	journal_superblock_t	*j_superblock;

	/* Version of the superblock format */
	int			j_format_version;

	/*
	 * Protect the various scalars in the journal
	 */
	spinlock_t		j_state_lock;

	/*
	 * Number of processes waiting to create a barrier lock [j_state_lock]
	 */
	/**
	 * 等待创建屏障的任务数
	 */
	int			j_barrier_count;

	/* The barrier lock itself */
	struct semaphore	j_barrier;

	/*
	 * Transactions: The current running transaction...
	 * [j_state_lock] [caller holding open handle]
	 */
	/**
	 * 当前正在运行的事务。
	 * 如果为NULL，需要为新的原子操作创建新的事务。
	 * 这个事务正在接受新的原子操作请求。
	 */
	transaction_t		*j_running_transaction;

	/*
	 * the transaction we are pushing to disk
	 * [j_state_lock] [caller holding open handle]
	 */
	/**
	 * 当前正在提交的事务。
	 */
	transaction_t		*j_committing_transaction;

	/*
	 * ... and a linked circular list of all transactions waiting for
	 * checkpointing. [j_list_lock]
	 */
	/**
	 * 等待checkpoint的事务链表头
	 */
	transaction_t		*j_checkpoint_transactions;

	/*
	 * Wait queue for waiting for a locked transaction to start committing,
	 * or for a barrier lock to be released
	 */
	/**
	 * 当开始进行一个新事务提交时
	 * 唤醒等待记录日志的线程，表示可以开始一个新事务了
	 */
	wait_queue_head_t	j_wait_transaction_locked;

	/* Wait queue for waiting for checkpointing to complete */
	wait_queue_head_t	j_wait_logspace;

	/* Wait queue for waiting for commit to complete */
	/**
	 * 等待队列
	 * 线程正在此队列上等待日志被提交
	 * 由日志线程唤醒队列上的等待线程
	 */
	wait_queue_head_t	j_wait_done_commit;

	/* Wait queue to trigger checkpointing */
	wait_queue_head_t	j_wait_checkpoint;

	/* Wait queue to trigger commit */
	/**
	 * 等待队列
	 * 日志线程会在此队列上等待
	 */
	wait_queue_head_t	j_wait_commit;

	/* Wait queue to wait for updates to complete */
	/**
	 * 等待队列
	 * 日志线程在此队列上等待
	 * 当结束原子操作时唤醒
	 */
	wait_queue_head_t	j_wait_updates;

	/* Semaphore for locking against concurrent checkpoints */
	/* 保护checkpoint链表的互斥锁 */
	struct semaphore 	j_checkpoint_sem;

	/*
	 * Journal head: identifies the first unused block in the journal.
	 * [j_state_lock]
	 */
	/**
	 *  第一个未使用的日志块
	 */
	unsigned long		j_head;

	/*
	 * Journal tail: identifies the oldest still-used block in the journal.
	 * [j_state_lock]
	 */
	/**
	 * 最后一个仍然在使用的日志块
	 */
	unsigned long		j_tail;

	/*
	 * Journal free: how many free blocks are there in the journal?
	 * [j_state_lock]
	 */
	/**
	 * 日志中剩余的空闲块，为0表示已经满了
	 */
	unsigned long		j_free;

	/*
	 * Journal start and end: the block numbers of the first usable block
	 * and one beyond the last usable block in the journal. [j_state_lock]
	 */
	/**
	 * 格式化时，确定的起始结束块号
	 */
	unsigned long		j_first;
	unsigned long		j_last;

	/*
	 * Device, blocksize and starting block offset for the location where we
	 * store the journal.
	 */
	/**
	 * 日志块设备
	 */
	struct block_device	*j_dev;
	/**
	 * 块大小
	 */
	int			j_blocksize;
	/* 日志在块设备中偏移量 */
	unsigned int		j_blk_offset;

	/*
	 * Device which holds the client fs.  For internal journal this will be
	 * equal to j_dev.
	 */
	/**
	 * 与日志绑定的文件系统，其所在的设备
	 */
	struct block_device	*j_fs_dev;

	/* Total maximum capacity of the journal region on disk. */
	/**
	 * 日志在磁盘中的最大容量
	 */
	unsigned int		j_maxlen;

	/*
	 * Protects the buffer lists and internal buffer state.
	 */
	spinlock_t		j_list_lock;

	/* Optional inode where we store the journal.  If present, all */
	/* journal block numbers are mapped into this inode via */
	/* bmap(). */
	struct inode		*j_inode;

	/*
	 * Sequence number of the oldest transaction in the log [j_state_lock]
	 */
	/* 日志中最老的事务编号 */
	tid_t			j_tail_sequence;

	/*
	 * Sequence number of the next transaction to grant [j_state_lock]
	 */
	/* 下一个事务的编号 */
	tid_t			j_transaction_sequence;

	/*
	 * Sequence number of the most recently committed transaction
	 * [j_state_lock].
	 */
	/* 最近提交的事务编号 */
	tid_t			j_commit_sequence;

	/*
	 * Sequence number of the most recent transaction wanting commit
	 * [j_state_lock]
	 */
	/**
	 * 最近想提交的事务编号 
	 * 调用者在该事务ID上调用了journal_stop
	 * 并且希望提交此事务
	 */
	tid_t			j_commit_request;

	/*
	 * Journal uuid: identifies the object (filesystem, LVM volume etc)
	 * backed by this journal.  This will eventually be replaced by an array
	 * of uuids, allowing us to index multiple devices within a single
	 * journal and to perform atomic updates across them.
	 */
	__u8			j_uuid[16];

	/* Pointer to the current commit thread for this journal */
	/* 日志线程 */
	struct task_struct	*j_task;

	/*
	 * Maximum number of metadata buffers to allow in a single compound
	 * commit transaction
	 */
	/* 一次允许提交的日志缓冲区个数 */
	int			j_max_transaction_buffers;

	/*
	 * What is the maximum transaction lifetime before we begin a commit?
	 */
	unsigned long		j_commit_interval;

	/* The timer used to wakeup the commit thread: */
	/* 定期唤醒线程的定时器 */
	struct timer_list	*j_commit_timer;

	/*
	 * The revoke table: maintains the list of revoked blocks in the
	 * current transaction.  [j_revoke_lock]
	 */
	/* 保护撤销块的锁 */
	spinlock_t		j_revoke_lock;
	/* 正在使用的撤销哈希表 */
	struct jbd_revoke_table_s *j_revoke;
	/* 两个撤销表，一个备用，一个正在用 */
	struct jbd_revoke_table_s *j_revoke_table[2];

	/*
	 * An opaque pointer to fs-private information.  ext3 puts its
	 * superblock pointer here
	 */
	/* 对ext3来说，指向其超级块 */
	void *j_private;
};

/* 
 * Journal flag definitions 
 */
#define JFS_UNMOUNT	0x001	/* Journal thread is being destroyed */
#define JFS_ABORT	0x002	/* Journaling has been aborted for errors. */
#define JFS_ACK_ERR	0x004	/* The errno in the sb has been acked */
#define JFS_FLUSHED	0x008	/* The journal superblock has been flushed */
#define JFS_LOADED	0x010	/* The journal superblock has been loaded */
/* 磁盘IO存在乱序问题，需要程序特殊处理 */
#define JFS_BARRIER	0x020	/* Use IDE barriers */

/* 
 * Function declarations for the journaling transaction and buffer
 * management
 */

/* Filing buffers */
extern void journal_unfile_buffer(journal_t *, struct journal_head *);
extern void __journal_unfile_buffer(struct journal_head *);
extern void __journal_refile_buffer(struct journal_head *);
extern void journal_refile_buffer(journal_t *, struct journal_head *);
extern void __journal_file_buffer(struct journal_head *, transaction_t *, int);
extern void __journal_free_buffer(struct journal_head *bh);
extern void journal_file_buffer(struct journal_head *, transaction_t *, int);
extern void __journal_clean_data_list(transaction_t *transaction);

/* Log buffer allocation */
extern struct journal_head * journal_get_descriptor_buffer(journal_t *);
int journal_next_log_block(journal_t *, unsigned long *);

/* Commit management */
extern void journal_commit_transaction(journal_t *);

/* Checkpoint list management */
int __journal_clean_checkpoint_list(journal_t *journal);
void __journal_remove_checkpoint(struct journal_head *);
void __journal_insert_checkpoint(struct journal_head *, transaction_t *);

/* Buffer IO */
extern int 
journal_write_metadata_buffer(transaction_t	  *transaction,
			      struct journal_head  *jh_in,
			      struct journal_head **jh_out,
			      int		   blocknr);

/* Transaction locking */
extern void		__wait_on_journal (journal_t *);

/*
 * Journal locking.
 *
 * We need to lock the journal during transaction state changes so that nobody
 * ever tries to take a handle on the running transaction while we are in the
 * middle of moving it to the commit phase.  j_state_lock does this.
 *
 * Note that the locking is completely interrupt unsafe.  We never touch
 * journal structures from interrupts.
 */

static inline handle_t *journal_current_handle(void)
{
	return current->journal_info;
}

/* The journaling code user interface:
 *
 * Create and destroy handles
 * Register buffer modifications against the current transaction. 
 */

extern handle_t *journal_start(journal_t *, int nblocks);
extern int	 journal_restart (handle_t *, int nblocks);
extern int	 journal_extend (handle_t *, int nblocks);
extern int	 journal_get_write_access(handle_t *, struct buffer_head *,
						int *credits);
extern int	 journal_get_create_access (handle_t *, struct buffer_head *);
extern int	 journal_get_undo_access(handle_t *, struct buffer_head *,
						int *credits);
extern int	 journal_dirty_data (handle_t *, struct buffer_head *);
extern int	 journal_dirty_metadata (handle_t *, struct buffer_head *);
extern void	 journal_release_buffer (handle_t *, struct buffer_head *,
						int credits);
extern int	 journal_forget (handle_t *, struct buffer_head *);
extern void	 journal_sync_buffer (struct buffer_head *);
extern int	 journal_invalidatepage(journal_t *,
				struct page *, unsigned long);
extern int	 journal_try_to_free_buffers(journal_t *, struct page *, int);
extern int	 journal_stop(handle_t *);
extern int	 journal_flush (journal_t *);
extern void	 journal_lock_updates (journal_t *);
extern void	 journal_unlock_updates (journal_t *);

extern journal_t * journal_init_dev(struct block_device *bdev,
				struct block_device *fs_dev,
				int start, int len, int bsize);
extern journal_t * journal_init_inode (struct inode *);
extern int	   journal_update_format (journal_t *);
extern int	   journal_check_used_features 
		   (journal_t *, unsigned long, unsigned long, unsigned long);
extern int	   journal_check_available_features 
		   (journal_t *, unsigned long, unsigned long, unsigned long);
extern int	   journal_set_features 
		   (journal_t *, unsigned long, unsigned long, unsigned long);
extern int	   journal_create     (journal_t *);
extern int	   journal_load       (journal_t *journal);
extern void	   journal_destroy    (journal_t *);
extern int	   journal_recover    (journal_t *journal);
extern int	   journal_wipe       (journal_t *, int);
extern int	   journal_skip_recovery	(journal_t *);
extern void	   journal_update_superblock	(journal_t *, int);
extern void	   __journal_abort_hard	(journal_t *);
extern void	   __journal_abort_soft	(journal_t *, int);
extern void	   journal_abort      (journal_t *, int);
extern int	   journal_errno      (journal_t *);
extern void	   journal_ack_err    (journal_t *);
extern int	   journal_clear_err  (journal_t *);
extern int	   journal_bmap(journal_t *, unsigned long, unsigned long *);
extern int	   journal_force_commit(journal_t *);

/*
 * journal_head management
 */
struct journal_head *journal_add_journal_head(struct buffer_head *bh);
struct journal_head *journal_grab_journal_head(struct buffer_head *bh);
void journal_remove_journal_head(struct buffer_head *bh);
void journal_put_journal_head(struct journal_head *jh);

/*
 * handle management
 */
extern kmem_cache_t *jbd_handle_cache;

static inline handle_t *jbd_alloc_handle(int gfp_flags)
{
	return kmem_cache_alloc(jbd_handle_cache, gfp_flags);
}

static inline void jbd_free_handle(handle_t *handle)
{
	kmem_cache_free(jbd_handle_cache, handle);
}

/* Primary revoke support */
#define JOURNAL_REVOKE_DEFAULT_HASH 256
extern int	   journal_init_revoke(journal_t *, int);
extern void	   journal_destroy_revoke_caches(void);
extern int	   journal_init_revoke_caches(void);

extern void	   journal_destroy_revoke(journal_t *);
extern int	   journal_revoke (handle_t *,
				unsigned long, struct buffer_head *);
extern int	   journal_cancel_revoke(handle_t *, struct journal_head *);
extern void	   journal_write_revoke_records(journal_t *, transaction_t *);

/* Recovery revoke support */
extern int	journal_set_revoke(journal_t *, unsigned long, tid_t);
extern int	journal_test_revoke(journal_t *, unsigned long, tid_t);
extern void	journal_clear_revoke(journal_t *);
extern void	journal_brelse_array(struct buffer_head *b[], int n);
extern void	journal_switch_revoke_table(journal_t *journal);

/*
 * The log thread user interface:
 *
 * Request space in the current transaction, and force transaction commit
 * transitions on demand.
 */

int __log_space_left(journal_t *); /* Called with journal locked */
int log_start_commit(journal_t *journal, tid_t tid);
int __log_start_commit(journal_t *journal, tid_t tid);
int journal_start_commit(journal_t *journal, tid_t *tid);
int journal_force_commit_nested(journal_t *journal);
int log_wait_commit(journal_t *journal, tid_t tid);
int log_do_checkpoint(journal_t *journal);

void __log_wait_for_space(journal_t *journal);
extern void	__journal_drop_transaction(journal_t *, transaction_t *);
extern int	cleanup_journal_tail(journal_t *);

/* Debugging code only: */

#define jbd_ENOSYS() \
do {								           \
	printk (KERN_ERR "JBD unimplemented function %s\n", __FUNCTION__); \
	current->state = TASK_UNINTERRUPTIBLE;			           \
	schedule();						           \
} while (1)

/*
 * is_journal_abort
 *
 * Simple test wrapper function to test the JFS_ABORT state flag.  This
 * bit, when set, indicates that we have had a fatal error somewhere,
 * either inside the journaling layer or indicated to us by the client
 * (eg. ext3), and that we and should not commit any further
 * transactions.  
 */

static inline int is_journal_aborted(journal_t *journal)
{
	return journal->j_flags & JFS_ABORT;
}

static inline int is_handle_aborted(handle_t *handle)
{
	if (handle->h_aborted)
		return 1;
	return is_journal_aborted(handle->h_transaction->t_journal);
}

static inline void journal_abort_handle(handle_t *handle)
{
	handle->h_aborted = 1;
}

#endif /* __KERNEL__   */

/* Comparison functions for transaction IDs: perform comparisons using
 * modulo arithmetic so that they work over sequence number wraps. */

static inline int tid_gt(tid_t x, tid_t y)
{
	int difference = (x - y);
	return (difference > 0);
}

static inline int tid_geq(tid_t x, tid_t y)
{
	int difference = (x - y);
	return (difference >= 0);
}

extern int journal_blocks_per_page(struct inode *inode);

/*
 * Return the minimum number of blocks which must be free in the journal
 * before a new transaction may be started.  Must be called under j_state_lock.
 */
static inline int jbd_space_needed(journal_t *journal)
{
	int nblocks = journal->j_max_transaction_buffers;
	if (journal->j_committing_transaction)
		nblocks += journal->j_committing_transaction->
					t_outstanding_credits;
	return nblocks;
}

/*
 * Definitions which augment the buffer_head layer
 */

/* journaling buffer types */
#define BJ_None		0	/* Not journaled */
#define BJ_SyncData	1	/* Normal data: flush before commit */
/* 缓冲区位于元数据队列 */
#define BJ_Metadata	2	/* Normal journaled metadata */
#define BJ_Forget	3	/* Buffer superseded by this transaction */
/* 转义后的，真正需要写入日志的 */
#define BJ_IO		4	/* Buffer is for temporary IO use */
/* 缓冲区位于Shadow队列，表示正在写入日志 */
#define BJ_Shadow	5	/* Buffer contents being shadowed to the log */
#define BJ_LogCtl	6	/* Buffer contains log descriptors */
#define BJ_Reserved	7	/* Buffer is reserved for access by journal */
#define BJ_Locked	8	/* Locked for I/O during commit */
#define BJ_Types	9
 
extern int jbd_blocks_per_page(struct inode *inode);

#ifdef __KERNEL__

#define buffer_trace_init(bh)	do {} while (0)
#define print_buffer_fields(bh)	do {} while (0)
#define print_buffer_trace(bh)	do {} while (0)
#define BUFFER_TRACE(bh, info)	do {} while (0)
#define BUFFER_TRACE2(bh, bh2, info)	do {} while (0)
#define JBUFFER_TRACE(jh, info)	do {} while (0)

#endif	/* __KERNEL__ */

#endif	/* CONFIG_JBD || CONFIG_JBD_MODULE || !__KERNEL__ */

/*
 * Compatibility no-ops which allow the kernel to compile without CONFIG_JBD
 * go here.
 */

#if defined(__KERNEL__) && !(defined(CONFIG_JBD) || defined(CONFIG_JBD_MODULE))

#define J_ASSERT(expr)			do {} while (0)
#define J_ASSERT_BH(bh, expr)		do {} while (0)
#define buffer_jbd(bh)			0
#define journal_buffer_journal_lru(bh)	0

#endif	/* defined(__KERNEL__) && !defined(CONFIG_JBD) */
#endif	/* _LINUX_JBD_H */
