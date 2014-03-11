/*
 * include/linux/buffer_head.h
 *
 * Everything to do with buffer_heads.
 */

#ifndef _LINUX_BUFFER_HEAD_H
#define _LINUX_BUFFER_HEAD_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/wait.h>
#include <asm/atomic.h>

enum bh_state_bits {
	/**
	 * 如果在读缓冲区包含有效数据时就置位
	 */
	BH_Uptodate,	/* Contains valid data */
	/**
	 * 如果读缓冲区脏就置位(表示其数据必须被写回磁盘)
	 */
	BH_Dirty,	/* Is dirty */
	/**
	 * 如果在读缓冲区加锁就置位，通常发生在缓冲区进行磁盘传输时。
	 */
	BH_Lock,	/* Is locked */
	/**
	 * 如果已经为缓冲区请示数据传输就置位
	 */
	BH_Req,		/* Has been submitted for I/O */

	/**
	 * 如果缓冲区被映射到磁盘就置位。
	 * 即：如果相应的缓冲区首部的b_bdev和b_blocknr是有效的就置位
	 */
	BH_Mapped,	/* Has a disk mapping */
	/**
	 * 如果相应的块刚被分配而还没有被访问过就置位
	 */
	BH_New,		/* Disk mapping was newly created by get_block */
	/**
	 * 如果在异步的读缓冲区就置位
	 */
	BH_Async_Read,	/* Is under end_buffer_async_read I/O */
	/**
	 * 如果在异步的写缓冲区就置位
	 */
	BH_Async_Write,	/* Is under end_buffer_async_write I/O */
	/**
	 * 如果还没有在磁盘上分配缓冲区就置位
	 */
	BH_Delay,	/* Buffer is not yet allocated on disk */
	/**
	 * 如果两个相邻的块在其中一个提交之后不再相邻就置位。
	 */
	BH_Boundary,	/* Block is followed by a discontiguity */
	/**
	 * 如果写块出现IO错误就置位
	 */
	BH_Write_EIO,	/* I/O error on write */
	/**
	 * 如果必须严格的把块写到在它之前提交的块的后面就置位（用于日志文件系统）
	 */
	BH_Ordered,	/* ordered write */
	/**
	 * 如果块设备的驱动程序不支持所请示的操作就置位
	 */
	BH_Eopnotsupp,	/* operation not supported (barrier) */

	BH_PrivateStart,/* not a state bit, but the first bit available
			 * for private allocation by other entities
			 */
};

#define MAX_BUF_PER_PAGE (PAGE_CACHE_SIZE / 512)

struct page;
struct buffer_head;
struct address_space;
typedef void (bh_end_io_t)(struct buffer_head *bh, int uptodate);

/*
 * Keep related fields in common cachelines.  The most commonly accessed
 * field (b_state) goes at the start so the compiler does not generate
 * indexed addressing for it.
 */
/**
 * 缓冲区首部结构
 */
struct buffer_head {
	/* First cache line: */
	/**
	 * 缓冲区状态标志,如BH_Uptodate
	 */
	unsigned long b_state;		/* buffer state bitmap (see above) */
	/**
	 * 指向缓冲区页的链表中的下一个元素的指针
	 */
	struct buffer_head *b_this_page;/* circular list of page's buffers */
	/**
	 * 批向拥有该块的缓冲区页的描述符指针
	 */
	struct page *b_page;		/* the page this bh is mapped to */
	/**
	 * 块引用计数
	 */
	atomic_t b_count;		/* users using this block */
	/**
	 * 块大小
	 */
	u32 b_size;			/* block size */

	/**
	 * 与块设备相关的块号（逻辑块号），即块在磁盘或者分区中的编号。
	 */
	sector_t b_blocknr;		/* block number */
	/**
	 * 块在缓冲区页内的位置，这个位置的编号依赖于页是否在高端内存。
	 * 如果在高端内存，则b_data字段存放的是块缓冲区相对于页的起始位置的偏移量。
	 * 否则存放的是块缓冲区的线性地址。
	 */
	char *b_data;			/* pointer to data block */

	/**
	 * 指向块设备描述符的指针,通常是磁盘或者分区。
	 */
	struct block_device *b_bdev;
	/**
	 * IO完成方法
	 */
	bh_end_io_t *b_end_io;		/* I/O completion */
	/**
	 * 指向IO完成方法数据的指针
	 */
 	void *b_private;		/* reserved for b_end_io */
	/**
	 * 间接块链表.
	 * 为与某个索引结点相关的间接块的链表提供的指针
	 */
	struct list_head b_assoc_buffers; /* associated with another mapping */
};

/*
 * macro tricks to expand the set_buffer_foo(), clear_buffer_foo()
 * and buffer_foo() functions.
 */
#define BUFFER_FNS(bit, name)						\
static inline void set_buffer_##name(struct buffer_head *bh)		\
{									\
	set_bit(BH_##bit, &(bh)->b_state);				\
}									\
static inline void clear_buffer_##name(struct buffer_head *bh)		\
{									\
	clear_bit(BH_##bit, &(bh)->b_state);				\
}									\
static inline int buffer_##name(const struct buffer_head *bh)		\
{									\
	return test_bit(BH_##bit, &(bh)->b_state);			\
}

/*
 * test_set_buffer_foo() and test_clear_buffer_foo()
 */
#define TAS_BUFFER_FNS(bit, name)					\
static inline int test_set_buffer_##name(struct buffer_head *bh)	\
{									\
	return test_and_set_bit(BH_##bit, &(bh)->b_state);		\
}									\
static inline int test_clear_buffer_##name(struct buffer_head *bh)	\
{									\
	return test_and_clear_bit(BH_##bit, &(bh)->b_state);		\
}									\

/*
 * Emit the buffer bitops functions.   Note that there are also functions
 * of the form "mark_buffer_foo()".  These are higher-level functions which
 * do something in addition to setting a b_state bit.
 */
BUFFER_FNS(Uptodate, uptodate)
BUFFER_FNS(Dirty, dirty)
TAS_BUFFER_FNS(Dirty, dirty)
BUFFER_FNS(Lock, locked)
TAS_BUFFER_FNS(Lock, locked)
BUFFER_FNS(Req, req)
TAS_BUFFER_FNS(Req, req)
BUFFER_FNS(Mapped, mapped)
BUFFER_FNS(New, new)
BUFFER_FNS(Async_Read, async_read)
BUFFER_FNS(Async_Write, async_write)
BUFFER_FNS(Delay, delay)
BUFFER_FNS(Boundary, boundary)
BUFFER_FNS(Write_EIO, write_io_error)
BUFFER_FNS(Ordered, ordered)
BUFFER_FNS(Eopnotsupp, eopnotsupp)

#define bh_offset(bh)		((unsigned long)(bh)->b_data & ~PAGE_MASK)
#define touch_buffer(bh)	mark_page_accessed(bh->b_page)

/* If we *know* page->private refers to buffer_heads */
#define page_buffers(page)					\
	({							\
		BUG_ON(!PagePrivate(page));		\
		((struct buffer_head *)(page)->private);	\
	})
#define page_has_buffers(page)	PagePrivate(page)

/*
 * Declarations
 */

void FASTCALL(mark_buffer_dirty(struct buffer_head *bh));
void init_buffer(struct buffer_head *, bh_end_io_t *, void *);
void set_bh_page(struct buffer_head *bh,
		struct page *page, unsigned long offset);
int try_to_free_buffers(struct page *);
struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		int retry);
void create_empty_buffers(struct page *, unsigned long,
			unsigned long b_state);
void end_buffer_read_sync(struct buffer_head *bh, int uptodate);
void end_buffer_write_sync(struct buffer_head *bh, int uptodate);
void end_buffer_async_write(struct buffer_head *bh, int uptodate);

/* Things to do with buffers at mapping->private_list */
void mark_buffer_dirty_inode(struct buffer_head *bh, struct inode *inode);
int inode_has_buffers(struct inode *);
void invalidate_inode_buffers(struct inode *);
int remove_inode_buffers(struct inode *inode);
int sync_mapping_buffers(struct address_space *mapping);
void unmap_underlying_metadata(struct block_device *bdev, sector_t block);

void mark_buffer_async_write(struct buffer_head *bh);
void invalidate_bdev(struct block_device *, int);
int sync_blockdev(struct block_device *bdev);
void __wait_on_buffer(struct buffer_head *);
wait_queue_head_t *bh_waitq_head(struct buffer_head *bh);
int fsync_bdev(struct block_device *);
struct super_block *freeze_bdev(struct block_device *);
void thaw_bdev(struct block_device *, struct super_block *);
int fsync_super(struct super_block *);
int fsync_no_super(struct block_device *);
struct buffer_head *__find_get_block(struct block_device *, sector_t, int);
struct buffer_head * __getblk(struct block_device *, sector_t, int);
void __brelse(struct buffer_head *);
void __bforget(struct buffer_head *);
void __breadahead(struct block_device *, sector_t block, int size);
struct buffer_head *__bread(struct block_device *, sector_t block, int size);
struct buffer_head *alloc_buffer_head(int gfp_flags);
void free_buffer_head(struct buffer_head * bh);
void FASTCALL(unlock_buffer(struct buffer_head *bh));
void FASTCALL(__lock_buffer(struct buffer_head *bh));
void ll_rw_block(int, int, struct buffer_head * bh[]);
int sync_dirty_buffer(struct buffer_head *bh);
int submit_bh(int, struct buffer_head *);
void write_boundary_block(struct block_device *bdev,
			sector_t bblock, unsigned blocksize);

extern int buffer_heads_over_limit;

/*
 * Generic address_space_operations implementations for buffer_head-backed
 * address_spaces.
 */
int try_to_release_page(struct page * page, int gfp_mask);
int block_invalidatepage(struct page *page, unsigned long offset);
int block_write_full_page(struct page *page, get_block_t *get_block,
				struct writeback_control *wbc);
int block_read_full_page(struct page*, get_block_t*);
int block_prepare_write(struct page*, unsigned, unsigned, get_block_t*);
int cont_prepare_write(struct page*, unsigned, unsigned, get_block_t*,
				loff_t *);
int generic_cont_expand(struct inode *inode, loff_t size) ;
int block_commit_write(struct page *page, unsigned from, unsigned to);
int block_sync_page(struct page *);
sector_t generic_block_bmap(struct address_space *, sector_t, get_block_t *);
int generic_commit_write(struct file *, struct page *, unsigned, unsigned);
int block_truncate_page(struct address_space *, loff_t, get_block_t *);
int file_fsync(struct file *, struct dentry *, int);
int nobh_prepare_write(struct page*, unsigned, unsigned, get_block_t*);
int nobh_commit_write(struct file *, struct page *, unsigned, unsigned);
int nobh_truncate_page(struct address_space *, loff_t);

/*
 * inline definitions
 */

static inline void attach_page_buffers(struct page *page,
		struct buffer_head *head)
{
	page_cache_get(page);
	SetPagePrivate(page);
	page->private = (unsigned long)head;
}

static inline void get_bh(struct buffer_head *bh)
{
        atomic_inc(&bh->b_count);
}

static inline void put_bh(struct buffer_head *bh)
{
        smp_mb__before_atomic_dec();
        atomic_dec(&bh->b_count);
}

static inline void brelse(struct buffer_head *bh)
{
	if (bh)
		__brelse(bh);
}

static inline void bforget(struct buffer_head *bh)
{
	if (bh)
		__bforget(bh);
}

static inline struct buffer_head *
sb_bread(struct super_block *sb, sector_t block)
{
	return __bread(sb->s_bdev, block, sb->s_blocksize);
}

static inline void
sb_breadahead(struct super_block *sb, sector_t block)
{
	__breadahead(sb->s_bdev, block, sb->s_blocksize);
}

static inline struct buffer_head *
sb_getblk(struct super_block *sb, sector_t block)
{
	return __getblk(sb->s_bdev, block, sb->s_blocksize);
}

static inline struct buffer_head *
sb_find_get_block(struct super_block *sb, sector_t block)
{
	return __find_get_block(sb->s_bdev, block, sb->s_blocksize);
}

static inline void
map_bh(struct buffer_head *bh, struct super_block *sb, sector_t block)
{
	set_buffer_mapped(bh);
	bh->b_bdev = sb->s_bdev;
	bh->b_blocknr = block;
}

/*
 * Calling wait_on_buffer() for a zero-ref buffer is illegal, so we call into
 * __wait_on_buffer() just to trip a debug check.  Because debug code in inline
 * functions is bloaty.
 */
static inline void wait_on_buffer(struct buffer_head *bh)
{
	might_sleep();
	if (buffer_locked(bh) || atomic_read(&bh->b_count) == 0)
		__wait_on_buffer(bh);
}

static inline void lock_buffer(struct buffer_head *bh)
{
	might_sleep();
	if (test_set_buffer_locked(bh))
		__lock_buffer(bh);
}

#endif /* _LINUX_BUFFER_HEAD_H */
