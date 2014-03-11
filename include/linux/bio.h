/*
 * 2.5 block I/O model
 *
 * Copyright (C) 2001 Jens Axboe <axboe@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of

 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */
#ifndef __LINUX_BIO_H
#define __LINUX_BIO_H

#include <linux/highmem.h>
#include <linux/mempool.h>

/* Platforms may set this to teach the BIO layer about IOMMU hardware. */
#include <asm/io.h>

#if defined(BIO_VMERGE_MAX_SIZE) && defined(BIO_VMERGE_BOUNDARY)
#define BIOVEC_VIRT_START_SIZE(x) (bvec_to_phys(x) & (BIO_VMERGE_BOUNDARY - 1))
#define BIOVEC_VIRT_OVERSIZE(x)	((x) > BIO_VMERGE_MAX_SIZE)
#else
#define BIOVEC_VIRT_START_SIZE(x)	0
#define BIOVEC_VIRT_OVERSIZE(x)		0
#endif

#ifndef BIO_VMERGE_BOUNDARY
#define BIO_VMERGE_BOUNDARY	0
#endif

#define BIO_DEBUG

#ifdef BIO_DEBUG
#define BIO_BUG_ON	BUG_ON
#else
#define BIO_BUG_ON
#endif

#define BIO_MAX_PAGES		(256)
#define BIO_MAX_SIZE		(BIO_MAX_PAGES << PAGE_CACHE_SHIFT)
#define BIO_MAX_SECTORS		(BIO_MAX_SIZE >> 9)

/*
 * was unsigned short, but we might as well be ready for > 64kB I/O pages
 */
/**
 * bio中的每个段由bio_vec表示。
 * bio中的bi_io_vec字段指向boi_vec数据结构的第一个元素。bi_vcnt字段则存放了bio_vec数组中当前的元素个数
 */
struct bio_vec {
	/**
	 * 指向段的页框中页描述符的指针
	 */
	struct page	*bv_page;
	/**
	 * 段的字节长度
	 */
	unsigned int	bv_len;
	/**
	 * 页框中段数据的偏移量
	 */
	unsigned int	bv_offset;
};

struct bio;
typedef int (bio_end_io_t) (struct bio *, unsigned int, int);
typedef void (bio_destructor_t) (struct bio *);

/*
 * main unit of I/O for the block layer and lower layers (ie drivers and
 * stacking drivers)
 */
/**
 * 通用块的核心数据结构。它描述了块设备的IO操作。
 * 通用块层是一个内核组件，它处理来自系统中的所有块设备发出的请求。
 * 每个bio都饮食一个磁盘存储区标识符（存储区中的起始扇区号和扇区数）。
 * 和一个或者多个描述与IO操作相关的内存区的段。
 */
struct bio {
	/**
	 * 块IO操作的第一个磁盘扇区
	 */
	sector_t		bi_sector;
	/**
	 * 链接到请求队列中的下一个bio
	 */
	struct bio		*bi_next;	/* request queue link */
	/**
	 * 指向块设备描述符的指针
	 */
	struct block_device	*bi_bdev;
	/**
	 * bio的状态标志。 
	 * 如果是写请求，最低有效位将被设置。需要使用bio_data_dir宏来确定读写标志。
	 */
	unsigned long		bi_flags;	/* status, command, etc */
	/**
	 * io操作标志。 
	 */
	unsigned long		bi_rw;		/* bottom bits READ/WRITE,
						 * top bits priority
						 */

	/**
	 * bio的bio_vec数组中的数目。
	 */
	unsigned short		bi_vcnt;	/* how many bio_vec's */
	/**
	 * bio的bio_vec数组中段的当前索引值
	 */
	unsigned short		bi_idx;		/* current index into bvl_vec */

	/* Number of segments in this BIO after
	 * physical address coalescing is performed.
	 */
	/**
	 * 合并之后bio中物理段的数目
	 */
	unsigned short		bi_phys_segments;

	/* Number of segments after physical and DMA remapping
	 * hardware coalescing is performed.
	 */
	/**
	 * 合并之后硬件段的数目。
	 */
	unsigned short		bi_hw_segments;

	/**
	 * 需要传送的字节数
	 */
	unsigned int		bi_size;	/* residual I/O count */

	/*
	 * To keep track of the max hw size, we account for the
	 * sizes of the first and last virtually mergeable segments
	 * in this bio
	 */
	/**
	 * 硬件段合并算法使用
	 */
	unsigned int		bi_hw_front_size;
	/**
	 * 硬件段合并算法使用
	 */
	unsigned int		bi_hw_back_size;

	/**
	 * bio的bio_vec数组中允许的最大段数
	 */
	unsigned int		bi_max_vecs;	/* max bvl_vecs we can hold */

	/**
	 * 指向bio的bio_vec数组的指针，它描述了要传送的数据缓冲区。
	 */
	struct bio_vec		*bi_io_vec;	/* the actual vec list */

	/**
	 * bio的IO操作结束时调用的方法
	 */
	bio_end_io_t		*bi_end_io;
	/**
	 * bio的引用计数器
	 */
	atomic_t		bi_cnt;		/* pin count */

	/**
	 * 通用块层和块设备驱动程序的IO完成方法使用的指针
	 */
	void			*bi_private;

	/**
	 * 释放bio时调用的析构方法（通常是bio_destructor方法）
	 */
	bio_destructor_t	*bi_destructor;	/* destructor */
};

/*
 * bio flags
 */
#define BIO_UPTODATE	0	/* ok after I/O completion */
#define BIO_RW_BLOCK	1	/* RW_AHEAD set, and read/write would block */
/**
 * 如果请求的块操作超过了块设备的扇区数，bio->bi_flags就会被置上该标志。
 * 然后内核打印一条出错标志。并调用bio_endio函数后终止。
 */
#define BIO_EOF		2	/* out-out-bounds error */
#define BIO_SEG_VALID	3	/* nr_hw_seg valid */
#define BIO_CLONED	4	/* doesn't own data */
#define BIO_BOUNCED	5	/* bio is a bounce bio */
#define BIO_USER_MAPPED 6	/* contains user pages */
#define BIO_EOPNOTSUPP	7	/* not supported */
#define bio_flagged(bio, flag)	((bio)->bi_flags & (1 << (flag)))

/*
 * top 4 bits of bio flags indicate the pool this bio came from
 */
#define BIO_POOL_BITS		(4)
#define BIO_POOL_OFFSET		(BITS_PER_LONG - BIO_POOL_BITS)
#define BIO_POOL_MASK		(1UL << BIO_POOL_OFFSET)
#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)	

/*
 * bio bi_rw flags
 *
 * bit 0 -- read (not set) or write (set)
 * bit 1 -- rw-ahead when set
 * bit 2 -- barrier
 * bit 3 -- fail fast, don't want low level driver retries
 * bit 4 -- synchronous I/O hint: the block layer will unplug immediately
 */
#define BIO_RW		0
/**
 * bio->bi_rw的标志值之一。表示本次IO操作是一次预读。
 * 当一个bio是预读，并且没有足够的内存时，就会直接退出并调用bio_endio.
 */
#define BIO_RW_AHEAD	1
#define BIO_RW_BARRIER	2
#define BIO_RW_FAILFAST	3
/**
 * 同步读写标志。
 * 如果设置了本标志，那么__make_request退出，就会从请求队列中摘除
 */
#define BIO_RW_SYNC	4

/*
 * various member access, note that bio_data should of course not be used
 * on highmem page vectors
 */
#define bio_iovec_idx(bio, idx)	(&((bio)->bi_io_vec[(idx)]))
#define bio_iovec(bio)		bio_iovec_idx((bio), (bio)->bi_idx)
/**
 * 指向下一个传输页的page结构的指针。
 */
#define bio_page(bio)		bio_iovec((bio))->bv_page
/**
 * 页中被传输数据的偏移量。
 */
#define bio_offset(bio)		bio_iovec((bio))->bv_offset
#define bio_segments(bio)	((bio)->bi_vcnt - (bio)->bi_idx)
/**
 * 得到BIO请求要传输的扇区数。
 */
#define bio_sectors(bio)	((bio)->bi_size >> 9)
/**
 * 在当前页中传输的扇区数量。
 */
#define bio_cur_sectors(bio)	(bio_iovec(bio)->bv_len >> 9)
/**
 * 被传输数据的内核逻辑地址。只有正在处理的页不在高端内存时，该地址才有效。
 * 默认情况下，块设备子系统不会把高端内存中的缓冲区传递给驱动程序，但是如果使用blk_queue_bounce_limit改变了这一设置，就不应该再使用bio_data了。
 */
#define bio_data(bio)		(page_address(bio_page((bio))) + bio_offset((bio)))
#define bio_barrier(bio)	((bio)->bi_rw & (1 << BIO_RW_BARRIER))
#define bio_sync(bio)		((bio)->bi_rw & (1 << BIO_RW_SYNC))
#define bio_failfast(bio)	((bio)->bi_rw & (1 << BIO_RW_FAILFAST))
#define bio_rw_ahead(bio)	((bio)->bi_rw & (1 << BIO_RW_AHEAD))

/*
 * will die
 */
#define bio_to_phys(bio)	(page_to_phys(bio_page((bio))) + (unsigned long) bio_offset((bio)))
#define bvec_to_phys(bv)	(page_to_phys((bv)->bv_page) + (unsigned long) (bv)->bv_offset)

/*
 * queues that have highmem support enabled may still need to revert to
 * PIO transfers occasionally and thus map high pages temporarily. For
 * permanent PIO fall back, user is probably better off disabling highmem
 * I/O completely on that queue (see ide-dma for example)
 */
/**
 * 映射bio中的待传输页。
 */
#define __bio_kmap_atomic(bio, idx, kmtype)				\
	(kmap_atomic(bio_iovec_idx((bio), (idx))->bv_page, kmtype) +	\
		bio_iovec_idx((bio), (idx))->bv_offset)

#define __bio_kunmap_atomic(addr, kmtype) kunmap_atomic(addr, kmtype)

/*
 * merge helpers etc
 */

#define __BVEC_END(bio)		bio_iovec_idx((bio), (bio)->bi_vcnt - 1)
#define __BVEC_START(bio)	bio_iovec_idx((bio), (bio)->bi_idx)

/*
 * allow arch override, for eg virtualized architectures (put in asm/io.h)
 */
#ifndef BIOVEC_PHYS_MERGEABLE
#define BIOVEC_PHYS_MERGEABLE(vec1, vec2)	\
	((bvec_to_phys((vec1)) + (vec1)->bv_len) == bvec_to_phys((vec2)))
#endif

#define BIOVEC_VIRT_MERGEABLE(vec1, vec2)	\
	((((bvec_to_phys((vec1)) + (vec1)->bv_len) | bvec_to_phys((vec2))) & (BIO_VMERGE_BOUNDARY - 1)) == 0)
#define __BIO_SEG_BOUNDARY(addr1, addr2, mask) \
	(((addr1) | (mask)) == (((addr2) - 1) | (mask)))
#define BIOVEC_SEG_BOUNDARY(q, b1, b2) \
	__BIO_SEG_BOUNDARY(bvec_to_phys((b1)), bvec_to_phys((b2)) + (b2)->bv_len, (q)->seg_boundary_mask)
#define BIO_SEG_BOUNDARY(q, b1, b2) \
	BIOVEC_SEG_BOUNDARY((q), __BVEC_END((b1)), __BVEC_START((b2)))

#define bio_io_error(bio, bytes) bio_endio((bio), (bytes), -EIO)

/*
 * drivers should not use the __ version unless they _really_ want to
 * run through the entire bio and not just pending pieces
 */
#define __bio_for_each_segment(bvl, bio, i, start_idx)			\
	for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);	\
	     i < (bio)->bi_vcnt;					\
	     bvl++, i++)

/**
 * 为了从索引bi_idx指向的当前段开始不断重复bio中的段，
 * 驱动程序可以执行宏bio_for_each_segment
 */
#define bio_for_each_segment(bvl, bio, i)				\
	__bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

/*
 * get a reference to a bio, so it won't disappear. the intended use is
 * something like:
 *
 * bio_get(bio);
 * submit_bio(rw, bio);
 * if (bio->bi_flags ...)
 *	do_something
 * bio_put(bio);
 *
 * without the bio_get(), it could potentially complete I/O before submit_bio
 * returns. and then bio would be freed memory when if (bio->bi_flags ...)
 * runs
 */
#define bio_get(bio)	atomic_inc(&(bio)->bi_cnt)


/*
 * A bio_pair is used when we need to split a bio.
 * This can only happen for a bio that refers to just one
 * page of data, and in the unusual situation when the
 * page crosses a chunk/device boundary
 *
 * The address of the master bio is stored in bio1.bi_private
 * The address of the pool the pair was allocated from is stored
 *   in bio2.bi_private
 */
struct bio_pair {
	struct bio	bio1, bio2;
	struct bio_vec	bv1, bv2;
	atomic_t	cnt;
	int		error;
};
extern struct bio_pair *bio_split(struct bio *bi, mempool_t *pool,
				  int first_sectors);
extern mempool_t *bio_split_pool;
extern void bio_pair_release(struct bio_pair *dbio);

extern struct bio *bio_alloc(int, int);
extern void bio_put(struct bio *);

extern void bio_endio(struct bio *, unsigned int, int);
struct request_queue;
extern int bio_phys_segments(struct request_queue *, struct bio *);
extern int bio_hw_segments(struct request_queue *, struct bio *);

extern void __bio_clone(struct bio *, struct bio *);
extern struct bio *bio_clone(struct bio *, int);

extern void bio_init(struct bio *);

extern int bio_add_page(struct bio *, struct page *, unsigned int,unsigned int);
extern int bio_get_nr_vecs(struct block_device *);
extern struct bio *bio_map_user(struct request_queue *, struct block_device *,
				unsigned long, unsigned int, int);
extern void bio_unmap_user(struct bio *);
extern void bio_set_pages_dirty(struct bio *bio);
extern void bio_check_pages_dirty(struct bio *bio);
extern struct bio *bio_copy_user(struct request_queue *, unsigned long, unsigned int, int);
extern int bio_uncopy_user(struct bio *);

#ifdef CONFIG_HIGHMEM
/*
 * remember to add offset! and never ever reenable interrupts between a
 * bvec_kmap_irq and bvec_kunmap_irq!!
 *
 * This function MUST be inlined - it plays with the CPU interrupt flags.
 * Hence the `extern inline'.
 */
/**
 * 为任何缓冲区返回内存虚拟地址。
 */
extern inline char *bvec_kmap_irq(struct bio_vec *bvec, unsigned long *flags)
{
	unsigned long addr;

	/*
	 * might not be a highmem page, but the preempt/irq count
	 * balancing is a lot nicer this way
	 */
	local_irq_save(*flags);
	addr = (unsigned long) kmap_atomic(bvec->bv_page, KM_BIO_SRC_IRQ);

	BUG_ON(addr & ~PAGE_MASK);

	return (char *) addr + bvec->bv_offset;
}

extern inline void bvec_kunmap_irq(char *buffer, unsigned long *flags)
{
	unsigned long ptr = (unsigned long) buffer & PAGE_MASK;

	kunmap_atomic((void *) ptr, KM_BIO_SRC_IRQ);
	local_irq_restore(*flags);
}

#else
#define bvec_kmap_irq(bvec, flags)	(page_address((bvec)->bv_page) + (bvec)->bv_offset)
#define bvec_kunmap_irq(buf, flags)	do { *(flags) = 0; } while (0)
#endif

extern inline char *__bio_kmap_irq(struct bio *bio, unsigned short idx,
				   unsigned long *flags)
{
	return bvec_kmap_irq(bio_iovec_idx(bio, idx), flags);
}
#define __bio_kunmap_irq(buf, flags)	bvec_kunmap_irq(buf, flags)

#define bio_kmap_irq(bio, flags) \
	__bio_kmap_irq((bio), (bio)->bi_idx, (flags))
#define bio_kunmap_irq(buf,flags)	__bio_kunmap_irq(buf, flags)

#endif /* __LINUX_BIO_H */
