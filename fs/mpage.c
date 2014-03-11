/*
 * fs/mpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains functions related to preparing and submitting BIOs which contain
 * multiple pagecache pages.
 *
 * 15May2002	akpm@zip.com.au
 *		Initial version
 * 27Jun2002	axboe@suse.de
 *		use bio_add_page() to build bio's just the right size
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
/**
 * mpage_readpage的bio的完成方法。当IO数据传输完成时，调用它。
 * 如果没有IO错误，则设置页描述符的PG_uptodate，调用unlock_page来解锁页面，并唤醒等待该事件的进程。
 * 最后调用bio_put来清除bio描述符。
 */
static int mpage_end_io_read(struct bio *bio, unsigned int bytes_done, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	if (bio->bi_size)
		return 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);

		if (uptodate) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	} while (bvec >= bio->bi_io_vec);
	bio_put(bio);
	return 0;
}

static int mpage_end_io_write(struct bio *bio, unsigned int bytes_done, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	if (bio->bi_size)
		return 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);

		if (!uptodate)
			SetPageError(page);
		end_page_writeback(page);
	} while (bvec >= bio->bi_io_vec);
	bio_put(bio);
	return 0;
}

struct bio *mpage_bio_submit(int rw, struct bio *bio)
{
	bio->bi_end_io = mpage_end_io_read;
	if (rw == WRITE)
		bio->bi_end_io = mpage_end_io_write;
	submit_bio(rw, bio);
	return NULL;
}

static struct bio *
mpage_alloc(struct block_device *bdev,
		sector_t first_sector, int nr_vecs, int gfp_flags)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, nr_vecs);

	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (nr_vecs /= 2))
			bio = bio_alloc(gfp_flags, nr_vecs);
	}

	if (bio) {
		bio->bi_bdev = bdev;
		bio->bi_sector = first_sector;
	}
	return bio;
}

/*
 * support function for mpage_readpages.  The fs supplied get_block might
 * return an up to date buffer.  This is used to map that buffer into
 * the page, which allows readpage to avoid triggering a duplicate call
 * to get_block.
 *
 * The idea is to avoid adding buffers to pages that don't already have
 * them.  So when the buffer is up to date and the page size == block size,
 * this marks the page up to date instead of adding new buffers.
 */
static void 
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block) 
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bh, *head;
	int block = 0;

	if (!page_has_buffers(page)) {
		/*
		 * don't make any buffers if there is only one buffer on
		 * the page and the page just needs to be set up to date
		 */
		if (inode->i_blkbits == PAGE_CACHE_SHIFT && 
		    buffer_uptodate(bh)) {
			SetPageUptodate(page);    
			return;
		}
		create_empty_buffers(page, 1 << inode->i_blkbits, 0);
	}
	head = page_buffers(page);
	page_bh = head;
	do {
		if (block == page_block) {
			page_bh->b_state = bh->b_state;
			page_bh->b_bdev = bh->b_bdev;
			page_bh->b_blocknr = bh->b_blocknr;
			break;
		}
		page_bh = page_bh->b_this_page;
		block++;
	} while (page_bh != head);
}

/**
 * mpage_readpages - populate an address space with some pages, and
 *                       start reads against them.
 *
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 *
 *   The page at @pages->prev has the lowest file offset, and reads should be
 *   issued in @pages->prev to @pages->next order.
 *
 * @nr_pages: The number of pages at *@pages
 * @get_block: The filesystem's block mapper function.
 *
 * This function walks the pages and the blocks within each page, building and
 * emitting large BIOs.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_CACHE_SIZE setups.
 *
 * BH_Boundary explanation:
 *
 * There is a problem.  The mpage read code assembles several pages, gets all
 * their disk mappings, and then submits them all.  That's fine, but obtaining
 * the disk mappings may require I/O.  Reads of indirect blocks, for example.
 *
 * So an mpage read of the first 16 blocks of an ext2 file will cause I/O to be
 * submitted in the following order:
 * 	12 0 1 2 3 4 5 6 7 8 9 10 11 13 14 15 16
 * because the indirect block has to be read to get the mappings of blocks
 * 13,14,15,16.  Obviously, this impacts performance.
 * 
 * So what we do it to allow the filesystem's get_block() function to set
 * BH_Boundary when it maps block 11.  BH_Boundary says: mapping of the block
 * after this one will require I/O against a block which is probably close to
 * this one.  So you should push what I/O you have currently accumulated.
 *
 * This all causes the disk requests to be issued in the correct order.
 */
/**
 * 对大多数文件来说，本函数是其readpage的实现方法。
 */
static struct bio *
do_mpage_readpage(struct bio *bio, struct page *page, unsigned nr_pages,
			sector_t *last_block_in_bio, get_block_t get_block)
{
	struct inode *inode = page->mapping->host;

	/**
	 * 得到块的大小
	 */
	const unsigned blkbits = inode->i_blkbits;
	/**
	 * 页中的块数
	 */
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_hole = blocks_per_page;
	struct block_device *bdev = NULL;
	struct buffer_head bh;
	int length;
	int fully_mapped = 1;

	/**
	 * 检查page的PG_private标志，如果该标志被置位，那么表示该页已经从磁盘上读入过，而且页中的块在磁盘上不是相邻的。
	 * 因此以一次读一块的方式读取该页。
	 */
	if (page_has_buffers(page))
		goto confused;

	/**
	 * 页中第一块的文件块号。
	 */
	block_in_file = page->index << (PAGE_CACHE_SHIFT - blkbits);
	last_block = (i_size_read(inode) + blocksize - 1) >> blkbits;

	bh.b_page = page;
	for (page_block = 0; page_block < blocks_per_page;
				page_block++, block_in_file++) {
		bh.b_state = 0;
		if (block_in_file < last_block) {
			/**
			 * 调用get_block得到逻辑块号，即相对于磁盘或分区开始位置的块索引。
			 * 页中每一块的逻辑号存放在一个本地数据中。
			 */
			if (get_block(inode, block_in_file, &bh, 0))
				goto confused;
		}


		/**
		 * 当发生以下异常情况时，采用一次读取一块的方式读该页:
		 *     一些块在磁盘上不相邻。
		 *     某些块在文件洞中。
		 */
		if (!buffer_mapped(&bh)) {
			fully_mapped = 0;
			if (first_hole == blocks_per_page)
				first_hole = page_block;
			continue;
		}

		/* some filesystems will copy data into the page during
		 * the get_block call, in which case we don't want to
		 * read it again.  map_buffer_to_page copies the data
		 * we just collected from get_block into the page's buffers
		 * so readpage doesn't have to repeat the get_block call
		 */
		if (buffer_uptodate(&bh)) {
			map_buffer_to_page(page, &bh, page_block);
			goto confused;
		}
	
		if (first_hole != blocks_per_page)
			goto confused;		/* hole -> non-hole */

		/* Contiguous blocks? */
		if (page_block && blocks[page_block-1] != bh.b_blocknr-1)
			goto confused;
		blocks[page_block] = bh.b_blocknr;
		bdev = bh.b_bdev;
	}

	/**
	 * 运行到此，说明页中的所有块在磁盘上是相邻的。
	 */
	if (first_hole != blocks_per_page) {
		/**
		 * 如果页是文件中的最后一页，某些块在磁盘中没有映像。将相应的块缓冲区填上0.
		 */
		char *kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr + (first_hole << blkbits), 0,
				PAGE_CACHE_SIZE - (first_hole << blkbits));
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
		if (first_hole == 0) {
			SetPageUptodate(page);
			unlock_page(page);
			goto out;
		}
	} else if (fully_mapped) {
		/**
		 * 不是文件的最后一页，将页描述符的标志PG_mappedtodisk置位。
		 */
		SetPageMappedToDisk(page);
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (bio && (*last_block_in_bio != blocks[0] - 1))
		bio = mpage_bio_submit(READ, bio);

alloc_new:
	if (bio == NULL) {/* 分配一个bio，并初始化它 */
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
			  	min_t(int, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL)
			goto confused;
	}

	length = first_hole << blkbits;
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(READ, bio);
		goto alloc_new;
	}

	/**
	 * 向驱动提交bio请求。
	 */
	if (buffer_boundary(&bh) || (first_hole != blocks_per_page))
		bio = mpage_bio_submit(READ, bio);
	else
		*last_block_in_bio = blocks[blocks_per_page - 1];
out:
	return bio;

/**
 * 函数运行到这里，则页中含有的块在磁盘不连续。
 */
confused:
	if (bio)
		bio = mpage_bio_submit(READ, bio);
	if (!PageUptodate(page))
		/**
		 * 页不是最新的，则调用block_read_full_page一次读一块的方式读该页。
		 */
	    block_read_full_page(page, get_block);
	else
		/**
		 * 如果页是最新的，则调用unlock_page来对该页解锁。
		 */
		unlock_page(page);
	goto out;
}

int
mpage_readpages(struct address_space *mapping, struct list_head *pages,
				unsigned nr_pages, get_block_t get_block)
{
	struct bio *bio = NULL;
	unsigned page_idx;
	sector_t last_block_in_bio = 0;
	struct pagevec lru_pvec;

	pagevec_init(&lru_pvec, 0);
	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		struct page *page = list_entry(pages->prev, struct page, lru);

		prefetchw(&page->flags);
		list_del(&page->lru);
		if (!add_to_page_cache(page, mapping,
					page->index, GFP_KERNEL)) {
			bio = do_mpage_readpage(bio, page,
					nr_pages - page_idx,
					&last_block_in_bio, get_block);
			if (!pagevec_add(&lru_pvec, page))
				__pagevec_lru_add(&lru_pvec);
		} else {
			page_cache_release(page);
		}
	}
	pagevec_lru_add(&lru_pvec);
	BUG_ON(!list_empty(pages));
	if (bio)
		mpage_bio_submit(READ, bio);
	return 0;
}
EXPORT_SYMBOL(mpage_readpages);

/*
 * This isn't called much at all
 */
/**
 * 对大多数文件来说，其address_space对象的readpage对象一般都是mpage_readpage的封装函数。
 */
int mpage_readpage(struct page *page, get_block_t get_block)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;

	/* 执行具体的工作 */
	bio = do_mpage_readpage(bio, page, 1,
			&last_block_in_bio, get_block);
	if (bio)/* do_mpage_readpage还有未提交的bio，在这里提交它 */
		mpage_bio_submit(READ, bio);
	return 0;
}
EXPORT_SYMBOL(mpage_readpage);

/*
 * Writing is not so simple.
 *
 * If the page has buffers then they will be used for obtaining the disk
 * mapping.  We only support pages which are fully mapped-and-dirty, with a
 * special case for pages which are unmapped at the end: end-of-file.
 *
 * If the page has no buffers (preferred) then the page is mapped here.
 *
 * If all blocks are found to be contiguous then the page can go into the
 * BIO.  Otherwise fall back to the mapping's writepage().
 * 
 * FIXME: This code wants an estimate of how many pages are still to be
 * written, so it can intelligently allocate a suitably-sized BIO.  For now,
 * just allocate full-size (16-page) BIOs.
 */
/**
 * 许多非日志型文件系统依赖于mpage_writepage而不是自定义的writepage方法。
 * 这样可以改善性能，因为mpage_writepage函数在进行IO传输时，在同一个bio描述符中聚集尽可能多的页。
 * 这就使得块设备驱动程序能利用现代硬盘控制器的DMA分散、聚集能力。
 */
static struct bio *
mpage_writepage(struct bio *bio, struct page *page, get_block_t get_block,
	sector_t *last_block_in_bio, int *ret, struct writeback_control *wbc)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	unsigned long end_index;
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
	sector_t last_block;
	sector_t block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_unmapped = blocks_per_page;
	struct block_device *bdev = NULL;
	int boundary = 0;
	sector_t boundary_block = 0;
	struct block_device *boundary_bdev = NULL;
	int length;
	struct buffer_head map_bh;
	loff_t i_size = i_size_read(inode);

	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		/* If they're all mapped and dirty, do it */
		page_block = 0;
		do {
			BUG_ON(buffer_locked(bh));
			if (!buffer_mapped(bh)) {
				/*
				 * unmapped dirty buffers are created by
				 * __set_page_dirty_buffers -> mmapped data
				 */
				if (buffer_dirty(bh))
					goto confused;
				if (first_unmapped == blocks_per_page)
					first_unmapped = page_block;
				continue;
			}

			if (first_unmapped != blocks_per_page)
				goto confused;	/* hole -> non-hole */

			if (!buffer_dirty(bh) || !buffer_uptodate(bh))
				goto confused;
			if (page_block) {
				if (bh->b_blocknr != blocks[page_block-1] + 1)
					goto confused;
			}
			blocks[page_block++] = bh->b_blocknr;
			boundary = buffer_boundary(bh);
			if (boundary) {
				boundary_block = bh->b_blocknr;
				boundary_bdev = bh->b_bdev;
			}
			bdev = bh->b_bdev;
		} while ((bh = bh->b_this_page) != head);

		if (first_unmapped)
			goto page_is_mapped;

		/*
		 * Page has buffers, but they are all unmapped. The page was
		 * created by pagein or read over a hole which was handled by
		 * block_read_full_page().  If this address_space is also
		 * using mpage_readpages then this can rarely happen.
		 */
		goto confused;
	}

	/*
	 * The page has no buffers: map it to disk
	 */
	BUG_ON(!PageUptodate(page));
	block_in_file = page->index << (PAGE_CACHE_SHIFT - blkbits);
	last_block = (i_size - 1) >> blkbits;
	map_bh.b_page = page;
	for (page_block = 0; page_block < blocks_per_page; ) {

		map_bh.b_state = 0;
		if (get_block(inode, block_in_file, &map_bh, 1))
			goto confused;
		if (buffer_new(&map_bh))
			unmap_underlying_metadata(map_bh.b_bdev,
						map_bh.b_blocknr);
		if (buffer_boundary(&map_bh)) {
			boundary_block = map_bh.b_blocknr;
			boundary_bdev = map_bh.b_bdev;
		}
		if (page_block) {
			if (map_bh.b_blocknr != blocks[page_block-1] + 1)
				goto confused;
		}
		blocks[page_block++] = map_bh.b_blocknr;
		boundary = buffer_boundary(&map_bh);
		bdev = map_bh.b_bdev;
		if (block_in_file == last_block)
			break;
		block_in_file++;
	}
	BUG_ON(page_block == 0);

	first_unmapped = page_block;

page_is_mapped:
	end_index = i_size >> PAGE_CACHE_SHIFT;
	if (page->index >= end_index) {
		/*
		 * The page straddles i_size.  It must be zeroed out on each
		 * and every writepage invokation because it may be mmapped.
		 * "A file is mapped in multiples of the page size.  For a file
		 * that is not a multiple of the page size, the remaining memory
		 * is zeroed when mapped, and writes to that region are not
		 * written out to the file."
		 */
		unsigned offset = i_size & (PAGE_CACHE_SIZE - 1);
		char *kaddr;

		if (page->index > end_index || !offset)
			goto confused;
		kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr + offset, 0, PAGE_CACHE_SIZE - offset);
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (bio && *last_block_in_bio != blocks[0] - 1)
		bio = mpage_bio_submit(WRITE, bio);

	/**
	 * 将页追加为bio描述符中的一段。
	 */
alloc_new:
	/**
	 * 如果传入的bio为空，就初始化一个新的bio描述符地址。
	 * 并将该描述符返回给调用函数，调用函数下次调用mpage_writepage时，将该描述符再次传入。
	 * 这样，同一个bio可以加载几个页。
	 */
	if (bio == NULL) {
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
				bio_get_nr_vecs(bdev), GFP_NOFS|__GFP_HIGH);
		if (bio == NULL)
			goto confused;
	}

	/*
	 * Must try to add the page before marking the buffer clean or
	 * the confused fail path above (OOM) will be very confused when
	 * it finds all bh marked clean (i.e. it will not write anything)
	 */
	length = first_unmapped << blkbits;
	/**
	 * 如果bio中某页与上一个加载页不相邻，则调用mpage_bio_submit开始新的IO数据传输。
	 * 然后分配一个新的bio。
	 */
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(WRITE, bio);
		goto alloc_new;
	}

	/*
	 * OK, we have our BIO, so we can now mark the buffers clean.  Make
	 * sure to only clean buffers which we know we'll be writing.
	 */
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;
		unsigned buffer_counter = 0;

		do {
			if (buffer_counter++ == first_unmapped)
				break;
			clear_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);

		/*
		 * we cannot drop the bh if the page is not uptodate
		 * or a concurrent readpage would fail to serialize with the bh
		 * and it would read from disk before we reach the platter.
		 */
		if (buffer_heads_over_limit && PageUptodate(page))
			try_to_free_buffers(page);
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);
	if (boundary || (first_unmapped != blocks_per_page)) {
		bio = mpage_bio_submit(WRITE, bio);
		if (boundary_block) {
			write_boundary_block(boundary_bdev,
					boundary_block, 1 << blkbits);
		}
	} else {
		*last_block_in_bio = blocks[blocks_per_page - 1];
	}
	goto out;

confused:
	if (bio)
		bio = mpage_bio_submit(WRITE, bio);
	*ret = page->mapping->a_ops->writepage(page, wbc);
	/*
	 * The caller has a ref on the inode, so *mapping is stable
	 */
	if (*ret) {
		if (*ret == -ENOSPC)
			set_bit(AS_ENOSPC, &mapping->flags);
		else
			set_bit(AS_EIO, &mapping->flags);
	}
out:
	return bio;
}

/**
 * mpage_writepages - walk the list of dirty pages of the given
 * address space and writepage() all of them.
 * 
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 * @get_block: the filesystem's block mapper function.
 *             If this is NULL then use a_ops->writepage.  Otherwise, go
 *             direct-to-BIO.
 *
 * This is a library function, which implements the writepages()
 * address_space_operation.
 *
 * If a page is already under I/O, generic_writepages() skips it, even
 * if it's dirty.  This is desirable behaviour for memory-cleaning writeback,
 * but it is INCORRECT for data-integrity system calls such as fsync().  fsync()
 * and msync() need to guarantee that all the data which was dirty at the time
 * the call was made get new I/O started against them.  If wbc->sync_mode is
 * WB_SYNC_ALL then we were called for data integrity and we must wait for
 * existing IO to complete.
 */
/**
 * 将脏页写回磁盘。
 * pdflush及同步写需要调用。
 */
int
mpage_writepages(struct address_space *mapping,
		struct writeback_control *wbc, get_block_t get_block)
{
	struct backing_dev_info *bdi = mapping->backing_dev_info;
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;
	int ret = 0;
	int done = 0;
	int (*writepage)(struct page *page, struct writeback_control *wbc);
	struct pagevec pvec;
	int nr_pages;
	pgoff_t index;
	pgoff_t end = -1;		/* Inclusive */
	int scanned = 0;
	int is_range = 0;

	/**
	 * 请求队列写拥塞，并且进程不希望阻塞，就直接返回。
	 */
	if (wbc->nonblocking && bdi_write_congested(bdi)) {
		wbc->encountered_congestion = 1;
		return 0;
	}

	writepage = NULL;
	if (get_block == NULL)
		writepage = mapping->a_ops->writepage;

	pagevec_init(&pvec, 0);
	/**
	 * 确定首页。如果wbc描述符指定线程无需等待IO数据传输结束，则将mapping->writeback_index设为初始页索引。
	 * 也就是说，从上一个写回操作的最后一页开始扫描。
	 */
	if (wbc->sync_mode == WB_SYNC_NONE) {
		index = mapping->writeback_index; /* Start from prev offset */
	} else {
		/**
		 * 否则，进程必须等待IO数据传输完毕，从文件的第一页开始扫描。
		 */
		index = 0;			  /* whole-file sweep */
		scanned = 1;
	}
	if (wbc->start || wbc->end) {
		index = wbc->start >> PAGE_CACHE_SHIFT;
		end = wbc->end >> PAGE_CACHE_SHIFT;
		is_range = 1;
		scanned = 1;
	}
retry:
	/**
	 * pagevec_lookup_tag会调用find_get_pages_tag在页高速缓存中查找脏页描述符。
	 */
	while (!done && (index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_DIRTY,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1))) {
		unsigned i;

		scanned = 1;
		/**
		 * 处理找到的每个脏页。
		 */
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/*
			 * At this point we hold neither mapping->tree_lock nor
			 * lock on the page itself: the page may be truncated or
			 * invalidated (changing page->mapping to NULL), or even
			 * swizzled back from swapper_space to tmpfs file
			 * mapping
			 */
			/**
			 * 先锁住脏页.
			 */
			lock_page(page);

			/**
			 * 确认页是有效的，并在页高速缓存内。
			 * 这是因为在锁住页之前，其他内核代码可能操作了该页。
			 */
			if (unlikely(page->mapping != mapping)) {
				unlock_page(page);
				continue;
			}

			if (unlikely(is_range) && page->index > end) {
				done = 1;
				unlock_page(page);
				continue;
			}

			/**
			 * 检查页面PG_writeback标志，如果置位，表示页已经被刷新到磁盘。
			 * 如果必须等待IO数据传输完毕，则调用wait_on_page_bit在PG_writeback清0之前一直阻塞当前进程。
			 */
			if (wbc->sync_mode != WB_SYNC_NONE)
				wait_on_page_writeback(page);

			/** 
			 * 如果PG_writeback标志置位，则检查PG_dirty，如果该标志为0，则正在运行的写回操作将处理该页。处理下一页。
			 */
			if (PageWriteback(page) ||
					!clear_page_dirty_for_io(page)) {
				unlock_page(page);
				continue;
			}

			if (writepage) {
				/**
				 * get_block为NULL，则调用mapping->writepage方法将页刷新到磁盘。
				 */
				ret = (*writepage)(page, wbc);
				if (ret) {
					if (ret == -ENOSPC)
						set_bit(AS_ENOSPC,
							&mapping->flags);
					else
						set_bit(AS_EIO,
							&mapping->flags);
				}
			} else {
				/**
				 * get_block不为NULL,则调用mpage_writepage刷新页面。
				 */
				bio = mpage_writepage(bio, page, get_block,
						&last_block_in_bio, &ret, wbc);
			}
			if (ret || (--(wbc->nr_to_write) <= 0))
				done = 1;
			if (wbc->nonblocking && bdi_write_congested(bdi)) {
				wbc->encountered_congestion = 1;
				done = 1;
			}
		}
		pagevec_release(&pvec);
		/**
		 * 增加一个调度点。
		 */
		cond_resched();
	}
	/**
	 * 没有扫描完给定范围内的所有页，或者写到磁盘的有效页数小于wbc中给定的值，则继续
	 */
	if (!scanned && !done) {
		/*
		 * We hit the last page and there is more work to be done: wrap
		 * back to the start of the file
		 */
		scanned = 1;
		index = 0;
		goto retry;
	}
	/**
	 * 如果wbc中没有给定文件内的初始位置，则将最后一个扫描的页赋给mapping->writeback_index
	 */
	if (!is_range)
		mapping->writeback_index = index;
	/**
	 * 如果曾经调用过mpage_writepage函数，而且返回了bio描述符地址，则调用mpage_bio_submit
	 */
	if (bio)
		mpage_bio_submit(WRITE, bio);
	return ret;
}
EXPORT_SYMBOL(mpage_writepages);
