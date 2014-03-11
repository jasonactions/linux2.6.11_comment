/*
 *  linux/mm/page_io.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, 
 *  Asynchronous swapping added 30.12.95. Stephen Tweedie
 *  Removed race in async swapping. 14.4.1996. Bruno Haible
 *  Add swap of shared pages through the page cache. 20.2.1998. Stephen Tweedie
 *  Always use brw_page, life becomes simpler. 12 May 1998 Eric Biederman
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <asm/pgtable.h>

static struct bio *get_swap_bio(int gfp_flags, pgoff_t index,
				struct page *page, bio_end_io_t end_io)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, 1);
	if (bio) {
		struct swap_info_struct *sis;
		swp_entry_t entry = { .val = index, };

		sis = get_swap_info_struct(swp_type(entry));
		bio->bi_sector = map_swap_page(sis, swp_offset(entry)) *
					(PAGE_SIZE >> 9);
		bio->bi_bdev = sis->bdev;
		bio->bi_io_vec[0].bv_page = page;
		bio->bi_io_vec[0].bv_len = PAGE_SIZE;
		bio->bi_io_vec[0].bv_offset = 0;
		bio->bi_vcnt = 1;
		bio->bi_idx = 0;
		bio->bi_size = PAGE_SIZE;
		bio->bi_end_io = end_io;
	}
	return bio;
}

/**
 * 页交换IO结束后，就会调用end_swap_bio_write
 * 这个函数唤醒正等待页PG_writeback标志清0的所有进程。
 * 它还会清除PG_writeback标志和基树中的相关标记。并释放用于IO传输的BIO描述符。
 */
static int end_swap_bio_write(struct bio *bio, unsigned int bytes_done, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (bio->bi_size)
		return 1;

	if (!uptodate)
		SetPageError(page);
	end_page_writeback(page);
	bio_put(bio);
	return 0;
}

static int end_swap_bio_read(struct bio *bio, unsigned int bytes_done, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (bio->bi_size)
		return 1;

	if (!uptodate) {
		SetPageError(page);
		ClearPageUptodate(page);
	} else {
		SetPageUptodate(page);
	}
	unlock_page(page);
	bio_put(bio);
	return 0;
}

/*
 * We may have stale swap cache pages in memory: notice
 * them here and get rid of the unnecessary final write.
 */
/**
 * shrink_list函数激活交换页的IO传输过程。它检查页框的PG_dirty标志，然后执行pageout函数。
 * 交换高速缓存的writepage方法为本函数。因此，最终的IO传输过程由本函数完成。
 */
int swap_writepage(struct page *page, struct writeback_control *wbc)
{
	struct bio *bio;
	int ret = 0, rw = WRITE;

	/**
	 * 检查是否有一个用户态进程引用该页。如果没有就从交换高速缓存删除该页。并返回0.
	 * 做这个检查的原因是:一个进程可能会与PFRA发生竞争并在shrink_list检查完后释放一页。
	 */
	if (remove_exclusive_swap_page(page)) {
		unlock_page(page);
		goto out;
	}
	/**
	 * 分配并初始化一个BIO描述符。
	 * 从换出页标识符算出交换区描述符地址。然后搜索交换子区链表，以找到页槽的磁盘扇区。
	 */
	bio = get_swap_bio(GFP_NOIO, page->private, page, end_swap_bio_write);
	if (bio == NULL) {
		set_page_dirty(page);
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}
	if (wbc->sync_mode == WB_SYNC_ALL)
		rw |= (1 << BIO_RW_SYNC);
	inc_page_state(pswpout);
	/**
	 * 设置页的的writeback标志。
	 */
	set_page_writeback(page);
	unlock_page(page);
	/**
	 * 提交写请求。
	 * 当IO传输完毕后，执行end_swap_bio_write，该函数唤醒等待页PG_writeback标志清0的所有进程。
	 * 清除PG_writeback标志和基树中的相关标志，并释放IO描述符。
	 */
	submit_bio(rw, bio);
out:
	return ret;
}

int swap_readpage(struct file *file, struct page *page)
{
	struct bio *bio;
	int ret = 0;

	BUG_ON(!PageLocked(page));
	ClearPageUptodate(page);
	bio = get_swap_bio(GFP_KERNEL, page->private, page, end_swap_bio_read);
	if (bio == NULL) {
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}
	inc_page_state(pswpin);
	submit_bio(READ, bio);
out:
	return ret;
}

#if defined(CONFIG_SOFTWARE_SUSPEND) || defined(CONFIG_PM_DISK)
/*
 * A scruffy utility function to read or write an arbitrary swap page
 * and wait on the I/O.  The caller must have a ref on the page.
 *
 * We use end_swap_bio_read() even for writes, because it happens to do what
 * we want.
 */
int rw_swap_page_sync(int rw, swp_entry_t entry, struct page *page)
{
	struct bio *bio;
	int ret = 0;

	lock_page(page);

	bio = get_swap_bio(GFP_KERNEL, entry.val, page, end_swap_bio_read);
	if (bio == NULL) {
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}

	submit_bio(rw | (1 << BIO_RW_SYNC), bio);
	wait_on_page_locked(page);

	if (!PageUptodate(page) || PageError(page))
		ret = -EIO;
out:
	return ret;
}
#endif
