/*
 * include/linux/backing-dev.h
 *
 * low-level device information and state which is propagated up through
 * to high-level code.
 */

#ifndef _LINUX_BACKING_DEV_H
#define _LINUX_BACKING_DEV_H

#include <asm/atomic.h>

/*
 * Bits in backing_dev_info.state
 */
enum bdi_state {
	/**
	 * 当pdflash进程运行时，由于有多个pdflash可能会同时运行。并且是运行在不同的CPU上。
	 * 当它们对脏页进行检查时，pdflash线程需要确定是否有其他CPU上的pdflash线程也在处理某一个脏页。
	 * 这就需要同步，而同步是通过一个原子测试和对索引结点的backing_dev_info的BDI_pdflush标志的设置操作来完成的。
	 */
	BDI_pdflush,		/* A pdflush thread is working this device */
	BDI_write_congested,	/* The write queue is getting full */
	BDI_read_congested,	/* The read queue is getting full */
	BDI_unused,		/* Available bits start here */
};

typedef int (congested_fn)(void *, int);

/**
 * 
 */
struct backing_dev_info {
	unsigned long ra_pages;	/* max readahead in PAGE_CACHE_SIZE units */
	unsigned long state;	/* Always use atomic bitops on this */
	int memory_backed;	/* Cannot clean pages with writepage */
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;	/* Pointer to aux data for congested func */
	void (*unplug_io_fn)(struct backing_dev_info *, struct page *);
	void *unplug_io_data;
};

extern struct backing_dev_info default_backing_dev_info;
void default_unplug_io_fn(struct backing_dev_info *bdi, struct page *page);

int writeback_acquire(struct backing_dev_info *bdi);
int writeback_in_progress(struct backing_dev_info *bdi);
void writeback_release(struct backing_dev_info *bdi);

static inline int bdi_congested(struct backing_dev_info *bdi, int bdi_bits)
{
	if (bdi->congested_fn)
		return bdi->congested_fn(bdi->congested_data, bdi_bits);
	return (bdi->state & bdi_bits);
}

static inline int bdi_read_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << BDI_read_congested);
}

static inline int bdi_write_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << BDI_write_congested);
}

static inline int bdi_rw_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, (1 << BDI_read_congested)|
				  (1 << BDI_write_congested));
}

#endif		/* _LINUX_BACKING_DEV_H */
