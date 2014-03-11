/*
 *  linux/drivers/block/ll_rw_blk.c
 *
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 1994,      Karl Keyte: Added support for disk statistics
 * Elevator latency, (C) 2000  Andrea Arcangeli <andrea@suse.de> SuSE
 * Queue request tables / lock, selectable elevator, Jens Axboe <axboe@suse.de>
 * kernel-doc documentation started by NeilBrown <neilb@cse.unsw.edu.au> -  July2000
 * bio rewrite, highmem i/o, etc, Jens Axboe <axboe@suse.de> - may 2001
 */

/*
 * This handles all read/write requests to block devices
 */
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bootmem.h>	/* for max_pfn/max_low_pfn */
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>

/*
 * for max sense size
 */
#include <scsi/scsi_cmnd.h>

static void blk_unplug_work(void *data);
static void blk_unplug_timeout(unsigned long data);

/*
 * For the allocated request tables
 */
static kmem_cache_t *request_cachep;

/*
 * For queue allocation
 */
static kmem_cache_t *requestq_cachep;

/*
 * For io context allocations
 */
static kmem_cache_t *iocontext_cachep;

static wait_queue_head_t congestion_wqh[2] = {
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[0]),
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[1])
	};

/*
 * Controlling structure to kblockd
 */
static struct workqueue_struct *kblockd_workqueue; 

unsigned long blk_max_low_pfn, blk_max_pfn;

EXPORT_SYMBOL(blk_max_low_pfn);
EXPORT_SYMBOL(blk_max_pfn);

/* Amount of time in which a process may batch requests */
#define BLK_BATCH_TIME	(HZ/50UL)

/* Number of requests a "batching" process may submit */
#define BLK_BATCH_REQ	32

/*
 * Return the threshold (number of used requests) at which the queue is
 * considered to be congested.  It include a little hysteresis to keep the
 * context switch rate down.
 */
static inline int queue_congestion_on_threshold(struct request_queue *q)
{
	return q->nr_congestion_on;
}

/*
 * The threshold at which a queue is considered to be uncongested
 */
static inline int queue_congestion_off_threshold(struct request_queue *q)
{
	return q->nr_congestion_off;
}

static void blk_queue_congestion_threshold(struct request_queue *q)
{
	int nr;

	nr = q->nr_requests - (q->nr_requests / 8) + 1;
	if (nr > q->nr_requests)
		nr = q->nr_requests;
	q->nr_congestion_on = nr;

	nr = q->nr_requests - (q->nr_requests / 8) - (q->nr_requests / 16) - 1;
	if (nr < 1)
		nr = 1;
	q->nr_congestion_off = nr;
}

/*
 * A queue has just exitted congestion.  Note this in the global counter of
 * congested queues, and wake up anyone who was waiting for requests to be
 * put back.
 */
static void clear_queue_congested(request_queue_t *q, int rw)
{
	enum bdi_state bit;
	wait_queue_head_t *wqh = &congestion_wqh[rw];

	bit = (rw == WRITE) ? BDI_write_congested : BDI_read_congested;
	clear_bit(bit, &q->backing_dev_info.state);
	smp_mb__after_clear_bit();
	if (waitqueue_active(wqh))
		wake_up(wqh);
}

/*
 * A queue has just entered congestion.  Flag that in the queue's VM-visible
 * state flags and increment the global gounter of congested queues.
 */
static void set_queue_congested(request_queue_t *q, int rw)
{
	enum bdi_state bit;

	bit = (rw == WRITE) ? BDI_write_congested : BDI_read_congested;
	set_bit(bit, &q->backing_dev_info.state);
}

/**
 * blk_get_backing_dev_info - get the address of a queue's backing_dev_info
 * @bdev:	device
 *
 * Locates the passed device's request queue and returns the address of its
 * backing_dev_info
 *
 * Will return NULL if the request queue cannot be located.
 */
struct backing_dev_info *blk_get_backing_dev_info(struct block_device *bdev)
{
	struct backing_dev_info *ret = NULL;
	request_queue_t *q = bdev_get_queue(bdev);

	if (q)
		ret = &q->backing_dev_info;
	return ret;
}

EXPORT_SYMBOL(blk_get_backing_dev_info);

void blk_queue_activity_fn(request_queue_t *q, activity_fn *fn, void *data)
{
	q->activity_fn = fn;
	q->activity_data = data;
}

EXPORT_SYMBOL(blk_queue_activity_fn);

/**
 * blk_queue_prep_rq - set a prepare_request function for queue
 * @q:		queue
 * @pfn:	prepare_request function
 *
 * It's possible for a queue to register a prepare_request callback which
 * is invoked before the request is handed to the request_fn. The goal of
 * the function is to prepare a request for I/O, it can be used to build a
 * cdb from the request data for instance.
 *
 */
/**
 * 设置预处理函数。
 */
void blk_queue_prep_rq(request_queue_t *q, prep_rq_fn *pfn)
{
	q->prep_rq_fn = pfn;
}

EXPORT_SYMBOL(blk_queue_prep_rq);

/**
 * blk_queue_merge_bvec - set a merge_bvec function for queue
 * @q:		queue
 * @mbfn:	merge_bvec_fn
 *
 * Usually queues have static limitations on the max sectors or segments that
 * we can put in a request. Stacking drivers may have some settings that
 * are dynamic, and thus we have to query the queue whether it is ok to
 * add a new bio_vec to a bio at a given offset or not. If the block device
 * has such limitations, it needs to register a merge_bvec_fn to control
 * the size of bio's sent to it. Note that a block device *must* allow a
 * single page to be added to an empty bio. The block device driver may want
 * to use the bio_split() function to deal with these bio's. By default
 * no merge_bvec_fn is defined for a queue, and only the fixed limits are
 * honored.
 */
void blk_queue_merge_bvec(request_queue_t *q, merge_bvec_fn *mbfn)
{
	q->merge_bvec_fn = mbfn;
}

EXPORT_SYMBOL(blk_queue_merge_bvec);

/**
 * blk_queue_make_request - define an alternate make_request function for a device
 * @q:  the request queue for the device to be affected
 * @mfn: the alternate make_request function
 *
 * Description:
 *    The normal way for &struct bios to be passed to a device
 *    driver is for them to be collected into requests on a request
 *    queue, and then to allow the device driver to select requests
 *    off that queue when it is ready.  This works well for many block
 *    devices. However some block devices (typically virtual devices
 *    such as md or lvm) do not benefit from the processing on the
 *    request queue, and are served best by having the requests passed
 *    directly to them.  This can be achieved by providing a function
 *    to blk_queue_make_request().
 *
 * Caveat:
 *    The driver that does this *must* be able to deal appropriately
 *    with buffers in "highmemory". This can be accomplished by either calling
 *    __bio_kmap_atomic() to get a temporary kernel mapping, or by calling
 *    blk_queue_bounce() to create a buffer in normal memory.
 **/
void blk_queue_make_request(request_queue_t * q, make_request_fn * mfn)
{
	/*
	 * set defaults
	 */
	q->nr_requests = BLKDEV_MAX_RQ;
	q->max_phys_segments = MAX_PHYS_SEGMENTS;
	q->max_hw_segments = MAX_HW_SEGMENTS;
	q->make_request_fn = mfn;
	q->backing_dev_info.ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
	q->backing_dev_info.state = 0;
	q->backing_dev_info.memory_backed = 0;
	blk_queue_max_sectors(q, MAX_SECTORS);
	blk_queue_hardsect_size(q, 512);
	blk_queue_dma_alignment(q, 511);
	blk_queue_congestion_threshold(q);
	q->nr_batching = BLK_BATCH_REQ;

	q->unplug_thresh = 4;		/* hmm */
	q->unplug_delay = (3 * HZ) / 1000;	/* 3 milliseconds */
	if (q->unplug_delay == 0)
		q->unplug_delay = 1;

	INIT_WORK(&q->unplug_work, blk_unplug_work, q);

	q->unplug_timer.function = blk_unplug_timeout;
	q->unplug_timer.data = (unsigned long)q;

	/*
	 * by default assume old behaviour and bounce for any highmem page
	 */
	blk_queue_bounce_limit(q, BLK_BOUNCE_HIGH);

	blk_queue_activity_fn(q, NULL, NULL);

	INIT_LIST_HEAD(&q->drain_list);
}

EXPORT_SYMBOL(blk_queue_make_request);

/**
 * blk_queue_ordered - does this queue support ordered writes
 * @q:     the request queue
 * @flag:  see below
 *
 * Description:
 *   For journalled file systems, doing ordered writes on a commit
 *   block instead of explicitly doing wait_on_buffer (which is bad
 *   for performance) can be a big win. Block drivers supporting this
 *   feature should call this function and indicate so.
 *
 **/
/**
 * 设置屏障请求标志。
 */
void blk_queue_ordered(request_queue_t *q, int flag)
{
	if (flag)
		set_bit(QUEUE_FLAG_ORDERED, &q->queue_flags);
	else
		clear_bit(QUEUE_FLAG_ORDERED, &q->queue_flags);
}

EXPORT_SYMBOL(blk_queue_ordered);

/**
 * blk_queue_issue_flush_fn - set function for issuing a flush
 * @q:     the request queue
 * @iff:   the function to be called issuing the flush
 *
 * Description:
 *   If a driver supports issuing a flush command, the support is notified
 *   to the block layer by defining it through this call.
 *
 **/
void blk_queue_issue_flush_fn(request_queue_t *q, issue_flush_fn *iff)
{
	q->issue_flush_fn = iff;
}

EXPORT_SYMBOL(blk_queue_issue_flush_fn);

/**
 * blk_queue_bounce_limit - set bounce buffer limit for queue
 * @q:  the request queue for the device
 * @dma_addr:   bus address limit
 *
 * Description:
 *    Different hardware can have different requirements as to what pages
 *    it can do I/O directly to. A low level driver can call
 *    blk_queue_bounce_limit to have lower memory pages allocated as bounce
 *    buffers for doing I/O to pages residing above @page. By default
 *    the block layer sets this to the highest numbered "low" memory page.
 **/
/**
 * 告诉内核驱动程序执行DMA所使用的最高物理内存。
 * 如果一个请求包含了超越界限的内存引用，将使用回弹缓冲区。
 * 可以把任何可行的物理地址作为参数，或者使用如下预定义的参数。
 *		BLK_BOUNCE_HIGH:		对高端内存页使用回弹缓冲区。
 *		BLK_BOUNCE_ISA:			驱动程序只能在16MB的ISA区执行DMA。
 *		BLK_BOUNCE_ANY:			可以在任何地址执行DMA。
 * 默认值是BLK_BOUNCE_HIGH。
 */
void blk_queue_bounce_limit(request_queue_t *q, u64 dma_addr)
{
	unsigned long bounce_pfn = dma_addr >> PAGE_SHIFT;

	/*
	 * set appropriate bounce gfp mask -- unfortunately we don't have a
	 * full 4GB zone, so we have to resort to low memory for any bounces.
	 * ISA has its own < 16MB zone.
	 */
	if (bounce_pfn < blk_max_low_pfn) {
		BUG_ON(dma_addr < BLK_BOUNCE_ISA);
		init_emergency_isa_pool();
		q->bounce_gfp = GFP_NOIO | GFP_DMA;
	} else
		q->bounce_gfp = GFP_NOIO;

	q->bounce_pfn = bounce_pfn;
}

EXPORT_SYMBOL(blk_queue_bounce_limit);

/**
 * blk_queue_max_sectors - set max sectors for a request for this queue
 * @q:  the request queue for the device
 * @max_sectors:  max sectors in the usual 512b unit
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the size of
 *    received requests.
 **/
/**
 * 以扇区为单位设置请求的最大值。默认值是255。
 */
void blk_queue_max_sectors(request_queue_t *q, unsigned short max_sectors)
{
	if ((max_sectors << 9) < PAGE_CACHE_SIZE) {
		max_sectors = 1 << (PAGE_CACHE_SHIFT - 9);
		printk("%s: set to minimum %d\n", __FUNCTION__, max_sectors);
	}

	q->max_sectors = q->max_hw_sectors = max_sectors;
}

EXPORT_SYMBOL(blk_queue_max_sectors);

/**
 * blk_queue_max_phys_segments - set max phys segments for a request for this queue
 * @q:  the request queue for the device
 * @max_segments:  max number of segments
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the number of
 *    physical data segments in a request.  This would be the largest sized
 *    scatter list the driver could handle.
 **/
/**
 * 控制在一个请求中包含多少个物理段(在系统内存中的非连续区成员)。
 */
void blk_queue_max_phys_segments(request_queue_t *q, unsigned short max_segments)
{
	if (!max_segments) {
		max_segments = 1;
		printk("%s: set to minimum %d\n", __FUNCTION__, max_segments);
	}

	q->max_phys_segments = max_segments;
}

EXPORT_SYMBOL(blk_queue_max_phys_segments);

/**
 * blk_queue_max_hw_segments - set max hw segments for a request for this queue
 * @q:  the request queue for the device
 * @max_segments:  max number of segments
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the number of
 *    hw data segments in a request.  This would be the largest number of
 *    address/length pairs the host adapter can actually give as once
 *    to the device.
 **/
/**
 * 设置驱动程序可以处理的段的最大值。
 */
void blk_queue_max_hw_segments(request_queue_t *q, unsigned short max_segments)
{
	if (!max_segments) {
		max_segments = 1;
		printk("%s: set to minimum %d\n", __FUNCTION__, max_segments);
	}

	q->max_hw_segments = max_segments;
}

EXPORT_SYMBOL(blk_queue_max_hw_segments);

/**
 * blk_queue_max_segment_size - set max segment size for blk_rq_map_sg
 * @q:  the request queue for the device
 * @max_size:  max size of segment in bytes
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the size of a
 *    coalesced segment
 **/
void blk_queue_max_segment_size(request_queue_t *q, unsigned int max_size)
{
	if (max_size < PAGE_CACHE_SIZE) {
		max_size = PAGE_CACHE_SIZE;
		printk("%s: set to minimum %d\n", __FUNCTION__, max_size);
	}

	q->max_segment_size = max_size;
}

EXPORT_SYMBOL(blk_queue_max_segment_size);

/**
 * blk_queue_hardsect_size - set hardware sector size for the queue
 * @q:  the request queue for the device
 * @size:  the hardware sector size, in bytes
 *
 * Description:
 *   This should typically be set to the lowest possible sector size
 *   that the hardware can operate on (possible without reverting to
 *   even internal read-modify-write operations). Usually the default
 *   of 512 covers most hardware.
 **/
/**
 * 告诉内核设备硬件的扇区大小。所有由内核生成的请求都是该大小的整数倍。并且做到了边界对齐。
 */
void blk_queue_hardsect_size(request_queue_t *q, unsigned short size)
{
	q->hardsect_size = size;
}

EXPORT_SYMBOL(blk_queue_hardsect_size);

/*
 * Returns the minimum that is _not_ zero, unless both are zero.
 */
#define min_not_zero(l, r) (l == 0) ? r : ((r == 0) ? l : min(l, r))

/**
 * blk_queue_stack_limits - inherit underlying queue limits for stacked drivers
 * @t:	the stacking driver (top)
 * @b:  the underlying device (bottom)
 **/
void blk_queue_stack_limits(request_queue_t *t, request_queue_t *b)
{
	/* zero is "infinity" */
	t->max_sectors = t->max_hw_sectors =
		min_not_zero(t->max_sectors,b->max_sectors);

	t->max_phys_segments = min(t->max_phys_segments,b->max_phys_segments);
	t->max_hw_segments = min(t->max_hw_segments,b->max_hw_segments);
	t->max_segment_size = min(t->max_segment_size,b->max_segment_size);
	t->hardsect_size = max(t->hardsect_size,b->hardsect_size);
}

EXPORT_SYMBOL(blk_queue_stack_limits);

/**
 * blk_queue_segment_boundary - set boundary rules for segment merging
 * @q:  the request queue for the device
 * @mask:  the memory boundary mask
 **/
/**
 * 一些设备无法处理那些跨越特定大小内存边界的请求。此函数告诉内存设备的特定边界。
 * 如果设备不能处理跨越4MB边界的请求，则mask的值为0x3fffff。默认的mask是0xffffffff。
 */
void blk_queue_segment_boundary(request_queue_t *q, unsigned long mask)
{
	if (mask < PAGE_CACHE_SIZE - 1) {
		mask = PAGE_CACHE_SIZE - 1;
		printk("%s: set to minimum %lx\n", __FUNCTION__, mask);
	}

	q->seg_boundary_mask = mask;
}

EXPORT_SYMBOL(blk_queue_segment_boundary);

/**
 * blk_queue_dma_alignment - set dma length and memory alignment
 * @q:     the request queue for the device
 * @mask:  alignment mask
 *
 * description:
 *    set required memory and length aligment for direct dma transactions.
 *    this is used when buiding direct io requests for the queue.
 *
 **/
/**
 * 告诉内核设备在使用DMA传输时的内存对齐限制。默认mask是0x1ff，这样，所有的请求都是512字节对齐。
 */
void blk_queue_dma_alignment(request_queue_t *q, int mask)
{
	q->dma_alignment = mask;
}

EXPORT_SYMBOL(blk_queue_dma_alignment);

/**
 * blk_queue_find_tag - find a request by its tag and queue
 *
 * @q:	 The request queue for the device
 * @tag: The tag of the request
 *
 * Notes:
 *    Should be used when a device returns a tag and you want to match
 *    it with a request.
 *
 *    no locks need be held.
 **/
/**
 * 通过标记找到所属的请求。
 */
struct request *blk_queue_find_tag(request_queue_t *q, int tag)
{
	struct blk_queue_tag *bqt = q->queue_tags;

	if (unlikely(bqt == NULL || tag >= bqt->real_max_depth))
		return NULL;

	return bqt->tag_index[tag];
}

EXPORT_SYMBOL(blk_queue_find_tag);

/**
 * __blk_queue_free_tags - release tag maintenance info
 * @q:  the request queue for the device
 *
 *  Notes:
 *    blk_cleanup_queue() will take care of calling this function, if tagging
 *    has been used. So there's no need to call this directly.
 **/
static void __blk_queue_free_tags(request_queue_t *q)
{
	struct blk_queue_tag *bqt = q->queue_tags;

	if (!bqt)
		return;

	if (atomic_dec_and_test(&bqt->refcnt)) {
		BUG_ON(bqt->busy);
		BUG_ON(!list_empty(&bqt->busy_list));

		kfree(bqt->tag_index);
		bqt->tag_index = NULL;

		kfree(bqt->tag_map);
		bqt->tag_map = NULL;

		kfree(bqt);
	}

	q->queue_tags = NULL;
	q->queue_flags &= ~(1 << QUEUE_FLAG_QUEUED);
}

/**
 * blk_queue_free_tags - release tag maintenance info
 * @q:  the request queue for the device
 *
 *  Notes:
 *	This is used to disabled tagged queuing to a device, yet leave
 *	queue in function.
 **/
void blk_queue_free_tags(request_queue_t *q)
{
	clear_bit(QUEUE_FLAG_QUEUED, &q->queue_flags);
}

EXPORT_SYMBOL(blk_queue_free_tags);

static int
init_tag_map(request_queue_t *q, struct blk_queue_tag *tags, int depth)
{
	int bits, i;
	struct request **tag_index;
	unsigned long *tag_map;

	if (depth > q->nr_requests * 2) {
		depth = q->nr_requests * 2;
		printk(KERN_ERR "%s: adjusted depth to %d\n",
				__FUNCTION__, depth);
	}

	tag_index = kmalloc(depth * sizeof(struct request *), GFP_ATOMIC);
	if (!tag_index)
		goto fail;

	bits = (depth / BLK_TAGS_PER_LONG) + 1;
	tag_map = kmalloc(bits * sizeof(unsigned long), GFP_ATOMIC);
	if (!tag_map)
		goto fail;

	memset(tag_index, 0, depth * sizeof(struct request *));
	memset(tag_map, 0, bits * sizeof(unsigned long));
	tags->max_depth = depth;
	tags->real_max_depth = bits * BITS_PER_LONG;
	tags->tag_index = tag_index;
	tags->tag_map = tag_map;

	/*
	 * set the upper bits if the depth isn't a multiple of the word size
	 */
	for (i = depth; i < bits * BLK_TAGS_PER_LONG; i++)
		__set_bit(i, tag_map);

	return 0;
fail:
	kfree(tag_index);
	return -ENOMEM;
}

/**
 * blk_queue_init_tags - initialize the queue tag info
 * @q:  the request queue for the device
 * @depth:  the maximum queue depth supported
 **/
/**
 * 通知内核设备支持标记命令队列。
 */
int blk_queue_init_tags(request_queue_t *q, int depth,
			struct blk_queue_tag *tags)
{
	int rc;

	BUG_ON(tags && q->queue_tags && tags != q->queue_tags);

	if (!tags && !q->queue_tags) {
		tags = kmalloc(sizeof(struct blk_queue_tag), GFP_ATOMIC);
		if (!tags)
			goto fail;

		if (init_tag_map(q, tags, depth))
			goto fail;

		INIT_LIST_HEAD(&tags->busy_list);
		tags->busy = 0;
		atomic_set(&tags->refcnt, 1);
	} else if (q->queue_tags) {
		if ((rc = blk_queue_resize_tags(q, depth)))
			return rc;
		set_bit(QUEUE_FLAG_QUEUED, &q->queue_flags);
		return 0;
	} else
		atomic_inc(&tags->refcnt);

	/*
	 * assign it, all done
	 */
	q->queue_tags = tags;
	q->queue_flags |= (1 << QUEUE_FLAG_QUEUED);
	return 0;
fail:
	kfree(tags);
	return -ENOMEM;
}

EXPORT_SYMBOL(blk_queue_init_tags);

/**
 * blk_queue_resize_tags - change the queueing depth
 * @q:  the request queue for the device
 * @new_depth: the new max command queueing depth
 *
 *  Notes:
 *    Must be called with the queue lock held.
 **/
/**
 * 重新设置设备支持的标记数量。
 */
int blk_queue_resize_tags(request_queue_t *q, int new_depth)
{
	struct blk_queue_tag *bqt = q->queue_tags;
	struct request **tag_index;
	unsigned long *tag_map;
	int bits, max_depth;

	if (!bqt)
		return -ENXIO;

	/*
	 * don't bother sizing down
	 */
	if (new_depth <= bqt->real_max_depth) {
		bqt->max_depth = new_depth;
		return 0;
	}

	/*
	 * save the old state info, so we can copy it back
	 */
	tag_index = bqt->tag_index;
	tag_map = bqt->tag_map;
	max_depth = bqt->real_max_depth;

	if (init_tag_map(q, bqt, new_depth))
		return -ENOMEM;

	memcpy(bqt->tag_index, tag_index, max_depth * sizeof(struct request *));
	bits = max_depth / BLK_TAGS_PER_LONG;
	memcpy(bqt->tag_map, tag_map, bits * sizeof(unsigned long));

	kfree(tag_index);
	kfree(tag_map);
	return 0;
}

EXPORT_SYMBOL(blk_queue_resize_tags);

/**
 * blk_queue_end_tag - end tag operations for a request
 * @q:  the request queue for the device
 * @rq: the request that has completed
 *
 *  Description:
 *    Typically called when end_that_request_first() returns 0, meaning
 *    all transfers have been done for a request. It's important to call
 *    this function before end_that_request_last(), as that will put the
 *    request back on the free list thus corrupting the internal tag list.
 *
 *  Notes:
 *   queue lock must be held.
 **/
/**
 * 当一个请求的所有数据传输完毕后，驱动程序使用本函数释放所用的标记。
 */
void blk_queue_end_tag(request_queue_t *q, struct request *rq)
{
	struct blk_queue_tag *bqt = q->queue_tags;
	int tag = rq->tag;

	BUG_ON(tag == -1);

	if (unlikely(tag >= bqt->real_max_depth))
		return;

	if (unlikely(!__test_and_clear_bit(tag, bqt->tag_map))) {
		printk("attempt to clear non-busy tag (%d)\n", tag);
		return;
	}

	list_del_init(&rq->queuelist);
	rq->flags &= ~REQ_QUEUED;
	rq->tag = -1;

	if (unlikely(bqt->tag_index[tag] == NULL))
		printk("tag %d is missing\n", tag);

	bqt->tag_index[tag] = NULL;
	bqt->busy--;
}

EXPORT_SYMBOL(blk_queue_end_tag);

/**
 * blk_queue_start_tag - find a free tag and assign it
 * @q:  the request queue for the device
 * @rq:  the block request that needs tagging
 *
 *  Description:
 *    This can either be used as a stand-alone helper, or possibly be
 *    assigned as the queue &prep_rq_fn (in which case &struct request
 *    automagically gets a tag assigned). Note that this function
 *    assumes that any type of request can be queued! if this is not
 *    true for your device, you must check the request type before
 *    calling this function.  The request will also be removed from
 *    the request queue, so it's the drivers responsibility to readd
 *    it if it should need to be restarted for some reason.
 *
 *  Notes:
 *   queue lock must be held.
 **/
/**
 * 将一个标记与一个请求相关联。
 */
int blk_queue_start_tag(request_queue_t *q, struct request *rq)
{
	struct blk_queue_tag *bqt = q->queue_tags;
	unsigned long *map = bqt->tag_map;
	int tag = 0;

	if (unlikely((rq->flags & REQ_QUEUED))) {
		printk(KERN_ERR 
		       "request %p for device [%s] already tagged %d",
		       rq, rq->rq_disk ? rq->rq_disk->disk_name : "?", rq->tag);
		BUG();
	}

	for (map = bqt->tag_map; *map == -1UL; map++) {
		tag += BLK_TAGS_PER_LONG;

		if (tag >= bqt->max_depth)
			return 1;
	}

	tag += ffz(*map);
	__set_bit(tag, bqt->tag_map);

	rq->flags |= REQ_QUEUED;
	rq->tag = tag;
	bqt->tag_index[tag] = rq;
	blkdev_dequeue_request(rq);
	list_add(&rq->queuelist, &bqt->busy_list);
	bqt->busy++;
	return 0;
}

EXPORT_SYMBOL(blk_queue_start_tag);

/**
 * blk_queue_invalidate_tags - invalidate all pending tags
 * @q:  the request queue for the device
 *
 *  Description:
 *   Hardware conditions may dictate a need to stop all pending requests.
 *   In this case, we will safely clear the block side of the tag queue and
 *   readd all requests to the request queue in the right order.
 *
 *  Notes:
 *   queue lock must be held.
 **/
/**
 * 将所有未执行的标记返回给缓冲区，并且把相应的请求发还给请求队列。
 */
void blk_queue_invalidate_tags(request_queue_t *q)
{
	struct blk_queue_tag *bqt = q->queue_tags;
	struct list_head *tmp, *n;
	struct request *rq;

	list_for_each_safe(tmp, n, &bqt->busy_list) {
		rq = list_entry_rq(tmp);

		if (rq->tag == -1) {
			printk("bad tag found on list\n");
			list_del_init(&rq->queuelist);
			rq->flags &= ~REQ_QUEUED;
		} else
			blk_queue_end_tag(q, rq);

		rq->flags &= ~REQ_STARTED;
		__elv_add_request(q, rq, ELEVATOR_INSERT_BACK, 0);
	}
}

EXPORT_SYMBOL(blk_queue_invalidate_tags);

static char *rq_flags[] = {
	"REQ_RW",
	"REQ_FAILFAST",
	"REQ_SOFTBARRIER",
	"REQ_HARDBARRIER",
	"REQ_CMD",
	"REQ_NOMERGE",
	"REQ_STARTED",
	"REQ_DONTPREP",
	"REQ_QUEUED",
	"REQ_PC",
	"REQ_BLOCK_PC",
	"REQ_SENSE",
	"REQ_FAILED",
	"REQ_QUIET",
	"REQ_SPECIAL",
	"REQ_DRIVE_CMD",
	"REQ_DRIVE_TASK",
	"REQ_DRIVE_TASKFILE",
	"REQ_PREEMPT",
	"REQ_PM_SUSPEND",
	"REQ_PM_RESUME",
	"REQ_PM_SHUTDOWN",
};

void blk_dump_rq_flags(struct request *rq, char *msg)
{
	int bit;

	printk("%s: dev %s: flags = ", msg,
		rq->rq_disk ? rq->rq_disk->disk_name : "?");
	bit = 0;
	do {
		if (rq->flags & (1 << bit))
			printk("%s ", rq_flags[bit]);
		bit++;
	} while (bit < __REQ_NR_BITS);

	printk("\nsector %llu, nr/cnr %lu/%u\n", (unsigned long long)rq->sector,
						       rq->nr_sectors,
						       rq->current_nr_sectors);
	printk("bio %p, biotail %p, buffer %p, data %p, len %u\n", rq->bio, rq->biotail, rq->buffer, rq->data, rq->data_len);

	if (rq->flags & (REQ_BLOCK_PC | REQ_PC)) {
		printk("cdb: ");
		for (bit = 0; bit < sizeof(rq->cmd); bit++)
			printk("%02x ", rq->cmd[bit]);
		printk("\n");
	}
}

EXPORT_SYMBOL(blk_dump_rq_flags);

void blk_recount_segments(request_queue_t *q, struct bio *bio)
{
	struct bio_vec *bv, *bvprv = NULL;
	int i, nr_phys_segs, nr_hw_segs, seg_size, hw_seg_size, cluster;
	int high, highprv = 1;

	if (unlikely(!bio->bi_io_vec))
		return;

	cluster = q->queue_flags & (1 << QUEUE_FLAG_CLUSTER);
	hw_seg_size = seg_size = nr_phys_segs = nr_hw_segs = 0;
	bio_for_each_segment(bv, bio, i) {
		/*
		 * the trick here is making sure that a high page is never
		 * considered part of another segment, since that might
		 * change with the bounce page.
		 */
		high = page_to_pfn(bv->bv_page) >= q->bounce_pfn;
		if (high || highprv)
			goto new_hw_segment;
		if (cluster) {
			if (seg_size + bv->bv_len > q->max_segment_size)
				goto new_segment;
			if (!BIOVEC_PHYS_MERGEABLE(bvprv, bv))
				goto new_segment;
			if (!BIOVEC_SEG_BOUNDARY(q, bvprv, bv))
				goto new_segment;
			if (BIOVEC_VIRT_OVERSIZE(hw_seg_size + bv->bv_len))
				goto new_hw_segment;

			seg_size += bv->bv_len;
			hw_seg_size += bv->bv_len;
			bvprv = bv;
			continue;
		}
new_segment:
		if (BIOVEC_VIRT_MERGEABLE(bvprv, bv) &&
		    !BIOVEC_VIRT_OVERSIZE(hw_seg_size + bv->bv_len)) {
			hw_seg_size += bv->bv_len;
		} else {
new_hw_segment:
			if (hw_seg_size > bio->bi_hw_front_size)
				bio->bi_hw_front_size = hw_seg_size;
			hw_seg_size = BIOVEC_VIRT_START_SIZE(bv) + bv->bv_len;
			nr_hw_segs++;
		}

		nr_phys_segs++;
		bvprv = bv;
		seg_size = bv->bv_len;
		highprv = high;
	}
	if (hw_seg_size > bio->bi_hw_back_size)
		bio->bi_hw_back_size = hw_seg_size;
	if (nr_hw_segs == 1 && hw_seg_size > bio->bi_hw_front_size)
		bio->bi_hw_front_size = hw_seg_size;
	bio->bi_phys_segments = nr_phys_segs;
	bio->bi_hw_segments = nr_hw_segs;
	bio->bi_flags |= (1 << BIO_SEG_VALID);
}


int blk_phys_contig_segment(request_queue_t *q, struct bio *bio,
				   struct bio *nxt)
{
	if (!(q->queue_flags & (1 << QUEUE_FLAG_CLUSTER)))
		return 0;

	if (!BIOVEC_PHYS_MERGEABLE(__BVEC_END(bio), __BVEC_START(nxt)))
		return 0;
	if (bio->bi_size + nxt->bi_size > q->max_segment_size)
		return 0;

	/*
	 * bio and nxt are contigous in memory, check if the queue allows
	 * these two to be merged into one
	 */
	if (BIO_SEG_BOUNDARY(q, bio, nxt))
		return 1;

	return 0;
}

EXPORT_SYMBOL(blk_phys_contig_segment);

int blk_hw_contig_segment(request_queue_t *q, struct bio *bio,
				 struct bio *nxt)
{
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);
	if (unlikely(!bio_flagged(nxt, BIO_SEG_VALID)))
		blk_recount_segments(q, nxt);
	if (!BIOVEC_VIRT_MERGEABLE(__BVEC_END(bio), __BVEC_START(nxt)) ||
	    BIOVEC_VIRT_OVERSIZE(bio->bi_hw_front_size + bio->bi_hw_back_size))
		return 0;
	if (bio->bi_size + nxt->bi_size > q->max_segment_size)
		return 0;

	return 1;
}

EXPORT_SYMBOL(blk_hw_contig_segment);

/*
 * map a request to scatterlist, return number of sg entries setup. Caller
 * must make sure sg can hold rq->nr_phys_segments entries
 */
/**
 * 该辅助函数返回一个可以立即被用来启动数据传送的分散-聚集链表。
 * 可以将返回的分散表sg传递给dma_map_sg。
 */
int blk_rq_map_sg(request_queue_t *q, struct request *rq, struct scatterlist *sg)
{
	struct bio_vec *bvec, *bvprv;
	struct bio *bio;
	int nsegs, i, cluster;

	nsegs = 0;
	cluster = q->queue_flags & (1 << QUEUE_FLAG_CLUSTER);

	/*
	 * for each bio in rq
	 */
	bvprv = NULL;
	rq_for_each_bio(bio, rq) {
		/*
		 * for each segment in bio
		 */
		bio_for_each_segment(bvec, bio, i) {
			int nbytes = bvec->bv_len;

			if (bvprv && cluster) {
				if (sg[nsegs - 1].length + nbytes > q->max_segment_size)
					goto new_segment;

				if (!BIOVEC_PHYS_MERGEABLE(bvprv, bvec))
					goto new_segment;
				if (!BIOVEC_SEG_BOUNDARY(q, bvprv, bvec))
					goto new_segment;

				sg[nsegs - 1].length += nbytes;
			} else {
new_segment:
				memset(&sg[nsegs],0,sizeof(struct scatterlist));
				sg[nsegs].page = bvec->bv_page;
				sg[nsegs].length = nbytes;
				sg[nsegs].offset = bvec->bv_offset;

				nsegs++;
			}
			bvprv = bvec;
		} /* segments in bio */
	} /* bios in rq */

	return nsegs;
}

EXPORT_SYMBOL(blk_rq_map_sg);

/*
 * the standard queue merge functions, can be overridden with device
 * specific ones if so desired
 */

static inline int ll_new_mergeable(request_queue_t *q,
				   struct request *req,
				   struct bio *bio)
{
	int nr_phys_segs = bio_phys_segments(q, bio);

	if (req->nr_phys_segments + nr_phys_segs > q->max_phys_segments) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}

	/*
	 * A hw segment is just getting larger, bump just the phys
	 * counter.
	 */
	req->nr_phys_segments += nr_phys_segs;
	return 1;
}

static inline int ll_new_hw_segment(request_queue_t *q,
				    struct request *req,
				    struct bio *bio)
{
	int nr_hw_segs = bio_hw_segments(q, bio);
	int nr_phys_segs = bio_phys_segments(q, bio);

	if (req->nr_hw_segments + nr_hw_segs > q->max_hw_segments
	    || req->nr_phys_segments + nr_phys_segs > q->max_phys_segments) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}

	/*
	 * This will form the start of a new hw segment.  Bump both
	 * counters.
	 */
	req->nr_hw_segments += nr_hw_segs;
	req->nr_phys_segments += nr_phys_segs;
	return 1;
}

static int ll_back_merge_fn(request_queue_t *q, struct request *req, 
			    struct bio *bio)
{
	int len;

	if (req->nr_sectors + bio_sectors(bio) > q->max_sectors) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}
	if (unlikely(!bio_flagged(req->biotail, BIO_SEG_VALID)))
		blk_recount_segments(q, req->biotail);
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);
	len = req->biotail->bi_hw_back_size + bio->bi_hw_front_size;
	if (BIOVEC_VIRT_MERGEABLE(__BVEC_END(req->biotail), __BVEC_START(bio)) &&
	    !BIOVEC_VIRT_OVERSIZE(len)) {
		int mergeable =  ll_new_mergeable(q, req, bio);

		if (mergeable) {
			if (req->nr_hw_segments == 1)
				req->bio->bi_hw_front_size = len;
			if (bio->bi_hw_segments == 1)
				bio->bi_hw_back_size = len;
		}
		return mergeable;
	}

	return ll_new_hw_segment(q, req, bio);
}

static int ll_front_merge_fn(request_queue_t *q, struct request *req, 
			     struct bio *bio)
{
	int len;

	if (req->nr_sectors + bio_sectors(bio) > q->max_sectors) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}
	len = bio->bi_hw_back_size + req->bio->bi_hw_front_size;
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);
	if (unlikely(!bio_flagged(req->bio, BIO_SEG_VALID)))
		blk_recount_segments(q, req->bio);
	if (BIOVEC_VIRT_MERGEABLE(__BVEC_END(bio), __BVEC_START(req->bio)) &&
	    !BIOVEC_VIRT_OVERSIZE(len)) {
		int mergeable =  ll_new_mergeable(q, req, bio);

		if (mergeable) {
			if (bio->bi_hw_segments == 1)
				bio->bi_hw_front_size = len;
			if (req->nr_hw_segments == 1)
				req->biotail->bi_hw_back_size = len;
		}
		return mergeable;
	}

	return ll_new_hw_segment(q, req, bio);
}

static int ll_merge_requests_fn(request_queue_t *q, struct request *req,
				struct request *next)
{
	int total_phys_segments = req->nr_phys_segments +next->nr_phys_segments;
	int total_hw_segments = req->nr_hw_segments + next->nr_hw_segments;

	/*
	 * First check if the either of the requests are re-queued
	 * requests.  Can't merge them if they are.
	 */
	if (req->special || next->special)
		return 0;

	/*
	 * Will it become to large?
	 */
	if ((req->nr_sectors + next->nr_sectors) > q->max_sectors)
		return 0;

	total_phys_segments = req->nr_phys_segments + next->nr_phys_segments;
	if (blk_phys_contig_segment(q, req->biotail, next->bio))
		total_phys_segments--;

	if (total_phys_segments > q->max_phys_segments)
		return 0;

	total_hw_segments = req->nr_hw_segments + next->nr_hw_segments;
	if (blk_hw_contig_segment(q, req->biotail, next->bio)) {
		int len = req->biotail->bi_hw_back_size + next->bio->bi_hw_front_size;
		/*
		 * propagate the combined length to the end of the requests
		 */
		if (req->nr_hw_segments == 1)
			req->bio->bi_hw_front_size = len;
		if (next->nr_hw_segments == 1)
			next->biotail->bi_hw_back_size = len;
		total_hw_segments--;
	}

	if (total_hw_segments > q->max_hw_segments)
		return 0;

	/* Merge is OK... */
	req->nr_phys_segments = total_phys_segments;
	req->nr_hw_segments = total_hw_segments;
	return 1;
}

/*
 * "plug" the device if there are no outstanding requests: this will
 * force the transfer to start only after we have put all the requests
 * on the list.
 *
 * This is called with interrupts off and no requests on the queue and
 * with the queue lock held.
 */
/**
 * 插入一个块设备-将其插入到某个块设备驱动程序处理的请求队列中。
 * 其参数是一个请求队列描述符的地址。
 */
void blk_plug_device(request_queue_t *q)
{
	WARN_ON(!irqs_disabled());

	/*
	 * don't plug a stopped queue, it must be paired with blk_start_queue()
	 * which will restart the queueing
	 */
	if (test_bit(QUEUE_FLAG_STOPPED, &q->queue_flags))
		return;
	/**
	 * 设置queue_flags字段中的QUEUE_FLAG_PLUGGED.
	 * 然后重启unplug_timer字段中的内嵌动态定时器。
	 */
	if (!test_and_set_bit(QUEUE_FLAG_PLUGGED, &q->queue_flags))
		mod_timer(&q->unplug_timer, jiffies + q->unplug_delay);
}

EXPORT_SYMBOL(blk_plug_device);

/*
 * remove the queue from the plugged list, if present. called with
 * queue lock held and interrupts disabled.
 */
/**
 * 摘除一个请求队列。
 */
int blk_remove_plug(request_queue_t *q)
{
	WARN_ON(!irqs_disabled());

	/**
	 * 清除QUEUE_FLAG_PLUGGED标志。
	 */ 
	if (!test_and_clear_bit(QUEUE_FLAG_PLUGGED, &q->queue_flags))
		return 0;

	/**
	 * 清除unplug_timer动态定时器的执行。
	 */
	del_timer(&q->unplug_timer);
	return 1;
}

EXPORT_SYMBOL(blk_remove_plug);

/*
 * remove the plug and let it rip..
 */
/**
 * 拨出块设备的辅助函数
 */
void __generic_unplug_device(request_queue_t *q)
{
	/**
	 * 首先检测块设备是否仍然活跃
	 */
	if (test_bit(QUEUE_FLAG_STOPPED, &q->queue_flags))
		return;

	/**
	 * 真正的移出块设备
	 */
	if (!blk_remove_plug(q))
		return;

	/*
	 * was plugged, fire request_fn if queue has stuff to do
	 */
	/**
	 * 执行request_fn来处理请求队列的下一个请求
	 */
	if (elv_next_request(q))
		q->request_fn(q);
}
EXPORT_SYMBOL(__generic_unplug_device);

/**
 * generic_unplug_device - fire a request queue
 * @q:    The &request_queue_t in question
 *
 * Description:
 *   Linux uses plugging to build bigger requests queues before letting
 *   the device have at them. If a queue is plugged, the I/O scheduler
 *   is still adding and merging requests on the queue. Once the queue
 *   gets unplugged, the request_fn defined for the queue is invoked and
 *   transfers started.
 **/
/**
 * 拨出块设备
 */
void generic_unplug_device(request_queue_t *q)
{
	spin_lock_irq(q->queue_lock);
	__generic_unplug_device(q);
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL(generic_unplug_device);

static void blk_backing_dev_unplug(struct backing_dev_info *bdi,
				   struct page *page)
{
	request_queue_t *q = bdi->unplug_io_data;

	/*
	 * devices don't necessarily have an ->unplug_fn defined
	 */
	if (q->unplug_fn)
		q->unplug_fn(q);
}

/**
 * 请求队列的unplug_work实现函数。
 */
static void blk_unplug_work(void *data)
{
	request_queue_t *q = data;

	/**
	 * 通常unplug_fn函数是由generic_unplug_device函数实现的。它的功能是拨出块设备
	 */
	q->unplug_fn(q);
}

/**
 * 当blk_unplug_timeout函数激活的动态定时器的时间用完后，就会执行本函数。
 */
static void blk_unplug_timeout(unsigned long data)
{
	request_queue_t *q = (request_queue_t *)data;

	/**
	 * kblockd执行blk_unplug_work函数，这个函数存放在q->unplug_work中。
	 * 该函数会调用请求队列中的q->unplug_fn方法，通常该方法是由generic_unplug_device函数实现的。
	 * generic_unplug_device函数的功能是拨出块设备：首先检查请求队列是否仍然活跃。
	 * 然后，调用blk_remove_plug函数。最后，执行策略例程request_fn来开始处理请求队列中的下一个请求。
	 */
	kblockd_schedule_work(&q->unplug_work);
}

/**
 * blk_start_queue - restart a previously stopped queue
 * @q:    The &request_queue_t in question
 *
 * Description:
 *   blk_start_queue() will clear the stop flag on the queue, and call
 *   the request_fn for the queue if it was in a stopped state when
 *   entered. Also see blk_stop_queue(). Queue lock must be held.
 **/
/**
 * 重新允许块设备层向IO队列中加入请求。
 */
void blk_start_queue(request_queue_t *q)
{
	clear_bit(QUEUE_FLAG_STOPPED, &q->queue_flags);

	/*
	 * one level of recursion is ok and is much faster than kicking
	 * the unplug handling
	 */
	if (!test_and_set_bit(QUEUE_FLAG_REENTER, &q->queue_flags)) {
		q->request_fn(q);
		clear_bit(QUEUE_FLAG_REENTER, &q->queue_flags);
	} else {
		blk_plug_device(q);
		kblockd_schedule_work(&q->unplug_work);
	}
}

EXPORT_SYMBOL(blk_start_queue);

/**
 * blk_stop_queue - stop a queue
 * @q:    The &request_queue_t in question
 *
 * Description:
 *   The Linux block layer assumes that a block driver will consume all
 *   entries on the request queue when the request_fn strategy is called.
 *   Often this will not happen, because of hardware limitations (queue
 *   depth settings). If a device driver gets a 'queue full' response,
 *   or if it simply chooses not to queue more I/O at one point, it can
 *   call this function to prevent the request_fn from being called until
 *   the driver has signalled it's ready to go again. This happens by calling
 *   blk_start_queue() to restart queue operations. Queue lock must be held.
 **/
/**
 * 如果驱动程序不能再处理更多命令，则调用此函数通知块设备层。
 */
void blk_stop_queue(request_queue_t *q)
{
	blk_remove_plug(q);
	set_bit(QUEUE_FLAG_STOPPED, &q->queue_flags);
}
EXPORT_SYMBOL(blk_stop_queue);

/**
 * blk_sync_queue - cancel any pending callbacks on a queue
 * @q: the queue
 *
 * Description:
 *     The block layer may perform asynchronous callback activity
 *     on a queue, such as calling the unplug function after a timeout.
 *     A block device may call blk_sync_queue to ensure that any
 *     such activity is cancelled, thus allowing it to release resources
 *     the the callbacks might use. The caller must already have made sure
 *     that its ->make_request_fn will not re-add plugging prior to calling
 *     this function.
 *
 */
void blk_sync_queue(struct request_queue *q)
{
	del_timer_sync(&q->unplug_timer);
	kblockd_flush();
}
EXPORT_SYMBOL(blk_sync_queue);

/**
 * blk_run_queue - run a single device queue
 * @q:	The queue to run
 */
void blk_run_queue(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	blk_remove_plug(q);
	q->request_fn(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(blk_run_queue);

/**
 * blk_cleanup_queue: - release a &request_queue_t when it is no longer needed
 * @q:    the request queue to be released
 *
 * Description:
 *     blk_cleanup_queue is the pair to blk_init_queue() or
 *     blk_queue_make_request().  It should be called when a request queue is
 *     being released; typically when a block device is being de-registered.
 *     Currently, its primary task it to free all the &struct request
 *     structures that were allocated to the queue and the queue itself.
 *
 * Caveat:
 *     Hopefully the low level driver will have finished any
 *     outstanding requests first...
 **/
/**
 * 把块设备请求队列返回给系统。
 */
void blk_cleanup_queue(request_queue_t * q)
{
	struct request_list *rl = &q->rq;

	if (!atomic_dec_and_test(&q->refcnt))
		return;

	if (q->elevator)
		elevator_exit(q->elevator);

	blk_sync_queue(q);

	if (rl->rq_pool)
		mempool_destroy(rl->rq_pool);

	if (q->queue_tags)
		__blk_queue_free_tags(q);

	kmem_cache_free(requestq_cachep, q);
}

EXPORT_SYMBOL(blk_cleanup_queue);

static int blk_init_free_list(request_queue_t *q)
{
	struct request_list *rl = &q->rq;

	rl->count[READ] = rl->count[WRITE] = 0;
	rl->starved[READ] = rl->starved[WRITE] = 0;
	init_waitqueue_head(&rl->wait[READ]);
	init_waitqueue_head(&rl->wait[WRITE]);
	init_waitqueue_head(&rl->drain);

	rl->rq_pool = mempool_create(BLKDEV_MIN_RQ, mempool_alloc_slab, mempool_free_slab, request_cachep);

	if (!rl->rq_pool)
		return -ENOMEM;

	return 0;
}

static int __make_request(request_queue_t *, struct bio *);

request_queue_t *blk_alloc_queue(int gfp_mask)
{
	request_queue_t *q = kmem_cache_alloc(requestq_cachep, gfp_mask);

	if (!q)
		return NULL;

	memset(q, 0, sizeof(*q));
	init_timer(&q->unplug_timer);
	atomic_set(&q->refcnt, 1);

	q->backing_dev_info.unplug_io_fn = blk_backing_dev_unplug;
	q->backing_dev_info.unplug_io_data = q;

	return q;
}

EXPORT_SYMBOL(blk_alloc_queue);

/**
 * blk_init_queue  - prepare a request queue for use with a block device
 * @rfn:  The function to be called to process requests that have been
 *        placed on the queue.
 * @lock: Request queue spin lock
 *
 * Description:
 *    If a block device wishes to use the standard request handling procedures,
 *    which sorts requests and coalesces adjacent requests, then it must
 *    call blk_init_queue().  The function @rfn will be called when there
 *    are requests on the queue that need to be processed.  If the device
 *    supports plugging, then @rfn may not be called immediately when requests
 *    are available on the queue, but may be called at some time later instead.
 *    Plugged queues are generally unplugged when a buffer belonging to one
 *    of the requests on the queue is needed, or due to memory pressure.
 *
 *    @rfn is not required, or even expected, to remove all requests off the
 *    queue, but only as many as it can handle at a time.  If it does leave
 *    requests on the queue, it is responsible for arranging that the requests
 *    get dealt with eventually.
 *
 *    The queue spin lock must be held while manipulating the requests on the
 *    request queue.
 *
 *    Function returns a pointer to the initialized request queue, or NULL if
 *    it didn't succeed.
 *
 * Note:
 *    blk_init_queue() must be paired with a blk_cleanup_queue() call
 *    when the block device is deactivated (such as at module unload).
 **/
/**
 * 分配一个请求队列描述符，并将其中许多字段初始化为缺省值。
 * 它接收的参数为设备描述符的自旋锁的地址（foo.gd->rq->queue_lock）
 * 和设备驱动程序的策略例程（foo.gd->rq->request_fn）
 * 该函数也初始化foo.gd->rq->elevator，并强制驱动程序使用缺省的IO调度算法。
 * 如果驱动程序想用其他调度算法，可以稍候覆盖elevator字段。
 */
request_queue_t *blk_init_queue(request_fn_proc *rfn, spinlock_t *lock)
{
	request_queue_t *q = blk_alloc_queue(GFP_KERNEL);

	if (!q)
		return NULL;

	if (blk_init_free_list(q))
		goto out_init;

	q->request_fn		= rfn;
	q->back_merge_fn       	= ll_back_merge_fn;
	q->front_merge_fn      	= ll_front_merge_fn;
	q->merge_requests_fn	= ll_merge_requests_fn;
	q->prep_rq_fn		= NULL;
	q->unplug_fn		= generic_unplug_device;
	q->queue_flags		= (1 << QUEUE_FLAG_CLUSTER);
	q->queue_lock		= lock;

	blk_queue_segment_boundary(q, 0xffffffff);

	blk_queue_make_request(q, __make_request);
	blk_queue_max_segment_size(q, MAX_SEGMENT_SIZE);

	blk_queue_max_hw_segments(q, MAX_HW_SEGMENTS);
	blk_queue_max_phys_segments(q, MAX_PHYS_SEGMENTS);

	/*
	 * all done
	 */
	if (!elevator_init(q, NULL)) {
		blk_queue_congestion_threshold(q);
		return q;
	}

	blk_cleanup_queue(q);
out_init:
	kmem_cache_free(requestq_cachep, q);
	return NULL;
}

EXPORT_SYMBOL(blk_init_queue);

int blk_get_queue(request_queue_t *q)
{
	if (!test_bit(QUEUE_FLAG_DEAD, &q->queue_flags)) {
		atomic_inc(&q->refcnt);
		return 0;
	}

	return 1;
}

EXPORT_SYMBOL(blk_get_queue);

static inline void blk_free_request(request_queue_t *q, struct request *rq)
{
	elv_put_request(q, rq);
	mempool_free(rq, q->rq.rq_pool);
}

static inline struct request *blk_alloc_request(request_queue_t *q, int rw,
						int gfp_mask)
{
	struct request *rq = mempool_alloc(q->rq.rq_pool, gfp_mask);

	if (!rq)
		return NULL;

	/*
	 * first three bits are identical in rq->flags and bio->bi_rw,
	 * see bio.h and blkdev.h
	 */
	rq->flags = rw;

	if (!elv_set_request(q, rq, gfp_mask))
		return rq;

	mempool_free(rq, q->rq.rq_pool);
	return NULL;
}

/*
 * ioc_batching returns true if the ioc is a valid batching request and
 * should be given priority access to a request.
 */
static inline int ioc_batching(request_queue_t *q, struct io_context *ioc)
{
	if (!ioc)
		return 0;

	/*
	 * Make sure the process is able to allocate at least 1 request
	 * even if the batch times out, otherwise we could theoretically
	 * lose wakeups.
	 */
	return ioc->nr_batch_requests == q->nr_batching ||
		(ioc->nr_batch_requests > 0
		&& time_before(jiffies, ioc->last_waited + BLK_BATCH_TIME));
}

/*
 * ioc_set_batching sets ioc to be a new "batcher" if it is not one. This
 * will cause the process to be a "batcher" on all queues in the system. This
 * is the behaviour we want though - once it gets a wakeup it should be given
 * a nice run.
 */
void ioc_set_batching(request_queue_t *q, struct io_context *ioc)
{
	if (!ioc || ioc_batching(q, ioc))
		return;

	ioc->nr_batch_requests = q->nr_batching;
	ioc->last_waited = jiffies;
}

static void __freed_request(request_queue_t *q, int rw)
{
	struct request_list *rl = &q->rq;

	if (rl->count[rw] < queue_congestion_off_threshold(q))
		clear_queue_congested(q, rw);

	if (rl->count[rw] + 1 <= q->nr_requests) {
		smp_mb();
		if (waitqueue_active(&rl->wait[rw]))
			wake_up(&rl->wait[rw]);

		blk_clear_queue_full(q, rw);
	}
}

/*
 * A request has just been released.  Account for it, update the full and
 * congestion status, wake up any waiters.   Called under q->queue_lock.
 */
static void freed_request(request_queue_t *q, int rw)
{
	struct request_list *rl = &q->rq;

	rl->count[rw]--;

	__freed_request(q, rw);

	if (unlikely(rl->starved[rw ^ 1]))
		__freed_request(q, rw ^ 1);

	if (!rl->count[READ] && !rl->count[WRITE]) {
		smp_mb();
		if (unlikely(waitqueue_active(&rl->drain)))
			wake_up(&rl->drain);
	}
}

#define blkdev_free_rq(list) list_entry((list)->next, struct request, queuelist)
/*
 * Get a free request, queue_lock must not be held
 */
static struct request *get_request(request_queue_t *q, int rw, int gfp_mask)
{
	struct request *rq = NULL;
	struct request_list *rl = &q->rq;
	struct io_context *ioc = get_io_context(gfp_mask);

	if (unlikely(test_bit(QUEUE_FLAG_DRAIN, &q->queue_flags)))
		goto out;

	spin_lock_irq(q->queue_lock);
	if (rl->count[rw]+1 >= q->nr_requests) {
		/*
		 * The queue will fill after this allocation, so set it as
		 * full, and mark this process as "batching". This process
		 * will be allowed to complete a batch of requests, others
		 * will be blocked.
		 */
		if (!blk_queue_full(q, rw)) {
			ioc_set_batching(q, ioc);
			blk_set_queue_full(q, rw);
		}
	}

	switch (elv_may_queue(q, rw)) {
		case ELV_MQUEUE_NO:
			goto rq_starved;
		case ELV_MQUEUE_MAY:
			break;
		case ELV_MQUEUE_MUST:
			goto get_rq;
	}

	if (blk_queue_full(q, rw) && !ioc_batching(q, ioc)) {
		/*
		 * The queue is full and the allocating process is not a
		 * "batcher", and not exempted by the IO scheduler
		 */
		spin_unlock_irq(q->queue_lock);
		goto out;
	}

get_rq:
	rl->count[rw]++;
	rl->starved[rw] = 0;
	if (rl->count[rw] >= queue_congestion_on_threshold(q))
		set_queue_congested(q, rw);
	spin_unlock_irq(q->queue_lock);

	rq = blk_alloc_request(q, rw, gfp_mask);
	if (!rq) {
		/*
		 * Allocation failed presumably due to memory. Undo anything
		 * we might have messed up.
		 *
		 * Allocating task should really be put onto the front of the
		 * wait queue, but this is pretty rare.
		 */
		spin_lock_irq(q->queue_lock);
		freed_request(q, rw);

		/*
		 * in the very unlikely event that allocation failed and no
		 * requests for this direction was pending, mark us starved
		 * so that freeing of a request in the other direction will
		 * notice us. another possible fix would be to split the
		 * rq mempool into READ and WRITE
		 */
rq_starved:
		if (unlikely(rl->count[rw] == 0))
			rl->starved[rw] = 1;

		spin_unlock_irq(q->queue_lock);
		goto out;
	}

	if (ioc_batching(q, ioc))
		ioc->nr_batch_requests--;
	
	INIT_LIST_HEAD(&rq->queuelist);

	rq->errors = 0;
	rq->rq_status = RQ_ACTIVE;
	rq->bio = rq->biotail = NULL;
	rq->buffer = NULL;
	rq->ref_count = 1;
	rq->q = q;
	rq->rl = rl;
	rq->waiting = NULL;
	rq->special = NULL;
	rq->data_len = 0;
	rq->data = NULL;
	rq->sense = NULL;

out:
	put_io_context(ioc);
	return rq;
}

/*
 * No available requests for this queue, unplug the device and wait for some
 * requests to become available.
 */
static struct request *get_request_wait(request_queue_t *q, int rw)
{
	DEFINE_WAIT(wait);
	struct request *rq;

	generic_unplug_device(q);
	do {
		struct request_list *rl = &q->rq;

		prepare_to_wait_exclusive(&rl->wait[rw], &wait,
				TASK_UNINTERRUPTIBLE);

		rq = get_request(q, rw, GFP_NOIO);

		if (!rq) {
			struct io_context *ioc;

			io_schedule();

			/*
			 * After sleeping, we become a "batching" process and
			 * will be able to allocate at least one request, and
			 * up to a big batch of them for a small period time.
			 * See ioc_batching, ioc_set_batching
			 */
			ioc = get_io_context(GFP_NOIO);
			ioc_set_batching(q, ioc);
			put_io_context(ioc);
		}
		finish_wait(&rl->wait[rw], &wait);
	} while (!rq);

	return rq;
}

/**
 * 试图从一个特定请求队列的内存池中获得空闲的描述符。
 * 如果内存区不足并且内存池已经用完，则挂起当前进程或者返回NULL
 */
struct request *blk_get_request(request_queue_t *q, int rw, int gfp_mask)
{
	struct request *rq;

	BUG_ON(rw != READ && rw != WRITE);

	if (gfp_mask & __GFP_WAIT)
		rq = get_request_wait(q, rw);
	else
		rq = get_request(q, rw, gfp_mask);

	return rq;
}

EXPORT_SYMBOL(blk_get_request);

/**
 * blk_requeue_request - put a request back on queue
 * @q:		request queue where request should be inserted
 * @rq:		request to be inserted
 *
 * Description:
 *    Drivers often keep queueing requests until the hardware cannot accept
 *    more, when that condition happens we need to put the request back
 *    on the queue. Must be called with queue lock held.
 */
void blk_requeue_request(request_queue_t *q, struct request *rq)
{
	if (blk_rq_tagged(rq))
		blk_queue_end_tag(q, rq);

	elv_requeue_request(q, rq);
}

EXPORT_SYMBOL(blk_requeue_request);

/**
 * blk_insert_request - insert a special request in to a request queue
 * @q:		request queue where request should be inserted
 * @rq:		request to be inserted
 * @at_head:	insert request at head or tail of queue
 * @data:	private data
 * @reinsert:	true if request it a reinsertion of previously processed one
 *
 * Description:
 *    Many block devices need to execute commands asynchronously, so they don't
 *    block the whole kernel from preemption during request execution.  This is
 *    accomplished normally by inserting aritficial requests tagged as
 *    REQ_SPECIAL in to the corresponding request queue, and letting them be
 *    scheduled for actual execution by the request queue.
 *
 *    We have the option of inserting the head or the tail of the queue.
 *    Typically we use the tail for new ioctls and so forth.  We use the head
 *    of the queue for things like a QUEUE_FULL message from a device, or a
 *    host that is unable to accept a particular command.
 */
void blk_insert_request(request_queue_t *q, struct request *rq,
			int at_head, void *data, int reinsert)
{
	unsigned long flags;

	/*
	 * tell I/O scheduler that this isn't a regular read/write (ie it
	 * must not attempt merges on this) and that it acts as a soft
	 * barrier
	 */
	rq->flags |= REQ_SPECIAL | REQ_SOFTBARRIER;

	rq->special = data;

	spin_lock_irqsave(q->queue_lock, flags);

	/*
	 * If command is tagged, release the tag
	 */
	if (reinsert)
		blk_requeue_request(q, rq);
	else {
		int where = ELEVATOR_INSERT_BACK;

		if (at_head)
			where = ELEVATOR_INSERT_FRONT;

		if (blk_rq_tagged(rq))
			blk_queue_end_tag(q, rq);

		drive_stat_acct(rq, rq->nr_sectors, 1);
		__elv_add_request(q, rq, where, 0);
	}
	if (blk_queue_plugged(q))
		__generic_unplug_device(q);
	else
		q->request_fn(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

EXPORT_SYMBOL(blk_insert_request);

/**
 * blk_rq_map_user - map user data to a request, for REQ_BLOCK_PC usage
 * @q:		request queue where request should be inserted
 * @rw:		READ or WRITE data
 * @ubuf:	the user buffer
 * @len:	length of user data
 *
 * Description:
 *    Data will be mapped directly for zero copy io, if possible. Otherwise
 *    a kernel bounce buffer is used.
 *
 *    A matching blk_rq_unmap_user() must be issued at the end of io, while
 *    still in process context.
 *
 *    Note: The mapped bio may need to be bounced through blk_queue_bounce()
 *    before being submitted to the device, as pages mapped may be out of
 *    reach. It's the callers responsibility to make sure this happens. The
 *    original bio must be passed back in to blk_rq_unmap_user() for proper
 *    unmapping.
 */
struct request *blk_rq_map_user(request_queue_t *q, int rw, void __user *ubuf,
				unsigned int len)
{
	unsigned long uaddr;
	struct request *rq;
	struct bio *bio;

	if (len > (q->max_sectors << 9))
		return ERR_PTR(-EINVAL);
	if ((!len && ubuf) || (len && !ubuf))
		return ERR_PTR(-EINVAL);

	rq = blk_get_request(q, rw, __GFP_WAIT);
	if (!rq)
		return ERR_PTR(-ENOMEM);

	/*
	 * if alignment requirement is satisfied, map in user pages for
	 * direct dma. else, set up kernel bounce buffers
	 */
	uaddr = (unsigned long) ubuf;
	if (!(uaddr & queue_dma_alignment(q)) && !(len & queue_dma_alignment(q)))
		bio = bio_map_user(q, NULL, uaddr, len, rw == READ);
	else
		bio = bio_copy_user(q, uaddr, len, rw == READ);

	if (!IS_ERR(bio)) {
		rq->bio = rq->biotail = bio;
		blk_rq_bio_prep(q, rq, bio);

		rq->buffer = rq->data = NULL;
		rq->data_len = len;
		return rq;
	}

	/*
	 * bio is the err-ptr
	 */
	blk_put_request(rq);
	return (struct request *) bio;
}

EXPORT_SYMBOL(blk_rq_map_user);

/**
 * blk_rq_unmap_user - unmap a request with user data
 * @rq:		request to be unmapped
 * @ubuf:	user buffer
 * @ulen:	length of user buffer
 *
 * Description:
 *    Unmap a request previously mapped by blk_rq_map_user().
 */
int blk_rq_unmap_user(struct request *rq, struct bio *bio, unsigned int ulen)
{
	int ret = 0;

	if (bio) {
		if (bio_flagged(bio, BIO_USER_MAPPED))
			bio_unmap_user(bio);
		else
			ret = bio_uncopy_user(bio);
	}

	blk_put_request(rq);
	return ret;
}

EXPORT_SYMBOL(blk_rq_unmap_user);

/**
 * blk_execute_rq - insert a request into queue for execution
 * @q:		queue to insert the request in
 * @bd_disk:	matching gendisk
 * @rq:		request to insert
 *
 * Description:
 *    Insert a fully prepared request at the back of the io scheduler queue
 *    for execution.
 */
int blk_execute_rq(request_queue_t *q, struct gendisk *bd_disk,
		   struct request *rq)
{
	DECLARE_COMPLETION(wait);
	char sense[SCSI_SENSE_BUFFERSIZE];
	int err = 0;

	rq->rq_disk = bd_disk;

	/*
	 * we need an extra reference to the request, so we can look at
	 * it after io completion
	 */
	rq->ref_count++;

	if (!rq->sense) {
		memset(sense, 0, sizeof(sense));
		rq->sense = sense;
		rq->sense_len = 0;
	}

	rq->flags |= REQ_NOMERGE;
	if (!rq->waiting)
		rq->waiting = &wait;
	elv_add_request(q, rq, ELEVATOR_INSERT_BACK, 1);
	generic_unplug_device(q);
	wait_for_completion(rq->waiting);
	rq->waiting = NULL;

	if (rq->errors)
		err = -EIO;

	return err;
}

EXPORT_SYMBOL(blk_execute_rq);

/**
 * blkdev_issue_flush - queue a flush
 * @bdev:	blockdev to issue flush for
 * @error_sector:	error sector
 *
 * Description:
 *    Issue a flush for the block device in question. Caller can supply
 *    room for storing the error offset in case of a flush error, if they
 *    wish to.  Caller must run wait_for_completion() on its own.
 */
int blkdev_issue_flush(struct block_device *bdev, sector_t *error_sector)
{
	request_queue_t *q;

	if (bdev->bd_disk == NULL)
		return -ENXIO;

	q = bdev_get_queue(bdev);
	if (!q)
		return -ENXIO;
	if (!q->issue_flush_fn)
		return -EOPNOTSUPP;

	return q->issue_flush_fn(q, bdev->bd_disk, error_sector);
}

EXPORT_SYMBOL(blkdev_issue_flush);

/**
 * blkdev_scsi_issue_flush_fn - issue flush for SCSI devices
 * @q:		device queue
 * @disk:	gendisk
 * @error_sector:	error offset
 *
 * Description:
 *    Devices understanding the SCSI command set, can use this function as
 *    a helper for issuing a cache flush. Note: driver is required to store
 *    the error offset (in case of error flushing) in ->sector of struct
 *    request.
 */
int blkdev_scsi_issue_flush_fn(request_queue_t *q, struct gendisk *disk,
			       sector_t *error_sector)
{
	struct request *rq = blk_get_request(q, WRITE, __GFP_WAIT);
	int ret;

	rq->flags |= REQ_BLOCK_PC | REQ_SOFTBARRIER;
	rq->sector = 0;
	memset(rq->cmd, 0, sizeof(rq->cmd));
	rq->cmd[0] = 0x35;
	rq->cmd_len = 12;
	rq->data = NULL;
	rq->data_len = 0;
	rq->timeout = 60 * HZ;

	ret = blk_execute_rq(q, disk, rq);

	if (ret && error_sector)
		*error_sector = rq->sector;

	blk_put_request(rq);
	return ret;
}

EXPORT_SYMBOL(blkdev_scsi_issue_flush_fn);

void drive_stat_acct(struct request *rq, int nr_sectors, int new_io)
{
	int rw = rq_data_dir(rq);

	if (!blk_fs_request(rq) || !rq->rq_disk)
		return;

	if (rw == READ) {
		__disk_stat_add(rq->rq_disk, read_sectors, nr_sectors);
		if (!new_io)
			__disk_stat_inc(rq->rq_disk, read_merges);
	} else if (rw == WRITE) {
		__disk_stat_add(rq->rq_disk, write_sectors, nr_sectors);
		if (!new_io)
			__disk_stat_inc(rq->rq_disk, write_merges);
	}
	if (new_io) {
		disk_round_stats(rq->rq_disk);
		rq->rq_disk->in_flight++;
	}
}

/*
 * add-request adds a request to the linked list.
 * queue lock is held and interrupts disabled, as we muck with the
 * request queue list.
 */
/* 将io请求添加到队列中 */
static inline void add_request(request_queue_t * q, struct request * req)
{
	drive_stat_acct(req, req->nr_sectors, 1);

	if (q->activity_fn)/* 调用请求队列的回调，表示有一个新请求加入，一般未定义 */
		q->activity_fn(q->activity_data, rq_data_dir(req));

	/*
	 * elevator indicated where it wants this request to be
	 * inserted at elevator_merge time
	 */
	__elv_add_request(q, req, ELEVATOR_INSERT_SORT, 0);
}
 
/*
 * disk_round_stats()	- Round off the performance stats on a struct
 * disk_stats.
 *
 * The average IO queue length and utilisation statistics are maintained
 * by observing the current state of the queue length and the amount of
 * time it has been in this state for.
 *
 * Normally, that accounting is done on IO completion, but that can result
 * in more than a second's worth of IO being accounted for within any one
 * second, leading to >100% utilisation.  To deal with that, we call this
 * function to do a round-off before returning the results when reading
 * /proc/diskstats.  This accounts immediately for all queue usage up to
 * the current jiffies and restarts the counters again.
 */
void disk_round_stats(struct gendisk *disk)
{
	unsigned long now = jiffies;

	__disk_stat_add(disk, time_in_queue,
			disk->in_flight * (now - disk->stamp));
	disk->stamp = now;

	if (disk->in_flight)
		__disk_stat_add(disk, io_ticks, (now - disk->stamp_idle));
	disk->stamp_idle = now;
}

/*
 * queue lock must be held
 */
void __blk_put_request(request_queue_t *q, struct request *req)
{
	struct request_list *rl = req->rl;

	if (unlikely(!q))
		return;
	if (unlikely(--req->ref_count))
		return;

	req->rq_status = RQ_INACTIVE;
	req->q = NULL;
	req->rl = NULL;

	/*
	 * Request may not have originated from ll_rw_blk. if not,
	 * it didn't come out of our reserved rq pools
	 */
	if (rl) {
		int rw = rq_data_dir(req);

		elv_completed_request(q, req);

		BUG_ON(!list_empty(&req->queuelist));

		blk_free_request(q, req);
		freed_request(q, rw);
	}
}

/**
 * 释放请求描述符，如果引用计数器为0，则释放到内存池。
 */
void blk_put_request(struct request *req)
{
	/*
	 * if req->rl isn't set, this request didnt originate from the
	 * block layer, so it's safe to just disregard it
	 */
	if (req->rl) {
		unsigned long flags;
		request_queue_t *q = req->q;

		spin_lock_irqsave(q->queue_lock, flags);
		__blk_put_request(q, req);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}
}

EXPORT_SYMBOL(blk_put_request);

/**
 * blk_congestion_wait - wait for a queue to become uncongested
 * @rw: READ or WRITE
 * @timeout: timeout in jiffies
 *
 * Waits for up to @timeout jiffies for a queue (any queue) to exit congestion.
 * If no queues are congested then just wait for the next request to be
 * returned.
 */
/**
 * 挂起当前进程，直到所有请求队列都变为不拥塞或超时已到
 */
long blk_congestion_wait(int rw, long timeout)
{
	long ret;
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = &congestion_wqh[rw];

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = io_schedule_timeout(timeout);
	finish_wait(wqh, &wait);
	return ret;
}

EXPORT_SYMBOL(blk_congestion_wait);

/*
 * Has to be called with the request spinlock acquired
 */
static int attempt_merge(request_queue_t *q, struct request *req,
			  struct request *next)
{
	if (!rq_mergeable(req) || !rq_mergeable(next))
		return 0;

	/*
	 * not contigious
	 */
	if (req->sector + req->nr_sectors != next->sector)
		return 0;

	if (rq_data_dir(req) != rq_data_dir(next)
	    || req->rq_disk != next->rq_disk
	    || next->waiting || next->special)
		return 0;

	/*
	 * If we are allowed to merge, then append bio list
	 * from next to rq and release next. merge_requests_fn
	 * will have updated segment counts, update sector
	 * counts here.
	 */
	if (!q->merge_requests_fn(q, req, next))
		return 0;

	/*
	 * At this point we have either done a back merge
	 * or front merge. We need the smaller start_time of
	 * the merged requests to be the current request
	 * for accounting purposes.
	 */
	if (time_after(req->start_time, next->start_time))
		req->start_time = next->start_time;

	req->biotail->bi_next = next->bio;
	req->biotail = next->biotail;

	req->nr_sectors = req->hard_nr_sectors += next->hard_nr_sectors;

	elv_merge_requests(q, req, next);

	if (req->rq_disk) {
		disk_round_stats(req->rq_disk);
		req->rq_disk->in_flight--;
	}

	__blk_put_request(q, next);
	return 1;
}

static inline int attempt_back_merge(request_queue_t *q, struct request *rq)
{
	struct request *next = elv_latter_request(q, rq);

	if (next)
		return attempt_merge(q, rq, next);

	return 0;
}

static inline int attempt_front_merge(request_queue_t *q, struct request *rq)
{
	struct request *prev = elv_former_request(q, rq);

	if (prev)
		return attempt_merge(q, prev, rq);

	return 0;
}

/**
 * blk_attempt_remerge  - attempt to remerge active head with next request
 * @q:    The &request_queue_t belonging to the device
 * @rq:   The head request (usually)
 *
 * Description:
 *    For head-active devices, the queue can easily be unplugged so quickly
 *    that proper merging is not done on the front request. This may hurt
 *    performance greatly for some devices. The block layer cannot safely
 *    do merging on that first request for these queues, but the driver can
 *    call this function and make it happen any way. Only the driver knows
 *    when it is safe to do so.
 **/
void blk_attempt_remerge(request_queue_t *q, struct request *rq)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	attempt_back_merge(q, rq);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

EXPORT_SYMBOL(blk_attempt_remerge);

/*
 * Non-locking blk_attempt_remerge variant.
 */
void __blk_attempt_remerge(request_queue_t *q, struct request *rq)
{
	attempt_back_merge(q, rq);
}

EXPORT_SYMBOL(__blk_attempt_remerge);

/**
 * 通用块层调用此函数，获得IO调度层的服务。
 */
static int __make_request(request_queue_t *q, struct bio *bio)
{
	struct request *req, *freereq = NULL;
	int el_ret, rw, nr_sectors, cur_nr_sectors, barrier, err;
	sector_t sector;

	sector = bio->bi_sector;
	nr_sectors = bio_sectors(bio);
	cur_nr_sectors = bio_cur_sectors(bio);

	rw = bio_data_dir(bio);

	/*
	 * low level driver can indicate that it wants pages above a
	 * certain limit bounced to low memory (ie for highmem, or even
	 * ISA dma in theory)
	 */
	/**
	 * 如果有必要，建立一个回弹缓冲区。如果回弹缓冲区被建立，后续将对该缓冲区而不是对原bio结构进行操作。
	 */
	blk_queue_bounce(q, &bio);

	spin_lock_prefetch(q->queue_lock);

	barrier = bio_barrier(bio);
	/* 屏障请求，但是队列不支持屏障，退出 */
	if (barrier && !(q->queue_flags & (1 << QUEUE_FLAG_ORDERED))) {
		err = -EOPNOTSUPP;
		goto end_io;
	}

again:
	spin_lock_irq(q->queue_lock);

	/**
	 * 检查请求队列中是否存在待处理请求。
	 */
	if (elv_queue_empty(q)) {
		/**
		 * 没有待处理请求，则调用blk_plug_device插入请求队列。
		 */
		blk_plug_device(q);
		goto get_rq;
	}
	if (barrier)
		goto get_rq;

	/**
	 * 请求队列中包含待处理请求。调用elv_merge检查新bio结构是否可以并入已有请求中。
	 */
	el_ret = elv_merge(q, &req, bio);
	switch (el_ret) {
		case ELEVATOR_BACK_MERGE:/* 可以添加到某个bio末尾 */
			BUG_ON(!rq_mergeable(req));

			/**
			 * 检查是否可以将请求合并到bio的末尾。
			 */
			if (!q->back_merge_fn(q, req, bio))
				break;

			/**
			 * 将该请求合并到bio的末尾。
			 */
			req->biotail->bi_next = bio;
			req->biotail = bio;
			req->nr_sectors = req->hard_nr_sectors += nr_sectors;
			drive_stat_acct(req, nr_sectors, 0);
			/**
			 * 检查是否可以与后面的请求合并。
			 */
			if (!attempt_back_merge(q, req))
				elv_merged_request(q, req);
			goto out;

		case ELEVATOR_FRONT_MERGE:/* 可以插到某个请求的前面 */
			BUG_ON(!rq_mergeable(req));

			/**
			 * 检查是否可以合并到该bio的前面
			 */
			if (!q->front_merge_fn(q, req, bio))
				break;

			/**
			 * 合并到该bio的前面
			 */
			bio->bi_next = req->bio;
			req->bio = bio;

			/*
			 * may not be valid. if the low level driver said
			 * it didn't need a bounce buffer then it better
			 * not touch req->buffer either...
			 */
			req->buffer = bio_data(bio);
			req->current_nr_sectors = cur_nr_sectors;
			req->hard_cur_sectors = cur_nr_sectors;
			req->sector = req->hard_sector = sector;
			req->nr_sectors = req->hard_nr_sectors += nr_sectors;
			drive_stat_acct(req, nr_sectors, 0);
			/**
			 * 检查是否可以与上面的bio进行进一步的合并。
			 */
			if (!attempt_front_merge(q, req))
				elv_merged_request(q, req);
			goto out;

		/*
		 * elevator says don't/can't merge. get new request
		 */
		case ELEVATOR_NO_MERGE:/* 未合并，转到get_rq将请求插入。 */
			break;

		default:
			printk("elevator returned crap (%d)\n", el_ret);
			BUG();
	}

	/*
	 * Grab a free request from the freelist - if that is empty, check
	 * if we are doing read ahead and abort instead of blocking for
	 * a free slot.
	 */
/**
 * 需要将请求插入到现有队列。
 */
get_rq:
	if (freereq) {/* 有可用描述符 */
		req = freereq;
		freereq = NULL;
	} else {
		spin_unlock_irq(q->queue_lock);
		/**
		 * 分配一个新请求
		 */
		if ((freereq = get_request(q, rw, GFP_ATOMIC)) == NULL) {
			/*
			 * READA bit set
			 */
			err = -EWOULDBLOCK;
			if (bio_rw_ahead(bio))
				goto end_io;

			/**
			 * 不能直接分配一个请求，那么等待内存可用，并分配一个请求描述短信超人 。
			 */
			freereq = get_request_wait(q, rw);
		}
		goto again;
	}

	/**
	 * 一次标准的读或写操作标志
	 */
	req->flags |= REQ_CMD;

	/*
	 * inherit FAILFAST from bio (for read-ahead, and explicit FAILFAST)
	 */
	/**
	 * 是一次预读。如果失败就直接返回不用重试。
	 */
	if (bio_rw_ahead(bio) || bio_failfast(bio))
		req->flags |= REQ_FAILFAST;

	/*
	 * REQ_BARRIER implies no merging, but lets make it explicit
	 */
	if (barrier)
		req->flags |= (REQ_HARDBARRIER | REQ_NOMERGE);

	/**
	 * 初始化请求描述符中的字段。
	 */
	req->errors = 0;
	req->hard_sector = req->sector = sector;
	req->hard_nr_sectors = req->nr_sectors = nr_sectors;
	req->current_nr_sectors = req->hard_cur_sectors = cur_nr_sectors;
	req->nr_phys_segments = bio_phys_segments(q, bio);
	req->nr_hw_segments = bio_hw_segments(q, bio);
	req->buffer = bio_data(bio);	/* see ->buffer comment above */
	req->waiting = NULL;
	req->bio = req->biotail = bio;
	req->rq_disk = bio->bi_bdev->bd_disk;
	req->start_time = jiffies;

	/**
	 * 将bio插入请求链表。
	 */
	add_request(q, req);
out:
	if (freereq)/* 临时申请了描述符，但是由于当前请求被合并而不需要该描述符，释放它 */
		__blk_put_request(q, freereq);
	if (bio_sync(bio))/* 如果设置了BIO_RW_SYNC，则调用__generic_unplug_device摘除块设备 */
		__generic_unplug_device(q);

	spin_unlock_irq(q->queue_lock);
	return 0;

end_io:
	bio_endio(bio, nr_sectors << 9, err);
	return 0;
}

/*
 * If bio->bi_dev is a partition, remap the location
 */
static inline void blk_partition_remap(struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;

	/**
	 * 检查一个块设备是否指的是一个磁盘分区（bio->bi_bdev!=bdev->bd_contains）
	 */
	if (bdev != bdev->bd_contains) {
		/**
		 * 获得分区的hd_struct描述符
		 */
		struct hd_struct *p = bdev->bd_part;

		/**
		 * 更新计数值
		 */
		switch (bio->bi_rw) {
		case READ:
			p->read_sectors += bio_sectors(bio);
			p->reads++;
			break;
		case WRITE:
			p->write_sectors += bio_sectors(bio);
			p->writes++;
			break;
		}
		/**
		 * 调整bi_sector，把相对于分区的起始扇区号转变为相对于整个磁盘的扇区号。
		 */
		bio->bi_sector += p->start_sect;
		/**
		 * 将bio->bi_bdev设置为整个磁盘的块设备描述符
		 * 这样，下次就不会再次调整上面的值了
		 */
		bio->bi_bdev = bdev->bd_contains;
	}
}

void blk_finish_queue_drain(request_queue_t *q)
{
	struct request_list *rl = &q->rq;
	struct request *rq;

	spin_lock_irq(q->queue_lock);
	clear_bit(QUEUE_FLAG_DRAIN, &q->queue_flags);

	while (!list_empty(&q->drain_list)) {
		rq = list_entry_rq(q->drain_list.next);

		list_del_init(&rq->queuelist);
		__elv_add_request(q, rq, ELEVATOR_INSERT_BACK, 1);
	}

	spin_unlock_irq(q->queue_lock);

	wake_up(&rl->wait[0]);
	wake_up(&rl->wait[1]);
	wake_up(&rl->drain);
}

static int wait_drain(request_queue_t *q, struct request_list *rl, int dispatch)
{
	int wait = rl->count[READ] + rl->count[WRITE];

	if (dispatch)
		wait += !list_empty(&q->queue_head);

	return wait;
}

/*
 * We rely on the fact that only requests allocated through blk_alloc_request()
 * have io scheduler private data structures associated with them. Any other
 * type of request (allocated on stack or through kmalloc()) should not go
 * to the io scheduler core, but be attached to the queue head instead.
 */
void blk_wait_queue_drained(request_queue_t *q, int wait_dispatch)
{
	struct request_list *rl = &q->rq;
	DEFINE_WAIT(wait);

	spin_lock_irq(q->queue_lock);
	set_bit(QUEUE_FLAG_DRAIN, &q->queue_flags);

	while (wait_drain(q, rl, wait_dispatch)) {
		prepare_to_wait(&rl->drain, &wait, TASK_UNINTERRUPTIBLE);

		if (wait_drain(q, rl, wait_dispatch)) {
			__generic_unplug_device(q);
			spin_unlock_irq(q->queue_lock);
			io_schedule();
			spin_lock_irq(q->queue_lock);
		}

		finish_wait(&rl->drain, &wait);
	}

	spin_unlock_irq(q->queue_lock);
}

/*
 * block waiting for the io scheduler being started again.
 */
/**
 * 检查当前正在使用的IO调度程序是否可以被动态取代。
 * 如果可以，则让当前进程睡眠直到启动一个新的IO调度程序。
 */
static inline void block_wait_queue_running(request_queue_t *q)
{
	DEFINE_WAIT(wait);

	while (test_bit(QUEUE_FLAG_DRAIN, &q->queue_flags)) {
		struct request_list *rl = &q->rq;

		prepare_to_wait_exclusive(&rl->drain, &wait,
				TASK_UNINTERRUPTIBLE);

		/*
		 * re-check the condition. avoids using prepare_to_wait()
		 * in the fast path (queue is running)
		 */
		if (test_bit(QUEUE_FLAG_DRAIN, &q->queue_flags))
			io_schedule();

		finish_wait(&rl->drain, &wait);
	}
}

static void handle_bad_sector(struct bio *bio)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_INFO "attempt to access beyond end of device\n");
	printk(KERN_INFO "%s: rw=%ld, want=%Lu, limit=%Lu\n",
			bdevname(bio->bi_bdev, b),
			bio->bi_rw,
			(unsigned long long)bio->bi_sector + bio_sectors(bio),
			(long long)(bio->bi_bdev->bd_inode->i_size >> 9));

	set_bit(BIO_EOF, &bio->bi_flags);
}

/**
 * generic_make_request: hand a buffer to its device driver for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * generic_make_request() is used to make I/O requests of block
 * devices. It is passed a &struct bio, which describes the I/O that needs
 * to be done.
 *
 * generic_make_request() does not return any status.  The
 * success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the bio->bi_end_io
 * function described (one day) else where.
 *
 * The caller of generic_make_request must make sure that bi_io_vec
 * are set to describe the memory buffer, and that bi_dev and bi_sector are
 * set to describe the device address, and the
 * bi_end_io and optionally bi_private are set to describe how
 * completion notification should be signaled.
 *
 * generic_make_request and the drivers it calls may use bi_next if this
 * bio happens to be merged with someone else, and may change bi_dev and
 * bi_sector for remaps as it sees fit.  So the values of these fields
 * should NOT be depended on after the call to generic_make_request.
 */
/**
 * 通用块层的入口点。
 */
void generic_make_request(struct bio *bio)
{
	request_queue_t *q;
	sector_t maxsector;
	int ret, nr_sectors = bio_sectors(bio);

	might_sleep();
	/* Test device or partition size, when known. */
	/**
	 * 计算块设备的最大扇区数。
	 */
	maxsector = bio->bi_bdev->bd_inode->i_size >> 9;
	if (maxsector) {
		sector_t sector = bio->bi_sector;

		/**
		 * 请求的起始扇区号大于最大盲区，或者扇区号溢出。
		 */
		if (maxsector < nr_sectors || maxsector - nr_sectors < sector) {
			/*
			 * This may well happen - the kernel calls bread()
			 * without checking the size of the device, e.g., when
			 * mounting a device.
			 */
			handle_bad_sector(bio);/* 打印失败信息，并结束本次请求 */
			goto end_io;
		}
	}

	/*
	 * Resolve the mapping until finished. (drivers are
	 * still free to implement/resolve their own stacking
	 * by explicitly returning 0)
	 *
	 * NOTE: we don't repeat the blk_size check for each new device.
	 * Stacking drivers are expected to know what they are doing.
	 */
	do {
		char b[BDEVNAME_SIZE];

		/* 获取与块设备相关的请求队列。 */
		q = bdev_get_queue(bio->bi_bdev);
		if (!q) {/* 如果为空，说明遇到异常情况 */
			printk(KERN_ERR
			       "generic_make_request: Trying to access "
				"nonexistent block-device %s (%Lu)\n",
				bdevname(bio->bi_bdev, b),
				(long long) bio->bi_sector);
end_io:
			bio_endio(bio, bio->bi_size, -EIO);
			break;
		}

		/* 请求的扇区数量太大，错误 */
		if (unlikely(bio_sectors(bio) > q->max_hw_sectors)) {
			printk("bio too big device %s (%u > %u)\n", 
				bdevname(bio->bi_bdev, b),
				bio_sectors(bio),
				q->max_hw_sectors);
			goto end_io;
		}

		if (test_bit(QUEUE_FLAG_DEAD, &q->queue_flags))
			goto end_io;

		/* 等待IO调度就绪。 */
		block_wait_queue_running(q);

		/*
		 * If this device has partitions, remap block n
		 * of partition p to block n+start(p) of the disk.
		 */
		/**
		 * 如果是分区，则将分区的扇区位置转换成设备的扇区位置。并对分区进行一些计数。
		 */
		blk_partition_remap(bio);

		/**
		 * 请BIO请求传递给IO调度层。
		 * 常见块设备的回调函数是__make_request
		 */
		ret = q->make_request_fn(q, bio);
	} while (ret);/* 如果ret不这0，表示bio已经被修改，需要将请求提交给另外的设备，主要处理栈式块设备 */
}

EXPORT_SYMBOL(generic_make_request);

/**
 * submit_bio: submit a bio to the block device layer for I/O
 * @rw: whether to %READ or %WRITE, or maybe to %READA (read ahead)
 * @bio: The &struct bio which describes the I/O
 *
 * submit_bio() is very similar in purpose to generic_make_request(), and
 * uses that function to do most of the work. Both are fairly rough
 * interfaces, @bio must be presetup and ready for I/O.
 *
 */
/* 上层向通用块层提交请求的接口函数 */
void submit_bio(int rw, struct bio *bio)
{
	int count = bio_sectors(bio);

	BIO_BUG_ON(!bio->bi_size);
	BIO_BUG_ON(!bio->bi_io_vec);
	bio->bi_rw = rw;/* 记录读写方式 */
	if (rw & WRITE)/* 统计读写数量 */
		mod_page_state(pgpgout, count);
	else
		mod_page_state(pgpgin, count);

	if (unlikely(block_dump)) {
		char b[BDEVNAME_SIZE];
		printk(KERN_DEBUG "%s(%d): %s block %Lu on %s\n",
			current->comm, current->pid,
			(rw & WRITE) ? "WRITE" : "READ",
			(unsigned long long)bio->bi_sector,
			bdevname(bio->bi_bdev,b));
	}

	/* 执行真正的工作 */
	generic_make_request(bio);
}

EXPORT_SYMBOL(submit_bio);

void blk_recalc_rq_segments(struct request *rq)
{
	struct bio *bio, *prevbio = NULL;
	int nr_phys_segs, nr_hw_segs;
	unsigned int phys_size, hw_size;
	request_queue_t *q = rq->q;

	if (!rq->bio)
		return;

	phys_size = hw_size = nr_phys_segs = nr_hw_segs = 0;
	rq_for_each_bio(bio, rq) {
		/* Force bio hw/phys segs to be recalculated. */
		bio->bi_flags &= ~(1 << BIO_SEG_VALID);

		nr_phys_segs += bio_phys_segments(q, bio);
		nr_hw_segs += bio_hw_segments(q, bio);
		if (prevbio) {
			int pseg = phys_size + prevbio->bi_size + bio->bi_size;
			int hseg = hw_size + prevbio->bi_size + bio->bi_size;

			if (blk_phys_contig_segment(q, prevbio, bio) &&
			    pseg <= q->max_segment_size) {
				nr_phys_segs--;
				phys_size += prevbio->bi_size + bio->bi_size;
			} else
				phys_size = 0;

			if (blk_hw_contig_segment(q, prevbio, bio) &&
			    hseg <= q->max_segment_size) {
				nr_hw_segs--;
				hw_size += prevbio->bi_size + bio->bi_size;
			} else
				hw_size = 0;
		}
		prevbio = bio;
	}

	rq->nr_phys_segments = nr_phys_segs;
	rq->nr_hw_segments = nr_hw_segs;
}

void blk_recalc_rq_sectors(struct request *rq, int nsect)
{
	if (blk_fs_request(rq)) {
		rq->hard_sector += nsect;
		rq->hard_nr_sectors -= nsect;

		/*
		 * Move the I/O submission pointers ahead if required.
		 */
		if ((rq->nr_sectors >= rq->hard_nr_sectors) &&
		    (rq->sector <= rq->hard_sector)) {
			rq->sector = rq->hard_sector;
			rq->nr_sectors = rq->hard_nr_sectors;
			rq->hard_cur_sectors = bio_cur_sectors(rq->bio);
			rq->current_nr_sectors = rq->hard_cur_sectors;
			rq->buffer = bio_data(rq->bio);
		}

		/*
		 * if total number of sectors is less than the first segment
		 * size, something has gone terribly wrong
		 */
		if (rq->nr_sectors < rq->current_nr_sectors) {
			printk("blk: request botched\n");
			rq->nr_sectors = rq->current_nr_sectors;
		}
	}
}

static int __end_that_request_first(struct request *req, int uptodate,
				    int nr_bytes)
{
	int total_bytes, bio_nbytes, error, next_idx = 0;
	struct bio *bio;

	/*
	 * extend uptodate bool to allow < 0 value to be direct io error
	 */
	error = 0;
	if (end_io_error(uptodate))
		error = !uptodate ? -EIO : uptodate;

	/*
	 * for a REQ_BLOCK_PC request, we want to carry any eventual
	 * sense key with us all the way through
	 */
	if (!blk_pc_request(req))
		req->errors = 0;

	if (!uptodate) {
		if (blk_fs_request(req) && !(req->flags & REQ_QUIET))
			printk("end_request: I/O error, dev %s, sector %llu\n",
				req->rq_disk ? req->rq_disk->disk_name : "?",
				(unsigned long long)req->sector);
	}

	total_bytes = bio_nbytes = 0;
	/**
	 * 扫描请求中的BIO结构及每个BIO字段。
	 */
	while ((bio = req->bio) != NULL) {
		int nbytes;

		if (nr_bytes >= bio->bi_size) {/* 该bio已经全部完成 */
			/**
			 * 修改BIO字段，使其指向请求中每一个未完成的BIO字段。
			 */
			req->bio = bio->bi_next;
			nbytes = bio->bi_size;
			/* 将bio从链表中取出 */
			bio_endio(bio, nbytes, error);
			next_idx = 0;
			bio_nbytes = 0;
		} else {/* bio还没有完成 */
			int idx = bio->bi_idx + next_idx;

			if (unlikely(bio->bi_idx >= bio->bi_vcnt)) {/* 为种情况应当是出现了逻辑错误 */
				blk_dump_rq_flags(req, "__end_that");
				printk("%s: bio idx %d >= vcnt %d\n",
						__FUNCTION__,
						bio->bi_idx, bio->bi_vcnt);
				break;
			}

			nbytes = bio_iovec_idx(bio, idx)->bv_len;
			BIO_BUG_ON(nbytes > bio->bi_size);

			/*
			 * not a complete bvec done
			 */
			if (unlikely(nbytes > nr_bytes)) {/* 当前bio的当前段还没有完成 */
				bio_nbytes += nr_bytes;
				total_bytes += nr_bytes;
				break;
			}

			/*
			 * advance to the next vector
			 */
			next_idx++;
			bio_nbytes += nbytes;
		}

		total_bytes += nbytes;
		nr_bytes -= nbytes;

		if ((bio = req->bio)) {
			/*
			 * end more in this run, or just return 'not-done'
			 */
			if (unlikely(nr_bytes <= 0))/* 本次处理完所有接收到的字节，退出 */
				break;
		}
	}

	/*
	 * completely done
	 */
	/**
	 * 数据已经传送完，返回0
	 */
	if (!req->bio)
		return 0;

	/*
	 * if the request wasn't completed, update state
	 */
	if (bio_nbytes) {/* 当前bio还没有完成 */
		/**
		 * 在已经完成数据传送的BIO结构上调用bio_endio函数。
		 */
		bio_endio(bio, bio_nbytes, error);
		/**
		 * 修改未完成BIO结构的bi_idx字段，使其指向第一个未完成的段。
		 */
		bio->bi_idx += next_idx;
		/**
		 * 修改未完成段的bv_offset和bv_len两个字段，使其指向仍需传递的数据。
		 */
		bio_iovec(bio)->bv_offset += nr_bytes;
		bio_iovec(bio)->bv_len -= nr_bytes;
	}

	blk_recalc_rq_sectors(req, total_bytes >> 9);
	blk_recalc_rq_segments(req);
	/**
	 * 数据还没有传送完，返回1。
	 */
	return 1;
}

/**
 * end_that_request_first - end I/O on a request
 * @req:      the request being processed
 * @uptodate: 1 for success, 0 for I/O error, < 0 for specific error
 * @nr_sectors: number of sectors to end I/O on
 *
 * Description:
 *     Ends I/O on a number of sectors attached to @req, and sets it up
 *     for the next range of segments (if any) in the cluster.
 *
 * Return:
 *     0 - we are done with this request, call end_that_request_last()
 *     1 - still buffers pending for this request
 **/
/**
 * end_that_request_first用于块设备驱动的中断处理程序。当设备完成一个IO请求的部分或者全部扇区时，调用此函数通知块设备子系统。
 * nr_sectors：DMA传送的扇区数
 * uptodate：传送成功的标志
 */
int end_that_request_first(struct request *req, int uptodate, int nr_sectors)
{
	/**
	 * 修改bio字段使其指向请求中的第一个未完成的bio结构。
	 * 修改未完成bio结构的bi_idx字段，使其指向第一个未完成的段。
	 * 修改未完成段的bv_offset和bv_len字段使其指向仍需传送的数据。
	 * 同时在每个完成传送的bio结构上调用bio_endio函数。
	 */
	return __end_that_request_first(req, uptodate, nr_sectors << 9);
}

EXPORT_SYMBOL(end_that_request_first);

/**
 * end_that_request_chunk - end I/O on a request
 * @req:      the request being processed
 * @uptodate: 1 for success, 0 for I/O error, < 0 for specific error
 * @nr_bytes: number of bytes to complete
 *
 * Description:
 *     Ends I/O on a number of bytes attached to @req, and sets it up
 *     for the next range of segments (if any). Like end_that_request_first(),
 *     but deals with bytes instead of sectors.
 *
 * Return:
 *     0 - we are done with this request, call end_that_request_last()
 *     1 - still buffers pending for this request
 **/
/**
 * 与end_that_request_first相似，不过参数是字节数而不是扇区数
 */
int end_that_request_chunk(struct request *req, int uptodate, int nr_bytes)
{
	return __end_that_request_first(req, uptodate, nr_bytes);
}

EXPORT_SYMBOL(end_that_request_chunk);

/*
 * queue lock must be held
 */
/**
 * 更新一些磁盘使用计数。把请求描述符从IO调用程序rq->elevator的调度队列中删除。
 * 唤醒等待请求描述符完成的任何进程，并释放删除的那个描述符。
 * 当一个完整的请求完成时回调
 */
void end_that_request_last(struct request *req)
{
	struct gendisk *disk = req->rq_disk;
	struct completion *waiting = req->waiting;

	if (unlikely(laptop_mode) && blk_fs_request(req))
		laptop_io_completion();

	if (disk && blk_fs_request(req)) {
		unsigned long duration = jiffies - req->start_time;
		switch (rq_data_dir(req)) {
		    case WRITE:
			__disk_stat_inc(disk, writes);
			__disk_stat_add(disk, write_ticks, duration);
			break;
		    case READ:
			__disk_stat_inc(disk, reads);
			__disk_stat_add(disk, read_ticks, duration);
			break;
		}
		disk_round_stats(disk);
		disk->in_flight--;
	}
	__blk_put_request(req->q, req);
	/* Do this LAST! The structure may be freed immediately afterwards */
	if (waiting)
		complete(waiting);
}

EXPORT_SYMBOL(end_that_request_last);

void end_request(struct request *req, int uptodate)
{
	if (!end_that_request_first(req, uptodate, req->hard_cur_sectors)) {
		add_disk_randomness(req->rq_disk);
		blkdev_dequeue_request(req);
		end_that_request_last(req);
	}
}

EXPORT_SYMBOL(end_request);

void blk_rq_bio_prep(request_queue_t *q, struct request *rq, struct bio *bio)
{
	/* first three bits are identical in rq->flags and bio->bi_rw */
	rq->flags |= (bio->bi_rw & 7);

	rq->nr_phys_segments = bio_phys_segments(q, bio);
	rq->nr_hw_segments = bio_hw_segments(q, bio);
	rq->current_nr_sectors = bio_cur_sectors(bio);
	rq->hard_cur_sectors = rq->current_nr_sectors;
	rq->hard_nr_sectors = rq->nr_sectors = bio_sectors(bio);
	rq->buffer = bio_data(bio);

	rq->bio = rq->biotail = bio;
}

EXPORT_SYMBOL(blk_rq_bio_prep);

int kblockd_schedule_work(struct work_struct *work)
{
	return queue_work(kblockd_workqueue, work);
}

EXPORT_SYMBOL(kblockd_schedule_work);

void kblockd_flush(void)
{
	flush_workqueue(kblockd_workqueue);
}
EXPORT_SYMBOL(kblockd_flush);

int __init blk_dev_init(void)
{
	kblockd_workqueue = create_workqueue("kblockd");
	if (!kblockd_workqueue)
		panic("Failed to create kblockd\n");

	request_cachep = kmem_cache_create("blkdev_requests",
			sizeof(struct request), 0, SLAB_PANIC, NULL, NULL);

	requestq_cachep = kmem_cache_create("blkdev_queue",
			sizeof(request_queue_t), 0, SLAB_PANIC, NULL, NULL);

	iocontext_cachep = kmem_cache_create("blkdev_ioc",
			sizeof(struct io_context), 0, SLAB_PANIC, NULL, NULL);

	blk_max_low_pfn = max_low_pfn;
	blk_max_pfn = max_pfn;

	return 0;
}

/*
 * IO Context helper functions
 */
void put_io_context(struct io_context *ioc)
{
	if (ioc == NULL)
		return;

	BUG_ON(atomic_read(&ioc->refcount) == 0);

	if (atomic_dec_and_test(&ioc->refcount)) {
		if (ioc->aic && ioc->aic->dtor)
			ioc->aic->dtor(ioc->aic);
		if (ioc->cic && ioc->cic->dtor)
			ioc->cic->dtor(ioc->cic);

		kmem_cache_free(iocontext_cachep, ioc);
	}
}
EXPORT_SYMBOL(put_io_context);

/* Called by the exitting task */
void exit_io_context(void)
{
	unsigned long flags;
	struct io_context *ioc;

	local_irq_save(flags);
	ioc = current->io_context;
	current->io_context = NULL;
	local_irq_restore(flags);

	if (ioc->aic && ioc->aic->exit)
		ioc->aic->exit(ioc->aic);
	if (ioc->cic && ioc->cic->exit)
		ioc->cic->exit(ioc->cic);

	put_io_context(ioc);
}

/*
 * If the current task has no IO context then create one and initialise it.
 * If it does have a context, take a ref on it.
 *
 * This is always called in the context of the task which submitted the I/O.
 * But weird things happen, so we disable local interrupts to ensure exclusive
 * access to *current.
 */
struct io_context *get_io_context(int gfp_flags)
{
	struct task_struct *tsk = current;
	unsigned long flags;
	struct io_context *ret;

	local_irq_save(flags);
	ret = tsk->io_context;
	if (ret)
		goto out;

	local_irq_restore(flags);

	ret = kmem_cache_alloc(iocontext_cachep, gfp_flags);
	if (ret) {
		atomic_set(&ret->refcount, 1);
		ret->pid = tsk->pid;
		ret->last_waited = jiffies; /* doesn't matter... */
		ret->nr_batch_requests = 0; /* because this is 0 */
		ret->aic = NULL;
		ret->cic = NULL;
		spin_lock_init(&ret->lock);

		local_irq_save(flags);

		/*
		 * very unlikely, someone raced with us in setting up the task
		 * io context. free new context and just grab a reference.
		 */
		if (!tsk->io_context)
			tsk->io_context = ret;
		else {
			kmem_cache_free(iocontext_cachep, ret);
			ret = tsk->io_context;
		}

out:
		atomic_inc(&ret->refcount);
		local_irq_restore(flags);
	}

	return ret;
}
EXPORT_SYMBOL(get_io_context);

void copy_io_context(struct io_context **pdst, struct io_context **psrc)
{
	struct io_context *src = *psrc;
	struct io_context *dst = *pdst;

	if (src) {
		BUG_ON(atomic_read(&src->refcount) == 0);
		atomic_inc(&src->refcount);
		put_io_context(dst);
		*pdst = src;
	}
}
EXPORT_SYMBOL(copy_io_context);

void swap_io_context(struct io_context **ioc1, struct io_context **ioc2)
{
	struct io_context *temp;
	temp = *ioc1;
	*ioc1 = *ioc2;
	*ioc2 = temp;
}
EXPORT_SYMBOL(swap_io_context);

/*
 * sysfs parts below
 */
struct queue_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct request_queue *, char *);
	ssize_t (*store)(struct request_queue *, const char *, size_t);
};

static ssize_t
queue_var_show(unsigned int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
queue_var_store(unsigned long *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtoul(p, &p, 10);
	return count;
}

static ssize_t queue_requests_show(struct request_queue *q, char *page)
{
	return queue_var_show(q->nr_requests, (page));
}

static ssize_t
queue_requests_store(struct request_queue *q, const char *page, size_t count)
{
	struct request_list *rl = &q->rq;

	int ret = queue_var_store(&q->nr_requests, page, count);
	if (q->nr_requests < BLKDEV_MIN_RQ)
		q->nr_requests = BLKDEV_MIN_RQ;
	blk_queue_congestion_threshold(q);

	if (rl->count[READ] >= queue_congestion_on_threshold(q))
		set_queue_congested(q, READ);
	else if (rl->count[READ] < queue_congestion_off_threshold(q))
		clear_queue_congested(q, READ);

	if (rl->count[WRITE] >= queue_congestion_on_threshold(q))
		set_queue_congested(q, WRITE);
	else if (rl->count[WRITE] < queue_congestion_off_threshold(q))
		clear_queue_congested(q, WRITE);

	if (rl->count[READ] >= q->nr_requests) {
		blk_set_queue_full(q, READ);
	} else if (rl->count[READ]+1 <= q->nr_requests) {
		blk_clear_queue_full(q, READ);
		wake_up(&rl->wait[READ]);
	}

	if (rl->count[WRITE] >= q->nr_requests) {
		blk_set_queue_full(q, WRITE);
	} else if (rl->count[WRITE]+1 <= q->nr_requests) {
		blk_clear_queue_full(q, WRITE);
		wake_up(&rl->wait[WRITE]);
	}
	return ret;
}

static ssize_t queue_ra_show(struct request_queue *q, char *page)
{
	int ra_kb = q->backing_dev_info.ra_pages << (PAGE_CACHE_SHIFT - 10);

	return queue_var_show(ra_kb, (page));
}

static ssize_t
queue_ra_store(struct request_queue *q, const char *page, size_t count)
{
	unsigned long ra_kb;
	ssize_t ret = queue_var_store(&ra_kb, page, count);

	spin_lock_irq(q->queue_lock);
	if (ra_kb > (q->max_sectors >> 1))
		ra_kb = (q->max_sectors >> 1);

	q->backing_dev_info.ra_pages = ra_kb >> (PAGE_CACHE_SHIFT - 10);
	spin_unlock_irq(q->queue_lock);

	return ret;
}

static ssize_t queue_max_sectors_show(struct request_queue *q, char *page)
{
	int max_sectors_kb = q->max_sectors >> 1;

	return queue_var_show(max_sectors_kb, (page));
}

static ssize_t
queue_max_sectors_store(struct request_queue *q, const char *page, size_t count)
{
	unsigned long max_sectors_kb,
			max_hw_sectors_kb = q->max_hw_sectors >> 1,
			page_kb = 1 << (PAGE_CACHE_SHIFT - 10);
	ssize_t ret = queue_var_store(&max_sectors_kb, page, count);
	int ra_kb;

	if (max_sectors_kb > max_hw_sectors_kb || max_sectors_kb < page_kb)
		return -EINVAL;
	/*
	 * Take the queue lock to update the readahead and max_sectors
	 * values synchronously:
	 */
	spin_lock_irq(q->queue_lock);
	/*
	 * Trim readahead window as well, if necessary:
	 */
	ra_kb = q->backing_dev_info.ra_pages << (PAGE_CACHE_SHIFT - 10);
	if (ra_kb > max_sectors_kb)
		q->backing_dev_info.ra_pages =
				max_sectors_kb >> (PAGE_CACHE_SHIFT - 10);

	q->max_sectors = max_sectors_kb << 1;
	spin_unlock_irq(q->queue_lock);

	return ret;
}

static ssize_t queue_max_hw_sectors_show(struct request_queue *q, char *page)
{
	int max_hw_sectors_kb = q->max_hw_sectors >> 1;

	return queue_var_show(max_hw_sectors_kb, (page));
}


static struct queue_sysfs_entry queue_requests_entry = {
	.attr = {.name = "nr_requests", .mode = S_IRUGO | S_IWUSR },
	.show = queue_requests_show,
	.store = queue_requests_store,
};

static struct queue_sysfs_entry queue_ra_entry = {
	.attr = {.name = "read_ahead_kb", .mode = S_IRUGO | S_IWUSR },
	.show = queue_ra_show,
	.store = queue_ra_store,
};

static struct queue_sysfs_entry queue_max_sectors_entry = {
	.attr = {.name = "max_sectors_kb", .mode = S_IRUGO | S_IWUSR },
	.show = queue_max_sectors_show,
	.store = queue_max_sectors_store,
};

static struct queue_sysfs_entry queue_max_hw_sectors_entry = {
	.attr = {.name = "max_hw_sectors_kb", .mode = S_IRUGO },
	.show = queue_max_hw_sectors_show,
};

static struct queue_sysfs_entry queue_iosched_entry = {
	.attr = {.name = "scheduler", .mode = S_IRUGO | S_IWUSR },
	.show = elv_iosched_show,
	.store = elv_iosched_store,
};

static struct attribute *default_attrs[] = {
	&queue_requests_entry.attr,
	&queue_ra_entry.attr,
	&queue_max_hw_sectors_entry.attr,
	&queue_max_sectors_entry.attr,
	&queue_iosched_entry.attr,
	NULL,
};

#define to_queue(atr) container_of((atr), struct queue_sysfs_entry, attr)

static ssize_t
queue_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct queue_sysfs_entry *entry = to_queue(attr);
	struct request_queue *q;

	q = container_of(kobj, struct request_queue, kobj);
	if (!entry->show)
		return 0;

	return entry->show(q, page);
}

static ssize_t
queue_attr_store(struct kobject *kobj, struct attribute *attr,
		    const char *page, size_t length)
{
	struct queue_sysfs_entry *entry = to_queue(attr);
	struct request_queue *q;

	q = container_of(kobj, struct request_queue, kobj);
	if (!entry->store)
		return -EINVAL;

	return entry->store(q, page, length);
}

static struct sysfs_ops queue_sysfs_ops = {
	.show	= queue_attr_show,
	.store	= queue_attr_store,
};

struct kobj_type queue_ktype = {
	.sysfs_ops	= &queue_sysfs_ops,
	.default_attrs	= default_attrs,
};

int blk_register_queue(struct gendisk *disk)
{
	int ret;

	request_queue_t *q = disk->queue;

	if (!q || !q->request_fn)
		return -ENXIO;

	q->kobj.parent = kobject_get(&disk->kobj);
	if (!q->kobj.parent)
		return -EBUSY;

	snprintf(q->kobj.name, KOBJ_NAME_LEN, "%s", "queue");
	q->kobj.ktype = &queue_ktype;

	ret = kobject_register(&q->kobj);
	if (ret < 0)
		return ret;

	ret = elv_register_queue(q);
	if (ret) {
		kobject_unregister(&q->kobj);
		return ret;
	}

	return 0;
}

void blk_unregister_queue(struct gendisk *disk)
{
	request_queue_t *q = disk->queue;

	if (q && q->request_fn) {
		elv_unregister_queue(q);

		kobject_unregister(&q->kobj);
		kobject_put(&disk->kobj);
	}
}
