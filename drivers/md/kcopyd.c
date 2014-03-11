/*
 * Copyright (C) 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 *
 * Kcopyd provides a simple interface for copying an area of one
 * block-device to one or more other block-devices, with an asynchronous
 * completion notification.
 */

#include <asm/atomic.h>

#include <linux/blkdev.h>
#include <linux/config.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "kcopyd.h"

static struct workqueue_struct *_kcopyd_wq;
static struct work_struct _kcopyd_work;

static inline void wake(void)
{
	queue_work(_kcopyd_wq, &_kcopyd_work);
}

/*-----------------------------------------------------------------
 * Each kcopyd client has its own little pool of preallocated
 * pages for kcopyd io.
 *---------------------------------------------------------------*/
struct kcopyd_client {
	struct list_head list;

	/* 保护页面分配的锁 */
	spinlock_t lock;
	/* 客户端空闲页面列表 */
	struct page_list *pages;
	/* 客户端拥有的页面数 */
	unsigned int nr_pages;
	/* 剩余空闲页面数 */
	unsigned int nr_free_pages;
};

static struct page_list *alloc_pl(void)
{
	struct page_list *pl;

	pl = kmalloc(sizeof(*pl), GFP_KERNEL);
	if (!pl)
		return NULL;

	pl->page = alloc_page(GFP_KERNEL);
	if (!pl->page) {
		kfree(pl);
		return NULL;
	}

	return pl;
}

static void free_pl(struct page_list *pl)
{
	__free_page(pl->page);
	kfree(pl);
}

static int kcopyd_get_pages(struct kcopyd_client *kc,
			    unsigned int nr, struct page_list **pages)
{
	struct page_list *pl;

	spin_lock(&kc->lock);
	if (kc->nr_free_pages < nr) {
		spin_unlock(&kc->lock);
		return -ENOMEM;
	}

	kc->nr_free_pages -= nr;
	for (*pages = pl = kc->pages; --nr; pl = pl->next)
		;

	kc->pages = pl->next;
	pl->next = NULL;

	spin_unlock(&kc->lock);

	return 0;
}

static void kcopyd_put_pages(struct kcopyd_client *kc, struct page_list *pl)
{
	struct page_list *cursor;

	spin_lock(&kc->lock);
	for (cursor = pl; cursor->next; cursor = cursor->next)
		kc->nr_free_pages++;

	kc->nr_free_pages++;
	cursor->next = kc->pages;
	kc->pages = pl;
	spin_unlock(&kc->lock);
}

/*
 * These three functions resize the page pool.
 */
static void drop_pages(struct page_list *pl)
{
	struct page_list *next;

	while (pl) {
		next = pl->next;
		free_pl(pl);
		pl = next;
	}
}

static int client_alloc_pages(struct kcopyd_client *kc, unsigned int nr)
{
	unsigned int i;
	struct page_list *pl = NULL, *next;

	for (i = 0; i < nr; i++) {
		next = alloc_pl();
		if (!next) {
			if (pl)
				drop_pages(pl);
			return -ENOMEM;
		}
		next->next = pl;
		pl = next;
	}

	kcopyd_put_pages(kc, pl);
	kc->nr_pages += nr;
	return 0;
}

static void client_free_pages(struct kcopyd_client *kc)
{
	BUG_ON(kc->nr_free_pages != kc->nr_pages);
	drop_pages(kc->pages);
	kc->pages = NULL;
	kc->nr_free_pages = kc->nr_pages = 0;
}

/*-----------------------------------------------------------------
 * kcopyd_jobs need to be allocated by the *clients* of kcopyd,
 * for this reason we use a mempool to prevent the client from
 * ever having to do io (which could cause a deadlock).
 *---------------------------------------------------------------*/
struct kcopyd_job {
	/* 所属的kcopyd客户端 */
	struct kcopyd_client *kc;
	/* 链接到客户端描述符的链表 */
	struct list_head list;
	/* 任务标志，如是否忽略读写错误 */
	unsigned long flags;

	/*
	 * Error state of the job.
	 */
	int read_err;/* 如果非0，表示发生了读取错误 */
	unsigned int write_err;/* 如果非0，表示发生了写入错误 */

	/*
	 * Either READ or WRITE
	 */
	int rw;/* 当前任务的IO方向，读或写 */
	struct io_region source;

	/*
	 * The destinations for the transfer.
	 */
	/* 目标数目 */
	unsigned int num_dests;
	/* 目标 */
	struct io_region dests[KCOPYD_MAX_REGIONS];

	/* 扇区偏移 */
	sector_t offset;
	/* 处理该任务需要分配的页面数 */
	unsigned int nr_pages;
	/* 分配给该任务的页面链表 */
	struct page_list *pages;

	/*
	 * Set this to ensure you are notified when the job has
	 * completed.  'context' is for callback to use.
	 */
	kcopyd_notify_fn fn;/* 完成时的回调函数 */
	void *context;/* 传递给回调函数的参数 */

	/*
	 * These fields are only used if the job has been split
	 * into more manageable parts.
	 */
	struct semaphore lock;/* 当前任务必须分为多个子任务时，使用的互斥量 */
	/* 子任务数 */
	atomic_t sub_jobs;
	/* 任务执行的进度 */
	sector_t progress;
};

/* FIXME: this should scale with the number of pages */
#define MIN_JOBS 512

static kmem_cache_t *_job_cache;
static mempool_t *_job_pool;

/*
 * We maintain three lists of jobs:
 *
 * i)   jobs waiting for pages
 * ii)  jobs that have pages, and are waiting for the io to be issued.
 * iii) jobs that have completed.
 *
 * All three of these are protected by job_lock.
 */
static DEFINE_SPINLOCK(_job_lock);

static LIST_HEAD(_complete_jobs);
static LIST_HEAD(_io_jobs);
static LIST_HEAD(_pages_jobs);

static int jobs_init(void)
{
	_job_cache = kmem_cache_create("kcopyd-jobs",
				       sizeof(struct kcopyd_job),
				       __alignof__(struct kcopyd_job),
				       0, NULL, NULL);
	if (!_job_cache)
		return -ENOMEM;

	_job_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
				   mempool_free_slab, _job_cache);
	if (!_job_pool) {
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

	return 0;
}

static void jobs_exit(void)
{
	BUG_ON(!list_empty(&_complete_jobs));
	BUG_ON(!list_empty(&_io_jobs));
	BUG_ON(!list_empty(&_pages_jobs));

	mempool_destroy(_job_pool);
	kmem_cache_destroy(_job_cache);
	_job_pool = NULL;
	_job_cache = NULL;
}

/*
 * Functions to push and pop a job onto the head of a given job
 * list.
 */
static inline struct kcopyd_job *pop(struct list_head *jobs)
{
	struct kcopyd_job *job = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);

	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct kcopyd_job, list);
		list_del(&job->list);
	}
	spin_unlock_irqrestore(&_job_lock, flags);

	return job;
}

static inline void push(struct list_head *jobs, struct kcopyd_job *job)
{
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add_tail(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}

/*
 * These three functions process 1 item from the corresponding
 * job list.
 *
 * They return:
 * < 0: error
 *   0: success
 * > 0: can't process yet.
 */
static int run_complete_job(struct kcopyd_job *job)
{
	void *context = job->context;
	int read_err = job->read_err;
	unsigned int write_err = job->write_err;
	kcopyd_notify_fn fn = job->fn;

	kcopyd_put_pages(job->kc, job->pages);/* 释放任务占用的页面 */
	mempool_free(job, _job_pool);/* 将任务放回内存池 */
	fn(read_err, write_err, context);/* 调用任务完成回调 */
	return 0;
}

/* IO完成后的回调函数 */
static void complete_io(unsigned long error, void *context)
{
	struct kcopyd_job *job = (struct kcopyd_job *) context;

	if (error) {/* 发生了IO错误 */
		if (job->rw == WRITE)/* 记录下读写错误 */
			job->write_err &= error;
		else
			job->read_err = 1;

		if (!test_bit(KCOPYD_IGNORE_ERROR, &job->flags)) {/* 上层要求不能忽略读写错误 */
			push(&_complete_jobs, job);/* 将它放到完成队列中 */
			wake();
			return;
		}
	}

	if (job->rw == WRITE)/* 完成写 */
		push(&_complete_jobs, job);/* 将其放入完成队列 */

	else {
		job->rw = WRITE;/* 改变读写方向，并将其放入IO队列 */
		push(&_io_jobs, job);
	}

	wake();
}

/*
 * Request io on as many buffer heads as we can currently get for
 * a particular job.
 */
static int run_io_job(struct kcopyd_job *job)
{
	int r;

	if (job->rw == READ)/* 从复制源读取数据 */
		r = dm_io_async(1, &job->source, job->rw,
				job->pages,
				job->offset, complete_io, job);

	else/* 向目标写入数据 */
		r = dm_io_async(job->num_dests, job->dests, job->rw,
				job->pages,
				job->offset, complete_io, job);

	return r;
}

static int run_pages_job(struct kcopyd_job *job)
{
	int r;

	/* 计算复制任务需要的页面数 */
	job->nr_pages = dm_div_up(job->dests[0].count + job->offset,
				  PAGE_SIZE >> 9);
	/* 分配所需要的页面 */
	r = kcopyd_get_pages(job->kc, job->nr_pages, &job->pages);
	if (!r) {/* 分配成功，将任务放到读写队列并返回0 */
		/* this job is ready for io */
		push(&_io_jobs, job);
		return 0;
	}

	if (r == -ENOMEM)/* 没有内存了，返回1，稍后再说 */
		/* can't complete now */
		return 1;

	return r;
}

/*
 * Run through a list for as long as possible.  Returns the count
 * of successful jobs.
 */
static int process_jobs(struct list_head *jobs, int (*fn) (struct kcopyd_job *))
{
	struct kcopyd_job *job;
	int r, count = 0;

	while ((job = pop(jobs))) {/* 从队列中取出任务 */

		r = fn(job);/* 调用回调函数处理该任务 */

		if (r < 0) {/* 出现错误 */
			/* error this rogue job */
			if (job->rw == WRITE)/* 记录错误 */
				job->write_err = (unsigned int) -1;
			else
				job->read_err = 1;
			/* 任务已经无法继续进行，将其放回完成队列 */
			push(&_complete_jobs, job);
			break;
		}

		if (r > 0) {/* 当前不能处理，今后可能能够继续 */
			/*
			 * We couldn't service this job ATM, so
			 * push this job back onto the list.
			 */
			push(jobs, job);/* 将任务放回队列头部 */
			break;
		}

		count++;/* 任务完成，递增计数并处理下一个任务 */
	}

	return count;
}

/*
 * kcopyd does this every time it's woken up.
 */
/* dm复制线程的主工作函数 */
static void do_work(void *ignored)
{
	/*
	 * The order that these are called is *very* important.
	 * complete jobs can free some pages for pages jobs.
	 * Pages jobs when successful will jump onto the io jobs
	 * list.  io jobs call wake when they complete and it all
	 * starts again.
	 */
	/* 先处理已经完成的任务队列，这样可以释放更多的页面 */
	process_jobs(&_complete_jobs, run_complete_job);
	/* 处理等待分配页面的队列 */
	process_jobs(&_pages_jobs, run_pages_job);
	/* 处理读写队列 */
	process_jobs(&_io_jobs, run_io_job);
}

/*
 * If we are copying a small region we just dispatch a single job
 * to do the copy, otherwise the io has to be split up into many
 * jobs.
 */
static void dispatch_job(struct kcopyd_job *job)
{
	push(&_pages_jobs, job);/* 将任务放到待分配页面队列 */
	wake();/* 唤醒工作队列处理任务 */
}

#define SUB_JOB_SIZE 128
static void segment_complete(int read_err,
			     unsigned int write_err, void *context)
{
	/* FIXME: tidy this function */
	sector_t progress = 0;
	sector_t count = 0;
	struct kcopyd_job *job = (struct kcopyd_job *) context;

	down(&job->lock);

	/* update the error */
	if (read_err)
		job->read_err = 1;

	if (write_err)
		job->write_err &= write_err;

	/*
	 * Only dispatch more work if there hasn't been an error.
	 */
	if ((!job->read_err && !job->write_err) ||
	    test_bit(KCOPYD_IGNORE_ERROR, &job->flags)) {
		/* get the next chunk of work */
		progress = job->progress;
		count = job->source.count - progress;
		if (count) {
			if (count > SUB_JOB_SIZE)
				count = SUB_JOB_SIZE;

			job->progress += count;
		}
	}
	up(&job->lock);

	if (count) {
		int i;
		struct kcopyd_job *sub_job = mempool_alloc(_job_pool, GFP_NOIO);

		*sub_job = *job;
		sub_job->source.sector += progress;
		sub_job->source.count = count;

		for (i = 0; i < job->num_dests; i++) {
			sub_job->dests[i].sector += progress;
			sub_job->dests[i].count = count;
		}

		sub_job->fn = segment_complete;
		sub_job->context = job;
		dispatch_job(sub_job);

	} else if (atomic_dec_and_test(&job->sub_jobs)) {

		/*
		 * To avoid a race we must keep the job around
		 * until after the notify function has completed.
		 * Otherwise the client may try and stop the job
		 * after we've completed.
		 */
		job->fn(read_err, write_err, job->context);
		mempool_free(job, _job_pool);
	}
}

/*
 * Create some little jobs that will do the move between
 * them.
 */
#define SPLIT_COUNT 8
static void split_job(struct kcopyd_job *job)
{
	int i;

	atomic_set(&job->sub_jobs, SPLIT_COUNT);
	for (i = 0; i < SPLIT_COUNT; i++)
		segment_complete(0, 0u, job);
}

/* 向kcopyd提交一个复制任务 */
int kcopyd_copy(struct kcopyd_client *kc, struct io_region *from,
		unsigned int num_dests, struct io_region *dests,
		unsigned int flags, kcopyd_notify_fn fn, void *context)
{
	struct kcopyd_job *job;

	/*
	 * Allocate a new job.
	 */
	job = mempool_alloc(_job_pool, GFP_NOIO);/* 从内存池中分配任务结构 */

	/*
	 * set up for the read.
	 */
	job->kc = kc;/* 构造一个任务 */
	job->flags = flags;
	job->read_err = 0;
	job->write_err = 0;
	job->rw = READ;

	job->source = *from;

	job->num_dests = num_dests;
	memcpy(&job->dests, dests, sizeof(*dests) * num_dests);

	job->offset = 0;
	job->nr_pages = 0;
	job->pages = NULL;

	job->fn = fn;
	job->context = context;

	if (job->source.count < SUB_JOB_SIZE)/* 不必分解为子任务 */
		dispatch_job(job);/* 分发任务 */

	else {/* 需要分解任务 */
		init_MUTEX(&job->lock);
		job->progress = 0;
		split_job(job);
	}

	return 0;
}

/*
 * Cancels a kcopyd job, eg. someone might be deactivating a
 * mirror.
 */
int kcopyd_cancel(struct kcopyd_job *job, int block)
{
	/* FIXME: finish */
	return -1;
}

/*-----------------------------------------------------------------
 * Unit setup
 *---------------------------------------------------------------*/
static DECLARE_MUTEX(_client_lock);
static LIST_HEAD(_clients);

static void client_add(struct kcopyd_client *kc)
{
	down(&_client_lock);
	list_add(&kc->list, &_clients);
	up(&_client_lock);
}

static void client_del(struct kcopyd_client *kc)
{
	down(&_client_lock);
	list_del(&kc->list);
	up(&_client_lock);
}

static DECLARE_MUTEX(kcopyd_init_lock);
static int kcopyd_clients = 0;

static int kcopyd_init(void)
{
	int r;

	down(&kcopyd_init_lock);

	if (kcopyd_clients) {
		/* Already initialized. */
		kcopyd_clients++;
		up(&kcopyd_init_lock);
		return 0;
	}

	r = jobs_init();
	if (r) {
		up(&kcopyd_init_lock);
		return r;
	}

	_kcopyd_wq = create_singlethread_workqueue("kcopyd");
	if (!_kcopyd_wq) {
		jobs_exit();
		up(&kcopyd_init_lock);
		return -ENOMEM;
	}

	kcopyd_clients++;
	INIT_WORK(&_kcopyd_work, do_work, NULL);
	up(&kcopyd_init_lock);
	return 0;
}

static void kcopyd_exit(void)
{
	down(&kcopyd_init_lock);
	kcopyd_clients--;
	if (!kcopyd_clients) {
		jobs_exit();
		destroy_workqueue(_kcopyd_wq);
		_kcopyd_wq = NULL;
	}
	up(&kcopyd_init_lock);
}

/* 分配kcopyd客户端结构 */
int kcopyd_client_create(unsigned int nr_pages, struct kcopyd_client **result)
{
	int r = 0;
	struct kcopyd_client *kc;

	r = kcopyd_init();
	if (r)
		return r;

	kc = kmalloc(sizeof(*kc), GFP_KERNEL);
	if (!kc) {
		kcopyd_exit();
		return -ENOMEM;
	}

	spin_lock_init(&kc->lock);
	kc->pages = NULL;
	kc->nr_pages = kc->nr_free_pages = 0;
	r = client_alloc_pages(kc, nr_pages);
	if (r) {
		kfree(kc);
		kcopyd_exit();
		return r;
	}

	r = dm_io_get(nr_pages);
	if (r) {
		client_free_pages(kc);
		kfree(kc);
		kcopyd_exit();
		return r;
	}

	client_add(kc);
	*result = kc;
	return 0;
}

/* 释放kcopyd客户端结构 */
void kcopyd_client_destroy(struct kcopyd_client *kc)
{
	dm_io_put(kc->nr_pages);
	client_free_pages(kc);
	client_del(kc);
	kfree(kc);
	kcopyd_exit();
}

EXPORT_SYMBOL(kcopyd_client_create);
EXPORT_SYMBOL(kcopyd_client_destroy);
EXPORT_SYMBOL(kcopyd_copy);
EXPORT_SYMBOL(kcopyd_cancel);
