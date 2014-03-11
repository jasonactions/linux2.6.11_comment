/*
 * dm-snapshot.c
 *
 * Copyright (C) 2001-2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#ifndef DM_SNAPSHOT_H
#define DM_SNAPSHOT_H

#include "dm.h"
#include <linux/blkdev.h>

struct exception_table {
	uint32_t hash_mask;
	struct list_head *table;
};

/*
 * The snapshot code deals with largish chunks of the disk at a
 * time. Typically 64k - 256k.
 */
/* FIXME: can we get away with limiting these to a uint32_t ? */
typedef sector_t chunk_t;

/*
 * An exception is used where an old chunk of data has been
 * replaced by a new one.
 */
/* 例外结构，表示源设备上的数据在快照创建之后进行过修改 */
struct exception {
	/* 链入快照的已经完成链表或待处理链表 */
	struct list_head hash_list;

	/* 旧chunk，即快照源设备上的chunk编号 */
	chunk_t old_chunk;
	/* 新chunk，即快照设备上的chunk编号 */
	chunk_t new_chunk;
};

/*
 * Abstraction to handle the meta/layout of exception stores (the
 * COW device).
 */
/* 例外仓库 */
struct exception_store {

	/*
	 * Destroys this object when you've finished with it.
	 */
	void (*destroy) (struct exception_store *store);

	/*
	 * The target shouldn't read the COW device until this is
	 * called.
	 */
	/* 读取元数据的回调 */
	int (*read_metadata) (struct exception_store *store);

	/*
	 * Find somewhere to store the next exception.
	 */
	/* 准备例外的回调函数 */
	int (*prepare_exception) (struct exception_store *store,
				  struct exception *e);

	/*
	 * Update the metadata with this exception.
	 */
	/* 提交例外的回调函数 */
	void (*commit_exception) (struct exception_store *store,
				  struct exception *e,
				  void (*callback) (void *, int success),
				  void *callback_context);

	/*
	 * The snapshot is invalid, note this in the metadata.
	 */
	/* 快照无效时在元数据中记录 */
	void (*drop_snapshot) (struct exception_store *store);

	/*
	 * Return how full the snapshot is.
	 */
	void (*fraction_full) (struct exception_store *store,
			       sector_t *numerator,
			       sector_t *denominator);

	/* 快照私有数据描述符 */
	struct dm_snapshot *snap;
	/* 例外仓库上下文 */
	void *context;
};

/* 快照映射私有数据结构 */
struct dm_snapshot {
	/* 保护本结构的锁 */
	struct rw_semaphore lock;
	struct dm_table *table;

	/* 快照源设备 */
	struct dm_dev *origin;
	/* COW设备指针 */
	struct dm_dev *cow;

	/* List of snapshots per Origin */
	/* 链入所属快照源的链表 */
	struct list_head list;

	/* Size of data blocks saved - must be a power of 2 */
	chunk_t chunk_size;
	chunk_t chunk_mask;
	chunk_t chunk_shift;

	/* You can't use a snapshot if this is 0 (e.g. if full) */
	/* 如果为0表示快照不可使用，如已经满了 */
	int valid;
	int have_metadata;

	/* Used for display of table */
	char type;

	/* The last percentage we notified */
	int last_percent;

	/* 待处理的例外表 */
	struct exception_table pending;
	/* 已经处理完成的例外表 */
	struct exception_table complete;

	/* The on disk metadata handler */
	/* 快照的例外仓库描述符指针 */
	struct exception_store store;

	/* 为快照进行复制任务的描述符指针 */
	struct kcopyd_client *kcopyd_client;
};

/*
 * Used by the exception stores to load exceptions hen
 * initialising.
 */
int dm_add_exception(struct dm_snapshot *s, chunk_t old, chunk_t new);

/*
 * Constructor and destructor for the default persistent
 * store.
 */
int dm_create_persistent(struct exception_store *store, uint32_t chunk_size);

int dm_create_transient(struct exception_store *store,
			struct dm_snapshot *s, int blocksize);

/*
 * Return the number of sectors in the device.
 */
static inline sector_t get_dev_size(struct block_device *bdev)
{
	return bdev->bd_inode->i_size >> SECTOR_SHIFT;
}

static inline chunk_t sector_to_chunk(struct dm_snapshot *s, sector_t sector)
{
	return (sector & ~s->chunk_mask) >> s->chunk_shift;
}

static inline sector_t chunk_to_sector(struct dm_snapshot *s, chunk_t chunk)
{
	return chunk << s->chunk_shift;
}

static inline int bdev_equal(struct block_device *lhs, struct block_device *rhs)
{
	/*
	 * There is only ever one instance of a particular block
	 * device so we can compare pointers safely.
	 */
	return lhs == rhs;
}

#endif
