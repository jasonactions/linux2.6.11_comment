/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 * Copyright (C) 2004 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the LGPL.
 */

#ifndef _LINUX_DEVICE_MAPPER_H
#define _LINUX_DEVICE_MAPPER_H

struct dm_target;
struct dm_table;
struct dm_dev;

typedef enum { STATUSTYPE_INFO, STATUSTYPE_TABLE } status_type_t;

union map_info {
	void *ptr;
	unsigned long long ll;
};

/*
 * In the constructor the target parameter will already have the
 * table, type, begin and len fields filled in.
 */
typedef int (*dm_ctr_fn) (struct dm_target *target,
			  unsigned int argc, char **argv);

/*
 * The destructor doesn't need to free the dm_target, just
 * anything hidden ti->private.
 */
typedef void (*dm_dtr_fn) (struct dm_target *ti);

/*
 * The map function must return:
 * < 0: error
 * = 0: The target will handle the io by resubmitting it later
 * > 0: simple remap complete
 */
typedef int (*dm_map_fn) (struct dm_target *ti, struct bio *bio,
			  union map_info *map_context);

/*
 * Returns:
 * < 0 : error (currently ignored)
 * 0   : ended successfully
 * 1   : for some reason the io has still not completed (eg,
 *       multipath target might want to requeue a failed io).
 */
typedef int (*dm_endio_fn) (struct dm_target *ti,
			    struct bio *bio, int error,
			    union map_info *map_context);

typedef void (*dm_presuspend_fn) (struct dm_target *ti);
typedef void (*dm_postsuspend_fn) (struct dm_target *ti);
typedef void (*dm_resume_fn) (struct dm_target *ti);

typedef int (*dm_status_fn) (struct dm_target *ti, status_type_t status_type,
			     char *result, unsigned int maxlen);

typedef int (*dm_message_fn) (struct dm_target *ti, unsigned argc, char **argv);

void dm_error(const char *message);

/*
 * Constructors should call these functions to ensure destination devices
 * are opened/closed correctly.
 * FIXME: too many arguments.
 */
int dm_get_device(struct dm_target *ti, const char *path, sector_t start,
		  sector_t len, int mode, struct dm_dev **result);
void dm_put_device(struct dm_target *ti, struct dm_dev *d);

/*
 * Information about a target type
 */
/* 映射目标类型 */
struct target_type {
	/* 映射类型名称，如线性、条带、致错、镜像、快照等等 */
	const char *name;
	/* 实现模块 */
	struct module *module;
	/* 版本号 */
        unsigned version[3];
	/* 构造、析构回调函数 */
	dm_ctr_fn ctr;
	dm_dtr_fn dtr;
	/* 映射回调函数 */
	dm_map_fn map;
	/* 完成回调函数 */
	dm_endio_fn end_io;
	/* 挂起前的回调函数 */
	dm_presuspend_fn presuspend;
	/* 挂起后的回调函数 */
	dm_postsuspend_fn postsuspend;
	/* 恢复时的回调函数 */
	dm_resume_fn resume;
	/* 状态报告回调函数 */
	dm_status_fn status;
	/* 用于向该类型映射目标传递消息的回调函数 */
	dm_message_fn message;
};

struct io_restrictions {
	unsigned short		max_sectors;
	unsigned short		max_phys_segments;
	unsigned short		max_hw_segments;
	unsigned short		hardsect_size;
	unsigned int		max_segment_size;
	unsigned long		seg_boundary_mask;
};

/* 映射目标描述符 */
struct dm_target {
	/* 所属映射表 */
	struct dm_table *table;
	/* 映射目标类型，如linear、striped、error等等 */
	struct target_type *type;

	/* target limits */
	/* 这个目标在映射设备上的起始扇区 */
	sector_t begin;
	/* 这个目标在映射设备上的长度 */
	sector_t len;

	/* FIXME: turn this into a mask, and merge with io_restrictions */
	/* Always a power of 2 */
	/* 映射到这个目标的IO必须再按照这个扇区数细分为更小的IO下发执行，必须为2的幂 */
	sector_t split_io;

	/*
	 * These are automatically filled in by
	 * dm_table_get_device.
	 */
	struct io_restrictions limits;

	/* target specific data */
	/* 私有信息，根据映射类型不同而不同 */
	void *private;

	/* Used to provide an error string from the ctr */
	/* 映射表构造过程中的错误字符串 */
	char *error;
};

int dm_register_target(struct target_type *t);
int dm_unregister_target(struct target_type *t);

#endif				/* _LINUX_DEVICE_MAPPER_H */
