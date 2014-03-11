/*
 * Copyright (C) 2001-2003 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>

/* 组成条带的设备 */
struct stripe {
	/* 条带所在的底层设备 */
	struct dm_dev *dev;
	/* 条带在底层设备的起始扇区编号 */
	sector_t physical_start;
};

/* 条带映射私有数据结构 */
struct stripe_c {
	/* 组成条带的设备数 */
	uint32_t stripes;

	/* The size of this target / num. stripes */
	/* 组成目标的块设备的有效长度 */
	sector_t stripe_width;

	/* stripe chunk size */
	/* 用于计算条带长度，假设块长度为2^n，则chunk_shift为1<<(n+1)，chunk_mask为0x11...1，即2^n-1 */
	uint32_t chunk_shift;
	sector_t chunk_mask;

	/* 条带数组 */
	struct stripe stripe[0];
};

static inline struct stripe_c *alloc_context(unsigned int stripes)
{
	size_t len;

	if (array_too_big(sizeof(struct stripe_c), sizeof(struct stripe),
			  stripes))
		return NULL;

	len = sizeof(struct stripe_c) + (sizeof(struct stripe) * stripes);

	return kmalloc(len, GFP_KERNEL);
}

/*
 * Parse a single <dev> <sector> pair
 */
static int get_stripe(struct dm_target *ti, struct stripe_c *sc,
		      unsigned int stripe, char **argv)
{
	sector_t start;

	if (sscanf(argv[1], SECTOR_FORMAT, &start) != 1)
		return -EINVAL;

	if (dm_get_device(ti, argv[0], start, sc->stripe_width,
			  dm_table_get_mode(ti->table),
			  &sc->stripe[stripe].dev))
		return -ENXIO;

	sc->stripe[stripe].physical_start = start;
	return 0;
}

/*
 * Construct a striped mapping.
 * <number of stripes> <chunk size (2^^n)> [<dev_path> <offset>]+
 */
/* 条带映射的构造函数 */
static int stripe_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct stripe_c *sc;
	sector_t width;
	uint32_t stripes;
	uint32_t chunk_size;
	char *end;
	int r;
	unsigned int i;

	if (argc < 2) {/* 至少有number_of_stripes和chunk_size两个参数 */
		ti->error = "dm-stripe: Not enough arguments";
		return -EINVAL;
	}

	stripes = simple_strtoul(argv[0], &end, 10);/* 解析条带数量 */
	if (*end) {
		ti->error = "dm-stripe: Invalid stripe count";
		return -EINVAL;
	}

	chunk_size = simple_strtoul(argv[1], &end, 10);/* 解析条带长度 */
	if (*end) {
		ti->error = "dm-stripe: Invalid chunk_size";
		return -EINVAL;
	}

	/*
	 * chunk_size is a power of two
	 */
	if (!chunk_size || (chunk_size & (chunk_size - 1)) ||/* 条带不应当为0，也必须是2的幂，并且不能小于一个页面 */
	    (chunk_size < (PAGE_SIZE >> SECTOR_SHIFT))) {
		ti->error = "dm-stripe: Invalid chunk size";
		return -EINVAL;
	}

	width = ti->len;
	if (sector_div(width, stripes)) {/* 映射目标长度必须能够整除条带数 */
		ti->error = "dm-stripe: Target length not divisable by "
		    "number of stripes";
		return -EINVAL;
	}

	/*
	 * Do we have enough arguments for that many stripes ?
	 */
	if (argc != (2 + 2 * stripes)) {/* 条带数必须与后面的参数数目匹配 */
		ti->error = "dm-stripe: Not enough destinations "
			"specified";
		return -EINVAL;
	}

	sc = alloc_context(stripes);/* 分配条带私有数据结构 */
	if (!sc) {
		ti->error = "dm-stripe: Memory allocation for striped context "
		    "failed";
		return -ENOMEM;
	}

	sc->stripes = stripes;
	sc->stripe_width = width;
	ti->split_io = chunk_size;

	/* 计算chunk_mask和chunk_shift，用于快速计算 */
	sc->chunk_mask = ((sector_t) chunk_size) - 1;
	for (sc->chunk_shift = 0; chunk_size; sc->chunk_shift++)
		chunk_size >>= 1;
	sc->chunk_shift--;

	/*
	 * Get the stripe destinations.
	 */
	for (i = 0; i < stripes; i++) {/* 解析条带设备 */
		argv += 2;

		r = get_stripe(ti, sc, i, argv);
		if (r < 0) {
			ti->error = "dm-stripe: Couldn't parse stripe "
				"destination";
			while (i--)
				dm_put_device(ti, sc->stripe[i].dev);
			kfree(sc);
			return r;
		}
	}

	ti->private = sc;
	return 0;
}

/* 析构函数，释放条带映射私有数据结构并解除对设备的引用 */
static void stripe_dtr(struct dm_target *ti)
{
	unsigned int i;
	struct stripe_c *sc = (struct stripe_c *) ti->private;

	for (i = 0; i < sc->stripes; i++)
		dm_put_device(ti, sc->stripe[i].dev);

	kfree(sc);
}

static int stripe_map(struct dm_target *ti, struct bio *bio,
		      union map_info *map_context)
{
	struct stripe_c *sc = (struct stripe_c *) ti->private;

	/* 计算BIO在目标中偏移 */
	sector_t offset = bio->bi_sector - ti->begin;
	/* 计算条带号 */
	sector_t chunk = offset >> sc->chunk_shift;
	/* 根据条带号计算设备编号 */
	uint32_t stripe = sector_div(chunk, sc->stripes);

	/* 转换设备为条带映射中的设备 */
	bio->bi_bdev = sc->stripe[stripe].dev->bdev;
	/* 转换扇区号 */
	bio->bi_sector = sc->stripe[stripe].physical_start +
	    (chunk << sc->chunk_shift) + (offset & sc->chunk_mask);
	return 1;
}

static int stripe_status(struct dm_target *ti,
			 status_type_t type, char *result, unsigned int maxlen)
{
	struct stripe_c *sc = (struct stripe_c *) ti->private;
	unsigned int sz = 0;
	unsigned int i;
	char buffer[32];

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%d " SECTOR_FORMAT, sc->stripes, sc->chunk_mask + 1);
		for (i = 0; i < sc->stripes; i++) {
			format_dev_t(buffer, sc->stripe[i].dev->bdev->bd_dev);
			DMEMIT(" %s " SECTOR_FORMAT, buffer,
			       sc->stripe[i].physical_start);
		}
		break;
	}
	return 0;
}

static struct target_type stripe_target = {
	.name   = "striped",
	.version= {1, 0, 2},
	.module = THIS_MODULE,
	.ctr    = stripe_ctr,
	.dtr    = stripe_dtr,
	.map    = stripe_map,
	.status = stripe_status,
};

int __init dm_stripe_init(void)
{
	int r;

	r = dm_register_target(&stripe_target);
	if (r < 0)
		DMWARN("striped target registration failed");

	return r;
}

void dm_stripe_exit(void)
{
	if (dm_unregister_target(&stripe_target))
		DMWARN("striped target unregistration failed");

	return;
}
