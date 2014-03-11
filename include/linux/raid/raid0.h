#ifndef _RAID0_H
#define _RAID0_H

#include <linux/raid/md.h>

/* RAID0中的条带区域描述符 */
struct strip_zone
{
	/* 当前条带的起始编号，以扇区为单位 */
	sector_t zone_offset;	/* Zone offset in md_dev */
	/* 该条带在真实磁盘上的起始位置 */
	sector_t dev_offset;	/* Zone offset in real dev */
	/* 条带长度 */
	sector_t size;		/* Zone size */
	/* 该条带包含的磁盘个数 */
	int nb_dev;		/* # of devices attached to the zone */
	/* 该条带包含的所有设备 */
	mdk_rdev_t **dev;	/* Devices attached to the zone */
};

/* RAID0私有数据结构描述符 */
struct raid0_private_data
{
	struct strip_zone **hash_table; /* Table of indexes into strip_zone */
	/* 条带区域数组 */
	struct strip_zone *strip_zone;
	/* 成员磁盘数组 */
	mdk_rdev_t **devlist; /* lists of rdevs, pointed to by strip_zone->dev */
	/* 条带区域数目 */
	int nr_strip_zones;

	sector_t hash_spacing;
	int preshift;			/* shift this before divide by hash_spacing */
};

typedef struct raid0_private_data raid0_conf_t;

#define mddev_to_conf(mddev) ((raid0_conf_t *) mddev->private)

#endif
