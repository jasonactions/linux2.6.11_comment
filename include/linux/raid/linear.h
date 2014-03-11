#ifndef _LINEAR_H
#define _LINEAR_H

#include <linux/raid/md.h>

/* 线性RAID中每个磁盘的描述符 */
struct dev_info {
	/* 该成员磁盘的通用描述符 */
	mdk_rdev_t	*rdev;
	/* 长度 */
	sector_t	size;
	/* 起始扇区号 */
	sector_t	offset;
};

typedef struct dev_info dev_info_t;

/* 线性RAID的私有数据结构 */
struct linear_private_data
{
	dev_info_t		**hash_table;
	dev_info_t		*smallest;
	int			nr_zones;
	/* 成员磁盘数组 */
	dev_info_t		disks[0];
};


typedef struct linear_private_data linear_conf_t;

#define mddev_to_conf(mddev) ((linear_conf_t *) mddev->private)

#endif
