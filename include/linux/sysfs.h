/*
 * sysfs.h - definitions for the device driver filesystem
 *
 * Copyright (c) 2001,2002 Patrick Mochel
 * Copyright (c) 2004 Silicon Graphics, Inc.
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#ifndef _SYSFS_H_
#define _SYSFS_H_

#include <asm/atomic.h>

struct kobject;
struct module;

/**
 * kobject属性的属性。
 */
struct attribute {
	/**
	 * 属性名称。
	 */
	char			* name;
	/**
	 * 属性所属模块。该模块实现这个属性。
	 */
	struct module 		* owner;
	/**
	 * 属性保护位。S_IRUGO表示只读属性。S_IWUSR仅仅为root提供写权限。
	 */
	mode_t			mode;
};

struct attribute_group {
	char			* name;
	struct attribute	** attrs;
};



/**
 * Use these macros to make defining attributes easier. See include/linux/device.h
 * for examples..
 */

#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE },	\
	.show	= _show,					\
	.store	= _store,					\
}

#define __ATTR_RO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0444, .owner = THIS_MODULE },	\
	.show	= _name##_show,	\
}

#define __ATTR_NULL { .attr = { .name = NULL } }

#define attr_name(_attr) (_attr).attr.name

struct vm_area_struct;

/**
 * 二进制属性。不能作为默认属性被创建。
 */
struct bin_attribute {
	/**
	 * 属性的名字、所有者、二进制属性的权限。
	 */
	struct attribute	attr;
	/**
	 * 二进制属性的最大长度。如果没有最大长度，则size为0.
	 */
	size_t			size;
	void			*private;
	/**
	 * 相当于sysfs_ops中的show和store方法。在一次加载过程中可能被调用多次。每次能够操作的最大数量是一页。
	 */
	ssize_t (*read)(struct kobject *, char *, loff_t, size_t);
	ssize_t (*write)(struct kobject *, char *, loff_t, size_t);
	int (*mmap)(struct kobject *, struct bin_attribute *attr,
		    struct vm_area_struct *vma);
};

/**
 * 实现kobject属性的方法。
 */
struct sysfs_ops {
	/**
	 * 当用户空间读取一个属性时，调用此方法。注意缓冲区长度为PAGE_SIZE个字节。
	 * 如果要返回大量的信息，则需要把它拆分成多个属性。
	 */
	ssize_t	(*show)(struct kobject *, struct attribute *,char *);
	/**
	 * 当用户空间要写一个属性时，调用此方法。需要注意处理输入的合法性。
	 */
	ssize_t	(*store)(struct kobject *,struct attribute *,const char *, size_t);
};

struct sysfs_dirent {
	atomic_t		s_count;
	struct list_head	s_sibling;
	struct list_head	s_children;
	void 			* s_element;
	int			s_type;
	umode_t			s_mode;
	struct dentry		* s_dentry;
};

#define SYSFS_ROOT		0x0001
#define SYSFS_DIR		0x0002
#define SYSFS_KOBJ_ATTR 	0x0004
#define SYSFS_KOBJ_BIN_ATTR	0x0008
#define SYSFS_KOBJ_LINK 	0x0020
#define SYSFS_NOT_PINNED	(SYSFS_KOBJ_ATTR | SYSFS_KOBJ_BIN_ATTR | SYSFS_KOBJ_LINK)

#ifdef CONFIG_SYSFS

extern int
sysfs_create_dir(struct kobject *);

extern void
sysfs_remove_dir(struct kobject *);

extern int
sysfs_rename_dir(struct kobject *, const char *new_name);

extern int
sysfs_create_file(struct kobject *, const struct attribute *);

extern int
sysfs_update_file(struct kobject *, const struct attribute *);

extern void
sysfs_remove_file(struct kobject *, const struct attribute *);

extern int 
sysfs_create_link(struct kobject * kobj, struct kobject * target, char * name);

extern void
sysfs_remove_link(struct kobject *, char * name);

int sysfs_create_bin_file(struct kobject * kobj, struct bin_attribute * attr);
int sysfs_remove_bin_file(struct kobject * kobj, struct bin_attribute * attr);

int sysfs_create_group(struct kobject *, const struct attribute_group *);
void sysfs_remove_group(struct kobject *, const struct attribute_group *);

#else /* CONFIG_SYSFS */

static inline int sysfs_create_dir(struct kobject * k)
{
	return 0;
}

static inline void sysfs_remove_dir(struct kobject * k)
{
	;
}

static inline int sysfs_rename_dir(struct kobject * k, const char *new_name)
{
	return 0;
}

static inline int sysfs_create_file(struct kobject * k, const struct attribute * a)
{
	return 0;
}

static inline int sysfs_update_file(struct kobject * k, const struct attribute * a)
{
	return 0;
}

static inline void sysfs_remove_file(struct kobject * k, const struct attribute * a)
{
	;
}

static inline int sysfs_create_link(struct kobject * k, struct kobject * t, char * n)
{
	return 0;
}

static inline void sysfs_remove_link(struct kobject * k, char * name)
{
	;
}


static inline int sysfs_create_bin_file(struct kobject * k, struct bin_attribute * a)
{
	return 0;
}

static inline int sysfs_remove_bin_file(struct kobject * k, struct bin_attribute * a)
{
	return 0;
}

static inline int sysfs_create_group(struct kobject * k, const struct attribute_group *g)
{
	return 0;
}

static inline void sysfs_remove_group(struct kobject * k, const struct attribute_group * g)
{
	;
}

#endif /* CONFIG_SYSFS */

#endif /* _SYSFS_H_ */
