/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: mount.h,v 2.0 1996/11/17 16:48:14 mvw Exp mvw $
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H
#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

/**
 * 在已经安装文件系统中禁止setuid和setgid标志。
 */
#define MNT_NOSUID	1
/**
 * 在已经安装文件系统中禁止访问设备文件
 */
#define MNT_NODEV	2
/**
 * 在已经安装文件系统中不允许程序执行。
 */
#define MNT_NOEXEC	4

/**
 * 文件系统安装点
 */
struct vfsmount
{
	/**
	 * 用于散列表链表的指针。
	 */
	struct list_head mnt_hash;
	/**
	 * 指向父文件系统，这个文件系统安装在其上。
	 */
	struct vfsmount *mnt_parent;	/* fs we are mounted on */
	/**
	 * 安装点目录节点。
	 */
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */
	/**
	 * 指向这个文件系统根目录的dentry。
	 */
	struct dentry *mnt_root;	/* root of the mounted tree */
	/**
	 * 该文件系统的超级块对象。
	 */
	struct super_block *mnt_sb;	/* pointer to superblock */
	/**
	 * 包含所有文件系统描述符链表的头
	 */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	/**
	 * 已安装文件系统链表头。通过此字段将其加入父文件系统的mnt_mounts链表中。
	 */
	struct list_head mnt_child;	/* and going through their mnt_child */
	/**
	 * 引用计数器，禁止文件系统被卸载。
	 */
	atomic_t mnt_count;
	/**
	 * mount标志
	 */
	int mnt_flags;
	/**
	 * 如果文件系统标记为过期，就设置这个标志。
	 */
	int mnt_expiry_mark;		/* true if marked for expiry */
	/**
	 * 设备文件名。
	 */
	char *mnt_devname;		/* Name of device e.g. /dev/dsk/hda1 */
	/**
	 * 已安装文件系统描述符的namespace链表指针?
	 * 通过此字段将其加入到namespace的list链表中。
	 */
	struct list_head mnt_list;
	/**
	 * 文件系统到期链表指针。
	 */
	struct list_head mnt_fslink;	/* link in fs-specific expiry list */
	/**
	 * 进程命名空间指针
	 */
	struct namespace *mnt_namespace; /* containing namespace */
};

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

extern void __mntput(struct vfsmount *mnt);

static inline void _mntput(struct vfsmount *mnt)
{
	if (mnt) {
		if (atomic_dec_and_test(&mnt->mnt_count))
			__mntput(mnt);
	}
}

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		_mntput(mnt);
	}
}

extern void free_vfsmnt(struct vfsmount *mnt);
extern struct vfsmount *alloc_vfsmnt(const char *name);
extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct nameidata;

extern int do_add_mount(struct vfsmount *newmnt, struct nameidata *nd,
			int mnt_flags, struct list_head *fslist);

extern void mark_mounts_for_expiry(struct list_head *mounts);

/**
 * 保护已经安装文件系统的链表。
 */
extern spinlock_t vfsmount_lock;

#endif
#endif /* _LINUX_MOUNT_H */
