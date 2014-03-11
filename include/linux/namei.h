#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/linkage.h>

struct vfsmount;

struct open_intent {
	int	flags;
	int	create_mode;
};

enum { MAX_NESTED_LINKS = 5 };

/**
 * 路径查找的结果
 */
struct nameidata {
	/**
	 * 查找到的目录对象。
	 */
	struct dentry	*dentry;
	/**
	 * 已经安装的文件系统对象。
	 */
	struct vfsmount *mnt;
	/**
	 * 路径名的最后一个分量。当指定LOOKUP_PARENT时使用。
	 */
	struct qstr	last;
	/**
	 * 查找标志。
	 */
	unsigned int	flags;
	/**
	 * 路径名最后一个分量的类型。如LAST_NORM
	 */
	int		last_type;
	/**
	 * 符号链接查找的嵌套深度。
	 */
	unsigned	depth;
	/**
	 * 嵌套关联路径名数组。
	 */
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	/**
	 * 指定如何访问文件。
	 */
	union {
		struct open_intent open;
	} intent;
};

/*
 * Type of the last component on LOOKUP_PARENT
 */
/**
 * LAST_NORM:	最后一个分量是普通文件名
 * LAST_ROOT:	最后一个分量是"/"
 * LAST_DOT:	最后一个分量是"."
 * LAST_DOTDOT:	最后一个分量是".."
 * LAST_BIND:	最后一个分量是链接到特殊文件系统的符号链接
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path compnents" flag
 *  - locked when lookup done with dcache_lock held
 */
/**
 * 如果最后一个分量是符号链接，则解释它。
 */
#define LOOKUP_FOLLOW		 1
/**
 * 最后一个分量必须是目录。
 */
#define LOOKUP_DIRECTORY	 2
/**
 * 在路径名中还有文件名要检查。
 */
#define LOOKUP_CONTINUE		 4
/**
 * 查找最后一个分量所在的目录
 */
#define LOOKUP_PARENT		16
/**
 * 不考虑模拟根目录
 */
#define LOOKUP_NOALT		32
/*
 * Intent data
 */
/**
 * 试图打开一个文件
 */
#define LOOKUP_OPEN		(0x0100)
/**
 * 试图创建一个文件
 */
#define LOOKUP_CREATE		(0x0200)
/**
 * 试图为一个文件检查用户的权限。
 */
#define LOOKUP_ACCESS		(0x0400)

extern int FASTCALL(__user_walk(const char __user *, unsigned, struct nameidata *));
#define user_path_walk(name,nd) \
	__user_walk(name, LOOKUP_FOLLOW, nd)
#define user_path_walk_link(name,nd) \
	__user_walk(name, 0, nd)
extern int FASTCALL(path_lookup(const char *, unsigned, struct nameidata *));
extern int FASTCALL(path_walk(const char *, struct nameidata *));
extern int FASTCALL(link_path_walk(const char *, struct nameidata *));
extern void path_release(struct nameidata *);
extern void path_release_on_umount(struct nameidata *);

extern struct dentry * lookup_one_len(const char *, struct dentry *, int);
extern struct dentry * lookup_hash(struct qstr *, struct dentry *);

extern int follow_down(struct vfsmount **, struct dentry **);
extern int follow_up(struct vfsmount **, struct dentry **);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

static inline void nd_set_link(struct nameidata *nd, char *path)
{
	nd->saved_names[nd->depth] = path;
}

static inline char *nd_get_link(struct nameidata *nd)
{
	return nd->saved_names[nd->depth];
}

#endif /* _LINUX_NAMEI_H */
