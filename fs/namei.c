/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

/* [Feb 1997 T. Schoebel-Theuer] Complete rewrite of the pathname
 * lookup logic.
 */
/* [Feb-Apr 2000, AV] Rewrite to the new namespace architecture.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/pagemap.h>
#include <linux/dnotify.h>
#include <linux/smp_lock.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <asm/namei.h>
#include <asm/uaccess.h>

#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

/* [Feb-1997 T. Schoebel-Theuer]
 * Fundamental changes in the pathname lookup mechanisms (namei)
 * were necessary because of omirr.  The reason is that omirr needs
 * to know the _real_ pathname, not the user-supplied one, in case
 * of symlinks (and also when transname replacements occur).
 *
 * The new code replaces the old recursive symlink resolution with
 * an iterative one (in case of non-nested symlink chains).  It does
 * this with calls to <fs>_follow_link().
 * As a side effect, dir_namei(), _namei() and follow_link() are now 
 * replaced with a single function lookup_dentry() that can handle all 
 * the special cases of the former code.
 *
 * With the new dcache, the pathname is stored at each inode, at least as
 * long as the refcount of the inode is positive.  As a side effect, the
 * size of the dcache depends on the inode cache and thus is dynamic.
 *
 * [29-Apr-1998 C. Scott Ananian] Updated above description of symlink
 * resolution to correspond with current state of the code.
 *
 * Note that the symlink resolution is not *completely* iterative.
 * There is still a significant amount of tail- and mid- recursion in
 * the algorithm.  Also, note that <fs>_readlink() is not used in
 * lookup_dentry(): lookup_dentry() on the result of <fs>_readlink()
 * may return different results than <fs>_follow_link().  Many virtual
 * filesystems (including /proc) exhibit this behavior.
 */

/* [24-Feb-97 T. Schoebel-Theuer] Side effects caused by new implementation:
 * New symlink semantics: when open() is called with flags O_CREAT | O_EXCL
 * and the name already exists in form of a symlink, try to create the new
 * name indicated by the symlink. The old code always complained that the
 * name already exists, due to not following the symlink even if its target
 * is nonexistent.  The new semantics affects also mknod() and link() when
 * the name is a symlink pointing to a non-existant name.
 *
 * I don't know which semantics is the right one, since I have no access
 * to standards. But I found by trial that HP-UX 9.0 has the full "new"
 * semantics implemented, while SunOS 4.1.1 and Solaris (SunOS 5.4) have the
 * "old" one. Personally, I think the new semantics is much more logical.
 * Note that "ln old new" where "new" is a symlink pointing to a non-existing
 * file does succeed in both HP-UX and SunOs, but not in Solaris
 * and in the old Linux semantics.
 */

/* [16-Dec-97 Kevin Buhr] For security reasons, we change some symlink
 * semantics.  See the comments in "open_namei" and "do_link" below.
 *
 * [10-Sep-98 Alan Modra] Another symlink change.
 */

/* [Feb-Apr 2000 AV] Complete rewrite. Rules for symlinks:
 *	inside the path - always follow.
 *	in the last component in creation/removal/renaming - never follow.
 *	if LOOKUP_FOLLOW passed - follow.
 *	if the pathname has trailing slashes - follow.
 *	otherwise - don't follow.
 * (applied in that order).
 *
 * [Jun 2000 AV] Inconsistent behaviour of open() in case if flags==O_CREAT
 * restored for 2.4. This is the last surviving part of old 4.2BSD bug.
 * During the 2.4 we need to fix the userland stuff depending on it -
 * hopefully we will be able to get rid of that wart in 2.5. So far only
 * XEmacs seems to be relying on it...
 */
/*
 * [Sep 2001 AV] Single-semaphore locking scheme (kudos to David Holland)
 * implemented.  Let's see if raised priority of ->s_vfs_rename_sem gives
 * any extra contention...
 */

/* In order to reduce some races, while at the same time doing additional
 * checking and hopefully speeding things up, we copy filenames to the
 * kernel data space before using them..
 *
 * POSIX.1 2.4: an empty pathname is invalid (ENOENT).
 * PATH_MAX includes the nul terminator --RR.
 */
static inline int do_getname(const char __user *filename, char *page)
{
	int retval;
	unsigned long len = PATH_MAX;

	if (!segment_eq(get_fs(), KERNEL_DS)) {
		if ((unsigned long) filename >= TASK_SIZE)
			return -EFAULT;
		if (TASK_SIZE - (unsigned long) filename < PATH_MAX)
			len = TASK_SIZE - (unsigned long) filename;
	}

	retval = strncpy_from_user(page, filename, len);
	if (retval > 0) {
		if (retval < len)
			return 0;
		return -ENAMETOOLONG;
	} else if (!retval)
		retval = -ENOENT;
	return retval;
}

char * getname(const char __user * filename)
{
	char *tmp, *result;

	result = ERR_PTR(-ENOMEM);
	tmp = __getname();
	if (tmp)  {
		int retval = do_getname(filename, tmp);

		result = tmp;
		if (retval < 0) {
			__putname(tmp);
			result = ERR_PTR(retval);
		}
	}
	if (unlikely(current->audit_context) && !IS_ERR(result) && result)
		audit_getname(result);
	return result;
}

/**
 * generic_permission  -  check for access rights on a Posix-like filesystem
 * @inode:	inode to check access rights for
 * @mask:	right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 * @check_acl:	optional callback to check for Posix ACLs
 *
 * Used to check for read/write/execute permissions on a file.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things..
 */
int generic_permission(struct inode *inode, int mask,
		int (*check_acl)(struct inode *inode, int mask))
{
	umode_t			mode = inode->i_mode;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG) && check_acl) {
			int error = check_acl(inode, mask);
			if (error == -EACCES)
				goto check_capabilities;
			else if (error != -EAGAIN)
				return error;
		}

		if (in_group_p(inode->i_gid))
			mode >>= 3;
	}

	/*
	 * If the DACs are ok we don't need any capability check.
	 */
	if (((mode & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask))
		return 0;

 check_capabilities:
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable if at least one exec bit is set.
	 */
	if (!(mask & MAY_EXEC) ||
	    (inode->i_mode & S_IXUGO) || S_ISDIR(inode->i_mode))
		if (capable(CAP_DAC_OVERRIDE))
			return 0;

	/*
	 * Searching includes executable on directories, else just read.
	 */
	if (mask == MAY_READ || (S_ISDIR(inode->i_mode) && !(mask & MAY_WRITE)))
		if (capable(CAP_DAC_READ_SEARCH))
			return 0;

	return -EACCES;
}

int permission(struct inode *inode, int mask, struct nameidata *nd)
{
	int retval, submask;

	if (mask & MAY_WRITE) {
		umode_t mode = inode->i_mode;

		/*
		 * Nobody gets write access to a read-only fs.
		 */
		if (IS_RDONLY(inode) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;

		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EACCES;
	}


	/* Ordinary permission routines do not understand MAY_APPEND. */
	submask = mask & ~MAY_APPEND;
	if (inode->i_op && inode->i_op->permission)
		retval = inode->i_op->permission(inode, submask, nd);
	else
		retval = generic_permission(inode, submask, NULL);
	if (retval)
		return retval;

	return security_inode_permission(inode, mask, nd);
}

/*
 * get_write_access() gets write permission for a file.
 * put_write_access() releases this write permission.
 * This is used for regular files.
 * We cannot support write (and maybe mmap read-write shared) accesses and
 * MAP_DENYWRITE mmappings simultaneously. The i_writecount field of an inode
 * can have the following values:
 * 0: no writers, no VM_DENYWRITE mappings
 * < 0: (-i_writecount) vm_area_structs with VM_DENYWRITE set exist
 * > 0: (i_writecount) users are writing to the file.
 *
 * Normally we operate on that counter with atomic_{inc,dec} and it's safe
 * except for the cases where we don't hold i_writecount yet. Then we need to
 * use {get,deny}_write_access() - these functions check the sign and refuse
 * to do the change if sign is wrong. Exclusion between them is provided by
 * the inode->i_lock spinlock.
 */

int get_write_access(struct inode * inode)
{
	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) < 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	atomic_inc(&inode->i_writecount);
	spin_unlock(&inode->i_lock);

	return 0;
}

int deny_write_access(struct file * file)
{
	struct inode *inode = file->f_dentry->d_inode;

	spin_lock(&inode->i_lock);
	/**
	 * deny_write_access通过检查索引结点的i_writecount字段，
	 * 确定可执行文件没有被写入。
	 */
	if (atomic_read(&inode->i_writecount) > 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	/**
	 * 并把-1存放在这个字段以禁止进一步的写访问
	 */
	atomic_dec(&inode->i_writecount);
	spin_unlock(&inode->i_lock);

	return 0;
}

void path_release(struct nameidata *nd)
{
	dput(nd->dentry);
	mntput(nd->mnt);
}

/*
 * umount() mustn't call path_release()/mntput() as that would clear
 * mnt_expiry_mark
 */
void path_release_on_umount(struct nameidata *nd)
{
	dput(nd->dentry);
	_mntput(nd->mnt);
}

/*
 * Internal lookup() using the new generic dcache.
 * SMP-safe
 */
static struct dentry * cached_lookup(struct dentry * parent, struct qstr * name, struct nameidata *nd)
{
	struct dentry * dentry = __d_lookup(parent, name);

	/* lockess __d_lookup may fail due to concurrent d_move() 
	 * in some unrelated directory, so try with d_lookup
	 */
	if (!dentry)
		dentry = d_lookup(parent, name);

	if (dentry && dentry->d_op && dentry->d_op->d_revalidate) {
		if (!dentry->d_op->d_revalidate(dentry, nd) && !d_invalidate(dentry)) {
			dput(dentry);
			dentry = NULL;
		}
	}
	return dentry;
}

/*
 * Short-cut version of permission(), for calling by
 * path_walk(), when dcache lock is held.  Combines parts
 * of permission() and generic_permission(), and tests ONLY for
 * MAY_EXEC permission.
 *
 * If appropriate, check DAC only.  If not appropriate, or
 * short-cut DAC fails, then call permission() to do more
 * complete permission check.
 */
/**
 * 检查存放在索引结点i_node字段的访问模式和运行进程的特权。
 */
static inline int exec_permission_lite(struct inode *inode,
				       struct nameidata *nd)
{
	umode_t	mode = inode->i_mode;

	if (inode->i_op && inode->i_op->permission)
		return -EAGAIN;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else if (in_group_p(inode->i_gid))
		mode >>= 3;

	if (mode & MAY_EXEC)
		goto ok;

	if ((inode->i_mode & S_IXUGO) && capable(CAP_DAC_OVERRIDE))
		goto ok;

	if (S_ISDIR(inode->i_mode) && capable(CAP_DAC_OVERRIDE))
		goto ok;

	if (S_ISDIR(inode->i_mode) && capable(CAP_DAC_READ_SEARCH))
		goto ok;

	return -EACCES;
ok:
	return security_inode_permission(inode, MAY_EXEC, nd);
}

/*
 * This is called when everything else fails, and we actually have
 * to go to the low-level filesystem to find out what we should do..
 *
 * We get the directory semaphore, and after getting that we also
 * make sure that nobody added the entry to the dcache in the meantime..
 * SMP-safe
 */
/**
 * 从磁盘中读取目录项，并搜索特定名称的目录项
 */
static struct dentry * real_lookup(struct dentry * parent, struct qstr * name, struct nameidata *nd)
{
	struct dentry * result;
	struct inode *dir = parent->d_inode;

	/* 获取目录项的锁 */
	down(&dir->i_sem);
	/*
	 * First re-do the cached lookup just in case it was created
	 * while we waited for the directory semaphore..
	 *
	 * FIXME! This could use version numbering or similar to
	 * avoid unnecessary cache lookups.
	 *
	 * The "dcache_lock" is purely to protect the RCU list walker
	 * from concurrent renames at this point (we mustn't get false
	 * negatives from the RCU list walk here, unlike the optimistic
	 * fast walk).
	 *
	 * so doing d_lookup() (with seqlock), instead of lockfree __d_lookup
	 */
	/* 在获取锁的过程中，目录项可能已经被读到缓存中，再次从目录项缓存中搜索 */
	result = d_lookup(parent, name);
	if (!result) {/* 目录项缓存中仍然不存在 */
		/* 分配并初始化目录项缓存 */
		struct dentry * dentry = d_alloc(parent, name);
		result = ERR_PTR(-ENOMEM);
		if (dentry) {
			/* 从磁盘中读取目录项缓存 */
			result = dir->i_op->lookup(dir, dentry, nd);
			if (result)
				dput(dentry);
			else
				result = dentry;
		}
		up(&dir->i_sem);/* 释放锁并返回 */
		return result;
	}

	/*
	 * Uhhuh! Nasty case: the cache was re-populated while
	 * we waited on the semaphore. Need to revalidate.
	 */
	/* 缓存中已经存在目录项了，释放锁 */
	up(&dir->i_sem);
	/* 文件系统要求对目录进行校验 */
	if (result->d_op && result->d_op->d_revalidate) {
		/* 如果校验不成功，说明目录项已经失效，返回失败 */
		if (!result->d_op->d_revalidate(result, nd) && !d_invalidate(result)) {
			dput(result);
			result = ERR_PTR(-ENOENT);
		}
	}
	return result;
}

static int __emul_lookup_dentry(const char *, struct nameidata *);

/* SMP-safe */
static inline int
walk_init_root(const char *name, struct nameidata *nd)
{
	read_lock(&current->fs->lock);
	if (current->fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
		nd->mnt = mntget(current->fs->altrootmnt);
		nd->dentry = dget(current->fs->altroot);
		read_unlock(&current->fs->lock);
		if (__emul_lookup_dentry(name,nd))
			return 0;
		read_lock(&current->fs->lock);
	}
	nd->mnt = mntget(current->fs->rootmnt);
	nd->dentry = dget(current->fs->root);
	read_unlock(&current->fs->lock);
	return 1;
}

static inline int __vfs_follow_link(struct nameidata *nd, const char *link)
{
	int res = 0;
	char *name;
	if (IS_ERR(link))
		goto fail;

	/**
	 * 检查符号链接是否以'/'开头
	 */
	if (*link == '/') {
		/**
		 * 是以'/'开头，已经找到一个绝对路径了，因此没有必要保留前一个路径的任何信息。
		 * path_release就会释放前一个查找步骤产生的对象，nameidata数据结构中的路径信息被清空了
		 * 一切从头开始。
		 */
		path_release(nd);
		/**
		 * 设置nameidata的dentry和mnt字段，以使它们指向当前进程的根目录
		 * walk_init_root就做这个事情。
		 */
		if (!walk_init_root(link, nd))
			/* weird __emul_prefix() stuff did it */
			goto out;
	}
	/**
	 * link_path_walk解析符号链的路径名,并返回res
	 */
	res = link_path_walk(link, nd);
out:
	if (nd->depth || res || nd->last_type!=LAST_NORM)
		return res;
	/*
	 * If it is an iterative symlinks resolution in open_namei() we
	 * have to copy the last component. And all that crap because of
	 * bloody create() on broken symlinks. Furrfu...
	 */
	name = __getname();
	if (unlikely(!name)) {
		path_release(nd);
		return -ENOMEM;
	}
	strcpy(name, nd->last.name);
	nd->last.name = name;
	return 0;
fail:
	path_release(nd);
	return PTR_ERR(link);
}

/**
 * 符号链接查找
 */
static inline int __do_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int error;

	/**
	 * 更新索引结点的访问时间。
	 */
	touch_atime(nd->mnt, dentry);
	nd_set_link(nd, NULL);
	/**
	 * 调用文件系统相关的函数实现的follow_link方法。
	 * 它读取存放在符号链接索引结点中的路径名，并把这个路径名保存在nd->save_names数组的项中
	 */
	error = dentry->d_inode->i_op->follow_link(dentry, nd);
	if (!error) {
		/* nd_get_link获得follow_link读取的字符串 */
		char *s = nd_get_link(nd);
		if (s)
		 	/**
		 	 * 如果符号链接的第一个字符是"/"，则在内存中不用保存前一个路径的信息。并将结果指向当前进程的根目录。
		 	 * 否则调用link_path_walk解析路径名。
		 	 */
			error = __vfs_follow_link(nd, s);
		/**
		 * 如果有put_link方法，就执行它，释放由follow_link方法分配的临时数据结构。
		 */
		if (dentry->d_inode->i_op->put_link)
			dentry->d_inode->i_op->put_link(dentry, nd);
	}

	return error;
}

/*
 * This limits recursive symlink follows to 8, while
 * limiting consecutive symlinks to 40.
 *
 * Without that kind of total limit, nasty chains of consecutive
 * symlinks can cause almost arbitrarily long lookups. 
 */
/**
 * 被link_path_walk调用。link_path_walk用于查找符号链接
 * dentry是符号链接的地址。nd是nameidata结构的址址。
 */
static inline int do_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int err = -ELOOP;
	/**
	 * 由于符号链接可能嵌套，如果不判断一下，可能在此形成递归调用。死循环。
	 */
	if (current->link_count >= MAX_NESTED_LINKS)
		goto loop;
	if (current->total_link_count >= 40)
		goto loop;
	BUG_ON(nd->depth >= MAX_NESTED_LINKS);
	/**
	 * 判断一下抢占
	 */
	cond_resched();
	err = security_inode_follow_link(dentry, nd);
	if (err)
		goto loop;
	/**
	 * 计数，请参见前面的注释。
	 */
	current->link_count++;
	current->total_link_count++;
	nd->depth++;
	/**
	 * __do_follow_link是一个递归调用，
	 */
	err = __do_follow_link(dentry, nd);
	/**
	 * link_count是__do_follow_link嵌套次数，调用完后减回来。
	 */
	current->link_count--;
	/**
	 * 本次查找的递归次数。
	 */
	nd->depth--;
	return err;
loop:
	path_release(nd);
	return err;
}

int follow_up(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *parent;
	struct dentry *mountpoint;
	spin_lock(&vfsmount_lock);
	parent=(*mnt)->mnt_parent;
	if (parent == *mnt) {
		spin_unlock(&vfsmount_lock);
		return 0;
	}
	mntget(parent);
	mountpoint=dget((*mnt)->mnt_mountpoint);
	spin_unlock(&vfsmount_lock);
	dput(*dentry);
	*dentry = mountpoint;
	mntput(*mnt);
	*mnt = parent;
	return 1;
}

/* no need for dcache_lock, as serialization is taken care in
 * namespace.c
 */
/* 找到挂载点 */
static int follow_mount(struct vfsmount **mnt, struct dentry **dentry)
{
	int res = 0;
	/* 直到当前路径不再是一个挂载点后再退出 */
	while (d_mountpoint(*dentry)) {
		/* 在哈希表中查找当前路径的文件系统装载实例 */
		struct vfsmount *mounted = lookup_mnt(*mnt, *dentry);
		if (!mounted)/* 未加载文件系统，退出 */
			break;
		/* 将文件系统的根目录作为当前路径，继续查找 */
		mntput(*mnt);
		*mnt = mounted;
		dput(*dentry);
		*dentry = dget(mounted->mnt_root);
		res = 1;
	}
	return res;
}

/* no need for dcache_lock, as serialization is taken care in
 * namespace.c
 */
static inline int __follow_down(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(*mnt, *dentry);
	if (mounted) {
		mntput(*mnt);
		*mnt = mounted;
		dput(*dentry);
		*dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}

int follow_down(struct vfsmount **mnt, struct dentry **dentry)
{
	return __follow_down(mnt,dentry);
}
 
/* 在搜索路径时，处理".."返回到上级路径 */
static inline void follow_dotdot(struct vfsmount **mnt, struct dentry **dentry)
{
	while(1) {
		struct vfsmount *parent;
		struct dentry *old = *dentry;

                read_lock(&current->fs->lock);
		if (*dentry == current->fs->root &&/* 已经到达当前进程的根目录，退出 */
		    *mnt == current->fs->rootmnt) {
                        read_unlock(&current->fs->lock);
			break;
		}
                read_unlock(&current->fs->lock);
		spin_lock(&dcache_lock);
		/* 当前目录还不是所在目录的根目录 */
		if (*dentry != (*mnt)->mnt_root) {
			/* 返回到上一级目录 */
			*dentry = dget((*dentry)->d_parent);
			spin_unlock(&dcache_lock);
			dput(old);
			break;
		}
		spin_unlock(&dcache_lock);
		/* 运行到这里，说明到达所在文件系统的根目录 */
		spin_lock(&vfsmount_lock);
		/* 转到挂载文件系统的上级目录 */
		parent = (*mnt)->mnt_parent;
		if (parent == *mnt) {/* 上级挂载目录已经是根目录了 */
			spin_unlock(&vfsmount_lock);
			break;
		}
		mntget(parent);
		/* 目录项变为当前文件系统的挂载点 */
		*dentry = dget((*mnt)->mnt_mountpoint);
		spin_unlock(&vfsmount_lock);
		dput(old);
		mntput(*mnt);
		*mnt = parent;
	}
	/* 最后找到的目录可能是一个挂载点，调用follow_mount跟踪到最后一次挂载的目录点 */
	follow_mount(mnt, dentry);
}

/* 内核中表示的路径 */
struct path {
	/* 文件系统中装载对象 */
	struct vfsmount *mnt;
	/* 目录项列表 */
	struct dentry *dentry;
};

/*
 *  It's more convoluted than I'd like it to be, but... it's still fairly
 *  small and for now I'd prefer to have fast path as straight as possible.
 *  It _is_ time-critical.
 */
/**
 * 得到与给定的父目录和文件名相关的目录项对象.
 */
static int do_lookup(struct nameidata *nd, struct qstr *name,
		     struct path *path)
{
	struct vfsmount *mnt = nd->mnt;
	/**
	 * __d_lookup在目录项高速缓存中搜索分量的目录项对象.
	 */
	struct dentry *dentry = __d_lookup(nd->dentry, name);

	/* 在目录项缓存中没有找到，则需要从磁盘上读取目录项后查找 */
	if (!dentry)
		goto need_lookup;
	/* 在目录项缓存中搜索到目录项，但是文件系统要求对缓存中的目录项进行校验 */
	if (dentry->d_op && dentry->d_op->d_revalidate)
		goto need_revalidate;
done:
	path->mnt = mnt;
	path->dentry = dentry;
	return 0;

need_lookup:
	/**
	 * 没有在目录项高速缓存中找到目录项对象,就调用real_lookup
	 * real_lookup执行索引节点的lookup方法从磁盘读取目录,创建一个新的目录项对象并把它插入到目录项高速缓存中.
	 * 然后创建一个新的索引节点,并将它插入到索引节点高速缓存中.
	 */
	dentry = real_lookup(nd->dentry, name, nd);
	if (IS_ERR(dentry))
		goto fail;
	goto done;

need_revalidate:
	/* 校验成功 */
	if (dentry->d_op->d_revalidate(dentry, nd))
		goto done;
	if (d_invalidate(dentry))
		goto done;
	dput(dentry);
	goto need_lookup;

fail:
	return PTR_ERR(dentry);
}

/*
 * Name resolution.
 *
 * This is the basic name resolution function, turning a pathname
 * into the final dentry.
 *
 * We expect 'base' to be positive and a directory.
 */
/**
 * 真正的路径查找实现。
 */
int fastcall link_path_walk(const char * name, struct nameidata *nd)
{
	struct path next;
	struct inode *inode;
	int err;
	/* 查找标志 */
	unsigned int lookup_flags = nd->flags;

	/* 多个/仅代表一个/ */
	while (*name=='/')
		name++;
	if (!*name)/* 查找根目录或者空目录，结果已经保存在nd中了，直接返回 */
		goto return_reval;

	/* 每次在inode所在的目录下进行查找 */
	inode = nd->dentry->d_inode;
	/**
	 * 符号链接查找。
	 */
	if (nd->depth)
		lookup_flags = LOOKUP_FOLLOW;

	/* At this point we know we have a real path component. */
	/**
	 * 循环处理每一个路径分量。
	 */
	for(;;) {
		unsigned long hash;
		struct qstr this;
		unsigned int c;

		/**
		 * 只有目录有可执行权限，才能被检索。
		 */
		err = exec_permission_lite(inode, nd);
		if (err == -EAGAIN) { 
			err = permission(inode, MAY_EXEC, nd);
		}
 		if (err)/* 权限错误 */
			break;

		this.name = name;
		c = *(const unsigned char *)name;

		/**
		 * 计算散列值
		 */
		hash = init_name_hash();
		do {
			name++;
			hash = partial_name_hash(c, hash);
			c = *(const unsigned char *)name;
		} while (c && (c != '/'));
		this.len = name - (const char *) this.name;
		this.hash = end_name_hash(hash);

		/* remove trailing slashes? */
		/**
		 * 最后一个分量，并且没有以"/"结束，是一个文件。
		 */
		if (!c)
			goto last_component;
		/**
		 * 如果分量以"/"结束，退出。
		 */
		while (*++name == '/');
		if (!*name)
			goto last_with_slashes;

		/*
		 * "." and ".." are special - ".." especially so because it has
		 * to be able to know about the current root directory and
		 * parent relationships.
		 */
		if (this.name[0] == '.') switch (this.len) {/* 分量是一个"." */
			default:/* 不是"."，开始处理该分量。 */
				break;
			case 2:	
				if (this.name[1] != '.')
					break;
				follow_dotdot(&nd->mnt, &nd->dentry);
				inode = nd->dentry->d_inode;/* dentry就是上一层目录，转回上级目录并继续。 */
				/* fallthrough */
			case 1:/* 当前目录，继续处理下一个分量。 */
				continue;
		}
		/*
		 * See if the low-level filesystem might want
		 * to use its own hash..
		 */
		/**
		 * 如果文件系统允许目录缓存，并且有自定义的散列函数，则计算它的散列值。
		 */
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(nd->dentry, &this);
			if (err < 0)
				break;
		}
		nd->flags |= LOOKUP_CONTINUE;
		/* This does the actual lookups.. */
		/**
		 * 在当前目录中搜索下一个分量。
		 */
		err = do_lookup(nd, &this, &next);
		if (err)
			break;
		/* Check mountpoints.. */
		/**
		 * 检查刚解析的分量是否对应一个文件系统的安装点。如果是，则更新next的mnt和dentry
		 */
		follow_mount(&next.mnt, &next.dentry);

		err = -ENOENT;
		inode = next.dentry->d_inode;
		if (!inode)/* 目录不存在 */
			goto out_dput;
		err = -ENOTDIR; 
		if (!inode->i_op)
			goto out_dput;

		if (inode->i_op->follow_link) {/* 刚解析的分量是一个符号链接 */
			mntget(next.mnt);
			/**
			 * 处理符号链接。
			 */
			err = do_follow_link(next.dentry, nd);
			dput(next.dentry);
			mntput(next.mnt);
			if (err)
				goto return_err;
			err = -ENOENT;
			inode = nd->dentry->d_inode;
			if (!inode)
				break;
			err = -ENOTDIR; 
			if (!inode->i_op)
				break;
		} else {
			dput(nd->dentry);
			nd->mnt = next.mnt;
			nd->dentry = next.dentry;
		}
		err = -ENOTDIR; 
		/**
		 * 刚解析的分量是否指向一个目录。如果没有，则返回错误。因为中间目录分量必须是一个目录。
		 */
		if (!inode->i_op->lookup)
			break;
		continue;
		/* here ends the main loop */

last_with_slashes:
		/**
		 * 文件名最后一个分量是"/"，设置LOOKUP_FOLLOW和LOOKUP_DIRECTORY标志。后面的函数会强制将最后一个分量作为目录。
		 */
		lookup_flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
last_component:
		/**
		 * 最后一个分量。清除LOOKUP_CONTINUE
		 */
		nd->flags &= ~LOOKUP_CONTINUE;
		if (lookup_flags & LOOKUP_PARENT)/* 查找父路径名 */
			goto lookup_parent;
		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:	
				if (this.name[1] != '.')/* 不是".."，应当是正常的文件名 */
					break;
				/* ".."，尝试回到父目录,如果当前是文件系统根目录并且根目录没有绑到其他目录，则返回根目录，否则向上移动 */
				follow_dotdot(&nd->mnt, &nd->dentry);
				inode = nd->dentry->d_inode;
				/* fallthrough */
			case 1:/* 最后一个字符是"."，无错误直接返回。返回结果的dentry和mnt字段指向路径名中倒数第二个分量对应的对象 */
				goto return_reval;
		}
		/**
		 * 最后一个分量是文件或目录名，先试图有文件系统的哈希方法重新计算哈希值。
		 */
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(nd->dentry, &this);
			if (err < 0)
				break;
		}
		/**
		 * 在目录高速缓存或者磁盘上搜索文件。
		 */
		err = do_lookup(nd, &this, &next);
		if (err)
			break;
		/**
		 * 检查最后一个分量是否为某一个文件系统的安装点。
		 * 如果是，则把next变量更新为最上层文件系统的根目录对应的目录项对其和已经安装文件系统对象的地址。
		 */
		follow_mount(&next.mnt, &next.dentry);
		inode = next.dentry->d_inode;
		if ((lookup_flags & LOOKUP_FOLLOW)/* 需要检查最后一个分量的符号链接 */
		    && inode && inode->i_op && inode->i_op->follow_link) {/* 有自定义的follow_link方法 */
			mntget(next.mnt);
			err = do_follow_link(next.dentry, nd);
			dput(next.dentry);
			mntput(next.mnt);
			if (err)
				goto return_err;
			inode = nd->dentry->d_inode;
		} else {/* 不需要符号链接查找 */
			/**
			 * 释放dentry的引用，因为要将最后查找的分量设置为返回结果的dentry
			 */
			dput(nd->dentry);
			nd->mnt = next.mnt;
			nd->dentry = next.dentry;
		}
		/**
		 * 检查最后一个分量对应的d_inode是否为空，如果是，则说明对应的目录不存在，返回错误。
		 */
		err = -ENOENT;
		if (!inode)
			break;
		/**
		 * LOOKUP_DIRECTORY标志要求最后一个分量必须是目录
		 */
		if (lookup_flags & LOOKUP_DIRECTORY) {
			err = -ENOTDIR; 
			/**
			 * 没有lookup说明这不是一个目录，返回ENOTDIR错误。
			 */
			if (!inode->i_op || !inode->i_op->lookup)
				break;
		}
		goto return_base;
lookup_parent:
		/**
		 * 将last设置为最后一个分量
		 */
		nd->last = this;
		/**
		 * 如果最后一个分量不是"."或者".."，那么最后一个分量默认就是LAST_NORM
		 */
		nd->last_type = LAST_NORM;
		if (this.name[0] != '.')
			goto return_base;
		/**
		 * 对"."和".."进行特殊处理
		 */
		if (this.len == 1)
			nd->last_type = LAST_DOT;
		else if (this.len == 2 && this.name[1] == '.')
			nd->last_type = LAST_DOTDOT;
		else
			goto return_base;/* 由于没有对最后一个分量进行解释，因此返回的dentry就是父目录 */
return_reval:
		/*
		 * We bypassed the ordinary revalidation routines.
		 * We may need to check the cached dentry for staleness.
		 */
		if (nd->dentry && nd->dentry->d_sb &&
		    (nd->dentry->d_sb->s_type->fs_flags & FS_REVAL_DOT)) {
			err = -ESTALE;
			/* Note: we do not d_invalidate() */
			if (!nd->dentry->d_op->d_revalidate(nd->dentry, nd))
				break;
		}
return_base:
		return 0;
out_dput:
		dput(next.dentry);
		break;
	}
	path_release(nd);
return_err:
	return err;
}

int fastcall path_walk(const char * name, struct nameidata *nd)
{
	current->total_link_count = 0;
	return link_path_walk(name, nd);
}

/* SMP-safe */
/* returns 1 if everything is done */
static int __emul_lookup_dentry(const char *name, struct nameidata *nd)
{
	if (path_walk(name, nd))
		return 0;		/* something went wrong... */

	if (!nd->dentry->d_inode || S_ISDIR(nd->dentry->d_inode->i_mode)) {
		struct dentry *old_dentry = nd->dentry;
		struct vfsmount *old_mnt = nd->mnt;
		struct qstr last = nd->last;
		int last_type = nd->last_type;
		/*
		 * NAME was not found in alternate root or it's a directory.  Try to find
		 * it in the normal root:
		 */
		nd->last_type = LAST_ROOT;
		read_lock(&current->fs->lock);
		nd->mnt = mntget(current->fs->rootmnt);
		nd->dentry = dget(current->fs->root);
		read_unlock(&current->fs->lock);
		if (path_walk(name, nd) == 0) {
			if (nd->dentry->d_inode) {
				dput(old_dentry);
				mntput(old_mnt);
				return 1;
			}
			path_release(nd);
		}
		nd->dentry = old_dentry;
		nd->mnt = old_mnt;
		nd->last = last;
		nd->last_type = last_type;
	}
	return 1;
}

void set_fs_altroot(void)
{
	char *emul = __emul_prefix();
	struct nameidata nd;
	struct vfsmount *mnt = NULL, *oldmnt;
	struct dentry *dentry = NULL, *olddentry;
	int err;

	if (!emul)
		goto set_it;
	err = path_lookup(emul, LOOKUP_FOLLOW|LOOKUP_DIRECTORY|LOOKUP_NOALT, &nd);
	if (!err) {
		mnt = nd.mnt;
		dentry = nd.dentry;
	}
set_it:
	write_lock(&current->fs->lock);
	oldmnt = current->fs->altrootmnt;
	olddentry = current->fs->altroot;
	current->fs->altrootmnt = mnt;
	current->fs->altroot = dentry;
	write_unlock(&current->fs->lock);
	if (olddentry) {
		dput(olddentry);
		mntput(oldmnt);
	}
}

/**
 * 查找路径名
 *		name:要查找的文件路径名
 *		flags:表示怎样访问查找的文件标志，如LOOKUP_FOLLOW
 *		nd:存放查找的结果。
 */
int fastcall path_lookup(const char *name, unsigned int flags, struct nameidata *nd)
{
	int retval;

	/**
	 * 在结果中设置初值。
	 */
	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags;
	nd->depth = 0;

	/**
	 * 获取fs的lock自旋锁。
	 */
	read_lock(&current->fs->lock);
	if (*name=='/') {/* 从根目录开始查找 */
		if (current->fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
			/**
			 * 从根目录开始查找。
			 */
			nd->mnt = mntget(current->fs->altrootmnt);
			nd->dentry = dget(current->fs->altroot);
			read_unlock(&current->fs->lock);
			if (__emul_lookup_dentry(name,nd))
				return 0;
			read_lock(&current->fs->lock);
		}
		nd->mnt = mntget(current->fs->rootmnt);
		nd->dentry = dget(current->fs->root);
	} else {
		/**
		 * 从当前目录开始查找。
		 */
		nd->mnt = mntget(current->fs->pwdmnt);
		nd->dentry = dget(current->fs->pwd);
	}
	/**
	 * 此时已经获得了初始目录项的引用，可以释放自旋锁了。
	 */
	read_unlock(&current->fs->lock);
	/**
	 * 当前进程的符号链接查找计数进行初始化。
	 */
	current->total_link_count = 0;
	/**
	 * link_path_walk执行真正的路径查找。
	 */
	retval = link_path_walk(name, nd);
	if (unlikely(current->audit_context
		     && nd && nd->dentry && nd->dentry->d_inode))
		audit_inode(name,
			    nd->dentry->d_inode->i_ino,
			    nd->dentry->d_inode->i_rdev);
	return retval;
}

/*
 * Restricted form of lookup. Doesn't follow links, single-component only,
 * needs parent already locked. Doesn't follow mounts.
 * SMP-safe.
 */
static struct dentry * __lookup_hash(struct qstr *name, struct dentry * base, struct nameidata *nd)
{
	struct dentry * dentry;
	struct inode *inode;
	int err;

	inode = base->d_inode;
	err = permission(inode, MAY_EXEC, nd);
	dentry = ERR_PTR(err);
	if (err)
		goto out;

	/*
	 * See if the low-level filesystem might want
	 * to use its own hash..
	 */
	if (base->d_op && base->d_op->d_hash) {
		err = base->d_op->d_hash(base, name);
		dentry = ERR_PTR(err);
		if (err < 0)
			goto out;
	}

	dentry = cached_lookup(base, name, nd);
	if (!dentry) {
		struct dentry *new = d_alloc(base, name);
		dentry = ERR_PTR(-ENOMEM);
		if (!new)
			goto out;
		dentry = inode->i_op->lookup(inode, new, nd);
		if (!dentry)
			dentry = new;
		else
			dput(new);
	}
out:
	return dentry;
}

struct dentry * lookup_hash(struct qstr *name, struct dentry * base)
{
	return __lookup_hash(name, base, NULL);
}

/* SMP-safe */
struct dentry * lookup_one_len(const char * name, struct dentry * base, int len)
{
	unsigned long hash;
	struct qstr this;
	unsigned int c;

	this.name = name;
	this.len = len;
	if (!len)
		goto access;

	hash = init_name_hash();
	while (len--) {
		c = *(const unsigned char *)name++;
		if (c == '/' || c == '\0')
			goto access;
		hash = partial_name_hash(c, hash);
	}
	this.hash = end_name_hash(hash);

	return lookup_hash(&this, base);
access:
	return ERR_PTR(-EACCES);
}

/*
 *	namei()
 *
 * is used by most simple commands to get the inode of a specified name.
 * Open, link etc use their own routines, but this is enough for things
 * like 'chmod' etc.
 *
 * namei exists in two versions: namei/lnamei. The only difference is
 * that namei follows links, while lnamei does not.
 * SMP-safe
 */
int fastcall __user_walk(const char __user *name, unsigned flags, struct nameidata *nd)
{
	char *tmp = getname(name);
	int err = PTR_ERR(tmp);

	if (!IS_ERR(tmp)) {
		err = path_lookup(tmp, flags, nd);
		putname(tmp);
	}
	return err;
}

/*
 * It's inline, so penalty for filesystems that don't use sticky bit is
 * minimal.
 */
static inline int check_sticky(struct inode *dir, struct inode *inode)
{
	if (!(dir->i_mode & S_ISVTX))
		return 0;
	if (inode->i_uid == current->fsuid)
		return 0;
	if (dir->i_uid == current->fsuid)
		return 0;
	return !capable(CAP_FOWNER);
}

/*
 *	Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *	a. be owner of dir, or
 *	b. be owner of victim, or
 *	c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do antyhing with
 *     links pointing to it.
 *  7. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  8. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 *  9. We can't remove a root or mountpoint.
 * 10. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 */
static inline int may_delete(struct inode *dir,struct dentry *victim,int isdir)
{
	int error;

	if (!victim->d_inode)
		return -ENOENT;

	BUG_ON(victim->d_parent->d_inode != dir);

	error = permission(dir,MAY_WRITE | MAY_EXEC, NULL);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;
	if (check_sticky(dir, victim->d_inode)||IS_APPEND(victim->d_inode)||
	    IS_IMMUTABLE(victim->d_inode))
		return -EPERM;
	if (isdir) {
		if (!S_ISDIR(victim->d_inode->i_mode))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (S_ISDIR(victim->d_inode->i_mode))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

/*	Check whether we can create an object with dentry child in directory
 *  dir.
 *  1. We can't do it if child already exists (open has special treatment for
 *     this case, but since we are inlined it's OK)
 *  2. We can't do it if dir is read-only (done in permission())
 *  3. We should have write and exec permissions on dir
 *  4. We can't do it if dir is immutable (done in permission())
 */
static inline int may_create(struct inode *dir, struct dentry *child,
			     struct nameidata *nd)
{
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return permission(dir,MAY_WRITE | MAY_EXEC, nd);
}

/* 
 * Special case: O_CREAT|O_EXCL implies O_NOFOLLOW for security
 * reasons.
 *
 * O_DIRECTORY translates into forcing a directory lookup.
 */
static inline int lookup_flags(unsigned int f)
{
	unsigned long retval = LOOKUP_FOLLOW;

	if (f & O_NOFOLLOW)
		retval &= ~LOOKUP_FOLLOW;
	
	if ((f & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL))
		retval &= ~LOOKUP_FOLLOW;
	
	if (f & O_DIRECTORY)
		retval |= LOOKUP_DIRECTORY;

	return retval;
}

/*
 * p1 and p2 should be directories on the same fs.
 */
struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	if (p1 == p2) {
		down(&p1->d_inode->i_sem);
		return NULL;
	}

	down(&p1->d_inode->i_sb->s_vfs_rename_sem);

	for (p = p1; p->d_parent != p; p = p->d_parent) {
		if (p->d_parent == p2) {
			down(&p2->d_inode->i_sem);
			down(&p1->d_inode->i_sem);
			return p;
		}
	}

	for (p = p2; p->d_parent != p; p = p->d_parent) {
		if (p->d_parent == p1) {
			down(&p1->d_inode->i_sem);
			down(&p2->d_inode->i_sem);
			return p;
		}
	}

	down(&p1->d_inode->i_sem);
	down(&p2->d_inode->i_sem);
	return NULL;
}

void unlock_rename(struct dentry *p1, struct dentry *p2)
{
	up(&p1->d_inode->i_sem);
	if (p1 != p2) {
		up(&p2->d_inode->i_sem);
		up(&p1->d_inode->i_sb->s_vfs_rename_sem);
	}
}

int vfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd)
{
	int error = may_create(dir, dentry, nd);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->create)
		return -EACCES;	/* shouldn't it be ENOSYS? */
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	DQUOT_INIT(dir);
	error = dir->i_op->create(dir, dentry, mode, nd);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_create(dir, dentry, mode);
	}
	return error;
}

int may_open(struct nameidata *nd, int acc_mode, int flag)
{
	struct dentry *dentry = nd->dentry;
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode)
		return -ENOENT;

	if (S_ISLNK(inode->i_mode))
		return -ELOOP;
	
	if (S_ISDIR(inode->i_mode) && (flag & FMODE_WRITE))
		return -EISDIR;

	error = permission(inode, acc_mode, nd);
	if (error)
		return error;

	/*
	 * FIFO's, sockets and device files are special: they don't
	 * actually live on the filesystem itself, and as such you
	 * can write to them even if the filesystem is read-only.
	 */
	if (S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
	    	flag &= ~O_TRUNC;
	} else if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode)) {
		if (nd->mnt->mnt_flags & MNT_NODEV)
			return -EACCES;

		flag &= ~O_TRUNC;
	} else if (IS_RDONLY(inode) && (flag & FMODE_WRITE))
		return -EROFS;
	/*
	 * An append-only file must be opened in append mode for writing.
	 */
	if (IS_APPEND(inode)) {
		if  ((flag & FMODE_WRITE) && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	/* O_NOATIME can only be set by the owner or superuser */
	if (flag & O_NOATIME)
		if (current->fsuid != inode->i_uid && !capable(CAP_FOWNER))
			return -EPERM;

	/*
	 * Ensure there are no outstanding leases on the file.
	 */
	error = break_lease(inode, flag);
	if (error)
		return error;

	if (flag & O_TRUNC) {
		error = get_write_access(inode);
		if (error)
			return error;

		/*
		 * Refuse to truncate files with mandatory locks held on them.
		 */
		error = locks_verify_locked(inode);
		if (!error) {
			DQUOT_INIT(inode);
			
			error = do_truncate(dentry, 0);
		}
		put_write_access(inode);
		if (error)
			return error;
	} else
		if (flag & FMODE_WRITE)
			DQUOT_INIT(inode);

	return 0;
}

/*
 *	open_namei()
 *
 * namei for open - this is in fact almost the whole open-routine.
 *
 * Note that the low bits of "flag" aren't the same as in the open
 * system call - they are 00 - no permissions needed
 *			  01 - read permission needed
 *			  10 - write permission needed
 *			  11 - read/write permissions needed
 * which is a lot more logical, and also allows the "no perm" needed
 * for symlinks (where the permissions are checked later).
 * SMP-safe
 */
int open_namei(const char * pathname, int flag, int mode, struct nameidata *nd)
{
	int acc_mode, error = 0;
	struct dentry *dentry;
	struct dentry *dir;
	int count = 0;

	acc_mode = ACC_MODE(flag);

	/* Allow the LSM permission hook to distinguish append 
	   access from general write access. */
	if (flag & O_APPEND)
		acc_mode |= MAY_APPEND;

	/* Fill in the open() intent data */
	nd->intent.open.flags = flag;
	nd->intent.open.create_mode = mode;

	/*
	 * The simplest case - just a plain lookup.
	 */
	if (!(flag & O_CREAT)) {/* 如果不创建文件，则用LOOKUP_OPEN标志查找文件 */
		error = path_lookup(pathname, lookup_flags(flag)|LOOKUP_OPEN, nd);
		if (error)
			return error;
		goto ok;
	}

	/*
	 * Create - we need to know the parent.
	 */
	/**
	 * 有O_CREAT标志，则用LOOKUP_CREATE标志查找文件。
	 */
	error = path_lookup(pathname, LOOKUP_PARENT|LOOKUP_OPEN|LOOKUP_CREATE, nd);
	if (error)
		return error;

	/*
	 * We have the parent and last component. First of all, check
	 * that we are not asked to creat(2) an obvious directory - that
	 * will not do.
	 */
	error = -EISDIR;
	/**
	 * 最后一个分量是目录。失败
	 */
	if (nd->last_type != LAST_NORM || nd->last.name[nd->last.len])
		goto exit;

	dir = nd->dentry;
	nd->flags &= ~LOOKUP_PARENT;
	down(&dir->d_inode->i_sem);
	dentry = __lookup_hash(&nd->last, nd->dentry, nd);

do_last:
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		up(&dir->d_inode->i_sem);
		goto exit;
	}

	/* Negative dentry, just create the file */
	if (!dentry->d_inode) {/* 文件还不存在 */
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current->fs->umask;
		/**
		 * 调用vfs_create来创建文件
		 */
		error = vfs_create(dir->d_inode, dentry, mode, nd);
		up(&dir->d_inode->i_sem);
		dput(nd->dentry);
		nd->dentry = dentry;
		if (error)
			goto exit;
		/* Don't check for write permission, don't truncate */
		acc_mode = 0;
		flag &= ~O_TRUNC;
		goto ok;
	}

	/*
	 * It already exists.
	 */
	up(&dir->d_inode->i_sem);

	error = -EEXIST;
	if (flag & O_EXCL)/* 文件已经存在，如果指定了O_EXCL标志，则需要返回错误。 */
		goto exit_dput;

	if (d_mountpoint(dentry)) {
		error = -ELOOP;
		if (flag & O_NOFOLLOW)
			goto exit_dput;
		while (__follow_down(&nd->mnt,&dentry) && d_mountpoint(dentry));
	}
	error = -ENOENT;
	if (!dentry->d_inode)
		goto exit_dput;
	if (dentry->d_inode->i_op && dentry->d_inode->i_op->follow_link)
		goto do_link;

	dput(nd->dentry);
	nd->dentry = dentry;
	error = -EISDIR;
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		goto exit;
ok:
	error = may_open(nd, acc_mode, flag);
	if (error)
		goto exit;
	return 0;

exit_dput:
	dput(dentry);
exit:
	path_release(nd);
	return error;

do_link:
	error = -ELOOP;
	if (flag & O_NOFOLLOW)
		goto exit_dput;
	/*
	 * This is subtle. Instead of calling do_follow_link() we do the
	 * thing by hands. The reason is that this way we have zero link_count
	 * and path_walk() (called from ->follow_link) honoring LOOKUP_PARENT.
	 * After that we have the parent and last component, i.e.
	 * we are in the same situation as after the first path_walk().
	 * Well, almost - if the last component is normal we get its copy
	 * stored in nd->last.name and we will have to putname() it when we
	 * are done. Procfs-like symlinks just set LAST_BIND.
	 */
	nd->flags |= LOOKUP_PARENT;
	error = security_inode_follow_link(dentry, nd);
	if (error)
		goto exit_dput;
	error = __do_follow_link(dentry, nd);
	dput(dentry);
	if (error)
		return error;
	nd->flags &= ~LOOKUP_PARENT;
	if (nd->last_type == LAST_BIND) {
		dentry = nd->dentry;
		goto ok;
	}
	error = -EISDIR;
	if (nd->last_type != LAST_NORM)
		goto exit;
	if (nd->last.name[nd->last.len]) {
		putname(nd->last.name);
		goto exit;
	}
	error = -ELOOP;
	if (count++==32) {
		putname(nd->last.name);
		goto exit;
	}
	dir = nd->dentry;
	down(&dir->d_inode->i_sem);
	dentry = __lookup_hash(&nd->last, nd->dentry, nd);
	putname(nd->last.name);
	goto do_last;
}

/**
 * lookup_create - lookup a dentry, creating it if it doesn't exist
 * @nd: nameidata info
 * @is_dir: directory flag
 *
 * Simple function to lookup and return a dentry and create it
 * if it doesn't exist.  Is SMP-safe.
 */
struct dentry *lookup_create(struct nameidata *nd, int is_dir)
{
	struct dentry *dentry;

	down(&nd->dentry->d_inode->i_sem);
	dentry = ERR_PTR(-EEXIST);
	if (nd->last_type != LAST_NORM)
		goto fail;
	nd->flags &= ~LOOKUP_PARENT;
	dentry = lookup_hash(&nd->last, nd->dentry);
	if (IS_ERR(dentry))
		goto fail;
	if (!is_dir && nd->last.name[nd->last.len] && !dentry->d_inode)
		goto enoent;
	return dentry;
enoent:
	dput(dentry);
	dentry = ERR_PTR(-ENOENT);
fail:
	return dentry;
}

int vfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op || !dir->i_op->mknod)
		return -EPERM;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	DQUOT_INIT(dir);
	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_mknod(dir, dentry, mode, dev);
	}
	return error;
}

/** 
 * 创建设备文件。设备文件通常位于/dev目录中
 */
asmlinkage long sys_mknod(const char __user * filename, int mode, unsigned dev)
{
	int error = 0;
	char * tmp;
	struct dentry * dentry;
	struct nameidata nd;

	if (S_ISDIR(mode))
		return -EPERM;
	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	error = path_lookup(tmp, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	dentry = lookup_create(&nd, 0);
	error = PTR_ERR(dentry);

	if (!IS_POSIXACL(nd.dentry->d_inode))
		mode &= ~current->fs->umask;
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(nd.dentry->d_inode,dentry,mode,&nd);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(nd.dentry->d_inode,dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(nd.dentry->d_inode,dentry,mode,0);
			break;
		case S_IFDIR:
			error = -EPERM;
			break;
		default:
			error = -EINVAL;
		}
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
	path_release(&nd);
out:
	putname(tmp);

	return error;
}

int vfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	DQUOT_INIT(dir);
	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_mkdir(dir,dentry, mode);
	}
	return error;
}

asmlinkage long sys_mkdir(const char __user * pathname, int mode)
{
	int error = 0;
	char * tmp;

	tmp = getname(pathname);
	error = PTR_ERR(tmp);
	if (!IS_ERR(tmp)) {
		struct dentry *dentry;
		struct nameidata nd;

		error = path_lookup(tmp, LOOKUP_PARENT, &nd);
		if (error)
			goto out;
		dentry = lookup_create(&nd, 1);
		error = PTR_ERR(dentry);
		if (!IS_ERR(dentry)) {
			if (!IS_POSIXACL(nd.dentry->d_inode))
				mode &= ~current->fs->umask;
			error = vfs_mkdir(nd.dentry->d_inode, dentry, mode);
			dput(dentry);
		}
		up(&nd.dentry->d_inode->i_sem);
		path_release(&nd);
out:
		putname(tmp);
	}

	return error;
}

/*
 * We try to drop the dentry early: we should have
 * a usage count of 2 if we're the only user of this
 * dentry, and if that is true (possibly after pruning
 * the dcache), then we drop the dentry now.
 *
 * A low-level filesystem can, if it choses, legally
 * do a
 *
 *	if (!d_unhashed(dentry))
 *		return -EBUSY;
 *
 * if it cannot handle the case of removing a directory
 * that is still in use by something else..
 */
void dentry_unhash(struct dentry *dentry)
{
	dget(dentry);
	spin_lock(&dcache_lock);
	switch (atomic_read(&dentry->d_count)) {
	default:
		spin_unlock(&dcache_lock);
		shrink_dcache_parent(dentry);
		spin_lock(&dcache_lock);
		if (atomic_read(&dentry->d_count) != 2)
			break;
	case 2:
		__d_drop(dentry);
	}
	spin_unlock(&dcache_lock);
}

int vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->rmdir)
		return -EPERM;

	DQUOT_INIT(dir);

	down(&dentry->d_inode->i_sem);
	dentry_unhash(dentry);
	if (d_mountpoint(dentry))
		error = -EBUSY;
	else {
		error = security_inode_rmdir(dir, dentry);
		if (!error) {
			error = dir->i_op->rmdir(dir, dentry);
			if (!error)
				dentry->d_inode->i_flags |= S_DEAD;
		}
	}
	up(&dentry->d_inode->i_sem);
	if (!error) {
		inode_dir_notify(dir, DN_DELETE);
		d_delete(dentry);
	}
	dput(dentry);

	return error;
}

asmlinkage long sys_rmdir(const char __user * pathname)
{
	int error = 0;
	char * name;
	struct dentry *dentry;
	struct nameidata nd;

	name = getname(pathname);
	if(IS_ERR(name))
		return PTR_ERR(name);

	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error)
		goto exit;

	switch(nd.last_type) {
		case LAST_DOTDOT:
			error = -ENOTEMPTY;
			goto exit1;
		case LAST_DOT:
			error = -EINVAL;
			goto exit1;
		case LAST_ROOT:
			error = -EBUSY;
			goto exit1;
	}
	down(&nd.dentry->d_inode->i_sem);
	dentry = lookup_hash(&nd.last, nd.dentry);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		error = vfs_rmdir(nd.dentry->d_inode, dentry);
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
exit1:
	path_release(&nd);
exit:
	putname(name);
	return error;
}

int vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 0);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->unlink)
		return -EPERM;

	DQUOT_INIT(dir);

	down(&dentry->d_inode->i_sem);
	if (d_mountpoint(dentry))
		error = -EBUSY;
	else {
		error = security_inode_unlink(dir, dentry);
		if (!error)
			error = dir->i_op->unlink(dir, dentry);
	}
	up(&dentry->d_inode->i_sem);

	/* We don't d_delete() NFS sillyrenamed files--they still exist. */
	if (!error && !(dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		d_delete(dentry);
		inode_dir_notify(dir, DN_DELETE);
	}
	return error;
}

/*
 * Make sure that the actual truncation of the file will occur outside its
 * directory's i_sem.  Truncate can take a long time if there is a lot of
 * writeout happening, and we don't want to prevent access to the directory
 * while waiting on the I/O.
 */
asmlinkage long sys_unlink(const char __user * pathname)
{
	int error = 0;
	char * name;
	struct dentry *dentry;
	struct nameidata nd;
	struct inode *inode = NULL;

	name = getname(pathname);
	if(IS_ERR(name))
		return PTR_ERR(name);

	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error)
		goto exit;
	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;
	down(&nd.dentry->d_inode->i_sem);
	dentry = lookup_hash(&nd.last, nd.dentry);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (nd.last.name[nd.last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (inode)
			atomic_inc(&inode->i_count);
		error = vfs_unlink(nd.dentry->d_inode, dentry);
	exit2:
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
	if (inode)
		iput(inode);	/* truncate the inode here */
exit1:
	path_release(&nd);
exit:
	putname(name);
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
		S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}

int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname, int mode)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	DQUOT_INIT(dir);
	error = dir->i_op->symlink(dir, dentry, oldname);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_symlink(dir, dentry, oldname);
	}
	return error;
}

asmlinkage long sys_symlink(const char __user * oldname, const char __user * newname)
{
	int error = 0;
	char * from;
	char * to;

	from = getname(oldname);
	if(IS_ERR(from))
		return PTR_ERR(from);
	to = getname(newname);
	error = PTR_ERR(to);
	if (!IS_ERR(to)) {
		struct dentry *dentry;
		struct nameidata nd;

		error = path_lookup(to, LOOKUP_PARENT, &nd);
		if (error)
			goto out;
		dentry = lookup_create(&nd, 0);
		error = PTR_ERR(dentry);
		if (!IS_ERR(dentry)) {
			error = vfs_symlink(nd.dentry->d_inode, dentry, from, S_IALLUGO);
			dput(dentry);
		}
		up(&nd.dentry->d_inode->i_sem);
		path_release(&nd);
out:
		putname(to);
	}
	putname(from);
	return error;
}

int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;

	if (!inode)
		return -ENOENT;

	error = may_create(dir, new_dentry, NULL);
	if (error)
		return error;

	if (dir->i_sb != inode->i_sb)
		return -EXDEV;

	/*
	 * A link to an append-only or immutable file cannot be created.
	 */
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	down(&old_dentry->d_inode->i_sem);
	DQUOT_INIT(dir);
	error = dir->i_op->link(old_dentry, dir, new_dentry);
	up(&old_dentry->d_inode->i_sem);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_link(old_dentry, dir, new_dentry);
	}
	return error;
}

/*
 * Hardlinks are often used in delicate situations.  We avoid
 * security-related surprises by not following symlinks on the
 * newname.  --KAB
 *
 * We don't follow them on the oldname either to be compatible
 * with linux 2.0, and to avoid hard-linking to directories
 * and other special files.  --ADM
 */
asmlinkage long sys_link(const char __user * oldname, const char __user * newname)
{
	struct dentry *new_dentry;
	struct nameidata nd, old_nd;
	int error;
	char * to;

	to = getname(newname);
	if (IS_ERR(to))
		return PTR_ERR(to);

	error = __user_walk(oldname, 0, &old_nd);
	if (error)
		goto exit;
	error = path_lookup(to, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	error = -EXDEV;
	if (old_nd.mnt != nd.mnt)
		goto out_release;
	new_dentry = lookup_create(&nd, 0);
	error = PTR_ERR(new_dentry);
	if (!IS_ERR(new_dentry)) {
		error = vfs_link(old_nd.dentry, nd.dentry->d_inode, new_dentry);
		dput(new_dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
out_release:
	path_release(&nd);
out:
	path_release(&old_nd);
exit:
	putname(to);

	return error;
}

/*
 * The worst of all namespace operations - renaming directory. "Perverted"
 * doesn't even start to describe it. Somebody in UCB had a heck of a trip...
 * Problems:
 *	a) we can get into loop creation. Check is done in is_subdir().
 *	b) race potential - two innocent renames can create a loop together.
 *	   That's where 4.4 screws up. Current fix: serialization on
 *	   sb->s_vfs_rename_sem. We might be more accurate, but that's another
 *	   story.
 *	c) we have to lock _three_ objects - parents and victim (if it exists).
 *	   And that - after we got ->i_sem on parents (until then we don't know
 *	   whether the target exists).  Solution: try to be smart with locking
 *	   order for inodes.  We rely on the fact that tree topology may change
 *	   only under ->s_vfs_rename_sem _and_ that parent of the object we
 *	   move will be locked.  Thus we can rank directories by the tree
 *	   (ancestors first) and rank all non-directories after them.
 *	   That works since everybody except rename does "lock parent, lookup,
 *	   lock child" and rename is under ->s_vfs_rename_sem.
 *	   HOWEVER, it relies on the assumption that any object with ->lookup()
 *	   has no more than 1 dentry.  If "hybrid" objects will ever appear,
 *	   we'd better make sure that there's no link(2) for them.
 *	d) some filesystems don't support opened-but-unlinked directories,
 *	   either because of layout or because they are not ready to deal with
 *	   all cases correctly. The latter will be fixed (taking this sort of
 *	   stuff into VFS), but the former is not going away. Solution: the same
 *	   trick as in rmdir().
 *	e) conversion from fhandle to dentry may come in the wrong moment - when
 *	   we are removing the target. Solution: we will have to grab ->i_sem
 *	   in the fhandle_to_dentry code. [FIXME - current nfsfh.c relies on
 *	   ->i_sem on parents, which works but leads to some truely excessive
 *	   locking].
 */
int vfs_rename_dir(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	int error = 0;
	struct inode *target;

	/*
	 * If we are going to change the parent - check write permissions,
	 * we'll need to flip '..'.
	 */
	if (new_dir != old_dir) {
		error = permission(old_dentry->d_inode, MAY_WRITE, NULL);
		if (error)
			return error;
	}

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		return error;

	target = new_dentry->d_inode;
	if (target) {
		down(&target->i_sem);
		dentry_unhash(new_dentry);
	}
	if (d_mountpoint(old_dentry)||d_mountpoint(new_dentry))
		error = -EBUSY;
	else 
		error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry);
	if (target) {
		if (!error)
			target->i_flags |= S_DEAD;
		up(&target->i_sem);
		if (d_unhashed(new_dentry))
			d_rehash(new_dentry);
		dput(new_dentry);
	}
	if (!error) {
		d_move(old_dentry,new_dentry);
		security_inode_post_rename(old_dir, old_dentry,
					   new_dir, new_dentry);
	}
	return error;
}

int vfs_rename_other(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *target;
	int error;

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		return error;

	dget(new_dentry);
	target = new_dentry->d_inode;
	if (target)
		down(&target->i_sem);
	if (d_mountpoint(old_dentry)||d_mountpoint(new_dentry))
		error = -EBUSY;
	else
		error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry);
	if (!error) {
		/* The following d_move() should become unconditional */
		if (!(old_dir->i_sb->s_type->fs_flags & FS_ODD_RENAME))
			d_move(old_dentry, new_dentry);
		security_inode_post_rename(old_dir, old_dentry, new_dir, new_dentry);
	}
	if (target)
		up(&target->i_sem);
	dput(new_dentry);
	return error;
}

int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	int error;
	int is_dir = S_ISDIR(old_dentry->d_inode->i_mode);

	if (old_dentry->d_inode == new_dentry->d_inode)
 		return 0;
 
	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry, NULL);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
	if (error)
		return error;

	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;

	DQUOT_INIT(old_dir);
	DQUOT_INIT(new_dir);

	if (is_dir)
		error = vfs_rename_dir(old_dir,old_dentry,new_dir,new_dentry);
	else
		error = vfs_rename_other(old_dir,old_dentry,new_dir,new_dentry);
	if (!error) {
		if (old_dir == new_dir)
			inode_dir_notify(old_dir, DN_RENAME);
		else {
			inode_dir_notify(old_dir, DN_DELETE);
			inode_dir_notify(new_dir, DN_CREATE);
		}
	}
	return error;
}

static inline int do_rename(const char * oldname, const char * newname)
{
	int error = 0;
	struct dentry * old_dir, * new_dir;
	struct dentry * old_dentry, *new_dentry;
	struct dentry * trap;
	struct nameidata oldnd, newnd;

	error = path_lookup(oldname, LOOKUP_PARENT, &oldnd);
	if (error)
		goto exit;

	error = path_lookup(newname, LOOKUP_PARENT, &newnd);
	if (error)
		goto exit1;

	error = -EXDEV;
	if (oldnd.mnt != newnd.mnt)
		goto exit2;

	old_dir = oldnd.dentry;
	error = -EBUSY;
	if (oldnd.last_type != LAST_NORM)
		goto exit2;

	new_dir = newnd.dentry;
	if (newnd.last_type != LAST_NORM)
		goto exit2;

	trap = lock_rename(new_dir, old_dir);

	old_dentry = lookup_hash(&oldnd.last, old_dir);
	error = PTR_ERR(old_dentry);
	if (IS_ERR(old_dentry))
		goto exit3;
	/* source must exist */
	error = -ENOENT;
	if (!old_dentry->d_inode)
		goto exit4;
	/* unless the source is a directory trailing slashes give -ENOTDIR */
	if (!S_ISDIR(old_dentry->d_inode->i_mode)) {
		error = -ENOTDIR;
		if (oldnd.last.name[oldnd.last.len])
			goto exit4;
		if (newnd.last.name[newnd.last.len])
			goto exit4;
	}
	/* source should not be ancestor of target */
	error = -EINVAL;
	if (old_dentry == trap)
		goto exit4;
	new_dentry = lookup_hash(&newnd.last, new_dir);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto exit4;
	/* target should not be an ancestor of source */
	error = -ENOTEMPTY;
	if (new_dentry == trap)
		goto exit5;

	error = vfs_rename(old_dir->d_inode, old_dentry,
				   new_dir->d_inode, new_dentry);
exit5:
	dput(new_dentry);
exit4:
	dput(old_dentry);
exit3:
	unlock_rename(new_dir, old_dir);
exit2:
	path_release(&newnd);
exit1:
	path_release(&oldnd);
exit:
	return error;
}

asmlinkage long sys_rename(const char __user * oldname, const char __user * newname)
{
	int error;
	char * from;
	char * to;

	from = getname(oldname);
	if(IS_ERR(from))
		return PTR_ERR(from);
	to = getname(newname);
	error = PTR_ERR(to);
	if (!IS_ERR(to)) {
		error = do_rename(from,to);
		putname(to);
	}
	putname(from);
	return error;
}

int vfs_readlink(struct dentry *dentry, char __user *buffer, int buflen, const char *link)
{
	int len;

	len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

/*
 * A helper for ->readlink().  This should be used *ONLY* for symlinks that
 * have ->follow_link() touching nd only in nd_set_link().  Using (or not
 * using) it for any given inode is up to filesystem.
 */
int generic_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct nameidata nd;
	int res;
	nd.depth = 0;
	res = dentry->d_inode->i_op->follow_link(dentry, &nd);
	if (!res) {
		res = vfs_readlink(dentry, buffer, buflen, nd_get_link(&nd));
		if (dentry->d_inode->i_op->put_link)
			dentry->d_inode->i_op->put_link(dentry, &nd);
	}
	return res;
}

int vfs_follow_link(struct nameidata *nd, const char *link)
{
	return __vfs_follow_link(nd, link);
}

/* get the link contents into pagecache */
static char *page_getlink(struct dentry * dentry, struct page **ppage)
{
	struct page * page;
	struct address_space *mapping = dentry->d_inode->i_mapping;
	page = read_cache_page(mapping, 0, (filler_t *)mapping->a_ops->readpage,
				NULL);
	if (IS_ERR(page))
		goto sync_fail;
	wait_on_page_locked(page);
	if (!PageUptodate(page))
		goto async_fail;
	*ppage = page;
	return kmap(page);

async_fail:
	page_cache_release(page);
	return ERR_PTR(-EIO);

sync_fail:
	return (char*)page;
}

int page_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct page *page = NULL;
	char *s = page_getlink(dentry, &page);
	int res = vfs_readlink(dentry,buffer,buflen,s);
	if (page) {
		kunmap(page);
		page_cache_release(page);
	}
	return res;
}

int page_follow_link_light(struct dentry *dentry, struct nameidata *nd)
{
	struct page *page;
	nd_set_link(nd, page_getlink(dentry, &page));
	return 0;
}

void page_put_link(struct dentry *dentry, struct nameidata *nd)
{
	if (!IS_ERR(nd_get_link(nd))) {
		struct page *page;
		page = find_get_page(dentry->d_inode->i_mapping, 0);
		if (!page)
			BUG();
		kunmap(page);
		page_cache_release(page);
		page_cache_release(page);
	}
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page = grab_cache_page(mapping, 0);
	int err = -ENOMEM;
	char *kaddr;

	if (!page)
		goto fail;
	err = mapping->a_ops->prepare_write(NULL, page, 0, len-1);
	if (err)
		goto fail_map;
	kaddr = kmap_atomic(page, KM_USER0);
	memcpy(kaddr, symname, len-1);
	kunmap_atomic(kaddr, KM_USER0);
	mapping->a_ops->commit_write(NULL, page, 0, len-1);
	/*
	 * Notice that we are _not_ going to block here - end of page is
	 * unmapped, so this will only try to map the rest of page, see
	 * that it is unmapped (typically even will not look into inode -
	 * ->i_size will be enough for everything) and zero it out.
	 * OTOH it's obviously correct and should make the page up-to-date.
	 */
	if (!PageUptodate(page)) {
		err = mapping->a_ops->readpage(NULL, page);
		wait_on_page_locked(page);
	} else {
		unlock_page(page);
	}
	page_cache_release(page);
	if (err < 0)
		goto fail;
	mark_inode_dirty(inode);
	return 0;
fail_map:
	unlock_page(page);
	page_cache_release(page);
fail:
	return err;
}

struct inode_operations page_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};

EXPORT_SYMBOL(__user_walk);
EXPORT_SYMBOL(follow_down);
EXPORT_SYMBOL(follow_up);
EXPORT_SYMBOL(get_write_access); /* binfmt_aout */
EXPORT_SYMBOL(getname);
EXPORT_SYMBOL(lock_rename);
EXPORT_SYMBOL(lookup_hash);
EXPORT_SYMBOL(lookup_one_len);
EXPORT_SYMBOL(page_follow_link_light);
EXPORT_SYMBOL(page_put_link);
EXPORT_SYMBOL(page_readlink);
EXPORT_SYMBOL(page_symlink);
EXPORT_SYMBOL(page_symlink_inode_operations);
EXPORT_SYMBOL(path_lookup);
EXPORT_SYMBOL(path_release);
EXPORT_SYMBOL(path_walk);
EXPORT_SYMBOL(permission);
EXPORT_SYMBOL(unlock_rename);
EXPORT_SYMBOL(vfs_create);
EXPORT_SYMBOL(vfs_follow_link);
EXPORT_SYMBOL(vfs_link);
EXPORT_SYMBOL(vfs_mkdir);
EXPORT_SYMBOL(vfs_mknod);
EXPORT_SYMBOL(generic_permission);
EXPORT_SYMBOL(vfs_readlink);
EXPORT_SYMBOL(vfs_rename);
EXPORT_SYMBOL(vfs_rmdir);
EXPORT_SYMBOL(vfs_symlink);
EXPORT_SYMBOL(vfs_unlink);
EXPORT_SYMBOL(dentry_unhash);
EXPORT_SYMBOL(generic_readlink);
