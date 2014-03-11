/*
 *  linux/fs/block_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 */

#include <linux/config.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/smp_lock.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/blkpg.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/mount.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <asm/uaccess.h>

struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
	return container_of(inode, struct bdev_inode, vfs_inode);
}

inline struct block_device *I_BDEV(struct inode *inode)
{
	return &BDEV_I(inode)->bdev;
}

EXPORT_SYMBOL(I_BDEV);

static sector_t max_block(struct block_device *bdev)
{
	sector_t retval = ~((sector_t)0);
	loff_t sz = i_size_read(bdev->bd_inode);

	if (sz) {
		unsigned int size = block_size(bdev);
		unsigned int sizebits = blksize_bits(size);
		retval = (sz >> sizebits);
	}
	return retval;
}

/* Kill _all_ buffers, dirty or not.. */
static void kill_bdev(struct block_device *bdev)
{
	invalidate_bdev(bdev, 1);
	truncate_inode_pages(bdev->bd_inode->i_mapping, 0);
}	

int set_blocksize(struct block_device *bdev, int size)
{
	/* Size must be a power of two, and between 512 and PAGE_SIZE */
	if (size > PAGE_SIZE || size < 512 || (size & (size-1)))
		return -EINVAL;

	/* Size cannot be smaller than the size supported by the device */
	if (size < bdev_hardsect_size(bdev))
		return -EINVAL;

	/* Don't change the size if it is same as current */
	if (bdev->bd_block_size != size) {
		sync_blockdev(bdev);
		bdev->bd_block_size = size;
		bdev->bd_inode->i_blkbits = blksize_bits(size);
		kill_bdev(bdev);
	}
	return 0;
}

EXPORT_SYMBOL(set_blocksize);

int sb_set_blocksize(struct super_block *sb, int size)
{
	int bits = 9; /* 2^9 = 512 */

	if (set_blocksize(sb->s_bdev, size))
		return 0;
	/* If we get here, we know size is power of two
	 * and it's value is between 512 and PAGE_SIZE */
	sb->s_blocksize = size;
	for (size >>= 10; size; size >>= 1)
		++bits;
	sb->s_blocksize_bits = bits;
	return sb->s_blocksize;
}

EXPORT_SYMBOL(sb_set_blocksize);

int sb_min_blocksize(struct super_block *sb, int size)
{
	int minsize = bdev_hardsect_size(sb->s_bdev);
	if (size < minsize)
		size = minsize;
	return sb_set_blocksize(sb, size);
}

EXPORT_SYMBOL(sb_min_blocksize);

/**
 * 被block_prepare_write，blkdev_writepage,blkdev_readpage等过程回调。
 * 用于将相对于文件开始处的文件块号转换为相对于块设备开始处的逻辑块号。
 * 对块设备来说，这两个数是一样的
 */
static int
blkdev_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh, int create)
{
	/**
	 * 检查页中第一个块的块号是否超过块设备的最后一块的索引值（存放在bdev->bd_inode->i_size中的块设备大小除以存放bdev->bd_block_size中的块大小得到该索引值，bdev指向块设备描述符）
	 * 如果超过，那么对于写操作它返回-EIO，对于读操作返回0(超出块设备读也是不允许的，但是不返回错误代码)
	 * 内核可以对块设备的最后数据试着发出读请求，而得到的缓冲区只被部分映射.
	 */
	if (iblock >= max_block(I_BDEV(inode))) {
		if (create)
			return -EIO;

		/*
		 * for reads, we're just trying to fill a partial page.
		 * return a hole, they will have to call get_block again
		 * before they can fill it, and they will get -EIO at that
		 * time
		 */
		return 0;
	}
	/**
	 * 设置缓冲区首部的b_dev字段为b_dev
	 */
	bh->b_bdev = I_BDEV(inode);
	/**
	 * 设置缓冲区首部的b_blocknr字段为文件块号。
	 */
	bh->b_blocknr = iblock;
	/**
	 * 设置缓冲区首部的BH_Mapped标志，以表明缓冲区首部的b_dev和b_blocknr字段是有效的。
	 */
	set_buffer_mapped(bh);
	return 0;
}

static int
blkdev_get_blocks(struct inode *inode, sector_t iblock,
		unsigned long max_blocks, struct buffer_head *bh, int create)
{
	sector_t end_block = max_block(I_BDEV(inode));

	if ((iblock + max_blocks) > end_block) {
		max_blocks = end_block - iblock;
		if ((long)max_blocks <= 0) {
			if (create)
				return -EIO;	/* write fully beyond EOF */
			/*
			 * It is a read which is fully beyond EOF.  We return
			 * a !buffer_mapped buffer
			 */
			max_blocks = 0;
		}
	}

	bh->b_bdev = I_BDEV(inode);
	bh->b_blocknr = iblock;
	bh->b_size = max_blocks << inode->i_blkbits;
	if (max_blocks)
		set_buffer_mapped(bh);
	return 0;
}

static ssize_t
blkdev_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;

	return blockdev_direct_IO_no_locking(rw, iocb, inode, I_BDEV(inode),
				iov, offset, nr_segs, blkdev_get_blocks, NULL);
}

/**
 * 块设备的writepage方法。
 */
static int blkdev_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, blkdev_get_block, wbc);
}

/**
 * 块设备的readpage方法。
 */
static int blkdev_readpage(struct file * file, struct page * page)
{
	/**
	 * blkdev_get_block函数把相对于文件开始处的文件块号转换为相对于块设备开始处的逻辑块号。
	 * 对块设备来说，这两个值是一样的。
	 */
	return block_read_full_page(page, blkdev_get_block);
}

/**
 * 块设备文件的address_space对象的prepare_write方法
 * 它调用了block_prepare_write，唯一的差异是第二个参数。它是一个指向函数的指针，该函数把相对于文件开始处的文件块号转换为相对于块设备开始处的逻辑块号。
 */
static int blkdev_prepare_write(struct file *file, struct page *page, unsigned from, unsigned to)
{
	return block_prepare_write(page, from, to, blkdev_get_block);
}

/**
 * 实现块设备文件的commit_write方法
 */
static int blkdev_commit_write(struct file *file, struct page *page, unsigned from, unsigned to)
{
	return block_commit_write(page, from, to);
}

/*
 * private llseek:
 * for a block special file file->f_dentry->d_inode->i_size is zero
 * so we compute the size by hand (just as in block_read/write above)
 */
static loff_t block_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *bd_inode = file->f_mapping->host;
	loff_t size;
	loff_t retval;

	down(&bd_inode->i_sem);
	size = i_size_read(bd_inode);

	switch (origin) {
		case 2:
			offset += size;
			break;
		case 1:
			offset += file->f_pos;
	}
	retval = -EINVAL;
	if (offset >= 0 && offset <= size) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
		}
		retval = offset;
	}
	up(&bd_inode->i_sem);
	return retval;
}
	
/*
 *	Filp is never NULL; the only case when ->fsync() is called with
 *	NULL first argument is nfsd_sync_dir() and that's not a directory.
 */


static int block_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
	return sync_blockdev(I_BDEV(filp->f_mapping->host));
}

/*
 * pseudo-fs
 */

static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(bdev_lock);
static kmem_cache_t * bdev_cachep;

static struct inode *bdev_alloc_inode(struct super_block *sb)
{
	struct bdev_inode *ei = kmem_cache_alloc(bdev_cachep, SLAB_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void bdev_destroy_inode(struct inode *inode)
{
	struct bdev_inode *bdi = BDEV_I(inode);

	bdi->bdev.bd_inode_backing_dev_info = NULL;
	kmem_cache_free(bdev_cachep, bdi);
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
	struct bdev_inode *ei = (struct bdev_inode *) foo;
	struct block_device *bdev = &ei->bdev;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR)
	{
		memset(bdev, 0, sizeof(*bdev));
		sema_init(&bdev->bd_sem, 1);
		sema_init(&bdev->bd_mount_sem, 1);
		INIT_LIST_HEAD(&bdev->bd_inodes);
		INIT_LIST_HEAD(&bdev->bd_list);
		inode_init_once(&ei->vfs_inode);
	}
}

static inline void __bd_forget(struct inode *inode)
{
	list_del_init(&inode->i_devices);
	inode->i_bdev = NULL;
	inode->i_mapping = &inode->i_data;
}

static void bdev_clear_inode(struct inode *inode)
{
	struct block_device *bdev = &BDEV_I(inode)->bdev;
	struct list_head *p;
	spin_lock(&bdev_lock);
	while ( (p = bdev->bd_inodes.next) != &bdev->bd_inodes ) {
		__bd_forget(list_entry(p, struct inode, i_devices));
	}
	list_del_init(&bdev->bd_list);
	spin_unlock(&bdev_lock);
}

static struct super_operations bdev_sops = {
	.statfs = simple_statfs,
	.alloc_inode = bdev_alloc_inode,
	.destroy_inode = bdev_destroy_inode,
	.drop_inode = generic_delete_inode,
	.clear_inode = bdev_clear_inode,
};

static struct super_block *bd_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_pseudo(fs_type, "bdev:", &bdev_sops, 0x62646576);
}

static struct file_system_type bd_type = {
	.name		= "bdev",
	.get_sb		= bd_get_sb,
	.kill_sb	= kill_anon_super,
};

static struct vfsmount *bd_mnt;
struct super_block *blockdev_superblock;

void __init bdev_cache_init(void)
{
	int err;
	bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
			0, SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|SLAB_PANIC,
			init_once, NULL);
	err = register_filesystem(&bd_type);
	if (err)
		panic("Cannot register bdev pseudo-fs");
	bd_mnt = kern_mount(&bd_type);
	err = PTR_ERR(bd_mnt);
	if (IS_ERR(bd_mnt))
		panic("Cannot create bdev pseudo-fs");
	blockdev_superblock = bd_mnt->mnt_sb;	/* For writeback */
}

/*
 * Most likely _very_ bad one - but then it's hardly critical for small
 * /dev and can be fixed when somebody will need really large one.
 * Keep in mind that it will be fed through icache hash function too.
 */
static inline unsigned long hash(dev_t dev)
{
	return MAJOR(dev)+MINOR(dev);
}

static int bdev_test(struct inode *inode, void *data)
{
	return BDEV_I(inode)->bdev.bd_dev == *(dev_t *)data;
}

static int bdev_set(struct inode *inode, void *data)
{
	BDEV_I(inode)->bdev.bd_dev = *(dev_t *)data;
	return 0;
}

/**
 * 所有的块设备描述符被插入在一个全局链表中，链表首部是由变量all_bdevs表示的。
 * 链表链表所用的指针位于块设备描述符的bd_list字段中。
 */
static LIST_HEAD(all_bdevs);

/**
 * 根据主次设备号获取块设备描述符的的地址。
 */
struct block_device *bdget(dev_t dev)
{
	struct block_device *bdev;
	struct inode *inode;

	/* 在dev文件系统中找到设备的inode */
	inode = iget5_locked(bd_mnt->mnt_sb, hash(dev),
			bdev_test, bdev_set, &dev);

	if (!inode)
		return NULL;

	bdev = &BDEV_I(inode)->bdev;

	if (inode->i_state & I_NEW) {
		bdev->bd_contains = NULL;
		bdev->bd_inode = inode;
		bdev->bd_block_size = (1 << inode->i_blkbits);
		bdev->bd_part_count = 0;
		bdev->bd_invalidated = 0;
		inode->i_mode = S_IFBLK;
		inode->i_rdev = dev;
		inode->i_bdev = bdev;
		inode->i_data.a_ops = &def_blk_aops;
		mapping_set_gfp_mask(&inode->i_data, GFP_USER);
		inode->i_data.backing_dev_info = &default_backing_dev_info;
		spin_lock(&bdev_lock);
		list_add(&bdev->bd_list, &all_bdevs);
		spin_unlock(&bdev_lock);
		unlock_new_inode(inode);
	}
	return bdev;
}

EXPORT_SYMBOL(bdget);

long nr_blockdev_pages(void)
{
	struct list_head *p;
	long ret = 0;
	spin_lock(&bdev_lock);
	list_for_each(p, &all_bdevs) {
		struct block_device *bdev;
		bdev = list_entry(p, struct block_device, bd_list);
		ret += bdev->bd_inode->i_mapping->nrpages;
	}
	spin_unlock(&bdev_lock);
	return ret;
}

void bdput(struct block_device *bdev)
{
	iput(bdev->bd_inode);
}

EXPORT_SYMBOL(bdput);

/**
 * 获得块设备描述符bdev的地址.该函数接收索引结点对象的地址
 */
static struct block_device *bd_acquire(struct inode *inode)
{
	struct block_device *bdev;
	spin_lock(&bdev_lock);
	bdev = inode->i_bdev;
	/**
	 * 检查索引结点对象的i_bdev字段是否不为NULL.
	 * 如果是,表明块设备文件已经打开了.该字段存放了相应块描述符的地址.
	 * 在这种情况下,增加bd_inode索引结点的引用计数器的值,并返回描述符inode->i_bdev的地址
	 */
	if (bdev && igrab(bdev->bd_inode)) {
		spin_unlock(&bdev_lock);
		return bdev;
	}

	/**
	 * 块设备文件没有被打开.根据设备文件的主设备号和次设备号,执行bdget获得描述符的地址.
	 * 如果描述符不存在,bdget就分配一个.当然,也可能存在描述符了(比如其他块设备文件已经访问了该块设备).
	 */
	spin_unlock(&bdev_lock);
	bdev = bdget(inode->i_rdev);
	if (bdev) {
		spin_lock(&bdev_lock);
		if (inode->i_bdev)
			__bd_forget(inode);
		/**
		 * 将描述符地址存放到inode->i_bdev中,以便加速将来对相同块设备文件的打开操作.
		 */
		inode->i_bdev = bdev;
		inode->i_mapping = bdev->bd_inode->i_mapping;
		/**
		 * 将索引结点插入到由bd_inodes确立的块设备描述符的已打开索引结点链表中
		 */
		list_add(&inode->i_devices, &bdev->bd_inodes);
		spin_unlock(&bdev_lock);
	}
	return bdev;
}

/* Call when you free inode */

void bd_forget(struct inode *inode)
{
	spin_lock(&bdev_lock);
	if (inode->i_bdev)
		__bd_forget(inode);
	spin_unlock(&bdev_lock);
}

/**
 * bd_claim函数将block_device的holder字段设置为一个特定的地址。
 */
int bd_claim(struct block_device *bdev, void *holder)
{
	int res;
	spin_lock(&bdev_lock);

	/* first decide result */
	if (bdev->bd_holder == holder)
		res = 0;	 /* already a holder */
	else if (bdev->bd_holder != NULL)
		res = -EBUSY; 	 /* held by someone else */
	else if (bdev->bd_contains == bdev)
		res = 0;  	 /* is a whole device which isn't held */

	else if (bdev->bd_contains->bd_holder == bd_claim)
		res = 0; 	 /* is a partition of a device that is being partitioned */
	else if (bdev->bd_contains->bd_holder != NULL)
		res = -EBUSY;	 /* is a partition of a held device */
	else
		res = 0;	 /* is a partition of an un-held device */

	/* now impose change */
	if (res==0) {
		/* note that for a whole device bd_holders
		 * will be incremented twice, and bd_holder will
		 * be set to bd_claim before being set to holder
		 */
		bdev->bd_contains->bd_holders ++;
		bdev->bd_contains->bd_holder = bd_claim;
		bdev->bd_holders++;
		bdev->bd_holder = holder;
	}
	spin_unlock(&bdev_lock);
	return res;
}

EXPORT_SYMBOL(bd_claim);

/**
 * bd_release将bdev的bd_holder字段设置为NULL
 */
void bd_release(struct block_device *bdev)
{
	spin_lock(&bdev_lock);
	if (!--bdev->bd_contains->bd_holders)
		bdev->bd_contains->bd_holder = NULL;
	if (!--bdev->bd_holders)
		bdev->bd_holder = NULL;
	spin_unlock(&bdev_lock);
}

EXPORT_SYMBOL(bd_release);

/*
 * Tries to open block device by device number.  Use it ONLY if you
 * really do not have anything better - i.e. when you are behind a
 * truly sucky interface and all you are given is a device number.  _Never_
 * to be used for internal purposes.  If you ever need it - reconsider
 * your API.
 */
struct block_device *open_by_devnum(dev_t dev, unsigned mode)
{
	struct block_device *bdev = bdget(dev);
	int err = -ENOMEM;
	int flags = mode & FMODE_WRITE ? O_RDWR : O_RDONLY;
	if (bdev)
		err = blkdev_get(bdev, mode, flags);
	return err ? ERR_PTR(err) : bdev;
}

EXPORT_SYMBOL(open_by_devnum);

/*
 * This routine checks whether a removable media has been changed,
 * and invalidates all buffer-cache-entries in that case. This
 * is a relatively slow routine, so we have to try to minimize using
 * it. Thus it is called only upon a 'mount' or 'open'. This
 * is the best way of combining speed and utility, I think.
 * People changing diskettes in the middle of an operation deserve
 * to lose :-)
 */
int check_disk_change(struct block_device *bdev)
{
	struct gendisk *disk = bdev->bd_disk;
	struct block_device_operations * bdops = disk->fops;

	if (!bdops->media_changed)
		return 0;
	if (!bdops->media_changed(bdev->bd_disk))
		return 0;

	if (__invalidate_device(bdev, 0))
		printk("VFS: busy inodes on changed media.\n");

	if (bdops->revalidate_disk)
		bdops->revalidate_disk(bdev->bd_disk);
	if (bdev->bd_disk->minors > 1)
		bdev->bd_invalidated = 1;
	return 1;
}

EXPORT_SYMBOL(check_disk_change);

void bd_set_size(struct block_device *bdev, loff_t size)
{
	unsigned bsize = bdev_hardsect_size(bdev);

	bdev->bd_inode->i_size = size;
	while (bsize < PAGE_CACHE_SIZE) {
		if (size & bsize)
			break;
		bsize <<= 1;
	}
	bdev->bd_block_size = bsize;
	bdev->bd_inode->i_blkbits = blksize_bits(bsize);
}
EXPORT_SYMBOL(bd_set_size);

static int do_open(struct block_device *bdev, struct file *file)
{
	struct module *owner = NULL;
	struct gendisk *disk;
	int ret = -ENXIO;
	int part;

	/**
	 * 在调用do_open前，blkdev_open会调用bd_acquire，在bd_acquire中
	 * inode->imapping字段会被设置为bdev索引结点中相应字段的值。该字段指向地址空间对象(address_space)
	 * 现在将它赋给f_mapping
	 */
	file->f_mapping = bdev->bd_inode->i_mapping;
	lock_kernel();
	/**
	 * 获取与块设备相关的gendisk描述符地址。
	 * 如果打开的块设备是一个分区，则返回的索引值存放在part中，否则part为0
	 * get_gendisk函数简单的在kobject映射域bdev_map上调用kobj_lookup来传递设备的主设备号和次设备号。
	 */
	disk = get_gendisk(bdev->bd_dev, &part);
	if (!disk) {
		unlock_kernel();
		bdput(bdev);
		return ret;
	}
	owner = disk->fops->owner;

	down(&bdev->bd_sem);
	/**
	 * bdev->bd_openers!=0表示设备已经打开。
	 */
	if (!bdev->bd_openers) {/* 还没有打开 */
		/**
		 * 第一次访问，以前没有打开过
		 * 就初始化它的bd_disk
		 */
		bdev->bd_disk = disk;
		bdev->bd_contains = bdev;
		if (!part) {/* 是一个整盘，而不是分区 */
			struct backing_dev_info *bdi;
			if (disk->fops->open) {
				/**
				 * 该盘定义了打开方法。就执行它
				 * 该方法是由块设备驱动程序定义的定制函数。
				 */
				ret = disk->fops->open(bdev->bd_inode, file);
				if (ret)
					goto out_first;
			}
			if (!bdev->bd_openers) {
				bd_set_size(bdev,(loff_t)get_capacity(disk)<<9);
				bdi = blk_get_backing_dev_info(bdev);
				if (bdi == NULL)
					bdi = &default_backing_dev_info;
				bdev->bd_inode->i_data.backing_dev_info = bdi;
			}
			if (bdev->bd_invalidated)
				rescan_partitions(disk, bdev);
		} else {/* 设备是一个分区 */
		 
			struct hd_struct *p;
			struct block_device *whole;
			/**
			 * 再次调用bdget_disk。这次参数不一样
			 * 获得整盘的块描述符地址whole
			 */
			whole = bdget_disk(disk, 0);
			ret = -ENOMEM;
			if (!whole)
				goto out_first;
			ret = blkdev_get(whole, file->f_mode, file->f_flags);
			if (ret)
				goto out_first;
			/**
			 * 设置描述符:dev是分区，则指向分区所在整盘描述符
			 * 否则指向块设备描述符
			 */
			bdev->bd_contains = whole;
			down(&whole->bd_sem);
			/**
			 * 增加bd_part_count从而说明磁盘分区上新的打开操作。
			 */
			whole->bd_part_count++;
			/**
			 * 用disk->part[part - 1]的值设置bdev->bd_part
			 * 它是分区描述符hd_struct的地址。
			 */
			p = disk->part[part - 1];
			bdev->bd_inode->i_data.backing_dev_info =
			   whole->bd_inode->i_data.backing_dev_info;
			if (!(disk->flags & GENHD_FL_UP) || !p || !p->nr_sects) {
				whole->bd_part_count--;
				up(&whole->bd_sem);
				ret = -ENXIO;
				goto out_first;
			}
			/**
			 * 增加分区引用计数器的值。
			 */
			kobject_get(&p->kobj);
			bdev->bd_part = p;
			/**
			 * 设置索引结点中分区大小和扇区大小
			 */
			bd_set_size(bdev, (loff_t) p->nr_sects << 9);
			up(&whole->bd_sem);
		}
	} else {
		/** 
		 * 设备已经打开了
		 */
		put_disk(disk);
		module_put(owner);
		/**
		 * bdev->bd_contains == bdev表示设备是一个整盘
		 */
		if (bdev->bd_contains == bdev) {
			/**
			 * 调用块设备的open方法。
			 */
			if (bdev->bd_disk->fops->open) {
				ret = bdev->bd_disk->fops->open(bdev->bd_inode, file);
				if (ret)
					goto out;
			}
			/**
			 * 检查bdev->bd_invalidated，如果有必要就调用rescan_partitions
			 * 如果设置了bdev->bd_invalidated就调用rescan_partitions扫描分区表并更新分区描述符。
			 * 该标志是由check_disk_change块设备方法设备的，仅适用于可移动设备(U盘、软盘??)。
			 */
			if (bdev->bd_invalidated)
				rescan_partitions(bdev->bd_disk, bdev);
		} else {
			down(&bdev->bd_contains->bd_sem);
			bdev->bd_contains->bd_part_count++;
			up(&bdev->bd_contains->bd_sem);
		}
	}
	/**
	 * 无论如何，都增加打开计数
	 */
	bdev->bd_openers++;
	up(&bdev->bd_sem);
	unlock_kernel();
	return 0;

out_first:
	bdev->bd_disk = NULL;
	bdev->bd_inode->i_data.backing_dev_info = &default_backing_dev_info;
	if (bdev != bdev->bd_contains)
		blkdev_put(bdev->bd_contains);
	bdev->bd_contains = NULL;
	put_disk(disk);
	module_put(owner);
out:
	up(&bdev->bd_sem);
	unlock_kernel();
	if (ret)
		bdput(bdev);
	return ret;
}

int blkdev_get(struct block_device *bdev, mode_t mode, unsigned flags)
{
	/*
	 * This crockload is due to bad choice of ->open() type.
	 * It will go away.
	 * For now, block device ->open() routine must _not_
	 * examine anything in 'inode' argument except ->i_rdev.
	 */
	struct file fake_file = {};
	struct dentry fake_dentry = {};
	fake_file.f_mode = mode;
	fake_file.f_flags = flags;
	fake_file.f_dentry = &fake_dentry;
	fake_dentry.d_inode = bdev->bd_inode;

	return do_open(bdev, &fake_file);
}

EXPORT_SYMBOL(blkdev_get);

/**
 * 块设备文件的缺省操作-open
 */
static int blkdev_open(struct inode * inode, struct file * filp)
{
	struct block_device *bdev;
	int res;

	/*
	 * Preserve backwards compatibility and allow large file access
	 * even if userspace doesn't ask for it explicitly. Some mkfs
	 * binary needs it. We might want to drop this workaround
	 * during an unstable branch.
	 */
	filp->f_flags |= O_LARGEFILE;

	/**
	 * 执行bd_acquire从而获得块设备描述符bdev的地址。
	 */
	bdev = bd_acquire(inode);

	res = do_open(bdev, filp);
	if (res)
		return res;

	/**
	 * 不是独占打开，就返回了
	 */
	if (!(filp->f_flags & O_EXCL) )
		return 0;

	/**
	 * 否则是独占打开，就调用bd_claim设置块设备的持有者。
	 */
	if (!(res = bd_claim(bdev, filp)))
		return 0;

	/**
	 * bd_claim失败了，说明已经被其他人占有了，就释放块设备描述符并返回错误。
	 */
	blkdev_put(bdev);
	return res;
}

int blkdev_put(struct block_device *bdev)
{
	int ret = 0;
	struct inode *bd_inode = bdev->bd_inode;
	struct gendisk *disk = bdev->bd_disk;

	down(&bdev->bd_sem);
	lock_kernel();
	if (!--bdev->bd_openers) {
		sync_blockdev(bdev);
		kill_bdev(bdev);
	}
	if (bdev->bd_contains == bdev) {
		if (disk->fops->release)
			ret = disk->fops->release(bd_inode, NULL);
	} else {
		down(&bdev->bd_contains->bd_sem);
		bdev->bd_contains->bd_part_count--;
		up(&bdev->bd_contains->bd_sem);
	}
	if (!bdev->bd_openers) {
		struct module *owner = disk->fops->owner;

		put_disk(disk);
		module_put(owner);

		if (bdev->bd_contains != bdev) {
			kobject_put(&bdev->bd_part->kobj);
			bdev->bd_part = NULL;
		}
		bdev->bd_disk = NULL;
		bdev->bd_inode->i_data.backing_dev_info = &default_backing_dev_info;
		if (bdev != bdev->bd_contains) {
			blkdev_put(bdev->bd_contains);
		}
		bdev->bd_contains = NULL;
	}
	unlock_kernel();
	up(&bdev->bd_sem);
	bdput(bdev);
	return ret;
}

EXPORT_SYMBOL(blkdev_put);

/**
 * 缺省的块设备文件操作方法-release
 */
static int blkdev_close(struct inode * inode, struct file * filp)
{
	struct block_device *bdev = I_BDEV(filp->f_mapping->host);
	if (bdev->bd_holder == filp)
		bd_release(bdev);
	return blkdev_put(bdev);
}

static ssize_t blkdev_file_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct iovec local_iov = { .iov_base = (void __user *)buf, .iov_len = count };

	return generic_file_write_nolock(file, &local_iov, 1, ppos);
}

/**
 * 缺省的块设备文件操作-aio_write
 */
static ssize_t blkdev_file_aio_write(struct kiocb *iocb, const char __user *buf,
				   size_t count, loff_t pos)
{
	struct iovec local_iov = { .iov_base = (void __user *)buf, .iov_len = count };

	return generic_file_aio_write_nolock(iocb, &local_iov, 1, &iocb->ki_pos);
}

static int block_ioctl(struct inode *inode, struct file *file, unsigned cmd,
			unsigned long arg)
{
	return blkdev_ioctl(file->f_mapping->host, file, cmd, arg);
}

struct address_space_operations def_blk_aops = {
	.readpage	= blkdev_readpage,
	.writepage	= blkdev_writepage,
	.sync_page	= block_sync_page,
	.prepare_write	= blkdev_prepare_write,
	.commit_write	= blkdev_commit_write,
	.writepages	= generic_writepages,
	.direct_IO	= blkdev_direct_IO,
};

/**
 * 处理设备文件的VFS时，dentry_open函数会定制文件对象的方法。它的f_op字段设置为表def_blk_fops的地址
 */
struct file_operations def_blk_fops = {
	.open		= blkdev_open,
	.release	= blkdev_close,
	.llseek		= block_llseek,
	.read		= generic_file_read,
	.write		= blkdev_file_write,
  	.aio_read	= generic_file_aio_read,
  	.aio_write	= blkdev_file_aio_write, 
	.mmap		= generic_file_mmap,
	.fsync		= block_fsync,
	.ioctl		= block_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_blkdev_ioctl,
#endif
	.readv		= generic_file_readv,
	.writev		= generic_file_write_nolock,
	.sendfile	= generic_file_sendfile,
};

int ioctl_by_bdev(struct block_device *bdev, unsigned cmd, unsigned long arg)
{
	int res;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	res = blkdev_ioctl(bdev->bd_inode, NULL, cmd, arg);
	set_fs(old_fs);
	return res;
}

EXPORT_SYMBOL(ioctl_by_bdev);

/**
 * lookup_bdev  - lookup a struct block_device by name
 *
 * @path:	special file representing the block device
 *
 * Get a reference to the blockdevice at @path in the current
 * namespace if possible and return it.  Return ERR_PTR(error)
 * otherwise.
 */
struct block_device *lookup_bdev(const char *path)
{
	struct block_device *bdev;
	struct inode *inode;
	struct nameidata nd;
	int error;

	if (!path || !*path)
		return ERR_PTR(-EINVAL);

	error = path_lookup(path, LOOKUP_FOLLOW, &nd);
	if (error)
		return ERR_PTR(error);

	inode = nd.dentry->d_inode;
	error = -ENOTBLK;
	if (!S_ISBLK(inode->i_mode))
		goto fail;
	error = -EACCES;
	if (nd.mnt->mnt_flags & MNT_NODEV)
		goto fail;
	error = -ENOMEM;
	bdev = bd_acquire(inode);
	if (!bdev)
		goto fail;
out:
	path_release(&nd);
	return bdev;
fail:
	bdev = ERR_PTR(error);
	goto out;
}

/**
 * open_bdev_excl  -  open a block device by name and set it up for use
 *
 * @path:	special file representing the block device
 * @flags:	%MS_RDONLY for opening read-only
 * @holder:	owner for exclusion
 *
 * Open the blockdevice described by the special file at @path, claim it
 * for the @holder.
 */
struct block_device *open_bdev_excl(const char *path, int flags, void *holder)
{
	struct block_device *bdev;
	mode_t mode = FMODE_READ;
	int error = 0;

	bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		return bdev;

	if (!(flags & MS_RDONLY))
		mode |= FMODE_WRITE;
	error = blkdev_get(bdev, mode, 0);
	if (error)
		return ERR_PTR(error);
	error = -EACCES;
	if (!(flags & MS_RDONLY) && bdev_read_only(bdev))
		goto blkdev_put;
	error = bd_claim(bdev, holder);
	if (error)
		goto blkdev_put;

	return bdev;
	
blkdev_put:
	blkdev_put(bdev);
	return ERR_PTR(error);
}

EXPORT_SYMBOL(open_bdev_excl);

/**
 * close_bdev_excl  -  release a blockdevice openen by open_bdev_excl()
 *
 * @bdev:	blockdevice to close
 *
 * This is the counterpart to open_bdev_excl().
 */
void close_bdev_excl(struct block_device *bdev)
{
	bd_release(bdev);
	blkdev_put(bdev);
}

EXPORT_SYMBOL(close_bdev_excl);
