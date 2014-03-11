/*
 *  linux/fs/char_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/config.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/devfs_fs_kernel.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif

/**
 * kobj_map包含一个散列表，它有255个表项。并由0-255范围的主设备号进行索引。
 * 散列表存放probe类型的对象。每个对象都拥有一个已经注册的主设备号和次设备号。
 * cdev_map是字符设备的kobject映射域。
 */
static struct kobj_map *cdev_map;

#define MAX_PROBE_HASH 255	/* random */

static DEFINE_RWLOCK(chrdevs_lock);

/**
 * 为了记录已经分配哪些字符设备号，内核使用散列表chrdevs，表的大小不超过设备号范围。
 * 两个不同的设备号范围可能共享同一个主设备号，但是范围不能重叠。
 * chrdevs包含255个表项，由于散列函数屏蔽了主设备号的高四位，因此需要将设备进行散列。
 * 冲突链表的每一项是一个char_device_struct
 */
static struct char_device_struct {
	/**
	 * 冲突链表中下一个元素的指针
	 */
	struct char_device_struct *next;
	/**
	 * 设备号范围内的主设备号
	 */
	unsigned int major;
	/**
	 * 设备号范围内的初始次设备号
	 */
	unsigned int baseminor;
	/**
	 * 设备号范围的大小
	 */
	int minorct;
	/**
	 * 处理设备号范围内的设备驱动程序的名称
	 */
	const char *name;
	/**
	 * 没有使用
	 */
	struct file_operations *fops;
	/**
	 * 指向字符设备驱动程序描述符的指针
	 */
	struct cdev *cdev;		/* will die */
} *chrdevs[MAX_PROBE_HASH];

/* index in the above */
static inline int major_to_index(int major)
{
	return major % MAX_PROBE_HASH;
}

/* get char device names in somewhat random order */
int get_chrdev_list(char *page)
{
	struct char_device_struct *cd;
	int i, len;

	len = sprintf(page, "Character devices:\n");

	read_lock(&chrdevs_lock);
	for (i = 0; i < ARRAY_SIZE(chrdevs) ; i++) {
		for (cd = chrdevs[i]; cd; cd = cd->next)
			len += sprintf(page+len, "%3d %s\n",
				       cd->major, cd->name);
	}
	read_unlock(&chrdevs_lock);

	return len;
}

/*
 * Register a single major with a specified minor range.
 *
 * If major == 0 this functions will dynamically allocate a major and return
 * its number.
 *
 * If major > 0 this function will attempt to reserve the passed range of
 * minors and will return zero on success.
 *
 * Returns a -ve errno on failure.
 */
/**
 * 为字符设备驱动程序分配一个范围内的设备号。所有新的驱动程序都使用而且应当使用这种方法而不是register_chrdev
 */
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
			   int minorct, const char *name)
{
	struct char_device_struct *cd, **cp;
	int ret = 0;
	int i;

	/**
	 * 分配一个新结构并用0填充
	 */
	cd = kmalloc(sizeof(struct char_device_struct), GFP_KERNEL);
	if (cd == NULL)
		return ERR_PTR(-ENOMEM);

	memset(cd, 0, sizeof(struct char_device_struct));

	write_lock_irq(&chrdevs_lock);

	/* temporary */
	/**
	 * 主设备号为0，那么请求动态分配一个设备号
	 * 从末尾项开始继续向前寻找一个尚未使用的主设备号对应的空冲突链表，没有找到就返回错误
	 */
	if (major == 0) {
		for (i = ARRAY_SIZE(chrdevs)-1; i > 0; i--) {
			if (chrdevs[i] == NULL)
				break;
		}

		if (i == 0) {
			ret = -EBUSY;
			goto out;
		}
		major = i;
		ret = major;
	}

	/**
	 * 初始化char_device_struct结构中的初始设备号、范围大小、驱动程序名称
	 */
	cd->major = major;
	cd->baseminor = baseminor;
	cd->minorct = minorct;
	cd->name = name;

	/**
	 * 执行散列函数计算与主设备号对应的散列表索引
	 */
	i = major_to_index(major);

	/**
	 * 遍历冲突链表，为新的结构寻找正确的位置
	 */
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major > major ||
		    ((*cp)->major == major && (*cp)->baseminor >= baseminor))
			break;
	/**
	 * 如果找到与请求的设备号范围重叠的范围，则返回错误
	 */
	if (*cp && (*cp)->major == major &&
	    (*cp)->baseminor < baseminor + minorct) {
		ret = -EBUSY;
		goto out;
	}
	cd->next = *cp;
	*cp = cd;
	write_unlock_irq(&chrdevs_lock);
	return cd;
out:
	write_unlock_irq(&chrdevs_lock);
	kfree(cd);
	return ERR_PTR(ret);
}

static struct char_device_struct *
__unregister_chrdev_region(unsigned major, unsigned baseminor, int minorct)
{
	struct char_device_struct *cd = NULL, **cp;
	int i = major_to_index(major);

	write_lock_irq(&chrdevs_lock);
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major == major &&
		    (*cp)->baseminor == baseminor &&
		    (*cp)->minorct == minorct)
			break;
	if (*cp) {
		cd = *cp;
		*cp = cd->next;
	}
	write_unlock_irq(&chrdevs_lock);
	return cd;
}

/**
 * register_chrdev_region接收三个参数：初始设备号，设备号范围大小，驱动名称
 * 为字符设备分配设备号。新驱动都应当使用这个方法。
 */
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
	struct char_device_struct *cd;
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		cd = __register_chrdev_region(MAJOR(n), MINOR(n),
			       next - n, name);
		if (IS_ERR(cd))
			goto fail;
	}
	return 0;
fail:
	to = n;
	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
	return PTR_ERR(cd);
}

/**
 * alloc_chrdev_region与register_chrdev_region类似，但是它可以动态的分配一个主设备号。
 * 它接收的参数为设备号范围内的初始次设备号，范围的大小及驱动程序的名称。
 */
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{
	struct char_device_struct *cd;
	cd = __register_chrdev_region(0, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	*dev = MKDEV(cd->major, cd->baseminor);
	return 0;
}

/**
 * 注册一个字符设备驱动程序的老方法。
 * 为给定的主设备号注册0－255为次设备号。并为每个设备建立一个对应的默认cdev结构。
 * 使用这一接口的驱动程序能够处理所有256个次设备号上的open调用(即使没有对应的实际设备)，也不能使用大于255的主设备号和次设备号。
 *		major:		设备的主设备号。
 *		name:		驱动程序的名称。
 *		fops:		默认的file_operations结构。
 */
int register_chrdev(unsigned int major, const char *name,
		    struct file_operations *fops)
{
	struct char_device_struct *cd;
	struct cdev *cdev;
	char *s;
	int err = -ENOMEM;

	/**
	 * 分配请求的设备号范围。
	 */
	cd = __register_chrdev_region(major, 0, 256, name);
	if (IS_ERR(cd))/* 设备号冲突，返回。 */
		return PTR_ERR(cd);

	/* 为设备驱动程序分配一个新的cdev结构 */
	cdev = cdev_alloc();
	if (!cdev)
		goto out2;

	/* 初始化cdev结构 */
	cdev->owner = fops->owner;
	cdev->ops = fops;
	kobject_set_name(&cdev->kobj, "%s", name);
	for (s = strchr(kobject_name(&cdev->kobj),'/'); s; s = strchr(s, '/'))
		*s = '!';

	/* 将设备添加到设备驱动模型中 */
	err = cdev_add(cdev, MKDEV(cd->major, 0), 256);
	if (err)
		goto out;

	cd->cdev = cdev;

	return major ? 0 : cd->major;
out:
	kobject_put(&cdev->kobj);
out2:
	kfree(__unregister_chrdev_region(cd->major, 0, 256));
	return err;
}

/**
 * 与register_chrdev设备对应的移除函数。
 */
void unregister_chrdev_region(dev_t from, unsigned count)
{
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
}

int unregister_chrdev(unsigned int major, const char *name)
{
	struct char_device_struct *cd;
	cd = __unregister_chrdev_region(major, 0, 256);
	if (cd && cd->cdev)
		cdev_del(cd->cdev);
	kfree(cd);
	return 0;
}

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
	struct module *owner = p->owner;
	struct kobject *kobj;

	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get(&p->kobj);
	if (!kobj)
		module_put(owner);
	return kobj;
}

void cdev_put(struct cdev *p)
{
	if (p) {
		kobject_put(&p->kobj);
		module_put(p->owner);
	}
}

/*
 * Called every time a character special file is opened
 */
/**
 * 字符设备的打开方法。open调用触发dentry_open，dentry_open调用def_chr_fops表中的open字段即本方法。
 * inode-索引结点的地址
 * filp-打开的文件指针
 */
int chrdev_open(struct inode * inode, struct file * filp)
{
	struct cdev *p;
	struct cdev *new = NULL;
	int ret = 0;

	spin_lock(&cdev_lock);
	/**
	 * 检查inode->i_cdev,如果不为空，表示inode结构已经被访问，则增加cdev的引用计数
	 */
	p = inode->i_cdev;
	if (!p) {
		struct kobject *kobj;
		int idx;
		spin_unlock(&cdev_lock);
		/**
		 * 调用kobj_lookup搜索包括该设备号在内的范围。
		 */
		kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
		/**
		 * 该范围不存在，直接返回错误
		 */
		if (!kobj)
			return -ENXIO;
		/**
		 * 范围存在，计算与该范围相对应的cdev描述符的地址。
		 */
		new = container_of(kobj, struct cdev, kobj);
		spin_lock(&cdev_lock);
		p = inode->i_cdev;
		if (!p) {
			/**
			 * inode没有被访问过，将找到的cdev描述符地址作为inode->i_cdev
			 */
			inode->i_cdev = p = new;
			/**
			 * 并设置i_cindex
			 */
			inode->i_cindex = idx;
			/**
			 * 将inode对象加入到cdev描述符的list链表中
			 */
			list_add(&inode->i_devices, &p->list);
			new = NULL;
		} else if (!cdev_get(p))
			ret = -ENXIO;
	} else if (!cdev_get(p))
		ret = -ENXIO;
	spin_unlock(&cdev_lock);
	cdev_put(new);
	if (ret)
		return ret;
	/**
	 * 初始化文件操作指针
	 */
	filp->f_op = fops_get(p->ops);
	if (!filp->f_op) {
		cdev_put(p);
		return -ENXIO;
	}
	/**
	 * 定义了open方法，就执行它。
	 */
	if (filp->f_op->open) {
		lock_kernel();
		/**
		 * 如果设备驱动程序处理一个以上的设备号，则本函数一般会再次设置file的f_op
		 */
		ret = filp->f_op->open(inode,filp);
		unlock_kernel();
	}
	if (ret)
		cdev_put(p);
	/**
	 * 成功完成了所有任务，返回0或者filp->f_op->open的结果
	 */
	return ret;
}

void cd_forget(struct inode *inode)
{
	spin_lock(&cdev_lock);
	list_del_init(&inode->i_devices);
	inode->i_cdev = NULL;
	spin_unlock(&cdev_lock);
}

void cdev_purge(struct cdev *cdev)
{
	spin_lock(&cdev_lock);
	while (!list_empty(&cdev->list)) {
		struct inode *inode;
		inode = container_of(cdev->list.next, struct inode, i_devices);
		list_del_init(&inode->i_devices);
		inode->i_cdev = NULL;
	}
	spin_unlock(&cdev_lock);
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the special file...
 */
struct file_operations def_chr_fops = {
	.open = chrdev_open,
};

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
	struct cdev *p = data;
	return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
	struct cdev *p = data;
	return cdev_get(p) ? 0 : -1;
}

/**
 * 在设备驱动程序模型中注册一个cdev描述符。
 * 它初始化cdev描述符中的dev和count字段，然后调用kobj_map函数。
 * kobj_map依次建立设备驱动程序模型的数据结构，把设备号范围复制到设备驱动程序的描述符中。
 * count经常为1，但是也有特殊情况。如SCSI磁带驱动程序，它通常每个物理设备的多个次设备号允许用户空间选择不同的操作模式(如密度)
 */
int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	p->dev = dev;
	p->count = count;
	return kobj_map(cdev_map, dev, count, NULL, exact_match, exact_lock, p);
}

static void cdev_unmap(dev_t dev, unsigned count)
{
	kobj_unmap(cdev_map, dev, count);
}

/**
 * 从系统中移除一个字符设备。
 */
void cdev_del(struct cdev *p)
{
	cdev_unmap(p->dev, p->count);
	kobject_put(&p->kobj);
}


static decl_subsys(cdev, NULL, NULL);

static void cdev_default_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
}

static void cdev_dynamic_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
	kfree(p);
}

static struct kobj_type ktype_cdev_default = {
	.release	= cdev_default_release,
};

static struct kobj_type ktype_cdev_dynamic = {
	.release	= cdev_dynamic_release,
};

/**
 * 动态分配cdev描述符，并初始化内嵌的kobject数据结构。
 */
struct cdev *cdev_alloc(void)
{
	struct cdev *p = kmalloc(sizeof(struct cdev), GFP_KERNEL);
	if (p) {
		memset(p, 0, sizeof(struct cdev));
		p->kobj.ktype = &ktype_cdev_dynamic;
		INIT_LIST_HEAD(&p->list);
		kobject_init(&p->kobj);
	}
	return p;
}

/**
 * 初始化cdev描述符。当cdev描述符是嵌入在其他结构中时，这是有用的方法。
 */
void cdev_init(struct cdev *cdev, struct file_operations *fops)
{
	memset(cdev, 0, sizeof *cdev);
	INIT_LIST_HEAD(&cdev->list);
	cdev->kobj.ktype = &ktype_cdev_default;
	kobject_init(&cdev->kobj);
	cdev->ops = fops;
}

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("char-major-%d", MAJOR(dev));
	return NULL;
}

void __init chrdev_init(void)
{
/*
 * Keep cdev_subsys around because (and only because) the kobj_map code
 * depends on the rwsem it contains.  We don't make it public in sysfs,
 * however.
 */
	subsystem_init(&cdev_subsys);
	cdev_map = kobj_map_init(base_probe, &cdev_subsys);
}


/* Let modules do char dev stuff */
EXPORT_SYMBOL(register_chrdev_region);
EXPORT_SYMBOL(unregister_chrdev_region);
EXPORT_SYMBOL(alloc_chrdev_region);
EXPORT_SYMBOL(cdev_init);
EXPORT_SYMBOL(cdev_alloc);
EXPORT_SYMBOL(cdev_del);
EXPORT_SYMBOL(cdev_add);
EXPORT_SYMBOL(register_chrdev);
EXPORT_SYMBOL(unregister_chrdev);
