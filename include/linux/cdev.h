#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H
#ifdef __KERNEL__

/**
 * 字符设备驱动程序描述符
 */
struct cdev {
	/**
	 * 内嵌的kobject
	 */
	struct kobject kobj;
	/**
	 * 指向实现驱动程序模块的指针(如果有的话)
	 */
	struct module *owner;
	/**
	 * 指向设备驱动程序文件操作表的指针
	 */
	struct file_operations *ops;
	/**
	 * 与字符设备文件对应的索引结点链表的头
	 */
	struct list_head list;
	/**
	 * 给设备驱动程序所分配的初始主设备呈和次设备号
	 */
	dev_t dev;
	/**
	 * 给设备驱动程序所分配的设备号范围的大小
	 */
	unsigned int count;
};

void cdev_init(struct cdev *, struct file_operations *);

struct cdev *cdev_alloc(void);

void cdev_put(struct cdev *p);

int cdev_add(struct cdev *, dev_t, unsigned);

void cdev_del(struct cdev *);

void cd_forget(struct inode *);

#endif
#endif
