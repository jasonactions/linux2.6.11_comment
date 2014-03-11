/*
 * device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 *
 * This file is released under the GPLv2
 *
 * See Documentation/driver-model/ for more information.
 */

#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <linux/config.h>
#include <linux/ioport.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <asm/semaphore.h>
#include <asm/atomic.h>

#define DEVICE_NAME_SIZE	50
#define DEVICE_NAME_HALF	__stringify(20)	/* Less than half to accommodate slop */
#define DEVICE_ID_SIZE		32
#define BUS_ID_SIZE		KOBJ_NAME_LEN


enum {
	SUSPEND_NOTIFY,
	SUSPEND_SAVE_STATE,
	SUSPEND_DISABLE,
	SUSPEND_POWER_DOWN,
};

enum {
	RESUME_POWER_ON,
	RESUME_RESTORE_STATE,
	RESUME_ENABLE,
};

struct device;
struct device_driver;
struct class;
struct class_device;
struct class_simple;

/**
 * 内核所支持的每一种总线类型都由一个bus_type描述。
 */
struct bus_type {
	/**
	 * 总线类型的名称。例如"pci"
	 */
	char			* name;

	/**
	 * 与总线类型相关的kobject子系统。这些子系统并不在sysfs的顶层。
	 * 一个总线包含两个kset，分别代表了总线的驱动程序和插入总线的所有设备。
	 */
	struct subsystem	subsys;
	/**
	 * 驱动程序的kobject集合
	 */
	struct kset		drivers;
	/**
	 * 设备的kobject集合
	 */
	struct kset		devices;

	/**
	 * 指向对象的指针，该对象包含总线属性和用于导出此属性到sysfs文件系统的方法
	 */
	struct bus_attribute	* bus_attrs;
	/**
	 * 指向对象的指针，该对象包含设备属性和用于导出此属性到sysfs文件系统的方法
	 */
	struct device_attribute	* dev_attrs;
	/**
	 * 指向对象的指针，该对象包含驱动程序属性和用于导出此属性到sysfs文件系统的方法
	 */
	struct driver_attribute	* drv_attrs;

	/**
	 * 检验给定的设备驱动程序是否支持特定设备的方法.
	 * 当一个总线上的新设备或者新驱动程序被添加时，会一次或多次调用这个函数。如果指定的驱动程序能够处理指定的设备，该函数返回非0值。
	 */
	int		(*match)(struct device * dev, struct device_driver * drv);
	/**
	 * 注册设备时调用的方法
	 * 在为用户空间产生热插拨事件前，这个方法允许总线添加环境变量。
	 */
	int		(*hotplug) (struct device *dev, char **envp, 
				    int num_envp, char *buffer, int buffer_size);
	/**
	 * 保存硬件设备的上下文状态并改变设备供电状态的方法
	 */
	int		(*suspend)(struct device * dev, pm_message_t state);
	/**
	 * 改变供电状态和恢复硬件设备上下文的方法
	 */
	int		(*resume)(struct device * dev);
};

extern int bus_register(struct bus_type * bus);
extern void bus_unregister(struct bus_type * bus);

extern int bus_rescan_devices(struct bus_type * bus);

extern struct bus_type * get_bus(struct bus_type * bus);
extern void put_bus(struct bus_type * bus);

extern struct bus_type * find_bus(char * name);

/* iterator helpers for buses */

int bus_for_each_dev(struct bus_type * bus, struct device * start, void * data,
		     int (*fn)(struct device *, void *));

int bus_for_each_drv(struct bus_type * bus, struct device_driver * start, 
		     void * data, int (*fn)(struct device_driver *, void *));


/* driverfs interface for exporting bus attributes */
/**
 * 总线属性。
 */
struct bus_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct bus_type *, char * buf);
	ssize_t (*store)(struct bus_type *, const char * buf, size_t count);
};

/**
 * 定义一个总线属性。
 */
#define BUS_ATTR(_name,_mode,_show,_store)	\
struct bus_attribute bus_attr_##_name = __ATTR(_name,_mode,_show,_store)

extern int bus_create_file(struct bus_type *, struct bus_attribute *);
extern void bus_remove_file(struct bus_type *, struct bus_attribute *);

/**
 * 驱动程序描述符
 */
struct device_driver {
	/**
	 * 驱动程序的名称
	 */
	char			* name;
	/**
	 * 指向总线描述符的指针。
	 */
	struct bus_type		* bus;

	/**
	 * 禁止卸载设备驱动程序的信号量。
	 */
	struct semaphore	unload_sem;
	/**
	 * 内嵌kobject
	 */
	struct kobject		kobj;
	/**
	 * 驱动程序所支持的所有设备组成的链表的首部。
	 */
	struct list_head	devices;

	/**
	 * 驱动程序所在模块（如果有的话）
	 */
	struct module 		* owner;

	/**
	 * 探测设备的方法
	 */
	int	(*probe)	(struct device * dev);
	/**
	 * 移走设备的方法（检测设备驱动程序是否可以控制该设备）
	 */
	int 	(*remove)	(struct device * dev);
	/**
	 * 设备断电时调用的方法。
	 */
	void	(*shutdown)	(struct device * dev);
	/**
	 * 设备置于低功率状态时所调用的方法
	 */
	int	(*suspend)	(struct device * dev, u32 state, u32 level);
	/**
	 * 设备恢复正常状态时所调用的方法
	 */
	int	(*resume)	(struct device * dev, u32 level);
};


extern int driver_register(struct device_driver * drv);
extern void driver_unregister(struct device_driver * drv);

extern struct device_driver * get_driver(struct device_driver * drv);
extern void put_driver(struct device_driver * drv);
extern struct device_driver *driver_find(const char *name, struct bus_type *bus);


/* driverfs interface for exporting driver attributes */
/**
 * 驱动程序属性。
 */
struct driver_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct device_driver *, char * buf);
	ssize_t (*store)(struct device_driver *, const char * buf, size_t count);
};

/**
 * 定义一个驱动程序属性。
 */
#define DRIVER_ATTR(_name,_mode,_show,_store)	\
struct driver_attribute driver_attr_##_name = __ATTR(_name,_mode,_show,_store)

extern int driver_create_file(struct device_driver *, struct driver_attribute *);
extern void driver_remove_file(struct device_driver *, struct driver_attribute *);


/*
 * device classes
 */
/**
 * 设备类。所有的类对象都属于与/sys/class目录相对应的class_subsys子系统。
 */
struct class {
	/**
	 * 类名称。将显示在/sys/class中。
	 */
	char			* name;

	struct subsystem	subsys;
	struct list_head	children;
	struct list_head	interfaces;

	/**
	 * 一个类被注册后，将创建该字段指向的数组中的所有属性。
	 */
	struct class_attribute		* class_attrs;
	/**
	 * 该类添加的设备的默认属性。
	 */
	struct class_device_attribute	* class_dev_attrs;

	/**
	 * 设备热插拨时，调用此回调函数为应用程序创建环境变量。
	 */
	int	(*hotplug)(struct class_device *dev, char **envp, 
			   int num_envp, char *buffer, int buffer_size);

	/**
	 * 把设备从类中删除时，调用release方法。
	 */
	void	(*release)(struct class_device *dev);
	/**
	 * 当类被释放时，调用此方法。
	 */
	void	(*class_release)(struct class *class);
};

extern int class_register(struct class *);
extern void class_unregister(struct class *);

extern struct class * class_get(struct class *);
extern void class_put(struct class *);


struct class_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct class *, char * buf);
	ssize_t (*store)(struct class *, const char * buf, size_t count);
};

#define CLASS_ATTR(_name,_mode,_show,_store)			\
struct class_attribute class_attr_##_name = __ATTR(_name,_mode,_show,_store) 

extern int class_create_file(struct class *, const struct class_attribute *);
extern void class_remove_file(struct class *, const struct class_attribute *);

/**
 * 
 */
struct class_device {
	struct list_head	node;

	struct kobject		kobj;
	struct class		* class;	/* required */
	struct device		* dev;		/* not necessary, but nice to have */
	void			* class_data;	/* class-specific data */

	char	class_id[BUS_ID_SIZE];	/* unique to this class */
};

static inline void *
class_get_devdata (struct class_device *dev)
{
	return dev->class_data;
}

static inline void
class_set_devdata (struct class_device *dev, void *data)
{
	dev->class_data = data;
}


extern int class_device_register(struct class_device *);
extern void class_device_unregister(struct class_device *);
extern void class_device_initialize(struct class_device *);
extern int class_device_add(struct class_device *);
extern void class_device_del(struct class_device *);

extern int class_device_rename(struct class_device *, char *);

extern struct class_device * class_device_get(struct class_device *);
extern void class_device_put(struct class_device *);

struct class_device_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct class_device *, char * buf);
	ssize_t (*store)(struct class_device *, const char * buf, size_t count);
};

#define CLASS_DEVICE_ATTR(_name,_mode,_show,_store)		\
struct class_device_attribute class_device_attr_##_name = 	\
	__ATTR(_name,_mode,_show,_store)

extern int class_device_create_file(struct class_device *, 
				    const struct class_device_attribute *);
extern void class_device_remove_file(struct class_device *, 
				     const struct class_device_attribute *);
extern int class_device_create_bin_file(struct class_device *,
					struct bin_attribute *);
extern void class_device_remove_bin_file(struct class_device *,
					 struct bin_attribute *);

struct class_interface {
	struct list_head	node;
	struct class		*class;

	int (*add)	(struct class_device *);
	void (*remove)	(struct class_device *);
};

extern int class_interface_register(struct class_interface *);
extern void class_interface_unregister(struct class_interface *);

/* interface for class simple stuff */
extern struct class_simple *class_simple_create(struct module *owner, char *name);
extern void class_simple_destroy(struct class_simple *cs);
extern struct class_device *class_simple_device_add(struct class_simple *cs, dev_t dev, struct device *device, const char *fmt, ...)
	__attribute__((format(printf,4,5)));
extern int class_simple_set_hotplug(struct class_simple *, 
	int (*hotplug)(struct class_device *dev, char **envp, int num_envp, char *buffer, int buffer_size));
extern void class_simple_device_remove(dev_t dev);


/**
 * 设备驱动程序模型中的每个设备由device表示
 */
struct device {
	/**
	 * 指向兄弟设备的指针
	 */
	struct list_head node;		/* node in sibling list */
	/**
	 * 指向连于同一类型总路线上的设备链表的指针。
	 */
	struct list_head bus_list;	/* node in bus's list */
	/**
	 * 指向设备驱动程序链表的指针。
	 */
	struct list_head driver_list;
	/**
	 * 子设备链表的首部
	 */
	struct list_head children;
	/**
	 * 指向父设备的指针
	 * 父设备。即该设备所属的设备。
	 * 大多数情况下，一个父设备通常是某种总线或者是宿主控制器。
	 * 如果parent为NULL，表示该设备是顶层设备。
	 */
	struct device 	* parent;

	/**
	 * 内嵌kobject。
	 * 通过该字段将设备连接到结构体系中。
	 * 作为通用准则，device->kobj->parent和device->parent->kobj是相同的。
	 */
	struct kobject kobj;
	/**
	 * 连接到总线上设备的位置
	 * 在总线上唯一标识该设备的字符串。如PCI设备使用了标准PCI ID格式，它包括:域编号、总线编号、设备编号和功能编号。
	 */
	char	bus_id[BUS_ID_SIZE];	/* position on parent bus */

	/**
	 * 指向所连接总线的指针
	 * 标识该设备连接在何种类型的总线上。
	 */
	struct bus_type	* bus;		/* type of bus device is on */
	/**
	 * 指向控制设备驱动程序的指针
	 */
	struct device_driver *driver;	/* which driver has allocated this
					   device */
	/**
	 * 指向驱动程序私有数据的指针
	 */
	void		*driver_data;	/* data private to the driver */
	
	/**
	 * 指向遗留设备驱动程序私有数据的指针
	 */
	void		*platform_data;	/* Platform specific data (e.g. ACPI,
					   BIOS data relevant to device) */
	/**
	 * 电源管理信息
	 */
	struct dev_pm_info	power;

	/**
	 * 卸载设备驱动程序时电源进入的状态
	 */
	u32		detach_state;	/* State to enter when device is
					   detached from its driver. */

	/**
	 * 指向设备的DMA屏蔽字的指针
	 */
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	/**
	 * 设备的一致性DMA的屏蔽字
	 */
	u64		coherent_dma_mask;/* Like dma_mask, but for
					     alloc_coherent mappings as
					     not all hardware supports
					     64 bit addresses for consistent
					     allocations such descriptors. */

	/**
	 * DMA缓冲池链表的首部
	 */
	struct list_head	dma_pools;	/* dma pools (if dma'ble) */

	/**
	 * 指向设备所使用的一致性DMA存储器描述符的指针
	 */
	struct dma_coherent_mem	*dma_mem; /* internal for coherent mem
					     override */

	/**
	 * 释放回调函数
	 */
	void	(*release)(struct device * dev);
};

static inline struct device *
list_to_dev(struct list_head *node)
{
	return list_entry(node, struct device, node);
}

static inline void *
dev_get_drvdata (struct device *dev)
{
	return dev->driver_data;
}

static inline void
dev_set_drvdata (struct device *dev, void *data)
{
	dev->driver_data = data;
}

/*
 * High level routines for use by the bus drivers
 */
extern int device_register(struct device * dev);
extern void device_unregister(struct device * dev);
extern void device_initialize(struct device * dev);
extern int device_add(struct device * dev);
extern void device_del(struct device * dev);
extern int device_for_each_child(struct device *, void *,
		     int (*fn)(struct device *, void *));

/*
 * Manual binding of a device to driver. See drivers/base/bus.c
 * for information on use.
 */
extern int  driver_probe_device(struct device_driver * drv, struct device * dev);
extern void device_bind_driver(struct device * dev);
extern void device_release_driver(struct device * dev);
extern int  device_attach(struct device * dev);
extern void driver_attach(struct device_driver * drv);


/* driverfs interface for exporting device attributes */

/**
 * 设备属性。
 */
struct device_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct device * dev, char * buf);
	ssize_t (*store)(struct device * dev, const char * buf, size_t count);
};

/**
 * 初始化一个设备属性。
 */
#define DEVICE_ATTR(_name,_mode,_show,_store) \
struct device_attribute dev_attr_##_name = __ATTR(_name,_mode,_show,_store)


extern int device_create_file(struct device *device, struct device_attribute * entry);
extern void device_remove_file(struct device * dev, struct device_attribute * attr);

/*
 * Platform "fixup" functions - allow the platform to have their say
 * about devices and actions that the general device layer doesn't
 * know about.
 */
/* Notify platform of device discovery */
extern int (*platform_notify)(struct device * dev);

extern int (*platform_notify_remove)(struct device * dev);


/**
 * get_device - atomically increment the reference count for the device.
 *
 */
extern struct device * get_device(struct device * dev);
extern void put_device(struct device * dev);
extern struct device *device_find(const char *name, struct bus_type *bus);


/* drivers/base/platform.c */

struct platform_device {
	char		* name;
	u32		id;
	struct device	dev;
	u32		num_resources;
	struct resource	* resource;
};

#define to_platform_device(x) container_of((x), struct platform_device, dev)

extern int platform_device_register(struct platform_device *);
extern void platform_device_unregister(struct platform_device *);

extern struct bus_type platform_bus_type;
extern struct device platform_bus;

extern struct resource *platform_get_resource(struct platform_device *, unsigned int, unsigned int);
extern int platform_get_irq(struct platform_device *, unsigned int);
extern struct resource *platform_get_resource_byname(struct platform_device *, unsigned int, char *);
extern int platform_get_irq_byname(struct platform_device *, char *);
extern int platform_add_devices(struct platform_device **, int);

extern struct platform_device *platform_device_register_simple(char *, unsigned int, struct resource *, unsigned int);

/* drivers/base/power.c */
extern void device_shutdown(void);


/* drivers/base/firmware.c */
extern int firmware_register(struct subsystem *);
extern void firmware_unregister(struct subsystem *);

/* debugging and troubleshooting/diagnostic helpers. */
#define dev_printk(level, dev, format, arg...)	\
	printk(level "%s %s: " format , (dev)->driver ? (dev)->driver->name : "" , (dev)->bus_id , ## arg)

#ifdef DEBUG
#define dev_dbg(dev, format, arg...)		\
	dev_printk(KERN_DEBUG , dev , format , ## arg)
#else
#define dev_dbg(dev, format, arg...) do { (void)(dev); } while (0)
#endif

#define dev_err(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#define dev_info(dev, format, arg...)		\
	dev_printk(KERN_INFO , dev , format , ## arg)
#define dev_warn(dev, format, arg...)		\
	dev_printk(KERN_WARNING , dev , format , ## arg)

/* Create alias, so I can be autoloaded. */
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")
#endif /* _DEVICE_H_ */
