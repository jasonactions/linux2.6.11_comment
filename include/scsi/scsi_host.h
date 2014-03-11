#ifndef _SCSI_SCSI_HOST_H
#define _SCSI_SCSI_HOST_H

#include <linux/device.h>
#include <linux/list.h>
#include <linux/types.h>

struct block_device;
struct module;
struct scsi_cmnd;
struct scsi_device;
struct Scsi_Host;
struct scsi_host_cmd_pool;
struct scsi_transport_template;


/*
 * The various choices mean:
 * NONE: Self evident.	Host adapter is not capable of scatter-gather.
 * ALL:	 Means that the host adapter module can do scatter-gather,
 *	 and that there is no limit to the size of the table to which
 *	 we scatter/gather data.
 * Anything else:  Indicates the maximum number of chains that can be
 *	 used in one scatter-gather request.
 */
#define SG_NONE 0
#define SG_ALL 0xff


#define DISABLE_CLUSTERING 0
#define ENABLE_CLUSTERING 1

enum scsi_eh_timer_return {
	EH_NOT_HANDLED,
	EH_HANDLED,
	EH_RESET_TIMER,
};


/**
 * SCSI主机模板，相同型号的主机适配器的公共内容，如队列深度、SCSI命令处理回调、错误恢复回调函数。
 */
struct scsi_host_template {
	/* 所属模块 */
	struct module *module;
	/* HBA驱动的名字 */
	const char *name;

	/*
	 * Used to initialize old-style drivers.  For new-style drivers
	 * just perform all work in your module initialization function.
	 *
	 * Status:  OBSOLETE
	 */
	/* 被老式驱动用来检测主机适配器 */
	int (* detect)(struct scsi_host_template *);

	/*
	 * Used as unload callback for hosts with old-style drivers.
	 *
	 * Status: OBSOLETE
	 */
	/* 被老式驱动用来释放主机适配器 */
	int (* release)(struct Scsi_Host *);

	/*
	 * The info function will return whatever useful information the
	 * developer sees fit.  If not provided, then the name field will
	 * be used instead.
	 *
	 * Status: OPTIONAL
	 */
	/* 返回适当的信息 */
	const char *(* info)(struct Scsi_Host *);

	/*
	 * Ioctl interface
	 *
	 * Status: OPTIONAL
	 */
	/* ioctl接口 */
	int (* ioctl)(struct scsi_device *dev, int cmd, void __user *arg);


#ifdef CONFIG_COMPAT
	/* 
	 * Compat handler. Handle 32bit ABI.
	 * When unknown ioctl is passed return -ENOIOCTLCMD.
	 *
	 * Status: OPTIONAL
	 */
	/* 兼容的ioctl，在64位上处理32位ioctl调用 */
	int (* compat_ioctl)(struct scsi_device *dev, int cmd, void __user *arg);
#endif

	/*
	 * The queuecommand function is used to queue up a scsi
	 * command block to the LLDD.  When the driver finished
	 * processing the command the done callback is invoked.
	 *
	 * If queuecommand returns 0, then the HBA has accepted the
	 * command.  The done() function must be called on the command
	 * when the driver has finished with it. (you may call done on the
	 * command before queuecommand returns, but in this case you
	 * *must* return 0 from queuecommand).
	 *
	 * Queuecommand may also reject the command, in which case it may
	 * not touch the command and must not call done() for it.
	 *
	 * There are two possible rejection returns:
	 *
	 *   SCSI_MLQUEUE_DEVICE_BUSY: Block this device temporarily, but
	 *   allow commands to other devices serviced by this host.
	 *
	 *   SCSI_MLQUEUE_HOST_BUSY: Block all devices served by this
	 *   host temporarily.
	 *
         * For compatibility, any other non-zero return is treated the
         * same as SCSI_MLQUEUE_HOST_BUSY.
	 *
	 * NOTE: "temporarily" means either until the next command for#
	 * this device/host completes, or a period of time determined by
	 * I/O pressure in the system if there are no other outstanding
	 * commands.
	 *
	 * STATUS: REQUIRED
	 */
	/**
	 * 将SCSI命令排入LLDD队列，SCSI中间层调用该回调函数向HBA发送SCSI命令
	 */
	int (* queuecommand)(struct scsi_cmnd *,
			     void (*done)(struct scsi_cmnd *));

	/*
	 * This is an error handling strategy routine.  You don't need to
	 * define one of these if you don't want to - there is a default
	 * routine that is present that should work in most cases.  For those
	 * driver authors that have the inclination and ability to write their
	 * own strategy routine, this is where it is specified.  Note - the
	 * strategy routine is *ALWAYS* run in the context of the kernel eh
	 * thread.  Thus you are guaranteed to *NOT* be in an interrupt
	 * handler when you execute this, and you are also guaranteed to
	 * *NOT* have any other commands being queued while you are in the
	 * strategy routine. When you return from this function, operations
	 * return to normal.
	 *
	 * See scsi_error.c scsi_unjam_host for additional comments about
	 * what this function should and should not be attempting to do.
	 *
	 * Status: REQUIRED	(at least one of them)
	 */
	int (* eh_strategy_handler)(struct Scsi_Host *);
	/* 错误恢复处理，放弃特定的命令 */
	int (* eh_abort_handler)(struct scsi_cmnd *);
	/* 目标节点复位 */
	int (* eh_device_reset_handler)(struct scsi_cmnd *);
	/* SCSI总线复位 */
	int (* eh_bus_reset_handler)(struct scsi_cmnd *);
	/* 主机适配器复位 */
	int (* eh_host_reset_handler)(struct scsi_cmnd *);

	/*
	 * This is an optional routine to notify the host that the scsi
	 * timer just fired.  The returns tell the timer routine what to
	 * do about this:
	 *
	 * EH_HANDLED:		I fixed the error, please complete the command
	 * EH_RESET_TIMER:	I need more time, reset the timer and
	 *			begin counting again
	 * EH_NOT_HANDLED	Begin normal error recovery
	 *
	 * Status: OPTIONAL
	 */
	/* 当中间层发现SCSI命令超时，将调用低层驱动的这个回调函数。 */
	enum scsi_eh_timer_return (* eh_timed_out)(struct scsi_cmnd *);

	/*
	 * Before the mid layer attempts to scan for a new device where none
	 * currently exists, it will call this entry in your driver.  Should
	 * your driver need to allocate any structs or perform any other init
	 * items in order to send commands to a currently unused target/lun
	 * combo, then this is where you can perform those allocations.  This
	 * is specifically so that drivers won't have to perform any kind of
	 * "is this a new device" checks in their queuecommand routine,
	 * thereby making the hot path a bit quicker.
	 *
	 * Return values: 0 on success, non-0 on failure
	 *
	 * Deallocation:  If we didn't find any devices at this ID, you will
	 * get an immediate call to slave_destroy().  If we find something
	 * here then you will get a call to slave_configure(), then the
	 * device will be used for however long it is kept around, then when
	 * the device is removed from the system (or * possibly at reboot
	 * time), you will then get a call to slave_destroy().  This is
	 * assuming you implement slave_configure and slave_destroy.
	 * However, if you allocate memory and hang it off the device struct,
	 * then you must implement the slave_destroy() routine at a minimum
	 * in order to avoid leaking memory
	 * each time a device is tore down.
	 *
	 * Status: OPTIONAL
	 */
	/* 扫描到一个新的SCSI设备后调用，可以在这个函数中分配么有device结构 */
	int (* slave_alloc)(struct scsi_device *);

	/*
	 * Once the device has responded to an INQUIRY and we know the
	 * device is online, we call into the low level driver with the
	 * struct scsi_device *.  If the low level device driver implements
	 * this function, it *must* perform the task of setting the queue
	 * depth on the device.  All other tasks are optional and depend
	 * on what the driver supports and various implementation details.
	 * 
	 * Things currently recommended to be handled at this time include:
	 *
	 * 1.  Setting the device queue depth.  Proper setting of this is
	 *     described in the comments for scsi_adjust_queue_depth.
	 * 2.  Determining if the device supports the various synchronous
	 *     negotiation protocols.  The device struct will already have
	 *     responded to INQUIRY and the results of the standard items
	 *     will have been shoved into the various device flag bits, eg.
	 *     device->sdtr will be true if the device supports SDTR messages.
	 * 3.  Allocating command structs that the device will need.
	 * 4.  Setting the default timeout on this device (if needed).
	 * 5.  Anything else the low level driver might want to do on a device
	 *     specific setup basis...
	 * 6.  Return 0 on success, non-0 on error.  The device will be marked
	 *     as offline on error so that no access will occur.  If you return
	 *     non-0, your slave_destroy routine will never get called for this
	 *     device, so don't leave any loose memory hanging around, clean
	 *     up after yourself before returning non-0
	 *
	 * Status: OPTIONAL
	 */
	/* 接收到SCSI设备的INQUIRY命令后调用，可进行特定的设置 */
	int (* slave_configure)(struct scsi_device *);

	/*
	 * Immediately prior to deallocating the device and after all activity
	 * has ceased the mid layer calls this point so that the low level
	 * driver may completely detach itself from the scsi device and vice
	 * versa.  The low level driver is responsible for freeing any memory
	 * it allocated in the slave_alloc or slave_configure calls. 
	 *
	 * Status: OPTIONAL
	 */
	/* 在销毁SCSI设备之前调用，释放关联的数据结构 */
	void (* slave_destroy)(struct scsi_device *);

	/*
	 * fill in this function to allow the queue depth of this host
	 * to be changeable (on a per device basis).  returns either
	 * the current queue depth setting (may be different from what
	 * was passed in) or an error.  An error should only be
	 * returned if the requested depth is legal but the driver was
	 * unable to set it.  If the requested depth is illegal, the
	 * driver should set and return the closest legal queue depth.
	 *
	 */
	/* 用于改变主机适配器队列深度的回调函数 */
	int (* change_queue_depth)(struct scsi_device *, int);

	/*
	 * fill in this function to allow the changing of tag types
	 * (this also allows the enabling/disabling of tag command
	 * queueing).  An error should only be returned if something
	 * went wrong in the driver while trying to set the tag type.
	 * If the driver doesn't support the requested tag type, then
	 * it should set the closest type it does support without
	 * returning an error.  Returns the actual tag type set.
	 */
	/* 改变主机适配器tag类型的回调函数 */
	int (* change_queue_type)(struct scsi_device *, int);

	/*
	 * This function determines the bios parameters for a given
	 * harddisk.  These tend to be numbers that are made up by
	 * the host adapter.  Parameters:
	 * size, device, list (heads, sectors, cylinders)
	 *
	 * Status: OPTIONAL */
	/* 返回磁盘的BIOS参数，如柱面数，磁盘数和扇区数 */
	int (* bios_param)(struct scsi_device *, struct block_device *,
			sector_t, int []);

	/*
	 * Can be used to export driver statistics and other infos to the
	 * world outside the kernel ie. userspace and it also provides an
	 * interface to feed the driver with information.
	 *
	 * Status: OBSOLETE
	 */
	/* 通过proc输出统计信息到用户空间，如可以向驱动中写入信息 */
	int (*proc_info)(struct Scsi_Host *, char *, char **, off_t, int, int);

	/*
	 * Name of proc directory
	 */
	/* proc目录名 */
	char *proc_name;

	/*
	 * Used to store the procfs directory if a driver implements the
	 * proc_info method.
	 */
	/* 如果实现了proc_info方法，本字段保存procfs目录 */
	struct proc_dir_entry *proc_dir;

	/*
	 * This determines if we will use a non-interrupt driven
	 * or an interrupt driven scheme,  It is set to the maximum number
	 * of simultaneous commands a given host adapter will accept.
	 */
	/* 主机适配器可以同时接受的命令数，必须大于0 */
	int can_queue;

	/*
	 * In many instances, especially where disconnect / reconnect are
	 * supported, our host also has an ID on the SCSI bus.  If this is
	 * the case, then it must be reserved.  Please set this_id to -1 if
	 * your setup is in single initiator mode, and the host lacks an
	 * ID.
	 */
	/* 预留的ID? */
	int this_id;

	/*
	 * This determines the degree to which the host adapter is capable
	 * of scatter-gather.
	 */
	/* 主机适配器支持分散/聚集的能力 */
	unsigned short sg_tablesize;

	/*
	 * If the host adapter has limitations beside segment count
	 */
	/* 主机适配器单个SCSI命令能访问的扇区最大数目 */
	unsigned short max_sectors;

	/*
	 * dma scatter gather segment boundary limit. a segment crossing this
	 * boundary will be split in two.
	 */
	/* DMA分散/聚集段边界限制，超过这个边界的段将被分割 */
	unsigned long dma_boundary;

	/*
	 * This specifies "machine infinity" for host templates which don't
	 * limit the transfer size.  Note this limit represents an absolute
	 * maximum, and may be over the transfer limits allowed for
	 * individual devices (e.g. 256 for SCSI-1)
	 */
#define SCSI_DEFAULT_MAX_SECTORS	1024

	/*
	 * True if this host adapter can make good use of linked commands.
	 * This will allow more than one command to be queued to a given
	 * unit on a given host.  Set this to the maximum number of command
	 * blocks to be provided for each device.  Set this to 1 for one
	 * command block per lun, 2 for two, etc.  Do not set this to 0.
	 * You should make sure that the host adapter will do the right thing
	 * before you try setting this above 1.
	 */
	/* 允许排入连接到这个主机适配器的SCSI设备的最大命令数目，即队列深度。 */
	short cmd_per_lun;

	/*
	 * present contains counter indicating how many boards of this
	 * type were found when we did the scan.
	 */
	/* 计数器，表示在扫描过程中发现了多少个这种类型的适配器 */
	unsigned char present;

	/*
	 * true if this host adapter uses unchecked DMA onto an ISA bus.
	 */
	/* 如果为1，表示只能使用RAM的低16M作为DMA地址空间 */
	unsigned unchecked_isa_dma:1;

	/*
	 * true if this host adapter can make good use of clustering.
	 * I originally thought that if the tablesize was large that it
	 * was a waste of CPU cycles to prepare a cluster list, but
	 * it works out that the Buslogic is faster if you use a smaller
	 * number of segments (i.e. use clustering).  I guess it is
	 * inefficient.
	 */
	/* 如果为1，表示在SCSI策略例程中构建SCSI命令的分散/聚集链表时，可以合并内存连续的IO请求 */
	unsigned use_clustering:1;

	/*
	 * True for emulated SCSI host adapters (e.g. ATAPI)
	 */
	/* 如果为1，表示是仿真的主机适配器如ATAPI */
	unsigned emulated:1;

	/*
	 * True if the low-level driver performs its own reset-settle delays.
	 */
	/* 如果为1，在主机适配器复位和总线复位后，低层驱动自行执行reset_settle延迟 */
	unsigned skip_settle_delay:1;

	/*
	 * Countdown for host blocking with no commands outstanding
	 */
	/* 当主机适配器没有待处理命令时，则暂时阻塞它，等待累积足够多的命令再说。当此值为0时，恢复正常操作，将命令派发到低层驱动 */
	unsigned int max_host_blocked;

	/*
	 * Default value for the blocking.  If the queue is empty,
	 * host_blocked counts down in the request_fn until it restarts
	 * host operations as zero is reached.  
	 *
	 * FIXME: This should probably be a value in the template
	 */
#define SCSI_DEFAULT_HOST_BLOCKED	7

	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	/* 主机适配器的公共属性及其操作方法 */
	struct class_device_attribute **shost_attrs;

	/*
	 * Pointer to the SCSI device properties for this host, NULL terminated.
	 */
	/* 连接到这个模板的主机适配器上的SCSI设备的公共属性及操作方法 */
	struct device_attribute **sdev_attrs;

	/*
	 * List of hosts per template.
	 *
	 * This is only for use by scsi_module.c for legacy templates.
	 * For these access to it is synchronized implicitly by
	 * module_init/module_exit.
	 */
	/* 老式驱动用于记录主机适配器链表的表头，已经过时 */
	struct list_head legacy_hosts;
};

/*
 * shost states
 */
enum {
	SHOST_ADD,
	SHOST_DEL,
	SHOST_CANCEL,
	SHOST_RECOVERY,
};

/* SCSI主机适配器描述符 */
struct Scsi_Host {
	/*
	 * __devices is protected by the host_lock, but you should
	 * usually use scsi_device_lookup / shost_for_each_device
	 * to access it and don't care about locking yourself.
	 * In the rare case of beeing in irq context you can use
	 * their __ prefixed variants with the lock held. NEVER
	 * access this list directly from a driver.
	 */
	/* 指向这个主机适配器的SCSI设备链表 */
	struct list_head	__devices;

	/* 分配SCSI命令的存储池 */
	struct scsi_host_cmd_pool *cmd_pool;
	/* 用于保护free_list链表的锁 */
	spinlock_t		free_list_lock;
	/* 预先准备的SCSI命令结构的链表，如果从缓冲池中分配结构失败，则从这里分配。 */
	struct list_head	free_list; /* backup store of cmd structs */
	/* 饥饿设备链表 */
	struct list_head	starved_list;

	/* 保护本结构的锁 */
	spinlock_t		default_lock;
	/* 指向default_lock */
	spinlock_t		*host_lock;

	/* 同步扫描过程的互斥量 */
	struct semaphore	scan_mutex;/* serialize scanning activity */

	/* 错误恢复的SCSI命令链表 */
	struct list_head	eh_cmd_q;
	/* 错误恢复线程 */
	struct task_struct    * ehandler;  /* Error recovery thread. */
	struct semaphore      * eh_wait;   /* The error recovery thread waits
					      on this. */
	struct completion     * eh_notify; /* wait for eh to begin or end */
	/* 等待特定的操作完成 */
	struct semaphore      * eh_action; /* Wait for specific actions on the
                                          host. */
	unsigned int            eh_active:1; /* Indicates the eh thread is awake and active if
                                          this is true. */
	unsigned int            eh_kill:1; /* set when killing the eh thread */
	/* SCSI设备错误恢复等待队列 */
	wait_queue_head_t       host_wait;
	/* 创建此设备的模板指针 */
	struct scsi_host_template *hostt;
	/* 指向SCSI传输层模板的指针 */
	struct scsi_transport_template *transportt;
	/* 已经派发给主机适配器低层驱动的命令数  */
	volatile unsigned short host_busy;   /* commands actually active on low-level */
	/* 失败的命令数 */
	volatile unsigned short host_failed; /* commands that failed. */

	/* 主机编号，用于标识这个主机适配器 */
	unsigned short host_no;  /* Used for IOCTL_GET_IDLUN, /proc/scsi et al. */
	/* 如果为1，表示last_reset值有效 */
	int resetting; /* if set, it means that last_reset is a valid value */
	/* 上次复位的时间，以jiffies为单位，在提交命令到主机适配前，必须确保上次复位时间超过2秒 */
	unsigned long last_reset;

	/*
	 * These three parameters can be used to allow for wide scsi,
	 * and for host adapters that support multiple busses
	 * The first two should be set to 1 more than the actual max id
	 * or lun (i.e. 8 for normal systems).
	 */
	/* 连接到本主机适配器的目标节点最大编号 */
	unsigned int max_id;
	/* 连接到本主机适配器的逻辑单元最大编号 */
	unsigned int max_lun;
	/* 最大通道编号 */
	unsigned int max_channel;

	/*
	 * This is a unique identifier that must be assigned so that we
	 * have some way of identifying each detected host adapter properly
	 * and uniquely.  For hosts that do not support more than one card
	 * in the system at one time, this does not need to be set.  It is
	 * initialized to 0 in scsi_register.
	 */
	/* 用于主机适配器的唯一标识号 */
	unsigned int unique_id;

	/*
	 * The maximum length of SCSI commands that this host can accept.
	 * Probably 12 for most host adapters, but could be 16 for others.
	 * For drivers that don't set this field, a value of 12 is
	 * assumed.  I am leaving this as a number rather than a bit
	 * because you never know what subsequent SCSI standards might do
	 * (i.e. could there be a 20 byte or a 24-byte command a few years
	 * down the road?).  
	 */
	/* 主机可以接受的最大SCSI命令长度 */
	unsigned char max_cmd_len;

	/* 主机的SCSI ID */
	int this_id;
	/* 可以同时接受的SCSI命令数，必须大于0 */
	int can_queue;
	/* 允许排入主机适配器的SCSI设备的最大命令数目，即队列深度 */
	short cmd_per_lun;
	/* 支持的S/G能力 */
	short unsigned int sg_tablesize;
	/* 单个命令所能访问的最大扇区数 */
	short unsigned int max_sectors;
	/* DMA S/G边界限制 */
	unsigned long dma_boundary;

	/* 为1表示只能使用16M的DMA空间 */
	unsigned unchecked_isa_dma:1;
	/* 为1表示可以合并连接的IO请求 */
	unsigned use_clustering:1;
	/* 未用 */
	unsigned use_blk_tcq:1;

	/*
	 * Host has requested that no further requests come through for the
	 * time being.
	 */
	/* 为1表示低层驱动要求阻塞该主机适配器，即SCSI中间层不要继续分发命令到队列中 */
	unsigned host_self_blocked:1;
    
	/*
	 * Host uses correct SCSI ordering not PC ordering. The bit is
	 * set for the minority of drivers whose authors actually read
	 * the spec ;)
	 */
	/* 如果为1，表示按逆序扫描SCSI总线 */
	unsigned reverse_ordering:1;

	/*
	 * Host has rejected a command because it was busy.
	 */
	/* 阻塞计数器 */
	unsigned int host_blocked;

	/*
	 * Value host_blocked counts down from
	 */
	/* 最大阻塞命令数量 */
	unsigned int max_host_blocked;

	/* legacy crap */
	/* 主机适配器的MMIO基地址 */
	unsigned long base;
	/* 主机适配器的IO端口编号 */
	unsigned long io_port;
	/* IO空间字节数 */
	unsigned char n_io_port;
	/* DMA通道，用于老式驱动 */
	unsigned char dma_channel;
	/* 该设备的IRQ号 */
	unsigned int  irq;
	
	/* 主机适配器的状态 */
	unsigned long shost_state;

	/* ldm bits */
	/* 内嵌通用设备 */
	struct device		shost_gendev;
	struct class_device	shost_classdev;

	/*
	 * List of hosts per template.
	 *
	 * This is only for use by scsi_module.c for legacy templates.
	 * For these access to it is synchronized implicitly by
	 * module_init/module_exit.
	 */
	/* 老式驱动使用它链接入模板的legacy_hosts链表 */
	struct list_head sht_legacy_list;

	/*
	 * Points to the transport data (if any) which is allocated
	 * separately
	 */
	/* 分配的传输层数据结构 */
	void *shost_data;

	/*
	 * We should ensure that this is aligned, both for better performance
	 * and also because some compilers (m68k) don't automatically force
	 * alignment to a long boundary.
	 */
	/* 主机适配器的专有数据 */
	unsigned long hostdata[0]  /* Used for storage of host specific stuff */
		__attribute__ ((aligned (sizeof(unsigned long))));
};
#define		dev_to_shost(d)		\
	container_of(d, struct Scsi_Host, shost_gendev)
#define		class_to_shost(d)	\
	container_of(d, struct Scsi_Host, shost_classdev)


extern struct Scsi_Host *scsi_host_alloc(struct scsi_host_template *, int);
extern int __must_check scsi_add_host(struct Scsi_Host *, struct device *);
extern void scsi_scan_host(struct Scsi_Host *);
extern void scsi_scan_single_target(struct Scsi_Host *, unsigned int,
	unsigned int);
extern void scsi_rescan_device(struct device *);
extern void scsi_remove_host(struct Scsi_Host *);
extern struct Scsi_Host *scsi_host_get(struct Scsi_Host *);
extern void scsi_host_put(struct Scsi_Host *t);
extern struct Scsi_Host *scsi_host_lookup(unsigned short);

extern u64 scsi_calculate_bounce_limit(struct Scsi_Host *);

static inline void scsi_assign_lock(struct Scsi_Host *shost, spinlock_t *lock)
{
	shost->host_lock = lock;
}

static inline void scsi_set_device(struct Scsi_Host *shost,
                                   struct device *dev)
{
        shost->shost_gendev.parent = dev;
}

static inline struct device *scsi_get_device(struct Scsi_Host *shost)
{
        return shost->shost_gendev.parent;
}

extern void scsi_unblock_requests(struct Scsi_Host *);
extern void scsi_block_requests(struct Scsi_Host *);

struct class_container;
/*
 * These two functions are used to allocate and free a pseudo device
 * which will connect to the host adapter itself rather than any
 * physical device.  You must deallocate when you are done with the
 * thing.  This physical pseudo-device isn't real and won't be available
 * from any high-level drivers.
 */
extern void scsi_free_host_dev(struct scsi_device *);
extern struct scsi_device *scsi_get_host_dev(struct Scsi_Host *);
int scsi_is_host_device(const struct device *);


/* legacy interfaces */
extern struct Scsi_Host *scsi_register(struct scsi_host_template *, int);
extern void scsi_unregister(struct Scsi_Host *);

#endif /* _SCSI_SCSI_HOST_H */
