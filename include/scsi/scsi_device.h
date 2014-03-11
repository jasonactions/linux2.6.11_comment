#ifndef _SCSI_SCSI_DEVICE_H
#define _SCSI_SCSI_DEVICE_H

#include <linux/device.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct request_queue;
struct scsi_cmnd;
struct scsi_mode_data;


/*
 * sdev state: If you alter this, you also need to alter scsi_sysfs.c
 * (for the ascii descriptions) and the state model enforcer:
 * scsi_lib:scsi_device_set_state().
 */
enum scsi_device_state {
	SDEV_CREATED = 1,	/* device created but not added to sysfs
				 * Only internal commands allowed (for inq) */
	SDEV_RUNNING,		/* device properly configured
				 * All commands allowed */
	SDEV_CANCEL,		/* beginning to delete device
				 * Only error handler commands allowed */
	SDEV_DEL,		/* device deleted 
				 * no commands allowed */
	SDEV_QUIESCE,		/* Device quiescent.  No block commands
				 * will be accepted, only specials (which
				 * originate in the mid-layer) */
	SDEV_OFFLINE,		/* Device offlined (by error handling or
				 * user request */
	SDEV_BLOCK,		/* Device blocked by scsi lld.  No scsi 
				 * commands from user or midlayer should be issued
				 * to the scsi lld. */
};

/* SCSI逻辑设备描述符 */
struct scsi_device {
	/* 所在的主机适配器 */
	struct Scsi_Host *host;
	/* 该设备的请求队列的指针 */
	struct request_queue *request_queue;

	/* the next two are protected by the host->host_lock */
	/* 链入到所属主机适配器的SCSI设备链表 */
	struct list_head    siblings;   /* list of all devices on this host */
	/* 链入到所属目标节点的SCSI设备链表 */
	struct list_head    same_target_siblings; /* just the devices sharing same target id */

	/* 已经派发给SCSI设备底层驱动的命令数 */
	volatile unsigned short device_busy;	/* commands actually active on low-level */
	spinlock_t sdev_lock;           /* also the request queue_lock */
	/* 用于保护本结构某些链表的指针 */
	spinlock_t list_lock;
	/* SCSI命令队列 */
	struct list_head cmd_list;	/* queue of in use SCSI Command structures */
	/* 链入所属主机适配器的饥饿链表的连接件 */
	struct list_head starved_entry;
	/* 当前活动命令 */
	struct scsi_cmnd *current_cmnd;	/* currently active command */
	/* 队列深度，即允许链入队列的命令数量 */
	unsigned short queue_depth;	/* How deep of a queue we want */
	/* 上次报告队列满时的活动命令数 */
	unsigned short last_queue_full_depth; /* These two are used by */
	unsigned short last_queue_full_count; /* scsi_track_queue_full() */
	/* 上次报告队列满的时间 */
	unsigned long last_queue_full_time;/* don't let QUEUE_FULLs on the same
					   jiffie count on our counter, they
					   could all be from the same event. */

	/**
	 * ID:	所在目标节点的ID 
	 * lun:	设备的LUN编号
	 * channel:	所在的通道号
	 */
	unsigned int id, lun, channel;

	/* 设备制造商 */
	unsigned int manufacturer;	/* Manufacturer of device, for using 
					 * vendor-specific cmd's */
	/* 硬件扇区长度 */
	unsigned sector_size;	/* size in bytes */

	/* 专有数据指针 */
	void *hostdata;		/* available to low-level driver */
	char devfs_name[256];	/* devfs junk */
	/* SCSI设备类型 */
	char type;
	/* SCSI规范的版本号 */
	char scsi_level;
	/* INQUIRY中的PQ域 */
	char inq_periph_qual;	/* PQ from INQUIRY data */
	/* INQUIRY字符串的有效长度 */
	unsigned char inquiry_len;	/* valid bytes in 'inquiry' */
	/* INQUIRY字符串 */
	unsigned char * inquiry;	/* INQUIRY response data */
	/* 厂商 */
	char * vendor;		/* [back_compat] point into 'inquiry' ... */
	/* 产品 */
	char * model;		/* ... after scan; point to static string */
	/* 产品修正号 */
	char * rev;		/* ... "nullnullnullnull" before scan */
	/* 当前标签 */
	unsigned char current_tag;	/* current tag */
	/* 所属目标节点，仅用于single_lun */
	struct scsi_target      *sdev_target;   /* used only for single_lun */

	/* 额外标志，可能是用户设置的 */
	unsigned int	sdev_bflags; /* black/white flags as also found in
				 * scsi_devinfo.[hc]. For now used only to
				 * pass settings from slave_alloc to scsi
				 * core. */
	/* 是否可写 */
	unsigned writeable:1;
	/* 是否可移除 */
	unsigned removable:1;
	/* 是否已经产生变化而导致数据不再有效 */
	unsigned changed:1;	/* Data invalid due to media change */
	/* 正忙，防止竞争 */
	unsigned busy:1;	/* Used to prevent races */
	/* 可以被上锁，防止设备被移除 */
	unsigned lockable:1;	/* Able to prevent media removal */
	/* 已经上锁，不允许移除介质 */
	unsigned locked:1;      /* Media removal disabled */
	/* 设备有握手问题 */
	unsigned borken:1;	/* Tell the Seagate driver to be 
				 * painfully slow on this device */
	/* 可以断开连接 */
	unsigned disconnect:1;	/* can disconnect */
	/* 使用软复位选项 */
	unsigned soft_reset:1;	/* Uses soft reset option */
	/* 设备支持同步传输，用于SPI设备 */
	unsigned sdtr:1;	/* Device supports SDTR messages */
	/* 设备支持16位宽数据传输，用于SPI设备 */
	unsigned wdtr:1;	/* Device supports WDTR messages */
	/* 支持PPR消息(并行协议请求) */
	unsigned ppr:1;		/* Device supports PPR messages */
	/* 支持SCSI-II tagged queuing */
	unsigned tagged_supported:1;	/* Supports SCSI-II tagged queuing */
	unsigned simple_tags:1;	/* simple queue tag messages are enabled */
	unsigned ordered_tags:1;/* ordered queue tag messages are enabled */
	unsigned single_lun:1;	/* Indicates we should only allow I/O to
				 * one of the luns for the device at a 
				 * time. */
	/* 表示刚做过复位 */
	unsigned was_reset:1;	/* There was a bus reset on the bus for 
				 * this device */
	/* 表示期望收到Check Condition */
	unsigned expecting_cc_ua:1; /* Expecting a CHECK_CONDITION/UNIT_ATTN
				     * because we did a bus reset. */
	/* 首先尝试10字节的读写命令 */
	unsigned use_10_for_rw:1; /* first try 10-byte read / write */
	/* 首先尝试10字节的Mode Sense/Select命令 */
	unsigned use_10_for_ms:1; /* first try 10-byte mode sense/select */
	unsigned skip_ms_page_8:1;	/* do not use MODE SENSE page 0x08 */
	unsigned skip_ms_page_3f:1;	/* do not use MODE SENSE page 0x3f */
	unsigned use_192_bytes_for_3f:1; /* ask for 192 bytes from page 0x3f */
	/* 添加设备时，不要自动启动它 */
	unsigned no_start_on_add:1;	/* do not issue start on add */
	/* 表示允许在错误处理函数中发送START_UNIT命令 */
	unsigned allow_restart:1; /* issue START_UNIT in error handler */
	/* 如果为1，表示禁止设备连接到高层驱动 */
	unsigned no_uld_attach:1; /* disable connecting to upper level drivers */
	/* 表示设备被选中时，不需要Assert ATN */
	unsigned select_no_atn:1;
	/* 如果为1，表示READ_CAPACITY可能多了1个 */
	unsigned fix_capacity:1;	/* READ_CAPACITY is too high by 1 */

	/* 阻塞计数器 */
	unsigned int device_blocked;	/* Device returned QUEUE_FULL. */

	/* 最大的阻塞数量 */
	unsigned int max_device_blocked; /* what device_blocked counts down from  */
#define SCSI_DEFAULT_DEVICE_BLOCKED	3

	int timeout;

	/* 内嵌通用设备 */
	struct device		sdev_gendev;
	/* 内嵌类设备 */
	struct class_device	sdev_classdev;

	/* 设备状态 */
	enum scsi_device_state sdev_state;
	/* 用于传输层 */
	unsigned long		sdev_data[0];
} __attribute__((aligned(sizeof(unsigned long))));
#define	to_scsi_device(d)	\
	container_of(d, struct scsi_device, sdev_gendev)
#define	class_to_sdev(d)	\
	container_of(d, struct scsi_device, sdev_classdev)
#define transport_class_to_sdev(class_dev) \
	to_scsi_device(class_dev->dev)

/*
 * scsi_target: representation of a scsi target, for now, this is only
 * used for single_lun devices. If no one has active IO to the target,
 * starget_sdev_user is NULL, else it points to the active sdev.
 */
/* SCSI目标节点描述符 */
struct scsi_target {
	/* 如果没有IO，则为NULL。否则为指向正在进行IO的SCSI设备 */
	struct scsi_device	*starget_sdev_user;
	/* 内嵌通用设备 */
	struct device		dev;
	/* 所在通道号 */
	unsigned int		channel;
	/* 目标节点的ID */
	unsigned int		id; /* target id ... replace
				     * scsi_device.id eventually */
	/* 如果为1，表示需要被添加 */
	unsigned long		create:1; /* signal that it needs to be added */
	/* 用于传输层 */
	unsigned long		starget_data[0];
} __attribute__((aligned(sizeof(unsigned long))));

#define to_scsi_target(d)	container_of(d, struct scsi_target, dev)
static inline struct scsi_target *scsi_target(struct scsi_device *sdev)
{
	return to_scsi_target(sdev->sdev_gendev.parent);
}
#define transport_class_to_starget(class_dev) \
	to_scsi_target(class_dev->dev)

extern struct scsi_device *__scsi_add_device(struct Scsi_Host *,
		uint, uint, uint, void *hostdata);
#define scsi_add_device(host, channel, target, lun) \
	__scsi_add_device(host, channel, target, lun, NULL)
extern void scsi_remove_device(struct scsi_device *);
extern int scsi_device_cancel(struct scsi_device *, int);

extern int scsi_device_get(struct scsi_device *);
extern void scsi_device_put(struct scsi_device *);
extern struct scsi_device *scsi_device_lookup(struct Scsi_Host *,
					      uint, uint, uint);
extern struct scsi_device *__scsi_device_lookup(struct Scsi_Host *,
						uint, uint, uint);
extern void starget_for_each_device(struct scsi_target *, void *,
		     void (*fn)(struct scsi_device *, void *));

/* only exposed to implement shost_for_each_device */
extern struct scsi_device *__scsi_iterate_devices(struct Scsi_Host *,
						  struct scsi_device *);

/**
 * shost_for_each_device  -  iterate over all devices of a host
 * @sdev:	iterator
 * @host:	host whiches devices we want to iterate over
 *
 * This traverses over each devices of @shost.  The devices have
 * a reference that must be released by scsi_host_put when breaking
 * out of the loop.
 */
#define shost_for_each_device(sdev, shost) \
	for ((sdev) = __scsi_iterate_devices((shost), NULL); \
	     (sdev); \
	     (sdev) = __scsi_iterate_devices((shost), (sdev)))

/**
 * __shost_for_each_device  -  iterate over all devices of a host (UNLOCKED)
 * @sdev:	iterator
 * @host:	host whiches devices we want to iterate over
 *
 * This traverses over each devices of @shost.  It does _not_ take a
 * reference on the scsi_device, thus it the whole loop must be protected
 * by shost->host_lock.
 *
 * Note:  The only reason why drivers would want to use this is because
 * they're need to access the device list in irq context.  Otherwise you
 * really want to use shost_for_each_device instead.
 */
#define __shost_for_each_device(sdev, shost) \
	list_for_each_entry((sdev), &((shost)->__devices), siblings)

extern void scsi_adjust_queue_depth(struct scsi_device *, int, int);
extern int scsi_track_queue_full(struct scsi_device *, int);

extern int scsi_set_medium_removal(struct scsi_device *, char);

extern int scsi_mode_sense(struct scsi_device *sdev, int dbd, int modepage,
			   unsigned char *buffer, int len, int timeout,
			   int retries, struct scsi_mode_data *data);
extern int scsi_test_unit_ready(struct scsi_device *sdev, int timeout,
				int retries);
extern int scsi_device_set_state(struct scsi_device *sdev,
				 enum scsi_device_state state);
extern int scsi_device_quiesce(struct scsi_device *sdev);
extern void scsi_device_resume(struct scsi_device *sdev);
extern void scsi_target_quiesce(struct scsi_target *);
extern void scsi_target_resume(struct scsi_target *);
extern const char *scsi_device_state_name(enum scsi_device_state);
extern int scsi_is_sdev_device(const struct device *);
extern int scsi_is_target_device(const struct device *);
static inline int scsi_device_online(struct scsi_device *sdev)
{
	return sdev->sdev_state != SDEV_OFFLINE;
}

/* accessor functions for the SCSI parameters */
static inline int scsi_device_sync(struct scsi_device *sdev)
{
	return sdev->sdtr;
}
static inline int scsi_device_wide(struct scsi_device *sdev)
{
	return sdev->wdtr;
}
static inline int scsi_device_dt(struct scsi_device *sdev)
{
	return sdev->ppr;
}
static inline int scsi_device_dt_only(struct scsi_device *sdev)
{
	if (sdev->inquiry_len < 57)
		return 0;
	return (sdev->inquiry[56] & 0x0c) == 0x04;
}
static inline int scsi_device_ius(struct scsi_device *sdev)
{
	if (sdev->inquiry_len < 57)
		return 0;
	return sdev->inquiry[56] & 0x01;
}
static inline int scsi_device_qas(struct scsi_device *sdev)
{
	if (sdev->inquiry_len < 57)
		return 0;
	return sdev->inquiry[56] & 0x02;
}
#endif /* _SCSI_SCSI_DEVICE_H */
