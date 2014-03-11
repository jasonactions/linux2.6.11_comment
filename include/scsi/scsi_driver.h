#ifndef _SCSI_SCSI_DRIVER_H
#define _SCSI_SCSI_DRIVER_H

#include <linux/device.h>

struct module;
struct scsi_cmnd;


/* SCSI驱动描述符，如SCSI磁盘驱动、磁盘驱动和SCSI光盘驱动 */
struct scsi_driver {
	/* 所属模块 */
	struct module		*owner;
	/* 内嵌设备驱动 */
	struct device_driver	gendrv;

	int (*init_command)(struct scsi_cmnd *);
	/* 用于重新扫描的回调函数 */
	void (*rescan)(struct device *);
	int (*issue_flush)(struct device *, sector_t *);
};
#define to_scsi_driver(drv) \
	container_of((drv), struct scsi_driver, gendrv)

extern int scsi_register_driver(struct device_driver *);
#define scsi_unregister_driver(drv) \
	driver_unregister(drv);

extern int scsi_register_interface(struct class_interface *);
#define scsi_unregister_interface(intf) \
	class_interface_unregister(intf)

#endif /* _SCSI_SCSI_DRIVER_H */
