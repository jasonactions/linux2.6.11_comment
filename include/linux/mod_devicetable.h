/*
 * Device tables which are exported to userspace via
 * scripts/table2alias.c.  You must keep that file in sync with this
 * header.
 */

#ifndef LINUX_MOD_DEVICETABLE_H
#define LINUX_MOD_DEVICETABLE_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef unsigned long kernel_ulong_t;
#endif

#define PCI_ANY_ID (~0)

/**
 * 设备标识号。这不是Linux中定义的ID,而是在PCI标准中定义的ID。
 */
struct pci_device_id {
	/**
	 * vendor和device已经足够唯一标识一个设备
	 */
	__u32 vendor, device;		/* Vendor and device ID or PCI_ANY_ID*/
	/**
	 * subvendor和subdevice很少会使用到，所以通常会被置成匹配任意设备(PCI_ANY_ID)
	 */
	__u32 subvendor, subdevice;	/* Subsystem ID's or PCI_ANY_ID */
	/**
	 * class和class_mark表示这个设备属于哪个类别,如NETWORK.
	 */
	__u32 class, class_mask;	/* (class,subclass,prog-if) triplet */
	/**
	 * driver_data不是PCIID的一部分，这是设备使用的私有参数。
	 */
	kernel_ulong_t driver_data;	/* Data private to the driver */
};


#define IEEE1394_MATCH_VENDOR_ID	0x0001
#define IEEE1394_MATCH_MODEL_ID		0x0002
#define IEEE1394_MATCH_SPECIFIER_ID	0x0004
#define IEEE1394_MATCH_VERSION		0x0008

struct ieee1394_device_id {
	__u32 match_flags;
	__u32 vendor_id;
	__u32 model_id;
	__u32 specifier_id;
	__u32 version;
	kernel_ulong_t driver_data;
};


/*
 * Device table entry for "new style" table-driven USB drivers.
 * User mode code can read these tables to choose which modules to load.
 * Declare the table as a MODULE_DEVICE_TABLE.
 *
 * A probe() parameter will point to a matching entry from this table.
 * Use the driver_info field for each match to hold information tied
 * to that match:  device quirks, etc.
 *
 * Terminate the driver's table with an all-zeroes entry.
 * Use the flag values to control which fields are compared.
 */

/**
 * struct usb_device_id - identifies USB devices for probing and hotplugging
 * @match_flags: Bit mask controlling of the other fields are used to match
 *	against new devices.  Any field except for driver_info may be used,
 *	although some only make sense in conjunction with other fields.
 *	This is usually set by a USB_DEVICE_*() macro, which sets all
 *	other fields in this structure except for driver_info.
 * @idVendor: USB vendor ID for a device; numbers are assigned
 *	by the USB forum to its members.
 * @idProduct: Vendor-assigned product ID.
 * @bcdDevice_lo: Low end of range of vendor-assigned product version numbers.
 *	This is also used to identify individual product versions, for
 *	a range consisting of a single device.
 * @bcdDevice_hi: High end of version number range.  The range of product
 *	versions is inclusive.
 * @bDeviceClass: Class of device; numbers are assigned
 *	by the USB forum.  Products may choose to implement classes,
 *	or be vendor-specific.  Device classes specify behavior of all
 *	the interfaces on a devices.
 * @bDeviceSubClass: Subclass of device; associated with bDeviceClass.
 * @bDeviceProtocol: Protocol of device; associated with bDeviceClass.
 * @bInterfaceClass: Class of interface; numbers are assigned
 *	by the USB forum.  Products may choose to implement classes,
 *	or be vendor-specific.  Interface classes specify behavior only
 *	of a given interface; other interfaces may support other classes.
 * @bInterfaceSubClass: Subclass of interface; associated with bInterfaceClass.
 * @bInterfaceProtocol: Protocol of interface; associated with bInterfaceClass.
 * @driver_info: Holds information used by the driver.  Usually it holds
 *	a pointer to a descriptor understood by the driver, or perhaps
 *	device flags.
 *
 * In most cases, drivers will create a table of device IDs by using
 * USB_DEVICE(), or similar macros designed for that purpose.
 * They will then export it to userspace using MODULE_DEVICE_TABLE(),
 * and provide it to the USB core through their usb_driver structure.
 *
 * See the usb_match_id() function for information about how matches are
 * performed.  Briefly, you will normally use one of several macros to help
 * construct these entries.  Each entry you provide will either identify
 * one or more specific products, or will identify a class of products
 * which have agreed to behave the same.  You should put the more specific
 * matches towards the beginning of your table, so that driver_info can
 * record quirks of specific products.
 */
/**
 * 提供了一列不同类型的驱动程序支持的USB设备。USB核心使用该列表来判断对于一个设备，该使用哪一个驱动程序。
 * 热拨插脚本使用它来确定当一个特定的设备插入到系统时该自动装载哪一个驱动程序。
 */
struct usb_device_id {
	/* which fields to match against? */
	/**
	 * 确定设备和结构体中下列字段中的哪一个相匹配。这些字段是USB_DEVICE_ID_MATCH_*定义的位字段。
	 * 通常不直接设置该字段，而是使用USB_DEVICE宏来初始化。
	 */
	__u16		match_flags;

	/* Used for product specific matches; range is inclusive */
	/**
	 * 设备的USB制造商ID。该编号是由USB论坛指派给其成员的。
	 */
	__u16		idVendor;
	/**
	 * 设备的USB产品ID。所有指派了制造商ID的制造商都可以随意的赋予其产品ID。
	 */
	__u16		idProduct;
	/**
	 * 定义了制造商指派的产品的版本叫范围的最低值和最高值。格式为BCD。
	 */
	__u16		bcdDevice_lo;
	__u16		bcdDevice_hi;

	/* Used for device class matches */
	/**
	 * 分别定义设备的类型、子类型和协议。这些编号由USB论坛指派，定义在USB规范中。详细说明了整个设备的行为，包括该设备上的所有接口。
	 */
	__u8		bDeviceClass;
	__u8		bDeviceSubClass;
	__u8		bDeviceProtocol;

	/* Used for interface class matches */
	/**
	 * 分别定义类型、子类型和单个接口的协议。这些编号由USB论坛指派，定义在USB规范中。
	 */
	__u8		bInterfaceClass;
	__u8		bInterfaceSubClass;
	__u8		bInterfaceProtocol;

	/* not matched against */
	/** 
	 * 该值不是用来比较是否匹配的，不过它包含了驱动程序在USB驱动程序的探测回调函数中可以用来区分不同设备的信息。
	 */
	kernel_ulong_t	driver_info;
};

/* Some useful macros to use to create struct usb_device_id */
#define USB_DEVICE_ID_MATCH_VENDOR		0x0001
#define USB_DEVICE_ID_MATCH_PRODUCT		0x0002
#define USB_DEVICE_ID_MATCH_DEV_LO		0x0004
#define USB_DEVICE_ID_MATCH_DEV_HI		0x0008
#define USB_DEVICE_ID_MATCH_DEV_CLASS		0x0010
#define USB_DEVICE_ID_MATCH_DEV_SUBCLASS	0x0020
#define USB_DEVICE_ID_MATCH_DEV_PROTOCOL	0x0040
#define USB_DEVICE_ID_MATCH_INT_CLASS		0x0080
#define USB_DEVICE_ID_MATCH_INT_SUBCLASS	0x0100
#define USB_DEVICE_ID_MATCH_INT_PROTOCOL	0x0200

/* s390 CCW devices */
struct ccw_device_id {
	__u16	match_flags;	/* which fields to match against */

	__u16	cu_type;	/* control unit type     */
	__u16	dev_type;	/* device type           */
	__u8	cu_model;	/* control unit model    */
	__u8	dev_model;	/* device model          */

	kernel_ulong_t driver_info;
};

#define CCW_DEVICE_ID_MATCH_CU_TYPE		0x01
#define CCW_DEVICE_ID_MATCH_CU_MODEL		0x02
#define CCW_DEVICE_ID_MATCH_DEVICE_TYPE		0x04
#define CCW_DEVICE_ID_MATCH_DEVICE_MODEL	0x08


#define PNP_ID_LEN	8
#define PNP_MAX_DEVICES	8

struct pnp_device_id {
	__u8 id[PNP_ID_LEN];
	kernel_ulong_t driver_data;
};

struct pnp_card_device_id {
	__u8 id[PNP_ID_LEN];
	kernel_ulong_t driver_data;
	struct {
		__u8 id[PNP_ID_LEN];
	} devs[PNP_MAX_DEVICES];
};


#endif /* LINUX_MOD_DEVICETABLE_H */
