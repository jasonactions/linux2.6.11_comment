/*
 *	Low-Level PCI Access for i386 machines.
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 */

#undef DEBUG

#ifdef DEBUG
#define DBG(x...) printk(x)
#else
#define DBG(x...)
#endif

#define PCI_PROBE_BIOS		0x0001
#define PCI_PROBE_CONF1		0x0002
#define PCI_PROBE_CONF2		0x0004
#define PCI_PROBE_MMCONF	0x0008
#define PCI_PROBE_MASK		0x000f

#define PCI_NO_SORT		0x0100
#define PCI_BIOS_SORT		0x0200
#define PCI_NO_CHECKS		0x0400
#define PCI_USE_PIRQ_MASK	0x0800
#define PCI_ASSIGN_ROMS		0x1000
#define PCI_BIOS_IRQ_SCAN	0x2000
#define PCI_ASSIGN_ALL_BUSSES	0x4000

extern unsigned int pci_probe;

/* pci-i386.c */

extern unsigned int pcibios_max_latency;

void pcibios_resource_survey(void);
int pcibios_enable_resources(struct pci_dev *, int);

/* pci-pc.c */

extern int pcibios_last_bus;
extern struct pci_bus *pci_root_bus;
extern struct pci_ops pci_root_ops;

/* pci-irq.c */

/* PCI插槽的IRQ描述表 */
struct irq_info {
	/* 总线，插槽/功能编号 */
	u8 bus, devfn;			/* Bus, device and function */
	struct {
		/* 链路值，依赖于芯片组，0表示未路由 */
		u8 link;		/* IRQ line ID, chipset dependent, 0=not routed */
		/* 允许使用的IRQ编号位图 */
		u16 bitmap;		/* Available IRQs */
	} __attribute__((packed)) irq[4];
	/* 插槽编号，0表示集成设备 */
	u8 slot;			/* Slot number, 0=onboard */
	/* 保留未用 */
	u8 rfu;
} __attribute__((packed));

/* 中断路由表，需要在BIOS ROM中查找该表 */
struct irq_routing_table {
	/* 签名，必须是"$PIR" */
	u32 signature;			/* PIRQ_SIGNATURE should be here */
	/* 版本号 */
	u16 version;			/* PIRQ_VERSION */
	/* 以字节为单位的表长度 */
	u16 size;			/* Table size in bytes */
	/* 中断路由器所在总线编号和插槽/功能编号 */
	u8 rtr_bus, rtr_devfn;		/* Where the interrupt router lies */
	/* 排它性IRQ位图，为1表示相应输入应当专用 */
	u16 exclusive_irqs;		/* IRQs devoted exclusively to PCI usage */
	/* 中断路由器的厂商ID和设备ID */
	u16 rtr_vendor, rtr_device;	/* Vendor and device ID of interrupt router */
	/* 未用 */
	u32 miniport_data;		/* Crap */
	/* 保留未用 */
	u8 rfu[11];
	/* 校验和，必须为0 */
	u8 checksum;			/* Modulo 256 checksum must give zero */
	/* 中断路由表项，每个PCI插槽占有一项 */
	struct irq_info slots[0];
} __attribute__((packed));

extern unsigned int pcibios_irq_mask;

extern int pcibios_scanned;
extern spinlock_t pci_config_lock;

extern int (*pcibios_enable_irq)(struct pci_dev *dev);
