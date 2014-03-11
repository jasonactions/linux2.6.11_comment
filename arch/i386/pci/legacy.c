/*
 * legacy.c - traditional, old school PCI bus probing
 */
#include <linux/init.h>
#include <linux/pci.h>
#include "pci.h"

/*
 * Discover remaining PCI buses in case there are peer host bridges.
 * We use the number of last PCI bus provided by the PCI BIOS.
 */
static void __devinit pcibios_fixup_peer_bridges(void)
{
	int n, devfn;

	if (pcibios_last_bus <= 0 || pcibios_last_bus >= 0xff)
		return;
	DBG("PCI: Peer bridge fixup\n");

	for (n=0; n <= pcibios_last_bus; n++) {
		u32 l;
		if (pci_find_bus(0, n))
			continue;
		for (devfn = 0; devfn < 256; devfn += 8) {
			if (!raw_pci_ops->read(0, n, devfn, PCI_VENDOR_ID, 2, &l) &&
			    l != 0x0000 && l != 0xffff) {
				DBG("Found device at %02x:%02x [%04x]\n", n, devfn, l);
				printk(KERN_INFO "PCI: Discovered peer bus %02x\n", n);
				pci_scan_bus(n, &pci_root_ops, NULL);
				break;
			}
		}
	}
}

/**
 * 完成对PCI总线的枚举，并在proc文件系统和sysfs文件系统中建立相应的结构。
 * 如果没有使能ACPI机制，则此函数是对PCI总线进行初始化的重要函数。
 */
static int __init pci_legacy_init(void)
{
	if (!raw_pci_ops) {
		printk("PCI: System does not support PCI\n");
		return 0;
	}

	/**
	 * 当引入ACPI后，pcibios_scanned默认就是1，本函数将直接返回。
	 */
	if (pcibios_scanned++)
		return 0;

	printk("PCI: Probing PCI hardware\n");
	/**
	 * 完成对PCI总线树的枚举。入参为0表示从总线号0开始进行枚举。
	 * pcibios_scan_root还会调用pci_bus_add_devices将PCI总线上的设备加入到sysfs文件系统中。
	 */
	pci_root_bus = pcibios_scan_root(0);

	pcibios_fixup_peer_bridges();

	return 0;
}

subsys_initcall(pci_legacy_init);
