/* ld script to make i386 Linux kernel
 * Written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>;
 */
/* thread_info.h: i386 low-level thread information
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds and Dave Miller
 */
/*
 * Automatically generated C config: don't edit
 * Linux kernel version: 2.6.11
 * Fri Oct  3 21:01:54 2008
 */







/*
 * Code maturity level options
 */




/*
 * General setup
 */
/*
 * Loadable module support
 */







/*
 * Processor type and features
 */
/*
 * Firmware Drivers
 */
/*
 * Power management options (ACPI, APM)
 */





/*
 * ACPI (Advanced Configuration and Power Interface) Support
 */
/*
 * APM (Advanced Power Management) BIOS Support
 */


/*
 * CPU Frequency scaling
 */


/*
 * Bus options (PCI, PCMCIA, EISA, MCA, ISA)
 */
/*
 * PCCARD (PCMCIA/CardBus) support
 */


/*
 * PC-card bridges
 */


/*
 * PCI Hotplug Support
 */


/*
 * Executable file formats
 */




/*
 * Device Drivers
 */

/*
 * Generic Driver Options
 */




/*
 * Memory Technology Devices (MTD)
 */


/*
 * Parallel port support
 */
/*
 * Plug and Play support
 */



/*
 * Protocols
 */




/*
 * Block devices
 */
/*
 * IO Schedulers
 */






/*
 * ATA/ATAPI/MFM/RLL support
 */



/*
 * Please see Documentation/ide.txt for help/info on IDE drives
 */
/*
 * IDE chipset support/bugfixes
 */
/*
 * SCSI device support
 */



/*
 * SCSI support type (disk, tape, CD-ROM)
 */






/*
 * Some SCSI devices (e.g. CD jukebox) support multiple LUNs
 */




/*
 * SCSI Transport Attributes
 */




/*
 * SCSI low-level drivers
 */
/*
 * Old CD-ROM drivers (not SCSI, not IDE)
 */


/*
 * Multi-device support (RAID and LVM)
 */


/*
 * Fusion MPT device support
 */


/*
 * IEEE 1394 (FireWire) support
 */


/*
 * Subsystem Options
 */




/*
 * Device Drivers
 */

/*
 * Texas Instruments PCILynx requires I2C
 */


/*
 * Protocol Drivers
 */







/*
 * I2O device support
 */


/*
 * Networking support
 */


/*
 * Networking options
 */
/*
 * IP: Virtual Server Configuration
 */





/*
 * IP: Netfilter Configuration
 */
/*
 * SCTP Configuration (EXPERIMENTAL)
 */
/*
 * QoS and/or fair queueing
 */



/*
 * Network testing
 */
/*
 * ARCnet devices
 */


/*
 * Ethernet (10 or 100Mbit)
 */
/*
 * Tulip family network device support
 */
/*
 * Ethernet (1000 Mbit)
 */
/*
 * Ethernet (10000 Mbit)
 */





/*
 * Token Ring devices
 */


/*
 * Wireless LAN (non-hamradio)
 */


/*
 * Wan interfaces
 */
/*
 * ISDN subsystem
 */


/*
 * Telephony Support
 */


/*
 * Input device support
 */


/*
 * Userland interfaces
 */
/*
 * Input I/O drivers
 */
/*
 * Input Device Drivers
 */
/*
 * Character devices
 */





/*
 * Serial drivers
 */






/*
 * Non-8250 serial port support
 */
/*
 * IPMI
 */


/*
 * Watchdog Cards
 */
/*
 * Ftape, the floppy tape device driver
 */
/*
 * I2C support
 */


/*
 * Dallas's 1-wire bus
 */


/*
 * Misc devices
 */


/*
 * Multimedia devices
 */


/*
 * Digital Video Broadcasting Devices
 */


/*
 * Graphics support
 */



/*
 * Console display driver support
 */




/*
 * Sound
 */


/*
 * Advanced Linux Sound Architecture
 */
/*
 * Generic devices
 */






/*
 * ISA devices
 */
/*
 * PCI devices
 */
/*
 * USB devices
 */



/*
 * Open Sound System
 */


/*
 * USB support
 */



/*
 * Miscellaneous USB options
 */
/*
 * USB Host Controller Drivers
 */







/*
 * USB Device Class drivers
 */






/*
 * NOTE: USB_STORAGE enables SCSI, and 'SCSI disk support' may also be needed; see USB_STORAGE Help for more information
 */
/*
 * USB Input Devices
 */
/*
 * USB Imaging devices
 */



/*
 * USB Multimedia devices
 */


/*
 * Video4Linux support is needed for USB Multimedia device support
 */

/*
 * USB Network Adapters
 */






/*
 * USB port drivers
 */


/*
 * USB Serial Converter support
 */


/*
 * USB Miscellaneous drivers
 */
/*
 * USB ATM/DSL drivers
 */

/*
 * USB Gadget Support
 */


/*
 * MMC/SD Card support
 */


/*
 * InfiniBand support
 */


/*
 * File systems
 */
/*
 * XFS support
 */
/*
 * CD-ROM/DVD Filesystems
 */






/*
 * DOS/FAT/NT Filesystems
 */







/*
 * Pseudo filesystems
 */
/*
 * Miscellaneous filesystems
 */
/*
 * Network File Systems
 */
/*
 * Partition Types
 */



/*
 * Native Language Support
 */
/*
 * Profiling support
 */



/*
 * Kernel hacking
 */
/*
 * Security options
 */



/*
 * Cryptographic options
 */


/*
 * Hardware crypto devices
 */

/*
 * Library routines
 */
/*
 * Allow us to mark functions as 'deprecated' and have gcc emit a nice
 * warning for each use, in hopes of speeding the functions removal.
 * Usage is:
 * 		int __deprecated foo(void)
 */
/*
 * Allow us to avoid 'defined but not used' warnings on functions and data,
 * as well as force them to be emitted to the assembly file.
 *
 * As of gcc 3.3, static functions that are not marked with attribute((used))
 * may be elided from the assembly file.  As of gcc 3.3, static data not so
 * marked will not be elided, but this may change in a future gcc version.
 *
 * In prior versions of gcc, such functions and data would be emitted, but
 * would be warned about except with attribute((unused)).
 */




/*
 * From the GCC manual:
 *
 * Many functions have no effects except the return value and their
 * return value depends only on the parameters and/or global
 * variables.  Such a function can be subject to common subexpression
 * elimination and loop optimization just as an arithmetic operator
 * would be.
 * [...]
 */




/*
 * From the GCC manual:
 *
 * Many functions do not examine any values except their arguments,
 * and have no effects except the return value.  Basically this is
 * just slightly more strict class than the `pure' attribute above,
 * since function is not allowed to read global memory.
 *
 * Note that a function that has pointer arguments and examines the
 * data pointed to must _not_ be declared `const'.  Likewise, a
 * function that calls a non-`const' function usually must not be
 * `const'.  It does not make sense for a `const' function to return
 * `void'.
 */
/* PAGE_SHIFT determines the page size */
/* to align the pointer to the (next) page boundary */


/*
 * This handles the memory map.. We could make this a config
 * option, but too many people screw it up, and too few need
 * it.
 *
 * A __PAGE_OFFSET of 0xC0000000 means that the kernel has
 * a virtual address space of one gigabyte, which limits the
 * amount of physical memory you can use to about 950MB. 
 *
 * If you want more physical memory than this then see the CONFIG_HIGHMEM4G
 * and CONFIG_HIGHMEM64G options in the kernel configuration.
 */
/*
 * low level task data that entry.S needs immediate access to
 * - this struct should fit entirely inside of one cache line
 * - this struct shares the supervisor stack pages
 * - if the contents of this structure are changed, the assembly constants must also be changed
 */
/*
 * DO NOT MODIFY.
 *
 * This file was generated by arch/i386/Makefile
 *
 */
/*
 * macros/functions for gaining access to the thread information structure
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
/* how to get the thread information struct from ASM */




/* use this one if reg already contains %esp */





/*
 * thread information flags
 * - these are process state flags that various assembly files may need to access
 * - pending work-to-be-done flags are in LSW
 * - other flags in MSW
 */
/* work to do on interrupt/exception return */




/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */







OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(startup_32)
jiffies = jiffies_64;
SECTIONS
{
  . = (0xC0000000) + 0x100000;
  /* read-only */
  _text = .; /* Text and read-only data */
  .text : {
 *(.text)
 __sched_text_start = .; *(.sched.text) __sched_text_end = .;
 __lock_text_start = .; *(.spinlock.text) __lock_text_end = .;
 *(.fixup)
 *(.gnu.warning)
 } = 0x9090

  _etext = .; /* End of text section */

  . = ALIGN(16); /* Exception table */
  __start___ex_table = .;
  __ex_table : { *(__ex_table) }
  __stop___ex_table = .;

  .rodata : AT(ADDR(.rodata) - 0) { *(.rodata) *(.rodata.*) *(__vermagic) } .rodata1 : AT(ADDR(.rodata1) - 0) { *(.rodata1) } .pci_fixup : AT(ADDR(.pci_fixup) - 0) { __start_pci_fixups_early = .; *(.pci_fixup_early) __end_pci_fixups_early = .; __start_pci_fixups_header = .; *(.pci_fixup_header) __end_pci_fixups_header = .; __start_pci_fixups_final = .; *(.pci_fixup_final) __end_pci_fixups_final = .; __start_pci_fixups_enable = .; *(.pci_fixup_enable) __end_pci_fixups_enable = .; } __ksymtab : AT(ADDR(__ksymtab) - 0) { __start___ksymtab = .; *(__ksymtab) __stop___ksymtab = .; } __ksymtab_gpl : AT(ADDR(__ksymtab_gpl) - 0) { __start___ksymtab_gpl = .; *(__ksymtab_gpl) __stop___ksymtab_gpl = .; } __kcrctab : AT(ADDR(__kcrctab) - 0) { __start___kcrctab = .; *(__kcrctab) __stop___kcrctab = .; } __kcrctab_gpl : AT(ADDR(__kcrctab_gpl) - 0) { __start___kcrctab_gpl = .; *(__kcrctab_gpl) __stop___kcrctab_gpl = .; } __ksymtab_strings : AT(ADDR(__ksymtab_strings) - 0) { *(__ksymtab_strings) } __param : AT(ADDR(__param) - 0) { __start___param = .; *(__param) __stop___param = .; }

  /* writeable */
  .data : { /* Data */
 *(.data)
 CONSTRUCTORS
 }

  . = ALIGN(4096);
  __nosave_begin = .;
  .data_nosave : { *(.data.nosave) }
  . = ALIGN(4096);
  __nosave_end = .;

  . = ALIGN(4096);
  .data.page_aligned : { *(.data.idt) }

  . = ALIGN(32);
  .data.cacheline_aligned : { *(.data.cacheline_aligned) }

  _edata = .; /* End of data section */

  . = ALIGN((4096)); /* init_task */
  .data.init_task : { *(.data.init_task) }

  /* will be freed after init */
  . = ALIGN(4096); /* Init code and data */
  __init_begin = .;
  .init.text : {
 _sinittext = .;
 *(.init.text)
 _einittext = .;
  }
  .init.data : { *(.init.data) }
  . = ALIGN(16);
  __setup_start = .;
  .init.setup : { *(.init.setup) }
  __setup_end = .;
  __initcall_start = .;
  .initcall.init : {
 *(.initcall1.init)
 *(.initcall2.init)
 *(.initcall3.init)
 *(.initcall4.init)
 *(.initcall5.init)
 *(.initcall6.init)
 *(.initcall7.init)
  }
  __initcall_end = .;
  __con_initcall_start = .;
  .con_initcall.init : { *(.con_initcall.init) }
  __con_initcall_end = .;
  .security_initcall.init : { __security_initcall_start = .; *(.security_initcall.init) __security_initcall_end = .; }
  . = ALIGN(4);
  __alt_instructions = .;
  .altinstructions : { *(.altinstructions) }
  __alt_instructions_end = .;
 .altinstr_replacement : { *(.altinstr_replacement) }
  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : { *(.exit.text) }
  .exit.data : { *(.exit.data) }
  . = ALIGN(4096);
  __initramfs_start = .;
  .init.ramfs : { *(.init.ramfs) }
  __initramfs_end = .;
  . = ALIGN(32);
  __per_cpu_start = .;
  .data.percpu : { *(.data.percpu) }
  __per_cpu_end = .;
  . = ALIGN(4096);
  __init_end = .;
  /* freed after init ends here */

  __bss_start = .; /* BSS */
  .bss : {
 *(.bss.page_aligned)
 *(.bss)
  }
  . = ALIGN(4);
  __bss_stop = .;

  _end = . ;

  /* This is where the kernel creates the early boot page tables */
  . = ALIGN(4096);
  pg0 = .;

  /* Sections to be discarded */
  /DISCARD/ : {
 *(.exitcall.exit)
 }

  /* Stabs debugging sections.  */
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .stab.excl 0 : { *(.stab.excl) }
  .stab.exclstr 0 : { *(.stab.exclstr) }
  .stab.index 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment 0 : { *(.comment) }
}
