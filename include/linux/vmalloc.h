#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <asm/page.h>		/* pgprot_t */

/* bits in vm_struct->flags */
/**
 * 表示使用ioremap映射的硬件设备的板上内存。
 */
#define VM_IOREMAP	0x00000001	/* ioremap() and friends */
/**
 * 表示使用vmalloc得到的页
 */
#define VM_ALLOC	0x00000002	/* vmalloc() */
/**
 * 表示使用vmap映射的已经被分配的页。
 */
#define VM_MAP		0x00000004	/* vmap()ed pages */
/* bits [20..32] reserved for arch specific ioremap internals */

/**
 * 非连续内存区的描述符
 */
struct vm_struct {
	/**
	 * 内存区内第一个内存单元的线性地址。
	 */
	void			*addr;
	/**
	 * 内存区大小加4096(内存区之间的安全区的大小)
	 */
	unsigned long		size;
	/**
	 * 非连续内存区映射的内存的类型。
	 * VM_ALLOC表示使用vmalloc得到的页.
	 * VM_MAP表示使用vmap映射的已经被分配的页。
	 * VM_IOREMAP表示使用ioremap映射的硬件设备的板上内存。
	 */
	unsigned long		flags;
	/**
	 * 指向nr_pages数组的指针，该数组由指向页描述符的指针组成。
	 */
	struct page		**pages;
	/**
	 * 内存区填充的页的个数。
	 */
	unsigned int		nr_pages;
	/**
	 * 一般为0,除非内存已经被创建来映射一个硬件设备IO共享内存。
	 */
	unsigned long		phys_addr;
	/**
	 * 指向下一个vm_struct结构的指针。
	 */
	struct vm_struct	*next;
};

/*
 *	Highlevel APIs for driver use
 */
extern void *vmalloc(unsigned long size);
extern void *vmalloc_exec(unsigned long size);
extern void *vmalloc_32(unsigned long size);
extern void *__vmalloc(unsigned long size, int gfp_mask, pgprot_t prot);
extern void vfree(void *addr);

extern void *vmap(struct page **pages, unsigned int count,
			unsigned long flags, pgprot_t prot);
extern void vunmap(void *addr);
 
/*
 *	Lowlevel-APIs (not for driver use!)
 */
extern struct vm_struct *get_vm_area(unsigned long size, unsigned long flags);
extern struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end);
extern struct vm_struct *remove_vm_area(void *addr);
extern int map_vm_area(struct vm_struct *area, pgprot_t prot,
			struct page ***pages);
extern void unmap_vm_area(struct vm_struct *area);

/*
 *	Internals.  Dont't use..
 */
extern rwlock_t vmlist_lock;
extern struct vm_struct *vmlist;

#endif /* _LINUX_VMALLOC_H */
