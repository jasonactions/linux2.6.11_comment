/*
 *  linux/mm/vmalloc.c
 *
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <linux/vmalloc.h>

#include <asm/uaccess.h>
#include <asm/tlbflush.h>


/**
 * 保护vmlist链表的自旋锁。
 */
DEFINE_RWLOCK(vmlist_lock);
/**
 * vm_struct链表的第一个元素。
 */
struct vm_struct *vmlist;

static void unmap_area_pte(pmd_t *pmd, unsigned long address,
				  unsigned long size)
{
	unsigned long end;
	pte_t *pte;

	if (pmd_none(*pmd))
		return;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}

	pte = pte_offset_kernel(pmd, address);
	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;

	do {
		pte_t page;
		page = ptep_get_and_clear(pte);
		address += PAGE_SIZE;
		pte++;
		if (pte_none(page))
			continue;
		if (pte_present(page))
			continue;
		printk(KERN_CRIT "Whee.. Swapped out page in kernel page table\n");
	} while (address < end);
}

static void unmap_area_pmd(pud_t *pud, unsigned long address,
				  unsigned long size)
{
	unsigned long end;
	pmd_t *pmd;

	if (pud_none(*pud))
		return;
	if (pud_bad(*pud)) {
		pud_ERROR(*pud);
		pud_clear(pud);
		return;
	}

	pmd = pmd_offset(pud, address);
	address &= ~PUD_MASK;
	end = address + size;
	if (end > PUD_SIZE)
		end = PUD_SIZE;

	do {
		unmap_area_pte(pmd, address, end - address);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
}

static void unmap_area_pud(pgd_t *pgd, unsigned long address,
			   unsigned long size)
{
	pud_t *pud;
	unsigned long end;

	if (pgd_none(*pgd))
		return;
	if (pgd_bad(*pgd)) {
		pgd_ERROR(*pgd);
		pgd_clear(pgd);
		return;
	}

	pud = pud_offset(pgd, address);
	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;

	do {
		unmap_area_pmd(pud, address, end - address);
		address = (address + PUD_SIZE) & PUD_MASK;
		pud++;
	} while (address && (address < end));
}

static int map_area_pte(pte_t *pte, unsigned long address,
			       unsigned long size, pgprot_t prot,
			       struct page ***pages)
{
	unsigned long end;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;

	do {
		struct page *page = **pages;
		WARN_ON(!pte_none(*pte));
		if (!page)
			return -ENOMEM;

		set_pte(pte, mk_pte(page, prot));
		address += PAGE_SIZE;
		pte++;
		(*pages)++;
	} while (address < end);
	return 0;
}

static int map_area_pmd(pmd_t *pmd, unsigned long address,
			       unsigned long size, pgprot_t prot,
			       struct page ***pages)
{
	unsigned long base, end;

	base = address & PUD_MASK;
	address &= ~PUD_MASK;
	end = address + size;
	if (end > PUD_SIZE)
		end = PUD_SIZE;

	do {
		pte_t * pte = pte_alloc_kernel(&init_mm, pmd, base + address);
		if (!pte)
			return -ENOMEM;
		if (map_area_pte(pte, address, end - address, prot, pages))
			return -ENOMEM;
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);

	return 0;
}

static int map_area_pud(pud_t *pud, unsigned long address,
			       unsigned long end, pgprot_t prot,
			       struct page ***pages)
{
	do {
		pmd_t *pmd = pmd_alloc(&init_mm, pud, address);
		if (!pmd)
			return -ENOMEM;
		if (map_area_pmd(pmd, address, end - address, prot, pages))
			return -ENOMEM;
		address = (address + PUD_SIZE) & PUD_MASK;
		pud++;
	} while (address && address < end);

	return 0;
}

void unmap_vm_area(struct vm_struct *area)
{
	unsigned long address = (unsigned long) area->addr;
	unsigned long end = (address + area->size);
	unsigned long next;
	pgd_t *pgd;
	int i;

	pgd = pgd_offset_k(address);
	flush_cache_vunmap(address, end);
	for (i = pgd_index(address); i <= pgd_index(end-1); i++) {
		next = (address + PGDIR_SIZE) & PGDIR_MASK;
		if (next <= address || next > end)
			next = end;
		unmap_area_pud(pgd, address, next - address);
		address = next;
	        pgd++;
	}
	flush_tlb_kernel_range((unsigned long) area->addr, end);
}

/**
 * 将线性地址和页框对应起来
 * area-指向内存区的vm_struct描述符的指针
 * prot-已分配页框的保护位，它总是被置为0x63，对应着present,accessed,read/write及dirty.
 * pages-指向一个指针数组的变量的地址。该指针数组的指针指向页描述符。
 */
int map_vm_area(struct vm_struct *area, pgprot_t prot, struct page ***pages)
{
	/**
	 * 首先将内存区的开始和末尾的线性地址分配给局部变量address和end
	 */
	unsigned long address = (unsigned long) area->addr;
	unsigned long end = address + (area->size-PAGE_SIZE);
	unsigned long next;
	pgd_t *pgd;
	int err = 0;
	int i;

	/**
	 * 使用pgd_offset_k来获得主内核页全局目录中的目录项。该目录项对应于内存区起始线性地址。
	 */
	pgd = pgd_offset_k(address);
	/**
	 * 获得内核页表自旋锁。
	 */
	spin_lock(&init_mm.page_table_lock);
	/**
	 * 此循环为每个页框建立页表项。
	 */
	for (i = pgd_index(address); i <= pgd_index(end-1); i++) {
		/**
		 * 调用pud_alloc来为新内存区创建一个页上级目录。并把它的物理地址写入内核页全局目录的合适表项。
		 */
		pud_t *pud = pud_alloc(&init_mm, pgd, address);
		if (!pud) {
			err = -ENOMEM;
			break;
		}
		next = (address + PGDIR_SIZE) & PGDIR_MASK;
		if (next < address || next > end)
			next = end;
		/**
		 * map_area_pud函数为页上级目录所指向的所有页表建立对应关系。
		 */
		if (map_area_pud(pud, address, next, prot, pages)) {
			err = -ENOMEM;
			break;
		}

		address = next;
		pgd++;
	}

	spin_unlock(&init_mm.page_table_lock);
	flush_cache_vmap((unsigned long) area->addr, end);
	return err;
}

#define IOREMAP_MAX_ORDER	(7 + PAGE_SHIFT)	/* 128 pages */

struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end)
{
	struct vm_struct **p, *tmp, *area;
	unsigned long align = 1;
	unsigned long addr;

	if (flags & VM_IOREMAP) {
		int bit = fls(size);

		if (bit > IOREMAP_MAX_ORDER)
			bit = IOREMAP_MAX_ORDER;
		else if (bit < PAGE_SHIFT)
			bit = PAGE_SHIFT;

		align = 1ul << bit;
	}
	addr = ALIGN(start, align);

	/**
	 * 调用kmalloc为vm_struct类型的新描述符获得一个内存区。
	 */
	area = kmalloc(sizeof(*area), GFP_KERNEL);
	if (unlikely(!area))
		return NULL;

	/*
	 * We always allocate a guard page.
	 */
	size += PAGE_SIZE;
	if (unlikely(!size)) {
		kfree (area);
		return NULL;
	}

	/**
	 * 为写获得vmlist_lock锁。
	 */
	write_lock(&vmlist_lock);
	/**
	 * 扫描vmlist链表，来查找线性地址的一个空闲区域。至少覆盖size+4096个地址(4096是安全区)
	 */
	for (p = &vmlist; (tmp = *p) != NULL ;p = &tmp->next) {
		if ((unsigned long)tmp->addr < addr) {
			if((unsigned long)tmp->addr + tmp->size >= addr)
				addr = ALIGN(tmp->size + 
					     (unsigned long)tmp->addr, align);
			continue;
		}
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long)tmp->addr)
			goto found;
		addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
		if (addr > end - size)
			goto out;
	}

found:
	/**
	 * 如果存在这样一个空闲区间，就初始化描述符的字段
	 */
	area->next = *p;
	*p = area;

	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->pages = NULL;
	area->nr_pages = 0;
	area->phys_addr = 0;
	/**
	 * 释放锁并返回内存区的起始地址。
	 */
	write_unlock(&vmlist_lock);

	return area;

out:
	/**
	 * 没有找到空闲区，就释放锁并释放先前得到的描述符，然后返回NULL。
	 */
	write_unlock(&vmlist_lock);
	kfree(area);
	if (printk_ratelimit())
		printk(KERN_WARNING "allocation failed: out of vmalloc space - use vmalloc=<size> to increase size.\n");
	return NULL;
}

/**
 *	get_vm_area  -  reserve a contingous kernel virtual area
 *
 *	@size:		size of the area
 *	@flags:		%VM_IOREMAP for I/O mappings or VM_ALLOC
 *
 *	Search an area of @size in the kernel virtual mapping area,
 *	and reserved it for out purposes.  Returns the area descriptor
 *	on success or %NULL on failure.
 */
/**
 * 在线性地址VMALLOC_START和VMALLOC_END之间查找一个空闲区域
 * size-将被创建的内存区的字节大小
 * flag-指定空闲区类型
 */
struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area(size, flags, VMALLOC_START, VMALLOC_END);
}

/**
 *	remove_vm_area  -  find and remove a contingous kernel virtual area
 *
 *	@addr:		base address
 *
 *	Search for the kernel VM area starting at @addr, and remove it.
 *	This function returns the found VM area, but using it is NOT safe
 *	on SMP machines.
 */
struct vm_struct *remove_vm_area(void *addr)
{
	struct vm_struct **p, *tmp;

	write_lock(&vmlist_lock);
	for (p = &vmlist ; (tmp = *p) != NULL ;p = &tmp->next) {
		 if (tmp->addr == addr)
			 goto found;
	}
	write_unlock(&vmlist_lock);
	return NULL;

found:
	unmap_vm_area(tmp);
	*p = tmp->next;
	write_unlock(&vmlist_lock);
	return tmp;
}

/**
 * 被vfree或者vunmap调用，来释放非连续分配的内存区。
 * addr-要释放的内存区的起始地址。
 * deallocate_pages-如果被映射的页框需要释放到分区页框分配器，就置位(当vfree调用本函数时)。否则不置位(被vunmap调用时)
 */
void __vunmap(void *addr, int deallocate_pages)
{
	struct vm_struct *area;

	if (!addr)
		return;

	if ((PAGE_SIZE-1) & (unsigned long)addr) {
		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		WARN_ON(1);
		return;
	}

	/**
	 * 调用remove_vm_area得到vm_struct描述符的地址。
	 * 并清除非连续内存区中的线性地址对应的内核的页表项。
	 */
	area = remove_vm_area(addr);
	if (unlikely(!area)) {
		printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
				addr);
		WARN_ON(1);
		return;
	}

	/**
	 * 如果deallocate_pages被置位，扫描指向页描述符的area->nr_pages
	 */
	if (deallocate_pages) {
		int i;

		for (i = 0; i < area->nr_pages; i++) {
			/**
			 * 对每一个数组元素，调用__free_page函数释放页框到分区页框分配器。
			 */
			if (unlikely(!area->pages[i]))
				BUG();
			__free_page(area->pages[i]);
		}

		/**
		 * 释放area->pages数组本身。
		 */
		if (area->nr_pages > PAGE_SIZE/sizeof(struct page *))
			vfree(area->pages);
		else
			kfree(area->pages);
	}

	/**
	 * 释放vm_struct描述符。
	 */
	kfree(area);
	return;
}

/**
 *	vfree  -  release memory allocated by vmalloc()
 *
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr, as
 *	obtained from vmalloc(), vmalloc_32() or __vmalloc().
 *
 *	May not be called in interrupt context.
 */
/**
 * 释放vmalloc或者vmalloc_32创建的非连续内存区。
 */
void vfree(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 1);
}

EXPORT_SYMBOL(vfree);

/**
 *	vunmap  -  release virtual mapping obtained by vmap()
 *
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr,
 *	which was created from the page array passed to vmap().
 *
 *	May not be called in interrupt context.
 */
/**
 * 释放vmap创建的内存区。
 */
void vunmap(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 0);
}

EXPORT_SYMBOL(vunmap);

/**
 *	vmap  -  map an array of pages into virtually contiguous space
 *
 *	@pages:		array of page pointers
 *	@count:		number of pages to map
 *	@flags:		vm_area->flags
 *	@prot:		page protection for the mapping
 *
 *	Maps @count pages from @pages into contiguous kernel virtual
 *	space.
 */
/**
 * 它将映射非连续内存区中已经分配的页框。本质上，该函数接收一组指向页描述符的指针作为参数，
 * 调用get_vm_area得到一个新的vm_struct描述符。然后调用map_vm_area来映射页框。因此该函数与vmalloc类似，但是不分配页框。
 */
void *vmap(struct page **pages, unsigned int count,
		unsigned long flags, pgprot_t prot)
{
	struct vm_struct *area;

	if (count > num_physpages)
		return NULL;

	area = get_vm_area((count << PAGE_SHIFT), flags);
	if (!area)
		return NULL;
	if (map_vm_area(area, prot, &pages)) {
		vunmap(area->addr);
		return NULL;
	}

	return area->addr;
}

EXPORT_SYMBOL(vmap);

/**
 *	__vmalloc  -  allocate virtually contiguous memory
 *
 *	@size:		allocation size
 *	@gfp_mask:	flags for the page level allocator
 *	@prot:		protection mask for the allocated pages
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator with @gfp_mask flags.  Map them into contiguous
 *	kernel virtual space, using a pagetable protection of @prot.
 */
void *__vmalloc(unsigned long size, int gfp_mask, pgprot_t prot)
{
	struct vm_struct *area;
	struct page **pages;
	unsigned int nr_pages, array_size, i;

	/**
	 * 首先将参数size设为4096的整数倍。
	 */
	size = PAGE_ALIGN(size);
	if (!size || (size >> PAGE_SHIFT) > num_physpages)
		return NULL;

	/**
	 * 通过调用get_vm_area来创建一个新的描述符。并返回分配给这个内存区的线性地址。
	 * 描述符的flags字段被初始化为VM_ALLOC，这意味着通过使用vmalloc函数，非连续页框将被映射到一个线性地址空间。
	 */
	area = get_vm_area(size, VM_ALLOC);
	if (!area)
		return NULL;

	nr_pages = size >> PAGE_SHIFT;
	array_size = (nr_pages * sizeof(struct page *));

	area->nr_pages = nr_pages;
	/* Please note that the recursion is strictly bounded. */
	/**
	 * 为页描述符指针数组分配页框。
	 */
	if (array_size > PAGE_SIZE)
		pages = __vmalloc(array_size, gfp_mask, PAGE_KERNEL);
	else
		pages = kmalloc(array_size, (gfp_mask & ~__GFP_HIGHMEM));
	area->pages = pages;
	if (!area->pages) {
		remove_vm_area(area->addr);
		kfree(area);
		return NULL;
	}
	memset(area->pages, 0, array_size);

	/**
	 * 重复调用alloc_page，为内存区分配nr_pages个页框。并把对应的页描述符放到area->pages中。
	 * 必须使用area->pages数组是因为:页框可能属于ZONE_HIGHMEM内存管理区，此时它们不一定映射到一个线性地址上。
	 */
	for (i = 0; i < area->nr_pages; i++) {
		area->pages[i] = alloc_page(gfp_mask);
		if (unlikely(!area->pages[i])) {
			/* Successfully allocated i pages, free them in __vunmap() */
			area->nr_pages = i;
			goto fail;
		}
	}

	/**
	 * 现在已经得到了一个连续的线性地址空间，并且分配了一组非连续的页框来映射这些地址。
	 * 需要修改内核页表项，将二者对应起来。这是map_vm_area的工作。
	 */
	if (map_vm_area(area, prot, &pages))
		goto fail;
	return area->addr;

fail:
	vfree(area->addr);
	return NULL;
}

EXPORT_SYMBOL(__vmalloc);

/**
 *	vmalloc  -  allocate virtually contiguous memory
 *
 *	@size:		allocation size
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
/**
 * 给内核分配一个非连续内存区。
 * size-所请求分配的内存区的大小。
 */
void *vmalloc(unsigned long size)
{
       return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
}

EXPORT_SYMBOL(vmalloc);

/**
 *	vmalloc_exec  -  allocate virtually contiguous, executable memory
 *
 *	@size:		allocation size
 *
 *	Kernel-internal function to allocate enough pages to cover @size
 *	the page level allocator and map them into contiguous and
 *	executable kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */

#ifndef PAGE_KERNEL_EXEC
# define PAGE_KERNEL_EXEC PAGE_KERNEL
#endif

void *vmalloc_exec(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
}

/**
 *	vmalloc_32  -  allocate virtually contiguous memory (32bit addressable)
 *
 *	@size:		allocation size
 *
 *	Allocate enough 32bit PA addressable pages to cover @size from the
 *	page level allocator and map them into contiguous kernel virtual space.
 */
/**
 * 与vmalloc类似，但是只从ZONE_NORMAL和ZONE_DMA中分配内存。
 */
void *vmalloc_32(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL);
}

EXPORT_SYMBOL(vmalloc_32);

long vread(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			*buf = '\0';
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*buf = *addr;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

long vwrite(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*addr = *buf;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}
