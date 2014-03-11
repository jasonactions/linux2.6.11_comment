#include <linux/highmem.h>

/**
 * 建立永久内核映射。
 */
void *kmap(struct page *page)
{
	/**
	 * kmap是允许睡眠的，意思是说不能在中断和可延迟函数中调用。
	 * 如果试图在中断中调用，那么might_sleep会触发异常。
	 */
	might_sleep();
	/**
	 * 如果页框不属于高端内存，则调用page_address直接返回线性地址。
	 */
	if (!PageHighMem(page))
		return page_address(page);
	/**
	 * 否则调用kmap_high真正建立永久内核映射。
	 */
	return kmap_high(page);
}

/**
 * 撤销先前由kmap建立的永久内核映射
 */
void kunmap(struct page *page)
{
	/**
	 * kmap和kunmap都不允许在中断中使用。
	 */
	if (in_interrupt())
		BUG();
	/**
	 * 如果对应页根本就不是高端内存，当然就没有进行内核映射，也就不用调用本函数了。
	 */
	if (!PageHighMem(page))
		return;
	/**
	 * kunmap_high真正执行unmap过程
	 */
	kunmap_high(page);
}

/*
 * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
 * no global lock is needed and because the kmap code must perform a global TLB
 * invalidation when the kmap pool wraps.
 *
 * However when holding an atomic kmap is is not legal to sleep, so atomic
 * kmaps are appropriate for short, tight code paths only.
 */
/**
 * 建立临时内核映射
 * type和CPU共同确定用哪个固定映射的线性地址映射请求页。
 */
void *kmap_atomic(struct page *page, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	/* even !CONFIG_PREEMPT needs this, for in_atomic in do_page_fault */
	inc_preempt_count();
	/**
	 * 如果被映射的页不属于高端内存，当然用不着映射。直接返回线性地址就行了。
	 */
	if (!PageHighMem(page))
		return page_address(page);

	/**
	 * 通过type和CPU确定线性地址。
	 */
	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
#ifdef CONFIG_DEBUG_HIGHMEM
	if (!pte_none(*(kmap_pte-idx)))
		BUG();
#endif
	/**
	 * 将线性地址与页表项建立映射。
	 */
	set_pte(kmap_pte-idx, mk_pte(page, kmap_prot));
	/**
	 * 当然，最后必须刷新一下TLB。然后才能返回线性地址。
	 */
	__flush_tlb_one(vaddr);

	return (void*) vaddr;
}

/**
 * 撤销内核临时映射
 */
void kunmap_atomic(void *kvaddr, enum km_type type)
{
#ifdef CONFIG_DEBUG_HIGHMEM
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	enum fixed_addresses idx = type + KM_TYPE_NR*smp_processor_id();

	if (vaddr < FIXADDR_START) { // FIXME
		dec_preempt_count();
		preempt_check_resched();
		return;
	}

	if (vaddr != __fix_to_virt(FIX_KMAP_BEGIN+idx))
		BUG();

	/*
	 * force other mappings to Oops if they'll try to access
	 * this pte without first remap it
	 */
	/**
	 * 取消映射并刷新TLB
	 */
	pte_clear(kmap_pte-idx);
	__flush_tlb_one(vaddr);
#endif
	/**
	 * 允许抢占，并检查调度点。
	 */
	dec_preempt_count();
	preempt_check_resched();
}

struct page *kmap_atomic_to_page(void *ptr)
{
	unsigned long idx, vaddr = (unsigned long)ptr;
	pte_t *pte;

	if (vaddr < FIXADDR_START)
		return virt_to_page(ptr);

	idx = virt_to_fix(vaddr);
	pte = kmap_pte - (idx - FIX_KMAP_BEGIN);
	return pte_page(*pte);
}

