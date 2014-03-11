#ifndef __LINUX_PERCPU_H
#define __LINUX_PERCPU_H
#include <linux/spinlock.h> /* For preempt_disable() */
#include <linux/slab.h> /* For kmalloc() */
#include <linux/smp.h>
#include <linux/string.h> /* For memset() */
#include <asm/percpu.h>

/* Enough to cover all DEFINE_PER_CPUs in kernel, including modules. */
#ifndef PERCPU_ENOUGH_ROOM
#define PERCPU_ENOUGH_ROOM 32768
#endif

/* Must be an lvalue. */
/**
 * 先禁用内核抢占，然后在每CPU数组name中，为本地CPU选择元素。
 */
#define get_cpu_var(var) (*({ preempt_disable(); &__get_cpu_var(var); }))
/**
 * 启用内核抢占（name参数无用）
 */
#define put_cpu_var(var) preempt_enable()

#ifdef CONFIG_SMP

struct percpu_data {
	void *ptrs[NR_CPUS];
	void *blkp;
};

/* 
 * Use this to get to a cpu's version of the per-cpu object allocated using
 * alloc_percpu.  Non-atomic access to the current CPU's version should
 * probably be combined with get_cpu()/put_cpu().
 */ 
/**
 * 返回每CPU数组中，与参数cpu对应的cpu元素地址，参数pointer给出数组的地址。
 */
#define per_cpu_ptr(ptr, cpu)                   \
({                                              \
        struct percpu_data *__p = (struct percpu_data *)~(unsigned long)(ptr); \
        (__typeof__(ptr))__p->ptrs[(cpu)];	\
})

extern void *__alloc_percpu(size_t size, size_t align);
extern void free_percpu(const void *);

#else /* CONFIG_SMP */

#define per_cpu_ptr(ptr, cpu) (ptr)

static inline void *__alloc_percpu(size_t size, size_t align)
{
	void *ret = kmalloc(size, GFP_KERNEL);
	if (ret)
		memset(ret, 0, size);
	return ret;
}

/**
 * 释放被动态分配的每CPU数组。
 */
static inline void free_percpu(const void *ptr)
{	
	kfree(ptr);
}

#endif /* CONFIG_SMP */

/* Simple wrapper for the common case: zeros memory. */
/**
 * 动态分配type类型数据结构的每CPU数组。并返回它的地址。
 */
#define alloc_percpu(type) \
	((type *)(__alloc_percpu(sizeof(type), __alignof__(type))))

#endif /* __LINUX_PERCPU_H */
