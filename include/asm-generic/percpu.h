#ifndef _ASM_GENERIC_PERCPU_H_
#define _ASM_GENERIC_PERCPU_H_
#include <linux/compiler.h>

#define __GENERIC_PER_CPU
#ifdef CONFIG_SMP

extern unsigned long __per_cpu_offset[NR_CPUS];

/* Separate out the type, so (int[3], foo) works. */
/**
 * 静态分配一个每CPU数组，数组名为name，结构类型为type
 */
#define DEFINE_PER_CPU(type, name) \
    __attribute__((__section__(".data.percpu"))) __typeof__(type) per_cpu__##name

/* var is in discarded region: offset to particular copy we want */
/**
 * 为CPU选择一个每CPU数组元素，CPU由参数CPU指定，数组名为name
 */
#define per_cpu(var, cpu) (*RELOC_HIDE(&per_cpu__##var, __per_cpu_offset[cpu]))
/**
 * 选择每CPU数组name的本地CPU元素。
 */
#define __get_cpu_var(var) per_cpu(var, smp_processor_id())

/* A macro to avoid #include hell... */
#define percpu_modcopy(pcpudst, src, size)			\
do {								\
	unsigned int __i;					\
	for (__i = 0; __i < NR_CPUS; __i++)			\
		if (cpu_possible(__i))				\
			memcpy((pcpudst)+__per_cpu_offset[__i],	\
			       (src), (size));			\
} while (0)
#else /* ! SMP */

#define DEFINE_PER_CPU(type, name) \
    __typeof__(type) per_cpu__##name

#define per_cpu(var, cpu)			(*((void)cpu, &per_cpu__##var))
#define __get_cpu_var(var)			per_cpu__##var

#endif	/* SMP */

#define DECLARE_PER_CPU(type, name) extern __typeof__(type) per_cpu__##name

#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(per_cpu__##var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(per_cpu__##var)

#endif /* _ASM_GENERIC_PERCPU_H_ */
