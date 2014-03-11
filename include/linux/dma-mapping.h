#ifndef _ASM_LINUX_DMA_MAPPING_H
#define _ASM_LINUX_DMA_MAPPING_H

#include <linux/device.h>
#include <linux/err.h>

/* These definitions mirror those in pci.h, so they can be used
 * interchangeably with their PCI_ counterparts */
/**
 * 流式映射数据流动的方向。
 */
enum dma_data_direction {
	/**
	 * 双向流动的数据。在一些体系结构中，这种类型的流式映射影响性能。
	 */
	DMA_BIDIRECTIONAL = 0,
	/**
	 * 数据被发送到设备。
	 */
	DMA_TO_DEVICE = 1,
	/**
	 * 数据从设备发送到CPU。
	 */
	DMA_FROM_DEVICE = 2,
	/**
	 * 用于调试目的。如果使用设置了该符号的缓冲区，将导致内核错误。
	 */
	DMA_NONE = 3,
};

#define DMA_64BIT_MASK	0xffffffffffffffffULL
#define DMA_32BIT_MASK	0x00000000ffffffffULL

#include <asm/dma-mapping.h>

/* Backwards compat, remove in 2.7.x */
#define dma_sync_single		dma_sync_single_for_cpu
#define dma_sync_sg		dma_sync_sg_for_cpu

extern u64 dma_get_required_mask(struct device *dev);

/* flags for the coherent memory api */
#define	DMA_MEMORY_MAP			0x01
#define DMA_MEMORY_IO			0x02
#define DMA_MEMORY_INCLUDES_CHILDREN	0x04
#define DMA_MEMORY_EXCLUSIVE		0x08

#ifndef ARCH_HAS_DMA_DECLARE_COHERENT_MEMORY
static inline int
dma_declare_coherent_memory(struct device *dev, dma_addr_t bus_addr,
			    dma_addr_t device_addr, size_t size, int flags)
{
	return 0;
}

static inline void
dma_release_declared_memory(struct device *dev)
{
}

static inline void *
dma_mark_declared_memory_occupied(struct device *dev,
				  dma_addr_t device_addr, size_t size)
{
	return ERR_PTR(-EBUSY);
}
#endif

#endif


