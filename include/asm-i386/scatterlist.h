#ifndef _I386_SCATTERLIST_H
#define _I386_SCATTERLIST_H

/**
 * 描述分散、聚集映射中，每个缓冲页面。
 */
struct scatterlist {
	/**
	 * 缓冲所在页面。
	 */
    struct page		*page;
	/**
	 * 缓冲区在页内的偏移。
	 */
    unsigned int	offset;
    dma_addr_t		dma_address;
	/**
	 * 缓冲区在页内的长度。
	 */
    unsigned int	length;
};

/* These macros should be used after a pci_map_sg call has been done
 * to get bus addresses of each of the SG entries and their lengths.
 * You should only work with the number of sg entries pci_map_sg
 * returns.
 */
/**
 * 从分散表的入口项中返回DMA总线地址。
 */
#define sg_dma_address(sg)	((sg)->dma_address)
/**
 * 从分散表的入口项中返回DMA缓冲区的长度。
 */
#define sg_dma_len(sg)		((sg)->length)

#define ISA_DMA_THRESHOLD (0x00ffffff)

#endif /* !(_I386_SCATTERLIST_H) */
