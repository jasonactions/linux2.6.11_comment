/*
 *	Definitions for the 'struct sk_buff' memory handlers.
 *
 *	Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Florian La Roche, <rzsfl@rz.uni-sb.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_SKBUFF_H
#define _LINUX_SKBUFF_H

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/time.h>
#include <linux/cache.h>

#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/poll.h>
#include <linux/net.h>
#include <net/checksum.h>

#define HAVE_ALLOC_SKB		/* For the drivers to know */
#define HAVE_ALIGNABLE_SKB	/* Ditto 8)		   */
#define SLAB_SKB 		/* Slabified skbuffs 	   */

/**
 * 在接收时，csum中的校验和无效，原因可能有以下几种：
 *		设备不提供硬件校验和计算。
 *		设备计算了硬件校验和，并且驱动发现该数据帧已损坏。
 *		校验和必须重算并重新验证。
 * 在传输时，表示协议已经处理了校验和，设备不需要做任何事情。当转发一个出口数据帧时，L4校验和已经准备好，因为已经由传送端主机计算好了，因此没有必要再计算它。
 */
#define CHECKSUM_NONE 0
/**
 * 在接收时，表示NIC以L4报头和有效载荷计算了校验和，然后把校验和拷贝到skb->csum字段。
 * 软件（如L4接收函数）不仅必须把伪报头的校验和加至skb->csum，还必须验证最后所得的校验和。
 * 在传输时，表示协议只把伪报头的校验和存储至报头内，而设备应该通过添加L4报头和有效负载的校验和来完成其他工作。
 */
#define CHECKSUM_HW 1
/**
 * 在接收时，表示NIC已经计算并验证了L4报头以及伪报头的校验和（伪报头的校验和可以由设备驱动程序在软件中计算），所以，软件无需对L4校验与验证工作再做任何事情。
 * 当错误的发生概率很低，不值得浪费时间和CPU运算能力去计算及验证L4校验和时，也可设定CHECKSUM_UNNECESSARY。
 * 实例之一就是回环设备.
 * 在传输时，不使用此标志。
 */
#define CHECKSUM_UNNECESSARY 2

#define SKB_DATA_ALIGN(X)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))
#define SKB_MAX_ORDER(X, ORDER)	(((PAGE_SIZE << (ORDER)) - (X) - \
				  sizeof(struct skb_shared_info)) & \
				  ~(SMP_CACHE_BYTES - 1))
#define SKB_MAX_HEAD(X)		(SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ALLOC		(SKB_MAX_ORDER(0, 2))

/* A. Checksumming of received packets by device.
 *
 *	NONE: device failed to checksum this packet.
 *		skb->csum is undefined.
 *
 *	UNNECESSARY: device parsed packet and wouldbe verified checksum.
 *		skb->csum is undefined.
 *	      It is bad option, but, unfortunately, many of vendors do this.
 *	      Apparently with secret goal to sell you new device, when you
 *	      will add new protocol to your host. F.e. IPv6. 8)
 *
 *	HW: the most generic way. Device supplied checksum of _all_
 *	    the packet as seen by netif_rx in skb->csum.
 *	    NOTE: Even if device supports only some protocols, but
 *	    is able to produce some skb->csum, it MUST use HW,
 *	    not UNNECESSARY.
 *
 * B. Checksumming on output.
 *
 *	NONE: skb is checksummed by protocol or csum is not required.
 *
 *	HW: device is required to csum packet as seen by hard_start_xmit
 *	from skb->h.raw to the end and to record the checksum
 *	at skb->h.raw+skb->csum.
 *
 *	Device must show its capabilities in dev->features, set
 *	at device setup time.
 *	NETIF_F_HW_CSUM	- it is clever device, it is able to checksum
 *			  everything.
 *	NETIF_F_NO_CSUM - loopback or reliable single hop media.
 *	NETIF_F_IP_CSUM - device is dumb. It is able to csum only
 *			  TCP/UDP over IPv4. Sigh. Vendors like this
 *			  way by an unknown reason. Though, see comment above
 *			  about CHECKSUM_UNNECESSARY. 8)
 *
 *	Any questions? No questions, good. 		--ANK
 */

#ifdef __i386__
#define NET_CALLER(arg) (*(((void **)&arg) - 1))
#else
#define NET_CALLER(arg) __builtin_return_address(0)
#endif

struct net_device;

#ifdef CONFIG_NETFILTER
struct nf_conntrack {
	atomic_t use;
	void (*destroy)(struct nf_conntrack *);
};

#ifdef CONFIG_BRIDGE_NETFILTER
struct nf_bridge_info {
	atomic_t use;
	struct net_device *physindev;
	struct net_device *physoutdev;
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
	struct net_device *netoutdev;
#endif
	unsigned int mask;
	unsigned long data[32 / sizeof(unsigned long)];
};
#endif

#endif

/**
 * sk_buff双向链表头结点。
 */
struct sk_buff_head {
	/* These two members must be first. */
	/**
	 * 头结点的前后指针必须与sk_buff一样，放到结构的前面。
	 */
	struct sk_buff	*next;
	struct sk_buff	*prev;

	/**
	 * 整个链表的长度。
	 */
	__u32		qlen;
	/**
	 * 保护链表的自旋锁。
	 */
	spinlock_t	lock;
};

struct sk_buff;

/* To allow 64K frame to be packed as single skb without frag_list */
#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 2)

typedef struct skb_frag_struct skb_frag_t;

/**
 * 当设备支持分散/聚集IO时，该结构表示一段数据片段在内存中的位置及大小。
 */
struct skb_frag_struct {
	/**
	 * 数据片段在哪个页面中。
	 */
	struct page *page;
	/**
	 * 在页面中的偏移。
	 */
	__u16 page_offset;
	/**
	 * 片段长度。
	 */
	__u16 size;
};

/* This data is invariant across clones and lives at
 * the end of the header data, ie. at skb->end.
 */
/**
 * sk_buff对应的数据区的附加信息，在缓冲区数据的末尾。
 * 这个数据结构紧跟在end指针所指的地址之后（end指针指示数据的末尾）
 */
struct skb_shared_info {
	/**
	 * 数据块的"用户"数,用于克隆和拷贝缓冲区
	 */
	atomic_t	dataref;
	/**
	 * 分散/聚集IO的页面数。
	 */
	unsigned int	nr_frags;
	/**
	 * 用于TCP段卸载（TSO）
	 */
	unsigned short	tso_size;
	unsigned short	tso_segs;
	/**
	 * 存储IP分片
	 */
	struct sk_buff	*frag_list;
	/**
	 * 分散/聚集IO启用时，指向所有页面。
	 */
	skb_frag_t	frags[MAX_SKB_FRAGS];
};

/** 
 *	struct sk_buff - socket buffer
 *	@next: Next buffer in list
 *	@prev: Previous buffer in list
 *	@list: List we are on
 *	@sk: Socket we are owned by
 *	@stamp: Time we arrived
 *	@dev: Device we arrived on/are leaving by
 *	@input_dev: Device we arrived on
 *      @real_dev: The real device we are using
 *	@h: Transport layer header
 *	@nh: Network layer header
 *	@mac: Link layer header
 *	@dst: FIXME: Describe this field
 *	@cb: Control buffer. Free for use by every layer. Put private vars here
 *	@len: Length of actual data
 *	@data_len: Data length
 *	@mac_len: Length of link layer header
 *	@csum: Checksum
 *	@__unused: Dead field, may be reused
 *	@cloned: Head may be cloned (check refcnt to be sure)
 *	@pkt_type: Packet class
 *	@ip_summed: Driver fed us an IP checksum
 *	@priority: Packet queueing priority
 *	@users: User count - see {datagram,tcp}.c
 *	@protocol: Packet protocol from driver
 *	@security: Security level of packet
 *	@truesize: Buffer size 
 *	@head: Head of buffer
 *	@data: Data head pointer
 *	@tail: Tail pointer
 *	@end: End pointer
 *	@destructor: Destruct function
 *	@nfmark: Can be used for communication between hooks
 *	@nfcache: Cache info
 *	@nfct: Associated connection, if any
 *	@nfctinfo: Relationship of this skb to the connection
 *	@nf_debug: Netfilter debugging
 *	@nf_bridge: Saved data about a bridged frame - see br_netfilter.c
 *      @private: Data which is private to the HIPPI implementation
 *	@tc_index: Traffic control index
 */

/**
 * 接收或发送数据包的元信息.
 * 这个结构被不同的网络层（MAC 或者其他二层链路协议，三层的 IP，四层的 TCP 或UDP等）使用，并且其中的成员变量在结构从一层向另一层传递时改变
 */
struct sk_buff {
	/* These two members must be first. */
	/**
	 * 将结构链入双向链表的指针。
	 * 双向链表头指针是一个独立的sk_buff_head。
	 */
	struct sk_buff		*next;
	struct sk_buff		*prev;

	/**
	 * 指向双向链表的头结点。这是为了快速找到包所在头结点。
	 */
	struct sk_buff_head	*list;
	/**
	 * 这是一个指向拥有这个sk_buff的sock结构的指针。
	 * 这个指针在网络包由本机发出或者由本机进程接收时有效，因为插口相关的信息被L4（TCP或UDP）或者用户空间程序使用。
	 * 如果sk_buff只在转发中使用（这意味着，源地址和目的地址都不是本机地址），这个指针是NULL。
	 */
	struct sock		*sk;
	/**
	 * 这个变量只对接收到的包有意义。它代表包接收时的时间戳，或者有时代表包准备发出时的时间戳。
	 * 它在netif_rx里面由函数net_timestamp设置，而netif_rx是设备驱动收到一个包后调用的函数。
	 * tv_sec被设为LOCALLY_ENQUEUED，表示放在队列中的代理ARP请求。
	 */
	struct timeval		stamp;
	/**
	 * 这个变量代表一个网络设备。dev的作用与这个包是准备发出的包还是刚刚接收的包有关。 
 	 * 当收到一个包时，设备驱动会把sk_buff的dev指针指向收到这个包的设备的数据结构。
	 * 当一个包被发送时，这个变量代表将要发送这个包的设备。
	 * 在某些情况下，指向传输设备的指针会在包处理过程中被改变(当发送设备是一个虚拟设备时)。
	 */
	struct net_device	*dev;
	/**
	 * 这是收到包的网络设备的指针。
	 * 如果包是本地生成的，这个值为NULL。
	 * 对以太网设备来说，这个值由eth_type_trans初始化。
	 * 它主要被流量控制代码使用。 
	 */
	struct net_device	*input_dev;
	/**
	 * 这个变量只对虚拟设备有意义，它代表与虚拟设备关联的真实设备。
	 * 例如，Bonding和VLAN设备都使用它来指向收到包的真实设备。
	 */
	struct net_device	*real_dev;

	/**
	 * 这些是指向TCP/IP各层协议头的指针：
	 *		h指向L4
	 *		nh指向L3
	 *		mac指向L2。
	 * 每个指针的类型都是一个联合，包含多个数据结构，每一个数据结构都表示内核在这一层可以解析的协议。
	 * 例如，h 是一个包含内核所能解析的 L4 协议的数据结构的联合。
	 * 每一个联合都有一个raw变量用于初始化，后续的访问都是通过协议相关的变量进行的。 
	 */
	union {
		struct tcphdr	*th;
		struct udphdr	*uh;
		struct icmphdr	*icmph;
		struct igmphdr	*igmph;
		struct iphdr	*ipiph;
		struct ipv6hdr	*ipv6h;
		unsigned char	*raw;
	} h;

	union {
		struct iphdr	*iph;
		struct ipv6hdr	*ipv6h;
		struct arphdr	*arph;
		unsigned char	*raw;
	} nh;

	union {
	  	unsigned char 	*raw;
	} mac;

	/**
	 * 这个变量在路由子系统中使用。
	 * 存储入包或者出包的路由缓存条目。
	 */
	struct  dst_entry	*dst;
	/**
	 * 这个变量被IPSec协议用于跟踪传输的信息。
	 */
	struct	sec_path	*sp;

	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */
	/**
	 * 这是一个"control buffer"，或者说是一个私有信息的存储空间，由每一层自己维护并使用。
	 * 它在分配sk_buff结构时分配（它目前的大小是40字节，已经足够为每一层存储必要的私有信息了）。
	 * 在每一层中，访问这个变量的代码通常用宏实现以增强代码的可读性。
	 */
	char			cb[40];

	/**
	 * 这是缓冲区中数据部分的长度。它包括主缓冲区中的数据长度（data指针指向它）和分片中的数据长度。
	 * 它的值在缓冲区从一个层向另一个层传递时改变，因为往上层传递，旧的头部就没有用了，而往下层传递，需要添加本层的头部。
	 * len 同样包含了协议头的长度。
	 */
	unsigned int		len,
	/**
	 * 分片中数据的长度.
	 */
				data_len,
	/**
	 * mac头的长度。
	 */
				mac_len,
	/**
	 * 表示校验和
	 * 当接收一个包时，csum可能包含其L4校验和。
	 * 当包传输后，csum代表指向缓冲区内的地点的指针，不再是校验和本身。而此地点是硬件适配卡存放校验和的地方。因此，在包传输期间，只有当校验和是在硬件中计算时，才会用到此字段。
	 */
				csum;
	unsigned char		local_df,
	/**
	 * 一个布尔标记，当被设置时，表示这个结构是另一个sk_buff的克隆。
	 */
				cloned,
	/**
	 * 这个变量表示帧的类型，分类是由 L2 的目的地址来决定的。
	 * 可能的取值都在include/linux/if_packet.h中定义。
	 * 对以太网设备来说，这个变量由eth_type_trans函数初始化。 
	 */
				pkt_type,
	/**
	 * L4校验和状态标记.
	 * 当IP层知道L4层校验和失效时（例如伪报头中的某个字段被修改），它维护这个字段的值。
	 */
				ip_summed;
	/**
	 * 这个变量描述发送或转发包的QoS 类别。
	 * 如果包是本地生成的，socket 层会设置priority变量。
	 * 如果包是将要被转发的，rt_tos2priority函数会根据ip头中的Tos域来计算赋给这个变量的值。
	 * 这个变量的值与第18章描述的 DSCP（DiffServ  Code Point）没有任何关系。
	 */
	__u32			priority;
	/**
	 * 这个变量是高层协议从二层设备的角度所看到的协议。以网络字节序进行保存。
	 * 典型的协议包括 IP，IPV6和ARP。
	 * 完整的列表在include/linux/if_ether.h中。
	 * 由于每个协议都有自己的协议处理函数来处理接收到的包，因此，这个域被设备驱动用于通知上层调用哪个协议处理函数。
	 * 每个网络驱动都调用 netif_rx 来通知上层网络协议的协议处理函数，因此protocol变量必须在这些协议处理函数调用之前初始化。
	 */
	unsigned short		protocol,
	/**
	 * 这是包的安全级别。这个变量最初由IPSec子系统使用，但现在已经作废了。
	 */
				security;

	/**
	 * 这个函数指针可以初始化成一个在缓冲区释放时完成某些动作的函数。
	 * 如果缓冲区不属于一个socket，这个函数指针通常是不会被赋值的。
	 * 如果缓冲区属于一个socket，这个函数指针会被赋值为 sock_rfree 或 sock_wfree（分别由 skb_set_owner_r 或skb_set_owner_w函数初始化）。
	 * 这两个sock_xxx函数用于更新socket的队列中的内存容量。
	 */
	void			(*destructor)(struct sk_buff *skb);
#ifdef CONFIG_NETFILTER
	/**
	 * 这些变量被 netfilter 使用（防火墙代码）,策略路由使用该字段来确定对入流量和出流量的路由应当使用哪一张路由表。
	 * 为0表示不存在防火墙标签。
	 */
        unsigned long		nfmark;
	__u32			nfcache;
	__u32			nfctinfo;
	struct nf_conntrack	*nfct;
#ifdef CONFIG_NETFILTER_DEBUG
        unsigned int		nf_debug;
#endif
#ifdef CONFIG_BRIDGE_NETFILTER
	struct nf_bridge_info	*nf_bridge;
#endif
#endif /* CONFIG_NETFILTER */
#if defined(CONFIG_HIPPI)
	/**
	 * 这个联合结构被高性能并行接口（HIPPI）使用。
	 */
	union {
		__u32		ifield;
	} private;
#endif
#ifdef CONFIG_NET_SCHED
	/**
	 * 这些变量被流量控制代码使用
	 */
       __u32			tc_index;        /* traffic control index */
#ifdef CONFIG_NET_CLS_ACT
	__u32           tc_verd;               /* traffic control verdict */
	__u32           tc_classid;            /* traffic control classid */
#endif

#endif


	/* These elements must be at the end, see alloc_skb() for details.  */
	/**
	 * 这是缓冲区的总长度，包括 sk_buff 结构和数据部分。
	 * 如果申请一个 len 字节的缓冲区，alloc_skb函数会把它初始化成len+sizeof(sk_buff)。
	 * 当skb->len变化时，这个变量也会变化。
	 */
	unsigned int		truesize;
	/**
	 * 这是一个引用计数，用于计算有多少实体引用了这个sk_buff缓冲区。
	 * 它的主要用途是防止释放sk_buff后，还有其他实体引用这个sk_buff。
	 * 因此，每个引用这个缓冲区的实体都必须在适当的时候增加或减小这个变量。
	 * 这个计数器只保护sk_buff结构本身，而缓冲区的数据部分由类似的计数器（dataref）来保护。 
	 * 有时可以用atomic_inc和atomic_dec函数来直接增加或减小users，但是，通常还是使用函数skb_get和kfree_skb来操作这个变量。
	 */
	atomic_t		users;
	/**
	 * 它们表示缓冲区和数据部分的边界。
	 * 在每一层申请缓冲区时，它会分配比协议头或协议数据大的空间。
	 * head和end指向缓冲区的头部和尾部，而data 和tail 指向实际数据的头部和尾部。
	 * 每一层会在head和data之间填充协议头，或者在tail 和 end 之间添加新的协议数据。
	 */
	unsigned char		*head,
				*data,
				*tail,
				*end;
};

#ifdef __KERNEL__
/*
 *	Handling routines are only of interest to the kernel
 */
#include <linux/slab.h>

#include <asm/system.h>

extern void	       __kfree_skb(struct sk_buff *skb);
extern struct sk_buff *alloc_skb(unsigned int size, int priority);
extern struct sk_buff *alloc_skb_from_cache(kmem_cache_t *cp,
					    unsigned int size, int priority);
extern void	       kfree_skbmem(struct sk_buff *skb);
extern struct sk_buff *skb_clone(struct sk_buff *skb, int priority);
extern struct sk_buff *skb_copy(const struct sk_buff *skb, int priority);
extern struct sk_buff *pskb_copy(struct sk_buff *skb, int gfp_mask);
extern int	       pskb_expand_head(struct sk_buff *skb,
					int nhead, int ntail, int gfp_mask);
extern struct sk_buff *skb_realloc_headroom(struct sk_buff *skb,
					    unsigned int headroom);
extern struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
				       int newheadroom, int newtailroom,
				       int priority);
extern struct sk_buff *		skb_pad(struct sk_buff *skb, int pad);
/**
 * 与dev_alloc_skb对应，此处仅仅简单的调用kfree_skb
 */
#define dev_kfree_skb(a)	kfree_skb(a)
extern void	      skb_over_panic(struct sk_buff *skb, int len,
				     void *here);
extern void	      skb_under_panic(struct sk_buff *skb, int len,
				      void *here);

/* Internal */
/**
 * sk_buff对应的skb_shared_info结构的指针,由end指向
 */
#define skb_shinfo(SKB)		((struct skb_shared_info *)((SKB)->end))

/**
 *	skb_queue_empty - check if a queue is empty
 *	@list: queue head
 *
 *	Returns true if the queue is empty, false otherwise.
 */
static inline int skb_queue_empty(const struct sk_buff_head *list)
{
	return list->next == (struct sk_buff *)list;
}

/**
 *	skb_get - reference buffer
 *	@skb: buffer to reference
 *
 *	Makes another reference to a socket buffer and returns a pointer
 *	to the buffer.
 */
static inline struct sk_buff *skb_get(struct sk_buff *skb)
{
	atomic_inc(&skb->users);
	return skb;
}

/*
 * If users == 1, we are the only owner and are can avoid redundant
 * atomic change.
 */

/**
 *	kfree_skb - free an sk_buff
 *	@skb: buffer to free
 *
 *	Drop a reference to the buffer and free it if the usage count has
 *	hit zero.
 */
/**
 * 释放sk_buff，当它的引用计数变成0时。
 * kfree_skb可以直接调用，也可以通过包装函数 dev_kfree_skb 调用
 */
static inline void kfree_skb(struct sk_buff *skb)
{
	/**
	 * 如果当前引用计数为1，则真正释放引用计数。
	 */
	if (likely(atomic_read(&skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&skb->users))) /* 当前引用计数不为1，则进行递减。如果递减后结果不为0，则退出。 */
		return;
	/**
	 * 引用计数为0，需要释放sk_buff占用的内存，同时还会释放相关的数据结构如dst_entry.
	 */
	__kfree_skb(skb);
}

/**
 *	skb_cloned - is the buffer a clone
 *	@skb: buffer to check
 *
 *	Returns true if the buffer was generated with skb_clone() and is
 *	one of multiple shared copies of the buffer. Cloned buffers are
 *	shared data so must not be written to under normal circumstances.
 */
/**
 * 测试skb的克隆状态。
 */
static inline int skb_cloned(const struct sk_buff *skb)
{
	return skb->cloned && atomic_read(&skb_shinfo(skb)->dataref) != 1;
}

/**
 *	skb_shared - is the buffer shared
 *	@skb: buffer to check
 *
 *	Returns true if more than one person has a reference to this
 *	buffer.
 */
static inline int skb_shared(const struct sk_buff *skb)
{
	return atomic_read(&skb->users) != 1;
}

/**
 *	skb_share_check - check if buffer is shared and if so clone it
 *	@skb: buffer to check
 *	@pri: priority for memory allocation
 *
 *	If the buffer is shared the buffer is cloned and the old copy
 *	drops a reference. A new clone with a single reference is returned.
 *	If the buffer is not shared the original buffer is returned. When
 *	being called from interrupt status or with spinlocks held pri must
 *	be GFP_ATOMIC.
 *
 *	NULL is returned on a memory allocation failure.
 */
/**
 * 检查引用计数 skb->users，如果 users 变量表明 skb 是被共享的，则克隆一个新的sk_buff。
 */
static inline struct sk_buff *skb_share_check(struct sk_buff *skb, int pri)
{
	might_sleep_if(pri & __GFP_WAIT);
	if (skb_shared(skb)) {
		struct sk_buff *nskb = skb_clone(skb, pri);
		kfree_skb(skb);
		skb = nskb;
	}
	return skb;
}

/*
 *	Copy shared buffers into a new sk_buff. We effectively do COW on
 *	packets to handle cases where we have a local reader and forward
 *	and a couple of other messy ones. The normal one is tcpdumping
 *	a packet thats being forwarded.
 */

/**
 *	skb_unshare - make a copy of a shared buffer
 *	@skb: buffer to check
 *	@pri: priority for memory allocation
 *
 *	If the socket buffer is a clone then this function creates a new
 *	copy of the data, drops a reference count on the old copy and returns
 *	the new copy with the reference count at 1. If the buffer is not a clone
 *	the original buffer is returned. When called with a spinlock held or
 *	from interrupt state @pri must be %GFP_ATOMIC
 *
 *	%NULL is returned on a memory allocation failure.
 */
static inline struct sk_buff *skb_unshare(struct sk_buff *skb, int pri)
{
	might_sleep_if(pri & __GFP_WAIT);
	if (skb_cloned(skb)) {
		struct sk_buff *nskb = skb_copy(skb, pri);
		kfree_skb(skb);	/* Free our shared copy */
		skb = nskb;
	}
	return skb;
}

/**
 *	skb_peek
 *	@list_: list to peek at
 *
 *	Peek an &sk_buff. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the head element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
static inline struct sk_buff *skb_peek(struct sk_buff_head *list_)
{
	struct sk_buff *list = ((struct sk_buff *)list_)->next;
	if (list == (struct sk_buff *)list_)
		list = NULL;
	return list;
}

/**
 *	skb_peek_tail
 *	@list_: list to peek at
 *
 *	Peek an &sk_buff. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the tail element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
static inline struct sk_buff *skb_peek_tail(struct sk_buff_head *list_)
{
	struct sk_buff *list = ((struct sk_buff *)list_)->prev;
	if (list == (struct sk_buff *)list_)
		list = NULL;
	return list;
}

/**
 *	skb_queue_len	- get queue length
 *	@list_: list to measure
 *
 *	Return the length of an &sk_buff queue.
 */
static inline __u32 skb_queue_len(const struct sk_buff_head *list_)
{
	return list_->qlen;
}

/**
 * 初始化sk_buff_head结构，创建一个空队列。
 */
static inline void skb_queue_head_init(struct sk_buff_head *list)
{
	spin_lock_init(&list->lock);
	list->prev = list->next = (struct sk_buff *)list;
	list->qlen = 0;
}

/*
 *	Insert an sk_buff at the start of a list.
 *
 *	The "__skb_xxxx()" functions are the non-atomic ones that
 *	can only be called with interrupts disabled.
 */

/**
 *	__skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
extern void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk);
static inline void __skb_queue_head(struct sk_buff_head *list,
				    struct sk_buff *newsk)
{
	struct sk_buff *prev, *next;

	newsk->list = list;
	list->qlen++;
	prev = (struct sk_buff *)list;
	next = prev->next;
	newsk->next = next;
	newsk->prev = prev;
	next->prev  = prev->next = newsk;
}

/**
 *	__skb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the end of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
extern void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk);
static inline void __skb_queue_tail(struct sk_buff_head *list,
				   struct sk_buff *newsk)
{
	struct sk_buff *prev, *next;

	newsk->list = list;
	list->qlen++;
	next = (struct sk_buff *)list;
	prev = next->prev;
	newsk->next = next;
	newsk->prev = prev;
	next->prev  = prev->next = newsk;
}


/**
 *	__skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */
extern struct sk_buff *skb_dequeue(struct sk_buff_head *list);
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *next, *prev, *result;

	prev = (struct sk_buff *) list;
	next = prev->next;
	result = NULL;
	if (next != prev) {
		result	     = next;
		next	     = next->next;
		list->qlen--;
		next->prev   = prev;
		prev->next   = next;
		result->next = result->prev = NULL;
		result->list = NULL;
	}
	return result;
}


/*
 *	Insert a packet on a list.
 */
extern void        skb_insert(struct sk_buff *old, struct sk_buff *newsk);
static inline void __skb_insert(struct sk_buff *newsk,
				struct sk_buff *prev, struct sk_buff *next,
				struct sk_buff_head *list)
{
	newsk->next = next;
	newsk->prev = prev;
	next->prev  = prev->next = newsk;
	newsk->list = list;
	list->qlen++;
}

/*
 *	Place a packet after a given packet in a list.
 */
extern void	   skb_append(struct sk_buff *old, struct sk_buff *newsk);
static inline void __skb_append(struct sk_buff *old, struct sk_buff *newsk)
{
	__skb_insert(newsk, old, old->next, old->list);
}

/*
 * remove sk_buff from list. _Must_ be called atomically, and with
 * the list known..
 */
extern void	   skb_unlink(struct sk_buff *skb);
static inline void __skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	struct sk_buff *next, *prev;

	list->qlen--;
	next	   = skb->next;
	prev	   = skb->prev;
	skb->next  = skb->prev = NULL;
	skb->list  = NULL;
	next->prev = prev;
	prev->next = next;
}


/* XXX: more streamlined implementation */

/**
 *	__skb_dequeue_tail - remove from the tail of the queue
 *	@list: list to dequeue from
 *
 *	Remove the tail of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The tail item is
 *	returned or %NULL if the list is empty.
 */
extern struct sk_buff *skb_dequeue_tail(struct sk_buff_head *list);
static inline struct sk_buff *__skb_dequeue_tail(struct sk_buff_head *list)
{
	struct sk_buff *skb = skb_peek_tail(list);
	if (skb)
		__skb_unlink(skb, list);
	return skb;
}

/**
 * 测试一个缓冲区是否是分片的
 */
static inline int skb_is_nonlinear(const struct sk_buff *skb)
{
	return skb->data_len;
}

/**
 * 对于指定某个缓冲区，返回主要缓冲区中的数据量（即不计算frags片段，也不考虑frag_list列表）。
 * 别把skb_headlen误码认为skb_headroom。Skb_headroom返回的是介于skb->head和skb->data之间的可用空间。
 */
static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

/**
 * 分片缓冲区的尺寸。会把主缓冲区中的数据以及frags片段中的数据计算进来，但是不考虑任何链接到frag_list列表的缓冲区。
 */
static inline int skb_pagelen(const struct sk_buff *skb)
{
	int i, len = 0;

	for (i = (int)skb_shinfo(skb)->nr_frags - 1; i >= 0; i--)
		len += skb_shinfo(skb)->frags[i].size;
	return len + skb_headlen(skb);
}

static inline void skb_fill_page_desc(struct sk_buff *skb, int i,
				      struct page *page, int off, int size)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

	frag->page		  = page;
	frag->page_offset	  = off;
	frag->size		  = size;
	skb_shinfo(skb)->nr_frags = i + 1;
}

#define SKB_PAGE_ASSERT(skb) 	BUG_ON(skb_shinfo(skb)->nr_frags)
#define SKB_FRAG_ASSERT(skb) 	BUG_ON(skb_shinfo(skb)->frag_list)
#define SKB_LINEAR_ASSERT(skb)  BUG_ON(skb_is_nonlinear(skb))

/*
 *	Add data to an sk_buff
 */
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
/**
 * 在缓冲区的末尾加入一块数据。
 * 与skb_reserve类似，不会真的往缓冲区中添加数据
 */
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb->tail;
	SKB_LINEAR_ASSERT(skb);
	/**
	 * 后移缓冲区指针，并增加缓冲区长度。
	 */
	skb->tail += len;
	skb->len  += len;
	if (unlikely(skb->tail>skb->end))
		skb_over_panic(skb, len, current_text_addr());
	return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len  += len;
	return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */
/**
 * 在缓冲区的开头加入一块数据
 */
static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	/**
	 * 向前移动缓冲区头部。
	 */
	skb->data -= len;
	/**
	 * 增加缓冲区长度。
	 */
	skb->len  += len;
	if (unlikely(skb->data<skb->head))
		skb_under_panic(skb, len, current_text_addr());
	return skb->data;
}

static inline unsigned char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len -= len;
	BUG_ON(skb->len < skb->data_len);
	return skb->data += len;
}

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */
/**
 * 通过把 head 指针往前移来在缓冲区的头部删除一块数据
 */
static inline unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	return unlikely(len > skb->len) ? NULL : __skb_pull(skb, len);
}

extern unsigned char *__pskb_pull_tail(struct sk_buff *skb, int delta);

static inline unsigned char *__pskb_pull(struct sk_buff *skb, unsigned int len)
{
	if (len > skb_headlen(skb) &&
	    !__pskb_pull_tail(skb, len-skb_headlen(skb)))
		return NULL;
	skb->len -= len;
	return skb->data += len;
}

static inline unsigned char *pskb_pull(struct sk_buff *skb, unsigned int len)
{
	return unlikely(len > skb->len) ? NULL : __pskb_pull(skb, len);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	if (likely(len <= skb_headlen(skb)))
		return 1;
	if (unlikely(len > skb->len))
		return 0;
	return __pskb_pull_tail(skb, len-skb_headlen(skb)) != NULL;
}

/**
 *	skb_headroom - bytes at buffer head
 *	@skb: buffer to check
 *
 *	Return the number of bytes of free space at the head of an &sk_buff.
 */
static inline int skb_headroom(const struct sk_buff *skb)
{
	return skb->data - skb->head;
}

/**
 *	skb_tailroom - bytes at buffer end
 *	@skb: buffer to check
 *
 *	Return the number of bytes of free space at the tail of an sk_buff
 */
static inline int skb_tailroom(const struct sk_buff *skb)
{
	return skb_is_nonlinear(skb) ? 0 : skb->end - skb->tail;
}

/**
 *	skb_reserve - adjust headroom
 *	@skb: buffer to alter
 *	@len: bytes to move
 *
 *	Increase the headroom of an empty &sk_buff by reducing the tail
 *	room. This is only allowed for an empty buffer.
 */
/**
 * skb_reserve可以在缓冲区的头部预留一定的空间，它通常被用来在缓冲区中插入协议头或者在某个边界上对齐
 */
static inline void skb_reserve(struct sk_buff *skb, unsigned int len)
{
	/**
	 * 这个函数改变data和tail指针，而data和tail指针分别指向负载的开头和结尾
	 */
	skb->data += len;
	skb->tail += len;
}

/*
 * CPUs often take a performance hit when accessing unaligned memory
 * locations. The actual performance hit varies, it can be small if the
 * hardware handles it or large if we have to take an exception and fix it
 * in software.
 *
 * Since an ethernet header is 14 bytes network drivers often end up with
 * the IP header at an unaligned offset. The IP header can be aligned by
 * shifting the start of the packet by 2 bytes. Drivers should do this
 * with:
 *
 * skb_reserve(NET_IP_ALIGN);
 *
 * The downside to this alignment of the IP header is that the DMA is now
 * unaligned. On some architectures the cost of an unaligned DMA is high
 * and this cost outweighs the gains made by aligning the IP header.
 * 
 * Since this trade off varies between architectures, we allow NET_IP_ALIGN
 * to be overridden.
 */
#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN	2
#endif

extern int ___pskb_trim(struct sk_buff *skb, unsigned int len, int realloc);

static inline void __skb_trim(struct sk_buff *skb, unsigned int len)
{
	if (!skb->data_len) {
		skb->len  = len;
		skb->tail = skb->data + len;
	} else
		___pskb_trim(skb, len, 0);
}

/**
 *	skb_trim - remove end from a buffer
 *	@skb: buffer to alter
 *	@len: new length
 *
 *	Cut the length of a buffer down by removing data from the tail. If
 *	the buffer is already under the length specified it is not modified.
 */
static inline void skb_trim(struct sk_buff *skb, unsigned int len)
{
	if (skb->len > len)
		__skb_trim(skb, len);
}


static inline int __pskb_trim(struct sk_buff *skb, unsigned int len)
{
	if (!skb->data_len) {
		skb->len  = len;
		skb->tail = skb->data+len;
		return 0;
	}
	return ___pskb_trim(skb, len, 1);
}

static inline int pskb_trim(struct sk_buff *skb, unsigned int len)
{
	return (len < skb->len) ? __pskb_trim(skb, len) : 0;
}

/**
 *	skb_orphan - orphan a buffer
 *	@skb: buffer to orphan
 *
 *	If a buffer currently has an owner then we call the owner's
 *	destructor function and make the @skb unowned. The buffer continues
 *	to exist but is no longer charged to its former owner.
 */
static inline void skb_orphan(struct sk_buff *skb)
{
	if (skb->destructor)
		skb->destructor(skb);
	skb->destructor = NULL;
	skb->sk		= NULL;
}

/**
 *	__skb_queue_purge - empty a list
 *	@list: list to empty
 *
 *	Delete all buffers on an &sk_buff list. Each buffer is removed from
 *	the list and one reference dropped. This function does not take the
 *	list lock and the caller must hold the relevant locks to use it.
 */
extern void skb_queue_purge(struct sk_buff_head *list);
static inline void __skb_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(list)) != NULL)
		kfree_skb(skb);
}

/**
 *	__dev_alloc_skb - allocate an skbuff for sending
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_skb
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned in there is no free memory.
 */
#ifndef CONFIG_HAVE_ARCH_DEV_ALLOC_SKB
/**
 * dev_alloc_skb与alloc_skb相似，也是一个缓冲区分配函数，它主要被设备驱动使用，通常用在中断上下文中。
 * 它的分配要求使用原子操作（GFP_ATOMIC），这是因为它是在中断处理函数中被调用的。 
 */
static inline struct sk_buff *__dev_alloc_skb(unsigned int length,
					      int gfp_mask)
{
	/**
	 * 在请求分配的大小上增加16字节的空间以优化缓冲区的读写效率
	 */
	struct sk_buff *skb = alloc_skb(length + 16, gfp_mask);
	/**
	 * 移动数据指针16个字节，将保留的16字节用于提高读写效率。
	 */
	if (likely(skb))
		skb_reserve(skb, 16);
	return skb;
}
#else
extern struct sk_buff *__dev_alloc_skb(unsigned int length, int gfp_mask);
#endif

/**
 *	dev_alloc_skb - allocate an skbuff for sending
 *	@length: length to allocate
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned in there is no free memory. Although this function
 *	allocates memory it can be called from an interrupt.
 */
/**
 * dev_alloc_skb与alloc_skb相似，也是一个缓冲区分配函数，它主要被设备驱动使用，通常用在中断上下文中。
 * 这是一个alloc_skb函数的包装函数，它会在请求分配的大小上增加16字节的空间以优化缓冲区的读写效率，它的分配要求使用原子操作（GFP_ATOMIC），这是因为它是在中断处理函数中被调用的。 
 */
static inline struct sk_buff *dev_alloc_skb(unsigned int length)
{
	return __dev_alloc_skb(length, GFP_ATOMIC);
}

/**
 *	skb_cow - copy header of skb when it is required
 *	@skb: buffer to cow
 *	@headroom: needed headroom
 *
 *	If the skb passed lacks sufficient headroom or its data part
 *	is shared, data is reallocated. If reallocation fails, an error
 *	is returned and original skb is not changed.
 *
 *	The result is skb with writable area skb->head...skb->tail
 *	and at least @headroom of space at head.
 */
static inline int skb_cow(struct sk_buff *skb, unsigned int headroom)
{
	int delta = (headroom > 16 ? headroom : 16) - skb_headroom(skb);

	if (delta < 0)
		delta = 0;

	if (delta || skb_cloned(skb))
		return pskb_expand_head(skb, (delta + 15) & ~15, 0, GFP_ATOMIC);
	return 0;
}

/**
 *	skb_padto	- pad an skbuff up to a minimal size
 *	@skb: buffer to pad
 *	@len: minimal length
 *
 *	Pads up a buffer to ensure the trailing bytes exist and are
 *	blanked. If the buffer already contains sufficient data it
 *	is untouched. Returns the buffer, which may be a replacement
 *	for the original, or NULL for out of memory - in which case
 *	the original buffer is still freed.
 */
 
static inline struct sk_buff *skb_padto(struct sk_buff *skb, unsigned int len)
{
	unsigned int size = skb->len;
	if (likely(size >= len))
		return skb;
	return skb_pad(skb, len-size);
}

static inline int skb_add_data(struct sk_buff *skb,
			       char __user *from, int copy)
{
	const int off = skb->len;

	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		unsigned int csum = csum_and_copy_from_user(from,
							    skb_put(skb, copy),
							    copy, 0, &err);
		if (!err) {
			skb->csum = csum_block_add(skb->csum, csum, off);
			return 0;
		}
	} else if (!copy_from_user(skb_put(skb, copy), from, copy))
		return 0;

	__skb_trim(skb, off);
	return -EFAULT;
}

static inline int skb_can_coalesce(struct sk_buff *skb, int i,
				   struct page *page, int off)
{
	if (i) {
		struct skb_frag_struct *frag = &skb_shinfo(skb)->frags[i - 1];

		return page == frag->page &&
		       off == frag->page_offset + frag->size;
	}
	return 0;
}

/**
 *	skb_linearize - convert paged skb to linear one
 *	@skb: buffer to linarize
 *	@gfp: allocation mode
 *
 *	If there is no free memory -ENOMEM is returned, otherwise zero
 *	is returned and the old skb data released.
 */
extern int __skb_linearize(struct sk_buff *skb, int gfp);
static inline int skb_linearize(struct sk_buff *skb, int gfp)
{
	return __skb_linearize(skb, gfp);
}

static inline void *kmap_skb_frag(const skb_frag_t *frag)
{
#ifdef CONFIG_HIGHMEM
	BUG_ON(in_irq());

	local_bh_disable();
#endif
	return kmap_atomic(frag->page, KM_SKB_DATA_SOFTIRQ);
}

static inline void kunmap_skb_frag(void *vaddr)
{
	kunmap_atomic(vaddr, KM_SKB_DATA_SOFTIRQ);
#ifdef CONFIG_HIGHMEM
	local_bh_enable();
#endif
}

/**
 * 按顺序遍历队列中的每一个元素。
 */
#define skb_queue_walk(queue, skb) \
		for (skb = (queue)->next;					\
		     prefetch(skb->next), (skb != (struct sk_buff *)(queue));	\
		     skb = skb->next)


extern struct sk_buff *skb_recv_datagram(struct sock *sk, unsigned flags,
					 int noblock, int *err);
extern unsigned int    datagram_poll(struct file *file, struct socket *sock,
				     struct poll_table_struct *wait);
extern int	       skb_copy_datagram_iovec(const struct sk_buff *from,
					       int offset, struct iovec *to,
					       int size);
extern int	       skb_copy_and_csum_datagram_iovec(const
							struct sk_buff *skb,
							int hlen,
							struct iovec *iov);
extern void	       skb_free_datagram(struct sock *sk, struct sk_buff *skb);
extern unsigned int    skb_checksum(const struct sk_buff *skb, int offset,
				    int len, unsigned int csum);
extern int	       skb_copy_bits(const struct sk_buff *skb, int offset,
				     void *to, int len);
extern unsigned int    skb_copy_and_csum_bits(const struct sk_buff *skb,
					      int offset, u8 *to, int len,
					      unsigned int csum);
extern void	       skb_copy_and_csum_dev(const struct sk_buff *skb, u8 *to);
extern void	       skb_split(struct sk_buff *skb,
				 struct sk_buff *skb1, const u32 len);

static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
				       int len, void *buffer)
{
	int hlen = skb_headlen(skb);

	if (offset + len <= hlen)
		return skb->data + offset;

	if (skb_copy_bits(skb, offset, buffer, len) < 0)
		return NULL;

	return buffer;
}

extern void skb_init(void);
extern void skb_add_mtu(int mtu);

struct skb_iter {
	/* Iteration functions set these */
	unsigned char *data;
	unsigned int len;

	/* Private to iteration */
	unsigned int nextfrag;
	struct sk_buff *fraglist;
};

/* Keep iterating until skb_iter_next returns false. */
extern void skb_iter_first(const struct sk_buff *skb, struct skb_iter *i);
extern int skb_iter_next(const struct sk_buff *skb, struct skb_iter *i);
/* Call this if aborting loop before !skb_iter_next */
extern void skb_iter_abort(const struct sk_buff *skb, struct skb_iter *i);

#ifdef CONFIG_NETFILTER
static inline void nf_conntrack_put(struct nf_conntrack *nfct)
{
	if (nfct && atomic_dec_and_test(&nfct->use))
		nfct->destroy(nfct);
}
static inline void nf_conntrack_get(struct nf_conntrack *nfct)
{
	if (nfct)
		atomic_inc(&nfct->use);
}
static inline void nf_reset(struct sk_buff *skb)
{
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
}
static inline void nf_reset_debug(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
}

#ifdef CONFIG_BRIDGE_NETFILTER
static inline void nf_bridge_put(struct nf_bridge_info *nf_bridge)
{
	if (nf_bridge && atomic_dec_and_test(&nf_bridge->use))
		kfree(nf_bridge);
}
static inline void nf_bridge_get(struct nf_bridge_info *nf_bridge)
{
	if (nf_bridge)
		atomic_inc(&nf_bridge->use);
}
#endif /* CONFIG_BRIDGE_NETFILTER */
#else /* CONFIG_NETFILTER */
static inline void nf_reset(struct sk_buff *skb) {}
#endif /* CONFIG_NETFILTER */

#endif	/* __KERNEL__ */
#endif	/* _LINUX_SKBUFF_H */
