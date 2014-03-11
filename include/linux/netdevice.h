/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Interfaces handler.
 *
 * Version:	@(#)dev.h	1.0.10	08/12/93
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Donald J. Becker, <becker@cesdis.gsfc.nasa.gov>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Bjorn Ekwall. <bj0rn@blox.se>
 *              Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *		Moved to /usr/include/linux for NET3
 */
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#ifdef __KERNEL__
#include <asm/atomic.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/config.h>
#include <linux/device.h>
#include <linux/percpu.h>

struct divert_blk;
struct vlan_group;
struct ethtool_ops;

					/* source back-compat hooks */
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )

#define HAVE_ALLOC_NETDEV		/* feature macro: alloc_xxxdev
					   functions are available. */
#define HAVE_FREE_NETDEV		/* free_netdev() */
#define HAVE_NETDEV_PRIV		/* netdev_priv() */

#define NET_XMIT_SUCCESS	0
#define NET_XMIT_DROP		1	/* skb dropped			*/
#define NET_XMIT_CN		2	/* congestion notification	*/
#define NET_XMIT_POLICED	3	/* skb is shot by police	*/
#define NET_XMIT_BYPASS		4	/* packet does not leave via dequeue;
					   (TC use only - dev_queue_xmit
					   returns this as NET_XMIT_SUCCESS) */

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0   /* keep 'em coming, baby */
#define NET_RX_DROP		1  /* packet dropped */
#define NET_RX_CN_LOW		2   /* storm alert, just in case */
#define NET_RX_CN_MOD		3   /* Storm on its way! */
#define NET_RX_CN_HIGH		4   /* The storm is here */
#define NET_RX_BAD		5  /* packet dropped due to kernel error */

#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

#endif

#define MAX_ADDR_LEN	32		/* Largest hardware address length */

/* Driver transmit return codes */
/**
 * 发送成功。缓冲区还没有被释放。
 * 驱动不会自行释放缓冲区，而是请求内核NET_TX_SOFTIRQ软中断处理它。它提供了比每一个驱动自行释放更有效的内存处理手段。
 */
#define NETDEV_TX_OK 0		/* driver took care of packet */
/**
 * 驱动发现网卡发送缓冲池缺少足够的空间。当这种情况被探测到时，驱动通常调用netif_stop_queue。
 */
#define NETDEV_TX_BUSY 1	/* driver tx path was busy*/
/**
 * 驱动被锁住。仅仅当驱动支持NETIF_F_LLTX时，才可能返回这处值。
 */
#define NETDEV_TX_LOCKED -1	/* driver tx lock was already taken */

/*
 *	Compute the worst case header length according to the protocols
 *	used.
 */
 
#if !defined(CONFIG_AX25) && !defined(CONFIG_AX25_MODULE) && !defined(CONFIG_TR)
#define LL_MAX_HEADER	32
#else
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
#define LL_MAX_HEADER	96
#else
#define LL_MAX_HEADER	48
#endif
#endif

#if !defined(CONFIG_NET_IPIP) && \
    !defined(CONFIG_IPV6) && !defined(CONFIG_IPV6_MODULE)
#define MAX_HEADER LL_MAX_HEADER
#else
#define MAX_HEADER (LL_MAX_HEADER + 48)
#endif

/*
 *	Network device statistics. Akin to the 2.0 ether stats but
 *	with byte counters.
 */
/**
 * 包含了所有网络设备都具有的常用统计信息，这些信息可以通过函数get_stats来获取
 */
struct net_device_stats
{
	unsigned long	rx_packets;		/* total packets received	*/
	unsigned long	tx_packets;		/* total packets transmitted	*/
	unsigned long	rx_bytes;		/* total bytes received 	*/
	unsigned long	tx_bytes;		/* total bytes transmitted	*/
	unsigned long	rx_errors;		/* bad packets received		*/
	unsigned long	tx_errors;		/* packet transmit problems	*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	
	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};


/* Media selection options. */
enum {
        IF_PORT_UNKNOWN = 0,
        IF_PORT_10BASE2,
        IF_PORT_10BASET,
        IF_PORT_AUI,
        IF_PORT_100BASET,
        IF_PORT_100BASETX,
        IF_PORT_100BASEFX
};

#ifdef __KERNEL__

#include <linux/cache.h>
#include <linux/skbuff.h>

struct neighbour;
struct neigh_parms;
struct sk_buff;

/**
 * 接收帧的统计信息。
 * 一些计数器通常仅仅在netif_rx中更新（仅用在非NAPI驱动中使用），这意味着使用NAPI驱动时，它们的值不正确。
 */
struct netif_rx_stats
{
	/**
	 * 已经处理的入包总数。包含丢弃的包。这个值在netif_rx和netif_recevie_skb中都会更新。这意味着在不使用NAPI时，同一个帧被统计了两次。
	 */
	unsigned total;
	/**
	 * 被丢弃的帧。当CPU处于throttle状态时接收到的包会被丢弃。
	 */
	unsigned dropped;
	/**
	 * 当CPU入队列中还有帧时，net_rx_action不得不返回，以避免CPU占用过多的次数。
	 */
	unsigned time_squeeze;
	/**
	 * CPU进入throttle状态的次数。它的值由netif_rx增加。
	 */
	unsigned throttled;
	/**
	 * Fastroute功能使用的字段。这个功能在2.6.8中已经不存在了。
	 */
	unsigned fastroute_hit;
	unsigned fastroute_success;
	unsigned fastroute_defer;
	unsigned fastroute_deferred_out;
	unsigned fastroute_latency_reduction;
	/**
	 * 不能获得设备驱动锁的次数。不能获得锁是由于另外一个CPU已经获得了这个锁。这个计数值由qdisc_restart更新。它仅在帧发送，而不会在接收时处理。
	 */
	unsigned cpu_collision;
};

DECLARE_PER_CPU(struct netif_rx_stats, netdev_rx_stat);


/*
 *	We tag multicasts with these structures.
 */
 
struct dev_mc_list
{	
	struct dev_mc_list	*next;
	__u8			dmi_addr[MAX_ADDR_LEN];
	unsigned char		dmi_addrlen;
	int			dmi_users;
	int			dmi_gusers;
};

/**
 * 缓存链路层头部信息用于加快传输速度。
 * 一次将一个缓存的头部信息复制到发送缓区中比按位填充头部信息要快得多。
 * 并不是所有的网络设备驱动都支持缓冲头部信息。
 */
struct hh_cache
{
	/**
	 * 和同一个neighbour项关联的缓存的L2帧头可以有多个，但是，给定一个hh_type值只能有一个与该邻居关联（参见neigh_hh_init）。
	 */
	struct hh_cache *hh_next;	/* Next entry			     */
	/**
	 * 引用计数。
	 */
	atomic_t	hh_refcnt;	/* number of users                   */
	/**
	 * 与L3地址相关的协议。
	 */
	unsigned short  hh_type;	/* protocol identifier, f.e ETH_P_IP
                                         *  NOTE:  For VLANs, this will be the
                                         *  encapuslated type. --BLG
                                         */
    /**
     * 以字节数表示的缓存的帧头长度。
     */
	int		hh_len;		/* length of header */
	/**
	 * 传输包的函数。和neigh->output一样，这个方法被初始化为neigh->ops VFT中的一个方法。
	 */
	int		(*hh_output)(struct sk_buff *skb);
	/**
	 * 于在竞争条件下保护hh_cache结构的锁。
	 */
	rwlock_t	hh_lock;

	/* cached hardware header; allow for machine alignment needs.        */
#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - ((__len) & (HH_DATA_MOD - 1)))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	/**
	 * 缓存的帧头。
	 */
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER) / sizeof(long)];
};

/* Reserve HH_DATA_MOD byte aligned hard_header_len, but at least that much.
 * Alternative is:
 *   dev->hard_header_len ? (dev->hard_header_len +
 *                           (HH_DATA_MOD - 1)) & ~(HH_DATA_MOD - 1) : 0
 *
 * We could use other alignment values, but we must maintain the
 * relationship HH alignment <= LL alignment.
 */
#define LL_RESERVED_SPACE(dev) \
	(((dev)->hard_header_len&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+extra)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

/* These flag bits are private to the generic network queueing
 * layer, they may not be explicitly referenced by any other
 * code.
 */

enum netdev_state_t
{
	/**
	 * 如果此位为1，则不允许发送帧。
	 */
	__LINK_STATE_XOFF=0,
	/**
	 * 设备时激活的，这个标志可以被netif_running检测。它可以允许或者禁止发送包，但是不能允许或者禁止接收包。
	 */
	__LINK_STATE_START,
	/**
	 * 设备是可见的，这个状态似乎是多余的，但是能够只是热插拔设备临时移除。
	 * 当系统处于挂起模式随后唤醒时，这个标志能够被分别清除和恢复。
	 * 这个标志能够由netif_device_present检测
	 */
	__LINK_STATE_PRESENT,
	/**
	 * 当设备正在发送帧时，此位被设置。
	 */
	__LINK_STATE_SCHED,
	/**
	 * 没有传递。此标志可由netif_carrier_ok检测,以检查网络是否连通。
	 */
	__LINK_STATE_NOCARRIER,
	/**
	 * 由代码设置以管理设备的入口和出口流量
	 * 如果在poll_list中，则此标志被设置。
	 */
	__LINK_STATE_RX_SCHED,
	__LINK_STATE_LINKWATCH_PENDING
};


/*
 * This structure holds at boot time configured netdevice settings. They
 * are then used in the device probing. 
 */
/**
 * netdev_boot_setup函数的处理结果。
 */
struct netdev_boot_setup {
	/**
	 * name 是设备名
	 */
	char name[IFNAMSIZ];
	/**
	 * ifmap 在 in include/linux/if.h 中定义，是存储输入配置的数据结构
	 */
	struct ifmap map;
};
/**
 * 启动时配置的设备的最大数,启动参数类似于LILO: linux ether=5,0x260,eth0 ether=15,0x300,eth1
 */
#define NETDEV_BOOT_SETUP_MAX 8


/*
 *	The DEVICE structure.
 *	Actually, this whole structure is a big mistake.  It mixes I/O
 *	data with strictly "high-level" data, and it has to know about
 *	almost every data structure used in the INET module.
 *
 *	FIXME: cleanup struct net_device such that network protocol info
 *	moves out.
 */
/**
 * net_device结构保存与网络设备相关的所有信息。
 * 每一个网络设备都对应一个这样的结构，包括真实设备（例如以太网卡）和虚拟设备（比如 bonding 或 VLAN）
 */
struct net_device
{

	/*
	 * This is the first field of the "visible" part of this structure
	 * (i.e. as seen by users in the "Space.c" file).  It is the name
	 * the interface.
	 */
	/**
	 * 设备名称（比如，eth0）
	 */
	char			name[IFNAMSIZ];

	/*
	 *	I/O specific fields
	 *	FIXME: Merge these and struct ifmap into one
	 */
	/**
	 * 这两个变量描述设备与内核通信所用到的内存边界。
	 * 它们由设备驱动初始化，并且只能被设备驱动访问；高层协议不需要关心这块内存。
	 */
	unsigned long		mem_end;	/* shared mem end	*/
	unsigned long		mem_start;	/* shared mem start	*/
	/**
	 * 映射到设备内存空间中I/O内存起始地址。
	 */
	unsigned long		base_addr;	/* device I/O address	*/
	/**
	 * 设备中断号。它可以被多个设备共享。设备驱动调用request_irq来分配这个值，并调用free_irq来释放它。
	 */
	unsigned int		irq;		/* device IRQ number	*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */
	/**
	 * 接口的端口类型。
	 */
	unsigned char		if_port;	/* Selectable AUI, TP,..*/
	/**
	 * 设备所使用的DMA通道。
	 */
	unsigned char		dma;		/* DMA channel		*/

	/**
	 * 包含一组被网络队列子系统使用的标记
	 */
	unsigned long		state;
	/**
	 * 指向全局链表中的下一个节点
	 */
	struct net_device	*next;
	
	/* The device initialization function. Called only once. */
	/**
	 * 用于初始化，清除，销毁，启用和停止一个设备。这些函数并不是每个设备都会用到。
	 */
	int			(*init)(struct net_device *dev);

	/* ------- Fields preinitialized in Space.c finish here ------- */

	/**
	 * 被流量管理的内核软中断使用
	 * 每个CPU上都有一个待发送的出设备队列，通过此指针，将出设备链接在一起。
	 */
	struct net_device	*next_sched;

	/* Interface index. Unique device identifier	*/
	/**
	 * 全局唯一的设备ID。在每个设备注册时，调用dev_new_index生成。
	 */
	int			ifindex;
	/**
	 * 这个变量主要被（虚拟）隧道设备使用，用于标识隧道的真实设备。
	 */
	int			iflink;


	/**
	 * 有些设备统计信息可以通过用户空间程序显示，比如ifconfig和ip；
	 * 而其他统计信息只能被内核使用。有两个函数用于获取设备统计信息。
	 * get_stats用于操作一个普通设备，而get_wireless_stats用于操作一个无线设备。
	 */
	struct net_device_stats* (*get_stats)(struct net_device *dev);
	struct iw_statistics*	(*get_wireless_stats)(struct net_device *dev);

	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	/**
	 * 被无线设备使用。
	 */
	const struct iw_handler_def *	wireless_handlers;
	/* Instance data managed by the core of Wireless Extensions. */
	struct iw_public_data *	wireless_data;

	/**
	 * 设置或获取不同设备参数的一组函数指针
	 */
	struct ethtool_ops *ethtool_ops;

	/*
	 * This marks the end of the "visible" part of the structure. All
	 * fields hereafter are internal to the system, and may change at
	 * will (read: may be cleaned up at will).
	 */

	/* These may be needed for future network-power-down code. */
	/**
	 * 最后一个帧开始发送的时间（用jiffies度量）。设备驱动在发送之前设置这个变量。
	 * 这个变量用来检测网卡是否在给定的时间内把帧发送了出去。
	 * 太长的发送时间意味着有错误发生，在这种情况下，设备驱动会重置网卡。
	 */
	unsigned long		trans_start;	/* Time (in jiffies) of last Tx	*/
	/**
	 * 接收到最后一个包的时间（用jiffies度量）。
	 * 目前，这个变量没有什么特殊的用途，但是，将来有可能会用到。
	 */
	unsigned long		last_rx;	/* Time of last Rx	*/

	/**
	 * flags变量中的某些位表示网络设备所支持的功能（例如是否支持多播IFF_MULTICAST 等），
	 * 其他位表示设备状态的变化（例如 IFF_UP 或者IFF_RUNNING）
	 * 设备驱动通常在设备初始化时设置设备所支持的功能，而设备状态则由内核根据某些外部事件来设置
	 */
	unsigned short		flags;	/* interface flags (a la BSD)	*/
	/**
	 * gflags几乎不会被使用，保留它只是为了保持兼容。
	 */
	unsigned short		gflags;
	/**
	 * priv_flags存储一些对用户空间程序不可见的标记。目前，这个变量被VLAN和桥虚拟设备使用。
	 */
        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
        unsigned short          unused_alignment_fixer; /* Because we need priv_flags,
                                                         * and we want to be 32-bit aligned.
                                                         */
	/**
	 * 最大传输单元，它表示设备可以处理帧的最大长度
	 */
	unsigned		mtu;	/* interface MTU value		*/
	/**
	 * 设备类型（以太网，帧中继等）。
	 */
	unsigned short		type;	/* interface hardware type	*/
	/**
	 * 以字节为单位的帧头部长度。例如，以太网帧的头是14字节。
	 */
	unsigned short		hard_header_len;	/* hardware hdr length	*/
	/**
	 * 不同的网卡的私有数据结构.
	 */
	void			*priv;	/* pointer to private data	*/

	/**
	 * 有些协议允许多个设备组合到一起当做一个设备使用。
	 * 这些协议包括 EQL（串行网络的复载均衡），Bonding（又被称作EtherChannel和trunking），和TEQL（true equalizer，它是流量控制子系统中的一个排队策略）。
	 * 在设备组中，有一个设备被选出来当作主设备，它有特殊的作用。这个变量是一个指向组中主设备的指针。
	 * 如果设备不是一个组的成员，这个指针被置为NULL。 
	 */
	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.
					  */

	/* Interface address info. */
	/**
	 * 链路层广播地址。
	 */
	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/
	/**
	 * dev_addr是设备的链路层地址，不要把它和IP地址或者L3地址混淆了。
	 */
	unsigned char		dev_addr[MAX_ADDR_LEN];	/* hw address	*/
	/**
	 * 链路层地址的长度是addr_len，以字节为单位。
	 * addr_len的大小与设备类型有关。以太网地址的长度是8。
	 */
	unsigned char		addr_len;	/* hardware address length	*/
	/**
	 * IPV6中使用 zSeries  OSA 网卡时用到这个变量。
	 * 这个变量用于区分同一设备的不同虚拟实体，这些虚拟实体可以在不同的虚拟操作系统中共享。
	 */
	unsigned short          dev_id;		/* for shared network cards */

	/**
	 * 设备监听的多播地址表.添加和删除多播地址可以分别调用函数 dev_mc_add 和dev_mc_delete完成
	 */
	struct dev_mc_list	*mc_list;	/* Multicast mac addresses	*/
	/**
	 * 设备多播地址的数量，它同样表示mc_list所指向链表的长度。
	 */
	int			mc_count;	/* Number of installed mcasts	*/
	/**
	 * "混杂模式"计数。
	 */
	int			promiscuity;
	/**
	 * 如果是非零值，那么设备将监听所有的多播地址。
	 * 和 promiscuity 一样，这个变量是一个计数器而不仅仅是一个布尔值。
	 * 这是因为多个设备（比如VLAN和bonding设备）可能独立地要求监听所有地址。
	 * 如果这个变量的值从0变为非零，内核会调用函数dev_set_allmulti通知设备监听所有的多播地址。
	 * 如果这个值变为0，则停止监听所有的多播地址。
	 */
	int			allmulti;

	/**
	 * 用于实现"Watchdog timer"，看门狗时钟的时间。
	 * 这是等待的时间总计。由设备驱动程序初始化。当它被设置成0时，watchdog_timer没有启动。
	 */
	int			watchdog_timeo;
	/**
	 * 看门狗时钟。
	 */
	struct timer_list	watchdog_timer;

	/* Protocol specific pointers */
	/**
	 * 这六个变量指向特定协议的数据结构，每个数据结构都包含协议私有的参数。
	 * 例如，ip_ptr指向一个 in_device 类型的结构（尽管 ip_ptr 的类型是 void*），它包含 IPv4相关的参数，其中包括设备的IP 地址列表等。
	 */
	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	*/  
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/
	void			*ax25_ptr;	/* AX.25 specific data */

	/**
	 * 这些变量被NAPI使用。
	 * 在入队列上有新帧的设备列表。列表头是softnet_data->poll_list。
	 * 在这个列表中的设备的中断被禁止，并且内核正在轮询它们。
	 */
	struct list_head	poll_list;	/* Link to poll list	*/
	/**
	 * quota是一个整数，表示在一次处理过程中，poll函数最多从队列中取出多少个缓冲区。
	 * 它的值每次以weight为单位增加，被用来在不同的设备间进行公平的排序。低的配额意味着更长的延迟，因此其他设备饿死的风险更小。
	 * 对与NAPI相关的设备，默认值由设备选择。大多数情况下，其值为64,但是也有使用16和32的。其值可以通过sysfs调整。
	 */
	int			quota;
	int			weight;

	/**
	 * 这些变量用于流量管理，管理设备的接收，发送队列，并且可以被不同的cpu访问。
	 */
	struct Qdisc		*qdisc;
	struct Qdisc		*qdisc_sleeping;
	struct Qdisc		*qdisc_ingress;
	struct list_head	qdisc_list;
	/**
	 * 设备发送队列的长度。
	 * 如果内核中包含了流量控制子系统，这个变量可能没有什么用（只有几个排队策略会使用它）。
	 * 这个值可以通过sysfs文件系统修改（在/sys/class/net/device_name/目录下）。
	 */
	unsigned long		tx_queue_len;	/* Max frames per queue allowed */

	/* ingress path synchronizer */
	/**
	 * 流量控制子系统用于避免并发访问接收队列。
	 */
	spinlock_t		ingress_lock;
	/* hard_start_xmit synchronizer */
	/**
	 * xmit_lock用来序列化对设备驱动函数hard_start_xmit的调用。
	 * 这意味着，每个cpu每次只能调用设备完成一次发送。
	 */
	spinlock_t		xmit_lock;
	/* cpu id of processor entered to hard_start_xmit or -1,
	   if nobody entered there.
	 */
	/**
	 * xmit_lock_owner 是拥有锁的 CPU 的 ID。
	 * 在单cpu系统上，这个值是 0；
	 * 在多 cpu 系统中，如果锁没有被占用，这个值是-1。
	 * 内核同样允许不加锁的发送，前提条件是设备驱动必须支持这个功能。
	 */
	int			xmit_lock_owner;
	/* device queue lock */
	/**
	 * 流量控制子系统为每个网络设备定义了一个私有的发送队列。
	 * queue_lock用于避免并发的访问。
	 */
	spinlock_t		queue_lock;
	/* Number of references to this device */
	/**
	 * 引用计数。如果计数不为0，设备就不能被卸载.
	 */
	atomic_t		refcnt;
	/* delayed register/unregister */
	/**
	 * 注册和卸载一个网络设备需要两个步骤，todo_list在第二个步骤中使用
	 */
	struct list_head	todo_list;
	/* device name hash chain */
	/**
	 * 把net_device结构链接到名称哈希表中。
	 */
	struct hlist_node	name_hlist;
	/* device index hash chain */
	/**
	 * 把net_device结构链接到索引哈希表中。
	 */
	struct hlist_node	index_hlist;

	/* register/unregister state machine */
	/**
	 * 设备的注册状态。
	 */
	enum { 
		   /**
		    * 定义为0，当net_device数据结构被分配，并且初始化时，dev->reg_state被赋此值，代表着0。
		    */
		   NETREG_UNINITIALIZED=0,
		   /**
		    * net_device结构被链入"net_device结构组织"一节介绍的结构链表，但内核仍然在/sys文件系统中加入一个入口。
		    */
	       NETREG_REGISTERING,	/* called register_netdevice */
	       /**
	        * 设备已完全注册
	        */
	       NETREG_REGISTERED,	/* completed register todo */
	       /**
	        * net_device结构从结构链表中移除
	        */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
	       /**
	        * 设备完全注销(包括移除/sys文件系统入口)，但net_device结构并未被释放 
	        */
	       NETREG_UNREGISTERED,	/* completed unregister todo */
	       /**
	        * 所有对net_device 结构的引用都已释放，数据结构亦即释放，但是，从网络代码的角度来看，这由sysfs来处理，参考"引用计数"
	        */
	       NETREG_RELEASED,		/* called free_netdev */
	} reg_state;

	/* Net device features */
	/**
	 * 表示设备所支持的功能的变量。
	 * features变量向CPU报告设备所支持的功能.
	 * 例如设备是否支持高端内存的 DMA，是否支持用硬件计算包的校验和等。
	 */
	int			features;
#define NETIF_F_SG		1	/* Scatter/gather IO. */
/**
 * 此设备可以在硬件中计算L4校验和，但是只针对使用Ipv4和TCP和UDP。
 */
#define NETIF_F_IP_CSUM		2	/* Can checksum only TCP/UDP over IPv4. */
/**
 * 此设备很可靠，不需要使用任何L4校验和。例如，环回设备就开启了此功能。
 */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
/**
 * 此设备可以为任何协议在硬件中计算L4校验和。和NETIF_F_IP_CSUM相比，此功能较少见。
 */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
/**
 * 设备是否支持分散/聚集IO功能。
 */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
#define NETIF_F_TSO		2048	/* Can offload TCP/IP segmentation */
/**
 * 是否由驱动自己实现发送锁。
 */
#define NETIF_F_LLTX		4096	/* LockLess TX */

	/* Called after device is detached from network. */
	/**
	 * 用于初始化，清除，销毁，启用和停止一个设备。这些函数并不是每个设备都会用到。
	 */
	void			(*uninit)(struct net_device *dev);
	/* Called after last user reference disappears. */
	void			(*destructor)(struct net_device *dev);

	/* Pointers to interface service routines.	*/
	int			(*open)(struct net_device *dev);
	int			(*stop)(struct net_device *dev);
	/**
	 * 发送一个帧。
	 */
	int			(*hard_start_xmit) (struct sk_buff *skb,
						    struct net_device *dev);
#define HAVE_NETDEV_POLL
	/**
	 * 用于NAPI，一个虚函数。用于从入队列中取出缓冲区。对每个设备来说，入队列是私有的。
	 */
	int			(*poll) (struct net_device *dev, int *quota);
	/**
	 * 这些函数被邻居层使用。按字段填充L2帧头。用于L2帧头缓冲。
	 */
	int			(*hard_header) (struct sk_buff *skb,
						struct net_device *dev,
						unsigned short type,
						void *daddr,
						void *saddr,
						unsigned len);
	/**
	 * 这些函数被邻居层使用。
	 * 该函数只是为了兼容2.2版以前的内核设备驱动程序。使用这个函数的设备不能使用hst_entry->neigh中的缓存的已经解析的地址。
	 */	
	int			(*rebuild_header)(struct sk_buff *skb);
#define HAVE_MULTICAST			
	/**
	 * mc_list 和 mc_count 用于维护 L2 的多播地址表。
	 * 这个方法用于设置设备驱动监听哪些多播地址。
	 * 通常情况下，它不会被直接调用，而是通过一个包装函数，比如 dev_mc_upload 或者不加锁版本__dev_mc_upload调用。
	 * 如果一个设备不能维护一个多播地址表，那么可以简单地设置它监听所有的多播地址。
	 */
	void			(*set_multicast_list)(struct net_device *dev);
#define HAVE_SET_MAC_ADDR  		 
	/**
	 * 修改设备的 MAC 地址。如果设备不提供这个功能（比如网桥设备），可以把这个指针设置为NULL。
	 */
	int			(*set_mac_address)(struct net_device *dev,
						   void *addr);
#define HAVE_PRIVATE_IOCTL
	/**
	 * ioctl系统调用用于向设备发送命令。这个函数被ioctl用来处理某些命令
	 */
	int			(*do_ioctl)(struct net_device *dev,
					    struct ifreq *ifr, int cmd);
#define HAVE_SET_CONFIG
	/**
	 * 设置设备参数，比如irq，io_addr，和if_port等。
	 * 高层参数（比如协议地址）由do_ioctl设置。
	 * 只有很少的设备使用这个函数。新的设备一般都采用自动探测的方式获取这些参数。
	 */
	int			(*set_config)(struct net_device *dev,
					      struct ifmap *map);
#define HAVE_HEADER_CACHE
	/**
	 * 这些函数被邻居层使用。将一个L2帧头缓存在hh_cache结构中。
	 */
	int			(*hard_header_cache)(struct neighbour *neigh,
						     struct hh_cache *hh);
	/**
	 * 这些函数被邻居层使用。
	 * 更新一个存在的hh_cache缓存项，用一个新的帧头替换该项中缓存的帧头。
	 * 通常从neigh_update_hhs中调用这个函数。Neigh_update使用neigh_update_hhs对邻居项进行更新。
	 */
	void			(*header_cache_update)(struct hh_cache *hh,
						       struct net_device *dev,
						       unsigned char *  haddr);
#define HAVE_CHANGE_MTU
	/**
	 * 修改设备的MTU。修改mtu不会对设备驱动有任何影响，它只是让协议栈软件可以根据新的mtu正确地处理分片。
	 */
	int			(*change_mtu)(struct net_device *dev, int new_mtu);

#define HAVE_TX_TIMEOUT
	/**
	 * 在watchdog定时器超时后调用这个函数。它用来确定发送一个帧的时间是否太长。
	 * 如果这个函数没有定义，watchdog定时器就不会被启用。
	 * 当时钟到期时，内核处理函数dev_watchdog调用tx_timeout指向的函数。后者通常重置网卡，并且通过netif_wake_queue重启接口调度。
	 */
	void			(*tx_timeout) (struct net_device *dev);

	/**
	 * 这三个函数指针被 VLAN 设备用来注册设备可以处理的VLAN 标记（参见net/8021q/vlan.c），它可以向设备增加一个VLAN或者从设备上删除一个VLAN。
	 */
	void			(*vlan_rx_register)(struct net_device *dev,
						    struct vlan_group *grp);
	void			(*vlan_rx_add_vid)(struct net_device *dev,
						   unsigned short vid);
	void			(*vlan_rx_kill_vid)(struct net_device *dev,
						    unsigned short vid);
	/**
	 * 这些函数被邻居层使用。
	 * 从一个缓冲区中取出源L2地址，然后返回该地址的长度。
	 */
	int			(*hard_header_parse)(struct sk_buff *skb,
						     unsigned char *haddr);
	/**
	 * 这些函数被邻居层使用。
	 */	
	int			(*neigh_setup)(struct net_device *dev, struct neigh_parms *);
	/**
	 * 这个函数用于测试一个设备是否支持快速交换功能。已经废弃。
	 */
	int			(*accept_fastpath)(struct net_device *, struct dst_entry*);
#ifdef CONFIG_NETPOLL
	/**
	 * 被Netpoll使用
	 */
	int			netpoll_rx;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	void                    (*poll_controller)(struct net_device *dev);
#endif

	/* bridge stuff */
	/**
	 * 设备被配置成网桥接口时所需要的附加信息。
	 */
	struct net_bridge_port	*br_port;

#ifdef CONFIG_NET_DIVERT
	/* this will get initialized at each interface type init routine */
	/**
	 * Diverter功能允许修改进入包的源地址和目的地址。
	 * 它可以把特定包转发到某个特定接口或主机。为了使用这个功能，内核必须包含其他一些功能，比如网桥。
	 * 这个指针指向的数据结构中包含了这个功能所使用的变量。相应的内核选项是"Device drivers ->Networking support ->Networking options ->Frame Diverter"。
	 */
	struct divert_blk	*divert;
#endif /* CONFIG_NET_DIVERT */

	/* class/net/name entry */
	/**
	 * 被新的内核驱动架构使用。用于/sys/class/net/name
	 */
	struct class_device	class_dev;
	/* how much padding had been added by alloc_netdev() */
	int padded;
};

#define	NETDEV_ALIGN		32
#define	NETDEV_ALIGN_CONST	(NETDEV_ALIGN - 1)

/**
 * 网线设备结构的priv
 */
static inline void *netdev_priv(struct net_device *dev)
{
	return (char *)dev + ((sizeof(struct net_device)
					+ NETDEV_ALIGN_CONST)
				& ~NETDEV_ALIGN_CONST);
}

#define SET_MODULE_OWNER(dev) do { } while (0)
/* Set the sysfs physical device reference for the network logical device
 * if set prior to registration will cause a symlink during initialization.
 */
#define SET_NETDEV_DEV(net, pdev)	((net)->class_dev.dev = (pdev))

/**
 * 包处理协议
 */
struct packet_type {
	/**
	 * 协议类型。如IPV4、IPV6、ETH_P_ALL
	 */
	unsigned short		type;	/* This is really htons(ether_type).	*/
	/**
	 * 指向激活此协议的设备，如eth0。NULL表示所有设备。
	 * 得益于这个参数，它使得不同的设备可以有不同的处理函数，或者为特定的设备关联一个处理函数。
	 */
	struct net_device		*dev;	/* NULL is wildcarded here		*/
	/**
	 * 当需要由skb->protocol_type处理一个帧时，由netif_receive_skb调用的处理函数（如ip_rcv）。
	 */
	int			(*func) (struct sk_buff *, struct net_device *,
					 struct packet_type *);
	/**
	 * 用于PF_SOCKET类型的socket。它指向相关的sock数据结构。
	 */
	void			*af_packet_priv;
	/**
	 * 用于将数据结构链接到链表中。
	 */
	struct list_head	list;
};

#include <linux/interrupt.h>
#include <linux/notifier.h>

extern struct net_device		loopback_dev;		/* The loopback */
extern struct net_device		*dev_base;		/* All devices */
/**
 * 在dev_base链和两个哈希表中的所有的搜索，都由dev_base_lock锁保护
 */
extern rwlock_t				dev_base_lock;		/* Device list lock */

extern int 			netdev_boot_setup_check(struct net_device *dev);
extern unsigned long		netdev_boot_base(const char *prefix, int unit);
extern struct net_device    *dev_getbyhwaddr(unsigned short type, char *hwaddr);
extern struct net_device *dev_getfirstbyhwtype(unsigned short type);
extern void		dev_add_pack(struct packet_type *pt);
extern void		dev_remove_pack(struct packet_type *pt);
extern void		__dev_remove_pack(struct packet_type *pt);

extern struct net_device	*dev_get_by_flags(unsigned short flags,
						  unsigned short mask);
extern struct net_device	*dev_get_by_name(const char *name);
extern struct net_device	*__dev_get_by_name(const char *name);
extern int		dev_alloc_name(struct net_device *dev, const char *name);
extern int		dev_open(struct net_device *dev);
extern int		dev_close(struct net_device *dev);
extern int		dev_queue_xmit(struct sk_buff *skb);
extern int		register_netdevice(struct net_device *dev);
extern int		unregister_netdevice(struct net_device *dev);
extern void		free_netdev(struct net_device *dev);
extern void		synchronize_net(void);
extern int 		register_netdevice_notifier(struct notifier_block *nb);
extern int		unregister_netdevice_notifier(struct notifier_block *nb);
extern int		call_netdevice_notifiers(unsigned long val, void *v);
extern struct net_device	*dev_get_by_index(int ifindex);
extern struct net_device	*__dev_get_by_index(int ifindex);
extern int		dev_restart(struct net_device *dev);
#ifdef CONFIG_NETPOLL_TRAP
extern int		netpoll_trap(void);
#endif

typedef int gifconf_func_t(struct net_device * dev, char __user * bufptr, int len);
extern int		register_gifconf(unsigned int family, gifconf_func_t * gifconf);
static inline int unregister_gifconf(unsigned int family)
{
	return register_gifconf(family, NULL);
}

/*
 * Incoming packets are placed on per-cpu queues so that
 * no locking is needed.
 */

struct softnet_data
{
	/**
	 * throttle、avg_blog、cng_level：这三字参数被用于拥塞管理算法
	 * throttle被作为布尔变量处理，当CPU是超载时，其值为true，否则为false。
	 * 它的值依赖于input_pkt_queue的数量。当throttle被设置时，当前CPU上的所有入包被丢弃，而不管队列中帧的数量。
	 */
	int			throttle;
	/**
	 * 表示拥塞级别。
	 * 默认的，avg_blog和cng_level在处理每一帧时重新计算。但是可以被暂缓，并且挂到时钟上，以避免增加太多负载。
	 */
	int			cng_level;
	/**
	 * 表示input_pkt_queue队列的平均长度。它的范围在0到最大长度之间（netdev_max_backlog）。avg_blog被用来计算cng_level。
	 * avg_blog和cng_level与CPU关联，因此被用于非NAPI驱动。
	 */
	int			avg_blog;
	/**
	 * 这个队列在net_dev_init中初始化。入帧在没有被驱动处理前被存储在这里。
	 * 它被非NAPI驱动使用。NAPI使用它自己私有的队列。
	 */
	struct sk_buff_head	input_pkt_queue;
	/**
	 * 这是等待处理入帧的双向设备链表。
	 */
	struct list_head	poll_list;
	/**
	 * output_queue是需要发包的设备列表。
	 */
	struct net_device	*output_queue;
	/**
	 * completion_queue是已经成功发送，因而可以释放的缓冲区。
	 */
	struct sk_buff		*completion_queue;

	/**
	 * 这完全是一个嵌入的数据结构，类型为net_device。表示与CPU相关的的设备。
	 * 这个字段被非NAPI驱动使用。设备名字为"backlog device"。
	 */
	struct net_device	backlog_dev;	/* Sorry. 8) */
};

DECLARE_PER_CPU(struct softnet_data,softnet_data);

#define HAVE_NETIF_QUEUE
/**
 * 调度设备发包。
 */
static inline void __netif_schedule(struct net_device *dev)
{
	/**
	 * 如果设备已经被调度发送，则不做任何事情。
	 */
	if (!test_and_set_bit(__LINK_STATE_SCHED, &dev->state)) {
		unsigned long flags;
		struct softnet_data *sd;

		/**
		 * 由于__netif_schedule可以在中断上下文内或者在中断上下文之外被调用，因此它在添加设备到output_queue链表时，禁止中断。
		 */
		local_irq_save(flags);
		sd = &__get_cpu_var(softnet_data);
		/**
		 * 添加设备到output_queue链表头。这个链表与poll_list相似。
		 * 每个CPU都有一个output_queue，就象每个CPU都有一个poll_list一样。
		 * 不论是NAPI还是非NAPI，都使用output_queue，而poll_list仅被非NAPI设备使用。
		 * output_list链表中的设备由net_device->next_sched指针链接在一起。
		 */
		dev->next_sched = sd->output_queue;
		sd->output_queue = dev;
		/**
		 * 调度执行NET_TX_SOFTIRQ软中断。__LINK_STATE_SCHED被用来标示设备在output_queue链表中，表示有一些包需要被发送。
		 * 它与__LINK_STATE_RX_SCHED相似。注意：如果设备已经被调度，那么__netif_schedule不做任何事情。
		 */
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}

/**
 * 仅当设备允许发送时，才调度设备。
 */
static inline void netif_schedule(struct net_device *dev)
{
	if (!test_bit(__LINK_STATE_XOFF, &dev->state))
		__netif_schedule(dev);
}

/**
 * 允许设备发送帧。通常，在设备激活，或者在重启设备时调用它。
 */
static inline void netif_start_queue(struct net_device *dev)
{
	clear_bit(__LINK_STATE_XOFF, &dev->state);
}

/**
 * 如果设备被禁止发送，就使能设备发送。同时调度设备开始发送。
 * 由于在设备队列被禁止期间，可能有地方尝试发送包，因此调度是有必要的。
 */
static inline void netif_wake_queue(struct net_device *dev)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	if (test_and_clear_bit(__LINK_STATE_XOFF, &dev->state))
		__netif_schedule(dev);
}

/**
 * 禁止设备发送帧。任何在设备上尝试进行发送的操作都将被禁止。
 */
static inline void netif_stop_queue(struct net_device *dev)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	set_bit(__LINK_STATE_XOFF, &dev->state);
}

/**
 * 返回出队列的状态：允许或者禁止。
 */
static inline int netif_queue_stopped(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline int netif_running(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}


/* Use this variant when it is known for sure that it
 * is executing from interrupt context.
 */
/**
 * 在中断上下文，释放sk_buff的函数。
 * 它简单的将缓冲区加入completion_queue队列，然后在软中断中释放。这样可以加快中断的处理。
 */
static inline void dev_kfree_skb_irq(struct sk_buff *skb)
{
	if (atomic_dec_and_test(&skb->users)) {
		struct softnet_data *sd;
		unsigned long flags;

		local_irq_save(flags);
		sd = &__get_cpu_var(softnet_data);
		skb->next = sd->completion_queue;
		sd->completion_queue = skb;
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}

/* Use this variant in places where it could be invoked
 * either from interrupt or non-interrupt context.
 */
/**
 * 在不同的上下文中释放缓冲区：在中断上下文中或者在中断上下文外。
 */
static inline void dev_kfree_skb_any(struct sk_buff *skb)
{
	if (in_irq() || irqs_disabled())/* 如果在中断上下文或者关中断状态下，仅简单的将待释放包放到链表中，然后在软中断上下文释放。 */
		dev_kfree_skb_irq(skb);
	else
		dev_kfree_skb(skb);
}

#define HAVE_NETIF_RX 1
extern int		netif_rx(struct sk_buff *skb);
extern int		netif_rx_ni(struct sk_buff *skb);
#define HAVE_NETIF_RECEIVE_SKB 1
extern int		netif_receive_skb(struct sk_buff *skb);
extern int		dev_ioctl(unsigned int cmd, void __user *);
extern int		dev_ethtool(struct ifreq *);
extern unsigned		dev_get_flags(const struct net_device *);
extern int		dev_change_flags(struct net_device *, unsigned);
extern int		dev_change_name(struct net_device *, char *);
extern int		dev_set_mtu(struct net_device *, int);
extern void		dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev);

extern void		dev_init(void);

extern int		netdev_nit;

/* Called by rtnetlink.c:rtnl_unlock() */
extern void netdev_run_todo(void);

static inline void dev_put(struct net_device *dev)
{
	atomic_dec(&dev->refcnt);
}

#define __dev_put(dev) atomic_dec(&(dev)->refcnt)
#define dev_hold(dev) atomic_inc(&(dev)->refcnt)

/* Carrier loss detection, dial on demand. The functions netif_carrier_on
 * and _off may be called from IRQ context, but it is caller
 * who is responsible for serialization of these calls.
 */

extern void linkwatch_fire_event(struct net_device *dev);

static inline int netif_carrier_ok(const struct net_device *dev)
{
	return !test_bit(__LINK_STATE_NOCARRIER, &dev->state);
}

extern void __netdev_watchdog_up(struct net_device *dev);

/**
 * 当设备驱动侦测到在其设备上传递信号时，它调用netif_carrier_on函数.
 * 下面是几个常见的导致连接状态改变的的情况： 
 *		从网卡拔出或插入电缆 
 *		电缆另一端的设备关闭或禁止。这些设备如hub、网桥、路由器、pc机网卡。
 */
static inline void netif_carrier_on(struct net_device *dev)
{
	/**
	 * 清除dev->state的__LINK_STATE_NOCARRIER标志位
	 */
	if (test_and_clear_bit(__LINK_STATE_NOCARRIER, &dev->state))
		/**
		 * 生成一个连接状态改变事件并提交给linkwatch_fire_event处理。
		 */
		linkwatch_fire_event(dev);
	/**
	 * 如果设备被使能，则启动一个监视定时器。定时器由流量控制使用，以侦测是否发送失败或获得一个时间戳(这种情况定时器超时)。
	 */
	if (netif_running(dev))
		__netdev_watchdog_up(dev);
}

/**
 * 当设备驱动侦测到在其设备上丢失信号时，它调用netif_carrier_off函数。
 */
static inline void netif_carrier_off(struct net_device *dev)
{
	/**
	 * 设置dev->state的__LINK_STATE_NOCARRIER标志位
	 */
	if (!test_and_set_bit(__LINK_STATE_NOCARRIER, &dev->state))
		/**
		 * 生成一个连接状态改变事件并提交给linkwatch_fire_event处理。
		 */
		linkwatch_fire_event(dev);
}

/* Hot-plugging. */
static inline int netif_device_present(struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

/**
 * 挂起设备时，进行一些公共处理事件。
 */
static inline void netif_device_detach(struct net_device *dev)
{
	/**
	 * 在这里会清除dev->state的__LINK_STATE_PRESENT标志位，因为设备临时不能够操作。
	 */
	 */
	if (test_and_clear_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
	    /*
		 * 如果设备用netif_stop_queue使能或禁止其入队列，以防止设备用于发送任何其它的包。
	 	 * 注意：已注册的设备不需要使能：当设备被验证后，它获取内核指派的设备驱动并注册；但是，设备直到有明确的用户配置请求时，才使能(因此可用)。
	 	 */
	 	netif_stop_queue(dev);
	}
}

/**
 * 唤醒设备时，进行一些公共处理事件。
 */
static inline void netif_device_attach(struct net_device *dev)
{
	/**
	 * 设置dev->state的__LINK_STATE_PRESENT标志位，因为设备现在可用了。
	 */
	if (!test_and_set_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
	    /**
	     * 如果设备在挂起前被使能，用netif_wake_queue函数重新使能其入口队列，并由流量控制重新开启其监视定时器
	     */
		netif_wake_queue(dev);
 		__netdev_watchdog_up(dev);
	}
}

/*
 * Network interface message level settings
 */
#define HAVE_NETIF_MSG 1

enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)

static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	/* use default */
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0)	/* no output */
		return 0;
	/* set low N bits */
	return (1 << debug_value) - 1;
}

/* Schedule rx intr now? */

static inline int netif_rx_schedule_prep(struct net_device *dev)
{
	return netif_running(dev) &&
		!test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* Add interface to tail of rx poll list. This assumes that _prep has
 * already been called and returned 1.
 */

static inline void __netif_rx_schedule(struct net_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	dev_hold(dev);
	list_add_tail(&dev->poll_list, &__get_cpu_var(softnet_data).poll_list);
	if (dev->quota < 0)
		dev->quota += dev->weight;
	else
		dev->quota = dev->weight;
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
	local_irq_restore(flags);
}

/* Try to reschedule poll. Called by irq handler. */
/**
 * 当设备驱动使用NAPI时，驱动在中断处理函数中调用它，以使能网络收包软中断。
 */
static inline void netif_rx_schedule(struct net_device *dev)
{
	/**
	 * 如果设备确实在运行，并且相应的软中断没有被使能。
	 */
	if (netif_rx_schedule_prep(dev))
		/**
		 * 将设备添加到poll_list链表，并触发软中断。
		 */
		__netif_rx_schedule(dev);
}

/* Try to reschedule poll. Called by dev->poll() after netif_rx_complete().
 * Do not inline this?
 */
static inline int netif_rx_reschedule(struct net_device *dev, int undo)
{
	if (netif_rx_schedule_prep(dev)) {
		unsigned long flags;

		dev->quota += undo;

		local_irq_save(flags);
		list_add_tail(&dev->poll_list, &__get_cpu_var(softnet_data).poll_list);
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
		local_irq_restore(flags);
		return 1;
	}
	return 0;
}

/* Remove interface from poll list: it must be in the poll list
 * on current cpu. This primitive is called by dev->poll(), when
 * it completes the work. The device cannot be out of poll list at this
 * moment, it is BUG().
 */
/**
 * 将设备从poll_list链表中删除。
 */
static inline void netif_rx_complete(struct net_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	BUG_ON(!test_bit(__LINK_STATE_RX_SCHED, &dev->state));
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
	local_irq_restore(flags);
}

/**
 * 临时的允许或者禁止轮询
 * 这并不意味着设备回到了中断驱动模式。轮询可以在某个设备上被禁止，例如，当设备需要重置，以让一些配置生效。
 */
static inline void netif_poll_disable(struct net_device *dev)
{
	/**
	 * 如果__LINK_STATE_RX_SCHED没有被设置，说明设备没有在poll_list中。
	 * 那么，简单的设置它并返回。
	 * 否则，睡眠，并等待__LINK_STATE_RX_SCHED标志被清除，然后再设置标志。
	 * 设置本标志后，设备不会再被加入到poll_list队列，也就暂时禁止了poll.
	 */
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}

/**
 * 临时的允许或者禁止轮询
 * 这并不意味着设备回到了中断驱动模式。轮询可以在某个设备上被禁止，例如，当设备需要重置，以让一些配置生效。
 */
static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* same as netif_rx_complete, except that local_irq_save(flags)
 * has already been issued
 */
static inline void __netif_rx_complete(struct net_device *dev)
{
	BUG_ON(!test_bit(__LINK_STATE_RX_SCHED, &dev->state));
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}

/* These functions live elsewhere (drivers/net/net_init.c, but related) */

extern void		ether_setup(struct net_device *dev);

/* Support for loadable net-drivers */
extern struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				       void (*setup)(struct net_device *));
extern int		register_netdev(struct net_device *dev);
extern void		unregister_netdev(struct net_device *dev);
/* Functions used for multicast support */
extern void		dev_mc_upload(struct net_device *dev);
extern int 		dev_mc_delete(struct net_device *dev, void *addr, int alen, int all);
extern int		dev_mc_add(struct net_device *dev, void *addr, int alen, int newonly);
extern void		dev_mc_discard(struct net_device *dev);
extern void		dev_set_promiscuity(struct net_device *dev, int inc);
extern void		dev_set_allmulti(struct net_device *dev, int inc);
extern void		netdev_state_change(struct net_device *dev);
/* Load a device via the kmod */
extern void		dev_load(const char *name);
extern void		dev_mcast_init(void);
extern int		netdev_max_backlog;
extern int		weight_p;
extern unsigned long	netdev_fc_xoff;
extern atomic_t netdev_dropping;
extern int		netdev_set_master(struct net_device *dev, struct net_device *master);
extern int skb_checksum_help(struct sk_buff *skb, int inward);
/* rx skb timestamps */
extern void		net_enable_timestamp(void);
extern void		net_disable_timestamp(void);

#ifdef CONFIG_SYSCTL
extern char *net_sysctl_strdup(const char *s);
#endif

#endif /* __KERNEL__ */

#endif	/* _LINUX_DEV_H */
