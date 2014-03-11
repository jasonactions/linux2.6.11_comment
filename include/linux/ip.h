/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP protocol.
 *
 * Version:	@(#)ip.h	1.0.2	04/28/93
 *
 * Authors:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_IP_H
#define _LINUX_IP_H
#include <asm/byteorder.h>

#define IPTOS_TOS_MASK		0x1E
#define IPTOS_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04
#define	IPTOS_MINCOST		0x02

#define IPTOS_PREC_MASK		0xE0
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00


/* IP options */
#define IPOPT_COPY		0x80
#define IPOPT_CLASS_MASK	0x60
#define IPOPT_NUMBER_MASK	0x1f

/**
 * 解析IP选项类型字段中的number，copied和class部分
 */
#define	IPOPT_COPIED(o)		((o)&IPOPT_COPY)
#define	IPOPT_CLASS(o)		((o)&IPOPT_CLASS_MASK)
#define	IPOPT_NUMBER(o)		((o)&IPOPT_NUMBER_MASK)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

/**
 * 当IP选项的长度不是4字节的整数倍时，发送IPOPT_END选项填充IP头，以使选项4字节对齐。
 */
#define IPOPT_END	(0 |IPOPT_CONTROL)
/**
 * IPOPT_NOOP选项用于在两个选项之间进行填充。例如，对齐后面的IP选项到给定的边界。
 */
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_RR	(7 |IPOPT_CONTROL)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

#define IPVERSION	4
#define MAXTTL		255
#define IPDEFTTL	64

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */

#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/igmp.h>
#include <net/flow.h>

/**
 * IP选项。
 */
struct ip_options {
  /**
   * 对于出包来说，如果指定了源路由，就是第一个源路由。
   */
  __u32		faddr;				/* Saved first hop address */
  /**
   * 这组选项的长度。根据IP报头的定义，其值最大为40字节。
   */
  unsigned char	optlen;
  unsigned char srr;
  /**
   * 当rr为非0时，"record route"就是IP选项之一，而该字段的值就代表该选项在IP报头中起始的偏移量。
   * 此字段和rr_needaddr一起合用。
   */
  unsigned char rr;
  /**
   * 当ts为非0时，"timestamp"是IP选项之一，而该字段的值就代表该选项在IP报头中起始的偏移量。
   * 此字段和ts_needaddr及ts_needtime一起合用。
   */
  unsigned char ts;
  /**
   * 此字段只对已传输包有意义，当选项从用户空间以setsockopt系统调用传递时，就会设定，然而，当前都没有用到。
   */
  unsigned char is_setbyuser:1,			/* Set by setsockopt?			*/
  				/**
  				 * 当本地节点传输一个本地产生的包时，以及当本地节点回复一条ICMP请求时。
  				 * 就这些情况而言，is_data为真，而_data会指向一个区域，此区域包含要附加到IP报头的选项。
  				 */
                is_data:1,			/* Options in __data, rather than skb	*/
                /**
                 * 当严格路由为选项之一时，is_strictroute标志就会设定。
                 */
                is_strictroute:1,		/* Strict source route			*/
                srr_is_hit:1,			/* Packet destination addr was our one	*/
                /**
                 * 如果IP报头已被修改（如IP地址或时间戳），就会设定。
                 * 知道这件事非常有用处，因为如果包要被转发，该字段会指出IP校验和必须重新计算。
                 */
                is_changed:1,			/* IP checksum more not valid		*/	
                /**
                 * 当rr_needaddr为真时，"record route"是IP选项之一，而且报头中还有空间可容纳另一条路径。
                 * 因此，当前节点应该把外出接口的IP地址拷贝到rr在IP报头中所指的偏移量。
                 */
                rr_needaddr:1,			/* Need to record addr of outgoing dev	*/
                /**
                 * 当此选项为真时，"timestamp"就是IP选项之一，而且报头中依然有空间可容纳另一个时间戳。
                 * 因此，当前节点应该把传输时间加入IP报头。而位置就是ts所指定的偏移量。
                 */
                ts_needtime:1,			/* Need to record timestamp		*/
                /**
                 * 与ts和ts_needtime一起使用，以指出出设备的IP地址也应该拷贝到IP报头。
                 */
                ts_needaddr:1;			/* Need to record addr of outgoing dev  */
  /**
   * 当此选项为真时，"route alert"就是IP选项之一。
   */
  unsigned char router_alert;
  /**
   * 因为当位置对齐32位边界时，内存的存取会比较快，LINUX内核数据结构通常会采用无用字段（__padn）做填充，以便使其尺寸为32的倍数。这就是__pad1和__pad2的用途，除此别无它用。
   */
  unsigned char __pad1;
  unsigned char __pad2;
  unsigned char __data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct ipv6_pinfo;

/**
 * PF_INET套口实例，是ipv4专用传输控制块，存储ipv4的一些专用属性。
 * 比较通用的IPv4协议族描述块，包含TCP\UDP\RAWSOCK的共有控制信息。
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	/**
	 * 套口的网络层信息
	 */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	/* 目的IP地址 */
	__u32			daddr;		/* Foreign IPv4 addr */
	/* 已经绑定的本地IP地址 */
	__u32			rcv_saddr;	/* Bound local IPv4 addr */
	/* 目的端口 */
	__u16			dport;		/* Destination port */
	/* 主机字节序的本地端口号 */
	__u16			num;		/* Local port */
	/* 发送时使用的地址。如果为0，表示使用发送接口的地址(如绑定了广播、多播地址时) */
	__u32			saddr;		/* Sending source */
	/* 单播TTL */
	int			uc_ttl;		/* Unicast TTL */
	/* 用于设置报文首部的TOS域 */
	int			tos;		/* TOS */
	/* 一些IPPROTO_IP级别的选项值，如IP_CMSG_PKTINFO */
	unsigned	   	cmsg_flags;
	/**
	 * IP数据报选项的指针。
	 */
	struct ip_options	*opt;
	/* 网络字节序的本地端口号 */
	__u16			sport;		/* Source port */
	/* 是否需要自己构建IP首部 */
	unsigned char		hdrincl;	/* Include headers ? */
	/* 组播TTL */
	__u8			mc_ttl;		/* Multicasting TTL */
	/* 组播是否需要环回 */
	__u8			mc_loop;	/* Loopback */
	/* 套接口是否支持PMTU */
	__u8			pmtudisc;
	__u16			id;		/* ID counter for DF pkts */
	/* 是否允许接收扩展的可靠错误信息 */
	unsigned		recverr : 1,
	/* 是否允许绑定非主机地址。 */
				freebind : 1;
	/* 组播设备索引 */
	int			mc_index;	/* Multicast device index */
	/* 发送组播报文的源地址 */
	__u32			mc_addr;
	/* 组播组列表 */
	struct ip_mc_socklist	*mc_list;	/* Group array */
	/*
	 * Following members are used to retain the infomation to build
	 * an ip header on each ip fragmentation while the socket is corked.
	 */
	/**
	 * cork结构是用于处理套接字CORK选项。
	 * cork结构在ip_append_data和ip_append_page中扮演着重要角色：存储由这两个函数正确做数据分段所必须的背景信息。在各种信息中，包含了IP报头里的选项（如果有的话）以及片段长度。
	 */
	struct {
		/**
		 * 目前IPV4只有一个标志可以设定：IPCORK_OPT。当此标志设定时，意味着opt中有选项。
		 */
		unsigned int		flags;
		/**
		 * 产生的数据片段的尺寸。此尺寸包括有效负荷和L3报头，而且通常就是PMTU。
		 */
		unsigned int		fragsize;
		/**
		 * 要用的IP选项。
		 */
		struct ip_options	*opt;
		/**
		 * 用于传输IP包的路由表缓存项目。
		 */
		struct rtable		*rt;
		/**
		 * 已经缓存的所有分段的总长。不能超过64KB。
		 */
		int			length; /* Total length of all frames */
		/**
		 * 目的地IP地址。
		 */
		u32			addr;
		/**
		 * 有关连接两端点的信息集。
		 */
		struct flowi		fl;
	} cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
/**
 * 将sock强转为inet_sock.
 */
static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->slab_obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif
#endif
/**
 * IP报头。
 */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	/**
	 * IP协议版本。
	 */
	__u8	version:4,
	/**
	 * 协议头长度。最大值为15，以4字节为单位。因此，IP头最大长度为60.
	 * 由于基本报头长度是20字节，因此，IP选项最多为40字节。
	 */
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	/**
	 * 服务类型，此字段的值已经与标准协议有所区别。
	 * 可以为流媒体相关协议所使用。
	 */
	__u8	tos;
	/**
	 * 报文长度，包括报头和分片。
	 */
	__u16	tot_len;
	/**
	 * IP标识。LINUX为每个远端地址保存了一个ID计数。
	 */
	__u16	id;
	/**
	 * 分片在原始报文中的偏移。
	 */
	__u16	frag_off;
	/**
	 * TTL，路由器在每次转发时递减此值。
	 */
	__u8	ttl;
	/**
	 * L4层协议标识。
	 */
	__u8	protocol;
	/**
	 * 校验和。
	 */
	__u16	check;
	/**
	 * 源地址。
	 */
	__u32	saddr;
	/**
	 * 目的地址。
	 */
	__u32	daddr;
	/*The options start here. */
};

struct ip_auth_hdr {
	__u8  nexthdr;
	__u8  hdrlen;		/* This one is measured in 32 bit units! */
	__u16 reserved;
	__u32 spi;
	__u32 seq_no;		/* Sequence number */
	__u8  auth_data[0];	/* Variable len but >=4. Mind the 64 bit alignment! */
};

struct ip_esp_hdr {
	__u32 spi;
	__u32 seq_no;		/* Sequence number */
	__u8  enc_data[0];	/* Variable len but >=8. Mind the 64 bit alignment! */
};

struct ip_comp_hdr {
	__u8 nexthdr;
	__u8 flags;
	__u16 cpi;
};

#endif	/* _LINUX_IP_H */
