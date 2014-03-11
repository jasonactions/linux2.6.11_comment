/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <linux/config.h>
#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>

#ifndef __KERNEL__
#warning This file is not supposed to be used outside of kernel.
#endif

#define RTO_ONLINK	0x01

#define RTO_CONN	0
/* RTO_CONN is not used (being alias for 0), but preserved not to break
 * some modules referring to it. */

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sk->sk_localroute)

struct inet_peer;
/**
 * IPV4路由缓存由结构rtable组成。
 * 每一个rtable实例对应于一个不同的IP地址。在rtable结构的字段中包括目的地址、下一跳地址和一个dst_entry类型的结构，用于存储与协议无关的信息。
 */
struct rtable
{
	/**
	 * 这个联合用来将一个dst_entry结构嵌入到rtable结构中。
	 * 该联合中的rt_next字段被用于链接分布在同一个哈希桶内的rtable实例。
	 */
	union
	{
		struct dst_entry	dst;
		/**
		 * 与dst共享的，指向下一个碰撞哈希表项的指针。与dst的next指向相同位置。
		 */
		struct rtable		*rt_next;
	} u;

	/**
	 * 该指针指向egress设备的IP配置块。
	 * 注意对送往本地的ingress报文的路由，设置的egress设备为loopback设备。
	 */
	struct in_device	*idev;

	/**
	 * 在该比特图中可以设置的标志为在include/linux/in_route.h文件内定义的RTCF_XXX
	 */
	unsigned		rt_flags;
	/**
	 * 路由类型。它间接定义了当路由查找匹配时应采取的动作。
	 * 该字段可能的取值是在include/linux/rtnetlink.h文件中定义的RTN_XXX宏。
	 */
	unsigned		rt_type;

	/**
	 * 下一跳，由路由子系统计算出。
	 */
	__u32			rt_dst;	/* Path destination	*/
	__u32			rt_src;	/* Path source		*/
	/**
	 * 入设备标识。
	 * 这个值是从ingress设备的net_device数据结构中得到。
	 * 对本地生成的流量（因此不是从任何接口上接收到的），该字段被设置为出设备的ifindex字段。
	 */
	int			rt_iif;

	/* Info on neighbour */
	/**
	 * 下一跳(由严格路由选项计算出)
	 * 当目的主机为直连时（即在同一链路上），rt_gateway表示目的地址。
	 * 当需要通过一个网关到达目的地时，rt_gateway被设置为由路由项中的下一跳网关。
	 */
	__u32			rt_gateway;

	/* Cache lookup keys */
	/**
	 * 用于缓存查找的搜索key
	 */
	struct flowi		fl;

	/* Miscellaneous cached information */
	/**
	 * RFC 1122中指定的目的地址。
	 */
	__u32			rt_spec_dst; /* RFC1122 specific destination */
	/**
	 * 该缓存路由项的目的IP地址对应的主机。与本地主机在最近一段时间通信的每个远端IP地址都有一个inet_peer结构。
	 */
	struct inet_peer	*peer; /* long-living peer info */
};

/**
 * 该结构被基于路由表的classifier使用，用于跟踪与一个标签（tag）相关联的路由流量的统计信息，该统计信息中包含字节数和报文数两类信息。
 */
struct ip_rt_acct
{
	__u32 	o_bytes;
	__u32 	o_packets;
	__u32 	i_bytes;
	__u32 	i_packets;
};

/**
 * 存储路由查找的统计信息。对每个处理器有该数据结构的一个实例。
 * 不仅仅与路由缓存相关。
 */
struct rt_cache_stat 
{
		/**
		 * 表示已经查找路由缓存成功而被路由的接收报文的数目。
		 */
        unsigned int in_hit;
		/**
		 * in_slow_tot是由于缓存查找失败而需要查找路由表的报文数目，只对查找路由表成功的报文计数。
		 * 也对广播报文计数，但不对多播流量计数。
		 * 多播流量是用in_slow_mc变量来计数。
		 */
        unsigned int in_slow_tot;
        unsigned int in_slow_mc;
		/**
		 * 由于路由表不知道如何到达目的IP地址（只可能在缺省网关没有配置或不可用的情况下才发生）而不能被转发的ingress报文的数目。
		 */
        unsigned int in_no_route;
		/**
		 * 被正确接收（即合理性检查都没有失败）的广播报文的数目。
		 */
        unsigned int in_brd;
		/**
		 * 这两个counters分别表示由于目的IP地址或源IP地址没有通过合理性检查而被丢弃的报文数目。
		 * 合理性检查的例子包括源IP地址不能为多播或广播，目的地址不能属于所谓的零网段，即地址不能为0.n.n.n。
		 */
        unsigned int in_martian_dst;
        unsigned int in_martian_src;
		/**
		 * 表示已经查找路由缓存成功而被路由的发送报文的数目。
		 */
        unsigned int out_hit;
		/**
		 * out_slow_tot和out_slow_mc所起的作用分别与in_slow_tot和in_slow_mc相同，但它们用于egress流量的计数。
		 */
        unsigned int out_slow_tot;
        unsigned int out_slow_mc;
		/**
		 * gc_total跟踪rt_garbage_collect函数被激活的次数。
		 */
        unsigned int gc_total;
		/**
		 * gc_ignored跟踪rt_garbage_collect函数刚被调用不久因而立即退出的次数。
		 */
        unsigned int gc_ignored;
		/**
		 * gc_goal_miss是rt_garbage_collect已经扫描完缓存但没能满足函数开始时所设定的目标的次数。
		 */
        unsigned int gc_goal_miss;
		/**
		 * gc_dst_overflow是gc_garbage_collect函数由于没有将缓存表项数目减少到ip_rt_max_size门限值以下而失败的次数。
		 */
        unsigned int gc_dst_overflow;
		/**
		 * 这两个字段分别由缓存查找程序ip_route_input和__ip_route_output_key更新。
		 * 它们表示已经测试但没有找到匹配的缓存元素数目（不是缓存查找失败次数）。
		 */
        unsigned int in_hlist_search;
        unsigned int out_hlist_search;
};

extern struct rt_cache_stat *rt_cache_stat;
#define RT_CACHE_STAT_INC(field)					  \
		(per_cpu_ptr(rt_cache_stat, _smp_processor_id())->field++)

extern struct ip_rt_acct *ip_rt_acct;

struct in_device;
extern int		ip_rt_init(void);
extern void		ip_rt_redirect(u32 old_gw, u32 dst, u32 new_gw,
				       u32 src, u8 tos, struct net_device *dev);
extern void		ip_rt_advice(struct rtable **rp, int advice);
extern void		rt_cache_flush(int how);
extern int		__ip_route_output_key(struct rtable **, const struct flowi *flp);
extern int		ip_route_output_key(struct rtable **, struct flowi *flp);
extern int		ip_route_output_flow(struct rtable **rp, struct flowi *flp, struct sock *sk, int flags);
extern int		ip_route_input(struct sk_buff*, u32 dst, u32 src, u8 tos, struct net_device *devin);
extern unsigned short	ip_rt_frag_needed(struct iphdr *iph, unsigned short new_mtu);
extern void		ip_rt_send_redirect(struct sk_buff *skb);

extern unsigned		inet_addr_type(u32 addr);
extern void		ip_rt_multicast_event(struct in_device *);
extern int		ip_rt_ioctl(unsigned int cmd, void __user *arg);
extern void		ip_rt_get_source(u8 *src, struct rtable *rt);
extern int		ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb);

static inline void ip_rt_put(struct rtable * rt)
{
	if (rt)
		dst_release(&rt->u.dst);
}

#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

/**
 * 特殊的路由查找函数，用于TCP。
 * 是对普通路由缓存查找函数的封装。
 */
static inline int ip_route_connect(struct rtable **rp, u32 dst,
				   u32 src, u32 tos, int oif, u8 protocol,
				   u16 sport, u16 dport, struct sock *sk)
{
	struct flowi fl = { .oif = oif,
			    .nl_u = { .ip4_u = { .daddr = dst,
						 .saddr = src,
						 .tos   = tos } },
			    .proto = protocol,
			    .uli_u = { .ports =
				       { .sport = sport,
					 .dport = dport } } };

	int err;
	if (!dst || !src) {
		err = __ip_route_output_key(rp, &fl);
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;
		fl.fl4_src = (*rp)->rt_src;
		ip_rt_put(*rp);
		*rp = NULL;
	}
	return ip_route_output_flow(rp, &fl, sk, 0);
}

/**
 * 特殊的路由查找函数，用于TCP。
 * 是对普通路由缓存查找函数的封装。
 */
static inline int ip_route_newports(struct rtable **rp, u16 sport, u16 dport,
				    struct sock *sk)
{
	if (sport != (*rp)->fl.fl_ip_sport ||
	    dport != (*rp)->fl.fl_ip_dport) {
		struct flowi fl;

		memcpy(&fl, &(*rp)->fl, sizeof(fl));
		fl.fl_ip_sport = sport;
		fl.fl_ip_dport = dport;
		ip_rt_put(*rp);
		*rp = NULL;
		return ip_route_output_flow(rp, &fl, sk, 0);
	}
	return 0;
}

extern void rt_bind_peer(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	rt_bind_peer(rt, 0);
	return rt->peer;
}

#endif	/* _ROUTE_H */
