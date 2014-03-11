/* linux/net/inet/arp.c
 *
 * Version:	$Id: arp.c,v 1.99 2001/08/30 22:55:42 davem Exp $
 *
 * Copyright (C) 1994 by Florian  La Roche
 *
 * This module implements the Address Resolution Protocol ARP (RFC 826),
 * which is used to convert IP addresses (or in the future maybe other
 * high-level addresses) into a low-level hardware address (like an Ethernet
 * address).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Fixes:
 *		Alan Cox	:	Removed the Ethernet assumptions in 
 *					Florian's code
 *		Alan Cox	:	Fixed some small errors in the ARP 
 *					logic
 *		Alan Cox	:	Allow >4K in /proc
 *		Alan Cox	:	Make ARP add its own protocol entry
 *		Ross Martin     :       Rewrote arp_rcv() and arp_get_info()
 *		Stephen Henson	:	Add AX25 support to arp_get_info()
 *		Alan Cox	:	Drop data when a device is downed.
 *		Alan Cox	:	Use init_timer().
 *		Alan Cox	:	Double lock fixes.
 *		Martin Seine	:	Move the arphdr structure
 *					to if_arp.h for compatibility.
 *					with BSD based programs.
 *		Andrew Tridgell :       Added ARP netmask code and
 *					re-arranged proxy handling.
 *		Alan Cox	:	Changed to use notifiers.
 *		Niibe Yutaka	:	Reply for this device or proxies only.
 *		Alan Cox	:	Don't proxy across hardware types!
 *		Jonathan Naylor :	Added support for NET/ROM.
 *		Mike Shaver     :       RFC1122 checks.
 *		Jonathan Naylor :	Only lookup the hardware address for
 *					the correct hardware type.
 *		Germano Caronni	:	Assorted subtle races.
 *		Craig Schlenter :	Don't modify permanent entry 
 *					during arp_rcv.
 *		Russ Nelson	:	Tidied up a few bits.
 *		Alexey Kuznetsov:	Major changes to caching and behaviour,
 *					eg intelligent arp probing and 
 *					generation
 *					of host down events.
 *		Alan Cox	:	Missing unlock in device events.
 *		Eckes		:	ARP ioctl control errors.
 *		Alexey Kuznetsov:	Arp free fix.
 *		Manuel Rodriguez:	Gratuitous ARP.
 *              Jonathan Layes  :       Added arpd support through kerneld 
 *                                      message queue (960314)
 *		Mike Shaver	:	/proc/sys/net/ipv4/arp_* support
 *		Mike McLagan    :	Routing by source
 *		Stuart Cheshire	:	Metricom and grat arp fixes
 *					*** FOR 2.1 clean this up ***
 *		Lawrence V. Stefani: (08/12/96) Added FDDI support.
 *		Alan Cox 	:	Took the AP1000 nasty FDDI hack and
 *					folded into the mainstream FDDI code.
 *					Ack spit, Linus how did you allow that
 *					one in...
 *		Jes Sorensen	:	Make FDDI work again in 2.1.x and
 *					clean up the APFDDI & gen. FDDI bits.
 *		Alexey Kuznetsov:	new arp state machine;
 *					now it is in net/core/neighbour.c.
 *		Krzysztof Halasa:	Added Frame Relay ARP support.
 *		Arnaldo C. Melo :	convert /proc/net/arp to seq_file
 *		Shmulik Hen:		Split arp_send to arp_create and
 *					arp_xmit so intermediate drivers like
 *					bonding can change the skb before
 *					sending (e.g. insert 8021q tag).
 *		Harald Welte	:	convert to make use of jenkins hash
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/config.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fddidevice.h>
#include <linux/if_arp.h>
#include <linux/trdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
#include <net/ax25.h>
#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
#include <net/netrom.h>
#endif
#endif
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
#include <net/atmclip.h>
struct neigh_table *clip_tbl_hook;
#endif

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/netfilter_arp.h>

/*
 *	Interface to generic neighbour cache.
 */
static u32 arp_hash(const void *pkey, const struct net_device *dev);
static int arp_constructor(struct neighbour *neigh);
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb);
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb);
static void parp_redo(struct sk_buff *skb);

static struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

static struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

static struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		dev_queue_xmit,
	.connected_output =	dev_queue_xmit,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

struct neigh_ops arp_broken_ops = {
	/**
	 * AF_INET表示ARP和IPV4一起工作。
	 */
	.family =		AF_INET,
	/**
	 * 调用arp_solicit来生成一个solicitation请求，可能是首次解析一个 址，也可能是要证实缓存中的地址。
	 * 在后一种情况中，会由一个定时器的超时触发这个函数。
	 */
	.solicit =		arp_solicit,
	/**
	 * 当一个ARP事务中发生错误时，arp_error_report函数就通知上面的网络层。
	 */
	.error_report =		arp_error_report,
	.output =		neigh_compat_output,
	.connected_output =	neigh_compat_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

/**
 * IPV4邻居协议表。
 */
struct neigh_table arp_tbl = {
	.family =	AF_INET,
	.entry_size =	sizeof(struct neighbour) + 4,
	.key_len =	4,
	.hash =		arp_hash,
	.constructor =	arp_constructor,
	.proxy_redo =	parp_redo,
	.id =		"arp_cache",
	.parms = {
		.tbl =			&arp_tbl,
		/**
		 * ARP只有在最后一个可到达性证据是在最近30秒内收到时，才认为一个邻居项是NUD_REACHABLE态。
		 */
		.base_reachable_time =	30 * HZ,
		/**
		 * 如果没有收到一个solicitation请求的应答，就在1秒后发送一个新的请求。
		 */
		.retrans_time =	1 * HZ,
		.gc_staletime =	60 * HZ,
		.reachable_time =		30 * HZ,
		.delay_probe_time =	5 * HZ,
		.queue_len =		3,
		.ucast_probes =	3,
		.mcast_probes =	3,
		.anycast_delay =	1 * HZ,
		.proxy_delay =		(8 * HZ) / 10,
		.proxy_qlen =		64,
		.locktime =		1 * HZ,
	},
	.gc_interval =	30 * HZ,
	.gc_thresh1 =	128,
	.gc_thresh2 =	512,
	.gc_thresh3 =	1024,
};

/**
 * 从L3多播地址导出L2多播地址。
 */
int arp_mc_map(u32 addr, u8 *haddr, struct net_device *dev, int dir)
{
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		ip_eth_mc_map(addr, haddr);
		return 0; 
	case ARPHRD_IEEE802_TR:
		ip_tr_mc_map(addr, haddr);
		return 0;
	case ARPHRD_INFINIBAND:
		ip_ib_mc_map(addr, haddr);
		return 0;
	default:
		if (dir) {
			memcpy(haddr, dev->broadcast, dev->addr_len);
			return 0;
		}
	}
	return -EINVAL;
}


static u32 arp_hash(const void *pkey, const struct net_device *dev)
{
	return jhash_2words(*(u32 *)pkey, dev->ifindex, arp_tbl.hash_rnd);
}

/**
 * arp_tbl结构定义的，ARP的初始化函数。用来设置neighbour结构。
 */
static int arp_constructor(struct neighbour *neigh)
{
	u32 addr = *(u32*)neigh->primary_key;
	struct net_device *dev = neigh->dev;
	struct in_device *in_dev;
	struct neigh_parms *parms;

	neigh->type = inet_addr_type(addr);

	rcu_read_lock();
	/**
	 * 首要任务是从与邻居相关的网络设备中取出一个in_dev结构。
	 * 这个结构中保存着该网络设备的IP层配置信息，其中也包括ARP的配置信息。
	 */
	in_dev = rcu_dereference(__in_dev_get(dev));
	/**
	 * 如果没有ARP配置信息，该设备也就没有IP配置信息，因此在其上使用ARP也就没有意义。
	 */
	if (in_dev == NULL) {
		rcu_read_unlock();
		return -EINVAL;
	}

	parms = in_dev->arp_parms;
	/**
	 * 要设置新的arp配置信息了，将原arp配置引用计数减1.
	 */
	__neigh_parms_put(neigh->parms);
	/**
	 * 从设备中取出配置信息，并设置给邻居项。
	 */
	neigh->parms = neigh_parms_clone(parms);
	rcu_read_unlock();

	/**
	 * 当没有设置dev->hard_header时，表示设备驱动程序没有提供填充L2帧头的函数。
	 * 也就是说设备不需要L2帧头。
	 */
	if (dev->hard_header == NULL) {/* 点到点设备 */
		/**
		 * 不需要ARP
		 */
		neigh->nud_state = NUD_NOARP;
		/**
		 * 点到点设备，使用arp_direct_ops
		 */
		neigh->ops = &arp_direct_ops;
		neigh->output = neigh->ops->queue_xmit;
		/* 不需要ha，因此不初始化它。 */
	} else {
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */

#if 1
		/* So... these "amateur" devices are hopeless.
		   The only thing, that I can say now:
		   It is very sad that we need to keep ugly obsolete
		   code to make them happy.

		   They should be moved to more reasonable state, now
		   they use rebuild_header INSTEAD OF hard_start_xmit!!!
		   Besides that, they are sort of out of date
		   (a lot of redundant clones/copies, useless in 2.1),
		   I wonder why people believe that they work.
		 */
		switch (dev->type) {
		default:
			break;
		/**
		 * 设备不支持新的邻居基础结构。
		 * 现在，只有业余无线电设备和一些WAN接口卡仍然使用旧驱动程序。
		 * 对于这些设备，neigh->ops会初始化为arp_broken_ops，后者内部包含了基于这些旧程序的虚函数。
		 */
		case ARPHRD_ROSE:	
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
		case ARPHRD_AX25:
#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
		case ARPHRD_NETROM:
#endif
			neigh->ops = &arp_broken_ops;
			neigh->output = neigh->ops->output;
			return 0;
#endif
		;}
#endif
		if (neigh->type == RTN_MULTICAST) {/* L3地址是一个多播地址 */
			/**
			 * 多播地址的L2地址是通过计算得到，不需要ARP。
			 */
			neigh->nud_state = NUD_NOARP;
			/**
			 * 直接计算L2多播地址。
			 */
			arp_mc_map(addr, neigh->ha, dev, 1);
		} else if (dev->flags&(IFF_NOARP|IFF_LOOPBACK)) {/* 设备不需要ARP，或者是环回地址 */
			neigh->nud_state = NUD_NOARP;
			/**
			 * 回环设备（lo）和设置IFF_NOARP标识的设备不需要使用ARP解析地址。
			 * 但是，邻居子系统仍需要一个地址来放到L2帧头中，这些函数就指定一个与该设备相关的地址。
			 */
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);
		} else if (neigh->type == RTN_BROADCAST || dev->flags&IFF_POINTOPOINT) {/* 广播地址或者点到点设备 */
			/**
			 * 不需要ARP。
			 */
			neigh->nud_state = NUD_NOARP;
			/**
			 * 从设备的广播地址中直接复制L2地址。
			 */
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);
		}/* 其他情况不需要设置nud_state，因为邻居基础协议已经设置了默认值。 */

		/**
		 * 根据设备是否支持L2帧头缓存，设置不同的ops.
		 */
		if (dev->hard_header_cache)
			neigh->ops = &arp_hh_ops;
		else
			neigh->ops = &arp_generic_ops;
		/**
		 * 根据指定给nud_state的值来初始化output。
		 */
		if (neigh->nud_state&NUD_VALID)
			neigh->output = neigh->ops->connected_output;
		else
			neigh->output = neigh->ops->output;
	}
	return 0;
}

/**
 * ARP邻居层向上层发送错误事件。
 */
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	/**
	 * 从路由表缓存中删除与不可到达的邻居相关的缓存项。
	 * 用一个ICMP UNREACHABLE消息通知发送方邻居不可到达。
	 */
	dst_link_failure(skb);
	kfree_skb(skb);
}

/**
 * 生成solicitation请求。
 *		neigh：		L3地址需要被解析的邻居。
 *		skb:		保存数据包的缓冲区，该包的传输由solicitation请求的产生触发。
 */
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	u32 saddr = 0;
	u8  *dst_ha = NULL;
	struct net_device *dev = neigh->dev;
	u32 target = *(u32*)neigh->primary_key;
	int probes = atomic_read(&neigh->probes);
	struct in_device *in_dev = in_dev_get(dev);

	if (!in_dev)
		return;

	/**
	 * 判断ARP_ANNOUNCE选项级别
	 */
	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP */
		/**
		 * 默认情况下，如果源地址是本地配置的IP地址，则使用源地址。
		 * 否则在外面使用inet_select_addr选择最佳的源地址。
		 */
		if (skb && inet_addr_type(skb->nh.iph->saddr) == RTN_LOCAL)
			saddr = skb->nh.iph->saddr;
		break;
	case 1:		/* Restrict announcements of saddr in same subnet */
		/**
		 * 优先使用与源地址处于同一子网的地址。
		 */
		if (!skb)
			break;
		saddr = skb->nh.iph->saddr;
		/**
		 * 源地址为本地IP地址，并且源和目的IP在相同子网内。
		 */
		if (inet_addr_type(saddr) == RTN_LOCAL) {
			/* saddr should be known to target */
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		/**
		 * 不在同一子网，清空saddr。外层选择合适的IP。
		 */
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		break;
	}

	if (in_dev)
		in_dev_put(in_dev);
	/**
	 * 如果还没有选择源地址，则选择与源地址在同一个子网内的地址。
	 */
	if (!saddr)
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);

	/**
	 * 对于内核生成的请求，使用arp_send传输solicitation请求
	 */
	if ((probes -= neigh->parms->ucast_probes) < 0) {
		if (!(neigh->nud_state&NUD_VALID))
			printk(KERN_DEBUG "trying to ucast probe in NUD_INVALID\n");
		dst_ha = neigh->ha;
		read_lock_bh(&neigh->lock);
	} else if ((probes -= neigh->parms->app_probes) < 0) {
#ifdef CONFIG_ARPD
		/**
		 * 对于用户空间产生的请求，arp_solicit调用neigh_app_ns来通知相应的用户空间程序：需要生成一个solicitation请求。
		 */
		neigh_app_ns(neigh);
#endif
		return;
	}

	arp_send(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		 dst_ha, dev->dev_addr, NULL);
	if (dst_ha)
		read_unlock_bh(&neigh->lock);
}

static int arp_ignore(struct in_device *in_dev, struct net_device *dev,
		      u32 sip, u32 tip)
{
	int scope;

	switch (IN_DEV_ARP_IGNORE(in_dev)) {
	case 0:	/* Reply, the tip is already validated */
		return 0;
	case 1:	/* Reply only if tip is configured on the incoming interface */
		sip = 0;
		scope = RT_SCOPE_HOST;
		break;
	case 2:	/*
		 * Reply only if tip is configured on the incoming interface
		 * and is in same subnet as sip
		 */
		scope = RT_SCOPE_HOST;
		break;
	case 3:	/* Do not reply for scope host addresses */
		sip = 0;
		scope = RT_SCOPE_LINK;
		dev = NULL;
		break;
	case 4:	/* Reserved */
	case 5:
	case 6:
	case 7:
		return 0;
	case 8:	/* Do not reply */
		return 1;
	default:
		return 0;
	}
	return !inet_confirm_addr(dev, sip, tip, scope);
}

static int arp_filter(__u32 sip, __u32 tip, struct net_device *dev)
{
	struct flowi fl = { .nl_u = { .ip4_u = { .daddr = sip,
						 .saddr = tip } } };
	struct rtable *rt;
	int flag = 0; 
	/*unsigned long now; */

	if (ip_route_output_key(&rt, &fl) < 0) 
		return 1;
	if (rt->u.dst.dev != dev) { 
		NET_INC_STATS_BH(LINUX_MIB_ARPFILTER);
		flag = 1;
	} 
	ip_rt_put(rt); 
	return flag; 
} 

/* OBSOLETE FUNCTIONS */

/*
 *	Find an arp mapping in the cache. If not found, post a request.
 *
 *	It is very UGLY routine: it DOES NOT use skb->dst->neighbour,
 *	even if it exists. It is supposed that skb->dev was mangled
 *	by a virtual device (eql, shaper). Nobody but broken devices
 *	is allowed to use this function, it is scheduled to be removed. --ANK
 */

static int arp_set_predefined(int addr_hint, unsigned char * haddr, u32 paddr, struct net_device * dev)
{
	switch (addr_hint) {
	case RTN_LOCAL:
		printk(KERN_DEBUG "ARP: arp called for own IP address\n");
		memcpy(haddr, dev->dev_addr, dev->addr_len);
		return 1;
	case RTN_MULTICAST:
		arp_mc_map(paddr, haddr, dev, 1);
		return 1;
	case RTN_BROADCAST:
		memcpy(haddr, dev->broadcast, dev->addr_len);
		return 1;
	}
	return 0;
}


int arp_find(unsigned char *haddr, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	u32 paddr;
	struct neighbour *n;

	if (!skb->dst) {
		printk(KERN_DEBUG "arp_find is called with dst==NULL\n");
		kfree_skb(skb);
		return 1;
	}

	paddr = ((struct rtable*)skb->dst)->rt_gateway;

	if (arp_set_predefined(inet_addr_type(paddr), haddr, paddr, dev))
		return 0;

	n = __neigh_lookup(&arp_tbl, &paddr, dev, 1);

	if (n) {
		n->used = jiffies;
		if (n->nud_state&NUD_VALID || neigh_event_send(n, skb) == 0) {
			read_lock_bh(&n->lock);
 			memcpy(haddr, n->ha, dev->addr_len);
			read_unlock_bh(&n->lock);
			neigh_release(n);
			return 0;
		}
		neigh_release(n);
	} else
		kfree_skb(skb);
	return 1;
}

/* END OF OBSOLETE FUNCTIONS */

int arp_bind_neighbour(struct dst_entry *dst)
{
	struct net_device *dev = dst->dev;
	struct neighbour *n = dst->neighbour;

	if (dev == NULL)
		return -EINVAL;
	if (n == NULL) {
		u32 nexthop = ((struct rtable*)dst)->rt_gateway;
		if (dev->flags&(IFF_LOOPBACK|IFF_POINTOPOINT))
			nexthop = 0;
		n = __neigh_lookup_errno(
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
		    dev->type == ARPHRD_ATM ? clip_tbl_hook :
#endif
		    &arp_tbl, &nexthop, dev);
		if (IS_ERR(n))
			return PTR_ERR(n);
		dst->neighbour = n;
	}
	return 0;
}

/*
 * Check if we can use proxy ARP for this path
 */
/**
 * 判断是否需要对某个ARP请求进行代理。
 */
static inline int arp_fwd_proxy(struct in_device *in_dev, struct rtable *rt)
{
	struct in_device *out_dev;
	int imi, omi = -1;

	/**
	 * 入设备没有配置代理。
	 */
	if (!IN_DEV_PROXY_ARP(in_dev))
		return 0;

	/**
	 * Medium ID特性已经被关闭，需要代理。
	 */
	if ((imi = IN_DEV_MEDIUM_ID(in_dev)) == 0)
		return 1;
	/**
	 * ARP代理已经关闭。
	 */
	if (imi == -1)
		return 0;

	/* place to check for proxy_arp for routes */

	/**
	 * 合法的medium ID，比较出设备的medium ID与入设备的medium ID。
	 */
	if ((out_dev = in_dev_get(rt->u.dst.dev)) != NULL) {
		omi = IN_DEV_MEDIUM_ID(out_dev);
		in_dev_put(out_dev);
	}
	/**
	 * 如果medium ID不相等，并且出设备没有禁止代理，则需要代理。
	 */
	return (omi != imi && omi != -1);
}

/*
 *	Interface to link layer: send routine and receive handler.
 */

/*
 *	Create an arp packet. If (dest_hw == NULL), we create a broadcast
 *	message.
 */
struct sk_buff *arp_create(int type, int ptype, u32 dest_ip,
			   struct net_device *dev, u32 src_ip,
			   unsigned char *dest_hw, unsigned char *src_hw,
			   unsigned char *target_hw)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	unsigned char *arp_ptr;

	/*
	 *	Allocate a buffer
	 */
	
	skb = alloc_skb(sizeof(struct arphdr)+ 2*(dev->addr_len+4)
				+ LL_RESERVED_SPACE(dev), GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb->nh.raw = skb->data;
	arp = (struct arphdr *) skb_put(skb,sizeof(struct arphdr) + 2*(dev->addr_len+4));
	skb->dev = dev;
	skb->protocol = htons(ETH_P_ARP);
	if (src_hw == NULL)
		src_hw = dev->dev_addr;
	if (dest_hw == NULL)
		dest_hw = dev->broadcast;

	/*
	 *	Fill the device header for the ARP frame
	 */
	if (dev->hard_header &&
	    dev->hard_header(skb,dev,ptype,dest_hw,src_hw,skb->len) < 0)
		goto out;

	/*
	 * Fill out the arp protocol part.
	 *
	 * The arp hardware type should match the device type, except for FDDI,
	 * which (according to RFC 1390) should always equal 1 (Ethernet).
	 */
	/*
	 *	Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 *	DIX code for the protocol. Make these device structure fields.
	 */
	switch (dev->type) {
	default:
		arp->ar_hrd = htons(dev->type);
		arp->ar_pro = htons(ETH_P_IP);
		break;

#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	case ARPHRD_AX25:
		arp->ar_hrd = htons(ARPHRD_AX25);
		arp->ar_pro = htons(AX25_P_IP);
		break;

#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
	case ARPHRD_NETROM:
		arp->ar_hrd = htons(ARPHRD_NETROM);
		arp->ar_pro = htons(AX25_P_IP);
		break;
#endif
#endif

#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
		arp->ar_hrd = htons(ARPHRD_ETHER);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
#ifdef CONFIG_TR
	case ARPHRD_IEEE802_TR:
		arp->ar_hrd = htons(ARPHRD_IEEE802);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
	}

	arp->ar_hln = dev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(type);

	arp_ptr=(unsigned char *)(arp+1);

	memcpy(arp_ptr, src_hw, dev->addr_len);
	arp_ptr+=dev->addr_len;
	memcpy(arp_ptr, &src_ip,4);
	arp_ptr+=4;
	if (target_hw != NULL)
		memcpy(arp_ptr, target_hw, dev->addr_len);
	else
		memset(arp_ptr, 0, dev->addr_len);
	arp_ptr+=dev->addr_len;
	memcpy(arp_ptr, &dest_ip, 4);

	return skb;

out:
	kfree_skb(skb);
	return NULL;
}

/*
 *	Send an arp packet.
 */
void arp_xmit(struct sk_buff *skb)
{
	/* Send it off, maybe filter it using firewalling first.  */
	NF_HOOK(NF_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);
}

/*
 *	Create and send an arp packet.
 */
/**
 * 传输ARP包。
 * 邻居子系统调用neigh_ops->solicit来发出solicitation请求。
 * 在ARP中，solicit函数（arp_solicit）只是对arp_send的简单封装。
 * Arp_send负责填充ARP包头和包内容，并调用dev_queue_xmit函数传送这个ARP请求。
 */
void arp_send(int type, int ptype, u32 dest_ip, 
	      struct net_device *dev, u32 src_ip, 
	      unsigned char *dest_hw, unsigned char *src_hw,
	      unsigned char *target_hw)
{
	struct sk_buff *skb;

	/*
	 *	No arp on this interface.
	 */
	
	if (dev->flags&IFF_NOARP)
		return;

	/**
	 * 初始化ARP包
	 */
	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);
	if (skb == NULL) {
		return;
	}

	/**
	 * 在netfilter中设置钩子，然后调用dev_queue_xmit函数。
	 * 分成arp_create和arp_xmit，是为了方便驱动程序的编写，可以方便的完成用户定制的任务。
	 */
	arp_xmit(skb);
}

static void parp_redo(struct sk_buff *skb)
{
	nf_reset(skb);
	arp_rcv(skb, skb->dev, NULL);
}

/*
 *	Process an arp request.
 */
/**
 * ARP包的处理函数。
 */
static int arp_process(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct in_device *in_dev = in_dev_get(dev);
	struct arphdr *arp;
	unsigned char *arp_ptr;
	struct rtable *rt;
	unsigned char *sha, *tha;
	u32 sip, tip;
	u16 dev_type = dev->type;
	int addr_type;
	struct neighbour *n;

	/* arp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (in_dev == NULL)
		goto out;

	arp = skb->nh.arph;

	/**
	 * 对所有ARP包类型进行合理性检查，然后根据包类型执行相应的操作。
	 * 某些设备类型，只有编译内核时明确指定支持它们，内核才会支持。
	 * 它们不属于默认设备，因为不会经常使用。
	 * 因此内核开发者决定将对它们的支持设为可选项，以减少内核的大小。
	 */
	switch (dev_type) {
	default:	
		if (arp->ar_pro != htons(ETH_P_IP) ||
		    htons(dev_type) != arp->ar_hrd)
			goto out;
		break;
#ifdef CONFIG_NET_ETHERNET
	case ARPHRD_ETHER:
#endif
#ifdef CONFIG_TR
	case ARPHRD_IEEE802_TR:
#endif
#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
#endif
#ifdef CONFIG_NET_FC
	case ARPHRD_IEEE802:
#endif
#if defined(CONFIG_NET_ETHERNET) || defined(CONFIG_TR) || \
    defined(CONFIG_FDDI)	 || defined(CONFIG_NET_FC)
		/*
		 * ETHERNET, Token Ring and Fibre Channel (which are IEEE 802
		 * devices, according to RFC 2625) devices will accept ARP
		 * hardware types of either 1 (Ethernet) or 6 (IEEE 802.2).
		 * This is the case also of FDDI, where the RFC 1390 says that
		 * FDDI devices should accept ARP hardware of (1) Ethernet,
		 * however, to be more robust, we'll accept both 1 (Ethernet)
		 * or 6 (IEEE 802.2)
		 */
		if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
		     arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
		    arp->ar_pro != htons(ETH_P_IP))
			goto out;
		break;
#endif
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	case ARPHRD_AX25:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_AX25))
			goto out;
		break;
#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
	case ARPHRD_NETROM:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_NETROM))
			goto out;
		break;
#endif
#endif
	}

	/* Understand only these message types */

	if (arp->ar_op != htons(ARPOP_REPLY) &&
	    arp->ar_op != htons(ARPOP_REQUEST))
		goto out;

/*
 *	Extract fields
 */
 	/**
 	 * arp_ptr指向硬件头的末尾。
 	 */
	arp_ptr= (unsigned char *)(arp+1);
	/**
	 * 发送方ethernet地址
	 */
	sha	= arp_ptr;
	arp_ptr += dev->addr_len;
	/**
	 * 发送方IP地址
	 */
	memcpy(&sip, arp_ptr, 4);
	arp_ptr += 4;
	/**
	 * 目的ethernet地址
	 */
	tha	= arp_ptr;
	arp_ptr += dev->addr_len;
	/**
	 * 目的IP地址
	 */
	memcpy(&tip, arp_ptr, 4);
/* 
 *	Check for bad requests for 127.x.x.x and requests for multicast
 *	addresses.  If this is one such, delete it.
 */
 	/**
 	 * 对多播IP地址和回环IP地址的请求会被丢弃，因为它们是不合规定的。
 	 */
	if (LOOPBACK(tip) || MULTICAST(tip))
		goto out;

/*
 *     Special case: We must set Frame Relay source Q.922 address
 */
	if (dev_type == ARPHRD_DLCI)
		sha = dev->broadcast;

/*
 *  Process entry.  The idea here is we want to send a reply if it is a
 *  request for us or if it is a request for someone else that we hold
 *  a proxy for.  We want to add an entry to our cache if it is a reply
 *  to us or if it is a request for our address.  
 *  (The assumption for this last is that if someone is requesting our 
 *  address, they are probably intending to talk to us, so it saves time 
 *  if we cache their address.  Their address is also probably not in 
 *  our cache, since ours is not in their cache.)
 * 
 *  Putting this another way, we only care about replies if they are to
 *  us, in which case we add them to the cache.  For requests, we care
 *  about those for us and those for our proxies.  We reply to both,
 *  and in the case of requests for us we add the requester to the arp 
 *  cache.
 */

	/* Special case: IPv4 duplicate address detection packet (RFC2131) */
	if (sip == 0) {/* IP重复地址检测，发送应答 */
		if (arp->ar_op == htons(ARPOP_REQUEST) &&
		    inet_addr_type(tip) == RTN_LOCAL &&
		    !arp_ignore(in_dev,dev,sip,tip))
			arp_send(ARPOP_REPLY,ETH_P_ARP,tip,dev,tip,sha,dev->dev_addr,dev->dev_addr);
		goto out;
	}

	if (arp->ar_op == htons(ARPOP_REQUEST) &&
	    ip_route_input(skb, tip, sip, 0, dev) == 0) {/* 在路由表中，有一条到该地址的有效路由 */

		rt = (struct rtable*)skb->dst;
		addr_type = rt->rt_type;

		if (addr_type == RTN_LOCAL) {/*  	请求的地址属于本地系统 */
			/**
			 * 首先进行被动学习。
			 * neigh_event_ns会检查是否有一个邻居项和请求者相关联；然后就会更新这个存在的邻居项。
			 * 当不存在时，就会创建一个新的邻居项。
			 * 不管是更新存在的邻居项，还是创建新的候项，该函数都要将邻居状态设为NUD_STALE态(不是NUD_REACHABLE态)。
			 */
			n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
			if (n) {
				int dont_send = 0;

				/**
				 * 根据proc设置，判断是否能够向源地址发送ARP。
				 */
				if (!dont_send)
					dont_send |= arp_ignore(in_dev,dev,sip,tip);
				if (!dont_send && IN_DEV_ARPFILTER(in_dev))
					dont_send |= arp_filter(sip,tip,dev); 
				/**
				 * 没有明确的配置为不允许发送ARP包，则向源地址回送ARP报文。
				 */
				if (!dont_send)
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);

				neigh_release(n);
			}
			goto out;
		} else if (IN_DEV_FORWARD(in_dev)) {/* 请求的地址不属于本地系统，因此判断入设备是否允许转发，以处理ARP代理。 */
			if ((rt->rt_flags&RTCF_DNAT) || /* 在接收包的设备上启动了转发功能。 */
			    (addr_type == RTN_UNICAST  && rt->u.dst.dev != dev && /* 目标IP地址是单播地址。收到这个请求的设备不是到达目的IP地址要使用的设备（否则，目的主机自己会应答） */
			     (arp_fwd_proxy(in_dev, rt) || pneigh_lookup(&arp_tbl, &tip, dev, 0)))) {/* 代理服务器设备上启动了转发功能，并且入设备和出设备不是同一个medium ID。代理过的地址数据库有目的地址，并且通过pneigh_lookup进行查询。 */
				/**
				 * 先进行被动学习。创建或更新发送IP对应的neighbour结构。
				 */
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				/**
				 * 释放被动学习对n的引用。
				 */
				if (n)
					neigh_release(n);

				/**
				 * 代理请求可能被延迟，这是为了防止网络流量突然增加。
				 */
				if (skb->stamp.tv_sec == LOCALLY_ENQUEUED || /* 包来自代理队列。 */
				    skb->pkt_type == PACKET_HOST || /* 包不是来自另一个主机。 */
				    in_dev->arp_parms->proxy_delay == 0) { /* 没有配置延迟处理。 */
				    /**
				     * 立即处理该包。
				     */
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);
				} else {/* 否则延迟处理。 */
					/**
					 * 将包放到代理队列。
					 */
					pneigh_enqueue(&arp_tbl, in_dev->arp_parms, skb);
					in_dev_put(in_dev);
					return 0;
				}
				goto out;
			}
		}
	}/* ARPOP_REQUEST和ARPOP_REPLY类型的包都由arp_process进行处理的。其他任何类型的包都被丢弃。 */

	/* Update our ARP tables */

	n = __neigh_lookup(&arp_tbl, &sip, dev, 0);

#ifdef CONFIG_IP_ACCEPT_UNSOLICITED_ARP
	/* Unsolicited ARP is not accepted by default.
	   It is possible, that this option should be enabled for some
	   devices (strip is candidate)
	 */
	/**
	 * 内核支持无端ARP。如果此时还不存在邻居项，就强制创建一个。
	 */
	if (n == NULL &&
	    arp->ar_op == htons(ARPOP_REPLY) &&
	    inet_addr_type(sip) == RTN_UNICAST)/* 源地址与本机处于同一个子网内 */
		n = __neigh_lookup(&arp_tbl, &sip, dev, -1);
#endif

	if (n) {
		int state = NUD_REACHABLE;
		int override;

		/* If several different ARP replies follows back-to-back,
		   use the FIRST one. It is possible, if several proxy
		   agents are active. Taking the first reply prevents
		   arp trashing and chooses the fastest router.
		 */
		/**
		 * 计算锁定期，在连续收到多个ARPOP_REPLY时，确保只对第一个包进行处理。
		 */
		override = time_after(jiffies, n->updated + n->parms->locktime);

		/* Broadcast replies and request packets
		   do not assert neighbour reachability.
		 */
		if (arp->ar_op != htons(ARPOP_REPLY) ||/* 无端ARP，将状态设置成NUD_STALE */
		    skb->pkt_type != PACKET_HOST)    /* 单播应答（PACKET_HOST）会设置邻居为NUD_REACHABLE态，而广播应答则是设为NUD_STALE态。 */
			state = NUD_STALE;
		/**
		 * 更新ARP缓存（如果对应的缓存项没有被锁定）。
		 */
		neigh_update(n, sha, state, override ? NEIGH_UPDATE_F_OVERRIDE : 0);
		neigh_release(n);
	}

out:
	if (in_dev)
		in_dev_put(in_dev);
	kfree_skb(skb);
	return 0;
}


/*
 *	Receive an arp request from the device layer.
 */
/**
 * 处理ARP包。可以被netfilter控制。
 */
int arp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
	struct arphdr *arp;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	/**
	 * 调用通用函数pskb_may_pull来保证在主缓冲区中有足够的空间，这些用于存放ARP包头和负载。
	 */
	if (!pskb_may_pull(skb, (sizeof(struct arphdr) +
				 (2 * dev->addr_len) +
				 (2 * sizeof(u32)))))
		goto freeskb;

	/**
	 * 以下进行包完整性检查。
	 */
	arp = skb->nh.arph;
	if (arp->ar_hln != dev->addr_len || /* 接收到的是一个碎包。 */
	    dev->flags & IFF_NOARP ||   /* 收到包的设备是没有使用ARP协议的设备（也就是说，有IFF_NOARP标识）。 */
	    skb->pkt_type == PACKET_OTHERHOST || /*  	包的目的地址不是收到该包的接口（目的地址不是接口的地址或者广播地址）。 */
	    skb->pkt_type == PACKET_LOOPBACK || /* 回环接口接收到的包 */
	    arp->ar_pln != 4)
		goto freeskb;

	/**
	 * 当缓冲区被共享时（其他程序可以对其使用），arp_rcv将用skb_share_check函数克隆一个缓冲区。
	 * 克隆是很有必要的，因为当处理ARP包时，要保证没有人会改变skb的内容，特别是skb的头指针。
	 */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		goto out_of_mem;

	/**
	 * 一旦入ARP包已经准备进行处理，假设netfilter没有拦截它，arp_process函数就会负责处理。
	 */
	return NF_HOOK(NF_ARP, NF_ARP_IN, skb, dev, NULL, arp_process);

freeskb:
	kfree_skb(skb);
out_of_mem:
	return 0;
}

/*
 *	User level interface (ioctl)
 */

/*
 *	Set (create) an ARP cache entry.
 */

static int arp_req_set(struct arpreq *r, struct net_device * dev)
{
	u32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;
	int err;

	if (r->arp_flags&ATF_PUBL) {
		u32 mask = ((struct sockaddr_in *) &r->arp_netmask)->sin_addr.s_addr;
		if (mask && mask != 0xFFFFFFFF)
			return -EINVAL;
		if (!dev && (r->arp_flags & ATF_COM)) {
			dev = dev_getbyhwaddr(r->arp_ha.sa_family, r->arp_ha.sa_data);
			if (!dev)
				return -ENODEV;
		}
		if (mask) {
			if (pneigh_lookup(&arp_tbl, &ip, dev, 1) == NULL)
				return -ENOBUFS;
			return 0;
		}
		if (dev == NULL) {
			ipv4_devconf.proxy_arp = 1;
			return 0;
		}
		if (__in_dev_get(dev)) {
			__in_dev_get(dev)->cnf.proxy_arp = 1;
			return 0;
		}
		return -ENXIO;
	}

	if (r->arp_flags & ATF_PERM)
		r->arp_flags |= ATF_COM;
	if (dev == NULL) {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = ip,
							 .tos = RTO_ONLINK } } };
		struct rtable * rt;
		if ((err = ip_route_output_key(&rt, &fl)) != 0)
			return err;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	switch (dev->type) {
#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
		/*
		 * According to RFC 1390, FDDI devices should accept ARP
		 * hardware types of 1 (Ethernet).  However, to be more
		 * robust, we'll accept hardware types of either 1 (Ethernet)
		 * or 6 (IEEE 802.2).
		 */
		if (r->arp_ha.sa_family != ARPHRD_FDDI &&
		    r->arp_ha.sa_family != ARPHRD_ETHER &&
		    r->arp_ha.sa_family != ARPHRD_IEEE802)
			return -EINVAL;
		break;
#endif
	default:
		if (r->arp_ha.sa_family != dev->type)
			return -EINVAL;
		break;
	}

	neigh = __neigh_lookup_errno(&arp_tbl, &ip, dev);
	err = PTR_ERR(neigh);
	if (!IS_ERR(neigh)) {
		unsigned state = NUD_STALE;
		if (r->arp_flags & ATF_PERM)
			state = NUD_PERMANENT;
		err = neigh_update(neigh, (r->arp_flags&ATF_COM) ?
				   r->arp_ha.sa_data : NULL, state, 
				   NEIGH_UPDATE_F_OVERRIDE|
				   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
	}
	return err;
}

static unsigned arp_state_to_flags(struct neighbour *neigh)
{
	unsigned flags = 0;
	if (neigh->nud_state&NUD_PERMANENT)
		flags = ATF_PERM|ATF_COM;
	else if (neigh->nud_state&NUD_VALID)
		flags = ATF_COM;
	return flags;
}

/*
 *	Get an ARP cache entry.
 */

static int arp_req_get(struct arpreq *r, struct net_device *dev)
{
	u32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;
	int err = -ENXIO;

	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		read_lock_bh(&neigh->lock);
		memcpy(r->arp_ha.sa_data, neigh->ha, dev->addr_len);
		r->arp_flags = arp_state_to_flags(neigh);
		read_unlock_bh(&neigh->lock);
		r->arp_ha.sa_family = dev->type;
		strlcpy(r->arp_dev, dev->name, sizeof(r->arp_dev));
		neigh_release(neigh);
		err = 0;
	}
	return err;
}

static int arp_req_delete(struct arpreq *r, struct net_device * dev)
{
	int err;
	u32 ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;

	if (r->arp_flags & ATF_PUBL) {
		u32 mask =
		       ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;
		if (mask == 0xFFFFFFFF)
			return pneigh_delete(&arp_tbl, &ip, dev);
		if (mask == 0) {
			if (dev == NULL) {
				ipv4_devconf.proxy_arp = 0;
				return 0;
			}
			if (__in_dev_get(dev)) {
				__in_dev_get(dev)->cnf.proxy_arp = 0;
				return 0;
			}
			return -ENXIO;
		}
		return -EINVAL;
	}

	if (dev == NULL) {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = ip,
							 .tos = RTO_ONLINK } } };
		struct rtable * rt;
		if ((err = ip_route_output_key(&rt, &fl)) != 0)
			return err;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	err = -ENXIO;
	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		if (neigh->nud_state&~NUD_NOARP)
			err = neigh_update(neigh, NULL, NUD_FAILED, 
					   NEIGH_UPDATE_F_OVERRIDE|
					   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
	}
	return err;
}

/*
 *	Handle an ARP layer I/O control request.
 */

int arp_ioctl(unsigned int cmd, void __user *arg)
{
	int err;
	struct arpreq r;
	struct net_device *dev = NULL;

	switch (cmd) {
		case SIOCDARP:
		case SIOCSARP:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
		case SIOCGARP:
			err = copy_from_user(&r, arg, sizeof(struct arpreq));
			if (err)
				return -EFAULT;
			break;
		default:
			return -EINVAL;
	}

	if (r.arp_pa.sa_family != AF_INET)
		return -EPFNOSUPPORT;

	if (!(r.arp_flags & ATF_PUBL) &&
	    (r.arp_flags & (ATF_NETMASK|ATF_DONTPUB)))
		return -EINVAL;
	if (!(r.arp_flags & ATF_NETMASK))
		((struct sockaddr_in *)&r.arp_netmask)->sin_addr.s_addr =
							   htonl(0xFFFFFFFFUL);
	rtnl_lock();
	if (r.arp_dev[0]) {
		err = -ENODEV;
		if ((dev = __dev_get_by_name(r.arp_dev)) == NULL)
			goto out;

		/* Mmmm... It is wrong... ARPHRD_NETROM==0 */
		if (!r.arp_ha.sa_family)
			r.arp_ha.sa_family = dev->type;
		err = -EINVAL;
		if ((r.arp_flags & ATF_COM) && r.arp_ha.sa_family != dev->type)
			goto out;
	} else if (cmd == SIOCGARP) {
		err = -ENODEV;
		goto out;
	}

	switch(cmd) {
	case SIOCDARP:
	        err = arp_req_delete(&r, dev);
		break;
	case SIOCSARP:
		err = arp_req_set(&r, dev);
		break;
	case SIOCGARP:
		err = arp_req_get(&r, dev);
		if (!err && copy_to_user(arg, &r, sizeof(r)))
			err = -EFAULT;
		break;
	}
out:
	rtnl_unlock();
	return err;
}

/**
 * ARP处理设备事件通知。
 */
static int arp_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	switch (event) {
	case NETDEV_CHANGEADDR:/* 仅仅对网络设备L2地址改变事件感兴趣。它更新邻居表。 */
		neigh_changeaddr(&arp_tbl, dev);
		/**
		 * 为了强制让IP层使用新的L2地址，rt_cache_flush函数会刷新IPV4的路由表。
		 * 该函数不是有选择地删除与产生通知的设备关联的缓存项，而是完全清除整个缓存。
		 */
		rt_cache_flush(0);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block arp_netdev_notifier = {
	.notifier_call = arp_netdev_event,
};

/* Note, that it is not on notifier chain.
   It is necessary, that this routine was called after route cache will be
   flushed.
 */
void arp_ifdown(struct net_device *dev)
{
	neigh_ifdown(&arp_tbl, dev);
}


/*
 *	Called once on startup.
 */

static struct packet_type arp_packet_type = {
	.type =	__constant_htons(ETH_P_ARP),
	.func =	arp_rcv,
};

static int arp_proc_init(void);

/**
 * ARP初始化。
 */
void __init arp_init(void)
{
	/**
	 * 用neigh_table_init函数初始化neigh_table结构。
	 */
	neigh_table_init(&arp_tbl);

	/**
	 * IPV4为ARP协议注册arp_rcv函数。
	 */
	dev_add_pack(&arp_packet_type);
	/**
	 * 在需要的时候（通常由管理员设置），在/proc文件系统中注册一组变量。
	 * 建立/proc/net/arp文件，读取该文件就可以看到ARP缓存的内容。
	 */
	arp_proc_init();
#ifdef CONFIG_SYSCTL
	/**
	 * 如果内核支持sysctl，就能依靠函数neigh_sysctl_register创建一个目录/proc/sys/net/ipv4/neigh，用于输出neigh_parms结构的默认调节参数。
	 * 注意，neigh_sysctl_register函数的第一个输入参数为NULL，表示调用函数想注册为默认目录。
	 */
	neigh_sysctl_register(NULL, &arp_tbl.parms, NET_IPV4,
			      NET_IPV4_NEIGH, "ipv4", NULL);
#endif
	/**
	 * 向内核注册一个回调函数，用于接收设备状态和配置变化的通知。
	 */
	register_netdevice_notifier(&arp_netdev_notifier);
}

#ifdef CONFIG_PROC_FS
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)

/* ------------------------------------------------------------------------ */
/*
 *	ax25 -> ASCII conversion
 */
static char *ax2asc2(ax25_address *a, char *buf)
{
	char c, *s;
	int n;

	for (n = 0, s = buf; n < 6; n++) {
		c = (a->ax25_call[n] >> 1) & 0x7F;

		if (c != ' ') *s++ = c;
	}
	
	*s++ = '-';

	if ((n = ((a->ax25_call[6] >> 1) & 0x0F)) > 9) {
		*s++ = '1';
		n -= 10;
	}
	
	*s++ = n + '0';
	*s++ = '\0';

	if (*buf == '\0' || *buf == '-')
	   return "*";

	return buf;

}
#endif /* CONFIG_AX25 */

#define HBUFFERLEN 30

static void arp_format_neigh_entry(struct seq_file *seq,
				   struct neighbour *n)
{
	char hbuffer[HBUFFERLEN];
	const char hexbuf[] = "0123456789ABCDEF";
	int k, j;
	char tbuf[16];
	struct net_device *dev = n->dev;
	int hatype = dev->type;

	read_lock(&n->lock);
	/* Convert hardware address to XX:XX:XX:XX ... form. */
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	if (hatype == ARPHRD_AX25 || hatype == ARPHRD_NETROM)
		ax2asc2((ax25_address *)n->ha, hbuffer);
	else {
#endif
	for (k = 0, j = 0; k < HBUFFERLEN - 3 && j < dev->addr_len; j++) {
		hbuffer[k++] = hexbuf[(n->ha[j] >> 4) & 15];
		hbuffer[k++] = hexbuf[n->ha[j] & 15];
		hbuffer[k++] = ':';
	}
	hbuffer[--k] = 0;
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	}
#endif
	sprintf(tbuf, "%u.%u.%u.%u", NIPQUAD(*(u32*)n->primary_key));
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);
	read_unlock(&n->lock);
}

static void arp_format_pneigh_entry(struct seq_file *seq,
				    struct pneigh_entry *n)
{
	struct net_device *dev = n->dev;
	int hatype = dev ? dev->type : 0;
	char tbuf[16];

	sprintf(tbuf, "%u.%u.%u.%u", NIPQUAD(*(u32*)n->key));
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, ATF_PUBL | ATF_PERM, "00:00:00:00:00:00",
		   dev ? dev->name : "*");
}

static int arp_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "IP address       HW type     Flags       "
			      "HW address            Mask     Device\n");
	} else {
		struct neigh_seq_state *state = seq->private;

		if (state->flags & NEIGH_SEQ_IS_PNEIGH)
			arp_format_pneigh_entry(seq, v);
		else
			arp_format_neigh_entry(seq, v);
	}

	return 0;
}

static void *arp_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* Don't want to confuse "arp -a" w/ magic entries,
	 * so we tell the generic iterator to skip NUD_NOARP.
	 */
	return neigh_seq_start(seq, pos, &arp_tbl, NEIGH_SEQ_SKIP_NOARP);
}

/* ------------------------------------------------------------------------ */

static struct seq_operations arp_seq_ops = {
	.start  = arp_seq_start,
	.next   = neigh_seq_next,
	.stop   = neigh_seq_stop,
	.show   = arp_seq_show,
};

static int arp_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct neigh_seq_state *s = kmalloc(sizeof(*s), GFP_KERNEL);
       
	if (!s)
		goto out;

	memset(s, 0, sizeof(*s));
	rc = seq_open(file, &arp_seq_ops);
	if (rc)
		goto out_kfree;

	seq	     = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

static struct file_operations arp_seq_fops = {
	.owner		= THIS_MODULE,
	.open           = arp_seq_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release	= seq_release_private,
};

static int __init arp_proc_init(void)
{
	if (!proc_net_fops_create("arp", S_IRUGO, &arp_seq_fops))
		return -ENOMEM;
	return 0;
}

#else /* CONFIG_PROC_FS */

static int __init arp_proc_init(void)
{
	return 0;
}

#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(arp_broken_ops);
EXPORT_SYMBOL(arp_find);
EXPORT_SYMBOL(arp_rcv);
EXPORT_SYMBOL(arp_create);
EXPORT_SYMBOL(arp_xmit);
EXPORT_SYMBOL(arp_send);
EXPORT_SYMBOL(arp_tbl);

#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
EXPORT_SYMBOL(clip_tbl_hook);
#endif
