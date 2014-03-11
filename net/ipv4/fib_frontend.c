/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: FIB frontend.
 *
 * Version:	$Id: fib_frontend.c,v 1.26 2001/10/31 21:55:54 davem Exp $
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/init.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/icmp.h>
#include <net/arp.h>
#include <net/ip_fib.h>

#define FFprint(a...) printk(KERN_DEBUG a)

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define RT_TABLE_MIN RT_TABLE_MAIN

/**
 * 内核将到本地地址的路由表项放在该表中，包括到相关的网段地址以及网段广播地址的路由表项。
 */
struct fib_table *ip_fib_local_table;
/**
 * 所有其他的路由表项（包括用户配置的静态路由表项，路由协议生成的动态路由表项）都放在该表内。
 */
struct fib_table *ip_fib_main_table;

#else

#define RT_TABLE_MIN 1
/**
 * 在支持策略路由情况下，指向255个路由表的指针被存储在fib_tables数组内
 */
struct fib_table *fib_tables[RT_TABLE_MAX+1];

struct fib_table *__fib_new_table(int id)
{
	struct fib_table *tb;

	tb = fib_hash_init(id);
	if (!tb)
		return NULL;
	fib_tables[id] = tb;
	return tb;
}


#endif /* CONFIG_IP_MULTIPLE_TABLES */

/**
 * 扫描ip_fib_main_table与ip_fib_local_table路由表，删除所有的设置有RTNH_F_DEAD 标志的fib_info结构。
 * 它既删除fib_info结构，也删除相关联的fib_alias结构。
 * 当一个fib_node实例不再有fib_alias结构时，该fib_node实例也被删除。
 * 当内核支持多路径时，fib_flush扫描所有的路由表。
 */
static void fib_flush(void)
{
	int flushed = 0;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_table *tb;
	int id;

	for (id = RT_TABLE_MAX; id>0; id--) {
		if ((tb = fib_get_table(id))==NULL)
			continue;
		flushed += tb->tb_flush(tb);
	}
#else /* CONFIG_IP_MULTIPLE_TABLES */
	flushed += ip_fib_main_table->tb_flush(ip_fib_main_table);
	flushed += ip_fib_local_table->tb_flush(ip_fib_local_table);
#endif /* CONFIG_IP_MULTIPLE_TABLES */

	if (flushed)
		rt_cache_flush(-1);
}

/*
 *	Find the first device with a given source address.
 */

struct net_device * ip_dev_find(u32 addr)
{
	struct flowi fl = { .nl_u = { .ip4_u = { .daddr = addr } } };
	struct fib_result res;
	struct net_device *dev = NULL;

#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif

	if (!ip_fib_local_table ||
	    ip_fib_local_table->tb_lookup(ip_fib_local_table, &fl, &res))
		return NULL;
	if (res.type != RTN_LOCAL)
		goto out;
	dev = FIB_RES_DEV(res);

	if (dev)
		dev_hold(dev);
out:
	fib_res_put(&res);
	return dev;
}
/**
 * 确定一个L3地址是一个单播、广播和多播地址。
 */
unsigned inet_addr_type(u32 addr)
{
	struct flowi		fl = { .nl_u = { .ip4_u = { .daddr = addr } } };
	struct fib_result	res;
	unsigned ret = RTN_BROADCAST;

	if (ZERONET(addr) || BADCLASS(addr))
		return RTN_BROADCAST;
	if (MULTICAST(addr))
		return RTN_MULTICAST;

#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif
	
	if (ip_fib_local_table) {
		ret = RTN_UNICAST;
		if (!ip_fib_local_table->tb_lookup(ip_fib_local_table,
						   &fl, &res)) {
			ret = res.type;
			fib_res_put(&res);
		}
	}
	return ret;
}

/* Given (packet source, input interface) and optional (dst, oif, tos):
   - (main) check, that source is valid i.e. not broadcast or our local
     address.
   - figure out what "logical" interface this packet arrived
     and calculate "specific destination" address.
   - check, that packet arrived from expected physical interface.
 */

/**
 * 对从一个给定设备接收到的报文的源IP地址检验，检测企图的IP欺骗。
 * 而且还要在使能非对称路由情况下，确保报文的源IP地址通过该报文接收接口是可达的
 */
int fib_validate_source(u32 src, u32 dst, u8 tos, int oif,
			struct net_device *dev, u32 *spec_dst, u32 *itag)
{
	struct in_device *in_dev;
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = src,
					.saddr = dst,
					.tos = tos } },
			    .iif = oif };
	struct fib_result res;
	int no_addr, rpf;
	int ret;

	no_addr = rpf = 0;
	rcu_read_lock();
	in_dev = __in_dev_get(dev);
	if (in_dev) {
		no_addr = in_dev->ifa_list == NULL;
		rpf = IN_DEV_RPFILTER(in_dev);
	}
	rcu_read_unlock();

	if (in_dev == NULL)
		goto e_inval;

	if (fib_lookup(&fl, &res))
		goto last_resort;
	if (res.type != RTN_UNICAST)
		goto e_inval_res;
	*spec_dst = FIB_RES_PREFSRC(res);
	fib_combine_itag(itag, &res);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (FIB_RES_DEV(res) == dev || res.fi->fib_nhs > 1)
#else
	if (FIB_RES_DEV(res) == dev)
#endif
	{
		ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
		fib_res_put(&res);
		return ret;
	}
	fib_res_put(&res);
	if (no_addr)
		goto last_resort;
	if (rpf)
		goto e_inval;
	fl.oif = dev->ifindex;

	ret = 0;
	if (fib_lookup(&fl, &res) == 0) {
		if (res.type == RTN_UNICAST) {
			*spec_dst = FIB_RES_PREFSRC(res);
			ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
		}
		fib_res_put(&res);
	}
	return ret;

last_resort:
	if (rpf)
		goto e_inval;
	*spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
	*itag = 0;
	return 0;

e_inval_res:
	fib_res_put(&res);
e_inval:
	return -EINVAL;
}

#ifndef CONFIG_IP_NOSIOCRT

/*
 *	Handle IP routing ioctl calls. These are used to manipulate the routing tables
 */
 
int ip_rt_ioctl(unsigned int cmd, void __user *arg)
{
	int err;
	struct kern_rta rta;
	struct rtentry  r;
	struct {
		struct nlmsghdr nlh;
		struct rtmsg	rtm;
	} req;

	switch (cmd) {
	case SIOCADDRT:		/* Add a route */
	case SIOCDELRT:		/* Delete a route */
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&r, arg, sizeof(struct rtentry)))
			return -EFAULT;
		rtnl_lock();
		err = fib_convert_rtentry(cmd, &req.nlh, &req.rtm, &rta, &r);
		if (err == 0) {
			if (cmd == SIOCDELRT) {
				struct fib_table *tb = fib_get_table(req.rtm.rtm_table);
				err = -ESRCH;
				if (tb)
					err = tb->tb_delete(tb, &req.rtm, &rta, &req.nlh, NULL);
			} else {
				struct fib_table *tb = fib_new_table(req.rtm.rtm_table);
				err = -ENOBUFS;
				if (tb)
					err = tb->tb_insert(tb, &req.rtm, &rta, &req.nlh, NULL);
			}
			if (rta.rta_mx)
				kfree(rta.rta_mx);
		}
		rtnl_unlock();
		return err;
	}
	return -EINVAL;
}

#else

int ip_rt_ioctl(unsigned int cmd, void *arg)
{
	return -EINVAL;
}

#endif

static int inet_check_attr(struct rtmsg *r, struct rtattr **rta)
{
	int i;

	for (i=1; i<=RTA_MAX; i++) {
		struct rtattr *attr = rta[i-1];
		if (attr) {
			if (RTA_PAYLOAD(attr) < 4)
				return -EINVAL;
			if (i != RTA_MULTIPATH && i != RTA_METRICS)
				rta[i-1] = (struct rtattr*)RTA_DATA(attr);
		}
	}
	return 0;
}

int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct fib_table * tb;
	struct rtattr **rta = arg;
	struct rtmsg *r = NLMSG_DATA(nlh);

	if (inet_check_attr(r, rta))
		return -EINVAL;

	tb = fib_get_table(r->rtm_table);
	if (tb)
		return tb->tb_delete(tb, r, (struct kern_rta*)rta, nlh, &NETLINK_CB(skb));
	return -ESRCH;
}

int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct fib_table * tb;
	struct rtattr **rta = arg;
	struct rtmsg *r = NLMSG_DATA(nlh);

	if (inet_check_attr(r, rta))
		return -EINVAL;

	tb = fib_new_table(r->rtm_table);
	if (tb)
		return tb->tb_insert(tb, r, (struct kern_rta*)rta, nlh, &NETLINK_CB(skb));
	return -ENOBUFS;
}

int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	int t;
	int s_t;
	struct fib_table *tb;

	if (NLMSG_PAYLOAD(cb->nlh, 0) >= sizeof(struct rtmsg) &&
	    ((struct rtmsg*)NLMSG_DATA(cb->nlh))->rtm_flags&RTM_F_CLONED)
		return ip_rt_dump(skb, cb);

	s_t = cb->args[0];
	if (s_t == 0)
		s_t = cb->args[0] = RT_TABLE_MIN;

	for (t=s_t; t<=RT_TABLE_MAX; t++) {
		if (t < s_t) continue;
		if (t > s_t)
			memset(&cb->args[1], 0, sizeof(cb->args)-sizeof(cb->args[0]));
		if ((tb = fib_get_table(t))==NULL)
			continue;
		if (tb->tb_dump(tb, skb, cb) < 0) 
			break;
	}

	cb->args[0] = t;

	return skb->len;
}

/* Prepare and feed intra-kernel routing request.
   Really, it should be netlink message, but :-( netlink
   can be not configured, so that we feed it directly
   to fib engine. It is legal, because all events occur
   only when netlink is already locked.
 */

static void fib_magic(int cmd, int type, u32 dst, int dst_len, struct in_ifaddr *ifa)
{
	struct fib_table * tb;
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	rtm;
	} req;
	struct kern_rta rta;

	memset(&req.rtm, 0, sizeof(req.rtm));
	memset(&rta, 0, sizeof(rta));

	if (type == RTN_UNICAST)
		tb = fib_new_table(RT_TABLE_MAIN);
	else
		tb = fib_new_table(RT_TABLE_LOCAL);

	if (tb == NULL)
		return;

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = cmd;
	req.nlh.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_APPEND;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 0;

	req.rtm.rtm_dst_len = dst_len;
	req.rtm.rtm_table = tb->tb_id;
	req.rtm.rtm_protocol = RTPROT_KERNEL;
	req.rtm.rtm_scope = (type != RTN_LOCAL ? RT_SCOPE_LINK : RT_SCOPE_HOST);
	req.rtm.rtm_type = type;

	rta.rta_dst = &dst;
	rta.rta_prefsrc = &ifa->ifa_local;
	rta.rta_oif = &ifa->ifa_dev->dev->ifindex;

	if (cmd == RTM_NEWROUTE)
		tb->tb_insert(tb, &req.rtm, &rta, &req.nlh, NULL);
	else
		tb->tb_delete(tb, &req.rtm, &rta, &req.nlh, NULL);
}

/**
 * 当配置一个新IP时，处理路由相关的事件。
 */
static void fib_add_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *prim = ifa;
	u32 mask = ifa->ifa_mask;
	u32 addr = ifa->ifa_local;
	u32 prefix = ifa->ifa_address&mask;

	/**
	 * 添加一条第二IP地址
	 */
	if (ifa->ifa_flags&IFA_F_SECONDARY) {
		/**
		 * 在该设备上必须存在在同一网段（prefix）内的一个主IP地址。如果这样的主IP地址不存在，那么将得到错误，配置不能够生效。
		 */
		prim = inet_ifa_byprefix(in_dev, prefix, mask);
		if (prim == NULL) {
			printk(KERN_DEBUG "fib_add_ifaddr: bug: prim == NULL\n");
			return;
		}
	}

	/**
	 * 添加到IP地址的本地路由。
	 * 即使此时设备没有使能，也可以安全的添加本地地址路由，因为即使后面设备使能后，添加本地地址也不会成功，不会造成重复。
	 */
	fib_magic(RTM_NEWROUTE, RTN_LOCAL, addr, 32, prim);

	/**
	 * 当设备没有使能时，其上的广播地址、网络地址都不能使用，因此在此可以退出。
	 * 当设备使能后，再添加它们的广播地址、网络地址。
	 */
	if (!(dev->flags&IFF_UP))
		return;

	/* Add broadcast address, if it is explicitly assigned. */
	/**
	 * 如果明确给出了广播地址且为受限广播地址255.255.255.255，那么不添加到该广播地址的路由，因为路由查找程序要检查全255的广播地址
	 */
	if (ifa->ifa_broadcast && ifa->ifa_broadcast != 0xFFFFFFFF)
		/**
		 * 否则添加设备广播地址到路由表中。
		 */
		fib_magic(RTM_NEWROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);

	if (!ZERONET(prefix) && !(ifa->ifa_flags&IFA_F_SECONDARY) && /* 第二IP地址不需要到网络地址的路由，也不需要到导出的广播地址的路由：相关的主地址配置时已经添加了这些路由项。 */
	    (prefix != addr || ifa->ifa_prefixlen < 32)) {/* 当prefixlen为32时，在子网内只有一个有效地址，所以不需要导出的广播路由或网络路由。 */
		/**
		 * 当prefixlen为31时，只有一个比特位参与，所以在子网内只有两个地址。
		 * clear比特位的地址表示网络地址，set比特位的地址表示主机地址（函数正在配置的地址）。
		 * 这种情况下需要到这两个地址的路由，而不需要到导出的广播地址的路由。
		 */
		fib_magic(RTM_NEWROUTE, dev->flags&IFF_LOOPBACK ? RTN_LOCAL :
			  RTN_UNICAST, prefix, ifa->ifa_prefixlen, prim);

		/* Add network specific broadcasts, when it takes a sense */

		/**
		 * 当prefixlen小于31时，子网内包含的地址数大于或等于四个，由于本地地址、网络地址和广播地址只占用其中三个，因而子网内还可以包含其他地址。
		 * 这时内核添加一条到导出的广播地址的路由及一条到导出的网段地址的路由。
		 */
		if (ifa->ifa_prefixlen < 31) {
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix, 32, prim);
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix|~mask, 32, prim);
		}
	}
}

/**
 * 当从一个接口删除一个IP地址时，路由子系统得到通知以便清理路由表和路由缓存。这是通过fib_del_ifaddr来实现的。
 */
static void fib_del_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *ifa1;
	struct in_ifaddr *prim = ifa;
	u32 brd = ifa->ifa_address|~ifa->ifa_mask;
	u32 any = ifa->ifa_address&ifa->ifa_mask;
#define LOCAL_OK	1
#define BRD_OK		2
#define BRD0_OK		4
#define BRD1_OK		8
	unsigned ok = 0;

	if (!(ifa->ifa_flags&IFA_F_SECONDARY))
		/**
		 * 删除本地地址。
		 */
		fib_magic(RTM_DELROUTE, dev->flags&IFF_LOOPBACK ? RTN_LOCAL :
			  RTN_UNICAST, any, ifa->ifa_prefixlen, prim);
	else {
		/**
		 * 若是删除一个第二IP地址，那么必须有一个主IP地址与它在同一网段。
		 * 如果不是，则前面某个地方可能出错因而返回一个错误。
		 */
		prim = inet_ifa_byprefix(in_dev, any, ifa->ifa_mask);
		if (prim == NULL) {
			printk(KERN_DEBUG "fib_del_ifaddr: bug: prim == NULL\n");
			return;
		}
	}

	/* Deletion is more complicated than add.
	   We should take care of not to delete too much :-)

	   Scan address list to be sure that addresses are really gone.
	 */
	/**
	 * fib_del_ifaddr扫描设备上配置的所有地址，检查哪些需要删除。
	 */
	for (ifa1 = in_dev->ifa_list; ifa1; ifa1 = ifa1->ifa_next) {
		if (ifa->ifa_local == ifa1->ifa_local)
			ok |= LOCAL_OK;
		if (ifa->ifa_broadcast == ifa1->ifa_broadcast)
			ok |= BRD_OK;
		if (brd == ifa1->ifa_broadcast)
			ok |= BRD1_OK;
		if (any == ifa1->ifa_broadcast)
			ok |= BRD0_OK;
	}

	if (!(ok&BRD_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);
	if (!(ok&BRD1_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, brd, 32, prim);
	if (!(ok&BRD0_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, any, 32, prim);
	if (!(ok&LOCAL_OK)) {
		fib_magic(RTM_DELROUTE, RTN_LOCAL, ifa->ifa_local, 32, prim);

		/* Check, that this local address finally disappeared. */
		/**
		 * 多数情况下，当删除一个第二IP地址时，路由子系统只需要删除到该IP地址的路由，而不删除到网段地址和广播地址的路由，因为主IP地址（以及其它可能存在的第二IP地址）仍然需要它们。
		 * 但还可能在删除一个第二IP地址时，不需要删除到该IP地址的路由：例如，当管理员配置的一个IP地址具有两个不同的网络掩码。
		 */
		if (inet_addr_type(ifa->ifa_local) != RTN_LOCAL) {
			/* And the last, but not the least thing.
			   We must flush stray FIB entries.

			   First of all, we scan fib_info list searching
			   for stray nexthop entries, then ignite fib_flush.
			*/
			/**
			 * 清理路由表。
			 */
			if (fib_sync_down(ifa->ifa_local, NULL, 0))
				fib_flush();
		}
	}
#undef LOCAL_OK
#undef BRD_OK
#undef BRD0_OK
#undef BRD1_OK
}

/**
 * 通过调用fib_sync_down来禁止输入参数dev上的IP协议。
 * 当删除的路由项数量为正值时（通过fib_sync_down的返回值判断），该函数也立即flush路由表。
 */
static void fib_disable_ip(struct net_device *dev, int force)
{
	if (fib_sync_down(0, dev, force))
		fib_flush();
	rt_cache_flush(0);
	arp_ifdown(dev);
}

/**
 * 旦设备的IP配置发生变化，路由子系统将收到一个通知，运行fib_inetaddr_event来处理该事件。
 */
static int fib_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr*)ptr;

	switch (event) {
	case NETDEV_UP:
		/**
		 * 本地设备上已经配置了一个新的IP地址。
		 * 处理钩子必须将必要的路由项添加到local_table路由表中，这是由fib_add_ifaddr程序来完成的。
		 */
		fib_add_ifaddr(ifa);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(ifa->ifa_dev->dev);
#endif
		rt_cache_flush(-1);
		break;
	case NETDEV_DOWN:
		/**
		 * 本地设备上已经删除了一个IP地址。
		 * 处理钩子必须将以前由NETDEV_UP事件添加的路由项删除，这是由fib_del_ifaddr来完成的。
		 */
		fib_del_ifaddr(ifa);
		/**
		 * 当fib_del_ifaddr从一个设备上删除最后一个IP地址时，fib_inetaddr_event函数调用fib_disable_ip来禁止该设备上的IP协议。
		 */
		if (ifa->ifa_dev && ifa->ifa_dev->ifa_list == NULL) {
			/* Last address was deleted from this interface.
			   Disable IP.
			 */
			fib_disable_ip(ifa->ifa_dev->dev, 1);
		} else {
			rt_cache_flush(-1);
		}
		break;
	}
	return NOTIFY_DONE;
}

/**
 * 当一个设备的状态或其某些配置部分发生变化，路由子系统将收到通知，调用fib_netdev_event来处理该事件。
 */
static int fib_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct in_device *in_dev = __in_dev_get(dev);

	if (event == NETDEV_UNREGISTER) {
		/**
		 * 当一个设备注销时，从路由表（包括路由缓存）删除使用该设备的所有路由项。
		 * 如果多路径路由项的下一跳中至少有一个使用该设备，则该路由项也被删除。
		 */
		fib_disable_ip(dev, 2);
		return NOTIFY_DONE;
	}

	if (!in_dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		/**
		 * 当一个设备变为UP时，必须将与该设备上所有IP地址相关的路由表项添加到ip_fib_local_table路由表中。
		 * 这是通过对该设备上配置的每一个IP地址，都调用fib_add_ifaddr函数来完成的。
		 */
		for_ifa(in_dev) {
			fib_add_ifaddr(ifa);
		} endfor_ifa(in_dev);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(dev);
#endif
		rt_cache_flush(-1);
		break;
	case NETDEV_DOWN:
		/**
		 * 当一个设备变为DOWN时，调用fib_disable_ip从路由表（包括路由缓存）删除使用该设备的所有路由项。
		 */
		fib_disable_ip(dev, 0);
		break;
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGE:
		/**
		 * 当一个设备的配置发生变化时，flush路由表缓存。
		 * 最常见的配置变化是MTU或PROMISCUITY状态被修改。
		 */
		rt_cache_flush(0);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block fib_inetaddr_notifier = {
	.notifier_call =fib_inetaddr_event,
};

static struct notifier_block fib_netdev_notifier = {
	.notifier_call =fib_netdev_event,
};

void __init ip_fib_init(void)
{
#ifndef CONFIG_IP_MULTIPLE_TABLES
	ip_fib_local_table = fib_hash_init(RT_TABLE_LOCAL);
	ip_fib_main_table  = fib_hash_init(RT_TABLE_MAIN);
#else
	fib_rules_init();
#endif

	register_netdevice_notifier(&fib_netdev_notifier);
	register_inetaddr_notifier(&fib_inetaddr_notifier);
}

EXPORT_SYMBOL(inet_addr_type);
EXPORT_SYMBOL(ip_dev_find);
EXPORT_SYMBOL(ip_rt_ioctl);
