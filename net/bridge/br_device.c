/*
 *	Device handling code
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_device.c,v 1.6 2001/12/24 00:59:55 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include "br_private.h"

static struct net_device_stats *br_dev_get_stats(struct net_device *dev)
{
	struct net_bridge *br;

	br = dev->priv;

	return &br->statistics;
}

/**
 * 网桥设备的发包函数。
 */
int br_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	const unsigned char *dest = skb->data;
	struct net_bridge_fdb_entry *dst;

	br->statistics.tx_packets++;
	br->statistics.tx_bytes += skb->len;

	skb->mac.raw = skb->data;
	skb_pull(skb, ETH_HLEN);

	rcu_read_lock();
	/**
	 * 如果目标地址是广播地址
	 */
	if (dest[0] & 1) 
		br_flood_deliver(br, skb, 0);/* 在所有端口上进行一次flood发送 */
	else if ((dst = __br_fdb_get(br, dest)) != NULL)/* 在转发数据库中找到目标地址的mac */
		br_deliver(dst->dst, skb);/* 在指定端口上转发。 */
	else
		br_flood_deliver(br, skb, 0);/* 否则也进行一次flood发送。 */

	rcu_read_unlock();
	return 0;
}

/**
 * 激活网桥设备。
 */
static int br_dev_open(struct net_device *dev)
{
	/**
	 * 通过函数netif_start_queue允许设备发送数据。
	 */
	netif_start_queue(dev);

	/**
	 * 通过函数br_stp_enable_bridge允许网桥设备。
	 */
	br_stp_enable_bridge(dev->priv);

	return 0;
}

static void br_dev_set_multicast_list(struct net_device *dev)
{
}

/**
 * 停止网桥设备。
 */
static int br_dev_stop(struct net_device *dev)
{
	br_stp_disable_bridge(dev->priv);

	netif_stop_queue(dev);

	return 0;
}

static int br_change_mtu(struct net_device *dev, int new_mtu)
{
	if ((new_mtu < 68) || new_mtu > br_min_mtu(dev->priv))
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int br_dev_accept_fastpath(struct net_device *dev, struct dst_entry *dst)
{
	return -1;
}

/**
 * 在分配net_device时，初始化net_device的函数。
 */
void br_dev_setup(struct net_device *dev)
{
	/**
	 * 网桥MAC地址dev_addr被清除，因为它源自于与之绑定的设备的MAC地址配置（br_stp_recalculate_bridge_id）。
	 */
	memset(dev->dev_addr, 0, ETH_ALEN);

	ether_setup(dev);

	dev->do_ioctl = br_dev_ioctl;
	dev->get_stats = br_dev_get_stats;
	dev->hard_start_xmit = br_dev_xmit;
	dev->open = br_dev_open;
	dev->set_multicast_list = br_dev_set_multicast_list;
	/**
	 * 当网桥设备上的MTU改变时，内核必须确保新值不会比所有绑定设备的最小MTU更大。这是由br_change_mtu保证的。
	 */
	dev->change_mtu = br_change_mtu;
	dev->destructor = free_netdev;
	SET_MODULE_OWNER(dev);
	dev->stop = br_dev_stop;
	dev->accept_fastpath = br_dev_accept_fastpath;
	/**
	 * 默认的，网桥设备并不定义队列。它让绑定的设备处理队列。
	 * 这也解释了为什么tx_queue_len被初始化为0。
	 * 但是管理员可以通过ifconfig或者ip link配置这个参数。
	 */
	dev->tx_queue_len = 0;
	/**
	 * 网桥MAC地址dev_addr被清除，因为它源自于与之绑定的设备的MAC地址配置（br_stp_recalculate_bridge_id）。
	 */
	dev->set_mac_address = NULL;
	/**
	 * IIF_EBRIGE标志被设置，这样内核代码可以在必要时区分网桥设备与其他设备的类型。
	 */
	dev->priv_flags = IFF_EBRIDGE;
}
