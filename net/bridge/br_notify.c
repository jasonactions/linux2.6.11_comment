/*
 *	Device event handling
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_notify.c,v 1.2 2000/02/21 15:51:34 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>

#include "br_private.h"

static int br_device_event(struct notifier_block *unused, unsigned long event, void *ptr);

struct notifier_block br_device_notifier = {
	.notifier_call = br_device_event
};

/*
 * Handle changes in state of network devices enslaved to a bridge.
 * 
 * Note: don't care about up/down if bridge itself is down, because
 *     port state is checked when bridge is brought up.
 */
/**
 * 网桥代码注册的网络设备事件回调函数。
 */
static int br_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p = dev->br_port;
	struct net_bridge *br;

	/* not a port of a bridge */
	if (p == NULL)
		return NOTIFY_DONE;

	br = p->br;

	spin_lock_bh(&br->lock);
	switch (event) {
	case NETDEV_CHANGEMTU:
		/**
		 * 网桥设备的MTU被修改为所有绑定设备的最小MTU。
		 */
		dev_set_mtu(br->dev, br_min_mtu(br));
		break;

	case NETDEV_CHANGEADDR:
		br_fdb_changeaddr(p, dev->dev_addr);
		br_stp_recalculate_bridge_id(br);
		break;

	case NETDEV_CHANGE:	/* device is up but carrier changed */
		/**
		 * 当与网桥相关的设备被管理员禁用时（即IFF_UP没有被设置），相关的通知事件被忽略。
		 */
		if (!(br->dev->flags & IFF_UP))
			break;

		/**
		 * 这个通知事件可以被用于几个原因。网桥子系统仅仅关注于载波状态的变化。
		 * 当一个绑定设备失去或者检测到载波状态时(网线被拨出或者插入时)，相关网桥端口分别被br_stp_enable_port或者br_stp_disable_port启用或者关闭。
		 */
		if (netif_carrier_ok(dev)) {
			if (p->state == BR_STATE_DISABLED)
				br_stp_enable_port(p);
		} else {
			if (p->state != BR_STATE_DISABLED)
				br_stp_disable_port(p);
		}
		break;

	case NETDEV_DOWN:
		/**
		 * 当一个绑定设备被管理员禁用时，相关网桥端口也必须被禁止。
		 * 这是由br_stp_disable_port处理的。当相关网桥端口已经关闭时，不必进行此处理。
		 */
		if (br->dev->flags & IFF_UP)
			br_stp_disable_port(p);
		break;

	case NETDEV_UP:
		/**
		 * 当一个绑定设备被管理员开启（即IFF_UP被设置）时，并且相关网桥端口处于传输状态、相关网桥设备被开启时，相关网桥端口被br_stp_enabled_port开启。
		 */
		if (netif_carrier_ok(dev) && (br->dev->flags & IFF_UP)) 
			br_stp_enable_port(p);
		break;

	case NETDEV_UNREGISTER:
		spin_unlock_bh(&br->lock);
		/**
		 * 当一个绑定设备取消注册时，相关网桥端口也被br_del_if删除。此事件不必在锁的保护下进行。
		 */
		br_del_if(br, dev);
		goto done;
	} 
	spin_unlock_bh(&br->lock);

 done:
	return NOTIFY_DONE;
}
