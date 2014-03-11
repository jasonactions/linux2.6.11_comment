/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br.c,v 1.47 2001/12/24 00:56:41 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>

#include "br_private.h"

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
#include "../atm/lec.h"
#endif

int (*br_should_route_hook) (struct sk_buff **pskb) = NULL;

/**
 * 网桥初始化代码
 */
static int __init br_init(void)
{
	/**
	 * 通过创建一个SLAB缓存来初始化转发数据库。
	 * 这个缓存用来分配net_bridge_fdb_entry数据结构。
	 */
	br_fdb_init();

#ifdef CONFIG_BRIDGE_NETFILTER
	if (br_netfilter_init())
		return 1;
#endif

	/**
	 * 始化函数指针br_ioctl_hook，因为处理ioctl命令的函数需要它。
 	 */
	brioctl_set(br_ioctl_deviceless_stub);
	/**
	 * 初始化函数指针br_handle_frame_hook，这个函数处理入帧BPDU
	 */
	br_handle_frame_hook = br_handle_frame;

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_get_hook = br_fdb_get;
	br_fdb_put_hook = br_fdb_put;
#endif
	/**
 	 * 过netdev_chain通知链注册一个回调函数。
 	 * 主要是为了监控与网桥绑定的设备事件。
 	 */
	register_netdevice_notifier(&br_device_notifier);

	return 0;
}

/**
 * 网桥反初始化代码。
 */
static void __exit br_deinit(void)
{
#ifdef CONFIG_BRIDGE_NETFILTER
	br_netfilter_fini();
#endif
	unregister_netdevice_notifier(&br_device_notifier);
	brioctl_set(NULL);

	br_cleanup_bridges();

	synchronize_net();

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_get_hook = NULL;
	br_fdb_put_hook = NULL;
#endif

	br_handle_frame_hook = NULL;
	br_fdb_fini();
}

EXPORT_SYMBOL(br_should_route_hook);

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
