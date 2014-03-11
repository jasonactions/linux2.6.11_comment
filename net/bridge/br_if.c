/*
 *	Userspace interface
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_if.c,v 1.7 2001/12/24 00:59:55 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>

#include "br_private.h"

/*
 * Determine initial path cost based on speed.
 * using recommendations from 802.1d standard
 *
 * Need to simulate user ioctl because not all device's that support
 * ethtool, use ethtool_ops.  Also, since driver might sleep need to
 * not be holding any locks.
 */
static int br_initial_port_cost(struct net_device *dev)
{

	struct ethtool_cmd ecmd = { ETHTOOL_GSET };
	struct ifreq ifr;
	mm_segment_t old_fs;
	int err;

	strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);
	ifr.ifr_data = (void __user *) &ecmd;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = dev_ethtool(&ifr);
	set_fs(old_fs);
	
	if (!err) {
		switch(ecmd.speed) {
		case SPEED_100:
			return 19;
		case SPEED_1000:
			return 4;
		case SPEED_10000:
			return 2;
		case SPEED_10:
			return 100;
		default:
			pr_info("bridge: can't decode speed from %s: %d\n",
				dev->name, ecmd.speed);
			return 100;
		}
	}

	/* Old silly heuristics based on name */
	if (!strncmp(dev->name, "lec", 3))
		return 7;

	if (!strncmp(dev->name, "plip", 4))
		return 2500;

	return 100;	/* assume old 10Mbps */
}

static void destroy_nbp(struct net_bridge_port *p)
{
	struct net_device *dev = p->dev;

	dev->br_port = NULL;
	p->br = NULL;
	p->dev = NULL;
	dev_put(dev);

	br_sysfs_freeif(p);
}

static void destroy_nbp_rcu(struct rcu_head *head)
{
	struct net_bridge_port *p =
			container_of(head, struct net_bridge_port, rcu);
	destroy_nbp(p);
}

/* called with RTNL */
static void del_nbp(struct net_bridge_port *p)
{
	struct net_bridge *br = p->br;
	struct net_device *dev = p->dev;

	dev_set_promiscuity(dev, -1);

	spin_lock_bh(&br->lock);
	br_stp_disable_port(p);
	spin_unlock_bh(&br->lock);

	/**
	 * 对每个网桥端口，使用br_fdb_delete_by_port删除所有相关的转发数据库条目。
	 */
	br_fdb_delete_by_port(br, p);

	list_del_rcu(&p->list);

	/**
	 * 停止所有端口时钟，递减计数器。
	 */
	del_timer_sync(&p->message_age_timer);
	del_timer_sync(&p->forward_delay_timer);
	del_timer_sync(&p->hold_timer);
	
	call_rcu(&p->rcu, destroy_nbp_rcu);
}

/* called with RTNL */
/**
 * 删除网桥设备。上层函数负责申请netlink锁。
 */
static void del_br(struct net_bridge *br)
{
	struct net_bridge_port *p, *n;

	/**
	 * 删除所有网桥端口。对每网桥端口，也删除在/sys中相关的连接。
	 */
	list_for_each_entry_safe(p, n, &br->port_list, list) {
		br_sysfs_removeif(p);
		del_nbp(p);
	}

	/**
	 * 停止垃圾收集时钟br->gc_timer。
	 */
	del_timer_sync(&br->gc_timer);

	/**
	 * 通过br_sysfs_delbr函数，删除在/sys/class/net目录下的网桥设备目录。
	 */
	br_sysfs_delbr(br->dev);
	/**
	 * 取消设备注册。
	 */
 	unregister_netdevice(br->dev);
}

/**
 * 建和注册一个网桥设备遵循第8章描述的模式。
 * 唯一的不同之处在于，由于网桥是一个虚拟设备，它需要在特定的地方额外的初始化它。
 * 这是由new_bridge_dev处理的.
 * 网桥设备可以被指定任何的名称。通常情况下，视STP是否被打开，其名称为brN或者stpN。
 */
static struct net_device *new_bridge_dev(const char *name)
{
	struct net_bridge *br;
	struct net_device *dev;

	/**
	 * 分配net_bridge时，同时分配一个net_bridge私有数据结构。
	 * 并且使用br_dev_setup初始化net_device数据结构。
	 */
	dev = alloc_netdev(sizeof(struct net_bridge), name,
			   br_dev_setup);
	
	if (!dev)
		return NULL;

	br = netdev_priv(dev);
	br->dev = dev;

	/**
	 * 初始化私有数据结构。
	 */
	spin_lock_init(&br->lock);
	INIT_LIST_HEAD(&br->port_list);
	spin_lock_init(&br->hash_lock);

	/**
	 * 初始化网桥优先级为默认值32768。
	 */
	br->bridge_id.prio[0] = 0x80;
	br->bridge_id.prio[1] = 0x00;
	memset(br->bridge_id.addr, 0, ETH_ALEN);

	br->stp_enabled = 0;
	/**
	 * 初始化指派网桥ID、设置根路径为0,根端口为0（即没有根端口）。这是因为网桥最初激活时，它认为自己是根桥。
	 */
	br->designated_root = br->bridge_id;
	br->root_path_cost = 0;
	br->root_port = 0;
	br->bridge_max_age = br->max_age = 20 * HZ;
	br->bridge_hello_time = br->hello_time = 2 * HZ;
	br->bridge_forward_delay = br->forward_delay = 15 * HZ;
	br->topology_change = 0;
	br->topology_change_detected = 0;
	/**
	 * 初始化老化时间为默认的5分钟。
	 */
	br->ageing_time = 300 * HZ;
	INIT_LIST_HEAD(&br->age_list);

	/**
	 * 使用函数br_stp_timer_init初始化每网桥时钟。
	 */
	br_stp_timer_init(br);

	return dev;
}

/* find an available port number */
/**
 * 在1-BR_MAX_PORTS范围内没有使用的第一个值被选择作为端口号。
 * 由find_portno函数完成端口号的选择。当端口被创建时，进行端口号的选择。
 */
static int find_portno(struct net_bridge *br)
{
	int index;
	struct net_bridge_port *p;
	unsigned long *inuse;

	inuse = kmalloc(BITS_TO_LONGS(BR_MAX_PORTS)*sizeof(unsigned long),
			GFP_KERNEL);
	if (!inuse)
		return -ENOMEM;

	memset(inuse, 0, BITS_TO_LONGS(BR_MAX_PORTS)*sizeof(unsigned long));
	set_bit(0, inuse);	/* zero is reserved */
	list_for_each_entry(p, &br->port_list, list) {
		set_bit(p->port_no, inuse);
	}
	index = find_first_zero_bit(inuse, BR_MAX_PORTS);
	kfree(inuse);

	return (index >= BR_MAX_PORTS) ? -EXFULL : index;
}

/* called with RTNL */
static struct net_bridge_port *new_nbp(struct net_bridge *br, 
				       struct net_device *dev,
				       unsigned long cost)
{
	int index;
	struct net_bridge_port *p;

	/**
	 * 分配一个端口号给网桥端口。
	 */
	index = find_portno(br);
	if (index < 0)
		return ERR_PTR(index);

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	memset(p, 0, sizeof(*p));
	/**
	 * 关联网桥端口与绑定设备、网桥设备。
	 */
	p->br = br;
	dev_hold(dev);
	p->dev = dev;
	p->path_cost = cost;
	/**
	 * 分配一个默认的优先级给端口。
	 */
 	p->priority = 0x8000 >> BR_PORT_BITS;
	dev->br_port = p;
	p->port_no = index;
	br_init_port(p);
	/**
	 * 指定初始的BR_STATE_DISABLED状态。
	 */
	p->state = BR_STATE_DISABLED;
	kobject_init(&p->kobj);

	return p;
}

/**
 * 创建网桥设备。
 */
int br_add_bridge(const char *name)
{
	struct net_device *dev;
	int ret;

	dev = new_bridge_dev(name);
	if (!dev) 
		return -ENOMEM;

	rtnl_lock();
	if (strchr(dev->name, '%')) {
		ret = dev_alloc_name(dev, dev->name);
		if (ret < 0)
			goto err1;
	}

	ret = register_netdevice(dev);
	if (ret)
		goto err2;

	/* network device kobject is not setup until
	 * after rtnl_unlock does it's hotplug magic.
	 * so hold reference to avoid race.
	 */
	dev_hold(dev);
	rtnl_unlock();

	ret = br_sysfs_addbr(dev);
	dev_put(dev);

	if (ret) 
		unregister_netdev(dev);
 out:
	return ret;

 err2:
	free_netdev(dev);
 err1:
	rtnl_unlock();
	goto out;
}

/**
 * 删除一个网桥设备。
 */
int br_del_bridge(const char *name)
{
	struct net_device *dev;
	int ret = 0;

	rtnl_lock();
	dev = __dev_get_by_name(name);
	/**
	 * 设备不存在。
	 */
	if (dev == NULL) 
		ret =  -ENXIO; 	/* Could not find device */
	/**
	 * 不是网桥设备。
	 */
	else if (!(dev->priv_flags & IFF_EBRIDGE)) {
		/* Attempt to delete non bridge device! */
		ret = -EPERM;
	}
	/**
	 * 网桥没有被停止。不能删除。
	 */
	else if (dev->flags & IFF_UP) {
		/* Not shutdown yet. */
		ret = -EBUSY;
	} 

	else /* del_br进行真正的删除操作。 */
		del_br(netdev_priv(dev));

	rtnl_unlock();
	return ret;
}

/* Mtu of the bridge pseudo-device 1500 or the minimum of the ports */
int br_min_mtu(const struct net_bridge *br)
{
	const struct net_bridge_port *p;
	int mtu = 0;

	ASSERT_RTNL();

	if (list_empty(&br->port_list))
		mtu = 1500;
	else {
		list_for_each_entry(p, &br->port_list, list) {
			if (!mtu  || p->dev->mtu < mtu)
				mtu = p->dev->mtu;
		}
	}
	return mtu;
}

/* called with RTNL */
/**
 * 向网桥设备添加一个网络设备。
 * 这个函数并不关心是否在网桥设备上打开了STP。
 */
int br_add_if(struct net_bridge *br, struct net_device *dev)
{
	struct net_bridge_port *p;
	int err = 0;

	/**
	 * 与端口相关的设备不是以太网设备（或者是回环设备）。
	 */
	if (dev->flags & IFF_LOOPBACK || dev->type != ARPHRD_ETHER)
		return -EINVAL;

	/**
	 * 与端口关联的设备是网桥。
	 * 必须为网桥端口分配一个实际的设备（或者不是网桥的虚拟设备）。
	 */
	if (dev->hard_start_xmit == br_dev_xmit)
		return -ELOOP;

	/**
	 * 设备已经指定了网桥端口（即dev_br_port不为空）。
	 */
	if (dev->br_port != NULL)
		return -EBUSY;

	/**
	 * net_nbp进行真正的操作。
	 * 基于绑定设备的速度，给端口分配一个默认的权重值。
	 * 这个值由br_initial_port_cost选择（请看看它是如何被new_npb调用的）。
	 * 它通过ethtool接口读取设备速度，并将它转换成一个权重值。
	 * 当绑定设备不支持ethtool接口时，不能由设备产生一个默认的权重值。
	 * 因此，假设设备是一个10M以太网设备，为其选择一个默认值。
	 * 关于设备速度与默认端口权重值的关系，在IEEE802.1D协议规范中定义。
	 */
	if (IS_ERR(p = new_nbp(br, dev, br_initial_port_cost(dev))))
		return PTR_ERR(p);

	/**
	 * 与新网桥端口关联的设备的MAC地址被br_fdb_insert函数添加到转发数据库。
	 */
 	if ((err = br_fdb_insert(br, p, dev->dev_addr, 1)))
		destroy_nbp(p);
 	/**
 	 * br_sysfs_addif添加必要的连接到/sys。
 	 */
	else if ((err = br_sysfs_addif(p)))
		del_nbp(p);
	else {
		/**
		 * 与网桥端口关联的NIC被dev_set_promiscuity函数设置成混杂模式。
		 */
		dev_set_promiscuity(dev, 1);

		/**
		 * 新网桥端口被添加到网桥端口列表.
		 */
		list_add_rcu(&p->list, &br->port_list);

		spin_lock_bh(&br->lock);
		/**
		 * 更新网桥ID和MTU
		 */
		br_stp_recalculate_bridge_id(br);
		if ((br->dev->flags & IFF_UP) 
		    && (dev->flags & IFF_UP) && netif_carrier_ok(dev))
			br_stp_enable_port(p);
		spin_unlock_bh(&br->lock);

		dev_set_mtu(br->dev, br_min_mtu(br));
	}

	return err;
}

/* called with RTNL */
/**
 * 从网桥设备中删除一个网络设备。
 */
int br_del_if(struct net_bridge *br, struct net_device *dev)
{
	struct net_bridge_port *p = dev->br_port;
	
	if (!p || p->br != br) 
		return -EINVAL;

	br_sysfs_removeif(p);
	del_nbp(p);

	spin_lock_bh(&br->lock);
	br_stp_recalculate_bridge_id(br);
	spin_unlock_bh(&br->lock);

	return 0;
}

void __exit br_cleanup_bridges(void)
{
	struct net_device *dev, *nxt;

	rtnl_lock();
	for (dev = dev_base; dev; dev = nxt) {
		nxt = dev->next;
		if (dev->priv_flags & IFF_EBRIDGE)
			del_br(dev->priv);
	}
	rtnl_unlock();

}
