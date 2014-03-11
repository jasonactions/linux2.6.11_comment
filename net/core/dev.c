/*
 * 	NET3	Protocol independent device support routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Derived from the non IP parts of dev.c 1.0.19
 * 		Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *				Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *				Mark Evans, <evansmp@uhura.aston.ac.uk>
 *
 *	Additional Authors:
 *		Florian la Roche <rzsfl@rz.uni-sb.de>
 *		Alan Cox <gw4pts@gw4pts.ampr.org>
 *		David Hinds <dahinds@users.sourceforge.net>
 *		Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *		Adam Sulmicki <adam@cfar.umd.edu>
 *              Pekka Riikonen <priikone@poesidon.pspt.fi>
 *
 *	Changes:
 *              D.J. Barrow     :       Fixed bug where dev->refcnt gets set
 *              			to 2 if register_netdev gets called
 *              			before net_dev_init & also removed a
 *              			few lines of code in the process.
 *		Alan Cox	:	device private ioctl copies fields back.
 *		Alan Cox	:	Transmit queue code does relevant
 *					stunts to keep the queue safe.
 *		Alan Cox	:	Fixed double lock.
 *		Alan Cox	:	Fixed promisc NULL pointer trap
 *		????????	:	Support the full private ioctl range
 *		Alan Cox	:	Moved ioctl permission check into
 *					drivers
 *		Tim Kordas	:	SIOCADDMULTI/SIOCDELMULTI
 *		Alan Cox	:	100 backlog just doesn't cut it when
 *					you start doing multicast video 8)
 *		Alan Cox	:	Rewrote net_bh and list manager.
 *		Alan Cox	: 	Fix ETH_P_ALL echoback lengths.
 *		Alan Cox	:	Took out transmit every packet pass
 *					Saved a few bytes in the ioctl handler
 *		Alan Cox	:	Network driver sets packet type before
 *					calling netif_rx. Saves a function
 *					call a packet.
 *		Alan Cox	:	Hashed net_bh()
 *		Richard Kooijman:	Timestamp fixes.
 *		Alan Cox	:	Wrong field in SIOCGIFDSTADDR
 *		Alan Cox	:	Device lock protection.
 *		Alan Cox	: 	Fixed nasty side effect of device close
 *					changes.
 *		Rudi Cilibrasi	:	Pass the right thing to
 *					set_mac_address()
 *		Dave Miller	:	32bit quantity for the device lock to
 *					make it work out on a Sparc.
 *		Bjorn Ekwall	:	Added KERNELD hack.
 *		Alan Cox	:	Cleaned up the backlog initialise.
 *		Craig Metz	:	SIOCGIFCONF fix if space for under
 *					1 device.
 *	    Thomas Bogendoerfer :	Return ENODEV for dev_open, if there
 *					is no device open function.
 *		Andi Kleen	:	Fix error reporting for SIOCGIFCONF
 *	    Michael Chastain	:	Fix signed/unsigned for SIOCGIFCONF
 *		Cyrus Durgin	:	Cleaned for KMOD
 *		Adam Sulmicki   :	Bug Fix : Network Device Unload
 *					A network device unload needs to purge
 *					the backlog queue.
 *	Paul Rusty Russell	:	SIOCSIFNAME
 *              Pekka Riikonen  :	Netdev boot-time settings code
 *              Andrew Morton   :       Make unregister_netdevice wait
 *              			indefinitely on dev->refcnt
 * 		J Hadi Salim	:	- Backlog queue sampling
 *				        - netif_rx() feedback
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/config.h>
#include <linux/cpu.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/if_bridge.h>
#include <linux/divert.h>
#include <net/dst.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#ifdef CONFIG_NET_RADIO
#include <linux/wireless.h>		/* Note : will define WIRELESS_EXT */
#include <net/iw_handler.h>
#endif	/* CONFIG_NET_RADIO */
#include <asm/current.h>

/* This define, if set, will randomly drop a packet when congestion
 * is more than moderate.  It helps fairness in the multi-interface
 * case when one of them is a hog, but it kills performance for the
 * single interface case so it is off now by default.
 */
#undef RAND_LIE

/* Setting this will sample the queue lengths and thus congestion
 * via a timer instead of as each packet is received.
 */
#undef OFFLINE_SAMPLE

/*
 *	The list of packet types we will receive (as opposed to discard)
 *	and the routines to invoke.
 *
 *	Why 16. Because with 16 the only overlap we get on a hash of the
 *	low nibble of the protocol value is RARP/SNAP/X.25.
 *
 *      NOTE:  That is no longer true with the addition of VLAN tags.  Not
 *             sure which should go first, but I bet it won't make much
 *             difference if we are running VLANs.  The good news is that
 *             this protocol won't be in the list unless compiled in, so
 *             the average user (w/out VLANs) will not be adversly affected.
 *             --BLG
 *
 *		0800	IP
 *		8100    802.1Q VLAN
 *		0001	802.3
 *		0002	AX.25
 *		0004	802.2
 *		8035	RARP
 *		0005	SNAP
 *		0805	X.25
 *		0806	ARP
 *		8137	IPX
 *		0009	Localtalk
 *		86DD	IPv6
 */

static DEFINE_SPINLOCK(ptype_lock);
static struct list_head ptype_base[16];	/* 16 way hashed list */
static struct list_head ptype_all;		/* Taps */

#ifdef OFFLINE_SAMPLE
static void sample_queue(unsigned long dummy);
static struct timer_list samp_timer = TIMER_INITIALIZER(sample_queue, 0, 0);
#endif

/*
 * The @dev_base list is protected by @dev_base_lock and the rtln
 * semaphore.
 *
 * Pure readers hold dev_base_lock for reading.
 *
 * Writers must hold the rtnl semaphore while they loop through the
 * dev_base list, and hold dev_base_lock for writing when they do the
 * actual updates.  This allows pure readers to access the list even
 * while a writer is preparing to update it.
 *
 * To put it another way, dev_base_lock is held for writing only to
 * protect against pure readers; the rtnl semaphore provides the
 * protection against other writers.
 *
 * See, for example usages, register_netdevice() and
 * unregister_netdevice(), which must be called with the rtnl
 * semaphore held.
 */
/**
 * 所有设备的 net_device 结构都放在一个全局链表中，链表的头指针是 dev_base。
 */
struct net_device *dev_base;
static struct net_device **dev_tail = &dev_base;
DEFINE_RWLOCK(dev_base_lock);

EXPORT_SYMBOL(dev_base);
EXPORT_SYMBOL(dev_base_lock);

#define NETDEV_HASHBITS	8
/**
 * 以设备名为索引的哈希表，它非常有用，如，当由 ioctl 接口改变一个配置时。
 * 早期的配置工具通过ioctl接口与内核交互，通常通过设备名来引用设备。 
 */
static struct hlist_head dev_name_head[1<<NETDEV_HASHBITS];
/**
 * 这是以设备 ID：dev->ifindex 为索引的哈希表，交叉引用 net_device 结构通常要么存储设备 ID，要么存储 net_device 结构的指针。
 * dev_index_head 对这种情形很有用，新的IP配置工具(来自 IPROUTE2包)通过 Netlink套接字和内核交互，通常通过设备ID引用设备。
 */
static struct hlist_head dev_index_head[1<<NETDEV_HASHBITS];

static inline struct hlist_head *dev_name_hash(const char *name)
{
	unsigned hash = full_name_hash(name, strnlen(name, IFNAMSIZ));
	return &dev_name_head[hash & ((1<<NETDEV_HASHBITS)-1)];
}

static inline struct hlist_head *dev_index_hash(int ifindex)
{
	return &dev_index_head[ifindex & ((1<<NETDEV_HASHBITS)-1)];
}

/*
 *	Our notifier list
 */
/**
 * 网络设备状态改变时发送通知。
 */
static struct notifier_block *netdev_chain;

/*
 *	Device drivers call our routines to queue packets here. We empty the
 *	queue in the local softnet handler.
 */
DEFINE_PER_CPU(struct softnet_data, softnet_data) = { 0, };

#ifdef CONFIG_SYSFS
extern int netdev_sysfs_init(void);
extern int netdev_register_sysfs(struct net_device *);
extern void netdev_unregister_sysfs(struct net_device *);
#else
#define netdev_sysfs_init()	 	(0)
#define netdev_register_sysfs(dev)	(0)
#define	netdev_unregister_sysfs(dev)	do { } while(0)
#endif


/*******************************************************************************

		Protocol management and registration routines

*******************************************************************************/

/*
 *	For efficiency
 */
/**
 * netdev_nit表示ETH_P_ALL协议数量。
 */
int netdev_nit;

/*
 *	Add a protocol ID to the list. Now that the input handler is
 *	smarter we can dispense with all the messy stuff that used to be
 *	here.
 *
 *	BEWARE!!! Protocol handlers, mangling input packets,
 *	MUST BE last in hash buckets and checking protocol handlers
 *	MUST start from promiscuous ptype_all chain in net_bh.
 *	It is true now, do not change it.
 *	Explanation follows: if protocol handler, mangling packet, will
 *	be the first on list, it is not able to sense, that packet
 *	is cloned and should be copied-on-write, so that it will
 *	change it and subsequent readers will get broken packet.
 *							--ANK (980803)
 */

/**
 *	dev_add_pack - add packet handler
 *	@pt: packet type declaration
 *
 *	Add a protocol handler to the networking stack. The passed &packet_type
 *	is linked into kernel lists and may not be freed until it has been
 *	removed from the kernel lists.
 *
 *	This call does not sleep therefore it can not 
 *	guarantee all CPU's that are in middle of receiving packets
 *	will see the new packet type (until the next received packet).
 */

/**
 * 注册一个二层协议处理函数。
 */
void dev_add_pack(struct packet_type *pt)
{
	int hash;

	spin_lock_bh(&ptype_lock);
	/**
	 * 要添加的函数是否是一个协议嗅探器(pt_type == htons(ETH_P_ALL))
	 */
	if (pt->type == htons(ETH_P_ALL)) {
		/**
		 * 增加注册的协议嗅探器数量(netdev_nit++)
		 */
		netdev_nit++;
		/**
		 * 添加它到ptype_all链表
		 */
		list_add_rcu(&pt->list, &ptype_all);
	} else {
		/**
		 * 将它插入到由ptype_base指向的16个链表中的一个，具体插入到哪个链表，依赖于它的hash值
		 */
		hash = ntohs(pt->type) & 15;
		list_add_rcu(&pt->list, &ptype_base[hash]);
	}
	spin_unlock_bh(&ptype_lock);
}

extern void linkwatch_run_queue(void);



/**
 *	__dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns. 
 *
 *      The packet type might still be in use by receivers
 *	and must not be freed until after all the CPU's have gone
 *	through a quiescent state.
 */
void __dev_remove_pack(struct packet_type *pt)
{
	struct list_head *head;
	struct packet_type *pt1;

	spin_lock_bh(&ptype_lock);

	if (pt->type == htons(ETH_P_ALL)) {
		netdev_nit--;
		head = &ptype_all;
	} else
		head = &ptype_base[ntohs(pt->type) & 15];

	list_for_each_entry(pt1, head, list) {
		if (pt == pt1) {
			list_del_rcu(&pt->list);
			goto out;
		}
	}

	printk(KERN_WARNING "dev_remove_pack: %p not found.\n", pt);
out:
	spin_unlock_bh(&ptype_lock);
}
/**
 *	dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns.
 *
 *	This call sleeps to guarantee that no CPU is looking at the packet
 *	type after return.
 */
/**
 * 移除协议处理函数。
 */
void dev_remove_pack(struct packet_type *pt)
{
	/**
	 * 从ptype_all或者ptype_base中删除packet_type数据结构。
	 */
	__dev_remove_pack(pt);

	/**
	 * Synchronize_net用于确保在dev_remove_pack函数返回时，没有一个地方还在对packet_type数据结构有所引用。
	 */
	synchronize_net();
}

/******************************************************************************

		      Device Boot-time Settings Routines

*******************************************************************************/

/* Boot time configuration table */
static struct netdev_boot_setup dev_boot_setup[NETDEV_BOOT_SETUP_MAX];

/**
 *	netdev_boot_setup_add	- add new setup entry
 *	@name: name of the device
 *	@map: configured settings for the device
 *
 *	Adds new setup entry to the dev_boot_setup list.  The function
 *	returns 0 on error and 1 on success.  This is a generic routine to
 *	all netdevices.
 */
static int netdev_boot_setup_add(char *name, struct ifmap *map)
{
	struct netdev_boot_setup *s;
	int i;

	s = dev_boot_setup;
	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] == '\0' || s[i].name[0] == ' ') {
			memset(s[i].name, 0, sizeof(s[i].name));
			strcpy(s[i].name, name);
			memcpy(&s[i].map, map, sizeof(s[i].map));
			break;
		}
	}

	return i >= NETDEV_BOOT_SETUP_MAX ? 0 : 1;
}

/**
 *	netdev_boot_setup_check	- check boot time settings
 *	@dev: the netdevice
 *
 * 	Check boot time settings for the device.
 *	The found settings are set for the device to be used
 *	later in the device probing.
 *	Returns 0 if no settings found, 1 if they are.
 */
/**
 * 启动阶段结束时，网络代码会调用 netdev_boot_setup_check 函数检查给定的接口是否与启动时配置有关联，在 dev_boot_setup 数组中查找时基于设备名 dev->name
 */
int netdev_boot_setup_check(struct net_device *dev)
{
	struct netdev_boot_setup *s = dev_boot_setup;
	int i;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] != '\0' && s[i].name[0] != ' ' &&
		    !strncmp(dev->name, s[i].name, strlen(s[i].name))) {
			dev->irq 	= s[i].map.irq;
			dev->base_addr 	= s[i].map.base_addr;
			dev->mem_start 	= s[i].map.mem_start;
			dev->mem_end 	= s[i].map.mem_end;
			return 1;
		}
	}
	return 0;
}


/**
 *	netdev_boot_base	- get address from boot time settings
 *	@prefix: prefix for network device
 *	@unit: id for network device
 *
 * 	Check boot time settings for the base address of device.
 *	The found settings are set for the device to be used
 *	later in the device probing.
 *	Returns 0 if no settings found.
 */
unsigned long netdev_boot_base(const char *prefix, int unit)
{
	const struct netdev_boot_setup *s = dev_boot_setup;
	char name[IFNAMSIZ];
	int i;

	sprintf(name, "%s%d", prefix, unit);

	/*
	 * If device already registered then return base of 1
	 * to indicate not to probe for this interface
	 */
	if (__dev_get_by_name(name))
		return 1;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++)
		if (!strcmp(name, s[i].name))
			return s[i].map.base_addr;
	return 0;
}

/*
 * Saves at boot time configured settings for any netdevice.
 */
int __init netdev_boot_setup(char *str)
{
	int ints[5];
	struct ifmap map;

	/**
	 * 从启动参数中提取输入参数，填充到 ifmap 结构中
	 */
	str = get_options(str, ARRAY_SIZE(ints), ints);
	if (!str || !*str)
		return 0;

	/* Save settings */
	memset(&map, 0, sizeof(map));
	if (ints[0] > 0)
		map.irq = ints[1];
	if (ints[0] > 1)
		map.base_addr = ints[2];
	if (ints[0] > 2)
		map.mem_start = ints[3];
	if (ints[0] > 3)
		map.mem_end = ints[4];

	/* Add new entry to the list */
	/**
	 * 通过 netdev_boot_setup_add 函数将 ifmap 信息加入到 dev_boot_setup 数组中
	 */
	return netdev_boot_setup_add(str, &map);
}
/**
 * 当内核参数中包含netdev=时，调用netdev_boot_setup函数。
 */
__setup("netdev=", netdev_boot_setup);

/*******************************************************************************

			    Device Interface Subroutines

*******************************************************************************/

/**
 *	__dev_get_by_name	- find a device by its name
 *	@name: name to find
 *
 *	Find an interface by name. Must be called under RTNL semaphore
 *	or @dev_base_lock. If the name is found a pointer to the device
 *	is returned. If the name is not found then %NULL is returned. The
 *	reference counters are not incremented so the caller must be
 *	careful with locks.
 */

struct net_device *__dev_get_by_name(const char *name)
{
	struct hlist_node *p;

	hlist_for_each(p, dev_name_hash(name)) {
		struct net_device *dev
			= hlist_entry(p, struct net_device, name_hlist);
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;
	}
	return NULL;
}

/**
 *	dev_get_by_name		- find a device by its name
 *	@name: name to find
 *
 *	Find an interface by name. This can be called from any
 *	context and does its own locking. The returned handle has
 *	the usage count incremented and the caller must use dev_put() to
 *	release it when it is no longer needed. %NULL is returned if no
 *	matching device is found.
 */
/**
 * 根据设备名称，在hash表中搜索网络设备。
 */
struct net_device *dev_get_by_name(const char *name)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(name);
	if (dev)
		dev_hold(dev);
	read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	__dev_get_by_index - find a device by its ifindex
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns %NULL if the device
 *	is not found or a pointer to the device. The device has not
 *	had its reference counter increased so the caller must be careful
 *	about locking. The caller must hold either the RTNL semaphore
 *	or @dev_base_lock.
 */

struct net_device *__dev_get_by_index(int ifindex)
{
	struct hlist_node *p;

	hlist_for_each(p, dev_index_hash(ifindex)) {
		struct net_device *dev
			= hlist_entry(p, struct net_device, index_hlist);
		if (dev->ifindex == ifindex)
			return dev;
	}
	return NULL;
}


/**
 *	dev_get_by_index - find a device by its ifindex
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns NULL if the device
 *	is not found or a pointer to the device. The device returned has
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */
/**
 * 根据设备索引，在hash表中搜索网络设备。
 */
struct net_device *dev_get_by_index(int ifindex)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_index(ifindex);
	if (dev)
		dev_hold(dev);
	read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	dev_getbyhwaddr - find a device by its hardware address
 *	@type: media type of device
 *	@ha: hardware address
 *
 *	Search for an interface by MAC address. Returns NULL if the device
 *	is not found or a pointer to the device. The caller must hold the
 *	rtnl semaphore. The returned device has not had its ref count increased
 *	and the caller must therefore be careful about locking
 *
 *	BUGS:
 *	If the API was consistent this would be __dev_get_by_hwaddr
 */

struct net_device *dev_getbyhwaddr(unsigned short type, char *ha)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for (dev = dev_base; dev; dev = dev->next)
		if (dev->type == type &&
		    !memcmp(dev->dev_addr, ha, dev->addr_len))
			break;
	return dev;
}

struct net_device *dev_getfirstbyhwtype(unsigned short type)
{
	struct net_device *dev;

	rtnl_lock();
	for (dev = dev_base; dev; dev = dev->next) {
		if (dev->type == type) {
			dev_hold(dev);
			break;
		}
	}
	rtnl_unlock();
	return dev;
}

EXPORT_SYMBOL(dev_getfirstbyhwtype);

/**
 *	dev_get_by_flags - find any device with given flags
 *	@if_flags: IFF_* values
 *	@mask: bitmask of bits in if_flags to check
 *
 *	Search for any interface with the given flags. Returns NULL if a device
 *	is not found or a pointer to the device. The device returned has 
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */

struct net_device * dev_get_by_flags(unsigned short if_flags, unsigned short mask)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	for (dev = dev_base; dev != NULL; dev = dev->next) {
		if (((dev->flags ^ if_flags) & mask) == 0) {
			dev_hold(dev);
			break;
		}
	}
	read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	dev_valid_name - check if name is okay for network device
 *	@name: name string
 *
 *	Network device names need to be valid file names to
 *	to allow sysfs to work
 */
static int dev_valid_name(const char *name)
{
	return !(*name == '\0' 
		 || !strcmp(name, ".")
		 || !strcmp(name, "..")
		 || strchr(name, '/'));
}

/**
 *	dev_alloc_name - allocate a name for a device
 *	@dev: device
 *	@name: name format string
 *
 *	Passed a format string - eg "lt%d" it will try and find a suitable
 *	id. Not efficient for many devices, not called a lot. The caller
 *	must hold the dev_base or rtnl lock while allocating the name and
 *	adding the device in order to avoid duplicates. Returns the number
 *	of the unit assigned or a negative errno code.
 */

int dev_alloc_name(struct net_device *dev, const char *name)
{
	int i = 0;
	char buf[IFNAMSIZ];
	const char *p;
	const int max_netdevices = 8*PAGE_SIZE;
	long *inuse;
	struct net_device *d;

	p = strnchr(name, IFNAMSIZ-1, '%');
	if (p) {
		/*
		 * Verify the string as this thing may have come from
		 * the user.  There must be either one "%d" and no other "%"
		 * characters.
		 */
		if (p[1] != 'd' || strchr(p + 2, '%'))
			return -EINVAL;

		/* Use one page as a bit array of possible slots */
		inuse = (long *) get_zeroed_page(GFP_ATOMIC);
		if (!inuse)
			return -ENOMEM;

		for (d = dev_base; d; d = d->next) {
			if (!sscanf(d->name, name, &i))
				continue;
			if (i < 0 || i >= max_netdevices)
				continue;

			/*  avoid cases where sscanf is not exact inverse of printf */
			snprintf(buf, sizeof(buf), name, i);
			if (!strncmp(buf, d->name, IFNAMSIZ))
				set_bit(i, inuse);
		}

		i = find_first_zero_bit(inuse, max_netdevices);
		free_page((unsigned long) inuse);
	}

	snprintf(buf, sizeof(buf), name, i);
	if (!__dev_get_by_name(buf)) {
		strlcpy(dev->name, buf, IFNAMSIZ);
		return i;
	}

	/* It is possible to run out of possible slots
	 * when the name is long and there isn't enough space left
	 * for the digits, or if all bits are used.
	 */
	return -ENFILE;
}


/**
 *	dev_change_name - change name of a device
 *	@dev: device
 *	@newname: name (or format string) must be at least IFNAMSIZ
 *
 *	Change name of a device, can pass format strings "eth%d".
 *	for wildcarding.
 */
int dev_change_name(struct net_device *dev, char *newname)
{
	int err = 0;

	ASSERT_RTNL();

	if (dev->flags & IFF_UP)
		return -EBUSY;

	if (!dev_valid_name(newname))
		return -EINVAL;

	if (strchr(newname, '%')) {
		err = dev_alloc_name(dev, newname);
		if (err < 0)
			return err;
		strcpy(newname, dev->name);
	}
	else if (__dev_get_by_name(newname))
		return -EEXIST;
	else
		strlcpy(dev->name, newname, IFNAMSIZ);

	err = class_device_rename(&dev->class_dev, dev->name);
	if (!err) {
		hlist_del(&dev->name_hlist);
		hlist_add_head(&dev->name_hlist, dev_name_hash(dev->name));
		notifier_call_chain(&netdev_chain, NETDEV_CHANGENAME, dev);
	}

	return err;
}

/**
 *	netdev_state_change - device changes state
 *	@dev: device to cause notification
 *
 *	Called to indicate a device has changed state. This function calls
 *	the notifier chains for netdev_chain and sends a NEWLINK message
 *	to the routing socket.
 */
void netdev_state_change(struct net_device *dev)
{
	if (dev->flags & IFF_UP) {
		notifier_call_chain(&netdev_chain, NETDEV_CHANGE, dev);
		rtmsg_ifinfo(RTM_NEWLINK, dev, 0);
	}
}

/**
 *	dev_load 	- load a network module
 *	@name: name of interface
 *
 *	If a network interface is not present and the process has suitable
 *	privileges this function loads the module. If module loading is not
 *	available in this kernel then it becomes a nop.
 */

void dev_load(const char *name)
{
	struct net_device *dev;  

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(name);
	read_unlock(&dev_base_lock);

	if (!dev && capable(CAP_SYS_MODULE))
		request_module("%s", name);
}

static int default_rebuild_header(struct sk_buff *skb)
{
	printk(KERN_DEBUG "%s: default_rebuild_header called -- BUG!\n",
	       skb->dev ? skb->dev->name : "NULL!!!");
	kfree_skb(skb);
	return 1;
}


/**
 *	dev_open	- prepare an interface for use.
 *	@dev:	device to open
 *
 *	Takes a device from down to up state. The device's private open
 *	function is invoked and then the multicast lists are loaded. Finally
 *	the device is moved into the up state and a %NETDEV_UP message is
 *	sent to the netdev notifier chain.
 *
 *	Calling this function on an active interface is a nop. On a failure
 *	a negative errno code is returned.
 */
/**
 * 使能网络设备。
 */
int dev_open(struct net_device *dev)
{
	int ret = 0;

	/*
	 *	Is it already up?
	 */

	if (dev->flags & IFF_UP)
		return 0;

	/*
	 *	Is it even present?
	 */
	if (!netif_device_present(dev))
		return -ENODEV;

	/*
	 *	Call device private open method
	 */
	/**
	 * 设置dev->state的__LINK_STATE_START标志位，标记设备打开并在运行。
	 */
	set_bit(__LINK_STATE_START, &dev->state);
	/**
	 * 如果dev->open被定义则调用它。并非所有的驱动程序都初始化这个函数。
	 */
	if (dev->open) {
		ret = dev->open(dev);
		if (ret)
			clear_bit(__LINK_STATE_START, &dev->state);
	}

 	/*
	 *	If it went open OK then:
	 */

	if (!ret) {
		/*
		 *	Set the flags.
		 */
		/**
		 * 设置dev->flags的IFF_UP标志位标记设备启动。
		 */
		dev->flags |= IFF_UP;

		/*
		 *	Initialize multicasting status
		 */
		dev_mc_upload(dev);

		/*
		 *	Wakeup transmit queue engine
		 */
		/**
		 * 调用dev_activate所指函数初始化流量控制用的排队规则，并启动监视定时器。
		 * 如果用户没有配置流量控制，则指定缺省的先进先出(FIFO)队列。
		 */
		dev_activate(dev);

		/*
		 *	... and announce new interface.
		 */
		/**
		 * 发送NETDEV_UP通知给netdev_chain通知链以通知对设备使能有兴趣的内核组件。
		 */
		notifier_call_chain(&netdev_chain, NETDEV_UP, dev);
	}
	return ret;
}

/**
 *	dev_close - shutdown an interface.
 *	@dev: device to shutdown
 *
 *	This function moves an active device into down state. A
 *	%NETDEV_GOING_DOWN is sent to the netdev notifier chain. The device
 *	is then deactivated and finally a %NETDEV_DOWN is sent to the notifier
 *	chain.
 */
/**
 * 禁止一个网络设备。
 */
int dev_close(struct net_device *dev)
{
	if (!(dev->flags & IFF_UP))
		return 0;

	/*
	 *	Tell people we are going down, so that they can
	 *	prepare to death, when device is still operating.
	 */
	/**
	 * 发送NETDEV_GOING_DOWN通知到netdev_chain通知链以通知对设备禁止有兴趣的内核组件。
	 */
	notifier_call_chain(&netdev_chain, NETDEV_GOING_DOWN, dev);

	/**
	 * 调用dev_deactivate函数禁止出口队列规则，这样确保设备不再用于传输，并停止不再需要的监控定时器。
	 */
	dev_deactivate(dev);

	/**
	 * 清除dev->state标志的__LINK_STATE_START标志位，标记设备卸载。
	 */
	clear_bit(__LINK_STATE_START, &dev->state);

	/* Synchronize to scheduled poll. We cannot touch poll list,
	 * it can be even on different cpu. So just clear netif_running(),
	 * and wait when poll really will happen. Actually, the best place
	 * for this is inside dev->stop() after device stopped its irq
	 * engine, but this requires more changes in devices. */

	smp_mb__after_clear_bit(); /* Commit netif_running(). */
	/**
	 * 如果轮询动作被调度在读设备入队列数据包，则等待此动作完成。
	 * 这是由于__LINK_STATE_START 标志位被清除，不再接受其它轮询在设备上调度，但在标志被清除前已有一个轮询正被调度
	 */
	while (test_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}

	/*
	 *	Call the device specific close. This cannot fail.
	 *	Only if device is UP
	 *
	 *	We allow it to be called even after a DETACH hot-plug
	 *	event.
	 */
	/**
	 * 如果dev->stop指针不空则调用它，并非所有的设备驱动都初始化此函数指针。
	 */
	if (dev->stop)
		dev->stop(dev);

	/*
	 *	Device is now down.
	 */
	/**
	 * 清除dev->flags的IFF_UP标志位标识设备关闭。
	 */
	dev->flags &= ~IFF_UP;

	/*
	 * Tell people we are down
	 */
	/**
	 * 发送NETDEV_DOWN通知给netdev_chain通知链，通知对设备禁止感兴趣的内核组件。
	 */
	notifier_call_chain(&netdev_chain, NETDEV_DOWN, dev);

	return 0;
}


/*
 *	Device change register/unregister. These are not inline or static
 *	as we export them to the world.
 */

/**
 *	register_netdevice_notifier - register a network notifier block
 *	@nb: notifier
 *
 *	Register a notifier to be called when network device events occur.
 *	The notifier passed is linked into the kernel structures and must
 *	not be reused until it has been unregistered. A negative errno code
 *	is returned on a failure.
 *
 * 	When registered all registration and up events are replayed
 *	to the new notifier to allow device to have a race free 
 *	view of the network device list.
 */

int register_netdevice_notifier(struct notifier_block *nb)
{
	struct net_device *dev;
	int err;

	rtnl_lock();
	err = notifier_chain_register(&netdev_chain, nb);
	if (!err) {
		for (dev = dev_base; dev; dev = dev->next) {
			nb->notifier_call(nb, NETDEV_REGISTER, dev);

			if (dev->flags & IFF_UP) 
				nb->notifier_call(nb, NETDEV_UP, dev);
		}
	}
	rtnl_unlock();
	return err;
}

/**
 *	unregister_netdevice_notifier - unregister a network notifier block
 *	@nb: notifier
 *
 *	Unregister a notifier previously registered by
 *	register_netdevice_notifier(). The notifier is unlinked into the
 *	kernel structures and may then be reused. A negative errno code
 *	is returned on a failure.
 */

int unregister_netdevice_notifier(struct notifier_block *nb)
{
	return notifier_chain_unregister(&netdev_chain, nb);
}

/**
 *	call_netdevice_notifiers - call all network notifier blocks
 *      @val: value passed unmodified to notifier function
 *      @v:   pointer passed unmodified to notifier function
 *
 *	Call all network notifier blocks.  Parameters and return value
 *	are as for notifier_call_chain().
 */

int call_netdevice_notifiers(unsigned long val, void *v)
{
	return notifier_call_chain(&netdev_chain, val, v);
}

/* When > 0 there are consumers of rx skb time stamps */
static atomic_t netstamp_needed = ATOMIC_INIT(0);

void net_enable_timestamp(void)
{
	atomic_inc(&netstamp_needed);
}

void net_disable_timestamp(void)
{
	atomic_dec(&netstamp_needed);
}

static inline void net_timestamp(struct timeval *stamp)
{
	if (atomic_read(&netstamp_needed))
		do_gettimeofday(stamp);
	else {
		stamp->tv_sec = 0;
		stamp->tv_usec = 0;
	}
}

/*
 *	Support routine. Sends outgoing frames to any network
 *	taps currently in use.
 */

void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
{
	struct packet_type *ptype;
	net_timestamp(&skb->stamp);

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		/* Never send packets back to the socket
		 * they originated from - MvS (miquels@drinkel.ow.org)
		 */
		if ((ptype->dev == dev || !ptype->dev) &&
		    (ptype->af_packet_priv == NULL ||
		     (struct sock *)ptype->af_packet_priv != skb->sk)) {
			struct sk_buff *skb2= skb_clone(skb, GFP_ATOMIC);
			if (!skb2)
				break;

			/* skb->nh should be correctly
			   set by sender, so that the second statement is
			   just protection against buggy protocols.
			 */
			skb2->mac.raw = skb2->data;

			if (skb2->nh.raw < skb2->data ||
			    skb2->nh.raw > skb2->tail) {
				if (net_ratelimit())
					printk(KERN_CRIT "protocol %04x is "
					       "buggy, dev %s\n",
					       skb2->protocol, dev->name);
				skb2->nh.raw = skb2->data;
			}

			skb2->h.raw = skb2->nh.raw;
			skb2->pkt_type = PACKET_OUTGOING;
			ptype->func(skb2, skb->dev, ptype);
		}
	}
	rcu_read_unlock();
}

/*
 * Invalidate hardware checksum when packet is to be mangled, and
 * complete checksum manually on outgoing path.
 */
/**
 * 这个函数有两个不同的行为。依赖于传递参数的是一个入包还是一个出包。
 * 对入包来说，它会使硬件校验和失效。
 * 对出包来说，它计算它的L4校验和。
 */
int skb_checksum_help(struct sk_buff *skb, int inward)
{
	unsigned int csum;
	int ret = 0, offset = skb->h.raw - skb->data;

	if (inward) {
		skb->ip_summed = CHECKSUM_NONE;
		goto out;
	}

	if (skb_cloned(skb)) {
		ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (ret)
			goto out;
	}

	if (offset > (int)skb->len)
		BUG();
	csum = skb_checksum(skb, offset, skb->len-offset, 0);

	offset = skb->tail - skb->h.raw;
	if (offset <= 0)
		BUG();
	if (skb->csum + 2 > offset)
		BUG();

	*(u16*)(skb->h.raw + skb->csum) = csum_fold(csum);
	skb->ip_summed = CHECKSUM_NONE;
out:	
	return ret;
}

#ifdef CONFIG_HIGHMEM
/* Actually, we should eliminate this check as soon as we know, that:
 * 1. IOMMU is present and allows to map all the memory.
 * 2. No high memory really exists on this machine.
 */

static inline int illegal_highdma(struct net_device *dev, struct sk_buff *skb)
{
	int i;

	if (dev->features & NETIF_F_HIGHDMA)
		return 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		if (PageHighMem(skb_shinfo(skb)->frags[i].page))
			return 1;

	return 0;
}
#else
#define illegal_highdma(dev, skb)	(0)
#endif

extern void skb_release_data(struct sk_buff *);

/* Keep head the same: replace data */
/**
 * 将分片组合成一个单一的缓冲区
 * 组合分片涉及到数据拷贝，它将严重影响系统性能。
 */
int __skb_linearize(struct sk_buff *skb, int gfp_mask)
{
	unsigned int size;
	u8 *data;
	long offset;
	struct skb_shared_info *ninfo;
	int headerlen = skb->data - skb->head;
	int expand = (skb->tail + skb->data_len) - skb->end;

	if (skb_shared(skb))
		BUG();

	if (expand <= 0)
		expand = 0;

	size = skb->end - skb->head + expand;
	size = SKB_DATA_ALIGN(size);
	data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
	if (!data)
		return -ENOMEM;

	/* Copy entire thing */
	if (skb_copy_bits(skb, -headerlen, data, headerlen + skb->len))
		BUG();

	/* Set up shinfo */
	ninfo = (struct skb_shared_info*)(data + size);
	atomic_set(&ninfo->dataref, 1);
	ninfo->tso_size = skb_shinfo(skb)->tso_size;
	ninfo->tso_segs = skb_shinfo(skb)->tso_segs;
	ninfo->nr_frags = 0;
	ninfo->frag_list = NULL;

	/* Offset between the two in bytes */
	offset = data - skb->head;

	/* Free old data. */
	skb_release_data(skb);

	skb->head = data;
	skb->end  = data + size;

	/* Set up new pointers */
	skb->h.raw   += offset;
	skb->nh.raw  += offset;
	skb->mac.raw += offset;
	skb->tail    += offset;
	skb->data    += offset;

	/* We are no longer a clone, even if we were. */
	skb->cloned    = 0;

	skb->tail     += skb->data_len;
	skb->data_len  = 0;
	return 0;
}

#define HARD_TX_LOCK(dev, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		spin_lock(&dev->xmit_lock);		\
		dev->xmit_lock_owner = cpu;		\
	}						\
}

#define HARD_TX_UNLOCK(dev) {				\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		dev->xmit_lock_owner = -1;		\
		spin_unlock(&dev->xmit_lock);		\
	}						\
}

/**
 *	dev_queue_xmit - transmit a buffer
 *	@skb: buffer to transmit
 *
 *	Queue a buffer for transmission to a network device. The caller must
 *	have set the device and priority and built the buffer before calling
 *	this function. The function can be called from an interrupt.
 *
 *	A negative errno code is returned on a failure. A success does not
 *	guarantee the frame will be transmitted as it may be dropped due
 *	to congestion or traffic shaping.
 */
/**
 * 发送报文的主函数。dev_queue_xmit能够通过两个路径，导致驱动发送函数hard_start_xmit的执行：
 *		与流量控制的接口（QoS层）：这是通过qdisc_run函数完成的。
 *		直接调用hard_start_xmit：当设备不使用流量控制机制时。
 */
int dev_queue_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct Qdisc *q;
	int rc = -ENOMEM;

	/**
	 * 当skb_shinfo(skb)->frag_list非空时，有效数据是一个分片列表；
	 * 其他情况下，有效数据是单一的块。
	 */
	if (skb_shinfo(skb)->frag_list &&
		/**
		 * 如果分片了，代码检查设备是否支持分散/聚集DMA功能。如果不支持，就自行将分片合并到单一缓冲区。
		 */
	    !(dev->features & NETIF_F_FRAGLIST) &&
	    /**
	     * 合并分片
	     */
	    __skb_linearize(skb, GFP_ATOMIC))
		goto out_kfree_skb;

	/* Fragmented skb is linearized if device does not support SG,
	 * or if at least one of fragments is in highmem and device
	 * does not support DMA from it.
	 */
	/**
	 * 如果报文被分片，并且设备不支持分片发送或者某个分片在高端内存，也需要合并分片。
	 */
	if (skb_shinfo(skb)->nr_frags &&
	    (!(dev->features & NETIF_F_SG) || illegal_highdma(dev, skb)) &&
	    __skb_linearize(skb, GFP_ATOMIC))
		goto out_kfree_skb;

	/* If packet is not checksummed and device does not support
	 * checksumming for this protocol, complete checksumming here.
	 */
	/**
	 * 软件还没有计算校验和。一般情况下，软件不会在之前计算校验和，但是某些情况下，软件会自行计算校验和。
	 */
	if (skb->ip_summed == CHECKSUM_HW &&
		/**
		 * 硬件不支持校验和计算，必须由软件计算。
		 */
	    (!(dev->features & (NETIF_F_HW_CSUM | NETIF_F_NO_CSUM)) &&
	    /**
		 * 硬件只支持IP层的校验和计算，但是报文不是IP协议。
		 */
	     (!(dev->features & NETIF_F_IP_CSUM) ||
	      skb->protocol != htons(ETH_P_IP))))
	      	/**
	      	 * 如果软件计算校验和失败，则退出。
	      	 */
	      	if (skb_checksum_help(skb, 0))
	      		goto out_kfree_skb;

	/* Disable soft irqs for various locks below. Also 
	 * stops preemption for RCU. 
	 */
	local_bh_disable(); 

	/* Updates of qdisc are serialized by queue_lock. 
	 * The struct Qdisc which is pointed to by qdisc is now a 
	 * rcu structure - it may be accessed without acquiring 
	 * a lock (but the structure may be stale.) The freeing of the
	 * qdisc will be deferred until it's known that there are no 
	 * more references to it.
	 * 
	 * If the qdisc has an enqueue function, we still need to 
	 * hold the queue_lock before calling it, since queue_lock
	 * also serializes access to the device queue.
	 */

	/**
	 * 一旦校验和被处理了，所有包头都准备好；下一步就是决定发送哪一个帧。
	 * 此时，后续行为还得看设备是否支持流量控制，如果支持流量控制，存在队列惩罚的问题。
	 * 这也许令人感到奇怪：函数只是处理一个缓冲区（如果必要就进行分片组合及校验和），但是却依赖于队列惩罚。
	 * 视出队列的状态，当前缓冲可能不是下一个需要发送的包。
	 */
	q = rcu_dereference(dev->qdisc);
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = SET_TC_AT(skb->tc_verd,AT_EGRESS);
#endif

	/**
     * 如果存在队列惩罚，那么设备受到dev->qdisc的影响。输入帧由enqueue虚函数进行排队，并且由qdisc_run进行出队和传送
 	 */
	if (q->enqueue) {
		/* Grab device queue */
		/**
		 * 出队和入队都由队列上的queue_lock锁保护。软中断也由local_bh_disable禁止，也通过RCU禁止了抢占。
		 */
		spin_lock(&dev->queue_lock);

		/**
		 * 将包入队。由于队列处罚的原因，disc_run中取出的待发送包并不一定是刚入队的包。
		 */
		rc = q->enqueue(skb, q);

		qdisc_run(dev);

		spin_unlock(&dev->queue_lock);
		rc = rc == NET_XMIT_BYPASS ? NET_XMIT_SUCCESS : rc;
		goto out;
	}

	/* The device has no queue. Common case for software devices:
	   loopback, all the sorts of tunnels...

	   Really, it is unlikely that xmit_lock protection is necessary here.
	   (f.e. loopback and IP tunnels are clean ignoring statistics
	   counters.)
	   However, it is possible, that they rely on protection
	   made by us here.

	   Check this and shot the lock. It is not prone from deadlocks.
	   Either shot noqueue qdisc, it is even simpler 8)
	 */
	/**
	 * 设备没有队列，可能是环回设备这样的设备。
	 * 直接发送它们。
	 */
	if (dev->flags & IFF_UP) {/* 一般都会有这个标志 */
		int cpu = smp_processor_id(); /* ok because BHs are off */

		if (dev->xmit_lock_owner != cpu) {/* 应该不会死锁。 */
			/**
			 * HARD_TX_LOCK使用spin_lock而不是spin_trylock：如果驱动锁被其他CPU获得了，dev_queue_xmit自旋，直到锁被释放。
			 */
			HARD_TX_LOCK(dev, cpu);

			if (!netif_queue_stopped(dev)) {/* 会被停止吗? */
				/**
				 * 回送包。AF_PACKET协议。
				 */
				if (netdev_nit)
					dev_queue_xmit_nit(skb, dev);

				rc = 0;
				/**
				 * 由虚拟设备发送。
				 */
				if (!dev->hard_start_xmit(skb, dev)) {
					HARD_TX_UNLOCK(dev);
					goto out;
				}
			}
			/**
			 * 这以后的状态都是不太正常的。
			 */
			HARD_TX_UNLOCK(dev);
			if (net_ratelimit())
				printk(KERN_CRIT "Virtual device %s asks to "
				       "queue packet!\n", dev->name);
		} else {
			/* Recursion is detected! It is possible,
			 * unfortunately */
			if (net_ratelimit())
				printk(KERN_CRIT "Dead loop on virtual device "
				       "%s, fix it urgently!\n", dev->name);
		}
	}

	rc = -ENETDOWN;
	local_bh_enable();

out_kfree_skb:
	kfree_skb(skb);
	return rc;
out:
	local_bh_enable();
	return rc;
}


/*=======================================================================
			Receiver routines
  =======================================================================*/

/**
 * 使用非NAPI时，每个CPU的输入队列的最大长度。可以通过proc修改。
 * 这个限制应用于非NAPI设备。因为NAPI使用私有队列，设备可以选择各自的最大值。通常是16,32,64。10G以太网驱动driver/net/s2io.c使用更大的值：90。
 */
int netdev_max_backlog = 300;
int weight_p = 64;            /* old backlog weight */
/* These numbers are selected based on intuition and some
 * experimentatiom, if you have more scientific way of doing this
 * please go ahead and fix things.
 */
int no_cong_thresh = 10;
int no_cong = 20;
int lo_cong = 100;
int mod_cong = 290;

DEFINE_PER_CPU(struct netif_rx_stats, netdev_rx_stat) = { 0, };

/**
 * 计算平均队列长度和拥塞级别
 * 每次接收到一个新的帧时，或者在在周期性的定时器中进行计算。
 * 要每次接收到一个新的帧时进行计算，需要定义OFFLINE_SAMPLE。这就是为什么在netif_rx中，执行get_sample_stats依赖于OFFLINE_SAMPLE。默认这是被禁止的
 */
static void get_sample_stats(int cpu)
{
#ifdef RAND_LIE
	unsigned long rd;
	int rq;
#endif
	struct softnet_data *sd = &per_cpu(softnet_data, cpu);
	int blog = sd->input_pkt_queue.qlen;
	int avg_blog = sd->avg_blog;

	/**
	 * 由于本函数经常被调用，因此，利用下面这个简单的公式计算平均长度。
	 */
	avg_blog = (avg_blog >> 1) + (blog >> 1);

	if (avg_blog > mod_cong) {
		/* Above moderate congestion levels. */
		sd->cng_level = NET_RX_CN_HIGH;
		/**
		 * RAND_LIE可以将拥塞级别随机的调高。这样可以随机的丢弃一些入包。
		 * 在多网卡共享输入队列的情况下，可以防止个别网卡将队列阻塞后，导致网卡间的不公平性。
		 */
#ifdef RAND_LIE
		rd = net_random();
		rq = rd % netdev_max_backlog;
		if (rq < avg_blog) /* unlucky bastard */
			sd->cng_level = NET_RX_DROP;
#endif
	} else if (avg_blog > lo_cong) {
		sd->cng_level = NET_RX_CN_MOD;
#ifdef RAND_LIE
		rd = net_random();
		rq = rd % netdev_max_backlog;
			if (rq < avg_blog) /* unlucky bastard */
				sd->cng_level = NET_RX_CN_HIGH;
#endif
	} else if (avg_blog > no_cong)
		sd->cng_level = NET_RX_CN_LOW;
	else  /* no congestion */
		sd->cng_level = NET_RX_SUCCESS;

	sd->avg_blog = avg_blog;
}

#ifdef OFFLINE_SAMPLE
static void sample_queue(unsigned long dummy)
{
/* 10 ms 0r 1ms -- i don't care -- JHS */
	int next_tick = 1;
	int cpu = smp_processor_id();

	get_sample_stats(cpu);
	next_tick += jiffies;
	mod_timer(&samp_timer, next_tick);
}
#endif


/**
 *	netif_rx	-	post buffer to the network code
 *	@skb: buffer to post
 *
 *	This function receives a packet from a device driver and queues it for
 *	the upper (protocol) levels to process.  It always succeeds. The buffer
 *	may be dropped during processing for congestion control or by the
 *	protocol layers.
 *
 *	return values:
 *	NET_RX_SUCCESS	(no congestion)
 *	NET_RX_CN_LOW   (low congestion)
 *	NET_RX_CN_MOD   (moderate congestion)
 *	NET_RX_CN_HIGH  (high congestion)
 *	NET_RX_DROP     (packet was dropped)
 *
 */
/**
 * 在中断中处理多个帧的方法。用于非NAPI驱动。一般运行在中断上下文。
 * 		skb:	接收到的缓冲区。
 * 返回值:		拥塞级别。
 */
int netif_rx(struct sk_buff *skb)
{
	int this_cpu;
	struct softnet_data *queue;
	unsigned long flags;

#ifdef CONFIG_NETPOLL
	/**
	 * 如果netpoll截获此包，则退出。
	 */
	if (skb->dev->netpoll_rx && netpoll_rx(skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
#endif
	/**
	 * 还没有设置包的接收时间，则设置它。
	 */
	if (!skb->stamp.tv_sec)
		/**
		 * net_enable_timestamp表示对有人对时间戳感兴趣，只有这样，才更新stamp。
		 * 这是在net_timestamp中判断的。
		 * 驱动中设置的时间，是针对设备的，并且保存的是tick.
		 */
		net_timestamp(&skb->stamp);

	/*
	 * The code is rearranged so that the path is the most
	 * short when CPU is congested, but is still operating.
	 */
	/**
	 * netif_rx通常由驱动在中断上下文中调用。
	 * 但是也有例外，特别是当回环设备调用这个函数时。
	 * 由于这个原因，netif_rx在运行时禁止本地CPU中断，当它结束时，再重新打开中断。
	 */
	local_irq_save(flags);
	/**
	 * 获取每CPU softnet_data数据结构，并设置计数。
	 */
	this_cpu = smp_processor_id();
	queue = &__get_cpu_var(softnet_data);

	__get_cpu_var(netdev_rx_stat).total++;
	/**
	 * 判断CPU的输入队列是否满了。
	 */
	if (queue->input_pkt_queue.qlen <= netdev_max_backlog) {
		/**
		 * 如果输入队列已经变为拥塞状态了，就丢弃包。
		 */
		if (queue->input_pkt_queue.qlen) {
			if (queue->throttle)
				goto drop;

enqueue:
			/**
			 * 队列还没有拥塞，将包挂入输入队列的尾部。
			 * dev_hold(skb->dev)调用增加设备的引用计数，因此设备不能被删除，直到缓冲被处理。递减计数由dev_put完成，这发生在net_rx_action
			 */
			dev_hold(skb->dev);
			__skb_queue_tail(&queue->input_pkt_queue, skb);
#ifndef OFFLINE_SAMPLE
			/**
			 * Avg_blog和cng_level在get_sample_status中更新
			 */
			get_sample_stats(this_cpu);
#endif
			local_irq_restore(flags);
			/**
			 * 返回当前拥塞级别，外层驱动可以根据此值确定是否在驱动中丢包。
			 */
			return queue->cng_level;
		}

		/**
		 * 当前列队为空，并且当前状态为拥塞状态，则应当将拥塞状态设置为FALSE。
		 * 实际上这基本上不可能发生，因为throttle状态应该在之前就已经设置了。
		 * 第一个帧进入一个空队列时被清除。它也可能在process_backlog中发生。
		 */
		if (queue->throttle)
			queue->throttle = 0;

		/**
		 * 这里会触发软中断处理报文。
		 * 注意：仅当新缓冲区添加到一个空的队列中时，netif_rx_schedule才会被调用。这是因为如果队列非空，NET_RX_SOFTIRQ已经被调度，没有必要再调度它了。
		 */
		netif_rx_schedule(&queue->backlog_dev);
		goto enqueue;
	}

	/**
	 * CPU输入队列已经满了，并且当前状态不是拥塞状态，则设置该状态。
	 * 并将拥塞次数统计加一。然后丢弃包。
	 */
	if (!queue->throttle) {
		queue->throttle = 1;
		__get_cpu_var(netdev_rx_stat).throttled++;
	}

drop:
	/**
	 * 设置丢包数并退出。
	 */
	__get_cpu_var(netdev_rx_stat).dropped++;
	local_irq_restore(flags);

	/**
	 * 释放skb
	 */
	kfree_skb(skb);
	return NET_RX_DROP;
}

/**
 * netif_rx的姊妹函数，它被用于非中断上下文。大多数情况下，它由TUN驱动使用。
 */
int netif_rx_ni(struct sk_buff *skb)
{
	int err;

	preempt_disable();
	err = netif_rx(skb);
	if (local_softirq_pending())
		do_softirq();
	preempt_enable();

	return err;
}

EXPORT_SYMBOL(netif_rx_ni);

static __inline__ void skb_bond(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	if (dev->master) {
		skb->real_dev = skb->dev;
		skb->dev = dev->master;
	}
}

/**
 * 网络包发送软中断。它被设备驱动触发（特定条件下由自己触发）.
 */
static void net_tx_action(struct softirq_action *h)
{
	struct softnet_data *sd = &__get_cpu_var(softnet_data);

	/**
	 * 释放缓冲区。这些缓冲区由驱动通过调用dev_kfree_skb_irq添加到completion_queue链表。
	 */
	if (sd->completion_queue) {
		struct sk_buff *clist;

		/**
		 * 由于net_tx_action运行在非中断上下文，设备驱动可以在任何时间将结点加到链表中，因此在访问softnet_data结构时，net_tx_action必须禁止中断。
		 */
		local_irq_disable();
		/**
		 * 禁止中断的时间应当尽可能的短，它通过设置completion_queue为空来清除链表，并且保存链表指针到一个局部变量clist中。
		 * 这样，没有谁能够访问链表（注意：每个CPU都有它自己的链表）。
		 * 它就能够遍历链表并且通过__kfree_skb释放每个元素，而此时，驱动可以继续向completion_queue中添加新结点。
		 */
		clist = sd->completion_queue;
		sd->completion_queue = NULL;
		local_irq_enable();

		/**
		 * 遍历临时链表中的所有元素，并将sk_buff释放掉。
		 */
		while (clist) {
			struct sk_buff *skb = clist;
			clist = clist->next;

			BUG_TRAP(!atomic_read(&skb->users));
			__kfree_skb(skb);
		}
	}

	/**
	 * 发送帧，它与第一部分类似：也使用一个局部变量。
	 */
	if (sd->output_queue) {
		struct net_device *head;

		local_irq_disable();
		head = sd->output_queue;
		sd->output_queue = NULL;
		local_irq_enable();

		/**
		 * 遍历链表中的所有设备。
		 */
		while (head) {
			struct net_device *dev = head;
			head = head->next_sched;

			smp_mb__before_clear_bit();
			clear_bit(__LINK_STATE_SCHED, &dev->state);

			/**
			 * 注意：对每个设备来说，在开始发送前，函数都需要获得设备队列锁（dev->queue_lock）。
			 * 如果函数不能获得锁（由于其他CPU获得了），它简单的使用netif_schedule重新调度设备发送需求。
			 */
			if (spin_trylock(&dev->queue_lock)) {
				qdisc_run(dev);
				spin_unlock(&dev->queue_lock);
			} else {
				netif_schedule(dev);
			}
		}
	}
}

static __inline__ int deliver_skb(struct sk_buff *skb,
				  struct packet_type *pt_prev)
{
	atomic_inc(&skb->users);
	return pt_prev->func(skb, skb->dev, pt_prev);
}

#if defined(CONFIG_BRIDGE) || defined (CONFIG_BRIDGE_MODULE)
int (*br_handle_frame_hook)(struct net_bridge_port *p, struct sk_buff **pskb);

/**
 * 当接收到包时，处理桥接事情。
 */
static __inline__ int handle_bridge(struct sk_buff **pskb,
				    struct packet_type **pt_prev, int *ret)
{
	struct net_bridge_port *port;

	/**
	 * 发往本地的包，或者接收设备不是网桥设备，则退出。
	 */
	if ((*pskb)->pkt_type == PACKET_LOOPBACK ||
	    (port = rcu_dereference((*pskb)->dev->br_port)) == NULL)
		return 0;

	if (*pt_prev) {
		*ret = deliver_skb(*pskb, *pt_prev);
		*pt_prev = NULL;
	} 

	/**
	 * br_handle_frame_hook钩子用于处理网桥相关的包。它被初始化为br_handle_frame。
	 */
	return br_handle_frame_hook(port, pskb);
}
#else
#define handle_bridge(skb, pt_prev, ret)	(0)
#endif

#ifdef CONFIG_NET_CLS_ACT
/* TODO: Maybe we should just force sch_ingress to be compiled in
 * when CONFIG_NET_CLS_ACT is? otherwise some useless instructions
 * a compare and 2 stores extra right now if we dont have it on
 * but have CONFIG_NET_CLS_ACT
 * NOTE: This doesnt stop any functionality; if you dont have 
 * the ingress scheduler, you just cant add policies on ingress.
 *
 */
static int ing_filter(struct sk_buff *skb) 
{
	struct Qdisc *q;
	struct net_device *dev = skb->dev;
	int result = TC_ACT_OK;
	
	if (dev->qdisc_ingress) {
		__u32 ttl = (__u32) G_TC_RTTL(skb->tc_verd);
		if (MAX_RED_LOOP < ttl++) {
			printk("Redir loop detected Dropping packet (%s->%s)\n",
				skb->input_dev?skb->input_dev->name:"??",skb->dev->name);
			return TC_ACT_SHOT;
		}

		skb->tc_verd = SET_TC_RTTL(skb->tc_verd,ttl);

		skb->tc_verd = SET_TC_AT(skb->tc_verd,AT_INGRESS);
		if (NULL == skb->input_dev) {
			skb->input_dev = skb->dev;
			printk("ing_filter:  fixed  %s out %s\n",skb->input_dev->name,skb->dev->name);
		}
		spin_lock(&dev->ingress_lock);
		if ((q = dev->qdisc_ingress) != NULL)
			result = q->enqueue(skb, q);
		spin_unlock(&dev->ingress_lock);

	}

	return result;
}
#endif

/**
 * 软中断中处理报文的主函数。适用于NAPI和非NAPI。
 */
int netif_receive_skb(struct sk_buff *skb)
{
	struct packet_type *ptype, *pt_prev;
	int ret = NET_RX_DROP;
	unsigned short type;

#ifdef CONFIG_NETPOLL
	if (skb->dev->netpoll_rx && skb->dev->poll && netpoll_rx(skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
#endif

	/**
	 * 这里的处理似乎是多余的，也许是为了与老驱动兼容，但是去掉应该没有问题。
	 */
	if (!skb->stamp.tv_sec)
		net_timestamp(&skb->stamp);

	/**
	 * 绑定功能允许一组网卡能够被组合在一起，并被当成一个单一的网卡进行处理。
	 * 如果接收帧的网卡属于这样的组，sk_buff数据结构中的接口必须必须在netif_receive_skb分发包到L3层处理接口前变成组设备。
	 */
	skb_bond(skb);

	/**
	 * 入帧计数。
	 */
	__get_cpu_var(netdev_rx_stat).total++;

	/**
	 * 初始化L2、L3、L4层协议起始地址。
	 */
	skb->h.raw = skb->nh.raw = skb->data;
	/**
	 * mac长度，L3地址减去L2地址即可。
	 */
	skb->mac_len = skb->nh.raw - skb->mac.raw;

	pt_prev = NULL;

	rcu_read_lock();

#ifdef CONFIG_NET_CLS_ACT
	/**
	 * 这里处理流量控制。
	 */
	if (skb->tc_verd & TC_NCLS) {
		skb->tc_verd = CLR_TC_NCLS(skb->tc_verd);
		goto ncls;
	}
#endif

	/**
	 * ptype_all中的协议处理所有协议类型，一般是嗅探器这类协议。
	 * 这里将包交给它们处理。
	 */
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		if (!ptype->dev || ptype->dev == skb->dev) {
			if (pt_prev) 
				ret = deliver_skb(skb, pt_prev);
			pt_prev = ptype;
		}
	}

#ifdef CONFIG_NET_CLS_ACT
	if (pt_prev) {
		ret = deliver_skb(skb, pt_prev);
		pt_prev = NULL; /* noone else should process this after*/
	} else {
		skb->tc_verd = SET_TC_OK2MUNGE(skb->tc_verd);
	}

	/**
	 * ing_filter用于处理流量控制。
	 */
	ret = ing_filter(skb);

	if (ret == TC_ACT_SHOT || (ret == TC_ACT_STOLEN)) {
		kfree_skb(skb);
		goto out;
	}

	skb->tc_verd = 0;
ncls:
#endif

	/**
	 * 分流允许内核改变帧的L2层原始目标地址，这些帧的目标地址指向其他主机，这样，帧能够被转到本机。内核可以被配置它的标准用法，以决定是否转移帧。它的标准用法有：
 	 * 		所有IP包（不管L4层协议）
 	 *		所有TCP包
 	 *		特定端口上的TCP包。
 	 *		所有UDP包
 	 *		特定端口上的UDP包。
	 * 调用handle_diverter以决定是否改变MAC目的地址。另外，如果改变目标MAC地址的话，skb->pkt_type也必须改变为PACKET_HOST。
	 */
	handle_diverter(skb);

	/**
	 * 处理网桥。
	 * 每一个net_device数据结构有一个指向net_bridge_port的数据结构。
	 * 这被用来存储表示桥接端口的扩展信息。当接口不允许桥接时，它的值为空。
	 * 当一个端口被配置成桥接端口时，内核仅仅关注L2头。
	 */
	if (handle_bridge(&skb, &pt_prev, &ret))
		goto out;

	/**
	 * 将包分发给L3层协议处理。
	 */
	type = skb->protocol;
	list_for_each_entry_rcu(ptype, &ptype_base[ntohs(type)&15], list) {
		if (ptype->type == type &&
		    (!ptype->dev || ptype->dev == skb->dev)) {
			if (pt_prev) 
				ret = deliver_skb(skb, pt_prev);
			pt_prev = ptype;
		}
	}

	if (pt_prev) {
		ret = pt_prev->func(skb, skb->dev, pt_prev);
	} else {
		kfree_skb(skb);
		/* Jamal, now you will not able to escape explaining
		 * me how you were going to use this. :-)
		 */
		ret = NET_RX_DROP;
	}

out:
	rcu_read_unlock();
	return ret;
}

/**
 * 在NAPI架构下，一些旧设备驱动不支持NAPI，仍然将入包放到每CPU多设备共享输入队列中。
 * process_backlog函数作为默认的poll函数，处理共享输入队列中的包。
 * 由于在运行此函数时，中断被打开，所以网卡中断可能打断本函数，而本函数需要访问softnet_data，因此在访问此结构时，需要关中断保护。
 */
static int process_backlog(struct net_device *backlog_dev, int *budget)
{
	int work = 0;
	int quota = min(backlog_dev->quota, *budget);
	struct softnet_data *queue = &__get_cpu_var(softnet_data);
	unsigned long start_time = jiffies;

	/**
	 * 开始主循环，试图从入队列中取出缓冲区并在以下条件之一得到满足时中止循环：
 	*		队列已经为空。
 	*		设备配额已经用完。
 	*		函数运行了足够长的时间。
	 */
	for (;;) {
		struct sk_buff *skb;
		struct net_device *dev;

		/**
		 * 由于要操作共享入包队列，并且多个设备可能产生中断向入队列写包，因此，在操作时，需要关闭中断。
		 * 这是本函数与NAPI设备的poll方法不同之处。
		 */
		local_irq_disable();
		/**
		 * 取出待处理的包。
		 */
		skb = __skb_dequeue(&queue->input_pkt_queue);
		if (!skb)
			goto job_done;
		local_irq_enable();

		dev = skb->dev;

		/**
		 * 处理帧的主函数，不论是NAPI还是非NAPI，都会调用此函数将包传递给上层协议栈处理。
		 */
		netif_receive_skb(skb);

		dev_put(dev);

		work++;

		if (work >= quota || jiffies - start_time > 1)
			break;

	}

	/**
	 * 根据本次处理的包数量，修改设备配额。
	 */
	backlog_dev->quota -= work;
	*budget -= work;
	return -1;

/**
 * 如果入队列已经变空了，主循环跳转到job_done。
 */
job_done:
	backlog_dev->quota -= work;
	*budget -= work;

	/**
	 * 设备将从poll_list中移除。一旦设备入队列中没有任何缓冲需要处理，__LINK_STATE_RX_SCHED标志也被清除，因此它不再被backlog处理过程调度。
	 */
	list_del(&backlog_dev->poll_list);
	smp_mb__before_clear_bit();
	netif_poll_enable(backlog_dev);

	/**
	 * 如果函数运行到这个点，throttle状态将被清除（如果它被设置了）
	 */
	if (queue->throttle)
		queue->throttle = 0;
	local_irq_enable();
	return 0;
}

/**
 * 接收帧的软中断处理函数。
 * 有两个地方的帧等待net_rx_action处理：
 *		共享的特定CPU的队列：非NAPI设备的中断处理将调用netif_rx，将帧放到softnet_data->input_pkt_queue。
 *		设备内存：被NAPI使用的设备poll方法直接从设备（或者驱动的接收缓冲区）中提取帧。
 */
static void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *queue = &__get_cpu_var(softnet_data);
	unsigned long start_time = jiffies;
	int budget = netdev_max_backlog;

	
	local_irq_disable();

	/**
	 * 遍历等待轮询的设备链表。
	 */
	while (!list_empty(&queue->poll_list)) {
		struct net_device *dev;

		/**
		 * 如果当前设备还没有用完它的全部配额，它给予设备一个机会，通过poll函数从队列中取出缓冲区
		 */
		if (budget <= 0 || jiffies - start_time > 1)
			goto softnet_break;

		local_irq_enable();

		/**
 		 * 由于打开中断后，设备驱动只会在poll_list中增加设备，而不会删除。
 		 * 因此，这里取第一个设备是没有问题的。
		 */
		dev = list_entry(queue->poll_list.next,
				 struct net_device, poll_list);

		/**
		 * 如果dev_poll因为设备配置不足以取出所有入队列中的所有缓冲而返回（这种情况下，它返回非0值），设备被移到poll_list的末尾
		 * 它在net_dev_init中被默认的初始化为process_backlog，因为这些设备不使用NAPI。
		 */
		if (dev->quota <= 0 || dev->poll(dev, &budget)) {
			local_irq_disable();
			/**
			 * 将设备移到链表尾部。
			 */
			list_del(&dev->poll_list);
			list_add_tail(&dev->poll_list, &queue->poll_list);
			/**
			 * 重置设备配额。
			 */
			if (dev->quota < 0)
				dev->quota += dev->weight;
			else
				dev->quota = dev->weight;
		} else {
			/**
			 * 当poll代替net_rx_action管理空队列，net_rx_action不从poll_list中移除设备：假定poll已经用netif_rx_complete这样做了
			 * 在软中断中，减少对设备的引用计数。
			 */
			dev_put(dev);
			/**
			 * 需要对链表进行判断了，此处需要关中断。
			 */
			local_irq_disable();
		}
	}
out:
	local_irq_enable();
	return;

softnet_break:
	/**
	 * 此计数表示用完一次总配额，或者超时收包的次数。
	 */
	__get_cpu_var(netdev_rx_stat).time_squeeze++;
	/**
	 * 由于还有设备需要收包，因此触发下一次软中断收包。
	 */
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
	goto out;
}

static gifconf_func_t * gifconf_list [NPROTO];

/**
 *	register_gifconf	-	register a SIOCGIF handler
 *	@family: Address family
 *	@gifconf: Function handler
 *
 *	Register protocol dependent address dumping routines. The handler
 *	that is passed must not be freed or reused until it has been replaced
 *	by another handler.
 */
int register_gifconf(unsigned int family, gifconf_func_t * gifconf)
{
	if (family >= NPROTO)
		return -EINVAL;
	gifconf_list[family] = gifconf;
	return 0;
}


/*
 *	Map an interface index to its name (SIOCGIFNAME)
 */

/*
 *	We need this ioctl for efficient implementation of the
 *	if_indextoname() function required by the IPv6 API.  Without
 *	it, we would have to search all the interfaces to find a
 *	match.  --pb
 */

static int dev_ifname(struct ifreq __user *arg)
{
	struct net_device *dev;
	struct ifreq ifr;

	/*
	 *	Fetch the caller's info block.
	 */

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_index(ifr.ifr_ifindex);
	if (!dev) {
		read_unlock(&dev_base_lock);
		return -ENODEV;
	}

	strcpy(ifr.ifr_name, dev->name);
	read_unlock(&dev_base_lock);

	if (copy_to_user(arg, &ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

/*
 *	Perform a SIOCGIFCONF call. This structure will change
 *	size eventually, and there is nothing I can do about it.
 *	Thus we will need a 'compatibility mode'.
 */

static int dev_ifconf(char __user *arg)
{
	struct ifconf ifc;
	struct net_device *dev;
	char __user *pos;
	int len;
	int total;
	int i;

	/*
	 *	Fetch the caller's info block.
	 */

	if (copy_from_user(&ifc, arg, sizeof(struct ifconf)))
		return -EFAULT;

	pos = ifc.ifc_buf;
	len = ifc.ifc_len;

	/*
	 *	Loop over the interfaces, and write an info block for each.
	 */

	total = 0;
	for (dev = dev_base; dev; dev = dev->next) {
		for (i = 0; i < NPROTO; i++) {
			if (gifconf_list[i]) {
				int done;
				if (!pos)
					done = gifconf_list[i](dev, NULL, 0);
				else
					done = gifconf_list[i](dev, pos + total,
							       len - total);
				if (done < 0)
					return -EFAULT;
				total += done;
			}
		}
  	}

	/*
	 *	All done.  Write the updated control block back to the caller.
	 */
	ifc.ifc_len = total;

	/*
	 * 	Both BSD and Solaris return 0 here, so we do too.
	 */
	return copy_to_user(arg, &ifc, sizeof(struct ifconf)) ? -EFAULT : 0;
}

#ifdef CONFIG_PROC_FS
/*
 *	This is invoked by the /proc filesystem handler to display a device
 *	in detail.
 */
static __inline__ struct net_device *dev_get_idx(loff_t pos)
{
	struct net_device *dev;
	loff_t i;

	for (i = 0, dev = dev_base; dev && i < pos; ++i, dev = dev->next);

	return i == pos ? dev : NULL;
}

void *dev_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock(&dev_base_lock);
	return *pos ? dev_get_idx(*pos - 1) : SEQ_START_TOKEN;
}

void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return v == SEQ_START_TOKEN ? dev_base : ((struct net_device *)v)->next;
}

void dev_seq_stop(struct seq_file *seq, void *v)
{
	read_unlock(&dev_base_lock);
}

static void dev_seq_printf_stats(struct seq_file *seq, struct net_device *dev)
{
	if (dev->get_stats) {
		struct net_device_stats *stats = dev->get_stats(dev);

		seq_printf(seq, "%6s:%8lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu "
				"%8lu %7lu %4lu %4lu %4lu %5lu %7lu %10lu\n",
			   dev->name, stats->rx_bytes, stats->rx_packets,
			   stats->rx_errors,
			   stats->rx_dropped + stats->rx_missed_errors,
			   stats->rx_fifo_errors,
			   stats->rx_length_errors + stats->rx_over_errors +
			     stats->rx_crc_errors + stats->rx_frame_errors,
			   stats->rx_compressed, stats->multicast,
			   stats->tx_bytes, stats->tx_packets,
			   stats->tx_errors, stats->tx_dropped,
			   stats->tx_fifo_errors, stats->collisions,
			   stats->tx_carrier_errors +
			     stats->tx_aborted_errors +
			     stats->tx_window_errors +
			     stats->tx_heartbeat_errors,
			   stats->tx_compressed);
	} else
		seq_printf(seq, "%6s: No statistics available.\n", dev->name);
}

/*
 *	Called from the PROCfs module. This now uses the new arbitrary sized
 *	/proc/net interface to create /proc/net/dev
 */
static int dev_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Inter-|   Receive                            "
			      "                    |  Transmit\n"
			      " face |bytes    packets errs drop fifo frame "
			      "compressed multicast|bytes    packets errs "
			      "drop fifo colls carrier compressed\n");
	else
		dev_seq_printf_stats(seq, v);
	return 0;
}

static struct netif_rx_stats *softnet_get_online(loff_t *pos)
{
	struct netif_rx_stats *rc = NULL;

	while (*pos < NR_CPUS)
	       	if (cpu_online(*pos)) {
			rc = &per_cpu(netdev_rx_stat, *pos);
			break;
		} else
			++*pos;
	return rc;
}

static void *softnet_seq_start(struct seq_file *seq, loff_t *pos)
{
	return softnet_get_online(pos);
}

static void *softnet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return softnet_get_online(pos);
}

static void softnet_seq_stop(struct seq_file *seq, void *v)
{
}

static int softnet_seq_show(struct seq_file *seq, void *v)
{
	struct netif_rx_stats *s = v;

	seq_printf(seq, "%08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		   s->total, s->dropped, s->time_squeeze, s->throttled,
		   s->fastroute_hit, s->fastroute_success, s->fastroute_defer,
		   s->fastroute_deferred_out,
#if 0
		   s->fastroute_latency_reduction
#else
		   s->cpu_collision
#endif
		  );
	return 0;
}

static struct seq_operations dev_seq_ops = {
	.start = dev_seq_start,
	.next  = dev_seq_next,
	.stop  = dev_seq_stop,
	.show  = dev_seq_show,
};

static int dev_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dev_seq_ops);
}

static struct file_operations dev_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = dev_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static struct seq_operations softnet_seq_ops = {
	.start = softnet_seq_start,
	.next  = softnet_seq_next,
	.stop  = softnet_seq_stop,
	.show  = softnet_seq_show,
};

static int softnet_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &softnet_seq_ops);
}

static struct file_operations softnet_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = softnet_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

#ifdef WIRELESS_EXT
extern int wireless_proc_init(void);
#else
#define wireless_proc_init() 0
#endif

static int __init dev_proc_init(void)
{
	int rc = -ENOMEM;

	if (!proc_net_fops_create("dev", S_IRUGO, &dev_seq_fops))
		goto out;
	if (!proc_net_fops_create("softnet_stat", S_IRUGO, &softnet_seq_fops))
		goto out_dev;
	if (wireless_proc_init())
		goto out_softnet;
	rc = 0;
out:
	return rc;
out_softnet:
	proc_net_remove("softnet_stat");
out_dev:
	proc_net_remove("dev");
	goto out;
}
#else
#define dev_proc_init() 0
#endif	/* CONFIG_PROC_FS */


/**
 *	netdev_set_master	-	set up master/slave pair
 *	@slave: slave device
 *	@master: new master device
 *
 *	Changes the master device of the slave. Pass %NULL to break the
 *	bonding. The caller must hold the RTNL semaphore. On a failure
 *	a negative errno code is returned. On success the reference counts
 *	are adjusted, %RTM_NEWLINK is sent to the routing socket and the
 *	function returns zero.
 */
int netdev_set_master(struct net_device *slave, struct net_device *master)
{
	struct net_device *old = slave->master;

	ASSERT_RTNL();

	if (master) {
		if (old)
			return -EBUSY;
		dev_hold(master);
	}

	slave->master = master;
	
	synchronize_net();

	if (old)
		dev_put(old);

	if (master)
		slave->flags |= IFF_SLAVE;
	else
		slave->flags &= ~IFF_SLAVE;

	rtmsg_ifinfo(RTM_NEWLINK, slave, IFF_SLAVE);
	return 0;
}

/**
 *	dev_set_promiscuity	- update promiscuity count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove promsicuity from a device. While the count in the device
 *	remains above zero the interface remains promiscuous. Once it hits zero
 *	the device reverts back to normal filtering operation. A negative inc
 *	value is used to drop promiscuity on the device.
 */
void dev_set_promiscuity(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;

	dev->flags |= IFF_PROMISC;
	if ((dev->promiscuity += inc) == 0)
		dev->flags &= ~IFF_PROMISC;
	if (dev->flags ^ old_flags) {
		dev_mc_upload(dev);
		printk(KERN_INFO "device %s %s promiscuous mode\n",
		       dev->name, (dev->flags & IFF_PROMISC) ? "entered" :
		       					       "left");
	}
}

/**
 *	dev_set_allmulti	- update allmulti count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove reception of all multicast frames to a device. While the
 *	count in the device remains above zero the interface remains listening
 *	to all interfaces. Once it hits zero the device reverts back to normal
 *	filtering operation. A negative @inc value is used to drop the counter
 *	when releasing a resource needing all multicasts.
 */
/**
 * 通知设备开始或者停止监听所有的多播地址
 */
void dev_set_allmulti(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;

	dev->flags |= IFF_ALLMULTI;
	if ((dev->allmulti += inc) == 0)
		dev->flags &= ~IFF_ALLMULTI;
	if (dev->flags ^ old_flags)
		dev_mc_upload(dev);
}

unsigned dev_get_flags(const struct net_device *dev)
{
	unsigned flags;

	flags = (dev->flags & ~(IFF_PROMISC |
				IFF_ALLMULTI |
				IFF_RUNNING)) | 
		(dev->gflags & (IFF_PROMISC |
				IFF_ALLMULTI));

	if (netif_running(dev) && netif_carrier_ok(dev))
		flags |= IFF_RUNNING;

	return flags;
}
/**
 * 通过dev_change_flags函数修改网络设备的标记。
 */
int dev_change_flags(struct net_device *dev, unsigned flags)
{
	int ret;
	int old_flags = dev->flags;

	/*
	 *	Set the flags on our device.
	 */

	dev->flags = (flags & (IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
			       IFF_DYNAMIC | IFF_MULTICAST | IFF_PORTSEL |
			       IFF_AUTOMEDIA)) |
		     (dev->flags & (IFF_UP | IFF_VOLATILE | IFF_PROMISC |
				    IFF_ALLMULTI));

	/*
	 *	Load in the correct multicast list now the flags have changed.
	 */

	dev_mc_upload(dev);

	/*
	 *	Have we downed the interface. We handle IFF_UP ourselves
	 *	according to user attempts to set it, rather than blindly
	 *	setting it.
	 */

	ret = 0;
	if ((old_flags ^ flags) & IFF_UP) {	/* Bit is different  ? */
		ret = ((old_flags & IFF_UP) ? dev_close : dev_open)(dev);

		if (!ret)
			dev_mc_upload(dev);
	}

	if (dev->flags & IFF_UP &&
	    ((old_flags ^ dev->flags) &~ (IFF_UP | IFF_PROMISC | IFF_ALLMULTI |
					  IFF_VOLATILE)))
		notifier_call_chain(&netdev_chain, NETDEV_CHANGE, dev);

	if ((flags ^ dev->gflags) & IFF_PROMISC) {
		int inc = (flags & IFF_PROMISC) ? +1 : -1;
		dev->gflags ^= IFF_PROMISC;
		dev_set_promiscuity(dev, inc);
	}

	/* NOTE: order of synchronization of IFF_PROMISC and IFF_ALLMULTI
	   is important. Some (broken) drivers set IFF_PROMISC, when
	   IFF_ALLMULTI is requested not asking us and not reporting.
	 */
	if ((flags ^ dev->gflags) & IFF_ALLMULTI) {
		int inc = (flags & IFF_ALLMULTI) ? +1 : -1;
		dev->gflags ^= IFF_ALLMULTI;
		dev_set_allmulti(dev, inc);
	}

	if (old_flags ^ dev->flags)
		rtmsg_ifinfo(RTM_NEWLINK, dev, old_flags ^ dev->flags);

	return ret;
}

int dev_set_mtu(struct net_device *dev, int new_mtu)
{
	int err;

	if (new_mtu == dev->mtu)
		return 0;

	/*	MTU must be positive.	 */
	if (new_mtu < 0)
		return -EINVAL;

	if (!netif_device_present(dev))
		return -ENODEV;

	err = 0;
	if (dev->change_mtu)
		err = dev->change_mtu(dev, new_mtu);
	else
		dev->mtu = new_mtu;
	if (!err && dev->flags & IFF_UP)
		notifier_call_chain(&netdev_chain,
				    NETDEV_CHANGEMTU, dev);
	return err;
}


/*
 *	Perform the SIOCxIFxxx calls.
 */
static int dev_ifsioc(struct ifreq *ifr, unsigned int cmd)
{
	int err;
	struct net_device *dev = __dev_get_by_name(ifr->ifr_name);

	if (!dev)
		return -ENODEV;

	switch (cmd) {
		case SIOCGIFFLAGS:	/* Get interface flags */
			ifr->ifr_flags = dev_get_flags(dev);
			return 0;

		case SIOCSIFFLAGS:	/* Set interface flags */
			return dev_change_flags(dev, ifr->ifr_flags);

		case SIOCGIFMETRIC:	/* Get the metric on the interface
					   (currently unused) */
			ifr->ifr_metric = 0;
			return 0;

		case SIOCSIFMETRIC:	/* Set the metric on the interface
					   (currently unused) */
			return -EOPNOTSUPP;

		case SIOCGIFMTU:	/* Get the MTU of a device */
			ifr->ifr_mtu = dev->mtu;
			return 0;

		case SIOCSIFMTU:	/* Set the MTU of a device */
			return dev_set_mtu(dev, ifr->ifr_mtu);

		case SIOCGIFHWADDR:
			if (!dev->addr_len)
				memset(ifr->ifr_hwaddr.sa_data, 0, sizeof ifr->ifr_hwaddr.sa_data);
			else
				memcpy(ifr->ifr_hwaddr.sa_data, dev->dev_addr,
				       min(sizeof ifr->ifr_hwaddr.sa_data, (size_t) dev->addr_len));
			ifr->ifr_hwaddr.sa_family = dev->type;
			return 0;

		case SIOCSIFHWADDR:
			if (!dev->set_mac_address)
				return -EOPNOTSUPP;
			if (ifr->ifr_hwaddr.sa_family != dev->type)
				return -EINVAL;
			if (!netif_device_present(dev))
				return -ENODEV;
			err = dev->set_mac_address(dev, &ifr->ifr_hwaddr);
			if (!err)
				notifier_call_chain(&netdev_chain,
						    NETDEV_CHANGEADDR, dev);
			return err;

		case SIOCSIFHWBROADCAST:
			if (ifr->ifr_hwaddr.sa_family != dev->type)
				return -EINVAL;
			memcpy(dev->broadcast, ifr->ifr_hwaddr.sa_data,
			       min(sizeof ifr->ifr_hwaddr.sa_data, (size_t) dev->addr_len));
			notifier_call_chain(&netdev_chain,
					    NETDEV_CHANGEADDR, dev);
			return 0;

		case SIOCGIFMAP:
			ifr->ifr_map.mem_start = dev->mem_start;
			ifr->ifr_map.mem_end   = dev->mem_end;
			ifr->ifr_map.base_addr = dev->base_addr;
			ifr->ifr_map.irq       = dev->irq;
			ifr->ifr_map.dma       = dev->dma;
			ifr->ifr_map.port      = dev->if_port;
			return 0;

		case SIOCSIFMAP:
			if (dev->set_config) {
				if (!netif_device_present(dev))
					return -ENODEV;
				return dev->set_config(dev, &ifr->ifr_map);
			}
			return -EOPNOTSUPP;

		case SIOCADDMULTI:
			if (!dev->set_multicast_list ||
			    ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
				return -EINVAL;
			if (!netif_device_present(dev))
				return -ENODEV;
			return dev_mc_add(dev, ifr->ifr_hwaddr.sa_data,
					  dev->addr_len, 1);

		case SIOCDELMULTI:
			if (!dev->set_multicast_list ||
			    ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
				return -EINVAL;
			if (!netif_device_present(dev))
				return -ENODEV;
			return dev_mc_delete(dev, ifr->ifr_hwaddr.sa_data,
					     dev->addr_len, 1);

		case SIOCGIFINDEX:
			ifr->ifr_ifindex = dev->ifindex;
			return 0;

		case SIOCGIFTXQLEN:
			ifr->ifr_qlen = dev->tx_queue_len;
			return 0;

		case SIOCSIFTXQLEN:
			if (ifr->ifr_qlen < 0)
				return -EINVAL;
			dev->tx_queue_len = ifr->ifr_qlen;
			return 0;

		case SIOCSIFNAME:
			ifr->ifr_newname[IFNAMSIZ-1] = '\0';
			return dev_change_name(dev, ifr->ifr_newname);

		/*
		 *	Unknown or private ioctl
		 */

		default:
			if ((cmd >= SIOCDEVPRIVATE &&
			    cmd <= SIOCDEVPRIVATE + 15) ||
			    cmd == SIOCBONDENSLAVE ||
			    cmd == SIOCBONDRELEASE ||
			    cmd == SIOCBONDSETHWADDR ||
			    cmd == SIOCBONDSLAVEINFOQUERY ||
			    cmd == SIOCBONDINFOQUERY ||
			    cmd == SIOCBONDCHANGEACTIVE ||
			    cmd == SIOCGMIIPHY ||
			    cmd == SIOCGMIIREG ||
			    cmd == SIOCSMIIREG ||
			    cmd == SIOCBRADDIF ||
			    cmd == SIOCBRDELIF ||
			    cmd == SIOCWANDEV) {
				err = -EOPNOTSUPP;
				if (dev->do_ioctl) {
					if (netif_device_present(dev))
						err = dev->do_ioctl(dev, ifr,
								    cmd);
					else
						err = -ENODEV;
				}
			} else
				err = -EINVAL;

	}
	return err;
}

/*
 *	This function handles all "interface"-type I/O control requests. The actual
 *	'doing' part of this is dev_ifsioc above.
 */

/**
 *	dev_ioctl	-	network device ioctl
 *	@cmd: command to issue
 *	@arg: pointer to a struct ifreq in user space
 *
 *	Issue ioctl functions to devices. This is normally called by the
 *	user space syscall interfaces but can sometimes be useful for
 *	other purposes. The return value is the return from the syscall if
 *	positive or a negative errno code on error.
 */

int dev_ioctl(unsigned int cmd, void __user *arg)
{
	struct ifreq ifr;
	int ret;
	char *colon;

	/* One special case: SIOCGIFCONF takes ifconf argument
	   and requires shared lock, because it sleeps writing
	   to user space.
	 */

	if (cmd == SIOCGIFCONF) {
		rtnl_shlock();
		ret = dev_ifconf((char __user *) arg);
		rtnl_shunlock();
		return ret;
	}
	if (cmd == SIOCGIFNAME)
		return dev_ifname((struct ifreq __user *)arg);

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	ifr.ifr_name[IFNAMSIZ-1] = 0;

	colon = strchr(ifr.ifr_name, ':');
	if (colon)
		*colon = 0;

	/*
	 *	See which interface the caller is talking about.
	 */

	switch (cmd) {
		/*
		 *	These ioctl calls:
		 *	- can be done by all.
		 *	- atomic and do not require locking.
		 *	- return a value
		 */
		case SIOCGIFFLAGS:
		case SIOCGIFMETRIC:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
		case SIOCGIFSLAVE:
		case SIOCGIFMAP:
		case SIOCGIFINDEX:
		case SIOCGIFTXQLEN:
			dev_load(ifr.ifr_name);
			read_lock(&dev_base_lock);
			ret = dev_ifsioc(&ifr, cmd);
			read_unlock(&dev_base_lock);
			if (!ret) {
				if (colon)
					*colon = ':';
				if (copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
					ret = -EFAULT;
			}
			return ret;

		case SIOCETHTOOL:
			dev_load(ifr.ifr_name);
			rtnl_lock();
			ret = dev_ethtool(&ifr);
			rtnl_unlock();
			if (!ret) {
				if (colon)
					*colon = ':';
				if (copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
					ret = -EFAULT;
			}
			return ret;

		/*
		 *	These ioctl calls:
		 *	- require superuser power.
		 *	- require strict serialization.
		 *	- return a value
		 */
		case SIOCGMIIPHY:
		case SIOCGMIIREG:
		case SIOCSIFNAME:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			dev_load(ifr.ifr_name);
			rtnl_lock();
			ret = dev_ifsioc(&ifr, cmd);
			rtnl_unlock();
			if (!ret) {
				if (colon)
					*colon = ':';
				if (copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
					ret = -EFAULT;
			}
			return ret;

		/*
		 *	These ioctl calls:
		 *	- require superuser power.
		 *	- require strict serialization.
		 *	- do not return a value
		 */
		case SIOCSIFFLAGS:
		case SIOCSIFMETRIC:
		case SIOCSIFMTU:
		case SIOCSIFMAP:
		case SIOCSIFHWADDR:
		case SIOCSIFSLAVE:
		case SIOCADDMULTI:
		case SIOCDELMULTI:
		case SIOCSIFHWBROADCAST:
		case SIOCSIFTXQLEN:
		case SIOCSMIIREG:
		case SIOCBONDENSLAVE:
		case SIOCBONDRELEASE:
		case SIOCBONDSETHWADDR:
		case SIOCBONDSLAVEINFOQUERY:
		case SIOCBONDINFOQUERY:
		case SIOCBONDCHANGEACTIVE:
		case SIOCBRADDIF:
		case SIOCBRDELIF:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			dev_load(ifr.ifr_name);
			rtnl_lock();
			ret = dev_ifsioc(&ifr, cmd);
			rtnl_unlock();
			return ret;

		case SIOCGIFMEM:
			/* Get the per device memory space. We can add this but
			 * currently do not support it */
		case SIOCSIFMEM:
			/* Set the per device memory buffer space.
			 * Not applicable in our case */
		case SIOCSIFLINK:
			return -EINVAL;

		/*
		 *	Unknown or private ioctl.
		 */
		default:
			if (cmd == SIOCWANDEV ||
			    (cmd >= SIOCDEVPRIVATE &&
			     cmd <= SIOCDEVPRIVATE + 15)) {
				dev_load(ifr.ifr_name);
				rtnl_lock();
				ret = dev_ifsioc(&ifr, cmd);
				rtnl_unlock();
				if (!ret && copy_to_user(arg, &ifr,
							 sizeof(struct ifreq)))
					ret = -EFAULT;
				return ret;
			}
#ifdef WIRELESS_EXT
			/* Take care of Wireless Extensions */
			if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {
				/* If command is `set a parameter', or
				 * `get the encoding parameters', check if
				 * the user has the right to do it */
				if (IW_IS_SET(cmd) || cmd == SIOCGIWENCODE) {
					if (!capable(CAP_NET_ADMIN))
						return -EPERM;
				}
				dev_load(ifr.ifr_name);
				rtnl_lock();
				/* Follow me in net/core/wireless.c */
				ret = wireless_process_ioctl(&ifr, cmd);
				rtnl_unlock();
				if (IW_IS_GET(cmd) &&
				    copy_to_user(arg, &ifr,
					    	 sizeof(struct ifreq)))
					ret = -EFAULT;
				return ret;
			}
#endif	/* WIRELESS_EXT */
			return -EINVAL;
	}
}


/**
 *	dev_new_index	-	allocate an ifindex
 *
 *	Returns a suitable unique value for a new device interface
 *	number.  The caller must hold the rtnl semaphore or the
 *	dev_base_lock to be sure it remains unique.
 */
static int dev_new_index(void)
{
	static int ifindex;
	for (;;) {
		if (++ifindex <= 0)
			ifindex = 1;
		if (!__dev_get_by_index(ifindex))
			return ifindex;
	}
}

/**
 * net_dev_init子系统函数是否已经执行。
 */
static int dev_boot_phase = 1;

/* Delayed registration/unregisteration */
static DEFINE_SPINLOCK(net_todo_list_lock);
static struct list_head net_todo_list = LIST_HEAD_INIT(net_todo_list);

static inline void net_set_todo(struct net_device *dev)
{
	spin_lock(&net_todo_list_lock);
	list_add_tail(&dev->todo_list, &net_todo_list);
	spin_unlock(&net_todo_list_lock);
}

/**
 *	register_netdevice	- register a network device
 *	@dev: device to register
 *
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	Callers must hold the rtnl semaphore. You may want
 *	register_netdev() instead of this.
 *
 *	BUGS:
 *	The locking appears insufficient to guarantee two parallel registers
 *	will not get the same name.
 */
/**
 * 网络设备注册
 */
int register_netdevice(struct net_device *dev)
{
	struct hlist_head *head;
	struct hlist_node *p;
	int ret;

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	/* When net_device's are persistent, this will be fatal. */
	BUG_ON(dev->reg_state != NETREG_UNINITIALIZED);

	/**
	 * net_device的部分域的初始化，包括用于锁操作的域
	 */
	spin_lock_init(&dev->queue_lock);
	spin_lock_init(&dev->xmit_lock);
	dev->xmit_lock_owner = -1;
#ifdef CONFIG_NET_CLS_ACT
	spin_lock_init(&dev->ingress_lock);
#endif

	/**
	 * 当内核支持转向特性时，分配一个特性需要的配置块，并连接到dev->divert，这是由alloc_divert_blk函数来实现的。
	 */
	ret = alloc_divert_blk(dev);
	if (ret)
		goto out;

	dev->iflink = -1;

	/* Init, if this function is available */
	/**
	 * 如果设备驱动程序提供了初始化函数(dev->init!=NULL)，则执行次函数。可参考"虚拟设备"一节。
	 */
	if (dev->init) {
		ret = dev->init(dev);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			goto out_err;
		}
	}
 
	if (!dev_valid_name(dev->name)) {
		ret = -EINVAL;
		goto out_err;
	}

	/**
	 * 用dev_new_index函数给设备分配一个唯一标识符。标识符由一个计数器生产，每次一个新设备加到系统中计数器就会递增。
	 * 计数器是32位变量，所以dev_new_index函数中有一个if子句用于回绕，还有一个if子句处理变量赋值为已经指派的值。
	 */
	dev->ifindex = dev_new_index();
	if (dev->iflink == -1)
		dev->iflink = dev->ifindex;

	/* Check for existence of name */
	head = dev_name_hash(dev->name);
	hlist_for_each(p, head) {
		struct net_device *d
			= hlist_entry(p, struct net_device, name_hlist);
		if (!strncmp(d->name, dev->name, IFNAMSIZ)) {
			ret = -EEXIST;
 			goto out_err;
		}
 	}

	/* Fix illegal SG+CSUM combinations. */
	/**
	 * 检测特性标志是否是有效的组合,例如: 
	 *		1.  Scather/Gather-DMA没有L4(传输层)硬件校验和支持则是无用的,所以在这种情况下被禁止。
	 *		2.  TCP Segmentation Offload (TSO)需要Scather/Gather-DMA，所以在后者不支持时也被禁止
	 */
	if ((dev->features & NETIF_F_SG) &&
	    !(dev->features & (NETIF_F_IP_CSUM |
			       NETIF_F_NO_CSUM |
			       NETIF_F_HW_CSUM))) {
		printk("%s: Dropping NETIF_F_SG since no checksum feature.\n",
		       dev->name);
		dev->features &= ~NETIF_F_SG;
	}

	/* TSO requires that SG is present as well. */
	if ((dev->features & NETIF_F_TSO) &&
	    !(dev->features & NETIF_F_SG)) {
		printk("%s: Dropping NETIF_F_TSO since no SG feature.\n",
		       dev->name);
		dev->features &= ~NETIF_F_TSO;
	}

	/*
	 *	nil rebuild_header routine,
	 *	that should be never called and used as just bug trap.
	 */

	if (!dev->rebuild_header)
		dev->rebuild_header = default_rebuild_header;

	/*
	 *	Default initial state at registry is that the
	 *	device is present.
	 */
	/**
	 * 设置dev->state中的__LINK_STATE_PRESENT 标志使设备对系统使可用的(可见和可用)。
	 * 例如，当一个热拔插设备被拔出，或者当支持电源管理的系统进入挂起模式时，这个设备标志被清除。
	 */
	set_bit(__LINK_STATE_PRESENT, &dev->state);

	dev->next = NULL;
	/**
	 * 初始化设备队列规则，用流量控制通过dev_init_scheduler实现QoS，队列规则定义了出口包如何入队列和从出口队列出队列，还定义了各种包在开始丢弃它们之前如何排队
	 */
	dev_init_scheduler(dev);
	/**
	 * 追加net_device到全局链表dev_base,并把它插入到两个哈希表中。
	 * 虽然把结构加到dev_base链表头很快,但内核偶尔也会扫描整个链表来检测相同的设备名。
	 * 设备名由dev_valid_name函数检测是否是有效的名字。
	 */
	write_lock_bh(&dev_base_lock);
	*dev_tail = dev;
	dev_tail = &dev->next;
	hlist_add_head(&dev->name_hlist, head);
	hlist_add_head(&dev->index_hlist, dev_index_hash(dev->ifindex));
	dev_hold(dev);
	dev->reg_state = NETREG_REGISTERING;
	write_unlock_bh(&dev_base_lock);

	/* Notify protocols, that a new device appeared. */
	/**
	 * 由netdev_chain通知链通知所有对设备注册感兴趣的子系统
	 */
	notifier_call_chain(&netdev_chain, NETDEV_REGISTER, dev);

	/* Finish registration after unlock */
	/**
	 * 当netdev_run_todo被调用以结束注册时，它仅更新dev->reg_state并在sysfs文件系统注册设备。
	 */
	net_set_todo(dev);
	ret = 0;

out:
	return ret;
out_err:
	free_divert_blk(dev);
	goto out;
}

/**
 *	register_netdev	- register a network device
 *	@dev: device to register
 *
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	This is a wrapper around register_netdev that takes the rtnl semaphore
 *	and expands the device name if you passed a format string to
 *	alloc_netdev.
 */
/**
 * 注册网络设备。
 */
int register_netdev(struct net_device *dev)
{
	int err;

	rtnl_lock();

	/*
	 * If the name is a format string the caller wants us to do a
	 * name allocation.
	 */
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto out;
	}
	
	/*
	 * Back compatibility hook. Kill this one in 2.5
	 */
	if (dev->name[0] == 0 || dev->name[0] == ' ') {
		err = dev_alloc_name(dev, "eth%d");
		if (err < 0)
			goto out;
	}

	err = register_netdevice(dev);
out:
	rtnl_unlock();
	return err;
}
EXPORT_SYMBOL(register_netdev);

/*
 * netdev_wait_allrefs - wait until all references are gone.
 *
 * This is called when unregistering network devices.
 *
 * Any protocol or device that holds a reference should register
 * for netdevice notification, and cleanup and put back the
 * reference if they receive an UNREGISTER event.
 * We can get stuck here if buggy protocols don't correctly
 * call dev_put. 
 */
/**
 * unregister_netdevice启动注销处理过程，并让netdev_run_todo结束它。
 * netdev_run_todo调用netdev_wait_allrefs函数等待所有对net_device 结构的引用释放
 */
static void netdev_wait_allrefs(struct net_device *dev)
{
	unsigned long rebroadcast_time, warning_time;

	rebroadcast_time = warning_time = jiffies;
	/**
	 * 循环等待，仅当dev->refcnt 值减到0时结束。
	 * 这里需要等待，主要是考虑到有些定时器中会释放对结构的引用。
	 */
	while (atomic_read(&dev->refcnt) != 0) {
		/**
		 * 每秒发送一个NETDEV_UNREGISTER通知。
		 */
		if (time_after(jiffies, rebroadcast_time + 1 * HZ)) {
			rtnl_shlock();

			/* Rebroadcast unregister notification */
			notifier_call_chain(&netdev_chain,
					    NETDEV_UNREGISTER, dev);

			if (test_bit(__LINK_STATE_LINKWATCH_PENDING,
				     &dev->state)) {
				/* We must not have linkwatch events
				 * pending on unregister. If this
				 * happens, we simply run the queue
				 * unscheduled, resulting in a noop
				 * for this device.
				 */
				linkwatch_run_queue();
			}

			rtnl_shunlock();

			rebroadcast_time = jiffies;
		}

		msleep(250);

		/**
		 * 每10秒朝控制台发送一个警告。
		 */
		if (time_after(jiffies, warning_time + 10 * HZ)) {
			printk(KERN_EMERG "unregister_netdevice: "
			       "waiting for %s to become free. Usage "
			       "count = %d\n",
			       dev->name, atomic_read(&dev->refcnt));
			warning_time = jiffies;
		}
	}
}

/* The sequence is:
 *
 *	rtnl_lock();
 *	...
 *	register_netdevice(x1);
 *	register_netdevice(x2);
 *	...
 *	unregister_netdevice(y1);
 *	unregister_netdevice(y2);
 *      ...
 *	rtnl_unlock();
 *	free_netdev(y1);
 *	free_netdev(y2);
 *
 * We are invoked by rtnl_unlock() after it drops the semaphore.
 * This allows us to deal with problems:
 * 1) We can create/delete sysfs objects which invoke hotplug
 *    without deadlocking with linkwatch via keventd.
 * 2) Since we run with the RTNL semaphore not held, we can sleep
 *    safely in order to wait for the netdev refcnt to drop to zero.
 */
static DECLARE_MUTEX(net_todo_run_mutex);
void netdev_run_todo(void)
{
	struct list_head list = LIST_HEAD_INIT(list);
	int err;


	/* Need to guard against multiple cpu's getting out of order. */
	down(&net_todo_run_mutex);

	/* Not safe to do outside the semaphore.  We must not return
	 * until all unregister events invoked by the local processor
	 * have been completed (either by this todo run, or one on
	 * another cpu).
	 */
	if (list_empty(&net_todo_list))
		goto out;

	/* Snapshot list, allow later requests */
	spin_lock(&net_todo_list_lock);
	list_splice_init(&net_todo_list, &list);
	spin_unlock(&net_todo_list_lock);
		
	while (!list_empty(&list)) {
		struct net_device *dev
			= list_entry(list.next, struct net_device, todo_list);
		list_del(&dev->todo_list);

		switch(dev->reg_state) {
		case NETREG_REGISTERING:
			err = netdev_register_sysfs(dev);
			if (err)
				printk(KERN_ERR "%s: failed sysfs registration (%d)\n",
				       dev->name, err);
			dev->reg_state = NETREG_REGISTERED;
			break;

		case NETREG_UNREGISTERING:
			netdev_unregister_sysfs(dev);
			dev->reg_state = NETREG_UNREGISTERED;

			netdev_wait_allrefs(dev);

			/* paranoia */
			BUG_ON(atomic_read(&dev->refcnt));
			BUG_TRAP(!dev->ip_ptr);
			BUG_TRAP(!dev->ip6_ptr);
			BUG_TRAP(!dev->dn_ptr);


			/* It must be the very last action, 
			 * after this 'dev' may point to freed up memory.
			 */
			if (dev->destructor)
				dev->destructor(dev);
			break;

		default:
			printk(KERN_ERR "network todo '%s' but state %d\n",
			       dev->name, dev->reg_state);
			break;
		}
	}

out:
	up(&net_todo_run_mutex);
}

/**
 *	alloc_netdev - allocate network device
 *	@sizeof_priv:	size of private data to allocate space for
 *	@name:		device name format string
 *	@setup:		callback to initialize device
 *
 *	Allocates a struct net_device with private data area for driver use
 *	and performs basic initialization.
 */
/**
 * 为net_device分配空间。
 *		 	sizeof_priv:	私有数据结构大小
 *			name:			设备名
 *			setup:		 	配置函数,这个函数用于初始化net_device结构的部分域
 * 返回值是alloc_netdev函数分配的net_device的结构指针，如果出错就返回NULL。
 */
struct net_device *alloc_netdev(int sizeof_priv, const char *name,
		void (*setup)(struct net_device *))
{
	void *p;
	struct net_device *dev;
	int alloc_size;

	/* ensure 32-byte alignment of both the device and private area */
	alloc_size = (sizeof(*dev) + NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST;
	alloc_size += sizeof_priv + NETDEV_ALIGN_CONST;

	p = kmalloc(alloc_size, GFP_KERNEL);
	if (!p) {
		printk(KERN_ERR "alloc_dev: Unable to allocate device.\n");
		return NULL;
	}
	memset(p, 0, alloc_size);

	dev = (struct net_device *)
		(((long)p + NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST);
	dev->padded = (char *)dev - (char *)p;

	if (sizeof_priv)
		dev->priv = netdev_priv(dev);

	setup(dev);
	strcpy(dev->name, name);
	return dev;
}
EXPORT_SYMBOL(alloc_netdev);

/**
 *	free_netdev - free network device
 *	@dev: device
 *
 *	This function does the last stage of destroying an allocated device 
 * 	interface. The reference to the device object is released.  
 *	If this is the last reference then it will be freed.
 */
void free_netdev(struct net_device *dev)
{
#ifdef CONFIG_SYSFS
	/*  Compatiablity with error handling in drivers */
	if (dev->reg_state == NETREG_UNINITIALIZED) {
		kfree((char *)dev - dev->padded);
		return;
	}

	BUG_ON(dev->reg_state != NETREG_UNREGISTERED);
	dev->reg_state = NETREG_RELEASED;

	/* will free via class release */
	class_device_put(&dev->class_dev);
#else
	kfree((char *)dev - dev->padded);
#endif
}
 
/* Synchronize with packet receive processing. */
void synchronize_net(void) 
{
	might_sleep();
	synchronize_kernel();
}

/**
 *	unregister_netdevice - remove device from the kernel
 *	@dev: device
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables. On success 0 is returned, on a failure
 *	a negative errno code is returned.
 *
 *	Callers must hold the rtnl semaphore.  You may want
 *	unregister_netdev() instead of this.
 */
/**
 * 注销网络设备
 */
int unregister_netdevice(struct net_device *dev)
{
	struct net_device *d, **dp;

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	/* Some devices call without registering for initialization unwind. */
	if (dev->reg_state == NETREG_UNINITIALIZED) {
		printk(KERN_DEBUG "unregister_netdevice: device %s/%p never "
				  "was registered\n", dev->name, dev);
		return -ENODEV;
	}

	BUG_ON(dev->reg_state != NETREG_REGISTERED);

	/* If device is running, close it first. */
	/**
	 * 如果设备没有被禁止，则首先由dev_close禁止它
	 */
	if (dev->flags & IFF_UP)
		dev_close(dev);

	/* And unlink it from device chain. */
	/**
	 * net_device实例从全局链表dev_base中移除，同时，"net_device结构组织"一节中介绍的两个哈希表也被移除。
	 * 注意这样并不能阻止内核子系统使用设备：它们仍然拥有指向net_device结构的指针。
	 * 这就是net_device结构使用引用计数以获取结构还有多少引用的原因
	 */
	for (dp = &dev_base; (d = *dp) != NULL; dp = &d->next) {
		if (d == dev) {
			write_lock_bh(&dev_base_lock);
			hlist_del(&dev->name_hlist);
			hlist_del(&dev->index_hlist);
			if (dev_tail == &dev->next)
				dev_tail = dp;
			*dp = d->next;
			write_unlock_bh(&dev_base_lock);
			break;
		}
	}
	if (!d) {
		printk(KERN_ERR "unregister net_device: '%s' not found\n",
		       dev->name);
		return -ENODEV;
	}

	dev->reg_state = NETREG_UNREGISTERING;

	synchronize_net();

	/* Shutdown queueing discipline. */
	/**
	 * 由dev_shutdown函数释放所有与设备相关的队列规则实例。
	 */
	dev_shutdown(dev);

	
	/* Notify protocols, that we are about to destroy
	   this device. They should clean all the things.
	*/
	/**
	 * NETDEV_UNREGISTER通知被送到netdev_chain通知链使其它内核组件知道此事件发生了
	 * 用户空间收到注销通知，例如，在一个用于访问internet网的双网卡的系统中，这个通知可用于启动第二块网卡。
	 */
	notifier_call_chain(&netdev_chain, NETDEV_UNREGISTER, dev);
	
	/*
	 *	Flush the multicast chain
	 */
	/**
	 * 释放所有链接到net_device结构的数据块。
	 * 例如，dev_mc_discard函数释放多播数据dev->mc_list，free_divert_blk函数释放转发块，等等。
	 */
	dev_mc_discard(dev);

	/**
	 * 在register_netdevice中的dev->init处理的任何事情在此都不被dev->uninit处理。
	 */
	if (dev->uninit)
		dev->uninit(dev);

	/* Notifier chain MUST detach us from master device. */
	/**
	 * 绑定的特性允许组合一组设备以欺骗它们作为一个单独的具有特殊功能的虚拟设备。
	 * 在这些设备之间，其中之一常被选择作为主设备，因为它扮演着组内的特殊角色。
	 * 由于这个明显的原因，被移除的设备应当释放所有的对主设备的引用：在这种情况下，dev->master 非空将是一个 bug。
	 */
	BUG_TRAP(!dev->master);

	free_divert_blk(dev);

	/* Finish processing unregister after unlock */
	/**
	 * net_set_todo被调用以使net_run_todo结束注销过程
	 * net_run_todo函数从sysfs中注销设备，并设置dev->reg_state 为NETREG_UNREGISTERED，等到所有的引用都释放后，调用dev->destructor结束注销过程。
	 */
	net_set_todo(dev);

	synchronize_net();

	/**
	 * dev_put函数减少引用计数
	 */
	dev_put(dev);
	return 0;
}

/**
 *	unregister_netdev - remove device from the kernel
 *	@dev: device
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables. On success 0 is returned, on a failure
 *	a negative errno code is returned.
 *
 *	This is just a wrapper for unregister_netdevice that takes
 *	the rtnl semaphore.  In general you want to use this and not
 *	unregister_netdevice.
 */
void unregister_netdev(struct net_device *dev)
{
	rtnl_lock();
	unregister_netdevice(dev);
	rtnl_unlock();
}

EXPORT_SYMBOL(unregister_netdev);

#ifdef CONFIG_HOTPLUG_CPU
static int dev_cpu_callback(struct notifier_block *nfb,
			    unsigned long action,
			    void *ocpu)
{
	struct sk_buff **list_skb;
	struct net_device **list_net;
	struct sk_buff *skb;
	unsigned int cpu, oldcpu = (unsigned long)ocpu;
	struct softnet_data *sd, *oldsd;

	if (action != CPU_DEAD)
		return NOTIFY_OK;

	local_irq_disable();
	cpu = smp_processor_id();
	sd = &per_cpu(softnet_data, cpu);
	oldsd = &per_cpu(softnet_data, oldcpu);

	/* Find end of our completion_queue. */
	list_skb = &sd->completion_queue;
	while (*list_skb)
		list_skb = &(*list_skb)->next;
	/* Append completion queue from offline CPU. */
	*list_skb = oldsd->completion_queue;
	oldsd->completion_queue = NULL;

	/* Find end of our output_queue. */
	list_net = &sd->output_queue;
	while (*list_net)
		list_net = &(*list_net)->next_sched;
	/* Append output queue from offline CPU. */
	*list_net = oldsd->output_queue;
	oldsd->output_queue = NULL;

	raise_softirq_irqoff(NET_TX_SOFTIRQ);
	local_irq_enable();

	/* Process offline CPU's input_pkt_queue */
	while ((skb = __skb_dequeue(&oldsd->input_pkt_queue)))
		netif_rx(skb);

	return NOTIFY_OK;
}
#endif /* CONFIG_HOTPLUG_CPU */


/*
 *	Initialize the DEV module. At boot time this walks the device list and
 *	unhooks any devices that fail to initialise (normally hardware not
 *	present) and leaves us with a valid list of present and active devices.
 *
 */

/*
 *       This is called single threaded during boot, so no need
 *       to take the rtnl semaphore.
 */
/**
 * 网络设备层初始化，网络代码中一些很重要的功能，比如流量控制，每个CPU的输入队列等功能的初始化。
 * 它在所有设备驱动处理前执行。
 */
static int __init net_dev_init(void)
{
	int i, rc = -ENOMEM;

	BUG_ON(!dev_boot_phase);

	/**
	 * net_random_init初始化每个cpu的种子数组，这些数组在 net_random 生成随机数时使用。
	 */
	net_random_init();

	/**
	 * 如果内核编译选项中包含了/proc文件系统（这是缺省配置），dev_proc_init和dev_mcast_init就会在/proc目录下增加一些文件
	 */
	if (dev_proc_init())
		goto out;

	/**
	 * netdev_sysfs_init注册了网络代码的sysfs。
	 * 它创建了/sys/class/net目录，在这个目录下，你会看到每个已注册网络设备的子目录。
	 * 这些目录下包含很多文件，有些文件原来是放在/proc目录下。
	 */
	if (netdev_sysfs_init())
		goto out;

	INIT_LIST_HEAD(&ptype_all);
	/**
	 * 初始化网络处理函数数组 ptype_base。这些处理函数用来多路分解接收到的包。
	 */
	for (i = 0; i < 16; i++) 
		INIT_LIST_HEAD(&ptype_base[i]);

	for (i = 0; i < ARRAY_SIZE(dev_name_head); i++)
		INIT_HLIST_HEAD(&dev_name_head[i]);

	for (i = 0; i < ARRAY_SIZE(dev_index_head); i++)
		INIT_HLIST_HEAD(&dev_index_head[i]);

	/*
	 *	Initialise the packet receive queues.
	 */
	/**
	 * 初始化cpu相关的数据结构，这些结构被两个网络软中断使用。
	 */
	for (i = 0; i < NR_CPUS; i++) {
		struct softnet_data *queue;

		queue = &per_cpu(softnet_data, i);
		skb_queue_head_init(&queue->input_pkt_queue);
		queue->throttle = 0;
		queue->cng_level = 0;
		queue->avg_blog = 10; /* arbitrary non-zero */
		queue->completion_queue = NULL;
		INIT_LIST_HEAD(&queue->poll_list);
		set_bit(__LINK_STATE_START, &queue->backlog_dev.state);
		/**
		 * backlog_dev是特殊的非NAPI设备。
		 */
		queue->backlog_dev.weight = weight_p;
		queue->backlog_dev.poll = process_backlog;
		atomic_set(&queue->backlog_dev.refcnt, 1);
	}

#ifdef OFFLINE_SAMPLE
	/**
	 * 如果定义了OFFLINE_SAMPLE标记，内核会定期运行一个函数收集设备队列长度的统计信息。
	 * 在这种情况下，net_dev_init需要为函数创建一个定时器，使它可以定期运行。
	 */
	samp_timer.expires = jiffies + (10 * HZ);
	add_timer(&samp_timer);
#endif

	/**
	 * 修改dev_boot_phase的值为0，表示本函数已经执行过了。
	 * 每次注册设备时，需要检查这个值是否为0.以确保本函数确实已经执行过了。
	 * 这主要是为了兼容旧的驱动代码。在2.6中，其实可以确保本函数先于驱动执行。
	 */
	dev_boot_phase = 0;

	open_softirq(NET_TX_SOFTIRQ, net_tx_action, NULL);
	open_softirq(NET_RX_SOFTIRQ, net_rx_action, NULL);

	/**
	 * 在通知链表上注册一个回调函数，用于接收 CPU 的热插拔事件。
	 * 这里的回调函数是dev_cpu_callback。当前唯一处理的事件是CPU关闭事件。
	 * 如果收到通知，CPU输入队列中的包被取下来并交个netif_rx。
	 */
	hotcpu_notifier(dev_cpu_callback, 0);
	/**
	 * dst_init初始化协议无关的目的缓存（DST）
	 */
	dst_init();
	dev_mcast_init();
	rc = 0;
out:
	return rc;
}
/**
 * subsys_initcall确保了该函数是子系统初始化函数，先于设备驱动之前运行。
 */
subsys_initcall(net_dev_init);

EXPORT_SYMBOL(__dev_get_by_index);
EXPORT_SYMBOL(__dev_get_by_name);
EXPORT_SYMBOL(__dev_remove_pack);
EXPORT_SYMBOL(__skb_linearize);
EXPORT_SYMBOL(dev_add_pack);
EXPORT_SYMBOL(dev_alloc_name);
EXPORT_SYMBOL(dev_close);
EXPORT_SYMBOL(dev_get_by_flags);
EXPORT_SYMBOL(dev_get_by_index);
EXPORT_SYMBOL(dev_get_by_name);
EXPORT_SYMBOL(dev_ioctl);
EXPORT_SYMBOL(dev_open);
EXPORT_SYMBOL(dev_queue_xmit);
EXPORT_SYMBOL(dev_remove_pack);
EXPORT_SYMBOL(dev_set_allmulti);
EXPORT_SYMBOL(dev_set_promiscuity);
EXPORT_SYMBOL(dev_change_flags);
EXPORT_SYMBOL(dev_set_mtu);
EXPORT_SYMBOL(free_netdev);
EXPORT_SYMBOL(netdev_boot_setup_check);
EXPORT_SYMBOL(netdev_set_master);
EXPORT_SYMBOL(netdev_state_change);
EXPORT_SYMBOL(netif_receive_skb);
EXPORT_SYMBOL(netif_rx);
EXPORT_SYMBOL(register_gifconf);
EXPORT_SYMBOL(register_netdevice);
EXPORT_SYMBOL(register_netdevice_notifier);
EXPORT_SYMBOL(skb_checksum_help);
EXPORT_SYMBOL(synchronize_net);
EXPORT_SYMBOL(unregister_netdevice);
EXPORT_SYMBOL(unregister_netdevice_notifier);
EXPORT_SYMBOL(net_enable_timestamp);
EXPORT_SYMBOL(net_disable_timestamp);

#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
EXPORT_SYMBOL(br_handle_frame_hook);
#endif

#ifdef CONFIG_KMOD
EXPORT_SYMBOL(dev_load);
#endif

EXPORT_PER_CPU_SYMBOL(softnet_data);
