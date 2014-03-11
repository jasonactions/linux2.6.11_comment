#ifndef _LINUX_INETDEVICE_H
#define _LINUX_INETDEVICE_H

#ifdef __KERNEL__

#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>

/**
 * 该结构（其字段通过/proc/sys/net/ipv4/conf输出）用于调整网络设备的行为。
 * 每个设备都有一个实例，另外还有一个是存储默认值的（ipv4_devconf_dflt）
 */
struct ipv4_devconf
{
	int	accept_redirects;
	int	send_redirects;
	int	secure_redirects;
	int	shared_media;
	int	accept_source_route;
	int	rp_filter;
	int	proxy_arp;
	int	bootp_relay;
	int	log_martians;
	/**
	 * 设为非0时，就可以让设备转发流量。
	 */
	int	forwarding;
	int	mc_forwarding;
	int	tag;
	/**
	 * 当一台主机有多个NIC连接到同一个LAN，且配置在同一个IP子网上时，这个选项可以控制一个接口是否对入ARPOP_REQUEST做出应答。
	 * 这个选项在使用了IP源路由选项的网络中很有用。
	 * 当设置该选项后，只有在内核知道如何到达发送方的IP地址，并且只有到达发送方IP地址的设备是接收入口ARPOP_REQUEST包的设备时，内核才会处理这个请求。
	 */
	int     arp_filter;
	/**
	 * 该选项可以通过proc配置，当产生ARP请求时，选择哪个IP地址放到ARP请求头中。其值含义为:
	 *		0 (Default)	:		任何本地IP地址都可以。
	 * 		1:					如果可能，选择和目的地址位于同一个子网内的地址。否则，使用级别2的结果。
	 *		2:					优先使用主地址。
	 */
	int	arp_announce;
	/**
	 * 是否忽略对某些ARP请求的响应。主要用于虚拟服务器上面，下面是取值含义:
	 *		0 (Default):		对任何本地地址的ARP请求都应答.
	 *		1:					如果目的IP配置在收到ARP请求的接口上，才应答。
	 *		2:					和1类似，但是源IP必须和目的IP属于同一个子网。
	 *		3:					如果目的IP的scope不是本地址主机，才应答。
	 *		4-7:				保留.
	 *		8:					不应答.
	 *		>8:					未知的值，接受请求.
	 */
	int	arp_ignore;
	/**
	 * 当ARP代理服务器两个NIC处于同一广播域内时，可能造成ARP代理出现问题。
	 * 通过此字段告诉ARP代理，两个相同medium_id的NIC处于同一广播域，对ARP请求需要做特殊处理。
	 *		-1:				ARP代理已经关闭。
	 *		0 (default):	Medium ID特性已经被关闭.
	 *		>0:				合法的medium ID.
	 */
	int	medium_id;
	int	no_xfrm;
	int	no_policy;
	int	force_igmp_version;
	void	*sysctl;
};

extern struct ipv4_devconf ipv4_devconf;

/**
 * in_device结构存储了一个网络设备所有与Ipv4相关的配置内容，诸如用户以ifconfig或ip命令所做的变更。该结构通过net_device->ip_ptr链接到net_device结构。
 */
struct in_device
{
	/**
	 * 指向相配的net_device结构的指针。
	 */
	struct net_device	*dev;
	/**
	 * 引用计数值。除非此字段为0，那么此结构就不能被释放。
	 */
	atomic_t		refcnt;
	/**
	 * 此字段设定时就是把设备标示成已死。这可用于检查一些情况。例如，项目无法被销毁，因其引用计数不为0。但是，销毁动作已经启动了。
	 */
	int			dead;
	/**
	 * 设备上所配置的IPV4地址列表。
	 * In_ifaddr实例会按范围排序（范围大者排前面），而相同范围的元素则按地址类型排序（主要地址排前面）。
	 */
	struct in_ifaddr	*ifa_list;	/* IP ifaddr chain		*/
	rwlock_t		mc_list_lock;
	/**
	 * 设备的多播配置，是ifa_list的多播配对物。
	 */
	struct ip_mc_list	*mc_list;	/* IP multicast filter chain    */
	spinlock_t		mc_tomb_lock;
	struct ip_mc_list	*mc_tomb;
	unsigned long		mr_v1_seen;
	/**
	 * 由IGMP协议所用的时间戳以记录IGMP包的接收。
	 */
	unsigned long		mr_v2_seen;
	unsigned long		mr_maxdelay;
	unsigned char		mr_qrv;
	unsigned char		mr_gq_running;
	unsigned char		mr_ifc_count;
	struct timer_list	mr_gq_timer;	/* general query timer */
	struct timer_list	mr_ifc_timer;	/* interface change timer */

	struct neigh_parms	*arp_parms;
	/**
	 * IP层配置信息。
	 */
	struct ipv4_devconf	cnf;
	/**
	 * 由RCU机制使用实现互斥。其完成的工作就如同锁一般。
	 */
	struct rcu_head		rcu_head;
};

#define IN_DEV_FORWARD(in_dev)		((in_dev)->cnf.forwarding)
#define IN_DEV_MFORWARD(in_dev)		(ipv4_devconf.mc_forwarding && (in_dev)->cnf.mc_forwarding)
#define IN_DEV_RPFILTER(in_dev)		(ipv4_devconf.rp_filter && (in_dev)->cnf.rp_filter)
#define IN_DEV_SOURCE_ROUTE(in_dev)	(ipv4_devconf.accept_source_route && (in_dev)->cnf.accept_source_route)
#define IN_DEV_BOOTP_RELAY(in_dev)	(ipv4_devconf.bootp_relay && (in_dev)->cnf.bootp_relay)

#define IN_DEV_LOG_MARTIANS(in_dev)	(ipv4_devconf.log_martians || (in_dev)->cnf.log_martians)
#define IN_DEV_PROXY_ARP(in_dev)	(ipv4_devconf.proxy_arp || (in_dev)->cnf.proxy_arp)
#define IN_DEV_SHARED_MEDIA(in_dev)	(ipv4_devconf.shared_media || (in_dev)->cnf.shared_media)
#define IN_DEV_TX_REDIRECTS(in_dev)	(ipv4_devconf.send_redirects || (in_dev)->cnf.send_redirects)
#define IN_DEV_SEC_REDIRECTS(in_dev)	(ipv4_devconf.secure_redirects || (in_dev)->cnf.secure_redirects)
#define IN_DEV_IDTAG(in_dev)		((in_dev)->cnf.tag)
#define IN_DEV_MEDIUM_ID(in_dev)	((in_dev)->cnf.medium_id)

#define IN_DEV_RX_REDIRECTS(in_dev) \
	((IN_DEV_FORWARD(in_dev) && \
	  (ipv4_devconf.accept_redirects && (in_dev)->cnf.accept_redirects)) \
	 || (!IN_DEV_FORWARD(in_dev) && \
	  (ipv4_devconf.accept_redirects || (in_dev)->cnf.accept_redirects)))

#define IN_DEV_ARPFILTER(in_dev)	(ipv4_devconf.arp_filter || (in_dev)->cnf.arp_filter)
/**
 * 获取proc配置，当主机配置多IP时，选择哪一个IP作为ARP请求的源IP字段。
 */
#define IN_DEV_ARP_ANNOUNCE(in_dev)	(max(ipv4_devconf.arp_announce, (in_dev)->cnf.arp_announce))
#define IN_DEV_ARP_IGNORE(in_dev)	(max(ipv4_devconf.arp_ignore, (in_dev)->cnf.arp_ignore))

/**
 * 当在接口上配置一个Ipv4地址时，内核会建立一个in_ifaddr结构。
 */
struct in_ifaddr
{
	/**
	 * 指向链表中下一个元素的指针。此链表包含了设备上所配置的所有地址。
	 */
	struct in_ifaddr	*ifa_next;
	/**
	 * 指向相配的in_device结构的指针。
	 */
	struct in_device	*ifa_dev;
	/**
	 * 由RCU机制使用以实现互斥，类似于锁。
	 */
	struct rcu_head		rcu_head;
	/**
	 * 这两个字段的值取决于该地址是否被指派给一个隧道接口。
	 * 如果是，ifa_local和ifa_address就是隧道的本地和远程地址。
	 * 如果不是，则两者所含都是本地接口的地址。
	 */
	u32			ifa_local;
	u32			ifa_address;
	/**
	 * ifa_mask就是和该地址相配的网络掩码。
	 */
	u32			ifa_mask;
	/**
	 * 广播地址。
	 */
	u32			ifa_broadcast;
	/**
	 * 选播地址。
	 */
	u32			ifa_anycast;
	/**
	 * 地址的范围。默认是RT_SCOPE_UNIVERSE（相当于0），而此字段通常设成ifconfig/ip所设的值。
	 * 不过，也可以选不同的值。主要的例外是位于范围127.x.x.x里的地址，其范围为RT_SCOPE_HOST。
	 */
	unsigned char		ifa_scope;
	/**
	 * 可能的IFA_F_XXX位标志都列在include/linux/rtnetlink.h中。以下是IPV4所用的一个标志：
	 *		IFA_F_SECONDARY：当一个新地址加至一台设备时，如果该设备已有另一个地址具有相同的子网络，则该地址就会被视为次要地址。
	 *		其他标志由IPV6使用。
	 */
	unsigned char		ifa_flags;
	/**
	 * 构成此网络掩码的数目。
	 */
	unsigned char		ifa_prefixlen;
	char			ifa_label[IFNAMSIZ];
};

extern int register_inetaddr_notifier(struct notifier_block *nb);
extern int unregister_inetaddr_notifier(struct notifier_block *nb);

extern struct net_device 	*ip_dev_find(u32 addr);
extern int		inet_addr_onlink(struct in_device *in_dev, u32 a, u32 b);
extern int		devinet_ioctl(unsigned int cmd, void __user *);
extern void		devinet_init(void);
extern struct in_device *inetdev_init(struct net_device *dev);
extern struct in_device	*inetdev_by_index(int);
extern u32		inet_select_addr(const struct net_device *dev, u32 dst, int scope);
extern u32		inet_confirm_addr(const struct net_device *dev, u32 dst, u32 local, int scope);
extern struct in_ifaddr *inet_ifa_byprefix(struct in_device *in_dev, u32 prefix, u32 mask);
extern void		inet_forward_change(void);

/**
 * 给定一个IP地址和一个网络掩码后，inet_ifa_match会检查指定的第二个IP地址是否落在相同子网内。
 * 此函数通常也用于分类出次要地址，以及检查指定的IP地址是否属于那些本地配置子网之一。
 */
static __inline__ int inet_ifa_match(u32 addr, struct in_ifaddr *ifa)
{
	return !((addr^ifa->ifa_address)&ifa->ifa_mask);
}

/*
 *	Check if a mask is acceptable.
 */
 
static __inline__ int bad_mask(u32 mask, u32 addr)
{
	if (addr & (mask = ~mask))
		return 1;
	mask = ntohl(mask);
	if (mask & (mask+1))
		return 1;
	return 0;
}

/**
 * 用于浏览给定的in_device结构内相配的所有in_ifaddr实例。
 * for_primary_ifa只考虑主要地址，而for_ifa则考虑所有地址。
 */
#define for_primary_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa && !(ifa->ifa_flags&IFA_F_SECONDARY); ifa = ifa->ifa_next)

/**
 * 用于浏览给定的in_device结构内相配的所有in_ifaddr实例。
 * for_primary_ifa只考虑主要地址，而for_ifa则考虑所有地址。
 */
#define for_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa; ifa = ifa->ifa_next)


#define endfor_ifa(in_dev) }

/**
 * 获取一个NIC设备配置的IP配置块。
 */
static __inline__ struct in_device *
in_dev_get(const struct net_device *dev)
{
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = dev->ip_ptr;
	if (in_dev)
		atomic_inc(&in_dev->refcnt);
	rcu_read_unlock();
	return in_dev;
}

static __inline__ struct in_device *
__in_dev_get(const struct net_device *dev)
{
	return (struct in_device*)dev->ip_ptr;
}

extern void in_dev_finish_destroy(struct in_device *idev);

static inline void in_dev_put(struct in_device *idev)
{
	if (atomic_dec_and_test(&idev->refcnt))
		in_dev_finish_destroy(idev);
}

#define __in_dev_put(idev)  atomic_dec(&(idev)->refcnt)
#define in_dev_hold(idev)   atomic_inc(&(idev)->refcnt)

#endif /* __KERNEL__ */

/**
 * 给定网络掩码(netmask)所组成的1的数目，inet_make_mask就可建立相配的网络掩码。
 * 例如，输入值24就会产生网络掩码255.255.255.0。
 */
static __inline__ __u32 inet_make_mask(int logmask)
{
	if (logmask)
		return htonl(~((1<<(32-logmask))-1));
	return 0;
}

/**
 * inet_mask_len会返回十进制网络掩码中1的数目、例如 255.255.0.0会返回16。
 */
static __inline__ int inet_mask_len(__u32 mask)
{
	if (!(mask = ntohl(mask)))
		return 0;
	return 32 - ffz(~mask);
}


#endif /* _LINUX_INETDEVICE_H */
