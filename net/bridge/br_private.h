/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_private.h,v 1.7 2001/12/24 00:59:55 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_PRIVATE_H
#define _BR_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/if_bridge.h>

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

#define BR_HOLD_TIME (1*HZ)

#define BR_PORT_BITS	10
/**
 * 每个网桥设备最多支持的端口数量。
 */
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

/**
 * 网桥ID。这个数据结构没有反映 802.1t的变化。
 */
struct bridge_id
{
	/**
	 * 网桥优先级。
	 */
	unsigned char	prio[2];
	/**
	 * 网桥MAC地址。
	 */
	unsigned char	addr[6];
};

/**
 * MAC地址。
 */
struct mac_addr
{
	unsigned char	addr[6];
};

/**
 * 转发数据库条目。
 * 每一个网桥进行地址学习时，每一个MAC地址都有一个这样的条目。
 */
struct net_bridge_fdb_entry
{
	/**
	 * 用于将数据结构链到hash表的冲突链表中。
	 */
	struct hlist_node		hlist;
	/**
	 * 网桥端口。
	 */
	struct net_bridge_port		*dst;
	union {
		struct list_head	age_list;
		/**
		 * 当使用RCU来删除该数据结构时使用。
		 */
		struct rcu_head		rcu;
	} u;
	/**
	 * 引用计数。
	 */
	atomic_t			use_count;
	/**
	 * 老化时钟。
	 */
	unsigned long			ageing_timer;
	/**
	 * MAC地址。这是用于查询的关键字段。
	 */
	mac_addr			addr;
	/**
	 * 当本标志为1时，表示MAC地址是本地设备的一个配置。
	 */
	unsigned char			is_local;
	/**
	 * 当本标志为1时，表示MAC地址是静态的，不会超期。所有本地地址都设置成1.
	 */
	unsigned char			is_static;
};

/**
 * 网桥端口。
 */
struct net_bridge_port
{
	/**
	 * 网桥设备
	 */
	struct net_bridge		*br;
	/**
	 * 绑定的设备。
	 */
	struct net_device		*dev;
	/**
	 * 用于将数据结构链到hash表的冲突链表中。
	 */
	struct list_head		list;

	/* STP */
	/**
	 * 端口优先级。
	 */
	u8				priority;
	/**
	 * 端口状态，有效值在include/linux/if_bridge.h中，这些枚举值的形式都是BR_STATE_XXX。
	 */
	u8				state;
	/**
	 * 端口号。
	 */
	u16				port_no;
	/**
	 * 当这个标志被设置时，必须在端口上发送的配置BPDU上设置TCA标志。
	 */
	unsigned char			topology_change_ack;
	/**
	 * 当一个配置BPDU由于被HOLD时钟阻塞而等待发送时，该标志被置1。
	 */
	unsigned char			config_pending;
	/**
	 * 端口ID，由br_make_port_id计算，由priority和port_no构成。
	 */
	port_id				port_id;
	/**
	 * 端口上接收到最近的配置BPDU的优先级向量。由br_record_config_configuration基于接收到的每一个配置BPDU进行更新。
	 */
	port_id				designated_port;
	bridge_id			designated_root;
	bridge_id			designated_bridge;
	/**
	 * 端口路径长度。
	 */
	u32				path_cost;
	u32				designated_cost;

	/**
	 * 端口时钟。
	 */
	struct timer_list		forward_delay_timer;
	struct timer_list		hold_timer;
	struct timer_list		message_age_timer;
	/**
	 * 用来生成设备文件。
	 */
	struct kobject			kobj;
	/**
	 * 用来通过RCU机制安全的释放数据结构。
	 */
	struct rcu_head			rcu;
};

/**
 * 单个网桥的信息。
 * 这个数据结构被添加到一个net_device数据结构。对大多数虚拟设备来说，它包含的私有数据仅仅被虚拟设备所理解。
 */
struct net_bridge
{
	/**
	 * 用来串行修改net_bridge数据结构或者它的port_list中的某个端口。要进行只读访问，只需要简单的使用rcu_read_lock和rcu_read_unlock即可。
	 */
	spinlock_t			lock;
	/**
	 * 网桥端口列表.
	 */
	struct list_head		port_list;
	/**
	 * 网桥设备。
	 */
	struct net_device		*dev;
	struct net_device_stats		statistics;
	/**
	 * 对转发数据库的元素进行串行读写访问。
	 * 只读访问可以简单的使用rcu_read_lock和rcu_read_unlock。
	 */
	spinlock_t			hash_lock;
	/**
	 * 转发数据库。
	 */
	struct hlist_head		hash[BR_HASH_SIZE];
	/**
	 * 该链表已经不再被使用。
	 */
	struct list_head		age_list;

	/* STP */
	/**
	 * 根桥ID。
	 */
	bridge_id			designated_root;
	/**
	 * 网桥ID。
	 */
	bridge_id			bridge_id;
	/**
	 * 到根桥的最佳路径的长度。
	 */
	u32				root_path_cost;
	/**
	 * 网桥时钟。这些值由根桥配置，并在接收到配置BPDU时，由br_record_config_timeout_values保存在本地。
	 */
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay;
	/**
	 * 本地配置的网桥时钟，仅在根桥上使用。
	 */
	unsigned long			bridge_max_age;
	/**
	 * 转发数据库中的元素的最大老化时间。
	 */
	unsigned long			ageing_time;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;

	/**
	 * 根端口号。
	 */
	u16				root_port;
	/**
	 * 如果该标志被设置，那么网桥就启用了STP。
	 */
	unsigned char			stp_enabled;
	/**
	 * 当最近一个从根端口接收到的配置BPDU存在TC标志时，该标志被设置。
	 * 当该标志被设置时，所有发送的配置BPDU也必须设置TC标志。
	 */
	unsigned char			topology_change;
	/**
	 * 当拓扑变化事件被检测到时，设置该标志。
	 */
	unsigned char			topology_change_detected;

	/**
	 * 网桥时钟。
	 */
	struct timer_list		hello_timer;
	struct timer_list		tcn_timer;
	struct timer_list		topology_change_timer;
	/**
	 * 转发数据库垃圾回收时钟。
	 */
	struct timer_list		gc_timer;
	/**
	 * 用来生成设备文件。
	 */
	struct kobject			ifobj;
};

extern struct notifier_block br_device_notifier;
extern const unsigned char bridge_ula[6];

/* called under bridge lock */
/**
 * br_is_root_bridge返回指定的设备是否是根桥设备。
 */
static inline int br_is_root_bridge(const struct net_bridge *br)
{
	return !memcmp(&br->bridge_id, &br->designated_root, 8);
}


/* br_device.c */
extern void br_dev_setup(struct net_device *dev);
extern int br_dev_xmit(struct sk_buff *skb, struct net_device *dev);

/* br_fdb.c */
extern void br_fdb_init(void);
extern void br_fdb_fini(void);
extern void br_fdb_changeaddr(struct net_bridge_port *p,
			      const unsigned char *newaddr);
extern void br_fdb_cleanup(unsigned long arg);
extern void br_fdb_delete_by_port(struct net_bridge *br,
			   struct net_bridge_port *p);
extern struct net_bridge_fdb_entry *__br_fdb_get(struct net_bridge *br,
						 const unsigned char *addr);
extern struct net_bridge_fdb_entry *br_fdb_get(struct net_bridge *br,
					       unsigned char *addr);
extern void br_fdb_put(struct net_bridge_fdb_entry *ent);
extern int br_fdb_fillbuf(struct net_bridge *br, void *buf, 
			  unsigned long count, unsigned long off);
extern int br_fdb_insert(struct net_bridge *br,
			 struct net_bridge_port *source,
			 const unsigned char *addr,
			 int is_local);

/* br_forward.c */
extern void br_deliver(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_dev_queue_push_xmit(struct sk_buff *skb);
extern void br_forward(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_forward_finish(struct sk_buff *skb);
extern void br_flood_deliver(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);
extern void br_flood_forward(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);

/* br_if.c */
extern int br_add_bridge(const char *name);
extern int br_del_bridge(const char *name);
extern void br_cleanup_bridges(void);
extern int br_add_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_del_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_min_mtu(const struct net_bridge *br);

/* br_input.c */
extern int br_handle_frame_finish(struct sk_buff *skb);
extern int br_handle_frame(struct net_bridge_port *p, struct sk_buff **pskb);

/* br_ioctl.c */
extern int br_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
extern int br_ioctl_deviceless_stub(unsigned int cmd, void __user *arg);

/* br_netfilter.c */
extern int br_netfilter_init(void);
extern void br_netfilter_fini(void);

/* br_stp.c */
extern void br_log_state(const struct net_bridge_port *p);
extern struct net_bridge_port *br_get_port(struct net_bridge *br,
				    	   u16 port_no);
extern void br_init_port(struct net_bridge_port *p);
extern void br_become_designated_port(struct net_bridge_port *p);

/* br_stp_if.c */
extern void br_stp_enable_bridge(struct net_bridge *br);
extern void br_stp_disable_bridge(struct net_bridge *br);
extern void br_stp_enable_port(struct net_bridge_port *p);
extern void br_stp_disable_port(struct net_bridge_port *p);
extern void br_stp_recalculate_bridge_id(struct net_bridge *br);
extern void br_stp_set_bridge_priority(struct net_bridge *br,
				       u16 newprio);
extern void br_stp_set_port_priority(struct net_bridge_port *p,
				     u8 newprio);
extern void br_stp_set_path_cost(struct net_bridge_port *p,
				 u32 path_cost);
extern ssize_t br_show_bridge_id(char *buf, const struct bridge_id *id);

/* br_stp_bpdu.c */
extern int br_stp_handle_bpdu(struct sk_buff *skb);

/* br_stp_timer.c */
extern void br_stp_timer_init(struct net_bridge *br);
extern void br_stp_port_timer_init(struct net_bridge_port *p);
extern unsigned long br_timer_value(const struct timer_list *timer);

#ifdef CONFIG_SYSFS
/* br_sysfs_if.c */
extern int br_sysfs_addif(struct net_bridge_port *p);
extern void br_sysfs_removeif(struct net_bridge_port *p);
extern void br_sysfs_freeif(struct net_bridge_port *p);

/* br_sysfs_br.c */
extern int br_sysfs_addbr(struct net_device *dev);
extern void br_sysfs_delbr(struct net_device *dev);

#else

#define br_sysfs_addif(p)	(0)
#define br_sysfs_removeif(p)	do { } while(0)
#define br_sysfs_freeif(p)	kfree(p)
#define br_sysfs_addbr(dev)	(0)
#define br_sysfs_delbr(dev)	do { } while(0)
#endif /* CONFIG_SYSFS */

#endif
