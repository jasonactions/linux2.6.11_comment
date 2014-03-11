/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: policy rules.
 *
 * Version:	$Id: fib_rules.c,v 1.17 2001/10/31 21:55:54 davem Exp $
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Fixes:
 * 		Rani Assaf	:	local_rule cannot be deleted
 *		Marc Boucher	:	routing by fwmark
 */

#include <linux/config.h>
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
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/init.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/ip_fib.h>

#define FRprintk(a...)

/**
 * 表示由策略路由选择相应路由表的规则。
 */
struct fib_rule
{
	/**
	 * 将这些fib_rule结构链接到一个包含所有fib_rule实例的全局链表内。
	 */
	struct fib_rule *r_next;
	/**
	 * 引用计数。该引用计数的递增是在fib_lookup函数（只在策略路由版的函数中）中进行的，这解释了为什么在每次路由查找成功后总是需要调用fib_res_put（递减该引用计数）。
	 */
	atomic_t	r_clntref;
	/**
	 * 路由规则的优先级。
	 * 当管理员利用IPROUTE2软件包添加一个策略时，可以使用关键字priority，preference和order来配置。
	 * 如果没有明确配置，内核为其分配一个优先级，该值比用户添加的最后一个规则的优先级小1
	 */
	u32		r_preference;
	/**
	 * 路由表标识，范围从0到255。
	 */
	unsigned char	r_table;
	/**
	 * 该字段允许的取值是在include/linux/rtnetlink.h文件中定义的rtm_type枚举值（RTN_UNICAST等）。
	 * 当用户配置一条规则时，使用type关键字来设定该字段。如果用户没有明确配置，IPROUTE2在添加规则时设置该字段的值为RTN_UNICAST。
	 */
	unsigned char	r_action;
	/**
	 * 目的IP地址与源IP地址的长度，单位为比特。它们被用于计算r_srcmask和r_dstmask。如果这两个字段未被初始化则设置为0。
	 */
	unsigned char	r_dst_len;
	unsigned char	r_src_len;
	/**
	 * 表示只有从该IP地址和网络掩码组成的源网络发送的报文才能被接受。
	 */
	u32		r_src;
	u32		r_srcmask;
	/**
	 * 表示只能向该IP地址和网络掩码组成的目的网络发送报文。
	 */
	u32		r_dst;
	u32		r_dstmask;
	/**
	 * 该字段是利用用户空间关键字nat和map-to来设置，在路由NAT实现代码使用。由于不再支持路由NAT，所以该字段也不再被使用。
	 */
	u32		r_srcmap;
	/**
	 * 一组标志。当前未使用。
	 */
	u8		r_flags;
	/**
	 * IP头中的TOS字段。包含该字段的原因是规则的定义中可以包含一个条件，该条件放在IP头部的TOS字段。
	 */
	u8		r_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	/**
	 * 当内核编译支持"使用Netfilter MARK值作为路由key"特性时，可以根据防火墙标签来定义规则。
	 * 该字段是管理员定义一条策略规则时利用fwmark关键字指定的标签。
	 */
	u32		r_fwmark;
#endif
	/**
	 * r_ifname是策略应用的设备的名称。
	 * 给定r_ifname，内核可以得到相关的net_device实例，将该实例的ifindex字段拷贝到r_ifindex中。
	 * r_ifindex值取-1表示禁止该规则
	 */
	int		r_ifindex;
#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * 策略realm.
	 * 源realm和目的realm都是8比特值（范围为0到255），但在r_tclassid中，它们都占用16比特。
	 * 当配置源realm时它被保存在高16比特位，当配置目的realm时它被保存在低16比特位
	 */
	__u32		r_tclassid;
#endif
	char		r_ifname[IFNAMSIZ];
	/**
	 * 当一个规则可用时该字段为0。
	 * 当利用inet_rtm_delrule删除规则时该字段被设置为1。
	 * 每当调用fib_rule_put删除到fib_rule数据结构的一个引用时，递减引用计数，当引用计数为0时就要释放该结构。
	 * 但此时如果r_dead没有设置，则表示发生了某种错误
	 */
	int		r_dead;
};

static struct fib_rule default_rule = {
	.r_clntref =	ATOMIC_INIT(2),
	.r_preference =	0x7FFF,
	.r_table =	RT_TABLE_DEFAULT,
	.r_action =	RTN_UNICAST,
};

static struct fib_rule main_rule = {
	.r_next =	&default_rule,
	.r_clntref =	ATOMIC_INIT(2),
	.r_preference =	0x7FFE,
	.r_table =	RT_TABLE_MAIN,
	.r_action =	RTN_UNICAST,
};

static struct fib_rule local_rule = {
	.r_next =	&main_rule,
	.r_clntref =	ATOMIC_INIT(2),
	.r_table =	RT_TABLE_LOCAL,
	.r_action =	RTN_UNICAST,
};

/**
 * 策略路由链表。按照优先级顺序进行排列。
 * 即使用户没有配置任何规则，fib_rules也包含三个缺省的fib_rule实例:local_rule,main_rule,default_rule
 */
static struct fib_rule *fib_rules = &local_rule;
/**
 * 这个rwlock锁保护类型为fib_rule数据结构的fib_rules全局链表。
 */
static DEFINE_RWLOCK(fib_rules_lock);

int inet_rtm_delrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtattr **rta = arg;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	struct fib_rule *r, **rp;
	int err = -ESRCH;

	for (rp=&fib_rules; (r=*rp) != NULL; rp=&r->r_next) {
		if ((!rta[RTA_SRC-1] || memcmp(RTA_DATA(rta[RTA_SRC-1]), &r->r_src, 4) == 0) &&
		    rtm->rtm_src_len == r->r_src_len &&
		    rtm->rtm_dst_len == r->r_dst_len &&
		    (!rta[RTA_DST-1] || memcmp(RTA_DATA(rta[RTA_DST-1]), &r->r_dst, 4) == 0) &&
		    rtm->rtm_tos == r->r_tos &&
#ifdef CONFIG_IP_ROUTE_FWMARK
		    (!rta[RTA_PROTOINFO-1] || memcmp(RTA_DATA(rta[RTA_PROTOINFO-1]), &r->r_fwmark, 4) == 0) &&
#endif
		    (!rtm->rtm_type || rtm->rtm_type == r->r_action) &&
		    (!rta[RTA_PRIORITY-1] || memcmp(RTA_DATA(rta[RTA_PRIORITY-1]), &r->r_preference, 4) == 0) &&
		    (!rta[RTA_IIF-1] || rtattr_strcmp(rta[RTA_IIF-1], r->r_ifname) == 0) &&
		    (!rtm->rtm_table || (r && rtm->rtm_table == r->r_table))) {
			err = -EPERM;
			if (r == &local_rule)
				break;

			write_lock_bh(&fib_rules_lock);
			*rp = r->r_next;
			r->r_dead = 1;
			write_unlock_bh(&fib_rules_lock);
			fib_rule_put(r);
			err = 0;
			break;
		}
	}
	return err;
}

/* Allocate new unique table id */

static struct fib_table *fib_empty_table(void)
{
	int id;

	for (id = 1; id <= RT_TABLE_MAX; id++)
		if (fib_tables[id] == NULL)
			return __fib_new_table(id);
	return NULL;
}

void fib_rule_put(struct fib_rule *r)
{
	if (atomic_dec_and_test(&r->r_clntref)) {
		if (r->r_dead)
			kfree(r);
		else
			printk("Freeing alive rule %p\n", r);
	}
}

int inet_rtm_newrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtattr **rta = arg;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	struct fib_rule *r, *new_r, **rp;
	unsigned char table_id;

	if (rtm->rtm_src_len > 32 || rtm->rtm_dst_len > 32 ||
	    (rtm->rtm_tos & ~IPTOS_TOS_MASK))
		return -EINVAL;

	if (rta[RTA_IIF-1] && RTA_PAYLOAD(rta[RTA_IIF-1]) > IFNAMSIZ)
		return -EINVAL;

	table_id = rtm->rtm_table;
	if (table_id == RT_TABLE_UNSPEC) {
		struct fib_table *table;
		if (rtm->rtm_type == RTN_UNICAST) {
			if ((table = fib_empty_table()) == NULL)
				return -ENOBUFS;
			table_id = table->tb_id;
		}
	}

	new_r = kmalloc(sizeof(*new_r), GFP_KERNEL);
	if (!new_r)
		return -ENOMEM;
	memset(new_r, 0, sizeof(*new_r));
	if (rta[RTA_SRC-1])
		memcpy(&new_r->r_src, RTA_DATA(rta[RTA_SRC-1]), 4);
	if (rta[RTA_DST-1])
		memcpy(&new_r->r_dst, RTA_DATA(rta[RTA_DST-1]), 4);
	if (rta[RTA_GATEWAY-1])
		memcpy(&new_r->r_srcmap, RTA_DATA(rta[RTA_GATEWAY-1]), 4);
	new_r->r_src_len = rtm->rtm_src_len;
	new_r->r_dst_len = rtm->rtm_dst_len;
	new_r->r_srcmask = inet_make_mask(rtm->rtm_src_len);
	new_r->r_dstmask = inet_make_mask(rtm->rtm_dst_len);
	new_r->r_tos = rtm->rtm_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	if (rta[RTA_PROTOINFO-1])
		memcpy(&new_r->r_fwmark, RTA_DATA(rta[RTA_PROTOINFO-1]), 4);
#endif
	new_r->r_action = rtm->rtm_type;
	new_r->r_flags = rtm->rtm_flags;
	if (rta[RTA_PRIORITY-1])
		memcpy(&new_r->r_preference, RTA_DATA(rta[RTA_PRIORITY-1]), 4);
	new_r->r_table = table_id;
	if (rta[RTA_IIF-1]) {
		struct net_device *dev;
		rtattr_strlcpy(new_r->r_ifname, rta[RTA_IIF-1], IFNAMSIZ);
		new_r->r_ifindex = -1;
		dev = __dev_get_by_name(new_r->r_ifname);
		if (dev)
			new_r->r_ifindex = dev->ifindex;
	}
#ifdef CONFIG_NET_CLS_ROUTE
	if (rta[RTA_FLOW-1])
		memcpy(&new_r->r_tclassid, RTA_DATA(rta[RTA_FLOW-1]), 4);
#endif

	rp = &fib_rules;
	if (!new_r->r_preference) {
		r = fib_rules;
		if (r && (r = r->r_next) != NULL) {
			rp = &fib_rules->r_next;
			if (r->r_preference)
				new_r->r_preference = r->r_preference - 1;
		}
	}

	while ( (r = *rp) != NULL ) {
		if (r->r_preference > new_r->r_preference)
			break;
		rp = &r->r_next;
	}

	new_r->r_next = r;
	atomic_inc(&new_r->r_clntref);
	write_lock_bh(&fib_rules_lock);
	*rp = new_r;
	write_unlock_bh(&fib_rules_lock);
	return 0;
}

#ifdef CONFIG_NET_CLS_ROUTE
/**
 * 从一个fib_rule数据结构内提取r_tclassid字段。
 * 因为fib_lookup返回的结果内包含一个指针指向匹配的fib_rule实例，所以在查找之后使用fib_rules_tclass来提取匹配规则。
 */
u32 fib_rules_tclass(struct fib_result *res)
{
	if (res->r)
		return res->r->r_tclassid;
	return 0;
}
#endif


static void fib_rules_detach(struct net_device *dev)
{
	struct fib_rule *r;

	for (r=fib_rules; r; r=r->r_next) {
		if (r->r_ifindex == dev->ifindex) {
			write_lock_bh(&fib_rules_lock);
			r->r_ifindex = -1;
			write_unlock_bh(&fib_rules_lock);
		}
	}
}

static void fib_rules_attach(struct net_device *dev)
{
	struct fib_rule *r;

	for (r=fib_rules; r; r=r->r_next) {
		if (r->r_ifindex == -1 && strcmp(dev->name, r->r_ifname) == 0) {
			write_lock_bh(&fib_rules_lock);
			r->r_ifindex = dev->ifindex;
			write_unlock_bh(&fib_rules_lock);
		}
	}
}

/**
 * 当内核支持策略路由时的fib_lookup。
 */
int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	int err;
	struct fib_rule *r, *policy;
	struct fib_table *tb;

	u32 daddr = flp->fl4_dst;
	u32 saddr = flp->fl4_src;

FRprintk("Lookup: %u.%u.%u.%u <- %u.%u.%u.%u ",
	NIPQUAD(flp->fl4_dst), NIPQUAD(flp->fl4_src));
	read_lock(&fib_rules_lock);
	/**
	 * 一个接一个地遍历路由策略，直到查找到与路由报文匹配的策略或到达策略链表尾部还没有找到任何匹配。
	 */
	for (r = fib_rules; r; r=r->r_next) {
		if (((saddr^r->r_src) & r->r_srcmask) ||
		    ((daddr^r->r_dst) & r->r_dstmask) ||
		    (r->r_tos && r->r_tos != flp->fl4_tos) ||
#ifdef CONFIG_IP_ROUTE_FWMARK
		    (r->r_fwmark && r->r_fwmark != flp->fl4_fwmark) ||
#endif
		    (r->r_ifindex && r->r_ifindex != flp->iif))
			continue;

FRprintk("tb %d r %d ", r->r_table, r->r_action);
		/**
		 * 当查找到匹配策略时，接下来的动作依赖于策略类型。
		 */
		switch (r->r_action) {
		/**
		 * 策略动作RTN_UNICAST将调用tb_lookup来查找，它实际上是调用fn_hash_lookup函数，该函数可以返回多种结果。
		 */
		case RTN_UNICAST:
			policy = r;
			break;
		/**
		 * 特别地，策略动作RTN_UNREACHABLE，RTN_BLACKHOLE和RTN_PROHIBIT将返回一个错误，fib_lookup的调用方根据该错误值来生成相应的ICMP消息。
		 */
		case RTN_UNREACHABLE:
			read_unlock(&fib_rules_lock);
			return -ENETUNREACH;
		default:
		case RTN_BLACKHOLE:
			read_unlock(&fib_rules_lock);
			return -EINVAL;
		case RTN_PROHIBIT:
			read_unlock(&fib_rules_lock);
			return -EACCES;
		}

		if ((tb = fib_get_table(r->r_table)) == NULL)
			continue;
		/**
		 * 运行到这里，说明需要在策略路由表中搜索具体的路由了。
		 */
		err = tb->tb_lookup(tb, flp, res);
		if (err == 0) {
			/**
			 * 当查找成功时，res->r被初始化为匹配策略。
			 */
			res->r = policy;
			if (policy)
				atomic_inc(&policy->r_clntref);
			read_unlock(&fib_rules_lock);
			return 0;
		}
		/**
		 * 路由查找失败。
		 */
		if (err < 0 && err != -EAGAIN) {
			read_unlock(&fib_rules_lock);
			return err;
		}
		/**
		 * 当查找失败时，如果错误类型为-EAGAIN则fib_lookup继续在循环内查找策略。
		 * 返回该错误值的原因是因为与fn_hash_lookup查找到的匹配路由相关的动作类型为RTN_THROW
		 */
	}
FRprintk("FAILURE\n");
	read_unlock(&fib_rules_lock);
	return -ENETUNREACH;
}

/**
 * 当内核支持策略路由时，选择缺省网关。
 */
void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	/**
	 * 当支持策略路由时选择缺省路由与不支持策略路由时选择的工作机理相同。
	 * 唯一的区别在于fib_select_default利用匹配策略（res->r）来得到使用的路由表。
	 */
	if (res->r && res->r->r_action == RTN_UNICAST &&
	    FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK) {
		struct fib_table *tb;
		if ((tb = fib_get_table(res->r->r_table)) != NULL)
			tb->tb_select_default(tb, flp, res);
	}
}

static int fib_rules_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	if (event == NETDEV_UNREGISTER)
		fib_rules_detach(dev);
	else if (event == NETDEV_REGISTER)
		fib_rules_attach(dev);
	return NOTIFY_DONE;
}


static struct notifier_block fib_rules_notifier = {
	.notifier_call =fib_rules_event,
};

static __inline__ int inet_fill_rule(struct sk_buff *skb,
				     struct fib_rule *r,
				     struct netlink_callback *cb)
{
	struct rtmsg *rtm;
	struct nlmsghdr  *nlh;
	unsigned char	 *b = skb->tail;

	nlh = NLMSG_PUT(skb, NETLINK_CREDS(cb->skb)->pid, cb->nlh->nlmsg_seq, RTM_NEWRULE, sizeof(*rtm));
	rtm = NLMSG_DATA(nlh);
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = r->r_dst_len;
	rtm->rtm_src_len = r->r_src_len;
	rtm->rtm_tos = r->r_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	if (r->r_fwmark)
		RTA_PUT(skb, RTA_PROTOINFO, 4, &r->r_fwmark);
#endif
	rtm->rtm_table = r->r_table;
	rtm->rtm_protocol = 0;
	rtm->rtm_scope = 0;
	rtm->rtm_type = r->r_action;
	rtm->rtm_flags = r->r_flags;

	if (r->r_dst_len)
		RTA_PUT(skb, RTA_DST, 4, &r->r_dst);
	if (r->r_src_len)
		RTA_PUT(skb, RTA_SRC, 4, &r->r_src);
	if (r->r_ifname[0])
		RTA_PUT(skb, RTA_IIF, IFNAMSIZ, &r->r_ifname);
	if (r->r_preference)
		RTA_PUT(skb, RTA_PRIORITY, 4, &r->r_preference);
	if (r->r_srcmap)
		RTA_PUT(skb, RTA_GATEWAY, 4, &r->r_srcmap);
#ifdef CONFIG_NET_CLS_ROUTE
	if (r->r_tclassid)
		RTA_PUT(skb, RTA_FLOW, 4, &r->r_tclassid);
#endif
	nlh->nlmsg_len = skb->tail - b;
	return skb->len;

nlmsg_failure:
rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}

int inet_dump_rules(struct sk_buff *skb, struct netlink_callback *cb)
{
	int idx;
	int s_idx = cb->args[0];
	struct fib_rule *r;

	read_lock(&fib_rules_lock);
	for (r=fib_rules, idx=0; r; r = r->r_next, idx++) {
		if (idx < s_idx)
			continue;
		if (inet_fill_rule(skb, r, cb) < 0)
			break;
	}
	read_unlock(&fib_rules_lock);
	cb->args[0] = idx;

	return skb->len;
}

/**
 * 策略路由的初始化。
 */
void __init fib_rules_init(void)
{
	register_netdevice_notifier(&fib_rules_notifier);
}
