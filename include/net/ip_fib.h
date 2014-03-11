/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <linux/config.h>
#include <net/flow.h>
#include <linux/seq_file.h>

/* WARNING: The ordering of these elements must match ordering
 *          of RTA_* rtnetlink attribute numbers.
 */
/**
 * 当内核接收到来自用户空间中一条IPROUTE2命令要求添加或删除一条路由时，内核解析请求并存储到kern_rta结构内.
 */
struct kern_rta {
	void		*rta_dst;
	void		*rta_src;
	int		*rta_iif;
	int		*rta_oif;
	void		*rta_gw;
	u32		*rta_priority;
	void		*rta_prefsrc;
	struct rtattr	*rta_mx;
	struct rtattr	*rta_mp;
	unsigned char	*rta_protoinfo;
	u32		*rta_flow;
	struct rta_cacheinfo *rta_ci;
	struct rta_session *rta_sess;
};

struct fib_info;

/**
 * 下一跳。
 * 如果使用诸如ip route add 10.0.0.0/24 scope global nexthop via 192.168.1.1命令定义一条路由，那么下一跳为192.168.1.1。
 * 一条路由表项一般只有一个下一跳，但当内核支持多路径特性时，那么，就可以对一条路由项配置多个下一跳。
 */
struct fib_nh {
	/**
	 * 这是与设备标识nh_oif（后面描述）相关联的net_device数据结构。
	 * 因为设备标识和指向net_device结构的指针都需要利用（在不同的上下文内），所以这两项都存在于fib_nh结构中，虽然利用其中任何一项就可以得到另一项。
	 */
	struct net_device	*nh_dev;
	/**
	 * 用于将fib_nh数据结构插入到哈希表中。
	 */
	struct hlist_node	nh_hash;
	/**
	 * 该指针指向包含该fib_nh实例的fib_info结构。
	 */
	struct fib_info		*nh_parent;
	/**
	 * 下一跳标志。如RTNH_F_DEAD、RTNH_F_ONLINK。
	 */
	unsigned		nh_flags;
	/**
	 * 用于获取下一跳的路由scope。在大多数情况下为RT_SCOPE_LINK。该字段由fib_check_nh来初始化。
	 */
	unsigned char		nh_scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/**
	 * 下一跳的权值。当用户没有明确配置时被设置为缺省值1。
	 */
	int			nh_weight;
	/**
	 * 使该下一跳被选中的tokens。这个值是在初始化fib_info->fib_power时，首先被初始化为fib_nh->nh_weight。
	 * 每当fib_select_multipath选中该下一跳时就递减该值。
	 * 当这个值递减为零时，不再选中该下一跳，直到nh_power被重新初始化为fib_nh->nh_weight（这是在重新初始化fib_info->fib_power值时进行的）。
	 */
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * 路由realm。
	 * 一般情况下，只使用目的realm来计算路由标签，根据目的地址来选择匹配路由。
	 * 但是，内核有时侯需要反向路径查找。当这种情况发生时，路由项的目的realm是从反向路由的源realm得出的。nh_tclassid是一个32比特变量。
	 */
	__u32			nh_tclassid;
#endif
	/**
	 * egress设备标识。它是利用关键字oif和dev来设置的。
	 */
	int			nh_oif;
	/**
	 * 下一跳网关的IP地址，它是利用关键字via来设置的。
	 */
	u32			nh_gw;
};

/*
 * This structure contains data shared by many of routes.
 */

/**
 * 不同路由表项之间可以共享一些参数，这些参数被存储在fib_info数据结构内。
 * 当一个新的路由表项所用的一组参数与一个已存在的路由项所用的参数匹配，则复用已存在的fib_info结构。
 * 一个引用计数用于跟踪用户数量。
 */
struct fib_info {
	/**
	 * 将结构插入到fib_info_hash表中。通过fib_find_info接口来查找该表。
	 */
	struct hlist_node	fib_hash;
	/**
	 * 将结构插入到fib_info_laddrhash表中。在路由表项有一个首选源地址时，才将fib_info结构插入到这个表中。
	 */	
	struct hlist_node	fib_lhash;
	/**
	 * fib_treeref是持有该fib_info实例引用的fib_node数据结构的数目
	 */
	int			fib_treeref;
	/**
	 * fib_clntref是由于路由查找成功而被持有的引用计数。
	 */
	atomic_t		fib_clntref;
	/**
	 * 标记路由项正在被删除的标志。当该标志被设置为1时，警告该数据结构将被删除而不能再使用。
	 */
	int			fib_dead;
	/**
	 * 该字段为RTNH_F_XXX标志的组合。当前使用的唯一标志是RTNH_F_DEAD。
	 * 当与一条多路径路由项相关联的所有fib_nh结构都设置了RTNH_F_DEAD标志时，设置该标志。
	 */
	unsigned		fib_flags;
	/**
	 * 设置路由的协议。表示路由协议守护进程。
	 * fib_protocol取值大于RTPROT_STATIC的路由项不是由内核生成（即由用户空间路由协议生成）。
	 */
	int			fib_protocol;
	/**
	 * 首选源IP地址。
	 */
	u32			fib_prefsrc;
	/**
	 * 路由优先级。值越小则优先级越高。
	 * 它的值可以用IPROUTE2包中的metric/priority/preference关键字来配置。当没有明确设定时，内核将它的值初始化为缺省值0。
	 */
	u32			fib_priority;
	/**
	 * 当配置路由时，ip route命令还可以指定一组metrics。
	 * fib_metrics是存储这一组metrics的一个向量。没有明确设定的Metrics在初始化时被设置为0。
	 */
	u32			fib_metrics[RTAX_MAX];
#define fib_mtu fib_metrics[RTAX_MTU-1]
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
	/**
	 * 路由项定义的下一跳的个数。
	 */
	int			fib_nhs;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/**
	 * 用于实现加权随机轮转算法。
	 * 该字段被初始化为fib_info实例的所有下一跳权值（fib_nh->nh_weight）的总和，但不包含由于某些原因而不能使用的下一跳（带有RTNH_F_DEAD标志）。
	 * 每当调用fib_select_multipath来选择一个下一跳时，fib_power的值递减。当该值递减为零时被重新初始化。
	 */
	int			fib_power;
#endif
	/**
	 * fib_nh结构数组，数组的大小为fib_info->fib_nhs。
	 */
	struct fib_nh		fib_nh[0];
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

/**
 * 查找路由表返回该结构。
 * 它的内容并不是简单地包含下一跳信息，而且包含由诸如策略路由等特性所需要的更多参数。
 */
struct fib_result {
	/**
	 * 匹配路由的前缀长度。
	 */
	unsigned char	prefixlen;
	/**
	 * 多路径路由是由多个下一跳来定义的。该字段标识已经被选中的下一跳。
	 */
	unsigned char	nh_sel;
	/**
	 * 这两个字段被初始化为相匹配的fib_alias实例的fa_type和fa_scope字段的取值。
	 */
	unsigned char	type;
	unsigned char	scope;
	/**
	 * 与匹配的fib_alias实例相关联的fib_info实例。
	 */
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	/**
	 * 与前面字段不同的是，该字段由fib_lookup来初始化。只有当内核编译支持策略路由时，该字段才包含在fib_result数据结构内。
	 */
	struct fib_rule	*r;
#endif
};


#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

/**
 * 这些宏从一个给定的fib_result结构中提取特定的字段，例如FIB_RES_DEV提取出nh_dev字段。
 */
#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

/**
 * 表示一张路由表。不要将它与路由表缓存混淆。
 * 这个结构主要由一个路由表标识和管理该路由表的一组函数指针组成
 */
struct fib_table {
	/**
	 * 路由表标识。在include/linux/rtnetlink.h文件中可以找到预先定义的类型为rt_class_t的值，例如RT_TABLE_LOCAL。
	 */
	unsigned char	tb_id;
	/**
	 * 未被使用。
	 */
	unsigned	tb_stamp;
	/**
	 * 这个函数被fib_lookup程序调用。用于路由查找。初始化为fn_hash_lookup。
	 */
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	/**
	 * tb_insert被inet_rtm_newroute和ip_rt_ioctl调用，处理用户空间的ip route add/change/replace/prepend/append/test 命令和 route add 命令。
	 * 也被fib_magic调用。
	 */
	int		(*tb_insert)(struct fib_table *table, struct rtmsg *r,
				     struct kern_rta *rta, struct nlmsghdr *n,
				     struct netlink_skb_parms *req);
	/**
	 * 类似地，tb_delete被inet_rtm_delroute（对ip route del ... 命令作出的响应）和ip_rt_ioctl（对route del ... 命令作出的响应）调用，用于从路由表中删除一条路由。
	 * 也被fib_magic调用。
	 */
	int		(*tb_delete)(struct fib_table *table, struct rtmsg *r,
				     struct kern_rta *rta, struct nlmsghdr *n,
				     struct netlink_skb_parms *req);
	/**
	 * Dump出路由表的内容。在处理诸如"ip route get..."等用户命令时被激活。
	 */
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	/**
	 * 将设置有RTNH_F_DEAD标志的fib_info结构删除。即垃圾回收。
	 */
	int		(*tb_flush)(struct fib_table *table);
	/**
	 * 选择一条缺省路由。
	 */
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);

	/**
	 * 包含一个fn_hash结构，含33个路由表。
	 * 指向该结构的尾部。当该fib_table结构是另一个更大结构的一部分时，这种做法是很有用的，因为可以在该结构结束时紧接着指向另一个数据结构
	 */
	unsigned char	tb_data[0];
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

extern struct fib_table *ip_fib_local_table;
extern struct fib_table *ip_fib_main_table;

static inline struct fib_table *fib_get_table(int id)
{
	if (id != RT_TABLE_LOCAL)
		return ip_fib_main_table;
	return ip_fib_local_table;
}

/**
 * 这个函数创建并初始化一个新路由表，并将它链接到fib_tables数组内。
 */
static inline struct fib_table *fib_new_table(int id)
{
	return fib_get_table(id);
}

/**
 * 用于路由表的查找。
 */
static inline int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	/**
	 * 当不支持策略路由时，直接调用本地路由和主路由的搜索函数。
	 * IPV4的搜索函数是fn_hash_lookup。
	 */
	if (ip_fib_local_table->tb_lookup(ip_fib_local_table, flp, res) &&
	    ip_fib_main_table->tb_lookup(ip_fib_main_table, flp, res))
		return -ENETUNREACH;
	return 0;
}

/**
 * 用于转发报文且没有到达目的地的路由表项时选择一个缺省路由。当以下两个条件都满足时它被ip_route_output_slow函数激活：
 *		fib_lookup返回的路由项网络掩码为/0（res.prefixlen为0）
 *		fib_lookup返回的路由项的类型为RTN_UNICAST
 * fib_select_default用来在多个可用的缺省路由项中作出最佳选择。
 */
static inline void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	/**
	 * 当res路由项的下一跳网关的scope为RT_SCOPE_LINK时，fib_select_default才查找ip_fib_main_table表
	 * 这是因为网关必须在L2可以直达的范围才行。
	 */
	if (FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		/**
		 * tb_select_default被初始化为fn_hash_select_default
		 */
		ip_fib_main_table->tb_select_default(ip_fib_main_table, flp, res);
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
#define ip_fib_local_table (fib_tables[RT_TABLE_LOCAL])
#define ip_fib_main_table (fib_tables[RT_TABLE_MAIN])

extern struct fib_table * fib_tables[RT_TABLE_MAX+1];
extern int fib_lookup(const struct flowi *flp, struct fib_result *res);
extern struct fib_table *__fib_new_table(int id);
extern void fib_rule_put(struct fib_rule *r);

/**
 * 给定一个路由表ID（从0到255的一个数值），该函数从fib_tables数组返回相应的fib_info结构。
 */
static inline struct fib_table *fib_get_table(int id)
{
	if (id == 0)
		id = RT_TABLE_MAIN;

	return fib_tables[id];
}

/**
 * 这个函数创建并初始化一个新路由表，并将它链接到fib_tables数组内。
 */
static inline struct fib_table *fib_new_table(int id)
{
	if (id == 0)
		id = RT_TABLE_MAIN;

	return fib_tables[id] ? : __fib_new_table(id);
}

extern void fib_select_default(const struct flowi *flp, struct fib_result *res);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern void		ip_fib_init(void);
extern int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_getroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb);
extern int fib_validate_source(u32 src, u32 dst, u8 tos, int oif,
			       struct net_device *dev, u32 *spec_dst, u32 *itag);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(u32 gw, struct net_device *dev);
extern int fib_sync_down(u32 local, struct net_device *dev, int force);
extern int fib_sync_up(struct net_device *dev);
extern int fib_convert_rtentry(int cmd, struct nlmsghdr *nl, struct rtmsg *rtm,
			       struct kern_rta *rta, struct rtentry *r);
extern u32  __fib_res_prefsrc(struct fib_result *res);

/* Exported by fib_hash.c */
extern struct fib_table *fib_hash_init(int id);

#ifdef CONFIG_IP_MULTIPLE_TABLES
/* Exported by fib_rules.c */

extern int inet_rtm_delrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_newrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_dump_rules(struct sk_buff *skb, struct netlink_callback *cb);
#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif
extern void fib_rules_init(void);
#endif

/**
 * 进行反向路径查找时来辅助查找realms。
 */
static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	/**
	 * 当内核没有使能策略路由时，它简单地将源路由realm和目的路由realm交换。
	 */
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	/**
	 * 当内核使能策略路由时，这个函数将策略源realm作为目的realm。
	 */
	rtag = fib_rules_tclass(res);
	/**
	 * 如果目的路由realm存在则将D1作为源realm，否则将目的策略realm作为源realm。
	 */
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#endif  /* _NET_FIB_H */
