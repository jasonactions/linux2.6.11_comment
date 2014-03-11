#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

/**
 * 到达同一目的网段但诸如TOS等参数不同的路由表项是通过fib_alias实例来区分的。
 */
struct fib_alias {
	/**
	 * 将与同一个fib_node结构相关联的所有fib_alias实例链接在一起。
	 */
	struct list_head	fa_list;
	/**
	 * 该指针指向一个fib_info实例，该实例存储着如何处理与该路由相匹配报文的信息。
	 */
	struct fib_info		*fa_info;
	/**
	 * 路由的服务类型（TOS）比特位字段。
	 * 该值为零时表示还没有配置TOS，所以在路由查找时任何值都可以匹配。
	 */
	u8			fa_tos;
	/**
	 * 路由类型。
	 */
	u8			fa_type;
	/**
	 * 路由的scope。IPv4路由代码中使用的主要scope：
	 *		RT_SCOPE_NOWHERE:		非法scope。它的字面含义是路由项不通往任何地方，这基本上就意味着没有到达目的地的路由。
	 *		RT_SCOPE_HOST:			本机范围内的路由。scope为RT_SCOPE_HOST的路由项的例子：为本地接口配置IP地址时自动创建的路由表项。
	 *		RT_SCOPE_LINK:			为本地接口配置地址时，派生的目的地为本地网络地址（由网络掩码定义）和子网广播地址的路由表项的scope就是RT_SCOPE_LINK。
	 *		RT_SCOPE_UNIVERSE:		该scope被用于所有的通往远程非直连目的地的路由表项（也就是需要一个下一跳网关的路由项）。
	 */
	u8			fa_scope;
	/**
	 * 一些标志的比特位图。只使用了一个标志:FA_S_ACCESSED。
	 */
	u8			fa_state;
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(const struct rtmsg *r,
					struct kern_rta *rta,
					const struct nlmsghdr *,
					int *err);
extern int fib_nh_match(struct rtmsg *r, struct nlmsghdr *,
			struct kern_rta *rta, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u8 tb_id, u8 type, u8 scope, void *dst,
			 int dst_len, u8 tos, struct fib_info *fi);
extern void rtmsg_fib(int event, u32 key, struct fib_alias *fa,
		      int z, int tb_id,
		      struct nlmsghdr *n, struct netlink_skb_parms *req);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int *dflt);

#endif /* _FIB_LOOKUP_H */
