/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_H
#define _NET_DST_H

#include <linux/config.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <net/neighbour.h>
#include <asm/processor.h>

/*
 * 0 - no debugging messages
 * 1 - rare events and bugs (default)
 * 2 - trace mode.
 */
#define RT_CACHE_DEBUG		0

#define DST_GC_MIN	(HZ/10)
#define DST_GC_INC	(HZ/2)
#define DST_GC_MAX	(120*HZ)

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

struct sk_buff;
/**
 * 路由表缓存项中与协议无关的部分（DST）。
 * 适用于任意三层协议（例如IPv4,IPv6, DECnet）的路由表缓存项字段被放在该结构内。
 * 在三层协议所用到的数据结构内，通常嵌入该结构来表示路由表缓存项。
 */
struct dst_entry
{
	/**
	 * 用于将分布在同一个哈希桶内的dst_entry实例链接在一起。
	 */
	struct dst_entry        *next;
	/**
	 * 引用计数。
	 */
	atomic_t		__refcnt;	/* client references	*/
	/**
	 * 该表项已经被使用的次数（即缓存查找返回该表项的次数）。
	 */
	int			__use;
	/**
	 * 用于IPSEC，只有最后一个实例中的input和output方法被实际应用于路由决策；
	 * 前面实例中的input和output方法被应用于所要求的transformations。
	 */
	struct dst_entry	*child;
	/**
	 * Egress设备（即将报文送达目的地的发送设备）。
	 */
	struct net_device       *dev;
	/**
	 * 用于定义该dst_entry实例的可用状态：0（缺省值）表示该结构有效而且可以被使用，2表示该结构将被删除因而不能被使用，-1被IPsec和IPv6使用但不被IPv4使用。
	 */
	int			obsolete;
	/**
	 * 标志集合。DST_HOST被TCP使用，表示主机路由（即它不是到网络或到一个广播/多播地址的路由）。
	 * DST_NOXFRM，DST_NOPOLICY和DST_NOHASH只用于IPsec。
	 */
	int			flags;
#define DST_HOST		1
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
/**
 * 当DST用于IPSEC时，child链表中非最后一个元素，并不是实际的路由缓存，因此设置此标志，表示DST对象不在HASH中。
 */
#define DST_NOHASH		8
	/**
	 * 用于记录该表项上次被使用的时间戳。
	 * 当缓存查找成功时更新该时间戳，垃圾回收程序使用该时间戳来选择最合适的应当被释放的结构。
	 */
	unsigned long		lastuse;
	/**
	 * 路由项过期时间，默认永不过期(值为0)。
	 */
	unsigned long		expires;

	unsigned short		header_len;	/* more space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	/**
	 * metrics向量，主要被TCP使用。
	 * 该向量是用fib_info->fib_metrics向量的一份拷贝来初始化（如果fib_metrics向量被定义），当需要时使用缺省值。
	 * 需要解释一下值RTAX_LOCK。RTAX_LOCK不是一个metric，而是一个比特位图：当位置n的比特位被设置时，表示已经利用lock选项/关键字配置了值为n的metric。
	 */
	u32			metrics[RTAX_MAX];
	/**
	 * 用于IPSEC，指向child链表中的最后一个元素。
	 */
	struct dst_entry	*path;

	/**
	 * 上一个IMCP重定向消息送出的时间戳。
	 */
	unsigned long		rate_last;	/* rate limiting for ICMP */
	/**
	 * 已经向与该dst_entry实例相关的目的地发送的ICMP重定向消息的数目。所以，rate_tokens-1表示目的地连续忽略的ICMP重定向消息的数目。
	 */
	unsigned long		rate_tokens;

	/**
	 * 当fib_lookup API（只被IPv4使用）失败时，错误值被保存在error（用一个正值）中，在后面的ip_error中使用该值来决定如何处理本次路由查找失败（即决定生成哪一类ICMP消息）。
	 */
	int			error;

	/**
	 * neighbour是包含下一跳三层地址到二层地址映射的结构，hh是缓存的二层头。
	 */
	struct neighbour	*neighbour;
	struct hh_cache		*hh;
	struct xfrm_state	*xfrm;

	/**
	 * 分别表示处理ingress报文和处理egress报文的函数。
	 */
	int			(*input)(struct sk_buff*);
	int			(*output)(struct sk_buff*);

#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * 基于路由表的classifier的标签。
	 */
	__u32			tclassid;
#endif

	/**
	 * 该结构内的虚函数表（VFT）用于处理dst_entry结构。
	 */
	struct  dst_ops	        *ops;
	/**
	 * 处理互斥。
	 */
	struct rcu_head		rcu_head;

	/**
	 * 该字段用作dst_entry数据结构尾部的指针很有用。它只是用于占位。
	 */
	char			info[0];
};


/**
 * DST核心代码使用虚函数表。向三层协议通知特定的事件（例如链路失效）。
 * 每个三层协议各自提供一组函数，按照自己的方式来处理这些事件。
 * VFT的每一个字段并不是被所有的协议都使用。
 */
struct dst_ops
{
	/**
	 * 地址系列。
	 */
	unsigned short		family;
	/**
	 * 协议ID。
	 */
	unsigned short		protocol;
	/**
	 * 该字段用于垃圾回收算法，指定了路由缓存的容量（即哈希桶的数目）。
	 * 其初始化是在ip_rt_init（IPv4路由子系统初始化函数）中完成的。
	 */
	unsigned		gc_thresh;

	/**
	 * 进行垃圾回收。当子系统通过dst_alloc来分配一个新的缓存表项，当该函数发现内存不够时进行垃圾回收。
	 */
	int			(*gc)(void);
	/**
	 * dst_entry被标记为dead的缓存路由项通常不再被使用，但当使用IPsec时该结论并不一定成立。
	 * 这个程序检查一个obsolete dst_entry是否还有用。
	 * 但是，ipv4_dst_check程序在删除dst_entry结构之前并不检查它是否还有用；而在相应的xfrm_dst_check程序中要对IPsec做"xfrm"转换。
	 */
	struct dst_entry *	(*check)(struct dst_entry *, __u32 cookie);
	/**
	 * 被dst_destroy调用，DST运行该程序来删除一个dst_entry结构，并将删除通知调用协议，以便调用协议先做一些必要的清理工作。
	 * 例如IPv4程序ipv4_dst_destroy使用该通知来释放其它数据结构的引用。
	 */
	void			(*destroy)(struct dst_entry *);
	/**
	 * 被dst_ifdown调用，当一个设备被关闭或注销时，DST子系统激活该函数。
	 * 对每一个受影响的缓存路由项都要调用一次。
	 * IPv4程序ipv4_dst_ifdown用一个指向loopback设备的指针来替换rtable中指向设备IP配置的idev指针，这是因为loopback设备总是存在。
	 */
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
	/**
	 * 被DST函数dst_negative_advice调用，它被用于向DST通知某个dst_entry实例出现问题。
	 * 例如当TCP检测到一次写操作超时时使用dst_negative_advice。
	 * IPv4程序ipv4_negative_advice使用该通知来删除缓存路由项。
	 * 当这个dst_entry已经被标记为dead，ipv4_negative_advice就释放到该dst_entry的rtable引用。
	 */
	struct dst_entry *	(*negative_advice)(struct dst_entry *);
	/**
	 * 被DST函数dst_link_failure调用，它是在发送报文时由于检测到目的地不可达而被激活。
	 */
	void			(*link_failure)(struct sk_buff *);
	/**
	 * 更新缓存路由项的PMTU。通常是在处理所接收到的ICMP分片需求消息时调用。
	 */
	void			(*update_pmtu)(struct dst_entry *dst, u32 mtu);
	/**
	 * 返回该路由使用的TCP最大段（MSS）。IPv4不初始化该程序，所以没有针对该函数的封装程序。
	 */
	int			(*get_mss)(struct dst_entry *dst, u32 mtu);
	/**
	 * 三层路由缓存结构（例如针对IPv4的结构为rtable）的大小。
	 */
	int			entry_size;

	atomic_t		entries;
	/**
	 * 分配路由缓存元素的内存池。
	 */
	kmem_cache_t 		*kmem_cachep;
};

#ifdef __KERNEL__

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32
dst_path_metric(const struct dst_entry *dst, int metric)
{
	return dst->path->metrics[metric-1];
}

/**
 * 给定一个路由缓存条目，返回它的PMTU。
 */
static inline u32
dst_pmtu(const struct dst_entry *dst)
{
	u32 mtu = dst_path_metric(dst, RTAX_MTU);
	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return mtu;
}

static inline int
dst_metric_locked(struct dst_entry *dst, int metric)
{
	return dst_metric(dst, RTAX_LOCK) & (1<<metric);
}

/**
 * 递增或递减一个dst_entry的引用计数。
 */
static inline void dst_hold(struct dst_entry * dst)
{
	atomic_inc(&dst->__refcnt);
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

/**
 * 递增或递减一个dst_entry的引用计数。
 */
static inline
void dst_release(struct dst_entry * dst)
{
	if (dst) {
		WARN_ON(atomic_read(&dst->__refcnt) < 1);
		smp_mb__before_atomic_dec();
		/**
		 * 当调用dst_release释放最后一个引用时，该表项并不被自动删除。
		 */
		atomic_dec(&dst->__refcnt);
	}
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *dst_pop(struct dst_entry *dst)
{
	struct dst_entry *child = dst_clone(dst->child);

	dst_release(dst);
	return child;
}

extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

/**
 * dst_entry结构并不总是嵌入在rtable结构内。孤立的dst_entry实例可通过调用dst_free来直接删除。
 */
static inline void dst_free(struct dst_entry * dst)
{
	/**
	 * 当一个表项仍然被引用时不能被删除时，设置其obsolete标志为2来标记它为dead（dst->obsolete的缺省值为0）。
	 * 试图删除一个已经标记为dead的表项将失败。
	 */
	if (dst->obsolete > 1)
		return;
	/**
	 * 当调用dst_free删除一个引用计数为0的表项，则调用dst_destroy立即删除该表项。
	 */
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		/**
		 * dst_destroy函数也尝试去删除链接到该结构的任何children。
		 * 当有一个children由于仍然被引用而不能被删除时，dst_destroy返回指向该child的一个指针，由dst_free来处理它。
		 */
		if (!dst)
			return;
	}
	/**
	 * 当调用dst_free删除一个引用计数非0的表项，这包括dst_destroy不能删除一个child时的情况，则做以下处理：
 	 *		通过设置其obsolete标志来标记该表项为dead。
 	 *		用两个钩子函数dst_discard_in和dst_discard_out来替换该表项原来的input和output程序，以此来确保相关的路由不能够接收和发送报文。这种处理方式是在设备还没有处于运行或处于down状态（没有设置IFF_UP标志）时的典型做法。
 	 *		将dst_entry结构添加到dst_garbage_list全局链表内，该链表将所有应当被删除的，但由于引用计数非0而还没有被删除的表项链接在一起。
 	 *	 	调整dst_gc_timer定时器在可配置的最小延迟时间（DST_GC_MIN）后到期，在该定时器还没有运行时激活它。
	 */
	__dst_free(dst);
}

static inline void dst_rcu_free(struct rcu_head *head)
{
	struct dst_entry *dst = container_of(head, struct dst_entry, rcu_head);
	dst_free(dst);
}
/**
 * 确认通过网关能够到达目的地址。
 */
static inline void dst_confirm(struct dst_entry *dst)
{
	if (dst)
		neigh_confirm(dst->neighbour);
}

static inline void dst_negative_advice(struct dst_entry **dst_p)
{
	struct dst_entry * dst = *dst_p;
	if (dst && dst->ops->negative_advice)
		*dst_p = dst->ops->negative_advice(dst);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry * dst = skb->dst;
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}

/**
 * 设置路由项过期时间。当以下事件发生时设置:
 *		当接收到一个ICMP UNREACHABLE或FRAGMENTATION NEEDED消息时，所有相关路由项的PMTU必须被更新为ICMP头中指定的MTU。ICMP核心代码调用ip_rt_frag_needed来更新路由缓存。这些受影响的表项在可配置的时间ip_rt_mtu_expires之后被设置为过期，这个时间值缺省为10分钟
 *		当TCP代码用路径MTU发现算法来更新一条路由的MTU时，调用ip_rt_update_pmtu函数，该函数将调用dst_set_expires。
 *		当一个目的IP地址被认为不可达时，通过直接或间接调用dst_ops数据结构中的link_failure方法，将缓存内相关的dst_entry结构标记为不可达
 */
static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}

/* Output packet to network from transport.  */
/**
 * 所有传输（不论是本地产生的还是从其他主机转发而来）都会通过dst_output进行，以到达目的主机。
 * 此时，IP报头已经完成：内含传输所需要的信息以及本地系统要负责添加的其他任何信息。
 */
static inline int dst_output(struct sk_buff *skb)
{
	int err;

	for (;;) {
		/**
		 * 如果目的地址是单播的，会初始化为ip_output，如果是多播的，则会初始化为ip_mc_output
		 * 分段也是在该函数内处理的。
		 * 最后会调用ip_finish_output来处理邻居子系统
		 */
		err = skb->dst->output(skb);

		if (likely(err == 0))
			return err;
		/**
		 * 如果IPSEC返回NET_XMIT_BYPASS，表示需要连续多次进行output。
		 */
		if (unlikely(err != NET_XMIT_BYPASS))
			return err;
	}
}

/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	int err;

	for (;;) {
		err = skb->dst->input(skb);

		if (likely(err == 0))
			return err;
		/* Oh, Jamal... Seems, I will not forgive you this mess. :-) */
		if (unlikely(err != NET_XMIT_BYPASS))
			return err;
	}
}

extern void		dst_init(void);

struct flowi;
#ifndef CONFIG_XFRM
static inline int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags)
{
	return 0;
} 
#else
extern int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags);
#endif
#endif

#endif /* _NET_DST_H */
