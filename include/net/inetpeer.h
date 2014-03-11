/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Version:	$Id: inetpeer.h,v 1.2 2002/01/12 07:54:56 davem Exp $
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

/**
 * 内核会为最近连接过的每个远程主机都保留一个这一结构的实例。
 * 所有inet_peer被一棵AVL组织在一起。
 */
struct inet_peer
{
	/**
	 * 它们是指向两棵子树的左右指针。
	 */
	struct inet_peer	*avl_left, *avl_right;
	/**
	 * 用于把此节点连接到一个内含过期元素的链表。而unused_prevp是用于检查此节点是否在该链表中。
	 */
	struct inet_peer	*unused_next, **unused_prevp;
	/**
	 * 此元素的引用计数值。使用此结构者有路由子系统及TCP层。
	 */
	atomic_t		refcnt;
	/**
	 * 当此元素通过inet_putpeer加入未用链表inet_peer_unuser_head的时间。
	 */
	unsigned long		dtime;		/* the time of last use of not
						 * referenced entries */
	/**
	 * 远程端点的IP地址。
	 */
	__u32			v4daddr;	/* peer's address */
	/**
	 * AVL树的高度。
	 */
	__u16			avl_height;
	/**
	 * 此端点下一个可用的包ID。
	 */
	__u16			ip_id_count;	/* IP ID for the next packet */
	/**
	 * 由TCP使用，管理时间戳。
	 */
	__u32			tcp_ts;
	unsigned long		tcp_ts_stamp;
};

void			inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(__u32 daddr, int create);

extern spinlock_t inet_peer_unused_lock;
extern struct inet_peer *inet_peer_unused_head;
extern struct inet_peer **inet_peer_unused_tailp;
/* can be called from BH context or outside */
static inline void	inet_putpeer(struct inet_peer *p)
{
	spin_lock_bh(&inet_peer_unused_lock);
	if (atomic_dec_and_test(&p->refcnt)) {
		p->unused_prevp = inet_peer_unused_tailp;
		p->unused_next = NULL;
		*inet_peer_unused_tailp = p;
		inet_peer_unused_tailp = &p->unused_next;
		p->dtime = jiffies;
	}
	spin_unlock_bh(&inet_peer_unused_lock);
}

extern spinlock_t inet_peer_idlock;
/* can be called with or without local BH being disabled */
static inline __u16	inet_getid(struct inet_peer *p, int more)
{
	__u16 id;

	spin_lock_bh(&inet_peer_idlock);
	id = p->ip_id_count;
	p->ip_id_count += 1 + more;
	spin_unlock_bh(&inet_peer_idlock);
	return id;
}

#endif /* _NET_INETPEER_H */
