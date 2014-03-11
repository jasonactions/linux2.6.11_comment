/*
 * net/core/dst.c	Protocol independent destination cache.
 *
 * Authors:		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>

#include <net/dst.h>

/* Locking strategy:
 * 1) Garbage collection state of dead destination cache
 *    entries is protected by dst_lock.
 * 2) GC is run only from BH context, and is the only remover
 *    of entries.
 * 3) Entries are added to the garbage list from both BH
 *    and non-BH context, so local BH disabling is needed.
 * 4) All operations modify state, so a spinlock is used.
 */
/**
 * 等待被删除的dst_entry结构组成的链表。
 * 当dst_gc_timer定时器到期时，执行定时处理钩子函数。
 * 只有引用计数__refcnt大于0的（不能被直接删除的）表项才被放入该链表内，以避免被直接删除。新表项被插入到链表首部。
 */
static struct dst_entry 	*dst_garbage_list;
#if RT_CACHE_DEBUG >= 2 
static atomic_t			 dst_total = ATOMIC_INIT(0);
#endif
static DEFINE_SPINLOCK(dst_lock);

/**
 * dst_gc_timer_expires是定时器在到期之前等待的秒数，取值范围在DST_GC_MIN和DST_GC_MAX之间，当定时处理钩子函数dst_run_gc运行而没能清空dst_garbage_list链表时，等待时间增加dst_gc_timer_inc。
 * 但dst_gc_timer_inc必须在DST_GC_MIN到DST_GC_MAX的范围内。
 */
static unsigned long dst_gc_timer_expires;
static unsigned long dst_gc_timer_inc = DST_GC_MAX;
static void dst_run_gc(unsigned long);
static void ___dst_free(struct dst_entry * dst);

static struct timer_list dst_gc_timer =
	TIMER_INITIALIZER(dst_run_gc, DST_GC_MIN, 0);

/**
 * 此垃圾回收定时器周期性地遍历dst_garbage_list链表，利用dst_destroy来删除引用计数为0的表项。
 */
static void dst_run_gc(unsigned long dummy)
{
	int    delayed = 0;
	struct dst_entry * dst, **dstp;

	/**
	 * 锁竞争失败，延后处理。
	 */
	if (!spin_trylock(&dst_lock)) {
		mod_timer(&dst_gc_timer, jiffies + HZ/10);
		return;
	}


	del_timer(&dst_gc_timer);
	dstp = &dst_garbage_list;
	while ((dst = *dstp) != NULL) {
		if (atomic_read(&dst->__refcnt)) {
			dstp = &dst->next;
			delayed++;
			continue;
		}
		*dstp = dst->next;

		/**
		 * 引用计数已经变成0，删除它。
		 */
		dst = dst_destroy(dst);
		/**
		 * 如果child链表中某个节点还被引用，则将节点再次挂入链表，等待下次删除。
		 */
		if (dst) {
			/* NOHASH and still referenced. Unless it is already
			 * on gc list, invalidate it and add to gc list.
			 *
			 * Note: this is temporary. Actually, NOHASH dst's
			 * must be obsoleted when parent is obsoleted.
			 * But we do not have state "obsoleted, but
			 * referenced by parent", so it is right.
			 */
			if (dst->obsolete > 1)
				continue;

			___dst_free(dst);
			dst->next = *dstp;
			*dstp = dst;
			dstp = &dst->next;
		}
	}
	if (!dst_garbage_list) {
		dst_gc_timer_inc = DST_GC_MAX;
		goto out;
	}
	/**
	 * 没有删除所有垃圾DST，重启定时器。
	 */
	if ((dst_gc_timer_expires += dst_gc_timer_inc) > DST_GC_MAX)
		dst_gc_timer_expires = DST_GC_MAX;
	dst_gc_timer_inc += DST_GC_INC;
	dst_gc_timer.expires = jiffies + dst_gc_timer_expires;
#if RT_CACHE_DEBUG >= 2
	printk("dst_total: %d/%d %ld\n",
	       atomic_read(&dst_total), delayed,  dst_gc_timer_expires);
#endif
	add_timer(&dst_gc_timer);

out:
	spin_unlock(&dst_lock);
}

static int dst_discard_in(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static int dst_discard_out(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

/**
 * 分配一个路由缓存表项。根据所处的环境，可能返回rtable(IPV4)也可能返回rt6_info(IPV6)。
 */
void * dst_alloc(struct dst_ops * ops)
{
	struct dst_entry * dst;

	/**
	 * 检查缓存项是否超过限制，如果是，则启动回收过程。
	 */
	if (ops->gc && atomic_read(&ops->entries) > ops->gc_thresh) {
		if (ops->gc())
			return NULL;
	}
	/**
	 * 为新缓存表项分配空间。
	 */
	dst = kmem_cache_alloc(ops->kmem_cachep, SLAB_ATOMIC);
	if (!dst)
		return NULL;
	/**
	 * 对缓存项的一些字段初始化，尤其重要的是以下字段：
	 * 		rth->u.dst.input
	 * 		rth->u.dst.output
	 */
	memset(dst, 0, ops->entry_size);
	atomic_set(&dst->__refcnt, 0);
	dst->ops = ops;
	dst->lastuse = jiffies;
	dst->path = dst;
	dst->input = dst_discard_in;
	dst->output = dst_discard_out;
#if RT_CACHE_DEBUG >= 2 
	atomic_inc(&dst_total);
#endif
	atomic_inc(&ops->entries);
	return dst;
}

static void ___dst_free(struct dst_entry * dst)
{
	/* The first case (dev==NULL) is required, when
	   protocol module is unloaded.
	 */
	if (dst->dev == NULL || !(dst->dev->flags&IFF_UP)) {
		dst->input = dst_discard_in;
		dst->output = dst_discard_out;
	}
	dst->obsolete = 2;
}

void __dst_free(struct dst_entry * dst)
{
	spin_lock_bh(&dst_lock);
	___dst_free(dst);
	dst->next = dst_garbage_list;
	dst_garbage_list = dst;
	if (dst_gc_timer_inc > DST_GC_INC) {
		dst_gc_timer_inc = DST_GC_INC;
		dst_gc_timer_expires = DST_GC_MIN;
		mod_timer(&dst_gc_timer, jiffies + dst_gc_timer_expires);
	}
	spin_unlock_bh(&dst_lock);
}

struct dst_entry *dst_destroy(struct dst_entry * dst)
{
	struct dst_entry *child;
	struct neighbour *neigh;
	struct hh_cache *hh;

	smp_rmb();

again:
	neigh = dst->neighbour;
	hh = dst->hh;
	child = dst->child;

	dst->hh = NULL;
	if (hh && atomic_dec_and_test(&hh->hh_refcnt))
		kfree(hh);

	if (neigh) {
		dst->neighbour = NULL;
		neigh_release(neigh);
	}

	atomic_dec(&dst->ops->entries);

	if (dst->ops->destroy)
		dst->ops->destroy(dst);
	if (dst->dev)
		dev_put(dst->dev);
#if RT_CACHE_DEBUG >= 2 
	atomic_dec(&dst_total);
#endif
	kmem_cache_free(dst->ops->kmem_cachep, dst);

	dst = child;
	if (dst) {
		if (atomic_dec_and_test(&dst->__refcnt)) {
			/* We were real parent of this dst, so kill child. */
			if (dst->flags&DST_NOHASH)
				goto again;
		} else {
			/* Child is still referenced, return it for freeing. */
			if (dst->flags&DST_NOHASH)
				return dst;
			/* Child is still in his hash table */
		}
	}
	return NULL;
}

/* Dirty hack. We did it in 2.2 (in __dst_free),
 * we have _very_ good reasons not to repeat
 * this mistake in 2.3, but we have no choice
 * now. _It_ _is_ _explicit_ _deliberate_
 * _race_ _condition_.
 *
 * Commented and originally written by Alexey.
 */
static inline void dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			      int unregister)
{
	if (dst->ops->ifdown)
		dst->ops->ifdown(dst, dev, unregister);

	if (dev != dst->dev)
		return;

	if (!unregister) {
		/**
		 * 因为设备为down，所以不再能够向该设备发送流量。
		 * 因而，dst_entry中的input和output程序被分别设置为dst_discard_in和dst_discard_out。
		 * 这两个程序将送来的任何输入buffer（即它们被要求处理的任意帧）简单丢弃掉。
		 */
		dst->input = dst_discard_in;
		dst->output = dst_discard_out;
	} else {
		/**
		 * 当设备被注销时，对该设备的所有引用都必须被删除。
		 * dst_ifdown将dst_entry结构和相关的neighbour实例中到该设备的引用都替换为到loopback设备的引用。
		 */
		dst->dev = &loopback_dev;
		dev_hold(&loopback_dev);
		dev_put(dev);
		if (dst->neighbour && dst->neighbour->dev == dev) {
			dst->neighbour->dev = &loopback_dev;
			dev_put(dev);
			dev_hold(&loopback_dev);
		}
	}
}

/**
 * DST子系统处理设备事件的代码。
 */
static int dst_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct dst_entry *dst;

	switch (event) {
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
		spin_lock_bh(&dst_lock);
		/**
		 * 遍历由dead dst_entry结构组成的dst_garbage_list链表，对每一项调用dst_ifdown。
		 * dst_ifdown的最后一个输入参数为要处理的事件。
		 */
		for (dst = dst_garbage_list; dst; dst = dst->next) {
			dst_ifdown(dst, dev, event != NETDEV_DOWN);
		}
		spin_unlock_bh(&dst_lock);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block dst_dev_notifier = {
	.notifier_call	= dst_dev_event,
};

/**
 * 初始化DST协议无关路由缓存。由net_dev_init调用。
 */
void __init dst_init(void)
{
	register_netdevice_notifier(&dst_dev_notifier);
}

EXPORT_SYMBOL(__dst_free);
EXPORT_SYMBOL(dst_alloc);
EXPORT_SYMBOL(dst_destroy);
