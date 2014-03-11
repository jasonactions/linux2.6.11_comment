/*
 *	Generic address resolution entity
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *	Fixes:
 *	Vitaly E. Lavrov	releasing NULL neighbor in neigh_add.
 *	Harald Welte		Add neighbour cache statistics like rtstat
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif
#include <linux/times.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/random.h>

#define NEIGH_DEBUG 1

#define NEIGH_PRINTK(x...) printk(x)
#define NEIGH_NOPRINTK(x...) do { ; } while(0)
#define NEIGH_PRINTK0 NEIGH_PRINTK
#define NEIGH_PRINTK1 NEIGH_NOPRINTK
#define NEIGH_PRINTK2 NEIGH_NOPRINTK

#if NEIGH_DEBUG >= 1
#undef NEIGH_PRINTK1
#define NEIGH_PRINTK1 NEIGH_PRINTK
#endif
#if NEIGH_DEBUG >= 2
#undef NEIGH_PRINTK2
#define NEIGH_PRINTK2 NEIGH_PRINTK
#endif

#define PNEIGH_HASHMASK		0xF

static void neigh_timer_handler(unsigned long arg);
#ifdef CONFIG_ARPD
static void neigh_app_notify(struct neighbour *n);
#endif
static int pneigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);

/**
 * 所有的邻居协议链表。由neigh_tbl_lock来加以保护。
 */
static struct neigh_table *neigh_tables;
static struct file_operations neigh_stat_seq_fops;

/*
   Neighbour hash table buckets are protected with rwlock tbl->lock.

   - All the scans/updates to hash buckets MUST be made under this lock.
   - NOTHING clever should be made under this lock: no callbacks
     to protocol backends, no attempts to send something to network.
     It will result in deadlocks, if backend/driver wants to use neighbour
     cache.
   - If the entry requires some non-trivial actions, increase
     its reference count and release table lock.

   Neighbour entries are protected:
   - with reference count.
   - with rwlock neigh->lock

   Reference count prevents destruction.

   neigh->lock mainly serializes ll address data and its validity state.
   However, the same lock is used to protect another entry fields:
    - timer
    - resolution queue

   Again, nothing clever shall be made under neigh->lock,
   the most complicated procedure, which we allow is dev->hard_header.
   It is supposed, that dev->hard_header is simplistic and does
   not make callbacks to neighbour tables.

   The last lock is neigh_tbl_lock. It is pure SMP lock, protecting
   list of neighbour tables. This list is used only in process context,
 */
/**
 * 保护邻居协议链表的锁。
 */
static DEFINE_RWLOCK(neigh_tbl_lock);

/**
 * 该函数用于处理neighbour结构不能删除的临时情况。因为有人仍要调用这个neighbour结构。
 * 函数neigh_blackhole会丢弃在输入接口上接收的任何包。
 * 为了确保任何试图给邻居传送包的行为不会发生，这样处理是必须的。因为邻居的数据结构将要被删除。
 */
static int neigh_blackhole(struct sk_buff *skb)
{
	kfree_skb(skb);
	return -ENETDOWN;
}

/*
 * It is random distribution in the interval (1/2)*base...(3/2)*base.
 * It corresponds to default IPv6 settings and is not overridable,
 * because it is really reasonable choice.
 */

unsigned long neigh_rand_reach_time(unsigned long base)
{
	return (base ? (net_random() % base) + (base >> 1) : 0);
}

/**
 * 同步清理邻居项缓存。
 */
static int neigh_forced_gc(struct neigh_table *tbl)
{
	int shrunk = 0;
	int i;

	/**
	 * 强制回收计数。
	 */
	NEIGH_CACHE_STAT_INC(tbl, forced_gc_runs);

	write_lock_bh(&tbl->lock);
	/**
	 * 遍历hash表中的每一个桶。
	 */
	for (i = 0; i <= tbl->hash_mask; i++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[i];
		/**
		 * 遍历桶中的每一个元素。
		 */
		while ((n = *np) != NULL) {
			/* Neighbour record may be discarded if:
			 * - nobody refers to it.
			 * - it is not permanent
			 */
			write_lock(&n->lock);
			/**
			 * 当引用计数为1，说明没有谁在使用邻居项。
			 * 同时，管理员手工添加的项不能删除。
			 */
			if (atomic_read(&n->refcnt) == 1 &&
			    !(n->nud_state & NUD_PERMANENT)) {
				*np	= n->next;
				n->dead = 1;
				shrunk	= 1;
				write_unlock(&n->lock);
				neigh_release(n);
				continue;
			}
			write_unlock(&n->lock);
			np = &n->next;
		}
	}

	/**
	 * 记录最后一次清理的时间。
	 */
	tbl->last_flush = jiffies;

	write_unlock_bh(&tbl->lock);

	return shrunk;
}

static int neigh_del_timer(struct neighbour *n)
{
	if ((n->nud_state & NUD_IN_TIMER) &&
	    del_timer(&n->timer)) {
		neigh_release(n);
		return 1;
	}
	return 0;
}

static void pneigh_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(list)) != NULL) {
		dev_put(skb->dev);
		kfree_skb(skb);
	}
}

/**
 * 当一个本地设备的L2地址发生变化时，邻居协议调用该函数来更新协议的缓存。
 */
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev)
{
	int i;

	write_lock_bh(&tbl->lock);

	/**
	 * 遍历邻居桶
	 */
	for (i=0; i <= tbl->hash_mask; i++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[i];
		/**
		 * 遍历所有邻居项。
		 */
		while ((n = *np) != NULL) {
			/**
			 * 该邻居项没有与关闭设备关联，处理下一个邻居项。
			 */
			if (dev && n->dev != dev) {
				np = &n->next;
				continue;
			}
			/**
			 * 停用邻居，但是不会立即删除。
			 */
			*np = n->next;
			write_lock_bh(&n->lock);
			/**
			 * 标记为停用。垃圾回收进程会负责处理这些停用项。
			 */
			n->dead = 1;
			/**
			 * 停止所有未决的定时器。
			 */
			neigh_del_timer(n);
			write_unlock_bh(&n->lock);
			neigh_release(n);
		}
	}

        write_unlock_bh(&tbl->lock);
}

/**
 * 其他的内核子系统要调用该函数，以通知邻居子系统有关设备和L3地址的变化。
 * L3地址的改变的通知由L3协议送出。
 */
int neigh_ifdown(struct neigh_table *tbl, struct net_device *dev)
{
	int i;

	write_lock_bh(&tbl->lock);

	for (i = 0; i <= tbl->hash_mask; i++) {
		struct neighbour *n, **np = &tbl->hash_buckets[i];

		while ((n = *np) != NULL) {
			if (dev && n->dev != dev) {
				np = &n->next;
				continue;
			}
			*np = n->next;
			write_lock(&n->lock);
			/**
			 * 停止所有未决的定时器。
			 */
			neigh_del_timer(n);
			n->dead = 1;

			if (atomic_read(&n->refcnt) != 1) {
				/* The most unpleasant situation.
				   We must destroy neighbour entry,
				   but someone still uses it.

				   The destroy will be delayed until
				   the last user releases us, but
				   we must kill timers etc. and move
				   it to safe state.
				 */
				/**
				 * 调用skb_queue_purge，将所有在arp_queue队列中待处理的包丢弃。
				 */
				skb_queue_purge(&n->arp_queue);
				n->output = neigh_blackhole;
				/**
				 * 将相关邻居项的状态改为NUD_NOARP态，这样试图使用该邻居项的任何流量不再会触发solicitation请求。
				 */
				if (n->nud_state & NUD_VALID)
					n->nud_state = NUD_NOARP;
				else
					n->nud_state = NUD_NONE;
				NEIGH_PRINTK2("neigh %p is stray.\n", n);
			}
			write_unlock(&n->lock);
			neigh_release(n);
		}
	}

	pneigh_ifdown(tbl, dev);
	write_unlock_bh(&tbl->lock);

	del_timer_sync(&tbl->proxy_timer);
	/**
	 * pneigh_ifdown清理代理缓存和代理服务器的proxy_queue队列中的相关项。
	 */
	pneigh_queue_purge(&tbl->proxy_queue);
	return 0;
}

static struct neighbour *neigh_alloc(struct neigh_table *tbl)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	entries = atomic_inc_return(&tbl->entries) - 1;
	/**
	 * 当前分配的邻居结构数目大于配置的阀值
	 */
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {
	    /**
	     * 垃圾回收器试图释放某块内存
	     */
		if (!neigh_forced_gc(tbl) &&
		    entries >= tbl->gc_thresh3)
		    /**
		     * 无法完成分配，失败。
		     */
			goto out_entries;
	}

	/**
	 * 分配一块内存。
	 */
	n = kmem_cache_alloc(tbl->kmem_cachep, SLAB_ATOMIC);
	if (!n)
		goto out_entries;

	/**
	 * 初始化一些值。
	 * 例如，嵌入的定时器、引用计数器、指向关联的neigh_table（邻居协议）结构的指针和对分配的neighbour结构数目的整体统计。
	 */
	skb_queue_head_init(&n->arp_queue);
	rwlock_init(&n->lock);
	n->updated	  = n->used = now;
	n->nud_state	  = NUD_NONE;
	n->output	  = neigh_blackhole;
	n->parms	  = neigh_parms_clone(&tbl->parms);
	init_timer(&n->timer);
	n->timer.function = neigh_timer_handler;
	n->timer.data	  = (unsigned long)n;

	NEIGH_CACHE_STAT_INC(tbl, allocs);
	n->tbl		  = tbl;
	atomic_set(&n->refcnt, 1);
	n->dead		  = 1;
out:
	return n;

out_entries:
	atomic_dec(&tbl->entries);
	goto out;
}

/**
 * 分配邻居子系统所用的hash表。
 */
static struct neighbour **neigh_hash_alloc(unsigned int entries)
{
	unsigned long size = entries * sizeof(struct neighbour *);
	struct neighbour **ret;

	if (size <= PAGE_SIZE) {
		ret = kmalloc(size, GFP_ATOMIC);
	} else {
		ret = (struct neighbour **)
			__get_free_pages(GFP_ATOMIC, get_order(size));
	}
	if (ret)
		memset(ret, 0, size);

	return ret;
}

/**
 * 释放邻居子系统使用的hash表。
 */
static void neigh_hash_free(struct neighbour **hash, unsigned int entries)
{
	unsigned long size = entries * sizeof(struct neighbour *);

	if (size <= PAGE_SIZE)
		kfree(hash);
	else
		free_pages((unsigned long)hash, get_order(size));
}

/**
 * 扩充邻居子系统使用的hash表。
 */
static void neigh_hash_grow(struct neigh_table *tbl, unsigned long new_entries)
{
	struct neighbour **new_hash, **old_hash;
	unsigned int i, new_hash_mask, old_entries;

	NEIGH_CACHE_STAT_INC(tbl, hash_grows);

	BUG_ON(new_entries & (new_entries - 1));
	new_hash = neigh_hash_alloc(new_entries);
	if (!new_hash)
		return;

	old_entries = tbl->hash_mask + 1;
	new_hash_mask = new_entries - 1;
	old_hash = tbl->hash_buckets;

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));
	for (i = 0; i < old_entries; i++) {
		struct neighbour *n, *next;

		for (n = old_hash[i]; n; n = next) {
			unsigned int hash_val = tbl->hash(n->primary_key, n->dev);

			hash_val &= new_hash_mask;
			next = n->next;

			n->next = new_hash[hash_val];
			new_hash[hash_val] = n;
		}
	}
	tbl->hash_buckets = new_hash;
	tbl->hash_mask = new_hash_mask;

	neigh_hash_free(old_hash, old_entries);
}

/**
 * 检查要查找的元素是否存在，并且在查找成功时返回指向该元素的指针。
 */
struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	struct neighbour *n;
	int key_len = tbl->key_len;
	u32 hash_val = tbl->hash(pkey, dev) & tbl->hash_mask;
	
	NEIGH_CACHE_STAT_INC(tbl, lookups);

	read_lock_bh(&tbl->lock);
	for (n = tbl->hash_buckets[hash_val]; n; n = n->next) {
		if (dev == n->dev && !memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);
			NEIGH_CACHE_STAT_INC(tbl, hits);
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;
}

/**
 * 邻居缓存查找，只在DECNet协议中使用。
 */
struct neighbour *neigh_lookup_nodev(struct neigh_table *tbl, const void *pkey)
{
	struct neighbour *n;
	int key_len = tbl->key_len;
	u32 hash_val = tbl->hash(pkey, NULL) & tbl->hash_mask;

	NEIGH_CACHE_STAT_INC(tbl, lookups);

	read_lock_bh(&tbl->lock);
	for (n = tbl->hash_buckets[hash_val]; n; n = n->next) {
		if (!memcmp(n->primary_key, pkey, key_len)) {
			neigh_hold(n);
			NEIGH_CACHE_STAT_INC(tbl, hits);
			break;
		}
	}
	read_unlock_bh(&tbl->lock);
	return n;
}

/**
 * 创建一个邻居项。以下情况会进行邻居项的创建:
 *		传输请求
 *		收到solicitation请求
 *		手工添加
 *		tbl：		表示使用的邻居协议。设置这个参数的方式很简单：如果调用者来自IPV4程序（也就是说，来自arp_rcv），就设为arp_tbl等等。
 *		Pkey：		表示L3地址。之所以称为pkey是因为它在缓存查找中被用作查找关键字。
 *		dev：		与要创建的邻居项相关的设备。因为每个neighbour项都与一个L3地址相关联，并且后者总是与一个设备相关联，所以neighbour实例就与一个设备相关联。
 *		返回值是指向创建的neighbour结构的指针。
 */
struct neighbour *neigh_create(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev)
{
	u32 hash_val;
	int key_len = tbl->key_len;
	int error;
	/**
	 * 用neigh_alloc函数来分配存储空间。
	 * 该函数也用于初始化一些参数，例如，嵌入的定时器、引用计数器、指向关联的neigh_table（邻居协议）结构的指针和对分配的neighbour结构数目的整体统计。
	 */
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl);

	if (!n) {
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}

	/**
	 * 在key_len的帮助下，pkey被复制到邻居数据结构中。Key_len提供被复制的数据的长度。
	 * 这是必要的，因为neighbour结构是被与协议无关的缓存查找函数使用，并且各种邻居协议表示地址的字节长度不同。
	 */
	memcpy(n->primary_key, pkey, key_len);
	/**
	 * 由于neighbour项中包括了对net_device结构中dev的引用，内核会使用dev_hold来对后者的引用计数器加，以此保证该设备在neighbour结构存在时不会被删除。
	 */
	n->dev = dev;
	dev_hold(dev);

	/* Protocol specific setup. */
	/**
	 * neighbour结构有两种初始化方式：一种由邻居协议执行，一种由设备执行。
	 * 协议执行的初始化靠调用neigh_table->constructor函数完成。
	 */
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	/* Device specific setup. */
	/**
	 * 设备执行的初始化工作由neigh_setup虚函数完成。
	 * 实际上只有少数设备定义了这个函数。例如，shaper虚拟设备使用这个设置函数来保证它与ARP提供一个特殊neigh_ops结构的实例相关联。
	 * 一些WAN设备出于类似的原因使用一个设置函数。
	 */
	if (n->parms->neigh_setup &&
	    (error = n->parms->neigh_setup(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	/**
	 * 设置创建的邻居项的confirmed字段，表示该邻居是可到达的。
	 * 正常情况下，该字段由可到达性证明来更新，并且其值设为用jiffies表示的当前时间。
	 * 但在这里，从新建的角度来说，neigh_create会把confirmed值减去一小段时间（reachable_time值的一半），这样就使得邻居状态能比平常和要求有可到达性证据时，稍快一点转移到NUD_STALE状态。
	 */
	n->confirmed = jiffies - (n->parms->base_reachable_time << 1);

	/**
	 * 一旦邻居项被初始化后，就使用邻居协议提供的hash函数将它增加到主要缓存中。
	 */
	write_lock_bh(&tbl->lock);

	if (atomic_read(&tbl->entries) > (tbl->hash_mask + 1))
		neigh_hash_grow(tbl, (tbl->hash_mask + 1) << 1);

	hash_val = tbl->hash(pkey, dev) & tbl->hash_mask;

	if (n->parms->dead) {
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}

	for (n1 = tbl->hash_buckets[hash_val]; n1; n1 = n1->next) {
		if (dev == n1->dev && !memcmp(n1->primary_key, pkey, key_len)) {
			neigh_hold(n1);
			rc = n1;
			goto out_tbl_unlock;
		}
	}

	n->next = tbl->hash_buckets[hash_val];
	tbl->hash_buckets[hash_val] = n;
	n->dead = 0;
	neigh_hold(n);
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK2("neigh %p is created.\n", n);
	rc = n;
out:
	return rc;
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	neigh_release(n);
	goto out;
}

/**
 * 按目的地进行代理时，搜索被代理的地址。
 */
struct pneigh_entry * pneigh_lookup(struct neigh_table *tbl, const void *pkey,
				    struct net_device *dev, int creat)
{
	struct pneigh_entry *n;
	int key_len = tbl->key_len;
	u32 hash_val = *(u32 *)(pkey + key_len - 4);

	hash_val ^= (hash_val >> 16);
	hash_val ^= hash_val >> 8;
	hash_val ^= hash_val >> 4;
	hash_val &= PNEIGH_HASHMASK;

	read_lock_bh(&tbl->lock);

	for (n = tbl->phash_buckets[hash_val]; n; n = n->next) {
		if (!memcmp(n->key, pkey, key_len) &&
		    (n->dev == dev || !n->dev)) {
			read_unlock_bh(&tbl->lock);
			goto out;
		}
	}
	read_unlock_bh(&tbl->lock);
	n = NULL;
	if (!creat)
		goto out;

	n = kmalloc(sizeof(*n) + key_len, GFP_KERNEL);
	if (!n)
		goto out;

	memcpy(n->key, pkey, key_len);
	n->dev = dev;
	if (dev)
		dev_hold(dev);

	if (tbl->pconstructor && tbl->pconstructor(n)) {
		if (dev)
			dev_put(dev);
		kfree(n);
		n = NULL;
		goto out;
	}

	write_lock_bh(&tbl->lock);
	n->next = tbl->phash_buckets[hash_val];
	tbl->phash_buckets[hash_val] = n;
	write_unlock_bh(&tbl->lock);
out:
	return n;
}

/**
 * 按目的地进行代理时，删除被代理的项。
 */
int pneigh_delete(struct neigh_table *tbl, const void *pkey,
		  struct net_device *dev)
{
	struct pneigh_entry *n, **np;
	int key_len = tbl->key_len;
	u32 hash_val = *(u32 *)(pkey + key_len - 4);

	hash_val ^= (hash_val >> 16);
	hash_val ^= hash_val >> 8;
	hash_val ^= hash_val >> 4;
	hash_val &= PNEIGH_HASHMASK;

	write_lock_bh(&tbl->lock);
	for (np = &tbl->phash_buckets[hash_val]; (n = *np) != NULL;
	     np = &n->next) {
		if (!memcmp(n->key, pkey, key_len) && n->dev == dev) {
			*np = n->next;
			write_unlock_bh(&tbl->lock);
			if (tbl->pdestructor)
				tbl->pdestructor(n);
			if (n->dev)
				dev_put(n->dev);
			kfree(n);
			return 0;
		}
	}
	write_unlock_bh(&tbl->lock);
	return -ENOENT;
}

static int pneigh_ifdown(struct neigh_table *tbl, struct net_device *dev)
{
	struct pneigh_entry *n, **np;
	u32 h;

	for (h = 0; h <= PNEIGH_HASHMASK; h++) {
		np = &tbl->phash_buckets[h];
		while ((n = *np) != NULL) {
			if (!dev || n->dev == dev) {
				*np = n->next;
				if (tbl->pdestructor)
					tbl->pdestructor(n);
				if (n->dev)
					dev_put(n->dev);
				kfree(n);
				continue;
			}
			np = &n->next;
		}
	}
	return -ENOENT;
}


/*
 *	neighbour must already be out of the table;
 *
 */
void neigh_destroy(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_CACHE_STAT_INC(neigh->tbl, destroys);

	if (!neigh->dead) {
		printk(KERN_WARNING
		       "Destroying alive neighbour %p\n", neigh);
		dump_stack();
		return;
	}

	/**
	 * 停止所有未决的定时器。理论上，在执行neigh_destroy函数时，不应该有任何定时器是未决的。
	 * 因为neigh_release调用neigh_destroy的条件是引用计数器为0，而且定时器运行时总是保持对要删除的数据结构的引用。
	 */
	if (neigh_del_timer(neigh))
		printk(KERN_WARNING "Impossible event.\n");

	/**
	 * 释放所有对外部数据结构的引用。例如，关联的设备及缓存的L2帧头。
	 */
	while ((hh = neigh->hh) != NULL) {
		neigh->hh = hh->hh_next;
		hh->hh_next = NULL;

		write_seqlock_bh(&hh->hh_lock);
		/**
		 * 设置缓存的L2帧头中的hh_cache->hh_output字段为neigh_blackhole。
		 */
		hh->hh_output = neigh_blackhole;
		write_unlock_bh(&hh->hh_lock);
		if (atomic_dec_and_test(&hh->hh_refcnt))
			kfree(hh);
	}

	/**
	 * 如果arp_queue队列非空，就要将其清空（删除其所有元素）。
	 */
	skb_queue_purge(&neigh->arp_queue);

	dev_put(neigh->dev);
	neigh_parms_put(neigh->parms);

	NEIGH_PRINTK2("neigh %p is destroyed.\n", neigh);

	/**
	 * 将表示主机使用的neighbour项总数的全局计数器减1。
	 */
	atomic_dec(&neigh->tbl->entries);
	/**
	 * 释放该neighbour结构。
	 */
	kmem_cache_free(neigh->tbl->kmem_cachep, neigh);
}

/* Neighbour state is suspicious;
   disable fast path.

   Called with write_locked neigh.
 */
/**
 * 执行可到达性确认。同时将neighbour->output设置为neigh_ops->output。
 */
static void neigh_suspect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);

	neigh->output = neigh->ops->output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->output;
}

/* Neighbour state is OK;
   enable fast path.

   Called with write_locked neigh.
 */
/**
 * 无论什么时候进入NUD_REACHABLE状态，邻居基础结构就调用neigh_connect函数，将neigh->output函数指向neigh_ops->connected_output。
 * 可能的触发点包含:
 *		 	收到一个solicitation应答
 *			L4认证
 *	 		人工配置
 */
static void neigh_connect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	NEIGH_PRINTK2("neigh %p is connected.\n", neigh);

	neigh->output = neigh->ops->connected_output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->hh_output;
}

/**
 * 邻居子系统垃圾回收定时器。这是一个周期性定时器，用于确保内存不会浪费在没用的数据结构上。
 */
static void neigh_periodic_timer(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;
	struct neighbour *n, **np;
	unsigned long expire, now = jiffies;

	NEIGH_CACHE_STAT_INC(tbl, periodic_gc_runs);

	write_lock(&tbl->lock);

	/*
	 *	periodically recompute ReachableTime from random function
	 */
	/**
	 * 如果与上次时间相差5分钟，那么重新设置配置参数中的reachable_time时间。
	 */
	if (time_after(now, tbl->last_rand + 300 * HZ)) {
		struct neigh_parms *p;
		tbl->last_rand = now;
		for (p = &tbl->parms; p; p = p->next)
			p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
	}

	/**
	 * 从上次扫描的桶开始扫描。
	 */
	np = &tbl->hash_buckets[tbl->hash_chain_gc];
	tbl->hash_chain_gc = ((tbl->hash_chain_gc + 1) & tbl->hash_mask);

	/**
	 * 每次只扫描一个桶。
	 */
	while ((n = *np) != NULL) {
		unsigned int state;

		write_lock(&n->lock);

		state = n->nud_state;
		/**
		 * 这两种状态的邻居项不被回收。
		 */
		if (state & (NUD_PERMANENT | NUD_IN_TIMER)) {
			write_unlock(&n->lock);
			goto next_elt;
		}

		/**
		 * neigh->confirmed表示一个最新的时间戳
		 */
		if (time_before(n->used, n->confirmed))
			n->used = n->confirmed;

		/**
		 * 如果引用计数为1，表示没有谁在引用该结构了。
		 * 同时，如果对象状态为NUD_FAILED，表示无效的邻居项，可以删除。
		 * 或者如果当前时间已经超过稳定期，也可以删除它。
		 */
		if (atomic_read(&n->refcnt) == 1 &&
		    (state == NUD_FAILED ||
		     time_after(now, n->used + n->parms->gc_staletime))) {
			*np = n->next;
			/**
			 * 在锁的保护下设置dead标志，那么其他内核代码将不会再试图使用这个项。
			 */
			n->dead = 1;
			write_unlock(&n->lock);
			neigh_release(n);
			continue;
		}
		write_unlock(&n->lock);

next_elt:
		np = &n->next;
	}

 	/* Cycle through all hash buckets every base_reachable_time/2 ticks.
 	 * ARP entry timeouts range from 1/2 base_reachable_time to 3/2
 	 * base_reachable_time.
	 */
	expire = tbl->parms.base_reachable_time >> 1;
	expire /= (tbl->hash_mask + 1);
	if (!expire)
		expire = 1;

 	mod_timer(&tbl->gc_timer, now + expire);

	write_unlock(&tbl->lock);
}

static __inline__ int neigh_max_probes(struct neighbour *n)
{
	struct neigh_parms *p = n->parms;
	return (n->nud_state & NUD_PROBE ?
		p->ucast_probes :
		p->ucast_probes + p->app_probes + p->mcast_probes);
}


/* Called when a timer expires for a neighbour entry. */

/**
 * 当用neigh_alloc函数创建一个neighbour项时，会为它创建一个状态转换定时器。
 * 该定时器的回调函数被初始化为neigh_timer_handler函数。
 */
static void neigh_timer_handler(unsigned long arg)
{
	unsigned long now, next;
	struct neighbour *neigh = (struct neighbour *)arg;
	unsigned state;
	int notify = 0;

	write_lock(&neigh->lock);

	state = neigh->nud_state;
	now = jiffies;
	next = now + HZ;

	if (!(state & NUD_IN_TIMER)) {
#ifndef CONFIG_SMP
		printk(KERN_WARNING "neigh: timer & !nud_in_timer\n");
#endif
		goto out;
	}

	if (state & NUD_REACHABLE) {
		if (time_before_eq(now, 
				   neigh->confirmed + neigh->parms->reachable_time)) {
			NEIGH_PRINTK2("neigh %p is still alive.\n", neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else if (time_before_eq(now,
					  neigh->used + neigh->parms->delay_probe_time)) {
			NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
			neigh->nud_state = NUD_DELAY;
			neigh_suspect(neigh);
			next = now + neigh->parms->delay_probe_time;
		} else {
			NEIGH_PRINTK2("neigh %p is suspected.\n", neigh);
			neigh->nud_state = NUD_STALE;
			neigh_suspect(neigh);
		}
	} else if (state & NUD_DELAY) {
		if (time_before_eq(now, 
				   neigh->confirmed + neigh->parms->delay_probe_time)) {
			NEIGH_PRINTK2("neigh %p is now reachable.\n", neigh);
			neigh->nud_state = NUD_REACHABLE;
			neigh_connect(neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else {
			NEIGH_PRINTK2("neigh %p is probed.\n", neigh);
			neigh->nud_state = NUD_PROBE;
			atomic_set(&neigh->probes, 0);
			next = now + neigh->parms->retrans_time;
		}
	} else {
		/* NUD_PROBE|NUD_INCOMPLETE */
		next = now + neigh->parms->retrans_time;
	}

	if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
	    atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
		struct sk_buff *skb;

		neigh->nud_state = NUD_FAILED;
		notify = 1;
		NEIGH_CACHE_STAT_INC(neigh->tbl, res_failed);
		NEIGH_PRINTK2("neigh %p is failed.\n", neigh);

		/* It is very thin place. report_unreachable is very complicated
		   routine. Particularly, it can hit the same neighbour entry!

		   So that, we try to be accurate and avoid dead loop. --ANK
		 */
		while (neigh->nud_state == NUD_FAILED &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			write_unlock(&neigh->lock);
			neigh->ops->error_report(neigh, skb);
			write_lock(&neigh->lock);
		}
		skb_queue_purge(&neigh->arp_queue);
	}

	if (neigh->nud_state & NUD_IN_TIMER) {
		neigh_hold(neigh);
		if (time_before(next, jiffies + HZ/2))
			next = jiffies + HZ/2;
		neigh->timer.expires = next;
		add_timer(&neigh->timer);
	}
	if (neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) {
		struct sk_buff *skb = skb_peek(&neigh->arp_queue);
		/* keep skb alive even if arp_queue overflows */
		if (skb)
			skb_get(skb);
		write_unlock(&neigh->lock);
		neigh->ops->solicit(neigh, skb);
		atomic_inc(&neigh->probes);
		if (skb)
			kfree_skb(skb);
	} else {
out:
		write_unlock(&neigh->lock);
	}

#ifdef CONFIG_ARPD
	if (notify && neigh->parms->app_probes)
		neigh_app_notify(neigh);
#endif
	neigh_release(neigh);
}

int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	unsigned long now;

	write_lock_bh(&neigh->lock);

	rc = 0;
	if (neigh->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		goto out_unlock_bh;

	now = jiffies;
	
	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {
		if (neigh->parms->mcast_probes + neigh->parms->app_probes) {
			atomic_set(&neigh->probes, neigh->parms->ucast_probes);
			neigh->nud_state     = NUD_INCOMPLETE;
			neigh_hold(neigh);
			neigh->timer.expires = now + 1;
			add_timer(&neigh->timer);
		} else {
			neigh->nud_state = NUD_FAILED;
			write_unlock_bh(&neigh->lock);

			if (skb)
				kfree_skb(skb);
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {
		NEIGH_PRINTK2("neigh %p is delayed.\n", neigh);
		neigh_hold(neigh);
		neigh->nud_state = NUD_DELAY;
		neigh->timer.expires = jiffies + neigh->parms->delay_probe_time;
		add_timer(&neigh->timer);
	}

	if (neigh->nud_state == NUD_INCOMPLETE) {
		if (skb) {
			if (skb_queue_len(&neigh->arp_queue) >=
			    neigh->parms->queue_len) {
				struct sk_buff *buff;
				buff = neigh->arp_queue.next;
				__skb_unlink(buff, &neigh->arp_queue);
				kfree_skb(buff);
			}
			__skb_queue_tail(&neigh->arp_queue, skb);
		}
		rc = 1;
	}
out_unlock_bh:
	write_unlock_bh(&neigh->lock);
	return rc;
}

/**
 * 当系统探测到邻居的L2地址发生变化，它就调用neigh_update_hhs函数来处理。
 */
static __inline__ void neigh_update_hhs(struct neighbour *neigh)
{
	struct hh_cache *hh;
	/**
	 * 调用设备驱动程序提供的header_cache_update函数来完成更新
	 */
	void (*update)(struct hh_cache*, struct net_device*, unsigned char *) =
		neigh->dev->header_cache_update;

	if (update) {
		/**
		 * 依次更新那个邻居使用的所有缓存帧头。
		 */
		for (hh = neigh->hh; hh; hh = hh->hh_next) {
			write_lock_bh(&hh->hh_lock);
			update(hh, neigh->dev, neigh->ha);
			write_unlock_bh(&hh->hh_lock);
		}
	}
}



/* Generic update routine.
   -- lladdr is new lladdr or NULL, if it is not supplied.
   -- new    is new state.
   -- flags
	NEIGH_UPDATE_F_OVERRIDE allows to override existing lladdr,
				if it is different.
	NEIGH_UPDATE_F_WEAK_OVERRIDE will suspect existing "connected"
				lladdr instead of overriding it 
				if it is different.
				It also allows to retain current state
				if lladdr is unchanged.
	NEIGH_UPDATE_F_ADMIN	means that the change is administrative.

	NEIGH_UPDATE_F_OVERRIDE_ISROUTER allows to override existing 
				NTF_ROUTER flag.
	NEIGH_UPDATE_F_ISROUTER	indicates if the neighbour is known as
				a router.

   Caller MUST hold reference count on the entry.
 */
/**
 * 用于更新neighbour结构链路层地址的通用函数。
 *		neigh：		指向要更新的neighbour结构。
 *		lladdr：	新的链路层（L2）地址。Lladdr并不总是初始化为一个新值。例如，当调用neigh_update来删除一个neighbour结构时（设置其状态为NUD_FAILED，参见"删除邻居"一节），会给lladdr传入一个NULL值。
 *		new：		新的NUD状态。
 *		flags：		用于传达信息，例如，是否要覆盖一个已有的链路层地址等。
 */
int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new,
		 u32 flags)
{
	u8 old;
	int err;
#ifdef CONFIG_ARPD
	int notify = 0;
#endif
	struct net_device *dev;
	int update_isrouter = 0;

	write_lock_bh(&neigh->lock);

	dev    = neigh->dev;
	old    = neigh->nud_state;
	err    = -EPERM;

	/**
	 * 只有管理命令（NEIGH_UPDATE_F_ADMIN）可以改变当前是NUD_NOARP态或NUD_PERMANENT态的邻居的状态。
	 */
	if (!(flags & NEIGH_UPDATE_F_ADMIN) && 
	    (old & (NUD_NOARP | NUD_PERMANENT)))
		goto out;

	/**
	 * 当新状态new不是一个有效状态时，如果它是NUD_NONE态或NUD_INCOMPLETE态，就要停止启动了的邻居定时器。
	 */
	if (!(new & NUD_VALID)) {
		neigh_del_timer(neigh);
		/**
		 * 如果旧状态是NUD_CONNECTED态，则使用neigh_suspect函数将该邻居项标识为可疑的。
		 */
		if (old & NUD_CONNECTED)
			neigh_suspect(neigh);
		neigh->nud_state = new;
		err = 0;
#ifdef CONFIG_ARPD
		notify = old & NUD_VALID;
#endif
		goto out;
	}

	/* Compare new lladdr with cached one */
	if (!dev->addr_len) {
		/* First case: device needs no address. */
		lladdr = neigh->ha;
	} else if (lladdr) {
		/* The second case: if something is already cached
		   and a new address is proposed:
		   - compare new & old
		   - if they are different, check override flag
		 */
		if ((old & NUD_VALID) && 
		    !memcmp(lladdr, neigh->ha, dev->addr_len))
			lladdr = neigh->ha;
	} else {
		/* No address is supplied; if we know something,
		   use it, otherwise discard the request.
		 */
		err = -EINVAL;
		if (!(old & NUD_VALID))
			goto out;
		lladdr = neigh->ha;
	}

	if (new & NUD_CONNECTED)
		neigh->confirmed = jiffies;
	neigh->updated = jiffies;

	/* If entry was valid and address is not changed,
	   do not change entry state, if new one is STALE.
	 */
	err = 0;
	update_isrouter = flags & NEIGH_UPDATE_F_OVERRIDE_ISROUTER;
	if (old & NUD_VALID) {
		if (lladdr != neigh->ha && !(flags & NEIGH_UPDATE_F_OVERRIDE)) {
			update_isrouter = 0;
			if ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) &&
			    (old & NUD_CONNECTED)) {
				lladdr = neigh->ha;
				new = NUD_STALE;
			} else
				goto out;
		} else {
			if (lladdr == neigh->ha && new == NUD_STALE &&
			    ((flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) ||
			     (old & NUD_CONNECTED))
			    )
				new = old;
		}
	}

	if (new != old) {
		neigh_del_timer(neigh);
		/**
		 * 新状态是一个合法态，如果其要求定时器（NUD_IN_TIMER），则邻居定时器就会重新启动。
		 */
		if (new & NUD_IN_TIMER) {
			neigh_hold(neigh);
			neigh->timer.expires = jiffies + 
						((new & NUD_REACHABLE) ? 
						 neigh->parms->reachable_time : 0);
			add_timer(&neigh->timer);
		}
		neigh->nud_state = new;
	}

	/**
	 * 该函数的输入参数中提供了一个新的链路层地址（也就是说，lladdr非空）
	 */
	if (lladdr != neigh->ha) {
		/**
		 * 改变链路层地址
		 */
		memcpy(&neigh->ha, lladdr, dev->addr_len);
		/**
		 * 所有缓存的帧头都要同步更新
		 */
		neigh_update_hhs(neigh);
		if (!(new & NUD_CONNECTED))
			neigh->confirmed = jiffies -
				      (neigh->parms->base_reachable_time << 1);
#ifdef CONFIG_ARPD
		notify = 1;
#endif
	}
	if (new == old)
		goto out;
	if (new & NUD_CONNECTED)
		neigh_connect(neigh);
	else
		neigh_suspect(neigh);
	/**
	 * 旧状态不是NUD_VALID态并且新状态是NUD_VALID态时，主机必须将在邻居arp_queue队列中等待发送的包都发送出去。
	 */
	if (!(old & NUD_VALID)) {
		struct sk_buff *skb;

		/* Again: avoid dead loop if something went wrong */

		while (neigh->nud_state & NUD_VALID &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			struct neighbour *n1 = neigh;
			write_unlock_bh(&neigh->lock);
			/* On shaper/eql skb->dst->neighbour != neigh :( */
			if (skb->dst && skb->dst->neighbour)
				n1 = skb->dst->neighbour;
			n1->output(skb);
			write_lock_bh(&neigh->lock);
		}
		skb_queue_purge(&neigh->arp_queue);
	}
out:
	if (update_isrouter) {
		neigh->flags = (flags & NEIGH_UPDATE_F_ISROUTER) ?
			(neigh->flags | NTF_ROUTER) :
			(neigh->flags & ~NTF_ROUTER);
	}
	write_unlock_bh(&neigh->lock);
#ifdef CONFIG_ARPD
	/**
	 * 如果编译内核时选择了支持arpd，并且arpd经过适当配置（也就是app_probes>0）
	 */
	if (notify && neigh->parms->app_probes)
		/**
		 * 将下列事件通知arpd进程:
		 *		状态从NUD_VALID态修改为无效态。
 		 *		链路层地址发生变化。
		 */
		neigh_app_notify(neigh);
#endif
	return err;
}

struct neighbour *neigh_event_ns(struct neigh_table *tbl,
				 u8 *lladdr, void *saddr,
				 struct net_device *dev)
{
	struct neighbour *neigh = __neigh_lookup(tbl, saddr, dev,
						 lladdr || !dev->addr_len);
	if (neigh)
		neigh_update(neigh, lladdr, NUD_STALE, 
			     NEIGH_UPDATE_F_OVERRIDE);
	return neigh;
}

static void neigh_hh_init(struct neighbour *n, struct dst_entry *dst,
			  u16 protocol)
{
	struct hh_cache	*hh;
	struct net_device *dev = dst->dev;

	for (hh = n->hh; hh; hh = hh->hh_next)
		if (hh->hh_type == protocol)
			break;

	if (!hh && (hh = kmalloc(sizeof(*hh), GFP_ATOMIC)) != NULL) {
		memset(hh, 0, sizeof(struct hh_cache));
		rwlock_init(&hh->hh_lock);
		hh->hh_type = protocol;
		atomic_set(&hh->hh_refcnt, 0);
		hh->hh_next = NULL;
		if (dev->hard_header_cache(n, hh)) {
			kfree(hh);
			hh = NULL;
		} else {
			atomic_inc(&hh->hh_refcnt);
			hh->hh_next = n->hh;
			n->hh	    = hh;
			if (n->nud_state & NUD_CONNECTED)
				hh->hh_output = n->ops->hh_output;
			else
				hh->hh_output = n->ops->output;
		}
	}
	if (hh)	{
		atomic_inc(&hh->hh_refcnt);
		dst->hh = hh;
	}
}

/* This function can be used in contexts, where only old dev_queue_xmit
   worked, f.e. if you want to override normal output path (eql, shaper),
   but resolution is not made yet.
 */
/**
 * 该函数是为了保证向下兼容，在引入邻居基础结构以前，由它负责调用dev_queue_xmit函数，即使L2地址还没有准备好。
 */
int neigh_compat_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	__skb_pull(skb, skb->nh.raw - skb->data);

	if (dev->hard_header &&
	    dev->hard_header(skb, dev, ntohs(skb->protocol), NULL, NULL,
		    	     skb->len) < 0 &&
	    dev->rebuild_header(skb))
		return 0;

	return dev_queue_xmit(skb);
}

/* Slow and careful. */
/**
 * 该函数在数据传输前将L3地址解析为L2地址。因此，当L3地址和L2地址的对应关系还没有被建立或者需要对其确认时，就会用到该函数。
 */
int neigh_resolve_output(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct neighbour *neigh;
	int rc = 0;

	if (!dst || !(neigh = dst->neighbour))
		goto discard;

	__skb_pull(skb, skb->nh.raw - skb->data);

	if (!neigh_event_send(neigh, skb)) {
		int err;
		struct net_device *dev = neigh->dev;
		/**
		 * 设备可以使用帧头缓存（也就是说，设置了hard_header_cache），但是帧头还没有准备好（!dst->hh）
		 */
		if (dev->hard_header_cache && !dst->hh) {
			write_lock_bh(&neigh->lock);
			if (!dst->hh)
				/**
				 * 创建hh_cache缓存项，并将其链接到dst->hh路由表缓存项上。
				 */
				neigh_hh_init(neigh, dst, dst->ops->protocol);
			/**
			 * 初始化并缓存L2帧头。
			 */
			err = dev->hard_header(skb, dev, ntohs(skb->protocol),
					       neigh->ha, NULL, skb->len);
			write_unlock_bh(&neigh->lock);
		} else {/* 设备不支持帧头缓存 */
			read_lock_bh(&neigh->lock);
			/**
			 * 使用hard_header来填充L2帧头。
			 */
			err = dev->hard_header(skb, dev, ntohs(skb->protocol),
					       neigh->ha, NULL, skb->len);
			read_unlock_bh(&neigh->lock);
		}
		if (err >= 0)
			rc = neigh->ops->queue_xmit(skb);
		else
			goto out_kfree_skb;
	}
out:
	return rc;
discard:
	NEIGH_PRINTK1("neigh_resolve_output: dst=%p neigh=%p\n",
		      dst, dst ? dst->neighbour : NULL);
out_kfree_skb:
	rc = -EINVAL;
	kfree_skb(skb);
	goto out;
}

/* As fast as possible without hh cache */
/**
 * 该函数只是填充L2帧头，然后调用neigh_ops->queue_xmit。因此，它希望L2地址被解析。
 * Neighbour结构在NUD_COONECTED状态会用到这个函数。
 */
int neigh_connected_output(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb->dst;
	struct neighbour *neigh = dst->neighbour;
	struct net_device *dev = neigh->dev;

	__skb_pull(skb, skb->nh.raw - skb->data);

	read_lock_bh(&neigh->lock);
	err = dev->hard_header(skb, dev, ntohs(skb->protocol),
			       neigh->ha, NULL, skb->len);
	read_unlock_bh(&neigh->lock);
	if (err >= 0)
		err = neigh->ops->queue_xmit(skb);
	else {
		err = -EINVAL;
		kfree_skb(skb);
	}
	return err;
}

/**
 * 代理延迟定时器处理函数。
 */
static void neigh_proxy_process(unsigned long arg)
{
	struct neigh_table *tbl = (struct neigh_table *)arg;
	long sched_next = 0;
	unsigned long now = jiffies;
	struct sk_buff *skb;

	spin_lock(&tbl->proxy_queue.lock);

	skb = tbl->proxy_queue.next;

	while (skb != (struct sk_buff *)&tbl->proxy_queue) {
		struct sk_buff *back = skb;
		long tdif = back->stamp.tv_usec - now;

		skb = skb->next;
		if (tdif <= 0) {
			struct net_device *dev = back->dev;
			__skb_unlink(back, &tbl->proxy_queue);
			if (tbl->proxy_redo && netif_running(dev))
				tbl->proxy_redo(back);
			else
				kfree_skb(back);

			dev_put(dev);
		} else if (!sched_next || tdif < sched_next)
			sched_next = tdif;
	}
	del_timer(&tbl->proxy_timer);
	if (sched_next)
		mod_timer(&tbl->proxy_timer, jiffies + sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}

void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb)
{
	unsigned long now = jiffies;
	unsigned long sched_next = now + (net_random() % p->proxy_delay);

	if (tbl->proxy_queue.qlen > p->proxy_qlen) {
		kfree_skb(skb);
		return;
	}
	skb->stamp.tv_sec  = LOCALLY_ENQUEUED;
	skb->stamp.tv_usec = sched_next;

	spin_lock(&tbl->proxy_queue.lock);
	if (del_timer(&tbl->proxy_timer)) {
		if (time_before(tbl->proxy_timer.expires, sched_next))
			sched_next = tbl->proxy_timer.expires;
	}
	dst_release(skb->dst);
	skb->dst = NULL;
	dev_hold(skb->dev);
	__skb_queue_tail(&tbl->proxy_queue, skb);
	mod_timer(&tbl->proxy_timer, sched_next);
	spin_unlock(&tbl->proxy_queue.lock);
}


struct neigh_parms *neigh_parms_alloc(struct net_device *dev,
				      struct neigh_table *tbl)
{
	struct neigh_parms *p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (p) {
		memcpy(p, &tbl->parms, sizeof(*p));
		p->tbl		  = tbl;
		atomic_set(&p->refcnt, 1);
		INIT_RCU_HEAD(&p->rcu_head);
		p->reachable_time =
				neigh_rand_reach_time(p->base_reachable_time);
		if (dev && dev->neigh_setup && dev->neigh_setup(dev, p)) {
			kfree(p);
			return NULL;
		}
		p->sysctl_table = NULL;
		write_lock_bh(&tbl->lock);
		p->next		= tbl->parms.next;
		tbl->parms.next = p;
		write_unlock_bh(&tbl->lock);
	}
	return p;
}

static void neigh_rcu_free_parms(struct rcu_head *head)
{
	struct neigh_parms *parms =
		container_of(head, struct neigh_parms, rcu_head);

	neigh_parms_put(parms);
}

void neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms)
{
	struct neigh_parms **p;

	if (!parms || parms == &tbl->parms)
		return;
	write_lock_bh(&tbl->lock);
	for (p = &tbl->parms.next; *p; p = &(*p)->next) {
		if (*p == parms) {
			*p = parms->next;
			parms->dead = 1;
			write_unlock_bh(&tbl->lock);
			call_rcu(&parms->rcu_head, neigh_rcu_free_parms);
			return;
		}
	}
	write_unlock_bh(&tbl->lock);
	NEIGH_PRINTK1("neigh_parms_release: not found\n");
}

void neigh_parms_destroy(struct neigh_parms *parms)
{
	kfree(parms);
}


void neigh_table_init(struct neigh_table *tbl)
{
	unsigned long now = jiffies;
	unsigned long phsize;

	/**
	 * 初始化一些参数
	 */
	atomic_set(&tbl->parms.refcnt, 1);
	INIT_RCU_HEAD(&tbl->parms.rcu_head);
	tbl->parms.reachable_time =
			  neigh_rand_reach_time(tbl->parms.base_reachable_time);

	if (!tbl->kmem_cachep)
		/**
		 * 为neighbour结构分配预备的内存池。
		 */
		tbl->kmem_cachep = kmem_cache_create(tbl->id,
						     tbl->entry_size,
						     0, SLAB_HWCACHE_ALIGN,
						     NULL, NULL);

	if (!tbl->kmem_cachep)
		panic("cannot create neighbour cache");

	/**
	 * 分配一个neigh_statistics结构来收集协议的统计信息。
	 */
	tbl->stats = alloc_percpu(struct neigh_statistics);
	if (!tbl->stats)
		panic("cannot create neighbour cache statistics");
	
#ifdef CONFIG_PROC_FS
	/**
	 * 在/proc/net中建立一个文件，用于转储缓存的内容。文件名来自于neigh_table->id。
	 */
	tbl->pde = create_proc_entry(tbl->id, 0, proc_net_stat);
	if (!tbl->pde) 
		panic("cannot create neighbour proc dir entry");
	tbl->pde->proc_fops = &neigh_stat_seq_fops;
	tbl->pde->data = tbl;
#endif

	tbl->hash_mask = 1;
	/**
	 * 分配两个hash表：hash_buckets和phash_buckets。
	 * 这两个表分别作为解析过的地址关联缓存和代理的地址数据库。
	 */
	tbl->hash_buckets = neigh_hash_alloc(tbl->hash_mask + 1);

	phsize = (PNEIGH_HASHMASK + 1) * sizeof(struct pneigh_entry *);
	tbl->phash_buckets = kmalloc(phsize, GFP_KERNEL);

	if (!tbl->hash_buckets || !tbl->phash_buckets)
		panic("cannot allocate neighbour cache hashes");

	memset(tbl->phash_buckets, 0, phsize);

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));

	rwlock_init(&tbl->lock);
	/**
	 * 启动gc_timer垃圾回收定时器
	 */
	init_timer(&tbl->gc_timer);
	tbl->gc_timer.data     = (unsigned long)tbl;
	tbl->gc_timer.function = neigh_periodic_timer;
	tbl->gc_timer.expires  = now + 1;
	add_timer(&tbl->gc_timer);

	/**
	 * 初始化（但是不启动）proxy_timer代理定时器和相关的proxy_queue队列。
	 */
	init_timer(&tbl->proxy_timer);
	tbl->proxy_timer.data	  = (unsigned long)tbl;
	tbl->proxy_timer.function = neigh_proxy_process;
	skb_queue_head_init(&tbl->proxy_queue);

	tbl->last_flush = now;
	tbl->last_rand	= now + tbl->parms.reachable_time * 20;
	/**
	 * 添加neigh_table结构到neigh_tables全局列表中。
	 */
	write_lock(&neigh_tbl_lock);
	tbl->next	= neigh_tables;
	neigh_tables	= tbl;
	write_unlock(&neigh_tbl_lock);
}

/**
 * 撤销neigh_table_init在初始化时做的工作。并且会清理在协议生存期内分配给该协议的任何资源，如定时器和队列。
 */
int neigh_table_clear(struct neigh_table *tbl)
{
	struct neigh_table **tp;

	/* It is not clean... Fix it to unload IPv6 module safely */
	del_timer_sync(&tbl->gc_timer);
	del_timer_sync(&tbl->proxy_timer);
	pneigh_queue_purge(&tbl->proxy_queue);
	neigh_ifdown(tbl, NULL);
	if (atomic_read(&tbl->entries))
		printk(KERN_CRIT "neighbour leakage\n");
	write_lock(&neigh_tbl_lock);
	for (tp = &neigh_tables; *tp; tp = &(*tp)->next) {
		if (*tp == tbl) {
			*tp = tbl->next;
			break;
		}
	}
	write_unlock(&neigh_tbl_lock);

	neigh_hash_free(tbl->hash_buckets, tbl->hash_mask + 1);
	tbl->hash_buckets = NULL;

	kfree(tbl->phash_buckets);
	tbl->phash_buckets = NULL;

	return 0;
}

int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ndmsg *ndm = NLMSG_DATA(nlh);
	struct rtattr **nda = arg;
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err = -ENODEV;

	if (ndm->ndm_ifindex &&
	    (dev = dev_get_by_index(ndm->ndm_ifindex)) == NULL)
		goto out;

	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		struct neighbour *n;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		err = -EINVAL;
		if (!nda[NDA_DST - 1] ||
		    nda[NDA_DST - 1]->rta_len != RTA_LENGTH(tbl->key_len))
			goto out_dev_put;

		if (ndm->ndm_flags & NTF_PROXY) {
			err = pneigh_delete(tbl,
					    RTA_DATA(nda[NDA_DST - 1]), dev);
			goto out_dev_put;
		}

		if (!dev)
			goto out;

		n = neigh_lookup(tbl, RTA_DATA(nda[NDA_DST - 1]), dev);
		if (n) {
			err = neigh_update(n, NULL, NUD_FAILED, 
					   NEIGH_UPDATE_F_OVERRIDE|
					   NEIGH_UPDATE_F_ADMIN);
			neigh_release(n);
		}
		goto out_dev_put;
	}
	read_unlock(&neigh_tbl_lock);
	err = -EADDRNOTAVAIL;
out_dev_put:
	if (dev)
		dev_put(dev);
out:
	return err;
}

int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ndmsg *ndm = NLMSG_DATA(nlh);
	struct rtattr **nda = arg;
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err = -ENODEV;

	if (ndm->ndm_ifindex &&
	    (dev = dev_get_by_index(ndm->ndm_ifindex)) == NULL)
		goto out;

	read_lock(&neigh_tbl_lock);
	for (tbl = neigh_tables; tbl; tbl = tbl->next) {
		int override = 1;
		struct neighbour *n;

		if (tbl->family != ndm->ndm_family)
			continue;
		read_unlock(&neigh_tbl_lock);

		err = -EINVAL;
		if (!nda[NDA_DST - 1] ||
		    nda[NDA_DST - 1]->rta_len != RTA_LENGTH(tbl->key_len))
			goto out_dev_put;
		if (ndm->ndm_flags & NTF_PROXY) {
			err = -ENOBUFS;
			if (pneigh_lookup(tbl,
					  RTA_DATA(nda[NDA_DST - 1]), dev, 1))
				err = 0;
			goto out_dev_put;
		}
		err = -EINVAL;
		if (!dev)
			goto out;
		if (nda[NDA_LLADDR - 1] &&
		    nda[NDA_LLADDR - 1]->rta_len != RTA_LENGTH(dev->addr_len))
			goto out_dev_put;
		err = 0;
		n = neigh_lookup(tbl, RTA_DATA(nda[NDA_DST - 1]), dev);
		if (n) {
			if (nlh->nlmsg_flags & NLM_F_EXCL)
				err = -EEXIST;
			override = nlh->nlmsg_flags & NLM_F_REPLACE;
		} else if (!(nlh->nlmsg_flags & NLM_F_CREATE))
			err = -ENOENT;
		else {
			n = __neigh_lookup_errno(tbl, RTA_DATA(nda[NDA_DST - 1]),
						 dev);
			if (IS_ERR(n)) {
				err = PTR_ERR(n);
				n = NULL;
			}
		}
		if (!err) {
			err = neigh_update(n, nda[NDA_LLADDR - 1] ?
						RTA_DATA(nda[NDA_LLADDR - 1]) :
						NULL,
					   ndm->ndm_state,
					   (override ? NEIGH_UPDATE_F_OVERRIDE : 0) |
					   NEIGH_UPDATE_F_ADMIN);
		}
		if (n)
			neigh_release(n);
		goto out_dev_put;
	}

	read_unlock(&neigh_tbl_lock);
	err = -EADDRNOTAVAIL;
out_dev_put:
	if (dev)
		dev_put(dev);
out:
	return err;
}


static int neigh_fill_info(struct sk_buff *skb, struct neighbour *n,
			   u32 pid, u32 seq, int event)
{
	unsigned long now = jiffies;
	unsigned char *b = skb->tail;
	struct nda_cacheinfo ci;
	int locked = 0;
	struct nlmsghdr *nlh = NLMSG_PUT(skb, pid, seq, event,
					 sizeof(struct ndmsg));
	struct ndmsg *ndm = NLMSG_DATA(nlh);

	nlh->nlmsg_flags = pid ? NLM_F_MULTI : 0;
	ndm->ndm_family	 = n->ops->family;
	ndm->ndm_flags	 = n->flags;
	ndm->ndm_type	 = n->type;
	ndm->ndm_ifindex = n->dev->ifindex;
	RTA_PUT(skb, NDA_DST, n->tbl->key_len, n->primary_key);
	read_lock_bh(&n->lock);
	locked		 = 1;
	ndm->ndm_state	 = n->nud_state;
	if (n->nud_state & NUD_VALID)
		RTA_PUT(skb, NDA_LLADDR, n->dev->addr_len, n->ha);
	ci.ndm_used	 = now - n->used;
	ci.ndm_confirmed = now - n->confirmed;
	ci.ndm_updated	 = now - n->updated;
	ci.ndm_refcnt	 = atomic_read(&n->refcnt) - 1;
	read_unlock_bh(&n->lock);
	locked		 = 0;
	RTA_PUT(skb, NDA_CACHEINFO, sizeof(ci), &ci);
	nlh->nlmsg_len	 = skb->tail - b;
	return skb->len;

nlmsg_failure:
rtattr_failure:
	if (locked)
		read_unlock_bh(&n->lock);
	skb_trim(skb, b - skb->data);
	return -1;
}


static int neigh_dump_table(struct neigh_table *tbl, struct sk_buff *skb,
			    struct netlink_callback *cb)
{
	struct neighbour *n;
	int rc, h, s_h = cb->args[1];
	int idx, s_idx = idx = cb->args[2];

	for (h = 0; h <= tbl->hash_mask; h++) {
		if (h < s_h)
			continue;
		if (h > s_h)
			s_idx = 0;
		read_lock_bh(&tbl->lock);
		for (n = tbl->hash_buckets[h], idx = 0; n; n = n->next, idx++) {
			if (idx < s_idx)
				continue;
			if (neigh_fill_info(skb, n, NETLINK_CB(cb->skb).pid,
					    cb->nlh->nlmsg_seq,
					    RTM_NEWNEIGH) <= 0) {
				read_unlock_bh(&tbl->lock);
				rc = -1;
				goto out;
			}
		}
		read_unlock_bh(&tbl->lock);
	}
	rc = skb->len;
out:
	cb->args[1] = h;
	cb->args[2] = idx;
	return rc;
}

int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct neigh_table *tbl;
	int t, family, s_t;

	read_lock(&neigh_tbl_lock);
	family = ((struct rtgenmsg *)NLMSG_DATA(cb->nlh))->rtgen_family;
	s_t = cb->args[0];

	for (tbl = neigh_tables, t = 0; tbl; tbl = tbl->next, t++) {
		if (t < s_t || (family && tbl->family != family))
			continue;
		if (t > s_t)
			memset(&cb->args[1], 0, sizeof(cb->args) -
						sizeof(cb->args[0]));
		if (neigh_dump_table(tbl, skb, cb) < 0)
			break;
	}
	read_unlock(&neigh_tbl_lock);

	cb->args[0] = t;
	return skb->len;
}

void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie)
{
	int chain;

	read_lock_bh(&tbl->lock);
	for (chain = 0; chain <= tbl->hash_mask; chain++) {
		struct neighbour *n;

		for (n = tbl->hash_buckets[chain]; n; n = n->next)
			cb(n, cookie);
	}
	read_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_for_each);

/* The tbl->lock must be held as a writer and BH disabled. */
void __neigh_for_each_release(struct neigh_table *tbl,
			      int (*cb)(struct neighbour *))
{
	int chain;

	for (chain = 0; chain <= tbl->hash_mask; chain++) {
		struct neighbour *n, **np;

		np = &tbl->hash_buckets[chain];
		while ((n = *np) != NULL) {
			int release;

			write_lock(&n->lock);
			release = cb(n);
			if (release) {
				*np = n->next;
				n->dead = 1;
			} else
				np = &n->next;
			write_unlock(&n->lock);
			if (release)
				neigh_release(n);
		}
	}
}
EXPORT_SYMBOL(__neigh_for_each_release);

#ifdef CONFIG_PROC_FS

static struct neighbour *neigh_get_first(struct seq_file *seq)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;
	struct neighbour *n = NULL;
	int bucket = state->bucket;

	state->flags &= ~NEIGH_SEQ_IS_PNEIGH;
	for (bucket = 0; bucket <= tbl->hash_mask; bucket++) {
		n = tbl->hash_buckets[bucket];

		while (n) {
			if (state->neigh_sub_iter) {
				loff_t fakep = 0;
				void *v;

				v = state->neigh_sub_iter(state, n, &fakep);
				if (!v)
					goto next;
			}
			if (!(state->flags & NEIGH_SEQ_SKIP_NOARP))
				break;
			if (n->nud_state & ~NUD_NOARP)
				break;
		next:
			n = n->next;
		}

		if (n)
			break;
	}
	state->bucket = bucket;

	return n;
}

static struct neighbour *neigh_get_next(struct seq_file *seq,
					struct neighbour *n,
					loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	if (state->neigh_sub_iter) {
		void *v = state->neigh_sub_iter(state, n, pos);
		if (v)
			return n;
	}
	n = n->next;

	while (1) {
		while (n) {
			if (state->neigh_sub_iter) {
				void *v = state->neigh_sub_iter(state, n, pos);
				if (v)
					return n;
				goto next;
			}
			if (!(state->flags & NEIGH_SEQ_SKIP_NOARP))
				break;

			if (n->nud_state & ~NUD_NOARP)
				break;
		next:
			n = n->next;
		}

		if (n)
			break;

		if (++state->bucket > tbl->hash_mask)
			break;

		n = tbl->hash_buckets[state->bucket];
	}

	if (n && pos)
		--(*pos);
	return n;
}

static struct neighbour *neigh_get_idx(struct seq_file *seq, loff_t *pos)
{
	struct neighbour *n = neigh_get_first(seq);

	if (n) {
		while (*pos) {
			n = neigh_get_next(seq, n, pos);
			if (!n)
				break;
		}
	}
	return *pos ? NULL : n;
}

static struct pneigh_entry *pneigh_get_first(struct seq_file *seq)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;
	struct pneigh_entry *pn = NULL;
	int bucket = state->bucket;

	state->flags |= NEIGH_SEQ_IS_PNEIGH;
	for (bucket = 0; bucket <= PNEIGH_HASHMASK; bucket++) {
		pn = tbl->phash_buckets[bucket];
		if (pn)
			break;
	}
	state->bucket = bucket;

	return pn;
}

static struct pneigh_entry *pneigh_get_next(struct seq_file *seq,
					    struct pneigh_entry *pn,
					    loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	pn = pn->next;
	while (!pn) {
		if (++state->bucket > PNEIGH_HASHMASK)
			break;
		pn = tbl->phash_buckets[state->bucket];
		if (pn)
			break;
	}

	if (pn && pos)
		--(*pos);

	return pn;
}

static struct pneigh_entry *pneigh_get_idx(struct seq_file *seq, loff_t *pos)
{
	struct pneigh_entry *pn = pneigh_get_first(seq);

	if (pn) {
		while (*pos) {
			pn = pneigh_get_next(seq, pn, pos);
			if (!pn)
				break;
		}
	}
	return *pos ? NULL : pn;
}

static void *neigh_get_idx_any(struct seq_file *seq, loff_t *pos)
{
	struct neigh_seq_state *state = seq->private;
	void *rc;

	rc = neigh_get_idx(seq, pos);
	if (!rc && !(state->flags & NEIGH_SEQ_NEIGH_ONLY))
		rc = pneigh_get_idx(seq, pos);

	return rc;
}

void *neigh_seq_start(struct seq_file *seq, loff_t *pos, struct neigh_table *tbl, unsigned int neigh_seq_flags)
{
	struct neigh_seq_state *state = seq->private;
	loff_t pos_minus_one;

	state->tbl = tbl;
	state->bucket = 0;
	state->flags = (neigh_seq_flags & ~NEIGH_SEQ_IS_PNEIGH);

	read_lock_bh(&tbl->lock);

	pos_minus_one = *pos - 1;
	return *pos ? neigh_get_idx_any(seq, &pos_minus_one) : SEQ_START_TOKEN;
}
EXPORT_SYMBOL(neigh_seq_start);

void *neigh_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct neigh_seq_state *state;
	void *rc;

	if (v == SEQ_START_TOKEN) {
		rc = neigh_get_idx(seq, pos);
		goto out;
	}

	state = seq->private;
	if (!(state->flags & NEIGH_SEQ_IS_PNEIGH)) {
		rc = neigh_get_next(seq, v, NULL);
		if (rc)
			goto out;
		if (!(state->flags & NEIGH_SEQ_NEIGH_ONLY))
			rc = pneigh_get_first(seq);
	} else {
		BUG_ON(state->flags & NEIGH_SEQ_NEIGH_ONLY);
		rc = pneigh_get_next(seq, v, NULL);
	}
out:
	++(*pos);
	return rc;
}
EXPORT_SYMBOL(neigh_seq_next);

void neigh_seq_stop(struct seq_file *seq, void *v)
{
	struct neigh_seq_state *state = seq->private;
	struct neigh_table *tbl = state->tbl;

	read_unlock_bh(&tbl->lock);
}
EXPORT_SYMBOL(neigh_seq_stop);

/* statistics via seq_file */

static void *neigh_stat_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;
	
	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(tbl->stats, cpu);
	}
	return NULL;
}

static void *neigh_stat_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(tbl->stats, cpu);
	}
	return NULL;
}

static void neigh_stat_seq_stop(struct seq_file *seq, void *v)
{

}

static int neigh_stat_seq_show(struct seq_file *seq, void *v)
{
	struct proc_dir_entry *pde = seq->private;
	struct neigh_table *tbl = pde->data;
	struct neigh_statistics *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs forced_gc_goal_miss\n");
		return 0;
	}

	seq_printf(seq, "%08x  %08lx %08lx %08lx  %08lx %08lx  %08lx  "
			"%08lx %08lx  %08lx %08lx\n",
		   atomic_read(&tbl->entries),

		   st->allocs,
		   st->destroys,
		   st->hash_grows,

		   st->lookups,
		   st->hits,

		   st->res_failed,

		   st->rcv_probes_mcast,
		   st->rcv_probes_ucast,

		   st->periodic_gc_runs,
		   st->forced_gc_runs
		   );

	return 0;
}

static struct seq_operations neigh_stat_seq_ops = {
	.start	= neigh_stat_seq_start,
	.next	= neigh_stat_seq_next,
	.stop	= neigh_stat_seq_stop,
	.show	= neigh_stat_seq_show,
};

static int neigh_stat_seq_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &neigh_stat_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE(inode);
	}
	return ret;
};

static struct file_operations neigh_stat_seq_fops = {
	.owner	 = THIS_MODULE,
	.open 	 = neigh_stat_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_ARPD
/**
 * 向用户态程序发送通知，处理solicitations。
 * 生成的消息类型是RTM_GETNETGH。
 * 由solicit(arp_solicit)调用。
 */
void neigh_app_ns(struct neighbour *n)
{
	struct nlmsghdr  *nlh;
	int size = NLMSG_SPACE(sizeof(struct ndmsg) + 256);
	struct sk_buff *skb = alloc_skb(size, GFP_ATOMIC);

	if (!skb)
		return;

	if (neigh_fill_info(skb, n, 0, 0, RTM_GETNEIGH) < 0) {
		kfree_skb(skb);
		return;
	}
	nlh			   = (struct nlmsghdr *)skb->data;
	nlh->nlmsg_flags	   = NLM_F_REQUEST;
	NETLINK_CB(skb).dst_groups = RTMGRP_NEIGH;
	netlink_broadcast(rtnl, skb, 0, RTMGRP_NEIGH, GFP_ATOMIC);
}
/**
 * 向应用程序发送通知。
 *		一个neighbour已被移到NUD_FAILED态，不久之后就会被垃圾回收器删除。这种情况下，这个状态的变化和对neigh_app_notify的调用是由neigh_periodic_timer处理。
 *		一个邻居的状态从一个有效态变为一个无效态，或者邻居的L2地址发生变化时，由neigh_update函数来处理状态的变化和调用neigh_app_notify。
 * neigh_app_notify函数生成的消息类型是RTM_NEWNEIGH。
 */
static void neigh_app_notify(struct neighbour *n)
{
	struct nlmsghdr *nlh;
	int size = NLMSG_SPACE(sizeof(struct ndmsg) + 256);
	struct sk_buff *skb = alloc_skb(size, GFP_ATOMIC);

	if (!skb)
		return;

	if (neigh_fill_info(skb, n, 0, 0, RTM_NEWNEIGH) < 0) {
		kfree_skb(skb);
		return;
	}
	nlh			   = (struct nlmsghdr *)skb->data;
	NETLINK_CB(skb).dst_groups = RTMGRP_NEIGH;
	netlink_broadcast(rtnl, skb, 0, RTMGRP_NEIGH, GFP_ATOMIC);
}

#endif /* CONFIG_ARPD */

#ifdef CONFIG_SYSCTL

static struct neigh_sysctl_table {
	struct ctl_table_header *sysctl_header;
	ctl_table		neigh_vars[17];
	ctl_table		neigh_dev[2];
	ctl_table		neigh_neigh_dir[2];
	ctl_table		neigh_proto_dir[2];
	ctl_table		neigh_root_dir[2];
} neigh_sysctl_template = {
	.neigh_vars = {
		{
			.ctl_name	= NET_NEIGH_MCAST_SOLICIT,
			.procname	= "mcast_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_UCAST_SOLICIT,
			.procname	= "ucast_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_APP_SOLICIT,
			.procname	= "app_solicit",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_RETRANS_TIME,
			.procname	= "retrans_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_REACHABLE_TIME,
			.procname	= "base_reachable_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_DELAY_PROBE_TIME,
			.procname	= "delay_first_probe_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_STALE_TIME,
			.procname	= "gc_stale_time",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_UNRES_QLEN,
			.procname	= "unres_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_PROXY_QLEN,
			.procname	= "proxy_qlen",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_ANYCAST_DELAY,
			.procname	= "anycast_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_PROXY_DELAY,
			.procname	= "proxy_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_LOCKTIME,
			.procname	= "locktime",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_userhz_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_INTERVAL,
			.procname	= "gc_interval",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec_jiffies,
			.strategy	= &sysctl_jiffies,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH1,
			.procname	= "gc_thresh1",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH2,
			.procname	= "gc_thresh2",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
			.ctl_name	= NET_NEIGH_GC_THRESH3,
			.procname	= "gc_thresh3",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
	},
	.neigh_dev = {
		{
			.ctl_name	= NET_PROTO_CONF_DEFAULT,
			.procname	= "default",
			.mode		= 0555,
		},
	},
	.neigh_neigh_dir = {
		{
			.procname	= "neigh",
			.mode		= 0555,
		},
	},
	.neigh_proto_dir = {
		{
			.mode		= 0555,
		},
	},
	.neigh_root_dir = {
		{
			.ctl_name	= CTL_NET,
			.procname	= "net",
			.mode		= 0555,
		},
	},
};

int neigh_sysctl_register(struct net_device *dev, struct neigh_parms *p,
			  int p_id, int pdev_id, char *p_name, 
			  proc_handler *handler)
{
	struct neigh_sysctl_table *t = kmalloc(sizeof(*t), GFP_KERNEL);
	const char *dev_name_source = NULL;
	char *dev_name = NULL;
	int err = 0;

	if (!t)
		return -ENOBUFS;
	memcpy(t, &neigh_sysctl_template, sizeof(*t));
	t->neigh_vars[0].data  = &p->mcast_probes;
	t->neigh_vars[1].data  = &p->ucast_probes;
	t->neigh_vars[2].data  = &p->app_probes;
	t->neigh_vars[3].data  = &p->retrans_time;
	if (handler) {
		t->neigh_vars[3].proc_handler = handler;
		t->neigh_vars[3].extra1 = dev;
	}
	t->neigh_vars[4].data  = &p->base_reachable_time;
	t->neigh_vars[5].data  = &p->delay_probe_time;
	t->neigh_vars[6].data  = &p->gc_staletime;
	t->neigh_vars[7].data  = &p->queue_len;
	t->neigh_vars[8].data  = &p->proxy_qlen;
	t->neigh_vars[9].data  = &p->anycast_delay;
	t->neigh_vars[10].data = &p->proxy_delay;
	t->neigh_vars[11].data = &p->locktime;

 	dev_name_source = t->neigh_dev[0].procname;
	if (dev) {
		dev_name_source = dev->name;
		t->neigh_dev[0].ctl_name = dev->ifindex;
		memset(&t->neigh_vars[12], 0, sizeof(ctl_table));
	} else {
		t->neigh_vars[12].data = (int *)(p + 1);
		t->neigh_vars[13].data = (int *)(p + 1) + 1;
		t->neigh_vars[14].data = (int *)(p + 1) + 2;
		t->neigh_vars[15].data = (int *)(p + 1) + 3;
	}

	dev_name = net_sysctl_strdup(dev_name_source);
	if (!dev_name) {
		err = -ENOBUFS;
		goto free;
	}

 	t->neigh_dev[0].procname = dev_name;

	t->neigh_neigh_dir[0].ctl_name = pdev_id;

	t->neigh_proto_dir[0].procname = p_name;
	t->neigh_proto_dir[0].ctl_name = p_id;

	t->neigh_dev[0].child	       = t->neigh_vars;
	t->neigh_neigh_dir[0].child    = t->neigh_dev;
	t->neigh_proto_dir[0].child    = t->neigh_neigh_dir;
	t->neigh_root_dir[0].child     = t->neigh_proto_dir;

	t->sysctl_header = register_sysctl_table(t->neigh_root_dir, 0);
	if (!t->sysctl_header) {
		err = -ENOBUFS;
		goto free_procname;
	}
	p->sysctl_table = t;
	return 0;

	/* error path */
 free_procname:
	kfree(dev_name);
 free:
	kfree(t);

	return err;
}

void neigh_sysctl_unregister(struct neigh_parms *p)
{
	if (p->sysctl_table) {
		struct neigh_sysctl_table *t = p->sysctl_table;
		p->sysctl_table = NULL;
		unregister_sysctl_table(t->sysctl_header);
		kfree(t->neigh_dev[0].procname);
		kfree(t);
	}
}

#endif	/* CONFIG_SYSCTL */

EXPORT_SYMBOL(__neigh_event_send);
EXPORT_SYMBOL(neigh_add);
EXPORT_SYMBOL(neigh_changeaddr);
EXPORT_SYMBOL(neigh_compat_output);
EXPORT_SYMBOL(neigh_connected_output);
EXPORT_SYMBOL(neigh_create);
EXPORT_SYMBOL(neigh_delete);
EXPORT_SYMBOL(neigh_destroy);
EXPORT_SYMBOL(neigh_dump_info);
EXPORT_SYMBOL(neigh_event_ns);
EXPORT_SYMBOL(neigh_ifdown);
EXPORT_SYMBOL(neigh_lookup);
EXPORT_SYMBOL(neigh_lookup_nodev);
EXPORT_SYMBOL(neigh_parms_alloc);
EXPORT_SYMBOL(neigh_parms_release);
EXPORT_SYMBOL(neigh_rand_reach_time);
EXPORT_SYMBOL(neigh_resolve_output);
EXPORT_SYMBOL(neigh_table_clear);
EXPORT_SYMBOL(neigh_table_init);
EXPORT_SYMBOL(neigh_update);
EXPORT_SYMBOL(neigh_update_hhs);
EXPORT_SYMBOL(pneigh_enqueue);
EXPORT_SYMBOL(pneigh_lookup);

#ifdef CONFIG_ARPD
EXPORT_SYMBOL(neigh_app_ns);
#endif
#ifdef CONFIG_SYSCTL
EXPORT_SYMBOL(neigh_sysctl_register);
EXPORT_SYMBOL(neigh_sysctl_unregister);
#endif
