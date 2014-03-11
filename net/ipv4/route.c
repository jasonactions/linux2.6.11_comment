/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		ROUTE - implementation of the IP router.
 *
 * Version:	$Id: route.c,v 1.103 2002/01/12 07:44:09 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Linus Torvalds, <Linus.Torvalds@helsinki.fi>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *		Alan Cox	:	Verify area fixes.
 *		Alan Cox	:	cli() protects routing changes
 *		Rui Oliveira	:	ICMP routing table updates
 *		(rco@di.uminho.pt)	Routing table insertion and update
 *		Linus Torvalds	:	Rewrote bits to be sensible
 *		Alan Cox	:	Added BSD route gw semantics
 *		Alan Cox	:	Super /proc >4K 
 *		Alan Cox	:	MTU in route table
 *		Alan Cox	: 	MSS actually. Also added the window
 *					clamper.
 *		Sam Lantinga	:	Fixed route matching in rt_del()
 *		Alan Cox	:	Routing cache support.
 *		Alan Cox	:	Removed compatibility cruft.
 *		Alan Cox	:	RTF_REJECT support.
 *		Alan Cox	:	TCP irtt support.
 *		Jonathan Naylor	:	Added Metric support.
 *	Miquel van Smoorenburg	:	BSD API fixes.
 *	Miquel van Smoorenburg	:	Metrics.
 *		Alan Cox	:	Use __u32 properly
 *		Alan Cox	:	Aligned routing errors more closely with BSD
 *					our system is still very different.
 *		Alan Cox	:	Faster /proc handling
 *	Alexey Kuznetsov	:	Massive rework to support tree based routing,
 *					routing caches and better behaviour.
 *		
 *		Olaf Erb	:	irtt wasn't being copied right.
 *		Bjorn Ekwall	:	Kerneld route support.
 *		Alan Cox	:	Multicast fixed (I hope)
 * 		Pavel Krauz	:	Limited broadcast fixed
 *		Mike McLagan	:	Routing by source
 *	Alexey Kuznetsov	:	End of old history. Split to fib.c and
 *					route.c and rewritten from scratch.
 *		Andi Kleen	:	Load-limit warning messages.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *	Vitaly E. Lavrov	:	Race condition in ip_route_input_slow.
 *	Tobias Ringstrom	:	Uninitialized res.type in ip_route_output_slow.
 *	Vladimir V. Ivanov	:	IP rule info (flowid) is really useful.
 *		Marc Boucher	:	routing by fwmark
 *	Robert Olsson		:	Added rt_cache statistics
 *	Arnaldo C. Melo		:	Convert proc stuff to seq_file
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
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
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/times.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#define IP_MAX_MTU	0xFFF0

#define RT_GC_TIMEOUT (300*HZ)

static int ip_rt_min_delay		= 2 * HZ;
/**
 * 一旦递交了一个flush请求，在ip_rt_max_delay秒之内肯定进行一次flush，这个参数缺省值为10秒。
 */
static int ip_rt_max_delay		= 10 * HZ;
static int ip_rt_max_size;
static int ip_rt_gc_timeout		= RT_GC_TIMEOUT;
static int ip_rt_gc_interval		= 60 * HZ;
static int ip_rt_gc_min_interval	= HZ / 2;
/**
 * 如果目的地持续忽略ICMP重定向消息，内核就持续发送ICMP重定向消息给它直到发送数目到达ip_rt_redirect_number
 */
static int ip_rt_redirect_number	= 9;
/**
 * 指数回退算法的初始延迟时间为ip_rt_redirect_load，每发送一个消息就翻倍间隔时间。
 */
static int ip_rt_redirect_load		= HZ / 50;
/**
 * 当发送的ICMP重定向数目达到ip_rt_redirect_number时，内核停止发送，直到ip_rt_redirect_silence秒过后还没有输入报文能够触发内核生成ICMP重定向消息。
 */
static int ip_rt_redirect_silence	= ((HZ / 50) << (9 + 1));
static int ip_rt_error_cost		= HZ;
static int ip_rt_error_burst		= 5 * HZ;
static int ip_rt_gc_elasticity		= 8;
static int ip_rt_mtu_expires		= 10 * 60 * HZ;
static int ip_rt_min_pmtu		= 512 + 20 + 20;
static int ip_rt_min_advmss		= 256;
static int ip_rt_secret_interval	= 10 * 60 * HZ;
static unsigned long rt_deadline;

#define RTprint(a...)	printk(KERN_DEBUG a)

static struct timer_list rt_flush_timer;
static struct timer_list rt_periodic_timer;
/**
 * 周期性定时器，刷新DST缓存。
 */
static struct timer_list rt_secret_timer;

/*
 *	Interface to generic destination cache.
 */

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie);
static void		 ipv4_dst_destroy(struct dst_entry *dst);
static void		 ipv4_dst_ifdown(struct dst_entry *dst,
					 struct net_device *dev, int how);
static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst);
static void		 ipv4_link_failure(struct sk_buff *skb);
static void		 ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu);
static int rt_garbage_collect(void);

/**
 * IPV4与路由子系统之间的接口。
 */
static struct dst_ops ipv4_dst_ops = {
	.family =		AF_INET,
	.protocol =		__constant_htons(ETH_P_IP),
	.gc =			rt_garbage_collect,
	.check =		ipv4_dst_check,
	.destroy =		ipv4_dst_destroy,
	.ifdown =		ipv4_dst_ifdown,
	.negative_advice =	ipv4_negative_advice,
	.link_failure =		ipv4_link_failure,
	.update_pmtu =		ip_rt_update_pmtu,
	.entry_size =		sizeof(struct rtable),
};

#define ECN_OR_COST(class)	TC_PRIO_##class

__u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};


/*
 * Route cache.
 */

/* The locking scheme is rather straight forward:
 *
 * 1) Read-Copy Update protects the buckets of the central route hash.
 * 2) Only writers remove entries, and they hold the lock
 *    as they look at rtable reference counts.
 * 3) Only readers acquire references to rtable entries,
 *    they do so with atomic increments and with the
 *    lock held.
 */

struct rt_hash_bucket {
	struct rtable	*chain;
	spinlock_t	lock;
} __attribute__((__aligned__(8)));

static struct rt_hash_bucket 	*rt_hash_table;
/**
 * 路由缓存容量，依赖于主机可用的物理内存的大小
 */
static unsigned			rt_hash_mask;
/**
 * 路由缓存容量，2的对数值。
 */
static int			rt_hash_log;
static unsigned int		rt_hash_rnd;

struct rt_cache_stat *rt_cache_stat;

static int rt_intern_hash(unsigned hash, struct rtable *rth,
				struct rtable **res);

static unsigned int rt_hash_code(u32 daddr, u32 saddr, u8 tos)
{
	return (jhash_3words(daddr, saddr, (u32) tos, rt_hash_rnd)
		& rt_hash_mask);
}

#ifdef CONFIG_PROC_FS
struct rt_cache_iter_state {
	int bucket;
};

static struct rtable *rt_cache_get_first(struct seq_file *seq)
{
	struct rtable *r = NULL;
	struct rt_cache_iter_state *st = seq->private;

	for (st->bucket = rt_hash_mask; st->bucket >= 0; --st->bucket) {
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
		if (r)
			break;
		rcu_read_unlock_bh();
	}
	return r;
}

static struct rtable *rt_cache_get_next(struct seq_file *seq, struct rtable *r)
{
	struct rt_cache_iter_state *st = rcu_dereference(seq->private);

	r = r->u.rt_next;
	while (!r) {
		rcu_read_unlock_bh();
		if (--st->bucket < 0)
			break;
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
	}
	return r;
}

static struct rtable *rt_cache_get_idx(struct seq_file *seq, loff_t pos)
{
	struct rtable *r = rt_cache_get_first(seq);

	if (r)
		while (pos && (r = rt_cache_get_next(seq, r)))
			--pos;
	return pos ? NULL : r;
}

static void *rt_cache_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? rt_cache_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *rt_cache_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct rtable *r = NULL;

	if (v == SEQ_START_TOKEN)
		r = rt_cache_get_first(seq);
	else
		r = rt_cache_get_next(seq, v);
	++*pos;
	return r;
}

static void rt_cache_seq_stop(struct seq_file *seq, void *v)
{
	if (v && v != SEQ_START_TOKEN)
		rcu_read_unlock_bh();
}

static int rt_cache_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "Iface\tDestination\tGateway \tFlags\t\tRefCnt\tUse\t"
			   "Metric\tSource\t\tMTU\tWindow\tIRTT\tTOS\tHHRef\t"
			   "HHUptod\tSpecDst");
	else {
		struct rtable *r = v;
		char temp[256];

		sprintf(temp, "%s\t%08lX\t%08lX\t%8X\t%d\t%u\t%d\t"
			      "%08lX\t%d\t%u\t%u\t%02X\t%d\t%1d\t%08X",
			r->u.dst.dev ? r->u.dst.dev->name : "*",
			(unsigned long)r->rt_dst, (unsigned long)r->rt_gateway,
			r->rt_flags, atomic_read(&r->u.dst.__refcnt),
			r->u.dst.__use, 0, (unsigned long)r->rt_src,
			(dst_metric(&r->u.dst, RTAX_ADVMSS) ?
			     (int)dst_metric(&r->u.dst, RTAX_ADVMSS) + 40 : 0),
			dst_metric(&r->u.dst, RTAX_WINDOW),
			(int)((dst_metric(&r->u.dst, RTAX_RTT) >> 3) +
			      dst_metric(&r->u.dst, RTAX_RTTVAR)),
			r->fl.fl4_tos,
			r->u.dst.hh ? atomic_read(&r->u.dst.hh->hh_refcnt) : -1,
			r->u.dst.hh ? (r->u.dst.hh->hh_output ==
				       dev_queue_xmit) : 0,
			r->rt_spec_dst);
		seq_printf(seq, "%-127s\n", temp);
        }
  	return 0;
}

static struct seq_operations rt_cache_seq_ops = {
	.start  = rt_cache_seq_start,
	.next   = rt_cache_seq_next,
	.stop   = rt_cache_seq_stop,
	.show   = rt_cache_seq_show,
};

static int rt_cache_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct rt_cache_iter_state *s = kmalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		goto out;
	rc = seq_open(file, &rt_cache_seq_ops);
	if (rc)
		goto out_kfree;
	seq          = file->private_data;
	seq->private = s;
	memset(s, 0, sizeof(*s));
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

static struct file_operations rt_cache_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cache_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release_private,
};


static void *rt_cpu_seq_start(struct seq_file *seq, loff_t *pos)
{
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(rt_cache_stat, cpu);
	}
	return NULL;
}

static void *rt_cpu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return per_cpu_ptr(rt_cache_stat, cpu);
	}
	return NULL;
	
}

static void rt_cpu_seq_stop(struct seq_file *seq, void *v)
{

}

static int rt_cpu_seq_show(struct seq_file *seq, void *v)
{
	struct rt_cache_stat *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  in_hit in_slow_tot in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search\n");
		return 0;
	}
	
	seq_printf(seq,"%08x  %08x %08x %08x %08x %08x %08x %08x "
		   " %08x %08x %08x %08x %08x %08x %08x %08x %08x \n",
		   atomic_read(&ipv4_dst_ops.entries),
		   st->in_hit,
		   st->in_slow_tot,
		   st->in_slow_mc,
		   st->in_no_route,
		   st->in_brd,
		   st->in_martian_dst,
		   st->in_martian_src,

		   st->out_hit,
		   st->out_slow_tot,
		   st->out_slow_mc, 

		   st->gc_total,
		   st->gc_ignored,
		   st->gc_goal_miss,
		   st->gc_dst_overflow,
		   st->in_hlist_search,
		   st->out_hlist_search
		);
	return 0;
}

static struct seq_operations rt_cpu_seq_ops = {
	.start  = rt_cpu_seq_start,
	.next   = rt_cpu_seq_next,
	.stop   = rt_cpu_seq_stop,
	.show   = rt_cpu_seq_show,
};


static int rt_cpu_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &rt_cpu_seq_ops);
}

static struct file_operations rt_cpu_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cpu_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#endif /* CONFIG_PROC_FS */
static __inline__ void rt_free(struct rtable *rt)
{
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static __inline__ void rt_drop(struct rtable *rt)
{
	ip_rt_put(rt);
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static __inline__ int rt_fast_clean(struct rtable *rth)
{
	/* Kill broadcast/multicast entries very aggresively, if they
	   collide in hash table with more useful entries */
	return (rth->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) &&
		rth->fl.iif && rth->u.rt_next;
}

static __inline__ int rt_valuable(struct rtable *rth)
{
	return (rth->rt_flags & (RTCF_REDIRECTED | RTCF_NOTIFY)) ||
		rth->u.dst.expires;
}

/**
 * 判断一个给定的dst_entry实例是否符合删除条件
 *		tmo1,tmo2:		表示候选者在符合删除条件之前必须在缓存中所处的最短时间。tmo2用于那些被认为特别好的应当被删除的候选项
 */
static int rt_may_expire(struct rtable *rth, unsigned long tmo1, unsigned long tmo2)
{
	unsigned long age;
	int ret = 0;

	if (atomic_read(&rth->u.dst.__refcnt))
		goto out;

	ret = 1;
	if (rth->u.dst.expires &&
	    time_after_eq(jiffies, rth->u.dst.expires))
		goto out;

	age = jiffies - rth->u.dst.lastuse;
	ret = 0;
	if ((age <= tmo1 && !rt_fast_clean(rth)) ||
	    (age <= tmo2 && rt_valuable(rth)))
		goto out;
	ret = 1;
out:	return ret;
}

/* Bits of score are:
 * 31: very valuable
 * 30: not quite useless
 * 29..0: usage counter
 */
static inline u32 rt_score(struct rtable *rt)
{
	u32 score = jiffies - rt->u.dst.lastuse;

	/**
	 * 根据路由最后使用时间，将其值存入score的低30位。
	 */
	score = ~score & ~(3<<30);

	/**
	 * 重定向路由、正被用户空间命令监控的、或者由于过期将被调度的路由。
	 * 这些路由尽量不要删除，设置其第32位。
	 */
	if (rt_valuable(rt))
		score |= (1<<31);

	/**
	 * 出路由、非广播路由、多播路由、本地地址路由，这些路由不容易生成，设置其第31位。
	 */
	if (!rt->fl.iif ||
	    !(rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST|RTCF_LOCAL)))
		score |= (1<<30);

	return score;
}

/* This runs via a timer and thus is always in BH context. */
/**
 * 异步清理DST缓存。
 * 每当rt_check_expire被激活时，它只扫描一部分缓存。
 */
static void rt_check_expire(unsigned long dummy)
{
	static int rover;
	/**
	 * 保持一个静态变量（rover）来记住前一次函数激活时扫描到的最后一个桶，每当该函数激活时就从下一个桶开始扫描。
	 */
	int i = rover, t;
	struct rtable *rth, **rthp;
	unsigned long now = jiffies;

	for (t = ip_rt_gc_interval << rt_hash_log; t >= 0;
	     t -= ip_rt_gc_timeout) {
		unsigned long tmo = ip_rt_gc_timeout;

		i = (i + 1) & rt_hash_mask;
		rthp = &rt_hash_table[i].chain;

		spin_lock(&rt_hash_table[i].lock);
		while ((rth = *rthp) != NULL) {
			if (rth->u.dst.expires) {
				/* Entry is expired even if it is in use */
				/**
				 * 表项没有过期。减小tmo，增加下一个表项被删除的机率。
				 */
				if (time_before_eq(now, rth->u.dst.expires)) {
					tmo >>= 1;
					rthp = &rth->u.rt_next;
					continue;
				}
			} else if (!rt_may_expire(rth, tmo, ip_rt_gc_timeout)) {
			    /**
			     * 减小tmo的值，这样，下一个DST项将更容易被选中。
			     */
				tmo >>= 1;
				rthp = &rth->u.rt_next;
				continue;
			}

			/* Cleanup aged off entries. */
			*rthp = rth->u.rt_next;
			/**
			 * 如果缓存内表项的时间已经过期，或者通过rt_may_expire判断出符合删除条件，则调用rt_free删除这些表项。
			 */
			rt_free(rth);
		}
		spin_unlock(&rt_hash_table[i].lock);

		/* Fallback loop breaker. */
		/**
		 * 当rt_check_expire完成扫描整张哈希表或已经运行至少一个jiffies时，就重新启动该定时器，函数返回。
		 */
		if (time_after(jiffies, now))
			break;
	}
	rover = i;
	mod_timer(&rt_periodic_timer, now + ip_rt_gc_interval);
}

/* This can run from both BH and non-BH contexts, the latter
 * in the case of a forced flush event.
 */
/**
 * 刷新路由缓存。并不被直接调用。
 * 一般由rt_cache_flush函数调用。
 */
static void rt_run_flush(unsigned long dummy)
{
	int i;
	struct rtable *rth, *next;

	rt_deadline = 0;

	get_random_bytes(&rt_hash_rnd, 4);

	for (i = rt_hash_mask; i >= 0; i--) {
		spin_lock_bh(&rt_hash_table[i].lock);
		rth = rt_hash_table[i].chain;
		if (rth)
			rt_hash_table[i].chain = NULL;
		spin_unlock_bh(&rt_hash_table[i].lock);

		for (; rth; rth = next) {
			next = rth->u.rt_next;
			rt_free(rth);
		}
	}
}
/**
 * 在rt_cache_flush接口中，使用这个spin锁保护对rt_deadline全局变量和rt_flush_timer定时器的操作。
 */
static DEFINE_SPINLOCK(rt_flush_lock);

/**
 * 在一个给定的时间段（由输入参数指定）后，调度一次路由缓存的flush。
 * delay的取值：
 *		小于0:		缓存在内核参数ip_rt_min_delay指定的时间后被flush，该参数可以通过/proc来调整
 *		0:			缓存立即被flush。
 *		大于0:		缓存在指定的时间后被flush。
 */
void rt_cache_flush(int delay)
{
	unsigned long now = jiffies;
	int user_mode = !in_softirq();

	if (delay < 0)
		delay = ip_rt_min_delay;

	spin_lock_bh(&rt_flush_lock);

	/**
	 * 重启定时器。这个新请求不能让定时器迟于ip_rt_max_delay秒之后才过期。
	 */
	if (del_timer(&rt_flush_timer) && delay > 0 && rt_deadline) {
		long tmo = (long)(rt_deadline - now);

		/* If flush timer is already running
		   and flush request is not immediate (delay > 0):

		   if deadline is not achieved, prolongate timer to "delay",
		   otherwise fire it at deadline time.
		 */

		if (user_mode && tmo < ip_rt_max_delay-ip_rt_min_delay)
			tmo = 0;
		
		if (delay > tmo)
			delay = tmo;
	}

	/**
	 * 这里不用判断<0，只需要判断==0就行了。这种情况下，立即刷新缓存。
	 */
	if (delay <= 0) {
		spin_unlock_bh(&rt_flush_lock);
		rt_run_flush(0);
		return;
	}

	if (rt_deadline == 0)
		rt_deadline = now + ip_rt_max_delay;

	mod_timer(&rt_flush_timer, now+delay);
	spin_unlock_bh(&rt_flush_lock);
}

/**
 * 周期性的刷新DST缓存。
 */
static void rt_secret_rebuild(unsigned long dummy)
{
	unsigned long now = jiffies;

	rt_cache_flush(0);
	mod_timer(&rt_secret_timer, now + ip_rt_secret_interval);
}

/*
   Short description of GC goals.

   We want to build algorithm, which will keep routing cache
   at some equilibrium point, when number of aged off entries
   is kept approximately equal to newly generated ones.

   Current expiration strength is variable "expire".
   We try to adjust it dynamically, so that if networking
   is idle expires is large enough to keep enough of warm entries,
   and when load increases it reduces to limit cache size.
 */

/**
 * IPV4的DST缓存回收函数。由DST子系统在以下两种情况下调用gc：
 *		当添加一个新表项到路由缓存中但发现内存不够时。
 *		当添加一个新表项到路由缓存中，但表项总数将超过门限值gc_thresh时。分配表项的dst_alloc函数通过限制缓存容量为一个固定值来触发一个清理，以减少占用的内存。
 */
static int rt_garbage_collect(void)
{
	static unsigned long expire = RT_GC_TIMEOUT;
	static unsigned long last_gc;
	static int rover;
	static int equilibrium;
	struct rtable *rth, **rthp;
	unsigned long now = jiffies;
	int goal;

	/*
	 * Garbage collection is pretty expensive,
	 * do not make it too frequently.
	 */

	RT_CACHE_STAT_INC(gc_total);

	/**
	 * rt_garbage_collect程序所做的垃圾回收需要花费大量的CPU时间。因此，如果该程序上次被调用的时间与现在的间隔小于ip_rt_gc_min_interval秒，则不做任何事而立即返回。
	 * 除非缓存内的表项数目已经达到最大值ip_rt_max_size，这时要求立刻执行。
	 */
	if (now - last_gc < ip_rt_gc_min_interval &&
	    atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size) {
		RT_CACHE_STAT_INC(gc_ignored);
		goto out;
	}

	/* Calculate number of entries, which we want to expire now. */
	/**
	 * 首先计算可能删除的缓存表项数目（goal）。
	 */
	goal = atomic_read(&ipv4_dst_ops.entries) -
		(ip_rt_gc_elasticity << rt_hash_log);/* 超过ip_rt_gc_elasticity*(2^rt_hash_log)时，其缺省值为哈希表的大小乘以8，认为缓存有变大的风险 */
	if (goal <= 0) {/* 缓存有变大的风险，设置更为激进的策略 */
		if (equilibrium < ipv4_dst_ops.gc_thresh)
			equilibrium = ipv4_dst_ops.gc_thresh;/* 保留gc_thresh个缓存项。 */
		goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		if (goal > 0) {
			equilibrium += min_t(unsigned int, goal / 2, rt_hash_mask + 1);
			goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		}
	} else {
		/* We are in dangerous area. Try to reduce cache really
		 * aggressively.
		 */
		goal = max_t(unsigned int, goal / 2, rt_hash_mask + 1);/* 哈希表的大小为rt_hash_mask+1，或2^rt_hash_log */
		/**
		 * 计算出一旦goal个表项被删除，还剩余的表项数目，这个数目被保存到equilibrium中。
		 */
		equilibrium = atomic_read(&ipv4_dst_ops.entries) - goal;
	}

	if (now - last_gc >= ip_rt_gc_min_interval)
		last_gc = now;

	if (goal <= 0) {
		equilibrium += goal;
		goto work_done;
	}

	/**
	 * 遍历哈希表，尝试使最符合条件的表项过期。
	 */
	do {
		int i, k;

		/**
		 * 哈希表的遍历并不是简单地从第一个桶开始到最后一个桶。
		 * rt_garbage_collect利用一个静态变量rover来记住前一次函数激活时扫描到的最后一个桶。
		 * 这是因为不一定必须完整地扫描一遍该哈希表。通过记住上次扫描的哈希桶，程序就可以公平对待所有的桶，而不总是从第一个桶开始来选择受害者。
		 */
		for (i = rt_hash_mask, k = rover; i >= 0; i--) {
			unsigned long tmo = expire;

			k = (k + 1) & rt_hash_mask;
			rthp = &rt_hash_table[k].chain;
			spin_lock_bh(&rt_hash_table[k].lock);
			while ((rth = *rthp) != NULL) {
				/**
				 * 利用rt_may_expire检查它们是否符合过期条件。
				 */
				if (!rt_may_expire(rth, tmo, expire)) {
					/**
					 * 当扫描一个桶的元素时，每当一个元素不符合删除条件，则降低（减半）第一个时间门限值。
					 */
					tmo >>= 1;
					rthp = &rth->u.rt_next;
					continue;
				}
				*rthp = rth->u.rt_next;
				/**
				 * 将符合删除条件的表项调用rt_free直接删除
				 */
				rt_free(rth);
				goal--;
			}
			spin_unlock_bh(&rt_hash_table[k].lock);
			/**
			 * 当扫描到每个桶链表的末尾时，函数将再次检查被删除表项的数目是否为函数开始时设置的数目goal。
			 */
			if (goal <= 0)
				break;
			/**
			 * 继续扫描下一个桶。该过程一直继续直到完成整张表的扫描。
			 */
		}
		rover = k;

		if (goal <= 0)
			goto work_done;

		/* Goal is not achieved. We stop process if:

		   - if expire reduced to zero. Otherwise, expire is halfed.
		   - if table is not full.
		   - if we are called from interrupt.
		   - jiffies check is just fallback/debug loop breaker.
		     We will not spin here for long time in any case.
		 */

		RT_CACHE_STAT_INC(gc_goal_miss);

		if (expire == 0)
			break;

		/**
		 * 用更为激进的判断标准来重新扫描哈希表。
		 */
		expire >>= 1;
#if RT_CACHE_DEBUG >= 2
		printk(KERN_DEBUG "expire>> %u %d %d %d\n", expire,
				atomic_read(&ipv4_dst_ops.entries), goal, i);
#endif

		if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
			goto out;
	/**
	 * 如果程序是在软中断上下文中被调用，或者前一次扫描花费的时间超过一个jiffies（在x86平台上即为1/1000秒），则认为本次重新扫描哈希表将花费太多的时间，因而跳过不做。
	 */
	} while (!in_softirq() && time_before_eq(jiffies, now));

	if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
		goto out;
	if (net_ratelimit())
		printk(KERN_WARNING "dst cache overflow\n");
	RT_CACHE_STAT_INC(gc_dst_overflow);
	return 1;

work_done:
	expire += ip_rt_gc_min_interval;
	if (expire > ip_rt_gc_timeout ||
	    atomic_read(&ipv4_dst_ops.entries) < ipv4_dst_ops.gc_thresh)
		expire = ip_rt_gc_timeout;
#if RT_CACHE_DEBUG >= 2
	printk(KERN_DEBUG "expire++ %u %d %d %d\n", expire,
			atomic_read(&ipv4_dst_ops.entries), goal, rover);
#endif
out:	return 0;
}

static inline int compare_keys(struct flowi *fl1, struct flowi *fl2)
{
	return memcmp(&fl1->nl_u.ip4_u, &fl2->nl_u.ip4_u, sizeof(fl1->nl_u.ip4_u)) == 0 &&
	       fl1->oif     == fl2->oif &&
	       fl1->iif     == fl2->iif;
}

/**
 * 将路由缓存表项插入到缓存表哈希桶的链表首部。
 */
static int rt_intern_hash(unsigned hash, struct rtable *rt, struct rtable **rp)
{
	struct rtable	*rth, **rthp;
	unsigned long	now;
	struct rtable *cand, **candp;
	u32 		min_score;
	int		chain_length;
	int attempts = !in_softirq();

restart:
	chain_length = 0;
	min_score = ~(u32)0;
	cand = NULL;
	candp = NULL;
	now = jiffies;

	rthp = &rt_hash_table[hash].chain;

	spin_lock_bh(&rt_hash_table[hash].lock);
	/**
	 * 通过一个简单的缓存查找来确定新路由表项是否已经存在。
	 * 虽然这个函数是在缓存查找失败后被调用，但该路由项可能同时已经被另一个CPU添加到缓存内。
	 */
	while ((rth = *rthp) != NULL) {
		if (compare_keys(&rth->fl, &rt->fl)) {/* 查找成功 */
			/* Put it first */
			*rthp = rth->u.rt_next;
			/*
			 * Since lookup is lockfree, the deletion
			 * must be visible to another weakly ordered CPU before
			 * the insertion at the start of the hash chain.
			 */
			/**
			 * 原来的缓存路由表项被移动到哈希桶链表的首部
			 */
			rcu_assign_pointer(rth->u.rt_next,
					   rt_hash_table[hash].chain);
			/*
			 * Since lookup is lockfree, the update writes
			 * must be ordered for consistency on SMP.
			 */
			rcu_assign_pointer(rt_hash_table[hash].chain, rth);

			rth->u.dst.__use++;
			dst_hold(&rth->u.dst);
			rth->u.dst.lastuse = now;
			spin_unlock_bh(&rt_hash_table[hash].lock);

			rt_drop(rt);
			*rp = rth;
			return 0;
		}

		/**
		 * 如果引用计数为0，那么这个缓存可以被回收。
		 */
		if (!atomic_read(&rth->u.dst.__refcnt)) {
			u32 score = rt_score(rth);

			/**
			 * 比较路由缓存的价值，尽量选择价值低的缓存被删除。
			 */
			if (score <= min_score) {
				cand = rth;
				candp = rthp;
				min_score = score;
			}
		}

		chain_length++;

		rthp = &rth->u.rt_next;
	}

	if (cand) {
		/* ip_rt_gc_elasticity used to be average length of chain
		 * length, when exceeded gc becomes really aggressive.
		 *
		 * The second limit is less certain. At the moment it allows
		 * only 2 entries per bucket. We will see.
		 */
		/**
		 * 有可以回收的缓存，并且桶内的元素大于ip_rt_gc_elasticity，则释放该缓存。
		 */
		if (chain_length > ip_rt_gc_elasticity) {
			*candp = cand->u.rt_next;
			rt_free(cand);
		}
	}

	/* Try to bind route to arp only if it is output
	   route or unicast forwarding path.
	 */
	/**
	 * 对出路由或者非直达路由，进行邻居绑定。
	 */
	if (rt->rt_type == RTN_UNICAST || rt->fl.iif == 0) {
		/**
		 * 将路由缓存绑定到邻居。
		 */
		int err = arp_bind_neighbour(&rt->u.dst);
		if (err) {
			spin_unlock_bh(&rt_hash_table[hash].lock);

			if (err != -ENOBUFS) {
				rt_drop(rt);
				return err;
			}

			/* Neighbour tables are full and nothing
			   can be released. Try to shrink route cache,
			   it is most likely it holds some neighbour records.
			 */
			/**
			 * 由于内存的原因，导致邻居绑定失败，则调用rt_garbage_collect来强行进行一次垃圾回收操作
			 */
			if (attempts-- > 0) {
				int saved_elasticity = ip_rt_gc_elasticity;
				int saved_int = ip_rt_gc_min_interval;
				/**
				 * 降低ip_rt_gc_elasticity和ip_rt_gc_min_interval门限值
				 */
				ip_rt_gc_elasticity	= 1;
				ip_rt_gc_min_interval	= 0;
				/**
				 * 调用rt_garbage_collect来完成回收。
				 */
				rt_garbage_collect();
				/**
				 * 恢复门限值。
				 */
				ip_rt_gc_min_interval	= saved_int;
				ip_rt_gc_elasticity	= saved_elasticity;
				/**
				 * 只进行一次回收，请注意attempts最大值为1.如果是在中断上下文，根本不进行回收。
				 */
				goto restart;
			}

			if (net_ratelimit())
				printk(KERN_WARNING "Neighbour table overflow.\n");
			rt_drop(rt);
			return -ENOBUFS;
		}
	}

	/**
	 * 将这个新路由项添加到缓存内。
	 */
	rt->u.rt_next = rt_hash_table[hash].chain;
#if RT_CACHE_DEBUG >= 2
	if (rt->u.rt_next) {
		struct rtable *trt;
		printk(KERN_DEBUG "rt_cache @%02x: %u.%u.%u.%u", hash,
		       NIPQUAD(rt->rt_dst));
		for (trt = rt->u.rt_next; trt; trt = trt->u.rt_next)
			printk(" . %u.%u.%u.%u", NIPQUAD(trt->rt_dst));
		printk("\n");
	}
#endif
	rt_hash_table[hash].chain = rt;
	spin_unlock_bh(&rt_hash_table[hash].lock);
	*rp = rt;
	return 0;
}

void rt_bind_peer(struct rtable *rt, int create)
{
	static DEFINE_SPINLOCK(rt_peer_lock);
	struct inet_peer *peer;

	peer = inet_getpeer(rt->rt_dst, create);

	spin_lock_bh(&rt_peer_lock);
	if (rt->peer == NULL) {
		rt->peer = peer;
		peer = NULL;
	}
	spin_unlock_bh(&rt_peer_lock);
	if (peer)
		inet_putpeer(peer);
}

/*
 * Peer allocation may fail only in serious out-of-memory conditions.  However
 * we still can generate some output.
 * Random ID selection looks a bit dangerous because we have no chances to
 * select ID being unique in a reasonable period of time.
 * But broken packet identifier may be better than no packet at all.
 */
/**
 * 当没有长效IP端点时(一般是负荷过重，无法分配inet_peer结构)，根据全局变量生成报文ID。
 */
static void ip_select_fb_ident(struct iphdr *iph)
{
	static DEFINE_SPINLOCK(ip_fb_id_lock);
	static u32 ip_fallback_id;
	u32 salt;

	spin_lock_bh(&ip_fb_id_lock);
	salt = secure_ip_id(ip_fallback_id ^ iph->daddr);
	iph->id = htons(salt & 0xFFFF);
	ip_fallback_id = salt;
	spin_unlock_bh(&ip_fb_id_lock);
}

/**
 * 选择一个IP包的ID。
 */
void __ip_select_ident(struct iphdr *iph, struct dst_entry *dst, int more)
{
	struct rtable *rt = (struct rtable *) dst;

	if (rt) {
		/**
		 * 如果inet_peer结构尚未在路由缓存项目rt中做好初始化，由rt_bind_peer会先寻找和该端点相匹配的inet_peer结构
		 * 然后，如果不存在，此函数就会试着建立（因为给rt_bind_peer的最后一个输入参数是设为1）
		 */
		if (rt->peer == NULL)
			rt_bind_peer(rt, 1);

		/* If peer is attached to destination, it is never detached,
		   so that we need not to grab a lock to dereference it.
		 */
		/**
		 * 这种建立的尝试会在负载过重而耗尽内存的系统上失败（无法分配新的inet_peer结构）
		 */
		if (rt->peer) {/* 有长效端点IP信息，从中分配一个ID。 */
			iph->id = htons(inet_getid(rt->peer, more));
			return;
		}
	} else
		printk(KERN_DEBUG "rt_bind_peer(0) @%p\n", NET_CALLER(iph));

	/**
	 * 没有对应的长效IP端点，则调用ip_select_fb_ident获得ID。
	 */
	ip_select_fb_ident(iph);
}

static void rt_del(unsigned hash, struct rtable *rt)
{
	struct rtable **rthp;

	spin_lock_bh(&rt_hash_table[hash].lock);
	ip_rt_put(rt);
	for (rthp = &rt_hash_table[hash].chain; *rthp;
	     rthp = &(*rthp)->u.rt_next)
		if (*rthp == rt) {
			*rthp = rt->u.rt_next;
			rt_free(rt);
			break;
		}
	spin_unlock_bh(&rt_hash_table[hash].lock);
}

void ip_rt_redirect(u32 old_gw, u32 daddr, u32 new_gw,
		    u32 saddr, u8 tos, struct net_device *dev)
{
	int i, k;
	struct in_device *in_dev = in_dev_get(dev);
	struct rtable *rth, **rthp;
	u32  skeys[2] = { saddr, 0 };
	int  ikeys[2] = { dev->ifindex, 0 };

	tos &= IPTOS_RT_MASK;

	if (!in_dev)
		return;

	if (new_gw == old_gw || !IN_DEV_RX_REDIRECTS(in_dev)
	    || MULTICAST(new_gw) || BADCLASS(new_gw) || ZERONET(new_gw))
		goto reject_redirect;

	if (!IN_DEV_SHARED_MEDIA(in_dev)) {
		if (!inet_addr_onlink(in_dev, new_gw, old_gw))
			goto reject_redirect;
		if (IN_DEV_SEC_REDIRECTS(in_dev) && ip_fib_check_default(new_gw, dev))
			goto reject_redirect;
	} else {
		if (inet_addr_type(new_gw) != RTN_UNICAST)
			goto reject_redirect;
	}

	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++) {
			unsigned hash = rt_hash_code(daddr,
						     skeys[i] ^ (ikeys[k] << 5),
						     tos);

			rthp=&rt_hash_table[hash].chain;

			rcu_read_lock();
			while ((rth = rcu_dereference(*rthp)) != NULL) {
				struct rtable *rt;

				if (rth->fl.fl4_dst != daddr ||
				    rth->fl.fl4_src != skeys[i] ||
				    rth->fl.fl4_tos != tos ||
				    rth->fl.oif != ikeys[k] ||
				    rth->fl.iif != 0) {
					rthp = &rth->u.rt_next;
					continue;
				}

				if (rth->rt_dst != daddr ||
				    rth->rt_src != saddr ||
				    rth->u.dst.error ||
				    rth->rt_gateway != old_gw ||
				    rth->u.dst.dev != dev)
					break;

				dst_hold(&rth->u.dst);
				rcu_read_unlock();

				rt = dst_alloc(&ipv4_dst_ops);
				if (rt == NULL) {
					ip_rt_put(rth);
					in_dev_put(in_dev);
					return;
				}

				/* Copy all the information. */
				*rt = *rth;
 				INIT_RCU_HEAD(&rt->u.dst.rcu_head);
				rt->u.dst.__use		= 1;
				atomic_set(&rt->u.dst.__refcnt, 1);
				rt->u.dst.child		= NULL;
				if (rt->u.dst.dev)
					dev_hold(rt->u.dst.dev);
				if (rt->idev)
					in_dev_hold(rt->idev);
				rt->u.dst.obsolete	= 0;
				rt->u.dst.lastuse	= jiffies;
				rt->u.dst.path		= &rt->u.dst;
				rt->u.dst.neighbour	= NULL;
				rt->u.dst.hh		= NULL;
				rt->u.dst.xfrm		= NULL;

				rt->rt_flags		|= RTCF_REDIRECTED;

				/* Gateway is different ... */
				rt->rt_gateway		= new_gw;

				/* Redirect received -> path was valid */
				dst_confirm(&rth->u.dst);

				if (rt->peer)
					atomic_inc(&rt->peer->refcnt);

				if (arp_bind_neighbour(&rt->u.dst) ||
				    !(rt->u.dst.neighbour->nud_state &
					    NUD_VALID)) {
					if (rt->u.dst.neighbour)
						neigh_event_send(rt->u.dst.neighbour, NULL);
					ip_rt_put(rth);
					rt_drop(rt);
					goto do_next;
				}

				rt_del(hash, rth);
				if (!rt_intern_hash(hash, rt, &rt))
					ip_rt_put(rt);
				goto do_next;
			}
			rcu_read_unlock();
		do_next:
			;
		}
	}
	in_dev_put(in_dev);
	return;

reject_redirect:
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_INFO "Redirect from %u.%u.%u.%u on %s about "
			"%u.%u.%u.%u ignored.\n"
			"  Advised path = %u.%u.%u.%u -> %u.%u.%u.%u, "
			"tos %02x\n",
		       NIPQUAD(old_gw), dev->name, NIPQUAD(new_gw),
		       NIPQUAD(saddr), NIPQUAD(daddr), tos);
#endif
	in_dev_put(in_dev);
}

static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable*)dst;
	struct dst_entry *ret = dst;

	if (rt) {
		if (dst->obsolete) {
			ip_rt_put(rt);
			ret = NULL;
		} else if ((rt->rt_flags & RTCF_REDIRECTED) ||
			   rt->u.dst.expires) {
			unsigned hash = rt_hash_code(rt->fl.fl4_dst,
						     rt->fl.fl4_src ^
							(rt->fl.oif << 5),
						     rt->fl.fl4_tos);
#if RT_CACHE_DEBUG >= 1
			printk(KERN_DEBUG "ip_rt_advice: redirect to "
					  "%u.%u.%u.%u/%02x dropped\n",
				NIPQUAD(rt->rt_dst), rt->fl.fl4_tos);
#endif
			rt_del(hash, rt);
			ret = NULL;
		}
	}
	return ret;
}

/*
 * Algorithm:
 *	1. The first ip_rt_redirect_number redirects are sent
 *	   with exponential backoff, then we stop sending them at all,
 *	   assuming that the host ignores our redirects.
 *	2. If we did not see packets requiring redirects
 *	   during ip_rt_redirect_silence, we assume that the host
 *	   forgot redirected route and start to send redirects again.
 *
 * This algorithm is much cheaper and more intelligent than dumb load limiting
 * in icmp.c.
 *
 * NOTE. Do not forget to inhibit load limiting for redirects (redundant)
 * and "frag. need" (breaks PMTU discovery) in icmp.c.
 */
/**
 * egress重定向消息处理。
 */
void ip_rt_send_redirect(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	struct in_device *in_dev = in_dev_get(rt->u.dst.dev);

	if (!in_dev)
		return;

	if (!IN_DEV_TX_REDIRECTS(in_dev))
		goto out;

	/* No redirected packets during ip_rt_redirect_silence;
	 * reset the algorithm.
	 */
	if (time_after(jiffies, rt->u.dst.rate_last + ip_rt_redirect_silence))
		rt->u.dst.rate_tokens = 0;

	/* Too many ignored redirects; do not send anything
	 * set u.dst.rate_last to the last seen redirected packet.
	 */
	if (rt->u.dst.rate_tokens >= ip_rt_redirect_number) {
		rt->u.dst.rate_last = jiffies;
		goto out;
	}

	/* Check for load limit; set rate_last to the latest sent
	 * redirect.
	 */
	if (time_after(jiffies,
		       (rt->u.dst.rate_last +
			(ip_rt_redirect_load << rt->u.dst.rate_tokens)))) {
		icmp_send(skb, ICMP_REDIRECT, ICMP_REDIR_HOST, rt->rt_gateway);
		rt->u.dst.rate_last = jiffies;
		++rt->u.dst.rate_tokens;
#ifdef CONFIG_IP_ROUTE_VERBOSE
		if (IN_DEV_LOG_MARTIANS(in_dev) &&
		    rt->u.dst.rate_tokens == ip_rt_redirect_number &&
		    net_ratelimit())
			printk(KERN_WARNING "host %u.%u.%u.%u/if%d ignores "
				"redirects for %u.%u.%u.%u to %u.%u.%u.%u.\n",
				NIPQUAD(rt->rt_src), rt->rt_iif,
				NIPQUAD(rt->rt_dst), NIPQUAD(rt->rt_gateway));
#endif
	}
out:
        in_dev_put(in_dev);
}

/**
 * 当不存在路由项时，处理对应的入包。会向发送方发送ICMP_UNREACHABLE消息。
 */
static int ip_error(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	unsigned long now;
	int code;

	switch (rt->u.dst.error) {
		case EINVAL:
		default:
			goto out;
		case EHOSTUNREACH:
			code = ICMP_HOST_UNREACH;
			break;
		case ENETUNREACH:
			code = ICMP_NET_UNREACH;
			break;
		case EACCES:
			code = ICMP_PKT_FILTERED;
			break;
	}

	now = jiffies;
	rt->u.dst.rate_tokens += now - rt->u.dst.rate_last;
	if (rt->u.dst.rate_tokens > ip_rt_error_burst)
		rt->u.dst.rate_tokens = ip_rt_error_burst;
	rt->u.dst.rate_last = now;
	if (rt->u.dst.rate_tokens >= ip_rt_error_cost) {
		rt->u.dst.rate_tokens -= ip_rt_error_cost;
		icmp_send(skb, ICMP_DEST_UNREACH, code, 0);
	}

out:	kfree_skb(skb);
	return 0;
} 

/*
 *	The last two values are not from the RFC but
 *	are needed for AMPRnet AX.25 paths.
 */

static unsigned short mtu_plateau[] =
{32000, 17914, 8166, 4352, 2002, 1492, 576, 296, 216, 128 };

static __inline__ unsigned short guess_mtu(unsigned short old_mtu)
{
	int i;
	
	for (i = 0; i < ARRAY_SIZE(mtu_plateau); i++)
		if (old_mtu > mtu_plateau[i])
			return mtu_plateau[i];
	return 68;
}

unsigned short ip_rt_frag_needed(struct iphdr *iph, unsigned short new_mtu)
{
	int i;
	unsigned short old_mtu = ntohs(iph->tot_len);
	struct rtable *rth;
	u32  skeys[2] = { iph->saddr, 0, };
	u32  daddr = iph->daddr;
	u8   tos = iph->tos & IPTOS_RT_MASK;
	unsigned short est_mtu = 0;

	if (ipv4_config.no_pmtu_disc)
		return 0;

	for (i = 0; i < 2; i++) {
		unsigned hash = rt_hash_code(daddr, skeys[i], tos);

		rcu_read_lock();
		for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		     rth = rcu_dereference(rth->u.rt_next)) {
			if (rth->fl.fl4_dst == daddr &&
			    rth->fl.fl4_src == skeys[i] &&
			    rth->rt_dst  == daddr &&
			    rth->rt_src  == iph->saddr &&
			    rth->fl.fl4_tos == tos &&
			    rth->fl.iif == 0 &&
			    !(dst_metric_locked(&rth->u.dst, RTAX_MTU))) {
				unsigned short mtu = new_mtu;

				if (new_mtu < 68 || new_mtu >= old_mtu) {

					/* BSD 4.2 compatibility hack :-( */
					if (mtu == 0 &&
					    old_mtu >= rth->u.dst.metrics[RTAX_MTU-1] &&
					    old_mtu >= 68 + (iph->ihl << 2))
						old_mtu -= iph->ihl << 2;

					mtu = guess_mtu(old_mtu);
				}
				if (mtu <= rth->u.dst.metrics[RTAX_MTU-1]) {
					if (mtu < rth->u.dst.metrics[RTAX_MTU-1]) { 
						dst_confirm(&rth->u.dst);
						if (mtu < ip_rt_min_pmtu) {
							mtu = ip_rt_min_pmtu;
							rth->u.dst.metrics[RTAX_LOCK-1] |=
								(1 << RTAX_MTU);
						}
						rth->u.dst.metrics[RTAX_MTU-1] = mtu;
						dst_set_expires(&rth->u.dst,
							ip_rt_mtu_expires);
					}
					est_mtu = mtu;
				}
			}
		}
		rcu_read_unlock();
	}
	return est_mtu ? : new_mtu;
}

static void ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu)
{
	if (dst->metrics[RTAX_MTU-1] > mtu && mtu >= 68 &&
	    !(dst_metric_locked(dst, RTAX_MTU))) {
		if (mtu < ip_rt_min_pmtu) {
			mtu = ip_rt_min_pmtu;
			dst->metrics[RTAX_LOCK-1] |= (1 << RTAX_MTU);
		}
		dst->metrics[RTAX_MTU-1] = mtu;
		dst_set_expires(dst, ip_rt_mtu_expires);
	}
}

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie)
{
	dst_release(dst);
	return NULL;
}

static void ipv4_dst_destroy(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable *) dst;
	struct inet_peer *peer = rt->peer;
	struct in_device *idev = rt->idev;

	if (peer) {
		rt->peer = NULL;
		inet_putpeer(peer);
	}

	if (idev) {
		rt->idev = NULL;
		in_dev_put(idev);
	}
}

static void ipv4_dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			    int how)
{
	struct rtable *rt = (struct rtable *) dst;
	struct in_device *idev = rt->idev;
	if (dev != &loopback_dev && idev && idev->dev == dev) {
		struct in_device *loopback_idev = in_dev_get(&loopback_dev);
		if (loopback_idev) {
			rt->idev = loopback_idev;
			in_dev_put(idev);
		}
	}
}

static void ipv4_link_failure(struct sk_buff *skb)
{
	struct rtable *rt;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

	rt = (struct rtable *) skb->dst;
	if (rt)
		dst_set_expires(&rt->u.dst, 0);
}

static int ip_rt_bug(struct sk_buff *skb)
{
	printk(KERN_DEBUG "ip_rt_bug: %u.%u.%u.%u -> %u.%u.%u.%u, %s\n",
		NIPQUAD(skb->nh.iph->saddr), NIPQUAD(skb->nh.iph->daddr),
		skb->dev ? skb->dev->name : "?");
	kfree_skb(skb);
	return 0;
}

/*
   We do not cache source address of outgoing interface,
   because it is used only by IP RR, TS and SRR options,
   so that it out of fast path.

   BTW remember: "addr" is allowed to be not aligned
   in IP options!
 */

void ip_rt_get_source(u8 *addr, struct rtable *rt)
{
	u32 src;
	struct fib_result res;

	if (rt->fl.iif == 0)
		src = rt->rt_src;
	else if (fib_lookup(&rt->fl, &res) == 0) {
		src = FIB_RES_PREFSRC(res);
		fib_res_put(&res);
	} else
		src = inet_select_addr(rt->u.dst.dev, rt->rt_gateway,
					RT_SCOPE_UNIVERSE);
	memcpy(addr, &src, 4);
}

#ifdef CONFIG_NET_CLS_ROUTE
/**
 * 给定一条路由和一个已经被调用方初始化了的标签，set_class_tag使用第二个参数来填充dst_entry.tclassid中还没有被初始化的realm。
 */
static void set_class_tag(struct rtable *rt, u32 tag)
{
	if (!(rt->u.dst.tclassid & 0xFFFF))
		rt->u.dst.tclassid |= tag & 0xFFFF;
	if (!(rt->u.dst.tclassid & 0xFFFF0000))
		rt->u.dst.tclassid |= tag & 0xFFFF0000;
}
#endif

/**
 * 给定一个路由缓存项rtable和一个路由表查找结果res，完成rtable内各字段的初始化，诸如rt_gateway、所嵌入的dst_entry结构的metrics向量等等。
 */
static void rt_set_nexthop(struct rtable *rt, struct fib_result *res, u32 itag)
{
	struct fib_info *fi = res->fi;

	if (fi) {
		if (FIB_RES_GW(*res) &&
		    FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
			rt->rt_gateway = FIB_RES_GW(*res);
		memcpy(rt->u.dst.metrics, fi->fib_metrics,
		       sizeof(rt->u.dst.metrics));
		if (fi->fib_mtu == 0) {
			rt->u.dst.metrics[RTAX_MTU-1] = rt->u.dst.dev->mtu;
			if (rt->u.dst.metrics[RTAX_LOCK-1] & (1 << RTAX_MTU) &&
			    rt->rt_gateway != rt->rt_dst &&
			    rt->u.dst.dev->mtu > 576)
				rt->u.dst.metrics[RTAX_MTU-1] = 576;
		}
#ifdef CONFIG_NET_CLS_ROUTE
		/**
		 * 设置路由标签。首先用目的路由的realm来初始化tclassid。
		 */
		rt->u.dst.tclassid = FIB_RES_NH(*res).nh_tclassid;
#endif
	} else
		rt->u.dst.metrics[RTAX_MTU-1]= rt->u.dst.dev->mtu;

	if (rt->u.dst.metrics[RTAX_HOPLIMIT-1] == 0)
		rt->u.dst.metrics[RTAX_HOPLIMIT-1] = sysctl_ip_default_ttl;
	if (rt->u.dst.metrics[RTAX_MTU-1] > IP_MAX_MTU)
		rt->u.dst.metrics[RTAX_MTU-1] = IP_MAX_MTU;
	if (rt->u.dst.metrics[RTAX_ADVMSS-1] == 0)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = max_t(unsigned int, rt->u.dst.dev->mtu - 40,
				       ip_rt_min_advmss);
	if (rt->u.dst.metrics[RTAX_ADVMSS-1] > 65535 - 40)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = 65535 - 40;

#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	/**
	 * 支持策略路由时，根据策略realms来填充dst.tclassid中还没有被初始化的字段。
	 */
	set_class_tag(rt, fib_rules_tclass(res));
#endif
	/**
 	 * 使用调用方先前计算的itag输入参数来填充dst.tclassid中还没有被初始化的字段
 	 *		ip_route_input_slow（通过调用__mkroute_input）传递的itag值是用fib_combine_itag计算的。
 	 *		ip_route_output_slow（通过调用__mkroute_output）传递的itag值为0，因为它路由的报文是本地生成的，因而内核不用做任何反向查找来填充还没有被初始化的realms。
 	 */
	set_class_tag(rt, itag);
#endif
        rt->rt_type = res->type;
}

static int ip_route_input_mc(struct sk_buff *skb, u32 daddr, u32 saddr,
				u8 tos, struct net_device *dev, int our)
{
	unsigned hash;
	struct rtable *rth;
	u32 spec_dst;
	struct in_device *in_dev = in_dev_get(dev);
	u32 itag = 0;

	/* Primary sanity checks. */

	if (in_dev == NULL)
		return -EINVAL;

	if (MULTICAST(saddr) || BADCLASS(saddr) || LOOPBACK(saddr) ||
	    skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	if (ZERONET(saddr)) {
		if (!LOCAL_MCAST(daddr))
			goto e_inval;
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	} else if (fib_validate_source(saddr, 0, tos, 0,
					dev, &spec_dst, &itag) < 0)
		goto e_inval;

	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	rth->fl.fl4_fwmark= skb->nfmark;
#endif
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= &loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif	= 0;
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	rth->rt_type	= RTN_MULTICAST;
	rth->rt_flags	= RTCF_MULTICAST;
	if (our) {
		rth->u.dst.input= ip_local_deliver;
		rth->rt_flags |= RTCF_LOCAL;
	}

#ifdef CONFIG_IP_MROUTE
	if (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
		rth->u.dst.input = ip_mr_input;
#endif
	RT_CACHE_STAT_INC(in_slow_mc);

	in_dev_put(in_dev);
	hash = rt_hash_code(daddr, saddr ^ (dev->ifindex << 5), tos);
	return rt_intern_hash(hash, rth, (struct rtable**) &skb->dst);

e_nobufs:
	in_dev_put(in_dev);
	return -ENOBUFS;

e_inval:
	in_dev_put(in_dev);
	return -EINVAL;
}

/*
 *	NOTE. We drop all the packets that has local source
 *	addresses, because every properly looped back packet
 *	must have correct destination already attached by output routine.
 *
 *	Such approach solves two big problems:
 *	1. Not simplex devices are handled properly.
 *	2. IP spoofing attempts are filtered with 100% of guarantee.
 */
/**
 * 输入选路。
 */
static int ip_route_input_slow(struct sk_buff *skb, u32 daddr, u32 saddr,
			u8 tos, struct net_device *dev)
{
	struct fib_result res;
	struct in_device *in_dev = in_dev_get(dev);
	struct in_device *out_dev = NULL;
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = daddr,
					.saddr = saddr,
					.tos = tos,
					.scope = RT_SCOPE_UNIVERSE,
#ifdef CONFIG_IP_ROUTE_FWMARK
					.fwmark = skb->nfmark
#endif
				      } },
			    .iif = dev->ifindex };
	unsigned	flags = 0;
	u32		itag = 0;
	struct rtable * rth;
	unsigned	hash;
	u32		spec_dst;
	int		err = -EINVAL;
	int		free_res = 0;

	/* IP on this device is disabled. */

	if (!in_dev)
		goto out;

	hash = rt_hash_code(daddr, saddr ^ (fl.iif << 5), tos);

	/* Check for the most weird martians, which can be not detected
	   by fib_lookup.
	 */
	/**
	 * 首先对源地址和目的地址进行一些合理性检查，例如源IP地址一定不能为多播地址。
	 */
	if (MULTICAST(saddr) || BADCLASS(saddr) || LOOPBACK(saddr))
		goto martian_source;

	/**
	 * 受限广播，受限广播地址由全1组成：255.255.255.255。
	 * 即使不调用fib_lookup也很容易识别出，受限广播被送给链路上的所有主机，与主机所配置的子网无关。不需要查找路由表。
	 */
	if (daddr == 0xFFFFFFFF || (saddr == 0 && daddr == 0))
		goto brd_input;

	/* Accept zero addresses only to limited broadcast;
	 * I even do not know to fix it or not. Waiting for complains :-)
	 */
	if (ZERONET(saddr))
		goto martian_source;

	if (BADCLASS(daddr) || ZERONET(daddr) || LOOPBACK(daddr))
		goto martian_destination;

	/*
	 *	Now we are ready to route packet.
	 */
	/**
	 * 查找路由表是由fib_lookup来完成
	 */
	if ((err = fib_lookup(&fl, &res)) != 0) {
		/**
		 * 如果接收接口被配置为使能转发，则向源地址回送一条ICMP_UNREACHABLE消息。
		 */
		if (!IN_DEV_FORWARD(in_dev))
			/**
			 * 该ICMP消息不是由ip_route_input_slow来送出的，而是由slow的调用方送出，当调用方看到返回值为RTN_UNREACHABLE时送出该ICMP消息。
			 */
			goto e_inval;
		/**
		 * 如果fib_lookup没有查找到一条匹配路由，则报文被丢弃。
		 */
		goto no_route;
	}
	free_res = 1;

	/**
	 * fib_lookup成功查找到匹配路由，先进行SNMP计数。
	 */
	RT_CACHE_STAT_INC(in_slow_tot);

	/**
	 * 报文目的地址为一个广播地址，报文被送往本地。
	 * 这里处理的不是受限广播，而是一个子网广播。
	 */
	if (res.type == RTN_BROADCAST)
		goto brd_input;

	/**
	 * 报文目的地址为一个本地地址
	 */
	if (res.type == RTN_LOCAL) {
		int result;
		/**
		 * 合理性检查，尤其是源地址。
		 * 再次检查源地址是否为非法值，并且通过fib_validate_source函数来检查spoofing企图。
		 */
		result = fib_validate_source(saddr, daddr, tos,
					     loopback_dev.ifindex,
					     dev, &spec_dst, &itag);
		if (result < 0)
			goto martian_source;
		if (result)
			flags |= RTCF_DIRECTSRC;
		/**
		 * 报文目的地址为本地地址时，报文被送往的本地地址为首选源地址
		 */
		spec_dst = daddr;
		goto local_input;
	}

	/**
	 * 如果报文需要被转发，但ingress设备配置为禁止转发，则该报文不能被发送而必须被丢弃。
	 * 利用IN_DEV_FORWARD检查设备的转发状态。
	 */
	if (!IN_DEV_FORWARD(in_dev))
		goto e_inval;
	if (res.type != RTN_UNICAST)
		goto martian_destination;

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/**
	 * 如果fib_lookup返回的匹配路由项有多个下一跳，调用fib_select_multipath来选择其中一个。
	 * 当支持多路径缓存特性时，有多种不同的选择方法。
	 */
	if (res.fi->fib_nhs > 1 && fl.oif == 0)
		fib_select_multipath(&fl, &res);
#endif
	out_dev = in_dev_get(FIB_RES_DEV(res));
	if (out_dev == NULL) {
		if (net_ratelimit())
			printk(KERN_CRIT "Bug in ip_route_input_slow(). "
					 "Please, report\n");
		goto e_inval;
	}

	/**
	 * 转发报文时，首选源地址由fib_validate_source来处理。
	 * 调用fib_validate_source来验证源地址。
	 */
	err = fib_validate_source(saddr, daddr, tos, FIB_RES_OIF(res), dev,
				  &spec_dst, &itag);
	if (err < 0)
		goto martian_source;

	/**
	 * 当ip_forward看到RTCF_DOREDIRECT标志后，向外发送该ICMP消息。
	 */
	if (err)
		flags |= RTCF_DIRECTSRC;

	if (out_dev == in_dev && err && !(flags & (RTCF_NAT | RTCF_MASQ)) &&
	    (IN_DEV_SHARED_MEDIA(out_dev) ||
	     inet_addr_onlink(out_dev, saddr, FIB_RES_GW(res))))
		flags |= RTCF_DOREDIRECT;

	if (skb->protocol != htons(ETH_P_IP)) {
		/* Not IP (i.e. ARP). Do not create route, if it is
		 * invalid for proxy arp. DNAT routes are always valid.
		 */
		if (out_dev == in_dev && !(flags & RTCF_DNAT))
			goto e_inval;
	}

	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	if (in_dev->cnf.no_xfrm)
		rth->u.dst.flags |= DST_NOXFRM;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	rth->fl.fl4_fwmark= skb->nfmark;
#endif
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
	rth->rt_gateway	= daddr;
	rth->rt_iif 	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= out_dev->dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif 	= 0;
	rth->rt_spec_dst= spec_dst;

	rth->u.dst.input = ip_forward;
	rth->u.dst.output = ip_output;

	rt_set_nexthop(rth, &res, itag);

	rth->rt_flags = flags;

intern:
	err = rt_intern_hash(hash, rth, (struct rtable**)&skb->dst);
done:
	in_dev_put(in_dev);
	if (out_dev)
		in_dev_put(out_dev);
	if (free_res)
		fib_res_put(&res);
out:	return err;

brd_input:
	/**
	 * ip_route_input_slow接受的广播报文只能由IP协议生成。
	 * 由于ip_route_input的输入缓冲参数不一定是需要被路由的报文，因此这里需要再次检查报文协议字段。
	 */
	if (skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	/**
	 * 当报文是广播报文时，广播地址不能被用作egress报文的首选源地址。ip_route_input_slow需要借助另外两个程序：inet_select_addr和fib_validate_source。
	 */
	if (ZERONET(saddr))
		/**
		 * 当接收报文内没有设置源IP地址（即为全零）时，inet_select_addr在接收该报文的设备上选择scope为RT_SCOPE_LINK的第一个地址。
		 * 这是因为报文源地址为空时目的地址为受限广播地址（limited broadcast address），而广播地址scope为RT_SCOPE_LINK。
		 * 其中一个例子为DHCP发现消息。
		 */
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	else {
		/**
		 * 当源地址不是全零时，由fib_validate_source来处理。
		 */
		err = fib_validate_source(saddr, 0, tos, 0, dev, &spec_dst,
					  &itag);
		if (err < 0)
			goto martian_source;
		if (err)
			flags |= RTCF_DIRECTSRC;
	}
	flags |= RTCF_BROADCAST;
	res.type = RTN_BROADCAST;
	/**
	 * 广播报文计数。
	 */
	RT_CACHE_STAT_INC(in_brd);

local_input:
	/**
	 * 创建和初始化一条新缓存表项（局部变量rth）
	 */
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	/**
	 * 使用输入参数来初始化fl，用做缓存查找的搜索key。
	 */
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	rth->fl.fl4_fwmark= skb->nfmark;
#endif
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= &loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->rt_gateway	= daddr;
	/**
	 * 首选源地址。用于ICMP和IP选项。
	 */
	rth->rt_spec_dst= spec_dst;
	rth->u.dst.input= ip_local_deliver;
	rth->rt_flags 	= flags|RTCF_LOCAL;
	if (res.type == RTN_UNREACHABLE) {
		rth->u.dst.input= ip_error;
		rth->u.dst.error= -err;
		rth->rt_flags 	&= ~RTCF_LOCAL;
	}
	rth->rt_type	= res.type;
	goto intern;

no_route:
	RT_CACHE_STAT_INC(in_no_route);
	spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
	res.type = RTN_UNREACHABLE;
	/**
	 * 当一个报文由于主机配置或是由于没有路由匹配而不能被路由时，一条新路由项被插入到缓存内，该路由的dst->input被初始化为ip_error。
	 * 因此，即使没有路由，也需要跳转到local_input，将路由缓存加入到缓存中。并由ip_error处理。
	 */
	goto local_input;

	/*
	 *	Do not cache martian addresses: they should be logged (RFC1812)
	 */
martian_destination:
	RT_CACHE_STAT_INC(in_martian_dst);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_WARNING "martian destination %u.%u.%u.%u from "
			"%u.%u.%u.%u, dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
#endif
e_inval:
	err = -EINVAL;
	goto done;

e_nobufs:
	err = -ENOBUFS;
	goto done;

martian_source:

	RT_CACHE_STAT_INC(in_martian_src);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit()) {
		/*
		 *	RFC1812 recommendation, if source is martian,
		 *	the only hint is MAC header.
		 */
		printk(KERN_WARNING "martian source %u.%u.%u.%u from "
			"%u.%u.%u.%u, on dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
		if (dev->hard_header_len) {
			int i;
			unsigned char *p = skb->mac.raw;
			printk(KERN_WARNING "ll header: ");
			for (i = 0; i < dev->hard_header_len; i++, p++) {
				printk("%02x", *p);
				if (i < (dev->hard_header_len - 1))
					printk(":");
			}
			printk("\n");
		}
	}
#endif
	goto e_inval;
}

/**
 * 用于入流量的路由查找，这些流量可能送往本地或被转发。
 * 这个函数决定如何来处理普通报文（是送往本地、还是转发、丢弃等），但它也被其它子系统用于确定如何来处理它们的入流量。
 * 例如，ARP使用该函数来判断是否应当对一个ARPOP_REQUEST作出应答
 *		skb:			触发路由查找的报文。这个报文本身可能不需要被路由。例如ARP出于某些原因使用ip_route_input来咨询local路由表，这时的skb应当是一个ingress ARP请求。
 * 		saddr,daddr:	用于查找的源地址和目的地址。
 *		tos:			ip报头中的TOS字段。
 *		dev:			接收该报文的设备。
 */
int ip_route_input(struct sk_buff *skb, u32 daddr, u32 saddr,
		   u8 tos, struct net_device *dev)
{
	struct rtable * rth;
	unsigned	hash;
	int iif = dev->ifindex;

	tos &= IPTOS_RT_MASK;
	/**
	 * ip_route_input首先根据输入条件选择应当包含该路由的哈希桶。
	 */
	hash = rt_hash_code(daddr, saddr ^ (iif << 5), tos);

	rcu_read_lock();
	/**
	 * 然后一个接一个遍历哈希桶链表中的路由项，比较所有必须的字段，直到查找到匹配或到链表尾部时还没有找到匹配。
	 */
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
	     rth = rcu_dereference(rth->u.rt_next)) {
		/**
		 * ip_route_input函数传递进来的输入参数被作为查找字段与路由缓存表项rtable中存储的fl字段相比较
		 */
		if (rth->fl.fl4_dst == daddr &&
		    rth->fl.fl4_src == saddr &&
		    rth->fl.iif == iif &&
		    rth->fl.oif == 0 &&
#ifdef CONFIG_IP_ROUTE_FWMARK
		    rth->fl.fl4_fwmark == skb->nfmark &&
#endif
		    rth->fl.fl4_tos == tos) {
			rth->u.dst.lastuse = jiffies;
			dst_hold(&rth->u.dst);
			rth->u.dst.__use++;
			RT_CACHE_STAT_INC(in_hit);
			rcu_read_unlock();
			skb->dst = (struct dst_entry*)rth;
			return 0;
		}
		/**
		 * 统计在桶中搜索的次数。
		 */
		RT_CACHE_STAT_INC(in_hlist_search);
	}
	rcu_read_unlock();

	/* Multicast recognition logic is moved from route cache to here.
	   The problem was that too many Ethernet cards have broken/missing
	   hardware multicast filters :-( As result the host on multicasting
	   network acquires a lot of useless route cache entries, sort of
	   SDR messages from all the world. Now we try to get rid of them.
	   Really, provided software IP multicast filter is organized
	   reasonably (at least, hashed), it does not result in a slowdown
	   comparing with route cache reject entries.
	   Note, that multicast routers are not affected, because
	   route cache entry is created eventually.
	 */
	/**
	 * 运行到这里，说明在缓存中查找已经失败。
	 * 首先判断报文目的地址是不是多播地址。
	 */
	if (MULTICAST(daddr)) {
		struct in_device *in_dev;

		rcu_read_lock();
		if ((in_dev = __in_dev_get(dev)) != NULL) {
			/**
			 * 通过ip_check_mc来检查目的地址是否为本地配置的多播地址。
			 */
			int our = ip_check_mc(in_dev, daddr, saddr,
				skb->nh.iph->protocol);
			if (our
#ifdef CONFIG_IP_MROUTE
				/**
				 * 目的地址不是本地配置，但内核编译时支持多播路由（CONFIG_IP_MROUTE）。
				 */
			    || (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
#endif
			    ) {
				rcu_read_unlock();
				/**
				 * 多播处理函数ip_route_input_mc。
				 */
				return ip_route_input_mc(skb, daddr, saddr,
							 tos, dev, our);
			}
		}
		/**
		 * 丢弃报文。
		 */
		rcu_read_unlock();
		return -EINVAL;
	}
	/**
	 * 如果在目的地址不是多播情况下缓存查找失败，ip_route_input调用ip_route_input_slow来查找路由表
	 */
	return ip_route_input_slow(skb, daddr, saddr, tos, dev);
}

/*
 * Major route resolver routine.
 */
/**
 * 出包选路。
 */
static int ip_route_output_slow(struct rtable **rp, const struct flowi *oldflp)
{
	/**
	 * 调用方可以将fl4_tos字段的两个最低位用于存储flags，ip_route_output_slow可以使用该flags来确定待搜索路由项的scope。
	 */
	u32 tos	= oldflp->fl4_tos & (IPTOS_RT_MASK | RTO_ONLINK);
	/**
	 * 初始化搜索key，该搜索key作为fib_lookup的参数用于路由表的查找。
	 * 该搜索key将与新的被缓存的路由项一起被保存起来，以用于后续的缓存查找。
	 */
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = oldflp->fl4_dst,	/* 源IP地址、目的IP地址和防火墙标记是直接从函数的输入参数拷贝而来。 */
					.saddr = oldflp->fl4_src,		/* 源IP地址、目的IP地址和防火墙标记是直接从函数的输入参数拷贝而来。 */
					.tos = tos & IPTOS_RT_MASK,		/* 后两位不是真正的TOS */
					.scope = ((tos & RTO_ONLINK) ?	/* 当RTO_ONLINK标志被设置时，设置待搜索的路由项的scope为RT_SCOPE_LINK；否则设置为RT_SCOPE_UNIVERSE。 */
						  RT_SCOPE_LINK :
						  RT_SCOPE_UNIVERSE),
#ifdef CONFIG_IP_ROUTE_FWMARK
					.fwmark = oldflp->fl4_fwmark	/* 源IP地址、目的IP地址和防火墙标记是直接从函数的输入参数拷贝而来。 */
#endif
				      } },
			    .iif = loopback_dev.ifindex,/* 因为调用ip_route_output_slow只是为了路由本地生成的流量，所以搜索key fl中的源设备被初始化为回环设备。 */
			    .oif = oldflp->oif };
	struct fib_result res;
	unsigned flags = 0;
	struct rtable *rth;
	struct net_device *dev_out = NULL;
	struct in_device *in_dev = NULL;
	unsigned hash;
	int free_res = 0;
	int err;

	res.fi		= NULL;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r		= NULL;
#endif

	/**
	 * 是否指定源IP地址。
	 */
	if (oldflp->fl4_src) {
		err = -EINVAL;
		/**
		 * 对源地址进行健康检查。
		 */
		if (MULTICAST(oldflp->fl4_src) ||
		    BADCLASS(oldflp->fl4_src) ||
		    ZERONET(oldflp->fl4_src))
			goto out;

		/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
		/**
		 * 查找源地址所在出设备。
		 */
		dev_out = ip_dev_find(oldflp->fl4_src);
		/**
		 * 目的设备不存在，退出。
		 */
		if (dev_out == NULL)
			goto out;

		/* I removed check for oif == dev_out->oif here.
		   It was wrong for two reasons:
		   1. ip_dev_find(saddr) can return wrong iface, if saddr is
		      assigned to multiple interfaces.
		   2. Moreover, we are allowed to send packets with saddr
		      of another iface. --ANK
		 */
		/**
		 * 目的地址是否为多播或者受限广播。
		 */
		if (oldflp->oif == 0
		    && (MULTICAST(oldflp->fl4_dst) || oldflp->fl4_dst == 0xFFFFFFFF)) {
			/* Special hack: user can direct multicasts
			   and limited broadcast via necessary interface
			   without fiddling with IP_MULTICAST_IF or IP_PKTINFO.
			   This hack is not just for fun, it allows
			   vic,vat and friends to work.
			   They bind socket to loopback, set ttl to zero
			   and expect that it will work.
			   From the viewpoint of routing cache they are broken,
			   because we are not allowed to build multicast path
			   with loopback source addr (look, routing cache
			   cannot know, that ttl is zero, so that packet
			   will not leave this host and route is valid).
			   Luckily, this hack is good workaround.
			 */
			/**
			 * 选择源地址对应的设备为出设备。
			 */
			fl.oif = dev_out->ifindex;
			/**
			 * 只提供了源地址，没有提供出设备，同时目的地址为广播地址，这种情况是由于使用诸如vic和vat等多媒体工具而引发的一个问题。
			 */
			goto make_route;
		}
		if (dev_out)
			dev_put(dev_out);
		dev_out = NULL;
	}
	/**
	 * 是否指定出设备。
	 */
	if (oldflp->oif) {
		dev_out = dev_get_by_index(oldflp->oif);
		err = -ENODEV;
		if (dev_out == NULL)
			goto out;
		if (__in_dev_get(dev_out) == NULL) {
			dev_put(dev_out);
			goto out;	/* Wrong error code */
		}

		/**
		 * 目的IP是否是本地多播或者限制广播。
		 */
		if (LOCAL_MCAST(oldflp->fl4_dst) || oldflp->fl4_dst == 0xFFFFFFFF) {
			/**
			 * 是否指定源IP
			 */
			if (!fl.fl4_src)
				/**
				 * 从OUT设备选择RT_SCOPE_LINK的源IP。
				 */
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			/**
			 * 这种情况下，路由子系统已经拥有路由该报文的所有信息，不需要查找路由了。
			 */
			goto make_route;
		}
		/**
		 * 不是广播，判断是否指定源IP。
		 */
		if (!fl.fl4_src) {
			/**
			 * 没有指定源IP，根据目的地址选择源IP。
			 */
			if (MULTICAST(oldflp->fl4_dst))
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      fl.fl4_scope);
			else if (!oldflp->fl4_dst)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_HOST);
		}
	}

	/**
	 * 没有指定目的IP。
	 * 报文目的地为未知地址，这些报文被送往本地，而不是被发送出去。
	 */
	if (!fl.fl4_dst) {
		/**
		 * 设置目的地址为源地址。
		 */
		fl.fl4_dst = fl.fl4_src;
		/**
		 * 没有源IP，则设置源和目的地址都为127.0.0.1。
		 */
		if (!fl.fl4_dst)
			fl.fl4_dst = fl.fl4_src = htonl(INADDR_LOOPBACK);
		if (dev_out)
			dev_put(dev_out);
		/**
		 * egress设备被设置为回环设备。这表示该报文不会离开本地主机，该报文被发送出后，将重新回到IP输入栈。
		 */
		dev_out = &loopback_dev;
		dev_hold(dev_out);
		fl.oif = loopback_dev.ifindex;
		res.type = RTN_LOCAL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

	if (fib_lookup(&fl, &res)) {/* 即使fib_lookup查找路由失败，但还是有可能成功地将报文发送出去。 */
		res.fi = NULL;
		/**
		 * 搜索key提供了egress设备，ip_route_output_slow假定通过该egress设备可以直接到达目的地。
		 */
		if (oldflp->oif) {
			/* Apparently, routing tables are wrong. Assume,
			   that the destination is on link.

			   WHY? DW.
			   Because we are allowed to send to iface
			   even if it has NO routes and NO assigned
			   addresses. When oif is specified, routing
			   tables are looked up with only one purpose:
			   to catch if destination is gatewayed, rather than
			   direct. Moreover, if MSG_DONTROUTE is set,
			   we send packet, ignoring both routing tables
			   and ifaddr state. --ANK


			   We could make it even if oif is unknown,
			   likely IPv6, but we do not.
			 */

			/**
			 * 如果还没有源IP地址，则还需要设置一个scope为RT_SCOPE_LINK的源IP地址，可能的情况下用的是该egress设备上的一个地址。
			 */
			if (fl.fl4_src == 0)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			res.type = RTN_UNICAST;
			goto make_route;
		}
		/**
		 * 没有提供出设备，路由查找也失败了，返回错误。
		 */
		if (dev_out)
			dev_put(dev_out);
		err = -ENETUNREACH;
		goto out;
	}
	free_res = 1;

	/**
	 * 报文被送往本地。
	 */
	if (res.type == RTN_LOCAL) {
		if (!fl.fl4_src)
			fl.fl4_src = fl.fl4_dst;
		if (dev_out)
			dev_put(dev_out);
		/**
		 * egress设备被设置为回环设备。这表示该报文不会离开本地主机，该报文被发送出后，将重新回到IP输入栈。
		 */
		dev_out = &loopback_dev;
		dev_hold(dev_out);
		fl.oif = dev_out->ifindex;
		if (res.fi)
			fib_info_put(res.fi);
		res.fi = NULL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

	/**
	 * 运行到这里，说明报文不是送往本地，而是发送给其他主机。
	 */
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/**
	 * 当查找返回的路由是一条多路径路由项时，需要选出下一跳。这由fib_select_multipath函数来执行。
	 */
	if (res.fi->fib_nhs > 1 && fl.oif == 0)/* 搜索key指定了要使用的egress设备（fl.oif）时，不需要调用fib_select_multipath */
		fib_select_multipath(&fl, &res);/* 注意:fib_select_multipath也能处理多路径路由。 */
	else
#endif
	/**
	 * 当查找返回的路由是缺省路由时，需要选择使用的缺省网关。这由fib_select_default函数来执行。
	 */
	if (!res.prefixlen && res.type == RTN_UNICAST && !fl.oif)/* 搜索key指定了要使用的egress设备（fl.oif）时，不需要调用fib_select_default */
		fib_select_default(&fl, &res);/* 注意:多路径也可用于缺省路由 */

	/**
	 * 根据路由确定源IP地址。
	 */
	if (!fl.fl4_src)
		/**
		 * FIB_RES_PREFSRC使用多种方法来选择首选源IP地址：如果用户为该路由项明确配置了首选源地址则返回它，否则用匹配路由的作用范围（res->scope）为输入参数，调用inet_select_addr来得到首选源IP地址。
		 */
		fl.fl4_src = FIB_RES_PREFSRC(res);

	if (dev_out)
		dev_put(dev_out);
	dev_out = FIB_RES_DEV(res);
	dev_hold(dev_out);
	fl.oif = dev_out->ifindex;

make_route:
	if (LOOPBACK(fl.fl4_src) && !(dev_out->flags&IFF_LOOPBACK))
		goto e_inval;

	if (fl.fl4_dst == 0xFFFFFFFF)
		res.type = RTN_BROADCAST;
	else if (MULTICAST(fl.fl4_dst))
		res.type = RTN_MULTICAST;
	else if (BADCLASS(fl.fl4_dst) || ZERONET(fl.fl4_dst))
		goto e_inval;

	if (dev_out->flags & IFF_LOOPBACK)
		flags |= RTCF_LOCAL;

	in_dev = in_dev_get(dev_out);
	if (!in_dev)
		goto e_inval;

	if (res.type == RTN_BROADCAST) {
		flags |= RTCF_BROADCAST | RTCF_LOCAL;
		if (res.fi) {
			fib_info_put(res.fi);
			res.fi = NULL;
		}
	} else if (res.type == RTN_MULTICAST) {
		flags |= RTCF_MULTICAST|RTCF_LOCAL;
		if (!ip_check_mc(in_dev, oldflp->fl4_dst, oldflp->fl4_src, oldflp->proto))
			flags &= ~RTCF_LOCAL;
		/* If multicast route do not exist use
		   default one, but do not gateway in this case.
		   Yes, it is hack.
		 */
		if (res.fi && res.prefixlen < 4) {
			fib_info_put(res.fi);
			res.fi = NULL;
		}
	}

	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (in_dev->cnf.no_xfrm)
		rth->u.dst.flags |= DST_NOXFRM;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= oldflp->fl4_dst;
	rth->fl.fl4_tos	= tos;
	rth->fl.fl4_src	= oldflp->fl4_src;
	rth->fl.oif	= oldflp->oif;
#ifdef CONFIG_IP_ROUTE_FWMARK
	rth->fl.fl4_fwmark= oldflp->fl4_fwmark;
#endif
	rth->rt_dst	= fl.fl4_dst;
	rth->rt_src	= fl.fl4_src;
	rth->rt_iif	= oldflp->oif ? : dev_out->ifindex;
	rth->u.dst.dev	= dev_out;
	dev_hold(dev_out);
	rth->idev	= in_dev_get(dev_out);
	rth->rt_gateway = fl.fl4_dst;
	rth->rt_spec_dst= fl.fl4_src;

	rth->u.dst.output=ip_output;

	RT_CACHE_STAT_INC(out_slow_tot);

	if (flags & RTCF_LOCAL) {
		/**
		 * dst->input被初始化为ip_local_deliver。
		 * 正是由于这一操作，当报文重新回到IP输入栈时，ip_rcv_finish调用dst_input，即调用ip_local_deliver函数来处理该报文。
		 */
		rth->u.dst.input = ip_local_deliver;
		rth->rt_spec_dst = fl.fl4_dst;
	}
	if (flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
		rth->rt_spec_dst = fl.fl4_src;
		if (flags & RTCF_LOCAL && !(dev_out->flags & IFF_LOOPBACK)) {
			rth->u.dst.output = ip_mc_output;
			RT_CACHE_STAT_INC(out_slow_mc);
		}
#ifdef CONFIG_IP_MROUTE
		if (res.type == RTN_MULTICAST) {
			if (IN_DEV_MFORWARD(in_dev) &&
			    !LOCAL_MCAST(oldflp->fl4_dst)) {
				rth->u.dst.input = ip_mr_input;
				rth->u.dst.output = ip_mc_output;
			}
		}
#endif
	}

	rt_set_nexthop(rth, &res, 0);
	

	rth->rt_flags = flags;

	hash = rt_hash_code(oldflp->fl4_dst, oldflp->fl4_src ^ (oldflp->oif << 5), tos);
	err = rt_intern_hash(hash, rth, rp);
done:
	if (free_res)
		fib_res_put(&res);
	if (dev_out)
		dev_put(dev_out);
	if (in_dev)
		in_dev_put(in_dev);
out:	return err;

e_inval:
	err = -EINVAL;
	goto done;
e_nobufs:
	err = -ENOBUFS;
	goto done;
}

/**
 * 出包路由查找。
 *		rp:		当程序返回成功时，*rp指向与搜索key flp相匹配的缓存表项。
 *		flp:	搜索key。
 */
int __ip_route_output_key(struct rtable **rp, const struct flowi *flp)
{
	unsigned hash;
	struct rtable *rth;

	hash = rt_hash_code(flp->fl4_dst, flp->fl4_src ^ (flp->oif << 5), flp->fl4_tos);

	rcu_read_lock_bh();
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		rth = rcu_dereference(rth->u.rt_next)) {
		if (rth->fl.fl4_dst == flp->fl4_dst &&
		    rth->fl.fl4_src == flp->fl4_src &&
		    rth->fl.iif == 0 &&
		    rth->fl.oif == flp->oif &&
#ifdef CONFIG_IP_ROUTE_FWMARK
		    rth->fl.fl4_fwmark == flp->fl4_fwmark &&
#endif
			/**
			 * egress缓存查找成功需要匹配RTO_ONLINK标志，检查该标志是否设置
			 * RTO_ONLINK标志指定搜索的路由类型的scope必须为RT_SCOPE_LINK
			 * 查找时的RTO_ONLINK标志可通过下面协议来设置：
			 * 		ARP:			当管理员手工配置一个ARP映射时，内核确保该IP地址是本地配置子网内的地址。
			 * 		Raw IP和UDP:	当通过一个套接字发送数据时，用户可以设置MSG_DONTROUTE标志。当应用程序从一个已知接口向直连目的地（不需要网关）发送报文时使用该标志，告诉内核不需要确定出设备。在路由协议和诊断应用程序中使用这种发送方式。
			 */
		    !((rth->fl.fl4_tos ^ flp->fl4_tos) & /* 路由缓存表项的TOS与搜索key中的TOS匹配。 */
			    (IPTOS_RT_MASK | RTO_ONLINK))) {/* 当路由缓存表项和搜索key都设置了RTO_ONLINK标志，或者都没有设置。 */
			rth->u.dst.lastuse = jiffies;
			dst_hold(&rth->u.dst);
			rth->u.dst.__use++;
			RT_CACHE_STAT_INC(out_hit);
			rcu_read_unlock_bh();
			*rp = rth;
			return 0;
		}
		RT_CACHE_STAT_INC(out_hlist_search);
	}
	rcu_read_unlock_bh();

	return ip_route_output_slow(rp, flp);
}

int ip_route_output_flow(struct rtable **rp, struct flowi *flp, struct sock *sk, int flags)
{
	int err;

	if ((err = __ip_route_output_key(rp, flp)) != 0)
		return err;

	if (flp->proto) {
		if (!flp->fl4_src)
			flp->fl4_src = (*rp)->rt_src;
		if (!flp->fl4_dst)
			flp->fl4_dst = (*rp)->rt_dst;
		return xfrm_lookup((struct dst_entry **)rp, flp, sk, flags);
	}

	return 0;
}

/**
 * 用于出流量的路由查找，这些流量是由本地生成，可能被送往本地或被发送出去。
 * 这两个函数的返回值包括：
 *		0:			路由查找成功。当缓存查找失败而触发路由表查找且成功时也返回0。
 *		-ENOBUF:	由于内存问题而使查找失败。
 * 		-ENODEV:	查找key包含了一个设备ID，但该设备ID无效。
 *		-EINVAL:	Generic查找失败。
 */
int ip_route_output_key(struct rtable **rp, struct flowi *flp)
{
	return ip_route_output_flow(rp, flp, NULL, 0);
}

static int rt_fill_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			int nowait)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	struct rtmsg *r;
	struct nlmsghdr  *nlh;
	unsigned char	 *b = skb->tail;
	struct rta_cacheinfo ci;
#ifdef CONFIG_IP_MROUTE
	struct rtattr *eptr;
#endif
	nlh = NLMSG_PUT(skb, pid, seq, event, sizeof(*r));
	r = NLMSG_DATA(nlh);
	nlh->nlmsg_flags = (nowait && pid) ? NLM_F_MULTI : 0;
	r->rtm_family	 = AF_INET;
	r->rtm_dst_len	= 32;
	r->rtm_src_len	= 0;
	r->rtm_tos	= rt->fl.fl4_tos;
	r->rtm_table	= RT_TABLE_MAIN;
	r->rtm_type	= rt->rt_type;
	r->rtm_scope	= RT_SCOPE_UNIVERSE;
	r->rtm_protocol = RTPROT_UNSPEC;
	r->rtm_flags	= (rt->rt_flags & ~0xFFFF) | RTM_F_CLONED;
	if (rt->rt_flags & RTCF_NOTIFY)
		r->rtm_flags |= RTM_F_NOTIFY;
	RTA_PUT(skb, RTA_DST, 4, &rt->rt_dst);
	if (rt->fl.fl4_src) {
		r->rtm_src_len = 32;
		RTA_PUT(skb, RTA_SRC, 4, &rt->fl.fl4_src);
	}
	if (rt->u.dst.dev)
		RTA_PUT(skb, RTA_OIF, sizeof(int), &rt->u.dst.dev->ifindex);
#ifdef CONFIG_NET_CLS_ROUTE
	if (rt->u.dst.tclassid)
		RTA_PUT(skb, RTA_FLOW, 4, &rt->u.dst.tclassid);
#endif
	if (rt->fl.iif)
		RTA_PUT(skb, RTA_PREFSRC, 4, &rt->rt_spec_dst);
	else if (rt->rt_src != rt->fl.fl4_src)
		RTA_PUT(skb, RTA_PREFSRC, 4, &rt->rt_src);
	if (rt->rt_dst != rt->rt_gateway)
		RTA_PUT(skb, RTA_GATEWAY, 4, &rt->rt_gateway);
	if (rtnetlink_put_metrics(skb, rt->u.dst.metrics) < 0)
		goto rtattr_failure;
	ci.rta_lastuse	= jiffies_to_clock_t(jiffies - rt->u.dst.lastuse);
	ci.rta_used	= rt->u.dst.__use;
	ci.rta_clntref	= atomic_read(&rt->u.dst.__refcnt);
	if (rt->u.dst.expires)
		ci.rta_expires = jiffies_to_clock_t(rt->u.dst.expires - jiffies);
	else
		ci.rta_expires = 0;
	ci.rta_error	= rt->u.dst.error;
	ci.rta_id	= ci.rta_ts = ci.rta_tsage = 0;
	if (rt->peer) {
		ci.rta_id = rt->peer->ip_id_count;
		if (rt->peer->tcp_ts_stamp) {
			ci.rta_ts = rt->peer->tcp_ts;
			ci.rta_tsage = xtime.tv_sec - rt->peer->tcp_ts_stamp;
		}
	}
#ifdef CONFIG_IP_MROUTE
	eptr = (struct rtattr*)skb->tail;
#endif
	RTA_PUT(skb, RTA_CACHEINFO, sizeof(ci), &ci);
	if (rt->fl.iif) {
#ifdef CONFIG_IP_MROUTE
		u32 dst = rt->rt_dst;

		if (MULTICAST(dst) && !LOCAL_MCAST(dst) &&
		    ipv4_devconf.mc_forwarding) {
			int err = ipmr_get_route(skb, r, nowait);
			if (err <= 0) {
				if (!nowait) {
					if (err == 0)
						return 0;
					goto nlmsg_failure;
				} else {
					if (err == -EMSGSIZE)
						goto nlmsg_failure;
					((struct rta_cacheinfo*)RTA_DATA(eptr))->rta_error = err;
				}
			}
		} else
#endif
			RTA_PUT(skb, RTA_IIF, sizeof(int), &rt->fl.iif);
	}

	nlh->nlmsg_len = skb->tail - b;
	return skb->len;

nlmsg_failure:
rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}

int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtattr **rta = arg;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	struct rtable *rt = NULL;
	u32 dst = 0;
	u32 src = 0;
	int iif = 0;
	int err = -ENOBUFS;
	struct sk_buff *skb;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		goto out;

	/* Reserve room for dummy headers, this skb can pass
	   through good chunk of routing engine.
	 */
	skb->mac.raw = skb->data;
	skb_reserve(skb, MAX_HEADER + sizeof(struct iphdr));

	if (rta[RTA_SRC - 1])
		memcpy(&src, RTA_DATA(rta[RTA_SRC - 1]), 4);
	if (rta[RTA_DST - 1])
		memcpy(&dst, RTA_DATA(rta[RTA_DST - 1]), 4);
	if (rta[RTA_IIF - 1])
		memcpy(&iif, RTA_DATA(rta[RTA_IIF - 1]), sizeof(int));

	if (iif) {
		struct net_device *dev = __dev_get_by_index(iif);
		err = -ENODEV;
		if (!dev)
			goto out_free;
		skb->protocol	= htons(ETH_P_IP);
		skb->dev	= dev;
		local_bh_disable();
		err = ip_route_input(skb, dst, src, rtm->rtm_tos, dev);
		local_bh_enable();
		rt = (struct rtable*)skb->dst;
		if (!err && rt->u.dst.error)
			err = -rt->u.dst.error;
	} else {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = dst,
							 .saddr = src,
							 .tos = rtm->rtm_tos } } };
		int oif = 0;
		if (rta[RTA_OIF - 1])
			memcpy(&oif, RTA_DATA(rta[RTA_OIF - 1]), sizeof(int));
		fl.oif = oif;
		err = ip_route_output_key(&rt, &fl);
	}
	if (err)
		goto out_free;

	skb->dst = &rt->u.dst;
	if (rtm->rtm_flags & RTM_F_NOTIFY)
		rt->rt_flags |= RTCF_NOTIFY;

	NETLINK_CB(skb).dst_pid = NETLINK_CB(in_skb).pid;

	err = rt_fill_info(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
				RTM_NEWROUTE, 0);
	if (!err)
		goto out_free;
	if (err < 0) {
		err = -EMSGSIZE;
		goto out_free;
	}

	err = netlink_unicast(rtnl, skb, NETLINK_CB(in_skb).pid, MSG_DONTWAIT);
	if (err > 0)
		err = 0;
out:	return err;

out_free:
	kfree_skb(skb);
	goto out;
}

int ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb)
{
	struct rtable *rt;
	int h, s_h;
	int idx, s_idx;

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];
	for (h = 0; h <= rt_hash_mask; h++) {
		if (h < s_h) continue;
		if (h > s_h)
			s_idx = 0;
		rcu_read_lock_bh();
		for (rt = rcu_dereference(rt_hash_table[h].chain), idx = 0; rt;
		     rt = rcu_dereference(rt->u.rt_next), idx++) {
			if (idx < s_idx)
				continue;
			skb->dst = dst_clone(&rt->u.dst);
			if (rt_fill_info(skb, NETLINK_CB(cb->skb).pid,
					 cb->nlh->nlmsg_seq,
					 RTM_NEWROUTE, 1) <= 0) {
				dst_release(xchg(&skb->dst, NULL));
				rcu_read_unlock_bh();
				goto done;
			}
			dst_release(xchg(&skb->dst, NULL));
		}
		rcu_read_unlock_bh();
	}

done:
	cb->args[0] = h;
	cb->args[1] = idx;
	return skb->len;
}

void ip_rt_multicast_event(struct in_device *in_dev)
{
	rt_cache_flush(0);
}

#ifdef CONFIG_SYSCTL
static int flush_delay;

static int ipv4_sysctl_rtcache_flush(ctl_table *ctl, int write,
					struct file *filp, void __user *buffer,
					size_t *lenp, loff_t *ppos)
{
	if (write) {
		proc_dointvec(ctl, write, filp, buffer, lenp, ppos);
		rt_cache_flush(flush_delay);
		return 0;
	} 

	return -EINVAL;
}

static int ipv4_sysctl_rtcache_flush_strategy(ctl_table *table,
						int __user *name,
						int nlen,
						void __user *oldval,
						size_t __user *oldlenp,
						void __user *newval,
						size_t newlen,
						void **context)
{
	int delay;
	if (newlen != sizeof(int))
		return -EINVAL;
	if (get_user(delay, (int __user *)newval))
		return -EFAULT; 
	rt_cache_flush(delay); 
	return 0;
}

ctl_table ipv4_route_table[] = {
        {
		.ctl_name 	= NET_IPV4_ROUTE_FLUSH,
		.procname	= "flush",
		.data		= &flush_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &ipv4_sysctl_rtcache_flush,
		.strategy	= &ipv4_sysctl_rtcache_flush_strategy,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_DELAY,
		.procname	= "min_delay",
		.data		= &ip_rt_min_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_DELAY,
		.procname	= "max_delay",
		.data		= &ip_rt_max_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_THRESH,
		.procname	= "gc_thresh",
		.data		= &ipv4_dst_ops.gc_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_SIZE,
		.procname	= "max_size",
		.data		= &ip_rt_max_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		/*  Deprecated. Use gc_min_interval_ms */
 
		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL,
		.procname	= "gc_min_interval",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS,
		.procname	= "gc_min_interval_ms",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_ms_jiffies,
		.strategy	= &sysctl_ms_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_TIMEOUT,
		.procname	= "gc_timeout",
		.data		= &ip_rt_gc_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_INTERVAL,
		.procname	= "gc_interval",
		.data		= &ip_rt_gc_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_LOAD,
		.procname	= "redirect_load",
		.data		= &ip_rt_redirect_load,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_NUMBER,
		.procname	= "redirect_number",
		.data		= &ip_rt_redirect_number,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_SILENCE,
		.procname	= "redirect_silence",
		.data		= &ip_rt_redirect_silence,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_COST,
		.procname	= "error_cost",
		.data		= &ip_rt_error_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_BURST,
		.procname	= "error_burst",
		.data		= &ip_rt_error_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_ELASTICITY,
		.procname	= "gc_elasticity",
		.data		= &ip_rt_gc_elasticity,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MTU_EXPIRES,
		.procname	= "mtu_expires",
		.data		= &ip_rt_mtu_expires,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_PMTU,
		.procname	= "min_pmtu",
		.data		= &ip_rt_min_pmtu,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_ADVMSS,
		.procname	= "min_adv_mss",
		.data		= &ip_rt_min_advmss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_SECRET_INTERVAL,
		.procname	= "secret_interval",
		.data		= &ip_rt_secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{ .ctl_name = 0 }
};
#endif

#ifdef CONFIG_NET_CLS_ROUTE
struct ip_rt_acct *ip_rt_acct;

/* This code sucks.  But you should have seen it before! --RR */

/* IP route accounting ptr for this logical cpu number. */
#define IP_RT_ACCT_CPU(i) (ip_rt_acct + i * 256)

#ifdef CONFIG_PROC_FS
static int ip_rt_acct_read(char *buffer, char **start, off_t offset,
			   int length, int *eof, void *data)
{
	unsigned int i;

	if ((offset & 3) || (length & 3))
		return -EIO;

	if (offset >= sizeof(struct ip_rt_acct) * 256) {
		*eof = 1;
		return 0;
	}

	if (offset + length >= sizeof(struct ip_rt_acct) * 256) {
		length = sizeof(struct ip_rt_acct) * 256 - offset;
		*eof = 1;
	}

	offset /= sizeof(u32);

	if (length > 0) {
		u32 *src = ((u32 *) IP_RT_ACCT_CPU(0)) + offset;
		u32 *dst = (u32 *) buffer;

		/* Copy first cpu. */
		*start = buffer;
		memcpy(dst, src, length);

		/* Add the other cpus in, one int at a time */
		for_each_cpu(i) {
			unsigned int j;

			src = ((u32 *) IP_RT_ACCT_CPU(i)) + offset;

			for (j = 0; j < length/4; j++)
				dst[j] += src[j];
		}
	}
	return length;
}
#endif /* CONFIG_PROC_FS */
#endif /* CONFIG_NET_CLS_ROUTE */

/**
 * 用户启动选项指定的路由缓存容量值。
 */
static __initdata unsigned long rhash_entries;
static int __init set_rhash_entries(char *str)
{
	if (!str)
		return 0;
	rhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("rhash_entries=", set_rhash_entries);

/**
 * Ipv4路由代码的初始化。
 * 系统启动时被初始化IP子系统的ip_init接口调用。
 * 策略路由的初始化是由fib_rules_init函数来实现。初始化就是简单为netdev_chain通知链注册处理钩子。注册的处理钩子为fib_rules_event。
 */
int __init ip_rt_init(void)
{
	int i, order, goal, rc = 0;

	/**
	 * 初始化一些数据结构和全局变量。
	 * rt_hash_rnd用于防止DoS攻击。系统启动后，会以get_random_bytes来重置该变量。
	 */
	rt_hash_rnd = (int) ((num_physpages ^ (num_physpages>>8)) ^
			     (jiffies ^ (jiffies >> 7)));

#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * 计算路由统计信息需要的内存。
	 */
	for (order = 0;
	     (PAGE_SIZE << order) < 256 * sizeof(struct ip_rt_acct) * NR_CPUS; order++)
		/* NOTHING */;
	/**
	 * 为路由统计信息分配页面。
	 */
	ip_rt_acct = (struct ip_rt_acct *)__get_free_pages(GFP_KERNEL, order);
	if (!ip_rt_acct)
		panic("IP: failed to allocate ip_rt_acct\n");
	memset(ip_rt_acct, 0, PAGE_SIZE << order);
#endif

	/**
	 * 创建用于分配路由缓存元素的内存池。
	 */
	ipv4_dst_ops.kmem_cachep = kmem_cache_create("ip_dst_cache",
						     sizeof(struct rtable),
						     0, SLAB_HWCACHE_ALIGN,
						     NULL, NULL);

	if (!ipv4_dst_ops.kmem_cachep)
		panic("IP: failed to allocate ip_dst_cache\n");

	goal = num_physpages >> (26 - PAGE_SHIFT);
	if (rhash_entries)
		goal = (rhash_entries * sizeof(struct rt_hash_bucket)) >> PAGE_SHIFT;
	for (order = 0; (1UL << order) < goal; order++)
		/* NOTHING */;

	/**
	 * 初始化路由缓存
	 */
	do {
		rt_hash_mask = (1UL << order) * PAGE_SIZE /
			sizeof(struct rt_hash_bucket);
		while (rt_hash_mask & (rt_hash_mask - 1))
			rt_hash_mask--;
		rt_hash_table = (struct rt_hash_bucket *)
			__get_free_pages(GFP_ATOMIC, order);
	} while (rt_hash_table == NULL && --order > 0);

	if (!rt_hash_table)
		panic("Failed to allocate IP route cache hash table\n");

	printk(KERN_INFO "IP: routing cache hash table of %u buckets, %ldKbytes\n",
	       rt_hash_mask,
	       (long) (rt_hash_mask * sizeof(struct rt_hash_bucket)) / 1024);

	for (rt_hash_log = 0; (1 << rt_hash_log) != rt_hash_mask; rt_hash_log++)
		/* NOTHING */;

	rt_hash_mask--;
	for (i = 0; i <= rt_hash_mask; i++) {
		spin_lock_init(&rt_hash_table[i].lock);
		rt_hash_table[i].chain = NULL;
	}

	/**
	 * 确定由垃圾回收算法使用的gc_thresh门限值
	 */
	ipv4_dst_ops.gc_thresh = (rt_hash_mask + 1);
	ip_rt_max_size = (rt_hash_mask + 1) * 16;

	rt_cache_stat = alloc_percpu(struct rt_cache_stat);
	if (!rt_cache_stat)
		return -ENOMEM;

	/**
	 * 为通知链netdev_chain注册另一个处理钩子，注册Netlink套接字上地址和路由命令（即ip addr ... 与ip route ..命令）的处理钩子函数，并创建/proc/sys/net/conf和/proc/sys/net/conf/default目录。
	 */
	devinet_init();
	/**
	 * 初始化缺省路由表，为两个通知链netdev_chain与inetaddr_chain分别注册处理钩子。
	 */
	ip_fib_init();

	init_timer(&rt_flush_timer);
	rt_flush_timer.function = rt_run_flush;
	init_timer(&rt_periodic_timer);
	rt_periodic_timer.function = rt_check_expire;
	init_timer(&rt_secret_timer);
	rt_secret_timer.function = rt_secret_rebuild;

	/* All the timers, started at system startup tend
	   to synchronize. Perturb it a bit.
	 */
	rt_periodic_timer.expires = jiffies + net_random() % ip_rt_gc_interval +
					ip_rt_gc_interval;
	/**
	 * 启动rt_periodic_timer定时器(垃圾回收)
	 */
	add_timer(&rt_periodic_timer);

	rt_secret_timer.expires = jiffies + net_random() % ip_rt_secret_interval +
		ip_rt_secret_interval;
	/**
	 * 启动rt_secret_timer定时器(Flush路由缓存)
	 */
	add_timer(&rt_secret_timer);

#ifdef CONFIG_PROC_FS
	/**
	 * 添加一些文件到/proc文件系统
	 */
	{
	struct proc_dir_entry *rtstat_pde = NULL; /* keep gcc happy */
	if (!proc_net_fops_create("rt_cache", S_IRUGO, &rt_cache_seq_fops) ||
	    !(rtstat_pde = create_proc_entry("rt_cache", S_IRUGO, 
			    		     proc_net_stat))) {
		free_percpu(rt_cache_stat);
		return -ENOMEM;
	}
	rtstat_pde->proc_fops = &rt_cpu_seq_fops;
	}
#ifdef CONFIG_NET_CLS_ROUTE
	create_proc_read_entry("rt_acct", 0, proc_net, ip_rt_acct_read, NULL);
#endif
#endif
#ifdef CONFIG_XFRM
	/**
	 * 如果内核编译时支持IPsec，那么ip_rt_init也调用两个IPsec初始化函数（xfrm_init与xfrm4_init）。
	 */
	xfrm_init();
	xfrm4_init();
#endif
	return rc;
}

EXPORT_SYMBOL(__ip_select_ident);
EXPORT_SYMBOL(ip_route_input);
EXPORT_SYMBOL(ip_route_output_key);
