/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP fragmentation functionality.
 *		
 * Version:	$Id: ip_fragment.c,v 1.59 2002/01/12 07:54:56 davem Exp $
 *
 * Authors:	Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox <Alan.Cox@linux.org>
 *
 * Fixes:
 *		Alan Cox	:	Split from ip.c , see ip_input.c for history.
 *		David S. Miller :	Begin massive cleanup...
 *		Andi Kleen	:	Add sysctls.
 *		xxxx		:	Overlapfrag bug.
 *		Ultima          :       ip_expire() kernel panic.
 *		Bill Hawes	:	Frag accounting and evictor fixes.
 *		John McDonald	:	0 length frag bug.
 *		Alexey Kuznetsov:	SMP races, threading, cleanup.
 *		Patrick McHardy :	LRU queue of frag heads for evictor.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>

/* NOTE. Logic of IP defragmentation is parallel to corresponding IPv6
 * code now. If you change something here, _PLEASE_ update ipv6/reassembly.c
 * as well. Or notify me, at least. --ANK
 */

/* Fragment cache limits. We will commit 256K at one time. Should we
 * cross that limit we will prune down to 192K. This should cope with
 * even the most extreme cases without allowing an attacker to measurably
 * harm machine performance.
 */
/**
 * 为了防止IP重组子系统滥用内存，对该内存的使用有强加限度，而且存储在sysctl_ipfrag_high_thresh变量中
 * 该变量的值可以在运行期间通过/proc文件系统而修改。
 */
int sysctl_ipfrag_high_thresh = 256*1024;
int sysctl_ipfrag_low_thresh = 192*1024;

/* Important NOTE! Fragment queue must be destroyed before MSL expires.
 * RFC791 is wrong proposing to prolongate timer each fragment arrival by TTL.
 */
/**
 * 传送进来的IP片段保留在内存内的最大时间值。
 */
int sysctl_ipfrag_time = IP_FRAG_TIME;

/**
 * 在IP重组时，缓存的IP片段在IP包中的位置。
 * 该结构保存在sk_buff的cb字段内。
 */
struct ipfrag_skb_cb
{
	/**
	 * IP选项和标志。
	 */
	struct inet_skb_parm	h;
	/**
	 * 片段在原IP包内的偏移量。
	 */
	int			offset;
};

/**
 * 读取skb->cb结构，在IP重组时，这返回的是IP片段在包中的位置信息。
 */
#define FRAG_CB(skb)	((struct ipfrag_skb_cb*)((skb)->cb))

/* Describe an entry in the "incomplete datagrams" queue. */
/**
 * IP包的分片集合。
 * 通过此结构，将同一IP报头的所有分片按顺序组织在一起。
 */
struct ipq {
	/**
	 * 当片段放进ipq_hash hash表时，冲突的元素（有相同hash值的元素）会用该字段连接起来。
	 * 注意，该字段没有指出片段在包内的次序。只是作为标准方式来组织hash表而已。
	 * 包内片段的次序是由fragments字段控制。
	 */
	struct ipq	*next;		/* linked list pointers			*/
	/**
	 * 所有ipq结构都会放在一个全局链表ipq_lru_list中，而排序的条件是根据最近最少使用的原则。
	 * 执行垃圾收集时，这个链表就有用。该字段可用于把ipq结构连接至这样一个链表。
	 */
	struct list_head lru_list;	/* lru list member 			*/
	/**
	 * 这是IP包为什么重组的原因。间接说出是哪个内核子系统要求重组。
	 * IP_DEFRAG_XXX容许值列表在include/net/ip.h中。最常见的值是IP_DEFRAG_LOCAL_DELIVER，当重组的入包要传给本地时，就会使用。
	 */
	u32		user;
	/**
	 * 这些参数代表来源地IP地址、目的IP地址、IP包ID、以及L4协议标识符。
	 * 这四个参数会指出片段所属的原有IP包。
	 * 因此，hash函数也会使用这些参数让元素能够在hash表中做最佳的分布。
	 */
	u32		saddr;
	u32		daddr;
	u16		id;
	u8		protocol;
	/**
	 * 存储三个标志
	 */
	u8		last_in;
/**
 * 所有片段都已经被接收，因此，可以连接起来获取原有IP包。
 * 该标志也可用于标示那些被选中要删除的ipq结构
 */
#define COMPLETE		4
/**
 * 片段中的第一个片段（offset=0的片段）已经接收到了。
 * 第一个片段就是唯一一个携带原有IP包中所有选项的片段。
 */
#define FIRST_IN		2
/**
 * 片段中最后一个片段（MF＝0的片段）已经接收到了。
 * 最后一个片段很重要，因为这个片段会告知我们原有IP包的尺寸。
 */
#define LAST_IN			1
	/**
	 * 是一个链表，内容是目前已经接收的片段。
	 */
	struct sk_buff	*fragments;	/* linked list of received fragments	*/
	/**
	 * 偏移量最大的的片段的结尾处的偏移量。
	 * 当最后一个片段（MF＝0的片段）已经接收时，len会指出原有IP包的尺寸。
	 */
	int		len;		/* total length of original datagram	*/
	/**
	 * 代表我们到目前为止接收了原有包多少字节。
	 */
	int		meat;
	/**
	 * 保护此结构以避免处于竞争条件下。
	 * 例如，不同IP片段由不同的NIC同时接收，而且由不同的CPU处理时，就会发生竞争情形。
	 */
	spinlock_t	lock;
	/**
	 * 计数器用于记录对该包的外部引用。
	 * 它的用途的例子如，timer定时器递增refcnt，来确保当定时器依然处于工作中时，没人可以释放ipq结构；
	 * 否则，该定时器可能会在过期时试着存取已不存在的数据结构。
	 */
	atomic_t	refcnt;
	/**
	 * IP片段不能永久存在内存中，而且当重组不可能时，一段时间后，就应该删除。
	 * 该字段就是处理此事的定时器。
	 */
	struct timer_list timer;	/* when will this queue expire?		*/
	/**
	 * 这个指针是指向链表头部，而该链表里的IP包都有相同的hash值。
	 */
	struct ipq	**pprev;
	/**
	 * 传送最后一个片段的设备的ID。当一个片段链表到期时，该字段可用于决定由哪一个设备传输ICMP消息。
	 */
	int		iif;
	/**
	 * 最后一个片段接收的时间
	 */
	struct timeval	stamp;
};

/* Hash table. */
/**
 * 接收到的IP片段被组织成一张hash，这是hash表的长度。
 */
#define IPQ_HASHSZ	64

/* Per-bucket lock is easy to add now. */
/**
 * 所有待重组的分片。
 */
static struct ipq *ipq_hash[IPQ_HASHSZ];
/**
 * 保护ipq_hash的读写自旋锁。
 */
static DEFINE_RWLOCK(ipfrag_lock);
static u32 ipfrag_hash_rnd;
/**
 * 所有待重组的ipq包链表。最近的包放在队尾。
 */
static LIST_HEAD(ipq_lru_list);
int ip_frag_nqueues = 0;

static __inline__ void __ipq_unlink(struct ipq *qp)
{
	if(qp->next)
		qp->next->pprev = qp->pprev;
	*qp->pprev = qp->next;
	list_del(&qp->lru_list);
	ip_frag_nqueues--;
}

static __inline__ void ipq_unlink(struct ipq *ipq)
{
	write_lock(&ipfrag_lock);
	__ipq_unlink(ipq);
	write_unlock(&ipfrag_lock);
}

static unsigned int ipqhashfn(u16 id, u32 saddr, u32 daddr, u8 prot)
{
	return jhash_3words((u32)id << 16 | prot, saddr, daddr,
			    ipfrag_hash_rnd) & (IPQ_HASHSZ - 1);
}

static struct timer_list ipfrag_secret_timer;
/**
 * 传送进来的IP片段从hash表中被抽出而又以不同hash函数重新插入的时间间隔。
 */
int sysctl_ipfrag_secret_interval = 10 * 60 * HZ;

/**
 * 为了防止DOS攻击，定期重新组织重组片段。
 */
static void ipfrag_secret_rebuild(unsigned long dummy)
{
	unsigned long now = jiffies;
	int i;

	write_lock(&ipfrag_lock);
	/**
	 * 产生一个随机数，然后将此值存储在全局变量ipfrag_hash_rnd中（由ipqhashfnhash函数使用）
	 */
	get_random_bytes(&ipfrag_hash_rnd, sizeof(u32));
	/**
	 * hash表内的每个元素会逐一解除，而它的hash值会用ipqhashfn重算（现在使用ipfrag_hash_rnd的新值）。最终重新插入到表中。
	 */
	for (i = 0; i < IPQ_HASHSZ; i++) {
		struct ipq *q;

		q = ipq_hash[i];
		while (q) {
			struct ipq *next = q->next;
			unsigned int hval = ipqhashfn(q->id, q->saddr,
						      q->daddr, q->protocol);

			if (hval != i) {
				/* Unlink. */
				if (q->next)
					q->next->pprev = q->pprev;
				*q->pprev = q->next;

				/* Relink to new hash chain. */
				if ((q->next = ipq_hash[hval]) != NULL)
					q->next->pprev = &q->next;
				ipq_hash[hval] = q;
				q->pprev = &ipq_hash[hval];
			}

			q = next;
		}
	}
	write_unlock(&ipfrag_lock);

	mod_timer(&ipfrag_secret_timer, now + sysctl_ipfrag_secret_interval);
}
/**
 * 全局变量ip_frag_mem代表当前由片段使用的内存。
 * 每次一个新片段加入ipq_hashhash表结构或从中删除时，其值就会被更新。
 * 当抵达系统限度时，就会调用ip_evictor来释放一些内存。
 */
atomic_t ip_frag_mem = ATOMIC_INIT(0);	/* Memory used for fragments */

/* Memory Tracking Functions. */
static __inline__ void frag_kfree_skb(struct sk_buff *skb, int *work)
{
	if (work)
		*work -= skb->truesize;
	atomic_sub(skb->truesize, &ip_frag_mem);
	kfree_skb(skb);
}

static __inline__ void frag_free_queue(struct ipq *qp, int *work)
{
	if (work)
		*work -= sizeof(struct ipq);
	atomic_sub(sizeof(struct ipq), &ip_frag_mem);
	kfree(qp);
}

static __inline__ struct ipq *frag_alloc_queue(void)
{
	struct ipq *qp = kmalloc(sizeof(struct ipq), GFP_ATOMIC);

	if(!qp)
		return NULL;
	atomic_add(sizeof(struct ipq), &ip_frag_mem);
	return qp;
}


/* Destruction primitives. */

/* Complete destruction of ipq. */
/**
 * 删除传进来的ipq结构以及其相关的所有IP片段，然后更新全局计数器ip_frag_mem。
 * 该函数是通过其封装函数ipq_put被调用的，而非直接调用。
 */
static void ip_frag_destroy(struct ipq *qp, int *work)
{
	struct sk_buff *fp;

	BUG_TRAP(qp->last_in&COMPLETE);
	BUG_TRAP(del_timer(&qp->timer) == 0);

	/* Release all fragment data. */
	fp = qp->fragments;
	while (fp) {
		struct sk_buff *xp = fp->next;

		frag_kfree_skb(fp, work);
		fp = xp;
	}

	/* Finally, release the queue descriptor itself. */
	frag_free_queue(qp, work);
}

/**
 * 递减传进来的ipq结构的引用计数值。如果没有其他用户对该结构进行引用，就用ip_frag_destroy将该结构及其片段删除掉。
 * 当work不为NULL时，将释放的内存数量被放置到这里。
 */
static __inline__ void ipq_put(struct ipq *ipq, int *work)
{
	if (atomic_dec_and_test(&ipq->refcnt))
		ip_frag_destroy(ipq, work);
}

/* Kill ipq entry. It is not destroyed immediately,
 * because caller (and someone more) holds reference count.
 */
/**
 * 把一个ipq结构标记为可删除，因为有些片段没有准时到达。
 */
static void ipq_kill(struct ipq *ipq)
{
	/**
	 * 此函数会在ip_expire调用，此时不会停止任何定时器，但是在其他情况下可能会停掉一个定时器。
	 */
	if (del_timer(&ipq->timer))
		atomic_dec(&ipq->refcnt);/* 在启动定时器时，为ipq增加了定时器，这种情况下，将它减回来。 */

	if (!(ipq->last_in & COMPLETE)) {
		ipq_unlink(ipq);
		atomic_dec(&ipq->refcnt);
		ipq->last_in |= COMPLETE;
	}
}

/* Memory limiting on fragments.  Evictor trashes the oldest 
 * fragment queue until we are back under the threshold.
 */
/**
 * 逐个删除不完整包的ipq结构。从最旧的入手，直到片段所用的内存降到sysctl_ipfrag_low_thresh值以下。
 */
static void ip_evictor(void)
{
	struct ipq *qp;
	struct list_head *tmp;
	int work;

	work = atomic_read(&ip_frag_mem) - sysctl_ipfrag_low_thresh;
	if (work <= 0)
		return;

	while (work > 0) {
		read_lock(&ipfrag_lock);
		if (list_empty(&ipq_lru_list)) {
			read_unlock(&ipfrag_lock);
			return;
		}
		tmp = ipq_lru_list.next;
		qp = list_entry(tmp, struct ipq, lru_list);
		atomic_inc(&qp->refcnt);
		read_unlock(&ipfrag_lock);

		spin_lock(&qp->lock);
		if (!(qp->last_in&COMPLETE))
			ipq_kill(qp);
		spin_unlock(&qp->lock);

		ipq_put(qp, &work);
		IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	}
}

/*
 * Oops, a fragment queue timed out.  Kill it and send an ICMP reply.
 */
/**
 * 当指定的时间到来时，如果重组的所有包还没有被收到，则丢弃该包。
 */
static void ip_expire(unsigned long arg)
{
	struct ipq *qp = (struct ipq *) arg;

	spin_lock(&qp->lock);

	/**
	 * 如果此时已经收完所有包，则退出。
	 * 或者如果已经有另外的地方已经在删除此结构，也退出。
	 */
	if (qp->last_in & COMPLETE)
		goto out;

	/**
	 * 标记ipq结构为删除状态。
	 * ipq_kill会通过调用ipq_unlink，来从ipq_hashhash表以及lru_list链表解除与ipq结构的链表。
	 */
	ipq_kill(qp);

	/**
	 * 更新SNMP计数器。
	 */
	IP_INC_STATS_BH(IPSTATS_MIB_REASMTIMEOUT);
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);

	/**
	 * ipq包含IP包的第一个片段，就传回一个ICMP_TIME_ECCEEDED消息给源主机。
	 * 本地主机必须接收了第一个片段，才可以传输ICMP消息，因为该消息必须在它的有效载荷中包含原有IP包的一部分，而且只有第一个片段才包含原有的IP的报头（未分段包的所有选项）以及所有或部分L4报头。
	 */
	if ((qp->last_in&FIRST_IN) && qp->fragments != NULL) {/* 如果 */
		struct sk_buff *head = qp->fragments;
		/* Send an ICMP "Fragment Reassembly Timeout" message. */
		/**
		 * 只有当接收最后一个片段的设备依然开启并运行，才会传送ICMP消息，因为该设备将极有可能用于传输ICMP消息。
		 */
		if ((head->dev = dev_get_by_index(qp->iif)) != NULL) {
			icmp_send(head, ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, 0);
			dev_put(head->dev);
		}
	}
out:
	spin_unlock(&qp->lock);
	ipq_put(qp, NULL);
}

/* Creation primitives. */

static struct ipq *ip_frag_intern(unsigned int hash, struct ipq *qp_in)
{
	struct ipq *qp;

	write_lock(&ipfrag_lock);
#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * promoted read lock to write lock.
	 */
	/**
 	 * 在SMP中，其他内核路径可能已经向hash表中增加irq对象了。
 	 */
	for(qp = ipq_hash[hash]; qp; qp = qp->next) {
		if(qp->id == qp_in->id		&&
		   qp->saddr == qp_in->saddr	&&
		   qp->daddr == qp_in->daddr	&&
		   qp->protocol == qp_in->protocol &&
		   qp->user == qp_in->user) {
			atomic_inc(&qp->refcnt);
			write_unlock(&ipfrag_lock);
			qp_in->last_in |= COMPLETE;
			/**
			 * 释放新分配的ipq对象，然后返回搜索到的对象。
			 */
			ipq_put(qp_in, NULL);
			return qp;
		}
	}
#endif
	qp = qp_in;

	/**
	 * 如果设置定时器成功，那么，为了避免定时器引用一个不存在的结构，这里需要将它的引用计数加1.
	 */
	if (!mod_timer(&qp->timer, jiffies + sysctl_ipfrag_time))
		atomic_inc(&qp->refcnt);

	/**
	 * 这里增加引用计数，是在写锁保护下，它代表了该结构被建立的事实。
	 */
	atomic_inc(&qp->refcnt);
	/**
	 * 将新ipq对象插入到桶中，作为桶中的第一个元素。
	 */
	if((qp->next = ipq_hash[hash]) != NULL)
		qp->next->pprev = &qp->next;
	ipq_hash[hash] = qp;
	qp->pprev = &ipq_hash[hash];
	INIT_LIST_HEAD(&qp->lru_list);
	/**
	 * 将新建立的ipq对象放到全局ipq_lru_list链表的尾部。
	 */
	list_add_tail(&qp->lru_list, &ipq_lru_list);
	/**
	 * ipq对象计数，这个计数与ipq_lru_list用于内存不足时，选择删除的ipq对象。
	 */
	ip_frag_nqueues++;
	write_unlock(&ipfrag_lock);
	return qp;
}

/* Add an entry to the 'ipq' queue for a newly received IP datagram. */
static struct ipq *ip_frag_create(unsigned hash, struct iphdr *iph, u32 user)
{
	struct ipq *qp;

	/**
	 * 为新包分配一个ipq对象。
	 */
	if ((qp = frag_alloc_queue()) == NULL)
		goto out_nomem;

	qp->protocol = iph->protocol;
	qp->last_in = 0;
	qp->id = iph->id;
	qp->saddr = iph->saddr;
	qp->daddr = iph->daddr;
	qp->user = user;
	qp->len = 0;
	qp->meat = 0;
	qp->fragments = NULL;
	qp->iif = 0;

	/* Initialize a timer for this entry. */
	/**
	 * 在新创建ipq对象时，为它初始化一个定时器。
	 * 这个定时器老化该ipq对象。
	 */
	init_timer(&qp->timer);
	qp->timer.data = (unsigned long) qp;	/* pointer to queue	*/
	qp->timer.function = ip_expire;		/* expire function	*/
	spin_lock_init(&qp->lock);
	atomic_set(&qp->refcnt, 1);

	/**
	 * 将新建立的ipq对象加入到hash表中。
	 */
	return ip_frag_intern(hash, qp);

out_nomem:
	NETDEBUG(if (net_ratelimit()) printk(KERN_ERR "ip_frag_create: no memory left !\n"));
	return NULL;
}

/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 */
/**
 * 找出和正在被处理的片段相关的包（片段链表）。
 * 查询是根据IP报送的4个字段：IP、源IP地址、目的IP地址以及L4协议。user参数指出重组的原因。
 */
static inline struct ipq *ip_find(struct iphdr *iph, u32 user)
{
	__u16 id = iph->id;
	__u32 saddr = iph->saddr;
	__u32 daddr = iph->daddr;
	__u8 protocol = iph->protocol;
	/**
	 * 计算分片的hash
	 */
	unsigned int hash = ipqhashfn(id, saddr, daddr, protocol);
	struct ipq *qp;

	read_lock(&ipfrag_lock);
	/**
	 * 在hash桶中搜索分片对应的包。
	 */
	for(qp = ipq_hash[hash]; qp; qp = qp->next) {
		if(qp->id == id		&&
		   qp->saddr == saddr	&&
		   qp->daddr == daddr	&&
		   qp->protocol == protocol &&
		   qp->user == user) {
			atomic_inc(&qp->refcnt);
			read_unlock(&ipfrag_lock);
			return qp;
		}
	}
	read_unlock(&ipfrag_lock);

	/**
	 * 没有在hash表中搜索到报文，则新建立一个。
	 */
	return ip_frag_create(hash, iph, user);
}

/* Add new segment to existing queue. */
/**
 * 把指定的片段插入和同一个IP包相关的片段链表（ipq结构）中。
 *		qp:		片段所属的IP包。
 *		skb:	要插入的新片段。
 */
static void ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	int flags, offset;
	int ihl, end;

	/**
	 * COMPLETE标志通常是在所有片段都接收后设定，但是在其他不寻常的情况下也会被设定。
	 * 如，当ipq_kill把一个ipq元素标记为死掉状态时。
	 * 这种情况下，不允许再接收包。
	 */
	if (qp->last_in & COMPLETE)
		goto err;

	/**
	 * 从报头中取出偏移量。
	 */
 	offset = ntohs(skb->nh.iph->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
 	ihl = skb->nh.iph->ihl * 4;

	/* Determine the position of this fragment. */
	/**
	 * end是片段在原始包中的位置。
	 */
 	end = offset + skb->len - ihl;

	/* Is this the final fragment? */
	/**
	 * 没有设置MF标志，表示是最后一个片段。
	 */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrrupted.
		 */
		/**
		 * 最后一个包的end值是包的总长度，如果与稍早前设置的长度不等的话，则说明有误。
		 */
		if (end < qp->len || /* qp->len是已经收到的包的最大长度，与本次收到的包的信息不一致。 */
		    ((qp->last_in & LAST_IN) && end != qp->len))/* 稍早前收到另外一个结尾包，并且与本次的结束地址不一致 */
			goto err;
		/**
		 * 设置标志，表示收到最后一个包。
		 */
		qp->last_in |= LAST_IN;
		qp->len = end;
	} else {
		/**
		 * 不是最后一个包，将包截断到8字节对齐。这本身是不正常的。
		 */
		if (end&7) {
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)/* 这种情况下必须使校验和失效。 */
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->len) {
			/* Some bits beyond end -> corruption. */
			if (qp->last_in & LAST_IN)/* 本次收到的包大于最后一个包指示的包长，明显是一种意外情况。 */
				goto err;
			/**
			 * 收到的包的最后的位置。
			 */
			qp->len = end;
		}
	}
	/**
	 * 有效负载一定不能为空，因为IP协议规定IP报头不能被分段。
	 */
	if (end == offset)
		goto err;

	/**
	 * 删除IP报头。
	 */
	if (pskb_pull(skb, ihl) == NULL)
		goto err;
	if (pskb_trim(skb, end-offset))
		goto err;

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment, right?
	 */
	prev = NULL;
	/**
	 * 包含在qp输入参数里的片段链表会保持排序结果，使得最低偏移量的片段放在链表头部。
	 * 因此，该函数现在必须找出应该把新片段加到链表何处。
	 */
	for(next = qp->fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)
			break;	/* bingo! */
		prev = next;
	}

	/* We found where to put this one.  Check for overlap with
	 * preceding fragment, and, if needed, align things so that
	 * any overlaps are eliminated.
	 */
	/**
	 * 如果新片段不必放到该链表头部（prev!=NULL），也就是我们至少已经接收到一个偏移量较小的片段，
	 * 那么，进行插入时就得把公共部分从重叠片段之一中删除。
	 */
	if (prev) {
		/**
		 * 求出重叠部分的尺寸，然后从新片段头部删除该尺寸大小的区块。
		 * 注意，下列程序中，重叠的存在是由i标志的
		 */
		int i = (FRAG_CB(prev)->offset + prev->len) - offset;

		/**
		 * 确实存在重叠。
		 */
		if (i > 0) {
			offset += i;
			/**
			 * 如果把偏移量往前移意味着片段的起始点比结束点还高，就表示新片段已完全包含在先前已收到的那些片段中，所以，此函数只要返回即可。
			 */
			if (end <= offset)
				goto err;
			/**
			 * 使用pskb_pull函数从新片段中把多余部分删除
			 */
			if (!pskb_pull(skb, i))
				goto err;
			/**
			 * 让硬件中所计算的L4校验和失效
			 */
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/**
	 * 处理过前面的片段后，此函数现在可以处理后续片段可能的重叠了。
	 */
	while (next && FRAG_CB(next)->offset < end) {/* 遍历后续的所有片段，找到所有offset小于当前片段结束点的片段。 */
		int i = end - FRAG_CB(next)->offset; /* overlap is 'i' bytes */

		/**
		 * 重叠部分的尺寸比新片段尺寸小.
		 */
		if (i < next->len) {
			/* Eat head of the next overlapped fragment
			 * and leave the loop. The next ones cannot overlap.
			 */
			/**
			 * 将后面的片段截断。
			 */
			if (!pskb_pull(next, i))
				goto err;
			/**
			 * 增加被截断片段的offset。并更新其meat值。
			 */
			FRAG_CB(next)->offset += i;
			qp->meat -= i;
			/**
			 * 使被截断片段的校验和失效。
			 */
			if (next->ip_summed != CHECKSUM_UNNECESSARY)
				next->ip_summed = CHECKSUM_NONE;
			/**
			 * 如果重叠部分的尺寸比新片段尺寸小，这表示该函数已抵达该链表的最后一个重叠片段
			 */
			break;
		} else {/* 与后面的片段完全重叠，将后面的片段删除。 */
			struct sk_buff *free_it = next;

			/* Old fragmnet is completely overridden with
			 * new one drop it.
			 */
			next = next->next;

			/**
			 * 将它从链表中删除（再次更新qp->meat）。如果被删除的片段是链表的头部，则头部指针必须被更新
			 */
			if (prev)
				prev->next = next;
			else
				qp->fragments = next;

			qp->meat -= free_it->len;
			frag_kfree_skb(free_it, NULL);
		}
	}

	FRAG_CB(skb)->offset = offset;

	/* Insert this fragment in the chain of fragments. */
	/**
	 * 将新片段插入到链表中。并更新qp的一些参数。
	 */
	skb->next = next;
	if (prev)
		prev->next = skb;
	else
		qp->fragments = skb;

 	if (skb->dev)
 		qp->iif = skb->dev->ifindex;
	skb->dev = NULL;
	qp->stamp = skb->stamp;
	qp->meat += skb->len;
	atomic_add(skb->truesize, &ip_frag_mem);
	if (offset == 0)
		qp->last_in |= FIRST_IN;

	write_lock(&ipfrag_lock);
	/**
	 * 将qp移到全局链表的尾部，以表示它最近被访问过。
	 */
	list_move_tail(&qp->lru_list, &ipq_lru_list);
	write_unlock(&ipfrag_lock);

	return;

err:
	kfree_skb(skb);
}


/* Build a new IP datagram from all its fragments. */
/**
 * 一旦所有片段都被接收到以后，就从这些片段构建原有IP包。
 */
static struct sk_buff *ip_frag_reasm(struct ipq *qp, struct net_device *dev)
{
	struct iphdr *iph;
	struct sk_buff *fp, *head = qp->fragments;
	int len;
	int ihlen;

	ipq_kill(qp);

	BUG_TRAP(head != NULL);
	BUG_TRAP(FRAG_CB(head)->offset == 0);

	/* Allocate a new buffer for the datagram. */
	ihlen = head->nh.iph->ihl*4;
	len = ihlen + qp->len;

	if(len > 65535)
		goto out_oversize;

	/* Head of list must not be cloned. */
	if (skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
		goto out_nomem;

	/* If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments. */
	if (skb_shinfo(head)->frag_list) {
		struct sk_buff *clone;
		int i, plen = 0;

		if ((clone = alloc_skb(0, GFP_ATOMIC)) == NULL)
			goto out_nomem;
		clone->next = head->next;
		head->next = clone;
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_shinfo(head)->frag_list = NULL;
		for (i=0; i<skb_shinfo(head)->nr_frags; i++)
			plen += skb_shinfo(head)->frags[i].size;
		clone->len = clone->data_len = head->data_len - plen;
		head->data_len -= clone->len;
		head->len -= clone->len;
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
		atomic_add(clone->truesize, &ip_frag_mem);
	}

	skb_shinfo(head)->frag_list = head->next;
	skb_push(head, head->data - head->nh.raw);
	atomic_sub(head->truesize, &ip_frag_mem);

	for (fp=head->next; fp; fp = fp->next) {
		head->data_len += fp->len;
		head->len += fp->len;
		if (head->ip_summed != fp->ip_summed)
			head->ip_summed = CHECKSUM_NONE;
		else if (head->ip_summed == CHECKSUM_HW)
			head->csum = csum_add(head->csum, fp->csum);
		head->truesize += fp->truesize;
		atomic_sub(fp->truesize, &ip_frag_mem);
	}

	head->next = NULL;
	head->dev = dev;
	head->stamp = qp->stamp;

	iph = head->nh.iph;
	iph->frag_off = 0;
	iph->tot_len = htons(len);
	IP_INC_STATS_BH(IPSTATS_MIB_REASMOKS);
	qp->fragments = NULL;
	return head;

out_nomem:
 	NETDEBUG(if (net_ratelimit())
	         printk(KERN_ERR 
			"IP: queue_glue: no memory for gluing queue %p\n",
			qp));
	goto out_fail;
out_oversize:
	if (net_ratelimit())
		printk(KERN_INFO
			"Oversized IP packet from %d.%d.%d.%d.\n",
			NIPQUAD(qp->saddr));
out_fail:
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	return NULL;
}

/* Process an incoming IP datagram fragment. */
/**
 * IP重组的主函数。
 * 当最后一个片段已经找到，并且包已经完全接收时，函数返回成功。
 *		skb:		待重组的包。
 *		user:		请求重组的原因。
 */
struct sk_buff *ip_defrag(struct sk_buff *skb, u32 user)
{
	struct iphdr *iph = skb->nh.iph;
	struct ipq *qp;
	struct net_device *dev;
	
	IP_INC_STATS_BH(IPSTATS_MIB_REASMREQDS);

	/* Start by cleaning up the memory. */
	/**
	 * 如果ipq对象所用的内存已经超过阀值，则调用ip_evictor清理一些内存。
	 */
	if (atomic_read(&ip_frag_mem) > sysctl_ipfrag_high_thresh)
		ip_evictor();

	dev = skb->dev;

	/* Lookup (or create) queue header */
	/**
	 * ip_find会创建一个新的ipq结构，或者从hash表中找到一个ipq对象。
	 */
	if ((qp = ip_find(iph, user)) != NULL) {
		struct sk_buff *ret = NULL;

		spin_lock(&qp->lock);

		/**
		 * 将片段加入到ipq队列中。
		 */
		ip_frag_queue(qp, skb);

		/**
		 * 第一个和最后一个片段都已经接收，而且片段总长度等于原有IP包的尺寸。
		 */
		if (qp->last_in == (FIRST_IN|LAST_IN) &&
		    qp->meat == qp->len)
			ret = ip_frag_reasm(qp, dev);/* 将这些片段联结起来获得原有的包，并将包传递给较高层。 */

		spin_unlock(&qp->lock);
		ipq_put(qp, NULL);
		return ret;
	}

	/**
	 * 没有内存了，计数并释放skb.
	 */
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	kfree_skb(skb);
	return NULL;
}

/**
 * 分片、重组初始化。
 */
void ipfrag_init(void)
{
	/**
	 * 初始化一个随机种子。用于分片hash表。
	 * 主要目的是为了防止DoS攻击。
	 */
	ipfrag_hash_rnd = (u32) ((num_physpages ^ (num_physpages>>7)) ^
				 (jiffies ^ (jiffies >> 6)));

	/**
	 * 初始化定时器。这个定时器用于销毁超时的分片。避免受到DoS攻击。
	 */
	init_timer(&ipfrag_secret_timer);
	ipfrag_secret_timer.function = ipfrag_secret_rebuild;
	ipfrag_secret_timer.expires = jiffies + sysctl_ipfrag_secret_interval;
	add_timer(&ipfrag_secret_timer);
}

EXPORT_SYMBOL(ip_defrag);
