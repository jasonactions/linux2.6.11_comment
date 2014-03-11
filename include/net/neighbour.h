#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

/* The following flags & states are exported to user space,
   so that they should be moved to include/linux/ directory.
 */

/*
 *	Neighbor Cache Entry Flags
 */

#define NTF_PROXY	0x08	/* == ATF_PUBL */
#define NTF_ROUTER	0x80

/*
 *	Neighbor Cache Entry States.
 */
/**
 * 诱发请求已经发送，但是尚未收到响应时所处的状态。在这个状态下，不可以使用任何硬件地址.
 */
#define NUD_INCOMPLETE	0x01
/**
 * 邻居地址被缓存，并且最近已知是可达的
 */
#define NUD_REACHABLE	0x02
/**
 * 这几个是迁移的中间状态；当本地主机判断邻居是否可达的过程中设置这些状态。
 */
#define NUD_STALE	0x04
#define NUD_DELAY	0x08
#define NUD_PROBE	0x10
/**
 * 由于诱发请求失败而标记邻居是不可达状态。包括创建条目时生成的和由NUD_PROBE触发的诱发请求失败。
 */
#define NUD_FAILED	0x20

/* Dummy states */
/**
 * 这个状态用于标记邻居不需要任何协议来解析L3层到L2层的地址映射转换
 */
#define NUD_NOARP	0x40
/**
 * L2层邻居地址被静态配置时的状态置(如用户空间命令配置)，所以不需要任何邻居协议考虑它。
 */
#define NUD_PERMANENT	0x80
/**
 * 表示邻居条目被创建，但目前尚不可用。
 */
#define NUD_NONE	0x00

/* NUD_NOARP & NUD_PERMANENT are pseudostates, they never change
   and make no address resolution or NUD.
   NUD_PERMANENT is also cannot be deleted by garbage collectors.
 */

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>

/**
 * 表示邻居子系统为邻居条目提供了一个正在运行的定时器，这发生在在邻居条目状态不确定时。
 * 符合这个状态的基本状态是：NUD_INCOMPLETE、NUD_DELAY、NUD_PROBE
 */
#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
/**
 * 如果一个邻居条目的状态是下述几个状态中的一个，则可以认定它是NUD_VALID状态。
 * 这表明邻居确信现在有一个可用地址。即：NUD_PERMANENT、NUD_NOARP、NUD_REACHABLE、NUD_PROBE、NUD_STALE、NUD_DELAY
 */
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
/**
 * 这个状态是NUD_VALID的子集，表明没有未决的确认处理.
 * 即如下几个状态都表示处在NUD_CONNECTED状态：NUD_PERMANENT、NUD_NOARP、NUD_REACHABLE
 */
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

/**
 * 对每个设备上邻居协议行为进行调整的一组参数。
 * 由于在大部分接口上可以启动多个协议（如IPV4和IPV6），所以一个net_device结构可以关联多个neigh_parms结构。
 */
struct neigh_parms
{
	/**
	 * 链接到和同一个协议簇关联的neigh_parms实例的指针。意思就是说每个neigh_table结构都有它自己的neigh_parms结构列表，每个实例对应于一个配置的设备。
	 */
	struct neigh_parms *next;
	/**
	 * 对于仍然使用旧邻居基础结构的设备，主要使用这个函数来初始化。
	 * 通常，该函数只用于将neighbour->ops初始化为arp_broken_ops。
	 */
	int	(*neigh_setup)(struct neighbour *);
	/**
	 * 回溯指针，指向持有该结构的neigh_table结构。
	 */
	struct neigh_table *tbl;
	int	entries;
	/**
	 * 暂不使用。
	 */
	void	*priv;

	/**
	 * 这个表在net/ipv4/neighbour.c文件中的结尾的程序中完成初始化。它与允许用户修改neigh_parms结构中的某些参数的值有关。
	 */
	void	*sysctl_table;

	/**
	 * 这是一个布尔标识，设置后表示该邻居实例可以"被删除"。
	 */
	int dead;
	/**
	 * 引用计数。
	 */
	atomic_t refcnt;
	/**
	 * 负责管理互斥。
	 */
	struct rcu_head rcu_head;

	/**
	 * base_reachable_time是一个时间间隔（用jiffies表示），表示自从最近一次收到可到达性证明后经过的时间。
	 * 注意，这个间隔是用于计算实际时间的一个基本值。实际时间保存在reachable_time中。
	 * 实际时间是base_reachable_time和3/2base_reachable_time之间的一个随机值（均匀分布）。
	 * 这个随机值每300秒由neigh_periodic_timer更新一次，但它也可以由其他事件更新。
	 */
	int	base_reachable_time;
	/**
	 * 当一台主机在retrans_time时间内没有收到solicitation请求的应答时，就会发出一个新的solicitation请求，一直尝试次数到达最大值。
	 * retrans_time也是用jiffies表示。
	 */
	int	retrans_time;
	/**
	 * 如果一个neighbour结构在gc_staletime时间内还没有被使用过，并且没有程序引用它，那么它就会被删除。
	 * gc_staletime是用jiffies表示的。
	 */
	int	gc_staletime;
	int	reachable_time;
	/**
	 * 这个变量表明在一个邻居在进入NUD_PROBE态前，在NUD_DELAY态等待多长时间。
	 */
	int	delay_probe_time;

	/**
	 * arp_queue队列中能容纳的元素的最大数目。
	 */
	int	queue_len;
	/**
	 * ucast_probes表示为了证实一个地址的可到达性，能发送的单播solicitations数量。
	 */
	int	ucast_probes;
	/**
	 * app_probes是用户空间程序在解析一个地址时，可以发送的solicitations的数量。
	 */
	int	app_probes;
	/**
	 * mcast_probes表示为了解析一个邻居地址，可以发出的多播solicitation的数量。
	 * 对ARP/IPV4来说，这实际就是广播solicitation的数目，因为ARP不使用多播solicitation，但是IPV6要使用多播。
	 */
	int	mcast_probes;
	/**
	 * 暂不使用。
	 */
	int	anycast_delay;
	/**
	 * 邻居协议包在代理处理前，在代理队列中应该保存的时间。
	 * 代理延迟时间。实际的延迟时间介于0到proxy_delay之间。
	 * 随机数的使用可以降低多个主机同时发出请求，并导致拥塞的可能性。
	 */
	int	proxy_delay;
	/**
	 * 临时存储队列的最大长度。
	 * proxy_queue队列中能容纳的元素的最大数目。
	 */
	int	proxy_qlen;
	/**
	 * 锁定期，当收到第一个ARPOP_REPLY时，如果针对同一个ARPOP_REQUEST的第二个ARPOP_REPLY在locktime内的时间到达，则第二个包会被忽略。
	 */
	int	locktime;
};

/**
 * 邻居协议的统计数据。
 */
struct neigh_statistics
{
	/**
 	 * 邻居协议分配的neighbour结构的总量。包括那些已经被删除的neighbour结构。
 	 */
	unsigned long allocs;		/* number of allocated neighs */
	/**
	 * 删除的neighbour项的数目。由neigh_destroy函数负责更新。
	 */
	unsigned long destroys;		/* number of destroyed neighs */
	/**
	 * hash表容量增加的次数。由neigh_hash_grow函数负责更新。
	 */
	unsigned long hash_grows;	/* number of hash resizes */

	/**
	 * 解析一个邻居地址识别后尝试的次数。每次送出一个新的solicitation包，不会增加这个值；只有当所有的尝试失败后，才会由neigh_timer_handler函数将该值递增。
	 */
	unsigned long res_failed;	/* nomber of failed resolutions */

	/**
	 * 调用neigh_lookup函数的次数。
	 */
	unsigned long lookups;		/* number of lookups */
	/**
	 * neigh_lookup函数查询成功的次数。
	 */
	unsigned long hits;		/* number of hits (among lookups) */

	/**
	 * 这两个字段只有IPV6使用，表示收到的solicitation请求的数量。两个字段分别表示多播地址和单播地址请求。
	 */
	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	/**
	 * neigh_periodic_timer和neigh_forced_gc各自被调用的次数。
	 */
	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

/**
 * 存储邻居的有关信息，例如，L2和L3地址、NUD状态、访问该邻居经过的设备等。
 * 一个neighbour项不是与一台主机有关，而是与一个L3地址有关。
 */
struct neighbour
{
	/**
	 * 每个neighbour项都插入到一个hash表中。Next指向另一个neighbour结构，这个结构与当前结构冲突且共享同一个bucket。
	 * 新元素总是插入到bucket列表的表头。
	 */
	struct neighbour	*next;
	/**
	 * 指向neigh_table结构的指针，这个结构定义了与当前邻居项有关的协议。
	 * 例如，如果邻居使用一个IPV4地址，tbl就指向arp_tbl结构。
	 */
	struct neigh_table	*tbl;
	/**
	 * 用于调整邻居协议行为的参数。当建立一个neighbour结构时，用嵌入到和协议相关的neigh_table结构中的neigh_parms结构的默认值初始化parms。
	 */
	struct neigh_parms	*parms;
	/**
	 * 通过这个设备，可以访问该邻居。每个邻居只能通过一个设备来访问。
	 * 该值不能为NULL，因为在其他内核子系统中，NULL值表示通配符，表示所有设备。
	 */
	struct net_device		*dev;
	/**
	 * 邻居项最近一次被使用的时间。这个值不会随着数据传输而同步更新。
	 * 当该邻居项还没有到NUD_CONNECTED态时，这个字段由neigh_resolve_ouput函数调用neigh_event_send来更新。
	 * 相应的，当邻居项进入NUD_CONNECTED态时，它的值由neigh_periodic_timer更新为该邻居项的可到达性最近被证实的时间。
	 */
	unsigned long		used;
	/**
	 * 时间戳（用jiffies表示）表示该邻居的可到达性最后验证过的时间。
	 * L4协议用neigh_confirm函数更新这个值。邻居基础协议用neigh_update更新它。
	 */
	unsigned long		confirmed;
	/**
	 * 邻居项更新时间，防止多次收到ARPOP_REPLY时，进行重复处理。
	 * 一个时间戳，表示neigh_update函数最近一次更新该邻居的时间（首次初始化时是由neigh_alloc函数设置）。
	 * 不要将updated和confirmed混淆，这两个字段表示不同的事件。
	 * 当邻居的状态改变时，要设置updated字段；而confirmed字段只记录邻居特殊的一次状态改变：当邻居最近一次证明是有效时，发生的状态改变。
	 */
	unsigned long		updated;
	/**
	 * 这个字段的可选值在include/linux/rtnetlink.h和include/net/neighbour.h中：
	 */
	__u8			flags;
	/**
	 * 指示邻居项的状态。可能的取值以NUD_XXX形式命名，它定义在include/net/neighbour.h和include/linux/rtnetlink.h中。
	 */
	__u8			nud_state;
	/**
	 * 当neigh_create函数调用协议的constructor方法创建邻居项时，就会设置这个字段。
	 * 它的值可以用于各种场合，例如，决定哪些值可以赋给nud_state。
	 */
	__u8			type;
	/**
	 * 如果dead被设为1，表示该结构将被删除，不能再使用了。
	 */
	__u8			dead;
	/**
	 * 失败的solicitation尝试的次数。它的值由neigh_timer_handler定时器检测。当尝试次数到达允许的最大值时，这个定时器就将该neighbour项转移到NUD_FAILED态。
	 */
	atomic_t		probes;
	/**
	 * 用于在出现竞争时对neighbour结构进行保护。
	 */
	rwlock_t		lock;
	/**
	 * 与primiary_key表示的L3地址关联的L2地址（如ethernet NIC的Ethernet MAC地址）。这个地址是二进制格式。向量ha的长度是MAX_ADDR_LEN（32），向上舍入到C语言long类型的一倍。
	 */
	unsigned char		ha[(MAX_ADDR_LEN+sizeof(unsigned long)-1)&~(sizeof(unsigned long)-1)];
	/**
	 * 缓存的L2帧头列表。
	 */
	struct hh_cache		*hh;
	/**
	 * 引用计数。
	 */
	atomic_t		refcnt;
	/**
	 * 用于向邻居发送帧的函数。根据一些因素，这个函数指针实际指向的函数在该结构的生存期内可以改变多次。
	 * 当邻居项的状态为NUD_REACHABLE态或NUD_STALE态时，可以分别通过调用neigh_connect和neigh_suspect函数更新该字段的值。
	 */
	int			(*output)(struct sk_buff *skb);
	/**
	 * 目的L3地址还没有被解析的包被临时放到这个队列中。不要管这个队列的名称，它能被所有邻居协议使用，不只是ARP。
	 *
	 * 当发送一个数据包时，如果目的L3地址和L2地址之间的关联还没有建立，邻居协议将该包临时插到arp_queue队列中
	 * 通常只有三个元素，多余的元素会将旧元素替换。
	 * 也可能设置成设备公共此队列。
	 */
	struct sk_buff_head	arp_queue;
	/**
	 * 用于处理几个任务的定时器。
	 */
	struct timer_list	timer;
	/**
	 * VFT中包含的各种方法，它们用于维护neighbour项。
	 */
	struct neigh_ops	*ops;
	/**
	 * 该邻居的L3地址。它作为缓存查找的关键字。对ARP项来说，它是一个IPV4地址。对ND来说，它是一个IPV6地址。
	 */
	u8			primary_key[0];
};

/**
 * 一组函数，用来表示L3协议（如IP）和dev_queue_xmit之间的接口。
 * 这些虚拟函数可以根据它们使用的上下文环境来改变。
 */
struct neigh_ops
{
	/**
	 * 地址簇。
	 */
	int			family;
	/**
	 * 当一个neighbour项要被neigh_destroy删除时，就执行该函数。
	 * 它基本上是neigh_table->constructor方法的互补方法。但由于某些原因，contructor位于neigh_table结构中，而destructor位于neigh_ops结构中。
	 */
	void			(*destructor)(struct neighbour *);
	/**
	 * 发送solicitation请求的函数。
	 */
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	/**
	 * 当一个邻居被认为不可到达时，要调用这个函数。
	 */
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	/**
	 * 这个是最普通的函数，用于所有的情况下。它会检查地址是否已经被解析过。
	 * 在没有被解析的情况下，它会启动解析程序。如果地址还没有准备好，它会把包保存在一个临时队列中，并启动解析程序。
	 * 由于该函数为了保证接收方是可到达的，它会做每件必要的事情，因此它相对来说需要的操作比较多。
	 * 不要将neigh_ops->output和neighbour->output相混淆。
	 */
	int			(*output)(struct sk_buff*);
	/**
	 * 当已经知道邻居是可到达时（邻居状态为NUD_CONNECTED态），使用该函数。因为使用需要的信息都是满足的，该函数只要简单填充一下L2帧头，因此它比output速度要快。
	 */
	int			(*connected_output)(struct sk_buff*);
	/**
	 * 当地址已被解析过，并且整个包头已经根据上一次传输结构放入帧头缓存时，就使用这个函数。
	 */
	int			(*hh_output)(struct sk_buff*);
	/**
	 * 前面的函数中，除了hh_output外，都不会实际传输包。它们所做的工作都是确保包头是编写好的，然后当缓冲区准备好时，调用queue_xmit方法来传输。
	 */
	int			(*queue_xmit)(struct sk_buff*);
};

/**
 * 基于目的地址的代理。
 */
struct pneigh_entry
{
	struct pneigh_entry	*next;
	struct net_device		*dev;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

/**
 * 描述一种邻居协议的参数和所用函数。每个邻居协议都有该结构的一个实例。
 * 所有实例都插入到一个由静态变量neigh_tables指向的一个全局表中，并由neight_tbl_lock来加以保护。该锁只会保护全局表的完整性，并不对表中每个条目的内容进行保护。
 */
struct neigh_table
{
	/**
	 * 将所有的协议表链接到一个链表中。
	 */
	struct neigh_table	*next;
	/**
	 * 邻居协议所表示的邻居项的地址簇。
	 * 它的可能取值位于include/linux/socket.h文件中，名称都是AF_XXX的形式。
	 * 对于IPV4和IPV6，对应的值分别是AF_INET和AF_INET6。
	 */
	int			family;
	/**
	 * 插入到缓存中的数据结构的长度。由于一个neighbour结构包含一个字段，它的长度与具体的协议有关（primary_key）。
	 * Entry_size字段的值就是一个neighbour结构的字节数与协议提供的primary_key字段的字节数之和
	 */
	int			entry_size;
	/**
	 * 查找函数使用的查找关键字的长度。
	 * 由于查找关键字是一个L3地址，对IPV4来说，该字段的值就是6。
	 * 对IPV6来说，就是8。
	 * 对DECnet来说，就是2。
	 */
	int			key_len;
	/**
	 * hash函数。在查找一个邻居项时，该函数用搜索关键字从hash表中选择正确的buchet。
	 */
	__u32			(*hash)(const void *pkey, const struct net_device *);
	/**
	 * 当建立一个新的邻居项时，neigh_create函数调用的constructor方法。
	 * 该方法会初始化新neighbour项中协议指定的一些字段。
	 */
	int			(*constructor)(struct neighbour *);
	/**
	 * pconstructor对应于constructor。现在，只有ipv6使用pconstructor。
	 */
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	/**
	 * 处理出列请求的函数。
	 * 当solicit请求从代理队列neigh_table->proxy_queue中取出后，处理该请求的函数。
	 */
	void			(*proxy_redo)(struct sk_buff *skb);
	/**
	 * 这只是一个用于标识协议的字符串。在分配内存池时（参见neigh_table_init），这个内存池用于分配neighbour结构，该字段主要作为一个ID。
	 */
	char			*id;
	/**
	 * 这个数据结构包含了一些用于调整邻居协议行为的参数。
	 */
	struct neigh_parms	parms;
	/* HACK. gc_* shoul follow parms without a gap! */
	/**
	 * 这个变量用来控制gc_timer定时器多久会超时，并启动垃圾回收。
	 */
	int			gc_interval;
	/**
	 * 这三个值定义了三个不同级别的内存状态，邻居协议可将这些状态赋给当前缓存中的neighbour项。
	 */
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
	/**
	 * 这个变量表示neigh_forced_gc最近一次执行的时间，用jiffies测量。
	 * 换句话说，它表示由于内存不足，最近一次垃圾回收程序执行的时间。
	 */
	unsigned long		last_flush;
	/**
	 * 垃圾回收定时器。
	 */
	struct timer_list 	gc_timer;
	/**
	 * 用于执行代理延时的定时器。
	 * 定时器由neigh_table_init初始化，默认处理函数是neigh_proxy_process。
	 * 当proxy_queue队列中至少有一个元素时，就会启动这个定时器。
	 * 如果定时器超时，执行的处理函数时neigh_proxy_process。
	 * 由neigh_table_init函数在协议初始化时对这个定时器初始化。
	 * 它与neigh_table->gc_timer定时器不同，不会周期性启动。
	 * 只在需要的时候启动（例如，在往proxy_queue中首次增加一个元素时，协议就会启动它）。
	 */
	struct timer_list 	proxy_timer;
	/**
	 * 协议私有的临时缓冲入solicitation请求的队列。
	 * 当启动代理并配置了非空的proxy_delay延迟时，收到的solicit请求（如ARP下收到ARPOP_REQUEST包）就放到这个队列中。新元素被加到队尾。
	 */
	struct sk_buff_head	proxy_queue;
	/**
	 * 在协议缓冲中当前neighbour结构实例的数目。
	 * 每当用neigh_alloc分配一个新的邻居项，它的值就增加1。用neigh_destroy释放一个邻居项，它的值就减1。
	 */
	atomic_t		entries;
	/**
	 * 用于在出现竞争时保护这个表的锁。
	 * 对于只需要读权限的函数，例如，neigh_lookup，该锁用于只读模式。对于其他函数，例如，neigh_periodic_timer，它可以处于读/写模式。
	 */
	rwlock_t		lock;
	/**
	 * 与一个表（每个设备都有这样一个表）关联的neigh_parms结构，变量reachable_time最近被更新的时间。
	 */
	unsigned long		last_rand;
	/**
	 * 没有使用。
	 */
	struct neigh_parms	*parms_list;
	/**
	 * 分配neighbour结构时需要的内存池。这个内存池在协议初始化时，由neigh_table_init分配和初始化。
	 */
	kmem_cache_t		*kmem_cachep;
	/**
	 * 缓存中的neighbour实例的各种统计信息。
	 */
	struct neigh_statistics	*stats;
	/**
	 * 缓存协议解析过对L3到L2的映射或静态配置。
	 * 存储neighbour项的hash表。
	 */
	struct neighbour	**hash_buckets;
	/**
	 * hash表的长度。
	 */
	unsigned int		hash_mask;
	/**
	 * 当缓存长度要增加时，用于分发neighbour项的随机数值。
	 */
	__u32			hash_rnd;
	/**
	 * 记录定期运行的垃圾回收定时器要扫描的hash表中的下一个bucket。这些bucket是按顺序扫描的。
	 */
	unsigned int		hash_chain_gc;
	/**
	 * 存储要被代理的L3地址的表。
	 * 按目的地进行代理时，保存需要被代理的IP地址。
	 * 没有容量限制，而且也没有垃圾回收机制。
	 * 在IPV4中，这些地址只能手动配置。
	 */
	struct pneigh_entry	**phash_buckets;
#ifdef CONFIG_PROC_FS
	/**
	 * 注册到/proc/net/stat中的文件，用于输出协议的统计信息。
	 */
	struct proc_dir_entry	*pde;
#endif
};

/* flags for neigh_update() */
/**
 * 指当前的L2地址可以被lladdr覆盖。
 * 管理性改变使用这个标识来区分replace和add命令。
 * 协议代码可以使用这个标识来给一个L2地址设定一个最小生存期。
 */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
/**
 * 如果输入参数中提供的链路层地址lladdr与当前已知的邻居neigh->ha的链路层地址不同，那么这个地址就是可疑的（也就是说，邻居的状态会转移到NUD_STALE，以便触发可到达性认证）。
 */
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
/**
 * 表示IPV6 NTF_ROUTER标识可以被覆盖
 */
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
/**
 * 表示这个邻居是个路由器。这个标识用于初始化neighbour->flags中的IPV6标识NTF_ROUTER。
 */
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
/**
 * 管理性改变。意思是说改变来自于用户空间命令。
 */
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);
extern void			neigh_parms_destroy(struct neigh_parms *parms);
extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, const void *key, struct net_device *dev, int creat);
extern int			pneigh_delete(struct neigh_table *tbl, const void *key, struct net_device *dev);

struct netlink_callback;
struct nlmsghdr;
extern int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern void neigh_app_ns(struct neighbour *n);

extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

/**
 * 释放对邻居缓存项的引用。删除neighbour结构的原因主要有以下三个：
 *		内核企图向一个不可到达的主机发送包。
 *		与该邻居结构关联的主机的L2地址改变了（可能是它更换了NIC），但它的L3地址还是原来的。
 *		该邻居结构存在时间太长，且内核需要它所占用的内存。因此使用垃圾回收将其删除。
 */
static inline void neigh_release(struct neighbour *neigh)
{
	/**
	 * 只有当一个结构的引用计数器为0时，才会删除该结构。
	 */
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)
/**
 * 增加邻居缓存项的引用。
 */
static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		/**
		 * 改变邻居缓存的时间戳，但是并不改变邻居状态。
		 * 当定时器检测到一个新的时间戳记时，它就会改变相关的邻居状态。
		 */
		neigh->confirmed = jiffies;
}

static inline int neigh_is_connected(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_CONNECTED;
}

static inline int neigh_is_valid(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_VALID;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}
/**
 * 当neigh_lookip查找失败和该函数的输入参数中设置了creat标志时，该函数就使用neigh_create函数来建立一个neighbour项。
 */
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

/**
 * 该函数使用neigh_lookup函数来查看要查找的邻居项是否存在，并且当查找失败时，总是创建一个的neighbour实例。
 * 除了不需要输入creat标识外，该函数基本上和__neigh_lookup函数相同。
 */
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

#define LOCALLY_ENQUEUED -2

#endif
#endif


