/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_ipv4.c,v 1.240 2002/02/01 22:01:04 davem Exp $
 *
 *		IPv4 specific functions
 *
 *
 *		code split from:
 *		linux/ipv4/tcp.c
 *		linux/ipv4/tcp_input.c
 *		linux/ipv4/tcp_output.c
 *
 *		See tcp.c for author information
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

/*
 * Changes:
 *		David S. Miller	:	New socket lookup architecture.
 *					This code is dedicated to John Dyson.
 *		David S. Miller :	Change semantics of established hash,
 *					half is devoted to TIME_WAIT sockets
 *					and the rest go in the other half.
 *		Andi Kleen :		Add support for syncookies and fixed
 *					some bugs: ip options weren't passed to
 *					the TCP layer, missed a check for an
 *					ACK bit.
 *		Andi Kleen :		Implemented fast path mtu discovery.
 *	     				Fixed many serious bugs in the
 *					open_request handling and moved
 *					most of it into the af independent code.
 *					Added tail drop and some other bugfixes.
 *					Added new listen sematics.
 *		Mike McLagan	:	Routing by source
 *	Juan Jose Ciarlante:		ip_dynaddr bits
 *		Andi Kleen:		various fixes.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year
 *					coma.
 *	Andi Kleen		:	Fix new listen.
 *	Andi Kleen		:	Fix accept error reporting.
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 */

#include <linux/config.h>

#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/times.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/xfrm.h>

#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

extern int sysctl_ip_dynaddr;
/**
 * 标识是否允许处于TIME-WAIT状态的端口用于新的TCP套接口字。
 */
int sysctl_tcp_tw_reuse;
/* 启用时，TCP段的接收在进程上下文进行。不启用时，可以在软中断中进行，从而提高吞吐量。某些情况下，如构建Beowulf集群的时候，启用它可以提高性能。 */
int sysctl_tcp_low_latency;

/* Check TCP sequence numbers in ICMP packets. */
#define ICMP_MIN_LENGTH 8

/* Socket used for sending RSTs */
static struct socket *tcp_socket;

void tcp_v4_send_check(struct sock *sk, struct tcphdr *th, int len,
		       struct sk_buff *skb);

/* 管理TCP哈希表的结构 */
struct tcp_hashinfo __cacheline_aligned tcp_hashinfo = {
	.__tcp_lhash_lock	=	RW_LOCK_UNLOCKED,
	.__tcp_lhash_users	=	ATOMIC_INIT(0),
	.__tcp_lhash_wait
	  = __WAIT_QUEUE_HEAD_INITIALIZER(tcp_hashinfo.__tcp_lhash_wait),
	.__tcp_portalloc_lock	=	SPIN_LOCK_UNLOCKED
};

/*
 * This array holds the first and last local port number.
 * For high-usage systems, use sysctl to change this to
 * 32768-61000
 */
/* 本地端口区间范围 */
int sysctl_local_port_range[2] = { 1024, 4999 };
int tcp_port_rover = 1024 - 1;

static __inline__ int tcp_hashfn(__u32 laddr, __u16 lport,
				 __u32 faddr, __u16 fport)
{
	int h = (laddr ^ lport) ^ (faddr ^ fport);
	h ^= h >> 16;
	h ^= h >> 8;
	return h & (tcp_ehash_size - 1);
}

static __inline__ int tcp_sk_hashfn(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	__u32 laddr = inet->rcv_saddr;
	__u16 lport = inet->num;
	__u32 faddr = inet->daddr;
	__u16 fport = inet->dport;

	return tcp_hashfn(laddr, lport, faddr, fport);
}

/* Allocate and initialize a new TCP local port bind bucket.
 * The bindhash mutex for snum's hash chain must be held here.
 */
struct tcp_bind_bucket *tcp_bucket_create(struct tcp_bind_hashbucket *head,
					  unsigned short snum)
{
	struct tcp_bind_bucket *tb = kmem_cache_alloc(tcp_bucket_cachep,
						      SLAB_ATOMIC);
	if (tb) {
		tb->port = snum;
		tb->fastreuse = 0;
		INIT_HLIST_HEAD(&tb->owners);
		hlist_add_head(&tb->node, &head->chain);
	}
	return tb;
}

/* Caller must hold hashbucket lock for this tb with local BH disabled */
void tcp_bucket_destroy(struct tcp_bind_bucket *tb)
{
	if (hlist_empty(&tb->owners)) {
		__hlist_del(&tb->node);
		kmem_cache_free(tcp_bucket_cachep, tb);
	}
}

/* Caller must disable local BH processing. */
static __inline__ void __tcp_inherit_port(struct sock *sk, struct sock *child)
{
	struct tcp_bind_hashbucket *head =
				&tcp_bhash[tcp_bhashfn(inet_sk(child)->num)];
	struct tcp_bind_bucket *tb;

	spin_lock(&head->lock);
	tb = tcp_sk(sk)->bind_hash;
	sk_add_bind_node(child, &tb->owners);
	tcp_sk(child)->bind_hash = tb;
	spin_unlock(&head->lock);
}

inline void tcp_inherit_port(struct sock *sk, struct sock *child)
{
	local_bh_disable();
	__tcp_inherit_port(sk, child);
	local_bh_enable();
}

void tcp_bind_hash(struct sock *sk, struct tcp_bind_bucket *tb,
		   unsigned short snum)
{
	inet_sk(sk)->num = snum;/* 设置传输控制块的端口 */
	sk_add_bind_node(sk, &tb->owners);/* 将传输控制块加入到端口信息块的传输控制块链表中 */
	tcp_sk(sk)->bind_hash = tb;
}

static inline int tcp_bind_conflict(struct sock *sk, struct tcp_bind_bucket *tb)
{
	const u32 sk_rcv_saddr = tcp_v4_rcv_saddr(sk);
	struct sock *sk2;
	struct hlist_node *node;
	int reuse = sk->sk_reuse;

	sk_for_each_bound(sk2, node, &tb->owners) {
		if (sk != sk2 &&
		    !tcp_v6_ipv6only(sk2) &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {
			if (!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == TCP_LISTEN) {
				const u32 sk2_rcv_saddr = tcp_v4_rcv_saddr(sk2);
				if (!sk2_rcv_saddr || !sk_rcv_saddr ||
				    sk2_rcv_saddr == sk_rcv_saddr)
					break;
			}
		}
	}
	return node != NULL;
}

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 */
/* 在sys_bind调用中，用来绑定套接口的端口。 */
static int tcp_v4_get_port(struct sock *sk, unsigned short snum)
{
	struct tcp_bind_hashbucket *head;
	struct hlist_node *node;
	struct tcp_bind_bucket *tb;
	int ret;

	local_bh_disable();/* 禁用软中断 */
	if (!snum) {/* 待绑定端口为0，则自动分配一个 */
		/* 获取自动绑定端口的区间 */
		int low = sysctl_local_port_range[0];
		int high = sysctl_local_port_range[1];
		/* 根据区间号确定重试次数 */
		int remaining = (high - low) + 1;
		int rover;

		spin_lock(&tcp_portalloc_lock);
		/* 起始端口号 */
		rover = tcp_port_rover;
		do {/* 遍历所有可能的端口号 */
			rover++;
			if (rover < low || rover > high)
				rover = low;
			/* 根据端口号计算哈希桶号 */
			head = &tcp_bhash[tcp_bhashfn(rover)];
			spin_lock(&head->lock);
			tb_for_each(tb, node, &head->chain)/* 遍历哈希链表 */
				if (tb->port == rover)/* 端口号已经被占用 */
					goto next;
			/* 运行到这里，说明端口号没有被占用，可以分配 */
			break;
		next:
			spin_unlock(&head->lock);
		} while (--remaining > 0);
		/* 成功找到端口号，或者尝试失败 */
		tcp_port_rover = rover;
		spin_unlock(&tcp_portalloc_lock);

		/* Exhausted local port range during search? */
		ret = 1;
		if (remaining <= 0)/* 遍历完毕，没有找到可用端口 */
			goto fail;

		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 */
		snum = rover;/* 找到合适的端口 */
	} else {/* 指定端口号 */
		head = &tcp_bhash[tcp_bhashfn(snum)];/* 获得该端口对应的哈希桶 */
		spin_lock(&head->lock);
		tb_for_each(tb, node, &head->chain)/* 遍历哈希链表 */
			if (tb->port == snum)/* 端口已经绑定 */
				goto tb_found;
	}
	/* 运行到此，说明已经正确分配到空闲端口，或者指定的端口没有被占用 */
	tb = NULL;
	goto tb_not_found;
tb_found:
	if (!hlist_empty(&tb->owners)) {/* 确定此端口是否有对应的传输控制块 */
		if (sk->sk_reuse > 1)/* 有传输控制块，但是可以强制复用 */
			goto success;
		if (tb->fastreuse > 0 &&
		    sk->sk_reuse && sk->sk_state != TCP_LISTEN) {/* 端口可复用，并且传输控制块不处于侦听状态 */
			goto success;
		} else {/* 端口不可复用 */
			ret = 1;
			if (tcp_bind_conflict(sk, tb))/* 检测复用端口是否冲突，如果不冲突，则可以复用 */
				goto fail_unlock;
		}
	}
	/* 端口没有对应的传输控制块，跳转到tb_not_found */
tb_not_found:
	/* 运行到这里，说明端口可用，或者可以复用 */
	ret = 1;
	if (!tb && (tb = tcp_bucket_create(head, snum)) == NULL)/* 如果是新分配端口，则创建绑定端口信息，并添加到哈希桶中 */
		goto fail_unlock;
	if (hlist_empty(&tb->owners)) {/* 端口没有传输控制块 */
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
			tb->fastreuse = 1;
		else
			tb->fastreuse = 0;
	} else if (tb->fastreuse &&
		   (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
		tb->fastreuse = 0;
success:
	if (!tcp_sk(sk)->bind_hash)/* 完成传输控制块与端口的绑定 */
		tcp_bind_hash(sk, tb, snum);
	BUG_TRAP(tcp_sk(sk)->bind_hash == tb);
 	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}

/* Get rid of any references to a local port held by the
 * given sock.
 */
static void __tcp_put_port(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_bind_hashbucket *head = &tcp_bhash[tcp_bhashfn(inet->num)];
	struct tcp_bind_bucket *tb;

	spin_lock(&head->lock);
	tb = tcp_sk(sk)->bind_hash;
	__sk_del_bind_node(sk);
	tcp_sk(sk)->bind_hash = NULL;
	inet->num = 0;
	tcp_bucket_destroy(tb);
	spin_unlock(&head->lock);
}

void tcp_put_port(struct sock *sk)
{
	local_bh_disable();
	__tcp_put_port(sk);
	local_bh_enable();
}

/* This lock without WQ_FLAG_EXCLUSIVE is good on UP and it can be very bad on SMP.
 * Look, when several writers sleep and reader wakes them up, all but one
 * immediately hit write lock and grab all the cpus. Exclusive sleep solves
 * this, _but_ remember, it adds useless work on UP machines (wake up each
 * exclusive lock release). It should be ifdefed really.
 */

void tcp_listen_wlock(void)
{
	write_lock(&tcp_lhash_lock);

	if (atomic_read(&tcp_lhash_users)) {
		DEFINE_WAIT(wait);

		for (;;) {
			prepare_to_wait_exclusive(&tcp_lhash_wait,
						&wait, TASK_UNINTERRUPTIBLE);
			if (!atomic_read(&tcp_lhash_users))
				break;
			write_unlock_bh(&tcp_lhash_lock);
			schedule();
			write_lock_bh(&tcp_lhash_lock);
		}

		finish_wait(&tcp_lhash_wait, &wait);
	}
}

static __inline__ void __tcp_v4_hash(struct sock *sk, const int listen_possible)
{
	struct hlist_head *list;
	rwlock_t *lock;

	BUG_TRAP(sk_unhashed(sk));
	if (listen_possible && sk->sk_state == TCP_LISTEN) {
		list = &tcp_listening_hash[tcp_sk_listen_hashfn(sk)];
		lock = &tcp_lhash_lock;
		tcp_listen_wlock();
	} else {
		list = &tcp_ehash[(sk->sk_hashent = tcp_sk_hashfn(sk))].chain;
		lock = &tcp_ehash[sk->sk_hashent].lock;
		write_lock(lock);
	}
	__sk_add_node(sk, list);
	sock_prot_inc_use(sk->sk_prot);
	write_unlock(lock);
	if (listen_possible && sk->sk_state == TCP_LISTEN)
		wake_up(&tcp_lhash_wait);
}

/* 将创建的连接加入到哈希表中 */
static void tcp_v4_hash(struct sock *sk)
{
	if (sk->sk_state != TCP_CLOSE) {
		local_bh_disable();
		__tcp_v4_hash(sk, 1);
		local_bh_enable();
	}
}

/* 将连接从哈希表中移除 */
void tcp_unhash(struct sock *sk)
{
	rwlock_t *lock;

	if (sk_unhashed(sk))
		goto ende;

	if (sk->sk_state == TCP_LISTEN) {
		local_bh_disable();
		tcp_listen_wlock();
		lock = &tcp_lhash_lock;
	} else {
		struct tcp_ehash_bucket *head = &tcp_ehash[sk->sk_hashent];
		lock = &head->lock;
		write_lock_bh(&head->lock);
	}

	if (__sk_del_node_init(sk))
		sock_prot_dec_use(sk->sk_prot);
	write_unlock_bh(lock);

 ende:
	if (sk->sk_state == TCP_LISTEN)
		wake_up(&tcp_lhash_wait);
}

/* Don't inline this cruft.  Here are some nice properties to
 * exploit here.  The BSD API does not allow a listening TCP
 * to specify the remote port nor the remote address for the
 * connection.  So always assume those are both wildcarded
 * during the search since they can never be otherwise.
 */
static struct sock *__tcp_v4_lookup_listener(struct hlist_head *head, u32 daddr,
					     unsigned short hnum, int dif)
{
	struct sock *result = NULL, *sk;
	struct hlist_node *node;
	int score, hiscore;

	hiscore=-1;
	sk_for_each(sk, node, head) {
		struct inet_sock *inet = inet_sk(sk);

		if (inet->num == hnum && !ipv6_only_sock(sk)) {
			__u32 rcv_saddr = inet->rcv_saddr;

			score = (sk->sk_family == PF_INET ? 1 : 0);
			if (rcv_saddr) {
				if (rcv_saddr != daddr)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			if (score == 5)
				return sk;
			if (score > hiscore) {
				hiscore = score;
				result = sk;
			}
		}
	}
	return result;
}

/* Optimize the common listener case. */
static inline struct sock *tcp_v4_lookup_listener(u32 daddr,
		unsigned short hnum, int dif)
{
	struct sock *sk = NULL;
	struct hlist_head *head;

	read_lock(&tcp_lhash_lock);
	head = &tcp_listening_hash[tcp_lhashfn(hnum)];
	if (!hlist_empty(head)) {
		struct inet_sock *inet = inet_sk((sk = __sk_head(head)));

		if (inet->num == hnum && !sk->sk_node.next &&
		    (!inet->rcv_saddr || inet->rcv_saddr == daddr) &&
		    (sk->sk_family == PF_INET || !ipv6_only_sock(sk)) &&
		    !sk->sk_bound_dev_if)
			goto sherry_cache;
		sk = __tcp_v4_lookup_listener(head, daddr, hnum, dif);
	}
	if (sk) {
sherry_cache:
		sock_hold(sk);
	}
	read_unlock(&tcp_lhash_lock);
	return sk;
}

/* Sockets in TCP_CLOSE state are _always_ taken out of the hash, so
 * we need not check it for TCP lookups anymore, thanks Alexey. -DaveM
 *
 * Local BH must be disabled here.
 */

static inline struct sock *__tcp_v4_lookup_established(u32 saddr, u16 sport,
						       u32 daddr, u16 hnum,
						       int dif)
{
	struct tcp_ehash_bucket *head;
	TCP_V4_ADDR_COOKIE(acookie, saddr, daddr)
	__u32 ports = TCP_COMBINED_PORTS(sport, hnum);
	struct sock *sk;
	struct hlist_node *node;
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	int hash = tcp_hashfn(daddr, hnum, saddr, sport);
	head = &tcp_ehash[hash];
	read_lock(&head->lock);
	sk_for_each(sk, node, &head->chain) {
		if (TCP_IPV4_MATCH(sk, acookie, saddr, daddr, ports, dif))
			goto hit; /* You sunk my battleship! */
	}

	/* Must check for a TIME_WAIT'er before going to listener hash. */
	sk_for_each(sk, node, &(head + tcp_ehash_size)->chain) {
		if (TCP_IPV4_TW_MATCH(sk, acookie, saddr, daddr, ports, dif))
			goto hit;
	}
	sk = NULL;
out:
	read_unlock(&head->lock);
	return sk;
hit:
	sock_hold(sk);
	goto out;
}

static inline struct sock *__tcp_v4_lookup(u32 saddr, u16 sport,
					   u32 daddr, u16 hnum, int dif)
{
	struct sock *sk = __tcp_v4_lookup_established(saddr, sport,
						      daddr, hnum, dif);

	return sk ? : tcp_v4_lookup_listener(daddr, hnum, dif);
}

inline struct sock *tcp_v4_lookup(u32 saddr, u16 sport, u32 daddr,
				  u16 dport, int dif)
{
	struct sock *sk;

	local_bh_disable();
	sk = __tcp_v4_lookup(saddr, sport, daddr, ntohs(dport), dif);
	local_bh_enable();

	return sk;
}

EXPORT_SYMBOL_GPL(tcp_v4_lookup);

static inline __u32 tcp_v4_init_sequence(struct sock *sk, struct sk_buff *skb)
{
	return secure_tcp_sequence_number(skb->nh.iph->daddr,
					  skb->nh.iph->saddr,
					  skb->h.th->dest,
					  skb->h.th->source);
}

/* called with local bh disabled */
static int __tcp_v4_check_established(struct sock *sk, __u16 lport,
				      struct tcp_tw_bucket **twp)
{
	struct inet_sock *inet = inet_sk(sk);
	u32 daddr = inet->rcv_saddr;
	u32 saddr = inet->daddr;
	int dif = sk->sk_bound_dev_if;
	TCP_V4_ADDR_COOKIE(acookie, saddr, daddr)
	__u32 ports = TCP_COMBINED_PORTS(inet->dport, lport);
	int hash = tcp_hashfn(daddr, lport, saddr, inet->dport);
	struct tcp_ehash_bucket *head = &tcp_ehash[hash];
	struct sock *sk2;
	struct hlist_node *node;
	struct tcp_tw_bucket *tw;

	write_lock(&head->lock);

	/* Check TIME-WAIT sockets first. */
	sk_for_each(sk2, node, &(head + tcp_ehash_size)->chain) {
		tw = (struct tcp_tw_bucket *)sk2;

		if (TCP_IPV4_TW_MATCH(sk2, acookie, saddr, daddr, ports, dif)) {
			struct tcp_sock *tp = tcp_sk(sk);

			/* With PAWS, it is safe from the viewpoint
			   of data integrity. Even without PAWS it
			   is safe provided sequence spaces do not
			   overlap i.e. at data rates <= 80Mbit/sec.

			   Actually, the idea is close to VJ's one,
			   only timestamp cache is held not per host,
			   but per port pair and TW bucket is used
			   as state holder.

			   If TW bucket has been already destroyed we
			   fall back to VJ's scheme and use initial
			   timestamp retrieved from peer table.
			 */
			if (tw->tw_ts_recent_stamp &&
			    (!twp || (sysctl_tcp_tw_reuse &&
				      xtime.tv_sec -
				      tw->tw_ts_recent_stamp > 1))) {
				if ((tp->write_seq =
						tw->tw_snd_nxt + 65535 + 2) == 0)
					tp->write_seq = 1;
				tp->rx_opt.ts_recent	   = tw->tw_ts_recent;
				tp->rx_opt.ts_recent_stamp = tw->tw_ts_recent_stamp;
				sock_hold(sk2);
				goto unique;
			} else
				goto not_unique;
		}
	}
	tw = NULL;

	/* And established part... */
	sk_for_each(sk2, node, &head->chain) {
		if (TCP_IPV4_MATCH(sk2, acookie, saddr, daddr, ports, dif))
			goto not_unique;
	}

unique:
	/* Must record num and sport now. Otherwise we will see
	 * in hash table socket with a funny identity. */
	inet->num = lport;
	inet->sport = htons(lport);
	sk->sk_hashent = hash;
	BUG_TRAP(sk_unhashed(sk));
	__sk_add_node(sk, &head->chain);
	sock_prot_inc_use(sk->sk_prot);
	write_unlock(&head->lock);

	if (twp) {
		*twp = tw;
		NET_INC_STATS_BH(LINUX_MIB_TIMEWAITRECYCLED);
	} else if (tw) {
		/* Silly. Should hash-dance instead... */
		tcp_tw_deschedule(tw);
		NET_INC_STATS_BH(LINUX_MIB_TIMEWAITRECYCLED);

		tcp_tw_put(tw);
	}

	return 0;

not_unique:
	write_unlock(&head->lock);
	return -EADDRNOTAVAIL;
}

static inline u32 connect_port_offset(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);

	return secure_tcp_port_ephemeral(inet->rcv_saddr, inet->daddr, 
					 inet->dport);
}

/*
 * Bind a port for a connect operation and hash it.
 */
/* 动态绑定端口，并将传输控制块加入哈希表 */
static inline int tcp_v4_hash_connect(struct sock *sk)
{
	unsigned short snum = inet_sk(sk)->num;
 	struct tcp_bind_hashbucket *head;
 	struct tcp_bind_bucket *tb;
	int ret;

 	if (!snum) {/* 未绑定端口，自动选择端口并进行绑定 */
		/* 动态端口的范围 */
 		int low = sysctl_local_port_range[0];
 		int high = sysctl_local_port_range[1];
		int range = high - low;
 		int i;
		int port;
		static u32 hint;
		u32 offset = hint + connect_port_offset(sk);
		struct hlist_node *node;
 		struct tcp_tw_bucket *tw = NULL;

 		local_bh_disable();
		for (i = 1; i <= range; i++) {/* 遍历动态端口的范围 */
			/* 通过源地址、目的地址和目的端口计算得到的值作为端口初始值 */
			port = low + (i + offset) % range;
 			head = &tcp_bhash[tcp_bhashfn(port)];
 			spin_lock(&head->lock);

 			/* Does not bother with rcv_saddr checks,
 			 * because the established check is already
 			 * unique enough.
 			 */
			tb_for_each(tb, node, &head->chain) {/* 检测临时端口是否可用 */
 				if (tb->port == port) {
 					BUG_TRAP(!hlist_empty(&tb->owners));
 					if (tb->fastreuse >= 0)/* 不能重用 */
 						goto next_port;
 					if (!__tcp_v4_check_established(sk,
									port,
									&tw))/* 能重用 */
 						goto ok;
 					goto next_port;
 				}
 			}

			/* 端口未被绑定，为该端口创建一个信息块 */
 			tb = tcp_bucket_create(head, port);
 			if (!tb) {
 				spin_unlock(&head->lock);
 				break;
 			}
 			tb->fastreuse = -1;
 			goto ok;

 		next_port:
 			spin_unlock(&head->lock);
 		}
 		local_bh_enable();

		/* 找不到可用端口 */
 		return -EADDRNOTAVAIL;

ok:
		hint += i;

 		/* Head lock still held and bh's disabled */
 		tcp_bind_hash(sk, tb, port);/* 将传输控制块与绑定端口信息关联，完成绑定 */
		if (sk_unhashed(sk)) {/* 该传输控制块未添加到哈希表 */
 			inet_sk(sk)->sport = htons(port);
 			__tcp_v4_hash(sk, 0);/* 将传输控制块加入到控制块 */
 		}
 		spin_unlock(&head->lock);

 		if (tw) {/* 与TIME_WAIT状态的套接口复用端口，则释放该套接口 */
 			tcp_tw_deschedule(tw);
 			tcp_tw_put(tw);
 		}

		ret = 0;
		goto out;
 	}

	/* 运行到这里，说明是指定端口，需要对其进行确认 */
 	head  = &tcp_bhash[tcp_bhashfn(snum)];
 	tb  = tcp_sk(sk)->bind_hash;
	spin_lock_bh(&head->lock);
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		__tcp_v4_hash(sk, 0);
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = __tcp_v4_check_established(sk, snum, NULL);
out:
		local_bh_enable();
		return ret;
	}
}

/* This will initiate an outgoing connection. */
/* 建立与服务器连接，发送SYN段 */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	u32 daddr, nexthop;
	int tmp;
	int err;

	/* 校验目的地址的长度及地址族的有效性 */
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	/* 将下一跳和目的地址都设置为源地址 */
	nexthop = daddr = usin->sin_addr.s_addr;
	if (inet->opt && inet->opt->srr) {/* 如果是源站路由，则下一跳设置为选项中的地址 */
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}

	/* 根据下一跳地址等信息查找目的路由缓存项。 */
	tmp = ip_route_connect(&rt, nexthop, inet->saddr,
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->sport, usin->sin_port, sk);
	if (tmp < 0)
		return tmp;

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {/* 对TCP来说，不能使用多播和组播路由项 */
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet->opt || !inet->opt->srr)/* 如果没有启用源路由选项，则使用路由缓存项中的目的地址 */
		daddr = rt->rt_dst;

	if (!inet->saddr)/* 如果未设置传输控制块中的源地址，则使用路由缓存项中的源地址 */
		inet->saddr = rt->rt_src;
	inet->rcv_saddr = inet->saddr;

	/* 如果传输控制块中的时间戳和目的地址已经使用过，则说明传输控制块之前已建立连接并进行通信 */
	if (tp->rx_opt.ts_recent_stamp && inet->daddr != daddr) {
		/* Reset inherited state */
		/* 重新初始化相关成员 */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

	if (sysctl_tcp_tw_recycle &&/* 允许处于TIME-WAIT状态快速迁移到CLOSE状态 */
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {/* 接收过时间戳 */
		struct inet_peer *peer = rt_get_peer(rt);

		/* VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state TIME-WAIT
		 * and initialize rx_opt.ts_recent from it, when trying new connection.
		 */

		/* 从对端信息块中获取值来初始化ts_recent_stamp和ts_recent */
		if (peer && peer->tcp_ts_stamp + TCP_PAWS_MSL >= xtime.tv_sec) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	/* 设置目的地址和目标端口 */
	inet->dport = usin->sin_port;
	inet->daddr = daddr;

	/* 设置IP首部选项长度 */
	tp->ext_header_len = 0;
	if (inet->opt)
		tp->ext_header_len = inet->opt->optlen;

	/* 初始化MSS上限 */
	tp->rx_opt.mss_clamp = 536;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);/* 设置状态 */
	err = tcp_v4_hash_connect(sk);/* 将传输控制添加到ehash散列表中，并动态分配端口 */
	if (err)
		goto failure;

	/* 如果源端口或者目的端口发生改变，则需要重新查找路由 */
	err = ip_route_newports(&rt, inet->sport, inet->dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	__sk_dst_set(sk, &rt->u.dst);/* 设置路由，并根据路由更新网络设备的特性 */
	tcp_v4_setup_caps(sk, &rt->u.dst);
	tp->ext2_header_len = rt->u.dst.header_len;

	if (!tp->write_seq)/* 还未计算初始序号 */
		/* 根据双方地址、端口计算初始序号 */
		tp->write_seq = secure_tcp_sequence_number(inet->saddr,
							   inet->daddr,
							   inet->sport,
							   usin->sin_port);

	/* 根据初始序号和当前时间，随机算一个初始id */
	inet->id = tp->write_seq ^ jiffies;

	/* 发送SYN段 */
	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/* This unhashes the socket and releases the local port, if necessary. */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->dport = 0;
	return err;
}

static __inline__ int tcp_v4_iif(struct sk_buff *skb)
{
	return ((struct rtable *)skb->dst)->rt_iif;
}

static __inline__ u32 tcp_v4_synq_hash(u32 raddr, u16 rport, u32 rnd)
{
	return (jhash_2words(raddr, (u32) rport, rnd) & (TCP_SYNQ_HSIZE - 1));
}

static struct open_request *tcp_v4_search_req(struct tcp_sock *tp,
					      struct open_request ***prevp,
					      __u16 rport,
					      __u32 raddr, __u32 laddr)
{
	struct tcp_listen_opt *lopt = tp->listen_opt;
	struct open_request *req, **prev;

	for (prev = &lopt->syn_table[tcp_v4_synq_hash(raddr, rport, lopt->hash_rnd)];
	     (req = *prev) != NULL;
	     prev = &req->dl_next) {
		if (req->rmt_port == rport &&
		    req->af.v4_req.rmt_addr == raddr &&
		    req->af.v4_req.loc_addr == laddr &&
		    TCP_INET_FAMILY(req->class->family)) {
			BUG_TRAP(!req->sk);
			*prevp = prev;
			break;
		}
	}

	return req;
}

static void tcp_v4_synq_add(struct sock *sk, struct open_request *req)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_listen_opt *lopt = tp->listen_opt;
	u32 h = tcp_v4_synq_hash(req->af.v4_req.rmt_addr, req->rmt_port, lopt->hash_rnd);

	req->expires = jiffies + TCP_TIMEOUT_INIT;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[h];

	write_lock(&tp->syn_wait_lock);
	lopt->syn_table[h] = req;
	write_unlock(&tp->syn_wait_lock);

	tcp_synq_added(sk);
}


/*
 * This routine does path mtu discovery as defined in RFC1191.
 */
/* TCP收到ICMP目的地址不可达报文时，会调用本函数进行路径MTU发现失败处理 */
static inline void do_pmtu_discovery(struct sock *sk, struct iphdr *iph,
				     u32 mtu)
{
	struct dst_entry *dst;
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* We are not interested in TCP_LISTEN and open_requests (SYN-ACKs
	 * send out by Linux are always <576bytes so they should go through
	 * unfragmented).
	 */
	if (sk->sk_state == TCP_LISTEN)/* 侦听状态不需要进行PMTU发现，因为该状态下输出的段SYN+ACK总是小于536B */
		return;

	/* We don't check in the destentry if pmtu discovery is forbidden
	 * on this route. We just assume that no packet_to_big packets
	 * are send back when pmtu discovery is not active.
     	 * There is a small race when the user changes this flag in the
	 * route, but I think that's acceptable.
	 */
	if ((dst = __sk_dst_check(sk, 0)) == NULL)/* 检测该状态下路由缓存项是否可用，如果失效则不用继续处理 */
		return;

	dst->ops->update_pmtu(dst, mtu);

	/* Something is about to be wrong... Remember soft error
	 * for the case, if this connection will not able to recover.
	 */
	if (mtu < dst_pmtu(dst) && ip_dont_fragment(sk, dst))/* 路由缓存项中的PMTU大于下一跳的MTU，且禁止分片 */
		sk->sk_err_soft = EMSGSIZE;/* 向上层返回错误 */

	mtu = dst_pmtu(dst);

	if (inet->pmtudisc != IP_PMTUDISC_DONT &&/* 允许PMTU */
	    tp->pmtu_cookie > mtu) {/* 传输控制块中的PMTU大于新的值，说明需要缩小MTU */
		tcp_sync_mss(sk, mtu);/* 将新的MTU更新到传输控制块，并更新MSS */

		/* Resend the TCP packet because it's
		 * clear that the old packet has been
		 * dropped. This is the new "fast" path mtu
		 * discovery.
		 */
		tcp_simple_retransmit(sk);/* 重传报文 */
	} /* else let the usual retransmit timer handle it */
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.  After adjustment
 * header points to the first 8 bytes of the tcp header.  We need
 * to find the appropriate port.
 *
 * The locking strategy used here is very "optimistic". When
 * someone else accesses the socket the ICMP is just dropped
 * and for some paths there is no check at all.
 * A more general error queue to queue errors for later handling
 * is probably better.
 *
 */
/* 处理ICMP层传来的错误报文 */
void tcp_v4_err(struct sk_buff *skb, u32 info)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	struct tcphdr *th = (struct tcphdr *)(skb->data + (iph->ihl << 2));
	struct tcp_sock *tp;
	struct inet_sock *inet;
	int type = skb->h.icmph->type;
	int code = skb->h.icmph->code;
	struct sock *sk;
	__u32 seq;
	int err;

	if (skb->len < (iph->ihl << 2) + 8) {/* 校验ICMP报文以及8字节传输控制块长度 */
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
		return;
	}

	/* 根据传输控制块中原始TCP首部端口号和源地址，得到发送该报文的传输控制块。 */
	sk = tcp_v4_lookup(iph->daddr, th->dest, iph->saddr,
			   th->source, tcp_v4_iif(skb));
	if (!sk) {/* 获取失败，说明ICMP报文有误或套接口已经关闭 */
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
		return;
	}
	if (sk->sk_state == TCP_TIME_WAIT) {/* 套接口即将关闭，无需进一步处理 */
		tcp_tw_put((struct tcp_tw_bucket *)sk);
		return;
	}

	bh_lock_sock(sk);
	/* If too many ICMPs get dropped on busy
	 * servers this needs to be solved differently.
	 */
	if (sock_owned_by_user(sk))/* 锁已经被用户进程锁定，更新统计量 */
		NET_INC_STATS_BH(LINUX_MIB_LOCKDROPPEDICMPS);

	if (sk->sk_state == TCP_CLOSE)/* 套口已经关闭，无需处理 */
		goto out;

	tp = tcp_sk(sk);
	seq = ntohl(th->seq);
	if (sk->sk_state != TCP_LISTEN &&/* 不在LISTEN状态 */
	    !between(seq, tp->snd_una, tp->snd_nxt)) {/* 序号不在已发送未确认的区间内 */
		NET_INC_STATS(LINUX_MIB_OUTOFWINDOWICMPS);/* ICMP报文异常，退出 */
		goto out;
	}

	switch (type) {
	case ICMP_SOURCE_QUENCH:/* 源端抑制，无需进一步处理 */
		/* Just silently ignore these. */
		goto out;
	case ICMP_PARAMETERPROB:/* 参数问题 */
		err = EPROTO;
		break;
	case ICMP_DEST_UNREACH:/* 目的不可达类型 */
		if (code > NR_ICMP_UNREACH)/* 检查参数有效性 */
			goto out;

		/* 需要分片，处理PMTU探测 */
		if (code == ICMP_FRAG_NEEDED) { /* PMTU discovery (RFC1191) */
			if (!sock_owned_by_user(sk))
				do_pmtu_discovery(sk, iph, info);/* 探测路径MTU */
			goto out;
		}

		/* 其他路径不可达，则取得错误码返回给上层 */
		err = icmp_err_convert[code].errno;
		break;
	case ICMP_TIME_EXCEEDED:/* 超时，主机不存在 */
		err = EHOSTUNREACH;
		break;
	default:
		goto out;
	}

	switch (sk->sk_state) {
		struct open_request *req, **prev;
	case TCP_LISTEN:
		if (sock_owned_by_user(sk))/* 被用户进程锁定，退出 */
			goto out;

		req = tcp_v4_search_req(tp, &prev, th->dest,
					iph->daddr, iph->saddr);/* 查找正在连接的对端套接口 */
		if (!req)/* 未查找到，退出 */
			goto out;

		/* ICMPs are not backlogged, hence we cannot get
		   an established socket here.
		 */
		BUG_TRAP(!req->sk);

		if (seq != req->snt_isn) {/* 发送出去TCP段的序号不等于对端套接口中的发送序号，说明有误，退出 */
			NET_INC_STATS_BH(LINUX_MIB_OUTOFWINDOWICMPS);
			goto out;
		}

		/*
		 * Still in SYN_RECV, just remove it silently.
		 * There is no good way to pass the error to the newly
		 * created socket, and POSIX does not want network
		 * errors returned from accept().
		 */
		/* 删除并释放连接控制块 */
		tcp_synq_drop(sk, req, prev);
		goto out;

	case TCP_SYN_SENT:
	case TCP_SYN_RECV:  /* Cannot happen.
			       It can f.e. if SYNs crossed.
			     */
		if (!sock_owned_by_user(sk)) {/* 用户没有获得锁 */
			TCP_INC_STATS_BH(TCP_MIB_ATTEMPTFAILS);
			sk->sk_err = err;

			/* 向套接口发送错误报告 */
			sk->sk_error_report(sk);

			tcp_done(sk);/* 关闭套接口 */
		} else {
			sk->sk_err_soft = err;/* 将错误码临时放到sk_err_soft，用户进程可以通过SO_ERROR选项获取错误码 */
		}
		goto out;
	}

	/* If we've already connected we will keep trying
	 * until we time out, or the user gives up.
	 *
	 * rfc1122 4.2.3.9 allows to consider as hard errors
	 * only PROTO_UNREACH and PORT_UNREACH (well, FRAG_FAILED too,
	 * but it is obsoleted by pmtu discovery).
	 *
	 * Note, that in modern internet, where routing is unreliable
	 * and in each dark corner broken firewalls sit, sending random
	 * errors ordered by their masters even this two messages finally lose
	 * their original sense (even Linux sends invalid PORT_UNREACHs)
	 *
	 * Now we are in compliance with RFCs.
	 *							--ANK (980905)
	 */

	/* 运行到这里，表示这是普通的套口 */
	inet = inet_sk(sk);
	if (!sock_owned_by_user(sk) && inet->recverr) {/* 未被用户锁定，并且允许接收错误信息 */
		/* 设置错误码并向套接口报告错误 */
		sk->sk_err = err;
		sk->sk_error_report(sk);
	} else	{ /* Only an error on timeout */
		sk->sk_err_soft = err;/* 设置错误并等待进程读取。 */
	}

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* This routine computes an IPv4 TCP checksum. */
/* 基于TCP用户数据的中间累加和，生成TCP包的校验和 */
void tcp_v4_send_check(struct sock *sk, struct tcphdr *th, int len,
		       struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);

	if (skb->ip_summed == CHECKSUM_HW) {/* 硬件完成校验和 */
		/* 执行伪首部校验和计算 */
		th->check = ~tcp_v4_check(th, len, inet->saddr, inet->daddr, 0);
		skb->csum = offsetof(struct tcphdr, check);
	} else {
		/* 首先计算TCP用户数据的中间校验和，再与伪首部一起生成TCP校验和 */
		th->check = tcp_v4_check(th, len, inet->saddr, inet->daddr,
					 csum_partial((char *)th,
						      th->doff << 2,
						      skb->csum));
	}
}

/*
 *	This routine will send an RST to the other tcp.
 *
 *	Someone asks: why I NEVER use socket parameters (TOS, TTL etc.)
 *		      for reset.
 *	Answer: if a packet caused RST, it is not for a socket
 *		existing in our system, if it is matched to a socket,
 *		it is just duplicate segment or bug in other side's TCP.
 *		So that we build reply only basing on parameters
 *		arrived with segment.
 *	Exception: precedence violation. We do not implement it in any case.
 */

static void tcp_v4_send_reset(struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	struct tcphdr rth;
	struct ip_reply_arg arg;

	/* Never send a reset in response to a reset. */
	if (th->rst)
		return;

	if (((struct rtable *)skb->dst)->rt_type != RTN_LOCAL)
		return;

	/* Swap the send and the receive. */
	memset(&rth, 0, sizeof(struct tcphdr));
	rth.dest   = th->source;
	rth.source = th->dest;
	rth.doff   = sizeof(struct tcphdr) / 4;
	rth.rst    = 1;

	if (th->ack) {
		rth.seq = th->ack_seq;
	} else {
		rth.ack = 1;
		rth.ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
				    skb->len - (th->doff << 2));
	}

	memset(&arg, 0, sizeof arg);
	arg.iov[0].iov_base = (unsigned char *)&rth;
	arg.iov[0].iov_len  = sizeof rth;
	arg.csum = csum_tcpudp_nofold(skb->nh.iph->daddr,
				      skb->nh.iph->saddr, /*XXX*/
				      sizeof(struct tcphdr), IPPROTO_TCP, 0);
	arg.csumoffset = offsetof(struct tcphdr, check) / 2;

	ip_send_reply(tcp_socket->sk, skb, &arg, sizeof rth);

	TCP_INC_STATS_BH(TCP_MIB_OUTSEGS);
	TCP_INC_STATS_BH(TCP_MIB_OUTRSTS);
}

/* The code following below sending ACKs in SYN-RECV and TIME-WAIT states
   outside socket context is ugly, certainly. What can I do?
 */

/* 在SYN_RECV或TIME_WAIT状态下，如果段序号无效或者序号不在接收窗口内，且非RST段，则需要向对方发送ACK段 */
static void tcp_v4_send_ack(struct sk_buff *skb, u32 seq, u32 ack,
			    u32 win, u32 ts)
{
	struct tcphdr *th = skb->h.th;
	/* 定义TCP首部，含时间戳 */
	struct {
		struct tcphdr th;
		u32 tsopt[3];
	} rep;
	struct ip_reply_arg arg;

	memset(&rep.th, 0, sizeof(struct tcphdr));
	memset(&arg, 0, sizeof arg);

	arg.iov[0].iov_base = (unsigned char *)&rep;
	arg.iov[0].iov_len  = sizeof(rep.th);
	if (ts) {/* 设置时间戳选项 */
		rep.tsopt[0] = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				     (TCPOPT_TIMESTAMP << 8) |
				     TCPOLEN_TIMESTAMP);
		rep.tsopt[1] = htonl(tcp_time_stamp);
		rep.tsopt[2] = htonl(ts);
		arg.iov[0].iov_len = sizeof(rep);
	}

	/* Swap the send and the receive. */
	/* 设置TCP首部中各字段 */
	rep.th.dest    = th->source;
	rep.th.source  = th->dest;
	rep.th.doff    = arg.iov[0].iov_len / 4;
	rep.th.seq     = htonl(seq);
	rep.th.ack_seq = htonl(ack);
	rep.th.ack     = 1;
	rep.th.window  = htons(win);

	/* 计算伪首部校验和 */
	arg.csum = csum_tcpudp_nofold(skb->nh.iph->daddr,
				      skb->nh.iph->saddr, /*XXX*/
				      arg.iov[0].iov_len, IPPROTO_TCP, 0);
	arg.csumoffset = offsetof(struct tcphdr, check) / 2;

	/* 调用网络层函数发送ACK段 */
	ip_send_reply(tcp_socket->sk, skb, &arg, arg.iov[0].iov_len);

	TCP_INC_STATS_BH(TCP_MIB_OUTSEGS);
}

static void tcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_tw_bucket *tw = (struct tcp_tw_bucket *)sk;

	tcp_v4_send_ack(skb, tw->tw_snd_nxt, tw->tw_rcv_nxt,
			tw->tw_rcv_wnd >> tw->tw_rcv_wscale, tw->tw_ts_recent);

	tcp_tw_put(tw);
}

static void tcp_v4_or_send_ack(struct sk_buff *skb, struct open_request *req)
{
	tcp_v4_send_ack(skb, req->snt_isn + 1, req->rcv_isn + 1, req->rcv_wnd,
			req->ts_recent);
}

/* 查询到对方的路由 */
static struct dst_entry* tcp_v4_route_req(struct sock *sk,
					  struct open_request *req)
{
	struct rtable *rt;
	struct ip_options *opt = req->af.v4_req.opt;
	/* 定义查询条件 */
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
			    .nl_u = { .ip4_u =
				      { .daddr = ((opt && opt->srr) ?
						  opt->faddr :
						  req->af.v4_req.rmt_addr),
					.saddr = req->af.v4_req.loc_addr,
					.tos = RT_CONN_FLAGS(sk) } },
			    .proto = IPPROTO_TCP,
			    .uli_u = { .ports =
				       { .sport = inet_sk(sk)->sport,
					 .dport = req->rmt_port } } };

	/* 根据查询条件，进行路由缓存项的查询 */
	if (ip_route_output_flow(&rt, &fl, sk, 0)) {
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	/* 如果定义了严格路由选项，并且从选项中获取的下一跳与查询到的路由不匹配，则失败 */
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway) {
		ip_rt_put(rt);
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	return &rt->u.dst;
}

/*
 *	Send a SYN-ACK after having received an ACK.
 *	This still operates on a open_request only, not on a big
 *	socket.
 */
/* 向客户端发送SYN+ACK报文 */
static int tcp_v4_send_synack(struct sock *sk, struct open_request *req,
			      struct dst_entry *dst)
{
	int err = -1;
	struct sk_buff * skb;

	/* First, grab a route. */
	/* 查找到客户端的路由 */
	if (!dst && (dst = tcp_v4_route_req(sk, req)) == NULL)
		goto out;

	/* 根据路由、传输控制块、连接请求块中的构建SYN+ACK段 */
	skb = tcp_make_synack(sk, dst, req);

	if (skb) {/* 生成SYN+ACK段成功 */
		struct tcphdr *th = skb->h.th;

		/* 生成校验码 */
		th->check = tcp_v4_check(th, skb->len,
					 req->af.v4_req.loc_addr,
					 req->af.v4_req.rmt_addr,
					 csum_partial((char *)th, skb->len,
						      skb->csum));

		/* 生成IP数据报并发送出去 */
		err = ip_build_and_send_pkt(skb, sk, req->af.v4_req.loc_addr,
					    req->af.v4_req.rmt_addr,
					    req->af.v4_req.opt);
		if (err == NET_XMIT_CN)
			err = 0;
	}

out:
	dst_release(dst);
	return err;
}

/*
 *	IPv4 open_request destructor.
 */
static void tcp_v4_or_free(struct open_request *req)
{
	if (req->af.v4_req.opt)
		kfree(req->af.v4_req.opt);
}

static inline void syn_flood_warning(struct sk_buff *skb)
{
	static unsigned long warntime;

	if (time_after(jiffies, (warntime + HZ * 60))) {
		warntime = jiffies;
		printk(KERN_INFO
		       "possible SYN flooding on port %d. Sending cookies.\n",
		       ntohs(skb->h.th->dest));
	}
}

/*
 * Save and compile IPv4 options into the open_request if needed.
 */
static inline struct ip_options *tcp_v4_save_options(struct sock *sk,
						     struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	struct ip_options *dopt = NULL;

	if (opt && opt->optlen) {
		int opt_size = optlength(opt);
		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt) {
			if (ip_options_echo(dopt, skb)) {
				kfree(dopt);
				dopt = NULL;
			}
		}
	}
	return dopt;
}

/*
 * Maximum number of SYN_RECV sockets in queue per LISTEN socket.
 * One SYN_RECV socket costs about 80bytes on a 32bit machine.
 * It would be better to replace it with a global counter for all sockets
 * but then some measure against one socket starving all other sockets
 * would be needed.
 *
 * It was 128 by default. Experiments with real servers show, that
 * it is absolutely not enough even at 100conn/sec. 256 cures most
 * of problems. This value is adjusted to 128 for very small machines
 * (<=32Mb of memory) and to 1024 on normal or better ones (>=256Mb).
 * Further increasing requires to change hash table size.
 */
/**
 * 系统可同时存在的未完成三次握手的SYNC请求的最大数目。
 * 对超过128M内存的系统是1024，其他是128.
 */
int sysctl_max_syn_backlog = 256;

struct or_calltable or_ipv4 = {
	.family		=	PF_INET,
	.rtx_syn_ack	=	tcp_v4_send_synack,
	.send_ack	=	tcp_v4_or_send_ack,
	.destructor	=	tcp_v4_or_free,
	.send_reset	=	tcp_v4_send_reset,
};

/* 处理客户端发送的SYN段 */
int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_options_received tmp_opt;
	struct open_request *req;
	__u32 saddr = skb->nh.iph->saddr;
	__u32 daddr = skb->nh.iph->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
	struct dst_entry *dst = NULL;
#ifdef CONFIG_SYN_COOKIES
	int want_cookie = 0;
#else
#define want_cookie 0 /* Argh, why doesn't gcc optimize this :( */
#endif

	/* Never answer to SYNs send to broadcast or multicast */
	if (((struct rtable *)skb->dst)->rt_flags &
	    (RTCF_BROADCAST | RTCF_MULTICAST))/* SYN段不能发送到广播地址或组播地址 */
		goto drop;

	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	if (tcp_synq_is_full(sk) && !isn) {/* 连接请求队列已满 */
#ifdef CONFIG_SYN_COOKIES
		if (sysctl_tcp_syncookies) {/* 如果启用了syncookie功能，则设置标志，启用syncookie */
			want_cookie = 1;
		} else
#endif
		goto drop;/* 没有启用syncookie功能，只能丢弃 */
	}

	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 */
	if (sk_acceptq_is_full(sk) && tcp_synq_young(sk) > 1)/* 连接队列长度已达上限且SYN请求队列中至少有一个握手过程中没有重传，则丢弃段 */
		goto drop;

	/* 运行到这里，说明可以接收并处理请求，先分配一个连接请求块 */
	req = tcp_openreq_alloc();
	if (!req)
		goto drop;

	tcp_clear_options(&tmp_opt);/* 初始化选项并初始化mss */
	tmp_opt.mss_clamp = 536;
	tmp_opt.user_mss  = tcp_sk(sk)->rx_opt.user_mss;

	/* 解析TCP段中的选项 */
	tcp_parse_options(skb, &tmp_opt, 0);

	if (want_cookie) {/* 如果启用了syncookie，则清除选项 */
		tcp_clear_options(&tmp_opt);
		tmp_opt.saw_tstamp = 0;
	}

	if (tmp_opt.saw_tstamp && !tmp_opt.rcv_tsval) {/* 如果选项有时间戳而时间值为0，则清除它 */
		/* Some OSes (unknown ones, but I see them on web server, which
		 * contains information interesting only for windows'
		 * users) do not send their stamp in SYN. It is easy case.
		 * We simply do not advertise TS support.
		 */
		tmp_opt.saw_tstamp = 0;
		tmp_opt.tstamp_ok  = 0;
	}
	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

	/* 初始化连接请求块 */
	tcp_openreq_init(req, &tmp_opt, skb);

	req->af.v4_req.loc_addr = daddr;
	req->af.v4_req.rmt_addr = saddr;
	/* 调用tcp_v4_save_options从IP层私有控制块中获取IP选项保存到传输控制块中 */
	req->af.v4_req.opt = tcp_v4_save_options(sk, skb);
	req->class = &or_ipv4;
	if (!want_cookie)
		TCP_ECN_create_request(req, skb->h.th);

	if (want_cookie) {/* 启用了syncookie */
#ifdef CONFIG_SYN_COOKIES
		syn_flood_warning(skb);/* 每60秒进行一次警告打印 */
#endif
		/* 根据客户端IP，端口，服务端IP，端口，初始序号等要素计算服务器端初始序号 */
		isn = cookie_v4_init_sequence(sk, skb, &req->mss);
	} else if (!isn) {
		struct inet_peer *peer = NULL;

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tmp_opt.saw_tstamp && /* 进入TIME-WAIT状态 */
		    sysctl_tcp_tw_recycle &&
		    (dst = tcp_v4_route_req(sk, req)) != NULL &&
		    (peer = rt_get_peer((struct rtable *)dst)) != NULL &&
		    peer->v4daddr == saddr) {
			if (xtime.tv_sec < peer->tcp_ts_stamp + TCP_PAWS_MSL &&
			    (s32)(peer->tcp_ts - req->ts_recent) >
							TCP_PAWS_WINDOW) {
				NET_INC_STATS_BH(LINUX_MIB_PAWSPASSIVEREJECTED);
				dst_release(dst);
				goto drop_and_free;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&/* 未启动syncookie的情况下，受到synflood攻击 */
			 (sysctl_max_syn_backlog - tcp_synq_len(sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 (!peer || !peer->tcp_ts_stamp) &&
			 (!dst || !dst_metric(dst, RTAX_RTT))) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			NETDEBUG(if (net_ratelimit()) \
					printk(KERN_DEBUG "TCP: drop open "
							  "request from %u.%u."
							  "%u.%u/%u\n", \
					       NIPQUAD(saddr),
					       ntohs(skb->h.th->source)));
			dst_release(dst);
			goto drop_and_free;
		}

		isn = tcp_v4_init_sequence(sk, skb);
	}
	req->snt_isn = isn;

	/* 发送SYN+ACK给客户端 */
	if (tcp_v4_send_synack(sk, req, dst))
		goto drop_and_free;

	if (want_cookie) {/* 启用了syncookie，则不能保存连接请求块 */
	   	tcp_openreq_free(req);
	} else {
		tcp_v4_synq_add(sk, req);/* 将连接请求块保存到父传输控制块的散列表中 */
	}
	return 0;

drop_and_free:
	tcp_openreq_free(req);
drop:
	TCP_INC_STATS_BH(TCP_MIB_ATTEMPTFAILS);
	return 0;
}


/*
 * The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 */
/* 为新连接创建一个传输控制块并初始化 */
struct sock *tcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				  struct open_request *req,
				  struct dst_entry *dst)
{
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;

	if (sk_acceptq_is_full(sk))/* 已经建立但是还没有被accept的连接达到上限，不能再创建新传输块 */
		goto exit_overflow;

	/* 获取目的路由缓存 */
	if (!dst && (dst = tcp_v4_route_req(sk, req)) == NULL)
		goto exit;

	/* 创建子传输控制块，并进行初始化 */
	newsk = tcp_create_openreq_child(sk, req, skb);
	if (!newsk)
		goto exit;

	/* 设置路由缓存，确定输出网络接口的特性 */
	newsk->sk_dst_cache = dst;
	tcp_v4_setup_caps(newsk, dst);

	/* 初始化传输控制块中的一些成员 */
	newtp		      = tcp_sk(newsk);
	newinet		      = inet_sk(newsk);
	newinet->daddr	      = req->af.v4_req.rmt_addr;
	newinet->rcv_saddr    = req->af.v4_req.loc_addr;
	newinet->saddr	      = req->af.v4_req.loc_addr;
	newinet->opt	      = req->af.v4_req.opt;
	req->af.v4_req.opt    = NULL;
	newinet->mc_index     = tcp_v4_iif(skb);
	newinet->mc_ttl	      = skb->nh.iph->ttl;
	newtp->ext_header_len = 0;
	if (newinet->opt)
		newtp->ext_header_len = newinet->opt->optlen;
	newtp->ext2_header_len = dst->header_len;
	newinet->id = newtp->write_seq ^ jiffies;

	/* 根据路由中的路径MTU信息，设置控制块MSS */
	tcp_sync_mss(newsk, dst_pmtu(dst));
	/* 设置最大段长度 */
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
	/* 延时发送ACK段控制数据块中的rcv_mss */
	tcp_initialize_rcv_mss(newsk);

	/* 将子传输控制块国响应到ebash散列表中，这样可以正常接收TCP段了 */
	__tcp_v4_hash(newsk, 0);
	/* 将子传输控制块与本地端口进行绑定 */
	__tcp_inherit_port(sk, newsk);

	return newsk;

exit_overflow:
	NET_INC_STATS_BH(LINUX_MIB_LISTENOVERFLOWS);
exit:
	NET_INC_STATS_BH(LINUX_MIB_LISTENDROPS);
	dst_release(dst);
	return NULL;
}

/* 处理半连接上的ACK消息 */
static struct sock *tcp_v4_hnd_req(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	struct iphdr *iph = skb->nh.iph;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *nsk;
	struct open_request **prev;
	/* Find possible connection requests. */
	/* 根据源端口、源地址、目的地址在父传输控制块的散列表中查找相应的连接请求块 */
	struct open_request *req = tcp_v4_search_req(tp, &prev, th->source,
						     iph->saddr, iph->daddr);
	if (req)/* 如果查找到控制块，说明两次握手已经完成 */
		return tcp_check_req(sk, skb, req, prev);/* 进行第三次握手的确认 */

	/* 如果在请求散列表中没有找到传输控制块，则在ehash散列表中进行查找 */
	nsk = __tcp_v4_lookup_established(skb->nh.iph->saddr,
					  th->source,
					  skb->nh.iph->daddr,
					  ntohs(th->dest),
					  tcp_v4_iif(skb));

	if (nsk) {/* 如果在ehash中搜索成功 */
		if (nsk->sk_state != TCP_TIME_WAIT) {/* 如果处于TCP_TIME_WAIT状态，也返回给上层进行处理 */
			bh_lock_sock(nsk);
			return nsk;
		}
		/* 控制块也不在TCP_TIME_WAIT状态，说明收到的段无效，返回NULL由上层丢弃报文 */
		tcp_tw_put((struct tcp_tw_bucket *)nsk);
		return NULL;
	}

#ifdef CONFIG_SYN_COOKIES
	if (!th->rst && !th->syn && th->ack)/* 如果启用了syncookie，并且接收到的段只有ACK标志，则调用cookie_v4_check进行第三次握手的检测 */
		sk = cookie_v4_check(sk, skb, &(IPCB(skb)->opt));
#endif
	return sk;
}

/* TCP段接收校验的初始化 */
static int tcp_v4_checksum_init(struct sk_buff *skb)
{
	if (skb->ip_summed == CHECKSUM_HW) {/* 硬件完成校验和 */
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		/* 对伪首部进行校验和计算 */
		if (!tcp_v4_check(skb->h.th, skb->len, skb->nh.iph->saddr,
				  skb->nh.iph->daddr, skb->csum))
			return 0;

		NETDEBUG(if (net_ratelimit())
				printk(KERN_DEBUG "hw tcp v4 csum failed\n"));
		skb->ip_summed = CHECKSUM_NONE;
	}
	if (skb->len <= 76) {/* 小包 */
		/* 直接进行全包校验 */
		if (tcp_v4_check(skb->h.th, skb->len, skb->nh.iph->saddr,
				 skb->nh.iph->daddr,
				 skb_checksum(skb, 0, skb->len, 0)))
			return -1;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {/* 大包 */
		/* 只生成伪首部的校验和 */
		skb->csum = ~tcp_v4_check(skb->h.th, skb->len,
					  skb->nh.iph->saddr,
					  skb->nh.iph->daddr, 0);
	}
	return 0;
}


/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
/* 传输层处理TCP段的主入口 */
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	/* 当连接已经建立时，用快速路径处理报文 */
	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		TCP_CHECK_TIMER(sk);
		if (tcp_rcv_established(sk, skb, skb->h.th, skb->len))
			goto reset;
		TCP_CHECK_TIMER(sk);
		return 0;
	}

	/* 验证报文长度和校验码 */
	if (skb->len < (skb->h.th->doff << 2) || tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {/* 如果是侦听套口，则处理被动连接 */
		/* tcp_v4_hnd_req处理半连接状态的ACK消息 */
		struct sock *nsk = tcp_v4_hnd_req(sk, skb);
		if (!nsk)
			goto discard;

		if (nsk != sk) {/* tcp_v4_hnd_req返回的套接字不是侦听套接字，说明已经建立了半连接 */
			if (tcp_child_process(sk, nsk, skb))/* 初始化子传输控制块，如果失败则向客户端发送rst段 */
				goto reset;
			return 0;
		}
	}

	TCP_CHECK_TIMER(sk);
	/**
	 * 其他情况由tcp_rcv_state_process处理，包含SYN消息
	 * 当套接口处于TCP_LISTEN，TCP_SYN_RECV，TCP_SYN_SENT，TCP_FIN_WAIT1，TCP_FIN_WAIT2，TCP_LAST_ACK，TCP_CLOSING状态
	 */
	if (tcp_rcv_state_process(sk, skb, skb->h.th, skb->len))
		goto reset;
	TCP_CHECK_TIMER(sk);
	return 0;

reset:
	tcp_v4_send_reset(skb);
discard:
	kfree_skb(skb);
	/* Be careful here. If this function gets more complicated and
	 * gcc suffers from register pressure on the x86, sk (in %ebx)
	 * might be destroyed here. This current version compiles correctly,
	 * but you have been warned.
	 */
	return 0;

csum_err:
	TCP_INC_STATS_BH(TCP_MIB_INERRS);
	goto discard;
}

/*
 *	From tcp_input.c
 */
/* 传输层报文处理入口 */
int tcp_v4_rcv(struct sk_buff *skb)
{
	struct tcphdr *th;
	struct sock *sk;
	int ret;

	if (skb->pkt_type != PACKET_HOST)/* 不是发送到本机的报文直接略过 */
		goto discard_it;

	/* Count it even if it's bad */
	TCP_INC_STATS_BH(TCP_MIB_INSEGS);

	/* 从报文中取得TCP头部数据，如果由于内存不足等原因导致读取失败则退出 */
	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		goto discard_it;

	th = skb->h.th;

	if (th->doff < sizeof(struct tcphdr) / 4)/* TCP首部长度小于最小的首部长度，说明报文有异常，退出 */
		goto bad_packet;
	/* 根据报头中的长度字段读取完整的报头，如果失败退出 */
	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

	/* An explanation is required here, I think.
	 * Packet length and doff are validated by header prediction,
	 * provided case of th->doff==0 is elimineted.
	 * So, we defer the checks. */
	if ((skb->ip_summed != CHECKSUM_UNNECESSARY &&
	     tcp_v4_checksum_init(skb) < 0))/* 验证TCP首部中的校验和，如果失败则退出 */
		goto bad_packet;

	/* 根据TCP首部中的信息来设置TCP控制块中的值，这里要进行字节序的转换 */
	th = skb->h.th;
	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->when	 = 0;
	TCP_SKB_CB(skb)->flags	 = skb->nh.iph->tos;
	TCP_SKB_CB(skb)->sacked	 = 0;

	/* __tcp_v4_lookup在ehash或者bhask中查找传输控制块。 */
	sk = __tcp_v4_lookup(skb->nh.iph->saddr, th->source,
			     skb->nh.iph->daddr, ntohs(th->dest),
			     tcp_v4_iif(skb));

	if (!sk)/* 如果在两个hask中都没有找到，则退出 */
		goto no_tcp_socket;

process:/* 运行到这里，说明找到相应的传输套接口 */
	if (sk->sk_state == TCP_TIME_WAIT)/* 套接口处于TIME_WAIT状态，不应该再接收报文了，单独处理这种情况 */
		goto do_time_wait;

	/* 防火墙处理，如果没有通过安全策略则退出 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_relse;

	/* 如果传输控制块安全了过滤器，则只有符合过滤规则的报文才放行，不符合的都丢弃 */
	if (sk_filter(sk, skb, 0))
		goto discard_and_relse;

	skb->dev = NULL;/* 马上要将报文传递到传输层，该层不关心接收报文的dev，将其设置为空 */

	bh_lock_sock(sk);/* 在软中断中对套接口加锁 */
	ret = 0;
	if (!sock_owned_by_user(sk)) {/* 如果进程没有访问传输控制块，则进行正常接收 */
		if (!tcp_prequeue(sk, skb))
			ret = tcp_v4_do_rcv(sk, skb);
	} else
		sk_add_backlog(sk, skb);/* 将报文添加到后备队列中，待用户进程解锁控制块时处理 */
	bh_unlock_sock(sk);

	sock_put(sk);

	return ret;

no_tcp_socket:/* 没有相应的传输控制块，通常给对方发送RST段 */
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))/* 如果IPSec策略不允许给对方发送消息，则退出 */
		goto discard_it;

	if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {/* 如果报文被损坏，则无法向对方发送RST消息，丢弃段 */
bad_packet:
		TCP_INC_STATS_BH(TCP_MIB_INERRS);
	} else {
		tcp_v4_send_reset(skb);/* 否则发送RST段给对方 */
	}

discard_it:
	/* Discard frame. */
	kfree_skb(skb);
  	return 0;

discard_and_relse:
	sock_put(sk);
	goto discard_it;

do_time_wait:/* 处理传输控制块为TIME_WAIT状态时接收到的报文 */
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {/* 处理防火墙 */
		tcp_tw_put((struct tcp_tw_bucket *) sk);
		goto discard_it;
	}

	if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {/* 检查报文长度和校验和 */
		TCP_INC_STATS_BH(TCP_MIB_INERRS);
		tcp_tw_put((struct tcp_tw_bucket *) sk);
		goto discard_it;
	}
	/* 由tcp_timewait_state_process处理在TIME_WAIT和FIN_WAIT_2状态下接收到的段 */
	switch (tcp_timewait_state_process((struct tcp_tw_bucket *)sk,
					   skb, th, skb->len)) {
	case TCP_TW_SYN: {/* 接收到连接请求，且可接受该请求 */
		/* 根据目的地址和端口，在bhask散列表中查找对应的传输控制块 */
		struct sock *sk2 = tcp_v4_lookup_listener(skb->nh.iph->daddr,
							  ntohs(th->dest),
							  tcp_v4_iif(skb));
		if (sk2) {/* 找到控制块 */
			/* 释放tw控制块，处理正常的请求 */
			tcp_tw_deschedule((struct tcp_tw_bucket *)sk);
			tcp_tw_put((struct tcp_tw_bucket *)sk);
			sk = sk2;
			goto process;
		}
		/* Fall through to ACK */
	}
	case TCP_TW_ACK:/* 需要向对方发送ACK */
		tcp_v4_timewait_ack(sk, skb);
		break;
	case TCP_TW_RST:/* 收到无效段，需要向对方发送RST段 */
		goto no_tcp_socket;
	case TCP_TW_SUCCESS:;
	}
	goto discard_it;
}

/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static void __tcp_v4_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	sk->sk_prot->hash(sk);
}

static int tcp_v4_reselect_saddr(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;
	struct rtable *rt;
	__u32 old_saddr = inet->saddr;
	__u32 new_saddr;
	__u32 daddr = inet->daddr;

	if (inet->opt && inet->opt->srr)
		daddr = inet->opt->faddr;

	/* Query new route. */
	err = ip_route_connect(&rt, daddr, 0,
			       RT_TOS(inet->tos) | sk->sk_localroute,
			       sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->sport, inet->dport, sk);
	if (err)
		return err;

	__sk_dst_set(sk, &rt->u.dst);
	tcp_v4_setup_caps(sk, &rt->u.dst);
	tcp_sk(sk)->ext2_header_len = rt->u.dst.header_len;

	new_saddr = rt->rt_src;

	if (new_saddr == old_saddr)
		return 0;

	if (sysctl_ip_dynaddr > 1) {
		printk(KERN_INFO "tcp_v4_rebuild_header(): shifting inet->"
				 "saddr from %d.%d.%d.%d to %d.%d.%d.%d\n",
		       NIPQUAD(old_saddr),
		       NIPQUAD(new_saddr));
	}

	inet->saddr = new_saddr;
	inet->rcv_saddr = new_saddr;

	/* XXX The only one ugly spot where we need to
	 * XXX really change the sockets identity after
	 * XXX it has entered the hashes. -DaveM
	 *
	 * Besides that, it does not check for connection
	 * uniqueness. Wait for troubles.
	 */
	__tcp_v4_rehash(sk);
	return 0;
}

int tcp_v4_rebuild_header(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
	u32 daddr;
	int err;

	/* Route is OK, nothing to do. */
	if (rt)
		return 0;

	/* Reroute. */
	daddr = inet->daddr;
	if (inet->opt && inet->opt->srr)
		daddr = inet->opt->faddr;

	{
		struct flowi fl = { .oif = sk->sk_bound_dev_if,
				    .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = inet->saddr,
						.tos = RT_CONN_FLAGS(sk) } },
				    .proto = IPPROTO_TCP,
				    .uli_u = { .ports =
					       { .sport = inet->sport,
						 .dport = inet->dport } } };
						
		err = ip_route_output_flow(&rt, &fl, sk, 0);
	}
	if (!err) {
		__sk_dst_set(sk, &rt->u.dst);
		tcp_v4_setup_caps(sk, &rt->u.dst);
		tcp_sk(sk)->ext2_header_len = rt->u.dst.header_len;
		return 0;
	}

	/* Routing failed... */
	sk->sk_route_caps = 0;

	if (!sysctl_ip_dynaddr ||
	    sk->sk_state != TCP_SYN_SENT ||
	    (sk->sk_userlocks & SOCK_BINDADDR_LOCK) ||
	    (err = tcp_v4_reselect_saddr(sk)) != 0)
		sk->sk_err_soft = -err;

	return err;
}

static void v4_addr2sockaddr(struct sock *sk, struct sockaddr * uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
	struct inet_sock *inet = inet_sk(sk);

	sin->sin_family		= AF_INET;
	sin->sin_addr.s_addr	= inet->daddr;
	sin->sin_port		= inet->dport;
}

/* VJ's idea. Save last timestamp seen from this destination
 * and hold it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter synchronized
 * state.
 */

int tcp_v4_remember_stamp(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_get(sk);
	struct inet_peer *peer = NULL;
	int release_it = 0;

	if (!rt || rt->rt_dst != inet->daddr) {
		peer = inet_getpeer(inet->daddr, 1);
		release_it = 1;
	} else {
		if (!rt->peer)
			rt_bind_peer(rt, 1);
		peer = rt->peer;
	}

	if (peer) {
		if ((s32)(peer->tcp_ts - tp->rx_opt.ts_recent) <= 0 ||
		    (peer->tcp_ts_stamp + TCP_PAWS_MSL < xtime.tv_sec &&
		     peer->tcp_ts_stamp <= tp->rx_opt.ts_recent_stamp)) {
			peer->tcp_ts_stamp = tp->rx_opt.ts_recent_stamp;
			peer->tcp_ts = tp->rx_opt.ts_recent;
		}
		if (release_it)
			inet_putpeer(peer);
		return 1;
	}

	return 0;
}

int tcp_v4_tw_remember_stamp(struct tcp_tw_bucket *tw)
{
	struct inet_peer *peer = NULL;

	peer = inet_getpeer(tw->tw_daddr, 1);

	if (peer) {
		if ((s32)(peer->tcp_ts - tw->tw_ts_recent) <= 0 ||
		    (peer->tcp_ts_stamp + TCP_PAWS_MSL < xtime.tv_sec &&
		     peer->tcp_ts_stamp <= tw->tw_ts_recent_stamp)) {
			peer->tcp_ts_stamp = tw->tw_ts_recent_stamp;
			peer->tcp_ts = tw->tw_ts_recent;
		}
		inet_putpeer(peer);
		return 1;
	}

	return 0;
}

struct tcp_func ipv4_specific = {
	.queue_xmit	=	ip_queue_xmit,
	.send_check	=	tcp_v4_send_check,
	.rebuild_header	=	tcp_v4_rebuild_header,
	.conn_request	=	tcp_v4_conn_request,
	.syn_recv_sock	=	tcp_v4_syn_recv_sock,
	.remember_stamp	=	tcp_v4_remember_stamp,
	.net_header_len	=	sizeof(struct iphdr),
	.setsockopt	=	ip_setsockopt,
	.getsockopt	=	ip_getsockopt,
	.addr2sockaddr	=	v4_addr2sockaddr,
	.sockaddr_len	=	sizeof(struct sockaddr_in),
};

/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
/* 新建一个TCP socket时的回调函数。 */
static int tcp_v4_init_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_head_init(&tp->out_of_order_queue);
	tcp_init_xmit_timers(sk);
	tcp_prequeue_init(tp);

	tp->rto  = TCP_TIMEOUT_INIT;
	tp->mdev = TCP_TIMEOUT_INIT;

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = 0x7fffffff;	/* Infinity */
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache_std = tp->mss_cache = 536;

	tp->reordering = sysctl_tcp_reordering;

	sk->sk_state = TCP_CLOSE;

	sk->sk_write_space = sk_stream_write_space;
	sk->sk_use_write_queue = 1;

	tp->af_specific = &ipv4_specific;

	sk->sk_sndbuf = sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_tcp_rmem[1];

	atomic_inc(&tcp_sockets_allocated);

	return 0;
}

int tcp_v4_destroy_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_clear_xmit_timers(sk);

	/* Cleanup up the write buffer. */
  	sk_stream_writequeue_purge(sk);

	/* Cleans up our, hopefully empty, out_of_order_queue. */
  	__skb_queue_purge(&tp->out_of_order_queue);

	/* Clean prequeue, it must be empty really */
	__skb_queue_purge(&tp->ucopy.prequeue);

	/* Clean up a referenced TCP bind bucket. */
	if (tp->bind_hash)
		tcp_put_port(sk);

	/*
	 * If sendmsg cached page exists, toss it.
	 */
	if (sk->sk_sndmsg_page) {
		__free_page(sk->sk_sndmsg_page);
		sk->sk_sndmsg_page = NULL;
	}

	atomic_dec(&tcp_sockets_allocated);

	return 0;
}

EXPORT_SYMBOL(tcp_v4_destroy_sock);

#ifdef CONFIG_PROC_FS
/* Proc filesystem TCP sock list dumping. */

static inline struct tcp_tw_bucket *tw_head(struct hlist_head *head)
{
	return hlist_empty(head) ? NULL :
		list_entry(head->first, struct tcp_tw_bucket, tw_node);
}

static inline struct tcp_tw_bucket *tw_next(struct tcp_tw_bucket *tw)
{
	return tw->tw_node.next ?
		hlist_entry(tw->tw_node.next, typeof(*tw), tw_node) : NULL;
}

static void *listening_get_next(struct seq_file *seq, void *cur)
{
	struct tcp_sock *tp;
	struct hlist_node *node;
	struct sock *sk = cur;
	struct tcp_iter_state* st = seq->private;

	if (!sk) {
		st->bucket = 0;
		sk = sk_head(&tcp_listening_hash[0]);
		goto get_sk;
	}

	++st->num;

	if (st->state == TCP_SEQ_STATE_OPENREQ) {
		struct open_request *req = cur;

	       	tp = tcp_sk(st->syn_wait_sk);
		req = req->dl_next;
		while (1) {
			while (req) {
				if (req->class->family == st->family) {
					cur = req;
					goto out;
				}
				req = req->dl_next;
			}
			if (++st->sbucket >= TCP_SYNQ_HSIZE)
				break;
get_req:
			req = tp->listen_opt->syn_table[st->sbucket];
		}
		sk	  = sk_next(st->syn_wait_sk);
		st->state = TCP_SEQ_STATE_LISTENING;
		read_unlock_bh(&tp->syn_wait_lock);
	} else {
	       	tp = tcp_sk(sk);
		read_lock_bh(&tp->syn_wait_lock);
		if (tp->listen_opt && tp->listen_opt->qlen)
			goto start_req;
		read_unlock_bh(&tp->syn_wait_lock);
		sk = sk_next(sk);
	}
get_sk:
	sk_for_each_from(sk, node) {
		if (sk->sk_family == st->family) {
			cur = sk;
			goto out;
		}
	       	tp = tcp_sk(sk);
		read_lock_bh(&tp->syn_wait_lock);
		if (tp->listen_opt && tp->listen_opt->qlen) {
start_req:
			st->uid		= sock_i_uid(sk);
			st->syn_wait_sk = sk;
			st->state	= TCP_SEQ_STATE_OPENREQ;
			st->sbucket	= 0;
			goto get_req;
		}
		read_unlock_bh(&tp->syn_wait_lock);
	}
	if (++st->bucket < TCP_LHTABLE_SIZE) {
		sk = sk_head(&tcp_listening_hash[st->bucket]);
		goto get_sk;
	}
	cur = NULL;
out:
	return cur;
}

static void *listening_get_idx(struct seq_file *seq, loff_t *pos)
{
	void *rc = listening_get_next(seq, NULL);

	while (rc && *pos) {
		rc = listening_get_next(seq, rc);
		--*pos;
	}
	return rc;
}

static void *established_get_first(struct seq_file *seq)
{
	struct tcp_iter_state* st = seq->private;
	void *rc = NULL;

	for (st->bucket = 0; st->bucket < tcp_ehash_size; ++st->bucket) {
		struct sock *sk;
		struct hlist_node *node;
		struct tcp_tw_bucket *tw;

		/* We can reschedule _before_ having picked the target: */
		cond_resched_softirq();

		read_lock(&tcp_ehash[st->bucket].lock);
		sk_for_each(sk, node, &tcp_ehash[st->bucket].chain) {
			if (sk->sk_family != st->family) {
				continue;
			}
			rc = sk;
			goto out;
		}
		st->state = TCP_SEQ_STATE_TIME_WAIT;
		tw_for_each(tw, node,
			    &tcp_ehash[st->bucket + tcp_ehash_size].chain) {
			if (tw->tw_family != st->family) {
				continue;
			}
			rc = tw;
			goto out;
		}
		read_unlock(&tcp_ehash[st->bucket].lock);
		st->state = TCP_SEQ_STATE_ESTABLISHED;
	}
out:
	return rc;
}

static void *established_get_next(struct seq_file *seq, void *cur)
{
	struct sock *sk = cur;
	struct tcp_tw_bucket *tw;
	struct hlist_node *node;
	struct tcp_iter_state* st = seq->private;

	++st->num;

	if (st->state == TCP_SEQ_STATE_TIME_WAIT) {
		tw = cur;
		tw = tw_next(tw);
get_tw:
		while (tw && tw->tw_family != st->family) {
			tw = tw_next(tw);
		}
		if (tw) {
			cur = tw;
			goto out;
		}
		read_unlock(&tcp_ehash[st->bucket].lock);
		st->state = TCP_SEQ_STATE_ESTABLISHED;

		/* We can reschedule between buckets: */
		cond_resched_softirq();

		if (++st->bucket < tcp_ehash_size) {
			read_lock(&tcp_ehash[st->bucket].lock);
			sk = sk_head(&tcp_ehash[st->bucket].chain);
		} else {
			cur = NULL;
			goto out;
		}
	} else
		sk = sk_next(sk);

	sk_for_each_from(sk, node) {
		if (sk->sk_family == st->family)
			goto found;
	}

	st->state = TCP_SEQ_STATE_TIME_WAIT;
	tw = tw_head(&tcp_ehash[st->bucket + tcp_ehash_size].chain);
	goto get_tw;
found:
	cur = sk;
out:
	return cur;
}

static void *established_get_idx(struct seq_file *seq, loff_t pos)
{
	void *rc = established_get_first(seq);

	while (rc && pos) {
		rc = established_get_next(seq, rc);
		--pos;
	}		
	return rc;
}

static void *tcp_get_idx(struct seq_file *seq, loff_t pos)
{
	void *rc;
	struct tcp_iter_state* st = seq->private;

	tcp_listen_lock();
	st->state = TCP_SEQ_STATE_LISTENING;
	rc	  = listening_get_idx(seq, &pos);

	if (!rc) {
		tcp_listen_unlock();
		local_bh_disable();
		st->state = TCP_SEQ_STATE_ESTABLISHED;
		rc	  = established_get_idx(seq, pos);
	}

	return rc;
}

static void *tcp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct tcp_iter_state* st = seq->private;
	st->state = TCP_SEQ_STATE_LISTENING;
	st->num = 0;
	return *pos ? tcp_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *tcp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	void *rc = NULL;
	struct tcp_iter_state* st;

	if (v == SEQ_START_TOKEN) {
		rc = tcp_get_idx(seq, 0);
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_OPENREQ:
	case TCP_SEQ_STATE_LISTENING:
		rc = listening_get_next(seq, v);
		if (!rc) {
			tcp_listen_unlock();
			local_bh_disable();
			st->state = TCP_SEQ_STATE_ESTABLISHED;
			rc	  = established_get_first(seq);
		}
		break;
	case TCP_SEQ_STATE_ESTABLISHED:
	case TCP_SEQ_STATE_TIME_WAIT:
		rc = established_get_next(seq, v);
		break;
	}
out:
	++*pos;
	return rc;
}

static void tcp_seq_stop(struct seq_file *seq, void *v)
{
	struct tcp_iter_state* st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_OPENREQ:
		if (v) {
			struct tcp_sock *tp = tcp_sk(st->syn_wait_sk);
			read_unlock_bh(&tp->syn_wait_lock);
		}
	case TCP_SEQ_STATE_LISTENING:
		if (v != SEQ_START_TOKEN)
			tcp_listen_unlock();
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
	case TCP_SEQ_STATE_ESTABLISHED:
		if (v)
			read_unlock(&tcp_ehash[st->bucket].lock);
		local_bh_enable();
		break;
	}
}

static int tcp_seq_open(struct inode *inode, struct file *file)
{
	struct tcp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	struct tcp_iter_state *s;
	int rc;

	if (unlikely(afinfo == NULL))
		return -EINVAL;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	memset(s, 0, sizeof(*s));
	s->family		= afinfo->family;
	s->seq_ops.start	= tcp_seq_start;
	s->seq_ops.next		= tcp_seq_next;
	s->seq_ops.show		= afinfo->seq_show;
	s->seq_ops.stop		= tcp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;
	seq	     = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

int tcp_proc_register(struct tcp_seq_afinfo *afinfo)
{
	int rc = 0;
	struct proc_dir_entry *p;

	if (!afinfo)
		return -EINVAL;
	afinfo->seq_fops->owner		= afinfo->owner;
	afinfo->seq_fops->open		= tcp_seq_open;
	afinfo->seq_fops->read		= seq_read;
	afinfo->seq_fops->llseek	= seq_lseek;
	afinfo->seq_fops->release	= seq_release_private;
	
	p = proc_net_fops_create(afinfo->name, S_IRUGO, afinfo->seq_fops);
	if (p)
		p->data = afinfo;
	else
		rc = -ENOMEM;
	return rc;
}

void tcp_proc_unregister(struct tcp_seq_afinfo *afinfo)
{
	if (!afinfo)
		return;
	proc_net_remove(afinfo->name);
	memset(afinfo->seq_fops, 0, sizeof(*afinfo->seq_fops)); 
}

static void get_openreq4(struct sock *sk, struct open_request *req,
			 char *tmpbuf, int i, int uid)
{
	int ttd = req->expires - jiffies;

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p",
		i,
		req->af.v4_req.loc_addr,
		ntohs(inet_sk(sk)->sport),
		req->af.v4_req.rmt_addr,
		ntohs(req->rmt_port),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req);
}

static void get_tcp4_sock(struct sock *sp, char *tmpbuf, int i)
{
	int timer_active;
	unsigned long timer_expires;
	struct tcp_sock *tp = tcp_sk(sp);
	struct inet_sock *inet = inet_sk(sp);
	unsigned int dest = inet->daddr;
	unsigned int src = inet->rcv_saddr;
	__u16 destp = ntohs(inet->dport);
	__u16 srcp = ntohs(inet->sport);

	if (tp->pending == TCP_TIME_RETRANS) {
		timer_active	= 1;
		timer_expires	= tp->timeout;
	} else if (tp->pending == TCP_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= tp->timeout;
	} else if (timer_pending(&sp->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sp->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5d %8d %lu %d %p %u %u %u %u %d",
		i, src, srcp, dest, destp, sp->sk_state,
		tp->write_seq - tp->snd_una, tp->rcv_nxt - tp->copied_seq,
		timer_active,
		jiffies_to_clock_t(timer_expires - jiffies),
		tp->retransmits,
		sock_i_uid(sp),
		tp->probes_out,
		sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp,
		tp->rto, tp->ack.ato, (tp->ack.quick << 1) | tp->ack.pingpong,
		tp->snd_cwnd,
		tp->snd_ssthresh >= 0xFFFF ? -1 : tp->snd_ssthresh);
}

static void get_timewait4_sock(struct tcp_tw_bucket *tw, char *tmpbuf, int i)
{
	unsigned int dest, src;
	__u16 destp, srcp;
	int ttd = tw->tw_ttd - jiffies;

	if (ttd < 0)
		ttd = 0;

	dest  = tw->tw_daddr;
	src   = tw->tw_rcv_saddr;
	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %p",
		i, src, srcp, dest, destp, tw->tw_substate, 0, 0,
		3, jiffies_to_clock_t(ttd), 0, 0, 0, 0,
		atomic_read(&tw->tw_refcnt), tw);
}

#define TMPSZ 150

static int tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state* st;
	char tmpbuf[TMPSZ + 1];

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_LISTENING:
	case TCP_SEQ_STATE_ESTABLISHED:
		get_tcp4_sock(v, tmpbuf, st->num);
		break;
	case TCP_SEQ_STATE_OPENREQ:
		get_openreq4(st->syn_wait_sk, v, tmpbuf, st->num, st->uid);
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
		get_timewait4_sock(v, tmpbuf, st->num);
		break;
	}
	seq_printf(seq, "%-*s\n", TMPSZ - 1, tmpbuf);
out:
	return 0;
}

static struct file_operations tcp4_seq_fops;
static struct tcp_seq_afinfo tcp4_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "tcp",
	.family		= AF_INET,
	.seq_show	= tcp4_seq_show,
	.seq_fops	= &tcp4_seq_fops,
};

int __init tcp4_proc_init(void)
{
	return tcp_proc_register(&tcp4_seq_afinfo);
}

void tcp4_proc_exit(void)
{
	tcp_proc_unregister(&tcp4_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

struct proto tcp_prot = {
	.name			= "TCP",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= tcp_accept,
	.ioctl			= tcp_ioctl,
	.init			= tcp_v4_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.sendmsg		= tcp_sendmsg,
	.recvmsg		= tcp_recvmsg,
	.backlog_rcv		= tcp_v4_do_rcv,
	.hash			= tcp_v4_hash,
	.unhash			= tcp_unhash,
	.get_port		= tcp_v4_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.sockets_allocated	= &tcp_sockets_allocated,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header		= MAX_TCP_HEADER,
	.slab_obj_size		= sizeof(struct tcp_sock),
};



void __init tcp_v4_init(struct net_proto_family *ops)
{
	int err = sock_create_kern(PF_INET, SOCK_RAW, IPPROTO_TCP, &tcp_socket);
	if (err < 0)
		panic("Failed to create the TCP control socket.\n");
	tcp_socket->sk->sk_allocation   = GFP_ATOMIC;
	inet_sk(tcp_socket->sk)->uc_ttl = -1;

	/* Unhash it so that IP input processing does not even
	 * see it, we do not wish this socket to see incoming
	 * packets.
	 */
	tcp_socket->sk->sk_prot->unhash(tcp_socket->sk);
}

EXPORT_SYMBOL(ipv4_specific);
EXPORT_SYMBOL(tcp_bind_hash);
EXPORT_SYMBOL(tcp_bucket_create);
EXPORT_SYMBOL(tcp_hashinfo);
EXPORT_SYMBOL(tcp_inherit_port);
EXPORT_SYMBOL(tcp_listen_wlock);
EXPORT_SYMBOL(tcp_port_rover);
EXPORT_SYMBOL(tcp_prot);
EXPORT_SYMBOL(tcp_put_port);
EXPORT_SYMBOL(tcp_unhash);
EXPORT_SYMBOL(tcp_v4_conn_request);
EXPORT_SYMBOL(tcp_v4_connect);
EXPORT_SYMBOL(tcp_v4_do_rcv);
EXPORT_SYMBOL(tcp_v4_rebuild_header);
EXPORT_SYMBOL(tcp_v4_remember_stamp);
EXPORT_SYMBOL(tcp_v4_send_check);
EXPORT_SYMBOL(tcp_v4_syn_recv_sock);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(tcp_proc_register);
EXPORT_SYMBOL(tcp_proc_unregister);
#endif
EXPORT_SYMBOL(sysctl_local_port_range);
EXPORT_SYMBOL(sysctl_max_syn_backlog);
EXPORT_SYMBOL(sysctl_tcp_low_latency);

