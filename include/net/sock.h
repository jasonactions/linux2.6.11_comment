/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/config.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/security.h>

#include <linux/filter.h>

#include <asm/atomic.h>
#include <net/dst.h>
#include <net/checksum.h>

/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the sk->sk_debug debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && ((sk)->sk_debug)) \
					printk(KERN_DEBUG msg); } while (0)
#else
#define SOCK_DEBUG(sk, msg...) do { } while (0)
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
struct sock_iocb;
/* 保护传输控制块的锁结构 */
typedef struct {
	/* 同步进程和下半部的自旋锁 */
	spinlock_t		slock;
	/* 实际上只有0和1两个取值，0表示未被用户进程锁定，1表示被用户进程锁 */
	struct sock_iocb	*owner;
	/* 当软中断锁定传输控制块时，用户态进程不能获得锁，进入此等待队列 */
	wait_queue_head_t	wq;
} socket_lock_t;

#define sock_lock_init(__sk) \
do {	spin_lock_init(&((__sk)->sk_lock.slock)); \
	(__sk)->sk_lock.owner = NULL; \
	init_waitqueue_head(&((__sk)->sk_lock.wq)); \
} while(0)

struct sock;

/**
  *	struct sock_common - minimal network layer representation of sockets
  *	@skc_family - network address family
  *	@skc_state - Connection state
  *	@skc_reuse - %SO_REUSEADDR setting
  *	@skc_bound_dev_if - bound device index if != 0
  *	@skc_node - main hash linkage for various protocol lookup tables
  *	@skc_bind_node - bind hash linkage for various protocol lookup tables
  *	@skc_refcnt - reference count
  *
  *	This is the minimal network layer representation of sockets, the header
  *	for struct sock and struct tcp_tw_bucket.
  */
/**
 * 是传输控制块最小公共组成部分。由sock和inet_timewait_sock结构前面相同部分构成。
 */
struct sock_common {
	/* 所属协议族 */
	unsigned short		skc_family;
	/* 连接状态，对UDP来说，存在TCP_CLOSE状态 */
	volatile unsigned char	skc_state;
	/* 是否可以重用地址和端口 */
	unsigned char		skc_reuse;
	/* 如果不为0，则为绑定的网络接口索引，使用此接口输出报文 */
	int			skc_bound_dev_if;
	/* 通过此节点，将控制块加入到散列表中 */
	struct hlist_node	skc_node;
	/* 如果已经绑定端口，则通过此节点将控制块加入到绑定散列表中 */
	struct hlist_node	skc_bind_node;
	/* 引用计数 */
	atomic_t		skc_refcnt;
};

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common - shared layout with tcp_tw_bucket
  *	@sk_zapped - ax25 & ipx means !linked
  *	@sk_shutdown - mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_use_write_queue - wheter to call sk->sk_write_space in sock_wfree
  *	@sk_userlocks - %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock -	synchronizer
  *	@sk_rcvbuf - size of receive buffer in bytes
  *	@sk_sleep - sock wait queue
  *	@sk_dst_cache - destination cache
  *	@sk_dst_lock - destination cache lock
  *	@sk_policy - flow policy
  *	@sk_rmem_alloc - receive queue bytes committed
  *	@sk_receive_queue - incoming packets
  *	@sk_wmem_alloc - transmit queue bytes committed
  *	@sk_write_queue - Packet sending queue
  *	@sk_omem_alloc - "o" is "option" or "other"
  *	@sk_wmem_queued - persistent queue size
  *	@sk_forward_alloc - space allocated forward
  *	@sk_allocation - allocation mode
  *	@sk_sndbuf - size of send buffer in bytes
  *	@sk_flags - %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE, %SO_OOBINLINE settings
  *	@sk_no_check - %SO_NO_CHECK setting, wether or not checkup packets
  *	@sk_debug - %SO_DEBUG setting
  *	@sk_rcvtstamp - %SO_TIMESTAMP setting
  *	@sk_no_largesend - whether to sent large segments or not
  *	@sk_route_caps - route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_lingertime - %SO_LINGER l_linger setting
  *	@sk_hashent - hash entry in several tables (e.g. tcp_ehash)
  *	@sk_backlog - always used with the per-socket spinlock held
  *	@sk_callback_lock - used with the callbacks in the end of this struct
  *	@sk_error_queue - rarely used
  *	@sk_prot - protocol handlers inside a network family
  *	@sk_err - last error
  *	@sk_err_soft - errors that don't cause failure but are the cause of a persistent failure not just 'timed out'
  *	@sk_ack_backlog - current listen backlog
  *	@sk_max_ack_backlog - listen backlog set in listen()
  *	@sk_priority - %SO_PRIORITY setting
  *	@sk_type - socket type (%SOCK_STREAM, etc)
  *	@sk_localroute - route locally only, %SO_DONTROUTE setting
  *	@sk_protocol - which protocol this socket belongs in this network family
  *	@sk_peercred - %SO_PEERCRED setting
  *	@sk_rcvlowat - %SO_RCVLOWAT setting
  *	@sk_rcvtimeo - %SO_RCVTIMEO setting
  *	@sk_sndtimeo - %SO_SNDTIMEO setting
  *	@sk_filter - socket filtering instructions
  *	@sk_protinfo - private area, net family specific, when not using slab
  *	@sk_slab - the slabcache this instance was allocated from
  *	@sk_timer - sock cleanup timer
  *	@sk_stamp - time stamp of last packet received
  *	@sk_socket - Identd and reporting IO signals
  *	@sk_user_data - RPC layer private data
  *	@sk_owner - module that owns this socket
  *	@sk_sndmsg_page - cached page for sendmsg
  *	@sk_sndmsg_off - cached offset for sendmsg
  *	@sk_send_head - front of stuff to transmit
  *	@sk_write_pending - a write to stream socket waits to start
  *	@sk_queue_shrunk - write queue has been shrunk recently
  *	@sk_state_change - callback to indicate change in the state of the sock
  *	@sk_data_ready - callback to indicate there is data to be processed
  *	@sk_write_space - callback to indicate there is bf sending space available
  *	@sk_error_report - callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv - callback to process the backlog
  *	@sk_destruct - called at sock freeing time, i.e. when all refcnt == 0
 */
/**
 * 公用的网络描述块，构成传输控制块的基础。与具体的协议族无关。
 * 描述各种协议族传输层协议的公共部分。
 */
struct sock {
	/*
	 * Now struct tcp_tw_bucket also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	/**
	 * 公共信息，必须放在最前面
	 */
	struct sock_common	__sk_common;
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_node			__sk_common.skc_node
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_refcnt		__sk_common.skc_refcnt
	volatile unsigned char	sk_zapped;
	/* 关闭套接口的标志，是仅仅关闭读写还是读写全关闭，如RCV_SHUTDOWN */
	unsigned char		sk_shutdown;
	unsigned char		sk_use_write_queue;
	/**
	 * 标识传输层的些状态。如:
	 *		SOCK_SNDBUF_LOCK:	用户通过套接口选项设置了发送缓冲区大小
	 *		SOCK_RCVBUF_LOCK:	用户通过套接口选项设置了接收缓冲区大小
	 *		SOCK_BINDADDR_LOCK:	用户绑定了本地地址
	 *		SOCK_BINDPORT_LOCK:	用户绑定了本地端口
	 */
	unsigned char		sk_userlocks;
	/**
	 * 同步锁，一是用于用户进程读取数据与网络层向传输层传递数据之间的同步。二是用于软中断之间同步访问传输块。
	 */
	socket_lock_t		sk_lock;
	/* 接收缓冲区大小的上限 */
	int			sk_rcvbuf;
	/**
	 * 等待队列。等待连接、等待输出缓冲区、等待读数据的线程都会暂存在此队列中。
	 */
	wait_queue_head_t	*sk_sleep;
	/** 
	 * 目的路由缓存。当断开连接、重传、重新绑定端口时，才重新获得路由。
	 */
	struct dst_entry	*sk_dst_cache;
	/**
	 * 操作目的路由缓存的读写锁
	 */
	rwlock_t		sk_dst_lock;
	/* 与IPSEC相关的传输策略 */
	struct xfrm_policy	*sk_policy[2];
	/**
	 * 接收队列中所有报文数据的总长度
	 */
	atomic_t		sk_rmem_alloc;
	/**
	 * 接收队列，等待用户进程读取。
	 * 对TCP来说，只有接收到的数据不能直接复制到用户空间时才缓存到此。
	 */
	struct sk_buff_head	sk_receive_queue;
	/* 为发送而分配的所有SKB数据区的总长度 */
	atomic_t		sk_wmem_alloc;
	/**
	 * 向内核添加数据时，被缓冲的数据可能会在内核中形成多个待发送的IP分片。
	 * 通过该指针将这些分片缓冲区连接起来。
	 * 这是ip_append_data函数的输出结果。
	 * 发送队列，对TCP来说，是重传队列和发送队列。sk_send_head之前是重传队列，之后是发送队列。
	 */
	struct sk_buff_head	sk_write_queue;
	/**
	 * 分配辅助缓冲区的上限。包括进行设置选项、设置过滤时分配的内存和组播设置等。
	 */
	atomic_t		sk_omem_alloc;
	/**
	 * 发送队列中所有报文数据的总长度，目前仅用于TCP.
	 */
	int			sk_wmem_queued;
	/**
	 * 预分配缓存长度。目前仅用于TCP.
	 * 当分配的缓存小于此值时，分配必然成功。否则需要确认分配的缓存是否有效。
	 */
	int			sk_forward_alloc;
	/**
	 * 内存分配标志。如GFP_KERNEL
	 */
	unsigned int		sk_allocation;
	/**
	 * 发送缓冲区长度上限。发送队列中报文数据总长度不能超过此值。
	 */
	int			sk_sndbuf;
	/**
	 * 一些状态和标志。如SOCK_DEAD
	 */
	unsigned long 		sk_flags;
	/* 是否对UDP和RAWSOCK进行校验和，参见SO_NO_CHECK选项 */
	char		 	sk_no_check;
	unsigned char		sk_debug;
	unsigned char		sk_rcvtstamp;
	unsigned char		sk_no_largesend;
	/* 目的路由网络设备的特性 */
	int			sk_route_caps;
	/**
	 * 关闭套接口前发送剩余数据的时间。参见SO_LINGER选项。
	 */
	unsigned long	        sk_lingertime;
	int			sk_hashent;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 */
	/**
	 * 后备接收队列。目前仅用于TCP。当传输控制块被用户锁定时，接收到的数据都存放到此队列中
	 */
	struct {
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	/**
	 * 保护一些数据成员，在IPV4和IPV6协议栈切换时使用。
	 */
	rwlock_t		sk_callback_lock;
	/**
	 * 错误链表。存放详细的出错信息。参见IP_RECVERR选项。
	 */
	struct sk_buff_head	sk_error_queue;
	/* 传输层接口 */
	struct proto		*sk_prot;
	/**
	 * 记录当前传输层最后一次致命错误的错误码。应用层读取后恢复。
	 */
	int			sk_err,
	/**
	 * 非致命性错误，或者用作在传输控制块被锁定时记录错误的后备成员。
	 */
				sk_err_soft;
	/**
	 * 当前已经建立的连接数。等待用户调用accept。
	 */
	unsigned short		sk_ack_backlog;
	/**
	 * 连接队列长度的上限。
	 */
	unsigned short		sk_max_ack_backlog;
	/**
	 * 用于设置数据报的QoS类别。参见SO_PRIORITY和IP_TOS选项。
	 */
	__u32			sk_priority;
	/* 套接口类型，如SOCK_STREAM */
	unsigned short		sk_type;
	unsigned char		sk_localroute;
	/* 所属的协议 */
	unsigned char		sk_protocol;
	/**
	 * 连接至该套接字的外部进程的身份认证，主要用于PF_UNIX协议族。参见SO_PEERCRED选项。
	 */
	struct ucred		sk_peercred;
	/* 接收缓存下限值 */
	int			sk_rcvlowat;
	/**
	 * 套接口层接收超时时间。参见SO_RCVTIMEO选项。
	 */
	long			sk_rcvtimeo;
	/**
	 * 套接口层发送超时时间。参见SO_SNDTIMEO选项。
	 */
	long			sk_sndtimeo;
	/**
	 * 套接口过滤器。
	 */
	struct sk_filter      	*sk_filter;
	/**
	 * 控制块私有数据。
	 */
	void			*sk_protinfo;
	kmem_cache_t		*sk_slab;
	/**
	 * 根据TCP的不同状态，来实现连接定时器、FIN_WAIT_2定时器和TCP保活定时器。
	 */
	struct timer_list	sk_timer;
	/**
	 * 在未启用SOCK_RCVTSTAMP选项时，记录报文接收数据到应用层的时间戳。
	 * 当启用SOCK_RCVTSTAMP选项时，接收数据的时间戳记录在SKB的tstamp中。
	 */
	struct timeval		sk_stamp;
	/**
	 * 指向相关套接口的指针
	 */
	struct socket		*sk_socket;
	/**
	 * RPC层存放私有数据的指针，IPV4中未使用。
	 */
	void			*sk_user_data;
	struct module		*sk_owner;
	/**
	 * 当支持分散/聚集IO时，上一次调用ip_append_data写入的页面。
	 */
	struct page		*sk_sndmsg_page;
	/**
	 * 当支持分散/聚集IO时，上一次调用ip_append_data写入的页面位置。
	 */
	__u32			sk_sndmsg_off;
	struct sk_buff		*sk_send_head;
	/**
	 * 表示有数据即将写入套接口，也就是有写数据的请求。
	 */
	int			sk_write_pending;
	/**
	 * 指向sk_security_struct结构，安全模块使用。
	 */
	void			*sk_security;
	__u8			sk_queue_shrunk;
	/* three bytes hole, try to pack */
	/**
	 * 当传输控制块状态发生变化时，唤醒那些等待本套接口的进程。在创建套接口时初始化。
	 * IPV4中sock_def_readable。
	 */
	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk, int bytes);
	/**
	 * 在发送缓存大小发生变化时，或者套接口被释放时，唤醒等待本套接口的进程。
	 * ipv4默认为sock_def_write_space，TCP中默认为sk_stream_write_space。
	 */
	void			(*sk_write_space)(struct sock *sk);
	/**
	 * 报告错误的回调函数。如果等待该套接口的进程正在睡眠，则将其唤醒。
	 * ipv4中为sock_def_error_report。
	 */
	void			(*sk_error_report)(struct sock *sk);
	/**
	 * 后备队列接收函数。用于ipv4和PPPoE。
	 */
  	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);  
	/**
	 * 在释放传输控制块时，回调此函数释放相关资源。
	 * ipv4中为inet_sock_destruct。
	 */
	void                    (*sk_destruct)(struct sock *sk);
};

/*
 * Hashed lists helper routines
 */
static inline struct sock *__sk_head(struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *sk_next(struct sock *sk)
{
	return sk->sk_node.next ?
		hlist_entry(sk->sk_node.next, struct sock, sk_node) : NULL;
}

static inline int sk_unhashed(struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline int sk_hashed(struct sock *sk)
{
	return sk->sk_node.pprev != NULL;
}

static __inline__ void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static __inline__ void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

static __inline__ int __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return 1;
	}
	return 0;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static inline void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt);
}

static __inline__ int sk_del_node_init(struct sock *sk)
{
	int rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static __inline__ void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static __inline__ void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static __inline__ void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static __inline__ void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_node)
#define sk_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_from(__sk, node, sk_node)
#define sk_for_each_continue(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_continue(__sk, node, sk_node)
#define sk_for_each_safe(__sk, node, tmp, list) \
	hlist_for_each_entry_safe(__sk, node, tmp, list, sk_node)
#define sk_for_each_bound(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_bind_node)

/* Sock flags */
enum sock_flags {
	/* 连接已经断开，套接口即将关闭 */
	SOCK_DEAD,
	/* 标志TCP会话即将结束，在接收到FIN报文时设置 */
	SOCK_DONE,
	/* 将带外数据放入正常数据流 */
	SOCK_URGINLINE,
	/* 启动了保活选项 */
	SOCK_KEEPOPEN,
	/* 关闭套接口前发送剩余数据的时间 */
	SOCK_LINGER,
	/* 控制块已经释放，IPV4未使用 */
	SOCK_DESTROY,
	/* 套接口支持收发广播报文 */
	SOCK_BROADCAST,
	/* 是否将段的接收时间作为时间戳 */
	SOCK_TIMESTAMP,
};

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

static inline int sk_acceptq_is_full(struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(struct sock *sk)
{
	return sk->sk_wmem_queued / 2;
}

static inline int sk_stream_wspace(struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

extern void sk_stream_write_space(struct sock *sk);

static inline int sk_stream_memory_free(struct sock *sk)
{
	return sk->sk_wmem_queued < sk->sk_sndbuf;
}

extern void sk_stream_rfree(struct sk_buff *skb);

/**
 * 将接收的skb报文与tcp控制接口关联起来。
 */
static inline void sk_stream_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb->sk = sk;
	skb->destructor = sk_stream_rfree;/* 设置释放接口 */
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);/* 增加接收缓存长度 */
	sk->sk_forward_alloc -= skb->truesize;/* 减少预分配缓存长度 */
}

static inline void sk_stream_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_queue_shrunk   = 1;
	sk->sk_wmem_queued   -= skb->truesize;
	sk->sk_forward_alloc += skb->truesize;
	__kfree_skb(skb);
}

/* The per-socket spinlock must be held here. */
#define sk_add_backlog(__sk, __skb)				\
do {	if (!(__sk)->sk_backlog.tail) {				\
		(__sk)->sk_backlog.head =			\
		     (__sk)->sk_backlog.tail = (__skb);		\
	} else {						\
		((__sk)->sk_backlog.tail)->next = (__skb);	\
		(__sk)->sk_backlog.tail = (__skb);		\
	}							\
	(__skb)->next = NULL;					\
} while(0)

#define sk_wait_event(__sk, __timeo, __condition)		\
({	int rc;							\
	release_sock(__sk);					\
	rc = __condition;					\
	if (!rc) {						\
		*(__timeo) = schedule_timeout(*(__timeo));	\
		rc = __condition;				\
	}							\
	lock_sock(__sk);					\
	rc;							\
})

extern int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
extern int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
extern void sk_stream_wait_close(struct sock *sk, long timeo_p);
extern int sk_stream_error(struct sock *sk, int flags, int err);
extern void sk_stream_kill_queues(struct sock *sk);

extern int sk_wait_data(struct sock *sk, long *timeo);

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 * transport -> network interface is defined by struct inet_proto
 */
/**
 * 传输层接口 
 * 实现传输层的操作和从传输层到网络层调用的跳转。
 */
struct proto {
	/**
	 * 在关闭套接口时使用。
	 */
	void			(*close)(struct sock *sk, 
					long timeout);
	int			(*connect)(struct sock *sk,
				        struct sockaddr *uaddr, 
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept) (struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	/**
	 * 传输层初始化接口。在创建套接口时。在inet_create中调用。
	 */
	int			(*init)(struct sock *sk);
	int			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval,
					int optlen);
	int			(*getsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval, 
					int __user *option);  	 
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					size_t len, int noblock, int flags, 
					int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk, 
					struct sockaddr *uaddr, int addr_len);

	/**
	 * 用于接收预备队列和后备队列中的TCP段。
	 */
	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	/**
	 * 将套接口添加到散列表的接口。如tcp_v4_hash
	 */
	void			(*hash)(struct sock *sk);
	/**
	 * 将套接口从散列表中移除。如tcp_unhash
	 */
	void			(*unhash)(struct sock *sk);
	/**
	 * 将套接口与端口进行绑定。如果snum为0，表示可以选择任意端口。
	 */
	int			(*get_port)(struct sock *sk, unsigned short snum);

	/* Memory pressure */
	/**
	 * 只有TCP使用。当缓存区分配的内存超过tcp_mem[1]时，调用此函数进入告警状态。
	 * TCP中回调是tcp_enter_memory_pressure
	 */
	void			(*enter_memory_pressure)(void);
	/**
	 * 只有TCP使用。表示整个TCP层为缓存区分配的内存(包括输入队列)。指向变量tcp_memory_allocated。
	 */
	atomic_t		*memory_allocated;	/* Current allocated memory. */
	/**
	 * 只有TCP使用，表示整个TCP层创建的套接口数目。指向tcp_sockets_allocated。
	 */
	atomic_t		*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the sk_stream_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	/**
	 * 指向标志tcp_memory_pressure，表示是否进入缓冲区警告状态。
	 */
	int			*memory_pressure;
	/**
	 * 指向sysctl_tcp_mem
	 */
	int			*sysctl_mem;
	/**
	 * 指向sysctl_tcp_wmem
	 */
	int			*sysctl_wmem;
	/**
	 * 指向sysctl_tcp_rmem
	 */
	int			*sysctl_rmem;
	/**
	 * 只有TCP使用，表示TCP首部的最大长度，包括所有选项。
	 */
	int			max_header;

	/**
	 * 分配传输控制块的slab高速缓存。
	 */
	kmem_cache_t		*slab;
	/**
	 * 传输控制块大小。如果创建kmem_cache_t失败，则通过kmalloc来分配内存，需要此参数。
	 */
	int			slab_obj_size;

	struct module		*owner;

	/**
	 * 协议名称，如"TCP"
	 */
	char			name[32];

	/**
	 * 统计每个CPU中proto的状态。
	 */
	struct {
		int inuse;
		u8  __pad[SMP_CACHE_BYTES - sizeof(int)];
	} stats[NR_CPUS];
};

extern int sk_alloc_slab(struct proto *prot, char *name);
extern void sk_free_slab(struct proto *prot);

static inline void sk_alloc_slab_error(struct proto *proto)
{
	printk(KERN_CRIT "%s: Can't create sock SLAB cache!\n", proto->name);
}

static __inline__ void sk_set_owner(struct sock *sk, struct module *owner)
{
	/*
	 * One should use sk_set_owner just once, after struct sock creation,
	 * be it shortly after sk_alloc or after a function that returns a new
	 * struct sock (and that down the call chain called sk_alloc), e.g. the
	 * IPv4 and IPv6 modules share tcp_create_openreq_child, so if
	 * tcp_create_openreq_child called sk_set_owner IPv6 would have to
	 * change the ownership of this struct sock, with one not needed
	 * transient sk_set_owner call.
	 */
	BUG_ON(sk->sk_owner != NULL);

	sk->sk_owner = owner;
	__module_get(owner);
}

/* Called with local bh disabled */
static __inline__ void sock_prot_inc_use(struct proto *prot)
{
	prot->stats[smp_processor_id()].inuse++;
}

static __inline__ void sock_prot_dec_use(struct proto *prot)
{
	prot->stats[smp_processor_id()].inuse--;
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
#define PROT_SOCK	1024

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

/* sock_iocb: used to kick off async processing of socket ios */
struct sock_iocb {
	struct list_head	list;

	int			flags;
	int			size;
	struct socket		*sock;
	struct sock		*sk;
	struct scm_cookie	*scm;
	struct msghdr		*msg, async_msg;
	struct iovec		async_iov;
	struct kiocb		*kiocb;
};

static inline struct sock_iocb *kiocb_to_siocb(struct kiocb *iocb)
{
	return (struct sock_iocb *)iocb->private;
}

static inline struct kiocb *siocb_to_kiocb(struct sock_iocb *si)
{
	return si->kiocb;
}

/**
 * socket套接口文件的inode
 */
struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

extern void __sk_stream_mem_reclaim(struct sock *sk);
extern int sk_stream_mem_schedule(struct sock *sk, int size, int kind);

#define SK_STREAM_MEM_QUANTUM ((int)PAGE_SIZE)

static inline int sk_stream_pages(int amt)
{
	return (amt + SK_STREAM_MEM_QUANTUM - 1) / SK_STREAM_MEM_QUANTUM;
}

/* 当断开连接、释放传输控制块、关闭TCP套接口时，释放缓存 */
static inline void sk_stream_mem_reclaim(struct sock *sk)
{
	if (sk->sk_forward_alloc >= SK_STREAM_MEM_QUANTUM)/* 当预分配缓存大于一个页面时才进行回收 */
		__sk_stream_mem_reclaim(sk);
}

static inline void sk_stream_writequeue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL)
		sk_stream_free_skb(sk, skb);
	sk_stream_mem_reclaim(sk);
}

static inline int sk_stream_rmem_schedule(struct sock *sk, struct sk_buff *skb)
{
	return (int)skb->truesize <= sk->sk_forward_alloc ||
		sk_stream_mem_schedule(sk, skb->truesize, 1);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */
/* 在软中断中，判断传输控制块是否被用户态进程锁定 */
#define sock_owned_by_user(sk)	((sk)->sk_lock.owner)

extern void FASTCALL(lock_sock(struct sock *sk));
extern void FASTCALL(release_sock(struct sock *sk));

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

extern struct sock *		sk_alloc(int family, int priority, int zero_it,
					 kmem_cache_t *slab);
extern void			sk_free(struct sock *sk);

extern struct sk_buff		*sock_wmalloc(struct sock *sk,
					      unsigned long size, int force,
					      int priority);
extern struct sk_buff		*sock_rmalloc(struct sock *sk,
					      unsigned long size, int force,
					      int priority);
extern void			sock_wfree(struct sk_buff *skb);
extern void			sock_rfree(struct sk_buff *skb);

extern int			sock_setsockopt(struct socket *sock, int level,
						int op, char __user *optval,
						int optlen);

extern int			sock_getsockopt(struct socket *sock, int level,
						int op, char __user *optval, 
						int __user *optlen);
extern struct sk_buff 		*sock_alloc_send_skb(struct sock *sk,
						     unsigned long size,
						     int noblock,
						     int *errcode);
extern void *sock_kmalloc(struct sock *sk, int size, int priority);
extern void sock_kfree_s(struct sock *sk, void *mem, int size);
extern void sk_send_sigurg(struct sock *sk);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
extern int                      sock_no_bind(struct socket *, 
					     struct sockaddr *, int);
extern int                      sock_no_connect(struct socket *,
						struct sockaddr *, int, int);
extern int                      sock_no_socketpair(struct socket *,
						   struct socket *);
extern int                      sock_no_accept(struct socket *,
					       struct socket *, int);
extern int                      sock_no_getname(struct socket *,
						struct sockaddr *, int *, int);
extern unsigned int             sock_no_poll(struct file *, struct socket *,
					     struct poll_table_struct *);
extern int                      sock_no_ioctl(struct socket *, unsigned int,
					      unsigned long);
extern int			sock_no_listen(struct socket *, int);
extern int                      sock_no_shutdown(struct socket *, int);
extern int			sock_no_getsockopt(struct socket *, int , int,
						   char __user *, int __user *);
extern int			sock_no_setsockopt(struct socket *, int, int,
						   char __user *, int);
extern int                      sock_no_sendmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t);
extern int                      sock_no_recvmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t, int);
extern int			sock_no_mmap(struct file *file,
					     struct socket *sock,
					     struct vm_area_struct *vma);
extern ssize_t			sock_no_sendpage(struct socket *sock,
						struct page *page,
						int offset, size_t size, 
						int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
extern int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
extern int sock_common_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags);
extern int sock_common_setsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int optlen);

extern void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */
 
/* Initialise core socket variables */
extern void sock_init_data(struct socket *sock, struct sock *sk);

/**
 *	sk_filter - run a packet through a socket filter
 *	@sk: sock associated with &sk_buff
 *	@skb: buffer to filter
 *	@needlock: set to 1 if the sock is not locked by caller.
 *
 * Run the filter code and then cut skb->data to correct size returned by
 * sk_run_filter. If pkt_len is 0 we toss packet. If skb->len is smaller
 * than pkt_len we keep whole skb->data. This is the socket level
 * wrapper to sk_run_filter. It returns 0 if the packet should
 * be accepted or -EPERM if the packet should be tossed.
 *
 */

static inline int sk_filter(struct sock *sk, struct sk_buff *skb, int needlock)
{
	int err;
	
	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;
	
	if (sk->sk_filter) {
		struct sk_filter *filter;
		
		if (needlock)
			bh_lock_sock(sk);
		
		filter = sk->sk_filter;
		if (filter) {
			int pkt_len = sk_run_filter(skb, filter->insns,
						    filter->len);
			if (!pkt_len)
				err = -EPERM;
			else
				skb_trim(skb, pkt_len);
		}

		if (needlock)
			bh_unlock_sock(sk);
	}
	return err;
}

/**
 *	sk_filter_release: Release a socket filter
 *	@sk: socket
 *	@fp: filter to remove
 *
 *	Remove a filter from a socket and release its resources.
 */
 
static inline void sk_filter_release(struct sock *sk, struct sk_filter *fp)
{
	unsigned int size = sk_filter_len(fp);

	atomic_sub(size, &sk->sk_omem_alloc);

	if (atomic_dec_and_test(&fp->refcnt))
		kfree(fp);
}

static inline void sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
	atomic_inc(&fp->refcnt);
	atomic_add(sk_filter_len(fp), &sk->sk_omem_alloc);
}

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
/* 递减传输层接口引用计数 */
static inline void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}

/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk->sk_socket = NULL;
	sk->sk_sleep  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_sleep = &parent->wait;
	parent->sk = sk;
	sk->sk_socket = parent;
	write_unlock_bh(&sk->sk_callback_lock);
}

extern int sock_i_uid(struct sock *sk);
extern unsigned long sock_i_ino(struct sock *sk);

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return sk->sk_dst_cache;
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	read_lock(&sk->sk_dst_lock);
	dst = sk->sk_dst_cache;
	if (dst)
		dst_hold(dst);
	read_unlock(&sk->sk_dst_lock);
	return dst;
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	old_dst = sk->sk_dst_cache;
	sk->sk_dst_cache = dst;
	dst_release(old_dst);
}

/**
 * 一旦连接套接字后，这个函数可以把用于抵达目的地的路径存放在sock结构中。
 */
static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	write_lock(&sk->sk_dst_lock);
	__sk_dst_set(sk, dst);
	write_unlock(&sk->sk_dst_lock);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	struct dst_entry *old_dst;

	old_dst = sk->sk_dst_cache;
	sk->sk_dst_cache = NULL;
	dst_release(old_dst);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	write_lock(&sk->sk_dst_lock);
	__sk_dst_reset(sk);
	write_unlock(&sk->sk_dst_lock);
}

/**
 * 测试路径的有效性，如果路径有效，返回它。
 */
static inline struct dst_entry *
__sk_dst_check(struct sock *sk, u32 cookie)
{
	struct dst_entry *dst = sk->sk_dst_cache;

	if (dst && dst->obsolete && dst->ops->check(dst, cookie) == NULL) {
		sk->sk_dst_cache = NULL;
		return NULL;
	}

	return dst;
}

/**
 * 测试路径的有效性，如果路径有效，返回它。
 */
static inline struct dst_entry *
sk_dst_check(struct sock *sk, u32 cookie)
{
	struct dst_entry *dst = sk_dst_get(sk);

	if (dst && dst->obsolete && dst->ops->check(dst, cookie) == NULL) {
		sk_dst_reset(sk);
		return NULL;
	}

	return dst;
}

static inline void sk_charge_skb(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_wmem_queued   += skb->truesize;
	sk->sk_forward_alloc -= skb->truesize;
}

static inline int skb_copy_to_page(struct sock *sk, char __user *from,
				   struct sk_buff *skb, struct page *page,
				   int off, int copy)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		unsigned int csum = csum_and_copy_from_user(from,
						     page_address(page) + off,
							    copy, 0, &err);
		if (err)
			return err;
		skb->csum = csum_block_add(skb->csum, csum, skb->len);
	} else if (copy_from_user(page_address(page) + off, from, copy))
		return -EFAULT;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk->sk_forward_alloc -= copy;
	return 0;
}

/*
 * 	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 * 	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
/**
 * 设置skb相关的传输控制块
 */
static inline void skb_set_owner_w
(struct sk_buff *skb, struct sock *sk)
{
	sock_hold(sk);/* 增加控制块的引用计数 */
	skb->sk = sk;
	skb->destructor = sock_wfree;/* 挂接skb的释放回调函数，主要是释放skb时增加控制块的发送缓存限额 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);/* 增加发送缓冲总额 */
}

/* 设置接收到的UDP报文的属主 */
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb->sk = sk;
	skb->destructor = sock_rfree;/* 设置回调函数 */
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);/* 增加接收缓存总数 */
}

extern void sk_reset_timer(struct sock *sk, struct timer_list* timer,
			   unsigned long expires);

extern void sk_stop_timer(struct sock *sk, struct timer_list* timer);

/* 将接收到的数据报添加到传输控制块的接收队列中 */
static inline int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int err = 0;
	int skb_len;

	/* Cast skb->rcvbuf to unsigned... It's pointless, but reduces
	   number of warnings when compiling with -W --ANK
	 */
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned)sk->sk_rcvbuf) {/* 检测当前用于接收的缓存大小是否已经达到了接收缓冲区大小的上限 */
		err = -ENOMEM;
		goto out;
	}

	/* It would be deadlock, if sock_queue_rcv_skb is used
	   with socket lock! We assume that users of this
	   function are lock free.
	*/
	err = sk_filter(sk, skb, 1);/* 如果安装了过滤器，则只接收满足过滤条件的报文 */
	if (err)
		goto out;

	skb->dev = NULL;/* 送到UDP层后，不需要再关注dev字段了 */
	skb_set_owner_r(skb, sk);/* 设置报文属主 */

	/* Cache the SKB length before we tack it onto the receive
	 * queue.  Once it is added it no longer belongs to us and
	 * may be freed by other threads of control pulling packets
	 * from the queue.
	 */
	skb_len = skb->len;

	/* 将报文添加到接收队列的尾部 */
	skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD))/* 如果套接口未关闭，则唤醒等待的进程 */
		sk->sk_data_ready(sk, skb_len);
out:
	return err;
}

static inline int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
	/* Cast skb->rcvbuf to unsigned... It's pointless, but reduces
	   number of warnings when compiling with -W --ANK
	 */
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned)sk->sk_rcvbuf)
		return -ENOMEM;
	skb_set_owner_r(skb, sk);
	skb_queue_tail(&sk->sk_error_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb->len);
	return 0;
}

/*
 *	Recover an error report and clear atomically
 */
 
static inline int sock_error(struct sock *sk)
{
	int err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
		if (amt < 0) 
			amt = 0;
	}
	return amt;
}

/**
 * 将SIGIO或SIGURG信号发送给套口上等待的线程
 *		sk:		该套口上有事件
 *		how:	0-检查是否有rcv调用的进程，1-检查发送队列是否已经达到了上限，2-不做任何检查，直接发送SIGIO信号，3-向等待进程发送SIGURG信号。
 *		band:	通知进程的IO读写类型，如POLL_IN
 */
static inline void sk_wake_async(struct sock *sk, int how, int band)
{
	if (sk->sk_socket && sk->sk_socket->fasync_list)/* 异步等待通知队列有效 */
		sock_wake_async(sk->sk_socket, how, band);
}

#define SOCK_MIN_SNDBUF 2048
#define SOCK_MIN_RCVBUF 256

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued / 2);
		sk->sk_sndbuf = max(sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

/* 分配发送缓冲区 */
static inline struct sk_buff *sk_stream_alloc_pskb(struct sock *sk,
						   int size, int mem, int gfp)
{
	/* 分配指定长度的skb */
	struct sk_buff *skb = alloc_skb(size + sk->sk_prot->max_header, gfp);

	if (skb) {
		skb->truesize += mem;
		if (sk->sk_forward_alloc >= (int)skb->truesize ||
		    sk_stream_mem_schedule(sk, skb->truesize, 0)) {/* 确认分配的缓存没有超过限制 */
			skb_reserve(skb, sk->sk_prot->max_header);/* 返回可用的发送缓存 */
			return skb;
		}
		__kfree_skb(skb);
	} else {
		/* 内存不足，进入警告状态，同时调整发送缓存大小上限 */
		sk->sk_prot->enter_memory_pressure();
		sk_stream_moderate_sndbuf(sk);
	}
	return NULL;
}

static inline struct sk_buff *sk_stream_alloc_skb(struct sock *sk,
						  int size, int gfp)
{
	return sk_stream_alloc_pskb(sk, size, 0, gfp);
}

static inline struct page *sk_stream_alloc_page(struct sock *sk)
{
	struct page *page = NULL;

	if (sk->sk_forward_alloc >= (int)PAGE_SIZE ||
	    sk_stream_mem_schedule(sk, PAGE_SIZE, 0))
		page = alloc_pages(sk->sk_allocation, 0);
	else {
		sk->sk_prot->enter_memory_pressure();
		sk_stream_moderate_sndbuf(sk);
	}
	return page;
}

#define sk_stream_for_retrans_queue(skb, sk)				\
		for (skb = (sk)->sk_write_queue.next;			\
		     (skb != (sk)->sk_send_head) &&			\
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline int sock_writeable(const struct sock *sk) 
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf / 2);
}

static inline int gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

static __inline__ void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	struct timeval *stamp = &skb->stamp;
	if (sk->sk_rcvtstamp) { 
		/* Race occurred between timestamp enabling and packet
		   receiving.  Fill in the current time for now. */
		if (stamp->tv_sec == 0)
			do_gettimeofday(stamp);
		put_cmsg(msg, SOL_SOCKET, SO_TIMESTAMP, sizeof(struct timeval),
			 stamp);
	} else
		sk->sk_stamp = *stamp;
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk - socket to eat this skb from
 * @skb - socket buffer to eat
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

extern void sock_enable_timestamp(struct sock *sk);
extern int sock_get_timestamp(struct sock *, struct timeval __user *);

/* 
 *	Enable debug/info messages 
 */

#if 0
#define NETDEBUG(x)	do { } while (0)
#define LIMIT_NETDEBUG(x) do {} while(0)
#else
#define NETDEBUG(x)	do { x; } while (0)
#define LIMIT_NETDEBUG(x) do { if (net_ratelimit()) { x; } } while(0)
#endif

/*
 * Macros for sleeping on a socket. Use them like this:
 *
 * SOCK_SLEEP_PRE(sk)
 * if (condition)
 * 	schedule();
 * SOCK_SLEEP_POST(sk)
 *
 * N.B. These are now obsolete and were, afaik, only ever used in DECnet
 * and when the last use of them in DECnet has gone, I'm intending to
 * remove them.
 */

#define SOCK_SLEEP_PRE(sk) 	{ struct task_struct *tsk = current; \
				DECLARE_WAITQUEUE(wait, tsk); \
				tsk->state = TASK_INTERRUPTIBLE; \
				add_wait_queue((sk)->sk_sleep, &wait); \
				release_sock(sk);

#define SOCK_SLEEP_POST(sk)	tsk->state = TASK_RUNNING; \
				remove_wait_queue((sk)->sk_sleep, &wait); \
				lock_sock(sk); \
				}

static inline void sock_valbool_flag(struct sock *sk, int bit, int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

#ifdef CONFIG_NET
int siocdevprivate_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
#else
static inline int siocdevprivate_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	return -ENODEV;
}
#endif

#endif	/* _SOCK_H */
