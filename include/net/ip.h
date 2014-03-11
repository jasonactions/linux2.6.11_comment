/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP module.
 *
 * Version:	@(#)ip.h	1.0.2	05/07/93
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Changes:
 *		Mike McLagan    :       Routing by source
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _IP_H
#define _IP_H

#include <linux/config.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in_route.h>
#include <net/route.h>
#include <net/arp.h>
#include <net/snmp.h>

struct sock;

/**
 * IP标志和选项结构。
 */
struct inet_skb_parm
{
	struct ip_options	opt;		/* Compiled IP options		*/
	unsigned char		flags;

#define IPSKB_MASQUERADED	1
#define IPSKB_TRANSLATED	2
#define IPSKB_FORWARDED		4
#define IPSKB_XFRM_TUNNEL_SIZE	8
};

/**
 * 此结构包含了传输包所需要的各种信息。
 */
struct ipcm_cookie
{
	/**
	 * 目的地IP地址
	 */
	u32			addr;
	/**
	 * 出设备
	 */
	int			oif;
	/**
	 * IP选项
	 */
	struct ip_options	*opt;
};
/**
 * 在重组时，用此宏返回skb->cb中的IP选项信息。由于此inet_skb_parm字段是ipfrag_skb_cb的第一个字段。
 * 因此，skb->cb可以安全的转化为inet_skb_parm或者ipfrag_skb_cb
 */
#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))

struct ip_ra_chain
{
	struct ip_ra_chain	*next;
	struct sock		*sk;
	void			(*destructor)(struct sock *);
};

extern struct ip_ra_chain *ip_ra_chain;
extern rwlock_t ip_ra_lock;

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define IP_FRAG_TIME	(30 * HZ)		/* fragment lifetime	*/

extern void		ip_mc_dropsocket(struct sock *);
extern void		ip_mc_dropdevice(struct net_device *dev);
extern int		igmp_mc_proc_init(void);

/*
 *	Functions provided by ip.c
 */

extern int		ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
					      u32 saddr, u32 daddr,
					      struct ip_options *opt);
extern int		ip_rcv(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt);
extern int		ip_local_deliver(struct sk_buff *skb);
extern int		ip_mr_input(struct sk_buff *skb);
extern int		ip_output(struct sk_buff *skb);
extern int		ip_mc_output(struct sk_buff *skb);
extern int		ip_fragment(struct sk_buff *skb, int (*out)(struct sk_buff*));
extern int		ip_do_nat(struct sk_buff *skb);
extern void		ip_send_check(struct iphdr *ip);
extern int		ip_queue_xmit(struct sk_buff *skb, int ipfragok);
extern void		ip_init(void);
extern int		ip_append_data(struct sock *sk,
				       int getfrag(void *from, char *to, int offset, int len,
						   int odd, struct sk_buff *skb),
				void *from, int len, int protolen,
				struct ipcm_cookie *ipc,
				struct rtable *rt,
				unsigned int flags);
extern int		ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb);
extern ssize_t		ip_append_page(struct sock *sk, struct page *page,
				int offset, size_t size, int flags);
extern int		ip_push_pending_frames(struct sock *sk);
extern void		ip_flush_pending_frames(struct sock *sk);

/* datagram.c */
extern int		ip4_datagram_connect(struct sock *sk, 
					     struct sockaddr *uaddr, int addr_len);

/*
 *	Map a multicast IP onto multicast MAC for type Token Ring.
 *      This conforms to RFC1469 Option 2 Multicasting i.e.
 *      using a functional address to transmit / receive 
 *      multicast packets.
 */

static inline void ip_tr_mc_map(u32 addr, char *buf)
{
	buf[0]=0xC0;
	buf[1]=0x00;
	buf[2]=0x00;
	buf[3]=0x04;
	buf[4]=0x00;
	buf[5]=0x00;
}

struct ip_reply_arg {
	struct kvec iov[1];   
	u32 	    csum; 
	int	    csumoffset; /* u16 offset of csum in iov[0].iov_base */
				/* -1 if not needed */ 
}; 

void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len); 

extern int ip_finish_output(struct sk_buff *skb);

/**
 * ipv4_devconf结构用于存储每个设备的配置，ipv4_config存储主机的配置。
 */
struct ipv4_config
{
	/**
	 * 该参数也存在于ipv4_devconfig结构内。
	 * 当特定错误发生时，此参数可用于决定是否打印警告信息到控制台上。
	 * 它的值不会被直接检查，而是通过宏IN_DEV_LOG_MARTIANS（可以把较高优先权给予这个设备实例）。
	 */
	int	log_martians;
	/**
	 * 当主机的IP配置是通过象DHCP这类协议完成时，就会设置成1。
	 */
	int	autoconfig;
	/**
	 * 当为0时，路径MTU发现功能就会开启。
	 */
	int	no_pmtu_disc;
};

extern struct ipv4_config ipv4_config;
DECLARE_SNMP_STAT(struct ipstats_mib, ip_statistics);
/**
 * 更新IP统计计数。
 * 用在任一种环境中，因为其内部会检查它是否在中断环境中被调用，然后据以更新正确元素。
 */
#define IP_INC_STATS(field)		SNMP_INC_STATS(ip_statistics, field)
/**
 * 更新IP统计计数。
 * 用在中断环境中。
 */
#define IP_INC_STATS_BH(field)		SNMP_INC_STATS_BH(ip_statistics, field)
/**
 * 更新IP统计计数。
 * 用在中断环境外。
 */
#define IP_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(ip_statistics, field)
DECLARE_SNMP_STAT(struct linux_mib, net_statistics);
#define NET_INC_STATS(field)		SNMP_INC_STATS(net_statistics, field)
#define NET_INC_STATS_BH(field)		SNMP_INC_STATS_BH(net_statistics, field)
#define NET_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(net_statistics, field)
#define NET_ADD_STATS_BH(field, adnd)	SNMP_ADD_STATS_BH(net_statistics, field, adnd)
#define NET_ADD_STATS_USER(field, adnd)	SNMP_ADD_STATS_USER(net_statistics, field, adnd)

extern int sysctl_local_port_range[2];
extern int sysctl_ip_default_ttl;

#ifdef CONFIG_INET
/* The function in 2.2 was invalid, producing wrong result for
 * check=0xFEFF. It was noticed by Arthur Skawina _year_ ago. --ANK(000625) */
/**
 * 在转发包时，递减TTL字段，同时会修正IP层校验和。
 */
static inline
int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = iph->check;
	check += htons(0x0100);
	iph->check = check + (check>=0xFFFF);
	return --iph->ttl;
}
/**
 * 根据系统设置，如果打开了PMTU发现功能，以及当前的PMTU值，确定是否需要对IP进行分片。
 */
static inline
int ip_dont_fragment(struct sock *sk, struct dst_entry *dst)
{
	return (inet_sk(sk)->pmtudisc == IP_PMTUDISC_DO ||
		(inet_sk(sk)->pmtudisc == IP_PMTUDISC_WANT &&
		 !(dst_metric(dst, RTAX_LOCK)&(1<<RTAX_MTU))));
}

extern void __ip_select_ident(struct iphdr *iph, struct dst_entry *dst, int more);

/**
 * 为IP报文选择ID。
 */
static inline void ip_select_ident(struct iphdr *iph, struct dst_entry *dst, struct sock *sk)
{
	if (iph->frag_off & htons(IP_DF)) {/* 不能分段的包 */
		/* This is only to work around buggy Windows95/2000
		 * VJ compression implementations.  If the ID field
		 * does not change, they drop every other packet in
		 * a TCP stream using header compression.
		 */
		/**
		 * 间接从sock数据结构中取出。这是为了解决windows系统的BUG。
		 */
		iph->id = (sk && inet_sk(sk)->daddr) ?
					htons(inet_sk(sk)->id++) : 0;
	} else
		__ip_select_ident(iph, dst, 0);/* 对可以分段的包，则从__ip_select_ident获得ID */
}

static inline void ip_select_ident_more(struct iphdr *iph, struct dst_entry *dst, struct sock *sk, int more)
{
	if (iph->frag_off & htons(IP_DF)) {
		if (sk && inet_sk(sk)->daddr) {
			iph->id = htons(inet_sk(sk)->id);
			inet_sk(sk)->id += 1 + more;
		} else
			iph->id = 0;
	} else
		__ip_select_ident(iph, dst, more);
}

/*
 *	Map a multicast IP onto multicast MAC for type ethernet.
 */

static inline void ip_eth_mc_map(u32 addr, char *buf)
{
	addr=ntohl(addr);
	buf[0]=0x01;
	buf[1]=0x00;
	buf[2]=0x5e;
	buf[5]=addr&0xFF;
	addr>>=8;
	buf[4]=addr&0xFF;
	addr>>=8;
	buf[3]=addr&0x7F;
}

/*
 *	Map a multicast IP onto multicast MAC for type IP-over-InfiniBand.
 *	Leave P_Key as 0 to be filled in by driver.
 */

static inline void ip_ib_mc_map(u32 addr, char *buf)
{
	buf[0]  = 0;		/* Reserved */
	buf[1]  = 0xff;		/* Multicast QPN */
	buf[2]  = 0xff;
	buf[3]  = 0xff;
	addr    = ntohl(addr);
	buf[4]  = 0xff;
	buf[5]  = 0x12;		/* link local scope */
	buf[6]  = 0x40;		/* IPv4 signature */
	buf[7]  = 0x1b;
	buf[8]  = 0;		/* P_Key */
	buf[9]  = 0;
	buf[10] = 0;
	buf[11] = 0;
	buf[12] = 0;
	buf[13] = 0;
	buf[14] = 0;
	buf[15] = 0;
	buf[19] = addr & 0xff;
	addr  >>= 8;
	buf[18] = addr & 0xff;
	addr  >>= 8;
	buf[17] = addr & 0xff;
	addr  >>= 8;
	buf[16] = addr & 0x0f;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

static __inline__ void inet_reset_saddr(struct sock *sk)
{
	inet_sk(sk)->rcv_saddr = inet_sk(sk)->saddr = 0;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (sk->sk_family == PF_INET6) {
		struct ipv6_pinfo *np = inet6_sk(sk);

		memset(&np->saddr, 0, sizeof(np->saddr));
		memset(&np->rcv_saddr, 0, sizeof(np->rcv_saddr));
	}
#endif
}

#endif

extern int	ip_call_ra_chain(struct sk_buff *skb);

/*
 *	Functions provided by ip_fragment.o
 */

enum ip_defrag_users
{
	IP_DEFRAG_LOCAL_DELIVER,
	IP_DEFRAG_CALL_RA_CHAIN,
	IP_DEFRAG_CONNTRACK_IN,
	IP_DEFRAG_CONNTRACK_OUT,
	IP_DEFRAG_NAT_OUT,
	IP_DEFRAG_VS_IN,
	IP_DEFRAG_VS_OUT,
	IP_DEFRAG_VS_FWD
};

struct sk_buff *ip_defrag(struct sk_buff *skb, u32 user);
extern int ip_frag_nqueues;
extern atomic_t ip_frag_mem;

/*
 *	Functions provided by ip_forward.c
 */
 
extern int ip_forward(struct sk_buff *skb);
extern int ip_net_unreachable(struct sk_buff *skb);
 
/*
 *	Functions provided by ip_options.c
 */
 
extern void ip_options_build(struct sk_buff *skb, struct ip_options *opt, u32 daddr, struct rtable *rt, int is_frag);
extern int ip_options_echo(struct ip_options *dopt, struct sk_buff *skb);
extern void ip_options_fragment(struct sk_buff *skb);
extern int ip_options_compile(struct ip_options *opt, struct sk_buff *skb);
extern int ip_options_get(struct ip_options **optp, unsigned char *data, int optlen, int user);
extern void ip_options_undo(struct ip_options * opt);
extern void ip_forward_options(struct sk_buff *skb);
extern int ip_options_rcv_srr(struct sk_buff *skb);

/*
 *	Functions provided by ip_sockglue.c
 */

extern void	ip_cmsg_recv(struct msghdr *msg, struct sk_buff *skb);
extern int	ip_cmsg_send(struct msghdr *msg, struct ipcm_cookie *ipc);
extern int	ip_setsockopt(struct sock *sk, int level, int optname, char __user *optval, int optlen);
extern int	ip_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);
extern int	ip_ra_control(struct sock *sk, unsigned char on, void (*destructor)(struct sock *));

extern int 	ip_recv_error(struct sock *sk, struct msghdr *msg, int len);
extern void	ip_icmp_error(struct sock *sk, struct sk_buff *skb, int err, 
			      u16 port, u32 info, u8 *payload);
extern void	ip_local_error(struct sock *sk, int err, u32 daddr, u16 dport,
			       u32 info);

/* sysctl helpers - any sysctl which holds a value that ends up being
 * fed into the routing cache should use these handlers.
 */
int ipv4_doint_and_flush(ctl_table *ctl, int write,
			 struct file* filp, void __user *buffer,
			 size_t *lenp, loff_t *ppos);
int ipv4_doint_and_flush_strategy(ctl_table *table, int __user *name, int nlen,
				  void __user *oldval, size_t __user *oldlenp,
				  void __user *newval, size_t newlen, 
				  void **context);

#endif	/* _IP_H */
