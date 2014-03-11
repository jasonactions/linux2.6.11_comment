/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Version:	$Id: ip_output.c,v 1.100 2002/02/01 22:01:03 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when 
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path 
 *					for decreased register pressure on x86 
 *					and more readibility. 
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/config.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/checksum.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *      Shall we try to damage output packets if routing dev changes?
 */

/**
 * 该变量用于处理的情况是：绑定至按需拨号接口的地址的套接字没接收到任何回复，直到该接口打开为止。如果ip_dynaddr被设定，套接字就会重新试着绑定。
 */
int sysctl_ip_dynaddr;
/**
 * 这是IP TTL字段的默认值（用于单播流量）。多播流量的默认值是1，而且没有相应的sysctl变量可供设定。
 */
int sysctl_ip_default_ttl = IPDEFTTL;

/* Generate a checksum for an outgoing IP datagram. */
/**
 * 计算IP包发包的校验和。
 * 它是对ip_fast_csum的一个简单包装，在调用ip_fast_csum前，预先将iphdr->check设置为0.
 */
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/* dev_loopback_xmit for use with netfilter. */
static int ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	newskb->mac.raw = newskb->data;
	__skb_pull(newskb, newskb->nh.raw - newskb->data);
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	BUG_TRAP(newskb->dst);

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_loopback_xmit(newskb);
#endif
	netif_rx(newskb);
	return 0;
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}

/* 
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  u32 saddr, u32 daddr, struct ip_options *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)skb->dst;
	struct iphdr *iph;

	/* Build the IP header. */
	if (opt)
		iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr) + opt->optlen);
	else
		iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr));

	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->daddr    = rt->rt_dst;
	iph->saddr    = rt->rt_src;
	iph->protocol = sk->sk_protocol;
	iph->tot_len  = htons(skb->len);
	ip_select_ident(iph, &rt->u.dst, sk);
	skb->nh.iph   = iph;

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, daddr, rt, 0);
	}
	ip_send_check(iph);

	skb->priority = sk->sk_priority;

	/* Send it out. */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);
}

/**
 * L3层与L2层的接口。
 */
static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct hh_cache *hh = dst->hh;
	struct net_device *dev = dst->dev;
	int hh_len = LL_RESERVED_SPACE(dev);

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->hard_header)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_finish_output2(skb);
#endif /*CONFIG_NETFILTER_DEBUG*/

	/**
	 * 有缓存的帧头。
	 */
	if (hh) {
		int hh_alen;

		read_lock_bh(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(hh->hh_len);
		/**
		 * 把它拷贝到skb缓冲区中。
		 */
  		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		read_unlock_bh(&hh->hh_lock);
	        skb_push(skb, hh->hh_len);
		return hh->hh_output(skb);
	} else if (dst->neighbour)/* 缓存的L2帧头是无效的 */
		return dst->neighbour->output(skb);/* 调用neigh->output方法，这可能将包放到缓存队列中延后发送。 */

	if (net_ratelimit())
		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

int ip_finish_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dst->dev;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev,
		       ip_finish_output2);
}

int ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if ((!sk || inet_sk(sk)->mc_loop)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    && ((rt->rt_flags&RTCF_LOCAL) || !(IPCB(skb)->flags&IPSKB_FORWARDED))
#endif
		) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
					newskb->dev, 
					ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (skb->nh.iph->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
				newskb->dev, ip_dev_loopback_xmit);
	}

	if (skb->len > dst_pmtu(&rt->u.dst))
		return ip_fragment(skb, ip_finish_output);
	else
		return ip_finish_output(skb);
}

int ip_output(struct sk_buff *skb)
{
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	if (skb->len > dst_pmtu(skb->dst) && !skb_shinfo(skb)->tso_size)
		return ip_fragment(skb, ip_finish_output);
	else
		return ip_finish_output(skb);
}

/**
 * TCP和SCTP发送包所用的函数。
 * 此函数只接收两个输入参数，所有处理包所需要的信息都可以通过skb直接或者间接的存取。
 *		Skb：		要传输的包的缓冲区描述符。此数据结构有填入IP报头以及传输包所需要的所有参数（如下一跳网关）。记住，ip_queue_xmit用于处理本地产生的包。转发包没有相关的套接字。
 *		Ipfragok：	主要由SCTP使用的标志，用来指出是否允许分段。
 */
int ip_queue_xmit(struct sk_buff *skb, int ipfragok)
{
	/**
	 * 和skb相关的套接字包含有一个名为opt的指针，指向IP选项结构。
	 * 此结构包含IP报头中的选项，而其存储格式使得IP层的函数更易于存取。
	 * 此结构是放在socket结构中的，因为此结构对每个要通过该套接字传输的包而言都是相同的。
	 * 为每个包重建此信息太浪费了。
	 */
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	/**
	 * opt结构里有一些字段是偏移量，指出函数可以在报头中的哪些位置存储IP选项所需的时间戳和IP地址。
	 */
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	/**
	 * 如果缓冲区已被设定正确路由信息（skb->dst），就没有必要查询路由表。
	 * 当缓冲区由SCTP协议处理时，在某些情况下这是有可能的
	 */
	rt = (struct rtable *) skb->dst;
	if (rt != NULL)
		goto packet_routed;

	/* Make sure we can route this packet. */
	/**
	 * 在其他情况下，ip_queue_xmit会检查套接字结构中是否已缓存了一条路径。
	 * 如果有的话，就会确定该路径是否依然有效（由__sk_dst_check检查）
	 */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	/**
	 * 套接字还没有一条缓存的路径可用，或者如果IP层一直在用的路径在此时失效了（例如路由协议更新了）
	 */
	if (rt == NULL) {
		u32 daddr;

		/* Use correct destination address if we have options. */
		/**
		 * daddr是出包使用的路由地址。如果是源路由，则使用IP选项中设定的地址。
		 */
		daddr = inet->daddr;
		if(opt && opt->srr)
			daddr = opt->faddr;

		{
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					    .nl_u = { .ip4_u =
						      { .daddr = daddr,
							.saddr = inet->saddr,
							.tos = RT_CONN_FLAGS(sk) } },
					    .proto = sk->sk_protocol,
					    .uli_u = { .ports =
						       { .sport = inet->sport,
							 .dport = inet->dport } } };

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			/**
			 * 利用ip_route_output_slow找到一条新路径，然后将结果存储到sk数据结构中
			 */
			if (ip_route_output_flow(&rt, &fl, sk, 0))
				goto no_route;
		}
		/**
		 * 将查询到的路由缓存到sock结构中。
		 */
		__sk_dst_set(sk, &rt->u.dst);
		/**
		 * tcp_v4_setup_caps会把出设备的一些功能存储在套接字sk中
		 */
		tcp_v4_setup_caps(sk, &rt->u.dst);
	}
	/**
	 * 增加路由缓存项的引用计数。
	 */
	skb->dst = dst_clone(&rt->u.dst);

packet_routed:
	/**
	 * 如果是严格源路由，并且路由表计算出的出设备与下一跳不符合，则退出。
	 */
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	/**
	 * 当ip_queue_xmit接收skb时，skb->data会指向L3有效负载（L4协议在此写入其数据）的开端。
	 * L3报头就在此指针之前。所以，这里会使用skb->push把skb->data往回移动，使其指向L3或IP报头的开端。
	 */
	iph = (struct iphdr *) skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	/**
	 * 对IP报头中的一组字段做初始化。
	 * 首先设定三个字段的值（veriosn、ihl和tos）。因为它们共享同一个16位。
	 * 因此，这一语句把报头中的版本设置为4，把报头长度设置为5，并把TOS设置成inet->tos。
	 */
	*((__u16 *)iph)	= htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	iph->tot_len = htons(skb->len);
	if (ip_dont_fragment(sk, &rt->u.dst) && !ipfragok)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;
	iph->saddr    = rt->rt_src;
	iph->daddr    = rt->rt_dst;
	skb->nh.iph   = iph;
	/* Transport layer set skb->h.foo itself. */

	/**
	 * 如果IP报头中包含了一些选项，此函数必须更新"报头长度"字段iph->length（它已经被预先设置为初始值5），然后调用ip_options_ build处理这些选项。
	 * Ip_options_build会使用opt变量（它已经被预先初始化为inet->opt）把所需的选项字段（如时间戳）添加至IP报头。注意，ip_options_build的最后一个参数被设置为0，以指出该报头不属于片段。
	 */
	if (opt && opt->optlen) {
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->daddr, rt, 0);
	}

	/**
	 * ip_select_ident_more会根据该包是否可能被分段而在报头中设定IP ID
	 */
	ip_select_ident_more(iph, &rt->u.dst, sk, skb_shinfo(skb)->tso_segs);

	/* Add an IP checksum. */
	/**
	 * ip_send_check会对IP报头计算校验和。
	 */
	ip_send_check(iph);

	/**
	 * 流量控制使用skb->priority来决定要把包排入哪一个出队列。
	 * 而这一点有助于决定该包会多快被传递。此函数中的值是来自sock结构的。
	 * 而在ip_forward（它管理非本地流量，因此没有本地套接字），其值是根据IP TOS的值，从一张转换表推导而得。
	 */
	skb->priority = sk->sk_priority;

	/**
	 * 调用Netfilter来了解该包是否有权跳至后续步骤（dst_output），并得以继续传输。
	 */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);

no_route:
	IP_INC_STATS(IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	to->security = from->security;
	dst_release(to->dst);
	to->dst = dst_clone(from->dst);
	to->dev = from->dev;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
#ifdef CONFIG_NETFILTER
	to->nfmark = from->nfmark;
	to->nfcache = from->nfcache;
	/* Connection association is same as pre-frag packet */
	nf_conntrack_put(to->nfct);
	to->nfct = from->nfct;
	nf_conntrack_get(to->nfct);
	to->nfctinfo = from->nfctinfo;
#ifdef CONFIG_BRIDGE_NETFILTER
	nf_bridge_put(to->nf_bridge);
	to->nf_bridge = from->nf_bridge;
	nf_bridge_get(to->nf_bridge);
#endif
#ifdef CONFIG_NETFILTER_DEBUG
	to->nf_debug = from->nf_debug;
#endif
#endif
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */
/**
 * 处理分片。
 *		skb:		包含要被分段的IP包的缓冲区。此包包含有一个已经初始化的IP报头，而这个IP报头将会被调整，用于拷贝到所有片段内。
 *		output：	用于传输片段的函数。
 */
int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff*))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs;
	int offset;
	int not_last_frag;
	struct rtable *rt = (struct rtable*)skb->dst;
	int err = 0;

	/**
	 * 从路由中取出出设备。
	 */
	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = skb->nh.iph;

	/**
	 * 如果输入的IP包因为来源地设有DF标志而无法被分段，则ip_fragment会传回一个ICMP包给来源地告知此问题。然后丢弃该包。
	 */
	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(dst_pmtu(&rt->u.dst)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	/**
	 * 报文MTU。不含三层报头。
	 */
	mtu = dst_pmtu(&rt->u.dst) - hlen;	/* Size of data space */

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	/**
	 * 已经分段了，此处进行快速分段。
	 * 如果是转发的包，则不会有frag_list，那么需要走慢速分片流程。
	 */
	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *frag;
		int first_len = skb_pagelen(skb);

		/**
		 * 在尝试进行快速分片前，先进行一些检查，确保能够进行快速分片。
		 */
		if (first_len - hlen > mtu ||	/* 第一个段的长度，含页面中的长度，不能超过MTU */
		    ((first_len - hlen) & 7) || /* 第一个段的长度没有8字节对齐 */
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) ||/* 原始报文是一个报文的片段。 */
		    skb_cloned(skb))/* 片段被共享，这样，就不能对片段进行修改(重新计算校验和) */
			goto slow_path;

		/**
		 * 对fraglist中的数据进行判断
		 */
		for (frag = skb_shinfo(skb)->frag_list; frag; frag = frag->next) {
			/* Correct geometry. */
			if (frag->len > mtu ||	/* 报文片段长度不能超过MTU */
			    ((frag->len & 7) && frag->next) || /* 不是最后一个片段，并且长度不以8字节对齐 */
			    skb_headroom(frag) < hlen)/* 片段长度不能容纳L2报头 */
			    goto slow_path;

			/* Partially cloned skb? */
			if (skb_shared(frag))/* 分段被共享。 */
				goto slow_path;
		}

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;
		/**
		 * 第一个片段的IP报头初始化在循环外完成，因为可以对其进行优化。
		 */
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		/**
		 * 可以直接设置MF标志。offset为默认值0.
		 */
		iph->frag_off |= htons(IP_MF);
		ip_send_check(iph);

		/**
		 * 循环处理每个片段。
		 */
		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->ip_summed = CHECKSUM_NONE;
				frag->h.raw = frag->data;
				frag->nh.raw = __skb_push(frag, hlen);
				/**
				 * 从第一个IP片段中把报头复制到当前片段。
				 */
				memcpy(frag->nh.raw, iph, hlen);
				iph = frag->nh.iph;
				iph->tot_len = htons(frag->len);
				/**
				 * 从第一个片段中把管理参数复制到新片段中。
				 */
				ip_copy_metadata(frag, skb);
				/**
				 * 第一个片段处理完后，需要调用ip_options_fragment修改报头。
				 * 这样，后续片段的报头就简单得多了。
				 */
				if (offset == 0)
					ip_options_fragment(frag);
				/**
				 * 计算报头的偏移量。
				 */
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				/**
				 * 如果不是最后一个片段，则设置MF标志。
				 */
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				/**
				 * 报头的校验和需要重新计算。
				 */
				ip_send_check(iph);
			}
			/**
			 * 传输片段。对IPV4来说，回调的函数是ip_finish_output。
			 */
			err = output(skb);

			/**
			 * 发生错误。或者处理完所有片段了。
			 */
			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		/**
		 * 没有发生错误。返回。
		 */
		if (err == 0) {
			IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		/**
		 * 如果发生错误，则释放剩余的所有片段。
		 */
		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
		return err;
	}

/**
 * 慢速分段。
 */
slow_path:
	/**
	 * 需要进行分片的数据长度，不含L2报头。初值是报文长度。
	 */
	left = skb->len - hlen;		/* Space per frame */
	/**
	 * Ptr就是要被分段的包里的偏移量，它的值会随着分段工作的进行而移动。
	 */
	ptr = raw + hlen;		/* Where to start from */

	/**
	 * 计算链路层保留空间
	 */
#ifdef CONFIG_BRIDGE_NETFILTER
	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header */
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, nf_bridge_pad(skb));
	mtu -= nf_bridge_pad(skb);
#else
	ll_rs = LL_RESERVED_SPACE(rt->u.dst.dev);
#endif
	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	/**
	 * not_last_frag标识是不是最后一个分片。
	 */
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	/**
	 * 为每个分片建立一个新缓冲区skb2。
	 */
	while(left > 0)	{
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		/**
		 * 每个片段的长度，最大为PMTU。
		 */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		/**
		 * RFC强制要求每个片段8字节对齐。
		 */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */
		/**
		 * 保存一个片段的缓冲区尺寸是下列各项之和：
 		 *		IP有效负载的尺寸。
 		 *		IP报头的尺寸。
 		 *		L2报头的尺寸。
		 */
		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(printk(KERN_INFO "IP: frag: no memory for new fragment!\n"));
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */
		/**
		 * 从skb中复制一些字段到skb2中，其中一些字段由ip_copy_metadata处理。
		 */
		ip_copy_metadata(skb2, skb);
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb2->nh.raw = skb2->data;
		skb2->h.raw = skb2->data + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		/**
		 * 设置新缓冲区关联的socket。
		 */
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */
		/**
		 * 现在，开始将真实数据写入缓冲区中。
		 * 首先复制IP报头。
		 */
		memcpy(skb2->nh.raw, skb->data, hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		/**
		 * 将原有包中的有效负载复制到新包中。这里无法使用memcpy。
		 * 因为，包内的数据可能分散在片段链表和内存页面中，而不仅仅在data中。
		 * 当L4层分段后，可能由于健康检查而走到慢速分段流程。
		 */
		if (skb_copy_bits(skb, ptr, skb2->h.raw, len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		iph = skb2->nh.iph;
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		/**
		 * 对第一个片段(offset == 0)来说，它的IP头包含了原包的所有选项。
		 * 这里，处理完第一个片段的IP头后，需要调用ip_options_fragment清掉与原有IP包相关的ip_opt结构的内容。
		 * 这样，以后的片段就不再有不需要的选项。
		 */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		/**
		 * left > 0表示被创建的片段不是最后一个片段。
		 * not_last_frag表示被分片的包，本身是一个片段并且不是最后一个片段。
		 * 这两种情况下，都需要设置MF标志。
		 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		/**
		 * ptr代表当前正在分段的包内的偏移量，offset代表当前片段在原包内的偏移量。
		 * 一般情况下这两个值是相等的，但是，需要offset的原因是，被分段的包可能是另外一个包的分片。此时，offset应该大于等于ptr。
		 */
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */

		IP_INC_STATS(IPSTATS_MIB_FRAGCREATES);

		/**
		 * 更新报头长度，这是因为要考虑选项的尺寸。
		 */
		iph->tot_len = htons(len + hlen);
		/**
		 * 计算校验和。
		 */
		ip_send_check(iph);
		/**
		 * 使用output函数传片段，对IPV4来说，这个函数是ip_finish_output。
		 */
		err = output(skb2);
		if (err)
			goto fail;
	}
	kfree_skb(skb);
	IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb); 
	IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
	return err;
}

/**
 * 当应用程序对UDP或Raw IP套接字发出一个sendmsg系统调用时，内核最终会调用ip_append_data，把ip_generic_getfrag当成getfrag函数。
 * 这种情况下，已经知道输入数据始终来自于用户空间。
 */
int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_HW) {/* 不需要计算校验和 */
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		unsigned int csum = 0;
		/**
		 * 在从用户态复制数据时，同时计算校验和。
		 */
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

static inline unsigned int
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	unsigned int csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *	
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
/**
 * 某些L4协议(如UDP)，会暂存数据，直到达到IP层的最大长度(64K).
 * ip_append_data函数用于这种情况。
 * 		sk:			该包所属的套接字。此数据结构包含一些参数（如IP选项），稍后必须用于填写IP报头（通过ip_push_pending_frames函数）。
 *		from：		指向L4层正试着传输的数据（有效负载）指针。这不是内核指针，就是用户空间的指针，getfrag函数的工作就是正确处理这一指针。
 *		getfrag：	用于把接收自L4层的有效负载拷贝到即将建立的一些数据片段中。
 *		length：	要传输的数据量（包含L4报头和L4有效负载）。
 *		transhdrlen：传输（L4）报头的尺寸。传输报头的范例就是那些常见的TCP、UDP以及ICMP协议的报头。
 * 		ipc：		正确转发包所需要的信息
 *		rt：		与此包相关的路由表缓存项目。当ip_queue_xmit接收此信息时，ip_append_data会依赖调用者通过ip_route_output_flow来收集该信息。
 *		flags：		此变量可包含任何一个MSG_XXX标志（定义在include/linux.socket.h中）。此函数会用到其中三个标志：
 *			MSG_MORE：		此标志由应用程序使用，来告知L4层马上就有更多其他传输。如我们所见，此标志会传播到L3层。稍后我们就会看到，在分配缓冲区时此项信息有何用处。
 *			MSG_DONTWAIT：	当此标志设定时，对ip_append_data的调用一定不能受到阻塞。Ip_append_data可能必须为套接字sk分配一个缓冲区（利用sock_alloc_send_skb）。当sock_alloc_send_skb用掉其限制时，不是堵塞住（通过定时器）以期望定时器到期前可以有些空间可用，不然就是失败。此标志可用在前两个选项中做选择。
 *			MSG_PROBE：		当此标志设定时，用户其实不想传输任何东西，而只是在探测路径。例如，此标志可用于测试通往指定IP地址的路径上的PMTU。可参考net/ipv4/raw.c中的raw_sed_hdrinc。如果此标志被设置，ip_append_data只会立刻传回一个代表成功的返回代码。
 */
int ip_append_data(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable *rt,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	/**
	 * 要加入IP报头的IP选项。当此变量为NULL时，就没有选项。
	 */
	struct ip_options *opt = NULL;
	int hh_len;
	/**
	 * 外部报头。exthdrlen是由rt间接取得的。
	 * 外部报头的范例是那些由ipsec套件里的协议所使用的报头，例如鉴定报头（AH）以及封装安全有效负载报头（ESP）。
	 */
	int exthdrlen;
	/**
	 * 和rt相关的PMTU。
	 */
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen;
	int csummode = CHECKSUM_NONE;

	if (flags&MSG_PROBE)
		return 0;

	/**
	 * 是建立的第一个包，因此需要初始化象cork这样的，inet结构内的数据。
	 */
	if (skb_queue_empty(&sk->sk_write_queue)) {
		/*
		 * setup for corking.
		 */
		opt = ipc->opt;
		/**
		 * 需要处理选项，将其分析后保存到cork中。
		 */
		if (opt) {
			if (inet->cork.opt == NULL) {
				inet->cork.opt = kmalloc(sizeof(struct ip_options) + 40, sk->sk_allocation);
				if (unlikely(inet->cork.opt == NULL))
					return -ENOBUFS;
			}
			memcpy(inet->cork.opt, opt, sizeof(struct ip_options)+opt->optlen);
			inet->cork.flags |= IPCORK_OPT;
			inet->cork.addr = ipc->addr;
		}
		dst_hold(&rt->u.dst);
		/**
		 * 得到路由上的PMTU，并将其缓存起来。
		 */
		inet->cork.fragsize = mtu = dst_pmtu(&rt->u.dst);
		inet->cork.rt = rt;
		inet->cork.length = 0;
		sk->sk_sndmsg_page = NULL;
		sk->sk_sndmsg_off = 0;
		if ((exthdrlen = rt->u.dst.header_len) != 0) {
			length += exthdrlen;
			transhdrlen += exthdrlen;
		}
	} else {
		rt = inet->cork.rt;
		/**
		 * cork中包含opt。
		 */
		if (inet->cork.flags & IPCORK_OPT)
			opt = inet->cork.opt;

		/**
		 * 只有第一个缓冲区需要传输报头。因此，后面的缓冲区需要将其设置为0.
		 */
		transhdrlen = 0;
		exthdrlen = 0;
		/**
		 * 取出缓存的PMTU.
		 */
		mtu = inet->cork.fragsize;
	}
	/**
	 * hh_len是L2报头的长度。在为IP之前的所有报头在缓冲区中保留空间时，ip_append_data必须知道L2报头需要多少空间。
	 * 如此一来，当设备驱动程序对其报头做初始化时，就不需要重新分配空间，或者移动缓冲区内的数据来腾出空间给L2报头了。
	 */
	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);

	/**
	 * Fraghdrlen是IP报头（包含IP选项）的尺寸
	 */
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	/**
	 * maxfraglen是IP片段的最大尺寸（基于路径PMTU）。
	 */
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	/**
	 * IP包（报头和有效负载）的最大尺寸是64KB。
	 * 这一点不仅适用于个别片段，也适用于整个包（这些片段最终会重组成此包）。
	 * 于是，ip_append_data会记录为特定包所接收的所有数据，并拒绝超过64KB的限制。
	 */
	if (inet->cork.length + length > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	/**
	 * 这里初始化的局部变量csummode会被指派给第一缓冲区的skb->ip_summed。
	 * 如果需要分段，而且ip_append_data据此分配更多的缓冲区（每个IP片段一个缓冲区），则后续缓冲区的skb->ip_summed就会被设成CHECKSUM_NONE。
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->u.dst.dev->features&(NETIF_F_IP_CSUM|NETIF_F_NO_CSUM|NETIF_F_HW_CSUM) &&
	    !exthdrlen)
		csummode = CHECKSUM_HW;

	/**
	 * 记录所有缓冲区的总长。
	 */
	inet->cork.length += length;

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		/**
		 * 对第一个缓冲区来说，不需要考虑MSG_MORE标志和NETIF_F_SG标志，总是需要分配sk_buff的。
		 */
		goto alloc_new_skb;

	/**
	 * 最初，length的值代表的是ip_append_data的调用者想传输的数据量。
	 * 然而，一旦进入循环，其值就代表剩余要处理的数据量。
	 */
	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		/**
		 * copy是本次需要填充的数据量。
		 * 首先检查上一个缓冲区是否还可以放一些数据进去。
		 */
		copy = mtu - skb->len;
		/**
		 * 不能完全容纳剩余的包。需要调整copy值，因为每个分片需要8字节对齐。而mtu并不是8字节对齐的。
		 */
		if (copy < length)
			/**
			 * 根据分片大小重新计算可以放到上一个缓冲区的数量。
			 */
			copy = maxfraglen - skb->len;
		/**
		 * 上一个分片不能存放任何数据了，需要再分配一个缓冲区。
		 */
		if (copy <= 0) {
			char *data;
			/**
			 * datalen是要拷贝到我们所分配的缓冲区的数据量。
			 * 其值会根据三个因素预先初始化：剩余数据量（length）、一个片段所能容纳的最大数据量（fraghdrlen）、以及一个可有可无，来自于前一个缓冲区的间隙（fraggap）。
			 */
			unsigned int datalen;
			unsigned int fraglen;
			/**
			 * 除了最后一个缓冲区（持有最后一个IP片段）以外，所有片段都必须遵循一个原则：IP片段的有效负载必须是8字节的倍数。
			 * 因此，当内核分配的一个新缓冲区不是给最后片段使用时，可能必须从前一个缓冲区的尾端移动一段数据（其尺寸为0－7字节）到新分配缓冲区的头部。
			 * 换句话说，除非下列条件都满足，则fraggap为0：
			 *	 	PMTU不是8字节的倍数。
 			 *		当前IP片段的尺寸还不到PMTU。
 			 *		当前IP片段的尺寸已经超过8字节的倍数。
			 */
			unsigned int fraggap;
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			/**
			 * 计算需要从前一个片段中移动多少数据到新缓冲区。
			 */
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;
			/**
			 * 新缓冲区不能容纳剩余的数据。则新缓冲区需要进行8字节对齐。
			 */
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
			/**
			 * 分片总长。
			 */
			fraglen = datalen + fragheaderlen;

			/**
			 * 如果预期还有更多数据，而且如果设备无法处理分散/聚集IO，此缓冲区就会以最大尺寸建立（根据PMTU）。
			 */
			if ((flags & MSG_MORE) && 
			    !(rt->u.dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else/* 否则缓冲区的大小只要能够容纳当前数据就行了。 */
				alloclen = datalen + fragheaderlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
			/**
			 * 当ip_append_data产生最后的片段时，就必须考虑一些报尾（如IPSec的报尾）是否存在。
			 * 这里果然有一个BUG，在以后的版本已经修复过来了。下面的判断条件应该是:if (datalen == length + fraggap)
			 */
			if (datalen == length)
				alloclen += rt->u.dst.trailer_len;

			if (transhdrlen) {
				/**
				 * sock_alloc_send_skb为第一个分片分配内存。
				 */
				skb = sock_alloc_send_skb(sk, 
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				/**
				 * sock_wmalloc为后续分片分配内存。
				 */
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk, 
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
			}
			/**
			 * 不能分配内存了。
			 */
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = csummode;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen);
			skb->nh.raw = data + exthdrlen;
			data += fragheaderlen;
			skb->h.raw = data + exthdrlen;

			/**
			 * 需要从前一个缓冲区中复制几个字节到新缓冲区。
			 */
			if (fraggap) {
				/**
				 * 从前一个缓冲区复制几个字节，并截断前一个缓冲区。
				 */
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				skb_trim(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap;
			/**
			 * 从用户空间或者内核空间中复制数据skb
			 */
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= datalen - fraggap;
			/**
			 * 已经处理完第一个缓冲区，需要将传输报头及扩展报头清空。
			 */
			transhdrlen = 0;
			exthdrlen = 0;
			/**
			 * 只有不分片时，才能使用硬件校验和的方式。
			 * 此处修改csummode标志，这样，如果进入下一个循环并运行到copy<=0的分支，说明进行了分片，需要设置为CHECKSUM_NONE。
			 */
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			/**
			 * 将新缓冲区加到缓存链表中。 
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		/**
		 * 运行到这里，说明copy > 0
		 * 这意味着skb(sk_write_queue的最后一个元素)有一些可用空间。
		 * Ip_append_data会先用那些空间。如果所剩空间不足（也就是length大于该可用空间），则循环会再次迭代，而这一次会进入下一情况。
		 */
		if (copy > length)
			copy = length;

		if (!(rt->u.dst.dev->features&NETIF_F_SG)) {/* 不支持分散/聚集IO */
			unsigned int off;

			off = skb->len;
			/**
			 * 复制数据到缓冲区的主缓存中。
			 */
			if (getfrag(from, skb_put(skb, copy), 
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
			int i = skb_shinfo(skb)->nr_frags;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
			struct page *page = sk->sk_sndmsg_page;
			int off = sk->sk_sndmsg_off;
			unsigned int left;

			/**
			 * 上次分配的页还有空余空间。
			 */
			if (page && (left = PAGE_SIZE - off) > 0) {
				if (copy >= left)
					copy = left;
				if (page != frag->page) {
					if (i == MAX_SKB_FRAGS) {/* 超过页面数限制了 */
						err = -EMSGSIZE;
						goto error;
					}
					/**
					 * skb_shinfo(skb)->frags[i]将指向该页。因此需要增加页面引用计数。
					 */
					get_page(page);
					/**
					 * skb_shinfo(skb)->frags[i]将指向该页。
					 */
	 				skb_fill_page_desc(skb, i, page, sk->sk_sndmsg_off, 0);
					frag = &skb_shinfo(skb)->frags[i];
				}
			} else if (i < MAX_SKB_FRAGS) {/* 还允许再分配页面 */
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				page = alloc_pages(sk->sk_allocation, 0);
				if (page == NULL)  {
					err = -ENOMEM;
					goto error;
				}
				/**
				 * 记录写入页面及起始位置。
				 */
				sk->sk_sndmsg_page = page;
				sk->sk_sndmsg_off = 0;

				skb_fill_page_desc(skb, i, page, 0, 0);
				frag = &skb_shinfo(skb)->frags[i];
				skb->truesize += PAGE_SIZE;
				atomic_add(PAGE_SIZE, &sk->sk_wmem_alloc);
			} else {/* 不允许再分配页面了 */
				err = -EMSGSIZE;
				goto error;
			}
			/**
			 * 读取数据报到指定的页面位置。
			 */
			if (getfrag(from, page_address(frag->page)+frag->page_offset+frag->size, offset, copy, skb->len, skb) < 0) {
				err = -EFAULT;
				goto error;
			}
			sk->sk_sndmsg_off += copy;
			frag->size += copy;
			skb->len += copy;
			skb->data_len += copy;
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error:
	inet->cork.length -= length;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err; 
}

/**
 * 当网卡支持分散/聚集IO时，实现"0拷贝"TCP/IP用到的接口。
 * 与ip_append_data对应。
 * 当前由UDP使用，TCP中对应的函数是do_tcp_sendpage
 */
ssize_t	ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	rt = inet->cork.rt;
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (!(rt->u.dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
	mtu = inet->cork.fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.length + size > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu);
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	inet->cork.length += size;

	while (size > 0) {
		int i;

		/* Check if the remaining data fits into current packet. */
		len = mtu - skb->len;
		if (len < size)
			len = maxfraglen - skb->len;
		if (len <= 0) {
			struct sk_buff *skb_prev;
			char *data;
			struct iphdr *iph;
			int alloclen;

			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fragheaderlen + fraggap);
			skb->nh.iph = iph = (struct iphdr *)data;
			data += fragheaderlen;
			skb->h.raw = data;

			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				skb_trim(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		/**
		 * 判断是否可以与合并
		 */
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i-1].size += len;/* 直接修改上一个frag合并。 */
		} else if (i < MAX_SKB_FRAGS) {
			/**
			 * 增加页面计数，同时用skb_fill_page_desc修改frag
			 */
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			unsigned int csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		offset += len;
		size -= len;
	}
	return 0;

error:
	inet->cork.length -= size;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
/**
 * 当L4层决定是时候把排在sw_write_queue里的那些片段（通过ip_append_data或ip_append_page）打包起来传输时（也就是因为某个协议特定的准则，或者因为较高层应用程序通知说要传送数据），就会调用ip_push_pending_frames：
 */
int ip_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = inet->cork.rt;
	struct iphdr *iph;
	int df = 0;
	__u8 ttl;
	int err = 0;

	/**
	 * 没有需要发送的数据。退出。
	 */
	if ((skb = __skb_dequeue(&sk->sk_write_queue)) == NULL)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb->nh.raw)
		__skb_pull(skb, skb->nh.raw - skb->data);
	/**
	 * 这个循环是计算所有分片的总长。
	 */
	while ((tmp_skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		__skb_pull(tmp_skb, skb->h.raw - skb->nh.raw);
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		__sock_put(tmp_skb->sk);
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	/**
	 * 如果用户设置的标志要求进行PMTU查找，那么就要在IP选项中带上DF标志。
	 */
	if (inet->pmtudisc != IP_PMTUDISC_DO)
		skb->local_df = 1;

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If local_df is set too, we still allow to fragment this frame
	 * locally. */
	/**
	 * 计算DF标志。
	 */
	if (inet->pmtudisc == IP_PMTUDISC_DO || /* 套接字希望进行PMTU发现 */
	    (!skb_shinfo(skb)->frag_list && ip_dont_fragment(sk, &rt->u.dst)))
		df = htons(IP_DF);/* df反映出包的"不分段状态" */

	/**
	 * 有选项。
	 */
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	/**
	 * 如果是多播，那么ttl一般是1，也可以由用户指定ttl。
	 * 如果是单播，那么ttl默认是64，但是可以通过proc修改默认值。
	 */
	if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->u.dst);

	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	/**
	 * 标准报头长度为20个字节。如果有选项，会在处理选项时加上选项的长度。
	 */
	iph->ihl = 5;
	/**
	 * 如果报头中有IP选项，则会用ip_options_build处理那些选项。
	 * 给ip_options_build的最后一个输入参数是0，以告诉该API，它正在填写的是第一个片段的选项。
	 * 这样的区别是必要的，因为第一个片段的IP选项会有不同的方式。
	 */
	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, inet->cork.addr, rt, 0);
	}
	iph->tos = inet->tos;
	iph->tot_len = htons(skb->len);
	iph->frag_off = df;
	/**
	 * 计算报文ID。
	 */
	if (!df) {
		__ip_select_ident(iph, &rt->u.dst, 0);	/* 根据长效IP端点进行ID计算。 */
	} else {
		iph->id = htons(inet->id++);/* 对不能分段的包，则根据流进行ID递增。这是为了处理windows的一个BUG。 */
	}
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	iph->saddr = rt->rt_src;
	iph->daddr = rt->rt_dst;
	ip_send_check(iph);

	/**
	 * 流量控制使用skb->priority来决定要把该包排入哪一个出队列。
	 */
	skb->priority = sk->sk_priority;
	skb->dst = dst_clone(&rt->u.dst);

	/* Netfilter gets whole the not fragmented skb. */
	/**
	 * 把缓冲区传给dst_output以完成传输之前，此函数必须取得netfilter的权限才能做这件事。
	 * 注意：只会为一个包中的所有片段查询一次netfilter。
	 */
	err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, 
		      skb->dst->dev, dst_output);
	if (err) {
		if (err > 0)
			err = inet->recverr ? net_xmit_errno(err) : 0;
		if (err)
			goto error;
	}

out:
	/**
	 * 返回之前，此函数会清除IPCORK_OPT字段，使得cork结构的内容失效。
	 * 这是因为后续相同目的地的包会重复使用cork结构.
	 */
	inet->cork.flags &= ~IPCORK_OPT;
	if (inet->cork.opt) {
		kfree(inet->cork.opt);
		inet->cork.opt = NULL;
	}
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
	return err;

error:
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

/*
 *	Throw away all pending data on the socket.
 */
void ip_flush_pending_frames(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	inet->cork.flags &= ~IPCORK_OPT;
	if (inet->cork.opt) {
		kfree(inet->cork.opt);
		inet->cork.opt = NULL;
	}
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
}


/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset, 
			      int len, int odd, struct sk_buff *skb)
{
	unsigned int csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;  
}

/* 
 *	Generic function to send a packet as reply to another packet.
 *	Used to send TCP resets so far. ICMP should use this function too.
 *
 *	Should run single threaded per socket because it uses the sock 
 *     	structure to pass arguments.
 *
 *	LATER: switch from ip_build_xmit to ip_append_*
 */
void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct {
		struct ip_options	opt;
		char			data[40];
	} replyopts;
	struct ipcm_cookie ipc;
	u32 daddr;
	struct rtable *rt = (struct rtable*)skb->dst;

	if (ip_options_echo(&replyopts.opt, skb))
		return;

	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;

	if (replyopts.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (ipc.opt->srr)
			daddr = replyopts.opt.faddr;
	}

	{
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(skb->nh.iph->tos) } },
				    /* Not quite clean, but right. */
				    .uli_u = { .ports =
					       { .sport = skb->h.th->dest,
					         .dport = skb->h.th->source } },
				    .proto = sk->sk_protocol };
		if (ip_route_output_key(&rt, &fl))
			return;
	}

	/* And let IP do all the hard work.

	   This chunk is not reenterable, hence spinlock.
	   Note that it uses the fact, that this function is called
	   with locally disabled BH and that sk cannot be already spinlocked.
	 */
	bh_lock_sock(sk);
	inet->tos = skb->nh.iph->tos;
	sk->sk_priority = skb->priority;
	sk->sk_protocol = skb->nh.iph->protocol;
	ip_append_data(sk, ip_reply_glue_bits, arg->iov->iov_base, len, 0,
		       &ipc, rt, MSG_DONTWAIT);
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (arg->csumoffset >= 0)
			*((u16 *)skb->h.raw + arg->csumoffset) = csum_fold(csum_add(skb->csum, arg->csum));
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(sk);
	}

	bh_unlock_sock(sk);

	ip_rt_put(rt);
}

/*
 *	IP protocol layer initialiser
 */
/**
 * 用于将ETH_P_IP的协议处理函数注册为ip_rcv。
 * ip_init会调用dev_add_pack(&ip_packet_type);注册此结构。
 */
static struct packet_type ip_packet_type = {
	.type = __constant_htons(ETH_P_IP),
	.func = ip_rcv,
};

/*
 *	IP registers the packet type and then calls the subprotocol initialisers
 */
/**
 * IPV4协议初始化函数。
 */
void __init ip_init(void)
{
	/**
	 * 用dev_add_pack函数为IP包注册处理函数，此处理程序为名为ip_rcv的函数。
	 */
	dev_add_pack(&ip_packet_type);

	/**
	 * 初始化路由子系统，包括与协议无关的缓存。
	 */
	ip_rt_init();
	/**
	 * 初始化用于管理IP端点的基础架构。
	 */
	inet_initpeers();

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
	igmp_mc_proc_init();
#endif
}

EXPORT_SYMBOL(ip_finish_output);
EXPORT_SYMBOL(ip_fragment);
EXPORT_SYMBOL(ip_generic_getfrag);
EXPORT_SYMBOL(ip_queue_xmit);
EXPORT_SYMBOL(ip_send_check);

#ifdef CONFIG_SYSCTL
EXPORT_SYMBOL(sysctl_ip_default_ttl);
#endif
