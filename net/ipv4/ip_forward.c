/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *		
 * Version:	$Id: ip_forward.c,v 1.48 2000/12/13 18:31:48 davem Exp $
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for 
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast 
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

static inline int ip_forward_finish(struct sk_buff *skb)
{
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(IPSTATS_MIB_OUTFORWDATAGRAMS);

	if (unlikely(opt->optlen))
		/**
		 * ip_forward_options处理转发时的IP选项
		 * Router Alert和Strict Source Routing已经在ip_forward中处理。
		 * 现在，我们把该包传给函数ip_forward_options，以处理那些选项所需要的最后工作。
		 * 只要检查早前由ip_options_compile(由ip_rcv_finish调用)做初始化设置的标志（例如opt->rr_needaddr）和偏移量（例如opt->rr），就可以找出该做些什么。
		 * Ip_forward_options也会重算IP校验和
		 */
		ip_forward_options(skb);

	/**
	 * dst_output执行实际的传输。
	 * 但是在让设备驱动程序传输包以前，还有些任务要做。
	 */
	return dst_output(skb);
}

/**
 * 转发包。
 */
int ip_forward(struct sk_buff *skb)
{
	/**
	 * iph代表包的IP报头，而其初值设定会重复地来自于skb的iph字段.
	 * 此字段必须重新设置初值，因为报头可能因为ip_forward里的一些函数调用来被修改
	 */
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

	/**
	 * Router Alert选项（如果存在），则调用ip_call_ra_chain，如果ip_call_ra_chain发现有套口对此包有兴趣，则放弃转发。
	 */
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	/**
	 * 在ip_recv中已经处理过了，此处再检查，可能是重复了。
	 * 这个判断是放弃L2层包。
	 */
	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	/**
	 * 既然我们在转发包，那么，所有的动作都是在L3层，因此我们不用担心L4查验工作.
	 * 我们以CHECKSUM_NONE指出当前校验和无误。如果有些处理工作稍后修改了IP报头，TCP报头或有效负载，那么，在传输前，内核就会在那儿重算校验和。
	 */
	skb->ip_summed = CHECKSUM_NONE;
	
	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */

	iph = skb->nh.iph;

	/**
	 * 真实的转发流程是由递减TTL字段开始的。
	 * IP协议的定义表明，当TTL到达0值时（这意味着你接收时其值为1，而当你递减后，其值为0），则包就必须被丢弃.
	 * 然后一条特殊的ICMP消息就得传回给来源地，以让对方知道你丢弃了包。
	 */
	if (iph->ttl <= 1)
                goto too_many_hops;

	/**
	 * IPSEC安全检查失败。
	 */
	if (!xfrm4_route_forward(skb))
		goto drop;

	iph = skb->nh.iph;
	/**
	 * rt指向类型为rtable的数据结构，它包含转发引擎所需要的所有信息，包括下个跳点（rt_gateway）。
	 */
	rt = (struct rtable*)skb->dst;

	/**
	 * 如果IP报头包含一个Strict Source Route选项，而且下个跳点（由该选项中取出）和路由子系统找到的不同，则Source Routing选项就失败了，同时该包会被丢弃。
	 */
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;

	/* We are about to mangle packet. Copy it! */
	/**
	 * 接下来会修改TTL字段，对报头的修改可能需要进行一次报文拷贝。
	 * 当该包为共享时（如果包没有被共享，就可以修改），或者包头的可用空间不足以存储L2报头时，做个本地拷贝.
	 */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;
	iph = skb->nh.iph;

	/* Decrease ttl after skb cow done */
	/**
	 * TTL会由ip_deccrease_ttl递减，而且ip_decrease_ttl也会更新IP校验和。
	 */
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	/**
	 * 没有源路由，并且有比请求的还要更好的下一个跳点存在，则发送ICMP_REDIRECT消息
	 */
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr)
		ip_rt_send_redirect(skb);

	/**
	 * 从报头中取出优先级字段，供QoS层使用。
	 */
	skb->priority = rt_tos2priority(iph->tos);

	/**
	 * ip_forward_finish真正完成转发过程。其行为会根据报头中是否包含选项而有所不同。
	 */
	return NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ip_forward_finish);

sr_failed:
        /*
	 *	Strict routing permits no gatewaying
	 */
	 /**
	  * 严格源路由选项与路由子系统设置的下一跳不符，目标地址不可达。
	  */
         icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
         goto drop;

too_many_hops:
        /* Tell the sender its packet died... */
        icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
