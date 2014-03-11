/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

const unsigned char bridge_ula[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static int br_pass_frame_up_finish(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
	netif_rx(skb);

	return 0;
}

/**
 * 当网桥设备处理帧时，如果数据包的目标地址是本地地址，或者网桥设备处于混杂模式，则需要将数据包上送到本机协议栈。
 * 这是br_pass_frame_up函数的主要作用:将数据包上送给本机。
 */
static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	/**
	 * 网桥设备本机收到的包。
	 */
	br->statistics.rx_packets++;
	br->statistics.rx_bytes += skb->len;

	/**
	 * 当包被网络设备接收时，dev指向接收包的设备，当时，需要将设备改为网桥设备上送到协议栈。
	 */
	indev = skb->dev;
	skb->dev = br->dev;

	/**
	 * 如果防火墙允许本包继续上送，则调用br_pass_frame_up_finish向上层发送包。
	 * br_pass_frame_up_finish仅仅简单的调用netif_rx
	 */
	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
			br_pass_frame_up_finish);
}

/* note: already called with rcu_read_lock (preempt_disabled) */
/**
 * 网桥代码处理数据入帧。
 */
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = skb->dev->br_port;
	struct net_bridge *br = p->br;
	struct net_bridge_fdb_entry *dst;
	int passedup = 0;

	/**
	 * 网桥设备(不是网桥端口所在的设备)处于混杂模式，需要继续向上层发送包。
	 */
	if (br->dev->flags & IFF_PROMISC) {
		struct sk_buff *skb2;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 != NULL) {
			passedup = 1;
			br_pass_frame_up(br, skb2);
		}
	}

	/**
	 * 广播包，需要向所有端口转发。
	 */
	if (dest[0] & 1) {
		/**
		 * 进行一次flood发送。
		 */
		br_flood_forward(br, skb, !passedup);
		/**
		 * 需要本机上层上送数据包。
		 */
		if (!passedup)
			br_pass_frame_up(br, skb);
		goto out;
	}

	/**
	 * 在转发数据库中搜索目标地址。
	 */
	dst = __br_fdb_get(br, dest);
	/**
	 * 目标地址是本机地址。
	 */
	if (dst != NULL && dst->is_local) {
		/**
		 * 如果还没有上送，则上送，否则删除包。
		 */
		if (!passedup)
			br_pass_frame_up(br, skb);
		else
			kfree_skb(skb);
		goto out;
	}

	/**
	 * 目标地址在转发数据库中，则通过目标端口转发包。
	 */
	if (dst != NULL) {
		br_forward(dst->dst, skb);
		goto out;
	}

	/**
	 * 目标地址还没有在转发数据库中，通过所有端口发送一下包，即flood风暴。
	 */
	br_flood_forward(br, skb, 0);

out:
	return 0;
}

/*
 * Called via br_handle_frame_hook.
 * Return 0 if *pskb should be processed furthur
 *	  1 if *pskb is handled
 * note: already called with rcu_read_lock (preempt_disabled) 
 */
/**
 * 网桥代码处理入帧
 */
int br_handle_frame(struct net_bridge_port *p, struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;

	/**
	 * 任何在禁止的端口上收到的帧都被丢弃。
	 */
	if (p->state == BR_STATE_DISABLED)
		goto err;

	/**
	 * 源MAC地址是多播地址。丢弃。
	 */
	if (eth_hdr(skb)->h_source[0] & 1)
		goto err;

	/**
	 * BR_STATE_LEARNING和BR_STATE_FORWARDING两种状态都需要进行地址学习。
	 */
	if (p->state == BR_STATE_LEARNING ||
	    p->state == BR_STATE_FORWARDING)
		br_fdb_insert(p->br, p, eth_hdr(skb)->h_source, 0);

	if (p->br->stp_enabled &&/* 打开了STP支持 */
	    !memcmp(dest, bridge_ula, 5) &&/* 目标地址是从01:80:C2:00:00:00到01:80:C2:00:00:FF内的L2层广播地址，它们被IEEE保留给标准协议。准确的说，第一个地址01:80:C2:00:00:00被用于802.1D STP：配置BPDU和TCN BPDU都发送到这个地址。 */
	    !(dest[5] & 0xF0)) {
		if (!dest[5]) {/* 目标地址是否是STP多播地址。 */
			NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev, 
				NULL, br_stp_handle_bpdu);/* 如果netfilter接受，则调用br_stp_handle_bpdu处理BPDU包 */
			return 1;
		}
	}
	/**
	 * 不是BPDU，或者没有开启STP功能。
	 */
	else if (p->state == BR_STATE_FORWARDING) {/* 端口处于激活状态，需要处理帧转发。 */
		/**
		 * L2层的防火墙功能。ebt表可以过滤并销毁任何类型的帧。
		 * 由于一个网卡可以同时配置成网桥端口和IP接口，因此，需要确定该包应该由网桥还是路由还处理。
		 */
		if (br_should_route_hook) {
			if (br_should_route_hook(pskb)) 
				return 0;
			/**
			 * br_should_route_hook可能修改skb，因此重新设置局部变量，并随后确定包类型。
			 */
			skb = *pskb;
			dest = eth_hdr(skb)->h_dest;
		}

		/**
		 * 包的目的地址与接收设备的MAC地址相等，即发给本机的包。
		 */
		if (!memcmp(p->br->dev->dev_addr, dest, ETH_ALEN))
			skb->pkt_type = PACKET_HOST;

		/**
		 * 由br_handle_frame_finish处理接收到的帧。
		 */
		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);
		return 1;
	}

err:
	kfree_skb(skb);
	return 1;
}
