/*
 *	common UDP/RAW code
 *	Linux INET implementation
 *
 * Authors:
 * 	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either version
 * 	2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/route.h>

/* connect连接的UDP传输层实现 */
int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
	struct rtable *rt;
	u32 saddr;
	int oif;
	int err;

	
	if (addr_len < sizeof(*usin))/* 检查参数是否有效，包含长度、地址簇 */
	  	return -EINVAL;

	if (usin->sin_family != AF_INET) 
	  	return -EAFNOSUPPORT;

	sk_dst_reset(sk);/* 传输控制块可能传输过数据，因此需要将路由缓存清除 */

	oif = sk->sk_bound_dev_if;
	saddr = inet->saddr;
	if (MULTICAST(usin->sin_addr.s_addr)) {/* 目的地址是多播地址 */
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}
	/* 查询输出路由 */
	err = ip_route_connect(&rt, usin->sin_addr.s_addr, saddr,
			       RT_CONN_FLAGS(sk), oif,
			       sk->sk_protocol,
			       inet->sport, usin->sin_port, sk);
	if (err)
		return err;
	/* 目的地址是广播地址，而套接口不支持广播，则返回错误 */
	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		return -EACCES;
	}
	/* 将查询得到的路由缓存中的源地址、目的地址及目的端口传输控制块中 */
  	if (!inet->saddr)
	  	inet->saddr = rt->rt_src;	/* Update source address */
	if (!inet->rcv_saddr)
		inet->rcv_saddr = rt->rt_src;
	inet->daddr = rt->rt_dst;
	inet->dport = usin->sin_port;
	sk->sk_state = TCP_ESTABLISHED;
	inet->id = jiffies;

	/* 缓存目的路由缓存到传输控制块中 */
	sk_dst_set(sk, &rt->u.dst);
	return(0);
}

EXPORT_SYMBOL(ip4_datagram_connect);

