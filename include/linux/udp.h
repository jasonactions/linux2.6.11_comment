/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the UDP protocol.
 *
 * Version:	@(#)udp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_UDP_H
#define _LINUX_UDP_H

#include <linux/types.h>

struct udphdr {
	__u16	source;
	__u16	dest;
	__u16	len;
	__u16	check;
};

/* UDP socket options */
#define UDP_CORK	1	/* Never send partially complete segments */
#define UDP_ENCAP	100	/* Set the socket to accept encapsulated packets */

/* UDP encapsulation types */
#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define UDP_ENCAP_ESPINUDP	2 /* draft-ietf-ipsec-udp-encaps-06 */

#ifdef __KERNEL__

#include <linux/config.h>
#include <net/sock.h>
#include <linux/ip.h>

/**
 * UDP传输控制块
 */
struct udp_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
	/**
	 * 0表示数据已经从UDP套接口发送到IP层，可以继续调用sendmsg发送数据。
	 * AF_INET表示UDP正在处理调用sendmsg的发送数据，不需要处理目的地址、路由等信息，直接处理UDP数据
	 */
	int		 pending;	/* Any pending frames ? */
	/**
	 * 标识发送的UDP数据是否组成一个单独的IP数据报发送出去，由UDP的UDP_CORK选项设置。
	 */
	unsigned int	 corkflag;	/* Cork is required */
	/**
	 * 标识本套接口是否通过IPSEC封装，由UDP的UDP_ENCAP套接口选项设置。
	 */
  	__u16		 encap_type;	/* Is this an Encapsulation socket? */
	/*
	 * Following member retains the infomation to create a UDP header
	 * when the socket is uncorked.
	 */
	/* 标识待发送数据的长度 */
	__u16		 len;		/* total length of pending frames */
};

static inline struct udp_sock *udp_sk(const struct sock *sk)
{
	return (struct udp_sock *)sk;
}

#endif

#endif	/* _LINUX_UDP_H */
