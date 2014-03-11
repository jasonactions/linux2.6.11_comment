#ifndef _LINUX_IN_ROUTE_H
#define _LINUX_IN_ROUTE_H

/* IPv4 routing cache flags */

#define RTCF_DEAD	RTNH_F_DEAD
#define RTCF_ONLINK	RTNH_F_ONLINK

/* Obsolete flag. About to be deleted */
#define RTCF_NOPMTUDISC RTM_F_NOPMTUDISC

/**
 * 路由表项的所有变化通过Netlink通知给感兴趣的用户空间应用程序。
 * 该选项还没有完全实现。利用诸如ip route get 10.0.1.0/24 notify等命令来设置该标志。
 */
#define RTCF_NOTIFY	0x00010000
/**
 * 未使用。
 */
#define RTCF_DIRECTDST	0x00020000
/**
 * 对接收到的ICMP_REDIRECT消息作出响应而添加一条路由表项
 */
#define RTCF_REDIRECTED	0x00040000
/**
 * 未使用。
 */
#define RTCF_TPROXY	0x00080000

/**
 * 未使用。该标志已经被废弃，设置该标志是用于标记一条路由对快速交换（Fast Switching）合法。
 * 快速交换特性已经在2.6内核中被废弃。
 */
#define RTCF_FAST	0x00200000
/**
 * 不再被IPv4使用。该标志是用于标记报文来自于masqueraded源地址。
 */
#define RTCF_MASQ	0x00400000
/**
 * 这些标志不再被IPv4使用。它们以前被FastNAT特性使用，该特性在2.6内核中已经被删除
 */
#define RTCF_SNAT	0x00800000
/**
 * 当必须向源站送回ICMP_REDIRECT消息时，ip_route_input_slow设置该标志。
 * ip_forward依据该标志和其它信息，决定是否需要发送ICMP重定向消息。
 */
#define RTCF_DOREDIRECT 0x01000000
/**
 * 该标志主要用于告诉ICMP代码，不应当对地址掩码请求消息作出回应。
 * 每当调用fib_validate_source检查到接收报文的源地址通过一个本地作用范围（RT_SCOPE_HOST）的下一跳是可达时，就设置该标志。
 */
#define RTCF_DIRECTSRC	0x04000000
/**
 * 这些标志不再被IPv4使用。它们以前被FastNAT特性使用，该特性在2.6内核中已经被删除
 */
#define RTCF_DNAT	0x08000000
/**
 * 路由的目的地址是一个广播地址。
 */
#define RTCF_BROADCAST	0x10000000
/**
 * 路由的目的地址是一个多播地址。
 */
#define RTCF_MULTICAST	0x20000000
/**
 * 未被使用。依据IPROUTE2软件包的ip rule命令的语法，在该命令中有一个关键字reject，但该关键字还未被接受。
 */
#define RTCF_REJECT	0x40000000
/**
 * 路由的目的地址是一个本地地址（即本地接口上配置的某个地址）。
 * 对本地广播地址和本地多播地址也设置该标志
 */
#define RTCF_LOCAL	0x80000000

/**
 * 这些标志不再被IPv4使用。它们以前被FastNAT特性使用，该特性在2.6内核中已经被删除
 */
#define RTCF_NAT	(RTCF_DNAT|RTCF_SNAT)

#define RT_TOS(tos)	((tos)&IPTOS_TOS_MASK)

#endif /* _LINUX_IN_ROUTE_H */
