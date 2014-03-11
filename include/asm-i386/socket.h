#ifndef _ASM_SOCKET_H
#define _ASM_SOCKET_H

#include <asm/sockios.h>

/* For setsockopt(2) */
#define SOL_SOCKET	1

/**
 * 使能此选项后，网络模块会调用SOCK_DEBUG宏向屏幕或者日志输出调试信息。
 */
#define SO_DEBUG	1
/**
 * 允许两个套接口复用地址和端口。
 * 要求两个套接口都设置此选项，或者第二个套接口设置此选项大于1.
 */
#define SO_REUSEADDR	2
/**
 * 从传输控制块中获得套接口的类型，如SOCK_DGRAM、SOCK_STREAM。
 */
#define SO_TYPE		3
/**
 * 从传输控制块中获得错误码。首先从sk_err中获得，如果为0，再从sk_err_soft中获得错误码。
 * 0表示没有错误。
 */
#define SO_ERROR	4
/**
 * 不需要查询路由表，直接从绑定的接口将数据发送出去。
 * 此选项的值保存在传输控制块的SOCK_LOCALROUTE标志位中。
 */
#define SO_DONTROUTE	5
/**
 * 表示套接口已经配置成收发广播消息。此选项仅仅对非SOCK_STREAM类型的套接口有效。
 */
#define SO_BROADCAST	6
/**
 * 设置发送缓冲区大小。不能大于sysctl_wmem_max。
 * 如果不设置，则默认缓冲区大小为tcp_wmem[1]
 */
#define SO_SNDBUF	7
/**
 * 设置接收缓冲区大小。
 */
#define SO_RCVBUF	8
/**
 * 是否启动保活功能。
 * 保存在传输控制块的SOCK_KEEPOPEN标志中。
 */
#define SO_KEEPALIVE	9
/**
 * 带外数据与普通数据流一起。
 * 此设置值保存在SOCK_URGINLINE标志中。
 */
#define SO_OOBINLINE	10
/**
 * 用于决定RAW和UDP是否进行校验和。保存在sk_no_check成员中。
 */
#define SO_NO_CHECK	11
/**
 * 设置发送或者转发包的QoS类别，选项值保存在sk_priorit成员中。其值必须介于0-6之间。
 */
#define SO_PRIORITY	12
/**
 * 设置或者获取套接口的延迟时间值。
 */
#define SO_LINGER	13
/**
 * 已经废弃
 */
#define SO_BSDCOMPAT	14
/* To add :#define SO_REUSEPORT 15 */
/**
 * 主要用于PF_UNIX协议族
 */
#define SO_PASSCRED	16
#define SO_PEERCRED	17
/**
 * 接收缓存下限值。保存在传输控制块的sk_rcvlowat成员中。
 */
#define SO_RCVLOWAT	18
/**
 * 发送缓存下限值。始终为1.
 */
#define SO_SNDLOWAT	19
/**
 * 设置或者获取接收超时值，以毫秒为单位。
 * 保存在sk_rcvtimeo成员中。
 */
#define SO_RCVTIMEO	20
/**
 * 发送超时值，以毫秒为单位。
 * 保存在sk_sndtimeo成员中。
 */
#define SO_SNDTIMEO	21

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

/**
 * 将套接口绑定到指定设备上。
 * 保存在sk_bound_def_if成员中。
 */
#define SO_BINDTODEVICE	25

/* Socket filtering */
/**
 * 装载、卸载套接口的过滤器。
 */
#define SO_ATTACH_FILTER        26
#define SO_DETACH_FILTER        27

/**
 * 获取对端的地址和端口。保存在daddr和dport中。
 */
#define SO_PEERNAME		28
/**
 * 如果为TRUE，那么将数据包接收时间作为时间戳。
 * 保存在SOCK_RCVTSTAMP标志位中。
 */
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP

/**
 * 是否处于listen状态。
 */
#define SO_ACCEPTCONN		30

/**
 * 从安全模块中获取安全认证的上下文。
 */
#define SO_PEERSEC		31

#endif /* _ASM_SOCKET_H */
