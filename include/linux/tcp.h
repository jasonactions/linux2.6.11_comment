/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>

/* TCP首部 */
struct tcphdr {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__u16	window;
	__u16	check;
	__u16	urg_ptr;
};


enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,	 /* now a valid state */

  TCP_MAX_STATES /* Leave at the end! */
};

#define TCP_STATE_MASK	0xF
#define TCP_ACTION_FIN	(1 << 7)

enum {
  TCPF_ESTABLISHED = (1 << 1),
  TCPF_SYN_SENT  = (1 << 2),
  TCPF_SYN_RECV  = (1 << 3),
  TCPF_FIN_WAIT1 = (1 << 4),
  TCPF_FIN_WAIT2 = (1 << 5),
  TCPF_TIME_WAIT = (1 << 6),
  TCPF_CLOSE     = (1 << 7),
  TCPF_CLOSE_WAIT = (1 << 8),
  TCPF_LAST_ACK  = (1 << 9),
  TCPF_LISTEN    = (1 << 10),
  TCPF_CLOSING   = (1 << 11) 
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__u32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

#ifdef __KERNEL__

#include <linux/config.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>

/* This defines a selective acknowledgement block. */
struct tcp_sack_block {
	__u32	start_seq;
	__u32	end_seq;
};

enum tcp_congestion_algo {
	TCP_RENO=0,
	TCP_VEGAS,
	TCP_WESTWOOD,
	TCP_BIC,
};

/* 用于保存接收到的TCP选项信息 */
struct tcp_options_received {
/*	PAWS/RTTM data	*/
	/* 记录从接收到的段中取出时间戳设置到ts_recent的时间，用于检测ts_recent的有效性。如果超过24天则认为ts_recent无效 */
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	/* 下一个待发送的TCP段中的时间戳回显值 */
	__u32	ts_recent;	/* Time stamp to echo next		*/
	/* 最近一次接收到对端的TCP段的时间戳选项中的时间戳值 */
	__u32	rcv_tsval;	/* Time stamp value             	*/
	/* 最近一次接收到的TCP段中的时间戳回显应答 */
	__u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	/* 最近一次接收到的段是否存在时间戳选项 */
	char	saw_tstamp;	/* Saw TIMESTAMP on last packet		*/
	/* 是否启用时间戳选项 */
	char	tstamp_ok;	/* TIMESTAMP seen on SYN packet		*/
	/* 是否支持SACK */
	char	sack_ok;	/* SACK seen on SYN packet		*/
	/* 接收方是否支持窗口扩大因子，只能出现在SYN段中 */
	char	wscale_ok;	/* Wscale seen on SYN packet		*/
	/* 发送窗口扩大因子 */
	__u8	snd_wscale;	/* Window scaling received from sender	*/
	/* 接收窗口扩大因子 */
	__u8	rcv_wscale;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	/* 标识下次发送的段中SACK选项是否存在D-SACK */
	__u8	dsack;		/* D-SACK is scheduled			*/
	/* 下一个待发送的段中SACK选项中的SACK数组大小，如果为0则可以认为没有SACK。 */
	__u8	eff_sacks;	/* Size of SACK array to send with next packet */
	/* 下一个待发送的段中SACK选项中的SACK块数。 */
	__u8	num_sacks;	/* Number of SACK blocks		*/
	__u8	__pad;
	/* 用户设置的MSS上限 */
	__u16	user_mss;  	/* mss requested by user in ioctl */
	/* 该连接的对端MSS上限 */
	__u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

/**
 * TCP传输控制块。
 */
struct tcp_sock {
	/* inet_sock has to be the first member of tcp_sock */
	struct inet_sock	inet;/* IPV4传输控制块，必须是第一个字段 */
	/* TCP首部长度，包含选项 */
	int	tcp_header_len;	/* Bytes of tcp header to send		*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
    /**
     * 首部预测标志，会在发送和接收SYN、更新窗口及其他时候设置该标志 
	 * 它和时间戳、序列号等因素都是判断执行快速还是慢速路径的条件。
     */
	__u32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	/* 等待接收的下一个TCP段的序号，每接收到一个段后设置该值 */
 	__u32	rcv_nxt;	/* What we want to receive next 	*/
	/* 等待发送的下一个TCP段的序号 */
 	__u32	snd_nxt;	/* Next sequence we send		*/

	/* 在输出的段中，最早一个未确认段的序号 */
 	__u32	snd_una;	/* First byte we want an ack for	*/
	/**
	 * 最近发送的小包(小于MSS段)的最后一个字节序号，在成功发送段后，如果报文小于MSS，即更新该字段。 
	 * 主要用来更新是否启用Nagle算法。
	 */
 	__u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	/* 最后一次收到ACK段的时间，用于TCP保活。 */
	__u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	/* 最近一次发送数据包的时间，主要用于拥塞窗口的设置 */
	__u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	/* 指向与之绑定的本地端口信息，在绑定过程中被设置 */
	struct tcp_bind_bucket *bind_hash;
	/* Delayed ACK control data */
	/* 延迟确认控制数据块 */
	struct {
		/* 当前需要发送的ACK的紧急程序和状态，如TCP_ACK_SCHED */
		__u8	pending;	/* ACK is pending */
		/* 在快速发送模式中，可以快速发送ACK的数量 */
		__u8	quick;		/* Scheduled number of quick acks	*/
		/* 标识是否启用或禁用快速确认模式，通过TCP_QUICKACK选项设置。 */
		__u8	pingpong;	/* The session is interactive		*/
		/* 虽然应当发送ACK，但是套接口锁被占用了，因此发送过程被阻塞 */
		__u8	blocked;	/* Delayed ACK was blocked by socket lock*/
		/* 用来计算延时确认的估值，在接收到TCP段时会根据本次与上次接收的时间间隔来调整该值。 */
		__u32	ato;		/* Predicted tick of soft clock		*/
		/* 当前的延时确认时间，超时后会发送ACK */
		unsigned long timeout;	/* Currently scheduled timeout		*/
		/* 最近一次接收到数据包的时间 */
		__u32	lrcvtime;	/* timestamp of last received data packet*/
		/* 最近一次接收到数据段的长度，用于计算rcv_mss */
		__u16	last_seg_size;	/* Size of last incoming segment	*/
		/* 由最近接收到的段长度计算出来的mss，主要用来确定是否执行延时确认。 */
		__u16	rcv_mss;	/* MSS used for delayed ACK decisions	*/ 
	} ack;

	/* Data for direct copy to user */
	/* 用来控制复制数据到用户进程的控制块，包括描述用户空间缓存及其长度，prequeue队列及其占用的内存 */
	struct {
		/* 如果未启用tcp_low_latecy(一般未开启)，TCP段将首先缓存到此队列，直到进程主动读取时才真正接收到接收队列中处理 */
		struct sk_buff_head	prequeue;
		/* 如果未启用tcp_low_latecy(一般未开启),当前正在读取TCP流的进程，如果为NULL表示没有进程读取数据 */
		struct task_struct	*task;
		/* 如果未启用tcp_low_latecy(一般未开启),用来存放数据的用户空间地址，在接收处理TCP段时直接复制到用户空间 */
		struct iovec		*iov;
		/* prequeue队列当前消耗的内存 */
		int			memory;
		/* 用户缓存中可以使用的缓存大小，由recv等系统调用的len参数初始化 */
		int			len;
	} ucopy;

	/* 更新发送窗口的那个ACK段的序号，用来判断是否需要更新窗口。如果后续收到的ACK段大于此值，则需要更新。 */
	__u32	snd_wl1;	/* Sequence for window update		*/
	/* 接收方提供的接收窗口大小，即发送方发送窗口大小 */
	__u32	snd_wnd;	/* The window we expect to receive	*/
	/* 接收方通告过的最大接收窗口值。 */
	__u32	max_window;	/* Maximal window ever seen from peer	*/
	/* 最后一次更新的路径MTU */
	__u32	pmtu_cookie;	/* Last pmtu seen by socket		*/
	/* 发送方当前有效MSS */
	__u32	mss_cache;	/* Cached effective mss, not including SACKS */
	__u16	mss_cache_std;	/* Like mss_cache, but without TSO */
	/* IP首部中选项部分长度 */
	__u16	ext_header_len;	/* Network protocol overhead (IP/IPv6 options) */
	__u16	ext2_header_len;/* Options depending on route */
	/* 快速重传状态 */
	__u8	ca_state;	/* State of fast-retransmit machine 	*/
	/* 超时重传的次数 */
	__u8	retransmits;	/* Number of unrecovered RTO timeouts.	*/

	/* 当重传超时发生时，在启用F-RTO情况下，用来保存待发送的下一个TCP段的序号，处理F-RTO时使用 */
	__u32	frto_highmark;	/* snd_nxt when RTO occurred */
	/**
	 * 在不支持SACK时，为由于连续接收到重复确认而进入快速恢复阶段的重复确认数阀值。
	 * 在支持SACK时，在没有确定丢失包的情况下，是TCP流中可以重排序的数据段数。
	 */
	__u8	reordering;	/* Packet reordering metric.		*/
	/**
	 * 在传送超时后，记录在启用F-RTO算法时接收到ACK段的数目。
	 */
	__u8	frto_counter;	/* Number of new acks after RTO */

	__u8	adv_cong;	/* Using Vegas, Westwood, or BIC */
	__u8	defer_accept;	/* User waits for some data after accept() */

/* RTT measurement */
	/* 平滑的RTT，为避免浮点运算，将其放大8倍后保存 */
	__u32	srtt;		/* smoothed round trip time << 3	*/
	/* RTT平均偏差，值越大说明抖动越厉害 */
	__u32	mdev;		/* medium deviation			*/
	/* 每次发送窗口内的段被全部确认过程中，RTT平均偏差的最大值。描述抖动的最大范围。 */
	__u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	/* 平滑的RTT平均偏差，由mdev计算得到，用来计算RTO */
	__u32	rttvar;		/* smoothed mdev_max			*/
	/* 更新rttvar时的序号 */
	__u32	rtt_seq;	/* sequence number to update rttvar	*/
	/* 超时重传的时间，当往返时间超过此值时认为传输失败。根据网络情况动态计算。 */
	__u32	rto;		/* retransmit timeout			*/

	/* 发出(离开发送队列)而没有得到确认的段数目 */
	__u32	packets_out;	/* Packets which are "in flight"	*/
	/**
	 * 已经离开网络且未确认的TCP段，包含两种情况:
	 *		一是通过SACK确认的段
	 *		二是已经丢失的段
	 */
	__u32	left_out;	/* Packets which leaved network	*/
	/* 重传而未得到确认的段 */
	__u32	retrans_out;	/* Retransmitted packets out		*/
	/* 用于计算持续定时器的下一个设定值 */
	__u8	backoff;	/* backoff				*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
 	/**
 	 * 是否启用Nagle算法。该算法把较小的段组装成更大的段，解决由于小包导致网络拥塞的问题。参见TCP_NODELAY和TCP_CORK选项。
 	 *		TCP_NAGLE_OFF:		关闭nagle算法
 	 *		TCP_NAGLE_CORK:		对Nagle算法进行优化，使发送的段尽可能携带更多的数据，但是有200ms的时间限制。
 	 *		TCP_NAGLE_PUSH:		正常的Nagle算法，不对其进行优化。
 	 */
	__u8	nonagle;	/* Disable Nagle algorithm?             */
	/* 保活探测次数，最大为127。 */
	__u8	keepalive_probes; /* num of allowed keep alive probes	*/

	/* 持续定时器或周期性定时器发送出去但未被确认的TCP段数目。在收到ACK之后清0 */
	__u8	probes_out;	/* unanswered 0 window probes		*/
	/* 接收到的TCP选项 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	/* 拥塞控制时慢启动的阀值 */
 	__u32	snd_ssthresh;	/* Slow start size threshold		*/
	/* 当前拥塞窗口的大小 */
 	__u32	snd_cwnd;	/* Sending congestion window		*/
	/* 自从上次调整拥塞窗口到目前为止接收到的总的ACK段数 */
 	__u16	snd_cwnd_cnt;	/* Linear increase counter		*/
	/* 允许的最大拥塞窗口值，初始值为65535 */
	__u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	/* 从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时调节拥塞窗口 */
	__u32	snd_cwnd_used;
	/* 记录最近一次检验拥塞窗口的时间。 */
	__u32	snd_cwnd_stamp;

	/* Two commonly used timers in both sender and receiver paths. */
	/* 如果指定时间内没有接收到ACK，则认为发送失败 */
	unsigned long		timeout;
	/* 重传定时器和持续定时器，通过pending标志来区分。 */
 	struct timer_list	retransmit_timer;	/* Resend (no ack)	*/
	/* 延迟发送ACK的定时器 */
 	struct timer_list	delack_timer;		/* Ack delay 		*/

	/* 乱序缓存队列，用来暂存接收到的乱序的TCP段 */
	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	struct tcp_func		*af_specific;	/* Operations which are AF_INET{4,6} specific	*/

	/* 当前接收窗口的大小 */
 	__u32	rcv_wnd;	/* Current receiver window		*/
	/* 接收但还没有确认的最小的段 */
	__u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	/* 已经加入接收队列中的最后一个字节的序号 */
	__u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	/* 一般表示已经真正发送出去的最后一个字节序号，有时也表示期望发出去的最后一个字节的序号 */
	__u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	/* 还没有从内核空间复制到用户空间的段的第一个字节的序号 */
	__u32	copied_seq;	/* Head of yet unread data		*/

/*	SACKs data	*/
	/* 存储用于回复对端的D-SACK信息 */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	/* 存储用于回复对端的SACK信息 */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	/* 滑动窗口的最大值，在TCP建立连接时，进行初始化。太大会导致滑动窗口不能在TCP首部中表示。 */
	__u32	window_clamp;	/* Maximal window to advertise		*/
	/* 当前接收窗口大小的阀值，用于控制滑动窗口的缓慢增长 */
	__u32	rcv_ssthresh;	/* Current window clamp			*/
	/* 本端能接收的MSS上限，在建立连接时通告对方 */
	__u16	advmss;		/* Advertised MSS			*/

	/* 在建立TCP连接时最多允许重试发送SYN或SYN+ACK段的次数 */
	__u8	syn_retries;	/* num of allowed syn retries */
	/* 显式拥塞通知状态位，如TCP_ECN_OK */
	__u8	ecn_flags;	/* ECN status bits.			*/
	/* 在启用RTO算法的情况下，路径MTU探测成功，进入拥塞控制状态时保存的ssthresh值。主要用于撤销拥塞窗口时，恢复慢启动阀值 */
	__u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	__u16	__pad1;
	/* 发送后丢失在传输过程中段的数量。目前在TCP中，lost_out==packets_out */
	__u32	lost_out;	/* Lost packets			*/
	/* 启用SACK时，通过SACK的TCP选项标识已接收到段的数量。 */
	__u32	sacked_out;	/* SACK'd packets			*/
	/* SACK选项中，接收方接收到的段最高序号与snd_una之间有段数。FACK算法用来计算丢失在网络上的段数。 */
	__u32	fackets_out;	/* FACK'd packets			*/
	/* 记录发生拥塞时的snd_nxt，标识重传队列的尾部 */
	__u32	high_seq;	/* snd_nxt at onset of congestion	*/

	/**
	 * 主动连接时，记录第一个SYN段的发送时间，用来检测ACK序号是否回绕。 
	 * 在数据传输阶段，当发送超时重传时，记录上次重传阶段第一个重传段的发送时间，用于判断是否可以进行拥塞撤销。
	 */
	__u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	/* 当使用F-RTO算法进行超时处理时，或进入Recovery进行重传，或进入Loss开始慢启动时，记录当时的snd_una，标记重传起始点。 */
	__u32	undo_marker;	/* tracking retrans started here. */
	/* 在恢复拥塞控制之前可进行撤销的重传段数。在进入FRTO算法或拥塞状态Loss时清0，是检测拥塞撤销的条件之一。 */
	int	undo_retrans;	/* number of undoable retransmissions. */
	/* 紧急数据的序号，由所在段的序号和紧急指针相加而得到 */
	__u32	urg_seq;	/* Seq of received urgent pointer */
	/* 低8位存储接收到的紧急数据，高8位用于标识紧急数据的状态，如TCP_URG_NOTYET */
	__u16	urg_data;	/* Saved octet of OOB data and control flags */
	/**
	 * 挂起的时钟事件 
	 */
	__u8	pending;	/* Scheduled timer event	*/
	/* 标识处于紧急模式，告诉接收方紧急数据已经放在普通数据流中 */
	__u8	urg_mode;	/* In urgent mode		*/
	/* 紧急数据指针，即带外数据的序号。 */
	__u32	snd_up;		/* Urgent pointer		*/

	/* 整个连接中的重传次数 */
	__u32	total_retrans;	/* Total retransmits for entire connection */

	/* The syn_wait_lock is necessary only to avoid proc interface having
	 * to grab the main lock sock while browsing the listening hash
	 * (otherwise it's deadlock prone).
	 * This lock is acquired in read mode only from listening_get_next()
	 * and it's acquired in write mode _only_ from code that is actively
	 * changing the syn_wait_queue. All readers that are holding
	 * the master sock lock don't need to grab this lock in read mode
	 * too as the syn_wait_queue writes are always protected from
	 * the main sock lock.
	 */
	/* 访问listen_opt结构成员的控制锁 */
	rwlock_t		syn_wait_lock;
	/* 在建立侦听时创建，保存连接请求块 */
	struct tcp_listen_opt	*listen_opt;

	/* FIFO of established children */
	/* 等待接收的连接请求队列 */
	struct open_request	*accept_queue;
	struct open_request	*accept_queue_tail;

	/* TCP保活探测前，TCP连接的空闲时间 */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	/* 发送保活探测的间隔 */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	/* TCP迁移到CLOSED状态之前保持在FIN_WAIT_2状态的时间。 */
	int			linger2;

	/* 在启用tcp_syncookies的情况下，建立连接时记录接收syn段的时间，用来检测连接是否超时 */
	unsigned long last_synq_overflow; 

/* Receiver side RTT estimation */
	/* 存储接收方的RTT估算值，用于限制调整TCP接收缓冲区空间的间隔时间不能小于RTT */
	struct {
		__u32	rtt;/* 接收方估算的RTT */
		__u32	seq;/* 在接收到的段没有时间戳的情况下，更新接收方RTT时的接收窗口右端序号，每完成一个接收更新一次接收方RTT */
		__u32	time;/* 在段没有时间戳的情况下，记录每次更新RTT的时间 */
	} rcv_rtt_est;

/* Receiver queue space */
	/* 用来调整TCP接收缓冲空间和接收窗口大小，也用于实现通过调节接收窗口来进行流量控制的功能。每次将数据复制到用户空间，都计算新的TCP接收缓冲空间大小。 */
	struct {
		int	space;/* 用于调整接收缓存的大小 */
		__u32	seq;/* 已复制到用户空间的TCP段序号 */
		__u32	time;/* 记录最近一次进行调整的时间 */
	} rcvq_space;

/* TCP Westwood structure */
        struct {
                __u32    bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
                __u32    bw_est;           /* bandwidth estimate */
                __u32    rtt_win_sx;       /* here starts a new evaluation... */
                __u32    bk;
                __u32    snd_una;          /* used for evaluating the number of acked bytes */
                __u32    cumul_ack;
                __u32    accounted;
                __u32    rtt;
                __u32    rtt_min;          /* minimum observed RTT */
        } westwood;

/* Vegas variables */
	struct {
		__u32	beg_snd_nxt;	/* right edge during last RTT */
		__u32	beg_snd_una;	/* left edge  during last RTT */
		__u32	beg_snd_cwnd;	/* saves the size of the cwnd */
		__u8	doing_vegas_now;/* if true, do vegas for this RTT */
		__u16	cntRTT;		/* # of RTTs measured within last RTT */
		__u32	minRTT;		/* min of RTTs measured within last RTT (in usec) */
		__u32	baseRTT;	/* the min of all Vegas RTT measurements seen (in usec) */
	} vegas;

	/* BI TCP Parameters */
	struct {
		__u32	cnt;		/* increase cwnd by 1 after this number of ACKs */
		__u32 	last_max_cwnd;	/* last maximium snd_cwnd */
		__u32	last_cwnd;	/* the last snd_cwnd */
		__u32   last_stamp;     /* time when updated last_cwnd */
	} bictcp;
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
