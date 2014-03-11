#ifndef __LINUX_IF_PACKET_H
#define __LINUX_IF_PACKET_H

struct sockaddr_pkt
{
	unsigned short spkt_family;
	unsigned char spkt_device[14];
	unsigned short spkt_protocol;
};

struct sockaddr_ll
{
	unsigned short	sll_family;
	unsigned short	sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
};

/* Packet types */

/**
 * 表示帧的类型，分类是由 L2 的目的地址来决定的
 */
/**
 * 包的目的地址与收到它的网络设备的L2地址相等。换句话说，这个包是发给本机的。
 */
#define PACKET_HOST		0		/* To us		*/
/**
 * 包的目的地址是一个广播地址，而这个广播地址也是收到这个包的网络设备的广播地址。
 */
#define PACKET_BROADCAST	1		/* To all		*/
/**
 * 包的目的地址是一个多播地址，而这个多播地址是收到这个包的网络设备所注册的多播地址。
 */
#define PACKET_MULTICAST	2		/* To group		*/
/**
 * 包的目的地址与收到它的网络设备的地址完全不同（不管是单播，多播还是广播），因此，如果本机的转发功能没有启用，这个包会被丢弃。
 */
#define PACKET_OTHERHOST	3		/* To someone else 	*/
/**
 * 这个包将被发出。用到这个标记的功能包括 Decnet 协议，或者是为每个网络tap都复制一份发出包的函数。
 */
#define PACKET_OUTGOING		4		/* Outgoing of any type */
/* These ones are invisible by user level */
/**
 * 这个包发向 loopback 设备。由于有这个标记，在处理 loopback 设备时，内核可以跳过一些真实设备才需要的操作。
 */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
/**
 * 这个包由快速路由代码查找路由。快速路由功能在2.6内核中已经去掉了。
 */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/

/* Packet socket options */

#define PACKET_ADD_MEMBERSHIP		1
#define PACKET_DROP_MEMBERSHIP		2
#define PACKET_RECV_OUTPUT		3
/* Value 4 is still used by obsolete turbo-packet. */
#define PACKET_RX_RING			5
#define PACKET_STATISTICS		6
#define PACKET_COPY_THRESH		7

struct tpacket_stats
{
	unsigned int	tp_packets;
	unsigned int	tp_drops;
};

struct tpacket_hdr
{
	unsigned long	tp_status;
#define TP_STATUS_KERNEL	0
#define TP_STATUS_USER		1
#define TP_STATUS_COPY		2
#define TP_STATUS_LOSING	4
#define TP_STATUS_CSUMNOTREADY	8
	unsigned int	tp_len;
	unsigned int	tp_snaplen;
	unsigned short	tp_mac;
	unsigned short	tp_net;
	unsigned int	tp_sec;
	unsigned int	tp_usec;
};

#define TPACKET_ALIGNMENT	16
#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct sockaddr_ll))

/*
   Frame structure:

   - Start. Frame must be aligned to TPACKET_ALIGNMENT=16
   - struct tpacket_hdr
   - pad to TPACKET_ALIGNMENT=16
   - struct sockaddr_ll
   - Gap, chosen so that packet data (Start+tp_net) alignes to TPACKET_ALIGNMENT=16
   - Start+tp_mac: [ Optional MAC header ]
   - Start+tp_net: Packet data, aligned to TPACKET_ALIGNMENT=16.
   - Pad to align to TPACKET_ALIGNMENT=16
 */

struct tpacket_req
{
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
};

struct packet_mreq
{
	int		mr_ifindex;
	unsigned short	mr_type;
	unsigned short	mr_alen;
	unsigned char	mr_address[8];
};

#define PACKET_MR_MULTICAST	0
#define PACKET_MR_PROMISC	1
#define PACKET_MR_ALLMULTI	2

#endif
