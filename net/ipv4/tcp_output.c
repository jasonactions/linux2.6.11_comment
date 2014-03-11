/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_output.c,v 1.146 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#include <net/tcp.h>

#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/smp_lock.h>

/* People can turn this off for buggy TCP's found in printers etc. */
/* 重传时，把数据包增大一些，来避免某些协议栈的BUG */
int sysctl_tcp_retrans_collapse = 1;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
/* 单个TSO段可消耗拥塞窗口比例 */
int sysctl_tcp_tso_win_divisor = 8;

static inline void update_send_head(struct sock *sk, struct tcp_sock *tp,
				    struct sk_buff *skb)
{
	sk->sk_send_head = skb->next;
	if (sk->sk_send_head == (struct sk_buff *)&sk->sk_write_queue)
		sk->sk_send_head = NULL;
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;
	tcp_packets_out_inc(sk, tp, skb);
}

/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(struct sock *sk, struct tcp_sock *tp)
{
	if (!before(tp->snd_una+tp->snd_wnd, tp->snd_nxt))
		return tp->snd_nxt;
	else
		return tp->snd_una+tp->snd_wnd;
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst && dst_metric(dst, RTAX_ADVMSS) < mss) {
		mss = dst_metric(dst, RTAX_ADVMSS);
		tp->advmss = mss;
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void tcp_cwnd_restart(struct tcp_sock *tp, struct dst_entry *dst)
{
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;

	if (tcp_is_vegas(tp)) 
		tcp_vegas_enable(tp);

	tp->snd_ssthresh = tcp_current_ssthresh(tp);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= tp->rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

/**
 * 当发送的TCP段有负载时，则检测拥塞窗口闲置是否超时。
 * 如果超时，则使拥塞窗口失效并重新计算拥塞窗口。
 */
static inline void tcp_event_data_sent(struct tcp_sock *tp,
				       struct sk_buff *skb, struct sock *sk)
{
	u32 now = tcp_time_stamp;

	/* 拥塞窗口闲置时间超过了RTO */
	if (!tp->packets_out && (s32)(now - tp->lsndtime) > tp->rto)
		tcp_cwnd_restart(tp, __sk_dst_get(sk));/* 使拥塞窗口失效并重新计算拥塞窗口 */

	tp->lsndtime = now;/* 记录TCP发送时间 */

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	/* 根据最近接收段的时间，来确认是否进入pingpong模式 */
	if ((u32)(now - tp->ack.lrcvtime) < tp->ack.ato)
		tp->ack.pingpong = 1;
}

static __inline__ void tcp_event_ack_sent(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_dec_quickack_mode(tp);
	tcp_clear_xmit_timer(sk, TCP_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss;

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. We try to be nice.
	 * If we are not window scaling, then this truncates
	 * our initial window offering to 32k. There should also
	 * be a sysctl option to stop being nice.
	 */
	(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window
		 * See RFC1323 for an explanation of the limit to 14 
		 */
		space = max_t(u32, sysctl_tcp_rmem[2], sysctl_rmem_max);
		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}

	/* Set initial window to value enough for senders,
	 * following RFC1414. Senders, not following this RFC,
	 * will be satisfied with 2.
	 */
	if (mss > (1<<*rcv_wscale)) {
		int init_cwnd = 4;
		if (mss > 1460*3)
			init_cwnd = 2;
		else if (mss > 1460)
			init_cwnd = 3;
		if (*rcv_wnd > init_cwnd*mss)
			*rcv_wnd = init_cwnd*mss;
	}

	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
}

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static __inline__ u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);

	/* Never shrink the offered window */
	if(new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = cur_win;
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;

	return new_win;
}


/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
/**
 * 发送一个TCP报文
 */
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
	if (skb != NULL) {
		struct inet_sock *inet = inet_sk(sk);
		struct tcp_sock *tp = tcp_sk(sk);
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
		int tcp_header_size = tp->tcp_header_len;
		struct tcphdr *th;
		int sysctl_flags;
		int err;

		BUG_ON(!tcp_skb_pcount(skb));

#define SYSCTL_FLAG_TSTAMPS	0x1
#define SYSCTL_FLAG_WSCALE	0x2
#define SYSCTL_FLAG_SACK	0x4

		sysctl_flags = 0;/* 标识TCP选项 */
		/* 根据TCP选项调整TCP首部长度 */
		if (tcb->flags & TCPCB_FLAG_SYN) {/* 如果当前段是SYN段，需要特殊处理一下 */
			/* SYN段必须通告MSS，因此报头加上MSS通告选项的长度 */
			tcp_header_size = sizeof(struct tcphdr) + TCPOLEN_MSS;
			if(sysctl_tcp_timestamps) {/* 启用了时间戳 */
				/* 报头加上时间戳标志 */
				tcp_header_size += TCPOLEN_TSTAMP_ALIGNED;
				sysctl_flags |= SYSCTL_FLAG_TSTAMPS;
			}
			if(sysctl_tcp_window_scaling) {/* 处理窗口扩大因子选项 */
				tcp_header_size += TCPOLEN_WSCALE_ALIGNED;
				sysctl_flags |= SYSCTL_FLAG_WSCALE;
			}
			if(sysctl_tcp_sack) {/* 处理SACK选项 */
				sysctl_flags |= SYSCTL_FLAG_SACK;
				if(!(sysctl_flags & SYSCTL_FLAG_TSTAMPS))
					tcp_header_size += TCPOLEN_SACKPERM_ALIGNED;
			}
		} else if (tp->rx_opt.eff_sacks) {/* 非SYN段，但是有SACK块 */
			/* A SACK is 2 pad bytes, a 2 byte header, plus
			 * 2 32-bit sequence numbers for each SACK block.
			 */
			/* 根据SACK块数调整TCP首部长度 */
			tcp_header_size += (TCPOLEN_SACK_BASE_ALIGNED +
					    (tp->rx_opt.eff_sacks * TCPOLEN_SACK_PERBLOCK));
		}
		
		/*
		 * If the connection is idle and we are restarting,
		 * then we don't want to do any Vegas calculations
		 * until we get fresh RTT samples.  So when we
		 * restart, we reset our Vegas state to a clean
		 * slate. After we get acks for this flight of
		 * packets, _then_ we can make Vegas calculations
		 * again.
		 */
		if (tcp_is_vegas(tp) && tcp_packets_in_flight(tp) == 0)
			tcp_vegas_enable(tp);

		/* 在报文首部中加入TCP首部 */
		th = (struct tcphdr *) skb_push(skb, tcp_header_size);
		/* 更新TCP首部指针 */
		skb->h.th = th;
		/* 设置报文的传输控制块 */
		skb_set_owner_w(skb, sk);

		/* Build TCP header and checksum it. */
		/* 填充TCP首部中的数据 */
		th->source		= inet->sport;
		th->dest		= inet->dport;
		th->seq			= htonl(tcb->seq);
		th->ack_seq		= htonl(tp->rcv_nxt);
		*(((__u16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) | tcb->flags);
		/* 设置TCP首部的接收窗口 */
		if (tcb->flags & TCPCB_FLAG_SYN) {
			/* RFC1323: The window in SYN & SYN/ACK segments
			 * is never scaled.
			 */
			th->window	= htons(tp->rcv_wnd);/* 对SYN段来说，接收窗口初始值为rcv_wnd */
		} else {
			/* 对其他段来说，调用tcp_select_window计算当前接收窗口的大小 */
			th->window	= htons(tcp_select_window(sk));
		}
		/* 初始化校验码和带外数据指针 */
		th->check		= 0;
		th->urg_ptr		= 0;

		if (tp->urg_mode &&/* 发送时设置了紧急方式 */
		    between(tp->snd_up, tcb->seq+1, tcb->seq+0xFFFF)) {/* 紧急指针在报文序号开始的65535范围内 */
			/* 设置紧急指针和带外数据标志位 */
			th->urg_ptr		= htons(tp->snd_up-tcb->seq);
			th->urg			= 1;
		}

		/* 开始构建TCP首部选项 */
		if (tcb->flags & TCPCB_FLAG_SYN) {
			/* 调用tcp_syn_build_options构建SYN段的首部 */
			tcp_syn_build_options((__u32 *)(th + 1),
					      tcp_advertise_mss(sk),
					      (sysctl_flags & SYSCTL_FLAG_TSTAMPS),
					      (sysctl_flags & SYSCTL_FLAG_SACK),
					      (sysctl_flags & SYSCTL_FLAG_WSCALE),
					      tp->rx_opt.rcv_wscale,
					      tcb->when,
		      			      tp->rx_opt.ts_recent);
		} else {
			/* 构建普通段的首部 */
			tcp_build_and_update_options((__u32 *)(th + 1),
						     tp, tcb->when);

			TCP_ECN_send(sk, tp, skb, tcp_header_size);
		}
		/* 计算传输层的校验和 */
		tp->af_specific->send_check(sk, th, skb->len, skb);

		/* 如果发送的段有ACK标志，则通知延时确认模块，递减快速发送ACK段的数量，同时停止延时确认定时器 */
		if (tcb->flags & TCPCB_FLAG_ACK)
			tcp_event_ack_sent(sk);

		if (skb->len != tcp_header_size)/* 发送的段有负载，则检测拥塞窗口闲置是否超时 */
			tcp_event_data_sent(tp, skb, sk);

		TCP_INC_STATS(TCP_MIB_OUTSEGS);

		/* 调用IP层的发送函数发送报文 */
		err = tp->af_specific->queue_xmit(skb, 0);
		if (err <= 0)
			return err;

		/* 如果发送失败，则类似于接收到显式拥塞通知的处理 */
		tcp_enter_cwr(tp);

		/* NET_XMIT_CN is special. It does not guarantee,
		 * that this packet is lost. It tells that device
		 * is about to start to drop packets or already
		 * drops some packets of the same priority and
		 * invokes us to send less aggressively.
		 */
		return err == NET_XMIT_CN ? 0 : err;
	}
	return -ENOBUFS;
#undef SYSCTL_FLAG_TSTAMPS
#undef SYSCTL_FLAG_WSCALE
#undef SYSCTL_FLAG_SACK
}


/* This routine just queue's the buffer 
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	__skb_queue_tail(&sk->sk_write_queue, skb);
	sk_charge_skb(sk, skb);

	/* Queue it, remembering where we must start sending. */
	if (sk->sk_send_head == NULL)
		sk->sk_send_head = skb;
}

static inline void tcp_tso_set_push(struct sk_buff *skb)
{
	/* Force push to be on for any TSO frames to workaround
	 * problems with busted implementations like Mac OS-X that
	 * hold off socket receive wakeups until push is seen.
	 */
	if (tcp_skb_pcount(skb) > 1)
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
/* 输出发送队列上的第一个段 */
void tcp_push_one(struct sock *sk, unsigned cur_mss)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = sk->sk_send_head;

	if (tcp_snd_test(tp, skb, cur_mss, TCP_NAGLE_PUSH)) {/* 判断是否可以立即发送，主要是考虑拥塞控制 */
		/* Send it out now. */
		/* 记录最后发送时间 */
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		tcp_tso_set_push(skb);
		/* 发送报文 */
		if (!tcp_transmit_skb(sk, skb_clone(skb, sk->sk_allocation))) {
			/* 发送成功则更新发送队列头及一些统计数据 */
			sk->sk_send_head = NULL;
			tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;
			tcp_packets_out_inc(sk, tp, skb);
			return;
		}
	}
}

void tcp_set_skb_tso_segs(struct sk_buff *skb, unsigned int mss_std)
{
	if (skb->len <= mss_std) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->tso_segs = 1;
		skb_shinfo(skb)->tso_size = 0;
	} else {
		unsigned int factor;

		factor = skb->len + (mss_std - 1);
		factor /= mss_std;
		skb_shinfo(skb)->tso_segs = factor;
		skb_shinfo(skb)->tso_size = mss_std;
	}
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope. 
 * Remember, these are still headerless SKBs at this point.
 */
static int tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize;
	u16 flags;

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	if (skb_cloned(skb) &&
	    skb_is_nonlinear(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */
	sk_charge_skb(sk, buff);

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;
	TCP_SKB_CB(skb)->flags = flags & ~(TCPCB_FLAG_FIN|TCPCB_FLAG_PSH);
	TCP_SKB_CB(buff)->flags = flags;
	TCP_SKB_CB(buff)->sacked =
		(TCP_SKB_CB(skb)->sacked &
		 (TCPCB_LOST | TCPCB_EVER_RETRANS | TCPCB_AT_TAIL));
	TCP_SKB_CB(skb)->sacked &= ~TCPCB_AT_TAIL;

	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_HW) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len, skb_put(buff, nsize),
						       nsize, 0);

		skb_trim(skb, len);

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_HW;
		skb_split(skb, buff, len);
	}

	buff->ip_summed = skb->ip_summed;

	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST) {
		tp->lost_out -= tcp_skb_pcount(skb);
		tp->left_out -= tcp_skb_pcount(skb);
	}

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, tp->mss_cache_std);
	tcp_set_skb_tso_segs(buff, tp->mss_cache_std);

	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST) {
		tp->lost_out += tcp_skb_pcount(skb);
		tp->left_out += tcp_skb_pcount(skb);
	}

	if (TCP_SKB_CB(buff)->sacked&TCPCB_LOST) {
		tp->lost_out += tcp_skb_pcount(buff);
		tp->left_out += tcp_skb_pcount(buff);
	}

	/* Link BUFF into the send queue. */
	__skb_append(skb, buff);

	return 0;
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static unsigned char *__pskb_trim_head(struct sk_buff *skb, int len)
{
	int i, k, eat;

	eat = len;
	k = 0;
	for (i=0; i<skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size <= eat) {
			put_page(skb_shinfo(skb)->frags[i].page);
			eat -= skb_shinfo(skb)->frags[i].size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_shinfo(skb)->frags[k].size -= eat;
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;

	skb->tail = skb->data;
	skb->data_len -= len;
	skb->len = skb->data_len;
	return skb->tail;
}

int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	if (skb_cloned(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	if (len <= skb_headlen(skb)) {
		__skb_pull(skb, len);
	} else {
		if (__pskb_trim_head(skb, len-skb_headlen(skb)) == NULL)
			return -ENOMEM;
	}

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_HW;

	skb->truesize	     -= len;
	sk->sk_queue_shrunk   = 1;
	sk->sk_wmem_queued   -= len;
	sk->sk_forward_alloc += len;

	/* Any change of skb->len requires recalculation of tso
	 * factor and mss.
	 */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(skb, tcp_skb_mss(skb));

	return 0;
}

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minumum of user_mss and mss received with SYN.
   It also does not include TCP options.

   tp->pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. tp->pmtu_cookie and tp->mss_cache are READ ONLY outside
   this function.			--ANK (980731)
 */
/* 为传输控制块中与mss相关的成员进行数据同步 */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	int mss_now;

	if (dst && dst->ops->get_mss)
		pmtu = dst->ops->get_mss(dst, pmtu);

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	/* 根据pmtu得到MSS，计算方法是pmtu减去IP首部长度和TCP首部长度 */
	mss_now = pmtu - tp->af_specific->net_header_len - sizeof(struct tcphdr);

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)/* MSS不能超过该连接的对端MSS上限 */
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	/* 再减去IP和TCP选项长度 */
	mss_now -= tp->ext_header_len + tp->ext2_header_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)/* MSS也不能小于48 */
		mss_now = 48;

	/* Now subtract TCP options size, not including SACKs */
	mss_now -= tp->tcp_header_len - sizeof(struct tcphdr);

	/* Bound mss with half of window */
	if (tp->max_window && mss_now > (tp->max_window>>1))/* MSS不能超过接收方通告过的接收窗口的最大值的一半 */
		mss_now = max((tp->max_window>>1), 68U - tp->tcp_header_len);

	/* And store cached results */
	tp->pmtu_cookie = pmtu;/* 保存pmtu，并更新mss到缓存中 */
	tp->mss_cache = tp->mss_cache_std = mss_now;

	return mss_now;
}

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 *
 * LARGESEND note: !urg_mode is overkill, only frames up to snd_up
 * cannot be large. However, taking into account rare use of URG, this
 * is not a big flaw.
 */
/* 计算当前有效MSS */
unsigned int tcp_current_mss(struct sock *sk, int large)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	unsigned int do_large, mss_now;

	/* 从套接口的路由缓存中取出PMTU */
	mss_now = tp->mss_cache_std;
	if (dst) {
		u32 mtu = dst_pmtu(dst);
		if (mtu != tp->pmtu_cookie ||/* PMTU与最近一次更新的PMTU不相等 */
		    tp->ext2_header_len != dst->header_len)
			mss_now = tcp_sync_mss(sk, mtu);/* 更新有效MSS */
	}

	do_large = (large &&
		    (sk->sk_route_caps & NETIF_F_TSO) &&
		    !tp->urg_mode);/* 确定是否支持TSO */

	if (do_large) {/* 支持TSO，则需要重新计算发送数据报的TCP段长度 */
		unsigned int large_mss, factor, limit;

		/* TSO模式下，TCP段长度的最大长度为64K减去IP首部及其选项、TCP首部的长度 */
		large_mss = 65535 - tp->af_specific->net_header_len -
			tp->ext_header_len - tp->ext2_header_len -
			tp->tcp_header_len;

		/* 不能超过接收方最大接收窗口的一半 */
		if (tp->max_window && large_mss > (tp->max_window>>1))
			large_mss = max((tp->max_window>>1),
					68U - tp->tcp_header_len);

		factor = large_mss / mss_now;

		/* Always keep large mss multiple of real mss, but
		 * do not exceed 1/tso_win_divisor of the congestion window
		 * so we can keep the ACK clock ticking and minimize
		 * bursting.
		 */
		limit = tp->snd_cwnd;
		if (sysctl_tcp_tso_win_divisor)
			limit /= sysctl_tcp_tso_win_divisor;
		limit = max(1U, limit);
		if (factor > limit)
			factor = limit;

		/* 支持TSO的TCP长度是当前有效MSS的整数倍，为什么?? */
		tp->mss_cache = mss_now * factor;

		mss_now = tp->mss_cache;
	}

	if (tp->rx_opt.eff_sacks)/* 支持SACK */
		/* 在有效MSS中减去SACK选项长度 */
		mss_now -= (TCPOLEN_SACK_BASE_ALIGNED +
			    (tp->rx_opt.eff_sacks * TCPOLEN_SACK_PERBLOCK));
	return mss_now;
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * Returns 1, if no segments are in flight and we have queued segments, but
 * cannot send anything now because of SWS or another problem.
 */
/* 将TCP发送队列上的段发送出去 */
int tcp_write_xmit(struct sock *sk, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now;

	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and all
	 * will be happy.
	 */
	if (sk->sk_state != TCP_CLOSE) {/* TCP_CLOSE状态不能发送数据 */
		struct sk_buff *skb;
		int sent_pkts = 0;/* 已发送总段数 */

		/* Account for SACKS, we may need to fragment due to this.
		 * It is just like the real MSS changing on us midstream.
		 * We also handle things correctly when the user adds some
		 * IP options mid-stream.  Silly to do, but cover it.
		 */
		mss_now = tcp_current_mss(sk, 1);

		while ((skb = sk->sk_send_head) &&/* 发送队列不空，则继续发送 */
		       tcp_snd_test(tp, skb, mss_now,/* 检测拥塞窗口大小，如果为0，则不能发送段 */
			       	    tcp_skb_is_last(sk, skb) ? nonagle :
				    			       TCP_NAGLE_PUSH)) {
			if (skb->len > mss_now) {/* 如果段长度超过了MSS，则进行分段。这可能是由于MSS发生变化引起的 */
				if (tcp_fragment(sk, skb, mss_now))
					break;
			}

			/* 记录报文发送时间，用于RTT计算 */
			TCP_SKB_CB(skb)->when = tcp_time_stamp;
			tcp_tso_set_push(skb);
			/* 发送TCP段 */
			if (tcp_transmit_skb(sk, skb_clone(skb, GFP_ATOMIC)))
				break;/* 如果发送失败，则终止发送过程 */

			/* Advance the send_head.  This one is sent out.
			 * This call will increment packets_out.
			 */
			/* 更新发送队列头，同时更新snd_nxt即下一个发送段的序号，然后统计发送但没有确认的段数。最后视情况复位重传定时器。 */
			update_send_head(sk, tp, skb);

			/* 如果发送的段小于MSS，则更新最近发送的小包的序号 */
			tcp_minshall_update(tp, mss_now, skb);
			sent_pkts = 1;
		}

		if (sent_pkts) {/* 如果本次发送了报文，则对拥塞窗口进行确认。 */
			tcp_cwnd_validate(sk, tp);
			return 0;
		}

		/* 本次没有发送数据，如果packets_out为0并且队列不为空，则表示成功 */
		return !tp->packets_out && sk->sk_send_head;
	}
	return 0;
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *  
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 * 
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 * 
 * BSD seems to make the following compromise:
 * 
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous verions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = tp->ack.rcv_mss;
	int free_space = tcp_space(sk);
	int full_space = min_t(int, tp->window_clamp, tcp_full_space(sk));
	int window;

	if (mss > full_space)
		mss = full_space; 

	if (free_space < full_space/2) {
		tp->ack.quick = 0;

		if (tcp_memory_pressure)
			tp->rcv_ssthresh = min(tp->rcv_ssthresh, 4U*tp->advmss);

		if (free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = tp->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		if (((window >> tp->rx_opt.rcv_wscale) << tp->rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = (free_space/mss)*mss;
	}

	return window;
}

/* Attempt to collapse two adjacent SKB's during retransmission. */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *skb, int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = skb->next;

	/* The first test we must make is that neither of these two
	 * SKB's are still referenced by someone else.
	 */
	if (!skb_cloned(skb) && !skb_cloned(next_skb)) {
		int skb_size = skb->len, next_skb_size = next_skb->len;
		u16 flags = TCP_SKB_CB(skb)->flags;

		/* Also punt if next skb has been SACK'd. */
		if(TCP_SKB_CB(next_skb)->sacked & TCPCB_SACKED_ACKED)
			return;

		/* Next skb is out of window. */
		if (after(TCP_SKB_CB(next_skb)->end_seq, tp->snd_una+tp->snd_wnd))
			return;

		/* Punt if not enough space exists in the first SKB for
		 * the data in the second, or the total combined payload
		 * would exceed the MSS.
		 */
		if ((next_skb_size > skb_tailroom(skb)) ||
		    ((skb_size + next_skb_size) > mss_now))
			return;

		BUG_ON(tcp_skb_pcount(skb) != 1 ||
		       tcp_skb_pcount(next_skb) != 1);

		/* Ok.  We will be able to collapse the packet. */
		__skb_unlink(next_skb, next_skb->list);

		memcpy(skb_put(skb, next_skb_size), next_skb->data, next_skb_size);

		if (next_skb->ip_summed == CHECKSUM_HW)
			skb->ip_summed = CHECKSUM_HW;

		if (skb->ip_summed != CHECKSUM_HW)
			skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

		/* Update sequence range on original skb. */
		TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

		/* Merge over control information. */
		flags |= TCP_SKB_CB(next_skb)->flags; /* This moves PSH/FIN etc. over */
		TCP_SKB_CB(skb)->flags = flags;

		/* All done, get rid of second SKB and account for it so
		 * packet counting does not break.
		 */
		TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked&(TCPCB_EVER_RETRANS|TCPCB_AT_TAIL);
		if (TCP_SKB_CB(next_skb)->sacked&TCPCB_SACKED_RETRANS)
			tp->retrans_out -= tcp_skb_pcount(next_skb);
		if (TCP_SKB_CB(next_skb)->sacked&TCPCB_LOST) {
			tp->lost_out -= tcp_skb_pcount(next_skb);
			tp->left_out -= tcp_skb_pcount(next_skb);
		}
		/* Reno case is special. Sigh... */
		if (!tp->rx_opt.sack_ok && tp->sacked_out) {
			tcp_dec_pcount_approx(&tp->sacked_out, next_skb);
			tp->left_out -= tcp_skb_pcount(next_skb);
		}

		/* Not quite right: it can be > snd.fack, but
		 * it is better to underestimate fackets.
		 */
		tcp_dec_pcount_approx(&tp->fackets_out, next_skb);
		tcp_packets_out_dec(tp, next_skb);
		sk_stream_free_skb(sk, next_skb);
	}
}

/* Do a simple retransmit without using the backoff mechanisms in
 * tcp_timer. This is used for path mtu discovery. 
 * The socket is already locked here.
 */ 
void tcp_simple_retransmit(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int mss = tcp_current_mss(sk, 0);
	int lost = 0;

	sk_stream_for_retrans_queue(skb, sk) {
		if (skb->len > mss && 
		    !(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED)) {
			if (TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_RETRANS) {
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= tcp_skb_pcount(skb);
			}
			if (!(TCP_SKB_CB(skb)->sacked&TCPCB_LOST)) {
				TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
				tp->lost_out += tcp_skb_pcount(skb);
				lost = 1;
			}
		}
	}

	if (!lost)
		return;

	tcp_sync_left_out(tp);

 	/* Don't muck with the congestion window here.
	 * Reason is that we do not increase amount of _data_
	 * in network, but units changed and effective
	 * cwnd/ssthresh really reduced now.
	 */
	if (tp->ca_state != TCP_CA_Loss) {
		tp->high_seq = tp->snd_nxt;
		tp->snd_ssthresh = tcp_current_ssthresh(tp);
		tp->prior_ssthresh = 0;
		tp->undo_marker = 0;
		tcp_set_ca_state(tp, TCP_CA_Loss);
	}
	tcp_xmit_retransmit_queue(sk);
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
/* 当超时或接收到分片ICMP时，重传段 */
int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
 	unsigned int cur_mss = tcp_current_mss(sk, 0);
	int err;

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: frgagmentation, tunneling, mangling etc.
	 */
	if (atomic_read(&sk->sk_wmem_alloc) >
	    min(sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2), sk->sk_sndbuf))
		return -EAGAIN;/* 只有1/4的发送缓存是留给分段用的，如果过多，则暂时不进行重传 */

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))/* TCP已经确认了整个段，再进行重传说明有BUG */
			BUG();

		if (sk->sk_route_caps & NETIF_F_TSO) {
			sk->sk_route_caps &= ~NETIF_F_TSO;
			sk->sk_no_largesend = 1;
			tp->mss_cache = tp->mss_cache_std;
		}

		/* 如果已经收到部分，则只需要重传一部分数据，将已经确认的部分截断 */
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tp->snd_una+tp->snd_wnd)/* 如果待发送的段已经不在发送窗口内，则不重传 */
	    && TCP_SKB_CB(skb)->seq != tp->snd_una)/* 这里是防止发送窗口为0，此时需要发送0探测窗口 */
		return -EAGAIN;

	if (skb->len > cur_mss) {/* 数据报长度大于MSS */
		int old_factor = tcp_skb_pcount(skb);
		int new_factor;

		if (tcp_fragment(sk, skb, cur_mss))/* 将报文进行分片 */
			return -ENOMEM; /* We'll try again later. */

		/* New SKB created, account for it. */
		new_factor = tcp_skb_pcount(skb);
		tp->packets_out -= old_factor - new_factor;
		tp->packets_out += tcp_skb_pcount(skb->next);
	}

	/* Collapse two adjacent packets if worthwhile and we can. */
	if(!(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_SYN) &&/* 这是为适应某些有问题的打印机而进行的，不是减小报文，而是适当增大报文 */
	   (skb->len < (cur_mss >> 1)) &&
	   (skb->next != sk->sk_send_head) &&
	   (skb->next != (struct sk_buff *)&sk->sk_write_queue) &&
	   (skb_shinfo(skb)->nr_frags == 0 && skb_shinfo(skb->next)->nr_frags == 0) &&
	   (tcp_skb_pcount(skb) == 1 && tcp_skb_pcount(skb->next) == 1) &&
	   (sysctl_tcp_retrans_collapse != 0))
		tcp_retrans_try_collapse(sk, skb, cur_mss);

	/* 查找路由，并重建报文首部 */
	if(tp->af_specific->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	/* Some Solaris stacks overoptimize and ignore the FIN on a
	 * retransmit when old data is attached.  So strip it off
	 * since it is cheap to do so and saves bytes on the network.
	 */
	if(skb->len > 0 &&/* 处理Solaris相关的BUG */
	   (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN) &&
	   tp->snd_una == (TCP_SKB_CB(skb)->end_seq - 1)) {
		if (!pskb_trim(skb, 0)) {
			TCP_SKB_CB(skb)->seq = TCP_SKB_CB(skb)->end_seq - 1;
			skb_shinfo(skb)->tso_segs = 1;
			skb_shinfo(skb)->tso_size = 0;
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
		}
	}

	/* Make a copy, if the first transmission SKB clone we made
	 * is still in somebody's hands, else make a clone.
	 */
	/* 记录发送时间戳 */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	tcp_tso_set_push(skb);

	/* 将数据报发送出去 */
	err = tcp_transmit_skb(sk, (skb_cloned(skb) ?
				    pskb_copy(skb, GFP_ATOMIC):
				    skb_clone(skb, GFP_ATOMIC)));

	if (err == 0) {/* 如果重传成功，则更新一些计数 */
		/* Update global TCP statistics. */
		TCP_INC_STATS(TCP_MIB_RETRANSSEGS);

		tp->total_retrans++;/* 重传总次数 */

#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_RETRANS) {
			if (net_ratelimit())
				printk(KERN_DEBUG "retrans_out leaked.\n");
		}
#endif
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);/* 重传而未确认的次数 */

		/* Save stamp of the first retransmit. */
		if (!tp->retrans_stamp)/* 记录上一次拥塞以来第一个重传段的时间，用于拥塞撤销 */
			tp->retrans_stamp = TCP_SKB_CB(skb)->when;

		tp->undo_retrans++;

		/* snd_nxt is stored to detect loss of retransmitted segment,
		 * see tcp_input.c tcp_sacktag_write_queue().
		 */
		TCP_SKB_CB(skb)->ack_seq = tp->snd_nxt;
	}
	return err;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 * If doing SACK, the first ACK which comes back for a timeout
 * based retransmit packet might feed us FACK information again.
 * If so, we use it to avoid unnecessarily retransmissions.
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int packet_cnt = tp->lost_out;

	/* First pass: retransmit lost packets. */
	if (packet_cnt) {
		sk_stream_for_retrans_queue(skb, sk) {
			__u8 sacked = TCP_SKB_CB(skb)->sacked;

			/* Assume this retransmit will generate
			 * only one packet for congestion window
			 * calculation purposes.  This works because
			 * tcp_retransmit_skb() will chop up the
			 * packet to be MSS sized and all the
			 * packet counting works out.
			 */
			if (tcp_packets_in_flight(tp) >= tp->snd_cwnd)
				return;

			if (sacked&TCPCB_LOST) {
				if (!(sacked&(TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))) {
					if (tcp_retransmit_skb(sk, skb))
						return;
					if (tp->ca_state != TCP_CA_Loss)
						NET_INC_STATS_BH(LINUX_MIB_TCPFASTRETRANS);
					else
						NET_INC_STATS_BH(LINUX_MIB_TCPSLOWSTARTRETRANS);

					if (skb ==
					    skb_peek(&sk->sk_write_queue))
						tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);
				}

				packet_cnt -= tcp_skb_pcount(skb);
				if (packet_cnt <= 0)
					break;
			}
		}
	}

	/* OK, demanded retransmission is finished. */

	/* Forward retransmissions are possible only during Recovery. */
	if (tp->ca_state != TCP_CA_Recovery)
		return;

	/* No forward retransmissions in Reno are possible. */
	if (!tp->rx_opt.sack_ok)
		return;

	/* Yeah, we have to make difficult choice between forward transmission
	 * and retransmission... Both ways have their merits...
	 *
	 * For now we do not retransmit anything, while we have some new
	 * segments to send.
	 */

	if (tcp_may_send_now(sk, tp))
		return;

	packet_cnt = 0;

	sk_stream_for_retrans_queue(skb, sk) {
		/* Similar to the retransmit loop above we
		 * can pretend that the retransmitted SKB
		 * we send out here will be composed of one
		 * real MSS sized packet because tcp_retransmit_skb()
		 * will fragment it if necessary.
		 */
		if (++packet_cnt > tp->fackets_out)
			break;

		if (tcp_packets_in_flight(tp) >= tp->snd_cwnd)
			break;

		if (TCP_SKB_CB(skb)->sacked & TCPCB_TAGBITS)
			continue;

		/* Ok, retransmit it. */
		if (tcp_retransmit_skb(sk, skb))
			break;

		if (skb == skb_peek(&sk->sk_write_queue))
			tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);

		NET_INC_STATS_BH(LINUX_MIB_TCPFORWARDRETRANS);
	}
}


/* Send a fin.  The caller locks the socket for us.  This cannot be
 * allowed to fail queueing a FIN frame under any circumstances.
 */
void tcp_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);	
	struct sk_buff *skb = skb_peek_tail(&sk->sk_write_queue);
	int mss_now;
	
	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = tcp_current_mss(sk, 1);

	if (sk->sk_send_head != NULL) {
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		/* Socket is locked, keep trying until memory is available. */
		for (;;) {
			skb = alloc_skb(MAX_TCP_HEADER, GFP_KERNEL);
			if (skb)
				break;
			yield();
		}

		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);
		skb->csum = 0;
		TCP_SKB_CB(skb)->flags = (TCPCB_FLAG_ACK | TCPCB_FLAG_FIN);
		TCP_SKB_CB(skb)->sacked = 0;
		skb_shinfo(skb)->tso_segs = 1;
		skb_shinfo(skb)->tso_size = 0;

		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		TCP_SKB_CB(skb)->seq = tp->write_seq;
		TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + 1;
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, tp, mss_now, TCP_NAGLE_OFF);
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by draft-ietf-tcpimpl-prob-03.txt section 3.10.  -DaveM
 */
void tcp_send_active_reset(struct sock *sk, int priority)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	skb->csum = 0;
	TCP_SKB_CB(skb)->flags = (TCPCB_FLAG_ACK | TCPCB_FLAG_RST);
	TCP_SKB_CB(skb)->sacked = 0;
	skb_shinfo(skb)->tso_segs = 1;
	skb_shinfo(skb)->tso_size = 0;

	/* Send it off. */
	TCP_SKB_CB(skb)->seq = tcp_acceptable_seq(sk, tp);
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	if (tcp_transmit_skb(sk, skb))
		NET_INC_STATS(LINUX_MIB_TCPABORTFAILED);
}

/* WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff* skb;

	skb = skb_peek(&sk->sk_write_queue);
	if (skb == NULL || !(TCP_SKB_CB(skb)->flags&TCPCB_FLAG_SYN)) {
		printk(KERN_DEBUG "tcp_send_synack: wrong queue state\n");
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->flags&TCPCB_FLAG_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
			if (nskb == NULL)
				return -ENOMEM;
			__skb_unlink(skb, &sk->sk_write_queue);
			__skb_queue_head(&sk->sk_write_queue, nskb);
			sk_stream_free_skb(sk, skb);
			sk_charge_skb(sk, nskb);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_ACK;
		TCP_ECN_send_synack(tcp_sk(sk), skb);
	}
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb_clone(skb, GFP_ATOMIC));
}

/*
 * Prepare a SYN-ACK.
 */
/* 构造一个syn+ack报文 */
struct sk_buff * tcp_make_synack(struct sock *sk, struct dst_entry *dst,
				 struct open_request *req)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th;
	int tcp_header_size;
	struct sk_buff *skb;

	/* 不管发送缓存是否已经达到上限，都分配skb */
	skb = sock_wmalloc(sk, MAX_TCP_HEADER + 15, 1, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers. */
	/* 为TCP头保留空间 */
	skb_reserve(skb, MAX_TCP_HEADER);

	skb->dst = dst_clone(dst);

	/* 根据接收的SYN段中的选项计算SYN+ACK段的首部长度 */
	tcp_header_size = (sizeof(struct tcphdr) + TCPOLEN_MSS +
			   (req->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0) +
			   (req->wscale_ok ? TCPOLEN_WSCALE_ALIGNED : 0) +
			   /* SACK_PERM is in the place of NOP NOP of TS */
			   ((req->sack_ok && !req->tstamp_ok) ? TCPOLEN_SACKPERM_ALIGNED : 0));
	/* 在SKB中预留TCP首部空间并清0 */
	skb->h.th = th = (struct tcphdr *) skb_push(skb, tcp_header_size);

	memset(th, 0, sizeof(struct tcphdr));
	/* 设置TCP控制块中的控制字段 */
	th->syn = 1;
	th->ack = 1;
	if (dst->dev->features&NETIF_F_TSO)
		req->ecn_ok = 0;
	TCP_ECN_make_synack(req, th);
	th->source = inet_sk(sk)->sport;
	th->dest = req->rmt_port;
	TCP_SKB_CB(skb)->seq = req->snt_isn;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + 1;
	TCP_SKB_CB(skb)->sacked = 0;
	skb_shinfo(skb)->tso_segs = 1;
	skb_shinfo(skb)->tso_size = 0;
	/* 设置首部中的序号 */
	th->seq = htonl(TCP_SKB_CB(skb)->seq);
	th->ack_seq = htonl(req->rcv_isn + 1);
	/* 请求块中rcv_wnd为0，表示本端窗口被初始化为0 */
	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns */
		__u8 rcv_wscale; 
		/* Set this up on the first call only */
		/* 根据路由项中获取的最大通告窗口初始化请求块中的最大通告窗口 */
		req->window_clamp = tp->window_clamp ? : dst_metric(dst, RTAX_WINDOW);
		/* tcp_full_space because it is guaranteed to be the first packet */
		/* 设置接收窗口、最大通告窗口、窗口扩大因子 */
		tcp_select_initial_window(tcp_full_space(sk), 
			dst_metric(dst, RTAX_ADVMSS) - (req->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
			&req->rcv_wnd,
			&req->window_clamp,
			req->wscale_ok,
			&rcv_wscale);
		req->rcv_wscale = rcv_wscale; 
	}

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	/* 设置首部中的窗口大小 */
	th->window = htons(req->rcv_wnd);

	/* 设置控制块的发送时间 */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	/* 根据SYN段中的选项，生成SYN+ACK段中的选项，包括MSS、SACK、窗口扩大因子、时间戳等 */
	tcp_syn_build_options((__u32 *)(th + 1), dst_metric(dst, RTAX_ADVMSS), req->tstamp_ok,
			      req->sack_ok, req->wscale_ok, req->rcv_wscale,
			      TCP_SKB_CB(skb)->when,
			      req->ts_recent);

	/* 初始化首部校验值 */
	skb->csum = 0;
	/* 设置首部长度 */
	th->doff = (tcp_header_size >> 2);
	TCP_INC_STATS(TCP_MIB_OUTSEGS);
	return skb;
}

/* 
 * Do all connect socket setups that can be done AF independent.
 */ 
static inline void tcp_connect_init(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr) +
		(sysctl_tcp_timestamps ? TCPOLEN_TSTAMP_ALIGNED : 0);

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_sync_mss(sk, dst_pmtu(dst));

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = dst_metric(dst, RTAX_ADVMSS);
	tcp_initialize_rcv_mss(sk);
	tcp_ca_init(tp);

	tcp_select_initial_window(tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sysctl_tcp_window_scaling,
				  &tp->rx_opt.rcv_wscale);

	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, tp->write_seq, 0);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->rcv_nxt = 0;
	tp->rcv_wup = 0;
	tp->copied_seq = 0;

	tp->rto = TCP_TIMEOUT_INIT;
	tp->retransmits = 0;
	tcp_clear_retrans(tp);
}

/*
 * Build a SYN and send it off.
 */ 
/* 构造并发送SYN段 */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;

	tcp_connect_init(sk);/* 初始化传输控制块中与连接相关的成员 */

	/* 为SYN段分配报文并进行初始化 */
	buff = alloc_skb(MAX_TCP_HEADER + 15, sk->sk_allocation);
	if (unlikely(buff == NULL))
		return -ENOBUFS;

	/* Reserve space for headers. */
	skb_reserve(buff, MAX_TCP_HEADER);

	TCP_SKB_CB(buff)->flags = TCPCB_FLAG_SYN;
	TCP_ECN_send_syn(sk, tp, buff);
	TCP_SKB_CB(buff)->sacked = 0;
	skb_shinfo(buff)->tso_segs = 1;
	skb_shinfo(buff)->tso_size = 0;
	buff->csum = 0;
	TCP_SKB_CB(buff)->seq = tp->write_seq++;
	TCP_SKB_CB(buff)->end_seq = tp->write_seq;
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	tcp_ca_init(tp);

	/* Send it off. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	tp->retrans_stamp = TCP_SKB_CB(buff)->when;

	/* 将报文添加到发送队列上 */
	__skb_queue_tail(&sk->sk_write_queue, buff);
	sk_charge_skb(sk, buff);
	tp->packets_out += tcp_skb_pcount(buff);
	/* 发送SYN段 */
	tcp_transmit_skb(sk, skb_clone(buff, GFP_KERNEL));
	TCP_INC_STATS(TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	/* 启动重传定时器 */
	tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);
	return 0;
}

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int ato = tp->ack.ato;
	unsigned long timeout;

	if (ato > TCP_DELACK_MIN) {
		int max_ato = HZ/2;

		if (tp->ack.pingpong || (tp->ack.pending&TCP_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use tp->rto here, use results of rtt measurements
		 * directly.
		 */
		if (tp->srtt) {
			int rtt = max(tp->srtt>>3, TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (tp->ack.pending&TCP_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		if (tp->ack.blocked || time_before_eq(tp->ack.timeout, jiffies+(ato>>2))) {
			tcp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, tp->ack.timeout))
			timeout = tp->ack.timeout;
	}
	tp->ack.pending |= TCP_ACK_SCHED|TCP_ACK_TIMER;
	tp->ack.timeout = timeout;
	sk_reset_timer(sk, &tp->delack_timer, timeout);
}

/* This routine sends an ack and also updates the window. */
/* 在主动连接时，向服务器端发送ACK完成连接，并更新窗口 */
void tcp_send_ack(struct sock *sk)
{
	/* If we have been reset, we may not send again. */
	if (sk->sk_state != TCP_CLOSE) {/* 不能处于TCP_CLOSE状态 */
		struct tcp_sock *tp = tcp_sk(sk);
		struct sk_buff *buff;

		/* We are not putting this on the write queue, so
		 * tcp_transmit_skb() will set the ownership to this
		 * sock.
		 */
		buff = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);/* 分配一个SKB */
		if (buff == NULL) {/* 如果分配失败，则启动延时确认定时器 */
			tcp_schedule_ack(tp);
			tp->ack.ato = TCP_ATO_MIN;
			tcp_reset_xmit_timer(sk, TCP_TIME_DACK, TCP_DELACK_MAX);
			return;
		}

		/* Reserve space for headers and prepare control bits. */
		/* 设置SKB中相关的参数 */
		skb_reserve(buff, MAX_TCP_HEADER);
		buff->csum = 0;
		TCP_SKB_CB(buff)->flags = TCPCB_FLAG_ACK;
		TCP_SKB_CB(buff)->sacked = 0;
		skb_shinfo(buff)->tso_segs = 1;
		skb_shinfo(buff)->tso_size = 0;

		/* Send it off, this clears delayed acks for us. */
		TCP_SKB_CB(buff)->seq = TCP_SKB_CB(buff)->end_seq = tcp_acceptable_seq(sk, tp);
		TCP_SKB_CB(buff)->when = tcp_time_stamp;
		/* 将SKB发送出去 */
		tcp_transmit_skb(sk, buff);
	}
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (skb == NULL) 
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	skb->csum = 0;
	TCP_SKB_CB(skb)->flags = TCPCB_FLAG_ACK;
	TCP_SKB_CB(skb)->sacked = urgent;
	skb_shinfo(skb)->tso_segs = 1;
	skb_shinfo(skb)->tso_size = 0;

	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	TCP_SKB_CB(skb)->seq = urgent ? tp->snd_una : tp->snd_una - 1;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb);
}

/* 输出持续探测段 */
int tcp_write_wakeup(struct sock *sk)
{
	if (sk->sk_state != TCP_CLOSE) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct sk_buff *skb;

		if ((skb = sk->sk_send_head) != NULL &&/* 发送队列不为空 */
		    before(TCP_SKB_CB(skb)->seq, tp->snd_una+tp->snd_wnd)) {/* 待发送的段在接收窗口内 */
			int err;
			/* 获取当前的MSS以及待分段的段长 */
			unsigned int mss = tcp_current_mss(sk, 0);
			unsigned int seg_size = tp->snd_una+tp->snd_wnd-TCP_SKB_CB(skb)->seq;

			/* 段序号大于pushed_seq，则更新pushed_seq */
			if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
				tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

			/* We are probing the opening of a window
			 * but the window size is != 0
			 * must have been a result SWS avoidance ( sender )
			 */
			if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||/* 段长大于剩余等待发送数据 */
			    skb->len > mss) {/* 段长大于当前mss */
				seg_size = min(seg_size, mss);/* 分段段长取二者小值 */
				TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
				if (tcp_fragment(sk, skb, seg_size))/* 将数据分段 */
					return -1;
				/* SWS override triggered forced fragmentation.
				 * Disable TSO, the connection is too sick. */
				if (sk->sk_route_caps & NETIF_F_TSO) {
					sk->sk_no_largesend = 1;
					sk->sk_route_caps &= ~NETIF_F_TSO;
					tp->mss_cache = tp->mss_cache_std;
				}
			} else if (!tcp_skb_pcount(skb))
				tcp_set_skb_tso_segs(skb, tp->mss_cache_std);

			/* 将分段发送出去 */
			TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
			TCP_SKB_CB(skb)->when = tcp_time_stamp;
			tcp_tso_set_push(skb);
			err = tcp_transmit_skb(sk, skb_clone(skb, GFP_ATOMIC));
			if (!err) {
				update_send_head(sk, tp, skb);
			}
			return err;
		} else {/* 发送队列为空 */
			/* 如果处于紧急模式，多发送一个序号为SND.UNA的段给对方 */
			if (tp->urg_mode &&
			    between(tp->snd_up, tp->snd_una+1, tp->snd_una+0xFFFF))
				tcp_xmit_probe_skb(sk, TCPCB_URG);
			/* 构造并发送一个序号已确认，长度为0的段给对端 */
			return tcp_xmit_probe_skb(sk, 0);
		}
	}
	return -1;
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
void tcp_send_probe0(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int err;

	/* 输出持续探测段 */
	err = tcp_write_wakeup(sk);

	/* 有已经发送但是未确认的段，或者发送队列为空，都无需发送探测段 */
	if (tp->packets_out || !sk->sk_send_head) {
		/* Cancel probe timer, if it is not required. */
		tp->probes_out = 0;
		tp->backoff = 0;
		return;
	}

	if (err <= 0) {/* 重传成功，或者不是由于本地拥塞而导致失败 */
		if (tp->backoff < sysctl_tcp_retries2)/* 更新计数 */
			tp->backoff++;
		tp->probes_out++;
		/* 复位持续定时器 */
		tcp_reset_xmit_timer (sk, TCP_TIME_PROBE0, 
				      min(tp->rto << tp->backoff, TCP_RTO_MAX));
	} else {/* 由于本地拥塞而失败 */
		/* If packet was not sent due to local congestion,
		 * do not backoff and do not remember probes_out.
		 * Let local senders to fight for local resources.
		 *
		 * Use accumulated backoff yet.
		 */
		if (!tp->probes_out)/* 不需要累计重传计数 */
			tp->probes_out=1;
		/* 复位定时器，缩短超时时间 */
		tcp_reset_xmit_timer (sk, TCP_TIME_PROBE0, 
				      min(tp->rto << tp->backoff, TCP_RESOURCE_PROBE_INTERVAL));
	}
}

EXPORT_SYMBOL(tcp_connect);
EXPORT_SYMBOL(tcp_make_synack);
EXPORT_SYMBOL(tcp_simple_retransmit);
EXPORT_SYMBOL(tcp_sync_mss);
