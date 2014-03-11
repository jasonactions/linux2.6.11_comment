/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_timer.c,v 1.88 2002/02/01 22:01:04 davem Exp $
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

#include <linux/module.h>
#include <net/tcp.h>

/* TCP建立连接时，最多尝试发送SYN连接请求的次数。不应大于255.默认为5，大约180s */
int sysctl_tcp_syn_retries = TCP_SYN_RETRIES; 
/* 被动连接端在放弃连接尝试前最多发送多少个SYN+ACK段。不应该大于255. */
int sysctl_tcp_synack_retries = TCP_SYNACK_RETRIES; 
/* 从最后一次数据交换到发送保活探测包的时间间隔，默认为2h */
int sysctl_tcp_keepalive_time = TCP_KEEPALIVE_TIME;
/* 探测次数，经过一定次数后认为连接已经断开 */
int sysctl_tcp_keepalive_probes = TCP_KEEPALIVE_PROBES;
/* TCP保活探测消息的发送间隔，默认为75s,断开时间约为11min */
int sysctl_tcp_keepalive_intvl = TCP_KEEPALIVE_INTVL;
/* 当重传次数超过此值时，可能遇到黑洞。因此清除缓存在传输控制块中的路由缓存项，在下次重传时进行路由选择，大约3s-8min */
int sysctl_tcp_retries1 = TCP_RETR1;
/* 持续定时器周期性发送TCP段或超时重传时，在确定断开连接之前重试的次数。默认为15次，约13-30分钟，该值必须大于100s */
int sysctl_tcp_retries2 = TCP_RETR2;
/* 在确认连接异常，并关闭本端TCP之前，最多重试的次数。默认值为7表示50s-16min。 */
int sysctl_tcp_orphan_retries;

static void tcp_write_timer(unsigned long);
static void tcp_delack_timer(unsigned long);
static void tcp_keepalive_timer (unsigned long data);

#ifdef TCP_DEBUG
const char tcp_timer_bug_msg[] = KERN_DEBUG "tcpbug: unknown timer value\n";
#endif

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies 
 * to optimize.
 */
/* 初始化传输控制块中的定时器 */
void tcp_init_xmit_timers(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	init_timer(&tp->retransmit_timer);
	tp->retransmit_timer.function=&tcp_write_timer;
	tp->retransmit_timer.data = (unsigned long) sk;
	tp->pending = 0;

	init_timer(&tp->delack_timer);
	tp->delack_timer.function=&tcp_delack_timer;
	tp->delack_timer.data = (unsigned long) sk;
	tp->ack.pending = 0;

	init_timer(&sk->sk_timer);
	sk->sk_timer.function	= &tcp_keepalive_timer;
	sk->sk_timer.data	= (unsigned long)sk;
}

void tcp_clear_xmit_timers(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->pending = 0;
	sk_stop_timer(sk, &tp->retransmit_timer);

	tp->ack.pending = 0;
	tp->ack.blocked = 0;
	sk_stop_timer(sk, &tp->delack_timer);

	sk_stop_timer(sk, &sk->sk_timer);
}

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criterium is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int orphans = atomic_read(&tcp_orphan_count);

	/* If peer does not open window for long time, or did not transmit 
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		orphans <<= 1;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		orphans <<= 1;

	if (orphans >= sysctl_tcp_max_orphans ||
	    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
	     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");

		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

/* A write timeout has occurred. Process the after effects. */
/* 重传发生后，检测当前资源使用情况 */
static int tcp_write_timeout(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int retry_until;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {/* 连接阶段 */
		if (tp->retransmits)/* 检测使用的路由缓存项 */
			dst_negative_advice(&sk->sk_dst_cache);
		retry_until = tp->syn_retries ? : sysctl_tcp_syn_retries;
	} else {
		if (tp->retransmits >= sysctl_tcp_retries1) {/* 重传次数超过3次，则需要进行黑洞检测 */
			/* NOTE. draft-ietf-tcpimpl-pmtud-01.txt requires pmtu black
			   hole detection. :-(

			   It is place to make it. It is not made. I do not want
			   to make it. It is disguisting. It does not work in any
			   case. Let me to cite the same draft, which requires for
			   us to implement this:

   "The one security concern raised by this memo is that ICMP black holes
   are often caused by over-zealous security administrators who block
   all ICMP messages.  It is vitally important that those who design and
   deploy security systems understand the impact of strict filtering on
   upper-layer protocols.  The safest web site in the world is worthless
   if most TCP implementations cannot transfer data from it.  It would
   be far nicer to have all of the black holes fixed rather than fixing
   all of the TCP implementations."

                           Golden words :-).
		   */

			dst_negative_advice(&sk->sk_dst_cache);
		}

		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {/* 套接口已经断开并即将关闭 */
			int alive = (tp->rto < TCP_RTO_MAX);
 
			retry_until = tcp_orphan_retries(sk, alive);

			/* 孤儿套接口数量达到最大值，或者当前已经使用的内存达到硬性限制时，需要立即关闭套接口 */
			if (tcp_out_of_resources(sk, alive || tp->retransmits < retry_until))
				return 1;
		}
	}

	if (tp->retransmits >= retry_until) {/* 达到重传上限，必须关闭套接口并报告相应错误 */
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

/* 延时确认定时器函数 */
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock*)data;
	struct tcp_sock *tp = tcp_sk(sk);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {/* 传输控制块已经被用户进程锁定，则此时不能作处理 */
		/* Try again later. */
		/* 标记ack被阻塞 */
		tp->ack.blocked = 1;
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOCKED);
		/* 重新设置定时器超时时间 */
		sk_reset_timer(sk, &tp->delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

	sk_stream_mem_reclaim(sk);/* ?? */

	/* 连接已经关闭，或者没有启动延时发送ACK定时器，则退出 */
	if (sk->sk_state == TCP_CLOSE || !(tp->ack.pending & TCP_ACK_TIMER))
		goto out;

	if (time_after(tp->ack.timeout, jiffies)) {/* 超时时间未到，复位定时器并退出 */
		sk_reset_timer(sk, &tp->delack_timer, tp->ack.timeout);
		goto out;
	}
	/* 去掉TCP_ACK_TIMER */
	tp->ack.pending &= ~TCP_ACK_TIMER;

	if (skb_queue_len(&tp->ucopy.prequeue)) {/* prequeue队列不为空 */
		struct sk_buff *skb;

		NET_ADD_STATS_BH(LINUX_MIB_TCPSCHEDULERFAILED, 
				 skb_queue_len(&tp->ucopy.prequeue));

		/* 通过sk_backlog_rcv处理队列中的SKB */
		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk->sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

	if (tcp_ack_scheduled(tp)) {/* 需要发送ACK */
		if (!tp->ack.pingpong) {/* 在发送ACK前先离开pingpong模式，并重新设定延时确认估算值。 */
			/* Delayed ACK missed: inflate ATO. */
			tp->ack.ato = min(tp->ack.ato << 1, tp->rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			tp->ack.pingpong = 0;
			tp->ack.ato = TCP_ATO_MIN;
		}
		/* 发送ACK */
		tcp_send_ack(sk);
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKS);
	}
	TCP_CHECK_TIMER(sk);

out:
	if (tcp_memory_pressure)
		sk_stream_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* 持续定时器，当对端通告接收窗口为0，阻止TCP继续发送数据时设定 */
static void tcp_probe_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	/**
	 * 有发送出去但是未被确认的段，或者发送队列还有待发送的段，则不用发送探测段。
	 */
	if (tp->packets_out || !sk->sk_send_head) {
		tp->probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_tcp_retries2;/* 断开连接前，持续定时器发送TCP段的数目上限 */

	if (sock_flag(sk, SOCK_DEAD)) {/* 连接已经断开，套接口即将关闭 */
		int alive = ((tp->rto<<tp->backoff) < TCP_RTO_MAX);

 		/* 关闭连接前，重试次数。 */
		max_probes = tcp_orphan_retries(sk, alive);

		/* 释放资源，如果套接口在释放过程中被关闭，就不必发送探测段了。 */
		if (tcp_out_of_resources(sk, alive || tp->probes_out <= max_probes))
			return;
	}

	if (tp->probes_out > max_probes) {/* 如果发送的探测段数目达到上限，则发送错误报告并关闭接口 */
		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		tcp_send_probe0(sk);/* 发送探测段 */
	}
}

/*
 *	The TCP retransmit timer.
 */
/* 重传定时器 */
static void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->packets_out)/* 所有发送的段都得到了确认，无需要重传处理 */
		goto out;

	BUG_TRAP(!skb_queue_empty(&sk->sk_write_queue));

	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&/* 发送窗口已经关闭，套口没有关闭 */
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {/* TCP不是连接过程 */
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
#ifdef TCP_DEBUG
		if (net_ratelimit()) {
			struct inet_sock *inet = inet_sk(sk);
			printk(KERN_DEBUG "TCP: Treason uncloaked! Peer %u.%u.%u.%u:%u/%u shrinks window %u:%u. Repaired.\n",
			       NIPQUAD(inet->daddr), htons(inet->dport),
			       inet->num, tp->snd_una, tp->snd_nxt);
		}
#endif
		/* 超过120s没有收到包了 */
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			/* 报告错误并关闭套口并返回 */
			tcp_write_err(sk);
			goto out;
		}
		/* 进入拥塞控制的LOSS状态 */
		tcp_enter_loss(sk, 0);
		/* 重新传送重传队列中第一个段 */
		tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue));
		/* 由于发生了重传，因此需要更新路由缓存，将其清除。 */
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

	/**
	 * 重传发生，检测当前的资源使用情况和重传的次数。
	 * 如果重传次数达到上限，则需要报告错误并强行关闭套接口。
	 * 如果只是使用资源达到使用上限，则不进行重传。
	 */
	if (tcp_write_timeout(sk))
		goto out;

	if (tp->retransmits == 0) {/* 重传次数为0，说明刚进入重传阶段，根据拥塞状态进行数据统计 */
		if (tp->ca_state == TCP_CA_Disorder || tp->ca_state == TCP_CA_Recovery) {
			if (tp->rx_opt.sack_ok) {
				if (tp->ca_state == TCP_CA_Recovery)
					NET_INC_STATS_BH(LINUX_MIB_TCPSACKRECOVERYFAIL);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPSACKFAILURES);
			} else {
				if (tp->ca_state == TCP_CA_Recovery)
					NET_INC_STATS_BH(LINUX_MIB_TCPRENORECOVERYFAIL);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPRENOFAILURES);
			}
		} else if (tp->ca_state == TCP_CA_Loss) {
			NET_INC_STATS_BH(LINUX_MIB_TCPLOSSFAILURES);
		} else {
			NET_INC_STATS_BH(LINUX_MIB_TCPTIMEOUTS);
		}
	}

	if (tcp_use_frto(sk)) {/* 启用了FRTO */
		tcp_enter_frto(sk);
	} else {
		tcp_enter_loss(sk, 0);/* 进入常规的RTO慢启动重传恢复 */
	}

	/* 如果发送重传队列上第一个SKB失败，则复位重传定时器，等待下次重传 */
	if (tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!tp->retransmits)
			tp->retransmits=1;
		tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS,
				     min(tp->rto, TCP_RESOURCE_PROBE_INTERVAL));
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	/* 发送成功后，递增指数退避算法指数和累计重传次数 */
	tp->backoff++;
	tp->retransmits++;

out_reset_timer:
	/* 完成重传后，重设超时时间，然后复位重传定时器。 */
	tp->rto = min(tp->rto << 1, TCP_RTO_MAX);
	tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);
	if (tp->retransmits > sysctl_tcp_retries1)
		__sk_dst_reset(sk);

out:;
}

/* TCP重传定时器，在发送数据时设定。其超时时间是动态计算的，取决于往返时间及重传次数 */
static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock*)data;
	struct tcp_sock *tp = tcp_sk(sk);
	int event;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {/* 控制块被用户态程序锁定 */
		/* Try again later */
		/* 重新设置定时器超时时间 */
		sk_reset_timer(sk, &tp->retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}

	/* 如果TCP状态已经关闭，或者没有挂起的事件，则返回 */
	if (sk->sk_state == TCP_CLOSE || !tp->pending)
		goto out;

	/* 如果还没有到达超时时间，则无需处理 */
	if (time_after(tp->timeout, jiffies)) {
		/* 重新设置定时器的下次超时时间 */
		sk_reset_timer(sk, &tp->retransmit_timer, tp->timeout);
		goto out;
	}

	/* 重传定时器和持续定时器都是使用本定时器，因此根据挂起事件判断到底是何事件 */
	event = tp->pending;
	tp->pending = 0;

	switch (event) {
	case TCP_TIME_RETRANS:/* 重传事件 */
		tcp_retransmit_timer(sk);
		break;
	case TCP_TIME_PROBE0:/* 持续事件 */
		tcp_probe_timer(sk);
		break;
	}
	TCP_CHECK_TIMER(sk);

out:
	sk_stream_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */
/* 连接定时器处理函数 */
static void tcp_synack_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_listen_opt *lopt = tp->listen_opt;
	/* 重发syn+ack次数 */
	int max_retries = tp->syn_retries ? : sysctl_tcp_synack_retries;
	/* 如果哈希表中年轻连接多，则重试次数也越多，否则会减少重试阀值 */
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct open_request **reqp, *req;
	int i, budget;

	/* 如果连接请求块的散列表还没有建立，或者还没有处于连接过程中的请求块，则直接返回 */
	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 3 seconds, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {/* 连接请求数已经超过了最大半连接数的一半，则调整阀值 */
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {/* 阀值必须大于1 */
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

	if (tp->defer_accept)/* 延迟应答的情况下，重试次数不一样 */
		max_retries = tp->defer_accept;

	/* 计算要检测的半连接队列个数，得到预计值。由于半连接队列较多，不可能全部检测 */
	budget = 2*(TCP_SYNQ_HSIZE/(TCP_TIMEOUT_INIT/TCP_SYNQ_INTERVAL));
	i = lopt->clock_hand;/* 从上次检测过的链表开始检测半连接队列 */

	do {
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {/* 遍历哈希桶中的半连接 */
			if (time_after_eq(now, req->expires)) {/* 当前请求块已经超时 */
				if ((req->retrans < thresh ||/* 该请求块重试次数还没有超过阀值  */
				     (req->acked && req->retrans < max_retries))/* 已经接收到ack信号，由于其他原因造成未连接 */
				    && !req->class->rtx_syn_ack(sk, req, NULL)) {
					unsigned long timeo;

					if (req->retrans++ == 0)
						lopt->qlen_young--;
					/* 计算重传超时值 */
					timeo = min((TCP_TIMEOUT_INIT << req->retrans),
						    TCP_RTO_MAX);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				/* 重传次数超过指定值，取消该连接请求，并将它从连接请求散列表中删除 */
				write_lock(&tp->syn_wait_lock);
				*reqp = req->dl_next;
				write_unlock(&tp->syn_wait_lock);
				lopt->qlen--;
				if (req->retrans == 0)
					lopt->qlen_young--;
				tcp_openreq_free(req);
				continue;
			}
			reqp = &req->dl_next;
		}

		/* 取下一个桶进行处理 */
		i = (i+1)&(TCP_SYNQ_HSIZE-1);

	} while (--budget > 0);

	lopt->clock_hand = i;

	if (lopt->qlen)/* 如果请求散列表中还有未完成连接的请求块，则再次启动定时器 */
		tcp_reset_keepalive_timer(sk, TCP_SYNQ_INTERVAL);
}

void tcp_delete_keepalive_timer (struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

void tcp_reset_keepalive_timer (struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		tcp_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		tcp_delete_keepalive_timer(sk);
}


/**
 * 连接建立定时器、保活定时器、FIN_WAIT_2定时器的处理函数。
 */
static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {/* 锁被用户进程获得 */
		/* Try again later. */ 
		tcp_reset_keepalive_timer (sk, HZ/20);/* 重置定时器，并退出 */
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN) {/* LISTEN状态，表示连接定时器 */
		tcp_synack_timer(sk);/* 连接定时器 */
		goto out;
	}

	/* 处理FIN_WAIT_2定时器 */
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		if (tp->linger2 >= 0) {/* 保持在FIN_WAIT_2状态的时间大于等于0 */
			int tmo = tcp_fin_time(tp) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {/* 定时器剩余时间大于0 */
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
		/* 给对端发送rst后关闭套口 */
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

	/* 如果未打开保活功能，或者连接已经关闭，则退出 */
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

	elapsed = keepalive_time_when(tp);/* 计算超时时间 */

	/* It is alive without keepalive 8) */
	if (tp->packets_out || sk->sk_send_head)/* 如果有已输出未确认的段，或者发送队列中还存在未发送的段，则不用作处理 */
		goto resched;

	elapsed = tcp_time_stamp - tp->rcv_tstamp;/* 持续空闲时间 */

	if (elapsed >= keepalive_time_when(tp)) {/* 持续空闲时间超过允许时间 */
		if ((!tp->keepalive_probes && tp->probes_out >= sysctl_tcp_keepalive_probes) ||/* 未设置保活探测次数并且已发送保活探测段数超过了默认数 */
		     (tp->keepalive_probes && tp->probes_out >= tp->keepalive_probes)) {/* 已经设置了保活探测次数，并且已发送次数已经超过了设置的次数 */
			/* 给对方发送rst段 */
			tcp_send_active_reset(sk, GFP_ATOMIC);
			/* 关闭相应的传输控制块 */
			tcp_write_err(sk);
			goto out;
		}
		if (tcp_write_wakeup(sk) <= 0) {/* 输出保活段(持续探测段)，并计算下次保活定时器的时间 */
			tp->probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {/* 持续空闲时间还未达到允许的持续空闲时间，则重新计算下次激活保活定时器的时间 */
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	TCP_CHECK_TIMER(sk);
	sk_stream_mem_reclaim(sk);/* 回收缓存?? */

resched:
	/* 重新设置保活定时器下次超时时间 */
	tcp_reset_keepalive_timer (sk, elapsed);
	goto out;

death:	
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

EXPORT_SYMBOL(tcp_clear_xmit_timers);
EXPORT_SYMBOL(tcp_delete_keepalive_timer);
EXPORT_SYMBOL(tcp_init_xmit_timers);
EXPORT_SYMBOL(tcp_reset_keepalive_timer);
