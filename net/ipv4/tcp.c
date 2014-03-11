/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp.c,v 1.216 2002/02/01 22:01:04 davem Exp $
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
 *
 * Fixes:
 *		Alan Cox	:	Numerous verify_area() calls
 *		Alan Cox	:	Set the ACK bit on a reset
 *		Alan Cox	:	Stopped it crashing if it closed while
 *					sk->inuse=1 and was trying to connect
 *					(tcp_err()).
 *		Alan Cox	:	All icmp error handling was broken
 *					pointers passed where wrong and the
 *					socket was looked up backwards. Nobody
 *					tested any icmp error code obviously.
 *		Alan Cox	:	tcp_err() now handled properly. It
 *					wakes people on errors. poll
 *					behaves and the icmp error race
 *					has gone by moving it into sock.c
 *		Alan Cox	:	tcp_send_reset() fixed to work for
 *					everything not just packets for
 *					unknown sockets.
 *		Alan Cox	:	tcp option processing.
 *		Alan Cox	:	Reset tweaked (still not 100%) [Had
 *					syn rule wrong]
 *		Herp Rosmanith  :	More reset fixes
 *		Alan Cox	:	No longer acks invalid rst frames.
 *					Acking any kind of RST is right out.
 *		Alan Cox	:	Sets an ignore me flag on an rst
 *					receive otherwise odd bits of prattle
 *					escape still
 *		Alan Cox	:	Fixed another acking RST frame bug.
 *					Should stop LAN workplace lockups.
 *		Alan Cox	: 	Some tidyups using the new skb list
 *					facilities
 *		Alan Cox	:	sk->keepopen now seems to work
 *		Alan Cox	:	Pulls options out correctly on accepts
 *		Alan Cox	:	Fixed assorted sk->rqueue->next errors
 *		Alan Cox	:	PSH doesn't end a TCP read. Switched a
 *					bit to skb ops.
 *		Alan Cox	:	Tidied tcp_data to avoid a potential
 *					nasty.
 *		Alan Cox	:	Added some better commenting, as the
 *					tcp is hard to follow
 *		Alan Cox	:	Removed incorrect check for 20 * psh
 *	Michael O'Reilly	:	ack < copied bug fix.
 *	Johannes Stille		:	Misc tcp fixes (not all in yet).
 *		Alan Cox	:	FIN with no memory -> CRASH
 *		Alan Cox	:	Added socket option proto entries.
 *					Also added awareness of them to accept.
 *		Alan Cox	:	Added TCP options (SOL_TCP)
 *		Alan Cox	:	Switched wakeup calls to callbacks,
 *					so the kernel can layer network
 *					sockets.
 *		Alan Cox	:	Use ip_tos/ip_ttl settings.
 *		Alan Cox	:	Handle FIN (more) properly (we hope).
 *		Alan Cox	:	RST frames sent on unsynchronised
 *					state ack error.
 *		Alan Cox	:	Put in missing check for SYN bit.
 *		Alan Cox	:	Added tcp_select_window() aka NET2E
 *					window non shrink trick.
 *		Alan Cox	:	Added a couple of small NET2E timer
 *					fixes
 *		Charles Hedrick :	TCP fixes
 *		Toomas Tamm	:	TCP window fixes
 *		Alan Cox	:	Small URG fix to rlogin ^C ack fight
 *		Charles Hedrick	:	Rewrote most of it to actually work
 *		Linus		:	Rewrote tcp_read() and URG handling
 *					completely
 *		Gerhard Koerting:	Fixed some missing timer handling
 *		Matthew Dillon  :	Reworked TCP machine states as per RFC
 *		Gerhard Koerting:	PC/TCP workarounds
 *		Adam Caldwell	:	Assorted timer/timing errors
 *		Matthew Dillon	:	Fixed another RST bug
 *		Alan Cox	:	Move to kernel side addressing changes.
 *		Alan Cox	:	Beginning work on TCP fastpathing
 *					(not yet usable)
 *		Arnt Gulbrandsen:	Turbocharged tcp_check() routine.
 *		Alan Cox	:	TCP fast path debugging
 *		Alan Cox	:	Window clamping
 *		Michael Riepe	:	Bug in tcp_check()
 *		Matt Dillon	:	More TCP improvements and RST bug fixes
 *		Matt Dillon	:	Yet more small nasties remove from the
 *					TCP code (Be very nice to this man if
 *					tcp finally works 100%) 8)
 *		Alan Cox	:	BSD accept semantics.
 *		Alan Cox	:	Reset on closedown bug.
 *	Peter De Schrijver	:	ENOTCONN check missing in tcp_sendto().
 *		Michael Pall	:	Handle poll() after URG properly in
 *					all cases.
 *		Michael Pall	:	Undo the last fix in tcp_read_urg()
 *					(multi URG PUSH broke rlogin).
 *		Michael Pall	:	Fix the multi URG PUSH problem in
 *					tcp_readable(), poll() after URG
 *					works now.
 *		Michael Pall	:	recv(...,MSG_OOB) never blocks in the
 *					BSD api.
 *		Alan Cox	:	Changed the semantics of sk->socket to
 *					fix a race and a signal problem with
 *					accept() and async I/O.
 *		Alan Cox	:	Relaxed the rules on tcp_sendto().
 *		Yury Shevchuk	:	Really fixed accept() blocking problem.
 *		Craig I. Hagan  :	Allow for BSD compatible TIME_WAIT for
 *					clients/servers which listen in on
 *					fixed ports.
 *		Alan Cox	:	Cleaned the above up and shrank it to
 *					a sensible code size.
 *		Alan Cox	:	Self connect lockup fix.
 *		Alan Cox	:	No connect to multicast.
 *		Ross Biro	:	Close unaccepted children on master
 *					socket close.
 *		Alan Cox	:	Reset tracing code.
 *		Alan Cox	:	Spurious resets on shutdown.
 *		Alan Cox	:	Giant 15 minute/60 second timer error
 *		Alan Cox	:	Small whoops in polling before an
 *					accept.
 *		Alan Cox	:	Kept the state trace facility since
 *					it's handy for debugging.
 *		Alan Cox	:	More reset handler fixes.
 *		Alan Cox	:	Started rewriting the code based on
 *					the RFC's for other useful protocol
 *					references see: Comer, KA9Q NOS, and
 *					for a reference on the difference
 *					between specifications and how BSD
 *					works see the 4.4lite source.
 *		A.N.Kuznetsov	:	Don't time wait on completion of tidy
 *					close.
 *		Linus Torvalds	:	Fin/Shutdown & copied_seq changes.
 *		Linus Torvalds	:	Fixed BSD port reuse to work first syn
 *		Alan Cox	:	Reimplemented timers as per the RFC
 *					and using multiple timers for sanity.
 *		Alan Cox	:	Small bug fixes, and a lot of new
 *					comments.
 *		Alan Cox	:	Fixed dual reader crash by locking
 *					the buffers (much like datagram.c)
 *		Alan Cox	:	Fixed stuck sockets in probe. A probe
 *					now gets fed up of retrying without
 *					(even a no space) answer.
 *		Alan Cox	:	Extracted closing code better
 *		Alan Cox	:	Fixed the closing state machine to
 *					resemble the RFC.
 *		Alan Cox	:	More 'per spec' fixes.
 *		Jorge Cwik	:	Even faster checksumming.
 *		Alan Cox	:	tcp_data() doesn't ack illegal PSH
 *					only frames. At least one pc tcp stack
 *					generates them.
 *		Alan Cox	:	Cache last socket.
 *		Alan Cox	:	Per route irtt.
 *		Matt Day	:	poll()->select() match BSD precisely on error
 *		Alan Cox	:	New buffers
 *		Marc Tamsky	:	Various sk->prot->retransmits and
 *					sk->retransmits misupdating fixed.
 *					Fixed tcp_write_timeout: stuck close,
 *					and TCP syn retries gets used now.
 *		Mark Yarvis	:	In tcp_read_wakeup(), don't send an
 *					ack if state is TCP_CLOSED.
 *		Alan Cox	:	Look up device on a retransmit - routes may
 *					change. Doesn't yet cope with MSS shrink right
 *					but it's a start!
 *		Marc Tamsky	:	Closing in closing fixes.
 *		Mike Shaver	:	RFC1122 verifications.
 *		Alan Cox	:	rcv_saddr errors.
 *		Alan Cox	:	Block double connect().
 *		Alan Cox	:	Small hooks for enSKIP.
 *		Alexey Kuznetsov:	Path MTU discovery.
 *		Alan Cox	:	Support soft errors.
 *		Alan Cox	:	Fix MTU discovery pathological case
 *					when the remote claims no mtu!
 *		Marc Tamsky	:	TCP_CLOSE fix.
 *		Colin (G3TNE)	:	Send a reset on syn ack replies in
 *					window but wrong (fixes NT lpd problems)
 *		Pedro Roque	:	Better TCP window handling, delayed ack.
 *		Joerg Reuter	:	No modification of locked buffers in
 *					tcp_do_retransmit()
 *		Eric Schenk	:	Changed receiver side silly window
 *					avoidance algorithm to BSD style
 *					algorithm. This doubles throughput
 *					against machines running Solaris,
 *					and seems to result in general
 *					improvement.
 *	Stefan Magdalinski	:	adjusted tcp_readable() to fix FIONREAD
 *	Willy Konynenberg	:	Transparent proxying support.
 *	Mike McLagan		:	Routing by source
 *		Keith Owens	:	Do proper merging with partial SKB's in
 *					tcp_do_sendmsg to avoid burstiness.
 *		Eric Schenk	:	Fix fast close down bug with
 *					shutdown() followed by close().
 *		Andi Kleen 	:	Make poll agree with SIGIO
 *	Salvatore Sanfilippo	:	Support SO_LINGER with linger == 1 and
 *					lingertime == 0 (RFC 793 ABORT Call)
 *	Hirokazu Takahashi	:	Use copy_from_user() instead of
 *					csum_and_copy_from_user() if possible.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 *
 * Description of States:
 *
 *	TCP_SYN_SENT		sent a connection request, waiting for ack
 *
 *	TCP_SYN_RECV		received a connection request, sent ack,
 *				waiting for final ack in three-way handshake.
 *
 *	TCP_ESTABLISHED		connection established
 *
 *	TCP_FIN_WAIT1		our side has shutdown, waiting to complete
 *				transmission of remaining buffered data
 *
 *	TCP_FIN_WAIT2		all buffered data sent, waiting for remote
 *				to shutdown
 *
 *	TCP_CLOSING		both sides have shutdown but we still have
 *				data we have to finish sending
 *
 *	TCP_TIME_WAIT		timeout to catch resent junk before entering
 *				closed, can only be entered from FIN_WAIT2
 *				or CLOSING.  Required because the other end
 *				may not have gotten our last ACK causing it
 *				to retransmit the data packet (which we ignore)
 *
 *	TCP_CLOSE_WAIT		remote side has shutdown and is waiting for
 *				us to finish writing our data and to shutdown
 *				(we have to close() to move on to LAST_ACK)
 *
 *	TCP_LAST_ACK		out side has shutdown after remote has
 *				shutdown.  There may still be data in our
 *				buffer that we have to finish sending
 *
 *	TCP_CLOSE		socket is finished
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/bootmem.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/ip.h>


#include <asm/uaccess.h>
#include <asm/ioctls.h>

/* 对于本端断开的套接口连接，保持在FIN_WAIT_2状态的时间。每个FIN_WAIT_2状态的连接消耗约1.5K的内存 */
int sysctl_tcp_fin_timeout = TCP_FIN_TIMEOUT;

DEFINE_SNMP_STAT(struct tcp_mib, tcp_statistics);

kmem_cache_t *tcp_openreq_cachep;
kmem_cache_t *tcp_bucket_cachep;
kmem_cache_t *tcp_timewait_cachep;

/**
 * TCP传输层中待销毁的套接口数目。
 */
atomic_t tcp_orphan_count = ATOMIC_INIT(0);

/**
 * 三个内存控制值。对应于low，pressure，high三个阀值。
 *	low:	当TCP使用的内存页面数量低于此值时，TCP不释放内存，且总能分配成功。
 *	pressure:	当TCP使用的内存数量超过该值时，进入告警状态。分配内存会根据参数来永定本次分配是否成功。
 *	high:	一旦已经分配的缓冲区总大小超出该值，会根据情况对发送和接收缓存做具体的确认。	
 */
int sysctl_tcp_mem[3];
/**
 * 发送缓冲区控制 
 *		min:		发送队列总长度的上限
 *		default:	发送缓冲区长度上限的初始值。用于初始化sock结构的sk_sndbuf。
 *		max:		发送缓冲区长度上限的最大值。
 */
int sysctl_tcp_wmem[3] = { 4 * 1024, 16 * 1024, 128 * 1024 };
/**
 * 接收缓存阀值。
 */
int sysctl_tcp_rmem[3] = { 4 * 1024, 87380, 87380 * 2 };

EXPORT_SYMBOL(sysctl_tcp_mem);
EXPORT_SYMBOL(sysctl_tcp_rmem);
EXPORT_SYMBOL(sysctl_tcp_wmem);

atomic_t tcp_memory_allocated;	/* Current allocated memory. */
atomic_t tcp_sockets_allocated;	/* Current number of TCP sockets. */

EXPORT_SYMBOL(tcp_memory_allocated);
EXPORT_SYMBOL(tcp_sockets_allocated);

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the sk_stream_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int tcp_memory_pressure;

EXPORT_SYMBOL(tcp_memory_pressure);

/* 当TCP内存分配进入告警状态时，调用此函数设置告警标志 */
void tcp_enter_memory_pressure(void)
{
	if (!tcp_memory_pressure) {
		NET_INC_STATS(LINUX_MIB_TCPMEMORYPRESSURES);
		tcp_memory_pressure = 1;
	}
}

EXPORT_SYMBOL(tcp_enter_memory_pressure);

/*
 * LISTEN is a special case for poll..
 */
static __inline__ unsigned int tcp_listen_poll(struct sock *sk,
					       poll_table *wait)
{
	return tcp_sk(sk)->accept_queue ? (POLLIN | POLLRDNORM) : 0;
}

/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	poll_wait(file, sk->sk_sleep, wait);
	if (sk->sk_state == TCP_LISTEN)
		return tcp_listen_poll(sk, wait);

	/* Socket is not locked. We are protected from async events
	   by poll logic and correct handling of state changes
	   made by another threads is impossible in any case.
	 */

	mask = 0;
	if (sk->sk_err)
		mask = POLLERR;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if PULLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why PULLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM;

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if ((tp->rcv_nxt != tp->copied_seq) &&
		    (tp->urg_seq != tp->copied_seq ||
		     tp->rcv_nxt != tp->copied_seq + 1 ||
		     sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data))
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}

		if (tp->urg_data & TCP_URG_VALID)
			mask |= POLLPRI;
	}
	return mask;
}

/* TCP的ioctl实现 */
int tcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int answ;

	switch (cmd) {
	case SIOCINQ:/* 获取接收缓存中的未读的数据量。 */
		if (sk->sk_state == TCP_LISTEN)/* 如果在listen状态，返回错误。 */
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !tp->urg_data ||
			 before(tp->urg_seq, tp->copied_seq) ||
			 !before(tp->urg_seq, tp->rcv_nxt)) {
			answ = tp->rcv_nxt - tp->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			if (answ && !skb_queue_empty(&sk->sk_receive_queue))
				answ -=
		       ((struct sk_buff *)sk->sk_receive_queue.prev)->h.th->fin;
		} else
			answ = tp->urg_seq - tp->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:/* 检测带外数据是否已经被用户进程接收 */
		answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
		break;
	case SIOCOUTQ:/* 获取在发送队列缓存中未发送出去的数据量。 */
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_una;
		break;
	default:
		return -ENOIOCTLCMD;
	};

	return put_user(answ, (int __user *)arg);
}


int tcp_listen_start(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_listen_opt *lopt;

	/* 初始连接队列长度上限 */
	sk->sk_max_ack_backlog = 0;
	sk->sk_ack_backlog = 0;
	tp->accept_queue = tp->accept_queue_tail = NULL;
	/* 初始化传输控制块中与延时发送ACK有关的数据结构 */
	rwlock_init(&tp->syn_wait_lock);
	tcp_delack_init(tp);

	/* 为管理连接请求块的散列表分配存储空间，如果失败则退出 */
	lopt = kmalloc(sizeof(struct tcp_listen_opt), GFP_KERNEL);
	if (!lopt)
		return -ENOMEM;

	memset(lopt, 0, sizeof(struct tcp_listen_opt));
	for (lopt->max_qlen_log = 6; ; lopt->max_qlen_log++)
		if ((1 << lopt->max_qlen_log) >= sysctl_max_syn_backlog)
			break;
	/* 计算哈希表的哈希种子 */
	get_random_bytes(&lopt->hash_rnd, 4);

	/* 将散列块与传输控制块绑定 */
	write_lock_bh(&tp->syn_wait_lock);
	tp->listen_opt = lopt;
	write_unlock_bh(&tp->syn_wait_lock);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	sk->sk_state = TCP_LISTEN;/* 设置控制块的状态 */
	if (!sk->sk_prot->get_port(sk, inet->num)) {/* 进行端口绑定 */
		inet->sport = htons(inet->num);/* 设置网络字节序的端口号 */

		sk_dst_reset(sk);/* 清除路由缓存 */
		sk->sk_prot->hash(sk);/* 将传输控制块添加到侦听散列表中 */

		return 0;
	}

	/* 绑定失败，设置其状态 */
	sk->sk_state = TCP_CLOSE;
	/* 解除侦听连接请求块与传输控制块的绑定 */
	write_lock_bh(&tp->syn_wait_lock);
	tp->listen_opt = NULL;
	write_unlock_bh(&tp->syn_wait_lock);
	kfree(lopt);/* 释放侦听连接请求块 */
	return -EADDRINUSE;
}

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
/* 关闭套接口时，终止侦听端口 */
static void tcp_listen_stop (struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_listen_opt *lopt = tp->listen_opt;
	struct open_request *acc_req = tp->accept_queue;
	struct open_request *req;
	int i;

	/* 停止sk_timer定时器 */
	tcp_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	write_lock_bh(&tp->syn_wait_lock);/* 设置listen_opt后，应当不会再接受新的连接请求了 */
	tp->listen_opt = NULL;
	write_unlock_bh(&tp->syn_wait_lock);
	tp->accept_queue = tp->accept_queue_tail = NULL;

	if (lopt->qlen) {/* 请求连接者数量大于0 */
		for (i = 0; i < TCP_SYNQ_HSIZE; i++) {/* 遍历半连接哈希表 */
			while ((req = lopt->syn_table[i]) != NULL) {/* 遍历链表中的半连接 */
				lopt->syn_table[i] = req->dl_next;
				lopt->qlen--;
				tcp_openreq_free(req);/* 关闭半连接 */

		/* Following specs, it would be better either to send FIN
		 * (and enter FIN-WAIT-1, it is normal close)
		 * or to send active reset (abort).
		 * Certainly, it is pretty dangerous while synflood, but it is
		 * bad justification for our negligence 8)
		 * To be honest, we are not able to make either
		 * of the variants now.			--ANK
		 */
			}
		}
	}
	BUG_TRAP(!lopt->qlen);

	kfree(lopt);

	while ((req = acc_req) != NULL) {/* 已经连接但是还没有被accept的连接 */
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		local_bh_disable();
		bh_lock_sock(child);
		BUG_TRAP(!sock_owned_by_user(child));
		sock_hold(child);

		/* 断开已经建立连接但是还没有被accept的连接 */
		tcp_disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		atomic_inc(&tcp_orphan_count);

		tcp_destroy_sock(child);

		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		tcp_openreq_fastfree(req);
	}
	BUG_TRAP(!sk->sk_ack_backlog);
}

static inline void tcp_mark_push(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static inline void skb_entail(struct sock *sk, struct tcp_sock *tp,
			      struct sk_buff *skb)
{
	skb->csum = 0;
	TCP_SKB_CB(skb)->seq = tp->write_seq;
	TCP_SKB_CB(skb)->end_seq = tp->write_seq;
	TCP_SKB_CB(skb)->flags = TCPCB_FLAG_ACK;
	TCP_SKB_CB(skb)->sacked = 0;
	__skb_queue_tail(&sk->sk_write_queue, skb);
	sk_charge_skb(sk, skb);
	if (!sk->sk_send_head)
		sk->sk_send_head = skb;
	else if (tp->nonagle&TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH; 
}

static inline void tcp_mark_urg(struct tcp_sock *tp, int flags,
				struct sk_buff *skb)
{
	if (flags & MSG_OOB) {
		tp->urg_mode = 1;
		tp->snd_up = tp->write_seq;
		TCP_SKB_CB(skb)->sacked |= TCPCB_URG;
	}
}

/* 增加PSH标志后将报文发送出去 */
static inline void tcp_push(struct sock *sk, struct tcp_sock *tp, int flags,
			    int mss_now, int nonagle)
{
	if (sk->sk_send_head) {
		struct sk_buff *skb = sk->sk_write_queue.prev;
		if (!(flags & MSG_MORE) || forced_push(tp))
			tcp_mark_push(tp, skb);
		tcp_mark_urg(tp, flags, skb);
		__tcp_push_pending_frames(sk, tp, mss_now,
					  (flags & MSG_MORE) ? TCP_NAGLE_CORK : nonagle);
	}
}

static ssize_t do_tcp_sendpages(struct sock *sk, struct page **pages, int poffset,
			 size_t psize, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (psize > 0) {
		struct sk_buff *skb = sk->sk_write_queue.prev;
		struct page *page = pages[poffset / PAGE_SIZE];
		int copy, i, can_coalesce;
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		if (!sk->sk_send_head || (copy = mss_now - skb->len) <= 0) {
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			skb = sk_stream_alloc_pskb(sk, 0, 0,
						   sk->sk_allocation);
			if (!skb)
				goto wait_for_memory;

			skb_entail(sk, tp, skb);
			copy = mss_now;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= MAX_SKB_FRAGS) {
			tcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (sk->sk_forward_alloc < copy &&
		    !sk_stream_mem_schedule(sk, copy, 0))
			goto wait_for_memory;
		
		if (can_coalesce) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk->sk_forward_alloc -= copy;
		skb->ip_summed = CHECKSUM_HW;
		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		skb_shinfo(skb)->tso_segs = 0;

		if (!copied)
			TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

		copied += copy;
		poffset += copy;
		if (!(psize -= copy))
			goto out;

		if (skb->len != mss_now || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, tp, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == sk->sk_send_head)
			tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			tcp_push(sk, tp, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

		if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
			goto do_error;

		mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
	}

out:
	if (copied)
		tcp_push(sk, tp, flags, mss_now, tp->nonagle);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	return sk_stream_error(sk, flags, err);
}

ssize_t tcp_sendpage(struct socket *sock, struct page *page, int offset,
		     size_t size, int flags)
{
	ssize_t res;
	struct sock *sk = sock->sk;

#define TCP_ZC_CSUM_FLAGS (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & TCP_ZC_CSUM_FLAGS))
		return sock_no_sendpage(sock, page, offset, size, flags);

#undef TCP_ZC_CSUM_FLAGS

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);
	res = do_tcp_sendpages(sk, &page, offset, size, flags);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return res;
}

#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)

static inline int select_size(struct sock *sk, struct tcp_sock *tp)
{
	int tmp = tp->mss_cache_std;

	if (sk->sk_route_caps & NETIF_F_SG) {
		int pgbreak = SKB_MAX_HEAD(MAX_TCP_HEADER);

		if (tmp >= pgbreak &&
		    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
			tmp = pgbreak;
	}
	return tmp;
}

/* sendmsg系统调用在TCP层的实现 */
int tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t size)
{
	struct iovec *iov;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now;
	int err, copied;
	long timeo;

	/* 获取套接口的锁 */
	lock_sock(sk);
	TCP_CHECK_TIMER(sk);

	/* 根据标志计算阻塞超时时间 */
	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))/* 只有这两种状态才能发送消息 */
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)/* 其它状态下等待连接正确建立，超时则进行错误处理 */
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	/* 获得有效的MSS，如果支持OOB，则不能支持TSO，MSS则应当是比较小的值 */
	mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));

	/* Ok commence sending. */
	/* 获取待发送数据块数及数据块指针 */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	/* copied表示从用户数据块复制到skb中的字节数。 */
	copied = 0;

	err = -EPIPE;
	/* 如果套接口存在错误，则不允许发送数据，返回EPIPE错误 */
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (--iovlen >= 0) {/* 处理所有待发送数据块 */
		int seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;

		while (seglen > 0) {/* 处理单个数据块中的所有数据 */
			int copy;

			skb = sk->sk_write_queue.prev;

			if (!sk->sk_send_head ||/* 发送队列为空，前面取得的skb无效 */
			    (copy = mss_now - skb->len) <= 0) {/* 如果skb有效，但是它已经没有多余的空间复制新数据了 */

new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))/* 发送队列中数据长度达到发送缓冲区的上限，等待缓冲区 */
					goto wait_for_sndbuf;

				skb = sk_stream_alloc_pskb(sk, select_size(sk, tp),
							   0, sk->sk_allocation);/* 分配新的skb */
				if (!skb)/* 分配失败，说明系统内存不足，等待 */
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps &
				    (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM |
				     NETIF_F_HW_CSUM))/* 根据路由网络设备的特性，确定是否由硬件执行校验和 */
					skb->ip_summed = CHECKSUM_HW;

				skb_entail(sk, tp, skb);/* 将SKB添加到发送队列尾部 */
				copy = mss_now;/* 本次需要复制的数据量是MSS */
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)/* 要复制的数据不能大于当前段的长度 */
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {/* skb线性存储区底部还有空间 */
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))/* 本次只复制skb存储区底部剩余空间大小的数据量 */
					copy = skb_tailroom(skb);
				/* 从用户空间复制指定长度的数据到skb中，如果失败，则退出 */
				if ((err = skb_add_data(skb, from, copy)) != 0)
					goto do_fault;
			} else {/* 线性存储区底部已经没有空间了，复制到分散/聚集存储区中 */
				int merge = 0;/* 是否在页中添加数据 */
				int i = skb_shinfo(skb)->nr_frags;/* 分散/聚集片断数 */
				struct page *page = TCP_PAGE(sk);/* 分片页页 */
				int off = TCP_OFF(sk);/* 分片内的偏移 */

				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {/* 当前分片还能添加数据 */
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == MAX_SKB_FRAGS ||/* 目前skb中的页不能添加数据，这里判断是否能再分配页 */
					   (!i &&
					   !(sk->sk_route_caps & NETIF_F_SG))) {/* 网卡不支持S/G，不能分片 */
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					tcp_mark_push(tp, skb);/* SKB可以提交了 */
					goto new_segment;/* 重新分配skb */
				} else if (page) {/* 分页数量未达到上限，判断当前页是否还有空间 */
					/* If page is cached, align
					 * offset to L1 cache boundary
					 */
					off = (off + L1_CACHE_BYTES - 1) &
					      ~(L1_CACHE_BYTES - 1);
					if (off == PAGE_SIZE) {/* 最后一个分页数据已经满，需要分配新页 */
						put_page(page);
						TCP_PAGE(sk) = page = NULL;
					}
				}

				if (!page) {/* 需要分配新页 */
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))/* 分配新页，如果内存不足则等待内存 */
						goto wait_for_memory;
					off = 0;
				}

				if (copy > PAGE_SIZE - off)/* 待复制的数据不能大于页中剩余空间 */
					copy = PAGE_SIZE - off;

				/* Time to copy data. We are close to
				 * the end! */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);/* 从用户态复制数据到页中 */
				if (err) {/* 复制失败了 */
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {/* 如果是新分配的页，则将页记录到skb中，供今后使用 */
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				/* 更新skb的分段信息 */
				if (merge) {/* 在最后一个页中追加数据 */
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;/* 更新最后一页的数据长度 */
				} else {/* 新分配的页 */
					/* 更新skb中分片信息 */
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TCP_PAGE(sk)) {
						get_page(page);
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TCP_PAGE(sk) = page;
					}
				}

				/* 更新页内偏移 */
				TCP_OFF(sk) = off + copy;
			}

			if (!copied)/* 如果没有复制数据，则取消PSH标志 */
				TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

			tp->write_seq += copy;/* 更新发送队列最后一个包的序号 */
			TCP_SKB_CB(skb)->end_seq += copy;/* 更新skb的序号 */
			skb_shinfo(skb)->tso_segs = 0;

			/* 更新数据复制的指针 */
			from += copy;
			copied += copy;
			/* 如果所有数据已经复制完毕则退出 */
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			/* 如果当前skb中的数据小于mss，说明可以往里面继续复制数据。或者发送的是OOB数据，则也跳过发送过程，继续复制数据 */
			if (skb->len != mss_now || (flags & MSG_OOB))
				continue;

			if (forced_push(tp)) {/* 必须立即发送数据，即上次发送后产生的数据已经超过通告窗口值的一半 */
				/* 设置PSH标志后发送数据 */
				tcp_mark_push(tp, skb);
				__tcp_push_pending_frames(sk, tp, mss_now, TCP_NAGLE_PUSH);
			} else if (skb == sk->sk_send_head)/* 虽然不是必须发送数据，但是发送队列上只存在当前段，也将其发送出去 */
				tcp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			/* 由于发送队列满的原因导致等待 */
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)/* 虽然没有内存了，但是本次调用复制了数据到缓冲区，调用tcp_push将其发送出去 */
				tcp_push(sk, tp, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

			/* 等待内存可用 */
			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;/* 确实没有内存了，超时后返回失败 */

			/* 睡眠后，MSS可能发生了变化，重新计算 */
			mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
		}
	}

out:
	if (copied)/* 从用户态复制了数据，发送它 */
		tcp_push(sk, tp, flags, mss_now, tp->nonagle);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);/* 释放锁以后返回 */
	return copied;

do_fault:
	if (!skb->len) {/* 复制数据失败了，如果skb长度为0，说明是新分配的，释放它 */
		if (sk->sk_send_head == skb)/* 如果skb是发送队列头，则清空队列头 */
			sk->sk_send_head = NULL;
		__skb_unlink(skb, skb->list);
		sk_stream_free_skb(sk, skb);/* 释放skb */
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;
}

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */
/* 将保存在传输控制块中的带外数据读取到用户空间中，当用户通过recv调用读取带外数据时使用 */
static int tcp_recv_urg(struct sock *sk, long timeo,
			struct msghdr *msg, int len, int flags,
			int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||/* 将URG读到正常数据流，或者没有带外数据 */
	    tp->urg_data == TCP_URG_READ)/* 带外数据已经被读取 */
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))/* 还没有连接，不能读取带外数据 */
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {/* 带外数据有效 */
		int err = 0;
		char c = tp->urg_data;

		if (!(flags & MSG_PEEK))/* 如果不是查看，则设置READ标志表示数据已经被读走 */
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;/* 向用户返回标志，表示读取了带外数据 */

		if (len > 0) {/* 用户指定了接收缓冲区 */
			if (!(flags & MSG_TRUNC))/* 用户不是想清除带外数据 */
				err = memcpy_toiovec(msg->msg_iov, &c, 1);/* 将带外数据复制到用户缓冲区 */
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;/* 返回此标志表示缓冲区不足，数据被截断 */

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))/* 此时返回0表示没有读到数据 */
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	/* 会运行到这里吗? */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
/* 将接收队列中的数据复制到用户空间后，为满负荷的段清理接收缓冲区，然后根据需要确定是否发送ACK段 */
static void cleanup_rbuf(struct sock *sk, int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time_to_ack = 0;

#if TCP_DEBUG
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

	BUG_TRAP(!skb || before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq));
#endif

	/* 确定是否需要立即发送ACK给对方 */
	if (tcp_ack_scheduled(tp)) {
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (tp->ack.blocked ||/* 由于锁被占用，因此ACK被延迟发送 */
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > tp->ack.rcv_mss ||/* 有一个以上的全尺寸段还没有给对方确认 */
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 && (tp->ack.pending & TCP_ACK_PUSHED) &&/* 发送到用户空间的数据量大于0，并且发送紧急程度为TCP_ACK_PUSHED */
		     !tp->ack.pingpong && !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	/* 其他情况下，如果还需要接收报文则继续判断 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {/* 当前接收窗口小于接收窗口上限的一半 */
			__u32 new_window = __tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			/* ??? */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}
	if (time_to_ack)
		tcp_send_ack(sk);
}

static void tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	NET_ADD_STATS_USER(LINUX_MIB_TCPPREQUEUED, skb_queue_len(&tp->ucopy.prequeue));

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk->sk_backlog_rcv(sk, skb);
	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

static inline struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		offset = seq - TCP_SKB_CB(skb)->seq;
		if (skb->h.th->syn)
			offset--;
		if (offset < skb->len || skb->h.th->fin) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * This routine provides an alternative to tcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			size_t used, len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			if (offset != skb->len)
				break;
		}
		if (skb->h.th->fin) {
			sk_eat_skb(sk, skb);
			++seq;
			break;
		}
		sk_eat_skb(sk, skb);
		if (!desc->count)
			break;
	}
	tp->copied_seq = seq;

	tcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied)
		cleanup_rbuf(sk, copied);
	return copied;
}

/*
 *	This routine copies from a sock struct into the user buffer.
 *
 *	Technical note: in 2.3 we work on _locked_ socket, so that
 *	tricks with *seq access order and skb->users are not required.
 *	Probably, code can be easily improved even more.
 */

/* recvmsg系统调用的传输层实现 */
int tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int nonblock, int flags, int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct task_struct *user_recv = NULL;

	lock_sock(sk);/* 首先获取套接口的锁 */

	TCP_CHECK_TIMER(sk);

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)/* LISTEN状态的套接口是不能读取数据的 */
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);/* 计算超时时间 */

	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)/* 带外数据的处理比较复杂，特殊处理 */
		goto recv_urg;

	seq = &tp->copied_seq;/* 默认情况下，是将报文从内核态读到用户态，需要更新copied_seq */
	if (flags & MSG_PEEK) {/* 如果只查看而不取走数据，则不能更新copied_seq，后面就只更新临时变量peek_seq了 */
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	/* target是本次复制数据的长度，如果指定了MSG_WAITALL，就需要读取用户指定长度的数据，否则可以只读取部分数据 */
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	do {
		struct sk_buff *skb;
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {/* 当前遇到了带外数据 */
			if (copied)/* 如果已经复制了部分数据到用户态，则退出 */
				break;
			if (signal_pending(current)) {/* 如果接收到信号，也退出 */
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */

		skb = skb_peek(&sk->sk_receive_queue);/* 获取下一个待读取的段 */
		do {
			if (!skb)/* 接收队列为空，退出，处理prequeue队列和后备队列 */
				break;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (before(*seq, TCP_SKB_CB(skb)->seq)) {/* 下一个段不是预期读取的段，只能退出处理prequeue队列和后备队列，实际上这不可能发生 */
				printk(KERN_INFO "recvmsg bug: copied %X "
				       "seq %X\n", *seq, TCP_SKB_CB(skb)->seq);
				break;
			}
			/* 计算我们应当在该段的何处开始复制数据，因为上次recv调用可能已经读取了部分数据 */
			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (skb->h.th->syn)/* syn标志占用一个序号，因此需要调整偏移 */
				offset--;
			if (offset < skb->len)/* 偏移还在段范围内，说明当前段是有效的，从该段中读取数据 */
				goto found_ok_skb;
			if (skb->h.th->fin)/* 该段的数据已经读取完毕，如果fin标志，那么不能继续处理后面的数据了 */
				goto found_fin_ok;
			BUG_TRAP(flags & MSG_PEEK);
			skb = skb->next;
		} while (skb != (struct sk_buff *)&sk->sk_receive_queue);

		/* Well, if we have backlog, try to process it now yet. */

		/* 数据已经读完，并且后备队列为空，直接退出 */
		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {/* 复制了部分数据，检查是否有退出事件需要处理 */
			if (sk->sk_err ||/* SOCK发生了错误 */
			    sk->sk_state == TCP_CLOSE ||/* 套口已经关闭 */
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||/* 停止接收 */
			    !timeo ||/* 超时时间到 */
			    signal_pending(current) ||/* 接收到信号 */
			    (flags & MSG_PEEK))/* 仅仅查看数据 */
				break;/* 这些事件都导致接收过程退出 */
		} else {
			if (sock_flag(sk, SOCK_DONE))/* TCP会话已经结束，收到了FIN报文 */
				break;

			if (sk->sk_err) {/* 有错误发生，退出 */
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)/* 停止接收 */
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {/* 可能是连接还没有建立 */
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {/* 非阻塞读，退出 */
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {/* 接收到信号 */
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		/* 检测是否有确认需要发送 */
		cleanup_rbuf(sk, copied);

		if (tp->ucopy.task == user_recv) {
			/* Install new reader */
			/* 第一次检测处理 */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {
				user_recv = current;
				tp->ucopy.task = user_recv;
				tp->ucopy.iov = msg->msg_iov;
			}

			tp->ucopy.len = len;/* 更新可使用的用户态缓存大小 */

			BUG_TRAP(tp->copied_seq == tp->rcv_nxt ||
				 (flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */
			/* 如果prequeue不为空，则处理prequeue队列 */
			if (skb_queue_len(&tp->ucopy.prequeue))
				goto do_prequeue;

			/* __ Set realtime policy in scheduler __ */
		}

		if (copied >= target) {/* 数据读取完毕 */
			/* Do not sleep, just process backlog. */
			release_sock(sk);/* 释放锁，主要是处理后备队列 */
			lock_sock(sk);/* 再次获取锁 */
		} else
			sk_wait_data(sk, &timeo);/* 等待新数据到来，或者超时。在此期间软中断可能复制数据到用户态 */

		if (user_recv) {
			int chunk;

			/* __ Restore normal policy in scheduler __ */

			/* 睡眠期间，复制了数据到用户态 */
			if ((chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
				len -= chunk;/* 更新计数 */
				copied += chunk;
			}

			if (tp->rcv_nxt == tp->copied_seq &&/* 接收队列中的数据已经全部复制到用户态 */
			    skb_queue_len(&tp->ucopy.prequeue)) {/* prequeue还有数据 */
do_prequeue:
				tcp_prequeue_process(sk);/* 处理prequeue队列 */

				if ((chunk = len - tp->ucopy.len) != 0) {/* 从prequeue队列复制了数据到用户态 */
					NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
					len -= chunk;/* 更新计数 */
					copied += chunk;
				}
			}
		}
		if ((flags & MSG_PEEK) && peek_seq != tp->copied_seq) {
			if (net_ratelimit())
				printk(KERN_DEBUG "TCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, current->pid);
			peek_seq = tp->copied_seq;
		}
		continue;/* 继续处理待读取的段 */

	found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;/* 本段中可以读取的长度 */
		if (len < used)/* 如果可读的长度较长，则只读取用户期望读取的长度 */
			used = len;

		/* Do we have urgent data here? */
		if (tp->urg_data) {/* 有带外数据 */
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {/* 带外数据在可读数据内，表示带外数据有效 */
				if (!urg_offset) {/* 偏移为0，表示当前要读的位置正好是带外数据 */
					if (!sock_flag(sk, SOCK_URGINLINE)) {/* 带外数据不放入数据流 */
						++*seq;/* 调整读取位置 */
						offset++;
						used--;
						if (!used)/* 调整后可读数据为0，说明没有数据可读，跳过 */
							goto skip_copy;
					}
				} else/* 当前位置不是带外数据，则调整位置，只读到带外数据处 */
					used = urg_offset;
			}
		}

		if (!(flags & MSG_TRUNC)) {/* 不是截断数据，表示要将数据复制到用户态 */
			err = skb_copy_datagram_iovec(skb, offset,
						      msg->msg_iov, used);/* 将数据复制到用户态 */
			if (err) {
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		/* 调整一些参数 */
		*seq += used;
		copied += used;
		len -= used;

		/* 调整合理的TCP接收缓冲区大小 */
		tcp_rcv_space_adjust(sk);

skip_copy:
		/* 如果完成了带外数据的处理，则清除标志，设置首部预测标志 */
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			tp->urg_data = 0;
			tcp_fast_path_check(sk, tp);
		}
		/* 还有数据没有复制到用户态，就不能删除这个段 */
		if (used + offset < skb->len)
			continue;

		if (skb->h.th->fin)/* 处理完该段，检测FIN标志 */
			goto found_fin_ok;
		if (!(flags & MSG_PEEK))/* 如果是读取而不是查看报文，并且处理完本段报文，则删除它 */
			sk_eat_skb(sk, skb);
		continue;/* 继续处理下一个段 */

	found_fin_ok:
		/* Process the FIN. */
		++*seq;/* FIN占用一个序号，因此递增序号 */
		if (!(flags & MSG_PEEK))/* 不是查看数据，将其从队列中删除 */
			sk_eat_skb(sk, skb);
		break;/* 收到FIN，不需要继续处理后续的段，退出 */
	} while (len > 0);

	if (user_recv) {
		if (skb_queue_len(&tp->ucopy.prequeue)) {/* prequeue队列不为空 */
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;

			tcp_prequeue_process(sk);/* 处理prequeue队列 */

			/* 在处理prequeue的过程中，有数据复制到用户态 */
			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
				len -= chunk;
				copied += chunk;
			}
		}

		/* 清除task和len，表示用户当前没有读取数据。这样处理prequeue队列时就不会向用户态复制了 */
		tp->ucopy.task = NULL;
		tp->ucopy.len = 0;
	}

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	/* 再次检查是否立即发送ACK */
	cleanup_rbuf(sk, copied);

	TCP_CHECK_TIMER(sk);
	release_sock(sk);/* 解锁传输控制块 */
	return copied;/* 返回复制的字节数 */

out:/* 接收过程中，如果发生错误，则解锁后返回 */
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;

recv_urg:
	/* 调用tcp_recv_urg处理带外数据  */
	err = tcp_recv_urg(sk, timeo, msg, len, flags, addr_len);
	goto out;
}

/*
 *	State processing on a close. This implements the state shift for
 *	sending our FIN frame. Note that we only send a FIN for some
 *	states. A shutdown() may have already sent the FIN, or we may be
 *	closed.
 */

static unsigned char new_state[16] = {
  /* current state:        new state:      action:	*/
  /* (Invalid)		*/ TCP_CLOSE,
  /* TCP_ESTABLISHED	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_SYN_SENT	*/ TCP_CLOSE,
  /* TCP_SYN_RECV	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_FIN_WAIT1	*/ TCP_FIN_WAIT1,
  /* TCP_FIN_WAIT2	*/ TCP_FIN_WAIT2,
  /* TCP_TIME_WAIT	*/ TCP_CLOSE,
  /* TCP_CLOSE		*/ TCP_CLOSE,
  /* TCP_CLOSE_WAIT	*/ TCP_LAST_ACK  | TCP_ACTION_FIN,
  /* TCP_LAST_ACK	*/ TCP_LAST_ACK,
  /* TCP_LISTEN		*/ TCP_CLOSE,
  /* TCP_CLOSING	*/ TCP_CLOSING,
};

static int tcp_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];
	int ns = next & TCP_STATE_MASK;

	tcp_set_state(sk, ns);

	return next & TCP_ACTION_FIN;
}

/*
 *	Shutdown the sending side of a connection. Much like close except
 *	that we don't receive shut down or set_sock_flag(sk, SOCK_DEAD).
 */
/* shutdown系统调用的传输层实现 */
void tcp_shutdown(struct sock *sk, int how)
{
	/*	We need to grab some memory, and put together a FIN,
	 *	and then put it into the queue to be sent.
	 *		Tim MacKenzie(tym@dibbler.cs.monash.edu.au) 4 Dec '92.
	 */
	if (!(how & SEND_SHUTDOWN))/* 参数错误，返回 */
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {/* 这些状态没有发送FIN */
		/* Clear out any half completed packets.  FIN if needed. */
		if (tcp_close_state(sk))/* 如果需要发送FIN，则发送 */
			tcp_send_fin(sk);
	}
}

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void tcp_destroy_sock(struct sock *sk)
{
	BUG_TRAP(sk->sk_state == TCP_CLOSE);
	BUG_TRAP(sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	BUG_TRAP(sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->num, it must be bound */
	BUG_TRAP(!inet_sk(sk)->num || tcp_sk(sk)->bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

#ifdef INET_REFCNT_DEBUG
	if (atomic_read(&sk->sk_refcnt) != 1) {
		printk(KERN_DEBUG "Destruction TCP %p delayed, c=%d\n",
		       sk, atomic_read(&sk->sk_refcnt));
	}
#endif

	atomic_dec(&tcp_orphan_count);
	sock_put(sk);
}

/* close系统调用的传输层实现 */
void tcp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;

	lock_sock(sk);/* 获取套接口锁 */
	sk->sk_shutdown = SHUTDOWN_MASK;/* 表示两个方向的上的关闭 */

	if (sk->sk_state == TCP_LISTEN) {/* LISTEN状态 */
		tcp_set_state(sk, TCP_CLOSE);/* 设置其状态为CLOSE */

		/* Special case. */
		tcp_listen_stop(sk);/* 终止侦听 */

		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	/* 遍历接收队列中的段 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		/* 段中数据长度，如果是fin段，则减少一个字节长度，因为fin占用一个序号 */
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  skb->h.th->fin;
		/* 未读取的段长度 */
		data_was_unread += len;
		/* 释放段 */
		__kfree_skb(skb);
	}

	/* 释放套接口占用的缓存 */
	sk_stream_mem_reclaim(sk);

	/* As outlined in draft-ietf-tcpimpl-prob-03.txt, section
	 * 3.10, we send a RST here because data was lost.  To
	 * witness the awful effects of the old behavior of always
	 * doing a FIN, run an older 2.1.x kernel or 2.0.x, start
	 * a bulk GET in an FTP client, suspend the process, wait
	 * for the client to advertise a zero window, then kill -9
	 * the FTP client, wheee...  Note: timeout is always zero
	 * in such a case.
	 */
	if (data_was_unread) {/* 有未读数据 */
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		/* 发送RST表示非正常的结束，不能发送FIN */
		tcp_send_active_reset(sk, GFP_KERNEL);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {/* 虽然设置了SOCK_LINGER选项，但是延时时间为0 */
		/* Check zero linger _after_ checking for unread data. */
		/* 调用disconnect断开、删除并释放已建立连接但是未被accept的传输控制块，同时删除并释放已经接收到接收队列和失序队列上的段和发送队列上的段 */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(sk)) {/* 其他情况，包括没有设置SOCK_LINGER或者启用了SOCK_LINGER且延时时间不为0，转换当前状态到对应的状态，如果新状态需要发送FIN */
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TCP_ESTABLISHED, TCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 */
		tcp_send_fin(sk);/* 发送FIN段，将发送队列上未发送的段发送出去 */
	}

	/* 在给对端发送RST或FIN段后，等待套接口的关闭，直到TCP状态为FIN_WAIT_1、CLOSING、LAST_ACK或等待超时 */
	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);/* 释放锁的目的，是为了处理后备队列，新版本将其移动到后面，这里应当有一个BUG */


	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();/* 关闭下半部并获得锁 */
	bh_lock_sock(sk);
	BUG_TRAP(!sock_owned_by_user(sk));

	sock_hold(sk);
	sock_orphan(sk);/* 设置套接口为DEAD状态，成为孤儿套接口，同时更新系统中孤儿套接口数 */

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (sk->sk_state == TCP_FIN_WAIT2) {/* 当前状态为TCP_FIN_WAIT2 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->linger2 < 0) {/* 该值小于0，表示可以从TCP_FIN_WAIT2状态直接转换为TCP_CLOSE状态 */
			/* 设置为CLOSE状态 */
			tcp_set_state(sk, TCP_CLOSE);
			/* 向对方发送RST段 */
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONLINGER);
		} else {/* 需要等待才进入CLOSE状态 */
			int tmo = tcp_fin_time(tp);/* 保持TCP_FIN_WAIT2状态的时间 */

			if (tmo > TCP_TIMEWAIT_LEN) {/* 超过60s */
				/* 通过FIN_WAIT_2定时器来处理状态转换 */
				tcp_reset_keepalive_timer(sk, tcp_fin_time(tp));
			} else {
				atomic_inc(&tcp_orphan_count);
				/* 小于60s，则等待，直到状态转换成功 */
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (sk->sk_state != TCP_CLOSE) {/* 此时不处于CLOSE状态 */
		sk_stream_mem_reclaim(sk);/* 释放内存缓存 */
		if (atomic_read(&tcp_orphan_count) > sysctl_tcp_max_orphans ||/* 孤儿套接口数量太多 */
		    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&/* 发送队列中的段数量大于下限 */
		     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {/* 且系统中总的TCP传输层缓冲区分配的内存超过缓存区大小的最高硬性限制 */
			if (net_ratelimit())
				printk(KERN_INFO "TCP: too many of orphaned "
				       "sockets\n");
			/* 这种情况下需要立即关闭套接口，设置其状态为CLOSE */
			tcp_set_state(sk, TCP_CLOSE);
			/* 向对方发送RST状态 */
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		}
	}
	/* 增加孤儿套接口数量，我觉得这里有点不妥 */
	atomic_inc(&tcp_orphan_count);

	if (sk->sk_state == TCP_CLOSE)/* 如果状态为CLOSE，则可以释放传输块及其占用的资源 */
		tcp_destroy_sock(sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/* These states need RST on ABORT according to RFC793 */

static inline int tcp_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
		TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

int tcp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err = 0;
	int old_state = sk->sk_state;

	if (old_state != TCP_CLOSE)
		tcp_set_state(sk, TCP_CLOSE);

	/* ABORT function of RFC793 */
	if (old_state == TCP_LISTEN) {
		tcp_listen_stop(sk);
	} else if (tcp_need_reset(old_state) ||
		   (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		/* The last check adjusts for discrepance of Linux wrt. RFC
		 * states
		 */
		tcp_send_active_reset(sk, gfp_any());
		sk->sk_err = ECONNRESET;
	} else if (old_state == TCP_SYN_SENT)
		sk->sk_err = ECONNRESET;

	tcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	sk_stream_writequeue_purge(sk);
	__skb_queue_purge(&tp->out_of_order_queue);

	inet->dport = 0;

	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	tp->backoff = 0;
	tp->snd_cwnd = 2;
	tp->probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = 0x7fffffff;
	tp->snd_cwnd_cnt = 0;
	tcp_set_ca_state(tp, TCP_CA_Open);
	tcp_clear_retrans(tp);
	tcp_delack_init(tp);
	sk->sk_send_head = NULL;
	tp->rx_opt.saw_tstamp = 0;
	tcp_sack_reset(&tp->rx_opt);
	__sk_dst_reset(sk);

	BUG_TRAP(!inet->num || tp->bind_hash);

	sk->sk_error_report(sk);
	return err;
}

/*
 *	Wait for an incoming connection, avoid race
 *	conditions. This must be called with the socket locked.
 */
static int wait_for_connect(struct sock *sk, long timeo)
{
	struct tcp_sock *tp = tcp_sk(sk);
	DEFINE_WAIT(wait);
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk->sk_sleep, &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (!tp->accept_queue)
			timeo = schedule_timeout(timeo);
		lock_sock(sk);
		err = 0;
		if (tp->accept_queue)
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk->sk_sleep, &wait);
	return err;
}

/*
 *	This will accept the next outstanding connection.
 */
/* accept调用的传输层实现 */
struct sock *tcp_accept(struct sock *sk, int flags, int *err)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct open_request *req;
	struct sock *newsk;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)/* 本调用仅仅针对侦听套口，不是此状态的套口则退出 */
		goto out;

	/* Find already established connection */
	if (!tp->accept_queue) {/* accept队列为空，说明还没有收到新连接 */
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);/* 如果套口是非阻塞的，或者在一定时间内没有新连接，则返回 */

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)/* 超时时间到，没有新连接，退出 */
			goto out;

		/* 运行到这里，说明有新连接到来，则等待新的传输控制块 */
		error = wait_for_connect(sk, timeo);
		if (error)
			goto out;
	}

	req = tp->accept_queue;
	if ((tp->accept_queue = req->dl_next) == NULL)
		tp->accept_queue_tail = NULL;

 	newsk = req->sk;
	sk_acceptq_removed(sk);
	tcp_openreq_fastfree(req);
	BUG_TRAP(newsk->sk_state != TCP_SYN_RECV);
	release_sock(sk);
	return newsk;

out:
	release_sock(sk);
	*err = error;
	return NULL;
}

/*
 *	Socket option code for TCP.
 */
/* 设置tcp选项 */
int tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int val;
	int err = 0;

	if (level != SOL_TCP)/* 如果不是TCP级别的选项，就调用接口处理ip层的选项 */
		return tp->af_specific->setsockopt(sk, level, optname,
						   optval, optlen);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);/* 获得连接锁后设置其选项 */

	switch (optname) {
	case TCP_MAXSEG:/* 设置应用层的MSS上限 */
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used */
		if (val < 8 || val > MAX_TCP_WINDOW) {/* 有效的MSS值在8到32767之间 */
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;/* 设置连接的用户层MSS */
		break;

	case TCP_NODELAY:/* 禁止或者启用套接口上的Nagle算法 */
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;/* 禁用Nagle算法 */
			tcp_push_pending_frames(sk, tp);/* 将连接中的待发送数据发出去 */
		} else {
			tp->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;

	case TCP_CORK:/* 使能此选项后，会对Nagle进行优化，200ms内发送的数据会被组合成大的报文 */
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TCP_NAGLE_CORK;
			if (tp->nonagle&TCP_NAGLE_OFF)
				tp->nonagle |= TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk, tp);
		}
		break;

	case TCP_KEEPIDLE:/* 设置保活探测前TCP空闲时间 */
		if (val < 1 || val > MAX_TCP_KEEPIDLE)/* 参数检测 */
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;/* 设置保活启动时间 */
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TCPF_CLOSE | TCPF_LISTEN))) {/* 判断当前是否需要启动保活定时器 */
				__u32 elapsed = tcp_time_stamp - tp->rcv_tstamp;
				if (tp->keepalive_time > elapsed)
					elapsed = tp->keepalive_time - elapsed;
				else
					elapsed = 0;
				tcp_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TCP_KEEPINTVL:/* 设置保活探测间隔时间 */
		if (val < 1 || val > MAX_TCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ;
		break;
	case TCP_KEEPCNT:/* 设置保活探测次数，超过此值，则认为连接已经断开 */
		if (val < 1 || val > MAX_TCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val;
		break;
	case TCP_SYNCNT:/* 为建立连接而重发SYN的次数 */
		if (val < 1 || val > MAX_TCP_SYNCNT)
			err = -EINVAL;
		else
			tp->syn_retries = val;
		break;

	case TCP_LINGER2:/* 保持在FIN_WAIT_2状态的时间 */
		if (val < 0)
			tp->linger2 = -1;
		else if (val > sysctl_tcp_fin_timeout / HZ)
			tp->linger2 = 0;
		else
			tp->linger2 = val * HZ;
		break;

	case TCP_DEFER_ACCEPT:/* 延迟accept，这样可以将ack放到数据报文中进行应答。对HTTP来说有用。 */
		tp->defer_accept = 0;
		if (val > 0) {
			/* Translate value in seconds to number of
			 * retransmits */
			while (tp->defer_accept < 32 &&
			       val > ((TCP_TIMEOUT_INIT / HZ) <<
				       tp->defer_accept))
				tp->defer_accept++;
			tp->defer_accept++;
		}
		break;

	case TCP_WINDOW_CLAMP:/* 设置滑动窗口上限 */
		if (!val) {
			if (sk->sk_state != TCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TCP_QUICKACK:/* 启用或者禁用快速确认模式，该标志是暂时性的。 */
		if (!val) {
			tp->ack.pingpong = 1;
		} else {
			tp->ack.pingpong = 0;
			if ((1 << sk->sk_state) &
			    (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
			    tcp_ack_scheduled(tp)) {
				tp->ack.pending |= TCP_ACK_PUSHED;
				cleanup_rbuf(sk, 1);
				if (!(val & 1))
					tp->ack.pingpong = 1;
			}
		}
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	};
	release_sock(sk);
	return err;
}

/* Return information about state of tcp endpoint in API format. */
void tcp_get_info(struct sock *sk, struct tcp_info *info)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 now = tcp_time_stamp;

	memset(info, 0, sizeof(*info));

	info->tcpi_state = sk->sk_state;
	info->tcpi_ca_state = tp->ca_state;
	info->tcpi_retransmits = tp->retransmits;
	info->tcpi_probes = tp->probes_out;
	info->tcpi_backoff = tp->backoff;

	if (tp->rx_opt.tstamp_ok)
		info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (tp->rx_opt.sack_ok)
		info->tcpi_options |= TCPI_OPT_SACK;
	if (tp->rx_opt.wscale_ok) {
		info->tcpi_options |= TCPI_OPT_WSCALE;
		info->tcpi_snd_wscale = tp->rx_opt.snd_wscale;
		info->tcpi_rcv_wscale = tp->rx_opt.rcv_wscale;
	} 

	if (tp->ecn_flags&TCP_ECN_OK)
		info->tcpi_options |= TCPI_OPT_ECN;

	info->tcpi_rto = jiffies_to_usecs(tp->rto);
	info->tcpi_ato = jiffies_to_usecs(tp->ack.ato);
	info->tcpi_snd_mss = tp->mss_cache_std;
	info->tcpi_rcv_mss = tp->ack.rcv_mss;

	info->tcpi_unacked = tp->packets_out;
	info->tcpi_sacked = tp->sacked_out;
	info->tcpi_lost = tp->lost_out;
	info->tcpi_retrans = tp->retrans_out;
	info->tcpi_fackets = tp->fackets_out;

	info->tcpi_last_data_sent = jiffies_to_msecs(now - tp->lsndtime);
	info->tcpi_last_data_recv = jiffies_to_msecs(now - tp->ack.lrcvtime);
	info->tcpi_last_ack_recv = jiffies_to_msecs(now - tp->rcv_tstamp);

	info->tcpi_pmtu = tp->pmtu_cookie;
	info->tcpi_rcv_ssthresh = tp->rcv_ssthresh;
	info->tcpi_rtt = jiffies_to_usecs(tp->srtt)>>3;
	info->tcpi_rttvar = jiffies_to_usecs(tp->mdev)>>2;
	info->tcpi_snd_ssthresh = tp->snd_ssthresh;
	info->tcpi_snd_cwnd = tp->snd_cwnd;
	info->tcpi_advmss = tp->advmss;
	info->tcpi_reordering = tp->reordering;

	info->tcpi_rcv_rtt = jiffies_to_usecs(tp->rcv_rtt_est.rtt)>>3;
	info->tcpi_rcv_space = tp->rcvq_space.space;

	info->tcpi_total_retrans = tp->total_retrans;
}

EXPORT_SYMBOL_GPL(tcp_get_info);

int tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int __user *optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int val, len;

	if (level != SOL_TCP)
		return tp->af_specific->getsockopt(sk, level, optname,
						   optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_MAXSEG:
		val = tp->mss_cache_std;
		if (!val && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		break;
	case TCP_NODELAY:
		val = !!(tp->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(tp->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = (tp->keepalive_time ? : sysctl_tcp_keepalive_time) / HZ;
		break;
	case TCP_KEEPINTVL:
		val = (tp->keepalive_intvl ? : sysctl_tcp_keepalive_intvl) / HZ;
		break;
	case TCP_KEEPCNT:
		val = tp->keepalive_probes ? : sysctl_tcp_keepalive_probes;
		break;
	case TCP_SYNCNT:
		val = tp->syn_retries ? : sysctl_tcp_syn_retries;
		break;
	case TCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : sysctl_tcp_fin_timeout) / HZ;
		break;
	case TCP_DEFER_ACCEPT:
		val = !tp->defer_accept ? 0 : ((TCP_TIMEOUT_INIT / HZ) <<
					       (tp->defer_accept - 1));
		break;
	case TCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TCP_INFO: {
		struct tcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		tcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUICKACK:
		val = !tp->ack.pingpong;
		break;
	default:
		return -ENOPROTOOPT;
	};

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}


extern void __skb_cb_too_small_for_tcp(int, int);
extern void tcpdiag_init(void);

static __initdata unsigned long thash_entries;
static int __init set_thash_entries(char *str)
{
	if (!str)
		return 0;
	thash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("thash_entries=", set_thash_entries);

void __init tcp_init(void)
{
	struct sk_buff *skb = NULL;
	int order, i;

	/* cb结构必须能够容纳tcp_skb_cb，否则报告错误 */
	if (sizeof(struct tcp_skb_cb) > sizeof(skb->cb))
		__skb_cb_too_small_for_tcp(sizeof(struct tcp_skb_cb),
					   sizeof(skb->cb));

	tcp_openreq_cachep = kmem_cache_create("tcp_open_request",
						   sizeof(struct open_request),
					       0, SLAB_HWCACHE_ALIGN,
					       NULL, NULL);
	if (!tcp_openreq_cachep)
		panic("tcp_init: Cannot alloc open_request cache.");

	/* 分配高速缓存，用于保存已经绑定端口的信息 */
	tcp_bucket_cachep = kmem_cache_create("tcp_bind_bucket",
					      sizeof(struct tcp_bind_bucket),
					      0, SLAB_HWCACHE_ALIGN,
					      NULL, NULL);
	if (!tcp_bucket_cachep)
		panic("tcp_init: Cannot alloc tcp_bind_bucket cache.");

	tcp_timewait_cachep = kmem_cache_create("tcp_tw_bucket",
						sizeof(struct tcp_tw_bucket),
						0, SLAB_HWCACHE_ALIGN,
						NULL, NULL);
	if (!tcp_timewait_cachep)
		panic("tcp_init: Cannot alloc tcp_tw_bucket cache.");

	/* Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	/* 分配已经建立的连接项的哈希表内存，thash_entries是内核参数 */
	tcp_ehash = (struct tcp_ehash_bucket *)
		alloc_large_system_hash("TCP established",
					sizeof(struct tcp_ehash_bucket),
					thash_entries,
					(num_physpages >= 128 * 1024) ?
						(25 - PAGE_SHIFT) :
						(27 - PAGE_SHIFT),
					HASH_HIGHMEM,
					&tcp_ehash_size,
					NULL,
					0);
	tcp_ehash_size = (1 << tcp_ehash_size) >> 1;
	for (i = 0; i < (tcp_ehash_size << 1); i++) {
		rwlock_init(&tcp_ehash[i].lock);
		INIT_HLIST_HEAD(&tcp_ehash[i].chain);
	}

	/* 分配绑定端口的散列表。 */
	tcp_bhash = (struct tcp_bind_hashbucket *)
		alloc_large_system_hash("TCP bind",
					sizeof(struct tcp_bind_hashbucket),
					tcp_ehash_size,
					(num_physpages >= 128 * 1024) ?
						(25 - PAGE_SHIFT) :
						(27 - PAGE_SHIFT),
					HASH_HIGHMEM,
					&tcp_bhash_size,
					NULL,
					64 * 1024);
	tcp_bhash_size = 1 << tcp_bhash_size;
	for (i = 0; i < tcp_bhash_size; i++) {
		spin_lock_init(&tcp_bhash[i].lock);
		INIT_HLIST_HEAD(&tcp_bhash[i].chain);
	}

	/* Try to be a bit smarter and adjust defaults depending
	 * on available memory.
	 */
	/* 将哈希表的大小折算成order值 */
	for (order = 0; ((1 << order) << PAGE_SHIFT) <
			(tcp_bhash_size * sizeof(struct tcp_bind_hashbucket));
			order++)
		;
	if (order > 4) {/* 根据order值基本上可以决定是服务器还是一般的桌面系统，据此设置相应参数 */
		sysctl_local_port_range[0] = 32768;
		sysctl_local_port_range[1] = 61000;
		sysctl_tcp_max_tw_buckets = 180000;
		sysctl_tcp_max_orphans = 4096 << (order - 4);
		sysctl_max_syn_backlog = 1024;
	} else if (order < 3) {
		sysctl_local_port_range[0] = 1024 * (3 - order);
		sysctl_tcp_max_tw_buckets >>= (3 - order);
		sysctl_tcp_max_orphans >>= (3 - order);
		sysctl_max_syn_backlog = 128;
	}
	tcp_port_rover = sysctl_local_port_range[0] - 1;

	/* 初始化内存控制参数 */
	sysctl_tcp_mem[0] =  768 << order;
	sysctl_tcp_mem[1] = 1024 << order;
	sysctl_tcp_mem[2] = 1536 << order;

	if (order < 3) {
		sysctl_tcp_wmem[2] = 64 * 1024;
		sysctl_tcp_rmem[0] = PAGE_SIZE;
		sysctl_tcp_rmem[1] = 43689;
		sysctl_tcp_rmem[2] = 2 * 43689;
	}

	printk(KERN_INFO "TCP: Hash tables configured "
	       "(established %d bind %d)\n",
	       tcp_ehash_size << 1, tcp_bhash_size);
}

EXPORT_SYMBOL(tcp_accept);
EXPORT_SYMBOL(tcp_close);
EXPORT_SYMBOL(tcp_destroy_sock);
EXPORT_SYMBOL(tcp_disconnect);
EXPORT_SYMBOL(tcp_getsockopt);
EXPORT_SYMBOL(tcp_ioctl);
EXPORT_SYMBOL(tcp_openreq_cachep);
EXPORT_SYMBOL(tcp_poll);
EXPORT_SYMBOL(tcp_read_sock);
EXPORT_SYMBOL(tcp_recvmsg);
EXPORT_SYMBOL(tcp_sendmsg);
EXPORT_SYMBOL(tcp_sendpage);
EXPORT_SYMBOL(tcp_setsockopt);
EXPORT_SYMBOL(tcp_shutdown);
EXPORT_SYMBOL(tcp_statistics);
EXPORT_SYMBOL(tcp_timewait_cachep);
