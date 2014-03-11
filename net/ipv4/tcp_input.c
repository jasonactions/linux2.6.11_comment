/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_input.c,v 1.243 2002/02/01 22:01:04 davem Exp $
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
 * Changes:
 *		Pedro Roque	:	Fast Retransmit/Recovery.
 *					Two receive queues.
 *					Retransmit queue handled by TCP.
 *					Better retransmit timer handling.
 *					New congestion avoidance.
 *					Header prediction.
 *					Variable renaming.
 *
 *		Eric		:	Fast Retransmit.
 *		Randy Scott	:	MSS option defines.
 *		Eric Schenk	:	Fixes to slow start algorithm.
 *		Eric Schenk	:	Yet another double ACK bug.
 *		Eric Schenk	:	Delayed ACK bug fixes.
 *		Eric Schenk	:	Floyd style fast retrans war avoidance.
 *		David S. Miller	:	Don't allow zero congestion window.
 *		Eric Schenk	:	Fix retransmitter so that it sends
 *					next packet on ack of previous packet.
 *		Andi Kleen	:	Moved open_request checking here
 *					and process RSTs for open_requests.
 *		Andi Kleen	:	Better prune_queue, and other fixes.
 *		Andrey Savochkin:	Fix RTT measurements in the presnce of
 *					timestamps.
 *		Andrey Savochkin:	Check sequence numbers correctly when
 *					removing SACKs due to in sequence incoming
 *					data segments.
 *		Andi Kleen:		Make sure we never ack data there is not
 *					enough room for. Also make this condition
 *					a fatal error if it might still happen.
 *		Andi Kleen:		Add tcp_measure_rcv_mss to make 
 *					connections with MSS<min(MTU,ann. MSS)
 *					work without delayed acks. 
 *		Andi Kleen:		Process packets with PSH set in the
 *					fast path.
 *		J Hadi Salim:		ECN support
 *	 	Andrei Gurtov,
 *		Pasi Sarolahti,
 *		Panu Kuhlberg:		Experimental audit of TCP (re)transmission
 *					engine. Lots of bugs are found.
 *		Pasi Sarolahti:		F-RTO for dealing with spurious RTOs
 *		Angelo Dell'Aera:	TCP Westwood+ support
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ipsec.h>

/* ÊÇ·ñÆôÓÃTCPÊ±¼ä´ÁÑ¡Ïî */
int sysctl_tcp_timestamps = 1;
/* ±êÊ¶ÊÇ·ñÆôÓÃTCP´°¿ÚÀ©´óÒò×ÓÑ¡Ïî */
int sysctl_tcp_window_scaling = 1;
/* ±êÊ¶ÊÇ·ñÆôÓÃÑ¡ÔñĞÔÈ·ÈÏSACKSÑ¡Ïî¡£¶Ô¹ãÓòÍøÀ´Ëµ¿ÉÒÔ´ò¿ª´ËÑ¡Ïî¡£ */
int sysctl_tcp_sack = 1;
/* ÊÇ·ñÆôÓÃFACKÓµÈû±ÜÃâÓë¿ìËÙÖØ´«¹¦ÄÜ¡£ */
int sysctl_tcp_fack = 1;
/**
 * ÔÚ²»Ö§³ÖSACKÊ±£¬ÎªÓÉÓÚÁ¬½Ó½ÓÊÕµ½ÖØ¸´È·ÈÏ¶ø½øÈë¿ìËÙ»Ö¸´¶ÎµÄÖØ¸´È·ÈÏÊı·§Öµ 
 * ÔÚÖ§³ÖSACKÊ±£¬ÔÚÃ»ÓĞÈ·¶¨¶ªÊ§°üµÄÇé¿öÏÂ£¬ÊÇTCPÁ÷ÖĞ¿ÉÒÔÖØÅÅĞòµÄÊı¾İ¶ÎÊı¡£
 */
int sysctl_tcp_reordering = TCP_FASTRETRANS_THRESH;
/* ÊÇ·ñÆôÓÃTCPµÄÏÔÊ½ÓµÈûÍ¨Öª¹¦ÄÜ¡£ */
int sysctl_tcp_ecn;
/* ÊÇ·ñÖ§³ÖD-SACK */
int sysctl_tcp_dsack = 1;
/* ÎªÓ¦ÓÃ³ÌĞò»º´æÊ¹ÓÃ£¬±£Áômax(window/2^sysctl_tcp_app_win, mss)´óĞ¡µÄ´°¿Ú¡£Îª0±íÊ¾²»±£Áô¡£ */
int sysctl_tcp_app_win = 31;
/* µ±Í¨¹ıµ÷½Ú½ÓÊÕ´°¿ÚÀ´½øĞĞÁ÷Á¿¿ØÖÆµÄÇé¿öÏÂ£¬¼ÆËãµ÷Õû½ÓÊÕ»º´æºÍ½ÓÊÕ´°¿ÚÊ±£¬ÓÃÀ´¶Ô¼ÆËãµÄ²ÎÊı½øĞĞÎ¢µ÷ */
int sysctl_tcp_adv_win_scale = 2;

/* ±êÊ¶ÊÇ·ñÊ¹ÓÃTCP½ô¼±Ö¸Õë×Ö¶Î±ê×¼½âÊÍ¡£ÎªÁËÓëÒÑÓĞÏµÍ³¼æÈİ£¬¹Ø±Õ´Ë¹¦ÄÜ¡£Õâ½«Óërfc±ê×¼²»¼æÈİ¡£ */
int sysctl_tcp_stdurg;
/* Ô¤·ÀÔÚrfc1337ÖĞÃèÊöµÄTIME-WAITÎÊÌâ£¬Ä¬ÈÏÎª0£¬½«¶ªÆúÄÇĞ©·¢ÍùTIME-WAIT×´Ì¬µÄRST¶Î¡£ */
int sysctl_tcp_rfc1337;
/**
 * ÏµÍ³×î¶àÄÜ´¦ÀíµÄ¹Â¶ùÌ×½Ó¿Ú(²»ÊôÓÚÈÎºÎ½ø³ÌµÄÌ×½Ó¿Ú)ÊıÁ¿£¬Ä¬ÈÏÎª16384¸ö 
 * Èç¹û³¬¹ıÕâ¸öÊıÁ¿£¬Ôò²»ÊôÓÚÈÎºÎ½ø³ÌµÄÁ¬½Ó»á±»Á¢¼´¸´Î»¡£
 * Ã¿¸ö¹Â¶ù½Ó¿ÚÏûºÄ64KµÄÄÚ´æ¡£
 */
int sysctl_tcp_max_orphans = NR_FILE;
/* ÊÇ·ñÆôÓÃfrto,¾­³£ÓÃÓÚÎŞÏß»·¾³£¬Ê¹ÓÃÓÅ»¯µÄTCPÖØ´«Ëã·¨ */
int sysctl_tcp_frto;
int sysctl_tcp_nometrics_save;
int sysctl_tcp_westwood;
int sysctl_tcp_vegas_cong_avoid;

/**
 * ±êÊ¶ÊÇ·ñÆô¶¯×Ô¶¯µ÷½Ú½ÓÊÕ»º³åÇø´óĞ¡¡£
 * Èç¹ûÆô¶¯£¬Ôò×Ô¶¯µØµ÷Õû½ÓÊÕ»º³åÇøµÄ´óĞ¡£¬ÒÔ´ËÀ´½øĞĞÁ÷Á¿¿ØÖÆ¡£
 */
int sysctl_tcp_moderate_rcvbuf = 1;

/* Default values of the Vegas variables, in fixed-point representation
 * with V_PARAM_SHIFT bits to the right of the binary point.
 */
#define V_PARAM_SHIFT 1
int sysctl_tcp_vegas_alpha = 1<<V_PARAM_SHIFT;
int sysctl_tcp_vegas_beta  = 3<<V_PARAM_SHIFT;
int sysctl_tcp_vegas_gamma = 1<<V_PARAM_SHIFT;
int sysctl_tcp_bic = 1;
int sysctl_tcp_bic_fast_convergence = 1;
int sysctl_tcp_bic_low_window = 14;
int sysctl_tcp_bic_beta = 819;		/* = 819/1024 (BICTCP_BETA_SCALE) */

/* ½ÓÊÕµ½µÄACK¶ÎµÄ±êÖ¾ */

/* ½ÓÊÕµÄACK¶ÎÊÇ¸ººÉÊı¾İµÄ */
#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
/* ½ÓÊÕµÄACk¶Î¸üĞÂÁË·¢ËÍ´°¿Ú */
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
/* ½ÓÊÕµÄACk¶ÎÈ·ÈÏÁËĞÂµÄÊı¾İ */
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
/* ´Ë¶ÎÒÑ¾­ÖØ´«¹ı */
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
/* ½ÓÊÕµÄACk¶ÎÈ·ÈÏÁËSYN¶Î */
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
/* ĞÂµÄSACK */
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
/* ½ÓÊÕµ½ÏÔÊ½ÓµÈûÍ¨Öª */
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
/* ÓÉSACK±êÊ¶µÄÊı¾İÒÑ¶ªÊ§ */
#define FLAG_DATA_LOST		0x80 /* SACK detected data lossage.		*/
/* ÔÚÂıËÙÂ·¾¶ÖĞ´¦ÀíµÄ */
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)

#define IsReno(tp) ((tp)->rx_opt.sack_ok == 0)
#define IsFack(tp) ((tp)->rx_opt.sack_ok & 2)
#define IsDSack(tp) ((tp)->rx_opt.sack_ok & 4)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)

/* Adapt the MSS value used to make delayed ack decision to the 
 * real world.
 */ 
/* ½ÓÊÕµ½±¨ÎÄºó£¬¹ÀËã·¢ËÍ·½µÄMSS */
static inline void tcp_measure_rcv_mss(struct tcp_sock *tp,
				       struct sk_buff *skb)
{
	unsigned int len, lss;

	lss = tp->ack.last_seg_size; 
	tp->ack.last_seg_size = 0; 

	/* skb->len may jitter because of SACKs, even if peer
	 * sends good full-sized frames.
	 */
	len = skb->len;
	if (len >= tp->ack.rcv_mss) {/* ½ÓÊÕµ½µÄ¶Î±¨ÎÄ´óÓÚ·¢ËÍ·½MSS£¬Ôò¸üĞÂMSS */
		tp->ack.rcv_mss = len;
	} else {
		/* Otherwise, we make more careful check taking into account,
		 * that SACKs block is variable.
		 *
		 * "len" is invariant segment length, including TCP header.
		 */
		len += skb->data - skb->h.raw;/* TCP±¨ÎÄ³¤¶È */
		if (len >= TCP_MIN_RCVMSS + sizeof(struct tcphdr) ||/* ´óÓÚ536 */
		    /* If PSH is not set, packet should be
		     * full sized, provided peer TCP is not badly broken.
		     * This observation (if it is correct 8)) allows
		     * to handle super-low mtu links fairly.
		     */
		    (len >= TCP_MIN_MSS + sizeof(struct tcphdr) &&/* ´óÓÚ×îĞ¡TCP¶Î³¤¶È88 */
		     !(tcp_flag_word(skb->h.th)&TCP_REMNANT))) {/* Ã»ÓĞPSH±êÖ¾£¬ËµÃ÷ÊÇÈ«³ß´ç¶Î */
			/* Subtract also invariant (if peer is RFC compliant),
			 * tcp header plus fixed timestamp option length.
			 * Resulting "len" is MSS free of SACK jitter.
			 */
			len -= tp->tcp_header_len;
			tp->ack.last_seg_size = len;
			if (len == lss) {/* ÓëÉÏ´Î½ÓÊÕµ½µÄ¶ÎÏàÍ¬£¬ËµÃ÷´ËMSSÖµÊÇ¿ÉĞÅµÄ£¬¸üĞÂMSS */
				tp->ack.rcv_mss = len;
				return;
			}
		}
		/* ÆäËûÇé¿öÏÂÔòÈÏÎª½ÓÊÕµ½Ğ¡°ü£¬ÉèÖÃTCP_ACK_PUSHED±êÖ¾¡£ĞÂ°æ±¾Ôö¼ÓÁËTCP_ACK_PUSHED2±êÖ¾ */
		tp->ack.pending |= TCP_ACK_PUSHED;
	}
}

static void tcp_incr_quickack(struct tcp_sock *tp)
{
	unsigned quickacks = tp->rcv_wnd/(2*tp->ack.rcv_mss);

	if (quickacks==0)
		quickacks=2;
	if (quickacks > tp->ack.quick)
		tp->ack.quick = min(quickacks, TCP_MAX_QUICKACKS);
}

/* ½øÈë¿ìËÙÈ·ÈÏÄ£Ê½ */
void tcp_enter_quickack_mode(struct tcp_sock *tp)
{
	/* ¸ù¾İ½ÓÊÕ´°¿ÚºÍMSS¼ÆËã¿ìËÙÈ·ÈÏ¶ÎÊı£¬³¬¹ıºó½øÈëÂıËÙÈ·ÈÏÄ£Ê½ */
	tcp_incr_quickack(tp);
	tp->ack.pingpong = 0;/* ¿ìËÙÈ·ÈÏÄ£Ê½ */
	/* ÑÓ³Ù40ºÁÃë¾Í±ØĞë·¢ËÍÈ·ÈÏ */
	tp->ack.ato = TCP_ATO_MIN;
}

/* Send ACKs quickly, if "quick" count is not exhausted
 * and the session is not interactive.
 */
/* µ±Ç°ÊÇ·ñÊÇ¿ìËÙÈ·ÈÏÄ£Ê½ */
static __inline__ int tcp_in_quickack_mode(struct tcp_sock *tp)
{
	return (tp->ack.quick && !tp->ack.pingpong);
}

/* Buffer size and advertised window tuning.
 *
 * 1. Tuning sk->sk_sndbuf, when connection enters established state.
 */

static void tcp_fixup_sndbuf(struct sock *sk)
{
	int sndmem = tcp_sk(sk)->rx_opt.mss_clamp + MAX_TCP_HEADER + 16 +
		     sizeof(struct sk_buff);

	if (sk->sk_sndbuf < 3 * sndmem)
		sk->sk_sndbuf = min(3 * sndmem, sysctl_tcp_wmem[2]);
}

/* 2. Tuning advertised window (window_clamp, rcv_ssthresh)
 *
 * All tcp_full_space() is split to two parts: "network" buffer, allocated
 * forward and advertised in receiver window (tp->rcv_wnd) and
 * "application buffer", required to isolate scheduling/application
 * latencies from network.
 * window_clamp is maximal advertised window. It can be less than
 * tcp_full_space(), in this case tcp_full_space() - window_clamp
 * is reserved for "application" buffer. The less window_clamp is
 * the smoother our behaviour from viewpoint of network, but the lower
 * throughput and the higher sensitivity of the connection to losses. 8)
 *
 * rcv_ssthresh is more strict window_clamp used at "slow start"
 * phase to predict further behaviour of this connection.
 * It is used for two goals:
 * - to enforce header prediction at sender, even when application
 *   requires some significant "application buffer". It is check #1.
 * - to prevent pruning of receive queue because of misprediction
 *   of receiver window. Check #2.
 *
 * The scheme does not work when sender sends good segments opening
 * window and then starts to feed us spagetti. But it should work
 * in common situations. Otherwise, we have to rely on queue collapsing.
 */

/* Slow part of check#2. */
static int __tcp_grow_window(struct sock *sk, struct tcp_sock *tp,
			     struct sk_buff *skb)
{
	/* Optimize this! */
	int truesize = tcp_win_from_space(skb->truesize)/2;
	int window = tcp_full_space(sk)/2;

	while (tp->rcv_ssthresh <= window) {
		if (truesize <= skb->len)
			return 2*tp->ack.rcv_mss;

		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

/* µ±½ÓÊÕµ½±¨ÎÄºó£¬Ôö¼Ó½ÓÊÕ´°¿Ú´óĞ¡·§Öµ */
static inline void tcp_grow_window(struct sock *sk, struct tcp_sock *tp,
				   struct sk_buff *skb)
{
	/* Check #1 */
	if (tp->rcv_ssthresh < tp->window_clamp &&/* µ±Ç°½ÓÊÕ´°¿Ú´óĞ¡·§ÖµĞ¡ÓÚ»¬¶¯´°¿Ú×î´óÖµ */
	    (int)tp->rcv_ssthresh < tcp_space(sk) &&/* Ò²Ğ¡ÓÚTCP¿ÉÓÃ½ÓÊÕ¿Õ¼ä */
	    !tcp_memory_pressure) {/* TCP»º´æÎ´¸æ¾¯ */
		int incr;

		/* Check #2. Increase window, if skb with such overhead
		 * will fit to rcvbuf in future.
		 */
		/* µİÔöµ±Ç°½ÓÊÕ´°¿Ú´óĞ¡µÄ·§Öµ */
		if (tcp_win_from_space(skb->truesize) <= skb->len)
			incr = 2*tp->advmss;
		else
			incr = __tcp_grow_window(sk, tp, skb);

		if (incr) {
			tp->rcv_ssthresh = min(tp->rcv_ssthresh + incr, tp->window_clamp);
			tp->ack.quick |= 1;
		}
	}
}

/* 3. Tuning rcvbuf, when connection enters established state. */

static void tcp_fixup_rcvbuf(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int rcvmem = tp->advmss + MAX_TCP_HEADER + 16 + sizeof(struct sk_buff);

	/* Try to select rcvbuf so that 4 mss-sized segments
	 * will fit to window and correspoding skbs will fit to our rcvbuf.
	 * (was 3; 4 is minimum to allow fast retransmit to work.)
	 */
	while (tcp_win_from_space(rcvmem) < tp->advmss)
		rcvmem += 128;
	if (sk->sk_rcvbuf < 4 * rcvmem)
		sk->sk_rcvbuf = min(4 * rcvmem, sysctl_tcp_rmem[2]);
}

/* 4. Try to fixup all. It is made iimediately after connection enters
 *    established state.
 */
static void tcp_init_buffer_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int maxwin;

	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		tcp_fixup_rcvbuf(sk);
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		tcp_fixup_sndbuf(sk);

	tp->rcvq_space.space = tp->rcv_wnd;

	maxwin = tcp_full_space(sk);

	if (tp->window_clamp >= maxwin) {
		tp->window_clamp = maxwin;

		if (sysctl_tcp_app_win && maxwin > 4 * tp->advmss)
			tp->window_clamp = max(maxwin -
					       (maxwin >> sysctl_tcp_app_win),
					       4 * tp->advmss);
	}

	/* Force reservation of one segment. */
	if (sysctl_tcp_app_win &&
	    tp->window_clamp > 2 * tp->advmss &&
	    tp->window_clamp + tp->advmss > maxwin)
		tp->window_clamp = max(2 * tp->advmss, maxwin - tp->advmss);

	tp->rcv_ssthresh = min(tp->rcv_ssthresh, tp->window_clamp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

static void init_bictcp(struct tcp_sock *tp)
{
	tp->bictcp.cnt = 0;

	tp->bictcp.last_max_cwnd = 0;
	tp->bictcp.last_cwnd = 0;
	tp->bictcp.last_stamp = 0;
}

/* 5. Recalculate window clamp after socket hit its memory bounds. */
static void tcp_clamp_window(struct sock *sk, struct tcp_sock *tp)
{
	struct sk_buff *skb;
	unsigned int app_win = tp->rcv_nxt - tp->copied_seq;
	int ofo_win = 0;

	tp->ack.quick = 0;

	skb_queue_walk(&tp->out_of_order_queue, skb) {
		ofo_win += skb->len;
	}

	/* If overcommit is due to out of order segments,
	 * do not clamp window. Try to expand rcvbuf instead.
	 */
	if (ofo_win) {
		if (sk->sk_rcvbuf < sysctl_tcp_rmem[2] &&
		    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK) &&
		    !tcp_memory_pressure &&
		    atomic_read(&tcp_memory_allocated) < sysctl_tcp_mem[0])
			sk->sk_rcvbuf = min(atomic_read(&sk->sk_rmem_alloc),
					    sysctl_tcp_rmem[2]);
	}
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf) {
		app_win += ofo_win;
		if (atomic_read(&sk->sk_rmem_alloc) >= 2 * sk->sk_rcvbuf)
			app_win >>= 1;
		if (app_win > tp->ack.rcv_mss)
			app_win -= tp->ack.rcv_mss;
		app_win = max(app_win, 2U*tp->advmss);

		if (!ofo_win)
			tp->window_clamp = min(tp->window_clamp, app_win);
		tp->rcv_ssthresh = min(tp->window_clamp, 2U*tp->advmss);
	}
}

/* Receiver "autotuning" code.
 *
 * The algorithm for RTT estimation w/o timestamps is based on
 * Dynamic Right-Sizing (DRS) by Wu Feng and Mike Fisk of LANL.
 * <http://www.lanl.gov/radiant/website/pubs/drs/lacsi2001.ps>
 *
 * More detail on this code can be found at
 * <http://www.psc.edu/~jheffner/senior_thesis.ps>,
 * though this reference is out of date.  A new paper
 * is pending.
 */
/**
 * ¸üĞÂRTT
 */
static void tcp_rcv_rtt_update(struct tcp_sock *tp, u32 sample, int win_dep)
{
	u32 new_sample = tp->rcv_rtt_est.rtt;/* new_sampleÎªÒÑ¾­µÃµ½RTT */
	long m = sample;/* sampleÊÇ±¾´Î²ÉÑùµÃµ½µÄRTT */

	if (m == 0)/* ²ÉÑùÖµ²»ÄÜÎª0£¬ÖÁÉÙÎª1¸ötick */
		m = 1;

	if (new_sample != 0) {
		/* If we sample in larger samples in the non-timestamp
		 * case, we could grossly overestimate the RTT especially
		 * with chatty applications or bulk transfer apps which
		 * are stalled on filesystem I/O.
		 *
		 * Also, since we are only going for a minimum in the
		 * non-timestamp case, we do not smoothe things out
		 * else with timestamps disabled convergance takes too
		 * long.
		 */
		if (!win_dep) {/* ½øĞĞRTTÎ¢µ÷£¬¹«Ê½Îªrtt=rtt+(sample-rtt)/8 */
			m -= (new_sample >> 3);
			new_sample += m;
		} else if (m < new_sample)/* ²»½øĞĞÎ¢µ÷£¬Èç¹ûRTTĞ¡ÓÚÔ­À´µÄÖµ£¬Ôò²ÉÓÃĞÂÖµ */
			new_sample = m << 3;
	} else {/* Èç¹ûÊÇµÚÒ»´Î²ÉÑù£¬ÔòÖ±½Ó±£´æ±¾´Î²ÉÑù½á¹û */
		/* No previous mesaure. */
		new_sample = m << 3;
	}

	if (tp->rcv_rtt_est.rtt != new_sample)/* ¸üĞÂRTT */
		tp->rcv_rtt_est.rtt = new_sample;
}

/* ÔÚÃ»ÓĞÊ±¼ä´ÁÑ¡ÏîµÄÇé¿öÏÂ£¬»òÕßµ±Êı¾İÁ÷Á¿·Ç³£Ğ¡µÄÇé¿öÏÂ£¬Ê¹ÓÃ´Ëº¯Êı²ÉÑùRTT */
static inline void tcp_rcv_rtt_measure(struct tcp_sock *tp)
{
	if (tp->rcv_rtt_est.time == 0)/* µÚÒ»´Î½ÓÊÕµ½Êı¾İ»òµÚÒ»´Î²ÉÓÃ±¾·½·¨£¬²»ÄÜ²ÉÑùRTT */
		goto new_measure;
	if (before(tp->rcv_nxt, tp->rcv_rtt_est.seq))/* ¼ì²éÊÇ·ñÒÑ¾­µ½´ï½øĞĞRTT²ÉÑùµÄÊ±¼äµã£¬¼´´ÓÉÏ´Î²ÉÑùºóÒ»¸ö½ÓÊÕ´°¿ÚÊıÁ¿µÄÊı¾İ */
		return;
	/* ²ÉÑùRTTÊı¾İ£¬µÚ¶ş¸ö²ÎÊıÎªRTTµÄ²ÉÑù£¬²ÎÊı1±íÊ¾²»¶ÔRTT²ÉÑù½øĞĞÎ¢µ÷ */
	tcp_rcv_rtt_update(tp,
			   jiffies - tp->rcv_rtt_est.time,
			   1);

new_measure:
	/* ¼ÇÂ¼±¾´Î²ÉÑùÊ±¼äºÍÏÂ´Î²ÉÑùµÄÊ±¼äµã */
	tp->rcv_rtt_est.seq = tp->rcv_nxt + tp->rcv_wnd;
	tp->rcv_rtt_est.time = tcp_time_stamp;
}

/* ÔÚÓĞÊ±¼ä´ÁµÄÇé¿öÏÂ²ÉÑùRTT */
static inline void tcp_rcv_rtt_measure_ts(struct tcp_sock *tp, struct sk_buff *skb)
{
	if (tp->rx_opt.rcv_tsecr &&/* TCP¶ÎÖĞÓĞÊ±¼ä´Á»ØÏÔ */
	    (TCP_SKB_CB(skb)->end_seq -
	     TCP_SKB_CB(skb)->seq >= tp->ack.rcv_mss))/* ±¨ÎÄ´óĞ¡´óÓÚµÈÓÚ½ÓÊÕ·½µÄMSS£¬±íÊ¾ÊÇÒ»¸öÈ«Êı¾İ¶Î */
		/* ¸üĞÂ²ÉÑùÊı¾İ£¬µÚ¶ş¸ö²ÎÊıÊÇµ±Ç°Ê±¼ä¼õÈ¥±¨ÎÄ»ØÏÔÊ±¼ä£¬µÚÈı¸ö²ÎÊı0±íÊ¾¶ÔRTT½øĞĞÎ¢µ÷ */
		tcp_rcv_rtt_update(tp, tcp_time_stamp - tp->rx_opt.rcv_tsecr, 0);
}

/*
 * This function should be called every time data is copied to user space.
 * It calculates the appropriate TCP receive buffer space.
 */
/* µ±Êı¾İ´Ó½ÓÊÕ»º´æ¸´ÖÆµ½ÓÃ»§¿Õ¼äºó£¬µ÷ÓÃ´Ëº¯Êıµ÷Õû½ÓÊÕ»º´æµÄ´óĞ¡ */
void tcp_rcv_space_adjust(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time;
	int space;
	
	if (tp->rcvq_space.time == 0)/* µÚÒ»´Îµ÷Õû£¬¼´½ÓÊÕµ½µÚÒ»¸öÓÃ»§Êı¾İ¶Î£¬²»±Øµ÷Õû½ÓÊÕ»º´æ£¬½ö½ö¼ÇÂ¼¸´ÖÆµ½ÓÃ»§¿Õ¼äµÄTCPĞòºÅºÍ×îºóÒ»´Îµ÷ÕûµÄÊ±¼ä */
		goto new_measure;
	
	time = tcp_time_stamp - tp->rcvq_space.time;
	if (time < (tp->rcv_rtt_est.rtt >> 3) ||/* ¾àÀëÉÏ´Îµ÷ÕûÊ±¼äĞ¡ÓÚRTT/8£¬»òÕß»¹Ã»ÓĞ¼ÆËã³öRTT£¬Ôò·µ»Ø */
	    tp->rcv_rtt_est.rtt == 0)
		return;

	/* 2±¶Íù·µÊ±¼äÄÚ½ÓÊÕ·½Ó¦ÓÃ³ÌĞò½ÓÊÕµÄÊı¾İÁ¿ */
	space = 2 * (tp->copied_seq - tp->rcvq_space.seq);

	/* ·¢ËÍ·½Ò»¸öÍù·µÊ±¼äÄÚ·¢ËÍµÄÊı¾İÁ¿ */
	space = max(tp->rcvq_space.space, space);

	if (tp->rcvq_space.space != space) {/* ĞèÒªµ÷Õû½ÓÊÕ´°¿Ú */
		int rcvmem;

		tp->rcvq_space.space = space;

		if (sysctl_tcp_moderate_rcvbuf) {/* ÔÊĞí×Ô¶¯µ÷½Ú½ÓÊÕ´°¿Ú´óĞ¡ */
			int new_clamp = space;

			/* Receive space grows, normalize in order to
			 * take into account packet headers and sk_buff
			 * structure overhead.
			 */
			space /= tp->advmss;
			if (!space)
				space = 1;
			rcvmem = (tp->advmss + MAX_TCP_HEADER +
				  16 + sizeof(struct sk_buff));
			while (tcp_win_from_space(rcvmem) < tp->advmss)
				rcvmem += 128;
			space *= rcvmem;
			space = min(space, sysctl_tcp_rmem[2]);
			if (space > sk->sk_rcvbuf) {
				sk->sk_rcvbuf = space;

				/* Make the window clamp follow along.  */
				tp->window_clamp = new_clamp;
			}
		}
	}
	
new_measure:
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tcp_time_stamp;
}

/* There is something which you must keep in mind when you analyze the
 * behavior of the tp->ato delayed ack timeout interval.  When a
 * connection starts up, we want to ack as quickly as possible.  The
 * problem is that "good" TCP's do slow start at the beginning of data
 * transmission.  The means that until we send the first few ACK's the
 * sender will sit on his end and only queue most of his data, because
 * he can only send snd_cwnd unacked packets at any given time.  For
 * each ACK we send, he increments snd_cwnd and transmits more of his
 * queue.  -DaveM
 */
/**
 * ÔÚ½ÓÊÕµ½Êı¾İºóµ÷ÓÃ£¬ÓÃÓÚ´¦Àí½ÓÊÕµ½Êı¾İÖ®ºóÓ¦¸Ã´¥·¢µÄÒ»Ğ©ÊÂ¼ş
 * ÈçÉèÖÃ·¢ËÍÈ·ÈÏ×´Ì¬£¬¹ÀËã¶Ô¶ËMSS£¬¼ÆËã½ÓÊÕ·½RTT£¬È·¶¨ÊÇ½øÈë¿ìËÙÈ·ÈÏ»¹ÊÇÂıËÙÈ·ÈÏ×´Ì¬£¬ÒÔ¼°¸üĞÂ×î½üÒ»´Î½ÓÊÕµ½µÄÊı¾İ°üÊ±¼ä
 */
static void tcp_event_data_recv(struct sock *sk, struct tcp_sock *tp, struct sk_buff *skb)
{
	u32 now;

	/* ½ÓÊÕµ½ĞÂµÄ¶Î£¬ÄÇÃ´¾ÍÓ¦µ±·¢ËÍACK£¬ÉèÖÃACk·¢ËÍ±êÖ¾ */
	tcp_schedule_ack(tp);

	/* ¹ÀËã¸üĞÂ¶Ô·½MSS */
	tcp_measure_rcv_mss(tp, skb);

	tcp_rcv_rtt_measure(tp);
	
	now = tcp_time_stamp;

	if (!tp->ack.ato) {/* Ã»ÓĞÉèÖÃÑÓÊ±È·ÈÏµÄÊ±¼ä£¬Ôò½øÈë¿ìËÙÈ·ÈÏÄ£Ê½ */
		/* The _first_ data packet received, initialize
		 * delayed ACK engine.
		 */
		tcp_incr_quickack(tp);
		tp->ack.ato = TCP_ATO_MIN;
	} else {/* ·ñÔò¸ù¾İ±¾´ÎÓëÉÏ´Î½ÓÊÕµ½µÄÊ±¼ä¼ä¸ô£¬ÖØĞÂÉèÖÃÑÓ³ÙACKµÄ³¬Ê±Ê±¼ä»òÕß½øÈë¿ìËÙÈ·ÈÏÄ£Ê½ */
		int m = now - tp->ack.lrcvtime;

		if (m <= TCP_ATO_MIN/2) {
			/* The fastest case is the first. */
			tp->ack.ato = (tp->ack.ato>>1) + TCP_ATO_MIN/2;
		} else if (m < tp->ack.ato) {
			tp->ack.ato = (tp->ack.ato>>1) + m;
			if (tp->ack.ato > tp->rto)
				tp->ack.ato = tp->rto;
		} else if (m > tp->rto) {
			/* Too long gap. Apparently sender falled to
			 * restart window, so that we send ACKs quickly.
			 */
			tcp_incr_quickack(tp);
			sk_stream_mem_reclaim(sk);
		}
	}
	/* ¸üĞÂ×î½ü½ÓÊÕÊı¾İ°üµÄÊ±¼ä */
	tp->ack.lrcvtime = now;

	/* ÔÚÖ§³ÖÏÔÊ½ÓµÈûÍ¨ÖªµÄÇé¿öÏÂ£¬È·¶¨½ÓÊÕµ½µÄ¶ÎÊÇ·ñ¾­ÀúÁËÓµÈû */
	TCP_ECN_check_ce(tp, skb);

	if (skb->len >= 128)/* Ôö¼Óµ±Ç°½ÓÊÕ´°¿Ú´óĞ¡µÄ·§Öµ */
		tcp_grow_window(sk, tp, skb);
}

/* When starting a new connection, pin down the current choice of 
 * congestion algorithm.
 */
void tcp_ca_init(struct tcp_sock *tp)
{
	if (sysctl_tcp_westwood) 
		tp->adv_cong = TCP_WESTWOOD;
	else if (sysctl_tcp_bic)
		tp->adv_cong = TCP_BIC;
	else if (sysctl_tcp_vegas_cong_avoid) {
		tp->adv_cong = TCP_VEGAS;
		tp->vegas.baseRTT = 0x7fffffff;
		tcp_vegas_enable(tp);
	} 
}

/* Do RTT sampling needed for Vegas.
 * Basically we:
 *   o min-filter RTT samples from within an RTT to get the current
 *     propagation delay + queuing delay (we are min-filtering to try to
 *     avoid the effects of delayed ACKs)
 *   o min-filter RTT samples from a much longer window (forever for now)
 *     to find the propagation delay (baseRTT)
 */
static inline void vegas_rtt_calc(struct tcp_sock *tp, __u32 rtt)
{
	__u32 vrtt = rtt + 1; /* Never allow zero rtt or baseRTT */

	/* Filter to find propagation delay: */
	if (vrtt < tp->vegas.baseRTT) 
		tp->vegas.baseRTT = vrtt;

	/* Find the min RTT during the last RTT to find
	 * the current prop. delay + queuing delay:
	 */
	tp->vegas.minRTT = min(tp->vegas.minRTT, vrtt);
	tp->vegas.cntRTT++;
}

/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
/* ¹ÀËãRTT£¬È»ºóÔÙÉèÖÃÖØ´«³¬Ê±Ê±¼ä */
static void tcp_rtt_estimator(struct tcp_sock *tp, __u32 mrtt)
{
	long m = mrtt; /* RTT */

	if (tcp_vegas_enabled(tp))
		vegas_rtt_calc(tp, mrtt);

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible 
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be incresed fastly, decrease too fastly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if(m == 0)/* ¹ÀËãRTTµÄ²ÉÑù²»ÄÜÎª0 */
		m = 1;
	if (tp->srtt != 0) {/* Í¨¹ı²ÉÑùÖµÓëÏÖÓĞRTT¹ÀËãĞÂµÄRTT */
		/* ¸ù¾İRFC2988µÄËã·¨£¬SRTT=(1-1/8)*SRTT+1/8*RTTÀ´»ñµÃRTTµÄÆ½»¬Öµ */
		m -= (tp->srtt >> 3);	/* m is now error in rtt est */
		tp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		/* °´mdev=3/4+1/4(|SRTT-RTT²ÉÑù|)À´»ñÈ¡mdev */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (tp->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (tp->mdev >> 2);   /* similar update on mdev */
		}
		tp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		/* ¸üĞÂRTT¶¶¶¯µÄ×î´ó·¶Î§ºÍÆ½»¬µÄRTTÆ½¾ùÆ«²î */
		if (tp->mdev > tp->mdev_max) {
			tp->mdev_max = tp->mdev;
			if (tp->mdev_max > tp->rttvar)
				tp->rttvar = tp->mdev_max;
		}
		/* ¼ì²âÊÇ·ñÓ¦¸Ã¸´Î»mdev_max£¬¼´ÉÏ´Î¸´Î»ºó½ÓÊÕ·½ÊÇ·ñÒÑ¾­½ÓÊÕÍêÒ»¸ö½ÓÊÕ´°¿ÚµÄÖµ */
		if (after(tp->snd_una, tp->rtt_seq)) {
			if (tp->mdev_max < tp->rttvar)
				tp->rttvar -= (tp->rttvar-tp->mdev_max)>>2;
			tp->rtt_seq = tp->snd_nxt;
			tp->mdev_max = TCP_RTO_MIN;
		}
	} else {/* µÚÒ»¸öRTTµÄ²âÁ¿ */
		/* no previous measure. */
		tp->srtt = m<<3;	/* take the measured time to be rtt */
		tp->mdev = m<<1;	/* make sure rto = 3*rtt */
		tp->mdev_max = tp->rttvar = max(tp->mdev, TCP_RTO_MIN);
		tp->rtt_seq = tp->snd_nxt;
	}

	tcp_westwood_update_rtt(tp, tp->srtt >> 3);
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
/* ¸ù¾İ×î½üÒ»´ÎµÃµ½µÄRTTÀ´¼ÆËãÖØ´«³¬Ê±Ê±¼ä */
static inline void tcp_set_rto(struct tcp_sock *tp)
{
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some curcumstances.
	 */
	tp->rto = (tp->srtt >> 3) + tp->rttvar;

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exaclty, which we pretend to do.
	 */
}

/* NOTE: clamping at TCP_RTO_MIN is not required, current algo
 * guarantees that rto is higher.
 */
static inline void tcp_bound_rto(struct tcp_sock *tp)
{
	if (tp->rto > TCP_RTO_MAX)
		tp->rto = TCP_RTO_MAX;
}

/* Save metrics learned by this TCP session.
   This function is called only, when TCP finishes successfully
   i.e. when it enters TIME-WAIT or goes from LAST-ACK to CLOSE.
 */
void tcp_update_metrics(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);

	if (sysctl_tcp_nometrics_save)
		return;

	dst_confirm(dst);

	if (dst && (dst->flags&DST_HOST)) {
		int m;

		if (tp->backoff || !tp->srtt) {
			/* This session failed to estimate rtt. Why?
			 * Probably, no packets returned in time.
			 * Reset our results.
			 */
			if (!(dst_metric_locked(dst, RTAX_RTT)))
				dst->metrics[RTAX_RTT-1] = 0;
			return;
		}

		m = dst_metric(dst, RTAX_RTT) - tp->srtt;

		/* If newly calculated rtt larger than stored one,
		 * store new one. Otherwise, use EWMA. Remember,
		 * rtt overestimation is always better than underestimation.
		 */
		if (!(dst_metric_locked(dst, RTAX_RTT))) {
			if (m <= 0)
				dst->metrics[RTAX_RTT-1] = tp->srtt;
			else
				dst->metrics[RTAX_RTT-1] -= (m>>3);
		}

		if (!(dst_metric_locked(dst, RTAX_RTTVAR))) {
			if (m < 0)
				m = -m;

			/* Scale deviation to rttvar fixed point */
			m >>= 1;
			if (m < tp->mdev)
				m = tp->mdev;

			if (m >= dst_metric(dst, RTAX_RTTVAR))
				dst->metrics[RTAX_RTTVAR-1] = m;
			else
				dst->metrics[RTAX_RTTVAR-1] -=
					(dst->metrics[RTAX_RTTVAR-1] - m)>>2;
		}

		if (tp->snd_ssthresh >= 0xFFFF) {
			/* Slow start still did not finish. */
			if (dst_metric(dst, RTAX_SSTHRESH) &&
			    !dst_metric_locked(dst, RTAX_SSTHRESH) &&
			    (tp->snd_cwnd >> 1) > dst_metric(dst, RTAX_SSTHRESH))
				dst->metrics[RTAX_SSTHRESH-1] = tp->snd_cwnd >> 1;
			if (!dst_metric_locked(dst, RTAX_CWND) &&
			    tp->snd_cwnd > dst_metric(dst, RTAX_CWND))
				dst->metrics[RTAX_CWND-1] = tp->snd_cwnd;
		} else if (tp->snd_cwnd > tp->snd_ssthresh &&
			   tp->ca_state == TCP_CA_Open) {
			/* Cong. avoidance phase, cwnd is reliable. */
			if (!dst_metric_locked(dst, RTAX_SSTHRESH))
				dst->metrics[RTAX_SSTHRESH-1] =
					max(tp->snd_cwnd >> 1, tp->snd_ssthresh);
			if (!dst_metric_locked(dst, RTAX_CWND))
				dst->metrics[RTAX_CWND-1] = (dst->metrics[RTAX_CWND-1] + tp->snd_cwnd) >> 1;
		} else {
			/* Else slow start did not finish, cwnd is non-sense,
			   ssthresh may be also invalid.
			 */
			if (!dst_metric_locked(dst, RTAX_CWND))
				dst->metrics[RTAX_CWND-1] = (dst->metrics[RTAX_CWND-1] + tp->snd_ssthresh) >> 1;
			if (dst->metrics[RTAX_SSTHRESH-1] &&
			    !dst_metric_locked(dst, RTAX_SSTHRESH) &&
			    tp->snd_ssthresh > dst->metrics[RTAX_SSTHRESH-1])
				dst->metrics[RTAX_SSTHRESH-1] = tp->snd_ssthresh;
		}

		if (!dst_metric_locked(dst, RTAX_REORDERING)) {
			if (dst->metrics[RTAX_REORDERING-1] < tp->reordering &&
			    tp->reordering != sysctl_tcp_reordering)
				dst->metrics[RTAX_REORDERING-1] = tp->reordering;
		}
	}
}

/* Numbers are taken from RFC2414.  */
__u32 tcp_init_cwnd(struct tcp_sock *tp, struct dst_entry *dst)
{
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

	if (!cwnd) {
		if (tp->mss_cache_std > 1460)
			cwnd = 2;
		else
			cwnd = (tp->mss_cache_std > 1095) ? 3 : 4;
	}
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}

/* Initialize metrics on socket. */

static void tcp_init_metrics(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);

	if (dst == NULL)
		goto reset;

	dst_confirm(dst);

	if (dst_metric_locked(dst, RTAX_CWND))
		tp->snd_cwnd_clamp = dst_metric(dst, RTAX_CWND);
	if (dst_metric(dst, RTAX_SSTHRESH)) {
		tp->snd_ssthresh = dst_metric(dst, RTAX_SSTHRESH);
		if (tp->snd_ssthresh > tp->snd_cwnd_clamp)
			tp->snd_ssthresh = tp->snd_cwnd_clamp;
	}
	if (dst_metric(dst, RTAX_REORDERING) &&
	    tp->reordering != dst_metric(dst, RTAX_REORDERING)) {
		tp->rx_opt.sack_ok &= ~2;
		tp->reordering = dst_metric(dst, RTAX_REORDERING);
	}

	if (dst_metric(dst, RTAX_RTT) == 0)
		goto reset;

	if (!tp->srtt && dst_metric(dst, RTAX_RTT) < (TCP_TIMEOUT_INIT << 3))
		goto reset;

	/* Initial rtt is determined from SYN,SYN-ACK.
	 * The segment is small and rtt may appear much
	 * less than real one. Use per-dst memory
	 * to make it more realistic.
	 *
	 * A bit of theory. RTT is time passed after "normal" sized packet
	 * is sent until it is ACKed. In normal curcumstances sending small
	 * packets force peer to delay ACKs and calculation is correct too.
	 * The algorithm is adaptive and, provided we follow specs, it
	 * NEVER underestimate RTT. BUT! If peer tries to make some clever
	 * tricks sort of "quick acks" for time long enough to decrease RTT
	 * to low value, and then abruptly stops to do it and starts to delay
	 * ACKs, wait for troubles.
	 */
	if (dst_metric(dst, RTAX_RTT) > tp->srtt) {
		tp->srtt = dst_metric(dst, RTAX_RTT);
		tp->rtt_seq = tp->snd_nxt;
	}
	if (dst_metric(dst, RTAX_RTTVAR) > tp->mdev) {
		tp->mdev = dst_metric(dst, RTAX_RTTVAR);
		tp->mdev_max = tp->rttvar = max(tp->mdev, TCP_RTO_MIN);
	}
	tcp_set_rto(tp);
	tcp_bound_rto(tp);
	if (tp->rto < TCP_TIMEOUT_INIT && !tp->rx_opt.saw_tstamp)
		goto reset;
	tp->snd_cwnd = tcp_init_cwnd(tp, dst);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	return;

reset:
	/* Play conservative. If timestamps are not
	 * supported, TCP will fail to recalculate correct
	 * rtt, if initial rto is too small. FORGET ALL AND RESET!
	 */
	if (!tp->rx_opt.saw_tstamp && tp->srtt) {
		tp->srtt = 0;
		tp->mdev = tp->mdev_max = tp->rttvar = TCP_TIMEOUT_INIT;
		tp->rto = TCP_TIMEOUT_INIT;
	}
}

static void tcp_update_reordering(struct tcp_sock *tp, int metric, int ts)
{
	if (metric > tp->reordering) {
		tp->reordering = min(TCP_MAX_REORDERING, metric);

		/* This exciting event is worth to be remembered. 8) */
		if (ts)
			NET_INC_STATS_BH(LINUX_MIB_TCPTSREORDER);
		else if (IsReno(tp))
			NET_INC_STATS_BH(LINUX_MIB_TCPRENOREORDER);
		else if (IsFack(tp))
			NET_INC_STATS_BH(LINUX_MIB_TCPFACKREORDER);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPSACKREORDER);
#if FASTRETRANS_DEBUG > 1
		printk(KERN_DEBUG "Disorder%d %d %u f%u s%u rr%d\n",
		       tp->rx_opt.sack_ok, tp->ca_state,
		       tp->reordering,
		       tp->fackets_out,
		       tp->sacked_out,
		       tp->undo_marker ? tp->undo_retrans : 0);
#endif
		/* Disable FACK yet. */
		tp->rx_opt.sack_ok &= ~2;
	}
}

/* This procedure tags the retransmission queue when SACKs arrive.
 *
 * We have three tag bits: SACKED(S), RETRANS(R) and LOST(L).
 * Packets in queue with these bits set are counted in variables
 * sacked_out, retrans_out and lost_out, correspondingly.
 *
 * Valid combinations are:
 * Tag  InFlight	Description
 * 0	1		- orig segment is in flight.
 * S	0		- nothing flies, orig reached receiver.
 * L	0		- nothing flies, orig lost by net.
 * R	2		- both orig and retransmit are in flight.
 * L|R	1		- orig is lost, retransmit is in flight.
 * S|R  1		- orig reached receiver, retrans is still in flight.
 * (L|S|R is logically valid, it could occur when L|R is sacked,
 *  but it is equivalent to plain S and code short-curcuits it to S.
 *  L|S is logically invalid, it would mean -1 packet in flight 8))
 *
 * These 6 states form finite state machine, controlled by the following events:
 * 1. New ACK (+SACK) arrives. (tcp_sacktag_write_queue())
 * 2. Retransmission. (tcp_retransmit_skb(), tcp_xmit_retransmit_queue())
 * 3. Loss detection event of one of three flavors:
 *	A. Scoreboard estimator decided the packet is lost.
 *	   A'. Reno "three dupacks" marks head of queue lost.
 *	   A''. Its FACK modfication, head until snd.fack is lost.
 *	B. SACK arrives sacking data transmitted after never retransmitted
 *	   hole was sent out.
 *	C. SACK arrives sacking SND.NXT at the moment, when the
 *	   segment was retransmitted.
 * 4. D-SACK added new rule: D-SACK changes any tag to S.
 *
 * It is pleasant to note, that state diagram turns out to be commutative,
 * so that we are allowed not to be bothered by order of our actions,
 * when multiple events arrive simultaneously. (see the function below).
 *
 * Reordering detection.
 * --------------------
 * Reordering metric is maximal distance, which a packet can be displaced
 * in packet stream. With SACKs we can estimate it:
 *
 * 1. SACK fills old hole and the corresponding segment was not
 *    ever retransmitted -> reordering. Alas, we cannot use it
 *    when segment was retransmitted.
 * 2. The last flaw is solved with D-SACK. D-SACK arrives
 *    for retransmitted and already SACKed segment -> reordering..
 * Both of these heuristics are not used in Loss state, when we cannot
 * account for retransmits accurately.
 */
/* µ±½ÓÊÕµ½ACKºó£¬¸ù¾İSACKÑ¡Ïî±ê¼ÇÖØ´«¶ÓÁĞÖĞSKBµÄ¼Ç·Ö´¦ÓÚ×´Ì¬ */
static int
tcp_sacktag_write_queue(struct sock *sk, struct sk_buff *ack_skb, u32 prior_snd_una)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* µÃµ½TCPÑ¡ÏîÖĞSACKEDÑ¡ÏîµÄÆ«ÒÆ£¬ÒÔ¼°SACKÑ¡ÏîµÄ¸öÊı */
	unsigned char *ptr = ack_skb->h.raw + TCP_SKB_CB(ack_skb)->sacked;
	struct tcp_sack_block *sp = (struct tcp_sack_block *)(ptr+2);
	int num_sacks = (ptr[1] - TCPOLEN_SACK_BASE)>>3;
	int reord = tp->packets_out;
	int prior_fackets;
	/* ÓÃÓÚ¼ÆËã¿ÉÄÜ¶ªÊ§µÄ¶ÎµÄ×î´óĞòºÅ */
	u32 lost_retrans = 0;
	int flag = 0;
	int i;

	/* So, SACKs for already sent large segments will be lost.
	 * Not good, but alternative is to resegment the queue. */
	if (sk->sk_route_caps & NETIF_F_TSO) {
		sk->sk_route_caps &= ~NETIF_F_TSO;
		sk->sk_no_largesend = 1;
		tp->mss_cache = tp->mss_cache_std;
	}

	if (!tp->sacked_out)
		tp->fackets_out = 0;
	prior_fackets = tp->fackets_out;

	for (i=0; i<num_sacks; i++, sp++) {/* ´ÓÑ¡ÏîÖĞ¶ÁÈ¡sack¿é */
		struct sk_buff *skb;
		__u32 start_seq = ntohl(sp->start_seq);
		__u32 end_seq = ntohl(sp->end_seq);
		int fack_count = 0;
		int dup_sack = 0;

		/* Check for D-SACK. */
		if (i == 0) {/* ¼ì²âµÚÒ»¸ö¿éÊÇ²»ÊÇDSACK */
			u32 ack = TCP_SKB_CB(ack_skb)->ack_seq;

			if (before(start_seq, ack)) {/* µÚÒ»¸öSACK¿éĞ¡ÓÚÒÑÈ·ÈÏ¿éºÅ£¬ËµÃ÷ÊÇDSACK */
				dup_sack = 1;
				tp->rx_opt.sack_ok |= 4;
				NET_INC_STATS_BH(LINUX_MIB_TCPDSACKRECV);
			} else if (num_sacks > 1 &&/* Èç¹ûµÚÒ»¸ö¿é´óÓÚÒÑÈ·ÈÏĞòºÅ£¬Ôò±È½ÏµÚÒ»¸öSACK¿éºÍµÚ¶ş¸öSACK¿é£¬Èç¹ûµÚÒ»¸öSACK¿é°üº¬ÔÚµÚ¶ş¸öSACKÖĞ£¬ÔòÒ²ÊÇDSACK¿é */
				   !after(end_seq, ntohl(sp[1].end_seq)) &&
				   !before(start_seq, ntohl(sp[1].start_seq))) {
				dup_sack = 1;
				tp->rx_opt.sack_ok |= 4;
				NET_INC_STATS_BH(LINUX_MIB_TCPDSACKOFORECV);
			}

			/* D-SACK for already forgotten data...
			 * Do dumb counting. */
			/**
			 * undo_markerÊÇ³¬Ê±ÖØ´«»òÕßFRTOÊ±¼ÇÂ¼µÄUNA£¬prior_snd_unaÊÇ±¾´ÎACKÖ®Ç°µÄUNA
			 * Èç¹ûDSACKÔÚÕâÖ®¼ä£¬ËµÃ÷ÊÇ³¬Ê±ÖØ´«»òFRTOÖ®ºó½øĞĞµÄÖØ´«
			 */
			if (dup_sack &&
			    !after(end_seq, prior_snd_una) &&
			    after(end_seq, tp->undo_marker))
				tp->undo_retrans--;/* ½ÓÊÕ·½ÖØ¸´½ÓÊÕÁË£¬¼õÉÙundo_retrans£¬ËµÃ÷ÍøÂçÓµÈû¿ÉÄÜ²»ÊÇºÜÑÏÖØ£¬¼õµ½0Ê±£¬Ó¦µ±»Ö¸´µ½Õı³£×´Ì¬ */

			/* Eliminate too old ACKs, but take into
			 * account more or less fresh ones, they can
			 * contain valid SACK info.
			 */
			/* ACKÊÇÒ»¸ö´°¿ÚÒÔÇ°µÄ£¬ËµÃ÷ACKÌ«ÀÏÁË£¬²»ĞèÒªÔÙ´¦Àí */
			if (before(ack, prior_snd_una - tp->max_window))
				return 0;
		}

		/* Event "B" in the comment above. */
		if (after(end_seq, tp->high_seq))/* SACK³¬¹ıÁËÖØ´«¶ÓÁĞµÄÎ²²¿£¬ËµÃ÷ÓĞ¶Î¶ªÊ§£¬Ôö¼ÓLOST±êÖ¾ */
			flag |= FLAG_DATA_LOST;

		sk_stream_for_retrans_queue(skb, sk) {/* ±éÀúÖØ´«¶ÓÁĞ */
			u8 sacked = TCP_SKB_CB(skb)->sacked;
			int in_sack;

			/* The retransmission queue is always in order, so
			 * we can short-circuit the walk early.
			 */
			/* ÖØ´«¶ÓÁĞÊÇÅÅĞòµÄ£¬Òò´ËÈç¹ûµ±Ç°SKBĞòºÅ´óÓÚSACKÓÒ¶ËĞòºÅÊ±£¬Ôò²»±Ø¼ÌĞø´¦Àí */
			if(!before(TCP_SKB_CB(skb)->seq, end_seq))
				break;

			fack_count += tcp_skb_pcount(skb);

			/* ¼ì²âµ±Ç°¶ÎÊÇ·ñÍêÈ«ÔÚSACKÖĞ£¬Èç¹ûÊÇ£¬ÔòËµÃ÷¸Ã¶ÎÒÑ¾­ÍêÈ«±»½ÓÊÕµ½ */
			in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) &&
				!before(end_seq, TCP_SKB_CB(skb)->end_seq);

			/* Account D-SACK for retransmitted packet. */
			if ((dup_sack && in_sack) &&/* ÖØ¸´½ÓÊÕ£¬¶ÎÍêÈ«ÔÚSACKÖ®ÄÚ */
			    (sacked & TCPCB_RETRANS) &&/* ÖØ´«¶Î */
			    after(TCP_SKB_CB(skb)->end_seq, tp->undo_marker))/* ¶ÎÎ»ÓÚÉÏ´ÎÓµÈûĞòºÅÖ®ºó */
				tp->undo_retrans--;/* ËµÃ÷½ÓÊÕ·½ÖØ¸´½ÓÊÕÁË¸ÃTCP¶Î£¬Òò´Ë¼õÉÙundo_retrans */

			/* The frame is ACKed. */
			/* ¸Ã¶ÎÒÑ¾­È·ÈÏ¹ı£¬ÔòÌø¹ı */
			if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una)) {
				if (sacked&TCPCB_RETRANS) {/* ÒÑ¾­È·ÈÏ¹ıµÄ¶ÎÖØ´«¹ı */
					if ((dup_sack && in_sack) &&/* µ±Ç°SACK¿éÈ·ÈÏÁË¸Ã¶Î */
					    (sacked&TCPCB_SACKED_ACKED))
						reord = min(fack_count, reord);
				} else {
					/* If it was in a hole, we detected reordering. */
					if (fack_count < prior_fackets &&
					    !(sacked&TCPCB_SACKED_ACKED))
						reord = min(fack_count, reord);
				}

				/* Nothing to do; acked frame is about to be dropped. */
				continue;
			}

			/* ¿ÉÄÜ¶ªÊ§µÄ¶ÎµÄ·¶Î§ÎªÖØ´«¶ÓÁĞÍ·ºÍSACK¿éÖĞ×îºóÒ»¸öÖØ´«¶ÎÖ®¼ä */
			if ((sacked&TCPCB_SACKED_RETRANS) &&
			    after(end_seq, TCP_SKB_CB(skb)->ack_seq) &&
			    (!lost_retrans || after(end_seq, lost_retrans)))
				lost_retrans = end_seq;

			/* ²»´¦ÀíÎ»ÓÚACK¿éÖ®¼äµÄ¶Î */
			if (!in_sack)
				continue;

			if (!(sacked&TCPCB_SACKED_ACKED)) {
				if (sacked & TCPCB_SACKED_RETRANS) {/* SACKÈ·ÈÏµÄÊÇÈÏÎª¶ªÊ§²¢¾­¹ıÖØ´«µÄ¶Î£¬ËµÃ÷²¢Ã»ÓĞ¶ªÊ§ */
					/* If the segment is not tagged as lost,
					 * we do not clear RETRANS, believing
					 * that retransmission is still in flight.
					 */
					if (sacked & TCPCB_LOST) {
						/* È¥³ıLOST±êÖ¾ */
						TCP_SKB_CB(skb)->sacked &= ~(TCPCB_LOST|TCPCB_SACKED_RETRANS);
						tp->lost_out -= tcp_skb_pcount(skb);
						tp->retrans_out -= tcp_skb_pcount(skb);
					}
				} else {/* È·ÈÏµÄÊÇÎ´ÖØ´«¹ıµÄ¶Î */
					/* New sack for not retransmitted frame,
					 * which was in hole. It is reordering.
					 */
					if (!(sacked & TCPCB_RETRANS) &&
					    fack_count < prior_fackets)
						reord = min(fack_count, reord);

					if (sacked & TCPCB_LOST) {/* Èç¹ûÊÇLOST¶Î£¬ÔòÇå³ıLOST±êÖ¾ */
						TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
						tp->lost_out -= tcp_skb_pcount(skb);
					}
				}

				/* ÓÉÓÚ¸Ã´¦ÓÚSACKÖĞ£¬Òò´ËÌí¼ÓÏà¹Ø±ê¼Ç£¬ÀÛ¼Æsacked_out */
				TCP_SKB_CB(skb)->sacked |= TCPCB_SACKED_ACKED;
				flag |= FLAG_DATA_SACKED;
				tp->sacked_out += tcp_skb_pcount(skb);

				if (fack_count > tp->fackets_out)
					tp->fackets_out = fack_count;
			} else {
				if (dup_sack && (sacked&TCPCB_RETRANS))
					reord = min(fack_count, reord);
			}

			/* D-SACK. We can detect redundant retransmission
			 * in S|R and plain R frames and clear it.
			 * undo_retrans is decreased above, L|R frames
			 * are accounted above as well.
			 */
			if (dup_sack &&/* ¶ÔÖØ´«°üÀ´Ëµ£¬ÊÕµ½SACKËµÃ÷ÖØ´«ÊÇ¶àÓàµÄ */
			    (TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_RETRANS)) {
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= tcp_skb_pcount(skb);
			}
		}
	}

	/* Check for lost retransmit. This superb idea is
	 * borrowed from "ratehalving". Event "C".
	 * Later note: FACK people cheated me again 8),
	 * we have to account for reordering! Ugly,
	 * but should help.
	 */
	if (lost_retrans && tp->ca_state == TCP_CA_Recovery) {/* ÓµÈû»ú×´Ì¬´¦ÓÚRecovery×´Ì¬£¬²¢ÇÒ´æÔÚ¿ÉÄÜ¶ªÊ§µÄ¶Î */
		struct sk_buff *skb;

		sk_stream_for_retrans_queue(skb, sk) {/* ±éÀúËùÓĞÖØ´«¶ÓÁĞÖĞµÄ¶Î */
			/* Ö»´¦Àí½éÓÚUNAºÍlost_retransÖ®¼äµÄ¶Î */
			if (after(TCP_SKB_CB(skb)->seq, lost_retrans))
				break;
			if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
				continue;
			if ((TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_RETRANS) &&
			    after(lost_retrans, TCP_SKB_CB(skb)->ack_seq) &&
			    (IsFack(tp) ||
			     !before(lost_retrans,
				     TCP_SKB_CB(skb)->ack_seq + tp->reordering *
				     tp->mss_cache_std))) {
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= tcp_skb_pcount(skb);

				if (!(TCP_SKB_CB(skb)->sacked&(TCPCB_LOST|TCPCB_SACKED_ACKED))) {
					tp->lost_out += tcp_skb_pcount(skb);
					TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
					flag |= FLAG_DATA_SACKED;
					NET_INC_STATS_BH(LINUX_MIB_TCPLOSTRETRANSMIT);
				}
			}
		}
	}

	/* ¼ÆËãÒÑ¾­Àë¿ªÖ÷»úµ«Î´±»È·ÈÏµÄ¶ÎÊı£¬°üÀ¨Í¨¹ıSACKÈ·ÈÏµÄ¶ÎºÍÈ·ÈÏ¶ªÊ§µÄ¶Î */
	tp->left_out = tp->sacked_out + tp->lost_out;

	/* ¸üĞÂÅÅĞò·§Öµ */
	if ((reord < tp->fackets_out) && tp->ca_state != TCP_CA_Loss)
		tcp_update_reordering(tp, ((tp->fackets_out + 1) - reord), 0);

#if FASTRETRANS_DEBUG > 0
	BUG_TRAP((int)tp->sacked_out >= 0);
	BUG_TRAP((int)tp->lost_out >= 0);
	BUG_TRAP((int)tp->retrans_out >= 0);
	BUG_TRAP((int)tcp_packets_in_flight(tp) >= 0);
#endif
	return flag;
}

/* RTO occurred, but do not yet enter loss state. Instead, transmit two new
 * segments to see from the next ACKs whether any data was really missing.
 * If the RTO was spurious, new ACKs should arrive.
 */
/**
 * µ±·¢ËÍ¶Î³¬Ê±ºó£¬²»Ö±½Ó½øÈëLOSS×´Ì¬£¬¶øÊÇ½øÈëFRTO×´Ì¬¡£
 * ¶øÊÇ´«ËÍÁ½¸ö¶Îºó¸ù¾İ½ÓÊÕµ½µÄACKÀ´È·ÈÏÊı¾İÊÇ·ñ¶ªÊ§¡£±ÜÃâĞé¼ÙµÄ³¬Ê±¡£
 */
void tcp_enter_frto(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	tp->frto_counter = 1;/* Îª1±íÊ¾¸Õ½øÈëFRTO */

	if (tp->ca_state <= TCP_CA_Disorder ||
            tp->snd_una == tp->high_seq ||
            (tp->ca_state == TCP_CA_Loss && !tp->retransmits)) {/* ½øÈëFRTOÊ±£¬ÍøÂç±È½ÏÁ÷³© */
		tp->prior_ssthresh = tcp_current_ssthresh(tp);/* ±£´æÂıÆô¶¯·§Öµ */
		if (!tcp_westwood_ssthresh(tp))
			tp->snd_ssthresh = tcp_recalc_ssthresh(tp);
	}

	/* Have to clear retransmission markers here to keep the bookkeeping
	 * in shape, even though we are not yet in Loss state.
	 * If something was really lost, it is eventually caught up
	 * in tcp_enter_frto_loss.
	 */
	/* Çå³ıÓëÖØ´«Ïà¹ØµÄ±ê¼Ç£¬Í¬Ê±¼ÇÂ¼µ±Ç°NUA£¬ÒÔ±ã»Ö¸´ */
	tp->retrans_out = 0;
	tp->undo_marker = tp->snd_una;
	tp->undo_retrans = 0;

	sk_stream_for_retrans_queue(skb, sk) {
		TCP_SKB_CB(skb)->sacked &= ~TCPCB_RETRANS;
	}
	/* Ë¢ĞÂÎ´È·ÈÏµÄTCP¶ÎÊıÁ¿ */
	tcp_sync_left_out(tp);

	/* ¼ÇÂ¼ÏÂFRTO×´Ì¬Ê±µÄnxt */
	tcp_set_ca_state(tp, TCP_CA_Open);
	tp->frto_highmark = tp->snd_nxt;
}

/* Enter Loss state after F-RTO was applied. Dupack arrived after RTO,
 * which indicates that we should follow the traditional RTO recovery,
 * i.e. mark everything lost and do go-back-N retransmission.
 */
/**
 * ÔÚFRTO½×¶Î£¬Èç¹û½ÓÊÕµ½ACK·¢ÏÖÈ·ÊµÊÇ²úÉúÁË´«ËÍ³¬Ê±£¬Ôòµ÷ÓÃ´Ëº¯Êı½øÈëÓµÈû»Ö¸´½×¶Î£¬¿ªÊ¼ÂıÆô¶¯¹ı³Ì¡£
 */
static void tcp_enter_frto_loss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int cnt = 0;

	/* ½øÈëLoss×´Ì¬ºó£¬ÖØĞÂÍ³¼ÆÏà¹ØµÄSACK¡¢¶ªÊ§µÈµÈÊı¾İ */
	tp->sacked_out = 0;
	tp->lost_out = 0;
	tp->fackets_out = 0;

	/* ±éÀúÖØ´«¶ÓÁĞ£¬ÖØĞÂ±ê¼ÇLOST±êÖ¾¡£ */
	sk_stream_for_retrans_queue(skb, sk) {
		cnt += tcp_skb_pcount(skb);
		TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED)) {/* ÒÑ¾­È·ÈÏ¹ıµÄ²»ÓÃĞŞ¸Ä */

			/* Do not mark those segments lost that were
			 * forward transmitted after RTO
			 */
			if (!after(TCP_SKB_CB(skb)->end_seq,/* ÉèÖÃ±êÖ¾ */
				   tp->frto_highmark)) {
				TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
				tp->lost_out += tcp_skb_pcount(skb);
			}
		} else {
			tp->sacked_out += tcp_skb_pcount(skb);
			tp->fackets_out = cnt;
		}
	}
	tcp_sync_left_out(tp);

	/* ½øÈëLoss×´Ì¬£¬ÖØĞÂÉèÖÃÓµÈû´°¿ÚµÈµÈ */
	tp->snd_cwnd = tp->frto_counter + tcp_packets_in_flight(tp)+1;
	tp->snd_cwnd_cnt = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->undo_marker = 0;
	tp->frto_counter = 0;

	tp->reordering = min_t(unsigned int, tp->reordering,
					     sysctl_tcp_reordering);
	tcp_set_ca_state(tp, TCP_CA_Loss);
	tp->high_seq = tp->frto_highmark;
	TCP_ECN_queue_cwr(tp);

	init_bictcp(tp);
}

void tcp_clear_retrans(struct tcp_sock *tp)
{
	tp->left_out = 0;
	tp->retrans_out = 0;

	tp->fackets_out = 0;
	tp->sacked_out = 0;
	tp->lost_out = 0;

	tp->undo_marker = 0;
	tp->undo_retrans = 0;
}

/* Enter Loss state. If "how" is not zero, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 */
/* ½øÈëLOSS×´Ì¬ */
void tcp_enter_loss(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int cnt = 0;

	/* Reduce ssthresh if it has not yet been made inside this window. */
	if (tp->ca_state <= TCP_CA_Disorder || tp->snd_una == tp->high_seq ||
	    (tp->ca_state == TCP_CA_Loss && !tp->retransmits)) {/* ¸Õ½øÈëLOSS×´Ì¬ */
	    /* ÉèÖÃ·¢ËÍÓµÈû´°¿ÚµÄ·§Öµ */
		tp->prior_ssthresh = tcp_current_ssthresh(tp);
		tp->snd_ssthresh = tcp_recalc_ssthresh(tp);
	}
	/* ½«ÓµÈû´°¿ÚÉèÖÃÎª1¸ö¶Î */
	tp->snd_cwnd	   = 1;
	/* Çå³ıCAK¶Î¼ÆÊı£¬ºÍÓµÈû´°¿ÚÊ±¼ä */
	tp->snd_cwnd_cnt   = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;

	tcp_clear_retrans(tp);

	/* Push undo marker, if it was plain RTO and nothing
	 * was retransmitted. */
	if (!how)/* ²»Çå³ıSACK±ê¼Ç£¬Ôò¼ÇÂ¼UNAÒÔ±ãÔÚºÏÊÊµÄÊ±ºòÄÜ¹»½øĞĞÓµÈû´°¿Úµ÷Õû³·Ïú²Ù×÷ */
		tp->undo_marker = tp->snd_una;

	sk_stream_for_retrans_queue(skb, sk) {
		cnt += tcp_skb_pcount(skb);/* ¶ÎÖĞGSO·Ö¶ÎÊıÁ¿£¬ÓÃÓÚÀÛ¼Æfackets_out */
		/* ÖØ´«¶ÓÁĞÖĞ¶ÎµÄ¼Ç·ÖÅÆÒÑ¾­ÓĞÖØ´«±êÖ¾£¬ÔòÇå³ıÓµÈû´°¿Úµ÷Õû³·Ïú±ê¼Ç */
		if (TCP_SKB_CB(skb)->sacked&TCPCB_RETRANS)
			tp->undo_marker = 0;
		/* ½«ÖØ´«¶ÓÁĞÖĞ¶Î¼Ç·ÖÅÆÈ¥µôÖØ´«ºÍ¶ªÊ§±ê¼Ç */
		TCP_SKB_CB(skb)->sacked &= (~TCPCB_TAGBITS)|TCPCB_SACKED_ACKED;
		/* ¶Î¼Ç·ÖÅÆÃ»ÓĞSACK±ê¼Ç»òĞèÒªÇå³ıSACK±ê¼Ç */
		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED) || how) {
			/* Çå³ıSACK±ê¼Ç²¢¼ÓÉÏLOST±ê¼Ç */
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_ACKED;
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
			/* Í³¼Æ¶ªÊ§¶ÎµÄÊıÁ¿ */
			tp->lost_out += tcp_skb_pcount(skb);
		} else {
			/* ¸üĞÂSACKÈ·ÈÏµÄÊıÁ¿ºÍfackets_out */
			tp->sacked_out += tcp_skb_pcount(skb);
			tp->fackets_out = cnt;
		}
	}
	tcp_sync_left_out(tp);

	/* ÖØÅÅĞòµÄÊıÁ¿ */
	tp->reordering = min_t(unsigned int, tp->reordering,
					     sysctl_tcp_reordering);
	/* ÉèÖÃÓµÈû×´Ì¬ÎªLOSS×´Ì¬ */
	tcp_set_ca_state(tp, TCP_CA_Loss);
	/* ·¢ÉúÓµÈûÊ±µÄnxt */
	tp->high_seq = tp->snd_nxt;
	/* Çå³ıÖØ´«µÄ±äÁ¿ */
	TCP_ECN_queue_cwr(tp);
}

/* Èç¹û½ÓÊÕµ½µÄACKÈ·ÈÏµÄÊÇÒÑ¾­Í¨¹ıSACKÈ·ÈÏµÄ¶Î£¬Ôò±íÊ¾¼ÇÂ¼µÄSACK²»ÄÜ·´Ó³½ÓÊÕ·½Êµ¼ÊµÄ×´Ì¬ */
static int tcp_check_sack_reneging(struct sock *sk, struct tcp_sock *tp)
{
	struct sk_buff *skb;

	/* If ACK arrived pointing to a remembered SACK,
	 * it means that our remembered SACKs do not reflect
	 * real state of receiver i.e.
	 * receiver _host_ is heavily congested (or buggy).
	 * Do processing similar to RTO timeout.
	 */
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL &&
	    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)) {
		NET_INC_STATS_BH(LINUX_MIB_TCPSACKRENEGING);

		tcp_enter_loss(sk, 1);
		tp->retransmits++;
		tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue));
		tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);
		return 1;
	}
	return 0;
}

static inline int tcp_fackets_out(struct tcp_sock *tp)
{
	return IsReno(tp) ? tp->sacked_out+1 : tp->fackets_out;
}

static inline int tcp_skb_timedout(struct tcp_sock *tp, struct sk_buff *skb)
{
	return (tcp_time_stamp - TCP_SKB_CB(skb)->when > tp->rto);
}

static inline int tcp_head_timedout(struct sock *sk, struct tcp_sock *tp)
{
	return tp->packets_out &&
	       tcp_skb_timedout(tp, skb_peek(&sk->sk_write_queue));
}

/* Linux NewReno/SACK/FACK/ECN state machine.
 * --------------------------------------
 *
 * "Open"	Normal state, no dubious events, fast path.
 * "Disorder"   In all the respects it is "Open",
 *		but requires a bit more attention. It is entered when
 *		we see some SACKs or dupacks. It is split of "Open"
 *		mainly to move some processing from fast path to slow one.
 * "CWR"	CWND was reduced due to some Congestion Notification event.
 *		It can be ECN, ICMP source quench, local device congestion.
 * "Recovery"	CWND was reduced, we are fast-retransmitting.
 * "Loss"	CWND was reduced due to RTO timeout or SACK reneging.
 *
 * tcp_fastretrans_alert() is entered:
 * - each incoming ACK, if state is not "Open"
 * - when arrived ACK is unusual, namely:
 *	* SACK
 *	* Duplicate ACK.
 *	* ECN ECE.
 *
 * Counting packets in flight is pretty simple.
 *
 *	in_flight = packets_out - left_out + retrans_out
 *
 *	packets_out is SND.NXT-SND.UNA counted in packets.
 *
 *	retrans_out is number of retransmitted segments.
 *
 *	left_out is number of segments left network, but not ACKed yet.
 *
 *		left_out = sacked_out + lost_out
 *
 *     sacked_out: Packets, which arrived to receiver out of order
 *		   and hence not ACKed. With SACKs this number is simply
 *		   amount of SACKed data. Even without SACKs
 *		   it is easy to give pretty reliable estimate of this number,
 *		   counting duplicate ACKs.
 *
 *       lost_out: Packets lost by network. TCP has no explicit
 *		   "loss notification" feedback from network (for now).
 *		   It means that this number can be only _guessed_.
 *		   Actually, it is the heuristics to predict lossage that
 *		   distinguishes different algorithms.
 *
 *	F.e. after RTO, when all the queue is considered as lost,
 *	lost_out = packets_out and in_flight = retrans_out.
 *
 *		Essentially, we have now two algorithms counting
 *		lost packets.
 *
 *		FACK: It is the simplest heuristics. As soon as we decided
 *		that something is lost, we decide that _all_ not SACKed
 *		packets until the most forward SACK are lost. I.e.
 *		lost_out = fackets_out - sacked_out and left_out = fackets_out.
 *		It is absolutely correct estimate, if network does not reorder
 *		packets. And it loses any connection to reality when reordering
 *		takes place. We use FACK by default until reordering
 *		is suspected on the path to this destination.
 *
 *		NewReno: when Recovery is entered, we assume that one segment
 *		is lost (classic Reno). While we are in Recovery and
 *		a partial ACK arrives, we assume that one more packet
 *		is lost (NewReno). This heuristics are the same in NewReno
 *		and SACK.
 *
 *  Imagine, that's all! Forget about all this shamanism about CWND inflation
 *  deflation etc. CWND is real congestion window, never inflated, changes
 *  only according to classic VJ rules.
 *
 * Really tricky (and requiring careful tuning) part of algorithm
 * is hidden in functions tcp_time_to_recover() and tcp_xmit_retransmit_queue().
 * The first determines the moment _when_ we should reduce CWND and,
 * hence, slow down forward transmission. In fact, it determines the moment
 * when we decide that hole is caused by loss, rather than by a reorder.
 *
 * tcp_xmit_retransmit_queue() decides, _what_ we should retransmit to fill
 * holes, caused by lost packets.
 *
 * And the most logically complicated part of algorithm is undo
 * heuristics. We detect false retransmits due to both too early
 * fast retransmit (reordering) and underestimated RTO, analyzing
 * timestamps and D-SACKs. When we detect that some segments were
 * retransmitted by mistake and CWND reduction was wrong, we undo
 * window reduction and abort recovery phase. This logic is hidden
 * inside several functions named tcp_try_undo_<something>.
 */

/* This function decides, when we should leave Disordered state
 * and enter Recovery phase, reducing congestion window.
 *
 * Main question: may we further continue forward transmission
 * with the same cwnd?
 */
/* ÓÃÓÚ¼ì²âÄÜ·ñ½øÈë¿ìËÙ»Ö¸´×´Ì¬¡£¶ÔÓÚNewRenoÀ´Ëµ£¬Á¬Ğø½ÓÊÕµ½3¸öÖØ¸´È·ÈÏ£¬±ã»á½øÈërecover×´Ì¬ */
static int tcp_time_to_recover(struct sock *sk, struct tcp_sock *tp)
{
	__u32 packets_out;

	/* Trick#1: The loss is proven. */
	if (tp->lost_out)/* ÓĞ¶ªÊ§µÄ¶Î£¬Ôò¿ÉÒÔ½øÈërecover×´Ì¬ */
		return 1;

	/* Not-A-Trick#2 : Classic rule... */
	if (tcp_fackets_out(tp) > tp->reordering)/* ¶ªÊ§µÄ¶Î³¬¹ıÂÒĞòµÄ¶Î */
		return 1;

	/* Trick#3 : when we use RFC2988 timer restart, fast
	 * retransmit can be triggered by timeout of queue head.
	 */
	if (tcp_head_timedout(sk, tp))/* ÖØ´«¶ÓÁĞ¶ÓÊ×µÄ¶Î·¢ËÍ³¬Ê±£¬¿ÉÒÔ½øÈërecover×´Ì¬ */
		return 1;

	/* Trick#4: It is still not OK... But will it be useful to delay
	 * recovery more?
	 */
	packets_out = tp->packets_out;
	/* Î´È·ÈÏµÄ¶Î½ÏÉÙ£¬Í¨¹ıSACKÈ·ÈÏµÄ¶Î³¬¹ıÎ´È·ÈÏµÄÒ»°ë£¬Í¬Ê±Ã»ÓĞ¶ÎĞèÒª¼°Ê±Êä³ö */
	if (packets_out <= tp->reordering &&
	    tp->sacked_out >= max_t(__u32, packets_out/2, sysctl_tcp_reordering) &&
	    !tcp_may_send_now(sk, tp)) {
		/* We have nothing to send. This connection is limited
		 * either by receiver window or by application.
		 */
		return 1;
	}

	return 0;
}

/* If we receive more dupacks than we expected counting segments
 * in assumption of absent reordering, interpret this as reordering.
 * The only another reason could be bug in receiver TCP.
 */
static void tcp_check_reno_reordering(struct tcp_sock *tp, int addend)
{
	u32 holes;

	holes = max(tp->lost_out, 1U);
	holes = min(holes, tp->packets_out);

	if ((tp->sacked_out + holes) > tp->packets_out) {
		tp->sacked_out = tp->packets_out - holes;
		tcp_update_reordering(tp, tp->packets_out+addend, 0);
	}
}

/* Emulate SACKs for SACKless connection: account for a new dupack. */

static void tcp_add_reno_sack(struct tcp_sock *tp)
{
	tp->sacked_out++;
	tcp_check_reno_reordering(tp, 0);
	tcp_sync_left_out(tp);
}

/* Account for ACK, ACKing some data in Reno Recovery phase. */

static void tcp_remove_reno_sacks(struct sock *sk, struct tcp_sock *tp, int acked)
{
	if (acked > 0) {
		/* One ACK acked hole. The rest eat duplicate ACKs. */
		if (acked-1 >= tp->sacked_out)
			tp->sacked_out = 0;
		else
			tp->sacked_out -= acked-1;
	}
	tcp_check_reno_reordering(tp, acked);
	tcp_sync_left_out(tp);
}

static inline void tcp_reset_reno_sack(struct tcp_sock *tp)
{
	tp->sacked_out = 0;
	tp->left_out = tp->lost_out;
}

/* Mark head of queue up as lost. */
/**
 * ´ÓÖØ´«¶ÓÁĞÊ×²¿»òÉÏ´Î±ê¼Ç¶ªÊ§¶ÎµÄÎ»ÖÃ¿ªÊ¼£¬Îª¼Ç·ÖÅÆÎª0µÄ¶ÎÌí¼ÓLOST±ê¼Ç¡£
 * Ö±µ½ËùÓĞ±»±ê¼ÇÎªLOSTµÄ¶Î´ïµ½packets»ò±»±ê¼ÇĞòºÅ³¬¹ıhigh_seqÎªÖ¹¡£
 */
static void tcp_mark_head_lost(struct sock *sk, struct tcp_sock *tp,
			       int packets, u32 high_seq)
{
	struct sk_buff *skb;
	int cnt = packets;

	BUG_TRAP(cnt <= tp->packets_out);

	sk_stream_for_retrans_queue(skb, sk) {
		cnt -= tcp_skb_pcount(skb);
		if (cnt < 0 || after(TCP_SKB_CB(skb)->end_seq, high_seq))
			break;
		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_TAGBITS)) {
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
			tp->lost_out += tcp_skb_pcount(skb);
		}
	}
	tcp_sync_left_out(tp);
}

/* Account newly detected lost packet(s) */

/* ÎªÈ·¶¨¶ªÊ§µÄ¶Î¸üĞÂ¼Ç·ÖÅÆ¡£Èç¹ûÈ·ÈÏ½ÓÊÕµ½ÖØ¸´ACK»òÕßÖØ´«¶ÓÊ×µÄ¶Î´«ËÍ³¬Ê±Ê±±»µ÷ÓÃ¡£ */
static void tcp_update_scoreboard(struct sock *sk, struct tcp_sock *tp)
{
	/* ÎªÖØ´«¶ÓÁĞÉÏµÄ¶ÎÌí¼ÓLOST±ê¼Ç */
	if (IsFack(tp)) {
		int lost = tp->fackets_out - tp->reordering;
		if (lost <= 0)
			lost = 1;
		tcp_mark_head_lost(sk, tp, lost, tp->high_seq);
	} else {
		tcp_mark_head_lost(sk, tp, 1, tp->high_seq);
	}

	/* New heuristics: it is possible only after we switched
	 * to restart timer each time when something is ACKed.
	 * Hence, we can detect timed out packets during fast
	 * retransmit without falling to slow start.
	 */
	if (tcp_head_timedout(sk, tp)) {/* ÖØ´«¶ÓÁĞ¶ÓÊ×µÄ¶ÎÒÑ¾­³¬Ê± */
		struct sk_buff *skb;

		sk_stream_for_retrans_queue(skb, sk) {/* ÎªÒÑ¾­³¬Ê±ÇÒ¼Ç·ÖÅÆÎª¿ÕµÄ¶ÎÌí¼ÓLOST±êÖ¾ */
			if (tcp_skb_timedout(tp, skb) &&
			    !(TCP_SKB_CB(skb)->sacked&TCPCB_TAGBITS)) {
				TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
				tp->lost_out += tcp_skb_pcount(skb);
			}
		}
		/* ¼ÆËãÒÑ¾­Àë¿ªÖ÷»úµ«ÊÇÃ»ÓĞÈ·ÈÏµÄ¶ÎÊı */
		tcp_sync_left_out(tp);
	}
}

/* CWND moderation, preventing bursts due to too big ACKs
 * in dubious situations.
 */
/**
 * ¶ÔÓµÈû´°¿Ú½øĞĞÎ¢µ÷¡£
 * ÔÙÈ¡ÓµÈû´°¿Ú´óĞ¡ºÍÒÑ·¢ËÍµ«Î´È·ÈÏ¶ÎÊıÁ¿¼Ó3Ö®¼äµÄ×îĞ¡Öµ×÷Îªµ±Ç°ÓµÈû´°¿Ú¡£
 * ²¢¼ÇÂ¼×î½üÒ»´Îµ÷ÕûÓµÈû´°¿ÚµÄÊ±¼ä¡£
 */
static inline void tcp_moderate_cwnd(struct tcp_sock *tp)
{
	tp->snd_cwnd = min(tp->snd_cwnd,
			   tcp_packets_in_flight(tp)+tcp_max_burst(tp));
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Decrease cwnd each second ack. */

static void tcp_cwnd_down(struct tcp_sock *tp)
{
	int decr = tp->snd_cwnd_cnt + 1;
	__u32 limit;

	/*
	 * TCP Westwood
	 * Here limit is evaluated as BWestimation*RTTmin (for obtaining it
	 * in packets we use mss_cache). If sysctl_tcp_westwood is off
	 * tcp_westwood_bw_rttmin() returns 0. In such case snd_ssthresh is
	 * still used as usual. It prevents other strange cases in which
	 * BWE*RTTmin could assume value 0. It should not happen but...
	 */

	if (!(limit = tcp_westwood_bw_rttmin(tp)))
		limit = tp->snd_ssthresh/2;

	tp->snd_cwnd_cnt = decr&1;
	decr >>= 1;

	if (decr && tp->snd_cwnd > limit)
		tp->snd_cwnd -= decr;

	tp->snd_cwnd = min(tp->snd_cwnd, tcp_packets_in_flight(tp)+1);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Nothing was retransmitted or returned timestamp is less
 * than timestamp of the first retransmission.
 */
static inline int tcp_packet_delayed(struct tcp_sock *tp)
{
	return !tp->retrans_stamp ||
		(tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		 (__s32)(tp->rx_opt.rcv_tsecr - tp->retrans_stamp) < 0);
}

/* Undo procedures. */

#if FASTRETRANS_DEBUG > 1
static void DBGUNDO(struct sock *sk, struct tcp_sock *tp, const char *msg)
{
	struct inet_sock *inet = inet_sk(sk);
	printk(KERN_DEBUG "Undo %s %u.%u.%u.%u/%u c%u l%u ss%u/%u p%u\n",
	       msg,
	       NIPQUAD(inet->daddr), ntohs(inet->dport),
	       tp->snd_cwnd, tp->left_out,
	       tp->snd_ssthresh, tp->prior_ssthresh,
	       tp->packets_out);
}
#else
#define DBGUNDO(x...) do { } while (0)
#endif

/* ²»ÔÙËõĞ¡ÓµÈû´°¿Ú */
static void tcp_undo_cwr(struct tcp_sock *tp, int undo)
{
	if (tp->prior_ssthresh) {/* ¸ù¾İÂıÆô¶¯·§ÖµµÄ¾ÉÖµ´æÔÚÓë·ñ£¬À´È·¶¨³·Ïú²Ù×÷ */
		/* ÔÚµ±Ç°µÄÓµÈû´°¿ÚºÍ2±¶´óµÄÂıÆô¶¯ÖµÖ®¼äÑ¡Ôñ½Ï´óÖµ×÷Îªµ±Ç°µÄÓµÈû´°¿Ú´óĞ¡ */
		tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh<<1);

		/* ³·ÏúÂıÆô¶¯·§Öµ¼°TCP_ECN_DEMAND_CWR±êÖ¾ */
		if (undo && tp->prior_ssthresh > tp->snd_ssthresh) {
			tp->snd_ssthresh = tp->prior_ssthresh;
			TCP_ECN_withdraw_cwr(tp);
		}
	} else {/* ²»´æÔÚÆô¶¯·§ÖµµÄ¾ÉÖµ */
		/* È¡ÓµÈû´°¿Ú´óĞ¡ºÍÆô¶¯·§ÖµÖ®¼äµÄ½Ï´óÎªµ±Ç°ÓµÈû´°¿Ú */
		tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh);
	}
	/* ¶ÔÓµÈû´°¿Ú½øĞĞÎ¢µ÷£¬È¡ÓµÈû´°¿Ú´óĞ¡ºÍÒÑ·¢ËÍµ«Î´È·ÈÏ¶ÎÊıÁ¿¼Ó3Ö®¼äµÄ×îĞ¡Öµ×÷Îªµ±Ç°ÓµÈû´°¿Ú */
	tcp_moderate_cwnd(tp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* ÔÚ½øĞĞÓµÈû´°¿Úµ÷Õû³·ÏúÖ®Ç°£¬µ÷ÓÃ´Ëº¯Êı¼ì²âÄÜ·ñ³·Ïú */
static inline int tcp_may_undo(struct tcp_sock *tp)
{
	return tp->undo_marker &&/* ÖØ´«ÆğÊ¼µã²»Îª0 */
		(!tp->undo_retrans || tcp_packet_delayed(tp));/* Ã»ÓĞ¿É³·ÏúµÄÖØ´«¶ÎÊı£¬»òÕßÃ»ÓĞÖØ´«»òÖØ´«ÁËÖ®ºó»¹Ã»ÓĞ½ÓÊÕµ½¶Ô·½·¢ËÍµÄÈ·ÈÏ */
}

/* People celebrate: "We love our President!" */
/* ´Órecovery×´Ì¬³·Ïú */
static int tcp_try_undo_recovery(struct sock *sk, struct tcp_sock *tp)
{
	if (tcp_may_undo(tp)) {/* ¿ÉÒÔ½øĞĞ³·Ïú */
		/* Happy end! We did not retransmit anything
		 * or our original transmission succeeded.
		 */
		DBGUNDO(sk, tp, tp->ca_state == TCP_CA_Loss ? "loss" : "retrans");
		/* »Ö¸´ÓµÈû´°¿ÚºÍÓµÈû¿ØÖÆÊ±ÂıÆô¶¯µÄ·§Öµ */
		tcp_undo_cwr(tp, 1);
		if (tp->ca_state == TCP_CA_Loss)
			NET_INC_STATS_BH(LINUX_MIB_TCPLOSSUNDO);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPFULLUNDO);
		tp->undo_marker = 0;
	}
	if (tp->snd_una == tp->high_seq && IsReno(tp)) {/* ²»Ö§³ÖSACK */
		/* Hold old state until something *above* high_seq
		 * is ACKed. For Reno it is MUST to prevent false
		 * fast retransmits (RFC2582). SACK TCP is safe. */
		 /* Ö»¶ÔÓµÈû´°¿Ú½øĞĞÎ¢µ÷ */
		tcp_moderate_cwnd(tp);
		return 1;
	}
	/* Ö§³ÖSACK£¬³·Ïúµ½OPEN×´Ì¬ */
	tcp_set_ca_state(tp, TCP_CA_Open);
	return 0;
}

/* Try to undo cwnd reduction, because D-SACKs acked all retransmitted data */
static void tcp_try_undo_dsack(struct sock *sk, struct tcp_sock *tp)
{
	if (tp->undo_marker && !tp->undo_retrans) {
		DBGUNDO(sk, tp, "D-SACK");
		tcp_undo_cwr(tp, 1);
		tp->undo_marker = 0;
		NET_INC_STATS_BH(LINUX_MIB_TCPDSACKUNDO);
	}
}

/* Undo during fast recovery after partial ACK. */

/* ÔÚRecoveryÓµÈû×´Ì¬£¬Èç¹ûACKÈ·ÈÏÁË²¿·ÖÖØ´«µÄ¶Î£¬µ÷ÓÃ´Ëº¯Êı½øĞĞÓµÈû´°¿ÚµÄ³·Ïú */
static int tcp_try_undo_partial(struct sock *sk, struct tcp_sock *tp,
				int acked)
{
	/* Partial ACK arrived. Force Hoe's retransmit. */
	int failed = IsReno(tp) || tp->fackets_out>tp->reordering;

	if (tcp_may_undo(tp)) {
		/* Plain luck! Hole if filled with delayed
		 * packet, rather than with a retransmit.
		 */
		if (tp->retrans_out == 0)
			tp->retrans_stamp = 0;

		tcp_update_reordering(tp, tcp_fackets_out(tp)+acked, 1);

		DBGUNDO(sk, tp, "Hoe");
		tcp_undo_cwr(tp, 0);
		NET_INC_STATS_BH(LINUX_MIB_TCPPARTIALUNDO);

		/* So... Do not make Hoe's retransmit yet.
		 * If the first packet was delayed, the rest
		 * ones are most probably delayed as well.
		 */
		failed = 0;
	}
	return failed;
}

/* Undo during loss recovery after partial ACK. */
/* ÔÚ½ÓÊÕµ½ĞÂµÄÈ·ÈÏÊ±£¬³¢ÊÔ´ÓLOSS×´Ì¬½øÈëopen×´Ì¬£¬·µ»Ø1±íÊ¾³·Ïú³É¹¦ */
static int tcp_try_undo_loss(struct sock *sk, struct tcp_sock *tp)
{
	if (tcp_may_undo(tp)) {/* ÊÇ·ñ¿ÉÒÔ´ÓLoss×´Ì¬³·Ïú */
		struct sk_buff *skb;
		/* Çå³ıÖØ´«¶ÓÁĞÉÏ£¬ËùÓĞ¶ÎµÄ¼Ç·ÖÅÆÉÏµÄLOST±êÖ¾ */
		sk_stream_for_retrans_queue(skb, sk) {
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		}
		DBGUNDO(sk, tp, "partial loss");
		/* Çå³ıËùÓĞÓëÓµÈû¿ØÖÆÏà¹ØµÄ±êÖ¾ */
		tp->lost_out = 0;
		tp->left_out = tp->sacked_out;
		tcp_undo_cwr(tp, 1);
		NET_INC_STATS_BH(LINUX_MIB_TCPLOSSUNDO);
		tp->retransmits = 0;
		tp->undo_marker = 0;
		if (!IsReno(tp))
			tcp_set_ca_state(tp, TCP_CA_Open);
		return 1;
	}
	return 0;
}

/* ½áÊøÓµÈû´°¿Ú¼õĞ¡£¬½«ÓµÈû´°¿Ú¸üĞÂÎªÓµÈû´°¿ÚÓëÂıÆô¶¯µÄ·§ÖµÖ®¼äµÄ½ÏĞ¡Öµ¡£¼ÇÂ¼×î½üÒ»´Îµ÷ÕûÓµÈû´°¿ÚµÄÊ±¼ä */
static inline void tcp_complete_cwr(struct tcp_sock *tp)
{
	if (tcp_westwood_cwnd(tp)) 
		tp->snd_ssthresh = tp->snd_cwnd;
	else
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

static void tcp_try_to_open(struct sock *sk, struct tcp_sock *tp, int flag)
{
	tp->left_out = tp->sacked_out;

	if (tp->retrans_out == 0)
		tp->retrans_stamp = 0;

	if (flag&FLAG_ECE)
		tcp_enter_cwr(tp);

	if (tp->ca_state != TCP_CA_CWR) {
		int state = TCP_CA_Open;

		if (tp->left_out || tp->retrans_out || tp->undo_marker)
			state = TCP_CA_Disorder;

		if (tp->ca_state != state) {
			tcp_set_ca_state(tp, state);
			tp->high_seq = tp->snd_nxt;
		}
		tcp_moderate_cwnd(tp);
	} else {
		tcp_cwnd_down(tp);
	}
}

/* Process an event, which can update packets-in-flight not trivially.
 * Main goal of this function is to calculate new estimate for left_out,
 * taking into account both packets sitting in receiver's buffer and
 * packets lost by network.
 *
 * Besides that it does CWND reduction, when packet loss is detected
 * and changes state of machine.
 *
 * It does _not_ decide what to send, it is made in function
 * tcp_xmit_retransmit_queue().
 */
/**
 * ÓµÈû¿ØÖÆ×´Ì¬µÄ´¦Àí 
 * °üÀ¨´¦ÀíÏÔÊ½ÓµÈûÍ¨Öª£¬ÅĞ¶ÏSACKÊÇ·ñĞé¼ÙµÈµÈ
 */
static void
tcp_fastretrans_alert(struct sock *sk, u32 prior_snd_una,
		      int prior_packets, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int is_dupack = (tp->snd_una == prior_snd_una && !(flag&FLAG_NOT_DUP));

	/* Some technical things:
	 * 1. Reno does not count dupacks (sacked_out) automatically. */
	/* ¶Ôsacked_outºÍfackets_out½øĞĞÎ¢µ÷ */
	if (!tp->packets_out)
		tp->sacked_out = 0;
        /* 2. SACK counts snd_fack in packets inaccurately. */
	if (tp->sacked_out == 0)
		tp->fackets_out = 0;

        /* Now state machine starts.
	 * A. ECE, hence prohibit cwnd undoing, the reduction is required. */
	if (flag&FLAG_ECE)/* ½ÓÊÕµ½ÏÔÊ½ÓµÈûÍ¨Öª£¬Òò´Ë½ûÖ¹ÓµÈû´°¿Ú³·Ïú£¬²¢¿ªÊ¼¼õĞ¡ÓµÈû´°¿Ú */
		tp->prior_ssthresh = 0;

	/* B. In all the states check for reneging SACKs. */
	/**
	 * Èç¹û½ÓÊÕµÄACKÖ¸ÏòÒÑ¼ÇÂ¼µÄSACK£¬ËµÃ÷¼ÇÂ¼µÄSACK²»ÄÜ·´Ó¦½ÓÊÕ·½µÄÕæÊµ×´Ì¬£¬ÄÇÃ´°´ÕÕÖØ´«³¬Ê±´¦Àí 
	 * ÒòÎªÒ»°ãÇé¿öÏÂ£¬ACKÓ¦µ±Ö¸ÏòSACKºóÃæÎ´½ÓÊÕµÄµØ·½¡£
	 */
	if (tp->sacked_out && tcp_check_sack_reneging(sk, tp))
		return;

	/* C. Process data loss notification, provided it is valid. */
	if ((flag&FLAG_DATA_LOST) &&/* Í¨¹ıSACK·¢ÏÖÓĞ¶Î¶ªÊ§ */
	    before(tp->snd_una, tp->high_seq) &&
	    tp->ca_state != TCP_CA_Open &&
	    tp->fackets_out > tp->reordering) {
	    /* ´ÓÖØ´«¶ÓÁĞÊ×²¿»òÉÏ´Î±êÊ¶¶ªÊ§¶ÎµÄÎ»ÖÃ¿ªÊ¼£¬Îª¼Ç·ÖÅÆÎª0µÄ¶ÎÌí¼ÓLOST±ê¼Ç */
		tcp_mark_head_lost(sk, tp, tp->fackets_out-tp->reordering, tp->high_seq);
		NET_INC_STATS_BH(LINUX_MIB_TCPLOSS);
	}

	/* D. Synchronize left_out to current state. */
	/* ¸üĞÂÒÑ¾­Àë¿ªÖ÷»ú£¬µ«ÊÇÔÚÍøÂçÖĞÎ´È·ÈÏµÄTCP¶ÎÊı */
	tcp_sync_left_out(tp);

	/* E. Check state exit conditions. State can be terminated
	 *    when high_seq is ACKed. */
	/* ¿ªÊ¼´¦Àí´ÓÓµÈû×´Ì¬³·Ïú */
	if (tp->ca_state == TCP_CA_Open) {/* µ±Ç°ÊÇopen×´Ì¬ */
		if (!sysctl_tcp_frto)
			BUG_TRAP(tp->retrans_out == 0);
		tp->retrans_stamp = 0;/* Çå³ıÉÏ´ÎÖØ´«½×¶ÎµÄµÚÒ»¸öÖØ´«¶ÎµÄ·¢ËÍÊ±¼ä */
	} else if (!before(tp->snd_una, tp->high_seq)) {/* µ±ÓµÈûÊ±¼ÇÂ¼µÄnxt±»È·ÈÏÊ±£¬ÓµÈû×´¿öÒÑ¾­ºÃ×ª£¬¿ÉÒÔÊÓÇé¿ö»Øµ½open×´Ì¬ */
		switch (tp->ca_state) {
		case TCP_CA_Loss:/* ´ÓLoss×´Ì¬³·Ïúµ½open×´Ì¬ */
			tp->retransmits = 0;
			if (tcp_try_undo_recovery(sk, tp))/* ³·Ïú²»³É¹¦Ôò·µ»Ø */
				return;
			/* ³·Ïú³É¹¦Ôò¼ÌĞø´¦Àíopen×´Ì¬ */
			break;

		case TCP_CA_CWR:
			/* CWR is to be held something *above* high_seq
			 * is ACKed for CWR bit to reach receiver. */
			if (tp->snd_una != tp->high_seq) {/* ÓµÈûÊ±¼ÇÂ¼µÄnxt¶Î¶¼±»È·ÈÏÁË */
				/* ¼õĞ¡ÓµÈû´°¿Ú£¬²¢³·Ïúµ½open×´Ì¬ */
				tcp_complete_cwr(tp);
				tcp_set_ca_state(tp, TCP_CA_Open);
			}
			break;

		case TCP_CA_Disorder:
			/* Èç¹ûDSACKÈ·ÈÏÁËËùÓĞÖØ´«µÄ¶Î£¬ÔòÒª³·ÏúÓµÈû´°¿Ú */
			tcp_try_undo_dsack(sk, tp);
			if (!tp->undo_marker ||/* ÓµÈûÊ±¼ÇÂ¼µÄnxtÖ®ºóµÄ¶Î¶¼±»È·ÈÏÁË */
			    /* For SACK case do not Open to allow to undo
			     * catching for all duplicate ACKs. */
			    IsReno(tp) || tp->snd_una != tp->high_seq) {/* ÆôÓÃÁËNewReno */
			    /* »Ö¸´µ½open×´Ì¬ */
				tp->undo_marker = 0;
				tcp_set_ca_state(tp, TCP_CA_Open);
			}
			break;

		case TCP_CA_Recovery:
			if (IsReno(tp))/* Èç¹ûÆôÓÃÁËNewReno */
				tcp_reset_reno_sack(tp);/* ¸´Î»SACKÏà¹ØµÄÊı¾İ */
			if (tcp_try_undo_recovery(sk, tp))/* ³¢ÊÔ´ÓRecovery×´Ì¬³·Ïú */
				return;
			/* Èç¹û³·Ïú³É¹¦£¬Ôò½áÊøÓµÈû´°¿Ú¼õĞ¡ */
			tcp_complete_cwr(tp);
			break;
		}
	}

	/* F. Process state. */
	switch (tp->ca_state) {
	case TCP_CA_Recovery:
		if (prior_snd_una == tp->snd_una) {/* Ã»ÓĞ¶Î±»È·ÈÏ */
			if (IsReno(tp) && is_dupack)/* ÊÇÖØ¸´ACK£¬¼ÇÂ¼½ÓÊÕµ½µÄÖØ¸´ACKÊıÁ¿ */
				tcp_add_reno_sack(tp);
		} else {/* ÓĞĞÂµÄ¶Î±»È·ÈÏ */
			/* ¼ÆËã±»È·ÈÏµÄ¶ÎÊıÁ¿ */
			int acked = prior_packets - tp->packets_out;
			if (IsReno(tp))
				tcp_remove_reno_sacks(sk, tp, acked);
			/* ´¦ÀíÓµÈû´°¿ÚµÄ³·Ïú */
			is_dupack = tcp_try_undo_partial(sk, tp, acked);
		}
		break;
	case TCP_CA_Loss:
		if (flag&FLAG_DATA_ACKED)/* È·ÈÏÁËĞÂµÄ¶Î */
			tp->retransmits = 0;
		if (!tcp_try_undo_loss(sk, tp)) {/* ³¢ÊÔ³·Ïúµ½open×´Ì¬ */
			/* Î¢µ÷ÓµÈû´°¿Ú */
			tcp_moderate_cwnd(tp);
			/* ¿ªÊ¼ÖØ´«ÄÇĞ©±ê¼Ç¶ªÊ§µÄ¶Î */
			tcp_xmit_retransmit_queue(sk);
			return;
		}
		if (tp->ca_state != TCP_CA_Open)
			return;
		/* Loss is undone; fall through to processing in Open state. */
	default:/* ´ÓDisorder½øÈëRecovery×´Ì¬ */
		if (IsReno(tp)) {/* ²»Ö§³ÖSACK */
			if (tp->snd_una != prior_snd_una)/* ÓĞĞÂµÄ¶Î±»È·ÈÏ */
				tcp_reset_reno_sack(tp);/* ¸´Î»ÖØ¸´È·ÈÏ¼ÆÊı */
			if (is_dupack)
				tcp_add_reno_sack(tp);
		}

		if (tp->ca_state == TCP_CA_Disorder)/* Èç¹û´¦ÓÚDisorder×´Ì¬ */
			tcp_try_undo_dsack(sk, tp);/* Èç¹ûD-SACKÈ·ÈÏÁËËùÓĞÖØ´«µÄ¶Î£¬Ôò³¢ÊÔ³·Ïú"ËõĞ¡ÓµÈû´°¿Ú" */

		if (!tcp_time_to_recover(sk, tp)) {/* ÅĞ¶ÏÊÇ·ñÄÜ¹»½øÈërecover×´Ì¬ */
			/* Èç¹û²»ÄÜ½øÈërecover×´Ì¬£¬Ôò³¢ÊÔÊÇ·ñÄÜ¹»½øÈëopen×´Ì¬ */
			tcp_try_to_open(sk, tp, flag);
			return;
		}

		/* Otherwise enter Recovery state */

		/* Í³¼Æmib¼ÆÊı */
		if (IsReno(tp))
			NET_INC_STATS_BH(LINUX_MIB_TCPRENORECOVERY);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPSACKRECOVERY);

		tp->high_seq = tp->snd_nxt;
		tp->prior_ssthresh = 0;
		tp->undo_marker = tp->snd_una;
		tp->undo_retrans = tp->retrans_out;

		if (tp->ca_state < TCP_CA_CWR) {
			if (!(flag&FLAG_ECE))/* ±£´æµ±Ç°µÄÂıÆô¶¯·§Öµ */
				tp->prior_ssthresh = tcp_current_ssthresh(tp);
			/* ¸ù¾İ²»Í¬µÄËã·¨ÉèÖÃµ±Ç°µÄÂıÆô¶¯·§Öµ */
			tp->snd_ssthresh = tcp_recalc_ssthresh(tp);
			TCP_ECN_queue_cwr(tp);
		}

		/* Çå³ı¼ÆÊıºó½øÈërecover×´Ì¬ */
		tp->snd_cwnd_cnt = 0;
		tcp_set_ca_state(tp, TCP_CA_Recovery);
	}

	/* ½ÓÊÕµ½ÖØ¸´ACK£¬»òÕßÖØ´«¶ÓÊ×µÄ¶Î´«ËÍ³¬Ê± */
	if (is_dupack || tcp_head_timedout(sk, tp))
		tcp_update_scoreboard(sk, tp);/* Îª¶ªÊ§µÄ¶Î¸üĞÂ¼Ç·ÖÅÆ */
	/* ÔÚCWRºÍRecovery×´Ì¬£¬ÓµÈû´°¿ÚÃ¿¸ôÒ»¸öĞÂµ½µÄÈ·ÈÏ¾Í¼õÉÙÒ»¸ö¶Î£¬Ö±µ½ÓµÈû´°¿Ú´óĞ¡µÈÓÚÓµÈû´°¿Ú·§ÖµÎªÖ¹ */
	tcp_cwnd_down(tp);
	/* ÖØ´«ÖØ´«¶ÓÁĞÖĞ±ê¼ÇÎªLOSTµÄ¶Î£¬Í¬Ê±ÖØÖÃRTO¶¨Ê±Æ÷ */
	tcp_xmit_retransmit_queue(sk);
}

/* Read draft-ietf-tcplw-high-performance before mucking
 * with this code. (Superceeds RFC1323)
 */
static void tcp_ack_saw_tstamp(struct tcp_sock *tp, int flag)
{
	__u32 seq_rtt;

	/* RTTM Rule: A TSecr value received in a segment is used to
	 * update the averaged RTT measurement only if the segment
	 * acknowledges some new data, i.e., only if it advances the
	 * left edge of the send window.
	 *
	 * See draft-ietf-tcplw-high-performance-00, section 3.3.
	 * 1998/04/10 Andrey V. Savochkin <saw@msu.ru>
	 *
	 * Changed: reset backoff as soon as we see the first valid sample.
	 * If we do not, we get strongly overstimated rto. With timestamps
	 * samples are accepted even from very old segments: f.e., when rtt=1
	 * increases to 8, we retransmit 5 times and after 8 seconds delayed
	 * answer arrives rto becomes 120 seconds! If at least one of segments
	 * in window is lost... Voila.	 			--ANK (010210)
	 */
	seq_rtt = tcp_time_stamp - tp->rx_opt.rcv_tsecr;
	tcp_rtt_estimator(tp, seq_rtt);
	tcp_set_rto(tp);
	tp->backoff = 0;
	tcp_bound_rto(tp);
}

static void tcp_ack_no_tstamp(struct tcp_sock *tp, u32 seq_rtt, int flag)
{
	/* We don't have a timestamp. Can only use
	 * packets that are not retransmitted to determine
	 * rtt estimates. Also, we must not reset the
	 * backoff for rto until we get a non-retransmitted
	 * packet. This allows us to deal with a situation
	 * where the network delay has increased suddenly.
	 * I.e. Karn's algorithm. (SIGCOMM '87, p5.)
	 */

	if (flag & FLAG_RETRANS_DATA_ACKED)
		return;

	tcp_rtt_estimator(tp, seq_rtt);
	tcp_set_rto(tp);
	tp->backoff = 0;
	tcp_bound_rto(tp);
}

/* µ±È·ÈÏÁË·¢ËÍ±¨ÎÄÊ±£¬µ÷ÓÃ´Ëº¯Êı¸üĞÂÍù·µÊ±¼ä */
static inline void tcp_ack_update_rtt(struct tcp_sock *tp,
				      int flag, s32 seq_rtt)
{
	/* Note that peer MAY send zero echo. In this case it is ignored. (rfc1323) */
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		tcp_ack_saw_tstamp(tp, flag);
	else if (seq_rtt >= 0)
		tcp_ack_no_tstamp(tp, seq_rtt, flag);
}

/*
 * Compute congestion window to use.
 *
 * This is from the implementation of BICTCP in
 * Lison-Xu, Kahaled Harfoush, and Injog Rhee.
 *  "Binary Increase Congestion Control for Fast, Long Distance
 *  Networks" in InfoComm 2004
 * Available from:
 *  http://www.csc.ncsu.edu/faculty/rhee/export/bitcp.pdf
 *
 * Unless BIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */
static inline __u32 bictcp_cwnd(struct tcp_sock *tp)
{
	/* orignal Reno behaviour */
	if (!tcp_is_bic(tp))
		return tp->snd_cwnd;

	if (tp->bictcp.last_cwnd == tp->snd_cwnd &&
	   (s32)(tcp_time_stamp - tp->bictcp.last_stamp) <= (HZ>>5))
		return tp->bictcp.cnt;

	tp->bictcp.last_cwnd = tp->snd_cwnd;
	tp->bictcp.last_stamp = tcp_time_stamp;
      
	/* start off normal */
	if (tp->snd_cwnd <= sysctl_tcp_bic_low_window)
		tp->bictcp.cnt = tp->snd_cwnd;

	/* binary increase */
	else if (tp->snd_cwnd < tp->bictcp.last_max_cwnd) {
		__u32 	dist = (tp->bictcp.last_max_cwnd - tp->snd_cwnd)
			/ BICTCP_B;

		if (dist > BICTCP_MAX_INCREMENT)
			/* linear increase */
			tp->bictcp.cnt = tp->snd_cwnd / BICTCP_MAX_INCREMENT;
		else if (dist <= 1U)
			/* binary search increase */
			tp->bictcp.cnt = tp->snd_cwnd * BICTCP_FUNC_OF_MIN_INCR
				/ BICTCP_B;
		else
			/* binary search increase */
			tp->bictcp.cnt = tp->snd_cwnd / dist;
	} else {
		/* slow start amd linear increase */
		if (tp->snd_cwnd < tp->bictcp.last_max_cwnd + BICTCP_B)
			/* slow start */
			tp->bictcp.cnt = tp->snd_cwnd * BICTCP_FUNC_OF_MIN_INCR
				/ BICTCP_B;
		else if (tp->snd_cwnd < tp->bictcp.last_max_cwnd
			 		+ BICTCP_MAX_INCREMENT*(BICTCP_B-1))
			/* slow start */
			tp->bictcp.cnt = tp->snd_cwnd * (BICTCP_B-1)
				/ (tp->snd_cwnd-tp->bictcp.last_max_cwnd);
		else
			/* linear increase */
			tp->bictcp.cnt = tp->snd_cwnd / BICTCP_MAX_INCREMENT;
	}
	return tp->bictcp.cnt;
}

/* This is Jacobson's slow start and congestion avoidance. 
 * SIGCOMM '88, p. 328.
 */
static inline void reno_cong_avoid(struct tcp_sock *tp)
{
        if (tp->snd_cwnd <= tp->snd_ssthresh) {
                /* In "safe" area, increase. */
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
	} else {
                /* In dangerous area, increase slowly.
		 * In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd
		 */
		if (tp->snd_cwnd_cnt >= bictcp_cwnd(tp)) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
			tp->snd_cwnd_cnt=0;
		} else
			tp->snd_cwnd_cnt++;
        }
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* This is based on the congestion detection/avoidance scheme described in
 *    Lawrence S. Brakmo and Larry L. Peterson.
 *    "TCP Vegas: End to end congestion avoidance on a global internet."
 *    IEEE Journal on Selected Areas in Communication, 13(8):1465--1480,
 *    October 1995. Available from:
 *	ftp://ftp.cs.arizona.edu/xkernel/Papers/jsac.ps
 *
 * See http://www.cs.arizona.edu/xkernel/ for their implementation.
 * The main aspects that distinguish this implementation from the
 * Arizona Vegas implementation are:
 *   o We do not change the loss detection or recovery mechanisms of
 *     Linux in any way. Linux already recovers from losses quite well,
 *     using fine-grained timers, NewReno, and FACK.
 *   o To avoid the performance penalty imposed by increasing cwnd
 *     only every-other RTT during slow start, we increase during
 *     every RTT during slow start, just like Reno.
 *   o Largely to allow continuous cwnd growth during slow start,
 *     we use the rate at which ACKs come back as the "actual"
 *     rate, rather than the rate at which data is sent.
 *   o To speed convergence to the right rate, we set the cwnd
 *     to achieve the right ("actual") rate when we exit slow start.
 *   o To filter out the noise caused by delayed ACKs, we use the
 *     minimum RTT sample observed during the last RTT to calculate
 *     the actual rate.
 *   o When the sender re-starts from idle, it waits until it has
 *     received ACKs for an entire flight of new data before making
 *     a cwnd adjustment decision. The original Vegas implementation
 *     assumed senders never went idle.
 */
static void vegas_cong_avoid(struct tcp_sock *tp, u32 ack, u32 seq_rtt)
{
	/* The key players are v_beg_snd_una and v_beg_snd_nxt.
	 *
	 * These are so named because they represent the approximate values
	 * of snd_una and snd_nxt at the beginning of the current RTT. More
	 * precisely, they represent the amount of data sent during the RTT.
	 * At the end of the RTT, when we receive an ACK for v_beg_snd_nxt,
	 * we will calculate that (v_beg_snd_nxt - v_beg_snd_una) outstanding
	 * bytes of data have been ACKed during the course of the RTT, giving
	 * an "actual" rate of:
	 *
	 *     (v_beg_snd_nxt - v_beg_snd_una) / (rtt duration)
	 *
	 * Unfortunately, v_beg_snd_una is not exactly equal to snd_una,
	 * because delayed ACKs can cover more than one segment, so they
	 * don't line up nicely with the boundaries of RTTs.
	 *
	 * Another unfortunate fact of life is that delayed ACKs delay the
	 * advance of the left edge of our send window, so that the number
	 * of bytes we send in an RTT is often less than our cwnd will allow.
	 * So we keep track of our cwnd separately, in v_beg_snd_cwnd.
	 */

	if (after(ack, tp->vegas.beg_snd_nxt)) {
		/* Do the Vegas once-per-RTT cwnd adjustment. */
		u32 old_wnd, old_snd_cwnd;

		
		/* Here old_wnd is essentially the window of data that was
		 * sent during the previous RTT, and has all
		 * been acknowledged in the course of the RTT that ended
		 * with the ACK we just received. Likewise, old_snd_cwnd
		 * is the cwnd during the previous RTT.
		 */
		old_wnd = (tp->vegas.beg_snd_nxt - tp->vegas.beg_snd_una) /
			tp->mss_cache_std;
		old_snd_cwnd = tp->vegas.beg_snd_cwnd;

		/* Save the extent of the current window so we can use this
		 * at the end of the next RTT.
		 */
		tp->vegas.beg_snd_una  = tp->vegas.beg_snd_nxt;
		tp->vegas.beg_snd_nxt  = tp->snd_nxt;
		tp->vegas.beg_snd_cwnd = tp->snd_cwnd;

		/* Take into account the current RTT sample too, to
		 * decrease the impact of delayed acks. This double counts
		 * this sample since we count it for the next window as well,
		 * but that's not too awful, since we're taking the min,
		 * rather than averaging.
		 */
		vegas_rtt_calc(tp, seq_rtt);

		/* We do the Vegas calculations only if we got enough RTT
		 * samples that we can be reasonably sure that we got
		 * at least one RTT sample that wasn't from a delayed ACK.
		 * If we only had 2 samples total,
		 * then that means we're getting only 1 ACK per RTT, which
		 * means they're almost certainly delayed ACKs.
		 * If  we have 3 samples, we should be OK.
		 */

		if (tp->vegas.cntRTT <= 2) {
			/* We don't have enough RTT samples to do the Vegas
			 * calculation, so we'll behave like Reno.
			 */
			if (tp->snd_cwnd > tp->snd_ssthresh)
				tp->snd_cwnd++;
		} else {
			u32 rtt, target_cwnd, diff;

			/* We have enough RTT samples, so, using the Vegas
			 * algorithm, we determine if we should increase or
			 * decrease cwnd, and by how much.
			 */

			/* Pluck out the RTT we are using for the Vegas
			 * calculations. This is the min RTT seen during the
			 * last RTT. Taking the min filters out the effects
			 * of delayed ACKs, at the cost of noticing congestion
			 * a bit later.
			 */
			rtt = tp->vegas.minRTT;

			/* Calculate the cwnd we should have, if we weren't
			 * going too fast.
			 *
			 * This is:
			 *     (actual rate in segments) * baseRTT
			 * We keep it as a fixed point number with
			 * V_PARAM_SHIFT bits to the right of the binary point.
			 */
			target_cwnd = ((old_wnd * tp->vegas.baseRTT)
				       << V_PARAM_SHIFT) / rtt;

			/* Calculate the difference between the window we had,
			 * and the window we would like to have. This quantity
			 * is the "Diff" from the Arizona Vegas papers.
			 *
			 * Again, this is a fixed point number with
			 * V_PARAM_SHIFT bits to the right of the binary
			 * point.
			 */
			diff = (old_wnd << V_PARAM_SHIFT) - target_cwnd;

			if (tp->snd_cwnd < tp->snd_ssthresh) {
				/* Slow start.  */
				if (diff > sysctl_tcp_vegas_gamma) {
					/* Going too fast. Time to slow down
					 * and switch to congestion avoidance.
					 */
					tp->snd_ssthresh = 2;

					/* Set cwnd to match the actual rate
					 * exactly:
					 *   cwnd = (actual rate) * baseRTT
					 * Then we add 1 because the integer
					 * truncation robs us of full link
					 * utilization.
					 */
					tp->snd_cwnd = min(tp->snd_cwnd,
							   (target_cwnd >>
							    V_PARAM_SHIFT)+1);

				}
			} else {
				/* Congestion avoidance. */
				u32 next_snd_cwnd;

				/* Figure out where we would like cwnd
				 * to be.
				 */
				if (diff > sysctl_tcp_vegas_beta) {
					/* The old window was too fast, so
					 * we slow down.
					 */
					next_snd_cwnd = old_snd_cwnd - 1;
				} else if (diff < sysctl_tcp_vegas_alpha) {
					/* We don't have enough extra packets
					 * in the network, so speed up.
					 */
					next_snd_cwnd = old_snd_cwnd + 1;
				} else {
					/* Sending just as fast as we
					 * should be.
					 */
					next_snd_cwnd = old_snd_cwnd;
				}

				/* Adjust cwnd upward or downward, toward the
				 * desired value.
				 */
				if (next_snd_cwnd > tp->snd_cwnd)
					tp->snd_cwnd++;
				else if (next_snd_cwnd < tp->snd_cwnd)
					tp->snd_cwnd--;
			}
		}

		/* Wipe the slate clean for the next RTT. */
		tp->vegas.cntRTT = 0;
		tp->vegas.minRTT = 0x7fffffff;
	}

	/* The following code is executed for every ack we receive,
	 * except for conditions checked in should_advance_cwnd()
	 * before the call to tcp_cong_avoid(). Mainly this means that
	 * we only execute this code if the ack actually acked some
	 * data.
	 */

	/* If we are in slow start, increase our cwnd in response to this ACK.
	 * (If we are not in slow start then we are in congestion avoidance,
	 * and adjust our congestion window only once per RTT. See the code
	 * above.)
	 */
	if (tp->snd_cwnd <= tp->snd_ssthresh) 
		tp->snd_cwnd++;

	/* to keep cwnd from growing without bound */
	tp->snd_cwnd = min_t(u32, tp->snd_cwnd, tp->snd_cwnd_clamp);

	/* Make sure that we are never so timid as to reduce our cwnd below
	 * 2 MSS.
	 *
	 * Going below 2 MSS would risk huge delayed ACKs from our receiver.
	 */
	tp->snd_cwnd = max(tp->snd_cwnd, 2U);

	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* ÓµÈû±ÜÃâ£¬Í¨¹ıµ÷ÓÃµ±Ç°µÄÓµÈû¿ØÖÆËã·¨ÖØĞÂ¼ÆËãÓµÈû´°¿Ú */
static inline void tcp_cong_avoid(struct tcp_sock *tp, u32 ack, u32 seq_rtt)
{
	if (tcp_vegas_enabled(tp))
		vegas_cong_avoid(tp, ack, seq_rtt);
	else
		reno_cong_avoid(tp);
}

/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */

static inline void tcp_ack_packets_out(struct sock *sk, struct tcp_sock *tp)
{
	if (!tp->packets_out) {
		tcp_clear_xmit_timer(sk, TCP_TIME_RETRANS);
	} else {
		tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);
	}
}

/* There is one downside to this scheme.  Although we keep the
 * ACK clock ticking, adjusting packet counters and advancing
 * congestion window, we do not liberate socket send buffer
 * space.
 *
 * Mucking with skb->truesize and sk->sk_wmem_alloc et al.
 * then making a write space wakeup callback is a possible
 * future enhancement.  WARNING: it is not trivial to make.
 */
static int tcp_tso_acked(struct sock *sk, struct sk_buff *skb,
			 __u32 now, __s32 *seq_rtt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb); 
	__u32 seq = tp->snd_una;
	__u32 packets_acked;
	int acked = 0;

	/* If we get here, the whole TSO packet has not been
	 * acked.
	 */
	BUG_ON(!after(scb->end_seq, seq));

	packets_acked = tcp_skb_pcount(skb);
	if (tcp_trim_head(sk, skb, seq - scb->seq))
		return 0;
	packets_acked -= tcp_skb_pcount(skb);

	if (packets_acked) {
		__u8 sacked = scb->sacked;

		acked |= FLAG_DATA_ACKED;
		if (sacked) {
			if (sacked & TCPCB_RETRANS) {
				if (sacked & TCPCB_SACKED_RETRANS)
					tp->retrans_out -= packets_acked;
				acked |= FLAG_RETRANS_DATA_ACKED;
				*seq_rtt = -1;
			} else if (*seq_rtt < 0)
				*seq_rtt = now - scb->when;
			if (sacked & TCPCB_SACKED_ACKED)
				tp->sacked_out -= packets_acked;
			if (sacked & TCPCB_LOST)
				tp->lost_out -= packets_acked;
			if (sacked & TCPCB_URG) {
				if (tp->urg_mode &&
				    !before(seq, tp->snd_up))
					tp->urg_mode = 0;
			}
		} else if (*seq_rtt < 0)
			*seq_rtt = now - scb->when;

		if (tp->fackets_out) {
			__u32 dval = min(tp->fackets_out, packets_acked);
			tp->fackets_out -= dval;
		}
		tp->packets_out -= packets_acked;

		BUG_ON(tcp_skb_pcount(skb) == 0);
		BUG_ON(!before(scb->seq, scb->end_seq));
	}

	return acked;
}


/* Remove acknowledged frames from the retransmission queue. */
/* É¾³ıÖØ´«¶ÓÁĞÖĞÒÑ¾­È·ÈÏµÄ¶Î */
static int tcp_clean_rtx_queue(struct sock *sk, __s32 *seq_rtt_p)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	__u32 now = tcp_time_stamp;
	int acked = 0;
	__s32 seq_rtt = -1;

	while ((skb = skb_peek(&sk->sk_write_queue)) &&
	       skb != sk->sk_send_head) {/* ±éÀúÖØ´«¶ÓÁĞ */
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb); 
		__u8 sacked = scb->sacked;

		/* If our packet is before the ack sequence we can
		 * discard it as it's confirmed to have arrived at
		 * the other end.
		 */
		if (after(scb->end_seq, tp->snd_una)) {/* µ±Ç°¶ÎÎ»ÓÚunaÖ®ºó£¬Ö»È·ÈÏÁË¶ÎµÄÒ»²¿·Ö */
			if (tcp_skb_pcount(skb) > 1)/* ÊÇTSO¶Î */
				acked |= tcp_tso_acked(sk, skb,
						       now, &seq_rtt);/* ½«ÒÑ¾­È·ÈÏµÄ²¿·Ö´ÓTCP¶ÎÖĞÉ¾³ı£¬Í¬Ê±¸üĞÂSBKÖĞGSOÆÆ¹ØĞÅÏ¢ */
			break;
		}

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		/* ÒÔÏÂµÄ¶Î¶¼ÊÇ±»ÍêÈ«È·ÈÏµÄ¡£ÉèÖÃacked±êÖ¾ */
		if (!(scb->flags & TCPCB_FLAG_SYN)) {
			acked |= FLAG_DATA_ACKED;
		} else {
			acked |= FLAG_SYN_ACKED;
			tp->retrans_stamp = 0;
		}

		if (sacked) {
			if (sacked & TCPCB_RETRANS) {/* ¶ÎÖØ´«¹ı */
				if(sacked & TCPCB_SACKED_RETRANS)
					tp->retrans_out -= tcp_skb_pcount(skb);
				acked |= FLAG_RETRANS_DATA_ACKED;
				seq_rtt = -1;
			} else if (seq_rtt < 0)/* ¶ÎÃ»ÓĞÖØ´«¹ı£¬»ñÈ¡Íù·µÊ±¼äºÍÊ±¼ä´Á */
				seq_rtt = now - scb->when;
			if (sacked & TCPCB_SACKED_ACKED)
				tp->sacked_out -= tcp_skb_pcount(skb);
			if (sacked & TCPCB_LOST)
				tp->lost_out -= tcp_skb_pcount(skb);
			if (sacked & TCPCB_URG) {/* ¶ÎÖĞ´æÔÚ´øÍâÊı¾İ */
				if (tp->urg_mode &&/* tcpÄ¿Ç°»¹´¦ÓÚ½ô¼±Ä£Ê½ */
				    !before(scb->end_seq, tp->snd_up))/* ´øÍâÊı¾İÎ»ÓÚÉÏ´ÎÖ¸Ê¾µÄ´øÍâÊı¾İÖ®ºó */
					tp->urg_mode = 0;/* ÓÃ»§ÒÑ¾­Ó¦´ğÁË´øÍâÊı¾İ£¬È¡Ïû½ô¼±Ä£Ê½ */
			}
		} else if (seq_rtt < 0)/* Î´»ñµÃ¶ÎµÄÍù·µÊ±¼ä */
			seq_rtt = now - scb->when;/* ÒÔ·¢ËÍ¸Ã¶ÎÓë½ÓÊÕµ½¸Ã¶ÎµÄACKÖ®¼äµÄÊ±¼ä×÷ÎªÍù·µ»ØÊ±¼ä */
		/* µ±Ç°¶ÎÒÑ¾­È·ÈÏ¹ıÁË£¬Òò´Ëµ÷ÓÃfackets_out£¬²¢½«¶Î´ÓÖØ´«¶ÓÁĞÖĞÉ¾³ı²¢ÊÍ·Å */
		tcp_dec_pcount_approx(&tp->fackets_out, skb);
		tcp_packets_out_dec(tp, skb);
		__skb_unlink(skb, skb->list);
		sk_stream_free_skb(sk, skb);
	}

	if (acked&FLAG_ACKED) {/* ±¾´Î´¦ÀíÓĞ¶ÔÊı¾İºÍSYNµÄÈ·ÈÏ */
		/* ²âÁ¿¸üĞÂÍù·µÊ±¼ä£¬²¢È·ÈÏÊÇ·ñÆô¶¯ÖØ´«¶¨Ê±Æ÷ */
		tcp_ack_update_rtt(tp, acked, seq_rtt);
		tcp_ack_packets_out(sk, tp);
	}

#if FASTRETRANS_DEBUG > 0
	BUG_TRAP((int)tp->sacked_out >= 0);
	BUG_TRAP((int)tp->lost_out >= 0);
	BUG_TRAP((int)tp->retrans_out >= 0);
	if (!tp->packets_out && tp->rx_opt.sack_ok) {
		if (tp->lost_out) {
			printk(KERN_DEBUG "Leak l=%u %d\n",
			       tp->lost_out, tp->ca_state);
			tp->lost_out = 0;
		}
		if (tp->sacked_out) {
			printk(KERN_DEBUG "Leak s=%u %d\n",
			       tp->sacked_out, tp->ca_state);
			tp->sacked_out = 0;
		}
		if (tp->retrans_out) {
			printk(KERN_DEBUG "Leak r=%u %d\n",
			       tp->retrans_out, tp->ca_state);
			tp->retrans_out = 0;
		}
	}
#endif
	*seq_rtt_p = seq_rtt;
	return acked;
}

static void tcp_ack_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Was it a usable window open? */

	if (!after(TCP_SKB_CB(sk->sk_send_head)->end_seq,
		   tp->snd_una + tp->snd_wnd)) {
		tp->backoff = 0;
		tcp_clear_xmit_timer(sk, TCP_TIME_PROBE0);
		/* Socket must be waked up by subsequent tcp_data_snd_check().
		 * This function is not for random using!
		 */
	} else {
		tcp_reset_xmit_timer(sk, TCP_TIME_PROBE0,
				     min(tp->rto << tp->backoff, TCP_RTO_MAX));
	}
}

static inline int tcp_ack_is_dubious(struct tcp_sock *tp, int flag)
{
	return (!(flag & FLAG_NOT_DUP) || (flag & FLAG_CA_ALERT) ||
		tp->ca_state != TCP_CA_Open);
}

static inline int tcp_may_raise_cwnd(struct tcp_sock *tp, int flag)
{
	return (!(flag & FLAG_ECE) || tp->snd_cwnd < tp->snd_ssthresh) &&
		!((1<<tp->ca_state)&(TCPF_CA_Recovery|TCPF_CA_CWR));
}

/* Check that window update is acceptable.
 * The function assumes that snd_una<=ack<=snd_next.
 */
static inline int tcp_may_update_window(struct tcp_sock *tp, u32 ack,
					u32 ack_seq, u32 nwin)
{
	return (after(ack, tp->snd_una) ||
		after(ack_seq, tp->snd_wl1) ||
		(ack_seq == tp->snd_wl1 && nwin > tp->snd_wnd));
}

/* Update our send window.
 *
 * Window update algorithm, described in RFC793/RFC1122 (used in linux-2.2
 * and in FreeBSD. NetBSD's one is even worse.) is wrong.
 */
/* ¸üĞÂ·¢ËÍ´°¿Ú */
static int tcp_ack_update_window(struct sock *sk, struct tcp_sock *tp,
				 struct sk_buff *skb, u32 ack, u32 ack_seq)
{
	int flag = 0;
	/* ´ÓTCPÊ×²¿ÖĞ»ñÈ¡½ÓÊÕ·½½ÓÊÕ´°¿Ú´óĞ¡ */
	u32 nwin = ntohs(skb->h.th->window);

	if (likely(!skb->h.th->syn))/* ²¢ÓÉ´°¿ÚÀ©´óÒò×Ó¼ÆËã³ö½ÓÊÕ´°¿ÚµÄ×Ö½ÚÊı */
		nwin <<= tp->rx_opt.snd_wscale;

	if (tcp_may_update_window(tp, ack, ack_seq, nwin)) {/* ÅĞ¶ÏÊÇ·ñĞèÒª¸üĞÂ·¢ËÍ·½µÄ·¢ËÍ´°¿Ú */
		flag |= FLAG_WIN_UPDATE;/* ¸üĞÂ±ê¼Ç */
		tcp_update_wl(tp, ack, ack_seq);/* ¼ÇÂ¼×îĞÂACKĞòºÅ */

		if (tp->snd_wnd != nwin) {/* ½ÓÊÕ·½µÄ½ÓÊÕ´°¿ÚÓë·¢ËÍ·½µÄ·¢ËÍ´°¿Ú²»ÏàµÈ */
			/* ÒÔ·¢ËÍ·½µÄ·¢ËÍ´°¿ÚÎª×¼ */
			tp->snd_wnd = nwin;

			/* Note, it is the only place, where
			 * fast path is recovered for sending TCP.
			 */
			tcp_fast_path_check(sk, tp);

			if (nwin > tp->max_window) {/* ½ÓÊÕ·½µÄ½ÓÊÕ´°¿Ú³¬¹ı×î´ó½ÓÊÕ´°¿Ú */
				/* ¸üĞÂ×î´ó½ÓÊÕ´°¿Ú£¬²¢ÖØĞÂ¼ÆËãMSS */
				tp->max_window = nwin;
				tcp_sync_mss(sk, tp->pmtu_cookie);
			}
		}
	}

	/* ¸üĞÂ·¢ËÍ´°¿Ú×ó¶Ë */
	tp->snd_una = ack;

	return flag;
}

/* µ±´¦ÓÚFRTO½×¶ÎÊ±£¬È·ÈÏ¶ÎÊÇ·ñÕæµÄ¶ªÊ§£¬ÒÔ¼°´«ËÍ³¬Ê±ÊÇ²»ÊÇĞé¼ÙµÄ */
static void tcp_process_frto(struct sock *sk, u32 prior_snd_una)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* ½ÓÊÕµ½ACKºó£¬Ë¢ĞÂÃ»ÓĞÈ·ÈÏµÄTCP¶ÎÊıÁ¿ */
	tcp_sync_left_out(tp);
	
	if (tp->snd_una == prior_snd_una ||
	    !before(tp->snd_una, tp->frto_highmark)) {/* ½ÓÊÕµ½µÄACKÊÇÖØ¸´µÄ£¬ËµÃ÷´«ËÍ³¬Ê±ÊÇÕæµÄ */
		/* RTO was caused by loss, start retransmitting in
		 * go-back-N slow start
		 */
		tcp_enter_frto_loss(sk);/* ½øÈëÓµÈû»Ö¸´½×¶Î */
		return;
	}

	if (tp->frto_counter == 1) {/* ½øÈëFRTOºó½ÓÊÕµÄµÚÒ»¸öACK */
		/* First ACK after RTO advances the window: allow two new
		 * segments out.
		 */
		/* ÖØĞÂÉèÖÃÓµÈû´°¿Ú£¬ÔÊĞíÔÙ·¢ËÍÁ½¸ö±¨ÎÄ */
		tp->snd_cwnd = tcp_packets_in_flight(tp) + 2;
	} else {/* ½øÈëFRTOºó£¬½ÓÊÕµ½µÄµÚ¶ş¸öACK */
		/* Also the second ACK after RTO advances the window.
		 * The RTO was likely spurious. Reduce cwnd and continue
		 * in congestion avoidance
		 */
		/* ½øÒ»²½µ÷ÕûÓµÈû´°¿Ú */
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
		tcp_moderate_cwnd(tp);
	}

	/* F-RTO affects on two new ACKs following RTO.
	 * At latest on third ACK the TCP behavor is back to normal.
	 */
	/* Ôö¼Ó¼ÆÊı£¬Èç¹ûÁ¬Ğø½ÓÊÕµ½Á½¸ö¶ÔĞÂÊı¾İµÄÈ·ÈÏ£¬ÔòËµÃ÷´«ËÍ³¬Ê±ÊÇĞé¼ÙµÄ£¬ÍË³öFRTO»Ö¸´ */
	tp->frto_counter = (tp->frto_counter + 1) % 3;
}

/*
 * TCP Westwood+
 */

/*
 * @init_westwood
 * This function initializes fields used in TCP Westwood+. We can't
 * get no information about RTTmin at this time so we simply set it to
 * TCP_WESTWOOD_INIT_RTT. This value was chosen to be too conservative
 * since in this way we're sure it will be updated in a consistent
 * way as soon as possible. It will reasonably happen within the first
 * RTT period of the connection lifetime.
 */

static void init_westwood(struct sock *sk)
{
        struct tcp_sock *tp = tcp_sk(sk);

        tp->westwood.bw_ns_est = 0;
        tp->westwood.bw_est = 0;
        tp->westwood.accounted = 0;
        tp->westwood.cumul_ack = 0;
        tp->westwood.rtt_win_sx = tcp_time_stamp;
        tp->westwood.rtt = TCP_WESTWOOD_INIT_RTT;
        tp->westwood.rtt_min = TCP_WESTWOOD_INIT_RTT;
        tp->westwood.snd_una = tp->snd_una;
}

/*
 * @westwood_do_filter
 * Low-pass filter. Implemented using constant coeffients.
 */

static inline __u32 westwood_do_filter(__u32 a, __u32 b)
{
	return (((7 * a) + b) >> 3);
}

static void westwood_filter(struct sock *sk, __u32 delta)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->westwood.bw_ns_est =
		westwood_do_filter(tp->westwood.bw_ns_est, 
				   tp->westwood.bk / delta);
	tp->westwood.bw_est =
		westwood_do_filter(tp->westwood.bw_est,
				   tp->westwood.bw_ns_est);
}

/* 
 * @westwood_update_rttmin
 * It is used to update RTTmin. In this case we MUST NOT use
 * WESTWOOD_RTT_MIN minimum bound since we could be on a LAN!
 */

static inline __u32 westwood_update_rttmin(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	__u32 rttmin = tp->westwood.rtt_min;

	if (tp->westwood.rtt != 0 &&
	    (tp->westwood.rtt < tp->westwood.rtt_min || !rttmin))
		rttmin = tp->westwood.rtt;

	return rttmin;
}

/*
 * @westwood_acked
 * Evaluate increases for dk. 
 */

static inline __u32 westwood_acked(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return tp->snd_una - tp->westwood.snd_una;
}

/*
 * @westwood_new_window
 * It evaluates if we are receiving data inside the same RTT window as
 * when we started.
 * Return value:
 * It returns 0 if we are still evaluating samples in the same RTT
 * window, 1 if the sample has to be considered in the next window.
 */

static int westwood_new_window(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	__u32 left_bound;
	__u32 rtt;
	int ret = 0;

	left_bound = tp->westwood.rtt_win_sx;
	rtt = max(tp->westwood.rtt, (u32) TCP_WESTWOOD_RTT_MIN);

	/*
	 * A RTT-window has passed. Be careful since if RTT is less than
	 * 50ms we don't filter but we continue 'building the sample'.
	 * This minimum limit was choosen since an estimation on small
	 * time intervals is better to avoid...
	 * Obvioulsy on a LAN we reasonably will always have
	 * right_bound = left_bound + WESTWOOD_RTT_MIN
         */

	if ((left_bound + rtt) < tcp_time_stamp)
		ret = 1;

	return ret;
}

/*
 * @westwood_update_window
 * It updates RTT evaluation window if it is the right moment to do
 * it. If so it calls filter for evaluating bandwidth. 
 */

static void __westwood_update_window(struct sock *sk, __u32 now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 delta = now - tp->westwood.rtt_win_sx;

        if (delta) {
		if (tp->westwood.rtt)
			westwood_filter(sk, delta);

		tp->westwood.bk = 0;
		tp->westwood.rtt_win_sx = tcp_time_stamp;
	}
}


static void westwood_update_window(struct sock *sk, __u32 now)
{
	if (westwood_new_window(sk)) 
		__westwood_update_window(sk, now);
}

/*
 * @__tcp_westwood_fast_bw
 * It is called when we are in fast path. In particular it is called when
 * header prediction is successfull. In such case infact update is
 * straight forward and doesn't need any particular care.
 */

static void __tcp_westwood_fast_bw(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	westwood_update_window(sk, tcp_time_stamp);

	tp->westwood.bk += westwood_acked(sk);
	tp->westwood.snd_una = tp->snd_una;
	tp->westwood.rtt_min = westwood_update_rttmin(sk);
}

static inline void tcp_westwood_fast_bw(struct sock *sk, struct sk_buff *skb)
{
        if (tcp_is_westwood(tcp_sk(sk)))
                __tcp_westwood_fast_bw(sk, skb);
}


/*
 * @westwood_dupack_update
 * It updates accounted and cumul_ack when receiving a dupack.
 */

static void westwood_dupack_update(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->westwood.accounted += tp->mss_cache_std;
	tp->westwood.cumul_ack = tp->mss_cache_std;
}

static inline int westwood_may_change_cumul(struct tcp_sock *tp)
{
	return (tp->westwood.cumul_ack > tp->mss_cache_std);
}

static inline void westwood_partial_update(struct tcp_sock *tp)
{
	tp->westwood.accounted -= tp->westwood.cumul_ack;
	tp->westwood.cumul_ack = tp->mss_cache_std;
}

static inline void westwood_complete_update(struct tcp_sock *tp)
{
	tp->westwood.cumul_ack -= tp->westwood.accounted;
	tp->westwood.accounted = 0;
}

/*
 * @westwood_acked_count
 * This function evaluates cumul_ack for evaluating dk in case of
 * delayed or partial acks.
 */

static inline __u32 westwood_acked_count(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->westwood.cumul_ack = westwood_acked(sk);

        /* If cumul_ack is 0 this is a dupack since it's not moving
         * tp->snd_una.
         */
        if (!(tp->westwood.cumul_ack))
                westwood_dupack_update(sk);

        if (westwood_may_change_cumul(tp)) {
		/* Partial or delayed ack */
		if (tp->westwood.accounted >= tp->westwood.cumul_ack)
			westwood_partial_update(tp);
		else
			westwood_complete_update(tp);
	}

	tp->westwood.snd_una = tp->snd_una;

	return tp->westwood.cumul_ack;
}


/*
 * @__tcp_westwood_slow_bw
 * It is called when something is going wrong..even if there could
 * be no problems! Infact a simple delayed packet may trigger a
 * dupack. But we need to be careful in such case.
 */

static void __tcp_westwood_slow_bw(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	westwood_update_window(sk, tcp_time_stamp);

	tp->westwood.bk += westwood_acked_count(sk);
	tp->westwood.rtt_min = westwood_update_rttmin(sk);
}

static inline void tcp_westwood_slow_bw(struct sock *sk, struct sk_buff *skb)
{
        if (tcp_is_westwood(tcp_sk(sk)))
                __tcp_westwood_slow_bw(sk, skb);
}

/* This routine deals with incoming acks, but not outgoing ones. */
/* ´¦Àí½ÓÊÕµ½µÄack±¨ÎÄ */
static int tcp_ack(struct sock *sk, struct sk_buff *skb, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 prior_snd_una = tp->snd_una;
	u32 ack_seq = TCP_SKB_CB(skb)->seq;
	u32 ack = TCP_SKB_CB(skb)->ack_seq;
	u32 prior_in_flight;
	s32 seq_rtt;
	int prior_packets;

	/* If the ack is newer than sent or older than previous acks
	 * then we can probably ignore it.
	 */
	if (after(ack, tp->snd_nxt))/* È·ÈÏµÄĞòºÅ´óÓÚnxt£¬²»ºÏ·¨ */
		goto uninteresting_ack;

	if (before(ack, prior_snd_una))/* È·ÈÏµÄĞòºÅĞ¡ÓÚuna£¬²»ºÏ·¨ */
		goto old_ack;

	if (!(flag&FLAG_SLOWPATH) && after(ack, prior_snd_una)) {/* ¿ìËÙÂ·¾¶£¬²¢ÇÒ¸üĞÂÁËuna */
		/* Window is constant, pure forward advance.
		 * No more checks are required.
		 * Note, we use the fact that SND.UNA>=SND.WL2.
		 */
		/* ¸üĞÂ·¢ËÍ´°¿Ú×ó±ß½ç */
		tcp_update_wl(tp, ack, ack_seq);
		tp->snd_una = ack;
		/* Í¨ÖªÓµÈû¿ØÖÆËã·¨±¾´ÎACKÊÇ¿ìËÙÂ·¾¶ */
		tcp_westwood_fast_bw(sk, skb);
		flag |= FLAG_WIN_UPDATE;

		NET_INC_STATS_BH(LINUX_MIB_TCPHPACKS);
	} else {/* ÂıËÙÂ·¾¶ */
		if (ack_seq != TCP_SKB_CB(skb)->end_seq)/* ±¨ÎÄÖĞ°üº¬ÓĞÊı¾İ */
			flag |= FLAG_DATA;
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPPUREACKS);

		/* ¸üĞÂ·¢ËÍ´°¿Ú */
		flag |= tcp_ack_update_window(sk, tp, skb, ack, ack_seq);

		if (TCP_SKB_CB(skb)->sacked)/* Èç¹ûÓĞsack±êÖ¾£¬Ôò±ê¼ÇÖØ´«¶ÓÁĞ */
			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);

		if (TCP_ECN_rcv_ecn_echo(tp, skb->h.th))/* Èç¹ûACK¶ÎÖĞ´æÔÚECE±êÖ¾ */
			flag |= FLAG_ECE;

		/* Í¨ÖªÓµÈû¿ØÖÆËã·¨±¾´ÎACKÊÇÂıËÙÂ·¾¶ */
		tcp_westwood_slow_bw(sk,skb);
	}

	/* We passed data and got it acked, remove any soft error
	 * log. Something worked...
	 */
	sk->sk_err_soft = 0;
	/* ¼ÇÂ¼×î½üÒ»´ÎÊÕµ½ACKµÄÊ±¼ä */
	tp->rcv_tstamp = tcp_time_stamp;
	prior_packets = tp->packets_out;
	if (!prior_packets)/* Èç¹ûÃ»ÓĞÒÑ¾­·¢³öµ«»¹Ã»ÓĞÈ·ÈÏµÄ¶Î */
		goto no_queue;

	/* ÕıÔÚ´«ÊäµÄ¶ÎÊı */
	prior_in_flight = tcp_packets_in_flight(tp);

	/* See if we can take anything off of the retransmit queue. */
	/* ÔÚÖØ´«¶ÓÁĞÖĞÉ¾³ıÒÑÈ·ÈÏµÄ¶Î */
	flag |= tcp_clean_rtx_queue(sk, &seq_rtt);

	if (tp->frto_counter)/* µ±Ç°´¦ÓÚFRTO½×¶Î£¬½øĞĞ´¦ÀíÒÔÅĞ¶ÏÊÇ·ñÕæµÄ³¬Ê± */
		tcp_process_frto(sk, prior_snd_una);

	/* ²»Ã÷È·????»òÕßÓµÈû×´Ì¬²»ÊÇopen£¬Ôò½øĞĞÓµÈû×´Ì¬»ú×´Ì¬µÄÇ¨ÒÆ¡£ */
	if (tcp_ack_is_dubious(tp, flag)) {/* ½ÓÊÕµ½µÄACKÊÇÖØ¸´µÄ£¬»òÕß½ÓÊÕµ½SACK¿é»òÏÔÊ½ÓµÈûÍ¨Öª£¬»òÕßµ±Ç°×´Ì¬²»ÊÇopen */
		/* Advanve CWND, if state allows this. */
		if ((flag & FLAG_DATA_ACKED) &&/* È·ÈÏÁËĞÂµÄ¶Î */
		    (tcp_vegas_enabled(tp) || prior_in_flight >= tp->snd_cwnd) &&
		    tcp_may_raise_cwnd(tp, flag))/* ÓµÈû´°¿Ú¿ÉÒÔ¸üĞÂ */
			tcp_cong_avoid(tp, ack, seq_rtt);/* ½øĞĞÓµÈû±ÜÃâ */
		/* ÓµÈû¿ØÖÆ×´Ì¬µÄ´¦Àí */
		tcp_fastretrans_alert(sk, prior_snd_una, prior_packets, flag);
	} else {
		if ((flag & FLAG_DATA_ACKED) && /* È·ÈÏÁËĞÂµÄ¶Î */
		    (tcp_vegas_enabled(tp) || prior_in_flight >= tp->snd_cwnd))
			tcp_cong_avoid(tp, ack, seq_rtt);/* ½øĞĞÓµÈû±ÜÃâ */
	}

	/* Èç¹ûÈ·ÈÏÁËĞÂµÄ¶Î£¬»òÕß½ÓÊÕµ½µÄACKÊÇÖØ¸´µÄ£¬ÔòÈ·ÈÏÊä³öÂ·ÓÉÊÇÓĞĞ§µÄ */
	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag&FLAG_NOT_DUP))
		dst_confirm(sk->sk_dst_cache);

	return 1;

no_queue:
	/* ÓÉÓÚ½ÓÊÕµ½¶Ô¶ËµÄack£¬Òò´Ë½«TCP±£»îÌ½²â¶ÎÎ´È·ÈÏÊıÇå0£¬ËµÃ÷´ËÊ±TCPÁ¬½ÓÊÇÕı³£µÄ */
	tp->probes_out = 0;

	/* If this ack opens up a zero window, clear backoff.  It was
	 * being used to time the probes, and is probably far higher than
	 * it needs to be for normal retransmission.
	 */
	if (sk->sk_send_head)/* »¹ÓĞ´ı·¢ËÍµÄÊı¾İ */
		/* ½ÓÊÕµ½ackºó£¬Èç¹û¶Ô·½½ÓÊÕ´°¿ÚÃ»ÓĞ¹Ø±Õ£¬ÔòÇå³ı³ÖĞø¶¨Ê±Æ÷ÖĞÖ¸ÊıÍË±ÜËã·¨Ö¸Êı£¬Í£Ö¹³ÖĞø¶¨Ê±Æ÷£¬·ñÔò¿ªÆô³ÖĞø¶¨Ê±Æ÷ */
		tcp_ack_probe(sk);/* tcp_ack_probeÓÃÀ´È·¶¨ÊÇ·ñĞèÒª½øĞĞ0´°¿ÚÌ½²â */
	return 1;

old_ack:
	if (TCP_SKB_CB(skb)->sacked)/* Èç¹ûÊÇÒÑ¾­È·ÈÏ¹ıµÄACK£¬²¢ÇÒÆäÖĞ´øÓĞSACKÑ¡ÏîĞÅÏ¢£¬Ôò±ê¼ÇÖØ´«¶ÓÁĞÖĞ¸÷¸ö¶ÎµÄ¼Ç·ÖÅÆ */
		tcp_sacktag_write_queue(sk, skb, prior_snd_una);

uninteresting_ack:
	SOCK_DEBUG(sk, "Ack %u out of %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return 0;
}


/* Look for tcp options. Normally only called on SYN and SYNACK packets.
 * But, this can also be called on packets in the established flow when
 * the fast version below fails.
 */
/* ÍêÕûµÄ½âÎöÊ±¼ä´ÁÑ¡Ïî£¬³ıÁËÔÚ·ÖÎöSYNºÍSYN+ACK¶ÎÊ±µ÷ÓÃÍâ£¬ÔÚÂıËÙÁ÷³ÌÖĞÒ²µ÷ÓÃ£¬ÒÔ½âÎö³ıÊ±¼ä´ÁÍâµÄÆäËûÑ¡Ïî */
void tcp_parse_options(struct sk_buff *skb, struct tcp_options_received *opt_rx, int estab)
{
	unsigned char *ptr;
	struct tcphdr *th = skb->h.th;
	int length=(th->doff*4)-sizeof(struct tcphdr);

	ptr = (unsigned char *)(th + 1);
	opt_rx->saw_tstamp = 0;

	while(length>0) {/* ±éÀúÑ¡Ïî£¬Ö±µ½ËùÓĞÑ¡Ïî·ÖÎöÍê±Ï */
	  	int opcode=*ptr++;/* Ñ¡ÏîÀàĞÍ */
		int opsize;

		switch (opcode) {
			case TCPOPT_EOL:
				return;/* Ñ¡Ïî½áÊø£¬·µ»Ø */
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;/* NOPÑ¡Ïî£¬Ö±½ÓÌøµ½ÏÂÒ»¸öÑ¡Ïî */
			default:
				opsize=*ptr++;/* »ñµÃÑ¡Ïî³¤¶È£¬²¢ÅĞ¶ÏÆäºÏ·¨ĞÔ  */
				if (opsize < 2) /* "silly options" */
					return;
				if (opsize > length)/* ³¬¹ıÑ¡Ïî×Ü³¤¶È£¬·Ç·¨Ñ¡Ïî */
					return;	/* don't parse partial options */
	  			switch(opcode) {
				case TCPOPT_MSS:/* MSSÍ¨¸æÑ¡Ïî */
					if(opsize==TCPOLEN_MSS && th->syn && !estab) {/* ´ËÑ¡Ïî½öÄÜ³öÏÖÔÚSYN¶ÎÖĞ,²¢ÇÒ²»ÄÜÔÚ½ÓÊÕ±¨ÎÄ½×¶Îµ÷ÓÃ */
						u16 in_mss = ntohs(*(__u16 *)ptr);
						if (in_mss) {/* »ñÈ¡Í¨¸æ´°¿Ú´óĞ¡ */
							/* Èç¹ûÍ¨¸æ´°¿Ú´óÓÚÓÃ»§ÉèÖÃµÄ´°¿Ú£¬ÔòÒÔÉèÖÃµÄ´°¿ÚÎª×¼ */
							if (opt_rx->user_mss && opt_rx->user_mss < in_mss)
								in_mss = opt_rx->user_mss;
							opt_rx->mss_clamp = in_mss;/* ÉèÖÃMSS×î´óÖµ */
						}
					}
					break;
				case TCPOPT_WINDOW:
					/* À©´óÒò×ÓÒ²Ö»ÄÜ³öÏÖÔÚSYN¶ÎÖĞ */
					if(opsize==TCPOLEN_WINDOW && th->syn && !estab)
						if (sysctl_tcp_window_scaling) {
							opt_rx->wscale_ok = 1;
							opt_rx->snd_wscale = *(__u8 *)ptr;
							if(opt_rx->snd_wscale > 14) {/* ´°¿ÚÀ©´óÒò×Ó²»ÄÜ´óÓÚ14 */
								if(net_ratelimit())
									printk(KERN_INFO "tcp_parse_options: Illegal window "
									       "scaling value %d >14 received.\n",
									       opt_rx->snd_wscale);
								opt_rx->snd_wscale = 14;
							}
						}
					break;
				case TCPOPT_TIMESTAMP:
					if(opsize==TCPOLEN_TIMESTAMP) {/* Ê±¼ä´ÁÑ¡Ïî£¬ÅĞ¶ÏÆä³¤¶ÈÊÇ·ñºÏ·¨ */
						if ((estab && opt_rx->tstamp_ok) ||
						    (!estab && sysctl_tcp_timestamps)) {
							opt_rx->saw_tstamp = 1;
							opt_rx->rcv_tsval = ntohl(*(__u32 *)ptr);
							opt_rx->rcv_tsecr = ntohl(*(__u32 *)(ptr+4));
						}
					}
					break;
				case TCPOPT_SACK_PERM:
					/* SACKÔÊĞíÑ¡ÏîÖ»ÄÜ³öÏÖÔÚSYN¶ÎÖĞ */
					if(opsize==TCPOLEN_SACK_PERM && th->syn && !estab) {
						if (sysctl_tcp_sack) {
							opt_rx->sack_ok = 1;/* ÔÊĞíSACK */
							tcp_sack_reset(opt_rx);
						}
					}
					break;

				case TCPOPT_SACK:
					if((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)) &&/* ÖÁÉÙ°üº¬Ò»¸öSACK */
					   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK) &&/* SACK±ß½çÅĞ¶Ï */
					   opt_rx->sack_ok) {/* ÔÊĞíSACK */
					   /* ½«sackedÖ¸ÏòSACKÊı¾İ¿ªÊ¼´¦ */
						TCP_SKB_CB(skb)->sacked = (ptr - 2) - (unsigned char *)th;
					}
	  			};
	  			ptr+=opsize-2;
	  			length-=opsize;
	  	};
	}
}

/* Fast parse options. This hopes to only see timestamps.
 * If it is wrong it falls back on tcp_parse_options().
 */
/* ÔÚTCPÂıËÙ½ÓÊÕ±¨ÎÄµÄ½×¶Î£¬µ÷ÓÃ´Ëº¯Êı½âÎöTCPÑ¡Ïî */
static inline int tcp_fast_parse_options(struct sk_buff *skb, struct tcphdr *th,
					 struct tcp_sock *tp)
{
	if (th->doff == sizeof(struct tcphdr)>>2) {/* Ã»ÓĞÑ¡Ïî */
		tp->rx_opt.saw_tstamp = 0;/* ½«Ê±¼ä´Á±êÖ¾ÉèÖÃ0ºóÍË³ö */
		return 0;
	} else if (tp->rx_opt.tstamp_ok &&/* ÆôÓÃÊ±¼ä´ÁÑ¡Ïî */
		   th->doff == (sizeof(struct tcphdr)>>2)+(TCPOLEN_TSTAMP_ALIGNED>>2)) {/* ²¢ÇÒ½ö½öÖ»¿ÉÄÜÓĞÊ±¼ä´ÁÑ¡Ïî */
		__u32 *ptr = (__u32 *)(th + 1);
		if (*ptr == ntohl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
				  | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)) {/* ÅĞ¶Ï¸ÃÑ¡ÏîÊÇ·ñÊÇÊ±¼ä´Á */
			/* »ñÈ¡Ê±¼ä´ÁµÄÖµ */
			tp->rx_opt.saw_tstamp = 1;
			++ptr;
			tp->rx_opt.rcv_tsval = ntohl(*ptr);
			++ptr;
			tp->rx_opt.rcv_tsecr = ntohl(*ptr);
			return 1;
		}
	}
	/* ³ıÁËÊ±¼ä´ÁÍâ£¬»¹ÓĞÆäËûÑ¡Ïî¡£ */
	tcp_parse_options(skb, &tp->rx_opt, 1);
	return 1;
}

static inline void tcp_store_ts_recent(struct tcp_sock *tp)
{
	tp->rx_opt.ts_recent = tp->rx_opt.rcv_tsval;
	tp->rx_opt.ts_recent_stamp = xtime.tv_sec;
}

static inline void tcp_replace_ts_recent(struct tcp_sock *tp, u32 seq)
{
	if (tp->rx_opt.saw_tstamp && !after(seq, tp->rcv_wup)) {
		/* PAWS bug workaround wrt. ACK frames, the PAWS discard
		 * extra check below makes sure this can only happen
		 * for pure ACK frames.  -DaveM
		 *
		 * Not only, also it occurs for expired timestamps.
		 */

		if((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) >= 0 ||
		   xtime.tv_sec >= tp->rx_opt.ts_recent_stamp + TCP_PAWS_24DAYS)
			tcp_store_ts_recent(tp);
	}
}

/* Sorry, PAWS as specified is broken wrt. pure-ACKs -DaveM
 *
 * It is not fatal. If this ACK does _not_ change critical state (seqs, window)
 * it can pass through stack. So, the following predicate verifies that
 * this segment is not used for anything but congestion avoidance or
 * fast retransmit. Moreover, we even are able to eliminate most of such
 * second order effects, if we apply some small "replay" window (~RTO)
 * to timestamp space.
 *
 * All these measures still do not guarantee that we reject wrapped ACKs
 * on networks with high bandwidth, when sequence space is recycled fastly,
 * but it guarantees that such events will be very rare and do not affect
 * connection seriously. This doesn't look nice, but alas, PAWS is really
 * buggy extension.
 *
 * [ Later note. Even worse! It is buggy for segments _with_ data. RFC
 * states that events when retransmit arrives after original data are rare.
 * It is a blatant lie. VJ forgot about fast retransmit! 8)8) It is
 * the biggest problem on large power networks even with minor reordering.
 * OK, let's give it small replay window. If peer clock is even 1hz, it is safe
 * up to bandwidth of 18Gigabit/sec. 8) ]
 */

static int tcp_disordered_ack(struct tcp_sock *tp, struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	u32 seq = TCP_SKB_CB(skb)->seq;
	u32 ack = TCP_SKB_CB(skb)->ack_seq;

	return (/* 1. Pure ACK with correct sequence number. */
		(th->ack && seq == TCP_SKB_CB(skb)->end_seq && seq == tp->rcv_nxt) &&

		/* 2. ... and duplicate ACK. */
		ack == tp->snd_una &&

		/* 3. ... and does not update window. */
		!tcp_may_update_window(tp, ack, seq, ntohs(th->window) << tp->rx_opt.snd_wscale) &&

		/* 4. ... and sits in replay window. */
		(s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) <= (tp->rto*1024)/HZ);
}

static inline int tcp_paws_discard(struct tcp_sock *tp, struct sk_buff *skb)
{
	return ((s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) > TCP_PAWS_WINDOW &&
		xtime.tv_sec < tp->rx_opt.ts_recent_stamp + TCP_PAWS_24DAYS &&
		!tcp_disordered_ack(tp, skb));
}

/* Check segment sequence number for validity.
 *
 * Segment controls are considered valid, if the segment
 * fits to the window after truncation to the window. Acceptability
 * of data (and SYN, FIN, of course) is checked separately.
 * See tcp_data_queue(), for example.
 *
 * Also, controls (RST is main one) are accepted using RCV.WUP instead
 * of RCV.NXT. Peer still did not advance his SND.UNA when we
 * delayed ACK, so that hisSND.UNA<=ourRCV.WUP.
 * (borrowed from freebsd)
 */

static inline int tcp_sequence(struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	return	!before(end_seq, tp->rcv_wup) &&
		!after(seq, tp->rcv_nxt + tcp_receive_window(tp));
}

/* When we get a reset we do this. */
static void tcp_reset(struct sock *sk)
{
	/* We want the right error as BSD sees it (and indeed as we do). */
	switch (sk->sk_state) {
		case TCP_SYN_SENT:
			sk->sk_err = ECONNREFUSED;
			break;
		case TCP_CLOSE_WAIT:
			sk->sk_err = EPIPE;
			break;
		case TCP_CLOSE:
			return;
		default:
			sk->sk_err = ECONNRESET;
	}

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);

	tcp_done(sk);
}

/*
 * 	Process the FIN bit. This now behaves as it is supposed to work
 *	and the FIN takes effect when it is validly part of sequence
 *	space. Not before when we get holes.
 *
 *	If we are ESTABLISHED, a received fin moves us to CLOSE-WAIT
 *	(and thence onto LAST-ACK and finally, CLOSE, we never enter
 *	TIME-WAIT)
 *
 *	If we are in FINWAIT-1, a received FIN indicates simultaneous
 *	close and we go into CLOSING (and later onto TIME-WAIT)
 *
 *	If we are in FINWAIT-2, a received FIN moves us to TIME-WAIT.
 */
/* µ±Ì×½Ó¿Ú½ÓÊÕµ½FIN¶Îºó£¬Í¨ÖªµÈ´ıµÄ½ø³Ì */
static void tcp_fin(struct sk_buff *skb, struct sock *sk, struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_schedule_ack(tp);/* ½ÓÊÕµ½FINºó£¬ĞèÒª·¢ËÍACK */

	sk->sk_shutdown |= RCV_SHUTDOWN;/* ½ÓÊÕ¹Ø±Õ */
	sock_set_flag(sk, SOCK_DONE);/* Ì×¿Ú¼´½«½áÊø£¬²»ÔÙ½ÓÊÕºóÃæµÄÊı¾İ */

	switch (sk->sk_state) {
		case TCP_SYN_RECV:
		case TCP_ESTABLISHED:
			/* Move to CLOSE_WAIT */
			/* ÕâÖÖÇé¿öÏÂ£¬ÉèÖÃ×´Ì¬ÎªTCP_CLOSE_WAIT£¬²¢ÑÓÊ±·¢ËÍACK */
			tcp_set_state(sk, TCP_CLOSE_WAIT);
			tp->ack.pingpong = 1;
			break;

		case TCP_CLOSE_WAIT:
		case TCP_CLOSING:/* ÕâÁ½ÖÖÇé¿öÏÂ£¬ÊÕµ½µÄFINÓ¦µ±ÊÇÖØ¸´¶Î£¬ºöÂÔ */
			/* Received a retransmission of the FIN, do
			 * nothing.
			 */
			break;
		case TCP_LAST_ACK:
			/* RFC793: Remain in the LAST-ACK state. */
			break;

		case TCP_FIN_WAIT1:/* ´Ë×´Ì¬±íÊ¾Á½¶ËÍ¬Ê±¹Ø±Õ */
			/* This case occurs when a simultaneous close
			 * happens, we must ack the received FIN and
			 * enter the CLOSING state.
			 */
			/* ¸ù¾İĞ­Òé£¬Ó¦µ±Ïò¶Ô·½·¢ËÍACK£¬²¢ÇÒ×ª»»µ½CLOSING×´Ì¬ */
			tcp_send_ack(sk);
			tcp_set_state(sk, TCP_CLOSING);
			break;
		case TCP_FIN_WAIT2:
			/* Received a FIN -- send ACK and enter TIME_WAIT. */
			/* ¸ù¾İ×´Ì¬Í¼£¬ÕâÖÖÇé¿öÏÂÓ¦µ±Ïò¶Ô·½·¢ËÍACK²¢½øÈëµ½TIME_WAIT×´Ì¬ */
			tcp_send_ack(sk);
			tcp_time_wait(sk, TCP_TIME_WAIT, 0);
			break;
		default:/* LISTENºÍCLOSE×´Ì¬ºöÂÔFIN¶Î */
			/* Only TCP_LISTEN and TCP_CLOSE are left, in these
			 * cases we should never reach this piece of code.
			 */
			printk(KERN_ERR "%s: Impossible, sk->sk_state=%d\n",
			       __FUNCTION__, sk->sk_state);
			break;
	};

	/* It _is_ possible, that we have something out-of-order _after_ FIN.
	 * Probably, we should reset in this case. For now drop them.
	 */
	/* Çå¿Õ½ÓÊÕµ½ÂÒĞò¶ÓÁĞÉÏµÄ¶Î */
	__skb_queue_purge(&tp->out_of_order_queue);
	if (tp->rx_opt.sack_ok)/* Çå³ıSACK±êÖ¾ */
		tcp_sack_reset(&tp->rx_opt);
	/* ÊÍ·ÅÌ×½Ó¿ÚÉÏµÄ»º´æ */
	sk_stream_mem_reclaim(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {/* Á¬½Ó»¹Ã»ÓĞÖÕÖ¹ */
		sk->sk_state_change(sk);/* »½ĞÑµÈ´ıÌ×¿ÚµÄ½ø³Ì */

		/* Do not send POLL_HUP for half duplex close. */
		if (sk->sk_shutdown == SHUTDOWN_MASK ||
		    sk->sk_state == TCP_CLOSE)/* ¶ÁĞ´ÒÑ¾­¹Ø±ÕÁË£¬Í¨ÖªÒì²½µÈ´ıµÄÏß³Ì */
			sk_wake_async(sk, 1, POLL_HUP);
		else/* Ö»¹Ø±ÕÁË¶Á£¬ÔòÍ¨ÖªÒì²½µÈ´ıµÄÏß³Ì£¬¶ÁÍ¨µÀ±»¹Ø±Õ */
			sk_wake_async(sk, 1, POLL_IN);
	}
}

static __inline__ int
tcp_sack_extend(struct tcp_sack_block *sp, u32 seq, u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return 1;
	}
	return 0;
}

/* µ±½ÓÊÕµ½ÖØ¸´¶ÎÊ±£¬Èç¹ûÆôÓÃÁËDSACK£¬Ôòµ÷ÓÃ´Ëº¯ÊıÉèÖÃÓÃÓÚ¹¹³ÉSACKÑ¡ÏîµÄduplicate_sackÊı×é */
static inline void tcp_dsack_set(struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	if (tp->rx_opt.sack_ok && sysctl_tcp_dsack) {
		if (before(seq, tp->rcv_nxt))
			NET_INC_STATS_BH(LINUX_MIB_TCPDSACKOLDSENT);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPDSACKOFOSENT);

		tp->rx_opt.dsack = 1;
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
		tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + 1, 4 - tp->rx_opt.tstamp_ok);
	}
}

static inline void tcp_dsack_extend(struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	if (!tp->rx_opt.dsack)
		tcp_dsack_set(tp, seq, end_seq);
	else
		tcp_sack_extend(tp->duplicate_sack, seq, end_seq);
}

static void tcp_send_dupack(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
	    before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOST);
		tcp_enter_quickack_mode(tp);

		if (tp->rx_opt.sack_ok && sysctl_tcp_dsack) {
			u32 end_seq = TCP_SKB_CB(skb)->end_seq;

			if (after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))
				end_seq = tp->rcv_nxt;
			tcp_dsack_set(tp, TCP_SKB_CB(skb)->seq, end_seq);
		}
	}

	tcp_send_ack(sk);
}

/* These routines update the SACK block as out-of-order packets arrive or
 * in-order packets close up the sequence space.
 */
static void tcp_sack_maybe_coalesce(struct tcp_sock *tp)
{
	int this_sack;
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	struct tcp_sack_block *swalk = sp+1;

	/* See if the recent change to the first SACK eats into
	 * or hits the sequence space of other SACK blocks, if so coalesce.
	 */
	for (this_sack = 1; this_sack < tp->rx_opt.num_sacks; ) {
		if (tcp_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
			 * Decrease num_sacks.
			 */
			tp->rx_opt.num_sacks--;
			tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + tp->rx_opt.dsack, 4 - tp->rx_opt.tstamp_ok);
			for(i=this_sack; i < tp->rx_opt.num_sacks; i++)
				sp[i] = sp[i+1];
			continue;
		}
		this_sack++, swalk++;
	}
}

static __inline__ void tcp_sack_swap(struct tcp_sack_block *sack1, struct tcp_sack_block *sack2)
{
	__u32 tmp;

	tmp = sack1->start_seq;
	sack1->start_seq = sack2->start_seq;
	sack2->start_seq = tmp;

	tmp = sack1->end_seq;
	sack1->end_seq = sack2->end_seq;
	sack2->end_seq = tmp;
}

/* µ±½ÓÊÕµ½ÂÒĞò¶Îºó£¬µ÷ÓÃ´Ëº¯ÊıÉèÖÃselective_acksÊı×é£¬¼ÆËãÏÂÒ»¸ö·¢ËÍ¶ÎÖĞSACKÑ¡ÏîÖĞSACK¿éÊı */
static void tcp_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int cur_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	if (!cur_sacks)
		goto new_sack;

	for (this_sack=0; this_sack<cur_sacks; this_sack++, sp++) {
		if (tcp_sack_extend(sp, seq, end_seq)) {
			/* Rotate this_sack to the first one. */
			for (; this_sack>0; this_sack--, sp--)
				tcp_sack_swap(sp, sp-1);
			if (cur_sacks > 1)
				tcp_sack_maybe_coalesce(tp);
			return;
		}
	}

	/* Could not find an adjacent existing SACK, build a new one,
	 * put it at the front, and shift everyone else down.  We
	 * always know there is at least one SACK present already here.
	 *
	 * If the sack array is full, forget about the last one.
	 */
	if (this_sack >= 4) {
		this_sack--;
		tp->rx_opt.num_sacks--;
		sp--;
	}
	for(; this_sack > 0; this_sack--, sp--)
		*sp = *(sp-1);

new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	tp->rx_opt.num_sacks++;
	tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + tp->rx_opt.dsack, 4 - tp->rx_opt.tstamp_ok);
}

/* RCV.NXT advances, some SACKs should be eaten. */
/* ÔÚ½ÓÊÕ¶ÎµÄÂıËÙÁ÷³ÌÖĞ£¬Èç¹û´ı»Ø¸´µÄACk¶ÎÖĞ´æÔÚSACKÑ¡Ïî£¬Ôòµ÷ÓÃ´Ëº¯Êı£¬¸ù¾İ½ÓÊÕµ½µÄ¶Îµ÷Õûselective_acksÊı×é */
static void tcp_sack_remove(struct tcp_sock *tp)
{
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int num_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	/* Empty ofo queue, hence, all the SACKs are eaten. Clear. */
	if (skb_queue_len(&tp->out_of_order_queue) == 0) {
		tp->rx_opt.num_sacks = 0;
		tp->rx_opt.eff_sacks = tp->rx_opt.dsack;
		return;
	}

	for(this_sack = 0; this_sack < num_sacks; ) {
		/* Check if the start of the sack is covered by RCV.NXT. */
		if (!before(tp->rcv_nxt, sp->start_seq)) {
			int i;

			/* RCV.NXT must cover all the block! */
			BUG_TRAP(!before(tp->rcv_nxt, sp->end_seq));

			/* Zap this SACK, by moving forward any other SACKS. */
			for (i=this_sack+1; i < num_sacks; i++)
				tp->selective_acks[i-1] = tp->selective_acks[i];
			num_sacks--;
			continue;
		}
		this_sack++;
		sp++;
	}
	if (num_sacks != tp->rx_opt.num_sacks) {
		tp->rx_opt.num_sacks = num_sacks;
		tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + tp->rx_opt.dsack, 4 - tp->rx_opt.tstamp_ok);
	}
}

/* This one checks to see if we can put data from the
 * out_of_order queue into the receive_queue.
 */
/* ¸Ãº¯Êı¼ì²â½«½ÓÊÕµÄ¶ÎÊÇ·ñÄÜÓëÂÒĞò¶ÓÁĞÖĞµÄ¶ÎºÏ²¢²¢·Åµ½½ÓÊÕ¶ÓÁĞÖĞ */
static void tcp_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 dsack_high = tp->rcv_nxt;/* dsack_highÊÇÒÑ¾­Í¨¹ıdsack´¦ÀíµÄĞòºÅ */
	struct sk_buff *skb;

	while ((skb = skb_peek(&tp->out_of_order_queue)) != NULL) {/* ±éÀúÂÒĞò¶ÓÁĞÖĞËùÓĞµÄ¶Î */
		if (after(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))/* µ±Ç°¶ÎµÄĞòºÅ³¬¹ıÔ¤ÆÚ½ÓÊÕµÄĞòºÅ£¬ÍË³ö */
			break;

		if (before(TCP_SKB_CB(skb)->seq, dsack_high)) {/* ¶ÎĞòºÅĞ¡ÓÚÔ¤ÆÚµÄĞòºÅ£¬ËµÃ÷ÖØ¸´½ÓÊÕÁË±¨ÎÄ */
			__u32 dsack = dsack_high;
			if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))/* ´¦ÀíDSACK */
				dsack_high = TCP_SKB_CB(skb)->end_seq;
			tcp_dsack_extend(tp, TCP_SKB_CB(skb)->seq, dsack);
		}

		if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {/* ¸Ã¶ÎÒÑ¾­±»È«²¿½ÓÊÕ£¬²»±ØÔÙ±£´æÔÚÂÒĞò¶ÓÁĞÖĞÁË */
			SOCK_DEBUG(sk, "ofo packet was already received \n");
			__skb_unlink(skb, skb->list);
			__kfree_skb(skb);
			continue;
		}
		SOCK_DEBUG(sk, "ofo requeuing : rcv_next %X seq %X - %X\n",
			   tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
			   TCP_SKB_CB(skb)->end_seq);

		/* Ô¤ÆÚµÄ¶Î£¬½«Æä´ÓÂÒĞò¶ÓÁĞÖĞÒÆµ½½ÓÊÕ¶ÓÁĞÖĞ */
		__skb_unlink(skb, skb->list);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		/* ¸üĞÂÔ¤ÆÚ¶ÎµÄĞòºÅ²¢´¦ÀíFIN */
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if(skb->h.th->fin)
			tcp_fin(skb, sk, skb->h.th);
	}
}

static int tcp_prune_queue(struct sock *sk);

/* ÂıËÙÂ·¾¶´¦ÀíTCPÊı¾İ±¨ÎÄ */
static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	struct tcp_sock *tp = tcp_sk(sk);
	int eaten = -1;

	if (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq)/* Ã»ÓĞÊı¾İ¸ººÉ£¬ÍË³ö */
		goto drop;

	th = skb->h.th;
	/* ÒÆ¶¯Ö¸Õë£¬Ìø¹ıTCP±¨Í· */
	__skb_pull(skb, th->doff*4);

	/* ´¦ÀíCWR±êÖ¾£¬Èç¹û½ÓÊÕµ½µÄTCPÊ×²¿ÖĞ´æÔÚ´Ë±êÖ¾£¬±íÊ¾·¢ËÍ·½×÷ÁËÓµÈû´¦Àí£¬ËùÒÔ±¾¶Ë¿ÉÒÔÈ¥µôTCP_ECN_DEMAND_CWR±êÖ¾ */
	TCP_ECN_accept_cwr(tp, skb);

	if (tp->rx_opt.dsack) {/* ÉÏ´ÎµÄ¶ÎÖĞ´æÔÚDSACK */
		tp->rx_opt.dsack = 0;/* ÒòÎªÄ¿Ç°»¹²»Çå³şÏÂ´Î·¢ËÍµÄ¶ÎÊÇ·ñ´æÔÚDSACK£¬Òò´ËÇå³ı´Ë±êÖ¾ */
		tp->rx_opt.eff_sacks = min_t(unsigned int, tp->rx_opt.num_sacks,
						    4 - tp->rx_opt.tstamp_ok);
	}

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {/* ÊÇÔ¤ÆÚµÄ¶Î£¬Ö»ÓĞ¹ı´æÔÚÑ¡Ïî¶øÒÑ */
		if (tcp_receive_window(tp) == 0)/* ½ÓÊÕ´°¿ÚÎª0£¬²»ÄÜ½ÓÊÕÊı¾İ£¬Ïò¶Ô·½·¢ËÍACKºó¶ªÆú¶Î¡£¶Ô·½½øĞĞÓµÈû´¦Àí¡£ */
			goto out_of_window;

		/* Ok. In sequence. In window. */
		if (tp->ucopy.task == current &&
		    tp->copied_seq == tp->rcv_nxt && tp->ucopy.len &&
		    sock_owned_by_user(sk) && !tp->urg_data) {/* ÅĞ¶ÏÊÇ·ñ¿ÉÒÔ¸´ÖÆµ½ÓÃ»§¿Õ¼ä */
			int chunk = min_t(unsigned int, skb->len,
							tp->ucopy.len);/* ¸´ÖÆµ½ÓÃ»§¿Õ¼äµÄÊı¾İ³¤¶È */

			__set_current_state(TASK_RUNNING);

			local_bh_enable();
			if (!skb_copy_datagram_iovec(skb, 0, tp->ucopy.iov, chunk)) {/* ½«Êı¾İ¸´ÖÆµ½ÓÃ»§¿Õ¼ä */
				/* ¸´ÖÆ³É¹¦µÄ»°£¬¸üĞÂÓÃ»§¿Õ¼ä»º´æ³¤¶È£¬¸´ÖÆµÄĞòºÅ */
				tp->ucopy.len -= chunk;
				tp->copied_seq += chunk;
				eaten = (chunk == skb->len && !th->fin);
				/* ¸üĞÂ½ÓÊÕ»º´æºÍ½ÓÊÕ´°¿Ú */
				tcp_rcv_space_adjust(sk);
			}
			local_bh_disable();
		}

		if (eaten <= 0) {/* Ã»ÓĞ¸´ÖÆµ½ÓÃ»§¿Õ¼ä£¬»º´æµ½½ÓÊÕ¶ÓÁĞÖĞ */
queue_and_out:
			if (eaten < 0 &&/* Èç¹û½ÓÊÕ»º´æ²»×ã£¬Ôò¶ªÆú */
			    (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
			     !sk_stream_rmem_schedule(sk, skb))) {
				if (tcp_prune_queue(sk) < 0 ||
				    !sk_stream_rmem_schedule(sk, skb))
					goto drop;
			}
			/* ÉèÖÃËŞÖ÷£¬²¢Ìí¼Óµ½½ÓÊÕ¶ÓÁĞ¶ÓÎ² */
			sk_stream_set_owner_r(skb, sk);
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		}
		/* ³É¹¦½ÓÊÕÁË±¨ÎÄ£¬¸üĞÂÏÂÒ»¸öÔ¤ÆÚ½ÓÊÕµÄĞòºÅ */
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if(skb->len)/* ½ÓÊÕµ½ÓĞĞ§Êı¾İ£¬Ôò´¦ÀíÒ»Ğ©Êı¾İ½ÓÊÕÏà¹ØµÄ²Ù×÷£¬Ö÷ÒªÊÇÓĞ¹ØÑÓÊ±ACKÒÔ¼°ECN±êÖ¾µÈµÈ */
			tcp_event_data_recv(sk, tp, skb);
		if(th->fin)/* ´¦ÀíFIN */
			tcp_fin(skb, sk, th);

		if (skb_queue_len(&tp->out_of_order_queue)) {/* ÂÒĞò¶ÓÁĞÖĞ´æÔÚÊı¾İ */
			/* ´¦ÀíÂÒĞò¶ÓÁĞ£¬½«ÆäÒÆµ½½ÓÊÕ¶ÓÁĞÖĞ */
			tcp_ofo_queue(sk);

			/* RFC2581. 4.2. SHOULD send immediate ACK, when
			 * gap in queue is filled.
			 */
			if (!skb_queue_len(&tp->out_of_order_queue))/* ÂÒĞò¶ÓÁĞÖĞÒÑ¾­Ã»ÓĞÊı¾İ£¬È¥³ıpingpong±êÖ¾£¬ÆôÓÃ¿ìËÙÈ·ÈÏ */
				tp->ack.pingpong = 0;
		}

		if (tp->rx_opt.num_sacks)/* ½ÓÊÕµ½ĞÂÊı¾İ£¬rcv.nxt·¢ÉúÁË±ä»¯£¬¿ÉÄÜĞèÒªÈ¥³ıselective_acksÖĞµÄÄ³Ğ©Ïî */
			tcp_sack_remove(tp);

		/* ÔÚÂú×ãÌõ¼şµÄÇé¿öÏÂ£¬ÖØĞÂÉèÖÃÊ×²¿Ô¤²âµÄ±êÖ¾ */
		tcp_fast_path_check(sk, tp);

		if (eaten > 0)/* ¸´ÖÆÊı¾İµ½ÓÃ»§¿Õ¼äÁË */
			__kfree_skb(skb);/* ÊÍ·Å±¨ÎÄ */
		else if (!sock_flag(sk, SOCK_DEAD))/* Ã»ÓĞ¸´ÖÆÊı¾İµ½ÓÃ»§¿Õ¼ä£¬²¢ÇÒÌ×½Ó¿ÚÁ¬½ÓÎ´¶Ï¿ª£¬Ôò»½ĞÑµÈ´ı½ÓÊÕÊı¾İµÄ½ø³Ì */
			sk->sk_data_ready(sk, 0);
		return;
	}

	/* ÔËĞĞµ½ÕâÀï£¬ËµÃ÷±¨ÎÄ²»ÊÇÔ¤ÆÚµÄ¶Î£¬ÂÒĞòÁË */
	if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {/* ±¾´Î½ÓÊÕµÄ¶ÎÊÇ½ÏÔçµÄ¶Î£¬ËµÃ÷¶Ô·½ÖØ·¢ÁË */
		/* A retransmit, 2nd most common case.  Force an immediate ack. */
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOST);
		/* ´¦ÀíDSACK£¬ÔÚÏÂÒ»¸öÈ·ÈÏÖĞ·¢ËÍDSACKÏûÏ¢ */
		tcp_dsack_set(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

out_of_window:/* µ÷¶ÈACK£¬ÈÃÈ·ÈÏ¶Î¾¡¿ÉÄÜ¿ìµÄ·¢ËÍ¸ø·¢ËÍ·½ */
		tcp_enter_quickack_mode(tp);
		tcp_schedule_ack(tp);
drop:
		__kfree_skb(skb);/* ÊÍ·ÅSKB²¢ÍË³ö */
		return;
	}

	/* Out of window. F.e. zero window probe. */
	/* ½ÓÊÕµ½µÄ¶ÎĞòºÅ½Ï´ó£¬³¬¹ıÁË½ÓÊÕ´°¿Ú£¬Ìøµ½out_of_window´¦ÊÍ·ÅËü */
	if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt + tcp_receive_window(tp)))
		goto out_of_window;

	/* ĞèÒª½ÓÊÕµÄÂÒĞòµÄ¶Î£¬ÏÈ½øĞĞ¿ìËÙÈ·ÈÏ´¦Àí */
	tcp_enter_quickack_mode(tp);

	if (before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {/* ²¿·Ö¶ÎÒÑ¾­½ÓÊÕ£¬ÔòÏÈ´¦ÀíSACKÑ¡ÏîµÄD-SACK */
		/* Partial packet, seq < rcv_next < end_seq */
		SOCK_DEBUG(sk, "partial packet: rcv_next %X seq %X - %X\n",
			   tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
			   TCP_SKB_CB(skb)->end_seq);

		tcp_dsack_set(tp, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);
		
		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		if (!tcp_receive_window(tp))/* ½ÓÊÕ´°¿ÚÎª0£¬Ö»ÄÜ¶ªÆúÁË */
			goto out_of_window;
		goto queue_and_out;/* »¹ÔÊĞí½ÓÊÕ£¬ÔòÌø×ªµ½queue_and_out½ÓÊÕÊı¾İ£¬ÕâÀïÃ»ÓĞÅĞ¶Ï±¨ÎÄ´óĞ¡? */
	}

	/**
	 * ½ÓÊÕµ½ÁËÂÒĞòµÄ¶Î£¬¿ÉÄÜÊÇ´«Êä¹ı³ÌÖĞ·¢ÉúÁËÓµÈû£¬Òò´Ë¼ì²âECN±êÖ¾ 
	 * Èç¹ûÓĞÓµÈû£¬ÔòĞèÒªË«·½½øĞĞÓµÈû¿ØÖÆ´¦Àí£¬·ñÔò¾¡¿ìÍ¨Öª¶Ô·½£¬ÈÃ·¢ËÍ·½¾¡¿ÉÄÜµÄÖØ´«¶ªÊ§µÄ¶Î
	 */
	TCP_ECN_check_ce(tp, skb);

	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    !sk_stream_rmem_schedule(sk, skb)) {
		if (tcp_prune_queue(sk) < 0 ||/* ½ÓÊÕ»º´æ¿Õ¼ä²»¹»£¬Ö»ÄÜ¶ªÆúÁË */
		    !sk_stream_rmem_schedule(sk, skb))
			goto drop;
	}

	/* Disable header prediction. */
	tp->pred_flags = 0;/* È¥µôÔ¤²â±êÖ¾£¬ÒòÎªÖ»ÒªÓĞÂÒĞò±¨ÎÄ´æÔÚ£¬¾Í²»¿ÉÄÜ×ß¿ìËÙÁ÷³Ì£¬²»±ØÔ¤²âÁË */
	tcp_schedule_ack(tp);/* ±êÊ¶ÓĞÈ·ÈÏĞèÒª·¢ËÍ */

	SOCK_DEBUG(sk, "out of order segment: rcv_next %X seq %X - %X\n",
		   tp->rcv_nxt, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

	sk_stream_set_owner_r(skb, sk);/* ÉèÖÃskbµÄowner */

	if (!skb_peek(&tp->out_of_order_queue)) {/* ÂÒĞò¶ÓÁĞÄ¿Ç°Îª¿Õ */
		/* Initial out of order segment, build 1 SACK. */
		if (tp->rx_opt.sack_ok) {/* ÔÊĞí·¢ËÍSACK£¬ÉèÖÃSACKµÄÊôĞÔ */
			tp->rx_opt.num_sacks = 1;
			tp->rx_opt.dsack     = 0;
			tp->rx_opt.eff_sacks = 1;
			tp->selective_acks[0].start_seq = TCP_SKB_CB(skb)->seq;
			tp->selective_acks[0].end_seq =
						TCP_SKB_CB(skb)->end_seq;
		}
		/* ½«±¨ÎÄ¼Óµ½ÂÒĞò¶ÓÁĞ */
		__skb_queue_head(&tp->out_of_order_queue,skb);
	} else {/* ÒÑ¾­ÓĞÂÒĞòµÄ±¨ÎÄÁË */
		struct sk_buff *skb1 = tp->out_of_order_queue.prev;/* ÂÒĞò¶ÓÁĞÖĞ×îºóÒ»¸ö±¨ÎÄ */
		u32 seq = TCP_SKB_CB(skb)->seq;
		u32 end_seq = TCP_SKB_CB(skb)->end_seq;

		if (seq == TCP_SKB_CB(skb1)->end_seq) {/* µ±Ç°±¨ÎÄµÄĞòºÅÊÇÂÒĞò¶ÓÁĞ×îºóÒ»¸ö±¨ÎÄµÄ½áÊøĞòºÅ£¬¼´¶şÕßÊÇÁ¬ĞøµÄ */
			__skb_append(skb1, skb);/* ½«ĞÂ±¨ÎÄÌí¼Óµ½Î²²¿¼´¿É */

			if (!tp->rx_opt.num_sacks ||/* SACK¸öÊıÎª0 */
			    tp->selective_acks[0].end_seq != seq)/* »òÕßÓëµÚÒ»¸öDSACKµÄĞòºÅ²»ÏàÁ¬ */
				goto add_sack;/* ĞÂÔöÒ»¸öDSACK */

			/* Common case: data arrive in order after hole. */
			/* ½«µ±Ç°±¨ÎÄµÄsackÌí¼Óµ½µÚÒ»¸öDSACKÖĞ¼´¿É */
			tp->selective_acks[0].end_seq = end_seq;
			return;
		}

		/* Find place to insert this segment. */
		/* ÔËĞĞµ½ÕâÀï£¬ËµÃ÷½ÓÊÕµÄ¶ÎÓë×îºóÒ»¸öÂÒĞòµÄ¶Î²»Á¬Ğø£¬ĞèÒª½øĞĞ²éÕÒ */
		do {
			if (!after(TCP_SKB_CB(skb1)->seq, seq))
				break;
		} while ((skb1 = skb1->prev) !=/* ´Ó¶ÓÎ²ÏòÉÏ±éÀú */
			 (struct sk_buff*)&tp->out_of_order_queue);

		/* Do skb overlap to previous one? */
		if (skb1 != (struct sk_buff*)&tp->out_of_order_queue &&/* ²»ÊÇ¶ÓÍ·½áµã */
		    before(seq, TCP_SKB_CB(skb1)->end_seq)) {/* ²¿·ÖÖØµş */
			if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {/* ÍêÈ«°üº¬ÔÚ¸Ã¶ÎÄÚ */
				/* All the bits are present. Drop. */
				__kfree_skb(skb);/* ÊÍ·ÅËü */
				/* ÉèÖÃDSACK£¬²¢Ìø×ªµ½add_sackÌí¼ÓDSACK */
				tcp_dsack_set(tp, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, TCP_SKB_CB(skb1)->seq)) {/* ÔÙ´ÎÈ·ÈÏÊÇ²¿·ÖÖØµş£¬Ó¦¸Ã×ÜÊÇÎªtrue */
				/* Partial overlap. */
				/* ÉèÖÃDSACKÊôĞÔ */
				tcp_dsack_set(tp, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				skb1 = skb1->prev;
			}
		}
		/* ½«±¨ÎÄ²åÈëµ½ºÏÊÊµÄÎ»ÖÃ */
		__skb_insert(skb, skb1, skb1->next, &tp->out_of_order_queue);
		
		/* And clean segments covered by new one as whole. */
		/* ½«µ±Ç°¶ÎºóÃæµÄËùÓĞ¶ÎÖĞ£¬°üº¬ÔÚµ±Ç°¶ÎÄÚµÄ¶ÎÉ¾³ı */
		while ((skb1 = skb->next) !=
		       (struct sk_buff*)&tp->out_of_order_queue &&
		       after(end_seq, TCP_SKB_CB(skb1)->seq)) {
		       if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {/* ²¿·ÖÖØµş */
			   	   /* ÉèÖÃDSACKºóÍË³ö²éÕÒ¹ı³Ì */
			       tcp_dsack_extend(tp, TCP_SKB_CB(skb1)->seq, end_seq);
			       break;
		       }
			   /* ÍêÈ«°üº¬£¬Ôò½«Æä´ÓÂÒĞò¶ÓÁĞÖĞÉ¾³ı²¢ÊÍ·Å£¬Í¬Ê±ÉèÖÃÏà¹ØDSACKÊôĞÔ */
		       __skb_unlink(skb1, skb1->list);
		       tcp_dsack_extend(tp, TCP_SKB_CB(skb1)->seq, TCP_SKB_CB(skb1)->end_seq);
		       __kfree_skb(skb1);
		}

add_sack:
		if (tp->rx_opt.sack_ok)/* Èç¹ûË«·½¶¼Ö§³ÖSACK£¬ÔòÉèÖÃSACK¿é */
			tcp_sack_new_ofo_skb(sk, seq, end_seq);
	}
}

/* Collapse contiguous sequence of skbs head..tail with
 * sequence numbers start..end.
 * Segments with FIN/SYN are not collapsed (only because this
 * simplifies code)
 */
static void
tcp_collapse(struct sock *sk, struct sk_buff *head,
	     struct sk_buff *tail, u32 start, u32 end)
{
	struct sk_buff *skb;

	/* First, check that queue is collapsable and find
	 * the point where collapsing can be useful. */
	for (skb = head; skb != tail; ) {
		/* No new bits? It is possible on ofo queue. */
		if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
			struct sk_buff *next = skb->next;
			__skb_unlink(skb, skb->list);
			__kfree_skb(skb);
			NET_INC_STATS_BH(LINUX_MIB_TCPRCVCOLLAPSED);
			skb = next;
			continue;
		}

		/* The first skb to collapse is:
		 * - not SYN/FIN and
		 * - bloated or contains data before "start" or
		 *   overlaps to the next one.
		 */
		if (!skb->h.th->syn && !skb->h.th->fin &&
		    (tcp_win_from_space(skb->truesize) > skb->len ||
		     before(TCP_SKB_CB(skb)->seq, start) ||
		     (skb->next != tail &&
		      TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb->next)->seq)))
			break;

		/* Decided to skip this, advance start seq. */
		start = TCP_SKB_CB(skb)->end_seq;
		skb = skb->next;
	}
	if (skb == tail || skb->h.th->syn || skb->h.th->fin)
		return;

	while (before(start, end)) {
		struct sk_buff *nskb;
		int header = skb_headroom(skb);
		int copy = SKB_MAX_ORDER(header, 0);

		/* Too big header? This can happen with IPv6. */
		if (copy < 0)
			return;
		if (end-start < copy)
			copy = end-start;
		nskb = alloc_skb(copy+header, GFP_ATOMIC);
		if (!nskb)
			return;
		skb_reserve(nskb, header);
		memcpy(nskb->head, skb->head, header);
		nskb->nh.raw = nskb->head + (skb->nh.raw-skb->head);
		nskb->h.raw = nskb->head + (skb->h.raw-skb->head);
		nskb->mac.raw = nskb->head + (skb->mac.raw-skb->head);
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
		TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(nskb)->end_seq = start;
		__skb_insert(nskb, skb->prev, skb, skb->list);
		sk_stream_set_owner_r(nskb, sk);

		/* Copy data, releasing collapsed skbs. */
		while (copy > 0) {
			int offset = start - TCP_SKB_CB(skb)->seq;
			int size = TCP_SKB_CB(skb)->end_seq - start;

			if (offset < 0) BUG();
			if (size > 0) {
				size = min(copy, size);
				if (skb_copy_bits(skb, offset, skb_put(nskb, size), size))
					BUG();
				TCP_SKB_CB(nskb)->end_seq += size;
				copy -= size;
				start += size;
			}
			if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
				struct sk_buff *next = skb->next;
				__skb_unlink(skb, skb->list);
				__kfree_skb(skb);
				NET_INC_STATS_BH(LINUX_MIB_TCPRCVCOLLAPSED);
				skb = next;
				if (skb == tail || skb->h.th->syn || skb->h.th->fin)
					return;
			}
		}
	}
}

/* Collapse ofo queue. Algorithm: select contiguous sequence of skbs
 * and tcp_collapse() them until all the queue is collapsed.
 */
static void tcp_collapse_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = skb_peek(&tp->out_of_order_queue);
	struct sk_buff *head;
	u32 start, end;

	if (skb == NULL)
		return;

	start = TCP_SKB_CB(skb)->seq;
	end = TCP_SKB_CB(skb)->end_seq;
	head = skb;

	for (;;) {
		skb = skb->next;

		/* Segment is terminated when we see gap or when
		 * we are at the end of all the queue. */
		if (skb == (struct sk_buff *)&tp->out_of_order_queue ||
		    after(TCP_SKB_CB(skb)->seq, end) ||
		    before(TCP_SKB_CB(skb)->end_seq, start)) {
			tcp_collapse(sk, head, skb, start, end);
			head = skb;
			if (skb == (struct sk_buff *)&tp->out_of_order_queue)
				break;
			/* Start new segment */
			start = TCP_SKB_CB(skb)->seq;
			end = TCP_SKB_CB(skb)->end_seq;
		} else {
			if (before(TCP_SKB_CB(skb)->seq, start))
				start = TCP_SKB_CB(skb)->seq;
			if (after(TCP_SKB_CB(skb)->end_seq, end))
				end = TCP_SKB_CB(skb)->end_seq;
		}
	}
}

/* Reduce allocated memory if we can, trying to get
 * the socket within its memory limits again.
 *
 * Return less than zero if we should start dropping frames
 * until the socket owning process reads some of the data
 * to stabilize the situation.
 */
static int tcp_prune_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk); 

	SOCK_DEBUG(sk, "prune_queue: c=%x\n", tp->copied_seq);

	NET_INC_STATS_BH(LINUX_MIB_PRUNECALLED);

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		tcp_clamp_window(sk, tp);
	else if (tcp_memory_pressure)
		tp->rcv_ssthresh = min(tp->rcv_ssthresh, 4U * tp->advmss);

	tcp_collapse_ofo_queue(sk);
	tcp_collapse(sk, sk->sk_receive_queue.next,
		     (struct sk_buff*)&sk->sk_receive_queue,
		     tp->copied_seq, tp->rcv_nxt);
	sk_stream_mem_reclaim(sk);

	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* Collapsing did not help, destructive actions follow.
	 * This must not ever occur. */

	/* First, purge the out_of_order queue. */
	if (skb_queue_len(&tp->out_of_order_queue)) {
		NET_ADD_STATS_BH(LINUX_MIB_OFOPRUNED, 
				 skb_queue_len(&tp->out_of_order_queue));
		__skb_queue_purge(&tp->out_of_order_queue);

		/* Reset SACK state.  A conforming SACK implementation will
		 * do the same at a timeout based retransmit.  When a connection
		 * is in a sad state like this, we care only about integrity
		 * of the connection not performance.
		 */
		if (tp->rx_opt.sack_ok)
			tcp_sack_reset(&tp->rx_opt);
		sk_stream_mem_reclaim(sk);
	}

	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* If we are really being abused, tell the caller to silently
	 * drop receive data on the floor.  It will get retransmitted
	 * and hopefully then we'll have sufficient space.
	 */
	NET_INC_STATS_BH(LINUX_MIB_RCVPRUNED);

	/* Massive buffer overcommit. */
	tp->pred_flags = 0;
	return -1;
}


/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
/* ¼ì²âÓµÈû´°¿ÚµÄÊ±¼ä³¬¹ıÁËRTO£¬ÖØĞÂµ÷Õû¼ì²âÓµÈû´°¿Ú */
void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ca_state == TCP_CA_Open &&/* µ±Ç°×´Ì¬Îªopen */
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {/* ·¢ËÍ¶ÓÁĞÎ´Âú£¬¿ÉÄÜÊÇÓ¦ÓÃ³ÌĞò»òÕß¶Ô·½½ÓÊÕ´°¿Ú½øĞĞÁËÏŞÖÆ */
		/* Limited by application or receiver window. */
		/* 2ÊÇÓµÈû´°¿ÚµÄ³õÊ¼Öµ */
		u32 win_used = max(tp->snd_cwnd_used, 2U);
		if (win_used < tp->snd_cwnd) {/* µ÷½ÚÓµÈû´°¿Ú */
			tp->snd_ssthresh = tcp_current_ssthresh(tp);
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_time_stamp;
}


/* When incoming ACK allowed to free some skb from write_queue,
 * we remember this event in flag sk->sk_queue_shrunk and wake up socket
 * on the exit from tcp input handler.
 *
 * PROBLEM: sndbuf expansion does not work well with largesend.
 */
static void tcp_new_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->packets_out < tp->snd_cwnd &&
	    !(sk->sk_userlocks & SOCK_SNDBUF_LOCK) &&
	    !tcp_memory_pressure &&
	    atomic_read(&tcp_memory_allocated) < sysctl_tcp_mem[0]) {
 		int sndmem = max_t(u32, tp->rx_opt.mss_clamp, tp->mss_cache_std) +
			MAX_TCP_HEADER + 16 + sizeof(struct sk_buff),
		    demanded = max_t(unsigned int, tp->snd_cwnd,
						   tp->reordering + 1);
		sndmem *= 2*demanded;
		if (sndmem > sk->sk_sndbuf)
			sk->sk_sndbuf = min(sndmem, sysctl_tcp_wmem[2]);
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}

	sk->sk_write_space(sk);
}

static inline void tcp_check_space(struct sock *sk)
{
	if (sk->sk_queue_shrunk) {
		sk->sk_queue_shrunk = 0;
		if (sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
			tcp_new_space(sk);
	}
}

static void __tcp_data_snd_check(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (after(TCP_SKB_CB(skb)->end_seq, tp->snd_una + tp->snd_wnd) ||
	    tcp_packets_in_flight(tp) >= tp->snd_cwnd ||
	    tcp_write_xmit(sk, tp->nonagle))
		tcp_check_probe_timer(sk, tp);
}

static __inline__ void tcp_data_snd_check(struct sock *sk)
{
	struct sk_buff *skb = sk->sk_send_head;

	if (skb != NULL)
		__tcp_data_snd_check(sk, skb);
	tcp_check_space(sk);
}

/*
 * Check if sending an ack is needed.
 */
static void __tcp_ack_snd_check(struct sock *sk, int ofo_possible)
{
	struct tcp_sock *tp = tcp_sk(sk);

	    /* More than one full frame received... */
	if (((tp->rcv_nxt - tp->rcv_wup) > tp->ack.rcv_mss/* ½ÓÊÕ´°¿ÚÖĞÓĞ¶à¸öÈ«³ß´ç¶Î»¹Ã»ÓĞÈ·ÈÏ */
	     /* ... and right edge of window advances far enough.
	      * (tcp_recvmsg() will send ACK otherwise). Or...
	      */
	     && __tcp_select_window(sk) >= tp->rcv_wnd) ||
	    /* We ACK each frame or... */
	    tcp_in_quickack_mode(tp) ||/* µ±Ç°´¦ÓÚ¿ìËÙÈ·ÈÏÄ£Ê½ */
	    /* We have out of order data. */
	    (ofo_possible &&
	     skb_peek(&tp->out_of_order_queue))) {/* ĞèÒªÅĞ¶ÏÂÒĞò¶ÓÁĞ£¬²¢ÇÒÂÒĞò¶ÓÁĞÖĞ´æÔÚ¶Î */
		/* Then ack it now */
		tcp_send_ack(sk);
	} else {
		/* Else, send delayed ack. */
		tcp_send_delayed_ack(sk);
	}
}

/* ¼ì²éÊÇ·ñÓĞÈ·ÈÏĞèÒª·¢ËÍ */
static __inline__ void tcp_ack_snd_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (!tcp_ack_scheduled(tp)) {/* Ã»ÓĞACKĞèÒª·¢ËÍ£¬ÍË³ö */
		/* We sent a data segment already. */
		return;
	}
	/* ÓĞACKĞèÒª·¢ËÍ£¬¸ù¾İÌõ¼şÆô¶¯ÑÓÊ±·¢ËÍ»òÕßÁ¢¼´·¢ËÍ */
	__tcp_ack_snd_check(sk, 1);
}

/*
 *	This routine is only called when we have urgent data
 *	signalled. Its the 'slow' part of tcp_urg. It could be
 *	moved inline now as tcp_urg is only called from one
 *	place. We handle URGent data wrong. We have to - as
 *	BSD still doesn't use the correction from RFC961.
 *	For 1003.1g we should support a new option TCP_STDURG to permit
 *	either form (or just set the sysctl tcp_stdurg).
 */
/* ¼ì²â½ô¼±Ö¸ÕëÊÇ·ñÓĞĞ§ */
static void tcp_check_urg(struct sock * sk, struct tcphdr * th)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 ptr = ntohs(th->urg_ptr);/* ¼ÆËã´øÍâÊı¾İµÄÎ»ÖÃ */

	if (ptr && !sysctl_tcp_stdurg)/* BSDÒ»¿ªÊ¼¾Í´íÎóÁË£¬½«ptr½âÊÍ³ÉURGºóÒ»¸öÖ¸Õë£¬Òò´ËÕâÀïĞèÒªÇ°ÒÆÒ»¸öÖ¸ÕëÖ¸ÏòURG */
		ptr--;
	ptr += ntohl(th->seq);

	/* Ignore urgent data that we've already seen and read. */
	/* ´øÍâÖ¸ÕëÒÑ¾­±»½ÓÊÕÁË£¬ÍË³ö */
	if (after(tp->copied_seq, ptr))
		return;

	/* Do not replay urg ptr.
	 *
	 * NOTE: interesting situation not covered by specs.
	 * Misbehaving sender may send urg ptr, pointing to segment,
	 * which we already have in ofo queue. We are not able to fetch
	 * such data and will stay in TCP_URG_NOTYET until will be eaten
	 * by recvmsg(). Seems, we are not obliged to handle such wicked
	 * situations. But it is worth to think about possibility of some
	 * DoSes using some hypothetical application level deadlock.
	 */
	/* ´øÍâÊı¾İÖ¸ÕëÔÚÔ¤ÆÚ½ÓÊÕ±¨ÎÄÖ®Ç°£¬ËµÃ÷ÒÑ¾­½ÓÊÕ¹ı£¬ÍË³ö */
	if (before(ptr, tp->rcv_nxt))
		return;

	/* Do we already have a newer (or duplicate) urgent pointer? */
	/* ÓĞÁíÍâµÄ´øÍâÊı¾İ£¬²¢ÇÒÎ»ÓÚµ±Ç°´øÍâÊı¾İÖ®ºó£¬Ò²ÍË³ö */
	if (tp->urg_data && !after(ptr, tp->urg_seq))
		return;

	/* Tell the world about our new urgent pointer. */
	/* ÏòµÈ´ıµÄ½ø³Ì·¢ËÍĞÅºÅ£¬¸æÖªËüÓĞ´øÍâÊı¾İµ½´ï */
	sk_send_sigurg(sk);

	/* We may be adding urgent data when the last byte read was
	 * urgent. To do this requires some care. We cannot just ignore
	 * tp->copied_seq since we would read the last urgent byte again
	 * as data, nor can we alter copied_seq until this data arrives
	 * or we break the sematics of SIOCATMARK (and thus sockatmark())
	 *
	 * NOTE. Double Dutch. Rendering to plain English: author of comment
	 * above did something sort of 	send("A", MSG_OOB); send("B", MSG_OOB);
	 * and expect that both A and B disappear from stream. This is _wrong_.
	 * Though this happens in BSD with high probability, this is occasional.
	 * Any application relying on this is buggy. Note also, that fix "works"
	 * only in this artificial test. Insert some normal data between A and B and we will
	 * decline of BSD again. Verdict: it is better to remove to trap
	 * buggy users.
	 */
	if (tp->urg_seq == tp->copied_seq && tp->urg_data &&/* ´øÍâÊı¾İµÄĞòºÅÕıÊÇÒª¸´ÖÆµ½ÓÃ»§Ì¬µÄĞòºÅ£ */
	    !sock_flag(sk, SOCK_URGINLINE) &&/* ÓÃ»§²»½ÓÊÕ´øÍâÊı¾İ */
	    tp->copied_seq != tp->rcv_nxt) {/* Òª¸´ÖÆµÄĞòºÅ²»ÊÇÏÂÒ»¸öÔ¤ÆÚ½ÓÊÕµÄĞòºÅ */
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);/* ½ÓÊÕ¶ÓÁĞÖĞµÄµÚÒ»¸ö¶Î */
		tp->copied_seq++;/* ´ÓÏÂÒ»¸ö×Ö½Ú¿ªÊ¼¸´ÖÆ£¬ÒòÎªÓÃ»§²»½ÓÊÕ´øÍâÊı¾İ */
		/* µÚÒ»¸ö±¨ÎÄµÄ×îºóÒ»¸ö×Ö½ÚÕıºÃÊÇ´øÍâÊı¾İ£¬ÒÑ¾­±»½ÓÊÕÁË£¬ÓÃ»§½ø³Ì½«»á´ÓÏÂÒ»¸ö±¨ÎÄ¿ªÊ¼½ÓÊÕ */
		if (skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq)) {
			/* ½«¸Ã±¨ÎÄ´Ó¶ÓÁĞÖĞÕª³ı²¢ÊÍ·Å */
			__skb_unlink(skb, skb->list);
			__kfree_skb(skb);
		}
	}

	/* ÉèÖÃ´øÍâÊı¾İ¼°±êºÅ */
	tp->urg_data   = TCP_URG_NOTYET;
	tp->urg_seq    = ptr;

	/* Disable header prediction. */
	/* ÓÉÓÚ¶ÁÈ¡µ½´øÍâÊı¾İ£¬Òò´Ë½ûÖ¹Ê×²¿Ô¤²â */
	tp->pred_flags = 0;
}

/* This is the 'fast' part of urgent handling. */
/* ´¦ÀíURG£¬´øÍâÊı¾İ */
static void tcp_urg(struct sock *sk, struct sk_buff *skb, struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check if we get a new urgent pointer - normally not. */
	if (th->urg)/* Í·²¿ÓĞURG±êÖ¾ */
		tcp_check_urg(sk,th);/* ¼ì²é´øÍâÊı¾İÆ«ÒÆÁ¿urg_seqÊÇ·ñÎª·Ç0£¬¼ì²âÊÇ·ñÕı³£ */

	/* Do we wait for any urgent data? - normally not... */
	if (tp->urg_data == TCP_URG_NOTYET) {/* µ±Ç°¶ÎÖĞ´øÍâÊı¾İÓĞĞ§ */
		/* ¼ÆËã´øÍâÊı¾İÎ»ÖÃ */
		u32 ptr = tp->urg_seq - ntohl(th->seq) + (th->doff * 4) -
			  th->syn;

		/* Is the urgent pointer pointing into this packet? */	 
		if (ptr < skb->len) {/* ´øÍâÊı¾İÔÚ±¾±¨ÎÄÄÚ */
			u8 tmp;
			if (skb_copy_bits(skb, ptr, &tmp, 1))/* ´Ó±¨ÎÄÖĞ¸´ÖÆÒ»¸ö×Ö½ÚµÄURGµ½tmpÖĞ */
				BUG();
			/* ¼ÇÂ¼ÏÂ´øÍâÊı¾İ£¬²¢ÉèÖÃ±êÖ¾±íÊ¾ÓÃ»§½ø³Ì¿ÉÒÔ¶ÁÈ¡´øÍâÊı¾İ */
			tp->urg_data = TCP_URG_VALID | tmp;
			if (!sock_flag(sk, SOCK_DEAD))/* Èç¹ûÌ×¿ÚÃ»ÓĞ¹Ø±Õ£¬ÔòÍ¨ÖªÆä¶ÁÈ¡Êı¾İ */
				sk->sk_data_ready(sk, 0);
		}
	}
}

/* ½«Êı¾İ¸´ÖÆµ½ÓÃ»§¿Õ¼ä */
static int tcp_copy_to_iovec(struct sock *sk, struct sk_buff *skb, int hlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int chunk = skb->len - hlen;
	int err;

	local_bh_enable();
	if (skb->ip_summed==CHECKSUM_UNNECESSARY)
		err = skb_copy_datagram_iovec(skb, hlen, tp->ucopy.iov, chunk);/* ²»½øĞĞĞ£ÑéºÍ¼ì²âÖ±½Ó¸´ÖÆµ½ÓÃ»§¿Õ¼ä */
	else
		err = skb_copy_and_csum_datagram_iovec(skb, hlen,
						       tp->ucopy.iov);/* Ö´ĞĞĞ£ÑéºÍ¼ì²â²¢¸´ÖÆµ½ÓÃ»§¿Õ¼ä */

	if (!err) {/* ¸´ÖÆ³É¹¦ */
		/* ¸üĞÂÄË½ø³Ì»º³åÇø³¤¶È£¬ÒÑ¾­¸´ÖÆµÄĞòºÅµÈµÈ */
		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		tcp_rcv_space_adjust(sk);
	}

	local_bh_disable();
	return err;
}

static int __tcp_checksum_complete_user(struct sock *sk, struct sk_buff *skb)
{
	int result;

	if (sock_owned_by_user(sk)) {
		local_bh_enable();
		result = __tcp_checksum_complete(skb);
		local_bh_disable();
	} else {
		result = __tcp_checksum_complete(skb);
	}
	return result;
}

/* »ùÓÚÎ±Ê×²¿ÀÛ¼ÓºÍ£¬Íê³ÉÈ«°üĞ£ÑéºÍ¼ì²â¡£ÓÃÓÚÒÑ¾­½¨Á¢Á¬½ÓµÄ¶Î */
static __inline__ int
tcp_checksum_complete_user(struct sock *sk, struct sk_buff *skb)
{
	return skb->ip_summed != CHECKSUM_UNNECESSARY &&
		__tcp_checksum_complete_user(sk, skb);
}

/*
 *	TCP receive function for the ESTABLISHED state. 
 *
 *	It is split into a fast path and a slow path. The fast path is 
 * 	disabled when:
 *	- A zero window was announced from us - zero window probing
 *        is only handled properly in the slow path. 
 *	- Out of order segments arrived.
 *	- Urgent data is expected.
 *	- There is no buffer space left
 *	- Unexpected TCP flags/window values/header lengths are received
 *	  (detected by checking the TCP header against pred_flags) 
 *	- Data is sent in both directions. Fast path only supports pure senders
 *	  or pure receivers (this means either the sequence number or the ack
 *	  value must stay constant)
 *	- Unexpected TCP option.
 *
 *	When these conditions are not satisfied it drops into a standard 
 *	receive procedure patterned after RFC793 to handle all cases.
 *	The first three cases are guaranteed by proper pred_flags setting,
 *	the rest is checked inline. Fast processing is turned on in 
 *	tcp_data_queue when everything is OK.
 */
/* µ±Á¬½ÓÒÑ¾­Õı³£½¨Á¢Ê±£¬´¦Àí½ÓÊÕµ½µÄTCP±¨ÎÄ */
int tcp_rcv_established(struct sock *sk, struct sk_buff *skb,
			struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous 
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *	
	 *	Van's trick is to deposit buffers into socket queue 
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the 
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */

	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_predition is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive 
	 *	 space for instance)
	 *	PSH flag is ignored.
	 */

	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&/* ½«TCPÊ×²¿ÖĞµÚ4¸ö×Ö»ñÈ¡Ò»¶¨µÄÎ»ÊıÓëÔ¤²â±êÖ¾±È½Ï£¬Èç¹û²»ÏàµÈ£¬Ôò²»ÄÜÖ´ĞĞ¿ìËÙÂ·¾¶ */
		TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {/* ±¾´Î½ÓÊÕµÄ¶ÎĞòºÅÊÇÔ¤ÆÚµÄ¶ÎĞòºÅ */
		int tcp_header_len = tp->tcp_header_len;

		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
		/* ÊÇ·ñ¿ÉÄÜ°üº¬Ê±¼ä´ÁÑ¡Ïî */
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
			__u32 *ptr = (__u32 *)(th + 1);

			/* No? Slow path! */
			if (*ptr != ntohl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
					  | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP))/* ²»ÊÇÊ±¼ä´ÁÑ¡Ïî£¬Ö»ÄÜÖ´ĞĞÂıËÙÂ·¾¶ */
				goto slow_path;

			/* ´ÓÑ¡ÏîÖĞ»ñÈ¡Ê±¼ä´Á */
			tp->rx_opt.saw_tstamp = 1;
			++ptr; 
			tp->rx_opt.rcv_tsval = ntohl(*ptr);
			++ptr;
			tp->rx_opt.rcv_tsecr = ntohl(*ptr);

			/* If PAWS failed, check it more carefully in slow path */
			/* ½«±¨ÎÄÖĞµÄÊ±¼ä´ÁÓë×î½ü½ÓÊÕ¶ÎµÄÊ±¼ä´Á±È½Ï£¬Èç¹û½ÏĞ¡£¬ËµÃ÷½ÓÊÕµ½µÄ¶ÎĞòºÅÊÇÔ¤ÆÚµÄ£¬µ«ÊÇÊ±¼ä´Á¹ıÔç£¬·¢ÉúÁËĞòºÅ»ØÈÆ£¬ĞèÒªÂıËÙ´¦Àí */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}

		if (len <= tcp_header_len) {/* ¸Ã¶ÎÃ»ÓĞ¸ººÉ */
			/* Bulk data transfer: sender */
			if (len == tcp_header_len) {/* ÓĞĞ§¶Î */
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&/* Ê×²¿ÖĞ´æÔÚÊ±¼ä´Á£¬ÕâÀïÖ»ĞèÒªÅĞ¶Ï³¤¶È¼´¿É */
				    tp->rcv_nxt == tp->rcv_wup)/* ËùÓĞ¶Î¶¼È·ÈÏÁË */
					tcp_store_ts_recent(tp);/* ±£´æÊ±¼ä´Á£¬ÓÃÓÚ·¢ËÍÏÂÒ»¶ÎµÄÊ±¼ä´Á»ØÏÔ */

				tcp_rcv_rtt_measure_ts(tp, skb);

				/* We know that such packets are checksummed
				 * on entry.
				 */
				/* ¶ÔACK½øĞĞ´¦Àí£¬Èç¸üĞÂ·¢ËÍ´°¿Ú¡¢ÊÍ·ÅÒÑÈ·ÈÏµÄ¶ÎµÈµÈ */
				tcp_ack(sk, skb, 0);
				__kfree_skb(skb); /* ÊÍ·ÅACK¶Î */
				tcp_data_snd_check(sk);/* ¼ì²âÊÇ·ñÓĞÊı¾İĞèÒª·¢ËÍ¸ø¶Ô·½£¬Í¬Ê±¼ì²âÊÇ·ñÓĞ±ØÒªÔö¼Ó·¢ËÍ»º³åÇø´óĞ¡ */
				return 0;
			} else { /* Header too small *//* ±¨ÎÄÌ«Ğ¡£¬·ÇÔ¤ÆÚµÄ¶Î£¬¶ªÆúËü */
				TCP_INC_STATS_BH(TCP_MIB_INERRS);
				goto discard;
			}
		} else {/* ÓĞÊı¾İ¸ººÉ */
			int eaten = 0;

			/* ÅĞ¶ÏÕıÔÚ½ÓÊÕµÄ¶ÎÊÇ·ñ¿ÉÒÔÖ±½Ó¸´ÖÆµ½ÓÃ»§¿Õ¼ä */
			if (tp->ucopy.task == current &&/* ÕıÔÚ½ÓÊÕµÄ¶ÎµÄĞòºÅÊÇ·ñÓëÉĞÎ´´ÓÄÚºË¿Õ¼ä¸´ÖÆµ½ÓÃ»§¿Õ¼äµÄ¶Î×îÇ°ÃæµÄĞòºÅÏàµÈ£¬¼´½ÓÊÕ¶ÓÁĞÓ¦µ±ÊÇ¿ÕµÄ */
			    tp->copied_seq == tp->rcv_nxt &&
			    len - tcp_header_len <= tp->ucopy.len &&/* TCP¶ÎÖĞµÄÓÃ»§Êı¾İ³¤¶ÈĞ¡ÓÚÓÃ»§¿Õ¼ä»º´æµÄÊ£Óà¿ÉÓÃÁ¿ */
			    sock_owned_by_user(sk)) {/* Ëø±»µ±Ç°½ø³Ì³ÖÓĞ */
				__set_current_state(TASK_RUNNING);

				if (!tcp_copy_to_iovec(sk, skb, tcp_header_len)) {/* ½«SKBµÄÊı¾İ¸´ÖÆµ½ÓÃ»§¿Õ¼ä */
					/* Predicted packet is in window by definition.
					 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
					 * Hence, check seq<=rcv_wup reduces to:
					 */
					if (tcp_header_len ==
					    (sizeof(struct tcphdr) +
					     TCPOLEN_TSTAMP_ALIGNED) &&
					    tp->rcv_nxt == tp->rcv_wup)/* ¸üĞÂÊ±¼ä´Á */
						tcp_store_ts_recent(tp);

					tcp_rcv_rtt_measure_ts(tp, skb);/* ¸üĞÂÍù·µÊ±¼ä */

					__skb_pull(skb, tcp_header_len);
					/* ÏÂÒ»¸öÔ¤ÆÚ½ÓÊÕµÄ¶ÎĞòºÅ */
					tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
					NET_INC_STATS_BH(LINUX_MIB_TCPHPHITSTOUSER);
					eaten = 1;
				}
			}
			if (!eaten) {/* Ã»ÓĞ½«Êı¾İÖ±½Ó¸´ÖÆµ½ÓÃ»§¿Õ¼ä£¬»òÕß¸´ÖÆµ½ÓÃ»§¿Õ¼äÊ§°Ü */
				if (tcp_checksum_complete_user(sk, skb))/* ¼ìÑéĞ£ÑéºÍ */
					goto csum_error;

				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)/* ¸üĞÂÊ±¼ä´Á */
					tcp_store_ts_recent(tp);

				tcp_rcv_rtt_measure_ts(tp, skb);

				if ((int)skb->truesize > sk->sk_forward_alloc)/* Èç¹ûÕû¸öskb»º³åÇø×Ü³¤¶È³¬¹ıÔ¤·ÖÅä»º´æ³åÇø³¤£¬ÔòÖ´ĞĞÂıËÙÂ·¾¶ */
					goto step5;

				NET_INC_STATS_BH(LINUX_MIB_TCPHPHITS);

				/* Bulk data transfer: receiver */
				__skb_pull(skb,tcp_header_len);/* ÒÆ¶¯Ö¸Õë£¬Ìø¹ıTCPÍ·²¿ */
				__skb_queue_tail(&sk->sk_receive_queue, skb);/* ½«Êı¾İ°üÌí¼Óµ½½ÓÊÕ¶ÓÁĞÖĞ»º´æÆğÀ´£¬µÈ´ı½ø³ÌÖ÷¶¯¶ÁÈ¡ */
				/* ÉèÖÃskbµÄÊôÖ÷Îªµ±Ç°Ì×¿Ú£¬¸üĞÂÊ¹ÓÃµÄ½ÓÊÕ»º´æ×ÜÁ¿¼°Ô¤·ÖÅä»º´æ³¤¶È */
				sk_stream_set_owner_r(skb, sk);
				/* ÉèÖÃÔ¤ÆÚĞòºÅ */
				tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
			}

			/* ÑÓÊ±È·ÈÏ¿ØÖÆ¿éµÄ¸üĞÂ */
			tcp_event_data_recv(sk, tp, skb);

			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {/* Èç¹û¶ÎÖĞ±êÊ¶µÄackĞòºÅÓëÌ×½Ó¿ÚÎ´È·ÈÏ¶ÎĞòºÅ²»µÈ£¬ÔòĞèÒª´¦Àíack */
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);/* ´¦ÀíACK */
				tcp_data_snd_check(sk);/* Èç¹ûÓĞÊı¾İĞèÒª·¢ËÍ£¬Ôò´¦Àí */
				if (!tcp_ack_scheduled(tp))
					goto no_ack;
			}

			/* ¸ù¾İÇé¿ö×ö¿ìËÙÈ·ÈÏ»òÑÓÊ±È·ÈÏ */
			if (eaten) {
				if (tcp_in_quickack_mode(tp)) {
					tcp_send_ack(sk);
				} else {
					tcp_send_delayed_ack(sk);
				}
			} else {
				__tcp_ack_snd_check(sk, 0);
			}

no_ack:
			/* Èç¹ûÊı¾İÒÑ¾­¸´ÖÆµ½ÓÃ»§¿Õ¼ä£¬ÔòÊÍ·Å¸Ãskb */
			if (eaten)
				__kfree_skb(skb);
			else/* ·ñÔòËµÃ÷Êı¾İÒÑ¾­¾ÍĞ÷£¬»½ĞÑµÈ´ı¶ÓÁĞÉÏµÄ½ø³Ì£¬Í¨ÖªËüÃÇ¶ÁÈ¡Êı¾İ */
				sk->sk_data_ready(sk, 0);
			return 0;
		}
	}

/* Èç¹û±¨ÎÄ²»Âú×ã¿ìËÙÂ·¾¶µÄÌõ¼ş£¬Ôòµ½´ËÖ´ĞĞÂıËÙÂ·¾¶ */
slow_path:
	/* ¼ì²â±¨ÎÄ³¤¶ÈÓĞĞ§ĞÔ¼°Ğ£ÑéºÍ */
	if (len < (th->doff<<2) || tcp_checksum_complete_user(sk, skb))
		goto csum_error;

	/*
	 * RFC1323: H1. Apply PAWS check first.
	 */
	if (tcp_fast_parse_options(skb, th, tp) && tp->rx_opt.saw_tstamp &&/* ½âÎöTCPÑ¡Ïî£¬²¢¼ì²âÊ±¼ä´ÁÑ¡Ïî */
	    tcp_paws_discard(tp, skb)) {/* ÓĞÊ±¼ä´ÁÑ¡Ïîµ«PAWS¼ì²âÊ§°Ü */
		if (!th->rst) {/* Ã»ÓĞRST±êÖ¾ÔòĞèÒªÏò¶Ô·½·¢ËÍDACK£¬ËµÃ÷½ÓÊÕµ½µÄTCP¶Î²»ÔÚ½ÓÊÕ´°¿ÚÄÚ */
			NET_INC_STATS_BH(LINUX_MIB_PAWSESTABREJECTED);
			tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Resets are accepted even if PAWS failed.

		   ts_recent update must be made after we are sure
		   that the packet is in window.
		 */
	}

	/*
	 *	Standard slow path.
	 */

	/* Èç¹û½ÓÊÕµÄ¶ÎĞòºÅ²»ÔÚ½ÓÊÕ´°¿ÚÄÚ */
	if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq)) {
		/* RFC793, page 37: "In all states except SYN-SENT, all reset
		 * (RST) segments are validated by checking their SEQ-fields."
		 * And page 69: "If an incoming segment is not acceptable,
		 * an acknowledgment should be sent in reply (unless the RST bit
		 * is set, if so drop the segment and return)".
		 */
		if (!th->rst)/* Ã»ÓĞ¸´Î»±êÖ¾£¬Ôò·¢ËÍdackÏûÏ¢ */
			tcp_send_dupack(sk, skb);
		goto discard;/* ¶ªÆú¸Ã±¨ÎÄ */
	}

	if(th->rst) {/* ´¦ÀíRSTÇëÇó */
		tcp_reset(sk);
		goto discard;
	}

	/* Èç¹û´æÔÚÊ±¼ä´ÁÑ¡Ïî²¢ÓĞĞ§£¬Ôò±£´æ¸ÃÊ±¼ä´Á */
	tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

	/* ±¨ÎÄÓĞĞ§£¬²¢ÇÒÓĞSYNÑ¡Ïî£¬ËµÃ÷¶Ô·½·¢ËÍÁË´íÎóµÄĞÅÏ¢£¬¸´Î»´¦Àí */
	if (th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		TCP_INC_STATS_BH(TCP_MIB_INERRS);
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONSYN);
		tcp_reset(sk);
		return 1;
	}

step5:
	if(th->ack)/* Í¨³£¶¼ÓĞACKÎ»£¬Ôò´¦Àíack */
		tcp_ack(sk, skb, FLAG_SLOWPATH);

	/* ²ÉÑù¸üĞÂRTT */
	tcp_rcv_rtt_measure_ts(tp, skb);

	/* Process urgent data. */
	tcp_urg(sk, skb, th);/* ÅĞ¶Ï´¦Àí´øÍâÊı¾İ */

	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);/* ´¦Àí¶ÎÖĞµÄÊı¾İ */

	tcp_data_snd_check(sk);/* ¼ì²éÊÇ·ñÓĞÊı¾İĞèÒª·¢ËÍ */
	tcp_ack_snd_check(sk);/* ¼ì²éÊÇ·ñÓĞACKÒª·¢ËÍ(¿ìËÙÈ·ÈÏ»òÑÓÊ±È·ÈÏ) */
	return 0;

csum_error:
	TCP_INC_STATS_BH(TCP_MIB_INERRS);

discard:
	__kfree_skb(skb);
	return 0;
}

/* ÔÚSYN_SENT×´Ì¬ÏÂ´¦Àí½ÓÊÕµ½µÄ¶Î£¬µ«ÊÇ²»´¦Àí´øÍâÊı¾İ */
static int tcp_rcv_synsent_state_process(struct sock *sk, struct sk_buff *skb,
					 struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int saved_clamp = tp->rx_opt.mss_clamp;

	/* ½âÎöTCPÑ¡Ïî²¢±£´æµ½´«Êä¿ØÖÆ¿éÖĞ */
	tcp_parse_options(skb, &tp->rx_opt, 0);

	if (th->ack) {/* ´¦ÀíACK±êÖ¾ */
		/* rfc793:
		 * "If the state is SYN-SENT then
		 *    first check the ACK bit
		 *      If the ACK bit is set
		 *	  If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send
		 *        a reset (unless the RST bit is set, if so drop
		 *        the segment and return)"
		 *
		 *  We do not send data with SYN, so that RFC-correct
		 *  test reduces to:
		 */
		if (TCP_SKB_CB(skb)->ack_seq != tp->snd_nxt)
			goto reset_and_undo;

		if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		    !between(tp->rx_opt.rcv_tsecr, tp->retrans_stamp,
			     tcp_time_stamp)) {
			NET_INC_STATS_BH(LINUX_MIB_PAWSACTIVEREJECTED);
			goto reset_and_undo;
		}

		/* Now ACK is acceptable.
		 *
		 * "If the RST bit is set
		 *    If the ACK was acceptable then signal the user "error:
		 *    connection reset", drop the segment, enter CLOSED state,
		 *    delete TCB, and return."
		 */

		if (th->rst) {/* ÊÕµ½ACK+RST¶Î£¬ĞèÒªtcp_resetÉèÖÃ´íÎóÂë£¬²¢¹Ø±ÕÌ×½Ó¿Ú */
			tcp_reset(sk);
			goto discard;
		}

		/* rfc793:
		 *   "fifth, if neither of the SYN or RST bits is set then
		 *    drop the segment and return."
		 *
		 *    See note below!
		 *                                        --ANK(990513)
		 */
		if (!th->syn)/* ÔÚSYN_SENT×´Ì¬ÏÂ½ÓÊÕµ½µÄ¶Î±ØĞë´æÔÚSYN±êÖ¾£¬·ñÔòËµÃ÷½ÓÊÕµ½µÄ¶ÎÎŞĞ§£¬¶ªÆú¸Ã¶Î */
			goto discard_and_undo;

		/* rfc793:
		 *   "If the SYN bit is on ...
		 *    are acceptable then ...
		 *    (our SYN has been ACKed), change the connection
		 *    state to ESTABLISHED..."
		 */

		/* ´ÓÊ×²¿±êÖ¾ÖĞ»ñÈ¡ÏÔÊ¾ÓµÈûÍ¨ÖªµÄÌØĞÔ */
		TCP_ECN_rcv_synack(tp, th);
		if (tp->ecn_flags&TCP_ECN_OK)/* Èç¹ûÖ§³ÖECN£¬ÔòÉèÖÃ±êÖ¾ */
			sk->sk_no_largesend = 1;

		/* ÉèÖÃÓë´°¿ÚÏà¹ØµÄ³ÉÔ±±äÁ¿ */
		tp->snd_wl1 = TCP_SKB_CB(skb)->seq;
		tcp_ack(sk, skb, FLAG_SLOWPATH);

		/* Ok.. it's good. Set up sequence numbers and
		 * move to established.
		 */
		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd = ntohs(th->window);
		tcp_init_wl(tp, TCP_SKB_CB(skb)->ack_seq, TCP_SKB_CB(skb)->seq);

		if (!tp->rx_opt.wscale_ok) {
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);
		}

		if (tp->rx_opt.saw_tstamp) {/* ¸ù¾İÊÇ·ñÖ§³ÖÊ±¼ä´ÁÑ¡ÏîÀ´ÉèÖÃ´«Êä¿ØÖÆ¿éµÄÏà¹Ø×Ö¶Î */
			tp->rx_opt.tstamp_ok	   = 1;
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
			tp->advmss	    -= TCPOLEN_TSTAMP_ALIGNED;
			tcp_store_ts_recent(tp);
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

		/* ³õÊ¼»¯PMTU¡¢MSSµÈ³ÉÔ±±äÁ¿ */
		if (tp->rx_opt.sack_ok && sysctl_tcp_fack)
			tp->rx_opt.sack_ok |= 2;

		tcp_sync_mss(sk, tp->pmtu_cookie);
		tcp_initialize_rcv_mss(sk);

		/* Remember, tcp_poll() does not lock socket!
		 * Change state from SYN-SENT only after copied_seq
		 * is initialized. */
		tp->copied_seq = tp->rcv_nxt;
		mb();
		tcp_set_state(sk, TCP_ESTABLISHED);

		/* Make sure socket is routed, for correct metrics.  */
		tp->af_specific->rebuild_header(sk);

		tcp_init_metrics(sk);

		/* Prevent spurious tcp_cwnd_restart() on first data
		 * packet.
		 */
		tp->lsndtime = tcp_time_stamp;

		tcp_init_buffer_space(sk);

		/* Èç¹ûÆôÓÃÁËÁ¬½Ó±£»î£¬ÔòÆôÓÃÁ¬½Ó±£»î¶¨Ê±Æ÷ */
		if (sock_flag(sk, SOCK_KEEPOPEN))
			tcp_reset_keepalive_timer(sk, keepalive_time_when(tp));

		if (!tp->rx_opt.snd_wscale)/* Ê×²¿Ô¤²â */
			__tcp_fast_path_on(tp, tp->snd_wnd);
		else
			tp->pred_flags = 0;

		if (!sock_flag(sk, SOCK_DEAD)) {/* Èç¹ûÌ×¿Ú²»´¦ÓÚSOCK_DEAD×´Ì¬£¬Ôò»½ĞÑµÈ´ı¸ÃÌ×½Ó¿ÚµÄ½ø³Ì */
			sk->sk_state_change(sk);
			sk_wake_async(sk, 0, POLL_OUT);
		}

		/* Á¬½Ó½¨Á¢Íê³É£¬¸ù¾İÇé¿ö½øÈëÑÓÊ±È·ÈÏÄ£Ê½ */
		if (sk->sk_write_pending || tp->defer_accept || tp->ack.pingpong) {
			/* Save one ACK. Data will be ready after
			 * several ticks, if write_pending is set.
			 *
			 * It may be deleted, but with this feature tcpdumps
			 * look so _wonderfully_ clever, that I was not able
			 * to stand against the temptation 8)     --ANK
			 */
			tcp_schedule_ack(tp);
			tp->ack.lrcvtime = tcp_time_stamp;
			tp->ack.ato	 = TCP_ATO_MIN;
			tcp_incr_quickack(tp);
			tcp_enter_quickack_mode(tp);
			tcp_reset_xmit_timer(sk, TCP_TIME_DACK, TCP_DELACK_MAX);

discard:
			__kfree_skb(skb);
			return 0;
		} else {/* ²»ĞèÒªÑÓÊ±È·ÈÏ£¬Á¢¼´·¢ËÍACK¶Î */
			tcp_send_ack(sk);
		}
		return -1;
	}

	/* No ACK in the segment */

	if (th->rst) {/* ÊÕµ½RST¶Î£¬Ôò¶ªÆú´«Êä¿ØÖÆ¿é */
		/* rfc793:
		 * "If the RST bit is set
		 *
		 *      Otherwise (no ACK) drop the segment and return."
		 */

		goto discard_and_undo;
	}

	/* PAWS check. */
	/* PAWS¼ì²âÊ§Ğ§£¬Ò²¶ªÆú´«Êä¿ØÖÆ¿é */
	if (tp->rx_opt.ts_recent_stamp && tp->rx_opt.saw_tstamp && tcp_paws_check(&tp->rx_opt, 0))
		goto discard_and_undo;

	/* ÔÚSYN_SENT×´Ì¬ÏÂÊÕµ½ÁËSYN¶Î²¢ÇÒÃ»ÓĞACK£¬ËµÃ÷ÊÇÁ½¶ËÍ¬Ê±´ò¿ª */
	if (th->syn) {
		/* We see SYN without ACK. It is attempt of
		 * simultaneous connect with crossed SYNs.
		 * Particularly, it can be connect to self.
		 */
		tcp_set_state(sk, TCP_SYN_RECV);/* ÉèÖÃ×´Ì¬ÎªTCP_SYN_RECV */

		if (tp->rx_opt.saw_tstamp) {/* ÉèÖÃÊ±¼ä´ÁÏà¹ØµÄ×Ö¶Î */
			tp->rx_opt.tstamp_ok = 1;
			tcp_store_ts_recent(tp);
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

		/* ³õÊ¼»¯´°¿ÚÏà¹ØµÄ³ÉÔ±±äÁ¿ */
		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd    = ntohs(th->window);
		tp->snd_wl1    = TCP_SKB_CB(skb)->seq;
		tp->max_window = tp->snd_wnd;

		TCP_ECN_rcv_syn(tp, th);/* ´ÓÊ×²¿±êÖ¾ÖĞ»ñÈ¡ÏÔÊ½ÓµÈûÍ¨ÖªµÄÌØĞÔ¡£ */
		if (tp->ecn_flags&TCP_ECN_OK)
			sk->sk_no_largesend = 1;

		/* ³õÊ¼»¯MSSÏà¹ØµÄ³ÉÔ±±äÁ¿ */
		tcp_sync_mss(sk, tp->pmtu_cookie);
		tcp_initialize_rcv_mss(sk);

		/* Ïò¶Ô¶Ë·¢ËÍSYN+ACK¶Î£¬²¢¶ªÆú½ÓÊÕµ½µÄSYN¶Î */
		tcp_send_synack(sk);
#if 0
		/* Note, we could accept data and URG from this segment.
		 * There are no obstacles to make this.
		 *
		 * However, if we ignore data in ACKless segments sometimes,
		 * we have no reasons to accept it sometimes.
		 * Also, seems the code doing it in step6 of tcp_rcv_state_process
		 * is not flawless. So, discard packet for sanity.
		 * Uncomment this return to process the data.
		 */
		return -1;
#else
		goto discard;
#endif
	}
	/* "fifth, if neither of the SYN or RST bits is set then
	 * drop the segment and return."
	 */

discard_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	goto discard;

reset_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	return 1;
}


/*
 *	This function implements the receiving procedure of RFC 793 for
 *	all states except ESTABLISHED and TIME_WAIT. 
 *	It's called from both tcp_v4_rcv and tcp_v6_rcv and should be
 *	address independent.
 */
/* ³ıÁËESTABLISHEDºÍTIME_WAIT×´Ì¬Íâ£¬ÆäËû×´Ì¬ÏÂµÄTCP¶Î´¦Àí¶¼ÓÉ±¾º¯ÊıÊµÏÖ */	
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
			  struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int queued = 0;

	tp->rx_opt.saw_tstamp = 0;

	switch (sk->sk_state) {
	case TCP_CLOSE:
		goto discard;

	case TCP_LISTEN:/* TCP_LISTEN×´Ì¬£¬Ö»´¦ÀíSYN¶Î */
		if(th->ack)/* Èç¹ûÊÇACK±¨ÎÄ£¬ÓÉÓÚÁ¬½Ó»¹Ã»ÓĞ½¨Á¢£¬Òò´Ë·µ»Ø1Ïò¶Ô·½·¢ËÍRST */
			return 1;

		if(th->rst)/* RST¶ÎÖ±½Ó¶ªÆú */
			goto discard;

		if(th->syn) {/* ´¦ÀíSYN±¨ÎÄÇëÇó */
			/* ´¦Àí¿Í»§¶ËÁ¬½ÓÇëÇó£¬tcp_v4_conn_request */
			if(tp->af_specific->conn_request(sk, skb) < 0)
				return 1;

			init_westwood(sk);
			init_bictcp(tp);

			/* Now we have several options: In theory there is 
			 * nothing else in the frame. KA9Q has an option to 
			 * send data with the syn, BSD accepts data with the
			 * syn up to the [to be] advertised window and 
			 * Solaris 2.1 gives you a protocol error. For now 
			 * we just ignore it, that fits the spec precisely 
			 * and avoids incompatibilities. It would be nice in
			 * future to drop through and process the data.
			 *
			 * Now that TTCP is starting to be used we ought to 
			 * queue this data.
			 * But, this leaves one open to an easy denial of
		 	 * service attack, and SYN cookies can't defend
			 * against this problem. So, we drop the data
			 * in the interest of security over speed.
			 */
			goto discard;
		}
		goto discard;

	case TCP_SYN_SENT:/* Ô¤ÆÚÓ¦µ±´¦ÀíÖ÷¶¯Á¬½ÓµÄµÚ¶ş´ÎÎÕÊÖ */
		init_westwood(sk);
		init_bictcp(tp);

		/* tcp_rcv_synsent_state_process´¦ÀíSYN_SENT×´Ì¬ÏÂ½ÓÊÕµ½µÄTCP¶Î */
		queued = tcp_rcv_synsent_state_process(sk, skb, th, len);
		if (queued >= 0)/* Èç¹û·µ»ØÖµ´óÓÚ0£¬±íÊ¾ĞèÒª¸ø¶Ô¶Ë·¢ËÍRST¶Î£¬ÓÉÉÏ²ã´¦Àí */
			return queued;

		/* Do step6 onward by hand. */
		/* ´¦ÀíÍêµÚ¶ş´ÎÎÕÊÖºó£¬»¹ĞèÒª´¦Àí´øÍâÊı¾İ */
		tcp_urg(sk, skb, th);
		/* ÊÍ·Å±¨ÎÄ */
		__kfree_skb(skb);
		/* ¼ì²âÊÇ·ñÓĞÊı¾İĞèÒª·¢ËÍ */
		tcp_data_snd_check(sk);
		return 0;
	}

	/* SYN_RECV×´Ì¬µÄ´¦Àí */
	if (tcp_fast_parse_options(skb, th, tp) && tp->rx_opt.saw_tstamp &&/* ½âÎöTCPÑ¡Ïî£¬Èç¹ûÊ×²¿ÖĞ´æÔÚÊ±¼ä´ÁÑ¡Ïî */
	    tcp_paws_discard(tp, skb)) {/* PAWS¼ì²âÊ§°Ü£¬Ôò¶ªÆú±¨ÎÄ */
		if (!th->rst) {/* Èç¹û²»ÊÇRST¶Î */
			/* ·¢ËÍDACK¸ø¶Ô¶Ë£¬ËµÃ÷½ÓÊÕµ½µÄTCP¶ÎÒÑ¾­´¦Àí¹ı */
			NET_INC_STATS_BH(LINUX_MIB_PAWSESTABREJECTED);
			tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Reset is accepted even if it did not pass PAWS. */
	}

	/* step 1: check sequence number */
	if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq)) {/* TCP¶ÎĞòºÅÎŞĞ§ */
		if (!th->rst)/* Èç¹ûTCP¶ÎÎŞRST±êÖ¾£¬Ôò·¢ËÍDACK¸ø¶Ô·½ */
			tcp_send_dupack(sk, skb);
		goto discard;
	}

	/* step 2: check RST bit */
	if(th->rst) {/* Èç¹ûÓĞRST±êÖ¾£¬ÔòÖØÖÃÁ¬½Ó */
		tcp_reset(sk);
		goto discard;
	}

	/* Èç¹ûÓĞ±ØÒª£¬Ôò¸üĞÂÊ±¼ä´Á */
	tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

	/* step 3: check security and precedence [ignored] */

	/*	step 4:
	 *
	 *	Check for a SYN in window.
	 */
	if (th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {/* Èç¹ûÓĞSYN±êÖ¾²¢ÇÒĞòºÅÔÚ½ÓÊÕ´°¿ÚÄÚ */
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONSYN);
		tcp_reset(sk);/* ¸´Î»Á¬½Ó */
		return 1;
	}

	/* step 5: check the ACK field */
	if (th->ack) {/* Èç¹ûÓĞACK±êÖ¾ */
		/* ¼ì²éACKÊÇ·ñÎªÕı³£µÄµÚÈı´ÎÎÕÊÖ */
		int acceptable = tcp_ack(sk, skb, FLAG_SLOWPATH);

		switch(sk->sk_state) {
		case TCP_SYN_RECV:
			if (acceptable) {
				tp->copied_seq = tp->rcv_nxt;
				mb();
				/* Õı³£µÄµÚÈı´ÎÎÕÊÖ£¬ÉèÖÃÁ¬½Ó×´Ì¬ÎªTCP_ESTABLISHED */
				tcp_set_state(sk, TCP_ESTABLISHED);
				sk->sk_state_change(sk);

				/* Note, that this wakeup is only for marginal
				 * crossed SYN case. Passively open sockets
				 * are not waked up, because sk->sk_sleep ==
				 * NULL and sk->sk_socket == NULL.
				 */
				if (sk->sk_socket) {/* ×´Ì¬ÒÑ¾­Õı³££¬»½ĞÑÄÇĞ©µÈ´ıµÄÏß³Ì */
					sk_wake_async(sk,0,POLL_OUT);
				}

				/* ³õÊ¼»¯´«Êä¿ØÖÆ¿é£¬Èç¹û´æÔÚÊ±¼ä´ÁÑ¡Ïî£¬Í¬Ê±Æ½»¬RTTÎª0£¬ÔòĞè¼ÆËãÖØ´«³¬Ê±Ê±¼ä */
				tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
				tp->snd_wnd = ntohs(th->window) <<
					      tp->rx_opt.snd_wscale;
				tcp_init_wl(tp, TCP_SKB_CB(skb)->ack_seq,
					    TCP_SKB_CB(skb)->seq);

				/* tcp_ack considers this ACK as duplicate
				 * and does not calculate rtt.
				 * Fix it at least with timestamps.
				 */
				if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
				    !tp->srtt)
					tcp_ack_saw_tstamp(tp, 0);

				if (tp->rx_opt.tstamp_ok)
					tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;

				/* Make sure socket is routed, for
				 * correct metrics.
				 */
				/* ½¨Á¢Â·ÓÉ£¬³õÊ¼»¯ÓµÈû¿ØÖÆÄ£¿é */
				tp->af_specific->rebuild_header(sk);

				tcp_init_metrics(sk);

				/* Prevent spurious tcp_cwnd_restart() on
				 * first data packet.
				 */
				tp->lsndtime = tcp_time_stamp;/* ¸üĞÂ×î½üÒ»´Î·¢ËÍÊı¾İ°üµÄÊ±¼ä */

				tcp_initialize_rcv_mss(sk);
				tcp_init_buffer_space(sk);
				tcp_fast_path_on(tp);/* ¼ÆËãÓĞ¹ØTCPÊ×²¿Ô¤²âµÄ±êÖ¾ */
			} else {
				return 1;
			}
			break;

		case TCP_FIN_WAIT1:/* ´¦ÀíFIN_WAIT1×´Ì¬ÏÂ½ÓÊÕµ½µÄACK */
			if (tp->snd_una == tp->write_seq) {/* Í¨¹ıACK¶ÎµÄÈ·ÈÏ£¬ËùÓĞ·¢ËÍ¶Î¶Ô·½¶¼ÒÑ¾­ÊÕµ½£¬ÔòÇ¨ÒÆµ½FIN_WAIT2×´Ì¬ */
				tcp_set_state(sk, TCP_FIN_WAIT2);
				sk->sk_shutdown |= SEND_SHUTDOWN;
				dst_confirm(sk->sk_dst_cache);/* ´Ó¶Ô·½ÊÕµ½ACK¶Î£¬Òò´Ë¿ÉÒÔÈ·ÈÏ´ËÂ·ÓÉ»º´æÓĞĞ§ */

				if (!sock_flag(sk, SOCK_DEAD))/* ²»ÔÚDEAD×´Ì¬²¢ÇÒ×´Ì¬·¢ÉúÁË±ä»¯£¬Í¨¹ıµÈ´ıµÄÏß³Ì */
					/* Wake up lingering close() */
					sk->sk_state_change(sk);
				else {/* ÔÚDEAD×´Ì¬£¬ÔòĞèÒª¹Ø±Õ´«Êä¿ØÖÆ¿é£¬»òÕßÔÚFIN_WAIT2×´Ì¬µÈ´ı */
					int tmo;

					if (tp->linger2 < 0 ||/* ÎŞĞèÒªÔÚFIN_WAIT2×´Ì¬µÈ´ı */
					    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&/* ½ÓÊÕµÄ¶ÎÓĞÊı¾İ²¢ÇÒ½ÓÊÕµÄ¶Î¶¼ÒÑ¾­Íê±Ï */
					     after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt))) {
						tcp_done(sk);/* ÎŞĞèµÈ´ı£¬Ö±½Ó¹Ø±ÕÌ×½Ó¿Ú */
						NET_INC_STATS_BH(LINUX_MIB_TCPABORTONDATA);
						return 1;
					}

					/* ÔÚFIN_WAIT2µÈ´ı */
					tmo = tcp_fin_time(tp);
					if (tmo > TCP_TIMEWAIT_LEN) {
						tcp_reset_keepalive_timer(sk, tmo - TCP_TIMEWAIT_LEN);
					} else if (th->fin || sock_owned_by_user(sk)) {
						/* Bad case. We could lose such FIN otherwise.
						 * It is not a big problem, but it looks confusing
						 * and not so rare event. We still can lose it now,
						 * if it spins in bh_lock_sock(), but it is really
						 * marginal case.
						 */
						tcp_reset_keepalive_timer(sk, tmo);
					} else {
						tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
						goto discard;
					}
				}
			}
			break;

		case TCP_CLOSING:/* Õâ¸ö×´Ì¬ÊÇ´¦ÀíÍ¬Ê±¹Ø±Õ */
			if (tp->snd_una == tp->write_seq) {/* ËùÓĞµÄ¶Î¶¼ÒÑ¾­ÊÕµ½ */
				tcp_time_wait(sk, TCP_TIME_WAIT, 0);/* Ç¨ÒÆµ½wait×´Ì¬ */
				goto discard;
			}
			break;

		case TCP_LAST_ACK:
			if (tp->snd_una == tp->write_seq) {/* ËùÓĞ¶Î¶¼ÒÑ¾­ÊÕµ½ */
				tcp_update_metrics(sk);/* ¸üĞÂÂ·ÓÉ»º´æ²¢¹Ø±ÕÌ×½Ó¿Ú */
				tcp_done(sk);
				goto discard;
			}
			break;
		}
	} else
		goto discard;

	/* step 6: check the URG bit */
	tcp_urg(sk, skb, th);/* ¼ì²â´øÍâÊı¾İÎ» */

	/* step 7: process the segment text */
	switch (sk->sk_state) {
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		/* ÕâÈıÖÖ×´Ì¬£¬Èç¹û½ÓÊÕµ½ÒÑ¾­È·ÈÏ¹ıµÄ¶Î£¬ÔòÖ±½Ó¶ªÆú */
		if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* RFC 793 says to queue data in these states,
		 * RFC 1122 says we MUST send a reset. 
		 * BSD 4.4 also does reset.
		 */
		if (sk->sk_shutdown & RCV_SHUTDOWN) {/* ½ÓÊÕ·½ÏòÒÑ¾­¹Ø±Õ */
			/* ½ÓÊÕµ½ĞÂÊı¾İ */
			if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
			    after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt)) {
				NET_INC_STATS_BH(LINUX_MIB_TCPABORTONDATA);
				tcp_reset(sk);/* ¸ø¶Ô·½·¢ËÍ¸´Î»ÏûÏ¢ */
				return 1;
			}
		}
		/* Fall through */
	case TCP_ESTABLISHED: 
		tcp_data_queue(sk, skb);/* ¶ÔÒÑ¾­½ÓÊÕµ½µÄ¶Î½øĞĞÅÅ¶Ó£¬Ó¦¸ÃÊÇÔÚ´¦Àí¿ìËÙTCP£¬ÔÚ·¢ËÍACKµÄÍ¬Ê±·¢ËÍÁËÊı¾İ¶Î */
		queued = 1;
		break;
	}

	/* tcp_data could move socket to TIME-WAIT */
	if (sk->sk_state != TCP_CLOSE) {/* Èç¹ûtcp_dataĞèÒª·¢ËÍÊı¾İºÍACKÔòÔÚÕâÀï´¦Àí */
		tcp_data_snd_check(sk);
		tcp_ack_snd_check(sk);
	}

	if (!queued) { /* Èç¹û¶ÎÃ»ÓĞ¼ÓÈë¶ÓÁĞ£¬»òÕßÇ°ÃæµÄÁ÷³ÌĞèÒªÊÍ·Å±¨ÎÄ£¬ÔòÊÍ·ÅËü */
discard:
		__kfree_skb(skb);
	}
	return 0;
}

EXPORT_SYMBOL(sysctl_tcp_ecn);
EXPORT_SYMBOL(sysctl_tcp_reordering);
EXPORT_SYMBOL(tcp_parse_options);
EXPORT_SYMBOL(tcp_rcv_established);
EXPORT_SYMBOL(tcp_rcv_state_process);
