/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Version:	$Id: ip_input.c,v 1.55 2002/01/12 07:39:45 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *  
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single 
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/config.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *	SNMP management statistics
 */
/**
 * IPÐ­ÒéÍ³¼Æ¼ÆÊý¡£
 */
DEFINE_SNMP_STAT(struct ipstats_mib, ip_statistics);

/*
 *	Process Router Attention IP option
 */ 
int ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = skb->nh.iph->protocol;
	struct sock *last = NULL;

	read_lock(&ip_ra_lock);
	for (ra = ip_ra_chain; ra; ra = ra->next) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == skb->dev->ifindex)) {
			if (skb->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
				skb = ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN);
				if (skb == NULL) {
					read_unlock(&ip_ra_lock);
					return 1;
				}
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		read_unlock(&ip_ra_lock);
		return 1;
	}
	read_unlock(&ip_ra_lock);
	return 0;
}

/**
 * L3µ½L4µÄ´«µÝ:Ö÷Òª¹¤×÷ÊÇ¸ù¾ÝÊäÈëIP°ü±¨Í·µÄ"Ð­Òé"×Ö¶ÎÕÒ³öÕýÈ·µÄÐ­Òé´¦Àíº¯Êý£¬È»ºó°Ñ¸Ã°ü½»¸ø¸Ã´¦Àíº¯Êý¡£
 * Í¬Ê±£¬ip_local_deliver_finish±ØÐë´¦ÀíRaw IP¡£´ËÍâ£¬Èç¹ûÓÐÅäÖÃ°²È«²ßÂÔ£¬¸Ãº¯ÊýÒ²ÒªÊ©¼Ó°²È«¼ì²é¡£
 */
static inline int ip_local_deliver_finish(struct sk_buff *skb)
{
	/**
	 * skb->nhÊÇÔÚnetif_receive_skbÖÐ³õÊ¼»¯£¬À´Ö¸ÏòIP±¨Í·µÄ¿ª¶Ë¡£
	 */
	int ihl = skb->nh.iph->ihl*4;

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_local_deliver(skb);
#endif /*CONFIG_NETFILTER_DEBUG*/

	/**
	 * ´ËÊ±ÄÚºË²»ÔÙÐèÒªIP±¨Í·ÁË£¬ÒòÎªIP²ãµÄÊÂÇéÒÑ¾­×öÍê£¬¶øÇÒ°üÒ²Òª´«¸øÏÂÒ»¸ö½Ï¸ß²ãÁË¡£
	 * Òò´Ë£¬ÕâÀïËùÊ¾µÄ__skb_pullµ÷ÓÃ»á°Ñ°üµÄÊý¾Ý²¿·ÖËõÐ¡À´ºöÂÔL3±¨Í·
	 */
	__skb_pull(skb, ihl);

	/* Free reference early: we don't need it any more, and it may
           hold ip_conntrack module loaded indefinitely. */
	nf_reset(skb);

        /* Point into the IP datagram, just past the header. */
		/**
		 * L4²ãÆðÊ¼µØÖ·¡£
		 */
        skb->h.raw = skb->data;

	rcu_read_lock();
	{
		/* Note: See raw.c and net/raw.h, RAWV4_HTABLE_SIZE==MAX_INET_PROTOS */
		/**
		 * Ð­ÒéIDÊÇ´Óskb->nh.iph->protocol±äÁ¿£¨Ö¸ÏòIP±¨Í·µÄ"Ð­Òé"×Ö¶Î£©È¡³öµÄ¡£
		 */
		int protocol = skb->nh.iph->protocol;
		int hash;
		struct sock *raw_sk;
		struct net_protocol *ipprot;

	resubmit:
		hash = protocol & (MAX_INET_PROTOS - 1);
		/**
		 * Ð­Òé¶ÔÓ¦µÄµÚÒ»¸öÔ­Ê¼Ì×¿Ú
		 */
		raw_sk = sk_head(&raw_v4_htable[hash]);

		/* If there maybe a raw socket we must check - if not we
		 * don't care less
		 */
		if (raw_sk)/* ´æÔÚÔ­Ê¼Ì×¿Ú£¬µ÷ÓÃraw_v4_input´¦ÀíËüÃÇ¡£raw_v4_input»á¸´ÖÆÊý¾Ý°ü¡£ */
			raw_v4_input(skb, skb->nh.iph, hash);

		/**
		 * ²éÕÒÄÚºËÖÐ×¢²áµÄÐ­Òé´¦Àíº¯Êý¡£
		 */
		if ((ipprot = rcu_dereference(inet_protos[hash])) != NULL) {
			int ret;

			/**
			 * Èç¹û´ËL4²ã´¦Àíº¯ÊýÐèÒª¼ì²éIPSEC²¢ÇÒÃ»ÓÐÍ¨¹ý¼ì²é£¬¾ÍÊÍ·Å°ü²¢ÍË³ö¡£
			 */
			if (!ipprot->no_policy &&
			    !xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				kfree_skb(skb);
				goto out;
			}
			/**
			 * µ÷ÓÃL4²ã´¦Àíº¯Êý¡£
			 */
			ret = ipprot->handler(skb);
			if (ret < 0) {/* ÕâÀïÓ¦¸ÃÊÇ´¦ÀíIPSEC */
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw_sk) {/* Ã»ÓÐL4²ã´¦Àíº¯Êý£¬Í¬Ê±Ã»ÓÐ¶ÔÓ¦µÄÔ­Ê¼Ì×½Ó×Ö´¦Àí¸Ã°ü¡£ */
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {/* Èç¹ûIPSECÔÊÐí¶Ô¸Ã°ü·¢ËÍICMP£¬Ôò»ØËÍICMPÏûÏ¢¡£ */
					IP_INC_STATS_BH(IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
			} else
				IP_INC_STATS_BH(IPSTATS_MIB_INDELIVERS);
			kfree_skb(skb);/* ÊÍ·Å°ü¡£ */
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */ 
/**
 * IPV4´¦Àí±¾µØ±¨ÎÄ½ÓÊÕ¡£
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	/**
	 * ºÍ×ª·¢£¨ÖØ×é»ù±¾ÉÏ¿ÉÒÔºöÂÔ£©Ïà·´µÄÊÇ£¬±¾µØ´«µÝ±ØÐë×öºÜ¶à¹¤×÷À´´¦ÀíÖØ×é¹¤×÷¡£
	 * ÔÚMF±êÖ¾»òÕßOFFSET²»Îª0£¬¶¼±íÊ¾ÊÇÒ»¸ö·ÖÆ¬¡£
	 */
	if (skb->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		/**
		 * ÖØ×é¹¤×÷ÊÇÔÚip_defragº¯ÊýÄÚ½øÐÐµÄ¡£
		 * µ±ip_defragÍê³ÉÖØ×é¹¤×÷Ê±£¬»á·µ»ØÒ»¸öÖ¸ÏòÔ­ÓÐ°üµÄÖ¸Õë£¬µ«ÊÇ£¬Èç¹û°ü»¹²»ÍêÕû£¬¾Í·µ»ØNULL¡£
		 */
		skb = ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER);
		if (!skb)
			return 0;
	}

	/**
	 * Èç¹ûÍ¨¹ýÁËnetfilterµÄ¼ì²é£¬°ü±»ip_local_deliver_finish´«µÝ¸øÉÏ²ãº¯Êý´¦Àí¡£
	 */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

/**
 * ip_recvµÄÖ÷Òª´¦Àíº¯Êý¡£´ËÊ±£¬°üÒÑ¾­Í¨¹ýÁË»ù±¾µÄ½¡¿µ¼ì²é£¬ÒÔ¼°·À»ðÇ½Éó²é¡£±¾º¯ÊýµÄÖ÷Òª¹¤×÷ÓÐå£º
 *		¾ö¶¨°üÊÇ·ñ±ØÐë±¾µØ´«µÝ»òÕß×ª·¢¡£Èç¹ûÐèÒª×ª·¢£¬¾Í±ØÐëÕÒµ½³ö¿ÚÉè±¸ºÍÏÂÒ»¸öÌøµã¡£
 *		·ÖÎöºÍ´¦ÀíÒ»Ð©IPÑ¡Ïî¡£È»¶ø£¬¹Ø°­ËùÓÐIPÑ¡Ïî¶¼ÔÚ´Ë´¦Àí¡£
 */
static inline int ip_rcv_finish(struct sk_buff *skb)
{
	/**
	 * skb->nh×Ö¶ÎÊÇÔÚnetif_receive_skbÀï³õÊ¼»¯µÄ¡£
	 * µ±Ê±£¬»¹²»ÖªµÀL3Ð­Òé£¬ËùÒÔ»áÊ¹ÓÃnh.raw×ö³õÊ¼»¯¡£ÏÖÔÚ£¬´Ëº¯Êý¿ÉÒÔÈ¡µÃÖ¸ÏòIP±¨Í·µÄÖ¸ÕëÁË¡£
	 */
	struct net_device *dev = skb->dev;
	struct iphdr *iph = skb->nh.iph;

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */ 
	/**
	 * skb->dst¿ÉÄÜ°üº¬°üÍ¨ÍùÆäÄ¿µÄµØµÄÂ·ÓÉÐÅÏ¢¡£
	 * Èç¹ûÃ»ÓÐµÃÖª¸ÃÏûÏ¢£¬´Ëº¯Êý»áÑ¯ÎÊÂ·ÓÉ×ÓÏµÍ³¸Ã°Ñ°ü´«ËÍµ½ÄÄ¶ù.
	 * ×¢:µ±°ü½øÈë´Ëº¯ÊýÊ±£¬Èç¹ûÊÇ»·»ØÉè±¸£¬dstÓ¦¸ÃÒÑ¾­×¼±¸ºÃÁË¡£
	 */
	if (skb->dst == NULL) {
		/**
		 * Èç¹ûÂ·ÓÉ×ÓÏµÍ³ËµÄ¿µÄµØÎÞ·¨µÖ´ï£¬Ôò¸Ã°ü»á±»¶ªÆú¡£
		 */
		if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos, dev))
			goto drop; 
	}

#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * ¸üÐÂÒ»Ð©QoSËùÓÃµÄÍ³¼ÆÊý¾Ý¡£
	 */
	if (skb->dst->tclassid) {
		struct ip_rt_acct *st = ip_rt_acct + 256*smp_processor_id();
		u32 idx = skb->dst->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes+=skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes+=skb->len;
	}
#endif

	/**
	 * µ±IP±¨Í·µÄ³¤¶È´óÓÚ20×Ö½Ú£¨5*32Î»£©£¬±íÊ¾ÓÐÒ»Ð©Ñ¡ÏîÐèÒª´¦Àí¡£
	 */
	if (iph->ihl > 5) {
		struct ip_options *opt;

		/* It looks as overkill, because not all
		   IP options require packet mangling.
		   But it is the easiest for now, especially taking
		   into account that combination of IP options
		   and running sniffer is extremely rare condition.
		                                      --ANK (980813)
		*/

		/**
		 * skb_cow±»µ÷ÓÃ¡£Èç¹û»º³åÇøºÍ±ðÈË¹²Ïí£¬¾Í»á×ö³ö»º³åÇøµÄ¸±±¾.
		 * ¶Ô»º³åÇø¾ßÓÐÅÅËûÓµÓÐÈ¨ÊÇ±ØÒªµÄ£¬ÒòÎªÎÒÃÇÒª´¦ÀíÄÇÐ©Ñ¡Ïî£¬¶øÇÒÓÐ¿ÉÄÜÐèÒªÐÞ¸ÄIP±¨Í·¡£
		 */
		if (skb_cow(skb, skb_headroom(skb))) {
			IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
			goto drop;
		}
		iph = skb->nh.iph;

		/**
		 * ip_option_compileÓÃÓÚ½â¶Á±¨Í·ÖÐËùÐ¯´øµÄIPÑ¡Ïî¡£
		 * IP²ãÓÃcb×Ö¶Î´æ´¢IP±¨Í·Ñ¡Ïî·ÖÎö½á¹ûÒÔ¼°ÆäËûÒ»Ð©Êý¾Ý£¨Èç·Ö¶ÎÏà¹ØµÄÐÅÏ¢£©¡£
		 * ´Ë½á¹û´¢´æÔÚÒ»¸östruct inet_skb_parmÀàÐÍµÄÊý¾Ý½á¹¹£¨¶¨ÒåÔÚinclude/net/ip.hÖÐ£©£¬¶øÇÒ¿ÉÒÔÓÉºêIPCB´æÈ¡¡£
		 */
		if (ip_options_compile(NULL, skb))
			goto inhdr_error;/* Èç¹ûÓÐÈÎºÎ´íÎóµÄÑ¡Ïî£¬°ü¾Í»á±»¶ªÆú¡£¶øÒ»ÌõÌØÊâµÄICMPÏûÏ¢¾Í»áËÍ»Ø¸ø´«ËÍÕßÀ´¸æÖªËù·¢ÉúµÄÎÊÌâ¡£ */

		/**
		 * ip_options_compile½«Ñ¡Ïî±£´æÔÚskb->cbÖÐ£¬´Ë´¦È¡³öÑ¡Ïî£¬½øÐÐ´¦Àí¡£
		 */
		opt = &(IPCB(skb)->opt);
		/**
		 * ´¦ÀíIPÔ´Â·ÓÉ
		 */
		if (opt->srr) {
			struct in_device *in_dev = in_dev_get(dev);
			if (in_dev) {
				/**
				 * ÅäÖÃ²»ÔÊÐí½øÐÐÔ´Â·ÓÉ¡£
				 */
				if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
					if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
						printk(KERN_INFO "source route option %u.%u.%u.%u -> %u.%u.%u.%u\n",
						       NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
					in_dev_put(in_dev);
					goto drop;
				}
				in_dev_put(in_dev);
			}
			/**
			 * ip_options_rcv_srr¸ù¾ÝÔ´Â·ÓÉÑ¡Ïî£¬È·¶¨Ê¹ÓÃÄÄ¸öÉè±¸°Ñ¸Ã°ü×ª·¢ÖÁÀ´Ô´µØÂ·ÓÉÁÐ±íÖÐµÄÏÂÒ»¸öÌøµã¡£
			 * ip_options_rcv_srr»¹µÃ¿¼ÂÇ"ÏÂÒ»Ìøµã"ÊÇ±¾µØÖ÷»úµÄÒ»¸ö½Ó¿ÚµÄ¿ÉÄÜÐÔ¡£Èç¹û·¢ÉúÕâÖÖÊÂÇé£¬´Ëº¯Êý»á°Ñ¸ÃIPµØÖ·Ð´ÈëIP±¨Í·µÄÄ¿µÄµØIPµØÖ·£¬È»ºó¼ÌÐø¼ì²éÀ´Ô´µØÂ·ÓÉÁÐ±íÖÐµÄÏÂÒ»¸öµØÖ·£¨Èç¹ûÓÐµÄ»°£©¡£ÔÚ³ÌÐòÖÐ£¬Õâ±»³ÆÎª"³¬¿ìÑ­»·×ª·¢"¡£
			 * Ip_options_rcv_srr»á³ÖÐøä¯ÀÀIP±¨Í·À´Ô´µØÖ·Â·ÓÉÑ¡ÏîÇø¿éÖÐµÄÏÂÒ»¸öÌøµãÁÐ±í¡£Ö±µ½ÆäÕÒµ½Ò»¸ö²»ÊÇÖ÷»ú±¾µØµÄIPµØÖ·¡£Õý³£µÄËµ£¬¸ÃÁÐ±íÖÐ²»»áÓÐÒ»¸öÒÔÉÏµÄ±¾µØIPµØÖ·¡£È»¶ø£¬ÓÐÒ»¸öÒÔÉÏÒ²ÊÇºÏ·¨µÄ¡£
			 */
			if (ip_options_rcv_srr(skb))
				goto drop;
		}
	}

	/**
	 * dst_inputÊµ¼ÊÉÏ»áµ÷ÓÃ´æ´¢ÓÚskb»º³åÇøµÄdst×Ö¶ÎµÄº¯Êý¡£
	 * skb->dstµÄ³õÊ¼»¯²»ÊÇÔÚip_rcv_finishµÄ¿ª¶Ë£¬¾ÍÊÇÔÚip_options_rcv_srrµÄÎ²¶Ë¡£
	 * skb->dst->input»áÉè³Éip_local_deliver»òip_forward£¬ÕâÈ¡¾öÓÚ°üµÄÄ¿µÄµØÖ·¡£
	 * Òò´Ë£¬µ÷ÓÃdst_inputÊ±£¬¾Í¿ÉÒÔÍê³É°üµÄ´¦Àí¡£
	 */
	return dst_input(skb);

inhdr_error:
	IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */ 
/**
 * IPV4Èë°üÖ÷´¦Àíº¯Êý¡£
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
	struct iphdr *iph;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	/**
	 * Êý¾ÝÖ¡µÄL2Ä¿µÄµØÖ·ºÍ½ÓÊÕ½Ó¿ÚµÄµØÖ·²»Í¬Ê±£¬skb->pkt_type¾Í»á±»ÉèÖÃ³ÉPACKET_OTHERHOST¡£Í¨³£ÕâÐ©°ü»á±»NIC±¾Éí¶ªÆú¡£
	 * È»¶ø£¬Èç¹û¸Ã½Ó¿ÚÒÑ¾­½øÈë»ìÔÓÄ£Ê½£¬ÎÞÂÛÄ¿µÄµØL2µØÖ·ÎªºÎ£¬¶¼»á½ÓÊÕËùÓÐ°ü²¢½«Æä×ª¸ø½Ï¸ß²ã¡£
	 * ÄÚºË»áµ÷ÓÃÄÇÐ©ÒªÇóÒª´æÈ¡ËùÓÐ°üµÄÐáÌ½Æ÷¡£µ«ÊÇip_rcvºÍ´«¸øÆäËûµØÖ·µÄÈë°üÎÞ¹Ø£¬¶øÖ»»á¼òµ¥µÄ¶ªÆúËüÃÇ¡£
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	IP_INC_STATS_BH(IPSTATS_MIB_INRECEIVES);

	/**
	 * Skb_share_check»á¼ì²é°üµÄÒýÓÃ¼ÆÊýÊÇ·ñ´óÓÚ1£¬´óÓÚ1Ôò±íÊ¾ÄÚºËµÄÆäËû²¿·ÖÓµÓÐ¶Ô¸Ã»º³åÇøµÄÒýÓÃ¡£
	 * Èç¹ûÒýÓÃ¼ÆÊý´óÓÚ1£¬¾Í»á×Ô¼º½¨ÒéÒ»·Ý»º³åÇø¸±±¾¡£
	 */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		/**
		 * ÓÉÓÚÄÚ´æ²»×ã¶øÊ§°Ü¡£
		 */
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	/**
	 * pskb_may_pullµÄ¹¤×÷ÊÇÈ·±£skb->dataËùÇøÓò°üº¬µÄÊý¾ÝÇøÖÁÉÙºÍIP±¨Í·Ò»Ñù´ó£¬ÒòÎªÃ¿¸öIP°ü£¨°üÀ¨Æ¬¶Î£©±ØÐë°üº¬Ò»¸öÍêÕûµÄIP±¨Í·¡£
	 * È±Ê§µÄ²¿·Ö¾Í»á´Ó´æ´¢ÔÚskb_shinfo(skb)->fragsÀïµÄÊý¾ÝÆ¬¶Î¸´ÖÆ¹ýÀ´¡£
	 */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	/**
	 * º¯Êý±ØÐëÔÙ´Î³õÊ¼»¯iph£¬ÒòÎªpskb_may_pull¿ÉÒÔ¸Ä±ä»º³åÇø½á¹¹¡£
	 */
	iph = skb->nh.iph;

	/*
	 *	RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	/**
	 * ½Ó×Å¶ÔIP±¨Í·×öÒ»Ð©½¡¿µ¼ì²é¡£
	 * »ù±¾IP±¨Í·µÄ³ß´çÊÇ20×Ö½Ú£¬ÒòÎª´æ´¢ÔÚ±¨Í·ÄÚµÄ³ß´çÊÇÒÔ32Î»£¨4×Ö½Ú£©µÄ±¶Êý±íÊ¾£¬Èç¹ûÆäÖµÐ¡ÓÚ5£¬Ôò±íÊ¾ÓÐ´íÎó¡£
	 * ºó¼ì²éÐ­Òé°æ±¾ºÅÊÇÎªÁËÐ§ÂÊÔ­Òò¡£
	 */
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error; 

	/**
	 * ÖØ¸´ÏÈÇ°×ö¹ýµÄÏàÍ¬¼ì²é£¬Ö»²»¹ýÕâÒ»´ÎÊ¹ÓÃµÄÊÇÍêÕûµÄIP±¨Í·³ß´ç£¨°üÀ¨Ñ¡Ïî£©¡£
	 * Èç¹ûIP±¨Í·ÉùÃ÷ÁËiph->ihlµÄ³ß´ç£¬Ôò°üÓ¦¸ÃÖÁÉÙºÍiph->ihlÒ»Ñù³¤¡£
	 * ÕâÏî¼ì²éÒ»Ö±µ½ÏÖÔÚ²Å×ö£¬ÊÇÒòÎª´Ëº¯Êý±ØÐëÏÈÈ·¶¨»ù±¾±¨Í·£¨¼´²»º¬Ñ¡ÏîµÄ±¨Í·£©Ã»ÓÐ±»½Ø¶Ï¡£
	 * ¶øÇÒ´ÓÖÐ¶ÁÈ¡µÄ¶«Î÷ÒÑ¾­¾­¹ý»ù±¾½¡¿µ¼ì²é¡£
	 */
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = skb->nh.iph;

	/**
	 * ´Ëº¯Êý±ØÐë¼ÆËãÐ£ÑéºÍ£¬È»ºó¿´¿´ÊÇ·ñºÍ±¨Í·ÖÐËùÐ¯´øµÄÎÇºÏ¡£Èç¹û²»ÎÇºÏ£¬¸Ã°ü¾Í»á±»¶ªÆú¡£
	 */
	if (ip_fast_csum((u8 *)iph, iph->ihl) != 0)
		goto inhdr_error; 

	{
		__u32 len = ntohs(iph->tot_len); 
		/**
		 * »º³åÇø£¨¼´ÒÑ½ÓÊÕµÄ°ü£©³¤¶È´óÓÚ»òÕßµÈÓÚIP±¨Í·ÖÐ¼ÇÂ¼µÄ³¤¶È¡£
		 *		ÕâÊÇÓÉÓÚL2Ð­Òé£¨Èçethernet£©»áÌî³äÓÐÐ§¸ºÔØ£¬ËùÒÔ£¬ÔÚIPÓÐÐ§¸ºÔØÖ®ºó¿ÉÄÜÓÐ¶àÓàµÄ×Ö½Ú.
		 * °üµÄ³ß´çÖÁÉÙºÍIP±¨Í·µÄ³ß´çÒ»Ñù´ó¡£
		 *		ÕâÊÇÓÉÓÚIP±¨Í·²»ÄÜ·Ö¶ÎµÄÊÂÊµ¡£Òò´Ë£¬Ã¿¸öIPÆ¬¶Î±ØÐëÖÁÉÙ°üº¬Ò»¸öIP±¨Í·¡£
		 */
		if (skb->len < len || len < (iph->ihl<<2))
			goto inhdr_error;

		/* Our transport medium may have padded the buffer out. Now we know it
		 * is IP we can trim to the true length of the frame.
		 * Note this now means skb->len holds ntohs(iph->tot_len).
		 */
		/**
		 * L2²ãÌî³äÁËÒ»Ð©Êý¾Ý±¨ÄÚÈÝ¡£
		 */
		if (skb->len > len) {
			/**
			 * ½Ø¶ÏL2²ãÌî³äµÄÊý¾Ý±¨ÄÚÈÝ¡£
			 */
			__pskb_trim(skb, len);
			/**
			 * ÓÉÓÚ±¨ÎÄÄÚÈÝ·¢ÉúÁË¸Ä±ä£¬¶øÓ²¼þ¼ÆËãµÄÐ£ÑéºÍ¿ÉÄÜÊÇ¼ÆËãÁËÌî³äµÄ±¨ÎÄ£¬´ËÊ±Ó¦µ±Ê§Ð§¡£
			 */
			if (skb->ip_summed == CHECKSUM_HW)
				skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/**
	 * Èç¹ûÍ¨¹ýÁË·À»ðÇ½µÄ¼ì²â£¬ÄÇÃ´¾Íµ÷ÓÃip_rcv_finish½øÐÐÕæÕýµÄÂ·ÓÉ¾ö²ß¡£
	 */
	return NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, dev, NULL,
		       ip_rcv_finish);

inhdr_error:
	IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
drop:
        kfree_skb(skb);
out:
        return NET_RX_DROP;
}

EXPORT_SYMBOL(ip_rcv);
EXPORT_SYMBOL(ip_statistics);
