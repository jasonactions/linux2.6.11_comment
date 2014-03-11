/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The options processing module for ip.c
 *
 * Version:	$Id: ip_options.c,v 1.21 2001/09/01 00:31:50 davem Exp $
 *
 * Authors:	A.N.Kuznetsov
 *		
 */

#include <linux/module.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>

/* 
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 */
/**
 * ¶ÔIP±¨Í·ÖĞ×¨ÊôµÄÄÇĞ©Ñ¡Ïî²¿·Ö×ö³õÊ¼»¯£¨¸ù¾İÊäÈëµÄip_options½á¹¹£©¡£´«Êä±¾µØ²úÉúµÄ°üÊ±£¬¾Í»áÓÃµ½´Ëº¯Êı¡£
 */
void ip_options_build(struct sk_buff * skb, struct ip_options * opt,
			    u32 daddr, struct rtable *rt, int is_frag) 
{
	unsigned char * iph = skb->nh.raw;

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);
	opt->is_data = 0;

	if (opt->srr)
		memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

	if (!is_frag) {
		if (opt->rr_needaddr)
			ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, rt);
		if (opt->ts_needaddr)
			ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, rt);
		if (opt->ts_needtime) {
			struct timeval tv;
			__u32 midtime;
			do_gettimeofday(&tv);
			midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
			memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
		}
		return;
	}
	if (opt->rr) {
		memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
		opt->rr = 0;
		opt->rr_needaddr = 0;
	}
	if (opt->ts) {
		memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
		opt->ts = 0;
		opt->ts_needaddr = opt->ts_needtime = 0;
	}
}

/* 
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */
/**
 * Ö¸¶¨Èë°ü¼°IPÑ¡Ïîºó£¬´Ëº¯Êı¾Í¿É½¨Á¢ÓÃÓÚ»Ø¸´´«ËÍÕßµÄIPÑ¡Ïî¡£
 *		 »Ø¸´ICMPÈë°üÇëÇóµÄicmp_replay¡£
 *	 	 µ±IPÈë°ü·ûºÏ²úÉúICMPÏûÏ¢ĞèÇóÊ±µÄicmp_send¡£
 *		 IP²ãËùÌá¹©µÄÍ¨ÓÃº¯Êıip_send_reply£¨ÒÔ»Ø¸´IPÈë°ü£©¡£
 *		 ´æ´¢ÈëSYN¶ÎµÄÑ¡ÏîµÄTCP¡£
 */
int ip_options_echo(struct ip_options * dopt, struct sk_buff * skb) 
{
	struct ip_options *sopt;
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;
	u32	daddr;

	memset(dopt, 0, sizeof(struct ip_options));

	dopt->is_data = 1;

	sopt = &(IPCB(skb)->opt);

	if (sopt->optlen == 0) {
		dopt->optlen = 0;
		return 0;
	}

	sptr = skb->nh.raw;
	dptr = dopt->__data;

	if (skb->dst)
		daddr = ((struct rtable*)skb->dst)->rt_spec_dst;
	else
		daddr = skb->nh.iph->daddr;

	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->rr, optlen);
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL;
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->ts, optlen);
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				dopt->ts_needaddr = 1;
				soffset += 4;
			}
			if (sopt->ts_needtime) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 8 <= optlen) {
						__u32 addr;

						memcpy(&addr, sptr+soffset-1, 4);
						if (inet_addr_type(addr) != RTN_LOCAL) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			dptr[2] = soffset;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->srr) {
		unsigned char * start = sptr+sopt->srr;
		u32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset-=4, doffset=4; soffset > 3; soffset-=4, doffset+=4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&skb->nh.iph->saddr, &start[soffset+3], 4) == 0)
				doffset -= 4;
		}
		if (doffset > 3) {
			memcpy(&start[doffset-1], &daddr, 4);
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */
/**
 * ÒòÎªµÚÒ»¸öÆ¬¶ÎÊÇÎ¨Ò»¼Ì³ĞÔ­ÓĞ°üµÄËùÓĞÑ¡ÏîµÄÆ¬¶Î£¬ËùÒÔ£¬Æä±¨Í·µÄ³ß´çÓ¦´óÓÚ»òµÈÓÚºóĞøÆ¬¶ÎµÄ³ß´ç¡£
 * LINUXÈÃËùÓĞÆ¬¶Î¶¼±£³ÖÏàÍ¬µÄ±¨Í·³ß´ç£¬ÈÃ·Ö¶ÎÁ÷³Ì¸üÎª¼òµ¥ÓĞĞ§¡£
 * Æä×ö·¨ÊÇ¿½±´Ô­ÓĞ±¨Í·¼°ÆäËùÓĞÑ¡Ïî£¬È»ºó£¬³ıÁËµÚÒ»¸öÆ¬¶ÎÒÔÍâ£¬¶ÔÆäËûËùÓĞÆ¬¶Î¶¼ÒÔ¿ÕÑ¡Ïî¸²¸ÇÄÇĞ©²»ĞèÒªÖØ¸´µÄÑ¡Ïî£¨Ò²¾ÍÊÇIPOPT_COPYÃ»Éè¶¨µÄÑ¡Ïî£©£¬È»ºóÇåµôºÍÆäÏà¹ØµÄip_options±êÖ¾£¨Èçts_needaddr£©¡£
 * ±¾º¯ÊıĞŞ¸ÄµÚÒ»¸öÆ¬¶ÎµÄIP±¨Í·£¬Ê¹Æä¿ÉÒÔ±»ºóĞøÆ¬¶ÎÑ­»·ÀûÓÃ¡£
 */
void ip_options_fragment(struct sk_buff * skb) 
{
	unsigned char * optptr = skb->nh.raw;
	struct ip_options * opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen<2 || optlen>l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
	return;
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 */
/**
 * ·ÖÎöIP±¨Í·ÖĞµÄÒ»Ğ©Ñ¡Ïî£¬È»ºóÏàÓ¦µÄ¶ÔÒ»¸öip_options½á¹¹µÄÊµÀı×ö³õÊ¼»¯¡£
 * Á½¸öÊäÈë²ÎÊıµÄÖµ»áÈÃº¯ÊıÖªµÀ×ÔÉíÊÇÔÚÊ²Ã´Çé¿öÏÂ±»µ÷ÓÃµÄ£º
 *		Èë°ü£ºskb²»ÎªNULL£¬optÎªNULL¡£
 * 		°üÕı±»´«Êä£ºskbÎªNULL£¬opt·Ç¿Õ¡£
 */
int ip_options_compile(struct ip_options * opt, struct sk_buff * skb)
{
	int l;
	unsigned char * iph;
	unsigned char * optptr;
	int optlen;
	unsigned char * pp_ptr = NULL;
	struct rtable *rt = skb ? (struct rtable*)skb->dst : NULL;

	/**
	 * optÎª¿Õ£¬ËµÃ÷ÊÇÈë°ü¡£
	 */
	if (!opt) {
		opt = &(IPCB(skb)->opt);
		memset(opt, 0, sizeof(struct ip_options));
		/**
		 * ´ÓÈë°üÖĞÈ¡IPÍ·¡£
		 */
		iph = skb->nh.raw;
		opt->optlen = ((struct iphdr *)iph)->ihl*4 - sizeof(struct iphdr);
		/**
		 * Ñ¡ÏîÆğÊ¼µØÖ·¡£¡£
		 */
		optptr = iph + sizeof(struct iphdr);
		opt->is_data = 0;
	} else {
		/**
		 * ´ÓoptÖĞÈ¡³öÑ¡ÏîÆğÊ¼µØÖ·ºÍ°üÍ·¡£
		 */
		optptr = opt->is_data ? opt->__data : (unsigned char*)&(skb->nh.iph[1]);
		iph = optptr - sizeof(struct iphdr);
	}

	/**
	 * ±éÀú´¦ÀíÑ¡Ïî¡£
	 *		L±íÊ¾ÈÔÈ»Ã»ÓĞ±»½âÎöµÄ¿éµÄ³¤¶È¡£
	 *		OptptrÖ¸ÕëÖ¸ÏòÒÑ¾­±»½âÎöÁËµÄÑ¡Ïî¿éµÄµ±Ç°µØÖ·¡£Optptr[1]ÊÇÑ¡ÏîµÄ³¤¶È£¬optptr[2]ÊÇÑ¡ÏîÖ¸Õë£¨Ñ¡Ïî¿ªÊ¼µÄµØ·½£©¡£
	 * 		Optlen±»³õÊ¼»¯Îªµ±Ç°Ñ¡ÏîµÄ³¤¶È¡£
	 * 		Is_changed±êÖ¾ÓÃÀ´±£´æµ±±¨Í·ÊÇ·ñÒÑ¾­±»ĞŞ¸Ä£¨ÕâĞèÒªÖØĞÂ¼ÆËãĞ£ÑéºÍ£©¡£
	 */
	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		      case IPOPT_END:
			/**
			 * ÔÚIPOPT_ENDÑ¡Ïîºó£¬²»ÄÜÔÙÓĞÆäËûÑ¡Ïî¡£Òò´Ë£¬Ò»µ©ÕÒµ½Ò»¸öÕâÑùµÄÑ¡Ïî£¬²»¹ÜÆäºóÊÇÊ²Ã´Ñ¡Ïî£¬¶¼±»¸²¸ÇÎªIPOPT_END¡£
			 */
			for (optptr++, l--; l>0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
			/**
			 * IPOPT_NOOPÓÃÓÚÕ¼Î»£¬Ö±½ÓÂÔ¹ı¡£
			 */
		      case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		/**
		 * ÒÔÏÂ´¦Àí¶à×Ö½ÚÑ¡Ïî¡£
		 */
		optlen = optptr[1];
		/**
		 * ÓÉÓÚÃ¿Ò»¸öÑ¡ÏîµÄ³¤¶È°üº¬ÁË×îÇ°ÃæµÄÁ½¸ö×Ö½Ú£¨typeºÍlength£©£¬²¢ÇÒËü´Ó1¿ªÊ¼¼ÆÊı£¨²»ÊÇ0£©£¬Èç¹ûlengthĞ¡ÓÚ2»òÕß´óÓÚÒÑ¾­±»·ÖÎöµÄÑ¡Ïî¿é¾Í±íÊ¾Ò»¸ö´íÎó
		 */
		if (optlen<2 || optlen>l) {
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr) {
			/**
			 * ÑÏ¸ñºÍ¿íËÉµÄÔ´Â·ÓÉÑ¡Ïî¡£
			 */
		      case IPOPT_SSRR:
		      case IPOPT_LSRR:
			/**
			 * Èç¹ûÑ¡Ïî³¤¶È£¨°üº¬typeºÍlength£©Ğ¡ÓÚ3£¬ÄÇÃ´¸ÃÑ¡Ïî½«±»ÊÓÎª´íÎóÑ¡Ïî¡£
			 * ÕâÊÇÒòÎª¸ÃÖµÒÑ¾­°üº¬ÁËtype¡¢lengthºÍpointer×Ö¶Î¡£
			 */
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * Í¬Ê±£¬pointer²»ÄÜ±È4Ğ¡£¬ÒòÎªµÚÒ»¸ö3×Ö½ÚµÄÑ¡ÏîÒÑ¾­±»type¡¢length¡¢pionter×Ö¶ÎÊ¹ÓÃ¡£
			 */
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/* NB: cf RFC-1812 5.2.4.1 */
			/**
			 * Ç°ÏÖµÄ½âÎöÖĞÒÑ¾­Ò»¸öÔ´Â·ÓÉÑ¡ÏîÁË¡£
			 * ÓÉÓÚÑÏ¸ñºÍ¿íËÉÔ´Â·ÓÉ²»ÄÜÍ¬Ê±²¢´æ£¬Òò´ËÌøµ½´íÎó´¦Àí¡£
			 */
			if (opt->srr) {
				pp_ptr = optptr;
				goto error;
			}
			/**
			 * µ±ÊäÈëµÄskb²ÎÊıÊÇNULLÊ±£¬±íÊ¾ip_options_compile±»µ÷ÓÃÒÔ½âÎöÒ»¸ö³ö°üµÄÑ¡Ïî£¨ÓÉ±¾µØÉú³É¶ø²»ÊÇ×ª·¢£©¡£
			 */
			if (!skb) {
				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				/**
				 * ÔÚÕâÖÖÇé¿öÏÂ£¬ÓÉÓÃ»§¿Õ¼äÌá¹©µÄµØÖ·Êı×éÖĞµÄµÚÒ»¸öIPµØÖ·±»±£´æÔÚopt->faddr£¬È»ºóÒÔmemmoveÔËËã°ÑÊı×éµÄÆäËûÔªËØÍù»ØÒÆ¶¯Ò»¸öÎ»ÖÃ£¬½«¸ÃµØÖ·´ÓÊı×éÖĞÉ¾³ı¡£
				 * Õâ¸öµØÖ·Ëæºó½«±»ip_queue_xmitº¯ÊıÈ¡³ö£¬ÕâÑù£¬ÄÇĞ©º¯Êı²ÅÖªµÀÄ¿µÄIPµØÖ·¡£Ê¹ÓÃopt->faddrµÄ¼òµ¥µÄÀı×Ó¿ÉÒÔÔÚudp_sendmsgÖĞÕÒµ½¡£
				 */
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7], optlen-7);
			}
			/**
			 * opt->is_strictroute±»ÓÃÀ´¸æËßµ÷ÓÃÕß£ºÔ´Â·ÓÉÑ¡ÏîÊÇ·ñÊÇÒ»¸öÑÏ¸ñ¡¢¿íËÉÂ·ÓÉ¡£
			 */
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph;
			break;
			/**
			 * ¼ÇÂ¼Â·ÓÉÑ¡Ïî¡£
			 */
		      case IPOPT_RR:
			/**
			 * ÖØ¸´Ñ¡Ïî£¬´íÎó¡£
			 */
			if (opt->rr) {
				pp_ptr = optptr;
				goto error;
			}
			/**
			 * ³¤¶È·Ç·¨¡£
			 */
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * pointer·Ç·¨¡£
			 */
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/*å*
			 * µ±Ç°Ö¸ÕëĞ¡ÓÚIPÑ¡Ïî×Ü³¤£¬IP±¨Í·ÖĞ»¹ÓĞ¿Õ¼ä¼ÇÂ¼Â·ÓÉ¡£ 
			 */
			if (optptr[2] <= optlen) {
				/**
				 * ¿Õ¼ä²»×ãÒÔ´æ´¢Ò»¸öµØÖ·ÁË¡£´íÎó¡£
				 */
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				/**
				 * ´¦ÀíÈë°ü¡£
				 */
				if (skb) {
					/**
					 * °ÑÊ×Ñ¡Ô´IPµØÖ·¿½±´µ½±¨Í·ÖĞµÄµØÖ·ÁĞ±í£¬È»ºó¸üĞÂ±êÖ¾is_changedÀ´Ç¿ÆÈ¸üĞÂIPĞ£ÑéºÍ¡£
					 */
					memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
					opt->is_changed = 1;
				}
				/**
				 * ÎŞÂÛÈçºÎ£¬¸ÃÑ¡ÏîµÄpointer×Ö¶Î¶¼»áÍùÇ°ÒÆ4¸ö½Ú£¨IPµØÖ·µÄ³ß´ç£©¡£
				 * Õâ¾ÍËµÃ÷ÁËÎªÊ²Ã´ip_forward_optionsÒªÍù»Ø×ß4¸ö×Ö½Ú£¬ÒÔ°ÑIPĞ´ÈëÕıÈ·µÄµØÖ·¡£ÒòÎªip_forward_options»á¸ù¾İrr_needaddrĞ´ÈëIPµØÖ·¡£
				 */
				optptr[2] += 4;
				/**
				 * Éè¶¨rr_needaddr±êÖ¾£¬ÒÔÍ¨ÖªÂ·ÓÉ×ÓÏµÍ³£¬µ±×ö³öÂ·ÓÉ¾ö²ßºó£¬°ÑÍâ³ö½Ó¿ÚµÄIPµØÖ·Ğ´ÈëIP±¨Í·¡£
				 */
				opt->rr_needaddr = 1;
			}
			opt->rr = optptr - iph;
			break;
			/**
			 * TimestampÑ¡Ïî
			 */
		      case IPOPT_TIMESTAMP:
			/**
			 * ÖØ¸´Ñ¡Ïî¡£
			 */
			if (opt->ts) {
				pp_ptr = optptr;
				goto error;
			}
			/**
			 * ³¤¶È·Ç·¨¡£
			 */
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * pointer·Ç·¨¡£
			 */
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/**
			 * »¹ÔÚ¿Õ¼äÓÃÓÚ±£´æÊ±¼ä´Á¡£
			 */
			if (optptr[2] <= optlen) {
				__u32 * timeptr = NULL;
				/**
				 * Ê£Óà¿Õ¼ä²»×ãÒÔ±£´æÊ±¼ä´Á¡£
				 */
				if (optptr[2]+3 > optptr[1]) {
					pp_ptr = optptr + 2;
					goto error;
				}
				/**
				 * ´¦Àísubtype×Ö¶Î
				 */
				switch (optptr[3]&0xF) {
				      case IPOPT_TS_TSONLY:
					opt->ts = optptr - iph;
					/**
					 * ½öµ±skb²»ÎªNULLÊ±£¨µ±¸ÃÑ¡ÏîÊôÓÚÄ³¸öÈë°üÊ±£©£¬timeptr²Å»á³õÊ¼»¯¡£
					 */
					if (skb) 
						/**
						 * TS_ONLYºÍTS_TSANDADDR±ØĞë¼ÇÂ¼Ê±¼ä´Á.
						 * TimeptrµÄ³õÊ¼ÖµÉèÖÃ³ÉÓ¦¸ÃĞ´Èëµ½IP±¨Í·ÖĞµÄÕıÈ·µØµã¡£
						 */
						timeptr = (__u32*)&optptr[optptr[2]-1];
					/**
					 * ts_needtimeÎª1£¬¶Ô³ö°üÀ´Ëµ£¬ip_options_build»á¸ù¾İÕâ¸ö±êÖ¾ÉèÖÃÊ±¼ä´Á
					 */
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				      case IPOPT_TS_TSANDADDR:
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					/**
					 * ½öµ±skb²»ÎªNULLÊ±£¨µ±¸ÃÑ¡ÏîÊôÓÚÄ³¸öÈë°üÊ±£©£¬timeptr²Å»á³õÊ¼»¯¡£
					 */
					if (skb) {
						/**
						 * Ğ´ÈëµØÖ·¡£
						 */
						memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
						/**
						 * TS_ONLYºÍTS_TSANDADDR±ØĞë¼ÇÂ¼Ê±¼ä´Á.
						 * TimeptrµÄ³õÊ¼ÖµÉèÖÃ³ÉÓ¦¸ÃĞ´Èëµ½IP±¨Í·ÖĞµÄÕıÈ·µØµã¡£
						 */						
						timeptr = (__u32*)&optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1;
					/**
					 * ts_needtimeÎª1£¬¶Ô³ö°üÀ´Ëµ£¬ip_options_build»á¸ù¾İÕâ¸ö±êÖ¾ÉèÖÃÊ±¼ä´Á
					 */
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
					  /**
					   * µ±×Ó´úÂëÎªIPOPT_TS_PRESPECÊ±£¬Ö»ÓĞµ±ÏÂÒ»¸öÒª±È¶ÔµÄIPµØÖ·ÊÇÏµÍ³±¾µØµØÖ·Ê±£¬Ê±¼ä´Á²Å»á¼Ó½øÈ¥
					   */
				      case IPOPT_TS_PRESPEC:
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					{
						u32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);
						/** 
						 * ¸ù¾İÂ·ÓÉ±í£¬¸ÃIPµØÖ·¿ÉÒÔµÖ´ï£¬¶øÇÒÊÇµ¥²¥µØÖ·¡£
						 * Òò´Ë£¬±¾»ú²»ÓÃ¼ÆËãÊ±¼ä´Á¡£
						 */
						if (inet_addr_type(addr) == RTN_UNICAST)
							break;
						/**
						 * ¶ÔÈë°üÀ´Ëµ£¬²ÅĞèÒªÔÚ±¾º¯Êı¼ÇÂ¼Ê±¼ä´Á¡£
						 */
						if (skb)
							timeptr = (__u32*)&optptr[optptr[2]+3];
					}
					/**
					 * ts_needtimeÎª1£¬¶Ô³ö°üÀ´Ëµ£¬ip_options_build»á¸ù¾İÕâ¸ö±êÖ¾ÉèÖÃÊ±¼ä´Á
					 */					
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				      default:
					if (!skb && !capable(CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				/**
				 * È¡¾öÓÚÕıÔÚ´¦ÀíµÄ×ÓÑ¡Ïî£¬Ê±¼ä´Á±ØĞëĞ´ÈëIP±¨Í·ÖĞµÄ²»Í¬Æ«ÒÆÁ¿´¦¡£Ç°ÃæÊÇ¸ù¾İÇé¿ö¶Ôtimeptr³õÊ¼»¯¡£
				 * ÏÖÔÚÊÇ°ÑÊ±¼ä´Á¿½±´µ½ÕıÈ·Î»ÖÃ¡£¸ù¾İ×ÓÑ¡Ïî¶ø¶¨£¬ts_needtimeºÍtr_needaddrÒ²»á±»³õÊ¼»¯¡£
				 */
				if (timeptr) {
					struct timeval tv;
					__u32  midtime;
					do_gettimeofday(&tv);
					midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
					memcpy(timeptr, &midtime, sizeof(__u32));
					/**
					 * ¶ÔÈë°üÀ´Ëµ£¬timeptr²»ÎªNULL£¬ÕâÀïÉèÖÃĞŞ¸Ä±êÖ¾£¬ÕâÑù£¬¾Í»áÖØĞÂ¼ÆËãĞ£ÑéºÍÁË¡£
					 * ÒòÎªÕâÖÖÇé¿öÏÂ£¬±¨Í·ÒÑ¾­·¢ÉúÁË±ä»¯¡£
					 */
					opt->is_changed = 1;
				}
			} else {/* ÕâÒ»²¿·ÖÊÇ´¦ÀíÊ±¼ä´Á¿Õ¼ä²»×ãµÄÒç³ö */
				unsigned overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				opt->ts = optptr - iph;
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			break;
		      case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * Router AlertÑ¡ÏîµÄ×îºóÁ½¸ö×Ö½Ú±ØĞëÎª0.
			 */
			if (optptr[2] == 0 && optptr[3] == 0)
				/**
				 * ÉèÖÃrouter_alert¹©ip_forward´¦Àí¡£
				 */
				opt->router_alert = optptr - iph;
			break;
		      case IPOPT_SEC:
		      case IPOPT_SID:
		      default:
			if (!skb && !capable(CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

/**
 * ÔËĞĞµ½´Ë£¬ËµÃ÷±¨Í·ÖĞÓĞ´íÎó·¢Éú¡£
 */
error:
	/**
	 * Èç¹ûÊÇÈë°ü£¬ÔòÏò¶Ô·½·¢ËÍICMPÏûÏ¢¡£
	 */
	if (skb) {
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((pp_ptr-iph)<<24));
	}
	return -EINVAL;
}


/*
 *	Undo all the changes done by ip_options_compile().
 */

void ip_options_undo(struct ip_options * opt)
{
	if (opt->srr) {
		unsigned  char * optptr = opt->__data+opt->srr-sizeof(struct  iphdr);
		memmove(optptr+7, optptr+3, optptr[1]-7);
		memcpy(optptr+3, &opt->faddr, 4);
	}
	if (opt->rr_needaddr) {
		unsigned  char * optptr = opt->__data+opt->rr-sizeof(struct  iphdr);
		optptr[2] -= 4;
		memset(&optptr[optptr[2]-1], 0, 4);
	}
	if (opt->ts) {
		unsigned  char * optptr = opt->__data+opt->ts-sizeof(struct  iphdr);
		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
			if ((optptr[3]&0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
		}
	}
}

/**
 * ´Ëº¯Êı»á½ÓÊÕÒ»ÈºÑ¡Ïî£¬ÓÃip_options_compile½âÎö£¬È»ºó°Ñ½á¹û´æ´¢ÔÚÆä·ÖÅäµÄÒ»¸öip_optioins½á¹¹¡£´Ëº¯ÊıÒ²¿É´ÓÄÚºË¿Õ¼ä»òÓÃ»§¿Õ¼ä½ÓÊÕÊäÈëÑ¡Ïî
 */
int ip_options_get(struct ip_options **optp, unsigned char *data, int optlen, int user)
{
	struct ip_options *opt;

	opt = kmalloc(sizeof(struct ip_options)+((optlen+3)&~3), GFP_KERNEL);
	if (!opt)
		return -ENOMEM;
	memset(opt, 0, sizeof(struct ip_options));
	if (optlen) {
		if (user) {
			if (copy_from_user(opt->__data, data, optlen)) {
				kfree(opt);
				return -EFAULT;
			}
		} else
			memcpy(opt->__data, data, optlen);
	}
	while (optlen & 3)
		opt->__data[optlen++] = IPOPT_END;
	opt->optlen = optlen;
	opt->is_data = 1;
	opt->is_setbyuser = 1;
	if (optlen && ip_options_compile(opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	if (*optp)
		kfree(*optp);
	*optp = opt;
	return 0;
}

/**
 * ×ª·¢Ò»¸ö°üÊ±£¬ÓĞĞ©Ñ¡Ïî¿ÉÄÜ±ØĞë±»´¦Àí¡£
 * Ip_options_compile»á½âÎöÒ»Ğ©Ñ¡Ïî£¬È»ºó¶ÔÓÃÓÚ´æ´¢½âÎö½á¹ûµÄip_options½á¹¹µÄÒ»×é±êÖ¾×ö³õÊ¼»¯¡£
 */
void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options * opt	= &(IPCB(skb)->opt);
	unsigned char * optptr;
	struct rtable *rt = (struct rtable*)skb->dst;
	unsigned char *raw = skb->nh.raw;

	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		ip_rt_get_source(&optptr[optptr[2]-5], rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for ( srrptr=optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&rt->rt_dst, &optptr[srrptr-1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_rt_get_source(&optptr[srrptr-1], rt);
			skb->nh.iph->daddr = rt->rt_dst;
			optptr[2] = srrptr+4;
		} else if (net_ratelimit())
			printk(KERN_CRIT "ip_forward(): Argh! Destination lost!\n");
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], rt);
			opt->is_changed = 1;
		}
	}
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(skb->nh.iph);
	}
}

/**
 * ´¦Àí»ùÓÚÔ´Õ¾Ñ°Â·¡£
 * ´ÓIPÍ·²¿ÌáÈ¡³öÒªÊ¹ÓÃµÄÏÂÒ»Ìø£¬²¢µ÷ÓÃip_route_inputÀ´½øĞĞµÚ¶ş´ÎÂ·ÓÉ²éÕÒ¡£
 * µÚ¶ş´ÎÂ·ÓÉ²éÕÒÊ¹ÓÃ¸üĞÂµÄ²éÕÒ½á¹û¸²¸ÇÔ­À´µÄskb->dst¡£
 */
int ip_options_rcv_srr(struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	u32 nexthop;
	struct iphdr *iph = skb->nh.iph;
	unsigned char * optptr = skb->nh.raw + opt->srr;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct rtable *rt2;
	int err;

	if (!opt->srr)
		return 0;

	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

	for (srrptr=optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		rt = (struct rtable*)skb->dst;
		skb->dst = NULL;
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, skb->dev);
		rt2 = (struct rtable*)skb->dst;
		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			ip_rt_put(rt2);
			skb->dst = &rt->u.dst;
			return -EINVAL;
		}
		ip_rt_put(rt);
		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		memcpy(&iph->daddr, &optptr[srrptr-1], 4);
		opt->is_changed = 1;
	}
	if (srrptr <= srrspace) {
		opt->srr_is_hit = 1;
		opt->is_changed = 1;
	}
	return 0;
}

EXPORT_SYMBOL(ip_options_compile);
EXPORT_SYMBOL(ip_options_undo);
