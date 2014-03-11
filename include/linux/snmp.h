/*
 * Definitions for MIBs
 *
 * Author: Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
 */

#ifndef _LINUX_SNMP_H
#define _LINUX_SNMP_H

/* ipstats mib definitions */
/*
 * RFC 1213:  MIB-II
 * RFC 2011 (updates 1213):  SNMPv2-MIB-IP
 * RFC 2863:  Interfaces Group MIB
 * RFC 2465:  IPv6 MIB: General Group
 * draft-ietf-ipv6-rfc2011-update-10.txt: MIB for IP: IP Statistics Tables
 */
enum
{
	IPSTATS_MIB_NUM = 0,
	/**
	 * 已接收包数目。此字段不区分完整IP包和片段，也包含会被接收及因任何原因会被丢弃的包数目（但是，处于混杂模式下的接口传给ip_rcv的数据帧如果不是要传给进行接收的接口因而被丢弃时，不计算在内）。
	 * 在ip_rcv的开头处，其值会被更新。
	 */
	IPSTATS_MIB_INRECEIVES,			/* InReceives */
	/**
	 * 因为IP报头损坏而被丢弃的包数目（片段以及非分段包）。
	 * 此字段可在ip_rcv和ip_rcv_finish里因为各种理由而被更新。
	 */
	IPSTATS_MIB_INHDRERRORS,		/* InHdrErrors */
	/**
	 * 在Ipv4没有使用此字段。
	 * Ipv6以此计算那些因为必须被分段（和Ipv4不同，Ipv6的路由器不可做分段运算）而无法转发的入包数目。
	 */
	IPSTATS_MIB_INTOOBIGERRORS,		/* InTooBigErrors */
	/**
	 * 当前没有使用。此字段应该计算那些因为本地主机没有有效路径而无法转发的入包。
	 */
	IPSTATS_MIB_INNOROUTES,			/* InNoRoutes */
	/**
	 * Ipv4当前没有使用。Ipv6以此计算那些已接收到但具有错误地址类型的包数目。
	 */
	IPSTATS_MIB_INADDRERRORS,		/* InAddrErrors */
	/**
	 * 已接收到但L4协议为未知协议（也就是该协议没有注册的处理函数）的包数目。
	 * 此字段会在ip_local_deliver_finish里更新。
	 */
	IPSTATS_MIB_INUNKNOWNPROTOS,		/* InUnknownProtos */
	/**
	 * 包被截断了（也就是不包含完整的IP报头）。Ipv6使用了，但是Ipv4没有使用。
	 */
	IPSTATS_MIB_INTRUNCATEDPKTS,		/* InTruncatedPkts */
	/**
	 * 被丢弃的包数目。关于这方面的计数器不包含因为报头错误而被丢弃的包，主要是包含内存分配问题而丢弃的包。
	 * 此字段是在ip_rcv和ip_rcv_finish里面被更新。
	 */
	IPSTATS_MIB_INDISCARDS,			/* InDiscards */
	/**
	 * 成功到L4协议处理函数的包数目。此字段是在ip_local_deliver_finish里面被更新。
	 */
	IPSTATS_MIB_INDELIVERS,			/* InDelivers */
	/**
	 * 必须被转发的入包数目。
	 * 实际上，在包传输前，以及理论上包可能会因某种因素而被丢弃时，关于统计入包的计数器就会被递增。
	 * 其值会在ip_forward_finish里被更新（对多播而言是在ipmr_forward_finish里）。
	 */
	IPSTATS_MIB_OUTFORWDATAGRAMS,		/* OutForwDatagrams */
	/**
	 * 系统试着传输的包数目（成功或失败），但不包括转发包。
	 * 此字段是在ip_output里被更新（对多播而言是在ip_mc_output里）。
	 */
	IPSTATS_MIB_OUTREQUESTS,		/* OutRequests */
	/**
	 * 传输失败的包数目。此字段会在包括ip_append_data、ip_push_pending_frames、raw_send_hdrinc等函数被更新。
	 */
	IPSTATS_MIB_OUTDISCARDS,		/* OutDiscards */
	/**
	 * 因为无路径传输而被丢弃的本地产生的包数目。
	 * 正常来讲，此字段是在ip_route_output_flow失败后而被更新。
	 * 另外，ip_queue_xmit也是其中一个字段的函数。
	 */
	IPSTATS_MIB_OUTNOROUTES,		/* OutNoRoutes */
	/**
	 * 重组失败的包数目（因为有些片段没有实时收到）。此值是完整包的数目，而非片段数目。
	 * 此字段会在ip_expire里更新。而ip_expire是在IP片段因超时而被丢弃时所执行的定时器函数。
	 * 注意，关于统计重组失败的包数目的计数器的用法和本节开头所提的两份RFC文件里的定义并不相同。
	 */
	IPSTATS_MIB_REASMTIMEOUT,		/* ReasmTimeout */
	/**
	 * 已接收片段的数目（也就是试着重组的数目）。此字段会在ip_defrag里被更新。
	 */
	IPSTATS_MIB_REASMREQDS,			/* ReasmReqds */
	/**
	 * 成功重组的包数目。此字段是在ip_frag_reasm里被更新。
	 */
	IPSTATS_MIB_REASMOKS,			/* ReasmOKs */
	/**
	 * 重组失败的包数目。
	 * 此字段会在几个地方因不同原因而被更新（__ip_evictor、ip_expire、ip_frag_reasm以及ip_defrag）。
	 */
	IPSTATS_MIB_REASMFAILS,			/* ReasmFails */
	/**
	 * 已经传输的片段数目
	 */
	IPSTATS_MIB_FRAGOKS,			/* FragOKs */
	/**
	 * 分段尝试失败次数。此字段是在ip_fragment里被更新（对多播而言是ipmr_queue_xmit）。
	 */
	IPSTATS_MIB_FRAGFAILS,			/* FragFails */
	/**
	 * 已创建的片段数目。
	 */
	IPSTATS_MIB_FRAGCREATES,		/* FragCreates */
	/**
	 * 已接收的多播包数目。此字段由ipv6使用，ipv4没有用。
	 */
	IPSTATS_MIB_INMCASTPKTS,		/* InMcastPkts */
	/**
	 * 已经传输的多播包的数目。目前，ipv4没有使用此字段。
	 */
	IPSTATS_MIB_OUTMCASTPKTS,		/* OutMcastPkts */
	__IPSTATS_MIB_MAX
};

/* icmp mib definitions */
/*
 * RFC 1213:  MIB-II ICMP Group
 * RFC 2011 (updates 1213):  SNMPv2 MIB for IP: ICMP group
 */
enum
{
	ICMP_MIB_NUM = 0,
	/**
	 * 已接收ICMP消息的数目。包括ICMP_MIB_INERRORS所记录的信息。
	 */
	ICMP_MIB_INMSGS,			/* InMsgs */
	/**
	 * 因某种问题而丢弃的ICMP消息数目。Icmp_rcv及表25.9的处理函数碰到截断的ICMP报头时，就会丢弃入消息。
	 */
	ICMP_MIB_INERRORS,			/* InErrors */
	/**
	 * 以下几个值，保存各种ICMP消息的数目。
	 */
	ICMP_MIB_INDESTUNREACHS,		/* InDestUnreachs */
	ICMP_MIB_INTIMEEXCDS,			/* InTimeExcds */
	ICMP_MIB_INPARMPROBS,			/* InParmProbs */
	ICMP_MIB_INSRCQUENCHS,			/* InSrcQuenchs */
	ICMP_MIB_INREDIRECTS,			/* InRedirects */
	ICMP_MIB_INECHOS,			/* InEchos */
	ICMP_MIB_INECHOREPS,			/* InEchoReps */
	ICMP_MIB_INTIMESTAMPS,			/* InTimestamps */
	ICMP_MIB_INTIMESTAMPREPS,		/* InTimestampReps */
	ICMP_MIB_INADDRMASKS,			/* InAddrMasks */
	ICMP_MIB_INADDRMASKREPS,		/* InAddrMaskReps */
	/**
	 * 已传输ICMP消息的数目。
	 */
	ICMP_MIB_OUTMSGS,			/* OutMsgs */
	/**
	 * 出错的ICMP传输数目。没有使用。
	 */
	ICMP_MIB_OUTERRORS,			/* OutErrors */
	/**
	 * 已经传输的，每ICMP消息类型的计数器。
	 */
	ICMP_MIB_OUTDESTUNREACHS,		/* OutDestUnreachs */
	ICMP_MIB_OUTTIMEEXCDS,			/* OutTimeExcds */
	ICMP_MIB_OUTPARMPROBS,			/* OutParmProbs */
	ICMP_MIB_OUTSRCQUENCHS,			/* OutSrcQuenchs */
	ICMP_MIB_OUTREDIRECTS,			/* OutRedirects */
	ICMP_MIB_OUTECHOS,			/* OutEchos */
	ICMP_MIB_OUTECHOREPS,			/* OutEchoReps */
	ICMP_MIB_OUTTIMESTAMPS,			/* OutTimestamps */
	ICMP_MIB_OUTTIMESTAMPREPS,		/* OutTimestampReps */
	ICMP_MIB_OUTADDRMASKS,			/* OutAddrMasks */
	ICMP_MIB_OUTADDRMASKREPS,		/* OutAddrMaskReps */
	__ICMP_MIB_MAX
};

/* icmp6 mib definitions */
/*
 * RFC 2466:  ICMPv6-MIB
 */
enum
{
	ICMP6_MIB_NUM = 0,
	ICMP6_MIB_INMSGS,			/* InMsgs */
	ICMP6_MIB_INERRORS,			/* InErrors */
	ICMP6_MIB_INDESTUNREACHS,		/* InDestUnreachs */
	ICMP6_MIB_INPKTTOOBIGS,			/* InPktTooBigs */
	ICMP6_MIB_INTIMEEXCDS,			/* InTimeExcds */
	ICMP6_MIB_INPARMPROBLEMS,		/* InParmProblems */
	ICMP6_MIB_INECHOS,			/* InEchos */
	ICMP6_MIB_INECHOREPLIES,		/* InEchoReplies */
	ICMP6_MIB_INGROUPMEMBQUERIES,		/* InGroupMembQueries */
	ICMP6_MIB_INGROUPMEMBRESPONSES,		/* InGroupMembResponses */
	ICMP6_MIB_INGROUPMEMBREDUCTIONS,	/* InGroupMembReductions */
	ICMP6_MIB_INROUTERSOLICITS,		/* InRouterSolicits */
	ICMP6_MIB_INROUTERADVERTISEMENTS,	/* InRouterAdvertisements */
	ICMP6_MIB_INNEIGHBORSOLICITS,		/* InNeighborSolicits */
	ICMP6_MIB_INNEIGHBORADVERTISEMENTS,	/* InNeighborAdvertisements */
	ICMP6_MIB_INREDIRECTS,			/* InRedirects */
	ICMP6_MIB_OUTMSGS,			/* OutMsgs */
	ICMP6_MIB_OUTDESTUNREACHS,		/* OutDestUnreachs */
	ICMP6_MIB_OUTPKTTOOBIGS,		/* OutPktTooBigs */
	ICMP6_MIB_OUTTIMEEXCDS,			/* OutTimeExcds */
	ICMP6_MIB_OUTPARMPROBLEMS,		/* OutParmProblems */
	ICMP6_MIB_OUTECHOREPLIES,		/* OutEchoReplies */
	ICMP6_MIB_OUTROUTERSOLICITS,		/* OutRouterSolicits */
	ICMP6_MIB_OUTNEIGHBORSOLICITS,		/* OutNeighborSolicits */
	ICMP6_MIB_OUTNEIGHBORADVERTISEMENTS,	/* OutNeighborAdvertisements */
	ICMP6_MIB_OUTREDIRECTS,			/* OutRedirects */
	ICMP6_MIB_OUTGROUPMEMBRESPONSES,	/* OutGroupMembResponses */
	ICMP6_MIB_OUTGROUPMEMBREDUCTIONS,	/* OutGroupMembReductions */
	__ICMP6_MIB_MAX
};

/* tcp mib definitions */
/*
 * RFC 1213:  MIB-II TCP group
 * RFC 2012 (updates 1213):  SNMPv2-MIB-TCP
 */
enum
{
	TCP_MIB_NUM = 0,
	TCP_MIB_RTOALGORITHM,			/* RtoAlgorithm */
	TCP_MIB_RTOMIN,				/* RtoMin */
	TCP_MIB_RTOMAX,				/* RtoMax */
	TCP_MIB_MAXCONN,			/* MaxConn */
	TCP_MIB_ACTIVEOPENS,			/* ActiveOpens */
	TCP_MIB_PASSIVEOPENS,			/* PassiveOpens */
	TCP_MIB_ATTEMPTFAILS,			/* AttemptFails */
	TCP_MIB_ESTABRESETS,			/* EstabResets */
	TCP_MIB_CURRESTAB,			/* CurrEstab */
	TCP_MIB_INSEGS,				/* InSegs */
	TCP_MIB_OUTSEGS,			/* OutSegs */
	TCP_MIB_RETRANSSEGS,			/* RetransSegs */
	TCP_MIB_INERRS,				/* InErrs */
	TCP_MIB_OUTRSTS,			/* OutRsts */
	__TCP_MIB_MAX
};

/* udp mib definitions */
/*
 * RFC 1213:  MIB-II UDP group
 * RFC 2013 (updates 1213):  SNMPv2-MIB-UDP
 */
enum
{
	UDP_MIB_NUM = 0,
	UDP_MIB_INDATAGRAMS,			/* InDatagrams */
	UDP_MIB_NOPORTS,			/* NoPorts */
	UDP_MIB_INERRORS,			/* InErrors */
	UDP_MIB_OUTDATAGRAMS,			/* OutDatagrams */
	__UDP_MIB_MAX
};

/* sctp mib definitions */
/*
 * draft-ietf-sigtran-sctp-mib-07.txt
 */
enum
{
	SCTP_MIB_NUM = 0,
	SCTP_MIB_CURRESTAB,			/* CurrEstab */
	SCTP_MIB_ACTIVEESTABS,			/* ActiveEstabs */
	SCTP_MIB_PASSIVEESTABS,			/* PassiveEstabs */
	SCTP_MIB_ABORTEDS,			/* Aborteds */
	SCTP_MIB_SHUTDOWNS,			/* Shutdowns */
	SCTP_MIB_OUTOFBLUES,			/* OutOfBlues */
	SCTP_MIB_CHECKSUMERRORS,		/* ChecksumErrors */
	SCTP_MIB_OUTCTRLCHUNKS,			/* OutCtrlChunks */
	SCTP_MIB_OUTORDERCHUNKS,		/* OutOrderChunks */
	SCTP_MIB_OUTUNORDERCHUNKS,		/* OutUnorderChunks */
	SCTP_MIB_INCTRLCHUNKS,			/* InCtrlChunks */
	SCTP_MIB_INORDERCHUNKS,			/* InOrderChunks */
	SCTP_MIB_INUNORDERCHUNKS,		/* InUnorderChunks */
	SCTP_MIB_FRAGUSRMSGS,			/* FragUsrMsgs */
	SCTP_MIB_REASMUSRMSGS,			/* ReasmUsrMsgs */
	SCTP_MIB_OUTSCTPPACKS,			/* OutSCTPPacks */
	SCTP_MIB_INSCTPPACKS,			/* InSCTPPacks */
	SCTP_MIB_RTOALGORITHM,			/* RtoAlgorithm */
	SCTP_MIB_RTOMIN,			/* RtoMin */
	SCTP_MIB_RTOMAX,			/* RtoMax */
	SCTP_MIB_RTOINITIAL,			/* RtoInitial */
	SCTP_MIB_VALCOOKIELIFE,			/* ValCookieLife */
	SCTP_MIB_MAXINITRETR,			/* MaxInitRetr */
	__SCTP_MIB_MAX
};

/* linux mib definitions */
enum
{
	LINUX_MIB_NUM = 0,
	LINUX_MIB_SYNCOOKIESSENT,		/* SyncookiesSent */
	LINUX_MIB_SYNCOOKIESRECV,		/* SyncookiesRecv */
	LINUX_MIB_SYNCOOKIESFAILED,		/* SyncookiesFailed */
	LINUX_MIB_EMBRYONICRSTS,		/* EmbryonicRsts */
	LINUX_MIB_PRUNECALLED,			/* PruneCalled */
	LINUX_MIB_RCVPRUNED,			/* RcvPruned */
	LINUX_MIB_OFOPRUNED,			/* OfoPruned */
	LINUX_MIB_OUTOFWINDOWICMPS,		/* OutOfWindowIcmps */
	LINUX_MIB_LOCKDROPPEDICMPS,		/* LockDroppedIcmps */
	LINUX_MIB_ARPFILTER,			/* ArpFilter */
	LINUX_MIB_TIMEWAITED,			/* TimeWaited */
	LINUX_MIB_TIMEWAITRECYCLED,		/* TimeWaitRecycled */
	LINUX_MIB_TIMEWAITKILLED,		/* TimeWaitKilled */
	LINUX_MIB_PAWSPASSIVEREJECTED,		/* PAWSPassiveRejected */
	LINUX_MIB_PAWSACTIVEREJECTED,		/* PAWSActiveRejected */
	LINUX_MIB_PAWSESTABREJECTED,		/* PAWSEstabRejected */
	LINUX_MIB_DELAYEDACKS,			/* DelayedACKs */
	LINUX_MIB_DELAYEDACKLOCKED,		/* DelayedACKLocked */
	LINUX_MIB_DELAYEDACKLOST,		/* DelayedACKLost */
	LINUX_MIB_LISTENOVERFLOWS,		/* ListenOverflows */
	LINUX_MIB_LISTENDROPS,			/* ListenDrops */
	LINUX_MIB_TCPPREQUEUED,			/* TCPPrequeued */
	LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG,	/* TCPDirectCopyFromBacklog */
	LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE,	/* TCPDirectCopyFromPrequeue */
	LINUX_MIB_TCPPREQUEUEDROPPED,		/* TCPPrequeueDropped */
	LINUX_MIB_TCPHPHITS,			/* TCPHPHits */
	LINUX_MIB_TCPHPHITSTOUSER,		/* TCPHPHitsToUser */
	LINUX_MIB_TCPPUREACKS,			/* TCPPureAcks */
	LINUX_MIB_TCPHPACKS,			/* TCPHPAcks */
	LINUX_MIB_TCPRENORECOVERY,		/* TCPRenoRecovery */
	LINUX_MIB_TCPSACKRECOVERY,		/* TCPSackRecovery */
	LINUX_MIB_TCPSACKRENEGING,		/* TCPSACKReneging */
	LINUX_MIB_TCPFACKREORDER,		/* TCPFACKReorder */
	LINUX_MIB_TCPSACKREORDER,		/* TCPSACKReorder */
	LINUX_MIB_TCPRENOREORDER,		/* TCPRenoReorder */
	LINUX_MIB_TCPTSREORDER,			/* TCPTSReorder */
	LINUX_MIB_TCPFULLUNDO,			/* TCPFullUndo */
	LINUX_MIB_TCPPARTIALUNDO,		/* TCPPartialUndo */
	LINUX_MIB_TCPDSACKUNDO,			/* TCPDSACKUndo */
	LINUX_MIB_TCPLOSSUNDO,			/* TCPLossUndo */
	LINUX_MIB_TCPLOSS,			/* TCPLoss */
	LINUX_MIB_TCPLOSTRETRANSMIT,		/* TCPLostRetransmit */
	LINUX_MIB_TCPRENOFAILURES,		/* TCPRenoFailures */
	LINUX_MIB_TCPSACKFAILURES,		/* TCPSackFailures */
	LINUX_MIB_TCPLOSSFAILURES,		/* TCPLossFailures */
	LINUX_MIB_TCPFASTRETRANS,		/* TCPFastRetrans */
	LINUX_MIB_TCPFORWARDRETRANS,		/* TCPForwardRetrans */
	LINUX_MIB_TCPSLOWSTARTRETRANS,		/* TCPSlowStartRetrans */
	LINUX_MIB_TCPTIMEOUTS,			/* TCPTimeouts */
	LINUX_MIB_TCPRENORECOVERYFAIL,		/* TCPRenoRecoveryFail */
	LINUX_MIB_TCPSACKRECOVERYFAIL,		/* TCPSackRecoveryFail */
	LINUX_MIB_TCPSCHEDULERFAILED,		/* TCPSchedulerFailed */
	LINUX_MIB_TCPRCVCOLLAPSED,		/* TCPRcvCollapsed */
	LINUX_MIB_TCPDSACKOLDSENT,		/* TCPDSACKOldSent */
	LINUX_MIB_TCPDSACKOFOSENT,		/* TCPDSACKOfoSent */
	LINUX_MIB_TCPDSACKRECV,			/* TCPDSACKRecv */
	LINUX_MIB_TCPDSACKOFORECV,		/* TCPDSACKOfoRecv */
	LINUX_MIB_TCPABORTONSYN,		/* TCPAbortOnSyn */
	LINUX_MIB_TCPABORTONDATA,		/* TCPAbortOnData */
	LINUX_MIB_TCPABORTONCLOSE,		/* TCPAbortOnClose */
	LINUX_MIB_TCPABORTONMEMORY,		/* TCPAbortOnMemory */
	LINUX_MIB_TCPABORTONTIMEOUT,		/* TCPAbortOnTimeout */
	LINUX_MIB_TCPABORTONLINGER,		/* TCPAbortOnLinger */
	LINUX_MIB_TCPABORTFAILED,		/* TCPAbortFailed */
	LINUX_MIB_TCPMEMORYPRESSURES,		/* TCPMemoryPressures */
	__LINUX_MIB_MAX
};

#endif	/* _LINUX_SNMP_H */
