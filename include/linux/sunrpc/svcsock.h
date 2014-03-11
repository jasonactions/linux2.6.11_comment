/*
 * linux/include/linux/sunrpc/svcsock.h
 *
 * RPC server socket I/O.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifndef SUNRPC_SVCSOCK_H
#define SUNRPC_SVCSOCK_H

#include <linux/sunrpc/svc.h>

/*
 * RPC server socket.
 */
/**
 * RPC服务器套接字，是对SOCKET的一个封装。
 */
struct svc_sock {
	/**
	 * 准备好的svc_socket的链表
	 */
	struct list_head	sk_ready;	/* list of ready sockets */
	/**
	 * 所有的svc_socket
	 */
	struct list_head	sk_list;	/* list of all sockets */
	/** 
	 * berkeley socket 层套接字。
	 */
	struct socket *		sk_sock;	/* berkeley socket layer */
	/** 
	 * INET层 
	 */
	struct sock *		sk_sk;		/* INET layer */

	/** 
	 * 对应这个socket的serv结构 
	 */
	struct svc_serv *	sk_server;	/* service for this socket */
	/**
	 * 使用计数 
	 */
	unsigned int		sk_inuse;	/* use count */
	unsigned long		sk_flags;
#define	SK_BUSY		0			/* enqueued/receiving */
#define	SK_CONN		1			/* conn pending */
#define	SK_CLOSE	2			/* dead or dying */
#define	SK_DATA		3			/* data pending */
#define	SK_TEMP		4			/* temp (TCP) socket */
#define	SK_DEAD		6			/* socket closed */
#define	SK_CHNGBUF	7			/* need to change snd/rcv buffer sizes */
#define	SK_DEFERRED	8			/* request on sk_deferred */

	int			sk_reserved;	/* space on outq that is reserved */

	struct list_head	sk_deferred;	/* deferred requests that need to
						 * be revisted */
	struct semaphore        sk_sem;		/* to serialize sending data */

	int			(*sk_recvfrom)(struct svc_rqst *rqstp);
	int			(*sk_sendto)(struct svc_rqst *rqstp);

	/* We keep the old state_change and data_ready CB's here */
	void			(*sk_ostate)(struct sock *);
	void			(*sk_odata)(struct sock *, int bytes);
	void			(*sk_owspace)(struct sock *);

	/* private TCP part */
	/** 
	 * 记录长度 
	 */
	int			sk_reclen;	/* length of record */
	/**
	 * 现在读长度 
	 */
	int			sk_tcplen;	/* current read length */
	/**
	 * 最后一次接收时间。
	 */
	time_t			sk_lastrecv;	/* time of last received request */
};

/*
 * Function prototypes.
 */
int		svc_makesock(struct svc_serv *, int, unsigned short);
void		svc_delete_socket(struct svc_sock *);
int		svc_recv(struct svc_serv *, struct svc_rqst *, long);
int		svc_send(struct svc_rqst *);
void		svc_drop(struct svc_rqst *);
void		svc_sock_update_bufs(struct svc_serv *serv);

#endif /* SUNRPC_SVCSOCK_H */
