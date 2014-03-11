/*
 *	Routines to manage notifier chains for passing status changes to any
 *	interested routines. We need this instead of hard coded call lists so
 *	that modules can poke their nose into the innards. The network devices
 *	needed them so here they are for the rest of you.
 *
 *				Alan Cox <Alan.Cox@linux.org>
 */
 
#ifndef _LINUX_NOTIFIER_H
#define _LINUX_NOTIFIER_H
#include <linux/errno.h>

/**
 * 通知链表结点。
 */
struct notifier_block
{
	/**
	 * 需要执行的函数
	 */
	int (*notifier_call)(struct notifier_block *self, unsigned long, void *);
	/**
	 * 指向下一结点的指针
	 */
	struct notifier_block *next;
	/**
	 * 函数优先级，但是，在实际的代码中，所有注册的节点不会设置priority，而是使用默认的 0。
	 * 这就意味着，节点的执行顺序是它注册的顺序
	 */
	int priority;
};


#ifdef __KERNEL__

extern int notifier_chain_register(struct notifier_block **list, struct notifier_block *n);
extern int notifier_chain_unregister(struct notifier_block **nl, struct notifier_block *n);
extern int notifier_call_chain(struct notifier_block **n, unsigned long val, void *v);

/**
 * 对这个通知不感兴趣
 */
#define NOTIFY_DONE		0x0000		/* Don't care */
/**
 * 通知处理成功
 */
#define NOTIFY_OK		0x0001		/* Suits me */
/**
 * notifier_call_chain检查这个标记来确定是停止遍历，还是继续。
 */
#define NOTIFY_STOP_MASK	0x8000		/* Don't call further */
/**
 * 有错误发生。停止对当前事件的处理。 
 */
#define NOTIFY_BAD		(NOTIFY_STOP_MASK|0x0002)	/* Bad/Veto action	*/
/*
 * Clean way to return from the notifier and stop further calls.
 */
/**
 * 回调函数出错。因此，后面的回调函数都不会被调用。
 */
#define NOTIFY_STOP		(NOTIFY_OK|NOTIFY_STOP_MASK)

/*
 *	Declared notifiers so far. I can imagine quite a few more chains
 *	over time (eg laptop power reset chains, reboot chain (to clean 
 *	device units up), device [un]mount chain, module load/unload chain,
 *	low memory chain, screenblank chain (for plug in modular screenblankers) 
 *	VC switch chains (for loadable kernel svgalib VC switch helpers) etc...
 */
 
/* netdevice notifier chain */
/**
 * 被触发以报告设备使能。它由dev_open产生。
 */
#define NETDEV_UP	0x0001	/* For now you can't veto a device up/down */
/**
 * NETDEV_GOING_DOWN被触发以报告将被禁止，而NETDEV_DOWN被触发报告设备已被禁止。两者均由dev_close产生。
 */
#define NETDEV_DOWN	0x0002
/**
 * 设备由于硬件错误而重启，目前不用，保留
 */
#define NETDEV_REBOOT	0x0003	/* Tell a protocol stack a network interface
				   detected a hardware crash and restarted
				   - we can use this eg to kick tcp sessions
				   once done */
/**
 * 设备状态或设备配置改变，这被用在各种情况，而不被 NETDEV_CHANGEADDR 和NETDEV_CHANGENAME屏蔽。
 * 它用于dev->flags标志改变时。
 */
#define NETDEV_CHANGE	0x0004	/* Notify device state change */
/**
 * 设备已经注册，事件由register_netdevice产生
 */
#define NETDEV_REGISTER 0x0005
/**
 * 设备已注销，事件由unregister_netdevice产生
 */
#define NETDEV_UNREGISTER	0x0006
#define NETDEV_CHANGEMTU	0x0007
/**
 * 设备硬件地址(或相关联的广播地址)已改变。
 */
#define NETDEV_CHANGEADDR	0x0008
/**
 * NETDEV_GOING_DOWN被触发以报告将被禁止，而NETDEV_DOWN被触发报告设备已被禁止。两者均由dev_close产生。
 */
#define NETDEV_GOING_DOWN	0x0009
/**
 * 设备的名字改变
 */
#define NETDEV_CHANGENAME	0x000A

#define SYS_DOWN	0x0001	/* Notify of system down */
#define SYS_RESTART	SYS_DOWN
#define SYS_HALT	0x0002	/* Notify of system halt */
#define SYS_POWER_OFF	0x0003	/* Notify of system power off */

#define NETLINK_URELEASE	0x0001	/* Unicast netlink socket released */

#define CPU_ONLINE		0x0002 /* CPU (unsigned)v is up */
#define CPU_UP_PREPARE		0x0003 /* CPU (unsigned)v coming up */
#define CPU_UP_CANCELED		0x0004 /* CPU (unsigned)v NOT coming up */
#define CPU_DOWN_PREPARE	0x0005 /* CPU (unsigned)v going down */
#define CPU_DOWN_FAILED		0x0006 /* CPU (unsigned)v NOT going down */
#define CPU_DEAD		0x0007 /* CPU (unsigned)v dead */

#endif /* __KERNEL__ */
#endif /* _LINUX_NOTIFIER_H */
