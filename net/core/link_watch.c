/*
 * Linux network device link state notification
 *
 * Author:
 *     Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <asm/types.h>


enum lw_bits {
	/**
	 * 当这个标志被设置时，linkwatch_event被调度执行，此标志由linkwatch_event自己清除。
	 */
	LW_RUNNING = 0,
	/**
	 * 由于lweventlist 通常有不止一个的元素，代码优化静态分配的 lw_event 数据结构并总是用它作为第一个元素。仅当内核需要明了不止一个的未决事件(事件在不止一个设备)，为它分配额外的lw_event结构；否则，它简单的重用同一个结构。
	 * 此标志表示第一个元素是否可用。
	 */
	LW_SE_USED
};

static unsigned long linkwatch_flags;
static unsigned long linkwatch_nextevent;

static void linkwatch_event(void *dummy);
static DECLARE_WORK(linkwatch_work, linkwatch_event, NULL);

/**
 * 连接状态改变事件列表。
 */
static LIST_HEAD(lweventlist);
/**
 * 保护lweventlist链表的锁。
 */
static DEFINE_SPINLOCK(lweventlist_lock);

/**
 * 网络设备连接状态改变事件。
 * lw_event结构并不包括任何区分信号传递的检测与丢失的参数.
 */
struct lw_event {
	/**
	 * 将结构连接到未决连接状态改变事件全局队列的字段lweventlist
	 */
	struct list_head list;
	/**
	 * 关联到net_device结构的指针
	 */
	struct net_device *dev;
};

/* Avoid kmalloc() for most systems */
static struct lw_event singleevent;

/* Must be called with the rtnl semaphore held */
void linkwatch_run_queue(void)
{
	LIST_HEAD(head);
	struct list_head *n, *next;

	spin_lock_irq(&lweventlist_lock);
	list_splice_init(&lweventlist, &head);
	spin_unlock_irq(&lweventlist_lock);

	list_for_each_safe(n, next, &head) {
		struct lw_event *event = list_entry(n, struct lw_event, list);
		struct net_device *dev = event->dev;

		if (event == &singleevent) {
			clear_bit(LW_SE_USED, &linkwatch_flags);
		} else {
			kfree(event);
		}

		/* We are about to handle this device,
		 * so new events can be accepted
		 */
		/**
		 * 清除dev->state的__LINK_STATE_LINKWATCH_PENDING标志位
		 */
		clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);

		if (dev->flags & IFF_UP) {
			/**
			 * 发送NETDEV_CHANGE通知给netdev_chain通知链。
			 * 发送RTM_NEWLINK通知给RTMGRP_LINK RTnetlink组。
			 */
			netdev_state_change(dev);
		}

		dev_put(dev);
	}
}       

/**
 * 处理lweventlist(包含linkwatch_run_queue)中的元素，这些元素包含未决的连接状态改变事件。
 */
static void linkwatch_event(void *dummy)
{
	/* Limit the number of linkwatch events to one
	 * per second so that a runaway driver does not
	 * cause a storm of messages on the netlink
	 * socket
	 */	
	linkwatch_nextevent = jiffies + HZ;
	clear_bit(LW_RUNNING, &linkwatch_flags);

	rtnl_shlock();
	linkwatch_run_queue();
	rtnl_shunlock();
}


void linkwatch_fire_event(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state)) {
		unsigned long flags;
		struct lw_event *event;

		if (test_and_set_bit(LW_SE_USED, &linkwatch_flags)) {
			event = kmalloc(sizeof(struct lw_event), GFP_ATOMIC);

			if (unlikely(event == NULL)) {
				clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);
				return;
			}
		} else {
			event = &singleevent;
		}

		dev_hold(dev);
		event->dev = dev;

		spin_lock_irqsave(&lweventlist_lock, flags);
		list_add_tail(&event->list, &lweventlist);
		spin_unlock_irqrestore(&lweventlist_lock, flags);

		if (!test_and_set_bit(LW_RUNNING, &linkwatch_flags)) {
			unsigned long thisevent = jiffies;

			if (thisevent >= linkwatch_nextevent) {
				schedule_work(&linkwatch_work);
			} else {
				schedule_delayed_work(&linkwatch_work, linkwatch_nextevent - thisevent);
			}
		}
	}
}

EXPORT_SYMBOL(linkwatch_fire_event);
