/*
 *	Spanning tree protocol; generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_stp.c,v 1.4 2000/06/19 10:13:35 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/smp_lock.h>

#include "br_private.h"
#include "br_private_stp.h"

/* since time values in bpdu are in jiffies and then scaled (1/256)
 * before sending, make sure that is at least one.
 */
#define MESSAGE_AGE_INCR	((HZ < 256) ? 1 : (HZ/256))

static const char *br_port_state_names[] = {
	[BR_STATE_DISABLED] = "disabled", 
	[BR_STATE_LISTENING] = "listening",
	[BR_STATE_LEARNING] = "learning", 
	[BR_STATE_FORWARDING] = "forwarding", 
	[BR_STATE_BLOCKING] = "blocking",
};

void br_log_state(const struct net_bridge_port *p)
{
	pr_info("%s: port %d(%s) entering %s state\n",
		p->br->dev->name, p->port_no, p->dev->name, 
		br_port_state_names[p->state]);

}

/* called under bridge lock */
/**
 * 对于指定的网桥设备和端口号，返回相关的net_bridge_port数据结构。
 */
struct net_bridge_port *br_get_port(struct net_bridge *br, u16 port_no)
{
	struct net_bridge_port *p;

	list_for_each_entry_rcu(p, &br->port_list, list) {
		if (p->port_no == port_no)
			return p;
	}

	return NULL;
}

/* called under bridge lock */
/**
 * 对于指定的网桥端口，和当前根端口，br_should_become_root_port比较端口和当前根端口的优先级向量，如果端口拥有更高优先级向量就返回1,否则返回0；
 */
static int br_should_become_root_port(const struct net_bridge_port *p, 
				      u16 root_port)
{
	struct net_bridge *br;
	struct net_bridge_port *rp;
	int t;

	br = p->br;
	if (p->state == BR_STATE_DISABLED ||
	    br_is_designated_port(p))
		return 0;

	if (memcmp(&br->bridge_id, &p->designated_root, 8) <= 0)
		return 0;

	if (!root_port)
		return 1;

	rp = br_get_port(br, root_port);

	t = memcmp(&p->designated_root, &rp->designated_root, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (p->designated_cost + p->path_cost <
	    rp->designated_cost + rp->path_cost)
		return 1;
	else if (p->designated_cost + p->path_cost >
		 rp->designated_cost + rp->path_cost)
		return 0;

	t = memcmp(&p->designated_bridge, &rp->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (p->designated_port < rp->designated_port)
		return 1;
	else if (p->designated_port > rp->designated_port)
		return 0;

	if (p->port_id < rp->port_id)
		return 1;

	return 0;
}

/* called under bridge lock */
/**
 * 对于给定的网桥，br_root_selection选择根端口。
 */
static void br_root_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;
	u16 root_port = 0;

	list_for_each_entry(p, &br->port_list, list) {
		if (br_should_become_root_port(p, root_port))
			root_port = p->port_no;

	}

	br->root_port = root_port;

	if (!root_port) {
		br->designated_root = br->bridge_id;
		br->root_path_cost = 0;
	} else {
		p = br_get_port(br, root_port);
		br->designated_root = p->designated_root;
		br->root_path_cost = p->designated_cost + p->path_cost;
	}
}

/* called under bridge lock */
/**
 * 当非根桥变为根桥时调用。
 */
void br_become_root_bridge(struct net_bridge *br)
{
	/**
	 * 更新其他时钟为本地配置值，因为根桥的时钟使用本地设置的值。
	 */
	br->max_age = br->bridge_max_age;
	br->hello_time = br->bridge_hello_time;
	br->forward_delay = br->bridge_forward_delay;
	/**
	 * 启动拓扑变化事件。
	 */
	br_topology_change_detection(br);
	/**
	 * 停止TCN时钟，因为它不应当在根桥上运行
	 */
	del_timer(&br->tcn_timer);

	if (br->dev->flags & IFF_UP) {
		br_config_bpdu_generation(br);
		/**
		 * 开始HELLO时钟，这个时钟仅仅运行在根桥中。
		 */
		mod_timer(&br->hello_timer, jiffies + br->hello_time);
	}
}

/* called under bridge lock */
/**
 * 发送一个配置BPDU。
 */
void br_transmit_config(struct net_bridge_port *p)
{
	struct br_config_bpdu bpdu;
	struct net_bridge *br;


	if (timer_pending(&p->hold_timer)) {
		p->config_pending = 1;
		return;
	}

	br = p->br;

	bpdu.topology_change = br->topology_change;
	bpdu.topology_change_ack = p->topology_change_ack;
	bpdu.root = br->designated_root;
	bpdu.root_path_cost = br->root_path_cost;
	bpdu.bridge_id = br->bridge_id;
	bpdu.port_id = p->port_id;
	if (br_is_root_bridge(br))
		bpdu.message_age = 0;
	else {
		struct net_bridge_port *root
			= br_get_port(br, br->root_port);
		bpdu.message_age = br->max_age
			- (root->message_age_timer.expires - jiffies)
			+ MESSAGE_AGE_INCR;
	}
	bpdu.max_age = br->max_age;
	bpdu.hello_time = br->hello_time;
	bpdu.forward_delay = br->forward_delay;

	if (bpdu.message_age < br->max_age) {
		br_send_config_bpdu(p, &bpdu);
		p->topology_change_ack = 0;
		p->config_pending = 0;
		mod_timer(&p->hold_timer, jiffies + BR_HOLD_TIME);
	}
}

/* called under bridge lock */
/**
 * 记录BPDU的优先级向量到端口的net_bridge_port数据结构，然后重启消息老化时钟；
 */
static inline void br_record_config_information(struct net_bridge_port *p, 
						const struct br_config_bpdu *bpdu)
{
	p->designated_root = bpdu->root;
	p->designated_cost = bpdu->root_path_cost;
	p->designated_bridge = bpdu->bridge_id;
	p->designated_port = bpdu->port_id;

	mod_timer(&p->message_age_timer, jiffies 
		  + (p->br->max_age - bpdu->message_age));
}

/* called under bridge lock */
/**
 * 记录BPDU中的时钟配置。
 */
static inline void br_record_config_timeout_values(struct net_bridge *br, 
					    const struct br_config_bpdu *bpdu)
{
	br->max_age = bpdu->max_age;
	br->hello_time = bpdu->hello_time;
	br->forward_delay = bpdu->forward_delay;
	br->topology_change = bpdu->topology_change;
}

/* called under bridge lock */
/**
 * 发送一个TCN BPDU。
 */
void br_transmit_tcn(struct net_bridge *br)
{
	br_send_tcn_bpdu(br_get_port(br, br->root_port));
}

/* called under bridge lock */
/**
 * 确定一个指定的端口是否应当被赋予指派者角色。
 */
static int br_should_become_designated_port(const struct net_bridge_port *p)
{
	struct net_bridge *br;
	int t;

	br = p->br;
	if (br_is_designated_port(p))
		return 1;

	if (memcmp(&p->designated_root, &br->designated_root, 8))
		return 1;

	if (br->root_path_cost < p->designated_cost)
		return 1;
	else if (br->root_path_cost > p->designated_cost)
		return 0;

	t = memcmp(&br->bridge_id, &p->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (p->port_id < p->designated_port)
		return 1;

	return 0;
}

/* called under bridge lock */
/**
 * 遍历所有网桥端口，并且将应当设置成指派角色的端口设置成指派端口。
 */
static void br_designated_port_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED &&
		    br_should_become_designated_port(p))
			br_become_designated_port(p);

	}
}

/* called under bridge lock */
/**
 * 对于指定的端口，以及在端口上接收到的配置BPDU，如果BPDU比端口优先级更高（拥有一个更高的优先级向量），则返回1,否则返回0.
 */
static int br_supersedes_port_info(struct net_bridge_port *p, struct br_config_bpdu *bpdu)
{
	int t;

	t = memcmp(&bpdu->root, &p->designated_root, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (bpdu->root_path_cost < p->designated_cost)
		return 1;
	else if (bpdu->root_path_cost > p->designated_cost)
		return 0;

	t = memcmp(&bpdu->bridge_id, &p->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (memcmp(&bpdu->bridge_id, &p->br->bridge_id, 8))
		return 1;

	if (bpdu->port_id <= p->designated_port)
		return 1;

	return 0;
}

/* called under bridge lock */
/**
 * 停止TCN时钟。
 */
static inline void br_topology_change_acknowledged(struct net_bridge *br)
{
	br->topology_change_detected = 0;
	del_timer(&br->tcn_timer);
}

/* called under bridge lock */
/**
 * 检测拓扑变化事件，区别处理根桥和非根桥检测到的拓扑变化事件。
 */
void br_topology_change_detection(struct net_bridge *br)
{
	int isroot = br_is_root_bridge(br);

	pr_info("%s: topology change detected, %s\n", br->dev->name,
		isroot ? "propagating" : "sending tcn bpdu");

	if (isroot) {
		br->topology_change = 1;
		mod_timer(&br->topology_change_timer, jiffies
			  + br->bridge_forward_delay + br->bridge_max_age);
	} else if (!br->topology_change_detected) {
		br_transmit_tcn(br);
		mod_timer(&br->tcn_timer, jiffies + br->bridge_hello_time);
	}

	br->topology_change_detected = 1;
}

/* called under bridge lock */
void br_config_bpdu_generation(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED &&
		    br_is_designated_port(p))
			br_transmit_config(p);
	}
}

/* called under bridge lock */
/**
 * 以另外一个BPDU应答接收到的配置BPDU入帧。它是对br_transmit_config的一个简单封装。
 */
static inline void br_reply(struct net_bridge_port *p)
{
	br_transmit_config(p);
}

/* called under bridge lock */
/**
 * 对于给定的网桥，确定根端口和指派端口并返回它们的信息。
 * 当网桥的配置发生了改变时被调用。
 *		br_received_config_bpdu:		在网桥端口上接收到一个更高优先级的配置BPDU。
 *		br_message_age_timer_expired:	网桥信息超时。BPDU老化了。
 *		br_stp_disable_port:			网桥端口被禁止了。
 *		br_stp_change_bridge_id:		网桥ID中的MAC地址被改变了。
 *		br_stp_set_bridge_priority:		当网桥优先级被修改时。
 *		br_stp_set_path_cost:			端口权重值被修改了。
 */
void br_configuration_update(struct net_bridge *br)
{
	br_root_selection(br);
	br_designated_port_selection(br);
}

/* called under bridge lock */
/**
 * 为一个网桥端口分配指派角色。
 */
void br_become_designated_port(struct net_bridge_port *p)
{
	struct net_bridge *br;

	br = p->br;
	p->designated_root = br->designated_root;
	p->designated_cost = br->root_path_cost;
	p->designated_bridge = br->bridge_id;
	p->designated_port = p->port_id;
}


/* called under bridge lock */
/**
 * 将网桥端口设置为阻塞状态。当STP发现一个发送端口被阻塞时调用。
 */
static void br_make_blocking(struct net_bridge_port *p)
{
	if (p->state != BR_STATE_DISABLED &&
	    p->state != BR_STATE_BLOCKING) {
		if (p->state == BR_STATE_FORWARDING ||
		    p->state == BR_STATE_LEARNING)
			br_topology_change_detection(p->br);

		p->state = BR_STATE_BLOCKING;
		br_log_state(p);
		del_timer(&p->forward_delay_timer);
	}
}

/* called under bridge lock */
/**
 * 将网桥端口转换为激活状态。
 */
static void br_make_forwarding(struct net_bridge_port *p)
{
	/**
	 * 只有BR_STATE_BLOCKING状态的端口才能转换为激活状态。
	 * 你不能为端口指定一个介于BR_STATE_BLOCKING和BR_STATE_FORWARDING之间的中间状态，中间状态一定时系统完成的。 
	 */
	if (p->state == BR_STATE_BLOCKING) {
		/**
		 * 当STP没有运行时，网桥端口跳过BR_STATE_LISTENING状态。
		 * 当STP没有运行时，所有网桥端口都被指定为发送状态。
		 * 因此，你可以跳过BR_STATE_LISTENING状态。
		 */
		if (p->br->stp_enabled) {
			/**
			 * 使用中间状态BR_STATE_LISTENING可以允许网桥学习一些MAC地址，并且减少flooding数量。
			 */
			p->state = BR_STATE_LISTENING;
		} else {
			p->state = BR_STATE_LEARNING;
		}
		br_log_state(p);
		/**
		 * 启动时钟，由时钟将端口状态转换成激活状态。
		 */
		mod_timer(&p->forward_delay_timer, jiffies + p->br->forward_delay);	}
}

/* called under bridge lock */
/**
 * 对于给定的网桥，为每一个网桥端口选择正确的端口状态。
 */
void br_port_state_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED) {/* 相关的绑定设备被UP。 */
			if (p->port_no == br->root_port) {
				p->config_pending = 0;
				p->topology_change_ack = 0;
				br_make_forwarding(p);
			} else if (br_is_designated_port(p)) {
				del_timer(&p->message_age_timer);
				br_make_forwarding(p);
			} else {
				p->config_pending = 0;
				p->topology_change_ack = 0;
				br_make_blocking(p);
			}
		}

	}
}

/* called under bridge lock */
/**
 * 通过发送一个带TCA标志的配置BPDU来应答接收到的TCN。
 */
static inline void br_topology_change_acknowledge(struct net_bridge_port *p)
{
	p->topology_change_ack = 1;
	br_transmit_config(p);
}

/* called under bridge lock */
/**
 * 处理接收到的配置BPDU包。可能引起根桥的变化。
 */
void br_received_config_bpdu(struct net_bridge_port *p, struct br_config_bpdu *bpdu)
{
	struct net_bridge *br;
	int was_root;
 
	br = p->br;
	was_root = br_is_root_bridge(br);

	if (br_supersedes_port_info(p, bpdu)) {
		br_record_config_information(p, bpdu);
		br_configuration_update(br);
		br_port_state_selection(br);

		if (!br_is_root_bridge(br) && was_root) {
			del_timer(&br->hello_timer);
			if (br->topology_change_detected) {
				del_timer(&br->topology_change_timer);
				br_transmit_tcn(br);

				mod_timer(&br->tcn_timer, 
					  jiffies + br->bridge_hello_time);
			}
		}

		if (p->port_no == br->root_port) {
			br_record_config_timeout_values(br, bpdu);
			br_config_bpdu_generation(br);
			if (bpdu->topology_change_ack)
				br_topology_change_acknowledged(br);
		}
	} else if (br_is_designated_port(p)) {		
		br_reply(p);		
	}
}

/* called under bridge lock */
/**
 * 当在一个网桥端口上接收到一个TCN BPDU时调用。
 */
void br_received_tcn_bpdu(struct net_bridge_port *p)
{
	if (br_is_designated_port(p)) {
		pr_info("%s: received tcn bpdu on port %i(%s)\n",
		       p->br->dev->name, p->port_no, p->dev->name);

		br_topology_change_detection(p->br);
		br_topology_change_acknowledge(p);
	}
}
