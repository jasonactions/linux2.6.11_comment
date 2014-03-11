/*
 *     SUCS NET3:
 *
 *     Generic stream handling routines. These are generic for most
 *     protocols. Even IP. Tonight 8-).
 *     This is used because TCP, LLC (others too) layer all have mostly
 *     identical sendmsg() and recvmsg() code.
 *     So we (will) share it here.
 *
 *     Authors:        Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *                     (from old tcp.c code)
 *                     Alan Cox <alan@redhat.com> (Borrowed comments 8-))
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/signal.h>
#include <linux/tcp.h>
#include <linux/wait.h>
#include <net/sock.h>

/**
 * sk_stream_write_space - stream socket write_space callback.
 * sk - socket
 *
 * FIXME: write proper description
 */
/* 检测发送缓冲区的大小，如果可用则唤醒等待的线程 */
void sk_stream_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
			wake_up_interruptible(sk->sk_sleep);
		if (sock->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(sock, 2, POLL_OUT);
	}
}

EXPORT_SYMBOL(sk_stream_write_space);

/**
 * sk_stream_wait_connect - Wait for a socket to get into the connected state
 * @sk - sock to wait on
 * @timeo_p - for how long to wait
 *
 * Must be called with the socket locked.
 */
int sk_stream_wait_connect(struct sock *sk, long *timeo_p)
{
	struct task_struct *tsk = current;
	DEFINE_WAIT(wait);

	while (1) {
		if (sk->sk_err)
			return sock_error(sk);
		if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV))
			return -EPIPE;
		if (!*timeo_p)
			return -EAGAIN;
		if (signal_pending(tsk))
			return sock_intr_errno(*timeo_p);

		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
		sk->sk_write_pending++;
		if (sk_wait_event(sk, timeo_p,
				  !((1 << sk->sk_state) & 
				    ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))))
			break;
		finish_wait(sk->sk_sleep, &wait);
		sk->sk_write_pending--;
	}
	return 0;
}

EXPORT_SYMBOL(sk_stream_wait_connect);

/**
 * sk_stream_closing - Return 1 if we still have things to send in our buffers.
 * @sk - socket to verify
 */
static inline int sk_stream_closing(struct sock *sk)
{
	return (1 << sk->sk_state) &
	       (TCPF_FIN_WAIT1 | TCPF_CLOSING | TCPF_LAST_ACK);
}

void sk_stream_wait_close(struct sock *sk, long timeout)
{
	if (timeout) {
		DEFINE_WAIT(wait);

		do {
			prepare_to_wait(sk->sk_sleep, &wait,
					TASK_INTERRUPTIBLE);
			if (sk_wait_event(sk, &timeout, !sk_stream_closing(sk)))
				break;
		} while (!signal_pending(current) && timeout);

		finish_wait(sk->sk_sleep, &wait);
	}
}

EXPORT_SYMBOL(sk_stream_wait_close);

/**
 * sk_stream_wait_memory - Wait for more memory for a socket
 * @sk - socket to wait for memory
 * @timeo_p - for how long
 */
/* 发送数据时，如果分配缓存区失败，则调用此函数进行等待 */
int sk_stream_wait_memory(struct sock *sk, long *timeo_p)
{
	int err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT(wait);

	if (sk_stream_memory_free(sk))
		current_timeo = vm_wait = (net_random() % (HZ / 5)) + 2;

	while (1) {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

		if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
			goto do_error;
		if (!*timeo_p)
			goto do_nonblock;
		if (signal_pending(current))
			goto do_interrupted;
		clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		if (sk_stream_memory_free(sk) && !vm_wait)
			break;

		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk->sk_write_pending++;
		sk_wait_event(sk, &current_timeo, sk_stream_memory_free(sk) &&
						  vm_wait);
		sk->sk_write_pending--;

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo_p;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo_p = current_timeo;
	}
out:
	finish_wait(sk->sk_sleep, &wait);
	return err;

do_error:
	err = -EPIPE;
	goto out;
do_nonblock:
	err = -EAGAIN;
	goto out;
do_interrupted:
	err = sock_intr_errno(*timeo_p);
	goto out;
}

EXPORT_SYMBOL(sk_stream_wait_memory);

/**
 * 当释放与TCP相关的接收报文时，回调此函数。
 */
void sk_stream_rfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);/* 减少接收缓存总数 */
	sk->sk_forward_alloc += skb->truesize;/* 增加预分配总数 */
}

EXPORT_SYMBOL(sk_stream_rfree);

int sk_stream_error(struct sock *sk, int flags, int err)
{
	if (err == -EPIPE)
		err = sock_error(sk) ? : -EPIPE;
	if (err == -EPIPE && !(flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);
	return err;
}

EXPORT_SYMBOL(sk_stream_error);

void __sk_stream_mem_reclaim(struct sock *sk)
{
	if (sk->sk_forward_alloc >= SK_STREAM_MEM_QUANTUM) {
		atomic_sub(sk->sk_forward_alloc / SK_STREAM_MEM_QUANTUM,
			   sk->sk_prot->memory_allocated);/* 将预分配缓存归还后，需要减少页面分配计数 */
		sk->sk_forward_alloc &= SK_STREAM_MEM_QUANTUM - 1;
		if (*sk->sk_prot->memory_pressure &&/* 目前已经进入告警状态 */
		    (atomic_read(sk->sk_prot->memory_allocated) </* 已经分配的内存低于告警线，退出告警状态 */
		     sk->sk_prot->sysctl_mem[0]))
			*sk->sk_prot->memory_pressure = 0;
	}
}

EXPORT_SYMBOL(__sk_stream_mem_reclaim);

/* 确认套接口是否能够分配特定长度的缓存 */
int sk_stream_mem_schedule(struct sock *sk, int size, int kind)
{
	/* 将长度转化为页面数 */
	int amt = sk_stream_pages(size);

	/* 调整预分配量，及总分配量 */
	sk->sk_forward_alloc += amt * SK_STREAM_MEM_QUANTUM;
	atomic_add(amt, sk->sk_prot->memory_allocated);

	/* Under limit. */
	/* 已分配内存低于低水平线，取消告警状态 */
	if (atomic_read(sk->sk_prot->memory_allocated) < sk->sk_prot->sysctl_mem[0]) {
		if (*sk->sk_prot->memory_pressure)
			*sk->sk_prot->memory_pressure = 0;
		return 1;
	}

	/* Over hard limit. */
	/* 超过告警限制，进入告警处理 */
	if (atomic_read(sk->sk_prot->memory_allocated) > sk->sk_prot->sysctl_mem[2]) {
		sk->sk_prot->enter_memory_pressure();
		goto suppress_allocation;
	}

	/* Under pressure. */
	/* 高于告警线，但是低于硬性限制线，则进入告警处理 */
	if (atomic_read(sk->sk_prot->memory_allocated) > sk->sk_prot->sysctl_mem[1])
		sk->sk_prot->enter_memory_pressure();

	if (kind) {/* 如果待确认的是接收缓存 */
		/* 接收队列中的数据总长度小于接收缓存部区的长度上限，则返回成功 */
		if (atomic_read(&sk->sk_rmem_alloc) < sk->sk_prot->sysctl_rmem[0])
			return 1;
	} else if (sk->sk_wmem_queued < sk->sk_prot->sysctl_wmem[0])/* 如果发送缓存总长度小于上限，也返回成功 */
		return 1;

	if (!*sk->sk_prot->memory_pressure ||/* 没有进入告警状态 */
	    sk->sk_prot->sysctl_mem[2] > atomic_read(sk->sk_prot->sockets_allocated) *
				sk_stream_pages(sk->sk_wmem_queued +
						atomic_read(&sk->sk_rmem_alloc) +
						sk->sk_forward_alloc))/* 或者总数据长度小于硬性限制线，也返回成功 */
		return 1;

suppress_allocation:

	if (!kind) {/* 确认的是发送缓存 */
		/* 缩小发送缓冲区的预分配大小为已经分配的缓冲队列大小的一半 */
		sk_stream_moderate_sndbuf(sk);

		/* Fail only if socket is _under_ its sndbuf.
		 * In this case we cannot block, so that we have to fail.
		 */
		if (sk->sk_wmem_queued + size >= sk->sk_sndbuf)/* ?? */
			return 1;
	}

	/* Alas. Undo changes. */
	/* 无法通过确认，恢复预分配值 */
	sk->sk_forward_alloc -= amt * SK_STREAM_MEM_QUANTUM;
	atomic_sub(amt, sk->sk_prot->memory_allocated);
	return 0;
}

EXPORT_SYMBOL(sk_stream_mem_schedule);

void sk_stream_kill_queues(struct sock *sk)
{
	/* First the read buffer. */
	__skb_queue_purge(&sk->sk_receive_queue);

	/* Next, the error queue. */
	__skb_queue_purge(&sk->sk_error_queue);

	/* Next, the write queue. */
	BUG_TRAP(skb_queue_empty(&sk->sk_write_queue));

	/* Account for returned memory. */
	sk_stream_mem_reclaim(sk);

	BUG_TRAP(!sk->sk_wmem_queued);
	BUG_TRAP(!sk->sk_forward_alloc);

	/* It is _impossible_ for the backlog to contain anything
	 * when we get here.  All user references to this socket
	 * have gone away, only the net layer knows can touch it.
	 */
}

EXPORT_SYMBOL(sk_stream_kill_queues);
