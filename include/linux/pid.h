#ifndef _LINUX_PID_H
#define _LINUX_PID_H

enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_TGID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};

struct pid
{
	/* Try to keep pid_chain in the same cacheline as nr for find_pid */
	/**
	 * PID值。
	 */
	int nr;
	/**
	 * 链接散列表中下一个和前一个元素。
	 */
	struct hlist_node pid_chain;
	/* list of pids with the same nr, only one of them is in the hash */
	/**
	 * 每个PID的进程链表头。
	 */
	struct list_head pid_list;
};

#define pid_task(elem, type) \
	list_entry(elem, struct task_struct, pids[type].pid_list)

/*
 * attach_pid() and detach_pid() must be called with the tasklist_lock
 * write-held.
 */
extern int FASTCALL(attach_pid(struct task_struct *task, enum pid_type type, int nr));

extern void FASTCALL(detach_pid(struct task_struct *task, enum pid_type));

/*
 * look up a PID in the hash table. Must be called with the tasklist_lock
 * held.
 */
extern struct pid *FASTCALL(find_pid(enum pid_type, int));

extern int alloc_pidmap(void);
extern void FASTCALL(free_pidmap(int));
extern void switch_exec_pids(struct task_struct *leader, struct task_struct *thread);

/**
 * 循环作用于链表上PID值等于who的PID链表上（进程链表上每个结点本身也是一个链表，包含了PID相同的线程组）
 * 链表类型为type,task指向当前被扫描的元素的进程描述符。
 */
#define do_each_task_pid(who, type, task)				\
	if ((task = find_task_by_pid_type(type, who))) {		\
		prefetch((task)->pids[type].pid_list.next);		\
		do {

#define while_each_task_pid(who, type, task)				\
		} while (task = pid_task((task)->pids[type].pid_list.next,\
						type),			\
			prefetch((task)->pids[type].pid_list.next),	\
			hlist_unhashed(&(task)->pids[type].pid_chain));	\
	}								\

#endif /* _LINUX_PID_H */
