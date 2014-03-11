#ifndef _LINUX_ELEVATOR_H
#define _LINUX_ELEVATOR_H

typedef int (elevator_merge_fn) (request_queue_t *, struct request **,
				 struct bio *);

typedef void (elevator_merge_req_fn) (request_queue_t *, struct request *, struct request *);

typedef void (elevator_merged_fn) (request_queue_t *, struct request *);

typedef struct request *(elevator_next_req_fn) (request_queue_t *);

typedef void (elevator_add_req_fn) (request_queue_t *, struct request *, int);
typedef int (elevator_queue_empty_fn) (request_queue_t *);
typedef void (elevator_remove_req_fn) (request_queue_t *, struct request *);
typedef void (elevator_requeue_req_fn) (request_queue_t *, struct request *);
typedef struct request *(elevator_request_list_fn) (request_queue_t *, struct request *);
typedef void (elevator_completed_req_fn) (request_queue_t *, struct request *);
typedef int (elevator_may_queue_fn) (request_queue_t *, int);

typedef int (elevator_set_req_fn) (request_queue_t *, struct request *, int);
typedef void (elevator_put_req_fn) (request_queue_t *, struct request *);

typedef int (elevator_init_fn) (request_queue_t *, elevator_t *);
typedef void (elevator_exit_fn) (elevator_t *);

/* 电梯算法的回调函数 */
struct elevator_ops
{
	/* 查找可以和bio进行合并的请求，返回如ELEVATOR_NO_MERGE */
	elevator_merge_fn *elevator_merge_fn;
	/* 在调度器有请求被合并时被调用。 */
	elevator_merged_fn *elevator_merged_fn;
	/* 合并请求时回调 */
	elevator_merge_req_fn *elevator_merge_req_fn;

	elevator_next_req_fn *elevator_next_req_fn;
	/* 往调度器中添加请求时调用 */
	elevator_add_req_fn *elevator_add_req_fn;
	elevator_remove_req_fn *elevator_remove_req_fn;
	elevator_requeue_req_fn *elevator_requeue_req_fn;

	/* 判断队列是否为空 */
	elevator_queue_empty_fn *elevator_queue_empty_fn;
	/* 请求被完成时调用 */
	elevator_completed_req_fn *elevator_completed_req_fn;

	elevator_request_list_fn *elevator_former_req_fn;
	elevator_request_list_fn *elevator_latter_req_fn;

	/* 被某些电梯算法用于为请求分配存储空间 */
	elevator_set_req_fn *elevator_set_req_fn;
	/* 被某些电梯算法用于为请求释放存储空间 */
	elevator_put_req_fn *elevator_put_req_fn;

	/* 如果调度器希望运行当前上下文将一个新的请求排入队列时调用，此时不管队列是否超过限制 */
	elevator_may_queue_fn *elevator_may_queue_fn;

	/* 初始化函数，为算法分配特定的内存 */
	elevator_init_fn *elevator_init_fn;
	/* 释放函数，释放特定的内存 */
	elevator_exit_fn *elevator_exit_fn;
};

#define ELV_NAME_MAX	(16)

/*
 * identifies an elevator type, such as AS or deadline
 */
/* IO调度算法描述符 */
struct elevator_type
{
	/* 通过此字段加入到电梯算法类型链表dlv_list中 */
	struct list_head list;
	/* 电梯算法的回调函数 */
	struct elevator_ops ops;
	struct elevator_type *elevator_type;
	/* 驱动模型使用 */
	struct kobj_type *elevator_ktype;
	/* 算法名称 */
	char elevator_name[ELV_NAME_MAX];
	/* 所属模块 */
	struct module *elevator_owner;
};

/*
 * each queue has an elevator_queue assoicated with it
 */
/* 磁盘IO调度队列 */
struct elevator_queue
{
	/* 调度器操作回调 */
	struct elevator_ops *ops;
	/* 调度队列私有数据，如最后期限调度算法是deadline_data */
	void *elevator_data;
	/* 驱动模型使用 */
	struct kobject kobj;
	/* 算法类型 */
	struct elevator_type *elevator_type;
};

/*
 * block elevator interface
 */
extern void elv_add_request(request_queue_t *, struct request *, int, int);
extern void __elv_add_request(request_queue_t *, struct request *, int, int);
extern int elv_merge(request_queue_t *, struct request **, struct bio *);
extern void elv_merge_requests(request_queue_t *, struct request *,
			       struct request *);
extern void elv_merged_request(request_queue_t *, struct request *);
extern void elv_remove_request(request_queue_t *, struct request *);
extern void elv_requeue_request(request_queue_t *, struct request *);
extern int elv_queue_empty(request_queue_t *);
extern struct request *elv_next_request(struct request_queue *q);
extern struct request *elv_former_request(request_queue_t *, struct request *);
extern struct request *elv_latter_request(request_queue_t *, struct request *);
extern int elv_register_queue(request_queue_t *q);
extern void elv_unregister_queue(request_queue_t *q);
extern int elv_may_queue(request_queue_t *, int);
extern void elv_completed_request(request_queue_t *, struct request *);
extern int elv_set_request(request_queue_t *, struct request *, int);
extern void elv_put_request(request_queue_t *, struct request *);

/*
 * io scheduler registration
 */
extern int elv_register(struct elevator_type *);
extern void elv_unregister(struct elevator_type *);

/*
 * io scheduler sysfs switching
 */
extern ssize_t elv_iosched_show(request_queue_t *, char *);
extern ssize_t elv_iosched_store(request_queue_t *, const char *, size_t);

extern int elevator_init(request_queue_t *, char *);
extern void elevator_exit(elevator_t *);
extern int elv_rq_merge_ok(struct request *, struct bio *);
extern int elv_try_merge(struct request *, struct bio *);
extern int elv_try_last_merge(request_queue_t *, struct bio *);

/*
 * Return values from elevator merger
 */
/**
 * elv_merge函数的返回值
 * 该函数检查新的BIO请求是否可以并入已经存在的请求中。
 */
/**
 * 已经存在的请求中不能包含BIO结构。
 */
#define ELEVATOR_NO_MERGE	0
/**
 * BIO结构可以作为末尾的BIO而插入到某个请求中。这时，可能还检查是否与下一个请求合并。
 */
#define ELEVATOR_FRONT_MERGE	1
/**
 * BIO结构可以作为某个请求的第一个BIO被插入。这时需要检查是否能够与前一个请求合并。
 */
#define ELEVATOR_BACK_MERGE	2

/*
 * Insertion selection
 */
#define ELEVATOR_INSERT_FRONT	1
#define ELEVATOR_INSERT_BACK	2
#define ELEVATOR_INSERT_SORT	3

/*
 * return values from elevator_may_queue_fn
 */
enum {
	ELV_MQUEUE_MAY,
	ELV_MQUEUE_NO,
	ELV_MQUEUE_MUST,
};

#endif
