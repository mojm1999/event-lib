#pragma once
#ifndef BUFFER_H_INCLUDED_
#define BUFFER_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <base.h>

#define BEV_EVENT_CONNECTED	0x80

#define EVBUFFER_FLAG_DRAINS_TO_FD 1

#define EVBUFFER_IMMUTABLE	0x0008
#define EVBUFFER_MEM_PINNED_R	0x0010
#define EVBUFFER_MEM_PINNED_W	0x0020
#define EVBUFFER_MEM_PINNED_ANY (EVBUFFER_MEM_PINNED_R|EVBUFFER_MEM_PINNED_W)

#define CHAIN_PINNED(ch)  (((ch)->flags & EVBUFFER_MEM_PINNED_ANY) != 0)
#define CHAIN_PINNED_R(ch)  (((ch)->flags & EVBUFFER_MEM_PINNED_R) != 0)

#define MIN_BUFFER_SIZE	1024

#define BEV_EVENT_WRITING	0x02
#define BEV_EVENT_EOF		0x10
#define BEV_EVENT_ERROR		0x20
#define BEV_EVENT_TIMEOUT	0x40

enum bufferevent_flush_mode {
	BEV_NORMAL = 0,
	BEV_FLUSH = 1,
	BEV_FINISHED = 2
};

enum bufferevent_ctrl_op {
	BEV_CTRL_SET_FD,
	BEV_CTRL_GET_FD,
	BEV_CTRL_GET_UNDERLYING,
	BEV_CTRL_CANCEL_ALL
};

enum bufferevent_options {
	BEV_OPT_CLOSE_ON_FREE = (1 << 0),
	BEV_OPT_THREADSAFE = (1 << 1),
	BEV_OPT_DEFER_CALLBACKS = (1 << 2),
	BEV_OPT_UNLOCK_CALLBACKS = (1 << 3)
};

enum bufferevent_trigger_options {
	BEV_TRIG_IGNORE_WATERMARKS = (1<<16),

};

typedef void (*bufferevent_event_cb)(struct bufferevent* bev, short what, void* ctx);
typedef void (*bufferevent_data_cb)(struct bufferevent* bev, void* ctx);
typedef void (*evbuffer_cb_func)(struct evbuffer* buffer, const struct evbuffer_cb_info* info, void* arg);
typedef void (*evbuffer_cb)(struct evbuffer* buffer, size_t old_len, size_t new_len, void* arg);

union bufferevent_ctrl_data {
	void* ptr;
	evutil_socket_t fd;
};

struct bufferevent_ops {
	const char* type;
	long mem_offset;
	int (*enable)(struct bufferevent*, short);
	int (*disable)(struct bufferevent*, short);
	void (*unlink)(struct bufferevent*);
	void (*destruct)(struct bufferevent*);
	int (*adj_timeouts)(struct bufferevent*);

	int (*flush)(struct bufferevent*, short, enum bufferevent_flush_mode);
	int (*ctrl)(struct bufferevent*, enum bufferevent_ctrl_op, union bufferevent_ctrl_data*);
};

struct evbuffer_chain {
	struct evbuffer_chain* next;
	unsigned flags;
	/** 缓冲区大小 */
	size_t buffer_len;
	/** 写入字节数 */
	size_t off;
	/** 已发送字节数 */
	ev_ssize_t misalign;
	/** 引用计数 */
	int refcnt;

	/** 字符串开始地址 */
	unsigned char* buffer;
};

#define EVBUFFER_CHAIN_SIZE sizeof(struct evbuffer_chain)
#define EVBUFFER_CHAIN_EXTRA(t, c) (t *)((struct evbuffer_chain *)(c) + 1)

struct evbuffer_cb_entry {
	LIST_ENTRY(evbuffer_cb_entry) next;
	union {
		evbuffer_cb_func cb_func;
		evbuffer_cb		cb_obsolete;
	} cb;	/** 回调函数 */
	void* cbarg;
	uint32_t flags;
};

struct evbuffer {
	/** 首元素 */
	struct evbuffer_chain* first;
	/** 尾元素 */
	struct evbuffer_chain* last;
	/** 最后带数据元素地址 */
	struct evbuffer_chain** last_with_datap;

	int refcnt;
	/** 总字节数 */
	size_t total_len;
	size_t n_add_for_cb;
	size_t n_del_for_cb;

	struct bufferevent* parent;
	unsigned deferred_cbs : 1;
	unsigned own_lock : 1;
	/** 回调队列 */
	LIST_HEAD(evbuffer_cb_queue, evbuffer_cb_entry) callbacks;
	struct event_base* cb_queue;
	struct event_callback deferred;
	/** 标记 */
	uint32_t flags;

	/** out */
	unsigned freeze_start : 1;
	/** in */
	unsigned freeze_end : 1;
};

struct evbuffer_cb_info {
	size_t orig_size;
	size_t n_added;
	size_t n_deleted;
};

struct event_watermark {
	size_t low;
	size_t high;
};

struct bufferevent {
	struct event_base* ev_base;
	/** 统一管理接口 */
	const struct bufferevent_ops* be_ops;
	/** 读事件 */
	struct event ev_read;
	struct timeval timeout_read;
	/** 写事件 */
	struct event ev_write;
	struct timeval timeout_write;
	/** 输入缓冲 */
	struct evbuffer* input;
	/** 输出缓冲 */
	struct evbuffer* output;

	/** 包含什么事件 如EV_WRITE */
	short enabled;

	/** 缓存数据读回调 */
	bufferevent_data_cb readcb;
	bufferevent_data_cb writecb;
	bufferevent_event_cb errorcb;

	/** 高低水位 */
	struct event_watermark wm_read;
	struct event_watermark wm_write;

	void* cbarg;
};

struct bufferevent_private {
	struct bufferevent bev;
	int refcnt;
	/** 延迟回调 */
	struct event_callback deferred;
	enum bufferevent_options options;

	short eventcb_pending;
	unsigned readcb_pending : 1;
	unsigned writecb_pending : 1;
	unsigned connecting : 1;

	uint16_t read_suspended;
	uint16_t write_suspended;

};

#define EVBUFFER_CB_ENABLED 1

#define EVBUFFER_CB_OBSOLETE	       0x00040000

#define BEV_UPCAST(b) EVUTIL_UPCAST((b), struct bufferevent_private, bev)

#define evbuffer_set_flags(evbuffer, flag)	(evbuffer)->flags |= flag

#define evbuffer_get_length(buffer)		(buffer)->total_len



/** 申请socket的缓存事件 */
struct bufferevent* bufferevent_socket_new(struct event_base* base, evutil_socket_t fd, int options);

/** 初始化缓存事件 */
int bufferevent_init_common_(struct bufferevent_private*, struct event_base*, const struct bufferevent_ops*, enum bufferevent_options options);

/** 初始化缓存区 */
struct evbuffer* evbuffer_new(void);

void evbuffer_free(struct evbuffer* buf);

/** 加入缓存区回调队列 */
struct evbuffer_cb_entry* evbuffer_add_cb(struct evbuffer* buffer, evbuffer_cb_func cb, void* cbarg);

int bufferevent_add_event_(struct event* ev, const struct timeval* tv);

int evbuffer_freeze(struct evbuffer* buf, int at_front);

int evbuffer_unfreeze(struct evbuffer *buf, int at_front);

/** 设置缓存事件的读写回调 */
void bufferevent_setcb(struct bufferevent* bufev,
	bufferevent_data_cb readcb, bufferevent_data_cb writecb,
	bufferevent_event_cb eventcb, void* cbarg);

/** 开启缓冲区X事件 */
int bufferevent_enable(struct bufferevent* bufev, short event);

/** 处理缓冲区X事件 */
int bufferevent_disable(struct bufferevent* bufev, short event);

/** 往缓冲事件写数据 */
int bufferevent_write(struct bufferevent* bufev,
	const void* data, size_t size);

/** 缓存区写字符串 */
int evbuffer_add(struct evbuffer* buf, const void* data, size_t datlen);

void evbuffer_invoke_callbacks_(struct evbuffer* buf);

/** 连接的socket写入传出数据 */
int evbuffer_write_atmost(struct evbuffer *buffer, evutil_socket_t fd,
						  ev_ssize_t howmuch);
/** 将所有chain的字符串合并 */
unsigned char *evbuffer_pullup(struct evbuffer *buf, ev_ssize_t size);

/** 将发送完的字符串删除 */
int evbuffer_drain(struct evbuffer *buf, size_t len);

/** 释放缓冲事件 */
void bufferevent_free(struct bufferevent *bufev);

/** 缓冲为空回调 */
void bufferevent_run_readcb_(struct bufferevent *bufev, int options);

void bufferevent_run_writecb_(struct bufferevent *bufev, int options);

static inline void
bufferevent_trigger_nolock_(struct bufferevent *bufev, short iotype, int options)
{
	if ((iotype & EV_READ) && ((options & BEV_TRIG_IGNORE_WATERMARKS) ||
	    evbuffer_get_length(bufev->input) >= bufev->wm_read.low))
		bufferevent_run_readcb_(bufev, options);
	if ((iotype & EV_WRITE) && ((options & BEV_TRIG_IGNORE_WATERMARKS) ||
	    evbuffer_get_length(bufev->output) <= bufev->wm_write.low))
		bufferevent_run_writecb_(bufev, options);
}

static inline void
evbuffer_chain_free(struct evbuffer_chain* chain)
{
	free(chain);
}

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // !BUFFER_H_INCLUDED_