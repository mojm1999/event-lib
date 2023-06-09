#pragma once
#ifndef BASE_H_INCLUDED_
#define BASE_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <winsock2.h>
#include <hashtable.h>
#include <signal.h>

#ifdef _WIN32
#define evutil_socket_t intptr_t
#define ev_ssize_t SSIZE_T
#else
#define evutil_socket_t int
#define ev_ssize_t ssize_t
#endif

#define EV_MONOT_PRECISE	1
#define EV_MONOT_FALLBACK	2

#define CLOCK_SYNC_INTERVAL 5

#define EVENT_MAX_PRIORITIES 256

/** event_callback */
#define EVLIST_TIMEOUT	    0x01	/** ��ʱ */
#define EVLIST_INSERTED	    0x02	/** �Ѳ��� */
#define EVLIST_ACTIVE	    0x08	/** ��Ծ */
#define EVLIST_INTERNAL	    0x10	/** �ڲ��� */
#define EVLIST_ACTIVE_LATER 0x20
#define EVLIST_FINALIZING   0x40	/** ���� */
#define EVLIST_INIT			0x80	/** �����¼�֮�� */

#define EVLIST_ALL          0xff

/*
 * Tail queue definitions
 */
#define TAILQ_HEAD(name, type)			\
struct name	{						\
	struct type *tqh_first;	/* ָ���һ��Ԫ�� */		\
	struct type **tqh_last;	/* ָ�����Ԫ�ص�nextָ�� */		\
}

#define TAILQ_ENTRY(type)			\
struct {						\
	struct type *tqe_next; /* ָ����һ��Ԫ��*/	\
	struct type **tqe_prev;	/* ָ����һ��Ԫ�ص�nextָ�� */	\
}

/*
* tail queue access methods
*/
#define TAILQ_FIRST(head)			((head)->tqh_first)
#define TAILQ_END(head)				NULL
#define TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#define	TAILQ_EMPTY(head)						\
	(TAILQ_FIRST(head) == TAILQ_END(head))

#define TAILQ_FOREACH(var, head, field)			\
for ((var) = TAILQ_FIRST(head);				\
	 (var) != TAILQ_END(head);						\
	 (var) = TAILQ_NEXT(var, field))	

/** ��ת */
#define TAILQ_LAST(head, headname)			\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#define TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
for((var) = TAILQ_LAST(head, headname);				\
	(var) != TAILQ_END(head);					\
	(var) = TAILQ_PREV(var, headname, field))

/*
 * tail queue functions
 */
#define TAILQ_INIT(head)				\
do {							\
	(head)->tqh_first = NULL;		\
	(head)->tqh_last = &(head)->tqh_first;		\
} while (0)

#define TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} while (0)

#define TAILQ_INSERT_TAIL(head, elm, field)				\
 do {											\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (0)

#define TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} while (0)

#define TAILQ_REMOVE(head, elm, field)				\
do {										\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
			(elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
} while (0)

/*
* List definitions
*/
#define LIST_HEAD(name, type)			\
struct name {					\
	struct type *lh_first;			\
}
#define LIST_ENTRY(type)			\
struct {					\
	struct type *le_next;		\
	struct type **le_prev;				\
}

/*
* list access methods
*/
#define	LIST_FIRST(head)		((head)->lh_first)
#define	LIST_END(head)			NULL
#define	LIST_EMPTY(head)		(LIST_FIRST(head) == LIST_END(head))
#define	LIST_NEXT(elm, field)		((elm)->field.le_next)

#define LIST_FOREACH(var, head, field)					\
for((var) = LIST_FIRST(head);					\
	(var)!= LIST_END(head);					\
	(var) = LIST_NEXT(var, field))

/*
* list functions
*/
#define	LIST_INIT(head) do {						\
	LIST_FIRST(head) = LIST_END(head);				\
} while (0)

#define LIST_INSERT_HEAD(head, elm, field) do {				\
	if (((elm)->field.le_next = (head)->lh_first) != NULL)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} while (0)

#define LIST_REMOVE(elm, field) do {					\
	if ((elm)->field.le_next != NULL)				\
		(elm)->field.le_next->field.le_prev =			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
} while (0)


/*
* Timeval definitions
*/
#define evutil_timeradd(tvp, uvp, vvp)			\
do {								\
	(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
	(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;		\
	if ((vvp)->tv_usec >= 1000000) {			\
		(vvp)->tv_sec++;				\
		(vvp)->tv_usec -= 1000000;			\
	}								\
} while (0)

#define evutil_timersub(tvp, uvp, vvp)			\
do {								\
	(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
	(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;		\
	if ((vvp)->tv_usec < 0) {				\
		(vvp)->tv_sec--;				\
		(vvp)->tv_usec += 1000000;			\
	}								\
} while (0)

#define evutil_timercmp(tvp, uvp, cmp)			\
(((tvp)->tv_sec == (uvp)->tv_sec) ?			\
((tvp)->tv_usec cmp (uvp)->tv_usec) :		\
((tvp)->tv_sec cmp (uvp)->tv_sec))

#define	evutil_timerclear(tvp)	(tvp)->tv_sec = (tvp)->tv_usec = 0

/** ƫ���� */
#define evutil_offsetof(type, field) offsetof(type, field)

#define EVUTIL_UPCAST(ptr, type, field)				\
	((type *)(((char*)(ptr)) - evutil_offsetof(type, field)))

void event_set(struct event*, evutil_socket_t, short, void (*)(evutil_socket_t, short, void*), void*);

/** ����ʱ���¼� */
#define evtimer_set(ev, cb, arg)	event_set((ev), -1, 0, (cb), (arg))

#define evtimer_assign(ev, b, cb, arg) \
	event_assign((ev), (b), -1, 0, (cb), (arg))

enum event_method_feature {
	EV_FEATURE_ET = 0x01,
	EV_FEATURE_O1 = 0x02,
	EV_FEATURE_FDS = 0x04,
	EV_FEATURE_EARLY_CLOSE = 0x08
};

enum event_base_config_flag {
	EVENT_BASE_FLAG_NOLOCK = 0x01,
	EVENT_BASE_FLAG_IGNORE_ENV = 0x02,
	EVENT_BASE_FLAG_STARTUP_IOCP = 0x04,
	EVENT_BASE_FLAG_NO_CACHE_TIME = 0x08,
	EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST = 0x10,
	EVENT_BASE_FLAG_PRECISE_TIMER = 0x20
};

struct event_config_entry {
	TAILQ_ENTRY(event_config_entry) next;
	const char *avoid_method;
};

struct event_config {
	TAILQ_HEAD(event_configq, event_config_entry) entries;
	int n_cpus_hint;
	struct timeval max_dispatch_interval;
	int max_dispatch_callbacks;
	int limit_callbacks_after_prio;
	enum event_method_feature require_features;
	enum event_base_config_flag flags;
};

struct eventop {
	const char *name;
	/** ��ʼ��base */
	void *(*init)(struct event_base *);
	/** �����¼� */
	int (*add)(struct event_base *, evutil_socket_t fd, short old, short events, void *fdinfo);
	int (*del)(struct event_base *, evutil_socket_t fd, short old, short events, void *fdinfo);
	int (*dispatch)(struct event_base *, struct timeval *);
	void (*dealloc)(struct event_base *);
	int need_reinit;
	enum event_method_feature features;
	/** ���ⳤ�� */
	size_t fdinfo_len;
};

struct event_change {
	evutil_socket_t fd;
	short old_events;
	uint8_t read_change;
	uint8_t write_change;
	uint8_t close_change;
};

struct event_changelist {
	struct event_change *changes;
	int n_changes;
	int changes_size;
};

struct event_callback {
	TAILQ_ENTRY(event_callback) evcb_active_next;
	short evcb_flags;	/** ״̬��� EVLIST_INIT */
	uint8_t evcb_pri;	/** ���ȼ� nactivequeues >> 2 */
	uint8_t evcb_closure;	/** �ر���Ϊ EV_CLOSURE_EVENT */
	union {
		void (*evcb_callback)(evutil_socket_t, short, void *);	/** �ص����� */
		void (*evcb_selfcb)(struct event_callback *, void*);
		void (*evcb_evfinalize)(struct event *, void *);
		void (*evcb_cbfinalize)(struct event_callback *, void *);
	} evcb_cb_union;
	void *evcb_arg;	/** �ص�ʵ�� */
};

#define EV_CLOSURE_EVENT			0	/** ���� */
#define EV_CLOSURE_EVENT_SIGNAL		1	/** �ź� */
#define EV_CLOSURE_EVENT_PERSIST	2	/** �־� */
#define EV_CLOSURE_CB_SELF			3
#define EV_CLOSURE_CB_FINALIZE		4
#define EV_CLOSURE_EVENT_FINALIZE	5
#define EV_CLOSURE_EVENT_FINALIZE_FREE 6


TAILQ_HEAD(evcallback_list, event_callback);

struct event {
	evutil_socket_t ev_fd;	/** �ļ������� -1 */
	struct event_base *ev_base;	/** �󶨵�event_base */
	struct event_callback ev_evcallback; /** �ص��ṹ�� */
	union {
		TAILQ_ENTRY(event) ev_next_with_common_timeout;
		int min_heap_idx;	/** ʱ��С��������λ -1 */
	} ev_timeout_pos;
	union {
		struct {
			LIST_ENTRY(event) ev_io_next;
			struct timeval ev_timeout;	/**  0 */
		} ev_io;
		struct {
			LIST_ENTRY(event) ev_signal_next;
			short ev_ncalls;
			short *ev_pncalls;
		} ev_signal;
	} ev_;
	short ev_events;	/** �¼����� 0 (EV_READ) */
	short ev_res;		/** �ص�������� 0 (EV_TIMEOUT) */
	struct timeval ev_timeout;	/** ��ʱʱ�� */
};

#define ev_callback ev_evcallback.evcb_cb_union.evcb_callback
#define ev_arg ev_evcallback.evcb_arg
#define ev_flags ev_evcallback.evcb_flags
#define ev_closure ev_evcallback.evcb_closure
#define ev_pri ev_evcallback.evcb_pri

#define ev_ncalls	ev_.ev_signal.ev_ncalls
#define ev_pncalls	ev_.ev_signal.ev_pncalls

#define ev_io_next		ev_.ev_io.ev_io_next
#define ev_io_timeout	ev_.ev_io.ev_timeout
#define ev_signal_next	ev_.ev_signal.ev_signal_next

inline evutil_socket_t
event_get_fd(const struct event* ev)	{ return ev->ev_fd; }

inline struct event_base*
event_get_base(const struct event* ev)	{ return ev->ev_base; }

LIST_HEAD(event_dlist, event);
TAILQ_HEAD(event_list, event);

typedef void (*ev_sighandler_t)(int);

struct evsig_info {
	/** ���¼� */
	struct event ev_signal;
	/** ��дfd */
	evutil_socket_t ev_signal_pair[2];
	int ev_signal_added;
	/** �¼����� */
	int ev_n_signals_added;
#ifdef EVENT__HAVE_SIGACTION
	struct sigaction **sh_old;
#else
	/** �źŻص��������� */
	ev_sighandler_t **sh_old;
#endif
	int sh_old_max;
};

#define EV_TIMEOUT	0x01
#define EV_READ		0x02
#define EV_WRITE	0x04
#define EV_SIGNAL	0x08

#define EV_PERSIST	0x10
#define EV_ET		0x20
#define EV_FINALIZE 0x40
#define EV_CLOSED	0x80

int evsig_init_(struct event_base *);

void evsig_set_base_(struct event_base* base);

int evsig_set_handler_(struct event_base* base, int evsignal,
	void (*fn)(int));

#define evsignal_new(b, x, cb, arg)				\
	event_new((b), (x), EV_SIGNAL|EV_PERSIST, (cb), (arg))

struct evmap_signal {
	struct event_dlist events;
};

struct evmap_io {
	struct event_dlist events;
	/** ���¼����� */
	uint16_t nread;
	uint16_t nwrite;
	uint16_t nclose;
};

struct event_map_entry {
	HT_ENTRY(event_map_entry) map_node;
	evutil_socket_t fd;
	union {
		struct evmap_io evmap_io;	/** ��¼���� */
	} ent;
};

HT_HEAD(event_io_map, event_map_entry);

/** ��ʼ����ϣ�� */
void evmap_io_initmap_(struct event_io_map *ctx);

/** ����IO�¼��������ϣ�� */
int evmap_io_add_(struct event_base *base, evutil_socket_t fd, struct event *ev);

/** ɾ��IO */
int evmap_io_del_(struct event_base* base, evutil_socket_t fd, struct event* ev);

/** ����IO */
void evmap_io_active_(struct event_base* base, evutil_socket_t fd, short events);

void *evmap_io_get_fdinfo_(struct event_io_map *ctx, evutil_socket_t fd);

struct event_signal_map {
	void **entries;
	int nentries;
};

int evmap_signal_add_(struct event_base* base, int signum, struct event* ev);

void evmap_signal_initmap_(struct event_signal_map *ctx);
void evmap_signal_active_(struct event_base* base, evutil_socket_t signum, int ncalls);

#define NSIG            23

#ifdef _WIN32
typedef ULONGLONG (WINAPI *ev_GetTickCount_func)(void);

typedef void (WINAPI *GetSystemTimePreciseAsFileTime_fn_t) (LPFILETIME);
#endif

struct evutil_monotonic_timer {

#ifdef _WIN32
	/** ϵͳ��������ĺ����� */
	ev_GetTickCount_func GetTickCount64_fn;
	ev_GetTickCount_func GetTickCount_fn;
	/** ��ʱ�� ��ʼ��ʱ�ĺ����� */
	uint64_t first_tick;
	uint64_t last_tick_count;
	/** ��׼���� ��ʼ������ֵ */
	uint64_t first_counter;
	uint64_t adjust_tick_count;
	/** ��׼���� ������� ΢��us */
	double usec_per_count;
	int use_performance_counter;
#endif
	/** У׼��ʱ�� */
	struct timeval adjust_monotonic_clock;
	/** ���һ�ε���ʱ�� */
	struct timeval last_time;
};

/** һ���ĳ�ʱʱ���Ŷ��У�����С���ѵ�ѹ�� */
struct common_timeout_list {
	struct event_list events;
	struct timeval duration;
	struct event timeout_event;
	struct event_base* base;
};

struct evutil_weakrand_state {
	uint32_t seed;
};

struct event_once {
	LIST_ENTRY(event_once) next_once;
	struct event ev;
	void (*cb)(evutil_socket_t, short, void *);
	void *arg;
};

#ifdef _WIN32
typedef BOOL(WINAPI* AcceptExPtr)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* ConnectExPtr)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef void (WINAPI* GetAcceptExSockaddrsPtr)(PVOID, DWORD, DWORD, DWORD, LPSOCKADDR*, LPINT, LPSOCKADDR*, LPINT);

struct win32_extension_fns {
	AcceptExPtr AcceptEx;
	ConnectExPtr ConnectEx;
	GetAcceptExSockaddrsPtr GetAcceptExSockaddrs;
};

struct event_iocp_port {
	HANDLE port;
	CRITICAL_SECTION lock;
	short n_threads;
	short shutdown;
	long ms;
	HANDLE *threads;
	short n_live_threads;
	HANDLE *shutdownSemaphore;
};

typedef void (*iocp_callback)(struct event_overlapped*, uintptr_t, ev_ssize_t, int success);

struct event_overlapped {
	OVERLAPPED overlapped;
	iocp_callback cb;
};
#endif

#include <minheap.h>

#define EVLOOP_ONCE	0x01
#define EVLOOP_NONBLOCK	0x02
#define EVLOOP_NO_EXIT_ON_EMPTY 0x04

#define EVENT_DEL_NOBLOCK 0
#define EVENT_DEL_AUTOBLOCK 2

#define EVENT_DEL_EVEN_IF_FINALIZING 3

struct event_base {
	/** ��˹���ӿ� */
	const struct eventop *evsel;
	/** win32op���� */
	void *evbase;
	/** ��ʱ������ */
	struct evutil_monotonic_timer monotonic_timer;
	/** �����µĶ�ʱ������ */
	time_t last_updated_clock_diff;
	/** ϵͳ����ʱ����� */
	struct timeval tv_clock_diff;
	/** ����������� */
	struct evcallback_list *activequeues;
	/** �������� */
	int nactivequeues;
	/** ʱ����С�� */
	struct min_heap timeheap;
	/** ��ϣ�����IO */
	struct event_io_map io;
	/** ��������ź� */
	struct event_signal_map sigmap;
	/** �źŶ�·���ýӿ� */
	const struct eventop *evsigsel;
	/** 256����ʱʱ���Ķ��� */
	struct common_timeout_list **common_timeout_queues;
	/** �ڲ��¼����� */
	int event_count;
	int event_count_max;
	/** ��Ծ�¼����� */
	int event_count_active;
	int event_count_active_max;
	/** �Ƿ�����loop���� */
	int running_loop;
	/** ��ɴ������ֹѭ�� */
	int event_gotterm;
	/** ֪ͨ���̹߳��� */
	int is_notify_pending;
	/** ���Ѻ��� */
	int (*th_notify_fn)(struct event_base *base);
	/** dispatchʱ�仺�� */
	struct timeval tv_cache;
	/** �´�Ӧ�ü�����¼��б� */
	struct evcallback_list active_later_queue;
	/** ����ͨ���ź� */
	struct evsig_info sig;
	struct event_changelist changelist;
	int virtual_event_count;
	int virtual_event_count_max;
	int event_break;
	int event_continue;
	/** ���ڴ���Ķ��� */
	int event_running_priority;
	int n_deferreds_queued;
	int n_common_timeouts;
	/** ����commonʱ���������� */
	int n_common_timeouts_allocated;
	struct event_callback *current_event;
#ifdef _WIN32
	struct event_iocp_port *iocp;
#endif
	/** ����ĳЩ���� */
	enum event_base_config_flag flags;
	struct timeval max_dispatch_time;
	int max_dispatch_callbacks;
	int limit_callbacks_after_prio;
	evutil_socket_t th_notify_fd[2];
	struct event th_notify;
	struct evutil_weakrand_state weakrand_seed;
	/** һ�����¼����� */
	LIST_HEAD(once_event_list, event_once) once_events;
};

/** �����õ�base */
struct event_base *event_base_new(void);

/** û�����õ�base */
struct event_base* event_init(void);

/** ����event_config���󣬸����ÿ��Ա���ĳЩ�¼�֪ͨ���� */
struct event_config *event_config_new(void);

/** ����event_config���� */
void event_config_free(struct event_config* cfg);

/** ����event_base */
struct event_base *event_base_new_with_config(const struct event_config *);

/** �ͷ�event_base */
void event_base_free(struct event_base *);

/** ��event_base���ö�ʱ������ */
int evutil_configure_monotonic_time_(struct evutil_monotonic_timer *mt, int flags);

/** ��ȡ��ʱ������ʱ�䣬��ȷ��΢�� */
int evutil_gettime_monotonic_(struct evutil_monotonic_timer *mt, struct timeval *tv);

/** ��ȡUnixʱ�������ȷ��΢�� */
int evutil_gettimeofday(struct timeval *tv, struct timezone *tz);

/** ת������ */
long evutil_tv_to_msec_(const struct timeval* tv);

/** �ص�����ָ�� */
typedef void (*event_callback_fn)(evutil_socket_t, short, void *);

/** ��ʼ���¼� */
int event_assign(struct event*, struct event_base*, evutil_socket_t, short, event_callback_fn, void*);

/** �����ڴ沢��ʼ���¼� */
struct event* event_new(struct event_base*, evutil_socket_t, short, event_callback_fn, void*);

/** �����¼� */
int event_add(struct event* ev, const struct timeval* timeout);

/** �����߼� */
int event_add_nolock_(struct event* ev, const struct timeval* tv, int tv_is_absolute);

/** ѭ�������¼� */
int event_dispatch(void);

/** ���δ��� */
int event_base_dispatch(struct event_base*);

/** �ȴ��¼���Ϊ�״̬��Ȼ���������ǵĻص� */
int event_base_loop(struct event_base*, int);

/** ѭ���˳� */
int event_base_loopexit(struct event_base*, const struct timeval*);

/** һ�����¼� */
int event_base_once(struct event_base*, evutil_socket_t, short, event_callback_fn, void*, const struct timeval*);

/** EVENT_DEL_AUTOBLOCKɾ�� */
int event_del(struct event*);

/** ɾ���¼� */
int event_del_nolock_(struct event* ev, int blocking);

/** �ͷ��¼� **/
void event_free(struct event*);

/** ת��Ծ�¼� */
void event_active_nolock_(struct event* ev, int res, short count);

/** �ص������Ծ�¼� */
int event_callback_activate_nolock_(struct event_base*, struct event_callback*);

/** ������ͬ�ĳ�ʱʱ�������ϱ�� */
const struct timeval* event_base_init_common_timeout(struct event_base* base,
	const struct timeval* duration);

/** ����ѭ�� */
int event_base_loopbreak(struct event_base*);

typedef void (*deferred_cb_fn)(struct event_callback*, void*);

/** �ӳٻص�������ʼ�� */
void event_deferred_cb_init_(struct event_callback*, uint8_t, deferred_cb_fn, void*);

int event_callback_cancel_nolock_(struct event_base* base,
	struct event_callback* evcb, int even_if_finalizing);

int event_pending(const struct event* ev, short events, struct timeval* tv);


int evutil_make_internal_pipe_(evutil_socket_t fd[2]);

void event_changelist_init_(struct event_changelist *changelist);

int event_base_priority_init(struct event_base *, int);

int	event_priority_set(struct event*, int);

int evutil_socketpair(int d, int type, int protocol, evutil_socket_t sv[2]);

int evutil_closesocket(evutil_socket_t sock);

uint32_t evutil_weakrand_seed_(struct evutil_weakrand_state* state, uint32_t seed);

int32_t evutil_weakrand_range_(struct evutil_weakrand_state* seed, int32_t top);


#define EVUTIL_SOCK_NONBLOCK	0x4000000

#define LEV_OPT_LEAVE_SOCKETS_BLOCKING	(1u<<0)
#define LEV_OPT_CLOSE_ON_FREE		(1u<<1)
#define LEV_OPT_DISABLED			(1u<<5)

/** socket�ص� */
typedef void (*evconnlistener_cb)(struct evconnlistener*, evutil_socket_t, struct sockaddr*, int socklen, void*);

typedef void (*evconnlistener_errorcb)(struct evconnlistener*, void*);

/** ����socket */
evutil_socket_t evutil_socket_(int domain, int type, int protocol);

/** �������� */
evutil_socket_t evutil_accept4_(evutil_socket_t sockfd, struct sockaddr* addr,
	int* addrlen, int flags);

struct evconnlistener* evconnlistener_new_bind(struct event_base* base,
	evconnlistener_cb cb, void* ptr, unsigned flags, int backlog,
	const struct sockaddr* sa, int socklen);

struct evconnlistener* evconnlistener_new(struct event_base* base,
	evconnlistener_cb cb, void* ptr, unsigned flags, int backlog,
	evutil_socket_t fd);

int evconnlistener_enable(struct evconnlistener* lev);

void evconnlistener_free(struct evconnlistener* lev);

#ifdef _WIN32
HMODULE evutil_load_windows_system_library_(const TCHAR *library_name);

int event_base_start_iocp_(struct event_base *base, int n_cpus);

struct event_iocp_port *event_iocp_port_launch_(int n_cpus);

const struct win32_extension_fns* event_get_win32_extension_fns_(void);

int event_iocp_port_associate_(struct event_iocp_port* port, evutil_socket_t fd,
	uintptr_t key);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BASE_H_INCLUDED_ */