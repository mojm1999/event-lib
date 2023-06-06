#include <tchar.h>
#include <process.h>
#include <base.h>

#ifdef _WIN32
extern const struct eventop win32ops;
#endif

static const struct eventop* eventops[] = {
#ifdef EVENT__HAVE_EPOLL
	&epollops,
#endif
#ifdef _WIN32
	&win32ops,
#endif
};

struct event_base* event_global_current_base_ = NULL;
#define current_base event_global_current_base_

struct event_config *
event_config_new(void)
{
	struct event_config *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL)
		return (NULL);
	TAILQ_INIT(&cfg->entries);
	cfg->max_dispatch_interval.tv_sec = -1;
	cfg->max_dispatch_callbacks = INT_MAX;
	cfg->limit_callbacks_after_prio = 1;
	return (cfg);
}

static void
event_config_entry_free(struct event_config_entry* entry)
{
	if (entry->avoid_method != NULL) {
		free((char*)entry->avoid_method);
	}
	free(entry);
}

void
event_config_free(struct event_config* cfg)
{
	struct event_config_entry* entry;

	while ((entry = TAILQ_FIRST(&cfg->entries)) != NULL) {
		TAILQ_REMOVE(&cfg->entries, entry, next);
		event_config_entry_free(entry);
	}
	free(cfg);
}

struct event_base*
event_init(void)
{
	struct event_base* base = event_base_new_with_config(NULL);
	if (base == NULL) {
		return NULL;
	}
	current_base = base;
	return (base);
}

static int
gettime(struct event_base* base, struct timeval* tp)
{
	if (base->tv_cache.tv_sec) {
		*tp = base->tv_cache;
		return (0);
	}
	if (evutil_gettime_monotonic_(&base->monotonic_timer, tp) == -1) {
		return -1;
	}
	if (base->last_updated_clock_diff + CLOCK_SYNC_INTERVAL < tp->tv_sec) {
		struct timeval tv;
		evutil_gettimeofday(&tv, NULL);
		evutil_timersub(&tv, tp, &base->tv_clock_diff);
		base->last_updated_clock_diff = tp->tv_sec;
	}
	return 0;
}

static int
event_config_is_avoided_method(const struct event_config* cfg, const char* method)
{
	struct event_config_entry* entry;
	TAILQ_FOREACH(entry, &cfg->entries, next) {
		if (entry->avoid_method != NULL && strcmp(entry->avoid_method, method) == 0) {
			return (1);
		}
	}
	return (0);
}

struct event_base *
event_base_new_with_config(const struct event_config* cfg)
{
	struct event_base *base;
	if ((base = calloc(1, sizeof(struct event_base))) == NULL) {
		return NULL;
	}
	if (cfg) {
		base->flags = cfg->flags;
	}
	int should_check_environment =
		!(cfg && (cfg->flags & EVENT_BASE_FLAG_IGNORE_ENV));
	{
		int precise_time = 
			cfg && (cfg->flags & EVENT_BASE_FLAG_PRECISE_TIMER);
		if (should_check_environment && !precise_time) {
			precise_time = getenv("EVENT_PRECISE_TIMER") != NULL;
			if (precise_time) {
				base->flags |= EVENT_BASE_FLAG_PRECISE_TIMER;
			}
		}
		int flags = precise_time ? EV_MONOT_PRECISE : 0;
		evutil_configure_monotonic_time_(&base->monotonic_timer, flags);
		struct timeval tmp;
		gettime(base, &tmp);
	}
	min_heap_ctor_(&base->timeheap);
	base->sig.ev_signal_pair[0] = -1;
	base->sig.ev_signal_pair[1] = -1;
	base->th_notify_fd[0] = -1;
	base->th_notify_fd[1] = -1;
	TAILQ_INIT(&base->active_later_queue);
	evmap_io_initmap_(&base->io);
	evmap_signal_initmap_(&base->sigmap);
	event_changelist_init_(&base->changelist);
	if (cfg) {
		memcpy(&base->max_dispatch_time, &cfg->max_dispatch_interval, sizeof(struct timeval));
		base->limit_callbacks_after_prio = cfg->limit_callbacks_after_prio;
	}
	else {
		base->max_dispatch_time.tv_sec = -1;
		base->limit_callbacks_after_prio = 1;
	}
	if (cfg && cfg->max_dispatch_callbacks >= 0) {
		base->max_dispatch_callbacks = cfg->max_dispatch_callbacks;
	}
	else {
		base->max_dispatch_callbacks = INT_MAX;
	}
	if (base->max_dispatch_callbacks == INT_MAX && base->max_dispatch_time.tv_sec == -1) {
		base->limit_callbacks_after_prio = INT_MAX;
	}
	base->evbase = NULL;
	for (int i = 0; eventops[i] && !base->evbase; ++i) {
		if (cfg != NULL) {
			if (event_config_is_avoided_method(cfg, eventops[i]->name)) {
				continue;
			}
			if ((eventops[i]->features & cfg->require_features) != cfg->require_features) {
				continue;
			}
		}
		base->evsel = eventops[i];
		base->evbase = base->evsel->init(base);
	}
	if (base->evbase == NULL) {
		base->evsel = NULL;
		event_base_free(base);
		return NULL;
	}
	if (event_base_priority_init(base, 1) < 0) {
		event_base_free(base);
		return NULL;
	}
#ifdef _WIN32
	if (cfg && (cfg->flags & EVENT_BASE_FLAG_STARTUP_IOCP)) {
		event_base_start_iocp_(base, cfg->n_cpus_hint);
	}
#endif
	return (base);
}

struct event_base *
event_base_new(void)
{
	struct event_base *base = NULL;
	struct event_config *cfg = event_config_new();
	if (cfg) {
		base = event_base_new_with_config(cfg);
		event_config_free(cfg);
	}
	return base;
}

static int
event_is_method_disabled(const char* name)
{
	return getenv(name) != NULL;
}

static uint64_t
evutil_GetTickCount_(struct evutil_monotonic_timer* base)
{
	if (base->GetTickCount64_fn) {
		return base->GetTickCount64_fn();
	}
	else if (base->GetTickCount_fn) {
		uint64_t v = base->GetTickCount_fn();
		return (DWORD)v | ((v >> 18) & 0xFFFFFFFF00000000);
	}
	else {
		DWORD ticks = GetTickCount();
		if (ticks < base->last_tick_count) {
			base->adjust_tick_count += ((uint64_t)1) << 32;
		}
		base->last_tick_count = ticks;
		return ticks + base->adjust_tick_count;
	}
}

int
evutil_configure_monotonic_time_(struct evutil_monotonic_timer* base, int flags)
{
	memset(base, 0, sizeof(*base));
	const int precise = flags & EV_MONOT_PRECISE;
	const int fallback = flags & EV_MONOT_FALLBACK;
	HANDLE h = evutil_load_windows_system_library_(TEXT("kernel32.dll"));
	if (h != NULL && !fallback) {
		base->GetTickCount64_fn = (ev_GetTickCount_func)GetProcAddress(h, "GetTickCount64");
		base->GetTickCount_fn = (ev_GetTickCount_func)GetProcAddress(h, "GetTickCount");
	}
	if (precise && !fallback) {
		LARGE_INTEGER freq;
		/** 每秒的计数次数 */
		if (QueryPerformanceFrequency(&freq)) {
			/** 计数时间间隔，单位微秒us */
			base->usec_per_count = 1.0e6 / freq.QuadPart;
			LARGE_INTEGER counter;
			QueryPerformanceCounter(&counter);
			/** 计数器当前值，总计数 */
			base->first_counter = counter.QuadPart;
			base->use_performance_counter = 1;
		}
	}
	base->first_tick = base->last_tick_count = evutil_GetTickCount_(base);
	return 0;
}

static inline int64_t
abs64(int64_t i)
{
	return i < 0 ? -i : i;
}

static void
adjust_monotonic_time(struct evutil_monotonic_timer *base, struct timeval *tv)
{
	evutil_timeradd(tv, &base->adjust_monotonic_clock, tv);
	if (evutil_timercmp(tv, &base->last_time, < )) {
		struct timeval adjust;
		evutil_timersub(&base->last_time, tv, &adjust);
		evutil_timeradd(&adjust, &base->adjust_monotonic_clock,
			&base->adjust_monotonic_clock);
		*tv = base->last_time;
	}
	base->last_time = *tv;
}

int
evutil_gettime_monotonic_(struct evutil_monotonic_timer* base, struct timeval* tp)
{
	uint64_t ticks = evutil_GetTickCount_(base);
	if (base->use_performance_counter) {
		LARGE_INTEGER counter;
		QueryPerformanceCounter(&counter);
		int64_t counter_elapsed = (int64_t)(counter.QuadPart - base->first_counter);
		int64_t ticks_elapsed = ticks - base->first_tick;
		int64_t counter_usec_elapsed = (int64_t)(counter_elapsed * base->usec_per_count);
		if (abs64(ticks_elapsed * 1000 - counter_usec_elapsed) > 1000000) {
			counter_usec_elapsed = ticks_elapsed * 1000;
			base->first_counter = (uint64_t) (counter.QuadPart - counter_usec_elapsed / base->usec_per_count);
		}
		tp->tv_sec = (time_t) (counter_usec_elapsed / 1000000);
		tp->tv_usec = counter_usec_elapsed % 1000000;
	}
	else {
		tp->tv_sec = (time_t) (ticks / 1000);
		tp->tv_usec = (ticks % 1000) * 1000;
	}
	adjust_monotonic_time(base, tp);
	return 0;
}

static inline unsigned
hashsocket(struct event_map_entry* e)
{
	unsigned h = (unsigned)e->fd;
	h += (h >> 2) | (h << 30);
	return h;
}

static inline int
eqsocket(struct event_map_entry* e1, struct event_map_entry* e2)
{
	return e1->fd == e2->fd;
}

HT_PROTOTYPE(event_io_map, event_map_entry, map_node, hashsocket, eqsocket)
HT_GENERATE(event_io_map, event_map_entry, map_node, hashsocket, eqsocket,
	0.5, malloc, realloc, free)

#define GET_IO_SLOT(x, map, slot, type)					\
do {								\
	struct event_map_entry key_, *ent_;			\
	key_.fd = slot;						\
	ent_ = HT_FIND(event_io_map, map, &key_);		\
	(x) = ent_ ? &ent_->ent.type : NULL;			\
} while (0);

/** 结果，哈希表，fd，实际类型，构造函数，额外长度 */
#define GET_IO_SLOT_AND_CTOR(x, map, slot, type, ctor, fdinfo_len)	\
do {								\
	struct event_map_entry key_, *ent_;			\
	key_.fd = slot;						\
	HT_FIND_OR_INSERT_(event_io_map, map_node, hashsocket, map, \
		event_map_entry, &key_, ptr,			\
		{							\
			ent_ = *ptr;				\
		},							\
		{							\
			ent_ = calloc(1,sizeof(struct event_map_entry)+fdinfo_len); \
			if (ent_ == NULL)		\
				return (-1);			\
			ent_->fd = slot;				\
			(ctor)(&ent_->ent.type);			\
			HT_FOI_INSERT_(map_node, map, &key_, ent_, ptr) \
		});					\
	(x) = &ent_->ent.type;					\
} while (0)

void
evmap_io_initmap_(struct event_io_map *ctx)
{
	HT_INIT(event_io_map, ctx);
}

static void
evmap_io_init(struct evmap_io* entry)
{
	LIST_INIT(&entry->events);
	entry->nread = 0;
	entry->nwrite = 0;
	entry->nclose = 0;
}

int
evmap_io_add_(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
	if (fd < 0)
		return 0;

	/** 主角 */
	struct evmap_io* ctx = NULL;

	struct event_io_map* io = &base->io;
	const struct eventop* evsel = base->evsel;
	/** 找到哈希找位置，构造IO事件 */
	GET_IO_SLOT_AND_CTOR(ctx, io, fd, evmap_io, evmap_io_init,
		evsel->fdinfo_len);

	int nread, nwrite, nclose;
	nread = ctx->nread;
	nwrite = ctx->nwrite;
	nclose = ctx->nclose;
	short res = 0, old = 0;
	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;
	if (nclose)
		old |= EV_CLOSED;

	if (ev->ev_events & EV_READ) {
		if (++nread == 1)
			res |= EV_READ;
	}
	if (ev->ev_events & EV_WRITE) {
		if (++nwrite == 1)
			res |= EV_WRITE;
	}
	if (ev->ev_events & EV_CLOSED) {
		if (++nclose == 1)
			res |= EV_CLOSED;
	}

	int retval = 0;
	/** fd第一次要加入IO多路复用 */
	if (res) {
		void *extra = ((char*)ctx) + sizeof(struct evmap_io);
		if (evsel->add(base, ev->ev_fd, old, (ev->ev_events & EV_ET) | res, extra) == -1)
			return -1;
		retval = 1;
	}

	ctx->nread = (uint16_t)nread;
	ctx->nwrite = (uint16_t)nwrite;
	ctx->nclose = (uint16_t)nclose;
	LIST_INSERT_HEAD(&ctx->events, ev, ev_io_next);

	return retval;
}

int
evmap_io_del_(struct event_base* base, evutil_socket_t fd, struct event* ev)
{
	if (fd < 0)
		return 0;

	struct evmap_io* ctx = NULL;
	struct event_io_map* io = &base->io;
	GET_IO_SLOT(ctx, io, fd, evmap_io);

	int nread, nwrite, nclose, retval = 0;
	nread = ctx->nread;
	nwrite = ctx->nwrite;
	nclose = ctx->nclose;
	short res = 0, old = 0;
	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;
	if (nclose)
		old |= EV_CLOSED;

	if (ev->ev_events & EV_READ) {
		if (--nread == 0)
			res |= EV_READ;
	}
	if (ev->ev_events & EV_WRITE) {
		if (--nwrite == 0)
			res |= EV_WRITE;
	}
	if (ev->ev_events & EV_CLOSED) {
		if (--nclose == 0)
			res |= EV_CLOSED;
	}

	const struct eventop* evsel = base->evsel;
	if (res) {
		void* extra = ((char*)ctx) + sizeof(struct evmap_io);
		if (evsel->del(base, ev->ev_fd, old, (ev->ev_events & EV_ET) | res, extra) == -1) {
			retval = -1;
		}
		else {
			retval = 1;
		}
	}

	ctx->nread = nread;
	ctx->nwrite = nwrite;
	ctx->nclose = nclose;
	LIST_REMOVE(ev, ev_io_next);

	return (retval);
}

void
evmap_io_active_(struct event_base* base, evutil_socket_t fd, short events)
{
	struct event_io_map* io = &base->io;
	struct evmap_io* ctx;
	GET_IO_SLOT(ctx, io, fd, evmap_io);
	if (NULL == ctx)
		return;

	struct event* ev;
	LIST_FOREACH(ev, &ctx->events, ev_io_next) {
		if (ev->ev_events & (events & ~EV_ET))
			event_active_nolock_(ev, ev->ev_events & events, 1);
	}
}

static int
evmap_make_space(struct event_signal_map* map, int slot, int msize)
{
	if (map->nentries <= slot) {
		int nentries = map->nentries ? map->nentries : 32;
		void** tmp;

		if (slot > INT_MAX / 2)
			return -1;

		while (nentries <= slot)
			nentries <<= 1;

		if (nentries > INT_MAX / msize)
			return -1;

		tmp = (void**)realloc(map->entries, nentries * msize);
		if (tmp == NULL)
			return -1;

		memset(&tmp[map->nentries], 0,
			(nentries - map->nentries) * msize);

		map->nentries = nentries;
		map->entries = tmp;
	}

	return 0;
}

#define GET_SIGNAL_SLOT(x, map, slot, type)			\
	(x) = (struct type *)((map)->entries[slot])

#define GET_SIGNAL_SLOT_AND_CTOR(x, map, slot, type, ctor, fdinfo_len)	\
do {								\
	if ((map)->entries[slot] == NULL) {			\
		(map)->entries[slot] =				\
			calloc(1,sizeof(struct type)+fdinfo_len); \
		if ((map)->entries[slot] == NULL) \
			return -1;				\
		(ctor)((struct type *)(map)->entries[slot]);	\
	}							\
	(x) = (struct type *)((map)->entries[slot]);		\
} while (0)

static void
evmap_signal_init(struct evmap_signal* entry)
{
	LIST_INIT(&entry->events);
}

int
evmap_signal_add_(struct event_base* base, int sig, struct event* ev)
{
	if (sig < 0 || sig >= NSIG)
		return -1;

	struct event_signal_map* map = &base->sigmap;
	/** 信号值对应数组索引 */
	if (sig >= map->nentries) {
		if (evmap_make_space(map, sig, sizeof(struct evmap_signal*)) == -1)
			return -1;
	}

	struct evmap_signal* ctx = NULL;
	/** 对应数组位置上构造节点 */
	GET_SIGNAL_SLOT_AND_CTOR(ctx, map, sig, evmap_signal, evmap_signal_init,
		base->evsigsel->fdinfo_len);

	const struct eventop* evsel = base->evsigsel;
	/** 第一次注册该信号事件，调用IO多路复用 */
	if (LIST_EMPTY(&ctx->events)) {
		if (evsel->add(base, ev->ev_fd, 0, EV_SIGNAL, NULL) == -1)
			return -1;
	}

	LIST_INSERT_HEAD(&ctx->events, ev, ev_signal_next);

	return 1;
}

int
evmap_signal_del_(struct event_base* base, int sig, struct event* ev)
{
	struct event_signal_map* map = &base->sigmap;
	if (sig < 0 || sig >= map->nentries)
		return -1;

	struct evmap_signal* ctx = NULL;
	GET_SIGNAL_SLOT(ctx, map, sig, evmap_signal);

	LIST_REMOVE(ev, ev_signal_next);

	const struct eventop* evsel = base->evsigsel;
	if (LIST_FIRST(&ctx->events) == NULL) {
		if (evsel->del(base, ev->ev_fd, 0, EV_SIGNAL, NULL) == -1)
			return -1;
	}

	return 1;
}

void
evmap_signal_initmap_(struct event_signal_map *ctx)
{
	ctx->entries = NULL;
	ctx->nentries = 0;
}

#define GET_SIGNAL_SLOT(x, map, slot, type)			\
	(x) = (struct type *)((map)->entries[slot])

void
evmap_signal_active_(struct event_base* base, evutil_socket_t sig, int ncalls)
{
	struct event_signal_map* map = &base->sigmap;
	if (sig < 0 || sig >= map->nentries) {
		return;
	}

	struct evmap_signal* ctx;
	GET_SIGNAL_SLOT(ctx, map, sig, evmap_signal);
	if (!ctx) {
		return;
	}

	struct event* ev;
	LIST_FOREACH(ev, &ctx->events, ev_signal_next) {
		event_active_nolock_(ev, EV_SIGNAL, ncalls);
	}
}

void
event_active_nolock_(struct event* ev, int res, short ncalls)
{
	if (ev->ev_flags & EVLIST_FINALIZING) {
		return;
	}

	switch ((ev->ev_flags & (EVLIST_ACTIVE | EVLIST_ACTIVE_LATER))) {
	default:
	case EVLIST_ACTIVE | EVLIST_ACTIVE_LATER:
		break;
	case EVLIST_ACTIVE:
		ev->ev_res |= res;
		return;
	case EVLIST_ACTIVE_LATER:
		ev->ev_res |= res;
		break;
	case 0:
		ev->ev_res = res;
		break;
	}

	struct event_base* base = ev->ev_base;
	if (ev->ev_pri < base->event_running_priority) {
		base->event_continue = 1;
	}

	if (ev->ev_events & EV_SIGNAL) {
		ev->ev_ncalls = ncalls;
		ev->ev_pncalls = NULL;
	}

	event_callback_activate_nolock_(base, &ev->ev_evcallback);
}

#define DECR_EVENT_COUNT(base,flags)						\
	((base)->event_count -= !((flags) & EVLIST_INTERNAL))

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#define MAX_EVENT_COUNT(var, v) var = MAX(var, v)

#define INCR_EVENT_COUNT(base,flags)							\
do {														\
	((base)->event_count += !((flags) & EVLIST_INTERNAL));			\
	MAX_EVENT_COUNT((base)->event_count_max, (base)->event_count);		\
} while (0)

static void
event_queue_remove_active_later(struct event_base* base, struct event_callback* evcb)
{
	if (!(evcb->evcb_flags & EVLIST_ACTIVE_LATER)) {
		return;
	}
	DECR_EVENT_COUNT(base, evcb->evcb_flags);
	evcb->evcb_flags &= ~EVLIST_ACTIVE_LATER;
	base->event_count_active--;

	TAILQ_REMOVE(&base->active_later_queue, evcb, evcb_active_next);
}

static void
event_queue_insert_active(struct event_base* base, struct event_callback* evcb)
{
	if (evcb->evcb_flags & EVLIST_ACTIVE) {
		return;
	}

	INCR_EVENT_COUNT(base, evcb->evcb_flags);
	evcb->evcb_flags |= EVLIST_ACTIVE;
	base->event_count_active++;
	MAX_EVENT_COUNT(base->event_count_active_max, base->event_count_active);
	TAILQ_INSERT_TAIL(&base->activequeues[evcb->evcb_pri],
		evcb, evcb_active_next);
}

int
event_callback_activate_nolock_(struct event_base* base, struct event_callback* evcb)
{
	if (evcb->evcb_flags & EVLIST_FINALIZING) {
		return 0;
	}

	int r = 1;
	switch (evcb->evcb_flags & (EVLIST_ACTIVE | EVLIST_ACTIVE_LATER)) {
	default:
	case EVLIST_ACTIVE_LATER:
		event_queue_remove_active_later(base, evcb);
		r = 0;
		break;
	case EVLIST_ACTIVE:
		return 0;
	case 0:
		break;
	}

	event_queue_insert_active(base, evcb);
	return r;
}

void
event_changelist_init_(struct event_changelist *changelist)
{
	changelist->changes = NULL;
	changelist->changes_size = 0;
	changelist->n_changes = 0;
}

static void
event_base_free_(struct event_base *base, int run_finalizers)
{

	free(base);
}

void
event_base_free(struct event_base *base)
{
	event_base_free_(base, 1);
}

int
event_base_priority_init(struct event_base* base, int npriorities)
{
	int r = -1;
	if (base->event_count_active || npriorities < 1 || npriorities >= EVENT_MAX_PRIORITIES) {
		goto err;
	}
	if (npriorities == base->nactivequeues) {
		goto ok;
	}
	if (base->nactivequeues) {
		free(base->activequeues);
		base->nactivequeues = 0;
	}
	base->activequeues = (struct evcallback_list *)
		calloc(npriorities, sizeof(struct evcallback_list));
	if (base->activequeues == NULL) {
		goto err;
	}
	base->nactivequeues = npriorities;
	for (int i = 0; i < base->nactivequeues; ++i) {
		TAILQ_INIT(&base->activequeues[i]);
	}
ok:
	r = 0;
err:
	return (r);
}

static struct event_base* evsig_base = NULL;
/** 信号事件数量 */
static int evsig_base_n_signals_added = 0;
/** 写fd */
static evutil_socket_t evsig_base_fd = -1;

static int evsig_add(struct event_base*, evutil_socket_t, short, short, void*);
static int evsig_del(struct event_base*, evutil_socket_t, short, short, void*);

static const struct eventop evsigops = {
	"signal",
	NULL,
	evsig_add,
	evsig_del,
	NULL,
	NULL,
	0, 0, 0
};

static void __cdecl
evsig_handler(int sig)
{
	if (evsig_base == NULL) {
		return ;
	}
	signal(sig, evsig_handler);
	uint8_t msg = sig;
	send(evsig_base_fd, (char*)&msg, 1, 0);
}

int
evsig_set_handler_(struct event_base* base,
	int evsignal, void(__cdecl* handler)(int))
{
	struct evsig_info* sig = &base->sig;
	void* p;
	if (evsignal >= sig->sh_old_max) {
		int new_max = evsignal + 1;
		p = realloc(sig->sh_old, new_max * sizeof(*sig->sh_old));
		if (p == NULL) {
			return (-1);
		}
		memset((char*)p + sig->sh_old_max * sizeof(*sig->sh_old),
			0, (new_max - sig->sh_old_max) * sizeof(*sig->sh_old));
		sig->sh_old_max = new_max;
		sig->sh_old = p;
	}

	sig->sh_old[evsignal] = malloc(sizeof *sig->sh_old[evsignal]);
	if (sig->sh_old[evsignal] == NULL) {
		return (-1);
	}

	ev_sighandler_t sh;
	if ((sh = signal(evsignal, handler)) == SIG_ERR) {
		free(sig->sh_old[evsignal]);
		sig->sh_old[evsignal] = NULL;
		return (-1);
	}
	*sig->sh_old[evsignal] = sh;

	return (0);
}

static int
evsig_add(struct event_base* base, evutil_socket_t evsignal, short old, short events, void* p)
{
	if (evsignal < 0 || evsignal >= NSIG) {
		goto err;
	}
	evsig_base = base;
	struct evsig_info* sig = &base->sig;
	evsig_base_n_signals_added = ++sig->ev_n_signals_added;
	evsig_base_fd = base->sig.ev_signal_pair[1];
	if (evsig_set_handler_(base, (int)evsignal, evsig_handler) == -1) {
		goto err;
	}
	/** 初次绑定信号，将读fd加入IO队列 */
	if (!sig->ev_signal_added) {
		if (event_add_nolock_(&sig->ev_signal, NULL, 0))
			goto err;
		sig->ev_signal_added = 1;
	}
	return (0);

err:
	--evsig_base_n_signals_added;
	--sig->ev_n_signals_added;
	return (-1);
}

static int
evsig_del(struct event_base* base, evutil_socket_t evsignal, short old, short events, void* p)
{
	return 0;
}

static void
evsig_cb(evutil_socket_t fd, short what, void* arg)
{
	struct event_base* base = arg;
	int ncaught[NSIG];
	memset(&ncaught, 0, sizeof(ncaught));

	static char signals[1024];
	ev_ssize_t n;

	while (1) {
#ifdef _WIN32
		n = recv(fd, signals, sizeof(signals), 0);
#else
		n = read(fd, signals, sizeof(signals));
#endif
		if (n == -1) {
			break;
		}
		else if (n == 0) {
			break;
		}
		for (int i = 0; i < n; ++i) {
			uint8_t sig = signals[i];
			if (sig < NSIG)
				ncaught[sig]++;
		}
	}

	for (int i = 0; i < NSIG; ++i) {
		if (ncaught[i]) {
			evmap_signal_active_(base, i, ncaught[i]);
		}
	}
}

int
evsig_init_(struct event_base* base)
{
	if (evutil_make_internal_pipe_(base->sig.ev_signal_pair) == -1) {
		return -1;
	}
	if (base->sig.sh_old) {
		free(base->sig.sh_old);
	}
	base->sig.sh_old = NULL;
	base->sig.sh_old_max = 0;
	event_assign(&base->sig.ev_signal, base, base->sig.ev_signal_pair[0],
		EV_READ | EV_PERSIST, evsig_cb, base);
	base->sig.ev_signal.ev_flags |= EVLIST_INTERNAL;
	event_priority_set(&base->sig.ev_signal, 0);
	base->evsigsel = &evsigops;
	return 0;
}

void
evsig_set_base_(struct event_base* base)
{
	evsig_base = base;
	evsig_base_n_signals_added = base->sig.ev_n_signals_added;
	evsig_base_fd = base->sig.ev_signal_pair[1];
}

int
event_priority_set(struct event* ev, int pri)
{
	if (ev->ev_flags & EVLIST_ACTIVE) {
		return (-1);
	}
	if (pri < 0 || pri >= ev->ev_base->nactivequeues) {
		return (-1);
	}
	ev->ev_pri = pri;
	return (0);
}

static int
evutil_fast_socket_nonblocking(evutil_socket_t fd)
{
#ifdef _WIN32
	unsigned long nonblocking = 1;
	if (ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
		return -1;
	}
#endif
	return 0;
}

int
evutil_make_internal_pipe_(evutil_socket_t fd[2])
{
#ifdef _WIN32
#define LOCAL_SOCKETPAIR_AF AF_INET
#else
#define LOCAL_SOCKETPAIR_AF AF_UNIX
#endif
	if (evutil_socketpair(LOCAL_SOCKETPAIR_AF, SOCK_STREAM, 0, fd) == 0) {
		if (evutil_fast_socket_nonblocking(fd[0]) < 0 ||
			evutil_fast_socket_nonblocking(fd[1]) < 0 ) {
			evutil_closesocket(fd[0]);
			evutil_closesocket(fd[1]);
			fd[0] = fd[1] = -1;
			return -1;
		}
		return 0;
	}
	fd[0] = fd[1] = -1;
	return -1;
}

void
event_set(struct event* ev, evutil_socket_t fd, short events,
	void (*callback)(evutil_socket_t, short, void*), void* arg)
{
	int r;
	r = event_assign(ev, current_base, fd, events, callback, arg);
}

int
event_assign(struct event* ev, struct event_base* base, evutil_socket_t fd, short events, void (*callback)(evutil_socket_t, short, void*), void* arg)
{
	ev->ev_base = base;
	ev->ev_fd = fd;
	ev->ev_events = events;
	ev->ev_res = 0;
	ev->ev_callback = callback;
	ev->ev_arg = arg;
	ev->ev_flags = EVLIST_INIT;
	ev->ev_ncalls = 0;
	ev->ev_pncalls = NULL;

	if (events & EV_SIGNAL) {
		if ((events & (EV_READ | EV_WRITE | EV_CLOSED)) != 0) {
			return -1;
		}
		ev->ev_closure = EV_CLOSURE_EVENT_SIGNAL;
	}
	else {
		if (events & EV_PERSIST) {
			evutil_timerclear(&ev->ev_io_timeout);
			ev->ev_closure = EV_CLOSURE_EVENT_PERSIST;
		}
		else {
			ev->ev_closure = EV_CLOSURE_EVENT;
		}
	}

	min_heap_elem_init_(ev);
	if (base != NULL) {
		ev->ev_pri = base->nactivequeues / 2;
	}

	return  0;
}

struct event *
event_new(struct event_base *base, evutil_socket_t fd, short events, void (*cb)(evutil_socket_t, short, void *), void *arg)
{
	struct event *ev = malloc(sizeof(struct event));
	if (ev == NULL)
		return (NULL);
	if (event_assign(ev, base, fd, events, cb, arg) < 0) {
		free(ev);
		return (NULL);
	}

	return (ev);
}

int
event_add(struct event* ev, const struct timeval* tv)
{
	int res = event_add_nolock_(ev, tv, 0);
	return (res);
}

#define MICROSECONDS_MASK		0x000fffff
#define COMMON_TIMEOUT_MASK     0xf0000000
#define COMMON_TIMEOUT_MAGIC    0x50000000

#define COMMON_TIMEOUT_IDX_MASK 0x0ff00000
#define COMMON_TIMEOUT_IDX_SHIFT 20

#define COMMON_TIMEOUT_IDX(tv) \
	(((tv)->tv_usec & COMMON_TIMEOUT_IDX_MASK)>>COMMON_TIMEOUT_IDX_SHIFT)

static inline int
is_common_timeout(const struct timeval* tv, const struct event_base* base)
{
	if ((tv->tv_usec & COMMON_TIMEOUT_MASK) != COMMON_TIMEOUT_MAGIC)
		return 0;
	int idx = COMMON_TIMEOUT_IDX(tv);
	return idx < base->n_common_timeouts;
}

static inline int
is_same_common_timeout(const struct timeval* tv1, const struct timeval* tv2)
{
	return (tv1->tv_usec & ~MICROSECONDS_MASK) ==
		(tv2->tv_usec & ~MICROSECONDS_MASK);
}

static inline struct common_timeout_list*
get_common_timeout_list(struct event_base* base, const struct timeval* tv)
{
	return base->common_timeout_queues[COMMON_TIMEOUT_IDX(tv)];
}

static void
common_timeout_schedule(struct common_timeout_list* ctl,
	const struct timeval* now, struct event* head)
{
	struct timeval timeout = head->ev_timeout;
	timeout.tv_usec &= MICROSECONDS_MASK;
	event_add_nolock_(&ctl->timeout_event, &timeout, 1);
}

static void
common_timeout_callback(evutil_socket_t fd, short what, void* arg)
{
	struct timeval now;
	struct common_timeout_list* ctl = arg;
	struct event_base* base = ctl->base;
	struct event* ev = NULL;
	gettime(base, &now);
	while (1) {
		ev = TAILQ_FIRST(&ctl->events);
		if (!ev || ev->ev_timeout.tv_sec > now.tv_sec ||
			(ev->ev_timeout.tv_sec == now.tv_sec &&
				(ev->ev_timeout.tv_usec & MICROSECONDS_MASK) > now.tv_usec))
			break;
		event_del_nolock_(ev, EVENT_DEL_NOBLOCK);
		event_active_nolock_(ev, EV_TIMEOUT, 1);
	}
	if (ev)
		common_timeout_schedule(ctl, &now, ev);
}

#define MAX_COMMON_TIMEOUTS 256

const struct timeval*
event_base_init_common_timeout(struct event_base* base,
	const struct timeval* duration)
{
	struct timeval tv;
	if (duration->tv_usec > 1000000) {
		memcpy(&tv, duration, sizeof(struct timeval));
		if (is_common_timeout(duration, base))
			tv.tv_usec &= MICROSECONDS_MASK;
		tv.tv_sec += tv.tv_usec / 1000000;
		tv.tv_usec %= 1000000;
		duration = &tv;
	}
	const struct timeval* result = NULL;
	for (int i = 0; i < base->n_common_timeouts; ++i) {
		const struct common_timeout_list* ctl =
			base->common_timeout_queues[i];
		if (duration->tv_sec == ctl->duration.tv_sec &&
			duration->tv_usec == (ctl->duration.tv_usec & MICROSECONDS_MASK)) {
			result = &ctl->duration;
			goto done;
		}
	}
	if (base->n_common_timeouts == MAX_COMMON_TIMEOUTS) {
		goto done;
	}
	if (base->n_common_timeouts_allocated == base->n_common_timeouts) {
		int n = base->n_common_timeouts < 16 ? 16 :
			base->n_common_timeouts * 2;
		/** 很有可能是从堆重新找新的空闲块 */
		struct common_timeout_list** newqueues = realloc(base->common_timeout_queues,
			n * sizeof(struct common_timeout_queue*));
		if (!newqueues) {
			goto done;
		}
		base->n_common_timeouts_allocated = n;
		base->common_timeout_queues = newqueues;
	}
	struct common_timeout_list* new_ctl = calloc(1, sizeof(struct common_timeout_list));
	if (!new_ctl) {
		goto done;
	}
	TAILQ_INIT(&new_ctl->events);
	new_ctl->duration.tv_sec = duration->tv_sec;
	new_ctl->duration.tv_usec =
		duration->tv_usec | COMMON_TIMEOUT_MAGIC |
		(base->n_common_timeouts << COMMON_TIMEOUT_IDX_SHIFT);
	evtimer_assign(&new_ctl->timeout_event, base,
		common_timeout_callback, new_ctl);
	new_ctl->timeout_event.ev_flags |= EVLIST_INTERNAL;
	event_priority_set(&new_ctl->timeout_event, 0);
	new_ctl->base = base;
	base->common_timeout_queues[base->n_common_timeouts++] = new_ctl;
	result = &new_ctl->duration;

done:

	return result;
}

static void
insert_common_timeout_inorder(struct common_timeout_list* ctl, struct event* ev)
{
	struct event* e;
	TAILQ_FOREACH_REVERSE(e, &ctl->events, event_list, ev_timeout_pos.ev_next_with_common_timeout) {
		if (evutil_timercmp(&ev->ev_timeout, &e->ev_timeout, >= )) {
			TAILQ_INSERT_AFTER(&ctl->events, e, ev,
				ev_timeout_pos.ev_next_with_common_timeout);
			return;
		}
	}
	TAILQ_INSERT_HEAD(&ctl->events, ev,
		ev_timeout_pos.ev_next_with_common_timeout);
}

static void
event_queue_insert_inserted(struct event_base* base, struct event* ev)
{
	INCR_EVENT_COUNT(base, ev->ev_flags);

	ev->ev_flags |= EVLIST_INSERTED;
}

static void
event_queue_remove_inserted(struct event_base* base, struct event* ev)
{
	if (!(ev->ev_flags & EVLIST_INSERTED)) {
		return;
	}
	DECR_EVENT_COUNT(base, ev->ev_flags);
	ev->ev_flags &= ~EVLIST_INSERTED;
}

static void
event_queue_insert_timeout(struct event_base* base, struct event* ev)
{
	INCR_EVENT_COUNT(base, ev->ev_flags);

	ev->ev_flags |= EVLIST_TIMEOUT;

	if (is_common_timeout(&ev->ev_timeout, base)) {
		struct common_timeout_list* ctl =
			get_common_timeout_list(base, &ev->ev_timeout);
		/** 插入common队列 */
		insert_common_timeout_inorder(ctl, ev);
	}
	else {
		/** 插入小根堆 */
		min_heap_push_(&base->timeheap, ev);
	}
}

static void
event_queue_remove_timeout(struct event_base* base, struct event* ev)
{
	DECR_EVENT_COUNT(base, ev->ev_flags);
	ev->ev_flags &= ~EVLIST_TIMEOUT;

	if (is_common_timeout(&ev->ev_timeout, base)) {
		struct common_timeout_list* ctl =
			get_common_timeout_list(base, &ev->ev_timeout);
		TAILQ_REMOVE(&ctl->events, ev,
			ev_timeout_pos.ev_next_with_common_timeout);
	}
	else {
		min_heap_erase_(&base->timeheap, ev);
	}
}

static void
event_queue_remove_active(struct event_base* base, struct event_callback* evcb)
{
	DECR_EVENT_COUNT(base, evcb->evcb_flags);
	evcb->evcb_flags &= ~EVLIST_ACTIVE;
	base->event_count_active--;

	TAILQ_REMOVE(&base->activequeues[evcb->evcb_pri],
		evcb, evcb_active_next);
}

static int
evthread_notify_base(struct event_base* base)
{
	if (!base->th_notify_fn)
		return -1;
	if (base->is_notify_pending)
		return 0;
	base->is_notify_pending = 1;
	return base->th_notify_fn(base);
}

int
event_add_nolock_(struct event* ev, const struct timeval* tv, int tv_is_absolute)
{
	if (ev->ev_flags & ~EVLIST_ALL ||
		ev->ev_flags & EVLIST_FINALIZING) {
		return -1;
	}

	struct event_base* base = ev->ev_base;
	/** 小根堆扩容 */
	if (tv != NULL && !(ev->ev_flags & EVLIST_TIMEOUT)) {
		if (min_heap_reserve_(&base->timeheap, 1 + min_heap_size_(&base->timeheap)) == -1)
			return -1;
	}

	int res = 0, notify = 0;
	if ((ev->ev_events & (EV_READ | EV_WRITE | EV_CLOSED | EV_SIGNAL)) &&
		!(ev->ev_flags & (EVLIST_INSERTED | EVLIST_ACTIVE | EVLIST_ACTIVE_LATER)))
	{
		if (ev->ev_events & (EV_READ | EV_WRITE | EV_CLOSED))
			res = evmap_io_add_(base, ev->ev_fd, ev);
		else if (ev->ev_events & EV_SIGNAL)
			res = evmap_signal_add_(base, (int)ev->ev_fd, ev);

		/** 事件插入队列中 */
		if (res != -1)
			event_queue_insert_inserted(base, ev);
		if (res == 1) {
			/* 需要通知主线程 */
			notify = 1;
			res = 0;
		}
	}

	if (res != -1 && tv != NULL) {
		if (ev->ev_closure == EV_CLOSURE_EVENT_PERSIST && !tv_is_absolute)
			ev->ev_io_timeout = *tv;

		if (ev->ev_flags & EVLIST_TIMEOUT)
			event_queue_remove_timeout(base, ev);

		if ((ev->ev_flags & EVLIST_ACTIVE) && (ev->ev_res & EV_TIMEOUT)) {
			if (ev->ev_events & EV_SIGNAL) {
				if (ev->ev_ncalls && ev->ev_pncalls) {
					/* Abort loop */
					*ev->ev_pncalls = 0;
				}
			}
			event_queue_remove_active(base, &ev->ev_evcallback);
		}

		struct timeval now;
		gettime(base, &now);

		int common_timeout = is_common_timeout(tv, base);
		if (tv_is_absolute) {
			ev->ev_timeout = *tv;
		}
		else if (common_timeout) {
			struct timeval tmp = *tv;
			tmp.tv_usec &= MICROSECONDS_MASK;
			evutil_timeradd(&now, &tmp, &ev->ev_timeout);
			ev->ev_timeout.tv_usec |=
				(tv->tv_usec & ~MICROSECONDS_MASK);
		}
		else {
			evutil_timeradd(&now, tv, &ev->ev_timeout);
		}

		/** 插入超时事件 */
		event_queue_insert_timeout(base, ev);

		if (common_timeout) {
			struct common_timeout_list* ctl =
				get_common_timeout_list(base, &ev->ev_timeout);
			/** 将common事件加入超时事件 */
			if (ev == TAILQ_FIRST(&ctl->events))
				common_timeout_schedule(ctl, &now, ev);
		}
		else {
			struct event* top = NULL;
			/** 当前的事件超时时间比最小堆根的时间 还早 */
			if (min_heap_elt_is_top_(ev))
				notify = 1;
			/** 最小堆根事件未触发 */
			else if ((top = min_heap_top_(&base->timeheap)) != NULL &&
				evutil_timercmp(&top->ev_timeout, &now, < ))
				notify = 1;
		}
	}

	if (res != -1 && notify && base->running_loop)
		evthread_notify_base(base);

	return res;
}

int
event_dispatch(void)
{
	return event_base_loop(current_base, 0);
}

int
event_base_dispatch(struct event_base* event_base)
{
	return (event_base_loop(event_base, 0));
}

static int
timeout_next(struct event_base* base, struct timeval** tv_p)
{
	struct event* ev = min_heap_top_(&base->timeheap);
	if (ev == NULL) {
		*tv_p = NULL;
		goto out;
	}

	int res = 0;
	struct timeval now;
	if (gettime(base, &now) == -1) {
		res = -1;
		goto out;
	}

	struct timeval* tv = *tv_p;
	if (evutil_timercmp(&ev->ev_timeout, &now, <= )) {
		evutil_timerclear(tv);
		goto out;
	}

	evutil_timersub(&ev->ev_timeout, &now, tv);

out:
	return res;
}

static int
event_haveevents(struct event_base* base)
{
	return (base->virtual_event_count > 0 || base->event_count > 0);
}

static void
event_queue_make_later_events_active(struct event_base* base)
{
	struct event_callback* evcb;

	while ((evcb = TAILQ_FIRST(&base->active_later_queue))) {
		TAILQ_REMOVE(&base->active_later_queue, evcb, evcb_active_next);
		evcb->evcb_flags = (evcb->evcb_flags & ~EVLIST_ACTIVE_LATER) | EVLIST_ACTIVE;
		TAILQ_INSERT_TAIL(&base->activequeues[evcb->evcb_pri], evcb, evcb_active_next);
		base->n_deferreds_queued += (evcb->evcb_closure == EV_CLOSURE_CB_SELF);
	}
}

static inline void
update_time_cache(struct event_base* base)
{
	base->tv_cache.tv_sec = 0;
	if (!(base->flags & EVENT_BASE_FLAG_NO_CACHE_TIME))
		gettime(base, &base->tv_cache);
}

static void
timeout_process(struct event_base* base)
{
	if (min_heap_empty_(&base->timeheap)) {
		return;
	}

	struct timeval now;
	gettime(base, &now);

	struct event* ev;
	while ((ev = min_heap_top_(&base->timeheap))) {
		if (evutil_timercmp(&ev->ev_timeout, &now, > ))
			break;
		event_del_nolock_(ev, EVENT_DEL_NOBLOCK);
		event_active_nolock_(ev, EV_TIMEOUT, 1);
	}
}

int
event_del(struct event* ev)
{
	return event_del_nolock_(ev, EVENT_DEL_AUTOBLOCK);
}

int
event_del_nolock_(struct event* ev, int blocking)
{
	if (ev->ev_base == NULL) {
		return -1;
	}
	if (blocking != EVENT_DEL_EVEN_IF_FINALIZING) {
		if (ev->ev_flags & EVLIST_FINALIZING) {
			return 0;
		}
	}

	if (ev->ev_events & EV_SIGNAL) {
		if (ev->ev_ncalls && ev->ev_pncalls) {
			*ev->ev_pncalls = 0;
		}
	}

	struct event_base* base = ev->ev_base;
	if (ev->ev_flags & EVLIST_TIMEOUT) {
		event_queue_remove_timeout(base, ev);
	}

	if (ev->ev_flags & EVLIST_ACTIVE)
		event_queue_remove_active(base, &ev->ev_evcallback);
	else if (ev->ev_flags & EVLIST_ACTIVE_LATER)
		event_queue_remove_active_later(base, &ev->ev_evcallback);

	int res = 0, notify = 0;
	if (ev->ev_flags & EVLIST_INSERTED) {
		event_queue_remove_inserted(base, ev);
		if (ev->ev_events & (EV_READ | EV_WRITE | EV_CLOSED))
			res = evmap_io_del_(base, ev->ev_fd, ev);
		else
			res = evmap_signal_del_(base, (int)ev->ev_fd, ev);
		if (res == 1) {
			notify = 1;
			res = 0;
		}

		if (!event_haveevents(base) && !(base)->event_count_active)
			notify = 1;
	}

	if (res != -1 && notify && (base)->running_loop)
		evthread_notify_base(base);

	return res;
}

void
event_free(struct event* ev)
{
	event_del(ev);
	free(ev);
}

static inline struct event*
event_callback_to_event(struct event_callback* evcb)
{
	return EVUTIL_UPCAST(evcb, struct event, ev_evcallback);
}

static inline void
event_signal_closure(struct event_base* base, struct event* ev)
{
	short ncalls;
	int should_break;

	ncalls = ev->ev_ncalls;
	if (ncalls != 0)
		ev->ev_pncalls = &ncalls;
	while (ncalls) {
		ncalls--;
		ev->ev_ncalls = ncalls;
		if (ncalls == 0)
			ev->ev_pncalls = NULL;
		(*ev->ev_callback)(ev->ev_fd, ev->ev_res, ev->ev_arg);

		should_break = base->event_break;

		if (should_break) {
			if (ncalls != 0)
				ev->ev_pncalls = NULL;
			return;
		}
	}
}

static inline void
event_persist_closure(struct event_base* base, struct event* ev)
{
	if (ev->ev_io_timeout.tv_sec || ev->ev_io_timeout.tv_usec) {

		struct timeval run_at, relative_to, delay, now;
		uint32_t usec_mask = 0;
		if (is_same_common_timeout(&ev->ev_timeout, &ev->ev_io_timeout))
			return ;

		gettime(base, &now);
		if (is_common_timeout(&ev->ev_timeout, base)) {
			delay = ev->ev_io_timeout;
			usec_mask = delay.tv_usec & ~MICROSECONDS_MASK;
			delay.tv_usec &= MICROSECONDS_MASK;
			if (ev->ev_res & EV_TIMEOUT) {
				relative_to = ev->ev_timeout;
				relative_to.tv_usec &= MICROSECONDS_MASK;
			}
			else {
				relative_to = now;
			}
		}
		else {
			delay = ev->ev_io_timeout;
			if (ev->ev_res & EV_TIMEOUT) {
				relative_to = ev->ev_timeout;
			}
			else {
				relative_to = now;
			}
		}
		evutil_timeradd(&relative_to, &delay, &run_at);
		if (evutil_timercmp(&run_at, &now, < )) {
			evutil_timeradd(&now, &delay, &run_at);
		}
		run_at.tv_usec |= usec_mask;
		event_add_nolock_(ev, &run_at, 1);
	}

	evutil_socket_t evcb_fd = ev->ev_fd;
	short evcb_res = ev->ev_res;
	void* evcb_arg = ev->ev_arg;

	void (*evcb_callback)(evutil_socket_t, short, void*);
	evcb_callback = ev->ev_callback;
	(evcb_callback)(evcb_fd, evcb_res, evcb_arg);
}

static int
event_process_active_single_queue(struct event_base* base,
	struct evcallback_list* activeq,
	int max_to_process, const struct timeval* endtime)
{
	if (activeq == NULL)
		return -1;

	struct event_callback* evcb;
	int count = 0;
	for (evcb = TAILQ_FIRST(activeq); evcb; evcb = TAILQ_FIRST(activeq)) {
		struct event* ev = NULL;
		if (evcb->evcb_flags & EVLIST_INIT) {
			/** 偏移量巧妙地转为event */
			ev = event_callback_to_event(evcb);
			if (ev->ev_events & EV_PERSIST || ev->ev_flags & EVLIST_FINALIZING)
				event_queue_remove_active(base, evcb);
			else
				event_del_nolock_(ev, EVENT_DEL_NOBLOCK);
		}
		else {
			event_queue_remove_active(base, evcb);
		}

		if (!(evcb->evcb_flags & EVLIST_INTERNAL)) {
			++count;
		}

		base->current_event = evcb;
		switch (evcb->evcb_closure) {
		case EV_CLOSURE_EVENT_SIGNAL:
			event_signal_closure(base, ev);
			break;
		case EV_CLOSURE_EVENT_PERSIST:
			event_persist_closure(base, ev);
			break;
		case EV_CLOSURE_EVENT:
			{
			void (*evcb_callback)(evutil_socket_t, short, void*);
			evcb_callback = *ev->ev_callback;
			short res = ev->ev_res;
			evcb_callback(ev->ev_fd, res, ev->ev_arg);
			}
			break;
		case EV_CLOSURE_CB_SELF:
			{
			void (*evcb_selfcb)(struct event_callback*, void*) = evcb->evcb_cb_union.evcb_selfcb;
			evcb_selfcb(evcb, evcb->evcb_arg);
			}
			break;
		case EV_CLOSURE_CB_FINALIZE:
			{
			void (*evcb_cbfinalize)(struct event_callback*, void*) = evcb->evcb_cb_union.evcb_cbfinalize;
			base->current_event = NULL;
			if(evcb->evcb_flags & EVLIST_FINALIZING)
				evcb_cbfinalize(evcb, evcb->evcb_arg);
			}
			break;
		case EV_CLOSURE_EVENT_FINALIZE:
		case EV_CLOSURE_EVENT_FINALIZE_FREE:
			{
			base->current_event = NULL;
			void (*evcb_evfinalize)(struct event*, void*);
			evcb_evfinalize = ev->ev_evcallback.evcb_cb_union.evcb_evfinalize;
			if(evcb->evcb_flags & EVLIST_FINALIZING);
				evcb_evfinalize(ev, ev->ev_arg);
			if (evcb->evcb_closure == EV_CLOSURE_EVENT_FINALIZE_FREE)
				free(ev);
			}
			break;
		}

		base->current_event = NULL;
		if (base->event_break)
			return -1;
		if (count >= max_to_process)
			return count;
		if (count && endtime) {
			struct timeval now;
			update_time_cache(base);
			gettime(base, &now);
			if (evutil_timercmp(&now, endtime, >= ))
				return count;
		}
		if (base->event_continue)
			break;
	}

	return count;
}

static int
event_process_active(struct event_base* base)
{
	struct timeval tv;
	const struct timeval* endtime;
	if (base->max_dispatch_time.tv_sec >= 0) {
		update_time_cache(base);
		gettime(base, &tv);
		evutil_timeradd(&base->max_dispatch_time, &tv, &tv);
		endtime = &tv;
	}
	else {
		endtime = NULL;
	}

	const int limit_after_prio = base->limit_callbacks_after_prio;
	const int maxcb = base->max_dispatch_callbacks;

	struct evcallback_list* activeq = NULL;
	int i, c = 0;
	/** 从头到尾取活跃队列 */
	for (i = 0; i < base->nactivequeues; ++i) {
		if (TAILQ_FIRST(&base->activequeues[i]) != NULL) {
			base->event_running_priority = i;
			activeq = &base->activequeues[i];
			if (i < limit_after_prio)
				/** 处理单条队列 */
				c = event_process_active_single_queue(base, activeq,
					INT_MAX, NULL);
			else
				c = event_process_active_single_queue(base, activeq,
					maxcb, endtime);
			if (c < 0) {
				goto done;
			}
			/** 真实事件要跳出 */
			else if (c > 0)
				break;
		}
	}


done:
	base->event_running_priority = -1;

	return c;
}

int
event_base_loop(struct event_base* base, int flags)
{
	base->running_loop = 1;
	base->tv_cache.tv_sec = 0;
	if (base->sig.ev_signal_added && base->sig.ev_n_signals_added)
		evsig_set_base_(base);
	base->event_gotterm = base->event_break = 0;

	int res, retval = 0;
	struct timeval tv = { 0, 0 };
	struct timeval* tv_p;
	const struct eventop* evsel = base->evsel;
	int done = 0;
	while (!done) {
		if (base->event_gotterm || base->event_break) {
			break;
		}
		if (!(flags & EVLOOP_NO_EXIT_ON_EMPTY) &&
			!event_haveevents(base) && !(base)->event_count_active) {
			retval = 1;
			goto done;
		}

		/** 待绪事件放入活跃队列 */
		base->n_deferreds_queued = 0;
		event_queue_make_later_events_active(base);

		base->tv_cache.tv_sec = 0;
		base->event_continue = 0;
		/** 最近超时事件倒计时 */
		tv_p = &tv;
		if (!(base)->event_count_active && !(flags & EVLOOP_NONBLOCK)) {
			timeout_next(base, &tv_p);
		}
		else {
			evutil_timerclear(tv_p);
		}
		res = evsel->dispatch(base, tv_p);
		if (res == -1) {
			retval = -1;
			goto done;
		}

		update_time_cache(base);
		/** 处理超时事件 */
		timeout_process(base);

		if ((base)->event_count_active) {
			/** 处理活跃事件 */
			int n = event_process_active(base);
			if ((flags & EVLOOP_ONCE)
				&& (base)->event_count_active == 0
				&& n != 0)
				done = 1;
		}
		else if (flags & EVLOOP_NONBLOCK)
			done = 1;
	}

done:
	base->tv_cache.tv_sec = 0;
	base->running_loop = 0;

	return retval;
}

static void
event_loopexit_cb(evutil_socket_t fd, short what, void* arg)
{
	struct event_base* base = arg;
	base->event_gotterm = 1;
}

int
event_base_loopexit(struct event_base* event_base, const struct timeval* tv)
{
	return (event_base_once(event_base, -1, EV_TIMEOUT, event_loopexit_cb,
		event_base, tv));
}

static void
event_once_cb(evutil_socket_t fd, short events, void* arg)
{
	struct event_once* eonce = arg;
	(*eonce->cb)(fd, events, eonce->arg);
	LIST_REMOVE(eonce, next_once);
	free(eonce);
}

int
event_base_once(struct event_base* base, evutil_socket_t fd, short events,
	void (*callback)(evutil_socket_t, short, void*),
	void* arg, const struct timeval* tv)
{
	if (!base)
		return (-1);
	if (events & (EV_SIGNAL | EV_PERSIST))
		return (-1);
	/** 申请单次事件 */
	struct event_once* eonce = calloc(1, sizeof(struct event_once));
	if (eonce == NULL)
		return (-1);

	eonce->cb = callback;
	eonce->arg = arg;

	int activate = 0;
	if ((events & (EV_TIMEOUT | EV_SIGNAL | EV_READ | EV_WRITE | EV_CLOSED)) == EV_TIMEOUT) {
		evtimer_assign(&eonce->ev, base, event_once_cb, eonce);
		if (tv == NULL || ! timerisset(tv)) {
			activate = 1;
		}
	}
	else if (events & (EV_READ | EV_WRITE | EV_CLOSED)) {
		events &= EV_READ | EV_WRITE | EV_CLOSED;
		event_assign(&eonce->ev, base, fd, events, event_once_cb, eonce);
	}
	else {
		free(eonce);
		return (-1);
	}

	int res = 0;
	if (activate)
		event_active_nolock_(&eonce->ev, EV_TIMEOUT, 1);
	else
		res = event_add_nolock_(&eonce->ev, tv, 0);

	if (res != 0) {
		free(eonce);
		return (res);
	}
	else {
		LIST_INSERT_HEAD(&base->once_events, eonce, next_once);
	}

	return (0);
}

int
evutil_socketpair(int family, int type, int protocol, evutil_socket_t fd[2])
{
#ifndef _WIN32
	//return socketpair(family, type, protocol, fd);
#else

	int family_test = family != AF_INET;
	if (protocol || family_test) {
		return -1;
	}
	if (!fd) {
		return -1;
	}

	evutil_socket_t listener = socket(AF_INET, type, 0);
	if (listener < 0) {
		return -1;
	}
	struct sockaddr_in listen_addr;
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listen_addr.sin_port = 0;
	if (bind(listener, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) == -1) {
		goto tidy_up_and_fail;
	}
	if (listen(listener, 1) == -1) {
		goto tidy_up_and_fail;
	}

	evutil_socket_t connector = socket(AF_INET, type, 0);
	if (connector < 0) {
		goto tidy_up_and_fail;
	}
	struct sockaddr_in connect_addr;
	memset(&connect_addr, 0, sizeof(connect_addr));
	int size = sizeof(connect_addr);
	if (getsockname(listener, (struct sockaddr *)&connect_addr, &size) == -1) {
		goto tidy_up_and_fail;
	}
	if (connect(connector, (struct sockaddr *)&connect_addr, size) == -1) {
		goto tidy_up_and_fail;
	}

	size = sizeof(listen_addr);
	evutil_socket_t acceptor = accept(listener, (struct sockaddr *) &listen_addr, &size);
	if (acceptor < 0) {
		goto tidy_up_and_fail;
	}
	if (getsockname(connector, (struct sockaddr*)&connect_addr, &size) == -1) {
		goto tidy_up_and_fail;
	}
	if (listen_addr.sin_family != connect_addr.sin_family
		|| listen_addr.sin_addr.s_addr != connect_addr.sin_addr.s_addr
		|| listen_addr.sin_port != connect_addr.sin_port) {
		goto abort_tidy_up_and_fail;
	}
	evutil_closesocket(listener);
	fd[0] = connector;
	fd[1] = acceptor;

	return 0;

	int saved_errno = -1;
#define ERR(e) WSA##e

abort_tidy_up_and_fail:
	saved_errno = ERR(ECONNABORTED);
tidy_up_and_fail:
	if (saved_errno < 0)
		saved_errno = WSAGetLastError();
	if (listener != -1)
		evutil_closesocket(listener);
	if (connector != -1)
		evutil_closesocket(connector);
	if (acceptor != -1)
		evutil_closesocket(acceptor);

	WSASetLastError(saved_errno);
	return -1;
#endif
}

int
evutil_closesocket(evutil_socket_t sock)
{
#ifdef _WIN32
	return closesocket(sock);
#else
	return close(sock);
#endif
}

uint32_t
evutil_weakrand_seed_(struct evutil_weakrand_state* state, uint32_t seed)
{
	if (seed == 0) {
		struct timeval tv;
		evutil_gettimeofday(&tv, NULL);
		seed = (uint32_t)tv.tv_sec + (uint32_t)tv.tv_usec;
#ifdef _WIN32
		seed += (uint32_t)_getpid();
#else
		seed += (uint32_t)getpid();
#endif
	}
	state->seed = seed;
	return seed;
}

int32_t
evutil_weakrand_(struct evutil_weakrand_state* state)
{
	state->seed = ((state->seed) * 1103515245 + 12345) & 0x7fffffff;
	return (int32_t)(state->seed);
}

int32_t
evutil_weakrand_range_(struct evutil_weakrand_state* state, int32_t top)
{
	int32_t divisor, result;
	divisor = INT32_MAX / top;
	do {
		result = evutil_weakrand_(state) / divisor;
	} while (result >= top);
	return result;
}

#ifdef _WIN32
#include <mswsock.h>

HMODULE
evutil_load_windows_system_library_(const TCHAR* library_name)
{
	TCHAR path[MAX_PATH];
	unsigned n;
	n = GetSystemDirectory(path, MAX_PATH);
	if (n == 0 || n + _tcslen(library_name) + 2 >= MAX_PATH)
		return 0;
	_tcscat(path, TEXT("\\"));
	_tcscat(path, library_name);
	return LoadLibrary(path);
}

int
evutil_gettimeofday(struct timeval* tv, struct timezone* tz)
{
#define EPOCH_BIAS 116444736000000000
#define UNITS_PER_SEC 10000000
#define USEC_PER_SEC 1000000
#define UNITS_PER_USEC 10

	if (tv == NULL)
		return -1;
	union {
		FILETIME ft_ft;
		uint64_t ft_64;
	} ft;
	static GetSystemTimePreciseAsFileTime_fn_t GetSystemTimePreciseAsFileTime_fn = NULL;
	static int check_precise = 1;
	if (check_precise) {
		HMODULE h = evutil_load_windows_system_library_(TEXT("kernel32.dll"));
		if (h != NULL) {
			GetSystemTimePreciseAsFileTime_fn = (GetSystemTimePreciseAsFileTime_fn_t)
				GetProcAddress(h, "GetSystemTimePreciseAsFileTime");
			check_precise = 0;
		}
	}
	if (GetSystemTimePreciseAsFileTime_fn != NULL) {
		GetSystemTimePreciseAsFileTime_fn(&ft.ft_ft);
	}
	else {
		GetSystemTimeAsFileTime(&ft.ft_ft);
	}
	if (ft.ft_64 < EPOCH_BIAS) {
		return -1;
	}
	ft.ft_64 -= EPOCH_BIAS;
	tv->tv_sec = (long)(ft.ft_64 / UNITS_PER_SEC);
	tv->tv_usec = (long)((ft.ft_64 / UNITS_PER_USEC) % USEC_PER_SEC);
	return 0;
}

#define MAX_SECONDS_IN_MSEC_LONG \
	(((LONG_MAX) - 999) / 1000)

long
evutil_tv_to_msec_(const struct timeval* tv)
{
	if (tv->tv_usec > 1000000 || tv->tv_sec > MAX_SECONDS_IN_MSEC_LONG)
		return -1;

	return (tv->tv_sec * 1000) + ((tv->tv_usec + 999) / 1000);
}

int
event_base_start_iocp_(struct event_base* base, int n_cpus)
{
	if (base->iocp)
		return 0;
	base->iocp = event_iocp_port_launch_(n_cpus);
	if (!base->iocp) {
		return -1;
	}
	return 0;
}

static int extension_fns_initialized = 0;
static struct win32_extension_fns the_extension_fns;

static void*
get_extension_function(SOCKET s, const GUID* which_fn)
{
	void* ptr = NULL;
	DWORD bytes = 0;
	WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		(GUID*)which_fn, sizeof(*which_fn),
		&ptr, sizeof(ptr),
		&bytes, NULL, NULL);

	return ptr;
}

static void
init_extension_functions(struct win32_extension_fns* ext)
{
	const GUID acceptex = WSAID_ACCEPTEX;
	const GUID connectex = WSAID_CONNECTEX;
	const GUID getacceptexsockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
		return;
	ext->AcceptEx = get_extension_function(s, &acceptex);
	ext->ConnectEx = get_extension_function(s, &connectex);
	ext->GetAcceptExSockaddrs = get_extension_function(s,
		&getacceptexsockaddrs);
	closesocket(s);

	extension_fns_initialized = 1;
}

static void
loop(void *port_)
{

}

#define N_CPUS_DEFAULT 2

struct event_iocp_port *
event_iocp_port_launch_(int n_cpus)
{
	if (!extension_fns_initialized) {
		init_extension_functions(&the_extension_fns);
	}
	struct event_iocp_port *port;
	if (!(port = calloc(1, sizeof(struct event_iocp_port)))) {
		return NULL;
	}
	if (n_cpus <= 0) {
		n_cpus = N_CPUS_DEFAULT;
	}
	port->n_threads = n_cpus * 2;
	port->threads = calloc(port->n_threads, sizeof(HANDLE));
	if (!port->threads) {
		goto err;
	}
	port->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, n_cpus);
	if (!port->port) {
		goto err;
	}
	port->ms = -1;
	port->shutdownSemaphore = CreateSemaphore(NULL, 0, 1, NULL);
	if (!port->shutdownSemaphore) {
		goto err;
	}
	for (int i = 0; i < port->n_threads; ++i) {
		uintptr_t th = _beginthread(loop, 0, port);
		if (th == (uintptr_t)-1) {
			goto err;
		}
		port->threads[i] = (HANDLE)th;
		++port->n_live_threads;
	}
	InitializeCriticalSectionAndSpinCount(&port->lock, 1000);
	return port;
err:
	if (port->port) {
		CloseHandle(port->port);
	}
	if (port->threads) {
		free(port->threads);
	}
	if (port->shutdownSemaphore) {
		CloseHandle(port->shutdownSemaphore);
	}
	free(port);
	return NULL;
}

const struct win32_extension_fns*
event_get_win32_extension_fns_(void)
{
	return &the_extension_fns;
}

#endif