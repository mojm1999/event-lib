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
	base->evbase = NULL;
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

HT_PROTOTYPE(event_io_map, event_map_entry, map_node, hashsocket, eqsocket)

void
evmap_io_initmap_(struct event_io_map *ctx)
{
	HT_INIT(event_io_map, ctx);
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

static int
evsig_add(struct event_base* base, evutil_socket_t evsignal, short old, short events, void* p)
{
	return 0;
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

#ifdef _WIN32
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

static void
init_extension_functions(struct win32_extension_fns* ext)
{

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
#endif