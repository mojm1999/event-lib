#include <base.h>

#ifdef _WIN32

static void* win32_init(struct event_base*);
static int win32_add(struct event_base*, evutil_socket_t, short old, short events, void* idx_);
static int win32_del(struct event_base*, evutil_socket_t, short old, short events, void* idx_);
static int win32_dispatch(struct event_base* base, struct timeval*);
static void win32_dealloc(struct event_base*);

struct idx_info {
	int read_pos_plus1;
	int write_pos_plus1;
};

struct eventop win32ops = {
	"win32",
	win32_init,
	win32_add,
	win32_del,
	win32_dispatch,
	win32_dealloc,
	0,
	0,
	sizeof(struct idx_info),
};

struct win_fd_set {
	/** 当前大小 */
	unsigned int fd_count;
	SOCKET fd_array[1];
};

struct win32op {
	/** 集合容量 */
	unsigned num_fds_in_fd_sets;
	/** fd读集合 */
	struct win_fd_set* readset_in;
	struct win_fd_set* writeset_in;
	struct win_fd_set* readset_out;
	struct win_fd_set* exset_out;
	struct win_fd_set* writeset_out;
	int resize_out_sets;
	unsigned signals_are_broken : 1;
};

#define FD_SET_ALLOC_SIZE(n) (sizeof(struct win_fd_set) + (n-1)*sizeof(SOCKET))

#define NEVENT 32

void*
win32_init(struct event_base* base)
{
	struct win32op* winop;
	if (!(winop = calloc(1, sizeof(struct win32op)))) {
		return NULL;
	}
	winop->num_fds_in_fd_sets = NEVENT;
	size_t size = FD_SET_ALLOC_SIZE(NEVENT);
	if (!(winop->readset_in = malloc(size))) {
		goto err;
	}
	if (!(winop->writeset_in = malloc(size))) {
		goto err;
	}
	if (!(winop->readset_out = malloc(size))) {
		goto err;
	}
	if (!(winop->writeset_out = malloc(size))) {
		goto err;
	}
	if (!(winop->exset_out = malloc(size))) {
		goto err;
	}
	winop->readset_in->fd_count = winop->writeset_in->fd_count = 0;
	winop->readset_out->fd_count = winop->writeset_out->fd_count
		= winop->exset_out->fd_count = 0;

	if (evsig_init_(base) < 0) {
		winop->signals_are_broken = 1;
	}
	evutil_weakrand_seed_(&base->weakrand_seed, 0);

	return (winop);
err:
	free(winop->readset_in);
	free(winop->writeset_in);
	free(winop->readset_out);
	free(winop->writeset_out);
	free(winop->exset_out);
	free(winop);
	return (NULL);
}

static int
grow_fd_sets(struct win32op* op, unsigned new_num_fds)
{
	size_t size;

	size = FD_SET_ALLOC_SIZE(new_num_fds);
	if (!(op->readset_in = realloc(op->readset_in, size)))
		return (-1);
	if (!(op->writeset_in = realloc(op->writeset_in, size)))
		return (-1);
	op->resize_out_sets = 1;
	op->num_fds_in_fd_sets = new_num_fds;
	return (0);
}

static int
do_fd_set(struct win32op* op, struct idx_info* ent, evutil_socket_t s, int read)
{
	struct win_fd_set* set = read ? op->readset_in : op->writeset_in;
	if (read) {
		if (ent->read_pos_plus1 > 0)
			return (0);
	}
	else {
		if (ent->write_pos_plus1 > 0)
			return (0);
	}
	if (set->fd_count == op->num_fds_in_fd_sets) {
		if (grow_fd_sets(op, op->num_fds_in_fd_sets * 2))
			return (-1);
		/** 因为重新分配了内存 */
		set = read ? op->readset_in : op->writeset_in;
	}
	set->fd_array[set->fd_count] = s;
	if (read)
		ent->read_pos_plus1 = set->fd_count + 1;
	else
		ent->write_pos_plus1 = set->fd_count + 1;
	return (set->fd_count++);
}

int
win32_add(struct event_base* base, evutil_socket_t fd,
	short old, short events, void* idx_)
{
	struct win32op* win32op = base->evbase;
	if ((events & EV_SIGNAL) && win32op->signals_are_broken)
		return (-1);
	if (!(events & (EV_READ | EV_WRITE)))
		return (0);
	
	struct idx_info* idx = idx_;
	if (events & EV_READ) {
		if (do_fd_set(win32op, idx, fd, 1) < 0)
			return (-1);
	}
	if (events & EV_WRITE) {
		if (do_fd_set(win32op, idx, fd, 0) < 0)
			return (-1);
	}
	return 0;
}

static int
do_fd_clear(struct event_base *base,
			struct win32op *op, struct idx_info *ent, int read)
{
	int i;
	struct win_fd_set *set = read ? op->readset_in : op->writeset_in;
	if (read) {
		i = ent->read_pos_plus1 - 1;
		ent->read_pos_plus1 = 0;
	} else {
		i = ent->write_pos_plus1 - 1;
		ent->write_pos_plus1 = 0;
	}
	if (i < 0)
		return (0);
	if (--set->fd_count != (unsigned)i) {
		SOCKET s2;
		s2 = set->fd_array[i] = set->fd_array[set->fd_count];

		struct idx_info *ent2;
		ent2 = evmap_io_get_fdinfo_(&base->io, s2);

		if (!ent2) /* This indicates a bug. */
			return (0);
		if (read)
			ent2->read_pos_plus1 = i+1;
		else
			ent2->write_pos_plus1 = i+1;
	}
	return (0);
}

int
win32_del(struct event_base* base, evutil_socket_t fd, short old, short events,
	void* idx_)
{
	struct win32op *win32op = base->evbase;
	struct idx_info *idx = idx_;
	if (events & EV_READ)
		do_fd_clear(base, win32op, idx, 1);
	if (events & EV_WRITE)
		do_fd_clear(base, win32op, idx, 0);
	return 0;
}

static void
fd_set_copy(struct win_fd_set* out, const struct win_fd_set* in)
{
	out->fd_count = in->fd_count;
	memcpy(out->fd_array, in->fd_array, in->fd_count * (sizeof(SOCKET)));
}

int
win32_dispatch(struct event_base* base, struct timeval* tv)
{
	struct win32op* win32op = base->evbase;
	if (win32op->resize_out_sets) {
		size_t size = FD_SET_ALLOC_SIZE(win32op->num_fds_in_fd_sets);
		if (!(win32op->readset_out = realloc(win32op->readset_out, size)))
			return (-1);
		if (!(win32op->exset_out = realloc(win32op->exset_out, size)))
			return (-1);
		if (!(win32op->writeset_out = realloc(win32op->writeset_out, size)))
			return (-1);
		win32op->resize_out_sets = 0;
	}

	fd_set_copy(win32op->readset_out, win32op->readset_in);
	fd_set_copy(win32op->exset_out, win32op->writeset_in);
	fd_set_copy(win32op->writeset_out, win32op->writeset_in);

	int fd_count = (win32op->readset_out->fd_count > win32op->writeset_out->fd_count) ?
		win32op->readset_out->fd_count : win32op->writeset_out->fd_count;

	if (!fd_count) {
		long msec = tv ? evutil_tv_to_msec_(tv) : LONG_MAX;
		if (msec < 0)
			msec = LONG_MAX;
		Sleep(msec);
		return 0;
	}

	int res = select(fd_count,
		(struct fd_set*)win32op->readset_out,
		(struct fd_set*)win32op->writeset_out,
		(struct fd_set*)win32op->exset_out, tv);

	if (res <= 0) {
		return res;
	}

	unsigned j, i;
	SOCKET s;
	if (win32op->readset_out->fd_count) {
		i = evutil_weakrand_range_(&base->weakrand_seed,
			win32op->readset_out->fd_count);
		for (j = 0; j < win32op->readset_out->fd_count; ++j) {
			if (++i >= win32op->readset_out->fd_count)
				i = 0;
			s = win32op->readset_out->fd_array[i];
			evmap_io_active_(base, s, EV_READ);
		}
	}
	if (win32op->exset_out->fd_count) {
		i = evutil_weakrand_range_(&base->weakrand_seed,
			win32op->exset_out->fd_count);
		for (j = 0; j < win32op->exset_out->fd_count; ++j) {
			if (++i >= win32op->exset_out->fd_count)
				i = 0;
			s = win32op->exset_out->fd_array[i];
			evmap_io_active_(base, s, EV_WRITE);
		}
	}
	if (win32op->writeset_out->fd_count) {
		i = evutil_weakrand_range_(&base->weakrand_seed,
			win32op->writeset_out->fd_count);
		for (j = 0; j < win32op->writeset_out->fd_count; ++j) {
			if (++i >= win32op->writeset_out->fd_count)
				i = 0;
			s = win32op->writeset_out->fd_array[i];
			evmap_io_active_(base, s, EV_WRITE);
		}
	}
	return 0;
}

void
win32_dealloc(struct event_base* base)
{
	struct win32op* win32op = base->evbase;


	memset(win32op, 0, sizeof(*win32op));
	free(win32op);
}

#endif