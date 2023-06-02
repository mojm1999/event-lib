#include <base.h>

struct evconnlistener_ops {
	int (*enable)(struct evconnlistener*);
	int (*disable)(struct evconnlistener*);
	void (*destroy)(struct evconnlistener*);
	void (*shutdown)(struct evconnlistener*);
	evutil_socket_t(*getfd)(struct evconnlistener*);
	struct event_base* (*getbase)(struct evconnlistener*);
};

struct evconnlistener {
	/** 行为 */
	const struct evconnlistener_ops* ops;
	/** 回调函数指针 */
	evconnlistener_cb cb;
	/** event_base */
	void* user_data;
	/** 行为标记 */
	unsigned flags;
	void* lock;
	evconnlistener_errorcb errorcb;
	short refcnt;
	int accept4_flags;
	unsigned enabled : 1;
};

struct evconnlistener_event {
	/** 基础内容 */
	struct evconnlistener base;
	/** 监听事件 */
	struct event listener;
};

#ifdef _WIN32
struct evconnlistener_iocp {
	struct evconnlistener base;
	evutil_socket_t fd;
	struct event_base* event_base;
	struct event_iocp_port* port;
	short n_accepting;
	unsigned shutting_down : 1;
	unsigned event_added : 1;
	struct accepting_socket** accepting;
};

struct accepting_socket {
	CRITICAL_SECTION lock;
	struct event_overlapped overlapped;
	SOCKET s;
	int error;
	struct event_callback deferred;
	struct evconnlistener_iocp* lev;
	uint8_t buflen;
	uint8_t family;
	unsigned free_on_cb : 1;
	char addrbuf[1];
};
#endif

struct evconnlistener *
evconnlistener_new_bind(struct event_base *base, evconnlistener_cb cb,
    void *ptr, unsigned flags, int backlog, const struct sockaddr *sa, int socklen)
{
	if (backlog == 0)
		return NULL;

	int family = sa ? sa->sa_family : AF_UNSPEC;
	int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;
	evutil_socket_t fd = evutil_socket_(family, socktype, 0);
	if (fd == -1)
		return NULL;

	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on)) < 0)
		goto err;

	if (sa) {
		if (bind(fd, sa, socklen) < 0)
			goto err;
	}
	struct evconnlistener* listener = evconnlistener_new(base, cb, ptr, flags, backlog, fd);
	if (!listener)
		goto err;

	return listener;
err:
	evutil_closesocket(fd);
	return NULL;
}

static int
iocp_listener_enable(struct evconnlistener* lev)
{
	return 0;
}

static int
iocp_listener_disable(struct evconnlistener* lev)
{
}

static void
iocp_listener_destroy(struct evconnlistener* lev)
{
}

static evutil_socket_t
iocp_listener_getfd(struct evconnlistener* lev)
{
}

static struct event_base*
iocp_listener_getbase(struct evconnlistener* lev)
{
}

static const struct evconnlistener_ops evconnlistener_iocp_ops = {
	iocp_listener_enable,
	iocp_listener_disable,
	iocp_listener_destroy,
	iocp_listener_destroy, /* shutdown */
	iocp_listener_getfd,
	iocp_listener_getbase
};

static void
accepted_socket_cb(struct event_overlapped* o, uintptr_t key, ev_ssize_t n, int ok)
{

}

static struct accepting_socket*
new_accepting_socket(struct evconnlistener_iocp* lev, int family)
{
	struct accepting_socket* res;

	return res;
}

#define N_SOCKETS_PER_LISTENER 4

struct evconnlistener *
evconnlistener_new_async(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
	if (!base || !base->iocp)
		goto err;
	if (backlog > 0) {
		if (listen(fd, backlog) < 0)
			goto err;
	}
	else if (backlog < 0) {
		if (listen(fd, 128) < 0)
			goto err;
	}
	struct sockaddr_storage ss;
	int socklen = sizeof(ss);
	if (getsockname(fd, (struct sockaddr*)&ss, &socklen)) {
		goto err;
	}

	struct evconnlistener_iocp* lev = calloc(1, sizeof(struct evconnlistener_iocp));
	if (!lev) {
		goto err;
	}
	lev->base.ops = &evconnlistener_iocp_ops;
	lev->base.cb = cb;
	lev->base.user_data = ptr;
	lev->base.flags = flags;
	lev->base.refcnt = 1;
	lev->base.enabled = 1;
	lev->port = base->iocp;
	lev->fd = fd;
	lev->event_base = base;

	if (event_iocp_port_associate_(lev->port, fd, 1) < 0)
		goto err_free_lev;

	lev->n_accepting = N_SOCKETS_PER_LISTENER;
	lev->accepting = calloc(lev->n_accepting,
		sizeof(struct accepting_socket*));
	if (!lev->accepting) {
		goto err_free_lev;
	}
	//for (int i = 0; i < lev->n_accepting; ++i) {
	//	lev->accepting[i] = new_accepting_socket(lev, ss.ss_family);
	//	if (!lev->accepting[i]) {
	//		goto err_free_accepting;
	//	}
	//	if (cb && start_accepting(lev->accepting[i]) < 0) {
	//		event_warnx("Couldn't start accepting on socket");
	//		EnterCriticalSection(&lev->accepting[i]->lock);
	//		free_and_unlock_accepting_socket(lev->accepting[i]);
	//		goto err_free_accepting;
	//	}
	//	++lev->base.refcnt;
	//}

	//iocp_listener_event_add(lev);

	return &lev->base;

err_free_lev:
	free(lev);
err:
	return NULL;
}

static int
event_listener_enable(struct evconnlistener* lev)
{
	struct evconnlistener_event* lev_e =
		EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_add(&lev_e->listener, NULL);
}

static int
event_listener_disable(struct evconnlistener* lev)
{
	struct evconnlistener_event* lev_e =
		EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_del(&lev_e->listener);
}

static void
event_listener_destroy(struct evconnlistener* lev)
{
	struct evconnlistener_event* lev_e =
		EVUTIL_UPCAST(lev, struct evconnlistener_event, base);

	event_del(&lev_e->listener);
	if (lev->flags & LEV_OPT_CLOSE_ON_FREE)
		evutil_closesocket(event_get_fd(&lev_e->listener));
}

static evutil_socket_t
event_listener_getfd(struct evconnlistener* lev)
{
	struct evconnlistener_event* lev_e =
		EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_get_fd(&lev_e->listener);
}

static struct event_base*
event_listener_getbase(struct evconnlistener* lev)
{
	struct evconnlistener_event* lev_e =
		EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_get_base(&lev_e->listener);
}

static const struct evconnlistener_ops evconnlistener_event_ops = {
	event_listener_enable,
	event_listener_disable,
	event_listener_destroy,
	NULL, /* shutdown */
	event_listener_getfd,
	event_listener_getbase
};

int
evconnlistener_enable(struct evconnlistener* lev)
{
	lev->enabled = 1;
	int r;
	if (lev->cb)
		r = lev->ops->enable(lev);
	else
		r = 0;
	return r;
}

static void
listener_read_cb(evutil_socket_t fd, short what, void* p)
{
	struct evconnlistener* lev = p;
	evconnlistener_cb cb = lev->cb;
	void* user_data = lev->user_data;

	while (1) {
		struct sockaddr_storage ss;
		int socklen = sizeof(ss);
		evutil_socket_t new_fd = evutil_accept4_(fd, (struct sockaddr*)&ss, &socklen, lev->accept4_flags);
		if (new_fd < 0)
			break;
		if (lev->cb == NULL) {
			evutil_closesocket(new_fd);
			return;
		}
		++lev->refcnt;
		cb(lev, new_fd, (struct sockaddr*)&ss, (int)socklen,
			user_data);
	}
}

struct evconnlistener *
evconnlistener_new(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
#ifdef _WIN32
	if (base && base->iocp) {
		const struct win32_extension_fns *ext =
			event_get_win32_extension_fns_();
		if (ext->AcceptEx && ext->GetAcceptExSockaddrs)
			return evconnlistener_new_async(base, cb, ptr, flags,
				backlog, fd);
	}
#endif
	if (backlog > 0) {
		if (listen(fd, backlog) < 0)
			return NULL;
	} else if (backlog < 0) {
		if (listen(fd, 128) < 0)
			return NULL;
	}

	struct evconnlistener_event* lev = calloc(1, sizeof(struct evconnlistener_event));
	if (!lev)
		return NULL;
	lev->base.ops = &evconnlistener_event_ops;
	lev->base.cb = cb;
	lev->base.user_data = ptr;
	lev->base.flags = flags;
	lev->base.refcnt = 1;
	lev->base.accept4_flags = 0;

	if (!(flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
		lev->base.accept4_flags |= EVUTIL_SOCK_NONBLOCK;

	event_assign(&lev->listener, base, fd, EV_READ|EV_PERSIST,
	    listener_read_cb, lev);

	if (!(flags & LEV_OPT_DISABLED))
	    evconnlistener_enable(&lev->base);

	return &lev->base;
}

static int
evutil_fast_socket_nonblocking(evutil_socket_t fd)
{
#ifdef _WIN32
	unsigned long nonblocking = 1;
	if (ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
		return -1;
	}
	return 0;
#else
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
#endif
}

evutil_socket_t
evutil_socket_(int domain, int type, int protocol)
{
#define SOCKET_TYPE_MASK (~(EVUTIL_SOCK_NONBLOCK))

	evutil_socket_t r = socket(domain, type & SOCKET_TYPE_MASK, protocol);
	if (r < 0) {
		return -1;
	}
	if (type & EVUTIL_SOCK_NONBLOCK) {
		if (evutil_fast_socket_nonblocking(r) < 0) {
			evutil_closesocket(r);
			return -1;
		}
	}
	return r;
}

evutil_socket_t
evutil_accept4_(evutil_socket_t sockfd, struct sockaddr* addr,
	int* addrlen, int flags)
{
	evutil_socket_t result = accept(sockfd, addr, addrlen);
	if (result < 0)
		return result;

	if (flags & EVUTIL_SOCK_NONBLOCK) {
		if (evutil_fast_socket_nonblocking(result) < 0) {
			evutil_closesocket(result);
			return -1;
		}
	}
	return result;
}

int
event_iocp_port_associate_(struct event_iocp_port* port, evutil_socket_t fd,
	uintptr_t key)
{
	HANDLE h;
	h = CreateIoCompletionPort((HANDLE)fd, port->port, key, port->n_threads);
	if (!h)
		return -1;
	return 0;
}