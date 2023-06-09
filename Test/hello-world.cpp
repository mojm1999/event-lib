#include <iostream>
#include <base.h>
#include <buffer_event.h>

#define cout std::cout
#define endl std::endl

static const int PORT = 9995;
static const char IP[] = "127.0.0.1";

static const char MESSAGE[] = "Hello, World!\n";

static void
conn_writecb(struct bufferevent* bev, void* user_data)
{
	if (evbuffer_get_length(bev->output) == 0) {
		cout << "flushed answer" << endl;
		bufferevent_free(bev);
	}
}

static void
conn_eventcb(struct bufferevent* bev, short events, void* user_data)
{

}

static void
listener_cb(struct evconnlistener* listener, evutil_socket_t fd,
	struct sockaddr* sa, int socklen, void* user_data)
{
	cout << "Create an connect" << endl;

	struct event_base* base = (event_base*)user_data;
	struct bufferevent* bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		cout << "Error constructing bufferevent!" << endl;
		event_base_loopbreak(base);
		return;
	}
	bufferevent_setcb(bev, NULL, conn_writecb, conn_eventcb, NULL);
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_disable(bev, EV_READ);

	bufferevent_write(bev, MESSAGE, strlen(MESSAGE));
}

static void
signal_cb(evutil_socket_t sig, short events, void* user_data)
{
	struct event_base* base = (event_base*)user_data;
	struct timeval delay = { 2, 0 };
	cout << "Caught an interrupt signal; exiting cleanly in two seconds." << endl;
	event_base_loopexit(base, &delay);
}

int
hello_main()
{
	/** 默认调用方已启动Winsock */

	struct event_base* base = event_base_new();
	if (!base) {
		cout << "Could not initialize base!" << endl;
		return 1;
	}
	struct sockaddr_in sin = { 0 };
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
	sin.sin_addr.s_addr = inet_addr(IP);

	struct evconnlistener* listener = evconnlistener_new_bind(base, listener_cb,
		(void*)base, LEV_OPT_CLOSE_ON_FREE, -1,
		(struct sockaddr*)&sin, sizeof(sin));
	if (!listener) {
		cout << "Could not create a listener!" << endl;
		return 1;
	}

	struct event* signal_event = evsignal_new(base, SIGINT, signal_cb, (void*)base);
	if (!signal_event || event_add(signal_event, NULL) < 0) {
		cout << "Could not create/add a signal event!" << endl;
		return 1;
	}

	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_free(signal_event);
	event_base_free(base);
	cout << "done" << endl;

	return 0;
}