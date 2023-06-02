#include <iostream>
#include <base.h>

#define cout std::cout
#define endl std::endl

static const int PORT = 9995;
static const char IP[] = "127.0.0.1";

static void
listener_cb(struct evconnlistener* listener, evutil_socket_t fd,
	struct sockaddr* sa, int socklen, void* user_data)
{
	struct event_base* base = (event_base*)user_data;
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

	event_base_dispatch(base);
}