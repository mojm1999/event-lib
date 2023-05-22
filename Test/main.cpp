#include <iostream>
#include <base.h>

#define cout std::cout
#define endl std::endl

int main()
{
	/** 设置环境变量 */
	putenv("EVENT_PRECISE_TIMER=1");

	/** 测试定时器 */
	struct event_base *base = event_base_new();
	ULONGLONG start64 = base->monotonic_timer.GetTickCount64_fn();
	cout << "start64: " << start64 << endl;
	ULONGLONG start = base->monotonic_timer.GetTickCount_fn();
	cout << "start: " << start << endl;

	struct evutil_monotonic_timer *timer = &base->monotonic_timer;
	cout << "use_performance: " << timer->use_performance_counter << endl;
	cout << "performance_counter: " << timer->first_counter <<
		"	performance_usec_per: " << timer->usec_per_count << endl;

	cout << "last_updated_clock_diff: " << base->last_updated_clock_diff <<
		"	tv_clock_diff: " << base->tv_clock_diff.tv_sec << endl;

	struct timeval tv;
	evutil_gettimeofday(&tv, NULL);
	cout << "gettimeofday_sec: " << tv.tv_sec <<
		"	gettimeofday_usec: " << tv.tv_usec << endl;

	Sleep(1*1000);
	evutil_gettime_monotonic_(&base->monotonic_timer, &tv);
	cout << "monotonic_sec: " << tv.tv_sec <<
		"	monotonic_usec: " << tv.tv_usec << endl;

	/** 测试小根堆 */
	min_heap_reserve_(&base->timeheap, 3);
	for (unsigned i = 0; i < 3; ++i) {
		struct event* e = (event*)calloc(1, sizeof(*e));
		min_heap_push_(&base->timeheap, e);
	}
	min_heap_pop_(&base->timeheap);
	return 0;
}