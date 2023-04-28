#include <iostream>
#include <base.h>

#define cout std::cout
#define endl std::endl

int main()
{
	struct event_base *base = event_base_new();
	ULONGLONG start64 = base->monotonic_timer.GetTickCount64_fn();
	cout << "start64: " << start64 << endl;
	ULONGLONG start = base->monotonic_timer.GetTickCount_fn();
	cout << "start: " << start << endl;
	return 0;
}