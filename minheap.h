#pragma once
#ifndef MINHEAP_H_INCLUDED_
#define MINHEAP_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include <base.h>

typedef struct min_heap
{
	struct event **p;	/** ͷָ�� */
	unsigned n, a;		/** ��ǰ������������С */
} min_heap_t;

static inline void			min_heap_ctor_(min_heap_t *s);
static inline void			min_heap_dtor_(min_heap_t* s);
static inline void			min_heap_elem_init_(struct event* e);
static inline int			min_heap_empty_(min_heap_t* s);
static inline unsigned	    min_heap_size_(min_heap_t* s);
static inline struct event* min_heap_top_(min_heap_t* s);

static inline int	     min_heap_reserve_(min_heap_t* s, unsigned n);
static inline int	     min_heap_push_(min_heap_t* s, struct event* e);
static inline struct event* min_heap_pop_(min_heap_t* s);
static inline int	     min_heap_adjust_(min_heap_t* s, struct event* e);
static inline int	     min_heap_erase_(min_heap_t* s, struct event* e);
static inline void	     min_heap_shift_up_(min_heap_t* s, unsigned hole_index, struct event* e);
static inline void	     min_heap_shift_up_unconditional_(min_heap_t* s, unsigned hole_index, struct event* e);
static inline void	     min_heap_shift_down_(min_heap_t* s, unsigned hole_index, struct event* e);

#define min_heap_elem_greater(a, b) \
	(evutil_timercmp(&(a)->ev_timeout, &(b)->ev_timeout, >))

void min_heap_ctor_(min_heap_t *s) { s->p = 0; s->n = 0; s->a = 0; }
void min_heap_dtor_(min_heap_t* s) { if (s->p) free(s->p); }
void min_heap_elem_init_(struct event* e) { e->ev_timeout_pos.min_heap_idx = -1; }
int min_heap_empty_(min_heap_t* s) { return 0u == s->n; }
unsigned min_heap_size_(min_heap_t* s) { return s->n; }
struct event* min_heap_top_(min_heap_t* s) { return s->n ? *s->p : 0; }

int min_heap_reserve_(min_heap_t* s, unsigned n)
{
	if (s->a < n) {
		struct event** p;
		unsigned a = s->a ? s->a * 2 : 8;
		if (a < n)
			a = n;
#if (SIZE_MAX == UINT32_MAX)
		if (a > SIZE_MAX / sizeof * p)
			return -1;
#endif
		if (!(p = (struct event**)realloc(s->p, a * sizeof * p)))
			return -1;
		s->p = p;
		s->a = a;
	}
	return 0;
}

int min_heap_push_(min_heap_t* s, struct event* e)
{
	if (s->n == UINT32_MAX || min_heap_reserve_(s, s->n + 1))
		return -1;
	min_heap_shift_up_(s, s->n++, e);
	return 0;
}

void min_heap_shift_up_(min_heap_t* s, unsigned hole_index, struct event* e)
{
	unsigned parent = (hole_index - 1) / 2;
	while (hole_index && min_heap_elem_greater(s->p[parent], e))
	{
		(s->p[hole_index] = s->p[parent])->ev_timeout_pos.min_heap_idx = hole_index;
		hole_index = parent;
		parent = (hole_index - 1) / 2;
	}
	(s->p[hole_index] = e)->ev_timeout_pos.min_heap_idx = hole_index;
}

void min_heap_shift_up_unconditional_(min_heap_t* s, unsigned hole_index, struct event* e)
{
	unsigned parent = (hole_index - 1) / 2;
	do {
		(s->p[hole_index] = s->p[parent])->ev_timeout_pos.min_heap_idx = hole_index;
		hole_index = parent;
		parent = (hole_index - 1) / 2;
	} while (hole_index && min_heap_elem_greater(s->p[parent], e));
	(s->p[hole_index] = e)->ev_timeout_pos.min_heap_idx = hole_index;
}

struct event* min_heap_pop_(min_heap_t* s)
{
	if (s->n) {
		struct event* e = *s->p;
		min_heap_shift_down_(s, 0u, s->p[--s->n]);
		e->ev_timeout_pos.min_heap_idx = -1;
		return e;
	}
	return 0;
}

void min_heap_shift_down_(min_heap_t* s, unsigned hole_index, struct event* e)
{
	unsigned min_child = 2 * (hole_index + 1);
	while (min_child <= s->n)
	{
		min_child -= min_child == s->n || min_heap_elem_greater(s->p[min_child], s->p[min_child - 1]);
		if (!(min_heap_elem_greater(e, s->p[min_child])))
			break;
		(s->p[hole_index] = s->p[min_child])->ev_timeout_pos.min_heap_idx = hole_index;
		hole_index = min_child;
		min_child = 2 * (hole_index + 1);
	}
	(s->p[hole_index] = e)->ev_timeout_pos.min_heap_idx = hole_index;
}

int min_heap_adjust_(min_heap_t* s, struct event* e)
{
	if (-1 == e->ev_timeout_pos.min_heap_idx) {
		return min_heap_push_(s, e);
	}
	else {
		unsigned parent = (e->ev_timeout_pos.min_heap_idx - 1) / 2;

		if (e->ev_timeout_pos.min_heap_idx > 0 && min_heap_elem_greater(s->p[parent], e))
			min_heap_shift_up_unconditional_(s, e->ev_timeout_pos.min_heap_idx, e);
		else
			min_heap_shift_down_(s, e->ev_timeout_pos.min_heap_idx, e);
		return 0;
	}
}

int min_heap_erase_(min_heap_t* s, struct event* e)
{
	if (-1 != e->ev_timeout_pos.min_heap_idx)
	{
		struct event* last = s->p[--s->n];
		unsigned parent = (e->ev_timeout_pos.min_heap_idx - 1) / 2;

		if (e->ev_timeout_pos.min_heap_idx > 0 && min_heap_elem_greater(s->p[parent], last))
			min_heap_shift_up_unconditional_(s, e->ev_timeout_pos.min_heap_idx, last);
		else
			min_heap_shift_down_(s, e->ev_timeout_pos.min_heap_idx, last);
		e->ev_timeout_pos.min_heap_idx = -1;
		return 0;
	}
	return -1;
}


#ifdef __cplusplus
}
#endif

#endif /* MINHEAP_H_INCLUDED_ */