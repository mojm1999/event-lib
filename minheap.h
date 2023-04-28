#pragma once
#ifndef MINHEAP_H_INCLUDED_
#define MINHEAP_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include <base.h>

typedef struct min_heap
{
	struct event **p;
	unsigned n, a;
} min_heap_t;

static inline void			min_heap_ctor_(min_heap_t *s);
static inline void			min_heap_elem_init_(struct event* e);

void min_heap_ctor_(min_heap_t *s) { s->p = 0; s->n = 0; s->a = 0; }
void min_heap_elem_init_(struct event* e) { e->ev_timeout_pos.min_heap_idx = -1; }

#ifdef __cplusplus
}
#endif

#endif /* MINHEAP_H_INCLUDED_ */