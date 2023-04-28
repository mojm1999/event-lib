#pragma once
#ifndef HASHTABLE_H_INCLUDED_
#define HASHTABLE_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#define HT_HEAD(name, type)				\
struct name {						\
	struct tyep **hth_table;			\
	unsigned hth_table_length;	\
	unsigned hth_n_entries;			\
	unsigned hth_load_limit;	\
	int hth_prime_idx;					\
}

#define HT_ENTRY(type)			\
struct {					\
	struct type *hte_next;			\
}

#define HT_INIT(name, head)			name##_HT_INIT(head)

#define HT_PROTOTYPE(name, type, field, hashfn, eqfn)				\
static inline void												\
name##_HT_INIT(struct name *head) {							\
	head->hth_table_length = 0;										\
	head->hth_table = NULL;										\
	head->hth_n_entries = 0;								\
	head->hth_load_limit = 0;										\
	head->hth_prime_idx = -1;									\
}

#ifdef __cplusplus
}
#endif

#endif /* HASHTABLE_H_INCLUDED_ */