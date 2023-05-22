#pragma once
#ifndef HASHTABLE_H_INCLUDED_
#define HASHTABLE_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#define HT_HEAD(name, type)				\
struct name {						\
	struct type **hth_table;			\
	unsigned hth_table_length;	\
	unsigned hth_n_entries;			\
	unsigned hth_load_limit; /** 限制元素个数 */	\
	int hth_prime_idx; /** 素数表位置 */		\
}

#define HT_ENTRY(type)			\
struct {					\
	struct type *hte_next;			\
}

#define HT_EMPTY(head)				((head)->hth_n_entries == 0)
#define HT_SIZE(head)				((head)->hth_n_entries)

#define HT_FIND(name, head, elm)     name##_HT_FIND((head), (elm))
#define HT_INIT(name, head)			name##_HT_INIT(head)

#define HT_ELT_HASH_(elm, field, hashfn)	\
	(hashfn(elm))
#define HT_BUCKET_(head, field, elm, hashfn)			\
	((head)->hth_table[HT_ELT_HASH_(elm,field,hashfn) % head->hth_table_length])


#define HT_PROTOTYPE(name, type, field, hashfn, eqfn)				\
static inline void												\
name##_HT_INIT(struct name *head) {							\
	head->hth_table_length = 0;										\
	head->hth_table = NULL;										\
	head->hth_n_entries = 0;								\
	head->hth_load_limit = 0;										\
	head->hth_prime_idx = -1;									\
}															\
static inline struct type **                                          \
name##_HT_FIND_P_(struct name *head, struct type *elm)		\
{                                                                     \
	struct type **p;                                                    \
	if (!head->hth_table)                                               \
		return NULL;                                                      \
	p = &HT_BUCKET_(head, field, elm, hashfn);				\
	while (*p) {                                                        \
		if (eqfn(*p, elm))                                                \
			return p;                                                       \
		p = &(*p)->field.hte_next;                                        \
	}                                                                   \
	return p;                                                           \
}															\
static inline struct type *                                           \
name##_HT_FIND(const struct name *head, struct type *elm)             \
{                                                                     \
	struct type **p;                                                    \
	struct name *h = (struct name *) head;                              \
	p = name##_HT_FIND_P_(h, elm);							\
	return p ? *p : NULL;                                               \
}                                                                     \



#ifdef __cplusplus
}
#endif

#endif /* HASHTABLE_H_INCLUDED_ */