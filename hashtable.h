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

#define HT_INIT(name, head)			name##_HT_INIT(head)
#define HT_FIND(name, head, elm)     name##_HT_FIND((head), (elm))
#define HT_INSERT(name, head, elm)   name##_HT_INSERT((head), (elm))
#define HT_REMOVE(name, head, elm)   name##_HT_REMOVE((head), (elm))
#define HT_START(name, head)         name##_HT_START(head)
#define HT_NEXT(name, head, elm)     name##_HT_NEXT((head), (elm))

#define HT_ELT_HASH_(elm, field, hashfn)	\
	(hashfn(elm))
#define HT_BUCKET_(head, field, elm, hashfn)			\
	((head)->hth_table[HT_ELT_HASH_(elm,field,hashfn) % head->hth_table_length])

#define HT_FOREACH(x, name, head)                 \
	for ((x) = HT_START(name, head);                \
       (x) != NULL;                               \
       (x) = HT_NEXT(name, head, x))


/* 哈希表结构名，元素类型， next字段名，散列函数，对比函数 */
#define HT_PROTOTYPE(name, type, field, hashfn, eqfn)				\
	int name##_HT_GROW(struct name *ht, unsigned min_capacity);           \
	void name##_HT_CLEAR(struct name *ht);                                \
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
	if (!head->hth_table)                                               \
		return NULL;                                                      \
	struct type **p = &HT_BUCKET_(head, field, elm, hashfn);				\
	while (*p) {                                                        \
		if (eqfn(*p, elm))                                                \
			return p;                                                       \
		p = &(*p)->field.hte_next;                                        \
	}                                                                   \
	return p;                                                           \
}															\
static inline struct type *                                           \
name##_HT_FIND(struct name *head, struct type *elm)             \
{                                                                     \
	struct type **p = name##_HT_FIND_P_(head, elm);							\
	return p ? *p : NULL;                                               \
}                                                                     \
static inline void															\
name##_HT_INSERT(struct name *head, struct type *elm)					\
{																			\
	if (!head->hth_table || head->hth_n_entries >= head->hth_load_limit) \
		name##_HT_GROW(head, head->hth_n_entries+1);                      \
	++head->hth_n_entries;                                              \
	struct type **p = &HT_BUCKET_(head, field, elm, hashfn);				\
	elm->field.hte_next = *p;                                           \
	*p = elm;                                                           \
}																	\
static inline struct type *                                                   \
name##_HT_REMOVE(struct name *head, struct type *elm)                 \
{                                                                     \
	struct type **p = name##_HT_FIND_P_(head, elm);					\
	if (!p || !*p)														\
		return ;													\
	struct type *tmp = *p;												\
	*p = tmp->field.hte_next;										\
	tmp->field.hte_next = NULL;											\
	--head->hth_n_entries;                                              \
	return tmp;														\
}																		\
static inline struct type **                                          \
name##_HT_START(struct name *head)                                    \
{                                                                     \
	unsigned b = 0;														\
	while (b < head->hth_table_length) {							\
		if (head->hth_table[b])                                           \
			return &head->hth_table[b];                                     \
		++b;                                                              \
	}                                                                   \
	return NULL;                                                        \
}                                                                     \
static inline struct type **                                          \
name##_HT_NEXT(struct name *head, struct type **elm)                  \
{                                                                     \
	if ((*elm)->field.hte_next) {                                       \
		return &(*elm)->field.hte_next;                                   \
	} else {                                                            \
		unsigned b = (HT_ELT_HASH_(*elm, field, hashfn) % head->hth_table_length)+1; \
		while (b < head->hth_table_length) {                              \
			if (head->hth_table[b])                                         \
				return &head->hth_table[b];                                   \
			++b;                                                            \
		}                                                                 \
		return NULL;                                                      \
	}                                                                   \
}																			\


#define HT_GENERATE(name, type, field, hashfn, eqfn,					\
                    load, mallocfn, reallocfn, freefn)				\
static unsigned name##_PRIMES[] = {                                   \
	53, 97, 193, 389,                                                   \
	769, 1543, 3079, 6151,                                              \
	12289, 24593, 49157, 98317,                                         \
	196613, 393241, 786433, 1572869,                                    \
	3145739, 6291469, 12582917, 25165843,                               \
	50331653, 100663319, 201326611, 402653189,                          \
	805306457, 1610612741                                               \
};                                                                    \
static unsigned name##_N_PRIMES =                                     \
	(unsigned)(sizeof(name##_PRIMES)/sizeof(name##_PRIMES[0]));         \
int                                                                   \
name##_HT_GROW(struct name *head, unsigned size)                      \
{                                                                     \
	if (head->hth_load_limit > size)                                    \
		return 0;                                                         \
	if (head->hth_prime_idx == (int)name##_N_PRIMES - 1)                \
		return 0;                                                         \
	int prime_idx = head->hth_prime_idx;                                    \
	unsigned new_len, new_load_limit;                                   \
	do {                                                                \
		new_len = name##_PRIMES[++prime_idx];                             \
		new_load_limit = (unsigned)(load*new_len);                        \
	} while (new_load_limit <= size &&                                  \
				prime_idx < (int)name##_N_PRIMES);                         \
	struct type **new_table;                                            \
	if ((new_table = mallocfn(new_len*sizeof(struct type*)))) {         \
		memset(new_table, 0, new_len*sizeof(struct type*));               \
		for (unsigned b = 0; b < head->hth_table_length; ++b) {                \
			struct type *elm, *next;                                        \
			unsigned b2;                                                    \
			elm = head->hth_table[b];                                       \
			while (elm) {                                                   \
				next = elm->field.hte_next;                                   \
				b2 = HT_ELT_HASH_(elm, field, hashfn) % new_len;              \
				elm->field.hte_next = new_table[b2];                          \
				new_table[b2] = elm;                                          \
				elm = next;                                                   \
			}                                                               \
		}                                                                 \
		if (head->hth_table)                                              \
			freefn(head->hth_table);                                        \
	}																		\
	else {																		\
		new_table = reallocfn(head->hth_table, new_len*sizeof(struct type*)); \
		if (!new_table) return -1;                                        \
		memset(new_table + head->hth_table_length, 0,                     \
				(new_len - head->hth_table_length)*sizeof(struct type*));  \
		unsigned b, b2;                                                   \
		for (b=0; b < head->hth_table_length; ++b) {                      \
			struct type *e, **pE;                                           \
			for (pE = &new_table[b], e = *pE; e != NULL; e = *pE) {         \
				b2 = HT_ELT_HASH_(e, field, hashfn) % new_len;                \
				if (b2 == b) {                                                \
					pE = &e->field.hte_next;                                    \
				}																\
				else {                                                      \
					*pE = e->field.hte_next;                                    \
					e->field.hte_next = new_table[b2];                          \
					new_table[b2] = e;                                          \
				}                                                             \
			}                                                               \
		}                                                                 \
	}                                                                   \
	head->hth_table = new_table;                                      \
	head->hth_table_length = new_len;                                   \
	head->hth_prime_idx = prime_idx;                                    \
	head->hth_load_limit = new_load_limit;                              \
	return 0;                                                           \
}                                                                     \
void                                                                  \
name##_HT_CLEAR(struct name *head)                                    \
{                                                                     \
	if (head->hth_table)                                                \
		freefn(head->hth_table);                                          \
	name##_HT_INIT(head);                                               \
}

/** 表类型名，字段名，散列函数，表头，元素类型，
* 目标元素，变量命名，执行y，执行n */
#define HT_FIND_OR_INSERT_(name, field, hashfn, head, eltype, elm, var, y, n) \
{                                                                     \
	struct name *var##_head_ = head;                                    \
	if (!var##_head_->hth_table || var##_head_->hth_n_entries >= var##_head_->hth_load_limit)      \
		name##_HT_GROW(var##_head_, var##_head_->hth_n_entries+1);        \
	struct eltype **var = name##_HT_FIND_P_(var##_head_, (elm));              \
	if (*var) {                                                         \
		y;                                                                \
	} else {                                                            \
		n;                                                                \
	}                                                                   \
}

#define HT_FOI_INSERT_(field, head, elm, newent, var)       \
{                                                         \
	newent->field.hte_next = NULL;                          \
	*var = newent;                                          \
	++((head)->hth_n_entries);                              \
}


#ifdef __cplusplus
}
#endif

#endif /* HASHTABLE_H_INCLUDED_ */