/*
 * kofcmp.h - the one qsort/bsearch comparator on an unsigned key, 32 and 64 bit.
 *
 * In core because the engine, the lib and the tools each sorted a uint32_t or a
 * uint64_t array with a three-line comparator of their own. These compare the
 * integer AT THE START of each element, so an array of structs uses them when the
 * key is the struct's FIRST member - the caller says so with a _Static_assert on
 * offsetof, so moving the key is a compile error and not a silent wrong order.
 *
 * Only for a key that is the whole ordering. A comparator that breaks ties
 * (funcs.c's longer-extent-first, diag_sym.c's address then index) stays its own,
 * because its second key is a decision.
 */
#ifndef KOFENG_KOFCMP_H
#define KOFENG_KOFCMP_H

#include <stdint.h>

static inline int kof_cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static inline int kof_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

#endif /* KOFENG_KOFCMP_H */
