/*
 * heapsort.h - the in-place, allocation-free sort of a record array, written once.
 *
 * Three tables in core are sorted by the same algorithm: the range list
 * (rangelist.h), the claim table (rangelist.h) and the run list (runlist.h).
 * Each carried its own copy of the sift and the sort, identical but for the record
 * type and the comparison. KOF_HEAPSORT(name, T, before) is the one definition: it
 * expands to `name_sift` and `name_sort` for records of type T ordered by
 * `before(const T *a, const T *b)` (nonzero when a must come first).
 *
 * WHY HEAPSORT AND WHY THE ORDER CHECK FIRST. The order comes from the file - a
 * table of segments, sections, entries or runs is stated in whatever order the
 * object likes - so insertion sort is linear on the ordinary case and quadratic on
 * one built to be reversed, which costs milliseconds per resolve at the caps and a
 * resolve happens per region per object. One pass checks whether anything is out of
 * order, which keeps the ordinary file at O(n); heapsort takes the rest: O(n log n)
 * with no input that defeats it, in place, and with no allocation on a path that
 * has nowhere to report a failure.
 *
 * A macro and not a function over void* and a size: the swap of a 16-byte or
 * 32-byte record and the comparison are inlined into the loop, which is the reason
 * these were `static inline` in the first place - this is on the resolve path.
 */
#ifndef KOFENG_HEAPSORT_H
#define KOFENG_HEAPSORT_H

#include <stdint.h>

#define KOF_HEAPSORT(name, T, before)                                          \
static inline void name##_sift(T *v, uint32_t root, uint32_t n)                \
{                                                                              \
	for (;;) {                                                             \
		uint32_t big = root, l = 2u * root + 1u, r = l + 1u;           \
									       \
		if (l < n && before(&v[big], &v[l]))                           \
			big = l;                                               \
		if (r < n && before(&v[big], &v[r]))                           \
			big = r;                                               \
		if (big == root)                                               \
			return;                                                \
		{                                                              \
			T t = v[root];                                         \
									       \
			v[root] = v[big];                                      \
			v[big] = t;                                            \
		}                                                              \
		root = big;                                                    \
	}                                                                      \
}                                                                              \
									       \
static inline void name##_sort(T *v, uint32_t n)                               \
{                                                                              \
	uint32_t i;                                                            \
									       \
	for (i = 1; i < n; i++)                                                \
		if (before(&v[i], &v[i - 1]))                                  \
			break;                                                 \
	if (i >= n)                                                            \
		return;                 /* already ordered: the usual case */  \
									       \
	for (i = n / 2u; i-- > 0; )                                            \
		name##_sift(v, i, n);                                          \
	for (i = n; i-- > 1; ) {                                               \
		T t = v[0];                                                    \
									       \
		v[0] = v[i];                                                   \
		v[i] = t;                                                      \
		name##_sift(v, 0, i);                                          \
	}                                                                      \
}

#endif /* KOFENG_HEAPSORT_H */
