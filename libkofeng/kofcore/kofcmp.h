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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

/*
 * THE FIRST ELEMENT WHOSE KEY IS NOT BELOW `key`, in `n` elements of `stride` bytes sorted by the uint64_t that lies `off` bytes
 * into each (the lower bound: n when every key is below). Four tables of the lineage stages, the codemap, the fingerprint
 * reference and the PDF index each wrote this loop; the caller gives the offset with offsetof, so a moved key is a compile error
 * where the loop would have read the wrong field.
 */
static inline uint32_t kof_lower_bound_u64(const void *base, uint32_t n, size_t stride, size_t off, uint64_t key)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;
		uint64_t k;

		memcpy(&k, (const char *)base + (size_t)mid * stride + off, sizeof k);
		if (k < key)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo;
}

/*
 * THE FIRST ELEMENT THAT ENDS ABOVE `x`, in `n` elements of `stride` bytes sorted by the end of the extent each holds (a uint64_t
 * start `off_at` bytes in and a uint64_t length `len_at` bytes in): the one that holds x if any does, and whichever of
 * the overlapping ones ends first when they nest. n when none ends above.
 */
static inline uint32_t kof_first_ending_above_u64(const void *base, uint32_t n, size_t stride, size_t off_at, size_t len_at, uint64_t x)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;
		const char *e = (const char *)base + (size_t)mid * stride;
		uint64_t a, l;

		memcpy(&a, e + off_at, sizeof a);
		memcpy(&l, e + len_at, sizeof l);
		if (a + l <= x)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo;
}

#endif /* KOFENG_KOFCMP_H */
