#ifndef KGENOME_IMAGE_CMP_H
#define KGENOME_IMAGE_CMP_H

/*
 * cmp.h - the one qsort/bsearch comparator on a 64-bit key.
 *
 * Four places sorted or searched an array by a uint64_t (a relocation's `where`,
 * an import's slot, a plain address list in the emulator and in the wrapper
 * walk), each with its own three-line comparator. This compares the uint64_t AT
 * THE START of each element, so an array of structs uses it when the key is the
 * struct's FIRST member - the caller says so with a _Static_assert on offsetof,
 * so moving the key is a compile error and not a silent wrong order.
 *
 * Only for a key that is the whole ordering. A comparator that breaks ties
 * (funcs.c's longer-extent-first, diag_sym.c's address then index) stays its own,
 * because its second key is a decision.
 */

#include <stdint.h>

static inline int kgenome_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

#endif /* KGENOME_IMAGE_CMP_H */
