/*
 * grow_cap - kgenome_grow_cap, the one spelling of "double a uint32 capacity" the lib's tables use (REV-D8d, -D8e, -D8g, -D8i..-D8q).
 *
 * Twelve tables wrote `cap ? cap * 2u : first`, which wraps to 0 or to a smaller number when cap is above 2^31, and the table was then written
 * past its end. Not reproducible at the sinks (2^31 elements are 2 GiB or more of input and the engine caps an object at 512 MiB), so the
 * property is pinned where it lives: exhaustive over the powers of two and the edges around 2^31, and a mutant of the old spelling must fail it.
 */
#include <stdio.h>
#include <stdint.h>

#include <kgenome_budget.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t old_spelling(uint32_t cap, uint32_t first)
{
	return cap ? cap * 2u : first;
}

int main(void)
{
	uint32_t c;
	unsigned k;

	CK(kgenome_grow_cap(0, 64u) == 64u);
	CK(kgenome_grow_cap(1, 64u) == 2u);
	for (k = 1; k < 31; k++) {
		c = 1u << k;
		CK(kgenome_grow_cap(c, 8u) == c * 2u);
		CK(kgenome_grow_cap(c - 1u, 8u) == (c - 1u) * 2u);
	}
	CK(kgenome_grow_cap(0x40000000u, 8u) == 0x80000000u);   /* the last doubling that fits */
	CK(kgenome_grow_cap(0x7fffffffu, 8u) == 0xfffffffeu);
	CK(kgenome_grow_cap(0x80000000u, 8u) == 0u);            /* would be 0: refused */
	CK(kgenome_grow_cap(0x80000001u, 8u) == 0u);            /* would be 2: refused */
	CK(kgenome_grow_cap(0xffffffffu, 8u) == 0u);
	/* the mutant: the old spelling answers a wrapped number exactly where the helper refuses */
	CK(old_spelling(0x80000000u, 8u) == 0u && old_spelling(0x80000001u, 8u) == 2u);
	CK(old_spelling(0xffffffffu, 8u) == 0xfffffffeu);
	if (fails) {
		printf("grow_cap: %d failure(s)\n", fails);
		return 1;
	}
	printf("grow_cap: ok\n");
	return 0;
}
