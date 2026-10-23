/* See diag_oatab.h. */

#include <stdlib.h>
#include <string.h>

#include "diag_oatab.h"

uint64_t kgenome_oatab_seed(const uint8_t *text, uint64_t n, uintptr_t salt)
{
	uint64_t h = 0x243f6a8885a308d3ull ^ ((uint64_t)salt * KGENOME_OATAB_K) ^ (n * 0xff51afd7ed558ccdull), i = 0;

	if (text) {
		for (; i + 8u <= n; i += 8u) {
			uint64_t w;

			memcpy(&w, text + i, 8);
			h = (h ^ w) * KGENOME_OATAB_K;
			h ^= h >> 32;
		}
		for (; i < n; i++)
			h = kgenome_oatab_step(h, text[i]);
	}
	/* murmur3's 64-bit finaliser: the low bits of the seed are as good as the high ones, whatever the salt's own (an address ends in zeros) */
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdull;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ull;
	h ^= h >> 33;
	return h;
}

uint32_t kgenome_oatab_want(uint32_t n, uint32_t cap, uint32_t first)
{
	return cap && (n + 1u) * 2u <= cap ? 0u : (cap ? cap * 2u : first);
}

static int slot_empty(const uint8_t *p, size_t elem)
{
	size_t i;

	for (i = 0; i < elem; i++)
		if (p[i])
			return 0;
	return 1;
}

int kgenome_oatab_rehash(void **tab, uint32_t *cap, uint32_t nc, size_t elem, kgenome_oatab_hash_fn hash, void *ctx, uint64_t *work)
{
	uint8_t *nv = calloc(nc, elem), *old = *tab;
	uint32_t k, m;

	if (!nv)
		return 0;
	for (k = 0; k < *cap; k++) {
		const uint8_t *s = old + (size_t)k * elem;

		if (slot_empty(s, elem))
			continue;
		for (m = hash(ctx, s) & (nc - 1u); !slot_empty(nv + (size_t)m * elem, elem); m = kgenome_oatab_next(m, nc))
			if (work)
				++*work;
		memcpy(nv + (size_t)m * elem, s, elem);
	}
	free(*tab);
	*tab = nv;
	*cap = nc;
	return 1;
}
