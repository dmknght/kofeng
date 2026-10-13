/*
 * mutation_pool.c - the pool, the sketch and the content-defined cut of a span of bytes.
 *
 * What a window is lives in mutation_window.h; what is made of windows is here.
 */

#include <stdlib.h>
#include <string.h>

#include <kofcmp.h>

#include "mutation.h"

uint32_t *kgenome_mutation_pool(const uint8_t *p, uint64_t n, uint32_t norm,
			  uint32_t *n_out)
{
	struct kgenome_mtn_win w;
	uint32_t *v, got = 0, k = 0;
	uint64_t room;

	if (n_out)
		*n_out = 0;
	if (!p || norm >= KGENOME_MUTATION_NORM_COUNT || !kgenome_mtn_win_begin(&w, p, n, norm))
		return NULL;
	room = w.n - KGENOME_MUTATION_NG + 1u;
	/* A span this size is not a block's input; refuse rather than wrap. */
	if (room > 0x3fffffffu)
		return NULL;
	v = malloc((size_t)room * sizeof *v);
	if (!v)
		return NULL;
	do {
		if (!kgenome_mtn_win_flat(&w))
			v[got++] = kgenome_mtn_win_value(&w);
	} while (kgenome_mtn_win_next(&w));
	if (!got) {
		free(v);
		return NULL;
	}
	qsort(v, got, sizeof *v, kof_cmp_u32);
	for (k = 1, room = 1; room < got; room++)
		if (v[room] != v[k - 1u])
			v[k++] = v[room];
	if (n_out)
		*n_out = k;
	return v;
}

/*
 * THE k SMALLEST OF THE POOL - what a block of one sample is, and the generator
 * every older block was made with, now spelled as what it always was. Returns
 * the values ascending and distinct, never more than K.
 */
uint32_t kgenome_mutation_minhash(const uint8_t *p, uint64_t n, uint32_t norm,
			    uint32_t *out)
{
	uint32_t np = 0, got, *pool = kgenome_mutation_pool(p, n, norm, &np);

	if (!pool)
		return 0;
	got = np < KGENOME_MUTATION_MINHASH_K ? np : KGENOME_MUTATION_MINHASH_K;
	memcpy(out, pool, got * sizeof *out);
	free(pool);
	return got;
}

void kgenome_mutation_member(const uint32_t *pool, uint32_t n_pool, const uint8_t *p,
		       uint64_t n, uint32_t norm, uint8_t *bits)
{
	struct kgenome_mtn_win w;
	uint64_t *bloom = NULL, nb = 1u << 12;
	uint32_t mask = 0;

	if (!pool || !n_pool || !p || !bits || norm >= KGENOME_MUTATION_NORM_COUNT ||
	    !kgenome_mtn_win_begin(&w, p, n, norm))
		return;
	/* Most windows of a sample are in no pool: a bit table says so without a
	 * search. Without room for it the search is simply done every time. */
	while (nb < (uint64_t)n_pool * 32u && nb < (1u << 24))
		nb <<= 1;
	bloom = calloc((size_t)(nb / 64u), sizeof *bloom);
	if (bloom) {
		uint32_t i;

		mask = (uint32_t)(nb - 1u);
		for (i = 0; i < n_pool; i++)
			bloom[(pool[i] & mask) >> 6] |=
				(uint64_t)1 << (pool[i] & 63u);
	}
	do {
		uint32_t v = kgenome_mtn_win_value(&w), lo = 0, hi = n_pool;

		if (v < pool[0] || v > pool[n_pool - 1u])
			continue;
		if (bloom &&
		    !((bloom[(v & mask) >> 6] >> (v & 63u)) & 1u))
			continue;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (pool[mid] < v)
				lo = mid + 1u;
			else
				hi = mid;
		}
		if (lo < n_pool && pool[lo] == v && !kgenome_mtn_win_flat(&w))
			bits[lo >> 3] |= (uint8_t)(1u << (lo & 7u));
	} while (kgenome_mtn_win_next(&w));
	free(bloom);
}

uint32_t kgenome_mutation_core(const uint32_t *pool, uint32_t n_pool,
			 const uint16_t *pos, uint32_t pos_need,
			 const uint16_t *bg, uint32_t bg_max, uint32_t k,
			 uint32_t *out)
{
	uint32_t i, got = 0;

	if (!pool || !pos || !out)
		return 0;
	/* The pool is ascending, so the first k that qualify are the k smallest. */
	for (i = 0; i < n_pool && got < k; i++)
		if (pos[i] >= pos_need && (!bg || bg[i] <= bg_max))
			out[got++] = pool[i];
	return got >= KGENOME_MUTATION_MIN_HASH ? got : 0u;
}

void kgenome_mutation_cut(const uint8_t *p, uint64_t len, uint32_t avg, uint32_t min,
		    uint32_t max, kgenome_mutation_cut_fn fn, void *user)
{
	uint32_t h = 0, drop = kgenome_mutation_drop_weight(), w;
	uint64_t at, cut = 0;

	for (w = 0; w < KGENOME_MUTATION_NG && w < len; w++)
		h = h * KGENOME_MUTATION_BASE + p[w];
	for (at = KGENOME_MUTATION_NG; at < len; at++) {
		int here = (kgenome_mutation_mix(h) & (avg - 1u)) == 0u;

		if ((here && at - cut >= min) || at - cut >= max) {
			if (fn(user, cut, at))
				return;
			cut = at;
		}
		h -= (uint32_t)p[at - KGENOME_MUTATION_NG] * drop;
		h = h * KGENOME_MUTATION_BASE + p[at];
	}
	/* And the tail, whatever is left of the span. */
	if (cut < len)
		(void)fn(user, cut, len);
}

