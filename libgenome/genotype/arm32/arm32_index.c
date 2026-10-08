/*
 * arm32_index.c - the first-level index of the ARM state and Thumb state decoders,
 * derived from the hand-written rows (arm32_rows.c, thumb_rows.c) by code, once,
 * the first time a decode needs it. See arm32_int.h for what it is and how the
 * guard works.
 *
 * For every value of the index key it lists, in priority order, the rows that can
 * match a word with that key, and stops after the first row the key alone
 * decides. Identical lists share storage. All storage is static; there is no
 * allocation. The capacity is fixed and checked by tests/unit/genotype_arm32.c,
 * which fails when the tables outgrow it - and if they ever did in a shipped
 * build the builder aborts rather than answer from a truncated list.
 */
#include <stdlib.h>
#include <string.h>

#include "arm32_ids.h"
#include "thumb_ids.h"
#include "arm32_int.h"

#define ARM_POOL 2048u
#define THUMB_POOL 2048u
#define MAXLIST 64u
#define MAXROWS 1024u

struct gt_arm32_row gt_arm32_lists[ARM_POOL];
uint16_t gt_arm32_idx[2 * GT_ARM32_KEYS];
struct gt_arm32_row gt_thumb_lists[THUMB_POOL];
uint16_t gt_thumb_idx_narrow[GT_THUMB_NARROW_KEYS];
uint16_t gt_thumb_idx_wide[GT_THUMB_WIDE_KEYS];

atomic_int gt_arm32_state, gt_thumb_state;

static unsigned g_pool_arm32, g_pool_thumb;
static unsigned g_shadowed_arm32, g_shadowed_thumb;

static unsigned key_arm32(uint32_t w) { return gt_arm32_key12(w); }
static unsigned key_narrow(uint32_t w) { return gt_thumb_narrow_key(w); }
static unsigned key_wide(uint32_t w) { return gt_thumb_wide_key(w); }

/*
 * One index. `keyf` maps a word to its key; `pre_mask`/`pre_val` are bits every
 * word of this table has fixed (the unconditional space's 1111); `direct` allows
 * the by-name entries. `hits` counts, per row, the keys that reach it. Returns
 * the pool use.
 */
static void build_one(const struct gt_arm32_row *rows, unsigned nrows, unsigned keys,
		      unsigned (*keyf)(uint32_t), uint32_t pre_mask, uint32_t pre_val,
		      int direct, struct gt_arm32_row *pool, unsigned cap, unsigned *used,
		      uint16_t *idx, unsigned char *hits)
{
	uint32_t keybit[32], keymask = 0;
	unsigned b, k, j, i, prev_start = 0, prev_n = 0;

	if (nrows > MAXROWS)
		abort();
	for (b = 0; b < 32; b++) {
		keybit[b] = keyf(1u << b);
		if (keybit[b])
			keymask |= 1u << b;
	}
	for (k = 0; k < keys; k++) {
		struct gt_arm32_row list[MAXLIST];
		unsigned n = 0, found = ~0u;
		uint32_t wk = pre_val;
		int decided = 0;

		for (b = 0; b < 32; b++)
			if (keybit[b] & k)
				wk |= 1u << b;
		memset(list, 0, sizeof list);   /* padding too: lists are compared bytewise */
		for (j = 0; j < nrows && !decided; j++) {
			const struct gt_arm32_row *r = &rows[j];

			if ((wk ^ r->value) & r->mask & (keymask | pre_mask))
				continue;
			hits[j] = 1;
			if (n >= MAXLIST)
				abort();
			list[n++] = *r;
			if (!(r->mask & ~(keymask | pre_mask)))
				decided = 1;
		}
		if (!decided)
			n++;            /* the zeroed row: mask 0, name 0 (INVALID) */
		if (direct && n == 1 && decided) {
			idx[k] = (uint16_t)(GT_ARM32_DIRECT | list[0].id);
			continue;
		}
		/* neighbouring keys mostly share a list: try the last one first */
		if (prev_n == n && !memcmp(&pool[prev_start], list, n * sizeof list[0])) {
			found = prev_start;
		} else {
			for (i = 0; i + n <= *used; i++)
				if (!memcmp(&pool[i], list, n * sizeof list[0])) {
					found = i;
					break;
				}
		}
		if (found == ~0u) {
			if (*used + n > cap)
				abort();
			found = *used;
			memcpy(&pool[found], list, n * sizeof list[0]);
			*used += n;
		}
		if (found >= GT_ARM32_DIRECT)
			abort();
		idx[k] = (uint16_t)found;
		prev_start = found;
		prev_n = n;
	}
}

static unsigned count_dead(const unsigned char *hits, unsigned n)
{
	unsigned i, dead = 0;

	for (i = 0; i < n; i++)
		dead += !hits[i];
	return dead;
}

/* Wait for whoever is building; take the job if nobody is. Returns 1 for the builder. */
static int claim(atomic_int *state)
{
	int expect = 0;

	if (atomic_compare_exchange_strong_explicit(state, &expect, 1, memory_order_acq_rel,
						    memory_order_acquire))
		return 1;
	while (atomic_load_explicit(state, memory_order_acquire) != 2)
		;
	return 0;
}

void gt_arm32_build(void)
{
	static unsigned char hc[MAXROWS], hu[MAXROWS];
	unsigned used = 0;

	if (!claim(&gt_arm32_state))
		return;
	memset(hc, 0, sizeof hc);
	memset(hu, 0, sizeof hu);
	build_one(gt_arm32_src_cond, gt_arm32_src_cond_n, GT_ARM32_KEYS, key_arm32, 0, 0, 0,
		  gt_arm32_lists, ARM_POOL, &used, gt_arm32_idx, hc);
	build_one(gt_arm32_src_unc, gt_arm32_src_unc_n, GT_ARM32_KEYS, key_arm32, 0xf0000000u,
		  0xf0000000u, 0, gt_arm32_lists, ARM_POOL, &used, gt_arm32_idx + GT_ARM32_KEYS, hu);
	g_pool_arm32 = used;
	g_shadowed_arm32 = count_dead(hc, gt_arm32_src_cond_n) + count_dead(hu, gt_arm32_src_unc_n);
	atomic_store_explicit(&gt_arm32_state, 2, memory_order_release);
}

void gt_thumb_build(void)
{
	static unsigned char hn[MAXROWS], hw[MAXROWS];
	unsigned used = 0;

	if (!claim(&gt_thumb_state))
		return;
	memset(hn, 0, sizeof hn);
	memset(hw, 0, sizeof hw);
	build_one(gt_thumb_src_narrow, gt_thumb_src_narrow_n, GT_THUMB_NARROW_KEYS, key_narrow, 0, 0,
		  1, gt_thumb_lists, THUMB_POOL, &used, gt_thumb_idx_narrow, hn);
	build_one(gt_thumb_src_wide, gt_thumb_src_wide_n, GT_THUMB_WIDE_KEYS, key_wide, 0, 0, 1,
		  gt_thumb_lists, THUMB_POOL, &used, gt_thumb_idx_wide, hw);
	g_pool_thumb = used;
	g_shadowed_thumb = count_dead(hn, gt_thumb_src_narrow_n) + count_dead(hw, gt_thumb_src_wide_n);
	atomic_store_explicit(&gt_thumb_state, 2, memory_order_release);
}

void gt_arm32_stats(struct gt_arm32_stats *out)
{
	gt_arm32_build();
	gt_thumb_build();
	out->shadowed_arm32 = g_shadowed_arm32;
	out->shadowed_thumb = g_shadowed_thumb;
	out->lists_arm32 = g_pool_arm32;
	out->lists_thumb = g_pool_thumb;
	out->cap_arm32 = ARM_POOL;
	out->cap_thumb = THUMB_POOL;
}
