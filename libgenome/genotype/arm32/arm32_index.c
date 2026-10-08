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
 * One index, built by walking the key's bits from the top instead of trying every
 * key against every row.
 *
 * The old builder took each of the 8192 ARM state keys (1024 Thumb) and tested it
 * against every row of the table. MEASURED on the 300 KB ARM sample (callgrind,
 * whole scan 45.4 M Ir) that was 19.8 M Ir, 44% of the scan, spent on the first
 * decode - and the answer for most keys is the same list as the key beside it.
 * The walk fixes one key bit at a time, keeping only the rows still compatible;
 * when no row of the list (up to the one the key decides) looks at a bit not yet
 * fixed, every key below is the same list, which is built once and written to the
 * whole run of keys. Keys are still reached in increasing order and the pool is
 * filled the same way, so the tables are byte for byte what the old builder made
 * (checked: the indexes, the pools and the shadowed-row counts hash equal before
 * and after).
 *
 * `pre_mask`/`pre_val` are bits every word of this table has fixed (the
 * unconditional space's 1111); `direct` allows the by-name entries. `hits` counts,
 * per row, the keys that reach it.
 *
 * WHY IT IS STILL BUILT WHOLE ON THE FIRST DECODE and not key by key on first
 * use: a lazy key needs the decoders to test the entry before they read it, and
 * those are arm32.h and thumb.h. The walk makes the whole build cheap enough
 * that it was left.
 */
struct bld {
	const struct gt_arm32_row *rows;
	unsigned nbits;
	uint32_t keymask, pre_mask;
	unsigned kbit[16];              /* the word bit each key bit comes from */
	int direct;
	struct gt_arm32_row *pool;
	unsigned cap, *used;
	uint16_t *idx;
	unsigned char *hits;
	unsigned prev_start, prev_n;
};

/* The pool entry (or the by-name entry) for the list the candidates make; the
 * rows it reaches are marked. */
static uint16_t bld_emit(struct bld *x, const uint16_t *cand, unsigned nc)
{
	struct gt_arm32_row list[MAXLIST + 1u];
	unsigned n = 0, found = ~0u, i, c;
	int decided = 0;

	for (c = 0; c < nc && !decided; c++) {
		const struct gt_arm32_row *r = &x->rows[cand[c]];

		x->hits[cand[c]] = 1;
		if (n >= MAXLIST)
			abort();
		memset(&list[n], 0, sizeof list[n]);    /* padding too: lists are compared bytewise */
		list[n].mask = r->mask;
		list[n].value = r->value;
		list[n].id = r->id;
		n++;
		if (!(r->mask & ~(x->keymask | x->pre_mask)))
			decided = 1;
	}
	if (!decided) {
		memset(&list[n], 0, sizeof list[n]);    /* mask 0, name 0 (INVALID) */
		n++;
	}
	if (x->direct && n == 1 && decided)
		return (uint16_t)(GT_ARM32_DIRECT | list[0].id);
	/* neighbouring keys mostly share a list: try the last one first */
	if (x->prev_n == n && !memcmp(&x->pool[x->prev_start], list, n * sizeof list[0])) {
		found = x->prev_start;
	} else {
		for (i = 0; i + n <= *x->used; i++)
			if (!memcmp(&x->pool[i], list, n * sizeof list[0])) {
				found = i;
				break;
			}
	}
	if (found == ~0u) {
		if (*x->used + n > x->cap)
			abort();
		found = *x->used;
		memcpy(&x->pool[found], list, n * sizeof list[0]);
		*x->used += n;
	}
	if (found >= GT_ARM32_DIRECT)
		abort();
	x->prev_start = found;
	x->prev_n = n;
	return (uint16_t)found;
}

/* `bit` is the next key bit to fix (counting down), `kk` the key so far. */
static void bld_walk(struct bld *x, int bit, unsigned kk, const uint16_t *cand, unsigned nc)
{
	uint32_t rest = 0;
	unsigned c;
	int b, free_bits = 0;

	for (b = 0; b <= bit; b++)
		rest |= 1u << x->kbit[b];
	/* Does anything the list is made of look at a bit not yet fixed? */
	for (c = 0; c < nc; c++) {
		const struct gt_arm32_row *r = &x->rows[cand[c]];

		if (r->mask & rest) {
			free_bits = 1;
			break;
		}
		if (!(r->mask & ~(x->keymask | x->pre_mask)))
			break;          /* decided: the list ends here */
	}
	if (bit < 0 || !free_bits) {
		uint16_t v = bld_emit(x, cand, nc);
		unsigned run = 1u << (bit + 1), k;

		for (k = 0; k < run; k++)
			x->idx[kk + k] = v;
		return;
	}
	{
		uint16_t sub[MAXROWS];
		unsigned v;

		for (v = 0; v < 2u; v++) {
			unsigned n = 0;

			for (c = 0; c < nc; c++) {
				const struct gt_arm32_row *r = &x->rows[cand[c]];

				if (((r->mask >> x->kbit[bit]) & 1u) &&
				    ((r->value >> x->kbit[bit]) & 1u) != v)
					continue;
				sub[n++] = cand[c];
			}
			bld_walk(x, bit - 1, kk | (v << bit), sub, n);
		}
	}
}

static void build_one(const struct gt_arm32_row *rows, unsigned nrows, unsigned keys,
		      unsigned (*keyf)(uint32_t), uint32_t pre_mask, uint32_t pre_val,
		      int direct, struct gt_arm32_row *pool, unsigned cap, unsigned *used,
		      uint16_t *idx, unsigned char *hits)
{
	struct bld x;
	uint16_t cand[MAXROWS];
	unsigned b, j, nc = 0;

	if (nrows > MAXROWS)
		abort();
	memset(&x, 0, sizeof x);
	x.rows = rows;
	x.pre_mask = pre_mask;
	x.direct = direct;
	x.pool = pool;
	x.cap = cap;
	x.used = used;
	x.idx = idx;
	x.hits = hits;
	while ((1u << x.nbits) < keys)
		x.nbits++;
	if ((1u << x.nbits) != keys || x.nbits > 16u)
		abort();
	for (b = 0; b < 32; b++) {
		unsigned kb = keyf(1u << b), i = 0;

		if (!kb)
			continue;
		if (kb & (kb - 1u))
			abort();        /* a word bit that feeds two key bits */
		while ((1u << i) != kb)
			i++;
		x.kbit[i] = b;
		x.keymask |= 1u << b;
	}
	/* The rows the fixed bits allow, in priority order. */
	for (j = 0; j < nrows; j++)
		if (!((pre_val ^ rows[j].value) & rows[j].mask & pre_mask))
			cand[nc++] = (uint16_t)j;
	bld_walk(&x, (int)x.nbits - 1, 0, cand, nc);
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
