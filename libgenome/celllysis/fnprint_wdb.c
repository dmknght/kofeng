/*
 * fnprint_wdb.c - the database side of the window stream, its per-scan context, and the pass that
 * rolls bytes through both.
 *
 * ONE ROLLING PASS, NO DECODE. Each window value is rejected by two cheap tests (the largest key of
 * the database, then a bit filter) before anything is looked up; the few that pass are asked of the
 * library table (so the window is credited to the LIB side or the USER side by what it IS) and then
 * of the sorted keys through a bucket index. This is the matcher's own shape (kofmutation.c) with
 * three changes, each one measured in fnprint_pred_eval.md: the keys are a plain array (4 bytes per
 * probe step, not 8), a bucket index replaces the binary search, and a bit per slot replaces the
 * stamp per pair.
 *
 * The credit is the matcher's credit: per OBJECT, the distinct (block, slot) pairs whose hash a window
 * of the object produced, on the block's side. A hot key (a window many blocks hold) is credited once
 * per object and side: its run is walked once, however many windows repeat it.
 */
#include "fnprint.h"

#include <stdlib.h>
#include <string.h>

#include "mutation.h"
#include "fnprint_private.h"

#define REF(b, s)   (((b) << 7) | (s))
#define REF_BLK(r)  ((r) >> 7)
#define REF_SLOT(r) ((r) & 127u)

static void *chg_alloc(struct kgenome_ledger *led, uint64_t n, uint64_t *sum, int zero)
{
	void *p;

	if (led && !kgenome_ledger_charge(led, n))
		return NULL;
	p = zero ? calloc(1, (size_t)n) : malloc((size_t)n);
	if (!p) {
		if (led)
			kgenome_ledger_release(led, n);
		return NULL;
	}
	*sum += n;
	return p;
}

/* LSD radix on the key (the high 32 bits of a pair word); stable, so equal keys stay in block order. */
static int radix_pairs(uint64_t *a, uint64_t n, struct kgenome_ledger *led)
{
	uint64_t *tmp, i, dummy = 0;
	uint32_t sh;

	tmp = chg_alloc(led, n * sizeof *tmp, &dummy, 0);
	if (!tmp)
		return 0;
	for (sh = 32; sh < 64; sh += 8) {
		uint64_t cnt[257];
		uint32_t d;

		memset(cnt, 0, sizeof cnt);
		for (i = 0; i < n; i++)
			cnt[((a[i] >> sh) & 0xffu) + 1u]++;
		for (d = 0; d < 256u; d++)
			if (cnt[d + 1u] == n)
				break;
		if (d < 256u)
			continue;
		for (d = 0; d < 256u; d++)
			cnt[d + 1u] += cnt[d];
		for (i = 0; i < n; i++)
			tmp[cnt[(a[i] >> sh) & 0xffu]++] = a[i];
		memcpy(a, tmp, (size_t)n * sizeof *a);
	}
	free(tmp);
	if (led)
		kgenome_ledger_release(led, n * sizeof *tmp);
	return 1;
}

static uint32_t clog2(uint64_t x)
{
	uint32_t b = 0;

	while (b < 63 && ((uint64_t)1 << b) < x)
		b++;
	return b;
}

static void fail(struct kgenome_fnprint_wdb *d, enum kgenome_status s)
{
	d->status = kgenome_status_merge(d->status, s);
}

static void set_filter(uint64_t *f, uint64_t mask, uint32_t key)
{
	uint64_t ix = key & mask;

	f[ix >> 6] |= (uint64_t)1 << (ix & 63u);
}

int kgenome_fnprint_wdb_build(struct kgenome_fnprint_wdb *d, const struct kgenome_fnprint_wblock *blk, uint32_t n_blk,
			      const uint32_t *pool, uint64_t n_pool, const struct kgenome_fnprint_wdb_opts *o)
{
	uint64_t np = 0, i, *pr = NULL, sum = 0, nbk;
	uint32_t b, j, bpk = o && o->filter_bits_per_hash ? o->filter_bits_per_hash : 32u, nt = o && o->n_tag ? o->n_tag : 1u;

	memset(d, 0, sizeof *d);
	d->led = o ? o->led : NULL;
	d->blk = blk; d->pool = pool; d->n_blk = n_blk; d->n_tag = nt;
	d->filter_bpk = bpk;
	if ((n_blk && (!blk || !pool)) || n_blk > KGENOME_FNP_WDB_MAX_BLOCKS) {
		fail(d, n_blk > KGENOME_FNP_WDB_MAX_BLOCKS ? KGENOME_TRUNCATED : KGENOME_BAD_INPUT);
		return 0;
	}
	for (b = 0; b < n_blk; b++) {
		if (!blk[b].n || blk[b].n > KGENOME_FNP_WDB_MAXN || blk[b].first > n_pool ||
		    blk[b].n > n_pool - blk[b].first || blk[b].tag >= nt) {
			fail(d, KGENOME_BAD_INPUT);
			return 0;
		}
		np += blk[b].n;
		if (blk[b].n > d->words * 32u)
			d->words = (blk[b].n + 31u) / 32u;
	}
	if (np >= 0xfffffff0ull) {              /* the bucket index holds 32-bit positions */
		fail(d, KGENOME_TRUNCATED);
		return 0;
	}
	d->n_pair = np;
	if (!np)
		return 1;
	pr = chg_alloc(d->led, np * sizeof *pr, &sum, 0);
	if (!pr)
		goto over;
	for (b = 0, i = 0; b < n_blk; b++)
		for (j = 0; j < blk[b].n; j++)
			pr[i++] = ((uint64_t)pool[blk[b].first + j] << 32) | REF(b, j);
	if (!radix_pairs(pr, np, d->led))
		goto over;
	d->key = chg_alloc(d->led, np * 4u, &d->bytes, 0);
	d->ref = chg_alloc(d->led, np * 4u, &d->bytes, 0);
	d->tag_pairs = chg_alloc(d->led, (uint64_t)nt * 8u, &d->bytes, 1);
	if (!d->key || !d->ref || !d->tag_pairs)
		goto over;
	for (i = 0; i < np; i++) {
		d->key[i] = (uint32_t)(pr[i] >> 32);
		d->ref[i] = (uint32_t)pr[i];
		d->tag_pairs[blk[REF_BLK(d->ref[i])].tag]++;
	}
	free(pr);
	if (d->led)
		kgenome_ledger_release(d->led, np * sizeof *pr);
	pr = NULL;
	d->top = d->key[np - 1u];
	{
		uint64_t run = 1;

		d->n_key = 1;
		d->max_run = 1;
		for (i = 1; i < np; i++) {
			if (d->key[i] == d->key[i - 1u]) {
				if (++run > d->max_run)
					d->max_run = run;
			} else {
				d->n_key++;
				run = 1;
			}
		}
	}
	/*
	 * THE BUCKET INDEX IS OVER THE RANGE OF THE KEYS, not the range of 32 bits: a block's hashes are
	 * the smallest window values of its span, so they sit at the bottom of the range (measured:
	 * the 32 smallest of 1000 windows are below 1/30 of 2^32) and an index on the top bits would use
	 * one bucket in thirty and put thirty times the keys in each. The shift is taken from `top`.
	 */
	d->bucket_bits = o && o->bucket_bits ? o->bucket_bits : clog2(np / 4u + 1u);
	if (d->bucket_bits < 8u) d->bucket_bits = 8u;
	if (d->bucket_bits > 28u) d->bucket_bits = 28u;
	{
		uint32_t bl = d->top ? 32u - (uint32_t)__builtin_clz(d->top) : 0u;

		d->shift = bl > d->bucket_bits ? bl - d->bucket_bits : 0u;
	}
	nbk = ((uint64_t)(d->top >> d->shift)) + 2u;
	d->bucket = chg_alloc(d->led, nbk * 4u, &d->bytes, 0);
	if (!d->bucket)
		goto over;
	{
		uint64_t k = 0;

		for (i = 0; i < nbk; i++) {
			while (k < np && (uint64_t)(d->key[k] >> d->shift) < i)
				k++;
			d->bucket[i] = (uint32_t)k;
		}
	}
	{
		uint64_t run = 0, k, nh = 0;

		for (i = 0; i < np; i++) {
			run++;
			if (i + 1u == np || d->key[i + 1u] != d->key[i]) {
				nh += run >= KGENOME_FNP_WDB_HOT;
				run = 0;
			}
		}
		if (nh) {
			d->hot_first = chg_alloc(d->led, nh * 4u, &d->bytes, 0);
			if (!d->hot_first)
				goto over;
			for (i = k = 0, run = 0; i < np; i++) {
				run++;
				if (i + 1u == np || d->key[i + 1u] != d->key[i]) {
					if (run >= KGENOME_FNP_WDB_HOT)
						d->hot_first[k++] = (uint32_t)(i + 1u - run);
					run = 0;
				}
			}
			d->n_hot = (uint32_t)nh;
		}
	}
	if (bpk != 0xFFFFFFFFu) {
		uint64_t bits = (uint64_t)1 << 12, w;

		while (bits < np * bpk && bits < ((uint64_t)1 << 36))
			bits <<= 1;
		w = bits / 64u;
		d->filter = chg_alloc(d->led, w * 8u, &d->bytes, 1);
		if (!d->filter)
			goto over;
		d->filter_mask = bits - 1u;
		for (i = 0; i < np; i++)
			set_filter(d->filter, d->filter_mask, d->key[i]);
	}
	d->bytes += 0;
	return 1;
over:
	fail(d, KGENOME_OVER_BUDGET);
	if (pr) {
		free(pr);
		if (d->led)
			kgenome_ledger_release(d->led, np * sizeof *pr);
	}
	{
		uint64_t keep = d->bytes;
		struct kgenome_ledger *l = d->led;
		enum kgenome_status st = d->status;

		kgenome_fnprint_wdb_free(d);
		d->status = st;
		d->led = l;
		(void)keep;
	}
	return 0;
}

void kgenome_fnprint_wdb_free(struct kgenome_fnprint_wdb *d)
{
	if (!d)
		return;
	if (d->led)
		kgenome_ledger_release(d->led, d->bytes);
	free(d->key); free(d->ref); free(d->bucket); free(d->filter); free(d->tag_pairs); free(d->hot_first);
	memset(d, 0, sizeof *d);
}

/* ---- the context ------------------------------------------------------------------ */

int kgenome_fnprint_wctx_init(struct kgenome_fnprint_wctx *c, const struct kgenome_fnprint_wdb *d, struct kgenome_ledger *led)
{
	uint32_t t;

	memset(c, 0, sizeof *c);
	c->db = d;
	c->led = led;
	c->gen = 1;
	c->rebuild_pct = 25;
	if (!d)
		return 0;
	c->stamp = chg_alloc(led, (uint64_t)(d->n_blk ? d->n_blk : 1u) * 4u, &c->bytes, 1);
	c->count = chg_alloc(led, (uint64_t)(d->n_blk ? d->n_blk : 1u) * 4u, &c->bytes, 1);
	c->mask = chg_alloc(led, (uint64_t)(d->n_blk ? d->n_blk : 1u) * (d->words ? d->words : 1u) * 4u, &c->bytes, 1);
	c->dead = chg_alloc(led, d->n_tag, &c->bytes, 1);
	c->decided = chg_alloc(led, d->n_tag, &c->bytes, 1);
	c->hstamp = chg_alloc(led, (uint64_t)(d->n_hot ? d->n_hot : 1u) * 4u, &c->bytes, 1);
	if (!c->hstamp || !c->stamp || !c->count || !c->mask || !c->dead || !c->decided) {
		c->status = KGENOME_OVER_BUDGET;
		kgenome_fnprint_wctx_done(c);
		c->status = KGENOME_OVER_BUDGET;
		return 0;
	}
	for (t = 0; t < d->n_tag; t++)
		c->n_tag_used += d->tag_pairs && d->tag_pairs[t] != 0;
	c->rtop = d->top;
	return 1;
}

void kgenome_fnprint_wctx_done(struct kgenome_fnprint_wctx *c)
{
	if (!c)
		return;
	kgenome_fnprint_dx_detach(c);
	if (c->led)
		kgenome_ledger_release(c->led, c->bytes);
	free(c->stamp); free(c->count); free(c->mask); free(c->dead); free(c->decided); free(c->hstamp); free(c->rfilter);
	{
		enum kgenome_status st = c->status;

		memset(c, 0, sizeof *c);
		c->status = st;
	}
}

void kgenome_fnprint_wctx_begin(struct kgenome_fnprint_wctx *c)
{
	const struct kgenome_fnprint_wdb *d = c->db;

	c->gen++;
	if (c->gen == 0 || c->gen >= (1u << 30)) {
		memset(c->stamp, 0, (size_t)(d->n_blk ? d->n_blk : 1u) * 4u);
		c->gen = 1;
	}
	memset(c->kc, 0, sizeof c->kc);
	if (d->n_hot && c->gen == 1)
		memset(c->hstamp, 0, (size_t)d->n_hot * 4u);
	if (c->n_dead || c->n_bdead) {
		memset(c->dead, 0, d->n_tag);
		c->n_dead = 0;
		c->n_bdead = 0;
		c->n_dead_pairs = c->rebuilt_at = 0;
		if (c->rfilter) {
			if (c->led)
				kgenome_ledger_release(c->led, ((c->rfilter_mask + 1u) / 64u) * 8u);
			c->bytes -= ((c->rfilter_mask + 1u) / 64u) * 8u;
			free(c->rfilter);
			c->rfilter = NULL;
		}
		c->rtop = d->top;
	}
	memset(c->decided, 0, d->n_tag);
	c->n_decided = 0;
	c->stop = 0;
	c->rem = 0;
	if (c->dxr)
		kgenome_fnprint_dx_begin(c);
}

uint32_t kgenome_fnprint_wctx_count(const struct kgenome_fnprint_wctx *c, uint32_t b)
{
	return c && b < c->db->n_blk && c->stamp[b] == c->gen ? c->count[b] : 0u;
}

/* Is pair i still looked up: its tag is not retired and its block is not dropped. */
static int pair_live(const struct kgenome_fnprint_wctx *c, uint64_t i)
{
	const struct kgenome_fnprint_wdb *d = c->db;
	uint32_t b = REF_BLK(d->ref[i]);

	return !c->dead[d->blk[b].tag] && !(c->bdead && c->bdead[b]);
}

/* The filter and the top rebuilt from the pairs that are still live. */
static void rebuild(struct kgenome_fnprint_wctx *c)
{
	const struct kgenome_fnprint_wdb *d = c->db;
	uint64_t live = 0, i, bits = (uint64_t)1 << 12, w, *nf;
	uint32_t bpk = d->filter_bpk, top = 0;

	if (bpk == 0xFFFFFFFFu)
		return;
	for (i = 0; i < d->n_pair; i++)
		if (pair_live(c, i)) {
			live++;
			top = d->key[i];
		}
	while (bits < live * bpk && bits < ((uint64_t)1 << 36))
		bits <<= 1;
	w = bits / 64u;
	if (c->led && !kgenome_ledger_try(c->led, w * 8u))
		return;                 /* a cache of a filter: not rebuilt costs time, not answers */
	nf = calloc((size_t)w, 8u);
	if (!nf) {
		if (c->led)
			kgenome_ledger_release(c->led, w * 8u);
		return;
	}
	for (i = 0; i < d->n_pair; i++)
		if (pair_live(c, i))
			set_filter(nf, bits - 1u, d->key[i]);
	if (c->rfilter) {
		if (c->led)
			kgenome_ledger_release(c->led, ((c->rfilter_mask + 1u) / 64u) * 8u);
		c->bytes -= ((c->rfilter_mask + 1u) / 64u) * 8u;
		free(c->rfilter);
	}
	c->bytes += w * 8u;
	c->rfilter = nf;
	c->rfilter_mask = bits - 1u;
	c->rtop = top;
	c->rebuilt_at = c->n_dead_pairs;
	c->n_rebuild++;
}

void kgenome_fnprint_wctx_retire(struct kgenome_fnprint_wctx *c, uint32_t tag, uint32_t rebuild_pct)
{
	const struct kgenome_fnprint_wdb *d = c->db;

	if (tag >= d->n_tag || c->dead[tag])
		return;
	c->dead[tag] = 1;
	c->n_dead++;
	c->n_dead_pairs += d->tag_pairs[tag];
	if (rebuild_pct && d->n_pair && (c->n_dead_pairs - c->rebuilt_at) * 100u >= (uint64_t)rebuild_pct * d->n_pair)
		rebuild(c);
}

/* The decision state says no live diagnose wants block b: stop looking its pairs up. */
void kgenome_fnprint_wctx_kill_block(struct kgenome_fnprint_wctx *c, uint32_t b)
{
	const struct kgenome_fnprint_wdb *d = c->db;

	if (!c->bdead || b >= d->n_blk || c->bdead[b])
		return;
	c->bdead[b] = 1;
	c->n_bdead++;
	c->n_dead_pairs += d->blk[b].n;
	/*
	 * A rebuild walks every pair; it pays back only if enough windows are still to come: a candidate
	 * costs about what four pairs of the walk do and the rebuild removes a share of them, so it is not
	 * done unless the windows left are a multiple of the pairs.
	 */
	if (c->rebuild_pct && d->n_pair && c->rem >= 16u * d->n_pair && (c->n_dead_pairs - c->rebuilt_at) * 100u >= (uint64_t)c->rebuild_pct * d->n_pair)
		rebuild(c);
}

/* A block's count rose: has its tag been decided? Only when a policy is set. */
static void decide(struct kgenome_fnprint_wctx *c, const struct kgenome_fnprint_wblock *bk, uint32_t b, uint32_t cnt)
{
	if (c->policy == KGENOME_FNP_RETIRE_DX) {
		if (c->dx_need_min && cnt >= c->dx_need_min[b])   /* below every threshold a diagnose has for this block: nothing to decide */
			kgenome_fnprint_dx_credit(c, b, cnt);
		return;
	}
	if ((uint64_t)cnt * 100u < (uint64_t)c->decide_pct * bk->n || c->decided[bk->tag])
		return;
	c->decided[bk->tag] = 1;
	c->n_decided++;
	if (c->policy == KGENOME_FNP_RETIRE_STOP_FIRST) {
		c->stop = 1;
		return;
	}
	kgenome_fnprint_wctx_retire(c, bk->tag, c->rebuild_pct);
	if (c->policy == KGENOME_FNP_RETIRE_TAG_STOP && c->n_dead >= c->n_tag_used)
		c->stop = 1;
}

void kgenome_fnprint_wctx_credit(struct kgenome_fnprint_wctx *c, uint32_t v, uint32_t side)
{
	const struct kgenome_fnprint_wdb *d = c->db;
	struct kgenome_fnprint_kc *k = &c->kc[(v * 2654435761u) >> 20];
	uint32_t want = (c->gen << 2) | (1u << (side & 1u)), lo, hi, walk0;

	c->n_lookup++;
	if (k->key == v && (k->tag >> 2) == c->gen && (k->tag & want & 3u)) {
		c->n_hot_repeat++;
		return;
	}
	if (k->key == v && (k->tag >> 2) == c->gen)
		k->tag |= want & 3u;
	else {
		k->key = v;
		k->tag = want;
	}
	if (v > d->top)
		return;
	lo = d->bucket[v >> d->shift];
	hi = d->bucket[(v >> d->shift) + 1u];
	c->n_search++;
	if (hi - lo > 16u) {                    /* a long bucket: bisect to the first key >= v */
		uint32_t a = lo, z = hi;

		while (a < z) {
			uint32_t m = a + (z - a) / 2u;

			if (d->key[m] < v)
				a = m + 1u;
			else
				z = m;
		}
		lo = a;
	}
	for (; lo < hi && d->key[lo] < v; lo++)
		;
	if (d->n_hot && lo < d->n_pair && d->key[lo] == v) {
		uint32_t a = 0, z = d->n_hot;

		while (a < z) {
			uint32_t m = a + (z - a) / 2u;

			if (d->hot_first[m] < lo)
				a = m + 1u;
			else
				z = m;
		}
		if (a < d->n_hot && d->hot_first[a] == lo) {
			uint32_t *hs = &c->hstamp[a], bit = 1u << (side & 1u);

			if ((*hs >> 2) == c->gen && (*hs & bit)) {
				c->n_hot_repeat++;
				return;
			}
			*hs = (*hs >> 2) == c->gen ? (*hs | bit) : ((c->gen << 2) | bit);
		}
	}
	walk0 = lo;
	for (; lo < d->n_pair && d->key[lo] == v; lo++) {
		uint32_t r = d->ref[lo], b = REF_BLK(r), s = REF_SLOT(r), *m;
		const struct kgenome_fnprint_wblock *bk = &d->blk[b];

		if (bk->side != side)
			continue;
		if (c->n_dead && c->dead[bk->tag]) {
			c->n_skip_dead++;
			continue;
		}
		if (c->bdead && c->bdead[b]) {
			c->n_skip_dead++;
			continue;
		}
		if (c->stamp[b] != c->gen) {
			uint32_t w;

			c->stamp[b] = c->gen;
			c->count[b] = 0;
			for (w = 0, m = &c->mask[(uint64_t)b * d->words]; w < d->words; w++)
				m[w] = 0;
		}
		m = &c->mask[(uint64_t)b * d->words + (s >> 5)];
		if (*m & (1u << (s & 31u)))
			continue;
		*m |= 1u << (s & 31u);
		c->count[b]++;
		c->n_credit++;
		if (c->policy)
			decide(c, bk, b, c->count[b]);
	}
	c->n_walked += lo - walk0;
}

/* ---- the pass --------------------------------------------------------------------- */

struct wp {
	const struct kgenome_fnprint_wpass_req *rq;
	struct kgenome_fnprint_wpass_stat *st;
	struct kgenome_fnprint_wctx *c;
	const struct kgenome_fnprint_libtab *lib;
};

static void roll(struct wp *w, const uint8_t *p, uint64_t n)
{
	struct kgenome_mtn_win it;
	struct kgenome_fnprint_wctx *c = w->c;
	const struct kgenome_fnprint_wdb *d = c->db;
	const uint64_t *filt = c->rfilter ? c->rfilter : d->filter;
	uint64_t fmask = c->rfilter ? c->rfilter_mask : d->filter_mask, nrb = c->n_rebuild;
	uint32_t top = c->rtop;

	if (!d->n_pair || !kgenome_mtn_win_begin(&it, p, n, KGENOME_MUTATION_RAW))
		return;
	do {
		uint32_t v = kgenome_mtn_win_value(&it);
		uint32_t side = KGENOME_MUTATION_SIDE_USER;

		if (v > top)
			continue;
		if (filt && !((filt[(v & fmask) >> 6] >> ((v & fmask) & 63u)) & 1u))
			continue;
		if (kgenome_mtn_win_flat(&it)) {
			w->st->n_flat++;
			continue;
		}
		w->st->n_cand++;
		if (w->lib && kgenome_fnprint_libtab_has(w->lib, v)) {
			side = KGENOME_MUTATION_SIDE_LIB;
			w->st->n_lib++;
		}
		kgenome_fnprint_wctx_credit(c, v, side);
		if (c->stop) {
			w->st->stopped = 1;
			w->st->n_stop_bytes += n - it.at - 1u;
			w->st->n_win_rolled += it.at + 1u;
			return;
		}
		if (c->n_rebuild != nrb) {
			nrb = c->n_rebuild;
			filt = c->rfilter ? c->rfilter : d->filter;
			fmask = c->rfilter ? c->rfilter_mask : d->filter_mask;
			top = c->rtop;
		}
	} while (kgenome_mtn_win_next(&it));
	w->st->n_win_rolled += n - KGENOME_MUTATION_NG + 1u;
}

#define CHUNK 4096u

static void one_range(struct wp *w, const uint8_t *p, uint64_t n)
{
	uint64_t at = 0, run = 0;

	w->st->bytes_in += n;
	w->st->n_win += n >= KGENOME_MUTATION_NG ? n - KGENOME_MUTATION_NG + 1u : 0;
	if (!(w->rq->flags & KGENOME_FNP_WP_SKIP_DATA)) {
		roll(w, p, n);
		return;
	}
	while (at < n && !w->c->stop) {
		uint32_t m = n - at < CHUNK ? (uint32_t)(n - at) : CHUNK;
		struct kgenome_fnprint_bstat bs;

		kgenome_fnprint_bstat(p + at, m, &bs);
		if (kgenome_fnprint_bstat_is_data(&bs)) {
			if (at > run)
				roll(w, p + run, at - run);
			w->st->n_skip_chunks++;
			w->st->skip_bytes += m;
			run = at + m;
		}
		at += m;
	}
	if (!w->c->stop && n > run)
		roll(w, p + run, n - run);
}

static uint64_t windows_of(uint64_t n)
{
	return n >= KGENOME_MUTATION_NG ? n - KGENOME_MUTATION_NG + 1u : 0;
}

void kgenome_fnprint_wpass(const struct kgenome_fnprint_wpass_req *rq)
{
	struct wp w;
	uint32_t i;
	uint64_t left = 0;

	if (!rq || !rq->c || !rq->stat || !rq->p)
		return;
	memset(rq->stat, 0, sizeof *rq->stat);
	w.rq = rq; w.st = rq->stat; w.c = rq->c; w.lib = rq->lib;
	if (rq->policy == KGENOME_FNP_RETIRE_DX && !rq->c->dxr) {
		rq->stat->status = KGENOME_BAD_INPUT;           /* no decision state: refused, not run as NONE */
		return;
	}
	rq->c->policy = rq->policy;
	rq->c->decide_pct = rq->decide_pct ? rq->decide_pct : 70u;
	for (i = 0; i < rq->n_ext; i++)
		if (rq->ext[i].off <= rq->n && rq->ext[i].len <= rq->n - rq->ext[i].off)
			left += windows_of(rq->ext[i].len);
	if (rq->policy == KGENOME_FNP_RETIRE_DX)
		kgenome_fnprint_dx_remain(rq->c, left);
	for (i = 0; i < rq->n_ext; i++) {
		if (rq->ext[i].off > rq->n || rq->ext[i].len > rq->n - rq->ext[i].off) {
			rq->stat->n_bad_ext++;
			continue;
		}
		if (rq->c->stop) {
			rq->stat->n_win_unvisited += windows_of(rq->ext[i].len);
			continue;
		}
		one_range(&w, rq->p + rq->ext[i].off, rq->ext[i].len);
		left -= windows_of(rq->ext[i].len);
		if (rq->policy == KGENOME_FNP_RETIRE_DX && !rq->c->stop)
			kgenome_fnprint_dx_remain(rq->c, left);
	}
	rq->stat->n_decided = rq->c->n_decided;
}
