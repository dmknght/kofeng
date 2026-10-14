/*
 * fnprint_sel.c - which functions of an object are rolled, decided from bytes.
 *
 * THE WORK IS THE ROLL. A window costs one rolling step whatever happens to its value afterwards (a
 * reject by the key range or the filter, or a lookup), so the only way to spend less on an object
 * without a decision about the answer is to NOT ROLL bytes whose windows cannot change it:
 *
 *   - bytes that make no window (shorter than one, or one repeated byte): nothing to roll, exact;
 *   - bytes that are a copy of bytes already rolled (a function emitted many times: a static runtime's
 *     stubs, the padding functions a linker adds): the copy's windows are a set the first copy already
 *     credited, and credit is a count of DISTINCT hashes per object. Exact. The hash that finds a
 *     candidate is not trusted: equality is checked on the bytes;
 *   - bytes that hold no key of the database in a SAMPLE of their windows: not exact (a window that
 *     was not looked at is not known), reported with the number of windows it left unread so the loss
 *     is bounded and a caller can read them afterwards.
 * A prefilter that avoids rolling can only be a sample: the value of a window is known only by
 * computing it. What a policy that is not exact removes is therefore counted, never silent.
 *
 * Nothing here reads a name, a section or a link order: the input is the extents and the bytes.
 */
#include "fnprint.h"

#include <stdlib.h>
#include <string.h>

#include "mutation.h"

#define WIN(n)  ((n) >= KGENOME_MUTATION_NG ? (n) - KGENOME_MUTATION_NG + 1u : 0u)

/*
 * The key that finds a candidate copy: the length and 16 bytes from each end and the middle. Cheap (48 bytes
 * read, whatever the function's size) because it only NOMINATES a candidate; equality is decided on every byte.
 */
static uint64_t cand_key(const uint8_t *p, uint64_t n)
{
	uint64_t h = 0xcbf29ce484222325ull ^ (n * 0x9e3779b97f4a7c15ull), w;
	uint32_t k, nseg = n > 48u ? 3u : 1u;

	for (k = 0; k < nseg; k++) {
		const uint8_t *q = nseg == 1u ? p : k == 0 ? p : k == 1 ? p + n / 2u - 8u : p + n - 16u;
		uint32_t m = nseg == 1u ? (uint32_t)n : 16u, i;

		for (i = 0; i + 8u <= m; i += 8u) {
			memcpy(&w, q + i, 8);
			h = (h ^ w) * 0x9e3779b97f4a7c15ull;
			h ^= h >> 29;
		}
		for (; i < m; i++)
			h = (h ^ q[i]) * 0x100000001b3ull;
	}
	return h ^ (h >> 32);
}

/* The length of the run of pairs whose key is v; 0 when v is not a key. */
static uint32_t key_run(const struct kgenome_fnprint_wdb *d, uint32_t v)
{
	uint32_t lo, hi;

	if (!d || !d->n_pair || v > d->top)
		return 0;
	if (d->filter && !((d->filter[(v & d->filter_mask) >> 6] >> ((v & d->filter_mask) & 63u)) & 1u))
		return 0;
	lo = d->bucket[v >> d->shift];
	hi = d->bucket[(v >> d->shift) + 1u];
	while (lo < hi) {                       /* first key >= v: bisection, a bucket can be as long as an attacker likes */
		uint32_t m = lo + (hi - lo) / 2u;

		if (d->key[m] < v)
			lo = m + 1u;
		else
			hi = m;
	}
	if (lo >= d->n_pair || d->key[lo] != v)
		return 0;
	{
		uint32_t a = lo, z = (uint32_t)d->n_pair;   /* first key > v: the run of a hot key is not walked */

		while (a < z) {
			uint32_t m = a + (z - a) / 2u;

			if (d->key[m] <= v)
				a = m + 1u;
			else
				z = m;
		}
		return a - lo;
	}
}

struct pvote {
	uint32_t hits;                  /* probed windows that are keys of the database */
	uint32_t lib_s, lib_h;          /* probed windows the library table samples / holds */
};

/* Score of a function: how rare the keys its sampled windows hold are (a key held by one block counts 1024). */
static uint32_t probe(const struct kgenome_fnprint_sel_req *rq, const uint8_t *p, uint64_t len, struct kgenome_fnprint_sel_stat *st,
		      struct pvote *pv)
{
	uint32_t k = rq->sample_k ? rq->sample_k : 8u, j, score = 0;
	uint64_t span = len - KGENOME_MUTATION_NG;

	memset(pv, 0, sizeof *pv);
	for (j = 0; j < k; j++) {
		struct kgenome_mtn_win it;
		uint64_t pos = k > 1u ? span * j / (k - 1u) : span / 2u;
		uint32_t run;

		if (!kgenome_mtn_win_begin(&it, p + pos, KGENOME_MUTATION_NG, KGENOME_MUTATION_RAW))
			continue;
		st->n_probe++;
		if (kgenome_mtn_win_flat(&it))
			continue;
		if (rq->lib && kgenome_fnprint_libtab_sampled(rq->lib, kgenome_mtn_win_value(&it))) {
			pv->lib_s++;
			pv->lib_h += kgenome_fnprint_libtab_has(rq->lib, kgenome_mtn_win_value(&it)) != 0;
		}
		run = key_run(rq->db, kgenome_mtn_win_value(&it));
		if (run) {
			pv->hits++;
			score += 1024u / (run < 1024u ? run : 1024u);
		}
	}
	return score;
}

struct item {
	uint32_t score, idx;
};

static int cmp_item(const void *a, const void *b)
{
	const struct item *x = a, *y = b;

	if (x->score != y->score)
		return x->score > y->score ? -1 : 1;
	return x->idx < y->idx ? -1 : x->idx > y->idx;
}

struct dtab {
	uint64_t *h;
	uint32_t *ix;                   /* index + 1 into fn; 0 empty */
	uint64_t  mask;
};

/* The most candidates compared byte by byte for one function: a set of functions that agree at the ends and
 * differ inside cannot make the planner quadratic. Past it the function is simply kept (n_dup_cap). */
#define DUP_TRIES 8u

/* 1 when a function with these bytes was registered before (verified byte by byte); else registers it. */
static int dup_seen(struct dtab *t, const struct kgenome_fnprint_sel_req *rq, uint32_t i, struct kgenome_fnprint_sel_stat *st)
{
	const struct kof_range *f = &rq->fn[i];
	uint64_t h = cand_key(rq->p + f->off, f->len), at = h & t->mask;
	uint32_t tries = 0;

	st->bytes_hashed += f->len >= 48u ? 48u : f->len;
	for (;; at = (at + 1u) & t->mask) {
		uint32_t j = t->ix[at];

		if (!j) {
			t->h[at] = h;
			t->ix[at] = i + 1u;
			return 0;
		}
		if (t->h[at] == h && rq->fn[j - 1u].len == f->len) {
			st->bytes_compared += f->len;
			if (!memcmp(rq->p + rq->fn[j - 1u].off, rq->p + f->off, (size_t)f->len))
				return 1;
			if (++tries >= DUP_TRIES) {
				st->n_dup_cap++;
				return 0;
			}
		}
	}
}

void kgenome_fnprint_sel_plan(const struct kgenome_fnprint_sel_req *rq)
{
	struct kgenome_fnprint_sel_stat *st;
	struct dtab t = { 0 };
	struct item *it = NULL;
	uint32_t i, n_it = 0, tiny, want_probe, lib_pct, lib_min;
	uint64_t cap = 0, bytes = 0;

	if (!rq || !rq->stat)
		return;
	st = rq->stat;
	memset(st, 0, sizeof *st);
	if (!rq->out || (rq->n_fn && (!rq->fn || !rq->p))) {
		st->status = KGENOME_BAD_INPUT;
		return;
	}
	st->n_in = rq->n_fn;
	tiny = rq->tiny ? rq->tiny : 64u;
	want_probe = !!(rq->policy & (KGENOME_FNP_SEL_SAMPLE | KGENOME_FNP_SEL_ORDER | KGENOME_FNP_SEL_LIB));
	lib_pct = rq->lib_pct ? rq->lib_pct : 90u;
	lib_min = rq->lib_min ? rq->lib_min : 8u;
	if (rq->policy & KGENOME_FNP_SEL_DUP) {
		cap = 16;
		while (cap < 2ull * rq->n_fn)
			cap <<= 1;
		bytes = cap * 12u;
		if (rq->led && !kgenome_ledger_charge(rq->led, bytes)) {
			st->status = KGENOME_OVER_BUDGET;
			bytes = 0;
			goto fail;
		}
		t.h = calloc((size_t)cap, 8);
		t.ix = calloc((size_t)cap, 4);
		t.mask = cap - 1u;
		if (!t.h || !t.ix) {
			st->status = KGENOME_OVER_BUDGET;
			goto fail;
		}
		st->scratch_bytes += bytes;
	}
	if (want_probe && rq->n_fn) {
		uint64_t b = (uint64_t)rq->n_fn * sizeof *it;

		if (rq->led && !kgenome_ledger_charge(rq->led, b)) {
			st->status = KGENOME_OVER_BUDGET;
			goto fail;
		}
		it = malloc((size_t)b);
		if (!it) {
			if (rq->led)
				kgenome_ledger_release(rq->led, b);
			st->status = KGENOME_OVER_BUDGET;
			goto fail;
		}
		bytes += b;
		st->scratch_bytes += b;
	}
	for (i = 0; i < rq->n_fn; i++) {
		const struct kof_range *f = &rq->fn[i];
		const uint8_t *p;
		struct pvote pv = { 0, 0, 0 };
		uint32_t score = 0;

		if (f->off > rq->n || f->len > rq->n - f->off) {
			st->n_bad++;
			continue;
		}
		p = rq->p + f->off;
		st->win_in += WIN(f->len);
		if ((rq->policy & KGENOME_FNP_SEL_FLAT) && (f->len < KGENOME_MUTATION_NG || !memcmp(p, p + 1, (size_t)f->len - 1u))) {
			st->n_flat++;
			continue;
		}
		if ((rq->policy & KGENOME_FNP_SEL_TINY) && f->len < tiny) {
			st->n_tiny++;
			continue;
		}
		if ((rq->policy & KGENOME_FNP_SEL_DUP) && f->len >= KGENOME_MUTATION_NG && dup_seen(&t, rq, i, st)) {
			st->n_dup++;
			continue;
		}
		if (want_probe && f->len >= KGENOME_MUTATION_NG) {
			score = probe(rq, p, f->len, st, &pv);
			if ((rq->policy & KGENOME_FNP_SEL_LIB) && pv.lib_s >= lib_min && (uint64_t)pv.lib_h * 100u >= (uint64_t)lib_pct * pv.lib_s) {
				st->n_lib++;
				continue;
			}
			if ((rq->policy & KGENOME_FNP_SEL_SAMPLE) && !pv.hits) {
				st->n_sample++;
				continue;
			}
			st->n_hit += pv.hits != 0;
		}
		if (it) {
			it[n_it].score = (rq->policy & KGENOME_FNP_SEL_ORDER) ? score : 0u;
			it[n_it++].idx = i;
		} else {
			rq->out[st->n_out].off = f->off;
			rq->out[st->n_out].len = f->len;
			if (rq->out_fn)
				rq->out_fn[st->n_out] = i;
			st->n_out++;
			st->win_out += WIN(f->len);
		}
	}
	if (it) {
		if (rq->policy & KGENOME_FNP_SEL_ORDER)
			qsort(it, n_it, sizeof *it, cmp_item);
		for (i = 0; i < n_it; i++) {
			const struct kof_range *f = &rq->fn[it[i].idx];

			rq->out[st->n_out].off = f->off;
			rq->out[st->n_out].len = f->len;
			if (rq->out_fn)
				rq->out_fn[st->n_out] = it[i].idx;
			st->n_out++;
			st->win_out += WIN(f->len);
		}
	}
fail:
	free(t.h);
	free(t.ix);
	free(it);
	if (rq->led && bytes)
		kgenome_ledger_release(rq->led, bytes);
	if (st->status == KGENOME_OVER_BUDGET) {
		/* no room for the scratch: nothing is removed. The whole set comes back, in order, and the status says why. */
		enum kgenome_status keep = st->status;
		uint32_t nb = 0;

		memset(st, 0, sizeof *st);
		st->status = keep;
		st->n_in = rq->n_fn;
		for (i = 0; i < rq->n_fn; i++) {
			const struct kof_range *f = &rq->fn[i];

			if (f->off > rq->n || f->len > rq->n - f->off) {
				nb++;
				continue;
			}
			rq->out[st->n_out] = *f;
			if (rq->out_fn)
				rq->out_fn[st->n_out] = i;
			st->n_out++;
			st->win_in += WIN(f->len);
			st->win_out += WIN(f->len);
		}
		st->n_bad = nb;
	}
}
