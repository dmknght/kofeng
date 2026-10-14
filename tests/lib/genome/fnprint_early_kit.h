/*
 * fnprint_early_kit.h - a deterministic world for the decision-complete interrupt tests: a window
 * database, a description of diagnoses and clusters over it, and an object as the stream of window
 * values a pass would hand over. Nothing is a file; the generator is a fixed-seed xorshift.
 *
 * A world is built to put the interesting cases in reach of a few hundred seeds: blocks that share
 * hashes (hot values), blocks that list one hash twice, blocks of one to 128 hashes, diagnoses that
 * list a block twice or ask for more blocks than they list, clusters that list a member twice or ask
 * for more members than they have, and objects that hold exactly `need - 1`, `need` and `all` of
 * a block's hashes.
 */
#ifndef KGENOME_TESTS_FNPRINT_EARLY_KIT_H
#define KGENOME_TESTS_FNPRINT_EARLY_KIT_H

#include <kgenome.h>

#include "hk.h"

#define EK_MAXB   160
#define EK_MAXDX  48
#define EK_MAXREF 512
#define EK_MAXCL  24
#define EK_MAXMEM 96
#define EK_HOT    6

struct ek_world {
	struct kgenome_fnprint_wblock blk[EK_MAXB];
	uint32_t pool[EK_MAXB * KGENOME_FNP_WDB_MAXN];
	uint32_t n_blk, n_pool;
	struct kgenome_fnprint_dx dx[EK_MAXDX];
	uint32_t ref[EK_MAXREF];
	uint32_t n_dx, n_ref;
	struct kgenome_fnprint_cl cl[EK_MAXCL];
	uint32_t mem[EK_MAXMEM];
	uint32_t n_cl, n_mem;
	int own_clusters;                       /* 0: singleton clusters (desc.cl NULL) */
	uint32_t hot[EK_HOT];
};

struct ek_obj {
	uint32_t *v;
	uint8_t  *side;
	uint32_t  n, cap;
};

static void ek_push(struct ek_obj *o, uint32_t v, uint8_t side) HK_UNUSED;
static void ek_push(struct ek_obj *o, uint32_t v, uint8_t side)
{
	if (o->n == o->cap) {
		o->cap = o->cap ? o->cap * 2u : 256u;
		o->v = realloc(o->v, (size_t)o->cap * sizeof *o->v);
		o->side = realloc(o->side, o->cap);
	}
	o->v[o->n] = v;
	o->side[o->n++] = side;
}

static void ek_obj_free(struct ek_obj *o) HK_UNUSED;
static void ek_obj_free(struct ek_obj *o)
{
	free(o->v);
	free(o->side);
	memset(o, 0, sizeof *o);
}

/* A value that is not a key of any block (with the odds 2^32 allows: tests that need certainty use the oracle). */
static uint32_t ek_low(struct hk_rng *r) HK_UNUSED;
static uint32_t ek_low(struct hk_rng *r)
{
	return (uint32_t)(hk_next(r) >> 37) | 0x100u;
}

/* mode bit 0: hostile blocks (128 hashes, one-value blocks, many repeats); mode 2: few diagnoses, so that a stream is decided early */
static void ek_world(struct ek_world *w, uint64_t seed, uint32_t mode) HK_UNUSED;
static void ek_world(struct ek_world *w, uint64_t seed, uint32_t mode)
{
	uint32_t hostile = mode & 1u;
	struct hk_rng r = { (0x9e3779b97f4a7c15ull ^ (seed * 0x2545f4914f6cdd1dull)) | 1u };
	uint32_t b, j, i, k;

	memset(w, 0, sizeof *w);
	for (j = 0; j < EK_HOT; j++)
		w->hot[j] = ek_low(&r);
	w->n_blk = 20u + hk_below(&r, EK_MAXB - 20u);
	for (b = 0; b < w->n_blk; b++) {
		uint32_t n = 16u + hk_below(&r, 17u), pick = hk_below(&r, 100u);
		uint32_t *h = w->pool + w->n_pool;

		if (pick < 5u)
			n = 1u + hk_below(&r, 15u);
		else if (pick < 12u)
			n = hostile ? KGENOME_FNP_WDB_MAXN : 64u;
		for (j = 0; j < n; j++) {
			h[j] = hk_below(&r, 100u) < 8u ? w->hot[hk_below(&r, EK_HOT)] : ek_low(&r);
			if (j && hk_below(&r, 100u) < (hostile ? 12u : 3u))
				h[j] = h[hk_below(&r, j)];            /* a hash listed twice by one block */
		}
		if (hostile && hk_below(&r, 100u) < 4u)
			for (j = 0; j < n; j++)
				h[j] = h[0];                           /* a block of one value, n times */
		w->blk[b].first = w->n_pool;
		w->blk[b].n = n;
		w->blk[b].side = hk_below(&r, 100u) < 12u ? KGENOME_MUTATION_SIDE_LIB : KGENOME_MUTATION_SIDE_USER;
		w->blk[b].tag = 0;
		w->n_pool += n;
	}
	w->n_dx = mode == 2u ? 1u + hk_below(&r, 3u) : 4u + hk_below(&r, EK_MAXDX - 4u);
	for (i = 0; i < w->n_dx; i++) {
		static const uint32_t pcts[] = { 0, 50, 70, 70, 70, 90, 100 };
		uint32_t n = 1u + hk_below(&r, 6u);

		if (w->n_ref + n > EK_MAXREF)
			n = 1;
		w->dx[i].first = w->n_ref;
		w->dx[i].n = n;
		for (j = 0; j < n; j++) {
			uint32_t v = j && hk_below(&r, 100u) < 8u ? w->ref[w->n_ref - 1u] : hk_below(&r, w->n_blk);

			w->ref[w->n_ref++] = v;
		}
		w->dx[i].need = hk_below(&r, 100u) < 10u ? hk_below(&r, n + 2u) : 1u + hk_below(&r, n);
		w->dx[i].pct = pcts[hk_below(&r, sizeof pcts / sizeof *pcts)];
	}
	w->own_clusters = mode == 2u ? 0 : hk_below(&r, 100u) < 70u;
	if (w->own_clusters) {
		w->n_cl = 2u + hk_below(&r, EK_MAXCL - 2u);
		for (k = 0; k < w->n_cl; k++) {
			uint32_t n = 1u + hk_below(&r, 5u);

			if (w->n_mem + n > EK_MAXMEM)
				n = 1;
			w->cl[k].first = w->n_mem;
			w->cl[k].n = n;
			for (j = 0; j < n; j++) {
				uint32_t v = j && hk_below(&r, 100u) < 8u ? w->mem[w->n_mem - 1u] : hk_below(&r, w->n_dx);

				w->mem[w->n_mem++] = v;
			}
			w->cl[k].k = hk_below(&r, 100u) < 10u ? hk_below(&r, n + 2u) : 1u + hk_below(&r, n);
		}
	}
}

static void ek_desc(const struct ek_world *w, struct kgenome_fnprint_dxdesc *d) HK_UNUSED;
static void ek_desc(const struct ek_world *w, struct kgenome_fnprint_dxdesc *d)
{
	memset(d, 0, sizeof *d);
	d->dx = w->dx; d->n_dx = w->n_dx;
	d->ref = w->ref; d->n_ref = w->n_ref;
	if (w->own_clusters) {
		d->cl = w->cl; d->n_cl = w->n_cl;
		d->mem = w->mem; d->n_mem = w->n_mem;
	}
}

static int ek_build(struct kgenome_fnprint_wdb *d, const struct ek_world *w, struct kgenome_ledger *led) HK_UNUSED;
static int ek_build(struct kgenome_fnprint_wdb *d, const struct ek_world *w, struct kgenome_ledger *led)
{
	struct kgenome_fnprint_wdb_opts o;

	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	o.led = led;
	return kgenome_fnprint_wdb_build(d, w->blk, w->n_blk, w->pool, w->n_pool, &o);
}

/* Offer `take` distinct slots of block b, in a random order, on the block's side. */
static void ek_offer(struct ek_obj *o, const struct ek_world *w, uint32_t b, uint32_t take, struct hk_rng *r) HK_UNUSED;
static void ek_offer(struct ek_obj *o, const struct ek_world *w, uint32_t b, uint32_t take, struct hk_rng *r)
{
	uint32_t n = w->blk[b].n, j, idx[KGENOME_FNP_WDB_MAXN];

	for (j = 0; j < n; j++)
		idx[j] = j;
	for (j = n; j > 1u; j--) {
		uint32_t x = hk_below(r, j), t = idx[j - 1u];

		idx[j - 1u] = idx[x];
		idx[x] = t;
	}
	for (j = 0; j < take && j < n; j++)
		ek_push(o, w->pool[w->blk[b].first + idx[j]], (uint8_t)w->blk[b].side);
}

/*
 * An object aimed at a few diagnoses: for each block of a target, a count of its hashes chosen among
 * none, a few, one short of the threshold, exactly the threshold, all. Noise, repeats and hot values are mixed
 * in and the whole stream is shuffled.
 */
static void ek_object(struct ek_obj *o, const struct ek_world *w, struct hk_rng *r) HK_UNUSED;
static void ek_object(struct ek_obj *o, const struct ek_world *w, struct hk_rng *r)
{
	uint32_t t, nt = 1u + hk_below(r, 5u), i, j;

	memset(o, 0, sizeof *o);
	for (t = 0; t < nt; t++) {
		uint32_t d = hk_below(r, w->n_dx);

		for (j = 0; j < w->dx[d].n; j++) {
			uint32_t b = w->ref[w->dx[d].first + j], n = w->blk[b].n, pct = w->dx[d].pct ? w->dx[d].pct : 70u;
			uint32_t need = (uint32_t)(((uint64_t)pct * n + 99u) / 100u), take;

			switch (hk_below(r, 6u)) {
			case 0: take = 0; break;
			case 1: take = 1u + hk_below(r, n); break;
			case 2: take = need ? need - 1u : 0; break;
			case 3: take = need; break;
			case 4: take = n; break;
			default: take = need + hk_below(r, 3u); break;
			}
			ek_offer(o, w, b, take, r);
		}
	}
	for (i = hk_below(r, 400u); i; i--)
		ek_push(o, hk_below(r, 100u) < 10u ? w->hot[hk_below(r, EK_HOT)] : ek_low(r), (uint8_t)hk_below(r, 2u));
	for (i = hk_below(r, 60u); i && o->n; i--)
		ek_push(o, o->v[hk_below(r, o->n)], o->side[hk_below(r, o->n)]);
	for (j = o->n; j > 1u; j--) {
		uint32_t x = hk_below(r, j);
		uint32_t tv = o->v[j - 1u];
		uint8_t ts = o->side[j - 1u];

		o->v[j - 1u] = o->v[x]; o->side[j - 1u] = o->side[x];
		o->v[x] = tv; o->side[x] = ts;
	}
}

#endif
