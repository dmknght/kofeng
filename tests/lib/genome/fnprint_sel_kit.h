/*
 * fnprint_sel_kit.h - what the fnprint_sel_*.c tests build: a database of blocks cut from random function
 * bodies (the generator's own kgenome_mutation_minhash), an object that lays bodies, copies, padding and
 * junk end to end, and the credit a pass gives the object for a list of ranges. All in memory.
 */
#ifndef KGENOME_TESTS_FNPRINT_SEL_KIT_H
#define KGENOME_TESTS_FNPRINT_SEL_KIT_H

#include <kgenome.h>

#include "hk.h"

#define SK_NF   40u
#define SK_MAXL 1200u

struct sk_db {
	uint8_t  body[SK_NF][SK_MAXL];
	uint32_t len[SK_NF];
	struct kgenome_fnprint_wblock blk[SK_NF];
	uint32_t pool[SK_NF * 32u];
	uint32_t n_blk;
	struct kgenome_fnprint_wdb d;
};

static int sk_db_make(struct sk_db *s, uint64_t seed, struct kgenome_ledger *led) HK_UNUSED;
static int sk_db_make(struct sk_db *s, uint64_t seed, struct kgenome_ledger *led)
{
	struct hk_rng g = { seed * 6364136223846793005ull + 1442695040888963407ull };
	struct kgenome_fnprint_wdb_opts o;
	uint32_t f, j;

	memset(s, 0, sizeof *s);
	for (f = 0; f < SK_NF; f++) {
		uint32_t n;

		s->len[f] = 200u + hk_below(&g, SK_MAXL - 200u);
		for (j = 0; j < s->len[f]; j++)
			s->body[f][j] = (uint8_t)hk_next(&g);
		n = kgenome_mutation_minhash(s->body[f], s->len[f], KGENOME_MUTATION_RAW, s->pool + s->n_blk * 32u);
		s->blk[s->n_blk].first = s->n_blk * 32u;
		s->blk[s->n_blk].n = n;
		s->blk[s->n_blk].side = KGENOME_MUTATION_SIDE_USER;
		s->blk[s->n_blk].tag = 0;
		s->n_blk++;
	}
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	o.led = led;
	return kgenome_fnprint_wdb_build(&s->d, s->blk, s->n_blk, s->pool, (uint64_t)s->n_blk * 32u, &o);
}

static void sk_db_free(struct sk_db *s) HK_UNUSED;
static void sk_db_free(struct sk_db *s)
{
	kgenome_fnprint_wdb_free(&s->d);
}

/* An object: bytes and the function extents laid over them. */
struct sk_obj {
	uint8_t *p;
	uint64_t n, cap;
	struct kof_range *fn;
	uint32_t n_fn, cap_fn;
};

static void sk_obj_free(struct sk_obj *o) HK_UNUSED;
static void sk_obj_free(struct sk_obj *o)
{
	free(o->p);
	free(o->fn);
	memset(o, 0, sizeof *o);
}

/* Append a function of these bytes (len may be 0: an empty extent). */
static void sk_add(struct sk_obj *o, const uint8_t *b, uint64_t len) HK_UNUSED;
static void sk_add(struct sk_obj *o, const uint8_t *b, uint64_t len)
{
	int64_t own = o->p && b >= o->p && b < o->p + o->cap ? (int64_t)(b - o->p) : -1;   /* bytes of the object itself: re-found after a move */

	if (o->n + len + 1u > o->cap) {
		o->cap = (o->n + len + 1u) * 2u + 4096u;
		o->p = realloc(o->p, o->cap);
	}
	if (o->n_fn == o->cap_fn) {
		o->cap_fn = o->cap_fn ? o->cap_fn * 2u : 64u;
		o->fn = realloc(o->fn, (size_t)o->cap_fn * sizeof *o->fn);
	}
	if (len)
		memmove(o->p + o->n, own >= 0 ? o->p + own : b, (size_t)len);
	o->fn[o->n_fn].off = o->n;
	o->fn[o->n_fn++].len = len;
	o->n += len;
}

static void sk_add_fill(struct sk_obj *o, uint8_t byte, uint64_t len) HK_UNUSED;
static void sk_add_fill(struct sk_obj *o, uint8_t byte, uint64_t len)
{
	uint8_t *tmp = malloc((size_t)len + 1u);

	memset(tmp, byte, (size_t)len);
	sk_add(o, tmp, len);
	free(tmp);
}

static void sk_add_random(struct sk_obj *o, struct hk_rng *g, uint64_t len) HK_UNUSED;
static void sk_add_random(struct sk_obj *o, struct hk_rng *g, uint64_t len)
{
	uint8_t *tmp = malloc((size_t)len + 1u);
	uint64_t i;

	for (i = 0; i < len; i++)
		tmp[i] = (uint8_t)hk_next(g);
	sk_add(o, tmp, len);
	free(tmp);
}

/* Credit of the given ranges, nothing retired: the counts of every block. */
static uint32_t sk_roll(const struct sk_db *db, struct kgenome_fnprint_wctx *c, const struct sk_obj *o, const struct kof_range *r,
			uint32_t nr, uint32_t *cnt, struct kgenome_fnprint_wpass_stat *st) HK_UNUSED;
static uint32_t sk_roll(const struct sk_db *db, struct kgenome_fnprint_wctx *c, const struct sk_obj *o, const struct kof_range *r,
			uint32_t nr, uint32_t *cnt, struct kgenome_fnprint_wpass_stat *st)
{
	struct kgenome_fnprint_wpass_req rq;
	uint32_t b;

	memset(&rq, 0, sizeof rq);
	rq.p = o->p; rq.n = o->n; rq.ext = r; rq.n_ext = nr; rq.c = c; rq.stat = st;
	kgenome_fnprint_wctx_begin(c);
	kgenome_fnprint_wpass(&rq);
	for (b = 0; b < db->n_blk; b++)
		cnt[b] = kgenome_fnprint_wctx_count(c, b);
	return db->n_blk;
}

/* The plan of a policy over an object; out has room for o->n_fn ranges. */
static void sk_plan(const struct sk_db *db, const struct sk_obj *o, uint32_t policy, uint32_t k, uint32_t tiny, struct kof_range *out,
		    uint32_t *out_fn, struct kgenome_ledger *led, struct kgenome_fnprint_sel_stat *st) HK_UNUSED;
static void sk_plan(const struct sk_db *db, const struct sk_obj *o, uint32_t policy, uint32_t k, uint32_t tiny, struct kof_range *out,
		    uint32_t *out_fn, struct kgenome_ledger *led, struct kgenome_fnprint_sel_stat *st)
{
	struct kgenome_fnprint_sel_req rq;

	memset(&rq, 0, sizeof rq);
	rq.p = o->p; rq.n = o->n; rq.fn = o->fn; rq.n_fn = o->n_fn; rq.policy = policy; rq.tiny = tiny; rq.sample_k = k;
	rq.db = db ? &db->d : NULL; rq.out = out; rq.out_fn = out_fn; rq.led = led; rq.stat = st;
	kgenome_fnprint_sel_plan(&rq);
}

#endif
