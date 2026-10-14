/*
 * fnprint_scale_synth - the window database at scale, on a synthetic database that needs no files.
 *
 * THE GENERATOR (deterministic PRNG) makes N blocks of 32 hashes with the structure a real database
 * has, as far as that can be stated without files:
 *   - "real-like" blocks: a block is the 32 SMALLEST window values of a span, so its values sit at the
 *     bottom of the 32-bit range (here below 2^27, measured on real blocks: the smallest 32 of ~1000
 *     windows are under 1/30 of the range). A fraction are FAMILY VARIANTS: blocks that share 28 of
 *     their 32 hashes with the family core (1000 per family in the variant case);
 *   - random blocks: uniform 32-bit values (the worst case for a bit filter);
 *   - a few HOT hashes held by many blocks (skew: common windows);
 *   - a tenth of the blocks on the LIB side.
 * An object is the list of window values the pass would hand over (what a pass over real bytes
 * produces is checked in fnprint_pred.c). The ORACLE is independent of the structure under test: a
 * sorted set of the object's values and a loop over each block's slots.
 *
 * Default scales (1e4, 1e5 blocks) run in a few seconds and under 200 MB; --scale=1e6 and --scale=1e7
 * (1e7 x 32 hashes = 1.28 GB of pool alone) are opt-in. The numbers are printed (SCALE lines) and the
 * measured curves are in fnprint_scale.md; the assertions are about CORRECTNESS: credit equals the
 * oracle, nothing is silently truncated, a hot key is not quadratic, threads agree, retirement is
 * opt-in and does not change what is not retired.
 */
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

#include <pthread.h>
#include <time.h>

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

struct rng { uint64_t s; };

static uint64_t rnext(struct rng *r)
{
	r->s ^= r->s << 13; r->s ^= r->s >> 7; r->s ^= r->s << 17;
	return r->s;
}

static uint32_t rlow(struct rng *r)
{
	return (uint32_t)(rnext(r) >> 37);                       /* below 2^27: the bottom of the range */
}

struct synth {
	struct kgenome_fnprint_wblock *blk;
	uint32_t *pool;
	uint32_t n_blk, n_tag;
	uint32_t n_family;
};

enum { MIX_PLAIN = 0, MIX_FAMILY = 1, MIX_HOT = 2 };

/* mix: PLAIN = 45% real-like, 45% random, 10% family variants (28 of 32 shared); FAMILY = 1000-block families only;
 * HOT = every block holds the `hot` values and 24 of its own. */
static int synth_make(struct synth *s, uint32_t n, uint32_t mix, const uint32_t *hot, uint32_t n_hot, uint64_t seed)
{
	struct rng r = { seed | 1u };
	uint32_t i, j;
	uint32_t *core = NULL, fam = 0;

	memset(s, 0, sizeof *s);
	s->blk = malloc((size_t)n * sizeof *s->blk);
	s->pool = malloc((size_t)n * 32u * sizeof *s->pool);
	if (!s->blk || !s->pool)
		return 0;
	s->n_blk = n;
	s->n_tag = 16;
	for (i = 0; i < n; i++) {
		uint32_t *h = s->pool + (size_t)i * 32u;
		uint32_t kind = mix == MIX_FAMILY ? 2u : mix == MIX_HOT ? 3u : (uint32_t)(rnext(&r) % 100u) < 45u ? 0u : (uint32_t)(rnext(&r) % 100u) < 82u ? 1u : 2u;

		if (kind == 2u) {                                  /* a family variant */
			if (i % 1000u == 0 || !core) {
				core = h;                          /* the family's core is the first member's first 28 */
				fam++;
				for (j = 0; j < 32; j++)
					h[j] = rlow(&r);
			} else {
				memcpy(h, core, 28u * sizeof *h);
				for (j = 28; j < 32; j++)
					h[j] = rlow(&r);
			}
		} else if (kind == 3u) {
			for (j = 0; j < 32; j++)
				h[j] = j < n_hot ? hot[j] : rlow(&r);
		} else {
			for (j = 0; j < 32; j++)
				h[j] = kind == 0u ? rlow(&r) : (uint32_t)rnext(&r);
		}
		s->blk[i].first = i * 32u;
		s->blk[i].n = 32;
		s->blk[i].side = (uint32_t)(rnext(&r) % 10u) == 0 ? KGENOME_MUTATION_SIDE_LIB : KGENOME_MUTATION_SIDE_USER;
		s->blk[i].tag = i % s->n_tag;
	}
	s->n_family = fam;
	return 1;
}

static void synth_free(struct synth *s)
{
	free(s->blk);
	free(s->pool);
	memset(s, 0, sizeof *s);
}

/* ---- the object and the oracle -------------------------------------------------- */

struct obj {
	uint32_t *v;                    /* window values */
	uint8_t  *side;
	uint32_t  n;
};

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

/* An object that holds `k` random blocks at 28 of 32 hashes, plus `noise` values in no block (with
 * probability about n_key / 2^32 each, one is). */
static void obj_make(struct obj *o, const struct synth *s, uint32_t k, uint32_t noise, uint64_t seed)
{
	struct rng r = { seed | 1u };
	uint32_t i, j, n = 0;

	o->v = malloc(((size_t)k * 28u + noise) * sizeof *o->v);
	o->side = malloc((size_t)k * 28u + noise);
	for (i = 0; i < k; i++) {
		uint32_t b = (uint32_t)(rnext(&r) % s->n_blk);

		for (j = 0; j < 28; j++) {
			o->v[n] = s->pool[(size_t)b * 32u + j];
			o->side[n++] = (uint8_t)s->blk[b].side;      /* offered on the side the block is on */
		}
	}
	for (i = 0; i < noise; i++) {
		o->v[n] = (uint32_t)rnext(&r);
		o->side[n++] = (uint8_t)(rnext(&r) & 1u);
	}
	o->n = n;
}

static void obj_free(struct obj *o)
{
	free(o->v);
	free(o->side);
	memset(o, 0, sizeof *o);
}

/* The oracle: the count of block b is the number of its slots whose hash the object offers on the block's side. */
static uint32_t oracle(const struct synth *s, uint32_t b, const uint32_t *set[2], const uint32_t n_set[2])
{
	uint32_t j, c = 0, side = s->blk[b].side;

	for (j = 0; j < 32; j++) {
		uint32_t h = s->pool[(size_t)b * 32u + j];

		c += bsearch(&h, set[side], n_set[side], sizeof h, cmp_u32) != NULL;
	}
	return c;
}

static void oracle_sets(const struct obj *o, uint32_t **set, uint32_t *n_set)
{
	uint32_t i, side;

	for (side = 0; side < 2; side++) {
		uint32_t n = 0;

		set[side] = malloc(((size_t)o->n + 1u) * sizeof **set);
		for (i = 0; i < o->n; i++)
			if (o->side[i] == side)
				set[side][n++] = o->v[i];
		qsort(set[side], n, sizeof **set, cmp_u32);
		n_set[side] = n;
	}
}

static void feed(struct kgenome_fnprint_wctx *c, const struct obj *o)
{
	uint32_t i;

	for (i = 0; i < o->n; i++)
		kgenome_fnprint_wctx_credit(c, o->v[i], o->side[i]);
}

/* Credit equals the oracle on every block. */
static uint32_t mismatches(const struct synth *s, const struct kgenome_fnprint_wctx *c, const struct obj *o)
{
	uint32_t *set[2], n_set[2], b, bad = 0;

	oracle_sets(o, set, n_set);
	for (b = 0; b < s->n_blk; b++) {
		const uint32_t *cs[2] = { set[0], set[1] };

		if (oracle(s, b, cs, n_set) != kgenome_fnprint_wctx_count(c, b))
			bad++;
	}
	free(set[0]); free(set[1]);
	return bad;
}

static int build(struct kgenome_fnprint_wdb *d, const struct synth *s, struct kgenome_ledger *led, uint32_t bpk)
{
	struct kgenome_fnprint_wdb_opts o;

	memset(&o, 0, sizeof o);
	o.n_tag = s->n_tag;
	o.led = led;
	o.filter_bits_per_hash = bpk;
	return kgenome_fnprint_wdb_build(d, s->blk, s->n_blk, s->pool, (uint64_t)s->n_blk * 32u, &o);
}

/* ---- the cases ------------------------------------------------------------------ */

/* Build time, memory, filter load, false hits: printed; credit correctness: asserted. */
static void t_scale(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c;
	struct kgenome_ledger led;
	struct obj o;
	double t0, t1, t2, t3;
	uint64_t i, hits = 0, probes = 2000000, filt_pass = 0;
	struct rng r = { 12345 };

	CK(synth_make(&s, n, MIX_PLAIN, NULL, 0, 1000 + n));
	kgenome_ledger_init(&led, 0);
	t0 = now();
	CK(build(&d, &s, &led, 32u));
	t1 = now();
	CK(d.status == KGENOME_OK && d.n_pair == (uint64_t)n * 32u && led.used == d.bytes);
	CK(kgenome_fnprint_wctx_init(&c, &d, &led));
	obj_make(&o, &s, n / 20u + 10u, 20000, 7);
	kgenome_fnprint_wctx_begin(&c);
	t2 = now();
	feed(&c, &o);
	t3 = now();
	CK(mismatches(&s, &c, &o) == 0);                         /* credit equals the oracle, every block */
	/* the false hits of a 32-bit key on values in no block: measured on uniform random probes */
	for (i = 0; i < probes; i++) {
		uint32_t v = (uint32_t)rnext(&r);

		if (d.filter && ((d.filter[(v & d.filter_mask) >> 6] >> ((v & d.filter_mask) & 63u)) & 1u))
			filt_pass++;
		if (v <= d.top) {
			uint32_t lo = d.bucket[v >> d.shift], hi = d.bucket[(v >> d.shift) + 1u];

			for (; lo < hi; lo++)
				if (d.key[lo] == v) { hits++; break; }
		}
	}
	/* expected: n_key / 2^32 per probe; a count within 6 sigma + 10 of it */
	{
		double p = (double)d.n_key / 4294967296.0, mean = p * (double)probes, sd = __builtin_sqrt(mean) * 6.0 + 10.0;

		CK((double)hits > mean - sd && (double)hits < mean + sd);
	}
	printf("SCALE\tN=%u\tpairs=%llu\tkeys=%llu\tbuild_ms=%.1f\tbytes=%llu\tbytes/pair=%.2f\tfilter_bits/hash=%.1f\tfilter_load=%.3f\tfilter_pass=%.4f\tmax_run=%llu\tbucket_bits=%u\tfeed_ns/value=%.1f\n",
	       n, (unsigned long long)d.n_pair, (unsigned long long)d.n_key, (t1 - t0) * 1e3, (unsigned long long)d.bytes,
	       (double)d.bytes / (double)d.n_pair, d.filter ? (double)(d.filter_mask + 1u) / (double)d.n_pair : 0.0,
	       d.n_pair ? (double)d.n_key / (double)(d.filter_mask + 1u) : 0.0, (double)filt_pass / (double)probes,
	       (unsigned long long)d.max_run, d.bucket_bits, (t3 - t2) * 1e9 / (double)o.n);
	obj_free(&o);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	CK(led.used == 0);
	synth_free(&s);
}

/* Family variants: 1000 blocks that share 28 of 32 hashes. */
static void t_family(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c;
	struct obj o;
	uint32_t b, full = 0, core = 0, i, j;
	double t0;

	CK(synth_make(&s, n, MIX_FAMILY, NULL, 0, 99));
	CK(build(&d, &s, NULL, 32u));
	CK(d.max_run >= 1000u || n < 1000u);                      /* the 28 shared hashes are held by every member */
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	/* the object holds family 0's CORE (28 hashes) and variant 5's own four: one block is full, the others are at the core */
	o.n = 32; o.v = malloc(32u * 4u); o.side = calloc(32, 1);
	for (j = 0; j < 32; j++)
		o.v[j] = s.pool[(size_t)5u * 32u + j];
	for (i = 0; i < 1u; i++) {
		kgenome_fnprint_wctx_begin(&c);
		t0 = now();
		feed(&c, &o);
		(void)t0;
	}
	for (b = 0; b < (n < 1000u ? n : 1000u); b++) {
		uint32_t cb = kgenome_fnprint_wctx_count(&c, b);

		if (b == 5u) full = cb == 32u;
		else if (b < 1000u && s.blk[b].side == KGENOME_MUTATION_SIDE_USER) core += cb == 28u;
	}
	CK(full);
	CK(core >= (n < 1000u ? n : 1000u) * 8u / 10u);           /* every USER variant of the family sits at 28 of 32 */
	CK(mismatches(&s, &c, &o) == 0);
	free(o.v); free(o.side);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	synth_free(&s);
}

/* Skew: a few hashes held by every block. Not quadratic, and not unfair to a colliding pair of hot keys. */
static void t_skew(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c;
	uint32_t hot[8], i, reps = 200000;
	double t0, t1;
	struct rng r = { 4242 };

	for (i = 0; i < 8; i++)
		hot[i] = rlow(&r);
	CK(synth_make(&s, n, MIX_HOT, hot, 8, 5));
	CK(build(&d, &s, NULL, 32u));
	CK(d.max_run >= n / 2u && d.n_hot >= 4u);                 /* the hottest key is in about every USER-or-LIB block of its side: runs are long */
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	kgenome_fnprint_wctx_begin(&c);
	t0 = now();
	/* a hostile object: the hot windows repeated, alternating two keys (the stamp cache cannot hold both
	 * if they collide: the hot table makes the answer independent of that) */
	for (i = 0; i < reps; i++) {
		kgenome_fnprint_wctx_credit(&c, hot[i & 1u], KGENOME_MUTATION_SIDE_USER);
		kgenome_fnprint_wctx_credit(&c, hot[2u + (i & 1u)], KGENOME_MUTATION_SIDE_LIB);
	}
	t1 = now();
	CK(t1 - t0 < 2.0);                                         /* 4e5 hot windows: milliseconds, not n * 4e5 steps */
	CK(c.n_hot_repeat >= (uint64_t)reps * 2u - 8u);
	{
		uint32_t b, bad = 0;

		for (b = 0; b < n && b < 5000u; b++) {
			uint32_t want = 0, j;

			for (j = 0; j < 8; j++)
				want += (s.blk[b].side == KGENOME_MUTATION_SIDE_USER ? (j < 2u) : (j >= 2u && j < 4u));
			if (kgenome_fnprint_wctx_count(&c, b) != want)
				bad++;
		}
		CK(bad == 0);
	}
	printf("SCALE\tSKEW N=%u\tmax_run=%llu\thot_keys=%u\twindows=%u\tms=%.2f\tsearches=%llu\n", n, (unsigned long long)d.max_run, d.n_hot,
	       reps * 2u, (t1 - t0) * 1e3, (unsigned long long)c.n_search);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	synth_free(&s);
}

/* A database larger than the allowance is REFUSED, loudly, and gives everything back. */
static void t_allowance(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c;
	struct kgenome_ledger led;

	CK(synth_make(&s, n, MIX_PLAIN, NULL, 0, 3));
	kgenome_ledger_init(&led, (uint64_t)n * 32u * 8u);        /* the pairs alone need 9 bytes each, plus the sort's copy */
	CK(!build(&d, &s, &led, 32u));
	CK(d.status == KGENOME_OVER_BUDGET && d.n_pair == 0 && d.key == NULL);
	CK(led.used == 0 && led.status == KGENOME_OVER_BUDGET);
	/* the same database fits when the allowance is honest, and then the context is charged too */
	kgenome_ledger_init(&led, (uint64_t)n * 32u * 40u);
	CK(build(&d, &s, &led, 32u));
	CK(kgenome_fnprint_wctx_init(&c, &d, &led) && led.used == d.bytes + c.bytes);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	CK(led.used == 0);
	/* a context the allowance cannot hold is refused as well */
	kgenome_ledger_init(&led, (uint64_t)n * 32u * 40u);
	CK(build(&d, &s, &led, 32u));
	led.limit = led.used + 8u;
	CK(!kgenome_fnprint_wctx_init(&c, &d, &led) && c.status == KGENOME_OVER_BUDGET);
	led.limit = 0;
	kgenome_fnprint_wdb_free(&d);
	synth_free(&s);
}

struct thr {
	const struct kgenome_fnprint_wdb *d;
	const struct obj *o;
	uint32_t *count;
	uint32_t n_blk;
};

static void *thr_main(void *u)
{
	struct thr *t = u;
	struct kgenome_fnprint_wctx c;
	uint32_t b, rep;

	if (!kgenome_fnprint_wctx_init(&c, t->d, NULL))
		return NULL;
	for (rep = 0; rep < 3; rep++) {                           /* three objects per thread: the generation moves */
		kgenome_fnprint_wctx_begin(&c);
		feed(&c, t->o);
	}
	for (b = 0; b < t->n_blk; b++)
		t->count[b] = kgenome_fnprint_wctx_count(&c, b);
	kgenome_fnprint_wctx_done(&c);
	return NULL;
}

/* Concurrent scans share one read-only database. */
static void t_threads(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c;
	struct obj o;
	struct thr t[4];
	pthread_t th[4];
	uint32_t i, b, bad = 0;

	CK(synth_make(&s, n, MIX_PLAIN, NULL, 0, 17));
	CK(build(&d, &s, NULL, 32u));
	obj_make(&o, &s, n / 10u + 5u, 5000, 21);
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	kgenome_fnprint_wctx_begin(&c);
	feed(&c, &o);
	for (i = 0; i < 4; i++) {
		t[i].d = &d; t[i].o = &o; t[i].n_blk = n;
		t[i].count = calloc(n, sizeof(uint32_t));
		pthread_create(&th[i], NULL, thr_main, &t[i]);
	}
	for (i = 0; i < 4; i++)
		pthread_join(th[i], NULL);
	for (i = 0; i < 4; i++) {
		for (b = 0; b < n; b++)
			bad += t[i].count[b] != kgenome_fnprint_wctx_count(&c, b);
		free(t[i].count);
	}
	CK(bad == 0);
	obj_free(&o);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	synth_free(&s);
}

/* Retirement at scale: opt-in, and it changes nothing for a tag that is not retired. */
static void t_retirement(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wctx c0, c1;
	struct obj o;
	uint32_t b, i, bad = 0, retired_changed = 0, retired_total = 0;
	uint64_t pairs_before;

	CK(synth_make(&s, n, MIX_PLAIN, NULL, 0, 31));
	CK(build(&d, &s, NULL, 32u));
	obj_make(&o, &s, n / 5u, 1000, 9);
	CK(kgenome_fnprint_wctx_init(&c0, &d, NULL) && kgenome_fnprint_wctx_init(&c1, &d, NULL));
	kgenome_fnprint_wctx_begin(&c0);
	kgenome_fnprint_wctx_begin(&c1);
	feed(&c0, &o);                                            /* the default: nothing retires */
	CK(c0.n_dead == 0 && c0.policy == KGENOME_FNP_RETIRE_NONE);
	/* a tag is retired after the first quarter of the object; the rest of the object is fed with it dead */
	for (i = 0; i < o.n / 4u; i++)
		kgenome_fnprint_wctx_credit(&c1, o.v[i], o.side[i]);
	pairs_before = c1.n_search;
	kgenome_fnprint_wctx_retire(&c1, 3, 10);
	kgenome_fnprint_wctx_retire(&c1, 7, 10);
	for (; i < o.n; i++)
		kgenome_fnprint_wctx_credit(&c1, o.v[i], o.side[i]);
	for (b = 0; b < n; b++) {
		uint32_t t = s.blk[b].tag, a = kgenome_fnprint_wctx_count(&c0, b), z = kgenome_fnprint_wctx_count(&c1, b);

		if (t == 3u || t == 7u) {
			retired_total++;
			retired_changed += z < a;                      /* a retired tag's credit stopped growing: stated, counted */
			bad += z > a;
		} else {
			bad += z != a;                                 /* every other tag: identical to the non-retiring run */
		}
	}
	CK(bad == 0);
	CK(retired_changed > 0 && retired_total > 0);
	CK(c1.n_skip_dead > 0 || c1.n_search - pairs_before < c0.n_search);
	printf("SCALE\tRETIRE N=%u\tretired_blocks=%u\tlost_credit_blocks=%u\tsearches(all)=%llu\tsearches(retire)=%llu\trebuilds=%llu\n", n, retired_total,
	       retired_changed, (unsigned long long)c0.n_search, (unsigned long long)c1.n_search, (unsigned long long)c1.n_rebuild);
	obj_free(&o);
	kgenome_fnprint_wctx_done(&c0); kgenome_fnprint_wctx_done(&c1);
	kgenome_fnprint_wdb_free(&d);
	synth_free(&s);
}

/* Load / rebuild: a database built twice from the same pack gives the same index. */
static void t_rebuild(uint32_t n)
{
	struct synth s;
	struct kgenome_fnprint_wdb a, b;
	uint64_t i;

	CK(synth_make(&s, n, MIX_PLAIN, NULL, 0, 41));
	CK(build(&a, &s, NULL, 32u) && build(&b, &s, NULL, 32u));
	CK(a.n_pair == b.n_pair && !memcmp(a.key, b.key, a.n_pair * 4u) && !memcmp(a.ref, b.ref, a.n_pair * 4u));
	for (i = 1; i < a.n_pair; i++)
		if (a.key[i] < a.key[i - 1u]) {
			CK(0 && "keys ascending");
			break;
		}
	kgenome_fnprint_wdb_free(&a); kgenome_fnprint_wdb_free(&b);
	synth_free(&s);
}

/* Scale limits that must be REFUSED, not cut. */
static void t_refusals(void)
{
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wblock b = { 0, 32, 0, 0 };
	uint32_t pool[32] = { 0 };

	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	CK(!kgenome_fnprint_wdb_build(&d, &b, KGENOME_FNP_WDB_MAX_BLOCKS + 1u, pool, 32, &o) && d.status == KGENOME_TRUNCATED);
	CK(d.n_pair == 0 && d.key == NULL);
}

static double parse_scale(const char *a)
{
	return strtod(a + 8, NULL);
}

int main(int argc, char **argv)
{
	uint32_t scales[8], ns = 0, i;
	double big = 0;

	scales[ns++] = 10000u;
	scales[ns++] = 100000u;
	for (i = 1; i < (uint32_t)argc; i++)
		if (!strncmp(argv[i], "--scale=", 8))
			big = parse_scale(argv[i]);
	if (big >= 1e6)
		scales[ns++] = (uint32_t)big;
	for (i = 0; i < ns; i++)
		t_scale(scales[i]);
	t_family(10000u);
	t_skew(20000u);
	t_allowance(20000u);
	t_threads(30000u);
	t_retirement(50000u);
	t_rebuild(20000u);
	t_refusals();
	printf("fnprint_scale_synth: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
