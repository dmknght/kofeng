/*
 * mutation_index - the block matcher (kofmutation.c, over the pack's index container) against the
 * matcher it replaced.
 *
 * THE OLD MATCHER IS KEPT HERE, renamed ref_*: a sorted array of (hash, block<<8|slot) pairs, a binary
 * search per surviving window, a walk of the whole equal range, one 4-byte stamp per pair. It is the
 * specification the new index must equal ENTRY FOR ENTRY: every (object, block) count the same, on
 * random databases and objects, with a hash shared by many blocks, a hash twice in one block, units
 * of several regions, normalizers and sides, and the any-region flag. The new matcher has ONE path (the
 * batch); it is run with the default batch and with a batch forced down to 4096 survivors, so that a
 * unit that spans many batches is held to the same counts, and both must equal ref.
 *
 * THE BOUNDS are asserted as VISIT COUNTS (kof_mutation_stat), not seconds: a hash held by 5000 blocks
 * and repeated by 64000 windows is ONE walk of 5000 entries. The index file's own failures (a bucket
 * larger than the read buffer, a spent read allowance, a short read) are in tests/unit/kix_container.c
 * and kix_load.c; here the matcher's answer to them is: counts only fall, and the status says so.
 *
 * Opt-in: --scale=N (blocks, e.g. 1e6) builds a synthetic database and prints load time, bytes per
 * hash and RSS; --corpus=LIST cuts a database from the files named in LIST (one path a line) and
 * compares ref against the matcher over them; --cell=... prints ns per window for one shape.
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../libkofeng/detectors/mutations/kofmutation.h"

static int fails;
static uint64_t credited;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t rnd(uint32_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
	return *s;
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* ---- the old matcher, verbatim in what it computes -------------------- */

struct ref_pair { uint32_t hash, bs; };
struct ref {
	const struct kof_mutation_block *block;
	struct ref_pair *pair;
	uint32_t n_pair, n_block, gen, *pstamp, *stamp, *seen;
	int any;
	uint64_t *bloom;
	uint32_t bmask;
};

static int ref_cmp(const void *a, const void *b)
{
	const struct ref_pair *x = a, *y = b;

	if (x->hash != y->hash)
		return x->hash < y->hash ? -1 : 1;
	return x->bs < y->bs ? -1 : x->bs > y->bs;
}

static void ref_init(struct ref *r, const struct kof_mutation_block *b, uint32_t nb, const uint32_t *pool)
{
	uint32_t i, j, n = 0;

	memset(r, 0, sizeof *r);
	for (i = 0; i < nb; i++)
		n += b[i].n_hash;
	r->pair = malloc((size_t)(n ? n : 1u) * sizeof *r->pair);
	for (i = 0; i < nb; i++)
		for (j = 0; j < b[i].n_hash; j++) {
			r->pair[r->n_pair].hash = pool[b[i].first_hash + j];
			r->pair[r->n_pair++].bs = (i << 8) | j;
		}
	qsort(r->pair, r->n_pair, sizeof *r->pair, ref_cmp);
	{
		uint64_t bits = 1u << 12;

		while (bits < (uint64_t)r->n_pair * 32u && bits < (1u << 28))
			bits <<= 1;
		r->bloom = calloc((size_t)(bits / 64u), 8);
		r->bmask = (uint32_t)(bits - 1u);
		for (i = 0; i < r->n_pair; i++) {
			uint32_t ix = r->pair[i].hash & r->bmask;

			r->bloom[ix >> 6] |= (uint64_t)1 << (ix & 63u);
		}
	}
	r->block = b; r->n_block = nb; r->gen = 1;
	r->pstamp = calloc(n ? n : 1u, 4);
	r->stamp = calloc(nb ? nb : 1u, 4);
	r->seen = calloc(nb ? nb : 1u, 4);
}

static void ref_free(struct ref *r)
{
	free(r->pair); free(r->bloom); free(r->pstamp); free(r->stamp); free(r->seen);
}

static void ref_unit(struct ref *r, uint32_t mask, uint32_t norm, uint32_t side, const uint8_t *p, uint64_t n)
{
	struct kgenome_mtn_win w;
	uint32_t top;

	if (!r->n_pair || !kgenome_mtn_win_begin(&w, p, n, norm))
		return;
	top = r->pair[r->n_pair - 1u].hash;
	do {
		uint32_t h = kgenome_mtn_win_value(&w), lo = 0, hi = r->n_pair;

		if (h > top)
			continue;
		if (!((r->bloom[(h & r->bmask) >> 6] >> (h & 63u)) & 1u))
			continue;
		if (kgenome_mtn_win_flat(&w))
			continue;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (r->pair[mid].hash < h)
				lo = mid + 1u;
			else
				hi = mid;
		}
		for (; lo < r->n_pair && r->pair[lo].hash == h; lo++) {
			uint32_t b = r->pair[lo].bs >> 8;
			const struct kof_mutation_block *k = &r->block[b];

			if (r->pstamp[lo] == r->gen)
				continue;
			if (k->norm != norm || k->side != side || (!r->any && !(k->scan_mask & mask)))
				continue;
			r->pstamp[lo] = r->gen;
			if (r->stamp[b] != r->gen) {
				r->stamp[b] = r->gen;
				r->seen[b] = 0;
			}
			r->seen[b]++;
		}
	} while (kgenome_mtn_win_next(&w));
}

static uint32_t ref_count(const struct ref *r, uint32_t b)
{
	return r->stamp[b] == r->gen ? r->seen[b] : 0u;
}

/* ---- material --------------------------------------------------------- */

struct unit {
	uint32_t mask, norm, side;
	int any;
	const uint8_t *p;
	uint64_t n;
};

/* The window values of a buffer, under a normalizer. */
static uint32_t values(const uint8_t *p, uint64_t n, uint32_t norm, uint32_t *out, uint32_t max)
{
	struct kgenome_mtn_win w;
	uint32_t k = 0;

	if (!kgenome_mtn_win_begin(&w, p, n, norm))
		return 0;
	do {
		if (k < max && !kgenome_mtn_win_flat(&w))
			out[k++] = kgenome_mtn_win_value(&w);
	} while (kgenome_mtn_win_next(&w));
	return k;
}

struct db {
	struct kof_mutation_block *b;
	uint32_t *pool, nb, np;
};

static void db_free(struct db *d)
{
	free(d->b);
	free(d->pool);
	memset(d, 0, sizeof *d);
}

/* Random blocks over a pool of values taken from `src`: so objects made of `src` hit. */
static void db_random(struct db *d, uint32_t nb, const uint32_t *src, uint32_t ns, uint32_t *seed,
		      uint32_t share)
{
	uint32_t i, j;

	d->nb = nb;
	d->b = calloc(nb ? nb : 1u, sizeof *d->b);
	d->pool = malloc((size_t)nb * 32u * 4u + 4u);
	d->np = 0;
	for (i = 0; i < nb; i++) {
		uint32_t n = 16u + rnd(seed) % 17u;

		d->b[i].first_hash = d->np;
		d->b[i].n_hash = n;
		d->b[i].scan_mask = 1u << (rnd(seed) % 3u);
		if (rnd(seed) % 5u == 0)
			d->b[i].scan_mask |= 1u << (rnd(seed) % 3u);
		d->b[i].norm = (uint8_t)(rnd(seed) % 3u);
		d->b[i].side = (uint8_t)(rnd(seed) % 2u);
		for (j = 0; j < n; j++) {
			uint32_t v;

			if (j && rnd(seed) % 16u == 0)
				v = d->pool[d->np - 1u];                  /* a hash twice in one block */
			else if (share && rnd(seed) % share == 0)
				v = src[rnd(seed) % (ns < 8u ? ns : 8u)]; /* a few values held by many blocks */
			else if (rnd(seed) % 4u)
				v = src[rnd(seed) % ns];
			else
				v = rnd(seed);
			d->pool[d->np++] = v;
		}
	}
}

/* Run a script on ref and on the new matcher (default batch, and a batch of 4096); compare every block. */
static int same_all(const struct db *d, const struct kof_mutation_build_req *rq0,
		    const struct unit *u, uint32_t nu, uint32_t objects)
{
	struct kof_mutation_build_req rq = *rq0;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx cs, cb;
	struct ref r;
	uint32_t o, i, b, bad = 0;

	rq.blocks = d->b; rq.n_blocks = d->nb; rq.pool = d->pool; rq.n_pool = d->np;
	set = kof_mutation_build_req(&rq);
	if (!set) {
		CK(set != NULL);
		return 0;
	}
	ref_init(&r, d->b, d->nb, d->pool);
	CK(kof_mutation_ctx_init(&cs, set) && kof_mutation_ctx_init(&cb, set));
	cs.chunk_max = 4096u;
	for (o = 0; o < objects; o++) {
		r.gen++;
		r.any = 0;
		kof_mutation_begin(&cs);
		kof_mutation_begin(&cb);
		for (i = 0; i < nu; i++) {
			if (u[i].any != r.any) {
				r.any = u[i].any;
				kof_mutation_any_region(&cs, u[i].any);
				kof_mutation_any_region(&cb, u[i].any);
			}
			ref_unit(&r, u[i].mask, u[i].norm, u[i].side, u[i].p, u[i].n);
			kof_mutation_unit(&cs, u[i].mask, u[i].norm, u[i].side, u[i].p, u[i].n);
			kof_mutation_unit(&cb, u[i].mask, u[i].norm, u[i].side, u[i].p, u[i].n);
		}
		for (b = 0; b < d->nb; b++) {
			uint32_t x = ref_count(&r, b);

			credited += x;

			if (kof_mutation_matched(&cs, b) != x || kof_mutation_matched(&cb, b) != x)
				bad++;
		}
	}
	CK(bad == 0);
	ref_free(&r);
	kof_mutation_ctx_done(&cs);
	kof_mutation_ctx_done(&cb);
	kof_mutation_set_free(set);
	return bad == 0;
}

static void fill(uint8_t *p, uint64_t n, uint32_t *seed)
{
	uint64_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)rnd(seed);
}

/* ---- exactness vs the old matcher ------------------------------------- */

static void t_exact(void)
{
	enum { N = 40000 };
	static uint8_t obj[N];
	static uint32_t src[N];
	struct unit u[16];
	struct kof_mutation_build_req rq;
	uint32_t seed = 0xC0FFEEu, t, ns, k;
	struct db d;

	memset(&rq, 0, sizeof rq);
	for (t = 0; t < 6; t++) {
		uint32_t nu = 0;

		fill(obj, N, &seed);
		if (t & 1u)                                   /* repetition: periodic data and copies */
			for (k = 4096; k < N; k++)
				obj[k] = obj[k % 4096u];
		if (t == 2)
			memset(obj + 9000, 0, 6000);          /* flat run: skipped by the flat test */
		ns = values(obj, N, 0, src, N);
		db_random(&d, 300 + t * 100u, src, ns, &seed, t % 3u ? 4u : 0u);
		/* units: pieces of the object in several regions, norms, sides; some repeated; any toggled */
		for (k = 0; k < 12u; k++) {
			u[nu].mask = 1u << (rnd(&seed) % 3u);
			u[nu].norm = rnd(&seed) % 3u;
			u[nu].side = rnd(&seed) % 2u;
			u[nu].any = (t >= 4u && k >= 8u);
			u[nu].p = obj + rnd(&seed) % (N / 2u);
			u[nu].n = 2000u + rnd(&seed) % (N / 2u - 2000u);
			nu++;
		}
		u[nu - 1u].mask = 0;                                   /* matches nothing unless any */
		same_all(&d, &rq, u, nu, 3);
		/* the same with a small filter and with none */
		rq.bloom_bpk = 1u;
		same_all(&d, &rq, u, nu, 1);
		rq.bloom_bpk = 0;
		rq.flags = KOF_MTN_BUILD_NO_FILTER;
		same_all(&d, &rq, u, nu, 1);
		rq.flags = 0;
		db_free(&d);
	}
	CK(credited > 1000u);                       /* the comparison saw real credit, not zeros */
	printf("  exact vs the old matcher (one batch, and batches of 4096): ok (%llu credits compared)\n", (unsigned long long)credited);
}

/* ---- DoS fixtures, in visit counts ------------------------------------ */

static void make_hot_db(struct db *d, uint32_t R, const uint32_t *hot, uint32_t nhot, uint32_t *seed)
{
	uint32_t i, j;

	d->nb = R;
	d->b = calloc(R, sizeof *d->b);
	d->pool = malloc((size_t)R * 32u * 4u);
	d->np = 0;
	for (i = 0; i < R; i++) {
		d->b[i].first_hash = d->np;
		d->b[i].n_hash = 32;
		d->b[i].scan_mask = 1u;
		for (j = 0; j < 32u; j++)
			d->pool[d->np++] = j < nhot ? hot[j] : rnd(seed);
	}
}

static void t_hot(void)
{
	enum { R = 5000, REP = 8000 };
	static uint8_t pat[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	uint8_t *obj = malloc((size_t)REP * 8u);
	uint32_t hot[8], seed = 31, i;
	struct db d;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;
	struct kof_mutation_build_res res;
	struct kof_mutation_build_req rq;

	for (i = 0; i < REP; i++)
		memcpy(obj + (size_t)i * 8u, pat, 8);
	values(obj, 64, 0, hot, 8);
	make_hot_db(&d, R, hot, 8, &seed);
	memset(&rq, 0, sizeof rq);
	rq.blocks = d.b; rq.n_blocks = R; rq.pool = d.pool; rq.n_pool = d.np; rq.res = &res;
	set = kof_mutation_build_req(&rq);
	CK(set && kof_mutation_ctx_init(&c, set));
	CK(res.max_mult == R);
	/* periodic data whose 8 rotations are held by 5000 blocks, 64000 windows: 8 walks of 5000 */
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, (uint64_t)REP * 8u);
	kof_mutation_stat(&c, &st);
	CK(st.walks == 8u && st.visits == 8u * R);
	CK(st.probes <= 8u + 1u);               /* every repeat is one survivor of the batch, not a probe */
	CK(st.touched == R && st.status == 0 && st.n_chunks == 1u);
	CK(kof_mutation_matched(&c, 0) == 8u && kof_mutation_matched(&c, R - 1u) == 8u);
	/* the same in batches of 4096: the hot table answers the second batch, nothing is walked twice */
	c.chunk_max = 4096u;
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, (uint64_t)REP * 8u);
	kof_mutation_stat(&c, &st);
	CK(st.walks == 8u && st.visits == 8u * R && st.n_chunks == 1u + (REP * 8u - 1u) / 4096u);
	/* a second unit with the same context repeats it for free */
	kof_mutation_unit(&c, 1u, 0, 0, obj, (uint64_t)REP * 8u);
	kof_mutation_stat(&c, &st);
	CK(st.walks == 8u);
	/* a different region walks again, once, and credits nothing (the blocks are in region 1) */
	kof_mutation_unit(&c, 2u, 0, 0, obj, (uint64_t)REP * 8u);
	kof_mutation_unit(&c, 2u, 0, 0, obj, (uint64_t)REP * 8u);
	kof_mutation_stat(&c, &st);
	CK(st.walks == 16u);                     /* region 2 is a new context: one more walk per value, once */
	/* alternating regions, 50 times: still bounded by (values x contexts) */
	kof_mutation_begin(&c);
	for (i = 0; i < 50u; i++) {
		kof_mutation_unit(&c, 1u, 0, 0, obj, 800u);
		kof_mutation_unit(&c, 2u, 0, 0, obj, 800u);
	}
	kof_mutation_stat(&c, &st);
	CK(st.walks <= 16u && st.visits <= 16u * R);
	CK(kof_mutation_matched(&c, 0) == 8u);
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
	db_free(&d);
	free(obj);
	printf("  hot hash, periodic data: ok\n");
}

static void t_flat_and_bloom_defeat(void)
{
	enum { R = 2000 };
	uint8_t *z = calloc(1, 1u << 20), *fp = malloc(8u << 14);
	uint32_t seed = 7, i, n = 0;
	struct db d;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;
	struct kof_mutation_build_res res;
	struct kof_mutation_build_req rq;

	make_hot_db(&d, R, NULL, 0, &seed);
	memset(&rq, 0, sizeof rq);
	rq.blocks = d.b; rq.n_blocks = R; rq.pool = d.pool; rq.n_pool = d.np; rq.res = &res;
	rq.bloom_bpk = 4u;                                 /* a small filter, so some windows pass it */
	set = kof_mutation_build_req(&rq);
	CK(set && kof_mutation_ctx_init(&c, set));
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, z, 1u << 20);      /* zero-filled: every window flat */
	kof_mutation_stat(&c, &st);
	CK(st.probes == 0 && st.walks == 0 && st.touched == 0 && st.io_reads == 0);
	/* windows that pass the filter and are in no block: found by trial through the probe, then
	 * repeated 16384 times in one object */
	while (n < 8u) {
		uint8_t w[9];
		uint32_t vv;

		fill(w, 9, &seed);
		values(w, 8, 0, &vv, 1);
		if (kof_mutation_probe(set, vv) == 1u) {
			memcpy(fp + (size_t)n * 8u, w, 8);
			n++;
		}
	}
	for (i = 8; i < (8u << 14) / 8u; i++)
		memcpy(fp + (size_t)i * 8u, fp + (size_t)(i % 8u) * 8u, 8);
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, fp, 8u << 14);
	kof_mutation_stat(&c, &st);
	/* bounded: no walk, no state, and the repeats are one survivor each in a batch */
	CK(st.walks == 0 && st.visits == 0 && st.touched == 0 && st.probes <= 64u);   /* 8 patterns x 8 rotations, each one survivor */
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
	db_free(&d);
	free(z); free(fp);
	printf("  zero-filled and filter-passing windows: ok\n");
}

static void t_zipf_and_everything(void)
{
	enum { N = 60000 };
	uint8_t *obj = malloc(N);
	uint32_t *src = malloc(N * 4u), seed = 99, ns, i, j;
	struct db d;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;
	struct kof_mutation_build_res res;
	struct kof_mutation_build_req rq;
	uint32_t zb = 4000;

	fill(obj, N, &seed);
	ns = values(obj, N, 0, src, N);
	/* every window of the object is in the database: the hit-everything object; and a Zipf-like skew */
	d.nb = zb;
	d.b = calloc(zb, sizeof *d.b);
	d.pool = malloc((size_t)zb * 32u * 4u);
	d.np = 0;
	for (i = 0; i < zb; i++) {
		d.b[i].first_hash = d.np; d.b[i].n_hash = 32; d.b[i].scan_mask = 1u;
		for (j = 0; j < 32u; j++) {
			uint32_t r = rnd(&seed) % 1024u, x = 0;

			while (r >>= 1)                         /* P(index) ~ 1/rank: heavy low indices */
				x++;
			d.pool[d.np++] = src[(x ? rnd(&seed) % (1u << (x < 12 ? x : 12)) : 0u) % ns];
		}
	}
	memset(&rq, 0, sizeof rq);
	rq.blocks = d.b; rq.n_blocks = zb; rq.pool = d.pool; rq.n_pool = d.np; rq.res = &res;
	set = kof_mutation_build_req(&rq);
	CK(set && kof_mutation_ctx_init(&c, set));
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, N);
	kof_mutation_stat(&c, &st);
	/* each distinct value walked once: visits is at most the number of entries, however skewed */
	CK(st.visits <= res.n_pair && st.walks <= res.n_key && st.touched <= zb);
	CK(st.status == 0);
	printf("  zipf db: visits %llu of %u entries, %llu walks of %u values, max multiplicity %u\n",
	       (unsigned long long)st.visits, res.n_pair, (unsigned long long)st.walks, res.n_key, res.max_mult);
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
	db_free(&d);
	free(obj); free(src);
}

/* The inverse of an odd number mod 2^32: how to make hashes whose KEY lands where a test wants. */
static uint32_t inv32(uint32_t m)
{
	uint32_t x = m, i;

	for (i = 0; i < 5u; i++)
		x *= 2u - m * x;
	return x;
}

/*
 * A DATABASE MADE TO SKEW: every hash that matters is in one bucket of the directory, and that
 * bucket is bigger than the read buffer (1 MiB: 149,796 entries of 7 bytes). Only a pack built
 * for it has one, since the key is multiplied - but a pack is a file. The matcher must still
 * answer exactly, by searching the bucket with small reads, and must stay inside the object's read
 * allowance and say so when it does not.
 */
static void t_skew_and_oversize(void)
{
	enum { N = 400000, NV = 8, R = 20000 };
	uint8_t *obj = malloc(N);
	uint32_t *val = malloc(N * 4u), seed = 1234, ns, i, j, k, best = 0, bestn = 0, nv = 0;
	uint32_t *cnt = calloc(65536u, 4), v8[NV];
	struct db d;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;
	struct kof_mutation_build_req rq;
	struct ref r;
	uint32_t bad = 0;

	fill(obj, N, &seed);
	ns = values(obj, N, 0, val, N);
	/* the bucket of the key that holds the most of the object's own windows */
	for (i = 0; i < ns; i++) {
		uint32_t bk = (val[i] * 0x9E3779B1u) >> 16;

		if (++cnt[bk] > bestn) {
			bestn = cnt[bk];
			best = bk;
		}
	}
	for (i = 0; i < ns && nv < NV; i++)
		if (((val[i] * 0x9E3779B1u) >> 16) == best)
			v8[nv++] = val[i];
	CK(nv >= 4u);
	/* R blocks each holding all of them (so the bucket has R x nv entries, runs of R) and random rest */
	d.nb = R;
	d.b = calloc(R, sizeof *d.b);
	d.pool = malloc((size_t)R * 32u * 4u);
	d.np = 0;
	for (i = 0; i < R; i++) {
		d.b[i].first_hash = d.np; d.b[i].n_hash = 32; d.b[i].scan_mask = 1u;
		for (j = 0; j < 32u; j++)
			d.pool[d.np++] = j < nv ? v8[j] : rnd(&seed);
	}
	CK((uint64_t)R * nv * 7u > (1u << 20));            /* the bucket is past the read buffer */
	/* a skew key of the other kind too: arbitrary values forced into one bucket by construction */
	{
		uint32_t m = inv32(0x9E3779B1u);

		CK((0x12345678u * 0x9E3779B1u) * m == 0x12345678u);
	}
	memset(&rq, 0, sizeof rq);
	rq.blocks = d.b; rq.n_blocks = d.nb; rq.pool = d.pool; rq.n_pool = d.np;
	set = kof_mutation_build_req(&rq);
	CK(set && kof_mutation_ctx_init(&c, set));
	ref_init(&r, d.b, d.nb, d.pool);
	r.gen++;
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, N);
	ref_unit(&r, 1u, 0, 0, obj, N);
	for (k = 0; k < d.nb; k++)
		bad += kof_mutation_matched(&c, k) != ref_count(&r, k);
	kof_mutation_stat(&c, &st);
	CK(bad == 0 && kof_mutation_matched(&c, 0) >= nv && st.status == 0);
	CK(st.io_reads > 0 && st.io_reads < 400u);          /* small reads, not the bucket: bounded by the search */
	/* the allowance: three pages of reads, then the object says it ran out and counts only fall */
	c.io_budget = 3u * 4096u;
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, N);
	kof_mutation_stat(&c, &st);
	CK(st.status & KOF_MTN_S_IO_BUDGET);
	for (k = 0; k < d.nb; k++)
		CK(kof_mutation_matched(&c, k) <= ref_count(&r, k));
	CK(kof_mutation_matched(&c, 0) < ref_count(&r, 0));
	kof_mutation_begin(&c);                              /* and the next object starts clean, the life counter kept it */
	kof_mutation_stat(&c, &st);
	CK(st.status == 0 && st.life_io_objects == 1u);
	ref_free(&r);
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
	db_free(&d);
	free(obj); free(val); free(cnt);
	printf("  skewed bucket past the read buffer: exact, bounded, reported (bucket %u holds %u entries' worth)\n",
	       best, R * nv);
}

/* ---- budget, allowance, wraparound, threads --------------------------- */

static void t_budget_and_allowance(void)
{
	enum { R = 3000 };
	static uint8_t pat[8] = { 9, 8, 7, 6, 5, 4, 3, 1 };
	uint8_t obj[8 * 64];
	uint32_t hot[8], seed = 5, i;
	struct db d;
	struct kof_mutation_build_res res;
	struct kof_mutation_build_req rq;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;

	for (i = 0; i < 64u; i++)
		memcpy(obj + i * 8u, pat, 8);
	values(obj, 64, 0, hot, 8);
	make_hot_db(&d, R, hot, 3, &seed);              /* three hot values, 3000 blocks each */
	memset(&rq, 0, sizeof rq);
	rq.blocks = d.b; rq.n_blocks = R; rq.pool = d.pool; rq.n_pool = d.np; rq.res = &res;
	rq.max_visit = 2u * R + 10u;                    /* room for two of the three walks */
	set = kof_mutation_build_req(&rq);
	CK(set && kof_mutation_ctx_init(&c, set));
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, sizeof obj);
	kof_mutation_stat(&c, &st);
	CK((st.status & KOF_MTN_S_WALK_TRUNCATED) && st.trunc_walks >= 1u && st.trunc_pairs >= R);
	CK(st.visits <= rq.max_visit);
	CK(kof_mutation_matched(&c, 0) < 3u);           /* a lower bound, never a higher count */
	kof_mutation_begin(&c);                         /* the next object starts clean, and the life counter kept it */
	kof_mutation_stat(&c, &st);
	CK(st.status == 0 && st.life_trunc_objects == 1u);
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);

	/* the allowance: refused whole, with the cause; the filter alone degrades */
	rq.max_visit = 0;
	rq.max_bytes = 1000;
	CK(kof_mutation_build_req(&rq) == NULL && (res.status & KOF_MTN_B_OVER_BUDGET));
	rq.max_bytes = 0;
	set = kof_mutation_build_req(&rq);
	CK(set && (res.status & ~KOF_MTN_B_IN_RAM) == 0 && res.bloom_bits >= (uint64_t)KOF_KIX_FILTER_FLOOR_BPK * res.n_key);
	{
		/* Squeeze the allowance: the filter halves first (each step reported), then the index is
		 * refused whole with its cause. Nothing in between is silent. */
		uint64_t full = res.bytes, was = res.bloom_bits, at;
		int degraded = 0, refused = 0;

		kof_mutation_set_free(set);
		for (at = full; at > 1000; at -= full / 64u) {
			rq.max_bytes = at;
			set = kof_mutation_build_req(&rq);
			if (set) {
				CK(res.bytes <= at);
				CK(!!(res.status & KOF_MTN_B_FILTER_DEGRADED) == (res.bloom_bits < (uint64_t)KOF_KIX_FILTER_FLOOR_BPK * res.n_key));
				degraded += (res.status & KOF_MTN_B_FILTER_DEGRADED) != 0;
				CK(res.bloom_bits <= was);
				kof_mutation_set_free(set);
			} else {
				CK(res.status & KOF_MTN_B_OVER_BUDGET);
				refused = 1;
				break;
			}
		}
		CK(degraded >= 1 && refused);
	}
	/* refusals name their cause */
	{
		struct kof_mutation_block b = { 0, 32, 1u, 0, 0, { 0, 0 } };
		uint32_t pool[256] = { 0 };

		memset(&rq, 0, sizeof rq);
		rq.res = &res; rq.blocks = &b; rq.pool = pool; rq.n_pool = 256;
		rq.n_blocks = 0x01000000u;
		CK(kof_mutation_build_req(&rq) == NULL && (res.status & KOF_MTN_B_TOO_MANY_BLOCKS));
		rq.n_blocks = 1; b.n_hash = 129;
		CK(kof_mutation_build_req(&rq) == NULL && (res.status & KOF_MTN_B_BAD_BLOCK));
	}
	db_free(&d);
	printf("  budget and allowance: ok\n");
}

/*
 * THE STATE IS CAPPED BY THE HOST'S LEDGER (kof_mutation_limit): what the object credited lives in tables that
 * grow with what it touched, and one the allowance will not let grow is not made - the object says so and
 * its counts are lower bounds, never higher ones. Held is what the host charges to its ledger.
 */
static void t_state_cap(void)
{
	enum { N = 60000 };
	uint8_t *obj = malloc(N);
	uint32_t *src = malloc(N * 4u), seed = 4242, ns, b, lower = 0, k;
	uint64_t caps[3] = { 20000u, 100000u, (1u << 20) + 65536u };
	struct db d;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;
	struct ref r;

	fill(obj, N, &seed);
	ns = values(obj, N, 0, src, N);
	db_random(&d, 2500, src, ns, &seed, 0);
	set = kof_mutation_build(d.b, d.nb, d.pool, d.np);
	CK(set && kof_mutation_ctx_init(&c, set));
	ref_init(&r, d.b, d.nb, d.pool);
	r.gen++;
	ref_unit(&r, 1u, 0, 0, obj, N);
	ref_unit(&r, 2u, 1, 0, obj, N);
	ref_unit(&r, 2u, 0, 1, obj, N);
	for (k = 0; k < 3u; k++) {
		kof_mutation_trim(&c);
		kof_mutation_limit(&c, caps[k]);
		kof_mutation_begin(&c);
		kof_mutation_unit(&c, 1u, 0, 0, obj, N);
		kof_mutation_unit(&c, 2u, 1, 0, obj, N);
		kof_mutation_unit(&c, 2u, 0, 1, obj, N);
		kof_mutation_stat(&c, &st);
		CK(st.status & KOF_MTN_S_STATE_NOMEM);
		CK(kof_mutation_held(&c) <= caps[k]);                   /* never past what the host allowed */
		lower = 0;
		for (b = 0; b < d.nb; b++) {
			CK(kof_mutation_matched(&c, b) <= ref_count(&r, b));
			lower += kof_mutation_matched(&c, b) < ref_count(&r, b);
		}
		CK(lower > 0u);
	}
	/* with room for it the same object is exact, and what it held is what the host is told */
	kof_mutation_trim(&c);
	kof_mutation_limit(&c, KOF_MUTATION_STATE_CAP);
	kof_mutation_begin(&c);
	kof_mutation_unit(&c, 1u, 0, 0, obj, N);
	kof_mutation_unit(&c, 2u, 1, 0, obj, N);
	kof_mutation_unit(&c, 2u, 0, 1, obj, N);
	kof_mutation_stat(&c, &st);
	CK(st.status == 0 && kof_mutation_held(&c) > 0 && kof_mutation_held(&c) == st.state_bytes);
	for (b = 0; b < d.nb; b++)
		CK(kof_mutation_matched(&c, b) == ref_count(&r, b));
	kof_mutation_trim(&c);
	CK(kof_mutation_held(&c) == 0 && kof_mutation_matched(&c, 0) == 0);   /* a trim gives all of it back */
	ref_free(&r);
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
	db_free(&d);
	free(obj); free(src);
	printf("  state cap: refused growth is flagged, counts are lower bounds, held never passes the cap, trim gives it back\n");
}

static void t_wrap(void)
{
	enum { N = 20000 };
	static uint8_t obj[N];
	static uint32_t src[N];
	uint32_t seed = 77, ns, o, b, bad = 0;
	struct db d;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx c;
	struct ref r;

	fill(obj, N, &seed);
	ns = values(obj, N, 0, src, N);
	db_random(&d, 200, src, ns, &seed, 3u);
	set = kof_mutation_build(d.b, d.nb, d.pool, d.np);
	CK(set && kof_mutation_ctx_init(&c, set));
	ref_init(&r, d.b, d.nb, d.pool);
	c.gen = 0xfffffffeu;                            /* the stamps and the node state cross zero */
	for (o = 0; o < 4u; o++) {
		uint32_t m = 1u << (o % 3u);

		r.gen++;
		kof_mutation_begin(&c);
		kof_mutation_unit(&c, m, 0, 0, obj, N);
		ref_unit(&r, m, 0, 0, obj, N);
		for (b = 0; b < d.nb; b++)
			bad += kof_mutation_matched(&c, b) != ref_count(&r, b);
	}
	CK(bad == 0 && c.gen < 8u);
	ref_free(&r);
	kof_mutation_ctx_done(&c);
	kof_mutation_set_free(set);
	db_free(&d);
	printf("  generation wraparound: ok\n");
}

struct thr {
	const struct kof_mutation_set *set;
	const uint8_t *obj;
	uint64_t n;
	uint32_t nb, *out;
};

static void *thr_run(void *a)
{
	struct thr *t = a;
	struct kof_mutation_ctx c;
	uint32_t i, b;

	if (!kof_mutation_ctx_init(&c, t->set))
		return NULL;
	c.chunk_max = t->nb & 1u ? 4096u : 0u;
	for (i = 0; i < 20u; i++) {
		kof_mutation_begin(&c);
		kof_mutation_unit(&c, 1u, 0, 0, t->obj, t->n);
		kof_mutation_unit(&c, 2u, 1, 0, t->obj, t->n);
	}
	for (b = 0; b < t->nb; b++)
		t->out[b] = kof_mutation_matched(&c, b);
	kof_mutation_ctx_done(&c);
	return NULL;
}

static void t_threads(void)
{
	enum { N = 150000, T = 4 };
	uint8_t *obj = malloc(N);
	uint32_t *src = malloc(N * 4u), seed = 21, ns, i, b, bad = 0;
	struct db d;
	struct kof_mutation_set *set;
	struct thr th[T];
	pthread_t id[T];
	uint32_t *want;

	fill(obj, N, &seed);
	ns = values(obj, N, 0, src, N);
	db_random(&d, 800, src, ns, &seed, 2u);
	set = kof_mutation_build(d.b, d.nb, d.pool, d.np);
	CK(set != NULL);
	want = calloc(d.nb, 4);
	for (i = 0; i < T; i++) {
		th[i].set = set; th[i].obj = obj; th[i].n = N; th[i].nb = d.nb;
		th[i].out = calloc(d.nb, 4);
	}
	thr_run(&th[0]);
	memcpy(want, th[0].out, (size_t)d.nb * 4u);
	for (i = 0; i < T; i++)
		pthread_create(&id[i], NULL, thr_run, &th[i]);
	for (i = 0; i < T; i++)
		pthread_join(id[i], NULL);
	for (i = 0; i < T; i++) {
		for (b = 0; b < d.nb; b++)
			bad += th[i].out[b] != want[b];
		free(th[i].out);
	}
	CK(bad == 0);
	free(want);
	kof_mutation_set_free(set);
	db_free(&d);
	free(obj); free(src);
	printf("  four scanners on one index: ok\n");
}

/* ---- opt-in: scale, corpus, bench ------------------------------------- */

static size_t rss_kb(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char l[128];
	size_t v = 0;

	while (f && fgets(l, sizeof l, f))
		if (!strncmp(l, "VmRSS:", 6))
			v = (size_t)strtoul(l + 6, NULL, 10);
	if (f)
		fclose(f);
	return v;
}

static void t_scale(double nbd)
{
	uint32_t nb = (uint32_t)nbd, i, j, seed = 3;
	struct kof_mutation_block *b = malloc((size_t)nb * sizeof *b);
	uint32_t *pool = malloc((size_t)nb * 32u * 4u);
	struct kof_mutation_build_res res;
	struct kof_mutation_build_req rq;
	struct kof_mutation_set *set;
	size_t r0 = rss_kb();
	double t0;

	for (i = 0; i < nb; i++) {
		b[i].first_hash = i * 32u; b[i].n_hash = 32; b[i].scan_mask = 1u; b[i].norm = 0; b[i].side = 0;
		b[i].reserved[0] = b[i].reserved[1] = 0;
		for (j = 0; j < 32u; j++)
			pool[(size_t)i * 32u + j] = rnd(&seed);
	}
	memset(&rq, 0, sizeof rq);
	rq.blocks = b; rq.n_blocks = nb; rq.pool = pool; rq.n_pool = nb * 32u; rq.res = &res;
	r0 = rss_kb();
	t0 = now();
	set = kof_mutation_build_req(&rq);
	CK(set != NULL);
	printf("SCALE\tblocks=%u build_s=%.2f resident_bytes=%llu rss_delta_mb=%zu bloom_bits_per_key=%.1f status=0x%x\n",
	       nb, now() - t0, (unsigned long long)res.bytes, (rss_kb() - r0) / 1024u,
	       (double)res.bloom_bits / (double)res.n_key, res.status);
	/* the filter is capped by the ledger, never by silence: a status says when it holds fewer than 16 bits a hash */
	CK(!!(res.status & KOF_MTN_B_FILTER_DEGRADED) == (res.bloom_bits < (uint64_t)KOF_KIX_FILTER_FLOOR_BPK * res.n_key));
	kof_mutation_set_free(set);
	free(b); free(pool);
}


/* ---- opt-in: one measured cell ---------------------------------------- */

static uint8_t *tile(const uint8_t *per, uint64_t L, uint64_t n)
{
	uint8_t *o = malloc(n);
	uint64_t i;

	for (i = 0; i < n; i++)
		o[i] = per[i % L];
	return o;
}

/* --cell=KIND,PATH,FILTER,S,M[,BPK] : KIND miss0|hit10|hit100|bflood|hot, PATH ref|kix, FILTER 0|1 */
static void t_cell(const char *spec)
{
	char kind[16], path[16];
	unsigned filt, bpk = 0;
	double Sd, Md;
	uint32_t S, M, i, j, seed = 11, L, nkeys;
	uint8_t *per, *obj;
	uint32_t *pool, *val;
	struct kof_mutation_block *b;
	struct kof_mutation_build_req rq;
	struct kof_mutation_build_res res;
	struct kof_mutation_set *set = NULL;
	struct kof_mutation_ctx c;
	struct kof_mutation_stat st;
	struct ref r;
	double t0, best = 1e30, build = 0;
	int rep, isref;

	if (sscanf(spec, "%15[^,],%15[^,],%u,%lf,%lf,%u", kind, path, &filt, &Sd, &Md, &bpk) < 5)
		return;
	S = (uint32_t)Sd; M = (uint32_t)Md;
	nkeys = M * 32u;
	L = S < nkeys ? S : nkeys;
	if (!strcmp(kind, "hot"))
		L = 8;
	per = malloc((size_t)L + 16u);
	fill(per, L, &seed);
	obj = tile(per, L, (uint64_t)S + 8u);
	val = malloc((size_t)(L + 8u) * 4u);
	{
		uint8_t *two = tile(per, L, (uint64_t)L + 8u);

		L = values(two, (uint64_t)L + 8u, 0, val, L + 8u);
		free(two);
	}
	pool = malloc((size_t)nkeys * 4u);
	b = calloc(M, sizeof *b);
	for (i = 0; i < nkeys; i++) {
		uint32_t v = rnd(&seed);

		if (!strcmp(kind, "hit100"))
			v = i < L ? val[i] : v;
		else if (!strcmp(kind, "hit10") && i < L / 10u)
			v = val[i * 10u];
		else if (!strcmp(kind, "hot") && i % 32u < 8u)
			v = val[(i % 32u) % (L ? L : 1u)];
		pool[i] = v;
	}
	for (i = 0; i < M; i++) {
		b[i].first_hash = i * 32u; b[i].n_hash = 32; b[i].scan_mask = 1u;
	}
	if (!strcmp(kind, "hit100") || !strcmp(kind, "hit10"))      /* shuffle so the hits are not contiguous */
		for (i = nkeys - 1u; i > 0; i--) {
			uint32_t k = rnd(&seed) % (i + 1u), t = pool[i];

			pool[i] = pool[k]; pool[k] = t;
		}
	isref = !strcmp(path, "ref");
	memset(&rq, 0, sizeof rq);
	rq.blocks = b; rq.n_blocks = M; rq.pool = pool; rq.n_pool = nkeys; rq.res = &res;
	rq.flags = filt ? 0u : KOF_MTN_BUILD_NO_FILTER;
	rq.bloom_bpk = bpk;
	t0 = now();
	if (isref)
		ref_init(&r, b, M, pool);
	else {
		set = kof_mutation_build_req(&rq);
		CK(set && kof_mutation_ctx_init(&c, set));
	}
	build = now() - t0;
	if (!strcmp(kind, "bflood") && set) {          /* greedy: each new byte picks a window that passes the filter and is in no block */
		uint32_t n = 0;

		memcpy(obj, per, 8);
		for (i = 8; i < S + 8u; i++) {
			uint32_t tries, vv;
			uint8_t w[8];

			uint32_t start = rnd(&seed) & 255u;

			for (tries = 0; tries < 256u; tries++) {
				uint32_t ok;

				memmove(w, obj + i - 7u, 7);
				w[7] = (uint8_t)(start + tries);
				values(w, 8, 0, &vv, 1);
				ok = kof_mutation_probe(set, vv);
				if (ok == 1u)
					break;
			}
			obj[i] = (uint8_t)(start + (tries < 256u ? tries : 0u));
			n += tries < 256u;
		}
		printf("CELL\tbflood crafted %u of %u windows\n", n, S);
	}
	for (rep = 0; rep < 3; rep++) {
		t0 = now();
		if (isref) {
			r.gen++;
			ref_unit(&r, 1u, 0, 0, obj, (uint64_t)S + 8u);
		} else {
			kof_mutation_begin(&c);
			kof_mutation_unit(&c, 1u, 0, 0, obj, (uint64_t)S + 8u);
		}
		t0 = now() - t0;
		if (t0 < best)
			best = t0;
	}
	if (set)
		kof_mutation_stat(&c, &st);
	else
		memset(&st, 0, sizeof st);
	(void)j;
	printf("CELL\t%s %s filter=%u bpk=%.1f S=%u M=%u\tns_per_window=%.2f build_s=%.2f bytes_per_hash=%.2f visits=%llu probes=%llu walks=%llu chunks=%u io_reads=%llu rss_mb=%zu\n",
	       kind, path, filt, set ? (double)res.bloom_bits / (double)res.n_key : 0.0, S, M, best * 1e9 / (double)S, build,
	       set ? (double)res.bytes / (double)res.n_pair : 0.0, (unsigned long long)st.visits,
	       (unsigned long long)st.probes, (unsigned long long)st.walks, st.n_chunks,
	       (unsigned long long)st.io_reads, rss_kb() / 1024u);
	if (isref)
		ref_free(&r);
	else {
		kof_mutation_ctx_done(&c);
		kof_mutation_set_free(set);
	}
	free(per); free(obj); free(pool); free(val); free(b);
}

/* ---- opt-in: a database cut from files, three matchers over the same files --- */

static void t_corpus(const char *list)
{
	FILE *f = fopen(list, "r");
	char line[4096];
	struct kof_mutation_block *b = NULL;
	uint32_t *pool = NULL, nb = 0, np = 0, cap = 0, nf = 0, bad = 0;
	char **names = NULL;
	uint8_t **bufs = NULL;
	uint64_t *lens = NULL;
	uint32_t i, k, norm;
	uint64_t total = 0;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx cs, cb;
	struct ref r;
	uint64_t cmp = 0, nz = 0;

	if (!f) {
		printf("  corpus list unreadable\n");
		fails++;
		return;
	}
	while (fgets(line, sizeof line, f)) {
		FILE *g;
		size_t n = strlen(line), got;
		uint8_t *buf;
		long len;

		while (n && (line[n - 1u] == '\n' || line[n - 1u] == '\r'))
			line[--n] = 0;
		g = fopen(line, "rb");
		if (!g)
			continue;
		fseek(g, 0, SEEK_END);
		len = ftell(g);
		fseek(g, 0, SEEK_SET);
		if (len < 4096 || len > (64l << 20)) {
			fclose(g);
			continue;
		}
		buf = malloc((size_t)len);
		got = fread(buf, 1, (size_t)len, g);
		fclose(g);
		if (got != (size_t)len) {
			free(buf);
			continue;
		}
		bufs = realloc(bufs, (nf + 1u) * sizeof *bufs);
		lens = realloc(lens, (nf + 1u) * sizeof *lens);
		bufs[nf] = buf; lens[nf] = (uint64_t)len; nf++;
		total += (uint64_t)len;
		for (k = 0; (uint64_t)k * 8192u < (uint64_t)len; k++) {
			uint32_t piece = (uint32_t)((uint64_t)len - (uint64_t)k * 8192u < 8192u ? (uint64_t)len - (uint64_t)k * 8192u : 8192u), h[64], m;

			norm = (nf + k) % 3u == 0 ? 1u : 0u;
			m = kgenome_mutation_minhash(buf + (size_t)k * 8192u, piece, norm, h);
			if (m < KGENOME_MUTATION_MIN_HASH)
				continue;
			if (nb == cap) {
				cap = cap ? cap * 2u : 1024u;
				b = realloc(b, (size_t)cap * sizeof *b);
				pool = realloc(pool, (size_t)cap * 32u * 4u);
			}
			memset(&b[nb], 0, sizeof b[nb]);
			if (m > 32u)
				m = 32u;
			b[nb].first_hash = np; b[nb].n_hash = m; b[nb].scan_mask = 1u; b[nb].norm = (uint8_t)norm;
			memcpy(pool + np, h, (size_t)m * 4u);
			np += m; nb++;
		}
	}
	fclose(f);
	set = kof_mutation_build(b, nb, pool, np);
	CK(set != NULL);
	ref_init(&r, b, nb, pool);
	CK(kof_mutation_ctx_init(&cs, set) && kof_mutation_ctx_init(&cb, set));
	cs.chunk_max = 4096u;
	for (i = 0; i < nf; i++) {
		r.gen++;
		kof_mutation_begin(&cs); kof_mutation_begin(&cb);
		for (norm = 0; norm < 2u; norm++) {
			ref_unit(&r, 1u, norm, 0, bufs[i], lens[i]);
			kof_mutation_unit(&cs, 1u, norm, 0, bufs[i], lens[i]);
			kof_mutation_unit(&cb, 1u, norm, 0, bufs[i], lens[i]);
		}
		for (k = 0; k < nb; k++) {
			uint32_t x = ref_count(&r, k);

			cmp++;
			nz += x != 0;
			bad += kof_mutation_matched(&cs, k) != x || kof_mutation_matched(&cb, k) != x;
		}
		free(bufs[i]);
	}
	printf("CORPUS\tfiles=%u bytes=%llu blocks=%u hashes=%u (file,block) pairs=%llu nonzero=%llu mismatches=%u\n",
	       nf, (unsigned long long)total, nb, np, (unsigned long long)cmp, (unsigned long long)nz, bad);
	CK(bad == 0 && nz > 0);
	ref_free(&r);
	kof_mutation_ctx_done(&cs); kof_mutation_ctx_done(&cb);
	kof_mutation_set_free(set);
	free(b); free(pool); free(bufs); free(lens); free(names);
}

int main(int argc, char **argv)
{
	int i;
	double scale = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--cell=", 7)) {
			t_cell(argv[i] + 7);
			return fails != 0;
		}
		if (!strncmp(argv[i], "--corpus=", 9)) {
			t_corpus(argv[i] + 9);
			return fails != 0;
		}
	}
	t_exact();
	t_hot();
	t_flat_and_bloom_defeat();
	t_zipf_and_everything();
	t_skew_and_oversize();
	t_budget_and_allowance();
	t_state_cap();
	t_wrap();
	t_threads();
	for (i = 1; i < argc; i++)
		if (!strncmp(argv[i], "--scale=", 8))
			scale = strtod(argv[i] + 8, NULL);
	if (scale >= 1e4)
		t_scale(scale);
	printf("mutation_index: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
