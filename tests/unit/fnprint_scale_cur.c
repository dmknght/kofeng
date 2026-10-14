/*
 * fnprint_scale_cur - the matcher the scanner ships (kofmutation.c), at scale, beside the window stream.
 *
 * WHY A SECOND SCALE TEST. fnprint_scale_synth.c measures the stream's own database on hash values.
 * The shipped matcher takes BYTES (kof_mutation_unit rolls the windows itself), so a fair comparison needs
 * a database whose hashes are window values of real byte spans and an object made of those spans: the
 * generator below makes N blocks, half of them the 32 smallest window values of a 1000-byte span of PRNG
 * bytes (so the values sit at the bottom of the range, as a real block's do) and half uniform random
 * (blocks no object holds), then an object that is M of the spans concatenated. The two structures are
 * asked the same question on the same bytes and must answer the same; the cost of each is printed.
 *
 * THE LIMITS OF THE MATCHER'S INDEX (kofmutation.c), each now loud or bounded:
 *   PL_MAX_BLOCK 0x00ffffff: 16,777,215 blocks (the block id is 24 bits of an entry); a larger set is refused with
 *                       KOF_MTN_B_TOO_MANY_BLOCKS (checked below, and in mutation_index.c).
 *   KOF_MUTATION_MAX_HASH 128 hashes in a block; a block with more is refused with KOF_MTN_B_BAD_BLOCK.
 *   the filter is sized from the database (12 to 24 bits a distinct hash) up to a cap of 16 MiB and by the engine's
 *                       ledger; when it holds under 12 bits a hash KOF_MTN_B_FILTER_DEGRADED says so. Checked below.
 *   per-scanner state is what an object TOUCHED (a table of blocks credited); nothing a block or a pair.
 *   a value's block list is walked once per object, under a visit budget that says when it cuts (kof_mutation_stat).
 *                       Checked below as a count of visits (mutation_index.c holds the rest of the fixtures).
 *   dbloader.c:299      the loader refuses totals above 2^32-1 blocks or pool entries (loud).
 * The default scales (1e4, 1e5 blocks) run in a few seconds and well under 200 MB; --scale=1e6 and
 * --scale=1e7 are opt-in.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include <celllysis/fnprint.h>
#include "known_miss.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static uint64_t rn(uint64_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17;
	return *s;
}

#define SPAN 1000u

static void span_bytes(uint32_t i, uint8_t *out)
{
	uint64_t s = 0x9e3779b97f4a7c15ull ^ ((uint64_t)i * 0x100000001b3ull) ^ 77u;
	uint32_t k;

	for (k = 0; k < SPAN; k++)
		out[k] = (uint8_t)(rn(&s) >> 24);
}

/* The 32 smallest distinct non-flat window values of a span, ascending. */
static uint32_t bottom32(const uint8_t *p, uint32_t *out)
{
	return kgenome_fnprint_wsketch(p, SPAN, NULL, out, 32);
}

struct world {
	struct kof_mutation_block *mb;
	struct kgenome_fnprint_wblock *wb;
	uint32_t *pool;
	uint32_t n;
};

static int world_make(struct world *w, uint32_t n)
{
	uint8_t sp[SPAN];
	uint64_t s = 555;
	uint32_t i, j;

	w->n = n;
	w->mb = malloc((size_t)n * sizeof *w->mb);
	w->wb = malloc((size_t)n * sizeof *w->wb);
	w->pool = malloc((size_t)n * 32u * 4u);
	if (!w->mb || !w->wb || !w->pool)
		return 0;
	for (i = 0; i < n; i++) {
		uint32_t *h = w->pool + (size_t)i * 32u, m = 0;

		if (i % 2u == 0) {                                 /* a block some object holds */
			span_bytes(i, sp);
			m = bottom32(sp, h);
		}
		for (j = m; j < 32; j++)
			h[j] = (uint32_t)rn(&s);                   /* or a block nothing holds */
		w->mb[i].first_hash = i * 32u; w->mb[i].n_hash = 32; w->mb[i].scan_mask = 1u;
		w->mb[i].norm = 0; w->mb[i].side = 0; w->mb[i].reserved[0] = w->mb[i].reserved[1] = 0;
		w->wb[i].first = i * 32u; w->wb[i].n = 32; w->wb[i].side = 0; w->wb[i].tag = i % 16u;
	}
	return 1;
}

static void world_free(struct world *w)
{
	free(w->mb); free(w->wb); free(w->pool);
	memset(w, 0, sizeof *w);
}

static size_t rss_kb(void)
{
	FILE *f = fopen("/proc/self/statm", "r");
	unsigned long a = 0, b = 0;

	if (f) {
		if (fscanf(f, "%lu %lu", &a, &b) != 2)
			b = 0;
		fclose(f);
	}
	return (size_t)b * 4u;
}

/* Both structures, same bytes: equal credit; the costs printed. Returns ns per byte of the matcher / the stream. */
static void t_both(uint32_t n, double *ns_cur, double *ns_new)
{
	struct world w;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx kc;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	struct kof_range ext;
	uint8_t *obj, sp[SPAN];
	uint64_t s = 99, objn;
	uint32_t m = n / 20u + 10u, i, b, bad = 0, full = 0, held = 0;
	double t0, t1, t2, t3, t4, t5;
	size_t r0, r1, r2, r3;

	if (m > 20000u)
		m = 20000u;
	CK(world_make(&w, n));
	obj = malloc((size_t)m * SPAN);
	objn = (uint64_t)m * SPAN;
	for (i = 0; i < m; i++) {
		span_bytes((uint32_t)(rn(&s) % (n / 2u)) * 2u, sp);
		memcpy(obj + (size_t)i * SPAN, sp, SPAN);
	}
	r0 = rss_kb();
	t0 = now();
	set = kof_mutation_build(w.mb, n, w.pool, n * 32u);
	t1 = now();
	CK(set != NULL && kof_mutation_ctx_init(&kc, set));
	r1 = rss_kb();
	kof_mutation_begin(&kc);
	t2 = now();
	kof_mutation_unit(&kc, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_USER, obj, objn);
	t3 = now();
	memset(&o, 0, sizeof o);
	o.n_tag = 16;
	CK(kgenome_fnprint_wdb_build(&d, w.wb, n, w.pool, (uint64_t)n * 32u, &o));
	t4 = now();
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	r2 = rss_kb();
	kgenome_fnprint_wctx_begin(&c);
	ext.off = 0; ext.len = objn;
	memset(&rq, 0, sizeof rq);
	rq.p = obj; rq.n = objn; rq.ext = &ext; rq.n_ext = 1; rq.c = &c; rq.stat = &st;
	t4 = now();
	kgenome_fnprint_wpass(&rq);
	t5 = now();
	r3 = rss_kb();
	for (b = 0; b < n; b++) {
		uint32_t a = kof_mutation_matched(&kc, b), z = kgenome_fnprint_wctx_count(&c, b);

		bad += a != z;
		full += z == 32u;
		held += z > 0;
	}
	CK(bad == 0);                                              /* the same credit on every block */
	{
		/* the filter is sized from the database (12 to 24 bits a distinct hash up to its cap of 16 MiB,
		 * which these scales stay under) and a status says when it holds less (KOF_MTN_B_FILTER_DEGRADED) */
		struct kof_mutation_build_res bi;

		kof_mutation_set_info(set, &bi);
		CK(bi.bloom_bits >= (uint64_t)KOF_KIX_FILTER_FLOOR_BPK * bi.n_key && !(bi.status & KOF_MTN_B_FILTER_DEGRADED));
		printf("SCALE\tINDEX N=%u bytes_per_hash=%.2f bloom_bits_per_key=%.1f max_mult=%u\n", n,
		       (double)bi.bytes / (double)bi.n_pair, (double)bi.bloom_bits / (double)bi.n_key, bi.max_mult);
	}
	CK(full > 0 && held >= full);
	printf("SCALE\tCUR N=%u\tmatcher: build_ms=%.1f rss_after_build_kb=%zu feed_ns/byte=%.2f | stream: pass_ns/byte=%.2f (cand=%llu of %llu windows) rss_kb=%zu\n",
	       n, (t1 - t0) * 1e3, r1 - r0, (t3 - t2) * 1e9 / (double)objn, (t5 - t4) * 1e9 / (double)objn,
	       (unsigned long long)st.n_cand, (unsigned long long)st.n_win, r3 - r2);
	*ns_cur = (t3 - t2) * 1e9 / (double)objn;
	*ns_new = (t5 - t4) * 1e9 / (double)objn;
	(void)r3;
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	kof_mutation_ctx_done(&kc);
	kof_mutation_set_free(set);
	free(obj);
	world_free(&w);
}

/* Refusals of the shipped matcher: loud (NULL), not a truncation. */
static void t_cur_limits(void)
{
	struct kof_mutation_block b = { 0, 32, 1u, 0, 0, { 0, 0 } };
	uint32_t pool[256] = { 0 };

	CK(kof_mutation_build(&b, 0x01000000u, pool, 32) == NULL);        /* PL_MAX_BLOCK + 1: kofmutation.c:199 */
	b.n_hash = 129;
	CK(kof_mutation_build(&b, 1, pool, 256) == NULL);                  /* KOF_MUTATION_MAX_HASH + 1 */
	b.n_hash = 15;
	CK(kof_mutation_build(&b, 1, pool, 256) == NULL);                  /* below KGENOME_MUTATION_MIN_HASH */
}

/* A hash held by R blocks, repeated by the object: the matcher walks the run per window, the stream once. */
static void t_hot_run(void)
{
	enum { R = 5000, REP = 8000 };
	struct kof_mutation_block *mb = malloc((size_t)R * sizeof *mb);
	struct kgenome_fnprint_wblock *wb = malloc((size_t)R * sizeof *wb);
	uint32_t *pool = malloc((size_t)R * 32u * 4u), rot[8], i, j;
	uint8_t pat[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }, *obj = malloc((size_t)REP * 8u + 8u);
	uint64_t s = 31;
	struct kof_mutation_set *set;
	struct kof_mutation_ctx kc;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	struct kof_range ext;
	double t0, t1, t2, t3;

	for (i = 0; i < REP; i++)
		memcpy(obj + (size_t)i * 8u, pat, 8);
	for (i = 0; i < 8; i++) {                                 /* the 8 window values of the rotating pattern */
		uint8_t w8[8];

		for (j = 0; j < 8; j++)
			w8[j] = pat[(i + j) % 8u];
		{
			uint32_t h = 0;

			for (j = 0; j < 8; j++)
				h = h * KGENOME_MUTATION_BASE + w8[j];
			rot[i] = kgenome_mutation_mix(h);
		}
	}
	for (i = 0; i < R; i++) {
		for (j = 0; j < 32; j++)
			pool[(size_t)i * 32u + j] = j < 8u ? rot[j] : (uint32_t)rn(&s);
		mb[i].first_hash = i * 32u; mb[i].n_hash = 32; mb[i].scan_mask = 1u; mb[i].norm = 0; mb[i].side = 0;
		mb[i].reserved[0] = mb[i].reserved[1] = 0;
		wb[i].first = i * 32u; wb[i].n = 32; wb[i].side = 0; wb[i].tag = 0;
	}
	set = kof_mutation_build(mb, R, pool, R * 32u);
	CK(set && kof_mutation_ctx_init(&kc, set));
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	CK(kgenome_fnprint_wdb_build(&d, wb, R, pool, (uint64_t)R * 32u, &o) && kgenome_fnprint_wctx_init(&c, &d, NULL));
	kof_mutation_begin(&kc);
	t0 = now();
	kof_mutation_unit(&kc, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_USER, obj, (uint64_t)REP * 8u);
	t1 = now();
	kgenome_fnprint_wctx_begin(&c);
	ext.off = 0; ext.len = (uint64_t)REP * 8u;
	memset(&rq, 0, sizeof rq);
	rq.p = obj; rq.n = (uint64_t)REP * 8u; rq.ext = &ext; rq.n_ext = 1; rq.c = &c; rq.stat = &st;
	t2 = now();
	kgenome_fnprint_wpass(&rq);
	t3 = now();
	CK(kof_mutation_matched(&kc, 0) == kgenome_fnprint_wctx_count(&c, 0) && kgenome_fnprint_wctx_count(&c, 0) == 8u);
	CK(kof_mutation_matched(&kc, R - 1u) == 8u);
	printf("SCALE\tHOTRUN R=%d windows=%d\tmatcher_ms=%.2f\tstream_ms=%.3f\n", R, REP * 8, (t1 - t0) * 1e3, (t3 - t2) * 1e3);
	/* the index walks a value's block list once per object: 8 values x 5000 blocks, however often the
	 * object repeats them - a count of visits, not a time */
	{
		struct kof_mutation_stat ms;

		kof_mutation_stat(&kc, &ms);
		CK(ms.walks == 8u && ms.visits == 8u * R);
		CK(ms.status == 0);
	}
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	kof_mutation_ctx_done(&kc);
	kof_mutation_set_free(set);
	free(mb); free(wb); free(pool); free(obj);
}

int main(int argc, char **argv)
{
	uint32_t scales[8], ns = 0, i;
	double big = 0, base_cur = 0, base_new = 0, c, nw;

	scales[ns++] = 10000u;
	scales[ns++] = 100000u;
	for (i = 1; i < (uint32_t)argc; i++)
		if (!strncmp(argv[i], "--scale=", 8))
			big = strtod(argv[i] + 8, NULL);
	if (big >= 1e6)
		scales[ns++] = (uint32_t)big;
	for (i = 0; i < ns; i++) {
		t_both(scales[i], &c, &nw);
		if (!i) { base_cur = c; base_new = nw; }
		(void)base_cur;
	}
	(void)base_new;
	t_cur_limits();
	t_hot_run();
	printf("fnprint_scale_cur: %s (known-miss %u)\n", fails ? "FAIL" : "ok", km_known());
	return fails != 0 || km_failed();
}
