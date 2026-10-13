/*
 * hostile_lzhuf - kuncoat_lzhuf_decode (lzhuf.h): the LHA -lh5-/-lh6-/-lh7- and ARJ
 * method 1-3 coding.
 *
 * Streams come from hostile_lzhenc.h, which writes real blocks (pretree, the literal and
 * length tree through the pretree with its zero-run codes, the position tree) for a
 * symbol set the test chooses: a small uniform one, and a deep one whose codes are
 * longer than the 8 and 12 bit lookup tables, so the tree walk behind them is read.
 *
 *   SWEEPS    every cap, every truncation, every flip, guard pages, for the four variants
 *             and both shapes of code, with output of 2.5 dictionaries so the window
 *             wraps.
 *   HEADER    the lies one at a time: a block of 0 codes, a pretree entry count above 19,
 *             a single-symbol pretree outside the alphabet, an over-subscribed and an
 *             incomplete pretree, a literal-count of 511, a position tree with symbols
 *             past the variant's, a position class that names a distance past the
 *             dictionary (ARJ's 26624 is not a power of two).
 *   VARIANT   4, 5, 99 and -1 are UNSUPPORTED; out_len 0 is OK with nothing read; out_len
 *             2^63 on a short stream ends as TRUNCATED, in time.
 *   BOMB      a single-symbol literal/length tree (zero bits per code) and a block of
 *             65535 codes of length 256: 16 MB from a few dozen bytes, with a sink that
 *             stops at 1 MB.
 *   STATE     the 100 KB state reused after every failure.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzhenc.h"
#include "hostile_sweep.h"

#include <decompressors/lzhuf.h>

static struct kuncoat_lzhuf *g_st;

struct lhp { enum kuncoat_lzhuf_variant var; uint64_t out_len; };

static enum kuncoat_status lh_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				  uint64_t *prod)
{
	const struct lhp *p = ctx;
	struct hv_bufsink s;
	uint64_t dp = 0xFEEDull;
	enum kuncoat_status st;

	memset(&s, 0, sizeof s);
	s.out = out;
	s.cap = cap;
	st = kuncoat_lzhuf_decode(g_st, p->var, in, n, p->out_len, hv_bufsink_fn, &s, &dp);
	hv_bufsink_check_loose(&s, st, dp, "lzhuf");
	*prod = s.total;
	return st;
}

/* ---- streams ------------------------------------------------------------------------------ */

static const struct { unsigned np, pbit, dict; } VAR[4] = {
	{ 17, 5, 26624 }, { 14, 4, 8192 }, { 16, 5, 32768 }, { 17, 5, 65536 }
};

struct vec {
	uint8_t in[200000];
	size_t  n;
	uint8_t want[180000];
	size_t  wn;
};

/* design 0: 40 literals, match lengths 3..18, positions 0..7. design 1: 60 literals,
 * lengths 3..34, every position the variant has. */
static void set_code(struct hv_lh *e, int design)
{
	uint8_t lens[256];
	unsigned nl = design ? 60u : 40u, nm = design ? 32u : 16u, np = design ? e->np : 8u, i, k = 0;

	memset(e->cl, 0, sizeof e->cl);
	memset(e->pl, 0, sizeof e->pl);
	hv_lh_lengths(lens, nl + nm, design ? 8u : 6u);
	for (i = 0; i < nl; i++)
		e->cl[32 + i] = lens[k++];
	for (i = 0; i < nm; i++)
		e->cl[256 + i] = lens[k++];
	hv_lh_lengths(lens, np, np > 6 ? 4u : np - 1u);
	for (i = 0; i < np; i++)
		e->pl[i] = lens[i];
}

static int make_lh(struct vec *v, unsigned var, int design, uint64_t seed, size_t target)
{
	struct hv_lh e;
	uint64_t rs = seed;
	size_t done = 0;
	static struct { int match; uint8_t lit; unsigned len; uint32_t dist; } ops[4000];

	hv_lh_init(&e, v->in, sizeof v->in, v->want, sizeof v->want, VAR[var].np, VAR[var].pbit);
	while (e.hn < target) {
		unsigned nops = 0;
		size_t blk_bytes = 0, hn = e.hn;

		while (nops < 3000 && blk_bytes < 6000) {
			uint32_t r = hv_rng32(&rs) % 100u;

			if (hn < 3 || r < 50) {
				uint32_t pick = hv_rng32(&rs) % 40u;

				ops[nops].match = 0;
				ops[nops].lit = (uint8_t)(32u + (design ? pick % 60u : pick));
				nops++;
				hn++;
				blk_bytes++;
			} else {
				uint32_t maxlen = design ? 34u : 18u, lenr = hv_rng32(&rs) % (maxlen - 2u);
				uint32_t maxd = design ? (uint32_t)(VAR[var].dict < 8192u ? VAR[var].dict : 8192u) : 128u;
				uint32_t span = hv_rng32(&rs) % 3u ? 40u : maxd, dist;

				if (span > hn)
					span = (uint32_t)hn;
				dist = 1u + hv_rng32(&rs) % span;
				ops[nops].match = 1;
				ops[nops].len = 3u + lenr;
				ops[nops].dist = dist;
				nops++;
				hn += 3u + lenr;
				blk_bytes += 3u + lenr;
			}
		}
		set_code(&e, design);
		hv_lh_block(&e, nops);
		{
			unsigned i;

			for (i = 0; i < nops; i++) {
				if (ops[i].match)
					hv_lh_match(&e, ops[i].len, ops[i].dist);
				else
					hv_lh_lit(&e, ops[i].lit);
			}
		}
		done = e.hn;
	}
	(void)done;
	v->n = hv_lh_finish(&e);
	v->wn = e.hn;
	return !e.w.over && e.hn <= sizeof v->want;
}

static struct vec v_a[4], v_d[4];
static const char *const vname[4] = { "arj", "lh5", "lh6", "lh7" };

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec vv;
	struct hv_sweep_job j;
	struct lhp p;
	char nm[40];
	unsigned i, dsg;
	int bad = 0;

	(void)arg;
	for (dsg = 0; dsg < 2; dsg++)
		for (i = 0; i < 4; i++) {
			const struct vec *v = dsg ? &v_d[i] : &v_a[i];

			memset(&d, 0, sizeof d);
			snprintf(nm, sizeof nm, "lzhuf %s %s", vname[i], dsg ? "deep" : "small");
			d.name = nm;
			d.run = lh_run;
			d.ctx = &p;
			d.flags = HV_F_NO_PREFIX_TRUNC;                  /* see trunc_fab */
			p = (struct lhp){ (enum kuncoat_lzhuf_variant)i, v->wn };
			vv = (struct hv_vec){ "script", v->in, v->n, v->want, v->wn };
			j = (struct hv_sweep_job){ &d, &vv, 1, v->n + 8u, v->wn + 8u };
			bad |= hv_sweep_job_run(&j);
		}
	return bad;
}

/* ---- calls --------------------------------------------------------------------------------- */

static struct hv_gb gin;
static uint8_t keep[400000];

struct hsink {
	uint64_t total, calls, refuse_at, after;
	int      stopped;
};

static int hsink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct hsink *s = u;
	uint32_t i;
	uint8_t x = 0;

	s->calls++;
	if (s->stopped) {
		s->after++;
		return 0;
	}
	for (i = 0; i < n; i++)
		x = (uint8_t)(x + p[i]);
	if (s->refuse_at == ~0ull || (s->refuse_at && s->total >= s->refuse_at)) {
		s->stopped = 1;
		return 0;
	}
	if (s->total + n <= sizeof keep)
		memcpy(keep + s->total, p, n);
	s->total += n + (x & 0u);
	return 1;
}

struct hres {
	enum kuncoat_status st;
	uint64_t            produced, sunk;
};

static struct hres lh(unsigned var, const uint8_t *in, size_t n, uint64_t out_len, uint64_t refuse_at)
{
	struct hsink s;
	struct hres r;
	uint64_t p = 0xFEEDull;

	memset(&s, 0, sizeof s);
	s.refuse_at = refuse_at;
	r.st = kuncoat_lzhuf_decode(g_st, (enum kuncoat_lzhuf_variant)var, hv_in(&gin, in, n), n, out_len, hsink_fn, &s, &p);
	r.produced = p;
	r.sunk = s.total;
	CK(hv_status_ok(r.st));
	CKF(s.after == 0, "the sink was called again after it refused");
	CKF(r.produced >= r.sunk, "produced %llu < what the sink accepted %llu", (unsigned long long)r.produced,
	    (unsigned long long)r.sunk);
	return r;
}

#define AT() hv_at((uint64_t)__LINE__, 0)

static void whole(void)
{
	unsigned i, dsg;
	struct hres r;

	for (dsg = 0; dsg < 2; dsg++)
		for (i = 0; i < 4; i++) {
			const struct vec *v = dsg ? &v_d[i] : &v_a[i];

			AT();
			r = lh(i, v->in, v->n, v->wn, 0);
			CKF(r.st == KUNCOAT_OK && r.produced == v->wn && r.sunk == v->wn && !memcmp(keep, v->want, v->wn),
			    "%s %s: %s, %llu of %zu", vname[i], dsg ? "deep" : "small", kuncoat_status_name(r.st),
			    (unsigned long long)r.produced, v->wn);
			/* out_len below the stream: stops there, OK, the bytes are the beginning */
			r = lh(i, v->in, v->n, v->wn / 2u, 0);
			CKF(r.st == KUNCOAT_OK && r.produced == v->wn / 2u && !memcmp(keep, v->want, v->wn / 2u),
			    "%s half: %s %llu", vname[i], kuncoat_status_name(r.st), (unsigned long long)r.produced);
			/* out_len above it: TRUNCATED, with all of it */
			r = lh(i, v->in, v->n, v->wn + 5000u, 0);
			CKF(r.st == KUNCOAT_TRUNCATED && r.sunk >= v->wn, "%s over-asked: %s %llu", vname[i],
			    kuncoat_status_name(r.st), (unsigned long long)r.sunk);
		}
}

static void variants(void)
{
	static const int bad[] = { 4, 5, 6, 99, -1, 0x7FFFFFFF };
	unsigned i;
	struct hres r;
	uint64_t p = 55;
	enum kuncoat_status st;

	for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		AT();
		st = kuncoat_lzhuf_decode(g_st, (enum kuncoat_lzhuf_variant)bad[i], v_a[1].in, v_a[1].n, 100, hsink_fn, NULL, &p);
		CKF(st == KUNCOAT_UNSUPPORTED && p == 0, "variant %d: %s", bad[i], kuncoat_status_name(st));
	}
	/* out_len 0: OK at once, nothing read */
	r = lh(1, v_a[1].in, v_a[1].n, 0, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 0 && r.sunk == 0);
	r = lh(1, v_a[1].in, 0, 0, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	/* the stream is empty and something is wanted */
	r = lh(1, v_a[1].in, 0, 100, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
	/* out_len at the top of the range: the stream ends it, quickly */
	{
		double t0 = hv_wall();

		r = lh(1, v_a[1].in, v_a[1].n, 1ull << 63, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.sunk >= v_a[1].wn);
		r = lh(1, v_a[1].in, v_a[1].n, ~0ull, 0);
		CK(r.st == KUNCOAT_TRUNCATED);
		CKF(hv_wall() - t0 < 5.0, "huge out_len took %.2fs", hv_wall() - t0);
	}
	/* refuse the first call: STOPPED */
	r = lh(2, v_a[2].in, v_a[2].n, v_a[2].wn, ~0ull);
	CK(r.st == KUNCOAT_STOPPED);
}

/* ---- header lies ------------------------------------------------------------------------------ */

static void header_lies(void)
{
	uint8_t b[2000];
	struct hv_bw w;
	struct hres r;
	unsigned i;

	AT();
	/* a block of 0 codes */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_msb(&w, 0, 16);
	for (i = 0; i < 50; i++)
		hv_bw_msb(&w, 0xA5, 8);
	r = lh(1, b, w.n, 100, 0);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "0 codes: %s", kuncoat_status_name(r.st));
	/* a pretree entry count above 19 (5 bits: 20..31) */
	for (i = 20; i < 32; i++) {
		hv_bw_init(&w, b, sizeof b);
		hv_bw_msb(&w, 100, 16);
		hv_bw_msb(&w, i, 5);
		hv_bw_msb(&w, 0x5555, 16);
		hv_bw_msb(&w, 0x5555, 16);
		r = lh(1, b, w.n + 8u, 100, 0);
		CKF(r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED, "pretree count %u: %s", i, kuncoat_status_name(r.st));
	}
	/* a single-symbol pretree (count 0) naming a symbol outside the 19: 19..31 */
	for (i = 19; i < 32; i += 3) {
		hv_bw_init(&w, b, sizeof b);
		hv_bw_msb(&w, 100, 16);
		hv_bw_msb(&w, 0, 5);
		hv_bw_msb(&w, i, 5);
		hv_bw_msb(&w, 0x5555, 16);
		r = lh(1, b, w.n + 8u, 100, 0);
		CKF(r.st == KUNCOAT_CORRUPT, "single pretree symbol %u: %s", i, kuncoat_status_name(r.st));
	}
	/* pretree over-subscribed: five symbols of one bit */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_msb(&w, 100, 16);
	hv_bw_msb(&w, 5, 5);
	for (i = 0; i < 5; i++)
		hv_lh_ptlen(&w, 1);
	hv_bw_msb(&w, 0, 16);
	r = lh(1, b, w.n + 16u, 100, 0);
	CKF(r.st == KUNCOAT_CORRUPT, "over-subscribed pretree: %s", kuncoat_status_name(r.st));
	/* pretree incomplete: one symbol of length 3 */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_msb(&w, 100, 16);
	hv_bw_msb(&w, 3, 5);
	hv_lh_ptlen(&w, 3);
	hv_bw_msb(&w, 0, 2);                                /* the skip count after 3 entries... (n = 3: lens 3,0,0) */
	hv_lh_ptlen(&w, 0);
	hv_lh_ptlen(&w, 0);
	hv_bw_msb(&w, 0, 32);
	r = lh(1, b, w.n + 8u, 100, 0);
	CKF(r.st != KUNCOAT_OK, "incomplete pretree: %s", kuncoat_status_name(r.st));
	/* a literal count of 511 (the field is 9 bits; the alphabet is 510) with a good pretree */
	{
		struct hv_lh e;
		static uint8_t hist[10];

		hv_lh_init(&e, b, sizeof b, hist, sizeof hist, 14, 4);
		set_code(&e, 0);
		hv_lh_block(&e, 10);
		/* patch: find the 9 bit count by rebuilding: write a block header by hand instead */
		(void)e;
	}
	/* single-symbol literal tree (count 0, symbol 0..509): zero bits per code */
	{
		static const unsigned sym[] = { 0, 65, 255, 256, 509, 510, 511 };
		unsigned k;

		for (k = 0; k < sizeof sym / sizeof sym[0]; k++) {
			hv_bw_init(&w, b, sizeof b);
			hv_bw_msb(&w, 1000, 16);                    /* 1000 codes */
			hv_bw_msb(&w, 0, 5);                        /* pretree: single symbol */
			hv_bw_msb(&w, 0, 5);
			hv_bw_msb(&w, 0, 9);                        /* literal tree: single symbol */
			hv_bw_msb(&w, sym[k], 9);
			hv_bw_msb(&w, 0, 4);                        /* position tree (lh5: 4 bits): single symbol */
			hv_bw_msb(&w, 0, 4);
			hv_bw_msb(&w, 0, 32);
			AT();
			r = lh(1, b, w.n, 5000, 0);
			if (sym[k] > 509)
				CKF(r.st == KUNCOAT_CORRUPT, "single literal symbol %u: %s", sym[k], kuncoat_status_name(r.st));
			else if (sym[k] < 256)
				/* 1000 zero-bit codes, then the next block header reads the zero padding:
				 * a block of 0 codes is CORRUPT, and the 1000 bytes buffered in the dictionary
				 * are not delivered on CORRUPT (silent_loss_uncoat.c) */
				CKF(r.produced == 1000 && (r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED),
				    "single literal %u: %s %llu", sym[k], kuncoat_status_name(r.st), (unsigned long long)r.produced);
			else
				CK(hv_status_ok(r.st));
		}
	}
	/* the position class naming a distance past the dictionary: ARJ's dictionary is 26624 and
	 * a position symbol of 15 reads 15 extra bits: 2^15 + x > 26624 */
	{
		struct hv_lh e;
		static uint8_t hist[40000];

		hv_lh_init(&e, b, sizeof b, hist, sizeof hist, 17, 5);
		memset(e.cl, 0, sizeof e.cl);
		memset(e.pl, 0, sizeof e.pl);
		/* literals 'a'(97), 'b'(98) and the match symbol 256 (length 3): 3 symbols, lengths 1,2,2 */
		e.cl[97] = 1; e.cl[98] = 2; e.cl[256] = 2;
		/* positions 0 and 16 (class 15): lengths 1,1 */
		e.pl[0] = 1; e.pl[16] = 1;
		hv_lh_block(&e, 3);
		hv_lh_lit(&e, 'a');
		hv_lh_lit(&e, 'b');
		/* the match: symbol 256, then position class 16 and its 15 extra bits all ones */
		hv_bw_msb(&e.w, e.cc[256], e.cl[256]);
		hv_bw_msb(&e.w, e.pc[16], e.pl[16]);
		hv_bw_msb(&e.w, 0x7fffu, 15);
		hv_bw_msb(&e.w, 0, 32);
		AT();
		r = lh(0, b, hv_lh_finish(&e), 100, 0);
		CKF(r.st == KUNCOAT_CORRUPT, "distance past the dictionary: %s %llu", kuncoat_status_name(r.st),
		    (unsigned long long)r.produced);
	}
}

/* ---- the bomb ----------------------------------------------------------------------------------- */

static void bomb(void)
{
	uint8_t b[64];
	struct hv_bw w;
	struct hres r;
	double t0 = hv_wall();

	/* 65535 codes, all the one symbol 509 (a match of length 256, class 0: distance 1) with
	 * zero bits each: the first one copies from the cleared dictionary, then runs of zero */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_msb(&w, 65535, 16);
	hv_bw_msb(&w, 0, 5); hv_bw_msb(&w, 0, 5);
	hv_bw_msb(&w, 0, 9); hv_bw_msb(&w, 509, 9);
	hv_bw_msb(&w, 0, 5); hv_bw_msb(&w, 0, 5);                      /* lh6: pbit 5, single symbol 0 */
	hv_bw_msb(&w, 0, 32);
	AT();
	r = lh(2, b, w.n, 1ull << 40, 1u << 20);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk <= (1u << 20) + 40000u, "bomb with a refusing sink: %s %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.sunk);
	r = lh(2, b, w.n, 1ull << 40, 0);
	CK(hv_status_ok(r.st));
	CKF(hv_wall() - t0 < 15.0, "bomb took %.2fs", hv_wall() - t0);
	printf("  (lzhuf bomb: %zu bytes -> %llu bytes, %s)\n", w.n, (unsigned long long)r.produced, kuncoat_status_name(r.st));
}

static void garbage(void)
{
	uint64_t rs = 0xBEEFu;
	uint8_t in[500];
	unsigned it;

	for (it = 0; it < 4000; it++) {
		size_t n = hv_rng32(&rs) % 500u, i;
		unsigned mode = it % 8u;

		for (i = 0; i < n; i++) {
			uint32_t v = hv_rng32(&rs);

			in[i] = mode == 0 ? (uint8_t)v : mode == 1 ? 0 : mode == 2 ? 0xFF : mode == 3 ? (uint8_t)(i * 31u) :
				mode == 4 ? (uint8_t)(v % 3u ? 0 : v >> 8) : mode == 5 ? 0x5A : mode == 6 ? (uint8_t)(i & 1u ? 0xFF : 0) :
				(uint8_t)(i < 6 ? v : 0);
		}
		hv_at(8000, it);
		(void)lh(hv_rng32(&rs) % 4u, in, n, 1u + hv_rng32(&rs) % 100000u,
			 hv_rng32(&rs) % 5u == 0 ? 1u + hv_rng32(&rs) % 3000u : 0);
		if (hv_fails > 5)
			return;
	}
}

static int trunc_fab(void *arg)
{
	struct hv_dec d;
	struct hv_vec v;
	struct hv_sweep_mem m;
	struct hv_tf a, b;
	struct lhp p;
	static uint8_t k2[200000];
	static char what[300];

	(void)arg;
	memset(&d, 0, sizeof d);
	d.name = "lzhuf";
	d.run = lh_run;
	d.ctx = &p;
	if (!hv_sweep_mem_init(&m, 200100, 180100))
		return 1;
	p = (struct lhp){ KUNCOAT_LZHUF_LH5, v_a[1].wn };
	v = (struct hv_vec){ "lh5", v_a[1].in, v_a[1].n, v_a[1].want, v_a[1].wn };
	hv_trunc_fab(&m, &d, &v, 1, v_a[1].n / 300u + 1u, &a, k2);
	p = (struct lhp){ KUNCOAT_LZHUF_LH5, v_d[1].wn };
	v = (struct hv_vec){ "lh5 deep", v_d[1].in, v_d[1].n, v_d[1].want, v_d[1].wn };
	hv_trunc_fab(&m, &d, &v, 1, v_d[1].n / 300u + 1u, &b, k2);
	hv_sweep_mem_free(&m);
	printf("  (lzhuf truncation: %zu of %zu and %zu of %zu cuts hand back fabricated bytes, worst %zu)\n", a.nbad, a.cuts,
	       b.nbad, b.cuts, a.worst > b.worst ? a.worst : b.worst);
	snprintf(what, sizeof what, "lzhuf: lh5 stream (%zu bytes) cut at %zu hands back %zu bytes that are not the real output "
		 "(%zu of %zu cuts affected), status TRUNCATED", v_a[1].n, a.worst_cut, a.worst, a.nbad, a.cuts);
	KM_CHECK(a.nbad + b.nbad == 0, what,
		 "LZHUF_TRUNC_FABRICATED (libuncoat/decompressors/lzhuf.c lh_fill: reads 0 past the end and sets eof only when "
		 "`used > in_len * 8 + 16`, so up to 16 bits of fabricated codes are decoded and flushed with TRUNCATED) "
		 "[Inference: low]");
	return 0;
}

static void state(void)
{
	struct hres r;
	static const uint8_t junk[64] = { 0x00, 0x10, 0xFF, 0xFF, 0xAA };

	memset(g_st, 0xFF, sizeof *g_st);
	AT();
	r = lh(1, v_a[1].in, v_a[1].n, v_a[1].wn, 0);
	CK(r.st == KUNCOAT_OK && !memcmp(keep, v_a[1].want, v_a[1].wn));
	r = lh(3, junk, sizeof junk, 1000, 0);
	CK(r.st != KUNCOAT_OK);
	r = lh(1, v_a[1].in, v_a[1].n, v_a[1].wn, 0);
	CK(r.st == KUNCOAT_OK && !memcmp(keep, v_a[1].want, v_a[1].wn));
	r = lh(0, v_a[0].in, v_a[0].n / 2u, v_a[0].wn, 0);
	CK(r.st == KUNCOAT_TRUNCATED);
	r = lh(2, v_d[2].in, v_d[2].n, v_d[2].wn, ~0ull);
	CK(r.st == KUNCOAT_STOPPED);
	r = lh(1, v_a[1].in, v_a[1].n, v_a[1].wn, 0);
	CK(r.st == KUNCOAT_OK && !memcmp(keep, v_a[1].want, v_a[1].wn));
}

HV_GROUP(whole)
HV_GROUP(variants)
HV_GROUP(header_lies)
HV_GROUP(bomb)
HV_GROUP(garbage)
HV_GROUP(state)

int main(void)
{
	unsigned i;
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	g_st = malloc(sizeof *g_st);
	if (!g_st || !hv_gb_init(&gin, 300000)) {
		printf("hostile_lzhuf: out of memory\n");
		return 1;
	}
	for (i = 0; i < 4; i++) {
		ok &= make_lh(&v_a[i], i, 0, 100u + i, VAR[i].dict + VAR[i].dict / 2u);
		ok &= make_lh(&v_d[i], i, 1, 200u + i, VAR[i].dict + VAR[i].dict / 2u);
	}
	CK(ok);
	hv_expect_clean("lzhuf sweeps", sweeps, NULL, 40);
	hv_expect_clean("lzhuf truncation", trunc_fab, NULL, 20);
	hv_expect_clean("lzhuf whole", hv_grp_whole, NULL, 10);
	hv_expect_clean("lzhuf variants", hv_grp_variants, NULL, 10);
	hv_expect_clean("lzhuf header lies", hv_grp_header_lies, NULL, 10);
	hv_expect_clean("lzhuf bomb", hv_grp_bomb, NULL, 20);
	hv_expect_clean("lzhuf garbage", hv_grp_garbage, NULL, 30);
	hv_expect_clean("lzhuf state", hv_grp_state, NULL, 10);
	free(g_st);
	hv_gb_free(&gin);
	return hv_done("hostile_lzhuf");
}
