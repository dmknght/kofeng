/*
 * hostile_lzma - kuncoat_lzma_decode and kuncoat_lzma2_decode (lzma.h).
 *
 * Streams come from the encoder in hostile_lzenc.h, which writes exactly the
 * operations it is told (literal, match, rep match 0..3, short rep, end marker), so
 * a test states the bytes the decoder must produce AND can state sequences no real
 * encoder writes. When the xz tool is installed its raw LZMA1 and LZMA2 output is
 * swept too (a real encoder is the oracle for the model, mine for the lies); without
 * it those vectors are skipped and said so.
 *
 *   SWEEPS      hostile_sweep.h on a mixed stream in several (lc, lp, pb), an LZMA2 stream
 *               of five chunks (LZMA, raw, continued LZMA, state reset, new properties),
 *               and xz's own output: every cap, every truncation, every bit flip.
 *   DISTANCES   a distance one past what was produced, at 2^31, 2^32-1; a match as the
 *               first operation; a short rep before anything exists; every one CORRUPT
 *               with the real prefix kept.
 *   LENGTHS     a 273 byte match with room for 10: STOPPED and the ten bytes are right.
 *   MARKER      the end marker in the middle: OK, everything after it is not read.
 *   PROPERTIES  lc 9, lp 5, pb 5, UINT_MAX: refused before the model is allocated;
 *               the largest legal model (lc 8, lp 4: 6 MB) works and is quick.
 *   BOMB        a stream of a few KB that expands to 68 MB: cap 1 MB gives STOPPED in
 *               well under a second; cap 70 MB gives the whole run.
 *   LZMA2       control bytes 3..0x7F, a first chunk with no properties, an invalid
 *               properties byte, a raw chunk longer than the input, chunk lengths at
 *               2^21, a chunk that decodes nothing (no infinite loop), and a storm of
 *               one-byte chunks that each reset a large model (time).
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_sweep.h"
#include "hostile_lzenc.h"

/* ---- adapters ---------------------------------------------------------------------- */

struct lzp { unsigned lc, lp, pb; };

static enum kuncoat_status lz1_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	const struct lzp *p = ctx;

	return kuncoat_lzma_decode(p->lc, p->lp, p->pb, in, n, out, cap, prod);
}

static enum kuncoat_status lz2_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	(void)ctx;
	return kuncoat_lzma2_decode(in, n, out, cap, prod);
}

/* ---- the vectors ----------------------------------------------------------------------- */

#define NOPS 700

/* A random but valid script of operations, ending when the history reaches `target`. */
static void script(struct hv_lz *e, uint64_t *rs, size_t target)
{
	static const char *const words[] = { "kernel", "socket", "payload", "stage", "/bin/sh", "VirtualAlloc" };

	while (e->hn < target) {
		uint32_t r = hv_rng32(rs) % 100u;
		unsigned len;
		uint32_t dist;

		if (e->hn < 4 || r < 55) {
			const char *w = words[hv_rng32(rs) % 6u];

			uint32_t pick = hv_rng32(rs) % 4u, pos = hv_rng32(rs) % (uint32_t)strlen(w), rnd = hv_rng32(rs);

			hv_lz_lit(e, (uint8_t)(pick ? (uint32_t)w[pos] : rnd));
		} else if (r < 80) {
			uint32_t k = hv_rng32(rs) % 4u;

			len = 2u + hv_rng32(rs) % (k == 0 ? 272u : k == 1 ? 16u : 8u);
			dist = k == 0 ? 1u + hv_rng32(rs) % (uint32_t)e->hn :
			       k == 1 ? 1u + hv_rng32(rs) % (e->hn < 300 ? (uint32_t)e->hn : 300u) :
			       1u + hv_rng32(rs) % (e->hn < 16 ? (uint32_t)e->hn : 16u);
			hv_lz_match(e, len, dist);
		} else if (r < 95) {
			uint32_t wide = hv_rng32(rs) % 3u, which = hv_rng32(rs) % 4u;

			len = 2u + hv_rng32(rs) % (wide ? 10u : 270u);
			hv_lz_rep(e, which, len);
		} else {
			hv_lz_short(e);
		}
	}
}

struct lzvec {
	uint8_t in[20000];
	size_t  n;
	uint8_t want[20000];
	size_t  wn;
};

/* One whole LZMA1 stream; end marker optional. */
static int make_lz1(struct lzvec *v, unsigned lc, unsigned lp, unsigned pb, uint64_t seed, size_t target,
		    int marker)
{
	struct hv_lz e;
	uint64_t rs = seed;

	if (!hv_lz_init(&e, v->in, sizeof v->in, lc, lp, pb, 30000))
		return 0;
	script(&e, &rs, target);
	if (marker)
		hv_lz_end_marker(&e);
	v->n = hv_lz_rc_finish(&e);
	v->wn = e.hn;
	memcpy(v->want, e.hist, e.hn);
	hv_lz_free(&e);
	return !e.over;
}

static struct lzvec v_a, v_b, v_c, v_d, v_m, v2;
static uint8_t *xz1_in, *xz2_in;
static size_t xz1_n, xz2_n;
static uint8_t xz_plain[30000];

/* The LZMA2 stream: five chunks and the end byte. */
static int make_lz2(struct lzvec *v)
{
	struct hv_lz e;
	uint64_t rs = 4242;
	uint8_t tmp[20000], *o = v->in;
	size_t n = 0, start, cl, i;
	uint8_t raw[300];

	if (!hv_lz_init(&e, tmp, sizeof tmp, 3, 0, 2, 30000))
		return 0;
	/* 1: LZMA, dictionary and state reset, props lc3 lp0 pb2 = 0x5D */
	start = 0;
	script(&e, &rs, 1500);
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(o + n, e.hn - start, cl, 3, 0x5D);
	memcpy(o + n, tmp, cl);
	n += cl;
	/* 2: raw, no dictionary reset */
	for (i = 0; i < sizeof raw; i++) {
		raw[i] = (uint8_t)(i * 5u + 1u);
		hv_lz_hist(&e, raw[i]);
	}
	n += hv_lz2_raw(o + n, raw, sizeof raw, 0);
	/* 3: LZMA continuing everything (reset 0) */
	hv_lz_rc_start(&e, tmp, sizeof tmp);
	start = e.hn;
	script(&e, &rs, e.hn + 900);
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(o + n, e.hn - start, cl, 0, 0);
	memcpy(o + n, tmp, cl);
	n += cl;
	/* 4: state reset only (reset 1): model back to even odds, reps back to 1 */
	hv_lz_reset(&e, 3, 0, 2);
	hv_lz_rc_start(&e, tmp, sizeof tmp);
	start = e.hn;
	script(&e, &rs, e.hn + 700);
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(o + n, e.hn - start, cl, 1, 0);
	memcpy(o + n, tmp, cl);
	n += cl;
	/* 5: new properties lc0 lp2 pb1 = 0x5D? props byte = (pb*5+lp)*9+lc = (5+2)*9+0 = 63 */
	hv_lz_reset(&e, 0, 2, 1);
	hv_lz_rc_start(&e, tmp, sizeof tmp);
	start = e.hn;
	script(&e, &rs, e.hn + 800);
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(o + n, e.hn - start, cl, 2, 63);
	memcpy(o + n, tmp, cl);
	n += cl;
	o[n++] = 0;
	v->n = n;
	v->wn = e.hn;
	memcpy(v->want, e.hist, e.hn);
	hv_lz_free(&e);
	return 1;
}

static void xz_vectors(void)
{
	static const char *const a1[] = { "xz", "-c", "--format=raw", "--lzma1=preset=6,lc=3,lp=0,pb=2", NULL };
	static const char *const a2[] = { "xz", "-c", "--format=raw", "--lzma2=preset=6", NULL };
	size_t i;
	uint64_t rs = 9;

	hv_body(xz_plain, 20000, 3);
	for (i = 20000; i < sizeof xz_plain; i++)           /* incompressible tail: raw chunks */
		xz_plain[i] = (uint8_t)hv_rng32(&rs);
	xz1_in = hv_tool(a1, xz_plain, 20000, &xz1_n);
	xz2_in = hv_tool(a2, xz_plain, sizeof xz_plain, &xz2_n);
}

static int sweeps(void *arg)
{
	static struct lzp p3 = { 3, 0, 2 }, p0 = { 0, 0, 0 }, p4 = { 4, 0, 0 }, p04 = { 0, 4, 4 };
	struct hv_dec d1, d0, d4, d04, d2, dx, dx2;
	struct hv_vec v[2];
	struct hv_sweep_job j;
	int bad = 0;

	(void)arg;
	memset(&d1, 0, sizeof d1);
	d1.name = "lzma lc3 lp0 pb2"; d1.run = lz1_run; d1.ctx = &p3;
	d1.flags = HV_F_TRUNC_OK_ALLOWED | HV_F_EXACT_MAY_STOP | HV_F_NO_PREFIX_TRUNC;
	d0 = d1; d0.name = "lzma lc0 lp0 pb0"; d0.ctx = &p0;
	d4 = d1; d4.name = "lzma lc4 lp0 pb0"; d4.ctx = &p4;
	d04 = d1; d04.name = "lzma lc0 lp4 pb4"; d04.ctx = &p04;
	d2 = d1; d2.name = "lzma2 five chunks"; d2.run = lz2_run; d2.ctx = NULL;
	d2.flags |= HV_F_CAP_OK_ALLOWED;       /* LZMA2_CAP_LAST_CHUNK, below */
	dx = d1; dx.name = "lzma xz raw";
	dx2 = d2; dx2.name = "lzma2 xz raw";

	v[0] = (struct hv_vec){ "a", v_a.in, v_a.n, v_a.want, v_a.wn };
	j = (struct hv_sweep_job){ &d1, v, 1, 21000, 21000 };
	bad |= hv_sweep_job_run(&j);
	v[0] = (struct hv_vec){ "b", v_b.in, v_b.n, v_b.want, v_b.wn };
	j.dec = &d0;
	bad |= hv_sweep_job_run(&j);
	v[0] = (struct hv_vec){ "c", v_c.in, v_c.n, v_c.want, v_c.wn };
	j.dec = &d4;
	bad |= hv_sweep_job_run(&j);
	v[0] = (struct hv_vec){ "d", v_d.in, v_d.n, v_d.want, v_d.wn };
	j.dec = &d04;
	bad |= hv_sweep_job_run(&j);
	v[0] = (struct hv_vec){ "marker", v_m.in, v_m.n, v_m.want, v_m.wn };
	j.dec = &d1;
	bad |= hv_sweep_job_run(&j);
	v[0] = (struct hv_vec){ "chunks", v2.in, v2.n, v2.want, v2.wn };
	j.dec = &d2;
	bad |= hv_sweep_job_run(&j);
	if (xz1_in) {
		v[0] = (struct hv_vec){ "xz1", xz1_in, xz1_n, xz_plain, 20000 };
		j = (struct hv_sweep_job){ &dx, v, 1, xz1_n + 8u, 20100 };
		bad |= hv_sweep_job_run(&j);
	}
	if (xz2_in) {
		v[0] = (struct hv_vec){ "xz2", xz2_in, xz2_n, xz_plain, sizeof xz_plain };
		j = (struct hv_sweep_job){ &dx2, v, 1, xz2_n + 8u, sizeof xz_plain + 100u };
		bad |= hv_sweep_job_run(&j);
	}
	return bad;
}

/* ---- crafted streams ---------------------------------------------------------------------- */

static struct hv_gb gin, gout;

static enum kuncoat_status lz1(unsigned lc, unsigned lp, unsigned pb, const uint8_t *in, size_t n,
			       size_t cap, uint64_t *p, uint8_t *copy)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	enum kuncoat_status st;

	*p = 0xABABull;
	st = kuncoat_lzma_decode(lc, lp, pb, ip, n, op, cap, p);
	CK(hv_status_ok(st));
	CKF(*p <= cap, "produced %llu > cap %zu", (unsigned long long)*p, cap);
	CK(hv_out_canary_ok(op));
	if (copy && *p <= cap)
		memcpy(copy, op, (size_t)*p);
	return st;
}

#define OPS_BEGIN(e, buf) \
	struct hv_lz e; \
	uint8_t buf[4000]; \
	if (!hv_lz_init(&e, buf, sizeof buf, 3, 0, 2, 100000)) { CK(0); return; }

static void crafted(void)
{
	uint8_t res[4096];
	uint64_t p;
	enum kuncoat_status st;
	size_t n;
	unsigned i;

	/* a distance one past what was produced: CORRUPT, the first byte kept */
	{
		OPS_BEGIN(e, b)
		hv_lz_lit(&e, 'a');
		hv_lz_match_raw(&e, 4, 5 - 1);               /* distance 5 with one byte written */
		n = hv_lz_rc_finish(&e);
		hv_at(1, 0);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CKF(st == KUNCOAT_CORRUPT && p == 1 && res[0] == 'a', "distance past produced: %s, %llu",
		    kuncoat_status_name(st), (unsigned long long)p);
		hv_lz_free(&e);
	}
	/* distance exactly what was produced: fine */
	{
		OPS_BEGIN(e, b)
		hv_lz_lit(&e, 'a'); hv_lz_lit(&e, 'b');
		hv_lz_match(&e, 4, 2);
		hv_lz_end_marker(&e);
		n = hv_lz_rc_finish(&e);
		hv_at(2, 0);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CK(p == 6 && !memcmp(res, "ababab", 6));
		CK(st == KUNCOAT_OK || st == KUNCOAT_TRUNCATED);
		hv_lz_free(&e);
	}
	/* distances at the limits of what the format can write: all CORRUPT, none an overread */
	{
		static const uint32_t d0[] = { 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFEu, 0x100u, 0x10000u, 0x3FFFFFFFu };

		for (i = 0; i < sizeof d0 / sizeof d0[0]; i++) {
			OPS_BEGIN(e, b)
			hv_lz_lit(&e, 'x');
			hv_lz_match_raw(&e, 273, d0[i]);
			n = hv_lz_rc_finish(&e);
			hv_at(3, i);
			st = lz1(3, 0, 2, b, n, 1000, &p, res);
			CKF(st == KUNCOAT_CORRUPT && p == 1 && res[0] == 'x', "dist0 %#x: %s p %llu", d0[i],
			    kuncoat_status_name(st), (unsigned long long)p);
			hv_lz_free(&e);
		}
	}
	/* a match first of all */
	{
		OPS_BEGIN(e, b)
		hv_lz_match_raw(&e, 10, 0);
		n = hv_lz_rc_finish(&e);
		hv_at(4, 0);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CK(st == KUNCOAT_CORRUPT && p == 0);
		hv_lz_free(&e);
	}
	/* a short rep and a rep match before anything exists (rep0 starts at 1, at is 0) */
	{
		OPS_BEGIN(e, b)
		hv_lz_short(&e);
		n = hv_lz_rc_finish(&e);
		hv_at(5, 0);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CK(st == KUNCOAT_CORRUPT && p == 0);
		hv_lz_free(&e);
	}
	{
		OPS_BEGIN(e, b)
		hv_lz_rep(&e, 0, 5);
		n = hv_lz_rc_finish(&e);
		hv_at(6, 0);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CK(st == KUNCOAT_CORRUPT && p == 0);
		hv_lz_free(&e);
	}
	/* rep 1/2/3 naming a distance never set (all are 1) after one literal: legal */
	for (i = 1; i < 4; i++) {
		OPS_BEGIN(e, b)
		hv_lz_lit(&e, 'q');
		hv_lz_rep(&e, i, 6);
		hv_lz_end_marker(&e);
		n = hv_lz_rc_finish(&e);
		hv_at(7, i);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CKF(p == 7 && !memcmp(res, "qqqqqqq", 7), "rep %u: %s p %llu", i, kuncoat_status_name(st),
		    (unsigned long long)p);
		hv_lz_free(&e);
	}
	/* the length past the room: 273 asked, 10 fit: STOPPED, the ten are right */
	{
		OPS_BEGIN(e, b)
		hv_lz_lit(&e, 'z');
		hv_lz_match(&e, 273, 1);
		hv_lz_end_marker(&e);
		n = hv_lz_rc_finish(&e);
		hv_at(8, 0);
		st = lz1(3, 0, 2, b, n, 10, &p, res);
		CKF(st == KUNCOAT_STOPPED && p == 10 && !memcmp(res, "zzzzzzzzzz", 10), "length past room: %s",
		    kuncoat_status_name(st));
		st = lz1(3, 0, 2, b, n, 274, &p, res);
		/* cap == the data: the marker is unread, which the decoder calls STOPPED */
		CK(p == 274 && (st == KUNCOAT_OK || st == KUNCOAT_TRUNCATED || st == KUNCOAT_STOPPED));
		st = lz1(3, 0, 2, b, n, 400, &p, res);
		CK(p == 274 && st == KUNCOAT_OK);
		hv_lz_free(&e);
	}
	/* the end marker in the middle: the rest of the stream is never read */
	{
		OPS_BEGIN(e, b)
		hv_lz_lit(&e, '1'); hv_lz_lit(&e, '2');
		hv_lz_end_marker(&e);
		hv_lz_lit(&e, '3'); hv_lz_lit(&e, '4');
		n = hv_lz_rc_finish(&e);
		hv_at(9, 0);
		st = lz1(3, 0, 2, b, n, 100, &p, res);
		CK(st == KUNCOAT_OK && p == 2 && !memcmp(res, "12", 2));
		hv_lz_free(&e);
	}
	/* zero input and one byte: TRUNCATED or CORRUPT, never OK with output */
	hv_at(10, 0);
	st = lz1(3, 0, 2, res, 0, 100, &p, NULL);
	CK(st == KUNCOAT_TRUNCATED && p == 0);
	for (i = 1; i <= 5; i++) {
		static const uint8_t z[8] = { 0 };

		st = lz1(3, 0, 2, z, i, 100, &p, NULL);
		CKF(st != KUNCOAT_OK || p == 0, "%u zero bytes: %s, produced %llu", i, kuncoat_status_name(st),
		    (unsigned long long)p);
	}
	/* a non-zero first byte (the range coder's first byte is always 0): decoded regardless */
	{
		static const uint8_t junk[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3 };

		st = lz1(3, 0, 2, junk, sizeof junk, 100, &p, NULL);
		CK(hv_status_ok(st));
	}
}

static void properties(void)
{
	uint8_t res[64], in[64] = { 0 };
	uint64_t p;
	enum kuncoat_status st;
	static const unsigned bad[][3] = {
		{ 9, 0, 0 }, { 0, 5, 0 }, { 0, 0, 5 }, { 0xFFFFFFFFu, 0, 0 }, { 0, 0xFFFFFFFFu, 0 },
		{ 0, 0, 0xFFFFFFFFu }, { 8, 5, 5 }, { 100, 100, 100 }, { 0x80000000u, 0, 0 },
	};
	unsigned i;
	clock_t t0 = clock();

	for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		p = 7;
		hv_at(20, i);
		st = kuncoat_lzma_decode(bad[i][0], bad[i][1], bad[i][2], in, sizeof in, res, sizeof res, &p);
		CKF(st == KUNCOAT_CORRUPT && p == 0, "props %u/%u/%u: %s", bad[i][0], bad[i][1], bad[i][2],
		    kuncoat_status_name(st));
	}
	/* the largest legal model: 0x300 << 12 entries = 6 MB, allocated and filled per call */
	{
		OPS_BEGIN(e, b)
		size_t n;
		struct hv_lz big;
		uint8_t *bb = malloc(4000);

		(void)e; (void)b;
		if (hv_lz_init(&big, bb, 4000, 8, 4, 4, 1000)) {
			hv_lz_lit(&big, 'h'); hv_lz_lit(&big, 'i'); hv_lz_match(&big, 6, 2);
			hv_lz_end_marker(&big);
			n = hv_lz_rc_finish(&big);
			hv_at(21, 0);
			st = lz1(8, 4, 4, bb, n, 100, &p, res);
			CK(p == 8 && !memcmp(res, "hihihihi", 8));
		} else {
			CK(0);
		}
		hv_lz_free(&big);
		free(bb);
		hv_lz_free(&e);
	}
	CKF((double)(clock() - t0) / CLOCKS_PER_SEC < 5.0, "properties took too long");
}

static void bomb(void)
{
	static uint8_t b[60000];
	struct hv_lz e;
	uint64_t p;
	enum kuncoat_status st;
	size_t n, i;
	uint8_t *big;
	double t0;

	if (!hv_lz_init(&e, b, sizeof b, 3, 0, 2, 64)) {
		CK(0);
		return;
	}
	hv_lz_lit(&e, 'A');
	e.hcap = 0;                                      /* the history is not needed */
	for (i = 0; i < 250000; i++)
		hv_lz_match_raw(&e, 273, 0), e.hn += 273;
	hv_lz_end_marker(&e);
	n = hv_lz_rc_finish(&e);
	CK(!e.over);
	hv_lz_free(&e);
	/* the match offsets above started at position 1 with distance 1 */
	big = malloc(70u << 20);
	if (!big) {
		CK(0);
		return;
	}
	t0 = hv_wall();
	hv_at(30, 0);
	st = kuncoat_lzma_decode(3, 0, 2, b, n, big, 1u << 20, &p);
	CKF(st == KUNCOAT_STOPPED && p == (1u << 20), "bomb, cap 1 MB: %s %llu", kuncoat_status_name(st),
	    (unsigned long long)p);
	CKF(hv_wall() - t0 < 5.0, "bomb with a 1 MB cap took %.2fs", hv_wall() - t0);
	t0 = hv_wall();
	hv_at(30, 1);
	st = kuncoat_lzma_decode(3, 0, 2, b, n, big, 70u << 20, &p);
	CKF(p == 1u + 250000u * 273u && (st == KUNCOAT_OK || st == KUNCOAT_TRUNCATED),
	    "bomb, cap 70 MB: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
	CKF(hv_wall() - t0 < 15.0, "68 MB bomb took %.2fs", hv_wall() - t0);
	for (i = 0; i < p && i < 4096; i++)
		if (big[i] != 'A') {
			CK(0);
			break;
		}
	printf("  (bomb: %zu bytes of LZMA -> %llu bytes)\n", n, (unsigned long long)p);
	free(big);
}

/* ---- LZMA2 ---------------------------------------------------------------------------------- */

static enum kuncoat_status lz2(const uint8_t *in, size_t n, size_t cap, uint64_t *p, uint8_t *copy)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	enum kuncoat_status st;

	*p = 0xABABull;
	st = kuncoat_lzma2_decode(ip, n, op, cap, p);
	CK(hv_status_ok(st));
	CKF(*p <= cap, "produced %llu > cap %zu", (unsigned long long)*p, cap);
	CK(hv_out_canary_ok(op));
	if (copy && *p <= cap)
		memcpy(copy, op, (size_t)*p);
	return st;
}

static void lzma2_headers(void)
{
	uint8_t b[300], res[300];
	uint64_t p;
	enum kuncoat_status st;
	unsigned c;

	/* the end byte alone: complete and empty; an empty input has no end byte (see silent_loss) */
	b[0] = 0;
	hv_at(40, 0);
	st = lz2(b, 1, 10, &p, res);
	CK(st == KUNCOAT_OK && p == 0);
	/* control bytes 3..0x7F are not defined */
	for (c = 3; c < 0x80; c++) {
		b[0] = (uint8_t)c; b[1] = 0; b[2] = 0; b[3] = 'x';
		hv_at(41, c);
		st = lz2(b, 4, 10, &p, res);
		CKF(st == KUNCOAT_CORRUPT && p == 0, "control %#x: %s", c, kuncoat_status_name(st));
	}
	/* an LZMA chunk (every control 0x80..0xFF, reset 0 or 1) before any properties */
	for (c = 0x80; c < 0x100; c++) {
		if (c >= 0xC0)
			continue;                           /* reset >= 2 carries its own properties */
		memset(b, 0, sizeof b);
		b[0] = (uint8_t)c; b[3] = 0; b[4] = 5;
		hv_at(42, c);
		st = lz2(b, 12, 10, &p, res);
		CKF(st == KUNCOAT_CORRUPT && p == 0, "control %#x without properties: %s", c, kuncoat_status_name(st));
	}
	/* invalid properties bytes: >= 225 (9*5*5) */
	for (c = 225; c < 256; c += 5) {
		b[0] = 0xE0; b[1] = 0; b[2] = 3; b[3] = 0; b[4] = 5; b[5] = (uint8_t)c;
		memset(b + 6, 0, 8);
		hv_at(43, c);
		st = lz2(b, 14, 10, &p, res);
		CKF(st == KUNCOAT_CORRUPT && p == 0, "props byte %u: %s", c, kuncoat_status_name(st));
	}
	/* a raw chunk longer than the input: the bytes that are there are real, TRUNCATED */
	b[0] = 1; b[1] = 0; b[2] = 99;
	memcpy(b + 3, "0123456789", 10);
	hv_at(44, 0);
	st = lz2(b, 13, 200, &p, res);
	CK(st == KUNCOAT_TRUNCATED && p == 10 && !memcmp(res, "0123456789", 10));
	/* a raw chunk header cut short */
	for (c = 1; c <= 2; c++) {
		hv_at(45, c);
		st = lz2(b, c, 200, &p, res);
		CKF(st == KUNCOAT_TRUNCATED && p == 0, "raw header cut at %u: %s", c, kuncoat_status_name(st));
	}
	/* an LZMA chunk header cut short (1..5 bytes) */
	b[0] = 0xE0; b[1] = 0; b[2] = 9; b[3] = 0; b[4] = 20; b[5] = 0x5D;
	for (c = 1; c <= 5; c++) {
		hv_at(46, c);
		st = lz2(b, c, 200, &p, res);
		CKF(st == KUNCOAT_TRUNCATED && p == 0, "chunk header cut at %u: %s", c, kuncoat_status_name(st));
	}
	/* the room: a raw chunk of 10 into a room of 4 is STOPPED with the real 4 */
	b[0] = 1; b[1] = 0; b[2] = 9;
	memcpy(b + 3, "ABCDEFGHIJ", 10);
	hv_at(47, 0);
	st = lz2(b, 13, 4, &p, res);
	CK(st == KUNCOAT_STOPPED && p == 4 && !memcmp(res, "ABCD", 4));
	/* two raw chunks and the end byte, room for exactly both: OK */
	{
		uint8_t t[64];
		size_t n = 0;

		n += hv_lz2_raw(t + n, (const uint8_t *)"hello ", 6, 1);
		n += hv_lz2_raw(t + n, (const uint8_t *)"world", 5, 0);
		t[n++] = 0;
		st = lz2(t, n, 11, &p, res);
		CK(st == KUNCOAT_OK && p == 11 && !memcmp(res, "hello world", 11));
		st = lz2(t, n, 12, &p, res);
		CK(st == KUNCOAT_OK && p == 11);
		st = lz2(t, n, 10, &p, res);
		CK(st == KUNCOAT_STOPPED && p == 10);
	}
	/* a chunk that decodes nothing: it must end, not loop (chunk of garbage with a tiny c_len) */
	{
		uint8_t t[128];
		size_t n = 0;

		t[n++] = 0xE0; t[n++] = 0; t[n++] = 255; t[n++] = 0; t[n++] = 0; t[n++] = 0x5D;
		t[n++] = 0xFF;                          /* the one compressed byte */
		for (c = 0; c < 20; c++) {
			t[n++] = 0x80; t[n++] = 0; t[n++] = 255; t[n++] = 0; t[n++] = 0;
			t[n++] = 0xFF;
		}
		hv_at(48, 0);
		st = lz2(t, n, 1000, &p, res);
		CK(hv_status_ok(st));
	}
	/* a chunk size of 2^21 (the format's maximum) over a room of 100 */
	b[0] = 0xFF; b[1] = 0xFF; b[2] = 0xFF; b[3] = 0; b[4] = 3; b[5] = 0x5D;
	memset(b + 6, 0, 16);
	hv_at(49, 0);
	st = lz2(b, 22, 100, &p, res);
	CK(hv_status_ok(st) && p <= 100);
}

/* A storm of one-literal chunks each asking for a state reset after one asked for the
 * largest model: how long do N of them take? */
static void lzma2_reset_storm(void)
{
	static uint8_t big[400000];
	struct hv_lz e;
	uint8_t tmp[64];
	uint8_t *o = big;
	size_t n = 0, cl, i, nchunks = 600;
	uint64_t p;
	uint8_t *out;
	enum kuncoat_status st;
	double t0;

	if (!hv_lz_init(&e, tmp, sizeof tmp, 8, 4, 4, 4096)) {
		CK(0);
		return;
	}
	/* chunk 1: the largest model (props lc8 lp4 pb4 = (4*5+4)*9+8 = 224), one literal */
	hv_lz_lit(&e, 'a');
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(o + n, 1, cl, 3, 224);
	memcpy(o + n, tmp, cl);
	n += cl;
	/* then small chunks with reset 2 and tiny properties: lc0 lp0 pb0 = 0; the decoder keeps
	 * the model it grew, and what it initialises each time is what is measured */
	for (i = 0; i < nchunks; i++) {
		hv_lz_reset(&e, 0, 0, 0);
		hv_lz_rc_start(&e, tmp, sizeof tmp);
		hv_lz_lit(&e, 'b');
		cl = hv_lz_rc_finish(&e);
		n += hv_lz2_head(o + n, 1, cl, 2, 0);
		memcpy(o + n, tmp, cl);
		n += cl;
	}
	o[n++] = 0;
	CK(n < sizeof big);
	hv_lz_free(&e);
	out = malloc(nchunks + 16);
	if (!out) {
		CK(0);
		return;
	}
	t0 = hv_wall();
	hv_at(50, 0);
	st = kuncoat_lzma2_decode(big, n, out, nchunks + 16, &p);
	t0 = hv_wall() - t0;
	CKF(st == KUNCOAT_OK && p == nchunks + 1u, "storm: %s, %llu bytes", kuncoat_status_name(st),
	    (unsigned long long)p);
	/* 600 chunks of ~11 bytes = 6.6 KB of input. lz_reset_state loops over every probability
	 * the model ever grew to (3.1 M for lc8 lp4) on each reset, whatever the chunk's own
	 * lc/lp: the cost per input byte is ~40 us and grows with the stream, so it is printed
	 * and bounded loosely here (a timing assertion tight enough to catch it would also
	 * fail on a slow machine). */
	printf("  (lzma2 reset storm: %zu bytes of input, %zu chunks, %.3fs)\n", n, nchunks + 1, t0);
	CKF(t0 < 30.0, "reset storm took %.1fs", t0);
	free(out);
}

/* "Output before the failure is real output" (status.h): is it, when the input is cut?
 * Every cut of a stream; returns the number of cuts that hand back bytes that are not
 * the real output, and the worst count of such bytes. */
struct tf { size_t nbad, worst, first, worst_cut; };

static void trunc_prefix_one(unsigned lc, unsigned lp, unsigned pb, const uint8_t *in, size_t n,
			     const uint8_t *want, size_t wn, size_t stride, struct tf *r)
{
	size_t cut, k;
	static uint8_t res[70000];
	uint64_t p;

	memset(r, 0, sizeof *r);
	for (cut = 6; cut < n; cut += stride) {
		hv_at(60, cut);
		(void)lz1(lc, lp, pb, in, cut, wn + 8u, &p, res);
		for (k = 0; k < p && k < wn && res[k] == want[k]; k++)
			;
		if (k < p) {
			if (!r->nbad)
				r->first = cut;
			r->nbad++;
			if (p - k > r->worst) {
				r->worst = p - k;
				r->worst_cut = cut;
			}
		}
	}
}

static void trunc_fabrication(void)
{
	static char what[300];
	struct tf a, b, c, d, x = { 0, 0, 0, 0 };
	size_t total;

	trunc_prefix_one(3, 0, 2, v_a.in, v_a.n, v_a.want, v_a.wn, 1, &a);
	trunc_prefix_one(0, 0, 0, v_b.in, v_b.n, v_b.want, v_b.wn, 1, &b);
	trunc_prefix_one(4, 0, 0, v_c.in, v_c.n, v_c.want, v_c.wn, 1, &c);
	trunc_prefix_one(0, 4, 4, v_d.in, v_d.n, v_d.want, v_d.wn, 1, &d);
	if (xz1_in)
		trunc_prefix_one(3, 0, 2, xz1_in, xz1_n, xz_plain, 20000, 7, &x);
	total = a.nbad + b.nbad + c.nbad + d.nbad + x.nbad;
	printf("  (lzma truncation: fabricated bytes a %zu/%zu b %zu/%zu c %zu/%zu d %zu/%zu xz %zu/%zu cuts, worst %zu bytes)\n",
	       a.nbad, a.worst, b.nbad, b.worst, c.nbad, c.worst, d.nbad, d.worst, x.nbad, x.worst,
	       a.worst > b.worst ? a.worst : b.worst);
	snprintf(what, sizeof what, "lzma: stream (lc0 lp0 pb0, seed 12, %zu bytes) cut at %zu hands back %zu bytes that are not "
		 "the real output, status TRUNCATED (%zu of %zu cuts affected)", v_b.n, b.worst_cut, b.worst, b.nbad, v_b.n - 6u);
	CK(total == 0);
}

/* A cap that ends inside the LAST chunk of an LZMA2 stream. */
static void lzma2_cap_last_chunk(void)
{
	struct hv_lz e;
	uint8_t tmp[400], in[600], res[200];
	uint64_t p;
	size_t cl, n = 0, i;
	enum kuncoat_status st;

	if (!hv_lz_init(&e, tmp, sizeof tmp, 3, 0, 2, 1000)) {
		CK(0);
		return;
	}
	for (i = 0; i < 100; i++)
		hv_lz_lit(&e, (uint8_t)('a' + i % 26));
	cl = hv_lz_rc_finish(&e);
	n += hv_lz2_head(in + n, 100, cl, 3, 0x5D);
	memcpy(in + n, tmp, cl);
	n += cl;
	in[n++] = 0;
	hv_lz_free(&e);
	hv_at(61, 0);
	st = lz2(in, n, 100, &p, res);
	CK(st == KUNCOAT_OK && p == 100);
	/* two chunks: a cap inside the FIRST is STOPPED (the next control byte is not 0) ... */
	st = lz2(in, n, 99, &p, res);
	CK(p == 99);
	CK(st != KUNCOAT_OK);
}

/* A dictionary reset: a match in the chunk after it may not reach into the chunk before
 * it, and with no reset (state and properties only) the same bytes decode. */
static void lzma2_dict_reset(void)
{
	struct hv_lz e;
	uint8_t tmp[200], in[400], res[100];
	static const uint8_t raw[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
	unsigned reset;
	size_t i;

	for (reset = 2; reset <= 3; reset++) {
		size_t n = 0, cl;
		uint64_t p;
		enum kuncoat_status st;

		if (!hv_lz_init(&e, tmp, sizeof tmp, 0, 0, 0, 100)) {
			CK(0);
			return;
		}
		for (i = 0; i < 8; i++)                 /* the history the encoder will reach into */
			hv_lz_lit(&e, raw[i]);
		(void)hv_lz_rc_finish(&e);
		hv_lz_reset(&e, 0, 0, 0);
		hv_lz_rc_start(&e, tmp, sizeof tmp);
		hv_lz_lit(&e, 'z');
		hv_lz_match(&e, 3, 5);                  /* five back from the 9th byte: 'e' */
		cl = hv_lz_rc_finish(&e);
		n += hv_lz2_raw(in + n, raw, sizeof raw, 1);   /* control 1: dictionary reset */
		n += hv_lz2_head(in + n, 4, cl, reset, 0);
		memcpy(in + n, tmp, cl);
		n += cl;
		in[n++] = 0;
		hv_lz_free(&e);
		hv_at(70, reset);
		st = lz2(in, n, 50, &p, res);
		if (reset == 3) {
			/* the chunk reset the dictionary: nothing before it is reachable */
			CKF(st == KUNCOAT_CORRUPT && p == 9, "dictionary reset: %s %llu", kuncoat_status_name(st),
			    (unsigned long long)p);
		} else {
			CKF(st == KUNCOAT_OK && p == 12 && !memcmp(res + 8, "zefg", 4), "no dictionary reset: %s %llu",
			    kuncoat_status_name(st), (unsigned long long)p);
		}
	}
}

HV_GROUP(trunc_fabrication)
HV_GROUP(lzma2_dict_reset)
HV_GROUP(lzma2_cap_last_chunk)
HV_GROUP(crafted)
HV_GROUP(properties)
HV_GROUP(bomb)
HV_GROUP(lzma2_headers)
HV_GROUP(lzma2_reset_storm)

static int sweeps_g_fn(void *a)
{
	return sweeps(a);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, 400000) || !hv_gb_init(&gout, 400000)) {
		printf("hostile_lzma: cannot map guard buffers\n");
		return 1;
	}
	CK(make_lz1(&v_a, 3, 0, 2, 11, 2500, 1));
	CK(make_lz1(&v_b, 0, 0, 0, 12, 2000, 1));
	CK(make_lz1(&v_c, 4, 0, 0, 13, 2000, 1));
	CK(make_lz1(&v_d, 0, 4, 4, 14, 1500, 1));
	CK(make_lz1(&v_m, 3, 0, 2, 15, 1200, 1));
	CK(make_lz2(&v2));
	xz_vectors();
	if (!xz1_in || !xz2_in)
		printf("  SKIP lzma/xz raw vectors: no xz tool\n");
	hv_expect_clean("lzma sweeps", sweeps_g_fn, NULL, 40);
	hv_expect_clean("lzma crafted", hv_grp_crafted, NULL, 10);
	hv_expect_clean("lzma truncation fabrication", hv_grp_trunc_fabrication, NULL, 10);
	hv_expect_clean("lzma2 cap in the last chunk", hv_grp_lzma2_cap_last_chunk, NULL, 10);
	hv_expect_clean("lzma2 dictionary reset", hv_grp_lzma2_dict_reset, NULL, 10);
	hv_expect_clean("lzma properties", hv_grp_properties, NULL, 10);
	hv_expect_clean("lzma bomb", hv_grp_bomb, NULL, 20);
	hv_expect_clean("lzma2 headers", hv_grp_lzma2_headers, NULL, 10);
	hv_expect_clean("lzma2 reset storm", hv_grp_lzma2_reset_storm, NULL, 60);
	free(xz1_in);
	free(xz2_in);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("hostile_lzma");
}
