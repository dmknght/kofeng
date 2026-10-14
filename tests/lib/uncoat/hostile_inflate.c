/*
 * hostile_inflate - kuncoat_inflate and kuncoat_inflate_seeded (inflate.h) against
 * streams that lie.
 *
 * The streams are built here (hostile_enc.h writes stored, fixed-Huffman and
 * dynamic-Huffman blocks and a hand-made dynamic header), plus one real dynamic
 * stream from the gzip tool when it is installed.
 *
 *   SWEEPS      hostile_sweep.h on stored, fixed, mixed, window-wrapping (40000 byte),
 *               dynamic and gzip-made streams: every cap, every truncation, every flip.
 *   HEADERS     the dynamic header's lies one by one: HLIT 288 and HDIST 32, an
 *               over-subscribed and an incomplete code-length code, symbol 16 with
 *               nothing before it, a repeat that overruns the table, no end-of-block
 *               code, an over-subscribed literal code, an incomplete one, an
 *               over-subscribed distance code, deep (15 bit) codes that are legal.
 *   SYMBOLS     length 286/287 and distance 30/31, a distance past what was written
 *               (by one), a distance exactly at the window, the reserved block type.
 *   STORED      LEN/NLEN mismatch, a stored block longer than the input, empty ones.
 *   SEEDED      a distance into the seed, one past it, seeds of 0, 1, 32768 bytes, a
 *               NULL seed with a length, the seed forgotten by the next call.
 *   BOMB        ratio ~1:160 stream asked for 200 MB with a sink that stops: STOPPED,
 *               not a hang, not a runaway buffer.
 *   SINK        refusing at the first call, in the middle and at the last one; the
 *               sink is not called again after it refused; `produced` and `consumed`
 *               set on every call and never above the lengths given.
 *   STATE       the state struct reused after CORRUPT, TRUNCATED and STOPPED with no
 *               re-initialisation (the decoder resets it itself), and the consumed
 *               count when streams are concatenated or followed by garbage.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_sweep.h"

#include <decompressors/inflate.h>

static struct kuncoat_inflate *g_st;

/* ---- the adapter ------------------------------------------------------------------ */

static enum kuncoat_status inf_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out,
				   size_t cap, uint64_t *prod)
{
	struct hv_bufsink s;
	struct kuncoat_io io;
	enum kuncoat_status st;

	memset(&s, 0, sizeof s);
	s.out = out;
	s.cap = cap;
	memset(&io, 0, sizeof io);
	io.in.p = in;
	io.in.n = n;
	io.sink = hv_bufsink_fn;
	io.user = &s;
	io.consumed = 0xDEADBEEFull;
	io.produced = 0xDEADBEEFull;
	st = kuncoat_inflate(ctx, &io);
	CKF(io.consumed <= n, "consumed %llu > in_len %zu", (unsigned long long)io.consumed, n);
	hv_bufsink_check(&s, st, io.produced, "inflate");
	*prod = s.total;
	return st;
}

/* ---- valid streams ---------------------------------------------------------------- */

#define MAXV 70000u

static uint8_t body[6000];
static uint8_t enc_a[MAXV], enc_b[MAXV], enc_c[MAXV], enc_d[MAXV], enc_e[MAXV], enc_g[MAXV];
static uint8_t want_d[40000], want_e[2000], want_g[33000];
static size_t len_a, len_b, len_c, len_d, len_e, len_g, want_e_n, want_g_n;
static uint8_t *gz_raw;
static size_t gz_raw_n;
static uint8_t gz_plain[6000];

/* The expected output of vector e, by an independent byte-wise expansion. */
static size_t expect_e(uint8_t *out)
{
	size_t n = 0, i;

	for (i = 0; i < 800; i++)
		out[n++] = body[i];
	for (i = 0; i < 258; i++, n++)
		out[n] = out[n - 1];
	for (i = 0; i < 100; i++, n++)
		out[n] = out[n - 800];
	for (i = 0; i < 3; i++, n++)
		out[n] = out[n - 32];
	return n;
}

static size_t expect_g(uint8_t *out)
{
	size_t i;

	for (i = 0; i < 32768; i++)
		out[i] = (uint8_t)(i * 7u);
	for (i = 0; i < 50; i++)
		out[32768 + i] = out[i];
	return 32768 + 50;
}

static void build_gzip_vector(void)
{
	static const char *const argv[] = { "gzip", "-n", "-c", "-9", NULL };
	size_t gn = 0, off = 0;
	uint8_t *gz;

	hv_body(gz_plain, sizeof gz_plain, 77);
	gz = hv_tool(argv, gz_plain, sizeof gz_plain, &gn);
	if (!gz)
		return;
	gz_raw_n = hv_gzip_raw(gz, gn, &off);
	if (gz_raw_n && (gz_raw = malloc(gz_raw_n)) != NULL)
		memcpy(gz_raw, gz + off, gz_raw_n);
	else
		gz_raw_n = 0;
	free(gz);
}

static void build_vectors(void)
{
	struct hv_bw w;
	uint64_t rs = 31;
	size_t i;
	uint8_t ll[286], dl[30];
	struct hv_dyn t;

	hv_body(body, sizeof body, 1);
	/* a: stored blocks, one of them empty */
	hv_bw_init(&w, enc_a, sizeof enc_a);
	hv_defl_stored(&w, body, 700, 0);
	hv_defl_stored(&w, body, 0, 0);
	hv_defl_stored(&w, body + 700, 1300, 0);
	hv_defl_stored(&w, body + 2000, 1, 1);
	len_a = hv_defl_end(&w);
	/* b: one fixed block with real matches */
	hv_bw_init(&w, enc_b, sizeof enc_b);
	hv_defl_fixed(&w, body, 6000, 1, 32768);
	len_b = hv_defl_end(&w);
	/* c: coded, stored, coded, stored, coded: a stored block after a coded one begins mid-byte */
	hv_bw_init(&w, enc_c, sizeof enc_c);
	hv_defl_fixed(&w, body, 1500, 0, 32768);
	hv_defl_stored(&w, body + 1500, 500, 0);
	hv_defl_fixed(&w, body + 2000, 2500, 0, 32768);
	hv_defl_stored(&w, body + 4500, 40, 0);
	hv_defl_fixed(&w, body + 4540, 1000, 1, 32768);
	len_c = hv_defl_end(&w);
	/* d: 40000 bytes so the window wraps: a random head, a copy from exactly 32768 back,
	 * a run of one byte, a copy from 15468 back */
	for (i = 0; i < 32768; i++)
		want_d[i] = (uint8_t)hv_rng32(&rs);
	for (i = 0; i < 700; i++)
		want_d[32768 + i] = want_d[i];
	for (i = 0; i < 2000; i++)
		want_d[33468 + i] = 'Z';
	for (i = 0; i < 4532; i++)
		want_d[35468 + i] = want_d[20000 + i];
	hv_bw_init(&w, enc_d, sizeof enc_d);
	hv_defl_fixed(&w, want_d, 40000, 1, 32768);
	len_d = hv_defl_end(&w);
	/* e: a dynamic block with run-length coded tables, a run, an overlap and a far copy */
	hv_dyn_std_tables(ll, dl);
	hv_bw_init(&w, enc_e, sizeof enc_e);
	hv_dyn_begin(&w, &t, 1, ll, 286, dl, 30, 1);
	for (i = 0; i < 800; i++)
		hv_dyn_sym(&w, &t, body[i]);
	hv_dyn_match(&w, &t, 258, 1);
	hv_dyn_match(&w, &t, 100, 800);
	hv_dyn_match(&w, &t, 3, 32);
	hv_dyn_sym(&w, &t, 256);
	len_e = hv_defl_end(&w);
	want_e_n = expect_e(want_e);
	/* g: the legal edge, a match 32768 back after exactly 32768 bytes */
	hv_bw_init(&w, enc_g, sizeof enc_g);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	for (i = 0; i < 32768; i++)
		hv_defl_fsym(&w, (uint8_t)(i * 7u));
	hv_defl_fmatch(&w, 50, 32768);
	hv_defl_fsym(&w, 256);
	len_g = hv_defl_end(&w);
	want_g_n = expect_g(want_g);
	build_gzip_vector();
}

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec v[8];
	unsigned nv = 0;

	(void)arg;
	memset(&d, 0, sizeof d);
	d.name = "inflate";
	d.run = inf_run;
	d.ctx = g_st;
	v[nv++] = (struct hv_vec){ "stored", enc_a, len_a, body, 2001 };
	v[nv++] = (struct hv_vec){ "fixed", enc_b, len_b, body, 6000 };
	v[nv++] = (struct hv_vec){ "mixed", enc_c, len_c, body, 5540 };
	v[nv++] = (struct hv_vec){ "dynamic", enc_e, len_e, want_e, want_e_n };
	v[nv++] = (struct hv_vec){ "window-edge", enc_g, len_g, want_g, want_g_n };
	v[nv++] = (struct hv_vec){ "wrap-40000", enc_d, len_d, want_d, 40000 };
	if (gz_raw)
		v[nv++] = (struct hv_vec){ "gzip-dynamic", gz_raw, gz_raw_n, gz_plain, sizeof gz_plain };
	else
		printf("  SKIP inflate/gzip-dynamic: no gzip tool\n");
	{
		struct hv_sweep_job j = { &d, v, nv, 45000, 41000 };

		return hv_sweep_job_run(&j);
	}
}

/* ---- one call with a counting sink -------------------------------------------------- */

struct ires {
	enum kuncoat_status st;
	uint64_t            produced, consumed, sunk;
	uint32_t            sink_calls;
	int                 over;
};

static struct hv_gb gin;
static uint8_t keep[300000];

struct rsink {
	uint64_t total, refuse_at_call, calls, after;
	uint64_t refuse_bytes;
	int      stopped;
};

static int rsink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct rsink *s = u;
	uint32_t i;
	uint8_t x = 0;

	s->calls++;
	if (s->stopped) {
		s->after++;
		return 0;
	}
	for (i = 0; i < n; i++)
		x = (uint8_t)(x + p[i]);
	if ((s->refuse_at_call && s->calls >= s->refuse_at_call) ||
	    (s->refuse_bytes && s->total >= s->refuse_bytes)) {
		s->stopped = 1;
		return 0;
	}
	if (s->total < sizeof keep)
		memcpy(keep + s->total, p, n < sizeof keep - s->total ? n : sizeof keep - (size_t)s->total);
	s->total += n;
	return 1 + (x & 0);
}

static struct ires inf(const uint8_t *in, size_t n, uint64_t refuse_call, uint64_t refuse_bytes,
		       const struct kuncoat_span *seed)
{
	struct rsink s;
	struct kuncoat_io io;
	struct ires r;

	memset(&s, 0, sizeof s);
	s.refuse_at_call = refuse_call;
	s.refuse_bytes = refuse_bytes;
	memset(&io, 0, sizeof io);
	io.in.p = hv_in(&gin, in, n);
	io.in.n = n;
	io.sink = rsink_fn;
	io.user = &s;
	io.consumed = io.produced = 0xFEEDFACEull;
	r.st = seed ? kuncoat_inflate_seeded(g_st, seed, &io) : kuncoat_inflate(g_st, &io);
	r.produced = io.produced;
	r.consumed = io.consumed;
	r.sunk = s.total;
	r.sink_calls = (uint32_t)s.calls;
	r.over = s.after != 0;
	CK(hv_status_ok(r.st));
	CKF(r.consumed <= n, "consumed %llu > %zu", (unsigned long long)r.consumed, n);
	CKF(!r.over, "the sink was called again after it refused");
	return r;
}

#define AT() hv_at((uint64_t)__LINE__, 0)

/* ---- the lies of a dynamic header ------------------------------------------------- */

static const uint8_t CLORDER[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

/* BFINAL, BTYPE 2, the three counts, and the code-length code lengths `cl[sym]`. */
static void raw_head(struct hv_bw *w, unsigned hlit, unsigned hdist, unsigned hclen, const uint8_t *cl)
{
	unsigned i;

	hv_bw_lsb(w, 1, 1);
	hv_bw_lsb(w, 2, 2);
	hv_bw_lsb(w, hlit, 5);
	hv_bw_lsb(w, hdist, 5);
	hv_bw_lsb(w, hclen, 4);
	for (i = 0; i < hclen + 4u; i++)
		hv_bw_lsb(w, cl[CLORDER[i]], 3);
}

static void headers(void)
{
	uint8_t b[600], ll[300], dl[40], cl[19];
	struct hv_bw w;
	struct hv_dyn t;
	struct ires r;
	unsigned i;

	/* a valid dynamic block through the same writer: the control */
	hv_dyn_std_tables(ll, dl);
	hv_bw_init(&w, b, sizeof b);
	hv_dyn_begin(&w, &t, 1, ll, 286, dl, 30, 0);
	hv_dyn_sym(&w, &t, 'A');
	hv_dyn_sym(&w, &t, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.produced == 1 && r.sunk == 1 && keep[0] == 'A');

	/* HLIT 31 (288 literal symbols) and HDIST 31 (32 distances) are not allowed */
	memset(ll, 0, sizeof ll);
	hv_dyn_std_tables(ll, dl);
	ll[286] = ll[287] = 0;
	hv_bw_init(&w, b, sizeof b);
	hv_dyn_begin(&w, &t, 1, ll, 288, dl, 30, 0);
	hv_dyn_sym(&w, &t, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "HLIT 288: %s", kuncoat_status_name(r.st));
	hv_dyn_std_tables(ll, dl);
	dl[30] = dl[31] = 0;
	hv_bw_init(&w, b, sizeof b);
	hv_dyn_begin(&w, &t, 1, ll, 286, dl, 32, 0);
	hv_dyn_sym(&w, &t, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "HDIST 32: %s", kuncoat_status_name(r.st));

	/* code-length code: over-subscribed (every symbol one bit), incomplete (one symbol of
	 * three bits), empty. All have to be refused, none may be decoded with. */
	for (i = 0; i < 3; i++) {
		unsigned s;

		for (s = 0; s < 19; s++)
			cl[s] = i == 0 ? 1 : i == 1 ? (s == 5 ? 3 : 0) : 0;
		hv_bw_init(&w, b, sizeof b);
		raw_head(&w, 0, 0, 15, cl);
		for (s = 0; s < 40; s++)
			hv_bw_lsb(&w, 0, 8);
		AT();
		r = inf(b, hv_defl_end(&w), 0, 0, NULL);
		CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "code-length code kind %u: %s", i,
		    kuncoat_status_name(r.st));
	}
	/* every length 0..15 at once is also a refusal if the set is not complete */
	{
		unsigned s;

		for (s = 0; s < 19; s++)
			cl[s] = (uint8_t)(1 + s % 7);
		hv_bw_init(&w, b, sizeof b);
		raw_head(&w, 0, 0, 15, cl);
		for (s = 0; s < 40; s++)
			hv_bw_lsb(&w, 0xA5, 8);
		AT();
		r = inf(b, hv_defl_end(&w), 0, 0, NULL);
		CK(r.st != KUNCOAT_OK);
	}
}

/* Header with the fixed code-length code and an explicit symbol list. */
struct dsym { uint8_t sym, extra, nex; };

static size_t dyn_syms(uint8_t *b, size_t cap, unsigned hlit, unsigned hdist, const struct dsym *s,
		       unsigned ns, int literal_after)
{
	uint8_t clen[19];
	uint16_t cc[19];
	struct hv_bw w;
	unsigned i;

	for (i = 0; i < 19; i++)
		clen[i] = i <= 12 ? 4 : 5;
	hv_canon(clen, 19, cc);
	hv_bw_init(&w, b, cap);
	raw_head(&w, hlit, hdist, 15, clen);
	for (i = 0; i < ns; i++) {
		hv_bw_code(&w, cc[s[i].sym], clen[s[i].sym]);
		hv_bw_lsb(&w, s[i].extra, s[i].nex);
	}
	if (literal_after)
		for (i = 0; i < 64; i++)
			hv_bw_lsb(&w, 0, 8);
	return hv_defl_end(&w);
}

static void header_lies(void)
{
	uint8_t b[700];
	struct dsym seq[400];
	struct ires r;
	unsigned i, n;

	/* symbol 16 (repeat previous) as the very first length */
	seq[0] = (struct dsym){ 16, 0, 2 };
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, 1, 1), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT, "16 first: %s", kuncoat_status_name(r.st));
	/* 18 (11..138 zeros) overrunning the table: 258 lengths asked for, 257+1 exist,
	 * after one length already given */
	n = 0;
	seq[n++] = (struct dsym){ 1, 0, 0 };
	seq[n++] = (struct dsym){ 18, 127, 7 };           /* 138 zeros */
	seq[n++] = (struct dsym){ 18, 127, 7 };           /* 138 more: 277 > 258 */
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, n, 1), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT, "18 over the end: %s", kuncoat_status_name(r.st));
	/* 17 and 16 over the end by exactly one */
	n = 0;
	for (i = 0; i < 255; i++)
		seq[n++] = (struct dsym){ 1, 0, 0 };
	seq[n++] = (struct dsym){ 17, 0, 3 };             /* 3 zeros: 258 >= 257+1... fits exactly */
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, n, 1), 0, 0, NULL);
	CK(r.st != KUNCOAT_OK);                           /* 255+3 = 258 lengths, then data lies */
	n = 0;
	for (i = 0; i < 256; i++)
		seq[n++] = (struct dsym){ 1, 0, 0 };
	seq[n++] = (struct dsym){ 16, 0, 2 };             /* 3 repeats: 259 > 258 */
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, n, 1), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT, "16 over the end: %s", kuncoat_status_name(r.st));
	/* no end-of-block code: 257 literal lengths, 0..255 eight bits (complete), 256 zero */
	n = 0;
	for (i = 0; i < 256; i++)
		seq[n++] = (struct dsym){ 8, 0, 0 };
	seq[n++] = (struct dsym){ 0, 0, 0 };              /* symbol 256: no code */
	seq[n++] = (struct dsym){ 1, 0, 0 };              /* the one distance */
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, n, 1), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "no EOB: %s", kuncoat_status_name(r.st));
	/* over-subscribed literal code: 257 symbols all of length 8 (257/256) */
	n = 0;
	for (i = 0; i < 257; i++)
		seq[n++] = (struct dsym){ 8, 0, 0 };
	seq[n++] = (struct dsym){ 1, 0, 0 };
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, n, 1), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT, "over-subscribed literal code: %s", kuncoat_status_name(r.st));
	/* incomplete literal code: EOB with two bits, nothing else */
	n = 0;
	for (i = 0; i < 256; i++)
		seq[n++] = (struct dsym){ 0, 0, 0 };
	seq[n++] = (struct dsym){ 2, 0, 0 };
	seq[n++] = (struct dsym){ 1, 0, 0 };
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 0, seq, n, 1), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT, "incomplete literal code: %s", kuncoat_status_name(r.st));
	/* over-subscribed distance code (three symbols of one bit) */
	n = 0;
	for (i = 0; i < 256; i++)
		seq[n++] = (struct dsym){ 8, 0, 0 };
	seq[n++] = (struct dsym){ 8, 0, 0 };              /* 257 symbols of 8 bits: over-subscribed */
	AT();
	r = inf(b, dyn_syms(b, sizeof b, 0, 2, seq, n, 1), 0, 0, NULL);
	CK(r.st == KUNCOAT_CORRUPT);
}

/* A complete table that goes 15 bits deep, with matching symbols written back. */
static void deep_codes(void)
{
	uint8_t ll[257], dl[1], b[400];
	struct hv_bw w;
	struct hv_dyn t;
	struct ires r;
	unsigned i;
	static const uint16_t syms[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 256 };

	memset(ll, 0, sizeof ll);
	for (i = 0; i < 14; i++)
		ll[syms[i]] = (uint8_t)(i + 1);               /* 1..14 */
	ll[14] = 15;
	ll[256] = 15;                                       /* two codes of 15 complete the tree */
	dl[0] = 1;
	hv_bw_init(&w, b, sizeof b);
	hv_dyn_begin(&w, &t, 1, ll, 257, dl, 1, 0);
	for (i = 0; i < 15; i++)
		hv_dyn_sym(&w, &t, syms[i]);
	hv_dyn_sym(&w, &t, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CKF(r.st == KUNCOAT_OK && r.produced == 15, "15-bit deep code: %s, %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.produced);
	for (i = 0; i < 15 && r.produced == 15; i++)
		CK(keep[i] == i);
	/* the incomplete distance code is tolerated: a literal-only block with one distance symbol */
	/* (that is the control above: dl = {1} is incomplete) */
}

/* A dynamic block whose literal/length code is the single symbol EOB (RFC 1951: valid). */
static void single_eob(void)
{
	uint8_t ll[257], dl[1], b[64];
	struct hv_bw w;
	struct hv_dyn t;
	struct ires r;

	memset(ll, 0, sizeof ll);
	ll[256] = 1;                                        /* the only code, one bit long */
	dl[0] = 1;
	hv_bw_init(&w, b, sizeof b);
	hv_dyn_begin(&w, &t, 1, ll, 257, dl, 1, 1);
	hv_dyn_sym(&w, &t, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CK(r.produced == 0);
	CK(r.st == KUNCOAT_OK);
}

/* ---- symbols, distances, stored blocks ------------------------------------------------ */

static void symbols(void)
{
	uint8_t b[128];
	struct hv_bw w;
	struct ires r;

	/* length symbol 286, 287 */
	for (unsigned s = 286; s <= 287; s++) {
		hv_bw_init(&w, b, sizeof b);
		hv_bw_lsb(&w, 1, 1);
		hv_bw_lsb(&w, 1, 2);
		hv_defl_fsym(&w, 'A');
		hv_defl_fsym(&w, s);
		hv_bw_lsb(&w, 0, 5);
		AT();
		r = inf(b, hv_defl_end(&w), 0, 0, NULL);
		CKF(r.st == KUNCOAT_CORRUPT && r.produced == 1 && r.sunk == 1 && keep[0] == 'A',
		    "length symbol %u: %s, produced %llu", s, kuncoat_status_name(r.st),
		    (unsigned long long)r.produced);
	}
	/* distance symbols 30 and 31 (the fixed distance code has five bits, 32 codes) */
	for (unsigned ds = 30; ds <= 31; ds++) {
		hv_bw_init(&w, b, sizeof b);
		hv_bw_lsb(&w, 1, 1);
		hv_bw_lsb(&w, 1, 2);
		hv_defl_fsym(&w, 'A');
		hv_defl_fsym(&w, 257);
		hv_bw_code(&w, ds, 5);
		hv_bw_lsb(&w, 0, 16);                        /* more bits, so the code is read to its end */
		AT();
		r = inf(b, hv_defl_end(&w), 0, 0, NULL);
		CKF(r.st == KUNCOAT_CORRUPT, "distance symbol %u: %s", ds, kuncoat_status_name(r.st));
	}
	/* a distance past what was written, by one; exactly what was written is fine */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 'a');
	hv_defl_fsym(&w, 'b');
	hv_defl_fmatch(&w, 3, 3);
	hv_defl_fsym(&w, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 2 && r.sunk == 2, "distance 3 after 2 bytes: %s",
	    kuncoat_status_name(r.st));
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 'a');
	hv_defl_fsym(&w, 'b');
	hv_defl_fmatch(&w, 3, 2);
	hv_defl_fsym(&w, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.produced == 5 && !memcmp(keep, "ababa", 5));
	/* a match first of all: nothing to copy from */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fmatch(&w, 10, 1);
	hv_defl_fsym(&w, 256);
	AT();
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	/* reserved block type 3, with and without BFINAL */
	{
		static const uint8_t t3a[] = { 0x07, 0, 0, 0 }, t3b[] = { 0x06, 0, 0, 0 };

		AT();
		r = inf(t3a, sizeof t3a, 0, 0, NULL);
		CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
		r = inf(t3b, sizeof t3b, 0, 0, NULL);
		CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	}
	/* no input at all, and a block that never ends */
	AT();
	r = inf(b, 0, 0, 0, NULL);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0 && r.consumed == 0);
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 'x');
	r = inf(b, hv_defl_end(&w), 0, 0, NULL);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 1 && r.sunk == 1);
	/* the empty stream: a final fixed block with only the end symbol */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 256);
	{
		size_t n = hv_defl_end(&w);

		r = inf(b, n, 0, 0, NULL);
		CK(r.st == KUNCOAT_OK && r.produced == 0 && r.consumed == n && r.sink_calls == 0);
	}
}

static void stored_blocks(void)
{
	uint8_t b[300];
	struct ires r;
	struct hv_bw w;
	unsigned i;

	/* LEN != ~NLEN: refused, nothing copied */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 0, 2);
	hv_bw_align_lsb(&w);
	hv_bw_byte(&w, 5); hv_bw_byte(&w, 0); hv_bw_byte(&w, 0xFA); hv_bw_byte(&w, 0xFE);
	for (i = 0; i < 8; i++)
		hv_bw_byte(&w, 'x');
	AT();
	r = inf(b, w.n, 0, 0, NULL);
	CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	/* a length of 100 with 10 bytes present: the 10 are real, status TRUNCATED */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 0, 2);
	hv_bw_align_lsb(&w);
	hv_bw_byte(&w, 100); hv_bw_byte(&w, 0); hv_bw_byte(&w, (uint8_t)~100); hv_bw_byte(&w, 0xFF);
	for (i = 0; i < 10; i++)
		hv_bw_byte(&w, (uint8_t)('0' + i));
	AT();
	r = inf(b, w.n, 0, 0, NULL);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 10 && r.sunk == 10 && !memcmp(keep, "0123456789", 10));
	/* LEN 65535 (the largest) with nothing after the header */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 0, 2);
	hv_bw_align_lsb(&w);
	hv_bw_byte(&w, 0xFF); hv_bw_byte(&w, 0xFF); hv_bw_byte(&w, 0); hv_bw_byte(&w, 0);
	AT();
	r = inf(b, w.n, 0, 0, NULL);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
	/* header cut: 1..4 bytes */
	for (i = 1; i <= 4; i++) {
		AT();
		r = inf(b, i, 0, 0, NULL);
		CKF(r.st == KUNCOAT_TRUNCATED && r.produced == 0, "stored header cut at %u: %s", i,
		    kuncoat_status_name(r.st));
	}
	/* a stored block after a coded one: the whole bytes the bit buffer holds go back */
	{
		struct ires q = inf(enc_c, len_c, 0, 0, NULL);

		CK(q.st == KUNCOAT_OK && q.produced == 5540 && !memcmp(keep, body, 5540));
		CK(q.consumed == len_c);
	}
}

/* ---- seeds ------------------------------------------------------------------------------ */

static void seeded(void)
{
	uint8_t b[64], seed[40000];
	struct hv_bw w;
	struct ires r;
	struct kuncoat_span sp;
	size_t i, n;

	for (i = 0; i < sizeof seed; i++)
		seed[i] = (uint8_t)(i * 13u + 5u);
	/* a match 5 back as the first thing in the stream: right with a 5 byte seed */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fmatch(&w, 3, 5);
	hv_defl_fsym(&w, 256);
	n = hv_defl_end(&w);
	sp.p = seed;
	sp.n = 5;
	AT();
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_OK && r.produced == 3 && !memcmp(keep, seed, 3));   /* seed[0..3) */
	sp.n = 4;                                    /* one byte too few */
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	/* seeds of 0, 1: dist 1 works only with 1+ */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fmatch(&w, 4, 1);
	hv_defl_fsym(&w, 256);
	n = hv_defl_end(&w);
	sp.n = 0;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_CORRUPT);
	sp.n = 1;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_OK && r.produced == 4 && keep[0] == seed[0] && keep[3] == seed[0]);
	/* a NULL pointer with a length is no seed; a pointer with n 0 is no seed */
	sp.p = NULL;
	sp.n = 100;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_CORRUPT);
	r = inf(b, n, 0, 0, NULL);
	CK(r.st == KUNCOAT_CORRUPT);
	/* exactly the window: a match 32768 back works, and the seed is not output */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fmatch(&w, 10, 32768);
	hv_defl_fsym(&w, 256);
	n = hv_defl_end(&w);
	sp.p = seed;
	sp.n = 32768;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_OK && r.produced == 10 && r.sunk == 10 && !memcmp(keep, seed, 10));
	/* longer than the window: the seed is clamped (the head is kept, see silent_loss_uncoat.c) */
	sp.n = 32769;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_OK && r.produced == 10);
	sp.n = 40000;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_OK && r.produced == 10);
	/* a seeded call does not leak its seed into the next, unseeded one */
	r = inf(b, n, 0, 0, NULL);
	CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	/* a seed and a stream that ends at once */
	hv_bw_init(&w, b, sizeof b);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 256);
	n = hv_defl_end(&w);
	sp.n = 100;
	r = inf(b, n, 0, 0, &sp);
	CK(r.st == KUNCOAT_OK && r.produced == 0 && r.sink_calls == 0);
}

/* ---- the sink ----------------------------------------------------------------------------- */

static void sinks(void)
{
	struct ires r;

	/* refuse the first call: STOPPED, the sink saw nothing more */
	AT();
	r = inf(enc_b, len_b, 1, 0, NULL);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk == 0 && r.sink_calls == 1, "refuse at 1: %s, %u calls",
	    kuncoat_status_name(r.st), r.sink_calls);
	/* refuse the second call of a window-wrapping stream: 32768 bytes were accepted */
	r = inf(enc_d, len_d, 2, 0, NULL);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk == 32768, "refuse at 2: %s, sunk %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.sunk);
	/* the sink is handed a window at a time: two calls for 40000 bytes, and refusing the
	 * LAST one is STOPPED although the stream was complete */
	r = inf(enc_d, len_d, 0, 0, NULL);
	CK(r.sink_calls == 2);
	/* never refuse: every call accepted, all 40000 bytes, in order */
	r = inf(enc_d, len_d, 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.sunk == 40000 && r.produced == 40000 && !memcmp(keep, want_d, 40000));
	/* a stream that is cut short: the prefix reaches the sink, then TRUNCATED */
	r = inf(enc_d, len_d / 2, 0, 0, NULL);
	CK(r.st == KUNCOAT_TRUNCATED && r.sunk == r.produced && !memcmp(keep, want_d, (size_t)r.sunk));
}

static void bomb(void)
{
	static uint8_t big[1400000];
	struct hv_bw w;
	struct ires r;
	size_t i, n;

	hv_bw_init(&w, big, sizeof big);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 'A');
	for (i = 0; i < 800000; i++)
		hv_defl_fmatch(&w, 258, 1);
	hv_defl_fsym(&w, 256);
	n = hv_defl_end(&w);
	CK(!w.over);
	/* a sink that stops after 1 MB: the decoder must stop with it */
	AT();
	r = inf(big, n, 0, 1u << 20, NULL);
	CKF(r.st == KUNCOAT_STOPPED, "bomb with a refusing sink: %s", kuncoat_status_name(r.st));
	CKF(r.sunk <= (1u << 20) + 32768u, "bomb: %llu bytes reached the sink", (unsigned long long)r.sunk);
	/* the same with 20 MB accepted: exact count */
	hv_bw_init(&w, big, sizeof big);
	hv_bw_lsb(&w, 1, 1);
	hv_bw_lsb(&w, 1, 2);
	hv_defl_fsym(&w, 'A');
	for (i = 0; i < 80000; i++)
		hv_defl_fmatch(&w, 258, 1);
	hv_defl_fsym(&w, 256);
	n = hv_defl_end(&w);
	r = inf(big, n, 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.produced == 1u + 80000u * 258u && r.consumed == n);
}

/* ---- state reuse, concatenation, trailing bytes ---------------------------------------------- */

static void reuse(void)
{
	struct ires r;
	static uint8_t cat[MAXV];
	size_t at;

	/* the state is deliberately full of 0xFF at the start: no initialisation is required */
	memset(g_st, 0xFF, sizeof *g_st);
	AT();
	r = inf(enc_b, len_b, 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.produced == 6000 && !memcmp(keep, body, 6000));
	/* after CORRUPT, TRUNCATED and STOPPED, a good stream decodes right with no reset */
	{
		static const uint8_t bad[] = { 0x07, 0, 0, 0 };

		r = inf(bad, sizeof bad, 0, 0, NULL);
		CK(r.st == KUNCOAT_CORRUPT);
		r = inf(enc_b, len_b, 0, 0, NULL);
		CK(r.st == KUNCOAT_OK && r.produced == 6000 && !memcmp(keep, body, 6000));
		r = inf(enc_d, len_d / 3, 0, 0, NULL);
		CK(r.st == KUNCOAT_TRUNCATED);
		r = inf(enc_b, len_b, 0, 0, NULL);
		CK(r.st == KUNCOAT_OK && r.produced == 6000 && !memcmp(keep, body, 6000));
		r = inf(enc_d, len_d, 1, 0, NULL);
		CK(r.st == KUNCOAT_STOPPED);
		r = inf(enc_d, len_d, 0, 0, NULL);
		CK(r.st == KUNCOAT_OK && r.produced == 40000 && !memcmp(keep, want_d, 40000));
	}
	/* a window left full by one stream is not visible to the next: a stream that reaches
	 * back before its own start is CORRUPT whatever the last one wrote */
	{
		uint8_t b[32];
		struct hv_bw w;

		r = inf(enc_d, len_d, 0, 0, NULL);
		hv_bw_init(&w, b, sizeof b);
		hv_bw_lsb(&w, 1, 1);
		hv_bw_lsb(&w, 1, 2);
		hv_defl_fmatch(&w, 5, 100);
		hv_defl_fsym(&w, 256);
		r = inf(b, hv_defl_end(&w), 0, 0, NULL);
		CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	}
	/* concatenated streams: consumed is where the first ends, the rest decodes after it */
	memcpy(cat, enc_b, len_b);
	memcpy(cat + len_b, enc_a, len_a);
	r = inf(cat, len_b + len_a, 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.produced == 6000 && r.consumed == len_b);
	at = (size_t)r.consumed;
	r = inf(cat + at, len_a, 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.produced == 2001 && r.consumed == len_a);
	/* trailing garbage is not touched */
	memcpy(cat, enc_e, len_e);
	memset(cat + len_e, 0xA7, 40);
	r = inf(cat, len_e + 40, 0, 0, NULL);
	CK(r.st == KUNCOAT_OK && r.consumed == len_e && r.produced == want_e_n);
}

HV_GROUP(headers)
HV_GROUP(header_lies)
HV_GROUP(deep_codes)
HV_GROUP(single_eob)
HV_GROUP(symbols)
HV_GROUP(stored_blocks)
HV_GROUP(seeded)
HV_GROUP(sinks)
HV_GROUP(bomb)
HV_GROUP(reuse)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	g_st = malloc(sizeof *g_st);
	if (!g_st || !hv_gb_init(&gin, 1500000)) {
		printf("hostile_inflate: out of memory\n");
		return 1;
	}
	build_vectors();
	hv_expect_clean("inflate sweeps", sweeps, NULL, 25);
	hv_expect_clean("dynamic header: code-length code", hv_grp_headers, NULL, 10);
	hv_expect_clean("dynamic header: lies", hv_grp_header_lies, NULL, 10);
	hv_expect_clean("deep codes", hv_grp_deep_codes, NULL, 10);
	hv_expect_clean("single EOB code", hv_grp_single_eob, NULL, 10);
	hv_expect_clean("symbols", hv_grp_symbols, NULL, 10);
	hv_expect_clean("stored", hv_grp_stored_blocks, NULL, 10);
	hv_expect_clean("seeded", hv_grp_seeded, NULL, 10);
	hv_expect_clean("sink", hv_grp_sinks, NULL, 10);
	hv_expect_clean("bomb", hv_grp_bomb, NULL, 20);
	hv_expect_clean("reuse", hv_grp_reuse, NULL, 10);
	free(gz_raw);
	free(g_st);
	hv_gb_free(&gin);
	return hv_done("hostile_inflate");
}
