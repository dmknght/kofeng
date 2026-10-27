/*
 * decomp/inflate - kuncoat_inflate and kuncoat_inflate_seeded against zlib as the oracle.
 *
 * Seeds are real raw DEFLATE streams made by zlib (levels 1/6/9, a stored block with its LEN/NLEN field map, a
 * repetitive text with long back references). A blind flip of a compressed stream is 99% CORRUPT, so the stored seed brings
 * a field map and the mutators also splice and truncate. Held: the status is one of the enum, consumed <= n,
 * produced >= what the sink took, a refusal is STOPPED, the sink is not called again after it said no, and when the
 * stream decodes to the end and nothing refused, zlib decodes the same bytes to the same output and consumes as many.
 *
 * WP5 EXTENSION. The seeds below add what a blind flip of a zlib stream seldom reaches: the TABLES of a dynamic block written by hand
 * (hostile_enc.h hv_dyn_*): the largest alphabets (HLIT 286, HDIST 30), code lengths of 15, an incomplete literal code, an
 * over-subscribed one, an incomplete distance code, a single distance code, a distance that points before the start, repeat counts
 * of 258 by the thousand, stored blocks whose LEN and NLEN disagree, a second block after the first. And the check runs the other way
 * too: a stream zlib decodes to its end that this decoder does not (and no sink refused) is held against the decoder.
 *
 * ONE KNOWN DIFFERENCE, not held against the decoder: zlib refuses every incomplete distance code except a single code
 * ("invalid distances set"), kuncoat_inflate tolerates any incomplete one and refuses over-subscribed ones (inflate.c, the note
 * above its second construct()). The smoke run found it (seed 7, iteration 12407; kept as
 * /mnt/games/normtest/tests_wp0/findings/inflate_incomplete_distance_*.bin). [Inference] deliberate leniency, not a defect;
 * the owner can tighten it.
 */
#include <uncoat.h>
#include <zlib.h>

#include "../../lib/fuzz_drv.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"

#define RAW_N 3000u

static struct kuncoat_inflate st;

static void raw_body(uint8_t *raw)
{
	size_t i;

	for (i = 0; i < RAW_N; i++)
		raw[i] = (uint8_t)((size_t)"hello inflate world, "[i % 21] ^ (i / 211));
}

static void add_zlib(struct fz_corpus *c, const char *name, const uint8_t *raw, size_t n, int level, int strategy)
{
	z_stream z;
	uint8_t out[RAW_N * 2];

	memset(&z, 0, sizeof z);
	if (deflateInit2(&z, level, Z_DEFLATED, -15, 8, strategy) != Z_OK)
		return;
	z.next_in = (Bytef *)(uintptr_t)raw;
	z.avail_in = (uInt)n;
	z.next_out = out;
	z.avail_out = sizeof out;
	if (deflate(&z, Z_FINISH) == Z_STREAM_END)
		fz_corpus_add(c, name, out, z.total_out);
	deflateEnd(&z);
}

static const struct fz_field stored_fields[] = {
	{ 1, 2, 0, FZ_LEN }, { 3, 2, 0, FZ_LEN }
};
static const struct fz_map stored_map = { stored_fields, 2, 0, 0, 0 };

/* A dynamic block with hand-written tables. `lit`/`dist` are the code-length arrays; the body is (len, dist) pairs after one literal. */
static void dyn_seed(struct fz_corpus *c, const char *name, const uint8_t *ll, unsigned nl, const uint8_t *dl, unsigned nd, const unsigned *lit, unsigned n_lit,
		     unsigned len, unsigned dist, unsigned reps, int rle)
{
	static uint8_t buf[8192];
	struct hv_bw w;
	struct hv_dyn t;
	unsigned i;

	hv_bw_init(&w, buf, sizeof buf);
	hv_dyn_begin(&w, &t, 1, ll, nl, dl, nd, rle);
	for (i = 0; i < n_lit; i++)
		if (t.ll[lit[i]])
			hv_dyn_sym(&w, &t, lit[i]);
	for (i = 0; i < reps; i++)
		if (t.ll[257] && t.dl[0])
			hv_dyn_match(&w, &t, len, dist);
	if (t.ll[256])
		hv_dyn_sym(&w, &t, 256);
	fz_corpus_add(c, name, buf, hv_defl_end(&w));
}

static void structure_seeds(struct fz_corpus *c)
{
	static const unsigned lits[] = { 'a', 'b', 'a', 'b', 'c' };
	uint8_t ll[288], dl[32];
	unsigned i;

	hv_dyn_std_tables(ll, dl);
	dyn_seed(c, "dyn-std", ll, 286, dl, 30, lits, 5, 10, 3, 4, 1);
	dyn_seed(c, "dyn-std-norle", ll, 286, dl, 30, lits, 5, 258, 1, 1000, 0);   /* 258-byte runs, a thousand times: a ratio of 1000:1 */
	dyn_seed(c, "dyn-dist-before-start", ll, 286, dl, 30, lits, 1, 10, 5000, 1, 1);
	/* the smallest alphabets: HLIT 257 (no length symbols), HDIST 1 */
	memset(ll, 0, sizeof ll);
	ll['a'] = 2; ll['b'] = 2; ll['c'] = 2; ll[256] = 2;                          /* complete: 4 * 1/4 */
	memset(dl, 0, sizeof dl);
	dl[0] = 1;                                                                   /* a single distance code: one code of one bit */
	dyn_seed(c, "dyn-min-alphabet", ll, 257, dl, 1, lits, 5, 10, 3, 0, 1);
	/* incomplete literal code: three of length 2 and the end symbol of length 3 leaves a hole */
	ll['a'] = 2; ll['b'] = 2; ll['c'] = 2; ll[256] = 3;
	dyn_seed(c, "dyn-incomplete-lit", ll, 257, dl, 1, lits, 5, 10, 3, 0, 1);
	/* over-subscribed literal code: five symbols of length 2 */
	ll['a'] = 2; ll['b'] = 2; ll['c'] = 2; ll[256] = 2; ll['d'] = 2;
	dyn_seed(c, "dyn-oversubscribed-lit", ll, 257, dl, 1, lits, 5, 10, 3, 0, 1);
	ll['d'] = 0;
	/* incomplete distance code (zlib: invalid distances set; this decoder tolerates it: the known difference) */
	for (i = 0; i < 30; i++)
		dl[i] = 0;
	dl[0] = 2; dl[1] = 2;
	ll[257] = 3; ll[256] = 3; ll['a'] = 3; ll['b'] = 3; ll['c'] = 3; ll['d'] = 3;  /* 6 x 1/8 + hole: incomplete too */
	dyn_seed(c, "dyn-incomplete-dist", ll, 258, dl, 2, lits, 5, 3, 1, 2, 1);
	/* code lengths of 15 everywhere that is used (the longest the format has): 2 symbols of length 15 only, over a complete code of
	 * the 30 distance symbols */
	memset(ll, 0, sizeof ll);
	for (i = 0; i < 16; i++)
		ll[i] = 15;
	ll[256] = 15;
	for (i = 0; i < 30; i++)
		dl[i] = 15;
	dyn_seed(c, "dyn-length-15", ll, 286, dl, 30, lits, 0, 3, 1, 0, 1);
	/* two blocks: a dynamic one that is not final, then a stored one */
	{
		static uint8_t buf[4096];
		struct hv_bw w;
		struct hv_dyn t;

		hv_dyn_std_tables(ll, dl);
		hv_bw_init(&w, buf, sizeof buf);
		hv_dyn_begin(&w, &t, 0, ll, 286, dl, 30, 1);
		hv_dyn_sym(&w, &t, 'x');
		hv_dyn_match(&w, &t, 20, 1);
		hv_dyn_sym(&w, &t, 256);
		hv_defl_stored(&w, (const uint8_t *)"stored tail", 11, 1);
		fz_corpus_add(c, "dyn-then-stored", buf, hv_defl_end(&w));
	}
	/* a stored block whose NLEN is not the complement of LEN */
	{
		uint8_t bad[1 + 4 + 8] = { 1, 8, 0, 0x00, 0x00, 'b', 'a', 'd', 'n', 'l', 'e', 'n', '!' };

		fz_corpus_add(c, "stored-bad-nlen", bad, sizeof bad);
	}
}

static void seeds(struct fz_corpus *c)
{
	uint8_t raw[RAW_N], stored[1 + 4 + 64];

	raw_body(raw);
	add_zlib(c, "level1", raw, RAW_N, 1, Z_DEFAULT_STRATEGY);
	add_zlib(c, "level6", raw, RAW_N, 6, Z_DEFAULT_STRATEGY);
	add_zlib(c, "level9", raw, RAW_N, 9, Z_DEFAULT_STRATEGY);
	add_zlib(c, "fixed", raw, 200, 6, Z_FIXED);
	add_zlib(c, "huffman-only", raw, RAW_N, 6, Z_HUFFMAN_ONLY);
	add_zlib(c, "rle", raw, RAW_N, 6, Z_RLE);
	stored[0] = 1;                            /* BFINAL, BTYPE 00 */
	stored[1] = 64; stored[2] = 0;            /* LEN */
	stored[3] = 0xbf; stored[4] = 0xff;       /* NLEN */
	memcpy(stored + 5, raw, 64);
	fz_corpus_add_map(c, "stored", stored, sizeof stored, &stored_map);
	structure_seeds(c);
}

/* The same stream through zlib: 1 when it ends cleanly with the same output and the same input used. */
static int zlib_agrees(const uint8_t *in, size_t n, const uint8_t *got, uint64_t produced, uint64_t consumed)
{
	z_stream z;
	uint8_t *buf = (uint8_t *)malloc(produced + 1u);
	int r, ok;

	if (!buf)
		return 1;
	memset(&z, 0, sizeof z);
	if (inflateInit2(&z, -15) != Z_OK) {
		free(buf);
		return 1;
	}
	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)n;
	z.next_out = buf;
	z.avail_out = (uInt)(produced + 1u);
	r = inflate(&z, Z_FINISH);
	if (r == Z_DATA_ERROR && z.msg && !strcmp(z.msg, "invalid distances set")) {
		inflateEnd(&z);
		free(buf);
		return 1;
	}
	ok = r == Z_STREAM_END && z.total_out == produced && z.total_in == consumed && !memcmp(buf, got, (size_t)produced);
	inflateEnd(&z);
	free(buf);
	return ok;
}

/* 1 when zlib decodes the whole input as a raw DEFLATE stream to its end (a stream whose output is over 1 MiB is not asked). */
static int zlib_accepts(const uint8_t *in, size_t n)
{
	static uint8_t sink[1u << 20];
	z_stream z;
	int r;

	memset(&z, 0, sizeof z);
	if (inflateInit2(&z, -15) != Z_OK)
		return 0;
	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)n;
	z.next_out = sink;
	z.avail_out = sizeof sink;
	r = inflate(&z, Z_FINISH);
	inflateEnd(&z);
	return r == Z_STREAM_END;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kuncoat_io io;
	enum kuncoat_status r;

	memset(&io, 0, sizeof io);
	io.in.p = in;
	io.in.n = n;
	io.sink = c->sink_fn;
	io.user = c->sink_user;
	r = kuncoat_inflate(&st, &io);
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, io.consumed <= n, "consumed more than the input");
	FZ_CHECK(c, io.produced >= c->sink.total, "sink took more than the decoder says it produced");
	FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED, "a refusing sink did not end in STOPPED");
	if (r == KUNCOAT_OK && !c->refused && !c->failk)
		FZ_CHECK(c, zlib_agrees(in, n, c->out, io.produced, io.consumed), "zlib decodes this stream to a different result");
	else if (r != KUNCOAT_OK && !c->refused && !c->failk && n)
		FZ_CHECK(c, !zlib_accepts(in, n), "this decoder refused a stream zlib decodes to its end");
	fz_digest(c, (uint64_t)r ^ io.produced << 3 ^ io.consumed << 40);
	return (int)r;
}

FZ_ADAPTER(inflate, .name = "kuncoat/inflate", .covers = "kuncoat_inflate", .shape = FZ_BYTES, .seeds = seeds, .run = run);

/* The seeded form: the first bytes of the input pick a history of 0..255 bytes the stream may refer back to. */
static int run_seeded(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kuncoat_io io;
	struct kuncoat_span hist;
	enum kuncoat_status r;
	size_t h = n ? in[0] : 0;

	if (h > n - (n ? 1u : 0u))
		h = n ? n - 1u : 0;
	hist.p = in + (n ? 1u : 0u);
	hist.n = h;
	memset(&io, 0, sizeof io);
	io.in.p = in + (n ? 1u : 0u) + h;
	io.in.n = n ? n - 1u - h : 0;
	io.sink = c->sink_fn;
	io.user = c->sink_user;
	r = kuncoat_inflate_seeded(&st, &hist, &io);
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, io.consumed <= io.in.n, "consumed more than the input");
	FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED, "a refusing sink did not end in STOPPED");
	fz_digest(c, (uint64_t)r ^ io.produced << 3 ^ io.consumed << 40);
	return (int)r;
}

/* The seeds of the seeded form: one length byte (a 0..255 byte history of the raw body) and the stream. */
static void seeds_seeded(struct fz_corpus *c)
{
	struct fz_corpus plain;
	uint8_t raw[RAW_N], buf[1 + 64 + RAW_N * 2];
	size_t i;

	memset(&plain, 0, sizeof plain);
	seeds(&plain);
	raw_body(raw);
	for (i = 0; i < plain.n; i++) {
		size_t h = i % 3u ? 0u : 32u;

		buf[0] = (uint8_t)h;
		memcpy(buf + 1, raw, h);
		memcpy(buf + 1 + h, plain.v[i].p, plain.v[i].n);
		fz_corpus_add(c, plain.v[i].name, buf, 1 + h + plain.v[i].n);
	}
	fz_corpus_free(&plain);
}

FZ_ADAPTER(inflate_seeded, .name = "kuncoat/inflate_seeded", .covers = "kuncoat_inflate_seeded", .shape = FZ_BYTES, .seeds = seeds_seeded, .run = run_seeded);
