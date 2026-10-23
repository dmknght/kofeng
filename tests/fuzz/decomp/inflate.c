/*
 * decomp/inflate - kuncoat_inflate and kuncoat_inflate_seeded against zlib as the oracle.
 *
 * Seeds are real raw DEFLATE streams made by zlib (levels 1/6/9, a stored block with its LEN/NLEN field map, a
 * repetitive text with long back references). A blind flip of a compressed stream is 99% CORRUPT, so the stored seed brings
 * a field map and the mutators also splice and truncate. Held: the status is one of the enum, consumed <= n,
 * produced >= what the sink took, a refusal is STOPPED, the sink is not called again after it said no, and when the
 * stream decodes to the end and nothing refused, zlib decodes the same bytes to the same output and consumes as many.
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
