/*
 * decomp/lzma - kuncoat_lzma_decode (raw LZMA1, lc/lp/pb given) and kuncoat_lzma2_decode against liblzma as the oracle (the
 * library xz and Python's lzma module are built on).
 *
 * LZMA1 row: the first input byte is the properties byte ((pb * 5 + lp) * 9 + lc), so a mutation of it sweeps lc 0..8, lp 0..4
 * and pb 0..4 and the values past them (which must be refused, not used to size a model); the rest is the raw stream.
 * Seeds are made by liblzma (raw encoder, end marker) from plain texts built here: a text, one repeated byte, noise, a
 * short text, empty; lc/lp/pb 3/0/2, 0/2/0, 4/0/4, 1/3/1. LZMA2 seeds: text, noise past one 64 KiB chunk (stored chunks),
 * a run, and the chunk stream of preset 0 and 6.
 *
 * Held (dc_buf_run): status in the enum, produced <= cap, a smaller cap changes no byte, a seed gives its plain text.
 * Held against the oracle (dc_cmp_ref): liblzma decodes the input completely -> ours gives the same bytes under a roomy cap, the
 * real beginning under a small one, never CORRUPT/TRUNCATED. LENIENT (ours OK, liblzma refuses) is expected and not held: ours
 * accepts a stream with no end marker when the output buffer ends it, a dictionary distance up to the bytes produced, an LZMA2
 * stream whose first chunk does not reset the dictionary (lzma.h says so). [Inference] all deliberate.
 */
#include <lzma.h>

#include "decomp_common.h"

#define LZ_PLAIN 100000u

static uint8_t plain[4][LZ_PLAIN];
static struct dc_plain plains1[24], plains2[24];
static size_t n_p1, n_p2;
static uint8_t refbuf[(1u << 20) + 16u];

static void make_plain(void)
{
	uint64_t rs = 0xabcdef12u;
	size_t i;

	for (i = 0; i < LZ_PLAIN; i++) {
		plain[0][i] = (uint8_t)(size_t)"pack my box with five dozen liquor jugs. "[i % 41];
		plain[1][i] = 0x5a;
		plain[2][i] = (uint8_t)(fz_rng_star(&rs) >> 44);
		plain[3][i] = (uint8_t)((i % 7u) * 31u + (i / 1000u));
	}
}

static int lz1_pack(const lzma_options_lzma *o, const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *got)
{
	lzma_filter f[2];

	f[0].id = LZMA_FILTER_LZMA1;
	f[0].options = (void *)(uintptr_t)o;
	f[1].id = LZMA_VLI_UNKNOWN;
	f[1].options = NULL;
	*got = 0;
	return lzma_raw_buffer_encode(f, NULL, in, n, out, got, cap) == LZMA_OK;
}

static void add1(struct fz_corpus *c, const char *name, unsigned lc, unsigned lp, unsigned pb, int preset, const uint8_t *src, size_t n)
{
	static uint8_t z[LZ_PLAIN * 2u];
	lzma_options_lzma o;
	size_t zn;

	if (lzma_lzma_preset(&o, (uint32_t)preset))
		return;
	o.lc = lc;
	o.lp = lp;
	o.pb = pb;
	o.dict_size = 1u << 20;
	z[0] = (uint8_t)((pb * 5u + lp) * 9u + lc);
	if (!lz1_pack(&o, src, n, z + 1, sizeof z - 1u, &zn) || n_p1 >= 24)
		return;
	plains1[n_p1].p = src;
	plains1[n_p1].n = n;
	n_p1++;
	fz_corpus_add(c, name, z, zn + 1u);
}

static void seeds1(struct fz_corpus *c)
{
	make_plain();
	n_p1 = 0;
	add1(c, "text-3-0-2", 3, 0, 2, 6, plain[0], 20000);
	add1(c, "run-3-0-2", 3, 0, 2, 1, plain[1], 50000);
	add1(c, "noise-0-2-0", 0, 2, 0, 3, plain[2], 6000);
	add1(c, "text-4-0-4", 4, 0, 4, 6, plain[0], 3000);
	add1(c, "periodic-1-3-1", 1, 3, 1, 9, plain[3], 20000);
	add1(c, "short", 3, 0, 2, 6, plain[0], 7);
	add1(c, "empty", 3, 0, 2, 6, plain[0], 0);
}

static const char *const dict1[] = { "\x5d", "\x00\x00\x10\x00", "\x00\x00\x00\x00", "\xff\xff\xff\xff", NULL };

/* The decoder under the shape of dc_buf_fn: byte 0 is the properties. */
static enum kuncoat_status lz1_fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	unsigned p = n ? in[0] : 0u, lc, lp, pb;

	(void)par;
	lc = p % 9u;
	p /= 9u;
	lp = p % 5u;
	pb = p / 5u;
	return kuncoat_lzma_decode(lc, lp, pb, n ? in + 1 : in, n ? n - 1u : 0u, out, cap, produced);
}

/* liblzma over the same input. 1: decoded to its end into ref; 0: refused or cut; -1: no reference for these parameters. */
static int ref1(const uint8_t *in, size_t n, size_t *got)
{
	unsigned p = n ? in[0] : 0u, lc = p % 9u, lp, pb;
	lzma_options_lzma o;
	lzma_filter f[2];
	size_t ip = 0;
	lzma_ret r;

	p /= 9u;
	lp = p % 5u;
	pb = p / 5u;
	if (!n || lc + lp > LZMA_LCLP_MAX || pb > LZMA_PB_MAX)
		return -1;
	if (lzma_lzma_preset(&o, 0))
		return -1;
	o.lc = lc;
	o.lp = lp;
	o.pb = pb;
	o.dict_size = 1u << 20;
	f[0].id = LZMA_FILTER_LZMA1;
	f[0].options = &o;
	f[1].id = LZMA_VLI_UNKNOWN;
	f[1].options = NULL;
	*got = 0;
	r = lzma_raw_buffer_decode(f, NULL, in + 1, &ip, n - 1u, refbuf, got, sizeof refbuf - 8u);
	return r == LZMA_OK;
}

static const struct dc_buf dcb1 = { lz1_fn, NULL, DC_EXACT_MAY_STOP, plains1, 24 };

static int run1(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced = 0;
	enum kuncoat_status r = dc_buf_run(c, &dcb1, in, n, &produced);
	size_t got = 0;
	int ok = ref1(in, n, &got);

	if (ok >= 0)
		dc_cmp_ref(c, "lzma", r, produced, refbuf, got, ok);
	return (int)r;
}

FZ_ADAPTER(lzma, .name = "kuncoat/lzma", .covers = "kuncoat_lzma_decode", .shape = FZ_BYTES, .seeds = seeds1, .dict = dict1, .run = run1,
	   .flags = FZ_MAY_HIT_CAP, .steps_base = 2000000u);

/* ---- LZMA2 -------------------------------------------------------------------------------------- */

static int lz2_pack(int preset, const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *got)
{
	lzma_options_lzma o;
	lzma_filter f[2];

	if (lzma_lzma_preset(&o, (uint32_t)preset))
		return 0;
	o.dict_size = 1u << 20;
	f[0].id = LZMA_FILTER_LZMA2;
	f[0].options = &o;
	f[1].id = LZMA_VLI_UNKNOWN;
	f[1].options = NULL;
	*got = 0;
	return lzma_raw_buffer_encode(f, NULL, in, n, out, got, cap) == LZMA_OK;
}

static void add2(struct fz_corpus *c, const char *name, int preset, const uint8_t *src, size_t n)
{
	static uint8_t z[LZ_PLAIN * 2u];
	size_t zn;

	if (!lz2_pack(preset, src, n, z, sizeof z, &zn) || n_p2 >= 24)
		return;
	plains2[n_p2].p = src;
	plains2[n_p2].n = n;
	n_p2++;
	fz_corpus_add(c, name, z, zn);
}

static void seeds2(struct fz_corpus *c)
{
	make_plain();
	n_p2 = 0;
	add2(c, "text-6", 6, plain[0], 30000);
	add2(c, "noise-70k", 6, plain[2], 70000);          /* stored chunks of 64 KiB and a tail */
	add2(c, "run-0", 0, plain[1], 100000);
	add2(c, "periodic-3", 3, plain[3], 40000);
	add2(c, "short", 6, plain[0], 5);
	add2(c, "empty", 6, plain[0], 0);
}

static const char *const dict2[] = { "\x01\x00\x00", "\x02\x00\x00", "\xe0", "\xa0", "\xc0", "\x80", "\x00", NULL };

static enum kuncoat_status lz2_fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	(void)par;
	return kuncoat_lzma2_decode(in, n, out, cap, produced);
}

static int ref2(const uint8_t *in, size_t n, size_t *got)
{
	lzma_options_lzma o;
	lzma_filter f[2];
	size_t ip = 0;

	if (lzma_lzma_preset(&o, 0))
		return -1;
	o.dict_size = 1u << 20;
	f[0].id = LZMA_FILTER_LZMA2;
	f[0].options = &o;
	f[1].id = LZMA_VLI_UNKNOWN;
	f[1].options = NULL;
	*got = 0;
	return lzma_raw_buffer_decode(f, NULL, in, &ip, n, refbuf, got, sizeof refbuf - 8u) == LZMA_OK;
}

static const struct dc_buf dcb2 = { lz2_fn, NULL, DC_CAP_OK_MAY, plains2, 24 };

static int run2(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced = 0;
	enum kuncoat_status r = dc_buf_run(c, &dcb2, in, n, &produced);
	size_t got = 0;
	int ok = ref2(in, n, &got);

	if (ok >= 0)
		dc_cmp_ref(c, "lzma2", r, produced, refbuf, got, ok);
	return (int)r;
}

FZ_ADAPTER(lzma2, .name = "kuncoat/lzma2", .covers = "kuncoat_lzma2_decode", .shape = FZ_BYTES, .seeds = seeds2, .dict = dict2, .run = run2,
	   .flags = FZ_MAY_HIT_CAP, .steps_base = 2000000u);
