/*
 * decomp/filters - the branch and call filters that go with decompression: kuncoat_bcj_x86_decode, kuncoat_bcj2_decode,
 * kuncoat_mpress_cto_decode and kuncoat_aspack_e8e9_decode. They rewrite or rebuild bytes; any byte string is a valid input to
 * all of them, so a mutation never makes a stream "corrupt" and what is held is the contract of the header and a reference.
 *
 * bcj      [start: 4 bytes LE][buffer]  against liblzma's own x86 filter (a stored LZMA2 chunk stream carries the buffer through
 *          {x86, LZMA2}), byte for byte, and the returned count (up to four short of n). A third-party reference, not a restatement.
 * bcj2     [nm u16][nc u16][nj u16][main][call][jump][rc]: the four streams of a BCJ2 block (seeds: the encoder of
 *          hostile_bcjenc.h over code-like bytes). Held: the result is <= the cap, a seed gives its original, and a smaller
 *          cap gives the real beginning of the same bytes.
 * mpress   [bits][buffer]: only 32 and 64 are accepted; a buffer of 0x1000 bytes or fewer is untouched; no byte at or after
 *          scan + 6 (scan = n - 0x1000) is touched; the count of rewritten displacements bounds the changed bytes.
 * e8e9     [mark][buffer]: against a restatement from aspack.h (rotate 24, subtract the position, skip four).
 */
#include <lzma.h>

#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"
#include "../../lib/uncoat/hostile_lzenc.h"
#include "../../lib/uncoat/hostile_bcjenc.h"

/* ---- bcj ---------------------------------------------------------------------------------------- */

static const struct fz_field bcj_fields[] = { { 0, 4, 0, FZ_OFFSET } };
static const struct fz_map bcj_map = { bcj_fields, 1, 0, 0, 0 };

static void bcj_seed(struct fz_corpus *c, const char *name, uint32_t start, size_t n, unsigned flavour, uint64_t seed)
{
	uint8_t b[4 + 3000];
	uint64_t rs = seed;

	if (n > 3000)
		n = 3000;
	b[0] = (uint8_t)start; b[1] = (uint8_t)(start >> 8); b[2] = (uint8_t)(start >> 16); b[3] = (uint8_t)(start >> 24);
	code_bytes(b + 4, n, &rs, flavour);
	fz_corpus_add_map(c, name, b, 4 + n, &bcj_map);
}

static void bcj_seeds(struct fz_corpus *c)
{
	bcj_seed(c, "code-0", 0, 1500, 1, 11);
	bcj_seed(c, "code-start", 0x401000u, 700, 1, 12);
	bcj_seed(c, "code-high-start", 0xfffffff0u, 300, 1, 13);
	bcj_seed(c, "plain", 0, 900, 0, 14);
	bcj_seed(c, "tiny", 5, 5, 1, 15);
	bcj_seed(c, "empty", 0, 0, 1, 16);
}

/* liblzma's answer for the same bytes: a stored LZMA2 stream under {x86 at `start`, LZMA2}. 1 and out[0..n) when it decoded. */
static int bcj_ref(const uint8_t *buf, size_t n, uint32_t start, uint8_t *out)
{
	uint8_t *z = (uint8_t *)malloc(n + n / 60000u * 3u + 16u);
	size_t zn = 0, at = 0, op = 0, ip = 0;
	lzma_options_bcj ob;
	lzma_options_lzma ol;
	lzma_filter f[3];
	int ok;

	if (!z)
		return -1;
	while (at < n) {
		size_t k = n - at > 65536u ? 65536u : n - at;

		z[zn++] = at ? 2u : 1u;
		z[zn++] = (uint8_t)((k - 1u) >> 8);
		z[zn++] = (uint8_t)(k - 1u);
		memcpy(z + zn, buf + at, k);
		zn += k;
		at += k;
	}
	z[zn++] = 0;
	memset(&ob, 0, sizeof ob);
	ob.start_offset = start;
	if (lzma_lzma_preset(&ol, 0)) {
		free(z);
		return -1;
	}
	ol.dict_size = 1u << 16;
	f[0].id = LZMA_FILTER_X86;
	f[0].options = &ob;
	f[1].id = LZMA_FILTER_LZMA2;
	f[1].options = &ol;
	f[2].id = LZMA_VLI_UNKNOWN;
	f[2].options = NULL;
	ok = lzma_raw_buffer_decode(f, NULL, z, &ip, zn, out, &op, n ? n : 1u) == LZMA_OK && op == n;
	free(z);
	return ok;
}

static int bcj_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	size_t bn = n > 4 ? n - 4u : 0;
	uint32_t start = n >= 4 ? (uint32_t)in[0] | (uint32_t)in[1] << 8 | (uint32_t)in[2] << 16 | (uint32_t)in[3] << 24 : 0;
	uint8_t *buf = (uint8_t *)malloc(bn ? bn : 1u), *ref = (uint8_t *)malloc(bn ? bn : 1u);
	uint64_t r;

	if (!buf || !ref) {
		free(buf);
		free(ref);
		return 0;
	}
	if (bn)
		memcpy(buf, in + 4, bn);
	r = kuncoat_bcj_x86_decode(buf, bn, start);
	FZ_CHECK(c, r <= bn, "bcj returned more than the buffer");
	FZ_CHECK(c, bn < 5 ? r == 0 : r + 4u >= bn, "bcj left more than four bytes unprocessed");
	if (r <= bn && bn)
		FZ_CHECK(c, !memcmp(buf + r, in + 4 + r, bn - (size_t)r), "bcj changed bytes past the processed prefix");
	if (!c->failk && bn >= 5 && bcj_ref(in + 4, bn, start, ref) == 1)
		FZ_CHECK(c, !memcmp(buf, ref, bn), "liblzma's x86 filter gives a different result");
	fz_digest(c, r ^ dc_hash(buf, bn) << 5);
	free(buf);
	free(ref);
	return (int)(r != 0);
}

FZ_ADAPTER(bcj, .name = "kuncoat/bcj", .covers = "kuncoat_bcj_x86_decode", .shape = FZ_BYTES, .seeds = bcj_seeds, .run = bcj_run);

/* ---- bcj2 --------------------------------------------------------------------------------------- */

static const struct fz_field b2_fields[] = { { 0, 2, 0, FZ_LEN }, { 2, 2, 0, FZ_LEN }, { 4, 2, 0, FZ_LEN } };
static const struct fz_map b2_map = { b2_fields, 3, 0, 0, 0 };
static struct dc_plain b2_plain[16];
static size_t n_b2;
static uint8_t b2_orig[8][2000];

static void b2_seed(struct fz_corpus *c, const char *name, size_t n, unsigned pct, uint64_t seed)
{
	static struct b2 s;
	static uint8_t pack[8 + 4000 * 3 + 2000];
	uint64_t rs = seed;
	uint8_t *o = b2_orig[n_b2 % 8u];
	size_t at = 6;

	if (n > 2000 || n_b2 >= 16)
		return;
	code_bytes(o, n, &rs, 1);
	if (!b2_encode(&s, o, n, seed + 1000u, pct))
		return;
	pack[0] = (uint8_t)s.nm; pack[1] = (uint8_t)(s.nm >> 8);
	pack[2] = (uint8_t)s.nc; pack[3] = (uint8_t)(s.nc >> 8);
	pack[4] = (uint8_t)s.nj; pack[5] = (uint8_t)(s.nj >> 8);
	memcpy(pack + at, s.main_s, s.nm); at += s.nm;
	memcpy(pack + at, s.call_s, s.nc); at += s.nc;
	memcpy(pack + at, s.jump_s, s.nj); at += s.nj;
	memcpy(pack + at, s.rc_s, s.nr); at += s.nr;
	b2_plain[n_b2].p = o;
	b2_plain[n_b2].n = n;
	n_b2++;
	fz_corpus_add_map(c, name, pack, at, &b2_map);
}

static void b2_seeds(struct fz_corpus *c)
{
	n_b2 = 0;
	b2_seed(c, "all-converted", 900, 100, 21);
	b2_seed(c, "half", 1500, 50, 22);
	b2_seed(c, "none", 400, 0, 23);
	b2_seed(c, "quarter", 2000, 25, 24);
	b2_seed(c, "short", 12, 100, 25);
}

static uint64_t b2_call(const uint8_t *in, size_t n, uint8_t *out, uint64_t cap)
{
	size_t nm = n >= 6 ? (size_t)in[0] | (size_t)in[1] << 8 : 0, nc = n >= 6 ? (size_t)in[2] | (size_t)in[3] << 8 : 0,
	       nj = n >= 6 ? (size_t)in[4] | (size_t)in[5] << 8 : 0, at = n >= 6 ? 6u : n, nr;
	uint8_t *m, *ca, *j, *rc;
	struct kuncoat_bcj2_io io;
	uint64_t r;

	if (nm > n - at) nm = n - at;
	if (nc > n - at - nm) nc = n - at - nm;
	if (nj > n - at - nm - nc) nj = n - at - nm - nc;
	nr = n - at - nm - nc - nj;
	m = (uint8_t *)malloc(nm + 1u); ca = (uint8_t *)malloc(nc + 1u); j = (uint8_t *)malloc(nj + 1u); rc = (uint8_t *)malloc(nr + 1u);
	if (!m || !ca || !j || !rc) {
		free(m); free(ca); free(j); free(rc);
		return 0;
	}
	memcpy(m, in + at, nm);
	memcpy(ca, in + at + nm, nc);
	memcpy(j, in + at + nm + nc, nj);
	memcpy(rc, in + at + nm + nc + nj, nr);
	memset(&io, 0, sizeof io);
	io.main_s.p = m; io.main_s.n = nm;
	io.call_s.p = ca; io.call_s.n = nc;
	io.jump_s.p = j; io.jump_s.n = nj;
	io.rc_s.p = rc; io.rc_s.n = nr;
	io.out = out;
	io.out_cap = cap;
	r = kuncoat_bcj2_decode(&io);
	free(m); free(ca); free(j); free(rc);
	return r;
}

static int b2_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t r = b2_call(in, n, c->out, c->cap), r2;
	uint8_t *o2;

	FZ_CHECK(c, r <= c->cap, "bcj2 returned more than the output capacity");
	if (r > c->cap)
		return 0;
	if (!c->failk && c->iter < n_b2 && b2_plain[c->iter].p) {
		const struct dc_plain *w = &b2_plain[c->iter];

		FZ_CHECK(c, r <= w->n && !memcmp(c->out, w->p, (size_t)(r < w->n ? r : w->n)), "a good BCJ2 block gave bytes that are not its original");
		if (c->cap >= w->n)
			FZ_CHECK(c, r == w->n, "a good BCJ2 block was not decoded whole");
	}
	if (!c->failk && r > 1) {
		uint64_t cap2 = 1u + fz_below(c->rng, r - 1u);

		o2 = (uint8_t *)malloc((size_t)cap2);
		if (o2) {
			r2 = b2_call(in, n, o2, cap2);
			FZ_CHECK(c, r2 <= cap2, "bcj2 returned more than a smaller capacity");
			if (r2 <= cap2)
				FZ_CHECK(c, !memcmp(o2, c->out, (size_t)r2), "a smaller capacity changed the bytes it did produce");
			free(o2);
		}
	}
	fz_digest(c, r ^ dc_hash(c->out, r) << 5);
	return (int)(r != 0);
}

FZ_ADAPTER(bcj2, .name = "kuncoat/bcj2", .covers = "kuncoat_bcj2_decode", .shape = FZ_BYTES, .seeds = b2_seeds, .run = b2_run);

/* ---- mpress ------------------------------------------------------------------------------------- */

static void mp_seed(struct fz_corpus *c, const char *name, unsigned bits, size_t n, uint64_t seed)
{
	uint8_t *b = (uint8_t *)malloc(1u + n);
	uint64_t rs = seed;
	size_t i;

	if (!b)
		return;
	b[0] = (uint8_t)bits;
	code_bytes(b + 1, n, &rs, 1);
	/* displacements the filter would take: absolute offsets below the scan limit after E8/E9 (and the 64-bit forms) */
	for (i = 0; i + 6 < n; i += 29) {
		b[1 + i] = (uint8_t)(i % 4u == 0 ? 0xe8 : i % 4u == 1 ? 0xe9 : i % 4u == 2 ? 0xff : 0x8d);
		b[2 + i] = (uint8_t)(i % 4u == 2 ? 0x15 : i % 4u == 3 ? 0x05 : b[2 + i]);
		{
			size_t o = i % 4u >= 2 ? 3u : 1u;
			uint32_t v = (uint32_t)(i * 7u % (n > 0x1000u ? n - 0x1000u : 1u));

			b[1 + i + o] = (uint8_t)v; b[2 + i + o] = (uint8_t)(v >> 8); b[3 + i + o] = (uint8_t)(v >> 16); b[4 + i + o] = (uint8_t)(v >> 24);
		}
	}
	fz_corpus_add(c, name, b, 1u + n);
	free(b);
}

static void mp_seeds(struct fz_corpus *c)
{
	mp_seed(c, "32-8k", 32, 0x2000, 31);
	mp_seed(c, "64-8k", 64, 0x2000, 32);
	mp_seed(c, "32-just-over", 32, 0x1000 + 6, 33);
	mp_seed(c, "32-tail-only", 32, 0x1000, 34);
	mp_seed(c, "16-8k", 16, 0x2000, 35);
	mp_seed(c, "64-small", 64, 100, 36);
}

static int mp_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	size_t bn = n ? n - 1u : 0, i, changed = 0, scan;
	unsigned bits = n ? in[0] : 0u;
	uint8_t *buf = (uint8_t *)malloc(bn ? bn : 1u);
	uint64_t r;

	if (!buf)
		return 0;
	if (bn)
		memcpy(buf, in + 1, bn);
	r = kuncoat_mpress_cto_decode(buf, bn, bits);
	scan = bn > 0x1000u ? bn - 0x1000u : 0;
	for (i = 0; i < bn; i++)
		changed += buf[i] != in[1 + i];
	if ((bits != 32u && bits != 64u) || bn <= 0x1000u)
		FZ_CHECK(c, r == 0 && !changed, "mpress touched a buffer it must refuse (bits not 32/64, or 0x1000 bytes or fewer)");
	FZ_CHECK(c, changed <= 4u * r, "mpress changed more bytes than 4 for each displacement it counted");
	FZ_CHECK(c, r <= bn / 5u, "mpress counted more displacements than the buffer can hold");
	for (i = scan + 6u; i < bn; i++)
		if (buf[i] != in[1 + i]) {
			FZ_CHECK(c, 0, "mpress wrote at or past scan + 6 (the stub's own bound)");
			break;
		}
	fz_digest(c, r ^ dc_hash(buf, bn) << 5);
	free(buf);
	return (int)(r != 0);
}

FZ_ADAPTER(mpress, .name = "kuncoat/mpress", .covers = "kuncoat_mpress_cto_decode", .shape = FZ_BYTES, .seeds = mp_seeds, .run = mp_run);

/* ---- aspack e8/e9 --------------------------------------------------------------------------------- */

static void e8_ref(uint8_t *b, size_t n, uint8_t mark)
{
	size_t k = 0;

	if (n < 7)
		return;
	while (k < n - 6u) {
		if ((b[k] == 0xe8 || b[k] == 0xe9) && b[k + 1] == mark) {
			uint32_t t = (uint32_t)b[k + 1] | (uint32_t)b[k + 2] << 8 | (uint32_t)b[k + 3] << 16 | (uint32_t)b[k + 4] << 24;

			t &= 0xffffff00u;
			t = (t << 24) | (t >> 8);
			t -= (uint32_t)k;
			b[k + 1] = (uint8_t)t; b[k + 2] = (uint8_t)(t >> 8); b[k + 3] = (uint8_t)(t >> 16); b[k + 4] = (uint8_t)(t >> 24);
			k += 4;
		}
		k++;
	}
}

static void e8_seed(struct fz_corpus *c, const char *name, uint8_t mark, size_t n, uint64_t seed)
{
	uint8_t b[1 + 600];
	uint64_t rs = seed;
	size_t i;

	b[0] = mark;
	code_bytes(b + 1, n, &rs, 1);
	for (i = 0; i + 8 < n; i += 17) {
		b[1 + i] = (uint8_t)(i & 1u ? 0xe8 : 0xe9);
		b[2 + i] = mark;
	}
	fz_corpus_add(c, name, b, 1u + n);
}

static void e8_seeds(struct fz_corpus *c)
{
	e8_seed(c, "mark-77", 0x77, 400, 41);
	e8_seed(c, "mark-00", 0x00, 300, 42);
	e8_seed(c, "mark-e8", 0xe8, 200, 43);
	e8_seed(c, "mark-ff", 0xff, 600, 44);
	e8_seed(c, "six", 0x77, 6, 45);
}

static int e8_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	size_t bn = n ? n - 1u : 0;
	uint8_t *buf = (uint8_t *)malloc(bn ? bn : 1u), *ref = (uint8_t *)malloc(bn ? bn : 1u);

	if (!buf || !ref) {
		free(buf);
		free(ref);
		return 0;
	}
	if (bn) {
		memcpy(buf, in + 1, bn);
		memcpy(ref, in + 1, bn);
	}
	kuncoat_aspack_e8e9_decode(buf, bn, n ? in[0] : 0);
	e8_ref(ref, bn, n ? in[0] : 0);
	FZ_CHECK(c, !bn || !memcmp(buf, ref, bn), "the E8/E9 filter differs from the rotate-subtract-skip-four restatement");
	fz_digest(c, dc_hash(buf, bn));
	free(buf);
	free(ref);
	return 0;
}

FZ_ADAPTER(aspack_e8e9, .name = "kuncoat/aspack_e8e9", .covers = "kuncoat_aspack_e8e9_decode", .shape = FZ_BYTES, .seeds = e8_seeds, .run = e8_run);
