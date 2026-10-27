/*
 * decomp_fixtures.h - containers with compressed streams, built in memory for the engine tests of the decompress stage
 * (suite_decomp_objects.c, suite_decomp_faults.c, suite_decomp_bombs.c): a gzip member and a PDF /FlateDecode stream made of
 * stored deflate blocks (no compressor needed), a zlib wrapper, and the bzip2 / xz tools run through pipes (hv_tool; skipped
 * visibly when the tool is missing). The includer has hostile_common.h (then `#undef CK`) and hostile_engine.h first.
 */
#ifndef KOFENG_TESTS_DECOMP_FIXTURES_H
#define KOFENG_TESTS_DECOMP_FIXTURES_H

#include "../lib/uncoat/hostile_enc.h"

#define DFX_MAX (4u << 20)      /* the largest payload a builder here takes */

/* CRC-32 continued over more bytes: start from 0xffffffff, finish with ~. */
static inline uint32_t crc32_update(uint32_t c, const uint8_t *p, size_t n)
{
	static uint32_t t[256];
	size_t i;

	if (!t[1]) {
		uint32_t k, j;

		for (k = 0; k < 256u; k++) {
			uint32_t v = k;

			for (j = 0; j < 8u; j++)
				v = (v & 1u) ? 0xedb88320u ^ (v >> 1) : v >> 1;
			t[k] = v;
		}
	}
	for (i = 0; i < n; i++)
		c = t[(c ^ p[i]) & 0xffu] ^ (c >> 8);
	return c;
}

static inline uint32_t crc32_of(const uint8_t *p, size_t n)
{
	return ~crc32_update(0xffffffffu, p, n);
}

static inline void stored_blocks(struct hv_bw *w, const uint8_t *d, size_t n)
{
	size_t at = 0;

	do {
		size_t blk = n - at > 65535u ? 65535u : n - at;

		hv_defl_stored(w, d + at, blk, at + blk == n);
		at += blk;
	} while (at < n);
	hv_defl_end(w);
}

/* A zlib stream of stored blocks: the header, the blocks, the Adler-32. Returns its length. */
static inline size_t zlib_stored(const uint8_t *d, size_t n, uint8_t *out, size_t cap)
{
	struct hv_bw w;
	uint32_t a = 1, b = 0;
	size_t i, k;

	out[0] = 0x78;
	out[1] = 0x01;
	hv_bw_init(&w, out + 2, cap - 6u);
	stored_blocks(&w, d, n);
	for (i = 0; i < n; i++) {
		a = (a + d[i]) % 65521u;
		b = (b + a) % 65521u;
	}
	k = 2u + w.n;
	out[k++] = (uint8_t)(b >> 8); out[k++] = (uint8_t)b; out[k++] = (uint8_t)(a >> 8); out[k++] = (uint8_t)a;
	return k;
}

static inline void le32(struct he_w *w, uint32_t v)
{
	he_u32(w, v);
}

static inline int b_gzip(struct he_w *w, const uint8_t *d, size_t n)
{
	static uint8_t body[DFX_MAX + 4096];
	struct hv_bw bw;
	static const uint8_t head[10] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 };

	hv_bw_init(&bw, body, sizeof body);
	stored_blocks(&bw, d, n);
	he_put(w, head, sizeof head);
	he_put(w, body, bw.n);
	le32(w, crc32_of(d, n));
	le32(w, (uint32_t)n);
	return 1;
}

static inline int b_pdf(struct he_w *w, const uint8_t *d, size_t n)
{
	static uint8_t body[DFX_MAX + 4096];
	size_t zn = zlib_stored(d, n, body, sizeof body);

	he_str(w, "%PDF-1.4\n1 0 obj\n<< /Length 9999 /Filter /FlateDecode >>\nstream\n");
	he_put(w, body, zn);
	he_str(w, "\nendstream\nendobj\n");
	return 1;
}

static inline int via_tool(struct he_w *w, const char *const *argv, const uint8_t *d, size_t n)
{
	size_t out = 0;
	uint8_t *z = hv_tool(argv, d, n, &out);

	if (!z)
		return 0;
	he_put(w, z, out);
	free(z);
	return 1;
}

static inline int b_bz2(struct he_w *w, const uint8_t *d, size_t n)
{
	static const char *const argv[] = { "bzip2", "-9", "-c", NULL };

	return via_tool(w, argv, d, n);
}

static inline int b_xz(struct he_w *w, const uint8_t *d, size_t n)
{
	static const char *const argv[] = { "xz", "-6", "-c", "--format=xz", NULL };

	return via_tool(w, argv, d, n);
}


/* A gzip member of the densest deflate the format allows: one literal, then `matches` copies of 258 bytes from one byte back. About 170
 * bytes out for each byte in. The payload is 1 + 258 * matches bytes of 'a'. */
static inline int b_gzip_bomb(struct he_w *w, uint32_t matches)
{
	static uint8_t body[1u << 20];
	static const uint8_t head[10] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 };
	uint8_t ll[288], dl[32];
	struct hv_bw bw;
	struct hv_dyn t;
	uint32_t i, crc = 0xffffffffu;
	uint64_t total = 1u + 258ull * matches;

	hv_dyn_std_tables(ll, dl);
	hv_bw_init(&bw, body, sizeof body);
	hv_dyn_begin(&bw, &t, 1, ll, 286, dl, 30, 1);
	hv_dyn_sym(&bw, &t, 'a');
	for (i = 0; i < matches; i++)
		hv_dyn_match(&bw, &t, 258, 1);
	hv_dyn_sym(&bw, &t, 256);
	hv_defl_end(&bw);
	if (bw.over)
		return 0;
	{
		uint8_t run[4096];
		uint64_t left = total;

		memset(run, 'a', sizeof run);
		while (left) {
			size_t c = left > sizeof run ? sizeof run : (size_t)left;

			crc = crc32_update(crc, run, c);
			left -= c;
		}
	}
	he_put(w, head, sizeof head);
	he_put(w, body, bw.n);
	le32(w, ~crc);
	le32(w, (uint32_t)total);
	return 1;
}

#endif /* KOFENG_TESTS_DECOMP_FIXTURES_H */
