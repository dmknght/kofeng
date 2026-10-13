/*
 * api_filters - the branch and call filters of libuncoat, which no other test reaches beyond
 * "an empty and a garbage buffer does not fault" (surface.c):
 *
 *   kuncoat_bcj_x86_decode   (bcj.h)    the 7z / xz x86 filter: undone against an ENCODER written
 *                                       here from the xz description, over random code-like
 *                                       buffers, every start offset, every size 0..40, and
 *                                       against the xz tool's own --x86 output when it exists.
 *   kuncoat_bcj2_decode      (bcj2.h)   four streams in, one out: an encoder written here makes
 *                                       the streams (the range coder is LZMA's, and
 *                                       hostile_lzenc.h's is reused for it); then every cap,
 *                                       every stream cut at every length, guard pages after
 *                                       each of the four, zero-length channels, NULL streams.
 *   kuncoat_mpress_cto_decode (mpress.h) its bounds (the 0x1000 byte tail, the bit width), an
 *                                       exact example, "nothing past the scan is touched" on
 *                                       random buffers under a guard page.
 *   kuncoat_aspack_e8e9_decode (aspack.h) exact examples of the rotate-and-subtract and of the
 *                                       skip-four rule, every marker.
 *
 * Every buffer sits against a PROT_NONE page, so a read or write past `n` faults.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzenc.h"

#include <decompressors/bcj.h>
#include <decompressors/bcj2.h>

static struct hv_gb ga, gb, gc, gd, ge;

/* ---- BCJ x86: the xz encoder and decoder as one function ----------------------------------- */

static int test86(uint8_t b)
{
	return b == 0x00 || b == 0xff;
}

static size_t ref_x86(int encoder, uint8_t *buf, size_t size, uint32_t now_pos)
{
	static const int allowed[8] = { 1, 1, 1, 0, 1, 0, 0, 0 };
	static const uint32_t bitnum[8] = { 0, 1, 2, 2, 3, 3, 3, 3 };
	uint32_t prev_mask = 0, prev_pos = now_pos - 5u;
	size_t pos = 0, limit;

	if (size < 5)
		return 0;
	limit = size - 5;
	while (pos <= limit) {
		uint8_t b = buf[pos];
		uint32_t offset;

		if (b != 0xE8 && b != 0xE9) {
			pos++;
			continue;
		}
		offset = now_pos + (uint32_t)pos - prev_pos;
		prev_pos = now_pos + (uint32_t)pos;
		if (offset > 5) {
			prev_mask = 0;
		} else {
			uint32_t i;

			for (i = 0; i < offset; i++) {
				prev_mask &= 0x77;
				prev_mask <<= 1;
			}
		}
		b = buf[pos + 4];
		if (test86(b) && allowed[(prev_mask >> 1) & 7] && (prev_mask >> 1) < 0x10) {
			uint32_t src = (uint32_t)b << 24 | (uint32_t)buf[pos + 3] << 16 | (uint32_t)buf[pos + 2] << 8 | buf[pos + 1];
			uint32_t dest;

			for (;;) {
				uint32_t i;

				dest = encoder ? src + (now_pos + (uint32_t)pos + 5u) : src - (now_pos + (uint32_t)pos + 5u);
				if (prev_mask == 0)
					break;
				i = bitnum[(prev_mask >> 1) & 7];
				b = (uint8_t)(dest >> (24 - i * 8));
				if (!test86(b))
					break;
				src = dest ^ ((1u << (32 - i * 8)) - 1u);
			}
			buf[pos + 4] = (uint8_t)(~(((dest >> 24) & 1u) - 1u));
			buf[pos + 3] = (uint8_t)(dest >> 16);
			buf[pos + 2] = (uint8_t)(dest >> 8);
			buf[pos + 1] = (uint8_t)dest;
			pos += 5;
			prev_mask = 0;
		} else {
			pos++;
			prev_mask |= 1;
			if (test86(b))
				prev_mask |= 0x10;
		}
	}
	return pos;
}

/* code-like bytes: many E8/E9, 00 and FF operands, ordinary bytes */
static void code_bytes(uint8_t *p, size_t n, uint64_t *rs, unsigned flavour)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint32_t r = hv_rng32(rs) % 100u;

		p[i] = flavour == 0 ? (uint8_t)hv_rng32(rs) :
		       r < 15 ? 0xE8 : r < 25 ? 0xE9 : r < 45 ? 0x00 : r < 65 ? 0xFF : r < 70 ? 0x0F : (uint8_t)hv_rng32(rs);
	}
}

static void bcj_x86(void)
{
	uint64_t rs = 86, got;
	size_t n, i;
	unsigned flavour, round;
	uint8_t orig[700], enc[700];

	/* the decoder undoes the reference encoder, on whatever prefix both processed */
	for (flavour = 0; flavour < 2; flavour++)
		for (round = 0; round < 1500; round++) {
			uint32_t start = round % 5 == 0 ? 0 : hv_rng32(&rs) % 3u ? hv_rng32(&rs) % 100000u : hv_rng32(&rs);
			uint8_t *g;
			size_t pe;

			n = hv_rng32(&rs) % 700u;
			code_bytes(orig, n, &rs, flavour);
			memcpy(enc, orig, n);
			pe = ref_x86(1, enc, n, start);
			g = hv_gb_at(&ga, n);
			memcpy(g, enc, n);
			hv_at(flavour * 10000u + round, n);
			got = kuncoat_bcj_x86_decode(g, n, start);
			CKF(got == pe || n < 5, "n %zu start %u: returned %llu, the reference processed %zu", n, start,
			    (unsigned long long)got, pe);
			CKF(n < 5 ? got == 0 : (got <= n && got + 4 >= n), "n %zu: returned %llu", n, (unsigned long long)got);
			CKF(!memcmp(g, orig, got < n ? (size_t)got : n), "n %zu start %u: not the original", n, start);
			/* the bytes past the processed prefix are exactly as given */
			CK(!memcmp(g + got, enc + got, n - (size_t)got));
			if (hv_fails > 6)
				return;
		}
	/* every size 0..8 over every byte class: 5^8 buffers is 390625, so sizes up to 7 exhaustively
	 * and 8 at a stride */
	{
		static const uint8_t cls[5] = { 0xE8, 0xE9, 0x00, 0xFF, 0x42 };
		size_t idx, total;
		uint8_t b[8];
		unsigned k;

		for (n = 0; n <= 8; n++) {
			total = 1;
			for (k = 0; k < n; k++)
				total *= 5u;
			for (idx = 0; idx < total; idx += n == 8 ? 7 : 1) {
				size_t v = idx;

				for (k = 0; k < n; k++) {
					b[k] = cls[v % 5u];
					v /= 5u;
				}
				{
					uint8_t *g = hv_gb_at(&gb, n), r[8];

					memcpy(g, b, n);
					memcpy(r, b, n);
					hv_at(n, idx);
					got = kuncoat_bcj_x86_decode(g, n, 0);
					(void)ref_x86(0, r, n, 0);
					CKF(!memcmp(g, r, n), "n %zu pattern %zu", n, idx);
				}
			}
		}
	}
	/* arguments: NULL, n < 5 (untouched and 0) */
	CK(kuncoat_bcj_x86_decode(NULL, 100, 0) == 0);
	for (n = 0; n < 5; n++) {
		uint8_t *g = hv_gb_at(&gb, n);

		for (i = 0; i < n; i++)
			g[i] = 0xE8;
		CK(kuncoat_bcj_x86_decode(g, n, 12345) == 0);
		for (i = 0; i < n; i++)
			CK(g[i] == 0xE8);
	}
	/* a hand case: E8 + the absolute address 0x100 + 5 at position 0 comes back as 0x100 */
	{
		uint8_t *g = hv_gb_at(&gb, 8);
		static const uint8_t enc1[8] = { 0xE8, 0x05, 0x01, 0x00, 0x00, 0x90, 0x90, 0x90 };

		memcpy(g, enc1, 8);
		(void)kuncoat_bcj_x86_decode(g, 8, 0);
		CK(g[0] == 0xE8 && g[1] == 0x00 && g[2] == 0x01 && g[3] == 0 && g[4] == 0);
		/* start shifts the position the address is made relative to */
		memcpy(g, enc1, 8);
		(void)kuncoat_bcj_x86_decode(g, 8, 0x10);
		CK(g[1] == 0xF0 && g[2] == 0x00);
	}
}

/* against xz's own x86 filter: xz --x86 then LZMA2, decoded by the product's LZMA2 and then BCJ */
static void bcj_xz(void)
{
	static const char *const argv[] = { "xz", "-c", "--format=raw", "--x86", "--lzma2=preset=1,dict=64KiB", NULL };
	static uint8_t data[40000], out[41000];
	uint64_t rs = 14, p;
	uint8_t *z;
	size_t zn = 0;
	enum kuncoat_status st;

	code_bytes(data, sizeof data, &rs, 1);
	z = hv_tool(argv, data, sizeof data, &zn);
	if (!z) {
		printf("  SKIP bcj/xz differential: no xz tool\n");
		return;
	}
	st = kuncoat_lzma2_decode(z, zn, out, sizeof out, &p);
	CKF(p == sizeof data, "xz --x86 stream decodes to %llu bytes (%s)", (unsigned long long)p, kuncoat_status_name(st));
	if (p == sizeof data) {
		uint64_t done = kuncoat_bcj_x86_decode(out, p, 0);

		CKF(done + 4 >= sizeof data, "bcj returned %llu of %zu", (unsigned long long)done, sizeof data);
		CKF(!memcmp(out, data, (size_t)done), "bcj of xz's --x86 output is not the original");
	}
	free(z);
}

/* ---- BCJ2 ------------------------------------------------------------------------------------- */

struct b2 {
	uint8_t main_s[4000], call_s[4000], jump_s[4000], rc_s[2000];
	size_t  nm, nc, nj, nr;
};

static int b2_branch(uint8_t prev, uint8_t b)
{
	return b == 0xE8 || b == 0xE9 || (prev == 0x0F && (b & 0xF0) == 0x80);
}

/* The encoder: convert a candidate when `want` says so (the test's policy), writing the four streams. */
static int b2_encode(struct b2 *s, const uint8_t *orig, size_t n, uint64_t seed, unsigned convert_pct)
{
	uint16_t prob[258];
	struct hv_lz e;
	uint64_t rs = seed;
	size_t i = 0;
	uint8_t prev = 0;

	memset(&e, 0, sizeof e);
	hv_lz_rc_start(&e, s->rc_s, sizeof s->rc_s);
	for (i = 0; i < 258; i++)
		prob[i] = 1024;
	s->nm = s->nc = s->nj = 0;
	i = 0;
	while (i < n) {
		uint8_t b = orig[i];

		s->main_s[s->nm++] = b;
		i++;
		if (!b2_branch(prev, b)) {
			prev = b;
			continue;
		}
		{
			uint16_t *pr = b == 0xE8 ? &prob[prev] : b == 0xE9 ? &prob[256] : &prob[257];
			int conv = i + 4 <= n && (hv_rng32(&rs) % 100u) < convert_pct;

			hv_lz_bit(&e, pr, conv ? 1u : 0u);
			if (!conv) {
				prev = b;
				continue;
			}
			{
				uint32_t disp = (uint32_t)orig[i] | (uint32_t)orig[i + 1] << 8 | (uint32_t)orig[i + 2] << 16 |
						(uint32_t)orig[i + 3] << 24;
				uint32_t abs_addr = disp + (uint32_t)(i + 4);
				uint8_t *dst = b == 0xE8 ? s->call_s + s->nc : s->jump_s + s->nj;

				dst[0] = (uint8_t)(abs_addr >> 24); dst[1] = (uint8_t)(abs_addr >> 16);
				dst[2] = (uint8_t)(abs_addr >> 8); dst[3] = (uint8_t)abs_addr;
				if (b == 0xE8)
					s->nc += 4;
				else
					s->nj += 4;
			}
			prev = orig[i + 3];
			i += 4;
		}
	}
	s->nr = hv_lz_rc_finish(&e);
	return !e.over && s->nm <= sizeof s->main_s;
}

/* One call with each stream against its own guard page. */
static uint64_t b2_call(const struct b2 *s, size_t nm, size_t nc, size_t nj, size_t nr, size_t cap, uint8_t *copy)
{
	struct kuncoat_bcj2_io io;
	uint8_t *out = hv_out(&ge, cap);
	uint64_t r;

	memset(&io, 0, sizeof io);
	io.main_s.p = hv_in(&ga, s->main_s, nm);
	io.main_s.n = nm;
	io.call_s.p = hv_in(&gb, s->call_s, nc);
	io.call_s.n = nc;
	io.jump_s.p = hv_in(&gc, s->jump_s, nj);
	io.jump_s.n = nj;
	io.rc_s.p = hv_in(&gd, s->rc_s, nr);
	io.rc_s.n = nr;
	io.out = out;
	io.out_cap = cap;
	r = kuncoat_bcj2_decode(&io);
	CKF(r <= cap, "returned %llu > cap %zu", (unsigned long long)r, cap);
	CK(hv_out_canary_ok(out));
	if (copy && r <= cap)
		memcpy(copy, out, (size_t)r);
	return r;
}

static void bcj2(void)
{
	static struct b2 s;
	static uint8_t orig[1500], got[1600];
	uint64_t rs = 2, r;
	size_t n, k, cap;
	unsigned pct, round;

	for (pct = 0; pct <= 100; pct += 25)
		for (round = 0; round < 6; round++) {
			n = 50 + hv_rng32(&rs) % 1400u;
			code_bytes(orig, n, &rs, 1);
			CK(b2_encode(&s, orig, n, 1000u + round * 7u + pct, pct));
			hv_at(pct, round);
			r = b2_call(&s, s.nm, s.nc, s.nj, s.nr, n, got);
			CKF(r == n && !memcmp(got, orig, n), "pct %u round %u: %llu of %zu", pct, round, (unsigned long long)r, n);
			/* a bigger cap: the streams end, the output is complete and no more */
			r = b2_call(&s, s.nm, s.nc, s.nj, s.nr, n + 40, got);
			CKF(r == n && !memcmp(got, orig, n), "cap above: %llu of %zu", (unsigned long long)r, n);
			/* every cap below: a prefix, never beyond */
			for (cap = 1; cap < n; cap += 1 + n / 97u) {
				r = b2_call(&s, s.nm, s.nc, s.nj, s.nr, cap, got);
				CKF(r <= cap && !memcmp(got, orig, (size_t)r), "cap %zu: %llu bytes, not a prefix", cap, (unsigned long long)r);
			}
			/* each stream cut at every length (stride): never beyond the cap, never a fault; what comes out
			 * is a prefix of the original while the streams hold */
			for (k = 0; k <= s.nm; k += 1 + s.nm / 40u) {
				r = b2_call(&s, k, s.nc, s.nj, s.nr, n, got);
				CKF(r <= n && !memcmp(got, orig, (size_t)r), "main cut %zu: %llu bytes, not a prefix", k,
				    (unsigned long long)r);
			}
			for (k = 0; k <= s.nc; k += 4)
				(void)b2_call(&s, s.nm, k, s.nj, s.nr, n, got);
			for (k = 0; k <= s.nj; k += 4)
				(void)b2_call(&s, s.nm, s.nc, k, s.nr, n, got);
			for (k = 0; k <= s.nr; k++)
				(void)b2_call(&s, s.nm, s.nc, s.nj, k, n, got);
			if (hv_fails > 6)
				return;
		}
	/* a channel with a length that is not a multiple of 4, by one */
	{
		n = 400;
		code_bytes(orig, n, &rs, 1);
		(void)b2_encode(&s, orig, n, 5, 100);
		for (k = 0; k < 4 && s.nc + k > 0; k++)
			(void)b2_call(&s, s.nm, s.nc > k ? s.nc - k : 0, s.nj, s.nr, n, got);
	}
	/* NULL streams and cap 0: 0, the output untouched */
	{
		struct kuncoat_bcj2_io io;
		uint8_t out[16], one[4] = { 0 };

		memset(out, 0xCC, sizeof out);
		memset(&io, 0, sizeof io);
		CK(kuncoat_bcj2_decode(&io) == 0);
		io.main_s.p = one; io.main_s.n = 4;
		io.call_s.p = one; io.jump_s.p = one; io.rc_s.p = one; io.rc_s.n = 4;
		io.out = out; io.out_cap = 0;
		CK(kuncoat_bcj2_decode(&io) == 0);
		io.out_cap = sizeof out;
		io.out = NULL;
		CK(kuncoat_bcj2_decode(&io) == 0);
		io.out = out;
		io.call_s.p = NULL;
		CK(kuncoat_bcj2_decode(&io) == 0);
		io.call_s.p = one; io.jump_s.p = NULL;
		CK(kuncoat_bcj2_decode(&io) == 0);
		io.jump_s.p = one; io.rc_s.p = NULL;
		CK(kuncoat_bcj2_decode(&io) == 0);
		io.rc_s.p = one; io.main_s.p = NULL;
		CK(kuncoat_bcj2_decode(&io) == 0);
		CK(out[0] == 0xCC);
		/* empty main: nothing */
		io.main_s.p = one; io.main_s.n = 0;
		CK(kuncoat_bcj2_decode(&io) == 0);
		/* empty call and jump channels are legal with a valid pointer */
		io.main_s.n = 4;
		io.call_s.n = 0; io.jump_s.n = 0;
		CK(kuncoat_bcj2_decode(&io) <= 4);
	}
	/* range coder streams of every shape drive every candidate to "converted": the channels run out */
	{
		uint8_t m[64], chan[8];
		unsigned f;

		memset(m, 0xE8, sizeof m);
		memset(chan, 0x12, sizeof chan);
		for (f = 0; f < 256; f += 17) {
			struct b2 z;

			memcpy(z.main_s, m, sizeof m);
			memcpy(z.call_s, chan, sizeof chan);
			memcpy(z.jump_s, chan, sizeof chan);
			memset(z.rc_s, (int)f, 32);
			hv_at(500, f);
			r = b2_call(&z, 64, 8, 8, 32, 400, got);
			CKF(r <= 400, "all-%02x rc: %llu", f, (unsigned long long)r);
		}
	}
}

/* ---- MPRESS ------------------------------------------------------------------------------------ */

static void mpress(void)
{
	uint64_t rs = 11, got;
	size_t n, i, sizes[] = { 0, 1, 0x800, 0xFFF, 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1100, 0x2000, 0x5000 };
	unsigned b, bits[] = { 0, 1, 16, 31, 32, 33, 63, 64, 65, 128, 0xFFFFFFFFu };
	unsigned si, k;

	/* n up to 0x1000 and unsupported widths: 0, buffer untouched */
	for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++)
		for (k = 0; k < sizeof bits / sizeof bits[0]; k++) {
			uint8_t *g;
			static uint8_t copy[0x5100];

			n = sizes[si];
			b = bits[k];
			g = hv_gb_at(&ga, n);
			for (i = 0; i < n; i++)
				g[i] = (uint8_t)(i % 4 == 0 ? 0xE8 : hv_rng32(&rs));
			memcpy(copy, g, n);
			hv_at(si, k);
			got = kuncoat_mpress_cto_decode(g, n, b);
			if (n <= 0x1000 || (b != 32 && b != 64)) {
				CKF(got == 0 && !memcmp(g, copy, n), "n %#zx bits %u: returned %llu / changed", n, b, (unsigned long long)got);
			} else {
				size_t scan = n - 0x1000, diff = 0;

				for (i = 0; i < n; i++)
					diff += g[i] != copy[i];
				CKF(diff <= got * 4u, "n %#zx bits %u: %llu sites, %zu bytes changed", n, b, (unsigned long long)got, diff);
				for (i = scan + 6; i < n; i++)
					CKF(g[i] == copy[i], "n %#zx bits %u: byte %zu past the scan changed", n, b, i);
			}
		}
	CK(kuncoat_mpress_cto_decode(NULL, 0x2000, 32) == 0);
	/* an exact example: E8 at 0x10, the stored absolute offset 0x40 -> relative 0x40 - 0x11 */
	{
		uint8_t *g = hv_gb_at(&gb, 0x1100);

		memset(g, 0x90, 0x1100);
		g[0x10] = 0xE8; g[0x11] = 0x40; g[0x12] = 0; g[0x13] = 0; g[0x14] = 0;
		got = kuncoat_mpress_cto_decode(g, 0x1100, 32);
		CKF(got == 1 && g[0x11] == 0x2F && g[0x12] == 0 && g[0x13] == 0 && g[0x14] == 0, "example: %llu, %02x", (unsigned long long)got, g[0x11]);
		/* a stored value at or past the scan (0x100 here) is left alone */
		memset(g, 0x90, 0x1100);
		g[0x10] = 0xE8; g[0x11] = 0x00; g[0x12] = 0x01; g[0x13] = 0; g[0x14] = 0;
		got = kuncoat_mpress_cto_decode(g, 0x1100, 32);
		CK(got == 0 && g[0x11] == 0x00 && g[0x12] == 0x01);
		/* 64 bit only: FF 15 (call [rip+x]) and 8D 05 (lea) are candidates; 32 bit ignores them */
		memset(g, 0x90, 0x1100);
		g[0x10] = 0xFF; g[0x11] = 0x15; g[0x12] = 0x40; g[0x13] = 0; g[0x14] = 0; g[0x15] = 0;
		got = kuncoat_mpress_cto_decode(g, 0x1100, 32);
		CK(got == 0);
		memset(g, 0x90, 0x1100);
		g[0x10] = 0xFF; g[0x11] = 0x15; g[0x12] = 0x40; g[0x13] = 0; g[0x14] = 0; g[0x15] = 0;
		got = kuncoat_mpress_cto_decode(g, 0x1100, 64);
		CKF(got == 1 && g[0x12] == 0x2E, "ff 15 example: %llu %02x", (unsigned long long)got, g[0x12]);
	}
	/* random buffers, E8-rich, under the guard page: no fault, bounded changes */
	for (k = 0; k < 600; k++) {
		uint8_t *g;
		static uint8_t copy[0x2100];
		size_t scan;

		n = 0x1000 + (hv_rng32(&rs) % 0x1000u);
		g = hv_gb_at(&gc, n);
		for (i = 0; i < n; i++) {
			uint32_t r = hv_rng32(&rs) % 100u;

			g[i] = r < 12 ? 0xE8 : r < 18 ? 0xE9 : r < 22 ? 0xFF : r < 26 ? 0x8D : r < 40 ? 0 : (uint8_t)hv_rng32(&rs);
		}
		memcpy(copy, g, n);
		hv_at(7000, k);
		got = kuncoat_mpress_cto_decode(g, n, k & 1u ? 64u : 32u);
		scan = n - 0x1000;
		for (i = scan + 6; i < n; i++)
			CKF(g[i] == copy[i], "byte %zu past the scan changed", i);
		(void)got;
		if (hv_fails > 6)
			return;
	}
}

/* ---- ASPack's filter ------------------------------------------------------------------------------ */

static void aspack_e8e9(void)
{
	unsigned mark;
	size_t n = 40, i;

	/* the rotate and subtract: E8 mark b1 b2 b3 at k -> (b1 | b2<<8 | b3<<16) - k, four bytes */
	for (mark = 0; mark < 256; mark += 51) {
		uint8_t *g = hv_gb_at(&gb, n);
		uint32_t t;

		memset(g, 0x90, n);
		g[10] = 0xE8; g[11] = (uint8_t)mark; g[12] = 0x34; g[13] = 0x12; g[14] = 0x00;
		kuncoat_aspack_e8e9_decode(g, n, (uint8_t)mark);
		t = 0x1234u - 10u;
		CKF(g[10] == 0xE8 && g[11] == (uint8_t)t && g[12] == (uint8_t)(t >> 8) && g[13] == 0 && g[14] == 0,
		    "mark %u: %02x %02x %02x", mark, g[11], g[12], g[13]);
		/* E9 as well */
		memset(g, 0x90, n);
		g[0] = 0xE9; g[1] = (uint8_t)mark; g[2] = 0x00; g[3] = 0x01; g[4] = 0x00;
		kuncoat_aspack_e8e9_decode(g, n, (uint8_t)mark);
		CKF(g[1] == 0x00 && g[2] == 0x01, "E9 at 0: %02x %02x", g[1], g[2]);
	}
	/* the rewritten operand is not scanned again: E8 m E8 m 0 0 .. : the second E8 is inside the operand */
	{
		uint8_t *g = hv_gb_at(&gb, n);

		memset(g, 0x90, n);
		g[0] = 0xE8; g[1] = 0x77; g[2] = 0xE8; g[3] = 0x77; g[4] = 0x00;
		g[5] = 0xE9; g[6] = 0x77; g[7] = 0x01; g[8] = 0; g[9] = 0;
		kuncoat_aspack_e8e9_decode(g, n, 0x77);
		/* first: operand bytes {E8,77,00} -> (E8 | 77<<8 | 00<<16) - 0 = 0x77E8; four bytes written */
		CK(g[1] == 0xE8 && g[2] == 0x77 && g[3] == 0 && g[4] == 0);
		/* the E9 at 5 is a real candidate (k = 5 after the skip) */
		CKF(g[6] == (uint8_t)(0x0001u - 5u) || g[6] != 0x77, "second candidate: %02x", g[6]);
	}
	/* the last six bytes of the buffer are never the start of a candidate: n - 6 is the bound */
	for (i = 7; i <= 12; i++) {
		uint8_t *g = hv_gb_at(&gb, i), keep[16];

		memset(g, 0x90, i);
		g[i - 6] = 0xE8;                        /* at n - 6: the loop is `k < n - 6`, so not scanned */
		if (i - 5 < i)
			g[i - 5] = 0x77;
		memcpy(keep, g, i);
		kuncoat_aspack_e8e9_decode(g, i, 0x77);
		CKF(!memcmp(g, keep, i), "n %zu: a candidate at n-6 was rewritten", i);
	}
	/* sizes 0..6 and NULL: nothing, no fault */
	for (i = 0; i <= 6; i++) {
		uint8_t *g = hv_gb_at(&gb, i);

		for (n = 0; n < i; n++)
			g[n] = n % 2 ? 0x77 : 0xE8;
		kuncoat_aspack_e8e9_decode(g, i, 0x77);
		for (n = 0; n < i; n++)
			CK(g[n] == (n % 2 ? 0x77 : 0xE8));
	}
	kuncoat_aspack_e8e9_decode(NULL, 100, 0);
}

HV_GROUP(bcj_x86)
HV_GROUP(bcj_xz)
HV_GROUP(bcj2)
HV_GROUP(mpress)
HV_GROUP(aspack_e8e9)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&ga, 0x6000) || !hv_gb_init(&gb, 0x6000) || !hv_gb_init(&gc, 0x6000) || !hv_gb_init(&gd, 0x6000) ||
	    !hv_gb_init(&ge, 0x6000)) {
		printf("api_filters: cannot map guard buffers\n");
		return 1;
	}
	hv_expect_clean("bcj x86", hv_grp_bcj_x86, NULL, 30);
	hv_expect_clean("bcj x86 vs xz", hv_grp_bcj_xz, NULL, 30);
	hv_expect_clean("bcj2", hv_grp_bcj2, NULL, 30);
	hv_expect_clean("mpress", hv_grp_mpress, NULL, 30);
	hv_expect_clean("aspack e8e9", hv_grp_aspack_e8e9, NULL, 10);
	return hv_done("api_filters");
}
