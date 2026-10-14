/*
 * cov_aplib_roundtrip - kuncoat_aplib_decode (aplib.h) against an encoder written from the format.
 *
 * aPLib packs a byte string as: the first byte raw, then a stream of tagged items whose tag bits are read a byte at
 * a time from the same stream (the tag byte sits in the stream where the first bit of its group was asked for):
 *
 *   0                        a literal byte
 *   111 + 4 bits             one byte copied from 1..15 back (0 means a zero byte)
 *   110 + byte               a match of 2 or 3 bytes from 1..127 back (offset*2 + length-2); offset 0 ends the stream
 *   10  + gamma + byte + gamma   a long match: the offset's high part (minus 3, or 2 right after a match),
 *                                its low byte, and the length less what the distance adds to it (+2 under 128,
 *                                +1 from 1280, +1 more from 32000); a gamma of 2 with no match just before it
 *                                means "the same distance as the last match" and is followed by the length alone
 *
 * The encoder below uses every one of those forms (greedy matching over a hash of three bytes), and the
 * plaintexts are chosen to make the decoder take each branch: a repeat of the last distance after a literal, a distance
 * under 128, between 128 and 1280, over 1280 and over 32000, one byte copies, runs (distance 1, overlapping copy),
 * zero bytes through the short form, and noise (literals only).
 *
 *   ROUND TRIP   each plaintext, each size
 *   OUTPUT CAP   every cap from 1 to the length: the decoder stops, says so, and what it wrote is the plaintext's prefix
 *   CUTS         every prefix of a stream: TRUNCATED (or the whole), never bytes the plaintext does not hold
 *   FLIPS        a thousand flipped bits: a status, no write past the cap, no more than cap bytes produced
 *   ARGUMENTS    no input, no room, NULL with a length
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <decompressors/aplib.h>

static unsigned fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		if (fails < 30) { \
			printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
		fails++; \
	} \
} while (0)

/* ---- the encoder --------------------------------------------------------------------------- */

struct enc {
	uint8_t *out;
	size_t   n, cap, tagpos;
	unsigned nbits;
	uint8_t  tag;
	int      lwm;                   /* the last item was a match */
	uint32_t r0;
	size_t   used[8];               /* how many of each form were written */
};

static void e_byte(struct enc *e, uint8_t b)
{
	if (e->n < e->cap)
		e->out[e->n] = b;
	e->n++;
}

static void e_bit(struct enc *e, unsigned b)
{
	if (e->nbits == 0) {
		e->tagpos = e->n;
		e_byte(e, 0);
		e->nbits = 8;
		e->tag = 0;
	}
	e->nbits--;
	e->tag = (uint8_t)(e->tag | ((b & 1u) << e->nbits));
	if (e->tagpos < e->cap)
		e->out[e->tagpos] = e->tag;
}

static void e_gamma(struct enc *e, uint32_t v)       /* v >= 2 */
{
	unsigned top = 31u - (unsigned)__builtin_clz(v), k;

	for (k = top; k-- > 0;) {
		e_bit(e, (v >> k) & 1u);
		e_bit(e, k ? 1u : 0u);
	}
}

static void e_lit(struct enc *e, uint8_t b)
{
	e_bit(e, 0);
	e_byte(e, b);
	e->lwm = 0;
	e->used[0]++;
}

static void e_short1(struct enc *e, unsigned dist)   /* 111 + 4 bits: dist 0 is a zero byte */
{
	e_bit(e, 1); e_bit(e, 1); e_bit(e, 1);
	e_bit(e, (dist >> 3) & 1u); e_bit(e, (dist >> 2) & 1u); e_bit(e, (dist >> 1) & 1u); e_bit(e, dist & 1u);
	e->lwm = 0;
	e->used[1]++;
}

static void e_short(struct enc *e, unsigned dist, unsigned len)   /* 110 + byte, dist 1..127, len 2..3 */
{
	e_bit(e, 1); e_bit(e, 1); e_bit(e, 0);
	e_byte(e, (uint8_t)(dist << 1 | (len - 2u)));
	e->lwm = 1;
	e->r0 = dist;
	e->used[2]++;
}

static unsigned adj_of(uint32_t dist)
{
	return (dist >= 32000u ? 1u : 0u) + (dist >= 1280u ? 1u : (dist < 128u ? 2u : 0u));
}

static void e_long(struct enc *e, uint32_t dist, unsigned len)
{
	e_bit(e, 1); e_bit(e, 0);
	if (!e->lwm && dist == e->r0) {
		e_gamma(e, 2);
		e_gamma(e, len);
		e->used[4]++;
	} else {
		e_gamma(e, (dist >> 8) + (e->lwm ? 2u : 3u));
		e_byte(e, (uint8_t)dist);
		e_gamma(e, len - adj_of(dist));
		e->r0 = dist;
		e->used[3]++;
	}
	e->lwm = 1;
}

static void e_end(struct enc *e)
{
	e_bit(e, 1); e_bit(e, 1); e_bit(e, 0);
	e_byte(e, 0);
}

static size_t encode(const uint8_t *p, size_t n, uint8_t *out, size_t cap, size_t *used)
{
	static int32_t head[1 << 16];
	struct enc e;
	size_t i = 1, k;

	memset(&e, 0, sizeof e);
	e.out = out;
	e.cap = cap;
	for (k = 0; k < (1u << 16); k++)
		head[k] = -1;
	if (!n)
		return 0;
	e_byte(&e, p[0]);
	while (i < n) {
		size_t best = 0, bd = 0;
		uint32_t h = 0;

		if (i + 3 <= n) {
			h = ((uint32_t)p[i] * 40503u ^ (uint32_t)p[i + 1] * 9973u ^ (uint32_t)p[i + 2]) & 0xffffu;
			if (head[h] >= 0) {
				size_t j = (size_t)head[h], l = 0;

				while (i + l < n && p[j + l] == p[i + l] && l < 4000)
					l++;
				best = l;
				bd = i - j;
			}
		}
		/* the form that fits */
		if (best >= 2 && bd < 128 && best <= 3 && bd >= 1) {
			e_short(&e, (unsigned)bd, (unsigned)best);
		} else if (best >= 2 + adj_of((uint32_t)bd) && bd >= 1 && bd < (1u << 20)) {
			if (!e.lwm && bd == e.r0 && best >= 2) {
				e_long(&e, (uint32_t)bd, (unsigned)best);          /* the repeated distance */
			} else {
				e_long(&e, (uint32_t)bd, (unsigned)best);
			}
		} else {
			best = 0;
		}
		if (best) {
			size_t q;

			for (q = 0; q < best; q++)
				if (i + q + 3 <= n)
					head[((uint32_t)p[i + q] * 40503u ^ (uint32_t)p[i + q + 1] * 9973u ^ (uint32_t)p[i + q + 2]) & 0xffffu] =
						(int32_t)(i + q);
			i += best;
			continue;
		}
		if (i + 3 <= n)
			head[h] = (int32_t)i;
		/* a single byte: equal to one a few back (or a zero), or a literal */
		{
			unsigned d;
			int done = 0;

			if (p[i] == 0 && (i & 3u) == 0) {
				e_short1(&e, 0);
				done = 1;
			}
			for (d = 1; d <= 15 && !done && (i & 1u); d++)
				if (d <= i && p[i - d] == p[i]) {
					e_short1(&e, d);
					done = 1;
				}
			if (!done)
				e_lit(&e, p[i]);
		}
		i++;
	}
	e_end(&e);
	if (used)
		memcpy(used, e.used, sizeof e.used);
	return e.n <= cap ? e.n : 0;
}

/* ---- plaintexts ------------------------------------------------------------------------------ */

static uint64_t rs = 0x853c49e6748fea9bull;

static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 24);
}

enum { T_TEXT, T_NOISE, T_RUN, T_ZEROS, T_FAR, T_REPEATS, T_BYTES, T_COUNT };
static const char *const TN[T_COUNT] = { "text", "noise", "runs", "zero bytes", "far repeats", "repeated distance", "ramp" };

static size_t make(unsigned k, uint8_t *p)
{
	size_t n = 0, i;
	static const char *const w[] = { "alpha", "beta", "gamma", "delta", "match", "offset", "length", "tag", "gamma-coded" };

	switch (k) {
	case T_TEXT:
		while (n < 6000) {
			const char *s = w[rnd() % 9u];

			memcpy(p + n, s, strlen(s));
			n += strlen(s);
			p[n++] = ' ';
		}
		break;
	case T_NOISE:
		for (; n < 3000; n++)
			p[n] = (uint8_t)rnd();
		break;
	case T_RUN:
		for (i = 0; i < 12; i++) {
			size_t len = 5u + (rnd() % 300u);

			memset(p + n, (int)('a' + i), len);
			n += len;
		}
		for (i = 0; i < 20; i++)
			p[n++] = (uint8_t)('A' + i);
		memset(p + n, 'z', 700);
		n += 700;
		break;
	case T_ZEROS:
		for (; n < 2000; n++)
			p[n] = (n % 16u < 12u) ? 0 : (uint8_t)rnd();
		break;
	case T_FAR:
		/* 40 KB of noise with the first block repeated at 33000 (over the 32000 line) and at 2000 (over 1280) */
		for (; n < 40000; n++)
			p[n] = (uint8_t)rnd();
		memcpy(p + 33000, p + 100, 300);
		memcpy(p + 2000 + 300, p + 100, 200);
		break;
	case T_REPEATS:
		/* match at distance D, a literal, the same distance again: the repeat form */
		for (i = 0; i < 30; i++) {
			size_t j;

			for (j = 0; j < 40; j++)
				p[n++] = (uint8_t)('a' + (rnd() % 26u));
			memcpy(p + n, p + n - 40, 12);
			n += 12;
			p[n++] = (uint8_t)rnd();
			memcpy(p + n, p + n - 53, 12);
			n += 12;
		}
		break;
	default:
		for (; n < 1500; n++)
			p[n] = (uint8_t)(n / 6u);
		break;
	}
	return n;
}

/* ---- the checks ------------------------------------------------------------------------------- */

static uint8_t plain[1 << 16], coded[1 << 17], back[1 << 16];

static void t_roundtrip(void)
{
	unsigned k;
	size_t forms[8] = { 0 };

	for (k = 0; k < T_COUNT; k++) {
		size_t n = make(k, plain), m, used[8] = { 0 }, f;
		uint64_t prod = 0;
		enum kuncoat_status st;

		m = encode(plain, n, coded, sizeof coded, used);
		CK(m > 0, "%s: the encoder wrote a stream", TN[k]);
		if (!m)
			continue;
		for (f = 0; f < 8; f++)
			forms[f] += used[f];
		memset(back, 0xcd, sizeof back);
		st = kuncoat_aplib_decode(coded, m, back, sizeof back, &prod);
		CK(st == KUNCOAT_OK && prod == n && !memcmp(back, plain, n), "%s: round trip (status %d, %llu of %zu bytes)", TN[k], (int)st,
		   (unsigned long long)prod, n);
		CK(back[n] == 0xcd, "%s: nothing is written past the plaintext", TN[k]);
	}
	CK(forms[0] > 100, "literals were used (%zu)", forms[0]);
	CK(forms[1] > 10, "the one byte form was used (%zu)", forms[1]);
	CK(forms[2] > 10, "the short match was used (%zu)", forms[2]);
	CK(forms[3] > 10, "the long match was used (%zu)", forms[3]);
	CK(forms[4] > 5, "the repeated distance was used (%zu)", forms[4]);
}

static void t_cap_cuts_flips(void)
{
	static const unsigned kinds[] = { T_TEXT, T_RUN, T_REPEATS, T_ZEROS };
	unsigned q;

	for (q = 0; q < sizeof kinds / sizeof kinds[0]; q++) {
		size_t n = make(kinds[q], plain), m, cap, cut;
		uint64_t prod;
		enum kuncoat_status st;
		unsigned bad = 0, fl;
		uint64_t s = 0x99u + q;

		if (n > 700)
			n = 700;
		m = encode(plain, n, coded, sizeof coded, NULL);
		/* every output cap: the plaintext's own prefix, and a status that is not OK until the whole fits */
		for (cap = 1; cap <= n + 1; cap++) {
			prod = 0;
			memset(back, 0xcd, cap + 8);
			st = kuncoat_aplib_decode(coded, m, back, cap, &prod);
			if (prod > cap || (prod && memcmp(back, plain, prod < n ? prod : n)) || back[cap] != 0xcd)
				bad++;
			if (cap < n && st == KUNCOAT_OK)
				bad++;
		}
		CK(bad == 0, "%s: %u of %zu output caps gave the wrong prefix, a write past the cap, or OK for a short buffer", TN[kinds[q]], bad, n + 1);
		/* every cut of the stream */
		bad = 0;
		for (cut = 0; cut <= m; cut++) {
			prod = 0;
			st = kuncoat_aplib_decode(coded, cut, back, sizeof back, &prod);
			if (prod > n || (prod && memcmp(back, plain, prod)))
				bad++;
			if (cut < m && st == KUNCOAT_OK && prod == n)
				bad++;
		}
		CK(bad == 0, "%s: %u of %zu cuts gave bytes the plaintext does not hold, or the whole from a cut stream", TN[kinds[q]], bad, m + 1);
		/* flips */
		bad = 0;
		for (fl = 0; fl < 1000; fl++) {
			static uint8_t bent[1 << 12];
			size_t at;

			s ^= s << 13; s ^= s >> 7; s ^= s << 17;
			memcpy(bent, coded, m);
			at = (size_t)(s % (m * 8u));
			bent[at / 8] ^= (uint8_t)(1u << (at % 8));
			prod = 0;
			memset(back, 0xcd, 4000);
			(void)kuncoat_aplib_decode(bent, m, back, 3000, &prod);
			if (prod > 3000 || back[3000] != 0xcd)
				bad++;
		}
		CK(bad == 0, "%s: %u flipped streams wrote past the cap", TN[kinds[q]], bad);
	}
}

static void t_args(void)
{
	uint64_t prod = 77;
	uint8_t in[4] = { 1, 2, 3, 4 }, out[8];

	CK(kuncoat_aplib_decode(NULL, 4, out, 8, &prod) == KUNCOAT_BAD_ARG && prod == 0, "no input with a length");
	CK(kuncoat_aplib_decode(in, 4, NULL, 8, &prod) == KUNCOAT_BAD_ARG, "no output with room");
	CK(kuncoat_aplib_decode(in, 0, out, 8, &prod) == KUNCOAT_CORRUPT && prod == 0, "an empty input is corrupt");
	CK(kuncoat_aplib_decode(in, 4, out, 0, &prod) == KUNCOAT_CORRUPT, "no room for the first byte");
	CK(kuncoat_aplib_decode(in, 4, out, 8, NULL) != KUNCOAT_BAD_ARG, "the count of bytes is optional");
	/* a match that reaches before the output: refused, and the first byte is what was written */
	{
		uint8_t bad[] = { 'x', 0x80 | 0x40, 0x80, 0x02, 0x00 };   /* 1 1 0 ... distance 2 with one byte written */
		uint8_t o2[16];

		prod = 0;
		(void)kuncoat_aplib_decode(bad, sizeof bad, o2, sizeof o2, &prod);
		CK(prod <= 1, "a distance before the start writes nothing (%llu)", (unsigned long long)prod);
	}
}

int main(void)
{
	t_roundtrip();
	t_cap_cuts_flips();
	t_args();
	if (fails) {
		printf("cov_aplib_roundtrip: FAILED (%u)\n", fails);
		return 1;
	}
	printf("cov_aplib_roundtrip: ok\n");
	return 0;
}
