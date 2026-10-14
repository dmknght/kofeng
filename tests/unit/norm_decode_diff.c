/*
 * norm_decode_diff - the normaliser's decode passes (base64, hex, percent) give the same bytes,
 * the same stretches and the same verdicts after they were made to look for their runs by an
 * anchor instead of walking every run.
 *
 * WHAT CHANGED. kof_exe_pass_pct walked every maximal run of its alphabet to learn that most
 * held no '%'; it now finds each '%' with memchr and judges the run round it by the unchanged
 * test. kof_exe_pass_hex probes every eighth byte for a hex digit; a hit now needs a neighbour
 * half a stride away before the run is walked. Both are exact (a run is written only with a '%'
 * in it; a run of eight digits that holds the probe holds one of the two neighbours); this holds
 * them to it.
 *
 * HOW. Every case builds a buffer from an alphabet the passes read (random bytes, hex text
 * quoted and bare, URL text with `%XX`, `%%`, `+`, runs that touch the window's ends, a base64
 * payload piped into `base64 -d`, runs of '%' only, an empty object) and runs, on a copy each:
 * kof_exe_decode_ex (all rounds), each pass alone over a random [from, to) window with the list
 * of stretches it noted, each pass in probe mode (which must write nothing), and
 * kof_exe_decode_would_change. The return values, the bytes, the stretches and the
 * limit/rounds/scanned counters are folded into one hash. EXPECT is the hash the three-pass
 * walk gave BEFORE the change (the unchanged functions, run over the same cases); a different
 * value is a different view. Also checked: a probe never writes, and the same case twice is the
 * same answer.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../libkofeng/analyzers/normalize/executables.h"
#include "../../libkofeng/analyzers/normalize/executables_private.h"

#define EXPECT 0x48611ae7ad865ea2ull

static unsigned s = 0x1357bdf1u;
static unsigned rnd(void) { s = s * 1103515245u + 12345u; return s >> 8; }
static uint64_t fold(uint64_t h, uint64_t v) { return (h ^ v) * 1099511628211ull; }
static int fails;
static unsigned wrote_all, wrote_pass[3], probed_yes;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static const char HEXC[] = "0123456789abcdefABCDEF";
static const char URLC[] = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=";
static const char SEPS[] = " \t\n\r\"'(=,;:>|{[<`\\^";
static const char B64C[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint64_t put(uint8_t *b, uint64_t n, uint64_t at, const char *s2, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len && at + i < n; i++)
		b[at + i] = (uint8_t)s2[i];
	return at + i;
}

/* A hex spelling of `k` printable bytes, or of random bytes (rejected by the text test). */
static uint64_t hexrun(uint8_t *b, uint64_t n, uint64_t at, unsigned k, int text)
{
	unsigned i;

	for (i = 0; i < k && at + 1u < n; i++) {
		unsigned v = text ? 0x20u + rnd() % 0x5fu : rnd() & 0xffu;
		const char *d = "0123456789abcdef";

		b[at++] = (uint8_t)(rnd() & 1u ? d[v >> 4] : "0123456789ABCDEF"[v >> 4]);
		b[at++] = (uint8_t)d[v & 15u];
	}
	return at;
}

static void build(uint8_t *b, uint64_t n, unsigned family)
{
	uint64_t i = 0;
	unsigned k;

	switch (family) {
	case 0:                 /* plain random */
		for (i = 0; i < n; i++)
			b[i] = (uint8_t)rnd();
		return;
	case 1:                 /* sparse hex digits in noise */
		for (i = 0; i < n; i++)
			b[i] = rnd() % 5u ? (uint8_t)rnd() : (uint8_t)HEXC[rnd() % 22u];
		return;
	case 2:                 /* hex text, quoted and bare, between separators */
		memset(b, 0, n);
		while (i + 2u < n) {
			unsigned kind = rnd() % 6u;
			unsigned len = 2u + rnd() % 14u;     /* 4..30 digits */

			if (kind < 2u)
				b[i++] = (uint8_t)SEPS[rnd() % (sizeof SEPS - 1u)];
			if (kind == 2u || kind == 3u) {      /* a quoted literal */
				uint8_t q = rnd() & 1u ? '"' : '\'';

				b[i++] = q;
				i = hexrun(b, n, i, len / 2u + 1u, rnd() % 4u != 0u);
				if (i < n)
					b[i++] = rnd() % 9u ? q : (uint8_t)'x';
			} else {
				i = hexrun(b, n, i, len, rnd() % 3u != 0u);
			}
			if (rnd() % 3u == 0u && i < n)
				b[i++] = (uint8_t)HEXC[rnd() % 22u];   /* an odd tail */
			if (rnd() % 4u == 0u)
				i += rnd() % 5u;
		}
		return;
	case 3:                 /* URL text with escapes, doubled percents, noise */
		memset(b, 0, n);
		while (i + 2u < n) {
			unsigned run = 4u + rnd() % 40u, j;

			if (rnd() % 3u == 0u && i < n)
				b[i++] = (uint8_t)SEPS[rnd() % (sizeof SEPS - 1u)];
			for (j = 0; j < run && i + 3u < n; j++) {
				unsigned t = rnd() % 10u;

				if (t < 3u) {
					b[i++] = '%';
					b[i++] = (uint8_t)"234567234567ab"[rnd() % 14u];  /* mostly printable bytes */
					b[i++] = (uint8_t)HEXC[rnd() % 22u];
				} else if (t == 3u && rnd() % 8u == 0u) {
					b[i++] = '%';
					if (rnd() & 1u)
						b[i++] = '%';
				} else if (t == 4u || t == 3u) {
					b[i++] = '+';
				} else {
					b[i++] = (uint8_t)URLC[rnd() % (sizeof URLC - 1u)];
				}
			}
			if (i < n)
				b[i++] = (uint8_t)(rnd() % 3u ? SEPS[rnd() % (sizeof SEPS - 1u)] : (int)(rnd() & 0xffu));
		}
		return;
	case 4:                 /* base64 payloads piped into a decoder, in noise */
		for (i = 0; i < n; i++)
			b[i] = (uint8_t)(rnd() % 3u ? ' ' : rnd());
		i = 0;
		while (i + 40u < n) {
			unsigned len = 8u + rnd() % 60u, j;
			static const char *dec[] = { "base64 -d", "base64 -D", "base64 --decode", "base64 -x", "base64 -di" };

			if (rnd() & 1u)
				b[i++] = '"';
			for (j = 0; j < len && i + 1u < n; j++)
				b[i++] = (uint8_t)B64C[rnd() % 64u];
			if (rnd() % 4u == 0u && i + 4u < n) {
				b[i++] = '%'; b[i++] = '4'; b[i++] = '1'; b[i++] = '4';
			}
			i = put(b, n, i, rnd() % 5u ? " | " : "  ", rnd() % 5u ? 3u : 2u);
			k = rnd() % 5u;
			i = put(b, n, i, dec[k], (uint64_t)strlen(dec[k]));
			i += rnd() % 24u;
		}
		return;
	case 5:                 /* only '%' and neighbours of the alphabets */
		for (i = 0; i < n; i++) {
			unsigned t = rnd() % 8u;

			b[i] = t < 3u ? '%' : t == 3u ? (uint8_t)HEXC[rnd() % 22u] : t == 4u ? (uint8_t)' '
			     : t == 5u ? (uint8_t)URLC[rnd() % (sizeof URLC - 1u)] : (uint8_t)rnd();
		}
		return;
	default:                /* every byte a body byte, one '%' or none */
		for (i = 0; i < n; i++)
			b[i] = (uint8_t)URLC[rnd() % (sizeof URLC - 1u)];
		if (n && family == 6u)
			b[rnd() % n] = '%';
		return;
	}
}

typedef int (*pass_fn)(uint8_t *, uint64_t, uint64_t, uint64_t, struct dec_out *);

static uint64_t fold_out(uint64_t h, const struct dec_out *o)
{
	uint32_t i;

	h = fold(h, o->n);
	h = fold(h, o->limit);
	for (i = 0; i < o->n; i++) {
		h = fold(h, o->v[i].off);
		h = fold(h, o->v[i].len);
	}
	return h;
}

static uint64_t fold_buf(uint64_t h, const uint8_t *b, uint64_t n)
{
	uint64_t i;

	for (i = 0; i < n; i++)
		h = fold(h, b[i]);
	return fold(h, n);
}

static uint64_t one(uint64_t n, unsigned family, uint64_t h)
{
	uint8_t *in = malloc(n + 1u), *a = malloc(n + 1u), *a2 = malloc(n + 1u);
	static const pass_fn pass[3] = { kof_exe_pass_b64, kof_exe_pass_hex, kof_exe_pass_pct };
	struct kof_exe_decode_res r, r2;
	unsigned k, w;
	int c, c2;

	build(in, n, family);

	/* All rounds, twice: the answer is the same and the object is what the passes left. */
	memcpy(a, in, n);
	memcpy(a2, in, n);
	c = kof_exe_decode_ex(a, n, &r);
	c2 = kof_exe_decode_ex(a2, n, &r2);
	CK(c == c2 && r.rounds == r2.rounds && r.scanned == r2.scanned && !memcmp(a, a2, n));
	wrote_all += c != 0;
	h = fold(h, (uint64_t)c);
	h = fold(h, r.limit);
	h = fold(h, r.rounds);
	h = fold(h, r.scanned);
	h = fold(h, r.dropped);
	h = fold_buf(h, a, n);

	/* The answer to "would it change", and the probe wrote nothing. */
	c = kof_exe_decode_would_change(in, n);
	h = fold(h, (uint64_t)c);

	for (k = 0; k < 3u; k++) {
		for (w = 0; w < 6u; w++) {
			uint64_t from = 0, to = n;
			struct dec_out o;
			int ch;

			if (w) {         /* a window: the ends of a stretch the last round noted */
				from = n ? rnd() % (n + 1u) : 0;
				to = from + (n - from ? rnd() % (n - from + 1u) : 0);
				if (w == 5u)
					to = n + rnd() % 3u;     /* past the end: clipped */
			}
			memcpy(a, in, n);
			dec_out_init(&o, n, 1);
			ch = pass[k](a, n, from, to, &o);
			wrote_pass[k] += ch != 0;
			h = fold(h, (uint64_t)ch);
			h = fold_out(h, &o);
			h = fold_buf(h, a, n);
			free(o.v);

			/* The probe: yes exactly where the pass would write, and it writes nothing. */
			memcpy(a, in, n);
			dec_out_init(&o, n, 1);
			o.probe = 1;
			c = pass[k](a, n, from, to, &o);
			CK(!memcmp(a, in, n));
			probed_yes += c != 0;
			h = fold(h, (uint64_t)(c != 0));
			free(o.v);
		}
	}
	free(in);
	free(a);
	free(a2);
	return h;
}

int main(void)
{
	uint64_t h = 1469598103934665603ull;
	unsigned f, i;
	static const uint64_t sizes[] = { 0, 1, 7, 8, 9, 15, 16, 23, 24, 25, 40, 64, 97, 300, 1000, 4096 };

	for (f = 0; f < 7u; f++)
		for (i = 0; i < 16u * 12u; i++) {
			uint64_t n = sizes[i % 16u];

			if (i % 16u == 15u)
				n += rnd() % 4000u;
			h = one(n, f, h);
		}
	/* A big one for each family: runs by the thousand, so the walk is the cost. */
	for (f = 0; f < 7u; f++)
		h = one(120000u + f, f, h);
	printf("norm_decode_diff: hash %016llx  (decode wrote %u, b64 %u hex %u pct %u, probe yes %u)\n",
	       (unsigned long long)h, wrote_all, wrote_pass[0], wrote_pass[1], wrote_pass[2], probed_yes);
	CK(wrote_all > 100 && wrote_pass[0] > 50 && wrote_pass[1] > 50 && wrote_pass[2] > 50);   /* the cases reach every write */
	if (EXPECT)
		CK(h == EXPECT);
	printf("%s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
