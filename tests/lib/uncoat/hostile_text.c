/*
 * hostile_text - the transport codings and the small dictionary decoders that sit
 * in front of document formats: kuncoat_a85_decode, kuncoat_ahx_decode,
 * kuncoat_rle_decode (textcode.h), kuncoat_lzw_decode (lzw.h), kuncoat_ovba_decode
 * and kuncoat_ovba_plausible (ovba.h).
 *
 * Valid streams come from encoders in hostile_enc.h; the sweeps (every cap, every
 * truncation, every bit flip, guard pages on input and output) run on each, then the
 * crafted cases:
 *
 *   ASCII85   'z' inside a group, a group that overflows 2^32 ("s8W-\"" is one past
 *             the largest), a lone character, characters outside the alphabet,
 *             white space everywhere, "~>" early, the all-zero shortcut with room for
 *             fewer than four bytes.
 *   ASCIIHex  separators (including NUL and FF), '>' early, an odd last digit, a
 *             non-digit, the produced count at CORRUPT.
 *   RunLength 128 early, a literal run cut mid-way, a repeat with no byte, a bomb of
 *             128x ratio against a sink that stops, a sink that refuses.
 *   LZW       a first code that was never built, the self-referential code with no
 *             previous one, EOD first, no EOD, a table that fills and goes on, the
 *             widths 9..12 each reached, CLEAR mid-stream, and a chain of codes that
 *             each name the entry just built (output grows with the square of the
 *             input) met by a sink that stops.
 *   OVBA      a token at the start of a chunk, an offset past what the chunk produced,
 *             a length past 4096, more literals than a chunk holds, a chunk header
 *             that is not 0b011, extents past the input, a stored chunk, no signature.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_sweep.h"

/* ---- adapters ------------------------------------------------------------------------- */

static enum kuncoat_status a85_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	(void)ctx;
	return kuncoat_a85_decode(in, n, out, cap, prod);
}

static enum kuncoat_status ahx_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	(void)ctx;
	return kuncoat_ahx_decode(in, n, out, cap, prod);
}

#define SINK_ADAPTER(NAME, CALL) \
static enum kuncoat_status NAME(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap, \
				uint64_t *prod) \
{ \
	struct hv_bufsink s; \
	uint64_t dp = 0xFEEDull; \
	enum kuncoat_status st; \
	(void)ctx; \
	memset(&s, 0, sizeof s); \
	s.out = out; \
	s.cap = cap; \
	st = CALL; \
	hv_bufsink_check(&s, st, dp, #NAME); \
	*prod = s.total; \
	return st; \
}

SINK_ADAPTER(rle_run, kuncoat_rle_decode(in, n, hv_bufsink_fn, &s, &dp))
SINK_ADAPTER(ovba_run, kuncoat_ovba_decode(in, n, hv_bufsink_fn, &s, &dp))

static struct kuncoat_lzw *g_lzw;

static enum kuncoat_status lzw_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	struct hv_bufsink s;
	uint64_t dp = 0xFEEDull;
	enum kuncoat_status st;

	(void)ctx;
	memset(&s, 0, sizeof s);
	s.out = out;
	s.cap = cap;
	st = kuncoat_lzw_decode(g_lzw, in, n, hv_bufsink_fn, &s, &dp);
	hv_bufsink_check(&s, st, dp, "lzw");
	*prod = s.total;
	return st;
}

/* ---- vectors ----------------------------------------------------------------------------- */

static uint8_t pl_a[301], pl_r[1500], pl_l[14000], pl_o[11000];
static uint8_t e_a85[900], e_a85w[900], e_ahx[700], e_ahxs[1000], e_rle[2000], e_lzw[30000], e_ovba[16000];
static size_t n_a85, n_a85w, n_ahx, n_ahxs, n_rle, n_lzw, n_ovba;

static void build(void)
{
	uint64_t rs = 17;
	size_t i;

	hv_body(pl_a, 300, 41);
	memset(pl_a + 100, 0, 8);                           /* two 'z' groups */
	n_a85 = hv_a85_enc(pl_a, 300, e_a85, sizeof e_a85, 0);
	n_a85w = hv_a85_enc(pl_a, 297, e_a85w, sizeof e_a85w, 20);   /* 297: ends in a partial group */
	n_ahx = hv_ahx_enc(pl_a, 300, e_ahx, sizeof e_ahx, 0);
	n_ahxs = hv_ahx_enc(pl_a, 299, e_ahxs, sizeof e_ahxs, ' ');
	hv_body(pl_r, sizeof pl_r, 42);
	memset(pl_r + 200, 'x', 300);                      /* a long run */
	for (i = 800; i < 1000; i++)
		pl_r[i] = (uint8_t)hv_rng32(&rs);
	n_rle = hv_rle_enc(pl_r, sizeof pl_r, e_rle, sizeof e_rle);
	hv_body(pl_l, sizeof pl_l, 43);
	for (i = 5000; i < 9000; i++)                        /* noise: the table fills and is cleared */
		pl_l[i] = (uint8_t)hv_rng32(&rs);
	n_lzw = hv_lzw_enc(pl_l, sizeof pl_l, e_lzw, sizeof e_lzw);
	hv_body(pl_o, sizeof pl_o, 44);
	for (i = 4096; i < 8192; i++)                        /* chunk 2 is noise: stored */
		pl_o[i] = (uint8_t)hv_rng32(&rs);
	e_ovba[0] = 1;
	n_ovba = 1;
	n_ovba += hv_ovba_chunk(pl_o, 4096, e_ovba + n_ovba, sizeof e_ovba - n_ovba, 0);
	n_ovba += hv_ovba_chunk(pl_o + 4096, 4096, e_ovba + n_ovba, sizeof e_ovba - n_ovba, 1);
	n_ovba += hv_ovba_chunk(pl_o + 8192, 2808, e_ovba + n_ovba, sizeof e_ovba - n_ovba, 0);
}

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec v[2];
	struct hv_sweep_job j;
	int bad = 0;

	(void)arg;
	memset(&d, 0, sizeof d);
	d.name = "a85";
	d.run = a85_run;
	d.flags = HV_F_TRUNC_OK_ALLOWED | HV_F_CAP_OK_ALLOWED | HV_F_NO_PREFIX_TRUNC | HV_F_NO_PREFIX_CAP;
	v[0] = (struct hv_vec){ "plain", e_a85, n_a85, pl_a, 300 };
	v[1] = (struct hv_vec){ "wrapped", e_a85w, n_a85w, pl_a, 297 };
	j = (struct hv_sweep_job){ &d, v, 2, 1000, 400 };
	bad |= hv_sweep_job_run(&j);

	memset(&d, 0, sizeof d);
	d.name = "ahx";
	d.run = ahx_run;
	d.flags = HV_F_TRUNC_OK_ALLOWED | HV_F_CAP_OK_ALLOWED | HV_F_NO_PREFIX_TRUNC | HV_F_NO_PREFIX_CAP;
	v[0] = (struct hv_vec){ "plain", e_ahx, n_ahx, pl_a, 300 };
	v[1] = (struct hv_vec){ "spaced", e_ahxs, n_ahxs, pl_a, 299 };
	j = (struct hv_sweep_job){ &d, v, 2, 1100, 400 };
	bad |= hv_sweep_job_run(&j);

	memset(&d, 0, sizeof d);
	d.name = "rle";
	d.run = rle_run;
	v[0] = (struct hv_vec){ "runs", e_rle, n_rle, pl_r, sizeof pl_r };
	j = (struct hv_sweep_job){ &d, v, 1, 2100, 1600 };
	bad |= hv_sweep_job_run(&j);

	memset(&d, 0, sizeof d);
	d.name = "lzw";
	d.run = lzw_run;
	v[0] = (struct hv_vec){ "mixed", e_lzw, n_lzw, pl_l, sizeof pl_l };
	j = (struct hv_sweep_job){ &d, v, 1, 30100, 14100 };
	bad |= hv_sweep_job_run(&j);

	memset(&d, 0, sizeof d);
	d.name = "ovba";
	d.run = ovba_run;
	d.flags = HV_F_TRUNC_OK_ALLOWED;
	v[0] = (struct hv_vec){ "three chunks", e_ovba, n_ovba, pl_o, sizeof pl_o };
	j = (struct hv_sweep_job){ &d, v, 1, 16100, 11100 };
	bad |= hv_sweep_job_run(&j);
	return bad;
}

/* ---- helpers ------------------------------------------------------------------------------- */

static struct hv_gb gin, gout;
static uint8_t keep[300000];

struct tsink {
	uint64_t total, calls, refuse_at, after;
	int      stopped;
};

static int tsink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct tsink *s = u;
	uint32_t i;
	uint8_t x = 0;

	s->calls++;
	if (s->stopped) {
		s->after++;
		return 0;
	}
	for (i = 0; i < n; i++)
		x = (uint8_t)(x + p[i]);
	if (s->refuse_at && s->total >= s->refuse_at) {
		s->stopped = 1;
		return 0;
	}
	if (s->total + n <= sizeof keep)
		memcpy(keep + s->total, p, n);
	s->total += n + (x & 0u);
	return 1;
}

struct tres {
	enum kuncoat_status st;
	uint64_t            produced, sunk;
};

/* the buffer decoders, through guard pages */
static struct tres buf_dec(int which, const void *in, size_t n, size_t cap)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	struct tres r;
	uint64_t p = 0xFEEDull;

	r.st = which ? kuncoat_ahx_decode(ip, n, op, cap, &p) : kuncoat_a85_decode(ip, n, op, cap, &p);
	CK(hv_status_ok(r.st));
	CKF(p <= cap, "produced %llu > cap %zu", (unsigned long long)p, cap);
	CK(hv_out_canary_ok(op));
	if (p <= cap)
		memcpy(keep, op, (size_t)p);
	r.produced = p;
	r.sunk = p;
	return r;
}

#define A85(s, cap) buf_dec(0, s, strlen(s), cap)
#define AHX(s, cap) buf_dec(1, s, strlen(s), cap)

#define AT() hv_at((uint64_t)__LINE__, 0)

/* ---- ASCII85 / ASCIIHex ---------------------------------------------------------------------- */

static void a85_cases(void)
{
	struct tres r;
	size_t i;

	AT();
	r = A85("9jqo^~>", 10);                    /* "Man " */
	CK(r.st == KUNCOAT_OK && r.produced == 4 && !memcmp(keep, "Man ", 4));
	r = A85("9jqo^BlbD-~>", 20);               /* "Man is d" */
	CK(r.st == KUNCOAT_OK && r.produced == 8 && !memcmp(keep, "Man is d", 8));
	/* the largest group value, and one past it */
	r = A85("s8W-!", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 4 && keep[0] == 0xFF && keep[3] == 0xFF);
	r = A85("s8W-\"", 8);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "2^32: %s", kuncoat_status_name(r.st));
	r = A85("uuuuu", 8);
	CK(r.st == KUNCOAT_CORRUPT);
	r = A85("s8W-!s8W-!uuuuu", 12);
	CK(r.st == KUNCOAT_CORRUPT && r.produced == 8);   /* the bytes before the bad group are kept */
	/* z: a zero group when between groups, an error inside one */
	r = A85("zz~>", 16);
	CK(r.st == KUNCOAT_OK && r.produced == 8);
	r = A85("9jz", 16);
	CK(r.st == KUNCOAT_CORRUPT);
	r = A85("z", 3);                           /* no room for four bytes */
	CK(hv_status_ok(r.st) && r.produced == 0);
	r = A85("z", 4);
	CK(r.st == KUNCOAT_OK && r.produced == 4);
	/* a lone character cannot be a group; two can; the partial group's pad */
	r = A85("9~>", 8);
	CK(r.st == KUNCOAT_CORRUPT);
	r = A85("9j~>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 1 && keep[0] == 'M');
	r = A85("9jq~>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 2 && !memcmp(keep, "Ma", 2));
	r = A85("9jqo~>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 3 && !memcmp(keep, "Man", 3));
	/* characters outside '!'..'u' (a space is skipped, which is checked below) */
	{
		static const unsigned bad[] = { 0x01, 0x7F, 0x80, 0xFF, 'v', '{', '}', 0x1F };

		for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
			uint8_t s[8] = { '9', 'j', 0, 'q', 'o', '^', 0, 0 };

			s[2] = (uint8_t)bad[i];
			AT();
			r = buf_dec(0, s, 6, 8);
			CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "byte %#x: %s", bad[i], kuncoat_status_name(r.st));
		}
	}
	/* white space the PDF way: space, tab, CR, LF, FF, NUL */
	r = A85(" 9\tj\rq\no\f^\n~>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 4);
	{
		static const uint8_t ws[] = { '9', 0, 'j', 'q', 'o', '^' };

		r = buf_dec(0, ws, sizeof ws, 8);
		CK(r.st == KUNCOAT_OK && r.produced == 4);
	}
	/* ~ stops at once, whatever follows */
	r = A85("9jqo^~garbage\xff", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 4);
	r = A85("~>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	r = A85("", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	/* cap 0 with data (the known silent loss is in silent_loss_uncoat.c): still no write */
	r = A85("9jqo^", 0);
	CK(r.produced == 0);
}

static void ahx_cases(void)
{
	struct tres r;

	AT();
	r = AHX("48656c6c6f>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 5 && !memcmp(keep, "Hello", 5));
	{
		static const uint8_t ws[] = { '4', ' ', '8', '\t', '6', '\r', '5', '\n', '6', '\f', 'c', 0, '6', 'c', ' ', '6', 'f', '>' };

		r = buf_dec(1, ws, sizeof ws, 8);                /* FF and NUL are white space here */
		CK(r.st == KUNCOAT_OK && r.produced == 5 && !memcmp(keep, "Hello", 5));
	}
	r = AHX("486>65", 8);                                    /* '>' ends it */
	CK(r.st == KUNCOAT_OK && r.produced == 2);
	r = AHX("4", 8);                                         /* the last digit pairs with 0 */
	CK(r.st == KUNCOAT_OK && r.produced == 1 && keep[0] == 0x40);
	r = AHX("486", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 2 && keep[1] == 0x60);
	r = AHX("48g5", 8);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 1, "non-digit: %s %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.produced);
	r = AHX("de:ad", 8);                                     /* ':' and ',' are NOT separators here */
	CK(r.st == KUNCOAT_CORRUPT);
	r = AHX("0x41", 8);
	CK(r.st == KUNCOAT_CORRUPT);
	r = AHX(">", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	r = AHX("", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	r = AHX("AbCdEf>", 8);
	CK(r.st == KUNCOAT_OK && r.produced == 3 && keep[0] == 0xAB && keep[1] == 0xCD && keep[2] == 0xEF);
	/* cap */
	r = AHX("48656c>", 2);
	CK(r.produced == 2);
	r = AHX("48656c>", 0);
	CK(r.produced == 0);
	/* a 64 KB run of valid digits, exact cap */
	{
		static uint8_t big[1 << 17];
		size_t i;

		for (i = 0; i < sizeof big; i++)
			big[i] = (uint8_t)"0123456789abcdef"[i & 15u];
		r = buf_dec(1, big, sizeof big, sizeof big / 2);
		CK(r.st == KUNCOAT_OK && r.produced == sizeof big / 2);
	}
}

/* ---- RunLength ------------------------------------------------------------------------------ */

static struct tres rl(const void *in, size_t n, uint64_t refuse_at)
{
	struct tsink s;
	struct tres r;
	uint64_t p = 0xFEEDull;

	memset(&s, 0, sizeof s);
	s.refuse_at = refuse_at;
	r.st = kuncoat_rle_decode(hv_in(&gin, in, n), n, tsink_fn, &s, &p);
	CK(hv_status_ok(r.st));
	CKF(s.after == 0, "the sink was called again after it refused");
	r.produced = p;
	r.sunk = s.total;
	return r;
}

static void rle_cases(void)
{
	struct tres r;
	static uint8_t big[1 << 20];
	size_t i;

	AT();
	{
		static const uint8_t ok[] = { 2, 'a', 'b', 'c', 254, 'x', 128 };

		r = rl(ok, sizeof ok, 0);
		CK(r.st == KUNCOAT_OK && r.produced == 6 && !memcmp(keep, "abcxxx", 6));
	}
	/* 128 first; 128 with data after it */
	{
		static const uint8_t e[] = { 128, 0, 'a', 128 };

		r = rl(e, sizeof e, 0);
		CK(r.st == KUNCOAT_OK && r.produced == 0);
	}
	/* no 128 at all: TRUNCATED, everything decoded is output */
	{
		static const uint8_t e[] = { 1, 'a', 'b', 255, 'z' };

		r = rl(e, sizeof e, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 4 && !memcmp(keep, "abzz", 4));
	}
	/* a literal run cut short, a repeat with no byte, the length byte alone */
	{
		static const uint8_t e1[] = { 9, 'a', 'b', 'c' }, e2[] = { 0, 'q', 200 }, e3[] = { 5 };

		r = rl(e1, sizeof e1, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 3 && !memcmp(keep, "abc", 3));
		r = rl(e2, sizeof e2, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 1);
		r = rl(e3, sizeof e3, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
		r = rl(e3, 0, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
	}
	/* every length byte 0..255 on its own followed by plenty */
	for (i = 0; i < 256; i++) {
		uint8_t e[300];

		memset(e, 'k', sizeof e);
		e[0] = (uint8_t)i;
		e[i < 128 ? i + 2u : 2u] = 128;
		AT();
		r = rl(e, i < 128 ? i + 3u : 3u, 0);
		if (i < 128)
			CKF(r.st == KUNCOAT_OK && r.produced == i + 1u, "literal run %zu: %s %llu", i,
			    kuncoat_status_name(r.st), (unsigned long long)r.produced);
		else if (i == 128)
			CK(r.st == KUNCOAT_OK && r.produced == 0);
		else
			CKF(r.st == KUNCOAT_OK && r.produced == 257u - i, "repeat %zu: %s %llu", i,
			    kuncoat_status_name(r.st), (unsigned long long)r.produced);
	}
	/* the bomb: pairs of (129, 'x') are 128 bytes each; 512 KB of input is 32 MB of output */
	for (i = 0; i + 2 <= sizeof big; i += 2) {
		big[i] = 129;
		big[i + 1] = 'x';
	}
	AT();
	r = rl(big, sizeof big, 1u << 20);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk <= (1u << 20) + 1024u, "bomb with a refusing sink: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.sunk);
	r = rl(big, sizeof big, 0);
	CKF(r.produced == (sizeof big / 2u) * 128u && r.st == KUNCOAT_TRUNCATED, "bomb in full: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.produced);
	/* a sink that refuses the very first chunk */
	r = rl(big, 1000, 1);
	CK(r.st == KUNCOAT_OK || r.st == KUNCOAT_STOPPED || r.st == KUNCOAT_TRUNCATED);
}

/* ---- LZW -------------------------------------------------------------------------------------- */

static struct tres lz(const uint8_t *in, size_t n, uint64_t refuse_at)
{
	struct tsink s;
	struct tres r;
	uint64_t p = 0xFEEDull;

	memset(&s, 0, sizeof s);
	s.refuse_at = refuse_at;
	r.st = kuncoat_lzw_decode(g_lzw, hv_in(&gin, in, n), n, tsink_fn, &s, &p);
	CK(hv_status_ok(r.st));
	CKF(s.after == 0, "the sink was called again after it refused");
	r.produced = p;
	r.sunk = s.total;
	return r;
}

/* codes written MSB first at the width given */
static size_t codes(uint8_t *b, size_t cap, const unsigned *c, const unsigned *wd, unsigned n)
{
	struct hv_bw w;
	unsigned i;

	hv_bw_init(&w, b, cap);
	for (i = 0; i < n; i++)
		hv_bw_msb(&w, c[i], wd[i]);
	hv_bw_align_msb(&w);
	return w.n;
}

static void lzw_cases(void)
{
	static uint8_t b[20000];
	unsigned c[6000], wd[6000], i, n;
	struct tres r;
	size_t bn;

	AT();
	/* EOD first; empty input; a clear and an end */
	c[0] = 257; wd[0] = 9;
	bn = codes(b, sizeof b, c, wd, 1);
	r = lz(b, bn, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	r = lz(b, 0, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
	/* a first code that was never built */
	c[0] = 256; c[1] = 300; c[2] = 257; wd[0] = wd[1] = wd[2] = 9;
	bn = codes(b, sizeof b, c, wd, 3);
	r = lz(b, bn, 0);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "unbuilt first code: %s", kuncoat_status_name(r.st));
	/* the code about to be built, with no previous code */
	c[1] = 258;
	bn = codes(b, sizeof b, c, wd, 3);
	r = lz(b, bn, 0);
	CKF(r.st == KUNCOAT_CORRUPT, "self-reference with no previous code: %s", kuncoat_status_name(r.st));
	/* a code one past what exists, after a good one */
	c[0] = 256; c[1] = 'A'; c[2] = 260; c[3] = 257;
	for (i = 0; i < 4; i++)
		wd[i] = 9;
	bn = codes(b, sizeof b, c, wd, 4);
	r = lz(b, bn, 0);
	CK(r.st == KUNCOAT_CORRUPT && r.produced == 1 && keep[0] == 'A');
	/* the self-referential code, legal: A, then 258 = "AA" */
	c[2] = 258;
	bn = codes(b, sizeof b, c, wd, 4);
	r = lz(b, bn, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 3 && !memcmp(keep, "AAA", 3));
	/* no EOD */
	bn = codes(b, sizeof b, c, wd, 3);
	r = lz(b, bn, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 3);
	/* CLEAR codes anywhere, 0 or 100 of them in a row, and EOD after */
	for (i = 0; i < 100; i++) {
		c[i] = 256; wd[i] = 9;
	}
	c[100] = 'x'; c[101] = 257; wd[100] = wd[101] = 9;
	bn = codes(b, sizeof b, c, wd, 102);
	r = lz(b, bn, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 1 && keep[0] == 'x');
	/* the table fills and the stream goes on: 'A' repeated 6000 times as single codes
	 * (every code adds an entry until 4096, then nothing more is added); the width
	 * follows the table through 9, 10, 11, 12 */
	n = 0;
	c[n] = 256; wd[n++] = 9;
	{
		unsigned next = 258, width = 9;

		for (i = 0; i < 5900; i++) {
			c[n] = 'A';
			wd[n++] = width;
			if (i > 0 && next < 4096)
				next++;
			if (next + 1u >= (1u << width) && width < 12)
				width++;
		}
		c[n] = 257; wd[n++] = width;
	}
	bn = codes(b, sizeof b, c, wd, n);
	AT();
	r = lz(b, bn, 0);
	CKF(r.st == KUNCOAT_OK && r.produced == 5900, "table past full: %s %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.produced);
	/* the squaring chain: 'A', then each next code names the entry just built: the k-th code
	 * emits k+1 bytes. 3800 codes: ~7.2 MB from 5.7 KB */
	n = 0;
	{
		unsigned next = 258, width = 9;

		c[n] = 256; wd[n++] = 9;
		c[n] = 'A'; wd[n++] = 9;
		for (i = 0; i < 3800; i++) {
			c[n] = next;                    /* the code about to be built: A..A + first byte */
			wd[n++] = width;
			next++;
			if (next + 1u >= (1u << width) && width < 12)
				width++;
		}
		c[n] = 257; wd[n++] = width;
	}
	bn = codes(b, sizeof b, c, wd, n);
	AT();
	r = lz(b, bn, 1u << 20);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk <= (1u << 20) + 512u, "squaring chain with a refusing sink: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.sunk);
	r = lz(b, bn, 0);
	CKF(r.st == KUNCOAT_OK && r.produced == 3801u * 3802u / 2u, "squaring chain in full: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.produced);
	printf("  (lzw chain: %zu bytes -> %llu bytes)\n", bn, (unsigned long long)r.produced);
	/* a sink that stops after the first chunk */
	r = lz(e_lzw, n_lzw, 1);
	CK(r.st == KUNCOAT_STOPPED);
	/* the state is reused: garbage, then a good stream */
	memset(g_lzw, 0xFF, sizeof *g_lzw);
	r = lz(e_lzw, n_lzw, 0);
	CK(r.st == KUNCOAT_OK && r.produced == sizeof pl_l && !memcmp(keep, pl_l, sizeof pl_l));
}

/* ---- OVBA ------------------------------------------------------------------------------------- */

static struct tres ov(const uint8_t *in, size_t n, uint64_t refuse_at)
{
	struct tsink s;
	struct tres r;
	uint64_t p = 0xFEEDull;

	memset(&s, 0, sizeof s);
	s.refuse_at = refuse_at;
	r.st = kuncoat_ovba_decode(hv_in(&gin, in, n), n, tsink_fn, &s, &p);
	CK(hv_status_ok(r.st));
	CKF(s.after == 0, "the sink was called again after it refused");
	r.produced = p;
	r.sunk = s.total;
	return r;
}

static void ovba_cases(void)
{
	uint8_t b[9000];
	struct tres r;
	unsigned i;

	AT();
	/* the signature and nothing else; no signature; empty */
	b[0] = 1;
	r = ov(b, 1, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	r = ov(b, 0, 0);
	CK(r.st == KUNCOAT_CORRUPT);
	for (i = 0; i < 256; i++) {
		b[0] = (uint8_t)i;
		b[1] = 0x00; b[2] = 0xB0; b[3] = 0;
		r = ov(b, 4, 0);
		if (i != 1)
			CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "signature %u: %s", i, kuncoat_status_name(r.st));
	}
	/* the chunk signature bits (12..14) must be 0b011: every other value is CORRUPT */
	for (i = 0; i < 8; i++) {
		b[0] = 1;
		b[1] = 0x00; b[2] = (uint8_t)(0x80u | (i << 4)); b[3] = 0; b[4] = 'a';
		r = ov(b, 5, 0);
		CKF(i == 3 ? r.st != KUNCOAT_CORRUPT : r.st == KUNCOAT_CORRUPT, "chunk signature %u: %s", i,
		    kuncoat_status_name(r.st));
	}
	/* a token as the first thing in a chunk (nothing to copy from) */
	{
		static const uint8_t t[] = { 1, 0x02, 0xB0, 0x01, 0x00, 0x00 };

		r = ov(t, sizeof t, 0);
		CK(r.st == KUNCOAT_CORRUPT && r.produced == 0);
	}
	/* an offset past what the chunk produced: one literal, then a copy of offset 2 */
	{
		static const uint8_t t[] = { 1, 0x03, 0xB0, 0x02, 'a', 0x00, 0x10 };

		r = ov(t, sizeof t, 0);
		CKF(r.st == KUNCOAT_CORRUPT, "offset past the chunk: %s", kuncoat_status_name(r.st));
	}
	/* a token that is legal: 'a', then offset 1 length 3 (token 0x0000) -> "aaaa" */
	{
		static const uint8_t t[] = { 1, 0x03, 0xB0, 0x02, 'a', 0x00, 0x00 };

		r = ov(t, sizeof t, 0);
		CK(r.st == KUNCOAT_OK && r.produced == 4 && !memcmp(keep, "aaaa", 4));
	}
	/* more literals than a chunk can hold: the header claims 4098 bytes and brings them */
	memset(b, 'z', sizeof b);
	b[0] = 1;
	b[1] = (uint8_t)(4095 & 0xff); b[2] = (uint8_t)(0xB0 | (4095 >> 8));
	{
		/* flag bytes of 0 followed by 8 literals each: 455 groups = 4095 data bytes -> 3640 literals;
		 * not enough, so use 4 KB of flag-free literal pairs: flag 0, 8 x 'z' repeated */
		size_t o = 3, lits = 0;

		while (o + 9 <= 4098 && lits < 4200) {
			b[o++] = 0;
			for (i = 0; i < 8; i++, o++)
				b[o] = 'z';
			lits += 8;
		}
		AT();
		r = ov(b, 4098, 0);
		CK(hv_status_ok(r.st) && r.produced <= 4096);
	}
	/* a length that would pass 4096: fill 4090 bytes then copy 10 */
	{
		uint8_t src[4090], c[9000];
		size_t n;

		memset(src, 'q', sizeof src);
		n = 1 + hv_ovba_chunk(src, sizeof src, c + 1, sizeof c - 1, 0);
		c[0] = 1;
		CK(n < 4200);
		r = ov(c, n, 0);
		CK(r.st == KUNCOAT_OK && r.produced == 4090);
	}
	/* extents: chunk header says 100 bytes, the container ends after 3 */
	{
		static const uint8_t t[] = { 1, 100 - 3, 0xB0, 0x00, 'a', 'b' };

		r = ov(t, sizeof t, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 2);
	}
	/* a stored chunk with fewer than 4096 bytes present: TRUNCATED with what is there */
	{
		static const uint8_t t[] = { 1, 0xFF, 0x3F, 'a', 'b', 'c' };

		r = ov(t, sizeof t, 0);
		CK(r.st == KUNCOAT_TRUNCATED && r.produced == 3 && !memcmp(keep, "abc", 3));
	}
	/* a chunk header with nothing after it */
	{
		static const uint8_t t[] = { 1, 0x00, 0x30 };

		r = ov(t, sizeof t, 0);
		CK(hv_status_ok(r.st) && r.produced == 0);
	}
	/* the sink refuses at the first chunk, at the second */
	AT();
	r = ov(e_ovba, n_ovba, 1);
	CK(r.st == KUNCOAT_STOPPED);
	r = ov(e_ovba, n_ovba, 4096);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk == 4096, "refuse at the second chunk: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.sunk);
	r = ov(e_ovba, n_ovba, 0);
	CK(r.st == KUNCOAT_OK && r.produced == sizeof pl_o && !memcmp(keep, pl_o, sizeof pl_o));
	/* many empty-ish chunks: 100000 chunks of 3 bytes (a header and one stored byte of a
	 * zero length is not allowed to loop) */
	{
		static uint8_t many[1 + 100000 * 3];
		size_t k;

		many[0] = 1;
		for (k = 0; k < 100000; k++) {
			many[1 + 3 * k] = 0x00;
			many[2 + 3 * k] = 0xB0;
			many[3 + 3 * k] = 0x00;
		}
		AT();
		r = ov(many, sizeof many, 0);
		CK(hv_status_ok(r.st));
	}
}

static void plausible(void)
{
	static const uint8_t good[] = { 1, 0x10, 0xB0, 0 }, nosig[] = { 2, 0x10, 0xB0 }, badhdr[] = { 1, 0x10, 0x80 };
	unsigned n;

	CK(kuncoat_ovba_plausible(good, 4) == 1);
	CK(kuncoat_ovba_plausible(good, 3) == 1);
	CK(kuncoat_ovba_plausible(good, 2) == 0);
	CK(kuncoat_ovba_plausible(good, 0) == 0);
	CK(kuncoat_ovba_plausible(NULL, 4) == 0);
	CK(kuncoat_ovba_plausible(nosig, 3) == 0);
	CK(kuncoat_ovba_plausible(badhdr, 3) == 0);
	for (n = 0; n <= 4; n++) {
		const uint8_t *ip = hv_in(&gin, good, n);

		AT();
		CKF(kuncoat_ovba_plausible(ip, n) == (n >= 3), "length %u", n);
	}
	/* the three bits at 12..14 are what is tested, bit 15 and the size are not */
	{
		uint8_t b[3] = { 1, 0xFF, 0 };
		unsigned i;

		for (i = 0; i < 256; i++) {
			b[2] = (uint8_t)i;
			CKF(kuncoat_ovba_plausible(b, 3) == (((i >> 4) & 7u) == 3u), "hdr high byte %u", i);
		}
	}
}

HV_GROUP(a85_cases)
HV_GROUP(ahx_cases)
HV_GROUP(rle_cases)
HV_GROUP(lzw_cases)
HV_GROUP(ovba_cases)
HV_GROUP(plausible)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	g_lzw = malloc(sizeof *g_lzw);
	if (!g_lzw || !hv_gb_init(&gin, 1100000) || !hv_gb_init(&gout, 70000)) {
		printf("hostile_text: out of memory\n");
		return 1;
	}
	build();
	hv_expect_clean("text sweeps", sweeps, NULL, 40);
	hv_expect_clean("ascii85", hv_grp_a85_cases, NULL, 10);
	hv_expect_clean("asciihex", hv_grp_ahx_cases, NULL, 10);
	hv_expect_clean("runlength", hv_grp_rle_cases, NULL, 20);
	hv_expect_clean("lzw", hv_grp_lzw_cases, NULL, 20);
	hv_expect_clean("ovba", hv_grp_ovba_cases, NULL, 20);
	hv_expect_clean("ovba plausible", hv_grp_plausible, NULL, 10);
	free(g_lzw);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("hostile_text");
}
