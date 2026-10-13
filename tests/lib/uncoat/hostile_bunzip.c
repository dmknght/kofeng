/*
 * hostile_bunzip - kuncoat_bunzip_decode and kuncoat_bunzip_sniff (bunzip.h).
 *
 * Real streams come from the bzip2 tool through pipes (hostile_common.h hv_tool; no
 * file is written) and the test SKIPS, visibly, without it; the crafted block headers
 * are written here with an MSB-first bit writer and a CRC-32/BZIP2 of this file's own.
 *
 *   SWEEPS      one block, two blocks (-1 on 110 KB), an empty stream, random bytes
 *               (nothing for the BWT to find): every cap, every truncation, every flip.
 *   SNIFF       what is and is not a stream start, with every length 0..12.
 *   LEVELS      the digit after "BZh": 1..9 all decode a stream that fits; '0', ':' and
 *               a non-digit do not; a block bigger than the declared level is CORRUPT
 *               and not an overrun.
 *   BLOCK       the header's lies: the randomised bit (UNSUPPORTED), no used bytes,
 *               1, 0 and 7 groups, 0 and 18003 selectors, a selector naming a group
 *               that does not exist, code lengths 0 and 24 and a walk that never ends,
 *               a run (RUNA x 40) that doubles past the block size, orig_ptr past the
 *               block, a wrong CRC and a wrong combined CRC.
 *   MEMBERS     concatenated streams, trailing garbage, an empty stream in front.
 *   BOMB        ~12 MB of zeros (a few hundred bytes of bz2): a sink that stops at 1 MB
 *               gets STOPPED in time; the full run is exact.
 *   STATE       the 3.6 MB state reused after every kind of failure.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_sweep.h"

#include <decompressors/bunzip.h>

static struct kuncoat_bunzip *g_st;

static enum kuncoat_status bz_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				  uint64_t *prod)
{
	struct hv_bufsink s;
	uint64_t dp = 0xFEEDull;
	enum kuncoat_status st;

	memset(&s, 0, sizeof s);
	s.out = out;
	s.cap = cap;
	st = kuncoat_bunzip_decode(ctx, in, n, hv_bufsink_fn, &s, &dp);
	hv_bufsink_check(&s, st, dp, "bunzip");
	*prod = s.total;
	return st;
}

/* ---- streams from the tool ---------------------------------------------------------- */

static uint8_t *bz_a, *bz_two, *bz_empty, *bz_rand, *bz_zeros;
static size_t n_a, n_two, n_empty, n_rand, n_zeros;
static uint8_t plain_a[3000], plain_two[110000], plain_rand[2500];
static const size_t ZEROS = 12u << 20;

static uint8_t *bzip(const char *level, const uint8_t *in, size_t n, size_t *outn)
{
	const char *argv[] = { "bzip2", "-c", level, NULL };

	return hv_tool(argv, in, n, outn);
}

static void build(void)
{
	uint64_t rs = 3;
	size_t i;
	uint8_t *z;

	hv_body(plain_a, sizeof plain_a, 21);
	bz_a = bzip("-9", plain_a, sizeof plain_a, &n_a);
	hv_body(plain_two, sizeof plain_two, 22);
	for (i = 0; i < sizeof plain_two; i += 97)           /* some noise, so blocks are not trivial */
		plain_two[i] = (uint8_t)hv_rng32(&rs);
	bz_two = bzip("-1", plain_two, sizeof plain_two, &n_two);
	bz_empty = bzip("-9", plain_a, 0, &n_empty);
	for (i = 0; i < sizeof plain_rand; i++)
		plain_rand[i] = (uint8_t)hv_rng32(&rs);
	bz_rand = bzip("-9", plain_rand, sizeof plain_rand, &n_rand);
	z = calloc(ZEROS, 1);
	if (z) {
		bz_zeros = bzip("-9", z, ZEROS, &n_zeros);
		free(z);
	}
}

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec v[4];
	unsigned nv = 0;
	struct hv_sweep_job j;

	(void)arg;
	memset(&d, 0, sizeof d);
	d.name = "bunzip";
	d.run = bz_run;
	d.ctx = g_st;
	/* a whole number of blocks is delivered before the cut: the cut input must never claim OK */
	if (bz_a)
		v[nv++] = (struct hv_vec){ "one block", bz_a, n_a, plain_a, sizeof plain_a };
	if (bz_rand)
		v[nv++] = (struct hv_vec){ "random", bz_rand, n_rand, plain_rand, sizeof plain_rand };
	if (bz_empty)
		v[nv++] = (struct hv_vec){ "empty", bz_empty, n_empty, plain_a, 0 };
	if (bz_two)
		v[nv++] = (struct hv_vec){ "two blocks", bz_two, n_two, plain_two, sizeof plain_two };
	j = (struct hv_sweep_job){ &d, v, nv, 80000, 115000 };
	return hv_sweep_job_run(&j);
}

/* ---- calls with a counting sink ------------------------------------------------------------ */

static struct hv_gb gin;
static uint8_t keep[200000];

struct bsink {
	uint64_t total, calls, refuse_at, after;
	int      stopped;
};

static int bsink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct bsink *s = u;
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

struct bres {
	enum kuncoat_status st;
	uint64_t            produced, sunk;
};

static struct bres bz(const uint8_t *in, size_t n, uint64_t refuse_at)
{
	struct bsink s;
	struct bres r;
	uint64_t p = 0xFEEDull;

	memset(&s, 0, sizeof s);
	s.refuse_at = refuse_at;
	r.st = kuncoat_bunzip_decode(g_st, hv_in(&gin, in, n), n, bsink_fn, &s, &p);
	r.produced = p;
	r.sunk = s.total;
	CK(hv_status_ok(r.st));
	CKF(s.after == 0, "the sink was called again after it refused");
	return r;
}

#define AT() hv_at((uint64_t)__LINE__, 0)

/* ---- sniff -------------------------------------------------------------------------------- */

static void sniff(void)
{
	static const uint8_t blk[12] = { 'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0, 0 };
	static const uint8_t end[12] = { 'B', 'Z', 'h', '1', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0 };
	uint8_t b[12];
	unsigned n, i;

	CK(kuncoat_bunzip_sniff(blk, 12) == 1);
	CK(kuncoat_bunzip_sniff(end, 12) == 1);
	CK(kuncoat_bunzip_sniff(blk, 10) == 1);
	CK(kuncoat_bunzip_sniff(blk, 9) == 0);
	CK(kuncoat_bunzip_sniff(NULL, 12) == 0);
	CK(kuncoat_bunzip_sniff(blk, 0) == 0);
	for (n = 0; n <= 12; n++) {
		const uint8_t *ip = hv_in(&gin, blk, n);

		AT();
		CKF(kuncoat_bunzip_sniff(ip, n) == (n >= 10u), "length %u", n);
	}
	/* the level digit: 1..9 only */
	for (i = 0; i < 256; i++) {
		memcpy(b, blk, 12);
		b[3] = (uint8_t)i;
		CKF(kuncoat_bunzip_sniff(b, 12) == (i >= '1' && i <= '9'), "level byte %u", i);
	}
	/* every other byte of the magics, one at a time */
	for (i = 0; i < 10; i++) {
		memcpy(b, blk, 12);
		b[i] ^= 0x01;
		if (i == 3)
			continue;
		CKF(kuncoat_bunzip_sniff(b, 12) == 0, "magic byte %u flipped", i);
		memcpy(b, end, 12);
		b[i] ^= 0x01;
		if (i == 3)
			continue;
		CKF(kuncoat_bunzip_sniff(b, 12) == 0, "end magic byte %u flipped", i);
	}
}

/* ---- the level digit ------------------------------------------------------------------------ */

static void levels(void)
{
	uint8_t *m;
	unsigned d;
	struct bres r;
	size_t i;

	if (!bz_a) {
		printf("  SKIP bunzip levels: no bzip2 tool\n");
		return;
	}
	m = malloc(n_a > 300000 ? n_a : 300000);
	if (!m) {
		CK(0);
		return;
	}
	for (d = '1'; d <= '9'; d++) {
		memcpy(m, bz_a, n_a);
		m[3] = (uint8_t)d;
		AT();
		r = bz(m, n_a, 0);
		CKF(r.st == KUNCOAT_OK && r.produced == sizeof plain_a && !memcmp(keep, plain_a, sizeof plain_a),
		    "level %c: %s", d, kuncoat_status_name(r.st));
	}
	for (d = 0; d < 256; d++) {
		if (d >= '1' && d <= '9')
			continue;
		memcpy(m, bz_a, n_a);
		m[3] = (uint8_t)d;
		r = bz(m, n_a, 0);
		CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0 && r.sunk == 0, "level byte %u: %s", d,
		    kuncoat_status_name(r.st));
	}
	/* a block bigger than the declared level: 250 KB of noise is one block of -9, and
	 * claims '1' (100000 bytes max) */
	{
		uint8_t *rnd = malloc(250000), *big;
		size_t bn = 0;
		uint64_t rs = 77;

		if (rnd) {
			for (i = 0; i < 250000; i++)
				rnd[i] = (uint8_t)hv_rng32(&rs);
			big = bzip("-9", rnd, 250000, &bn);
			if (big && bn < 300000) {
				memcpy(m, big, bn);
				m[3] = '1';
				AT();
				r = bz(m, bn, 0);
				CKF(r.st == KUNCOAT_CORRUPT, "250 KB block under level 1: %s", kuncoat_status_name(r.st));
				m[3] = '9';
				r = bz(m, bn, 0);
				CK(r.st == KUNCOAT_OK && r.produced == 250000 && !memcmp(keep, rnd, 190000));
			}
			free(big);
		}
		free(rnd);
	}
	free(m);
}

/* ---- crafted blocks --------------------------------------------------------------------------- */

static uint32_t bzcrc(const uint8_t *p, size_t n)
{
	uint32_t crc = 0xFFFFFFFFu;
	size_t i;
	unsigned k;

	for (i = 0; i < n; i++) {
		crc ^= (uint32_t)p[i] << 24;
		for (k = 0; k < 8; k++)
			crc = (crc & 0x80000000u) ? (crc << 1) ^ 0x04C11DB7u : crc << 1;
	}
	return ~crc;
}

/*
 * One block over a single byte value `val` (alphabet: RUNA, RUNB, end), two groups with
 * the lengths {1,2,2}: RUNA = 0, RUNB = 10, end = 11. `syms` is a string of symbols,
 * 'a' RUNA, 'b' RUNB, 'e' end. Every field the format puts before the data can be
 * overridden with the knobs, which is what the lies are.
 */
struct bk {
	uint32_t crc;           /* block CRC; ~0u: computed for the decoded `expect` */
	unsigned randomised;
	uint32_t orig_ptr;
	uint32_t used16;        /* 0: the one-byte map for `val` */
	unsigned groups;
	unsigned selectors;
	unsigned sel_unary;     /* length of the first selector's run of ones (0: a plain 0) */
	unsigned start_len;     /* first code length of group 0 (5 bits) */
	int      endless_walk;  /* a length walk that never stops */
	uint32_t comb;          /* combined CRC in the trailer; ~0u: right */
};

static size_t bz_block_stream(uint8_t *out, size_t cap, const struct bk *k, uint8_t val, const char *syms,
			      const uint8_t *expect, size_t en, char level)
{
	struct hv_bw w;
	uint32_t crc = k->crc == ~0u ? bzcrc(expect, en) : k->crc, comb;
	unsigned g, i, hi = val >> 4, lo = val & 15u;
	const char *s;

	hv_bw_init(&w, out, cap);
	hv_bw_byte(&w, 'B'); hv_bw_byte(&w, 'Z'); hv_bw_byte(&w, 'h'); hv_bw_byte(&w, (uint8_t)level);
	hv_bw_msb(&w, 0x314159u, 24); hv_bw_msb(&w, 0x265359u, 24);
	hv_bw_msb(&w, crc, 32);
	hv_bw_msb(&w, k->randomised, 1);
	hv_bw_msb(&w, k->orig_ptr, 24);
	if (k->used16 == ~0u) {
		hv_bw_msb(&w, 0, 16);                          /* no byte values at all */
	} else {
		hv_bw_msb(&w, 0x8000u >> hi, 16);
		hv_bw_msb(&w, 0x8000u >> lo, 16);
	}
	hv_bw_msb(&w, k->groups, 3);
	hv_bw_msb(&w, k->selectors, 15);
	for (i = 0; i < k->selectors && i < 20000; i++) {
		unsigned run = i == 0 ? k->sel_unary : 0;

		while (run--)
			hv_bw_msb(&w, 1, 1);
		hv_bw_msb(&w, 0, 1);
	}
	for (g = 0; g < (k->groups ? k->groups : 2u) && g < 7; g++) {
		hv_bw_msb(&w, g == 0 ? k->start_len : 1u, 5);
		/* symbol 0: stop (length stays 1); symbol 1: +1 then stop; symbol 2: stop */
		if (k->endless_walk && g == 0) {
			for (i = 0; i < 4000; i++) {
				hv_bw_msb(&w, 2, 2);                    /* "10": +1 */
				hv_bw_msb(&w, 3, 2);                    /* "11": -1, and never a stop */
			}
			continue;
		}
		hv_bw_msb(&w, 0, 1);
		hv_bw_msb(&w, 2, 2); hv_bw_msb(&w, 0, 1);
		hv_bw_msb(&w, 0, 1);
	}
	for (s = syms; *s; s++) {
		if (*s == 'a')
			hv_bw_msb(&w, 0, 1);
		else if (*s == 'b')
			hv_bw_msb(&w, 2, 2);
		else
			hv_bw_msb(&w, 3, 2);
	}
	hv_bw_msb(&w, 0x177245u, 24); hv_bw_msb(&w, 0x385090u, 24);
	comb = k->comb == ~0u ? crc : k->comb;
	hv_bw_msb(&w, comb, 32);
	hv_bw_align_msb(&w);
	return w.n;
}

static void crafted_blocks(void)
{
	uint8_t b[600];
	struct bk k;
	struct bres r;
	size_t n;
	static const uint8_t AAA[3] = { 'A', 'A', 'A' };

	memset(&k, 0, sizeof k);
	k.crc = ~0u; k.groups = 2; k.selectors = 1; k.start_len = 1; k.comb = ~0u;
	/* the control: three 'A' (RUNA RUNA = 1 + 2: the run digits weigh 1, 2, 4 ...) */
	n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
	AT();
	r = bz(b, n, 0);
	CKF(r.st == KUNCOAT_OK && r.produced == 3 && !memcmp(keep, "AAA", 3), "control: %s, %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.produced);
	/* the randomised bit */
	k.randomised = 1;
	n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
	r = bz(b, n, 0);
	CKF(r.st == KUNCOAT_UNSUPPORTED && r.produced == 0, "randomised: %s", kuncoat_status_name(r.st));
	k.randomised = 0;
	/* orig_ptr at nblock (3) and far past it */
	for (unsigned i = 0; i < 4; i++) {
		static const uint32_t op[] = { 3, 4, 0xFFFFFF, 900000 };

		k.orig_ptr = op[i];
		n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
		AT();
		r = bz(b, n, 0);
		CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "orig_ptr %u: %s", op[i], kuncoat_status_name(r.st));
	}
	k.orig_ptr = 0;
	/* no byte values in use */
	k.used16 = ~0u;
	n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
	r = bz(b, n, 0);
	CK(r.st == KUNCOAT_CORRUPT);
	k.used16 = 0;
	/* the group count: 0, 1 (below the 2 minimum), 7 (above the 6 maximum) */
	{
		static const unsigned gc[] = { 0, 1, 7 };

		for (unsigned i = 0; i < 3; i++) {
			k.groups = gc[i];
			n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
			AT();
			r = bz(b, n, 0);
			CKF(r.st == KUNCOAT_CORRUPT, "groups %u: %s", gc[i], kuncoat_status_name(r.st));
		}
		k.groups = 2;
	}
	/* the selector count: 0 and 18003 (the maximum is 18002) */
	{
		static const unsigned sc[] = { 0, 18003, 32767 };
		static uint8_t sb[40000];

		for (unsigned i = 0; i < 3; i++) {
			k.selectors = sc[i];
			n = bz_block_stream(sb, sizeof sb, &k, 'A', "aae", AAA, 3, '9');
			AT();
			r = bz(sb, n, 0);
			CKF(r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED, "selectors %u: %s", sc[i],
			    kuncoat_status_name(r.st));
		}
		k.selectors = 1;
	}
	/* a selector naming group 2 of 2 (unary run of 2 ones) */
	k.sel_unary = 2;
	n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
	AT();
	r = bz(b, n, 0);
	CKF(r.st == KUNCOAT_CORRUPT, "selector past the groups: %s", kuncoat_status_name(r.st));
	k.sel_unary = 0;
	/* code lengths: start 0, start 24..31, and a walk that never stops */
	{
		static const unsigned sl[] = { 0, 24, 25, 31 };

		for (unsigned i = 0; i < 4; i++) {
			k.start_len = sl[i];
			n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
			AT();
			r = bz(b, n, 0);
			CKF(r.st == KUNCOAT_CORRUPT, "start length %u: %s", sl[i], kuncoat_status_name(r.st));
		}
		k.start_len = 1;
	}
	{
		static uint8_t big[6000];

		k.endless_walk = 1;
		n = bz_block_stream(big, sizeof big, &k, 'A', "aae", AAA, 3, '9');
		AT();
		r = bz(big, n, 0);
		CKF(r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED, "endless length walk: %s",
		    kuncoat_status_name(r.st));
		k.endless_walk = 0;
	}
	/* a run that doubles past the block (RUNA x 40: 2^40 - 1 bytes), level 1: block_max 100000 */
	{
		char syms[100];

		memset(syms, 'a', 40);
		syms[40] = 'e';
		syms[41] = 0;
		n = bz_block_stream(b, sizeof b, &k, 'A', syms, AAA, 3, '1');
		AT();
		r = bz(b, n, 0);
		CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "run past the block: %s", kuncoat_status_name(r.st));
		memset(syms, 'a', 70);                  /* so many doublings that the run counter would wrap */
		syms[70] = 'e';
		syms[71] = 0;
		n = bz_block_stream(b, sizeof b, &k, 'A', syms, AAA, 3, '9');
		r = bz(b, n, 0);
		CKF(r.st == KUNCOAT_CORRUPT && r.produced == 0, "run counter wrap: %s", kuncoat_status_name(r.st));
		/* 'b' (RUNB) runs of the maximum legal size: 2^k - 2 equal bytes ... a block of exactly
		 * block_max bytes is legal: level 1 = 100000; 1+2+4+... is not that; so use RUNA x 16 = 65535 */
		memset(syms, 'a', 16);
		syms[16] = 'e';
		syms[17] = 0;
		{
			static uint8_t exp[65535];

			memset(exp, 'A', sizeof exp);
			n = bz_block_stream(b, sizeof b, &k, 'A', syms, exp, sizeof exp, '1');
			r = bz(b, n, 0);
			/* a run of 65535 'A': 4-run RLE with count bytes: the decoded text is the RLE1 form */
			CK(hv_status_ok(r.st));
		}
	}
	/* a wrong block CRC: the data was handed over, then CORRUPT; a wrong combined CRC */
	k.crc = 0x12345678u;
	n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
	AT();
	r = bz(b, n, 0);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 3, "wrong block CRC: %s, %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.produced);
	k.crc = ~0u;
	k.comb = 0xDEADBEEFu;
	n = bz_block_stream(b, sizeof b, &k, 'A', "aae", AAA, 3, '9');
	r = bz(b, n, 0);
	CKF(r.st == KUNCOAT_CORRUPT && r.produced == 3, "wrong combined CRC: %s", kuncoat_status_name(r.st));
	k.comb = ~0u;
	/* a symbol stream that never ends (no 'e'): the input runs out */
	n = bz_block_stream(b, sizeof b, &k, 'A', "ababab", AAA, 3, '9');
	r = bz(b, n, 0);
	CK(r.st != KUNCOAT_OK);
}

/* ---- members ------------------------------------------------------------------------------------ */

static void members(void)
{
	uint8_t *m;
	struct bres r;

	if (!bz_a || !bz_empty || !bz_rand) {
		printf("  SKIP bunzip members: no bzip2 tool\n");
		return;
	}
	m = malloc(n_a + n_rand + n_empty + 100);
	if (!m) {
		CK(0);
		return;
	}
	memcpy(m, bz_a, n_a);
	memcpy(m + n_a, bz_rand, n_rand);
	AT();
	r = bz(m, n_a + n_rand, 0);
	CKF(r.st == KUNCOAT_OK && r.produced == sizeof plain_a + sizeof plain_rand &&
	    !memcmp(keep, plain_a, sizeof plain_a) && !memcmp(keep + sizeof plain_a, plain_rand, sizeof plain_rand),
	    "two streams: %s %llu", kuncoat_status_name(r.st), (unsigned long long)r.produced);
	/* an empty stream in front of a real one, and behind */
	memcpy(m, bz_empty, n_empty);
	memcpy(m + n_empty, bz_a, n_a);
	r = bz(m, n_empty + n_a, 0);
	CK(r.st == KUNCOAT_OK && r.produced == sizeof plain_a && !memcmp(keep, plain_a, sizeof plain_a));
	memcpy(m, bz_a, n_a);
	memcpy(m + n_a, bz_empty, n_empty);
	r = bz(m, n_a + n_empty, 0);
	CK(r.st == KUNCOAT_OK && r.produced == sizeof plain_a);
	/* the second cut short: the first is complete in the sink and the status is not OK */
	memcpy(m, bz_a, n_a);
	memcpy(m + n_a, bz_rand, n_rand);
	r = bz(m, n_a + n_rand / 2, 0);
	CKF(r.st != KUNCOAT_OK && r.produced >= sizeof plain_a && !memcmp(keep, plain_a, sizeof plain_a),
	    "second stream cut: %s %llu", kuncoat_status_name(r.st), (unsigned long long)r.produced);
	/* garbage after a complete stream is not read, and not an error */
	memcpy(m, bz_a, n_a);
	memset(m + n_a, 0xA7, 64);
	r = bz(m, n_a + 64, 0);
	CK(r.st == KUNCOAT_OK && r.produced == sizeof plain_a);
	/* the sink refuses at the first byte, in the middle of the second member */
	memcpy(m, bz_a, n_a);
	memcpy(m + n_a, bz_rand, n_rand);
	r = bz(m, n_a + n_rand, sizeof plain_a);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk == sizeof plain_a, "refuse in the second member: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.sunk);
	r = bz(m, n_a + n_rand, 1);
	CK(r.st == KUNCOAT_STOPPED);
	free(m);
}

static void bomb(void)
{
	struct bres r;
	double t0;

	if (!bz_zeros) {
		printf("  SKIP bunzip bomb: no bzip2 tool\n");
		return;
	}
	t0 = hv_wall();
	AT();
	r = bz(bz_zeros, n_zeros, 1u << 20);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk <= (1u << 20) + 65536u, "bomb with a refusing sink: %s %llu",
	    kuncoat_status_name(r.st), (unsigned long long)r.sunk);
	CKF(hv_wall() - t0 < 5.0, "bomb with a 1 MB sink took %.2fs", hv_wall() - t0);
	r = bz(bz_zeros, n_zeros, 0);
	CKF(r.st == KUNCOAT_OK && r.produced == ZEROS, "bomb in full: %s %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.produced);
	printf("  (bomb: %zu bytes of bzip2 -> %llu bytes)\n", n_zeros, (unsigned long long)r.produced);
}

static void state(void)
{
	struct bres r;
	static const uint8_t junk[40] = "BZh9\x31\x41\x59\x26\x53\x59 not a block";

	if (!bz_a || !bz_two) {
		printf("  SKIP bunzip state: no bzip2 tool\n");
		return;
	}
	memset(g_st, 0xFF, sizeof *g_st);               /* no initialisation is required */
	AT();
	r = bz(bz_a, n_a, 0);
	CK(r.st == KUNCOAT_OK && r.produced == sizeof plain_a);
	r = bz(junk, sizeof junk, 0);
	CK(r.st != KUNCOAT_OK);
	r = bz(bz_a, n_a, 0);
	CK(r.st == KUNCOAT_OK && !memcmp(keep, plain_a, sizeof plain_a));
	r = bz(bz_two, n_two / 2, 0);
	CK(r.st != KUNCOAT_OK);
	r = bz(bz_a, n_a, 0);
	CK(r.st == KUNCOAT_OK && !memcmp(keep, plain_a, sizeof plain_a));
	r = bz(bz_two, n_two, 1);
	CK(r.st == KUNCOAT_STOPPED);
	r = bz(bz_a, n_a, 0);
	CK(r.st == KUNCOAT_OK && !memcmp(keep, plain_a, sizeof plain_a));
	/* nothing at all, and a short one */
	r = bz(bz_a, 0, 0);
	CK(r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED);
	r = bz(bz_a, 9, 0);
	CK(r.st != KUNCOAT_OK);
}

HV_GROUP(sniff)
HV_GROUP(levels)
HV_GROUP(crafted_blocks)
HV_GROUP(members)
HV_GROUP(bomb)
HV_GROUP(state)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	g_st = malloc(sizeof *g_st);
	if (!g_st || !hv_gb_init(&gin, 400000)) {
		printf("hostile_bunzip: out of memory\n");
		return 1;
	}
	build();
	if (!bz_a)
		printf("  SKIP bunzip real-stream sweeps: no bzip2 tool\n");
	else
		hv_expect_clean("bunzip sweeps", sweeps, NULL, 40);
	hv_expect_clean("bunzip sniff", hv_grp_sniff, NULL, 10);
	hv_expect_clean("bunzip levels", hv_grp_levels, NULL, 20);
	hv_expect_clean("bunzip crafted blocks", hv_grp_crafted_blocks, NULL, 10);
	hv_expect_clean("bunzip members", hv_grp_members, NULL, 10);
	hv_expect_clean("bunzip bomb", hv_grp_bomb, NULL, 20);
	hv_expect_clean("bunzip state", hv_grp_state, NULL, 10);
	free(bz_a); free(bz_two); free(bz_empty); free(bz_rand); free(bz_zeros);
	free(g_st);
	hv_gb_free(&gin);
	return hv_done("hostile_bunzip");
}
