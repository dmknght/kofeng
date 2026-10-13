/*
 * hostile_rar - kuncoat_rar3_decode (rar3.h), kuncoat_rar5_decode (rar5.h) and the PPMd
 * object they drive (ppmd.h: _new, _free, _arena_want, _start, _resume, _next, _at).
 *
 * The LZ halves of both formats are written by hostile_rarenc.h from a script: literals,
 * new matches (near and far, so every length adjustment the distance brings is used),
 * repeated distances, "repeat the last", RAR5's filters (E8, E8E9, ARM, delta, the last
 * through the caller's scratch). The expected bytes are the script's own history, with the
 * filters applied by independent implementations written below.
 *
 *   SWEEPS    every declared size (RAR has no end marker: the size is the caller's), every
 *             truncation, every flip, guard pages, scratch given and withheld.
 *   RAR5      a block header whose checksum is wrong, a size field of 4 bytes, a block with
 *             no tables first, a filter longer than 4 MB, a delta filter with no scratch or
 *             a short one, 1025 filters, a filter that starts past the output, a distance
 *             one past the output, a repeat of a distance that was never set.
 *   RAR3      the same for its header and repeats, a PPM block (restarted 24 times), the
 *             VM-code symbol with nothing behind it, every short input.
 *   PPMD      the object's own arguments: orders 0..70, arenas around the limits, a start
 *             that is refused, resume without a model, next on a broken model, at() on a
 *             NULL model, determinism, and a RAR3 stream of PPM blocks that each restart
 *             a 64 MB model and write nothing (the cost per input byte is printed).
 *   GARBAGE   structured random input through both decoders under guard pages.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzhenc.h"
#include "hostile_rarenc.h"
#include "hostile_sweep.h"

#include <decompressors/ppmd.h>

#define MAXV 60000u

static uint8_t g_scratch5[KUNCOAT_RAR5_SCRATCH];
static uint8_t g_scratch3[KUNCOAT_RAR3_SCRATCH];

struct rarp { int v5; int scratch; };

static enum kuncoat_status rar_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap, uint64_t *prod)
{
	const struct rarp *p = ctx;

	if (p->v5)
		return kuncoat_rar5_decode(in, n, out, cap, p->scratch ? g_scratch5 : NULL, sizeof g_scratch5, prod);
	return kuncoat_rar3_decode(in, n, out, cap, p->scratch ? g_scratch3 : NULL, sizeof g_scratch3, prod);
}

/* ---- scripts ------------------------------------------------------------------------------- */

struct vec {
	uint8_t in[MAXV];
	size_t  n;
	uint8_t want[MAXV];
	size_t  wn;
};

struct filt { uint64_t at; uint32_t len; unsigned type, chan; };

/* independent restatements of the three RAR5 filters */
static void ref_e8(uint8_t *d, uint32_t n, uint32_t file_off, int e9)
{
	uint32_t cur = 0;

	if (n < 5)
		return;
	while (cur < n - 4u) {
		uint8_t c = d[cur++];

		if (c == 0xE8 || (e9 && c == 0xE9)) {
			uint32_t off = (cur + file_off) % 0x1000000u;
			uint32_t addr = (uint32_t)d[cur] | (uint32_t)d[cur + 1] << 8 | (uint32_t)d[cur + 2] << 16 | (uint32_t)d[cur + 3] << 24;
			uint32_t nv = addr;
			int w = 0;

			if (addr < 0x1000000u) {
				nv = addr - off;
				w = 1;
			} else if ((addr & 0x80000000u) && !((addr + off) & 0x80000000u)) {
				nv = addr + 0x1000000u;
				w = 1;
			}
			if (w) {
				d[cur] = (uint8_t)nv; d[cur + 1] = (uint8_t)(nv >> 8);
				d[cur + 2] = (uint8_t)(nv >> 16); d[cur + 3] = (uint8_t)(nv >> 24);
			}
			cur += 4;
		}
	}
}

static void ref_delta(uint8_t *d, uint32_t n, unsigned chan)
{
	static uint8_t tmp[70000];
	uint32_t ch, src = 0, at;

	memcpy(tmp, d, n);
	for (ch = 0; ch < chan; ch++) {
		uint8_t prev = 0;

		for (at = ch; at < n; at += chan) {
			prev = (uint8_t)(prev - tmp[src++]);
			d[at] = prev;
		}
	}
}

static void ref_arm(uint8_t *d, uint32_t n, uint32_t file_off)
{
	uint32_t i;

	for (i = 0; i + 4 <= n; i += 4)
		if (d[i + 3] == 0xEB) {
			uint32_t off = (uint32_t)d[i] | (uint32_t)d[i + 1] << 8 | (uint32_t)d[i + 2] << 16;

			off -= (file_off + i) / 4u;
			d[i] = (uint8_t)off; d[i + 1] = (uint8_t)(off >> 8); d[i + 2] = (uint8_t)(off >> 16);
		}
}

static uint8_t rnd_lit(uint64_t *rs)
{
	uint32_t a = hv_rng32(rs) % 100u, b = hv_rng32(rs) % 3u, c = hv_rng32(rs) % 100u;

	return hv_rar_lit(b ? a % 96u : c);
}

/* A random RAR5 stream, two blocks (the second with no tables), optionally with filters. */
static int make_r5(struct vec *v, uint64_t seed, size_t target, int filters)
{
	struct hv_r5 e;
	static uint8_t pay[MAXV];
	uint64_t rs = seed;
	size_t half = target / 2, n;
	struct filt fl[6];
	unsigned nf = 0, blk, i;

	memset(&e, 0, sizeof e);
	for (blk = 0; blk < 2; blk++) {
		size_t until = blk ? target : half;

		hv_r5_begin(&e, v->in, sizeof v->in, pay, sizeof pay, v->want, sizeof v->want, blk == 0);
		while (e.hn < until) {
			uint32_t r = hv_rng32(&rs) % 100u;

			if (e.hn < 3 || r < 50) {
				hv_r5_lit(&e, rnd_lit(&rs));
			} else if (r < 70) {
				uint32_t k = hv_rng32(&rs) % 4u, span = k == 0 ? 60000u : k == 1 ? 200u : k == 2 ? 9000u : 40u, d;
				uint32_t len, adj;

				if (span > e.hn)
					span = (uint32_t)e.hn;
				d = 1u + hv_rng32(&rs) % span;
				adj = d > 0x40000u ? 3u : d > 0x2000u ? 2u : d > 0x100u ? 1u : 0u;
				len = adj + 2u + hv_rng32(&rs) % 40u;
				(void)hv_r5_match(&e, len, d);
			} else if (r < 80 && e.old[0] && e.old[0] <= e.hn && e.last_len) {
				hv_r5_repeat_last(&e);
			} else if (r < 92) {
				unsigned k = hv_rng32(&rs) % 4u;

				if (e.old[k] && e.old[k] <= e.hn)
					(void)hv_r5_rep(&e, k, 2u + hv_rng32(&rs) % 8u);
				else
					hv_r5_lit(&e, rnd_lit(&rs));
			} else if (filters && nf < 6 && e.hn > 400) {
				static const unsigned types[] = { 1, 2, 3, 0, 1, 0 };
				unsigned t = types[nf];
				uint32_t st = (uint32_t)(hv_rng32(&rs) % 3u);

				fl[nf].at = e.hn + st;
				fl[nf].len = 100u + hv_rng32(&rs) % 300u;
				fl[nf].type = t;
				fl[nf].chan = 1u + hv_rng32(&rs) % 4u;
				hv_r5_filter(&e, st, fl[nf].len, t, fl[nf].chan);
				nf++;
			} else {
				hv_r5_lit(&e, rnd_lit(&rs));
			}
		}
		n = hv_r5_end_block(&e, blk == 0, blk == 1);
		(void)n;
	}
	v->n = e.w.n;
	v->wn = e.hn;
	/* apply the filters to the expected bytes, in the order the decoder will */
	for (i = 0; i < nf; i++) {
		if (fl[i].at + fl[i].len > v->wn)
			continue;
		if (fl[i].type == 1 || fl[i].type == 2)
			ref_e8(v->want + fl[i].at, fl[i].len, (uint32_t)fl[i].at, fl[i].type == 2);
		else if (fl[i].type == 3)
			ref_arm(v->want + fl[i].at, fl[i].len, (uint32_t)fl[i].at);
		else
			ref_delta(v->want + fl[i].at, fl[i].len, fl[i].chan);
	}
	return !e.w.over && e.hn <= MAXV;
}

static int make_r3(struct vec *v, uint64_t seed, size_t target)
{
	struct hv_r3 e;
	uint64_t rs = seed;

	hv_r3_init(&e, v->in, sizeof v->in, v->want, sizeof v->want);
	while (e.hn < target) {
		uint32_t r = hv_rng32(&rs) % 100u;

		if (e.hn < 3 || r < 50) {
			hv_r3_lit(&e, rnd_lit(&rs));
		} else if (r < 70) {
			uint32_t d = 1u + hv_rng32(&rs) % (e.hn < 256 ? (uint32_t)e.hn : 256u), len = 3u + hv_rng32(&rs) % 24u;

			if (!hv_r3_match(&e, len, d))
				hv_r3_lit(&e, rnd_lit(&rs));
		} else if (r < 78 && e.last_len && e.last_dist <= e.hn) {
			hv_r3_repeat_last(&e);
		} else if (r < 90) {
			unsigned k = hv_rng32(&rs) % 4u;

			if (e.old[k] && e.old[k] <= e.hn) {
				if (!hv_r3_rep(&e, k, 2u + hv_rng32(&rs) % 8u))
					hv_r3_lit(&e, rnd_lit(&rs));
			} else {
				hv_r3_lit(&e, rnd_lit(&rs));
			}
		} else {
			uint32_t d = 1u + hv_rng32(&rs) % (e.hn < 256 ? (uint32_t)e.hn : 256u);

			if (!hv_r3_short(&e, d))
				hv_r3_lit(&e, rnd_lit(&rs));
		}
	}
	v->n = hv_r3_finish(&e);
	v->wn = e.hn;
	return !e.w.over && e.hn <= MAXV;
}

static struct vec v5a, v5f, v3a;

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec vv;
	struct hv_sweep_job j;
	struct rarp p;
	int bad = 0;

	(void)arg;
	memset(&d, 0, sizeof d);
	d.run = rar_run;
	d.ctx = &p;
	d.flags = HV_F_DECLARED_SIZE | HV_F_NO_PREFIX_TRUNC;

	d.name = "rar5 lz";
	p = (struct rarp){ 1, 1 };
	vv = (struct hv_vec){ "two blocks", v5a.in, v5a.n, v5a.want, v5a.wn };
	j = (struct hv_sweep_job){ &d, &vv, 1, MAXV, MAXV };
	bad |= hv_sweep_job_run(&j);

	d.name = "rar5 filters";
	d.flags |= HV_F_NO_PREFIX_CAP;                 /* a filter whose range is not all there is not applied */
	vv = (struct hv_vec){ "filters", v5f.in, v5f.n, v5f.want, v5f.wn };
	bad |= hv_sweep_job_run(&j);

	d.name = "rar3 lz";
	d.flags = HV_F_DECLARED_SIZE | HV_F_NO_PREFIX_TRUNC;
	p = (struct rarp){ 0, 1 };
	vv = (struct hv_vec){ "one block", v3a.in, v3a.n, v3a.want, v3a.wn };
	bad |= hv_sweep_job_run(&j);
	return bad;
}

/* ---- calls ------------------------------------------------------------------------------------ */

static struct hv_gb gin, gout;
static uint8_t res[MAXV * 3u];

static enum kuncoat_status rcall(int v5, const uint8_t *in, size_t n, size_t cap, int scratch, uint64_t *p)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	enum kuncoat_status st;

	*p = 0xFEEDull;
	if (v5)
		st = kuncoat_rar5_decode(ip, n, op, cap, scratch ? g_scratch5 : NULL, scratch ? sizeof g_scratch5 : 0, p);
	else
		st = kuncoat_rar3_decode(ip, n, op, cap, scratch ? g_scratch3 : NULL, scratch ? sizeof g_scratch3 : 0, p);
	CK(hv_status_ok(st));
	CKF(*p <= cap, "produced %llu > cap %zu", (unsigned long long)*p, cap);
	CK(hv_out_canary_ok(op));
	if (*p <= cap)
		memcpy(res, op, (size_t)*p);
	return st;
}

#define AT() hv_at((uint64_t)__LINE__, 0)

static void whole(void)
{
	uint64_t p;
	enum kuncoat_status st;

	AT();
	st = rcall(1, v5a.in, v5a.n, v5a.wn, 1, &p);
	CKF(st == KUNCOAT_OK && p == v5a.wn && !memcmp(res, v5a.want, v5a.wn), "rar5: %s %llu of %zu", kuncoat_status_name(st),
	    (unsigned long long)p, v5a.wn);
	st = rcall(1, v5f.in, v5f.n, v5f.wn, 1, &p);
	CKF(st == KUNCOAT_OK && p == v5f.wn && !memcmp(res, v5f.want, v5f.wn), "rar5 filters: %s %llu of %zu",
	    kuncoat_status_name(st), (unsigned long long)p, v5f.wn);
	st = rcall(0, v3a.in, v3a.n, v3a.wn, 1, &p);
	CKF(st == KUNCOAT_OK && p == v3a.wn && !memcmp(res, v3a.want, v3a.wn), "rar3: %s %llu of %zu", kuncoat_status_name(st),
	    (unsigned long long)p, v3a.wn);
	/* the stream without a scratch, rar3 */
	st = rcall(0, v3a.in, v3a.n, v3a.wn, 0, &p);
	CK(st == KUNCOAT_OK && p == v3a.wn && !memcmp(res, v3a.want, v3a.wn));
	/* a size above the data: the decoder has nothing more: not OK, with all of it */
	st = rcall(1, v5a.in, v5a.n, v5a.wn + 100u, 1, &p);
	CK(st != KUNCOAT_OK && p == v5a.wn);
	st = rcall(0, v3a.in, v3a.n, v3a.wn + 100u, 1, &p);
	CK(st != KUNCOAT_OK && p == v3a.wn);
}

/* RAR5 block header lies */
static void r5_headers(void)
{
	uint8_t b[MAXV];
	uint64_t p;
	enum kuncoat_status st;
	unsigned i;

	AT();
	/* a flipped checksum byte, a flipped flags byte, every size-field length (1..4 bytes) */
	memcpy(b, v5a.in, v5a.n);
	for (i = 0; i < 6; i++) {
		memcpy(b, v5a.in, v5a.n);
		b[i] ^= 0xFF;
		st = rcall(1, b, v5a.n, v5a.wn, 1, &p);
		CKF(st != KUNCOAT_OK || i >= 4, "header byte %u inverted: %s", i, kuncoat_status_name(st));
	}
	memcpy(b, v5a.in, v5a.n);
	b[0] = (uint8_t)((b[0] & ~0x18u) | 0x18u);              /* size field of 4 bytes: not allowed */
	st = rcall(1, b, v5a.n, v5a.wn, 1, &p);
	CKF(st == KUNCOAT_CORRUPT && p == 0, "4 byte size field: %s", kuncoat_status_name(st));
	/* a first block with no tables (the checksum is made right again, so the refusal is the tables') */
	memcpy(b, v5a.in, v5a.n);
	b[0] &= 0x7F;
	{
		unsigned nb = ((b[0] >> 3) & 3u) + 1u, k;
		uint32_t sz = 0;

		for (k = 0; k < nb; k++)
			sz |= (uint32_t)b[2 + k] << (8u * k);
		b[1] = (uint8_t)(0x5Au ^ b[0] ^ sz ^ (sz >> 8) ^ (sz >> 16));
	}
	st = rcall(1, b, v5a.n, v5a.wn, 1, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	/* nothing; one byte; two */
	for (i = 0; i < 4; i++) {
		st = rcall(1, v5a.in, i, 100, 1, &p);
		CKF(st == KUNCOAT_CORRUPT && p == 0, "%u bytes: %s", i, kuncoat_status_name(st));
	}
	st = kuncoat_rar5_decode(v5a.in, v5a.n, res, 0, NULL, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_rar5_decode(NULL, 10, res, 10, NULL, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_rar5_decode(v5a.in, v5a.n, NULL, 10, NULL, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_rar5_decode(v5a.in, v5a.n, res, 10, NULL, 0, NULL);
	CK(hv_status_ok(st));
}

/* A single block built by hand: tables, then ops, with the knobs for the lies. */
static size_t r5_one(uint8_t *out, size_t cap, struct hv_r5 *e, uint8_t *pay, uint8_t *hist, size_t hcap)
{
	memset(e, 0, sizeof *e);
	hv_r5_begin(e, out, cap, pay, MAXV, hist, hcap, 1);
	return 0;
}

static void r5_symbols(void)
{
	struct hv_r5 e;
	static uint8_t out[8000], pay[8000], hist[100000];
	uint64_t p;
	enum kuncoat_status st;
	size_t n;
	unsigned i;

	/* a repeat before anything exists (old distances are 0) */
	(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
	hv_r5_lit(&e, 'a');
	hv_r5_lsym(&e, 258);                                  /* rep distance 0 */
	hv_bw_msb(&e.pw, e.rcode[0], e.rc[0]);
	n = hv_r5_end_block(&e, 1, 1);
	AT();
	st = rcall(1, out, n, 100, 1, &p);
	CKF(st == KUNCOAT_CORRUPT && p == 1, "rep of a distance that was never set: %s %llu", kuncoat_status_name(st),
	    (unsigned long long)p);
	/* repeat-last with nothing to repeat is a no-op, not an error */
	(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
	hv_r5_lit(&e, 'a');
	hv_r5_lsym(&e, 257);
	hv_r5_lit(&e, 'b');
	n = hv_r5_end_block(&e, 1, 1);
	st = rcall(1, out, n, 2, 1, &p);
	CK(st == KUNCOAT_OK && p == 2 && !memcmp(res, "ab", 2));
	/* a distance one past the output, and exactly the output */
	for (i = 0; i < 2; i++) {
		(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
		hv_r5_lit(&e, 'a'); hv_r5_lit(&e, 'b'); hv_r5_lit(&e, 'c');
		(void)hv_r5_match(&e, 4, 3u + (1u - i));       /* i=0: distance 4 (one past), i=1: distance 3 */
		n = hv_r5_end_block(&e, 1, 1);
		st = rcall(1, out, n, 7, 1, &p);
		if (i == 0)
			CKF(st == KUNCOAT_CORRUPT && p == 3, "distance one past: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
		else
			CKF(st == KUNCOAT_OK && p == 7 && !memcmp(res, "abcabca", 7), "distance exact: %s %llu", kuncoat_status_name(st),
			    (unsigned long long)p);
	}
	/* the distance slots at the top: dslot 31 reads 14 extra bits: distance up to 65536, far past the
	 * 3 bytes of output */
	(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
	hv_r5_lit(&e, 'a');
	hv_r5_lsym(&e, 262);                                   /* length slot 0 */
	hv_bw_msb(&e.pw, e.dcode[31], e.dc[31]);
	hv_bw_msb(&e.pw, 0x3ff, 10);                           /* bits-4 = 10 */
	hv_bw_msb(&e.pw, e.lowcode[15], e.lowc[15]);
	n = hv_r5_end_block(&e, 1, 1);
	st = rcall(1, out, n, 50, 1, &p);
	CKF(st == KUNCOAT_CORRUPT && p == 1, "far distance: %s", kuncoat_status_name(st));
}

static void r5_filters(void)
{
	struct hv_r5 e;
	static uint8_t out[40000], pay[40000], hist[70000];
	uint64_t p;
	enum kuncoat_status st;
	size_t n, i;
	double t0;

	/* delta with no scratch, with a short one; E8 needs none */
	(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
	for (i = 0; i < 100; i++)
		hv_r5_lit(&e, (uint8_t)(32 + i % 90));
	hv_r5_filter(&e, 0, 50, 0, 2);
	n = hv_r5_end_block(&e, 1, 1);
	AT();
	st = rcall(1, out, n, 100, 0, &p);
	CKF(st == KUNCOAT_UNSUPPORTED || st == KUNCOAT_OK, "delta filter, no scratch: %s", kuncoat_status_name(st));
	{
		uint8_t small[10];

		st = kuncoat_rar5_decode(out, n, res, 100, small, sizeof small, &p);
		CK(hv_status_ok(st));
	}
	/* a filter longer than the format's 4 MB, a filter of length 0, one starting past the output */
	{
		static const uint32_t lens[] = { 0, 0x400001u, 0xFFFFFFFFu };
		static const uint32_t starts[] = { 0, 1u << 30, 0xFFFFFFFFu };
		unsigned k;

		for (k = 0; k < 3; k++) {
			(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
			for (i = 0; i < 100; i++)
				hv_r5_lit(&e, (uint8_t)(32 + i % 90));
			hv_r5_filter(&e, starts[k], lens[k], 1, 1);
			n = hv_r5_end_block(&e, 1, 1);
			AT();
			st = rcall(1, out, n, 100, 1, &p);
			CKF(hv_status_ok(st) && p <= 100, "filter len %#x: %s", lens[k], kuncoat_status_name(st));
		}
		(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
		for (i = 0; i < 100; i++)
			hv_r5_lit(&e, (uint8_t)(32 + i % 90));
		hv_r5_filter(&e, 1u << 30, 50, 1, 1);               /* starts a gigabyte ahead: never applied */
		n = hv_r5_end_block(&e, 1, 1);
		st = rcall(1, out, n, 100, 1, &p);
		CK(st == KUNCOAT_OK && p == 100);
	}
	/* a type the format reserved (5, 6, 7) and a delta of 32 channels */
	{
		unsigned t;

		for (t = 4; t < 8; t++) {
			(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
			for (i = 0; i < 100; i++)
				hv_r5_lit(&e, (uint8_t)(32 + i % 90));
			hv_r5_filter(&e, 0, 50, t, 1);
			n = hv_r5_end_block(&e, 1, 1);
			st = rcall(1, out, n, 100, 1, &p);
			CKF(hv_status_ok(st), "filter type %u: %s", t, kuncoat_status_name(st));
		}
	}
	/* 1025 filters (the table holds 1024): refused, with what was decoded so far */
	(void)r5_one(out, sizeof out, &e, pay, hist, sizeof hist);
	for (i = 0; i < 400; i++)
		hv_r5_lit(&e, (uint8_t)(32 + i % 90));
	for (i = 0; i < 1025; i++)
		hv_r5_filter(&e, 0, 300, 1, 1);
	n = hv_r5_end_block(&e, 1, 1);
	AT();
	t0 = hv_wall();
	st = rcall(1, out, n, 400, 1, &p);
	CKF(hv_status_ok(st) && p == 400, "1025 filters: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
	(void)t0;
}

/* The cost of 1024 E8 filters over a large output: input bytes against work. The filters are
 * declared first (a RAR5 filter covers data AHEAD of the read position), each over the whole
 * output, then the output is made from long matches at distance 1. */
static void r5_filter_cost(void)
{
	struct hv_r5 e;
	static uint8_t out[200000], pay[200000], hist[8];
	uint8_t *big;
	uint64_t p;
	enum kuncoat_status st;
	size_t n, i, goal = 1u << 20;
	double t0;

	(void)r5_one(out, sizeof out, &e, pay, hist, 0);
	for (i = 0; i < 1024; i++)
		hv_r5_filter(&e, 0, (uint32_t)goal, 1, 1);
	hv_r5_lit(&e, 'a');
	for (i = 1; i < goal; i += 40)
		(void)hv_r5_match(&e, 40, 1);
	n = hv_r5_end_block(&e, 1, 1);
	CK(!e.w.over);
	big = malloc(goal + 1000);
	if (!big) {
		CK(0);
		return;
	}
	t0 = hv_wall();
	AT();
	st = kuncoat_rar5_decode(out, n, big, goal, NULL, 0, &p);
	t0 = hv_wall() - t0;
	CK(hv_status_ok(st));
	printf("  (rar5 filters: %zu bytes of input -> %llu bytes, 1024 E8 filters over all of it: %.3fs)\n", n,
	       (unsigned long long)p, t0);
	CKF(t0 < 30.0, "filter storm took %.1fs", t0);
	free(big);
}

/* ---- RAR3 ---------------------------------------------------------------------------------- */

static void r3_cases(void)
{
	struct hv_r3 e;
	static uint8_t out[4000], hist[10000];
	uint64_t p;
	enum kuncoat_status st;
	size_t n;

	AT();
	/* repeats before anything exists: old distances are 0 */
	hv_r3_init(&e, out, sizeof out, hist, sizeof hist);
	hv_r3_lit(&e, 'a');
	hv_r3_lsym(&e, 259);
	hv_bw_msb(&e.w, e.rcode[0], e.rc[0]);
	n = hv_r3_finish(&e);
	st = rcall(0, out, n, 100, 1, &p);
	CKF(st == KUNCOAT_CORRUPT && p == 1, "rep of a distance never set: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
	/* a match at a distance past the output; and at exactly the output */
	hv_r3_init(&e, out, sizeof out, hist, sizeof hist);
	hv_r3_lit(&e, 'a'); hv_r3_lit(&e, 'b');
	(void)hv_r3_match(&e, 5, 3);
	n = hv_r3_finish(&e);
	st = rcall(0, out, n, 100, 1, &p);
	CKF(st == KUNCOAT_CORRUPT && p == 2, "distance past: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
	hv_r3_init(&e, out, sizeof out, hist, sizeof hist);
	hv_r3_lit(&e, 'a'); hv_r3_lit(&e, 'b');
	(void)hv_r3_match(&e, 5, 2);
	n = hv_r3_finish(&e);
	st = rcall(0, out, n, 7, 1, &p);
	CKF(st == KUNCOAT_OK && p == 7 && !memcmp(res, "abababa", 7), "distance exact: %s %llu", kuncoat_status_name(st),
	    (unsigned long long)p);
	/* the symbols 257 (VM code) and 256 + more tables, and short-distance k >= 8 */
	hv_r3_init(&e, out, sizeof out, hist, sizeof hist);
	hv_r3_lit(&e, 'a');
	hv_r3_lsym(&e, 257);
	hv_bw_msb(&e.w, 0, 32);
	n = hv_r3_finish(&e);
	st = rcall(0, out, n, 100, 1, &p);
	CKF(hv_status_ok(st) && p <= 100, "VM code: %s", kuncoat_status_name(st));
	/* empty and short inputs */
	for (n = 0; n < 4; n++) {
		st = rcall(0, out, n, 100, 1, &p);
		CKF(st != KUNCOAT_OK, "%zu bytes: %s", n, kuncoat_status_name(st));
	}
	st = kuncoat_rar3_decode(out, 10, res, 0, NULL, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_rar3_decode(NULL, 10, res, 10, NULL, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_rar3_decode(out, 10, NULL, 10, NULL, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_rar3_decode(v3a.in, v3a.n, res, 10, NULL, 0, NULL);
	CK(hv_status_ok(st));
}

/* ---- PPMd ---------------------------------------------------------------------------------- */

static void ppmd_api(void)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	uint8_t in[64];
	int order, got;
	unsigned i;
	uint64_t arena;

	AT();
	CK(m != NULL);
	/* arena_want: byte + 1 megabytes, clamped to 64 MB */
	CK(kuncoat_ppmd_arena_want(0) == 1u << 20);
	CK(kuncoat_ppmd_arena_want(24) == 25u << 20);
	CK(kuncoat_ppmd_arena_want(62) == 63u << 20);
	CK(kuncoat_ppmd_arena_want(63) == 64u << 20);
	for (i = 64; i < 256; i++)
		CK(kuncoat_ppmd_arena_want((uint8_t)i) == 64u << 20);
	for (i = 0; i < sizeof in; i++)
		in[i] = (uint8_t)(i * 37u + 11u);
	/* start: orders 2..64 are accepted, outside them refused; the arena has a floor and a ceiling */
	for (order = -5; order <= 70; order++) {
		int r = kuncoat_ppmd_start(m, order, 1u << 20, in, sizeof in, 0);

		CKF(r == (order >= 2 && order <= 64), "order %d: %d", order, r);
	}
	{
		static const uint64_t arenas[] = { 0, 1, 100, 1000, 12 * 16 - 1, 12 * 16, 1u << 16, (64u << 20) - 1, 64u << 20,
						   (64u << 20) + 1, 1ull << 32, ~0ull };

		for (i = 0; i < sizeof arenas / sizeof arenas[0]; i++) {
			int r;

			arena = arenas[i];
			r = kuncoat_ppmd_start(m, 8, arena, in, sizeof in, 0);
			if (arena > (64u << 20) || arena < 16u * 12u)
				CKF(r == 0, "arena %llu accepted", (unsigned long long)arena);
			else
				CKF(r == 1 || r == 0, "arena %llu", (unsigned long long)arena);
		}
	}
	/* NULL model everywhere */
	CK(kuncoat_ppmd_start(NULL, 8, 1u << 20, in, sizeof in, 0) == 0);
	CK(kuncoat_ppmd_resume(NULL, in, sizeof in, 0) == 0);
	CK(kuncoat_ppmd_next(NULL) == -1);
	CK(kuncoat_ppmd_at(NULL) == 0);
	kuncoat_ppmd_free(NULL);
	kuncoat_ppmd_free(kuncoat_ppmd_new());              /* a model that was never started */
	{
		struct kuncoat_ppmd *fresh = kuncoat_ppmd_new();

		CK(kuncoat_ppmd_resume(fresh, in, sizeof in, 0) == 0);   /* nothing to resume */
		CK(kuncoat_ppmd_next(fresh) == -1);
		CK(kuncoat_ppmd_at(fresh) == 0);
		kuncoat_ppmd_free(fresh);
	}
	/* a decode of a fixed input is the same twice, and `at` never passes the input */
	{
		int a[300], b[300];
		unsigned k;

		CK(kuncoat_ppmd_start(m, 6, 1u << 20, in, sizeof in, 0) == 1);
		for (k = 0; k < 300; k++) {
			a[k] = kuncoat_ppmd_next(m);
			CKF(a[k] >= -1 && a[k] <= 255, "symbol %d", a[k]);
			CKF(kuncoat_ppmd_at(m) <= sizeof in + 8u, "at %llu", (unsigned long long)kuncoat_ppmd_at(m));
		}
		CK(kuncoat_ppmd_start(m, 6, 1u << 20, in, sizeof in, 0) == 1);
		for (k = 0; k < 300; k++)
			b[k] = kuncoat_ppmd_next(m);
		CK(!memcmp(a, b, sizeof a));
		/* once -1, always -1 */
		for (k = 0; k < 299; k++)
			if (a[k] == -1) {
				CK(a[k + 1] == -1);
				break;
			}
	}
	/* in_at past the end, the input NULL with a length, an empty input */
	got = kuncoat_ppmd_start(m, 6, 1u << 20, in, sizeof in, sizeof in + 100);
	CK(got == 0 || got == 1);
	for (i = 0; i < 50; i++)
		got = kuncoat_ppmd_next(m);
	CK(got >= -1 && got <= 255);
	got = kuncoat_ppmd_start(m, 6, 1u << 20, NULL, 0, 0);
	for (i = 0; i < 50; i++)
		got = kuncoat_ppmd_next(m);
	CK(got >= -1 && got <= 255);
	got = kuncoat_ppmd_start(m, 6, 1u << 20, in, 0, 0);
	(void)got;
	for (i = 0; i < 50; i++)
		got = kuncoat_ppmd_next(m);
	CK(got >= -1 && got <= 255);
	/* resume continues the model with a fresh range coder */
	CK(kuncoat_ppmd_start(m, 6, 1u << 20, in, sizeof in, 0) == 1);
	for (i = 0; i < 20; i++)
		(void)kuncoat_ppmd_next(m);
	CK(kuncoat_ppmd_resume(m, in, sizeof in, 4) == 1);
	for (i = 0; i < 200; i++)
		got = kuncoat_ppmd_next(m);
	CK(got >= -1 && got <= 255);
	/* an input of every byte pattern through the model: no fault, symbols in range */
	{
		static uint8_t buf[300];
		unsigned f;

		for (f = 0; f < 256; f += 5) {
			memset(buf, (int)f, sizeof buf);
			CK(kuncoat_ppmd_start(m, (int)(2u + f % 20u), 1u << 20, hv_in(&gin, buf, sizeof buf), sizeof buf, 0) == 1);
			for (i = 0; i < 400; i++) {
				got = kuncoat_ppmd_next(m);
				if (got < 0)
					break;
				CK(got <= 255);
			}
		}
	}
	kuncoat_ppmd_free(m);
}

/* Find a short range-coder input whose first decoded symbol, taken as the escape, is followed by 0:
 * that block ends at once. */
static int find_empty_block(uint8_t *data, size_t *dn, uint8_t *esc)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	uint64_t rs = 77;
	unsigned t;
	int ok = 0;

	for (t = 0; t < 400000 && !ok; t++) {
		uint8_t d[8];
		unsigned i;
		int c0, c1;

		for (i = 0; i < 8; i++)
			d[i] = (uint8_t)hv_rng32(&rs);
		if (!kuncoat_ppmd_start(m, 4, 1u << 20, d, 8, 0))
			continue;
		c0 = kuncoat_ppmd_next(m);
		c1 = kuncoat_ppmd_next(m);
		if (c0 >= 0 && c1 == 0 && c0 != 0) {
			memcpy(data, d, 8);
			*esc = (uint8_t)c0;
			*dn = (size_t)kuncoat_ppmd_at(m);
			ok = 1;
		}
	}
	kuncoat_ppmd_free(m);
	return ok;
}

/* RAR3: PPM blocks that each restart a model of the size the header names and produce no output. */
static void ppm_blocks(void)
{
	uint8_t d[8], esc = 0;
	size_t dn = 0, n = 0, i, blocks = 24;
	static uint8_t in[2000];
	uint64_t p;
	enum kuncoat_status st;
	double t0;

	if (!find_empty_block(d, &dn, &esc)) {
		printf("  SKIP rar3 ppm blocks: no empty block found\n");
		return;
	}
	for (i = 0; i < blocks; i++) {
		in[n++] = 0xE0 | 3;                         /* PPM, reset (new model), escape given, order 4 */
		in[n++] = 0xFF;                             /* the arena: (255 + 1) MB, clamped to 64 MB */
		in[n++] = esc;
		memcpy(in + n, d, dn);
		n += dn;
	}
	/* the first block's data starts with the range coder's init: the same data again each block */
	AT();
	t0 = hv_wall();
	st = rcall(0, in, n, 1000, 1, &p);
	t0 = hv_wall() - t0;
	printf("  (rar3 ppm blocks: %zu bytes of input = %zu restarts of a 64 MB model, %s, %.3fs: %.1f ms per input byte)\n", n,
	       blocks, kuncoat_status_name(st), t0, t0 * 1000.0 / (double)n);
	CK(hv_status_ok(st));
	CKF(t0 < 60.0, "ppm restarts took %.1fs", t0);
	/* a header that names order 1 (refused) and order 0, and a resume with no model */
	{
		uint8_t b[16] = { 0xE0 | 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };

		st = rcall(0, b, sizeof b, 100, 1, &p);
		CKF(st == KUNCOAT_UNSUPPORTED || st == KUNCOAT_CORRUPT, "order 1: %s", kuncoat_status_name(st));
		b[0] = 0x80 | 0x00;                         /* PPM without the reset bit and no model */
		st = rcall(0, b, sizeof b, 100, 1, &p);
		CKF(st == KUNCOAT_UNSUPPORTED || st == KUNCOAT_CORRUPT, "resume with no model: %s", kuncoat_status_name(st));
	}
}

/* ---- garbage ---------------------------------------------------------------------------------- */

static void garbage(void)
{
	uint64_t rs = 0x5EEDu;
	static uint8_t in[800];
	unsigned it;
	uint64_t p;

	for (it = 0; it < 1500; it++) {
		size_t n = hv_rng32(&rs) % 800u, i, cap = 1u + hv_rng32(&rs) % 5000u;
		unsigned mode = it % 10u;

		for (i = 0; i < n; i++) {
			uint32_t v = hv_rng32(&rs);

			in[i] = mode == 0 ? (uint8_t)v : mode == 1 ? 0 : mode == 2 ? 0xFF : mode == 3 ? (uint8_t)(i * 29u) :
				mode == 4 ? (uint8_t)(v % 3u ? 0 : v >> 8) : mode == 5 ? 0x5A : mode == 6 ? (uint8_t)(i & 1u ? 0xFF : 0) :
				mode == 7 ? (uint8_t)(i < 12 ? v : 0) : mode == 8 ? (uint8_t)(i < 12 ? v : 0xFF) : (uint8_t)(0x7F & v);
		}
		if (mode >= 7 && n > 2)
			in[0] = (uint8_t)(in[0] & 0x7F);
		hv_at(9000, it);
		(void)rcall(it & 1u, in, n, cap, (it >> 1) & 1u, &p);
		if (hv_fails > 5)
			return;
	}
}

/* From valid streams, one byte at a time replaced: the table and block-size bytes are where the
 * decoders have most to check. */
static void table_mutation(void)
{
	static uint8_t m[MAXV];
	unsigned which, pos, val;
	uint64_t p;

	for (which = 0; which < 2; which++) {
		const struct vec *v = which ? &v3a : &v5a;
		static const uint8_t vals[] = { 0x00, 0xFF, 0x7F, 0x80, 0x0F, 0xF0, 0x55 };

		for (pos = 0; pos < 140 && pos < v->n; pos++)
			for (val = 0; val < sizeof vals; val++) {
				memcpy(m, v->in, v->n);
				m[pos] = vals[val];
				hv_at(which * 1000u + pos, val);
				(void)rcall(which ? 0 : 1, m, v->n, v->wn, 1, &p);
				(void)rcall(which ? 0 : 1, m, v->n, v->wn + 50u, 0, &p);
			}
	}
}

HV_GROUP(whole)
HV_GROUP(r5_headers)
HV_GROUP(r5_symbols)
HV_GROUP(r5_filters)
HV_GROUP(r5_filter_cost)
HV_GROUP(r3_cases)
HV_GROUP(ppmd_api)
HV_GROUP(ppm_blocks)
HV_GROUP(garbage)
HV_GROUP(table_mutation)

int main(void)
{
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, MAXV + 100) || !hv_gb_init(&gout, MAXV * 3u)) {
		printf("hostile_rar: cannot map guard buffers\n");
		return 1;
	}
	ok &= make_r5(&v5a, 31, 14000, 0);
	ok &= make_r5(&v5f, 32, 6000, 1);
	ok &= make_r3(&v3a, 33, 9000);
	CK(ok);
	hv_expect_clean("rar sweeps", sweeps, NULL, 60);
	hv_expect_clean("rar whole streams", hv_grp_whole, NULL, 10);
	hv_expect_clean("rar5 headers", hv_grp_r5_headers, NULL, 10);
	hv_expect_clean("rar5 symbols", hv_grp_r5_symbols, NULL, 10);
	hv_expect_clean("rar5 filters", hv_grp_r5_filters, NULL, 20);
	hv_expect_clean("rar5 filter cost", hv_grp_r5_filter_cost, NULL, 60);
	hv_expect_clean("rar3", hv_grp_r3_cases, NULL, 20);
	hv_expect_clean("ppmd api", hv_grp_ppmd_api, NULL, 60);
	hv_expect_clean("rar3 ppm blocks", hv_grp_ppm_blocks, NULL, 120);
	hv_expect_clean("rar garbage", hv_grp_garbage, NULL, 60);
	hv_expect_clean("rar table mutation", hv_grp_table_mutation, NULL, 60);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("hostile_rar");
}
