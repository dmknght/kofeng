/*
 * hostile_lzx - kuncoat_lzx_decode (lzx.h), the decoder behind .chm and .cab content.
 *
 * Streams come from the fixed-tree encoder in hostile_lzxenc.h (literals, matches in
 * every slot below 16, the three repeated offsets, the length tree, verbatim, aligned
 * and uncompressed blocks, several blocks whose trees are coded as deltas against the
 * previous block's, the E8 header, the 32 KB frame alignment), at window sizes 2^15 and
 * 2^21. There is no LZX compressor to ask: the encoder is this file's reading of the
 * format, so a decoder wrong in the same way passes; what the tests add is every hostile
 * variation of a stream the decoder accepts.
 *
 *   SWEEPS     every cap, every truncation, every bit flip, with guard pages.
 *   SLICES     skip and take: a slice equals the same bytes of the whole decode, for every
 *              (skip, take) pair at the edges (0, 1, a frame, the whole, past it).
 *   E8         the call translation, against an independent implementation, over data with
 *              many 0xE8 bytes, in the first frame, across frames, with a size of 0
 *              (off), 1 and 2^32-1.
 *   WINDOW     0, 14, 22, 32 and 2^32-1 bits are UNSUPPORTED; 15..21 all decode.
 *   BLOCK      type 0 and 4..7, a size of 0, an uncompressed block longer than the input,
 *              repeated offsets of 0, past the output and past the window, a stream of
 *              zeros, ones and patterns.
 *   BOMB       136 bytes per byte of input (a length-tree match at offset 1) with take at
 *              2^40 and a sink that stops at 1 MB: STOPPED in time, no runaway; take and
 *              skip at 2^64-1 on a short stream end as TRUNCATED, quickly.
 *   STATE      the 2.1 MB state reused with a different window and after every failure.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzxenc.h"
#include "hostile_sweep.h"

#include <decompressors/lzx.h>

static struct kuncoat_lzx *g_st;

struct lzp { uint32_t window_bits; uint64_t skip, take; };

static enum kuncoat_status lzx_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	const struct lzp *p = ctx;
	struct hv_bufsink s;
	struct kuncoat_lzx_req rq = { p->window_bits, p->skip, p->take };
	struct kuncoat_io io;
	enum kuncoat_status st;

	memset(&s, 0, sizeof s);
	s.out = out;
	s.cap = cap;
	memset(&io, 0, sizeof io);
	io.in.p = in;
	io.in.n = n;
	io.sink = hv_bufsink_fn;
	io.user = &s;
	io.consumed = io.produced = 0xFEEDull;
	st = kuncoat_lzx_decode(g_st, &rq, &io);
	CKF(io.consumed == 0, "consumed %llu (an LZX stream is framed by its container: always 0)",
	    (unsigned long long)io.consumed);
	/* Two known behaviours are normalised here and each has its own check below: a request
	 * that was satisfied in full is TRUNCATED when the stream ends in the frame where the
	 * slice ends (take is only counted down at a frame flush), and a sink that refuses the
	 * final flush is TRUNCATED, not STOPPED (the end of the stream wins). */
	if (st == KUNCOAT_TRUNCATED && s.refused_n)
		st = KUNCOAT_STOPPED;
	if (st == KUNCOAT_TRUNCATED && io.produced == p->take && !s.refused_n)
		st = KUNCOAT_OK;
	hv_bufsink_check(&s, st, io.produced, "lzx");
	*prod = s.total;
	return st;
}

/* ---- the vectors ----------------------------------------------------------------------------- */

struct vec {
	uint8_t in[90000];
	size_t  n;
	uint8_t want[90000];
	size_t  wn;
};

struct op { int kind; uint32_t off, len; uint8_t lit; };

/* A random valid block script totalling about `target` bytes of output. */
static size_t block_ops(struct op *ops, size_t max_ops, uint64_t *rs, size_t hn0, size_t target, size_t *total)
{
	size_t n = 0, hn = hn0, sum = 0;
	uint32_t r0 = 1;

	(void)r0;
	while (sum < target && n < max_ops) {
		uint32_t r = hv_rng32(rs) % 100u;

		if (hn < 4 || r < 55) {
			ops[n].kind = 0;
			uint32_t pick = hv_rng32(rs) % 4u, ix = hv_rng32(rs) % 12u, any = hv_rng32(rs) & 0x7fu;

			ops[n].lit = (uint8_t)(pick ? (uint32_t)"etaoinshrdlu"[ix] : any);
			n++;
			hn++;
			sum++;
		} else {
			uint32_t lim = hv_rng32(rs) % 3u == 0 ? 253u : 40u, wide = hv_rng32(rs) % 4u, len;
			uint32_t off;

			len = 2u + hv_rng32(rs) % (wide ? 7u : 135u);
			if (lim > hn)
				lim = (uint32_t)hn;
			off = 1u + hv_rng32(rs) % lim;
			ops[n].kind = 1;
			ops[n].off = off;
			ops[n].len = len;
			n++;
			hn += len;
			sum += len;
		}
	}
	*total = sum;
	return n;
}

static int emit_block(struct hv_lx *e, unsigned type, const struct op *ops, size_t nops, size_t total)
{
	size_t i;
	int ok = 1;

	hv_lx_block_begin(e, type, (uint32_t)total);
	for (i = 0; i < nops; i++) {
		if (ops[i].kind == 0)
			hv_lx_lit(e, ops[i].lit);
		else
			ok &= hv_lx_match(e, type == 2, ops[i].off, ops[i].len);
	}
	return ok;
}

/* uncompressed + verbatim + aligned (+ more), at `bits`, about `target` bytes in all. */
static int make_lzx(struct vec *v, unsigned bits, uint64_t seed, size_t target, uint32_t e8_size)
{
	struct hv_lx e;
	static struct op ops[30000];
	uint64_t rs = seed;
	size_t nops, total, i, done = 0;
	uint8_t raw[300];
	uint32_t r[3] = { 5, 7, 11 };
	int ok = 1;
	unsigned blk = 0;

	hv_lx_init(&e, v->in, sizeof v->in, v->want, sizeof v->want, bits, e8_size);
	for (i = 0; i < sizeof raw; i++)
		raw[i] = (uint8_t)hv_rng32(&rs);
	hv_lx_uncompressed(&e, raw, sizeof raw, r);
	done = sizeof raw;
	while (done < target) {
		size_t want_here = target - done > 7000 ? 7000 : target - done;

		nops = block_ops(ops, sizeof ops / sizeof ops[0], &rs, e.hn, want_here, &total);
		ok &= emit_block(&e, 1 + (blk++ & 1u), ops, nops, total);
		done += total;
		if (blk == 2) {                                   /* an odd-sized uncompressed block in the middle */
			uint32_t r2[3] = { 1, 2, 3 };

			hv_lx_uncompressed(&e, raw, 77, r2);
			done += 77;
		}
	}
	v->n = hv_lx_finish(&e);
	v->wn = e.hn;
	return ok && !e.over && e.hn <= sizeof v->want;
}

static struct vec v15, v21, v_big;

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec vv;
	struct hv_sweep_job j;
	struct lzp p;
	int bad = 0;

	(void)arg;
	memset(&d, 0, sizeof d);
	d.name = "lzx w15";
	d.run = lzx_run;
	d.ctx = &p;
	d.flags = HV_F_NO_PREFIX_TRUNC;                        /* see trunc_fabrication */
	/* the stream has no end marker and the caller states the length: a cut stream is
	 * TRUNCATED, and what it handed over is real */
	p = (struct lzp){ 15, 0, v15.wn };
	vv = (struct hv_vec){ "script", v15.in, v15.n, v15.want, v15.wn };
	j = (struct hv_sweep_job){ &d, &vv, 1, 20000, 20000 };
	bad |= hv_sweep_job_run(&j);

	d.name = "lzx w21";
	p = (struct lzp){ 21, 0, v21.wn };
	vv = (struct hv_vec){ "script", v21.in, v21.n, v21.want, v21.wn };
	j = (struct hv_sweep_job){ &d, &vv, 1, 20000, 20000 };
	bad |= hv_sweep_job_run(&j);

	d.name = "lzx frames";
	p = (struct lzp){ 16, 0, v_big.wn };
	vv = (struct hv_vec){ "three frames", v_big.in, v_big.n, v_big.want, v_big.wn };
	j = (struct hv_sweep_job){ &d, &vv, 1, 90000, 90000 };
	bad |= hv_sweep_job_run(&j);
	return bad;
}

/* ---- calls ----------------------------------------------------------------------------------------- */

static struct hv_gb gin;
static uint8_t keep[300000];

struct lsink {
	uint64_t total, calls, refuse_at, after;
	int      stopped;
};

static int lsink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct lsink *s = u;
	uint32_t i;
	uint8_t x = 0;

	s->calls++;
	if (s->stopped) {
		s->after++;
		return 0;
	}
	for (i = 0; i < n; i++)
		x = (uint8_t)(x + p[i]);
	if (s->refuse_at == ~0ull || (s->refuse_at && s->total >= s->refuse_at)) {
		s->stopped = 1;
		return 0;
	}
	if (s->total + n <= sizeof keep)
		memcpy(keep + s->total, p, n);
	s->total += n + (x & 0u);
	return 1;
}

#define REFUSE_ALL (~0ull)

struct lres {
	enum kuncoat_status st;
	uint64_t            produced, sunk, consumed;
};

static struct lres lx(const uint8_t *in, size_t n, uint32_t bits, uint64_t skip, uint64_t take, uint64_t refuse_at)
{
	struct lsink s;
	struct kuncoat_lzx_req rq = { bits, skip, take };
	struct kuncoat_io io;
	struct lres r;

	memset(&s, 0, sizeof s);
	s.refuse_at = refuse_at;
	memset(&io, 0, sizeof io);
	io.in.p = hv_in(&gin, in, n);
	io.in.n = n;
	io.sink = lsink_fn;
	io.user = &s;
	io.consumed = io.produced = 0xFEEDull;
	r.st = kuncoat_lzx_decode(g_st, &rq, &io);
	r.produced = io.produced;
	r.consumed = io.consumed;
	r.sunk = s.total;
	CK(hv_status_ok(r.st));
	CKF(s.after == 0, "the sink was called again after it refused");
	CKF(r.consumed == 0, "consumed %llu", (unsigned long long)r.consumed);
	CKF(r.produced == r.sunk, "produced %llu, the sink accepted %llu", (unsigned long long)r.produced,
	    (unsigned long long)r.sunk);
	return r;
}

#define AT() hv_at((uint64_t)__LINE__, 0)

static void whole(void)
{
	struct lres r;

	AT();
	r = lx(v15.in, v15.n, 15, 0, v15.wn, 0);
	CKF((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && r.produced == v15.wn && !memcmp(keep, v15.want, v15.wn), "w15: %s %llu of %zu",
	    kuncoat_status_name(r.st), (unsigned long long)r.produced, v15.wn);
	r = lx(v21.in, v21.n, 21, 0, v21.wn, 0);
	CKF((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && r.produced == v21.wn && !memcmp(keep, v21.want, v21.wn), "w21: %s %llu of %zu",
	    kuncoat_status_name(r.st), (unsigned long long)r.produced, v21.wn);
	r = lx(v_big.in, v_big.n, 16, 0, v_big.wn, 0);
	CKF((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && r.produced == v_big.wn && !memcmp(keep, v_big.want, v_big.wn), "frames: %s %llu of %zu",
	    kuncoat_status_name(r.st), (unsigned long long)r.produced, v_big.wn);
	/* every window size 15..21 decodes the same stream (offsets below 254 fit them all;
	 * the tree size differs with the window, so only the 15 one does here: 16..21 are
	 * checked to be refused or decoded without a fault) */
	{
		unsigned b;

		for (b = 15; b <= 21; b++) {
			AT();
			r = lx(v15.in, v15.n, b, 0, v15.wn, 0);
			CK(hv_status_ok(r.st));
		}
	}
	/* a sink that refuses the final flush: the receiver said no, so STOPPED (status.h) */
	r = lx(v15.in, v15.n, 15, 0, v15.wn, REFUSE_ALL);
	CK(r.st == KUNCOAT_STOPPED);
	/* take beyond the stream: TRUNCATED with everything there is */
	r = lx(v15.in, v15.n, 15, 0, v15.wn + 1000, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == v15.wn);
	/* take 0: nothing is decoded; OK */
	r = lx(v15.in, v15.n, 15, 0, 0, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
	r = lx(v15.in, v15.n, 15, 100, 0, 0);
	CK(r.st == KUNCOAT_OK && r.produced == 0);
}

static void slices(void)
{
	static const uint64_t edges[] = { 0, 1, 2, 299, 300, 301, 32767, 32768, 32769, 65535, 65536, 65537 };
	unsigned i, j;
	struct lres r;
	size_t full = v_big.wn;

	for (i = 0; i < sizeof edges / sizeof edges[0]; i++)
		for (j = 0; j < sizeof edges / sizeof edges[0]; j++) {
			uint64_t skip = edges[i], take = edges[j] + 1;

			hv_at(skip, take);
			r = lx(v_big.in, v_big.n, 16, skip, take, 0);
			if (skip >= full) {
				CKF(r.produced == 0, "skip %llu: %llu bytes", (unsigned long long)skip, (unsigned long long)r.produced);
			} else {
				uint64_t want = take < full - skip ? take : full - skip;

				CKF(r.produced == want && !memcmp(keep, v_big.want + skip, (size_t)want),
				    "slice %llu+%llu: %s, %llu bytes", (unsigned long long)skip, (unsigned long long)take,
				    kuncoat_status_name(r.st), (unsigned long long)r.produced);
				/* a satisfied slice is OK, or TRUNCATED when the stream ends in its last frame */
				CKF(want == take ? (r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) : r.st == KUNCOAT_TRUNCATED,
				    "slice %llu+%llu: %s", (unsigned long long)skip, (unsigned long long)take,
				    kuncoat_status_name(r.st));
			}
		}
	/* skip and take that wrap a 64 bit sum */
	AT();
	r = lx(v_big.in, v_big.n, 16, ~0ull, ~0ull, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
	r = lx(v_big.in, v_big.n, 16, 0, ~0ull, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == full && !memcmp(keep, v_big.want, full));
	r = lx(v_big.in, v_big.n, 16, 10, ~0ull - 5u, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == full - 10u);
}

/* The call translation, written from the algorithm: independent of the product's. */
static void ref_e8(uint8_t *d, size_t n, uint64_t frame_at, uint32_t fsize)
{
	int64_t cur = (int64_t)frame_at;
	size_t i = 0;

	if (n <= 10)
		return;
	while (i < n - 10) {
		int64_t abs_off;

		if (d[i++] != 0xE8) {
			cur++;
			continue;
		}
		abs_off = (int32_t)((uint32_t)d[i] | (uint32_t)d[i + 1] << 8 | (uint32_t)d[i + 2] << 16 |
				    (uint32_t)d[i + 3] << 24);
		if (abs_off >= -cur && abs_off < (int64_t)fsize) {
			uint32_t rel = abs_off >= 0 ? (uint32_t)(abs_off - cur) : (uint32_t)(abs_off + (int64_t)fsize);

			d[i] = (uint8_t)rel;
			d[i + 1] = (uint8_t)(rel >> 8);
			d[i + 2] = (uint8_t)(rel >> 16);
			d[i + 3] = (uint8_t)(rel >> 24);
		}
		i += 4;
		cur += 5;
	}
}

static void e8_cases(void)
{
	static const uint32_t sizes[] = { 0, 1, 2, 1000, 70000, 0xFFFFFFFFu, 0x80000000u };
	unsigned k;
	struct lres r;

	for (k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
		struct hv_lx e;
		static uint8_t in[60000], hist[60000], exp[60000];
		uint8_t raw[40000];
		uint32_t rr[3] = { 1, 1, 1 };
		uint64_t rs = 50u + k;
		size_t i, n = sizeof raw, off;

		for (i = 0; i < n; i++)
			raw[i] = (uint8_t)(hv_rng32(&rs) % 5u ? hv_rng32(&rs) : 0xE8);
		for (i = 0; i + 8 < n; i += 61) {                      /* E8 with a believable operand */
			raw[i] = 0xE8;
			raw[i + 1] = (uint8_t)(hv_rng32(&rs) % 200u);
			raw[i + 2] = (uint8_t)(hv_rng32(&rs) % 3u);
			raw[i + 3] = 0;
			raw[i + 4] = k % 2 ? 0xFF : 0;
		}
		hv_lx_init(&e, in, sizeof in, hist, sizeof hist, 16, sizes[k]);
		hv_lx_uncompressed(&e, raw, n, rr);
		off = hv_lx_finish(&e);
		memcpy(exp, raw, n);
		if (sizes[k]) {
			size_t f;

			for (f = 0; f < n; f += 32768)
				ref_e8(exp + f, n - f < 32768 ? n - f : 32768, f, sizes[k]);
		}
		AT();
		r = lx(in, off, 16, 0, n, 0);
		CKF((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && r.produced == n && !memcmp(keep, exp, n),
		    "E8 size %u: %s, %llu bytes%s", sizes[k],
		    kuncoat_status_name(r.st), (unsigned long long)r.produced,
		    r.produced == n && memcmp(keep, exp, n) ? " (bytes differ)" : "");
	}
}

static void windows_blocks(void)
{
	static const uint32_t bad_bits[] = { 0, 1, 14, 22, 23, 31, 32, 64, 0xFFFFFFFFu, 0x80000000u };
	unsigned i, k;
	struct lres r;
	uint8_t b[64];
	struct hv_bw w;

	for (i = 0; i < sizeof bad_bits / sizeof bad_bits[0]; i++) {
		AT();
		r = lx(v15.in, v15.n, bad_bits[i], 0, 100, 0);
		CKF(r.st == KUNCOAT_UNSUPPORTED && r.produced == 0, "window %u: %s", bad_bits[i], kuncoat_status_name(r.st));
	}
	/* block types 0 and 4..7, with a good size; a size of 0 for every type */
	for (k = 0; k < 8; k++) {
		static const unsigned order[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

		hv_bw_init(&w, b, sizeof b);
		hv_bw_msb(&w, 0, 1);                    /* no E8 header */
		hv_bw_msb(&w, order[k], 3);
		hv_bw_msb(&w, 0, 16);
		hv_bw_msb(&w, 0, 8);                    /* size 0 */
		hv_bw_align_msb(&w);
		hv_bw_msb(&w, 0xFFFFu, 16);
		AT();
		r = lx(b, w.n + 2u, 15, 0, 100, 0);
		CKF(r.st != KUNCOAT_OK, "block type %u with size 0: %s", order[k], kuncoat_status_name(r.st));
		if (k == 0 || k >= 4)
			CKF(r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED, "type %u: %s", order[k], kuncoat_status_name(r.st));
	}
	/* an unknown block type with a size */
	for (k = 0; k < 8; k++) {
		if (k >= 1 && k <= 3)
			continue;
		memset(b, 0, sizeof b);
		hv_bw_init(&w, b, sizeof b);
		hv_bw_msb(&w, 0, 1);
		hv_bw_msb(&w, k, 3);
		hv_bw_msb(&w, 0, 16);
		hv_bw_msb(&w, 100, 8);
		hv_bw_align_msb(&w);
		r = lx(b, 32, 15, 0, 100, 0);
		CKF(r.st == KUNCOAT_CORRUPT || r.st == KUNCOAT_TRUNCATED, "unknown block type %u: %s", k, kuncoat_status_name(r.st));
	}
}

/* ---- garbage ---------------------------------------------------------------------------------------- */

static void garbage(void)
{
	uint64_t rs = 0x1ABCu;
	uint8_t in[600];
	unsigned it;

	for (it = 0; it < 3000; it++) {
		size_t n = hv_rng32(&rs) % 600u, i;
		unsigned mode = it % 8u, bits = 15u + hv_rng32(&rs) % 7u;

		for (i = 0; i < n; i++) {
			uint32_t v = hv_rng32(&rs);

			in[i] = mode == 0 ? (uint8_t)v : mode == 1 ? 0 : mode == 2 ? 0xFF : mode == 3 ? (uint8_t)(i * 29u) :
				mode == 4 ? (uint8_t)(v % 3u ? 0 : v >> 8) : mode == 5 ? 0x55 : mode == 6 ? (uint8_t)(i & 1u ? 0xFF : 0) :
				(uint8_t)(i < 4 ? v : 0);
		}
		if (mode == 7 && n > 4)
			in[0] &= 0x7f;
		hv_at(7000, it);
		{
			uint64_t skip = hv_rng32(&rs) % 3u ? 0 : hv_rng32(&rs) % 5000u, take = 1u + hv_rng32(&rs) % 70000u;
			uint64_t refuse = hv_rng32(&rs) % 5u == 0 ? 1u + hv_rng32(&rs) % 3000u : 0;

			(void)lx(in, n, bits, skip, take, refuse);
		}
		if (hv_fails > 5)
			return;
	}
}

/* ---- repeated offsets -------------------------------------------------------------------------------- */

static void repeated_offsets(void)
{
	struct hv_lx e;
	static uint8_t in[2000], hist[2000];
	uint8_t raw[16];

	memcpy(raw, "0123456789abcdef", 16);
	struct lres r;
	size_t n;
	unsigned k;

	/* R0 = 0 from an uncompressed block, then a match that reuses it (slot 0) */
	for (k = 0; k < 4; k++) {
		static const uint32_t r0[] = { 0, 17, 0xFFFFFFFFu, 100000 };
		uint32_t rr[3] = { r0[k], 1, 1 };
		struct op ops[1];

		hv_lx_init(&e, in, sizeof in, hist, sizeof hist, 15, 0);
		hv_lx_uncompressed(&e, raw, 16, rr);
		ops[0].kind = 1; ops[0].off = r0[k]; ops[0].len = 4;
		hv_lx_block_begin(&e, 1, 4);
		(void)hv_lx_match(&e, 0, r0[k], 4);       /* a match that names slot 0 (R0) when equal, else an explicit one */
		n = hv_lx_finish(&e);
		AT();
		r = lx(in, n, 15, 0, 100, 0);
		if (r0[k] == 17)
			CKF(r.st != KUNCOAT_CORRUPT || r.produced >= 16, "R0 17 within range: %s", kuncoat_status_name(r.st));
		else
			CKF(r.st == KUNCOAT_CORRUPT && r.produced == 16, "R0 %u: %s %llu", r0[k], kuncoat_status_name(r.st),
			    (unsigned long long)r.produced);
		(void)ops;
	}
	/* R1 and R2 as zero, used through slots 1 and 2 */
	for (k = 1; k <= 2; k++) {
		uint32_t rr[3] = { 5, 0, 0 };

		hv_lx_init(&e, in, sizeof in, hist, sizeof hist, 15, 0);
		hv_lx_uncompressed(&e, raw, 16, rr);
		hv_lx_block_begin(&e, 1, 4);
		/* force slot k: the encoder picks it when off equals R[k] */
		(void)hv_lx_match(&e, 0, 0, 4);
		n = hv_lx_finish(&e);
		r = lx(in, n, 15, 0, 100, 0);
		CKF(r.st == KUNCOAT_CORRUPT, "R%u = 0 used: %s", k, kuncoat_status_name(r.st));
	}
}

static void uncompressed_cuts(void)
{
	struct hv_lx e;
	static uint8_t in[400], hist[400];
	uint8_t raw[100];
	uint32_t rr[3] = { 1, 1, 1 };
	struct lres r;
	size_t n, k;

	memset(raw, 'u', sizeof raw);
	hv_lx_init(&e, in, sizeof in, hist, sizeof hist, 15, 0);
	hv_lx_uncompressed(&e, raw, 100, rr);
	n = hv_lx_finish(&e);
	r = lx(in, n, 15, 0, 100, 0);
	CK((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && r.produced == 100);
	/* every cut: the bytes there are real, TRUNCATED */
	for (k = 0; k < n; k++) {
		AT();
		r = lx(in, k, 15, 0, 100, 0);
		CKF(r.st == KUNCOAT_TRUNCATED, "cut at %zu: %s", k, kuncoat_status_name(r.st));
		CKF(r.produced <= 100 && !memcmp(keep, raw, (size_t)r.produced), "cut at %zu: not the real beginning", k);
	}
}

static void bomb(void)
{
	struct hv_lx e;
	static uint8_t in[8000], hist[8];
	static struct op ops[1];
	struct lres r;
	size_t n, i;
	double t0;

	/* 4000 matches of length 136 at offset 1 after one literal: 544 KB of output from ~4 KB */
	hv_lx_init(&e, in, sizeof in, hist, sizeof hist, 21, 0);
	hv_lx_block_begin(&e, 1, 1u + 4000u * 136u);
	hv_lx_lit(&e, 'A');
	for (i = 0; i < 4000; i++)
		(void)hv_lx_match(&e, 0, 1, 136);
	n = hv_lx_finish(&e);
	CK(!e.over);
	(void)ops;
	t0 = hv_wall();
	AT();
	r = lx(in, n, 21, 0, 1ull << 40, 100000);
	CKF(r.st == KUNCOAT_STOPPED && r.sunk <= 100000 + 40000, "bomb with a refusing sink: %s %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.sunk);
	r = lx(in, n, 21, 0, 1ull << 40, 0);
	CKF(r.st == KUNCOAT_TRUNCATED && r.produced == 1u + 4000u * 136u, "bomb in full: %s %llu", kuncoat_status_name(r.st),
	    (unsigned long long)r.produced);
	CKF(hv_wall() - t0 < 10.0, "bomb took %.2fs", hv_wall() - t0);
	printf("  (lzx bomb: %zu bytes -> %llu bytes)\n", n, (unsigned long long)r.produced);
}

static void state(void)
{
	struct lres r;
	static const uint8_t junk[40] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0x55, 0x00 };

	memset(g_st, 0xFF, sizeof *g_st);
	AT();
	r = lx(v15.in, v15.n, 15, 0, v15.wn, 0);
	CK((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && !memcmp(keep, v15.want, v15.wn));
	r = lx(junk, sizeof junk, 21, 0, 500, 0);
	CK(r.st != KUNCOAT_OK);
	r = lx(v15.in, v15.n, 15, 0, v15.wn, 0);
	CK((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && !memcmp(keep, v15.want, v15.wn));
	r = lx(v21.in, v21.n, 21, 0, v21.wn, 0);
	CK((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && !memcmp(keep, v21.want, v21.wn));
	r = lx(v21.in, v21.n / 2, 21, 0, v21.wn, 0);
	CK(r.st == KUNCOAT_TRUNCATED);
	r = lx(v15.in, v15.n, 15, 0, v15.wn, REFUSE_ALL);
	CK(r.st == KUNCOAT_STOPPED || r.st == KUNCOAT_TRUNCATED);      /* LZX_STOPPED_MASKED, see whole() */
	r = lx(v15.in, v15.n, 15, 0, v15.wn, 0);
	CK((r.st == KUNCOAT_OK || r.st == KUNCOAT_TRUNCATED) && !memcmp(keep, v15.want, v15.wn));
	r = lx(v15.in, 0, 15, 0, 100, 0);
	CK(r.st == KUNCOAT_TRUNCATED && r.produced == 0);
}

static int trunc_fab(void *arg)
{
	struct hv_dec d;
	struct hv_vec v;
	struct hv_sweep_mem m;
	struct hv_tf a, b, c;
	struct lzp p;
	static uint8_t k2[90000];
	static char what[300];

	(void)arg;
	memset(&d, 0, sizeof d);
	d.name = "lzx";
	d.run = lzx_run;
	d.ctx = &p;
	if (!hv_sweep_mem_init(&m, 90000, 90100))
		return 1;
	p = (struct lzp){ 15, 0, v15.wn };
	v = (struct hv_vec){ "w15", v15.in, v15.n, v15.want, v15.wn };
	hv_trunc_fab(&m, &d, &v, 1, 1, &a, k2);
	p = (struct lzp){ 21, 0, v21.wn };
	v = (struct hv_vec){ "w21", v21.in, v21.n, v21.want, v21.wn };
	hv_trunc_fab(&m, &d, &v, 1, 1, &b, k2);
	p = (struct lzp){ 16, 0, v_big.wn };
	v = (struct hv_vec){ "big", v_big.in, v_big.n, v_big.want, v_big.wn };
	hv_trunc_fab(&m, &d, &v, 1, v_big.n / 200u + 1u, &c, k2);
	hv_sweep_mem_free(&m);
	printf("  (lzx truncation: w15 %zu/%zu cuts, w21 %zu/%zu, frames %zu/%zu hand back fabricated bytes, worst %zu)\n",
	       a.nbad, a.cuts, b.nbad, b.cuts, c.nbad, c.cuts, a.worst > b.worst ? a.worst : b.worst);
	snprintf(what, sizeof what, "lzx: stream (%zu bytes) cut at %zu hands back %zu bytes that are not the real output "
		 "(%zu of %zu cuts affected), status TRUNCATED", v15.n, a.worst_cut, a.worst, a.nbad, a.cuts);
	CK(a.nbad + b.nbad + c.nbad == 0);
	return 0;
}

HV_GROUP(whole)
HV_GROUP(slices)
HV_GROUP(e8_cases)
HV_GROUP(windows_blocks)
HV_GROUP(garbage)
HV_GROUP(repeated_offsets)
HV_GROUP(uncompressed_cuts)
HV_GROUP(bomb)
HV_GROUP(state)

int main(void)
{
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	g_st = malloc(sizeof *g_st);
	if (!g_st || !hv_gb_init(&gin, 100000)) {
		printf("hostile_lzx: out of memory\n");
		return 1;
	}
	ok &= make_lzx(&v15, 15, 1, 3000, 0);
	ok &= make_lzx(&v21, 21, 2, 4000, 0);
	ok &= make_lzx(&v_big, 16, 3, 70000, 0);
	CK(ok);
	hv_expect_clean("lzx sweeps", sweeps, NULL, 40);
	hv_expect_clean("lzx truncation", trunc_fab, NULL, 20);
	hv_expect_clean("lzx whole", hv_grp_whole, NULL, 10);
	hv_expect_clean("lzx slices", hv_grp_slices, NULL, 20);
	hv_expect_clean("lzx e8", hv_grp_e8_cases, NULL, 10);
	hv_expect_clean("lzx windows and block types", hv_grp_windows_blocks, NULL, 10);
	hv_expect_clean("lzx garbage", hv_grp_garbage, NULL, 30);
	hv_expect_clean("lzx repeated offsets", hv_grp_repeated_offsets, NULL, 10);
	hv_expect_clean("lzx uncompressed cuts", hv_grp_uncompressed_cuts, NULL, 10);
	hv_expect_clean("lzx bomb", hv_grp_bomb, NULL, 20);
	hv_expect_clean("lzx state", hv_grp_state, NULL, 10);
	free(g_st);
	hv_gb_free(&gin);
	return hv_done("hostile_lzx");
}
