/*
 * decomp_ratio - a RATIO-BOMB ROW per decoder that had none, through <uncoat.h> alone, with the work counted (sink calls, bytes
 * produced, bytes consumed) and not timed (a wall-clock backstop only).
 *
 * hostile_{inflate,bunzip,lzma,lzx,lzhuf,text} already carry a bomb (a stream that expands a hundredfold or a thousandfold, a sink that
 * stops it). This file adds the decoders without one: LZW, OVBA, NRV2 (B, D, E; 8 and 32 bit tag words), aPLib, LZMAT, ASPack, RAR 3
 * and RAR 5. Each stream is written by the encoders of tests/lib/uncoat (hostile_*enc.h, hostile_lzvec.h, hostile_aspenc.h) as the
 * densest the format allows: a run of one byte copied by the longest match from one byte before (or the longest repeat).
 *
 * What a row asserts, whatever the codec:
 *   THE CAP IS A BOUND  (buffer decoders: the caller's out_cap; sink decoders: a sink that refuses after 1 MiB): the output is at
 *                       most the cap, and within one item (the longest match) of it; the status says the work was cut (STOPPED,
 *                       OVER_BUDGET; for the RAR pair, whose cap IS the declared size, OK at exactly the cap) and is never OK
 *                       with fewer bytes than the stream holds, and never CORRUPT
 *   THE SINK IS TOLD    a refusing sink is called once after the refusal at most (the receiver's no is final)
 *   THE WORK IS THE OUTPUT'S  the sink calls are at most one per input byte times a constant (8: a code is under a byte of input
 *                       in the densest run); the whole stream decodes OK to the exact bytes under a roomy cap
 *   TIME                every row under 10 s (backstop; the counters are the assertion)
 */
#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_lzenc.h"
#include "hostile_lzhenc.h"
#include "hostile_nrvenc.h"
#include "hostile_lzvec.h"
#include "hostile_rarenc.h"
#include "hostile_aspenc.h"

#define MIB (1u << 20)

static uint8_t in_buf[1u << 20];
static uint8_t big_plain[8u * MIB];
static uint8_t big_out[8u * MIB + 4096u];

static double t_start;

static void row_begin(const char *name)
{
	hv_at(0, 0);
	t_start = hv_wall();
	(void)name;
}

static void row_end(const char *name)
{
	double el = hv_wall() - t_start;

	CKF(el < 10.0, "%s took %.2fs", name, el);
}

static int all_same(const uint8_t *p, uint64_t n, uint8_t b)
{
	uint64_t i;

	for (i = 0; i < n; i++)
		if (p[i] != b)
			return 0;
	return 1;
}

/* ---- buffer decoders ------------------------------------------------------------------------- */

typedef enum kuncoat_status (*buf_fn)(int a, int b, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p);

static enum kuncoat_status f_nrv(int variant, int bits, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p)
{
	return kuncoat_nrv2_decode(variant, bits, in, n, out, cap, p);
}

static enum kuncoat_status f_aplib(int a, int b, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p)
{
	(void)a; (void)b;
	return kuncoat_aplib_decode(in, n, out, cap, p);
}

static enum kuncoat_status f_lzmat(int a, int b, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p)
{
	(void)a; (void)b;
	return kuncoat_lzmat_decode(in, n, out, cap, p);
}

static enum kuncoat_status f_aspack(int a, int b, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p)
{
	(void)a; (void)b;
	return kuncoat_aspack_decode(in, n, out, cap, p);
}

static uint8_t g_scratch3[KUNCOAT_RAR3_SCRATCH];

static enum kuncoat_status f_rar3(int a, int b, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p)
{
	(void)a; (void)b;
	return kuncoat_rar3_decode(in, n, out, cap, g_scratch3, sizeof g_scratch3, p);
}

static uint8_t g_scratch5[KUNCOAT_RAR5_SCRATCH];

static enum kuncoat_status f_rar5(int a, int b, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *p)
{
	(void)a; (void)b;
	return kuncoat_rar5_decode(in, n, out, cap, g_scratch5, sizeof g_scratch5, p);
}

/*
 * One buffer decoder over one dense stream: `total` bytes of `fill` once decoded, `item` the longest single copy, `declared` 1 for the
 * RAR pair (the cap is the declared size, reaching it is OK), 2 for ASPack (the cap is the declared size, a match that does not fit is CORRUPT).
 */
static void buffer_row(const char *name, buf_fn fn, int a, int b, const uint8_t *in, size_t n, uint64_t total, unsigned item, int declared)
{
	uint64_t p = 0;
	enum kuncoat_status st;
	uint64_t cap = MIB;

	row_begin(name);
	hv_at((uint64_t)n, total);
	CKF(total > 2u * cap, "%s: the bomb is only %llu bytes", name, (unsigned long long)total);
	memset(big_out, 0xCC, cap + 64u);
	st = fn(a, b, in, n, big_out, cap, &p);
	CKF(p <= cap, "%s: %llu bytes under a 1 MiB cap", name, (unsigned long long)p);
	CKF(declared == 1 ? (st == KUNCOAT_OK && p == cap) :
	    declared == 2 ? (p + item >= cap && (st == KUNCOAT_OK || st == KUNCOAT_CORRUPT)) :
	    (p + 2u * item >= cap && st != KUNCOAT_OK && st != KUNCOAT_CORRUPT && hv_status_ok(st)),
	    "%s: 1 MiB cap on %llu bytes of output: %s, %llu bytes", name, (unsigned long long)total, kuncoat_status_name(st), (unsigned long long)p);
	CKF(all_same(big_out, p, 'A') || all_same(big_out, p, 'a') || all_same(big_out + 1, p ? p - 1u : 0, big_out[1]), "%s: the bytes under the cap are not the run", name);
	CKF(big_out[cap] == 0xCC && big_out[cap + 63u] == 0xCC, "%s: wrote past the cap", name);
	st = fn(a, b, in, n, big_out, total, &p);
	CKF(st == KUNCOAT_OK && p == total, "%s: roomy cap: %s, %llu of %llu", name, kuncoat_status_name(st), (unsigned long long)p, (unsigned long long)total);
	CKF(all_same(big_out + 1, p ? p - 1u : 0, big_out[1]), "%s: roomy cap: the bytes are not the run", name);
	printf("  (%s: %zu bytes -> %llu bytes, %llu : 1)\n", name, n, (unsigned long long)total, (unsigned long long)(total / (n ? n : 1u)));
	row_end(name);
}

static void bomb_nrv(void)
{
	static const int bits[2] = { 8, 32 };
	unsigned variant, k, i;

	for (variant = 0; variant < 3; variant++)
		for (k = 0; k < 2; k++) {
			struct hv_tw w;
			char name[40];
			uint64_t total;

			hv_tw_init(&w, in_buf, sizeof in_buf, (unsigned)bits[k], NULL, 0);
			hv_nrv_lit(&w, 'A');
			for (i = 0; i < 4000; i++)
				hv_nrv_match(&w, (int)variant, 1, 1000);
			hv_nrv_end(&w, (int)variant);
			total = 1u + 4000u * 1000u;
			CK(!w.over);
			snprintf(name, sizeof name, "nrv2%c-%d", "bde"[variant], bits[k]);
			buffer_row(name, f_nrv, (int)variant, bits[k], in_buf, w.n, total, 1000, 0);
		}
}

static void bomb_aplib(void)
{
	struct hv_tw w;
	unsigned i;

	hv_tw_init(&w, in_buf, sizeof in_buf, 8, NULL, 0);
	hv_ap_first(&w, 'A');
	for (i = 0; i < 3000; i++)
		hv_ap_match(&w, 1, 1000);
	hv_ap_end(&w);
	CK(!w.over);
	buffer_row("aplib", f_aplib, 0, 0, in_buf, w.n, 1u + 3000u * 1000u, 1000, 0);
}

static void bomb_lzmat(void)
{
	struct nib e;
	unsigned i;
	static uint8_t hist[8];

	memset(&e, 0, sizeof e);
	e.out = in_buf;
	e.cap = sizeof in_buf;
	e.hist = hist;
	e.hcap = 0;
	nib_val(&e, 'A', 2);
	lm_hist(&e, 'A');
	for (i = 0; i < 100; i++)
		lm_item(&e, 1, 1, 0x111u + 0xfff0u, 0);
	if (e.ng)
		lm_flush(&e);
	if (e.n & 1u)
		nib_put(&e, 0);
	CK((e.n >> 1) <= e.cap);
	buffer_row("lzmat", f_lzmat, 0, 0, in_buf, e.n >> 1, 1u + 100u * (0x111u + 0xfff0u), 0x111u + 0xfff0u, 0);
}

static void bomb_aspack(void)
{
	static struct hv_aspvec v;

	CK(make_asp_bomb(&v, 10000));
	buffer_row("aspack", f_aspack, 0, 0, v.in, v.n, v.wn, 264, 2);
}

static void bomb_rar3(void)
{
	static uint8_t hist[8];
	struct hv_r3 e;
	unsigned i;
	size_t n;

	hv_r3_init(&e, in_buf, sizeof in_buf, hist, 0);
	hv_r3_lit(&e, 'A');
	CK(hv_r3_match(&e, 26, 1));
	for (i = 0; i < 100000; i++)
		hv_r3_repeat_last(&e);
	n = hv_r3_finish(&e);
	CK(!e.w.over);
	buffer_row("rar3", f_rar3, 0, 0, in_buf, n, 1u + 26u + 100000u * 26u, 26, 1);
}

static void bomb_rar5(void)
{
	static uint8_t hist[8], pay[1u << 19];
	struct hv_r5 e;
	unsigned i;
	size_t n;

	memset(&e, 0, sizeof e);
	hv_r5_begin(&e, in_buf, sizeof in_buf, pay, sizeof pay, hist, 0, 1);
	hv_r5_lit(&e, 'A');
	CK(hv_r5_match(&e, 40, 1));
	for (i = 0; i < 60000; i++)
		hv_r5_repeat_last(&e);
	n = hv_r5_end_block(&e, 1, 1);
	CK(!e.w.over);
	buffer_row("rar5", f_rar5, 0, 0, in_buf, n, 1u + 40u + 60000u * 40u, 40, 1);
}

/* ---- sink decoders --------------------------------------------------------------------------- */

typedef enum kuncoat_status (*sink_fn)(const uint8_t *in, uint64_t n, kuncoat_bunzip_sink sink, void *user, uint64_t *p);

static struct kuncoat_lzw lzw_st;

static enum kuncoat_status g_lzw(const uint8_t *in, uint64_t n, kuncoat_bunzip_sink sink, void *user, uint64_t *p)
{
	return kuncoat_lzw_decode(&lzw_st, in, n, sink, user, p);
}

static enum kuncoat_status g_ovba(const uint8_t *in, uint64_t n, kuncoat_bunzip_sink sink, void *user, uint64_t *p)
{
	return kuncoat_ovba_decode(in, n, sink, user, p);
}

static void sink_row(const char *name, sink_fn fn, const uint8_t *in, size_t n, uint64_t total, unsigned item)
{
	struct hv_sink s;
	uint64_t p = 0;
	enum kuncoat_status st;

	row_begin(name);
	hv_at((uint64_t)n, total);
	memset(&s, 0, sizeof s);
	s.refuse_at = MIB;
	st = fn(in, n, hv_sink_fn, &s, &p);
	CKF(st == KUNCOAT_STOPPED, "%s: a sink that stops at 1 MiB: %s", name, kuncoat_status_name(st));
	CKF(s.total >= MIB && s.total <= MIB + item, "%s: %llu bytes reached a sink that stops at 1 MiB (one item is %u)", name, (unsigned long long)s.total, item);
	CKF(s.refused_calls == 1, "%s: the sink was called %llu times after it said no", name, (unsigned long long)s.refused_calls);
	CKF(s.calls <= 8u * n + 16u, "%s: %llu sink calls for %zu bytes of input", name, (unsigned long long)s.calls, n);
	memset(&s, 0, sizeof s);
	st = fn(in, n, hv_sink_fn, &s, &p);
	CKF(st == KUNCOAT_OK && s.total == total && p == total, "%s: whole: %s, %llu of %llu", name, kuncoat_status_name(st), (unsigned long long)s.total,
	    (unsigned long long)total);
	CKF(s.calls <= 8u * n + 16u, "%s: whole: %llu sink calls for %zu bytes of input", name, (unsigned long long)s.calls, n);
	printf("  (%s: %zu bytes -> %llu bytes in %llu sink calls)\n", name, n, (unsigned long long)total, (unsigned long long)s.calls);
	row_end(name);
}

static void bomb_lzw(void)
{
	size_t n;

	memset(big_plain, 'A', 6u * MIB);
	n = hv_lzw_enc(big_plain, 6u * MIB, in_buf, sizeof in_buf);
	CK(n < sizeof in_buf);
	sink_row("lzw", g_lzw, in_buf, n, 6u * MIB, 4096);
}

static void bomb_ovba(void)
{
	size_t n;
	enum { PL = 4096 * 400 };

	memset(big_plain, 'A', PL);
	n = hv_ovba_enc(big_plain, PL, in_buf, sizeof in_buf);
	CK(n < sizeof in_buf);
	/* an OVBA container is at most 4096 bytes of output a chunk: the 1 MiB refusal is met at a chunk boundary of the sink calls */
	sink_row("ovba", g_ovba, in_buf, n, PL, 4096);
}

HV_GROUP(bomb_nrv)
HV_GROUP(bomb_aplib)
HV_GROUP(bomb_lzmat)
HV_GROUP(bomb_aspack)
HV_GROUP(bomb_rar3)
HV_GROUP(bomb_rar5)
HV_GROUP(bomb_lzw)
HV_GROUP(bomb_ovba)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	hv_expect_clean("nrv2 bombs", hv_grp_bomb_nrv, NULL, 60);
	hv_expect_clean("aplib bomb", hv_grp_bomb_aplib, NULL, 30);
	hv_expect_clean("lzmat bomb", hv_grp_bomb_lzmat, NULL, 30);
	hv_expect_clean("aspack bomb", hv_grp_bomb_aspack, NULL, 30);
	hv_expect_clean("rar3 bomb", hv_grp_bomb_rar3, NULL, 30);
	hv_expect_clean("rar5 bomb", hv_grp_bomb_rar5, NULL, 30);
	hv_expect_clean("lzw bomb", hv_grp_bomb_lzw, NULL, 30);
	hv_expect_clean("ovba bomb", hv_grp_bomb_ovba, NULL, 30);
	return hv_done("decomp_ratio");
}
