/*
 * hostile_lzbit - the bit-stream LZ decoders that write into a caller's buffer:
 * kuncoat_aplib_decode (aplib.h), kuncoat_nrv2_decode (nrv2.h: B, D, E at 8, 16 and
 * 32 bit tag words), kuncoat_lzmat_decode (lzmat.h) and kuncoat_aspack_decode
 * (aspack.h).
 *
 * aPLib and NRV2 streams come from the encoders in hostile_nrvenc.h; LZMAT streams
 * from a nibble-stream encoder written here; ASPack has no encoder (its tables are the
 * packer's) and is driven by structured garbage instead.
 *
 *   SWEEPS    every cap, every truncation, every bit flip, guard pages after both
 *             buffers, on every format and every NRV2 variant x width.
 *   NRV2      a distance prefix of 2^24 and past it, a prefix that doubles until it
 *             would wrap, a forward reference (a stored offset with the sign wrong),
 *             a distance one past what exists, the reuse of a distance that was never
 *             set, a length that doubles past 2^32, a length of 2^24 with room for 100,
 *             a variant or a bit width the decoder does not have.
 *   APLIB     a gamma code that never ends, a distance past the output (all three
 *             short forms), the reuse of the offset before one exists, a 4 GB length
 *             against a small buffer, end marker in the middle.
 *   LZMAT     literals and matches of every distance form and length form the format
 *             has (both sides of the 0x881 output position), stream cut at every
 *             nibble, and garbage of every shape.
 *   ASPACK    garbage of every shape, guard pages, and the E8/E9 call filter with
 *             every marker, every length around its 7 byte minimum and a PROT_NONE page
 *             after the buffer.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"
#include "hostile_nrvenc.h"
#include "hostile_lzvec.h"
#include "hostile_sweep.h"

/* ---- adapters ---------------------------------------------------------------------------- */

struct nrvp { int variant, bits; };

static enum kuncoat_status nrv_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				   uint64_t *prod)
{
	const struct nrvp *p = ctx;

	return kuncoat_nrv2_decode(p->variant, p->bits, in, n, out, cap, prod);
}

static enum kuncoat_status ap_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				  uint64_t *prod)
{
	(void)ctx;
	return kuncoat_aplib_decode(in, n, out, cap, prod);
}

static enum kuncoat_status lm_run(void *ctx, const uint8_t *in, size_t n, uint8_t *out, size_t cap,
				  uint64_t *prod)
{
	(void)ctx;
	return kuncoat_lzmat_decode(in, n, out, cap, prod);
}



/* ---- the sweeps ----------------------------------------------------------------------------- */

static struct vec v_nrv[9], v_ap[2], v_lm[2];
static const struct nrvp P[9] = {
	{ HV_NRV2B, 8 }, { HV_NRV2B, 16 }, { HV_NRV2B, 32 }, { HV_NRV2D, 8 }, { HV_NRV2D, 16 },
	{ HV_NRV2D, 32 }, { HV_NRV2E, 8 }, { HV_NRV2E, 16 }, { HV_NRV2E, 32 }
};
static const char *const pname[9] = {
	"nrv2b-8", "nrv2b-16", "nrv2b-32", "nrv2d-8", "nrv2d-16", "nrv2d-32", "nrv2e-8", "nrv2e-16", "nrv2e-32"
};

static int sweeps(void *arg)
{
	struct hv_dec d;
	struct hv_vec vv[2];
	struct hv_sweep_job j;
	unsigned i;
	int bad = 0;

	(void)arg;
	for (i = 0; i < 9; i++) {
		memset(&d, 0, sizeof d);
		d.name = pname[i];
		d.run = nrv_run;
		d.ctx = (void *)(uintptr_t)&P[i];
		vv[0] = (struct hv_vec){ "script", v_nrv[i].in, v_nrv[i].n, v_nrv[i].want, v_nrv[i].wn };
		j = (struct hv_sweep_job){ &d, vv, 1, 8100, 8100 };
		bad |= hv_sweep_job_run(&j);
	}
	memset(&d, 0, sizeof d);
	d.name = "aplib";
	d.run = ap_run;
	d.flags = HV_F_EXACT_MAY_STOP | HV_F_NO_PREFIX_TRUNC | HV_F_TRUNC_OK_ALLOWED;   /* see ap_fab, ap_crafted */
	vv[0] = (struct hv_vec){ "a", v_ap[0].in, v_ap[0].n, v_ap[0].want, v_ap[0].wn };
	vv[1] = (struct hv_vec){ "b", v_ap[1].in, v_ap[1].n, v_ap[1].want, v_ap[1].wn };
	j = (struct hv_sweep_job){ &d, vv, 2, 8100, 8100 };
	bad |= hv_sweep_job_run(&j);
	/* LZMAT has no end marker: the size is the caller's, so a cap above the true size decodes
	 * what the input holds and ends OK; a cap below it is OK too (the known silent loss) */
	memset(&d, 0, sizeof d);
	d.name = "lzmat";
	d.run = lm_run;
	d.flags = HV_F_TRUNC_OK_ALLOWED | HV_F_CAP_OK_ALLOWED | HV_F_NO_PREFIX_TRUNC;
	vv[0] = (struct hv_vec){ "a", v_lm[0].in, v_lm[0].n, v_lm[0].want, v_lm[0].wn };
	vv[1] = (struct hv_vec){ "b", v_lm[1].in, v_lm[1].n, v_lm[1].want, v_lm[1].wn };
	j = (struct hv_sweep_job){ &d, vv, 2, 8100, 8100 };
	bad |= hv_sweep_job_run(&j);
	return bad;
}

/* The input cut short: how many cuts hand back bytes that are not the real beginning. */
static void fab_measure(const char *name, hv_run_fn run, const struct vec *a, const struct vec *b, struct hv_tf *ra,
			struct hv_tf *rb)
{
	struct hv_dec d;
	struct hv_vec v;
	struct hv_sweep_mem m;
	static uint8_t keep[9000];

	memset(&d, 0, sizeof d);
	d.name = name;
	d.run = run;
	memset(ra, 0, sizeof *ra);
	memset(rb, 0, sizeof *rb);
	if (!hv_sweep_mem_init(&m, 8100, 8200))
		return;
	v = (struct hv_vec){ "a", a->in, a->n, a->want, a->wn };
	hv_trunc_fab(&m, &d, &v, 1, 1, ra, keep);
	v = (struct hv_vec){ "b", b->in, b->n, b->want, b->wn };
	hv_trunc_fab(&m, &d, &v, 1, 1, rb, keep);
	hv_sweep_mem_free(&m);
}

static int ap_fab(void *arg)
{
	struct hv_tf a, b;
	static char what[300];

	(void)arg;
	fab_measure("aplib", ap_run, &v_ap[0], &v_ap[1], &a, &b);
	printf("  (aplib truncation: %zu of %zu and %zu of %zu cuts hand back fabricated bytes, worst %zu)\n",
	       a.nbad, a.cuts, b.nbad, b.cuts, a.worst > b.worst ? a.worst : b.worst);
	snprintf(what, sizeof what, "aplib: stream cut at %zu of %zu bytes hands back %zu bytes that are not the real output "
		 "(%zu of %zu cuts affected), status TRUNCATED", b.worst_cut, v_ap[1].n, b.worst, b.nbad, b.cuts);
	CK(a.nbad + b.nbad == 0);
	return 0;
}

static int lm_fab(void *arg)
{
	struct hv_tf a, b;
	static char what[300];

	(void)arg;
	fab_measure("lzmat", lm_run, &v_lm[0], &v_lm[1], &a, &b);
	printf("  (lzmat truncation: %zu of %zu and %zu of %zu cuts hand back fabricated bytes, worst %zu)\n",
	       a.nbad, a.cuts, b.nbad, b.cuts, a.worst > b.worst ? a.worst : b.worst);
	snprintf(what, sizeof what, "lzmat: stream cut at %zu of %zu bytes hands back %zu bytes that are not the real output "
		 "(%zu of %zu cuts affected)", b.worst_cut, v_lm[1].n, b.worst, b.nbad, b.cuts);
	CK(a.nbad + b.nbad == 0);
	return 0;
}

/* ---- a call through guard buffers, for the crafted cases ----------------------------------------- */

static struct hv_gb gin, gout;
static uint8_t res[70000];

static enum kuncoat_status call(int which, const struct nrvp *np, const uint8_t *in, size_t n, size_t cap,
				uint64_t *p)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	enum kuncoat_status st;

	*p = 0xFEEDull;
	if (which == 0)
		st = kuncoat_nrv2_decode(np->variant, np->bits, ip, n, op, cap, p);
	else if (which == 1)
		st = kuncoat_aplib_decode(ip, n, op, cap, p);
	else if (which == 2)
		st = kuncoat_lzmat_decode(ip, n, op, cap, p);
	else
		st = kuncoat_aspack_decode(ip, n, op, cap, p);
	CK(hv_status_ok(st));
	CKF(*p <= cap, "produced %llu > cap %zu", (unsigned long long)*p, cap);
	CK(hv_out_canary_ok(op));
	if (*p <= cap)
		memcpy(res, op, (size_t)*p);
	return st;
}

#define AT() hv_at((uint64_t)__LINE__, 0)

static void nrv_crafted(void)
{
	uint8_t b[600];
	struct hv_tw w;
	uint8_t hist[4000];
	uint64_t p;
	enum kuncoat_status st;
	unsigned vi, wi;

	for (vi = 0; vi < 3; vi++)
		for (wi = 0; wi < 3; wi++) {
			struct nrvp np = { (int)vi, 8 << wi };
			unsigned width = 8u << wi;

			/* control: 'a' 'b' then a match of 6 at distance 2 and the end */
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_lit(&w, 'a'); hv_nrv_lit(&w, 'b');
			hv_nrv_match(&w, (int)vi, 2, 6);
			hv_nrv_end(&w, (int)vi);
			AT();
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_OK && p == 8 && !memcmp(res, "abababab", 8), "v%u w%u control: %s %llu", vi, width,
			    kuncoat_status_name(st), (unsigned long long)p);
			/* cap 7: the match does not fit and is not partly copied: STOPPED, 2 bytes */
			st = call(0, &np, b, w.n, 7, &p);
			CKF(st == KUNCOAT_STOPPED && p == 2, "v%u w%u cap 7: %s %llu", vi, width, kuncoat_status_name(st),
			    (unsigned long long)p);
			st = call(0, &np, b, w.n, 8, &p);
			CKF(st == KUNCOAT_OK && p == 8, "v%u w%u cap 8: %s", vi, width, kuncoat_status_name(st));
			/* distance 3 after two bytes: one past what exists */
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_lit(&w, 'a'); hv_nrv_lit(&w, 'b');
			hv_nrv_match(&w, (int)vi, 3, 4);
			hv_nrv_end(&w, (int)vi);
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_CORRUPT && p == 2, "v%u w%u dist past: %s %llu", vi, width, kuncoat_status_name(st),
			    (unsigned long long)p);
			/* reuse of the distance before any was set (it starts at 1): fine after one byte,
			 * CORRUPT as the very first item */
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_lit(&w, 'x');
			w.last = 1;
			hv_nrv_rep(&w, (int)vi, 5);
			hv_nrv_end(&w, (int)vi);
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_OK && p == 6 && !memcmp(res, "xxxxxx", 6), "v%u w%u rep after one byte: %s %llu", vi,
			    width, kuncoat_status_name(st), (unsigned long long)p);
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_rep(&w, (int)vi, 5);
			hv_nrv_end(&w, (int)vi);
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_CORRUPT && p == 0, "v%u w%u rep first: %s", vi, width, kuncoat_status_name(st));
			/* the end marker first: complete and empty */
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_end(&w, (int)vi);
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_OK && p == 0, "v%u w%u end first: %s", vi, width, kuncoat_status_name(st));
			/* a prefix of 2^24 + 3 (one past the largest) and of 0x800003 (a forward reference) */
			{
				static const uint32_t pr[] = { 0x1000003u, 0x1000004u, 0x800003u, 0x7fffffu, 0x2000000u };
				unsigned k;

				for (k = 0; k < 5; k++) {
					hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
					hv_nrv_lit(&w, 'a');
					hv_nrv_match_raw(&w, (int)vi, pr[k], 0x12, 1);
					hv_nrv_end(&w, (int)vi);
					AT();
					st = call(0, &np, b, w.n, 100, &p);
					CKF(st == KUNCOAT_CORRUPT && p == 1, "v%u w%u prefix %#x: %s %llu", vi, width, pr[k],
					    kuncoat_status_name(st), (unsigned long long)p);
				}
			}
			/* a prefix that doubles until it would wrap: a '0' (match) then zeros. The decoder
			 * must refuse, not run on. */
			{
				uint8_t z[300];

				memset(z, 0, sizeof z);
				AT();
				st = call(0, &np, z, sizeof z, 100, &p);
				CKF(st == KUNCOAT_CORRUPT || st == KUNCOAT_TRUNCATED, "v%u w%u zeros: %s", vi, width,
				    kuncoat_status_name(st));
				memset(z, 0xFF, sizeof z);
				st = call(0, &np, z, sizeof z, 100, &p);
				CKF(st == KUNCOAT_STOPPED || st == KUNCOAT_CORRUPT || st == KUNCOAT_TRUNCATED,
				    "v%u w%u ones: %s", vi, width, kuncoat_status_name(st));
				memset(z, 0xAA, sizeof z);
				st = call(0, &np, z, sizeof z, 100, &p);
				CK(hv_status_ok(st));
				memset(z, 0x55, sizeof z);
				st = call(0, &np, z, sizeof z, 100, &p);
				CK(hv_status_ok(st));
			}
			/* a length that doubles past 2^32: a match, then the tail of (1,0) pairs, 40 of them */
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_lit(&w, 'a');
			hv_nrv_match_raw(&w, (int)vi, 3, 0x00, 0);
			{
				unsigned k;

				for (k = 0; k < 40; k++) {
					hv_tw_bit(&w, 1);
					hv_tw_bit(&w, 0);
				}
			}
			AT();
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_CORRUPT || st == KUNCOAT_TRUNCATED, "v%u w%u runaway length: %s", vi, width,
			    kuncoat_status_name(st));
			/* a length of 2^22 with room for 100: STOPPED at once, not a copy of 4 MB */
			hv_tw_init(&w, b, sizeof b, width, hist, sizeof hist);
			hv_nrv_lit(&w, 'a');
			hv_nrv_match(&w, (int)vi, 1, 1u << 22);
			hv_nrv_end(&w, (int)vi);
			st = call(0, &np, b, w.n, 100, &p);
			CKF(st == KUNCOAT_STOPPED && p == 1, "v%u w%u length 2^22 into 100: %s %llu", vi, width,
			    kuncoat_status_name(st), (unsigned long long)p);
		}
	/* the variant and the width the decoder does not have */
	{
		static const int badbits[] = { 0, 1, 7, 9, 15, 24, 33, 64, -8 };
		unsigned k;
		struct nrvp np;

		for (k = 0; k < sizeof badbits / sizeof badbits[0]; k++) {
			np.variant = HV_NRV2B;
			np.bits = badbits[k];
			p = 99;
			st = call(0, &np, b, 10, 100, &p);
			CKF(st == KUNCOAT_CORRUPT && p == 0, "bit width %d: %s", badbits[k], kuncoat_status_name(st));
		}
		np.bits = 8;
		{
			unsigned accepted = 0;

			for (k = 0; k < 4; k++) {
				static const int badvar[] = { 3, 4, -1, 99 };

				np.variant = badvar[k];
				hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
				hv_nrv_lit(&w, 'a');
				hv_nrv_end(&w, HV_NRV2E);
				st = call(0, &np, b, w.n, 100, &p);
				accepted += st == KUNCOAT_OK;
			}
			CK(accepted == 0);
		}
	}
	/* cap 0 is STOPPED at once; a NULL buffer with a length is BAD_ARG (status.h: nothing was read) */
	{
		struct nrvp np = { HV_NRV2B, 8 };

		p = 99;
		st = kuncoat_nrv2_decode(np.variant, np.bits, b, 10, NULL, 100, &p);
		CK(st == KUNCOAT_BAD_ARG && p == 0);
		st = kuncoat_nrv2_decode(np.variant, np.bits, b, 10, res, 0, &p);
		CK(st == KUNCOAT_STOPPED && p == 0);
		st = kuncoat_nrv2_decode(np.variant, np.bits, NULL, 10, res, 100, &p);
		CK(st == KUNCOAT_BAD_ARG && p == 0);
		st = kuncoat_nrv2_decode(np.variant, np.bits, b, 0, res, 100, &p);
		CK(st == KUNCOAT_TRUNCATED && p == 0);
		st = kuncoat_nrv2_decode(np.variant, np.bits, b, 10, res, 100, NULL);
		CK(hv_status_ok(st));
	}
}

static void ap_crafted(void)
{
	uint8_t b[600], hist[4000];
	struct hv_tw w;
	uint64_t p;
	enum kuncoat_status st;

	AT();
	/* control */
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a'); hv_ap_lit(&w, 'b'); hv_ap_short(&w, 2, 3); hv_ap_end(&w);
	st = call(1, NULL, b, w.n, 100, &p);
	CK(st == KUNCOAT_OK && p == 5 && !memcmp(res, "ababa", 5));
	st = call(1, NULL, b, w.n, 5, &p);
	CKF(st == KUNCOAT_OK || st == KUNCOAT_STOPPED, "cap == size: %s", kuncoat_status_name(st));
	CK(p == 5);
	st = call(1, NULL, b, w.n, 4, &p);
	CK(st == KUNCOAT_STOPPED && p == 4);
	/* each short form reaching one byte past the output */
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a'); hv_ap_short(&w, 2, 2); hv_ap_end(&w);
	st = call(1, NULL, b, w.n, 100, &p);
	CKF(st == KUNCOAT_CORRUPT, "short form past the output: %s", kuncoat_status_name(st));
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a'); hv_ap_single(&w, 2); hv_ap_end(&w);
	st = call(1, NULL, b, w.n, 100, &p);
	CKF(st == KUNCOAT_CORRUPT, "single byte past the output: %s", kuncoat_status_name(st));
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a'); hv_ap_match(&w, 2, 5); hv_ap_end(&w);
	st = call(1, NULL, b, w.n, 100, &p);
	CKF(st == KUNCOAT_CORRUPT, "long form past the output: %s", kuncoat_status_name(st));
	/* the offset reused before any was set */
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a'); w.lwm = 0; w.last = 0; hv_ap_rep(&w, 4); hv_ap_end(&w);
	st = call(1, NULL, b, w.n, 100, &p);
	CKF(st == KUNCOAT_CORRUPT, "rep before any offset: %s", kuncoat_status_name(st));
	/* the end marker in the middle: the rest is not read */
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a'); hv_ap_end(&w); hv_ap_lit(&w, 'b');
	st = call(1, NULL, b, w.n, 100, &p);
	CK(st == KUNCOAT_OK && p == 1);
	/* a gamma code of ones that never stops, behind a match opcode: input of 0xFF */
	{
		uint8_t o[400];

		memset(o, 0xFF, sizeof o);
		o[0] = 'a';
		AT();
		st = call(1, NULL, o, sizeof o, 100, &p);
		CK(hv_status_ok(st) && st != KUNCOAT_OK);
		memset(o, 0, sizeof o);
		st = call(1, NULL, o, sizeof o, 100, &p);
		CK(hv_status_ok(st));
		memset(o, 0xAA, sizeof o);
		st = call(1, NULL, o, sizeof o, 100, &p);
		CK(hv_status_ok(st));
	}
	/* a 4 GB length against a small buffer: bounded by the cap, quick */
	hv_tw_init(&w, b, sizeof b, 8, hist, sizeof hist);
	hv_ap_first(&w, 'a');
	hv_tw_bit(&w, 1); hv_tw_bit(&w, 0);                 /* a match: the gamma of the high offset */
	hv_ap_gamma(&w, 3);                                 /* lwm 0: distance high 0 */
	hv_tw_byte(&w, 1);                                  /* low byte: distance 1 */
	{
		unsigned k;

		for (k = 0; k < 31; k++) {                  /* a gamma value of ~2^31 */
			hv_tw_bit(&w, 1);
			hv_tw_bit(&w, k != 30);
		}
	}
	hv_ap_end(&w);
	AT();
	st = call(1, NULL, b, w.n, 100, &p);
	CKF(st == KUNCOAT_STOPPED && p == 100 && res[99] == 'a', "huge length: %s %llu", kuncoat_status_name(st),
	    (unsigned long long)p);
	/* the end marker with its last byte missing: "41 C0" is 'A', the bits 1 1 0 and then the
	 * byte of the short-match form, which is absent and read as 0, which is the end marker.
	 * A stream cut one byte before its end is reported complete. */
	{
		static const uint8_t cut[2] = { 0x41, 0xC0 };

		st = call(1, NULL, cut, 2, 100, &p);
		CK(p == 1 && res[0] == 'A');
		CK(st != KUNCOAT_OK);
	}
	/* the first byte alone; no input; no room */
	st = call(1, NULL, b, 1, 100, &p);
	CK(hv_status_ok(st) && p >= 1 && res[0] == b[0]);
	st = kuncoat_aplib_decode(b, 0, res, 10, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_aplib_decode(b, 5, res, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_aplib_decode(b, 5, res, 10, NULL);
	CK(hv_status_ok(st));
}

/* ---- LZMAT: crafted ------------------------------------------------------------------------------- */

static void lzmat_crafted(void)
{
	uint8_t b[600];
	uint64_t p;
	enum kuncoat_status st;
	size_t n, k;

	AT();
	/* the smallest input is two bytes: first literal and a control byte */
	b[0] = 'x'; b[1] = 0;
	st = call(2, NULL, b, 2, 10, &p);
	CK(hv_status_ok(st) && p >= 1 && res[0] == 'x');
	st = call(2, NULL, b, 1, 10, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = call(2, NULL, b, 0, 10, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_lzmat_decode(b, 5, res, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	/* every input of every length that is 0x00, 0xFF, 0x55, 0xAA, 0x80: the decoder walks
	 * nibbles off the end of the data and must clamp (guard page after the input) */
	{
		static const uint8_t fill[] = { 0x00, 0xFF, 0x55, 0xAA, 0x80, 0x0F, 0xF0, 0x81, 0x7F };
		unsigned f;

		for (f = 0; f < sizeof fill; f++)
			for (n = 2; n <= 70; n++) {
				memset(b, fill[f], n);
				hv_at(1000 + f, n);
				st = call(2, NULL, b, n, 4096, &p);
				CK(hv_status_ok(st));
				st = call(2, NULL, b, n, 7, &p);
				CK(hv_status_ok(st));
			}
	}
	/* the long run (a length of 0x10110 reads dwords from the stream) from garbage: cap 1 MB */
	{
		static uint8_t g[300];

		memset(g, 0xFF, sizeof g);
		g[0] = 'a';
		g[1] = 0xFF;
		AT();
		st = call(2, NULL, g, sizeof g, 65536, &p);
		CK(hv_status_ok(st));
	}
	/* a distance past the output */
	b[0] = 'a'; b[1] = 0x80; b[2] = (uint8_t)(9 << 1); b[3] = 0x00;
	st = call(2, NULL, b, 4, 10, &p);
	CKF(st == KUNCOAT_CORRUPT && p == 1, "dist past: %s %llu", kuncoat_status_name(st), (unsigned long long)p);
	/* all of the valid forms are in the sweeps; one explicit: 'a', then 7 of 'a' at distance 1 */
	b[0] = 'a'; b[1] = 0x80; b[2] = 0x00; b[3] = 0x04;
	st = call(2, NULL, b, 4, 8, &p);
	CK(p == 8 && !memcmp(res, "aaaaaaaa", 8));
	(void)k;
}

/* ---- ASPACK ------------------------------------------------------------------------------------------ */

static void aspack_garbage(void)
{
	uint64_t rs = 0xA5Au;
	uint8_t in[400];
	unsigned it;
	uint64_t p;
	enum kuncoat_status st;

	for (it = 0; it < 6000; it++) {
		size_t n = hv_rng32(&rs) % 400u, cap = 1u + hv_rng32(&rs) % 3000u, i;
		unsigned mode = it % 8u;

		for (i = 0; i < n; i++) {
			uint32_t r = hv_rng32(&rs);

			in[i] = mode == 0 ? (uint8_t)r : mode == 1 ? 0 : mode == 2 ? 0xFF : mode == 3 ? (uint8_t)(i * 37u) :
				mode == 4 ? (uint8_t)(r % 4u ? 0 : r >> 8) : mode == 5 ? (uint8_t)(0xA5 ^ (r % 3u)) :
				mode == 6 ? (uint8_t)(i < 8 ? r : 0) : (uint8_t)(i & 1u ? 0xFF : 0x01);
		}
		hv_at(2000, it);
		st = call(3, NULL, in, n, cap, &p);
		(void)st;
		if (hv_fails > 5)
			return;
	}
	/* the empty input and the empty output */
	st = kuncoat_aspack_decode(in, 0, res, 10, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_aspack_decode(in, 10, res, 0, &p);
	CK(st == KUNCOAT_CORRUPT && p == 0);
	st = kuncoat_aspack_decode(in, 10, res, 10, NULL);
	CK(hv_status_ok(st));
}

static void aspack_filter(void)
{
	uint8_t buf[64], ref[64];
	unsigned mark, n;
	size_t i;

	/* an n-byte buffer sits against a PROT_NONE page: nothing is read or written past it,
	 * for every marker and every length from 0 to 40 */
	for (n = 0; n <= 40; n++)
		for (mark = 0; mark < 256; mark += 15) {
			uint8_t *g = hv_gb_at(&gout, n);

			for (i = 0; i < n; i++)
				g[i] = (uint8_t)((i % 3u == 0 ? 0xE8 : i % 3u == 1 ? mark : 0x11 + i));
			memcpy(buf, g, n);
			hv_at(3000 + n, mark);
			kuncoat_aspack_e8e9_decode(g, n, (uint8_t)mark);
			if (n < 7)
				CKF(n == 0 || !memcmp(g, buf, n), "n %u < 7 was modified", n);
		}
	/* a known case: E8 mark b1 b2 b3: the operand is rotated and made relative; the five
	 * bytes before the end of a 7 byte buffer are all the scan looks at */
	memset(buf, 0x90, sizeof buf);
	buf[10] = 0xE8; buf[11] = 0x77; buf[12] = 0x00; buf[13] = 0x00; buf[14] = 0x30;
	memcpy(ref, buf, sizeof buf);
	kuncoat_aspack_e8e9_decode(buf, 40, 0x77);
	CK(memcmp(buf, ref, 40) != 0);                      /* it rewrote the operand */
	CK(buf[10] == 0xE8 && !memcmp(buf, ref, 10));       /* and nothing before the opcode */
	/* a different marker leaves it alone; NULL and short buffers are no-ops */
	memcpy(buf, ref, sizeof buf);
	kuncoat_aspack_e8e9_decode(buf, 40, 0x78);
	CK(!memcmp(buf, ref, 40));
	kuncoat_aspack_e8e9_decode(NULL, 40, 0x77);
	kuncoat_aspack_e8e9_decode(buf, 0, 0x77);
	kuncoat_aspack_e8e9_decode(buf, 6, 0x77);
	CK(!memcmp(buf, ref, 40));
	/* an operand that is itself an E8 + marker (the `k += 4` rule): the second is not rewritten */
	memset(buf, 0x90, sizeof buf);
	buf[0] = 0xE9; buf[1] = 0x77; buf[2] = 0xE8; buf[3] = 0x77; buf[4] = 0; buf[5] = 0xE8; buf[6] = 0x77;
	buf[7] = 0; buf[8] = 0; buf[9] = 0;
	memcpy(ref, buf, sizeof buf);
	kuncoat_aspack_e8e9_decode(buf, 30, 0x77);
	CK(hv_status_ok(KUNCOAT_OK));
	(void)ref;
}

HV_GROUP(nrv_crafted)
HV_GROUP(ap_crafted)
HV_GROUP(lzmat_crafted)
HV_GROUP(aspack_garbage)
HV_GROUP(aspack_filter)

int main(void)
{
	unsigned i;
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, 70000) || !hv_gb_init(&gout, 70000)) {
		printf("hostile_lzbit: cannot map guard buffers\n");
		return 1;
	}
	for (i = 0; i < 9; i++)
		ok &= make_nrv(&v_nrv[i], P[i].variant, (unsigned)P[i].bits, 100u + i, 2500);
	ok &= make_ap(&v_ap[0], 7, 2500);
	ok &= make_ap(&v_ap[1], 8, 900);
	ok &= make_lzmat_even(&v_lm[0], 9, 3000);
	ok &= make_lzmat_even(&v_lm[1], 10, 1200);
	CK(ok);
	hv_expect_clean("lzbit sweeps", sweeps, NULL, 40);
	hv_expect_clean("aplib truncation", ap_fab, NULL, 20);
	hv_expect_clean("lzmat truncation", lm_fab, NULL, 20);
	hv_expect_clean("nrv2 crafted", hv_grp_nrv_crafted, NULL, 20);
	hv_expect_clean("aplib crafted", hv_grp_ap_crafted, NULL, 20);
	hv_expect_clean("lzmat crafted", hv_grp_lzmat_crafted, NULL, 20);
	hv_expect_clean("aspack garbage", hv_grp_aspack_garbage, NULL, 30);
	hv_expect_clean("aspack e8e9 filter", hv_grp_aspack_filter, NULL, 10);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("hostile_lzbit");
}
