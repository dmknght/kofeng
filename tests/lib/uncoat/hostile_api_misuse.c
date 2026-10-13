/*
 * hostile_api_misuse - every public decoder entry point of libuncoat called with the
 * arguments a careless or hostile caller passes: NULL where a pointer is required, a
 * zero length, an output of zero bytes, a NULL `produced`.
 *
 * status.h says what such a request is: KUNCOAT_BAD_ARG, "the request itself is not usable,
 * and nothing was read: a null buffer, ...". Each call runs in a forked child (a crash is a
 * finding and must not end the runner) and the outcome - the status, or a crash - is
 * tabulated. Three questions are then asked of the table, each as one KNOWN-MISS because
 * each has one cause:
 *
 *   1. does any entry point CRASH on a NULL `produced` while its siblings accept it?
 *   2. does any CRASH on a NULL state, request, io or sink - or a NULL output with room?
 *   3. does a NULL input or output buffer get any status other than BAD_ARG?
 *
 * and then the same buffer given as input and as output (and an output that starts a few bytes
 * before or after the input) to every buffer decoder, which must not read or write outside it.
 *
 * kuncoat_transform is the one entry point that answers all three correctly (api_transform.c
 * covers it); kuncoat_cipher and kuncoat_coding trust their caller by contract (codings.h,
 * ciphers.h) and are not called here.
 */

#define _GNU_SOURCE

#include "hostile_common.h"

#include <decompressors/inflate.h>
#include <decompressors/lzx.h>

static int zsink(void *u, const uint8_t *p, uint32_t n)
{
	(void)u; (void)p; (void)n;
	return 1;
}

static uint8_t g_in[64], g_out[64];
static struct kuncoat_inflate *g_inf;
static struct kuncoat_lzw *g_lzw;
static struct kuncoat_lzx *g_lzx;
static struct kuncoat_lzhuf *g_lh;
static struct kuncoat_bunzip *g_bz;

/* A case returns its status; the child stores it where the parent reads it. */
#define CASE(NAME, EXPR) \
	static int c_##NAME(void *arg) \
	{ \
		uint64_t p = 0; \
		enum kuncoat_status st; \
		(void)arg; (void)p; \
		memset(g_in, 0x41, sizeof g_in); \
		st = (EXPR); \
		hv_at(1, (uint64_t)(int)st); \
		return 0; \
	}

#define IO(IN, N, SINK) ((struct kuncoat_io){ { (IN), (N) }, (SINK), NULL, 0, 0 })

CASE(inflate_io_null, ({ g_in[0] = 3; kuncoat_inflate(g_inf, NULL); }))
CASE(inflate_state_null, ({ struct kuncoat_io io = IO(g_in, 8, zsink); kuncoat_inflate(NULL, &io); }))
CASE(inflate_in_null, ({ struct kuncoat_io io = IO(NULL, 8, zsink); kuncoat_inflate(g_inf, &io); }))
CASE(inflate_sink_null, ({ struct kuncoat_io io = IO(g_in, 8, NULL); g_in[0] = 0x01; g_in[1] = 0x01; g_in[2] = 0x00; g_in[3] = 0xFE; g_in[4] = 0xFF; g_in[5] = 'a'; kuncoat_inflate(g_inf, &io); }))
CASE(inflate_seeded_io_null, ({ kuncoat_inflate_seeded(g_inf, NULL, NULL); }))
CASE(lzw_state_null, kuncoat_lzw_decode(NULL, g_in, 8, zsink, NULL, &p))
CASE(lzw_in_null, kuncoat_lzw_decode(g_lzw, NULL, 8, zsink, NULL, &p))
CASE(lzw_sink_null, ({ g_in[0] = 0x80; g_in[1] = 0x20; g_in[2] = 0x40; kuncoat_lzw_decode(g_lzw, g_in, 8, NULL, NULL, &p); }))
CASE(lzw_produced_null, kuncoat_lzw_decode(g_lzw, g_in, 8, zsink, NULL, NULL))
CASE(ovba_in_null, kuncoat_ovba_decode(NULL, 8, zsink, NULL, &p))
CASE(ovba_sink_null, ({ g_in[0] = 1; g_in[1] = 0; g_in[2] = 0x30; kuncoat_ovba_decode(g_in, 8, NULL, NULL, &p); }))
CASE(ovba_produced_null, kuncoat_ovba_decode(g_in, 8, zsink, NULL, NULL))
CASE(a85_in_null, kuncoat_a85_decode(NULL, 8, g_out, 8, &p))
CASE(a85_out_null, ({ memset(g_in, '9', 8); kuncoat_a85_decode(g_in, 8, NULL, 8, &p); }))
CASE(a85_produced_null, kuncoat_a85_decode(g_in, 8, g_out, 8, NULL))
CASE(ahx_in_null, kuncoat_ahx_decode(NULL, 8, g_out, 8, &p))
CASE(ahx_out_null, ({ memset(g_in, '4', 8); kuncoat_ahx_decode(g_in, 8, NULL, 8, &p); }))
CASE(ahx_produced_null, kuncoat_ahx_decode(g_in, 8, g_out, 8, NULL))
CASE(rle_in_null, kuncoat_rle_decode(NULL, 8, zsink, NULL, &p))
CASE(rle_sink_null, ({ g_in[0] = 0; g_in[1] = 'a'; g_in[2] = 128; kuncoat_rle_decode(g_in, 8, NULL, NULL, &p); }))
CASE(rle_produced_null, kuncoat_rle_decode(g_in, 8, zsink, NULL, NULL))
CASE(bunzip_state_null, kuncoat_bunzip_decode(NULL, g_in, 8, zsink, NULL, &p))
CASE(bunzip_in_null, kuncoat_bunzip_decode(g_bz, NULL, 8, zsink, NULL, &p))
CASE(bunzip_sink_null, kuncoat_bunzip_decode(g_bz, g_in, 8, NULL, NULL, &p))
CASE(bunzip_produced_null, kuncoat_bunzip_decode(g_bz, g_in, 8, zsink, NULL, NULL))
CASE(lzhuf_state_null, kuncoat_lzhuf_decode(NULL, KUNCOAT_LZHUF_LH5, g_in, 8, 10, zsink, NULL, &p))
CASE(lzhuf_in_null, kuncoat_lzhuf_decode(g_lh, KUNCOAT_LZHUF_LH5, NULL, 8, 10, zsink, NULL, &p))
CASE(lzhuf_sink_null, kuncoat_lzhuf_decode(g_lh, KUNCOAT_LZHUF_LH5, g_in, 8, 10, NULL, NULL, &p))
CASE(lzhuf_produced_null, kuncoat_lzhuf_decode(g_lh, KUNCOAT_LZHUF_LH5, g_in, 8, 10, zsink, NULL, NULL))
CASE(lzx_state_null, ({ struct kuncoat_lzx_req rq = { 15, 0, 10 }; struct kuncoat_io io = IO(g_in, 8, zsink); kuncoat_lzx_decode(NULL, &rq, &io); }))
CASE(lzx_req_null, ({ struct kuncoat_io io = IO(g_in, 8, zsink); kuncoat_lzx_decode(g_lzx, NULL, &io); }))
CASE(lzx_io_null, ({ struct kuncoat_lzx_req rq = { 15, 0, 10 }; kuncoat_lzx_decode(g_lzx, &rq, NULL); }))
CASE(lzx_in_null, ({ struct kuncoat_lzx_req rq = { 15, 0, 10 }; struct kuncoat_io io = IO(NULL, 8, zsink); kuncoat_lzx_decode(g_lzx, &rq, &io); }))
CASE(lzx_sink_null, ({ struct kuncoat_lzx_req rq = { 15, 0, 10 }; struct kuncoat_io io = IO(g_in, 8, NULL); kuncoat_lzx_decode(g_lzx, &rq, &io); }))
CASE(lzma_in_null, kuncoat_lzma_decode(3, 0, 2, NULL, 8, g_out, 8, &p))
CASE(lzma_out_null, kuncoat_lzma_decode(3, 0, 2, g_in, 8, NULL, 8, &p))
CASE(lzma_produced_null, kuncoat_lzma_decode(3, 0, 2, g_in, 8, g_out, 8, NULL))
CASE(lzma2_in_null, kuncoat_lzma2_decode(NULL, 8, g_out, 8, &p))
CASE(lzma2_out_null, kuncoat_lzma2_decode(g_in, 8, NULL, 8, &p))
CASE(lzma2_produced_null, kuncoat_lzma2_decode(g_in, 8, g_out, 8, NULL))
CASE(aplib_in_null, kuncoat_aplib_decode(NULL, 8, g_out, 8, &p))
CASE(aplib_out_null, kuncoat_aplib_decode(g_in, 8, NULL, 8, &p))
CASE(aplib_produced_null, kuncoat_aplib_decode(g_in, 8, g_out, 8, NULL))
CASE(nrv2_in_null, kuncoat_nrv2_decode(0, 8, NULL, 8, g_out, 8, &p))
CASE(nrv2_out_null, kuncoat_nrv2_decode(0, 8, g_in, 8, NULL, 8, &p))
CASE(nrv2_produced_null, kuncoat_nrv2_decode(0, 8, g_in, 8, g_out, 8, NULL))
CASE(lzmat_in_null, kuncoat_lzmat_decode(NULL, 8, g_out, 8, &p))
CASE(lzmat_out_null, kuncoat_lzmat_decode(g_in, 8, NULL, 8, &p))
CASE(lzmat_produced_null, kuncoat_lzmat_decode(g_in, 8, g_out, 8, NULL))
CASE(aspack_in_null, kuncoat_aspack_decode(NULL, 8, g_out, 8, &p))
CASE(aspack_out_null, kuncoat_aspack_decode(g_in, 8, NULL, 8, &p))
CASE(aspack_produced_null, kuncoat_aspack_decode(g_in, 8, g_out, 8, NULL))
CASE(rar3_in_null, kuncoat_rar3_decode(NULL, 8, g_out, 8, NULL, 0, &p))
CASE(rar3_out_null, kuncoat_rar3_decode(g_in, 8, NULL, 8, NULL, 0, &p))
CASE(rar3_produced_null, kuncoat_rar3_decode(g_in, 8, g_out, 8, NULL, 0, NULL))
CASE(rar5_in_null, kuncoat_rar5_decode(NULL, 8, g_out, 8, NULL, 0, &p))
CASE(rar5_out_null, kuncoat_rar5_decode(g_in, 8, NULL, 8, NULL, 0, &p))
CASE(rar5_produced_null, kuncoat_rar5_decode(g_in, 8, g_out, 8, NULL, 0, NULL))

/* ---- input and output sharing one buffer ------------------------------------------------------ */

/*
 * A caller that decodes in place hands the same bytes in as the room for the output, or an
 * output that starts a few bytes before or after the input. The buffer decoders read their
 * input while they write their output, so the answer is garbage: what must hold is that nothing
 * is read or written outside the one buffer (it ends at a PROT_NONE page) and the status and
 * count are still sane. Each decoder, each offset, several fills.
 */
static struct hv_gb g_ov;

static int overlap_all(void *arg)
{
	enum { NDEC = 14 };
	size_t total = 3000, off, f, dec, in_len;
	static const size_t offs[] = { 0, 1, 2, 3, 7, 16, 100 };
	uint64_t rs = 0x0FF5E7u;

	(void)arg;
	for (dec = 0; dec < NDEC; dec++)
		for (f = 0; f < 5; f++)
			for (off = 0; off < sizeof offs / sizeof offs[0]; off++) {
				uint8_t *base = hv_gb_at(&g_ov, total);
				uint8_t *in, *out;
				size_t cap, i;
				uint64_t p = 0xFEEDull;
				enum kuncoat_status st = KUNCOAT_OK;

				for (i = 0; i < total; i++) {
					uint32_t r = hv_rng32(&rs);

					base[i] = f == 0 ? (uint8_t)r : f == 1 ? 0 : f == 2 ? 0xFF : f == 3 ? (uint8_t)(i * 7u) :
						  (uint8_t)(r % 3u ? 0x30 + r % 40u : 0x7E);
				}
				if (dec & 1u) {                       /* the output starts before the input */
					out = base;
					in = base + offs[off];
					in_len = total - offs[off];
					cap = total;
				} else {                              /* the output starts after it */
					in = base;
					out = base + offs[off];
					in_len = total;
					cap = total - offs[off];
				}
				if (cap > 2000)
					cap = 2000;
				hv_at(1000u + (uint64_t)dec, (uint64_t)(f * 100u + off));
				switch (dec / 2u) {
				case 0: st = kuncoat_lzma_decode(3, 0, 2, in, in_len, out, cap, &p); break;
				case 1: st = kuncoat_lzma2_decode(in, in_len, out, cap, &p); break;
				case 2: st = kuncoat_aplib_decode(in, in_len, out, cap, &p); break;
				case 3: st = kuncoat_nrv2_decode(KUNCOAT_NRV2E, 8, in, in_len, out, cap, &p); break;
				case 4: st = kuncoat_lzmat_decode(in, in_len, out, cap, &p); break;
				case 5: st = kuncoat_aspack_decode(in, in_len, out, cap, &p); break;
				default:
					if (dec == 12)
						st = kuncoat_a85_decode(in, in_len, out, cap, &p);
					else
						st = kuncoat_ahx_decode(in, in_len, out, cap, &p);
					break;
				}
				CKF(hv_status_ok(st) && p <= cap, "decoder %zu fill %zu offset %zu: %s, produced %llu of %zu", dec, f, offs[off],
				    kuncoat_status_name(st), (unsigned long long)p, cap);
				if (hv_fails > 5)
					return 1;
			}
	/* the two RAR decoders, with a scratch in the same buffer as well */
	for (off = 0; off < 3; off++) {
		uint8_t *base = hv_gb_at(&g_ov, total);
		uint64_t p = 0;
		size_t i;

		for (i = 0; i < total; i++)
			base[i] = (uint8_t)(hv_rng32(&rs) % 4u ? 0 : hv_rng32(&rs));
		base[0] &= 0x7F;
		hv_at(2000, off);
		CK(hv_status_ok(kuncoat_rar3_decode(base, total, base + off, 1500, base + 1500, 1000, &p)) && p <= 1500);
		CK(hv_status_ok(kuncoat_rar5_decode(base, total, base + off, 1500, base + 1500, 1000, &p)) && p <= 1500);
	}
	return hv_fails != 0;
}

enum { G_PRODUCED, G_OBJECT, G_BUFFER };

struct mcase {
	const char *name;
	int       (*fn)(void *);
	int         group;
};

#define M(NAME, GRP) { #NAME, c_##NAME, GRP }

static const struct mcase cases[] = {
	M(inflate_io_null, G_OBJECT), M(inflate_state_null, G_OBJECT), M(inflate_in_null, G_BUFFER),
	M(inflate_sink_null, G_OBJECT), M(inflate_seeded_io_null, G_OBJECT),
	M(lzw_state_null, G_OBJECT), M(lzw_in_null, G_BUFFER), M(lzw_sink_null, G_OBJECT), M(lzw_produced_null, G_PRODUCED),
	M(ovba_in_null, G_BUFFER), M(ovba_sink_null, G_OBJECT), M(ovba_produced_null, G_PRODUCED),
	M(a85_in_null, G_BUFFER), M(a85_out_null, G_BUFFER), M(a85_produced_null, G_PRODUCED),
	M(ahx_in_null, G_BUFFER), M(ahx_out_null, G_BUFFER), M(ahx_produced_null, G_PRODUCED),
	M(rle_in_null, G_BUFFER), M(rle_sink_null, G_OBJECT), M(rle_produced_null, G_PRODUCED),
	M(bunzip_state_null, G_OBJECT), M(bunzip_in_null, G_BUFFER), M(bunzip_sink_null, G_OBJECT),
	M(bunzip_produced_null, G_PRODUCED),
	M(lzhuf_state_null, G_OBJECT), M(lzhuf_in_null, G_BUFFER), M(lzhuf_sink_null, G_OBJECT),
	M(lzhuf_produced_null, G_PRODUCED),
	M(lzx_state_null, G_OBJECT), M(lzx_req_null, G_OBJECT), M(lzx_io_null, G_OBJECT), M(lzx_in_null, G_BUFFER),
	M(lzx_sink_null, G_OBJECT),
	M(lzma_in_null, G_BUFFER), M(lzma_out_null, G_BUFFER), M(lzma_produced_null, G_PRODUCED),
	M(lzma2_in_null, G_BUFFER), M(lzma2_out_null, G_BUFFER), M(lzma2_produced_null, G_PRODUCED),
	M(aplib_in_null, G_BUFFER), M(aplib_out_null, G_BUFFER), M(aplib_produced_null, G_PRODUCED),
	M(nrv2_in_null, G_BUFFER), M(nrv2_out_null, G_BUFFER), M(nrv2_produced_null, G_PRODUCED),
	M(lzmat_in_null, G_BUFFER), M(lzmat_out_null, G_BUFFER), M(lzmat_produced_null, G_PRODUCED),
	M(aspack_in_null, G_BUFFER), M(aspack_out_null, G_BUFFER), M(aspack_produced_null, G_PRODUCED),
	M(rar3_in_null, G_BUFFER), M(rar3_out_null, G_BUFFER), M(rar3_produced_null, G_PRODUCED),
	M(rar5_in_null, G_BUFFER), M(rar5_out_null, G_BUFFER), M(rar5_produced_null, G_PRODUCED),
};

#define NCASES (sizeof cases / sizeof cases[0])

int main(void)
{
	static char crash_prod[400], crash_obj[600], not_bad[900];
	size_t i;
	unsigned crashed_prod = 0, crashed_obj = 0, not_bad_n = 0, buffer_n = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
	/* every case here is a NULL that crashes in the product: without fork there is no isolation */
	printf("hostile_api_misuse: SKIPPED on this host (needs fork to survive the crashes it records)\n");
	return 0;
#endif
	g_inf = calloc(1, sizeof *g_inf);
	g_lzw = calloc(1, sizeof *g_lzw);
	g_lzx = calloc(1, sizeof *g_lzx);
	g_lh = calloc(1, sizeof *g_lh);
	g_bz = calloc(1, sizeof *g_bz);
	if (!g_inf || !g_lzw || !g_lzx || !g_lh || !g_bz) {
		printf("hostile_api_misuse: out of memory\n");
		return 1;
	}
	for (i = 0; i < NCASES; i++) {
		int r = hv_isolate(cases[i].name, cases[i].fn, NULL, 5);
		int st = (int)hv_prog_p->b;

		if (r != HV_OK) {
			if (cases[i].group == G_PRODUCED) {
				crashed_prod++;
				snprintf(crash_prod + strlen(crash_prod), sizeof crash_prod - strlen(crash_prod), "%s%s",
					 crashed_prod > 1 ? ", " : "", cases[i].name);
			} else {
				crashed_obj++;
				snprintf(crash_obj + strlen(crash_obj), sizeof crash_obj - strlen(crash_obj), "%s%s",
					 crashed_obj > 1 ? ", " : "", cases[i].name);
			}
			continue;
		}
		CKF(hv_status_ok((enum kuncoat_status)st), "%s: status %d", cases[i].name, st);
		if (cases[i].group == G_BUFFER) {
			buffer_n++;
			if (st != (int)KUNCOAT_BAD_ARG) {
				not_bad_n++;
				snprintf(not_bad + strlen(not_bad), sizeof not_bad - strlen(not_bad), "%s%s=%s", not_bad_n > 1 ? ", " : "",
					 cases[i].name, kuncoat_status_name((enum kuncoat_status)st));
			}
		}
	}
	{
		static char what[1200];

		snprintf(what, sizeof what, "%u entry point(s) crash on a NULL `produced` (lzma, aplib, nrv2, lzmat, aspack, bunzip, lzhuf, "
			 "rar3 and rar5 accept it): %s", crashed_prod, crashed_prod ? crash_prod : "none");
		KM_CHECK(crashed_prod == 0, what,
			 "NULL_PRODUCED_CRASH (libuncoat/decoders/textcode.c kuncoat_a85_decode / kuncoat_ahx_decode / kuncoat_rle_decode "
			 "`*produced = 0;` first line, and libuncoat/decompressors/lzw.c kuncoat_lzw_decode, ovba.c kuncoat_ovba_decode: "
			 "no NULL test, the other decoders write it under `if (produced)`) [Inference: low, a caller bug, not attacker input]");
		snprintf(what, sizeof what, "%u entry point(s) crash on a NULL state, request, io, sink or output: %s", crashed_obj,
			 crashed_obj ? crash_obj : "none");
		KM_CHECK(crashed_obj == 0, what,
			 "NULL_OBJECT_CRASH (libuncoat/decompressors/inflate.c kuncoat_inflate_seeded reads io->in and io->sink first; "
			 "lzx.c kuncoat_lzx_decode reads rq->window_bits and io->in before its `!s || !in || !sink` test; lzw.c, rle, a85 "
			 "likewise; the sink is called without a test) [Inference: low, a caller bug]");
		snprintf(what, sizeof what, "%u of %u NULL-buffer calls return something other than BAD_ARG: %s", not_bad_n, buffer_n,
			 not_bad_n ? not_bad : "none");
		KM_CHECK(not_bad_n == 0, what,
			 "NULL_NOT_BAD_ARG (status.h: KUNCOAT_BAD_ARG is 'a null buffer ... nothing was read'; only kuncoat_transform returns it. "
			 "The decompressors answer CORRUPT (a verdict on the INPUT, which status.h says BAD_ARG is not), STOPPED or TRUNCATED) "
			 "[Inference: low: a caller that tests for CORRUPT to mean 'the file is damaged' reports a NULL buffer as a finding]");
	}
#ifdef HV_ASAN
	/* AddressSanitizer reports memcpy-param-overlap for a stream the decoder copies with memcpy
	 * (lzma2's stored chunk, for one) when input and output overlap: that is the misuse itself,
	 * not an out-of-bounds access, and the plain build checks the bounds. */
	printf("  SKIP in place and overlapping buffers under AddressSanitizer (memcpy-param-overlap is the misuse)\n");
	(void)overlap_all;
#else
	if (hv_gb_init(&g_ov, 4000))
		hv_expect_clean("in place and overlapping buffers", overlap_all, NULL, 30);
#endif
	free(g_inf); free(g_lzw); free(g_lzx); free(g_lh); free(g_bz);
	return hv_done("hostile_api_misuse");
}
