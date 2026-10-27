/*
 * decomp/lzbit - the bit-stream LZ decoders that write into a caller's buffer: kuncoat_nrv2_decode (B, D, E at 8, 16 and 32 bit
 * tag words), kuncoat_aplib_decode and kuncoat_lzmat_decode. None of them has a third-party reference on this host, so the
 * oracle is the writer: the seeds are random valid scripts of the writers in tests/lib/uncoat/hostile_lzvec.h (the same ones
 * the sweeps of hostile_lzbit.c use) and a seed must give back the bytes it was made from. What is held for every input is
 * dc_buf_run (decomp_common.h): status in the enum, produced <= cap, a smaller cap changes no byte and is not reported as the
 * whole answer. A cap of zero is refused by contract. Not held (documented, hostile_sweep.h): the bytes of a cut stream are a
 * prefix (aPLib and LZMAT hand back bytes a cut stream does not support, silent_loss_uncoat.c); LZMAT may say OK under a cap
 * below its size (it has no end marker; DC_CAP_OK_MAY).
 *
 * nrv2: the first byte picks variant (bits 0-1: B D E, 3 is not one) and tag width (bits 2-3: 8 16 32, 3 is not one), the rest is
 * the stream, so a mutation reaches the refusal of a variant or width the decoder does not have.
 */
#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"
#include "../../lib/uncoat/hostile_nrvenc.h"
#include "../../lib/uncoat/hostile_lzvec.h"

static struct vec v_nrv[9], v_ap[3], v_lm[3];
static struct dc_plain pl_nrv[16], pl_ap[8], pl_lm[8];

static void put_seed(struct fz_corpus *c, const char *name, uint8_t head, int has_head, const struct vec *v, struct dc_plain *pl, size_t *np)
{
	static uint8_t b[8001 + 1];
	size_t n = 0;

	if (has_head)
		b[n++] = head;
	memcpy(b + n, v->in, v->n);
	n += v->n;
	pl[*np].p = v->want;
	pl[*np].n = v->wn;
	(*np)++;
	fz_corpus_add(c, name, b, n);
}

/* ---- nrv2 -------------------------------------------------------------------------------------- */

static const int nrv_width[4] = { 8, 16, 32, 0 };

static enum kuncoat_status nrv_fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	unsigned h = n ? in[0] : 0u;

	(void)par;
	return kuncoat_nrv2_decode((int)(h & 3u), nrv_width[(h >> 2) & 3u], n ? in + 1 : in, n ? n - 1u : 0u, out, cap, produced);
}

static const struct dc_buf dcb_nrv = { nrv_fn, NULL, 0, pl_nrv, 16 };

static void nrv_seeds(struct fz_corpus *c)
{
	static const char *const name[9] = { "b8", "b16", "b32", "d8", "d16", "d32", "e8", "e16", "e32" };
	size_t np = 0;
	unsigned i;

	for (i = 0; i < 9; i++) {
		unsigned variant = i / 3u, w = i % 3u;

		if (make_nrv(&v_nrv[i], (int)variant, 8u << w, 100u + i, 2500))
			put_seed(c, name[i], (uint8_t)(variant | w << 2), 1, &v_nrv[i], pl_nrv, &np);
	}
}

static int nrv_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced;

	return (int)dc_buf_run(c, &dcb_nrv, in, n, &produced);
}

FZ_ADAPTER(nrv2, .name = "kuncoat/nrv2", .covers = "kuncoat_nrv2_decode", .shape = FZ_BYTES, .seeds = nrv_seeds, .run = nrv_run, .flags = FZ_MAY_HIT_CAP);

/* ---- aplib -------------------------------------------------------------------------------------- */

static enum kuncoat_status ap_fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	(void)par;
	return kuncoat_aplib_decode(in, n, out, cap, produced);
}

static const struct dc_buf dcb_ap = { ap_fn, NULL, DC_EXACT_MAY_STOP, pl_ap, 8 };

static void ap_seeds(struct fz_corpus *c)
{
	size_t np = 0;
	unsigned i;

	for (i = 0; i < 3; i++)
		if (make_ap(&v_ap[i], 200u + i, i == 0 ? 400u : i == 1 ? 2500u : 6000u))
			put_seed(c, i == 0 ? "short" : i == 1 ? "mid" : "long", 0, 0, &v_ap[i], pl_ap, &np);
}

static int ap_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced;

	return (int)dc_buf_run(c, &dcb_ap, in, n, &produced);
}

FZ_ADAPTER(aplib, .name = "kuncoat/aplib", .covers = "kuncoat_aplib_decode", .shape = FZ_BYTES, .seeds = ap_seeds, .run = ap_run);

/* ---- lzmat -------------------------------------------------------------------------------------- */

static enum kuncoat_status lm_fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	(void)par;
	return kuncoat_lzmat_decode(in, n, out, cap, produced);
}

static const struct dc_buf dcb_lm = { lm_fn, NULL, DC_CAP_OK_MAY, pl_lm, 8 };

static void lm_seeds(struct fz_corpus *c)
{
	size_t np = 0;
	unsigned i;

	for (i = 0; i < 3; i++)
		if (make_lzmat_even(&v_lm[i], 300u + i, i == 0 ? 200u : i == 1 ? 1500u : 6000u))
			put_seed(c, i == 0 ? "short" : i == 1 ? "mid" : "long", 0, 0, &v_lm[i], pl_lm, &np);
}

static int lm_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint64_t produced;

	return (int)dc_buf_run(c, &dcb_lm, in, n, &produced);
}

FZ_ADAPTER(lzmat, .name = "kuncoat/lzmat", .covers = "kuncoat_lzmat_decode", .shape = FZ_BYTES, .seeds = lm_seeds, .run = lm_run);
