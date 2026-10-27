/*
 * decomp/rar - kuncoat_rar3_decode (RAR 2.9/3.x: LZ, PPMd blocks, a fixed set of seven filters) and kuncoat_rar5_decode (RAR 5: LZ,
 * four filters, tables carried between blocks). The cap IS the entry's declared size (rar3.h): reaching it is OK, ending short of it
 * is TRUNCATED (input ran out) or CORRUPT.
 *
 * Input layout: [mode: bit 0 = RAR5, bit 1 = pass the filter scratch][stream], so one mutation moves a stream to the other decoder
 * and drops the scratch (a filter that needs it is then UNSUPPORTED, not a fault). Seeds: random valid streams of
 * tests/lib/uncoat/hostile_rarvec.h (RAR3 LZ; RAR5 LZ in two blocks, the second with no tables; RAR5 with x86, ARM and delta
 * filters). The true size is the declared size when the driver's cap is at least it; under a smaller cap the first cap bytes are
 * the stream's (a filter whose range is not all there is not applied: DC_NO_CAP_PREFIX, so the second call under a smaller cap is
 * made and bounded but its bytes are not compared). Held: dc_buf_run (decomp_common.h).
 */
#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"
#include "../../lib/uncoat/hostile_lzhenc.h"
#include "../../lib/uncoat/hostile_rarenc.h"
#include "../../lib/uncoat/hostile_rarvec.h"

static uint8_t scratch5[KUNCOAT_RAR5_SCRATCH];
static uint8_t scratch3[KUNCOAT_RAR3_SCRATCH];
static struct vec v5a, v5f, v3a, v3b;
static struct dc_plain plains[8];
static size_t n_plain;

static enum kuncoat_status rar_fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	unsigned mode = n ? in[0] : 0u;

	(void)par;
	if (mode & 1u)
		return kuncoat_rar5_decode(n ? in + 1 : in, n ? n - 1u : 0u, out, cap, (mode & 2u) ? scratch5 : NULL, sizeof scratch5, produced);
	return kuncoat_rar3_decode(n ? in + 1 : in, n ? n - 1u : 0u, out, cap, (mode & 2u) ? scratch3 : NULL, sizeof scratch3, produced);
}

static void add(struct fz_corpus *c, const char *name, unsigned mode, const struct vec *v)
{
	static uint8_t b[MAXV + 8];

	if (n_plain >= 8)
		return;
	b[0] = (uint8_t)mode;
	memcpy(b + 1, v->in, v->n);
	plains[n_plain].p = v->want;
	plains[n_plain].n = v->wn;
	n_plain++;
	fz_corpus_add(c, name, b, 1 + v->n);
}

static void seeds(struct fz_corpus *c)
{
	n_plain = 0;
	if (make_r3(&v3a, 61, 1800))
		add(c, "r3-lz", 0, &v3a);
	if (make_r3(&v3b, 62, 7000))
		add(c, "r3-lz-long", 2, &v3b);
	if (make_r5(&v5a, 63, 3000, 0))
		add(c, "r5-lz-2blocks", 1, &v5a);
	if (make_r5(&v5f, 64, 5000, 1))
		add(c, "r5-filters", 3, &v5f);
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const struct dc_buf d = { rar_fn, NULL, DC_DECLARED_SIZE | DC_NO_CAP_PREFIX, plains, 8 };
	uint64_t produced;

	return (int)dc_buf_run(c, &d, in, n, &produced);
}

FZ_ADAPTER(rar, .name = "kuncoat/rar", .covers = "kuncoat_rar3_decode kuncoat_rar5_decode", .shape = FZ_BYTES, .seeds = seeds, .run = run,
	   .flags = FZ_MAY_HIT_CAP, .steps_base = 4000000u, .backstop_s = 1800);
