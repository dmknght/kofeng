/*
 * decomp/aspack - kuncoat_aspack_decode, the coding ASPack 2.x compresses a PE image with (four Huffman alphabets, a repeat-offset
 * history, a dictionary that can be rebuilt part way). The cap IS the block's declared size (aspack.h).
 *
 * There is no tool on this host that writes it, so the seeds come from the encoder of tests/lib/uncoat/hostile_aspenc.h, written from
 * the decoder's control flow: a seed must decode to the plain text it was made from, under a cap equal to its size. Seeds cover one
 * block and several (rebuild symbols, the carry bit set and not), the flat and the skewed offset alphabet, every offset class
 * the text reaches, repeat offsets, the escape lengths up to 264. Mutations then reach what the decoder defends against: a code
 * that does not fill the space, a length above 15, a delta that wraps, a repeat count past the end of the 757 lengths, a rebuild
 * symbol at the end, an offset before the start, a match past the declared size, an escape symbol outside the table.
 *
 * Held: dc_buf_run (decomp_common.h) with DC_DECLARED_SIZE: the status is in the enum, produced <= cap, a smaller cap changes no
 * byte, a seed decodes whole under a cap equal to its size.
 */
#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"
#include "../../lib/uncoat/hostile_aspenc.h"

static struct hv_aspvec vs[8];
static struct dc_plain plains[8];
static size_t n_plain;

static void add(struct fz_corpus *c, const char *name, uint64_t seed, size_t target, unsigned nseg, int flat)
{
	struct hv_aspvec *v = &vs[n_plain];

	if (n_plain >= 8 || !make_asp(v, seed, target, nseg, flat))
		return;
	plains[n_plain].p = v->want;
	plains[n_plain].n = v->wn;
	n_plain++;
	fz_corpus_add(c, name, v->in, v->n);
}

static void seeds(struct fz_corpus *c)
{
	n_plain = 0;
	add(c, "one-block-flat", 71, 1500, 1, 1);
	add(c, "one-block-skewed", 72, 3000, 1, 0);
	add(c, "two-blocks", 73, 4000, 2, 0);
	add(c, "four-blocks-flat", 74, 9000, 4, 1);
	add(c, "long", 75, 20000, 3, 0);
	add(c, "short", 76, 40, 1, 1);
}

static enum kuncoat_status fn(const void *par, const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *produced)
{
	(void)par;
	return kuncoat_aspack_decode(in, n, out, cap, produced);
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const struct dc_buf d = { fn, NULL, DC_DECLARED_SIZE, plains, 8 };
	uint64_t produced;

	return (int)dc_buf_run(c, &d, in, n, &produced);
}

FZ_ADAPTER(aspack, .name = "kuncoat/aspack", .covers = "kuncoat_aspack_decode", .shape = FZ_BYTES, .seeds = seeds, .run = run, .steps_base = 4000000u);
