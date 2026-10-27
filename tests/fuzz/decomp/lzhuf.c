/*
 * decomp/lzhuf - kuncoat_lzhuf_decode, the coding LHA (-lh5-, -lh6-, -lh7-) and ARJ (methods 1-3) share.
 *
 * Input layout: [variant: 1 byte][out_len: u32 LE][stream]. A mutation of the variant reaches the values the enum does not have;
 * out_len is the length the container declares and the only thing that ends the stream (a LEN field of the map: 0, the true size,
 * one past, 2^32-1). Seeds: random valid streams of tests/lib/uncoat/hostile_lzhvec.h for the four variants and two code designs
 * (a small alphabet and the deep one that uses every position bucket the variant has); a seed under its true out_len gives its plain
 * text.
 *
 * Held: status in the enum; produced >= what the sink took (lzhuf counts what it decoded, and the bytes buffered in its dictionary
 * when a stream fails are counted and not delivered: silent_loss_uncoat.c); the sink is not called again after a refusal; a refusing
 * sink ends in STOPPED; a seed gives its plain text, in full when the sink took everything. Not held (documented): a cut stream gives a
 * prefix of the full output (hostile_sweep.h HV_F_NO_PREFIX_TRUNC).
 */
#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"
#include "../../lib/uncoat/hostile_lzhenc.h"
#include "../../lib/uncoat/hostile_lzhvec.h"

static struct kuncoat_lzhuf st;
static struct vec vs[8];
static struct { const uint8_t *p; size_t n; } plain[8];
static size_t n_seed;

static const struct fz_field fields[] = { { 1, 4, 0, FZ_LEN } };
static const struct fz_map map = { fields, 1, 0, 0, 0 };

static void seeds(struct fz_corpus *c)
{
	static const char *const name[8] = { "arj-small", "lh5-small", "lh6-small", "lh7-small", "arj-deep", "lh5-deep", "lh6-deep", "lh7-deep" };
	static uint8_t b[5 + 200000];
	unsigned i;

	n_seed = 0;
	for (i = 0; i < 8; i++) {
		unsigned var = i & 3u;
		struct vec *v = &vs[i];

		if (!make_lh(v, var, (int)(i >> 2), 400u + i, i < 4 ? 3000u : 9000u))
			continue;
		b[0] = (uint8_t)var;
		b[1] = (uint8_t)v->wn; b[2] = (uint8_t)(v->wn >> 8); b[3] = (uint8_t)(v->wn >> 16); b[4] = (uint8_t)(v->wn >> 24);
		memcpy(b + 5, v->in, v->n);
		plain[n_seed].p = v->want;
		plain[n_seed].n = v->wn;
		n_seed++;
		fz_corpus_add_map(c, name[i], b, 5 + v->n, &map);
	}
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	enum kuncoat_status r;
	uint64_t produced = 0, out_len = n >= 5 ? (uint64_t)in[1] | (uint64_t)in[2] << 8 | (uint64_t)in[3] << 16 | (uint64_t)in[4] << 24 : 0;

	r = kuncoat_lzhuf_decode(&st, (enum kuncoat_lzhuf_variant)(n ? in[0] : 0u), n >= 5 ? in + 5 : in, n >= 5 ? n - 5u : n, out_len, c->sink_fn,
				 c->sink_user, &produced);
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, produced >= c->sink.total, "sink took more than the decoder says it produced");
	FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED, "a refusing sink did not end in STOPPED");
	if (r == KUNCOAT_OK)
		FZ_CHECK(c, produced == out_len, "OK without out_len bytes produced");
	if (!c->failk && c->iter < n_seed) {
		uint64_t k = c->sink.total;

		FZ_CHECK(c, k <= plain[c->iter].n && !memcmp(c->out, plain[c->iter].p, (size_t)(k < plain[c->iter].n ? k : plain[c->iter].n)),
			 "a good stream gave bytes that are not its plain text");
		if (!c->refused)
			FZ_CHECK(c, r == KUNCOAT_OK && k == plain[c->iter].n, "a good stream was not decoded whole");
	}
	fz_digest(c, (uint64_t)r ^ produced << 3 ^ dc_hash(c->out, c->sink.total) << 17);
	return (int)r;
}

FZ_ADAPTER(lzhuf, .name = "kuncoat/lzhuf", .covers = "kuncoat_lzhuf_decode", .shape = FZ_BYTES, .seeds = seeds, .run = run, .steps_base = 4000000u);
