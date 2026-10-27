/*
 * decomp/lzx - kuncoat_lzx_decode (LZX as a cabinet or a help file frames it: no length in the stream, the window width and the
 * slice to take come from the container).
 *
 * Input layout of the row: [window bits: 1 byte][skip: u32 LE][take: u32 LE][stream], so a mutation reaches the widths the format
 * does not define (15..21 are), a skip past the stream, a take past it, and 0. Field map: skip is an OFFSET, take a LEN.
 * Seeds are random valid streams of tests/lib/uncoat/hostile_lzxvec.h (uncompressed, verbatim and aligned blocks; windows 15, 16
 * and 21; one with a call-translation size in its header): a seed under its own (bits, 0, wn) must give its plain text.
 *
 * Held: the status is in the enum; consumed is 0 (the container frames the stream); produced >= what the sink took; the sink is
 * not called again after a refusal; a refusing sink ends in STOPPED, or in TRUNCATED when the refusal was the final flush (the end
 * of the stream wins; documented in hostile_lzx.c, kept lenient here); a seed gives exactly the slice of its plain text.
 */
#include "decomp_common.h"
#include "../../lib/uncoat/hostile_common.h"
#include "../../lib/uncoat/hostile_enc.h"
#include "../../lib/uncoat/hostile_lzxenc.h"
#include "../../lib/uncoat/hostile_lzxvec.h"

static struct kuncoat_lzx st;
static struct vec v15, v16, v21, v_e8;
static struct { const uint8_t *p; size_t n; unsigned bits; } seed_of[8];
static size_t n_seed;

static const struct fz_field fields[] = { { 1, 4, 0, FZ_OFFSET }, { 5, 4, 0, FZ_LEN } };
static const struct fz_map map = { fields, 2, 0, 0, 0 };

static void add(struct fz_corpus *c, const char *name, const struct vec *v, unsigned bits, int plain_known)
{
	static uint8_t b[9 + 90000];

	if (n_seed >= 8)
		return;
	b[0] = (uint8_t)bits;
	b[1] = b[2] = b[3] = b[4] = 0;
	b[5] = (uint8_t)v->wn; b[6] = (uint8_t)(v->wn >> 8); b[7] = (uint8_t)(v->wn >> 16); b[8] = (uint8_t)(v->wn >> 24);
	memcpy(b + 9, v->in, v->n);
	seed_of[n_seed].p = plain_known ? v->want : NULL;
	seed_of[n_seed].n = v->wn;
	seed_of[n_seed].bits = bits;
	n_seed++;
	fz_corpus_add_map(c, name, b, 9 + v->n, &map);
}

static void seeds(struct fz_corpus *c)
{
	n_seed = 0;
	if (make_lzx(&v15, 15, 51, 3000, 0))
		add(c, "w15", &v15, 15, 1);
	if (make_lzx(&v16, 16, 52, 70000, 0))
		add(c, "w16-frames", &v16, 16, 1);
	if (make_lzx(&v21, 21, 53, 5000, 0))
		add(c, "w21", &v21, 21, 1);
	if (make_lzx(&v_e8, 17, 54, 4000, 0x10000u))
		add(c, "w17-e8", &v_e8, 17, 0);
}

static const char *const dict[] = { "\x00\x00\x00\x00", "\xff\xff\xff\xff", NULL };

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kuncoat_lzx_req rq;
	struct kuncoat_io io;
	enum kuncoat_status r;

	memset(&rq, 0, sizeof rq);
	if (n >= 9) {
		rq.window_bits = in[0];
		rq.skip = (uint64_t)in[1] | (uint64_t)in[2] << 8 | (uint64_t)in[3] << 16 | (uint64_t)in[4] << 24;
		rq.take = (uint64_t)in[5] | (uint64_t)in[6] << 8 | (uint64_t)in[7] << 16 | (uint64_t)in[8] << 24;
	}
	memset(&io, 0, sizeof io);
	io.in.p = n >= 9 ? in + 9 : in;
	io.in.n = n >= 9 ? n - 9u : n;
	io.sink = c->sink_fn;
	io.user = c->sink_user;
	io.consumed = io.produced = 0xFEEDull;
	r = kuncoat_lzx_decode(&st, &rq, &io);
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	FZ_CHECK(c, io.consumed == 0, "consumed is not 0 (an LZX stream is framed by its container)");
	FZ_CHECK(c, io.produced >= c->sink.total, "sink took more than the decoder says it produced");
	FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED || r == KUNCOAT_TRUNCATED, "a refusing sink did not end in STOPPED (or TRUNCATED on the final flush)");
	if (!c->failk && c->iter < n_seed && seed_of[c->iter].p) {
		uint64_t k = c->sink.total;

		FZ_CHECK(c, k <= seed_of[c->iter].n && !memcmp(c->out, seed_of[c->iter].p, (size_t)(k < seed_of[c->iter].n ? k : seed_of[c->iter].n)),
			 "a good stream gave bytes that are not its plain text");
		if (!c->refused)
			FZ_CHECK(c, k == seed_of[c->iter].n, "a good stream was not decoded whole");
	}
	fz_digest(c, (uint64_t)r ^ io.produced << 3 ^ dc_hash(c->out, c->sink.total) << 17);
	return (int)r;
}

FZ_ADAPTER(lzx, .name = "kuncoat/lzx", .covers = "kuncoat_lzx_decode", .shape = FZ_BYTES, .seeds = seeds, .dict = dict, .run = run,
	   .steps_base = 4000000u);
