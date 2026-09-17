/*
 * stream_fuzz - drive the two newest streaming decoders with input that is not
 * a stream.
 *
 * WHY THESE TWO AND WHY NOW. LZX and the LHA/ARJ coding are both reachable from
 * any .chm, .cab, .lzh or .arj a scanner is handed, and both were written for
 * this tree rather than lifted from a library that has been fuzzed for twenty
 * years. lzx_chm, lzx_cab and lzhuf_arj prove them RIGHT on real streams,
 * against reset tables, PE checksums and CRC-32s. They prove nothing about what
 * either does when the bytes are wrong, and that is the half that decides
 * whether a malformed archive is a finding or a crash.
 *
 * decomp_fuzz is the same idea for the buffered decoders - NRV2 and LZMA - and
 * this is deliberately its sibling rather than an extension of it: these two
 * decode THROUGH A SINK and into a window they own, so the invariants are about
 * what reaches the sink rather than about a caller's buffer.
 *
 * NEITHER FORMAT TURNS RANDOM INPUT AWAY. LZX has one header bit and no magic;
 * the LHA coding has a 16 bit block count and no magic either. So random bytes
 * walk straight into the tree readers and the match copier instead of being
 * rejected at a signature - which is why no seed corpus is needed for the bulk
 * of it. Real streams are corrupted as well, because a plausible-but-wrong tree
 * reaches states random bytes reach rarely.
 *
 * WHAT IS ASSERTED, each a bug class rather than a behaviour:
 *
 *   - the status is one of the five. Anything else is a path nobody wrote.
 *   - what reaches the sink never exceeds what was asked for. The bound that
 *     stops a decoder from filling a caller's buffer past its end.
 *   - `produced` agrees with what the sink was actually handed.
 *   - it TERMINATES. Both decoders loop until an output count is reached, so a
 *     stream that produces nothing and never errors would hang a scan; the sink
 *     counts calls and the decoder must stop on its own before the cap.
 *   - a sink that refuses is obeyed at once, and the answer is STOPPED.
 *
 * Under SAN=1 this is where the window and table arithmetic is checked: both
 * decoders index arrays they own with values that came out of the stream, so a
 * sanitizer sees what a return code cannot.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofdecomp/lzx.h"
#include "../../libkofeng/kofdecomp/lzhuf.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- the receiver ------------------------------------------------------------- */

struct sink {
	uint64_t seen;      /* bytes handed over */
	uint64_t cap;       /* what was asked for */
	uint64_t calls;
	uint64_t refuse_at; /* refuse once this many bytes have arrived */
	int      over;      /* more arrived than was asked for */
};

static int sink_fn(void *user, const uint8_t *p, uint32_t n)
{
	struct sink *s = user;

	(void)p;
	s->calls++;
	if (s->refuse_at && s->seen >= s->refuse_at)
		return 0;
	s->seen += n;
	if (s->seen > s->cap)
		s->over = 1;
	return 1;
}

static int status_ok(enum kof_decomp_status st)
{
	return st == KOF_DEC_OK || st == KOF_DEC_STOPPED ||
	       st == KOF_DEC_TRUNCATED || st == KOF_DEC_CORRUPT ||
	       st == KOF_DEC_UNSUPPORTED;
}

/* A small deterministic generator: the same rounds run on every host and on
 * every rerun, so a failure is reproducible from the round number alone. */
static uint32_t rnd(uint32_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 17;
	*s ^= *s << 5;
	return *s;
}

/* ---- the rounds ---------------------------------------------------------------- */

#define IN_MAX   4096u
#define TAKE_MAX 65536u

static void one_lzx(struct kof_lzx *st, const uint8_t *in, uint32_t n,
		    uint32_t bits, uint64_t skip, uint64_t take,
		    uint64_t refuse_at, const char *what)
{
	struct sink s;
	enum kof_decomp_status r;
	uint64_t produced = 12345u;   /* must be overwritten */

	memset(&s, 0, sizeof s);
	s.cap = take;
	s.refuse_at = refuse_at;
	r = kof_lzx_decode(st, bits, in, n, skip, take, sink_fn, &s, &produced);
	if (!status_ok(r))
		fail(what, "the status is not one of the five");
	if (s.over)
		fail(what, "more bytes reached the receiver than were asked "
		     "for");
	if (produced != s.seen)
		fail(what, "the count it reports is not what it handed over");
	if (refuse_at && r != KOF_DEC_STOPPED && s.seen >= refuse_at)
		fail(what, "the receiver refused and the answer was not "
		     "STOPPED");
	/*
	 * TERMINATION, as a bound on work rather than on time. Each call hands
	 * over at least one byte, and nothing may be handed over past `take`,
	 * so a decoder that is making progress cannot call more than that many
	 * times. One that is not making progress would not return at all -
	 * which this cannot catch and a hang would - so the bound is here for
	 * the case where it spins WITHOUT producing.
	 */
	if (s.calls > take + 64u)
		fail(what, "the receiver was called more times than there are "
		     "bytes to hand over");
}

static void one_lzhuf(struct kof_lzhuf *st, enum kof_lzhuf_variant var,
		      const uint8_t *in, uint32_t n, uint64_t out_len,
		      uint64_t refuse_at, const char *what)
{
	struct sink s;
	enum kof_decomp_status r;
	uint64_t produced = 12345u;

	memset(&s, 0, sizeof s);
	s.cap = out_len;
	s.refuse_at = refuse_at;
	r = kof_lzhuf_decode(st, var, in, n, out_len, sink_fn, &s, &produced);
	if (!status_ok(r))
		fail(what, "the status is not one of the five");
	if (s.over)
		fail(what, "more bytes reached the receiver than were asked "
		     "for");
	if (produced < s.seen)
		fail(what, "it reports less than it handed over");
	if (refuse_at && r != KOF_DEC_STOPPED && s.seen >= refuse_at)
		fail(what, "the receiver refused and the answer was not "
		     "STOPPED");
	if (s.calls > out_len + 64u)
		fail(what, "the receiver was called more times than there are "
		     "bytes to hand over");
}

int main(void)
{
	struct kof_lzx *lzx = malloc(sizeof *lzx);
	struct kof_lzhuf *lzh = malloc(sizeof *lzh);
	uint8_t *in = malloc(IN_MAX);
	uint32_t seed = 0x5eed1234u, round;
	int rounds = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!lzx || !lzh || !in) {
		free(lzx);
		free(lzh);
		free(in);
		printf("stream fuzz: out of memory\n");
		return 1;
	}

	for (round = 0; round < 3000u && !failures; round++) {
		uint32_t n = rnd(&seed) % IN_MAX;
		uint32_t i;
		uint64_t take = (uint64_t)(rnd(&seed) % TAKE_MAX) + 1u;
		uint64_t skip = rnd(&seed) % 70000u;
		uint32_t bits = 15u + rnd(&seed) % 9u;   /* two of them illegal */
		char what[64];

		for (i = 0; i < n; i++)
			in[i] = (uint8_t)rnd(&seed);
		/*
		 * A RUN OF ONE BYTE, every so often. Random bytes give every
		 * tree a plausible shape; a stream of zeroes or of 0xff gives
		 * the degenerate ones - an empty code, a run code that never
		 * ends - which is where the bounds are.
		 */
		if ((round & 7u) == 0u)
			memset(in, (int)(rnd(&seed) & 0xffu), n);

		snprintf(what, sizeof what, "lzx round %u", round);
		one_lzx(lzx, in, n, bits, skip, take,
			(round & 3u) == 1u ? take / 2u + 1u : 0u, what);

		snprintf(what, sizeof what, "lzhuf round %u", round);
		one_lzhuf(lzh, (enum kof_lzhuf_variant)(rnd(&seed) % 4u), in, n,
			  take, (round & 3u) == 2u ? take / 2u + 1u : 0u, what);
		rounds++;
	}

	/* The empty input and the zero request, which every decoder gets asked
	 * for eventually and which are the two easiest to get wrong. */
	one_lzx(lzx, in, 0, 15u, 0, 16u, 0, "lzx empty");
	one_lzx(lzx, in, 4u, 15u, 0, 0, 0, "lzx nothing wanted");
	one_lzhuf(lzh, KOF_LZHUF_ARJ, in, 0, 16u, 0, "lzhuf empty");
	one_lzhuf(lzh, KOF_LZHUF_LH5, in, 4u, 0, 0, "lzhuf nothing wanted");

	free(lzx);
	free(lzh);
	free(in);

	if (failures) {
		printf("stream fuzz: %d check(s) failed\n", failures);
		return 1;
	}
	printf("stream fuzz: %d round(s) of hostile input through LZX and the "
	       "LHA/ARJ coding - status, bound, count, refusal and termination "
	       "ok\n", rounds);
	return 0;
}
