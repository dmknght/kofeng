/*
 * lzma.c - LZMA1, decoded into a caller-owned buffer.
 *
 * Three things make up an LZMA decoder and they are separable, so they are
 * separate here: a RANGE DECODER that turns bytes into bits at a cost proportional
 * to how likely each bit was, a PROBABILITY MODEL that says how likely, and a
 * MATCH DECODER that reads literals and back references out of the bits. Everything
 * below is one of those three.
 *
 * The model is the part worth understanding before reading the code. Every bit
 * decoded is decoded against a probability that is then updated toward what the bit
 * turned out to be, so the decoder's state after N bits depends on all N of them:
 * there is no resynchronisation and no framing. One wrong bit does not corrupt a
 * byte, it corrupts everything after it. That is why the only useful check on a
 * stream is whether it produced the length it was supposed to.
 *
 *
 * WHAT HOSTILE INPUT CAN REACH
 *
 * Less than in NRV2, because LZMA's lengths and distances are bounded by their
 * coding rather than by convention - a distance is at most 32 bits and a length at
 * most 273. What is left, and where each is stopped:
 *
 *   - lc, lp and pb size the probability model, and they arrive from a container.
 *     Checked against the specification's maxima BEFORE the allocation they
 *     determine, because 0x300 << (lc+lp) with unchecked inputs is an allocation an
 *     attacker chose.
 *   - a distance may name any byte already produced and nothing else. Checked
 *     against WHAT HAS BEEN WRITTEN, not against the buffer: a distance inside the
 *     allocation but ahead of the write cursor would copy whatever the allocator
 *     last left there into an object about to be scanned.
 *   - a match length is checked against the room left before the copy, so the copy
 *     needs no test per byte.
 *   - the end marker is a distance of 0xffffffff, which is a legal encoding and
 *     must end the stream rather than be treated as a distance.
 *   - every input byte is bounded; running out is truncation rather than
 *     corruption, because a cut-short stream is what a damaged sample looks like.
 */

#include "lzma.h"

#include <stdlib.h>
#include <string.h>

/* ---- the model's shape ------------------------------------------------------- */

#define PROB_BITS      11u
#define PROB_INIT      (1u << (PROB_BITS - 1))    /* even odds */
#define MOVE_BITS       5u
#define TOP_VALUE      (1u << 24)

#define N_STATES       12u
#define MAX_PB_STATES  16u                        /* 1 << KOF_LZMA_MAX_PB */
#define LEN_TO_POS_STATES 4u
#define ALIGN_BITS      4u
#define ALIGN_SIZE     (1u << ALIGN_BITS)
#define END_POS_MODEL_INDEX 14u
#define FULL_DISTANCES (1u << (END_POS_MODEL_INDEX >> 1))
#define MATCH_MIN_LEN   2u

/*
 * The fixed part of the model, laid out as one array so it is one allocation with
 * the literal probabilities that follow it.
 *
 * The offsets are named rather than the sub-arrays, because the length coders are
 * used twice - once for matches and once for repeats - and giving each a base
 * offset says that plainly where two near-identical structs would not.
 */
#define LEN_CHOICE_N   1u
#define LEN_LOW_N      (MAX_PB_STATES * 8u)
#define LEN_MID_N      (MAX_PB_STATES * 8u)
#define LEN_HIGH_N     256u
#define LEN_CODER_N    (2u * LEN_CHOICE_N + LEN_LOW_N + LEN_MID_N + LEN_HIGH_N)

enum {
	O_IS_MATCH   = 0,
	O_IS_REP     = O_IS_MATCH   + N_STATES * MAX_PB_STATES,
	O_IS_REP_G0  = O_IS_REP     + N_STATES,
	O_IS_REP_G1  = O_IS_REP_G0  + N_STATES,
	O_IS_REP_G2  = O_IS_REP_G1  + N_STATES,
	O_IS_REP0LNG = O_IS_REP_G2  + N_STATES,
	O_POS_SLOT   = O_IS_REP0LNG + N_STATES * MAX_PB_STATES,
	O_SPEC_POS   = O_POS_SLOT   + LEN_TO_POS_STATES * 64u,
	O_ALIGN      = O_SPEC_POS   + FULL_DISTANCES - END_POS_MODEL_INDEX,
	O_LEN        = O_ALIGN      + ALIGN_SIZE,
	O_REP_LEN    = O_LEN        + LEN_CODER_N,
	O_LITERAL    = O_REP_LEN    + LEN_CODER_N     /* the variable part follows */
};

/* ---- the range decoder ------------------------------------------------------- */

struct rc {
	const uint8_t *in;
	uint64_t n, at;
	uint32_t range, code;
	int      short_input;      /* set once, rather than tested at every read */
};

/* A byte, or zero once the input is spent. Reading past the end is recorded and
 * decoding continues, so the caller learns it was truncated rather than getting a
 * decoder that stops mid-symbol in an unexamined state. */
static uint8_t rc_byte(struct rc *r)
{
	if (r->at >= r->n) {
		r->short_input = 1;
		return 0;
	}
	return r->in[r->at++];
}

/* The first byte is ignored by the format and the next four are the initial code. */
static void rc_init(struct rc *r, const uint8_t *in, uint64_t n)
{
	int i;

	r->in = in;
	r->n = n;
	r->at = 0;
	r->range = 0xffffffffu;
	r->code = 0;
	r->short_input = 0;
	(void)rc_byte(r);
	for (i = 0; i < 4; i++)
		r->code = (r->code << 8) | rc_byte(r);
}

static void rc_normalise(struct rc *r)
{
	if (r->range < TOP_VALUE) {
		r->range <<= 8;
		r->code = (r->code << 8) | rc_byte(r);
	}
}

/*
 * One bit, against the probability at *p, which is then moved toward the answer.
 *
 * This is the whole of the compression: a bit that was likely costs almost no range
 * and a bit that was not costs most of it.
 */
static uint32_t rc_bit(struct rc *r, uint16_t *p)
{
	uint32_t bound = (r->range >> PROB_BITS) * *p;

	if (r->code < bound) {
		r->range = bound;
		*p = (uint16_t)(*p + (((1u << PROB_BITS) - *p) >> MOVE_BITS));
		rc_normalise(r);
		return 0;
	}
	r->range -= bound;
	r->code  -= bound;
	*p = (uint16_t)(*p - (*p >> MOVE_BITS));
	rc_normalise(r);
	return 1;
}

/* `n` bits, most significant first, through a tree of 2^n probabilities. */
static uint32_t rc_tree(struct rc *r, uint16_t *probs, unsigned n)
{
	uint32_t m = 1;
	unsigned i;

	for (i = 0; i < n; i++)
		m = (m << 1) | rc_bit(r, &probs[m]);
	/* The walk leaves the leaf index with a 1 above it; the symbol is what is
	 * left once that is taken off. Written as a subtraction rather than a bit
	 * scan so it needs no compiler builtin. */
	return m - (1u << n);
}

/* The same tree read the other way round, for the distance's low bits. */
static uint32_t rc_tree_rev(struct rc *r, uint16_t *probs, unsigned n)
{
	uint32_t m = 1, out = 0, i;

	for (i = 0; i < n; i++) {
		uint32_t b = rc_bit(r, &probs[m]);

		m = (m << 1) | b;
		out |= b << i;
	}
	return out;
}

/* Bits with no model behind them, used for the middle of a large distance. */
static uint32_t rc_direct(struct rc *r, unsigned n)
{
	uint32_t out = 0;

	while (n--) {
		uint32_t t;

		r->range >>= 1;
		r->code -= r->range;
		t = 0u - (r->code >> 31);
		r->code += r->range & t;
		rc_normalise(r);
		out = (out << 1) | (t + 1);
	}
	return out;
}

/* ---- lengths ----------------------------------------------------------------- */

/*
 * A length, from one of the two length coders.
 *
 * Three ranges with a bit each to choose between them: 2-9, 10-17, 18-273. The
 * shape is the format's and the only thing worth noting is that the result cannot
 * exceed 273, so nothing here needs a bound of its own.
 */
static uint32_t decode_len(struct rc *r, uint16_t *base, uint32_t pos_state)
{
	uint16_t *choice = base;
	uint16_t *choice2 = base + 1;
	uint16_t *low = base + 2;
	uint16_t *mid = low + LEN_LOW_N;
	uint16_t *high = mid + LEN_MID_N;

	if (rc_bit(r, choice) == 0)
		return rc_tree(r, low + pos_state * 8u, 3);
	if (rc_bit(r, choice2) == 0)
		return 8u + rc_tree(r, mid + pos_state * 8u, 3);
	return 16u + rc_tree(r, high, 8);
}

/* ---- the decoder ------------------------------------------------------------- */

int kof_lzma_decode(unsigned lc, unsigned lp, unsigned pb,
		    const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced)
{
	struct rc r;
	uint16_t *probs;
	uint64_t at = 0, n_probs;
	uint32_t state = 0, rep0 = 1, rep1 = 1, rep2 = 1, rep3 = 1;
	uint32_t pos_mask, lit_pos_mask;
	int status = KOF_DEC_OK;

	if (produced)
		*produced = 0;
	/* Checked before the allocation they size, and before anything else uses
	 * them: these came out of a container and nothing has vouched for them. */
	if (lc > KOF_LZMA_MAX_LC || lp > KOF_LZMA_MAX_LP || pb > KOF_LZMA_MAX_PB)
		return KOF_DEC_CORRUPT;
	if (!in || !out || out_cap == 0)
		return KOF_DEC_STOPPED;

	n_probs = (uint64_t)O_LITERAL + ((uint64_t)0x300u << (lc + lp));
	probs = malloc((size_t)n_probs * sizeof *probs);
	if (!probs)
		return KOF_DEC_STOPPED;
	{
		uint64_t i;

		for (i = 0; i < n_probs; i++)
			probs[i] = PROB_INIT;
	}

	pos_mask = (1u << pb) - 1u;
	lit_pos_mask = (1u << lp) - 1u;
	rc_init(&r, in, in_len);

	while (at < out_cap) {
		uint32_t pos_state = (uint32_t)at & pos_mask;
		uint32_t len;

		if (r.short_input) {
			status = KOF_DEC_TRUNCATED;
			break;
		}

		if (rc_bit(&r, &probs[O_IS_MATCH + state * MAX_PB_STATES + pos_state])
		    == 0) {
			/*
			 * A literal, coded against the previous byte when the state
			 * says the last thing was a match - which is what lets the
			 * model predict the byte that "should" have been there.
			 */
			uint16_t *lit = probs + O_LITERAL +
				(uint64_t)0x300u *
				((((uint32_t)at & lit_pos_mask) << lc) +
				 (at ? (uint32_t)(out[at - 1] >> (8u - lc)) : 0u));
			uint32_t sym = 1;

			if (state >= 7) {
				uint32_t match = at >= rep0 ? out[at - rep0] : 0;

				do {
					uint32_t mb = (match >> 7) & 1u;
					uint32_t b;

					match <<= 1;
					b = rc_bit(&r, &lit[((1u + mb) << 8) + sym]);
					sym = (sym << 1) | b;
					if (mb != b) {
						while (sym < 0x100)
							sym = (sym << 1) |
							      rc_bit(&r, &lit[sym]);
						break;
					}
				} while (sym < 0x100);
			} else {
				while (sym < 0x100)
					sym = (sym << 1) | rc_bit(&r, &lit[sym]);
			}
			out[at++] = (uint8_t)sym;
			state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
			continue;
		}

		if (rc_bit(&r, &probs[O_IS_REP + state])) {
			/* A repeat of an earlier distance. */
			if (rc_bit(&r, &probs[O_IS_REP_G0 + state]) == 0) {
				if (rc_bit(&r, &probs[O_IS_REP0LNG +
						      state * MAX_PB_STATES +
						      pos_state]) == 0) {
					/* One byte at the last distance. */
					state = state < 7 ? 9 : 11;
					if (rep0 == 0 || (uint64_t)rep0 > at) {
						status = KOF_DEC_CORRUPT;
						break;
					}
					out[at] = out[at - rep0];
					at++;
					continue;
				}
			} else {
				uint32_t d;

				if (rc_bit(&r, &probs[O_IS_REP_G1 + state]) == 0) {
					d = rep1;
				} else if (rc_bit(&r, &probs[O_IS_REP_G2 + state]) == 0) {
					d = rep2;
					rep2 = rep1;
				} else {
					d = rep3;
					rep3 = rep2;
					rep2 = rep1;
				}
				rep1 = rep0;
				rep0 = d;
			}
			len = MATCH_MIN_LEN + decode_len(&r, probs + O_REP_LEN,
							 pos_state);
			state = state < 7 ? 8 : 11;
		} else {
			/* A new match: a length, then a distance. */
			uint32_t slot, len_state;

			rep3 = rep2;
			rep2 = rep1;
			rep1 = rep0;
			len = MATCH_MIN_LEN + decode_len(&r, probs + O_LEN, pos_state);
			state = state < 7 ? 7 : 10;

			len_state = len - MATCH_MIN_LEN;
			if (len_state >= LEN_TO_POS_STATES)
				len_state = LEN_TO_POS_STATES - 1u;
			slot = rc_tree(&r, probs + O_POS_SLOT + len_state * 64u, 6);

			if (slot < 4) {
				rep0 = slot;
			} else {
				unsigned nd = (unsigned)((slot >> 1) - 1u);

				rep0 = (2u | (slot & 1u)) << nd;
				if (slot < END_POS_MODEL_INDEX) {
					rep0 += rc_tree_rev(&r,
						probs + O_SPEC_POS + rep0 - slot - 1u,
						nd);
				} else {
					rep0 += rc_direct(&r, nd - ALIGN_BITS)
						<< ALIGN_BITS;
					rep0 += rc_tree_rev(&r, probs + O_ALIGN,
							    ALIGN_BITS);
				}
			}
			/*
			 * The end marker. A real encoding rather than a sentinel
			 * this code invented: an all-ones distance cannot be a
			 * distance, so the format spends it on saying "done".
			 */
			if (rep0 == 0xffffffffu)
				break;
			rep0++;
		}

		/*
		 * The two checks that make the copy safe, and they check different
		 * things: the distance against what has been WRITTEN, the length
		 * against the room left. A distance inside the buffer but ahead of
		 * the cursor would copy bytes this stream never produced.
		 */
		if (rep0 == 0 || (uint64_t)rep0 > at) {
			status = KOF_DEC_CORRUPT;
			break;
		}
		if ((uint64_t)len > out_cap - at) {
			len = (uint32_t)(out_cap - at);
			status = KOF_DEC_STOPPED;
		}
		/*
		 * Non-overlapping matches are a straight copy; a distance shorter
		 * than the length is a run and has to stay byte at a time, because
		 * each byte it reads is one this loop just wrote.
		 */
		if ((uint64_t)rep0 >= (uint64_t)len) {
			memcpy(out + at, out + at - rep0, (size_t)len);
			at += len;
		} else {
			while (len--) {
				out[at] = out[at - rep0];
				at++;
			}
		}
		if (status == KOF_DEC_STOPPED)
			break;
	}

	if (status == KOF_DEC_OK && at >= out_cap && r.at < r.n)
		status = KOF_DEC_STOPPED;
	if (r.short_input && status == KOF_DEC_OK)
		status = KOF_DEC_TRUNCATED;

	free(probs);
	if (produced)
		*produced = at;
	return status;
}
