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
#include "inbyte.h"

#include <stdlib.h>
#include <string.h>

/*
 * WORK COUNTING, for the test that bounds a state reset. A test that wants to count
 * the probability words this file writes defines KUNCOAT_LZMA_WORK_HOOK, supplies
 * `kuncoat_lzma_work`, and includes this file; in every other build the macro is
 * empty and costs nothing.
 */
#ifdef KUNCOAT_LZMA_WORK_HOOK
extern uint64_t kuncoat_lzma_work;
#define LZ_WORK(n) (kuncoat_lzma_work += (uint64_t)(n))
#else
#define LZ_WORK(n) ((void)0)
#endif

/* ---- the model's shape ------------------------------------------------------- */

#define PROB_BITS      11u
#define PROB_INIT      (1u << (PROB_BITS - 1))    /* even odds */
#define MOVE_BITS       5u
#define TOP_VALUE      (1u << 24)

#define N_STATES       12u
#define MAX_PB_STATES  16u                        /* 1 << KUNCOAT_LZMA_MAX_PB */
#define LEN_TO_POS_STATES 4u
#define ALIGN_BITS      4u
#define ALIGN_SIZE     (1u << ALIGN_BITS)
#define END_POS_MODEL_INDEX 14u
#define FULL_DISTANCES (1u << (END_POS_MODEL_INDEX >> 1))

/*
 * THE TWO BOUNDS THAT KEEP THE PROBABILITY INDICES INSIDE THE ARRAY, said to
 * the compiler rather than to the reader.
 *
 * MAX_PB_STATES is written as 16 and the comment next to it is the only thing
 * tying it to KUNCOAT_LZMA_MAX_PB. Raise that constant to 5 and `pos_state` reaches
 * 31 while every `state * MAX_PB_STATES + pos_state` still strides by 16: the
 * index runs off the end of a heap array, on attacker-supplied header bytes,
 * and nothing in this file would say so.
 *
 * MAX_LC is load-bearing in a quieter way. The literal context is
 * `out[at - 1] >> (8u - lc)`, and `8u - lc` is UNSIGNED - at lc of 9 it is not
 * -1 but 4294967295, a shift wider than the type, which is undefined and on
 * x86 becomes a shift by 31. The byte would still be in range by luck; the
 * next person to widen the literal slot would not be so lucky.
 */
_Static_assert(MAX_PB_STATES == (1u << KUNCOAT_LZMA_MAX_PB),
	       "MAX_PB_STATES must be 1 << KUNCOAT_LZMA_MAX_PB");
_Static_assert(KUNCOAT_LZMA_MAX_LC <= 8u,
	       "literal context uses 8 - lc as an unsigned shift count");
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
	int      fab;              /* a decision was taken from bytes that are not there */
};

/* A byte, or zero once the input is spent. Reading past the end is recorded and
 * decoding continues, so the caller learns it was truncated rather than getting a
 * decoder that stops mid-symbol in an unexamined state. */
static inline uint8_t rc_byte(struct rc *r)
{
	return kuncoat_in_byte(r->in, r->n, &r->at, &r->short_input);
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
	r->fab = 0;
	(void)rc_byte(r);
	for (i = 0; i < 4; i++)
		r->code = (r->code << 8) | rc_byte(r);
}

static inline void rc_normalise(struct rc *r)
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
static inline uint32_t rc_bit(struct rc *r, uint16_t *p)
{
	uint32_t bound = (r->range >> PROB_BITS) * *p;

	r->fab |= r->short_input;
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
static inline uint32_t rc_tree(struct rc *r, uint16_t *probs, unsigned n)
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
static inline uint32_t rc_tree_rev(struct rc *r, uint16_t *probs, unsigned n)
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
static inline uint32_t rc_direct(struct rc *r, unsigned n)
{
	uint32_t out = 0;

	r->fab |= r->short_input;
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

/*
 * The decoder's whole state, lifted out of the function that used to hold it.
 *
 * It was all locals, which is correct for LZMA and wrong for LZMA2: an LZMA2
 * stream is a sequence of chunks that may CONTINUE the previous one - same
 * probability model, same match distances, same dictionary - and a decoder whose
 * state dies with its call cannot express that. Nothing here is new; it is the
 * same six values, in a struct that can outlive one chunk.
 *
 * The dictionary is not in here because it never was: matches read out of the
 * OUTPUT buffer, so the caller's buffer is the window and continuing across chunks
 * costs nothing but passing the cursor back in.
 */
struct lz_state {
	uint16_t *probs;
	uint64_t  n_probs;
	/* Which reset each literal context's 0x300 words were last initialised
	 * under. A reset bumps `gen` instead of rewriting the whole literal
	 * model (3.1M words at lc8 lp4); a context is initialised the first time
	 * it is used after a reset. The work of a reset is then the fixed part,
	 * and the rest is paid for by the symbols that use it. */
	uint32_t *lit_gen;
	uint64_t  n_lit_gen;
	uint32_t  gen;
	unsigned  lc, lp, pb;
	uint32_t  state, rep0, rep1, rep2, rep3;
	/* Where the dictionary starts in the output: LZMA2's dictionary reset
	 * means a match may not reach before it, and the position the model
	 * keeps (pos_state, the literal's context) counts from it. */
	uint64_t  dict_start;
};

static void lz_reset_state(struct lz_state *z)
{
	uint64_t i;

	z->state = 0;
	z->rep0 = z->rep1 = z->rep2 = z->rep3 = 1;
	for (i = 0; i < O_LITERAL; i++)
		z->probs[i] = PROB_INIT;
	LZ_WORK(O_LITERAL);
	if (++z->gen == 0) {                    /* wrapped: nothing is current any more */
		memset(z->lit_gen, 0, (size_t)z->n_lit_gen * sizeof *z->lit_gen);
		z->gen = 1;
	}
}

/* The literal coder for context `ctx`, initialised if this reset has not yet. */
static inline uint16_t *lz_literal(struct lz_state *z, uint64_t ctx)
{
	uint16_t *lit = z->probs + O_LITERAL + (uint64_t)0x300u * ctx;

	if (z->lit_gen[ctx] != z->gen) {
		uint32_t i;

		for (i = 0; i < 0x300u; i++)
			lit[i] = PROB_INIT;
		z->lit_gen[ctx] = z->gen;
		LZ_WORK(0x300u);
	}
	return lit;
}

/*
 * Make the model fit lc, lp and pb, allocating or growing as needed.
 *
 * LZMA2 may change the properties between chunks, so the size of the model is not
 * fixed for the life of a stream. Growing rather than reallocating every time
 * matters because a stream that alternates two property sets would otherwise
 * allocate per chunk.
 */
static int lz_set_props(struct lz_state *z, unsigned lc, unsigned lp, unsigned pb)
{
	uint64_t want;

	if (lc > KUNCOAT_LZMA_MAX_LC || lp > KUNCOAT_LZMA_MAX_LP || pb > KUNCOAT_LZMA_MAX_PB)
		return 0;
	want = (uint64_t)O_LITERAL + ((uint64_t)0x300u << (lc + lp));
	if (want > z->n_probs) {
		uint16_t *nv = realloc(z->probs, (size_t)want * sizeof *nv);

		if (!nv)
			return 0;
		z->probs = nv;
		z->n_probs = want;
	}
	if (((uint64_t)1 << (lc + lp)) > z->n_lit_gen) {
		uint32_t *ng = realloc(z->lit_gen, ((size_t)1 << (lc + lp)) * sizeof *ng);

		if (!ng)
			return 0;
		memset(ng + z->n_lit_gen, 0,
		       ((size_t)((uint64_t)1 << (lc + lp)) - (size_t)z->n_lit_gen) * sizeof *ng);
		z->lit_gen = ng;
		z->n_lit_gen = (uint64_t)1 << (lc + lp);
	}
	z->lc = lc;
	z->lp = lp;
	z->pb = pb;
	return 1;
}

/*
 * The distance of a new match, as the raw field (0xffffffff is the end marker).
 * Shared by the decode and by the look at what follows a full buffer.
 */
static inline uint32_t decode_dist(struct rc *r, uint16_t *probs, uint32_t len)
{
	uint32_t slot, rep0, len_state = len - MATCH_MIN_LEN;

	if (len_state >= LEN_TO_POS_STATES)
		len_state = LEN_TO_POS_STATES - 1u;
	slot = rc_tree(r, probs + O_POS_SLOT + len_state * 64u, 6);

	if (slot < 4)
		return slot;
	{
		unsigned nd = (unsigned)((slot >> 1) - 1u);

		rep0 = (2u | (slot & 1u)) << nd;
		if (slot < END_POS_MODEL_INDEX) {
			rep0 += rc_tree_rev(r, probs + O_SPEC_POS + rep0 - slot - 1u, nd);
		} else {
			rep0 += rc_direct(r, nd - ALIGN_BITS) << ALIGN_BITS;
			rep0 += rc_tree_rev(r, probs + O_ALIGN, ALIGN_BITS);
		}
	}
	return rep0;
}

/* Is the next thing in the stream the end marker? Asked once the output is full,
 * to tell a stream that ends here (marker, or none) from one that has more to say.
 * It consumes the rest of the coder's state, so only a stream's last look may ask. */
static int at_end_marker(struct rc *r, uint16_t *probs, uint32_t state, uint32_t pos_state)
{
	uint32_t len;

	if (r->short_input)
		return 1;
	if (rc_bit(r, &probs[O_IS_MATCH + state * MAX_PB_STATES + pos_state]) == 0)
		return 0;
	if (rc_bit(r, &probs[O_IS_REP + state]))
		return 0;
	len = MATCH_MIN_LEN + decode_len(r, probs + O_LEN, pos_state);
	return !r->fab && decode_dist(r, probs, len) == 0xffffffffu && !r->fab;
}

/*
 * Decode one LZMA stream into out[] starting at `at`, stopping at `limit`.
 *
 * `at` is both where output goes and how far back a match may reach, which is why
 * it comes in rather than starting at zero: an LZMA2 chunk continues the previous
 * chunk's dictionary, and the dictionary is the output written so far (from
 * z->dict_start, which a dictionary reset moves).
 *
 * NOTHING IS EMITTED FROM BYTES THAT ARE NOT THERE. Past the end of the input the
 * range decoder feeds zeros so the symbol under way finishes in a defined state,
 * but a decision taken from them is a decision the stream never made: `r.fab` says
 * one was, and the symbol is then dropped (TRUNCATED) instead of written. A stream
 * that is complete never sets it, because the coder's normalisation after the last
 * bit consumes exactly the bytes the encoder flushed.
 *
 * `peek_end` is for a stream that stands alone (plain LZMA): when the buffer fills
 * with input left, look at whether what is left is the end marker, so a stream
 * whose size the caller knew exactly is OK and not STOPPED.
 */
static int lz_run(struct lz_state *z, const uint8_t *in, uint64_t in_len,
		  uint8_t *out, uint64_t limit, uint64_t *at_io, int peek_end)
{
	struct rc r;
	uint16_t *probs = z->probs;
	uint64_t at = *at_io;
	const uint64_t dstart = z->dict_start;
	uint32_t state = z->state, rep0 = z->rep0, rep1 = z->rep1;
	uint32_t rep2 = z->rep2, rep3 = z->rep3;
	uint32_t pos_mask = (1u << z->pb) - 1u;
	uint32_t lit_pos_mask = (1u << z->lp) - 1u;
	unsigned lc = z->lc;
	uint64_t out_cap = limit;
	int status = KUNCOAT_OK;

	rc_init(&r, in, in_len);

	while (at < out_cap) {
		uint32_t pos_state = (uint32_t)(at - dstart) & pos_mask;
		uint32_t len;

		if (r.fab) {
			status = KUNCOAT_TRUNCATED;
			break;
		}

		if (rc_bit(&r, &probs[O_IS_MATCH + state * MAX_PB_STATES + pos_state])
		    == 0) {
			/*
			 * A literal, coded against the previous byte when the state
			 * says the last thing was a match - which is what lets the
			 * model predict the byte that "should" have been there.
			 */
			uint16_t *lit = lz_literal(z,
				((((uint64_t)(at - dstart) & lit_pos_mask) << lc) +
				 (at > dstart ? (uint32_t)(out[at - 1] >> (8u - lc)) : 0u)));
			uint32_t sym = 1;

			if (state >= 7) {
				uint32_t match = at - dstart >= rep0 ? out[at - rep0] : 0;

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
			if (r.fab) {
				status = KUNCOAT_TRUNCATED;
				break;
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
					if (r.fab) {
						status = KUNCOAT_TRUNCATED;
						break;
					}
					state = state < 7 ? 9 : 11;
					if (rep0 == 0 || (uint64_t)rep0 > at - dstart) {
						status = KUNCOAT_CORRUPT;
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
			rep3 = rep2;
			rep2 = rep1;
			rep1 = rep0;
			len = MATCH_MIN_LEN + decode_len(&r, probs + O_LEN, pos_state);
			state = state < 7 ? 7 : 10;
			rep0 = decode_dist(&r, probs, len);
			/*
			 * The end marker. A real encoding rather than a sentinel
			 * this code invented: an all-ones distance cannot be a
			 * distance, so the format spends it on saying "done".
			 */
			if (r.fab) {
				status = KUNCOAT_TRUNCATED;
				break;
			}
			if (rep0 == 0xffffffffu)
				break;
			rep0++;
		}
		if (r.fab) {                    /* the length or the distance is not the stream's */
			status = KUNCOAT_TRUNCATED;
			break;
		}

		/*
		 * The two checks that make the copy safe, and they check different
		 * things: the distance against what has been WRITTEN (since the
		 * dictionary began), the length against the room left. A distance
		 * inside the buffer but ahead of the cursor would copy bytes this
		 * stream never produced.
		 */
		if (rep0 == 0 || (uint64_t)rep0 > at - dstart) {
			status = KUNCOAT_CORRUPT;
			break;
		}
		if ((uint64_t)len > out_cap - at) {
			len = (uint32_t)(out_cap - at);
			status = KUNCOAT_STOPPED;
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
		if (status == KUNCOAT_STOPPED)
			break;
	}

	if (status == KUNCOAT_OK && at >= out_cap && r.at < r.n) {
		if (peek_end && at_end_marker(&r, probs, state, (uint32_t)(at - dstart) & pos_mask))
			;                       /* the buffer is the whole stream */
		else
			status = KUNCOAT_STOPPED;
	}
	if (r.short_input && status == KUNCOAT_OK)
		status = KUNCOAT_TRUNCATED;

	z->state = state;
	z->rep0 = rep0;
	z->rep1 = rep1;
	z->rep2 = rep2;
	z->rep3 = rep3;
	*at_io = at;
	return status;
}

/*
 * One LZMA stream, which is what every caller before LZMA2 wanted.
 *
 * A thin wrapper now: fresh state, decode once, throw the state away.
 */
enum kuncoat_status kuncoat_lzma_decode(unsigned lc, unsigned lp, unsigned pb,
		    const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced)
{
	struct lz_state z;
	uint64_t at = 0;
	int status;

	if (produced)
		*produced = 0;
	if ((!in && in_len) || (!out && out_cap))
		return KUNCOAT_BAD_ARG;
	if (out_cap == 0)
		return KUNCOAT_STOPPED;

	memset(&z, 0, sizeof z);
	/* Checked before the allocation they size, and before anything else uses
	 * them: these came out of a container and nothing has vouched for them. */
	if (!lz_set_props(&z, lc, lp, pb)) {
		free(z.probs);
		free(z.lit_gen);
		return KUNCOAT_CORRUPT;
	}
	lz_reset_state(&z);
	status = lz_run(&z, in, in_len, out, out_cap, &at, 1);
	free(z.probs);
	free(z.lit_gen);
	if (produced)
		*produced = at;
	return status;
}

/*
 * LZMA2: the same coder, cut into chunks that say what to carry over.
 *
 * 7-Zip writes its content with this rather than with plain LZMA - measured over
 * 369 real archives, every one of the 258 whose folder could be located uses it and
 * none use plain LZMA. So an engine with an LZMA decoder and no LZMA2 can read a
 * 7z's file list and none of its files, which is where this one was.
 *
 * The format is a header byte and then a chunk:
 *
 *   0x00        the stream ends
 *   0x01, 0x02  an UNCOMPRESSED chunk, with and without a dictionary reset. Two
 *               more bytes give its length and the bytes follow verbatim.
 *   0x80..0xff  an LZMA chunk. The low five bits are the top of the decoded
 *               length, two bytes give the rest of it and two more give the
 *               compressed length; bits five and six say how much state to throw
 *               away first, and at two or above a properties byte follows.
 *
 * Every length is stored one less than it is, so a chunk can never be empty and
 * the loop always advances - which is what bounds it without a counter.
 *
 * What makes this more than a wrapper is the carrying over. A chunk asking for no
 * reset continues the previous chunk's probability model, its match distances and
 * its dictionary, so decoding it alone produces bytes that are not the file. The
 * dictionary needs no special handling here because a match reads out of the output
 * buffer and the output cursor is simply not rewound between chunks.
 */
enum kuncoat_status kuncoat_lzma2_decode(const uint8_t *in, uint64_t in_len, uint8_t *out,
		     uint64_t out_cap, uint64_t *produced)
{
	struct lz_state z;
	uint64_t p = 0, at = 0;
	int status = KUNCOAT_OK, have_props = 0, ended = 0;

	if (produced)
		*produced = 0;
	if ((!in && in_len) || (!out && out_cap))
		return KUNCOAT_BAD_ARG;
	if (out_cap == 0)
		return KUNCOAT_STOPPED;

	memset(&z, 0, sizeof z);

	while (p < in_len && at < out_cap) {
		uint8_t control = in[p++];
		uint64_t u_len, u_full, c_len;
		unsigned reset;

		if (control == 0) {
			ended = 1;              /* the stream says it is done */
			break;
		}

		if (control < 0x80u) {
			if (control > 2u) {
				status = KUNCOAT_CORRUPT;
				break;
			}
			if (p + 2u > in_len) {
				status = KUNCOAT_TRUNCATED;
				break;
			}
			u_len = ((uint64_t)in[p] << 8 | in[p + 1]) + 1u;
			p += 2u;
			if (control == 1u)
				z.dict_start = at;      /* a dictionary reset */
			if (p + u_len > in_len) {
				u_len = in_len - p;
				status = KUNCOAT_TRUNCATED;
			}
			if (u_len > out_cap - at) {
				u_len = out_cap - at;
				status = KUNCOAT_STOPPED;
			}
			memcpy(out + at, in + p, (size_t)u_len);
			at += u_len;
			p += u_len;
			/*
			 * The model is NOT reset here, and getting that wrong is
			 * what cut four real archives short.
			 *
			 * The intuition is that bytes written without the coder
			 * must invalidate it - and the format says otherwise. An
			 * uncompressed chunk resets the dictionary when its control
			 * byte is 1 and nothing at all when it is 2, leaving the
			 * probability model and the match distances for the chunk
			 * that follows to continue. Measured on an archive whose
			 * second chunk is uncompressed and whose third asks for no
			 * reset: resetting produced 115470 bytes of 1657182, all of
			 * them wrong after the first chunk.
			 */
			if (status != KUNCOAT_OK)
				break;
			continue;
		}

		if (p + 4u > in_len) {
			status = KUNCOAT_TRUNCATED;
			break;
		}
		u_full = (((uint64_t)(control & 0x1fu) << 16) |
			  ((uint64_t)in[p] << 8) | in[p + 1]) + 1u;
		u_len = u_full;
		c_len = (((uint64_t)in[p + 2] << 8) | in[p + 3]) + 1u;
		p += 4u;
		reset = ((unsigned)control >> 5) & 3u;

		if (reset >= 2u) {
			unsigned d;

			if (p >= in_len) {
				status = KUNCOAT_TRUNCATED;
				break;
			}
			d = in[p++];
			if (d >= 9u * 5u * 5u ||
			    !lz_set_props(&z, d % 9u, (d / 9u) % 5u, d / (9u * 5u))) {
				status = KUNCOAT_CORRUPT;
				break;
			}
			have_props = 1;
		}
		if (!have_props) {
			/* A chunk that continues properties nobody set. */
			status = KUNCOAT_CORRUPT;
			break;
		}
		if (reset == 3u)
			z.dict_start = at;      /* a dictionary reset: nothing before it is reachable */
		if (reset >= 1u)
			lz_reset_state(&z);

		if (p + c_len > in_len) {
			c_len = in_len - p;
			status = KUNCOAT_TRUNCATED;
		}
		if (u_len > out_cap - at)
			u_len = out_cap - at;

		{
			uint64_t before = at;
			int r_status;

			/*
			 * The decoder is given the rest of the stream, not just
			 * this chunk, and the OUTPUT length is what stops it.
			 *
			 * A range decoder reads ahead: normalising consumes bytes
			 * before the symbols that need them, so a decoder handed
			 * exactly c_len bytes runs out a few bytes early and
			 * reports a truncation that is not one. Measured, that cut
			 * four of 256 real archives short - one of them to 218697
			 * bytes of 14035136 - and the larger the chunk the likelier
			 * it was, because more symbols means more normalising.
			 *
			 * Reading past the chunk is safe because u_len bounds what
			 * comes out and `p` advances by c_len regardless: the
			 * chunk's own length still decides where the next one
			 * begins, which is the only thing it is authoritative for.
			 */
			r_status = lz_run(&z, in + p, in_len - p, out, at + u_len, &at, 0);
			/*
			 * A CHUNK THAT FILLED ITS OWN LENGTH HAS ENDED, NOT BEEN
			 * REFUSED.
			 *
			 * lz_run is given `at + u_len` as its output bound - the
			 * CHUNK's declared size, chosen by this loop - so reaching
			 * it is the ordinary way a chunk finishes, and lz_run says
			 * STOPPED because from inside it a bound is a bound. The
			 * loop below then treated that as a reason to stop the
			 * whole stream, so every LZMA2 stream of more than one
			 * chunk ended after the first.
			 *
			 * It went unnoticed because most do not have a second:
			 * 251 of 256 archives measured are a single chunk, and for
			 * those the break lands where the stream ends anyway.
			 * Win32.Fearso.c.7z is two folders of several chunks each,
			 * and produced 67075 of 392128 bytes - the first chunk,
			 * exactly - while a reference decoder read both folders
			 * whole.
			 *
			 * But the bound is the CHUNK's only when the caller's room
			 * did not cut it: a chunk clipped to the room (u_len below
			 * the declared u_full) ended because the buffer filled, and
			 * that is STOPPED.
			 */
			if ((r_status == KUNCOAT_STOPPED || r_status == KUNCOAT_OK) &&
			    at == before + u_len)
				r_status = u_len < u_full ? KUNCOAT_STOPPED : KUNCOAT_OK;
			/* A chunk is exactly its declared length: an end marker or any
			 * other way of stopping short is the stream disagreeing with
			 * itself. (A chunk that produced nothing is the same fault, and
			 * is what keeps a chain of empty chunks from never ending.) */
			if (r_status == KUNCOAT_OK && at != before + u_len)
				r_status = KUNCOAT_CORRUPT;
			/* Not just the zero-progress case: a chunk can produce
			 * some bytes and still end short (r.short_input mid-stream),
			 * and that status must survive past `p += c_len` too, or a
			 * corrupt/truncated chunk that decoded partially reads as a
			 * clean KUNCOAT_OK once the loop moves on to the next chunk
			 * header. */
			if (status == KUNCOAT_OK)
				status = r_status;
			if (at == before) {
				if (status == KUNCOAT_OK)
					status = KUNCOAT_CORRUPT;
				break;
			}
		}
		p += c_len;
		if (status != KUNCOAT_OK)
			break;
	}

	if (status == KUNCOAT_OK) {
		if (at >= out_cap) {
			/*
			 * The buffer is full. Filling it is not being refused: it
			 * is the whole answer when the stream ends here, with its
			 * end byte or (a container that kept no end byte) with its
			 * last chunk. STOPPED belongs to the case where the stream
			 * has more chunks to say.
			 */
			if (p < in_len && in[p] != 0)
				status = KUNCOAT_STOPPED;
		} else if (!ended) {
			status = KUNCOAT_TRUNCATED;   /* no end byte: the input ended first */
		}
	}

	free(z.probs);
	free(z.lit_gen);
	if (produced)
		*produced = at;
	return status;
}
