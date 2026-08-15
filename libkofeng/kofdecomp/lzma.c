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
static inline uint8_t rc_byte(struct rc *r)
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
	unsigned  lc, lp, pb;
	uint32_t  state, rep0, rep1, rep2, rep3;
};

static void lz_reset_state(struct lz_state *z)
{
	uint64_t i;

	z->state = 0;
	z->rep0 = z->rep1 = z->rep2 = z->rep3 = 1;
	for (i = 0; i < z->n_probs; i++)
		z->probs[i] = PROB_INIT;
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

	if (lc > KOF_LZMA_MAX_LC || lp > KOF_LZMA_MAX_LP || pb > KOF_LZMA_MAX_PB)
		return 0;
	want = (uint64_t)O_LITERAL + ((uint64_t)0x300u << (lc + lp));
	if (want > z->n_probs) {
		uint16_t *nv = realloc(z->probs, (size_t)want * sizeof *nv);

		if (!nv)
			return 0;
		z->probs = nv;
		z->n_probs = want;
	}
	z->lc = lc;
	z->lp = lp;
	z->pb = pb;
	return 1;
}

/*
 * Decode one LZMA stream into out[] starting at `at`, stopping at `limit`.
 *
 * `at` is both where output goes and how far back a match may reach, which is why
 * it comes in rather than starting at zero: an LZMA2 chunk continues the previous
 * chunk's dictionary, and the dictionary is the output written so far.
 */
static int lz_run(struct lz_state *z, const uint8_t *in, uint64_t in_len,
		  uint8_t *out, uint64_t limit, uint64_t *at_io)
{
	struct rc r;
	uint16_t *probs = z->probs;
	uint64_t at = *at_io;
	uint32_t state = z->state, rep0 = z->rep0, rep1 = z->rep1;
	uint32_t rep2 = z->rep2, rep3 = z->rep3;
	uint32_t pos_mask = (1u << z->pb) - 1u;
	uint32_t lit_pos_mask = (1u << z->lp) - 1u;
	unsigned lc = z->lc;
	uint64_t out_cap = limit;
	int status = KOF_DEC_OK;

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
int kof_lzma_decode(unsigned lc, unsigned lp, unsigned pb,
		    const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced)
{
	struct lz_state z;
	uint64_t at = 0;
	int status;

	if (produced)
		*produced = 0;
	if (!in || !out || out_cap == 0)
		return KOF_DEC_STOPPED;

	memset(&z, 0, sizeof z);
	/* Checked before the allocation they size, and before anything else uses
	 * them: these came out of a container and nothing has vouched for them. */
	if (!lz_set_props(&z, lc, lp, pb)) {
		free(z.probs);
		return KOF_DEC_CORRUPT;
	}
	lz_reset_state(&z);
	status = lz_run(&z, in, in_len, out, out_cap, &at);
	free(z.probs);
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
int kof_lzma2_decode(const uint8_t *in, uint64_t in_len, uint8_t *out,
		     uint64_t out_cap, uint64_t *produced)
{
	struct lz_state z;
	uint64_t p = 0, at = 0;
	int status = KOF_DEC_OK, have_props = 0;

	if (produced)
		*produced = 0;
	if (!in || !out || out_cap == 0)
		return KOF_DEC_STOPPED;

	memset(&z, 0, sizeof z);

	while (p < in_len && at < out_cap) {
		uint8_t control = in[p++];
		uint64_t u_len, c_len;
		unsigned reset;

		if (control == 0)
			break;                  /* the stream says it is done */

		if (control < 0x80u) {
			if (control > 2u) {
				status = KOF_DEC_CORRUPT;
				break;
			}
			if (p + 2u > in_len) {
				status = KOF_DEC_TRUNCATED;
				break;
			}
			u_len = ((uint64_t)in[p] << 8 | in[p + 1]) + 1u;
			p += 2u;
			if (p + u_len > in_len) {
				u_len = in_len - p;
				status = KOF_DEC_TRUNCATED;
			}
			if (u_len > out_cap - at) {
				u_len = out_cap - at;
				status = KOF_DEC_STOPPED;
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
			if (status != KOF_DEC_OK)
				break;
			continue;
		}

		if (p + 4u > in_len) {
			status = KOF_DEC_TRUNCATED;
			break;
		}
		u_len = (((uint64_t)(control & 0x1fu) << 16) |
			 ((uint64_t)in[p] << 8) | in[p + 1]) + 1u;
		c_len = (((uint64_t)in[p + 2] << 8) | in[p + 3]) + 1u;
		p += 4u;
		reset = ((unsigned)control >> 5) & 3u;

		if (reset >= 2u) {
			unsigned d;

			if (p >= in_len) {
				status = KOF_DEC_TRUNCATED;
				break;
			}
			d = in[p++];
			if (d >= 9u * 5u * 5u ||
			    !lz_set_props(&z, d % 9u, (d / 9u) % 5u, d / (9u * 5u))) {
				status = KOF_DEC_CORRUPT;
				break;
			}
			have_props = 1;
		}
		if (!have_props) {
			/* A chunk that continues properties nobody set. */
			status = KOF_DEC_CORRUPT;
			break;
		}
		if (reset >= 1u)
			lz_reset_state(&z);

		if (p + c_len > in_len) {
			c_len = in_len - p;
			status = KOF_DEC_TRUNCATED;
		}
		if (u_len > out_cap - at)
			u_len = out_cap - at;

		{
			uint64_t before = at;

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
			lz_run(&z, in + p, in_len - p, out, at + u_len, &at);
			if (at == before) {
				/* The chunk decoded nothing. Continuing would ask
				 * the next record the same question with the same
				 * answer, which is how a chain of empty chunks
				 * becomes a decode that never ends. */
				if (status == KOF_DEC_OK)
					status = KOF_DEC_CORRUPT;
				break;
			}
		}
		p += c_len;
		if (status != KOF_DEC_OK)
			break;
		/*
		 * Filling the buffer is not being refused.
		 *
		 * The loop condition ends the decode on its own when the output is
		 * full, and reporting STOPPED there would call every stream that
		 * decoded to exactly its declared length a truncated one - measured,
		 * 251 of 256 real archives. STOPPED belongs to the case below,
		 * where the buffer is full AND the stream has more to say.
		 */
		if (at >= out_cap && p < in_len && in[p] != 0) {
			status = KOF_DEC_STOPPED;
			break;
		}
	}

	free(z.probs);
	if (produced)
		*produced = at;
	return status;
}
