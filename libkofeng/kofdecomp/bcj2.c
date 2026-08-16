/*
 * bcj2.c - the four stream x86 branch decoder.
 *
 * The range coder here is the same arithmetic coder LZMA uses, cut down to the one
 * operation this needs: decode a single bit under an adaptive probability. It is
 * written out rather than shared with lzma.c because the two want different things
 * from it - lzma.c's version is tangled with the match state it drives, and prying
 * them apart to save forty lines would put a hot loop behind an indirection for the
 * benefit of a cold one.
 */

#include "bcj2.h"

/*
 * The coder's constants, all from the format.
 *
 * Eleven bits of probability, five bits of adaptation, and renormalisation once the
 * range drops below 2^24. A probability starts at half - 1024 of 2048 - and moves
 * toward whichever answer keeps arriving.
 */
#define PROB_BITS   11
#define PROB_TOTAL  (1u << PROB_BITS)
#define PROB_INIT   (PROB_TOTAL / 2u)
#define MOVE_BITS   5
#define TOP_VALUE   (1u << 24)

/* 0xE8 gets a slot per preceding byte; 0xE9 and the conditional jumps get one
 * each. The preceding byte matters because what comes before a call in compiled
 * code is far from uniform, and splitting on it is most of what makes this model
 * work. */
#define N_PROBS     (256u + 2u)
#define PROB_E9     256u
#define PROB_JCC    257u

struct rc {
	const uint8_t *p;
	uint64_t n, at;
	uint32_t range, code;
};

/*
 * Out of input reads as zero.
 *
 * A truncated stream then decodes to something rather than reading past its end,
 * and the caller finds out because the output comes up short. The alternative -
 * failing at the first missing byte - throws away the part that did arrive, which
 * for a scanner is the part worth having.
 */
static uint8_t rc_byte(struct rc *r)
{
	return r->at < r->n ? r->p[r->at++] : 0u;
}

static void rc_init(struct rc *r, const uint8_t *p, uint64_t n)
{
	uint32_t i;

	r->p = p;
	r->n = n;
	r->at = 0;
	r->range = 0xffffffffu;
	r->code = 0;
	/* Five bytes, of which the first carries no information: the encoder emits
	 * it so that the first renormalisation has something to shift in. */
	(void)rc_byte(r);
	for (i = 0; i < 4u; i++)
		r->code = (r->code << 8) | rc_byte(r);
}

static uint32_t rc_bit(struct rc *r, uint16_t *prob)
{
	uint32_t bound = (r->range >> PROB_BITS) * (uint32_t)*prob;
	uint32_t bit;

	if (r->code < bound) {
		r->range = bound;
		*prob = (uint16_t)(*prob + ((PROB_TOTAL - *prob) >> MOVE_BITS));
		bit = 0;
	} else {
		r->range -= bound;
		r->code -= bound;
		*prob = (uint16_t)(*prob - (*prob >> MOVE_BITS));
		bit = 1;
	}
	if (r->range < TOP_VALUE) {
		r->range <<= 8;
		r->code = (r->code << 8) | rc_byte(r);
	}
	return bit;
}

/*
 * Is this byte the opcode of a branch the encoder may have converted?
 *
 * `prev` is the byte before it, which only matters for the two byte conditional
 * jumps - 0x0F 0x8x. A one byte 0xE8 or 0xE9 is a candidate wherever it appears.
 */
static int is_branch(uint8_t prev, uint8_t b)
{
	return b == 0xe8u || b == 0xe9u ||
	       (prev == 0x0fu && (b & 0xf0u) == 0x80u);
}

uint64_t kof_bcj2_decode(const uint8_t *main_p, uint64_t main_n,
			 const uint8_t *call_p, uint64_t call_n,
			 const uint8_t *jump_p, uint64_t jump_n,
			 const uint8_t *rc_p, uint64_t rc_n,
			 uint8_t *out, uint64_t out_cap)
{
	uint16_t prob[N_PROBS];
	struct rc r;
	uint64_t at = 0, mi = 0, ci = 0, ji = 0;
	uint32_t i;
	uint8_t prev = 0;

	if (!main_p || !call_p || !jump_p || !rc_p || !out || out_cap == 0)
		return 0;

	for (i = 0; i < N_PROBS; i++)
		prob[i] = PROB_INIT;
	rc_init(&r, rc_p, rc_n);

	while (at < out_cap) {
		uint8_t b;

		if (mi >= main_n)
			break;                  /* the code stream ran out */
		b = main_p[mi++];
		out[at++] = b;

		if (!is_branch(prev, b)) {
			prev = b;
			continue;
		}

		{
			uint16_t *p = b == 0xe8u ? &prob[prev]
				    : b == 0xe9u ? &prob[PROB_E9]
						 : &prob[PROB_JCC];

			if (!rc_bit(&r, p)) {
				/* Not converted: an ordinary byte that happens to
				 * look like an opcode. */
				prev = b;
				continue;
			}
		}

		/*
		 * Converted. The absolute target comes from the channel that matches
		 * the opcode - calls and jumps are separated because their targets
		 * cluster differently, which is the whole point of having two.
		 */
		{
			const uint8_t *src;
			uint64_t *idx, avail;
			uint32_t abs_addr, disp;

			if (b == 0xe8u) {
				src = call_p; idx = &ci; avail = call_n;
			} else {
				src = jump_p; idx = &ji; avail = jump_n;
			}
			if (*idx + 4u > avail)
				break;          /* the channel ran out */

			/* Big endian, which is how the channel stores it. */
			abs_addr = ((uint32_t)src[*idx] << 24) |
				   ((uint32_t)src[*idx + 1u] << 16) |
				   ((uint32_t)src[*idx + 2u] << 8) |
				   (uint32_t)src[*idx + 3u];
			*idx += 4u;

			/*
			 * Absolute back to relative, measured from the END of the
			 * instruction - which is four bytes past where the
			 * displacement starts, and `at` is already sitting on that
			 * start.
			 */
			disp = abs_addr - (uint32_t)(at + 4u);

			if (at + 4u > out_cap)
				break;          /* no room for the displacement */
			out[at++] = (uint8_t)disp;
			out[at++] = (uint8_t)(disp >> 8);
			out[at++] = (uint8_t)(disp >> 16);
			out[at++] = (uint8_t)(disp >> 24);
			/* The byte before the next opcode is the last one written,
			 * not the opcode that started this. */
			prev = (uint8_t)(disp >> 24);
		}
	}
	return at;
}
