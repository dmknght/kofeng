/*
 * bcj.c - the x86 branch transform, undone.
 *
 * The whole of it is: find a byte that could begin a CALL (0xE8) or a JMP (0xE9),
 * decide whether it really does, and if so turn the four byte address after it from
 * absolute back into relative.
 *
 * The deciding is the hard half. A 0xE8 byte occurs constantly in data that is not
 * an instruction, so rewriting every one would corrupt more than it fixed. Two
 * tests are applied and both come from the format:
 *
 *   - the address's top byte must be 0x00 or 0xFF. A real relative branch reaches
 *     somewhere nearby, so the high byte of the converted value is one of those two
 *     and anything else was never an instruction.
 *
 *   - a small state machine remembers which of the last few positions looked like
 *     branches. Instructions do not overlap, so a candidate a byte or two after
 *     another candidate is evidence that at least one of them is not real, and the
 *     mask below is how the format says to resolve that.
 *
 * The loop that follows the first test exists because the conversion can produce a
 * value whose own top byte is again 0x00 or 0xFF, which would have been converted
 * differently on the way in. It walks that back until the two agree.
 */

#include "bcj.h"

/* The two values a real converted address can have in its top byte. */
static int top_is_sign(uint8_t b)
{
	return b == 0x00u || b == 0xffu;
}

/*
 * Which mask states allow a conversion, and which bit each state points at.
 *
 * Both are from the format. The first says whether the recent history of
 * candidates leaves room for this one to be real; the second says, when the
 * conversion has to be walked back, how far.
 */
static const uint8_t MASK_ALLOWED[8] = { 1, 1, 1, 0, 1, 0, 0, 0 };
static const uint8_t MASK_BIT[8]     = { 0, 1, 2, 2, 3, 3, 3, 3 };

uint64_t kof_bcj_x86_decode(uint8_t *buf, uint64_t n, uint32_t start)
{
	uint64_t at = 0, limit;
	uint32_t mask = 0;
	uint32_t prev = (uint32_t)-1;   /* no candidate seen yet */

	if (!buf || n < 5u)
		return 0;
	limit = n - 5u;

	/*
	 * The first candidate has no history behind it. Placing `prev` five before
	 * the start makes the distance test below say "far away", which is what
	 * "nothing before this" means to the state machine.
	 */
	prev = start - 5u;

	while (at <= limit) {
		uint8_t b = buf[at];
		uint32_t here, gap;
		uint32_t src, dest;

		if (b != 0xe8u && b != 0xe9u) {
			at++;
			continue;
		}

		here = start + (uint32_t)at;
		gap = here - prev;
		prev = here;

		/*
		 * How far back the last candidate was. Beyond five it cannot
		 * overlap this one, so the history is irrelevant and starts again;
		 * within five, the mask is shifted by the distance so that the bits
		 * line up with where those candidates were.
		 */
		if (gap > 5u) {
			mask = 0;
		} else {
			uint32_t k;

			for (k = 0; k < gap; k++) {
				mask &= 0x77u;
				mask <<= 1;
			}
		}

		b = buf[at + 4u];

		if (top_is_sign(b) && MASK_ALLOWED[(mask >> 1) & 7u] &&
		    (mask >> 1) < 0x10u) {
			src = ((uint32_t)b << 24) |
			      ((uint32_t)buf[at + 3u] << 16) |
			      ((uint32_t)buf[at + 2u] << 8) |
			      (uint32_t)buf[at + 1u];

			for (;;) {
				uint32_t i;

				/* Absolute back to relative: the address is
				 * measured from the END of the instruction. */
				dest = src - (here + 5u);
				if (mask == 0)
					break;

				i = MASK_BIT[mask >> 1];
				b = (uint8_t)(dest >> (24u - i * 8u));
				if (!top_is_sign(b))
					break;
				src = dest ^ ((1u << (32u - i * 8u)) - 1u);
			}

			/*
			 * The top byte is written as all ones or all zeros from the
			 * sign of the result rather than copied, because that is
			 * what the conversion produced going the other way.
			 */
			buf[at + 4u] = (uint8_t)(~(((dest >> 24) & 1u) - 1u));
			buf[at + 3u] = (uint8_t)(dest >> 16);
			buf[at + 2u] = (uint8_t)(dest >> 8);
			buf[at + 1u] = (uint8_t)dest;
			at += 5u;
			mask = 0;
		} else {
			/* Not a branch, but remembered as a candidate: the next one
			 * within five bytes has to know this was here. */
			mask |= 1u;
			if (top_is_sign(b))
				mask |= 0x10u;
			at++;
		}
	}

	return at;
}
