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

				/* Masked, like its sibling above. The reachable
				 * mask values never exceed seven here - proved by
				 * walking the state machine's closure - but that
				 * is a fact about another function, and the guard
				 * one line up already permits fifteen. */
				i = MASK_BIT[(mask >> 1) & 7u];
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

/* ---- MPRESS's call target conversion. See bcj.h for what it is and is not. */

#define MPRESS_TAIL 0x1000u     /* the stub's own bound on the scan */

uint64_t kof_mpress_cto_decode(uint8_t *buf, uint64_t n, unsigned bits)
{
	uint64_t at = 0, scan, done = 0;
	uint8_t cand[256];

	if (!buf || (bits != 32u && bits != 64u) || n <= MPRESS_TAIL)
		return 0;
	scan = n - MPRESS_TAIL;

	/*
	 * `at + 5 <= n` and not `at < scan` alone: the loop consumes a byte, may
	 * consume a second on the wide rule, and then reads four. The stub gets
	 * away without the test because it decompresses into a section with a
	 * page of slack after it and zeroes four bytes there; this buffer is
	 * exactly as long as it is, so the reads are bounded here instead.
	 */
	/*
	 * A TABLE, NOT THREE COMPARES PER BYTE.
	 *
	 * The scan looks at every byte of a multi-megabyte buffer and almost
	 * every one of them is none of the four it wants. Measured on the 8 MB
	 * an MPRESS sample decompresses to, the compare-per-byte form was
	 * 121,304,380 instructions, 9.2% of the scan - about fifteen a byte to
	 * answer "no" four times.
	 *
	 * The set is the same set: 0xE8, 0xE9, and on 64 bit also 0xFF and
	 * 0x8D. Built per call because it depends on the width, which costs
	 * 256 stores against millions of lookups.
	 */
	{
		unsigned c;

		for (c = 0; c < 256u; c++)
			cand[c] = 0;
		cand[0xe8] = 1; cand[0xe9] = 1;
		if (bits == 64u) {
			cand[0xff] = 1; cand[0x8d] = 1;
		}
	}

	while (at < scan && at + 5u <= n) {
		uint8_t b;

		while (at < scan && !cand[buf[at]])
			at++;
		if (at >= scan || at + 5u > n)
			break;
		b = buf[at++];
		{
		uint64_t site;
		uint32_t v;
		int32_t sv;

		if (b == 0xffu) {
			if (bits != 64u || (buf[at] & 0xfdu) != 0x15u)
				continue;
			at++;
		} else if (b == 0x8du) {
			if (bits != 64u || (buf[at] & 0xc7u) != 0x05u)
				continue;
			at++;
		} else if ((b & 0xfeu) != 0xe8u) {
			continue;
		}
		if (at + 4u > n)
			break;

		site = at;
		at += 4u;
		v = (uint32_t)buf[site] | ((uint32_t)buf[site + 1] << 8) |
		    ((uint32_t)buf[site + 2] << 16) |
		    ((uint32_t)buf[site + 3] << 24);
		sv = (int32_t)v;

		/*
		 * The two rejections are the stub's, in its order. A
		 * non-negative value that does not address this buffer was
		 * never a converted target; a negative one is given its
		 * position back and rejected if it is still negative.
		 *
		 * The arithmetic is done in uint32_t throughout because the
		 * stub does it in 32 bit registers and wraps - `site` is
		 * truncated deliberately rather than by accident, and a buffer
		 * over 4 GB is not one this decoder produces.
		 */
		if (sv >= 0) {
			if ((uint32_t)sv >= (uint32_t)scan)
				continue;
		} else {
			v = (uint32_t)(v + (uint32_t)site);
			if ((int32_t)v < 0)
				continue;
			v = (uint32_t)(v + (uint32_t)scan);
		}
		v = (uint32_t)(v - (uint32_t)site);

		buf[site]     = (uint8_t)(v);
		buf[site + 1] = (uint8_t)(v >> 8);
		buf[site + 2] = (uint8_t)(v >> 16);
		buf[site + 3] = (uint8_t)(v >> 24);
		done++;
		}
	}
	return done;
}
