/*
 * mpress.c - MPRESS's call target conversion, undone. See mpress.h for what it is and is not.
 */

#include <kofcore.h>   /* kof_ld_le32 */
#include "mpress.h"

#define MPRESS_TAIL 0x1000u     /* the stub's own bound on the scan */

uint64_t kuncoat_mpress_cto_decode(uint8_t *buf, uint64_t n, unsigned bits)
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
		v = kof_ld_le32(buf + site);
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
