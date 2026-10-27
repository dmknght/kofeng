/*
 * kofentropy.h - Shannon entropy of bytes. In core: the emulator gate (genome) and
 * the tools read the same number; <kofeng.h> includes this.
 */
#ifndef KOFENG_KOFENTROPY_H
#define KOFENG_KOFENTROPY_H

#include <stdint.h>

/*
 * SHANNON ENTROPY OF A BUFFER, IN EIGHTHS OF A BIT - 0 to 64.
 *
 * How evenly the 256 byte values are spread. 0 means every byte is the same
 * value, 64 means all 256 occur equally often. The prefix is `kentropy_` and
 * not something shorter because a name nobody can expand is a name that gets
 * misread, and this number is misread easily enough as it is - see the
 * paragraph on what it is NOT, below.
 *
 * Public because three places need the same number and were about to have three
 * of them: the emulator's gate uses it to decide whether a segment looks
 * encrypted, and both tools want it beside a region's size, where it is the
 * cheapest thing that separates code from compressed data from padding.
 *
 * EIGHTHS AND NOT A DOUBLE, and the engine computes it without floating point
 * at all: an integer log2 plus a linear correction, which is accurate to well
 * under the eighth of a bit it reports and is checked against the float version
 * in tests/unit/emu_gate.c. A host that wants to print bits divides by 8.0.
 *
 * IT IS A SHAPE AND NEVER A VERDICT. 7.9 bits is a compressed archive, an
 * encrypted payload, and a JPEG; 1.0 is padding and also a long run of one
 * instruction. What it is good for is telling a reader which region to look at
 * first, and telling a gate which region is not worth interpreting.
 *
 * Zero for an empty buffer, which is honest: no bytes carry no information.
 */
uint32_t kentropy_eighths(const void *bytes, uint64_t n);

/*
 * THE SAME NUMBER, FROM A COUNT SOMEBODY ALREADY HAS.
 *
 * `hist[v]` is how many times byte value `v` occurs; `total` is their sum.
 *
 * Two entry points because there are two ways the count arrives and neither is
 * free: a caller measuring one buffer wants the wrapper above, and a caller
 * sliding a window over a segment maintains the histogram incrementally and
 * would pay a full recount per step to use it. `total` is the sum of the
 * buckets and is passed rather than recomputed, since the sliding caller
 * already knows it.
 */
uint32_t kentropy_hist(const uint32_t hist[256], uint64_t total);

/*
 * THE SAME NUMBER IN HUNDREDTHS OF A BIT - 0 to 800, rounded to nearest.
 *
 * For a reader that prints bits per byte with two decimals: the eighths above are a
 * 0.125 step and say nothing of the second decimal. Integer arithmetic only, like
 * kentropy_hist: log2 of each bucket's share is taken to 12 fractional bits by
 * repeated squaring, so the error of a bucket's term is far below 0.005 bit. A
 * bucket above `total` is clamped as kentropy_hist clamps it; zero for no bytes.
 */
uint32_t kentropy_hist_centi(const uint32_t hist[256], uint64_t total);

/*
 * THE COUNT ITSELF: add the `n` bytes at `bytes` to `hist`. The one place a byte
 * histogram is built - kentropy_eighths, the emulator's gate windows and the
 * engine's region measure all count through it, and each then asks
 * kentropy_hist for the number. The caller zeroes `hist` first (or keeps adding
 * to one histogram over several ranges, which is what a region of several
 * extents does).
 */
static inline void kentropy_count(uint32_t hist[256], const void *bytes, uint64_t n)
{
	const uint8_t *p = (const uint8_t *)bytes;
	uint64_t i;

	for (i = 0; i < n; i++)
		hist[p[i]]++;
}

#endif /* KOFENG_KOFENTROPY_H */
