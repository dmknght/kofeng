/* kofentropy.c - see kofentropy.h. */

#include <string.h>
#include <kofentropy.h>

/*
 * See kofentropy.h. The arithmetic is the emulator gate's, lifted here rather than
 * copied: emu_unpack_gate.c calls this, so there is one implementation and one
 * place for the test in tests/unit/emu_gate.c to check.
 */
uint32_t kentropy_hist(const uint32_t hist[256], uint64_t total)
{
	uint64_t acc = 0, n = total;
	unsigned k;

	if (!hist || !n)
		return 0;
	for (k = 0; k < 256u; k++) {
		uint64_t c = hist[k], scaled, base, frac;
		unsigned lg = 0;

		if (!c)
			continue;
		/*
		 * A BUCKET CANNOT HOLD MORE THAN THE TOTAL - `total` is the sum of them, and
		 * a caller that passes less (a sliding window whose total was not kept in
		 * step) used to get scaled below 256, a negative per-bucket term in unsigned
		 * arithmetic and an average near 2^64 / n: an astronomically large number no
		 * caller can tell from "very high entropy" (8 bits is 64 eighths). Clamped,
		 * the term is zero for that bucket, so the answer stays within 0..64.
		 */
		if (c > n)
			c = n;
		/*
		 * -log2(c/n) = log2(n) - log2(c), computed on n*256/c so the
		 * fraction survives the integer log.
		 */
		scaled = (n << 8) / c;
		/*
		 * floor(log2(scaled)) IN ONE INSTRUCTION, and the loop it
		 * replaces had a shift this one cannot have.
		 *
		 * `while (scaled >> (lg + 1u)) lg++;` walks one bit per round -
		 * up to forty rounds for each of 256 buckets, every time a
		 * region's entropy is taken. It also steps lg up to 63 and then
		 * evaluates `scaled >> 64`, which is undefined: on x86 the count
		 * is taken modulo 64, so the test reads `scaled >> 0`, stays
		 * non-zero, and the loop runs away. `scaled` is (n << 8) / c
		 * with c <= n, so it is at least 256 and would need a 36-petabyte
		 * buffer to reach bit 63 - unreachable, but unreachable by
		 * arithmetic nobody restates when they change the caller.
		 *
		 * clzll is undefined at zero, which is the one input it must
		 * never see; the `if (!c)` above and c <= n together mean it
		 * cannot, and the test below says so rather than trusting it.
		 */
		lg = scaled ? 63u - (unsigned)__builtin_clzll(scaled) : 0u;
		base = (uint64_t)1 << lg;
		frac = ((scaled - base) << 3) / base;
		acc += c * (((uint64_t)lg << 3) + frac - (8u << 3));
	}
	/* 8 bits per byte is the most any byte string holds. Buckets that add up to MORE
	 * than `total` (the clamp above bounds one bucket, not their sum) could still
	 * push the average past it. */
	acc /= n;
	return acc > 64u ? 64u : (uint32_t)acc;
}

uint32_t kentropy_eighths(const void *bytes, uint64_t n)
{
	uint32_t hist[256];

	if (!bytes || !n)
		return 0;
	memset(hist, 0, sizeof hist);
	kentropy_count(hist, bytes, n);
	return kentropy_hist(hist, n);
}
