/*
 * rarcommon.h - the parts of RAR decoding that are the same in 2.9/3.x and 5.
 *
 * The two decoders are deliberately separate files: the table sizes differ, the
 * bit reader is sixteen bits wide in one and thirty two in the other, and the
 * headers of both say why matching each format exactly is the difference
 * between a decoder that works and one that drifts a bit at a time.
 *
 * These three are the pieces where that argument does not apply. A canonical
 * Huffman table is built the same way whatever the alphabet is, a delta filter
 * is a delta filter, and the four most recent distances are a shift register.
 * They were byte-for-byte identical in both files, which is two places for a
 * fix to be applied once.
 *
 * THE HUFFMAN BOUND IS STILL PER FORMAT. It was spelled TABLE_SIZE in both, and
 * TABLE_SIZE is 404 in rar3.c and 430 in rar5.c - the same word for two numbers.
 * Merging on the larger would have let rar3 record table entries its format
 * cannot have; merging on the smaller would have truncated rar5's. So the cap
 * is an argument and each caller passes its own, which is also the only shape
 * in which the bound is visible at the call site rather than hidden in a macro.
 */

#ifndef KOFENG_DECOMP_RARCOMMON_H
#define KOFENG_DECOMP_RARCOMMON_H

#include <stdint.h>
#include <string.h>

/*
 * Build a canonical Huffman decode table from `size` four-bit lengths.
 *
 * `len` and `pos` are sixteen entries each - one per code length - and `num`
 * holds `num_cap` symbol numbers. A length of zero is not a code and is not
 * counted, which is what makes count[0] = 0 rather than an oversight.
 */
static inline void kof_rar_huff_build(uint32_t *len, uint32_t *pos,
				      uint16_t *num, uint32_t num_cap,
				      uint32_t *max, const uint8_t *bits,
				      uint32_t size)
{
	uint32_t count[16], tmp[16], i;
	uint32_t n = 0, m;

	memset(count, 0, sizeof count);
	memset(num, 0, (size_t)num_cap * sizeof *num);
	for (i = 0; i < size; i++)
		count[bits[i] & 0x0fu]++;
	count[0] = 0;

	tmp[0] = pos[0] = len[0] = 0;
	for (i = 1; i < 16u; i++) {
		n = 2u * (n + count[i]);
		m = n << (15u - i);
		if (m > 0xffffu)
			m = 0xffffu;
		len[i] = m;
		tmp[i] = pos[i] = pos[i - 1u] + count[i - 1u];
	}
	for (i = 0; i < size; i++)
		if (bits[i] & 0x0fu) {
			uint32_t l = bits[i] & 0x0fu;

			if (tmp[l] < num_cap)
				num[tmp[l]++] = (uint16_t)i;
		}
	*max = size;
}

/*
 * The delta filter: de-interleave `chan` channels and undo the differences.
 *
 * `scratch` holds the interleaved copy while the output is rewritten in place,
 * so it must be at least `n` bytes; a shorter one is refused rather than
 * clamped, because a clamp would produce plausible bytes from half the input.
 */
static inline int kof_rar_filt_delta(uint8_t *d, uint32_t n, uint32_t chan,
				     uint8_t *scratch, uint64_t scratch_len)
{
	uint32_t ch, src = 0;

	if (chan == 0u || n == 0u || (uint64_t)n > scratch_len)
		return 0;
	memcpy(scratch, d, n);
	for (ch = 0; ch < chan; ch++) {
		uint8_t prev = 0;
		uint32_t at;

		for (at = ch; at < n; at += chan) {
			prev = (uint8_t)(prev - scratch[src++]);
			d[at] = prev;
		}
	}
	return 1;
}

/* The four most recent distances, newest first. */
static inline void kof_rar_push_dist(uint32_t *old_dist, uint32_t d)
{
	old_dist[3] = old_dist[2];
	old_dist[2] = old_dist[1];
	old_dist[1] = old_dist[0];
	old_dist[0] = d;
}

#endif /* KOFENG_DECOMP_RARCOMMON_H */
