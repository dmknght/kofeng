/*
 * inbyte.h - the input cursor shared by the byte-at-a-time decoders.
 *
 * The range decoder in lzma.c and the bit reader in aplib.c each fetched a byte
 * the same way and wrote it out twice: the next byte, or zero once the input is
 * spent, with the shortfall recorded in a flag the caller reads at the end. The
 * two structs name that flag differently (short_input, eof), which is why the
 * flag is passed by address and the cursor is three plain arguments instead of a
 * shared struct: forcing one struct on both would put a rename on every access
 * in two decoders that otherwise have nothing in common.
 *
 * Reading past the end is recorded and decoding continues, so the caller learns
 * the input was truncated rather than getting a decoder that stops mid-symbol in
 * an unexamined state.
 */

#ifndef KUNCOAT_DECOMP_INBYTE_H
#define KUNCOAT_DECOMP_INBYTE_H

#include <stdint.h>

static inline uint8_t kuncoat_in_byte(const uint8_t *in, uint64_t n, uint64_t *at,
				      int *spent)
{
	if (*at >= n) {
		*spent = 1;
		return 0;
	}
	return in[(*at)++];
}

#endif /* KUNCOAT_DECOMP_INBYTE_H */
