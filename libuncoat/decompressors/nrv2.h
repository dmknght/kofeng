/*
 * nrv2.h - the NRV2B, NRV2D and NRV2E decoders that UPX packs with.
 *
 * Measured on 9482 real Linux malware samples: 804 carry a UPX PackHeader, and of
 * those 93% are compressed with one of these three - NRV2E alone is 82.5%. LZMA is
 * 1.7%. That is what makes these the ones to have.
 *
 *
 * WHY THIS DOES NOT STREAM, WHEN INFLATE DOES
 *
 * The one structural difference worth knowing before reading the code. DEFLATE
 * bounds a back reference at 32768 bytes, so a decoder needs a window of exactly
 * that and output can leave through a sink as it is produced - which is what makes
 * inflate cost 32KB regardless of how large the stream is.
 *
 * NRV2 has NO SUCH BOUND. A match distance is built up bit by bit with no ceiling
 * and may reach any byte the stream has already produced, so the decoder needs the
 * whole of its output randomly addressable until the stream ends. There is no
 * window size that makes this streamable; the buffer IS the window.
 *
 * The consequence is that a caller must decide how large an output it is willing to
 * hold BEFORE decoding, and that decision is the memory limit. It is passed in as
 * out_cap and it is a hard bound: reaching it stops the decode. The declared
 * uncompressed length in a UPX header is a claim by the file and is a hint for
 * sizing at most, never a bound - the bound is what the caller allocated.
 *
 *
 * WRITTEN FROM THE FORMAT, NOT FROM A REFERENCE
 *
 * The bit coding was worked out from the UCL/NRV format as UPX's decompression
 * stub implements it, and the structure here is deliberately its own: one decode
 * loop with the two points the variants actually differ at, rather than three
 * near-copies. ClamAV's upx.c decodes the same formats and is GPL-2; it was read to
 * understand the coding, and no part of it is reproduced here.
 */

#ifndef KUNCOAT_NRV2_H
#define KUNCOAT_NRV2_H

#include <stdint.h>

#include "../status.h"

/*
 * Which coding. The values are ours, not UPX's method numbers; mapping one to the
 * other belongs where the UPX header is parsed.
 */
enum kuncoat_nrv2_variant {
	KUNCOAT_NRV2B = 0,
	KUNCOAT_NRV2D,
	KUNCOAT_NRV2E
};

/*
 * How wide the bit buffer is, and why it is a separate argument.
 *
 * UPX names its methods NRV2B_8, NRV2B_LE16 and NRV2B_LE32, and the suffix is the
 * WIDTH OF THE BIT BUFFER: an _8 stream refills one byte at a time and takes its
 * next bit from position 7, an _LE32 stream refills four bytes little endian and
 * takes bit 31. The item coding above is identical across the three.
 *
 * Worth stating because the obvious reading is wrong and this code was first written
 * on it - that the suffix named the filter applied before compression, so all three
 * would decode the same way. Run against real samples, every _LE32 block decoded to
 * its declared length and every _8 block failed: 285 of 285 against 0 of 52. A
 * suffix that looked like packaging was the bit reader.
 */
enum kuncoat_nrv2_bits {
	KUNCOAT_NRV2_BITS_8  = 8,
	KUNCOAT_NRV2_BITS_16 = 16,
	KUNCOAT_NRV2_BITS_32 = 32
};

/*
 * Decode into a caller-owned buffer.
 *
 * `produced` is always set, whatever the status: a truncated or corrupt stream
 * still yields a real prefix, and for a scanner that prefix is usually the part
 * that identifies the sample.
 *
 * Returns a kuncoat_status. KUNCOAT_STOPPED means the output buffer filled -
 * the receiver's limit, not the stream's failure. A variant that is not one of the
 * three above, a NULL `in` with in_len > 0 or a NULL `out` with out_cap > 0 is
 * KUNCOAT_BAD_ARG (nothing is read); a bit width other than 8, 16 or 32 is CORRUPT,
 * and out_cap 0 is STOPPED. `produced` may be NULL.
 */
enum kuncoat_status kuncoat_nrv2_decode(int variant, int bits, const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced);

#endif /* KUNCOAT_NRV2_H */
