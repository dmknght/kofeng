/*
 * lzw.h - LZW as PDF and TIFF write it.
 *
 * NOT the GIF variant, and the difference is not cosmetic: GIF packs its codes
 * least-significant-bit first and this packs them most-significant-bit first,
 * so a decoder for one produces confident nonsense on the other. The two
 * formats that matter here - PDF's /LZWDecode and TIFF's compression 5 - agree
 * with each other, which is why one decoder serves both.
 *
 * WHY IT IS WORTH HAVING AT ALL, given that Flate replaced it in 1996.
 *
 * Because it was replaced. A stream nobody expects is a stream a parser was
 * never taught, and reaching for an obsolete filter is a cheap way to put
 * content past one - the content is ordinary, only the wrapper is unusual. This
 * decoder exists for the wrapper, not because LZW is common.
 *
 * A SEPARATE FILE FROM textcode.c, which holds the other codings PDF layers in
 * front of its streams. Those are loops with a few bytes of carry; this has a
 * dictionary of four thousand entries and a code width that grows as it fills,
 * so it needs state that outlives a call and it gets a struct of its own -
 * allocated once per thread and reused, the way kof_inflate is.
 *
 * EARLY CHANGE IS ASSUMED PRESENT, which is PDF's default and TIFF's
 * behaviour: the code width grows one code BEFORE the table would strictly
 * require it. A stream that says /EarlyChange 0 is decoded wrongly by this and
 * the caller is expected to refuse it rather than let it through - see the
 * parser's check for that key. Stated here because a decoder that is right for
 * one setting and silent about the other is the kind of thing that produces
 * plausible garbage.
 */

#ifndef KOFENG_LZW_H
#define KOFENG_LZW_H

#include <stdint.h>

#include "decomp.h"

/* The largest code the format allows, and the table that holds them.
 *
 * 12 bits, so 4096 codes: 0..255 are the single bytes, 256 clears the table,
 * 257 ends the data, and 258 upward are what the stream builds. An entry is a
 * PREFIX CODE plus one byte, which is what makes the table fixed size - a
 * sequence of any length is a chain of those, walked backwards. */
#define KOF_LZW_CODES 4096u

struct kof_lzw {
	uint16_t prefix[KOF_LZW_CODES];
	uint8_t  tail[KOF_LZW_CODES];
	/* A decoded sequence is emitted in reverse, so it is built here first.
	 * It can be no longer than the number of codes, because each entry adds
	 * exactly one byte to its prefix. */
	uint8_t  rev[KOF_LZW_CODES];
};

/* Receives decoded bytes; returns zero to refuse more, which the decoder
 * reports as KOF_DEC_STOPPED. */
typedef int (*kof_lzw_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * Decode an LZW stream at `in`, handing output to `sink`.
 *
 * `st` is caller-owned and needs no initialisation - everything is set here -
 * and is 20KB, meant to be allocated once and reused rather than per stream.
 *
 * `produced` is always set, whatever the status, because a caller that was
 * stopped or truncated still needs to know how far it got and the bytes up to
 * there are real output.
 *
 * A stream that ends without the end-of-data code is TRUNCATED rather than
 * CORRUPT: what decoded before it is the part worth scanning, which is the
 * judgement inflate makes about a damaged archive. A code that names a table
 * entry the stream never built IS corrupt - it cannot be decoded into anything,
 * and guessing would be inventing content.
 */
enum kof_decomp_status kof_lzw_decode(struct kof_lzw *st, const uint8_t *in,
				      uint64_t in_len, kof_lzw_sink sink,
				      void *user, uint64_t *produced);

#endif /* KOFENG_LZW_H */
