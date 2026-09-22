/*
 * textcode.h - the codings that are transport rather than compression.
 *
 * ASCII85, ASCIIHex and RunLength. A document format reaches for these to get a
 * stream through a channel that will not carry arbitrary bytes, or to compress
 * a little without a dictionary - so they sit IN FRONT OF the real coding
 * rather than instead of it, and a decoder handed only the real one decodes
 * transport text as though it were compressed data. That is not a hypothetical
 * failure: it is what made a clean document report "could not finish".
 *
 * WHY THEY ARE TOGETHER, AND SEPARATE FROM THE OTHERS
 *
 * Every decoder beside these has a dictionary, a window or a probability model,
 * and needs state that outlives a call. These have none: each is a loop over
 * input with at most four bytes of carry. So they are functions rather than
 * objects, and there is no per-thread block to allocate.
 *
 * TWO SHAPES, AND THE DIFFERENCE IS WHETHER OUTPUT CAN BE SIZED IN ADVANCE
 *
 *   ASCII85    five characters carry four bytes, so output <= 4/5 of input
 *   ASCIIHex   two characters carry one, so output <= 1/2 of input
 *
 * Both can be decoded into a buffer sized from the input, and that is what lets
 * them be the MIDDLE of a coding chain: the next step has to read what this one
 * produced, and a buffer that can be sized before the decode is the only kind
 * that can be allocated for it.
 *
 *   RunLength  a two byte pair can mean 128 identical bytes
 *
 * RunLength expands - up to 128x - and cannot be sized from its input at all.
 * It streams instead, bounded by the receiver rather than by a buffer, and it
 * therefore cannot be a middle step, only a last one. That is a real
 * restriction, and the host reports it rather than working around it.
 *
 * ALL THREE REFUSE RATHER THAN GUESS. Input that is not what it claims - a
 * character outside the alphabet, a run that runs past the end - is CORRUPT,
 * because a container SAID this was the coding and a stream that is not it is
 * the file disagreeing with itself. Damage is a different answer from "decoded
 * nothing", and they lead different places.
 *
 * STATUS AND A COUNT, like kof_inflate, rather than a count with a sentinel in
 * it. `produced` is always set whatever the status, because a caller that was
 * truncated still needs to know how far it got - and the bytes up to there are
 * real output.
 */

#ifndef KOFENG_TEXTCODE_H
#define KOFENG_TEXTCODE_H

#include <stdint.h>

#include "decomp.h"

/* Receives decoded bytes; returns zero to refuse more, which the decoder
 * reports as KOF_DEC_STOPPED. The same shape as kof_inflate_sink, declared
 * separately for the reason that one is: a decoder's callback is part of that
 * decoder's interface. */
typedef int (*kof_textcode_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * ASCII85 into `out`, at most `cap` bytes.
 *
 * '!'..'u' are the alphabet, 'z' is four zero bytes written short, whitespace
 * is skipped because every producer line-wraps, and "~>" ends the data. A final
 * partial group is the ordinary ending and is padded per the specification; a
 * group of ONE character cannot be padded into anything and is CORRUPT.
 *
 * Filling `cap` exactly is OK and is not truncation: the caller sized the
 * buffer from the input, so a full buffer means the input decoded to precisely
 * what it should.
 */
enum kof_decomp_status kof_a85_decode(const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap,
				      uint64_t *produced);

/*
 * ASCIIHex into `out`, at most `cap` bytes.
 *
 * Whitespace is skipped and '>' ends the data. A trailing ODD digit is not an
 * error: PDF 32000-1 7.4.2 says the last digit is paired with a zero. That is
 * what the format MEANS rather than a repair of a broken file, so following it
 * is decoding, and refusing it would be wrong.
 */
enum kof_decomp_status kof_ahx_decode(const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap,
				      uint64_t *produced);

/*
 * RunLength through a sink, because its output cannot be sized from its input.
 *
 * A length byte 0..127 means the next n+1 bytes are literal; 129..255 means the
 * next byte repeats 257-n times; 128 ends the data.
 *
 * Input that ends mid-run is TRUNCATED rather than CORRUPT - what was decoded
 * before it is real output and is the part worth scanning, which is the same
 * judgement inflate makes about a damaged archive. Input with no 128 at all is
 * also TRUNCATED: the data ran out before the end marker.
 */
enum kof_decomp_status kof_rle_decode(const uint8_t *in, uint64_t n,
				      kof_textcode_sink sink, void *user,
				      uint64_t *produced);

#endif /* KOFENG_TEXTCODE_H */
