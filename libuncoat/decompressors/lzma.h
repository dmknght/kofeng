/*
 * lzma.h - LZMA1, raw, for the packers that use it.
 *
 * The last coding UPX uses that this engine did not have: 9 of 154 packed ELF
 * samples and 4 of 400 packed PE samples in one collection reach the unpackers and
 * stop here. Small numbers, and the reason to have it anyway is that those samples
 * are otherwise completely opaque - not scanned in part, not scanned at all.
 *
 * The same decoder is what 7z and xz are built on, so it is the one piece of this
 * work that is certain to be needed again.
 *
 *
 * RAW, AND WHY THAT MATTERS HERE
 *
 * This decodes the LZMA1 stream itself: a range coder and a probability model, with
 * no container around it. It takes lc, lp and pb as arguments rather than reading
 * them from a properties byte, because the packers that embed LZMA do not agree on
 * where those live - one writes the standard byte, another states them in its own
 * header, a third leaves them implicit. Reading them is the caller's business,
 * which keeps this file about the coding and lets a wrong guess about a container
 * be fixed without touching a decoder that is right.
 *
 *
 * MEMORY
 *
 * Two costs, and both are the caller's to bound:
 *
 *   - the OUTPUT, which like NRV2 must be addressable in full while decoding: an
 *     LZMA match may reach back as far as the dictionary allows, so the buffer is
 *     the window and out_cap is the ceiling.
 *   - the PROBABILITY MODEL, whose size is 0x300 << (lc + lp) entries plus a fixed
 *     part. At the maximum lc and lp the specification allows that is six
 *     megabytes, so it is allocated per call from the size the caller passed and
 *     never kept - LZMA streams are rare enough that holding the worst case per
 *     thread would cost far more than decoding them does.
 */

#ifndef KUNCOAT_LZMA_H
#define KUNCOAT_LZMA_H

#include <stdint.h>

#include "format_limits.h"

#include "../status.h"

/*
 * The per-parameter maxima are in the module ABI, beside the method id that carries
 * them: a module reads them out of a container and refuses what is out of range,
 * and this decoder checks again on its own side. One definition, two checks - the
 * limits are a property of the format, not of either caller.
 */

/*
 * Decode a raw LZMA1 stream into a caller-owned buffer.
 *
 * `produced` is always set, whatever the status: a stream cut short still yields a
 * real prefix, and for a scanner that prefix is usually what identifies the sample.
 *
 * Returns a kuncoat_status. KUNCOAT_STOPPED means the output buffer filled with
 * stream left to decode, which is the receiver's limit rather than a failure of the
 * stream. A buffer that fills exactly where the stream ends is OK: with input left,
 * the decoder looks at whether that is the end marker, and a stream that has no
 * marker (the container knew the size) ends with its last byte.
 *
 * INPUT THAT ENDS EARLY IS TRUNCATED, and what comes back is only what the stream
 * said. The range coder is given zeros past the end so the symbol under way finishes
 * in a defined state, but a symbol whose bits came from them is dropped, never
 * written (a match could otherwise invent 273 bytes). [Inference] A complete stream
 * never needs them: the coder normalises after each bit, so its last normalisation
 * takes exactly the bytes the encoder flushed; the differential tests against an
 * independent encoder's output (hostile_lzma) decode whole streams without ever setting the flag.
 *
 * A NULL `in` with in_len > 0, or a NULL `out` with out_cap > 0, is KUNCOAT_BAD_ARG;
 * out_cap 0 is STOPPED (nothing can be produced). `produced` may be NULL.
 */
enum kuncoat_status kuncoat_lzma_decode(unsigned lc, unsigned lp, unsigned pb,
		    const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced);

/*
 * LZMA2, which is LZMA in chunks that may continue one another.
 *
 * No properties argument: they are in the stream, and may change part way through
 * it. The dictionary is the output buffer, so out_cap bounds both how much is
 * produced and how far a match may reach - the same arrangement plain LZMA uses
 * here and for the same reason.
 *
 * STATUS. OK is a complete answer: the end byte (0x00) was reached, or the buffer is
 * full and the stream has no more chunks. The buffer full with a chunk (or part of
 * one) left is STOPPED, never a short OK. The end byte missing with room left, a
 * chunk cut short, and every symbol that would have come from past the end are
 * TRUNCATED. A chunk must be exactly its declared length: ending short of it (an end
 * marker inside a chunk, or nothing decoded) is CORRUPT.
 *
 * DICTIONARY RESET (control 1, or an LZMA chunk with reset 3) is honoured: a match
 * may not reach before it, and the position the model keeps (for pb, lp and the
 * literal context) counts from it. What is NOT enforced is any ordering rule between
 * chunks (that the first chunk resets the dictionary, that a chunk after an
 * uncompressed dictionary reset resets state) [Unverified] against the format
 * specification: a stream that breaks them decodes the way its chunk headers say,
 * and no byte is read from outside the buffer in either case.
 *
 * A state reset does work in proportion to the model it uses: the fixed part is
 * rewritten and a literal context is initialised when first used, so a chunk header
 * cannot make the decoder rewrite megabytes it will not read.
 */
enum kuncoat_status kuncoat_lzma2_decode(const uint8_t *in, uint64_t in_len, uint8_t *out,
		     uint64_t out_cap, uint64_t *produced);

#endif /* KUNCOAT_LZMA_H */
