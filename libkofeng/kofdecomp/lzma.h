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

#ifndef KOFENG_LZMA_H
#define KOFENG_LZMA_H

#include <stdint.h>

#include <kofmod/kofsig.h>

#include "decomp.h"

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
 * Returns a kof_decomp_status. KOF_DEC_STOPPED means the output buffer filled,
 * which is the receiver's limit rather than a failure of the stream.
 */
int kof_lzma_decode(unsigned lc, unsigned lp, unsigned pb,
		    const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced);

#endif /* KOFENG_LZMA_H */
