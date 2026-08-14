/*
 * ovba.h - the run-length coding an Office document compresses its macros with.
 *
 * MS-OVBA 2.4.1. The smallest decoder in this engine and the one with the narrowest
 * job: it decodes exactly one thing, the CompressedContainer that holds VBA source
 * inside a compound file, and nothing else in any format uses it.
 *
 *
 * WHAT IT BUYS, STATED HONESTLY
 *
 * Less than it first appears, and the measurement is worth carrying next to the
 * code. Over 50 real macro-bearing documents, identifiers of 8 characters or more
 * are ALREADY findable in the compressed bytes 88.7% of the time - the coding has a
 * 4096 byte window and a three byte minimum match, so most words survive as
 * literals. At 20 characters and up it falls to 57.9%.
 *
 * So this is not what makes macros searchable. What it buys is:
 *
 *   - the 42% of long tokens that do not survive, which are the distinctive ones:
 *     full API call sites, URLs, long identifiers;
 *
 *   - matching a SEQUENCE at all. "CreateObject(\"Wscript.Shell\")" cannot be
 *     matched in compressed bytes because any part of it may be a back reference,
 *     so without this a signature can only match isolated fragments;
 *
 *   - and the one that decides it: the 88.7% is ACCIDENT, not design. Whether a
 *     token survives depends on where it falls in the compression window, so the
 *     same macro at a different offset gives a different answer. A signature that
 *     works on one sample and silently misses its variant is worse than no
 *     signature, because nothing reports the miss.
 *
 *
 * WHY THIS STREAMS WHEN NRV2 CANNOT
 *
 * Because a back reference cannot cross a chunk boundary. The offset in a CopyToken
 * is computed against the start of the CURRENT chunk, and a chunk decodes to at
 * most 4096 bytes - so the window is 4096 bytes whatever the stream's length, and
 * output can leave through a sink as it is produced.
 *
 * That bound is a property of well formed input and is ENFORCED here rather than
 * assumed. The token's field is wide enough to name an offset up to twice the bytes
 * decoded so far in the chunk, so a hostile file can point one before the chunk
 * began; such a token is refused as corrupt rather than allowed to read whatever
 * the window held from the chunk before it.
 *
 *
 * WRITTEN FROM THE SPECIFICATION
 *
 * The chunk header layout and the CopyToken bit split are from MS-OVBA section
 * 2.4.1 as published. The structure here is its own.
 */

#ifndef KOFENG_OVBA_H
#define KOFENG_OVBA_H

#include <stdint.h>

#include "decomp.h"

/* One chunk decodes to at most this, and a back reference reaches no further. */
#define KOF_OVBA_CHUNK 4096u

/* The byte that begins a CompressedContainer. */
#define KOF_OVBA_SIGNATURE 0x01u

/*
 * Where output goes. Returns non-zero to continue, zero to stop.
 *
 * Same contract as the inflate sink and for the same reason: zero is the receiver
 * having enough, not the stream failing, and the decoder reports it as STOPPED.
 */
typedef int (*kof_ovba_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * Decode a CompressedContainer.
 *
 * `in` points at the SignatureByte. `produced` is always set, whatever the status -
 * a container that fails part way still yields real source, and for a scanner that
 * prefix is usually the part that identifies the sample.
 */
int kof_ovba_decode(const uint8_t *in, uint64_t in_len, kof_ovba_sink sink,
		    void *user, uint64_t *produced);

/*
 * Does a CompressedContainer plausibly begin here?
 *
 * The signature byte plus a first chunk header that agrees with itself. That is one
 * byte and three bits of constraint, which is not much: measured over 50 documents
 * it accepts 3455 positions of which 208 hold real macro source. So this is a cheap
 * pre-test for a caller that must SCAN, and scanning is the recovery path - the
 * ordinary path reaches a container through the directory, which says exactly where
 * it starts and needs no guessing.
 */
int kof_ovba_plausible(const uint8_t *in, uint64_t in_len);

#endif /* KOFENG_OVBA_H */
