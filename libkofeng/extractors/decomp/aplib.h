/*
 * aplib.h - the aPLib coding, which Themida's loader is compressed with.
 *
 * Reached through .boot: a Themida protected PE puts its loader in a section
 * called .boot whose entry point is a PLAIN aPLib depacker - not virtualised,
 * not encrypted - and the stream it reads decompresses to exactly the
 * VirtualSize of the section before it. See bases/unp/themida_pe.c, which is
 * where that container is documented and measured.
 *
 *
 * WHY THIS DOES NOT STREAM, WHICH IS THE SAME REASON NRV2 DOES NOT
 *
 * An aPLib match distance is built from a gamma code with no ceiling and may
 * reach any byte already produced, so there is no window size that makes this
 * streamable - the buffer IS the window, exactly as nrv2.h explains for UPX's
 * codings. out_cap is therefore a hard bound and the caller's decision, and a
 * length declared by a container is a hint for sizing and never a bound.
 *
 *
 * THE CODING
 *
 * A bit stream, most significant bit first, over a byte at a time. The first
 * byte of the stream is a literal and is copied before any bit is read. After
 * that each iteration reads one to three bits:
 *
 *     0      a literal byte follows
 *     10     a match: gamma coded high offset, one byte of low offset, gamma
 *            coded length, with the length adjusted by how far back the offset
 *            reaches and with a short form that reuses the previous offset
 *     110    a short match: one byte holding a seven bit offset and a length of
 *            two or three. An offset of zero is the end of the stream.
 *     111    a single byte at a four bit offset, or a zero byte when that
 *            offset is zero
 *
 * `lwm` - "last was match" - is what selects the reuse form, and it is the part
 * of aPLib that is easy to get subtly wrong: after a literal or a four bit
 * single byte it is cleared, after either match form it is set, and the gamma
 * value 2 means "the previous offset again" only when it is clear.
 *
 * Written from the coding rather than from a reference implementation, and
 * checked against one: the decoder was run beside an independent implementation
 * of the same coding over the four Themida samples in the collection, and every
 * byte of all four outputs agrees.
 */

#ifndef KOFENG_APLIB_H
#define KOFENG_APLIB_H

#include <stdint.h>

#include "decomp.h"

/*
 * Decode an aPLib stream into a caller-owned buffer.
 *
 * `produced` is always set, whatever the status: a stream cut short still
 * yields a real prefix, and for a scanner that prefix is usually what
 * identifies the sample.
 *
 * Returns a kof_decomp_status. KOF_DEC_STOPPED means the output buffer filled,
 * which is the receiver's limit rather than a failure of the stream.
 */
enum kof_decomp_status kof_aplib_decode(const uint8_t *in, uint64_t in_len,
				        uint8_t *out, uint64_t out_cap,
				        uint64_t *produced);

#endif /* KOFENG_APLIB_H */
