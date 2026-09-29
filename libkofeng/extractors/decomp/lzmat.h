/*
 * LZMAT, the coding MPRESS used before it moved to LZMA.
 *
 * A byte oriented LZ77 with a control byte every eight items and lengths and
 * distances that widen as the output grows - and with a NIBBLE stream running
 * through it, so a decoder carries "am I half a byte along" alongside its
 * position. That is the whole of what makes it awkward: every read is either
 * aligned or shifted by four bits, and the shift changes as it goes.
 *
 * THE ALGORITHM IS NOT THIS PROJECT'S. It was read off RetDec's
 * implementation (Avast, MIT) - see THIRD-PARTY.md. Nothing is copied: this is
 * C against this engine's decoder interface and its buffers, and the bounds
 * are this file's own.
 */

#ifndef KOFENG_LZMAT_H
#define KOFENG_LZMAT_H

#include <stdint.h>

#include "decomp.h"

/*
 * Decode an LZMAT stream into a caller-owned buffer.
 *
 * `produced` is always set, whatever the status: a stream cut short still
 * yields a real prefix, and for a scanner that prefix is usually what
 * identifies the sample.
 *
 * Returns a kof_decomp_status. KOF_DEC_STOPPED means the output buffer filled,
 * which is the receiver's limit rather than a failure of the stream.
 */
enum kof_decomp_status kof_lzmat_decode(const uint8_t *in, uint64_t in_len,
					uint8_t *out, uint64_t out_cap,
					uint64_t *produced);

#endif /* KOFENG_LZMAT_H */
