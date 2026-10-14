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

#ifndef KUNCOAT_LZMAT_H
#define KUNCOAT_LZMAT_H

#include <stdint.h>

#include "../status.h"

/*
 * Decode an LZMAT stream into a caller-owned buffer.
 *
 * `produced` is always set, whatever the status: a stream cut short still
 * yields a real prefix, and for a scanner that prefix is usually what
 * identifies the sample.
 *
 * Returns a kuncoat_status. The format has NO END MARKER: the stream ends where the
 * output reaches the size the container declared, and that is what `out_cap` is. OK
 * is "the input was consumed item by item to its end" - `out_cap` bytes produced, or
 * fewer when the input ran out first. THE TWO CANNOT BE TOLD APART: an encoder's last
 * control group is usually partial, so a stream cut at an item boundary reads exactly
 * like a complete one under a cap a little above its size. A caller that knows the
 * size compares `produced` with it. What IS reported: STOPPED is an item that does
 * not fit in the room left (nothing past `produced` is written), TRUNCATED is an item
 * whose bits lie past the end of the input - it is dropped, never written from the
 * zeros the reader would give. A NULL `in` with in_len > 0, or a NULL `out` with
 * out_cap > 0, is KUNCOAT_BAD_ARG; a stream shorter than two bytes or a zero out_cap
 * is CORRUPT. `produced` may be NULL.
 */
enum kuncoat_status kuncoat_lzmat_decode(const uint8_t *in, uint64_t in_len,
					uint8_t *out, uint64_t out_cap,
					uint64_t *produced);

#endif /* KUNCOAT_LZMAT_H */
