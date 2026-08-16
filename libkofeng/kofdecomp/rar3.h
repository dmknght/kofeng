/*
 * rar3.h - the RAR 2.9/3.x LZ decoder.
 *
 * WHAT THIS COVERS AND WHY THAT IS THE LINE
 *
 * RAR3 picks between two compressors per BLOCK, and says which in the first bit of
 * each block header: an LZSS scheme with Huffman coded lengths and distances, or
 * PPMd variant H. Measured over the 152 RAR3 archives here that this build cannot
 * finish, across 13971 compressed entries:
 *
 *     LZ    12934   92.6%
 *     PPM    1037    7.4%
 *
 * PPMd variant H is a model with a suballocator and SEE contexts - some two thousand
 * lines - for the last 7.4%. So the LZ half is written and a PPM block is recorded as
 * a gap rather than guessed at. That is the same rule every other decoder here
 * follows: a coding this build lacks ends the decode and says so, because bytes that
 * are almost the file are worse than no bytes at all.
 *
 * Unpack version 20 - RAR 2.0, an older and incompatible LZ layout - is 259 of those
 * entries and is refused for the same reason.
 *
 *
 * SOLID ARCHIVES
 *
 * An entry marked solid continues the window of the entry before it, so it cannot be
 * decoded alone. Three percent of the archives here are solid. The caller is told
 * rather than handed a decode that starts from an empty window and silently differs
 * from the file after the first back reference.
 *
 *
 * THE FILTERS
 *
 * RAR3 can attach a small program - RarVM bytecode - that post-processes a range of
 * the output, most often the x86 branch transform. Running it needs an interpreter;
 * not running it leaves those ranges holding pre-filter bytes. Both are recorded, so
 * a caller can tell a clean decode from one with unfiltered ranges in it, and neither
 * is presented as the other.
 */

#ifndef KOFENG_RAR3_H
#define KOFENG_RAR3_H

#include <stdint.h>
#include "decomp.h"

/*
 * Decode one RAR3 entry into `out`.
 *
 * `dict` is the window size the entry's header declared, rounded up by the decoder
 * to what it can use; passing 0 asks for the largest RAR3 allows.
 *
 * Returns a KOF_DEC_* status. `*produced` is set in every case, including the
 * failures - a truncated or unsupported stream still yields the bytes that arrived
 * before it stopped, and for a scanner those are worth keeping.
 *
 * KOF_DEC_UNSUPPORTED means a PPM block or a filter this build does not run, and is
 * the honest answer for both: what came out is not the whole file.
 */
enum kof_decomp_status kof_rar3_decode(const uint8_t *in, uint64_t in_len,
				       uint8_t *out, uint64_t out_cap,
				       uint32_t dict, uint64_t *produced);

#endif /* KOFENG_RAR3_H */
