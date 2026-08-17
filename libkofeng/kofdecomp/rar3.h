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
 * the output. No archiver has ever emitted one outside a fixed set of seven, which
 * RAR itself recognises by the CRC32 of the program and runs natively; the
 * interpreter in RAR exists for code nobody writes. So the set is what is
 * implemented here and there is no VM.
 *
 * Of the seven, the x86 branch transform (in both its forms) and the channel delta
 * are carried out. Itanium, RGB, audio and upcase are recognised and refused,
 * because no archive in the collection this was built against uses one and an
 * unvalidated transform is worse than a stated gap - the same rule PPM gets above.
 */

#ifndef KOFENG_RAR3_H
#define KOFENG_RAR3_H

#include <stdint.h>
#include "decomp.h"

/*
 * Decode one RAR3 entry into `out`.
 *
 * `scratch` is working room for the filters, and only for them: the channel delta
 * writes a permutation of its input and cannot do so in place. KOF_RAR3_SCRATCH is
 * enough for any block RAR can declare. Passing NULL is allowed and costs only the
 * entries that carry that filter, which come back UNSUPPORTED like any other
 * transform this build will not run.
 *
 * Returns a KOF_DEC_* status. `*produced` is set in every case, including the
 * failures - a truncated or unsupported stream still yields the bytes that arrived
 * before it stopped, and for a scanner those are worth keeping.
 *
 * KOF_DEC_UNSUPPORTED means a PPM block or a filter this build does not run, and is
 * the honest answer for both: what came out is not the whole file.
 */
/* The largest block a RAR3 filter can be attached to: the VM's own memory bound,
 * which the format checks against before it runs one. */
#define KOF_RAR3_SCRATCH 0x3c000u

enum kof_decomp_status kof_rar3_decode(const uint8_t *in, uint64_t in_len,
				       uint8_t *out, uint64_t out_cap,
				       uint8_t *scratch, uint64_t scratch_len,
				       uint64_t *produced);

#endif /* KOFENG_RAR3_H */
