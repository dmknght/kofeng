/*
 * rar5.h - the RAR 5 LZ decoder.
 *
 * RAR 5 shares a name with RAR 3 and nothing else. The container is different -
 * variable length integers where RAR3 had fixed fields, which rar_parse.c already
 * handles - and so is the compressor:
 *
 *   ONE CODING, NOT TWO. RAR3 chose between LZ and PPMd per block and this build
 *   carries only the LZ half of it. RAR5 dropped PPM entirely, so a RAR5 entry that
 *   is compressed at all is compressed by the scheme below and there is no second
 *   half to be missing.
 *
 *   BLOCKS END BY COUNT, NOT BY A SYMBOL. A RAR3 block ended when the stream said
 *   256; a RAR5 block header states its size in bits, and the decoder stops when the
 *   cursor reaches it. A decoder that waited for an end symbol would run into the
 *   next block's header and produce noise that looks like data.
 *
 *   THE TABLES ARE ABSOLUTE. RAR3 coded each block's Huffman lengths as a delta
 *   against the previous block's; RAR5 sends them whole, and a block may state that
 *   it reuses the tables already in hand.
 *
 *   THE SLOT ENCODING IS ARITHMETIC. RAR3 looked lengths and distances up in tables
 *   of constants; RAR5 derives them from the slot number, which is why there are no
 *   such tables here.
 *
 *
 * THE FILTERS
 *
 * Four, named by a three bit field rather than by a program: the x86 branch
 * transform in both its forms, the ARM branch transform, and the channel delta. All
 * four are carried out. RAR5 has no VM and no filter this build cannot name, which
 * is the one way it is simpler than RAR3.
 *
 * They are applied after the LZ stage for the reason rar3.h gives: a filter rewrites
 * what goes to the file and not what the window holds, and this decoder's output is
 * its window.
 *
 *
 * WHAT IS NOT COVERED
 *
 * Encryption, and an entry marked solid - which continues the window of the entry
 * before it and so cannot be decoded alone. Both are refused by the caller before a
 * byte reaches here.
 */

#ifndef KUNCOAT_RAR5_H
#define KUNCOAT_RAR5_H

#include <stdint.h>
#include "../status.h"

/*
 * The largest block a RAR5 filter may cover, from the format.
 *
 * Only the channel delta needs the room - it writes a permutation of its input and
 * so cannot work in place. Passing NULL is allowed and costs only the entries
 * carrying that filter, which come back UNSUPPORTED like any transform not run.
 */
#define KUNCOAT_RAR5_SCRATCH 0x400000u

/*
 * Decode one RAR5 entry into `out`. `out_cap` is the DECLARED SIZE of the entry and
 * reaching it is OK (see rar3.h, which states the same contract for both: the
 * decoder stops at the declared size; a filter block extending past it is not
 * applied; ending short of it is TRUNCATED when the input ran out and CORRUPT
 * otherwise; a NULL `in` with in_len > 0 or a NULL `out` with out_cap > 0 is
 * KUNCOAT_BAD_ARG; `produced` may be NULL and is set in every case).
 */

enum kuncoat_status kuncoat_rar5_decode(const uint8_t *in, uint64_t in_len,
				       uint8_t *out, uint64_t out_cap,
				       uint8_t *scratch, uint64_t scratch_len,
				       uint64_t *produced);

#endif /* KUNCOAT_RAR5_H */
