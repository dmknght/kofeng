/*
 * aspack.h - the coding ASPack 2.x compresses a PE image with.
 *
 * A Huffman-coded LZ77 with four alphabets, a repeat-offset history and a
 * dictionary that can be rebuilt part way through the stream. Close enough to
 * DEFLATE in shape that the resemblance is worth stating and misleading enough
 * that it is worth stating twice: the code-length alphabet is read the same way
 * DEFLATE reads its own, and everything after that differs - 721 symbols rather
 * than 288, the offset split across two alphabets, and four most-recent offsets
 * kept instead of none.
 *
 *
 * WHY IT IS A HOST DECODER AND NOT MODULE CODE
 *
 * The rule in kofsig.h is that a coding peculiar to one family is the module's
 * own business. This one has the property that rule is written against and the
 * property that overrides it: an offset is bounded by nothing, so a match may
 * reach any byte already produced and THE BUFFER IS THE WINDOW - the same
 * reason aPLib and NRV2 are here. A module cannot hold megabytes, and the whole
 * output has to be addressable until the last symbol is decoded.
 *
 *
 * IT TAKES NO PARAMETERS, WHICH IS A MEASURED FACT AND NOT AN ASSUMPTION
 *
 * The decoder is steered by two tables the stub carries: a 0x72-byte table of
 * match-length bases and extra-bit counts, and a 58-byte table of offset
 * widths. Both are CONSTANT across every ASPack build this engine recognises -
 * the second is byte for byte the first from offset 0x38 on, measured over the
 * three samples in the collection - so they are compiled in here rather than
 * passed. bases/unp/aspack_pe.c requires the stub's copies to match before it
 * decodes anything, so a build with different tables is reported as
 * unsupported instead of decoded into plausible rubbish.
 *
 *
 * THE CALL/JMP FILTER
 *
 * ASPack rewrites the operand of every E8/E9 whose first operand byte equals a
 * per-file marker, turning a relative displacement into a big-endian absolute
 * one. Undoing it needs the whole decoded block and the position of each
 * instruction WITHIN that block, so it runs here, after the decode, exactly as
 * the BCJ and MPRESS filters do - see KOF_UNP_LZMA2_BCJ_X86 in kofsig.h. The
 * marker rides in the method id because it is one byte and differs per file.
 *
 * Only the first block of an image carries it; the rest decode plain.
 *
 *
 * Written from XVolkolak's `xaspack.cpp` (MIT) - see THIRD-PARTY.md. The coding
 * is not documented anywhere else this project could find.
 */

#ifndef KOFENG_ASPACK_H
#define KOFENG_ASPACK_H

#include <stdint.h>

#include "decomp.h"

/* The tables, shared with the module that checks the stub against them. */
#include "../../kofcore/kofmod/aspack_tab.h"

/*
 * Decode one ASPack block into a caller-owned buffer.
 *
 * `out_cap` is the block's declared size and a hard bound: the coding states no
 * length of its own, and the block table in the stub is the only thing that
 * says how long the output is. The decoder stops when it has produced that
 * many bytes, which is the stream's real end.
 *
 * The bit reader runs ahead of the symbols it is decoding, so it reads past the
 * compressed bytes by up to KOF_ASPACK_LOOKAHEAD at the end of a block. Those
 * bytes are supplied as zeroes here rather than demanded from the caller: the
 * compressed stream sits inside the image with its own section around it, so a
 * caller that had to pad would have to copy the block first.
 *
 * `produced` is always set. Returns a kof_decomp_status.
 */
#define KOF_ASPACK_LOOKAHEAD 0x10eu

enum kof_decomp_status kof_aspack_decode(const uint8_t *in, uint64_t in_len,
					 uint8_t *out, uint64_t out_cap,
					 uint64_t *produced);

/*
 * Undo the call/jmp filter over a decoded block. `mark` is the marker byte the
 * stub holds. Safe on any buffer: it rewrites only where the marker matches and
 * never reads or writes outside [buf, buf + n).
 */
void kof_aspack_e8e9_decode(uint8_t *buf, uint64_t n, uint8_t mark);

#endif /* KOFENG_ASPACK_H */
