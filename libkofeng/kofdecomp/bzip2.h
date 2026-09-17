/*
 * bzip2.h - the .bz2 coding, as the format's own tools write it.
 *
 * WHY IT IS HERE. bzip2 is not a format this engine could decline politely: a
 * .tar.bz2 is a tar, a .bz2 is whatever was compressed, and a zip entry with
 * method 12 is an entry like any other. Without this they all stop at the
 * wrapper - the bytes inside are entropy coded, so no rule can reach them and
 * no parse can say what they are. Measured on the exploit-db binary corpus:
 * 14 of 2335 files are a bare BZh stream, and every one of them was skipped
 * with "no module targets the format".
 *
 * THE SHAPE, and why it needs more state than DEFLATE.
 *
 * DEFLATE is a sliding window: 32KB of history and a byte comes out for every
 * byte or two that goes in. bzip2 is block sorted, which means the whole block
 * has to exist before ANY of it can be produced - the last stage is an inverse
 * Burrows-Wheeler transform over the block, and the transform is a permutation,
 * so byte zero of the output can come from anywhere in it. A block is up to
 * 900000 bytes and the walk needs a 32 bit link per byte, so the state is
 * measured in megabytes rather than kilobytes. It is allocated once and reused,
 * exactly like kof_inflate and kof_lzw, and for a stronger reason.
 *
 * FOUR STAGES, in the order this undoes them:
 *
 *   Huffman      up to six tables, switched every fifty symbols by a selector
 *                list that is itself move-to-front coded
 *   MTF + RLE2   the symbols are move-to-front ranks, and a run of zeros is
 *                written in a bijective base two (RUNA, RUNB)
 *   BWT          the block, unsorted, from the row index the header names
 *   RLE1         four equal bytes are followed by a count of how many more
 *
 * WHAT IS REFUSED, and it is one thing: a RANDOMISED block. bzip2 0.9.0 could
 * mark a block randomised and de-randomise it with a fixed table of 512
 * numbers; 0.9.5 stopped producing them in 1999 and the field has been a
 * constant zero ever since. Carrying the table to decode files that the
 * format's own author considered gone is not a trade worth making, so a
 * randomised block is reported UNSUPPORTED - which is the honest answer, and it
 * is a different answer from CORRUPT, because the stream is well formed and
 * this build simply lacks a stage for it.
 *
 * THE CRC IS CHECKED. Every block carries one and the stream carries their
 * combination, and they are the only thing that separates "decoded" from
 * "decoded wrongly" - a bzip2 stream with a flipped bit in the middle does not
 * usually fail structurally, it produces different bytes. A mismatch is
 * reported CORRUPT and the output up to it is still handed on, for the reason
 * inflate gives about damaged archives: those bytes are real and are the part
 * worth scanning.
 */

#ifndef KOFENG_BZIP2_H
#define KOFENG_BZIP2_H

#include <stdint.h>

#include "decomp.h"

/*
 * The largest block the format can declare - level 9, "BZh9", 900000 bytes.
 *
 * Not a tuning parameter and not a limit this engine chose: the level digit in
 * the header is 1 to 9 and the block is that many hundred thousand bytes, so
 * nine is the whole of it. A header that says anything else is not bzip2.
 */
#define KOF_BZ_MAX_BLOCK 900000u

/* The format's own bounds on its Huffman stage, all fixed by the specification:
 * at most six tables, a code no longer than twenty-three bits, an alphabet of
 * 256 symbols plus RUNA, RUNB and the end marker, and a selector every fifty
 * symbols of a block. */
#define KOF_BZ_GROUPS      6u
#define KOF_BZ_MAX_CODELEN 23u
#define KOF_BZ_ALPHA       258u
#define KOF_BZ_MAX_SELECT  18002u

struct kof_bunzip {
	/*
	 * THE BLOCK AND ITS LINKS IN ONE ARRAY, which is how the format's own
	 * implementation does it and is not an optimisation for its own sake.
	 *
	 * The inverse transform needs, per position, the byte and a link to the
	 * next position. Kept apart that is 900000 bytes plus 3.6MB; kept
	 * together the byte lives in the low eight bits of the link and the
	 * array is the 3.6MB alone. The decode stage writes the bytes, the
	 * transform stage adds the links above them in place.
	 */
	uint32_t tt[KOF_BZ_MAX_BLOCK];

	/* The canonical Huffman tables, one set per group, in the
	 * limit/base/perm form the specification describes: a code is read one
	 * bit at a time until it falls inside a length's limit, and perm turns
	 * its position into a symbol. */
	int32_t  limit[KOF_BZ_GROUPS][KOF_BZ_MAX_CODELEN + 2u];
	int32_t  base[KOF_BZ_GROUPS][KOF_BZ_MAX_CODELEN + 2u];
	int32_t  perm[KOF_BZ_GROUPS][KOF_BZ_ALPHA];
	uint8_t  len[KOF_BZ_GROUPS][KOF_BZ_ALPHA];
	uint8_t  minlen[KOF_BZ_GROUPS];

	uint8_t  selector[KOF_BZ_MAX_SELECT];
	uint8_t  seq_to_unseq[256];   /* the byte values this block uses */
	uint8_t  mtf[256];            /* the move-to-front list */
	uint32_t unzftab[256];        /* how many of each byte the block holds */
	uint32_t cftab[257];          /* their running total, which is the sort */

	/* Where the output is gathered before the sink is called. A byte at a
	 * time through a callback would be the same decode and ten times the
	 * call overhead. */
	uint8_t  out[65536];
};

/* Receives decoded bytes; returns zero to refuse more, which the decoder
 * reports as KOF_DEC_STOPPED. The same shape kof_lzw and kof_inflate use. */
typedef int (*kof_bunzip_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * Decode the bzip2 stream at `in`, handing output to `sink`.
 *
 * `st` is caller-owned and needs no initialisation - everything is set here -
 * and is about 3.7MB, so it is meant to be allocated once and reused rather
 * than per stream.
 *
 * `produced` is always set, whatever the status, because a caller that was
 * stopped or truncated still needs to know how far it got.
 *
 * CONCATENATED STREAMS ARE FOLLOWED. `bzip2 -c a b > both.bz2` writes two
 * complete streams end to end and every bzip2 reads all of them, so stopping at
 * the first end-of-stream marker would silently drop everything after it. The
 * next stream starts on a BYTE boundary, which is the one place this decoder
 * realigns.
 */
enum kof_decomp_status kof_bunzip_decode(struct kof_bunzip *st,
					 const uint8_t *in, uint64_t in_len,
					 kof_bunzip_sink sink, void *user,
					 uint64_t *produced);

/*
 * Is this the start of a bzip2 stream - "BZh" and a level digit.
 *
 * Four bytes is a weak magic on its own, so this also requires the first
 * block's own six byte marker right behind it, which is what tells a bzip2
 * from a file that happens to start with three letters and a digit. An empty
 * stream - header then end-of-stream marker - is accepted for the same reason
 * the parsers accept empty archives: it is a real file that a real tool wrote.
 */
int kof_bunzip_sniff(const uint8_t *p, uint64_t n);

#endif /* KOFENG_BZIP2_H */
