/*
 * lzhuf.h - the LZSS-plus-adaptive-block-Huffman coding that LHA and ARJ share.
 *
 * WHY ONE DECODER FOR TWO FORMATS. ARJ's methods 1 to 3 and LHA's -lh5-, -lh6-
 * and -lh7- are the SAME CODING with different constants. Both descend from
 * Haruyasu Yoshizaki's LZHUF, both cut the stream into blocks that carry their
 * own Huffman tables, both code those tables through a third tree of code
 * lengths, and both end a file by counting output rather than by a marker.
 * Written twice they would be two copies of four hundred lines that differ in
 * three numbers.
 *
 *
 * THE SHAPE, in the order it is read:
 *
 *   - A BLOCK HEADER of a 16 bit count: how many codes the block holds. Then
 *     three trees, in this order and each stated as code lengths rather than as
 *     codes: the PRETREE of nineteen (the lengths of the literal tree are coded
 *     with it), the LITERAL/LENGTH tree, and the POSITION tree.
 *   - CODES. Under 256 is a literal. At or above it, the code names a match
 *     LENGTH, and a position code follows saying how far back - its value is a
 *     bucket, and the bits inside the bucket follow it.
 *   - NO END MARKER. The stream stops when the declared output length has been
 *     produced, which is why `out_len` is an argument and not a hint: without
 *     it there is nothing to stop on.
 *
 * WHAT DIFFERS BETWEEN THE FOUR VARIANTS is the dictionary size, how many
 * position buckets there are, and how many bits the position tree's length
 * counts in. Nothing else - which is what makes one decoder honest rather than
 * a merge of two.
 *
 * ARJ'S DICTIONARY IS NOT A POWER OF TWO. It is 26624 bytes, so the wrap is a
 * comparison and not a mask; a decoder written for LHA alone masks and is
 * silently wrong on every ARJ match that crosses the end of the buffer.
 */

#ifndef KUNCOAT_LZHUF_H
#define KUNCOAT_LZHUF_H

#include <stdint.h>

#include "../status.h"

/*
 * Which variant, and the container's own name for it.
 *
 * ARJ methods 1, 2 and 3 are one entry because they are one coding: the number
 * is how hard the compressor looked, not what the decoder must do. ARJ's
 * method 4 is a different coding and is not here.
 */
enum kuncoat_lzhuf_variant {
	KUNCOAT_LZHUF_ARJ = 0,     /* ARJ -m1, -m2, -m3 */
	KUNCOAT_LZHUF_LH5,         /* LHA -lh5-: 8KB  */
	KUNCOAT_LZHUF_LH6,         /* LHA -lh6-: 32KB */
	KUNCOAT_LZHUF_LH7,         /* LHA -lh7-: 64KB */
	KUNCOAT_LZHUF_VARIANTS
};

/* The literal/length alphabet: 256 literals plus every match length from
 * THRESHOLD to MAXMATCH. Fixed for every variant. */
#define KUNCOAT_LZHUF_NC   510u
/* The pretree, which is as wide as a code length can be plus three run codes. */
#define KUNCOAT_LZHUF_NT    19u
/* The widest position alphabet any variant has, and the widest dictionary. */
#define KUNCOAT_LZHUF_NP    17u
#define KUNCOAT_LZHUF_DICT  65536u

struct kuncoat_lzhuf {
	uint8_t  dict[KUNCOAT_LZHUF_DICT];

	uint8_t  c_len[KUNCOAT_LZHUF_NC];
	uint8_t  pt_len[KUNCOAT_LZHUF_NT];
	uint16_t c_table[4096];
	uint16_t pt_table[256];
	/* The part of a code too long for the table, as a tree. Two nodes per
	 * symbol is the bound: a binary tree with NC leaves has fewer. */
	uint16_t left[2u * KUNCOAT_LZHUF_NC];
	uint16_t right[2u * KUNCOAT_LZHUF_NC];

	const uint8_t *in;
	uint64_t in_len, in_pos;
	uint16_t bitbuf;
	uint8_t  sub;
	uint8_t  bitcount;
	uint32_t blocksize;
	/*
	 * HOW MANY BITS HAVE BEEN ASKED FOR, which is not how many have been
	 * read out of the input.
	 *
	 * The reader keeps a window ahead of the decoder, so it reaches the end
	 * of the input while the decoder still has every bit it needs. Counting
	 * "the reader ran out" as truncation cuts the last symbols off every
	 * stream - measured on a real ARJ archive as four bytes missing from
	 * the end of the first file. Counted this way the two are separable:
	 * the window is sixteen bits wide, so the decoder has overrun exactly
	 * when it has asked for more than the input holds plus that.
	 */
	uint64_t used;
	int      eof;              /* a bit was asked for that is not there */
};

/* Receives decoded bytes; returns zero to refuse more, which the decoder
 * reports as KUNCOAT_STOPPED. The same shape every decoder here uses. */
typedef int (*kuncoat_lzhuf_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * Decode `out_len` bytes of the stream at `in`.
 *
 * `st` is caller-owned and needs no initialisation - everything is set here -
 * and is about 90KB, so it is meant to be allocated once and reused.
 *
 * `out_len` comes from the container's own header: ARJ writes the original
 * size in the local header and LHA in its own. It is the only thing that ends
 * the stream, so a caller that does not know it cannot decode at all.
 *
 * STATUS. OK only when `out_len` bytes were produced. The input ending first is
 * TRUNCATED, and no byte is decoded from bits past the end (the reader pads with
 * zeros, and a symbol that needs them is not output). A bad table or code is
 * CORRUPT. In both cases the bytes decoded before the failure are handed to the
 * sink (the buffered tail of the dictionary included) and counted in `produced`;
 * the one status that skips that flush is a sink that already refused (STOPPED).
 * A NULL `st` or `sink`, or a NULL `in` with in_len > 0, is KUNCOAT_BAD_ARG;
 * `produced` may be NULL.
 *
 * HUFFMAN CODES. A set of code lengths that over- or under-fills the code space
 * is CORRUPT. The accepted gaps are the single-symbol tree spelled with a zero
 * count, and a set of all-zero lengths (every symbol then decodes as 0, which is
 * bounded by `out_len`). [Unverified] against the reference decoders: that is what
 * this code has always done and it is kept.
 */
enum kuncoat_status kuncoat_lzhuf_decode(struct kuncoat_lzhuf *st,
					enum kuncoat_lzhuf_variant var,
					const uint8_t *in, uint64_t in_len,
					uint64_t out_len,
					kuncoat_lzhuf_sink sink, void *user,
					uint64_t *produced);

#endif /* KUNCOAT_LZHUF_H */
