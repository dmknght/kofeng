/*
 * lzx.h - LZX, as a cabinet and a help file use it.
 *
 * WHY THIS ONE IS WORTH THE SIZE. It is the coding behind the content of a
 * .chm and behind most of what a modern .cab carries, so without it two whole
 * formats stop at their directories: the names are readable, the pages and the
 * payloads are not. Every other coding this engine lacks costs one archive
 * shape; this one costs two.
 *
 *
 * THE SHAPE, and what makes it unlike DEFLATE.
 *
 *   - THE BITSTREAM IS 16 BIT WORDS, little endian, and the bits inside a word
 *     are consumed most significant first. A reader written for DEFLATE's
 *     byte-wise least-significant-first order produces nothing recognisable.
 *   - THE TREES ARE DELTA CODED AGAINST THE PREVIOUS BLOCK'S. A block does not
 *     state its code lengths, it states how they DIFFER from the ones before,
 *     through a pretree of twenty elements with run codes of its own. So a
 *     decoder cannot start in the middle of a stream, and losing one block
 *     loses every block after it.
 *   - THREE REPEATED OFFSETS. Position slots 0, 1 and 2 do not encode a
 *     distance, they name one of the last three used - which is where most of
 *     LZX's advantage over DEFLATE comes from, and which makes the decoder
 *     stateful in a way DEFLATE's is not.
 *   - ALIGNED BLOCKS split a long offset's low three bits into their own tree,
 *     so the same field is read differently depending on a block type declared
 *     three bits earlier.
 *   - E8 TRANSLATION rewrites x86 call targets across 32KB frames when the
 *     stream says so. It is a transform on the OUTPUT and has nothing to do
 *     with the coding; getting it wrong corrupts a handful of bytes in a file
 *     that otherwise decodes perfectly.
 *
 *
 * WHAT THIS IMPLEMENTATION IS FOR, and it decides the shape of the interface:
 * cutting ONE FILE out of a stream. A CHM's content is a single LZX stream
 * holding every page, and a cabinet folder is one stream holding every file, so
 * reaching a file means decoding what is in front of it and throwing that away
 * - which is why `skip` and `take` are arguments rather than the caller's
 * problem. Nothing before `skip` is handed to the sink and nothing after
 * `skip + take` is decoded at all.
 */

#ifndef KOFENG_LZX_H
#define KOFENG_LZX_H

#include <stdint.h>

#include <kofmod/kofsig.h>

#include "decomp.h"

/* The window sizes the format defines are KOF_LZX_MIN_BITS to
 * KOF_LZX_MAX_BITS, declared in kofsig.h because a module reads the width out
 * of its container. A stream declaring anything else is not one this decoder
 * will run. */
#define KOF_LZX_MAX_WINDOW (1u << KOF_LZX_MAX_BITS)

/* The format's own bounds on its three trees. 656 is 256 literals plus eight
 * length headers for each of the fifty position slots a 2MB window has. */
#define KOF_LZX_MAIN_MAX    656u
#define KOF_LZX_LEN_MAX     249u
#define KOF_LZX_ALIGN_MAX     8u
#define KOF_LZX_PRETREE_MAX  20u

/* The unit the format counts output in, and the unit E8 translation works in:
 * the bitstream realigns at every boundary and a translated frame is rewritten
 * whole, so a frame is also what leaves the window at a time. */
#define KOF_LZX_FRAME 32768u

/* One canonical Huffman code, in the count-and-symbol form - the same shape
 * inflate.h describes, without its fast table: LZX decodes a few hundred
 * kilobytes at a time and the walk is not what costs. */
struct kof_lzx_huff {
	int16_t count[18];
	int16_t symbol[KOF_LZX_MAIN_MAX];
};

struct kof_lzx {
	uint8_t  win[KOF_LZX_MAX_WINDOW];
	uint32_t wpos;              /* where the next byte goes */
	uint32_t wmask;

	/* The code lengths, kept BETWEEN BLOCKS because the next block states
	 * itself as a difference from them. */
	uint8_t  main_len[KOF_LZX_MAIN_MAX];
	uint8_t  len_len[KOF_LZX_LEN_MAX];
	uint8_t  align_len[KOF_LZX_ALIGN_MAX];

	struct kof_lzx_huff main_h, len_h, align_h, pre_h;

	/* The three offsets a repeated-offset slot names. */
	uint32_t r0, r1, r2;

	/*
	 * ONE FRAME, ON ITS WAY OUT.
	 *
	 * The window cannot be handed to the sink directly - a match copies out
	 * of it, so what is in it has to stay - and E8 translation rewrites a
	 * whole frame in place, which a byte at a time cannot do. So a
	 * completed frame is copied here, translated if the stream asked for
	 * it, and emitted.
	 */
	uint8_t  frame[KOF_LZX_FRAME];

	/* The bit reader: a 32 bit buffer filled 16 bits at a time. */
	const uint8_t *in;
	uint64_t in_len, in_pos;
	uint32_t bitbuf;
	uint32_t bitcnt;
	/*
	 * How many of those bits are NOT from the input.
	 *
	 * The reader keeps the buffer full, so it runs ahead of what the
	 * decoder has asked for by up to four bytes; past the end of the input
	 * it tops the buffer up with zeroes instead. Without counting them,
	 * "the reader reached the end" and "the decoder needed a bit that is
	 * not there" are the same event, and a stream whose last symbols sit in
	 * its last bytes is cut short - measured on a help file, two bytes lost
	 * off the end of every reset interval, which then moved every byte of
	 * the next one.
	 */
	uint32_t pad;
	int      eof;              /* a bit was actually taken from the pad */
};

/* Receives decoded bytes; returns zero to refuse more, which the decoder
 * reports as KOF_DEC_STOPPED. The same shape every decoder here uses. */
typedef int (*kof_lzx_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * Decode the LZX stream at `in`, hand `take` bytes starting at `skip` to the
 * sink, and stop.
 *
 * `st` is caller-owned and needs no initialisation - everything is set here -
 * and is about 2.1MB, so it is meant to be allocated once and reused rather
 * than per stream.
 *
 * `window_bits` comes from the container: a cabinet's folder says it in its
 * compression type, a help file in its ControlData. It is not in the stream,
 * which is why a decoder cannot be handed only the bytes.
 *
 * `produced` is always set - what was handed to the sink, not what was decoded
 * - because a caller that was stopped or truncated still needs to know how much
 * of its file it got.
 */
enum kof_decomp_status kof_lzx_decode(struct kof_lzx *st, uint32_t window_bits,
				      const uint8_t *in, uint64_t in_len,
				      uint64_t skip, uint64_t take,
				      kof_lzx_sink sink, void *user,
				      uint64_t *produced);

#endif /* KOFENG_LZX_H */
