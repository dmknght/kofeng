/*
 * bz2.h - the bzip2 view of an object.
 *
 * Including this header declares that the module targets bzip2, on the same
 * terms as gzip.h and xz.h: a module may include exactly one format header,
 * because kof_bz2() below casts ctx->file_header and the cast is sound only
 * while the host never calls a module for a format it did not declare.
 *
 * THE THINNEST WRAPPER OF ANY CONTAINER HERE, and the view says so. gzip
 * carries a filename, a timestamp and a declared output size - three things a
 * rule can match before a byte is decompressed. bzip2 carries four bytes: "BZh"
 * and a digit. There is no name, no time, no length, and nothing else until the
 * bit stream starts.
 *
 * So what is this view FOR. Two things, and neither is evidence about content:
 *
 *   - FORMAT IS WHAT THE PREFILTER RULES ON. Without a value here nothing can
 *     target a .bz2, which means nothing unpacks one, which means the bytes
 *     inside are reached by nobody. The unpacker needs a format to declare.
 *   - THE BLOCK SIZE IS A FACT ABOUT THE WRITER. The digit is the level the
 *     compressor was asked for, and it is the only thing in the wrapper an
 *     author chose. Default tools write 9; a build script or a library binding
 *     that asked for something else leaves that digit behind, and it is the
 *     same kind of family evidence as gzip's OS byte.
 *
 * WHAT IS NOT HERE, deliberately: how many blocks the stream holds, and where
 * they are. A block header is 48 bits at an arbitrary BIT offset - the format
 * aligns nothing after the first four bytes - so counting them means a bit-wise
 * search of the whole object, which is a decode's worth of work to answer a
 * question no rule asks. Whoever wants what is inside asks the unpacker.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KOFENG_BZ2_H
#define KOFENG_BZ2_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_BZ2_INFO_VERSION 1

/*
 * Scan regions.
 *
 * Two of them, and the split is the only one the format offers: four bytes that
 * are not coded, and everything else, which is. Searching DATA is close to
 * useless for the reason gzip.h gives about its own - the bytes are entropy
 * coded, so no string an author wrote is in there in a form a pattern can find.
 * It exists because the regions must partition the object and because "how
 * large is the compressed part" is a question a bomb heuristic asks.
 *
 * UNCLAIMED is everything past the end-of-stream marker, and finding that
 * marker is not free, so in practice it is empty and the DATA region runs to
 * the end. What lands there instead is what a second CONCATENATED STREAM would
 * land in - and both are opened by the unpacker, which follows them.
 */
enum kof_scan_bz2 {
	KOF_SCAN_BZ2_HEADER    = 1u << 1,  /* "BZh" and the level digit */
	KOF_SCAN_BZ2_DATA      = 1u << 2,  /* the coded blocks */
	KOF_SCAN_BZ2_UNCLAIMED = 1u << 3
};

#define KOF_SCAN_BZ2_CLAIMED (KOF_SCAN_BZ2_HEADER | KOF_SCAN_BZ2_DATA)

enum {
	/*
	 * The level digit is outside 1 to 9.
	 *
	 * Never valid, and it is the one field in the wrapper that can be
	 * wrong - which makes it the one place a file can claim to be bzip2
	 * without being readable by anything that is.
	 */
	KOF_BZ2_ANOM_BAD_LEVEL   = 1ull << 0,
	/* Too short to hold a header and a marker of any kind. */
	KOF_BZ2_ANOM_TRUNCATED   = 1ull << 1,
	/*
	 * The header is followed by the END marker rather than a block: a
	 * stream holding nothing. bzip2 writes one for an empty input, so it is
	 * a real file and not damage - recorded because "empty" and "could not
	 * be read" must never look the same to a reader.
	 */
	KOF_BZ2_ANOM_EMPTY       = 1ull << 2,
	/*
	 * What follows the header is neither a block nor an end marker.
	 *
	 * The two markers are byte aligned exactly once - right behind the four
	 * byte header - so this is the one structural check the wrapper affords,
	 * and it costs six bytes to make.
	 */
	KOF_BZ2_ANOM_NO_BLOCK    = 1ull << 3
};

/* How many of the above there are, so the name table cannot fall behind them. */
#define KOF_BZ2_ANOM_COUNT 4

struct kof_bz2_info {
	uint32_t version;        /* KOF_BZ2_INFO_VERSION */
	uint32_t valid;          /* the magic was right */
	uint64_t anomalies;

	uint8_t  level;          /* 1 to 9, as the digit says */
	uint32_t block_size;     /* level * 100000, the format's own arithmetic */

	/* Where the coded bits start, and how much of the object is left for
	 * them. The true end is only known by decoding, so the length is an
	 * upper bound and the decoder stops before it. */
	uint64_t data_off, data_len;
};

static inline const struct kof_bz2_info *kof_bz2(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_bz2_info *)ctx->file_header;
}

#endif /* KOFENG_BZ2_H */
