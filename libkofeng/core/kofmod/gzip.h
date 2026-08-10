/*
 * gzip.h - the gzip view of an object.
 *
 * Including this header declares that the module targets gzip, on the same terms
 * as elf.h and pe.h: a module may include exactly one format header, because
 * kof_gzip() below casts ctx->file_header and the cast is sound only while the
 * host never calls a module for a format it did not declare.
 *
 * RFC 1952. The wrapper only - a fixed ten byte header, up to three optional
 * fields, a DEFLATE stream, and eight bytes of trailer. The stream itself is not
 * described here because nothing about it can be known without decoding it, and
 * decoding is what an unpacker asks the host to do.
 *
 *
 * WHY A CONTAINER GETS A VIEW AT ALL
 *
 * The obvious reading is that a compressed file has nothing to look at until it is
 * decompressed, so the parse should be a formality on the way to the unpacker. It
 * is the opposite: what the wrapper states about the stream is evidence, and it is
 * evidence available before spending a byte of budget.
 *
 *   - the ORIGINAL FILENAME is stored in the clear, and it is its own region for
 *     that reason. A gzip whose stored name ends in .exe, or holds a path, or is
 *     the name a known dropper writes, can be matched without decompressing at
 *     all - and a name is one of the few things about a compressed file an author
 *     controls and reuses.
 *   - ISIZE states the decompressed length. Against the object's own size it is a
 *     declared expansion ratio, which is what a bomb has to lie about or admit to.
 *     Attacker controlled and modulo 2^32, so it is a heuristic and never a bound
 *     - the bound is the host's budget, which does not consult it.
 *   - MTIME and OS are build fingerprints, which are family evidence in the same
 *     way a PE's Rich header is.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move
 * or change meaning.
 */

#ifndef KOFENG_GZIP_H
#define KOFENG_GZIP_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_GZIP_INFO_VERSION 1

/*
 * Scan regions.
 *
 * NAME is separate from HEADER although it sits inside it, and that is the whole
 * point of the split: it is the one part of a gzip wrapper with attacker-authored
 * text in it, so a module that wants to match a filename should be able to say so
 * and search a few dozen bytes rather than the header plus whatever else. HEADER
 * is therefore the two pieces on either side of it - a region is a set of extents,
 * not one range.
 *
 * DATA is the compressed stream, and searching it is close to useless: it is
 * entropy-coded, so an author's string is not in there in any form a pattern can
 * find. It exists because the regions must partition the object - every byte in
 * exactly one - and because "how large is the compressed part" is a question a
 * bomb heuristic asks. The way to look inside it is to unpack it.
 *
 * UNCLAIMED is everything past the trailer. Not padding: gzip permits members to
 * be concatenated, so a second member lands here, and so does anything appended
 * to a gzip by something that assumed nobody would look.
 */
enum kof_scan_gzip {
	KOF_SCAN_GZIP_HEADER  = 1u << 1,  /* fixed 10 bytes, FEXTRA, FCOMMENT,
					   * FHCRC - everything but the name */
	KOF_SCAN_GZIP_NAME    = 1u << 2,  /* FNAME, without its terminator */
	KOF_SCAN_GZIP_DATA    = 1u << 3,  /* the DEFLATE stream */
	KOF_SCAN_GZIP_TRAILER = 1u << 4,  /* CRC32 and ISIZE */
	KOF_SCAN_GZIP_UNCLAIMED = 1u << 5 /* past the trailer: further members, or
					   * whatever was appended */
};

/* Every region except the complement. UNCLAIMED is what is left when these are
 * taken, so it is defined by this and cannot be in it. */
#define KOF_SCAN_GZIP_CLAIMED (KOF_SCAN_GZIP_HEADER | KOF_SCAN_GZIP_NAME | \
			       KOF_SCAN_GZIP_DATA | KOF_SCAN_GZIP_TRAILER)

/* FLG, RFC 1952 section 2.3.1. */
enum {
	KOF_GZIP_FTEXT    = 1u << 0,
	KOF_GZIP_FHCRC    = 1u << 1,
	KOF_GZIP_FEXTRA   = 1u << 2,
	KOF_GZIP_FNAME    = 1u << 3,
	KOF_GZIP_FCOMMENT = 1u << 4
};

/* The only compression method gzip ever defined. Anything else is a file that
 * says gzip and is not one. */
#define KOF_GZIP_DEFLATE 8u

enum {
	KOF_GZIP_ANOM_BAD_METHOD       = 1ull << 0,  /* CM is not 8 */
	KOF_GZIP_ANOM_RESERVED_FLAGS   = 1ull << 1,  /* FLG bits 5-7 set */
	KOF_GZIP_ANOM_TRUNCATED_HEADER = 1ull << 2,  /* optional fields run past
						      * the end of the object */
	KOF_GZIP_ANOM_NAME_UNTERMINATED= 1ull << 3,
	KOF_GZIP_ANOM_COMMENT_UNTERM   = 1ull << 4,
	KOF_GZIP_ANOM_NO_TRAILER       = 1ull << 5,  /* too short to hold one */
	KOF_GZIP_ANOM_EMPTY_STREAM     = 1ull << 6,  /* header and trailer, no data */
	/*
	 * The declared ratio is one no honest file reaches.
	 *
	 * A heuristic and a hint, not a limit and not a verdict: ISIZE is written
	 * by whoever built the file and is modulo 2^32, so a bomb can simply
	 * declare a small one. What it is good for is the other direction - a file
	 * that ADMITS to expanding ten thousand fold is worth a module's attention
	 * before anything is spent decompressing it.
	 */
	KOF_GZIP_ANOM_RATIO_ABSURD     = 1ull << 7
};

/* The ratio at which the bit above is set. Deliberately far above what real data
 * reaches - text compresses about 3:1 and a disk image of zeroes reaches roughly
 * 1000:1, so this is past anything that is not built to expand. */
#define KOF_GZIP_RATIO_ABSURD 5000u

struct kof_gzip_info {
	uint32_t version;        /* KOF_GZIP_INFO_VERSION */
	uint32_t valid;          /* the magic and CM were right */
	uint64_t anomalies;

	uint8_t  method;         /* CM */
	uint8_t  flags;          /* FLG */
	uint8_t  xfl;
	uint8_t  os;
	uint32_t mtime;          /* seconds since the epoch, or 0 for unset */

	/* Where the DEFLATE stream starts, and how much of the object is left for
	 * it once the trailer is taken off. The true end is only known by decoding
	 * it, so this is an upper bound and the decoder stops before it. */
	uint64_t data_off, data_len;

	/* The optional fields, each zero length when absent. Offsets are into the
	 * object; name_len and comment_len exclude the terminator. */
	uint64_t extra_off, extra_len;
	uint64_t name_off, name_len;
	uint64_t comment_off, comment_len;

	uint64_t trailer_off;    /* 0 when there is no room for one */
	uint32_t crc32;          /* what the file says the output hashes to */
	uint32_t isize;          /* what the file says the output is, modulo 2^32 */
};

static inline const struct kof_gzip_info *kof_gzip(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_gzip_info *)ctx->file_header;
}

#endif /* KOFENG_GZIP_H */
