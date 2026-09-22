/*
 * xz.h - the xz view of an object.
 *
 * The container that arrived free. Its blocks are coded with LZMA2, which this
 * engine grew in order to read 7z content, so the decoder was already here and
 * paid for - what was missing was the twelve bytes at each end that say where the
 * blocks are.
 *
 *
 * WHY THE INDEX IS READ FIRST, AND NOT THE BLOCKS
 *
 * Because a block header is allowed to omit both of its sizes. The flags say
 * whether each is present and most encoders leave them out, which means a walk
 * forward from the stream header reaches the first block and then has nowhere to
 * go: the compressed length it would need to step over is not written down there.
 *
 * The Index at the end lists every block's size, so it is what makes the blocks
 * locatable at all. That gives the same shape as a zip - a directory at the end
 * that says what exists, then a header at each entry that says how to read it -
 * and it is read the same way round, with the directory first.
 *
 * The footer is what finds the Index: its backward size counts four byte units
 * from the end, which is the only pointer in the format that runs that way.
 *
 *
 * WHAT A BLOCK'S SIZE IN THE INDEX MEANS
 *
 * "Unpadded size" is the block header plus the compressed data plus the integrity
 * check, and specifically NOT the padding that rounds a block up to four bytes. So
 * the data is that number less the header and the check, and the next block starts
 * at the number rounded up. Both facts are needed and neither is stated directly.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_XZ_H
#define KOFENG_XZ_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_XZ_INFO_VERSION 1

/*
 * Scan regions.
 *
 * Three, and the split is the one every container here draws: structure against
 * content. HEADERS is the stream header, every block header, the index and the
 * footer - all of it readable, none of it large. PACKED is the coded data, which
 * finds nothing whatever is in it until a decoder has run.
 *
 * There is no STORED counterpart. xz has no stored mode: a block is always coded,
 * so there is never a run of bytes in an xz that is the file itself.
 */
enum kof_scan_xz {
	KOF_SCAN_XZ_HEADERS   = 1u << 1,  /* stream header, block headers, index,
					   * footer */
	KOF_SCAN_XZ_PACKED    = 1u << 2,  /* block data: opaque */
	KOF_SCAN_XZ_UNCLAIMED = 1u << 3
};

#define KOF_SCAN_XZ_CLAIMED (KOF_SCAN_XZ_HEADERS | KOF_SCAN_XZ_PACKED)

enum kof_xz_class {
	KOF_XZ_CLS_HEADERS = 0,
	KOF_XZ_CLS_PACKED,
	KOF_XZ_CLS_COUNT
};

#define KOF_XZ_MAGIC_LEN     6u
#define KOF_XZ_HEADER_LEN   12u
#define KOF_XZ_FOOTER_LEN   12u

/*
 * Filter ids. Only LZMA2 turns bytes into a file on its own; the rest are
 * transforms that run in front of it, and a stream that uses one is recorded and
 * not decoded - running the second half of a chain yields bytes that are not the
 * file, which is the same rule 7z folders are held to.
 */
#define KOF_XZ_FILTER_DELTA  0x03u
#define KOF_XZ_FILTER_X86    0x04u
#define KOF_XZ_FILTER_PPC    0x05u
#define KOF_XZ_FILTER_IA64   0x06u
#define KOF_XZ_FILTER_ARM    0x07u
#define KOF_XZ_FILTER_ARMT   0x08u
#define KOF_XZ_FILTER_SPARC  0x09u
#define KOF_XZ_FILTER_LZMA2  0x21u

/*
 * How the stream checks itself, which decides how many bytes sit after each
 * block's data - and therefore where the next block begins. Not a detail: reading
 * it wrong moves every block after the first.
 */
enum kof_xz_check {
	KOF_XZ_CHECK_NONE   = 0,
	KOF_XZ_CHECK_CRC32  = 1,
	KOF_XZ_CHECK_CRC64  = 4,
	KOF_XZ_CHECK_SHA256 = 10
};

/* Bytes the check occupies, for a check id. Zero, four, eight, sixteen, thirty two
 * and sixty four are the only sizes the format defines, in that pattern. */
static inline uint32_t kof_xz_check_len(uint32_t id)
{
	if (id == 0u)
		return 0u;
	if (id > 15u)
		return 0u;
	return 4u << ((id - 1u) / 3u);
}

/*
 * Blocks described.
 *
 * Measured over the xz files on this machine the median stream holds one block and
 * none holds more than a handful; xz splits into several only when told to compress
 * in parallel. 256 is far above anything ordinary and reaching it is recorded.
 */
#define KOF_XZ_MAX_BLOCKS  256u
#define KOF_XZ_MAX_EXTENTS 1024u

enum {
	KOF_XZ_ANOM_BAD_HEADER   = 1ull << 0,  /* the first twelve bytes disagree */
	KOF_XZ_ANOM_BAD_FOOTER   = 1ull << 1,
	KOF_XZ_ANOM_NO_INDEX     = 1ull << 2,  /* the footer points nowhere usable */
	KOF_XZ_ANOM_BAD_BLOCK    = 1ull << 3,
	KOF_XZ_ANOM_TRUNCATED    = 1ull << 4,  /* a block runs past the end */
	KOF_XZ_ANOM_BLOCKS_FULL  = 1ull << 5,
	KOF_XZ_ANOM_EXTENTS_FULL = 1ull << 6,
	KOF_XZ_ANOM_FILTER_CHAIN = 1ull << 7,  /* a transform in front of the coder */
	KOF_XZ_ANOM_UNKNOWN_FILTER = 1ull << 8,
	KOF_XZ_ANOM_BAD_CHECK    = 1ull << 9,  /* a check id the format does not define */
	KOF_XZ_ANOM_RATIO_ABSURD = 1ull << 10,
	KOF_XZ_ANOM_OVERLAP      = 1ull << 11,
	KOF_XZ_ANOM_MULTI_STREAM = 1ull << 12  /* more concatenated streams follow */
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KOF_XZ_ANOM_COUNT 13


/* On the same reasoning as gzip's and zip's: far past anything not built to
 * expand. */
#define KOF_XZ_RATIO_ABSURD 5000u

struct kof_xz_block {
	uint64_t hdr_off;        /* the block header */
	uint32_t hdr_len;
	uint32_t n_filters;
	uint64_t data_off;       /* first byte of coded data */
	uint64_t comp_size;      /* coded bytes, check and padding excluded */
	uint64_t uncomp_size;    /* what the index says the decode yields */
	uint32_t filter;         /* the LAST filter, which is the coder */
	/*
	 * The transform in front of it, zero when there is none.
	 *
	 * Same arrangement as a 7z folder's filter and for the same reason: the
	 * bytes were changed before compression and have to be changed back after
	 * decompression, and decoding without doing so yields something that looks
	 * like a program and is not one.
	 */
	uint32_t transform;
	uint32_t suspicious;     /* KOF_XZ_BLK_* */
};

enum {
	KOF_XZ_BLK_PAST_EOF = 1u << 0,
	KOF_XZ_BLK_RATIO    = 1u << 1,
	KOF_XZ_BLK_CHAIN    = 1u << 2   /* more than one filter: not decoded */
};

struct kof_xz_info {
	uint32_t version;         /* KOF_XZ_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t check;           /* enum kof_xz_check */
	uint32_t check_len;       /* bytes, derived from it */
	uint32_t n_blocks;
	uint32_t declared_blocks; /* what the index claimed */

	uint64_t index_off, index_len;
	uint64_t footer_off;
	uint64_t total_comp, total_uncomp;

	uint64_t region_bytes[KOF_XZ_CLS_COUNT];

	uint32_t n_runs;
	uint32_t reserved0;
	struct {
		uint64_t off, len;
		uint32_t cls;         /* enum kof_xz_class */
		uint32_t reserved;
	} run[KOF_XZ_MAX_EXTENTS];

	struct kof_xz_block block[KOF_XZ_MAX_BLOCKS];
};

static inline const struct kof_xz_info *kof_xz(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_xz_info *)ctx->file_header;
}

#endif /* KOFENG_XZ_H */
