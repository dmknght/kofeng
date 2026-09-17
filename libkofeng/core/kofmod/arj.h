/*
 * arj.h - the ARJ view of an object.
 *
 * Including this header declares that the module targets ARJ, on the same
 * terms as the other container headers.
 *
 * WHY IT IS HERE is the reason lha.h gives about itself, and one more: ARJ has
 * a SELF EXTRACTOR, and an .exe that is an ARJ archive is a shape that predates
 * every installer format and still works. The engine already notes that
 * /usr/bin/arj carries its own ARJ_SFX stub - see heur.h - so the bytes turn up
 * whether or not anybody is still making archives.
 *
 * THE SHAPE: a chain of headers, like LHA, but each one is framed. A header
 * begins with the two byte magic 0x60 0xEA and a length, which means a walk
 * that loses its place can at least tell: the next header either starts with
 * the magic or the archive is over. That framing is the one thing this format
 * has that LHA does not, and it is what the walk below leans on.
 *
 * The FIRST header is the archive's own - a name and a comment, no data. The
 * ones after it are files, each followed by its body.
 *
 * WHAT THIS BUILD DOES NOT DO: decode. Method 0 is stored and those entries are
 * plain ranges; methods 1 to 4 are ARJ's own LZ77 and Huffman coding, which
 * this build has no decoder for, so they are counted and left in the DATA
 * region - the same judgement as every other coding this engine lacks.
 *
 * Layout rule: append only.
 */

#ifndef KOFENG_ARJ_H
#define KOFENG_ARJ_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_ARJ_INFO_VERSION 1

enum kof_scan_arj {
	KOF_SCAN_ARJ_HEADERS   = 1u << 1,  /* every header, less its names */
	KOF_SCAN_ARJ_NAMES     = 1u << 2,  /* the names and comments */
	KOF_SCAN_ARJ_DATA      = 1u << 3,  /* the entry bodies */
	KOF_SCAN_ARJ_UNCLAIMED = 1u << 4
};

#define KOF_SCAN_ARJ_CLAIMED (KOF_SCAN_ARJ_HEADERS | KOF_SCAN_ARJ_NAMES | \
			      KOF_SCAN_ARJ_DATA)

enum {
	KOF_ARJ_ANOM_TRUNCATED    = 1ull << 0,
	/* The first header is not the archive's own, or its basic header is
	 * shorter than the fields it must hold. */
	KOF_ARJ_ANOM_BAD_HEADER   = 1ull << 1,
	/* An entry is coded with a method this build does not decode. */
	KOF_ARJ_ANOM_CODED        = 1ull << 2,
	/* The archive says it is one volume of several: the rest of a file's
	 * bytes are in another object. */
	KOF_ARJ_ANOM_VOLUME       = 1ull << 3,
	/* The archive or an entry says it is encrypted - GARBLED, in the
	 * format's own word. Nothing here can open it. */
	KOF_ARJ_ANOM_ENCRYPTED    = 1ull << 4,
	KOF_ARJ_ANOM_TRAVERSAL    = 1ull << 5,
	KOF_ARJ_ANOM_ENTRIES_FULL = 1ull << 6,
	/* The chain ran into the end of the object rather than reaching the
	 * zero length header that ends an archive. */
	KOF_ARJ_ANOM_NO_END       = 1ull << 7
};

#define KOF_ARJ_ANOM_COUNT 8

#define KOF_ARJ_MAX_ENTRIES 1024u
/* The basic header may not exceed this by the format's own rule, which is also
 * what bounds the name and comment inside it. */
#define KOF_ARJ_MAX_BASIC   2600u

struct kof_arj_info {
	uint32_t version;         /* KOF_ARJ_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint8_t  archiver_ver;    /* what wrote it, and what it needs to read */
	uint8_t  min_ver;
	uint8_t  host_os;
	uint8_t  arj_flags;

	uint32_t n_entries;
	uint32_t n_coded;
	uint32_t n_dirs;

	uint64_t names_off, names_len;
	uint64_t data_off, data_len;

	struct kof_entry entry[KOF_ARJ_MAX_ENTRIES];
};

static inline const struct kof_arj_info *kof_arj(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_arj_info *)ctx->file_header;
}

#endif /* KOFENG_ARJ_H */
