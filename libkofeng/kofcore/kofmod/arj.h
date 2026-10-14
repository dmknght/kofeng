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
 * WHICH ENTRIES ARE OPENED, and it is decided by the method number.
 *
 *   0         stored: the body IS the file, so the entry is a plain range and
 *             the host opens it with no module at all - see
 *             kof_objtree_declared.
 *   1, 2, 3   one coding - the number is how hard the compressor looked, not
 *             what a decoder must do - and the one this build decodes. The
 *             entry names it in coding[0] and carries the ORIGINAL SIZE in
 *             out_hint, because that coding has no end marker and stops on the
 *             count - see KOF_UNP_LZHUF_ARJ. Decoding is bases/decomp/arj.c's,
 *             not the host's.
 *   4         a different coding with no decoder here.
 *
 * A GARBLED entry is encrypted and is not opened whatever its method. Both it
 * and method 4 are counted in n_coded and left in the DATA region, the same
 * judgement as every other coding this engine lacks.
 *
 * n_coded counts EVERY coded entry, opened or not: a reader asking how much of
 * an archive is behind a coding means that, not how much was left over.
 *
 * Layout rule: append only.
 */

#ifndef KOFENG_ARJ_H
#define KOFENG_ARJ_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_ARJ_INFO_VERSION 2

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
	/* An entry is coded rather than stored - whether or not this build has
	 * that coding. A FACT about the archive and not a failure: it says the
	 * DATA region holds compressed bytes rather than files. */
	KOF_ARJ_ANOM_CODED        = 1ull << 2,
	/* The archive says it is one volume of several: the rest of a file's
	 * bytes are in another object. */
	KOF_ARJ_ANOM_VOLUME       = 1ull << 3,
	/* The archive or an entry says it is encrypted - GARBLED, in the
	 * format's own word. Nothing here can open it. */
	KOF_ARJ_ANOM_ENCRYPTED    = 1ull << 4,
	KOF_ARJ_ANOM_TRAVERSAL    = 1ull << 5,
	/* The entry table could not grow: the archive has entries not read. */
	KOF_ARJ_ANOM_ENTRIES_FULL = 1ull << 6,
	/* The chain ran into the end of the object rather than reaching the
	 * zero length header that ends an archive. */
	KOF_ARJ_ANOM_NO_END       = 1ull << 7
};

#define KOF_ARJ_ANOM_COUNT 8

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT OF ENTRIES IS A LIMIT ON THE FILE. The entry table was 1024 rows, so the 1025th member
 * of an archive was not there. The table is allocated to what the chain holds, and what bounds an
 * allocation is the file: a header is the two magic bytes, a length, a basic header of at least
 * KOF_ARJ_BASIC_MIN bytes, its CRC and the zero that ends the extended headers, so the rows cannot
 * exceed the length of the file over KOF_ARJ_HEADER_MIN. Under that sits the engine's per-object
 * ledger (struct kof_view_mem.room): when the table cannot grow the walk stops, ENTRIES_FULL is
 * raised and the object reads KOF_BROKEN_LIMIT - what was not read is said, what was read is whole.
 */
#define KOF_ARJ_BASIC_MIN   30u
#define KOF_ARJ_HEADER_MIN  (4u + KOF_ARJ_BASIC_MIN + 4u + 2u)
/* The basic header may not exceed this by the format's own rule, which is also
 * what bounds the name and comment inside it. */
#define KOF_ARJ_MAX_BASIC   2600u

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2, the same change as the zip view's (zip.h has the long form): `entry[1024]` is a table
 * the parse allocates to the size of the archive, reached through the pointer at the tail, and the
 * scalars before it are where they were. `n_entries` WAS AT OFFSET 20 AND IS NOW
 * `legacy_n_entries`, ALWAYS ZERO: a module built against version 1 loops over a count of zero,
 * reads a valid empty table, and the engine - which sees that the walk below was never called
 * while the archive has rows - reports the object instead of passing it as examined
 * (sx_walk_check). The real count is `n_entries` at the tail. A module walks the table with
 * kof_arj_next below; it does not index `entry`.
 */
struct kof_arj_info {
	uint32_t version;         /* KOF_ARJ_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint8_t  archiver_ver;    /* what wrote it, and what it needs to read */
	uint8_t  min_ver;
	uint8_t  host_os;
	uint8_t  arj_flags;

	uint32_t legacy_n_entries;/* version 1's count, kept for its offset: always 0 */
	uint32_t n_coded;         /* entries behind a coding, opened or not */
	uint32_t n_dirs;

	uint64_t names_off, names_len;
	uint64_t data_off, data_len;

	/* ---- version 2: from here the table is the file's size ------------------------ */

	struct kof_view_mem mem;  /* what the table holds; see range.h */
	struct kof_entry *entry;
	uint32_t n_entries;       /* rows in `entry`: all of the archive's unless ENTRIES_FULL */
	uint32_t reserved1;
};

static inline const struct kof_arj_info *kof_arj(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_arj_info *)ctx->file_header;
}

/*
 * THE NEXT ENTRY OF THE ARCHIVE, in chain order: row `*cursor`, and the cursor is advanced; NULL
 * at the end. The row's index is the cursor minus one after the call. See kof_zip_next, which this
 * is the same walk as.
 */
static inline const struct kof_entry *kof_arj_next(const struct kof_obj_ctx *ctx,
						   uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_ARJ_H */
