/*
 * lha.h - the LHA/LZH view of an object.
 *
 * Including this header declares that the module targets LHA, on the same
 * terms as the other container headers: a module may include exactly one, and
 * kof_lha() below casts ctx->file_header.
 *
 * WHY A FORMAT FROM 1988 IS HERE. Not for the files people still keep in it -
 * there are almost none. For the reason lzw.h gives about its own coding: a
 * wrapper nobody expects is a wrapper a reader was never taught. LHA is
 * trivially available on Windows through third party tools, its header is
 * forty bytes of plain structure, and an archive in it walks past anything that
 * only knows zip. What arrives inside is ordinary.
 *
 * THE SHAPE: a flat sequence of headers, each followed by its own data. There
 * is no central directory and no index - the next header is at the end of this
 * one's data, so the walk is a chain and a single wrong length ends it. That is
 * also its one structural weakness as a container, and it is why this parse
 * stops rather than resynchronising: a walk that hunts for the next plausible
 * header in a damaged archive is a walk that finds one in attacker chosen
 * bytes.
 *
 * THREE HEADER LEVELS, and they differ in where the length lives:
 *
 *   level 0   a one byte header size, a name, a checksum. MS-DOS era.
 *   level 1   level 0 plus a chain of extension headers after the data start,
 *             whose combined size is counted INTO the compressed size.
 *   level 2   a two byte TOTAL header size at offset zero, extension headers
 *             inside it, and no name in the base header at all.
 *
 * WHICH ENTRIES ARE OPENED, and it is decided by the method name.
 *
 *   "-lh0-", "-lz4-"          stored: the body IS the file, so the entry is a
 *                             plain range and the host opens it with no module
 *                             at all - see kof_objtree_declared.
 *   "-lh5-", "-lh6-", "-lh7-" one coding under three dictionary sizes, and the
 *                             one this build decodes. The entry names it in
 *                             coding[0] and carries the ORIGINAL SIZE in
 *                             out_hint, because that coding has no end marker
 *                             and stops on the count - see KOF_UNP_LZHUF_LH5.
 *                             Decoding is bases/decomp/lha.c's, not the host's.
 *   the rest                  "-lh1-" through "-lh4-" and "-lzs-" are older,
 *                             different codings with no decoder here. They are
 *                             counted in n_coded and left in the DATA region,
 *                             the same judgement as every other coding this
 *                             engine lacks - see cab.h.
 *
 * n_coded counts EVERY coded entry, opened or not: a reader asking how much of
 * an archive is behind a coding means that, not how much was left over.
 *
 * Layout rule: append only.
 */

#ifndef KOFENG_LHA_H
#define KOFENG_LHA_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_LHA_INFO_VERSION 2

/*
 * Scan regions.
 *
 * NAMES is its own region for the reason gzip.h and cab.h give: the names are
 * the part of an archive an author chose, they are in the clear whatever the
 * entries are coded with, and they are a few hundred bytes rather than the
 * whole file. HEADERS is the structure around them.
 */
enum kof_scan_lha {
	KOF_SCAN_LHA_HEADERS   = 1u << 1,  /* every entry header, less its name */
	KOF_SCAN_LHA_NAMES     = 1u << 2,  /* the names, as one region */
	KOF_SCAN_LHA_DATA      = 1u << 3,  /* the entry bodies */
	KOF_SCAN_LHA_UNCLAIMED = 1u << 4   /* the end mark, and anything after */
};

#define KOF_SCAN_LHA_CLAIMED (KOF_SCAN_LHA_HEADERS | KOF_SCAN_LHA_NAMES | \
			      KOF_SCAN_LHA_DATA)

enum {
	/* A header runs past the end of the object, or the chain stops in the
	 * middle of one. */
	KOF_LHA_ANOM_TRUNCATED   = 1ull << 0,
	/* The header level is not 0, 1 or 2 - the three that exist. */
	KOF_LHA_ANOM_BAD_LEVEL   = 1ull << 1,
	/* A level 0 or 1 header's checksum does not match its bytes. Recorded
	 * and not acted on: what it usually means is a file somebody edited. */
	KOF_LHA_ANOM_BAD_CHECKSUM = 1ull << 2,
	/* An entry is coded rather than stored - whether or not this build has
	 * that coding. A FACT about the archive and not a failure: it says the
	 * DATA region holds compressed bytes rather than files. */
	KOF_LHA_ANOM_CODED       = 1ull << 3,
	/* A name holds ".." or an absolute path. */
	KOF_LHA_ANOM_TRAVERSAL   = 1ull << 4,
	/* The entry table could not grow: the archive has entries not read. */
	KOF_LHA_ANOM_ENTRIES_FULL = 1ull << 5,
	/* There is no end mark: the chain ran into the end of the object
	 * instead of stopping at a zero length header. */
	KOF_LHA_ANOM_NO_END      = 1ull << 6
};

#define KOF_LHA_ANOM_COUNT 7

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT OF ENTRIES IS A LIMIT ON THE FILE. The entry table was 1024 rows, so the 1025th
 * member of an archive was not there. The table is allocated to what the chain holds, and what
 * bounds an allocation is the file: a header is at least KOF_LHA_HEADER_MIN bytes, so the rows
 * cannot exceed the length of the file over it. Under that sits the engine's per-object ledger
 * (struct kof_view_mem.room): when the table cannot grow the walk stops, ENTRIES_FULL is raised
 * and the object reads KOF_BROKEN_LIMIT - what was not read is said, and what was read is whole.
 */
#define KOF_LHA_HEADER_MIN  22u
/* The format's own limit: the name length is one byte. */
#define KOF_LHA_MAX_NAME    255u

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2, the same change as the zip view's (zip.h has the long form): `entry[1024]` is a table
 * the parse allocates to the size of the archive, reached through the pointer at the tail, and the
 * scalars before it are where they were. `n_entries` WAS AT OFFSET 16 AND IS NOW
 * `legacy_n_entries`, ALWAYS ZERO: a module built against version 1 loops over a count of zero,
 * reads a valid empty table, and the engine - which sees that the walk below was never called
 * while the archive has rows - reports the object instead of passing it as examined
 * (sx_walk_check). The real count is `n_entries` at the tail. A module walks the table with
 * kof_lha_next below; it does not index `entry`.
 */
struct kof_lha_info {
	uint32_t version;         /* KOF_LHA_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t legacy_n_entries;/* version 1's count, kept for its offset: always 0 */
	uint32_t n_coded;         /* entries behind a coding, opened or not */
	uint32_t n_dirs;          /* "-lhd-": a directory, which has no data */
	uint8_t  level;           /* of the first header */
	uint8_t  reserved0[3];

	uint64_t names_off, names_len;   /* first name to last, as one range */
	uint64_t data_off, data_len;     /* first body to last */

	/* ---- version 2: from here the table is the file's size ------------------------ */

	struct kof_view_mem mem;  /* what the table holds; see range.h */
	struct kof_entry *entry;
	uint32_t n_entries;       /* rows in `entry`: all of the archive's unless ENTRIES_FULL */
	uint32_t reserved1;
};

static inline const struct kof_lha_info *kof_lha(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_lha_info *)ctx->file_header;
}

/*
 * THE NEXT ENTRY OF THE ARCHIVE, in chain order: row `*cursor`, and the cursor is advanced; NULL
 * at the end. The row's index is the cursor minus one after the call. See kof_zip_next, which this
 * is the same walk as.
 */
static inline const struct kof_entry *kof_lha_next(const struct kof_obj_ctx *ctx,
						   uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_LHA_H */
