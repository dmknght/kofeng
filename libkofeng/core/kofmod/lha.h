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
 * WHAT THIS BUILD DOES NOT DO: decode. "-lh0-" is stored and those entries are
 * plain ranges; "-lh1-" through "-lh7-" are LZHUF, which this build has no
 * decoder for, so those are counted and left in the DATA region. The same
 * judgement as every other coding this engine lacks - see cab.h.
 *
 * Layout rule: append only.
 */

#ifndef KOFENG_LHA_H
#define KOFENG_LHA_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_LHA_INFO_VERSION 1

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
	/* An entry is coded with a method this build does not decode. */
	KOF_LHA_ANOM_CODED       = 1ull << 3,
	/* A name holds ".." or an absolute path. */
	KOF_LHA_ANOM_TRAVERSAL   = 1ull << 4,
	/* More entries than the table below holds. */
	KOF_LHA_ANOM_ENTRIES_FULL = 1ull << 5,
	/* There is no end mark: the chain ran into the end of the object
	 * instead of stopping at a zero length header. */
	KOF_LHA_ANOM_NO_END      = 1ull << 6
};

#define KOF_LHA_ANOM_COUNT 7

#define KOF_LHA_MAX_ENTRIES 1024u
/* The format's own limit: the name length is one byte. */
#define KOF_LHA_MAX_NAME    255u

struct kof_lha_info {
	uint32_t version;         /* KOF_LHA_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t n_entries;       /* recorded below */
	uint32_t n_coded;         /* entries this build cannot decode */
	uint32_t n_dirs;          /* "-lhd-": a directory, which has no data */
	uint8_t  level;           /* of the first header */
	uint8_t  reserved0[3];

	uint64_t names_off, names_len;   /* first name to last, as one range */
	uint64_t data_off, data_len;     /* first body to last */

	struct kof_entry entry[KOF_LHA_MAX_ENTRIES];
};

static inline const struct kof_lha_info *kof_lha(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_lha_info *)ctx->file_header;
}

#endif /* KOFENG_LHA_H */
