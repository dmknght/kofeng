/*
 * chm.h - the CHM (HTML Help) view of an object.
 *
 * Including this header declares that the module targets CHM, on the same
 * terms as pdf.h and docole.h: a module may include exactly one format header,
 * because kof_chm() below casts ctx->file_header and the cast is sound only
 * while the host never calls a module for a format it did not declare.
 *
 * WHAT A CHM IS. An ITSS archive - "ITSF" at offset zero - holding a small
 * filesystem: a directory of named entries, and one or more content sections
 * the entries point into. Microsoft shipped it as the help format and it
 * outlived that: a .chm opens on a double click, runs script from its own
 * pages, and has been a delivery wrapper for as long as it has existed.
 *
 * WHY THE DIRECTORY IS THE PART THAT PAYS. The names are stored in the clear
 * and they are what an author chose - "/exploit.htm", "/#IDXHDR", a path with
 * a traversal in it. They are a region of their own for that reason, so a rule
 * can search a few kilobytes of names rather than the whole file, and it can do
 * so without decompressing anything. That is the same trade gzip.h describes
 * for its stored filename, one directory wide.
 *
 * WHAT THIS BUILD DOES NOT DO, stated plainly because the gap decides what a
 * rule can be written against: entries in a COMPRESSED section are not opened.
 * A CHM keeps its pages in "::DataSpace/Storage/MSCompressed/Content", coded
 * with LZX, and this build has no LZX decoder - so those entries are counted
 * (n_compressed) and left as bytes inside the content region. Entries in the
 * UNCOMPRESSED section are ordinary ranges and become children like any other
 * carried file.
 *
 * It is NOT reported as an engine failure. A document whose pages this build
 * cannot decode has still been examined as fully as it intends to - the same
 * judgement pdf.c's PDF_F_IMAGE note records after measuring what the opposite
 * did to ordinary files.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KOFENG_CHM_H
#define KOFENG_CHM_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_CHM_INFO_VERSION 1

/*
 * Scan regions.
 *
 * DIRECTORY is where the names are, and it is the region worth searching -
 * see the note above. CONTENT is the data area: entry bytes, compressed or
 * not, which is where a stored payload sits and where a coded one is
 * unreachable. HEADERS is the two fixed structures that say where the other
 * two are.
 *
 * UNCLAIMED is whatever lies outside all three - a CHM with something appended
 * to it, which is the ordinary shape of a dropper that carries a help file.
 */
enum kof_scan_chm {
	KOF_SCAN_CHM_HEADERS   = 1u << 1,  /* ITSF, and the ITSP behind it */
	KOF_SCAN_CHM_DIRECTORY = 1u << 2,  /* the PMGL/PMGI chunks: the names */
	KOF_SCAN_CHM_CONTENT   = 1u << 3,  /* the sections the entries point at */
	KOF_SCAN_CHM_UNCLAIMED = 1u << 4
};

#define KOF_SCAN_CHM_CLAIMED (KOF_SCAN_CHM_HEADERS | KOF_SCAN_CHM_DIRECTORY | \
			      KOF_SCAN_CHM_CONTENT)

enum {
	/* The version is not 3. Version 2 exists, is rare, and puts the content
	 * area in a different place - so the offsets here are a guess for it
	 * and it is recorded rather than trusted. */
	KOF_CHM_ANOM_OLD_VERSION   = 1ull << 0,
	/* A structure the header points at is outside the object. */
	KOF_CHM_ANOM_TRUNCATED     = 1ull << 1,
	/* The directory header is not "ITSP", or its chunk size is not a power
	 * of two: the walk cannot be trusted and stops. */
	KOF_CHM_ANOM_BAD_DIRECTORY = 1ull << 2,
	/* A chunk claims to be neither PMGL nor PMGI. */
	KOF_CHM_ANOM_BAD_CHUNK     = 1ull << 3,
	/* An entry's bytes run past the end of the object. */
	KOF_CHM_ANOM_ENTRY_PAST_EOF = 1ull << 4,
	/* An entry name holds ".." or begins with a drive or a slash-slash -
	 * a path that means to escape wherever it is written. */
	KOF_CHM_ANOM_TRAVERSAL     = 1ull << 5,
	/* More entries than the table below holds. The ones recorded are real;
	 * what is past the cap was not examined. */
	KOF_CHM_ANOM_ENTRIES_FULL  = 1ull << 6
};

/* How many of the above there are, so the name table cannot fall behind. */
#define KOF_CHM_ANOM_COUNT 7

/*
 * The entries recorded, and the cap.
 *
 * A help file with a thousand pages is ordinary, so this is generous; what it
 * bounds is a directory that claims millions, which is a file built to make a
 * parser allocate. Past the cap the walk stops and says so through
 * KOF_CHM_ANOM_ENTRIES_FULL, for the reason tar.h gives about its own: the
 * entries recorded are still true.
 */
#define KOF_CHM_MAX_ENTRIES 2048u

/* The longest entry name kept as a range. Names are paths inside the help
 * file and real ones are short; this is what stops a length field from
 * naming the whole object. */
#define KOF_CHM_MAX_NAME 1024u

struct kof_chm_info {
	uint32_t version;          /* KOF_CHM_INFO_VERSION */
	uint32_t valid;            /* "ITSF" was there */
	uint64_t anomalies;

	uint32_t itsf_version;     /* 2 or 3 in practice */
	uint32_t lang_id;          /* the header's LCID: a build fingerprint */
	uint32_t timestamp;        /* what the header says; author controlled */

	uint64_t dir_off, dir_len;      /* the PMGL/PMGI chunks */
	uint64_t content_off;           /* where section 0's data begins */
	uint32_t chunk_size, n_chunks;

	uint32_t n_entries;        /* recorded below, at most MAX_ENTRIES */
	uint32_t n_compressed;     /* entries in a section this build cannot
				    * open - see the note at the top */
	uint32_t n_special;        /* names beginning with ':' or '#': the
				    * format's own bookkeeping, not content */
	uint32_t reserved0;

	/*
	 * The entries, in the host's own shape.
	 *
	 * struct kof_entry and not a struct of this format's own, because the
	 * host opens carried files generically from this table - see
	 * kof_objtree_declared - so an entry that is a plain range becomes a
	 * named child without this format needing a module at all.
	 */
	struct kof_entry entry[KOF_CHM_MAX_ENTRIES];
};

static inline const struct kof_chm_info *kof_chm(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_chm_info *)ctx->file_header;
}

#endif /* KOFENG_CHM_H */
