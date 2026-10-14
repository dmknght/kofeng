/*
 * tar.h - the tar view of an object.
 *
 * A header block, then the file's bytes, then the next header block, until two
 * blocks of zeroes end it. Everything is 512 byte aligned and nothing is
 * compressed, which makes this the one container in this engine that a parser
 * finishes on its own: there is no decoder to write, now or later.
 *
 *
 * WHY IT MATTERS MORE THAN ITS SIZE SUGGESTS
 *
 * Almost nothing arrives as a plain tar. It arrives as a tar inside a gzip, which
 * is how Linux software and Linux malware are both shipped - measured over this
 * collection, 268 of 295 gzip files hold one. The engine already pays the expensive
 * part of that chain: it inflates the stream and produces the tar as a child. Until
 * this parser existed that child identified as nothing and everything inside it was
 * invisible, so the cost had been paid and the answer thrown away one step short.
 *
 *
 * WHY THERE IS NO NAMES REGION, WHEN ZIP HAS ONE
 *
 * Because the same split costs five times as much here and saves almost nothing.
 *
 * A zip keeps each entry name in one contiguous field beside its header, so naming
 * it separately costs one extra extent per entry. A tar scatters its name fields
 * THROUGH the 512 byte header - the name at 0, the link target at 157, the owner
 * and group at 265, the path prefix at 345 - so a NAMES region would come apart
 * into five extents per entry instead of one.
 *
 * And the thing it would save is small: measured over 431 real archives holding
 * 28316 entries, the header blocks are 1.9% of the bytes and the content is 96.9%.
 * Searching names separately would avoid at most 1.9% of a scan, at five times the
 * extents - and the extent budget is the binding constraint here, since the largest
 * archive in that collection holds 2007 entries.
 *
 * The names stay reachable, and more precisely than a region would allow: the entry
 * table below carries the offset and length of each one, so a module searches a
 * single name and knows WHICH entry answered. A region can only say the archive
 * contains the bytes somewhere.
 *
 *
 * WHAT UNCLAIMED MEANS HERE
 *
 * Every entry's content is padded out to a 512 byte boundary, and DATA claims only
 * the declared size - so the padding falls into the complement rather than being
 * claimed. That is not bookkeeping: the padding is slack, it is written by whatever
 * buffer the archiver happened to hold, and it is a place to put bytes that no
 * extractor will ever write out. An archive whose slack is not zeroes has had
 * something put there, and KOF_TAR_ANOM_SLACK says so.
 *
 * It costs nothing to leave it there. The complement is computed from the gaps at
 * resolve time, so an unclaimed run is not an extent anybody paid for during the
 * parse.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_TAR_H
#define KOFENG_TAR_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_TAR_INFO_VERSION 2

enum kof_scan_tar {
	KOF_SCAN_TAR_HEADERS   = 1u << 1,  /* the 512 byte blocks, whole */
	KOF_SCAN_TAR_DATA      = 1u << 2,  /* entry content, exactly as declared */
	KOF_SCAN_TAR_UNCLAIMED = 1u << 3   /* slack, the end blocks, anything after */
};

#define KOF_SCAN_TAR_CLAIMED (KOF_SCAN_TAR_HEADERS | KOF_SCAN_TAR_DATA)

enum kof_tar_class {
	KOF_TAR_CLS_HEADERS = 0,
	KOF_TAR_CLS_DATA,
	KOF_TAR_CLS_COUNT
};

/*
 * Type flags, POSIX 1003.1 and the GNU extensions that are actually met.
 *
 * The two long-name flags are why an entry's name is given as an offset rather than
 * copied: a GNU long name is stored as the DATA of a preceding pseudo entry, so the
 * name of the entry after it lives outside its own header.
 */
enum {
	KOF_TAR_T_FILE     = '0',
	KOF_TAR_T_FILE_ALT = '\0',  /* the older spelling of a regular file */
	KOF_TAR_T_HARDLINK = '1',
	KOF_TAR_T_SYMLINK  = '2',
	KOF_TAR_T_CHAR     = '3',
	KOF_TAR_T_BLOCK    = '4',
	KOF_TAR_T_DIR      = '5',
	KOF_TAR_T_FIFO     = '6',
	KOF_TAR_T_LONGNAME = 'L',   /* GNU: this entry's data is the next one's name */
	KOF_TAR_T_LONGLINK = 'K',   /* GNU: likewise for the link target */
	KOF_TAR_T_PAX      = 'x',   /* extended header for the next entry */
	KOF_TAR_T_PAX_GLOB = 'g'
};

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT OF ENTRIES IS A LIMIT ON THE FILE. The entry table was 2048 rows and the run
 * list 4096 (two runs an entry: the header block and the content) - "the largest archive
 * measured here holds 2007, which is close enough to the ceiling to be worth saying out
 * loud" - so the 2049th member of a tar was not there, and an archive of 5000 small files
 * lost three quarters of them. A tar is a stream and has no count to disbelieve; what a
 * file can hold is bounded by its own bytes.
 *
 * The tables are allocated to what the walk finds, and what bounds an allocation is the
 * file: every entry costs at least one KOF_TAR_BLOCK header block, so the rows cannot
 * exceed the length of the file over it, and an entry makes at most KOF_TAR_RUNS_PER_ENTRY
 * runs. Under that sits the engine's per-object ledger (struct kof_view_mem.room): when a
 * table cannot grow the walk stops, ENTRIES_FULL or EXTENTS_FULL is raised, and the object
 * reads KOF_BROKEN_LIMIT - what was not read is said, and what was read is whole.
 */
#define KOF_TAR_RUNS_PER_ENTRY 2u

#define KOF_TAR_BLOCK    512u
#define KOF_TAR_MAGIC_AT 257u    /* "ustar", the only thing that identifies a tar */

enum {
	KOF_TAR_ANOM_BAD_CHECKSUM = 1ull << 0, /* a header does not sum to its field */
	KOF_TAR_ANOM_BAD_SIZE     = 1ull << 1, /* the size field is not a number */
	KOF_TAR_ANOM_TRUNCATED    = 1ull << 2, /* an entry runs past the end */
	KOF_TAR_ANOM_ENTRIES_FULL = 1ull << 3, /* the entry table could not grow: the
						* archive has entries not read */
	KOF_TAR_ANOM_EXTENTS_FULL = 1ull << 4, /* the run table could not grow */
	KOF_TAR_ANOM_NO_END       = 1ull << 5, /* no pair of zero blocks closes it */
	KOF_TAR_ANOM_TRAVERSAL    = 1ull << 6, /* a name escapes the extract root */
	KOF_TAR_ANOM_LONGNAME     = 1ull << 7, /* GNU long name or link used */
	KOF_TAR_ANOM_PAX          = 1ull << 8, /* PAX extended headers used */
	KOF_TAR_ANOM_OVERLAP      = 1ull << 9,
	/*
	 * Padding that is not zeroes.
	 *
	 * Every entry is padded to a block boundary and no extractor writes those
	 * bytes out, so what is in them is whatever the archiver left there - or what
	 * somebody put there. Both are worth knowing; neither is visible to a tool
	 * that lists an archive.
	 */
	KOF_TAR_ANOM_SLACK        = 1ull << 10,
	KOF_TAR_ANOM_STRANGE_TYPE = 1ull << 11 /* a type flag the format does not define */
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KOF_TAR_ANOM_COUNT 12


/*
 * One entry.
 *
 * `name_off` points into the object and may land in a preceding entry's DATA when a
 * GNU long name was used - which is why it is an offset and not a copy. `size` is
 * what the header declared; what the object actually holds is bounded by data_off
 * against the object's end, and the two disagreeing sets TRUNCATED.
 */
struct kof_tar_entry {
	uint64_t hdr_off;
	uint64_t data_off;
	uint64_t size;
	uint64_t name_off;
	uint64_t mtime;
	uint32_t name_len;
	uint32_t mode, uid, gid;
	uint8_t  typeflag;
	uint8_t  suspicious;      /* KOF_TAR_ENT_* */
	uint16_t reserved;
};

enum {
	KOF_TAR_ENT_TRAVERSAL = 1u << 0,  /* ../ or an absolute path */
	KOF_TAR_ENT_PAST_EOF  = 1u << 1,  /* content runs past the object */
	KOF_TAR_ENT_SLACK     = 1u << 2,  /* this entry's padding is not zeroes */
	KOF_TAR_ENT_BAD_SUM   = 1u << 3
};

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2, the same change as the zip view's (zip.h has the long form). The two arrays that
 * used to end this struct - `run[4096]` and `entry[2048]`, 229448 bytes - are tables the
 * parse allocates to the size of the archive, reached through the pointers at the tail.
 * Everything before them is where it was.
 *
 * `n_entries` WAS AT OFFSET 16 AND IS NOW `legacy_n_entries`, ALWAYS ZERO: a module built
 * against version 1 loops `i < t->n_entries` over `t->entry[i]`, finds zero, runs nothing and
 * reads a valid empty table - never the bytes that happen to lie where its array was - and
 * the engine, which sees that the walk below was never called while the archive has rows,
 * reports the object instead of passing it as examined (sx_walk_check). The real count is
 * `n_entries` at the tail.
 *
 * A module walks the table with kof_tar_next below; it does not index `entry`.
 */
struct kof_tar_info {
	uint32_t version;         /* KOF_TAR_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t legacy_n_entries;/* version 1's count, kept for its offset: always 0 */
	uint32_t n_dirs, n_links, n_files;
	uint64_t total_size;      /* declared, summed over the entries examined */
	uint64_t end_off;         /* where the zero blocks start, 0 if absent */

	uint64_t region_bytes[KOF_TAR_CLS_COUNT];

	/* Runs, classified and settled. struct kof_run is range.h's. */
	uint32_t n_runs;
	uint32_t reserved0;

	/* ---- version 2: from here the tables are the file's size ---------------------- */

	struct kof_view_mem mem;  /* what the tables hold; see range.h */
	struct kof_run *run;      /* n_runs of them; cls is enum kof_tar_class */
	struct kof_tar_entry *entry;
	uint32_t n_entries;       /* rows in `entry`: every header the walk met that the
				   * tables could take, which is all of them unless
				   * ENTRIES_FULL is raised */
	uint32_t reserved1;
};

static inline const struct kof_tar_info *kof_tar(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_tar_info *)ctx->file_header;
}

/*
 * THE NEXT ENTRY OF THE ARCHIVE, in the order the headers follow one another: row `*cursor`,
 * and the cursor is advanced; NULL at the end. The cursor is the module's (the row's index is
 * the cursor minus one after the call), the table is as long as the archive, and the host sees
 * every call - see kof_zip_next, which this is the same walk as.
 */
static inline const struct kof_tar_entry *kof_tar_next(const struct kof_obj_ctx *ctx,
						       uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_tar_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_TAR_H */
