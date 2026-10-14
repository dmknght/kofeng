/*
 * docole.h - the OLE document view of an object.
 *
 * Including this header declares that the module targets DOCOLE, on the same terms
 * as elf.h, pe.h and gzip.h: one format header per module, because kof_docole()
 * casts ctx->file_header and the cast is sound only while the host never calls a
 * module for a format it did not declare.
 *
 * MS-CFB, the Compound File Binary format: a filesystem in a file. A header, an
 * allocation table, a directory of named entries, and streams whose bytes are
 * scattered across fixed size sectors in whatever order the allocator left them.
 *
 *
 * WHY THIS FORMAT IS DIFFERENT FROM THE ONES ALREADY HERE
 *
 * Every other parser in this engine walks a structure that terminates by
 * construction: an ELF has a segment count, a PE has a section count, a gzip has
 * one header. A CFB has neither - a stream is a linked list through the allocation
 * table, and the directory is a red-black tree of pointers. Both can be made to
 * point at themselves, and a reader that follows them without a bound does not
 * return. So the walks here are bounded by counters rather than by trusting the
 * file to end, and that is why the bounds appear in the anomalies below: running
 * into one is a fact about the file worth reporting, not an internal detail.
 *
 *
 * WHY THE REGIONS ARE WHAT THEY ARE
 *
 * Three groups, and the split is by what a byte can tell you rather than by what
 * the specification calls it:
 *
 *   - HEADERS and DIRECTORY are the container describing itself. They are split
 *     apart because the directory holds NAMES, which are attacker-authored text,
 *     for the same reason gzip splits NAME out of HEADER. Everything else that
 *     merely says where bytes live - the header, the DIFAT, the FAT, the MiniFAT -
 *     does one job and is one region.
 *
 *   - CONTENT_* are the document itself, split three ways because they answer
 *     different questions and cost different amounts. CONTENT_MACROS is code, is
 *     small, and is where nearly everything malicious in a document lives.
 *     CONTENT_METADATA is the property streams, which are small and carry authoring
 *     fingerprints. CONTENT_DATA is the rest of the document body.
 *
 *   - RESOURCES is embedded payload: pictures, object pools, the streams a
 *     document carries but did not author. Measured across 77 OLE documents it is
 *     37.8% of the bytes, and it is the part a pattern almost never wants.
 *
 * The names carry the nesting on purpose. CONTENT_MACROS is a sub-object of the
 * content, not a peer of HEADERS, and the prefix says so where a flat name would
 * not - while the regions themselves stay flat and disjoint, because the partition
 * is what lets masks be OR-ed without scanning a byte twice.
 *
 *
 * A REGION IS A LIST OF EXTENTS, AND HERE THAT IS NOT A FORMALITY
 *
 * In an ELF a region is nearly always one range. In a CFB a stream is a chain of
 * sectors and its region is one extent per run of consecutive ones - so a pattern
 * lying across the join between two sectors is in neither extent and cannot be
 * found in place. That is what kunp_static_gather_all() is for, and why this format has an
 * unpacker as well as a parser: the parse names the bytes for free, and joining
 * them up costs budget and happens only when something asks.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move
 * or change meaning.
 */

#ifndef KOFENG_DOCOLE_H
#define KOFENG_DOCOLE_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_DOCOLE_INFO_VERSION 2

/*
 * Scan regions.
 *
 * UNCLAIMED is everything no structure admitted to owning: sectors the allocation
 * table marks free, the slack past the last sector, and anything appended to the
 * file by something that assumed nobody would look. It is the complement of the
 * rest and so cannot be listed among them.
 */
enum kof_scan_docole {
	KOF_SCAN_DOCOLE_HEADERS   = 1u << 1,  /* header, DIFAT, FAT, MiniFAT */
	KOF_SCAN_DOCOLE_DIRECTORY = 1u << 2,  /* the entry table, names and all */
	KOF_SCAN_DOCOLE_CONTENT_DATA     = 1u << 3,
	KOF_SCAN_DOCOLE_CONTENT_MACROS   = 1u << 4,
	KOF_SCAN_DOCOLE_CONTENT_METADATA = 1u << 5,
	KOF_SCAN_DOCOLE_RESOURCES = 1u << 6,
	KOF_SCAN_DOCOLE_UNCLAIMED = 1u << 7
};

/* Every region except the complement. */
#define KOF_SCAN_DOCOLE_CLAIMED                                              \
	(KOF_SCAN_DOCOLE_HEADERS | KOF_SCAN_DOCOLE_DIRECTORY |               \
	 KOF_SCAN_DOCOLE_CONTENT_DATA | KOF_SCAN_DOCOLE_CONTENT_MACROS |     \
	 KOF_SCAN_DOCOLE_CONTENT_METADATA | KOF_SCAN_DOCOLE_RESOURCES)

/*
 * The nesting, said once so a module does not have to spell it out.
 *
 * STRUCT is the container talking about itself and holds nothing the document
 * authored; CONTENT is the document. A module that wants "anywhere in the document
 * body" says CONTENT rather than listing three bits and getting it wrong when a
 * fourth is added.
 */
#define KOF_SCAN_DOCOLE_STRUCT                                               \
	(KOF_SCAN_DOCOLE_HEADERS | KOF_SCAN_DOCOLE_DIRECTORY)
#define KOF_SCAN_DOCOLE_CONTENT                                              \
	(KOF_SCAN_DOCOLE_CONTENT_DATA | KOF_SCAN_DOCOLE_CONTENT_MACROS |     \
	 KOF_SCAN_DOCOLE_CONTENT_METADATA)

/*
 * Where a run of bytes belongs. One value per claimed region, in the same order,
 * because the parse records extents as it walks and the resolve filters them.
 */
enum kof_docole_class {
	KOF_DOCOLE_CLS_HEADERS = 0,
	KOF_DOCOLE_CLS_DIRECTORY,
	KOF_DOCOLE_CLS_DATA,
	KOF_DOCOLE_CLS_MACROS,
	KOF_DOCOLE_CLS_METADATA,
	KOF_DOCOLE_CLS_RESOURCES,
	KOF_DOCOLE_CLS_COUNT
};

/* Object types, MS-CFB 2.6.1. */
enum {
	KOF_DOCOLE_T_UNUSED  = 0,
	KOF_DOCOLE_T_STORAGE = 1,
	KOF_DOCOLE_T_STREAM  = 2,
	KOF_DOCOLE_T_ROOT    = 5
};

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT IS A LIMIT ON THE FILE. The directory was 2048 entries, the runs a region resolves
 * from 512, the listed streams 256 with 1024 runs between them, the FAT 1024 sectors (64 MB), the
 * MiniFAT 256 and the mini stream 2048 - "sized from measurement": 77 documents, a directory of 96
 * entries at most. A document past any of them lost what lay beyond, and the FAT and the mini
 * stream said so in two anomaly bits nothing read. Each is now a table the parse allocates to what
 * the file holds, and what bounds an allocation is the file: a directory entry is KOF_DOCOLE_DIR_ENT
 * (128) bytes, a sector of the FAT, the MiniFAT, the directory or the mini stream is a sector of the
 * file, and the claims a chain makes are bounded by the walk's own step budgets, which are sized
 * from the file (docole_parse.c: struct ole). Under that sits the engine's per-object ledger (struct
 * kof_view_mem.room). A table that cannot grow raises WORK_FULL (the work tables of the parse) or
 * ENTRIES_FULL / ENT_RUNS_FULL / EXTENTS_FULL (the tables a module reads): what was not read is
 * said, and what was read is whole.
 *
 * ONE LIMIT IS KEPT AS A NUMBER AND IS NOT ONE ANY MORE: storages nested deeper than
 * KOF_DOCOLE_MAX_DEPTH are noted (DIR_DEPTH), and walked all the same - nesting costs nothing, an
 * entry is entered once.
 */
#define KOF_DOCOLE_DIR_ENT       128u   /* bytes of one directory entry, the format's own */
#define KOF_DOCOLE_MAX_DEPTH     32u    /* storage nesting that is worth a note */

/*
 * Streams described one by one, and the runs it takes to describe them.
 *
 * Separate from run[] above, which is settled: settling sorts by offset and trims
 * overlaps, which is exactly what a region needs and exactly what destroys the
 * association between a run and the stream it came from. A caller that wants ONE
 * stream's bytes - to decompress it, which is a thing done to a stream and never to
 * a region - needs the unsettled form, so both are kept.
 *
 * Measured over 50 macro-bearing documents: 1208 streams across them, so 24 per
 * document, and a stream is one run 76.4% of the time because its sectors are
 * consecutive. Said for what is common, and not as a bound on anything.
 */

/*
 * The size past which a macro is worth saying something about.
 *
 * Not a limit and nothing enforces it: it is here so a module can flag a document
 * whose macros are larger than any honest one, without gathering a byte of them.
 * Measured over 64 documents carrying VBA the median is 14.1KB and the largest is
 * 25.4KB, so this is roughly 160 times anything observed - a threshold that catches
 * what is absurd rather than what is merely large.
 */
#define KOF_DOCOLE_MACRO_SUSPECT (4u * 1024u * 1024u)

enum {
	KOF_DOCOLE_ENT_MINI     = 1u << 0,  /* lives in the mini stream */
	KOF_DOCOLE_ENT_SHORT    = 1u << 1,  /* fewer bytes recorded than declared */
	KOF_DOCOLE_ENT_RUNS_FULL = 1u << 2, /* the run table could not grow before it ended */
	/*
	 * The bytes at data_off begin a compressed container.
	 *
	 * Checked by the parse rather than left for a caller to try, because
	 * trying costs more than looking: a failed decode is reported as damage,
	 * and a VBA storage is mostly streams that were never compressed - the
	 * project record, the compiled p-code, the reference list. Without this
	 * a module would report every document as damaged for reading the streams
	 * that were never meant to decode.
	 */
	KOF_DOCOLE_ENT_OVBA     = 1u << 3
};

enum {
	KOF_DOCOLE_ANOM_BAD_HEADER    = 1ull << 0,  /* byte order or version */
	KOF_DOCOLE_ANOM_BAD_SECTOR    = 1ull << 1,  /* sector shift not 9 or 12 */
	KOF_DOCOLE_ANOM_TRUNCATED     = 1ull << 2,  /* a named sector is past the end */
	KOF_DOCOLE_ANOM_FAT_CYCLE     = 1ull << 3,  /* chains ran longer than the
						     * file can hold, so one loops */
	KOF_DOCOLE_ANOM_DIR_CYCLE     = 1ull << 4,  /* the tree revisits an entry */
	KOF_DOCOLE_ANOM_DIR_DEPTH     = 1ull << 5,  /* storages nested past MAX_DEPTH: noted,
						     * not a limit - they are walked */
	KOF_DOCOLE_ANOM_DIR_OVERFLOW  = 1ull << 6,  /* the directory's chain names more
						     * entries than the file can hold, so it
						     * loops: read as far as the file goes */
	KOF_DOCOLE_ANOM_BAD_DIR_ENTRY = 1ull << 7,  /* name length or type invalid */
	KOF_DOCOLE_ANOM_EXTENTS_FULL  = 1ull << 8,  /* the run table could not grow */
	KOF_DOCOLE_ANOM_FAT_UNMAPPED  = 1ull << 9,  /* a chain reached a sector whose FAT
						     * block the DIFAT does not list */
	KOF_DOCOLE_ANOM_MINI_UNMAPPED = 1ull << 10, /* ... or whose mini stream sector the
						     * root's chain does not reach */
	KOF_DOCOLE_ANOM_STREAM_PAST_EOF = 1ull << 11,
	KOF_DOCOLE_ANOM_MACRO_OVERSIZE  = 1ull << 12, /* past MACRO_SUSPECT */
	KOF_DOCOLE_ANOM_NO_STREAMS      = 1ull << 13, /* a directory with nothing in it */
	KOF_DOCOLE_ANOM_ENCRYPTED       = 1ull << 14, /* content is ciphertext */
	KOF_DOCOLE_ANOM_OVERLAP         = 1ull << 15, /* two structures claimed the
						       * same bytes */
	KOF_DOCOLE_ANOM_ENTRIES_FULL    = 1ull << 16, /* the stream table could not grow */
	KOF_DOCOLE_ANOM_ENT_RUNS_FULL   = 1ull << 17, /* the per-entry run table could not grow */
	/*
	 * The directory tree reached nothing and the directory was read straight
	 * through instead.
	 *
	 * Worth its own bit rather than being folded into damage: the entries are
	 * real and so is what they point at, but the parent-child structure that
	 * says which storage a stream belongs to was not usable - so a caller
	 * relying on "this stream is under the VBA storage" is relying on something
	 * this file did not supply.
	 */
	KOF_DOCOLE_ANOM_DIR_RECOVERED   = 1ull << 18,
	/*
	 * A table or buffer the parse works with could not grow, or hit its bound: the
	 * FAT, the MiniFAT, the map of the mini stream, the directory's sectors, the walk's
	 * own stack, or the buffer the project directory is decoded into. What lies past it
	 * was not read - a document that cannot be walked to its end - and the object says
	 * so. Its own bit, not FAT_UNMAPPED's: a file whose chains run off its FAT is damaged,
	 * and one the engine could not afford to read is not.
	 */
	KOF_DOCOLE_ANOM_WORK_FULL       = 1ull << 19
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KOF_DOCOLE_ANOM_COUNT 20


/*
 * ONE STREAM of the directory.
 *
 * A name here is a range in the OBJECT - a CFB stores directory names as UTF-16 in the directory
 * entry - so it is an offset and a length like every other name in this engine, and not a copy.
 * `first_run` and `n_runs` index ent_run, which is where the stream's bytes actually are; empty
 * streams get no runs and are still listed.
 */
struct kof_docole_ent_run {
	uint64_t off, len;
};

struct kof_docole_entry {
	uint64_t name_off;    /* UTF-16 name, in the object */
	uint32_t name_len;    /* bytes, so twice the character count */
	uint32_t size_lo;     /* declared size, split so the struct packs */
	uint32_t size_hi;
	uint32_t first_run;   /* into ent_run */
	uint32_t n_runs;
	uint32_t cls;         /* enum kof_docole_class, or COUNT for none */
	uint32_t flags;       /* KOF_DOCOLE_ENT_* */

	/*
	 * Where this stream's DECODABLE content starts, counted from the
	 * start of the stream rather than of the object.
	 *
	 * Zero for every stream but one kind. A VBA module stream begins
	 * with the compiled p-code and the compressed source follows it,
	 * at an offset that is stated in the project's `dir` stream and
	 * nowhere else - so the parse decompresses `dir` and puts the
	 * answer here. Guessing instead was measured: scanning the stream
	 * for something that looks like the start of a compressed
	 * container finds the right place first only 57% of the time.
	 */
	uint32_t data_off;

	/*
	 * WHAT THE STREAM'S RUNS ADD UP TO, and where the first one is - the two facts a module
	 * asks of the run table without walking it. A projection of ent_run and not a second
	 * source: the module read the runs by index to sum them, which made the table an array
	 * it indexed; this is the sum, kept as the runs are made. `run_bytes` is the bytes the
	 * chain really reaches (never more than the declared size) and `first_off` where the first
	 * of them is, which is the stream when `n_runs` is one.
	 */
	uint64_t run_bytes;
	uint64_t first_off;
};

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2, the same change as the zip view's (zip.h has the long form). The arrays that ended
 * this struct - the settled runs, the listed streams, their runs and six tables the parse keeps for
 * itself, 62 KB in all - are tables the parse allocates to the size of the document, reached
 * through the pointers at the tail; the six that no module and no tool reads (the DIFAT, the
 * MiniFAT, the map of the mini stream, the directory's sectors and the walk's bitmap and stack) are
 * the parse's own work and are gone from the view. Everything before them is where it was.
 * `n_entries` WAS AT OFFSET 136 AND IS NOW `legacy_n_entries`, ALWAYS ZERO: a module built against
 * version 1 loops over a count of zero, reads a valid empty table, and the engine - which sees that
 * the walk below was never called while the document has rows - reports the object instead of
 * passing it as examined (sx_walk_check). The real count is `n_entries` at the tail. A module walks
 * the streams with kof_docole_next below; it does not index `ent`.
 */
struct kof_docole_info {
	uint32_t version;         /* KOF_DOCOLE_INFO_VERSION */
	uint32_t valid;           /* the signature and the header agreed */
	uint64_t anomalies;

	uint16_t major;           /* 3 or 4 */
	uint16_t minor;
	uint32_t sector_size;     /* 512 or 4096 */
	uint32_t mini_sector_size;/* 64 */
	uint32_t mini_cutoff;     /* streams below this live in the mini stream */

	uint32_t dir_count;       /* entries examined, used and unused */
	uint32_t stream_count;
	uint32_t storage_count;

	/*
	 * What the directory DECLARED each class holds, which is not the same as
	 * what the region covers: a stream whose chain is broken contributes its
	 * declared size here and fewer bytes there. Both are worth having - the gap
	 * between them is itself evidence.
	 */
	uint64_t data_bytes, macro_bytes, meta_bytes, resource_bytes;

	/*
	 * What each region actually covers, which is the number to hold a gather to.
	 *
	 * Not the same as the declared sizes above, and the difference is the point.
	 * A stream whose chain runs off the end of the file, or whose sectors another
	 * structure already claimed, declares more than it owns - so a module that
	 * checked a gather against the DECLARED size would report a limit on a file
	 * that had no limit reached, only damage. Against this, a short gather means
	 * a cap bound and nothing else, and the damage is what the anomalies say.
	 *
	 * Indexed by enum kof_docole_class.
	 */
	uint64_t region_bytes[KOF_DOCOLE_CLS_COUNT];

	uint32_t has_macros;      /* a VBA storage was found */

	/*
	 * The document's content is encrypted.
	 *
	 * Office stores an encrypted document as an ordinary compound file holding one
	 * opaque stream, so the container parses perfectly and everything inside it is
	 * ciphertext. That is the case worth naming: without it the scan searches high
	 * entropy bytes, finds nothing, and reports clean - which is the one verdict an
	 * unreadable document must never get.
	 *
	 * A fact and not a verdict. Encrypting a document is ordinary; what a module
	 * does about it is the module's decision.
	 */
	uint32_t encrypted;

	/*
	 * The streams, listed one by one - see `ent` below.
	 */
	uint32_t legacy_n_entries;/* version 1's count, kept for its offset: always 0 */
	uint32_t n_ent_runs;      /* rows in `ent_run` */

	/* Runs, classified, joined where consecutive and settled so that no byte is
	 * in two of them. struct kof_run is the shared shape, defined once in
	 * range.h (core, types only, re-exported by kofsig.h). */
	uint32_t n_runs;
	uint32_t reserved1;

	/* ---- version 2: from here the tables are the file's size ----------------------- */

	struct kof_view_mem mem;  /* what the tables hold; see range.h */
	struct kof_run *run;      /* n_runs of them; cls is enum kof_docole_class */

	/*
	 * The streams, named and locatable one at a time.
	 *
	 * A name here is a range in the OBJECT - a CFB stores directory names as
	 * UTF-16 in the directory entry - so it is an offset and a length like every
	 * other name in this engine, and not a copy. That is what a 7z entry could
	 * not be, and it is why these exist and 7z's do not.
	 *
	 * `first_run` and `n_runs` index ent_run below, which is where the stream's
	 * bytes actually are. Empty streams get no runs and are still listed: a
	 * module deciding what a document contains cares that a stream is there.
	 */
	struct kof_docole_entry *ent;           /* n_entries of them */
	struct kof_docole_ent_run *ent_run;     /* n_ent_runs of them */
	uint32_t n_entries;       /* rows in `ent`: every stream the walk found that the table
				   * could take */
	uint32_t reserved2;
};

static inline const struct kof_docole_info *kof_docole(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_docole_info *)ctx->file_header;
}

/*
 * THE NEXT STREAM OF THE DOCUMENT, in the order the directory walk found them: row `*cursor`,
 * and the cursor is advanced; NULL at the end. The row's index - what kunp_static_entry takes -
 * is the cursor minus one after the call. See kof_zip_next, which this is the same walk as.
 */
static inline const struct kof_docole_entry *kof_docole_next(const struct kof_obj_ctx *ctx,
							     uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_docole_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_DOCOLE_H */
