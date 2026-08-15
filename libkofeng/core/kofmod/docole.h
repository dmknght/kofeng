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
 * found in place. That is what kof_gather() is for, and why this format has an
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

#define KOF_DOCOLE_INFO_VERSION 1

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
 * Bounds the parse holds itself to.
 *
 * Every one of them exists because the structure it bounds cannot be trusted to
 * end on its own, and each has an anomaly bit so that reaching one is visible
 * rather than silent. Sized from measurement, not from the specification's maxima:
 * across 77 real OLE documents the largest directory held 96 entries and the most
 * fragmented stream came apart into 15 runs.
 */
#define KOF_DOCOLE_MAX_DIR       2048u  /* directory entries examined */
#define KOF_DOCOLE_MAX_DEPTH     32u    /* storage nesting */
#define KOF_DOCOLE_MAX_EXTENTS   512u   /* runs recorded, across all classes */
#define KOF_DOCOLE_MAX_FAT       1024u  /* FAT sectors reachable, so 64MB at 512 */
#define KOF_DOCOLE_MAX_MINIFAT   256u   /* MiniFAT sectors reachable */
#define KOF_DOCOLE_MAX_MINI_SEC  2048u  /* sectors of mini stream mapped */

/*
 * Streams described one by one, and the runs it takes to describe them.
 *
 * Separate from run[] above, which is settled: settling sorts by offset and trims
 * overlaps, which is exactly what a region needs and exactly what destroys the
 * association between a run and the stream it came from. A caller that wants ONE
 * stream's bytes - to decompress it, which is a thing done to a stream and never to
 * a region - needs the unsettled form, so both are kept.
 *
 * Sized from measurement over 50 macro-bearing documents: 1208 streams across them,
 * so 24 per document, and a stream is one run 76.4% of the time because its sectors
 * are consecutive. 256 and 1024 are an order of magnitude above that.
 */
#define KOF_DOCOLE_MAX_ENTRIES   256u
#define KOF_DOCOLE_MAX_ENT_RUNS  1024u

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
	KOF_DOCOLE_ENT_RUNS_FULL = 1u << 2, /* the run pool bound before it ended */
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
	KOF_DOCOLE_ANOM_DIR_DEPTH     = 1ull << 5,
	KOF_DOCOLE_ANOM_DIR_OVERFLOW  = 1ull << 6,  /* more entries than examined */
	KOF_DOCOLE_ANOM_BAD_DIR_ENTRY = 1ull << 7,  /* name length or type invalid */
	KOF_DOCOLE_ANOM_EXTENTS_FULL  = 1ull << 8,  /* more runs than recorded */
	KOF_DOCOLE_ANOM_FAT_UNMAPPED  = 1ull << 9,  /* FAT past MAX_FAT */
	KOF_DOCOLE_ANOM_MINI_UNMAPPED = 1ull << 10, /* mini stream past MAX_MINI_SEC */
	KOF_DOCOLE_ANOM_STREAM_PAST_EOF = 1ull << 11,
	KOF_DOCOLE_ANOM_MACRO_OVERSIZE  = 1ull << 12, /* past MACRO_SUSPECT */
	KOF_DOCOLE_ANOM_NO_STREAMS      = 1ull << 13, /* a directory with nothing in it */
	KOF_DOCOLE_ANOM_ENCRYPTED       = 1ull << 14, /* content is ciphertext */
	KOF_DOCOLE_ANOM_OVERLAP         = 1ull << 15, /* two structures claimed the
						       * same bytes */
	KOF_DOCOLE_ANOM_ENTRIES_FULL    = 1ull << 16, /* more streams than listed */
	KOF_DOCOLE_ANOM_ENT_RUNS_FULL   = 1ull << 17, /* the per-entry run pool bound */
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
	KOF_DOCOLE_ANOM_DIR_RECOVERED   = 1ull << 18
};

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
	uint32_t n_entries;
	uint32_t n_ent_runs;

	/* Runs, classified, joined where consecutive and settled so that no byte is
	 * in two of them. struct kof_run is the shared shape from runlist.h; it is
	 * spelled out here rather than included because a module never walks these
	 * and including a host header from the ABI would invert the dependency. */
	uint32_t n_runs;
	uint32_t reserved1;
	struct {
		uint64_t off, len;
		uint32_t cls;         /* enum kof_docole_class */
		uint32_t reserved;
	} run[KOF_DOCOLE_MAX_EXTENTS];

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
	} ent[KOF_DOCOLE_MAX_ENTRIES];

	struct kof_docole_ent_run {
		uint64_t off, len;
	} ent_run[KOF_DOCOLE_MAX_ENT_RUNS];

	/*
	 * Host bookkeeping past this point.
	 *
	 * The lookup tables the parse builds so that following a chain is a table
	 * read rather than a walk from the beginning - without them, resolving n
	 * streams over n sectors is quadratic and a hand-built file makes that the
	 * whole scan. No module has a reason to read them; they are here rather than
	 * on the stack because a view is allocated once per scanner and 30KB of stack
	 * inside a parse is not.
	 */
	uint32_t n_dif, n_mfat, n_mini;
	uint32_t dif[KOF_DOCOLE_MAX_FAT];        /* sector holding each FAT block */
	uint32_t mfat[KOF_DOCOLE_MAX_MINIFAT];   /* sectors of the MiniFAT */
	uint32_t mini[KOF_DOCOLE_MAX_MINI_SEC];  /* sectors of the mini stream */

	/*
	 * The directory walk's own stack, and what it has already been to.
	 *
	 * Explicit rather than the C stack because the thing being walked is a
	 * red-black tree whose sibling links can degenerate into a list as long as the
	 * directory: recursion over them is a stack depth the file chooses. The bitmap
	 * is what makes a cycle terminate rather than merely be bounded - an entry is
	 * entered once, so a tree pointing back at itself is noticed and named instead
	 * of being run into a budget.
	 */
	uint32_t seen[(KOF_DOCOLE_MAX_DIR + 31u) / 32u];
	uint32_t stack[KOF_DOCOLE_MAX_DIR];

	/* Sectors of the directory chain, so reaching entry n is a table read. Four
	 * entries fit a 512 byte sector, which is what sizes this. */
	uint32_t n_dirsec;
	uint32_t dirsec[KOF_DOCOLE_MAX_DIR / 4u];
};

static inline const struct kof_docole_info *kof_docole(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_docole_info *)ctx->file_header;
}

#endif /* KOFENG_DOCOLE_H */
