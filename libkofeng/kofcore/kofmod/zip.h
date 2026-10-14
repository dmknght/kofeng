/*
 * zip.h - the zip view of an object, for both formats that use one.
 *
 * The one format header two formats share, and the exception is deliberate. A zip
 * and a zip that happens to be a document are read the SAME WAY - same central
 * directory, same local headers, same entry data - and differ only in what the
 * entries are called. So there is one parse, one view, and two format ids, and a
 * module may target either or both.
 *
 * That is the opposite of docole.h, which is one format and one header, and the
 * difference is worth stating: DOCOLE and DOCZIP are separate formats because a
 * document's parts live in different PLACES in the two - regions of one object in a
 * compound file, separate child objects in a zip - so a module written for one
 * cannot run against the other. ZIP and DOCZIP are the same shape throughout, so
 * splitting the header would be splitting nothing.
 *
 *
 * WHY A CONTAINER GETS A VIEW, AGAIN
 *
 * Same argument as gzip.h, and stronger here because a zip states far more before
 * anything is decompressed:
 *
 *   - ENTRY NAMES are stored in the clear, twice, and they are their own region for
 *     that reason. A name holding "../" is a path traversal against whatever opens
 *     the archive and is matchable without spending a byte of budget; so is a name
 *     ending .exe inside something claiming to be a document, and so is the set of
 *     names a particular builder always writes.
 *
 *   - THE COMPRESSION METHOD decides whether the data can be searched AT ALL, which
 *     is why it splits the data into two regions rather than being a field. Measured
 *     over 280 archives: method 0 is 10.2% of the compressed bytes, deflate 75.9%,
 *     and encrypted 14.0%.
 *
 *   - THE DECLARED RATIO is csize against usize per entry and needs no decoding. A
 *     bomb has to admit to it or lie about it, and both are evidence.
 *
 *   - ENCRYPTION is a flag. An archive nothing can read must never come back clean.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_ZIP_H
#define KOFENG_ZIP_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_ZIP_INFO_VERSION 2

/*
 * Scan regions.
 *
 * The split between STORED and PACKED is the one that carries weight. It is not by
 * what the specification calls the field but by what a byte can tell you: a stored
 * entry's data is the file itself, sitting in the archive in the clear, and can be
 * searched in place for nothing. Anything else - deflate, bzip2, lzma, encrypted -
 * is opaque until decoded, and a pattern run over it finds nothing whatever it is.
 *
 * That distinction pays for itself immediately on documents. Measured over 8 ODF
 * files, images are 97.4% of the bytes and every one of them is STORED - so the
 * expensive part of a document is already searchable without decompressing
 * anything, and the 2.5% that is XML is the whole real cost of opening one.
 *
 * NAMES holds both copies of every entry name - a zip stores each name in the local
 * header and again in the central directory, and a disagreement between them is
 * itself an evasion - plus the archive comment, which is the other place an author
 * writes text that no reader displays.
 *
 * UNCLAIMED is the complement, and it is not padding: a self-extracting archive is
 * an executable with a zip glued to the end, so everything BEFORE the first local
 * header lands here, as does anything appended after the central directory.
 */
enum kof_scan_zip {
	KOF_SCAN_ZIP_HEADERS   = 1u << 1,  /* local and central records, EOCD,
					    * extra fields, data descriptors */
	KOF_SCAN_ZIP_NAMES     = 1u << 2,  /* entry names, both copies, and the
					    * archive comment */
	KOF_SCAN_ZIP_STORED    = 1u << 3,  /* entry data at method 0: in the clear */
	KOF_SCAN_ZIP_PACKED    = 1u << 4,  /* entry data otherwise: opaque */
	KOF_SCAN_ZIP_UNCLAIMED = 1u << 5
};

#define KOF_SCAN_ZIP_CLAIMED                                                 \
	(KOF_SCAN_ZIP_HEADERS | KOF_SCAN_ZIP_NAMES | KOF_SCAN_ZIP_STORED |   \
	 KOF_SCAN_ZIP_PACKED)

/* The container's own structure, and the entries' bytes. Said once so a module
 * does not spell it out and get it wrong when a region is added. */
#define KOF_SCAN_ZIP_STRUCT  (KOF_SCAN_ZIP_HEADERS | KOF_SCAN_ZIP_NAMES)
#define KOF_SCAN_ZIP_CONTENT (KOF_SCAN_ZIP_STORED | KOF_SCAN_ZIP_PACKED)

enum kof_zip_class {
	KOF_ZIP_CLS_HEADERS = 0,
	KOF_ZIP_CLS_NAMES,
	KOF_ZIP_CLS_STORED,
	KOF_ZIP_CLS_PACKED,
	KOF_ZIP_CLS_COUNT
};

/*
 * What the archive turned out to be, decided from the entry names.
 *
 * A field rather than a format id for everything except documents, because these
 * differ in what their entries are CALLED and not in how the archive is read - and
 * a prefilter that ruled on them would need one format value per convention, with
 * a new one every time a packaging format appeared. DOCZIP is the exception because
 * that split was decided on other grounds: a document is a thing modules are
 * written for.
 */
enum kof_zip_kind {
	KOF_ZIP_PLAIN = 0,
	KOF_ZIP_OOXML,     /* [Content_Types].xml - Word, Excel, PowerPoint */
	KOF_ZIP_ODF,       /* mimetype first and stored - OpenDocument */
	KOF_ZIP_APK,       /* AndroidManifest.xml */
	KOF_ZIP_JAR        /* META-INF/MANIFEST.MF and no Android manifest */
};

/* Compression methods this engine names. Anything else is recorded as its number
 * and reported unsupported rather than guessed at. */
enum {
	KOF_ZIP_M_STORE   = 0,
	KOF_ZIP_M_DEFLATE = 8,
	KOF_ZIP_M_DEFLATE64 = 9,
	KOF_ZIP_M_BZIP2   = 12,
	KOF_ZIP_M_LZMA    = 14,
	KOF_ZIP_M_ZSTD    = 93,
	KOF_ZIP_M_XZ      = 95,
	KOF_ZIP_M_AES     = 99   /* WinZip AES: the real method hides in an extra field */
};

/* General purpose bit flags, APPNOTE 4.4.4. Only the ones that change how the
 * entry is read are named. */
enum {
	KOF_ZIP_F_ENCRYPTED = 1u << 0,
	KOF_ZIP_F_DESCRIPTOR = 1u << 3,  /* sizes follow the data, not precede it */
	KOF_ZIP_F_UTF8      = 1u << 11
};

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT OF ENTRIES IS A LIMIT ON THE FILE. The tables of this view (the entries and
 * the runs that partition the object) were arrays of 4096 and 16384 until 2100 members
 * were enough to lose all of them (their NAMES region needs two extents each against the
 * 4096 a resolve could hold) and an APK with 5242 class files was cut at the 4096th.
 * Measured over 707 archives the median is 8 entries, the 99th percentile 4041 and the
 * largest 41659 - a distribution whose tail is the interesting part, and no number
 * chosen from it would be right for the next archive.
 *
 * They are allocated to what the central directory holds. What bounds an allocation is
 * therefore not a count the file states (the end record says 65535, ZIP64 says 2^64) but
 * the bytes the file really has: a central record is at least KOF_ZIP_CENTRAL_MIN bytes,
 * so the rows cannot exceed the length of the directory divided by it, and a row makes at
 * most KOF_ZIP_RUNS_PER_ENTRY runs. Under that sits the engine's per-object ledger
 * (struct kof_view_mem.room): when a table cannot grow the walk stops, ENTRIES_FULL or
 * EXTENTS_FULL is raised, and the object reads KOF_BROKEN_LIMIT - what was not read is
 * said, and what was read is whole.
 */
#define KOF_ZIP_CENTRAL_MIN  46u
/* The runs one entry can make: central header, name, extra and comment; local header,
 * name, extra; the data; the descriptor. Two more cover the end record and its comment,
 * two the ZIP64 records. A bound on the pool, not a count anyone relies on. */
#define KOF_ZIP_RUNS_PER_ENTRY 8u

/* How far back from the end the end-of-central-directory record is looked for: its
 * own 22 bytes plus the largest comment a 16 bit length can describe. */
#define KOF_ZIP_EOCD_SEARCH  (22u + 65535u)

enum {
	KOF_ZIP_ANOM_NO_EOCD        = 1ull << 0,  /* no end record found at all */
	KOF_ZIP_ANOM_CD_PAST_EOF    = 1ull << 1,
	KOF_ZIP_ANOM_CD_SHORT       = 1ull << 2,  /* fewer records than declared */
	KOF_ZIP_ANOM_BAD_LOCAL      = 1ull << 3,  /* a local header is not one */
	KOF_ZIP_ANOM_LOCAL_MISMATCH = 1ull << 4,  /* the two copies of a name differ */
	KOF_ZIP_ANOM_DATA_PAST_EOF  = 1ull << 5,
	KOF_ZIP_ANOM_ENTRIES_FULL   = 1ull << 6,  /* the entry table could not grow: the
						   * directory has entries not read */
	KOF_ZIP_ANOM_EXTENTS_FULL   = 1ull << 7,  /* the run table could not grow */
	KOF_ZIP_ANOM_ENCRYPTED      = 1ull << 8,
	KOF_ZIP_ANOM_TRAVERSAL      = 1ull << 9,  /* a name escapes the extract root */
	KOF_ZIP_ANOM_RATIO_ABSURD   = 1ull << 10, /* a declared expansion no file reaches */
	KOF_ZIP_ANOM_OVERLAP        = 1ull << 11, /* two entries claim the same bytes */
	KOF_ZIP_ANOM_SFX            = 1ull << 12, /* the archive's offsets are not
						   * the file's: a stub in front, or
						   * a front that was cut off */
	KOF_ZIP_ANOM_UNSUPPORTED    = 1ull << 13  /* a method this engine cannot decode */
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KOF_ZIP_ANOM_COUNT 14


/* The ratio at which the bit above is set, on the same reasoning as gzip's: far
 * past anything that is not built to expand. */
#define KOF_ZIP_RATIO_ABSURD 5000u

/*
 * One entry, as the central directory describes it and the local header places it.
 *
 * `data_off` is resolved through the LOCAL header, never computed from the central
 * one: the two carry independent extra-field lengths, and a reader that trusts the
 * central copy lands in the middle of an extra field on any archive built to make
 * it. The central record is what says an entry exists; the local one says where its
 * bytes are.
 */
struct kof_zip_entry {
	uint64_t data_off;        /* first byte of entry data, 0 if unresolved */
	uint64_t csize, usize;    /* as declared */
	uint64_t local_off;       /* where the local header is */
	uint64_t name_off;        /* the central copy of the name */
	uint32_t name_len;
	uint32_t crc32;
	uint16_t method;
	uint16_t flags;
	uint32_t suspicious;      /* KOF_ZIP_ENT_* below */
};

enum {
	KOF_ZIP_ENT_TRAVERSAL  = 1u << 0,  /* ../ or an absolute path */
	KOF_ZIP_ENT_ENCRYPTED  = 1u << 1,
	KOF_ZIP_ENT_NO_LOCAL   = 1u << 2,  /* the local header is not where it said */
	KOF_ZIP_ENT_RATIO      = 1u << 3   /* declares an absurd expansion */
};

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2. The two arrays that used to end this struct - `run[16384]` and
 * `entry[4096]`, 622728 bytes - are tables the parse allocates to the size of the
 * archive, reached through the pointers at the tail. Everything before them is where
 * it was.
 *
 * `n_entries` WAS AT OFFSET 12 AND IS NOW `legacy_n_entries`, ALWAYS ZERO, and that is
 * the whole of the compatibility story, so it is spelled out. A module built against
 * version 1 reads `z->entry[i]` for `i < z->n_entries` at the offsets its build put
 * them; in this layout there is nothing there. Leaving the count would make it read
 * whatever lives at those addresses - no crash, no refusal, a scan deciding on the
 * wrong bytes. With the count at zero the loop does not run: such a module reads a valid
 * empty table, opens nothing, and the engine - which sees that the walk below was never
 * called while the archive has rows - reports the object instead of passing it as
 * examined (sx_walk_check). The way to REFUSE such a module outright is the floor,
 * KOFSIG_ABI_MIN, raised by whoever owns it; see kofabi.h. The real count is
 * `n_entries` at the tail.
 *
 * A module walks the table with kof_zip_next below; it does not index `entry`.
 */
struct kof_zip_info {
	uint32_t version;         /* KOF_ZIP_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t kind;            /* enum kof_zip_kind */
	uint32_t legacy_n_entries;/* version 1's count, kept for its offset: always 0 */
	uint32_t declared_entries;/* what the end record claimed */
	uint32_t n_encrypted;

	uint64_t eocd_off;
	uint64_t cd_off, cd_size;
	/*
	 * How far the archive's own coordinates are from the file's.
	 *
	 * Zero for an ordinary archive. Positive when something is glued in front - a
	 * self-extracting stub - and negative when the archive was carved out of a
	 * larger file and its front was cut off. Every offset the directory states is
	 * corrected by it, so cd_off and every entry's local_off above are already
	 * file offsets and a module never applies this itself.
	 */
	int64_t  base_delta;
	uint64_t comment_off, comment_len;

	/* Totals over the entries examined, declared rather than verified. */
	uint64_t total_csize, total_usize;

	uint64_t region_bytes[KOF_ZIP_CLS_COUNT];

	/* Runs, classified, joined where consecutive and settled so no byte is in two
	 * of them. struct kof_run is range.h's. */
	uint32_t n_runs;
	uint32_t reserved0;

	/* ---- version 2: from here the tables are the file's size ---------------------- */

	struct kof_view_mem mem;  /* what the tables hold; see range.h */
	struct kof_run *run;      /* n_runs of them; cls is enum kof_zip_class */
	struct kof_zip_entry *entry;
	uint32_t n_entries;       /* rows in `entry`: every record the directory held that
				   * the tables could take, which is all of them unless
				   * ENTRIES_FULL is raised */
	uint32_t reserved1;
};

static inline const struct kof_zip_info *kof_zip(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_zip_info *)ctx->file_header;
}

/*
 * THE NEXT ENTRY OF THE ARCHIVE, in the order the central directory lists them.
 *
 *     uint32_t cur = 0;
 *     const struct kof_zip_entry *e;
 *
 *     while ((e = kof_zip_next(ctx, &cur)) != 0)
 *             ...
 *
 * A walk with a cursor the module owns, which is what lets the table be as long as the
 * archive: there is no `entry[4096]` to index and no count to trust. NULL at the end. The
 * host sees every call (it is a vtable slot), which is how it knows a module read the
 * table - see struct kof_view_mem.walked. An archive that declares more entries than
 * the engine could hold says so (KOF_ZIP_ANOM_ENTRIES_FULL) and the walk ends where the
 * table does.
 */
static inline const struct kof_zip_entry *kof_zip_next(const struct kof_obj_ctx *ctx,
						       uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_zip_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_ZIP_H */
