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

#define KOF_ZIP_INFO_VERSION 1

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
 * Bounds the parse holds itself to.
 *
 * The entry count is the one that matters and it is sized from measurement rather
 * than from the specification, which allows 65535 per disk and unbounded with
 * ZIP64.
 *
 * The first measurement was 280 archives with a median of 2 entries and a largest
 * of 991, and it was drawn before this engine could tell a JAR or an APK from a
 * plain zip. Those change the distribution completely: over 707 archives the median
 * is 8, the 99th percentile is 4041 and the largest holds 41659 - an APK is a zip
 * with every class file in it, and 5242 entries is an ordinary one.
 *
 * So 4096 covers 99% of them. It is not enough for the largest and nothing
 * reasonable would be; what matters is that falling short is RECORDED - the entries
 * beyond it are not scanned, and an archive that hit the cap says so rather than
 * reporting the part it read as the whole.
 */
#define KOF_ZIP_MAX_ENTRIES  4096u
/*
 * Runs recorded, across all classes.
 *
 * Four per entry is the shape: a local header and a central record, each split by
 * the name sitting inside it. The entry cap above is what this is derived from, so
 * the two move together - a run pool that did not grow with the entries would make
 * the extra entries describable and not locatable.
 */
#define KOF_ZIP_MAX_EXTENTS  (KOF_ZIP_MAX_ENTRIES * 4u)

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
	KOF_ZIP_ANOM_ENTRIES_FULL   = 1ull << 6,  /* more entries than examined */
	KOF_ZIP_ANOM_EXTENTS_FULL   = 1ull << 7,
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

struct kof_zip_info {
	uint32_t version;         /* KOF_ZIP_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t kind;            /* enum kof_zip_kind */
	uint32_t n_entries;       /* examined, which is at most MAX_ENTRIES */
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
	 * of them. Spelled out rather than including runlist.h, for the reason
	 * docole.h gives: the ABI must not depend on a host header. */
	uint32_t n_runs;
	uint32_t reserved0;
	struct {
		uint64_t off, len;
		uint32_t cls;         /* enum kof_zip_class */
		uint32_t reserved;
	} run[KOF_ZIP_MAX_EXTENTS];

	struct kof_zip_entry entry[KOF_ZIP_MAX_ENTRIES];
};

static inline const struct kof_zip_info *kof_zip(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_zip_info *)ctx->file_header;
}

#endif /* KOFENG_ZIP_H */
