/*
 * rar.h - the RAR view of an object.
 *
 * The largest hole this engine had. Measured over the collection, RAR is 865 files
 * and 18.7% of all the bytes - more than every ELF in it put together - and until
 * this existed every one of them was scanned as a single opaque blob.
 *
 *
 * WHAT A PARSER GETS WITHOUT A DECODER, AND IT IS MORE THAN IT SOUNDS
 *
 * RAR keeps its file list in the clear, in a chain of block headers running through
 * the file. So unlike 7z - which compresses its own metadata - every name, size,
 * ratio and encryption flag is readable for nothing, and 23% of the entries in this
 * collection are STORED, which means their bytes are readable too.
 *
 * What needs a decoder is the other 77%: RAR's own compression, which is the single
 * most expensive thing left unimplemented here. This view is what makes the free
 * part usable, and it names the rest honestly rather than reporting an archive
 * clean because nothing looked inside it.
 *
 *
 * TWO FORMATS BEHIND ONE MAGIC
 *
 * RAR3 and RAR5 share nothing but the first six bytes: RAR3 walks fixed little
 * endian block headers, RAR5 walks variable length integers with a different block
 * vocabulary. They are one format id with a version field rather than two ids
 * because a module that wants "any RAR" is the common case and neither shape
 * changes what a signature does with a name.
 *
 * Measured here: 787 RAR3 to 78 RAR5. Only RAR3 is walked; a RAR5 is identified,
 * its version recorded, and reported as a version this build does not read - which
 * is a gap somebody can close, and is named as one.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_RAR_H
#define KOFENG_RAR_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_RAR_INFO_VERSION 2

/*
 * Scan regions, the same five a zip has and for the same reasons: the names are
 * where an author's text is and the compression method decides whether the data can
 * be searched at all.
 *
 * A name here follows its header directly, so splitting NAMES out costs one extra
 * extent per entry rather than the five it would cost in a tar - which is why this
 * has the region and tar does not.
 */
enum kof_scan_rar {
	KOF_SCAN_RAR_HEADERS   = 1u << 1,  /* block headers, without their names */
	KOF_SCAN_RAR_NAMES     = 1u << 2,
	KOF_SCAN_RAR_STORED    = 1u << 3,  /* method 0x30: the file, in the clear */
	KOF_SCAN_RAR_PACKED    = 1u << 4,  /* anything else: opaque */
	KOF_SCAN_RAR_UNCLAIMED = 1u << 5
};

#define KOF_SCAN_RAR_CLAIMED                                                 \
	(KOF_SCAN_RAR_HEADERS | KOF_SCAN_RAR_NAMES | KOF_SCAN_RAR_STORED |   \
	 KOF_SCAN_RAR_PACKED)

enum kof_rar_class {
	KOF_RAR_CLS_HEADERS = 0,
	KOF_RAR_CLS_NAMES,
	KOF_RAR_CLS_STORED,
	KOF_RAR_CLS_PACKED,
	KOF_RAR_CLS_COUNT
};

/* Which of the two formats this is. */
enum kof_rar_version {
	KOF_RAR_V3 = 3,
	KOF_RAR_V5 = 5
};

/* RAR3 block types. Only the ones the walk acts on are named. */
enum {
	KOF_RAR3_BLK_MARKER  = 0x72,
	KOF_RAR3_BLK_ARCHIVE = 0x73,
	KOF_RAR3_BLK_FILE    = 0x74,
	KOF_RAR3_BLK_COMMENT = 0x75,
	KOF_RAR3_BLK_SUB     = 0x7a,
	KOF_RAR3_BLK_END     = 0x7b
};

/*
 * RAR5 block types and flags.
 *
 * A different vocabulary from RAR3 and a different encoding: every number is a
 * variable length integer, seven bits to a byte, and every block states its own
 * header size so a walk can step over a block it does not understand. That last
 * property is why RAR5 is worth walking even without a decoder - the structure is
 * self describing in a way RAR3's is not.
 */
enum {
	KOF_RAR5_BLK_MAIN    = 1,
	KOF_RAR5_BLK_FILE    = 2,
	KOF_RAR5_BLK_SERVICE = 3,
	KOF_RAR5_BLK_CRYPT   = 4,   /* the archive's headers are encrypted */
	KOF_RAR5_BLK_END     = 5
};

enum {
	KOF_RAR5_H_EXTRA = 0x0001,  /* an extra area follows the header */
	KOF_RAR5_H_DATA  = 0x0002   /* a data area follows the block */
};

/*
 * Extra-record types on a RAR5 file header.
 *
 * Only the one that changes what can be said about an entry is named. RAR5 has
 * no password flag - encryption is this record - so an archive whose entries
 * all carry it is encrypted, and saying "damaged" instead sends a reader to
 * look for a corruption that is not there.
 */
enum {
	KOF_RAR5_EXTRA_CRYPT = 1
};

enum {
	KOF_RAR5_F_DIR      = 0x0001,
	KOF_RAR5_F_TIME     = 0x0002,  /* four bytes of mtime are present */
	KOF_RAR5_F_CRC      = 0x0004,  /* four bytes of CRC32 are present */
	KOF_RAR5_F_UNKNOWN  = 0x0008   /* the unpacked size is not stated */
};

/* RAR3 header flags. */
enum {
	KOF_RAR3_F_SPLIT_BEFORE = 1u << 0,
	KOF_RAR3_F_SPLIT_AFTER  = 1u << 1,
	KOF_RAR3_F_ENCRYPTED    = 1u << 2,
	KOF_RAR3_F_SOLID        = 1u << 4,
	KOF_RAR3_F_LARGE        = 1u << 8,   /* the 64 bit halves are present */
	KOF_RAR3_F_UNICODE      = 1u << 9,
	KOF_RAR3_F_ADD_SIZE     = 1u << 15   /* data follows the header */
};

/*
 * Flags that mean something only on the RAR3 archive header (KOF_RAR3_BLK_ARCHIVE).
 *
 * The bit values collide with the file-header flags above and mean different
 * things, which is why they are named apart rather than added to that set.
 */
enum {
	/* Every block header AFTER this one is ciphertext. Not "some entry is
	 * encrypted" - the archive's structure itself is unreadable. */
	KOF_RAR3_M_ENC_HEADERS = 1u << 7
};

/* Methods, 0x30 through 0x35. Only "stored" changes what can be done. */
#define KOF_RAR_M_STORE 0x30u

/*
 * What bounds the parse, and what does not.
 *
 * NO COUNT OF ENTRIES IS A LIMIT ON THE FILE. The entry table was 2048 rows and the run list
 * 8192: "across 787 RAR3 archives holding 28848 entries the median holds 12 and the largest
 * 1458", which is what is common and says nothing about what a builder emits - an archive of
 * 3000 small files lost the last thousand of them. The tables are allocated to what the block
 * chain holds, and what bounds an allocation is the file: a file block is at least
 * KOF_RAR_ENTRY_MIN bytes (RAR3's fixed part is 32, RAR5's header is a dozen at the least), so
 * the rows cannot exceed the length of the file over it, and an entry makes at most
 * KOF_RAR_RUNS_PER_ENTRY runs. Under that sits the engine's per-object ledger (struct
 * kof_view_mem.room): when a table cannot grow the walk goes on classifying what follows into
 * regions - the bytes are still the archive's - and ENTRIES_FULL or EXTENTS_FULL says the entries
 * past it were not listed, so the object reads KOF_BROKEN_LIMIT.
 */
#define KOF_RAR_ENTRY_MIN       12u
#define KOF_RAR_RUNS_PER_ENTRY   5u

enum {
	KOF_RAR_ANOM_BAD_BLOCK    = 1ull << 0, /* a header shorter than a header */
	KOF_RAR_ANOM_TRUNCATED    = 1ull << 1, /* a block or its data runs past the end */
	KOF_RAR_ANOM_ENTRIES_FULL = 1ull << 2, /* the entry table could not grow: the
						* archive has entries not listed */
	KOF_RAR_ANOM_EXTENTS_FULL = 1ull << 3, /* the run table could not grow */
	KOF_RAR_ANOM_ENCRYPTED    = 1ull << 4,
	KOF_RAR_ANOM_TRAVERSAL    = 1ull << 5,
	KOF_RAR_ANOM_RATIO_ABSURD = 1ull << 6,
	KOF_RAR_ANOM_OVERLAP      = 1ull << 7,
	KOF_RAR_ANOM_NO_END       = 1ull << 8, /* no end block closes it */
	KOF_RAR_ANOM_SOLID        = 1ull << 9, /* entries share a compression window */
	KOF_RAR_ANOM_UNSUPPORTED  = 1ull << 10 /* RAR5, which this build does not walk */
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KOF_RAR_ANOM_COUNT 11


/* The ratio at which the bit above is set, on the same reasoning as gzip's and
 * zip's: far past anything that is not built to expand. */
#define KOF_RAR_RATIO_ABSURD 5000u

struct kof_rar_entry {
	uint64_t hdr_off;         /* the block header */
	uint64_t data_off;        /* first byte of packed data, 0 if none */
	uint64_t csize, usize;    /* as declared */
	uint64_t name_off;
	uint32_t name_len;
	uint32_t crc32;
	uint16_t flags;
	uint8_t  method;          /* 0x30..0x35 */
	uint8_t  unp_ver;
	uint32_t suspicious;      /* KOF_RAR_ENT_* */
};

enum {
	KOF_RAR_ENT_TRAVERSAL = 1u << 0,
	KOF_RAR_ENT_ENCRYPTED = 1u << 1,
	KOF_RAR_ENT_PAST_EOF  = 1u << 2,
	KOF_RAR_ENT_RATIO     = 1u << 3,
	KOF_RAR_ENT_SPLIT     = 1u << 4,  /* continues into or from another volume */
	KOF_RAR_ENT_SOLID     = 1u << 5   /* continues the previous entry's window */
};

/*
 * THE VIEW, AND WHAT CHANGED IN IT.
 *
 * Version 2, the same change as the zip view's (zip.h has the long form): `run[8192]` and
 * `entry[2048]`, 311 KB, are tables the parse allocates to the size of the archive, reached through
 * the pointers at the tail. Everything before them is where it was. `n_entries` WAS AT OFFSET 20 AND
 * IS NOW `legacy_n_entries`, ALWAYS ZERO: a module built against version 1 loops over a count of
 * zero, reads a valid empty table, and the engine - which sees that the walk below was never called
 * while the archive has rows - reports the object instead of passing it as examined
 * (sx_walk_check). The real count is `n_entries` at the tail. A module walks the table with
 * kof_rar_next below; it does not index `entry`.
 */
struct kof_rar_info {
	uint32_t version;         /* KOF_RAR_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t rar_version;     /* enum kof_rar_version */
	uint32_t legacy_n_entries;/* version 1's count, kept for its offset: always 0 */
	uint32_t n_encrypted;
	uint32_t n_stored;

	uint64_t total_csize, total_usize;
	uint64_t region_bytes[KOF_RAR_CLS_COUNT];

	uint32_t n_runs;
	uint32_t reserved0;

	/* ---- version 2: from here the tables are the file's size ----------------------- */

	struct kof_view_mem mem;  /* what the tables hold; see range.h */
	struct kof_run *run;      /* n_runs of them; cls is enum kof_rar_class */
	struct kof_rar_entry *entry;
	uint32_t n_entries;       /* rows in `entry`: every file block the walk met that the
				   * tables could take */
	uint32_t reserved1;
};

static inline const struct kof_rar_info *kof_rar(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_rar_info *)ctx->file_header;
}

/*
 * THE NEXT ENTRY OF THE ARCHIVE, in the order the blocks follow one another: row `*cursor`, and the
 * cursor is advanced; NULL at the end. See kof_zip_next, which this is the same walk as.
 */
static inline const struct kof_rar_entry *kof_rar_next(const struct kof_obj_ctx *ctx,
						       uint32_t *cursor)
{
	return ctx->content->view_next
	       ? (const struct kof_rar_entry *)ctx->content->view_next(ctx, cursor)
	       : 0;
}

#endif /* KOFENG_RAR_H */
