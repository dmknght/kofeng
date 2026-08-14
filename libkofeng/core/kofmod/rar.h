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

#define KOF_RAR_INFO_VERSION 1

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

/* Methods, 0x30 through 0x35. Only "stored" changes what can be done. */
#define KOF_RAR_M_STORE 0x30u

/*
 * Bounds, from measurement. Across 787 RAR3 archives holding 28848 entries the
 * median holds 12 and the largest 1458, so the entry cap is not close to binding on
 * anything real and reaching it is worth reporting.
 */
#define KOF_RAR_MAX_ENTRIES 2048u
#define KOF_RAR_MAX_EXTENTS 8192u

enum {
	KOF_RAR_ANOM_BAD_BLOCK    = 1ull << 0, /* a header shorter than a header */
	KOF_RAR_ANOM_TRUNCATED    = 1ull << 1, /* a block or its data runs past the end */
	KOF_RAR_ANOM_ENTRIES_FULL = 1ull << 2,
	KOF_RAR_ANOM_EXTENTS_FULL = 1ull << 3,
	KOF_RAR_ANOM_ENCRYPTED    = 1ull << 4,
	KOF_RAR_ANOM_TRAVERSAL    = 1ull << 5,
	KOF_RAR_ANOM_RATIO_ABSURD = 1ull << 6,
	KOF_RAR_ANOM_OVERLAP      = 1ull << 7,
	KOF_RAR_ANOM_NO_END       = 1ull << 8, /* no end block closes it */
	KOF_RAR_ANOM_SOLID        = 1ull << 9, /* entries share a compression window */
	KOF_RAR_ANOM_UNSUPPORTED  = 1ull << 10 /* RAR5, which this build does not walk */
};

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
	KOF_RAR_ENT_SPLIT     = 1u << 4   /* continues into or from another volume */
};

struct kof_rar_info {
	uint32_t version;         /* KOF_RAR_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t rar_version;     /* enum kof_rar_version */
	uint32_t n_entries;
	uint32_t n_encrypted;
	uint32_t n_stored;

	uint64_t total_csize, total_usize;
	uint64_t region_bytes[KOF_RAR_CLS_COUNT];

	uint32_t n_runs;
	uint32_t reserved0;
	struct {
		uint64_t off, len;
		uint32_t cls;         /* enum kof_rar_class */
		uint32_t reserved;
	} run[KOF_RAR_MAX_EXTENTS];

	struct kof_rar_entry entry[KOF_RAR_MAX_ENTRIES];
};

static inline const struct kof_rar_info *kof_rar(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_rar_info *)ctx->file_header;
}

#endif /* KOFENG_RAR_H */
