/*
 * sevenzip.h - the 7z view of an object.
 *
 * The first container in this engine that COMPRESSES ITS OWN METADATA. A zip keeps
 * its central directory in the clear and a tar keeps its headers in the clear, so a
 * parser can say what is inside either without decoding a byte. A 7z puts its file
 * list through the same coder as its content - measured over 44 real archives, 43
 * of them do - so the list of names is not readable until something has run LZMA
 * over it.
 *
 * That is why this view says so little. It describes what can be established
 * WITHOUT decoding, which is the shape of the archive and one fact that turns out
 * to matter more than the rest.
 *
 *
 * THE ONE FACT WORTH HAVING FOR FREE
 *
 * Whether the header is encrypted. 19 of those 44 archives encrypt it, which means
 * even the list of file names is ciphertext and no build of this engine will ever
 * read them. An archive nothing can read must not come back clean, and the coder
 * that compressed the header is stated in the clear right at the front of the
 * header - so this costs a few bytes of parsing and answers the question.
 *
 * The distinction it draws is the one an operator acts on: ENCRYPTED never becomes
 * readable, UNSUPPORTED might in a later build.
 *
 *
 * WHY THERE ARE NO ENTRIES HERE
 *
 * Because there is nowhere honest to put them yet. A 7z entry name lives in the
 * DECODED header, not in the object, so it cannot be an offset into the object the
 * way a zip or tar name is - and the whole naming path, including how a child is
 * labelled for reporting, is built on names being ranges in the object. Inventing a
 * second convention for one format is worse than admitting this describes the
 * container and not its contents.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_SEVENZIP_H
#define KOFENG_SEVENZIP_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_7Z_INFO_VERSION 1

/*
 * Scan regions.
 *
 * Three, and two of them are structure at opposite ends of the file: the fixed 32
 * byte start header at the front, and the variable "next header" at the back. They
 * are one region because they do one job - saying where things are - which is the
 * same reason a zip's local and central records share HEADERS.
 *
 * PACKED is everything between them: the coded streams. Searching it finds nothing
 * whatever is in it, which is exactly what makes the region worth naming - a module
 * can say "not there" and a bomb heuristic can ask how large it is.
 */
enum kof_scan_7z {
	KOF_SCAN_7Z_HEADERS   = 1u << 1,  /* the start header and the next header */
	KOF_SCAN_7Z_PACKED    = 1u << 2,  /* the coded streams: opaque */
	KOF_SCAN_7Z_UNCLAIMED = 1u << 3
};

#define KOF_SCAN_7Z_CLAIMED (KOF_SCAN_7Z_HEADERS | KOF_SCAN_7Z_PACKED)

enum kof_7z_class {
	KOF_7Z_CLS_HEADERS = 0,
	KOF_7Z_CLS_PACKED,
	KOF_7Z_CLS_COUNT
};

/* Property ids, from the format's own description. Only the handful this reads. */
enum {
	KOF_7Z_ID_END      = 0x00,
	KOF_7Z_ID_HEADER   = 0x01,
	KOF_7Z_ID_PACKINFO = 0x06,
	KOF_7Z_ID_UNPACK   = 0x07,
	KOF_7Z_ID_SIZE     = 0x09,
	KOF_7Z_ID_FOLDER   = 0x0b,
	KOF_7Z_ID_ENCODED  = 0x17   /* the header itself is coded */
};

/*
 * How the header was stored.
 *
 * PLAIN is readable as it lies. CODED needs a decoder this build may or may not
 * have. ENCRYPTED needs a key, which is a different answer entirely and the reason
 * these are three values rather than a flag.
 */
enum kof_7z_header_kind {
	KOF_7Z_HDR_PLAIN = 0,
	KOF_7Z_HDR_CODED,
	KOF_7Z_HDR_ENCRYPTED,
	KOF_7Z_HDR_MISSING       /* the start header points outside the object */
};

/* Coder ids, as the bytes they are written with. AES is the one that decides
 * whether an archive is readable at all; LZMA is what almost every other header
 * uses. */
#define KOF_7Z_CODER_LZMA   0x030101u
#define KOF_7Z_CODER_LZMA2  0x21u
#define KOF_7Z_CODER_AES    0x06f10701u
#define KOF_7Z_CODER_COPY   0x00u

#define KOF_7Z_SIG_LEN 32u   /* magic, version, crc, and the two next-header fields */

enum {
	KOF_7Z_ANOM_BAD_START     = 1ull << 0, /* the 32 byte header is not readable */
	KOF_7Z_ANOM_HDR_PAST_EOF  = 1ull << 1, /* the next header is outside the file */
	KOF_7Z_ANOM_HDR_EMPTY     = 1ull << 2, /* no next header at all */
	KOF_7Z_ANOM_ENCRYPTED     = 1ull << 3, /* the file list itself is ciphertext */
	KOF_7Z_ANOM_UNKNOWN_CODER = 1ull << 4,
	KOF_7Z_ANOM_BAD_VERSION   = 1ull << 5,
	KOF_7Z_ANOM_OVERLAP       = 1ull << 6
};

struct kof_7z_info {
	uint32_t version;         /* KOF_7Z_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint8_t  major, minor;
	uint8_t  header_kind;     /* enum kof_7z_header_kind */
	uint8_t  reserved0;

	/* Where the archive says its header is, and how large. Both come from the
	 * start header and are stated relative to the end of it. */
	uint64_t next_hdr_off;    /* already made absolute */
	uint64_t next_hdr_size;

	/* The coder the header was put through, zero when it is plain. Read without
	 * decoding anything: it sits in the clear at the front of the coded header. */
	uint32_t hdr_coder;
	uint32_t reserved1;

	uint64_t region_bytes[KOF_7Z_CLS_COUNT];
};

static inline const struct kof_7z_info *kof_7z(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_7z_info *)ctx->file_header;
}

#endif /* KOFENG_SEVENZIP_H */
