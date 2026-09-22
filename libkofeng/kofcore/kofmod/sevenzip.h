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
	KOF_7Z_ID_CODERS_SIZE = 0x0c,
	KOF_7Z_ID_ENCODED  = 0x17,  /* the header itself is coded */
	KOF_7Z_ID_STREAMS  = 0x04,  /* kMainStreamsInfo */
	KOF_7Z_ID_FILES    = 0x05,
	KOF_7Z_ID_SUBSTREAMS = 0x08,
	KOF_7Z_ID_CRC      = 0x0a
};

/*
 * Folders described, and why a cap this small is the right one.
 *
 * A folder is 7z's unit of decompression: one coder chain over one run of packed
 * bytes, yielding the concatenation of every file in it. Most archives use one for
 * everything, which is what "solid" means and why extracting a single file from a
 * 7z means decoding everything before it.
 *
 * Reaching this cap is recorded rather than silently truncating.
 */
#define KOF_7Z_MAX_FOLDERS 64u
/* Four inputs is the widest coder this format defines, so a folder cannot own more
 * than four packed streams and sixty four folders cannot own more than this. */
#define KOF_7Z_MAX_PACK   256u

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
#define KOF_7Z_CODER_BCJ_X86 0x03030103u
#define KOF_7Z_CODER_BCJ2   0x0303011bu

#define KOF_7Z_SIG_LEN 32u   /* magic, version, crc, and the two next-header fields */

enum {
	KOF_7Z_ANOM_BAD_START     = 1ull << 0, /* the 32 byte header is not readable */
	KOF_7Z_ANOM_HDR_PAST_EOF  = 1ull << 1, /* the next header is outside the file */
	KOF_7Z_ANOM_HDR_EMPTY     = 1ull << 2, /* no next header at all */
	KOF_7Z_ANOM_ENCRYPTED     = 1ull << 3, /* the file list itself is ciphertext */
	KOF_7Z_ANOM_UNKNOWN_CODER = 1ull << 4,
	KOF_7Z_ANOM_BAD_VERSION   = 1ull << 5,
	KOF_7Z_ANOM_OVERLAP       = 1ull << 6,
	KOF_7Z_ANOM_FOLDERS_FULL  = 1ull << 7,  /* more folders than listed */
	KOF_7Z_ANOM_HDR_UNREAD    = 1ull << 8,  /* the coded header did not decode */
	KOF_7Z_ANOM_CODER_CHAIN   = 1ull << 9   /* a folder chains coders: not decoded */
};

/* How many of the above there are, so the name table cannot silently fall behind
 * them - three of these bits went unnamed until a checklist pass found it. */
enum {
	KOF_7Z_ANOM_COUNT = 10
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

	/*
	 * Where the coded header's bytes are and what it takes to decode them.
	 *
	 * Everything here is stated in the clear at the front of the coded header -
	 * it has to be, since it is what tells a reader how to decode the rest - so
	 * the parse can hand it over without decompressing anything itself.
	 *
	 * This is the whole of what a module needs to recover the file list, and it
	 * is deliberately not an entry table. A 7z archive in this collection holds a
	 * median of 18 files and a maximum of 84644, with names up to 1361 characters
	 * - so a table with names in it would either be megabytes of view or would cut
	 * off the archives that most need reading. The decoded header is produced as a
	 * child instead, and the names inside it are searched the way any other text
	 * is, with no cap, no table, and no second convention for where a name lives.
	 */
	uint64_t hdr_pack_off;    /* absolute, of the coded bytes */
	uint64_t hdr_pack_size;
	uint64_t hdr_unpack_size; /* what the archive says the decode yields */
	uint8_t  hdr_lc, hdr_lp, hdr_pb;
	uint8_t  reserved2;

	uint64_t region_bytes[KOF_7Z_CLS_COUNT];

	/*
	 * The content, once the header has been read.
	 *
	 * Everything above describes the archive without decoding anything. This
	 * needs the header decompressed first - the folder list lives inside it -
	 * so the parse does that decode itself, the same way the compound file
	 * parse decompresses a VBA project directory to find where the modules
	 * are. It is the one thing in 7z that cannot be established any other way.
	 *
	 * Measured over 369 real archives: 351 code their content with plain LZMA,
	 * which this engine already decodes and has checked against a reference on
	 * 355 headers. Four use LZMA2 and eleven are encrypted. So the folder list
	 * is what stands between the parse and 95% of the content.
	 */
	uint32_t n_folders;
	uint32_t reserved3;
	struct kof_7z_folder {
		uint64_t pack_off;     /* absolute, of the coded bytes */
		uint64_t pack_size;
		uint64_t unpack_size;  /* what the archive says the decode yields */
		uint32_t coder;        /* KOF_7Z_CODER_* */
		uint8_t  lc, lp, pb;   /* meaningful for LZMA */
		uint8_t  n_coders;
		/*
		 * The transform in front of the coder, zero when there is none.
		 *
		 * A folder may run a filter over its bytes before compressing them,
		 * and undoing it is a separate step after the decode. Measured over
		 * the archives here: 342 folders use no filter, 76 use BCJ x86 and
		 * 8 use BCJ2 - so one filter is 90% of them and the rest are named
		 * rather than guessed at.
		 */
		uint32_t filter;
		uint32_t out_first;    /* index of this folder's first output stream */

	} folder[KOF_7Z_MAX_FOLDERS];

	/*
	 * Every packed stream in the archive, and which folder owns it.
	 *
	 * APPENDED AFTER folder[] ON PURPOSE. A folder used to be one packed stream,
	 * so pack_off and pack_size above said all there was to say. BCJ2 breaks that:
	 * it takes FOUR inputs - the main stream, the call addresses, the jump
	 * addresses, and the range coder's control bytes - and three of them are
	 * themselves the output of other coders in the same folder. Only the ones not
	 * fed by a bind pair are packed streams, and there are four of them.
	 *
	 * Widening kof_7z_folder would have moved every field after the one that grew
	 * and changed the stride of the array, which is an ABI break for every module
	 * compiled against the old layout. A table after the last member is not: the
	 * offsets a module already reads stay where they were, and the struct simply
	 * gets longer.
	 *
	 * pack_off and pack_size keep meaning the folder's FIRST packed stream, which
	 * for every single-coder folder is still its only one.
	 */
	uint32_t n_pack;
	uint32_t reserved4;
	struct kof_7z_pack {
		uint64_t off;          /* absolute, of the coded bytes */
		uint64_t size;
		uint32_t folder;       /* index into folder[] */
		/*
		 * Which BCJ2 input this stream feeds: 0 main, 1 call, 2 jump,
		 * 3 the range coder. 0xffffffff when the folder is not BCJ2,
		 * which is every folder with a single coder.
		 */
		uint32_t role;
		/*
		 * What this stream decodes to on its own, and with which settings.
		 *
		 * A BCJ2 folder is four coders, and three of them are separate LZMA
		 * streams with separate properties and separate output lengths. The
		 * folder record carries one of each because a folder used to be one
		 * coder; carrying the rest here is what makes the three decodable
		 * apart from one another.
		 *
		 * out_size is zero for a stream that is packed straight into its
		 * consumer - the range coder's control bytes are not compressed.
		 */
		uint64_t out_size;
		uint32_t coder;        /* KOF_7Z_CODER_* feeding this stream */
		uint8_t  lc, lp, pb, reserved5;
	} pack[KOF_7Z_MAX_PACK];
};

static inline const struct kof_7z_info *kof_7z(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_7z_info *)ctx->file_header;
}

#endif /* KOFENG_SEVENZIP_H */
