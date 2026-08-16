/*
 * pdf.h - the PDF view of an object.
 *
 * PDF is not a container in the sense zip is. It is a graph of numbered objects,
 * most of them small dictionaries of key/value pairs, some of them carrying a
 * stream of bytes that may be compressed. What matters for a scan is that the two
 * halves want completely different treatment:
 *
 *   THE DICTIONARIES ARE TEXT IN THE CLEAR, and they are where a malicious PDF
 *   declares itself. /OpenAction and /AA say what runs when the file is opened,
 *   /Launch says what program to start, /JS and /JavaScript carry script, /EmbeddedFile
 *   and /Filespec name a payload. None of that needs decoding to be searched.
 *
 *   THE STREAMS ARE OPAQUE until a filter has been undone, and most of a PDF's bytes
 *   are streams - fonts, images, page content. Searching them raw finds nothing.
 *
 * So the region split is the one this engine draws everywhere: structure against
 * content, with the structure readable and the content named rather than guessed at.
 *
 *
 * WHY THE OBJECTS ARE FOUND BY SCANNING AND NOT BY THE XREF
 *
 * The cross reference table is the index a reader is supposed to use, and a hostile
 * PDF is free to lie in it - viewers famously recover by scanning for "obj" when the
 * xref disagrees, which means malware can put an object where the xref says there is
 * none and still have it run. A parse that trusted the xref would then classify the
 * bytes that matter as UNCLAIMED.
 *
 * So objects are located by walking the file for the `N G obj` pattern, and the xref
 * is read only to be reported on. That is slower and it is what the format actually
 * means.
 *
 *
 * WHAT IS NOT DONE HERE
 *
 * Stream filters are not undone by the parse. /FlateDecode is the common one and the
 * engine has the decoder; running it belongs to an unpacker, which produces the
 * decoded stream as a child object the same way every other container does. The parse
 * names each stream's filter so the unpacker knows what it is looking at, and records
 * a filter it does not recognise rather than assuming Flate.
 *
 * Object streams - /ObjStm, a stream that holds other objects - are named for the
 * same reason and left to the unpacker: their contents are dictionaries, and once
 * decoded they are searched as the dictionaries of any other object are.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_PDF_H
#define KOFENG_PDF_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_PDF_INFO_VERSION 1

/*
 * Scan regions.
 *
 * HEADER is the version line, the trailer, the xref and the startxref pointer -
 * small, and the part that describes the rest. OBJECTS is every object's dictionary
 * and any direct content that is not a stream: this is the region a signature for a
 * malicious action searches. STREAM_PLAIN is stream data with no filter, which is
 * readable where it lies. STREAM_PACKED is stream data behind a filter, opaque until
 * an unpacker has run.
 */
enum kof_scan_pdf {
	KOF_SCAN_PDF_HEADER       = 1u << 1,
	KOF_SCAN_PDF_OBJECTS      = 1u << 2,  /* dictionaries, in the clear */
	KOF_SCAN_PDF_STREAM_PLAIN = 1u << 3,  /* unfiltered stream data */
	KOF_SCAN_PDF_STREAM_PACKED= 1u << 4,  /* filtered stream data: opaque */
	KOF_SCAN_PDF_UNCLAIMED    = 1u << 5
};

#define KOF_SCAN_PDF_CLAIMED                                                  \
	(KOF_SCAN_PDF_HEADER | KOF_SCAN_PDF_OBJECTS |                         \
	 KOF_SCAN_PDF_STREAM_PLAIN | KOF_SCAN_PDF_STREAM_PACKED)

enum kof_pdf_class {
	KOF_PDF_CLS_HEADER = 0,
	KOF_PDF_CLS_OBJECTS,
	KOF_PDF_CLS_STREAM_PLAIN,
	KOF_PDF_CLS_STREAM_PACKED,
	KOF_PDF_CLS_COUNT
};

#define KOF_PDF_REGION_COUNT 5u

/*
 * Bounds.
 *
 * Measured over the PDFs on this machine the largest holds 548 objects; a document
 * built by a generator can hold far more, so the cap is set well above what was seen
 * and reaching it is recorded rather than silently truncating the walk.
 */
#define KOF_PDF_MAX_OBJECTS  4096u
#define KOF_PDF_MAX_EXTENTS 16384u

/* How far into the file the %PDF- header may sit. Readers accept junk in front of
 * it, and malware uses that, so a small window is searched rather than offset 0
 * alone. */
#define KOF_PDF_HEADER_SEARCH 1024u

/* Filters, as a bitmask so a chain can be recorded whole. */
enum {
	KOF_PDF_F_FLATE    = 1u << 0,
	KOF_PDF_F_LZW      = 1u << 1,
	KOF_PDF_F_ASCIIHEX = 1u << 2,
	KOF_PDF_F_ASCII85  = 1u << 3,
	KOF_PDF_F_RUNLEN   = 1u << 4,
	KOF_PDF_F_DCT      = 1u << 5,   /* JPEG image data */
	KOF_PDF_F_CCITT    = 1u << 6,
	KOF_PDF_F_JBIG2    = 1u << 7,
	KOF_PDF_F_JPX      = 1u << 8,
	KOF_PDF_F_CRYPT    = 1u << 9,
	KOF_PDF_F_OTHER    = 1u << 10   /* a name this build does not know */
};

/*
 * What an object announces about itself.
 *
 * These are the reasons a PDF is worth a second look, and they are recorded per
 * object as well as per file so that a module can ask which object carried one.
 */
enum {
	KOF_PDF_OBJ_STREAM     = 1u << 0,  /* carries a stream */
	KOF_PDF_OBJ_JS         = 1u << 1,  /* /JS or /JavaScript */
	KOF_PDF_OBJ_OPENACTION = 1u << 2,  /* /OpenAction or /AA: runs on open */
	KOF_PDF_OBJ_LAUNCH     = 1u << 3,  /* /Launch: starts a program */
	KOF_PDF_OBJ_EMBEDDED   = 1u << 4,  /* /EmbeddedFile or /Filespec */
	KOF_PDF_OBJ_OBJSTM     = 1u << 5,  /* /ObjStm: objects inside a stream */
	KOF_PDF_OBJ_URI        = 1u << 6,
	KOF_PDF_OBJ_GOTOE      = 1u << 7,  /* /GoToE: into an embedded file */
	KOF_PDF_OBJ_RICHMEDIA  = 1u << 8,
	KOF_PDF_OBJ_XFA        = 1u << 9,
	KOF_PDF_OBJ_ACROFORM   = 1u << 10
};

enum {
	/*
	 * There is no NO_HEADER bit: an object with no %PDF- is not a PDF and the
	 * parse refuses it, so the bit could never be set. A flag that cannot be
	 * raised is a promise to a reader that nothing keeps.
	 */
	KOF_PDF_ANOM_HEADER_OFFSET  = 1ull << 0,  /* bytes in front of %PDF- */
	KOF_PDF_ANOM_NO_EOF         = 1ull << 1,  /* no %%EOF marker */
	KOF_PDF_ANOM_NO_XREF        = 1ull << 2,
	KOF_PDF_ANOM_BAD_STARTXREF  = 1ull << 3,  /* points outside the file */
	KOF_PDF_ANOM_OBJECTS_FULL   = 1ull << 4,
	KOF_PDF_ANOM_EXTENTS_FULL   = 1ull << 5,
	KOF_PDF_ANOM_OVERLAP        = 1ull << 6,
	KOF_PDF_ANOM_STREAM_UNTERM  = 1ull << 7,  /* stream with no endstream */
	KOF_PDF_ANOM_ENCRYPTED      = 1ull << 8,  /* /Encrypt in the trailer */
	KOF_PDF_ANOM_JS             = 1ull << 9,
	KOF_PDF_ANOM_OPENACTION     = 1ull << 10,
	KOF_PDF_ANOM_LAUNCH         = 1ull << 11,
	KOF_PDF_ANOM_EMBEDDED       = 1ull << 12,
	KOF_PDF_ANOM_OBJSTM         = 1ull << 13,
	KOF_PDF_ANOM_UNKNOWN_FILTER = 1ull << 14,
	KOF_PDF_ANOM_TRUNCATED      = 1ull << 15  /* an object runs past the end */
};

#define KOF_PDF_ANOM_COUNT 16

struct kof_pdf_object {
	uint64_t off;          /* the 'N G obj' token */
	uint64_t len;          /* through 'endobj', clipped to the object */
	uint32_t num, gen;
	uint64_t dict_off, dict_len;      /* the part in the clear */
	uint64_t stream_off, stream_len;  /* zero when there is no stream */
	uint32_t filters;      /* KOF_PDF_F_* */
	uint32_t flags;        /* KOF_PDF_OBJ_* */
};

struct kof_pdf_info {
	uint32_t version;      /* KOF_PDF_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint64_t header_off;   /* where %PDF- was found */
	uint8_t  ver_major, ver_minor, reserved0, reserved1;
	uint64_t startxref;    /* what the file says; not trusted */
	uint64_t eof_off;      /* the last %%EOF, or 0 */

	uint32_t n_objects;
	uint32_t n_streams;
	uint32_t declared_objects;   /* what the walk found before any cap */

	uint64_t region_bytes[KOF_PDF_CLS_COUNT];

	uint32_t n_runs;
	uint32_t reserved2;
	struct {
		uint64_t off, len;
		uint32_t cls;
		uint32_t reserved;
	} run[KOF_PDF_MAX_EXTENTS];

	struct kof_pdf_object object[KOF_PDF_MAX_OBJECTS];
};

static inline const struct kof_pdf_info *kof_pdf(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_pdf_info *)ctx->file_header;
}

#endif /* KOFENG_PDF_H */
