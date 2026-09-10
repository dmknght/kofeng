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

#define KOF_PDF_INFO_VERSION 4

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
	KOF_SCAN_PDF_UNCLAIMED    = 1u << 5,
	/*
	 * PIXELS, AND THE REASON THIS REGION EXISTS AT ALL.
	 *
	 * The bulk of a PDF is images, and none of it is worth searching for
	 * anything this engine looks for. Measured on an ordinary 1.65MB
	 * document: 25 streams and 1,307,894 bytes are image data - 79% of the
	 * file. Left inside STREAM_PACKED, every rule that names that region
	 * walks all of it to find a marker that could not be there.
	 *
	 * That is what a region is for. It is not a label; it is the thing that
	 * lets a rule say which bytes its question could possibly be answered
	 * in, and a format whose largest part cannot answer any question should
	 * be able to say so.
	 *
	 * DECIDED FROM THE OBJECT'S OWN DICTIONARY, so it is decided on every
	 * document rather than on the ones whose graph happens to resolve -
	 * /Subtype /Image says it, and an image coding says it where no
	 * /Subtype does. See enum kof_pdf_cat, which is where that is settled.
	 *
	 * SEPARATE FROM STREAM_PACKED rather than carved out of it, because the
	 * two answer different questions: PACKED means "opaque until something
	 * decodes it", IMAGE means "opaque, and decoding it buys nothing". A
	 * rule wanting everything opaque names both.
	 */
	KOF_SCAN_PDF_STREAM_IMAGE = 1u << 6
};

#define KOF_SCAN_PDF_CLAIMED                                                  \
	(KOF_SCAN_PDF_HEADER | KOF_SCAN_PDF_OBJECTS |                         \
	 KOF_SCAN_PDF_STREAM_PLAIN | KOF_SCAN_PDF_STREAM_PACKED |             \
	 KOF_SCAN_PDF_STREAM_IMAGE)

/* Every stream, whatever its coding says about it - for a rule that wants the
 * opaque parts and does not care why they are opaque. */
#define KOF_SCAN_PDF_STREAMS                                                  \
	(KOF_SCAN_PDF_STREAM_PLAIN | KOF_SCAN_PDF_STREAM_PACKED |             \
	 KOF_SCAN_PDF_STREAM_IMAGE)

/*
 * THIS IS NOT A RUN CLASS, AND THE TWO MUST NEVER BE SWAPPED.
 *
 * Said here, at the top of the enum, because the mistake is one character and
 * the failure is silent.
 *
 * enum kof_pdf_class is what kof_runs_add takes - it decides which REGION a
 * range of bytes lands in. This enum says what a stream HOLDS. Both are small
 * unsigned values and C converts between them without a word, so
 * `kof_runs_add(..., o->cat)` compiles clean. What it would do:
 *
 *   - a category at or above KOF_PDF_CLS_COUNT is dropped by kof_runs_add's
 *     own bound check, so the bytes fall to the complement and turn up in
 *     UNCLAIMED - wrong, but visible in region_bytes
 *   - a category BELOW it is accepted as a class, and the bytes are filed
 *     into HEADER or OBJECTS. The partition still holds, every extent still
 *     coalesces, coverage still totals the whole file, and every region in
 *     the document is quietly wrong. No test that checks the partition can
 *     see it, because nothing about the partition is broken.
 *
 * The one thing that cannot happen is a read out of bounds: kof_runs_add
 * refuses any class at or above ncls, and ncls here is KOF_PDF_CLS_COUNT, so
 * no run ever carries a class that pdf_cls_bit[] does not have. That is the
 * runlist's contract and it holds whatever is passed.
 *
 * There is no way to make C refuse the swap. What stands in for it: the two
 * are never spelled alike, `cat` is written in exactly one function and read
 * by consumers rather than by the region machinery, and region_bytes is
 * asserted against the object table in the tests - a mis-filed class moves
 * bytes between regions and that identity is what notices.
 */
/*
 * WHAT KIND OF DATA A STREAM HOLDS.
 *
 * The question a scan actually wants answered, and separate from `filters`,
 * which says how the bytes are CODED rather than what they are. A payload
 * hidden in a document is not found by knowing that something was deflated;
 * it is found by knowing which of the deflated things is worth looking inside.
 *
 *
 * DECIDABLE HERE, WHICH IS WHY THIS LIST IS SHORT.
 *
 * Every category below is settled from the stream's OWN dictionary and from
 * nothing else. That is the line, and it is not the line between "layout" and
 * "meaning" - it is the line between what an object says about itself and what
 * only the document's object graph could say.
 *
 * Measured on the documents to hand: 3 of 15 streams in one and 0 of 4 in
 * another declare a /Type at all, so a category taken from /Type alone would
 * leave most streams unlabelled. The coding does not: an image coding IS the
 * statement that these are pixels, and it is present whenever /Type is not.
 * So the two are read together and the more specific wins.
 *
 * WHAT IS DELIBERATELY ABSENT is the page tree, the page objects and anything
 * else that needs /Root followed through /Pages and /Kids. Those are not shy
 * about what they are - they are simply not reachable from one dictionary, and
 * in a modern document they live inside an ObjStm and are not in the file's
 * bytes at all until it has been decoded. A category that resolved on some
 * documents and not others would be worse than none: a rule written against it
 * would stop matching for a reason nobody could see.
 *
 * CONTENT is the honest name for the remainder - a stream that declares no type
 * and carries no image coding, which in practice is a page's drawing operators.
 * Named rather than left at UNKNOWN because "no dictionary said" is a fact, and
 * a scan that treats it as a category can still choose to look inside.
 */
enum kof_pdf_cat {
	KOF_PDF_CAT_UNKNOWN = 0,   /* no stream, or nothing said at all */
	KOF_PDF_CAT_OBJSTM,        /* /Type /ObjStm: objects, once decoded */
	KOF_PDF_CAT_XREF,          /* /Type /XRef: the cross reference, as a stream */
	KOF_PDF_CAT_METADATA,      /* /Type /Metadata: XMP, and it is text */
	KOF_PDF_CAT_EMBEDDED,      /* /Type /EmbeddedFile: a file, whatever it is */
	KOF_PDF_CAT_SCRIPT,        /* the same dictionary carries /JS */
	KOF_PDF_CAT_IMAGE,         /* /Subtype /Image, or an image coding */
	KOF_PDF_CAT_FONT,          /* /Type /Font, /FontFile and friends */
	KOF_PDF_CAT_CONTENT,       /* a stream that said none of the above */
	KOF_PDF_CAT_COUNT
};

enum kof_pdf_class {
	KOF_PDF_CLS_HEADER = 0,
	KOF_PDF_CLS_OBJECTS,
	KOF_PDF_CLS_STREAM_PLAIN,
	KOF_PDF_CLS_STREAM_PACKED,
	/*
	 * APPENDED, so that HEADER stays 0 and PACKED stays 3.
	 *
	 * A class number is not private to this enum: it is written into
	 * run[].cls, which lives in the view a module reads. Inserting IMAGE
	 * among the others would renumber the ones after it and every stored
	 * run would mean something else. Order also decides who wins a tie in
	 * kof_runs_settle, and streams do not overlap each other, so there is
	 * nothing to gain by putting it anywhere but the end.
	 */
	KOF_PDF_CLS_STREAM_IMAGE,
	KOF_PDF_CLS_COUNT
};

#define KOF_PDF_REGION_COUNT 6u

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
	KOF_PDF_OBJ_ACROFORM   = 1u << 10,
	/*
	 * The three below are not things an object ANNOUNCES - they are things
	 * the parse caught it doing, and they are per object for the same
	 * reason the rest are: a heuristic asking which object carried a
	 * finding cannot be answered from a file-wide bit.
	 */
	KOF_PDF_OBJ_STREAM_DECOY = 1u << 11, /* "endstream" inside its own data */
	KOF_PDF_OBJ_NAME_ESC     = 1u << 12, /* a name written as /J#61vaScript */
	KOF_PDF_OBJ_REDEFINED    = 1u << 13, /* this number and gen seen before */
	KOF_PDF_OBJ_ENCRYPT      = 1u << 14  /* declares /Encrypt: a trailer */
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
	KOF_PDF_ANOM_TRUNCATED      = 1ull << 15, /* an object runs past the end */

	/*
	 * WHAT /Length IS FOR, AND WHY IT IS WORTH TWO BITS.
	 *
	 * The format says /Length is the authority on where a stream ends and
	 * "endstream" is the recovery path; this parse read only the second of
	 * those for a long time, and a stream carrying the nine bytes
	 * "endstream" in its data was therefore cut short at them. That is a
	 * place to hide a payload: everything past the decoy sat outside the
	 * stream, was never handed to the decompressor, and nothing said so.
	 *
	 * So /Length is read, and CORROBORATED rather than trusted - a length
	 * is a number the file chooses, and a huge one would swallow the rest
	 * of the document into one opaque region, which is the same trick from
	 * the other end. It wins only where an "endstream" actually stands at
	 * the offset it names.
	 *
	 * DECOY is the two disagreeing with /Length corroborated: the stream
	 * really is as long as it said, and something that reads like its end
	 * was placed inside it. Nothing does that by accident.
	 *
	 * LENGTH_BAD is /Length naming an offset where no "endstream" is. That
	 * is damage as often as it is intent - a document edited by hand and
	 * not re-lengthed does it - so it is the weaker of the two and says so
	 * by being a different bit.
	 */
	KOF_PDF_ANOM_LENGTH_BAD     = 1ull << 16,
	KOF_PDF_ANOM_STREAM_DECOY   = 1ull << 17,
	/* /Length written as `12 0 R`. Legal, and resolving it needs the object
	 * graph this parse does not build, so the stream falls back to the
	 * search and the reason is recorded rather than hidden. */
	KOF_PDF_ANOM_LENGTH_INDIR   = 1ull << 18,
	/*
	 * A NAME THAT WAS SPELLED TO AVOID BEING READ.
	 *
	 * #hh is a legal escape in a PDF name, so /J#61vaScript IS /JavaScript
	 * to every viewer. A substring search does not see it, and this file
	 * used to say the escape was "recorded separately" while nothing
	 * recorded it. Names are now decoded before they are matched, so the
	 * marker fires on its own account; this bit is the separate fact that
	 * an escape was needed to write it.
	 */
	KOF_PDF_ANOM_NAME_ESCAPED   = 1ull << 19,
	/*
	 * The same object number and generation defined twice.
	 *
	 * A FACT AND A WEAK ONE, because an incrementally updated document is
	 * built out of exactly this - a revision appends a new definition and
	 * the cross reference table says which one counts. This parse does not
	 * trust that table, so it cannot say which a viewer would pick, and it
	 * reports the ambiguity instead of resolving it. Worth having because
	 * two definitions plus one xref is how a document is made to read
	 * differently to two readers; not worth alarming on alone.
	 */
	KOF_PDF_ANOM_OBJ_REDEFINED  = 1ull << 20
};

#define KOF_PDF_ANOM_COUNT 21

struct kof_pdf_object {
	uint64_t off;          /* the 'N G obj' token */
	uint64_t len;          /* through 'endobj', clipped to the object */
	uint32_t num, gen;
	uint64_t dict_off, dict_len;      /* the part in the clear */
	uint64_t stream_off, stream_len;  /* zero when there is no stream */
	uint32_t filters;      /* KOF_PDF_F_* */
	uint32_t flags;        /* KOF_PDF_OBJ_* */

	/*
	 * WHAT THIS STREAM IS, AND WHERE THE FILE SAYS SO.
	 *
	 * Appended, per the layout rule at the top of this file.
	 *
	 * `cat` is the answer; `cat_off` and `cat_len` are the bytes IN THIS
	 * OBJECT that produced it - `ObjStm` out of /Type /ObjStm, `DCTDecode`
	 * out of /Filter /DCTDecode. A range and not a string because that is
	 * what naming a child takes: kof_name_next is given where a name is,
	 * never a name, and a module has nothing to build a string in. Every
	 * other container module in this tree names its children that way and
	 * this one did not, which is the whole reason a PDF's children arrived
	 * at a viewer as "Raw" while a zip's arrived as their entry names.
	 *
	 * Zero length when nothing in the dictionary named a category, which is
	 * a stream the walk found and the dictionary did not describe.
	 */
	uint64_t cat_off;
	uint32_t cat_len;
	uint32_t cat;          /* enum kof_pdf_cat */
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

	/*
	 * EIGHT, AND NOT KOF_PDF_CLS_COUNT.
	 *
	 * Sized to the run list's own ceiling rather than to the count of
	 * classes this format has today, because this array is NOT at the end
	 * of the structure: n_runs, run[] and object[] follow it. Sized to the
	 * count, adding a class moved every one of them - which is exactly what
	 * the layout rule at the top of this file forbids, and what a module
	 * compiled against the older header would read straight through.
	 *
	 * Adding the fifth class cost that move once. At eight it cannot happen
	 * again: KOF_RUNS_MAX_CLS is the most the run list will carry, and
	 * pdf_parse.c asserts the two agree.
	 */
	uint64_t region_bytes[8];

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
