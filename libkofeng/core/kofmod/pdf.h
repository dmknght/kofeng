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
 * SCAN REGIONS: WHAT THE BYTES ARE, AND NEVER HOW THEY ARE CODED.
 *
 * ONE AXIS, AND IT TOOK TWO ATTEMPTS. The first set of names had both.
 * STREAM_PLAIN and STREAM_PACKED said whether a filter stood in the way;
 * STREAM_IMAGE, _SCRIPT, _FONT and _META said what the bytes held. A stream
 * gets exactly ONE class, so the two axes had to fight over every stream - and
 * the coding won the ones that mattered least. A deflated font was FONT, a
 * deflated page was PACKED, so PACKED meant "content, compressed" on one
 * document and "whatever declared no type" on the next, and a rule could name
 * neither thing. Read a region list of such a document and it says the file is
 * 94% "packed", which is a statement about zlib and not about the document.
 *
 * So a region answers WHAT, and nothing else:
 *
 *   HEADERS, XREF, OBJ_TABLE      - the document's own structure
 *   CONTENT, _SCRIPT, _METADATA   - what the document is made of
 *   RESOURCE_IMAGE, _FONT         - what it draws with
 *   KOF_SCAN_EMBEDDED             - a passenger, and not PDF's to name
 *   UNCLAIMED                     - the complement, which owes an explanation
 *
 * WHERE THE CODING WENT: onto the entry table, which is where it belongs.
 * kof_entry.coding names the filter chain of each stream, and
 * KOF_ENT_F_CODED_UNKNOWN says the chain could not be read; the decoded bytes
 * become a CHILD object with regions of its own. A region is a statement about
 * bytes that are HERE. A coding is a statement about how to reach bytes that
 * are not - a different question, and it now has a different answer.
 *
 * WHAT THAT COSTS A SCAN, measured rather than argued. The coding axis looked
 * useful because coded bytes cannot be searched for anything, and on an
 * ordinary 1.65MB document they are 94% of the file. Naming kinds recovers all
 * but a sliver of it, because the coded bulk IS the images and the fonts: a
 * rule for script or text names CONTENT, _SCRIPT and _METADATA, walks 63KB,
 * and the deflated page operators inside CONTENT are the only bytes it still
 * touches that it cannot read.
 *
 * THE VALUES ARE COMPILED INTO A DATABASE. ksigbuilder turns the names below
 * into these bits when it builds a module, so a blob and the engine that loads
 * it must come from the same spelling of this enum. Renaming or renumbering a
 * region means `make databases`, and that is the reason to do it once and
 * deliberately rather than a bit at a time.
 */
enum kof_scan_pdf {
	/*
	 * THE VERSION LINE AND THE POINTERS AT THE END.
	 *
	 * %PDF-1.x and the binary comment under it, then every startxref and
	 * %%EOF - both ends of the file, which is why it is plural. Small, and
	 * the part that describes the rest.
	 *
	 * It was called HEADER and carried the cross reference section too,
	 * which is how a 9464 byte xref table in an ordinary document came to
	 * be reported as "header".
	 */
	KOF_SCAN_PDF_HEADERS          = 1u << 1,
	/*
	 * THE CROSS REFERENCE, IN EITHER SHAPE.
	 *
	 * A classic xref section with its trailer dictionary, and a /Type
	 * /XRef stream: the same statement written two ways, and a rule about
	 * it should not have to know which way a document chose. Worth its own
	 * name because /Encrypt and /Root live in the trailer - a rule asking
	 * whether a document is encrypted is asking about exactly these bytes.
	 *
	 * The stream shape had no class at all and fell into the old PACKED,
	 * which is also where a compressed page's operators went. Every
	 * document written this century uses the stream shape.
	 */
	KOF_SCAN_PDF_XREF             = 1u << 2,
	/*
	 * THE OBJECT DEFINITIONS: every dictionary, the "N G obj" and
	 * "endstream endobj" that bracket one, any direct content that is not
	 * a stream - and /Type /ObjStm, which is this same table deflated.
	 *
	 * The region a signature for a malicious action searches, because
	 * /Launch, /OpenAction, /JavaScript and /URI are dictionary keys. An
	 * ObjStm belongs here for that reason and not for its shape: its bytes
	 * hold object definitions, so a rule that names this region is asking
	 * about them whether the document chose to compress them or not. What
	 * such a rule will FIND in a deflated one is nothing, and that is what
	 * the decoded child exists for.
	 */
	KOF_SCAN_PDF_OBJ_TABLE        = 1u << 3,
	/*
	 * WHAT THE DOCUMENT IS MADE OF: a stream that declared no type and
	 * carried no image coding, which in practice is a page's drawing
	 * operators.
	 *
	 * The honest remainder, and named rather than left nameless because
	 * "no dictionary said" is a fact a rule can act on. It was called
	 * STREAM_PLAIN, which said something else entirely - that no filter
	 * was present - and on all three documents to hand the whole of
	 * STREAM_PLAIN was the XMP metadata and not one page operator.
	 */
	KOF_SCAN_PDF_CONTENT          = 1u << 4,
	/*
	 * SCRIPT, AND WHY IT COULD NOT BE LEFT IN WITH THE REST.
	 *
	 * Measured on a document written to carry all of it at once: the
	 * page's drawing operators, the JavaScript and an embedded executable
	 * were three unfiltered streams, and all three landed in STREAM_PLAIN
	 * together. A rule for script had no way to say "the script" - it
	 * could only say "streams that happen not to be compressed", which on
	 * that document meant the content and the payload as well.
	 *
	 * The script is usually not where the /JS is - see
	 * kof_pdf_object.js_ref - so this region rests on following that one
	 * reference. Where it cannot be followed the stream stays CONTENT,
	 * which is the honest answer rather than a guess.
	 */
	KOF_SCAN_PDF_CONTENT_SCRIPT   = 1u << 5,
	/*
	 * THE DOCUMENT'S OWN METADATA, AND IT WAS BEING CALLED PLAIN.
	 *
	 * XMP is a packet of XML - text, in the clear, and the one stream in
	 * an ordinary document that is not compressed at all. That last fact
	 * is why it needed saying: on all three documents to hand, the whole
	 * of STREAM_PLAIN was the metadata and nothing else. 3057 bytes of
	 * 3057 on one, 3629 of 3629 on the next. A region called PLAIN was
	 * answering "which streams happen not to be deflated" and being read
	 * as though it said something about content.
	 *
	 * Worth its own name and not just a correction: metadata is where a
	 * producer string, a title and an author live, and a rule about who
	 * built a document wants exactly this and none of a page's operators.
	 */
	KOF_SCAN_PDF_CONTENT_METADATA = 1u << 6,
	/*
	 * PIXELS, AND THE REASON THIS REGION EXISTS AT ALL.
	 *
	 * The bulk of a PDF is images, and none of it is worth searching for
	 * anything this engine looks for. Measured on an ordinary 1.65MB
	 * document: 25 streams and 1,307,894 bytes are image data - 79% of the
	 * file. RESOURCE because that is what it is to the document: not part
	 * of what the document SAYS, part of what it draws with.
	 *
	 * That is what a region is for. It is not a label; it is the thing
	 * that lets a rule say which bytes its question could possibly be
	 * answered in, and a format whose largest part cannot answer any
	 * question should be able to say so.
	 *
	 * DECIDED FROM THE OBJECT'S OWN DICTIONARY, so it is decided on every
	 * document rather than on the ones whose graph happens to resolve -
	 * /Subtype /Image says it, and an image coding says it where no
	 * /Subtype does. See enum kof_pdf_cat, which is where that is settled.
	 */
	KOF_SCAN_PDF_RESOURCE_IMAGE   = 1u << 7,
	/*
	 * FONT PROGRAMS, AND THEY ARE MOST OF WHAT WAS LEFT.
	 *
	 * A font is a program for a rasteriser. It is not text, it carries no
	 * URL and no script, and nothing this engine looks for can be in one -
	 * the same argument IMAGE rests on, and the same size of prize: with
	 * images taken out, 90% of the remaining stream bytes on three
	 * ordinary documents were fonts. After both, a rule for script or text
	 * walks 63KB of a 1.66MB document instead of 1.62MB.
	 *
	 * REACHED THROUGH A REFERENCE, because a font program's own dictionary
	 * says only how long it is - see kof_pdf_object.ref_num. Where the
	 * reference cannot be followed the stream stays CONTENT, which is the
	 * honest answer rather than a guess.
	 */
	KOF_SCAN_PDF_RESOURCE_FONT    = 1u << 8,
	/*
	 * AND THE COMPLEMENT: the bytes no structure claimed.
	 *
	 * Computed by kof_runs_resolve rather than assigned, so it is the one
	 * region with no class - it is whatever the classes did not cover. A
	 * document with a lot of it is a document holding something the format
	 * does not explain, which is a finding in itself.
	 */
	KOF_SCAN_PDF_UNCLAIMED        = 1u << 9
};

/*
 * EVERY REGION SOME STRUCTURE CLAIMED - which is every class's bit, so it is
 * generated from the class list rather than kept as a second copy of it. The
 * definition is beside KOF_PDF_CLASSES below, because that is the list it
 * comes out of.
 *
 * The complement, KOF_SCAN_PDF_UNCLAIMED, is deliberately not part of it.
 *
 * KOF_SCAN_PDF_STREAMS used to sit here - "every stream, whatever its coding".
 * It went with the coding axis: a stream now lands in one of five kinds or in
 * OBJ_TABLE or XREF, so a macro claiming to name all of them would list seven
 * bits and would still be answering "what might a stream be" rather than any
 * question a rule asks. A rule that wants every byte says KOF_SCAN_ALL.
 */

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
/* Declared below the categories it reads - see kof_pdf_entry_format. */
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

/*
 * WHAT THIS FORMAT IS WILLING TO DECLARE ABOUT A CATEGORY'S DECODED BYTES.
 *
 * A CLAIM AND NOT A GUESS, and the list is short because most of it would be a
 * guess. Here rather than inside the parse because the decompressor module
 * declares the same thing about the same streams, and two copies of a mapping
 * are two things that can drift - which is the fault this header exists to
 * prevent, stated at the top of it.
 *
 * SCRIPT is the one the format states outright: /JS names a script.
 *
 * CONTENT AND METADATA ARE NOT NAMED, AND "TEXT WOULD BE TRUE" IS NOT ENOUGH.
 *
 * A page description stream IS operators in ASCII and an XMP packet IS XML, so
 * KOF_FMT_TEXT would be an honest claim. It was made here and then withdrawn,
 * because a format id is not only an identity - IT IS A GATE.
 * kof_module_precond tests `target_mask & (1u << ctx->format)` before anything
 * else, so naming an object more specifically NARROWS who is allowed to look
 * at it.
 *
 * Measured against the shipped base: five modules target
 * ELF|PE|KOF_FMT_UNKNOWN - the Metasploit stub decoders, which exist to find
 * x86 shellcode in bytes nothing has named - and ZERO target TEXT. Calling a
 * content stream TEXT therefore takes it away from five rules and gives it to
 * none. A PDF hiding a decoder stub in a page stream is exactly the case those
 * five are for.
 *
 * So the rule is: declare a format when a rule base exists for it, not merely
 * when the claim would be true. When TEXT rules exist, this is one line.
 *
 * EMBEDDED is deliberately NOT named. A carried file is a file of unknown kind
 * by definition; declaring one would run the wrong parse and hide what the
 * sniff chain would have found.
 *
 * IMAGE AND FONT ARE NAMED, AND THAT PARAGRAPH USED TO SAY THE OPPOSITE.
 *
 * It said there was no honest id for a JPEG sample block or a CFF program.
 * There is now - KOF_FMT_IMAGE and KOF_FMT_FONT - and naming them is what
 * turns "those are never opened" from a decision written into a module into a
 * question the database answers.
 *
 * The TEXT argument above is the same argument, and it reaches the opposite
 * conclusion because the facts are opposite. Naming a format narrows who may
 * look: TEXT would have taken content streams from five rules that target
 * KOF_FMT_UNKNOWN and given them to none, so it was withdrawn. FONT takes a
 * rasteriser program away from those same five - and that is the intent,
 * measured: 88% of one ordinary document is font programs, inflated and
 * searched for stub decoders that were written to find x86 shellcode in
 * unnamed bytes. A CFF charstring table is not unnamed bytes.
 *
 * AND IT IS REVERSIBLE BY ONE LINE, which is why this is safe to do and TEXT
 * was not. What is given up - a payload hidden in a stream that declares
 * /Subtype /Image or is reached through a /FontFile - comes back the moment
 * somebody writes KOF_TARGET_FORMAT(KOF_FMT_FONT) in a signature source: the
 * producer asks fmt_wanted, the database now says yes, and the streams are
 * opened again with no engine change. Until then the bytes are still in the
 * file, still inside KOF_SCAN_PDF_RESOURCE_FONT, and still searchable where
 * they lie; and a rule that fires on the document raises the whole of it -
 * see KOF_ENG_OPEN_CARRIED.
 */
/*
 * WHAT A CATEGORY IS, in the engine's own vocabulary.
 *
 * Beside the format mapping and shared for the same reason: the parse fills
 * the entry table with it and the decompressor names its children from it, so
 * two copies would be two things that can drift.
 *
 * A KIND IS NOT A FORMAT, and the difference is what makes this safe where
 * naming a format was not. A format id GATES which modules see the object -
 * see the note on the format mapping for the five rules that were lost by
 * naming one too precisely. A kind gates nothing: it says what the thing is
 * for, and it is what a policy and a reader both want.
 */
static inline uint32_t kof_pdf_entry_kind(uint32_t cat)
{
	switch (cat) {
	case KOF_PDF_CAT_OBJSTM:   return KOF_ENT_STRUCTURE;
	case KOF_PDF_CAT_XREF:     return KOF_ENT_STRUCTURE;
	case KOF_PDF_CAT_METADATA: return KOF_ENT_METADATA;
	case KOF_PDF_CAT_EMBEDDED: return KOF_ENT_EMBEDDED;
	case KOF_PDF_CAT_SCRIPT:   return KOF_ENT_SCRIPT;
	case KOF_PDF_CAT_IMAGE:    return KOF_ENT_IMAGE;
	case KOF_PDF_CAT_FONT:     return KOF_ENT_FONT;
	case KOF_PDF_CAT_CONTENT:  return KOF_ENT_CONTENT;
	default:                   return KOF_ENT_UNKNOWN;
	}
}

static inline uint8_t kof_pdf_entry_format(uint32_t cat)
{
	switch (cat) {
	case KOF_PDF_CAT_SCRIPT:   return (uint8_t)KOF_FMT_SCRIPT;
	/* What the document draws with. Both are read off the object's own
	 * dictionary - /Subtype /Image, or a /FontFile reference - so this is
	 * the structure talking and not a look at the bytes. */
	case KOF_PDF_CAT_IMAGE:    return (uint8_t)KOF_FMT_IMAGE;
	case KOF_PDF_CAT_FONT:     return (uint8_t)KOF_FMT_FONT;
	default:                   return (uint8_t)KOF_FMT_UNKNOWN;
	}
}

/*
 * THE CLASS LIST, AND IT IS THE ONLY PLACE A PDF CLASS IS DECLARED.
 *
 * A class, and the region bit the bytes of that class land in. Written once:
 * three things are generated from this list and a fourth is held against it.
 *
 *   enum kof_pdf_class      - what kof_runs_add takes
 *   pdf_cls_bit[]           - what kof_runs_resolve turns a class back into
 *   KOF_SCAN_PDF_CLAIMED    - every region some structure owns
 *   PDF_REGIONS(X)          - the name list in pdf_parse.h, which signatures
 *                             are written against; pinned to this list by two
 *                             asserts in pdf_parse.c
 *
 * WHY IT IS GENERATED AND NOT WRITTEN OUT. pdf_cls_bit[] was a hand-kept array
 * declared [KOF_PDF_CLS_COUNT] with one line per class, and a class appended to
 * the enum without a line added there read a ZERO. A zero matches no mask, so
 * that class's bytes resolved into no region at all - and nothing said so: the
 * partition still totalled the whole file, because the bytes were in a run and
 * the run was in the list. The only symptom would have been a rule that named
 * the new region and matched nothing, quietly, for as long as nobody checked.
 * The array cannot be short now, because the array IS this list.
 *
 * THE ORDER IS THE CLASS NUMBERING, and those numbers are written into
 * run[].cls in the view a module reads. That view is built and read within one
 * run of one build, so reordering here is safe in a way that renaming a region
 * BIT is not - a bit value is compiled into a signature blob, and a database
 * built against a different spelling of enum kof_scan_pdf has to be rebuilt.
 * Prefer appending anyway: two tools of the same vintage should agree about
 * what "class 4" meant when one of them printed a run list.
 *
 * EMBEDDED MAPS TO THE SHARED BIT, KOF_SCAN_EMBEDDED, and not to a PDF one:
 * "a file this document is carrying" is not a question about PDF, and a rule
 * for carried files should not have to name every container's word for it. See
 * that bit in kofsig.h.
 */
#define KOF_PDF_CLASSES(X)                                              \
	/* the document's own structure */                              \
	X(HEADERS,          KOF_SCAN_PDF_HEADERS)                       \
	X(XREF,             KOF_SCAN_PDF_XREF)                          \
	X(OBJ_TABLE,        KOF_SCAN_PDF_OBJ_TABLE)                     \
	/* what the document is made of */                              \
	X(CONTENT,          KOF_SCAN_PDF_CONTENT)                       \
	X(CONTENT_SCRIPT,   KOF_SCAN_PDF_CONTENT_SCRIPT)                \
	X(CONTENT_METADATA, KOF_SCAN_PDF_CONTENT_METADATA)              \
	/* what it draws with */                                        \
	X(RESOURCE_IMAGE,   KOF_SCAN_PDF_RESOURCE_IMAGE)                \
	X(RESOURCE_FONT,    KOF_SCAN_PDF_RESOURCE_FONT)                 \
	/* and its passengers */                                        \
	X(EMBEDDED,         KOF_SCAN_EMBEDDED)

enum kof_pdf_class {
#define KOF_PDF_CLS_ENUM(n, bit) KOF_PDF_CLS_##n,
	KOF_PDF_CLASSES(KOF_PDF_CLS_ENUM)
#undef KOF_PDF_CLS_ENUM
	/*
	 * NINE, OF THE TWELVE THE RUN LIST CARRIES.
	 *
	 * What is deliberately not here. THE PAGE TREE, the page objects, and
	 * anything else that needs /Root followed through /Pages and /Kids:
	 * those are not shy about what they are, they are simply not reachable
	 * from one object's own dictionary, and in a modern document they live
	 * inside an ObjStm and are not in the file's bytes at all until it has
	 * been decoded. A class that resolved on some documents and not others
	 * would be worse than none - a rule written against it would stop
	 * matching for a reason nobody could see.
	 *
	 * THE OBJECT STREAMS AND THE XREF STREAM used to be listed here as
	 * classes that were decidable and deliberately left out, on the ground
	 * that a region over deflated bytes tells a rule where some compressed
	 * data is and answers nothing. That was the coding axis talking. They
	 * have classes now - OBJ_TABLE and XREF, the same classes their
	 * uncompressed equivalents get - because a region says what bytes ARE,
	 * and an ObjStm holds object definitions whatever was done to them
	 * afterwards. What it takes to READ them is still a decoded child, and
	 * that is still a different mechanism from a region.
	 */
	KOF_PDF_CLS_COUNT
};

/* Or-ed and summed: both are constant expressions, and they are equal only
 * when no two classes name the same bit - see the assert below. */
#define KOF_PDF_CLS_OR(n, bit)  | (bit)
#define KOF_PDF_CLS_SUM(n, bit) + (bit)

#define KOF_SCAN_PDF_CLAIMED (0u KOF_PDF_CLASSES(KOF_PDF_CLS_OR))

/*
 * NO CLASS MAPS TO NOTHING, AND NO TWO MAP TO THE SAME BIT.
 *
 * The sum equals the or only when nothing is shared. Two classes on one bit
 * would make a region that two different kinds of byte land in, so a rule
 * naming it would be handed both and could not say which it had asked for -
 * and the partition would still be perfect, so no existing test would see it.
 *
 * The per-class assert is the same test written once for each entry, so a
 * mistake names the class that made it rather than the list as a whole.
 */
_Static_assert((0u KOF_PDF_CLASSES(KOF_PDF_CLS_SUM)) == KOF_SCAN_PDF_CLAIMED,
	       "two PDF classes share one region bit");
#define KOF_PDF_CLS_NONZERO(n, bit) \
	_Static_assert((bit) != 0u, "PDF class " #n " maps to no region bit");
KOF_PDF_CLASSES(KOF_PDF_CLS_NONZERO)
#undef KOF_PDF_CLS_NONZERO

/*
 * THE REGIONS: every class's, plus the complement.
 *
 * Derived rather than counted, because it was `10u` written out by hand and
 * what it has to equal is the length of PDF_REGIONS(X) - the list a signature
 * writer picks names from. Held to that list by the asserts in pdf_parse.c,
 * so the three cannot come apart.
 */
#define KOF_PDF_REGION_COUNT (KOF_PDF_CLS_COUNT + 1u)

/*
 * Bounds.
 *
 * Measured over the PDFs on this machine the largest holds 548 objects; a document
 * built by a generator can hold far more, so the cap is set well above what was seen
 * and reaching it is recorded rather than silently truncating the walk.
 */
#define KOF_PDF_MAX_OBJECTS  4096u
/* A quarter of the object cap: one entry per stream, and the documents to
 * hand carry 57, 15 and 4 of them. See the entry table in kof_pdf_info. */
#define KOF_PDF_MAX_STREAMS  1024u
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
	KOF_PDF_ANOM_OBJ_REDEFINED  = 1ull << 20,
	/*
	 * A CARRIED FILE THIS PARSE COULD NOT REACH.
	 *
	 * /EF is a dictionary of references - /F, /UF and three legacy platform
	 * keys - so the file is one step in, which this parse follows. Written
	 * as an INDIRECT reference (`/EF 9 0 R`) it is two steps, and two is
	 * the graph resolution this parse refuses.
	 *
	 * Recorded rather than passed over, because the consequence is that a
	 * file the document carries was classified as page content. A reader
	 * seeing this bit knows there is an attachment whose bytes went
	 * somewhere else, which is worth an eye.
	 */
	KOF_PDF_ANOM_EF_UNRESOLVED  = 1ull << 21
};

#define KOF_PDF_ANOM_COUNT 22

/*
 * WHAT THE DOCUMENT SAYS ABOUT ITSELF - the /Info dictionary.
 *
 * Six strings a producer writes and a reader wants first: who made it, with
 * what, and what it claims to be about. A researcher opening an unknown
 * document reads these before anything else, and until now nothing read them
 * at all.
 *
 * WHY THEY ARE WORTH PARSING when a rule could already match them: they live
 * in the OBJECTS region, uncompressed, so a signature scoped there reaches
 * them without any of this. What a rule cannot do is put them on a screen in
 * order, and that is the whole of what this is for - the same reason the
 * region list is published rather than left for each host to derive.
 *
 * A PRODUCER STRING IS ALSO EVIDENCE. Malware builders leave theirs in, and
 * one that claims a version of a tool that does not lay objects out the way
 * this document does is a disagreement worth seeing.
 */
enum kof_pdf_docinfo {
	KOF_PDF_DOCINFO_TITLE = 0,
	KOF_PDF_DOCINFO_AUTHOR,
	KOF_PDF_DOCINFO_SUBJECT,
	KOF_PDF_DOCINFO_KEYWORDS,
	KOF_PDF_DOCINFO_CREATOR,
	KOF_PDF_DOCINFO_PRODUCER,
	KOF_PDF_DOCINFO_COUNT
};

/* What each one is called, so a host does not carry its own list - the same
 * reason kof_pdf_region_name exists. */
const char *kof_pdf_docinfo_name(unsigned which);

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

	/*
	 * AN OBJECT THIS ONE POINTS AT, AND WHAT THAT MAKES IT.
	 *
	 * The one kind of indirect reference this parse follows, and it is
	 * worth saying why it is not the graph resolution the rest of this file
	 * refuses.
	 *
	 * A DICTIONARY OFTEN DESCRIBES A STREAM IT IS NOT. A document almost
	 * never puts its script inline: it writes `/S /JavaScript /JS 6 0 R`
	 * and object 6's own dictionary says `<< /Length 68 >>` and nothing
	 * else. A font is the same shape - a descriptor says
	 * `/FontFile2 9 0 R` and object 9 declares only its length. So the
	 * stream that HOLDS the interesting thing declares nothing about
	 * itself, and a category taken from one dictionary called both of them
	 * CONTENT.
	 *
	 * Measured, because the size of it decided that this was worth doing:
	 * of the bytes this parse called CONTENT, 90%, 92% and 83% on three
	 * ordinary documents were font programs. Page drawing operators - the
	 * thing CONTENT is supposed to mean - were 30KB of a 1.6MB file.
	 *
	 * ONE STEP, AND BOUNDED. A lookup by object number in a table the walk
	 * has already built - not /Root through /Pages through /Kids, which
	 * needs the trailer, needs the xref this parse does not trust, and in a
	 * modern document runs through an ObjStm whose bytes are not in the
	 * file yet. Following a number to a row cannot recurse, and it fails
	 * closed: a reference to an object that is not there leaves the
	 * category exactly as it was.
	 *
	 * ONE PAIR AND NOT ONE PER KIND. `ref_cat` says what the reference
	 * makes its target, so a kind added later costs a line in dict_scan
	 * rather than a field here. The first reference in a dictionary wins;
	 * nothing sensible carries two, and a dictionary that did would be
	 * describing two streams at once.
	 */
	uint32_t ref_num;      /* the object number, or zero */
	uint32_t ref_cat;      /* enum kof_pdf_cat: what it makes that object */
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
	uint64_t region_bytes[12];

	uint32_t n_runs;
	uint32_t reserved2;
	struct {
		uint64_t off, len;
		uint32_t cls;
		uint32_t reserved;
	} run[KOF_PDF_MAX_EXTENTS];

	struct kof_pdf_object object[KOF_PDF_MAX_OBJECTS];

	/*
	 * THE SAME STREAMS, IN THE SHAPE THE HOST READS.
	 *
	 * Built from object[] above and holding nothing that is not already
	 * there - so this is a projection and not a second source of truth. It
	 * exists because struct kof_entry is what every format speaks and
	 * kof_pdf_object is what only PDF speaks: the host cannot walk the
	 * second, and teaching it to would be teaching it one format at a time.
	 *
	 * One entry per stream, so `n_entries` is n_streams and never more.
	 */
	uint32_t n_entries;
	uint32_t reserved4;
	/*
	 * SIZED TO WHAT STREAMS CAN NUMBER, not to what objects can.
	 *
	 * One entry per stream and never more, and a stream needs its own
	 * object - so the ceiling is the object cap. Sized THERE it cost 196KB
	 * of a view for rows that cannot be filled: the documents measured
	 * carry 57, 15 and 4 streams against 4096 objects. A quarter of the
	 * cap is still far past anything seen and is a fifth of the memory.
	 *
	 * Reaching it is recorded rather than silently truncating, the same way
	 * the object walk records KOF_PDF_ANOM_OBJECTS_FULL.
	 */
	/*
	 * The /Info strings, as RANGES IN THE FILE and never as copies - the
	 * text is already there and a parse has nowhere to build another one,
	 * which is the rule every name in this tree follows. Zero length for a
	 * key the document does not carry, which is most of them in most files.
	 *
	 * The range is what is INSIDE the delimiters: a literal string's
	 * parentheses and a hex string's angle brackets are syntax, and a host
	 * drawing them would be drawing the file's punctuation.
	 */
	struct kof_entry entry[KOF_PDF_MAX_STREAMS];

	/*
	 * APPENDED, and the placement is the point rather than a preference.
	 * This header's own rule is at the top of it: new fields go at the END,
	 * existing fields never move. These went in above entry[] first, which
	 * moved a 64KB array and every offset after it - and the version number
	 * that exists to catch exactly that would have had to be bumped for a
	 * change that needed no bump at all.
	 */
	/*
	 * `hex` says the value was written <4A4B> rather than (JK), which a
	 * host cannot tell from the bytes: hex digits are also letters, so a
	 * value of "0FACED" is a legal spelling of three bytes AND a legal
	 * word. Recording the form is one byte; guessing it is a title rendered
	 * as gibberish or the reverse.
	 */
	struct {
		uint64_t off;
		uint32_t len;
		uint8_t  hex;
	} docinfo[KOF_PDF_DOCINFO_COUNT];

	/* The trailer's own dictionary, which is where /Info is declared. Zero
	 * length in a document that has an xref STREAM instead - there the same
	 * keys are on that stream's dictionary, and the parse looks there. */
	uint64_t trailer_off;
	uint32_t trailer_len;

};

static inline const struct kof_pdf_info *kof_pdf(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_pdf_info *)ctx->file_header;
}

#endif /* KOFENG_PDF_H */
